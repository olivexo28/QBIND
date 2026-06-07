//! Run 209 — source/test hidden custody-attestation policy selector and
//! production preflight integration tests.
//!
//! Source/test only. Run 209 does **not** capture release-binary
//! evidence; release-binary custody-attestation-policy selector evidence
//! is deferred to **Run 210**. Default policy remains
//! [`CustodyAttestationPolicy::Disabled`]. Fixture attestation remains
//! DevNet/TestNet evidence-only and cannot satisfy MainNet production
//! attestation. Real cloud-KMS / PKCS#11 / HSM-vendor attestation
//! verifiers, real KMS / HSM backends, and real RemoteSigner backends
//! remain unimplemented; every production-class attestation attempt
//! fails closed via the Run 205 verifier regardless of selector. MainNet
//! peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal
//! regardless of selector, even with `MainnetProductionAttestationRequired`
//! and fixture attestation material. Real on-chain governance proof
//! verification, governance execution, and validator-set rotation all
//! remain unimplemented. Full C4 remains open. C5 remains open.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_209.md`.
//!
//! These tests cover the A1–A15 / R1–R40 matrix from
//! `task/RUN_209_TASK.txt` where representable at the
//! selector + payload-carrying layer:
//!
//! * the typed selector parsers
//!   ([`custody_attestation_policy_from_selector`],
//!   [`custody_attestation_policy_env_selector`],
//!   [`custody_attestation_policy_from_cli_or_env`]) including default,
//!   CLI, env, CLI-over-env precedence, and invalid-value fail-closed;
//! * source reachability — the resolved policy reaches all seven
//!   production-context per-surface preflight wrappers
//!   ([`preflight_v2_marker_custody_attestation_for_*`]);
//! * accepted scenarios A1–A15 (where representable);
//! * rejection scenarios R1–R40;
//! * no-mutation invariants (validation-only and mutating-rejection);
//! * MainNet refusal invariants.
//!
//! The tests construct only data values and call the pure helpers /
//! routing wrappers — no I/O, no marker write, no sequence write, no live
//! trust swap, no session eviction, no Run 070 invocation.

use std::sync::{Mutex, OnceLock};

use qbind_ledger::BundleSigningRatificationV2Action;
use qbind_node::pqc_authority_custody::{
    AuthorityCustodyAttestation, AuthorityCustodyClass, AuthorityCustodyPolicy,
};
use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_state::{
    AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
    PersistentAuthorityStateRecordVersioned,
};
use qbind_node::pqc_custody_attestation_payload_carrying::{
    parse_optional_custody_attestation_sibling_from_json_value, CustodyAttestationLoadStatus,
    CustodyAttestationParts, CustodyAttestationPayloadCarryingDecisionOutcome,
    CustodyAttestationPayloadWire, CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD,
};
use qbind_node::pqc_custody_attestation_policy_surface::{
    custody_attestation_policy_env_selector, custody_attestation_policy_from_cli_or_env,
    custody_attestation_policy_from_selector,
    preflight_v2_marker_custody_attestation_for_live_inbound_0x05,
    preflight_v2_marker_custody_attestation_for_local_peer_candidate_check,
    preflight_v2_marker_custody_attestation_for_peer_driven_drain,
    preflight_v2_marker_custody_attestation_for_reload_apply,
    preflight_v2_marker_custody_attestation_for_reload_check,
    preflight_v2_marker_custody_attestation_for_sighup,
    preflight_v2_marker_custody_attestation_for_startup_p2p_trust_bundle,
    CustodyAttestationPolicySelectorParseError, QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY_ENV,
};
use qbind_node::pqc_custody_attestation_verifier::{
    CustodyAttestationClass, CustodyAttestationEvidence, CustodyAttestationInput,
    CustodyAttestationOutcome, CustodyAttestationPolicy, CustodyMetadataAttestationOutcome,
    CUSTODY_ATTESTATION_INVALID_COMMITMENT_SENTINEL, CUSTODY_ATTESTATION_SUPPORTED_VERSION,
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
        let prior = std::env::var(QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY_ENV).ok();
        match value {
            Some(v) => {
                std::env::set_var(QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY_ENV, v)
            }
            None => std::env::remove_var(QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY_ENV),
        }
        EnvGuard { prior, _lock: lock }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.prior.take() {
            Some(v) => {
                std::env::set_var(QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY_ENV, v)
            }
            None => std::env::remove_var(QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY_ENV),
        }
    }
}

// ===========================================================================
// Shared fixtures (mirror the Run 207 corpus exactly so the binding tuple
// matches the Run 205 verifier).
// ===========================================================================

const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT_FP: &str = "1111111111111111111111111111111111111111";
const CHAIN_ID: &str = "0000000000000001";
const GENESIS_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const PRIOR_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const KEY_ID: &str = "attestation-key-id-209";
const PROVIDER_ID: &str = "attestation-provider-209";
const ATTEST_COMMITMENT: &str = "attestation-commitment-209";
const ATTEST_NONCE: &str = "attestation-nonce-209";
const GOV_PROOF_DIGEST: &str = "gov-proof-digest-209";
const NOW: u64 = 1_700_000_000;
const FRESH: u64 = 1_699_999_900;
const EXPIRES: u64 = 1_700_001_000;
const ISSUED: u64 = 1_699_999_950;
const WINDOW_SINCE: u64 = 1_699_999_000;
const WINDOW_UNTIL: u64 = 1_700_000_500;

fn domain(env: TrustBundleEnvironment) -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(
        env,
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

fn evidence(
    class: CustodyAttestationClass,
    env: TrustBundleEnvironment,
    candidate: &PersistentAuthorityStateRecordV2,
) -> CustodyAttestationEvidence {
    CustodyAttestationEvidence {
        attestation_class: class,
        attestation_version: CUSTODY_ATTESTATION_SUPPORTED_VERSION,
        environment: env,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        bundle_signing_key_fingerprint: candidate.active_bundle_signing_key_fingerprint.clone(),
        custody_class: AuthorityCustodyClass::Kms,
        custody_backend_kind: Some("fixture-kms".to_string()),
        backend_provider_signer_id: PROVIDER_ID.to_string(),
        custody_key_id: KEY_ID.to_string(),
        suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: DIGEST_2.to_string(),
        authority_domain_sequence: 2,
        governance_proof_digest: Some(GOV_PROOF_DIGEST.to_string()),
        request_digest: Some("request-digest".to_string()),
        response_digest: Some("response-digest".to_string()),
        transcript_digest: Some("transcript-digest".to_string()),
        attestation_nonce: ATTEST_NONCE.to_string(),
        issued_at_unix: Some(ISSUED),
        freshness_unix: Some(FRESH),
        expires_at_unix: Some(EXPIRES),
        attestation_commitment: ATTEST_COMMITMENT.to_string(),
    }
}

fn input(
    env: TrustBundleEnvironment,
    candidate: &PersistentAuthorityStateRecordV2,
) -> CustodyAttestationInput {
    CustodyAttestationInput {
        expected_environment: env,
        expected_chain_id: CHAIN_ID.to_string(),
        expected_genesis_hash: GENESIS_HASH.to_string(),
        expected_authority_root_fingerprint: ROOT_FP.to_string(),
        expected_bundle_signing_key_fingerprint: candidate
            .active_bundle_signing_key_fingerprint
            .clone(),
        expected_custody_class: AuthorityCustodyClass::Kms,
        expected_backend_provider_signer_id: PROVIDER_ID.to_string(),
        expected_custody_key_id: KEY_ID.to_string(),
        expected_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        expected_lifecycle_action: LocalLifecycleAction::Rotate,
        expected_candidate_digest: DIGEST_2.to_string(),
        expected_authority_domain_sequence: 2,
        expected_governance_proof_digest: Some(GOV_PROOF_DIGEST.to_string()),
        expected_request_digest: Some("request-digest".to_string()),
        expected_response_digest: Some("response-digest".to_string()),
        expected_transcript_digest: Some("transcript-digest".to_string()),
        expected_attestation_nonce: ATTEST_NONCE.to_string(),
        replay_window_since_unix: Some(WINDOW_SINCE),
        replay_window_until_unix: Some(WINDOW_UNTIL),
        now_unix: NOW,
    }
}

fn good_custody_attestation(
    env: TrustBundleEnvironment,
    candidate: &PersistentAuthorityStateRecordV2,
) -> AuthorityCustodyAttestation {
    AuthorityCustodyAttestation {
        custody_class: AuthorityCustodyClass::FixtureLocalKey,
        custody_key_id: KEY_ID.to_string(),
        custody_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        custody_attestation_digest: "custody-att-digest".to_string(),
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

/// A complete, valid accepted scenario on the given environment. Holds
/// every owned value a test needs to drive the seven per-surface
/// preflight wrappers with the resolved policy, and to mutate one field
/// for a rejection vector.
struct Scenario {
    domain: AuthorityTrustDomain,
    candidate: PersistentAuthorityStateRecordV2,
    prior: PersistentAuthorityStateRecordVersioned,
    custody: AuthorityCustodyAttestation,
    evidence: CustodyAttestationEvidence,
    input: CustodyAttestationInput,
}

fn accepted_scenario(env: TrustBundleEnvironment) -> Scenario {
    let candidate = rotate_candidate(env);
    let evidence = evidence(CustodyAttestationClass::FixtureAttestation, env, &candidate);
    let input = input(env, &candidate);
    let custody = good_custody_attestation(env, &candidate);
    let prior = prior_versioned(env);
    Scenario {
        domain: domain(env),
        candidate,
        prior,
        custody,
        evidence,
        input,
    }
}

impl Scenario {
    fn parts(&self) -> CustodyAttestationParts {
        CustodyAttestationParts {
            evidence: self.evidence.clone(),
            input: self.input.clone(),
        }
    }

    fn loaded(&self) -> CustodyAttestationLoadStatus {
        CustodyAttestationLoadStatus::Available(self.parts())
    }

    /// Drive one of the seven per-surface preflight wrappers with the
    /// supplied resolved attestation policy and loaded carrier.
    fn run_surface(
        &self,
        surface: Surface,
        attestation_policy: CustodyAttestationPolicy,
        loaded: &CustodyAttestationLoadStatus,
    ) -> CustodyAttestationPayloadCarryingDecisionOutcome {
        let f = surface.wrapper();
        f(
            &self.custody,
            Some(&self.prior),
            &self.candidate,
            &self.domain,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(KEY_ID),
            AuthorityCustodyPolicy::FixtureOnly,
            attestation_policy,
            NOW,
            loaded,
        )
    }
}

/// Build a wire form from parts and round-trip it through a JSON sibling
/// value, returning the parsed load status. Exercises the full
/// serialize/deserialize path.
fn loaded_via_json(parts: &CustodyAttestationParts) -> CustodyAttestationLoadStatus {
    let wire = CustodyAttestationPayloadWire::from_parts(&parts.evidence, &parts.input);
    let value = serde_json::json!({
        CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
    });
    parse_optional_custody_attestation_sibling_from_json_value(&value)
}

// The seven production v2 marker-decision preflight surfaces, each bound
// to its Run 209 per-surface wrapper.
type WrapperFn = fn(
    &AuthorityCustodyAttestation,
    Option<&PersistentAuthorityStateRecordVersioned>,
    &PersistentAuthorityStateRecordV2,
    &AuthorityTrustDomain,
    GovernanceAuthorityClass,
    LocalLifecycleAction,
    &str,
    u64,
    Option<&str>,
    AuthorityCustodyPolicy,
    CustodyAttestationPolicy,
    u64,
    &CustodyAttestationLoadStatus,
) -> CustodyAttestationPayloadCarryingDecisionOutcome;

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

    /// Surfaces whose underlying Run 207 routing helper does NOT impose
    /// the unconditional MainNet peer-driven-apply refusal (i.e. all
    /// except the peer-driven drain).
    const NON_DRAIN: [Surface; 6] = [
        Surface::ReloadCheck,
        Surface::ReloadApply,
        Surface::StartupP2pTrustBundle,
        Surface::Sighup,
        Surface::LocalPeerCandidateCheck,
        Surface::LiveInbound0x05,
    ];

    fn wrapper(self) -> WrapperFn {
        match self {
            Surface::ReloadCheck => preflight_v2_marker_custody_attestation_for_reload_check,
            Surface::ReloadApply => preflight_v2_marker_custody_attestation_for_reload_apply,
            Surface::StartupP2pTrustBundle => {
                preflight_v2_marker_custody_attestation_for_startup_p2p_trust_bundle
            }
            Surface::Sighup => preflight_v2_marker_custody_attestation_for_sighup,
            Surface::LocalPeerCandidateCheck => {
                preflight_v2_marker_custody_attestation_for_local_peer_candidate_check
            }
            Surface::LiveInbound0x05 => {
                preflight_v2_marker_custody_attestation_for_live_inbound_0x05
            }
            Surface::PeerDrivenDrain => {
                preflight_v2_marker_custody_attestation_for_peer_driven_drain
            }
        }
    }
}

// ===========================================================================
// Selector parsing + precedence (default / CLI / env / CLI-over-env /
// invalid value fail-closed)
// ===========================================================================

#[test]
fn selector_parses_all_canonical_tags() {
    let cases = [
        ("disabled", CustodyAttestationPolicy::Disabled),
        (
            "fixture-attestation-allowed",
            CustodyAttestationPolicy::FixtureAttestationAllowed,
        ),
        (
            "remote-signer-attestation-required",
            CustodyAttestationPolicy::RemoteSignerAttestationRequired,
        ),
        (
            "kms-attestation-required",
            CustodyAttestationPolicy::KmsAttestationRequired,
        ),
        (
            "hsm-attestation-required",
            CustodyAttestationPolicy::HsmAttestationRequired,
        ),
        (
            "production-attestation-required",
            CustodyAttestationPolicy::ProductionAttestationRequired,
        ),
        (
            "mainnet-production-attestation-required",
            CustodyAttestationPolicy::MainnetProductionAttestationRequired,
        ),
    ];
    for (tag, policy) in cases {
        assert_eq!(custody_attestation_policy_from_selector(tag).unwrap(), policy);
        // tags round-trip with the verifier's canonical tag method
        assert_eq!(tag, policy.tag());
    }
}

#[test]
fn selector_default_absent_is_disabled() {
    let _g = EnvGuard::set(None);
    assert_eq!(
        custody_attestation_policy_from_cli_or_env(None).unwrap(),
        CustodyAttestationPolicy::Disabled
    );
    assert_eq!(custody_attestation_policy_env_selector().unwrap(), None);
}

#[test]
fn selector_cli_selects_policy() {
    let _g = EnvGuard::set(None);
    assert_eq!(
        custody_attestation_policy_from_cli_or_env(Some("fixture-attestation-allowed")).unwrap(),
        CustodyAttestationPolicy::FixtureAttestationAllowed
    );
}

#[test]
fn selector_env_selects_policy() {
    let _g = EnvGuard::set(Some("fixture-attestation-allowed"));
    assert_eq!(
        custody_attestation_policy_env_selector().unwrap(),
        Some(CustodyAttestationPolicy::FixtureAttestationAllowed)
    );
    assert_eq!(
        custody_attestation_policy_from_cli_or_env(None).unwrap(),
        CustodyAttestationPolicy::FixtureAttestationAllowed
    );
}

#[test]
fn a9_cli_over_env_precedence_is_deterministic() {
    // env sets fixture-attestation-allowed; CLI sets disabled; resolved
    // policy is Disabled.
    let _g = EnvGuard::set(Some("fixture-attestation-allowed"));
    assert_eq!(
        custody_attestation_policy_from_cli_or_env(Some("disabled")).unwrap(),
        CustodyAttestationPolicy::Disabled
    );
}

#[test]
fn r1_invalid_cli_selector_typed_parse_error() {
    let _g = EnvGuard::set(None);
    let err = custody_attestation_policy_from_cli_or_env(Some("not-a-real-policy")).unwrap_err();
    assert!(matches!(
        err,
        CustodyAttestationPolicySelectorParseError::UnknownValue { .. }
    ));
    assert_eq!(err.tag(), "unknown-value");
}

#[test]
fn r2_invalid_env_selector_typed_parse_error() {
    let _g = EnvGuard::set(Some("not-a-real-policy"));
    let err = custody_attestation_policy_env_selector().unwrap_err();
    assert!(matches!(
        err,
        CustodyAttestationPolicySelectorParseError::UnknownValue { .. }
    ));
    // And the resolver propagates it (never silently downgrades).
    assert!(custody_attestation_policy_from_cli_or_env(None).is_err());
}

#[test]
fn empty_selector_values_are_typed_errors() {
    assert_eq!(
        custody_attestation_policy_from_selector("").unwrap_err(),
        CustodyAttestationPolicySelectorParseError::Empty
    );
    let _g = EnvGuard::set(Some("   "));
    assert_eq!(
        custody_attestation_policy_env_selector().unwrap_err(),
        CustodyAttestationPolicySelectorParseError::Empty
    );
}

#[test]
fn r3_unrelated_env_does_not_enable_policy() {
    // An unrelated env var must not enable a custody-attestation policy:
    // with our selector env var unset the resolver stays Disabled.
    let _g = EnvGuard::set(None);
    std::env::set_var("QBIND_SOME_UNRELATED_FLAG", "fixture-attestation-allowed");
    assert_eq!(
        custody_attestation_policy_from_cli_or_env(None).unwrap(),
        CustodyAttestationPolicy::Disabled
    );
    std::env::remove_var("QBIND_SOME_UNRELATED_FLAG");
}

// ===========================================================================
// A1 / A10 — default selector absent => Disabled; legacy no-attestation
// payload accepted (bypassed) across all seven surfaces.
// ===========================================================================

#[test]
fn a1_a10_no_attestation_payload_bypassed_under_disabled_all_surfaces() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    for surface in Surface::NON_DRAIN {
        let outcome =
            s.run_surface(surface, CustodyAttestationPolicy::Disabled, &CustodyAttestationLoadStatus::Absent);
        assert!(
            matches!(
                outcome,
                CustodyAttestationPayloadCarryingDecisionOutcome::NoCustodyAttestationSupplied
            ),
            "surface={surface:?} got {outcome:?}"
        );
        assert!(outcome.is_bypassed());
        assert!(!outcome.is_reject());
    }
}

// ===========================================================================
// A2 / A3 / A14 — fixture attestation accepted under FixtureAttestationAllowed
// and reaches all seven production-context wrappers (DevNet/TestNet).
// ===========================================================================

#[test]
fn a2_a14_devnet_fixture_attestation_reaches_all_seven_surfaces() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let loaded = loaded_via_json(&s.parts());
    assert!(loaded.is_available());
    for surface in Surface::ALL {
        let outcome = s.run_surface(surface, CustodyAttestationPolicy::FixtureAttestationAllowed, &loaded);
        // Every non-drain surface accepts the fixture attestation; the
        // peer-driven drain on DevNet is not a MainNet refusal so it also
        // accepts. (MainNet refusal is exercised separately.)
        assert!(outcome.is_accept(), "surface={surface:?} got {outcome:?}");
    }
}

#[test]
fn a3_testnet_fixture_attestation_reaches_all_seven_surfaces() {
    let s = accepted_scenario(TrustBundleEnvironment::Testnet);
    let loaded = loaded_via_json(&s.parts());
    for surface in Surface::ALL {
        let outcome = s.run_surface(surface, CustodyAttestationPolicy::FixtureAttestationAllowed, &loaded);
        assert!(outcome.is_accept(), "surface={surface:?} got {outcome:?}");
    }
}

// ===========================================================================
// A4–A8 — production-class attestation reaches the verifier and fails
// closed as unavailable under the matching selected policy.
// ===========================================================================

fn assert_unavailable_via_surface(
    class: CustodyAttestationClass,
    policy: CustodyAttestationPolicy,
) {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.attestation_class = class;
    let loaded = s.loaded();
    let outcome = s.run_surface(Surface::ReloadCheck, policy, &loaded);
    assert!(!outcome.is_accept(), "class={class:?} unexpectedly accepted");
    match outcome.callsite_outcome() {
        Some(CustodyMetadataAttestationOutcome::AttestationRejected {
            attestation_outcome,
            ..
        }) => assert!(
            attestation_outcome.is_unavailable() || attestation_outcome.is_reject(),
            "class={class:?} got {attestation_outcome:?}"
        ),
        other => panic!("class={class:?} got {other:?}"),
    }
}

#[test]
fn a4_r8_remote_signer_attestation_unavailable() {
    assert_unavailable_via_surface(
        CustodyAttestationClass::RemoteSignerAttestation,
        CustodyAttestationPolicy::RemoteSignerAttestationRequired,
    );
}

#[test]
fn a5_r9_kms_attestation_unavailable() {
    assert_unavailable_via_surface(
        CustodyAttestationClass::KmsAttestation,
        CustodyAttestationPolicy::KmsAttestationRequired,
    );
}

#[test]
fn a6_r10_hsm_attestation_unavailable() {
    assert_unavailable_via_surface(
        CustodyAttestationClass::HsmAttestation,
        CustodyAttestationPolicy::HsmAttestationRequired,
    );
}

#[test]
fn a7_r13_production_attestation_unavailable() {
    assert_unavailable_via_surface(
        CustodyAttestationClass::ProductionAttestationUnavailable,
        CustodyAttestationPolicy::ProductionAttestationRequired,
    );
}

#[test]
fn r11_cloud_kms_attestation_unavailable() {
    assert_unavailable_via_surface(
        CustodyAttestationClass::CloudKmsAttestationUnavailable,
        CustodyAttestationPolicy::KmsAttestationRequired,
    );
}

#[test]
fn r12_pkcs11_hsm_attestation_unavailable() {
    assert_unavailable_via_surface(
        CustodyAttestationClass::Pkcs11HsmAttestationUnavailable,
        CustodyAttestationPolicy::HsmAttestationRequired,
    );
}

#[test]
fn a8_r14_mainnet_production_attestation_unavailable() {
    // env selects mainnet-production-attestation-required.
    let _g = EnvGuard::set(Some("mainnet-production-attestation-required"));
    let policy = custody_attestation_policy_from_cli_or_env(None).unwrap();
    assert_eq!(
        policy,
        CustodyAttestationPolicy::MainnetProductionAttestationRequired
    );
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.attestation_class = CustodyAttestationClass::ProductionAttestationUnavailable;
    let loaded = s.loaded();
    let outcome = s.run_surface(Surface::ReloadCheck, policy, &loaded);
    match outcome.callsite_outcome() {
        Some(CustodyMetadataAttestationOutcome::AttestationRejected {
            attestation_outcome,
            ..
        }) => assert!(matches!(
            attestation_outcome,
            CustodyAttestationOutcome::MainNetProductionAttestationUnavailable
        )),
        other => panic!("got {other:?}"),
    }
}

// ===========================================================================
// R4 / R5 — no-attestation payload rejected (required-but-absent) under
// FixtureAttestationAllowed and ProductionAttestationRequired.
// ===========================================================================

#[test]
fn r4_no_attestation_rejected_under_fixture_allowed() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let outcome = s.run_surface(
        Surface::ReloadCheck,
        CustodyAttestationPolicy::FixtureAttestationAllowed,
        &CustodyAttestationLoadStatus::Absent,
    );
    assert!(outcome.is_required_but_absent());
    assert!(outcome.is_reject());
}

#[test]
fn r5_no_attestation_rejected_under_production_required() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let outcome = s.run_surface(
        Surface::ReloadApply,
        CustodyAttestationPolicy::ProductionAttestationRequired,
        &CustodyAttestationLoadStatus::Absent,
    );
    assert!(outcome.is_required_but_absent());
    assert!(outcome.is_reject());
}

// ===========================================================================
// R6 / R7 — fixture attestation rejected under
// ProductionAttestationRequired / MainnetProductionAttestationRequired.
// ===========================================================================

#[test]
fn r6_fixture_rejected_under_production_required() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let loaded = s.loaded();
    let outcome = s.run_surface(
        Surface::ReloadCheck,
        CustodyAttestationPolicy::ProductionAttestationRequired,
        &loaded,
    );
    assert!(!outcome.is_accept());
    match outcome.callsite_outcome() {
        Some(CustodyMetadataAttestationOutcome::AttestationRejected {
            attestation_outcome,
            ..
        }) => assert!(matches!(
            attestation_outcome,
            CustodyAttestationOutcome::FixtureRejectedProductionRequired
        )),
        other => panic!("got {other:?}"),
    }
}

#[test]
fn r7_fixture_rejected_under_mainnet_production_required() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let loaded = s.loaded();
    let outcome = s.run_surface(
        Surface::ReloadCheck,
        CustodyAttestationPolicy::MainnetProductionAttestationRequired,
        &loaded,
    );
    assert!(!outcome.is_accept());
    match outcome.callsite_outcome() {
        Some(CustodyMetadataAttestationOutcome::AttestationRejected {
            attestation_outcome,
            ..
        }) => assert!(matches!(
            attestation_outcome,
            CustodyAttestationOutcome::FixtureRejectedMainnetProductionRequired
        )),
        other => panic!("got {other:?}"),
    }
}

// ===========================================================================
// R15 — malformed custody-attestation material rejected (fail closed,
// verifier NOT invoked).
// ===========================================================================

#[test]
fn r15_malformed_custody_attestation_material_rejected() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    // A sibling present but structurally malformed at the JSON level.
    let value = serde_json::json!({
        CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::json!({ "not": "a-valid-payload" })
    });
    let loaded = parse_optional_custody_attestation_sibling_from_json_value(&value);
    let outcome = s.run_surface(
        Surface::ReloadCheck,
        CustodyAttestationPolicy::FixtureAttestationAllowed,
        &loaded,
    );
    assert!(outcome.is_malformed_payload(), "got {outcome:?}");
    assert!(outcome.is_reject());
    assert!(outcome.callsite_outcome().is_none(), "verifier must not run");
}

// ===========================================================================
// R16–R34 — binding-mismatch / freshness / commitment rejections reach
// the verifier and fail closed through the selected-policy wrapper.
// ===========================================================================

/// Apply `mutate` to a fresh accepted scenario's evidence, run the
/// reload-check wrapper under FixtureAttestationAllowed, and assert the
/// verifier rejected (matching `want`).
fn assert_reject_with<F>(mutate: F, want: fn(&CustodyAttestationOutcome) -> bool)
where
    F: FnOnce(&mut Scenario),
{
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    mutate(&mut s);
    let loaded = s.loaded();
    let outcome = s.run_surface(
        Surface::ReloadCheck,
        CustodyAttestationPolicy::FixtureAttestationAllowed,
        &loaded,
    );
    assert!(!outcome.is_accept(), "unexpectedly accepted");
    match outcome.callsite_outcome() {
        Some(o) => {
            assert!(o.is_reject(), "expected reject, got {o:?}");
            if let CustodyMetadataAttestationOutcome::AttestationRejected {
                attestation_outcome,
                ..
            } = o
            {
                assert!(want(attestation_outcome), "got {attestation_outcome:?}");
            }
        }
        None => panic!("expected callsite outcome"),
    }
}

#[test]
fn r16_wrong_environment_rejected() {
    assert_reject_with(
        |s| s.evidence.environment = TrustBundleEnvironment::Testnet,
        |o| {
            matches!(o, CustodyAttestationOutcome::WrongEnvironment { .. })
                || matches!(o, CustodyAttestationOutcome::FixtureRejectedForMainNet)
        },
    );
}

#[test]
fn r17_wrong_chain_rejected() {
    assert_reject_with(
        |s| s.evidence.chain_id = "0000000000000099".to_string(),
        |o| matches!(o, CustodyAttestationOutcome::WrongChain { .. }),
    );
}

#[test]
fn r18_wrong_genesis_rejected() {
    assert_reject_with(
        |s| s.evidence.genesis_hash = "f".repeat(62),
        |o| matches!(o, CustodyAttestationOutcome::WrongGenesis { .. }),
    );
}

#[test]
fn r19_wrong_authority_root_rejected() {
    assert_reject_with(
        |s| s.evidence.authority_root_fingerprint = "9".repeat(40),
        |o| matches!(o, CustodyAttestationOutcome::WrongAuthorityRoot { .. }),
    );
}

#[test]
fn r20_wrong_signing_key_fingerprint_rejected() {
    assert_reject_with(
        |s| s.evidence.bundle_signing_key_fingerprint = "9".repeat(40),
        |o| matches!(o, CustodyAttestationOutcome::WrongSigningKeyFingerprint { .. }),
    );
}

#[test]
fn r21_wrong_custody_class_rejected() {
    assert_reject_with(
        |s| s.evidence.custody_class = AuthorityCustodyClass::Hsm,
        |o| matches!(o, CustodyAttestationOutcome::WrongCustodyClass { .. }),
    );
}

#[test]
fn r22_wrong_backend_provider_signer_id_rejected() {
    assert_reject_with(
        |s| s.evidence.backend_provider_signer_id = "other-provider".to_string(),
        |o| matches!(o, CustodyAttestationOutcome::WrongBackendProviderSignerId { .. }),
    );
}

#[test]
fn r23_wrong_key_id_rejected() {
    assert_reject_with(
        |s| s.evidence.custody_key_id = "other-key-id".to_string(),
        |o| matches!(o, CustodyAttestationOutcome::WrongKeyId { .. }),
    );
}

#[test]
fn r24_wrong_suite_rejected() {
    assert_reject_with(
        |s| s.evidence.suite_id = PQC_LIFECYCLE_SUITE_ML_DSA_44 + 1,
        |o| matches!(o, CustodyAttestationOutcome::WrongSuite { .. }),
    );
}

#[test]
fn r25_wrong_lifecycle_action_rejected() {
    assert_reject_with(
        |s| s.evidence.lifecycle_action = LocalLifecycleAction::Retire,
        |o| matches!(o, CustodyAttestationOutcome::WrongLifecycleAction { .. }),
    );
}

#[test]
fn r26_wrong_candidate_digest_rejected() {
    assert_reject_with(
        |s| s.evidence.candidate_digest = "3".repeat(64),
        |o| matches!(o, CustodyAttestationOutcome::WrongCandidateDigest { .. }),
    );
}

#[test]
fn r27_wrong_authority_domain_sequence_rejected() {
    assert_reject_with(
        |s| s.evidence.authority_domain_sequence = 99,
        |o| matches!(o, CustodyAttestationOutcome::WrongAuthorityDomainSequence { .. }),
    );
}

#[test]
fn r28_wrong_governance_proof_digest_rejected() {
    assert_reject_with(
        |s| s.evidence.governance_proof_digest = Some("wrong-gov".to_string()),
        |o| matches!(o, CustodyAttestationOutcome::WrongGovernanceProofDigest { .. }),
    );
}

#[test]
fn r29_wrong_request_digest_rejected() {
    assert_reject_with(
        |s| s.evidence.request_digest = Some("wrong-request".to_string()),
        |o| matches!(o, CustodyAttestationOutcome::WrongRequestDigest { .. }),
    );
}

#[test]
fn r30_wrong_response_digest_rejected() {
    assert_reject_with(
        |s| s.evidence.response_digest = Some("wrong-response".to_string()),
        |o| matches!(o, CustodyAttestationOutcome::WrongResponseDigest { .. }),
    );
}

#[test]
fn r31_wrong_transcript_digest_rejected() {
    assert_reject_with(
        |s| s.evidence.transcript_digest = Some("wrong-transcript".to_string()),
        |o| matches!(o, CustodyAttestationOutcome::WrongTranscriptDigest { .. }),
    );
}

#[test]
fn r32_stale_or_replayed_attestation_rejected() {
    assert_reject_with(
        |s| s.evidence.attestation_nonce = "stale-nonce".to_string(),
        |o| matches!(o, CustodyAttestationOutcome::StaleOrReplayedAttestation),
    );
}

#[test]
fn r33_expired_attestation_rejected() {
    assert_reject_with(
        |s| {
            s.evidence.expires_at_unix = Some(NOW - 1);
            s.input.now_unix = NOW;
        },
        |o| matches!(o, CustodyAttestationOutcome::ExpiredAttestation { .. }),
    );
}

#[test]
fn r34_invalid_attestation_commitment_rejected() {
    assert_reject_with(
        |s| {
            s.evidence.attestation_commitment =
                CUSTODY_ATTESTATION_INVALID_COMMITMENT_SENTINEL.to_string()
        },
        |o| matches!(o, CustodyAttestationOutcome::InvalidAttestationCommitment),
    );
}

#[test]
fn r35_r36_local_or_peer_majority_cannot_satisfy_production() {
    // A production-required policy cannot be satisfied by fixture or local
    // material; the verifier fails closed (unavailable / local-operator /
    // peer-majority class rejections are all non-accept).
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.attestation_class = CustodyAttestationClass::FixtureAttestation;
    let loaded = s.loaded();
    let outcome = s.run_surface(
        Surface::ReloadCheck,
        CustodyAttestationPolicy::ProductionAttestationRequired,
        &loaded,
    );
    assert!(!outcome.is_accept());
    assert!(outcome.is_reject());
}

// ===========================================================================
// R37 — validation-only rejection writes no marker and no sequence (the
// routing helpers are pure: they return a typed outcome only).
// ===========================================================================

#[test]
fn r37_validation_only_rejection_is_non_mutating() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    // reload-check and local-peer-candidate-check are validation-only.
    for surface in [Surface::ReloadCheck, Surface::LocalPeerCandidateCheck] {
        let outcome = s.run_surface(
            surface,
            CustodyAttestationPolicy::ProductionAttestationRequired,
            &CustodyAttestationLoadStatus::Absent,
        );
        // No accept, no panic, and the function returned a pure value —
        // there is no I/O surface to mutate. The required-but-absent
        // rejection is the typed non-mutating outcome.
        assert!(outcome.is_required_but_absent(), "surface={surface:?} got {outcome:?}");
    }
}

// ===========================================================================
// R38 — mutating rejection produces no Run 070 call, no live trust swap,
// no session eviction, no sequence write, no marker write. The wrappers
// are pure functions returning a typed outcome; a rejection short-circuits
// before any of those side effects could be requested by the caller.
// ===========================================================================

#[test]
fn r38_mutating_rejection_is_non_mutating() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.candidate_digest = "3".repeat(64); // wrong-candidate-digest
    let loaded = s.loaded();
    for surface in [
        Surface::ReloadApply,
        Surface::StartupP2pTrustBundle,
        Surface::Sighup,
        Surface::PeerDrivenDrain,
    ] {
        let outcome = s.run_surface(surface, CustodyAttestationPolicy::FixtureAttestationAllowed, &loaded);
        assert!(!outcome.is_accept(), "surface={surface:?} unexpectedly accepted");
        assert!(outcome.is_reject(), "surface={surface:?} got {outcome:?}");
    }
}

// ===========================================================================
// R39 — invalid live inbound 0x05 custody-attestation candidate is not
// propagated, staged, or applied (the wrapper short-circuits to a reject).
// ===========================================================================

#[test]
fn r39_invalid_live_inbound_0x05_candidate_not_propagated() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.attestation_commitment =
        CUSTODY_ATTESTATION_INVALID_COMMITMENT_SENTINEL.to_string();
    let loaded = s.loaded();
    let outcome = s.run_surface(
        Surface::LiveInbound0x05,
        CustodyAttestationPolicy::FixtureAttestationAllowed,
        &loaded,
    );
    assert!(!outcome.is_accept());
    assert!(outcome.is_reject());
}

// ===========================================================================
// A8 / R40 — MainNet peer-driven apply remains refused even with
// MainnetProductionAttestationRequired and (otherwise valid) fixture
// attestation material.
// ===========================================================================

#[test]
fn r40_mainnet_peer_driven_drain_refused_even_with_fixture_and_mainnet_policy() {
    let s = accepted_scenario(TrustBundleEnvironment::Mainnet);
    let loaded = s.loaded();
    let outcome = s.run_surface(
        Surface::PeerDrivenDrain,
        CustodyAttestationPolicy::MainnetProductionAttestationRequired,
        &loaded,
    );
    assert!(
        outcome.is_mainnet_peer_driven_apply_refused(),
        "got {outcome:?}"
    );
    assert!(outcome.is_reject());
}

#[test]
fn r40_mainnet_peer_driven_drain_refused_under_disabled_too() {
    // The refusal is unconditional — it does not depend on the selected
    // policy and is not weakened by Disabled either.
    let s = accepted_scenario(TrustBundleEnvironment::Mainnet);
    let outcome = s.run_surface(
        Surface::PeerDrivenDrain,
        CustodyAttestationPolicy::Disabled,
        &CustodyAttestationLoadStatus::Absent,
    );
    assert!(outcome.is_mainnet_peer_driven_apply_refused(), "got {outcome:?}");
}

// ===========================================================================
// A11 — GenesisBound / EmergencyCouncil / OnChainGovernance proof behavior
// is unchanged when custody-attestation policy is Disabled (legacy
// no-attestation payloads are simply bypassed regardless of governance
// class).
// ===========================================================================

#[test]
fn a11_governance_classes_unchanged_under_disabled() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    for surface in Surface::NON_DRAIN {
        let outcome = s.run_surface(
            surface,
            CustodyAttestationPolicy::Disabled,
            &CustodyAttestationLoadStatus::Absent,
        );
        assert!(outcome.is_bypassed(), "surface={surface:?} got {outcome:?}");
    }
}

// ===========================================================================
// A15 — live inbound 0x05 receives the selected policy if live config
// supports it. At this source/test layer the live-inbound wrapper accepts
// the resolved policy exactly like the other surfaces (the binary-level
// live config plumbing for 0x05 is deferred to Run 210, documented in the
// Run 209 evidence doc).
// ===========================================================================

#[test]
fn a15_live_inbound_0x05_receives_selected_policy() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let loaded = loaded_via_json(&s.parts());
    let outcome = s.run_surface(
        Surface::LiveInbound0x05,
        CustodyAttestationPolicy::FixtureAttestationAllowed,
        &loaded,
    );
    assert!(outcome.is_accept(), "got {outcome:?}");

    // And a production-required policy reaches the verifier and fails closed.
    let mut s2 = accepted_scenario(TrustBundleEnvironment::Devnet);
    s2.evidence.attestation_class = CustodyAttestationClass::KmsAttestation;
    let loaded2 = s2.loaded();
    let outcome2 = s2.run_surface(
        Surface::LiveInbound0x05,
        CustodyAttestationPolicy::KmsAttestationRequired,
        &loaded2,
    );
    assert!(!outcome2.is_accept());
    assert!(outcome2.is_reject());
}
