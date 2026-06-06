//! Run 198 — source/test hidden RemoteSigner policy selector and
//! production preflight integration tests.
//!
//! Source/test only. Run 198 does **not** capture release-binary
//! evidence; release-binary RemoteSigner-policy selector evidence is
//! deferred to **Run 199**. Default policy remains
//! [`RemoteSignerPolicy::Disabled`]. Fixture loopback RemoteSigner
//! remains DevNet/TestNet evidence-only and cannot satisfy MainNet
//! production RemoteSigner. Real RemoteSigner / KMS / HSM / cloud-KMS /
//! PKCS#11 backends remain unimplemented; every production-class
//! RemoteSigner attempt fails closed via the Run 194 verifier
//! regardless of selector. MainNet peer-driven apply remains the
//! Run 147 / 148 / 152 FATAL refusal regardless of selector, even with
//! `MainnetProductionRemoteSignerRequired` and fixture loopback
//! material. Real on-chain governance proof verification, governance
//! execution, and validator-set rotation all remain unimplemented. Full
//! C4 remains open. C5 remains open.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_198.md`.
//!
//! These tests cover the A1–A11 / R1–R34 matrix from
//! `task/RUN_198_TASK.txt`:
//!
//! * the typed selector parsers
//!   ([`remote_signer_policy_from_selector`],
//!   [`remote_signer_policy_env_selector`],
//!   [`remote_signer_policy_from_cli_or_env`]) including default, CLI,
//!   env, CLI-over-env precedence, and invalid-value fail-closed;
//! * source reachability — the resolved policy reaches all seven
//!   production-context per-surface preflight wrappers
//!   ([`preflight_v2_marker_remote_signer_for_*`]);
//! * accepted scenarios A1–A11 (where representable);
//! * rejection scenarios R1–R34;
//! * no-mutation invariants (validation-only and mutating-rejection);
//! * MainNet refusal invariants (fixture/local rejected on MainNet,
//!   peer-driven drain refuses MainNet regardless of material).
//!
//! The tests construct only data values and call the pure helpers /
//! routing wrappers — no I/O, no marker write, no sequence write, no
//! live trust swap, no session eviction, no Run 070 invocation.

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
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_remote_authority_signer::{
    FixtureLoopbackRemoteSigner, LifecycleCustodyRemoteSignerOutcome, RemoteAuthoritySigner,
    RemoteSignerExpectations, RemoteSignerIdentity, RemoteSignerMode, RemoteSignerOutcome,
    RemoteSignerPolicy, RemoteSignerRequest, RemoteSignerResponse,
};
use qbind_node::pqc_remote_signer_payload_carrying::{
    parse_optional_remote_signer_attestation_sibling_from_json_value,
    RemoteSignerAttestationParts, RemoteSignerAttestationWire, RemoteSignerLoadStatus,
    RemoteSignerPayloadCarryingDecisionOutcome, REMOTE_SIGNER_ATTESTATION_PAYLOAD_SIBLING_FIELD,
};
use qbind_node::pqc_remote_signer_policy_surface::{
    preflight_v2_marker_remote_signer_for_live_inbound_0x05,
    preflight_v2_marker_remote_signer_for_local_peer_candidate_check,
    preflight_v2_marker_remote_signer_for_peer_driven_drain,
    preflight_v2_marker_remote_signer_for_reload_apply,
    preflight_v2_marker_remote_signer_for_reload_check,
    preflight_v2_marker_remote_signer_for_sighup,
    preflight_v2_marker_remote_signer_for_startup_p2p_trust_bundle,
    remote_signer_policy_env_selector, remote_signer_policy_from_cli_or_env,
    remote_signer_policy_from_selector, RemoteSignerPolicySelectorParseError,
    QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY_ENV,
};
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
        let prior = std::env::var(QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY_ENV).ok();
        match value {
            Some(v) => std::env::set_var(QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY_ENV, v),
            None => std::env::remove_var(QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY_ENV),
        }
        EnvGuard { prior, _lock: lock }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.prior.take() {
            Some(v) => std::env::set_var(QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY_ENV, v),
            None => std::env::remove_var(QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY_ENV),
        }
    }
}

// ===========================================================================
// Shared fixtures (mirror the Run 196 corpus exactly so the binding
// tuple matches the Run 194 verifier).
// ===========================================================================

const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT_FP: &str = "1111111111111111111111111111111111111111";
const CHAIN_ID: &str = "0000000000000001";
const GENESIS_HASH: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const PRIOR_DIGEST: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const CUSTODY_ATTEST_DIGEST: &str = "custody-att-digest-198";
const CUSTODY_KEY_ID: &str = "custody-key-id-198";
const SIGNER_ID: &str = "remote-signer-198";
const SIGNER_PUBID: &str = "remote-signer-pubid-198";
const ATTEST_DIGEST: &str = "remote-signer-attest-198";
const REQ_NONCE: &str = "req-nonce-198";
const RESP_NONCE: &str = "resp-nonce-198";
const NOW: u64 = 1_700_000_000;
const FRESH: u64 = 1_699_999_900;
const EXPIRES: u64 = 1_700_001_000;

fn domain(env: TrustBundleEnvironment) -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(env, CHAIN_ID, GENESIS_HASH, ROOT_FP, PQC_LIFECYCLE_SUITE_ML_DSA_44)
}

fn rotate_candidate(env: TrustBundleEnvironment) -> PersistentAuthorityStateRecordV2 {
    PersistentAuthorityStateRecordV2::new(
        CHAIN_ID.to_string(),
        env,
        GENESIS_HASH.to_string(),
        ROOT_FP.to_string(),
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        KEY_B.to_string(),
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(KEY_A.to_string()),
        DIGEST_2.to_string(),
        None,
        AuthorityStateUpdateSource::TestOrFixture,
        NOW,
    )
}

fn prior_versioned(env: TrustBundleEnvironment) -> PersistentAuthorityStateRecordVersioned {
    PersistentAuthorityStateRecordVersioned::V2(PersistentAuthorityStateRecordV2::new(
        CHAIN_ID.to_string(),
        env,
        GENESIS_HASH.to_string(),
        ROOT_FP.to_string(),
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        KEY_A.to_string(),
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        PRIOR_DIGEST.to_string(),
        None,
        AuthorityStateUpdateSource::TestOrFixture,
        NOW,
    ))
}

fn identity(env: TrustBundleEnvironment) -> RemoteSignerIdentity {
    RemoteSignerIdentity {
        signer_id: SIGNER_ID.to_string(),
        signer_public_identity: SIGNER_PUBID.to_string(),
        custody_key_id: CUSTODY_KEY_ID.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        bundle_signing_key_fingerprint: KEY_B.to_string(),
        environment: env,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        supported_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        supported_lifecycle_actions: vec![
            LocalLifecycleAction::Rotate,
            LocalLifecycleAction::ActivateInitial,
        ],
        attestation_digest: ATTEST_DIGEST.to_string(),
        freshness_unix: Some(FRESH),
        expires_at_unix: Some(EXPIRES),
    }
}

fn request(env: TrustBundleEnvironment) -> RemoteSignerRequest {
    RemoteSignerRequest {
        environment: env,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: DIGEST_2.to_string(),
        authority_domain_sequence: 2,
        active_signing_key_fingerprint: Some(KEY_A.to_string()),
        new_signing_key_fingerprint: Some(KEY_B.to_string()),
        revoked_signing_key_fingerprint: None,
        governance_proof_digest: None,
        custody_attestation_digest: CUSTODY_ATTEST_DIGEST.to_string(),
        replay_nonce: REQ_NONCE.to_string(),
        request_timestamp_unix: Some(NOW),
    }
}

fn fixture_signer(env: TrustBundleEnvironment) -> FixtureLoopbackRemoteSigner {
    FixtureLoopbackRemoteSigner {
        identity: identity(env),
        response_nonce: RESP_NONCE.to_string(),
        response_freshness_unix: Some(FRESH),
        response_expires_at_unix: Some(EXPIRES),
    }
}

fn fixture_response(env: TrustBundleEnvironment) -> RemoteSignerResponse {
    fixture_signer(env)
        .sign(&request(env))
        .expect("fixture loopback signs")
}

/// A well-formed response that claims `Production` signer mode (no real
/// production backend exists; the verifier refuses it as unavailable).
fn production_response(env: TrustBundleEnvironment) -> RemoteSignerResponse {
    let mut resp = fixture_response(env);
    resp.signer_mode = RemoteSignerMode::Production;
    resp
}

fn expectations() -> RemoteSignerExpectations {
    RemoteSignerExpectations {
        expected_lifecycle_action: LocalLifecycleAction::Rotate,
        expected_candidate_digest: DIGEST_2.to_string(),
        expected_authority_domain_sequence: 2,
        expected_custody_key_id: CUSTODY_KEY_ID.to_string(),
        expected_signing_key_fingerprint: KEY_B.to_string(),
        expected_custody_attestation_digest: CUSTODY_ATTEST_DIGEST.to_string(),
        expected_request_nonce: REQ_NONCE.to_string(),
        expected_response_nonce: RESP_NONCE.to_string(),
        now_unix: NOW,
    }
}

fn custody_attestation(
    env: TrustBundleEnvironment,
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
        bundle_signing_key_fingerprint: KEY_B.to_string(),
        governance_authority_class: GovernanceAuthorityClass::GenesisBound,
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: DIGEST_2.to_string(),
        authority_domain_sequence: 2,
    }
}

fn parts(env: TrustBundleEnvironment) -> RemoteSignerAttestationParts {
    RemoteSignerAttestationParts {
        identity: identity(env),
        request: request(env),
        response: fixture_response(env),
    }
}

/// Wrap parts as an `Available` load status by round-tripping through
/// the wire form (exercises the full payload-carrying path).
fn available_via_wire(p: &RemoteSignerAttestationParts) -> RemoteSignerLoadStatus {
    let wire = RemoteSignerAttestationWire::from_parts(&p.identity, &p.request, &p.response);
    let value = serde_json::json!({
        REMOTE_SIGNER_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
    });
    let loaded = parse_optional_remote_signer_attestation_sibling_from_json_value(&value);
    assert!(loaded.is_available(), "expected available, got {loaded:?}");
    loaded
}

fn malformed_loaded(
    mutate: impl FnOnce(&mut RemoteSignerAttestationWire),
) -> RemoteSignerLoadStatus {
    let p = parts(TrustBundleEnvironment::Devnet);
    let mut wire = RemoteSignerAttestationWire::from_parts(&p.identity, &p.request, &p.response);
    mutate(&mut wire);
    let value = serde_json::json!({
        REMOTE_SIGNER_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
    });
    parse_optional_remote_signer_attestation_sibling_from_json_value(&value)
}

/// Owning bundle so a preflight wrapper can borrow.
struct Ctx {
    custody: AuthorityCustodyAttestation,
    candidate: PersistentAuthorityStateRecordV2,
    prior: PersistentAuthorityStateRecordVersioned,
    domain: AuthorityTrustDomain,
    expected: RemoteSignerExpectations,
}

fn ctx_for(env: TrustBundleEnvironment, custody_class: AuthorityCustodyClass) -> Ctx {
    Ctx {
        custody: custody_attestation(env, custody_class),
        candidate: rotate_candidate(env),
        prior: prior_versioned(env),
        domain: domain(env),
        expected: expectations(),
    }
}

/// Identifies which of the seven production v2 marker-decision preflight
/// surfaces to drive.
#[derive(Clone, Copy, Debug)]
enum Surface {
    ReloadCheck,
    ReloadApply,
    Startup,
    Sighup,
    LocalPeerCandidateCheck,
    LiveInbound0x05,
    PeerDrivenDrain,
}

const ALL_SURFACES: [Surface; 7] = [
    Surface::ReloadCheck,
    Surface::ReloadApply,
    Surface::Startup,
    Surface::Sighup,
    Surface::LocalPeerCandidateCheck,
    Surface::LiveInbound0x05,
    Surface::PeerDrivenDrain,
];

/// Drive the chosen per-surface Run 198 preflight wrapper with the given
/// resolved RemoteSigner policy and a parsed carrier.
#[allow(clippy::too_many_arguments)]
fn preflight(
    surface: Surface,
    c: &Ctx,
    custody_policy: AuthorityCustodyPolicy,
    remote_signer_policy: RemoteSignerPolicy,
    loaded: &RemoteSignerLoadStatus,
) -> RemoteSignerPayloadCarryingDecisionOutcome {
    let f = match surface {
        Surface::ReloadCheck => preflight_v2_marker_remote_signer_for_reload_check,
        Surface::ReloadApply => preflight_v2_marker_remote_signer_for_reload_apply,
        Surface::Startup => preflight_v2_marker_remote_signer_for_startup_p2p_trust_bundle,
        Surface::Sighup => preflight_v2_marker_remote_signer_for_sighup,
        Surface::LocalPeerCandidateCheck => {
            preflight_v2_marker_remote_signer_for_local_peer_candidate_check
        }
        Surface::LiveInbound0x05 => preflight_v2_marker_remote_signer_for_live_inbound_0x05,
        Surface::PeerDrivenDrain => preflight_v2_marker_remote_signer_for_peer_driven_drain,
    };
    f(
        &c.custody,
        Some(&c.prior),
        &c.candidate,
        &c.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        custody_policy,
        &c.expected,
        remote_signer_policy,
        NOW,
        loaded,
    )
}

/// Convenience: drive the reload-check surface (the canonical
/// validation-only entry) with an `Available` carrier built directly
/// from parts.
fn route_available(
    env: TrustBundleEnvironment,
    custody_class: AuthorityCustodyClass,
    custody_policy: AuthorityCustodyPolicy,
    remote_signer_policy: RemoteSignerPolicy,
    p: RemoteSignerAttestationParts,
) -> RemoteSignerPayloadCarryingDecisionOutcome {
    let c = ctx_for(env, custody_class);
    let loaded = RemoteSignerLoadStatus::Available(p);
    preflight(
        Surface::ReloadCheck,
        &c,
        custody_policy,
        remote_signer_policy,
        &loaded,
    )
}

fn assert_remote_signer_reject(
    outcome: &RemoteSignerPayloadCarryingDecisionOutcome,
) -> RemoteSignerOutcome {
    assert!(outcome.is_reject(), "expected reject, got {outcome:?}");
    match outcome.callsite_outcome().unwrap() {
        LifecycleCustodyRemoteSignerOutcome::RemoteSignerRejected {
            remote_signer_outcome,
            ..
        } => remote_signer_outcome.clone(),
        other => panic!("expected RemoteSignerRejected, got {other:?}"),
    }
}

// ===========================================================================
// Selector parsing + precedence
// ===========================================================================

#[test]
fn selector_parses_all_canonical_tags() {
    assert_eq!(
        remote_signer_policy_from_selector("disabled").unwrap(),
        RemoteSignerPolicy::Disabled
    );
    assert_eq!(
        remote_signer_policy_from_selector("fixture-loopback-allowed").unwrap(),
        RemoteSignerPolicy::FixtureLoopbackAllowed
    );
    assert_eq!(
        remote_signer_policy_from_selector("production-remote-signer-required").unwrap(),
        RemoteSignerPolicy::ProductionRemoteSignerRequired
    );
    assert_eq!(
        remote_signer_policy_from_selector("mainnet-production-remote-signer-required").unwrap(),
        RemoteSignerPolicy::MainnetProductionRemoteSignerRequired
    );
}

#[test]
fn selector_is_case_insensitive_and_trims() {
    assert_eq!(
        remote_signer_policy_from_selector("  FIXTURE-LOOPBACK-ALLOWED ").unwrap(),
        RemoteSignerPolicy::FixtureLoopbackAllowed
    );
}

#[test]
fn r1_invalid_cli_selector_value_rejected() {
    assert!(matches!(
        remote_signer_policy_from_cli_or_env(Some("kms-required")).unwrap_err(),
        RemoteSignerPolicySelectorParseError::UnknownValue { .. }
    ));
    assert_eq!(
        remote_signer_policy_from_cli_or_env(Some("")).unwrap_err(),
        RemoteSignerPolicySelectorParseError::Empty
    );
}

#[test]
fn r2_invalid_env_selector_value_rejected() {
    let _g = EnvGuard::set(Some("totally-bogus"));
    assert!(matches!(
        remote_signer_policy_env_selector().unwrap_err(),
        RemoteSignerPolicySelectorParseError::UnknownValue { .. }
    ));
    // Resolver with absent CLI must propagate the typed env error.
    assert!(matches!(
        remote_signer_policy_from_cli_or_env(None).unwrap_err(),
        RemoteSignerPolicySelectorParseError::UnknownValue { .. }
    ));
}

#[test]
fn a1_default_selector_absent_is_disabled() {
    let _g = EnvGuard::set(None);
    assert_eq!(
        remote_signer_policy_env_selector().unwrap(),
        None,
        "absent env yields None"
    );
    assert_eq!(
        remote_signer_policy_from_cli_or_env(None).unwrap(),
        RemoteSignerPolicy::Disabled
    );
}

#[test]
fn a2_cli_fixture_loopback_selects_fixture_loopback() {
    let _g = EnvGuard::set(None);
    assert_eq!(
        remote_signer_policy_from_cli_or_env(Some("fixture-loopback-allowed")).unwrap(),
        RemoteSignerPolicy::FixtureLoopbackAllowed
    );
}

#[test]
fn a3_env_fixture_loopback_selects_fixture_loopback() {
    let _g = EnvGuard::set(Some("fixture-loopback-allowed"));
    assert_eq!(
        remote_signer_policy_from_cli_or_env(None).unwrap(),
        RemoteSignerPolicy::FixtureLoopbackAllowed
    );
}

#[test]
fn a4_cli_production_required_selects_production_required() {
    let _g = EnvGuard::set(None);
    assert_eq!(
        remote_signer_policy_from_cli_or_env(Some("production-remote-signer-required")).unwrap(),
        RemoteSignerPolicy::ProductionRemoteSignerRequired
    );
}

#[test]
fn a5_env_mainnet_production_required_selects_mainnet_production_required() {
    let _g = EnvGuard::set(Some("mainnet-production-remote-signer-required"));
    assert_eq!(
        remote_signer_policy_from_cli_or_env(None).unwrap(),
        RemoteSignerPolicy::MainnetProductionRemoteSignerRequired
    );
}

#[test]
fn a6_cli_over_env_precedence_is_deterministic() {
    let _g = EnvGuard::set(Some("fixture-loopback-allowed"));
    // CLI `disabled` wins over env `fixture-loopback-allowed`.
    assert_eq!(
        remote_signer_policy_from_cli_or_env(Some("disabled")).unwrap(),
        RemoteSignerPolicy::Disabled
    );
}

#[test]
fn r3_unrelated_env_does_not_enable_remote_signer_policy() {
    let _g = EnvGuard::set(None);
    // An unrelated env var set must not be observed by the selector.
    std::env::set_var("QBIND_SOME_UNRELATED_FLAG", "fixture-loopback-allowed");
    assert_eq!(
        remote_signer_policy_from_cli_or_env(None).unwrap(),
        RemoteSignerPolicy::Disabled
    );
    std::env::remove_var("QBIND_SOME_UNRELATED_FLAG");
}

// ===========================================================================
// Source reachability — resolved policy reaches all seven surfaces
// ===========================================================================

#[test]
fn reachability_resolved_policy_reaches_all_seven_surfaces_accept() {
    // A valid DevNet fixture loopback carrier under FixtureLoopbackAllowed
    // is accepted at every non-peer-driven surface and at the
    // peer-driven drain surface (non-MainNet candidate).
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let loaded = available_via_wire(&parts(TrustBundleEnvironment::Devnet));
    for surface in ALL_SURFACES {
        let outcome = preflight(
            surface,
            &c,
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
            &loaded,
        );
        assert!(outcome.is_accept(), "surface {surface:?} should accept, got {outcome:?}");
    }
}

#[test]
fn reachability_resolved_policy_reaches_all_seven_surfaces_required_but_absent() {
    // Absent carrier under an explicit non-Disabled policy fails closed
    // at every surface.
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let loaded = RemoteSignerLoadStatus::Absent;
    for surface in ALL_SURFACES {
        let outcome = preflight(
            surface,
            &c,
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
            &loaded,
        );
        assert!(
            outcome.is_required_but_absent(),
            "surface {surface:?} should be required-but-absent, got {outcome:?}"
        );
        assert!(outcome.is_reject());
    }
}

// ===========================================================================
// Accepted scenarios A1–A11 (routing through the preflight wrappers)
// ===========================================================================

#[test]
fn a1_no_remote_signer_payload_compatible_under_default_disabled() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let loaded = RemoteSignerLoadStatus::Absent;
    let outcome = preflight(
        Surface::ReloadCheck,
        &c,
        AuthorityCustodyPolicy::Disabled,
        RemoteSignerPolicy::default(),
        &loaded,
    );
    assert_eq!(
        outcome,
        RemoteSignerPayloadCarryingDecisionOutcome::NoRemoteSignerSupplied
    );
    assert!(outcome.is_bypassed());
    assert!(!outcome.is_accept());
    assert!(!outcome.is_reject());
}

#[test]
fn a2_devnet_fixture_loopback_accepted_under_fixture_loopback_allowed() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let loaded = available_via_wire(&parts(TrustBundleEnvironment::Devnet));
    let outcome = preflight(
        Surface::ReloadCheck,
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        &loaded,
    );
    assert!(outcome.is_accept(), "expected accept, got {outcome:?}");
    assert!(matches!(
        outcome.callsite_outcome().unwrap(),
        LifecycleCustodyRemoteSignerOutcome::Accepted { .. }
    ));
}

#[test]
fn a3_testnet_fixture_loopback_accepted_under_fixture_loopback_allowed() {
    let c = ctx_for(TrustBundleEnvironment::Testnet, AuthorityCustodyClass::FixtureLocalKey);
    let loaded = available_via_wire(&parts(TrustBundleEnvironment::Testnet));
    let outcome = preflight(
        Surface::ReloadCheck,
        &c,
        AuthorityCustodyPolicy::TestnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        &loaded,
    );
    assert!(outcome.is_accept(), "expected accept, got {outcome:?}");
}

#[test]
fn a4_production_remote_signer_reaches_boundary_and_fails_closed() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.response = production_response(TrustBundleEnvironment::Devnet);
    let loaded = RemoteSignerLoadStatus::Available(p);
    let outcome = preflight(
        Surface::ReloadCheck,
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::ProductionRemoteSignerRequired,
        &loaded,
    );
    assert!(assert_remote_signer_reject(&outcome).is_production_unavailable());
}

#[test]
fn a5_mainnet_production_remote_signer_unavailable_outcome_reached() {
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.response = production_response(TrustBundleEnvironment::Devnet);
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::MainnetProductionRemoteSignerRequired,
        p,
    );
    assert_eq!(
        assert_remote_signer_reject(&outcome),
        RemoteSignerOutcome::MainNetProductionRemoteSignerUnavailable
    );
}

#[test]
fn a7_no_remote_signer_payload_compatible_under_default_disabled_other_classes() {
    for class in [
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyClass::LocalOperatorKey,
        AuthorityCustodyClass::Kms,
        AuthorityCustodyClass::Hsm,
    ] {
        let c = ctx_for(TrustBundleEnvironment::Devnet, class);
        let outcome = preflight(
            Surface::ReloadCheck,
            &c,
            AuthorityCustodyPolicy::Disabled,
            RemoteSignerPolicy::Disabled,
            &RemoteSignerLoadStatus::Absent,
        );
        assert!(outcome.is_bypassed(), "class {class:?} should bypass");
    }
}

#[test]
fn a8_governance_classes_unchanged_when_remote_signer_policy_disabled() {
    for class in [
        GovernanceAuthorityClass::GenesisBound,
        GovernanceAuthorityClass::EmergencyCouncil,
        GovernanceAuthorityClass::OnChainGovernance,
    ] {
        let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
        let outcome = preflight_v2_marker_remote_signer_for_reload_check(
            &c.custody,
            Some(&c.prior),
            &c.candidate,
            &c.domain,
            class,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(CUSTODY_KEY_ID),
            AuthorityCustodyPolicy::Disabled,
            &c.expected,
            RemoteSignerPolicy::Disabled,
            NOW,
            &RemoteSignerLoadStatus::Absent,
        );
        assert!(outcome.is_bypassed(), "class {class:?} should bypass");
    }
}

#[test]
fn a10_mutating_devnet_fixture_loopback_accepted_under_fixture_loopback_allowed() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let loaded = available_via_wire(&parts(TrustBundleEnvironment::Devnet));
    for surface in [Surface::ReloadApply, Surface::Startup, Surface::Sighup] {
        let outcome = preflight(
            surface,
            &c,
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
            &loaded,
        );
        assert!(outcome.is_accept(), "surface {surface:?} should accept, got {outcome:?}");
    }
}

#[test]
fn a11_live_inbound_0x05_receives_selected_policy() {
    // The live inbound 0x05 validation-only surface receives the resolved
    // policy and accepts valid DevNet fixture loopback material.
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let loaded = available_via_wire(&parts(TrustBundleEnvironment::Devnet));
    let outcome = preflight(
        Surface::LiveInbound0x05,
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        &loaded,
    );
    assert!(outcome.is_accept(), "expected accept, got {outcome:?}");
}

// ===========================================================================
// Rejection scenarios R4–R34
// ===========================================================================

#[test]
fn r4_no_remote_signer_payload_rejected_under_fixture_loopback_allowed() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let outcome = preflight(
        Surface::ReloadCheck,
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        &RemoteSignerLoadStatus::Absent,
    );
    assert!(outcome.is_required_but_absent());
    assert!(outcome.is_reject());
}

#[test]
fn r5_no_remote_signer_payload_rejected_under_production_required() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let outcome = preflight(
        Surface::ReloadCheck,
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::ProductionRemoteSignerRequired,
        &RemoteSignerLoadStatus::Absent,
    );
    assert!(outcome.is_required_but_absent());
}

#[test]
fn r6_fixture_rejected_under_production_required() {
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::ProductionRemoteSignerRequired,
        parts(TrustBundleEnvironment::Devnet),
    );
    assert_eq!(
        assert_remote_signer_reject(&outcome),
        RemoteSignerOutcome::FixtureRejectedProductionRequired
    );
}

#[test]
fn r7_fixture_rejected_under_mainnet_production_required() {
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::MainnetProductionRemoteSignerRequired,
        parts(TrustBundleEnvironment::Devnet),
    );
    assert_eq!(
        assert_remote_signer_reject(&outcome),
        RemoteSignerOutcome::FixtureRejectedMainnetProductionRequired
    );
}

#[test]
fn r8_production_rejected_as_unavailable() {
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.response = production_response(TrustBundleEnvironment::Devnet);
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        p,
    );
    assert_eq!(
        assert_remote_signer_reject(&outcome),
        RemoteSignerOutcome::ProductionRemoteSignerUnavailable
    );
}

#[test]
fn r9_mainnet_production_rejected_as_unavailable() {
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.response = production_response(TrustBundleEnvironment::Devnet);
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::MainnetProductionRemoteSignerRequired,
        p,
    );
    assert_eq!(
        assert_remote_signer_reject(&outcome),
        RemoteSignerOutcome::MainNetProductionRemoteSignerUnavailable
    );
}

#[test]
fn r10_wrong_environment_rejected() {
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.request.environment = TrustBundleEnvironment::Testnet;
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        p,
    );
    assert!(matches!(
        assert_remote_signer_reject(&outcome),
        RemoteSignerOutcome::WrongEnvironment { .. }
    ));
}

#[test]
fn r11_wrong_chain_rejected() {
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.request.chain_id = "00000000000000ff".to_string();
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        p,
    );
    assert!(matches!(
        assert_remote_signer_reject(&outcome),
        RemoteSignerOutcome::WrongChain { .. }
    ));
}

#[test]
fn r12_wrong_genesis_rejected() {
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.request.genesis_hash =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string();
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        p,
    );
    assert!(matches!(
        assert_remote_signer_reject(&outcome),
        RemoteSignerOutcome::WrongGenesis { .. }
    ));
}

#[test]
fn r13_wrong_authority_root_rejected() {
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.request.authority_root_fingerprint =
        "9999999999999999999999999999999999999999".to_string();
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        p,
    );
    assert!(matches!(
        assert_remote_signer_reject(&outcome),
        RemoteSignerOutcome::WrongAuthorityRoot { .. }
    ));
}

#[test]
fn r14_wrong_custody_key_id_rejected() {
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.response.custody_key_id = "wrong-custody-key".to_string();
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        p,
    );
    assert!(matches!(
        assert_remote_signer_reject(&outcome),
        RemoteSignerOutcome::WrongCustodyKeyId { .. }
    ));
}

#[test]
fn r15_wrong_signing_key_fingerprint_rejected() {
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.request.new_signing_key_fingerprint =
        Some("cccccccccccccccccccccccccccccccccccccccc".to_string());
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        p,
    );
    assert!(matches!(
        assert_remote_signer_reject(&outcome),
        RemoteSignerOutcome::WrongSigningKeyFingerprint { .. }
    ));
}

#[test]
fn r16_wrong_lifecycle_action_rejected() {
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.request.lifecycle_action = LocalLifecycleAction::Revoke;
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        p,
    );
    assert!(matches!(
        assert_remote_signer_reject(&outcome),
        RemoteSignerOutcome::WrongLifecycleAction { .. }
    ));
}

#[test]
fn r17_wrong_candidate_digest_rejected() {
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.request.candidate_digest =
        "3333333333333333333333333333333333333333333333333333333333333333".to_string();
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        p,
    );
    assert!(matches!(
        assert_remote_signer_reject(&outcome),
        RemoteSignerOutcome::WrongCandidateDigest { .. }
    ));
}

#[test]
fn r18_wrong_authority_domain_sequence_rejected() {
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.request.authority_domain_sequence = 7;
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        p,
    );
    assert!(matches!(
        assert_remote_signer_reject(&outcome),
        RemoteSignerOutcome::WrongAuthorityDomainSequence { .. }
    ));
}

#[test]
fn r19_wrong_request_digest_rejected() {
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.response.request_digest = "deadbeef".to_string();
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        p,
    );
    assert!(matches!(
        assert_remote_signer_reject(&outcome),
        RemoteSignerOutcome::WrongRequestDigest { .. }
    ));
}

#[test]
fn r20_stale_or_replayed_request_rejected() {
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.request.replay_nonce = "stale-req-nonce".to_string();
    p.response.request_digest = p.request.canonical_digest();
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        p,
    );
    assert!(matches!(
        assert_remote_signer_reject(&outcome),
        RemoteSignerOutcome::StaleOrReplayedRequest { .. }
    ));
}

#[test]
fn r21_stale_or_replayed_response_rejected() {
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.response.response_nonce = "stale-resp-nonce".to_string();
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        p,
    );
    assert!(matches!(
        assert_remote_signer_reject(&outcome),
        RemoteSignerOutcome::StaleOrReplayedResponse { .. }
    ));
}

#[test]
fn r22_expired_attestation_rejected() {
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.identity.expires_at_unix = Some(NOW - 1);
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        p,
    );
    assert!(matches!(
        assert_remote_signer_reject(&outcome),
        RemoteSignerOutcome::ExpiredAttestation { .. }
    ));
}

#[test]
fn r23_expired_response_rejected() {
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.response.expires_at_unix = Some(NOW - 1);
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        p,
    );
    assert!(matches!(
        assert_remote_signer_reject(&outcome),
        RemoteSignerOutcome::ExpiredResponse { .. }
    ));
}

#[test]
fn r24_unsupported_suite_rejected() {
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.response.signature_suite_id = 0xEE;
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        p,
    );
    assert!(matches!(
        assert_remote_signer_reject(&outcome),
        RemoteSignerOutcome::UnsupportedSuite { .. }
    ));
}

#[test]
fn r25_invalid_signature_rejected() {
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.response.signature_commitment =
        qbind_node::pqc_remote_authority_signer::REMOTE_SIGNER_INVALID_SIGNATURE_SENTINEL
            .to_string();
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        p,
    );
    assert_eq!(
        assert_remote_signer_reject(&outcome),
        RemoteSignerOutcome::InvalidSignature
    );
}

#[test]
fn r26_malformed_remote_signer_material_rejected() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let loaded = malformed_loaded(|w| w.identity.signer_public_identity = String::new());
    let outcome = preflight(
        Surface::ReloadCheck,
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        &loaded,
    );
    assert!(outcome.is_malformed_payload());
    assert!(outcome.is_reject());
    assert!(outcome.callsite_outcome().is_none(), "verifier not reached");
}

#[test]
fn r27_local_operator_key_cannot_satisfy_remote_signer() {
    // A LocalOperatorKey custody candidate cannot satisfy RemoteSigner:
    // the Run 188 custody validation rejects the candidate before the
    // RemoteSigner is consulted under FixtureLoopbackAllowed.
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::LocalOperatorKey);
    let loaded = available_via_wire(&parts(TrustBundleEnvironment::Devnet));
    let outcome = preflight(
        Surface::ReloadCheck,
        &c,
        AuthorityCustodyPolicy::ProductionCustodyRequired,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        &loaded,
    );
    assert!(outcome.is_reject());
}

#[test]
fn r28_peer_majority_cannot_satisfy_remote_signer() {
    assert!(qbind_node::pqc_remote_authority_signer::peer_majority_cannot_satisfy_remote_signer());
}

#[test]
fn r29_remote_signer_valid_but_custody_metadata_invalid_rejected() {
    let mut c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    c.custody.candidate_digest =
        "3333333333333333333333333333333333333333333333333333333333333333".to_string();
    let loaded = available_via_wire(&parts(TrustBundleEnvironment::Devnet));
    let outcome = preflight(
        Surface::ReloadCheck,
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        &loaded,
    );
    assert!(outcome.is_reject());
    assert!(matches!(
        outcome.callsite_outcome().unwrap(),
        LifecycleCustodyRemoteSignerOutcome::LifecycleOrCustodyRejected(_)
    ));
}

#[test]
fn r30_custody_valid_but_remote_signer_response_invalid_rejected() {
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.response.signature_commitment =
        qbind_node::pqc_remote_authority_signer::REMOTE_SIGNER_INVALID_SIGNATURE_SENTINEL
            .to_string();
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        p,
    );
    assert_eq!(
        assert_remote_signer_reject(&outcome),
        RemoteSignerOutcome::InvalidSignature
    );
}

#[test]
fn r31_validation_only_rejection_is_pure_no_mutation() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let loaded = malformed_loaded(|w| w.response.signature_commitment = String::new());
    let a = preflight(
        Surface::ReloadCheck,
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        &loaded,
    );
    let b = preflight(
        Surface::LocalPeerCandidateCheck,
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        &loaded,
    );
    assert!(a.is_reject());
    assert_eq!(a, b, "pure routing wrappers are deterministic");
}

#[test]
fn r32_mutating_rejection_produces_no_mutation() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let loaded = malformed_loaded(|w| w.identity.attestation_digest = String::new());
    for surface in [Surface::ReloadApply, Surface::Startup, Surface::Sighup] {
        let outcome = preflight(
            surface,
            &c,
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
            &loaded,
        );
        assert!(outcome.is_malformed_payload(), "surface {surface:?}");
        assert!(outcome.is_reject());
        assert!(outcome.callsite_outcome().is_none(), "verifier not reached");
    }
}

#[test]
fn r33_invalid_live_0x05_remote_signer_not_propagated() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let loaded = malformed_loaded(|w| w.response.response_nonce = String::new());
    let outcome = preflight(
        Surface::LiveInbound0x05,
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        &loaded,
    );
    assert!(outcome.is_malformed_payload());
    assert!(outcome.is_reject());
    assert!(outcome.callsite_outcome().is_none(), "verifier not reached");
}

#[test]
fn r34_mainnet_peer_driven_apply_refused_even_with_fixture_loopback() {
    // Even with MainnetProductionRemoteSignerRequired *and* fully-valid
    // fixture loopback material, MainNet peer-driven apply is refused
    // unconditionally at the drain surface.
    let c = ctx_for(TrustBundleEnvironment::Mainnet, AuthorityCustodyClass::FixtureLocalKey);
    let loaded = available_via_wire(&parts(TrustBundleEnvironment::Mainnet));
    for policy in [
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        RemoteSignerPolicy::MainnetProductionRemoteSignerRequired,
    ] {
        let outcome = preflight(
            Surface::PeerDrivenDrain,
            &c,
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            policy,
            &loaded,
        );
        assert!(
            outcome.is_mainnet_peer_driven_apply_refused(),
            "policy {policy:?} must not weaken MainNet refusal"
        );
        assert!(outcome.is_reject());
    }
}
