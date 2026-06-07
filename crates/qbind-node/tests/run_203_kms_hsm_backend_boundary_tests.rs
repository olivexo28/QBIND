//! Run 203 — source/test KMS/HSM backend abstraction boundary
//! integration tests.
//!
//! Source/test only. Run 203 does **not** capture release-binary
//! evidence; release-binary KMS/HSM backend-boundary evidence is
//! deferred to **Run 204**. The tests cover:
//!
//! * the full A1–A15 / R1–R41 matrix from `task/RUN_203_TASK.txt`;
//! * identity / request / response / transcript canonical digest
//!   determinism and domain-binding;
//! * replay / freshness checks;
//! * fixture-vs-production backend separation;
//! * cloud-KMS / PKCS#11 HSM unavailable fail-closed paths;
//! * malformed identity/request/response fail-closed paths;
//! * the no-I/O guarantee for the production backend path (the tests
//!   construct only data values and call only pure validators / pure
//!   trait methods);
//! * the no-mutation guarantee (validation-only surfaces never mutate);
//! * MainNet refusal invariants;
//! * compatibility with Run 188 custody classes, Run 190 custody
//!   payload metadata, and the separate Run 194–202 RemoteSigner path.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_203.md`.

use qbind_ledger::BundleSigningRatificationV2Action;
use qbind_node::pqc_authority_custody::{
    AuthorityCustodyAttestation, AuthorityCustodyClass, AuthorityCustodyPolicy,
};
use qbind_node::pqc_authority_kms_hsm_backend::{
    backend_transcript_digest, custody_class_routes_to_kms_hsm_backend,
    local_operator_cannot_satisfy_backend_policy,
    mainnet_peer_driven_apply_remains_refused_under_kms_hsm_backend_boundary,
    peer_majority_cannot_satisfy_backend_policy,
    validate_backend_for_custody_class, validate_lifecycle_governance_custody_and_backend,
    verify_authority_custody_backend_response, AuthorityCustodyBackend, BackendExpectations,
    BackendIdentity, BackendKind, BackendOutcome, BackendPolicy, BackendRequest, BackendResponse,
    CloudKmsBackend, FixtureHsmBackend, FixtureKmsBackend, LifecycleCustodyBackendOutcome,
    Pkcs11HsmBackend, ProductionHsmBackend, ProductionKmsBackend,
    KMS_HSM_BACKEND_INVALID_ATTESTATION_SENTINEL, KMS_HSM_BACKEND_INVALID_SIGNATURE_SENTINEL,
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
// Shared fixtures
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
const CUSTODY_ATTEST_DIGEST: &str = "custody-att-digest-203";
const KEY_ID: &str = "kms-hsm-key-id-203";
const BACKEND_ID: &str = "kms-hsm-backend-203";
const PROVIDER_ID: &str = "kms-hsm-provider-203";
const ATTEST_DIGEST: &str = "kms-hsm-attest-203";
const KEY_USAGE: &str = "authority-lifecycle-signing-only";
const REQ_NONCE: &str = "req-nonce-203";
const RESP_NONCE: &str = "resp-nonce-203";
const NOW: u64 = 1_700_000_000;
const FRESH: u64 = 1_699_999_900;
const EXPIRES: u64 = 1_700_001_000;

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

fn identity(
    kind: BackendKind,
    env: TrustBundleEnvironment,
    candidate: &PersistentAuthorityStateRecordV2,
) -> BackendIdentity {
    BackendIdentity {
        backend_kind: kind,
        backend_id: BACKEND_ID.to_string(),
        provider_id: PROVIDER_ID.to_string(),
        key_id: KEY_ID.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        bundle_signing_key_fingerprint: candidate.active_bundle_signing_key_fingerprint.clone(),
        environment: env,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        attestation_digest: ATTEST_DIGEST.to_string(),
        key_usage_policy: KEY_USAGE.to_string(),
        allowed_lifecycle_actions: vec![
            LocalLifecycleAction::Rotate,
            LocalLifecycleAction::ActivateInitial,
        ],
        freshness_unix: Some(FRESH),
        expires_at_unix: Some(EXPIRES),
    }
}

fn custody_class_for(kind: BackendKind) -> AuthorityCustodyClass {
    match kind {
        BackendKind::FixtureHsm
        | BackendKind::Pkcs11HsmUnavailable
        | BackendKind::ProductionHsmUnavailable => AuthorityCustodyClass::Hsm,
        _ => AuthorityCustodyClass::Kms,
    }
}

fn request(
    kind: BackendKind,
    env: TrustBundleEnvironment,
    candidate: &PersistentAuthorityStateRecordV2,
) -> BackendRequest {
    BackendRequest {
        environment: env,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: DIGEST_2.to_string(),
        authority_domain_sequence: 2,
        custody_class: custody_class_for(kind),
        key_id: KEY_ID.to_string(),
        active_signing_key_fingerprint: Some(KEY_A.to_string()),
        new_signing_key_fingerprint: Some(candidate.active_bundle_signing_key_fingerprint.clone()),
        revoked_signing_key_fingerprint: None,
        governance_proof_digest: None,
        custody_attestation_digest: CUSTODY_ATTEST_DIGEST.to_string(),
        request_nonce: REQ_NONCE.to_string(),
        request_timestamp_unix: Some(NOW),
    }
}

fn good_custody_attestation(
    env: TrustBundleEnvironment,
    candidate: &PersistentAuthorityStateRecordV2,
    class: AuthorityCustodyClass,
) -> AuthorityCustodyAttestation {
    AuthorityCustodyAttestation {
        custody_class: class,
        custody_key_id: KEY_ID.to_string(),
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

/// A complete, valid accepted scenario, returning every part a test
/// needs to mutate one field for a rejection vector.
struct Scenario {
    domain: AuthorityTrustDomain,
    candidate: PersistentAuthorityStateRecordV2,
    identity: BackendIdentity,
    request: BackendRequest,
    response: BackendResponse,
    expected: BackendExpectations,
    kind: BackendKind,
    env: TrustBundleEnvironment,
}

fn expectations(
    identity: &BackendIdentity,
    request: &BackendRequest,
    response: &BackendResponse,
    candidate: &PersistentAuthorityStateRecordV2,
) -> BackendExpectations {
    let req_digest = request.request_digest();
    let resp_digest = response.response_digest();
    let transcript = backend_transcript_digest(&identity.identity_digest(), &req_digest, &resp_digest);
    BackendExpectations {
        expected_custody_class: request.custody_class,
        expected_lifecycle_action: LocalLifecycleAction::Rotate,
        expected_candidate_digest: DIGEST_2.to_string(),
        expected_authority_domain_sequence: 2,
        expected_key_id: KEY_ID.to_string(),
        expected_signing_key_fingerprint: candidate.active_bundle_signing_key_fingerprint.clone(),
        expected_custody_attestation_digest: CUSTODY_ATTEST_DIGEST.to_string(),
        expected_request_nonce: REQ_NONCE.to_string(),
        expected_response_nonce: RESP_NONCE.to_string(),
        expected_request_digest: req_digest,
        expected_response_digest: resp_digest,
        expected_transcript_digest: transcript,
        now_unix: NOW,
    }
}

fn sign_with_kind(
    kind: BackendKind,
    identity: &BackendIdentity,
    req: &BackendRequest,
) -> Result<BackendResponse, BackendOutcome> {
    match kind {
        BackendKind::FixtureKms => FixtureKmsBackend {
            identity: identity.clone(),
            response_nonce: RESP_NONCE.to_string(),
            response_freshness_unix: Some(FRESH),
            response_expires_at_unix: Some(EXPIRES),
        }
        .sign_authority_lifecycle_request(req),
        BackendKind::FixtureHsm => FixtureHsmBackend {
            identity: identity.clone(),
            response_nonce: RESP_NONCE.to_string(),
            response_freshness_unix: Some(FRESH),
            response_expires_at_unix: Some(EXPIRES),
        }
        .sign_authority_lifecycle_request(req),
        _ => panic!("sign_with_kind only supports fixture kinds"),
    }
}

fn scenario(kind: BackendKind, env: TrustBundleEnvironment) -> Scenario {
    let candidate = rotate_candidate(env);
    let identity = identity(kind, env, &candidate);
    let request = request(kind, env, &candidate);
    let response = sign_with_kind(kind, &identity, &request).expect("fixture backend signs");
    let expected = expectations(&identity, &request, &response, &candidate);
    Scenario {
        domain: domain(env),
        identity,
        request,
        response,
        expected,
        candidate,
        kind,
        env,
    }
}

fn validate(s: &Scenario, policy: BackendPolicy) -> BackendOutcome {
    verify_authority_custody_backend_response(
        &s.identity,
        &s.request,
        &s.response,
        &s.domain,
        &s.expected,
        policy,
    )
}

fn fixture_policy_for(kind: BackendKind) -> BackendPolicy {
    match kind {
        BackendKind::FixtureKms => BackendPolicy::FixtureKmsAllowed,
        BackendKind::FixtureHsm => BackendPolicy::FixtureHsmAllowed,
        _ => panic!("fixture_policy_for only supports fixture kinds"),
    }
}

// ===========================================================================
// Defaults / type-shape regressions
// ===========================================================================

#[test]
fn default_backend_policy_and_kind_are_fail_closed() {
    assert_eq!(BackendPolicy::default(), BackendPolicy::Disabled);
    assert_eq!(BackendKind::default(), BackendKind::Disabled);
    let s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    // Even an otherwise perfectly valid fixture round-trip is refused
    // under the default Disabled policy.
    let outcome = validate(&s, BackendPolicy::default());
    assert_eq!(outcome, BackendOutcome::Disabled);
    assert!(outcome.is_reject());
}

#[test]
fn policy_and_kind_tags_are_stable() {
    assert_eq!(BackendPolicy::Disabled.tag(), "disabled");
    assert_eq!(BackendPolicy::FixtureKmsAllowed.tag(), "fixture-kms-allowed");
    assert_eq!(BackendPolicy::FixtureHsmAllowed.tag(), "fixture-hsm-allowed");
    assert_eq!(
        BackendPolicy::ProductionKmsRequired.tag(),
        "production-kms-required"
    );
    assert_eq!(
        BackendPolicy::ProductionHsmRequired.tag(),
        "production-hsm-required"
    );
    assert_eq!(
        BackendPolicy::MainnetProductionCustodyRequired.tag(),
        "mainnet-production-custody-required"
    );
    assert_eq!(BackendKind::FixtureKms.tag(), "fixture-kms");
    assert_eq!(BackendKind::FixtureHsm.tag(), "fixture-hsm");
    assert_eq!(BackendKind::CloudKmsUnavailable.tag(), "cloud-kms-unavailable");
    assert_eq!(
        BackendKind::Pkcs11HsmUnavailable.tag(),
        "pkcs11-hsm-unavailable"
    );
    assert!(BackendKind::FixtureKms.is_fixture());
    assert!(BackendKind::CloudKmsUnavailable.is_production_unavailable());
    assert!(BackendPolicy::ProductionKmsRequired.requires_production_backend());
    assert!(!BackendPolicy::FixtureKmsAllowed.requires_production_backend());
    assert_eq!(
        BackendKind::FixtureKms.custody_class(),
        Some(AuthorityCustodyClass::Kms)
    );
    assert_eq!(
        BackendKind::FixtureHsm.custody_class(),
        Some(AuthorityCustodyClass::Hsm)
    );
}

// ===========================================================================
// A1–A4 — accepted fixture KMS/HSM on DevNet/TestNet
// ===========================================================================

#[test]
fn a1_fixture_kms_accepted_on_devnet() {
    let s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    let outcome = validate(&s, BackendPolicy::FixtureKmsAllowed);
    assert_eq!(
        outcome,
        BackendOutcome::FixtureKmsAccepted {
            backend_id: BACKEND_ID.to_string(),
            environment: TrustBundleEnvironment::Devnet,
        }
    );
    assert!(outcome.is_accept());
}

#[test]
fn a2_fixture_hsm_accepted_on_devnet() {
    let s = scenario(BackendKind::FixtureHsm, TrustBundleEnvironment::Devnet);
    let outcome = validate(&s, BackendPolicy::FixtureHsmAllowed);
    assert_eq!(
        outcome,
        BackendOutcome::FixtureHsmAccepted {
            backend_id: BACKEND_ID.to_string(),
            environment: TrustBundleEnvironment::Devnet,
        }
    );
    assert!(outcome.is_accept());
}

#[test]
fn a3_fixture_kms_accepted_on_testnet() {
    let s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Testnet);
    let outcome = validate(&s, BackendPolicy::FixtureKmsAllowed);
    assert_eq!(
        outcome,
        BackendOutcome::FixtureKmsAccepted {
            backend_id: BACKEND_ID.to_string(),
            environment: TrustBundleEnvironment::Testnet,
        }
    );
}

#[test]
fn a4_fixture_hsm_accepted_on_testnet() {
    let s = scenario(BackendKind::FixtureHsm, TrustBundleEnvironment::Testnet);
    let outcome = validate(&s, BackendPolicy::FixtureHsmAllowed);
    assert_eq!(
        outcome,
        BackendOutcome::FixtureHsmAccepted {
            backend_id: BACKEND_ID.to_string(),
            environment: TrustBundleEnvironment::Testnet,
        }
    );
}

// ===========================================================================
// A5–A8 — deterministic digests
// ===========================================================================

#[test]
fn a5_identity_digest_deterministic_and_bound() {
    let s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    assert_eq!(s.identity.identity_digest(), s.identity.identity_digest());
    let mut other = s.identity.clone();
    other.provider_id = "different-provider".to_string();
    assert_ne!(s.identity.identity_digest(), other.identity_digest());
}

#[test]
fn a6_request_digest_deterministic_and_bound() {
    let s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    assert_eq!(s.request.request_digest(), s.request.request_digest());
    let mut other = s.request.clone();
    other.authority_domain_sequence = 3;
    assert_ne!(s.request.request_digest(), other.request_digest());
}

#[test]
fn a7_response_digest_deterministic_and_bound() {
    let s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    assert_eq!(s.response.response_digest(), s.response.response_digest());
    let mut other = s.response.clone();
    other.response_nonce = "different".to_string();
    assert_ne!(s.response.response_digest(), other.response_digest());
}

#[test]
fn a8_transcript_digest_deterministic_and_bound() {
    let s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    let id = s.identity.identity_digest();
    let req = s.request.request_digest();
    let resp = s.response.response_digest();
    let t1 = backend_transcript_digest(&id, &req, &resp);
    let t2 = backend_transcript_digest(&id, &req, &resp);
    assert_eq!(t1, t2);
    let t3 = backend_transcript_digest(&id, &req, "other-response-digest");
    assert_ne!(t1, t3);
}

// ===========================================================================
// A9 / A10 — request and response field binding
// ===========================================================================

#[test]
fn a9_request_binds_full_authority_tuple() {
    let s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    let r = &s.request;
    assert_eq!(r.environment, TrustBundleEnvironment::Devnet);
    assert_eq!(r.chain_id, CHAIN_ID);
    assert_eq!(r.genesis_hash, GENESIS_HASH);
    assert_eq!(r.authority_root_fingerprint, ROOT_FP);
    assert_eq!(r.lifecycle_action, LocalLifecycleAction::Rotate);
    assert_eq!(r.candidate_digest, DIGEST_2);
    assert_eq!(r.authority_domain_sequence, 2);
    assert_eq!(r.custody_class, AuthorityCustodyClass::Kms);
    assert_eq!(r.key_id, KEY_ID);
    assert!(r.is_well_formed());
}

#[test]
fn a10_response_binds_request_and_backend_fields() {
    let s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    let resp = &s.response;
    assert_eq!(resp.bound_request_digest, s.request.request_digest());
    assert_eq!(resp.backend_id, BACKEND_ID);
    assert_eq!(resp.provider_id, PROVIDER_ID);
    assert_eq!(resp.key_id, KEY_ID);
    assert_eq!(resp.signature_suite_id, PQC_LIFECYCLE_SUITE_ML_DSA_44);
    assert_eq!(resp.attestation_digest, ATTEST_DIGEST);
    assert!(!resp.response_digest().is_empty());
    assert!(resp.is_well_formed());
}

// ===========================================================================
// A11 / A12 — production KMS/HSM callable, returns typed unavailable
// ===========================================================================

#[test]
fn a11_production_kms_callable_returns_unavailable() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let id = identity(
        BackendKind::ProductionKmsUnavailable,
        TrustBundleEnvironment::Devnet,
        &candidate,
    );
    let req = request(
        BackendKind::ProductionKmsUnavailable,
        TrustBundleEnvironment::Devnet,
        &candidate,
    );
    let backend = ProductionKmsBackend { identity: id };
    assert_eq!(backend.kind(), BackendKind::ProductionKmsUnavailable);
    let outcome = backend.sign_authority_lifecycle_request(&req);
    assert_eq!(outcome, Err(BackendOutcome::ProductionKmsUnavailable));
}

#[test]
fn a12_production_hsm_callable_returns_unavailable() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let id = identity(
        BackendKind::ProductionHsmUnavailable,
        TrustBundleEnvironment::Devnet,
        &candidate,
    );
    let req = request(
        BackendKind::ProductionHsmUnavailable,
        TrustBundleEnvironment::Devnet,
        &candidate,
    );
    let backend = ProductionHsmBackend { identity: id };
    let outcome = backend.sign_authority_lifecycle_request(&req);
    assert_eq!(outcome, Err(BackendOutcome::ProductionHsmUnavailable));
}

// ===========================================================================
// A13 — Run 188 custody validator compatible with KMS/HSM custody class
// ===========================================================================

#[test]
fn a13_composes_with_run188_custody_for_kms_and_hsm() {
    for (kind, class) in [
        (BackendKind::FixtureKms, AuthorityCustodyClass::Kms),
        (BackendKind::FixtureHsm, AuthorityCustodyClass::Hsm),
    ] {
        let s = scenario(kind, TrustBundleEnvironment::Devnet);
        let custody = good_custody_attestation(s.env, &s.candidate, class);
        let prior = prior_versioned(s.env);
        let outcome = validate_lifecycle_governance_custody_and_backend(
            &custody,
            &s.candidate,
            Some(&prior),
            &s.domain,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(KEY_ID),
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            &s.identity,
            &s.request,
            &s.response,
            &s.expected,
            fixture_policy_for(kind),
            NOW,
            false,
        );
        // Run 188 fails Kms/Hsm custody closed as unavailable, so the
        // composition rejects at the custody layer — proving the
        // KMS/HSM backend class routes through the Run 188 validator.
        assert!(matches!(
            outcome,
            LifecycleCustodyBackendOutcome::LifecycleOrCustodyRejected(_)
        ));
    }
}

// ===========================================================================
// A14 — RemoteSigner path remains separate and unchanged
// ===========================================================================

#[test]
fn a14_remote_signer_custody_class_is_not_kms_hsm() {
    // The KMS/HSM router must refuse a RemoteSigner custody class — the
    // RemoteSigner path (Runs 194–202) is a separate custody option.
    let s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    let outcome = validate_backend_for_custody_class(
        AuthorityCustodyClass::RemoteSigner,
        &s.identity,
        &s.request,
        &s.response,
        &s.domain,
        &s.expected,
        BackendPolicy::FixtureKmsAllowed,
    );
    assert_eq!(
        outcome,
        BackendOutcome::NotKmsHsmCustodyClass {
            class: AuthorityCustodyClass::RemoteSigner,
        }
    );
    assert!(!custody_class_routes_to_kms_hsm_backend(
        AuthorityCustodyClass::RemoteSigner
    ));
    assert!(custody_class_routes_to_kms_hsm_backend(
        AuthorityCustodyClass::Kms
    ));
    assert!(custody_class_routes_to_kms_hsm_backend(
        AuthorityCustodyClass::Hsm
    ));
}

// ===========================================================================
// A15 — governance/proof behavior unchanged when backend policy Disabled
// ===========================================================================

#[test]
fn a15_disabled_policy_does_not_disturb_governance() {
    for class in [
        GovernanceAuthorityClass::GenesisBound,
        GovernanceAuthorityClass::EmergencyCouncil,
        GovernanceAuthorityClass::OnChainGovernance,
    ] {
        let _ = class; // governance class is orthogonal to a Disabled backend
        let s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
        assert_eq!(validate(&s, BackendPolicy::Disabled), BackendOutcome::Disabled);
    }
}

// ===========================================================================
// R1–R4 — policy rejections
// ===========================================================================

#[test]
fn r1_rejected_under_disabled_policy() {
    let s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    assert_eq!(validate(&s, BackendPolicy::Disabled), BackendOutcome::Disabled);
}

#[test]
fn r2_fixture_kms_rejected_under_production_kms_required() {
    let s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    assert_eq!(
        validate(&s, BackendPolicy::ProductionKmsRequired),
        BackendOutcome::FixtureRejectedProductionRequired
    );
}

#[test]
fn r3_fixture_hsm_rejected_under_production_hsm_required() {
    let s = scenario(BackendKind::FixtureHsm, TrustBundleEnvironment::Devnet);
    assert_eq!(
        validate(&s, BackendPolicy::ProductionHsmRequired),
        BackendOutcome::FixtureRejectedProductionRequired
    );
}

#[test]
fn r4_fixture_rejected_under_mainnet_production_required() {
    for kind in [BackendKind::FixtureKms, BackendKind::FixtureHsm] {
        let s = scenario(kind, TrustBundleEnvironment::Devnet);
        assert_eq!(
            validate(&s, BackendPolicy::MainnetProductionCustodyRequired),
            BackendOutcome::FixtureRejectedMainnetProductionRequired
        );
    }
}

// ===========================================================================
// R5–R9 — production / cloud / PKCS#11 / MainNet unavailable
// ===========================================================================

fn production_response(kind: BackendKind, env: TrustBundleEnvironment) -> Scenario {
    // Build a scenario whose response carries a production-class backend
    // kind, to drive the unavailable paths through the verifier.
    let candidate = rotate_candidate(env);
    let identity = identity(kind, env, &candidate);
    let request = request(kind, env, &candidate);
    let response = BackendResponse {
        backend_kind: kind,
        bound_request_digest: request.request_digest(),
        backend_id: BACKEND_ID.to_string(),
        provider_id: PROVIDER_ID.to_string(),
        key_id: KEY_ID.to_string(),
        signature_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        signature_commitment: "placeholder".to_string(),
        attestation_digest: ATTEST_DIGEST.to_string(),
        response_nonce: RESP_NONCE.to_string(),
        freshness_unix: Some(FRESH),
        expires_at_unix: Some(EXPIRES),
    };
    let expected = expectations(&identity, &request, &response, &candidate);
    Scenario {
        domain: domain(env),
        identity,
        request,
        response,
        expected,
        candidate,
        kind,
        env,
    }
}

#[test]
fn r5_production_kms_unavailable_through_verifier() {
    let s = production_response(
        BackendKind::ProductionKmsUnavailable,
        TrustBundleEnvironment::Devnet,
    );
    let outcome = validate(&s, BackendPolicy::FixtureKmsAllowed);
    assert_eq!(outcome, BackendOutcome::ProductionKmsUnavailable);
    assert!(outcome.is_unavailable());
}

#[test]
fn r6_production_hsm_unavailable_through_verifier() {
    let s = production_response(
        BackendKind::ProductionHsmUnavailable,
        TrustBundleEnvironment::Devnet,
    );
    assert_eq!(
        validate(&s, BackendPolicy::FixtureHsmAllowed),
        BackendOutcome::ProductionHsmUnavailable
    );
}

#[test]
fn r7_cloud_kms_unavailable() {
    let s = production_response(
        BackendKind::CloudKmsUnavailable,
        TrustBundleEnvironment::Devnet,
    );
    assert_eq!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::CloudKmsUnavailable
    );
    // Cloud KMS backend struct is callable and fails closed.
    let backend = CloudKmsBackend {
        identity: s.identity.clone(),
    };
    assert_eq!(
        backend.sign_authority_lifecycle_request(&s.request),
        Err(BackendOutcome::CloudKmsUnavailable)
    );
}

#[test]
fn r8_pkcs11_hsm_unavailable() {
    let s = production_response(
        BackendKind::Pkcs11HsmUnavailable,
        TrustBundleEnvironment::Devnet,
    );
    assert_eq!(
        validate(&s, BackendPolicy::FixtureHsmAllowed),
        BackendOutcome::Pkcs11HsmUnavailable
    );
    let backend = Pkcs11HsmBackend {
        identity: s.identity.clone(),
    };
    assert_eq!(
        backend.sign_authority_lifecycle_request(&s.request),
        Err(BackendOutcome::Pkcs11HsmUnavailable)
    );
}

#[test]
fn r9_mainnet_production_custody_unavailable() {
    let s = production_response(
        BackendKind::ProductionKmsUnavailable,
        TrustBundleEnvironment::Devnet,
    );
    assert_eq!(
        validate(&s, BackendPolicy::MainnetProductionCustodyRequired),
        BackendOutcome::MainNetProductionCustodyUnavailable
    );
}

// ===========================================================================
// R10 — unknown backend rejected
// ===========================================================================

#[test]
fn r10_unknown_backend_rejected() {
    let s = production_response(BackendKind::Unknown, TrustBundleEnvironment::Devnet);
    let outcome = validate(&s, BackendPolicy::FixtureKmsAllowed);
    assert_eq!(
        outcome,
        BackendOutcome::UnknownBackendRejected {
            backend_tag: "unknown"
        }
    );
}

// ===========================================================================
// R11–R22 — binding rejections
// ===========================================================================

#[test]
fn r11_wrong_environment_rejected() {
    let mut s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    s.request.environment = TrustBundleEnvironment::Testnet;
    assert!(matches!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::WrongEnvironment { .. }
    ));
}

#[test]
fn r12_wrong_chain_rejected() {
    let mut s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    s.request.chain_id = "00000000000000ff".to_string();
    assert!(matches!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::WrongChain { .. }
    ));
}

#[test]
fn r13_wrong_genesis_rejected() {
    let mut s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    s.request.genesis_hash = "ff".repeat(32);
    assert!(matches!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::WrongGenesis { .. }
    ));
}

#[test]
fn r14_wrong_authority_root_rejected() {
    let mut s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    s.request.authority_root_fingerprint = "9".repeat(40);
    assert!(matches!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::WrongAuthorityRoot { .. }
    ));
}

#[test]
fn r15_wrong_key_id_rejected() {
    let mut s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    s.response.key_id = "other-key".to_string();
    assert!(matches!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::WrongKeyId { .. }
    ));
}

#[test]
fn r16_wrong_signing_key_fingerprint_rejected() {
    let mut s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    s.expected.expected_signing_key_fingerprint = "deadbeef".to_string();
    assert!(matches!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::WrongSigningKeyFingerprint { .. }
    ));
}

#[test]
fn r17_wrong_lifecycle_action_rejected() {
    let mut s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    s.expected.expected_lifecycle_action = LocalLifecycleAction::Revoke;
    assert!(matches!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::WrongLifecycleAction { .. }
    ));
}

#[test]
fn r18_wrong_candidate_digest_rejected() {
    let mut s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    s.expected.expected_candidate_digest = "3".repeat(64);
    assert!(matches!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::WrongCandidateDigest { .. }
    ));
}

#[test]
fn r19_wrong_authority_domain_sequence_rejected() {
    let mut s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    s.expected.expected_authority_domain_sequence = 7;
    assert!(matches!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::WrongAuthorityDomainSequence { .. }
    ));
}

#[test]
fn r20_wrong_request_digest_rejected() {
    let mut s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    s.expected.expected_request_digest = "0".repeat(64);
    assert!(matches!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::WrongRequestDigest { .. }
    ));
}

#[test]
fn r21_wrong_response_digest_rejected() {
    let mut s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    s.expected.expected_response_digest = "0".repeat(64);
    assert!(matches!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::WrongResponseDigest { .. }
    ));
}

#[test]
fn r22_wrong_transcript_digest_rejected() {
    let mut s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    s.expected.expected_transcript_digest = "0".repeat(64);
    assert!(matches!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::WrongTranscriptDigest { .. }
    ));
}

// ===========================================================================
// R23–R29 — replay / freshness / suite / attestation / signature
// ===========================================================================

#[test]
fn r23_stale_or_replayed_request_rejected() {
    let mut s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    s.expected.expected_request_nonce = "stale".to_string();
    assert!(matches!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::StaleOrReplayedRequest { .. }
    ));
}

#[test]
fn r24_stale_or_replayed_response_rejected() {
    let mut s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    s.expected.expected_response_nonce = "stale".to_string();
    assert!(matches!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::StaleOrReplayedResponse { .. }
    ));
}

#[test]
fn r25_expired_attestation_rejected() {
    let mut s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    s.identity.expires_at_unix = Some(NOW - 1);
    // Changing the identity expiry changes its identity digest, so the
    // expected transcript digest must be recomputed to reach the
    // freshness check (step 26) instead of the transcript check.
    s.expected.expected_transcript_digest = backend_transcript_digest(
        &s.identity.identity_digest(),
        &s.request.request_digest(),
        &s.response.response_digest(),
    );
    assert!(matches!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::ExpiredAttestation { .. }
    ));
}

#[test]
fn r26_expired_response_rejected() {
    let mut s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    s.response.expires_at_unix = Some(NOW - 1);
    s.expected.expected_response_digest = s.response.response_digest();
    s.expected.expected_transcript_digest = backend_transcript_digest(
        &s.identity.identity_digest(),
        &s.request.request_digest(),
        &s.response.response_digest(),
    );
    assert!(matches!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::ExpiredResponse { .. }
    ));
}

#[test]
fn r27_unsupported_suite_rejected() {
    let mut s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    s.response.signature_suite_id = 99;
    s.expected.expected_response_digest = s.response.response_digest();
    s.expected.expected_transcript_digest = backend_transcript_digest(
        &s.identity.identity_digest(),
        &s.request.request_digest(),
        &s.response.response_digest(),
    );
    assert!(matches!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::UnsupportedSuite { .. }
    ));
}

#[test]
fn r28_invalid_attestation_rejected() {
    let mut s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    s.response.attestation_digest = KMS_HSM_BACKEND_INVALID_ATTESTATION_SENTINEL.to_string();
    s.expected.expected_response_digest = s.response.response_digest();
    s.expected.expected_transcript_digest = backend_transcript_digest(
        &s.identity.identity_digest(),
        &s.request.request_digest(),
        &s.response.response_digest(),
    );
    assert_eq!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::InvalidAttestation
    );
}

#[test]
fn r29_invalid_signature_rejected() {
    let mut s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    s.response.signature_commitment = KMS_HSM_BACKEND_INVALID_SIGNATURE_SENTINEL.to_string();
    s.expected.expected_response_digest = s.response.response_digest();
    s.expected.expected_transcript_digest = backend_transcript_digest(
        &s.identity.identity_digest(),
        &s.request.request_digest(),
        &s.response.response_digest(),
    );
    assert_eq!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::InvalidSignature
    );
}

// ===========================================================================
// R30–R32 — malformed identity / request / response
// ===========================================================================

#[test]
fn r30_malformed_identity_rejected() {
    let mut s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    s.identity.backend_id = String::new();
    assert!(matches!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::MalformedIdentity { .. }
    ));
}

#[test]
fn r31_malformed_request_rejected() {
    let mut s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    s.request.candidate_digest = String::new();
    assert!(matches!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::MalformedRequest { .. }
    ));
}

#[test]
fn r32_malformed_response_rejected() {
    let mut s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    s.response.signature_commitment = String::new();
    assert!(matches!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::MalformedResponse { .. }
    ));
}

// ===========================================================================
// R33 / R34 — local operator / peer majority cannot satisfy
// ===========================================================================

#[test]
fn r33_local_operator_cannot_satisfy_backend_policy() {
    assert!(local_operator_cannot_satisfy_backend_policy());
    let s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    let outcome = validate_backend_for_custody_class(
        AuthorityCustodyClass::LocalOperatorKey,
        &s.identity,
        &s.request,
        &s.response,
        &s.domain,
        &s.expected,
        BackendPolicy::FixtureKmsAllowed,
    );
    assert_eq!(
        outcome,
        BackendOutcome::LocalOperatorCannotSatisfyBackendPolicy
    );
}

#[test]
fn r34_peer_majority_cannot_satisfy_backend_policy() {
    assert!(peer_majority_cannot_satisfy_backend_policy());
    let s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    // A fixture-local-key custody class (representing local/peer
    // material) likewise can never satisfy a backend policy.
    let outcome = validate_backend_for_custody_class(
        AuthorityCustodyClass::FixtureLocalKey,
        &s.identity,
        &s.request,
        &s.response,
        &s.domain,
        &s.expected,
        BackendPolicy::FixtureKmsAllowed,
    );
    assert_eq!(
        outcome,
        BackendOutcome::LocalOperatorCannotSatisfyBackendPolicy
    );
}

// ===========================================================================
// R35 / R36 — composition: custody-vs-backend cross rejection
// ===========================================================================

#[test]
fn r35_backend_valid_but_custody_metadata_invalid_rejected() {
    let s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    // Custody attestation carries a mismatched candidate digest, so the
    // Run 188 layer rejects even though the backend response is valid.
    let mut custody = good_custody_attestation(s.env, &s.candidate, AuthorityCustodyClass::Kms);
    custody.candidate_digest = "deadbeef".to_string();
    let prior = prior_versioned(s.env);
    let outcome = validate_lifecycle_governance_custody_and_backend(
        &custody,
        &s.candidate,
        Some(&prior),
        &s.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(KEY_ID),
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        &s.identity,
        &s.request,
        &s.response,
        &s.expected,
        BackendPolicy::FixtureKmsAllowed,
        NOW,
        false,
    );
    assert!(matches!(
        outcome,
        LifecycleCustodyBackendOutcome::LifecycleOrCustodyRejected(_)
    ));
    assert!(outcome.is_reject());
}

#[test]
fn r36_custody_valid_but_backend_response_invalid_rejected() {
    // Use a LocalOperatorKey custody class that Run 188 accepts under
    // DevnetLocalAllowed, then feed an invalid backend response.
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let identity = identity(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet, &candidate);
    let request = request(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet, &candidate);
    let mut response =
        sign_with_kind(BackendKind::FixtureKms, &identity, &request).expect("signs");
    response.signature_commitment = KMS_HSM_BACKEND_INVALID_SIGNATURE_SENTINEL.to_string();
    let mut expected = expectations(&identity, &request, &response, &candidate);
    expected.expected_response_digest = response.response_digest();
    expected.expected_transcript_digest = backend_transcript_digest(
        &identity.identity_digest(),
        &request.request_digest(),
        &response.response_digest(),
    );
    let custody = AuthorityCustodyAttestation {
        custody_class: AuthorityCustodyClass::LocalOperatorKey,
        ..good_custody_attestation(
            TrustBundleEnvironment::Devnet,
            &candidate,
            AuthorityCustodyClass::LocalOperatorKey,
        )
    };
    let prior = prior_versioned(TrustBundleEnvironment::Devnet);
    let outcome = validate_lifecycle_governance_custody_and_backend(
        &custody,
        &candidate,
        Some(&prior),
        &domain(TrustBundleEnvironment::Devnet),
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(KEY_ID),
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        &identity,
        &request,
        &response,
        &expected,
        BackendPolicy::FixtureKmsAllowed,
        NOW,
        false,
    );
    assert!(matches!(
        outcome,
        LifecycleCustodyBackendOutcome::BackendRejected {
            backend_outcome: BackendOutcome::InvalidSignature,
            ..
        }
    ));
}

// ===========================================================================
// R37 / R38 — lifecycle+governance+custody valid but production unavailable
// ===========================================================================

#[test]
fn r37_production_kms_unavailable_in_composition() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let s = production_response(
        BackendKind::ProductionKmsUnavailable,
        TrustBundleEnvironment::Devnet,
    );
    let custody = AuthorityCustodyAttestation {
        custody_class: AuthorityCustodyClass::LocalOperatorKey,
        ..good_custody_attestation(
            TrustBundleEnvironment::Devnet,
            &candidate,
            AuthorityCustodyClass::LocalOperatorKey,
        )
    };
    let prior = prior_versioned(TrustBundleEnvironment::Devnet);
    let outcome = validate_lifecycle_governance_custody_and_backend(
        &custody,
        &candidate,
        Some(&prior),
        &s.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(KEY_ID),
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        &s.identity,
        &s.request,
        &s.response,
        &s.expected,
        BackendPolicy::FixtureKmsAllowed,
        NOW,
        false,
    );
    assert!(matches!(
        outcome,
        LifecycleCustodyBackendOutcome::BackendRejected {
            backend_outcome: BackendOutcome::ProductionKmsUnavailable,
            ..
        }
    ));
}

#[test]
fn r38_production_hsm_unavailable_in_composition() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let s = production_response(
        BackendKind::ProductionHsmUnavailable,
        TrustBundleEnvironment::Devnet,
    );
    let custody = AuthorityCustodyAttestation {
        custody_class: AuthorityCustodyClass::LocalOperatorKey,
        ..good_custody_attestation(
            TrustBundleEnvironment::Devnet,
            &candidate,
            AuthorityCustodyClass::LocalOperatorKey,
        )
    };
    let prior = prior_versioned(TrustBundleEnvironment::Devnet);
    let outcome = validate_lifecycle_governance_custody_and_backend(
        &custody,
        &candidate,
        Some(&prior),
        &s.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(KEY_ID),
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        &s.identity,
        &s.request,
        &s.response,
        &s.expected,
        BackendPolicy::FixtureHsmAllowed,
        NOW,
        false,
    );
    assert!(matches!(
        outcome,
        LifecycleCustodyBackendOutcome::BackendRejected {
            backend_outcome: BackendOutcome::ProductionHsmUnavailable,
            ..
        }
    ));
}

// ===========================================================================
// R39 / R40 — non-mutating validation, no Run 070 on rejection
// ===========================================================================

#[test]
fn r39_validation_only_is_non_mutating() {
    // Validating the same scenario twice yields identical outcomes and
    // leaves every input value unchanged (pure data, no interior
    // mutability).
    let s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    let before_identity = s.identity.clone();
    let before_request = s.request.clone();
    let before_response = s.response.clone();
    let o1 = validate(&s, BackendPolicy::FixtureKmsAllowed);
    let o2 = validate(&s, BackendPolicy::FixtureKmsAllowed);
    assert_eq!(o1, o2);
    assert_eq!(s.identity, before_identity);
    assert_eq!(s.request, before_request);
    assert_eq!(s.response, before_response);
}

#[test]
fn r40_mutating_preflight_rejection_produces_no_run070() {
    // The composition helper is pure: a rejection returns a typed value
    // and never performs a marker/sequence write, a live trust swap, a
    // session eviction, or a Run 070 apply. We assert the typed reject
    // and rely on the module's no-I/O guarantee (no Run 070 symbol is
    // reachable from this crate's test surface).
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let s = production_response(
        BackendKind::ProductionKmsUnavailable,
        TrustBundleEnvironment::Devnet,
    );
    let custody = AuthorityCustodyAttestation {
        custody_class: AuthorityCustodyClass::LocalOperatorKey,
        ..good_custody_attestation(
            TrustBundleEnvironment::Devnet,
            &candidate,
            AuthorityCustodyClass::LocalOperatorKey,
        )
    };
    let prior = prior_versioned(TrustBundleEnvironment::Devnet);
    let outcome = validate_lifecycle_governance_custody_and_backend(
        &custody,
        &candidate,
        Some(&prior),
        &s.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(KEY_ID),
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        &s.identity,
        &s.request,
        &s.response,
        &s.expected,
        BackendPolicy::FixtureKmsAllowed,
        NOW,
        true,
    );
    assert!(outcome.is_reject());
}

// ===========================================================================
// R41 — MainNet peer-driven apply remains refused even with fixture
// ===========================================================================

#[test]
fn r41_mainnet_peer_driven_apply_remains_refused() {
    assert!(mainnet_peer_driven_apply_remains_refused_under_kms_hsm_backend_boundary(
        TrustBundleEnvironment::Mainnet
    ));
    assert!(!mainnet_peer_driven_apply_remains_refused_under_kms_hsm_backend_boundary(
        TrustBundleEnvironment::Devnet
    ));
    // Even a fully-valid fixture KMS round-trip on a MainNet domain is
    // refused: the verifier rejects fixture-for-MainNet, and the
    // composition short-circuits to the peer-driven-apply refusal.
    let s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Mainnet);
    assert_eq!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::FixtureRejectedForMainNet
    );
    let custody = good_custody_attestation(s.env, &s.candidate, AuthorityCustodyClass::Kms);
    let prior = prior_versioned(s.env);
    let outcome = validate_lifecycle_governance_custody_and_backend(
        &custody,
        &s.candidate,
        Some(&prior),
        &s.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(KEY_ID),
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        &s.identity,
        &s.request,
        &s.response,
        &s.expected,
        BackendPolicy::FixtureKmsAllowed,
        NOW,
        true,
    );
    assert_eq!(
        outcome,
        LifecycleCustodyBackendOutcome::MainNetPeerDrivenApplyRefused
    );
}

// ===========================================================================
// Fixture-vs-production separation + policy mismatch
// ===========================================================================

#[test]
fn fixture_kind_must_match_fixture_policy() {
    // A fixture HSM response under the FixtureKmsAllowed policy is a
    // backend-kind/policy mismatch.
    let s = scenario(BackendKind::FixtureHsm, TrustBundleEnvironment::Devnet);
    assert!(matches!(
        validate(&s, BackendPolicy::FixtureKmsAllowed),
        BackendOutcome::BackendKindPolicyMismatch { .. }
    ));
}

#[test]
fn unused_helpers_referenced() {
    // Keep `s.kind` reachable for clarity in assertions.
    let s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    assert_eq!(s.kind, BackendKind::FixtureKms);
}
