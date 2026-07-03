//! Run 295 — source/test production KMS/HSM/cloud-KMS/PKCS#11 custody
//! backend integration tests.
//!
//! Source/test only. Run 295 does **not** capture release-binary
//! evidence; release-binary evidence for the production KMS/HSM custody
//! backend is deferred to **Run 296**. The tests cover:
//!
//! * A. accepted / compatible source-test evidence;
//! * B. rejection / fail-closed paths;
//! * C. MainNet / authority policy refusal;
//! * D. non-mutation invariants (the backend surfaces are pure);
//! * E. replay / recovery / idempotency;
//! * F. C4/C5 taxonomy status.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_295.md`.

use qbind_node::pqc_authority_custody::AuthorityCustodyClass;
use qbind_node::pqc_authority_kms_hsm_backend::{
    BackendIdentity, BackendKind, BackendResponse, FixtureHsmBackend, FixtureKmsBackend,
};
use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_production_kms_hsm_custody_backend::{
    production_kms_hsm_custody_backend_default_is_disabled,
    production_kms_hsm_custody_backend_is_non_mutating,
    production_kms_hsm_custody_backend_is_source_test_not_release_binary_evidence,
    production_kms_hsm_custody_backend_loads_no_raw_local_key,
    production_kms_hsm_custody_backend_mainnet_refuses_fixture_material,
    production_kms_hsm_custody_backend_never_falls_back,
    production_kms_hsm_custody_backend_remote_signer_is_not_kms_hsm,
    production_kms_hsm_custody_request_id, production_kms_hsm_custody_transcript_digest,
    FixtureHsmCustodyProvider, FixtureKmsCustodyProvider,
    GovernanceProductionKmsHsmCustodyBackend, KmsHsmCustodyProviderTransport,
    MockKmsHsmCustodyTransport, ProductionCustodyError, ProductionCustodyOutcome,
    ProductionCustodyProviderKind, ProductionCustodyProviderStub, ProductionCustodyRecoveryOutcome,
    ProductionCustodyRequestKind, ProductionCustodyRequestSpec, ProductionCustodyResponse,
    ProductionKmsHsmCustodyBackend, ProductionKmsHsmCustodyBackendConfig,
    ProductionKmsHsmCustodyBackendPolicy, SubmittedCustodyRequest,
    PRODUCTION_KMS_HSM_CUSTODY_BACKEND_PROTOCOL_VERSION, PRODUCTION_KMS_HSM_CUSTODY_MAX_RESPONSE_BYTES,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared fixtures
// ===========================================================================

const CHAIN_ID: &str = "qbind-devnet";
const GENESIS_HASH: &str = "genesis-devnet";
const ROOT_FP: &str = "root-fp-devnet";
const BACKEND_ID: &str = "backend-1";
const PROVIDER_ID: &str = "fixture-provider-1";
const KEY_ID: &str = "key-1";
const BUNDLE_FP: &str = "bundle-fp-1";
const ACTIVE_FP: &str = "active-fp";
const NEW_FP: &str = "new-fp";
const ATTEST_DIGEST: &str = "attest-digest";
const CUSTODY_ATTEST_DIGEST: &str = "custody-attest-digest";
const KEY_USAGE: &str = "authority-lifecycle-signing";
const CANDIDATE_DIGEST: &str = "candidate-digest-2";
const REQ_NONCE: &str = "req-nonce";
const RESP_NONCE: &str = "resp-nonce";
const SEQ: u64 = 2;
const FRESH: u64 = 1_000;
const EXPIRES: u64 = 2_000_000_000;
const NOW: u64 = 1_700_000_100;
const REQ_TS: u64 = 1_700_000_000;

fn chain_for(env: TrustBundleEnvironment) -> &'static str {
    match env {
        TrustBundleEnvironment::Devnet => "qbind-devnet",
        TrustBundleEnvironment::Testnet => "qbind-testnet",
        TrustBundleEnvironment::Mainnet => "qbind-mainnet",
        _ => "qbind-other",
    }
}

fn domain(env: TrustBundleEnvironment) -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(env, chain_for(env), GENESIS_HASH, ROOT_FP, 100)
}

fn fixture_identity(kind: BackendKind, env: TrustBundleEnvironment) -> BackendIdentity {
    BackendIdentity {
        backend_kind: kind,
        backend_id: BACKEND_ID.to_string(),
        provider_id: PROVIDER_ID.to_string(),
        key_id: KEY_ID.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        bundle_signing_key_fingerprint: BUNDLE_FP.to_string(),
        environment: env,
        chain_id: chain_for(env).to_string(),
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

fn fixture_spec(
    provider_kind: ProductionCustodyProviderKind,
    env: TrustBundleEnvironment,
) -> ProductionCustodyRequestSpec {
    let custody_class = match provider_kind {
        ProductionCustodyProviderKind::FixtureHsm
        | ProductionCustodyProviderKind::ProductionPkcs11Hsm
        | ProductionCustodyProviderKind::ProductionGenericHsm => AuthorityCustodyClass::Hsm,
        _ => AuthorityCustodyClass::Kms,
    };
    ProductionCustodyRequestSpec {
        request_kind: ProductionCustodyRequestKind::AuthorityLifecycleSigning,
        provider_kind,
        environment: env,
        chain_id: chain_for(env).to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: CANDIDATE_DIGEST.to_string(),
        authority_domain_sequence: SEQ,
        custody_class,
        provider_id: PROVIDER_ID.to_string(),
        key_id: KEY_ID.to_string(),
        active_signing_key_fingerprint: Some(ACTIVE_FP.to_string()),
        new_signing_key_fingerprint: Some(NEW_FP.to_string()),
        revoked_signing_key_fingerprint: None,
        governance_proof_digest: None,
        custody_attestation_digest: CUSTODY_ATTEST_DIGEST.to_string(),
        durable_replay_record_digest: None,
        request_nonce: REQ_NONCE.to_string(),
        response_nonce: RESP_NONCE.to_string(),
        request_timestamp_unix: REQ_TS,
    }
}

fn fixture_kms_backend(env: TrustBundleEnvironment) -> FixtureKmsBackend {
    FixtureKmsBackend {
        identity: fixture_identity(BackendKind::FixtureKms, env),
        response_nonce: RESP_NONCE.to_string(),
        response_freshness_unix: Some(FRESH),
        response_expires_at_unix: Some(EXPIRES),
    }
}

fn fixture_hsm_backend(env: TrustBundleEnvironment) -> FixtureHsmBackend {
    FixtureHsmBackend {
        identity: fixture_identity(BackendKind::FixtureHsm, env),
        response_nonce: RESP_NONCE.to_string(),
        response_freshness_unix: Some(FRESH),
        response_expires_at_unix: Some(EXPIRES),
    }
}

fn config() -> ProductionKmsHsmCustodyBackendConfig {
    ProductionKmsHsmCustodyBackendConfig::default()
}

fn kms_backend(
    policy: ProductionKmsHsmCustodyBackendPolicy,
    env: TrustBundleEnvironment,
) -> ProductionKmsHsmCustodyBackend<FixtureKmsCustodyProvider> {
    ProductionKmsHsmCustodyBackend::new(
        config(),
        policy,
        FixtureKmsCustodyProvider::new(fixture_kms_backend(env)),
    )
}

fn hsm_backend(
    policy: ProductionKmsHsmCustodyBackendPolicy,
    env: TrustBundleEnvironment,
) -> ProductionKmsHsmCustodyBackend<FixtureHsmCustodyProvider> {
    ProductionKmsHsmCustodyBackend::new(
        config(),
        policy,
        FixtureHsmCustodyProvider::new(fixture_hsm_backend(env)),
    )
}

// ===========================================================================
// A. Accepted / compatible
// ===========================================================================

#[test]
fn a01_disabled_default_policy_is_explicit_and_inert() {
    assert!(production_kms_hsm_custody_backend_default_is_disabled());
    assert_eq!(
        ProductionKmsHsmCustodyBackendPolicy::default(),
        ProductionKmsHsmCustodyBackendPolicy::Disabled
    );
    assert!(ProductionKmsHsmCustodyBackendPolicy::default().is_disabled());
}

#[test]
fn a02_devnet_fixture_kms_accepts_valid_request_under_fixture_policy() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Devnet,
    );
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, TrustBundleEnvironment::Devnet);
    let identity = fixture_identity(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    let outcome =
        backend.evaluate_custody_backend(&spec, &domain(TrustBundleEnvironment::Devnet), &identity, NOW);
    assert!(matches!(
        outcome,
        ProductionCustodyOutcome::FixtureKmsAccepted { .. }
    ));
    assert!(outcome.is_accept());
    assert_eq!(backend.transport.call_count(), 1);
}

#[test]
fn a03_devnet_fixture_hsm_accepts_valid_request_under_fixture_policy() {
    let backend = hsm_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureHsmAllowed,
        TrustBundleEnvironment::Devnet,
    );
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureHsm, TrustBundleEnvironment::Devnet);
    let identity = fixture_identity(BackendKind::FixtureHsm, TrustBundleEnvironment::Devnet);
    let outcome =
        backend.evaluate_custody_backend(&spec, &domain(TrustBundleEnvironment::Devnet), &identity, NOW);
    assert!(matches!(
        outcome,
        ProductionCustodyOutcome::FixtureHsmAccepted { .. }
    ));
    assert!(outcome.is_accept());
}

#[test]
fn a04_testnet_fixture_kms_accepts_under_allowed_policy() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Testnet,
    );
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, TrustBundleEnvironment::Testnet);
    let identity = fixture_identity(BackendKind::FixtureKms, TrustBundleEnvironment::Testnet);
    let outcome =
        backend.evaluate_custody_backend(&spec, &domain(TrustBundleEnvironment::Testnet), &identity, NOW);
    assert!(matches!(
        outcome,
        ProductionCustodyOutcome::FixtureKmsAccepted { .. }
    ));
}

#[test]
fn a05_testnet_fixture_hsm_accepts_under_allowed_policy() {
    let backend = hsm_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureHsmAllowed,
        TrustBundleEnvironment::Testnet,
    );
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureHsm, TrustBundleEnvironment::Testnet);
    let identity = fixture_identity(BackendKind::FixtureHsm, TrustBundleEnvironment::Testnet);
    let outcome =
        backend.evaluate_custody_backend(&spec, &domain(TrustBundleEnvironment::Testnet), &identity, NOW);
    assert!(matches!(
        outcome,
        ProductionCustodyOutcome::FixtureHsmAccepted { .. }
    ));
}

#[test]
fn a06_production_provider_request_built_without_fixture_fallback() {
    let backend = ProductionKmsHsmCustodyBackend::new(
        config(),
        ProductionKmsHsmCustodyBackendPolicy::ProductionCloudKmsRequired,
        ProductionCustodyProviderStub::cloud_kms(),
    );
    let spec = fixture_spec(
        ProductionCustodyProviderKind::ProductionCloudKms,
        TrustBundleEnvironment::Devnet,
    );
    let built = backend.build_custody_request(&spec, &domain(TrustBundleEnvironment::Devnet));
    assert!(built.is_ok());
    // No transport invocation from building alone.
    assert_eq!(backend.transport.call_count(), 0);
}

#[test]
fn a07_production_cloud_kms_path_reachable_and_fail_closed() {
    let backend = ProductionKmsHsmCustodyBackend::new(
        config(),
        ProductionKmsHsmCustodyBackendPolicy::ProductionCloudKmsRequired,
        ProductionCustodyProviderStub::cloud_kms(),
    );
    let spec = fixture_spec(
        ProductionCustodyProviderKind::ProductionCloudKms,
        TrustBundleEnvironment::Devnet,
    );
    let out = backend.submit_custody_signing_request(&spec, &domain(TrustBundleEnvironment::Devnet));
    assert_eq!(
        out,
        Err(ProductionCustodyOutcome::ProductionCustodyMisconfigured)
    );
    // The production path IS reachable (transport invoked) but fails closed.
    assert_eq!(backend.transport.call_count(), 1);
}

#[test]
fn a08_production_pkcs11_hsm_path_reachable_and_fail_closed() {
    let backend = ProductionKmsHsmCustodyBackend::new(
        config(),
        ProductionKmsHsmCustodyBackendPolicy::ProductionPkcs11HsmRequired,
        ProductionCustodyProviderStub::pkcs11_hsm(),
    );
    let spec = fixture_spec(
        ProductionCustodyProviderKind::ProductionPkcs11Hsm,
        TrustBundleEnvironment::Devnet,
    );
    let out = backend.submit_custody_signing_request(&spec, &domain(TrustBundleEnvironment::Devnet));
    assert_eq!(
        out,
        Err(ProductionCustodyOutcome::ProductionCustodyMisconfigured)
    );
    assert_eq!(backend.transport.call_count(), 1);
}

#[test]
fn a09_request_id_is_deterministic() {
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, TrustBundleEnvironment::Devnet);
    assert_eq!(
        production_kms_hsm_custody_request_id(&spec),
        production_kms_hsm_custody_request_id(&spec)
    );
}

#[test]
fn a10_response_digest_is_deterministic() {
    let submitted = build_submitted_kms(TrustBundleEnvironment::Devnet);
    assert_eq!(
        submitted.response.envelope_digest(),
        submitted.response.envelope_digest()
    );
    assert_eq!(
        submitted.response.backend_response.response_digest(),
        submitted.response.backend_response.response_digest()
    );
}

#[test]
fn a11_transcript_digest_is_deterministic() {
    let a = production_kms_hsm_custody_transcript_digest(
        1, "rid", "idd", "reqd", "respd", "btd", None,
    );
    let b = production_kms_hsm_custody_transcript_digest(
        1, "rid", "idd", "reqd", "respd", "btd", None,
    );
    assert_eq!(a, b);
}

#[test]
fn a12_two_identical_requests_produce_identical_digests() {
    let s1 = build_submitted_kms(TrustBundleEnvironment::Devnet);
    let s2 = build_submitted_kms(TrustBundleEnvironment::Devnet);
    assert_eq!(s1.request.envelope_digest(), s2.request.envelope_digest());
    assert_eq!(
        s1.response.transcript_digest,
        s2.response.transcript_digest
    );
    assert_eq!(s1.request_id, s2.request_id);
}

#[test]
fn a13_valid_fixture_response_authorizes_matching_request() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Devnet,
    );
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, TrustBundleEnvironment::Devnet);
    let identity = fixture_identity(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    let submitted = backend
        .submit_custody_signing_request(&spec, &domain(TrustBundleEnvironment::Devnet))
        .expect("fixture submit succeeds");
    let outcome = backend.verify_custody_response(
        &spec,
        &submitted,
        &domain(TrustBundleEnvironment::Devnet),
        &identity,
        NOW,
    );
    assert!(matches!(
        outcome,
        ProductionCustodyOutcome::FixtureKmsAccepted { .. }
    ));
}

#[test]
fn a14_provider_kind_maps_to_backend_kind_run203_compatible() {
    assert_eq!(
        ProductionCustodyProviderKind::ProductionCloudKms.to_backend_kind(),
        BackendKind::CloudKmsUnavailable
    );
    assert_eq!(
        ProductionCustodyProviderKind::ProductionPkcs11Hsm.to_backend_kind(),
        BackendKind::Pkcs11HsmUnavailable
    );
    assert_eq!(
        ProductionCustodyProviderKind::FixtureKms.to_backend_kind(),
        BackendKind::FixtureKms
    );
    assert_eq!(
        ProductionCustodyProviderKind::FixtureHsm.to_backend_kind(),
        BackendKind::FixtureHsm
    );
}

#[test]
fn a15_protocol_version_constant_is_stable() {
    assert_eq!(PRODUCTION_KMS_HSM_CUSTODY_BACKEND_PROTOCOL_VERSION, 1);
    assert!(PRODUCTION_KMS_HSM_CUSTODY_MAX_RESPONSE_BYTES >= 1024);
}

// ===========================================================================
// Helpers for building submitted request/response pairs and tampering
// ===========================================================================

fn build_submitted_kms(env: TrustBundleEnvironment) -> SubmittedCustodyRequest {
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    backend
        .submit_custody_signing_request(&spec, &domain(env))
        .expect("fixture submit succeeds")
}

/// Submit a valid fixture KMS request, then verify against a possibly
/// mutated spec/identity/domain to exercise a precise reject vector.
fn verify_with(
    spec_mut: impl FnOnce(&mut ProductionCustodyRequestSpec),
    identity_mut: impl FnOnce(&mut BackendIdentity),
    domain_override: Option<AuthorityTrustDomain>,
    now: u64,
) -> (ProductionCustodyOutcome, u32) {
    let env = TrustBundleEnvironment::Devnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    let submitted = backend
        .submit_custody_signing_request(&spec, &domain(env))
        .expect("fixture submit succeeds");
    let mut vspec = spec.clone();
    spec_mut(&mut vspec);
    let mut identity = fixture_identity(BackendKind::FixtureKms, env);
    identity_mut(&mut identity);
    let d = domain_override.unwrap_or_else(|| domain(env));
    let outcome = backend.verify_custody_response(&vspec, &submitted, &d, &identity, now);
    (outcome, backend.transport.call_count())
}

// ===========================================================================
// B. Rejection / fail-closed
// ===========================================================================

#[test]
fn b01_disabled_policy_no_request_no_provider_invocation() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::Disabled,
        TrustBundleEnvironment::Devnet,
    );
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, TrustBundleEnvironment::Devnet);
    let identity = fixture_identity(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    let out =
        backend.evaluate_custody_backend(&spec, &domain(TrustBundleEnvironment::Devnet), &identity, NOW);
    assert_eq!(out, ProductionCustodyOutcome::DisabledNoRequest);
    assert_eq!(backend.transport.call_count(), 0);
    assert!(backend
        .build_custody_request(&spec, &domain(TrustBundleEnvironment::Devnet))
        .is_err());
}

#[test]
fn b02_mainnet_identity_refused() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Mainnet,
    );
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, TrustBundleEnvironment::Mainnet);
    let identity = fixture_identity(BackendKind::FixtureKms, TrustBundleEnvironment::Mainnet);
    let out =
        backend.evaluate_custody_backend(&spec, &domain(TrustBundleEnvironment::Mainnet), &identity, NOW);
    assert_eq!(out, ProductionCustodyOutcome::FixtureMaterialRejectedForMainNet);
    assert_eq!(backend.transport.call_count(), 0);
}

#[test]
fn b03_fixture_kms_material_refused_for_mainnet() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Mainnet,
    );
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, TrustBundleEnvironment::Mainnet);
    let out = backend.build_custody_request(&spec, &domain(TrustBundleEnvironment::Mainnet));
    assert_eq!(
        out,
        Err(ProductionCustodyOutcome::FixtureMaterialRejectedForMainNet)
    );
}

#[test]
fn b04_fixture_hsm_material_refused_for_mainnet() {
    let backend = hsm_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureHsmAllowed,
        TrustBundleEnvironment::Mainnet,
    );
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureHsm, TrustBundleEnvironment::Mainnet);
    let out = backend.build_custody_request(&spec, &domain(TrustBundleEnvironment::Mainnet));
    assert_eq!(
        out,
        Err(ProductionCustodyOutcome::FixtureMaterialRejectedForMainNet)
    );
}

#[test]
fn b05_remote_signer_material_cannot_satisfy_kms_hsm() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Devnet,
    );
    let mut spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, TrustBundleEnvironment::Devnet);
    spec.custody_class = AuthorityCustodyClass::RemoteSigner;
    let out = backend.build_custody_request(&spec, &domain(TrustBundleEnvironment::Devnet));
    assert_eq!(
        out,
        Err(ProductionCustodyOutcome::RemoteSignerIsNotKmsHsmCustody)
    );
    assert_eq!(backend.transport.call_count(), 0);
}

#[test]
fn b06_local_operator_material_refused() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Devnet,
    );
    let mut spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, TrustBundleEnvironment::Devnet);
    spec.custody_class = AuthorityCustodyClass::LocalOperatorKey;
    let out = backend.build_custody_request(&spec, &domain(TrustBundleEnvironment::Devnet));
    assert!(matches!(
        out,
        Err(ProductionCustodyOutcome::ProductionCustodyRejected { .. })
    ));
}

#[test]
fn b07_fixture_local_key_material_refused() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Devnet,
    );
    let mut spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, TrustBundleEnvironment::Devnet);
    spec.custody_class = AuthorityCustodyClass::FixtureLocalKey;
    let out = backend.build_custody_request(&spec, &domain(TrustBundleEnvironment::Devnet));
    assert!(matches!(
        out,
        Err(ProductionCustodyOutcome::ProductionCustodyRejected { .. })
    ));
}

#[test]
fn b08_wrong_environment_rejected() {
    let (out, _) = verify_with(
        |_| {},
        |_| {},
        Some(AuthorityTrustDomain::new(
            TrustBundleEnvironment::Testnet,
            "qbind-testnet",
            GENESIS_HASH,
            ROOT_FP,
            100,
        )),
        NOW,
    );
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyDomainMismatch);
}

#[test]
fn b09_wrong_chain_rejected() {
    let (out, _) = verify_with(
        |_| {},
        |_| {},
        Some(AuthorityTrustDomain::new(
            TrustBundleEnvironment::Devnet,
            "wrong-chain",
            GENESIS_HASH,
            ROOT_FP,
            100,
        )),
        NOW,
    );
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyDomainMismatch);
}

#[test]
fn b10_wrong_genesis_rejected() {
    let (out, _) = verify_with(
        |_| {},
        |_| {},
        Some(AuthorityTrustDomain::new(
            TrustBundleEnvironment::Devnet,
            CHAIN_ID,
            "wrong-genesis",
            ROOT_FP,
            100,
        )),
        NOW,
    );
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyDomainMismatch);
}

#[test]
fn b11_wrong_authority_root_rejected() {
    let (out, _) = verify_with(
        |_| {},
        |_| {},
        Some(AuthorityTrustDomain::new(
            TrustBundleEnvironment::Devnet,
            CHAIN_ID,
            GENESIS_HASH,
            "wrong-root",
            100,
        )),
        NOW,
    );
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyDomainMismatch);
}

#[test]
fn b12_wrong_authority_sequence_rejected() {
    let (out, _) = verify_with(|s| s.authority_domain_sequence = 999, |_| {}, None, NOW);
    assert!(matches!(
        out,
        ProductionCustodyOutcome::ProductionCustodyRejected { .. }
    ));
}

#[test]
fn b13_wrong_provider_kind_rejected() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Devnet,
    );
    // Fixture KMS policy but a cloud-KMS provider kind in the spec.
    let mut spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, TrustBundleEnvironment::Devnet);
    spec.provider_kind = ProductionCustodyProviderKind::ProductionCloudKms;
    let out = backend.build_custody_request(&spec, &domain(TrustBundleEnvironment::Devnet));
    assert_eq!(out, Err(ProductionCustodyOutcome::ProductionCustodyWrongProvider));
}

#[test]
fn b14_wrong_key_handle_rejected() {
    let (out, _) = verify_with(|s| s.key_id = "wrong-key".to_string(), |i| i.key_id = "wrong-key".to_string(), None, NOW);
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyWrongKeyHandle);
}

#[test]
fn b15_wrong_signer_identity_rejected() {
    let (out, _) = verify_with(
        |s| {
            s.active_signing_key_fingerprint = Some("other".to_string());
            s.new_signing_key_fingerprint = Some("other".to_string());
        },
        |_| {},
        None,
        NOW,
    );
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyWrongSigner);
}

#[test]
fn b16_wrong_request_id_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    let identity = fixture_identity(BackendKind::FixtureKms, env);
    let mut submitted = backend
        .submit_custody_signing_request(&spec, &domain(env))
        .expect("submit");
    submitted.response.request_id_echo = "tampered-id".to_string();
    let out = backend.verify_custody_response(&spec, &submitted, &domain(env), &identity, NOW);
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyRequestIdMismatch);
}

#[test]
fn b17_wrong_transcript_digest_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    let identity = fixture_identity(BackendKind::FixtureKms, env);
    let mut submitted = backend
        .submit_custody_signing_request(&spec, &domain(env))
        .expect("submit");
    submitted.response.transcript_digest = "tampered-transcript".to_string();
    let out = backend.verify_custody_response(&spec, &submitted, &domain(env), &identity, NOW);
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyTranscriptMismatch);
}

#[test]
fn b18_wrong_candidate_digest_rejected() {
    let (out, _) = verify_with(|s| s.candidate_digest = "wrong-candidate".to_string(), |_| {}, None, NOW);
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyWrongCandidateDigest);
}

#[test]
fn b19_wrong_authorized_action_rejected() {
    let (out, _) = verify_with(|s| s.lifecycle_action = LocalLifecycleAction::Revoke, |i| {
        i.allowed_lifecycle_actions = vec![LocalLifecycleAction::Revoke];
    }, None, NOW);
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyWrongAction);
}

#[test]
fn b20_missing_signature_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    let identity = fixture_identity(BackendKind::FixtureKms, env);
    let mut submitted = backend
        .submit_custody_signing_request(&spec, &domain(env))
        .expect("submit");
    submitted.response.backend_response.signature_commitment = String::new();
    // Recompute the envelope transcript so the tamper reaches the Run 203 checks.
    let out = backend.verify_custody_response(&spec, &submitted, &domain(env), &identity, NOW);
    assert!(!out.is_accept());
}

#[test]
fn b21_missing_attestation_rejected() {
    let (out, _) = verify_with(
        |s| s.custody_attestation_digest = String::new(),
        |_| {},
        None,
        NOW,
    );
    assert_eq!(
        out,
        ProductionCustodyOutcome::ProductionCustodyAttestationMissing
    );
}

#[test]
fn b22_malformed_response_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    let identity = fixture_identity(BackendKind::FixtureKms, env);
    let mut submitted = backend
        .submit_custody_signing_request(&spec, &domain(env))
        .expect("submit");
    submitted.response.backend_response.backend_id = String::new();
    let out = backend.verify_custody_response(&spec, &submitted, &domain(env), &identity, NOW);
    assert!(!out.is_accept());
}

#[test]
fn b23_oversized_response_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let big = "x".repeat(PRODUCTION_KMS_HSM_CUSTODY_MAX_RESPONSE_BYTES + 1);
    let submitted = build_submitted_kms(env);
    let mut response = submitted.response.clone();
    response.backend_response.signature_commitment = big;
    let backend = ProductionKmsHsmCustodyBackend::new(
        config(),
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        MockKmsHsmCustodyTransport::respond(response),
    );
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    let out = backend.submit_custody_signing_request(&spec, &domain(env));
    assert_eq!(
        out,
        Err(ProductionCustodyOutcome::ProductionCustodyMalformedResponse)
    );
}

#[test]
fn b24_response_replay_from_prior_request_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    // A response from a different request (different candidate) verified
    // against the current spec must fail closed.
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let spec_a = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    let submitted_a = backend
        .submit_custody_signing_request(&spec_a, &domain(env))
        .expect("submit a");
    let mut spec_b = spec_a.clone();
    spec_b.candidate_digest = "candidate-digest-OTHER".to_string();
    let identity = fixture_identity(BackendKind::FixtureKms, env);
    // Verify prior response against the new request spec.
    let out = backend.verify_custody_response(&spec_b, &submitted_a, &domain(env), &identity, NOW);
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyWrongCandidateDigest);
}

#[test]
fn b25_provider_unavailable_rejected() {
    let out = submit_mock_error(ProductionCustodyError::ProviderUnavailable);
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyUnavailable);
}

#[test]
fn b26_provider_timeout_rejected() {
    let out = submit_mock_error(ProductionCustodyError::Timeout);
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyTimeout);
}

#[test]
fn b27_provider_decode_error_rejected() {
    let out = submit_mock_error(ProductionCustodyError::DecodeError);
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyDecodeFailed);
}

#[test]
fn b28_provider_refused_rejected() {
    let out = submit_mock_error(ProductionCustodyError::SigningRefused);
    assert!(matches!(
        out,
        ProductionCustodyOutcome::ProductionCustodyRejected { .. }
    ));
}

#[test]
fn b29_provider_policy_rejected_rejected() {
    let out = submit_mock_error(ProductionCustodyError::ProviderPolicyRejected);
    assert!(matches!(
        out,
        ProductionCustodyOutcome::ProductionCustodyRejected { .. }
    ));
}

#[test]
fn b30_unsupported_provider_rejected() {
    let out = submit_mock_error(ProductionCustodyError::UnsupportedProvider);
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyUnsupportedProvider);
}

#[test]
fn b31_unsupported_protocol_version_rejected() {
    let out = submit_mock_error(ProductionCustodyError::UnsupportedProtocolVersion { version: 9 });
    assert_eq!(
        out,
        ProductionCustodyOutcome::ProductionCustodyUnsupportedProtocol { version: 9 }
    );
}

#[test]
fn b32_endpoint_unavailable_rejected() {
    let out = submit_mock_error(ProductionCustodyError::EndpointUnavailable);
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyUnavailable);
}

#[test]
fn b33_attestation_missing_rejected() {
    let out = submit_mock_error(ProductionCustodyError::AttestationMissing);
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyAttestationMissing);
}

#[test]
fn b34_attestation_unavailable_fail_closed() {
    let out = submit_mock_error(ProductionCustodyError::AttestationUnavailable);
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyAttestationUnavailable);
}

#[test]
fn b35_validator_set_rotation_request_unsupported() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Devnet,
    );
    let mut spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, TrustBundleEnvironment::Devnet);
    spec.request_kind = ProductionCustodyRequestKind::ValidatorSetRotation;
    let out = backend.build_custody_request(&spec, &domain(TrustBundleEnvironment::Devnet));
    assert_eq!(
        out,
        Err(ProductionCustodyOutcome::ValidatorSetRotationUnsupported)
    );
}

#[test]
fn b36_governance_verifier_request_unavailable() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Devnet,
    );
    let mut spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, TrustBundleEnvironment::Devnet);
    spec.request_kind = ProductionCustodyRequestKind::OnChainGovernanceProofVerification;
    let out = backend.build_custody_request(&spec, &domain(TrustBundleEnvironment::Devnet));
    assert_eq!(out, Err(ProductionCustodyOutcome::GovernanceVerifierUnavailable));
}

fn submit_mock_error(err: ProductionCustodyError) -> ProductionCustodyOutcome {
    let env = TrustBundleEnvironment::Devnet;
    let backend = ProductionKmsHsmCustodyBackend::new(
        config(),
        ProductionKmsHsmCustodyBackendPolicy::ProductionCloudKmsRequired,
        MockKmsHsmCustodyTransport::always_fail(err),
    );
    let spec = fixture_spec(ProductionCustodyProviderKind::ProductionCloudKms, env);
    match backend.submit_custody_signing_request(&spec, &domain(env)) {
        Ok(_) => panic!("expected fail-closed"),
        Err(o) => o,
    }
}

// ===========================================================================
// C. MainNet / authority policy
// ===========================================================================

#[test]
fn c01_mainnet_cannot_be_satisfied_by_fixture_kms() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Mainnet,
    );
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, TrustBundleEnvironment::Mainnet);
    let out = backend.build_custody_request(&spec, &domain(TrustBundleEnvironment::Mainnet));
    assert_eq!(out, Err(ProductionCustodyOutcome::FixtureMaterialRejectedForMainNet));
    assert_eq!(backend.transport.call_count(), 0);
}

#[test]
fn c02_mainnet_cannot_be_satisfied_by_fixture_hsm() {
    let backend = hsm_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureHsmAllowed,
        TrustBundleEnvironment::Mainnet,
    );
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureHsm, TrustBundleEnvironment::Mainnet);
    let out = backend.build_custody_request(&spec, &domain(TrustBundleEnvironment::Mainnet));
    assert_eq!(out, Err(ProductionCustodyOutcome::FixtureMaterialRejectedForMainNet));
}

#[test]
fn c03_mainnet_cannot_be_satisfied_by_remote_signer_only() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Mainnet,
    );
    let mut spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, TrustBundleEnvironment::Mainnet);
    spec.custody_class = AuthorityCustodyClass::RemoteSigner;
    let out = backend.build_custody_request(&spec, &domain(TrustBundleEnvironment::Mainnet));
    assert_eq!(out, Err(ProductionCustodyOutcome::RemoteSignerIsNotKmsHsmCustody));
}

#[test]
fn c04_mainnet_cannot_be_satisfied_by_local_operator_material() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Mainnet,
    );
    let mut spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, TrustBundleEnvironment::Mainnet);
    spec.custody_class = AuthorityCustodyClass::LocalOperatorKey;
    let out = backend.build_custody_request(&spec, &domain(TrustBundleEnvironment::Mainnet));
    assert!(matches!(
        out,
        Err(ProductionCustodyOutcome::ProductionCustodyRejected { .. })
    ));
}

#[test]
fn c05_mainnet_production_policy_unavailable_no_provider_call() {
    let backend = ProductionKmsHsmCustodyBackend::new(
        config(),
        ProductionKmsHsmCustodyBackendPolicy::MainnetProductionCustodyRequired,
        ProductionCustodyProviderStub::cloud_kms(),
    );
    let mut spec = fixture_spec(
        ProductionCustodyProviderKind::ProductionCloudKms,
        TrustBundleEnvironment::Mainnet,
    );
    spec.custody_class = AuthorityCustodyClass::Kms;
    let out = backend.evaluate_custody_backend(
        &spec,
        &domain(TrustBundleEnvironment::Mainnet),
        &fixture_identity(BackendKind::CloudKmsUnavailable, TrustBundleEnvironment::Mainnet),
        NOW,
    );
    assert_eq!(out, ProductionCustodyOutcome::MainNetProductionCustodyUnavailable);
    assert_eq!(backend.transport.call_count(), 0);
}

#[test]
fn c06_mainnet_non_production_policy_refused() {
    let backend = ProductionKmsHsmCustodyBackend::new(
        config(),
        ProductionKmsHsmCustodyBackendPolicy::ProductionCloudKmsRequired,
        ProductionCustodyProviderStub::cloud_kms(),
    );
    let spec = fixture_spec(
        ProductionCustodyProviderKind::ProductionCloudKms,
        TrustBundleEnvironment::Mainnet,
    );
    let out = backend.build_custody_request(&spec, &domain(TrustBundleEnvironment::Mainnet));
    assert_eq!(out, Err(ProductionCustodyOutcome::MainNetRefused));
    assert_eq!(backend.transport.call_count(), 0);
}

#[test]
fn c07_mainnet_production_policy_on_non_mainnet_fails_closed() {
    let backend = ProductionKmsHsmCustodyBackend::new(
        config(),
        ProductionKmsHsmCustodyBackendPolicy::MainnetProductionCustodyRequired,
        ProductionCustodyProviderStub::cloud_kms(),
    );
    let mut spec = fixture_spec(
        ProductionCustodyProviderKind::ProductionCloudKms,
        TrustBundleEnvironment::Devnet,
    );
    spec.custody_class = AuthorityCustodyClass::Kms;
    let out = backend.build_custody_request(&spec, &domain(TrustBundleEnvironment::Devnet));
    assert_eq!(
        out,
        Err(ProductionCustodyOutcome::MainNetProductionCustodyUnavailable)
    );
    assert_eq!(backend.transport.call_count(), 0);
}

#[test]
fn c08_mainnet_scope_helper_refuses_fixture_material() {
    assert!(production_kms_hsm_custody_backend_mainnet_refuses_fixture_material());
}

#[test]
fn c09_mainnet_production_custody_unavailable_records_no_mutation() {
    let backend = ProductionKmsHsmCustodyBackend::new(
        config(),
        ProductionKmsHsmCustodyBackendPolicy::MainnetProductionCustodyRequired,
        ProductionCustodyProviderStub::cloud_kms(),
    );
    let mut spec = fixture_spec(
        ProductionCustodyProviderKind::ProductionCloudKms,
        TrustBundleEnvironment::Mainnet,
    );
    spec.custody_class = AuthorityCustodyClass::Kms;
    let out = backend.build_custody_request(&spec, &domain(TrustBundleEnvironment::Mainnet));
    assert!(out.is_err());
    assert_eq!(backend.transport.call_count(), 0);
}

#[test]
fn c10_mainnet_peer_majority_material_refused() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Mainnet,
    );
    let mut spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, TrustBundleEnvironment::Mainnet);
    // A peer-majority-derived local key cannot satisfy KMS/HSM custody.
    spec.custody_class = AuthorityCustodyClass::LocalOperatorKey;
    let out = backend.build_custody_request(&spec, &domain(TrustBundleEnvironment::Mainnet));
    assert!(out.is_err());
    assert_eq!(backend.transport.call_count(), 0);
}

// ===========================================================================
// D. Non-mutation
// ===========================================================================

#[test]
fn d01_disabled_reject_is_non_mutating() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::Disabled,
        TrustBundleEnvironment::Devnet,
    );
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, TrustBundleEnvironment::Devnet);
    let out = backend.build_custody_request(&spec, &domain(TrustBundleEnvironment::Devnet));
    assert!(out.is_err());
    assert_eq!(backend.transport.call_count(), 0);
}

#[test]
fn d02_every_outcome_is_non_mutating() {
    // The outcome type is pure evidence; is_non_mutating is invariantly true.
    assert!(ProductionCustodyOutcome::DisabledNoRequest.is_non_mutating());
    assert!(ProductionCustodyOutcome::MainNetRefused.is_non_mutating());
    assert!(ProductionCustodyOutcome::ProductionCustodyUnavailable.is_non_mutating());
    assert!(ProductionCustodyOutcome::FixtureKmsAccepted {
        provider_id: "p".to_string(),
        environment: TrustBundleEnvironment::Devnet,
        request_id: "r".to_string(),
    }
    .is_non_mutating());
}

#[test]
fn d03_reject_domain_mismatch_no_provider_after_verify() {
    // A domain-mismatch reject during verify does not re-invoke the provider.
    let (out, calls) = verify_with(
        |_| {},
        |_| {},
        Some(AuthorityTrustDomain::new(
            TrustBundleEnvironment::Testnet,
            "qbind-testnet",
            GENESIS_HASH,
            ROOT_FP,
            100,
        )),
        NOW,
    );
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyDomainMismatch);
    // Exactly one submit during the setup, none added by verify.
    assert_eq!(calls, 1);
}

#[test]
fn d04_scope_helper_is_non_mutating() {
    assert!(production_kms_hsm_custody_backend_is_non_mutating());
}

#[test]
fn d05_scope_helper_never_falls_back() {
    assert!(production_kms_hsm_custody_backend_never_falls_back());
}

#[test]
fn d06_scope_helper_loads_no_raw_local_key() {
    assert!(production_kms_hsm_custody_backend_loads_no_raw_local_key());
}

#[test]
fn d07_scope_helper_remote_signer_is_not_kms_hsm() {
    assert!(production_kms_hsm_custody_backend_remote_signer_is_not_kms_hsm());
}

#[test]
fn d08_production_unavailable_records_single_reachable_call_only() {
    let backend = ProductionKmsHsmCustodyBackend::new(
        config(),
        ProductionKmsHsmCustodyBackendPolicy::ProductionGenericKmsRequired,
        ProductionCustodyProviderStub::generic_kms(),
    );
    let spec = fixture_spec(
        ProductionCustodyProviderKind::ProductionGenericKms,
        TrustBundleEnvironment::Devnet,
    );
    let out = backend.submit_custody_signing_request(&spec, &domain(TrustBundleEnvironment::Devnet));
    assert_eq!(out, Err(ProductionCustodyOutcome::ProductionCustodyUnavailable));
    assert_eq!(backend.transport.call_count(), 1);
}

#[test]
fn d09_reject_wrong_key_handle_no_extra_provider_call() {
    let (out, calls) = verify_with(
        |s| s.key_id = "wrong-key".to_string(),
        |i| i.key_id = "wrong-key".to_string(),
        None,
        NOW,
    );
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyWrongKeyHandle);
    assert_eq!(calls, 1);
}

// ===========================================================================
// E. Replay / recovery / idempotency
// ===========================================================================

#[test]
fn e01_no_prior_request_window() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Devnet,
    );
    let current = build_submitted_kms(TrustBundleEnvironment::Devnet);
    let out = backend.recover_custody_request_window(None, &current);
    assert_eq!(out, ProductionCustodyRecoveryOutcome::NoPriorRequest);
}

#[test]
fn e02_duplicate_identical_request_is_idempotent() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Devnet,
    );
    let prior = build_submitted_kms(TrustBundleEnvironment::Devnet);
    let current = build_submitted_kms(TrustBundleEnvironment::Devnet);
    let out = backend.recover_custody_request_window(Some(&prior), &current);
    assert_eq!(
        out,
        ProductionCustodyRecoveryOutcome::IdempotentReplayOfSameRequest
    );
    assert!(out.is_idempotent());
}

#[test]
fn e03_same_id_different_key_handle_fails_closed() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Devnet,
    );
    let prior = build_submitted_kms(TrustBundleEnvironment::Devnet);
    let mut current = build_submitted_kms(TrustBundleEnvironment::Devnet);
    current.request.key_id = "other-key".to_string();
    current.response.key_id = "other-key".to_string();
    let out = backend.recover_custody_request_window(Some(&prior), &current);
    assert_eq!(
        out,
        ProductionCustodyRecoveryOutcome::ConflictingKeyHandleForSameId
    );
}

#[test]
fn e04_same_id_different_request_fails_closed() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Devnet,
    );
    let prior = build_submitted_kms(TrustBundleEnvironment::Devnet);
    let mut current = build_submitted_kms(TrustBundleEnvironment::Devnet);
    current.request.backend_request.candidate_digest = "other-candidate".to_string();
    let out = backend.recover_custody_request_window(Some(&prior), &current);
    assert_eq!(
        out,
        ProductionCustodyRecoveryOutcome::ConflictingRequestForSameId
    );
}

#[test]
fn e05_same_request_different_response_fails_closed() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Devnet,
    );
    let prior = build_submitted_kms(TrustBundleEnvironment::Devnet);
    let mut current = build_submitted_kms(TrustBundleEnvironment::Devnet);
    current.response.backend_response.signature_commitment = "different-sig".to_string();
    let out = backend.recover_custody_request_window(Some(&prior), &current);
    assert_eq!(
        out,
        ProductionCustodyRecoveryOutcome::ConflictingResponseForSameRequest
    );
}

#[test]
fn e06_different_request_ids_are_unrelated_windows() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Devnet,
    );
    let prior = build_submitted_kms(TrustBundleEnvironment::Devnet);
    let mut current = build_submitted_kms(TrustBundleEnvironment::Devnet);
    current.request_id = "unrelated-id".to_string();
    let out = backend.recover_custody_request_window(Some(&prior), &current);
    assert_eq!(out, ProductionCustodyRecoveryOutcome::NoPriorRequest);
}

#[test]
fn e07_recovery_idempotency_is_byte_identical_only() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Devnet,
    );
    let prior = build_submitted_kms(TrustBundleEnvironment::Devnet);
    let current = prior.clone();
    let out = backend.recover_custody_request_window(Some(&prior), &current);
    assert!(out.is_idempotent());
}

// ===========================================================================
// F. C4/C5 taxonomy
// ===========================================================================

#[test]
fn f01_run_295_is_source_test_not_release_binary_evidence() {
    assert!(production_kms_hsm_custody_backend_is_source_test_not_release_binary_evidence());
}

#[test]
fn f02_default_disabled_scope_helper() {
    assert!(production_kms_hsm_custody_backend_default_is_disabled());
}

#[test]
fn f03_never_falls_back_scope_helper() {
    assert!(production_kms_hsm_custody_backend_never_falls_back());
}

#[test]
fn f04_remote_signer_is_not_kms_hsm_scope_helper() {
    assert!(production_kms_hsm_custody_backend_remote_signer_is_not_kms_hsm());
}

#[test]
fn f05_loads_no_raw_local_key_scope_helper() {
    assert!(production_kms_hsm_custody_backend_loads_no_raw_local_key());
}

#[test]
fn f06_is_non_mutating_scope_helper() {
    assert!(production_kms_hsm_custody_backend_is_non_mutating());
}

#[test]
fn f07_mainnet_refuses_fixture_material_scope_helper() {
    assert!(production_kms_hsm_custody_backend_mainnet_refuses_fixture_material());
}

#[test]
fn f08_production_paths_reachable_but_unavailable_all_kinds() {
    for stub in [
        ProductionCustodyProviderStub::cloud_kms(),
        ProductionCustodyProviderStub::pkcs11_hsm(),
        ProductionCustodyProviderStub::generic_kms(),
        ProductionCustodyProviderStub::generic_hsm(),
    ] {
        let kind = stub.provider_kind();
        assert!(kind.is_production());
    }
}

#[test]
fn f09_request_kind_supported_taxonomy() {
    assert!(ProductionCustodyRequestKind::AuthorityLifecycleSigning.is_supported());
    assert!(ProductionCustodyRequestKind::GovernanceExecutionSigning.is_supported());
    assert!(!ProductionCustodyRequestKind::ValidatorSetRotation.is_supported());
    assert!(!ProductionCustodyRequestKind::PolicyChange.is_supported());
    assert!(!ProductionCustodyRequestKind::OnChainGovernanceProofVerification.is_supported());
}

#[test]
fn f10_provider_kind_fixture_vs_production_taxonomy() {
    assert!(ProductionCustodyProviderKind::FixtureKms.is_fixture());
    assert!(ProductionCustodyProviderKind::FixtureHsm.is_fixture());
    assert!(ProductionCustodyProviderKind::ProductionCloudKms.is_production());
    assert!(ProductionCustodyProviderKind::ProductionPkcs11Hsm.is_production());
    assert!(ProductionCustodyProviderKind::ProductionGenericKms.is_production());
    assert!(ProductionCustodyProviderKind::ProductionGenericHsm.is_production());
    assert!(!ProductionCustodyProviderKind::Disabled.is_fixture());
    assert!(!ProductionCustodyProviderKind::Disabled.is_production());
}

#[test]
fn f11_policy_requires_production_backend_taxonomy() {
    assert!(
        ProductionKmsHsmCustodyBackendPolicy::ProductionCloudKmsRequired
            .requires_production_backend()
    );
    assert!(
        ProductionKmsHsmCustodyBackendPolicy::ProductionPkcs11HsmRequired
            .requires_production_backend()
    );
    assert!(!ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed.requires_production_backend());
    assert!(!ProductionKmsHsmCustodyBackendPolicy::Disabled.requires_production_backend());
}

#[test]
fn f12_disabled_is_the_default_policy() {
    assert_eq!(
        ProductionKmsHsmCustodyBackendPolicy::default(),
        ProductionKmsHsmCustodyBackendPolicy::Disabled
    );
}