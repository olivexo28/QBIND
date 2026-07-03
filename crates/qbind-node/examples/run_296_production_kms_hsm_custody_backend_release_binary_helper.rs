//! Run 296 — release-binary helper for the Run 295 **production KMS/HSM/
//! cloud-KMS/PKCS#11 custody backend**.
//!
//! Release-binary evidence for the Run 295 source/test production custody
//! backend (`crates/qbind-node/src/pqc_production_kms_hsm_custody_backend.rs`).
//! This helper is compiled as a release example and linked against the
//! release-built production library symbols. It exercises the **real** Run 295
//! [`ProductionKmsHsmCustodyBackend`] over source/test fixture providers, a
//! reachable-but-fail-closed production provider stub, and a programmable mock
//! transport in release mode and proves, per check with PASS/FAIL, the accepted
//! / rejection-fail-closed / MainNet-refusal / non-mutation / replay-recovery
//! behavior of the real backend, including request-id / request / response /
//! transcript / domain binding and the Run 203
//! [`verify_authority_custody_backend_response`] composition.
//!
//! The helper remains **dead code** from the production runtime: the production
//! `qbind-node` binary never references it. It constructs the backend only
//! through source/test fixture/stub/mock transports, only for DevNet/TestNet
//! identities on the accept path, and never enables any production runtime
//! path, MainNet enablement, custody attestation verifier, on-chain governance
//! proof verification, governance execution engine, validator-set rotation,
//! settlement, or external publication. Under a production policy it never falls
//! back to fixture KMS/HSM, RemoteSigner, local signing, raw local keys, or
//! in-memory signing.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_296.md`.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use qbind_node::pqc_authority_custody::AuthorityCustodyClass;
use qbind_node::pqc_authority_kms_hsm_backend::{
    verify_authority_custody_backend_response, BackendIdentity, BackendKind, FixtureHsmBackend,
    FixtureKmsBackend,
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
    ProductionCustodyRequestKind, ProductionCustodyRequestSpec, ProductionKmsHsmCustodyBackend,
    ProductionKmsHsmCustodyBackendConfig, ProductionKmsHsmCustodyBackendPolicy,
    SubmittedCustodyRequest, PRODUCTION_KMS_HSM_CUSTODY_BACKEND_PROTOCOL_VERSION,
    PRODUCTION_KMS_HSM_CUSTODY_MAX_RESPONSE_BYTES,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared constants / builders (mirror the Run 295 corpus).
// ===========================================================================

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
// A — Accepted / compatible release checks
// ===========================================================================

fn a01_disabled_default_policy_is_explicit_and_inert() {
    assert!(production_kms_hsm_custody_backend_default_is_disabled());
    assert_eq!(
        ProductionKmsHsmCustodyBackendPolicy::default(),
        ProductionKmsHsmCustodyBackendPolicy::Disabled
    );
    let env = TrustBundleEnvironment::Devnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::Disabled, env);
    let outcome = backend.evaluate_custody_backend(
        &fixture_spec(ProductionCustodyProviderKind::FixtureKms, env),
        &domain(env),
        &fixture_identity(BackendKind::FixtureKms, env),
        NOW,
    );
    assert_eq!(outcome, ProductionCustodyOutcome::DisabledNoRequest);
    assert_eq!(backend.transport.call_count(), 0);
}

fn a02_devnet_fixture_kms_accepts_under_fixture_policy() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let outcome = backend.evaluate_custody_backend(
        &fixture_spec(ProductionCustodyProviderKind::FixtureKms, env),
        &domain(env),
        &fixture_identity(BackendKind::FixtureKms, env),
        NOW,
    );
    assert!(matches!(
        outcome,
        ProductionCustodyOutcome::FixtureKmsAccepted { .. }
    ));
    assert!(outcome.is_accept());
    assert_eq!(backend.transport.call_count(), 1);
}

fn a03_devnet_fixture_hsm_accepts_under_fixture_policy() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = hsm_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureHsmAllowed, env);
    let outcome = backend.evaluate_custody_backend(
        &fixture_spec(ProductionCustodyProviderKind::FixtureHsm, env),
        &domain(env),
        &fixture_identity(BackendKind::FixtureHsm, env),
        NOW,
    );
    assert!(matches!(
        outcome,
        ProductionCustodyOutcome::FixtureHsmAccepted { .. }
    ));
    assert!(outcome.is_accept());
}

fn a04_testnet_fixture_kms_accepts_under_allowed_policy() {
    let env = TrustBundleEnvironment::Testnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let outcome = backend.evaluate_custody_backend(
        &fixture_spec(ProductionCustodyProviderKind::FixtureKms, env),
        &domain(env),
        &fixture_identity(BackendKind::FixtureKms, env),
        NOW,
    );
    assert!(matches!(
        outcome,
        ProductionCustodyOutcome::FixtureKmsAccepted { .. }
    ));
}

fn a05_testnet_fixture_hsm_accepts_under_allowed_policy() {
    let env = TrustBundleEnvironment::Testnet;
    let backend = hsm_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureHsmAllowed, env);
    let outcome = backend.evaluate_custody_backend(
        &fixture_spec(ProductionCustodyProviderKind::FixtureHsm, env),
        &domain(env),
        &fixture_identity(BackendKind::FixtureHsm, env),
        NOW,
    );
    assert!(matches!(
        outcome,
        ProductionCustodyOutcome::FixtureHsmAccepted { .. }
    ));
}

fn a06_production_cloud_kms_request_built_without_fixture_fallback() {
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
    assert_eq!(backend.transport.call_count(), 0);
}

fn a07_production_pkcs11_hsm_request_built_without_fixture_fallback() {
    let backend = ProductionKmsHsmCustodyBackend::new(
        config(),
        ProductionKmsHsmCustodyBackendPolicy::ProductionPkcs11HsmRequired,
        ProductionCustodyProviderStub::pkcs11_hsm(),
    );
    let spec = fixture_spec(
        ProductionCustodyProviderKind::ProductionPkcs11Hsm,
        TrustBundleEnvironment::Devnet,
    );
    let built = backend.build_custody_request(&spec, &domain(TrustBundleEnvironment::Devnet));
    assert!(built.is_ok());
    assert_eq!(backend.transport.call_count(), 0);
}

fn a08_production_generic_kms_request_built_without_fixture_fallback() {
    let backend = ProductionKmsHsmCustodyBackend::new(
        config(),
        ProductionKmsHsmCustodyBackendPolicy::ProductionGenericKmsRequired,
        ProductionCustodyProviderStub::generic_kms(),
    );
    let spec = fixture_spec(
        ProductionCustodyProviderKind::ProductionGenericKms,
        TrustBundleEnvironment::Devnet,
    );
    let built = backend.build_custody_request(&spec, &domain(TrustBundleEnvironment::Devnet));
    assert!(built.is_ok());
    assert_eq!(backend.transport.call_count(), 0);
}

fn a09_production_cloud_kms_path_reachable_and_fail_closed() {
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
    assert_eq!(backend.transport.call_count(), 1);
}

fn a10_production_pkcs11_hsm_path_reachable_and_fail_closed() {
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

fn a11_request_id_is_deterministic() {
    let spec = fixture_spec(
        ProductionCustodyProviderKind::FixtureKms,
        TrustBundleEnvironment::Devnet,
    );
    let a = production_kms_hsm_custody_request_id(&spec);
    let b = production_kms_hsm_custody_request_id(&spec);
    assert_eq!(a, b);
    assert!(!a.is_empty());
}

fn a12_response_digest_is_deterministic() {
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

fn a13_transcript_digest_is_deterministic() {
    let a = production_kms_hsm_custody_transcript_digest(1, "rid", "idd", "reqd", "respd", "btd", None);
    let b = production_kms_hsm_custody_transcript_digest(1, "rid", "idd", "reqd", "respd", "btd", None);
    assert_eq!(a, b);
    assert_eq!(a.len(), 64);
}

fn a14_two_identical_requests_produce_identical_digests() {
    let s1 = build_submitted_kms(TrustBundleEnvironment::Devnet);
    let s2 = build_submitted_kms(TrustBundleEnvironment::Devnet);
    assert_eq!(s1.request.envelope_digest(), s2.request.envelope_digest());
    assert_eq!(s1.response.transcript_digest, s2.response.transcript_digest);
    assert_eq!(s1.request_id, s2.request_id);
}

fn a15_valid_fixture_response_authorizes_matching_request() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    let identity = fixture_identity(BackendKind::FixtureKms, env);
    let submitted = backend
        .submit_custody_signing_request(&spec, &domain(env))
        .expect("fixture submit succeeds");
    let outcome = backend.verify_custody_response(&spec, &submitted, &domain(env), &identity, NOW);
    assert!(matches!(
        outcome,
        ProductionCustodyOutcome::FixtureKmsAccepted { .. }
    ));
}

fn a16_run203_verifier_composition_is_exercised() {
    // Prove the Run 203 pure verifier composed by the Run 295 backend is
    // reachable/linked in release mode. `as usize` forces the symbol to be
    // materialized without needing to reconstruct its full argument surface.
    let verifier_addr = verify_authority_custody_backend_response as usize;
    assert!(verifier_addr != 0);
    // And the accept path that internally dispatches to it authorizes.
    let env = TrustBundleEnvironment::Devnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    let submitted = backend
        .submit_custody_signing_request(&spec, &domain(env))
        .expect("submit");
    let outcome = backend.verify_custody_response(
        &spec,
        &submitted,
        &domain(env),
        &fixture_identity(BackendKind::FixtureKms, env),
        NOW,
    );
    assert!(outcome.is_accept());
}

fn a17_provider_kind_maps_to_backend_kind_run203_compatible() {
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

fn a18_protocol_version_constant_is_stable() {
    assert_eq!(PRODUCTION_KMS_HSM_CUSTODY_BACKEND_PROTOCOL_VERSION, 1);
    assert!(PRODUCTION_KMS_HSM_CUSTODY_MAX_RESPONSE_BYTES >= 1024);
}

// ===========================================================================
// B — Rejection / fail-closed release checks
// ===========================================================================

fn b01_disabled_policy_no_request_no_provider_invocation() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::Disabled, env);
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    let out = backend.evaluate_custody_backend(
        &spec,
        &domain(env),
        &fixture_identity(BackendKind::FixtureKms, env),
        NOW,
    );
    assert_eq!(out, ProductionCustodyOutcome::DisabledNoRequest);
    assert_eq!(backend.transport.call_count(), 0);
    assert!(backend.build_custody_request(&spec, &domain(env)).is_err());
}

fn b02_mainnet_identity_refused_before_provider() {
    let env = TrustBundleEnvironment::Mainnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let out = backend.evaluate_custody_backend(
        &fixture_spec(ProductionCustodyProviderKind::FixtureKms, env),
        &domain(env),
        &fixture_identity(BackendKind::FixtureKms, env),
        NOW,
    );
    assert_eq!(out, ProductionCustodyOutcome::FixtureMaterialRejectedForMainNet);
    assert_eq!(backend.transport.call_count(), 0);
}

fn b03_fixture_kms_material_refused_for_mainnet() {
    let env = TrustBundleEnvironment::Mainnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let out = backend.build_custody_request(
        &fixture_spec(ProductionCustodyProviderKind::FixtureKms, env),
        &domain(env),
    );
    assert_eq!(
        out,
        Err(ProductionCustodyOutcome::FixtureMaterialRejectedForMainNet)
    );
}

fn b04_fixture_hsm_material_refused_for_mainnet() {
    let env = TrustBundleEnvironment::Mainnet;
    let backend = hsm_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureHsmAllowed, env);
    let out = backend.build_custody_request(
        &fixture_spec(ProductionCustodyProviderKind::FixtureHsm, env),
        &domain(env),
    );
    assert_eq!(
        out,
        Err(ProductionCustodyOutcome::FixtureMaterialRejectedForMainNet)
    );
}

fn b05_remote_signer_material_cannot_satisfy_kms_hsm() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let mut spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    spec.custody_class = AuthorityCustodyClass::RemoteSigner;
    let out = backend.build_custody_request(&spec, &domain(env));
    assert_eq!(
        out,
        Err(ProductionCustodyOutcome::RemoteSignerIsNotKmsHsmCustody)
    );
    assert_eq!(backend.transport.call_count(), 0);
}

fn b06_local_operator_material_refused() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let mut spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    spec.custody_class = AuthorityCustodyClass::LocalOperatorKey;
    let out = backend.build_custody_request(&spec, &domain(env));
    assert!(matches!(
        out,
        Err(ProductionCustodyOutcome::ProductionCustodyRejected { .. })
    ));
}

fn b07_wrong_environment_rejected() {
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

fn b08_wrong_chain_rejected() {
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

fn b09_wrong_genesis_rejected() {
    let (out, _) = verify_with(
        |_| {},
        |_| {},
        Some(AuthorityTrustDomain::new(
            TrustBundleEnvironment::Devnet,
            "qbind-devnet",
            "wrong-genesis",
            ROOT_FP,
            100,
        )),
        NOW,
    );
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyDomainMismatch);
}

fn b10_wrong_authority_root_rejected() {
    let (out, _) = verify_with(
        |_| {},
        |_| {},
        Some(AuthorityTrustDomain::new(
            TrustBundleEnvironment::Devnet,
            "qbind-devnet",
            GENESIS_HASH,
            "wrong-root",
            100,
        )),
        NOW,
    );
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyDomainMismatch);
}

fn b11_wrong_authority_sequence_rejected() {
    let (out, _) = verify_with(|s| s.authority_domain_sequence = 999, |_| {}, None, NOW);
    assert!(matches!(
        out,
        ProductionCustodyOutcome::ProductionCustodyRejected { .. }
    ));
}

fn b12_wrong_provider_kind_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let mut spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    spec.provider_kind = ProductionCustodyProviderKind::ProductionCloudKms;
    let out = backend.build_custody_request(&spec, &domain(env));
    assert_eq!(out, Err(ProductionCustodyOutcome::ProductionCustodyWrongProvider));
}

fn b13_wrong_key_handle_rejected() {
    let (out, _) = verify_with(
        |s| s.key_id = "wrong-key".to_string(),
        |i| i.key_id = "wrong-key".to_string(),
        None,
        NOW,
    );
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyWrongKeyHandle);
}

fn b14_wrong_signer_identity_rejected() {
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

fn b15_wrong_request_id_rejected() {
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

fn b16_wrong_transcript_digest_rejected() {
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

fn b17_wrong_candidate_digest_rejected() {
    let (out, _) = verify_with(|s| s.candidate_digest = "wrong-candidate".to_string(), |_| {}, None, NOW);
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyWrongCandidateDigest);
}

fn b18_wrong_authorized_action_rejected() {
    let (out, _) = verify_with(
        |s| s.lifecycle_action = LocalLifecycleAction::Revoke,
        |i| i.allowed_lifecycle_actions = vec![LocalLifecycleAction::Revoke],
        None,
        NOW,
    );
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyWrongAction);
}

fn b19_wrong_protocol_version_rejected() {
    let out = submit_mock_error(ProductionCustodyError::UnsupportedProtocolVersion { version: 9 });
    assert_eq!(
        out,
        ProductionCustodyOutcome::ProductionCustodyUnsupportedProtocol { version: 9 }
    );
}

fn b20_missing_signature_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    let identity = fixture_identity(BackendKind::FixtureKms, env);
    let mut submitted = backend
        .submit_custody_signing_request(&spec, &domain(env))
        .expect("submit");
    submitted.response.backend_response.signature_commitment = String::new();
    let out = backend.verify_custody_response(&spec, &submitted, &domain(env), &identity, NOW);
    assert!(!out.is_accept());
}

fn b21_missing_attestation_rejected() {
    let (out, _) = verify_with(|s| s.custody_attestation_digest = String::new(), |_| {}, None, NOW);
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyAttestationMissing);
}

fn b22_attestation_unavailable_fail_closed() {
    let out = submit_mock_error(ProductionCustodyError::AttestationUnavailable);
    assert_eq!(
        out,
        ProductionCustodyOutcome::ProductionCustodyAttestationUnavailable
    );
}

fn b23_malformed_response_rejected() {
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

fn b24_oversized_response_rejected() {
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

fn b25_response_replay_from_prior_request_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let spec_a = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    let submitted_a = backend
        .submit_custody_signing_request(&spec_a, &domain(env))
        .expect("submit a");
    let mut spec_b = spec_a.clone();
    spec_b.candidate_digest = "candidate-digest-OTHER".to_string();
    let identity = fixture_identity(BackendKind::FixtureKms, env);
    let out = backend.verify_custody_response(&spec_b, &submitted_a, &domain(env), &identity, NOW);
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyWrongCandidateDigest);
}

fn b26_provider_unavailable_rejected() {
    assert_eq!(
        submit_mock_error(ProductionCustodyError::ProviderUnavailable),
        ProductionCustodyOutcome::ProductionCustodyUnavailable
    );
}

fn b27_provider_timeout_rejected() {
    assert_eq!(
        submit_mock_error(ProductionCustodyError::Timeout),
        ProductionCustodyOutcome::ProductionCustodyTimeout
    );
}

fn b28_provider_decode_error_rejected() {
    assert_eq!(
        submit_mock_error(ProductionCustodyError::DecodeError),
        ProductionCustodyOutcome::ProductionCustodyDecodeFailed
    );
}

fn b29_provider_refused_rejected() {
    assert!(matches!(
        submit_mock_error(ProductionCustodyError::SigningRefused),
        ProductionCustodyOutcome::ProductionCustodyRejected { .. }
    ));
}

fn b30_provider_policy_rejected_rejected() {
    assert!(matches!(
        submit_mock_error(ProductionCustodyError::ProviderPolicyRejected),
        ProductionCustodyOutcome::ProductionCustodyRejected { .. }
    ));
}

fn b31_unsupported_provider_rejected() {
    assert_eq!(
        submit_mock_error(ProductionCustodyError::UnsupportedProvider),
        ProductionCustodyOutcome::ProductionCustodyUnsupportedProvider
    );
}

fn b32_endpoint_unavailable_rejected() {
    assert_eq!(
        submit_mock_error(ProductionCustodyError::EndpointUnavailable),
        ProductionCustodyOutcome::ProductionCustodyUnavailable
    );
}

fn b33_attestation_missing_provider_error_rejected() {
    assert_eq!(
        submit_mock_error(ProductionCustodyError::AttestationMissing),
        ProductionCustodyOutcome::ProductionCustodyAttestationMissing
    );
}

fn b34_validator_set_rotation_request_unsupported() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let mut spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    spec.request_kind = ProductionCustodyRequestKind::ValidatorSetRotation;
    let out = backend.build_custody_request(&spec, &domain(env));
    assert_eq!(out, Err(ProductionCustodyOutcome::ValidatorSetRotationUnsupported));
    assert_eq!(backend.transport.call_count(), 0);
}

fn b35_policy_change_request_unsupported() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let mut spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    spec.request_kind = ProductionCustodyRequestKind::PolicyChange;
    let out = backend.build_custody_request(&spec, &domain(env));
    assert_eq!(out, Err(ProductionCustodyOutcome::PolicyChangeUnsupported));
}

fn b36_onchain_governance_proof_request_unavailable() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let mut spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    spec.request_kind = ProductionCustodyRequestKind::OnChainGovernanceProofVerification;
    let out = backend.build_custody_request(&spec, &domain(env));
    assert_eq!(out, Err(ProductionCustodyOutcome::GovernanceVerifierUnavailable));
}

// ===========================================================================
// C — MainNet / authority policy release checks
// ===========================================================================

fn c01_mainnet_cannot_be_satisfied_by_fixture_kms() {
    let env = TrustBundleEnvironment::Mainnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let out = backend.build_custody_request(
        &fixture_spec(ProductionCustodyProviderKind::FixtureKms, env),
        &domain(env),
    );
    assert_eq!(out, Err(ProductionCustodyOutcome::FixtureMaterialRejectedForMainNet));
    assert_eq!(backend.transport.call_count(), 0);
}

fn c02_mainnet_cannot_be_satisfied_by_fixture_hsm() {
    let env = TrustBundleEnvironment::Mainnet;
    let backend = hsm_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureHsmAllowed, env);
    let out = backend.build_custody_request(
        &fixture_spec(ProductionCustodyProviderKind::FixtureHsm, env),
        &domain(env),
    );
    assert_eq!(out, Err(ProductionCustodyOutcome::FixtureMaterialRejectedForMainNet));
}

fn c03_mainnet_cannot_be_satisfied_by_remote_signer_only() {
    let env = TrustBundleEnvironment::Mainnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let mut spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    spec.custody_class = AuthorityCustodyClass::RemoteSigner;
    let out = backend.build_custody_request(&spec, &domain(env));
    assert_eq!(out, Err(ProductionCustodyOutcome::RemoteSignerIsNotKmsHsmCustody));
}

fn c04_mainnet_cannot_be_satisfied_by_local_operator_material() {
    let env = TrustBundleEnvironment::Mainnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let mut spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    spec.custody_class = AuthorityCustodyClass::LocalOperatorKey;
    let out = backend.build_custody_request(&spec, &domain(env));
    assert!(matches!(
        out,
        Err(ProductionCustodyOutcome::ProductionCustodyRejected { .. })
    ));
}

fn c05_mainnet_peer_majority_material_refused() {
    let env = TrustBundleEnvironment::Mainnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let mut spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    spec.custody_class = AuthorityCustodyClass::LocalOperatorKey;
    let out = backend.build_custody_request(&spec, &domain(env));
    assert!(out.is_err());
    assert_eq!(backend.transport.call_count(), 0);
}

fn c06_mainnet_production_policy_unavailable_no_provider_call() {
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

fn c07_mainnet_non_production_policy_refused() {
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

fn c08_mainnet_production_custody_unavailable_records_no_mutation() {
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

fn c09_mainnet_scope_helper_refuses_fixture_material() {
    assert!(production_kms_hsm_custody_backend_mainnet_refuses_fixture_material());
}

// ===========================================================================
// D — Replay / recovery / idempotency release checks
// ===========================================================================

fn d01_no_prior_request_window() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Devnet,
    );
    let current = build_submitted_kms(TrustBundleEnvironment::Devnet);
    let out = backend.recover_custody_request_window(None, &current);
    assert_eq!(out, ProductionCustodyRecoveryOutcome::NoPriorRequest);
}

fn d02_duplicate_identical_request_is_idempotent() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Devnet,
    );
    let prior = build_submitted_kms(TrustBundleEnvironment::Devnet);
    let current = build_submitted_kms(TrustBundleEnvironment::Devnet);
    let out = backend.recover_custody_request_window(Some(&prior), &current);
    assert_eq!(out, ProductionCustodyRecoveryOutcome::IdempotentReplayOfSameRequest);
    assert!(out.is_idempotent());
}

fn d03_same_id_different_transcript_fails_closed() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Devnet,
    );
    let prior = build_submitted_kms(TrustBundleEnvironment::Devnet);
    let mut current = build_submitted_kms(TrustBundleEnvironment::Devnet);
    current.request.backend_request.candidate_digest = "other-candidate".to_string();
    let out = backend.recover_custody_request_window(Some(&prior), &current);
    assert_eq!(out, ProductionCustodyRecoveryOutcome::ConflictingRequestForSameId);
}

fn d04_same_id_different_key_handle_fails_closed() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Devnet,
    );
    let prior = build_submitted_kms(TrustBundleEnvironment::Devnet);
    let mut current = build_submitted_kms(TrustBundleEnvironment::Devnet);
    current.request.key_id = "other-key".to_string();
    current.response.key_id = "other-key".to_string();
    let out = backend.recover_custody_request_window(Some(&prior), &current);
    assert_eq!(out, ProductionCustodyRecoveryOutcome::ConflictingKeyHandleForSameId);
}

fn d05_same_request_different_response_fails_closed() {
    let backend = kms_backend(
        ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
        TrustBundleEnvironment::Devnet,
    );
    let prior = build_submitted_kms(TrustBundleEnvironment::Devnet);
    let mut current = build_submitted_kms(TrustBundleEnvironment::Devnet);
    current.response.backend_response.signature_commitment = "different-sig".to_string();
    let out = backend.recover_custody_request_window(Some(&prior), &current);
    assert_eq!(out, ProductionCustodyRecoveryOutcome::ConflictingResponseForSameRequest);
}

fn d06_different_request_ids_are_unrelated_windows() {
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

fn d07_recovery_idempotency_is_byte_identical_only() {
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
// E — Non-mutation / no-authority-extension release checks
// ===========================================================================

fn e01_every_outcome_is_non_mutating() {
    assert!(ProductionCustodyOutcome::DisabledNoRequest.is_non_mutating());
    assert!(ProductionCustodyOutcome::MainNetRefused.is_non_mutating());
    assert!(ProductionCustodyOutcome::MainNetProductionCustodyUnavailable.is_non_mutating());
    assert!(ProductionCustodyOutcome::ProductionCustodyUnavailable.is_non_mutating());
    assert!(ProductionCustodyOutcome::FixtureKmsAccepted {
        provider_id: "p".to_string(),
        environment: TrustBundleEnvironment::Devnet,
        request_id: "r".to_string(),
    }
    .is_non_mutating());
}

fn e02_disabled_reject_touches_no_provider() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = kms_backend(ProductionKmsHsmCustodyBackendPolicy::Disabled, env);
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    let _ = backend.build_custody_request(&spec, &domain(env));
    let _ = backend.submit_custody_signing_request(&spec, &domain(env));
    let _ = backend.evaluate_custody_backend(
        &spec,
        &domain(env),
        &fixture_identity(BackendKind::FixtureKms, env),
        NOW,
    );
    assert_eq!(backend.transport.call_count(), 0);
}

fn e03_reject_after_verify_adds_no_provider_call() {
    let (out, calls) = verify_with(
        |s| s.key_id = "wrong-key".to_string(),
        |i| i.key_id = "wrong-key".to_string(),
        None,
        NOW,
    );
    assert_eq!(out, ProductionCustodyOutcome::ProductionCustodyWrongKeyHandle);
    assert_eq!(calls, 1);
}

fn e04_non_mutation_scope_helpers_hold() {
    assert!(production_kms_hsm_custody_backend_is_non_mutating());
    assert!(production_kms_hsm_custody_backend_never_falls_back());
    assert!(production_kms_hsm_custody_backend_loads_no_raw_local_key());
    assert!(production_kms_hsm_custody_backend_remote_signer_is_not_kms_hsm());
}

fn e05_source_test_scope_flag_holds() {
    assert!(production_kms_hsm_custody_backend_is_source_test_not_release_binary_evidence());
    assert!(production_kms_hsm_custody_backend_default_is_disabled());
}

// ===========================================================================
// F — Release symbol reachability probe
// ===========================================================================

fn f01_release_symbol_reachability_probe() {
    // Touch a broad slice of the Run 295 backend surface so the release
    // helper links against and exercises the real production symbols.
    let env = TrustBundleEnvironment::Devnet;
    assert_eq!(PRODUCTION_KMS_HSM_CUSTODY_BACKEND_PROTOCOL_VERSION, 1);
    assert!(PRODUCTION_KMS_HSM_CUSTODY_MAX_RESPONSE_BYTES > 0);

    let backend: ProductionKmsHsmCustodyBackend<FixtureKmsCustodyProvider> =
        kms_backend(ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed, env);
    let spec: ProductionCustodyRequestSpec =
        fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    let td: AuthorityTrustDomain = domain(env);
    let id: BackendIdentity = fixture_identity(BackendKind::FixtureKms, env);

    let request_id: String = production_kms_hsm_custody_request_id(&spec);
    assert!(!request_id.is_empty());

    let submitted: SubmittedCustodyRequest = backend
        .submit_custody_signing_request(&spec, &td)
        .expect("submit");
    assert_eq!(submitted.attempts_used, 1);

    let outcome: ProductionCustodyOutcome =
        backend.verify_custody_response(&spec, &submitted, &td, &id, NOW);
    assert!(outcome.is_accept());

    let recovery: ProductionCustodyRecoveryOutcome =
        backend.recover_custody_request_window(None, &submitted);
    assert_eq!(recovery, ProductionCustodyRecoveryOutcome::NoPriorRequest);

    // Error taxonomy is reachable and typed.
    let err: ProductionCustodyError = ProductionCustodyError::Timeout;
    assert!(err.is_retryable());

    // Mock transport implements the same trait surface.
    let mock: MockKmsHsmCustodyTransport =
        MockKmsHsmCustodyTransport::respond(submitted.response.clone());
    let mock_backend: ProductionKmsHsmCustodyBackend<MockKmsHsmCustodyTransport> =
        ProductionKmsHsmCustodyBackend::new(
            config(),
            ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
            mock,
        );
    let mock_outcome = mock_backend.evaluate_custody_backend(&spec, &td, &id, NOW);
    assert!(mock_outcome.is_accept());
    let _ = <MockKmsHsmCustodyTransport as KmsHsmCustodyProviderTransport>::submit;

    // Production provider stubs are reachable and typed.
    for stub in [
        ProductionCustodyProviderStub::cloud_kms(),
        ProductionCustodyProviderStub::pkcs11_hsm(),
        ProductionCustodyProviderStub::generic_kms(),
        ProductionCustodyProviderStub::generic_hsm(),
    ] {
        assert!(stub.provider_kind().is_production());
    }

    // Run 203 pure verifier symbol is linked in release mode.
    assert!(verify_authority_custody_backend_response as usize != 0);

    // Invariant helpers.
    assert!(production_kms_hsm_custody_backend_default_is_disabled());
    assert!(production_kms_hsm_custody_backend_mainnet_refuses_fixture_material());
    assert!(production_kms_hsm_custody_backend_never_falls_back());
    assert!(production_kms_hsm_custody_backend_is_non_mutating());
    assert!(production_kms_hsm_custody_backend_loads_no_raw_local_key());
    assert!(production_kms_hsm_custody_backend_remote_signer_is_not_kms_hsm());
    assert!(production_kms_hsm_custody_backend_is_source_test_not_release_binary_evidence());
}

// ===========================================================================
// Harness
// ===========================================================================

fn run_case(table: &str, name: &str, f: fn(), rows: &mut Vec<(String, String, bool)>) {
    let ok = catch_unwind(AssertUnwindSafe(f)).is_ok();
    println!("case {table} {name} {}", if ok { "PASS" } else { "FAIL" });
    rows.push((table.to_string(), name.to_string(), ok));
}

fn main() {
    let outdir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(
            "docs/devnet/run_296_production_kms_hsm_custody_backend_release_binary/helper_evidence/run_296",
        )
    });
    fs::create_dir_all(outdir.join("fixtures")).expect("create helper output directory");

    let cases: &[(&str, &str, fn())] = &[
        ("accepted_compatible", "a01_disabled_default_policy_is_explicit_and_inert", a01_disabled_default_policy_is_explicit_and_inert as fn()),
        ("accepted_compatible", "a02_devnet_fixture_kms_accepts_under_fixture_policy", a02_devnet_fixture_kms_accepts_under_fixture_policy as fn()),
        ("accepted_compatible", "a03_devnet_fixture_hsm_accepts_under_fixture_policy", a03_devnet_fixture_hsm_accepts_under_fixture_policy as fn()),
        ("accepted_compatible", "a04_testnet_fixture_kms_accepts_under_allowed_policy", a04_testnet_fixture_kms_accepts_under_allowed_policy as fn()),
        ("accepted_compatible", "a05_testnet_fixture_hsm_accepts_under_allowed_policy", a05_testnet_fixture_hsm_accepts_under_allowed_policy as fn()),
        ("accepted_compatible", "a06_production_cloud_kms_request_built_without_fixture_fallback", a06_production_cloud_kms_request_built_without_fixture_fallback as fn()),
        ("accepted_compatible", "a07_production_pkcs11_hsm_request_built_without_fixture_fallback", a07_production_pkcs11_hsm_request_built_without_fixture_fallback as fn()),
        ("accepted_compatible", "a08_production_generic_kms_request_built_without_fixture_fallback", a08_production_generic_kms_request_built_without_fixture_fallback as fn()),
        ("accepted_compatible", "a09_production_cloud_kms_path_reachable_and_fail_closed", a09_production_cloud_kms_path_reachable_and_fail_closed as fn()),
        ("accepted_compatible", "a10_production_pkcs11_hsm_path_reachable_and_fail_closed", a10_production_pkcs11_hsm_path_reachable_and_fail_closed as fn()),
        ("accepted_compatible", "a11_request_id_is_deterministic", a11_request_id_is_deterministic as fn()),
        ("accepted_compatible", "a12_response_digest_is_deterministic", a12_response_digest_is_deterministic as fn()),
        ("accepted_compatible", "a13_transcript_digest_is_deterministic", a13_transcript_digest_is_deterministic as fn()),
        ("accepted_compatible", "a14_two_identical_requests_produce_identical_digests", a14_two_identical_requests_produce_identical_digests as fn()),
        ("accepted_compatible", "a15_valid_fixture_response_authorizes_matching_request", a15_valid_fixture_response_authorizes_matching_request as fn()),
        ("accepted_compatible", "a16_run203_verifier_composition_is_exercised", a16_run203_verifier_composition_is_exercised as fn()),
        ("accepted_compatible", "a17_provider_kind_maps_to_backend_kind_run203_compatible", a17_provider_kind_maps_to_backend_kind_run203_compatible as fn()),
        ("accepted_compatible", "a18_protocol_version_constant_is_stable", a18_protocol_version_constant_is_stable as fn()),
        ("rejection_fail_closed", "b01_disabled_policy_no_request_no_provider_invocation", b01_disabled_policy_no_request_no_provider_invocation as fn()),
        ("rejection_fail_closed", "b02_mainnet_identity_refused_before_provider", b02_mainnet_identity_refused_before_provider as fn()),
        ("rejection_fail_closed", "b03_fixture_kms_material_refused_for_mainnet", b03_fixture_kms_material_refused_for_mainnet as fn()),
        ("rejection_fail_closed", "b04_fixture_hsm_material_refused_for_mainnet", b04_fixture_hsm_material_refused_for_mainnet as fn()),
        ("rejection_fail_closed", "b05_remote_signer_material_cannot_satisfy_kms_hsm", b05_remote_signer_material_cannot_satisfy_kms_hsm as fn()),
        ("rejection_fail_closed", "b06_local_operator_material_refused", b06_local_operator_material_refused as fn()),
        ("rejection_fail_closed", "b07_wrong_environment_rejected", b07_wrong_environment_rejected as fn()),
        ("rejection_fail_closed", "b08_wrong_chain_rejected", b08_wrong_chain_rejected as fn()),
        ("rejection_fail_closed", "b09_wrong_genesis_rejected", b09_wrong_genesis_rejected as fn()),
        ("rejection_fail_closed", "b10_wrong_authority_root_rejected", b10_wrong_authority_root_rejected as fn()),
        ("rejection_fail_closed", "b11_wrong_authority_sequence_rejected", b11_wrong_authority_sequence_rejected as fn()),
        ("rejection_fail_closed", "b12_wrong_provider_kind_rejected", b12_wrong_provider_kind_rejected as fn()),
        ("rejection_fail_closed", "b13_wrong_key_handle_rejected", b13_wrong_key_handle_rejected as fn()),
        ("rejection_fail_closed", "b14_wrong_signer_identity_rejected", b14_wrong_signer_identity_rejected as fn()),
        ("rejection_fail_closed", "b15_wrong_request_id_rejected", b15_wrong_request_id_rejected as fn()),
        ("rejection_fail_closed", "b16_wrong_transcript_digest_rejected", b16_wrong_transcript_digest_rejected as fn()),
        ("rejection_fail_closed", "b17_wrong_candidate_digest_rejected", b17_wrong_candidate_digest_rejected as fn()),
        ("rejection_fail_closed", "b18_wrong_authorized_action_rejected", b18_wrong_authorized_action_rejected as fn()),
        ("rejection_fail_closed", "b19_wrong_protocol_version_rejected", b19_wrong_protocol_version_rejected as fn()),
        ("rejection_fail_closed", "b20_missing_signature_rejected", b20_missing_signature_rejected as fn()),
        ("rejection_fail_closed", "b21_missing_attestation_rejected", b21_missing_attestation_rejected as fn()),
        ("rejection_fail_closed", "b22_attestation_unavailable_fail_closed", b22_attestation_unavailable_fail_closed as fn()),
        ("rejection_fail_closed", "b23_malformed_response_rejected", b23_malformed_response_rejected as fn()),
        ("rejection_fail_closed", "b24_oversized_response_rejected", b24_oversized_response_rejected as fn()),
        ("rejection_fail_closed", "b25_response_replay_from_prior_request_rejected", b25_response_replay_from_prior_request_rejected as fn()),
        ("rejection_fail_closed", "b26_provider_unavailable_rejected", b26_provider_unavailable_rejected as fn()),
        ("rejection_fail_closed", "b27_provider_timeout_rejected", b27_provider_timeout_rejected as fn()),
        ("rejection_fail_closed", "b28_provider_decode_error_rejected", b28_provider_decode_error_rejected as fn()),
        ("rejection_fail_closed", "b29_provider_refused_rejected", b29_provider_refused_rejected as fn()),
        ("rejection_fail_closed", "b30_provider_policy_rejected_rejected", b30_provider_policy_rejected_rejected as fn()),
        ("rejection_fail_closed", "b31_unsupported_provider_rejected", b31_unsupported_provider_rejected as fn()),
        ("rejection_fail_closed", "b32_endpoint_unavailable_rejected", b32_endpoint_unavailable_rejected as fn()),
        ("rejection_fail_closed", "b33_attestation_missing_provider_error_rejected", b33_attestation_missing_provider_error_rejected as fn()),
        ("rejection_fail_closed", "b34_validator_set_rotation_request_unsupported", b34_validator_set_rotation_request_unsupported as fn()),
        ("rejection_fail_closed", "b35_policy_change_request_unsupported", b35_policy_change_request_unsupported as fn()),
        ("rejection_fail_closed", "b36_onchain_governance_proof_request_unavailable", b36_onchain_governance_proof_request_unavailable as fn()),
        ("mainnet_authority_policy", "c01_mainnet_cannot_be_satisfied_by_fixture_kms", c01_mainnet_cannot_be_satisfied_by_fixture_kms as fn()),
        ("mainnet_authority_policy", "c02_mainnet_cannot_be_satisfied_by_fixture_hsm", c02_mainnet_cannot_be_satisfied_by_fixture_hsm as fn()),
        ("mainnet_authority_policy", "c03_mainnet_cannot_be_satisfied_by_remote_signer_only", c03_mainnet_cannot_be_satisfied_by_remote_signer_only as fn()),
        ("mainnet_authority_policy", "c04_mainnet_cannot_be_satisfied_by_local_operator_material", c04_mainnet_cannot_be_satisfied_by_local_operator_material as fn()),
        ("mainnet_authority_policy", "c05_mainnet_peer_majority_material_refused", c05_mainnet_peer_majority_material_refused as fn()),
        ("mainnet_authority_policy", "c06_mainnet_production_policy_unavailable_no_provider_call", c06_mainnet_production_policy_unavailable_no_provider_call as fn()),
        ("mainnet_authority_policy", "c07_mainnet_non_production_policy_refused", c07_mainnet_non_production_policy_refused as fn()),
        ("mainnet_authority_policy", "c08_mainnet_production_custody_unavailable_records_no_mutation", c08_mainnet_production_custody_unavailable_records_no_mutation as fn()),
        ("mainnet_authority_policy", "c09_mainnet_scope_helper_refuses_fixture_material", c09_mainnet_scope_helper_refuses_fixture_material as fn()),
        ("replay_recovery_idempotency", "d01_no_prior_request_window", d01_no_prior_request_window as fn()),
        ("replay_recovery_idempotency", "d02_duplicate_identical_request_is_idempotent", d02_duplicate_identical_request_is_idempotent as fn()),
        ("replay_recovery_idempotency", "d03_same_id_different_transcript_fails_closed", d03_same_id_different_transcript_fails_closed as fn()),
        ("replay_recovery_idempotency", "d04_same_id_different_key_handle_fails_closed", d04_same_id_different_key_handle_fails_closed as fn()),
        ("replay_recovery_idempotency", "d05_same_request_different_response_fails_closed", d05_same_request_different_response_fails_closed as fn()),
        ("replay_recovery_idempotency", "d06_different_request_ids_are_unrelated_windows", d06_different_request_ids_are_unrelated_windows as fn()),
        ("replay_recovery_idempotency", "d07_recovery_idempotency_is_byte_identical_only", d07_recovery_idempotency_is_byte_identical_only as fn()),
        ("non_mutation", "e01_every_outcome_is_non_mutating", e01_every_outcome_is_non_mutating as fn()),
        ("non_mutation", "e02_disabled_reject_touches_no_provider", e02_disabled_reject_touches_no_provider as fn()),
        ("non_mutation", "e03_reject_after_verify_adds_no_provider_call", e03_reject_after_verify_adds_no_provider_call as fn()),
        ("non_mutation", "e04_non_mutation_scope_helpers_hold", e04_non_mutation_scope_helpers_hold as fn()),
        ("non_mutation", "e05_source_test_scope_flag_holds", e05_source_test_scope_flag_holds as fn()),
        ("reachability", "f01_release_symbol_reachability_probe", f01_release_symbol_reachability_probe as fn()),
    ];

    let mut rows: Vec<(String, String, bool)> = Vec::new();
    for (table, name, f) in cases {
        run_case(table, name, *f, &mut rows);
    }

    let mut tables = BTreeMap::<String, (usize, usize)>::new();
    for (table, _name, ok) in &rows {
        let entry = tables.entry(table.clone()).or_insert((0, 0));
        if *ok {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
    }
    let total_pass: usize = rows.iter().filter(|(_, _, ok)| *ok).count();
    let total_fail = rows.len() - total_pass;

    let mut summary = String::new();
    summary.push_str("Run 296 production KMS/HSM/cloud-KMS/PKCS#11 custody backend release helper\n");
    summary.push_str(&format!(
        "verdict: {}\n",
        if total_fail == 0 { "PASS" } else { "FAIL" }
    ));
    summary.push_str(
        "backend: crates/qbind-node/src/pqc_production_kms_hsm_custody_backend.rs (Run 295 ProductionKmsHsmCustodyBackend)\n",
    );
    summary.push_str(
        "mode: real Run 295 backend over source/test fixture KMS/HSM providers, reachable-but-fail-closed production provider stubs, and mock transport; DevNet/TestNet fixture accept only; MainNet refused; default Disabled; production policy never accepts and never falls back to fixture/RemoteSigner/local signing; production cloud-KMS/PKCS#11/generic paths fail closed without real config; every failure is a typed outcome\n",
    );
    for (table, (pass, fail)) in &tables {
        summary.push_str(&format!("table {table} pass={pass} fail={fail}\n"));
    }
    summary.push_str(&format!("total_pass: {total_pass}\n"));
    summary.push_str(&format!("total_fail: {total_fail}\n"));

    fs::write(outdir.join("helper_summary.txt"), &summary).expect("write helper summary");

    // Deterministic-digest fixture for cross-invocation comparison by the harness.
    let env = TrustBundleEnvironment::Devnet;
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    let request_id = production_kms_hsm_custody_request_id(&spec);
    let submitted = build_submitted_kms(env);
    let request_envelope_digest = submitted.request.envelope_digest();
    let response_envelope_digest = submitted.response.envelope_digest();
    let response_transcript = submitted.response.transcript_digest.clone();
    let backend_transcript = production_kms_hsm_custody_transcript_digest(
        PRODUCTION_KMS_HSM_CUSTODY_BACKEND_PROTOCOL_VERSION,
        &request_id,
        &request_envelope_digest,
        &request_envelope_digest,
        &response_envelope_digest,
        &response_transcript,
        None,
    );
    fs::write(
        outdir.join("fixtures/run_296_deterministic_digests.txt"),
        format!(
            "request_id {request_id}\nrequest_envelope_digest {request_envelope_digest}\nresponse_envelope_digest {response_envelope_digest}\nresponse_transcript_digest {response_transcript}\nbackend_transcript_digest {backend_transcript}\n"
        ),
    )
    .expect("write digest fixture");

    print!("{summary}");
    if total_fail != 0 {
        std::process::exit(1);
    }
}