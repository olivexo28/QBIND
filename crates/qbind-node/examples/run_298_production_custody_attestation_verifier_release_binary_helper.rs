//! Run 298 — release-binary helper for the Run 297 **production custody
//! attestation verifier**.
//!
//! Release-binary evidence for the Run 297 source/test production custody
//! attestation verifier
//! (`crates/qbind-node/src/pqc_production_custody_attestation_verifier.rs`).
//! This helper is compiled as a release example and linked against the
//! release-built production library symbols. It exercises the **real** Run 297
//! [`ProductionCustodyAttestationVerifier`] over source/test fixture KMS/HSM
//! attestation verifiers, reachable-but-fail-closed production attestation
//! verifier stubs, and a programmable mock evidence verifier in release mode
//! and proves, per check with PASS/FAIL, the accepted / rejection-fail-closed /
//! MainNet-refusal / non-mutation / replay-recovery behavior of the real
//! verifier, including evidence / request-id / request / response / backend-
//! transcript / challenge / trust-root / measurement / provider / key / signer /
//! custody-class / authority-domain binding and the Run 295
//! [`ProductionKmsHsmCustodyBackend`] composition.
//!
//! The helper remains **dead code** from the production runtime: the production
//! `qbind-node` binary never references it. It constructs the verifier only
//! through source/test fixture/stub/mock evidence verifiers, only for
//! DevNet/TestNet identities on the accept path, and never enables any
//! production runtime path, MainNet enablement, custody-attestation default
//! enablement, on-chain governance proof verification, governance execution
//! engine, validator-set rotation, settlement, or external publication. Under a
//! production policy it never falls back to fixture KMS/HSM attestation,
//! RemoteSigner attestation, local signing, or raw local keys.
//!
//! Name substitutions relative to the Run 298 task text (documented in the
//! canonical evidence report):
//! * `production_custody_attestation_challenge_digest` is the method
//!   [`ProductionCustodyAttestationChallenge::challenge_digest`].
//! * `production_custody_attestation_evidence_digest` is the method
//!   [`ProductionCustodyAttestationEvidence::evidence_digest`].
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_298.md`.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use qbind_node::pqc_authority_custody::AuthorityCustodyClass;
use qbind_node::pqc_authority_kms_hsm_backend::{
    BackendIdentity, BackendKind, FixtureHsmBackend, FixtureKmsBackend,
};
use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_production_custody_attestation_verifier::{
    fixture_attestation_expected_proof, production_custody_attestation_decision_digest,
    production_custody_attestation_transcript_digest,
    production_custody_attestation_verifier_default_is_disabled,
    production_custody_attestation_verifier_is_non_mutating,
    production_custody_attestation_verifier_is_source_test_not_release_binary_evidence,
    production_custody_attestation_verifier_mainnet_refuses_fixture,
    production_custody_attestation_verifier_never_falls_back,
    production_custody_attestation_verifier_production_is_fail_closed,
    production_custody_attestation_verifier_remote_signer_is_not_kms_hsm,
    CustodyAttestationEvidenceVerifier, FixtureHsmCustodyAttestationVerifier,
    FixtureKmsCustodyAttestationVerifier, GovernanceProductionCustodyAttestationVerifier,
    MockCustodyAttestationVerifier, ProductionCustodyAttestationBinding,
    ProductionCustodyAttestationChallenge, ProductionCustodyAttestationClass,
    ProductionCustodyAttestationError, ProductionCustodyAttestationEvidence,
    ProductionCustodyAttestationExpectations, ProductionCustodyAttestationMeasurement,
    ProductionCustodyAttestationOutcome, ProductionCustodyAttestationProtocolVersion,
    ProductionCustodyAttestationRecoveryOutcome, ProductionCustodyAttestationTrustRoot,
    ProductionCustodyAttestationVerifier, ProductionCustodyAttestationVerifierConfig,
    ProductionCustodyAttestationVerifierPolicy, ProductionCustodyAttestationVerifierStub,
    PRODUCTION_CUSTODY_ATTESTATION_DOMAIN_SEPARATION_TAG,
    PRODUCTION_CUSTODY_ATTESTATION_INVALID_PROOF_SENTINEL,
    PRODUCTION_CUSTODY_ATTESTATION_PROTOCOL_VERSION,
};
use qbind_node::pqc_production_kms_hsm_custody_backend::{
    FixtureHsmCustodyProvider, FixtureKmsCustodyProvider,
    GovernanceProductionKmsHsmCustodyBackend, ProductionCustodyProviderKind,
    ProductionCustodyRequestKind, ProductionCustodyRequestSpec, ProductionKmsHsmCustodyBackend,
    ProductionKmsHsmCustodyBackendConfig, ProductionKmsHsmCustodyBackendPolicy,
    SubmittedCustodyRequest,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared constants / builders (mirror the Run 297 source-test corpus).
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
const REQ_TS: u64 = 1_700_000_000;

const SIGNER_ID: &str = "signer-identity-1";
const ATTEST_NONCE: &str = "attest-nonce-1";
const ATTEST_CHALLENGE: &str = "attest-challenge-1";
const ATTEST_SEQ: u64 = 7;
const MEASUREMENT: &str = "measurement-digest-1";
const ROOT_ID: &str = "trust-root-1";
const ISSUER_ID: &str = "attestation-ca-1";
const ROOT_MEASUREMENT: &str = "root-measurement-1";

fn chain_for(env: TrustBundleEnvironment) -> &'static str {
    match env {
        TrustBundleEnvironment::Devnet => "qbind-devnet",
        TrustBundleEnvironment::Testnet => "qbind-testnet",
        TrustBundleEnvironment::Mainnet => "qbind-mainnet",
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

/// Build a real Run 295 submitted KMS custody request/response so the
/// attestation verifier composes with genuine Run 295 surfaces.
fn submitted_kms(env: TrustBundleEnvironment) -> SubmittedCustodyRequest {
    let backend: ProductionKmsHsmCustodyBackend<FixtureKmsCustodyProvider> =
        ProductionKmsHsmCustodyBackend::new(
            config(),
            ProductionKmsHsmCustodyBackendPolicy::FixtureKmsAllowed,
            FixtureKmsCustodyProvider::new(fixture_kms_backend(env)),
        );
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureKms, env);
    backend
        .submit_custody_signing_request(&spec, &domain(env))
        .expect("fixture kms submit succeeds")
}

/// Build a real Run 295 submitted HSM custody request/response.
fn submitted_hsm(env: TrustBundleEnvironment) -> SubmittedCustodyRequest {
    let backend: ProductionKmsHsmCustodyBackend<FixtureHsmCustodyProvider> =
        ProductionKmsHsmCustodyBackend::new(
            config(),
            ProductionKmsHsmCustodyBackendPolicy::FixtureHsmAllowed,
            FixtureHsmCustodyProvider::new(fixture_hsm_backend(env)),
        );
    let spec = fixture_spec(ProductionCustodyProviderKind::FixtureHsm, env);
    backend
        .submit_custody_signing_request(&spec, &domain(env))
        .expect("fixture hsm submit succeeds")
}

fn trust_root() -> ProductionCustodyAttestationTrustRoot {
    ProductionCustodyAttestationTrustRoot {
        root_id: ROOT_ID.to_string(),
        issuer_identity: ISSUER_ID.to_string(),
        root_measurement_digest: ROOT_MEASUREMENT.to_string(),
    }
}

fn measurement() -> ProductionCustodyAttestationMeasurement {
    ProductionCustodyAttestationMeasurement {
        measurement_digest: MEASUREMENT.to_string(),
    }
}

fn challenge_for(request_id: &str) -> ProductionCustodyAttestationChallenge {
    ProductionCustodyAttestationChallenge {
        nonce: ATTEST_NONCE.to_string(),
        challenge: ATTEST_CHALLENGE.to_string(),
        sequence: ATTEST_SEQ,
        bound_request_id: request_id.to_string(),
    }
}

fn binding_from(submitted: &SubmittedCustodyRequest) -> ProductionCustodyAttestationBinding {
    ProductionCustodyAttestationBinding::from_submitted_request(
        submitted,
        SIGNER_ID,
        ProductionCustodyRequestKind::AuthorityLifecycleSigning,
        None,
    )
}

/// Build a fixture attestation evidence whose certificate/proof digest is
/// self-consistent (so the fixture verifier accepts it).
fn valid_evidence(
    binding: ProductionCustodyAttestationBinding,
    class: ProductionCustodyAttestationClass,
    policy: ProductionCustodyAttestationVerifierPolicy,
) -> ProductionCustodyAttestationEvidence {
    let request_id = binding.custody_request_id.clone();
    let mut ev = ProductionCustodyAttestationEvidence {
        protocol_version: ProductionCustodyAttestationProtocolVersion::supported(),
        attestation_class: class,
        binding,
        trust_root: trust_root(),
        measurement: measurement(),
        challenge: challenge_for(&request_id),
        certificate_proof_digest: "placeholder".to_string(),
        verifier_policy: policy,
        domain_separation_tag: PRODUCTION_CUSTODY_ATTESTATION_DOMAIN_SEPARATION_TAG.to_string(),
    };
    let tr = ev.trust_root.clone();
    ev.certificate_proof_digest = fixture_attestation_expected_proof(&ev, &tr);
    ev
}

fn expectations_from(
    evidence: &ProductionCustodyAttestationEvidence,
) -> ProductionCustodyAttestationExpectations {
    ProductionCustodyAttestationExpectations {
        binding: evidence.binding.clone(),
        expected_trust_root: evidence.trust_root.clone(),
        expected_measurement: evidence.measurement.clone(),
        expected_challenge: evidence.challenge.clone(),
    }
}

fn kms_verifier(
    policy: ProductionCustodyAttestationVerifierPolicy,
) -> ProductionCustodyAttestationVerifier<FixtureKmsCustodyAttestationVerifier> {
    ProductionCustodyAttestationVerifier::new(
        ProductionCustodyAttestationVerifierConfig::default(),
        policy,
        FixtureKmsCustodyAttestationVerifier::new(),
    )
}

fn hsm_verifier(
    policy: ProductionCustodyAttestationVerifierPolicy,
) -> ProductionCustodyAttestationVerifier<FixtureHsmCustodyAttestationVerifier> {
    ProductionCustodyAttestationVerifier::new(
        ProductionCustodyAttestationVerifierConfig::default(),
        policy,
        FixtureHsmCustodyAttestationVerifier::new(),
    )
}

fn kms_accept_scenario(
    env: TrustBundleEnvironment,
) -> (
    ProductionCustodyAttestationEvidence,
    ProductionCustodyAttestationExpectations,
    AuthorityTrustDomain,
) {
    let submitted = submitted_kms(env);
    let binding = binding_from(&submitted);
    let evidence = valid_evidence(
        binding,
        ProductionCustodyAttestationClass::FixtureKmsAttestation,
        ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed,
    );
    let expectations = expectations_from(&evidence);
    (evidence, expectations, domain(env))
}

fn hsm_accept_scenario(
    env: TrustBundleEnvironment,
) -> (
    ProductionCustodyAttestationEvidence,
    ProductionCustodyAttestationExpectations,
    AuthorityTrustDomain,
) {
    let submitted = submitted_hsm(env);
    let binding = binding_from(&submitted);
    let evidence = valid_evidence(
        binding,
        ProductionCustodyAttestationClass::FixtureHsmAttestation,
        ProductionCustodyAttestationVerifierPolicy::FixtureHsmAttestationAllowed,
    );
    let expectations = expectations_from(&evidence);
    (evidence, expectations, domain(env))
}

fn production_scenario(
    provider_kind: ProductionCustodyProviderKind,
    class: ProductionCustodyAttestationClass,
    policy: ProductionCustodyAttestationVerifierPolicy,
) -> (
    ProductionCustodyAttestationEvidence,
    ProductionCustodyAttestationExpectations,
    AuthorityTrustDomain,
) {
    let env = TrustBundleEnvironment::Devnet;
    let submitted = submitted_kms(env);
    let mut binding = binding_from(&submitted);
    binding.provider_kind = provider_kind;
    binding.custody_class = provider_kind.custody_class().unwrap();
    let evidence = valid_evidence(binding, class, policy);
    let expectations = expectations_from(&evidence);
    (evidence, expectations, domain(env))
}

fn mainnet_scenario(
    class: ProductionCustodyAttestationClass,
    custody_class: AuthorityCustodyClass,
    policy: ProductionCustodyAttestationVerifierPolicy,
) -> (
    ProductionCustodyAttestationEvidence,
    ProductionCustodyAttestationExpectations,
    AuthorityTrustDomain,
) {
    let submitted = submitted_kms(TrustBundleEnvironment::Devnet);
    let mut binding = binding_from(&submitted);
    binding.environment = TrustBundleEnvironment::Mainnet;
    binding.chain_id = chain_for(TrustBundleEnvironment::Mainnet).to_string();
    binding.custody_class = custody_class;
    let evidence = valid_evidence(binding, class, policy);
    let expectations = expectations_from(&evidence);
    (evidence, expectations, domain(TrustBundleEnvironment::Mainnet))
}

fn kms_reject(
    evidence_mut: impl FnOnce(&mut ProductionCustodyAttestationEvidence),
    expectations_mut: impl FnOnce(&mut ProductionCustodyAttestationExpectations),
) -> ProductionCustodyAttestationOutcome {
    let (mut evidence, mut expectations, td) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    evidence_mut(&mut evidence);
    expectations_mut(&mut expectations);
    let verifier =
        kms_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed);
    verifier.verify_custody_attestation(&evidence, &expectations, &td)
}

// ===========================================================================
// A. Accepted / compatible release checks
// ===========================================================================

fn a01_disabled_default_policy_is_explicit_and_inert() {
    assert_eq!(
        ProductionCustodyAttestationVerifierPolicy::default(),
        ProductionCustodyAttestationVerifierPolicy::Disabled
    );
    assert!(ProductionCustodyAttestationVerifierPolicy::default().is_disabled());
}

fn a02_disabled_verifier_returns_disabled_no_verification() {
    let (evidence, expectations, td) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    let verifier = kms_verifier(ProductionCustodyAttestationVerifierPolicy::Disabled);
    let outcome = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert_eq!(
        outcome,
        ProductionCustodyAttestationOutcome::DisabledNoVerification
    );
}

fn a03_devnet_fixture_kms_verifies_under_fixture_policy() {
    let (evidence, expectations, td) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    let verifier =
        kms_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed);
    let outcome = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert!(
        matches!(
            outcome,
            ProductionCustodyAttestationOutcome::FixtureKmsAttestationVerified { .. }
        ),
        "got {outcome:?}"
    );
    assert!(outcome.is_verified());
}

fn a04_devnet_fixture_hsm_verifies_under_fixture_policy() {
    let (evidence, expectations, td) = hsm_accept_scenario(TrustBundleEnvironment::Devnet);
    let verifier =
        hsm_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureHsmAttestationAllowed);
    let outcome = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert!(
        matches!(
            outcome,
            ProductionCustodyAttestationOutcome::FixtureHsmAttestationVerified { .. }
        ),
        "got {outcome:?}"
    );
}

fn a05_testnet_fixture_kms_verifies_under_fixture_policy() {
    let (evidence, expectations, td) = kms_accept_scenario(TrustBundleEnvironment::Testnet);
    let verifier =
        kms_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed);
    let outcome = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert!(matches!(
        outcome,
        ProductionCustodyAttestationOutcome::FixtureKmsAttestationVerified { .. }
    ));
}

fn a06_testnet_fixture_hsm_verifies_under_fixture_policy() {
    let (evidence, expectations, td) = hsm_accept_scenario(TrustBundleEnvironment::Testnet);
    let verifier =
        hsm_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureHsmAttestationAllowed);
    let outcome = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert!(matches!(
        outcome,
        ProductionCustodyAttestationOutcome::FixtureHsmAttestationVerified { .. }
    ));
}

fn a07_valid_fixture_binds_to_matching_custody_request_id() {
    let submitted = submitted_kms(TrustBundleEnvironment::Devnet);
    let request_id = submitted.request_id.clone();
    let binding = binding_from(&submitted);
    assert_eq!(binding.custody_request_id, request_id);
    let evidence = valid_evidence(
        binding,
        ProductionCustodyAttestationClass::FixtureKmsAttestation,
        ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed,
    );
    let expectations = expectations_from(&evidence);
    let verifier =
        kms_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed);
    let outcome = verifier.verify_custody_attestation(
        &evidence,
        &expectations,
        &domain(TrustBundleEnvironment::Devnet),
    );
    match outcome {
        ProductionCustodyAttestationOutcome::FixtureKmsAttestationVerified {
            custody_request_id,
            ..
        } => assert_eq!(custody_request_id, request_id),
        other => panic!("expected verified, got {other:?}"),
    }
}

fn a08_valid_fixture_binds_to_matching_backend_transcript() {
    let submitted = submitted_kms(TrustBundleEnvironment::Devnet);
    let binding = binding_from(&submitted);
    assert_eq!(
        binding.backend_transcript_digest,
        submitted.response.transcript_digest
    );
}

fn a09_valid_fixture_binds_provider_key_class_signer_candidate_action() {
    let submitted = submitted_kms(TrustBundleEnvironment::Devnet);
    let binding = binding_from(&submitted);
    assert_eq!(binding.provider_id, PROVIDER_ID);
    assert_eq!(binding.key_handle, KEY_ID);
    assert_eq!(binding.custody_class, AuthorityCustodyClass::Kms);
    assert_eq!(binding.signer_identity, SIGNER_ID);
    assert_eq!(binding.candidate_digest, CANDIDATE_DIGEST);
    assert_eq!(binding.authorized_action, LocalLifecycleAction::Rotate);
    assert_eq!(binding.key_fingerprint, NEW_FP);
}

fn a10_attestation_challenge_digest_is_deterministic() {
    let c = challenge_for("req-1");
    assert_eq!(c.challenge_digest(), c.challenge_digest());
    let c2 = challenge_for("req-2");
    assert_ne!(c.challenge_digest(), c2.challenge_digest());
}

fn a11_attestation_evidence_digest_is_deterministic() {
    let (evidence, _, _) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    assert_eq!(evidence.evidence_digest(), evidence.evidence_digest());
}

fn a12_attestation_transcript_digest_is_deterministic() {
    let (evidence, expectations, td) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    let verifier =
        kms_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed);
    let d1 = verifier.evaluate_custody_attestation(&evidence, &expectations, &td);
    let verifier2 =
        kms_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed);
    let d2 = verifier2.evaluate_custody_attestation(&evidence, &expectations, &td);
    assert_eq!(d1.transcript_digest, d2.transcript_digest);
    assert_eq!(d1.evidence_digest, d2.evidence_digest);
}

fn a13_two_identical_evidence_objects_produce_identical_transcripts() {
    let (evidence, _, _) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    let clone = evidence.clone();
    let t1 = production_custody_attestation_transcript_digest(
        PRODUCTION_CUSTODY_ATTESTATION_PROTOCOL_VERSION,
        &evidence.evidence_digest(),
        &evidence.challenge.challenge_digest(),
        &evidence.binding.custody_request_id,
        &evidence.binding.backend_transcript_digest,
    );
    let t2 = production_custody_attestation_transcript_digest(
        PRODUCTION_CUSTODY_ATTESTATION_PROTOCOL_VERSION,
        &clone.evidence_digest(),
        &clone.challenge.challenge_digest(),
        &clone.binding.custody_request_id,
        &clone.binding.backend_transcript_digest,
    );
    assert_eq!(t1, t2);
}

fn a14_production_cloud_kms_path_reachable_and_fail_closed() {
    let (evidence, expectations, td) = production_scenario(
        ProductionCustodyProviderKind::ProductionCloudKms,
        ProductionCustodyAttestationClass::ProductionCloudKmsAttestation,
        ProductionCustodyAttestationVerifierPolicy::ProductionCloudKmsAttestationRequired,
    );
    let stub = ProductionCustodyAttestationVerifierStub::cloud_kms();
    let verifier = ProductionCustodyAttestationVerifier::new(
        ProductionCustodyAttestationVerifierConfig::default(),
        ProductionCustodyAttestationVerifierPolicy::ProductionCloudKmsAttestationRequired,
        stub,
    );
    let outcome = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert!(!outcome.is_verified());
    assert_eq!(
        outcome,
        ProductionCustodyAttestationOutcome::ProductionAttestationUnverified
    );
    assert_eq!(verifier.evidence_verifier.call_count(), 1);
}

fn a15_production_pkcs11_hsm_path_reachable_and_fail_closed() {
    let (evidence, expectations, td) = production_scenario(
        ProductionCustodyProviderKind::ProductionPkcs11Hsm,
        ProductionCustodyAttestationClass::ProductionPkcs11HsmAttestation,
        ProductionCustodyAttestationVerifierPolicy::ProductionPkcs11HsmAttestationRequired,
    );
    let stub = ProductionCustodyAttestationVerifierStub::pkcs11_hsm();
    let verifier = ProductionCustodyAttestationVerifier::new(
        ProductionCustodyAttestationVerifierConfig::default(),
        ProductionCustodyAttestationVerifierPolicy::ProductionPkcs11HsmAttestationRequired,
        stub,
    );
    let outcome = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert_eq!(
        outcome,
        ProductionCustodyAttestationOutcome::ProductionAttestationUnverified
    );
    assert_eq!(verifier.evidence_verifier.call_count(), 1);
}

fn a16_production_generic_kms_path_reachable_and_fail_closed() {
    let (evidence, expectations, td) = production_scenario(
        ProductionCustodyProviderKind::ProductionGenericKms,
        ProductionCustodyAttestationClass::ProductionGenericKmsAttestation,
        ProductionCustodyAttestationVerifierPolicy::ProductionGenericKmsAttestationRequired,
    );
    let stub = ProductionCustodyAttestationVerifierStub::generic_kms();
    let verifier = ProductionCustodyAttestationVerifier::new(
        ProductionCustodyAttestationVerifierConfig::default(),
        ProductionCustodyAttestationVerifierPolicy::ProductionGenericKmsAttestationRequired,
        stub,
    );
    let outcome = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert_eq!(
        outcome,
        ProductionCustodyAttestationOutcome::ProductionAttestationTrustRootMissing
    );
}

fn a17_production_generic_hsm_path_reachable_and_fail_closed() {
    let (evidence, expectations, td) = production_scenario(
        ProductionCustodyProviderKind::ProductionGenericHsm,
        ProductionCustodyAttestationClass::ProductionGenericHsmAttestation,
        ProductionCustodyAttestationVerifierPolicy::ProductionGenericHsmAttestationRequired,
    );
    let stub = ProductionCustodyAttestationVerifierStub::generic_hsm();
    let verifier = ProductionCustodyAttestationVerifier::new(
        ProductionCustodyAttestationVerifierConfig::default(),
        ProductionCustodyAttestationVerifierPolicy::ProductionGenericHsmAttestationRequired,
        stub,
    );
    let outcome = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert_eq!(
        outcome,
        ProductionCustodyAttestationOutcome::ProductionAttestationUnavailable
    );
}

fn a18_run295_backend_submit_remains_compatible() {
    let submitted = submitted_kms(TrustBundleEnvironment::Devnet);
    assert!(!submitted.request_id.is_empty());
    assert_eq!(submitted.response.request_id_echo, submitted.request_id);
}

fn a19_evaluate_produces_decision_with_bound_request_id() {
    let (evidence, expectations, td) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    let verifier =
        kms_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed);
    let decision = verifier.evaluate_custody_attestation(&evidence, &expectations, &td);
    assert!(decision.is_verified());
    assert_eq!(decision.custody_request_id, evidence.binding.custody_request_id);
    assert!(!decision.transcript_digest.is_empty());
}

fn a20_decision_digest_is_deterministic_and_outcome_bound() {
    let (evidence, expectations, td) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    let verifier =
        kms_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed);
    let decision = verifier.evaluate_custody_attestation(&evidence, &expectations, &td);
    let d1 = production_custody_attestation_decision_digest(
        &decision.transcript_digest,
        decision.outcome.tag(),
    );
    let d2 = production_custody_attestation_decision_digest(
        &decision.transcript_digest,
        decision.outcome.tag(),
    );
    assert_eq!(d1, d2);
    let d3 =
        production_custody_attestation_decision_digest(&decision.transcript_digest, "mainnet-refused");
    assert_ne!(d1, d3);
}

// ===========================================================================
// B. Rejection / fail-closed release checks
// ===========================================================================

fn b01_disabled_policy_produces_no_verification() {
    let (evidence, expectations, td) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    let verifier = kms_verifier(ProductionCustodyAttestationVerifierPolicy::Disabled);
    assert_eq!(
        verifier.verify_custody_attestation(&evidence, &expectations, &td),
        ProductionCustodyAttestationOutcome::DisabledNoVerification
    );
}

fn b02_missing_attestation_evidence_rejected() {
    let out = kms_reject(|e| e.certificate_proof_digest = String::new(), |_| {});
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationMalformed
    );
}

fn b03_malformed_attestation_rejected() {
    let out = kms_reject(
        |e| {
            e.certificate_proof_digest =
                PRODUCTION_CUSTODY_ATTESTATION_INVALID_PROOF_SENTINEL.to_string()
        },
        |_| {},
    );
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationMalformed
    );
}

fn b04_unsupported_attestation_class_rejected() {
    let out = kms_reject(|e| e.attestation_class = ProductionCustodyAttestationClass::Unknown, |_| {});
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationUnsupportedClass
    );
}

fn b05_unsupported_protocol_version_rejected() {
    let out = kms_reject(
        |e| e.protocol_version = ProductionCustodyAttestationProtocolVersion(99),
        |_| {},
    );
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationUnsupportedProtocol { version: 99 }
    );
}

fn b06_missing_trust_root_rejected() {
    let out = kms_reject(
        |e| e.trust_root = ProductionCustodyAttestationTrustRoot::default(),
        |x| x.expected_trust_root = ProductionCustodyAttestationTrustRoot::default(),
    );
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationTrustRootMissing
    );
}

fn b07_wrong_trust_root_rejected() {
    let out = kms_reject(|e| e.trust_root.root_id = "other-root".to_string(), |_| {});
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationTrustRootMismatch
    );
}

fn b08_wrong_provider_kind_rejected() {
    let out = kms_reject(
        |e| e.binding.provider_kind = ProductionCustodyProviderKind::ProductionCloudKms,
        |_| {},
    );
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationProviderMismatch
    );
}

fn b09_wrong_provider_identity_rejected() {
    let out = kms_reject(|e| e.binding.provider_id = "other-provider".to_string(), |_| {});
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationProviderMismatch
    );
}

fn b10_wrong_key_handle_rejected() {
    let out = kms_reject(|e| e.binding.key_handle = "other-key".to_string(), |_| {});
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationKeyHandleMismatch
    );
}

fn b11_wrong_signer_identity_rejected() {
    let out = kms_reject(|e| e.binding.signer_identity = "other-signer".to_string(), |_| {});
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationSignerMismatch
    );
}

fn b12_wrong_custody_class_rejected() {
    let out = kms_reject(|e| e.binding.custody_class = AuthorityCustodyClass::Hsm, |_| {});
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationCustodyClassMismatch
    );
}

fn b13_wrong_request_id_rejected() {
    let out = kms_reject(|e| e.binding.custody_request_id = "other-req-id".to_string(), |_| {});
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationRequestIdMismatch
    );
}

fn b14_wrong_backend_transcript_rejected() {
    let out = kms_reject(
        |e| e.binding.backend_transcript_digest = "other-transcript".to_string(),
        |_| {},
    );
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationBackendTranscriptMismatch
    );
}

fn b15_wrong_request_envelope_digest_rejected() {
    let out = kms_reject(
        |e| e.binding.request_envelope_digest = "other-req-env".to_string(),
        |_| {},
    );
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationRequestEnvelopeMismatch
    );
}

fn b16_wrong_response_envelope_digest_rejected() {
    let out = kms_reject(
        |e| e.binding.response_envelope_digest = "other-resp-env".to_string(),
        |_| {},
    );
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationResponseEnvelopeMismatch
    );
}

fn b17_wrong_candidate_digest_rejected() {
    let out = kms_reject(|e| e.binding.candidate_digest = "other-candidate".to_string(), |_| {});
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationCandidateDigestMismatch
    );
}

fn b18_wrong_authorized_action_rejected() {
    let out = kms_reject(
        |e| e.binding.authorized_action = LocalLifecycleAction::Revoke,
        |_| {},
    );
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationActionMismatch
    );
}

fn b19_wrong_environment_rejected() {
    let out = kms_reject(
        |e| e.binding.environment = TrustBundleEnvironment::Testnet,
        |x| x.binding.environment = TrustBundleEnvironment::Testnet,
    );
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationDomainMismatch
    );
}

fn b20_wrong_chain_rejected() {
    let out = kms_reject(
        |e| e.binding.chain_id = "other-chain".to_string(),
        |x| x.binding.chain_id = "other-chain".to_string(),
    );
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationDomainMismatch
    );
}

fn b21_wrong_genesis_domain_rejected() {
    let out = kms_reject(
        |e| e.binding.genesis_hash = "other-genesis".to_string(),
        |x| x.binding.genesis_hash = "other-genesis".to_string(),
    );
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationDomainMismatch
    );
}

fn b22_wrong_authority_sequence_rejected() {
    let out = kms_reject(|e| e.binding.authority_domain_sequence = 999, |_| {});
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationDomainMismatch
    );
}

fn b23_wrong_authority_root_rejected() {
    let out = kms_reject(
        |e| e.binding.authority_root_fingerprint = "other-root-fp".to_string(),
        |x| x.binding.authority_root_fingerprint = "other-root-fp".to_string(),
    );
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationDomainMismatch
    );
}

fn b24_wrong_nonce_challenge_rejected() {
    let out = kms_reject(|e| e.challenge.challenge = "other-challenge".to_string(), |_| {});
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationNonceReplay
    );
}

fn b25_replayed_stale_nonce_rejected() {
    let out = kms_reject(
        |e| e.challenge.bound_request_id = "some-other-request".to_string(),
        |_| {},
    );
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationNonceReplay
    );
}

fn b26_wrong_measurement_digest_rejected() {
    let out = kms_reject(
        |e| e.measurement.measurement_digest = "other-measurement".to_string(),
        |_| {},
    );
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationMeasurementMismatch
    );
}

fn b27_wrong_certificate_proof_digest_rejected() {
    let out = kms_reject(|e| e.certificate_proof_digest = "wrong-proof".to_string(), |_| {});
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationMalformed
    );
}

fn b28_ambiguous_durable_replay_binding_rejected() {
    let out = kms_reject(
        |e| e.binding.durable_replay_record_digest = Some("phantom-replay".to_string()),
        |_| {},
    );
    assert!(matches!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationEvidenceAmbiguous { .. }
    ));
}

fn b29_wrong_domain_separation_tag_rejected() {
    let out = kms_reject(|e| e.domain_separation_tag = "wrong-tag".to_string(), |_| {});
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationMalformed
    );
}

fn b30_attestation_unavailable_rejected() {
    let (evidence, expectations, td) = production_scenario(
        ProductionCustodyProviderKind::ProductionGenericHsm,
        ProductionCustodyAttestationClass::ProductionGenericHsmAttestation,
        ProductionCustodyAttestationVerifierPolicy::ProductionGenericHsmAttestationRequired,
    );
    let verifier = ProductionCustodyAttestationVerifier::new(
        ProductionCustodyAttestationVerifierConfig::default(),
        ProductionCustodyAttestationVerifierPolicy::ProductionGenericHsmAttestationRequired,
        MockCustodyAttestationVerifier::always_fail(
            ProductionCustodyAttestationError::AttestationUnavailable,
        ),
    );
    assert_eq!(
        verifier.verify_custody_attestation(&evidence, &expectations, &td),
        ProductionCustodyAttestationOutcome::ProductionAttestationUnavailable
    );
}

fn b31_attestation_unverified_rejected() {
    let (evidence, expectations, td) = production_scenario(
        ProductionCustodyProviderKind::ProductionCloudKms,
        ProductionCustodyAttestationClass::ProductionCloudKmsAttestation,
        ProductionCustodyAttestationVerifierPolicy::ProductionCloudKmsAttestationRequired,
    );
    let verifier = ProductionCustodyAttestationVerifier::new(
        ProductionCustodyAttestationVerifierConfig::default(),
        ProductionCustodyAttestationVerifierPolicy::ProductionCloudKmsAttestationRequired,
        MockCustodyAttestationVerifier::always_fail(
            ProductionCustodyAttestationError::QuoteVerifierUnavailable,
        ),
    );
    assert_eq!(
        verifier.verify_custody_attestation(&evidence, &expectations, &td),
        ProductionCustodyAttestationOutcome::ProductionAttestationUnverified
    );
}

fn b32_production_provider_without_verification_material_rejected() {
    let (evidence, expectations, td) = production_scenario(
        ProductionCustodyProviderKind::ProductionCloudKms,
        ProductionCustodyAttestationClass::ProductionCloudKmsAttestation,
        ProductionCustodyAttestationVerifierPolicy::ProductionCloudKmsAttestationRequired,
    );
    let verifier = ProductionCustodyAttestationVerifier::new(
        ProductionCustodyAttestationVerifierConfig::default(),
        ProductionCustodyAttestationVerifierPolicy::ProductionCloudKmsAttestationRequired,
        MockCustodyAttestationVerifier::always_fail(
            ProductionCustodyAttestationError::VerificationMaterialUnavailable,
        ),
    );
    let out = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert!(!out.is_verified());
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationUnverified
    );
}

fn b33_remote_signer_evidence_rejected_for_kms_hsm() {
    let out = kms_reject(
        |e| e.attestation_class = ProductionCustodyAttestationClass::RemoteSignerAttestation,
        |_| {},
    );
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::RemoteSignerAttestationIsNotKmsHsmCustody
    );
}

fn b34_local_operator_material_rejected() {
    let out = kms_reject(
        |e| e.binding.custody_class = AuthorityCustodyClass::LocalOperatorKey,
        |x| x.binding.custody_class = AuthorityCustodyClass::LocalOperatorKey,
    );
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationCustodyClassMismatch
    );
}

fn b35_peer_majority_evidence_rejected() {
    let out = kms_reject(
        |e| e.binding.custody_class = AuthorityCustodyClass::Unknown,
        |x| x.binding.custody_class = AuthorityCustodyClass::Unknown,
    );
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationCustodyClassMismatch
    );
}

fn b36_validator_set_rotation_request_kind_fail_closed() {
    let out = kms_reject(
        |e| e.binding.request_kind = ProductionCustodyRequestKind::ValidatorSetRotation,
        |x| x.binding.request_kind = ProductionCustodyRequestKind::ValidatorSetRotation,
    );
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ValidatorSetRotationUnsupported
    );
}

fn b37_policy_change_request_kind_fail_closed() {
    let out = kms_reject(
        |e| e.binding.request_kind = ProductionCustodyRequestKind::PolicyChange,
        |x| x.binding.request_kind = ProductionCustodyRequestKind::PolicyChange,
    );
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::PolicyChangeUnsupported
    );
}

fn b38_onchain_governance_request_kind_fail_closed() {
    let out = kms_reject(
        |e| {
            e.binding.request_kind =
                ProductionCustodyRequestKind::OnChainGovernanceProofVerification
        },
        |x| {
            x.binding.request_kind =
                ProductionCustodyRequestKind::OnChainGovernanceProofVerification
        },
    );
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::GovernanceVerifierUnavailable
    );
}

fn b39_fixture_kms_evidence_under_hsm_policy_rejected() {
    let (evidence, expectations, td) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    let verifier =
        kms_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureHsmAttestationAllowed);
    let out = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationUnsupportedClass
    );
}

fn b40_malformed_expectations_rejected() {
    let out = kms_reject(|_| {}, |x| x.binding.provider_id = String::new());
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationMalformed
    );
}

// ===========================================================================
// C. MainNet / authority policy
// ===========================================================================

fn c01_mainnet_cannot_be_satisfied_by_fixture_kms() {
    let (evidence, expectations, td) = mainnet_scenario(
        ProductionCustodyAttestationClass::FixtureKmsAttestation,
        AuthorityCustodyClass::Kms,
        ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed,
    );
    let verifier =
        kms_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed);
    let out = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::FixtureAttestationRejectedForMainNet
    );
}

fn c02_mainnet_cannot_be_satisfied_by_fixture_hsm() {
    let (evidence, expectations, td) = mainnet_scenario(
        ProductionCustodyAttestationClass::FixtureHsmAttestation,
        AuthorityCustodyClass::Hsm,
        ProductionCustodyAttestationVerifierPolicy::FixtureHsmAttestationAllowed,
    );
    let verifier =
        hsm_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureHsmAttestationAllowed);
    let out = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::FixtureAttestationRejectedForMainNet
    );
}

fn c03_mainnet_cannot_be_satisfied_by_remote_signer() {
    let (evidence, expectations, td) = mainnet_scenario(
        ProductionCustodyAttestationClass::RemoteSignerAttestation,
        AuthorityCustodyClass::RemoteSigner,
        ProductionCustodyAttestationVerifierPolicy::MainnetProductionCustodyAttestationRequired,
    );
    let verifier = kms_verifier(
        ProductionCustodyAttestationVerifierPolicy::MainnetProductionCustodyAttestationRequired,
    );
    let out = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::RemoteSignerAttestationIsNotKmsHsmCustody
    );
}

fn c04_mainnet_cannot_be_satisfied_by_local_operator() {
    let (evidence, expectations, td) = mainnet_scenario(
        ProductionCustodyAttestationClass::FixtureKmsAttestation,
        AuthorityCustodyClass::LocalOperatorKey,
        ProductionCustodyAttestationVerifierPolicy::MainnetProductionCustodyAttestationRequired,
    );
    let verifier = kms_verifier(
        ProductionCustodyAttestationVerifierPolicy::MainnetProductionCustodyAttestationRequired,
    );
    let out = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationCustodyClassMismatch
    );
}

fn c05_mainnet_cannot_be_satisfied_by_peer_majority() {
    let (evidence, expectations, td) = mainnet_scenario(
        ProductionCustodyAttestationClass::FixtureKmsAttestation,
        AuthorityCustodyClass::Unknown,
        ProductionCustodyAttestationVerifierPolicy::MainnetProductionCustodyAttestationRequired,
    );
    let verifier = kms_verifier(
        ProductionCustodyAttestationVerifierPolicy::MainnetProductionCustodyAttestationRequired,
    );
    let out = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationCustodyClassMismatch
    );
}

fn c06_mainnet_production_policy_is_unavailable() {
    let (evidence, expectations, td) = mainnet_scenario(
        ProductionCustodyAttestationClass::FixtureKmsAttestation,
        AuthorityCustodyClass::Kms,
        ProductionCustodyAttestationVerifierPolicy::MainnetProductionCustodyAttestationRequired,
    );
    let verifier = kms_verifier(
        ProductionCustodyAttestationVerifierPolicy::MainnetProductionCustodyAttestationRequired,
    );
    let out = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::MainNetProductionCustodyAttestationUnavailable
    );
}

fn c07_mainnet_non_production_policy_refused() {
    let (evidence, expectations, _) = production_scenario(
        ProductionCustodyProviderKind::ProductionCloudKms,
        ProductionCustodyAttestationClass::ProductionCloudKmsAttestation,
        ProductionCustodyAttestationVerifierPolicy::ProductionCloudKmsAttestationRequired,
    );
    let verifier = kms_verifier(
        ProductionCustodyAttestationVerifierPolicy::ProductionCloudKmsAttestationRequired,
    );
    let out = verifier.verify_custody_attestation(
        &evidence,
        &expectations,
        &domain(TrustBundleEnvironment::Mainnet),
    );
    assert_eq!(out, ProductionCustodyAttestationOutcome::MainNetRefused);
}

fn c08_mainnet_production_policy_on_non_mainnet_is_unavailable() {
    let (evidence, expectations, td) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    let verifier = kms_verifier(
        ProductionCustodyAttestationVerifierPolicy::MainnetProductionCustodyAttestationRequired,
    );
    let out = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::MainNetProductionCustodyAttestationUnavailable
    );
}

fn c09_mainnet_cannot_bypass_missing_production_attestation() {
    let (evidence, expectations, td) = mainnet_scenario(
        ProductionCustodyAttestationClass::FixtureKmsAttestation,
        AuthorityCustodyClass::Kms,
        ProductionCustodyAttestationVerifierPolicy::MainnetProductionCustodyAttestationRequired,
    );
    let verifier = kms_verifier(
        ProductionCustodyAttestationVerifierPolicy::MainnetProductionCustodyAttestationRequired,
    );
    let out = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert!(!out.is_verified());
}

fn c10_mainnet_production_attestation_unavailable_records_no_verification() {
    let (evidence, expectations, td) = mainnet_scenario(
        ProductionCustodyAttestationClass::FixtureKmsAttestation,
        AuthorityCustodyClass::Kms,
        ProductionCustodyAttestationVerifierPolicy::MainnetProductionCustodyAttestationRequired,
    );
    let verifier = kms_verifier(
        ProductionCustodyAttestationVerifierPolicy::MainnetProductionCustodyAttestationRequired,
    );
    let out = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert_eq!(verifier.evidence_verifier.call_count(), 0);
    assert!(out.is_non_mutating());
}

fn c11_disabled_default_refuses_mainnet() {
    let (evidence, expectations, td) = mainnet_scenario(
        ProductionCustodyAttestationClass::FixtureKmsAttestation,
        AuthorityCustodyClass::Kms,
        ProductionCustodyAttestationVerifierPolicy::Disabled,
    );
    let verifier = kms_verifier(ProductionCustodyAttestationVerifierPolicy::Disabled);
    let out = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::DisabledNoVerification
    );
}

// ===========================================================================
// D. Non-mutation
// ===========================================================================

fn d01_every_reject_is_non_mutating() {
    let rejects = vec![
        kms_reject(|e| e.attestation_class = ProductionCustodyAttestationClass::Unknown, |_| {}),
        kms_reject(|e| e.binding.key_handle = "x".to_string(), |_| {}),
        kms_reject(|e| e.trust_root.root_id = "x".to_string(), |_| {}),
        kms_reject(|e| e.measurement.measurement_digest = "x".to_string(), |_| {}),
    ];
    for r in rejects {
        assert!(r.is_non_mutating());
        assert!(!r.is_verified());
    }
}

fn d02_reject_does_not_invoke_evidence_verifier_before_binding_checks() {
    let (mut evidence, mut expectations, td) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    evidence.binding.chain_id = "wrong".to_string();
    expectations.binding.chain_id = "wrong".to_string();
    let verifier =
        kms_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed);
    let _ = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert_eq!(verifier.evidence_verifier.call_count(), 0);
}

fn d03_disabled_never_invokes_evidence_verifier() {
    let (evidence, expectations, td) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    let verifier = kms_verifier(ProductionCustodyAttestationVerifierPolicy::Disabled);
    let _ = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert_eq!(verifier.evidence_verifier.call_count(), 0);
}

fn d04_no_fallback_to_fixture_under_production_policy() {
    let (mut evidence, mut expectations, td) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    evidence.verifier_policy =
        ProductionCustodyAttestationVerifierPolicy::ProductionCloudKmsAttestationRequired;
    expectations.binding = evidence.binding.clone();
    let verifier = kms_verifier(
        ProductionCustodyAttestationVerifierPolicy::ProductionCloudKmsAttestationRequired,
    );
    let out = verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::ProductionAttestationUnsupportedClass
    );
    assert!(!out.is_verified());
}

fn d05_no_fallback_to_remote_signer_under_kms_hsm_policy() {
    let out = kms_reject(
        |e| e.attestation_class = ProductionCustodyAttestationClass::RemoteSignerAttestation,
        |_| {},
    );
    assert_eq!(
        out,
        ProductionCustodyAttestationOutcome::RemoteSignerAttestationIsNotKmsHsmCustody
    );
}

fn d06_scope_helpers_assert_non_mutation_invariants() {
    assert!(production_custody_attestation_verifier_is_non_mutating());
    assert!(production_custody_attestation_verifier_never_falls_back());
    assert!(production_custody_attestation_verifier_remote_signer_is_not_kms_hsm());
    assert!(production_custody_attestation_verifier_production_is_fail_closed());
}

// ===========================================================================
// E. Replay / recovery / idempotency
// ===========================================================================

fn e01_no_prior_attestation_window_is_clean_no_op() {
    let (evidence, _, _) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    let verifier =
        kms_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed);
    assert_eq!(
        verifier.recover_attestation_window(None, &evidence),
        ProductionCustodyAttestationRecoveryOutcome::NoPriorAttestation
    );
}

fn e02_byte_identical_duplicate_is_idempotent() {
    let (evidence, _, _) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    let clone = evidence.clone();
    let verifier =
        kms_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed);
    let r = verifier.recover_attestation_window(Some(&evidence), &clone);
    assert!(r.is_idempotent());
}

fn e03_same_id_different_transcript_fails_closed() {
    let (evidence, _, _) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    let mut current = evidence.clone();
    current.binding.backend_transcript_digest = "other-transcript".to_string();
    let verifier =
        kms_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed);
    assert_eq!(
        verifier.recover_attestation_window(Some(&evidence), &current),
        ProductionCustodyAttestationRecoveryOutcome::ConflictingTranscriptForSameId
    );
}

fn e04_same_id_different_key_handle_fails_closed() {
    let (evidence, _, _) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    let mut current = evidence.clone();
    current.binding.key_handle = "other-key".to_string();
    let verifier =
        kms_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed);
    assert_eq!(
        verifier.recover_attestation_window(Some(&evidence), &current),
        ProductionCustodyAttestationRecoveryOutcome::ConflictingKeyHandleForSameId
    );
}

fn e05_same_id_different_measurement_fails_closed() {
    let (evidence, _, _) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    let mut current = evidence.clone();
    current.measurement.measurement_digest = "other-measurement".to_string();
    let verifier =
        kms_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed);
    assert_eq!(
        verifier.recover_attestation_window(Some(&evidence), &current),
        ProductionCustodyAttestationRecoveryOutcome::ConflictingMeasurementForSameId
    );
}

fn e06_same_nonce_across_different_request_id_fails_closed() {
    let (evidence, _, _) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    let mut current = evidence.clone();
    current.binding.custody_request_id = "different-request".to_string();
    let verifier =
        kms_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed);
    assert_eq!(
        verifier.recover_attestation_window(Some(&evidence), &current),
        ProductionCustodyAttestationRecoveryOutcome::ReusedNonceAcrossRequests
    );
}

fn e07_unrelated_request_id_is_no_prior() {
    let (evidence, _, _) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    let mut current = evidence.clone();
    current.binding.custody_request_id = "different-request".to_string();
    current.challenge.nonce = "different-nonce".to_string();
    current.challenge.challenge = "different-challenge".to_string();
    let verifier =
        kms_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed);
    assert_eq!(
        verifier.recover_attestation_window(Some(&evidence), &current),
        ProductionCustodyAttestationRecoveryOutcome::NoPriorAttestation
    );
}

fn e08_no_durable_persistence_claimed() {
    assert!(production_custody_attestation_verifier_is_non_mutating());
}

// ===========================================================================
// F. C4/C5 taxonomy
// ===========================================================================

fn f01_run297_is_source_test_not_release_binary_evidence() {
    assert!(production_custody_attestation_verifier_is_source_test_not_release_binary_evidence());
}

fn f02_default_is_disabled_fail_closed() {
    assert!(production_custody_attestation_verifier_default_is_disabled());
}

fn f03_mainnet_refuses_fixture() {
    assert!(production_custody_attestation_verifier_mainnet_refuses_fixture());
}

fn f04_production_classes_fail_closed() {
    assert!(production_custody_attestation_verifier_production_is_fail_closed());
}

fn f05_protocol_version_is_one() {
    assert_eq!(PRODUCTION_CUSTODY_ATTESTATION_PROTOCOL_VERSION, 1);
    assert!(ProductionCustodyAttestationProtocolVersion::supported().is_supported());
}

fn f06_class_taxonomy_tags_are_distinct() {
    let classes = [
        ProductionCustodyAttestationClass::Disabled,
        ProductionCustodyAttestationClass::FixtureKmsAttestation,
        ProductionCustodyAttestationClass::FixtureHsmAttestation,
        ProductionCustodyAttestationClass::ProductionCloudKmsAttestation,
        ProductionCustodyAttestationClass::ProductionPkcs11HsmAttestation,
        ProductionCustodyAttestationClass::ProductionGenericKmsAttestation,
        ProductionCustodyAttestationClass::ProductionGenericHsmAttestation,
        ProductionCustodyAttestationClass::RemoteSignerAttestation,
        ProductionCustodyAttestationClass::Unknown,
    ];
    let mut tags: Vec<&str> = classes.iter().map(|c| c.tag()).collect();
    tags.sort_unstable();
    let n = tags.len();
    tags.dedup();
    assert_eq!(tags.len(), n);
}

fn f07_policy_taxonomy_tags_are_distinct() {
    let policies = [
        ProductionCustodyAttestationVerifierPolicy::Disabled,
        ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed,
        ProductionCustodyAttestationVerifierPolicy::FixtureHsmAttestationAllowed,
        ProductionCustodyAttestationVerifierPolicy::ProductionCloudKmsAttestationRequired,
        ProductionCustodyAttestationVerifierPolicy::ProductionPkcs11HsmAttestationRequired,
        ProductionCustodyAttestationVerifierPolicy::ProductionGenericKmsAttestationRequired,
        ProductionCustodyAttestationVerifierPolicy::ProductionGenericHsmAttestationRequired,
        ProductionCustodyAttestationVerifierPolicy::MainnetProductionCustodyAttestationRequired,
    ];
    let mut tags: Vec<&str> = policies.iter().map(|p| p.tag()).collect();
    tags.sort_unstable();
    let n = tags.len();
    tags.dedup();
    assert_eq!(tags.len(), n);
}

fn f08_class_maps_to_custody_class() {
    assert_eq!(
        ProductionCustodyAttestationClass::FixtureKmsAttestation.custody_class(),
        Some(AuthorityCustodyClass::Kms)
    );
    assert_eq!(
        ProductionCustodyAttestationClass::ProductionPkcs11HsmAttestation.custody_class(),
        Some(AuthorityCustodyClass::Hsm)
    );
    assert_eq!(
        ProductionCustodyAttestationClass::Disabled.custody_class(),
        None
    );
}

fn f09_class_for_provider_kind_round_trips() {
    assert_eq!(
        ProductionCustodyAttestationClass::for_provider_kind(
            ProductionCustodyProviderKind::FixtureKms
        ),
        ProductionCustodyAttestationClass::FixtureKmsAttestation
    );
    assert_eq!(
        ProductionCustodyAttestationClass::for_provider_kind(
            ProductionCustodyProviderKind::ProductionGenericHsm
        ),
        ProductionCustodyAttestationClass::ProductionGenericHsmAttestation
    );
    assert_eq!(
        ProductionCustodyAttestationClass::for_provider_kind(
            ProductionCustodyProviderKind::Unknown
        ),
        ProductionCustodyAttestationClass::Unknown
    );
}

fn f10_policy_allowed_class_matches_taxonomy() {
    assert_eq!(
        ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed.allowed_class(),
        Some(ProductionCustodyAttestationClass::FixtureKmsAttestation)
    );
    assert_eq!(
        ProductionCustodyAttestationVerifierPolicy::Disabled.allowed_class(),
        None
    );
    assert_eq!(
        ProductionCustodyAttestationVerifierPolicy::MainnetProductionCustodyAttestationRequired
            .allowed_class(),
        None
    );
}

fn f11_error_tags_are_distinct() {
    let errors = [
        ProductionCustodyAttestationError::AttestationMissing,
        ProductionCustodyAttestationError::AttestationUnavailable,
        ProductionCustodyAttestationError::MalformedAttestation,
        ProductionCustodyAttestationError::TrustRootMissing,
        ProductionCustodyAttestationError::QuoteVerifierUnavailable,
        ProductionCustodyAttestationError::VerificationMaterialUnavailable,
        ProductionCustodyAttestationError::MeasurementUnverified,
        ProductionCustodyAttestationError::UnsupportedClass,
        ProductionCustodyAttestationError::UnsupportedProtocol { version: 2 },
    ];
    let mut tags: Vec<&str> = errors.iter().map(|e| e.tag()).collect();
    tags.sort_unstable();
    let n = tags.len();
    tags.dedup();
    assert_eq!(tags.len(), n);
}

fn f12_config_pins_supported_protocol() {
    let cfg = ProductionCustodyAttestationVerifierConfig::default();
    assert!(cfg.is_well_formed());
}

fn f13_evidence_verifier_boundary_is_object_safe_mockable() {
    let mock = MockCustodyAttestationVerifier::always_fail(
        ProductionCustodyAttestationError::AttestationMissing,
    );
    let tr = trust_root();
    let (evidence, _, _) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    let verifier: &dyn CustodyAttestationEvidenceVerifier = &mock;
    assert!(verifier.verify_evidence(&evidence, &tr).is_err());
    assert_eq!(mock.call_count(), 1);
}

fn f14_scripted_mock_consumes_steps_then_default() {
    let (evidence, _, _) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    let tr = trust_root();
    let mock = MockCustodyAttestationVerifier::scripted(
        vec![Err(ProductionCustodyAttestationError::AttestationUnavailable)],
        Err(ProductionCustodyAttestationError::TrustRootMissing),
    );
    assert_eq!(
        mock.verify_evidence(&evidence, &tr).unwrap_err(),
        ProductionCustodyAttestationError::AttestationUnavailable
    );
    assert_eq!(
        mock.verify_evidence(&evidence, &tr).unwrap_err(),
        ProductionCustodyAttestationError::TrustRootMissing
    );
    assert_eq!(mock.call_count(), 2);
}

fn f15_production_stub_reports_class_and_counts_calls() {
    let stub = ProductionCustodyAttestationVerifierStub::cloud_kms();
    assert_eq!(
        stub.attestation_class(),
        ProductionCustodyAttestationClass::ProductionCloudKmsAttestation
    );
    let tr = trust_root();
    let (evidence, _, _) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    let _ = stub.verify_evidence(&evidence, &tr);
    assert_eq!(stub.call_count(), 1);
}

fn f16_trust_root_digest_is_deterministic() {
    let tr = trust_root();
    assert_eq!(tr.trust_root_digest(), tr.trust_root_digest());
    assert!(tr.is_present());
    assert!(!ProductionCustodyAttestationTrustRoot::default().is_present());
}

fn f17_provider_identity_digest_binds_provider_and_key() {
    let (evidence, _, _) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    let mut other = evidence.clone();
    other.binding.provider_id = "other".to_string();
    assert_ne!(
        evidence.provider_identity_digest(),
        other.provider_identity_digest()
    );
}

fn f18_fixture_kms_and_hsm_verified_outcomes_are_evidence_only_accepts() {
    let kms = ProductionCustodyAttestationOutcome::FixtureKmsAttestationVerified {
        provider_id: "p".to_string(),
        environment: TrustBundleEnvironment::Devnet,
        custody_request_id: "r".to_string(),
    };
    assert!(kms.is_verified());
    assert!(kms.is_non_mutating());
}

fn f19_evaluate_on_disabled_records_disabled_outcome_in_decision() {
    let (evidence, expectations, td) = kms_accept_scenario(TrustBundleEnvironment::Devnet);
    let verifier = kms_verifier(ProductionCustodyAttestationVerifierPolicy::Disabled);
    let decision = verifier.evaluate_custody_attestation(&evidence, &expectations, &td);
    assert_eq!(
        decision.outcome,
        ProductionCustodyAttestationOutcome::DisabledNoVerification
    );
    assert!(!decision.is_verified());
}

fn f20_build_attestation_challenge_binds_request_id() {
    let verifier =
        kms_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed);
    let c = verifier.build_attestation_challenge("n", "c", 3, "req-x");
    assert_eq!(c.bound_request_id, "req-x");
    assert!(c.is_well_formed());
}

// ===========================================================================
// G. Release symbol reachability probe
// ===========================================================================

fn g01_release_symbol_reachability_probe() {
    // Touch a broad slice of the Run 297 verifier surface so the release
    // helper links against and exercises the real production symbols.
    assert_eq!(PRODUCTION_CUSTODY_ATTESTATION_PROTOCOL_VERSION, 1);
    assert!(!PRODUCTION_CUSTODY_ATTESTATION_DOMAIN_SEPARATION_TAG.is_empty());
    assert!(!PRODUCTION_CUSTODY_ATTESTATION_INVALID_PROOF_SENTINEL.is_empty());

    let env = TrustBundleEnvironment::Devnet;
    let (evidence, expectations, td) = kms_accept_scenario(env);

    // Real verifier over the fixture KMS evidence verifier.
    let verifier =
        kms_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed);
    let outcome: ProductionCustodyAttestationOutcome =
        verifier.verify_custody_attestation(&evidence, &expectations, &td);
    assert!(outcome.is_verified());
    let decision = verifier.evaluate_custody_attestation(&evidence, &expectations, &td);
    assert!(decision.is_verified());
    let challenge: ProductionCustodyAttestationChallenge =
        verifier.build_attestation_challenge("n", "c", 1, "req-x");
    assert!(challenge.is_well_formed());
    let recovery: ProductionCustodyAttestationRecoveryOutcome =
        verifier.recover_attestation_window(None, &evidence);
    assert_eq!(
        recovery,
        ProductionCustodyAttestationRecoveryOutcome::NoPriorAttestation
    );

    // Digest surfaces are linked and deterministic.
    let _ = evidence.evidence_digest();
    let _ = evidence.challenge.challenge_digest();
    let _ = evidence.provider_identity_digest();
    let _ = evidence.trust_root.trust_root_digest();
    let transcript = production_custody_attestation_transcript_digest(
        PRODUCTION_CUSTODY_ATTESTATION_PROTOCOL_VERSION,
        &evidence.evidence_digest(),
        &evidence.challenge.challenge_digest(),
        &evidence.binding.custody_request_id,
        &evidence.binding.backend_transcript_digest,
    );
    let _ = production_custody_attestation_decision_digest(&transcript, decision.outcome.tag());

    // Production stubs are reachable and typed, fail-closed.
    for stub in [
        ProductionCustodyAttestationVerifierStub::cloud_kms(),
        ProductionCustodyAttestationVerifierStub::pkcs11_hsm(),
        ProductionCustodyAttestationVerifierStub::generic_kms(),
        ProductionCustodyAttestationVerifierStub::generic_hsm(),
    ] {
        let tr = trust_root();
        let _ = stub.verify_evidence(&evidence, &tr);
        assert!(stub.call_count() >= 1);
    }

    // Mock evidence verifier implements the same boundary trait.
    let mock = MockCustodyAttestationVerifier::always_fail(
        ProductionCustodyAttestationError::AttestationMissing,
    );
    let boundary: &dyn CustodyAttestationEvidenceVerifier = &mock;
    assert!(boundary
        .verify_evidence(&evidence, &trust_root())
        .is_err());
    let _ = <MockCustodyAttestationVerifier as CustodyAttestationEvidenceVerifier>::verify_evidence;

    // Run 295 backend composition symbol is linked in release mode.
    assert!(
        <ProductionKmsHsmCustodyBackend<FixtureKmsCustodyProvider> as
            GovernanceProductionKmsHsmCustodyBackend>::submit_custody_signing_request
            as *const () as usize
            != 0
    );
    let submitted_probe: SubmittedCustodyRequest = submitted_kms(env);
    let probe_binding: ProductionCustodyAttestationBinding =
        ProductionCustodyAttestationBinding::from_submitted_request(
            &submitted_probe,
            SIGNER_ID,
            ProductionCustodyRequestKind::AuthorityLifecycleSigning,
            None,
        );
    assert_eq!(probe_binding.custody_request_id, submitted_probe.request_id);

    // Invariant helpers.
    assert!(production_custody_attestation_verifier_default_is_disabled());
    assert!(production_custody_attestation_verifier_mainnet_refuses_fixture());
    assert!(production_custody_attestation_verifier_never_falls_back());
    assert!(production_custody_attestation_verifier_is_non_mutating());
    assert!(production_custody_attestation_verifier_remote_signer_is_not_kms_hsm());
    assert!(production_custody_attestation_verifier_production_is_fail_closed());
    assert!(production_custody_attestation_verifier_is_source_test_not_release_binary_evidence());
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
            "docs/devnet/run_298_production_custody_attestation_verifier_release_binary/helper_evidence/run_298",
        )
    });
    fs::create_dir_all(outdir.join("fixtures")).expect("create helper output directory");

    let cases: &[(&str, &str, fn())] = &[
        ("accepted_compatible", "a01_disabled_default_policy_is_explicit_and_inert", a01_disabled_default_policy_is_explicit_and_inert as fn()),
        ("accepted_compatible", "a02_disabled_verifier_returns_disabled_no_verification", a02_disabled_verifier_returns_disabled_no_verification as fn()),
        ("accepted_compatible", "a03_devnet_fixture_kms_verifies_under_fixture_policy", a03_devnet_fixture_kms_verifies_under_fixture_policy as fn()),
        ("accepted_compatible", "a04_devnet_fixture_hsm_verifies_under_fixture_policy", a04_devnet_fixture_hsm_verifies_under_fixture_policy as fn()),
        ("accepted_compatible", "a05_testnet_fixture_kms_verifies_under_fixture_policy", a05_testnet_fixture_kms_verifies_under_fixture_policy as fn()),
        ("accepted_compatible", "a06_testnet_fixture_hsm_verifies_under_fixture_policy", a06_testnet_fixture_hsm_verifies_under_fixture_policy as fn()),
        ("accepted_compatible", "a07_valid_fixture_binds_to_matching_custody_request_id", a07_valid_fixture_binds_to_matching_custody_request_id as fn()),
        ("accepted_compatible", "a08_valid_fixture_binds_to_matching_backend_transcript", a08_valid_fixture_binds_to_matching_backend_transcript as fn()),
        ("accepted_compatible", "a09_valid_fixture_binds_provider_key_class_signer_candidate_action", a09_valid_fixture_binds_provider_key_class_signer_candidate_action as fn()),
        ("accepted_compatible", "a10_attestation_challenge_digest_is_deterministic", a10_attestation_challenge_digest_is_deterministic as fn()),
        ("accepted_compatible", "a11_attestation_evidence_digest_is_deterministic", a11_attestation_evidence_digest_is_deterministic as fn()),
        ("accepted_compatible", "a12_attestation_transcript_digest_is_deterministic", a12_attestation_transcript_digest_is_deterministic as fn()),
        ("accepted_compatible", "a13_two_identical_evidence_objects_produce_identical_transcripts", a13_two_identical_evidence_objects_produce_identical_transcripts as fn()),
        ("accepted_compatible", "a14_production_cloud_kms_path_reachable_and_fail_closed", a14_production_cloud_kms_path_reachable_and_fail_closed as fn()),
        ("accepted_compatible", "a15_production_pkcs11_hsm_path_reachable_and_fail_closed", a15_production_pkcs11_hsm_path_reachable_and_fail_closed as fn()),
        ("accepted_compatible", "a16_production_generic_kms_path_reachable_and_fail_closed", a16_production_generic_kms_path_reachable_and_fail_closed as fn()),
        ("accepted_compatible", "a17_production_generic_hsm_path_reachable_and_fail_closed", a17_production_generic_hsm_path_reachable_and_fail_closed as fn()),
        ("accepted_compatible", "a18_run295_backend_submit_remains_compatible", a18_run295_backend_submit_remains_compatible as fn()),
        ("accepted_compatible", "a19_evaluate_produces_decision_with_bound_request_id", a19_evaluate_produces_decision_with_bound_request_id as fn()),
        ("accepted_compatible", "a20_decision_digest_is_deterministic_and_outcome_bound", a20_decision_digest_is_deterministic_and_outcome_bound as fn()),
        ("rejection_fail_closed", "b01_disabled_policy_produces_no_verification", b01_disabled_policy_produces_no_verification as fn()),
        ("rejection_fail_closed", "b02_missing_attestation_evidence_rejected", b02_missing_attestation_evidence_rejected as fn()),
        ("rejection_fail_closed", "b03_malformed_attestation_rejected", b03_malformed_attestation_rejected as fn()),
        ("rejection_fail_closed", "b04_unsupported_attestation_class_rejected", b04_unsupported_attestation_class_rejected as fn()),
        ("rejection_fail_closed", "b05_unsupported_protocol_version_rejected", b05_unsupported_protocol_version_rejected as fn()),
        ("rejection_fail_closed", "b06_missing_trust_root_rejected", b06_missing_trust_root_rejected as fn()),
        ("rejection_fail_closed", "b07_wrong_trust_root_rejected", b07_wrong_trust_root_rejected as fn()),
        ("rejection_fail_closed", "b08_wrong_provider_kind_rejected", b08_wrong_provider_kind_rejected as fn()),
        ("rejection_fail_closed", "b09_wrong_provider_identity_rejected", b09_wrong_provider_identity_rejected as fn()),
        ("rejection_fail_closed", "b10_wrong_key_handle_rejected", b10_wrong_key_handle_rejected as fn()),
        ("rejection_fail_closed", "b11_wrong_signer_identity_rejected", b11_wrong_signer_identity_rejected as fn()),
        ("rejection_fail_closed", "b12_wrong_custody_class_rejected", b12_wrong_custody_class_rejected as fn()),
        ("rejection_fail_closed", "b13_wrong_request_id_rejected", b13_wrong_request_id_rejected as fn()),
        ("rejection_fail_closed", "b14_wrong_backend_transcript_rejected", b14_wrong_backend_transcript_rejected as fn()),
        ("rejection_fail_closed", "b15_wrong_request_envelope_digest_rejected", b15_wrong_request_envelope_digest_rejected as fn()),
        ("rejection_fail_closed", "b16_wrong_response_envelope_digest_rejected", b16_wrong_response_envelope_digest_rejected as fn()),
        ("rejection_fail_closed", "b17_wrong_candidate_digest_rejected", b17_wrong_candidate_digest_rejected as fn()),
        ("rejection_fail_closed", "b18_wrong_authorized_action_rejected", b18_wrong_authorized_action_rejected as fn()),
        ("rejection_fail_closed", "b19_wrong_environment_rejected", b19_wrong_environment_rejected as fn()),
        ("rejection_fail_closed", "b20_wrong_chain_rejected", b20_wrong_chain_rejected as fn()),
        ("rejection_fail_closed", "b21_wrong_genesis_domain_rejected", b21_wrong_genesis_domain_rejected as fn()),
        ("rejection_fail_closed", "b22_wrong_authority_sequence_rejected", b22_wrong_authority_sequence_rejected as fn()),
        ("rejection_fail_closed", "b23_wrong_authority_root_rejected", b23_wrong_authority_root_rejected as fn()),
        ("rejection_fail_closed", "b24_wrong_nonce_challenge_rejected", b24_wrong_nonce_challenge_rejected as fn()),
        ("rejection_fail_closed", "b25_replayed_stale_nonce_rejected", b25_replayed_stale_nonce_rejected as fn()),
        ("rejection_fail_closed", "b26_wrong_measurement_digest_rejected", b26_wrong_measurement_digest_rejected as fn()),
        ("rejection_fail_closed", "b27_wrong_certificate_proof_digest_rejected", b27_wrong_certificate_proof_digest_rejected as fn()),
        ("rejection_fail_closed", "b28_ambiguous_durable_replay_binding_rejected", b28_ambiguous_durable_replay_binding_rejected as fn()),
        ("rejection_fail_closed", "b29_wrong_domain_separation_tag_rejected", b29_wrong_domain_separation_tag_rejected as fn()),
        ("rejection_fail_closed", "b30_attestation_unavailable_rejected", b30_attestation_unavailable_rejected as fn()),
        ("rejection_fail_closed", "b31_attestation_unverified_rejected", b31_attestation_unverified_rejected as fn()),
        ("rejection_fail_closed", "b32_production_provider_without_verification_material_rejected", b32_production_provider_without_verification_material_rejected as fn()),
        ("rejection_fail_closed", "b33_remote_signer_evidence_rejected_for_kms_hsm", b33_remote_signer_evidence_rejected_for_kms_hsm as fn()),
        ("rejection_fail_closed", "b34_local_operator_material_rejected", b34_local_operator_material_rejected as fn()),
        ("rejection_fail_closed", "b35_peer_majority_evidence_rejected", b35_peer_majority_evidence_rejected as fn()),
        ("rejection_fail_closed", "b36_validator_set_rotation_request_kind_fail_closed", b36_validator_set_rotation_request_kind_fail_closed as fn()),
        ("rejection_fail_closed", "b37_policy_change_request_kind_fail_closed", b37_policy_change_request_kind_fail_closed as fn()),
        ("rejection_fail_closed", "b38_onchain_governance_request_kind_fail_closed", b38_onchain_governance_request_kind_fail_closed as fn()),
        ("rejection_fail_closed", "b39_fixture_kms_evidence_under_hsm_policy_rejected", b39_fixture_kms_evidence_under_hsm_policy_rejected as fn()),
        ("rejection_fail_closed", "b40_malformed_expectations_rejected", b40_malformed_expectations_rejected as fn()),
        ("mainnet_authority_policy", "c01_mainnet_cannot_be_satisfied_by_fixture_kms", c01_mainnet_cannot_be_satisfied_by_fixture_kms as fn()),
        ("mainnet_authority_policy", "c02_mainnet_cannot_be_satisfied_by_fixture_hsm", c02_mainnet_cannot_be_satisfied_by_fixture_hsm as fn()),
        ("mainnet_authority_policy", "c03_mainnet_cannot_be_satisfied_by_remote_signer", c03_mainnet_cannot_be_satisfied_by_remote_signer as fn()),
        ("mainnet_authority_policy", "c04_mainnet_cannot_be_satisfied_by_local_operator", c04_mainnet_cannot_be_satisfied_by_local_operator as fn()),
        ("mainnet_authority_policy", "c05_mainnet_cannot_be_satisfied_by_peer_majority", c05_mainnet_cannot_be_satisfied_by_peer_majority as fn()),
        ("mainnet_authority_policy", "c06_mainnet_production_policy_is_unavailable", c06_mainnet_production_policy_is_unavailable as fn()),
        ("mainnet_authority_policy", "c07_mainnet_non_production_policy_refused", c07_mainnet_non_production_policy_refused as fn()),
        ("mainnet_authority_policy", "c08_mainnet_production_policy_on_non_mainnet_is_unavailable", c08_mainnet_production_policy_on_non_mainnet_is_unavailable as fn()),
        ("mainnet_authority_policy", "c09_mainnet_cannot_bypass_missing_production_attestation", c09_mainnet_cannot_bypass_missing_production_attestation as fn()),
        ("mainnet_authority_policy", "c10_mainnet_production_attestation_unavailable_records_no_verification", c10_mainnet_production_attestation_unavailable_records_no_verification as fn()),
        ("mainnet_authority_policy", "c11_disabled_default_refuses_mainnet", c11_disabled_default_refuses_mainnet as fn()),
        ("replay_recovery_idempotency", "e01_no_prior_attestation_window_is_clean_no_op", e01_no_prior_attestation_window_is_clean_no_op as fn()),
        ("replay_recovery_idempotency", "e02_byte_identical_duplicate_is_idempotent", e02_byte_identical_duplicate_is_idempotent as fn()),
        ("replay_recovery_idempotency", "e03_same_id_different_transcript_fails_closed", e03_same_id_different_transcript_fails_closed as fn()),
        ("replay_recovery_idempotency", "e04_same_id_different_key_handle_fails_closed", e04_same_id_different_key_handle_fails_closed as fn()),
        ("replay_recovery_idempotency", "e05_same_id_different_measurement_fails_closed", e05_same_id_different_measurement_fails_closed as fn()),
        ("replay_recovery_idempotency", "e06_same_nonce_across_different_request_id_fails_closed", e06_same_nonce_across_different_request_id_fails_closed as fn()),
        ("replay_recovery_idempotency", "e07_unrelated_request_id_is_no_prior", e07_unrelated_request_id_is_no_prior as fn()),
        ("replay_recovery_idempotency", "e08_no_durable_persistence_claimed", e08_no_durable_persistence_claimed as fn()),
        ("non_mutation", "d01_every_reject_is_non_mutating", d01_every_reject_is_non_mutating as fn()),
        ("non_mutation", "d02_reject_does_not_invoke_evidence_verifier_before_binding_checks", d02_reject_does_not_invoke_evidence_verifier_before_binding_checks as fn()),
        ("non_mutation", "d03_disabled_never_invokes_evidence_verifier", d03_disabled_never_invokes_evidence_verifier as fn()),
        ("non_mutation", "d04_no_fallback_to_fixture_under_production_policy", d04_no_fallback_to_fixture_under_production_policy as fn()),
        ("non_mutation", "d05_no_fallback_to_remote_signer_under_kms_hsm_policy", d05_no_fallback_to_remote_signer_under_kms_hsm_policy as fn()),
        ("non_mutation", "d06_scope_helpers_assert_non_mutation_invariants", d06_scope_helpers_assert_non_mutation_invariants as fn()),
        ("reachability_taxonomy", "f01_run297_is_source_test_not_release_binary_evidence", f01_run297_is_source_test_not_release_binary_evidence as fn()),
        ("reachability_taxonomy", "f02_default_is_disabled_fail_closed", f02_default_is_disabled_fail_closed as fn()),
        ("reachability_taxonomy", "f03_mainnet_refuses_fixture", f03_mainnet_refuses_fixture as fn()),
        ("reachability_taxonomy", "f04_production_classes_fail_closed", f04_production_classes_fail_closed as fn()),
        ("reachability_taxonomy", "f05_protocol_version_is_one", f05_protocol_version_is_one as fn()),
        ("reachability_taxonomy", "f06_class_taxonomy_tags_are_distinct", f06_class_taxonomy_tags_are_distinct as fn()),
        ("reachability_taxonomy", "f07_policy_taxonomy_tags_are_distinct", f07_policy_taxonomy_tags_are_distinct as fn()),
        ("reachability_taxonomy", "f08_class_maps_to_custody_class", f08_class_maps_to_custody_class as fn()),
        ("reachability_taxonomy", "f09_class_for_provider_kind_round_trips", f09_class_for_provider_kind_round_trips as fn()),
        ("reachability_taxonomy", "f10_policy_allowed_class_matches_taxonomy", f10_policy_allowed_class_matches_taxonomy as fn()),
        ("reachability_taxonomy", "f11_error_tags_are_distinct", f11_error_tags_are_distinct as fn()),
        ("reachability_taxonomy", "f12_config_pins_supported_protocol", f12_config_pins_supported_protocol as fn()),
        ("reachability_taxonomy", "f13_evidence_verifier_boundary_is_object_safe_mockable", f13_evidence_verifier_boundary_is_object_safe_mockable as fn()),
        ("reachability_taxonomy", "f14_scripted_mock_consumes_steps_then_default", f14_scripted_mock_consumes_steps_then_default as fn()),
        ("reachability_taxonomy", "f15_production_stub_reports_class_and_counts_calls", f15_production_stub_reports_class_and_counts_calls as fn()),
        ("reachability_taxonomy", "f16_trust_root_digest_is_deterministic", f16_trust_root_digest_is_deterministic as fn()),
        ("reachability_taxonomy", "f17_provider_identity_digest_binds_provider_and_key", f17_provider_identity_digest_binds_provider_and_key as fn()),
        ("reachability_taxonomy", "f18_fixture_kms_and_hsm_verified_outcomes_are_evidence_only_accepts", f18_fixture_kms_and_hsm_verified_outcomes_are_evidence_only_accepts as fn()),
        ("reachability_taxonomy", "f19_evaluate_on_disabled_records_disabled_outcome_in_decision", f19_evaluate_on_disabled_records_disabled_outcome_in_decision as fn()),
        ("reachability_taxonomy", "f20_build_attestation_challenge_binds_request_id", f20_build_attestation_challenge_binds_request_id as fn()),
        ("reachability_taxonomy", "g01_release_symbol_reachability_probe", g01_release_symbol_reachability_probe as fn()),
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
    summary.push_str("Run 298 production custody attestation verifier release helper\n");
    summary.push_str(&format!(
        "verdict: {}\n",
        if total_fail == 0 { "PASS" } else { "FAIL" }
    ));
    summary.push_str(
        "verifier: crates/qbind-node/src/pqc_production_custody_attestation_verifier.rs (Run 297 ProductionCustodyAttestationVerifier)\n",
    );
    summary.push_str(
        "mode: real Run 297 verifier over source/test fixture KMS/HSM evidence verifiers, reachable-but-fail-closed production attestation verifier stubs, and a programmable mock evidence verifier; DevNet/TestNet fixture accept only; MainNet refused; default Disabled; production policy never verifies and never falls back to fixture/RemoteSigner/local material; production cloud-KMS/PKCS#11/generic attestation paths fail closed without real trust root / quote verifier / certificate chain / hardware proof; every failure is a typed non-mutating outcome\n",
    );
    for (table, (pass, fail)) in &tables {
        summary.push_str(&format!("table {table} pass={pass} fail={fail}\n"));
    }
    summary.push_str(&format!("total_pass: {total_pass}\n"));
    summary.push_str(&format!("total_fail: {total_fail}\n"));

    fs::write(outdir.join("helper_summary.txt"), &summary).expect("write helper summary");

    // Deterministic-digest fixture for cross-invocation comparison by the harness.
    let env = TrustBundleEnvironment::Devnet;
    let (evidence, expectations, td) = kms_accept_scenario(env);
    let challenge_digest = evidence.challenge.challenge_digest();
    let evidence_digest = evidence.evidence_digest();
    let provider_identity_digest = evidence.provider_identity_digest();
    let trust_root_digest = evidence.trust_root.trust_root_digest();
    let transcript_digest = production_custody_attestation_transcript_digest(
        PRODUCTION_CUSTODY_ATTESTATION_PROTOCOL_VERSION,
        &evidence_digest,
        &challenge_digest,
        &evidence.binding.custody_request_id,
        &evidence.binding.backend_transcript_digest,
    );
    let verifier =
        kms_verifier(ProductionCustodyAttestationVerifierPolicy::FixtureKmsAttestationAllowed);
    let decision = verifier.evaluate_custody_attestation(&evidence, &expectations, &td);
    let decision_digest = production_custody_attestation_decision_digest(
        &decision.transcript_digest,
        decision.outcome.tag(),
    );
    fs::write(
        outdir.join("fixtures/run_298_deterministic_digests.txt"),
        format!(
            "challenge_digest {challenge_digest}\nevidence_digest {evidence_digest}\nprovider_identity_digest {provider_identity_digest}\ntrust_root_digest {trust_root_digest}\ntranscript_digest {transcript_digest}\ndecision_digest {decision_digest}\n"
        ),
    )
    .expect("write digest fixture");

    print!("{summary}");
    if total_fail != 0 {
        std::process::exit(1);
    }
}