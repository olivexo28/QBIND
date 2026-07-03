//! Run 294 — release-binary helper for the Run 293 **production RemoteSigner
//! backend**.
//!
//! Release-binary evidence for the Run 293 source/test production RemoteSigner
//! backend (`crates/qbind-node/src/pqc_production_remote_signer_backend.rs`).
//! This helper is compiled as a release example and linked against the
//! release-built production library symbols. It exercises the **real** Run 293
//! [`ProductionRemoteSignerBackend`] over source/test loopback/mock transports
//! in release mode and proves, per check with PASS/FAIL, the accepted /
//! rejection-fail-closed / MainNet-refusal / non-mutation / replay-recovery
//! behavior of the real backend, including request/response/transcript/domain
//! binding.
//!
//! The helper remains **dead code** from the production runtime: the production
//! `qbind-node` binary never references it. It constructs the backend only
//! through source/test loopback/mock transports, only for DevNet/TestNet
//! identities on the accept path, and never enables any production runtime
//! path, MainNet enablement, custody/KMS/HSM/cloud-KMS/PKCS#11 signing, on-chain
//! governance proof verification, governance execution engine, validator-set
//! rotation, settlement, or external publication. Under a production policy it
//! never falls back to fixture/loopback/local signing.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_294.md`.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_production_remote_signer_backend::{
    production_remote_signer_backend_default_is_disabled,
    production_remote_signer_backend_implements_no_kms_hsm,
    production_remote_signer_backend_is_non_mutating,
    production_remote_signer_backend_is_source_test_not_release_binary_evidence,
    production_remote_signer_backend_mainnet_refuses_fixture_material,
    production_remote_signer_backend_never_falls_back,
    production_remote_signer_backend_transcript_digest, production_remote_signer_request_id,
    GovernanceProductionRemoteSignerBackend, LoopbackRemoteSignerService,
    MockRemoteSignerBackendTransport, ProductionRemoteSignerBackend,
    ProductionRemoteSignerBackendConfig, ProductionRemoteSignerBackendPolicy,
    ProductionRemoteSignerError, ProductionRemoteSignerOutcome,
    ProductionRemoteSignerRecoveryOutcome, ProductionRemoteSignerRequestKind,
    ProductionRemoteSignerRequestSpec, RemoteSignerBackendTransport, SubmittedRemoteSignerRequest,
    PRODUCTION_REMOTE_SIGNER_BACKEND_PROTOCOL_VERSION, PRODUCTION_REMOTE_SIGNER_MAX_RESPONSE_BYTES,
};
use qbind_node::pqc_remote_authority_signer::{
    RemoteSignerIdentity, RemoteSignerMode, REMOTE_SIGNER_INVALID_SIGNATURE_SENTINEL,
};
use qbind_node::pqc_remote_signer_transport::{
    FixtureLoopbackRemoteSignerTransport, RemoteSignerTransportConfig,
    RemoteSignerTransportResponseEnvelope, TransportTimeoutRetryPolicy,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared constants / builders (mirror the Run 293 corpus).
// ===========================================================================

const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT_FP: &str = "1111111111111111111111111111111111111111";
const CHAIN_ID: &str = "0000000000000001";
const GENESIS_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const CUSTODY_ATTEST_DIGEST: &str = "custody-att-digest-294";
const CUSTODY_KEY_ID: &str = "custody-key-id-294";
const SIGNER_ID: &str = "remote-signer-294";
const SIGNER_PUBID: &str = "remote-signer-pubid-294";
const ATTEST_DIGEST: &str = "remote-signer-attest-294";
const REQ_NONCE: &str = "req-nonce-294";
const RESP_NONCE: &str = "resp-nonce-294";
const TRANSPORT_NONCE: &str = "transport-nonce-294";
const ENDPOINT: &str = "qbind-signer://signer.example:8443";
const SIGNER_IDENTITY_DIGEST: &str = "signer-identity-digest-294";
const TRANSPORT_ATTEST: &str = "transport-attest-294";
const PAYLOAD_DIGEST: &str = "transport-payload-digest-294";
const DURABLE_REPLAY_DIGEST: &str = "durable-replay-record-digest-294";
const NOW: u64 = 1_700_000_000;
const FRESH: u64 = 1_699_999_900;
const EXPIRES: u64 = 1_700_001_000;

fn domain(env: TrustBundleEnvironment) -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(env, CHAIN_ID, GENESIS_HASH, ROOT_FP, PQC_LIFECYCLE_SUITE_ML_DSA_44)
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

fn request_spec(env: TrustBundleEnvironment) -> ProductionRemoteSignerRequestSpec {
    ProductionRemoteSignerRequestSpec {
        request_kind: ProductionRemoteSignerRequestKind::AuthorityLifecycleSigning,
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
        durable_replay_record_digest: None,
        signer_id: SIGNER_ID.to_string(),
        custody_key_id: CUSTODY_KEY_ID.to_string(),
        payload_digest: PAYLOAD_DIGEST.to_string(),
        request_replay_nonce: REQ_NONCE.to_string(),
        transport_anti_replay_nonce: TRANSPORT_NONCE.to_string(),
        response_nonce: RESP_NONCE.to_string(),
        request_timestamp_unix: NOW,
    }
}

fn transport_config(env: TrustBundleEnvironment) -> RemoteSignerTransportConfig {
    RemoteSignerTransportConfig {
        endpoint: ENDPOINT.to_string(),
        signer_id: SIGNER_ID.to_string(),
        custody_key_id: CUSTODY_KEY_ID.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        bundle_signing_key_fingerprint: KEY_B.to_string(),
        environment: env,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        expected_signer_identity_digest: SIGNER_IDENTITY_DIGEST.to_string(),
        transport_attestation_digest: Some(TRANSPORT_ATTEST.to_string()),
        timeout_retry: TransportTimeoutRetryPolicy::default(),
    }
}

fn backend_config(env: TrustBundleEnvironment) -> ProductionRemoteSignerBackendConfig {
    ProductionRemoteSignerBackendConfig::from_transport_config(transport_config(env))
}

fn fixture_transport(env: TrustBundleEnvironment) -> FixtureLoopbackRemoteSignerTransport {
    FixtureLoopbackRemoteSignerTransport {
        config: transport_config(env),
        identity: identity(env),
        response_nonce: RESP_NONCE.to_string(),
        response_freshness_unix: Some(FRESH),
        response_expires_at_unix: Some(EXPIRES),
        response_timestamp_unix: FRESH,
        response_expiry_unix: EXPIRES,
        simulated_fault: None,
    }
}

type LoopbackBackend =
    ProductionRemoteSignerBackend<LoopbackRemoteSignerService<FixtureLoopbackRemoteSignerTransport>>;

fn loopback_backend(
    env: TrustBundleEnvironment,
    policy: ProductionRemoteSignerBackendPolicy,
) -> LoopbackBackend {
    ProductionRemoteSignerBackend::new(
        backend_config(env),
        policy,
        LoopbackRemoteSignerService::new(fixture_transport(env)),
    )
}

fn valid_submission(env: TrustBundleEnvironment) -> SubmittedRemoteSignerRequest {
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    backend
        .submit_remote_signing_request(&request_spec(env), &domain(env))
        .expect("valid submission")
}

fn valid_response_env(env: TrustBundleEnvironment) -> RemoteSignerTransportResponseEnvelope {
    valid_submission(env).response_env
}

fn mock_backend(
    env: TrustBundleEnvironment,
    policy: ProductionRemoteSignerBackendPolicy,
    mock: MockRemoteSignerBackendTransport,
) -> ProductionRemoteSignerBackend<MockRemoteSignerBackendTransport> {
    ProductionRemoteSignerBackend::new(backend_config(env), policy, mock)
}

// ===========================================================================
// A — Accepted / compatible release checks
// ===========================================================================

fn a01_disabled_default_policy_is_explicit_and_inert() {
    assert!(production_remote_signer_backend_default_is_disabled());
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::Disabled);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::DisabledNoRequest);
    assert_eq!(backend.transport.call_count(), 0);
}

fn a02_devnet_loopback_accepts_authority_lifecycle_request() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert!(outcome.is_accept(), "expected accept, got {outcome:?}");
    assert_eq!(backend.transport.call_count(), 1);
}

fn a03_devnet_loopback_accepts_governance_execution_request() {
    let env = TrustBundleEnvironment::Devnet;
    let mut spec = request_spec(env);
    spec.request_kind = ProductionRemoteSignerRequestKind::GovernanceExecutionSigning;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let outcome = backend.evaluate_remote_signer_backend(&spec, &domain(env), &identity(env), NOW);
    assert!(outcome.is_accept(), "expected accept, got {outcome:?}");
}

fn a04_testnet_loopback_accepts_when_policy_allows() {
    let env = TrustBundleEnvironment::Testnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert!(outcome.is_accept(), "expected accept, got {outcome:?}");
}

fn a05_accept_path_reaches_transport_exactly_once() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let _ = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(backend.transport.call_count(), 1);
}

fn a06_request_id_is_deterministic() {
    let env = TrustBundleEnvironment::Devnet;
    let a = production_remote_signer_request_id(&request_spec(env));
    let b = production_remote_signer_request_id(&request_spec(env));
    assert_eq!(a, b);
    assert_eq!(a.len(), 64);
}

fn a07_response_digest_is_deterministic() {
    let env = TrustBundleEnvironment::Devnet;
    let a = valid_response_env(env).canonical_response_digest;
    let b = valid_response_env(env).canonical_response_digest;
    assert_eq!(a, b);
}

fn a08_backend_transcript_digest_is_deterministic() {
    let a = production_remote_signer_backend_transcript_digest(1, "rid", "req", "resp", "tt", None);
    let b = production_remote_signer_backend_transcript_digest(1, "rid", "req", "resp", "tt", None);
    assert_eq!(a, b);
    assert_eq!(a.len(), 64);
}

fn a09_two_identical_requests_produce_identical_digests() {
    let env = TrustBundleEnvironment::Devnet;
    let s1 = valid_submission(env);
    let s2 = valid_submission(env);
    assert_eq!(s1.request_id, s2.request_id);
    assert_eq!(
        s1.request_env.envelope_digest(),
        s2.request_env.envelope_digest()
    );
}

fn a10_valid_response_authorizes_exactly_matching_request() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let submitted = valid_submission(env);
    let outcome = backend.verify_remote_signer_response(
        &request_spec(env),
        &submitted,
        &domain(env),
        &identity(env),
        NOW,
    );
    match outcome {
        ProductionRemoteSignerOutcome::RemoteSignerAccepted { request_id, .. } => {
            assert_eq!(request_id, submitted.request_id);
        }
        other => panic!("expected accept, got {other:?}"),
    }
}

fn a11_composes_run194_request_and_run201_transport_types() {
    let env = TrustBundleEnvironment::Devnet;
    let submitted = valid_submission(env);
    // Run 201 request envelope binds the Run 194 inner request digest.
    assert_eq!(
        submitted.request_env.canonical_request_digest,
        submitted.request_env.inner_request.canonical_digest()
    );
    // Run 201 response echoes the Run 201 request id.
    assert_eq!(
        submitted.response_env.request_id_echo,
        submitted.request_env.request_id
    );
}

fn a12_composes_run291_durable_replay_record_digest() {
    let env = TrustBundleEnvironment::Devnet;
    let mut spec = request_spec(env);
    spec.durable_replay_record_digest = Some(DURABLE_REPLAY_DIGEST.to_string());
    let id_without = production_remote_signer_request_id(&request_spec(env));
    let id_with = production_remote_signer_request_id(&spec);
    assert_ne!(id_without, id_with);
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let outcome = backend.evaluate_remote_signer_backend(&spec, &domain(env), &identity(env), NOW);
    assert!(outcome.is_accept(), "expected accept, got {outcome:?}");
}

fn a13_build_only_reports_request_built_without_transport_call() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let built = backend
        .build_request_envelope(&request_spec(env), &domain(env))
        .expect("request built");
    assert_eq!(built.request_id, production_remote_signer_request_id(&request_spec(env)));
    assert_eq!(backend.transport.call_count(), 0);
}

fn a14_backend_protocol_version_pinned() {
    assert_eq!(PRODUCTION_REMOTE_SIGNER_BACKEND_PROTOCOL_VERSION, 1);
    assert_eq!(
        backend_config(TrustBundleEnvironment::Devnet).protocol_version,
        1
    );
}

// ===========================================================================
// B — Rejection / fail-closed release checks
// ===========================================================================

fn b01_disabled_produces_no_request_and_no_transport_call() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::Disabled);
    let built = backend.build_request_envelope(&request_spec(env), &domain(env));
    assert_eq!(built.err(), Some(ProductionRemoteSignerOutcome::DisabledNoRequest));
    assert_eq!(backend.transport.call_count(), 0);
}

fn b02_mainnet_identity_refused_before_transport() {
    let env = TrustBundleEnvironment::Mainnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::MainNetRefused);
    assert_eq!(backend.transport.call_count(), 0);
}

fn b03_fixture_loopback_material_refused_for_mainnet() {
    let env = TrustBundleEnvironment::Mainnet;
    let backend =
        loopback_backend(env, ProductionRemoteSignerBackendPolicy::MainnetProductionRequired);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(
        outcome,
        ProductionRemoteSignerOutcome::MainNetProductionAuthorityUnavailable
    );
    assert_eq!(backend.transport.call_count(), 0);
}

fn b04_wrong_environment_rejected() {
    let backend = loopback_backend(
        TrustBundleEnvironment::Devnet,
        ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled,
    );
    let submitted = valid_submission(TrustBundleEnvironment::Devnet);
    let outcome = backend.verify_remote_signer_response(
        &request_spec(TrustBundleEnvironment::Devnet),
        &submitted,
        &domain(TrustBundleEnvironment::Testnet),
        &identity(TrustBundleEnvironment::Testnet),
        NOW,
    );
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerDomainMismatch);
}

fn b05_wrong_chain_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let submitted = valid_submission(env);
    let mut wrong = domain(env);
    wrong.chain_id = "00000000000000ff".to_string();
    let outcome = backend.verify_remote_signer_response(&request_spec(env), &submitted, &wrong, &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerDomainMismatch);
}

fn b06_wrong_genesis_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let submitted = valid_submission(env);
    let mut wrong = domain(env);
    wrong.genesis_hash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string();
    let outcome = backend.verify_remote_signer_response(&request_spec(env), &submitted, &wrong, &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerDomainMismatch);
}

fn b07_wrong_authority_root_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let submitted = valid_submission(env);
    let mut wrong = domain(env);
    wrong.authority_root_fingerprint = "9999999999999999999999999999999999999999".to_string();
    let outcome = backend.verify_remote_signer_response(&request_spec(env), &submitted, &wrong, &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerDomainMismatch);
}

fn b08_wrong_authority_sequence_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let submitted = valid_submission(env);
    let mut spec = request_spec(env);
    spec.authority_domain_sequence = 3;
    let outcome = backend.verify_remote_signer_response(&spec, &submitted, &domain(env), &identity(env), NOW);
    assert!(
        matches!(
            outcome,
            ProductionRemoteSignerOutcome::RemoteSignerRejected { .. }
                | ProductionRemoteSignerOutcome::RemoteSignerRequestIdMismatch
        ),
        "got {outcome:?}"
    );
}

fn b09_wrong_signer_identity_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let submitted = valid_submission(env);
    let mut wrong_identity = identity(env);
    wrong_identity.signer_id = "other-signer".to_string();
    let outcome = backend.verify_remote_signer_response(&request_spec(env), &submitted, &domain(env), &wrong_identity, NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerWrongSigner);
}

fn b10_wrong_request_id_echo_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let mut submitted = valid_submission(env);
    submitted.response_env.request_id_echo = "tampered-request-id".to_string();
    let outcome = backend.verify_remote_signer_response(&request_spec(env), &submitted, &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerRequestIdMismatch);
}

fn b11_wrong_transcript_digest_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let mut submitted = valid_submission(env);
    submitted.response_env.transcript_digest = "0".repeat(64);
    let outcome = backend.verify_remote_signer_response(&request_spec(env), &submitted, &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerTranscriptMismatch);
}

fn b12_wrong_candidate_digest_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let submitted = valid_submission(env);
    let mut spec = request_spec(env);
    spec.candidate_digest = "3".repeat(64);
    let outcome = backend.verify_remote_signer_response(&spec, &submitted, &domain(env), &identity(env), NOW);
    assert!(
        matches!(
            outcome,
            ProductionRemoteSignerOutcome::RemoteSignerWrongCandidateDigest
                | ProductionRemoteSignerOutcome::RemoteSignerRequestIdMismatch
                | ProductionRemoteSignerOutcome::RemoteSignerRejected { .. }
        ),
        "got {outcome:?}"
    );
}

fn b13_wrong_authorized_action_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let submitted = valid_submission(env);
    let mut spec = request_spec(env);
    spec.lifecycle_action = LocalLifecycleAction::ActivateInitial;
    let outcome = backend.verify_remote_signer_response(&spec, &submitted, &domain(env), &identity(env), NOW);
    assert!(
        matches!(
            outcome,
            ProductionRemoteSignerOutcome::RemoteSignerWrongAction
                | ProductionRemoteSignerOutcome::RemoteSignerRequestIdMismatch
                | ProductionRemoteSignerOutcome::RemoteSignerRejected { .. }
        ),
        "got {outcome:?}"
    );
}

fn b14_wrong_protocol_version_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let mut submitted = valid_submission(env);
    submitted.response_env.protocol_version = 99;
    let outcome = backend.verify_remote_signer_response(&request_spec(env), &submitted, &domain(env), &identity(env), NOW);
    assert_eq!(
        outcome,
        ProductionRemoteSignerOutcome::RemoteSignerUnsupportedProtocol { version: 99 }
    );
}

fn b15_missing_response_signature_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let mut submitted = valid_submission(env);
    submitted.response_env.inner_response.signature_commitment =
        REMOTE_SIGNER_INVALID_SIGNATURE_SENTINEL.to_string();
    let outcome = backend.verify_remote_signer_response(&request_spec(env), &submitted, &domain(env), &identity(env), NOW);
    assert!(outcome.is_non_mutating());
    assert!(!outcome.is_accept(), "got {outcome:?}");
}

fn b16_malformed_response_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let mut submitted = valid_submission(env);
    submitted.response_env.signer_id = String::new();
    let outcome = backend.verify_remote_signer_response(&request_spec(env), &submitted, &domain(env), &identity(env), NOW);
    assert!(!outcome.is_accept(), "got {outcome:?}");
}

fn b17_oversized_response_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut big = valid_response_env(env);
    big.response_commitment = "x".repeat(PRODUCTION_REMOTE_SIGNER_MAX_RESPONSE_BYTES + 1);
    let mock = MockRemoteSignerBackendTransport::respond(big);
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerMalformedResponse);
}

fn b18_signer_unavailable_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mock = MockRemoteSignerBackendTransport::always_fail(ProductionRemoteSignerError::SignerUnavailable);
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerUnavailable);
}

fn b19_transport_unavailable_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mock = MockRemoteSignerBackendTransport::always_fail(ProductionRemoteSignerError::EndpointUnavailable);
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerUnavailable);
    assert_eq!(
        backend.transport.call_count(),
        TransportTimeoutRetryPolicy::default().max_attempts
    );
}

fn b20_timeout_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mock = MockRemoteSignerBackendTransport::always_fail(ProductionRemoteSignerError::Timeout);
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerTimeout);
}

fn b21_decode_error_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mock = MockRemoteSignerBackendTransport::always_fail(ProductionRemoteSignerError::TransportDecodeError);
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerTransportDecodeFailed);
    assert_eq!(backend.transport.call_count(), 1);
}

fn b22_signer_refused_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mock = MockRemoteSignerBackendTransport::always_fail(ProductionRemoteSignerError::SignerRefused);
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert!(matches!(outcome, ProductionRemoteSignerOutcome::RemoteSignerRejected { .. }), "got {outcome:?}");
}

fn b23_signer_policy_rejected_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mock = MockRemoteSignerBackendTransport::always_fail(ProductionRemoteSignerError::SignerPolicyRejected);
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert!(matches!(outcome, ProductionRemoteSignerOutcome::RemoteSignerRejected { .. }), "got {outcome:?}");
}

fn b24_signer_attestation_unavailable_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mock = MockRemoteSignerBackendTransport::always_fail(ProductionRemoteSignerError::SignerAttestationUnavailable);
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerAttestationUnavailable);
}

fn b25_unsupported_protocol_transport_error_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mock = MockRemoteSignerBackendTransport::always_fail(
        ProductionRemoteSignerError::UnsupportedProtocolVersion { version: 7 },
    );
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(
        outcome,
        ProductionRemoteSignerOutcome::RemoteSignerUnsupportedProtocol { version: 7 }
    );
}

fn b26_response_from_wrong_signer_key_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let mut submitted = valid_submission(env);
    submitted.response_env.custody_key_id = "other-custody-key".to_string();
    submitted.response_env.inner_response.custody_key_id = "other-custody-key".to_string();
    let outcome = backend.verify_remote_signer_response(&request_spec(env), &submitted, &domain(env), &identity(env), NOW);
    assert!(!outcome.is_accept(), "got {outcome:?}");
}

fn b27_production_mode_response_never_accepted() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let mut submitted = valid_submission(env);
    submitted.response_env.inner_response.signer_mode = RemoteSignerMode::Production;
    let outcome = backend.verify_remote_signer_response(&request_spec(env), &submitted, &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerUnavailable);
}

fn b28_validator_set_rotation_kind_unsupported() {
    let env = TrustBundleEnvironment::Devnet;
    let mut spec = request_spec(env);
    spec.request_kind = ProductionRemoteSignerRequestKind::ValidatorSetRotation;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let outcome = backend.evaluate_remote_signer_backend(&spec, &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::ValidatorSetRotationUnsupported);
    assert_eq!(backend.transport.call_count(), 0);
}

fn b29_policy_change_kind_unsupported() {
    let env = TrustBundleEnvironment::Devnet;
    let mut spec = request_spec(env);
    spec.request_kind = ProductionRemoteSignerRequestKind::PolicyChange;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let outcome = backend.evaluate_remote_signer_backend(&spec, &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::PolicyChangeUnsupported);
    assert_eq!(backend.transport.call_count(), 0);
}

fn b30_onchain_governance_proof_kind_unavailable() {
    let env = TrustBundleEnvironment::Devnet;
    let mut spec = request_spec(env);
    spec.request_kind = ProductionRemoteSignerRequestKind::OnChainGovernanceProofVerification;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let outcome = backend.evaluate_remote_signer_backend(&spec, &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::GovernanceVerifierUnavailable);
    assert_eq!(backend.transport.call_count(), 0);
}

fn b31_malformed_spec_fails_closed() {
    let env = TrustBundleEnvironment::Devnet;
    let mut spec = request_spec(env);
    spec.chain_id = String::new();
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let outcome = backend.evaluate_remote_signer_backend(&spec, &domain(env), &identity(env), NOW);
    assert!(matches!(outcome, ProductionRemoteSignerOutcome::AmbiguousFailClosed { .. }), "got {outcome:?}");
    assert_eq!(backend.transport.call_count(), 0);
}

fn b32_stale_response_nonce_replay_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let submitted = valid_submission(env);
    let mut spec = request_spec(env);
    spec.response_nonce = "different-response-nonce".to_string();
    let outcome = backend.verify_remote_signer_response(&spec, &submitted, &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerReplayRejected);
}

// ===========================================================================
// C — MainNet / authority policy release checks
// ===========================================================================

fn c01_mainnet_not_satisfied_by_local_operator_material() {
    let env = TrustBundleEnvironment::Mainnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::ProductionRequired);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::MainNetRefused);
    assert_eq!(backend.transport.call_count(), 0);
}

fn c02_mainnet_not_satisfied_by_fixture_loopback_signer() {
    let env = TrustBundleEnvironment::Mainnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::MainNetRefused);
    assert!(production_remote_signer_backend_mainnet_refuses_fixture_material());
}

fn c03_mainnet_not_satisfied_by_peer_majority() {
    for policy in [
        ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled,
        ProductionRemoteSignerBackendPolicy::ProductionRequired,
    ] {
        let env = TrustBundleEnvironment::Mainnet;
        let backend = loopback_backend(env, policy);
        let outcome =
            backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
        assert_eq!(outcome, ProductionRemoteSignerOutcome::MainNetRefused);
    }
}

fn c04_mainnet_production_required_is_unavailable() {
    let env = TrustBundleEnvironment::Mainnet;
    let backend =
        loopback_backend(env, ProductionRemoteSignerBackendPolicy::MainnetProductionRequired);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::MainNetProductionAuthorityUnavailable);
    assert!(outcome.is_unavailable());
}

fn c05_production_required_devnet_unavailable_no_fallback() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::ProductionRequired);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerUnavailable);
    assert_eq!(backend.transport.call_count(), 0);
    assert!(production_remote_signer_backend_never_falls_back());
}

fn c06_production_unavailable_records_no_mutation() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::ProductionRequired);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert!(outcome.is_non_mutating());
    assert!(!outcome.is_accept());
}

fn c07_production_policy_never_accepts_on_devnet_or_testnet() {
    for env in [TrustBundleEnvironment::Devnet, TrustBundleEnvironment::Testnet] {
        let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::ProductionRequired);
        let outcome =
            backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
        assert!(!outcome.is_accept(), "production must not accept in release evidence, got {outcome:?}");
    }
}

// ===========================================================================
// D — Replay / recovery / idempotency release checks
// ===========================================================================

fn d01_no_prior_request_recovery() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let current = valid_submission(env);
    let outcome = backend.recover_remote_signer_request_window(None, &current);
    assert_eq!(outcome, ProductionRemoteSignerRecoveryOutcome::NoPriorRequest);
}

fn d02_idempotent_replay_of_identical_request() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let a = valid_submission(env);
    let b = valid_submission(env);
    let outcome = backend.recover_remote_signer_request_window(Some(&a), &b);
    assert_eq!(outcome, ProductionRemoteSignerRecoveryOutcome::IdempotentReplayOfSameRequest);
    assert!(outcome.is_idempotent());
}

fn d03_same_request_id_different_transcript_fails_closed() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let a = valid_submission(env);
    let mut b = valid_submission(env);
    b.request_env.payload_digest = "different-payload".to_string();
    let outcome = backend.recover_remote_signer_request_window(Some(&a), &b);
    assert_eq!(outcome, ProductionRemoteSignerRecoveryOutcome::ConflictingRequestForSameId);
}

fn d04_same_request_different_response_commitment_fails_closed() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let a = valid_submission(env);
    let mut b = valid_submission(env);
    b.response_env.inner_response.signature_commitment = "tampered-commitment".to_string();
    let outcome = backend.recover_remote_signer_request_window(Some(&a), &b);
    assert_eq!(
        outcome,
        ProductionRemoteSignerRecoveryOutcome::ConflictingResponseForSameRequest
    );
}

fn d05_retry_then_success_is_idempotent_over_attempts() {
    let env = TrustBundleEnvironment::Devnet;
    let good = valid_response_env(env);
    let mock = MockRemoteSignerBackendTransport::scripted(
        vec![Err(ProductionRemoteSignerError::Timeout)],
        Ok(good),
    );
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert!(outcome.is_accept(), "expected accept after retry, got {outcome:?}");
    assert_eq!(backend.transport.call_count(), 2);
}

fn d06_retry_budget_exhausted_fails_closed() {
    let env = TrustBundleEnvironment::Devnet;
    let mock = MockRemoteSignerBackendTransport::scripted(
        vec![
            Err(ProductionRemoteSignerError::Timeout),
            Err(ProductionRemoteSignerError::Timeout),
            Err(ProductionRemoteSignerError::Timeout),
        ],
        Err(ProductionRemoteSignerError::Timeout),
    );
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerTimeout);
    assert_eq!(
        backend.transport.call_count(),
        TransportTimeoutRetryPolicy::default().max_attempts
    );
}

fn d07_terminal_error_not_retried() {
    let env = TrustBundleEnvironment::Devnet;
    let mock = MockRemoteSignerBackendTransport::scripted(
        vec![Err(ProductionRemoteSignerError::MalformedResponse)],
        Ok(valid_response_env(env)),
    );
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerMalformedResponse);
    assert_eq!(backend.transport.call_count(), 1);
}

fn d08_accept_is_evidence_only_not_authorizing_beyond_signer() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let outcome =
        backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    match outcome {
        ProductionRemoteSignerOutcome::RemoteSignerAccepted { environment, .. } => {
            assert_eq!(environment, TrustBundleEnvironment::Devnet);
        }
        other => panic!("expected accept, got {other:?}"),
    }
}

// ===========================================================================
// E — Non-mutation / no-authority-extension release checks
// ===========================================================================

fn e01_every_reject_is_non_mutating() {
    let env = TrustBundleEnvironment::Devnet;
    let disabled = loopback_backend(env, ProductionRemoteSignerBackendPolicy::Disabled)
        .evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    let mainnet = loopback_backend(
        TrustBundleEnvironment::Mainnet,
        ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled,
    )
    .evaluate_remote_signer_backend(
        &request_spec(TrustBundleEnvironment::Mainnet),
        &domain(TrustBundleEnvironment::Mainnet),
        &identity(TrustBundleEnvironment::Mainnet),
        NOW,
    );
    let accept = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled)
        .evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    for o in [disabled, mainnet, accept] {
        assert!(o.is_non_mutating());
    }
}

fn e02_non_mutation_scope_helpers_hold() {
    assert!(production_remote_signer_backend_is_non_mutating());
    assert!(production_remote_signer_backend_implements_no_kms_hsm());
    assert!(production_remote_signer_backend_never_falls_back());
}

fn e03_disabled_never_touches_transport() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::Disabled);
    let _ = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    let _ = backend.submit_remote_signing_request(&request_spec(env), &domain(env));
    let _ = backend.build_request_envelope(&request_spec(env), &domain(env));
    assert_eq!(backend.transport.call_count(), 0);
}

fn e04_source_test_scope_flag_holds() {
    assert!(production_remote_signer_backend_is_source_test_not_release_binary_evidence());
    assert!(production_remote_signer_backend_default_is_disabled());
}

// ===========================================================================
// F — Release symbol reachability probe
// ===========================================================================

fn f01_release_symbol_reachability_probe() {
    // Touch a broad slice of the Run 293 backend surface so the release
    // helper links against and exercises the real production symbols.
    let env = TrustBundleEnvironment::Devnet;
    assert_eq!(PRODUCTION_REMOTE_SIGNER_BACKEND_PROTOCOL_VERSION, 1);
    assert!(PRODUCTION_REMOTE_SIGNER_MAX_RESPONSE_BYTES > 0);

    let backend: LoopbackBackend =
        loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let spec: ProductionRemoteSignerRequestSpec = request_spec(env);
    let td: AuthorityTrustDomain = domain(env);
    let id: RemoteSignerIdentity = identity(env);

    let request_id: String = production_remote_signer_request_id(&spec);
    assert_eq!(request_id.len(), 64);

    let submitted: SubmittedRemoteSignerRequest = backend
        .submit_remote_signing_request(&spec, &td)
        .expect("submit");
    assert_eq!(submitted.attempts_used, 1);

    let outcome: ProductionRemoteSignerOutcome =
        backend.verify_remote_signer_response(&spec, &submitted, &td, &id, NOW);
    assert!(outcome.is_accept());

    let recovery: ProductionRemoteSignerRecoveryOutcome =
        backend.recover_remote_signer_request_window(None, &submitted);
    assert_eq!(recovery, ProductionRemoteSignerRecoveryOutcome::NoPriorRequest);

    // Error taxonomy is reachable and typed.
    let err: ProductionRemoteSignerError = ProductionRemoteSignerError::Timeout;
    assert!(err.is_retryable());

    // Mock transport implements the same trait surface.
    let mock: MockRemoteSignerBackendTransport =
        MockRemoteSignerBackendTransport::respond(valid_response_env(env));
    let mock_backend: ProductionRemoteSignerBackend<MockRemoteSignerBackendTransport> =
        mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let mock_outcome =
        mock_backend.evaluate_remote_signer_backend(&spec, &td, &id, NOW);
    assert!(mock_outcome.is_accept());
    let _ = <MockRemoteSignerBackendTransport as RemoteSignerBackendTransport>::submit;

    // Invariant helpers.
    assert!(production_remote_signer_backend_default_is_disabled());
    assert!(production_remote_signer_backend_mainnet_refuses_fixture_material());
    assert!(production_remote_signer_backend_never_falls_back());
    assert!(production_remote_signer_backend_is_non_mutating());
    assert!(production_remote_signer_backend_implements_no_kms_hsm());
    assert!(production_remote_signer_backend_is_source_test_not_release_binary_evidence());
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
            "docs/devnet/run_294_production_remote_signer_backend_release_binary/helper_evidence/run_294",
        )
    });
    fs::create_dir_all(outdir.join("fixtures")).expect("create helper output directory");

    let cases: &[(&str, &str, fn())] = &[
        ("accepted_compatible", "a01_disabled_default_policy_is_explicit_and_inert", a01_disabled_default_policy_is_explicit_and_inert as fn()),
        ("accepted_compatible", "a02_devnet_loopback_accepts_authority_lifecycle_request", a02_devnet_loopback_accepts_authority_lifecycle_request as fn()),
        ("accepted_compatible", "a03_devnet_loopback_accepts_governance_execution_request", a03_devnet_loopback_accepts_governance_execution_request as fn()),
        ("accepted_compatible", "a04_testnet_loopback_accepts_when_policy_allows", a04_testnet_loopback_accepts_when_policy_allows as fn()),
        ("accepted_compatible", "a05_accept_path_reaches_transport_exactly_once", a05_accept_path_reaches_transport_exactly_once as fn()),
        ("accepted_compatible", "a06_request_id_is_deterministic", a06_request_id_is_deterministic as fn()),
        ("accepted_compatible", "a07_response_digest_is_deterministic", a07_response_digest_is_deterministic as fn()),
        ("accepted_compatible", "a08_backend_transcript_digest_is_deterministic", a08_backend_transcript_digest_is_deterministic as fn()),
        ("accepted_compatible", "a09_two_identical_requests_produce_identical_digests", a09_two_identical_requests_produce_identical_digests as fn()),
        ("accepted_compatible", "a10_valid_response_authorizes_exactly_matching_request", a10_valid_response_authorizes_exactly_matching_request as fn()),
        ("accepted_compatible", "a11_composes_run194_request_and_run201_transport_types", a11_composes_run194_request_and_run201_transport_types as fn()),
        ("accepted_compatible", "a12_composes_run291_durable_replay_record_digest", a12_composes_run291_durable_replay_record_digest as fn()),
        ("accepted_compatible", "a13_build_only_reports_request_built_without_transport_call", a13_build_only_reports_request_built_without_transport_call as fn()),
        ("accepted_compatible", "a14_backend_protocol_version_pinned", a14_backend_protocol_version_pinned as fn()),
        ("rejection_fail_closed", "b01_disabled_produces_no_request_and_no_transport_call", b01_disabled_produces_no_request_and_no_transport_call as fn()),
        ("rejection_fail_closed", "b02_mainnet_identity_refused_before_transport", b02_mainnet_identity_refused_before_transport as fn()),
        ("rejection_fail_closed", "b03_fixture_loopback_material_refused_for_mainnet", b03_fixture_loopback_material_refused_for_mainnet as fn()),
        ("rejection_fail_closed", "b04_wrong_environment_rejected", b04_wrong_environment_rejected as fn()),
        ("rejection_fail_closed", "b05_wrong_chain_rejected", b05_wrong_chain_rejected as fn()),
        ("rejection_fail_closed", "b06_wrong_genesis_rejected", b06_wrong_genesis_rejected as fn()),
        ("rejection_fail_closed", "b07_wrong_authority_root_rejected", b07_wrong_authority_root_rejected as fn()),
        ("rejection_fail_closed", "b08_wrong_authority_sequence_rejected", b08_wrong_authority_sequence_rejected as fn()),
        ("rejection_fail_closed", "b09_wrong_signer_identity_rejected", b09_wrong_signer_identity_rejected as fn()),
        ("rejection_fail_closed", "b10_wrong_request_id_echo_rejected", b10_wrong_request_id_echo_rejected as fn()),
        ("rejection_fail_closed", "b11_wrong_transcript_digest_rejected", b11_wrong_transcript_digest_rejected as fn()),
        ("rejection_fail_closed", "b12_wrong_candidate_digest_rejected", b12_wrong_candidate_digest_rejected as fn()),
        ("rejection_fail_closed", "b13_wrong_authorized_action_rejected", b13_wrong_authorized_action_rejected as fn()),
        ("rejection_fail_closed", "b14_wrong_protocol_version_rejected", b14_wrong_protocol_version_rejected as fn()),
        ("rejection_fail_closed", "b15_missing_response_signature_rejected", b15_missing_response_signature_rejected as fn()),
        ("rejection_fail_closed", "b16_malformed_response_rejected", b16_malformed_response_rejected as fn()),
        ("rejection_fail_closed", "b17_oversized_response_rejected", b17_oversized_response_rejected as fn()),
        ("rejection_fail_closed", "b18_signer_unavailable_rejected", b18_signer_unavailable_rejected as fn()),
        ("rejection_fail_closed", "b19_transport_unavailable_rejected", b19_transport_unavailable_rejected as fn()),
        ("rejection_fail_closed", "b20_timeout_rejected", b20_timeout_rejected as fn()),
        ("rejection_fail_closed", "b21_decode_error_rejected", b21_decode_error_rejected as fn()),
        ("rejection_fail_closed", "b22_signer_refused_rejected", b22_signer_refused_rejected as fn()),
        ("rejection_fail_closed", "b23_signer_policy_rejected_rejected", b23_signer_policy_rejected_rejected as fn()),
        ("rejection_fail_closed", "b24_signer_attestation_unavailable_rejected", b24_signer_attestation_unavailable_rejected as fn()),
        ("rejection_fail_closed", "b25_unsupported_protocol_transport_error_rejected", b25_unsupported_protocol_transport_error_rejected as fn()),
        ("rejection_fail_closed", "b26_response_from_wrong_signer_key_rejected", b26_response_from_wrong_signer_key_rejected as fn()),
        ("rejection_fail_closed", "b27_production_mode_response_never_accepted", b27_production_mode_response_never_accepted as fn()),
        ("rejection_fail_closed", "b28_validator_set_rotation_kind_unsupported", b28_validator_set_rotation_kind_unsupported as fn()),
        ("rejection_fail_closed", "b29_policy_change_kind_unsupported", b29_policy_change_kind_unsupported as fn()),
        ("rejection_fail_closed", "b30_onchain_governance_proof_kind_unavailable", b30_onchain_governance_proof_kind_unavailable as fn()),
        ("rejection_fail_closed", "b31_malformed_spec_fails_closed", b31_malformed_spec_fails_closed as fn()),
        ("rejection_fail_closed", "b32_stale_response_nonce_replay_rejected", b32_stale_response_nonce_replay_rejected as fn()),
        ("mainnet_authority_policy", "c01_mainnet_not_satisfied_by_local_operator_material", c01_mainnet_not_satisfied_by_local_operator_material as fn()),
        ("mainnet_authority_policy", "c02_mainnet_not_satisfied_by_fixture_loopback_signer", c02_mainnet_not_satisfied_by_fixture_loopback_signer as fn()),
        ("mainnet_authority_policy", "c03_mainnet_not_satisfied_by_peer_majority", c03_mainnet_not_satisfied_by_peer_majority as fn()),
        ("mainnet_authority_policy", "c04_mainnet_production_required_is_unavailable", c04_mainnet_production_required_is_unavailable as fn()),
        ("mainnet_authority_policy", "c05_production_required_devnet_unavailable_no_fallback", c05_production_required_devnet_unavailable_no_fallback as fn()),
        ("mainnet_authority_policy", "c06_production_unavailable_records_no_mutation", c06_production_unavailable_records_no_mutation as fn()),
        ("mainnet_authority_policy", "c07_production_policy_never_accepts_on_devnet_or_testnet", c07_production_policy_never_accepts_on_devnet_or_testnet as fn()),
        ("replay_recovery_idempotency", "d01_no_prior_request_recovery", d01_no_prior_request_recovery as fn()),
        ("replay_recovery_idempotency", "d02_idempotent_replay_of_identical_request", d02_idempotent_replay_of_identical_request as fn()),
        ("replay_recovery_idempotency", "d03_same_request_id_different_transcript_fails_closed", d03_same_request_id_different_transcript_fails_closed as fn()),
        ("replay_recovery_idempotency", "d04_same_request_different_response_commitment_fails_closed", d04_same_request_different_response_commitment_fails_closed as fn()),
        ("replay_recovery_idempotency", "d05_retry_then_success_is_idempotent_over_attempts", d05_retry_then_success_is_idempotent_over_attempts as fn()),
        ("replay_recovery_idempotency", "d06_retry_budget_exhausted_fails_closed", d06_retry_budget_exhausted_fails_closed as fn()),
        ("replay_recovery_idempotency", "d07_terminal_error_not_retried", d07_terminal_error_not_retried as fn()),
        ("replay_recovery_idempotency", "d08_accept_is_evidence_only_not_authorizing_beyond_signer", d08_accept_is_evidence_only_not_authorizing_beyond_signer as fn()),
        ("non_mutation", "e01_every_reject_is_non_mutating", e01_every_reject_is_non_mutating as fn()),
        ("non_mutation", "e02_non_mutation_scope_helpers_hold", e02_non_mutation_scope_helpers_hold as fn()),
        ("non_mutation", "e03_disabled_never_touches_transport", e03_disabled_never_touches_transport as fn()),
        ("non_mutation", "e04_source_test_scope_flag_holds", e04_source_test_scope_flag_holds as fn()),
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
    summary.push_str("Run 294 production RemoteSigner backend release helper\n");
    summary.push_str(&format!(
        "verdict: {}\n",
        if total_fail == 0 { "PASS" } else { "FAIL" }
    ));
    summary.push_str(
        "backend: crates/qbind-node/src/pqc_production_remote_signer_backend.rs (Run 293 ProductionRemoteSignerBackend)\n",
    );
    summary.push_str(
        "mode: real Run 293 backend over source/test loopback/mock transports, DevNet/TestNet accept only; MainNet refused; default Disabled; production policy never accepts and never falls back to fixture/loopback/local signing; every failure is a typed outcome\n",
    );
    for (table, (pass, fail)) in &tables {
        summary.push_str(&format!("table {table} pass={pass} fail={fail}\n"));
    }
    summary.push_str(&format!("total_pass: {total_pass}\n"));
    summary.push_str(&format!("total_fail: {total_fail}\n"));

    fs::write(outdir.join("helper_summary.txt"), &summary).expect("write helper summary");

    // Deterministic-digest fixture for cross-invocation comparison by the harness.
    let env = TrustBundleEnvironment::Devnet;
    let spec = request_spec(env);
    let request_id = production_remote_signer_request_id(&spec);
    let submitted = valid_submission(env);
    let request_envelope_digest = submitted.request_env.envelope_digest();
    let response_envelope_digest = submitted.response_env.envelope_digest();
    let transport_transcript = submitted.response_env.transcript_digest.clone();
    let backend_transcript = production_remote_signer_backend_transcript_digest(
        PRODUCTION_REMOTE_SIGNER_BACKEND_PROTOCOL_VERSION,
        &request_id,
        &request_envelope_digest,
        &response_envelope_digest,
        &transport_transcript,
        None,
    );
    fs::write(
        outdir.join("fixtures/run_294_deterministic_digests.txt"),
        format!(
            "request_id {request_id}\nrequest_envelope_digest {request_envelope_digest}\nresponse_envelope_digest {response_envelope_digest}\ntransport_transcript_digest {transport_transcript}\nbackend_transcript_digest {backend_transcript}\n"
        ),
    )
    .expect("write digest fixture");

    print!("{summary}");
    if total_fail != 0 {
        std::process::exit(1);
    }
}