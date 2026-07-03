//! Run 293 — source/test production RemoteSigner backend integration
//! tests.
//!
//! Source/test only. Run 293 does **not** capture release-binary
//! evidence; release-binary evidence for the production RemoteSigner
//! backend is deferred to **Run 294**. The tests cover:
//!
//! * A. accepted / compatible source-test evidence;
//! * B. rejection / fail-closed paths;
//! * C. MainNet / authority policy refusal;
//! * D. non-mutation invariants (the backend surfaces are pure);
//! * E. replay / recovery / idempotency;
//! * F. C4/C5 taxonomy status.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_293.md`.

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
    FixtureLoopbackRemoteSignerTransport, RemoteSignerTransport, RemoteSignerTransportConfig,
    RemoteSignerTransportResponseEnvelope, SimulatedTransportFault, TransportTimeoutRetryPolicy,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared fixtures
// ===========================================================================

const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT_FP: &str = "1111111111111111111111111111111111111111";
const CHAIN_ID: &str = "0000000000000001";
const GENESIS_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const CUSTODY_ATTEST_DIGEST: &str = "custody-att-digest-293";
const CUSTODY_KEY_ID: &str = "custody-key-id-293";
const SIGNER_ID: &str = "remote-signer-293";
const SIGNER_PUBID: &str = "remote-signer-pubid-293";
const ATTEST_DIGEST: &str = "remote-signer-attest-293";
const REQ_NONCE: &str = "req-nonce-293";
const RESP_NONCE: &str = "resp-nonce-293";
const TRANSPORT_NONCE: &str = "transport-nonce-293";
const ENDPOINT: &str = "qbind-signer://signer.example:8443";
const SIGNER_IDENTITY_DIGEST: &str = "signer-identity-digest-293";
const TRANSPORT_ATTEST: &str = "transport-attest-293";
const PAYLOAD_DIGEST: &str = "transport-payload-digest-293";
const DURABLE_REPLAY_DIGEST: &str = "durable-replay-record-digest-293";
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

/// Build a valid response envelope for `env` by driving the fixture
/// transport with the backend's own request envelope.
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
// A. Accepted / compatible
// ===========================================================================

#[test]
fn a01_disabled_default_policy_is_explicit_and_inert() {
    assert!(production_remote_signer_backend_default_is_disabled());
    let backend = loopback_backend(TrustBundleEnvironment::Devnet, ProductionRemoteSignerBackendPolicy::Disabled);
    let outcome = backend.evaluate_remote_signer_backend(
        &request_spec(TrustBundleEnvironment::Devnet),
        &domain(TrustBundleEnvironment::Devnet),
        &identity(TrustBundleEnvironment::Devnet),
        NOW,
    );
    assert_eq!(outcome, ProductionRemoteSignerOutcome::DisabledNoRequest);
    // The transport was never invoked.
    assert_eq!(backend.transport.call_count(), 0);
}

#[test]
fn a02_devnet_loopback_accepts_valid_request_response() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let outcome = backend.evaluate_remote_signer_backend(
        &request_spec(env),
        &domain(env),
        &identity(env),
        NOW,
    );
    assert!(outcome.is_accept(), "expected accept, got {outcome:?}");
    assert_eq!(backend.transport.call_count(), 1);
}

#[test]
fn a03_testnet_loopback_accepts_when_policy_allows() {
    let env = TrustBundleEnvironment::Testnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let outcome = backend.evaluate_remote_signer_backend(
        &request_spec(env),
        &domain(env),
        &identity(env),
        NOW,
    );
    assert!(outcome.is_accept(), "expected accept, got {outcome:?}");
}

#[test]
fn a04_request_digest_is_deterministic() {
    let env = TrustBundleEnvironment::Devnet;
    let a = request_spec(env).build_inner_request().canonical_digest();
    let b = request_spec(env).build_inner_request().canonical_digest();
    assert_eq!(a, b);
    assert_eq!(a.len(), 64);
}

#[test]
fn a05_request_id_is_deterministic() {
    let env = TrustBundleEnvironment::Devnet;
    let a = production_remote_signer_request_id(&request_spec(env));
    let b = production_remote_signer_request_id(&request_spec(env));
    assert_eq!(a, b);
    assert_eq!(a.len(), 64);
}

#[test]
fn a06_response_digest_is_deterministic() {
    let env = TrustBundleEnvironment::Devnet;
    let a = valid_response_env(env).canonical_response_digest;
    let b = valid_response_env(env).canonical_response_digest;
    assert_eq!(a, b);
}

#[test]
fn a07_transcript_digest_is_deterministic() {
    let a = production_remote_signer_backend_transcript_digest(1, "rid", "req", "resp", "tt", None);
    let b = production_remote_signer_backend_transcript_digest(1, "rid", "req", "resp", "tt", None);
    assert_eq!(a, b);
    assert_eq!(a.len(), 64);
}

#[test]
fn a08_two_identical_requests_produce_identical_digests() {
    let env = TrustBundleEnvironment::Devnet;
    let s1 = valid_submission(env);
    let s2 = valid_submission(env);
    assert_eq!(s1.request_id, s2.request_id);
    assert_eq!(
        s1.request_env.envelope_digest(),
        s2.request_env.envelope_digest()
    );
}

#[test]
fn a09_valid_response_authorizes_exactly_matching_request() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let submitted = valid_submission(env);
    let outcome =
        backend.verify_remote_signer_response(&request_spec(env), &submitted, &domain(env), &identity(env), NOW);
    match outcome {
        ProductionRemoteSignerOutcome::RemoteSignerAccepted { request_id, .. } => {
            assert_eq!(request_id, submitted.request_id);
        }
        other => panic!("expected accept, got {other:?}"),
    }
}

#[test]
fn a10_backend_composes_with_run194_request_and_run201_transport_types() {
    // The backend derives Run 194 RemoteSignerRequest and Run 201 request
    // envelope; a valid submission exposes both, bound to the same digest.
    let env = TrustBundleEnvironment::Devnet;
    let submitted = valid_submission(env);
    assert_eq!(
        submitted.request_env.canonical_request_digest,
        submitted.request_env.inner_request.canonical_digest()
    );
    assert_eq!(
        submitted.response_env.request_id_echo,
        submitted.request_env.request_id
    );
}

#[test]
fn a11_backend_composes_with_run291_durable_replay_record_digest() {
    // When a durable replay record digest is present it is bound into the
    // request id and backend transcript, changing both deterministically.
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

#[test]
fn a12_build_only_reports_request_built_without_transport_call() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let built = backend
        .build_request_envelope(&request_spec(env), &domain(env))
        .expect("request built");
    assert_eq!(built.request_id, production_remote_signer_request_id(&request_spec(env)));
    // build_request_envelope must not invoke the transport.
    assert_eq!(backend.transport.call_count(), 0);
}

#[test]
fn a13_governance_execution_signing_kind_is_supported() {
    let env = TrustBundleEnvironment::Devnet;
    let mut spec = request_spec(env);
    spec.request_kind = ProductionRemoteSignerRequestKind::GovernanceExecutionSigning;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    // Note: the request id/kind change but the loopback still echoes the
    // request; the accept path still holds because the transport verifier
    // does not inspect the backend request kind.
    let outcome = backend.evaluate_remote_signer_backend(&spec, &domain(env), &identity(env), NOW);
    assert!(outcome.is_accept(), "expected accept, got {outcome:?}");
}

#[test]
fn a14_backend_protocol_version_pinned() {
    assert_eq!(PRODUCTION_REMOTE_SIGNER_BACKEND_PROTOCOL_VERSION, 1);
    assert_eq!(
        backend_config(TrustBundleEnvironment::Devnet).protocol_version,
        1
    );
}

// ===========================================================================
// B. Rejection / fail-closed
// ===========================================================================

#[test]
fn b01_disabled_produces_no_request_and_no_transport_call() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::Disabled);
    let built = backend.build_request_envelope(&request_spec(env), &domain(env));
    assert_eq!(built.err(), Some(ProductionRemoteSignerOutcome::DisabledNoRequest));
    assert_eq!(backend.transport.call_count(), 0);
}

#[test]
fn b02_mainnet_identity_refused() {
    let env = TrustBundleEnvironment::Mainnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let outcome = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::MainNetRefused);
    assert_eq!(backend.transport.call_count(), 0);
}

#[test]
fn b03_fixture_loopback_material_refused_for_mainnet_production_policy() {
    let env = TrustBundleEnvironment::Mainnet;
    let backend =
        loopback_backend(env, ProductionRemoteSignerBackendPolicy::MainnetProductionRequired);
    let outcome = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(
        outcome,
        ProductionRemoteSignerOutcome::MainNetProductionAuthorityUnavailable
    );
    assert_eq!(backend.transport.call_count(), 0);
}

#[test]
fn b04_wrong_environment_rejected() {
    // Response built for Devnet but verified against a Testnet trust domain.
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

#[test]
fn b05_wrong_chain_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let submitted = valid_submission(env);
    let mut wrong = domain(env);
    wrong.chain_id = "00000000000000ff".to_string();
    let outcome = backend.verify_remote_signer_response(&request_spec(env), &submitted, &wrong, &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerDomainMismatch);
}

#[test]
fn b06_wrong_genesis_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let submitted = valid_submission(env);
    let mut wrong = domain(env);
    wrong.genesis_hash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string();
    let outcome = backend.verify_remote_signer_response(&request_spec(env), &submitted, &wrong, &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerDomainMismatch);
}

#[test]
fn b07_wrong_authority_root_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let submitted = valid_submission(env);
    let mut wrong = domain(env);
    wrong.authority_root_fingerprint = "9999999999999999999999999999999999999999".to_string();
    let outcome = backend.verify_remote_signer_response(&request_spec(env), &submitted, &wrong, &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerDomainMismatch);
}

#[test]
fn b08_wrong_authority_sequence_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let submitted = valid_submission(env);
    // Expected sequence differs from the request's bound sequence.
    let mut spec = request_spec(env);
    spec.authority_domain_sequence = 3;
    let outcome = backend.verify_remote_signer_response(&spec, &submitted, &domain(env), &identity(env), NOW);
    // The submitted request bound sequence 2; expectations now expect 3.
    assert!(
        matches!(
            outcome,
            ProductionRemoteSignerOutcome::RemoteSignerRejected { .. }
                | ProductionRemoteSignerOutcome::RemoteSignerRequestIdMismatch
        ),
        "got {outcome:?}"
    );
}

#[test]
fn b09_wrong_signer_identity_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let submitted = valid_submission(env);
    let mut wrong_identity = identity(env);
    wrong_identity.signer_id = "other-signer".to_string();
    let outcome = backend.verify_remote_signer_response(&request_spec(env), &submitted, &domain(env), &wrong_identity, NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerWrongSigner);
}

#[test]
fn b10_wrong_request_id_echo_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let mut submitted = valid_submission(env);
    submitted.response_env.request_id_echo = "tampered-request-id".to_string();
    let outcome = backend.verify_remote_signer_response(&request_spec(env), &submitted, &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerRequestIdMismatch);
}

#[test]
fn b11_wrong_transcript_digest_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let mut submitted = valid_submission(env);
    submitted.response_env.transcript_digest = "0".repeat(64);
    let outcome = backend.verify_remote_signer_response(&request_spec(env), &submitted, &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerTranscriptMismatch);
}

#[test]
fn b12_wrong_candidate_digest_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let submitted = valid_submission(env);
    let mut spec = request_spec(env);
    spec.candidate_digest = "3".repeat(64);
    let outcome = backend.verify_remote_signer_response(&spec, &submitted, &domain(env), &identity(env), NOW);
    // Expectation candidate digest now differs from the bound request.
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

#[test]
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

#[test]
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

#[test]
fn b15_missing_response_signature_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let mut submitted = valid_submission(env);
    submitted.response_env.inner_response.signature_commitment =
        REMOTE_SIGNER_INVALID_SIGNATURE_SENTINEL.to_string();
    let outcome = backend.verify_remote_signer_response(&request_spec(env), &submitted, &domain(env), &identity(env), NOW);
    // Tampering the inner signature breaks the canonical response digest
    // binding first (transcript mismatch), then the inner signature check.
    assert!(outcome.is_non_mutating());
    assert!(!outcome.is_accept(), "got {outcome:?}");
}

#[test]
fn b16_malformed_response_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let mut submitted = valid_submission(env);
    submitted.response_env.signer_id = String::new();
    let outcome = backend.verify_remote_signer_response(&request_spec(env), &submitted, &domain(env), &identity(env), NOW);
    assert!(!outcome.is_accept(), "got {outcome:?}");
}

#[test]
fn b17_oversized_response_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut big = valid_response_env(env);
    big.response_commitment = "x".repeat(PRODUCTION_REMOTE_SIGNER_MAX_RESPONSE_BYTES + 1);
    let mock = MockRemoteSignerBackendTransport::respond(big);
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerMalformedResponse);
}

#[test]
fn b18_signer_unavailable_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mock = MockRemoteSignerBackendTransport::always_fail(ProductionRemoteSignerError::SignerUnavailable);
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerUnavailable);
}

#[test]
fn b19_transport_unavailable_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mock = MockRemoteSignerBackendTransport::always_fail(ProductionRemoteSignerError::EndpointUnavailable);
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerUnavailable);
    // Endpoint unavailable is retryable → exhausts all attempts.
    assert_eq!(backend.transport.call_count(), TransportTimeoutRetryPolicy::default().max_attempts);
}

#[test]
fn b20_timeout_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mock = MockRemoteSignerBackendTransport::always_fail(ProductionRemoteSignerError::Timeout);
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerTimeout);
}

#[test]
fn b21_decode_error_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mock = MockRemoteSignerBackendTransport::always_fail(ProductionRemoteSignerError::TransportDecodeError);
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerTransportDecodeFailed);
    // Decode error is terminal (non-retryable) → single attempt.
    assert_eq!(backend.transport.call_count(), 1);
}

#[test]
fn b22_signer_refused_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mock = MockRemoteSignerBackendTransport::always_fail(ProductionRemoteSignerError::SignerRefused);
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert!(matches!(outcome, ProductionRemoteSignerOutcome::RemoteSignerRejected { .. }), "got {outcome:?}");
}

#[test]
fn b23_signer_policy_rejected_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mock = MockRemoteSignerBackendTransport::always_fail(ProductionRemoteSignerError::SignerPolicyRejected);
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert!(matches!(outcome, ProductionRemoteSignerOutcome::RemoteSignerRejected { .. }), "got {outcome:?}");
}

#[test]
fn b24_signer_attestation_unavailable_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mock = MockRemoteSignerBackendTransport::always_fail(ProductionRemoteSignerError::SignerAttestationUnavailable);
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerAttestationUnavailable);
}

#[test]
fn b25_unsupported_protocol_transport_error_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mock = MockRemoteSignerBackendTransport::always_fail(
        ProductionRemoteSignerError::UnsupportedProtocolVersion { version: 7 },
    );
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(
        outcome,
        ProductionRemoteSignerOutcome::RemoteSignerUnsupportedProtocol { version: 7 }
    );
}

#[test]
fn b26_response_from_wrong_signer_key_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let mut submitted = valid_submission(env);
    submitted.response_env.custody_key_id = "other-custody-key".to_string();
    submitted.response_env.inner_response.custody_key_id = "other-custody-key".to_string();
    let outcome = backend.verify_remote_signer_response(&request_spec(env), &submitted, &domain(env), &identity(env), NOW);
    assert!(!outcome.is_accept(), "got {outcome:?}");
}

#[test]
fn b27_production_mode_response_never_accepted() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let mut submitted = valid_submission(env);
    submitted.response_env.inner_response.signer_mode = RemoteSignerMode::Production;
    let outcome = backend.verify_remote_signer_response(&request_spec(env), &submitted, &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerUnavailable);
}

#[test]
fn b28_validator_set_rotation_kind_unsupported() {
    let env = TrustBundleEnvironment::Devnet;
    let mut spec = request_spec(env);
    spec.request_kind = ProductionRemoteSignerRequestKind::ValidatorSetRotation;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let outcome = backend.evaluate_remote_signer_backend(&spec, &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::ValidatorSetRotationUnsupported);
    assert_eq!(backend.transport.call_count(), 0);
}

#[test]
fn b29_policy_change_kind_unsupported() {
    let env = TrustBundleEnvironment::Devnet;
    let mut spec = request_spec(env);
    spec.request_kind = ProductionRemoteSignerRequestKind::PolicyChange;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let outcome = backend.evaluate_remote_signer_backend(&spec, &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::PolicyChangeUnsupported);
}

#[test]
fn b30_onchain_governance_proof_kind_unavailable() {
    let env = TrustBundleEnvironment::Devnet;
    let mut spec = request_spec(env);
    spec.request_kind = ProductionRemoteSignerRequestKind::OnChainGovernanceProofVerification;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let outcome = backend.evaluate_remote_signer_backend(&spec, &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::GovernanceVerifierUnavailable);
}

#[test]
fn b31_malformed_spec_fails_closed() {
    let env = TrustBundleEnvironment::Devnet;
    let mut spec = request_spec(env);
    spec.chain_id = String::new();
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let outcome = backend.evaluate_remote_signer_backend(&spec, &domain(env), &identity(env), NOW);
    assert!(matches!(outcome, ProductionRemoteSignerOutcome::AmbiguousFailClosed { .. }), "got {outcome:?}");
    assert_eq!(backend.transport.call_count(), 0);
}

#[test]
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
// C. MainNet / authority policy
// ===========================================================================

#[test]
fn c01_mainnet_not_satisfied_by_local_operator_material() {
    // A production-required (non-mainnet) policy on a MainNet domain is
    // refused before any transport call.
    let env = TrustBundleEnvironment::Mainnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::ProductionRequired);
    let outcome = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::MainNetRefused);
}

#[test]
fn c02_mainnet_not_satisfied_by_fixture_loopback_signer() {
    let env = TrustBundleEnvironment::Mainnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let outcome = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::MainNetRefused);
    assert!(production_remote_signer_backend_mainnet_refuses_fixture_material());
}

#[test]
fn c03_mainnet_production_required_is_unavailable() {
    let env = TrustBundleEnvironment::Mainnet;
    let backend =
        loopback_backend(env, ProductionRemoteSignerBackendPolicy::MainnetProductionRequired);
    let outcome = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::MainNetProductionAuthorityUnavailable);
}

#[test]
fn c04_production_required_devnet_unavailable_no_fallback() {
    // Production policy on DevNet has no real backend → unavailable, and
    // it must NOT fall back to the fixture loopback transport.
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::ProductionRequired);
    let outcome = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerUnavailable);
    assert_eq!(backend.transport.call_count(), 0);
    assert!(production_remote_signer_backend_never_falls_back());
}

#[test]
fn c05_production_unavailable_records_no_mutation() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::ProductionRequired);
    let outcome = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert!(outcome.is_non_mutating());
    assert!(!outcome.is_accept());
}

#[test]
fn c06_mainnet_cannot_be_satisfied_by_peer_majority() {
    // There is no peer-majority path into the backend at all; a MainNet
    // domain is refused regardless of policy short of production authority.
    for policy in [
        ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled,
        ProductionRemoteSignerBackendPolicy::ProductionRequired,
    ] {
        let env = TrustBundleEnvironment::Mainnet;
        let backend = loopback_backend(env, policy);
        let outcome = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
        assert_eq!(outcome, ProductionRemoteSignerOutcome::MainNetRefused);
    }
}

// ===========================================================================
// D. Non-mutation
// ===========================================================================

#[test]
fn d01_every_reject_is_non_mutating() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    // A representative set of rejects.
    let disabled = loopback_backend(env, ProductionRemoteSignerBackendPolicy::Disabled)
        .evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    let mainnet = loopback_backend(TrustBundleEnvironment::Mainnet, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled)
        .evaluate_remote_signer_backend(&request_spec(TrustBundleEnvironment::Mainnet), &domain(TrustBundleEnvironment::Mainnet), &identity(TrustBundleEnvironment::Mainnet), NOW);
    let accept = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    for o in [disabled, mainnet, accept] {
        assert!(o.is_non_mutating());
    }
}

#[test]
fn d02_non_mutation_scope_helpers_hold() {
    assert!(production_remote_signer_backend_is_non_mutating());
    assert!(production_remote_signer_backend_implements_no_kms_hsm());
    assert!(production_remote_signer_backend_never_falls_back());
}

#[test]
fn d03_disabled_never_touches_transport() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::Disabled);
    let _ = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    let _ = backend.submit_remote_signing_request(&request_spec(env), &domain(env));
    let _ = backend.build_request_envelope(&request_spec(env), &domain(env));
    assert_eq!(backend.transport.call_count(), 0);
}

#[test]
fn d04_accept_is_evidence_only_not_authorizing_beyond_signer() {
    // Acceptance carries only signer id / environment / request id /
    // transcript — no mutation payload, no apply.
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let outcome = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    match outcome {
        ProductionRemoteSignerOutcome::RemoteSignerAccepted { environment, .. } => {
            assert_eq!(environment, TrustBundleEnvironment::Devnet);
        }
        other => panic!("expected accept, got {other:?}"),
    }
}

// ===========================================================================
// E. Replay / recovery / idempotency
// ===========================================================================

#[test]
fn e01_no_prior_request_recovery() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let current = valid_submission(env);
    let outcome = backend.recover_remote_signer_request_window(None, &current);
    assert_eq!(outcome, ProductionRemoteSignerRecoveryOutcome::NoPriorRequest);
}

#[test]
fn e02_idempotent_replay_of_identical_request() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let a = valid_submission(env);
    let b = valid_submission(env);
    let outcome = backend.recover_remote_signer_request_window(Some(&a), &b);
    assert_eq!(outcome, ProductionRemoteSignerRecoveryOutcome::IdempotentReplayOfSameRequest);
    assert!(outcome.is_idempotent());
}

#[test]
fn e03_same_request_id_different_transcript_fails_closed() {
    let env = TrustBundleEnvironment::Devnet;
    let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled);
    let a = valid_submission(env);
    let mut b = valid_submission(env);
    // Keep the same request id but mutate the request envelope framing.
    b.request_env.payload_digest = "different-payload".to_string();
    let outcome = backend.recover_remote_signer_request_window(Some(&a), &b);
    assert_eq!(outcome, ProductionRemoteSignerRecoveryOutcome::ConflictingRequestForSameId);
}

#[test]
fn e04_same_request_different_response_commitment_fails_closed() {
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

#[test]
fn e05_retry_then_success_is_idempotent_over_attempts() {
    // A retryable timeout on attempt 1, then a valid response on attempt 2.
    let env = TrustBundleEnvironment::Devnet;
    let good = valid_response_env(env);
    let mock = MockRemoteSignerBackendTransport::scripted(
        vec![Err(ProductionRemoteSignerError::Timeout)],
        Ok(good),
    );
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert!(outcome.is_accept(), "expected accept after retry, got {outcome:?}");
    assert_eq!(backend.transport.call_count(), 2);
}

#[test]
fn e06_retry_budget_exhausted_fails_closed() {
    let env = TrustBundleEnvironment::Devnet;
    // Two timeouts then a good response, but default max_attempts is 3, so
    // it should succeed on the third. Use a policy with only timeouts to
    // exhaust: script 3 timeouts.
    let mock = MockRemoteSignerBackendTransport::scripted(
        vec![
            Err(ProductionRemoteSignerError::Timeout),
            Err(ProductionRemoteSignerError::Timeout),
            Err(ProductionRemoteSignerError::Timeout),
        ],
        Err(ProductionRemoteSignerError::Timeout),
    );
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerTimeout);
    assert_eq!(backend.transport.call_count(), TransportTimeoutRetryPolicy::default().max_attempts);
}

#[test]
fn e07_terminal_error_not_retried() {
    let env = TrustBundleEnvironment::Devnet;
    let mock = MockRemoteSignerBackendTransport::scripted(
        vec![Err(ProductionRemoteSignerError::MalformedResponse)],
        Ok(valid_response_env(env)),
    );
    let backend = mock_backend(env, ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled, mock);
    let outcome = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
    assert_eq!(outcome, ProductionRemoteSignerOutcome::RemoteSignerMalformedResponse);
    assert_eq!(backend.transport.call_count(), 1);
}

// ===========================================================================
// F. C4/C5 taxonomy
// ===========================================================================

#[test]
fn f01_run293_is_source_test_not_release_binary_evidence() {
    assert!(production_remote_signer_backend_is_source_test_not_release_binary_evidence());
}

#[test]
fn f02_default_disabled_preserves_conservative_posture() {
    assert!(production_remote_signer_backend_default_is_disabled());
}

#[test]
fn f03_backend_implements_no_kms_hsm_custody() {
    assert!(production_remote_signer_backend_implements_no_kms_hsm());
}

#[test]
fn f04_backend_is_non_mutating_no_run070() {
    assert!(production_remote_signer_backend_is_non_mutating());
}

#[test]
fn f05_backend_never_falls_back_to_fixture_when_production() {
    assert!(production_remote_signer_backend_never_falls_back());
    // A production policy never produces an accept in Run 293.
    for env in [TrustBundleEnvironment::Devnet, TrustBundleEnvironment::Testnet] {
        let backend = loopback_backend(env, ProductionRemoteSignerBackendPolicy::ProductionRequired);
        let outcome = backend.evaluate_remote_signer_backend(&request_spec(env), &domain(env), &identity(env), NOW);
        assert!(!outcome.is_accept(), "production must not accept in Run 293, got {outcome:?}");
    }
}

#[test]
fn f06_transcript_digest_binds_durable_replay_record_digest() {
    // Changing the durable replay record digest changes the backend
    // transcript digest — proving Run 291 composition is representable.
    let a = production_remote_signer_backend_transcript_digest(1, "rid", "req", "resp", "tt", None);
    let b = production_remote_signer_backend_transcript_digest(1, "rid", "req", "resp", "tt", Some(DURABLE_REPLAY_DIGEST));
    assert_ne!(a, b);
}
