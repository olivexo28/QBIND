//! Run 201 — source/test production RemoteSigner transport boundary
//! integration tests.
//!
//! Source/test only. Run 201 does **not** capture release-binary
//! evidence; release-binary RemoteSigner transport-boundary evidence is
//! deferred to **Run 202**. The tests cover:
//!
//! * the full A1–A10 / R1–R35 matrix from `task/RUN_201_TASK.txt`;
//! * request / response / transcript envelope digest determinism;
//! * request/response/transcript binding;
//! * fixture-vs-production transport separation;
//! * timeout / retry / malformed-envelope fail-closed paths;
//! * the no-I/O guarantee for the production transport path (the tests
//!   construct only data values and call only pure validators / pure
//!   trait methods);
//! * the no-mutation guarantee (validation-only surfaces never mutate);
//! * the MainNet peer-driven-apply refusal invariant.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_201.md`.

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
    validate_remote_signer, RemoteSignerExpectations, RemoteSignerIdentity, RemoteSignerMode,
    RemoteSignerOutcome, RemoteSignerPolicy, RemoteSignerRequest,
};
use qbind_node::pqc_remote_signer_transport::{
    custody_class_routes_to_remote_signer_transport, endpoint_is_well_formed,
    local_operator_cannot_satisfy_remote_signer_transport,
    mainnet_peer_driven_apply_remains_refused_under_remote_signer_transport_boundary,
    peer_majority_cannot_satisfy_remote_signer_transport, remote_signer_response_canonical_digest,
    send_remote_signer_request, transport_transcript_digest,
    validate_lifecycle_custody_remote_signer_and_transport, validate_remote_signer_transport,
    validate_remote_signer_transport_for_custody_class, FixtureLoopbackRemoteSignerTransport,
    LifecycleCustodyRemoteSignerTransportOutcome, ProductionRemoteSignerTransport,
    RemoteSignerTransport, RemoteSignerTransportConfig, RemoteSignerTransportExpectations,
    RemoteSignerTransportOutcome, RemoteSignerTransportRequestEnvelope,
    RemoteSignerTransportResponseEnvelope, SimulatedTransportFault, TransportTimeoutRetryPolicy,
    REMOTE_SIGNER_TRANSPORT_INVALID_ATTESTATION_SENTINEL,
    REMOTE_SIGNER_TRANSPORT_PROTOCOL_VERSION,
    REMOTE_SIGNER_TRANSPORT_REQUEST_ENVELOPE_DOMAIN_TAG,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared fixtures
// ===========================================================================

const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT_FP: &str = "1111111111111111111111111111111111111111";
const OTHER_ROOT_FP: &str = "9999999999999999999999999999999999999999";
const CHAIN_ID: &str = "0000000000000001";
const OTHER_CHAIN: &str = "00000000000000ff";
const GENESIS_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_GENESIS: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const PRIOR_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const CUSTODY_ATTEST_DIGEST: &str = "custody-att-digest-201";
const CUSTODY_KEY_ID: &str = "custody-key-id-201";
const SIGNER_ID: &str = "remote-signer-201";
const SIGNER_PUBID: &str = "remote-signer-pubid-201";
const ATTEST_DIGEST: &str = "remote-signer-attest-201";
const REQ_NONCE: &str = "req-nonce-201";
const RESP_NONCE: &str = "resp-nonce-201";
const ENDPOINT: &str = "qbind-signer://signer.example:8443";
const SIGNER_IDENTITY_DIGEST: &str = "signer-identity-digest-201";
const TRANSPORT_ATTEST: &str = "transport-attest-201";
const REQUEST_ID: &str = "transport-request-id-201";
const PAYLOAD_DIGEST: &str = "transport-payload-digest-201";
const TRANSPORT_NONCE: &str = "transport-nonce-201";
const NOW: u64 = 1_700_000_000;
const FRESH: u64 = 1_699_999_900;
const EXPIRES: u64 = 1_700_001_000;

fn domain(env: TrustBundleEnvironment) -> AuthorityTrustDomain {
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
    build_v2(env, KEY_B, 2, BundleSigningRatificationV2Action::Rotate, Some(KEY_A), DIGEST_2)
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

fn inner_request(env: TrustBundleEnvironment) -> RemoteSignerRequest {
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

fn rs_expectations() -> RemoteSignerExpectations {
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

fn transport_expectations() -> RemoteSignerTransportExpectations {
    RemoteSignerTransportExpectations {
        expected_request_id: REQUEST_ID.to_string(),
        expected_payload_digest: PAYLOAD_DIGEST.to_string(),
        expected_anti_replay_nonce: TRANSPORT_NONCE.to_string(),
        expected_signer_identity_digest: SIGNER_IDENTITY_DIGEST.to_string(),
        expected_transport_attestation_digest: Some(TRANSPORT_ATTEST.to_string()),
        now_unix: NOW,
    }
}

fn request_envelope(env: TrustBundleEnvironment) -> RemoteSignerTransportRequestEnvelope {
    let inner = inner_request(env);
    let canonical = inner.canonical_digest();
    RemoteSignerTransportRequestEnvelope {
        protocol_version: REMOTE_SIGNER_TRANSPORT_PROTOCOL_VERSION,
        domain_tag: REMOTE_SIGNER_TRANSPORT_REQUEST_ENVELOPE_DOMAIN_TAG.to_string(),
        request_id: REQUEST_ID.to_string(),
        timestamp_unix: NOW,
        environment: env,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        custody_key_id: CUSTODY_KEY_ID.to_string(),
        expected_signer_id: SIGNER_ID.to_string(),
        canonical_request_digest: canonical,
        payload_digest: PAYLOAD_DIGEST.to_string(),
        anti_replay_nonce: TRANSPORT_NONCE.to_string(),
        inner_request: inner,
    }
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

/// A complete, valid accepted transport scenario for `env`.
struct Scenario {
    domain: AuthorityTrustDomain,
    config: RemoteSignerTransportConfig,
    identity: RemoteSignerIdentity,
    request_env: RemoteSignerTransportRequestEnvelope,
    response_env: RemoteSignerTransportResponseEnvelope,
    rs_expected: RemoteSignerExpectations,
    transport_expected: RemoteSignerTransportExpectations,
}

fn scenario(env: TrustBundleEnvironment) -> Scenario {
    let transport = fixture_transport(env);
    let request_env = request_envelope(env);
    let response_env = transport
        .call_remote_signer(&request_env)
        .expect("fixture loopback transport returns a response");
    Scenario {
        domain: domain(env),
        config: transport_config(env),
        identity: identity(env),
        request_env,
        response_env,
        rs_expected: rs_expectations(),
        transport_expected: transport_expectations(),
    }
}

fn validate(s: &Scenario, policy: RemoteSignerPolicy) -> RemoteSignerTransportOutcome {
    validate_remote_signer_transport(
        &s.config,
        &s.request_env,
        &s.response_env,
        &s.domain,
        &s.identity,
        &s.rs_expected,
        &s.transport_expected,
        policy,
    )
}

fn validate_fixture(s: &Scenario) -> RemoteSignerTransportOutcome {
    validate(s, RemoteSignerPolicy::FixtureLoopbackAllowed)
}

// Build a production-mode response envelope (signer_mode = Production)
// by replacing the inner response. Used for the production-unavailable
// vectors.
fn production_mode_response(
    s: &Scenario,
) -> RemoteSignerTransportResponseEnvelope {
    let mut env = s.response_env.clone();
    env.inner_response.signer_mode = RemoteSignerMode::Production;
    env
}

fn good_custody_attestation(
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

// ===========================================================================
// Defaults / type-shape regressions
// ===========================================================================

#[test]
fn protocol_version_constant_is_one() {
    assert_eq!(REMOTE_SIGNER_TRANSPORT_PROTOCOL_VERSION, 1);
}

#[test]
fn default_policy_disabled_fails_closed_even_with_valid_transport() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    let outcome = validate(&s, RemoteSignerPolicy::default());
    assert_eq!(outcome, RemoteSignerTransportOutcome::TransportDisabled);
    assert!(outcome.is_reject());
}

// ===========================================================================
// Accepted scenarios A1–A10
// ===========================================================================

#[test]
fn a1_fixture_loopback_transport_accepted_devnet() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    let outcome = validate_fixture(&s);
    assert_eq!(
        outcome,
        RemoteSignerTransportOutcome::FixtureLoopbackTransportAccepted {
            signer_id: SIGNER_ID.to_string(),
            environment: TrustBundleEnvironment::Devnet,
        }
    );
    assert!(outcome.is_accept());
}

#[test]
fn a2_fixture_loopback_transport_accepted_testnet() {
    let s = scenario(TrustBundleEnvironment::Testnet);
    let outcome = validate_fixture(&s);
    assert_eq!(
        outcome,
        RemoteSignerTransportOutcome::FixtureLoopbackTransportAccepted {
            signer_id: SIGNER_ID.to_string(),
            environment: TrustBundleEnvironment::Testnet,
        }
    );
}

#[test]
fn a3_request_envelope_digest_deterministic() {
    let a = request_envelope(TrustBundleEnvironment::Devnet);
    let b = request_envelope(TrustBundleEnvironment::Devnet);
    assert_eq!(a.envelope_digest(), b.envelope_digest());
    // A different field changes the digest.
    let mut c = request_envelope(TrustBundleEnvironment::Devnet);
    c.request_id = "different".to_string();
    assert_ne!(a.envelope_digest(), c.envelope_digest());
}

#[test]
fn a4_response_envelope_digest_deterministic() {
    let s1 = scenario(TrustBundleEnvironment::Devnet);
    let s2 = scenario(TrustBundleEnvironment::Devnet);
    assert_eq!(
        s1.response_env.envelope_digest(),
        s2.response_env.envelope_digest()
    );
    // Mutating a bound field changes the digest.
    let mut other = s1.response_env.clone();
    other.signer_id = "other-signer".to_string();
    assert_ne!(
        s1.response_env.envelope_digest(),
        other.envelope_digest()
    );
}

#[test]
fn a5_request_response_transcript_digest_deterministic() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    let req_d = s.request_env.envelope_digest();
    let resp_d = s.response_env.envelope_digest();
    let t1 = transport_transcript_digest(&req_d, &resp_d);
    let t2 = transport_transcript_digest(&req_d, &resp_d);
    assert_eq!(t1, t2);
    // The fixture transport bound exactly this transcript.
    assert_eq!(s.response_env.transcript_digest, t1);
    // Order-sensitive: swapping inputs changes the transcript.
    assert_ne!(t1, transport_transcript_digest(&resp_d, &req_d));
}

#[test]
fn a6_transport_request_binds_full_authority_tuple() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    let r = &s.request_env;
    assert_eq!(r.environment, TrustBundleEnvironment::Devnet);
    assert_eq!(r.chain_id, CHAIN_ID);
    assert_eq!(r.genesis_hash, GENESIS_HASH);
    assert_eq!(r.authority_root_fingerprint, ROOT_FP);
    assert_eq!(r.expected_signer_id, SIGNER_ID);
    assert_eq!(r.custody_key_id, CUSTODY_KEY_ID);
    assert_eq!(r.inner_request.lifecycle_action, LocalLifecycleAction::Rotate);
    assert_eq!(r.inner_request.candidate_digest, DIGEST_2);
    assert_eq!(r.inner_request.authority_domain_sequence, 2);
    // The canonical request digest binds all of the above.
    assert_eq!(r.canonical_request_digest, r.inner_request.canonical_digest());
}

#[test]
fn a7_transport_response_binds_request_and_transcript() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    let resp = &s.response_env;
    assert_eq!(resp.request_id_echo, REQUEST_ID);
    assert_eq!(resp.signer_id, SIGNER_ID);
    assert_eq!(resp.custody_key_id, CUSTODY_KEY_ID);
    assert_eq!(
        resp.inner_response.request_digest,
        s.request_env.inner_request.canonical_digest()
    );
    assert_eq!(
        resp.canonical_response_digest,
        remote_signer_response_canonical_digest(&resp.inner_response)
    );
    let expected_transcript = transport_transcript_digest(
        &s.request_env.envelope_digest(),
        &resp.envelope_digest(),
    );
    assert_eq!(resp.transcript_digest, expected_transcript);
}

#[test]
fn a8_production_transport_callable_returns_typed_unavailable() {
    let prod = ProductionRemoteSignerTransport {
        config: transport_config(TrustBundleEnvironment::Devnet),
    };
    let req = request_envelope(TrustBundleEnvironment::Devnet);
    let outcome = prod.call_remote_signer(&req);
    assert_eq!(
        outcome,
        Err(RemoteSignerTransportOutcome::ProductionTransportUnavailable)
    );
    // Also reachable through the free helper.
    let outcome2 = send_remote_signer_request(&prod, &req);
    assert_eq!(
        outcome2,
        Err(RemoteSignerTransportOutcome::ProductionTransportUnavailable)
    );
}

#[test]
fn a9_run194_validation_compatible_with_fixture_transport_response() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    // The Run 194 verifier accepts the wrapped request/response directly.
    let outcome = validate_remote_signer(
        &s.identity,
        &s.request_env.inner_request,
        &s.response_env.inner_response,
        &s.domain,
        &s.rs_expected,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    assert!(
        matches!(outcome, RemoteSignerOutcome::FixtureLoopbackAccepted { .. }),
        "got {outcome:?}"
    );
}

#[test]
fn a10_disabled_transport_policy_does_not_disturb_inner_governance() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    // Transport disabled fails closed.
    assert_eq!(
        validate(&s, RemoteSignerPolicy::Disabled),
        RemoteSignerTransportOutcome::TransportDisabled
    );
    // ...yet the Run 194 GenesisBound remote-signer verification is
    // unchanged and still accepts under its own fixture policy.
    let inner = validate_remote_signer(
        &s.identity,
        &s.request_env.inner_request,
        &s.response_env.inner_response,
        &s.domain,
        &s.rs_expected,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    assert!(matches!(
        inner,
        RemoteSignerOutcome::FixtureLoopbackAccepted { .. }
    ));
}

// ===========================================================================
// Rejection scenarios R1–R35
// ===========================================================================

#[test]
fn r1_transport_rejected_under_disabled() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    assert_eq!(
        validate(&s, RemoteSignerPolicy::Disabled),
        RemoteSignerTransportOutcome::TransportDisabled
    );
}

#[test]
fn r2_fixture_rejected_production_required() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    assert_eq!(
        validate(&s, RemoteSignerPolicy::ProductionRemoteSignerRequired),
        RemoteSignerTransportOutcome::FixtureTransportRejectedProductionRequired
    );
}

#[test]
fn r3_fixture_rejected_mainnet_production_required() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    assert_eq!(
        validate(&s, RemoteSignerPolicy::MainnetProductionRemoteSignerRequired),
        RemoteSignerTransportOutcome::FixtureTransportRejectedMainnetProductionRequired
    );
}

#[test]
fn r4_production_transport_unavailable() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    let mut s2 = scenario(TrustBundleEnvironment::Devnet);
    s2.response_env = production_mode_response(&s);
    // Under FixtureLoopbackAllowed, a production-mode response is
    // unavailable.
    assert_eq!(
        validate_fixture(&s2),
        RemoteSignerTransportOutcome::ProductionTransportUnavailable
    );
    // And the production transport itself fails closed.
    let prod = ProductionRemoteSignerTransport {
        config: transport_config(TrustBundleEnvironment::Devnet),
    };
    assert_eq!(
        prod.call_remote_signer(&s.request_env),
        Err(RemoteSignerTransportOutcome::ProductionTransportUnavailable)
    );
}

#[test]
fn r5_mainnet_production_transport_unavailable() {
    let prod = ProductionRemoteSignerTransport {
        config: transport_config(TrustBundleEnvironment::Mainnet),
    };
    let req = request_envelope(TrustBundleEnvironment::Mainnet);
    assert_eq!(
        prod.call_remote_signer(&req),
        Err(RemoteSignerTransportOutcome::MainNetProductionTransportUnavailable)
    );
    // Through the validator with a production-mode response under the
    // MainNet production policy.
    let s = scenario(TrustBundleEnvironment::Devnet);
    let mut s2 = scenario(TrustBundleEnvironment::Devnet);
    s2.response_env = production_mode_response(&s);
    assert_eq!(
        validate(&s2, RemoteSignerPolicy::MainnetProductionRemoteSignerRequired),
        RemoteSignerTransportOutcome::MainNetProductionTransportUnavailable
    );
}

#[test]
fn r6_endpoint_missing_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.config.endpoint = String::new();
    assert_eq!(validate_fixture(&s), RemoteSignerTransportOutcome::EndpointMissing);
}

#[test]
fn r7_endpoint_malformed_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.config.endpoint = "no-scheme-here".to_string();
    assert_eq!(
        validate_fixture(&s),
        RemoteSignerTransportOutcome::EndpointMalformed {
            endpoint: "no-scheme-here".to_string()
        }
    );
}

#[test]
fn r8_wrong_environment_rejected() {
    // Build a TestNet scenario but validate against a DevNet domain.
    let s = scenario(TrustBundleEnvironment::Testnet);
    let dev_domain = domain(TrustBundleEnvironment::Devnet);
    let outcome = validate_remote_signer_transport(
        &s.config,
        &s.request_env,
        &s.response_env,
        &dev_domain,
        &s.identity,
        &s.rs_expected,
        &s.transport_expected,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    assert!(matches!(
        outcome,
        RemoteSignerTransportOutcome::WrongEnvironment { .. }
    ));
}

#[test]
fn r9_wrong_chain_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.config.chain_id = OTHER_CHAIN.to_string();
    assert!(matches!(
        validate_fixture(&s),
        RemoteSignerTransportOutcome::WrongChain { .. }
    ));
}

#[test]
fn r10_wrong_genesis_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.config.genesis_hash = OTHER_GENESIS.to_string();
    assert!(matches!(
        validate_fixture(&s),
        RemoteSignerTransportOutcome::WrongGenesis { .. }
    ));
}

#[test]
fn r11_wrong_signer_id_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.config.signer_id = "wrong-signer".to_string();
    assert!(matches!(
        validate_fixture(&s),
        RemoteSignerTransportOutcome::WrongSignerId { .. }
    ));
}

#[test]
fn r12_wrong_custody_key_id_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.config.custody_key_id = "wrong-custody".to_string();
    assert!(matches!(
        validate_fixture(&s),
        RemoteSignerTransportOutcome::WrongCustodyKeyId { .. }
    ));
}

#[test]
fn r13_wrong_authority_root_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.config.authority_root_fingerprint = OTHER_ROOT_FP.to_string();
    assert!(matches!(
        validate_fixture(&s),
        RemoteSignerTransportOutcome::WrongAuthorityRoot { .. }
    ));
}

#[test]
fn r14_wrong_signing_key_fingerprint_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.config.bundle_signing_key_fingerprint = KEY_A.to_string();
    assert!(matches!(
        validate_fixture(&s),
        RemoteSignerTransportOutcome::WrongSigningKeyFingerprint { .. }
    ));
}

#[test]
fn r15_wrong_request_id_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.response_env.request_id_echo = "wrong-echo".to_string();
    assert!(matches!(
        validate_fixture(&s),
        RemoteSignerTransportOutcome::WrongRequestId { .. }
    ));
}

#[test]
fn r16_wrong_request_digest_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.request_env.canonical_request_digest = "deadbeef".to_string();
    assert!(matches!(
        validate_fixture(&s),
        RemoteSignerTransportOutcome::WrongRequestDigest { .. }
    ));
}

#[test]
fn r17_wrong_response_digest_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.response_env.canonical_response_digest = "deadbeef".to_string();
    assert!(matches!(
        validate_fixture(&s),
        RemoteSignerTransportOutcome::WrongResponseDigest { .. }
    ));
}

#[test]
fn r18_wrong_transcript_digest_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.response_env.transcript_digest = "deadbeef".to_string();
    assert!(matches!(
        validate_fixture(&s),
        RemoteSignerTransportOutcome::WrongTranscriptDigest { .. }
    ));
}

#[test]
fn r19_stale_or_replayed_request_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.request_env.anti_replay_nonce = "stale-nonce".to_string();
    assert!(matches!(
        validate_fixture(&s),
        RemoteSignerTransportOutcome::StaleOrReplayedRequest { .. }
    ));
}

#[test]
fn r20_stale_or_replayed_response_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    // now beyond the response expiry window.
    s.transport_expected.now_unix = EXPIRES + 1;
    s.rs_expected.now_unix = EXPIRES + 1;
    assert!(matches!(
        validate_fixture(&s),
        RemoteSignerTransportOutcome::StaleOrReplayedResponse { .. }
    ));
}

#[test]
fn r21_timeout_rejected() {
    let mut transport = fixture_transport(TrustBundleEnvironment::Devnet);
    transport.simulated_fault = Some(SimulatedTransportFault::Timeout);
    let req = request_envelope(TrustBundleEnvironment::Devnet);
    assert_eq!(
        transport.call_remote_signer(&req),
        Err(RemoteSignerTransportOutcome::Timeout)
    );
}

#[test]
fn r22_retry_exhausted_rejected() {
    let mut transport = fixture_transport(TrustBundleEnvironment::Devnet);
    transport.simulated_fault = Some(SimulatedTransportFault::RetryExhausted);
    let req = request_envelope(TrustBundleEnvironment::Devnet);
    assert_eq!(
        transport.call_remote_signer(&req),
        Err(RemoteSignerTransportOutcome::RetryExhausted)
    );
}

#[test]
fn r23_malformed_request_envelope_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.request_env.request_id = String::new();
    assert!(matches!(
        validate_fixture(&s),
        RemoteSignerTransportOutcome::MalformedRequestEnvelope { .. }
    ));
}

#[test]
fn r24_malformed_response_envelope_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.response_env.response_commitment = String::new();
    assert!(matches!(
        validate_fixture(&s),
        RemoteSignerTransportOutcome::MalformedResponseEnvelope { .. }
    ));
}

#[test]
fn r25_unsupported_protocol_version_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.request_env.protocol_version = 99;
    assert_eq!(
        validate_fixture(&s),
        RemoteSignerTransportOutcome::UnsupportedProtocolVersion { version: 99 }
    );
}

#[test]
fn r26_unsupported_suite_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.config.suite_id = 7;
    assert!(matches!(
        validate_fixture(&s),
        RemoteSignerTransportOutcome::UnsupportedSuite { .. }
    ));
}

#[test]
fn r27_invalid_transport_attestation_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.config.transport_attestation_digest =
        Some(REMOTE_SIGNER_TRANSPORT_INVALID_ATTESTATION_SENTINEL.to_string());
    assert_eq!(
        validate_fixture(&s),
        RemoteSignerTransportOutcome::InvalidTransportAttestation
    );
}

#[test]
fn r28_local_operator_cannot_satisfy_transport() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    let outcome = validate_remote_signer_transport_for_custody_class(
        AuthorityCustodyClass::LocalOperatorKey,
        &s.config,
        &s.request_env,
        &s.response_env,
        &s.domain,
        &s.identity,
        &s.rs_expected,
        &s.transport_expected,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    assert_eq!(
        outcome,
        RemoteSignerTransportOutcome::LocalOperatorCannotSatisfyTransport
    );
    assert!(local_operator_cannot_satisfy_remote_signer_transport());
}

#[test]
fn r29_peer_majority_cannot_satisfy_transport() {
    assert!(peer_majority_cannot_satisfy_remote_signer_transport());
    // The typed variant is constructible and distinct.
    let v = RemoteSignerTransportOutcome::PeerMajorityCannotSatisfyTransport;
    assert!(v.is_reject());
}

#[test]
fn r30_transport_valid_but_remote_signer_response_invalid() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    // Break only the Run 194 expectation (response nonce), leaving every
    // transport framing field valid. The Run 194 verifier rejects.
    s.rs_expected.expected_response_nonce = "wrong-response-nonce".to_string();
    let outcome = validate_fixture(&s);
    assert!(
        matches!(
            outcome,
            RemoteSignerTransportOutcome::RemoteSignerResponseInvalid { .. }
        ),
        "got {outcome:?}"
    );
}

#[test]
fn r31_remote_signer_valid_but_transport_transcript_invalid() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    // Keep the Run 194 inner response valid (its canonical digest still
    // matches) but corrupt only the transport transcript binding.
    s.response_env.transcript_digest =
        transport_transcript_digest("not-the-request", "not-the-response");
    assert!(matches!(
        validate_fixture(&s),
        RemoteSignerTransportOutcome::WrongTranscriptDigest { .. }
    ));
}

#[test]
fn r32_lifecycle_governance_custody_valid_but_production_transport_unavailable() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    // The Run 194 lifecycle/custody/remote-signer composition accepts the
    // fixture material.
    let inner = validate_remote_signer(
        &s.identity,
        &s.request_env.inner_request,
        &s.response_env.inner_response,
        &s.domain,
        &s.rs_expected,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    assert!(matches!(
        inner,
        RemoteSignerOutcome::FixtureLoopbackAccepted { .. }
    ));
    // ...yet the production transport remains unavailable/fail-closed.
    let prod = ProductionRemoteSignerTransport {
        config: transport_config(TrustBundleEnvironment::Devnet),
    };
    assert_eq!(
        prod.call_remote_signer(&s.request_env),
        Err(RemoteSignerTransportOutcome::ProductionTransportUnavailable)
    );
}

#[test]
fn r33_validation_only_rejection_remains_non_mutating() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    let config_before = s.config.clone();
    let request_before = s.request_env.clone();
    let response_before = s.response_env.clone();
    // A rejecting policy.
    let _ = validate(&s, RemoteSignerPolicy::Disabled);
    // ...and a rejecting binding.
    let mut s2 = scenario(TrustBundleEnvironment::Devnet);
    s2.config.chain_id = OTHER_CHAIN.to_string();
    let _ = validate_fixture(&s2);
    // Inputs to the first (valid) scenario are unchanged.
    assert_eq!(s.config, config_before);
    assert_eq!(s.request_env, request_before);
    assert_eq!(s.response_env, response_before);
}

#[test]
fn r34_mutating_preflight_rejection_produces_no_mutation() {
    // The composition helper is pure: on a reject it returns a reject
    // variant and touches no marker / sequence / live trust / Run 070.
    let s = scenario(TrustBundleEnvironment::Devnet);
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let prior = prior_versioned(TrustBundleEnvironment::Devnet);
    let custody = good_custody_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let candidate_before = candidate.clone();
    // Disabled transport policy ⇒ inner Run 194 fixture verification also
    // fails closed, so the whole composition rejects without mutation.
    let outcome = validate_lifecycle_custody_remote_signer_and_transport(
        &custody,
        &candidate,
        Some(&prior),
        &s.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        &s.identity,
        &s.request_env.inner_request,
        &s.response_env.inner_response,
        &s.rs_expected,
        RemoteSignerPolicy::Disabled,
        &s.config,
        &s.request_env,
        &s.response_env,
        &s.transport_expected,
        NOW,
        false,
    );
    assert!(outcome.is_reject(), "got {outcome:?}");
    assert_eq!(candidate, candidate_before);
}

#[test]
fn r35_mainnet_peer_driven_apply_refused_even_with_fixture_transport() {
    let s = scenario(TrustBundleEnvironment::Mainnet);
    let candidate = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let prior = prior_versioned(TrustBundleEnvironment::Mainnet);
    let custody = good_custody_attestation(
        TrustBundleEnvironment::Mainnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let outcome = validate_lifecycle_custody_remote_signer_and_transport(
        &custody,
        &candidate,
        Some(&prior),
        &s.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        &s.identity,
        &s.request_env.inner_request,
        &s.response_env.inner_response,
        &s.rs_expected,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        &s.config,
        &s.request_env,
        &s.response_env,
        &s.transport_expected,
        NOW,
        true,
    );
    assert_eq!(
        outcome,
        LifecycleCustodyRemoteSignerTransportOutcome::MainNetPeerDrivenApplyRefused
    );
    // And the explicit grep-verifiable helper agrees.
    assert!(
        mainnet_peer_driven_apply_remains_refused_under_remote_signer_transport_boundary(
            TrustBundleEnvironment::Mainnet
        )
    );
}

// ===========================================================================
// Determinism / binding / separation / fail-closed extras
// ===========================================================================

#[test]
fn fixture_loopback_transport_rejected_for_mainnet() {
    let s = scenario(TrustBundleEnvironment::Mainnet);
    assert_eq!(
        validate_fixture(&s),
        RemoteSignerTransportOutcome::FixtureLoopbackTransportRejectedForMainNet
    );
}

#[test]
fn fixture_vs_production_transport_are_distinct() {
    // A fixture transport returns a fixture-mode response; the production
    // transport never returns a response.
    let s = scenario(TrustBundleEnvironment::Devnet);
    assert_eq!(
        s.response_env.inner_response.signer_mode,
        RemoteSignerMode::FixtureLoopback
    );
    let prod = ProductionRemoteSignerTransport {
        config: transport_config(TrustBundleEnvironment::Devnet),
    };
    assert!(prod.call_remote_signer(&s.request_env).is_err());
}

#[test]
fn production_transport_path_performs_no_io_and_fails_closed() {
    // The production transport path constructs only data values and
    // returns a typed unavailable outcome — no network, no file I/O.
    for env in [
        TrustBundleEnvironment::Devnet,
        TrustBundleEnvironment::Testnet,
    ] {
        let prod = ProductionRemoteSignerTransport {
            config: transport_config(env),
        };
        let req = request_envelope(env);
        assert_eq!(
            prod.call_remote_signer(&req),
            Err(RemoteSignerTransportOutcome::ProductionTransportUnavailable)
        );
    }
}

#[test]
fn malformed_envelope_call_fails_closed_before_response() {
    let transport = fixture_transport(TrustBundleEnvironment::Devnet);
    let mut req = request_envelope(TrustBundleEnvironment::Devnet);
    req.canonical_request_digest = String::new();
    assert!(matches!(
        transport.call_remote_signer(&req),
        Err(RemoteSignerTransportOutcome::MalformedRequestEnvelope { .. })
    ));
}

#[test]
fn endpoint_helper_matches_validator_decision() {
    assert!(endpoint_is_well_formed(ENDPOINT));
    assert!(!endpoint_is_well_formed(""));
    assert!(!endpoint_is_well_formed("bad endpoint"));
}

#[test]
fn custody_class_routing_predicate_and_non_remote_signer_class() {
    assert!(custody_class_routes_to_remote_signer_transport(
        AuthorityCustodyClass::RemoteSigner
    ));
    let s = scenario(TrustBundleEnvironment::Devnet);
    let outcome = validate_remote_signer_transport_for_custody_class(
        AuthorityCustodyClass::FixtureLocalKey,
        &s.config,
        &s.request_env,
        &s.response_env,
        &s.domain,
        &s.identity,
        &s.rs_expected,
        &s.transport_expected,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    assert!(matches!(
        outcome,
        RemoteSignerTransportOutcome::NotRemoteSignerCustodyClass { .. }
    ));
}

#[test]
fn composition_accepts_full_lifecycle_custody_remote_signer_and_transport_devnet() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let prior = prior_versioned(TrustBundleEnvironment::Devnet);
    let custody = good_custody_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let outcome = validate_lifecycle_custody_remote_signer_and_transport(
        &custody,
        &candidate,
        Some(&prior),
        &s.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        &s.identity,
        &s.request_env.inner_request,
        &s.response_env.inner_response,
        &s.rs_expected,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        &s.config,
        &s.request_env,
        &s.response_env,
        &s.transport_expected,
        NOW,
        false,
    );
    assert!(outcome.is_accept(), "got {outcome:?}");
    assert!(matches!(
        outcome,
        LifecycleCustodyRemoteSignerTransportOutcome::Accepted { .. }
    ));
}

#[test]
fn composition_transport_rejected_when_inner_accepts_but_transport_fails() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    // Corrupt only the transport transcript so the Run 194 inner
    // composition accepts but the transport boundary rejects.
    s.response_env.transcript_digest = "deadbeef".to_string();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let prior = prior_versioned(TrustBundleEnvironment::Devnet);
    let custody = good_custody_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let outcome = validate_lifecycle_custody_remote_signer_and_transport(
        &custody,
        &candidate,
        Some(&prior),
        &s.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        &s.identity,
        &s.request_env.inner_request,
        &s.response_env.inner_response,
        &s.rs_expected,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        &s.config,
        &s.request_env,
        &s.response_env,
        &s.transport_expected,
        NOW,
        false,
    );
    assert!(matches!(
        outcome,
        LifecycleCustodyRemoteSignerTransportOutcome::TransportRejected { .. }
    ));
}

#[test]
fn timeout_retry_policy_validation() {
    assert!(TransportTimeoutRetryPolicy::default().is_well_formed());
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.config.timeout_retry = TransportTimeoutRetryPolicy {
        per_attempt_timeout_ms: 0,
        max_attempts: 0,
    };
    // A malformed timeout/retry policy fails the config well-formedness
    // check and is rejected before acceptance.
    assert!(matches!(
        validate_fixture(&s),
        RemoteSignerTransportOutcome::MalformedRequestEnvelope { .. }
    ));
}

#[test]
fn transport_trait_object_is_mockable() {
    let transport = fixture_transport(TrustBundleEnvironment::Devnet);
    let dynref: &dyn RemoteSignerTransport = &transport;
    let req = request_envelope(TrustBundleEnvironment::Devnet);
    assert!(dynref.call_remote_signer(&req).is_ok());
    assert_eq!(dynref.config().signer_id, SIGNER_ID);
}

#[test]
fn accepted_scenario_round_trips_through_run194_inner() {
    // Cross-check: the same response that the transport accepts is the
    // one the Run 194 verifier accepts, proving compatibility (A9) holds
    // for both DevNet and TestNet.
    for env in [
        TrustBundleEnvironment::Devnet,
        TrustBundleEnvironment::Testnet,
    ] {
        let s = scenario(env);
        assert!(validate_fixture(&s).is_accept());
        let inner = validate_remote_signer(
            &s.identity,
            &s.request_env.inner_request,
            &s.response_env.inner_response,
            &s.domain,
            &s.rs_expected,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
        );
        assert!(matches!(
            inner,
            RemoteSignerOutcome::FixtureLoopbackAccepted { .. }
        ));
    }
}
