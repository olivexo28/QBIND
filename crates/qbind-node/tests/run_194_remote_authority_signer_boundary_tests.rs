//! Run 194 — source/test RemoteSigner production-custody interface
//! boundary integration tests.
//!
//! Source/test only. Run 194 does **not** capture release-binary
//! evidence; release-binary RemoteSigner boundary evidence is deferred
//! to **Run 195**. The tests cover:
//!
//! * the full A1–A7 / R1–R31 matrix from `task/RUN_194_TASK.txt`;
//! * request/response canonical digest determinism;
//! * replay/freshness checks;
//! * fixture-vs-production separation;
//! * source reachability from the Run 188 / 190 custody composition;
//! * pure no-I/O guarantee (the tests construct only data values and
//!   call only pure validators / pure trait methods);
//! * no-mutation guarantee (validation-only surfaces never mutate);
//! * MainNet refusal invariants.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_194.md`.

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
    custody_class_routes_to_remote_signer,
    local_operator_key_cannot_satisfy_remote_signer,
    mainnet_peer_driven_apply_remains_refused_under_remote_signer_boundary,
    peer_majority_cannot_satisfy_remote_signer, validate_lifecycle_governance_custody_and_remote_signer,
    validate_remote_signer, validate_remote_signer_for_custody_class, FixtureLoopbackRemoteSigner,
    LifecycleCustodyRemoteSignerOutcome, ProductionRemoteSigner, RemoteAuthoritySigner,
    RemoteSignerExpectations, RemoteSignerIdentity, RemoteSignerMode, RemoteSignerOutcome,
    RemoteSignerPolicy, RemoteSignerRequest, RemoteSignerResponse,
    REMOTE_SIGNER_INVALID_SIGNATURE_SENTINEL,
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
const GENESIS_HASH: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_GENESIS: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DIGEST_OTHER: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";
const PRIOR_DIGEST: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const CUSTODY_ATTEST_DIGEST: &str = "custody-att-digest-194";
const CUSTODY_KEY_ID: &str = "custody-key-id-194";
const SIGNER_ID: &str = "remote-signer-194";
const SIGNER_PUBID: &str = "remote-signer-pubid-194";
const ATTEST_DIGEST: &str = "remote-signer-attest-194";
const REQ_NONCE: &str = "req-nonce-194";
const RESP_NONCE: &str = "resp-nonce-194";
const NOW: u64 = 1_700_000_000;
const FRESH: u64 = 1_699_999_900;
const EXPIRES: u64 = 1_700_001_000;

fn devnet_domain() -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(
        TrustBundleEnvironment::Devnet,
        CHAIN_ID,
        GENESIS_HASH,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
    )
}

fn testnet_domain() -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(
        TrustBundleEnvironment::Testnet,
        CHAIN_ID,
        GENESIS_HASH,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
    )
}

fn mainnet_domain() -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(
        TrustBundleEnvironment::Mainnet,
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

fn identity(env: TrustBundleEnvironment, candidate: &PersistentAuthorityStateRecordV2) -> RemoteSignerIdentity {
    RemoteSignerIdentity {
        signer_id: SIGNER_ID.to_string(),
        signer_public_identity: SIGNER_PUBID.to_string(),
        custody_key_id: CUSTODY_KEY_ID.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        bundle_signing_key_fingerprint: candidate
            .active_bundle_signing_key_fingerprint
            .clone(),
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

fn request(env: TrustBundleEnvironment, candidate: &PersistentAuthorityStateRecordV2) -> RemoteSignerRequest {
    RemoteSignerRequest {
        environment: env,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: DIGEST_2.to_string(),
        authority_domain_sequence: 2,
        active_signing_key_fingerprint: Some(KEY_A.to_string()),
        new_signing_key_fingerprint: Some(candidate.active_bundle_signing_key_fingerprint.clone()),
        revoked_signing_key_fingerprint: None,
        governance_proof_digest: None,
        custody_attestation_digest: CUSTODY_ATTEST_DIGEST.to_string(),
        replay_nonce: REQ_NONCE.to_string(),
        request_timestamp_unix: Some(NOW),
    }
}

fn fixture_signer(env: TrustBundleEnvironment, candidate: &PersistentAuthorityStateRecordV2) -> FixtureLoopbackRemoteSigner {
    FixtureLoopbackRemoteSigner {
        identity: identity(env, candidate),
        response_nonce: RESP_NONCE.to_string(),
        response_freshness_unix: Some(FRESH),
        response_expires_at_unix: Some(EXPIRES),
    }
}

fn expectations(candidate: &PersistentAuthorityStateRecordV2) -> RemoteSignerExpectations {
    RemoteSignerExpectations {
        expected_lifecycle_action: LocalLifecycleAction::Rotate,
        expected_candidate_digest: DIGEST_2.to_string(),
        expected_authority_domain_sequence: 2,
        expected_custody_key_id: CUSTODY_KEY_ID.to_string(),
        expected_signing_key_fingerprint: candidate.active_bundle_signing_key_fingerprint.clone(),
        expected_custody_attestation_digest: CUSTODY_ATTEST_DIGEST.to_string(),
        expected_request_nonce: REQ_NONCE.to_string(),
        expected_response_nonce: RESP_NONCE.to_string(),
        now_unix: NOW,
    }
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
        bundle_signing_key_fingerprint: candidate
            .active_bundle_signing_key_fingerprint
            .clone(),
        governance_authority_class: GovernanceAuthorityClass::GenesisBound,
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: DIGEST_2.to_string(),
        authority_domain_sequence: 2,
    }
}

/// Build a complete, valid accepted scenario for `env`, returning every
/// part a test needs to mutate one field for a rejection vector.
struct Scenario {
    domain: AuthorityTrustDomain,
    candidate: PersistentAuthorityStateRecordV2,
    identity: RemoteSignerIdentity,
    request: RemoteSignerRequest,
    response: RemoteSignerResponse,
    expected: RemoteSignerExpectations,
}

fn scenario(env: TrustBundleEnvironment) -> Scenario {
    let candidate = rotate_candidate(env);
    let signer = fixture_signer(env, &candidate);
    let request = request(env, &candidate);
    let response = signer.sign(&request).expect("fixture loopback signs");
    Scenario {
        domain: match env {
            TrustBundleEnvironment::Devnet => devnet_domain(),
            TrustBundleEnvironment::Testnet => testnet_domain(),
            TrustBundleEnvironment::Mainnet => mainnet_domain(),
        },
        identity: identity(env, &candidate),
        expected: expectations(&candidate),
        request,
        response,
        candidate,
    }
}

fn validate(s: &Scenario, policy: RemoteSignerPolicy) -> RemoteSignerOutcome {
    validate_remote_signer(
        &s.identity,
        &s.request,
        &s.response,
        &s.domain,
        &s.expected,
        policy,
    )
}

// ===========================================================================
// Defaults / type-shape regressions
// ===========================================================================

#[test]
fn default_remote_signer_policy_is_disabled_fail_closed() {
    assert_eq!(RemoteSignerPolicy::default(), RemoteSignerPolicy::Disabled);
    let s = scenario(TrustBundleEnvironment::Devnet);
    // Even an otherwise perfectly valid fixture loopback round-trip is
    // refused under the default Disabled policy.
    let outcome = validate(&s, RemoteSignerPolicy::default());
    assert_eq!(outcome, RemoteSignerOutcome::Disabled);
    assert!(outcome.is_reject());
}

#[test]
fn policy_tags_are_stable() {
    assert_eq!(RemoteSignerPolicy::Disabled.tag(), "disabled");
    assert_eq!(
        RemoteSignerPolicy::FixtureLoopbackAllowed.tag(),
        "fixture-loopback-allowed"
    );
    assert_eq!(
        RemoteSignerPolicy::ProductionRemoteSignerRequired.tag(),
        "production-remote-signer-required"
    );
    assert_eq!(
        RemoteSignerPolicy::MainnetProductionRemoteSignerRequired.tag(),
        "mainnet-production-remote-signer-required"
    );
    assert!(RemoteSignerPolicy::ProductionRemoteSignerRequired.requires_production_remote_signer());
    assert!(
        RemoteSignerPolicy::MainnetProductionRemoteSignerRequired.requires_production_remote_signer()
    );
    assert!(!RemoteSignerPolicy::FixtureLoopbackAllowed.requires_production_remote_signer());
    assert_eq!(RemoteSignerMode::FixtureLoopback.tag(), "fixture-loopback");
    assert_eq!(RemoteSignerMode::Production.tag(), "production");
}

// ===========================================================================
// Accepted scenarios A1–A7
// ===========================================================================

#[test]
fn a1_fixture_loopback_accepted_devnet() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    let outcome = validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed);
    assert_eq!(
        outcome,
        RemoteSignerOutcome::FixtureLoopbackAccepted {
            signer_id: SIGNER_ID.to_string(),
            environment: TrustBundleEnvironment::Devnet,
        }
    );
    assert!(outcome.is_accept());
}

#[test]
fn a2_fixture_loopback_accepted_testnet() {
    let s = scenario(TrustBundleEnvironment::Testnet);
    let outcome = validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed);
    assert_eq!(
        outcome,
        RemoteSignerOutcome::FixtureLoopbackAccepted {
            signer_id: SIGNER_ID.to_string(),
            environment: TrustBundleEnvironment::Testnet,
        }
    );
}

#[test]
fn a3_request_response_bind_full_domain_tuple() {
    // Changing ANY bound field changes the canonical digest, so the
    // response (which echoes the original digest) no longer validates.
    let s = scenario(TrustBundleEnvironment::Devnet);
    let base = s.request.canonical_digest();

    let mut wrong_env = s.request.clone();
    wrong_env.environment = TrustBundleEnvironment::Testnet;
    assert_ne!(wrong_env.canonical_digest(), base);

    let mut wrong_chain = s.request.clone();
    wrong_chain.chain_id = OTHER_CHAIN.to_string();
    assert_ne!(wrong_chain.canonical_digest(), base);

    let mut wrong_genesis = s.request.clone();
    wrong_genesis.genesis_hash = OTHER_GENESIS.to_string();
    assert_ne!(wrong_genesis.canonical_digest(), base);

    let mut wrong_root = s.request.clone();
    wrong_root.authority_root_fingerprint = OTHER_ROOT_FP.to_string();
    assert_ne!(wrong_root.canonical_digest(), base);

    let mut wrong_action = s.request.clone();
    wrong_action.lifecycle_action = LocalLifecycleAction::Revoke;
    assert_ne!(wrong_action.canonical_digest(), base);

    let mut wrong_cand = s.request.clone();
    wrong_cand.candidate_digest = DIGEST_OTHER.to_string();
    assert_ne!(wrong_cand.canonical_digest(), base);

    let mut wrong_seq = s.request.clone();
    wrong_seq.authority_domain_sequence = 99;
    assert_ne!(wrong_seq.canonical_digest(), base);
}

#[test]
fn a4_remote_signer_custody_class_routes_into_boundary() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    assert!(custody_class_routes_to_remote_signer(
        AuthorityCustodyClass::RemoteSigner
    ));
    assert!(!custody_class_routes_to_remote_signer(
        AuthorityCustodyClass::FixtureLocalKey
    ));
    let outcome = validate_remote_signer_for_custody_class(
        AuthorityCustodyClass::RemoteSigner,
        &s.identity,
        &s.request,
        &s.response,
        &s.domain,
        &s.expected,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    assert_eq!(
        outcome,
        RemoteSignerOutcome::FixtureLoopbackAccepted {
            signer_id: SIGNER_ID.to_string(),
            environment: TrustBundleEnvironment::Devnet,
        }
    );
}

#[test]
fn a5_combined_lifecycle_governance_custody_and_fixture_remote_signer_accepted_devnet() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    let custody = good_custody_attestation(
        TrustBundleEnvironment::Devnet,
        &s.candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let prior = prior_versioned(TrustBundleEnvironment::Devnet);
    let outcome = validate_lifecycle_governance_custody_and_remote_signer(
        &custody,
        &s.candidate,
        Some(&prior),
        &s.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        &s.identity,
        &s.request,
        &s.response,
        &s.expected,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        NOW,
        false,
    );
    assert!(outcome.is_accept(), "expected accept, got {outcome:?}");
    assert!(matches!(
        outcome,
        LifecycleCustodyRemoteSignerOutcome::Accepted { .. }
    ));
}

#[test]
fn a6_disabled_policy_does_not_disturb_governance_classes() {
    // When the remote signer policy is Disabled, every request fails
    // closed as Disabled regardless of the governance authority class
    // bound elsewhere — the boundary never elevates or alters
    // GenesisBound / EmergencyCouncil / OnChainGovernance behavior.
    for env in [TrustBundleEnvironment::Devnet, TrustBundleEnvironment::Testnet] {
        let s = scenario(env);
        assert_eq!(
            validate(&s, RemoteSignerPolicy::Disabled),
            RemoteSignerOutcome::Disabled
        );
    }
}

#[test]
fn a7_production_remote_signer_callable_returns_unavailable() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let prod = ProductionRemoteSigner {
        identity: identity(TrustBundleEnvironment::Devnet, &candidate),
    };
    let req = request(TrustBundleEnvironment::Devnet, &candidate);
    let result = prod.sign(&req);
    assert_eq!(
        result,
        Err(RemoteSignerOutcome::ProductionRemoteSignerUnavailable)
    );
    // The boundary is reachable through the trait object.
    let dyn_signer: &dyn RemoteAuthoritySigner = &prod;
    assert_eq!(dyn_signer.identity().signer_id, SIGNER_ID);
    assert!(dyn_signer.sign(&req).is_err());
}

// ===========================================================================
// Rejection scenarios R1–R31
// ===========================================================================

#[test]
fn r1_rejected_under_disabled() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    assert_eq!(
        validate(&s, RemoteSignerPolicy::Disabled),
        RemoteSignerOutcome::Disabled
    );
}

#[test]
fn r2_fixture_rejected_under_production_required() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    assert_eq!(
        validate(&s, RemoteSignerPolicy::ProductionRemoteSignerRequired),
        RemoteSignerOutcome::FixtureRejectedProductionRequired
    );
}

#[test]
fn r3_fixture_rejected_under_mainnet_production_required() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    assert_eq!(
        validate(&s, RemoteSignerPolicy::MainnetProductionRemoteSignerRequired),
        RemoteSignerOutcome::FixtureRejectedMainnetProductionRequired
    );
}

#[test]
fn r4_production_rejected_as_unavailable() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    // A production-mode response under any non-Disabled policy is
    // unavailable.
    s.response.signer_mode = RemoteSignerMode::Production;
    assert_eq!(
        validate(&s, RemoteSignerPolicy::ProductionRemoteSignerRequired),
        RemoteSignerOutcome::ProductionRemoteSignerUnavailable
    );
    assert_eq!(
        validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed),
        RemoteSignerOutcome::ProductionRemoteSignerUnavailable
    );
}

#[test]
fn r5_mainnet_production_rejected_as_unavailable() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.response.signer_mode = RemoteSignerMode::Production;
    assert_eq!(
        validate(&s, RemoteSignerPolicy::MainnetProductionRemoteSignerRequired),
        RemoteSignerOutcome::MainNetProductionRemoteSignerUnavailable
    );
}

#[test]
fn r6_wrong_environment_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.request.environment = TrustBundleEnvironment::Testnet;
    s.identity.environment = TrustBundleEnvironment::Testnet;
    // Recompute the response digest so we reach the environment check
    // (not the request-digest check).
    let signer = FixtureLoopbackRemoteSigner {
        identity: s.identity.clone(),
        response_nonce: RESP_NONCE.to_string(),
        response_freshness_unix: Some(FRESH),
        response_expires_at_unix: Some(EXPIRES),
    };
    s.response = signer.sign(&s.request).unwrap();
    assert!(matches!(
        validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed),
        RemoteSignerOutcome::WrongEnvironment { .. }
    ));
}

#[test]
fn r7_wrong_chain_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.request.chain_id = OTHER_CHAIN.to_string();
    s.identity.chain_id = OTHER_CHAIN.to_string();
    s.response.request_digest = s.request.canonical_digest();
    assert!(matches!(
        validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed),
        RemoteSignerOutcome::WrongChain { .. }
    ));
}

#[test]
fn r8_wrong_genesis_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.request.genesis_hash = OTHER_GENESIS.to_string();
    s.identity.genesis_hash = OTHER_GENESIS.to_string();
    s.response.request_digest = s.request.canonical_digest();
    assert!(matches!(
        validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed),
        RemoteSignerOutcome::WrongGenesis { .. }
    ));
}

#[test]
fn r9_wrong_authority_root_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.request.authority_root_fingerprint = OTHER_ROOT_FP.to_string();
    s.identity.authority_root_fingerprint = OTHER_ROOT_FP.to_string();
    s.response.request_digest = s.request.canonical_digest();
    assert!(matches!(
        validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed),
        RemoteSignerOutcome::WrongAuthorityRoot { .. }
    ));
}

#[test]
fn r10_wrong_custody_key_id_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.identity.custody_key_id = "other-key".to_string();
    s.response.custody_key_id = "other-key".to_string();
    assert!(matches!(
        validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed),
        RemoteSignerOutcome::WrongCustodyKeyId { .. }
    ));
}

#[test]
fn r11_wrong_signing_key_fingerprint_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.request.new_signing_key_fingerprint = Some("ffffffffffffffffffffffffffffffffffffffff".to_string());
    s.response.request_digest = s.request.canonical_digest();
    assert!(matches!(
        validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed),
        RemoteSignerOutcome::WrongSigningKeyFingerprint { .. }
    ));
}

#[test]
fn r12_wrong_lifecycle_action_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.request.lifecycle_action = LocalLifecycleAction::Revoke;
    s.response.request_digest = s.request.canonical_digest();
    assert!(matches!(
        validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed),
        RemoteSignerOutcome::WrongLifecycleAction { .. }
    ));
}

#[test]
fn r13_wrong_candidate_digest_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.request.candidate_digest = DIGEST_OTHER.to_string();
    s.response.request_digest = s.request.canonical_digest();
    assert!(matches!(
        validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed),
        RemoteSignerOutcome::WrongCandidateDigest { .. }
    ));
}

#[test]
fn r14_wrong_authority_domain_sequence_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.request.authority_domain_sequence = 99;
    s.response.request_digest = s.request.canonical_digest();
    assert!(matches!(
        validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed),
        RemoteSignerOutcome::WrongAuthorityDomainSequence { .. }
    ));
}

#[test]
fn r15_wrong_request_digest_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    // Tamper with the echoed digest only.
    s.response.request_digest = "deadbeef".to_string();
    assert!(matches!(
        validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed),
        RemoteSignerOutcome::WrongRequestDigest { .. }
    ));
}

#[test]
fn r16_stale_or_replayed_request_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.request.replay_nonce = "replayed-nonce".to_string();
    s.response.request_digest = s.request.canonical_digest();
    assert!(matches!(
        validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed),
        RemoteSignerOutcome::StaleOrReplayedRequest { .. }
    ));
}

#[test]
fn r17_stale_or_replayed_response_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.response.response_nonce = "replayed-resp".to_string();
    assert!(matches!(
        validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed),
        RemoteSignerOutcome::StaleOrReplayedResponse { .. }
    ));
}

#[test]
fn r18_expired_attestation_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    // now is past the identity expiry window.
    s.expected.now_unix = EXPIRES + 1;
    assert_eq!(
        validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed),
        RemoteSignerOutcome::ExpiredAttestation {
            now_unix: EXPIRES + 1
        }
    );
}

#[test]
fn r19_expired_response_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    // Keep identity window open but expire the response window.
    s.identity.freshness_unix = None;
    s.identity.expires_at_unix = None;
    s.response.freshness_unix = Some(FRESH);
    s.response.expires_at_unix = Some(NOW - 1);
    assert_eq!(
        validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed),
        RemoteSignerOutcome::ExpiredResponse { now_unix: NOW }
    );
}

#[test]
fn r20_unsupported_suite_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.response.signature_suite_id = 7;
    assert_eq!(
        validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed),
        RemoteSignerOutcome::UnsupportedSuite { suite_id: 7 }
    );
}

#[test]
fn r21_invalid_signature_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.response.signature_commitment = REMOTE_SIGNER_INVALID_SIGNATURE_SENTINEL.to_string();
    assert_eq!(
        validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed),
        RemoteSignerOutcome::InvalidSignature
    );
}

#[test]
fn r22_malformed_request_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.request.replay_nonce = String::new();
    s.response.request_digest = s.request.canonical_digest();
    assert!(matches!(
        validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed),
        RemoteSignerOutcome::MalformedRequest { .. }
    ));
}

#[test]
fn r23_malformed_response_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.response.signature_commitment = String::new();
    assert!(matches!(
        validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed),
        RemoteSignerOutcome::MalformedResponse { .. }
    ));
}

#[test]
fn r24_local_operator_key_cannot_satisfy_remote_signer() {
    assert!(local_operator_key_cannot_satisfy_remote_signer());
    let s = scenario(TrustBundleEnvironment::Devnet);
    let outcome = validate_remote_signer_for_custody_class(
        AuthorityCustodyClass::LocalOperatorKey,
        &s.identity,
        &s.request,
        &s.response,
        &s.domain,
        &s.expected,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    assert_eq!(
        outcome,
        RemoteSignerOutcome::LocalOperatorKeyCannotSatisfyRemoteSigner
    );
}

#[test]
fn r25_peer_majority_cannot_satisfy_remote_signer() {
    assert!(peer_majority_cannot_satisfy_remote_signer());
}

#[test]
fn r26_remote_signer_valid_but_custody_metadata_invalid_rejected() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    // Custody attestation with a mismatched custody key id => Run 188
    // custody rejects, so the composition rejects before the remote
    // signer can accept.
    let mut custody = good_custody_attestation(
        TrustBundleEnvironment::Devnet,
        &s.candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    custody.custody_key_id = "wrong-custody-key".to_string();
    let prior = prior_versioned(TrustBundleEnvironment::Devnet);
    let outcome = validate_lifecycle_governance_custody_and_remote_signer(
        &custody,
        &s.candidate,
        Some(&prior),
        &s.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        &s.identity,
        &s.request,
        &s.response,
        &s.expected,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        NOW,
        false,
    );
    assert!(outcome.is_reject());
    assert!(matches!(
        outcome,
        LifecycleCustodyRemoteSignerOutcome::LifecycleOrCustodyRejected(_)
    ));
}

#[test]
fn r27_custody_valid_but_remote_signer_response_invalid_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    // Valid custody but tamper the remote signer response digest.
    s.response.request_digest = "deadbeef".to_string();
    let custody = good_custody_attestation(
        TrustBundleEnvironment::Devnet,
        &s.candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let prior = prior_versioned(TrustBundleEnvironment::Devnet);
    let outcome = validate_lifecycle_governance_custody_and_remote_signer(
        &custody,
        &s.candidate,
        Some(&prior),
        &s.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        &s.identity,
        &s.request,
        &s.response,
        &s.expected,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        NOW,
        false,
    );
    assert!(matches!(
        outcome,
        LifecycleCustodyRemoteSignerOutcome::RemoteSignerRejected { .. }
    ));
}

#[test]
fn r28_lifecycle_governance_custody_valid_production_remote_signer_unavailable_rejected() {
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    // Production-mode response under FixtureLoopbackAllowed => the
    // remote signer is unavailable even though lifecycle + custody pass.
    s.response.signer_mode = RemoteSignerMode::Production;
    let custody = good_custody_attestation(
        TrustBundleEnvironment::Devnet,
        &s.candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let prior = prior_versioned(TrustBundleEnvironment::Devnet);
    let outcome = validate_lifecycle_governance_custody_and_remote_signer(
        &custody,
        &s.candidate,
        Some(&prior),
        &s.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        &s.identity,
        &s.request,
        &s.response,
        &s.expected,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        NOW,
        false,
    );
    match outcome {
        LifecycleCustodyRemoteSignerOutcome::RemoteSignerRejected {
            remote_signer_outcome,
            ..
        } => assert_eq!(
            remote_signer_outcome,
            RemoteSignerOutcome::ProductionRemoteSignerUnavailable
        ),
        other => panic!("expected RemoteSignerRejected, got {other:?}"),
    }
}

#[test]
fn r29_mainnet_peer_driven_apply_refused_even_with_fixture_loopback() {
    // The helper refuses MainNet regardless of fixture loopback success.
    assert!(mainnet_peer_driven_apply_remains_refused_under_remote_signer_boundary(
        TrustBundleEnvironment::Mainnet
    ));
    assert!(!mainnet_peer_driven_apply_remains_refused_under_remote_signer_boundary(
        TrustBundleEnvironment::Devnet
    ));

    // A MainNet fixture loopback round-trip is refused at the verifier.
    let s = scenario(TrustBundleEnvironment::Mainnet);
    assert_eq!(
        validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed),
        RemoteSignerOutcome::FixtureLoopbackRejectedForMainNet
    );

    // And the composition helper short-circuits the MainNet preflight.
    let custody = good_custody_attestation(
        TrustBundleEnvironment::Mainnet,
        &s.candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let outcome = validate_lifecycle_governance_custody_and_remote_signer(
        &custody,
        &s.candidate,
        None,
        &s.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        &s.identity,
        &s.request,
        &s.response,
        &s.expected,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        NOW,
        true,
    );
    assert_eq!(
        outcome,
        LifecycleCustodyRemoteSignerOutcome::MainNetPeerDrivenApplyRefused
    );
}

#[test]
fn r30_validation_only_rejection_is_non_mutating() {
    // Build a scenario, snapshot every input, run a rejecting
    // validation, then assert nothing changed. The validators take
    // shared references and return owned outcomes — they cannot mutate.
    let s = scenario(TrustBundleEnvironment::Devnet);
    let candidate_before = s.candidate.clone();
    let identity_before = s.identity.clone();
    let request_before = s.request.clone();
    let response_before = s.response.clone();

    let _ = validate(&s, RemoteSignerPolicy::Disabled);
    let _ = validate(&s, RemoteSignerPolicy::ProductionRemoteSignerRequired);

    assert_eq!(s.candidate, candidate_before);
    assert_eq!(s.identity, identity_before);
    assert_eq!(s.request, request_before);
    assert_eq!(s.response, response_before);
}

#[test]
fn r31_mutating_preflight_rejection_produces_no_mutation() {
    // The composition helper is validation-only: a rejecting preflight
    // produces no Run 070 call, no live trust swap, no session
    // eviction, no sequence write, and no marker write — there is no
    // such surface in this module to invoke. We assert the typed reject
    // and that all inputs are byte-for-byte unchanged.
    let mut s = scenario(TrustBundleEnvironment::Devnet);
    s.response.signer_mode = RemoteSignerMode::Production;
    let candidate_before = s.candidate.clone();
    let request_before = s.request.clone();
    let response_before = s.response.clone();

    let custody = good_custody_attestation(
        TrustBundleEnvironment::Devnet,
        &s.candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let custody_before = custody.clone();
    let prior = prior_versioned(TrustBundleEnvironment::Devnet);
    let outcome = validate_lifecycle_governance_custody_and_remote_signer(
        &custody,
        &s.candidate,
        Some(&prior),
        &s.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        &s.identity,
        &s.request,
        &s.response,
        &s.expected,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        NOW,
        false,
    );
    assert!(outcome.is_reject());
    assert_eq!(s.candidate, candidate_before);
    assert_eq!(s.request, request_before);
    assert_eq!(s.response, response_before);
    assert_eq!(custody, custody_before);
}

// ===========================================================================
// Canonical digest determinism / replay / fixture-vs-production
// ===========================================================================

#[test]
fn canonical_digest_is_deterministic_and_field_sensitive() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let req = request(TrustBundleEnvironment::Devnet, &candidate);
    // Determinism: same request hashes identically across calls and
    // across clones.
    assert_eq!(req.canonical_digest(), req.canonical_digest());
    assert_eq!(req.clone().canonical_digest(), req.canonical_digest());
    // Field sensitivity: the optional governance proof digest changes
    // the digest.
    let mut with_gov = req.clone();
    with_gov.governance_proof_digest = Some("gov-proof".to_string());
    assert_ne!(with_gov.canonical_digest(), req.canonical_digest());
    // And the anti-replay nonce changes the digest.
    let mut with_nonce = req.clone();
    with_nonce.replay_nonce = "different".to_string();
    assert_ne!(with_nonce.canonical_digest(), req.canonical_digest());
}

#[test]
fn fixture_and_production_signers_are_separated() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let fixture = fixture_signer(TrustBundleEnvironment::Devnet, &candidate);
    let req = request(TrustBundleEnvironment::Devnet, &candidate);
    let resp = fixture.sign(&req).unwrap();
    assert_eq!(resp.signer_mode, RemoteSignerMode::FixtureLoopback);

    let prod = ProductionRemoteSigner {
        identity: identity(TrustBundleEnvironment::Devnet, &candidate),
    };
    assert_eq!(
        prod.sign(&req),
        Err(RemoteSignerOutcome::ProductionRemoteSignerUnavailable)
    );
}

#[test]
fn fixture_loopback_response_echoes_request_digest() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let fixture = fixture_signer(TrustBundleEnvironment::Devnet, &candidate);
    let req = request(TrustBundleEnvironment::Devnet, &candidate);
    let resp = fixture.sign(&req).unwrap();
    assert_eq!(resp.request_digest, req.canonical_digest());
    assert_eq!(resp.signer_id, SIGNER_ID);
    assert_eq!(resp.custody_key_id, CUSTODY_KEY_ID);
}

#[test]
fn not_remote_signer_custody_class_does_not_route() {
    let s = scenario(TrustBundleEnvironment::Devnet);
    for class in [
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyClass::Kms,
        AuthorityCustodyClass::Hsm,
        AuthorityCustodyClass::Unknown,
    ] {
        let outcome = validate_remote_signer_for_custody_class(
            class,
            &s.identity,
            &s.request,
            &s.response,
            &s.domain,
            &s.expected,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
        );
        assert_eq!(
            outcome,
            RemoteSignerOutcome::NotRemoteSignerCustodyClass { class }
        );
    }
}