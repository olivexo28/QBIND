//! Run 195 — release-built helper that exercises the Run 194 RemoteSigner
//! production-custody interface boundary **in release mode** through the
//! production library symbols
//! [`qbind_node::pqc_remote_authority_signer`] layered over the Run 188
//! [`qbind_node::pqc_authority_custody`] boundary.
//!
//! Per `task/RUN_195_TASK.txt`, Run 195 is the release-binary evidence
//! run for the Run 194 source/test RemoteSigner production-custody
//! interface boundary. This helper is fixture-only tooling and:
//!
//! * does NOT modify any production runtime code, CLI flag, env var,
//!   wire / marker / sequence / trust-bundle / peer-candidate-envelope
//!   schema beyond what Runs 070, 130–194 already established;
//! * does NOT enable MainNet peer-driven apply on any surface;
//! * does NOT mutate any live trust state, write any marker, advance
//!   any sequence, swap any live trust, evict any session, or invoke
//!   Run 070;
//! * does NOT open any P2P socket;
//! * does NOT implement any real RemoteSigner backend, networked signer
//!   service, real KMS, real HSM, cloud KMS, or PKCS#11 integration; the
//!   [`qbind_node::pqc_remote_authority_signer::ProductionRemoteSigner`]
//!   placeholder always returns the typed
//!   `RemoteSignerOutcome::ProductionRemoteSignerUnavailable` reject;
//! * never elevates the DevNet/TestNet
//!   [`qbind_node::pqc_remote_authority_signer::FixtureLoopbackRemoteSigner`]
//!   into MainNet production custody (MainNet always refuses at the
//!   typed boundary);
//! * exists alongside (and does NOT replace) the Run 194 source/test
//!   target
//!   `crates/qbind-node/tests/run_194_remote_authority_signer_boundary_tests.rs`.
//!
//! The helper writes the following files under `<OUT_DIR>/`:
//!
//! ```text
//! <OUT_DIR>/manifest.txt              # one row per scenario
//! <OUT_DIR>/expected_outcomes.txt
//! <OUT_DIR>/actual_outcomes.txt
//! <OUT_DIR>/scenarios/<id>/{note,expected,actual}.txt
//! <OUT_DIR>/canonical_digest_table.txt
//! <OUT_DIR>/policy_mode_table.txt
//! <OUT_DIR>/custody_routing_table.txt
//! <OUT_DIR>/composition_table.txt
//! <OUT_DIR>/refusal_helpers_table.txt
//! <OUT_DIR>/no_mutation_evidence.txt
//! <OUT_DIR>/determinism_evidence.txt
//! <OUT_DIR>/fixtures/{request,response}.json
//! <OUT_DIR>/helper_summary.txt
//! ```
//!
//! The helper exits non-zero if any scenario does not match its
//! expected typed outcome.
//!
//! Usage:
//! ```text
//! run_195_remote_authority_signer_boundary_release_binary_helper <OUT_DIR>
//! ```

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

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
    custody_class_routes_to_remote_signer, local_operator_key_cannot_satisfy_remote_signer,
    mainnet_peer_driven_apply_remains_refused_under_remote_signer_boundary,
    peer_majority_cannot_satisfy_remote_signer,
    validate_lifecycle_governance_custody_and_remote_signer, validate_remote_signer,
    validate_remote_signer_for_custody_class, FixtureLoopbackRemoteSigner,
    LifecycleCustodyRemoteSignerOutcome, ProductionRemoteSigner, RemoteAuthoritySigner,
    RemoteSignerExpectations, RemoteSignerIdentity, RemoteSignerMode, RemoteSignerOutcome,
    RemoteSignerPolicy, RemoteSignerRequest, RemoteSignerResponse,
    REMOTE_SIGNER_INVALID_SIGNATURE_SENTINEL,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ---------------------------------------------------------------------------
// Constants — kept structurally identical to the Run 194 source/test
// fixtures (`tests/run_194_remote_authority_signer_boundary_tests.rs`) so
// the typed RemoteSigner boundary semantics carry over end-to-end in
// release mode.
// ---------------------------------------------------------------------------

const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT_FP: &str = "1111111111111111111111111111111111111111";
const OTHER_ROOT_FP: &str = "9999999999999999999999999999999999999999";
const CHAIN_ID: &str = "0000000000000001";
const OTHER_CHAIN: &str = "00000000000000ff";
const GENESIS_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_GENESIS: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DIGEST_OTHER: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const PRIOR_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
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

// ---------------------------------------------------------------------------
// Fixture builders — mirror `tests/run_194_remote_authority_signer_boundary_tests.rs`.
// ---------------------------------------------------------------------------

fn domain_for(env: TrustBundleEnvironment) -> AuthorityTrustDomain {
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

fn identity(
    env: TrustBundleEnvironment,
    candidate: &PersistentAuthorityStateRecordV2,
) -> RemoteSignerIdentity {
    RemoteSignerIdentity {
        signer_id: SIGNER_ID.to_string(),
        signer_public_identity: SIGNER_PUBID.to_string(),
        custody_key_id: CUSTODY_KEY_ID.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        bundle_signing_key_fingerprint: candidate.active_bundle_signing_key_fingerprint.clone(),
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

fn request(
    env: TrustBundleEnvironment,
    candidate: &PersistentAuthorityStateRecordV2,
) -> RemoteSignerRequest {
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

fn fixture_signer(
    env: TrustBundleEnvironment,
    candidate: &PersistentAuthorityStateRecordV2,
) -> FixtureLoopbackRemoteSigner {
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
        bundle_signing_key_fingerprint: candidate.active_bundle_signing_key_fingerprint.clone(),
        governance_authority_class: GovernanceAuthorityClass::GenesisBound,
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: DIGEST_2.to_string(),
        authority_domain_sequence: 2,
    }
}

/// Complete, valid accepted scenario for `env`, mirroring the Run 194
/// `Scenario` test helper.
#[derive(Clone)]
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
        domain: domain_for(env),
        identity: identity(env, &candidate),
        expected: expectations(&candidate),
        request,
        response,
        candidate,
    }
}

fn validate(s: &Scenario, policy: RemoteSignerPolicy) -> RemoteSignerOutcome {
    validate_remote_signer(&s.identity, &s.request, &s.response, &s.domain, &s.expected, policy)
}

// ---------------------------------------------------------------------------
// Symbolic expected outcome — a coarse tag we can compare against the
// typed `RemoteSignerOutcome` without echoing inner mismatch payloads.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    FixtureLoopbackAccepted,
    Disabled,
    FixtureRejectedProductionRequired,
    FixtureRejectedMainnetProductionRequired,
    ProductionRemoteSignerUnavailable,
    MainNetProductionRemoteSignerUnavailable,
    FixtureLoopbackRejectedForMainNet,
    WrongEnvironment,
    WrongChain,
    WrongGenesis,
    WrongAuthorityRoot,
    WrongCustodyKeyId,
    WrongSigningKeyFingerprint,
    WrongLifecycleAction,
    WrongCandidateDigest,
    WrongAuthorityDomainSequence,
    WrongRequestDigest,
    StaleOrReplayedRequest,
    StaleOrReplayedResponse,
    ExpiredAttestation,
    ExpiredResponse,
    UnsupportedSuite,
    InvalidSignature,
    MalformedRequest,
    MalformedResponse,
    LocalOperatorKeyCannotSatisfyRemoteSigner,
    NotRemoteSignerCustodyClass,
}

fn matches_expect(actual: &RemoteSignerOutcome, expected: Expect) -> bool {
    use RemoteSignerOutcome as O;
    matches!(
        (actual, expected),
        (O::FixtureLoopbackAccepted { .. }, Expect::FixtureLoopbackAccepted)
            | (O::Disabled, Expect::Disabled)
            | (
                O::FixtureRejectedProductionRequired,
                Expect::FixtureRejectedProductionRequired
            )
            | (
                O::FixtureRejectedMainnetProductionRequired,
                Expect::FixtureRejectedMainnetProductionRequired
            )
            | (
                O::ProductionRemoteSignerUnavailable,
                Expect::ProductionRemoteSignerUnavailable
            )
            | (
                O::MainNetProductionRemoteSignerUnavailable,
                Expect::MainNetProductionRemoteSignerUnavailable
            )
            | (
                O::FixtureLoopbackRejectedForMainNet,
                Expect::FixtureLoopbackRejectedForMainNet
            )
            | (O::WrongEnvironment { .. }, Expect::WrongEnvironment)
            | (O::WrongChain { .. }, Expect::WrongChain)
            | (O::WrongGenesis { .. }, Expect::WrongGenesis)
            | (O::WrongAuthorityRoot { .. }, Expect::WrongAuthorityRoot)
            | (O::WrongCustodyKeyId { .. }, Expect::WrongCustodyKeyId)
            | (
                O::WrongSigningKeyFingerprint { .. },
                Expect::WrongSigningKeyFingerprint
            )
            | (O::WrongLifecycleAction { .. }, Expect::WrongLifecycleAction)
            | (O::WrongCandidateDigest { .. }, Expect::WrongCandidateDigest)
            | (
                O::WrongAuthorityDomainSequence { .. },
                Expect::WrongAuthorityDomainSequence
            )
            | (O::WrongRequestDigest { .. }, Expect::WrongRequestDigest)
            | (O::StaleOrReplayedRequest { .. }, Expect::StaleOrReplayedRequest)
            | (O::StaleOrReplayedResponse { .. }, Expect::StaleOrReplayedResponse)
            | (O::ExpiredAttestation { .. }, Expect::ExpiredAttestation)
            | (O::ExpiredResponse { .. }, Expect::ExpiredResponse)
            | (O::UnsupportedSuite { .. }, Expect::UnsupportedSuite)
            | (O::InvalidSignature, Expect::InvalidSignature)
            | (O::MalformedRequest { .. }, Expect::MalformedRequest)
            | (O::MalformedResponse { .. }, Expect::MalformedResponse)
            | (
                O::LocalOperatorKeyCannotSatisfyRemoteSigner,
                Expect::LocalOperatorKeyCannotSatisfyRemoteSigner
            )
            | (
                O::NotRemoteSignerCustodyClass { .. },
                Expect::NotRemoteSignerCustodyClass
            )
    )
}

// ---------------------------------------------------------------------------
// Scenario corpus (A1..A7 / R1..R31 from `task/RUN_195_TASK.txt`).
//
// Each scenario produces a single `RemoteSignerOutcome` via the typed
// verifier `validate_remote_signer` (or the custody-class router) and
// is compared against its symbolic `Expect`. The composition-helper
// scenarios (A5 / R26 / R27 / R28 / R29) are exercised in
// `run_composition_table` because they yield the richer
// `LifecycleCustodyRemoteSignerOutcome`.
// ---------------------------------------------------------------------------

/// A small recipe describing how to mutate a fresh scenario before
/// validation. We deliberately re-derive the fixture-loopback response
/// after binding-field edits (exactly like the Run 194 tests) so each
/// rejection reaches the intended verifier check rather than tripping
/// the request-digest echo guard first.
#[derive(Clone)]
struct ScenarioCase {
    id: &'static str,
    note: &'static str,
    env: TrustBundleEnvironment,
    policy: RemoteSignerPolicy,
    /// Routing class: `None` => call `validate_remote_signer` directly;
    /// `Some(class)` => call `validate_remote_signer_for_custody_class`.
    route_class: Option<AuthorityCustodyClass>,
    mutate: fn(&mut Scenario),
    expected: Expect,
}

fn noop(_s: &mut Scenario) {}

/// Re-sign the fixture response so it echoes the (possibly mutated)
/// request digest and carries the canonical fixture-loopback nonces.
fn resign(s: &mut Scenario) {
    let signer = FixtureLoopbackRemoteSigner {
        identity: s.identity.clone(),
        response_nonce: RESP_NONCE.to_string(),
        response_freshness_unix: Some(FRESH),
        response_expires_at_unix: Some(EXPIRES),
    };
    if let Ok(resp) = signer.sign(&s.request) {
        s.response = resp;
    }
}

fn corpus() -> Vec<ScenarioCase> {
    use TrustBundleEnvironment::*;
    vec![
        // ===================== A1..A4 / A6 / A7 ======================
        ScenarioCase {
            id: "A1_fixture_loopback_accepted_devnet",
            note: "fixture loopback accepted under FixtureLoopbackAllowed on DevNet",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: None,
            mutate: noop,
            expected: Expect::FixtureLoopbackAccepted,
        },
        ScenarioCase {
            id: "A2_fixture_loopback_accepted_testnet",
            note: "fixture loopback accepted under FixtureLoopbackAllowed on TestNet",
            env: Testnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: None,
            mutate: noop,
            expected: Expect::FixtureLoopbackAccepted,
        },
        ScenarioCase {
            id: "A4_remote_signer_custody_class_routes_into_boundary",
            note: "AuthorityCustodyClass::RemoteSigner routes into the boundary and accepts",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: Some(AuthorityCustodyClass::RemoteSigner),
            mutate: noop,
            expected: Expect::FixtureLoopbackAccepted,
        },
        ScenarioCase {
            id: "A6_disabled_policy_devnet_fails_closed",
            note: "Disabled policy fails closed without disturbing governance classes (DevNet)",
            env: Devnet,
            policy: RemoteSignerPolicy::Disabled,
            route_class: None,
            mutate: noop,
            expected: Expect::Disabled,
        },
        ScenarioCase {
            id: "A6_disabled_policy_testnet_fails_closed",
            note: "Disabled policy fails closed without disturbing governance classes (TestNet)",
            env: Testnet,
            policy: RemoteSignerPolicy::Disabled,
            route_class: None,
            mutate: noop,
            expected: Expect::Disabled,
        },
        ScenarioCase {
            id: "A7_production_signer_typed_unavailable",
            note: "production-mode response under FixtureLoopbackAllowed => typed unavailable",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: None,
            mutate: |s| s.response.signer_mode = RemoteSignerMode::Production,
            expected: Expect::ProductionRemoteSignerUnavailable,
        },
        // ============================ R1..R25 ========================
        ScenarioCase {
            id: "R1_rejected_under_disabled",
            note: "fixture loopback rejected under Disabled policy",
            env: Devnet,
            policy: RemoteSignerPolicy::Disabled,
            route_class: None,
            mutate: noop,
            expected: Expect::Disabled,
        },
        ScenarioCase {
            id: "R2_fixture_rejected_production_required",
            note: "fixture loopback rejected under ProductionRemoteSignerRequired",
            env: Devnet,
            policy: RemoteSignerPolicy::ProductionRemoteSignerRequired,
            route_class: None,
            mutate: noop,
            expected: Expect::FixtureRejectedProductionRequired,
        },
        ScenarioCase {
            id: "R3_fixture_rejected_mainnet_production_required",
            note: "fixture loopback rejected under MainnetProductionRemoteSignerRequired",
            env: Devnet,
            policy: RemoteSignerPolicy::MainnetProductionRemoteSignerRequired,
            route_class: None,
            mutate: noop,
            expected: Expect::FixtureRejectedMainnetProductionRequired,
        },
        ScenarioCase {
            id: "R4_production_rejected_unavailable",
            note: "production-mode response under ProductionRemoteSignerRequired => unavailable",
            env: Devnet,
            policy: RemoteSignerPolicy::ProductionRemoteSignerRequired,
            route_class: None,
            mutate: |s| s.response.signer_mode = RemoteSignerMode::Production,
            expected: Expect::ProductionRemoteSignerUnavailable,
        },
        ScenarioCase {
            id: "R5_mainnet_production_rejected_unavailable",
            note: "production-mode response under MainnetProductionRemoteSignerRequired => unavailable",
            env: Devnet,
            policy: RemoteSignerPolicy::MainnetProductionRemoteSignerRequired,
            route_class: None,
            mutate: |s| s.response.signer_mode = RemoteSignerMode::Production,
            expected: Expect::MainNetProductionRemoteSignerUnavailable,
        },
        ScenarioCase {
            id: "R6_wrong_environment_rejected",
            note: "wrong environment rejected",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: None,
            mutate: |s| {
                s.request.environment = TrustBundleEnvironment::Testnet;
                s.identity.environment = TrustBundleEnvironment::Testnet;
                resign(s);
            },
            expected: Expect::WrongEnvironment,
        },
        ScenarioCase {
            id: "R7_wrong_chain_rejected",
            note: "wrong chain rejected",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: None,
            mutate: |s| {
                s.request.chain_id = OTHER_CHAIN.to_string();
                s.identity.chain_id = OTHER_CHAIN.to_string();
                s.response.request_digest = s.request.canonical_digest();
            },
            expected: Expect::WrongChain,
        },
        ScenarioCase {
            id: "R8_wrong_genesis_rejected",
            note: "wrong genesis rejected",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: None,
            mutate: |s| {
                s.request.genesis_hash = OTHER_GENESIS.to_string();
                s.identity.genesis_hash = OTHER_GENESIS.to_string();
                s.response.request_digest = s.request.canonical_digest();
            },
            expected: Expect::WrongGenesis,
        },
        ScenarioCase {
            id: "R9_wrong_authority_root_rejected",
            note: "wrong authority root rejected",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: None,
            mutate: |s| {
                s.request.authority_root_fingerprint = OTHER_ROOT_FP.to_string();
                s.identity.authority_root_fingerprint = OTHER_ROOT_FP.to_string();
                s.response.request_digest = s.request.canonical_digest();
            },
            expected: Expect::WrongAuthorityRoot,
        },
        ScenarioCase {
            id: "R10_wrong_custody_key_id_rejected",
            note: "wrong custody key id rejected",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: None,
            mutate: |s| {
                s.identity.custody_key_id = "other-key".to_string();
                s.response.custody_key_id = "other-key".to_string();
            },
            expected: Expect::WrongCustodyKeyId,
        },
        ScenarioCase {
            id: "R11_wrong_signing_key_fingerprint_rejected",
            note: "wrong signing-key fingerprint rejected",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: None,
            mutate: |s| {
                s.request.new_signing_key_fingerprint =
                    Some("ffffffffffffffffffffffffffffffffffffffff".to_string());
                s.response.request_digest = s.request.canonical_digest();
            },
            expected: Expect::WrongSigningKeyFingerprint,
        },
        ScenarioCase {
            id: "R12_wrong_lifecycle_action_rejected",
            note: "wrong lifecycle action rejected",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: None,
            mutate: |s| {
                s.request.lifecycle_action = LocalLifecycleAction::Revoke;
                s.response.request_digest = s.request.canonical_digest();
            },
            expected: Expect::WrongLifecycleAction,
        },
        ScenarioCase {
            id: "R13_wrong_candidate_digest_rejected",
            note: "wrong candidate digest rejected",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: None,
            mutate: |s| {
                s.request.candidate_digest = DIGEST_OTHER.to_string();
                s.response.request_digest = s.request.canonical_digest();
            },
            expected: Expect::WrongCandidateDigest,
        },
        ScenarioCase {
            id: "R14_wrong_authority_domain_sequence_rejected",
            note: "wrong authority-domain sequence rejected",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: None,
            mutate: |s| {
                s.request.authority_domain_sequence = 99;
                s.response.request_digest = s.request.canonical_digest();
            },
            expected: Expect::WrongAuthorityDomainSequence,
        },
        ScenarioCase {
            id: "R15_wrong_request_digest_rejected",
            note: "wrong (tampered) request digest rejected",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: None,
            mutate: |s| s.response.request_digest = "deadbeef".to_string(),
            expected: Expect::WrongRequestDigest,
        },
        ScenarioCase {
            id: "R16_stale_or_replayed_request_rejected",
            note: "stale/replayed request nonce rejected",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: None,
            mutate: |s| {
                s.request.replay_nonce = "replayed-nonce".to_string();
                s.response.request_digest = s.request.canonical_digest();
            },
            expected: Expect::StaleOrReplayedRequest,
        },
        ScenarioCase {
            id: "R17_stale_or_replayed_response_rejected",
            note: "stale/replayed response nonce rejected",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: None,
            mutate: |s| s.response.response_nonce = "replayed-resp".to_string(),
            expected: Expect::StaleOrReplayedResponse,
        },
        ScenarioCase {
            id: "R18_expired_attestation_rejected",
            note: "expired identity attestation rejected",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: None,
            mutate: |s| s.expected.now_unix = EXPIRES + 1,
            expected: Expect::ExpiredAttestation,
        },
        ScenarioCase {
            id: "R19_expired_response_rejected",
            note: "expired response window rejected",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: None,
            mutate: |s| {
                s.identity.freshness_unix = None;
                s.identity.expires_at_unix = None;
                s.response.freshness_unix = Some(FRESH);
                s.response.expires_at_unix = Some(NOW - 1);
            },
            expected: Expect::ExpiredResponse,
        },
        ScenarioCase {
            id: "R20_unsupported_suite_rejected",
            note: "unsupported signature suite rejected",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: None,
            mutate: |s| s.response.signature_suite_id = 7,
            expected: Expect::UnsupportedSuite,
        },
        ScenarioCase {
            id: "R21_invalid_signature_rejected",
            note: "placeholder invalid-signature sentinel rejected",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: None,
            mutate: |s| {
                s.response.signature_commitment = REMOTE_SIGNER_INVALID_SIGNATURE_SENTINEL.to_string()
            },
            expected: Expect::InvalidSignature,
        },
        ScenarioCase {
            id: "R22_malformed_request_rejected",
            note: "malformed request (empty replay nonce) rejected",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: None,
            mutate: |s| {
                s.request.replay_nonce = String::new();
                s.response.request_digest = s.request.canonical_digest();
            },
            expected: Expect::MalformedRequest,
        },
        ScenarioCase {
            id: "R23_malformed_response_rejected",
            note: "malformed response (empty signature commitment) rejected",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: None,
            mutate: |s| s.response.signature_commitment = String::new(),
            expected: Expect::MalformedResponse,
        },
        ScenarioCase {
            id: "R24_local_operator_key_cannot_satisfy_remote_signer",
            note: "local operator key cannot satisfy a remote signer policy (router)",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: Some(AuthorityCustodyClass::LocalOperatorKey),
            mutate: noop,
            expected: Expect::LocalOperatorKeyCannotSatisfyRemoteSigner,
        },
        // R25 (peer majority) is covered in run_refusal_helpers_table.
        ScenarioCase {
            id: "R29_fixture_loopback_rejected_for_mainnet",
            note: "fixture loopback rejected on MainNet trust domain (verifier surface of R29)",
            env: Mainnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: None,
            mutate: noop,
            expected: Expect::FixtureLoopbackRejectedForMainNet,
        },
        // Non-RemoteSigner custody classes do not route.
        ScenarioCase {
            id: "RX_not_remote_signer_custody_class_kms",
            note: "AuthorityCustodyClass::Kms does not route into the remote-signer boundary",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: Some(AuthorityCustodyClass::Kms),
            mutate: noop,
            expected: Expect::NotRemoteSignerCustodyClass,
        },
        ScenarioCase {
            id: "RX_not_remote_signer_custody_class_hsm",
            note: "AuthorityCustodyClass::Hsm does not route into the remote-signer boundary",
            env: Devnet,
            policy: RemoteSignerPolicy::FixtureLoopbackAllowed,
            route_class: Some(AuthorityCustodyClass::Hsm),
            mutate: noop,
            expected: Expect::NotRemoteSignerCustodyClass,
        },
    ]
}

fn run_scenarios(
    out_dir: &Path,
    manifest: &mut String,
    expected_buf: &mut String,
    actual_buf: &mut String,
) -> std::io::Result<(usize, usize)> {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let scenarios_dir = out_dir.join("scenarios");
    fs::create_dir_all(&scenarios_dir)?;

    for case in corpus() {
        let mut s = scenario(case.env);
        (case.mutate)(&mut s);
        let outcome = match case.route_class {
            None => validate(&s, case.policy),
            Some(class) => validate_remote_signer_for_custody_class(
                class,
                &s.identity,
                &s.request,
                &s.response,
                &s.domain,
                &s.expected,
                case.policy,
            ),
        };
        let ok = matches_expect(&outcome, case.expected);
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!(
                "[run-195-helper] FAIL scenario={} expected={:?} actual={:?}",
                case.id, case.expected, outcome
            );
        }
        let scn_dir = scenarios_dir.join(case.id);
        fs::create_dir_all(&scn_dir)?;
        fs::write(scn_dir.join("note.txt"), format!("{}\n", case.note))?;
        fs::write(
            scn_dir.join("expected.txt"),
            format!(
                "env={:?} policy={} route_class={:?} expected={:?}\n",
                case.env,
                case.policy.tag(),
                case.route_class,
                case.expected
            ),
        )?;
        fs::write(
            scn_dir.join("actual.txt"),
            format!("outcome={:?}\tmatch={}\n", outcome, ok),
        )?;
        let line = format!("{}\t{:?}\t{:?}\tmatch={}\n", case.id, case.expected, outcome, ok);
        manifest.push_str(&line);
        expected_buf.push_str(&format!("{}\t{:?}\n", case.id, case.expected));
        actual_buf.push_str(&format!("{}\t{:?}\n", case.id, outcome));
    }
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// A3 — canonical-digest determinism + full domain-tuple binding table.
// Every bound field, when changed, changes the deterministic SHA3-256
// canonical digest.
// ---------------------------------------------------------------------------

fn run_canonical_digest_table(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut buf = String::new();

    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let base_req = request(TrustBundleEnvironment::Devnet, &candidate);
    let base = base_req.canonical_digest();

    let mut record = |label: &str, ok: bool, detail: &str| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!("[run-195-helper] FAIL canonical-digest: {} {}", label, detail);
        }
        buf.push_str(&format!("{}\tok={}\t{}\n", label, ok, detail));
    };

    // Determinism: same request hashes identically across calls + clones.
    record(
        "deterministic_same_call",
        base_req.canonical_digest() == base,
        "two evaluations equal",
    );
    record(
        "deterministic_clone",
        base_req.clone().canonical_digest() == base,
        "clone equals original",
    );

    // Field sensitivity: changing each bound field changes the digest.
    let mut env_req = base_req.clone();
    env_req.environment = TrustBundleEnvironment::Testnet;
    record("env_changes_digest", env_req.canonical_digest() != base, "environment");

    let mut chain_req = base_req.clone();
    chain_req.chain_id = OTHER_CHAIN.to_string();
    record("chain_changes_digest", chain_req.canonical_digest() != base, "chain_id");

    let mut gen_req = base_req.clone();
    gen_req.genesis_hash = OTHER_GENESIS.to_string();
    record("genesis_changes_digest", gen_req.canonical_digest() != base, "genesis_hash");

    let mut root_req = base_req.clone();
    root_req.authority_root_fingerprint = OTHER_ROOT_FP.to_string();
    record(
        "authority_root_changes_digest",
        root_req.canonical_digest() != base,
        "authority_root_fingerprint",
    );

    let mut act_req = base_req.clone();
    act_req.lifecycle_action = LocalLifecycleAction::Revoke;
    record("action_changes_digest", act_req.canonical_digest() != base, "lifecycle_action");

    let mut cand_req = base_req.clone();
    cand_req.candidate_digest = DIGEST_OTHER.to_string();
    record(
        "candidate_changes_digest",
        cand_req.canonical_digest() != base,
        "candidate_digest",
    );

    let mut seq_req = base_req.clone();
    seq_req.authority_domain_sequence = 99;
    record(
        "sequence_changes_digest",
        seq_req.canonical_digest() != base,
        "authority_domain_sequence",
    );

    let mut gov_req = base_req.clone();
    gov_req.governance_proof_digest = Some("gov-proof".to_string());
    record(
        "governance_proof_changes_digest",
        gov_req.canonical_digest() != base,
        "governance_proof_digest",
    );

    let mut nonce_req = base_req.clone();
    nonce_req.replay_nonce = "different".to_string();
    record("nonce_changes_digest", nonce_req.canonical_digest() != base, "replay_nonce");

    // Fixture loopback response echoes the canonical request digest.
    let fixture = fixture_signer(TrustBundleEnvironment::Devnet, &candidate);
    let resp = fixture.sign(&base_req).expect("fixture signs");
    record(
        "fixture_response_echoes_request_digest",
        resp.request_digest == base,
        "response.request_digest == request.canonical_digest()",
    );
    record(
        "fixture_response_mode_is_fixture_loopback",
        resp.signer_mode == RemoteSignerMode::FixtureLoopback,
        "signer_mode",
    );

    fs::write(out_dir.join("canonical_digest_table.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Policy / mode tag table — stable typed tags + fixture-vs-production
// separation.
// ---------------------------------------------------------------------------

fn run_policy_mode_table(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut buf = String::new();

    let mut record = |label: &str, ok: bool| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!("[run-195-helper] FAIL policy/mode: {}", label);
        }
        buf.push_str(&format!("{}\tok={}\n", label, ok));
    };

    record("default_policy_is_disabled", RemoteSignerPolicy::default() == RemoteSignerPolicy::Disabled);
    record("tag_disabled", RemoteSignerPolicy::Disabled.tag() == "disabled");
    record(
        "tag_fixture_loopback_allowed",
        RemoteSignerPolicy::FixtureLoopbackAllowed.tag() == "fixture-loopback-allowed",
    );
    record(
        "tag_production_remote_signer_required",
        RemoteSignerPolicy::ProductionRemoteSignerRequired.tag()
            == "production-remote-signer-required",
    );
    record(
        "tag_mainnet_production_remote_signer_required",
        RemoteSignerPolicy::MainnetProductionRemoteSignerRequired.tag()
            == "mainnet-production-remote-signer-required",
    );
    record(
        "requires_production_remote_signer_production",
        RemoteSignerPolicy::ProductionRemoteSignerRequired.requires_production_remote_signer(),
    );
    record(
        "requires_production_remote_signer_mainnet",
        RemoteSignerPolicy::MainnetProductionRemoteSignerRequired.requires_production_remote_signer(),
    );
    record(
        "fixture_policy_does_not_require_production",
        !RemoteSignerPolicy::FixtureLoopbackAllowed.requires_production_remote_signer(),
    );
    record("tag_mode_fixture_loopback", RemoteSignerMode::FixtureLoopback.tag() == "fixture-loopback");
    record("tag_mode_production", RemoteSignerMode::Production.tag() == "production");

    // Fixture vs production signer separation: the production signer is
    // callable through the trait object but always returns the typed
    // unavailable reject; the fixture loopback signer produces a
    // well-formed fixture response.
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let req = request(TrustBundleEnvironment::Devnet, &candidate);
    let fixture = fixture_signer(TrustBundleEnvironment::Devnet, &candidate);
    let fx = fixture.sign(&req);
    record(
        "fixture_signer_produces_fixture_loopback_response",
        matches!(&fx, Ok(r) if r.signer_mode == RemoteSignerMode::FixtureLoopback),
    );
    let prod = ProductionRemoteSigner {
        identity: identity(TrustBundleEnvironment::Devnet, &candidate),
    };
    let prod_dyn: &dyn RemoteAuthoritySigner = &prod;
    record("production_signer_identity_reachable", prod_dyn.identity().signer_id == SIGNER_ID);
    record(
        "production_signer_fails_closed",
        prod_dyn.sign(&req) == Err(RemoteSignerOutcome::ProductionRemoteSignerUnavailable),
    );

    fs::write(out_dir.join("policy_mode_table.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Custody-class routing table — `custody_class_routes_to_remote_signer`
// and the router dispatch outcomes.
// ---------------------------------------------------------------------------

fn run_custody_routing_table(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut buf = String::new();

    let mut record = |label: &str, ok: bool, detail: &str| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!("[run-195-helper] FAIL custody-routing: {} {}", label, detail);
        }
        buf.push_str(&format!("{}\tok={}\t{}\n", label, ok, detail));
    };

    record(
        "remote_signer_routes",
        custody_class_routes_to_remote_signer(AuthorityCustodyClass::RemoteSigner),
        "RemoteSigner routes => true",
    );
    for class in [
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyClass::LocalOperatorKey,
        AuthorityCustodyClass::Kms,
        AuthorityCustodyClass::Hsm,
        AuthorityCustodyClass::Unknown,
    ] {
        record(
            "non_remote_signer_does_not_route",
            !custody_class_routes_to_remote_signer(class),
            &format!("{:?} routes => false", class),
        );
    }

    // Router dispatch: RemoteSigner accepts; LocalOperatorKey refuses
    // with the named outcome; every other class is NotRemoteSignerCustodyClass.
    let s = scenario(TrustBundleEnvironment::Devnet);
    let routed = validate_remote_signer_for_custody_class(
        AuthorityCustodyClass::RemoteSigner,
        &s.identity,
        &s.request,
        &s.response,
        &s.domain,
        &s.expected,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    record(
        "router_remote_signer_accepts",
        matches!(routed, RemoteSignerOutcome::FixtureLoopbackAccepted { .. }),
        &format!("{:?}", routed),
    );
    let routed_local = validate_remote_signer_for_custody_class(
        AuthorityCustodyClass::LocalOperatorKey,
        &s.identity,
        &s.request,
        &s.response,
        &s.domain,
        &s.expected,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    record(
        "router_local_operator_refused",
        routed_local == RemoteSignerOutcome::LocalOperatorKeyCannotSatisfyRemoteSigner,
        &format!("{:?}", routed_local),
    );
    for class in [
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyClass::Kms,
        AuthorityCustodyClass::Hsm,
        AuthorityCustodyClass::Unknown,
    ] {
        let routed_other = validate_remote_signer_for_custody_class(
            class,
            &s.identity,
            &s.request,
            &s.response,
            &s.domain,
            &s.expected,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
        );
        record(
            "router_other_class_not_remote_signer",
            routed_other == RemoteSignerOutcome::NotRemoteSignerCustodyClass { class },
            &format!("{:?} => {:?}", class, routed_other),
        );
    }

    fs::write(out_dir.join("custody_routing_table.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Composition table — `validate_lifecycle_governance_custody_and_remote_signer`
// (A5 / R26 / R27 / R28 / R29 composition surfaces).
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn compose(
    s: &Scenario,
    custody: &AuthorityCustodyAttestation,
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    custody_policy: AuthorityCustodyPolicy,
    remote_policy: RemoteSignerPolicy,
    is_peer_driven_apply_preflight: bool,
) -> LifecycleCustodyRemoteSignerOutcome {
    validate_lifecycle_governance_custody_and_remote_signer(
        custody,
        &s.candidate,
        persisted,
        &s.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        custody_policy,
        &s.identity,
        &s.request,
        &s.response,
        &s.expected,
        remote_policy,
        NOW,
        is_peer_driven_apply_preflight,
    )
}

fn run_composition_table(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut buf = String::new();

    let mut record = |label: &str, ok: bool, outcome: &LifecycleCustodyRemoteSignerOutcome| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!("[run-195-helper] FAIL composition: {} actual={:?}", label, outcome);
        }
        buf.push_str(&format!("{}\tok={}\toutcome={:?}\n", label, ok, outcome));
    };

    // A5 — combined lifecycle + governance + custody + fixture remote
    // signer accepted on DevNet.
    {
        let s = scenario(TrustBundleEnvironment::Devnet);
        let custody = good_custody_attestation(
            TrustBundleEnvironment::Devnet,
            &s.candidate,
            AuthorityCustodyClass::FixtureLocalKey,
        );
        let prior = prior_versioned(TrustBundleEnvironment::Devnet);
        let o = compose(
            &s,
            &custody,
            Some(&prior),
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
            false,
        );
        record(
            "A5_combined_accept_devnet",
            matches!(o, LifecycleCustodyRemoteSignerOutcome::Accepted { .. }),
            &o,
        );
    }

    // R26 — remote signer valid but custody metadata invalid: the Run
    // 188 custody composition rejects first.
    {
        let s = scenario(TrustBundleEnvironment::Devnet);
        let mut custody = good_custody_attestation(
            TrustBundleEnvironment::Devnet,
            &s.candidate,
            AuthorityCustodyClass::FixtureLocalKey,
        );
        custody.custody_key_id = "wrong-custody-key".to_string();
        let prior = prior_versioned(TrustBundleEnvironment::Devnet);
        let o = compose(
            &s,
            &custody,
            Some(&prior),
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
            false,
        );
        record(
            "R26_custody_invalid_rejected_before_remote_signer",
            matches!(o, LifecycleCustodyRemoteSignerOutcome::LifecycleOrCustodyRejected(_)),
            &o,
        );
    }

    // R27 — custody valid but remote signer response invalid.
    {
        let mut s = scenario(TrustBundleEnvironment::Devnet);
        s.response.request_digest = "deadbeef".to_string();
        let custody = good_custody_attestation(
            TrustBundleEnvironment::Devnet,
            &s.candidate,
            AuthorityCustodyClass::FixtureLocalKey,
        );
        let prior = prior_versioned(TrustBundleEnvironment::Devnet);
        let o = compose(
            &s,
            &custody,
            Some(&prior),
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
            false,
        );
        record(
            "R27_custody_valid_remote_signer_invalid_rejected",
            matches!(o, LifecycleCustodyRemoteSignerOutcome::RemoteSignerRejected { .. }),
            &o,
        );
    }

    // R28 — lifecycle + governance + custody valid but production remote
    // signer unavailable.
    {
        let mut s = scenario(TrustBundleEnvironment::Devnet);
        s.response.signer_mode = RemoteSignerMode::Production;
        let custody = good_custody_attestation(
            TrustBundleEnvironment::Devnet,
            &s.candidate,
            AuthorityCustodyClass::FixtureLocalKey,
        );
        let prior = prior_versioned(TrustBundleEnvironment::Devnet);
        let o = compose(
            &s,
            &custody,
            Some(&prior),
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
            false,
        );
        let ok = matches!(
            &o,
            LifecycleCustodyRemoteSignerOutcome::RemoteSignerRejected { remote_signer_outcome, .. }
                if *remote_signer_outcome == RemoteSignerOutcome::ProductionRemoteSignerUnavailable
        );
        record("R28_production_remote_signer_unavailable_rejected", ok, &o);
    }

    // R29 — MainNet peer-driven apply refused even with fixture loopback
    // remote signer (composition short-circuit when preflight=true).
    {
        let s = scenario(TrustBundleEnvironment::Mainnet);
        let custody = good_custody_attestation(
            TrustBundleEnvironment::Mainnet,
            &s.candidate,
            AuthorityCustodyClass::FixtureLocalKey,
        );
        let o = compose(
            &s,
            &custody,
            None,
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
            true,
        );
        record(
            "R29_mainnet_peer_driven_apply_refused",
            o == LifecycleCustodyRemoteSignerOutcome::MainNetPeerDrivenApplyRefused,
            &o,
        );
    }

    fs::write(out_dir.join("composition_table.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Named refusal-helper table — grep-verifiable refusal helpers.
// ---------------------------------------------------------------------------

fn run_refusal_helpers_table(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut buf = String::new();

    let mut record = |label: &str, ok: bool| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!("[run-195-helper] FAIL refusal-helper: {}", label);
        }
        buf.push_str(&format!("{}\tok={}\n", label, ok));
    };

    record(
        "mainnet_refused_under_remote_signer_boundary_mainnet",
        mainnet_peer_driven_apply_remains_refused_under_remote_signer_boundary(
            TrustBundleEnvironment::Mainnet,
        ),
    );
    record(
        "mainnet_refused_under_remote_signer_boundary_devnet_false",
        !mainnet_peer_driven_apply_remains_refused_under_remote_signer_boundary(
            TrustBundleEnvironment::Devnet,
        ),
    );
    record(
        "mainnet_refused_under_remote_signer_boundary_testnet_false",
        !mainnet_peer_driven_apply_remains_refused_under_remote_signer_boundary(
            TrustBundleEnvironment::Testnet,
        ),
    );
    record(
        "local_operator_key_cannot_satisfy_remote_signer",
        local_operator_key_cannot_satisfy_remote_signer(),
    );
    // R25 — peer majority cannot satisfy a remote signer policy.
    record(
        "peer_majority_cannot_satisfy_remote_signer",
        peer_majority_cannot_satisfy_remote_signer(),
    );

    fs::write(out_dir.join("refusal_helpers_table.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// No-mutation evidence (R30 / R31) — a rejecting validation / composition
// leaves every input bit-equal: no marker write, no sequence write, no
// live trust swap, no session eviction, no Run 070 call. The validators
// take shared references and return owned outcomes — they cannot mutate.
// ---------------------------------------------------------------------------

fn run_no_mutation_evidence(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut buf = String::new();

    let mut record = |label: &str, ok: bool| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!("[run-195-helper] FAIL no-mutation: {}", label);
        }
        buf.push_str(&format!("{}\tok={}\n", label, ok));
    };

    // R30 — validation-only rejection is non-mutating.
    {
        let s = scenario(TrustBundleEnvironment::Devnet);
        let candidate_before = s.candidate.clone();
        let identity_before = s.identity.clone();
        let request_before = s.request.clone();
        let response_before = s.response.clone();

        let o1 = validate(&s, RemoteSignerPolicy::Disabled);
        let o2 = validate(&s, RemoteSignerPolicy::ProductionRemoteSignerRequired);

        record("R30_disabled_rejects", o1.is_reject());
        record("R30_production_required_rejects", o2.is_reject());
        record("R30_candidate_unchanged", s.candidate == candidate_before);
        record("R30_identity_unchanged", s.identity == identity_before);
        record("R30_request_unchanged", s.request == request_before);
        record("R30_response_unchanged", s.response == response_before);
    }

    // R31 — mutating-preflight rejection (composition helper) produces no
    // mutation. The composition helper is validation-only: there is no
    // Run 070 call, live trust swap, session eviction, sequence write, or
    // marker write surface to invoke.
    {
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
        let prior_before = prior.clone();
        let o = compose(
            &s,
            &custody,
            Some(&prior),
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
            false,
        );
        record("R31_composition_rejects", o.is_reject());
        record("R31_candidate_unchanged", s.candidate == candidate_before);
        record("R31_request_unchanged", s.request == request_before);
        record("R31_response_unchanged", s.response == response_before);
        record("R31_custody_unchanged", custody == custody_before);
        record("R31_prior_unchanged", prior == prior_before);
    }

    fs::write(out_dir.join("no_mutation_evidence.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Determinism — 32 re-evaluations of the accepted DevNet fixture scenario
// and a representative rejection reproduce the typed outcome bit-for-bit.
// ---------------------------------------------------------------------------

fn run_determinism_check(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut buf = String::new();

    // Accepted fixture-loopback scenario.
    {
        let s = scenario(TrustBundleEnvironment::Devnet);
        let mut samples = Vec::new();
        for _ in 0..32 {
            samples.push(validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed));
        }
        let first = samples[0].clone();
        let all_eq = samples.iter().all(|o| *o == first);
        let ok = all_eq && first.is_accept();
        if ok {
            pass += 1;
        } else {
            fail += 1;
        }
        buf.push_str(&format!(
            "accepted_fixture\tsamples=32\tall_equal={}\tfirst_accept={}\tsample={:?}\n",
            all_eq,
            first.is_accept(),
            first
        ));
    }

    // Rejected production-unavailable scenario.
    {
        let mut s = scenario(TrustBundleEnvironment::Devnet);
        s.response.signer_mode = RemoteSignerMode::Production;
        let mut samples = Vec::new();
        for _ in 0..32 {
            samples.push(validate(&s, RemoteSignerPolicy::FixtureLoopbackAllowed));
        }
        let first = samples[0].clone();
        let all_eq = samples.iter().all(|o| *o == first);
        let ok = all_eq && first == RemoteSignerOutcome::ProductionRemoteSignerUnavailable;
        if ok {
            pass += 1;
        } else {
            fail += 1;
        }
        buf.push_str(&format!(
            "rejected_production_unavailable\tsamples=32\tall_equal={}\tsample={:?}\n",
            all_eq, first
        ));
    }

    fs::write(out_dir.join("determinism_evidence.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Fixture dump — persist the canonical accepted request/response so the
// harness can capture their SHA-256.
// ---------------------------------------------------------------------------

fn run_fixture_dump(out_dir: &Path) -> std::io::Result<()> {
    let fixtures = out_dir.join("fixtures");
    fs::create_dir_all(&fixtures)?;
    let s = scenario(TrustBundleEnvironment::Devnet);
    fs::write(
        fixtures.join("request.txt"),
        format!(
            "environment={:?}\nchain_id={}\ngenesis_hash={}\nauthority_root_fingerprint={}\nlifecycle_action={:?}\ncandidate_digest={}\nauthority_domain_sequence={}\nreplay_nonce={}\ncanonical_digest={}\n",
            s.request.environment,
            s.request.chain_id,
            s.request.genesis_hash,
            s.request.authority_root_fingerprint,
            s.request.lifecycle_action,
            s.request.candidate_digest,
            s.request.authority_domain_sequence,
            s.request.replay_nonce,
            s.request.canonical_digest(),
        ),
    )?;
    fs::write(
        fixtures.join("response.txt"),
        format!(
            "request_digest={}\nsigner_id={}\ncustody_key_id={}\nsignature_suite_id={}\nsignature_commitment={}\nresponse_nonce={}\nsigner_mode={:?}\n",
            s.response.request_digest,
            s.response.signer_id,
            s.response.custody_key_id,
            s.response.signature_suite_id,
            s.response.signature_commitment,
            s.response.response_nonce,
            s.response.signer_mode,
        ),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    let mut args = env::args().skip(1);
    let out_dir: PathBuf = match args.next() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!(
                "usage: run_195_remote_authority_signer_boundary_release_binary_helper <OUT_DIR>"
            );
            std::process::exit(2);
        }
    };
    fs::create_dir_all(&out_dir).expect("create out_dir");

    let mut manifest = String::new();
    let mut expected_buf = String::new();
    let mut actual_buf = String::new();

    let (s_pass, s_fail) =
        run_scenarios(&out_dir, &mut manifest, &mut expected_buf, &mut actual_buf)
            .expect("scenario corpus");
    let (g_pass, g_fail) = run_canonical_digest_table(&out_dir).expect("canonical digest table");
    let (p_pass, p_fail) = run_policy_mode_table(&out_dir).expect("policy/mode table");
    let (c_pass, c_fail) = run_custody_routing_table(&out_dir).expect("custody routing table");
    let (m_pass, m_fail) = run_composition_table(&out_dir).expect("composition table");
    let (r_pass, r_fail) = run_refusal_helpers_table(&out_dir).expect("refusal helpers table");
    let (n_pass, n_fail) = run_no_mutation_evidence(&out_dir).expect("no mutation evidence");
    let (d_pass, d_fail) = run_determinism_check(&out_dir).expect("determinism check");
    run_fixture_dump(&out_dir).expect("fixture dump");

    fs::write(out_dir.join("manifest.txt"), &manifest).expect("write manifest");
    fs::write(out_dir.join("expected_outcomes.txt"), &expected_buf).expect("write expected");
    fs::write(out_dir.join("actual_outcomes.txt"), &actual_buf).expect("write actual");

    let total_pass =
        s_pass + g_pass + p_pass + c_pass + m_pass + r_pass + n_pass + d_pass;
    let total_fail =
        s_fail + g_fail + p_fail + c_fail + m_fail + r_fail + n_fail + d_fail;
    let verdict = if total_fail == 0 { "PASS" } else { "FAIL" };

    let mut summary =
        fs::File::create(out_dir.join("helper_summary.txt")).expect("create helper_summary.txt");
    writeln!(
        summary,
        "Run 195 helper - release-mode RemoteSigner production-custody boundary corpus"
    )
    .unwrap();
    writeln!(summary, "verdict: {}", verdict).unwrap();
    writeln!(summary, "total_pass: {}", total_pass).unwrap();
    writeln!(summary, "total_fail: {}", total_fail).unwrap();
    writeln!(summary, "scenarios_pass: {}", s_pass).unwrap();
    writeln!(summary, "scenarios_fail: {}", s_fail).unwrap();
    writeln!(summary, "canonical_digest_pass: {}", g_pass).unwrap();
    writeln!(summary, "canonical_digest_fail: {}", g_fail).unwrap();
    writeln!(summary, "policy_mode_pass: {}", p_pass).unwrap();
    writeln!(summary, "policy_mode_fail: {}", p_fail).unwrap();
    writeln!(summary, "custody_routing_pass: {}", c_pass).unwrap();
    writeln!(summary, "custody_routing_fail: {}", c_fail).unwrap();
    writeln!(summary, "composition_pass: {}", m_pass).unwrap();
    writeln!(summary, "composition_fail: {}", m_fail).unwrap();
    writeln!(summary, "refusal_helpers_pass: {}", r_pass).unwrap();
    writeln!(summary, "refusal_helpers_fail: {}", r_fail).unwrap();
    writeln!(summary, "no_mutation_pass: {}", n_pass).unwrap();
    writeln!(summary, "no_mutation_fail: {}", n_fail).unwrap();
    writeln!(summary, "determinism_pass: {}", d_pass).unwrap();
    writeln!(summary, "determinism_fail: {}", d_fail).unwrap();

    if total_fail != 0 {
        eprintln!("[run-195-helper] FAIL: total_fail={}", total_fail);
        std::process::exit(1);
    }
}