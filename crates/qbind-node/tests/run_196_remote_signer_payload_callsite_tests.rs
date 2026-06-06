//! Run 196 — source/test RemoteSigner attestation payload carrying and
//! production-context custody composition wiring integration tests.
//!
//! Source/test only. Run 196 does **not** capture release-binary
//! evidence; release-binary RemoteSigner payload/carrying evidence is
//! deferred to **Run 197**. The tests cover:
//!
//! * the A1–A10 / R1–R34 matrix from `task/RUN_196_TASK.txt`;
//! * serde/parse compatibility (old no-RemoteSigner payload, carrying
//!   payload, malformed identity/request/response, unsupported future
//!   schema version);
//! * canonical digest determinism through wire conversion;
//! * source reachability of the production call-site context,
//!   `validate_remote_signer`, and
//!   `validate_lifecycle_governance_custody_and_remote_signer`;
//! * no-mutation invariants (validation-only routing helpers are pure);
//! * MainNet refusal invariants.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_196.md`.

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
    peer_majority_cannot_satisfy_remote_signer, FixtureLoopbackRemoteSigner,
    LifecycleCustodyRemoteSignerOutcome, RemoteAuthoritySigner, RemoteSignerExpectations,
    RemoteSignerIdentity, RemoteSignerMode, RemoteSignerOutcome, RemoteSignerPolicy,
    RemoteSignerRequest, RemoteSignerResponse,
};
use qbind_node::pqc_remote_signer_payload_carrying::{
    callsite_context_for_remote_signer,
    load_v2_ratification_sidecar_with_remote_signer_attestation_from_bytes,
    mainnet_peer_driven_apply_remains_refused_under_remote_signer_payload_carrying,
    parse_optional_remote_signer_attestation_sibling_from_json_value,
    route_loaded_remote_signer_attestation_to_live_inbound_0x05_callsite_decision,
    route_loaded_remote_signer_attestation_to_local_peer_candidate_check_callsite_decision,
    route_loaded_remote_signer_attestation_to_peer_driven_drain_callsite_decision,
    route_loaded_remote_signer_attestation_to_reload_apply_callsite_decision,
    route_loaded_remote_signer_attestation_to_reload_check_callsite_decision,
    route_loaded_remote_signer_attestation_to_sighup_callsite_decision,
    route_loaded_remote_signer_attestation_to_startup_p2p_trust_bundle_callsite_decision,
    route_remote_signer_attestation_for_custody_class, validate_loaded_remote_signer,
    RemoteSignerAttestationParts, RemoteSignerAttestationWire,
    RemoteSignerAttestationWireParseError, RemoteSignerCallsiteContext, RemoteSignerLoadStatus,
    RemoteSignerPayloadCarryingDecisionOutcome, RemoteSignerRequestWire, RemoteSignerResponseWire,
    REMOTE_SIGNER_ATTESTATION_PAYLOAD_SIBLING_FIELD, REMOTE_SIGNER_ATTESTATION_WIRE_SCHEMA_VERSION,
};
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
const CUSTODY_ATTEST_DIGEST: &str = "custody-att-digest-196";
const CUSTODY_KEY_ID: &str = "custody-key-id-196";
const SIGNER_ID: &str = "remote-signer-196";
const SIGNER_PUBID: &str = "remote-signer-pubid-196";
const ATTEST_DIGEST: &str = "remote-signer-attest-196";
const REQ_NONCE: &str = "req-nonce-196";
const RESP_NONCE: &str = "resp-nonce-196";
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

/// Build the typed parts (identity/request/response) for `env`.
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

/// Owning bundle so a `RemoteSignerCallsiteContext` can borrow.
struct Ctx {
    custody: AuthorityCustodyAttestation,
    candidate: PersistentAuthorityStateRecordV2,
    prior: PersistentAuthorityStateRecordVersioned,
    domain: AuthorityTrustDomain,
    expected: RemoteSignerExpectations,
}

fn ctx_for(
    env: TrustBundleEnvironment,
    custody_class: AuthorityCustodyClass,
) -> Ctx {
    Ctx {
        custody: custody_attestation(env, custody_class),
        candidate: rotate_candidate(env),
        prior: prior_versioned(env),
        domain: domain(env),
        expected: expectations(),
    }
}

fn ctx_view<'a>(
    c: &'a Ctx,
    custody_policy: AuthorityCustodyPolicy,
    remote_signer_policy: RemoteSignerPolicy,
) -> RemoteSignerCallsiteContext<'a> {
    callsite_context_for_remote_signer(
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
    )
}

// ===========================================================================
// Type-shape regressions
// ===========================================================================

#[test]
fn schema_version_and_sibling_field_are_canonical() {
    assert_eq!(REMOTE_SIGNER_ATTESTATION_WIRE_SCHEMA_VERSION, 1);
    assert_eq!(
        REMOTE_SIGNER_ATTESTATION_PAYLOAD_SIBLING_FIELD,
        "remote_signer_attestation"
    );
}

// ===========================================================================
// Serde / parse compatibility
// ===========================================================================

#[test]
fn serde_old_no_remote_signer_payload_parses_as_absent() {
    let value = serde_json::json!({ "schema_version": 2, "unrelated": 1 });
    let s = parse_optional_remote_signer_attestation_sibling_from_json_value(&value);
    assert!(s.is_absent());
    assert!(s.as_parts().is_none());
}

#[test]
fn serde_null_sibling_parses_as_absent() {
    let value = serde_json::json!({ "remote_signer_attestation": null });
    let s = parse_optional_remote_signer_attestation_sibling_from_json_value(&value);
    assert!(s.is_absent());
}

#[test]
fn serde_remote_signer_carrying_payload_parses_as_available() {
    let p = parts(TrustBundleEnvironment::Devnet);
    let loaded = available_via_wire(&p);
    assert_eq!(loaded.as_parts().unwrap(), &p);
}

#[test]
fn serde_malformed_identity_fails_closed() {
    let p = parts(TrustBundleEnvironment::Devnet);
    let mut wire = RemoteSignerAttestationWire::from_parts(&p.identity, &p.request, &p.response);
    wire.identity.signer_id = String::new();
    let value = serde_json::json!({
        REMOTE_SIGNER_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
    });
    let s = parse_optional_remote_signer_attestation_sibling_from_json_value(&value);
    assert!(s.is_malformed());
    assert!(matches!(
        s.malformed_error().unwrap(),
        qbind_node::pqc_remote_signer_payload_carrying::RemoteSignerAttestationPayloadParseError::Wire(
            RemoteSignerAttestationWireParseError::EmptyRequiredField { part: "identity" }
        )
    ));
}

#[test]
fn serde_malformed_request_fails_closed() {
    let p = parts(TrustBundleEnvironment::Devnet);
    let mut wire = RemoteSignerAttestationWire::from_parts(&p.identity, &p.request, &p.response);
    wire.request.chain_id = String::new();
    let value = serde_json::json!({
        REMOTE_SIGNER_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
    });
    let s = parse_optional_remote_signer_attestation_sibling_from_json_value(&value);
    assert!(s.is_malformed());
    assert!(matches!(
        s.malformed_error().unwrap(),
        qbind_node::pqc_remote_signer_payload_carrying::RemoteSignerAttestationPayloadParseError::Wire(
            RemoteSignerAttestationWireParseError::EmptyRequiredField { part: "request" }
        )
    ));
}

#[test]
fn serde_malformed_response_fails_closed() {
    let p = parts(TrustBundleEnvironment::Devnet);
    let mut wire = RemoteSignerAttestationWire::from_parts(&p.identity, &p.request, &p.response);
    wire.response.signature_commitment = String::new();
    let value = serde_json::json!({
        REMOTE_SIGNER_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
    });
    let s = parse_optional_remote_signer_attestation_sibling_from_json_value(&value);
    assert!(s.is_malformed());
    assert!(matches!(
        s.malformed_error().unwrap(),
        qbind_node::pqc_remote_signer_payload_carrying::RemoteSignerAttestationPayloadParseError::Wire(
            RemoteSignerAttestationWireParseError::EmptyRequiredField { part: "response" }
        )
    ));
}

#[test]
fn serde_unsupported_future_schema_version_fails_closed() {
    let p = parts(TrustBundleEnvironment::Devnet);
    let mut wire = RemoteSignerAttestationWire::from_parts(&p.identity, &p.request, &p.response);
    wire.schema_version = 9_999;
    let value = serde_json::json!({
        REMOTE_SIGNER_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
    });
    let s = parse_optional_remote_signer_attestation_sibling_from_json_value(&value);
    assert!(s.is_malformed());
    assert!(matches!(
        s.malformed_error().unwrap(),
        qbind_node::pqc_remote_signer_payload_carrying::RemoteSignerAttestationPayloadParseError::Wire(
            RemoteSignerAttestationWireParseError::UnknownSchemaVersion { got: 9_999, .. }
        )
    ));
}

#[test]
fn serde_non_object_sibling_fails_closed_with_json_error() {
    let value = serde_json::json!({ "remote_signer_attestation": "not-an-object" });
    let s = parse_optional_remote_signer_attestation_sibling_from_json_value(&value);
    assert!(s.is_malformed());
    assert!(matches!(
        s.malformed_error().unwrap(),
        qbind_node::pqc_remote_signer_payload_carrying::RemoteSignerAttestationPayloadParseError::Json { .. }
    ));
}

// ===========================================================================
// Canonical digest determinism through wire conversion
// ===========================================================================

#[test]
fn a5_request_response_canonical_digest_preserved_through_wire() {
    let req = request(TrustBundleEnvironment::Devnet);
    let before = req.canonical_digest();
    let req_wire = RemoteSignerRequestWire::from_request(&req);
    let req_back = req_wire.to_request().expect("request round-trips");
    assert_eq!(req_back, req);
    assert_eq!(req_back.canonical_digest(), before);

    let resp = fixture_response(TrustBundleEnvironment::Devnet);
    assert_eq!(resp.request_digest, before);
    let resp_wire = RemoteSignerResponseWire::from_response(&resp);
    let resp_back = resp_wire.to_response().expect("response round-trips");
    assert_eq!(resp_back, resp);
    assert_eq!(resp_back.request_digest, before);
}

// ===========================================================================
// Combined v2 sidecar loader
// ===========================================================================

fn make_v2_sidecar_value(
    env: TrustBundleEnvironment,
    remote_signer_sibling: Option<serde_json::Value>,
) -> serde_json::Value {
    use qbind_crypto::MlDsa44Backend;
    use qbind_ledger::bundle_signing_ratification::v2_test_helpers::build_signed_ratification_v2;
    use qbind_ledger::genesis::GENESIS_AUTHORITY_SUITE_ML_DSA_44;
    use qbind_ledger::RatificationEnvironment;

    let ratification_env = match env {
        TrustBundleEnvironment::Mainnet => RatificationEnvironment::Mainnet,
        TrustBundleEnvironment::Testnet => RatificationEnvironment::Testnet,
        TrustBundleEnvironment::Devnet => RatificationEnvironment::Devnet,
    };
    let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let (target_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
    let mut auth_pk_hex = String::with_capacity(auth_pk.len() * 2);
    for b in &auth_pk {
        use std::fmt::Write;
        let _ = write!(&mut auth_pk_hex, "{:02x}", b);
    }
    let genesis_hash: qbind_ledger::genesis::GenesisHash = [0xaa; 32];
    let v2 = build_signed_ratification_v2(
        CHAIN_ID,
        ratification_env,
        genesis_hash,
        GENESIS_AUTHORITY_SUITE_ML_DSA_44 as u32,
        &auth_pk_hex,
        &auth_sk,
        &target_pk,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(KEY_A.to_string()),
        Some(DIGEST_2.to_string()),
        None,
        None,
        None,
        None,
    );
    let mut value = serde_json::to_value(&v2).expect("ratification serializes");
    if let Some(p) = remote_signer_sibling {
        value
            .as_object_mut()
            .unwrap()
            .insert(REMOTE_SIGNER_ATTESTATION_PAYLOAD_SIBLING_FIELD.to_string(), p);
    }
    value
}

#[test]
fn loader_legacy_v2_sidecar_without_sibling_yields_absent() {
    let value = make_v2_sidecar_value(TrustBundleEnvironment::Devnet, None);
    let bytes = serde_json::to_vec(&value).unwrap();
    let path = std::path::PathBuf::from("/dev/null/run-196-legacy.json");
    let loaded =
        load_v2_ratification_sidecar_with_remote_signer_attestation_from_bytes(&bytes, &path)
            .expect("legacy v2 sidecar parses");
    assert!(loaded.remote_signer_attestation.is_absent());
    assert!(loaded.authority_custody_attestation.is_absent());
}

#[test]
fn loader_v2_sidecar_with_remote_signer_sibling_yields_available() {
    let p = parts(TrustBundleEnvironment::Devnet);
    let wire = RemoteSignerAttestationWire::from_parts(&p.identity, &p.request, &p.response);
    let value = make_v2_sidecar_value(
        TrustBundleEnvironment::Devnet,
        Some(serde_json::to_value(&wire).unwrap()),
    );
    let bytes = serde_json::to_vec(&value).unwrap();
    let path = std::path::PathBuf::from("/dev/null/run-196-carry.json");
    let loaded =
        load_v2_ratification_sidecar_with_remote_signer_attestation_from_bytes(&bytes, &path)
            .expect("v2 sidecar with sibling parses");
    assert!(loaded.remote_signer_attestation.is_available());
    assert_eq!(loaded.remote_signer_attestation.as_parts().unwrap(), &p);
}

// ===========================================================================
// Accepted scenarios A1–A10
// ===========================================================================

#[test]
fn a1_no_remote_signer_payload_compatible_under_default_disabled() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let ctx = ctx_view(&c, AuthorityCustodyPolicy::Disabled, RemoteSignerPolicy::default());
    let loaded = RemoteSignerLoadStatus::Absent;
    let outcome =
        route_loaded_remote_signer_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert_eq!(
        outcome,
        RemoteSignerPayloadCarryingDecisionOutcome::NoRemoteSignerSupplied
    );
    assert!(outcome.is_bypassed());
    assert!(!outcome.is_accept());
    assert!(!outcome.is_reject());
}

#[test]
fn a2_devnet_fixture_loopback_carried_through_reload_check_accepted() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let ctx = ctx_view(
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    let loaded = available_via_wire(&parts(TrustBundleEnvironment::Devnet));
    let outcome =
        route_loaded_remote_signer_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_accept(), "expected accept, got {outcome:?}");
    assert!(matches!(
        outcome.callsite_outcome().unwrap(),
        LifecycleCustodyRemoteSignerOutcome::Accepted { .. }
    ));
}

#[test]
fn a3_testnet_fixture_loopback_carried_through_reload_check_accepted() {
    let c = ctx_for(TrustBundleEnvironment::Testnet, AuthorityCustodyClass::FixtureLocalKey);
    let ctx = ctx_view(
        &c,
        AuthorityCustodyPolicy::TestnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    let loaded = available_via_wire(&parts(TrustBundleEnvironment::Testnet));
    let outcome =
        route_loaded_remote_signer_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_accept(), "expected accept, got {outcome:?}");
}

#[test]
fn a4_devnet_fixture_loopback_carried_through_reload_apply_accepted() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let ctx = ctx_view(
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    let loaded = available_via_wire(&parts(TrustBundleEnvironment::Devnet));
    let outcome =
        route_loaded_remote_signer_attestation_to_reload_apply_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_accept(), "expected accept, got {outcome:?}");
}

#[test]
fn a6_custody_class_remote_signer_routes_to_remote_signer_boundary() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::RemoteSigner);
    let ctx = ctx_view(
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    let loaded = available_via_wire(&parts(TrustBundleEnvironment::Devnet));
    let outcome = route_remote_signer_attestation_for_custody_class(
        AuthorityCustodyClass::RemoteSigner,
        &ctx,
        &loaded,
    );
    assert!(matches!(
        outcome,
        RemoteSignerOutcome::FixtureLoopbackAccepted { .. }
    ));
}

#[test]
fn a7_combined_lifecycle_governance_custody_fixture_remote_signer_accepted_devnet() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let ctx = ctx_view(
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    let loaded = available_via_wire(&parts(TrustBundleEnvironment::Devnet));
    let outcome = route_loaded_remote_signer_attestation_to_startup_p2p_trust_bundle_callsite_decision(
        &ctx, &loaded,
    );
    assert!(outcome.is_accept(), "expected accept, got {outcome:?}");
}

#[test]
fn a8_governance_classes_unchanged_when_remote_signer_policy_disabled() {
    // With the RemoteSigner policy Disabled and no carrier, the routing
    // helper bypasses the RemoteSigner boundary regardless of which
    // governance class the candidate binds — RemoteSigner never alters
    // GenesisBound / EmergencyCouncil / OnChainGovernance behavior.
    for class in [
        GovernanceAuthorityClass::GenesisBound,
        GovernanceAuthorityClass::EmergencyCouncil,
        GovernanceAuthorityClass::OnChainGovernance,
    ] {
        let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
        let ctx = callsite_context_for_remote_signer(
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
        );
        let outcome = route_loaded_remote_signer_attestation_to_reload_check_callsite_decision(
            &ctx,
            &RemoteSignerLoadStatus::Absent,
        );
        assert!(outcome.is_bypassed());
    }
}

#[test]
fn a9_other_custody_paths_compatible_with_remote_signer_absent() {
    for class in [
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyClass::LocalOperatorKey,
        AuthorityCustodyClass::Kms,
        AuthorityCustodyClass::Hsm,
    ] {
        let c = ctx_for(TrustBundleEnvironment::Devnet, class);
        let ctx = ctx_view(&c, AuthorityCustodyPolicy::Disabled, RemoteSignerPolicy::Disabled);
        let outcome = route_loaded_remote_signer_attestation_to_reload_check_callsite_decision(
            &ctx,
            &RemoteSignerLoadStatus::Absent,
        );
        assert!(outcome.is_bypassed(), "class {class:?} should bypass");
    }
}

#[test]
fn a10_production_remote_signer_reaches_boundary_and_is_unavailable() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let ctx = ctx_view(
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::ProductionRemoteSignerRequired,
    );
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.response = production_response(TrustBundleEnvironment::Devnet);
    let loaded = RemoteSignerLoadStatus::Available(p);
    let outcome =
        route_loaded_remote_signer_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_reject());
    match outcome.callsite_outcome().unwrap() {
        LifecycleCustodyRemoteSignerOutcome::RemoteSignerRejected {
            remote_signer_outcome,
            ..
        } => assert!(remote_signer_outcome.is_production_unavailable()),
        other => panic!("expected RemoteSignerRejected unavailable, got {other:?}"),
    }
}

// ===========================================================================
// Rejection scenarios R1–R34
// ===========================================================================

#[test]
fn r1_absent_where_policy_requires_fails_closed() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let ctx = ctx_view(
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    let outcome = route_loaded_remote_signer_attestation_to_reload_check_callsite_decision(
        &ctx,
        &RemoteSignerLoadStatus::Absent,
    );
    assert!(outcome.is_required_but_absent());
    assert!(outcome.is_reject());
}

fn malformed_loaded(mutate: impl FnOnce(&mut RemoteSignerAttestationWire)) -> RemoteSignerLoadStatus {
    let p = parts(TrustBundleEnvironment::Devnet);
    let mut wire = RemoteSignerAttestationWire::from_parts(&p.identity, &p.request, &p.response);
    mutate(&mut wire);
    let value = serde_json::json!({
        REMOTE_SIGNER_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
    });
    parse_optional_remote_signer_attestation_sibling_from_json_value(&value)
}

#[test]
fn r2_malformed_identity_rejected() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let ctx = ctx_view(
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    let loaded = malformed_loaded(|w| w.identity.signer_public_identity = String::new());
    let outcome =
        route_loaded_remote_signer_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_malformed_payload());
    assert!(outcome.is_reject());
}

#[test]
fn r3_malformed_request_rejected() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let ctx = ctx_view(
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    let loaded = malformed_loaded(|w| w.request.replay_nonce = String::new());
    let outcome =
        route_loaded_remote_signer_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_malformed_payload());
}

#[test]
fn r4_malformed_response_rejected() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let ctx = ctx_view(
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    let loaded = malformed_loaded(|w| w.response.response_nonce = String::new());
    let outcome =
        route_loaded_remote_signer_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_malformed_payload());
}

#[test]
fn r5_malformed_combined_attestation_rejected() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let ctx = ctx_view(
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    let loaded = malformed_loaded(|w| w.schema_version = 7);
    let outcome =
        route_loaded_remote_signer_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_malformed_payload());
}

/// Route an `Available` carrier (built directly from parts) through the
/// reload-check helper under the given policies, returning the inner
/// Run 194 outcome.
fn route_available(
    env: TrustBundleEnvironment,
    custody_class: AuthorityCustodyClass,
    custody_policy: AuthorityCustodyPolicy,
    remote_signer_policy: RemoteSignerPolicy,
    parts: RemoteSignerAttestationParts,
) -> RemoteSignerPayloadCarryingDecisionOutcome {
    let c = ctx_for(env, custody_class);
    let ctx = ctx_view(&c, custody_policy, remote_signer_policy);
    let loaded = RemoteSignerLoadStatus::Available(parts);
    route_loaded_remote_signer_attestation_to_reload_check_callsite_decision(&ctx, &loaded)
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
    // Mutate the request nonce *and* re-derive the response digest so
    // the digest binding passes and the replay-nonce check is reached.
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
fn r26_local_operator_key_cannot_satisfy_remote_signer() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::LocalOperatorKey);
    let ctx = ctx_view(
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    let loaded = available_via_wire(&parts(TrustBundleEnvironment::Devnet));
    let outcome = route_remote_signer_attestation_for_custody_class(
        AuthorityCustodyClass::LocalOperatorKey,
        &ctx,
        &loaded,
    );
    assert_eq!(
        outcome,
        RemoteSignerOutcome::LocalOperatorKeyCannotSatisfyRemoteSigner
    );
}

#[test]
fn r27_peer_majority_cannot_satisfy_remote_signer() {
    assert!(peer_majority_cannot_satisfy_remote_signer());
}

#[test]
fn r28_remote_signer_valid_but_custody_invalid_rejected() {
    // Custody candidate-digest mismatch makes the Run 188 custody
    // validation reject before the RemoteSigner is consulted.
    let mut c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    c.custody.candidate_digest =
        "3333333333333333333333333333333333333333333333333333333333333333".to_string();
    let ctx = ctx_view(
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    let loaded = available_via_wire(&parts(TrustBundleEnvironment::Devnet));
    let outcome =
        route_loaded_remote_signer_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_reject());
    assert!(matches!(
        outcome.callsite_outcome().unwrap(),
        LifecycleCustodyRemoteSignerOutcome::LifecycleOrCustodyRejected(_)
    ));
}

#[test]
fn r29_custody_valid_but_remote_signer_response_invalid_rejected() {
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
fn r30_lifecycle_governance_custody_valid_production_unavailable_rejected() {
    let mut p = parts(TrustBundleEnvironment::Devnet);
    p.response = production_response(TrustBundleEnvironment::Devnet);
    let outcome = route_available(
        TrustBundleEnvironment::Devnet,
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::ProductionRemoteSignerRequired,
        p,
    );
    assert!(assert_remote_signer_reject(&outcome).is_production_unavailable());
}

#[test]
fn r31_validation_only_rejection_is_pure_no_mutation() {
    // The reload-check / local-peer-candidate-check helpers are pure
    // functions returning typed outcomes; a rejection cannot write a
    // marker or sequence because no such API is reachable from here.
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let ctx = ctx_view(
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    let loaded = malformed_loaded(|w| w.response.signature_commitment = String::new());
    let a = route_loaded_remote_signer_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    let b = route_loaded_remote_signer_attestation_to_local_peer_candidate_check_callsite_decision(
        &ctx, &loaded,
    );
    assert!(a.is_reject());
    assert_eq!(a, b, "pure routing helpers are deterministic");
}

#[test]
fn r32_mutating_rejection_produces_no_mutation() {
    // The mutating-preflight helpers (reload-apply / startup / sighup)
    // short-circuit a malformed carrier before the Run 194 verifier and
    // therefore before any sequence/marker write or Run 070 call.
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let ctx = ctx_view(
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    let loaded = malformed_loaded(|w| w.identity.attestation_digest = String::new());
    for outcome in [
        route_loaded_remote_signer_attestation_to_reload_apply_callsite_decision(&ctx, &loaded),
        route_loaded_remote_signer_attestation_to_startup_p2p_trust_bundle_callsite_decision(
            &ctx, &loaded,
        ),
        route_loaded_remote_signer_attestation_to_sighup_callsite_decision(&ctx, &loaded),
    ] {
        assert!(outcome.is_malformed_payload());
        assert!(outcome.is_reject());
    }
}

#[test]
fn r33_invalid_live_0x05_remote_signer_not_propagated() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let ctx = ctx_view(
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    let loaded = malformed_loaded(|w| w.response.response_nonce = String::new());
    let outcome = route_loaded_remote_signer_attestation_to_live_inbound_0x05_callsite_decision(
        &ctx, &loaded,
    );
    assert!(outcome.is_malformed_payload());
    assert!(outcome.is_reject());
    assert!(outcome.callsite_outcome().is_none(), "verifier not reached");
}

#[test]
fn r34_mainnet_peer_driven_apply_refused_even_with_fixture_loopback() {
    let c = ctx_for(TrustBundleEnvironment::Mainnet, AuthorityCustodyClass::FixtureLocalKey);
    let ctx = ctx_view(
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    let loaded = available_via_wire(&parts(TrustBundleEnvironment::Mainnet));
    let outcome =
        route_loaded_remote_signer_attestation_to_peer_driven_drain_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_mainnet_peer_driven_apply_refused());
    assert!(outcome.is_reject());
    assert!(mainnet_peer_driven_apply_remains_refused_under_remote_signer_payload_carrying(
        TrustBundleEnvironment::Mainnet
    ));
}

// ===========================================================================
// Source reachability
// ===========================================================================

#[test]
fn reachability_remote_signer_material_reaches_production_callsite_context() {
    // The carried wire material reaches a production call-site context
    // and drives the Run 194 composition to an accept.
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let ctx = ctx_view(
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    let loaded = available_via_wire(&parts(TrustBundleEnvironment::Devnet));
    let outcome =
        route_loaded_remote_signer_attestation_to_sighup_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_accept());
}

#[test]
fn reachability_validate_remote_signer_reached_from_payload_layer() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::RemoteSigner);
    let ctx = ctx_view(
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    let loaded = available_via_wire(&parts(TrustBundleEnvironment::Devnet));
    let outcome = validate_loaded_remote_signer(&ctx, &loaded).expect("available");
    assert!(matches!(
        outcome,
        RemoteSignerOutcome::FixtureLoopbackAccepted { .. }
    ));
}

#[test]
fn reachability_composition_reached_from_payload_layer() {
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let ctx = ctx_view(
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    let loaded = available_via_wire(&parts(TrustBundleEnvironment::Devnet));
    let outcome =
        route_loaded_remote_signer_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(matches!(
        outcome.callsite_outcome().unwrap(),
        LifecycleCustodyRemoteSignerOutcome::Accepted { .. }
    ));
}
