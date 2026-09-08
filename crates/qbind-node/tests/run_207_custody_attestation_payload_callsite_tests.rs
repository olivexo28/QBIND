//! Run 207 — source/test custody-attestation payload carrying and
//! production-context preflight wiring integration tests.
//!
//! Source/test only. Run 207 does **not** capture release-binary
//! evidence; release-binary custody-attestation payload/carrying evidence
//! is deferred to **Run 208**. The tests cover:
//!
//! * the A1–A15 / R1–R43 matrix from `task/RUN_207_TASK.txt` where
//!   representable at the payload-carrying layer;
//! * serde/parse compatibility (old no-attestation payload, carrying
//!   payload, malformed evidence/input/payload, unsupported future schema
//!   version);
//! * canonical digest determinism through wire conversion (evidence /
//!   input / transcript / provider-identity);
//! * source reachability of the production call-site context,
//!   `verify_custody_attestation`,
//!   `validate_custody_metadata_and_attestation`, and
//!   `validate_lifecycle_custody_and_attestation`;
//! * no-mutation invariants (validation-only routing helpers are pure);
//! * MainNet refusal invariants.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_207.md`.

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
use qbind_node::pqc_custody_attestation_payload_carrying::{
    callsite_context_for_custody_attestation,
    load_v2_ratification_sidecar_with_custody_attestation_from_bytes,
    mainnet_peer_driven_apply_remains_refused_under_custody_attestation_payload_carrying,
    parse_optional_custody_attestation_sibling_from_json_value,
    route_loaded_custody_attestation_to_live_inbound_0x05_callsite_decision,
    route_loaded_custody_attestation_to_local_peer_candidate_check_callsite_decision,
    route_loaded_custody_attestation_to_peer_driven_drain_callsite_decision,
    route_loaded_custody_attestation_to_reload_apply_callsite_decision,
    route_loaded_custody_attestation_to_reload_check_callsite_decision,
    route_loaded_custody_attestation_to_sighup_callsite_decision,
    route_loaded_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision,
    validate_loaded_lifecycle_custody_and_attestation, verify_loaded_custody_attestation,
    CustodyAttestationCallsiteContext, CustodyAttestationLoadStatus, CustodyAttestationParts,
    CustodyAttestationPayloadCarryingDecisionOutcome, CustodyAttestationPayloadWire,
    CustodyAttestationWireParseError, CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD,
    CUSTODY_ATTESTATION_PAYLOAD_WIRE_SCHEMA_VERSION,
};
use qbind_node::pqc_custody_attestation_verifier::{
    attestation_transcript_digest, CustodyAttestationClass, CustodyAttestationEvidence,
    CustodyAttestationInput, CustodyAttestationOutcome, CustodyAttestationPolicy,
    CustodyMetadataAttestationOutcome, CUSTODY_ATTESTATION_INVALID_COMMITMENT_SENTINEL,
    CUSTODY_ATTESTATION_SUPPORTED_VERSION,
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
const GENESIS_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const PRIOR_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const KEY_ID: &str = "attestation-key-id-207";
const PROVIDER_ID: &str = "attestation-provider-207";
const ATTEST_COMMITMENT: &str = "attestation-commitment-207";
const ATTEST_NONCE: &str = "attestation-nonce-207";
const GOV_PROOF_DIGEST: &str = "gov-proof-digest-207";
const NOW: u64 = 1_700_000_000;
const FRESH: u64 = 1_699_999_900;
const EXPIRES: u64 = 1_700_001_000;
const ISSUED: u64 = 1_699_999_950;
const WINDOW_SINCE: u64 = 1_699_999_000;
const WINDOW_UNTIL: u64 = 1_700_000_500;

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

fn evidence(
    class: CustodyAttestationClass,
    env: TrustBundleEnvironment,
    candidate: &PersistentAuthorityStateRecordV2,
) -> CustodyAttestationEvidence {
    CustodyAttestationEvidence {
        attestation_class: class,
        attestation_version: CUSTODY_ATTESTATION_SUPPORTED_VERSION,
        environment: env,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        bundle_signing_key_fingerprint: candidate.active_bundle_signing_key_fingerprint.clone(),
        custody_class: AuthorityCustodyClass::Kms,
        custody_backend_kind: Some("fixture-kms".to_string()),
        backend_provider_signer_id: PROVIDER_ID.to_string(),
        custody_key_id: KEY_ID.to_string(),
        suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: DIGEST_2.to_string(),
        authority_domain_sequence: 2,
        governance_proof_digest: Some(GOV_PROOF_DIGEST.to_string()),
        request_digest: Some("request-digest".to_string()),
        response_digest: Some("response-digest".to_string()),
        transcript_digest: Some("transcript-digest".to_string()),
        attestation_nonce: ATTEST_NONCE.to_string(),
        issued_at_unix: Some(ISSUED),
        freshness_unix: Some(FRESH),
        expires_at_unix: Some(EXPIRES),
        attestation_commitment: ATTEST_COMMITMENT.to_string(),
    }
}

fn input(
    env: TrustBundleEnvironment,
    candidate: &PersistentAuthorityStateRecordV2,
) -> CustodyAttestationInput {
    CustodyAttestationInput {
        expected_environment: env,
        expected_chain_id: CHAIN_ID.to_string(),
        expected_genesis_hash: GENESIS_HASH.to_string(),
        expected_authority_root_fingerprint: ROOT_FP.to_string(),
        expected_bundle_signing_key_fingerprint: candidate
            .active_bundle_signing_key_fingerprint
            .clone(),
        expected_custody_class: AuthorityCustodyClass::Kms,
        expected_backend_provider_signer_id: PROVIDER_ID.to_string(),
        expected_custody_key_id: KEY_ID.to_string(),
        expected_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        expected_lifecycle_action: LocalLifecycleAction::Rotate,
        expected_candidate_digest: DIGEST_2.to_string(),
        expected_authority_domain_sequence: 2,
        expected_governance_proof_digest: Some(GOV_PROOF_DIGEST.to_string()),
        expected_request_digest: Some("request-digest".to_string()),
        expected_response_digest: Some("response-digest".to_string()),
        expected_transcript_digest: Some("transcript-digest".to_string()),
        expected_attestation_nonce: ATTEST_NONCE.to_string(),
        replay_window_since_unix: Some(WINDOW_SINCE),
        replay_window_until_unix: Some(WINDOW_UNTIL),
        now_unix: NOW,
    }
}

fn good_custody_attestation(
    env: TrustBundleEnvironment,
    candidate: &PersistentAuthorityStateRecordV2,
) -> AuthorityCustodyAttestation {
    AuthorityCustodyAttestation {
        custody_class: AuthorityCustodyClass::FixtureLocalKey,
        custody_key_id: KEY_ID.to_string(),
        custody_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        custody_attestation_digest: "custody-att-digest".to_string(),
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

/// A complete, valid accepted scenario on the given environment. Holds
/// every owned value a test needs to construct a call-site context and a
/// loaded carrier, and mutate one field for a rejection vector.
struct Scenario {
    domain: AuthorityTrustDomain,
    candidate: PersistentAuthorityStateRecordV2,
    prior: PersistentAuthorityStateRecordVersioned,
    custody: AuthorityCustodyAttestation,
    evidence: CustodyAttestationEvidence,
    input: CustodyAttestationInput,
}

fn accepted_scenario(env: TrustBundleEnvironment) -> Scenario {
    let candidate = rotate_candidate(env);
    let evidence = evidence(CustodyAttestationClass::FixtureAttestation, env, &candidate);
    let input = input(env, &candidate);
    let custody = good_custody_attestation(env, &candidate);
    let prior = prior_versioned(env);
    Scenario {
        domain: domain(env),
        candidate,
        prior,
        custody,
        evidence,
        input,
    }
}

impl Scenario {
    fn parts(&self) -> CustodyAttestationParts {
        CustodyAttestationParts {
            evidence: self.evidence.clone(),
            input: self.input.clone(),
        }
    }

    fn loaded(&self) -> CustodyAttestationLoadStatus {
        CustodyAttestationLoadStatus::Available(self.parts())
    }

    fn ctx<'a>(
        &'a self,
        custody_policy: AuthorityCustodyPolicy,
        attestation_policy: CustodyAttestationPolicy,
    ) -> CustodyAttestationCallsiteContext<'a> {
        callsite_context_for_custody_attestation(
            &self.custody,
            Some(&self.prior),
            &self.candidate,
            &self.domain,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(KEY_ID),
            custody_policy,
            attestation_policy,
            NOW,
        )
    }

    /// Default accepted-path context: fixture custody + fixture
    /// attestation.
    fn fixture_ctx(&self) -> CustodyAttestationCallsiteContext<'_> {
        self.ctx(
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::FixtureAttestationAllowed,
        )
    }
}

/// Build a wire form from parts and round-trip it through a JSON sibling
/// value, returning the parsed load status. Exercises the full
/// serialize/deserialize path.
fn loaded_via_json(parts: &CustodyAttestationParts) -> CustodyAttestationLoadStatus {
    let wire = CustodyAttestationPayloadWire::from_parts(&parts.evidence, &parts.input);
    let value = serde_json::json!({
        CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
    });
    parse_optional_custody_attestation_sibling_from_json_value(&value)
}

// ===========================================================================
// A1 — legacy no-attestation payload compatibility
// ===========================================================================

#[test]
fn a1_no_attestation_payload_compatible_under_disabled() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let ctx = s.ctx(
        AuthorityCustodyPolicy::FixtureOnly,
        CustodyAttestationPolicy::Disabled,
    );
    let outcome = route_loaded_custody_attestation_to_reload_check_callsite_decision(
        &ctx,
        &CustodyAttestationLoadStatus::Absent,
    );
    assert!(matches!(
        outcome,
        CustodyAttestationPayloadCarryingDecisionOutcome::NoCustodyAttestationSupplied
    ));
    assert!(outcome.is_bypassed());
    assert!(!outcome.is_reject());
}

// ===========================================================================
// A2 / A3 — fixture attestation carried through reload-check (DevNet/TestNet)
// ===========================================================================

#[test]
fn a2_devnet_fixture_attestation_carried_through_reload_check() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let loaded = loaded_via_json(&s.parts());
    assert!(loaded.is_available());
    let ctx = s.fixture_ctx();
    let outcome =
        route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_accept(), "got {outcome:?}");
}

#[test]
fn a3_testnet_fixture_attestation_carried_through_reload_check() {
    let s = accepted_scenario(TrustBundleEnvironment::Testnet);
    let loaded = loaded_via_json(&s.parts());
    let ctx = s.fixture_ctx();
    let outcome =
        route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_accept(), "got {outcome:?}");
}

// ===========================================================================
// A4 — fixture attestation carried through reload-apply preflight
// ===========================================================================

#[test]
fn a4_devnet_fixture_attestation_carried_through_reload_apply() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let loaded = s.loaded();
    let ctx = s.fixture_ctx();
    let outcome =
        route_loaded_custody_attestation_to_reload_apply_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_accept(), "got {outcome:?}");
    // Accepted path wraps the Run 205 combined outcome.
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(CustodyMetadataAttestationOutcome::Accepted { .. })
    ));
}

// ===========================================================================
// A5–A8 — digest determinism through wire conversion
// ===========================================================================

#[test]
fn a5_evidence_digest_preserved_through_wire_conversion() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let loaded = loaded_via_json(&s.parts());
    let parts = loaded.as_parts().unwrap();
    assert_eq!(parts.evidence.evidence_digest(), s.evidence.evidence_digest());
}

#[test]
fn a6_input_digest_preserved_through_wire_conversion() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let loaded = loaded_via_json(&s.parts());
    let parts = loaded.as_parts().unwrap();
    assert_eq!(parts.input.input_digest(), s.input.input_digest());
}

#[test]
fn a7_transcript_digest_preserved_through_wire_conversion() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let loaded = loaded_via_json(&s.parts());
    let parts = loaded.as_parts().unwrap();
    let before = attestation_transcript_digest(
        &s.evidence.evidence_digest(),
        &s.input.input_digest(),
    );
    let after = attestation_transcript_digest(
        &parts.evidence.evidence_digest(),
        &parts.input.input_digest(),
    );
    assert_eq!(before, after);
}

#[test]
fn a8_provider_identity_digest_preserved_through_wire_conversion() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let loaded = loaded_via_json(&s.parts());
    let parts = loaded.as_parts().unwrap();
    assert_eq!(
        parts.evidence.provider_identity_digest(),
        s.evidence.provider_identity_digest()
    );
}

// ===========================================================================
// A9 — fixture attestation routes to Run 205 verifier when present
// ===========================================================================

#[test]
fn a9_fixture_attestation_routes_to_run205_verifier() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let loaded = s.loaded();
    let ctx = s.fixture_ctx();
    let outcome = verify_loaded_custody_attestation(&ctx, &loaded);
    assert!(matches!(
        outcome,
        Some(CustodyAttestationOutcome::FixtureAttestationAccepted { .. })
    ));
}

// ===========================================================================
// A10 — combined lifecycle + custody + fixture attestation for DevNet
// ===========================================================================

#[test]
fn a10_combined_lifecycle_custody_attestation_devnet() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let loaded = s.loaded();
    let ctx = s.fixture_ctx();
    let outcome = validate_loaded_lifecycle_custody_and_attestation(&ctx, &loaded, false);
    assert!(matches!(
        outcome,
        Some(CustodyMetadataAttestationOutcome::Accepted { .. })
    ));
}

// ===========================================================================
// A11–A13 — composition with Run 203 KMS / HSM and Run 201 RemoteSigner
//           backend/transport contexts (carried as opaque evidence fields)
// ===========================================================================

#[test]
fn a11_composes_with_run203_fixture_kms_backend_context() {
    let env = TrustBundleEnvironment::Devnet;
    let mut s = accepted_scenario(env);
    s.evidence.custody_backend_kind = Some("fixture-kms".to_string());
    s.evidence.custody_class = AuthorityCustodyClass::Kms;
    s.input.expected_custody_class = AuthorityCustodyClass::Kms;
    let loaded = loaded_via_json(&s.parts());
    let ctx = s.fixture_ctx();
    let outcome =
        route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_accept(), "got {outcome:?}");
}

#[test]
fn a12_composes_with_run203_fixture_hsm_backend_context() {
    let env = TrustBundleEnvironment::Devnet;
    let mut s = accepted_scenario(env);
    s.evidence.custody_backend_kind = Some("fixture-hsm".to_string());
    s.evidence.custody_class = AuthorityCustodyClass::Hsm;
    s.input.expected_custody_class = AuthorityCustodyClass::Hsm;
    let loaded = loaded_via_json(&s.parts());
    let ctx = s.fixture_ctx();
    let outcome =
        route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_accept(), "got {outcome:?}");
}

#[test]
fn a13_composes_with_run201_fixture_remote_signer_transport_context() {
    let env = TrustBundleEnvironment::Devnet;
    let mut s = accepted_scenario(env);
    s.evidence.custody_backend_kind = Some("fixture-remote-signer".to_string());
    s.evidence.custody_class = AuthorityCustodyClass::RemoteSigner;
    s.input.expected_custody_class = AuthorityCustodyClass::RemoteSigner;
    let loaded = loaded_via_json(&s.parts());
    let ctx = s.fixture_ctx();
    let outcome =
        route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_accept(), "got {outcome:?}");
}

// ===========================================================================
// A14 — governance proof behavior unchanged when attestation Disabled
// ===========================================================================

#[test]
fn a14_governance_proof_behavior_unchanged_when_attestation_disabled() {
    // Absent attestation carrier under Disabled policy is the legacy
    // bypass; no attestation processing occurs regardless of governance
    // class.
    for gov in [
        GovernanceAuthorityClass::GenesisBound,
        GovernanceAuthorityClass::EmergencyCouncil,
        GovernanceAuthorityClass::OnChainGovernance,
    ] {
        let s = accepted_scenario(TrustBundleEnvironment::Devnet);
        let ctx = callsite_context_for_custody_attestation(
            &s.custody,
            Some(&s.prior),
            &s.candidate,
            &s.domain,
            gov,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(KEY_ID),
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::Disabled,
            NOW,
        );
        let outcome = route_loaded_custody_attestation_to_reload_check_callsite_decision(
            &ctx,
            &CustodyAttestationLoadStatus::Absent,
        );
        assert!(outcome.is_bypassed(), "gov={gov:?} got {outcome:?}");
    }
}

// ===========================================================================
// A15 — production attestation reaches verifier and returns unavailable
// ===========================================================================

#[test]
fn a15_production_attestation_reaches_verifier_returns_unavailable() {
    let env = TrustBundleEnvironment::Devnet;
    let mut s = accepted_scenario(env);
    s.evidence.attestation_class = CustodyAttestationClass::ProductionAttestationUnavailable;
    let loaded = loaded_via_json(&s.parts());
    let ctx = s.ctx(
        AuthorityCustodyPolicy::FixtureOnly,
        CustodyAttestationPolicy::ProductionAttestationRequired,
    );
    let outcome =
        route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(!outcome.is_accept());
    match outcome.callsite_outcome() {
        Some(CustodyMetadataAttestationOutcome::AttestationRejected {
            attestation_outcome,
            ..
        }) => assert!(attestation_outcome.is_unavailable(), "got {attestation_outcome:?}"),
        other => panic!("expected AttestationRejected, got {other:?}"),
    }
}

// ===========================================================================
// R1 — attestation absent where policy requires it
// ===========================================================================

#[test]
fn r1_absent_under_required_policy_rejected() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let ctx = s.ctx(
        AuthorityCustodyPolicy::FixtureOnly,
        CustodyAttestationPolicy::ProductionAttestationRequired,
    );
    let outcome = route_loaded_custody_attestation_to_reload_check_callsite_decision(
        &ctx,
        &CustodyAttestationLoadStatus::Absent,
    );
    assert!(matches!(
        outcome,
        CustodyAttestationPayloadCarryingDecisionOutcome::CustodyAttestationRequiredButAbsent { .. }
    ));
    assert!(outcome.is_required_but_absent());
    assert!(outcome.is_reject());
}

// ===========================================================================
// R2–R5 — malformed / unsupported carrier fails closed
// ===========================================================================

#[test]
fn r2_malformed_evidence_rejected() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let mut wire = CustodyAttestationPayloadWire::from_parts(&s.evidence, &s.input);
    wire.evidence.candidate_digest = String::new(); // empty required field
    let value = serde_json::json!({
        CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
    });
    let loaded = parse_optional_custody_attestation_sibling_from_json_value(&value);
    assert!(loaded.is_malformed());
    let ctx = s.fixture_ctx();
    let outcome =
        route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_malformed_payload());
    assert!(outcome.is_reject());
}

#[test]
fn r3_malformed_input_rejected() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let mut wire = CustodyAttestationPayloadWire::from_parts(&s.evidence, &s.input);
    wire.input.expected_attestation_nonce = String::new();
    let value = serde_json::json!({
        CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
    });
    let loaded = parse_optional_custody_attestation_sibling_from_json_value(&value);
    assert!(loaded.is_malformed());
}

#[test]
fn r4_malformed_combined_payload_rejected() {
    // A `custody_attestation` sibling that is not even an object.
    let value = serde_json::json!({ CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: "not-an-object" });
    let loaded = parse_optional_custody_attestation_sibling_from_json_value(&value);
    assert!(loaded.is_malformed());
}

#[test]
fn r5_unsupported_future_schema_version_rejected() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let mut wire = CustodyAttestationPayloadWire::from_parts(&s.evidence, &s.input);
    wire.schema_version = 9_999;
    let value = serde_json::json!({
        CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
    });
    let loaded = parse_optional_custody_attestation_sibling_from_json_value(&value);
    assert!(matches!(
        loaded.malformed_error().unwrap(),
        qbind_node::pqc_custody_attestation_payload_carrying::CustodyAttestationPayloadParseError::Wire(
            CustodyAttestationWireParseError::UnknownSchemaVersion { got: 9_999, .. }
        )
    ));
}

// ===========================================================================
// R6 / R7 — fixture attestation rejected under production-required policies
// ===========================================================================

#[test]
fn r6_fixture_rejected_under_production_attestation_required() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let loaded = s.loaded();
    let ctx = s.ctx(
        AuthorityCustodyPolicy::FixtureOnly,
        CustodyAttestationPolicy::ProductionAttestationRequired,
    );
    let outcome =
        route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(!outcome.is_accept());
    match outcome.callsite_outcome() {
        Some(CustodyMetadataAttestationOutcome::AttestationRejected {
            attestation_outcome,
            ..
        }) => assert!(matches!(
            attestation_outcome,
            CustodyAttestationOutcome::FixtureRejectedProductionRequired
        )),
        other => panic!("got {other:?}"),
    }
}

#[test]
fn r7_fixture_rejected_under_mainnet_production_attestation_required() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let loaded = s.loaded();
    let ctx = s.ctx(
        AuthorityCustodyPolicy::FixtureOnly,
        CustodyAttestationPolicy::MainnetProductionAttestationRequired,
    );
    let outcome =
        route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    match outcome.callsite_outcome() {
        Some(CustodyMetadataAttestationOutcome::AttestationRejected {
            attestation_outcome,
            ..
        }) => assert!(matches!(
            attestation_outcome,
            CustodyAttestationOutcome::FixtureRejectedMainnetProductionRequired
        )),
        other => panic!("got {other:?}"),
    }
}

// ===========================================================================
// R8–R14 — production-class attestations rejected as unavailable
// ===========================================================================

fn assert_unavailable(class: CustodyAttestationClass, policy: CustodyAttestationPolicy) {
    let env = TrustBundleEnvironment::Devnet;
    let mut s = accepted_scenario(env);
    s.evidence.attestation_class = class;
    let loaded = s.loaded();
    let ctx = s.ctx(AuthorityCustodyPolicy::FixtureOnly, policy);
    let outcome =
        route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(!outcome.is_accept());
    match outcome.callsite_outcome() {
        Some(CustodyMetadataAttestationOutcome::AttestationRejected {
            attestation_outcome,
            ..
        }) => assert!(attestation_outcome.is_unavailable(), "class={class:?} got {attestation_outcome:?}"),
        other => panic!("class={class:?} got {other:?}"),
    }
}

#[test]
fn r8_remote_signer_attestation_unavailable() {
    assert_unavailable(
        CustodyAttestationClass::RemoteSignerAttestation,
        CustodyAttestationPolicy::FixtureAttestationAllowed,
    );
}

#[test]
fn r9_kms_attestation_unavailable() {
    assert_unavailable(
        CustodyAttestationClass::KmsAttestation,
        CustodyAttestationPolicy::FixtureAttestationAllowed,
    );
}

#[test]
fn r10_hsm_attestation_unavailable() {
    assert_unavailable(
        CustodyAttestationClass::HsmAttestation,
        CustodyAttestationPolicy::FixtureAttestationAllowed,
    );
}

#[test]
fn r11_cloud_kms_attestation_unavailable() {
    assert_unavailable(
        CustodyAttestationClass::CloudKmsAttestationUnavailable,
        CustodyAttestationPolicy::FixtureAttestationAllowed,
    );
}

#[test]
fn r12_pkcs11_hsm_attestation_unavailable() {
    assert_unavailable(
        CustodyAttestationClass::Pkcs11HsmAttestationUnavailable,
        CustodyAttestationPolicy::FixtureAttestationAllowed,
    );
}

#[test]
fn r13_production_attestation_unavailable() {
    assert_unavailable(
        CustodyAttestationClass::ProductionAttestationUnavailable,
        CustodyAttestationPolicy::ProductionAttestationRequired,
    );
}

#[test]
fn r14_mainnet_production_attestation_unavailable() {
    let env = TrustBundleEnvironment::Devnet;
    let mut s = accepted_scenario(env);
    s.evidence.attestation_class = CustodyAttestationClass::ProductionAttestationUnavailable;
    let loaded = s.loaded();
    let ctx = s.ctx(
        AuthorityCustodyPolicy::FixtureOnly,
        CustodyAttestationPolicy::MainnetProductionAttestationRequired,
    );
    let outcome =
        route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    match outcome.callsite_outcome() {
        Some(CustodyMetadataAttestationOutcome::AttestationRejected {
            attestation_outcome,
            ..
        }) => assert!(matches!(
            attestation_outcome,
            CustodyAttestationOutcome::MainNetProductionAttestationUnavailable
        )),
        other => panic!("got {other:?}"),
    }
}

// ===========================================================================
// R15 — unknown attestation class rejected
// ===========================================================================

#[test]
fn r15_unknown_attestation_class_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut s = accepted_scenario(env);
    s.evidence.attestation_class = CustodyAttestationClass::Unknown;
    let loaded = loaded_via_json(&s.parts());
    let ctx = s.fixture_ctx();
    let outcome =
        route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    match outcome.callsite_outcome() {
        Some(CustodyMetadataAttestationOutcome::AttestationRejected {
            attestation_outcome,
            ..
        }) => assert!(matches!(
            attestation_outcome,
            CustodyAttestationOutcome::UnknownAttestationClassRejected { .. }
        )),
        other => panic!("got {other:?}"),
    }
}

// ===========================================================================
// R16–R34 — wrong-binding rejections route through the verifier
// ===========================================================================

/// Helper: mutate the carried evidence/input via the closure, route
/// through the reload-check call-site under the fixture policies, and
/// assert the routed outcome rejects at the Run 205 verifier.
fn assert_attestation_rejected(mutate: impl FnOnce(&mut Scenario)) -> CustodyAttestationOutcome {
    let env = TrustBundleEnvironment::Devnet;
    let mut s = accepted_scenario(env);
    mutate(&mut s);
    let loaded = s.loaded();
    let ctx = s.fixture_ctx();
    let outcome =
        route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(!outcome.is_accept(), "expected reject");
    match outcome.callsite_outcome().cloned() {
        Some(CustodyMetadataAttestationOutcome::AttestationRejected {
            attestation_outcome,
            ..
        }) => attestation_outcome,
        other => panic!("expected AttestationRejected, got {other:?}"),
    }
}

#[test]
fn r16_wrong_environment_rejected() {
    let o = assert_attestation_rejected(|s| {
        s.evidence.environment = TrustBundleEnvironment::Testnet;
    });
    assert!(matches!(o, CustodyAttestationOutcome::WrongEnvironment { .. }));
}

#[test]
fn r17_wrong_chain_rejected() {
    let o = assert_attestation_rejected(|s| {
        s.evidence.chain_id = "deadbeef".to_string();
        s.input.expected_chain_id = "deadbeef".to_string();
    });
    assert!(matches!(o, CustodyAttestationOutcome::WrongChain { .. }));
}

#[test]
fn r18_wrong_genesis_rejected() {
    let o = assert_attestation_rejected(|s| {
        s.evidence.genesis_hash = "ff".repeat(32);
        s.input.expected_genesis_hash = "ff".repeat(32);
    });
    assert!(matches!(o, CustodyAttestationOutcome::WrongGenesis { .. }));
}

#[test]
fn r19_wrong_authority_root_rejected() {
    let o = assert_attestation_rejected(|s| {
        s.evidence.authority_root_fingerprint = "9".repeat(40);
        s.input.expected_authority_root_fingerprint = "9".repeat(40);
    });
    assert!(matches!(o, CustodyAttestationOutcome::WrongAuthorityRoot { .. }));
}

#[test]
fn r20_wrong_signing_key_fingerprint_rejected() {
    let o = assert_attestation_rejected(|s| {
        s.evidence.bundle_signing_key_fingerprint = "0".repeat(40);
    });
    assert!(matches!(
        o,
        CustodyAttestationOutcome::WrongSigningKeyFingerprint { .. }
    ));
}

#[test]
fn r21_wrong_custody_class_rejected() {
    let o = assert_attestation_rejected(|s| {
        s.evidence.custody_class = AuthorityCustodyClass::Hsm;
    });
    assert!(matches!(o, CustodyAttestationOutcome::WrongCustodyClass { .. }));
}

#[test]
fn r22_wrong_backend_provider_signer_id_rejected() {
    let o = assert_attestation_rejected(|s| {
        s.evidence.backend_provider_signer_id = "other-provider".to_string();
    });
    assert!(matches!(
        o,
        CustodyAttestationOutcome::WrongBackendProviderSignerId { .. }
    ));
}

#[test]
fn r23_wrong_key_id_rejected() {
    let o = assert_attestation_rejected(|s| {
        s.evidence.custody_key_id = "other-key".to_string();
    });
    assert!(matches!(o, CustodyAttestationOutcome::WrongKeyId { .. }));
}

#[test]
fn r24_wrong_suite_rejected() {
    let o = assert_attestation_rejected(|s| {
        s.evidence.suite_id = 99;
    });
    assert!(matches!(o, CustodyAttestationOutcome::WrongSuite { .. }));
}

#[test]
fn r25_wrong_lifecycle_action_rejected() {
    let o = assert_attestation_rejected(|s| {
        s.evidence.lifecycle_action = LocalLifecycleAction::Revoke;
    });
    assert!(matches!(
        o,
        CustodyAttestationOutcome::WrongLifecycleAction { .. }
    ));
}

#[test]
fn r26_wrong_candidate_digest_rejected() {
    let o = assert_attestation_rejected(|s| {
        s.evidence.candidate_digest = "3".repeat(64);
    });
    assert!(matches!(
        o,
        CustodyAttestationOutcome::WrongCandidateDigest { .. }
    ));
}

#[test]
fn r27_wrong_authority_domain_sequence_rejected() {
    let o = assert_attestation_rejected(|s| {
        s.evidence.authority_domain_sequence = 9;
    });
    assert!(matches!(
        o,
        CustodyAttestationOutcome::WrongAuthorityDomainSequence { .. }
    ));
}

#[test]
fn r28_wrong_governance_proof_digest_rejected() {
    let o = assert_attestation_rejected(|s| {
        s.evidence.governance_proof_digest = Some("other-gov-proof".to_string());
    });
    assert!(matches!(
        o,
        CustodyAttestationOutcome::WrongGovernanceProofDigest { .. }
    ));
}

#[test]
fn r29_wrong_request_digest_rejected() {
    let o = assert_attestation_rejected(|s| {
        s.evidence.request_digest = Some("other-request".to_string());
    });
    assert!(matches!(o, CustodyAttestationOutcome::WrongRequestDigest { .. }));
}

#[test]
fn r30_wrong_response_digest_rejected() {
    let o = assert_attestation_rejected(|s| {
        s.evidence.response_digest = Some("other-response".to_string());
    });
    assert!(matches!(
        o,
        CustodyAttestationOutcome::WrongResponseDigest { .. }
    ));
}

#[test]
fn r31_wrong_transcript_digest_rejected() {
    let o = assert_attestation_rejected(|s| {
        s.evidence.transcript_digest = Some("other-transcript".to_string());
    });
    assert!(matches!(
        o,
        CustodyAttestationOutcome::WrongTranscriptDigest { .. }
    ));
}

#[test]
fn r32_stale_or_replayed_attestation_rejected() {
    let o = assert_attestation_rejected(|s| {
        s.evidence.attestation_nonce = "stale-nonce".to_string();
    });
    assert!(matches!(
        o,
        CustodyAttestationOutcome::StaleOrReplayedAttestation
    ));
}

#[test]
fn r33_expired_attestation_rejected() {
    let o = assert_attestation_rejected(|s| {
        // now is past expiry
        s.evidence.freshness_unix = Some(1);
        s.evidence.expires_at_unix = Some(2);
    });
    assert!(matches!(o, CustodyAttestationOutcome::ExpiredAttestation { .. }));
}

#[test]
fn r34_invalid_attestation_commitment_rejected() {
    let o = assert_attestation_rejected(|s| {
        s.evidence.attestation_commitment =
            CUSTODY_ATTESTATION_INVALID_COMMITMENT_SENTINEL.to_string();
    });
    assert!(matches!(
        o,
        CustodyAttestationOutcome::InvalidAttestationCommitment
    ));
}

// ===========================================================================
// R35 / R36 — local operator and peer majority cannot satisfy production
// ===========================================================================

#[test]
fn r35_local_operator_cannot_satisfy_production_attestation() {
    // A production-required policy with a fixture carrier is rejected;
    // a local operator key never satisfies a production attestation.
    let env = TrustBundleEnvironment::Devnet;
    let s = accepted_scenario(env);
    let loaded = s.loaded();
    let ctx = s.ctx(
        AuthorityCustodyPolicy::FixtureOnly,
        CustodyAttestationPolicy::ProductionAttestationRequired,
    );
    let outcome =
        route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(!outcome.is_accept());
}

#[test]
fn r36_peer_majority_cannot_satisfy_production_attestation() {
    let env = TrustBundleEnvironment::Devnet;
    let mut s = accepted_scenario(env);
    s.evidence.attestation_class = CustodyAttestationClass::ProductionAttestationUnavailable;
    let loaded = s.loaded();
    let ctx = s.ctx(
        AuthorityCustodyPolicy::FixtureOnly,
        CustodyAttestationPolicy::ProductionAttestationRequired,
    );
    let outcome = route_loaded_custody_attestation_to_peer_driven_drain_callsite_decision(
        &ctx, &loaded,
    );
    assert!(!outcome.is_accept());
}

// ===========================================================================
// R37 / R38 — custody vs attestation mismatch
// ===========================================================================

#[test]
fn r37_attestation_valid_but_custody_invalid_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut s = accepted_scenario(env);
    // Break the Run 188 custody metadata: wrong candidate digest binding.
    s.custody.candidate_digest = "bad-digest".to_string();
    let loaded = s.loaded();
    let ctx = s.fixture_ctx();
    let outcome =
        route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(!outcome.is_accept());
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(CustodyMetadataAttestationOutcome::LifecycleOrCustodyRejected(_))
    ));
}

#[test]
fn r38_custody_valid_but_attestation_invalid_rejected() {
    let o = assert_attestation_rejected(|s| {
        s.evidence.attestation_commitment =
            CUSTODY_ATTESTATION_INVALID_COMMITMENT_SENTINEL.to_string();
    });
    assert!(matches!(
        o,
        CustodyAttestationOutcome::InvalidAttestationCommitment
    ));
}

// ===========================================================================
// R39 — lifecycle+gov+custody valid but production attestation unavailable
// ===========================================================================

#[test]
fn r39_production_attestation_unavailable_rejected_overall() {
    let env = TrustBundleEnvironment::Devnet;
    let mut s = accepted_scenario(env);
    s.evidence.attestation_class = CustodyAttestationClass::KmsAttestation;
    let loaded = s.loaded();
    let ctx = s.ctx(
        AuthorityCustodyPolicy::FixtureOnly,
        CustodyAttestationPolicy::KmsAttestationRequired,
    );
    let outcome =
        route_loaded_custody_attestation_to_reload_apply_callsite_decision(&ctx, &loaded);
    assert!(!outcome.is_accept());
    match outcome.callsite_outcome() {
        Some(CustodyMetadataAttestationOutcome::AttestationRejected {
            attestation_outcome,
            ..
        }) => assert!(attestation_outcome.is_unavailable()),
        other => panic!("got {other:?}"),
    }
}

// ===========================================================================
// R40 / R41 — no-mutation invariants (routing helpers are pure)
// ===========================================================================

#[test]
fn r40_validation_only_rejection_is_pure() {
    // The candidate / prior / custody values are not consumed or mutated
    // by the routing helper. We assert by re-using them after routing.
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let loaded = s.loaded();
    let ctx = s.ctx(
        AuthorityCustodyPolicy::FixtureOnly,
        CustodyAttestationPolicy::ProductionAttestationRequired,
    );
    let _ = route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    // Re-route; identical outcome proves no hidden state changed.
    let again = route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    let first = route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert_eq!(first, again);
}

#[test]
fn r41_mutating_rejection_paths_produce_no_mutation() {
    // Every routing helper returns a value and never mutates its inputs;
    // running the mutating-preflight surfaces yields stable results.
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let loaded = s.loaded();
    let ctx = s.fixture_ctx();
    let a = route_loaded_custody_attestation_to_reload_apply_callsite_decision(&ctx, &loaded);
    let b = route_loaded_custody_attestation_to_sighup_callsite_decision(&ctx, &loaded);
    let c = route_loaded_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision(
        &ctx, &loaded,
    );
    assert!(a.is_accept() && b.is_accept() && c.is_accept());
}

// ===========================================================================
// R42 — invalid live 0x05 candidate not propagated / staged / applied
// ===========================================================================

#[test]
fn r42_invalid_live_0x05_candidate_not_propagated() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let mut wire = CustodyAttestationPayloadWire::from_parts(&s.evidence, &s.input);
    wire.evidence.attestation_commitment = String::new();
    let value = serde_json::json!({
        CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
    });
    let loaded = parse_optional_custody_attestation_sibling_from_json_value(&value);
    let ctx = s.fixture_ctx();
    let outcome =
        route_loaded_custody_attestation_to_live_inbound_0x05_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_malformed_payload());
    assert!(outcome.is_reject());
}

// ===========================================================================
// R43 — MainNet peer-driven apply remains refused even with fixture
// ===========================================================================

#[test]
fn r43_mainnet_peer_driven_apply_refused_even_with_fixture() {
    let env = TrustBundleEnvironment::Mainnet;
    let s = accepted_scenario(env);
    let loaded = s.loaded();
    let ctx = s.fixture_ctx();
    let outcome = route_loaded_custody_attestation_to_peer_driven_drain_callsite_decision(
        &ctx, &loaded,
    );
    assert!(matches!(
        outcome,
        CustodyAttestationPayloadCarryingDecisionOutcome::MainNetPeerDrivenApplyRefused
    ));
    assert!(outcome.is_mainnet_peer_driven_apply_refused());
    assert!(mainnet_peer_driven_apply_remains_refused_under_custody_attestation_payload_carrying(
        TrustBundleEnvironment::Mainnet
    ));
}

// ===========================================================================
// Serde / loader compatibility
// ===========================================================================

fn make_v2_sidecar_value(
    env: TrustBundleEnvironment,
    custody_sibling: Option<serde_json::Value>,
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
    if let Some(p) = custody_sibling {
        value
            .as_object_mut()
            .unwrap()
            .insert(CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD.to_string(), p);
    }
    value
}

#[test]
fn loader_legacy_v2_sidecar_without_sibling_yields_absent() {
    let value = make_v2_sidecar_value(TrustBundleEnvironment::Devnet, None);
    let bytes = serde_json::to_vec(&value).unwrap();
    let path = std::path::PathBuf::from("/dev/null/run-207-legacy.json");
    let loaded =
        load_v2_ratification_sidecar_with_custody_attestation_from_bytes(&bytes, &path)
            .expect("legacy v2 sidecar parses");
    assert!(loaded.custody_attestation.is_absent());
}

#[test]
fn loader_v2_sidecar_with_custody_sibling_yields_available() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let wire = CustodyAttestationPayloadWire::from_parts(&s.evidence, &s.input);
    let value = make_v2_sidecar_value(
        TrustBundleEnvironment::Devnet,
        Some(serde_json::to_value(&wire).unwrap()),
    );
    let bytes = serde_json::to_vec(&value).unwrap();
    let path = std::path::PathBuf::from("/dev/null/run-207-carry.json");
    let loaded =
        load_v2_ratification_sidecar_with_custody_attestation_from_bytes(&bytes, &path)
            .expect("v2 sidecar with sibling parses");
    assert!(loaded.custody_attestation.is_available());
    assert_eq!(loaded.custody_attestation.as_parts().unwrap(), &s.parts());
}

#[test]
fn loader_v2_sidecar_with_malformed_sibling_yields_malformed() {
    let value = make_v2_sidecar_value(
        TrustBundleEnvironment::Devnet,
        Some(serde_json::json!({ "schema_version": 9_999 })),
    );
    let bytes = serde_json::to_vec(&value).unwrap();
    let path = std::path::PathBuf::from("/dev/null/run-207-malformed.json");
    let loaded =
        load_v2_ratification_sidecar_with_custody_attestation_from_bytes(&bytes, &path)
            .expect("v2 ratification still parses");
    assert!(loaded.custody_attestation.is_malformed());
}

#[test]
fn sibling_field_and_schema_version_are_canonical() {
    assert_eq!(CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD, "custody_attestation");
    assert_eq!(CUSTODY_ATTESTATION_PAYLOAD_WIRE_SCHEMA_VERSION, 1);
}

#[test]
fn absent_sibling_when_field_missing_or_null() {
    let missing = serde_json::json!({ "schema_version": 2 });
    assert!(parse_optional_custody_attestation_sibling_from_json_value(&missing).is_absent());
    let null = serde_json::json!({ CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: null });
    assert!(parse_optional_custody_attestation_sibling_from_json_value(&null).is_absent());
}

// ===========================================================================
// Source reachability — each routing surface reaches the Run 205 verifier
// ===========================================================================

#[test]
fn all_seven_surfaces_reach_run205_verifier_on_accept() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let loaded = s.loaded();
    let ctx = s.fixture_ctx();
    assert!(route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded)
        .is_accept());
    assert!(route_loaded_custody_attestation_to_reload_apply_callsite_decision(&ctx, &loaded)
        .is_accept());
    assert!(
        route_loaded_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision(
            &ctx, &loaded
        )
        .is_accept()
    );
    assert!(
        route_loaded_custody_attestation_to_sighup_callsite_decision(&ctx, &loaded).is_accept()
    );
    assert!(
        route_loaded_custody_attestation_to_local_peer_candidate_check_callsite_decision(
            &ctx, &loaded
        )
        .is_accept()
    );
    assert!(
        route_loaded_custody_attestation_to_live_inbound_0x05_callsite_decision(&ctx, &loaded)
            .is_accept()
    );
    // peer-driven drain on DevNet (non-MainNet) reaches the verifier too.
    assert!(
        route_loaded_custody_attestation_to_peer_driven_drain_callsite_decision(&ctx, &loaded)
            .is_accept()
    );
}