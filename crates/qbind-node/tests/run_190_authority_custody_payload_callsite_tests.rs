//! Run 190 — source/test authority-custody metadata carrying and
//! production call-site wiring tests.
//!
//! Source/test only. Run 190 does **not** capture release-binary
//! evidence; release-binary custody-metadata evidence is deferred to
//! **Run 191**. Default policy remains
//! [`AuthorityCustodyPolicy::Disabled`]. Real KMS / HSM / cloud-KMS
//! / PKCS#11 / remote-signer backends remain unimplemented; every
//! production-class custody attempt fails closed via the Run 188
//! validator. MainNet peer-driven apply remains the Run 147 / 148 /
//! 152 FATAL refusal regardless of custody attestation contents.
//! Real on-chain governance proof verification, governance execution,
//! and validator-set rotation all remain unimplemented. Full C4
//! remains open. C5 remains open.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_190.md`.
//!
//! These tests target the additive optional
//! `authority_custody_attestation` sibling on the v2 ratification
//! sidecar JSON, the typed [`AuthorityCustodyLoadStatus`], the wire
//! form [`AuthorityCustodyAttestationWire`], and the seven
//! per-surface routing helpers
//! ([`route_loaded_authority_custody_attestation_to_*_callsite_decision`])
//! exposed by [`qbind_node::pqc_authority_custody_payload_carrying`].

use qbind_ledger::BundleSigningRatificationV2Action;
use qbind_node::pqc_authority_custody::{
    local_operator_config_alone_cannot_satisfy_mainnet_production_custody,
    mainnet_peer_driven_apply_remains_refused_under_custody_boundary,
    peer_majority_cannot_satisfy_custody, validate_authority_custody_attestation,
    validate_lifecycle_governance_and_custody, AuthorityCustodyAttestation, AuthorityCustodyClass,
    AuthorityCustodyPolicy, AuthorityCustodyValidationOutcome, LifecycleGovernanceCustodyOutcome,
};
use qbind_node::pqc_authority_custody_payload_carrying::{
    callsite_context_for_authority_custody,
    mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying,
    parse_optional_authority_custody_attestation_sibling_from_json_value,
    route_loaded_authority_custody_attestation_to_live_inbound_0x05_callsite_decision,
    route_loaded_authority_custody_attestation_to_local_peer_candidate_check_callsite_decision,
    route_loaded_authority_custody_attestation_to_peer_driven_drain_callsite_decision,
    route_loaded_authority_custody_attestation_to_reload_apply_callsite_decision,
    route_loaded_authority_custody_attestation_to_reload_check_callsite_decision,
    route_loaded_authority_custody_attestation_to_sighup_callsite_decision,
    route_loaded_authority_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision,
    AuthorityCustodyAttestationPayloadParseError, AuthorityCustodyAttestationWire,
    AuthorityCustodyAttestationWireParseError, AuthorityCustodyCallsiteContext,
    AuthorityCustodyClassWire, AuthorityCustodyLoadStatus,
    AuthorityCustodyPayloadCarryingDecisionOutcome, GovernanceAuthorityClassWire,
    AUTHORITY_CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD,
    AUTHORITY_CUSTODY_ATTESTATION_WIRE_SCHEMA_VERSION,
};
use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_state::{
    AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
    PersistentAuthorityStateRecordVersioned,
};
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared fixtures (kept structurally identical to Run 188 so the typed
// custody-binding semantics carry over).
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
const CUSTODY_ATTEST_DIGEST: &str = "custody-att-digest-190";
const CUSTODY_KEY_ID: &str = "custody-key-id-190";
const OTHER_CUSTODY_KEY_ID: &str = "custody-key-id-other";
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

fn good_attestation(
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

fn devnet_ctx<'a>(
    persisted: Option<&'a PersistentAuthorityStateRecordVersioned>,
    candidate: &'a PersistentAuthorityStateRecordV2,
    domain: &'a AuthorityTrustDomain,
    policy: AuthorityCustodyPolicy,
) -> AuthorityCustodyCallsiteContext<'a> {
    callsite_context_for_authority_custody(
        persisted,
        candidate,
        domain,
        policy,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        NOW,
    )
}

fn wire_for(att: &AuthorityCustodyAttestation) -> AuthorityCustodyAttestationWire {
    AuthorityCustodyAttestationWire::from_attestation(att)
}

fn sibling_value_for(att: &AuthorityCustodyAttestation) -> serde_json::Value {
    serde_json::json!({
        AUTHORITY_CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD:
            serde_json::to_value(wire_for(att)).unwrap()
    })
}

// ===========================================================================
// Type-shape regressions
// ===========================================================================

#[test]
fn run_190_default_custody_policy_remains_disabled_fail_closed() {
    assert_eq!(AuthorityCustodyPolicy::default(), AuthorityCustodyPolicy::Disabled);
}

#[test]
fn run_190_wire_schema_version_is_one_and_field_name_is_canonical() {
    assert_eq!(AUTHORITY_CUSTODY_ATTESTATION_WIRE_SCHEMA_VERSION, 1);
    assert_eq!(
        AUTHORITY_CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD,
        "authority_custody_attestation"
    );
}

#[test]
fn run_190_class_wire_round_trips_through_every_class() {
    for c in [
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyClass::LocalOperatorKey,
        AuthorityCustodyClass::RemoteSigner,
        AuthorityCustodyClass::Kms,
        AuthorityCustodyClass::Hsm,
        AuthorityCustodyClass::Unknown,
    ] {
        let wire = AuthorityCustodyClassWire::from_class(c);
        assert_eq!(wire.to_class(), c);
    }
}

#[test]
fn run_190_governance_class_wire_round_trips_through_every_class() {
    for c in [
        GovernanceAuthorityClass::GenesisBound,
        GovernanceAuthorityClass::EmergencyCouncil,
        GovernanceAuthorityClass::OnChainGovernance,
    ] {
        let wire = GovernanceAuthorityClassWire::from_class(c);
        assert_eq!(wire.to_class(), c);
    }
}

// ===========================================================================
// Serde / parse compatibility
// ===========================================================================

#[test]
fn serde_old_no_custody_payload_parses_as_absent() {
    // A v2 sidecar that does NOT carry the Run 190 sibling continues
    // to parse exactly as before.
    let value = serde_json::json!({
        "schema_version": 2,
        "unrelated": 1,
        "governance_authority_proof": null,
        "onchain_governance_proof": null
    });
    let s = parse_optional_authority_custody_attestation_sibling_from_json_value(&value);
    assert!(s.is_absent());
    assert!(s.as_attestation().is_none());
}

#[test]
fn serde_custody_carrying_payload_parses_into_typed_attestation() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let value = sibling_value_for(&att);
    let s = parse_optional_authority_custody_attestation_sibling_from_json_value(&value);
    assert!(s.is_available());
    assert_eq!(s.as_attestation().unwrap(), &att);
}

#[test]
fn serde_malformed_custody_payload_fails_closed_at_payload_layer() {
    let value = serde_json::json!({
        AUTHORITY_CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: "not-an-object"
    });
    let s = parse_optional_authority_custody_attestation_sibling_from_json_value(&value);
    assert!(s.is_malformed());
    assert!(matches!(
        s.malformed_error().unwrap(),
        AuthorityCustodyAttestationPayloadParseError::Json { .. }
    ));
}

#[test]
fn serde_unsupported_future_schema_version_fails_closed() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let mut wire = wire_for(&att);
    wire.schema_version = 9_999;
    let value = serde_json::json!({
        AUTHORITY_CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(wire).unwrap()
    });
    let s = parse_optional_authority_custody_attestation_sibling_from_json_value(&value);
    assert!(s.is_malformed());
    assert!(matches!(
        s.malformed_error().unwrap(),
        AuthorityCustodyAttestationPayloadParseError::Wire(
            AuthorityCustodyAttestationWireParseError::UnknownSchemaVersion { .. }
        )
    ));
}

#[test]
fn serde_empty_required_field_fails_closed() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let mut wire = wire_for(&att);
    wire.custody_key_id = String::new();
    let value = serde_json::json!({
        AUTHORITY_CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(wire).unwrap()
    });
    let s = parse_optional_authority_custody_attestation_sibling_from_json_value(&value);
    assert!(s.is_malformed());
    assert!(matches!(
        s.malformed_error().unwrap(),
        AuthorityCustodyAttestationPayloadParseError::Wire(
            AuthorityCustodyAttestationWireParseError::EmptyRequiredField
        )
    ));
}

#[test]
fn serde_null_sibling_yields_absent() {
    let value = serde_json::json!({
        AUTHORITY_CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: null
    });
    let s = parse_optional_authority_custody_attestation_sibling_from_json_value(&value);
    assert!(s.is_absent());
}

// ===========================================================================
// A1 — no-custody payload remains compatible under default Disabled
// ===========================================================================

#[test]
fn a1_no_custody_payload_remains_compatible_under_default_disabled() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let loaded = AuthorityCustodyLoadStatus::Absent;
    let ctx = devnet_ctx(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::Disabled,
    );
    for outcome in &[
        route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded),
        route_loaded_authority_custody_attestation_to_reload_apply_callsite_decision(&ctx, &loaded),
        route_loaded_authority_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision(
            &ctx, &loaded,
        ),
        route_loaded_authority_custody_attestation_to_sighup_callsite_decision(&ctx, &loaded),
        route_loaded_authority_custody_attestation_to_local_peer_candidate_check_callsite_decision(
            &ctx, &loaded,
        ),
        route_loaded_authority_custody_attestation_to_live_inbound_0x05_callsite_decision(
            &ctx, &loaded,
        ),
        route_loaded_authority_custody_attestation_to_peer_driven_drain_callsite_decision(
            &ctx, &loaded,
        ),
    ] {
        assert_eq!(
            outcome,
            &AuthorityCustodyPayloadCarryingDecisionOutcome::NoCustodyAttestationSupplied,
            "default-Disabled+absent must bypass on every surface"
        );
        assert!(outcome.is_bypassed());
        assert!(!outcome.is_accept());
        assert!(!outcome.is_reject());
    }
}

// ===========================================================================
// A2 — DevNet fixture custody carried through reload-check accepted
// ===========================================================================

#[test]
fn a2_devnet_fixture_custody_carried_through_reload_check_accepted() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let value = sibling_value_for(&att);
    let loaded = parse_optional_authority_custody_attestation_sibling_from_json_value(&value);
    assert!(loaded.is_available());

    let ctx = devnet_ctx(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::FixtureOnly,
    );
    let outcome =
        route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_accept());
    match outcome.callsite_outcome().unwrap() {
        LifecycleGovernanceCustodyOutcome::Accepted { custody_outcome, .. } => assert!(matches!(
            custody_outcome,
            AuthorityCustodyValidationOutcome::AcceptedFixtureCustody { .. }
        )),
        other => panic!("expected Accepted fixture custody, got {:?}", other),
    }
}

// ===========================================================================
// A3 — TestNet fixture custody accepted under FixtureOnly
// ===========================================================================

#[test]
fn a3_testnet_fixture_custody_carried_through_reload_check_accepted() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Testnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Testnet);
    let domain = testnet_domain();
    let att = good_attestation(
        TrustBundleEnvironment::Testnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let ctx = devnet_ctx(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::FixtureOnly,
    );
    let outcome =
        route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_accept());
}

// ===========================================================================
// A4 — DevNet local-operator custody accepted under DevnetLocalAllowed
// ===========================================================================

#[test]
fn a4_devnet_local_operator_custody_accepted_under_devnet_local_policy() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::LocalOperatorKey,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let ctx = devnet_ctx(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
    );
    let outcome =
        route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_accept());
    match outcome.callsite_outcome().unwrap() {
        LifecycleGovernanceCustodyOutcome::Accepted { custody_outcome, .. } => assert!(matches!(
            custody_outcome,
            AuthorityCustodyValidationOutcome::AcceptedLocalOperatorCustody { .. }
        )),
        other => panic!("expected accepted local custody, got {:?}", other),
    }
}

// ===========================================================================
// A5 — TestNet local-operator custody accepted under TestnetLocalAllowed
// ===========================================================================

#[test]
fn a5_testnet_local_operator_custody_accepted_under_testnet_local_policy() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Testnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Testnet);
    let domain = testnet_domain();
    let att = good_attestation(
        TrustBundleEnvironment::Testnet,
        &candidate,
        AuthorityCustodyClass::LocalOperatorKey,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let ctx = devnet_ctx(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::TestnetLocalAllowed,
    );
    let outcome =
        route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_accept());
}

// ===========================================================================
// A6 — DevNet fixture custody carried through reload-apply preflight
// accepted (preflight only — sequence-before-marker is invariant of
// the calling surface).
// ===========================================================================

#[test]
fn a6_devnet_fixture_custody_carried_through_reload_apply_preflight_accepted() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let ctx = devnet_ctx(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::FixtureOnly,
    );
    let outcome =
        route_loaded_authority_custody_attestation_to_reload_apply_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_accept());
}

// ===========================================================================
// A7 — combined lifecycle + governance + fixture custody accepted
// for DevNet source/test production-context path.
// ===========================================================================

#[test]
fn a7_combined_lifecycle_governance_fixture_custody_accepted_devnet() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let outcome = validate_lifecycle_governance_and_custody(
        &att,
        &candidate,
        Some(&persisted),
        &domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::FixtureOnly,
        NOW,
    );
    assert!(outcome.is_accept());
}

// ===========================================================================
// A8 — combined lifecycle + governance + local custody accepted for
// TestNet where policy allows.
// ===========================================================================

#[test]
fn a8_combined_lifecycle_governance_local_custody_accepted_testnet() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Testnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Testnet);
    let domain = testnet_domain();
    let att = good_attestation(
        TrustBundleEnvironment::Testnet,
        &candidate,
        AuthorityCustodyClass::LocalOperatorKey,
    );
    let outcome = validate_lifecycle_governance_and_custody(
        &att,
        &candidate,
        Some(&persisted),
        &domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::TestnetLocalAllowed,
        NOW,
    );
    assert!(outcome.is_accept());
}

// ===========================================================================
// A9 — GenesisBound / EmergencyCouncil / OnChainGovernance proof paths
// remain compatible when custody validation is Disabled.
// ===========================================================================

#[test]
fn a9_governance_proof_paths_compatible_under_custody_disabled() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let loaded = AuthorityCustodyLoadStatus::Absent;
    for class in [
        GovernanceAuthorityClass::GenesisBound,
        GovernanceAuthorityClass::EmergencyCouncil,
        GovernanceAuthorityClass::OnChainGovernance,
    ] {
        let ctx = callsite_context_for_authority_custody(
            Some(&persisted),
            &candidate,
            &domain,
            AuthorityCustodyPolicy::Disabled,
            class,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(CUSTODY_KEY_ID),
            NOW,
        );
        let outcome =
            route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(
                &ctx, &loaded,
            );
        assert_eq!(
            outcome,
            AuthorityCustodyPayloadCarryingDecisionOutcome::NoCustodyAttestationSupplied,
            "Disabled+absent under {:?} must bypass",
            class
        );
    }
}

// ===========================================================================
// A10 — KMS/HSM/RemoteSigner placeholder metadata reaches custody
// validator and returns typed unavailable.
// ===========================================================================

#[test]
fn a10_kms_hsm_remote_signer_placeholders_reach_validator_and_return_unavailable() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    for (class, expected) in [
        (
            AuthorityCustodyClass::Kms,
            AuthorityCustodyValidationOutcome::KmsUnavailable,
        ),
        (
            AuthorityCustodyClass::Hsm,
            AuthorityCustodyValidationOutcome::HsmUnavailable,
        ),
        (
            AuthorityCustodyClass::RemoteSigner,
            AuthorityCustodyValidationOutcome::RemoteSignerUnavailable,
        ),
    ] {
        let att = good_attestation(TrustBundleEnvironment::Devnet, &candidate, class);
        let loaded = AuthorityCustodyLoadStatus::Available(att);
        // Use ProductionCustodyRequired so the validator does not
        // short-circuit at the policy gate before reaching the
        // placeholder branch.
        let ctx = devnet_ctx(
            Some(&persisted),
            &candidate,
            &domain,
            AuthorityCustodyPolicy::ProductionCustodyRequired,
        );
        let outcome =
            route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(
                &ctx, &loaded,
            );
        let custody = match outcome.callsite_outcome().unwrap() {
            LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. } => {
                custody_outcome
            }
            other => panic!("expected custody-rejected, got {:?}", other),
        };
        assert_eq!(custody, &expected, "class {:?}", class);
        assert!(custody.is_production_unavailable());
    }
}

// ===========================================================================
// R1 — custody metadata absent where custody policy requires custody:
// rejected fail-closed.
// ===========================================================================

#[test]
fn r1_absent_custody_under_required_policy_fails_closed() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let loaded = AuthorityCustodyLoadStatus::Absent;
    for policy in [
        AuthorityCustodyPolicy::FixtureOnly,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        AuthorityCustodyPolicy::TestnetLocalAllowed,
        AuthorityCustodyPolicy::ProductionCustodyRequired,
        AuthorityCustodyPolicy::MainnetProductionCustodyRequired,
    ] {
        let ctx = devnet_ctx(Some(&persisted), &candidate, &domain, policy);
        let outcome =
            route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(
                &ctx, &loaded,
            );
        assert!(
            outcome.is_required_but_absent(),
            "policy {:?} must require custody",
            policy
        );
        assert!(outcome.is_reject());
        assert!(!outcome.is_accept());
        assert!(!outcome.is_bypassed());
    }
}

// ===========================================================================
// R2 — malformed custody metadata payload rejected.
// ===========================================================================

#[test]
fn r2_malformed_custody_payload_rejected_on_every_surface() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let loaded = AuthorityCustodyLoadStatus::Malformed(
        AuthorityCustodyAttestationPayloadParseError::Json {
            error: "synthetic".to_string(),
        },
    );
    let ctx = devnet_ctx(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::FixtureOnly,
    );
    for outcome in &[
        route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded),
        route_loaded_authority_custody_attestation_to_reload_apply_callsite_decision(&ctx, &loaded),
        route_loaded_authority_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision(
            &ctx, &loaded,
        ),
        route_loaded_authority_custody_attestation_to_sighup_callsite_decision(&ctx, &loaded),
        route_loaded_authority_custody_attestation_to_local_peer_candidate_check_callsite_decision(
            &ctx, &loaded,
        ),
        route_loaded_authority_custody_attestation_to_live_inbound_0x05_callsite_decision(
            &ctx, &loaded,
        ),
        route_loaded_authority_custody_attestation_to_peer_driven_drain_callsite_decision(
            &ctx, &loaded,
        ),
    ] {
        assert!(outcome.is_malformed_payload(), "expected malformed-payload reject");
        assert!(outcome.is_reject());
        assert!(!outcome.is_accept());
    }
}

// ===========================================================================
// R3 — fixture custody rejected under production custody policy.
// ===========================================================================

#[test]
fn r3_fixture_custody_rejected_under_production_custody_required() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let ctx = devnet_ctx(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::ProductionCustodyRequired,
    );
    let outcome =
        route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(!outcome.is_accept());
    let custody = match outcome.callsite_outcome().unwrap() {
        LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. } => {
            custody_outcome
        }
        other => panic!("expected custody-rejected, got {:?}", other),
    };
    assert!(custody.is_production_unavailable());
}

// ===========================================================================
// R4 — local operator custody rejected under production custody policy.
// ===========================================================================

#[test]
fn r4_local_operator_custody_rejected_under_production_custody_required() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::LocalOperatorKey,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let ctx = devnet_ctx(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::ProductionCustodyRequired,
    );
    let outcome =
        route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    let custody = match outcome.callsite_outcome().unwrap() {
        LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. } => {
            custody_outcome
        }
        other => panic!("expected custody-rejected, got {:?}", other),
    };
    assert!(custody.is_production_unavailable());
}

// ===========================================================================
// R5 — fixture custody rejected for MainNet (validator boundary).
// ===========================================================================

#[test]
fn r5_fixture_custody_rejected_for_mainnet() {
    // Use the validator directly so we exercise the MainNet refusal
    // without short-circuiting at the peer-driven-drain surface.
    let candidate = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let domain = mainnet_domain();
    let att = good_attestation(
        TrustBundleEnvironment::Mainnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let outcome = validate_authority_custody_attestation(
        &att,
        &candidate,
        &domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::MainnetProductionCustodyRequired,
        NOW,
    );
    assert!(outcome.is_reject());
}

// ===========================================================================
// R6 — local operator custody rejected for MainNet.
// ===========================================================================

#[test]
fn r6_local_operator_custody_rejected_for_mainnet() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let domain = mainnet_domain();
    let att = good_attestation(
        TrustBundleEnvironment::Mainnet,
        &candidate,
        AuthorityCustodyClass::LocalOperatorKey,
    );
    let outcome = validate_authority_custody_attestation(
        &att,
        &candidate,
        &domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::MainnetProductionCustodyRequired,
        NOW,
    );
    assert!(outcome.is_reject());
}

// ===========================================================================
// R7-R9 — KMS / HSM / RemoteSigner placeholders rejected as unavailable.
// ===========================================================================

#[test]
fn r7_kms_placeholder_rejected_as_unavailable() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::Kms,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let ctx = devnet_ctx(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::ProductionCustodyRequired,
    );
    let outcome =
        route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    let custody = outcome
        .callsite_outcome()
        .and_then(|o| match o {
            LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. } => {
                Some(custody_outcome)
            }
            _ => None,
        })
        .expect("custody-rejected expected");
    assert_eq!(custody, &AuthorityCustodyValidationOutcome::KmsUnavailable);
}

#[test]
fn r8_hsm_placeholder_rejected_as_unavailable() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::Hsm,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let ctx = devnet_ctx(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::ProductionCustodyRequired,
    );
    let outcome =
        route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    let custody = match outcome.callsite_outcome().unwrap() {
        LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. } => {
            custody_outcome
        }
        _ => panic!("expected custody-rejected"),
    };
    assert_eq!(custody, &AuthorityCustodyValidationOutcome::HsmUnavailable);
}

#[test]
fn r9_remote_signer_placeholder_rejected_as_unavailable() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::RemoteSigner,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let ctx = devnet_ctx(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::ProductionCustodyRequired,
    );
    let outcome =
        route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    let custody = match outcome.callsite_outcome().unwrap() {
        LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. } => {
            custody_outcome
        }
        _ => panic!("expected custody-rejected"),
    };
    assert_eq!(
        custody,
        &AuthorityCustodyValidationOutcome::RemoteSignerUnavailable
    );
}

// ===========================================================================
// R10 — unknown custody class rejected.
// ===========================================================================

#[test]
fn r10_unknown_custody_class_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let mut att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::Unknown,
    );
    att.custody_class = AuthorityCustodyClass::Unknown;
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let ctx = devnet_ctx(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::FixtureOnly,
    );
    let outcome =
        route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    let custody = match outcome.callsite_outcome().unwrap() {
        LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. } => {
            custody_outcome
        }
        _ => panic!("expected custody-rejected"),
    };
    assert_eq!(
        custody,
        &AuthorityCustodyValidationOutcome::UnknownCustodyClassRejected
    );
}

// ===========================================================================
// Helper for binding-mismatch tests that build a tweaked attestation.
// ===========================================================================

fn run_validator_with_tweak(
    tweak: impl FnOnce(&mut AuthorityCustodyAttestation),
) -> AuthorityCustodyValidationOutcome {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let mut att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    tweak(&mut att);
    validate_authority_custody_attestation(
        &att,
        &candidate,
        &domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::FixtureOnly,
        NOW,
    )
}

// R11 — wrong environment.
#[test]
fn r11_wrong_environment_rejected() {
    let outcome = run_validator_with_tweak(|a| a.environment = TrustBundleEnvironment::Testnet);
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::WrongEnvironment { .. }
    ));
}

// R12 — wrong chain.
#[test]
fn r12_wrong_chain_rejected() {
    let outcome = run_validator_with_tweak(|a| a.chain_id = OTHER_CHAIN.to_string());
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::WrongChain { .. }
    ));
}

// R13 — wrong genesis.
#[test]
fn r13_wrong_genesis_rejected() {
    let outcome = run_validator_with_tweak(|a| a.genesis_hash = OTHER_GENESIS.to_string());
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::WrongGenesis { .. }
    ));
}

// R14 — wrong authority root.
#[test]
fn r14_wrong_authority_root_rejected() {
    let outcome = run_validator_with_tweak(|a| {
        a.authority_root_fingerprint = OTHER_ROOT_FP.to_string();
    });
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::WrongAuthorityRoot { .. }
    ));
}

// R15 — wrong signing-key fingerprint.
#[test]
fn r15_wrong_signing_key_fingerprint_rejected() {
    let outcome = run_validator_with_tweak(|a| {
        a.bundle_signing_key_fingerprint = KEY_A.to_string();
    });
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::WrongSigningKeyFingerprint { .. }
    ));
}

// R16 — wrong candidate digest.
#[test]
fn r16_wrong_candidate_digest_rejected() {
    let outcome = run_validator_with_tweak(|a| a.candidate_digest = DIGEST_OTHER.to_string());
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::WrongCandidateDigest { .. }
    ));
}

// R17 — wrong authority-domain sequence.
#[test]
fn r17_wrong_authority_domain_sequence_rejected() {
    let outcome = run_validator_with_tweak(|a| a.authority_domain_sequence = 9_999);
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::WrongAuthorityDomainSequence { .. }
    ));
}

// R18 — wrong lifecycle action.
#[test]
fn r18_wrong_lifecycle_action_rejected() {
    let outcome = run_validator_with_tweak(|a| a.lifecycle_action = LocalLifecycleAction::Retire);
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::WrongLifecycleAction { .. }
    ));
}

// R19 — missing custody attestation (empty digest).
#[test]
fn r19_missing_custody_attestation_rejected() {
    let outcome = run_validator_with_tweak(|a| a.custody_attestation_digest = String::new());
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::CustodyAttestationMissing
            | AuthorityCustodyValidationOutcome::CustodyAttestationMalformed { .. }
    ));
}

// R20 — malformed custody attestation (empty key id).
#[test]
fn r20_malformed_custody_attestation_rejected() {
    let outcome = run_validator_with_tweak(|a| a.custody_key_id = String::new());
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::CustodyAttestationMalformed { .. }
            | AuthorityCustodyValidationOutcome::CustodyKeyIdMismatch { .. }
    ));
}

// R21 — expired custody attestation.
#[test]
fn r21_expired_custody_attestation_rejected() {
    let outcome = run_validator_with_tweak(|a| {
        a.freshness_unix = Some(FRESH);
        a.expires_at_unix = Some(NOW - 1);
    });
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::CustodyAttestationExpired { .. }
    ));
}

// R22 — custody key id mismatch.
#[test]
fn r22_custody_key_id_mismatch_rejected() {
    let outcome = run_validator_with_tweak(|a| a.custody_key_id = OTHER_CUSTODY_KEY_ID.to_string());
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::CustodyKeyIdMismatch { .. }
    ));
}

// R23 — unsupported custody suite.
#[test]
fn r23_unsupported_custody_suite_rejected() {
    let outcome = run_validator_with_tweak(|a| a.custody_suite_id = 0xff);
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::UnsupportedCustodySuite { .. }
    ));
}

// ===========================================================================
// R24 — custody valid but governance proof invalid: rejected
// (governance proof binding is enforced via expected_governance_authority_class
// passed by the call-site context — a mismatch surfaces as
// WrongGovernanceAuthorityClass / WrongLifecycleAction-style typed reject).
// ===========================================================================

#[test]
fn r24_custody_valid_but_governance_class_mismatch_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let mut att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.governance_authority_class = GovernanceAuthorityClass::EmergencyCouncil;
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    // The call-site context expects GenesisBound; the attestation
    // declares EmergencyCouncil. Run 188 must fail closed.
    let ctx = devnet_ctx(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::FixtureOnly,
    );
    let outcome =
        route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(!outcome.is_accept());
    assert!(matches!(
        outcome.callsite_outcome().unwrap(),
        LifecycleGovernanceCustodyOutcome::CustodyRejected { .. }
    ));
}

// ===========================================================================
// R25 — governance proof valid but custody invalid: rejected.
// ===========================================================================

#[test]
fn r25_governance_valid_but_custody_invalid_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let mut att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.custody_attestation_digest = String::new();
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let ctx = devnet_ctx(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::FixtureOnly,
    );
    let outcome =
        route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(matches!(
        outcome.callsite_outcome().unwrap(),
        LifecycleGovernanceCustodyOutcome::CustodyRejected { .. }
    ));
}

// ===========================================================================
// R26 — lifecycle valid + governance valid + custody placeholder
// unavailable: rejected.
// ===========================================================================

#[test]
fn r26_lifecycle_governance_valid_but_custody_placeholder_unavailable_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::Hsm,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let ctx = devnet_ctx(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::ProductionCustodyRequired,
    );
    let outcome =
        route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    let custody = match outcome.callsite_outcome().unwrap() {
        LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. } => {
            custody_outcome
        }
        _ => panic!("expected custody-rejected"),
    };
    assert!(custody.is_production_unavailable());
}

// ===========================================================================
// R27 — local operator config alone cannot satisfy MainNet production
// custody.
// ===========================================================================

#[test]
fn r27_local_operator_config_alone_cannot_satisfy_mainnet_production_custody() {
    assert!(local_operator_config_alone_cannot_satisfy_mainnet_production_custody());
    let candidate = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let domain = mainnet_domain();
    let att = good_attestation(
        TrustBundleEnvironment::Mainnet,
        &candidate,
        AuthorityCustodyClass::LocalOperatorKey,
    );
    let outcome = validate_authority_custody_attestation(
        &att,
        &candidate,
        &domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::MainnetProductionCustodyRequired,
        NOW,
    );
    assert!(outcome.is_reject());
}

// ===========================================================================
// R28 — peer majority / gossip count cannot satisfy custody.
// ===========================================================================

#[test]
fn r28_peer_majority_cannot_satisfy_custody() {
    assert!(peer_majority_cannot_satisfy_custody());
}

// ===========================================================================
// R29 — validation-only rejection produces no marker write, no
// sequence write, no live trust swap, no session eviction, and no
// Run 070 call. Verified by structural inspection: the routing
// helpers borrow inputs and return a typed outcome; they own no I/O
// handles, no sequence/marker writers, no session manager. The only
// side effects available to a `route_loaded_*` call are CPU cycles
// and an immutable typed return value.
// ===========================================================================

#[test]
fn r29_validation_only_rejection_is_pure() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let loaded = AuthorityCustodyLoadStatus::Malformed(
        AuthorityCustodyAttestationPayloadParseError::Json {
            error: "synthetic".to_string(),
        },
    );
    let ctx = devnet_ctx(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::FixtureOnly,
    );
    let before_candidate_digest = candidate.latest_ratification_v2_digest.clone();
    let before_persisted_seq = match &persisted {
        PersistentAuthorityStateRecordVersioned::V2(v2) => v2.latest_authority_domain_sequence,
        _ => unreachable!(),
    };
    let outcome = [
        route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded),
        route_loaded_authority_custody_attestation_to_local_peer_candidate_check_callsite_decision(
            &ctx, &loaded,
        ),
        route_loaded_authority_custody_attestation_to_live_inbound_0x05_callsite_decision(
            &ctx, &loaded,
        ),
    ];
    for o in &outcome {
        assert!(o.is_malformed_payload());
    }
    // Inputs must remain bit-for-bit unchanged (the routing helpers
    // borrow immutably).
    assert_eq!(candidate.latest_ratification_v2_digest, before_candidate_digest);
    if let PersistentAuthorityStateRecordVersioned::V2(v2) = &persisted {
        assert_eq!(v2.latest_authority_domain_sequence, before_persisted_seq);
    }
}

// ===========================================================================
// R30 — mutating rejection produces no Run 070 call, no live trust
// swap, no session eviction, no sequence write, and no marker write.
// ===========================================================================

#[test]
fn r30_mutating_rejection_is_pure() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    // Rejected by validator (wrong sequence).
    let mut att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.authority_domain_sequence = 9_999;
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let ctx = devnet_ctx(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::FixtureOnly,
    );
    let outcomes = [
        route_loaded_authority_custody_attestation_to_reload_apply_callsite_decision(&ctx, &loaded),
        route_loaded_authority_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision(
            &ctx, &loaded,
        ),
        route_loaded_authority_custody_attestation_to_sighup_callsite_decision(&ctx, &loaded),
        route_loaded_authority_custody_attestation_to_peer_driven_drain_callsite_decision(
            &ctx, &loaded,
        ),
    ];
    for o in &outcomes {
        assert!(!o.is_accept(), "rejected outcome must not accept");
    }
}

// ===========================================================================
// R31 — invalid live `0x05` custody metadata candidate is not
// propagated, staged, or applied.
// ===========================================================================

#[test]
fn r31_invalid_live_0x05_custody_is_not_staged_or_applied() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let loaded_malformed = AuthorityCustodyLoadStatus::Malformed(
        AuthorityCustodyAttestationPayloadParseError::Json {
            error: "synthetic-live-0x05".to_string(),
        },
    );
    let ctx = devnet_ctx(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::FixtureOnly,
    );
    let outcome = route_loaded_authority_custody_attestation_to_live_inbound_0x05_callsite_decision(
        &ctx,
        &loaded_malformed,
    );
    assert!(outcome.is_malformed_payload());
    assert!(outcome.is_reject());

    // Also: a wrong-binding attestation reaches the validator and is
    // rejected, never staged.
    let mut bad_att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    bad_att.candidate_digest = DIGEST_OTHER.to_string();
    let loaded = AuthorityCustodyLoadStatus::Available(bad_att);
    let outcome2 = route_loaded_authority_custody_attestation_to_live_inbound_0x05_callsite_decision(
        &ctx, &loaded,
    );
    assert!(!outcome2.is_accept());
}

// ===========================================================================
// R32 — MainNet peer-driven apply remains refused even with custody
// metadata claiming KMS/HSM.
// ===========================================================================

#[test]
fn r32_mainnet_peer_driven_apply_refused_even_with_kms_hsm_custody() {
    assert!(mainnet_peer_driven_apply_remains_refused_under_custody_boundary(
        TrustBundleEnvironment::Mainnet
    ));
    assert!(mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying(
        TrustBundleEnvironment::Mainnet
    ));
    let candidate = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Mainnet);
    let domain = mainnet_domain();
    for class in [AuthorityCustodyClass::Kms, AuthorityCustodyClass::Hsm] {
        let mut att = good_attestation(TrustBundleEnvironment::Mainnet, &candidate, class);
        att.custody_class = class;
        let loaded = AuthorityCustodyLoadStatus::Available(att);
        let ctx = devnet_ctx(
            Some(&persisted),
            &candidate,
            &domain,
            AuthorityCustodyPolicy::MainnetProductionCustodyRequired,
        );
        let outcome =
            route_loaded_authority_custody_attestation_to_peer_driven_drain_callsite_decision(
                &ctx, &loaded,
            );
        assert!(
            outcome.is_mainnet_peer_driven_apply_refused(),
            "MainNet peer-driven apply must remain refused for class {:?}",
            class
        );
    }
}

// ===========================================================================
// Source-reachability invariants
// ===========================================================================

#[test]
fn source_reachability_validate_authority_custody_attestation_is_reached_outside_helper_modules() {
    // Direct call from this integration test file proves the symbol
    // is reachable outside helper / example / in-crate modules.
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let outcome = validate_authority_custody_attestation(
        &att,
        &candidate,
        &domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::FixtureOnly,
        NOW,
    );
    assert!(outcome.is_accept());
}

#[test]
fn source_reachability_validate_lifecycle_governance_and_custody_is_reached_outside_helper_modules()
{
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let outcome = validate_lifecycle_governance_and_custody(
        &att,
        &candidate,
        Some(&persisted),
        &domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::FixtureOnly,
        NOW,
    );
    assert!(outcome.is_accept());
}

#[test]
fn source_reachability_custody_metadata_reaches_production_callsite_context() {
    // Build a context, build a load status, route it, and assert the
    // outcome is the typed Run 188 combined outcome — not the
    // pre-Run-190 "validator never reached" placeholder.
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let ctx = devnet_ctx(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::FixtureOnly,
    );
    let outcome =
        route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    assert!(outcome.callsite_outcome().is_some(), "validator must be reached");
}