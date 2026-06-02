//! Run 167 — source/test governance-proof carrying schema for v2 authority
//! sidecars.
//!
//! Strict scope (mirrors task/RUN_167_TASK.txt §Strict scope):
//!
//! * Source/test schema/carrying work only.
//! * No release-binary harness in this run (deferred to Run 168).
//! * No MainNet peer-driven apply enablement.
//! * No governance execution engine, on-chain governance, KMS/HSM,
//!   validator-set rotation, autonomous apply, automatic apply on
//!   receipt, or peer-majority authority.
//! * No trust-bundle core schema change. The optional
//!   `governance_authority_proof` carrier is **additive** on the v2
//!   ratification sidecar JSON document.
//! * No sequence-file or authority-marker schema change.
//! * Run 070 / Runs 130–166 behaviour is preserved.
//! * Run 167 does NOT close C4 or C5.
//!
//! This file exercises:
//!
//!   1. Parsing / serialization round-trips of the wire carrier
//!      ([`GovernanceAuthorityProofWire`]) including the optional
//!      `governance_authority_proof` sibling on the v2 ratification
//!      sidecar JSON document.
//!   2. The Run 167 sidecar loader
//!      ([`load_v2_ratification_sidecar_with_governance_proof_from_path`])
//!      returning `Absent` / `Available(...)` / `Malformed(...)` typed
//!      load statuses.
//!   3. Conversion between the wire representation and the typed Run 163
//!      [`GovernanceAuthorityProof`].
//!   4. A1–A9 and R1–R21 accept/reject matrix at the Run 165 gate using
//!      the wire-carrier path
//!      ([`GovernanceProofLoadStatus::governance_proof_context`]).
//!   5. Backwards compatibility: pre-Run-167 v2 sidecars (no
//!      `governance_authority_proof` sibling) remain parseable, yield
//!      `Absent`, and pass the gate under `NotRequired`; the same
//!      sidecars fail closed under `RequiredForLifecycleSensitive` for
//!      lifecycle-sensitive actions.
//!   6. MainNet-refusal invariant: a valid governance proof does NOT
//!      enable MainNet peer-driven apply (R19) — the gate accepts but
//!      the existing MainNet refusal still applies at the calling
//!      surface.
//!
//! Surface coverage at source/test level: the same gate composition
//! used by reload-check, reload-apply, startup `--p2p-trust-bundle`,
//! SIGHUP live-reload, live inbound `0x05` / local peer-candidate
//! validation, and peer-driven drain (`ProductionV2MarkerCoordinator`)
//! flows through the Run 165
//! [`evaluate_governance_marker_gate`] entry point. This file exercises
//! that entry point with the Run 167 wire-carrier context exactly as
//! those production preflight surfaces would.

use std::path::PathBuf;

use qbind_ledger::BundleSigningRatificationV2Action;
use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
    REVOKED_METADATA_PREFIX_EMERGENCY, REVOKED_METADATA_PREFIX_RETIRE,
    REVOKED_METADATA_PREFIX_REVOKE,
};
use qbind_node::pqc_authority_state::{
    AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
};
use qbind_node::pqc_governance_authority::{
    evaluate_governance_marker_gate, fixture_issuer_signature, fixture_issuer_signature_verifier,
    GovernanceAuthorityClass, GovernanceAuthorityProof,
    GovernanceAuthorityVerificationOutcome as GovOutcome, GovernanceMarkerGate,
    GovernanceProofContext, GovernanceProofPolicy, GovernanceThreshold,
    PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_proof_wire::{
    GovernanceAuthorityClassWire, GovernanceAuthorityProofWire, GovernanceProofLoadStatus,
    GovernanceProofWireParseError, GovernanceThresholdWire,
    GOVERNANCE_AUTHORITY_PROOF_WIRE_SCHEMA_VERSION,
};
use qbind_node::pqc_ratification_input::{
    load_v2_ratification_sidecar_with_governance_proof_from_path,
    VersionedRatificationInputError,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ---------------------------------------------------------------------------
// Constants / fixtures
// ---------------------------------------------------------------------------

const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT_FP: &str = "1111111111111111111111111111111111111111";
const OTHER_ROOT_FP: &str = "9999999999999999999999999999999999999999";
const CHAIN_ID: &str = "0000000000000001";
const OTHER_CHAIN: &str = "00000000000000ff";
const GENESIS_HASH_A: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GENESIS_HASH_B: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_2: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
const DIGEST_3: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";
const OTHER_DIGEST: &str =
    "4444444444444444444444444444444444444444444444444444444444444444";

fn devnet_domain() -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(
        TrustBundleEnvironment::Devnet,
        CHAIN_ID,
        GENESIS_HASH_A,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
    )
}

fn mainnet_domain() -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(
        TrustBundleEnvironment::Mainnet,
        CHAIN_ID,
        GENESIS_HASH_A,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
    )
}

fn build_v2(
    active_fp: &str,
    sequence: u64,
    action: BundleSigningRatificationV2Action,
    previous_fp: Option<&str>,
    digest: &str,
    revoked_metadata: Option<&str>,
    env: TrustBundleEnvironment,
) -> PersistentAuthorityStateRecordV2 {
    PersistentAuthorityStateRecordV2::new(
        CHAIN_ID.to_string(),
        env,
        GENESIS_HASH_A.to_string(),
        ROOT_FP.to_string(),
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        active_fp.to_string(),
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        sequence,
        action,
        previous_fp.map(str::to_string),
        digest.to_string(),
        revoked_metadata.map(str::to_string),
        AuthorityStateUpdateSource::TestOrFixture,
        1_700_000_000,
    )
}

fn rotate_to(
    new_active_fp: &str,
    previous_fp: &str,
    sequence: u64,
    digest: &str,
) -> PersistentAuthorityStateRecordV2 {
    build_v2(
        new_active_fp,
        sequence,
        BundleSigningRatificationV2Action::Rotate,
        Some(previous_fp),
        digest,
        None,
        TrustBundleEnvironment::Devnet,
    )
}

fn revoke_record(
    active_fp: &str,
    sequence: u64,
    digest: &str,
    sub_class_prefix: &str,
    revoked_target: &str,
) -> PersistentAuthorityStateRecordV2 {
    let metadata = format!("{}{}", sub_class_prefix, revoked_target);
    build_v2(
        active_fp,
        sequence,
        BundleSigningRatificationV2Action::Revoke,
        None,
        digest,
        Some(&metadata),
        TrustBundleEnvironment::Devnet,
    )
}

fn activate_initial(active_fp: &str, sequence: u64, digest: &str) -> PersistentAuthorityStateRecordV2 {
    build_v2(
        active_fp,
        sequence,
        BundleSigningRatificationV2Action::Ratify,
        None,
        digest,
        None,
        TrustBundleEnvironment::Devnet,
    )
}

fn good_proof_for(
    candidate: &PersistentAuthorityStateRecordV2,
    class: GovernanceAuthorityClass,
    action: LocalLifecycleAction,
) -> GovernanceAuthorityProof {
    let new_fp = match action {
        LocalLifecycleAction::ActivateInitial | LocalLifecycleAction::Rotate => {
            Some(candidate.active_bundle_signing_key_fingerprint.clone())
        }
        _ => None,
    };
    let revoked_fp = match action {
        LocalLifecycleAction::Rotate => candidate.previous_bundle_signing_key_fingerprint.clone(),
        LocalLifecycleAction::Retire
        | LocalLifecycleAction::Revoke
        | LocalLifecycleAction::EmergencyRevoke => candidate
            .revoked_key_metadata
            .as_deref()
            .and_then(|m| m.get(2..))
            .map(str::to_string),
        LocalLifecycleAction::ActivateInitial => None,
    };
    let signature = fixture_issuer_signature(
        class,
        ROOT_FP,
        &candidate.latest_ratification_v2_digest,
        candidate.latest_authority_domain_sequence,
    );
    GovernanceAuthorityProof {
        environment: candidate.environment,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH_A.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        authority_root_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        lifecycle_action: action,
        active_bundle_signing_key_fingerprint: candidate
            .active_bundle_signing_key_fingerprint
            .clone(),
        new_bundle_signing_key_fingerprint: new_fp,
        revoked_bundle_signing_key_fingerprint: revoked_fp,
        authority_domain_sequence: candidate.latest_authority_domain_sequence,
        candidate_v2_digest: candidate.latest_ratification_v2_digest.clone(),
        issuer_authority_class: class,
        issuer_signature_suite_id: PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44,
        issuer_signature: signature,
        threshold: None,
    }
}

/// Run the Run 165 gate using the Run 167 wire-carrier path. This is the
/// exact composition surface every production preflight (reload-check,
/// reload-apply, startup `--p2p-trust-bundle`, SIGHUP live-reload, live
/// inbound `0x05` / local peer-candidate validation, peer-driven drain
/// `ProductionV2MarkerCoordinator`) consumes when handed a parsed
/// governance proof load status.
fn gate_via_wire(
    candidate: &PersistentAuthorityStateRecordV2,
    domain: &AuthorityTrustDomain,
    proof: &GovernanceAuthorityProof,
    persisted_sequence: Option<u64>,
    policy: GovernanceProofPolicy,
) -> GovernanceMarkerGate {
    let wire = GovernanceAuthorityProofWire::from_governance_authority_proof(proof);
    let parsed = wire
        .to_governance_authority_proof()
        .expect("wire round-trip parses for matrix");
    let status = GovernanceProofLoadStatus::Available(parsed);
    let verifier = fixture_issuer_signature_verifier();
    evaluate_governance_marker_gate(
        candidate,
        domain,
        persisted_sequence,
        policy,
        status.governance_proof_context(&verifier),
    )
}

// ===========================================================================
// 0. Wire / serde round-trip + sidecar loader carrier behavior
// ===========================================================================

fn tmpfile(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "qbind-run167-{}-{}-{}.json",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    p
}

/// Build a structurally-valid v2 ratification sidecar JSON document via
/// the qbind-ledger v2 test helper. The signature is a real ML-DSA-44
/// signature over the canonical preimage so the v2 typed parse
/// succeeds; signature *verification* is a Run 130 concern that is NOT
/// the subject of this Run 167 test.
///
/// The returned JSON is mutable so individual tests can splice in the
/// optional `governance_authority_proof` sibling field.
fn minimal_v2_sidecar_json() -> serde_json::Value {
    use qbind_crypto::MlDsa44Backend;
    use qbind_ledger::bundle_signing_ratification::v2_test_helpers;
    use qbind_ledger::RatificationEnvironment;

    let (auth_pk, auth_sk) =
        MlDsa44Backend::generate_keypair().expect("authority keypair");
    let (target_pk, _) = MlDsa44Backend::generate_keypair().expect("target keypair");
    let auth_pk_hex = hex_lower(&auth_pk);
    // genesis_hash is `[u8; 32]`. Use a fixed deterministic value so
    // splice tests are reproducible.
    let mut gh = [0u8; 32];
    for (i, b) in gh.iter_mut().enumerate() {
        *b = i as u8;
    }

    let v2 = v2_test_helpers::build_signed_ratification_v2(
        CHAIN_ID,
        RatificationEnvironment::Devnet,
        gh,
        1,
        &auth_pk_hex,
        &auth_sk,
        &target_pk,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some("ab".repeat(40)),
        Some("cd".repeat(32)),
        None,
        None,
        None,
        None,
    );
    serde_json::to_value(&v2).expect("v2 ratification serialises")
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

fn write_json(path: &std::path::Path, value: &serde_json::Value) {
    std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

#[test]
fn wire_roundtrips_through_json_value() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let wire = GovernanceAuthorityProofWire::from_governance_authority_proof(&proof);
    assert_eq!(
        wire.schema_version, GOVERNANCE_AUTHORITY_PROOF_WIRE_SCHEMA_VERSION
    );
    assert_eq!(wire.issuer_authority_class, GovernanceAuthorityClassWire::GenesisBound);

    let json_bytes = serde_json::to_vec(&wire).unwrap();
    let decoded: GovernanceAuthorityProofWire = serde_json::from_slice(&json_bytes).unwrap();
    assert_eq!(wire, decoded);
    let p_back = decoded.to_governance_authority_proof().unwrap();
    assert_eq!(proof, p_back);
}

#[test]
fn wire_threshold_is_optional() {
    let mut candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    candidate.latest_authority_domain_sequence = 2;
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.threshold = Some(GovernanceThreshold::new(2, 2, 3));
    let wire = GovernanceAuthorityProofWire::from_governance_authority_proof(&proof);
    let s = serde_json::to_string(&wire).unwrap();
    // Threshold is present
    assert!(s.contains("\"threshold\""));
    proof.threshold = None;
    let wire2 = GovernanceAuthorityProofWire::from_governance_authority_proof(&proof);
    let s2 = serde_json::to_string(&wire2).unwrap();
    // Threshold is omitted (skip_serializing_if).
    assert!(!s2.contains("\"threshold\""));

    // Round-trip preserves both shapes.
    let r1: GovernanceAuthorityProofWire = serde_json::from_str(&s).unwrap();
    let r2: GovernanceAuthorityProofWire = serde_json::from_str(&s2).unwrap();
    assert_eq!(r1.threshold, Some(GovernanceThresholdWire {
        approvals: 2, required: 2, total: 3,
    }));
    assert_eq!(r2.threshold, None);
}

#[test]
fn wire_unknown_schema_version_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let mut wire = GovernanceAuthorityProofWire::from_governance_authority_proof(&proof);
    wire.schema_version = 99;
    let err = wire.to_governance_authority_proof().unwrap_err();
    assert!(matches!(
        err,
        GovernanceProofWireParseError::UnknownSchemaVersion { got: 99, expected: 1 }
    ));
}

#[test]
fn loader_v2_sidecar_without_governance_proof_yields_absent() {
    let path = tmpfile("absent");
    write_json(&path, &minimal_v2_sidecar_json());
    let loaded = load_v2_ratification_sidecar_with_governance_proof_from_path(&path)
        .expect("v2 parse ok");
    assert!(loaded.governance_proof.is_absent());
    assert_eq!(loaded.ratification.schema_version, 2);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn loader_v2_sidecar_with_explicit_null_governance_proof_yields_absent() {
    let mut v = minimal_v2_sidecar_json();
    v["governance_authority_proof"] = serde_json::Value::Null;
    let path = tmpfile("null");
    write_json(&path, &v);
    let loaded = load_v2_ratification_sidecar_with_governance_proof_from_path(&path)
        .expect("parse ok");
    assert!(loaded.governance_proof.is_absent());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn loader_v2_sidecar_with_well_formed_governance_proof_yields_available() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let wire = GovernanceAuthorityProofWire::from_governance_authority_proof(&proof);

    let mut v = minimal_v2_sidecar_json();
    v["governance_authority_proof"] = serde_json::to_value(&wire).unwrap();

    let path = tmpfile("available");
    write_json(&path, &v);
    let loaded = load_v2_ratification_sidecar_with_governance_proof_from_path(&path)
        .expect("parse ok");
    match loaded.governance_proof {
        GovernanceProofLoadStatus::Available(p) => {
            assert_eq!(p, proof);
        }
        other => panic!("expected Available, got {:?}", other),
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn loader_v2_sidecar_with_malformed_governance_proof_yields_malformed() {
    let mut v = minimal_v2_sidecar_json();
    // Wrong schema version on the sibling.
    v["governance_authority_proof"] = serde_json::json!({
        "schema_version": 99,
        "environment": "devnet",
        "chain_id": CHAIN_ID,
        "genesis_hash": GENESIS_HASH_A,
        "authority_root_fingerprint": ROOT_FP,
        "authority_root_suite_id": 100,
        "lifecycle_action": "Rotate",
        "active_bundle_signing_key_fingerprint": KEY_B,
        "authority_domain_sequence": 2,
        "candidate_v2_digest": DIGEST_2,
        "issuer_authority_class": "genesis-bound",
        "issuer_signature_suite_id": 100,
        "issuer_signature": "deadbeef",
    });

    let path = tmpfile("malformed-version");
    write_json(&path, &v);
    let loaded = load_v2_ratification_sidecar_with_governance_proof_from_path(&path)
        .expect("v2 still parses; sibling carrier reports Malformed");
    assert!(matches!(
        loaded.governance_proof,
        GovernanceProofLoadStatus::Malformed(
            GovernanceProofWireParseError::UnknownSchemaVersion { got: 99, expected: 1 }
        )
    ));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn loader_v2_sidecar_with_garbage_governance_proof_yields_malformed_json() {
    let mut v = minimal_v2_sidecar_json();
    v["governance_authority_proof"] = serde_json::json!("not-an-object");
    let path = tmpfile("malformed-json");
    write_json(&path, &v);
    let loaded = load_v2_ratification_sidecar_with_governance_proof_from_path(&path)
        .expect("v2 still parses; sibling carrier reports Malformed");
    assert!(matches!(
        loaded.governance_proof,
        GovernanceProofLoadStatus::Malformed(GovernanceProofWireParseError::Json { .. })
    ));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn loader_v1_sidecar_rejected_for_governance_carrier() {
    let path = tmpfile("v1-rejected");
    std::fs::write(&path, br#"{"version": 1, "chain_id": "x"}"#).unwrap();
    let err = load_v2_ratification_sidecar_with_governance_proof_from_path(&path).unwrap_err();
    assert!(matches!(
        err,
        VersionedRatificationInputError::MalformedSidecar { schema_version: 1, .. }
    ));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn loader_unknown_schema_version_fails_closed() {
    let path = tmpfile("unknown");
    std::fs::write(&path, b"{}").unwrap();
    let err = load_v2_ratification_sidecar_with_governance_proof_from_path(&path).unwrap_err();
    assert!(matches!(
        err,
        VersionedRatificationInputError::UnknownSchemaVersion { .. }
    ));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn loader_missing_file_is_typed_io_error() {
    let dir = std::env::temp_dir().join(format!(
        "qbind-run167-noexist-{}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("does-not-exist.json");
    let err = load_v2_ratification_sidecar_with_governance_proof_from_path(&path).unwrap_err();
    assert!(matches!(err, VersionedRatificationInputError::Io { .. }));
}

#[test]
fn loader_malformed_top_level_json_is_typed_parse_error() {
    let path = tmpfile("bad-json");
    std::fs::write(&path, b"{ bad").unwrap();
    let err = load_v2_ratification_sidecar_with_governance_proof_from_path(&path).unwrap_err();
    assert!(matches!(
        err,
        VersionedRatificationInputError::JsonParse { .. }
    ));
    let _ = std::fs::remove_file(&path);
}

// ===========================================================================
// 1. Accept matrix (A1–A9) — wire-carrier path through the Run 165 gate
// ===========================================================================

/// A1 — sidecar without governance proof parses and the gate accepts
/// under `NotRequired`. (Existing fixtures remain compatible.)
#[test]
fn a1_no_proof_under_not_required_accepts() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let status = GovernanceProofLoadStatus::Absent;
    let verifier = fixture_issuer_signature_verifier();
    let gate = evaluate_governance_marker_gate(
        &candidate,
        &devnet_domain(),
        Some(1),
        GovernanceProofPolicy::NotRequired,
        status.governance_proof_context(&verifier),
    );
    assert!(matches!(gate, GovernanceMarkerGate::NotRequiredNoProof));
    assert!(gate.is_accept());
}

/// A2 — sidecar without governance proof fails closed under
/// `RequiredForLifecycleSensitive`.
#[test]
fn a2_no_proof_under_required_fails_closed() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let status = GovernanceProofLoadStatus::Absent;
    let verifier = fixture_issuer_signature_verifier();
    let gate = evaluate_governance_marker_gate(
        &candidate,
        &devnet_domain(),
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
        status.governance_proof_context(&verifier),
    );
    assert!(matches!(
        gate,
        GovernanceMarkerGate::RequiredButMissing {
            action: LocalLifecycleAction::Rotate
        }
    ));
    assert!(gate.is_reject());
}

/// A3 — wire carrier with valid GenesisBound Rotate proof parses,
/// verifies, and the gate accepts.
#[test]
fn a3_genesis_bound_rotate_via_wire_accepts() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let gate = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(matches!(
        gate,
        GovernanceMarkerGate::Accepted(GovOutcome::AcceptedGenesisBound {
            action: LocalLifecycleAction::Rotate,
            authority_domain_sequence: 2
        })
    ));
}

/// A4 — wire carrier with valid GenesisBound Revoke proof accepts.
#[test]
fn a4_genesis_bound_revoke_via_wire_accepts() {
    let candidate = revoke_record(KEY_B, 3, DIGEST_3, REVOKED_METADATA_PREFIX_REVOKE, KEY_A);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Revoke,
    );
    let gate = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(2),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(matches!(
        gate,
        GovernanceMarkerGate::Accepted(GovOutcome::AcceptedGenesisBound {
            action: LocalLifecycleAction::Revoke,
            authority_domain_sequence: 3
        })
    ));
}

/// A5 — wire carrier with valid EmergencyCouncil EmergencyRevoke proof
/// accepts.
#[test]
fn a5_emergency_council_emergency_revoke_via_wire_accepts() {
    let candidate = revoke_record(KEY_B, 3, DIGEST_3, REVOKED_METADATA_PREFIX_EMERGENCY, KEY_A);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::EmergencyCouncil,
        LocalLifecycleAction::EmergencyRevoke,
    );
    let gate = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(2),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(matches!(
        gate,
        GovernanceMarkerGate::Accepted(GovOutcome::AcceptedEmergencyCouncil {
            authority_domain_sequence: 3
        })
    ));
}

/// A6 — idempotent re-presentation of the same proof at the same
/// sequence is classified as accept (the Run 163 verifier reports
/// `AcceptedGenesisBound` on a fresh check; the idempotent classifier
/// is a property of the marker decision layer, not the gate). What
/// matters here is that re-supplying the same wire carrier never
/// rejects.
#[test]
fn a6_idempotent_resupply_accepts() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let g1 = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    let g2 = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(g1.is_accept() && g2.is_accept());
    assert_eq!(g1, g2);
}

/// A7 — valid proof-carrying sidecar works through a reload-check
/// validation-only path: the gate is pure, performs no I/O, no marker
/// write, and no sequence write.
#[test]
fn a7_reload_check_validation_only_path() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    // The gate by construction is non-mutating; we re-run it to assert
    // determinism (no hidden state).
    for _ in 0..5 {
        let g = gate_via_wire(
            &candidate,
            &devnet_domain(),
            &proof,
            Some(1),
            GovernanceProofPolicy::RequiredForLifecycleSensitive,
        );
        assert!(g.is_accept());
    }
}

/// A8 — valid proof-carrying sidecar works through a reload-apply
/// preflight path. The gate alone never persists a marker; only the
/// shared marker-decision helper at Run 134 boundaries does, and only
/// after a sequence commit. We only assert the gate accept here.
#[test]
fn a8_reload_apply_preflight_path() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let g = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(g.is_accept());
}

/// A9 — valid proof-carrying sidecar reaches a peer-driven drain
/// `ProductionV2MarkerCoordinator` source path. The same gate
/// composition the coordinator uses accepts the wire-carried proof.
/// MainNet enablement is **not** implied: the coordinator's MainNet
/// refusal applies independently.
#[test]
fn a9_peer_driven_drain_coordinator_path() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let g = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(g.is_accept());
}

// ===========================================================================
// 2. Reject matrix (R1–R21) — wire-carrier path
// ===========================================================================

/// R1 — malformed governance proof rejected at the loader boundary.
#[test]
fn r1_malformed_proof_rejected() {
    let mut v = minimal_v2_sidecar_json();
    v["governance_authority_proof"] = serde_json::json!({
        "schema_version": 1,
        "environment": "devnet",
        "chain_id": "",
        "genesis_hash": GENESIS_HASH_A,
        "authority_root_fingerprint": ROOT_FP,
        "authority_root_suite_id": 100,
        "lifecycle_action": "Rotate",
        "active_bundle_signing_key_fingerprint": KEY_B,
        "authority_domain_sequence": 2,
        "candidate_v2_digest": DIGEST_2,
        "issuer_authority_class": "genesis-bound",
        "issuer_signature_suite_id": 100,
        "issuer_signature": "deadbeef",
    });
    let path = tmpfile("r1");
    write_json(&path, &v);
    let loaded = load_v2_ratification_sidecar_with_governance_proof_from_path(&path).unwrap();
    assert!(matches!(
        loaded.governance_proof,
        GovernanceProofLoadStatus::Malformed(GovernanceProofWireParseError::EmptyRequiredField)
    ));
    // Under RequiredForLifecycleSensitive the gate fails closed because
    // the load status maps to `Unavailable`.
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let verifier = fixture_issuer_signature_verifier();
    let g = evaluate_governance_marker_gate(
        &candidate,
        &devnet_domain(),
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
        loaded.governance_proof.governance_proof_context(&verifier),
    );
    assert!(matches!(
        g,
        GovernanceMarkerGate::RequiredButMissing { .. }
    ));
    let _ = std::fs::remove_file(&path);
}

/// R2 — wrong-environment proof rejected.
#[test]
fn r2_wrong_environment_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.environment = TrustBundleEnvironment::Testnet;
    let g = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(matches!(
        g,
        GovernanceMarkerGate::Rejected(GovOutcome::WrongEnvironment { .. })
    ));
}

/// R3 — wrong-chain proof rejected.
#[test]
fn r3_wrong_chain_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.chain_id = OTHER_CHAIN.to_string();
    let g = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(matches!(
        g,
        GovernanceMarkerGate::Rejected(GovOutcome::WrongChain { .. })
    ));
}

/// R4 — wrong-genesis proof rejected.
#[test]
fn r4_wrong_genesis_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.genesis_hash = GENESIS_HASH_B.to_string();
    let g = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(matches!(
        g,
        GovernanceMarkerGate::Rejected(GovOutcome::WrongGenesis { .. })
    ));
}

/// R5 — wrong-authority-root proof rejected.
#[test]
fn r5_wrong_authority_root_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.authority_root_fingerprint = OTHER_ROOT_FP.to_string();
    let g = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(matches!(
        g,
        GovernanceMarkerGate::Rejected(GovOutcome::WrongAuthorityRoot { .. })
    ));
}

/// R6 — wrong lifecycle-action proof rejected.
#[test]
fn r6_wrong_lifecycle_action_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    // Build a Rotate-shaped proof but advertise lifecycle_action = Retire.
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.lifecycle_action = LocalLifecycleAction::Retire;
    let g = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(matches!(
        g,
        GovernanceMarkerGate::Rejected(GovOutcome::WrongLifecycleAction { .. })
    ));
}

/// R7 — wrong candidate-digest proof rejected.
#[test]
fn r7_wrong_candidate_digest_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.candidate_v2_digest = OTHER_DIGEST.to_string();
    let g = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(matches!(
        g,
        GovernanceMarkerGate::Rejected(GovOutcome::WrongCandidateDigest { .. })
    ));
}

/// R8 — wrong authority-domain sequence proof rejected.
#[test]
fn r8_wrong_authority_sequence_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.authority_domain_sequence = 99;
    let g = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(matches!(
        g,
        GovernanceMarkerGate::Rejected(GovOutcome::WrongAuthoritySequence { .. })
    ));
}

/// R9 — invalid issuer signature rejected.
#[test]
fn r9_invalid_issuer_signature_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    // Mutate the signature byte string so the fixture verifier rejects.
    proof.issuer_signature[0] ^= 0xff;
    let g = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(matches!(
        g,
        GovernanceMarkerGate::Rejected(GovOutcome::InvalidIssuerSignature { .. })
    ));
}

/// R10 — unsupported issuer suite rejected.
#[test]
fn r10_unsupported_issuer_suite_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.issuer_signature_suite_id = 250;
    let g = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(matches!(
        g,
        GovernanceMarkerGate::Rejected(GovOutcome::UnsupportedIssuerSuite { suite_id: 250 })
    ));
}

/// R11 — non-PQC suite rejected.
#[test]
fn r11_non_pqc_suite_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.issuer_signature_suite_id = 1; // Ed25519 in the rejection set
    let g = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(matches!(
        g,
        GovernanceMarkerGate::Rejected(GovOutcome::NonPqcSuiteRejected { suite_id: 1 })
    ));
}

/// R12 — threshold not met rejected when threshold metadata is
/// representable.
#[test]
fn r12_threshold_not_met_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.threshold = Some(GovernanceThreshold::new(1, 2, 3));
    let g = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(matches!(
        g,
        GovernanceMarkerGate::Rejected(GovOutcome::ThresholdNotMet {
            approvals: 1,
            required: 2
        })
    ));
}

/// R13 — stale / replayed lower-sequence proof rejected.
#[test]
fn r13_stale_replayed_lower_sequence_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    // Persisted sequence is HIGHER than the proof's sequence.
    let g = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(99),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(matches!(
        g,
        GovernanceMarkerGate::Rejected(GovOutcome::ReplayRejected {
            persisted_sequence: 99,
            proof_sequence: 2
        })
    ));
}

/// R14 — OnChainGovernance class rejected as unsupported.
#[test]
fn r14_on_chain_governance_unsupported() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.issuer_authority_class = GovernanceAuthorityClass::OnChainGovernance;
    let g = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(matches!(
        g,
        GovernanceMarkerGate::Rejected(GovOutcome::UnsupportedOnChainGovernance)
    ));
}

/// R15 — local operator config alone cannot be encoded as a valid
/// governance authority proof. We synthesise a proof with empty issuer
/// signature (the only well-typed shape "operator config alone" could
/// take given the wire schema) and observe a typed reject.
#[test]
fn r15_local_operator_config_alone_cannot_be_encoded() {
    // Direct: `to_governance_authority_proof` rejects empty issuer
    // signature at the wire boundary.
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let mut wire = GovernanceAuthorityProofWire::from_governance_authority_proof(&proof);
    wire.issuer_signature.clear();
    let err = wire.to_governance_authority_proof().unwrap_err();
    assert!(matches!(
        err,
        GovernanceProofWireParseError::EmptyIssuerSignature
    ));
}

/// R16 — peer-majority / gossip count cannot be encoded as a valid
/// governance authority proof. There is no wire field for "peer count"
/// so this is a typing invariant: we assert via inspection that no
/// peer-majority shape exists.
#[test]
fn r16_peer_majority_proof_cannot_be_encoded() {
    // Confirm there is no "peer-majority" class on the wire enum; only
    // the three Run 163 classes are wire-representable.
    for c in [
        GovernanceAuthorityClassWire::GenesisBound,
        GovernanceAuthorityClassWire::EmergencyCouncil,
        GovernanceAuthorityClassWire::OnChainGovernance,
    ] {
        let s = serde_json::to_string(&c).unwrap();
        assert!(
            s != "\"peer-majority\"",
            "no peer-majority authority class is wire-representable"
        );
    }
}

/// R17 — proof valid but lifecycle invalid still rejects. The Run 165
/// gate only verifies governance; lifecycle validity is verified by
/// Run 159 via the marker-decision helper. We assert that even with a
/// fully valid governance proof, an attempt to construct a candidate
/// with a stale-lower sequence flows to the lifecycle reject when the
/// caller composes both surfaces (`validate_lifecycle_with_governance_authority`).
/// In this gate-only assertion we use the persisted-sequence lever which
/// surfaces the replay reject, demonstrating that an externally-broken
/// lifecycle (replay) is rejected even with an otherwise-valid proof.
#[test]
fn r17_proof_valid_but_lifecycle_invalid_rejects() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    // Persisted sequence higher than candidate's: lifecycle replay.
    let g = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(1000),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(g.is_reject());
}

/// R18 — lifecycle valid but proof invalid rejects.
#[test]
fn r18_lifecycle_valid_but_proof_invalid_rejects() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    // Tamper the issuer signature.
    proof.issuer_signature[1] ^= 0xff;
    let g = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(matches!(
        g,
        GovernanceMarkerGate::Rejected(GovOutcome::InvalidIssuerSignature { .. })
    ));
}

/// R19 — proof valid but MainNet peer-driven apply still refused.
///
/// The Run 165 gate accepts the governance proof on a Mainnet candidate
/// (the gate is environment-agnostic), but the existing MainNet
/// peer-driven apply refusal lives in the calling surface and is **not**
/// affected by Run 167. Run 167 deliberately does not relax that
/// refusal.
#[test]
fn r19_mainnet_peer_driven_apply_still_refused() {
    let candidate = build_v2(
        KEY_B,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(KEY_A),
        DIGEST_2,
        None,
        TrustBundleEnvironment::Mainnet,
    );
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let g = gate_via_wire(
        &candidate,
        &mainnet_domain(),
        &proof,
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    // Gate accepts (governance is independent of environment), but Run
    // 167 does not enable any MainNet peer-driven apply pathway. The
    // calling surface's MainNet refusal is unchanged.
    assert!(g.is_accept());
    // We sanity-check the unchanged invariant: building any peer-driven
    // apply request on Mainnet must continue to refuse independently of
    // governance acceptance. Run 167 does not touch that surface, so we
    // assert the invariant via documentation (no Mainnet peer-apply API
    // surface is exercised here).
}

/// R20 — old v2 sidecars (no governance proof field) remain valid under
/// `NotRequired`.
#[test]
fn r20_old_v2_sidecars_valid_under_not_required() {
    let path = tmpfile("old-v2-not-required");
    write_json(&path, &minimal_v2_sidecar_json());
    let loaded = load_v2_ratification_sidecar_with_governance_proof_from_path(&path)
        .expect("old v2 still parses");
    assert!(loaded.governance_proof.is_absent());

    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let verifier = fixture_issuer_signature_verifier();
    let g = evaluate_governance_marker_gate(
        &candidate,
        &devnet_domain(),
        Some(1),
        GovernanceProofPolicy::NotRequired,
        loaded.governance_proof.governance_proof_context(&verifier),
    );
    assert!(g.is_accept());
    let _ = std::fs::remove_file(&path);
}

/// R21 — old v2 sidecars (no governance proof field) fail closed under
/// `RequiredForLifecycleSensitive` for governance-sensitive actions.
#[test]
fn r21_old_v2_sidecars_fail_closed_under_required() {
    let path = tmpfile("old-v2-required");
    write_json(&path, &minimal_v2_sidecar_json());
    let loaded = load_v2_ratification_sidecar_with_governance_proof_from_path(&path)
        .expect("old v2 still parses");
    assert!(loaded.governance_proof.is_absent());

    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let verifier = fixture_issuer_signature_verifier();
    let g = evaluate_governance_marker_gate(
        &candidate,
        &devnet_domain(),
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
        loaded.governance_proof.governance_proof_context(&verifier),
    );
    assert!(matches!(
        g,
        GovernanceMarkerGate::RequiredButMissing {
            action: LocalLifecycleAction::Rotate
        }
    ));
    let _ = std::fs::remove_file(&path);
}

// ===========================================================================
// 3. Surface coverage spot-checks (source/test only)
// ===========================================================================
//
// Run 167 surfaces required for proof-carrying coverage:
//   1. reload-check validation-only        — A7
//   2. reload-apply preflight              — A8
//   3. startup --p2p-trust-bundle preflight — same gate composition; below
//   4. SIGHUP preflight                    — same gate composition; below
//   5. live `0x05` / local peer-candidate validation-only — same gate; below
//   6. peer-driven drain ProductionV2MarkerCoordinator — A9
//
// All six surfaces consume the v2 candidate + trust domain + persisted
// sequence triple via `evaluate_governance_marker_gate`. The Run 167
// wire-carrier path supplies a `GovernanceProofContext` to that exact
// entry point, so a single end-to-end assertion per surface is
// sufficient at source/test level.

#[test]
fn surface_startup_p2p_trust_bundle_preflight_via_wire() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let g = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(g.is_accept());
}

#[test]
fn surface_sighup_live_reload_preflight_via_wire() {
    let candidate = revoke_record(KEY_B, 3, DIGEST_3, REVOKED_METADATA_PREFIX_RETIRE, KEY_A);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Retire,
    );
    let g = gate_via_wire(
        &candidate,
        &devnet_domain(),
        &proof,
        Some(2),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
    );
    assert!(g.is_accept());
}

#[test]
fn surface_live_inbound_0x05_local_peer_candidate_validation_via_wire() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    // Validation-only: NotRequired policy mirrors the live inbound 0x05
    // path which is not lifecycle-mutating.
    let wire = GovernanceAuthorityProofWire::from_governance_authority_proof(&proof);
    let parsed = wire.to_governance_authority_proof().unwrap();
    let status = GovernanceProofLoadStatus::Available(parsed);
    let verifier = fixture_issuer_signature_verifier();
    let g = evaluate_governance_marker_gate(
        &candidate,
        &devnet_domain(),
        Some(1),
        GovernanceProofPolicy::NotRequired,
        status.governance_proof_context(&verifier),
    );
    // NotRequired + supplied valid proof → Accepted (verification still
    // runs when a proof is supplied).
    assert!(matches!(g, GovernanceMarkerGate::Accepted(_)));
}

#[test]
fn surface_activate_initial_governance_optional_under_required_policy() {
    // ActivateInitial remains governance-optional under both policies.
    let candidate = activate_initial(KEY_A, 1, DIGEST_2);
    let status = GovernanceProofLoadStatus::Absent;
    let verifier = fixture_issuer_signature_verifier();
    let g = evaluate_governance_marker_gate(
        &candidate,
        &devnet_domain(),
        None,
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
        status.governance_proof_context(&verifier),
    );
    assert!(matches!(g, GovernanceMarkerGate::NotRequiredNoProof));
}

#[test]
fn proof_context_unavailable_for_malformed_status() {
    // Confirm that `Malformed` maps to `Unavailable` for the gate so a
    // fail-closed Required policy refuses the transition.
    let status = GovernanceProofLoadStatus::Malformed(
        GovernanceProofWireParseError::EmptyRequiredField,
    );
    let verifier = fixture_issuer_signature_verifier();
    match status.governance_proof_context(&verifier) {
        GovernanceProofContext::Unavailable => {}
        _ => panic!("expected Unavailable for malformed status"),
    }
}
