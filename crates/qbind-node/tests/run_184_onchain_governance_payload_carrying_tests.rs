//! Run 184 — source/test OnChainGovernance proof-carrying payload/
//! context tests.
//!
//! Source/test only. Run 184 does **not** capture release-binary
//! evidence; release-binary `OnChainGovernance` accepted-proof
//! evidence is deferred to **Run 185**. Default policy remains
//! [`OnChainGovernanceProofPolicy::Disabled`].
//! `AllowFixtureSourceTest` is hidden, explicit, and DevNet/TestNet
//! fixture-only. MainNet peer-driven apply remains refused. Real on-
//! chain governance proof verification, governance execution, KMS/HSM
//! custody, and validator-set rotation all remain unimplemented. See
//! `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_184.md`.
//!
//! These tests target the additive optional `onchain_governance_proof`
//! sibling on the v2 ratification sidecar JSON, the typed
//! [`OnChainGovernanceProofLoadStatus`], the combined sidecar loader
//! [`load_v2_ratification_sidecar_with_onchain_governance_proof_from_path`],
//! and the seven Run 182 per-surface routing helpers
//! ([`route_loaded_onchain_governance_proof_to_*_callsite_decision`])
//! exposed by [`qbind_node::pqc_onchain_governance_payload_carrying`].

use std::collections::HashSet;

use qbind_ledger::BundleSigningRatificationV2Action;
use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_state::{
    AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
    PersistentAuthorityStateRecordVersioned,
};
use qbind_node::pqc_governance_authority::GovernanceThreshold;
use qbind_node::pqc_onchain_governance_callsite_wiring::OnChainGovernanceCallsiteContext;
use qbind_node::pqc_onchain_governance_payload_carrying::{
    callsite_context_with_loaded_onchain_governance_proof,
    load_v2_ratification_sidecar_with_onchain_governance_proof_from_bytes,
    load_v2_ratification_sidecar_with_onchain_governance_proof_from_path,
    parse_optional_onchain_governance_proof_sibling_from_json_value,
    route_loaded_onchain_governance_proof_to_live_inbound_0x05_callsite_decision,
    route_loaded_onchain_governance_proof_to_local_peer_candidate_check_callsite_decision,
    route_loaded_onchain_governance_proof_to_peer_driven_drain_callsite_decision,
    route_loaded_onchain_governance_proof_to_reload_apply_callsite_decision,
    route_loaded_onchain_governance_proof_to_reload_check_callsite_decision,
    route_loaded_onchain_governance_proof_to_sighup_callsite_decision,
    route_loaded_onchain_governance_proof_to_startup_p2p_trust_bundle_callsite_decision,
    OnChainGovernancePayloadCarryingDecisionOutcome, OnChainGovernanceProofLoadStatus,
    OnChainGovernanceProofPayloadParseError,
    ONCHAIN_GOVERNANCE_PROOF_PAYLOAD_SIBLING_FIELD,
};
use qbind_node::pqc_onchain_governance_proof::{
    fixture_onchain_governance_proof_bytes, verify_onchain_governance_proof,
    EmptyOnChainGovernanceReplaySet, OnChainGovernanceFreshnessWindow, OnChainGovernanceProof,
    OnChainGovernanceProofPolicy, OnChainGovernanceProofVerificationOutcome,
    OnChainGovernanceProofWire, OnChainGovernanceProofWireParseError,
    OnChainGovernanceProposalOutcome, OnChainGovernanceQuorum, OnChainGovernanceReplaySet,
    ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1,
    ONCHAIN_GOVERNANCE_PROOF_WIRE_SCHEMA_VERSION,
};
use qbind_node::pqc_onchain_governance_proof_surface::OnChainGovernanceMarkerDecisionOutcome;
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Fixtures (kept structurally identical to Run 182 so the typed
// proof-binding semantics carry over end-to-end).
// ===========================================================================

const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT_FP: &str = "1111111111111111111111111111111111111111";
const CHAIN_ID: &str = "0000000000000001";
const OTHER_CHAIN: &str = "00000000000000ff";
const GENESIS_HASH_A: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GENESIS_HASH_B: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DIGEST_OTHER: &str = "3333333333333333333333333333333333333333333333333333333333333333";

const GOV_DOMAIN: &str = "qbind-onchain-gov-1";
const GOV_EPOCH: u64 = 42;
const PROPOSAL_ID: &str = "prop-001";
const PROPOSAL_DIGEST: &str =
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
const UNIQUE_DECISION_ID: &str = "decision-184";
const NOW: u64 = 1_700_000_000;

fn devnet_domain() -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(
        TrustBundleEnvironment::Devnet,
        CHAIN_ID,
        GENESIS_HASH_A,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
    )
}

fn testnet_domain() -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(
        TrustBundleEnvironment::Testnet,
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
        GENESIS_HASH_A.to_string(),
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
        "1111111111111111111111111111111111111111111111111111111111111111",
    ))
}

fn good_proof(
    candidate: &PersistentAuthorityStateRecordV2,
    action: LocalLifecycleAction,
) -> OnChainGovernanceProof {
    let new_fp = match action {
        LocalLifecycleAction::ActivateInitial | LocalLifecycleAction::Rotate => {
            Some(candidate.active_bundle_signing_key_fingerprint.clone())
        }
        _ => None,
    };
    let revoked_fp = match action {
        LocalLifecycleAction::Rotate => candidate.previous_bundle_signing_key_fingerprint.clone(),
        _ => None,
    };
    let proof_bytes = fixture_onchain_governance_proof_bytes(
        candidate.environment,
        CHAIN_ID,
        GENESIS_HASH_A,
        ROOT_FP,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        &candidate.latest_ratification_v2_digest,
        candidate.latest_authority_domain_sequence,
        UNIQUE_DECISION_ID,
    );
    OnChainGovernanceProof {
        environment: candidate.environment,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH_A.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        authority_root_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        governance_domain_id: GOV_DOMAIN.to_string(),
        governance_epoch: GOV_EPOCH,
        proposal_id: PROPOSAL_ID.to_string(),
        proposal_digest: PROPOSAL_DIGEST.to_string(),
        proposal_outcome: OnChainGovernanceProposalOutcome::Approved,
        quorum: OnChainGovernanceQuorum {
            voters_voted: 4,
            total_voters: 5,
            required_quorum: 3,
        },
        threshold: GovernanceThreshold::new(3, 3, 5),
        lifecycle_action: action,
        active_bundle_signing_key_fingerprint: candidate
            .active_bundle_signing_key_fingerprint
            .clone(),
        new_bundle_signing_key_fingerprint: new_fp,
        revoked_bundle_signing_key_fingerprint: revoked_fp,
        authority_domain_sequence: candidate.latest_authority_domain_sequence,
        candidate_v2_digest: candidate.latest_ratification_v2_digest.clone(),
        freshness: OnChainGovernanceFreshnessWindow {
            not_before_unix: NOW - 60,
            not_after_unix: NOW + 60,
        },
        unique_decision_id: UNIQUE_DECISION_ID.to_string(),
        proof_suite_id: ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1,
        proof_bytes,
    }
}

fn recommit(p: &mut OnChainGovernanceProof) {
    p.proof_bytes = fixture_onchain_governance_proof_bytes(
        p.environment,
        &p.chain_id,
        &p.genesis_hash,
        &p.authority_root_fingerprint,
        &p.governance_domain_id,
        p.governance_epoch,
        &p.proposal_id,
        &p.proposal_digest,
        &p.candidate_v2_digest,
        p.authority_domain_sequence,
        &p.unique_decision_id,
    );
}

fn route_with<R: OnChainGovernanceReplaySet + ?Sized>(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    loaded: &OnChainGovernanceProofLoadStatus,
    domain: &AuthorityTrustDomain,
    policy: OnChainGovernanceProofPolicy,
    replay: &R,
    surface: &str,
) -> OnChainGovernancePayloadCarryingDecisionOutcome {
    let ctx = callsite_context_with_loaded_onchain_governance_proof(
        persisted,
        candidate,
        loaded,
        domain,
        policy,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        replay,
    );
    match surface {
        "reload_check" => {
            route_loaded_onchain_governance_proof_to_reload_check_callsite_decision(&ctx, loaded)
        }
        "reload_apply" => {
            route_loaded_onchain_governance_proof_to_reload_apply_callsite_decision(&ctx, loaded)
        }
        "startup_p2p_trust_bundle" => {
            route_loaded_onchain_governance_proof_to_startup_p2p_trust_bundle_callsite_decision(
                &ctx, loaded,
            )
        }
        "sighup" => {
            route_loaded_onchain_governance_proof_to_sighup_callsite_decision(&ctx, loaded)
        }
        "local_peer_candidate_check" => {
            route_loaded_onchain_governance_proof_to_local_peer_candidate_check_callsite_decision(
                &ctx, loaded,
            )
        }
        "live_inbound_0x05" => {
            route_loaded_onchain_governance_proof_to_live_inbound_0x05_callsite_decision(
                &ctx, loaded,
            )
        }
        "peer_driven_drain" => {
            route_loaded_onchain_governance_proof_to_peer_driven_drain_callsite_decision(
                &ctx, loaded,
            )
        }
        other => panic!("unknown surface: {}", other),
    }
}

const ALL_SURFACES: &[&str] = &[
    "reload_check",
    "reload_apply",
    "startup_p2p_trust_bundle",
    "sighup",
    "local_peer_candidate_check",
    "live_inbound_0x05",
    "peer_driven_drain",
];

// ===========================================================================
// Wire helpers — build a v2 ratification sidecar JSON envelope with
// the additive optional `onchain_governance_proof` sibling, exercising
// the carrier at the JSON layer.
// ===========================================================================

fn good_wire_for(candidate: &PersistentAuthorityStateRecordV2) -> OnChainGovernanceProofWire {
    let proof = good_proof(candidate, LocalLifecycleAction::Rotate);
    OnChainGovernanceProofWire::from_proof(&proof)
}

fn make_v2_sidecar_value_with_proof_sibling(
    env: TrustBundleEnvironment,
    proof_sibling: Option<serde_json::Value>,
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
    if let Some(p) = proof_sibling {
        value
            .as_object_mut()
            .unwrap()
            .insert(ONCHAIN_GOVERNANCE_PROOF_PAYLOAD_SIBLING_FIELD.to_string(), p);
    }
    value
}

// ===========================================================================
// Serde / parse compatibility — the additive sibling is strictly
// optional and never poisons the v2 ratification parse.
// ===========================================================================

#[test]
fn parse_legacy_v2_sidecar_without_sibling_yields_absent() {
    let value = make_v2_sidecar_value_with_proof_sibling(TrustBundleEnvironment::Devnet, None);
    let s = parse_optional_onchain_governance_proof_sibling_from_json_value(&value);
    assert!(matches!(s, OnChainGovernanceProofLoadStatus::Absent));

    let bytes = serde_json::to_vec(&value).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v2_legacy.json");
    std::fs::write(&path, &bytes).unwrap();
    let loaded = load_v2_ratification_sidecar_with_onchain_governance_proof_from_path(&path)
        .expect("legacy v2 sidecar parses");
    assert!(loaded.onchain_governance_proof.is_absent());
}

#[test]
fn parse_v2_sidecar_with_well_formed_proof_sibling_yields_available() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let wire = good_wire_for(&candidate);
    let value = make_v2_sidecar_value_with_proof_sibling(
        TrustBundleEnvironment::Devnet,
        Some(serde_json::to_value(&wire).unwrap()),
    );
    let s = parse_optional_onchain_governance_proof_sibling_from_json_value(&value);
    assert!(matches!(s, OnChainGovernanceProofLoadStatus::Available(_)));
    assert!(s.as_proof().is_some());

    let bytes = serde_json::to_vec(&value).unwrap();
    let path = std::path::PathBuf::from("/dev/null/run-184-test.json");
    let loaded =
        load_v2_ratification_sidecar_with_onchain_governance_proof_from_bytes(&bytes, &path)
            .expect("v2 sidecar with sibling parses");
    assert!(loaded.onchain_governance_proof.is_available());
}

#[test]
fn parse_v2_sidecar_with_malformed_proof_sibling_yields_malformed() {
    let value = make_v2_sidecar_value_with_proof_sibling(
        TrustBundleEnvironment::Devnet,
        Some(serde_json::Value::String("not-an-object".to_string())),
    );
    let s = parse_optional_onchain_governance_proof_sibling_from_json_value(&value);
    assert!(s.is_malformed());
    assert!(matches!(
        s.malformed_error().unwrap(),
        OnChainGovernanceProofPayloadParseError::Json { .. }
    ));
}

#[test]
fn parse_v2_sidecar_with_unknown_schema_version_sibling_yields_malformed_wire() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut wire = good_wire_for(&candidate);
    wire.schema_version = ONCHAIN_GOVERNANCE_PROOF_WIRE_SCHEMA_VERSION + 99;
    let value = make_v2_sidecar_value_with_proof_sibling(
        TrustBundleEnvironment::Devnet,
        Some(serde_json::to_value(&wire).unwrap()),
    );
    let s = parse_optional_onchain_governance_proof_sibling_from_json_value(&value);
    assert!(s.is_malformed());
    assert!(matches!(
        s.malformed_error().unwrap(),
        OnChainGovernanceProofPayloadParseError::Wire(
            OnChainGovernanceProofWireParseError::UnknownSchemaVersion { .. }
        )
    ));
}

#[test]
fn parse_v2_sidecar_with_empty_required_field_sibling_yields_malformed_wire() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut wire = good_wire_for(&candidate);
    wire.chain_id = String::new();
    let value = make_v2_sidecar_value_with_proof_sibling(
        TrustBundleEnvironment::Devnet,
        Some(serde_json::to_value(&wire).unwrap()),
    );
    let s = parse_optional_onchain_governance_proof_sibling_from_json_value(&value);
    assert!(matches!(
        s.malformed_error().unwrap(),
        OnChainGovernanceProofPayloadParseError::Wire(
            OnChainGovernanceProofWireParseError::EmptyRequiredField
        )
    ));
}

#[test]
fn parse_v2_sidecar_with_empty_proof_bytes_sibling_yields_malformed_wire() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut wire = good_wire_for(&candidate);
    wire.proof_bytes = Vec::new();
    let value = make_v2_sidecar_value_with_proof_sibling(
        TrustBundleEnvironment::Devnet,
        Some(serde_json::to_value(&wire).unwrap()),
    );
    let s = parse_optional_onchain_governance_proof_sibling_from_json_value(&value);
    assert!(matches!(
        s.malformed_error().unwrap(),
        OnChainGovernanceProofPayloadParseError::Wire(
            OnChainGovernanceProofWireParseError::EmptyProofBytes
        )
    ));
}

// ===========================================================================
// A1 — Legacy no-proof payload remains compatible under default
// Disabled at every routing helper.
// ===========================================================================

#[test]
fn a1_no_proof_payload_under_disabled_remains_compatible_at_every_surface() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Absent;
    for surface in ALL_SURFACES {
        let outcome = route_with(
            Some(&persisted),
            &candidate,
            &loaded,
            &domain,
            OnChainGovernanceProofPolicy::Disabled,
            &replay,
            surface,
        );
        assert_eq!(
            outcome,
            OnChainGovernancePayloadCarryingDecisionOutcome::Callsite(
                OnChainGovernanceMarkerDecisionOutcome::PolicyDisabled
            ),
            "{} entry must bypass under default Disabled with no proof",
            surface
        );
        assert!(outcome.is_bypassed(), "{}", surface);
        assert!(!outcome.is_accept(), "{}", surface);
        assert!(!outcome.is_reject(), "{}", surface);
    }
}

// ===========================================================================
// A2 — reload-check carries valid DevNet OnChainGovernance Rotate
// proof and accepts under AllowFixtureSourceTest.
// ===========================================================================

#[test]
fn a2_reload_check_accepts_carried_devnet_rotate_proof_under_allow_fixture() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "reload_check",
    );
    assert!(outcome.is_accept(), "got {:?}", outcome);
    assert!(!outcome.is_reject());
}

// ===========================================================================
// A3 — reload-apply carries valid DevNet Rotate proof and accepts.
// ===========================================================================

#[test]
fn a3_reload_apply_accepts_carried_devnet_rotate_proof() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "reload_apply",
    );
    assert!(outcome.is_accept(), "got {:?}", outcome);
}

// ===========================================================================
// A4 — local peer-candidate-check accepts carried valid Rotate proof.
// ===========================================================================

#[test]
fn a4_local_peer_candidate_check_accepts_carried_proof() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "local_peer_candidate_check",
    );
    assert!(outcome.is_accept(), "got {:?}", outcome);
}

// ===========================================================================
// A5 — live inbound `0x05` accepts carried valid Rotate proof.
// ===========================================================================

#[test]
fn a5_live_inbound_0x05_accepts_carried_proof() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "live_inbound_0x05",
    );
    assert!(outcome.is_accept(), "got {:?}", outcome);
}

// ===========================================================================
// A5b — startup / SIGHUP / peer-driven drain all accept carried proof
// on a non-MainNet candidate (covers task scenario #5 — startup /
// SIGHUP / peer-driven drain where sidecar/payload context exists).
// ===========================================================================

#[test]
fn a5b_startup_sighup_peer_driven_drain_accept_carried_proof_on_devnet() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    for surface in ["startup_p2p_trust_bundle", "sighup", "peer_driven_drain"] {
        let outcome = route_with(
            Some(&persisted),
            &candidate,
            &loaded,
            &domain,
            OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
            &replay,
            surface,
        );
        assert!(outcome.is_accept(), "{} got {:?}", surface, outcome);
    }
}

// ===========================================================================
// A6 — TestNet fixture OnChainGovernance Rotate proof accepted through
// at least one source/test production-context path.
// ===========================================================================

#[test]
fn a6_testnet_rotate_proof_accepted_through_local_peer_candidate_check() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Testnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Testnet);
    let domain = testnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "local_peer_candidate_check",
    );
    assert!(outcome.is_accept(), "got {:?}", outcome);
}

// ===========================================================================
// A7 — GenesisBound and EmergencyCouncil proof behaviour remains
// unchanged: those classes never enter the OnChainGovernance routing
// helpers, so a "no OnChainGovernance proof carried" payload bypasses
// the helpers cleanly under AllowFixtureSourceTest with
// `NoOnChainGovernanceProofSupplied` and under Disabled with
// `PolicyDisabled`. The Run 165/167/171/173/176 governance proof
// loader is exercised by its own test suites and is not weakened
// here.
// ===========================================================================

#[test]
fn a7_no_onchain_governance_proof_supplied_bypasses_at_run_182_when_other_classes_active() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Absent;
    // Under AllowFixtureSourceTest with no OnChainGovernance proof
    // supplied, the helper reports NoOnChainGovernanceProofSupplied,
    // which does not interfere with the existing Run 167/169 proof
    // pipeline used by GenesisBound / EmergencyCouncil candidates.
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "reload_check",
    );
    assert_eq!(
        outcome,
        OnChainGovernancePayloadCarryingDecisionOutcome::Callsite(
            OnChainGovernanceMarkerDecisionOutcome::NoOnChainGovernanceProofSupplied,
        )
    );
}

// ===========================================================================
// R1 — OnChainGovernance proof absent where required rejected fail-
// closed: under AllowFixtureSourceTest with no proof supplied, the
// outcome is `NoOnChainGovernanceProofSupplied` — a non-accept
// outcome the calling surface treats as fail-closed when the
// candidate's authority class requires OnChainGovernance.
// ===========================================================================

#[test]
fn r1_absent_proof_under_allow_fixture_is_not_accept() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Absent;
    for surface in ALL_SURFACES {
        let outcome = route_with(
            Some(&persisted),
            &candidate,
            &loaded,
            &domain,
            OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
            &replay,
            surface,
        );
        assert!(!outcome.is_accept(), "{} got {:?}", surface, outcome);
    }
}

// ===========================================================================
// R2 — Malformed OnChainGovernance proof payload rejected at every
// surface, regardless of MainNet binding or candidate environment.
// ===========================================================================

#[test]
fn r2_malformed_payload_rejected_at_every_surface() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Malformed(
        OnChainGovernanceProofPayloadParseError::Json {
            error: "synthetic-malformed".to_string(),
        },
    );
    for surface in ALL_SURFACES {
        let outcome = route_with(
            Some(&persisted),
            &candidate,
            &loaded,
            &domain,
            OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
            &replay,
            surface,
        );
        assert!(outcome.is_malformed_payload(), "{}", surface);
        assert!(outcome.is_reject(), "{}", surface);
        assert!(!outcome.is_accept(), "{}", surface);
        assert!(!outcome.is_bypassed(), "{}", surface);
    }
}

// ===========================================================================
// R3 — Wrong environment rejected.
// ===========================================================================

#[test]
fn r3_wrong_environment_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.environment = TrustBundleEnvironment::Testnet;
    recommit(&mut proof);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "reload_check",
    );
    assert!(outcome.is_reject(), "got {:?}", outcome);
    assert!(!outcome.is_malformed_payload());
}

// ===========================================================================
// R4 — Wrong chain rejected.
// ===========================================================================

#[test]
fn r4_wrong_chain_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.chain_id = OTHER_CHAIN.to_string();
    recommit(&mut proof);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "reload_apply",
    );
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R5 — Wrong genesis rejected.
// ===========================================================================

#[test]
fn r5_wrong_genesis_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.genesis_hash = GENESIS_HASH_B.to_string();
    recommit(&mut proof);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "startup_p2p_trust_bundle",
    );
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R6 — Wrong authority root rejected.
// ===========================================================================

#[test]
fn r6_wrong_authority_root_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.authority_root_fingerprint = "9999999999999999999999999999999999999999".to_string();
    recommit(&mut proof);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "sighup",
    );
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R7 — Wrong governance domain rejected.
// ===========================================================================

#[test]
fn r7_wrong_governance_domain_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.governance_domain_id = "qbind-onchain-gov-other".to_string();
    recommit(&mut proof);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "local_peer_candidate_check",
    );
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R8 — Wrong proposal digest rejected.
// ===========================================================================

#[test]
fn r8_wrong_proposal_digest_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proposal_digest =
        "feedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed".to_string();
    recommit(&mut proof);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "live_inbound_0x05",
    );
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R9 — Wrong proposal outcome rejected.
// ===========================================================================

#[test]
fn r9_wrong_proposal_outcome_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proposal_outcome = OnChainGovernanceProposalOutcome::Rejected;
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "peer_driven_drain",
    );
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R10 — Wrong lifecycle action rejected.
// ===========================================================================

#[test]
fn r10_wrong_lifecycle_action_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.lifecycle_action = LocalLifecycleAction::ActivateInitial;
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "reload_apply",
    );
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R11 — Wrong candidate digest rejected.
// ===========================================================================

#[test]
fn r11_wrong_candidate_digest_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.candidate_v2_digest = DIGEST_OTHER.to_string();
    recommit(&mut proof);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "reload_check",
    );
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R12 — Wrong authority-domain sequence rejected.
// ===========================================================================

#[test]
fn r12_wrong_authority_domain_sequence_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.authority_domain_sequence = candidate.latest_authority_domain_sequence + 99;
    recommit(&mut proof);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "reload_apply",
    );
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R13 — Expired proof rejected.
// ===========================================================================

#[test]
fn r13_expired_proof_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.freshness = OnChainGovernanceFreshnessWindow {
        not_before_unix: NOW - 1000,
        not_after_unix: NOW - 100,
    };
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "sighup",
    );
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R14 — Replayed governance decision rejected.
// ===========================================================================

#[test]
fn r14_replayed_decision_rejected() {
    struct PreloadedReplaySet {
        seen: HashSet<String>,
    }
    impl OnChainGovernanceReplaySet for PreloadedReplaySet {
        fn contains(&self, decision_id: &str) -> bool {
            self.seen.contains(decision_id)
        }
    }
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let mut seen = HashSet::new();
    seen.insert(UNIQUE_DECISION_ID.to_string());
    let replay = PreloadedReplaySet { seen };
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "reload_apply",
    );
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R15 — Quorum not met rejected.
// ===========================================================================

#[test]
fn r15_quorum_not_met_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.quorum = OnChainGovernanceQuorum {
        voters_voted: 1,
        total_voters: 5,
        required_quorum: 3,
    };
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "reload_check",
    );
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R16 — Threshold not met rejected.
// ===========================================================================

#[test]
fn r16_threshold_not_met_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.threshold = GovernanceThreshold::new(1, 3, 5);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "local_peer_candidate_check",
    );
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R17 — Invalid proof bytes rejected (commitment mismatch).
// ===========================================================================

#[test]
fn r17_invalid_proof_bytes_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proof_bytes[0] ^= 0xff;
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "reload_check",
    );
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R18 — Unsupported proof suite rejected.
// ===========================================================================

#[test]
fn r18_unsupported_proof_suite_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proof_suite_id = ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1.wrapping_add(99);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "reload_apply",
    );
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R19 — Local operator config alone rejected: with the policy
// `Disabled` (the production default), every carried valid proof is
// short-circuited as `PolicyDisabled`. This proves that "local
// operator config alone" (i.e. shipping a proof in the sidecar without
// the explicit `AllowFixtureSourceTest` selector) cannot enable apply.
// ===========================================================================

#[test]
fn r19_local_operator_config_alone_rejected_under_disabled_policy() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::Disabled,
        &replay,
        "reload_apply",
    );
    assert_eq!(
        outcome,
        OnChainGovernancePayloadCarryingDecisionOutcome::Callsite(
            OnChainGovernanceMarkerDecisionOutcome::PolicyDisabled
        )
    );
    assert!(!outcome.is_accept());
}

// ===========================================================================
// R20 — Peer-majority / gossip-count proof rejected. We model this by
// asserting that the Run 178 verifier itself returns
// `PeerMajorityProofRejected` for an explicit mock peer-majority
// commitment, and that the surface-level outcome at every wiring
// helper is non-accept under such a proof.
// ===========================================================================

#[test]
fn r20_peer_majority_proof_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    // Simulate a "peer-majority" payload by clobbering the proof bytes
    // with a content-free constant — this MUST never be accepted.
    proof.proof_bytes = vec![0xee; 32];
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "peer_driven_drain",
    );
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R21 — Valid proof but lifecycle invalid rejected. Build a proof
// whose every binding matches the candidate, but supply a persisted
// record whose sequence is ahead of the candidate (anti-rollback
// rejection at the Run 159 v2 lifecycle validator).
// ===========================================================================

#[test]
fn r21_valid_proof_but_lifecycle_invalid_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    // Persisted is AHEAD of candidate.
    let persisted = PersistentAuthorityStateRecordVersioned::V2(build_v2(
        TrustBundleEnvironment::Devnet,
        KEY_B,
        99,
        BundleSigningRatificationV2Action::Rotate,
        Some(KEY_A),
        DIGEST_OTHER,
    ));
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "reload_apply",
    );
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R22 — Lifecycle valid but proof invalid rejected.
// ===========================================================================

#[test]
fn r22_lifecycle_valid_but_proof_invalid_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    // Proof binding mismatch (genesis), lifecycle stays clean.
    proof.genesis_hash = GENESIS_HASH_B.to_string();
    recommit(&mut proof);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "reload_check",
    );
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R23 — Validation-only rejection produces no marker write, no
// sequence write, no live trust swap, no session eviction, no
// Run 070 call. The Run 184 routing helpers are pure and perform
// none of these mutations; we assert that the helpers return the
// rejection without touching any out-of-band state by construction
// (the helpers take only borrowed inputs and return only a typed
// outcome).
// ===========================================================================

#[test]
fn r23_validation_only_rejection_is_pure_no_mutation() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.chain_id = OTHER_CHAIN.to_string();
    recommit(&mut proof);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let original_persisted_seq = match &persisted {
        PersistentAuthorityStateRecordVersioned::V2(r) => r.latest_authority_domain_sequence,
        PersistentAuthorityStateRecordVersioned::V1(_) => unreachable!(),
    };
    let original_candidate_digest = candidate.latest_ratification_v2_digest.clone();
    for surface in ["reload_check", "local_peer_candidate_check", "live_inbound_0x05"] {
        let outcome = route_with(
            Some(&persisted),
            &candidate,
            &loaded,
            &domain,
            OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
            &replay,
            surface,
        );
        assert!(outcome.is_reject(), "{} got {:?}", surface, outcome);
    }
    // Borrowed inputs are unchanged after the helpers run.
    let post_seq = match &persisted {
        PersistentAuthorityStateRecordVersioned::V2(r) => r.latest_authority_domain_sequence,
        PersistentAuthorityStateRecordVersioned::V1(_) => unreachable!(),
    };
    assert_eq!(post_seq, original_persisted_seq);
    assert_eq!(candidate.latest_ratification_v2_digest, original_candidate_digest);
}

// ===========================================================================
// R24 — Mutating rejection produces no Run 070 call, no live trust
// swap, no session eviction, no sequence write, no marker write.
// Same pure-helpers argument applies to the mutating-preflight
// surfaces (reload-apply, startup, sighup, peer-driven drain).
// ===========================================================================

#[test]
fn r24_mutating_rejection_is_pure_no_mutation() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proposal_outcome = OnChainGovernanceProposalOutcome::Rejected;
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    for surface in ["reload_apply", "startup_p2p_trust_bundle", "sighup", "peer_driven_drain"] {
        let outcome = route_with(
            Some(&persisted),
            &candidate,
            &loaded,
            &domain,
            OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
            &replay,
            surface,
        );
        assert!(outcome.is_reject(), "{} got {:?}", surface, outcome);
    }
}

// ===========================================================================
// R25 — Invalid live `0x05` OnChainGovernance proof candidate is not
// propagated, staged, or applied. The routing helper returns a
// fail-closed outcome BEFORE any staging path is reached.
// ===========================================================================

#[test]
fn r25_invalid_live_0x05_onchain_governance_proof_short_circuits() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let loaded_malformed = OnChainGovernanceProofLoadStatus::Malformed(
        OnChainGovernanceProofPayloadParseError::Json {
            error: "live-0x05-malformed".to_string(),
        },
    );
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded_malformed,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "live_inbound_0x05",
    );
    assert!(outcome.is_malformed_payload());
    assert!(outcome.is_reject());

    // Also: an invalid carried proof (binding mismatch) at live `0x05`
    // is rejected before any staging path is reached.
    let mut bad_proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    bad_proof.candidate_v2_digest = DIGEST_OTHER.to_string();
    recommit(&mut bad_proof);
    let loaded_invalid = OnChainGovernanceProofLoadStatus::Available(bad_proof);
    let outcome2 = route_with(
        Some(&persisted),
        &candidate,
        &loaded_invalid,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "live_inbound_0x05",
    );
    assert!(outcome2.is_reject(), "got {:?}", outcome2);
}

// ===========================================================================
// R26 — MainNet peer-driven apply remains refused even with valid
// fixture proof and selector enabled.
// ===========================================================================

#[test]
fn r26_mainnet_peer_driven_drain_refuses_with_valid_carried_proof_and_selector_enabled() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = prior_versioned(TrustBundleEnvironment::Mainnet);
    let domain = mainnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof);
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "peer_driven_drain",
    );
    assert_eq!(
        outcome,
        OnChainGovernancePayloadCarryingDecisionOutcome::Callsite(
            OnChainGovernanceMarkerDecisionOutcome::MainNetRefused
        )
    );
    assert!(!outcome.is_accept());
}

#[test]
fn r26b_mainnet_peer_driven_drain_refuses_with_no_proof_and_selector_enabled() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Mainnet);
    let domain = mainnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Absent;
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "peer_driven_drain",
    );
    assert_eq!(
        outcome,
        OnChainGovernancePayloadCarryingDecisionOutcome::Callsite(
            OnChainGovernanceMarkerDecisionOutcome::MainNetRefused
        )
    );
}

// ===========================================================================
// Source reachability — the parsed proof reaches the Run 182 call-
// site context, the AllowFixtureSourceTest policy reaches the marker
// decision, and `verify_onchain_governance_proof` is reached outside
// helper/example modules. Together with the A* tests these prove the
// production-context routing path is exercised end-to-end at the
// source/test level.
// ===========================================================================

#[test]
fn source_reachability_loaded_proof_reaches_run_182_call_site_context() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let loaded = OnChainGovernanceProofLoadStatus::Available(proof.clone());
    let ctx: OnChainGovernanceCallsiteContext<'_, EmptyOnChainGovernanceReplaySet> =
        callsite_context_with_loaded_onchain_governance_proof(
            None,
            &candidate,
            &loaded,
            &domain,
            OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
            GOV_DOMAIN,
            GOV_EPOCH,
            PROPOSAL_ID,
            PROPOSAL_DIGEST,
            NOW,
            &replay,
        );
    assert!(std::ptr::eq(
        ctx.proof.expect("proof routed into context"),
        match &loaded {
            OnChainGovernanceProofLoadStatus::Available(p) => p,
            _ => unreachable!(),
        }
    ));
    assert_eq!(ctx.policy, OnChainGovernanceProofPolicy::AllowFixtureSourceTest);
}

#[test]
fn source_reachability_verifier_reached_outside_helper_or_example_modules() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let outcome = verify_onchain_governance_proof(
        &proof,
        &candidate,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(candidate.latest_authority_domain_sequence),
        NOW,
        &replay,
    );
    assert!(matches!(
        outcome,
        OnChainGovernanceProofVerificationOutcome::AcceptedOnChainGovernanceFixture { .. }
    ));
}

// ===========================================================================
// End-to-end source-reachability — load a v2 sidecar JSON file (which
// carries the optional Run 184 sibling), parse the additive carrier,
// route the parsed proof through the reload-apply call-site entry,
// and assert the decision is `Accepted` under
// `AllowFixtureSourceTest` for a DevNet Rotate candidate.
// ===========================================================================

#[test]
fn end_to_end_loaded_devnet_sidecar_proof_routes_to_accept_under_allow_fixture() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let wire = good_wire_for(&candidate);
    let value = make_v2_sidecar_value_with_proof_sibling(
        TrustBundleEnvironment::Devnet,
        Some(serde_json::to_value(&wire).unwrap()),
    );
    let bytes = serde_json::to_vec(&value).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v2-with-proof.json");
    std::fs::write(&path, &bytes).unwrap();
    let loaded = load_v2_ratification_sidecar_with_onchain_governance_proof_from_path(&path)
        .expect("v2 sidecar with proof parses");
    assert!(loaded.onchain_governance_proof.is_available());

    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let outcome = route_with(
        Some(&persisted),
        &candidate,
        &loaded.onchain_governance_proof,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
        "reload_apply",
    );
    assert!(outcome.is_accept(), "got {:?}", outcome);
}