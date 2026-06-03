//! Run 185 — release-built helper that exercises the Run 184
//! OnChainGovernance proof-carrying production v2 ratification
//! sidecar payload layer end-to-end **in release mode** through the
//! production library symbols
//! [`qbind_node::pqc_onchain_governance_payload_carrying`] and the
//! seven Run 182 named call-site entries
//! [`qbind_node::pqc_onchain_governance_callsite_wiring`], with the
//! Run 180 per-surface composed wrappers
//! [`qbind_node::pqc_onchain_governance_proof_surface`] underneath
//! and the Run 178 typed verifier
//! [`qbind_node::pqc_onchain_governance_proof::verify_onchain_governance_proof`]
//! as the ultimate accept boundary.
//!
//! Per `task/RUN_185_TASK.txt`, Run 185 is a **release-binary
//! evidence / boundary** run. This helper is fixture-tooling and:
//!
//! * does NOT modify any production runtime code, CLI flag, env var,
//!   wire / marker / sequence / trust-bundle / peer-candidate-envelope
//!   schema, or any reachable production caller of
//!   `verify_onchain_governance_proof` beyond what Run 178 / 180 /
//!   182 / 184 already established;
//! * does NOT enable MainNet peer-driven apply on any surface;
//! * does NOT mutate any live trust state;
//! * does NOT open a P2P socket;
//! * never elevates a fixture acceptance into a MainNet apply
//!   (MainNet always returns `MainNetRefused` from the Run 180
//!   per-surface wrapper);
//! * exists alongside (and does NOT replace) the Run 184
//!   source/test target
//!   `crates/qbind-node/tests/run_184_onchain_governance_payload_carrying_tests.rs`.
//!
//! The helper writes the following files under `<OUT_DIR>/`:
//!
//! ```text
//! <OUT_DIR>/manifest.txt              # one line per scenario: <id>\t<expected_label>
//! <OUT_DIR>/expected_outcomes.txt     # human-readable map
//! <OUT_DIR>/actual_outcomes.txt       # actual typed-outcome Debug dumps
//! <OUT_DIR>/scenarios/<id>/policy.txt
//! <OUT_DIR>/scenarios/<id>/expected.txt
//! <OUT_DIR>/scenarios/<id>/actual.txt
//! <OUT_DIR>/scenarios/<id>/sidecar.json   # v2 ratification sidecar +/- proof sibling
//! <OUT_DIR>/scenarios/<id>/sidecar.sha256
//! <OUT_DIR>/scenarios/<id>/note.txt        # short human-readable description
//! <OUT_DIR>/sidecars/legacy_no_proof.json   # canonical legacy sidecar without sibling
//! <OUT_DIR>/sidecars/devnet_rotate_valid.json # canonical DevNet Rotate sidecar with valid sibling
//! <OUT_DIR>/sidecars/testnet_rotate_valid.json # canonical TestNet Rotate sidecar with valid sibling
//! <OUT_DIR>/sidecars/mainnet_rotate_valid.json # canonical MainNet Rotate sidecar (R26 carrier)
//! <OUT_DIR>/sidecars/malformed_non_object.json # malformed sibling (non-object)
//! <OUT_DIR>/sidecars/malformed_unknown_schema.json # malformed sibling (unknown schema_version)
//! <OUT_DIR>/sidecars/malformed_empty_field.json # malformed sibling (empty required field)
//! <OUT_DIR>/sidecars/malformed_empty_proof_bytes.json # malformed sibling (empty proof_bytes)
//! <OUT_DIR>/helper_summary.txt             # release-built helper verdict
//! ```
//!
//! The helper exits with a non-zero status if any scenario does not
//! match its expected typed outcome, mirroring the Run 168 / Run 178
//! / Run 179 release-built-helper pattern.
//!
//! Usage:
//! ```text
//! run_185_onchain_governance_payload_release_binary_helper <OUT_DIR>
//! ```

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use qbind_crypto::MlDsa44Backend;
use qbind_ledger::bundle_signing_ratification::v2_test_helpers::build_signed_ratification_v2;
use qbind_ledger::genesis::GENESIS_AUTHORITY_SUITE_ML_DSA_44;
use qbind_ledger::{BundleSigningRatificationV2Action, RatificationEnvironment};

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
    parse_optional_onchain_governance_proof_sibling_from_json_value,
    route_loaded_onchain_governance_proof_to_live_inbound_0x05_callsite_decision,
    route_loaded_onchain_governance_proof_to_local_peer_candidate_check_callsite_decision,
    route_loaded_onchain_governance_proof_to_peer_driven_drain_callsite_decision,
    route_loaded_onchain_governance_proof_to_reload_apply_callsite_decision,
    route_loaded_onchain_governance_proof_to_reload_check_callsite_decision,
    route_loaded_onchain_governance_proof_to_sighup_callsite_decision,
    route_loaded_onchain_governance_proof_to_startup_p2p_trust_bundle_callsite_decision,
    OnChainGovernancePayloadCarryingDecisionOutcome, OnChainGovernanceProofLoadStatus,
    ONCHAIN_GOVERNANCE_PROOF_PAYLOAD_SIBLING_FIELD,
};
use qbind_node::pqc_onchain_governance_proof::{
    fixture_onchain_governance_proof_bytes, EmptyOnChainGovernanceReplaySet,
    OnChainGovernanceFreshnessWindow, OnChainGovernanceProof, OnChainGovernanceProofPolicy,
    OnChainGovernanceProofWire, OnChainGovernanceProposalOutcome, OnChainGovernanceQuorum,
    OnChainGovernanceReplaySet, ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1,
    ONCHAIN_GOVERNANCE_PROOF_WIRE_SCHEMA_VERSION,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ---------------------------------------------------------------------------
// Constants — kept structurally identical to the Run 184 test target so the
// typed proof-binding semantics carry over end-to-end in release mode.
// ---------------------------------------------------------------------------

const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT_FP: &str = "1111111111111111111111111111111111111111";
const CHAIN_ID: &str = "0000000000000001";
const GENESIS_HASH_HEX: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const GOV_DOMAIN: &str = "qbind-onchain-gov-1";
const GOV_EPOCH: u64 = 42;
const PROPOSAL_ID: &str = "prop-001";
const PROPOSAL_DIGEST: &str =
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
const UNIQUE_DECISION_ID: &str = "decision-185";
const NOW: u64 = 1_700_000_000;

// ---------------------------------------------------------------------------
// Scenario routing surfaces — every Run 182 named call-site entry.
// ---------------------------------------------------------------------------

const ALL_SURFACES: &[&str] = &[
    "reload_check",
    "reload_apply",
    "startup_p2p_trust_bundle",
    "sighup",
    "local_peer_candidate_check",
    "live_inbound_0x05",
    "peer_driven_drain",
];

// ---------------------------------------------------------------------------
// Fixture helpers — directly mirror the Run 184 test target's helpers so
// the fixture surface this helper exercises is bit-identical to the
// source/test corpus.
// ---------------------------------------------------------------------------

fn domain(env: TrustBundleEnvironment) -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(
        env,
        CHAIN_ID,
        GENESIS_HASH_HEX,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
    )
}

fn build_v2_record(
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
        GENESIS_HASH_HEX.to_string(),
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
    build_v2_record(
        env,
        KEY_B,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(KEY_A),
        DIGEST_2,
    )
}

fn prior_versioned(env: TrustBundleEnvironment) -> PersistentAuthorityStateRecordVersioned {
    PersistentAuthorityStateRecordVersioned::V2(build_v2_record(
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
        GENESIS_HASH_HEX,
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
        genesis_hash: GENESIS_HASH_HEX.to_string(),
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

fn good_wire_for(candidate: &PersistentAuthorityStateRecordV2) -> OnChainGovernanceProofWire {
    let proof = good_proof(candidate, LocalLifecycleAction::Rotate);
    OnChainGovernanceProofWire::from_proof(&proof)
}

fn rat_env(env: TrustBundleEnvironment) -> RatificationEnvironment {
    match env {
        TrustBundleEnvironment::Mainnet => RatificationEnvironment::Mainnet,
        TrustBundleEnvironment::Testnet => RatificationEnvironment::Testnet,
        TrustBundleEnvironment::Devnet => RatificationEnvironment::Devnet,
    }
}

/// Build a v2 ratification sidecar JSON envelope optionally carrying
/// the Run 184 additive `onchain_governance_proof` sibling.
fn make_v2_sidecar_value_with_proof_sibling(
    env: TrustBundleEnvironment,
    proof_sibling: Option<serde_json::Value>,
) -> serde_json::Value {
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
        rat_env(env),
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
        value.as_object_mut().unwrap().insert(
            ONCHAIN_GOVERNANCE_PROOF_PAYLOAD_SIBLING_FIELD.to_string(),
            p,
        );
    }
    value
}

// ---------------------------------------------------------------------------
// Routing harness — dispatch a parsed load status through any of the
// seven Run 182 named call-site entries.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn route_with<R: OnChainGovernanceReplaySet + ?Sized>(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    loaded: &OnChainGovernanceProofLoadStatus,
    trust_domain: &AuthorityTrustDomain,
    policy: OnChainGovernanceProofPolicy,
    replay: &R,
    surface: &str,
) -> OnChainGovernancePayloadCarryingDecisionOutcome {
    let ctx: OnChainGovernanceCallsiteContext<'_, R> =
        callsite_context_with_loaded_onchain_governance_proof(
            persisted,
            candidate,
            loaded,
            trust_domain,
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

// ---------------------------------------------------------------------------
// Scenario records.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Accept,
    Reject,
    Bypassed,
    Malformed,
}

impl Expect {
    fn label(self) -> &'static str {
        match self {
            Expect::Accept => "accept",
            Expect::Reject => "reject",
            Expect::Bypassed => "bypassed",
            Expect::Malformed => "malformed_payload",
        }
    }

    fn matches(self, outcome: &OnChainGovernancePayloadCarryingDecisionOutcome) -> bool {
        match self {
            Expect::Accept => outcome.is_accept(),
            Expect::Reject => outcome.is_reject() && !outcome.is_malformed_payload(),
            Expect::Bypassed => outcome.is_bypassed(),
            Expect::Malformed => outcome.is_malformed_payload(),
        }
    }
}

struct Scenario {
    id: String,
    note: String,
    surface: &'static str,
    policy: OnChainGovernanceProofPolicy,
    env: TrustBundleEnvironment,
    /// Pre-built sidecar JSON value (with or without the Run 184 sibling).
    sidecar: serde_json::Value,
    expect: Expect,
}

fn run_scenarios(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let scenarios_dir = out_dir.join("scenarios");
    fs::create_dir_all(&scenarios_dir)?;
    let sidecars_dir = out_dir.join("sidecars");
    fs::create_dir_all(&sidecars_dir)?;

    let mut manifest = String::new();
    let mut expected = String::new();
    let mut actual = String::new();

    let mut scenarios: Vec<Scenario> = Vec::new();

    // Canonical sidecars (written once at the top level for the harness
    // to pass into real `target/release/qbind-node` via
    // `--p2p-trust-bundle-reload-check <path>` /
    // `--p2p-trust-bundle-reload-apply-path <path>`).
    let legacy =
        make_v2_sidecar_value_with_proof_sibling(TrustBundleEnvironment::Devnet, None);
    let devnet_candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let devnet_wire = good_wire_for(&devnet_candidate);
    let devnet_valid = make_v2_sidecar_value_with_proof_sibling(
        TrustBundleEnvironment::Devnet,
        Some(serde_json::to_value(&devnet_wire).unwrap()),
    );
    let testnet_candidate = rotate_candidate(TrustBundleEnvironment::Testnet);
    let testnet_wire = good_wire_for(&testnet_candidate);
    let testnet_valid = make_v2_sidecar_value_with_proof_sibling(
        TrustBundleEnvironment::Testnet,
        Some(serde_json::to_value(&testnet_wire).unwrap()),
    );
    let mainnet_candidate = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let mainnet_wire = good_wire_for(&mainnet_candidate);
    let mainnet_valid = make_v2_sidecar_value_with_proof_sibling(
        TrustBundleEnvironment::Mainnet,
        Some(serde_json::to_value(&mainnet_wire).unwrap()),
    );

    let malformed_non_object = make_v2_sidecar_value_with_proof_sibling(
        TrustBundleEnvironment::Devnet,
        Some(serde_json::Value::String("not-an-object".to_string())),
    );
    let mut wire_unknown = devnet_wire.clone();
    wire_unknown.schema_version = ONCHAIN_GOVERNANCE_PROOF_WIRE_SCHEMA_VERSION + 99;
    let malformed_unknown_schema = make_v2_sidecar_value_with_proof_sibling(
        TrustBundleEnvironment::Devnet,
        Some(serde_json::to_value(&wire_unknown).unwrap()),
    );
    let mut wire_empty_field = devnet_wire.clone();
    wire_empty_field.chain_id = String::new();
    let malformed_empty_field = make_v2_sidecar_value_with_proof_sibling(
        TrustBundleEnvironment::Devnet,
        Some(serde_json::to_value(&wire_empty_field).unwrap()),
    );
    let mut wire_empty_proof = devnet_wire.clone();
    wire_empty_proof.proof_bytes = Vec::new();
    let malformed_empty_proof_bytes = make_v2_sidecar_value_with_proof_sibling(
        TrustBundleEnvironment::Devnet,
        Some(serde_json::to_value(&wire_empty_proof).unwrap()),
    );

    write_sidecar(&sidecars_dir.join("legacy_no_proof.json"), &legacy)?;
    write_sidecar(&sidecars_dir.join("devnet_rotate_valid.json"), &devnet_valid)?;
    write_sidecar(&sidecars_dir.join("testnet_rotate_valid.json"), &testnet_valid)?;
    write_sidecar(&sidecars_dir.join("mainnet_rotate_valid.json"), &mainnet_valid)?;
    write_sidecar(
        &sidecars_dir.join("malformed_non_object.json"),
        &malformed_non_object,
    )?;
    write_sidecar(
        &sidecars_dir.join("malformed_unknown_schema.json"),
        &malformed_unknown_schema,
    )?;
    write_sidecar(
        &sidecars_dir.join("malformed_empty_field.json"),
        &malformed_empty_field,
    )?;
    write_sidecar(
        &sidecars_dir.join("malformed_empty_proof_bytes.json"),
        &malformed_empty_proof_bytes,
    )?;

    // ---- A1 / A1b — Default Disabled bypasses both no-sibling and
    //                 with-sibling sidecars (no acceptance possible).
    for surface in ALL_SURFACES {
        scenarios.push(Scenario {
            id: format!("A1_default_disabled_legacy_no_proof_{}", surface),
            note: "default Disabled + legacy v2 sidecar without sibling -> bypassed".into(),
            surface,
            policy: OnChainGovernanceProofPolicy::Disabled,
            env: TrustBundleEnvironment::Devnet,
            sidecar: legacy.clone(),
            expect: Expect::Bypassed,
        });
        scenarios.push(Scenario {
            id: format!("A1b_default_disabled_with_sibling_{}", surface),
            note: "default Disabled + valid sibling -> bypassed (PolicyDisabled before verifier)"
                .into(),
            surface,
            policy: OnChainGovernanceProofPolicy::Disabled,
            env: TrustBundleEnvironment::Devnet,
            sidecar: devnet_valid.clone(),
            expect: Expect::Bypassed,
        });
    }

    // ---- A2 / A4 — CLI selector + DevNet Rotate proof on
    //                reload-check (validation-only) and reload-apply
    //                (mutating).
    for surface in ALL_SURFACES {
        // MainNet refusal lives in R26 below; on every other surface
        // the AllowFixtureSourceTest policy + valid DevNet payload
        // accepts.
        scenarios.push(Scenario {
            id: format!("A2_allow_fixture_devnet_rotate_{}", surface),
            note: "AllowFixtureSourceTest + valid DevNet Rotate sibling -> Accepted".into(),
            surface,
            policy: OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
            env: TrustBundleEnvironment::Devnet,
            sidecar: devnet_valid.clone(),
            expect: Expect::Accept,
        });
    }

    // ---- A6 — TestNet Rotate accepted via reload-check.
    scenarios.push(Scenario {
        id: "A6_allow_fixture_testnet_rotate_reload_check".into(),
        note: "AllowFixtureSourceTest + valid TestNet Rotate sibling -> Accepted (validation-only)"
            .into(),
        surface: "reload_check",
        policy: OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        env: TrustBundleEnvironment::Testnet,
        sidecar: testnet_valid.clone(),
        expect: Expect::Accept,
    });

    // ---- R2 / malformed corpus — fail-closed BEFORE verifier on
    //                              every surface, regardless of policy.
    let malformed_inputs = [
        ("R2a_malformed_non_object", &malformed_non_object),
        ("R2b_malformed_unknown_schema_version", &malformed_unknown_schema),
        ("R2c_malformed_empty_required_field", &malformed_empty_field),
        ("R2d_malformed_empty_proof_bytes", &malformed_empty_proof_bytes),
    ];
    for (label, sidecar) in &malformed_inputs {
        for surface in ALL_SURFACES {
            scenarios.push(Scenario {
                id: format!("{}_{}", label, surface),
                note:
                    "malformed sibling -> typed MalformedOnChainGovernanceProofPayload before verifier"
                        .into(),
                surface,
                policy: OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
                env: TrustBundleEnvironment::Devnet,
                sidecar: (*sidecar).clone(),
                expect: Expect::Malformed,
            });
        }
    }

    // ---- R26 — MainNet refusal even with armed selector + fully-
    //            valid MainNet fixture proof carried in payload.
    for surface in ALL_SURFACES {
        scenarios.push(Scenario {
            id: format!("R26_mainnet_refused_armed_selector_valid_payload_{}", surface),
            note:
                "MainNet + AllowFixtureSourceTest + valid MainNet Rotate sibling -> Run 147 FATAL refusal (MainNetRefused) ahead of verifier"
                    .into(),
            surface,
            policy: OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
            env: TrustBundleEnvironment::Mainnet,
            sidecar: mainnet_valid.clone(),
            expect: Expect::Reject,
        });
    }

    // Run every scenario.
    let replay = EmptyOnChainGovernanceReplaySet;
    let mut pass = 0usize;
    let mut fail = 0usize;
    for s in &scenarios {
        let scenario_dir = scenarios_dir.join(&s.id);
        fs::create_dir_all(&scenario_dir)?;
        let bytes = serde_json::to_vec_pretty(&s.sidecar).expect("sidecar serializes");
        let scenario_path = scenario_dir.join("sidecar.json");
        fs::write(&scenario_path, &bytes)?;
        let sha = sha256_hex(&bytes);
        fs::write(scenario_dir.join("sidecar.sha256"), format!("{}\n", sha))?;
        fs::write(scenario_dir.join("note.txt"), format!("{}\n", s.note))?;
        fs::write(scenario_dir.join("expected.txt"), format!("{}\n", s.expect.label()))?;
        fs::write(scenario_dir.join("policy.txt"), format!("{:?}\n", s.policy))?;

        // Parse the sibling out of the sidecar value. (We could also
        // exercise the bytes loader; we do exercise both for the A1
        // legacy path in `bytes_loader_round_trip` below.)
        let load = parse_optional_onchain_governance_proof_sibling_from_json_value(&s.sidecar);

        let candidate = rotate_candidate(s.env);
        let prior = prior_versioned(s.env);
        let trust_domain = domain(s.env);
        let outcome = route_with(
            Some(&prior),
            &candidate,
            &load,
            &trust_domain,
            s.policy,
            &replay,
            s.surface,
        );

        let actual_dump = format!("{:?}\n", outcome);
        fs::write(scenario_dir.join("actual.txt"), &actual_dump)?;

        let line = format!(
            "{}\texpect={}\tactual_match={}\n",
            s.id,
            s.expect.label(),
            s.expect.matches(&outcome)
        );
        manifest.push_str(&line);
        expected.push_str(&format!("{}\t{}\n", s.id, s.expect.label()));
        actual.push_str(&format!("{}\t{:?}\n", s.id, outcome));

        if s.expect.matches(&outcome) {
            pass += 1;
        } else {
            fail += 1;
            eprintln!(
                "[run-185-helper] FAIL scenario {} expected {} got {:?}",
                s.id,
                s.expect.label(),
                outcome
            );
        }
    }

    // Bytes-loader round-trip on the canonical legacy sidecar
    // (asserts the Run 184 sibling pre-extraction does not poison the
    // strict v2 parse).
    let legacy_bytes = serde_json::to_vec(&legacy).expect("serializes");
    let synthetic_path = PathBuf::from("run-185-helper.json");
    let loaded = load_v2_ratification_sidecar_with_onchain_governance_proof_from_bytes(
        &legacy_bytes,
        &synthetic_path,
    )
    .expect("legacy sidecar parses");
    if !loaded.onchain_governance_proof.is_absent() {
        eprintln!(
            "[run-185-helper] FAIL legacy sidecar bytes-loader round-trip: sibling not Absent"
        );
        fail += 1;
    } else {
        pass += 1;
    }

    fs::write(out_dir.join("manifest.txt"), manifest)?;
    fs::write(out_dir.join("expected_outcomes.txt"), expected)?;
    fs::write(out_dir.join("actual_outcomes.txt"), actual)?;

    Ok((pass, fail))
}

fn write_sidecar(path: &Path, value: &serde_json::Value) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(value).expect("sidecar serializes");
    fs::write(path, &bytes)?;
    let sha_path = path.with_extension("json.sha256");
    fs::write(sha_path, format!("{}\n", sha256_hex(&bytes)))?;
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha3::Digest;
    // Use SHA2-256 if available; fall back to a hex of sha3-256 if not.
    // The release-binary harness independently writes sha256sum-based
    // hashes; this is for in-helper provenance only.
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut s = String::with_capacity(out.len() * 2);
    use std::fmt::Write;
    for b in out.iter() {
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

fn main() {
    let mut args = env::args().skip(1);
    let out_dir: PathBuf = match args.next() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!(
                "usage: run_185_onchain_governance_payload_release_binary_helper <OUT_DIR>"
            );
            std::process::exit(2);
        }
    };
    fs::create_dir_all(&out_dir).expect("create out_dir");

    let (pass, fail) = run_scenarios(&out_dir).expect("scenarios");
    let mut summary =
        fs::File::create(out_dir.join("helper_summary.txt")).expect("create summary");
    let verdict = if fail == 0 { "PASS" } else { "FAIL" };
    writeln!(
        summary,
        "Run 185 helper — release-mode OnChainGovernance payload-carrying corpus"
    )
    .unwrap();
    writeln!(summary, "verdict: {}", verdict).unwrap();
    writeln!(summary, "scenarios_pass: {}", pass).unwrap();
    writeln!(summary, "scenarios_fail: {}", fail).unwrap();
    writeln!(summary, "production_symbols_exercised:").unwrap();
    writeln!(
        summary,
        "  - qbind_node::pqc_onchain_governance_payload_carrying::parse_optional_onchain_governance_proof_sibling_from_json_value"
    )
    .unwrap();
    writeln!(
        summary,
        "  - qbind_node::pqc_onchain_governance_payload_carrying::load_v2_ratification_sidecar_with_onchain_governance_proof_from_bytes"
    )
    .unwrap();
    writeln!(
        summary,
        "  - qbind_node::pqc_onchain_governance_payload_carrying::callsite_context_with_loaded_onchain_governance_proof"
    )
    .unwrap();
    for n in &[
        "route_loaded_onchain_governance_proof_to_reload_check_callsite_decision",
        "route_loaded_onchain_governance_proof_to_reload_apply_callsite_decision",
        "route_loaded_onchain_governance_proof_to_startup_p2p_trust_bundle_callsite_decision",
        "route_loaded_onchain_governance_proof_to_sighup_callsite_decision",
        "route_loaded_onchain_governance_proof_to_local_peer_candidate_check_callsite_decision",
        "route_loaded_onchain_governance_proof_to_live_inbound_0x05_callsite_decision",
        "route_loaded_onchain_governance_proof_to_peer_driven_drain_callsite_decision",
    ] {
        writeln!(
            summary,
            "  - qbind_node::pqc_onchain_governance_payload_carrying::{}",
            n
        )
        .unwrap();
    }
    writeln!(summary, "honest_limits:").unwrap();
    writeln!(
        summary,
        "  default OnChainGovernanceProofPolicy::Disabled preserved on every surface"
    )
    .unwrap();
    writeln!(
        summary,
        "  AllowFixtureSourceTest hidden, explicit, DevNet/TestNet fixture-only"
    )
    .unwrap();
    writeln!(
        summary,
        "  MainNet peer-driven apply remains refused (Run 147 FATAL invariant) even with valid carried fixture proof"
    )
    .unwrap();
    writeln!(
        summary,
        "  no real on-chain governance, no governance execution, no KMS/HSM, no validator-set rotation"
    )
    .unwrap();
    writeln!(
        summary,
        "  no schema/wire/metric drift beyond Run 184 additive optional sibling"
    )
    .unwrap();

    if fail != 0 {
        std::process::exit(1);
    }
}
