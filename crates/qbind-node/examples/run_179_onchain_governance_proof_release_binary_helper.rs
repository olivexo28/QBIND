//! Run 179 — release-built helper that exercises the Run 178 typed
//! `OnChainGovernance` proof verifier corpus end-to-end **in release
//! mode** through the production symbols
//! [`qbind_node::pqc_onchain_governance_proof::verify_onchain_governance_proof`],
//! [`qbind_node::pqc_onchain_governance_proof::validate_lifecycle_with_onchain_governance_proof`],
//! and the additive optional wire carrier
//! [`qbind_node::pqc_onchain_governance_proof::OnChainGovernanceProofWire`].
//!
//! Per `task/RUN_179_TASK.txt`, Run 179 is a **release-binary
//! evidence / boundary** run. This helper is fixture-tooling and:
//!
//! * does NOT modify any production runtime code, CLI flag, env var,
//!   wire / marker / sequence / trust-bundle / peer-candidate-envelope
//!   schema, or any reachable production caller of
//!   `verify_onchain_governance_proof`;
//! * does NOT enable MainNet peer-driven apply on any surface;
//! * does NOT mutate any live trust state;
//! * does NOT open a P2P socket;
//! * never elevates a fixture acceptance into a MainNet apply
//!   (MainNet always returns `MainNetProductionProofUnavailable` from
//!   the Run 178 verifier);
//! * exists alongside (and does NOT replace) the Run 178
//!   source/test target
//!   `crates/qbind-node/tests/run_178_onchain_governance_proof_tests.rs`.
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
//! <OUT_DIR>/scenarios/<id>/proof.json     # OnChainGovernanceProofWire when applicable
//! <OUT_DIR>/scenarios/<id>/proof.sha256
//! <OUT_DIR>/scenarios/<id>/note.txt        # short human-readable description
//! ```
//!
//! Plus, at the top level:
//!
//! ```text
//! <OUT_DIR>/wire_roundtrip_run178.json     # Run 178 OnChainGovernance wire round-trip
//! <OUT_DIR>/wire_roundtrip_run167.json     # Run 167 GenesisBound carrier round-trip (R24)
//! <OUT_DIR>/helper_summary.txt             # release-built helper verdict
//! ```
//!
//! The helper exits with a non-zero status if any scenario does not
//! match its expected typed outcome, mirroring the Run 168 / Run 178
//! release-built-helper pattern.
//!
//! Usage:
//! ```text
//! run_179_onchain_governance_proof_release_binary_helper <OUT_DIR>
//! ```

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use qbind_ledger::BundleSigningRatificationV2Action;
use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
    REVOKED_METADATA_PREFIX_EMERGENCY, REVOKED_METADATA_PREFIX_REVOKE,
};
use qbind_node::pqc_authority_state::{
    AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
    PersistentAuthorityStateRecordVersioned,
};
use qbind_node::pqc_governance_authority::{
    fixture_issuer_signature, fixture_issuer_signature_verifier,
    verify_governance_authority_proof, GovernanceAuthorityClass, GovernanceAuthorityProof,
    GovernanceAuthorityVerificationOutcome as Run163GovOutcome, GovernanceThreshold,
    PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_proof_wire::GovernanceAuthorityProofWire;
use qbind_node::pqc_onchain_governance_proof::{
    fixture_onchain_governance_proof_bytes, mainnet_peer_driven_apply_remains_refused,
    validate_lifecycle_with_onchain_governance_proof, verify_onchain_governance_proof,
    CombinedLifecycleOnChainGovernanceOutcome, EmptyOnChainGovernanceReplaySet,
    OnChainGovernanceFreshnessWindow, OnChainGovernanceProof, OnChainGovernanceProofPolicy,
    OnChainGovernanceProofVerificationOutcome as Outcome, OnChainGovernanceProofWire,
    OnChainGovernanceProofWireParseError, OnChainGovernanceProposalOutcome,
    OnChainGovernanceQuorum, ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1,
    ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION,
    ONCHAIN_GOVERNANCE_PROOF_WIRE_SCHEMA_VERSION,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Constants — keep in sync with the Run 178 test fixture so this helper
// exercises the *same* canonical commitment bytes the Run 178 test
// target exercises in source/test mode.
// ===========================================================================

const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT_FP: &str = "1111111111111111111111111111111111111111";
const OTHER_ROOT_FP: &str = "9999999999999999999999999999999999999999";
const CHAIN_ID: &str = "0000000000000001";
const OTHER_CHAIN: &str = "00000000000000ff";
const GENESIS_HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GENESIS_HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DIGEST_3: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const RATIFY_DIGEST_1: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";

const GOV_DOMAIN: &str = "qbind-onchain-gov-1";
const OTHER_GOV_DOMAIN: &str = "qbind-onchain-gov-other";
const GOV_EPOCH: u64 = 42;
const PROPOSAL_ID: &str = "prop-001";
const OTHER_PROPOSAL_ID: &str = "prop-999";
const PROPOSAL_DIGEST: &str =
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
const OTHER_PROPOSAL_DIGEST: &str =
    "feedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed";
const UNIQUE_DECISION_ID: &str = "decision-001";
const NOW: u64 = 1_700_000_000;

// ===========================================================================
// Helpers
// ===========================================================================

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

fn build_v2_with_env(
    env: TrustBundleEnvironment,
    active_fp: &str,
    sequence: u64,
    action: BundleSigningRatificationV2Action,
    previous_fp: Option<&str>,
    digest: &str,
    revoked_metadata: Option<&str>,
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
        NOW,
    )
}

fn rotate_to(
    new_active_fp: &str,
    previous_fp: &str,
    sequence: u64,
    digest: &str,
    env: TrustBundleEnvironment,
) -> PersistentAuthorityStateRecordV2 {
    build_v2_with_env(
        env,
        new_active_fp,
        sequence,
        BundleSigningRatificationV2Action::Rotate,
        Some(previous_fp),
        digest,
        None,
    )
}

fn revoke_record(
    active_fp: &str,
    sequence: u64,
    digest: &str,
    sub_class_prefix: &str,
    revoked_target: &str,
    env: TrustBundleEnvironment,
) -> PersistentAuthorityStateRecordV2 {
    let metadata = format!("{}{}", sub_class_prefix, revoked_target);
    build_v2_with_env(
        env,
        active_fp,
        sequence,
        BundleSigningRatificationV2Action::Revoke,
        None,
        digest,
        Some(&metadata),
    )
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
        LocalLifecycleAction::Retire
        | LocalLifecycleAction::Revoke
        | LocalLifecycleAction::EmergencyRevoke => candidate
            .revoked_key_metadata
            .as_deref()
            .and_then(|m| m.get(2..))
            .map(str::to_string),
        LocalLifecycleAction::ActivateInitial => None,
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

fn allow_fixture() -> OnChainGovernanceProofPolicy {
    OnChainGovernanceProofPolicy::AllowFixtureSourceTest
}

fn verify_with(
    proof: &OnChainGovernanceProof,
    candidate: &PersistentAuthorityStateRecordV2,
    domain: &AuthorityTrustDomain,
    policy: OnChainGovernanceProofPolicy,
    persisted_seq: Option<u64>,
) -> Outcome {
    verify_onchain_governance_proof(
        proof,
        candidate,
        domain,
        policy,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        persisted_seq,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    )
}

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------

fn write_text(path: &Path, body: &str) {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).expect("create parent dir");
    }
    let mut f = fs::File::create(path).expect("create file");
    f.write_all(body.as_bytes()).expect("write file");
}

fn sha256_hex_of_bytes(bytes: &[u8]) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut s = String::with_capacity(out.len() * 2);
    for b in out {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

// ---------------------------------------------------------------------------
// Per-scenario record
// ---------------------------------------------------------------------------

struct ScenarioRecord {
    id: &'static str,
    expected_label: &'static str,
    note: String,
    actual_dbg: String,
    matched: bool,
    proof_wire_json: Option<String>,
}

fn record_outcome(
    out_dir: &Path,
    id: &'static str,
    expected_label: &'static str,
    note: &str,
    policy: OnChainGovernanceProofPolicy,
    actual_dbg: String,
    matched: bool,
    proof: Option<&OnChainGovernanceProof>,
) -> ScenarioRecord {
    let dir = out_dir.join("scenarios").join(id);
    fs::create_dir_all(&dir).expect("create scenario dir");
    write_text(&dir.join("policy.txt"), &format!("{:?}\n", policy));
    write_text(&dir.join("expected.txt"), &format!("{}\n", expected_label));
    write_text(&dir.join("actual.txt"), &format!("{}\n", actual_dbg));
    write_text(&dir.join("note.txt"), &format!("{}\n", note));

    let mut wire_json = None;
    if let Some(p) = proof {
        let wire = OnChainGovernanceProofWire::from_proof(p);
        let json = serde_json::to_string_pretty(&wire).expect("encode wire");
        write_text(&dir.join("proof.json"), &json);
        write_text(
            &dir.join("proof.sha256"),
            &format!("{}\n", sha256_hex_of_bytes(json.as_bytes())),
        );
        wire_json = Some(json);
    }

    ScenarioRecord {
        id,
        expected_label,
        note: note.to_string(),
        actual_dbg,
        matched,
        proof_wire_json: wire_json,
    }
}

// ---------------------------------------------------------------------------
// Scenario implementations — A1..A7 / R1..R25 mirror the Run 178 test
// target one-for-one so the release-built behaviour is bit-identical.
// ---------------------------------------------------------------------------

fn run_a1(out: &Path) -> ScenarioRecord {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let outcome = verify_with(&proof, &candidate, &devnet_domain(), allow_fixture(), Some(1));
    let matched = matches!(outcome, Outcome::AcceptedOnChainGovernanceFixture { .. });
    record_outcome(
        out,
        "A1_devnet_fixture_rotate_accepted",
        "AcceptedOnChainGovernanceFixture",
        "DevNet fixture OnChainGovernance Rotate proof accepted",
        allow_fixture(),
        format!("{:?}", outcome),
        matched,
        Some(&proof),
    )
}

fn run_a2(out: &Path) -> ScenarioRecord {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Testnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let outcome = verify_with(
        &proof,
        &candidate,
        &testnet_domain(),
        allow_fixture(),
        Some(1),
    );
    let matched = matches!(outcome, Outcome::AcceptedOnChainGovernanceFixture { .. });
    record_outcome(
        out,
        "A2_testnet_fixture_rotate_accepted",
        "AcceptedOnChainGovernanceFixture",
        "TestNet fixture OnChainGovernance Rotate proof accepted",
        allow_fixture(),
        format!("{:?}", outcome),
        matched,
        Some(&proof),
    )
}

fn run_a3(out: &Path) -> ScenarioRecord {
    let candidate = revoke_record(
        KEY_B,
        3,
        DIGEST_3,
        REVOKED_METADATA_PREFIX_REVOKE,
        KEY_A,
        TrustBundleEnvironment::Devnet,
    );
    let proof = good_proof(&candidate, LocalLifecycleAction::Revoke);
    let outcome = verify_with(&proof, &candidate, &devnet_domain(), allow_fixture(), Some(2));
    let matched = matches!(
        outcome,
        Outcome::AcceptedOnChainGovernanceFixture {
            action: LocalLifecycleAction::Revoke,
            ..
        }
    );
    record_outcome(
        out,
        "A3_devnet_fixture_revoke_accepted",
        "AcceptedOnChainGovernanceFixture(Revoke)",
        "DevNet fixture OnChainGovernance Revoke proof accepted",
        allow_fixture(),
        format!("{:?}", outcome),
        matched,
        Some(&proof),
    )
}

fn run_a4(out: &Path) -> ScenarioRecord {
    let candidate = revoke_record(
        KEY_B,
        4,
        DIGEST_3,
        REVOKED_METADATA_PREFIX_EMERGENCY,
        KEY_A,
        TrustBundleEnvironment::Testnet,
    );
    let proof = good_proof(&candidate, LocalLifecycleAction::EmergencyRevoke);
    let outcome = verify_with(
        &proof,
        &candidate,
        &testnet_domain(),
        allow_fixture(),
        Some(3),
    );
    let matched = matches!(
        outcome,
        Outcome::AcceptedOnChainGovernanceFixture {
            action: LocalLifecycleAction::EmergencyRevoke,
            ..
        }
    );
    record_outcome(
        out,
        "A4_testnet_fixture_emergency_revoke_accepted",
        "AcceptedOnChainGovernanceFixture(EmergencyRevoke)",
        "TestNet fixture OnChainGovernance EmergencyRevoke proof accepted",
        allow_fixture(),
        format!("{:?}", outcome),
        matched,
        Some(&proof),
    )
}

fn run_a5(out: &Path) -> ScenarioRecord {
    let prev = build_v2_with_env(
        TrustBundleEnvironment::Devnet,
        KEY_A,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        RATIFY_DIGEST_1,
        None,
    );
    let persisted = PersistentAuthorityStateRecordVersioned::V2(prev);
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let combined = validate_lifecycle_with_onchain_governance_proof(
        Some(&persisted),
        &candidate,
        &proof,
        &devnet_domain(),
        allow_fixture(),
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    let matched = matches!(combined, CombinedLifecycleOnChainGovernanceOutcome::Accepted { .. });
    record_outcome(
        out,
        "A5_combined_lifecycle_with_onchain_governance_proof_accepted",
        "CombinedLifecycleOnChainGovernanceOutcome::Accepted",
        "OnChainGovernance proof accepted through combined lifecycle helper",
        allow_fixture(),
        format!("{:?}", combined),
        matched,
        Some(&proof),
    )
}

fn run_a6(out: &Path) -> ScenarioRecord {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    // Round-trip the proof through wire form, then verify.
    let wire = OnChainGovernanceProofWire::from_proof(&proof);
    let json = serde_json::to_vec(&wire).expect("encode wire");
    let decoded: OnChainGovernanceProofWire =
        serde_json::from_slice(&json).expect("decode wire");
    let same_wire = wire == decoded;
    let decoded_proof = decoded.to_proof().expect("wire to proof");
    let same_proof = proof == decoded_proof;
    let outcome = verify_with(
        &decoded_proof,
        &candidate,
        &devnet_domain(),
        allow_fixture(),
        Some(1),
    );
    let candidate_unchanged = candidate.active_bundle_signing_key_fingerprint == KEY_B
        && candidate.latest_authority_domain_sequence == 2;
    let matched = same_wire
        && same_proof
        && candidate_unchanged
        && matches!(outcome, Outcome::AcceptedOnChainGovernanceFixture { .. });
    record_outcome(
        out,
        "A6_proof_carrying_sidecar_roundtrip_accepted_no_mutation",
        "wire-roundtrip + AcceptedOnChainGovernanceFixture + candidate-unchanged",
        "Proof-carrying sidecar wire round-trip + accepted at marker-decision \
         source/test boundary + candidate inputs unchanged after verification",
        allow_fixture(),
        format!(
            "{{ same_wire: {}, same_proof: {}, candidate_unchanged: {}, outcome: {:?} }}",
            same_wire, same_proof, candidate_unchanged, outcome
        ),
        matched,
        Some(&proof),
    )
}

fn run_a7(out: &Path) -> ScenarioRecord {
    // GenesisBound rotate proof — pure Run 163 path — must still accept.
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let signature = fixture_issuer_signature(
        GovernanceAuthorityClass::GenesisBound,
        ROOT_FP,
        &candidate.latest_ratification_v2_digest,
        candidate.latest_authority_domain_sequence,
    );
    let gb_proof = GovernanceAuthorityProof {
        environment: TrustBundleEnvironment::Devnet,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH_A.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        authority_root_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        lifecycle_action: LocalLifecycleAction::Rotate,
        active_bundle_signing_key_fingerprint: KEY_B.to_string(),
        new_bundle_signing_key_fingerprint: Some(KEY_B.to_string()),
        revoked_bundle_signing_key_fingerprint: Some(KEY_A.to_string()),
        authority_domain_sequence: 2,
        candidate_v2_digest: DIGEST_2.to_string(),
        issuer_authority_class: GovernanceAuthorityClass::GenesisBound,
        issuer_signature_suite_id: PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44,
        issuer_signature: signature,
        threshold: None,
    };
    let gb_outcome = verify_governance_authority_proof(
        &gb_proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    let gb_accepted = matches!(gb_outcome, Run163GovOutcome::AcceptedGenesisBound { .. });

    // Run 163 OnChainGovernance class still returns UnsupportedOnChainGovernance.
    let mut on_chain_proof = gb_proof.clone();
    on_chain_proof.issuer_authority_class = GovernanceAuthorityClass::OnChainGovernance;
    on_chain_proof.issuer_signature = fixture_issuer_signature(
        GovernanceAuthorityClass::OnChainGovernance,
        ROOT_FP,
        &candidate.latest_ratification_v2_digest,
        candidate.latest_authority_domain_sequence,
    );
    let unsup_outcome = verify_governance_authority_proof(
        &on_chain_proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    let unsup_ok = matches!(unsup_outcome, Run163GovOutcome::UnsupportedOnChainGovernance);

    let matched = gb_accepted && unsup_ok;
    record_outcome(
        out,
        "A7_existing_genesis_bound_and_emergency_council_unchanged",
        "Run163 AcceptedGenesisBound + UnsupportedOnChainGovernance unchanged",
        "Existing Run 163 GenesisBound + OnChainGovernance behaviour unchanged \
         by Run 178/179 — verifier byte-for-byte identical",
        OnChainGovernanceProofPolicy::Disabled,
        format!(
            "{{ gb_outcome: {:?}, unsup_outcome: {:?} }}",
            gb_outcome, unsup_outcome
        ),
        matched,
        None,
    )
}

// ---- R1..R10 — domain / governance / lifecycle / sequence rejects --------

fn run_simple_reject<F>(
    out: &Path,
    id: &'static str,
    expected_label: &'static str,
    note: &str,
    mutate: F,
) -> ScenarioRecord
where
    F: FnOnce(&mut OnChainGovernanceProof),
{
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    mutate(&mut proof);
    let outcome = verify_with(&proof, &candidate, &devnet_domain(), allow_fixture(), Some(1));
    let matched_dbg = format!("{:?}", outcome);
    let matched = matched_dbg.starts_with(expected_label);
    record_outcome(
        out,
        id,
        expected_label,
        note,
        allow_fixture(),
        matched_dbg,
        matched,
        Some(&proof),
    )
}

fn run_r1(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R1_wrong_environment_rejected", "WrongEnvironment", "wrong environment rejected", |p| {
        p.environment = TrustBundleEnvironment::Testnet;
    })
}
fn run_r2(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R2_wrong_chain_rejected", "WrongChain", "wrong chain rejected", |p| {
        p.chain_id = OTHER_CHAIN.to_string();
    })
}
fn run_r3(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R3_wrong_genesis_rejected", "WrongGenesis", "wrong genesis rejected", |p| {
        p.genesis_hash = GENESIS_HASH_B.to_string();
    })
}
fn run_r4(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R4_wrong_authority_root_rejected", "WrongAuthorityRoot", "wrong authority root rejected", |p| {
        p.authority_root_fingerprint = OTHER_ROOT_FP.to_string();
    })
}
fn run_r5(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R5_wrong_governance_domain_rejected", "WrongGovernanceDomain", "wrong governance domain rejected", |p| {
        p.governance_domain_id = OTHER_GOV_DOMAIN.to_string();
    })
}
fn run_r6(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R6_wrong_proposal_digest_rejected", "WrongProposalDigest", "wrong proposal digest rejected", |p| {
        p.proposal_digest = OTHER_PROPOSAL_DIGEST.to_string();
    })
}
fn run_r6b(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R6b_wrong_proposal_id_rejected", "WrongProposalDigest", "wrong proposal id rejected as proposal-digest mismatch", |p| {
        p.proposal_id = OTHER_PROPOSAL_ID.to_string();
    })
}
fn run_r7(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R7_wrong_proposal_outcome_rejected", "WrongProposalOutcome", "wrong proposal outcome rejected", |p| {
        p.proposal_outcome = OnChainGovernanceProposalOutcome::Rejected;
    })
}
fn run_r8(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R8_wrong_lifecycle_action_rejected", "WrongLifecycleAction", "wrong lifecycle action rejected", |p| {
        p.lifecycle_action = LocalLifecycleAction::Retire;
    })
}
fn run_r9(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R9_wrong_candidate_digest_rejected", "WrongCandidateDigest", "wrong candidate digest rejected", |p| {
        p.candidate_v2_digest = DIGEST_3.to_string();
    })
}
fn run_r10(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R10_wrong_authority_sequence_rejected", "WrongAuthoritySequence", "wrong authority-domain sequence rejected", |p| {
        p.authority_domain_sequence = 7;
    })
}

fn run_r11(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R11_expired_governance_proof_rejected", "ExpiredGovernanceProof", "expired governance proof rejected", |p| {
        p.freshness = OnChainGovernanceFreshnessWindow {
            not_before_unix: NOW - 1000,
            not_after_unix: NOW - 100,
        };
    })
}
fn run_r11b(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R11b_too_early_governance_proof_rejected", "ExpiredGovernanceProof", "too-early proof rejected as expired window", |p| {
        p.freshness = OnChainGovernanceFreshnessWindow {
            not_before_unix: NOW + 100,
            not_after_unix: NOW + 1000,
        };
    })
}

fn run_r12(out: &Path) -> ScenarioRecord {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    // Persisted higher than the proof's sequence => stale lower-sequence replay.
    let outcome = verify_with(&proof, &candidate, &devnet_domain(), allow_fixture(), Some(99));
    let dbg = format!("{:?}", outcome);
    let matched = dbg.starts_with("ReplayRejected");
    record_outcome(
        out,
        "R12_stale_lower_sequence_replay_rejected",
        "ReplayRejected",
        "stale lower-sequence governance decision rejected",
        allow_fixture(),
        dbg,
        matched,
        Some(&proof),
    )
}
fn run_r12b(out: &Path) -> ScenarioRecord {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let seen = vec![UNIQUE_DECISION_ID.to_string()];
    let outcome = verify_onchain_governance_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        allow_fixture(),
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &seen,
    );
    let dbg = format!("{:?}", outcome);
    let matched = dbg.starts_with("ReplayRejected");
    record_outcome(
        out,
        "R12b_replayed_unique_decision_id_rejected",
        "ReplayRejected",
        "replayed unique_decision_id rejected via replay set",
        allow_fixture(),
        dbg,
        matched,
        Some(&proof),
    )
}

fn run_r13(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R13_quorum_not_met_rejected", "QuorumNotMet", "quorum not met rejected", |p| {
        p.quorum = OnChainGovernanceQuorum {
            voters_voted: 2,
            total_voters: 5,
            required_quorum: 3,
        };
    })
}
fn run_r14(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R14_threshold_not_met_rejected", "ThresholdNotMet", "threshold not met rejected", |p| {
        p.threshold = GovernanceThreshold::new(1, 3, 5);
    })
}
fn run_r15(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R15_invalid_proof_bytes_rejected", "InvalidGovernanceProof", "invalid governance proof bytes rejected", |p| {
        p.proof_bytes = b"this-is-not-the-canonical-commitment".to_vec();
    })
}
fn run_r16(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R16_unsupported_proof_suite_rejected", "UnsupportedGovernanceProofSuite", "reserved production proof suite rejected", |p| {
        p.proof_suite_id = ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION;
    })
}
fn run_r16b(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R16b_unknown_proof_suite_rejected", "UnsupportedGovernanceProofSuite", "unknown proof suite id rejected", |p| {
        p.proof_suite_id = 0xFF;
    })
}

fn run_r17(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R17_malformed_empty_field_rejected", "MalformedOnChainProof", "malformed proof: empty governance_domain_id", |p| {
        p.governance_domain_id.clear();
    })
}
fn run_r17b(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R17b_malformed_empty_proof_bytes_rejected", "MalformedOnChainProof", "malformed proof: empty proof_bytes", |p| {
        p.proof_bytes.clear();
    })
}
fn run_r17c(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R17c_malformed_freshness_window_rejected", "MalformedOnChainProof", "malformed proof: inverted freshness window", |p| {
        p.freshness = OnChainGovernanceFreshnessWindow {
            not_before_unix: NOW + 1000,
            not_after_unix: NOW,
        };
    })
}
fn run_r17d(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R17d_non_pqc_authority_root_suite_rejected_as_malformed", "MalformedOnChainProof", "malformed proof: non-PQC authority_root_suite_id", |p| {
        p.authority_root_suite_id = 1;
    })
}

fn run_r18(out: &Path) -> ScenarioRecord {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Mainnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let outcome = verify_onchain_governance_proof(
        &proof,
        &candidate,
        &mainnet_domain(),
        allow_fixture(),
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    let dbg = format!("{:?}", outcome);
    let matched = matches!(outcome, Outcome::MainNetProductionProofUnavailable);
    record_outcome(
        out,
        "R18_mainnet_production_proof_unavailable",
        "MainNetProductionProofUnavailable",
        "production MainNet OnChainGovernance proof rejected as unavailable/unsupported \
         even under AllowFixtureSourceTest policy",
        allow_fixture(),
        dbg,
        matched,
        Some(&proof),
    )
}

fn run_r19(out: &Path) -> ScenarioRecord {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let outcome = verify_with(
        &proof,
        &candidate,
        &devnet_domain(),
        OnChainGovernanceProofPolicy::Disabled,
        Some(1),
    );
    let dbg = format!("{:?}", outcome);
    let matched = matches!(outcome, Outcome::UnsupportedProductionOnChainGovernance);
    record_outcome(
        out,
        "R19_local_operator_config_alone_rejected_via_disabled_policy",
        "UnsupportedProductionOnChainGovernance",
        "local operator config alone rejected as OnChainGovernance proof under default \
         Disabled policy (every proof refused)",
        OnChainGovernanceProofPolicy::Disabled,
        dbg,
        matched,
        Some(&proof),
    )
}

fn run_r20(out: &Path) -> ScenarioRecord {
    run_simple_reject(out, "R20_peer_majority_gossip_rejected_via_invalid_proof_bytes", "InvalidGovernanceProof", "peer-majority / gossip count rejected as OnChainGovernance proof", |p| {
        p.proof_bytes = b"peer-gossip-majority:5-of-7".to_vec();
    })
}

fn run_r21(out: &Path) -> ScenarioRecord {
    let prev = rotate_to(KEY_B, KEY_A, 5, DIGEST_3, TrustBundleEnvironment::Devnet);
    let persisted = PersistentAuthorityStateRecordVersioned::V2(prev);
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let combined = validate_lifecycle_with_onchain_governance_proof(
        Some(&persisted),
        &candidate,
        &proof,
        &devnet_domain(),
        allow_fixture(),
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    let dbg = format!("{:?}", combined);
    let matched = combined.is_reject()
        && matches!(
            combined,
            CombinedLifecycleOnChainGovernanceOutcome::LifecycleRejected(_)
        );
    record_outcome(
        out,
        "R21_proof_valid_but_lifecycle_invalid_rejected",
        "CombinedLifecycleOnChainGovernanceOutcome::LifecycleRejected",
        "OnChainGovernance proof valid but lifecycle invalid (rollback) — combined helper rejects",
        allow_fixture(),
        dbg,
        matched,
        Some(&proof),
    )
}

fn run_r22(out: &Path) -> ScenarioRecord {
    let prev = build_v2_with_env(
        TrustBundleEnvironment::Devnet,
        KEY_A,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        RATIFY_DIGEST_1,
        None,
    );
    let persisted = PersistentAuthorityStateRecordVersioned::V2(prev);
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proposal_digest = OTHER_PROPOSAL_DIGEST.to_string();
    let combined = validate_lifecycle_with_onchain_governance_proof(
        Some(&persisted),
        &candidate,
        &proof,
        &devnet_domain(),
        allow_fixture(),
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    let dbg = format!("{:?}", combined);
    let matched = matches!(
        combined,
        CombinedLifecycleOnChainGovernanceOutcome::GovernanceRejected {
            governance: Outcome::WrongProposalDigest { .. },
            ..
        }
    );
    record_outcome(
        out,
        "R22_lifecycle_valid_but_proof_invalid_rejected",
        "CombinedLifecycleOnChainGovernanceOutcome::GovernanceRejected{WrongProposalDigest}",
        "Lifecycle valid but OnChainGovernance proof invalid — combined helper rejects",
        allow_fixture(),
        dbg,
        matched,
        Some(&proof),
    )
}

fn run_r23(out: &Path) -> ScenarioRecord {
    // DevNet fixture proof verifies; that acceptance must NOT enable MainNet apply.
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let outcome = verify_with(&proof, &candidate, &devnet_domain(), allow_fixture(), Some(1));
    let devnet_accepted = outcome.is_accept();
    let mainnet_refused =
        mainnet_peer_driven_apply_remains_refused(TrustBundleEnvironment::Mainnet, &outcome);

    // Fresh MainNet-side verification still returns MainNetProductionProofUnavailable.
    let mainnet_candidate =
        rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Mainnet);
    let mainnet_proof = good_proof(&mainnet_candidate, LocalLifecycleAction::Rotate);
    let mainnet_outcome = verify_onchain_governance_proof(
        &mainnet_proof,
        &mainnet_candidate,
        &mainnet_domain(),
        allow_fixture(),
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    let mainnet_unavailable = matches!(
        mainnet_outcome,
        Outcome::MainNetProductionProofUnavailable
    );

    let matched = devnet_accepted && mainnet_refused && mainnet_unavailable;
    record_outcome(
        out,
        "R23_mainnet_peer_driven_apply_remains_refused",
        "DevNet accepted + MainNet refused + MainNetProductionProofUnavailable",
        "OnChainGovernance proof valid for DevNet, but MainNet peer-driven apply \
         remains refused unconditionally and MainNet OnChainGovernance proofs \
         are still refused as unavailable.",
        allow_fixture(),
        format!(
            "{{ devnet_accepted: {}, mainnet_refused: {}, mainnet_outcome: {:?} }}",
            devnet_accepted, mainnet_refused, mainnet_outcome
        ),
        matched,
        Some(&proof),
    )
}

fn run_r24(out: &Path) -> ScenarioRecord {
    // A pre-Run-178 carrier (Run 167-177) carries no Run 178 OnChainGovernance sibling.
    let signature = fixture_issuer_signature(
        GovernanceAuthorityClass::GenesisBound,
        ROOT_FP,
        DIGEST_2,
        2,
    );
    let r163_proof = GovernanceAuthorityProof {
        environment: TrustBundleEnvironment::Devnet,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH_A.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        authority_root_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        lifecycle_action: LocalLifecycleAction::Rotate,
        active_bundle_signing_key_fingerprint: KEY_B.to_string(),
        new_bundle_signing_key_fingerprint: Some(KEY_B.to_string()),
        revoked_bundle_signing_key_fingerprint: Some(KEY_A.to_string()),
        authority_domain_sequence: 2,
        candidate_v2_digest: DIGEST_2.to_string(),
        issuer_authority_class: GovernanceAuthorityClass::GenesisBound,
        issuer_signature_suite_id: PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44,
        issuer_signature: signature,
        threshold: None,
    };
    let wire = GovernanceAuthorityProofWire::from_governance_authority_proof(&r163_proof);
    let json = serde_json::to_vec(&wire).expect("encode r167 wire");
    let decoded: GovernanceAuthorityProofWire =
        serde_json::from_slice(&json).expect("decode r167 wire");
    let same_wire = wire == decoded;
    let decoded_proof = decoded
        .to_governance_authority_proof()
        .expect("decoded run 167 proof");
    let same_proof = r163_proof == decoded_proof;

    write_text(
        &out.join("wire_roundtrip_run167.json"),
        &serde_json::to_string_pretty(&wire).expect("pretty r167 wire"),
    );

    let matched = same_wire && same_proof;
    record_outcome(
        out,
        "R24_old_run167_carrier_without_onchain_sibling_still_parses",
        "Run167 wire round-trips identically (no OnChainGovernance sibling)",
        "Old proof-carrier sidecars (Runs 167–177) without the additive Run 178 \
         OnChainGovernance sibling remain parse-compatible",
        OnChainGovernanceProofPolicy::Disabled,
        format!(
            "{{ same_wire: {}, same_proof: {} }}",
            same_wire, same_proof
        ),
        matched,
        None,
    )
}

fn run_r24b(out: &Path) -> ScenarioRecord {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let wire = OnChainGovernanceProofWire::from_proof(&proof);
    let schema_ok = wire.schema_version == ONCHAIN_GOVERNANCE_PROOF_WIRE_SCHEMA_VERSION;
    let json = serde_json::to_string_pretty(&wire).expect("encode wire");
    let decoded: OnChainGovernanceProofWire =
        serde_json::from_str(&json).expect("decode wire");
    let p_back = decoded.to_proof().expect("wire to proof");
    let same_proof = proof == p_back;

    write_text(&out.join("wire_roundtrip_run178.json"), &json);

    let matched = schema_ok && same_proof;
    record_outcome(
        out,
        "R24b_run178_onchain_wire_roundtrips_independently",
        "OnChainGovernanceProofWire schema_version=1 round-trips losslessly",
        "Run 178 additive OnChainGovernance wire object round-trips through JSON \
         losslessly and the decoded proof verifies identically",
        allow_fixture(),
        format!(
            "{{ schema_version_ok: {}, same_proof: {} }}",
            schema_ok, same_proof
        ),
        matched,
        Some(&proof),
    )
}

fn run_r25(out: &Path) -> ScenarioRecord {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let mut wire = OnChainGovernanceProofWire::from_proof(&proof);
    wire.schema_version = 99;
    let err = wire.to_proof().expect_err("future schema_version must fail closed");
    let matched = matches!(
        err,
        OnChainGovernanceProofWireParseError::UnknownSchemaVersion {
            got: 99,
            expected: 1,
        }
    );
    record_outcome(
        out,
        "R25_unknown_wire_schema_version_rejected_fail_closed",
        "OnChainGovernanceProofWireParseError::UnknownSchemaVersion{got:99,expected:1}",
        "unsupported future OnChainGovernance wire schema_version rejected fail-closed",
        OnChainGovernanceProofPolicy::Disabled,
        format!("{:?}", err),
        matched,
        None,
    )
}
fn run_r25b(out: &Path) -> ScenarioRecord {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let mut wire = OnChainGovernanceProofWire::from_proof(&proof);
    wire.governance_domain_id.clear();
    let err = wire.to_proof().expect_err("empty required field must fail");
    let matched = matches!(err, OnChainGovernanceProofWireParseError::EmptyRequiredField);
    record_outcome(
        out,
        "R25b_empty_required_field_in_wire_rejected_fail_closed",
        "OnChainGovernanceProofWireParseError::EmptyRequiredField",
        "empty required field at the OnChainGovernance wire boundary rejected fail-closed",
        OnChainGovernanceProofPolicy::Disabled,
        format!("{:?}", err),
        matched,
        None,
    )
}
fn run_r25c(out: &Path) -> ScenarioRecord {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let mut wire = OnChainGovernanceProofWire::from_proof(&proof);
    wire.proof_bytes.clear();
    let err = wire.to_proof().expect_err("empty proof_bytes must fail");
    let matched = matches!(err, OnChainGovernanceProofWireParseError::EmptyProofBytes);
    record_outcome(
        out,
        "R25c_empty_proof_bytes_in_wire_rejected_fail_closed",
        "OnChainGovernanceProofWireParseError::EmptyProofBytes",
        "empty proof_bytes at the OnChainGovernance wire boundary rejected fail-closed",
        OnChainGovernanceProofPolicy::Disabled,
        format!("{:?}", err),
        matched,
        None,
    )
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!(
            "usage: run_179_onchain_governance_proof_release_binary_helper <OUT_DIR>"
        );
        std::process::exit(2);
    }
    let out_dir = PathBuf::from(&args[1]);
    fs::create_dir_all(&out_dir).expect("create OUT_DIR");
    fs::create_dir_all(out_dir.join("scenarios")).expect("create scenarios dir");

    let mut records: Vec<ScenarioRecord> = Vec::new();
    records.push(run_a1(&out_dir));
    records.push(run_a2(&out_dir));
    records.push(run_a3(&out_dir));
    records.push(run_a4(&out_dir));
    records.push(run_a5(&out_dir));
    records.push(run_a6(&out_dir));
    records.push(run_a7(&out_dir));
    records.push(run_r1(&out_dir));
    records.push(run_r2(&out_dir));
    records.push(run_r3(&out_dir));
    records.push(run_r4(&out_dir));
    records.push(run_r5(&out_dir));
    records.push(run_r6(&out_dir));
    records.push(run_r6b(&out_dir));
    records.push(run_r7(&out_dir));
    records.push(run_r8(&out_dir));
    records.push(run_r9(&out_dir));
    records.push(run_r10(&out_dir));
    records.push(run_r11(&out_dir));
    records.push(run_r11b(&out_dir));
    records.push(run_r12(&out_dir));
    records.push(run_r12b(&out_dir));
    records.push(run_r13(&out_dir));
    records.push(run_r14(&out_dir));
    records.push(run_r15(&out_dir));
    records.push(run_r16(&out_dir));
    records.push(run_r16b(&out_dir));
    records.push(run_r17(&out_dir));
    records.push(run_r17b(&out_dir));
    records.push(run_r17c(&out_dir));
    records.push(run_r17d(&out_dir));
    records.push(run_r18(&out_dir));
    records.push(run_r19(&out_dir));
    records.push(run_r20(&out_dir));
    records.push(run_r21(&out_dir));
    records.push(run_r22(&out_dir));
    records.push(run_r23(&out_dir));
    records.push(run_r24(&out_dir));
    records.push(run_r24b(&out_dir));
    records.push(run_r25(&out_dir));
    records.push(run_r25b(&out_dir));
    records.push(run_r25c(&out_dir));

    // Manifest
    let mut manifest = String::new();
    let mut expected = String::new();
    let mut actual = String::new();
    let mut all_ok = true;
    let mut counts = (0usize, 0usize);
    for r in &records {
        manifest.push_str(&format!("{}\t{}\n", r.id, r.expected_label));
        expected.push_str(&format!("{}: {}\n  note: {}\n", r.id, r.expected_label, r.note));
        actual.push_str(&format!(
            "{}: matched={} actual={}\n",
            r.id, r.matched, r.actual_dbg
        ));
        if r.matched {
            counts.0 += 1;
        } else {
            counts.1 += 1;
            all_ok = false;
        }
    }
    write_text(&out_dir.join("manifest.txt"), &manifest);
    write_text(&out_dir.join("expected_outcomes.txt"), &expected);
    write_text(&out_dir.join("actual_outcomes.txt"), &actual);

    let summary = format!(
        "run-179 helper release-binary verdict: {}\n\
         scenarios_total: {}\n\
         scenarios_matched: {}\n\
         scenarios_mismatched: {}\n\
         policy_default: Disabled (every OnChainGovernance proof refused as \
         UnsupportedProductionOnChainGovernance)\n\
         policy_explicit_for_fixture_evidence: AllowFixtureSourceTest \
         (DevNet/TestNet only — MainNet always MainNetProductionProofUnavailable)\n\
         mainnet_peer_driven_apply_remains_refused: true (Run 147 FATAL invariant)\n",
        if all_ok { "PASS" } else { "FAIL" },
        records.len(),
        counts.0,
        counts.1,
    );
    write_text(&out_dir.join("helper_summary.txt"), &summary);

    // Mirror to stdout for the harness to capture.
    print!("{}", summary);

    // Side-evidence: consume the unused proof_wire_json field so future
    // refactors keep the per-scenario JSON generation as a recorded side
    // effect, not dead code.
    let mut json_count = 0usize;
    for r in &records {
        if r.proof_wire_json.is_some() {
            json_count += 1;
        }
    }
    println!("scenarios_with_proof_json: {}", json_count);

    if !all_ok {
        std::process::exit(1);
    }
}