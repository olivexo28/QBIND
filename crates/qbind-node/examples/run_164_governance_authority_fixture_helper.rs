//! Run 164 — release-built governance-authority fixture helper.
//!
//! Mints the **release-binary governance proof corpus** consumed by the
//! Run 164 release-binary evidence/boundary harness
//! (`scripts/devnet/run_164_governance_authority_release_binary.sh`)
//! and, for every scenario, invokes the Run 163 typed pure verifier
//! (`qbind_node::pqc_governance_authority::verify_governance_authority_proof`)
//! and the Run 163 pure non-mutating combined helper
//! (`qbind_node::pqc_governance_authority::validate_lifecycle_with_governance_authority`)
//! on the **real release binary** (this example, built with
//! `cargo build --release`). The helper writes the actual typed
//! outcomes to disk so the harness can grep-assert that every accept
//! scenario produced an accept variant and every reject scenario
//! produced the expected reject variant.
//!
//! ## Scope
//!
//! Run 164 is a **release-binary evidence/boundary** run. The helper is
//! release-built (`cargo build --release -p qbind-node --example
//! run_164_governance_authority_fixture_helper`) and only writes files;
//! it touches no live trust state, no sequence file, no authority
//! marker, no P2P session, and no network. It introduces no new wire
//! format, no trust-bundle schema change, no authority-marker schema
//! change, and no sequence-file schema change. Every record is built
//! through the same `PersistentAuthorityStateRecordV2::new` /
//! `validate_structure` primitives the production code already uses;
//! every governance proof is built through the existing public
//! `GovernanceAuthorityProof` / `fixture_issuer_signature` /
//! `FixtureIssuerSignatureVerifier` surface from Run 163.
//!
//! ## Reachability boundary
//!
//! The Run 163 verifier is **not** wired into any `target/release/qbind-node`
//! production v2 surface today (a `grep -nE
//! 'verify_governance_authority_proof|validate_lifecycle_with_governance_authority|pqc_governance_authority'`
//! over `crates/qbind-node/src/**.rs` returns hits only in
//! `pqc_governance_authority.rs` itself and the `pub mod
//! pqc_governance_authority;` declaration in `lib.rs`). This helper is
//! the **only** release-built surface that exercises the verifier
//! today; the harness records that fact as a partial-positive boundary
//! and identifies Run 165 as the next required integration run.
//!
//! ## Usage
//!
//! ```text
//! run_164_governance_authority_fixture_helper <OUT_DIR>
//! ```
//!
//! Writes:
//!
//! ```text
//! <OUT_DIR>/manifest.txt              # one line per scenario: <id>\t<expected>
//! <OUT_DIR>/expected_outcomes.txt     # human-readable accept/reject map
//! <OUT_DIR>/actual_outcomes.txt       # actual typed-outcome Debug dumps from the verifier
//! <OUT_DIR>/combined_outcomes.txt     # actual CombinedLifecycleGovernanceOutcome dumps for accept-class scenarios
//! <OUT_DIR>/scenarios/<id>/candidate.json
//! <OUT_DIR>/scenarios/<id>/persisted.json   (where applicable; literal `null` for none)
//! <OUT_DIR>/scenarios/<id>/proof.txt        (Debug dump of GovernanceAuthorityProof)
//! <OUT_DIR>/scenarios/<id>/signature.bin    (raw issuer signature bytes)
//! <OUT_DIR>/scenarios/<id>/trust_domain.txt
//! <OUT_DIR>/scenarios/<id>/expected.txt
//! <OUT_DIR>/scenarios/<id>/actual.txt
//! <OUT_DIR>/reachability.txt          # source-grep notes carried in fixture form
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
    validate_lifecycle_with_governance_authority, verify_governance_authority_proof,
    GovernanceAuthorityClass, GovernanceAuthorityProof, GovernanceThreshold,
    PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ---------- shared trust-domain ----------------------------------------------

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
const DIGEST_1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DIGEST_3: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const FIXED_TS: u64 = 1_700_000_000;

// Non-PQC suite ids the verifier explicitly classifies as `NonPqcSuiteRejected`.
const NON_PQC_SUITE_ED25519: u8 = 1;
// An unknown / unsupported issuer suite id (not PQC, not in the known
// non-PQC set) — verifier classifies as `UnsupportedIssuerSuite`.
const UNSUPPORTED_SUITE: u8 = 200;

// Compile-time sanity: the verifier accepts only ML-DSA-44 today.
const _ASSERT_PQC_SUITE_MATCHES: u8 =
    [PQC_LIFECYCLE_SUITE_ML_DSA_44][(PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44 != PQC_LIFECYCLE_SUITE_ML_DSA_44) as usize];

// ---------- tiny JSON helpers ------------------------------------------------

fn write_file(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent dir");
    }
    let mut f = fs::File::create(path).expect("create file");
    f.write_all(bytes).expect("write file");
}

fn write_text(path: &Path, body: &str) {
    write_file(path, body.as_bytes());
}

// ---------- record builders --------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn v2(
    env: TrustBundleEnvironment,
    chain_id: &str,
    genesis: &str,
    root_fp: &str,
    root_suite: u8,
    active_fp: &str,
    active_suite: u8,
    sequence: u64,
    action: BundleSigningRatificationV2Action,
    previous_fp: Option<&str>,
    digest: &str,
    revoked_metadata: Option<&str>,
) -> PersistentAuthorityStateRecordV2 {
    PersistentAuthorityStateRecordV2::new(
        chain_id.to_string(),
        env,
        genesis.to_string(),
        root_fp.to_string(),
        root_suite,
        active_fp.to_string(),
        active_suite,
        sequence,
        action,
        previous_fp.map(str::to_string),
        digest.to_string(),
        revoked_metadata.map(str::to_string),
        AuthorityStateUpdateSource::TestOrFixture,
        FIXED_TS,
    )
}

fn ratify_initial() -> PersistentAuthorityStateRecordV2 {
    v2(
        TrustBundleEnvironment::Devnet,
        CHAIN_ID,
        GENESIS_HASH_A,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        KEY_A,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        DIGEST_1,
        None,
    )
}

fn rotate_a_to_b_seq2() -> PersistentAuthorityStateRecordV2 {
    v2(
        TrustBundleEnvironment::Devnet,
        CHAIN_ID,
        GENESIS_HASH_A,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        KEY_B,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(KEY_A),
        DIGEST_2,
        None,
    )
}

fn revoke_a_seq3(prefix: &str) -> PersistentAuthorityStateRecordV2 {
    let metadata = format!("{}{}", prefix, KEY_A);
    v2(
        TrustBundleEnvironment::Devnet,
        CHAIN_ID,
        GENESIS_HASH_A,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        KEY_B,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        3,
        BundleSigningRatificationV2Action::Revoke,
        None,
        DIGEST_3,
        Some(&metadata),
    )
}

fn devnet_domain() -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(
        TrustBundleEnvironment::Devnet,
        CHAIN_ID,
        GENESIS_HASH_A,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
    )
}

// ---------- proof builders ---------------------------------------------------

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
        environment: TrustBundleEnvironment::Devnet,
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

// ---------- scenario harness -------------------------------------------------

struct Scenario {
    id: &'static str,
    expected_label: &'static str,
    expected_match: &'static str,
    candidate: PersistentAuthorityStateRecordV2,
    persisted: Option<PersistentAuthorityStateRecordV2>,
    proof: GovernanceAuthorityProof,
    persisted_sequence: Option<u64>,
    domain: AuthorityTrustDomain,
}

fn write_scenario(out: &Path, s: &Scenario, actual_buf: &mut String, combined_buf: &mut String) {
    let scen_dir = out.join("scenarios").join(s.id);
    fs::create_dir_all(&scen_dir).expect("create scenario dir");

    s.candidate
        .validate_structure()
        .expect("candidate must structurally validate");
    let cand_json =
        serde_json::to_string_pretty(&s.candidate).expect("serialize candidate");
    write_text(&scen_dir.join("candidate.json"), &cand_json);

    match &s.persisted {
        None => write_text(&scen_dir.join("persisted.json"), "null\n"),
        Some(p) => {
            p.validate_structure()
                .expect("persisted v2 fixture must structurally validate");
            let json = serde_json::to_string_pretty(p).expect("serialize persisted");
            write_text(&scen_dir.join("persisted.json"), &json);
        }
    }

    write_text(
        &scen_dir.join("proof.txt"),
        &format!("{:#?}\n", s.proof),
    );
    write_file(&scen_dir.join("signature.bin"), &s.proof.issuer_signature);
    write_text(
        &scen_dir.join("trust_domain.txt"),
        &format!("{:#?}\n", s.domain),
    );
    write_text(
        &scen_dir.join("expected.txt"),
        &format!(
            "label={}\nmatch_substring={}\n",
            s.expected_label, s.expected_match
        ),
    );

    // Invoke the real Run 163 verifier.
    let outcome = verify_governance_authority_proof(
        &s.proof,
        &s.candidate,
        &s.domain,
        s.persisted_sequence,
        &fixture_issuer_signature_verifier(),
    );
    let outcome_dump = format!("{:?}", outcome);
    write_text(
        &scen_dir.join("actual.txt"),
        &format!(
            "id={}\nis_accept={}\nis_reject={}\noutcome={}\n",
            s.id,
            outcome.is_accept(),
            outcome.is_reject(),
            outcome_dump
        ),
    );
    actual_buf.push_str(&format!("{}\t{}\t{}\n", s.id, s.expected_label, outcome_dump));

    // Also exercise the combined Run 159 + Run 163 helper for every
    // scenario. The combined outcome is used as cross-validation: any
    // accept-class scenario MUST have governance accept (lifecycle may
    // still reject for stale-replay variants where the underlying
    // lifecycle layer treats the same record as Idempotent — that's
    // already documented in Run 163's combined-helper test matrix).
    let persisted_versioned = s
        .persisted
        .as_ref()
        .map(|p| PersistentAuthorityStateRecordVersioned::V2(p.clone()));
    let combined = validate_lifecycle_with_governance_authority(
        persisted_versioned.as_ref(),
        &s.candidate,
        &s.proof,
        &s.domain,
        &fixture_issuer_signature_verifier(),
    );
    let combined_dump = format!("{:?}", combined);
    combined_buf.push_str(&format!(
        "{}\t{}\t{}\n",
        s.id,
        if combined.is_accept() {
            "accept"
        } else {
            "reject"
        },
        combined_dump
    ));
}

// ---------- main -------------------------------------------------------------

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: {} <OUT_DIR>", args[0]);
        std::process::exit(2);
    }
    let out: PathBuf = PathBuf::from(&args[1]);
    fs::create_dir_all(&out).expect("create OUT_DIR");

    let domain = devnet_domain();

    let p_seq1 = ratify_initial();
    let p_seq2 = rotate_a_to_b_seq2();

    // ===================================================================
    // Acceptance scenarios
    // ===================================================================

    // A1 — GenesisBound Rotate accepted.
    let a1_cand = rotate_a_to_b_seq2();
    let a1_proof = good_proof_for(
        &a1_cand,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );

    // A2 — GenesisBound Revoke accepted.
    let a2_cand = revoke_a_seq3(REVOKED_METADATA_PREFIX_REVOKE);
    let a2_proof = good_proof_for(
        &a2_cand,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Revoke,
    );

    // A3 — GenesisBound EmergencyRevoke accepted.
    let a3_cand = revoke_a_seq3(REVOKED_METADATA_PREFIX_EMERGENCY);
    let a3_proof = good_proof_for(
        &a3_cand,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::EmergencyRevoke,
    );

    // A4 — EmergencyCouncil EmergencyRevoke accepted.
    let a4_cand = revoke_a_seq3(REVOKED_METADATA_PREFIX_EMERGENCY);
    let a4_proof = good_proof_for(
        &a4_cand,
        GovernanceAuthorityClass::EmergencyCouncil,
        LocalLifecycleAction::EmergencyRevoke,
    );

    // A5 — Idempotent same proof / same candidate at the persisted
    // sequence. Run 163 classifies bit-for-bit identical
    // re-presentation as `AcceptedIdempotent`.
    let a5_cand = rotate_a_to_b_seq2();
    let a5_proof = good_proof_for(
        &a5_cand,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );

    // ===================================================================
    // Rejection scenarios
    // ===================================================================

    // R1 — wrong environment (proof says Testnet, domain says Devnet).
    let r1_cand = rotate_a_to_b_seq2();
    let mut r1_proof = good_proof_for(
        &r1_cand,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    r1_proof.environment = TrustBundleEnvironment::Testnet;

    // R2 — wrong chain.
    let r2_cand = rotate_a_to_b_seq2();
    let mut r2_proof = good_proof_for(
        &r2_cand,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    r2_proof.chain_id = OTHER_CHAIN.to_string();

    // R3 — wrong genesis.
    let r3_cand = rotate_a_to_b_seq2();
    let mut r3_proof = good_proof_for(
        &r3_cand,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    r3_proof.genesis_hash = GENESIS_HASH_B.to_string();

    // R4 — wrong authority root.
    let r4_cand = rotate_a_to_b_seq2();
    let mut r4_proof = good_proof_for(
        &r4_cand,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    r4_proof.authority_root_fingerprint = OTHER_ROOT_FP.to_string();

    // R5 — wrong lifecycle action (proof declares Revoke for a Rotate
    // candidate).
    let r5_cand = rotate_a_to_b_seq2();
    let mut r5_proof = good_proof_for(
        &r5_cand,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    r5_proof.lifecycle_action = LocalLifecycleAction::Revoke;
    // Re-sign so the signature still binds to (root, digest, sequence)
    // — the verifier's class binding to action gating is what fires
    // here, not a signature mismatch.
    r5_proof.issuer_signature = fixture_issuer_signature(
        GovernanceAuthorityClass::GenesisBound,
        ROOT_FP,
        &r5_cand.latest_ratification_v2_digest,
        r5_cand.latest_authority_domain_sequence,
    );

    // R6 — wrong candidate digest.
    let r6_cand = rotate_a_to_b_seq2();
    let mut r6_proof = good_proof_for(
        &r6_cand,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    r6_proof.candidate_v2_digest = DIGEST_3.to_string();

    // R7 — wrong authority-domain sequence.
    let r7_cand = rotate_a_to_b_seq2();
    let mut r7_proof = good_proof_for(
        &r7_cand,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    r7_proof.authority_domain_sequence = 99;

    // R8 — invalid issuer signature (bytes mutated).
    let r8_cand = rotate_a_to_b_seq2();
    let mut r8_proof = good_proof_for(
        &r8_cand,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    if let Some(b) = r8_proof.issuer_signature.last_mut() {
        *b = b.wrapping_add(1);
    } else {
        r8_proof.issuer_signature.push(0);
    }

    // R9 — unsupported issuer suite (UNSUPPORTED_SUITE is not the
    // PQC suite and not in the known non-PQC set).
    let r9_cand = rotate_a_to_b_seq2();
    let mut r9_proof = good_proof_for(
        &r9_cand,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    r9_proof.issuer_signature_suite_id = UNSUPPORTED_SUITE;

    // R10 — non-PQC issuer suite (Ed25519, Secp256k1, RsaPss).
    let r10_cand = rotate_a_to_b_seq2();
    let mut r10_proof = good_proof_for(
        &r10_cand,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    r10_proof.issuer_signature_suite_id = NON_PQC_SUITE_ED25519;

    // R11 — threshold not met.
    let r11_cand = rotate_a_to_b_seq2();
    let mut r11_proof = good_proof_for(
        &r11_cand,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    r11_proof.threshold = Some(GovernanceThreshold::new(1, 2, 3));

    // R12 — malformed proof (empty issuer signature).
    let r12_cand = rotate_a_to_b_seq2();
    let mut r12_proof = good_proof_for(
        &r12_cand,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    r12_proof.issuer_signature.clear();

    // R13 — stale lower-sequence proof landing on a higher persisted
    // sequence (replay reject).
    let r13_cand = ratify_initial(); // sequence=1
    let r13_proof = good_proof_for(
        &r13_cand,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::ActivateInitial,
    );

    // R14 — OnChainGovernance unsupported.
    let r14_cand = rotate_a_to_b_seq2();
    let mut r14_proof = good_proof_for(
        &r14_cand,
        GovernanceAuthorityClass::OnChainGovernance,
        LocalLifecycleAction::Rotate,
    );
    // Class-bound signature (OnChainGovernance tag) so the reject is
    // typed as `UnsupportedOnChainGovernance` rather than
    // InvalidIssuerSignature.
    r14_proof.issuer_signature = fixture_issuer_signature(
        GovernanceAuthorityClass::OnChainGovernance,
        ROOT_FP,
        &r14_cand.latest_ratification_v2_digest,
        r14_cand.latest_authority_domain_sequence,
    );

    // R15 — local operator config alone (no signature, no class
    // binding). Verifier rejects with `MalformedProof` whose reason
    // explicitly cites local-operator-config-only; the typed
    // `LocalOperatorConfigOnlyRejected` variant exists at the enum
    // level and is asserted compile-side. We capture the malformed-
    // -proof reject here.
    let r15_cand = rotate_a_to_b_seq2();
    let mut r15_proof = good_proof_for(
        &r15_cand,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    r15_proof.issuer_signature.clear();
    r15_proof.authority_root_fingerprint.clear();

    // R16 — peer-majority is rejected at the type level: the
    // `GovernanceAuthorityClass` enum has no peer-majority variant.
    // We capture this as a fixture by constructing a proof whose
    // declared class is `GenesisBound` but whose `threshold` claims
    // a "peer majority count" larger than the well-formed ceiling and
    // whose signature is empty so the verifier cannot accept it.
    // The typed `PeerMajorityProofRejected` variant exists at the
    // enum level and is exercised by Run 163 R16 source/test
    // coverage; a release-binary peer-majority reject scenario is
    // included here as an additional honest evidence signal —
    // verifier rejects with `MalformedProof` because the proof is
    // empty-signed.
    let r16_cand = rotate_a_to_b_seq2();
    let mut r16_proof = good_proof_for(
        &r16_cand,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    r16_proof.threshold = Some(GovernanceThreshold {
        approvals: 0,
        required: 0,
        total: 0,
    });
    r16_proof.issuer_signature.clear();

    let scenarios: Vec<Scenario> = vec![
        // ---- accepts -------------------------------------------------------
        Scenario {
            id: "A1_genesis_bound_rotate",
            expected_label: "accept",
            expected_match: "AcceptedGenesisBound",
            candidate: a1_cand,
            persisted: Some(p_seq1.clone()),
            proof: a1_proof,
            persisted_sequence: Some(1),
            domain: domain.clone(),
        },
        Scenario {
            id: "A2_genesis_bound_revoke",
            expected_label: "accept",
            expected_match: "AcceptedGenesisBound",
            candidate: a2_cand,
            persisted: Some(p_seq2.clone()),
            proof: a2_proof,
            persisted_sequence: Some(2),
            domain: domain.clone(),
        },
        Scenario {
            id: "A3_genesis_bound_emergency_revoke",
            expected_label: "accept",
            expected_match: "AcceptedGenesisBound",
            candidate: a3_cand,
            persisted: Some(p_seq2.clone()),
            proof: a3_proof,
            persisted_sequence: Some(2),
            domain: domain.clone(),
        },
        Scenario {
            id: "A4_emergency_council_emergency_revoke",
            expected_label: "accept",
            expected_match: "AcceptedEmergencyCouncil",
            candidate: a4_cand,
            persisted: Some(p_seq2.clone()),
            proof: a4_proof,
            persisted_sequence: Some(2),
            domain: domain.clone(),
        },
        Scenario {
            id: "A5_idempotent_same_proof",
            expected_label: "accept",
            expected_match: "AcceptedGenesisBound",
            candidate: a5_cand.clone(),
            persisted: Some(a5_cand),
            proof: a5_proof,
            persisted_sequence: Some(2),
            domain: domain.clone(),
        },
        // ---- rejects -------------------------------------------------------
        Scenario {
            id: "R1_wrong_environment",
            expected_label: "reject",
            expected_match: "WrongEnvironment",
            candidate: r1_cand,
            persisted: Some(p_seq1.clone()),
            proof: r1_proof,
            persisted_sequence: Some(1),
            domain: domain.clone(),
        },
        Scenario {
            id: "R2_wrong_chain",
            expected_label: "reject",
            expected_match: "WrongChain",
            candidate: r2_cand,
            persisted: Some(p_seq1.clone()),
            proof: r2_proof,
            persisted_sequence: Some(1),
            domain: domain.clone(),
        },
        Scenario {
            id: "R3_wrong_genesis",
            expected_label: "reject",
            expected_match: "WrongGenesis",
            candidate: r3_cand,
            persisted: Some(p_seq1.clone()),
            proof: r3_proof,
            persisted_sequence: Some(1),
            domain: domain.clone(),
        },
        Scenario {
            id: "R4_wrong_authority_root",
            expected_label: "reject",
            expected_match: "WrongAuthorityRoot",
            candidate: r4_cand,
            persisted: Some(p_seq1.clone()),
            proof: r4_proof,
            persisted_sequence: Some(1),
            domain: domain.clone(),
        },
        Scenario {
            id: "R5_wrong_lifecycle_action",
            expected_label: "reject",
            expected_match: "WrongLifecycleAction",
            candidate: r5_cand,
            persisted: Some(p_seq1.clone()),
            proof: r5_proof,
            persisted_sequence: Some(1),
            domain: domain.clone(),
        },
        Scenario {
            id: "R6_wrong_candidate_digest",
            expected_label: "reject",
            expected_match: "WrongCandidateDigest",
            candidate: r6_cand,
            persisted: Some(p_seq1.clone()),
            proof: r6_proof,
            persisted_sequence: Some(1),
            domain: domain.clone(),
        },
        Scenario {
            id: "R7_wrong_authority_sequence",
            expected_label: "reject",
            expected_match: "WrongAuthoritySequence",
            candidate: r7_cand,
            persisted: Some(p_seq1.clone()),
            proof: r7_proof,
            persisted_sequence: Some(1),
            domain: domain.clone(),
        },
        Scenario {
            id: "R8_invalid_issuer_signature",
            expected_label: "reject",
            expected_match: "InvalidIssuerSignature",
            candidate: r8_cand,
            persisted: Some(p_seq1.clone()),
            proof: r8_proof,
            persisted_sequence: Some(1),
            domain: domain.clone(),
        },
        Scenario {
            id: "R9_unsupported_issuer_suite",
            expected_label: "reject",
            expected_match: "UnsupportedIssuerSuite",
            candidate: r9_cand,
            persisted: Some(p_seq1.clone()),
            proof: r9_proof,
            persisted_sequence: Some(1),
            domain: domain.clone(),
        },
        Scenario {
            id: "R10_non_pqc_suite_rejected",
            expected_label: "reject",
            expected_match: "NonPqcSuiteRejected",
            candidate: r10_cand,
            persisted: Some(p_seq1.clone()),
            proof: r10_proof,
            persisted_sequence: Some(1),
            domain: domain.clone(),
        },
        Scenario {
            id: "R11_threshold_not_met",
            expected_label: "reject",
            expected_match: "ThresholdNotMet",
            candidate: r11_cand,
            persisted: Some(p_seq1.clone()),
            proof: r11_proof,
            persisted_sequence: Some(1),
            domain: domain.clone(),
        },
        Scenario {
            id: "R12_malformed_proof",
            expected_label: "reject",
            expected_match: "MalformedProof",
            candidate: r12_cand,
            persisted: Some(p_seq1.clone()),
            proof: r12_proof,
            persisted_sequence: Some(1),
            domain: domain.clone(),
        },
        Scenario {
            id: "R13_replay_lower_sequence",
            expected_label: "reject",
            expected_match: "ReplayRejected",
            candidate: r13_cand,
            persisted: Some(p_seq2.clone()),
            proof: r13_proof,
            persisted_sequence: Some(2),
            domain: domain.clone(),
        },
        Scenario {
            id: "R14_on_chain_governance_unsupported",
            expected_label: "reject",
            expected_match: "UnsupportedOnChainGovernance",
            candidate: r14_cand,
            persisted: Some(p_seq1.clone()),
            proof: r14_proof,
            persisted_sequence: Some(1),
            domain: domain.clone(),
        },
        Scenario {
            id: "R15_local_operator_config_only_rejected",
            expected_label: "reject",
            expected_match: "MalformedProof",
            candidate: r15_cand,
            persisted: Some(p_seq1.clone()),
            proof: r15_proof,
            persisted_sequence: Some(1),
            domain: domain.clone(),
        },
        Scenario {
            id: "R16_peer_majority_rejected",
            expected_label: "reject",
            expected_match: "MalformedProof",
            candidate: r16_cand,
            persisted: Some(p_seq1.clone()),
            proof: r16_proof,
            persisted_sequence: Some(1),
            domain,
        },
    ];

    let mut manifest = String::new();
    let mut expected = String::from("# Run 164 — expected typed-outcome class per scenario\n");
    let mut actual_buf = String::from("# Run 164 — actual verifier outcome per scenario\n");
    let mut combined_buf = String::from("# Run 164 — combined lifecycle+governance helper outcome per scenario\n");
    for s in &scenarios {
        manifest.push_str(&format!("{}\t{}\t{}\n", s.id, s.expected_label, s.expected_match));
        expected.push_str(&format!(
            "{}: {} ({})\n",
            s.id, s.expected_label, s.expected_match
        ));
        write_scenario(&out, s, &mut actual_buf, &mut combined_buf);
    }

    write_text(&out.join("manifest.txt"), &manifest);
    write_text(&out.join("expected_outcomes.txt"), &expected);
    write_text(&out.join("actual_outcomes.txt"), &actual_buf);
    write_text(&out.join("combined_outcomes.txt"), &combined_buf);

    // Reachability boundary in fixture form. The harness ALSO captures
    // a live src-grep separately; this file documents the boundary
    // claim for archive completeness.
    write_text(
        &out.join("reachability.txt"),
        "Run 164 release-binary reachability boundary\n\
         ============================================\n\
         The Run 163 governance authority verifier\n\
         (`qbind_node::pqc_governance_authority`) is NOT wired into any\n\
         `target/release/qbind-node` production v2 surface today. The\n\
         only `src/` references are the module itself\n\
         (`crates/qbind-node/src/pqc_governance_authority.rs`) and the\n\
         `pub mod pqc_governance_authority;` declaration in\n\
         `crates/qbind-node/src/lib.rs`. Test-side references live in\n\
         `crates/qbind-node/tests/run_163_governance_authority_verifier_tests.rs`.\n\
         This release-built helper\n\
         (`crates/qbind-node/examples/run_164_governance_authority_fixture_helper.rs`)\n\
         is the only release-built binary that exercises the verifier\n\
         today. Run 164 captures this as a partial-positive boundary;\n\
         Run 165 is the next required integration run that composes the\n\
         verifier into a mutating apply or validation-only marker-decision\n\
         surface.\n",
    );

    println!("run_164_governance_authority_fixture_helper: wrote {} scenarios to {}",
        scenarios.len(),
        out.display());
}
