//! Run 160 — release-built lifecycle fixture helper.
//!
//! Mints the **release-binary lifecycle fixture corpus** consumed by the
//! Run 160 release-binary boundary harness
//! (`scripts/devnet/run_160_authority_lifecycle_release_binary.sh`).
//!
//! The corpus is a set of `PersistentAuthorityStateRecordVersioned` /
//! `PersistentAuthorityStateRecordV2` JSON files that exactly cover the
//! Run 160 acceptance matrix (A1–A6) and rejection matrix (R1–R14)
//! against the Run 159 typed pure validator
//! (`qbind_node::pqc_authority_lifecycle::validate_v2_lifecycle_transition`).
//!
//! ## Scope
//!
//! Run 160 is a release-binary **evidence/boundary** run. The helper is
//! release-built (`cargo build --release -p qbind-node --example
//! run_160_authority_lifecycle_fixture_helper`) and only writes files;
//! it touches no live trust state, no sequence file, no authority
//! marker, no P2P session, and no network. It introduces no new wire
//! format, no trust-bundle schema change, no authority-marker schema
//! change, and no sequence-file schema change. Every record is built
//! through the same `PersistentAuthorityStateRecordV2::new` /
//! `validate_structure` primitives the production code already uses.
//!
//! ## Usage
//!
//! ```text
//! run_160_authority_lifecycle_fixture_helper <OUT_DIR>
//! ```
//!
//! Writes:
//!
//! ```text
//! <OUT_DIR>/manifest.txt
//! <OUT_DIR>/expected_outcomes.txt
//! <OUT_DIR>/persisted/
//!   none.json                # literal JSON `null` (no prior marker)
//!   seq1_initial.json        # Ratify@seq=1, KEY_A active
//!   seq2_rotated.json        # Rotate@seq=2, KEY_B active, prev=KEY_A
//!   seq3_revoke_b.json       # Revoke@seq=3 (sub-class 01), active=KEY_B, target=KEY_B
//!   seq3_retire_b.json       # Revoke@seq=3 (sub-class 02), active=KEY_B, target=KEY_A
//!   seq3_emergency_b.json    # Revoke@seq=3 (sub-class 03), active=KEY_B, target=KEY_B
//!   seq1_v1.json             # legacy v1 marker (for V1-persisted-V2-candidate)
//! <OUT_DIR>/candidates/
//!   A1_initial.json
//!   A2_rotate.json
//!   A3_retire.json
//!   A4_revoke.json
//!   A5_emergency_revoke.json
//!   A6_idempotent_initial.json
//!   R1_lower_seq.json
//!   R2_same_seq_diff_digest.json
//!   R3_wrong_environment.json
//!   R4_wrong_chain.json
//!   R5_wrong_genesis.json
//!   R6_wrong_authority_root.json
//!   R7_wrong_previous_key.json
//!   R8_revoked_key_reuse.json     (paired with persisted/seq3_revoke_b.json)
//!   R9_retired_key_reuse.json     (paired with persisted/seq3_retire_b.json)
//!   R10_emergency_replay.json     (paired with persisted/seq3_emergency_b.json)
//!   R11_malformed_metadata.json
//!   R12_non_pqc_suite.json
//!   R13_unsupported_action.json   (Rotate against persisted None)
//!   R14_v1_persisted_v2_candidate.json (paired with persisted/seq1_v1.json)
//! ```
//!
//! ## What this helper does NOT do
//!
//! * It does NOT call `validate_v2_lifecycle_transition`. The validator
//!   is invoked by the Run 159 test suite running on release-built
//!   test binaries; the Run 160 harness records that test outcome.
//! * It does NOT mint signing material, KEM material, or wire envelopes.
//!   The Run 159 validator is a typed pure transition validator over
//!   already-deserialised marker records; release-binary lifecycle
//!   evidence does not require wire-signed material.
//! * It does NOT introduce or wire any production runtime caller.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use qbind_ledger::BundleSigningRatificationV2Action;
use qbind_node::pqc_authority_lifecycle::{
    PQC_LIFECYCLE_SUITE_ML_DSA_44, REVOKED_METADATA_PREFIX_EMERGENCY,
    REVOKED_METADATA_PREFIX_RETIRE, REVOKED_METADATA_PREFIX_REVOKE,
};
use qbind_node::pqc_authority_state::{
    AuthorityStateUpdateSource, PersistentAuthorityStateRecord,
    PersistentAuthorityStateRecordV2, PersistentAuthorityStateRecordVersioned,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ---------- shared trust-domain ----------

const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const KEY_C: &str = "cccccccccccccccccccccccccccccccccccccccc";
const ROOT_FP: &str = "1111111111111111111111111111111111111111";
const ROOT_FP_OTHER: &str = "2222222222222222222222222222222222222222";
const CHAIN_ID: &str = "0000000000000001";
const CHAIN_ID_OTHER: &str = "00000000000000ff";
const GENESIS_HASH: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GENESIS_HASH_OTHER: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DIGEST_3: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const DIGEST_4: &str = "4444444444444444444444444444444444444444444444444444444444444444";
const FIXED_TS: u64 = 1_700_000_000;

// Non-PQC suite id used in R12 (anything != PQC_LIFECYCLE_SUITE_ML_DSA_44).
const NON_PQC_SUITE: u8 = 0;
// Unsupported sub-class prefix used in R11.
const BAD_PREFIX: &str = "ff";

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
        GENESIS_HASH,
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

fn rotate_to_b_seq2() -> PersistentAuthorityStateRecordV2 {
    v2(
        TrustBundleEnvironment::Devnet,
        CHAIN_ID,
        GENESIS_HASH,
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

fn revoke_target(active: &str, target: &str, sequence: u64, prefix: &str, digest: &str)
    -> PersistentAuthorityStateRecordV2
{
    let metadata = format!("{}{}", prefix, target);
    v2(
        TrustBundleEnvironment::Devnet,
        CHAIN_ID,
        GENESIS_HASH,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        active,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        sequence,
        BundleSigningRatificationV2Action::Revoke,
        None,
        digest,
        Some(&metadata),
    )
}

fn write_versioned(path: &Path, rec: &PersistentAuthorityStateRecordVersioned) {
    rec.validate_structure_loose();
    let json = match rec {
        PersistentAuthorityStateRecordVersioned::V1(r) => {
            serde_json::to_string_pretty(r).expect("serialize v1 record")
        }
        PersistentAuthorityStateRecordVersioned::V2(r) => {
            serde_json::to_string_pretty(r).expect("serialize v2 record")
        }
    };
    write_file(path, json.as_bytes());
}

fn write_v2(path: &Path, rec: &PersistentAuthorityStateRecordV2) {
    rec.validate_structure()
        .expect("v2 fixture must structurally validate");
    let json = serde_json::to_string_pretty(rec).expect("serialize v2 record");
    write_file(path, json.as_bytes());
}

#[inline]
fn write_v2_validated(path: &Path, rec: &PersistentAuthorityStateRecordV2) {
    write_v2(path, rec);
}

fn write_file(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("mkdir -p");
    }
    let mut f = fs::File::create(path).expect("create fixture file");
    f.write_all(bytes).expect("write fixture file");
    f.write_all(b"\n").expect("trailing newline");
}

fn write_text(path: &Path, body: &str) {
    write_file(path, body.as_bytes());
}

// Minimal helper trait so the helper compiles regardless of whether the
// versioned wrapper exposes its own validator (it does, but we only need
// to ensure the inner record's `validate_structure` ran via `new`/explicit
// re-construction; this is a no-op for already-valid inputs).
trait ValidateStructureLoose {
    fn validate_structure_loose(&self);
}
impl ValidateStructureLoose for PersistentAuthorityStateRecordVersioned {
    fn validate_structure_loose(&self) {
        match self {
            PersistentAuthorityStateRecordVersioned::V1(r) => {
                r.validate_structure().expect("v1 fixture must validate");
            }
            PersistentAuthorityStateRecordVersioned::V2(r) => {
                r.validate_structure().expect("v2 fixture must validate");
            }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: {} <OUT_DIR>", args[0]);
        std::process::exit(2);
    }
    let out: PathBuf = PathBuf::from(&args[1]);
    fs::create_dir_all(&out).expect("create OUT_DIR");

    // ===== Persisted markers =================================================

    // None — represented as JSON null so the harness can `cat` it as
    // an explicit "no prior marker" fixture.
    write_text(&out.join("persisted").join("none.json"), "null\n");

    let p_seq1 = ratify_initial();
    write_versioned(
        &out.join("persisted").join("seq1_initial.json"),
        &PersistentAuthorityStateRecordVersioned::V2(p_seq1.clone()),
    );

    let p_seq2 = rotate_to_b_seq2();
    write_versioned(
        &out.join("persisted").join("seq2_rotated.json"),
        &PersistentAuthorityStateRecordVersioned::V2(p_seq2.clone()),
    );

    // Persisted Revoke@seq=3 marking KEY_B as revoked (active stays B).
    let p_seq3_revoke_b = revoke_target(KEY_B, KEY_B, 3, REVOKED_METADATA_PREFIX_REVOKE, DIGEST_3);
    write_versioned(
        &out.join("persisted").join("seq3_revoke_b.json"),
        &PersistentAuthorityStateRecordVersioned::V2(p_seq3_revoke_b),
    );

    // Persisted Retire@seq=3 marking KEY_A as retired (active stays B,
    // matches the Rotate@seq=2 audit trail).
    let p_seq3_retire_a = revoke_target(KEY_B, KEY_A, 3, REVOKED_METADATA_PREFIX_RETIRE, DIGEST_3);
    write_versioned(
        &out.join("persisted").join("seq3_retire_b.json"),
        &PersistentAuthorityStateRecordVersioned::V2(p_seq3_retire_a),
    );

    // Persisted EmergencyRevoke@seq=3 marking KEY_B (active stays B).
    let p_seq3_emergency_b = revoke_target(
        KEY_B,
        KEY_B,
        3,
        REVOKED_METADATA_PREFIX_EMERGENCY,
        DIGEST_3,
    );
    write_versioned(
        &out.join("persisted").join("seq3_emergency_b.json"),
        &PersistentAuthorityStateRecordVersioned::V2(p_seq3_emergency_b),
    );

    // Legacy v1 persisted marker (used by R14: V1-persisted with V2-candidate).
    let p_v1 = PersistentAuthorityStateRecord::new(
        /*chain_id_hex*/ CHAIN_ID.to_string(),
        /*environment*/ TrustBundleEnvironment::Devnet,
        /*genesis_hash_hex*/ GENESIS_HASH.to_string(),
        /*authority_policy_version*/ 1,
        /*authority_sequence*/ 1,
        /*authority_epoch*/ Some(1),
        /*authority_root_fingerprint*/ ROOT_FP.to_string(),
        /*ratified_bundle_signing_key_fingerprint*/ KEY_A.to_string(),
        /*ratification_object_hash*/ DIGEST_1.to_string(),
        /*last_update_source*/ AuthorityStateUpdateSource::TestOrFixture,
        /*updated_at_unix_secs*/ FIXED_TS,
    );
    write_versioned(
        &out.join("persisted").join("seq1_v1.json"),
        &PersistentAuthorityStateRecordVersioned::V1(p_v1),
    );

    // ===== Accept candidates =================================================

    // A1 — ActivateInitial: same as p_seq1, paired with persisted/none.json.
    write_v2_validated(&out.join("candidates").join("A1_initial.json"), &p_seq1);

    // A2 — Rotate@seq=2 paired with persisted/seq1_initial.json.
    write_v2_validated(&out.join("candidates").join("A2_rotate.json"), &p_seq2);

    // A3 — Retire candidate: Revoke@seq=3 sub-class 02 retiring KEY_A,
    // paired with persisted/seq2_rotated.json. Active stays at KEY_B
    // (audit-only transition — the validator forbids changing the
    // active key on a Retire).
    let a3_retire = revoke_target(KEY_B, KEY_A, 3, REVOKED_METADATA_PREFIX_RETIRE, DIGEST_3);
    write_v2_validated(&out.join("candidates").join("A3_retire.json"), &a3_retire);

    // A4 — Revoke candidate: Revoke@seq=3 sub-class 01 revoking KEY_A,
    // paired with persisted/seq2_rotated.json. Active stays at KEY_B.
    let a4_revoke = revoke_target(KEY_B, KEY_A, 3, REVOKED_METADATA_PREFIX_REVOKE, DIGEST_3);
    write_v2_validated(&out.join("candidates").join("A4_revoke.json"), &a4_revoke);

    // A5 — EmergencyRevoke candidate: Revoke@seq=3 sub-class 03 revoking
    // KEY_A, paired with persisted/seq2_rotated.json.
    let a5_emergency = revoke_target(KEY_B, KEY_A, 3, REVOKED_METADATA_PREFIX_EMERGENCY, DIGEST_3);
    write_v2(
        &out.join("candidates").join("A5_emergency_revoke.json"),
        &a5_emergency,
    );

    // A6 — Idempotent: same record as p_seq1, paired with
    // persisted/seq1_initial.json. Validator returns Idempotent { sequence: 1 }.
    write_v2(
        &out.join("candidates").join("A6_idempotent_initial.json"),
        &p_seq1,
    );

    // ===== Reject candidates =================================================

    // R1 — lower-sequence candidate paired with persisted/seq2_rotated.json.
    let r1 = v2(
        TrustBundleEnvironment::Devnet,
        CHAIN_ID,
        GENESIS_HASH,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        KEY_A,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        DIGEST_4,
        None,
    );
    write_v2_validated(&out.join("candidates").join("R1_lower_seq.json"), &r1);

    // R2 — same sequence different digest, paired with persisted/seq2_rotated.json.
    let r2 = v2(
        TrustBundleEnvironment::Devnet,
        CHAIN_ID,
        GENESIS_HASH,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        KEY_C,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(KEY_A),
        DIGEST_4,
        None,
    );
    write_v2(
        &out.join("candidates").join("R2_same_seq_diff_digest.json"),
        &r2,
    );

    // R3 — wrong environment (TestNet candidate against DevNet trust domain),
    // paired with persisted/none.json.
    let r3 = v2(
        TrustBundleEnvironment::Testnet,
        CHAIN_ID,
        GENESIS_HASH,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        KEY_A,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        DIGEST_1,
        None,
    );
    write_v2_validated(&out.join("candidates").join("R3_wrong_environment.json"), &r3);

    // R4 — wrong chain.
    let r4 = v2(
        TrustBundleEnvironment::Devnet,
        CHAIN_ID_OTHER,
        GENESIS_HASH,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        KEY_A,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        DIGEST_1,
        None,
    );
    write_v2_validated(&out.join("candidates").join("R4_wrong_chain.json"), &r4);

    // R5 — wrong genesis.
    let r5 = v2(
        TrustBundleEnvironment::Devnet,
        CHAIN_ID,
        GENESIS_HASH_OTHER,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        KEY_A,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        DIGEST_1,
        None,
    );
    write_v2_validated(&out.join("candidates").join("R5_wrong_genesis.json"), &r5);

    // R6 — wrong authority root.
    let r6 = v2(
        TrustBundleEnvironment::Devnet,
        CHAIN_ID,
        GENESIS_HASH,
        ROOT_FP_OTHER,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        KEY_A,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        DIGEST_1,
        None,
    );
    write_v2(
        &out.join("candidates").join("R6_wrong_authority_root.json"),
        &r6,
    );

    // R7 — wrong previous-key fingerprint on a Rotate, paired with
    // persisted/seq1_initial.json.
    let r7 = v2(
        TrustBundleEnvironment::Devnet,
        CHAIN_ID,
        GENESIS_HASH,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        KEY_B,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(KEY_C), // wrong: persisted active is KEY_A
        DIGEST_2,
        None,
    );
    write_v2(
        &out.join("candidates").join("R7_wrong_previous_key.json"),
        &r7,
    );

    // R8 — revoked key reuse: candidate Rotate@seq=4 making revoked KEY_B
    // active again, paired with persisted/seq3_revoke_b.json. Use KEY_C
    // as cosmetic prev so structural validation passes (rotate requires
    // prev != active); the validator rejects on revoked-active-key reuse
    // before checking previous-key match.
    let r8 = v2(
        TrustBundleEnvironment::Devnet,
        CHAIN_ID,
        GENESIS_HASH,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        KEY_B,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        4,
        BundleSigningRatificationV2Action::Rotate,
        Some(KEY_C),
        DIGEST_4,
        None,
    );
    write_v2_validated(&out.join("candidates").join("R8_revoked_key_reuse.json"), &r8);

    // R9 — retired key reuse: candidate Rotate@seq=4 making retired KEY_A
    // active again, paired with persisted/seq3_retire_b.json.
    let r9 = v2(
        TrustBundleEnvironment::Devnet,
        CHAIN_ID,
        GENESIS_HASH,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        KEY_A,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        4,
        BundleSigningRatificationV2Action::Rotate,
        Some(KEY_C),
        DIGEST_4,
        None,
    );
    write_v2_validated(&out.join("candidates").join("R9_retired_key_reuse.json"), &r9);

    // R10 — emergency-revoke replay: same-sequence-different-digest replay
    // of persisted/seq3_emergency_b.json.
    let r10 = revoke_target(KEY_B, KEY_B, 3, REVOKED_METADATA_PREFIX_EMERGENCY, DIGEST_4);
    write_v2(
        &out.join("candidates").join("R10_emergency_replay.json"),
        &r10,
    );

    // R11 — malformed revoked metadata (unknown sub-class prefix).
    let r11 = revoke_target(KEY_A, KEY_A, 2, BAD_PREFIX, DIGEST_2);
    write_v2(
        &out.join("candidates").join("R11_malformed_metadata.json"),
        &r11,
    );

    // R12 — non-PQC suite for the active bundle-signing key.
    let r12 = v2(
        TrustBundleEnvironment::Devnet,
        CHAIN_ID,
        GENESIS_HASH,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        KEY_A,
        NON_PQC_SUITE,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        DIGEST_1,
        None,
    );
    write_v2_validated(&out.join("candidates").join("R12_non_pqc_suite.json"), &r12);

    // R13 — unsupported lifecycle action against persisted/none.json
    // (Rotate at first-write is rejected as UnsupportedLifecycleActionRejected).
    let r13 = v2(
        TrustBundleEnvironment::Devnet,
        CHAIN_ID,
        GENESIS_HASH,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        KEY_B,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        1,
        BundleSigningRatificationV2Action::Rotate,
        Some(KEY_A),
        DIGEST_1,
        None,
    );
    write_v2(
        &out.join("candidates").join("R13_unsupported_action.json"),
        &r13,
    );

    // R14 — V1-persisted / V2-candidate refusal: any structurally valid
    // V2 candidate paired with persisted/seq1_v1.json.
    write_v2(
        &out.join("candidates").join("R14_v1_persisted_v2_candidate.json"),
        &p_seq1,
    );

    // ===== Manifest + expected outcomes =====================================

    let manifest = r#"# Run 160 release-binary lifecycle fixture corpus
# Each line: <persisted-marker-relpath>  <candidate-relpath>  <expected-outcome-tag>

persisted/none.json                candidates/A1_initial.json                  InitialActivationAccepted
persisted/seq1_initial.json        candidates/A2_rotate.json                   RotationAccepted
persisted/seq2_rotated.json        candidates/A3_retire.json                   RetirementAccepted
persisted/seq2_rotated.json        candidates/A4_revoke.json                   RevocationAccepted
persisted/seq2_rotated.json        candidates/A5_emergency_revoke.json         EmergencyRevocationAccepted
persisted/seq1_initial.json        candidates/A6_idempotent_initial.json       Idempotent

persisted/seq2_rotated.json        candidates/R1_lower_seq.json                LowerSequenceRejected
persisted/seq2_rotated.json        candidates/R2_same_seq_diff_digest.json     SameSequenceConflictingDigestRejected
persisted/none.json                candidates/R3_wrong_environment.json        WrongEnvironmentRejected
persisted/none.json                candidates/R4_wrong_chain.json              WrongChainRejected
persisted/none.json                candidates/R5_wrong_genesis.json            WrongGenesisRejected
persisted/none.json                candidates/R6_wrong_authority_root.json     WrongAuthorityRootRejected
persisted/seq1_initial.json        candidates/R7_wrong_previous_key.json       WrongPreviousKeyRejected
persisted/seq3_revoke_b.json       candidates/R8_revoked_key_reuse.json        RevokedKeyReuseRejected
persisted/seq3_retire_b.json       candidates/R9_retired_key_reuse.json        RetiredKeyReuseRejected
persisted/seq3_emergency_b.json    candidates/R10_emergency_replay.json        SameSequenceConflictingDigestRejected
persisted/seq1_initial.json        candidates/R11_malformed_metadata.json      MalformedRevokedMetadataRejected
persisted/none.json                candidates/R12_non_pqc_suite.json           NonPqcSuiteRejected
persisted/none.json                candidates/R13_unsupported_action.json      UnsupportedLifecycleActionRejected
persisted/seq1_v1.json             candidates/R14_v1_persisted_v2_candidate.json V1PersistedV2CandidateNotSupportedHere
"#;
    write_text(&out.join("manifest.txt"), manifest);

    // expected_outcomes.txt is a flat list keyed by candidate basename for
    // easy `grep` from the harness.
    let expected = r#"# Run 160 expected validator outcomes (Run 159 typed pure validator).
A1_initial.json                  InitialActivationAccepted
A2_rotate.json                   RotationAccepted
A3_retire.json                   RetirementAccepted
A4_revoke.json                   RevocationAccepted
A5_emergency_revoke.json         EmergencyRevocationAccepted
A6_idempotent_initial.json       Idempotent
R1_lower_seq.json                LowerSequenceRejected
R2_same_seq_diff_digest.json     SameSequenceConflictingDigestRejected
R3_wrong_environment.json        WrongEnvironmentRejected
R4_wrong_chain.json              WrongChainRejected
R5_wrong_genesis.json            WrongGenesisRejected
R6_wrong_authority_root.json     WrongAuthorityRootRejected
R7_wrong_previous_key.json       WrongPreviousKeyRejected
R8_revoked_key_reuse.json        RevokedKeyReuseRejected
R9_retired_key_reuse.json        RetiredKeyReuseRejected
R10_emergency_replay.json        SameSequenceConflictingDigestRejected
R11_malformed_metadata.json      MalformedRevokedMetadataRejected
R12_non_pqc_suite.json           NonPqcSuiteRejected
R13_unsupported_action.json      UnsupportedLifecycleActionRejected
R14_v1_persisted_v2_candidate.json V1PersistedV2CandidateNotSupportedHere
"#;
    write_text(&out.join("expected_outcomes.txt"), expected);

    println!(
        "run_160_authority_lifecycle_fixture_helper: minted lifecycle fixture corpus at {}",
        out.display()
    );
}
