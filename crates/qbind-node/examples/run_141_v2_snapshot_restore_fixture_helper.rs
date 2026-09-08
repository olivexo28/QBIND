//! Run 141 evidence-only fixture helper for the release-binary
//! snapshot/restore v2 authority-marker parity scenarios (Run 140 source
//! wiring; Run 141 release-binary evidence).
//!
//! This helper mints an ephemeral DevNet genesis with the Run 101
//! `genesis_authority` block, computes the canonical Run 101 genesis
//! hash, builds the snapshot directories required by the
//! `task/RUN_141_TASK.txt` scenario matrix using the canonical
//! `StateSnapshotter::create_snapshot` API plus the additive Run 140
//! `AuthorityStateSnapshotMetaV2` block, and emits matching /
//! conflicting / corrupt local authority-marker JSON fixtures plus a
//! plain-text shell-sourceable manifest the release-binary harness
//! consumes.
//!
//! Run 141 is evidence-only. This helper does NOT modify production
//! runtime code, does NOT introduce signing-key rotation / revocation
//! lifecycle, does NOT change KMS/HSM custody, governance, wire format,
//! or CLI/metric surfaces. It is an `examples/` target only and never
//! participates in any production binary path.
//!
//! Layout written under `<outdir>`:
//!
//! ```text
//! <outdir>/
//! ├── genesis.json                       # DevNet genesis with Run 101 authority block
//! ├── expected-genesis-hash.txt          # `0x` + 64 lowercase-hex chars
//! ├── manifest.env                       # KEY=VALUE shell-sourceable manifest
//! ├── snapshots/
//! │   ├── snap-v2-only/                  # B3 snapshot, only `authority_state_v2`
//! │   ├── snap-v2-higher-seq/            # B3 snapshot, v2 with strictly higher sequence
//! │   ├── snap-v2-lower-seq/             # B3 snapshot, v2 with strictly lower sequence
//! │   ├── snap-v2-same-seq-diff-digest/  # B3 snapshot, same seq, different ratification digest
//! │   ├── snap-v2-wrong-genesis/         # B3 snapshot, v2 with mismatched genesis_hash
//! │   ├── snap-v2-wrong-environment/     # B3 snapshot, v2 with mismatched environment
//! │   ├── snap-v2-wrong-chain/           # B3 snapshot, v2 with mismatched chain_id_hex
//! │   ├── snap-v2-wrong-authority-root/  # B3 snapshot, v2 with different authority root fingerprint
//! │   ├── snap-v2-and-v1-ambiguous/      # B3 snapshot, BOTH `authority_state` and `authority_state_v2`
//! │   ├── snap-v1-only/                  # B3 snapshot, only legacy v1 `authority_state`
//! │   └── snap-legacy-no-marker/         # B3 snapshot, no authority block at all (Run 124 baseline)
//! └── markers/
//!     ├── matching-v2.json               # PersistentAuthorityStateRecordV2 matching snap-v2-only
//!     ├── matching-v1.json               # PersistentAuthorityStateRecord (v1) matching snap-v1-only
//!     └── corrupt.bin                    # non-JSON bytes (RejectLocalMarkerCorrupt fixture)
//! ```
//!
//! Notes:
//!
//! * The trust-domain triple `(chain_id_hex, environment,
//!   genesis_hash_hex)` is identical across all v2 markers (snapshot +
//!   local) except for the explicitly-mismatching `snap-v2-wrong-*`
//!   variants. The matching genesis hash is the canonical Run 101 hash
//!   of the freshly minted DevNet `genesis.json`, exactly as the
//!   `target/release/qbind-node` binary computes it at startup when
//!   `--genesis-path` is supplied with `--env devnet`.
//! * The local v2 marker is at `latest_authority_domain_sequence = 5`
//!   so the harness can construct:
//!     * `snap-v2-only`              → seq=5, same digest         → A2 accept
//!     * `snap-v2-higher-seq`        → seq=10, new digest         → A3 accept
//!     * `snap-v2-lower-seq`         → seq=2, fresh digest         → R2 reject
//!     * `snap-v2-same-seq-diff-digest` → seq=5, different digest → R3 reject
//!     * `snap-v2-wrong-authority-root` → seq=5, different root   → R9 reject
//!   matching the Run 140 [`compare_authority_marker_v2`] semantics
//!   without invoking the v2 verifier or signing primitives.
//! * `snap-v2-and-v1-ambiguous` carries an arbitrary v1 block plus the
//!   matching v2 block; the Run 140 ambiguity guard
//!   (`RejectAmbiguousSnapshotMarkers`) refuses it without consulting
//!   either block.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use qbind_crypto::MlDsa44Backend;
use qbind_ledger::{
    compute_canonical_genesis_hash, format_genesis_hash, AccountState,
    AuthorityStateSnapshotMeta, AuthorityStateSnapshotMetaV2, BundleSigningRatificationV2Action,
    GenesisAllocation, GenesisAuthorityConfig, GenesisAuthorityRoot, GenesisConfig,
    GenesisCouncilConfig, GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy,
    PersistentAccountState, RocksDbAccountState, StateSnapshotMeta, StateSnapshotter,
    GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_state::{
    persist_authority_state_atomic, persist_authority_state_v2_atomic,
    AuthorityStateUpdateSource, PersistentAuthorityStateRecord,
    PersistentAuthorityStateRecordV2,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_node::pqc_trust_sequence::chain_id_hex;
use qbind_types::NetworkEnvironment;

// ----------------------------------------------------------------------
// Shared constants for the v2 marker trust-domain plus the local
// baseline sequence. The exact byte/hex values are arbitrary but stable
// and reused across the snapshot variants and the local-marker fixture
// so [`compare_authority_marker_v2`] reaches the expected accept/reject
// branch on each scenario.
// ----------------------------------------------------------------------

const V2_LOCAL_SEQUENCE: u64 = 5;
const V2_HIGHER_SEQUENCE: u64 = 10;
const V2_LOWER_SEQUENCE: u64 = 2;
const V1_AUTH_POLICY_VERSION: u32 = 1;
const V1_AUTH_SEQUENCE: u64 = 7;
const V1_AUTH_EPOCH: Option<u64> = Some(3);

fn matching_authority_root_fingerprint() -> String {
    "b".repeat(40)
}
fn different_authority_root_fingerprint() -> String {
    "1".repeat(40)
}
fn matching_active_signing_key_fingerprint() -> String {
    "c".repeat(40)
}
fn matching_v2_digest() -> String {
    "d".repeat(64)
}
fn higher_v2_digest() -> String {
    "e".repeat(64)
}
fn lower_v2_digest() -> String {
    "f".repeat(64)
}
fn same_seq_conflicting_v2_digest() -> String {
    "9".repeat(64)
}

// IMPORTANT: the v1 marker's `authority_root_fingerprint` must match the
// v2 marker's `authority_root_fingerprint` because the Run 140 explicit
// v1→v2 migration path (`V2AfterV1ExplicitMigrationAllowed`) requires the
// local v1 marker's authority root to equal the candidate v2 marker's
// authority root (see `compare_authority_marker_v2`). The other v1
// fingerprints (signing key / ratification object hash) are unrelated.
fn v1_root_fingerprint() -> String {
    matching_authority_root_fingerprint()
}
fn v1_signing_key_fingerprint() -> String {
    "8".repeat(40)
}
fn v1_ratification_object_hash() -> String {
    "c".repeat(64)
}

fn write_text(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap_or_else(|e| panic!("write {}: {}", path.display(), e));
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) {
    let bytes = serde_json::to_vec_pretty(value).expect("serialize json");
    fs::write(path, bytes).unwrap_or_else(|e| panic!("write {}: {}", path.display(), e));
}

/// Build a B3-compatible snapshot directory at `target` populated with a
/// well-known account-state row plus the supplied optional `authority_state`
/// (v1) and `authority_state_v2` (v2) blocks embedded in `meta.json`.
fn build_snapshot(
    target: &Path,
    chain_id_u64: u64,
    height: u64,
    auth_v1: Option<AuthorityStateSnapshotMeta>,
    auth_v2: Option<AuthorityStateSnapshotMetaV2>,
) {
    // Fresh RocksDB state dir holds the source rows so `create_snapshot`
    // can take a real checkpoint. The state dir itself is throwaway.
    let state_dir = target
        .parent()
        .expect("target has parent")
        .join(format!(
            ".state-{}",
            target.file_name().unwrap().to_string_lossy()
        ));
    fs::create_dir_all(&state_dir).expect("mkdir state dir");
    {
        let storage = RocksDbAccountState::open(&state_dir).expect("open source state");
        let account: [u8; 32] = [(height as u8).wrapping_add(0xA0); 32];
        let state = AccountState::new(11, 9999);
        storage
            .put_account_state(&account, &state)
            .expect("put account state");
        storage.flush().expect("flush");
        let meta = StateSnapshotMeta::new(
            height,
            [height as u8; 32],
            1_700_000_000_000,
            chain_id_u64,
        )
        .with_authority_state(auth_v1)
        .with_authority_state_v2(auth_v2);
        storage
            .create_snapshot(&meta, target)
            .unwrap_or_else(|e| panic!("create_snapshot at {}: {:?}", target.display(), e));
    }
    // Throwaway state dir is no longer needed by the harness — the
    // snapshot is self-contained under `target/`.
    let _ = fs::remove_dir_all(&state_dir);
}

fn main() {
    let outdir = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: run_141_v2_snapshot_restore_fixture_helper <outdir>");
    fs::create_dir_all(&outdir).expect("mkdir outdir");

    // ----------------------------------------------------------------
    // 1. Mint an ephemeral DevNet genesis with a Run 101 authority block.
    //    The authority secret key is dropped before main exits because
    //    Run 141 never needs to sign anything (the restore surface
    //    compares marker strings, not signatures).
    // ----------------------------------------------------------------
    let env_kind = NetworkEnvironment::Devnet;
    let env_policy = NetworkEnvironmentPolicy::Devnet;
    let (authority_pk, _authority_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 authority keygen");
    let authority_root = GenesisAuthorityRoot::with_public_key_bytes(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &authority_pk,
        "run141-snapshot-restore-v2-authority",
    );

    let chain_id_u64 = env_kind.chain_id().as_u64();
    let chain_hex16 = chain_id_hex(env_kind.chain_id()); // 16 lowercase hex chars, no `0x`

    let mut genesis = GenesisConfig::new(
        "qbind-devnet-v0",
        1_738_000_000_000,
        vec![GenesisAllocation::new(format!("0x{}", "11".repeat(32)), 100)],
        vec![GenesisValidator::new(
            format!("0x{}", "22".repeat(32)),
            "ab".repeat(32),
            100,
        )],
        GenesisCouncilConfig::new(
            vec![
                format!("0x{}", "33".repeat(32)),
                format!("0x{}", "44".repeat(32)),
                format!("0x{}", "55".repeat(32)),
            ],
            2,
        ),
        GenesisMonetaryConfig::mainnet_default(),
    );
    genesis.authority = Some(GenesisAuthorityConfig::new(vec![authority_root]));
    let canonical_hash = compute_canonical_genesis_hash(&genesis, env_policy);
    let canonical_hash_with_prefix = format_genesis_hash(&canonical_hash); // "0x" + 64 hex
    let canonical_hash_no_prefix = canonical_hash_with_prefix
        .strip_prefix("0x")
        .expect("0x prefix")
        .to_string();

    write_json(&outdir.join("genesis.json"), &genesis);
    write_text(
        &outdir.join("expected-genesis-hash.txt"),
        &format!("{}\n", canonical_hash_with_prefix),
    );

    // ----------------------------------------------------------------
    // 2. Snapshots.
    // ----------------------------------------------------------------
    let snap_root = outdir.join("snapshots");
    fs::create_dir_all(&snap_root).expect("mkdir snapshots");

    // Common matching v2 block — same trust domain + same root + seq 5.
    let matching_v2 = AuthorityStateSnapshotMetaV2 {
        chain_id_hex: chain_hex16.clone(),
        environment: "devnet".to_string(),
        genesis_hash_hex: canonical_hash_no_prefix.clone(),
        authority_root_fingerprint: matching_authority_root_fingerprint(),
        authority_root_suite_id: 1,
        active_bundle_signing_key_fingerprint: matching_active_signing_key_fingerprint(),
        active_bundle_signing_key_suite_id: 1,
        latest_authority_domain_sequence: V2_LOCAL_SEQUENCE,
        latest_lifecycle_action_byte: 0, // Ratify
        previous_bundle_signing_key_fingerprint: None,
        latest_ratification_v2_digest: matching_v2_digest(),
        revoked_key_metadata: None,
    };

    let higher_seq_v2 = AuthorityStateSnapshotMetaV2 {
        latest_authority_domain_sequence: V2_HIGHER_SEQUENCE,
        latest_ratification_v2_digest: higher_v2_digest(),
        ..matching_v2.clone()
    };

    let lower_seq_v2 = AuthorityStateSnapshotMetaV2 {
        latest_authority_domain_sequence: V2_LOWER_SEQUENCE,
        latest_ratification_v2_digest: lower_v2_digest(),
        ..matching_v2.clone()
    };

    let same_seq_diff_digest_v2 = AuthorityStateSnapshotMetaV2 {
        // Same sequence as the local marker, different ratification digest.
        latest_ratification_v2_digest: same_seq_conflicting_v2_digest(),
        ..matching_v2.clone()
    };

    let wrong_genesis_v2 = AuthorityStateSnapshotMetaV2 {
        genesis_hash_hex: "0".repeat(64),
        ..matching_v2.clone()
    };

    let wrong_environment_v2 = AuthorityStateSnapshotMetaV2 {
        environment: "mainnet".to_string(),
        ..matching_v2.clone()
    };

    let wrong_chain_v2 = AuthorityStateSnapshotMetaV2 {
        chain_id_hex: "f".repeat(16),
        ..matching_v2.clone()
    };

    let wrong_authority_root_v2 = AuthorityStateSnapshotMetaV2 {
        authority_root_fingerprint: different_authority_root_fingerprint(),
        ..matching_v2.clone()
    };

    // Legacy v1 block — present only for the ambiguous-snapshot variant
    // and the v1 regression. Domain bound to the same DevNet runtime.
    let matching_v1 = AuthorityStateSnapshotMeta {
        chain_id_hex: chain_hex16.clone(),
        environment: "devnet".to_string(),
        genesis_hash_hex: canonical_hash_no_prefix.clone(),
        authority_policy_version: V1_AUTH_POLICY_VERSION,
        authority_sequence: V1_AUTH_SEQUENCE,
        authority_epoch: V1_AUTH_EPOCH,
        authority_root_fingerprint: v1_root_fingerprint(),
        ratified_bundle_signing_key_fingerprint: v1_signing_key_fingerprint(),
        ratification_object_hash: v1_ratification_object_hash(),
    };

    build_snapshot(
        &snap_root.join("snap-v2-only"),
        chain_id_u64,
        201,
        None,
        Some(matching_v2.clone()),
    );
    build_snapshot(
        &snap_root.join("snap-v2-higher-seq"),
        chain_id_u64,
        202,
        None,
        Some(higher_seq_v2),
    );
    build_snapshot(
        &snap_root.join("snap-v2-lower-seq"),
        chain_id_u64,
        203,
        None,
        Some(lower_seq_v2),
    );
    build_snapshot(
        &snap_root.join("snap-v2-same-seq-diff-digest"),
        chain_id_u64,
        204,
        None,
        Some(same_seq_diff_digest_v2),
    );
    build_snapshot(
        &snap_root.join("snap-v2-wrong-genesis"),
        chain_id_u64,
        205,
        None,
        Some(wrong_genesis_v2),
    );
    build_snapshot(
        &snap_root.join("snap-v2-wrong-environment"),
        chain_id_u64,
        206,
        None,
        Some(wrong_environment_v2),
    );
    build_snapshot(
        &snap_root.join("snap-v2-wrong-chain"),
        chain_id_u64,
        207,
        None,
        Some(wrong_chain_v2),
    );
    build_snapshot(
        &snap_root.join("snap-v2-wrong-authority-root"),
        chain_id_u64,
        208,
        None,
        Some(wrong_authority_root_v2),
    );
    build_snapshot(
        &snap_root.join("snap-v2-and-v1-ambiguous"),
        chain_id_u64,
        209,
        Some(matching_v1.clone()),
        Some(matching_v2.clone()),
    );
    build_snapshot(
        &snap_root.join("snap-v1-only"),
        chain_id_u64,
        210,
        Some(matching_v1.clone()),
        None,
    );
    build_snapshot(
        &snap_root.join("snap-legacy-no-marker"),
        chain_id_u64,
        211,
        None,
        None,
    );

    // ----------------------------------------------------------------
    // 3. Local marker fixtures.
    //
    // `matching-v2.json` is the bit-for-bit `pqc_authority_state.json`
    // v2 marker the harness drops into the per-scenario data dir before
    // invoking the release binary. Its (chain_id, environment,
    // genesis_hash) MUST match the runtime authority context the binary
    // computes from `--genesis-path` + `--env devnet`, or the Run 140
    // v2 check would reject it as `RejectLocalMarkerWrongDomain` BEFORE
    // ever looking at the snapshot.
    //
    // `matching-v1.json` is the legacy v1 marker used for the A4
    // explicit v1→v2 migration scenario and for the v1 regression
    // scenario; same runtime trust domain.
    //
    // `corrupt.bin` is a fixed non-JSON byte sequence that fails the
    // versioned-marker load structurally → `RejectLocalMarkerCorrupt`.
    // ----------------------------------------------------------------
    let markers = outdir.join("markers");
    fs::create_dir_all(&markers).expect("mkdir markers");

    let matching_v2_record = PersistentAuthorityStateRecordV2::new(
        chain_hex16.clone(),
        TrustBundleEnvironment::Devnet,
        canonical_hash_no_prefix.clone(),
        matching_authority_root_fingerprint(),
        1,
        matching_active_signing_key_fingerprint(),
        1,
        V2_LOCAL_SEQUENCE,
        BundleSigningRatificationV2Action::Ratify,
        None,
        matching_v2_digest(),
        None,
        AuthorityStateUpdateSource::StartupLoad,
        1_700_000_000,
    );
    persist_authority_state_v2_atomic(&markers.join("matching-v2.json"), &matching_v2_record)
        .expect("persist matching v2 marker fixture");

    let matching_v1_record = PersistentAuthorityStateRecord::new(
        chain_hex16.clone(),
        TrustBundleEnvironment::Devnet,
        canonical_hash_no_prefix.clone(),
        V1_AUTH_POLICY_VERSION,
        V1_AUTH_SEQUENCE,
        V1_AUTH_EPOCH,
        v1_root_fingerprint(),
        v1_signing_key_fingerprint(),
        v1_ratification_object_hash(),
        AuthorityStateUpdateSource::StartupLoad,
        1_700_000_000,
    );
    persist_authority_state_atomic(&markers.join("matching-v1.json"), &matching_v1_record)
        .expect("persist matching v1 marker fixture");

    fs::write(markers.join("corrupt.bin"), b"NOT-A-VALID-JSON-RUN-141")
        .expect("write corrupt marker fixture");

    // ----------------------------------------------------------------
    // 4. Shell-sourceable manifest.
    // ----------------------------------------------------------------
    let manifest = format!(
        "# Run 141 fixture helper manifest (shell-sourceable).\n\
         RUN_141_GENESIS_PATH={genesis}\n\
         RUN_141_GENESIS_HASH={hash}\n\
         RUN_141_GENESIS_HASH_NO_PREFIX={hash_np}\n\
         RUN_141_CHAIN_ID_HEX={chain_hex}\n\
         RUN_141_V2_LOCAL_SEQUENCE={v2_local_seq}\n\
         RUN_141_V2_HIGHER_SEQUENCE={v2_higher_seq}\n\
         RUN_141_V2_LOWER_SEQUENCE={v2_lower_seq}\n\
         RUN_141_SNAP_V2_ONLY={snap_v2_only}\n\
         RUN_141_SNAP_V2_HIGHER_SEQ={snap_v2_higher}\n\
         RUN_141_SNAP_V2_LOWER_SEQ={snap_v2_lower}\n\
         RUN_141_SNAP_V2_SAME_SEQ_DIFF_DIGEST={snap_v2_same_seq}\n\
         RUN_141_SNAP_V2_WRONG_GENESIS={snap_v2_wrong_genesis}\n\
         RUN_141_SNAP_V2_WRONG_ENVIRONMENT={snap_v2_wrong_env}\n\
         RUN_141_SNAP_V2_WRONG_CHAIN={snap_v2_wrong_chain}\n\
         RUN_141_SNAP_V2_WRONG_AUTHORITY_ROOT={snap_v2_wrong_root}\n\
         RUN_141_SNAP_V2_AND_V1_AMBIGUOUS={snap_v2_v1_ambiguous}\n\
         RUN_141_SNAP_V1_ONLY={snap_v1_only}\n\
         RUN_141_SNAP_LEGACY_NO_MARKER={snap_legacy}\n\
         RUN_141_LOCAL_MARKER_MATCHING_V2={local_matching_v2}\n\
         RUN_141_LOCAL_MARKER_MATCHING_V1={local_matching_v1}\n\
         RUN_141_LOCAL_MARKER_CORRUPT={local_corrupt}\n",
        genesis = outdir.join("genesis.json").display(),
        hash = canonical_hash_with_prefix,
        hash_np = canonical_hash_no_prefix,
        chain_hex = chain_hex16,
        v2_local_seq = V2_LOCAL_SEQUENCE,
        v2_higher_seq = V2_HIGHER_SEQUENCE,
        v2_lower_seq = V2_LOWER_SEQUENCE,
        snap_v2_only = snap_root.join("snap-v2-only").display(),
        snap_v2_higher = snap_root.join("snap-v2-higher-seq").display(),
        snap_v2_lower = snap_root.join("snap-v2-lower-seq").display(),
        snap_v2_same_seq = snap_root.join("snap-v2-same-seq-diff-digest").display(),
        snap_v2_wrong_genesis = snap_root.join("snap-v2-wrong-genesis").display(),
        snap_v2_wrong_env = snap_root.join("snap-v2-wrong-environment").display(),
        snap_v2_wrong_chain = snap_root.join("snap-v2-wrong-chain").display(),
        snap_v2_wrong_root = snap_root.join("snap-v2-wrong-authority-root").display(),
        snap_v2_v1_ambiguous = snap_root.join("snap-v2-and-v1-ambiguous").display(),
        snap_v1_only = snap_root.join("snap-v1-only").display(),
        snap_legacy = snap_root.join("snap-legacy-no-marker").display(),
        local_matching_v2 = markers.join("matching-v2.json").display(),
        local_matching_v1 = markers.join("matching-v1.json").display(),
        local_corrupt = markers.join("corrupt.bin").display(),
    );
    write_text(&outdir.join("manifest.env"), &manifest);

    eprintln!(
        "[run141-fixture-helper] wrote ephemeral release-binary snapshot/restore v2 fixtures under {}",
        outdir.display()
    );
}
