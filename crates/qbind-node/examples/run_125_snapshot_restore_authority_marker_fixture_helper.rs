//! Run 125 evidence-only fixture helper for the release-binary
//! snapshot/restore authority-marker conflict enforcement scenarios.
//!
//! This helper mints an ephemeral DevNet genesis with the Run 101
//! `genesis_authority` block, computes the canonical Run 101 genesis
//! hash, builds four real B3-format snapshot directories using the
//! canonical `StateSnapshotter::create_snapshot` API, and emits matching
//! / conflicting / corrupt local authority-marker JSON fixtures plus a
//! plain-text manifest the release-binary harness consumes.
//!
//! Run 125 is evidence-only. This helper does NOT modify production
//! runtime code, does NOT create fallback authorities, static production
//! source-code anchors, peer-driven live apply, signing-key rotation /
//! revocation lifecycle, KMS/HSM, governance, or wire-format changes.
//! It is an `examples/` target only and never participates in any
//! production binary path.
//!
//! Layout written under `<outdir>`:
//!
//! ```text
//! <outdir>/
//! ├── genesis.json                   # DevNet genesis with Run 101 authority block
//! ├── expected-genesis-hash.txt      # `0x` + 64 lowercase-hex chars
//! ├── manifest.env                   # KEY=VALUE shell-sourceable manifest
//! ├── snapshots/
//! │   ├── snap-legacy/               # B3 snapshot, NO authority_state block
//! │   ├── snap-matching/             # B3 snapshot, matching authority_state
//! │   ├── snap-conflicting/          # same authority_sequence, different ratification_object_hash
//! │   └── snap-wrong-domain/         # authority_state with wrong genesis_hash
//! └── markers/
//!     ├── matching.json              # PersistentAuthorityStateRecord matching snap-matching
//!     └── corrupt.bin                # 16 non-JSON bytes
//! ```

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use qbind_crypto::MlDsa44Backend;
use qbind_ledger::{
    compute_canonical_genesis_hash, format_genesis_hash, AccountState, AuthorityStateSnapshotMeta,
    GenesisAllocation, GenesisAuthorityConfig, GenesisAuthorityRoot, GenesisConfig,
    GenesisCouncilConfig, GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy,
    PersistentAccountState, RocksDbAccountState, StateSnapshotMeta, StateSnapshotter,
    GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_state::{
    persist_authority_state_atomic, AuthorityStateUpdateSource, PersistentAuthorityStateRecord,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_node::pqc_trust_sequence::chain_id_hex;
use qbind_types::NetworkEnvironment;

/// Constant authority-state field values reused across snapshot and local
/// marker fixtures. The string forms are arbitrary canonical-hex blobs
/// the Run 124 helper compares verbatim; no cryptographic verification
/// is performed against them on the restore surface.
const AUTH_POLICY_VERSION: u32 = 1;
const AUTH_SEQUENCE: u64 = 7;
const AUTH_EPOCH: Option<u64> = Some(3);

fn auth_root_fingerprint() -> String {
    "b".repeat(40)
}
fn ratified_bundle_signing_key_fingerprint() -> String {
    "c".repeat(40)
}
fn ratification_object_hash_matching() -> String {
    "d".repeat(64)
}
/// Same `authority_sequence` (= conflict by the Run 117 "two distinct
/// ratifications cannot share the same authority_sequence" rule) but a
/// different `ratification_object_hash`. The Run 124 helper surfaces this
/// as `RejectConflict(SameSequenceConflictingHash)`.
fn ratification_object_hash_conflicting() -> String {
    "e".repeat(64)
}

fn write_text(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap_or_else(|e| panic!("write {}: {}", path.display(), e));
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) {
    let bytes = serde_json::to_vec_pretty(value).expect("serialize json");
    fs::write(path, bytes).unwrap_or_else(|e| panic!("write {}: {}", path.display(), e));
}

/// Build a B3-compatible snapshot directory at `target` populated with a
/// well-known account state, with the supplied optional
/// `authority_state` block embedded in `meta.json`.
fn build_snapshot(
    target: &Path,
    chain_id_u64: u64,
    height: u64,
    auth: Option<AuthorityStateSnapshotMeta>,
) {
    // Fresh RocksDB state dir holds the source rows so `create_snapshot`
    // can take a real checkpoint. The state dir itself is throwaway.
    let state_dir = target
        .parent()
        .expect("target has parent")
        .join(format!(".state-{}", target.file_name().unwrap().to_string_lossy()));
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
        .with_authority_state(auth);
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
        .expect("usage: run_125_snapshot_restore_authority_marker_fixture_helper <outdir>");
    fs::create_dir_all(&outdir).expect("mkdir outdir");

    // ----------------------------------------------------------------
    // 1. Mint an ephemeral DevNet genesis with a Run 101 authority block.
    //    We never persist the authority secret key beyond this process;
    //    the secret is dropped before main exits because Run 125 never
    //    needs to sign anything (it is evidence-only; the restore surface
    //    compares marker strings, not signatures).
    // ----------------------------------------------------------------
    let env_kind = NetworkEnvironment::Devnet;
    let env_policy = NetworkEnvironmentPolicy::Devnet;
    let (authority_pk, _authority_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 authority keygen");
    let authority_root = GenesisAuthorityRoot::with_public_key_bytes(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &authority_pk,
        "run125-snapshot-restore-authority",
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

    // Common fields used by every present-authority-state snapshot.
    let matching_auth = AuthorityStateSnapshotMeta {
        chain_id_hex: chain_hex16.clone(),
        environment: "devnet".to_string(),
        genesis_hash_hex: canonical_hash_no_prefix.clone(),
        authority_policy_version: AUTH_POLICY_VERSION,
        authority_sequence: AUTH_SEQUENCE,
        authority_epoch: AUTH_EPOCH,
        authority_root_fingerprint: auth_root_fingerprint(),
        ratified_bundle_signing_key_fingerprint: ratified_bundle_signing_key_fingerprint(),
        ratification_object_hash: ratification_object_hash_matching(),
    };
    let conflicting_auth = AuthorityStateSnapshotMeta {
        ratification_object_hash: ratification_object_hash_conflicting(),
        ..matching_auth.clone()
    };
    let wrong_domain_auth = AuthorityStateSnapshotMeta {
        // Same shape, but the genesis_hash_hex points at a different
        // canonical hash. The Run 124 helper rejects this BEFORE the
        // sequence/hash equality compare.
        genesis_hash_hex: "f".repeat(64),
        ..matching_auth.clone()
    };

    build_snapshot(&snap_root.join("snap-legacy"), chain_id_u64, 100, None);
    build_snapshot(
        &snap_root.join("snap-matching"),
        chain_id_u64,
        101,
        Some(matching_auth.clone()),
    );
    build_snapshot(
        &snap_root.join("snap-conflicting"),
        chain_id_u64,
        102,
        Some(conflicting_auth),
    );
    build_snapshot(
        &snap_root.join("snap-wrong-domain"),
        chain_id_u64,
        103,
        Some(wrong_domain_auth),
    );

    // ----------------------------------------------------------------
    // 3. Local marker fixtures.
    //
    // `matching.json` is the bit-for-bit `pqc_authority_state.json` the
    // harness drops into the per-scenario data dir before invoking the
    // release binary; its (chain_id, environment, genesis_hash) MUST
    // match the runtime authority context the binary computes from
    // `--genesis-path` + `--env devnet`, or the Run 124 helper would
    // reject it as `RejectLocalMarkerWrongDomain` BEFORE ever looking
    // at the snapshot.
    //
    // `corrupt.bin` is 16 non-JSON bytes that fail `load_authority_state`
    // structurally → `RejectLocalMarkerCorrupt(...)`. The exact byte
    // sequence is recorded verbatim in the harness summary so the
    // before/after byte equality assertion is meaningful.
    // ----------------------------------------------------------------
    let markers = outdir.join("markers");
    fs::create_dir_all(&markers).expect("mkdir markers");
    let matching_record = PersistentAuthorityStateRecord::new(
        chain_hex16.clone(),
        TrustBundleEnvironment::Devnet,
        canonical_hash_no_prefix.clone(),
        AUTH_POLICY_VERSION,
        AUTH_SEQUENCE,
        AUTH_EPOCH,
        auth_root_fingerprint(),
        ratified_bundle_signing_key_fingerprint(),
        ratification_object_hash_matching(),
        AuthorityStateUpdateSource::TestOrFixture,
        1_700_000_000,
    );
    persist_authority_state_atomic(&markers.join("matching.json"), &matching_record)
        .expect("persist matching marker fixture");
    // Deliberately non-JSON bytes. They are not the empty string (which
    // could be mistaken for an absent file), and they are not a stray
    // prefix of a valid JSON object — they are a stable, recognisable
    // garbage payload.
    fs::write(
        markers.join("corrupt.bin"),
        b"NOT-A-VALID-JSON",
    )
    .expect("write corrupt marker fixture");

    // ----------------------------------------------------------------
    // 4. Shell-sourceable manifest.
    //
    // The harness sources this file so it has a single source of truth
    // for paths + the canonical genesis hash. Future runs that want to
    // extend the scenario matrix can append additional fixtures and a
    // single new line per fixture here.
    // ----------------------------------------------------------------
    let manifest = format!(
        "# Run 125 fixture helper manifest (shell-sourceable).\n\
         RUN_125_GENESIS_PATH={genesis}\n\
         RUN_125_GENESIS_HASH={hash}\n\
         RUN_125_GENESIS_HASH_NO_PREFIX={hash_np}\n\
         RUN_125_CHAIN_ID_HEX={chain_hex}\n\
         RUN_125_AUTH_SEQUENCE={seq}\n\
         RUN_125_SNAP_LEGACY={snap_legacy}\n\
         RUN_125_SNAP_MATCHING={snap_matching}\n\
         RUN_125_SNAP_CONFLICTING={snap_conflicting}\n\
         RUN_125_SNAP_WRONG_DOMAIN={snap_wrong_domain}\n\
         RUN_125_LOCAL_MARKER_MATCHING={local_matching}\n\
         RUN_125_LOCAL_MARKER_CORRUPT={local_corrupt}\n",
        genesis = outdir.join("genesis.json").display(),
        hash = canonical_hash_with_prefix,
        hash_np = canonical_hash_no_prefix,
        chain_hex = chain_hex16,
        seq = AUTH_SEQUENCE,
        snap_legacy = snap_root.join("snap-legacy").display(),
        snap_matching = snap_root.join("snap-matching").display(),
        snap_conflicting = snap_root.join("snap-conflicting").display(),
        snap_wrong_domain = snap_root.join("snap-wrong-domain").display(),
        local_matching = markers.join("matching.json").display(),
        local_corrupt = markers.join("corrupt.bin").display(),
    );
    write_text(&outdir.join("manifest.env"), &manifest);

    eprintln!(
        "[run125-fixture-helper] wrote ephemeral release-binary snapshot/restore fixtures under {}",
        outdir.display()
    );
}