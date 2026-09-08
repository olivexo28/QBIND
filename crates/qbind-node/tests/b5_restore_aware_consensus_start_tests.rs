//! B5 integration tests: restore-aware consensus start.
//!
//! These tests cover the smallest honest restore-aware consensus
//! initialization on the binary path — see
//! `crates/qbind-node/src/snapshot_restore.rs`,
//! `crates/qbind-node/src/binary_consensus_loop.rs`,
//! `crates/qbind-consensus/src/basic_hotstuff_engine.rs`
//! (`initialize_from_snapshot_baseline`), and
//! `docs/whitepaper/contradiction.md` C4 (B5 sub-item).
//!
//! The tests drive the same library entry points the binary calls
//! (`apply_snapshot_restore_if_requested` → `RestoreOutcome` →
//! `BinaryConsensusLoopConfig::with_restore_baseline` →
//! `run_binary_consensus_loop`); they do not spawn a child `qbind-node`
//! process. This mirrors the style of `b3_snapshot_restore_tests.rs`.
//!
//! Coverage:
//!
//! - **A. restore-aware startup baseline applied**: a real snapshot at
//!   height H is materialized via `apply_snapshot_restore_if_requested`,
//!   the resulting `RestoreOutcome` is converted to a
//!   `BinaryConsensusLoopConfig::restore_baseline`, and the loop's first
//!   ticks observe `current_view = H + 1` and a committed height that is
//!   strictly above H.
//! - **B. normal startup unchanged**: when no restore is requested,
//!   `apply_snapshot_restore_if_requested` returns `Ok(None)`, no
//!   baseline is applied, and the loop starts from view 0 / no committed
//!   prefix as before.
//! - **C. post-restore committed height progresses above the snapshot
//!   height** (DevNet Run 004 enabler): explicit assertion that
//!   `committed_height > snapshot_height` and every committed entry's
//!   height is strictly above the snapshot height.
//! - **D. invalid restore still rejected**: re-asserts the B3 invariant
//!   that a bad snapshot still fails fast (no silent baseline-from-zero
//!   degradation).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tempfile::tempdir;
use tokio::sync::watch;

use qbind_consensus::ids::ValidatorId;
use qbind_ledger::{
    AccountState, PersistentAccountState, RocksDbAccountState, StateSnapshotMeta,
    StateSnapshotter,
};
use qbind_node::binary_consensus_loop::{
    run_binary_consensus_loop, BinaryConsensusLoopConfig, BinaryConsensusLoopProgress,
    RestoreBaseline,
};
use qbind_node::metrics::NodeMetrics;
use qbind_node::node_config::{FastSyncConfig, NodeConfig};
use qbind_node::snapshot_restore::{
    apply_snapshot_restore_if_requested, RestoreError,
};

// ============================================================================
// Helpers
// ============================================================================

/// Build a real snapshot directory at `target` populated by writing a
/// well-known account state into a fresh `RocksDbAccountState` and then
/// invoking `create_snapshot`. Returns the meta written.
fn build_real_snapshot(
    state_dir: &Path,
    target: &Path,
    chain_id: u64,
    height: u64,
) -> StateSnapshotMeta {
    let storage = RocksDbAccountState::open(state_dir).expect("open state dir");
    let account: [u8; 32] = [0xCD; 32];
    let state = AccountState::new(7, 4242);
    storage
        .put_account_state(&account, &state)
        .expect("put account state");
    storage.flush().expect("flush state");

    let meta = StateSnapshotMeta::new(height, [height as u8; 32], 1_700_000_000_000, chain_id);
    storage
        .create_snapshot(&meta, target)
        .expect("create_snapshot");

    drop(storage);
    meta
}

fn devnet_chain_id() -> u64 {
    NodeConfig::default().chain_id().as_u64()
}

/// Drive the binary consensus loop for a bounded number of ticks, optionally
/// applying a restore baseline. Mirrors the wiring used by
/// `qbind_node::main::run_local_mesh_node` (single-validator).
async fn run_loop(
    baseline: Option<RestoreBaseline>,
    max_ticks: u64,
) -> BinaryConsensusLoopProgress {
    let mut cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 1)
        .with_tick_interval(Duration::from_millis(1))
        .with_max_ticks(max_ticks);
    if let Some(b) = baseline {
        cfg = cfg.with_restore_baseline(b);
    }
    let (_shutdown_tx, shutdown_rx) = watch::channel(());
    let progress =
        Arc::new(parking_lot::Mutex::new(BinaryConsensusLoopProgress::default()));
    let metrics = Arc::new(NodeMetrics::new());
    run_binary_consensus_loop(cfg, shutdown_rx, progress, metrics).await
}

// ============================================================================
// A. restore-aware startup baseline applied (real snapshot → real loop)
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b5_real_snapshot_restore_seeds_consensus_baseline() {
    const SNAPSHOT_HEIGHT: u64 = 333;

    // 1. Build a real snapshot using the canonical StateSnapshotter format.
    let snap_root = tempdir().expect("tempdir");
    let src_state = tempdir().expect("tempdir");
    let data_dir = tempdir().expect("tempdir");
    let snapshot_dir = snap_root.path().join(format!("snap-{}", SNAPSHOT_HEIGHT));
    let chain_id = devnet_chain_id();
    let meta = build_real_snapshot(src_state.path(), &snapshot_dir, chain_id, SNAPSHOT_HEIGHT);

    // 2. Drive the binary's library entry point for restore (same call
    //    `main.rs` makes).
    let mut config = NodeConfig::default();
    config.data_dir = Some(data_dir.path().to_path_buf());
    config.fast_sync_config = FastSyncConfig::from_snapshot(snapshot_dir);
    let outcome = apply_snapshot_restore_if_requested(&config)
        .expect("valid snapshot must apply")
        .expect("restore should be requested");
    assert_eq!(outcome.meta.height, SNAPSHOT_HEIGHT);
    assert_eq!(outcome.meta, meta);

    // 3. Convert outcome → consensus baseline (same translation `main.rs`
    //    does).
    let baseline = RestoreBaseline {
        snapshot_height: outcome.meta.height,
        snapshot_block_id: outcome.meta.block_hash,
    };

    // 4. Run the binary consensus loop with the baseline. 80 ticks at 1ms
    //    is comfortably enough for the 3-chain rule to fire (which needs at
    //    least 3 leader steps after the baseline anchor).
    let progress = run_loop(Some(baseline), 80).await;

    // 5. Post-restore committed height must be strictly above the snapshot
    //    height — the central B5 / Run 004 evidence claim.
    let committed_height = progress.committed_height.expect(
        "post-restore loop should commit at least one block above the baseline anchor",
    );
    assert!(
        committed_height > SNAPSHOT_HEIGHT,
        "post-restore committed_height ({}) must advance above snapshot_height ({})",
        committed_height,
        SNAPSHOT_HEIGHT
    );

    // 6. Current view must also be > snapshot_height + 1 (engine has
    //    advanced past the seeded view).
    assert!(
        progress.current_view > SNAPSHOT_HEIGHT + 1,
        "post-restore current_view ({}) must advance past seeded view ({})",
        progress.current_view,
        SNAPSHOT_HEIGHT + 1
    );

    // 7. Some real progress was made beyond the seed (sanity).
    assert!(progress.commits >= 1);
    assert!(progress.proposals_emitted >= 1);
}

// ============================================================================
// B. normal startup unchanged (no restore requested → no baseline applied)
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b5_no_restore_requested_leaves_loop_unchanged() {
    let data_dir = tempdir().expect("tempdir");
    let mut config = NodeConfig::default();
    config.data_dir = Some(data_dir.path().to_path_buf());
    // No fast_sync_config → restore is disabled.

    // The library entry point yields no outcome → no baseline.
    let outcome = apply_snapshot_restore_if_requested(&config)
        .expect("no-restore path returns Ok(None)");
    assert!(outcome.is_none(), "no-restore path must yield None");

    // Run the loop with no baseline; engine should start from view 0 and
    // committed height should stay small (no baseline-from-zero confusion).
    let progress = run_loop(None, 20).await;

    if let Some(h) = progress.committed_height {
        assert!(
            h < 100,
            "no-restore loop committed_height ({}) climbed unexpectedly high \
             — non-restore startup may have been regressed by B5",
            h
        );
    }
    assert!(progress.current_view <= 20);
}

// ============================================================================
// C. post-restore committed height progresses above snapshot height (large H)
// ============================================================================

/// DevNet Evidence Run 004 enabler: pick a height that is far larger than
/// any plausible "started from zero" run could reach in the bounded test
/// window, so that the committed-height-above-snapshot signal is unambiguous.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b5_committed_height_strictly_above_snapshot_height_for_large_h() {
    // 1_000_000 is well beyond what 80 ticks could reach from view 0
    // (single-validator self-quorum advances at most one view per tick).
    const SNAPSHOT_HEIGHT: u64 = 1_000_000;
    let baseline = RestoreBaseline {
        snapshot_height: SNAPSHOT_HEIGHT,
        snapshot_block_id: [0x5C; 32],
    };

    let progress = run_loop(Some(baseline), 80).await;
    let h = progress.committed_height.expect("expected commits");
    assert!(
        h > SNAPSHOT_HEIGHT,
        "committed_height ({}) did not advance above snapshot_height ({}); \
         a non-restore engine could not reach this in 80 ticks, so this \
         confirms the engine resumed from the seeded baseline",
        h,
        SNAPSHOT_HEIGHT
    );
    // Also: current_view must be strictly above the snapshot height + 1.
    assert!(progress.current_view > SNAPSHOT_HEIGHT + 1);
}

// ============================================================================
// D. invalid restore still rejected (B3 regression guard)
// ============================================================================

#[test]
fn b5_invalid_restore_still_rejected_no_silent_baseline_from_zero() {
    // An invalid snapshot must still fail fast (B3 contract) — B5 must
    // not have added a code path that silently degrades to "no baseline,
    // start from zero".
    let data_dir = tempdir().expect("tempdir");
    let mut config = NodeConfig::default();
    config.data_dir = Some(data_dir.path().to_path_buf());
    // Point to a non-existent snapshot dir.
    config.fast_sync_config =
        FastSyncConfig::from_snapshot(data_dir.path().join("does-not-exist"));

    let err = apply_snapshot_restore_if_requested(&config)
        .expect_err("invalid restore must be rejected");
    assert!(
        matches!(err, RestoreError::SnapshotPathMissing(_)),
        "expected SnapshotPathMissing, got {:?}",
        err
    );
}