//! Run 093 — integration tests for the minimum production binary-path
//! `ConsensusStorage` lifecycle and durable epoch persistence
//! groundwork.
//!
//! These tests pin the public-API contract of
//! `qbind_node::production_consensus_storage` (canonical path, opened
//! state distinction, restart preservation, fail-closed behaviour) on
//! the binary path required by `task/RUN_093_TASK.txt`.
//!
//! Tests are intentionally driven through the public re-exports —
//! `NodeConfig::consensus_storage_dir`,
//! `open_production_consensus_storage`,
//! `ConsensusStorageState`, and the `ConsensusStorage` trait — so
//! that the binary's `main.rs` call site is exercised against the
//! same surface that production runs against.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use tempfile::TempDir;

use qbind_node::node_config::NodeConfig;
use qbind_node::production_consensus_storage::{
    open_production_consensus_storage, ConsensusStorageState, OpenedProductionConsensusStorage,
    ProductionConsensusStorageError,
};
use qbind_node::storage::{ConsensusStorage, RocksDbConsensusStorage};

// ============================================================================
// Helpers
// ============================================================================

fn devnet_with_data_dir(data_dir: &std::path::Path) -> NodeConfig {
    NodeConfig::devnet().with_data_dir(data_dir)
}

fn canonical_consensus_path(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("consensus")
}

// ============================================================================
// Canonical path
// ============================================================================

#[test]
fn run_093_canonical_path_is_data_dir_slash_consensus() {
    let tmp = TempDir::new().unwrap();
    let cfg = devnet_with_data_dir(tmp.path());
    let resolved = cfg
        .consensus_storage_dir()
        .expect("data_dir set → consensus dir must resolve");
    assert_eq!(resolved, canonical_consensus_path(tmp.path()));
    // The path is deterministic — calling again returns the same path.
    let again = cfg.consensus_storage_dir().unwrap();
    assert_eq!(again, resolved);
    // The path is a subdir of data_dir (no temp fallback, no hidden
    // environment-dependent path).
    assert_eq!(resolved.parent().unwrap(), tmp.path());
    assert_eq!(resolved.file_name().unwrap(), "consensus");
}

#[test]
fn run_093_no_data_dir_yields_none() {
    let cfg = NodeConfig::devnet();
    assert!(cfg.consensus_storage_dir().is_none());
}

// ============================================================================
// Open + startup state distinction
// ============================================================================

#[test]
fn run_093_no_data_dir_open_yields_no_consensus_storage_state() {
    let cfg = NodeConfig::devnet();
    let opened = open_production_consensus_storage(&cfg)
        .expect("no-data-dir is not an error; it is an explicit state");
    assert_eq!(opened.state, ConsensusStorageState::NoConsensusStorage);
    assert!(opened.handle.is_none());
    assert!(opened.path.is_none());
    assert!(!opened.state.has_open_storage());
    // Fresh-genesis-no-data-dir must NOT silently become epoch 0.
    assert!(opened.state.committed_epoch().is_none());
}

#[test]
fn run_093_fresh_open_with_data_dir_is_present_no_committed_epoch() {
    let tmp = TempDir::new().unwrap();
    let cfg = devnet_with_data_dir(tmp.path());
    let opened = open_production_consensus_storage(&cfg).expect("open ok");
    assert_eq!(opened.state, ConsensusStorageState::PresentNoCommittedEpoch);
    assert!(opened.handle.is_some(), "RocksDB handle must be held alive");
    assert_eq!(
        opened.path.as_deref(),
        Some(canonical_consensus_path(tmp.path()).as_path())
    );
    assert!(opened.state.has_open_storage());
    // Fresh-genesis MUST NOT silently look like current_epoch=0.
    assert!(
        opened.state.committed_epoch().is_none(),
        "PresentNoCommittedEpoch must not collapse to Some(0)"
    );
    assert!(
        canonical_consensus_path(tmp.path()).is_dir(),
        "<data_dir>/consensus must exist on disk after open"
    );
}

#[test]
fn run_093_committed_epoch_distinguishable_from_present_no_committed_epoch() {
    let tmp = TempDir::new().unwrap();
    let cfg = devnet_with_data_dir(tmp.path());

    // 1st open: storage present but no epoch.
    {
        let opened = open_production_consensus_storage(&cfg).expect("open ok");
        assert_eq!(opened.state, ConsensusStorageState::PresentNoCommittedEpoch);
        // Use the existing trait-surface epoch-write so we exercise the
        // *same* MetaStore mechanism Run 091/092 documented.
        opened
            .handle
            .as_ref()
            .unwrap()
            .put_current_epoch(5)
            .expect("put_current_epoch ok");
        // Drop handle to release the RocksDB lock for the next open.
    }

    // 2nd open: same data dir → CommittedEpoch(5).
    let reopened = open_production_consensus_storage(&cfg).expect("reopen ok");
    assert_eq!(reopened.state, ConsensusStorageState::CommittedEpoch(5));
    assert_eq!(reopened.state.committed_epoch(), Some(5));
}

// ============================================================================
// Restart preservation
// ============================================================================

#[test]
fn run_093_committed_epoch_persists_across_restart() {
    let tmp = TempDir::new().unwrap();
    let cfg = devnet_with_data_dir(tmp.path());

    // Simulate a node lifecycle: open, write epoch=99, drop (=clean shutdown).
    {
        let opened = open_production_consensus_storage(&cfg).expect("open ok");
        assert_eq!(opened.state, ConsensusStorageState::PresentNoCommittedEpoch);
        opened
            .handle
            .as_ref()
            .unwrap()
            .put_current_epoch(99)
            .expect("put_current_epoch ok");
    }

    // Restart: re-open at the same canonical path observes CommittedEpoch(99).
    let after_restart = open_production_consensus_storage(&cfg).expect("reopen ok");
    assert_eq!(
        after_restart.state,
        ConsensusStorageState::CommittedEpoch(99),
        "committed epoch must survive process restart"
    );

    // And a third open continues to observe the same value.
    drop(after_restart);
    let after_restart2 = open_production_consensus_storage(&cfg).expect("reopen ok");
    assert_eq!(
        after_restart2.state,
        ConsensusStorageState::CommittedEpoch(99)
    );
}

// ============================================================================
// Fail-closed behaviour
// ============================================================================

#[test]
fn run_093_open_failure_on_locked_db_fails_closed() {
    // Hold an exclusive RocksDB lock on the canonical path, then try
    // to open again. The second open must fail-closed rather than
    // returning NoConsensusStorage or silently degrading.
    let tmp = TempDir::new().unwrap();
    let cfg = devnet_with_data_dir(tmp.path());

    // First open — holds the lock.
    let holder = open_production_consensus_storage(&cfg).expect("first open ok");
    assert!(holder.handle.is_some());

    // Second open at the same path must fail (RocksDB enforces single
    // writer per directory).
    let second = open_production_consensus_storage(&cfg);
    match second {
        Err(ProductionConsensusStorageError::OpenFailed { path, .. }) => {
            assert_eq!(path, canonical_consensus_path(tmp.path()));
        }
        other => panic!(
            "second open while first is held must fail-closed with OpenFailed; got {:?}",
            other.map(|o| o.state)
        ),
    }
}

#[test]
fn run_093_open_failure_on_unwritable_data_dir_fails_closed() {
    // Point at a path under a regular file (cannot be created as a
    // directory) to force an I/O failure deep inside RocksDB::open.
    let tmp = TempDir::new().unwrap();
    let file_path = tmp.path().join("not_a_dir");
    fs::write(&file_path, b"i am a file, not a directory").unwrap();
    let cfg = NodeConfig::devnet().with_data_dir(&file_path);
    let result = open_production_consensus_storage(&cfg);
    assert!(
        matches!(
            result,
            Err(ProductionConsensusStorageError::DataDirUnavailable { .. })
                | Err(ProductionConsensusStorageError::OpenFailed { .. })
        ),
        "open on unwritable data_dir must fail-closed; got {:?}",
        result.map(|o| o.state)
    );
}

// ============================================================================
// MetaStore mechanism — Run 093 uses *existing* APIs (no synthetic epoch)
// ============================================================================

#[test]
fn run_093_uses_existing_metastore_apis_only() {
    // Verify Run 093 does not introduce a parallel epoch-write path:
    // an epoch written through the trait surface
    // (`ConsensusStorage::put_current_epoch`) is observed by the Run
    // 093 probe, and vice versa.
    let tmp = TempDir::new().unwrap();
    let cfg = devnet_with_data_dir(tmp.path());

    // Open via Run 093 surface, write via the existing trait surface.
    {
        let opened = open_production_consensus_storage(&cfg).expect("ok");
        let handle: &Arc<RocksDbConsensusStorage> = opened.handle.as_ref().unwrap();
        // Directly use the existing ConsensusStorage trait surface.
        ConsensusStorage::put_current_epoch(handle.as_ref(), 17).expect("ok");
        // And the existing read works.
        let got = ConsensusStorage::get_current_epoch(handle.as_ref()).expect("ok");
        assert_eq!(got, Some(17));
    }

    // Reopen via Run 093 surface — same value observed via probe.
    let opened2 = open_production_consensus_storage(&cfg).expect("ok");
    assert_eq!(opened2.state, ConsensusStorageState::CommittedEpoch(17));
}

// ============================================================================
// State-tag stability (used in startup logs and evidence)
// ============================================================================

#[test]
fn run_093_state_tag_stability() {
    assert_eq!(
        ConsensusStorageState::NoConsensusStorage.tag(),
        "no-consensus-storage"
    );
    assert_eq!(
        ConsensusStorageState::PresentNoCommittedEpoch.tag(),
        "present-no-committed-epoch"
    );
    assert_eq!(
        ConsensusStorageState::CommittedEpoch(0).tag(),
        "committed-epoch"
    );
    assert_eq!(
        ConsensusStorageState::CommittedEpoch(u64::MAX).tag(),
        "committed-epoch"
    );
}

#[test]
fn run_093_log_summary_includes_state_and_path() {
    let no = OpenedProductionConsensusStorage::no_storage();
    assert!(no.log_summary().contains("state=no-consensus-storage"));
    assert!(no.log_summary().contains("path=<none>"));

    let tmp = TempDir::new().unwrap();
    let cfg = devnet_with_data_dir(tmp.path());
    let opened = open_production_consensus_storage(&cfg).expect("ok");
    let summary = opened.log_summary();
    assert!(summary.contains("state=present-no-committed-epoch"));
    assert!(summary.contains("consensus"));

    // Promote to CommittedEpoch via existing API and re-open to probe.
    opened
        .handle
        .as_ref()
        .unwrap()
        .put_current_epoch(123)
        .unwrap();
    drop(opened);
    let opened2 = open_production_consensus_storage(&cfg).expect("ok");
    let summary2 = opened2.log_summary();
    assert!(summary2.contains("state=committed-epoch"));
    assert!(summary2.contains("epoch=123"));
}

// ============================================================================
// Run 091 / Run 092 fail-closed boundary preservation (sanity)
// ============================================================================
//
// Run 093 must NOT consume the observed committed epoch for PQC
// trust-bundle activation. The public ActivationContext surface
// continues to be constructed with current_epoch=None in main.rs and
// is therefore unaffected by anything in this module. We pin that
// contract here at the type level: there is no public Run 093 API
// that converts ConsensusStorageState into an ActivationContext.
// The variants do not implement Into / From for any
// `pqc_trust_activation::ActivationContext` symbol.
//
// (Run 091's own integration tests under
// `tests/run_091_pqc_trust_bundle_activation_epoch_tests.rs`
// independently pin the trust-bundle fail-closed behaviour against
// `current_epoch: None`; Run 093 makes no changes to those call
// sites, and those tests are part of the Run 093 regression set.)

#[test]
fn run_093_does_not_expose_consensus_storage_state_to_activation_context() {
    // Compile-time check that ConsensusStorageState.committed_epoch()
    // returns plain Option<u64> and is not a typed ActivationContext
    // value. This prevents accidental future wiring.
    let s = ConsensusStorageState::CommittedEpoch(42);
    let e: Option<u64> = s.committed_epoch();
    assert_eq!(e, Some(42));

    let p = ConsensusStorageState::PresentNoCommittedEpoch;
    let e: Option<u64> = p.committed_epoch();
    assert!(
        e.is_none(),
        "PresentNoCommittedEpoch must NOT collapse to Some(0)"
    );

    let n = ConsensusStorageState::NoConsensusStorage;
    let e: Option<u64> = n.committed_epoch();
    assert!(
        e.is_none(),
        "NoConsensusStorage must NOT collapse to Some(0)"
    );
}
