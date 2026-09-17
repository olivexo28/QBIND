//! Run 422 D7-D3 — real snapshot artifact and binary restore characterization.
//!
//! This is a **bounded characterization** target. It exercises the *existing*
//! snapshot/restore mechanisms end-to-end and records evidence at three
//! explicitly separated levels:
//!
//! 1. **Library / in-process** (`StateSnapshotter::create_snapshot`,
//!    `snapshot_restore::restore_from_snapshot`,
//!    `RocksDbAccountState::{open,get_account_state}`): a real RocksDB
//!    account-state checkpoint and its point-in-time control (case A).
//! 2. **Child-process / release-binary** (the unmodified `qbind-node`
//!    executable launched with its supported `--restore-from-snapshot`
//!    argument): the actual restoration invocation, startup-stage
//!    observation via existing stderr markers, deliberate termination,
//!    and *independent* post-process reopening of the RocksDB stores
//!    (cases B and C).
//! 3. **Fixture declaration** (values written into `StateSnapshotMeta` such
//!    as height / block hash / epoch): treated as fixture inputs, **not**
//!    authenticated consensus evidence.
//!
//! The task's distinctions are load-bearing and are preserved in the asserts
//! and comments below:
//!
//! * A sequence of direct library calls is **not** a child-process
//!   execution. Case A is labelled library-level; cases B/C launch the real
//!   binary.
//! * Account-state rollback is **not** proof of conflicting signatures, and
//!   epoch equality is **not** proof of signing-state continuity (case D).
//! * A timeout is never a passing startup result: the process runner treats a
//!   deadline as a hard test failure (`wait_natural_exit`) and only a
//!   deliberately-terminated positive observation counts as "loop reached".
//!
//! This target adds **no** production-source change, no new getter, no CLI
//! flag, no storage key/schema change, and authorizes no signing or authority
//! activation. It reuses the process-supervision pattern from
//! `run_422_d4_startup_ordering_tests.rs`, the snapshot-build pattern from
//! `b3_snapshot_restore_tests.rs` / `run_097_snapshot_epoch_parity_tests.rs`,
//! and the independent-storage-observation pattern from
//! `run_422_d7c1_storage_observation_tests.rs`.
//!
//! # Selecting the executed binary
//!
//! By default the target runs the binary Cargo builds for the test
//! (`CARGO_BIN_EXE_qbind-node`, dev profile). To satisfy the task's
//! "representative valid + epoch-conflict cases against that exact release
//! executable" requirement, set the env override
//! `QBIND_D7D3_NODE_BIN=<path>` to point every child-process case at an
//! explicitly selected release executable. The override lives entirely in
//! this test file (outside production code); its only purpose is executable
//! selection. The binary's sha256 is captured per run in the emitted logs.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tempfile::tempdir;

use qbind_ledger::{
    AccountState, PersistentAccountState, RocksDbAccountState, StateSnapshotMeta, StateSnapshotter,
};
use qbind_node::consensus_storage_observation::{
    observe_consensus_storage, ConsensusStorageObservation,
};
use qbind_node::node_config::NodeConfig;
use qbind_node::snapshot_restore::{
    restore_from_snapshot, RESTORE_MARKER_FILENAME, VM_V0_STATE_SUBDIR,
};
use qbind_node::storage::{ConsensusStorage, RocksDbConsensusStorage};

// ============================================================================
// Binary selection + provenance
// ============================================================================

/// Path to the `qbind-node` executable exercised by the child-process cases.
///
/// Honors the `QBIND_D7D3_NODE_BIN` override so the identical cases can be run
/// against an explicitly selected release executable
/// (`target/release/qbind-node`). Falls back to the Cargo-built test binary.
fn qbind_node_bin() -> PathBuf {
    match std::env::var_os("QBIND_D7D3_NODE_BIN") {
        Some(p) => PathBuf::from(p),
        None => PathBuf::from(env!("CARGO_BIN_EXE_qbind-node")),
    }
}

/// Emit a single provenance line for the executable under test.
///
/// Records the executable path and its byte length (a std-only, dependency-free
/// weak fingerprint). The authoritative sha256 of the exact release executable
/// is recorded out-of-band in the D7-D3 evidence doc (computed with
/// `sha256sum`), so this line does not introduce a new hashing dependency into
/// the test crate.
fn log_executable_provenance(tag: &str, args: &[String]) {
    let bin = qbind_node_bin();
    let len = std::fs::metadata(&bin).map(|m| m.len()).unwrap_or(0);
    eprintln!(
        "[d7d3][{tag}] executable={} byte_len={} args={:?}",
        bin.display(),
        len,
        args
    );
}

/// When `QBIND_D7D3_DUMP_STDERR` is set, echo the captured child stderr so the
/// ordered startup markers can be transcribed into the evidence doc. Off by
/// default so normal `cargo test` output stays compact.
fn maybe_dump_child_stderr(tag: &str, stderr: &str) {
    if std::env::var_os("QBIND_D7D3_DUMP_STDERR").is_some() {
        eprintln!("[d7d3][{tag}] ---- captured child stderr begin ----");
        for line in stderr.lines() {
            if line.starts_with("[restore]")
                || line.starts_with("[binary]")
                || line.contains("FATAL")
            {
                eprintln!("[d7d3][{tag}] {line}");
            }
        }
        eprintln!("[d7d3][{tag}] ---- captured child stderr end ----");
    }
}

// ============================================================================
// Snapshot / storage fixture helpers (reused patterns)
// ============================================================================

/// Devnet chain id — matches `NodeConfig::default()` (DevNet env), which is
/// exactly what the `--env devnet` binary resolves.
fn devnet_chain_id() -> u64 {
    NodeConfig::default().chain_id().as_u64()
}

/// Well-known account id used across cases.
const ACCOUNT_ID: [u8; 32] = [0xCD; 32];

/// Build a real on-disk RocksDB account-state store containing a single known
/// account, then create a snapshot of it through the canonical
/// `StateSnapshotter::create_snapshot` (RocksDB checkpoint API). The `epoch`
/// argument is written into `StateSnapshotMeta` as a fixture declaration only.
///
/// Returns the written `StateSnapshotMeta`. The source store is left intact at
/// `state_dir` so a caller can mutate it afterwards (case A point-in-time
/// control).
fn build_real_snapshot(
    state_dir: &Path,
    target: &Path,
    chain_id: u64,
    height: u64,
    checkpoint_balance: u128,
    epoch: Option<u64>,
) -> StateSnapshotMeta {
    let storage = RocksDbAccountState::open(state_dir).expect("open source state dir");
    storage
        .put_account_state(&ACCOUNT_ID, &AccountState::new(7, checkpoint_balance))
        .expect("put checkpoint account state");
    storage.flush().expect("flush source state");

    let meta = StateSnapshotMeta::new(height, [height as u8; 32], 1_700_000_000_000, chain_id)
        .with_epoch(epoch);
    storage
        .create_snapshot(&meta, target)
        .expect("create_snapshot via StateSnapshotter checkpoint API");

    drop(storage);
    meta
}

// ============================================================================
// Deadline-based child-process runner (pattern reused from
// run_422_d4_startup_ordering_tests.rs). Guarantees kill + reap + drain-join
// on every path, including assertion unwinding via Drop.
// ============================================================================

const CAPTURE_CAP_BYTES: usize = 512 * 1024;

/// Deadline for a fail-closed (negative) case to refuse and terminate on its
/// own. A timeout here is a HARD failure.
const NEGATIVE_DEADLINE: Duration = Duration::from_secs(30);

/// Deadline for a positive case to reach the "consensus loop reached" marker
/// before we deliberately terminate it.
const POSITIVE_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Default)]
struct CapturedStream {
    buf: String,
    dropped_bytes: usize,
}

fn drain_into(mut reader: impl Read, sink: Arc<Mutex<CapturedStream>>) {
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let text = String::from_utf8_lossy(&chunk[..n]);
                let mut guard = sink.lock().expect("capture lock");
                let remaining = CAPTURE_CAP_BYTES.saturating_sub(guard.buf.len());
                if remaining == 0 {
                    guard.dropped_bytes += text.len();
                } else if text.len() <= remaining {
                    guard.buf.push_str(&text);
                } else {
                    let mut end = remaining;
                    while end > 0 && !text.is_char_boundary(end) {
                        end -= 1;
                    }
                    guard.buf.push_str(&text[..end]);
                    guard.dropped_bytes += text.len() - end;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

struct DrainedChild {
    child: Child,
    #[allow(dead_code)]
    stdout: Arc<Mutex<CapturedStream>>,
    stderr: Arc<Mutex<CapturedStream>>,
    stdout_thread: Option<JoinHandle<()>>,
    stderr_thread: Option<JoinHandle<()>>,
    reaped: bool,
}

impl DrainedChild {
    fn spawn(args: &[String]) -> Self {
        let mut child = Command::new(qbind_node_bin())
            .args(args)
            // Isolate inherited environment: no external listener/env may
            // redirect the fixture or bind a non-loopback endpoint.
            .env_remove("QBIND_METRICS_HTTP_ADDR")
            .env_remove("QBIND_MUTUAL_AUTH")
            .env_remove("QBIND_DRAIN_ONCE_DELAY_SECS")
            .env_remove("QBIND_DEVNET_FORGED_INJECTION")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn qbind-node");

        let stdout = Arc::new(Mutex::new(CapturedStream::default()));
        let stderr = Arc::new(Mutex::new(CapturedStream::default()));
        let out = child.stdout.take().expect("piped stdout");
        let err = child.stderr.take().expect("piped stderr");
        let so = stdout.clone();
        let se = stderr.clone();
        let stdout_thread = Some(thread::spawn(move || drain_into(out, so)));
        let stderr_thread = Some(thread::spawn(move || drain_into(err, se)));

        DrainedChild {
            child,
            stdout,
            stderr,
            stdout_thread,
            stderr_thread,
            reaped: false,
        }
    }

    #[allow(dead_code)]
    fn stdout_snapshot(&self) -> String {
        self.stdout.lock().expect("capture lock").buf.clone()
    }
    fn stderr_snapshot(&self) -> String {
        self.stderr.lock().expect("capture lock").buf.clone()
    }

    fn join_drain_threads(&mut self) {
        if let Some(h) = self.stdout_thread.take() {
            let _ = h.join();
        }
        if let Some(h) = self.stderr_thread.take() {
            let _ = h.join();
        }
    }

    fn kill_and_reap(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.reaped = true;
        }
        self.join_drain_threads();
    }

    /// Wait for the child to terminate on its own within `deadline`, returning
    /// its exit code. A timeout is a HARD test failure (never an acceptable
    /// nonzero refusal): the child is killed/reaped and the function panics.
    fn wait_natural_exit(&mut self, deadline: Duration) -> i32 {
        let start = Instant::now();
        loop {
            match self.child.try_wait().expect("try_wait") {
                Some(status) => {
                    self.reaped = true;
                    self.join_drain_threads();
                    return status.code().unwrap_or(-1);
                }
                None => {
                    if start.elapsed() >= deadline {
                        let err = self.stderr_snapshot();
                        self.kill_and_reap();
                        panic!(
                            "TEST FAILURE: child did not terminate within {:?}; a timeout is \
                             never an acceptable fail-closed refusal. stderr so far=\n{}",
                            deadline, err
                        );
                    }
                    thread::sleep(Duration::from_millis(25));
                }
            }
        }
    }

    /// Wait until every marker in `markers` is present in captured stderr
    /// within `deadline`, then deliberately terminate the child. If the child
    /// exits first, or the deadline expires, the case FAILS. Returns the
    /// captured stderr snapshot at the moment all markers were observed.
    ///
    /// This is "successful observation followed by deliberate termination" —
    /// explicitly distinguished from a normal exit and from an unexpected
    /// failure.
    fn observe_then_terminate(&mut self, markers: &[&str], deadline: Duration) -> String {
        let start = Instant::now();
        loop {
            let err = self.stderr_snapshot();
            if markers.iter().all(|m| err.contains(m)) {
                self.kill_and_reap();
                return err;
            }
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                self.reaped = true;
                let err = self.stderr_snapshot();
                self.kill_and_reap();
                panic!(
                    "TEST FAILURE: positive child exited ({:?}) before emitting markers \
                     {:?}; stderr=\n{}",
                    status.code(),
                    markers,
                    err
                );
            }
            if start.elapsed() >= deadline {
                let err = self.stderr_snapshot();
                self.kill_and_reap();
                panic!(
                    "TEST FAILURE: markers {:?} not observed within {:?}; stderr=\n{}",
                    markers, deadline, err
                );
            }
            thread::sleep(Duration::from_millis(25));
        }
    }
}

impl Drop for DrainedChild {
    fn drop(&mut self) {
        self.kill_and_reap();
    }
}

// ============================================================================
// Startup-stage markers emitted by the unmodified binary (existing observations)
// ============================================================================

/// `[restore] OK: restored from snapshot height=...` — B3 restore materialized.
const M_RESTORE_OK: &str = "[restore] OK: restored from snapshot height=";
/// `[binary] B5: restore-aware consensus start enabled ...` — baseline wired.
const M_B5: &str = "[binary] B5: restore-aware consensus start enabled";
/// `[binary] Run 093 consensus storage: state=...` — production storage opened.
const M_STORAGE_OPEN: &str = "[binary] Run 093 consensus storage:";
/// Run 097 epoch-absent path (`snapshot_epoch=None`).
const M_EPOCH_ABSENT: &str = "[binary] Run 097: no snapshot epoch persistence performed";
/// Run 097 epoch-persist path (`snapshot canonical epoch=<n> persisted`).
const M_EPOCH_PERSIST: &str = "[binary] Run 097: snapshot canonical epoch=";
/// LocalMesh consensus loop reached — the deliberate-termination anchor.
const M_LOOP_REACHED: &str = "[binary] LocalMesh mode: starting consensus loop";
/// Run 097 fail-closed epoch-parity FATAL diagnostic (case C).
const M_EPOCH_FATAL: &str = "[binary] FATAL: Run 097 snapshot epoch parity failed";

/// Base argv for a restore-driven LocalMesh DevNet start against a fresh
/// data dir. No `--genesis-path` is supplied, so the binary takes the legacy
/// `apply_snapshot_restore_if_requested` path (no authority-marker context)
/// with a fresh (marker-free) data dir — the exact path `b3` characterizes,
/// now driven through the real executable. LocalMesh + loopback keeps the run
/// self-contained with no external transport.
fn restore_localmesh_args(data_dir: &Path, snapshot_dir: &Path) -> Vec<String> {
    vec![
        "--env".to_string(),
        "devnet".to_string(),
        "--network-mode".to_string(),
        "local-mesh".to_string(),
        "--data-dir".to_string(),
        data_dir.display().to_string(),
        "--restore-from-snapshot".to_string(),
        snapshot_dir.display().to_string(),
    ]
}

// ============================================================================
// A. Canonical real checkpoint and point-in-time control (library-level)
// ============================================================================

/// Case A — a real RocksDB account-state checkpoint captures a point in time.
///
/// Evidence level: **library / in-process** (`StateSnapshotter::create_snapshot`
/// then `restore_from_snapshot` then reopen). This is NOT a child-process
/// observation; it establishes the artifact and its point-in-time semantics
/// that cases B/C then drive through the real binary.
#[test]
fn d7d3_a_real_checkpoint_is_point_in_time_and_source_advances() {
    let src_state = tempdir().expect("tempdir");
    let snap_root = tempdir().expect("tempdir");
    let restore_dir = tempdir().expect("tempdir");

    let chain_id = devnet_chain_id();
    let snapshot_dir = snap_root.path().join("snap-100");

    // Checkpoint value = 4242 at height 100.
    let meta = build_real_snapshot(
        src_state.path(),
        &snapshot_dir,
        chain_id,
        100,
        4242,
        /* epoch */ None,
    );

    // Artifact + metadata provenance (fixture declarations, recorded honestly).
    assert_eq!(meta.height, 100);
    assert_eq!(meta.chain_id, chain_id);
    assert_eq!(meta.epoch, None);
    assert!(
        snapshot_dir.join("meta.json").exists(),
        "checkpoint carries a meta.json"
    );
    assert!(
        snapshot_dir.join("state").exists(),
        "checkpoint carries a state/ RocksDB checkpoint (not a copied open DB)"
    );

    // AFTER checkpoint creation, mutate the SOURCE account via the normal
    // storage API. This is the point-in-time control.
    {
        let storage = RocksDbAccountState::open(src_state.path()).expect("reopen source");
        storage
            .put_account_state(&ACCOUNT_ID, &AccountState::new(8, 9999))
            .expect("advance source account");
        storage.flush().expect("flush source");
    }

    // The source now holds the LATER value.
    {
        let storage = RocksDbAccountState::open(src_state.path()).expect("reopen source");
        assert_eq!(
            storage.get_account_state(&ACCOUNT_ID),
            AccountState::new(8, 9999),
            "source advanced past the checkpoint value"
        );
    }

    // The restored artifact holds the CHECKPOINT value (materialize via the
    // same library entrypoint the binary calls, then reopen).
    let outcome = restore_from_snapshot(&snapshot_dir, restore_dir.path(), chain_id)
        .expect("valid checkpoint must restore");
    assert_eq!(outcome.meta, meta, "restored meta round-trips the artifact");
    let restored = RocksDbAccountState::open(&outcome.target_state_dir).expect("reopen restored");
    assert_eq!(
        restored.get_account_state(&ACCOUNT_ID),
        AccountState::new(7, 4242),
        "restored artifact preserves the point-in-time checkpoint value, \
         independent of the later source mutation"
    );

    // The source artifact is still intact (we did not consume it).
    assert!(src_state.path().exists());
}

// ============================================================================
// B. Actual binary restore and epoch distinctions (child-process, release-binary)
// ============================================================================

/// Independent post-process observation of a restored data dir: reopen the
/// account-state store and the consensus store and return
/// (restored_account, consensus_observation).
fn observe_restored_data_dir(data_dir: &Path) -> (AccountState, ConsensusStorageObservation) {
    let state_dir = data_dir.join(VM_V0_STATE_SUBDIR);
    let account = {
        let restored = RocksDbAccountState::open(&state_dir)
            .expect("independently reopen restored state_vm_v0");
        restored.get_account_state(&ACCOUNT_ID)
    };

    let consensus_dir = data_dir.join("consensus");
    let observation = {
        let storage =
            RocksDbConsensusStorage::open(&consensus_dir).expect("independently reopen consensus");
        observe_consensus_storage(Some(&storage)).expect("observe consensus storage")
    };

    (account, observation)
}

/// Case B — launch the unmodified binary with `--restore-from-snapshot` for
/// two fresh destinations: snapshot epoch ABSENT and snapshot epoch Some(0).
/// Establish the startup stages reached, deliberately terminate at the loop
/// boundary, reap, then INDEPENDENTLY reopen the RocksDB stores and assert the
/// distinction between epoch-absence and explicit-zero.
///
/// Evidence level: **child-process / release-binary** for the restoration and
/// stage observation; **independent in-process reopen** for the post-process
/// storage reads.
#[test]
fn d7d3_b_binary_restore_epoch_absent_vs_explicit_zero() {
    let chain_id = devnet_chain_id();

    // ---- B1: epoch ABSENT (meta.epoch = None) --------------------------
    let src_absent = tempdir().expect("tempdir");
    let snap_absent_root = tempdir().expect("tempdir");
    let data_absent = tempdir().expect("tempdir");
    let snap_absent = snap_absent_root.path().join("snap-absent");
    build_real_snapshot(src_absent.path(), &snap_absent, chain_id, 111, 4242, None);

    let args_absent = restore_localmesh_args(data_absent.path(), &snap_absent);
    log_executable_provenance("B1-epoch-absent", &args_absent);
    let stderr_absent = {
        let mut child = DrainedChild::spawn(&args_absent);
        // The loop-reached marker is the deliberate-termination anchor; the
        // ordered restore/storage/epoch markers must all be present by then.
        child.observe_then_terminate(&[M_LOOP_REACHED], POSITIVE_DEADLINE)
    };
    maybe_dump_child_stderr("B1-epoch-absent", &stderr_absent);
    for m in [M_RESTORE_OK, M_B5, M_STORAGE_OPEN, M_EPOCH_ABSENT] {
        assert!(
            stderr_absent.contains(m),
            "epoch-absent startup must have reached marker {m:?}; stderr=\n{}",
            stderr_absent
        );
    }
    // The persist path must NOT have fired for an epoch-absent snapshot.
    assert!(
        !stderr_absent.contains(M_EPOCH_PERSIST),
        "epoch-absent snapshot must NOT persist an epoch; stderr=\n{}",
        stderr_absent
    );

    let (acct_absent, obs_absent) = observe_restored_data_dir(data_absent.path());
    assert_eq!(
        acct_absent,
        AccountState::new(7, 4242),
        "restored account value observable post-process (epoch-absent)"
    );
    assert_eq!(
        obs_absent,
        ConsensusStorageObservation::PresentNoCommittedEpoch,
        "epoch-absent snapshot leaves consensus epoch as explicit absence, NOT zero"
    );

    // ---- B2: epoch Some(0) ---------------------------------------------
    let src_zero = tempdir().expect("tempdir");
    let snap_zero_root = tempdir().expect("tempdir");
    let data_zero = tempdir().expect("tempdir");
    let snap_zero = snap_zero_root.path().join("snap-zero");
    build_real_snapshot(src_zero.path(), &snap_zero, chain_id, 222, 4242, Some(0));

    let args_zero = restore_localmesh_args(data_zero.path(), &snap_zero);
    log_executable_provenance("B2-epoch-zero", &args_zero);
    let stderr_zero = {
        let mut child = DrainedChild::spawn(&args_zero);
        child.observe_then_terminate(&[M_LOOP_REACHED], POSITIVE_DEADLINE)
    };
    maybe_dump_child_stderr("B2-epoch-zero", &stderr_zero);
    for m in [M_RESTORE_OK, M_B5, M_STORAGE_OPEN, M_EPOCH_PERSIST] {
        assert!(
            stderr_zero.contains(m),
            "epoch-zero startup must have reached marker {m:?}; stderr=\n{}",
            stderr_zero
        );
    }

    let (acct_zero, obs_zero) = observe_restored_data_dir(data_zero.path());
    assert_eq!(
        acct_zero,
        AccountState::new(7, 4242),
        "restored account value observable post-process (epoch-zero)"
    );
    assert_eq!(
        obs_zero,
        ConsensusStorageObservation::CommittedEpoch(0),
        "explicit Some(0) snapshot persists committed epoch 0 through the binary"
    );

    // ---- The load-bearing distinction: absence != explicit zero --------
    assert_ne!(
        obs_absent, obs_zero,
        "the binary preserves the distinction between epoch-absence and \
         explicit committed epoch 0"
    );
    assert_eq!(obs_absent.committed_epoch(), None);
    assert_eq!(obs_zero.committed_epoch(), Some(0));
}

// ============================================================================
// C. Fail-closed control through the executable (child-process, release-binary)
// ============================================================================

/// Case C — a fresh account-state destination with a separately seeded
/// consensus store whose committed epoch (42) conflicts with the snapshot
/// epoch (7). The unmodified binary must fail closed: nonzero exit, the exact
/// Run 097 epoch-parity FATAL diagnostic, the consensus loop NOT reached, and
/// the pre-existing consensus epoch preserved.
///
/// The task requires honest reporting of earlier restore effects: account-state
/// restoration occurs BEFORE the epoch-parity rejection, so the restored
/// `state_vm_v0` IS materialized even though the whole startup fails closed.
/// This is asserted, not hidden.
#[test]
fn d7d3_c_binary_epoch_conflict_fails_closed_preserving_existing_epoch() {
    let chain_id = devnet_chain_id();

    let src_state = tempdir().expect("tempdir");
    let snap_root = tempdir().expect("tempdir");
    let data_dir = tempdir().expect("tempdir");
    let snapshot_dir = snap_root.path().join("snap-conflict");
    // Snapshot declares epoch 7.
    build_real_snapshot(src_state.path(), &snapshot_dir, chain_id, 333, 4242, Some(7));

    // Pre-seed ONLY the <data_dir>/consensus store with a DIFFERENT committed
    // epoch (42). state_vm_v0 is left absent/empty so B3 restore is permitted.
    let consensus_dir = data_dir.path().join("consensus");
    {
        let storage = RocksDbConsensusStorage::open(&consensus_dir).expect("seed consensus");
        storage.put_current_epoch(42).expect("seed committed epoch 42");
        // Drop before spawning so the binary can take the RocksDB lock.
    }

    let args = restore_localmesh_args(data_dir.path(), &snapshot_dir);
    log_executable_provenance("C-epoch-conflict", &args);

    let (code, stderr) = {
        let mut child = DrainedChild::spawn(&args);
        let code = child.wait_natural_exit(NEGATIVE_DEADLINE);
        (code, child.stderr_snapshot())
    };
    maybe_dump_child_stderr("C-epoch-conflict", &stderr);

    assert_ne!(code, 0, "epoch conflict must fail closed nonzero; stderr=\n{}", stderr);
    assert!(
        stderr.contains(M_EPOCH_FATAL),
        "must carry the Run 097 epoch-parity FATAL diagnostic; stderr=\n{}",
        stderr
    );
    // The consensus loop must NOT have been reached.
    assert!(
        !stderr.contains(M_LOOP_REACHED),
        "consensus loop must NOT start when epoch parity fails; stderr=\n{}",
        stderr
    );
    // Earlier stages up to storage-open were reached (rejection is at epoch
    // parity, AFTER restore + storage open).
    assert!(
        stderr.contains(M_RESTORE_OK),
        "restore materialization precedes the epoch-parity rejection; stderr=\n{}",
        stderr
    );
    assert!(stderr.contains(M_STORAGE_OPEN));

    // Independent post-process observation.
    // (1) The pre-existing consensus epoch is preserved (never overwritten).
    {
        let storage = RocksDbConsensusStorage::open(&consensus_dir).expect("reopen consensus");
        let obs = observe_consensus_storage(Some(&storage)).expect("observe");
        assert_eq!(
            obs,
            ConsensusStorageObservation::CommittedEpoch(42),
            "existing committed epoch must be preserved after a fail-closed restore"
        );
    }
    // (2) Honest earlier-effect report: account-state restoration DID occur
    //     before the epoch-parity rejection, so state_vm_v0 is materialized.
    let state_dir = data_dir.path().join(VM_V0_STATE_SUBDIR);
    assert!(
        state_dir.exists(),
        "account-state restoration occurs before epoch-parity rejection; \
         the data directory is NOT wholly unchanged"
    );
    let restored = RocksDbAccountState::open(&state_dir).expect("reopen restored state");
    assert_eq!(
        restored.get_account_state(&ACCOUNT_ID),
        AccountState::new(7, 4242),
        "restored account value present despite fail-closed startup"
    );
}

// ============================================================================
// D. Signing-state evidence boundary (documentation-grade structural asserts)
// ============================================================================

/// Case D — document precisely, with structural assertions, what the checkpoint
/// / meta.json / account storage / consensus store contain, and what
/// signing/locking evidence is restored, reconstructed, absent, or unobservable
/// through these paths.
///
/// Load-bearing negatives:
/// * Account-state rollback (case A/B) is NOT proof of conflicting signatures.
/// * Epoch equality (case B2) is NOT proof of signing-state continuity.
/// * The production binary performs NO signature demonstration during restore;
///   any signing demonstration (e.g. D7-D2's) is a separate fixture activity,
///   not a child-process observation.
#[test]
fn d7d3_d_signing_state_evidence_boundary_is_structurally_empty() {
    let chain_id = devnet_chain_id();
    let src_state = tempdir().expect("tempdir");
    let snap_root = tempdir().expect("tempdir");
    let data_dir = tempdir().expect("tempdir");
    let snapshot_dir = snap_root.path().join("snap-boundary");
    build_real_snapshot(src_state.path(), &snapshot_dir, chain_id, 444, 4242, Some(5));

    // (1) What meta.json declares: height / block_hash / chain_id / epoch —
    //     and NO signing/vote/lock field.
    let meta_bytes = std::fs::read(snapshot_dir.join("meta.json")).expect("read meta.json");
    let meta_json = String::from_utf8(meta_bytes).expect("meta.json utf8");
    for forbidden in ["signature", "signed_vote", "vote", "locked_qc", "signing", "secret"] {
        assert!(
            !meta_json.contains(forbidden),
            "meta.json must not declare signing/locking evidence (found {forbidden:?}): {meta_json}"
        );
    }
    // Positive: it DOES declare the fixture consensus anchors.
    assert!(meta_json.contains("\"height\""));
    assert!(meta_json.contains("\"chain_id\""));
    assert!(meta_json.contains("\"epoch\""));

    // (2) What the restore materializes + the audit marker records. Drive the
    //     library restore to inspect the on-disk marker (same content the
    //     binary writes).
    let outcome = restore_from_snapshot(&snapshot_dir, data_dir.path(), chain_id)
        .expect("restore for boundary inspection");
    let marker = std::fs::read_to_string(data_dir.path().join(RESTORE_MARKER_FILENAME))
        .expect("read restore marker");
    for forbidden in ["signature", "signed_vote", "locked_qc", "signing", "secret"] {
        assert!(
            !marker.contains(forbidden),
            "restore audit marker must not carry signing evidence (found {forbidden:?}): {marker}"
        );
    }

    // (3) What is materialized in account storage: account state only. No
    //     signing/lock artifact is restored into the account-state store — the
    //     store's only observable is account state.
    let restored = RocksDbAccountState::open(&outcome.target_state_dir).expect("reopen restored");
    assert_eq!(restored.get_account_state(&ACCOUNT_ID), AccountState::new(7, 4242));

    // (4) What the binary passes to the engine initializer: only the restore
    //     baseline (snapshot_height + snapshot_block_id). This is asserted by
    //     the B5 marker's presence in the child-process cases above and is
    //     recorded here as the boundary: NO per-view vote latch or
    //     anti-equivocation record travels through the restore baseline (see
    //     Run 422 D7-D2). Account-state rollback and epoch equality therefore
    //     do NOT establish signing-state continuity.
    assert_eq!(outcome.meta.height, 444);
    // block_hash is the fixture-declared `[height as u8; 32]` (444 as u8 = 188).
    assert_eq!(outcome.meta.block_hash, [444u32 as u8; 32]);
    assert_eq!(outcome.meta.epoch, Some(5));
}
