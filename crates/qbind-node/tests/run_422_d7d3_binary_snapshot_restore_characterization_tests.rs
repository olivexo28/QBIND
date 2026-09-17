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
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
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
/// This runner records ONLY the executable path and its byte length (a
/// std-only, dependency-free weak fingerprint). It does **not** compute or emit
/// a SHA-256: the authoritative sha256 of the exact release executable is
/// recorded separately, out-of-band, in the D7-D3 evidence doc (computed with
/// `sha256sum`). This keeps a new hashing dependency out of the test crate and
/// avoids any claim that the runner itself emits a content hash.
fn log_executable_provenance(tag: &str, args: &[String]) {
    let bin = qbind_node_bin();
    let len = std::fs::metadata(&bin).map(|m| m.len()).unwrap_or(0);
    // NOTE: `byte_len` is a weak fingerprint only; it is NOT a SHA-256. The
    // sha256 is captured out-of-band (see the D7-D3 evidence doc).
    eprintln!(
        "[d7d3][{tag}] executable={} byte_len={} (no sha256 emitted here) args={:?}",
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
                || line.starts_with("[binary-consensus]")
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
    /// Spawn the `qbind-node` release/dev executable for a protocol-evidence
    /// case. Per-child `env_remove` isolation only — no process-global
    /// environment mutation, so parallel tests never interfere.
    fn spawn(args: &[String]) -> Self {
        let mut command = Command::new(qbind_node_bin());
        command
            .args(args)
            // Isolate inherited environment: no external listener/env may
            // redirect the fixture or bind a non-loopback endpoint. These are
            // per-`Command` removals (not `std::env::set_var`), so they do not
            // affect any other test process.
            .env_remove("QBIND_METRICS_HTTP_ADDR")
            .env_remove("QBIND_MUTUAL_AUTH")
            .env_remove("QBIND_DRAIN_ONCE_DELAY_SECS")
            .env_remove("QBIND_DEVNET_FORGED_INJECTION");
        Self::spawn_command(command, "spawn qbind-node")
    }

    /// Spawn a small **test-only** child command used exclusively by the
    /// runner-control tests (see the `runner_control_*` cases). Kept
    /// deliberately separate from `spawn`, which launches the real qbind-node
    /// protocol binary: these controls exercise the *runner's* outcome
    /// classification, not qbind-node protocol evidence.
    #[cfg(unix)]
    fn sh_child(script: &str) -> Self {
        let mut command = Command::new("sh");
        command.arg("-c").arg(script);
        Self::spawn_command(command, "spawn sh runner-control child")
    }

    /// Common spawn path: wire piped stdio and start the drain threads.
    fn spawn_command(mut command: Command, ctx: &'static str) -> Self {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("{ctx}: {e}"));

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

    /// Number of stderr bytes the capture had to DROP (ring cap or capture
    /// failure). A nonzero value means the captured stderr is truncated, so it
    /// cannot support any assertion that a forbidden *later* marker was absent.
    fn stderr_dropped_bytes(&self) -> usize {
        self.stderr.lock().expect("capture lock").dropped_bytes
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
    /// the FULL `ExitStatus` (exit code AND terminating signal preserved; not
    /// collapsed into an arbitrary integer). A timeout is a HARD test failure
    /// (never an acceptable nonzero refusal): the child is killed/reaped and
    /// the function panics. Captured streams are drained and joined before the
    /// status is returned so callers assess final diagnostics on complete
    /// output.
    fn wait_natural_exit(&mut self, deadline: Duration) -> ExitStatus {
        let start = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.reaped = true;
                    self.join_drain_threads();
                    return status;
                }
                Ok(None) => {
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
                Err(e) => {
                    // Explicit wait-error handling on the normal result path.
                    let err = self.stderr_snapshot();
                    self.kill_and_reap();
                    panic!("TEST FAILURE: try_wait errored: {e}; stderr so far=\n{}", err);
                }
            }
        }
    }

    /// Observe every marker in `markers` while the child is STILL ALIVE, then
    /// deliberately terminate it. Returns a classified [`PositiveObservation`]
    /// (this method never panics on a normal outcome; the caller decides what
    /// is acceptable).
    ///
    /// Reliability properties (Correction B):
    ///
    /// * Liveness is checked FIRST each iteration, so an already-exited child
    ///   is rejected as [`PositiveObservation::ExitedBeforeDeliberateTermination`]
    ///   even if the expected markers were captured.
    /// * When markers are present and the child is alive we kill+wait and
    ///   inspect the REAL `ExitStatus`: a terminating signal ⇒ deliberate
    ///   termination; a natural exit code (the liveness/terminate race lost)
    ///   ⇒ we report the unexpected exit rather than claiming deliberate
    ///   termination.
    ///   Signals are preserved via `ExitStatus`, never collapsed to an integer.
    /// * Kill/wait errors are handled explicitly on the normal result path.
    /// * Captured streams are drained and joined before the returned stderr is
    ///   snapshotted, so callers assess final diagnostics on complete output.
    /// * A deadline is a bounded failure ([`PositiveObservation::Deadline`]).
    fn observe_then_terminate(
        &mut self,
        markers: &[&str],
        deadline: Duration,
    ) -> PositiveObservation {
        let start = Instant::now();
        loop {
            // 1. Liveness FIRST — an already-exited child is rejected even if
            //    its markers were captured.
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.reaped = true;
                    self.join_drain_threads();
                    return PositiveObservation::ExitedBeforeDeliberateTermination {
                        status,
                        stderr: self.stderr_snapshot(),
                    };
                }
                Ok(None) => {}
                Err(e) => {
                    self.kill_and_reap();
                    panic!("TEST FAILURE: try_wait errored: {e}");
                }
            }

            // 2. Child alive: are all markers present?
            let err = self.stderr_snapshot();
            if markers.iter().all(|m| err.contains(m)) {
                // Deliberate termination. Kill + wait, handling errors
                // explicitly, then classify on the ACTUAL status to resolve
                // the liveness/terminate race.
                let kill_res = self.child.kill();
                let wait_res = self.child.wait();
                self.reaped = true;
                self.join_drain_threads();
                let stderr = self.stderr_snapshot();
                match wait_res {
                    Ok(status) => {
                        if let Some(term_signal) = status.signal() {
                            return PositiveObservation::ObservedThenTerminated {
                                stderr,
                                term_signal,
                            };
                        }
                        // Lost the race: the child exited naturally between the
                        // liveness check and the kill. Do NOT claim deliberate
                        // termination — report the recorded unexpected exit.
                        let _ = kill_res;
                        return PositiveObservation::ExitedBeforeDeliberateTermination {
                            status,
                            stderr,
                        };
                    }
                    Err(e) => panic!(
                        "TEST FAILURE: wait after kill errored (kill_ok={}): {e}; stderr=\n{}",
                        kill_res.is_ok(),
                        stderr
                    ),
                }
            }

            // 3. Bounded deadline — timeout is failure.
            if start.elapsed() >= deadline {
                let dropped_bytes = self.stderr_dropped_bytes();
                self.kill_and_reap();
                return PositiveObservation::Deadline {
                    stderr: self.stderr_snapshot(),
                    dropped_bytes,
                };
            }
            thread::sleep(Duration::from_millis(25));
        }
    }
}

/// Classified outcome of [`DrainedChild::observe_then_terminate`].
///
/// Only [`PositiveObservation::ObservedThenTerminated`] is an accepted positive
/// result; the other variants are rejections that a positive case must fail on.
#[derive(Debug)]
enum PositiveObservation {
    /// All markers observed while the child was still alive; the runner then
    /// deliberately terminated it with signal `term_signal`.
    ObservedThenTerminated { stderr: String, term_signal: i32 },
    /// The child exited on its own (natural or unexpected) before deliberate
    /// termination — rejected even if the expected markers were captured. The
    /// full `ExitStatus` is preserved.
    ExitedBeforeDeliberateTermination { status: ExitStatus, stderr: String },
    /// The bounded deadline elapsed before all markers were observed.
    Deadline { stderr: String, dropped_bytes: usize },
}

impl PositiveObservation {
    /// Assert this is the accepted positive outcome (observed-while-alive then
    /// deliberately signal-terminated) and return the captured stderr. Any
    /// other outcome — including an already-exited child that had emitted the
    /// markers — is a hard failure.
    fn expect_observed_then_terminated(self, tag: &str) -> String {
        match self {
            PositiveObservation::ObservedThenTerminated { stderr, term_signal } => {
                assert!(
                    term_signal > 0,
                    "[{tag}] deliberate termination must carry a real signal, got {term_signal}"
                );
                stderr
            }
            other => panic!(
                "TEST FAILURE [{tag}]: expected observed-while-alive-then-deliberately-\
                 terminated positive outcome; got {other:?}"
            ),
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
/// Entry into the LocalMesh **startup function** (`run_local_mesh_node`).
///
/// IMPORTANT boundary: at the reviewed revision this line is printed at the
/// very *beginning* of `run_local_mesh_node`, BEFORE the
/// `BinaryConsensusLoopConfig` is built and BEFORE `spawn_binary_consensus_loop`
/// runs the loop that consumes the restore baseline. Its presence therefore
/// establishes only **entry into the LocalMesh startup dispatch**, not that the
/// engine initializer executed. Do not read this marker as proof that
/// `initialize_from_snapshot_baseline` ran.
const M_LOOP_REACHED: &str = "[binary] LocalMesh mode: starting consensus loop";
/// The **post-baseline-application** observation emitted by the running
/// consensus loop (`run_binary_consensus_loop_with_io`) *after*
/// `engine.initialize_from_snapshot_baseline(...)` has executed
/// (`crates/qbind-node/src/binary_consensus_loop.rs`). This is the earliest
/// existing observation that the engine initializer actually consumed the
/// restore baseline at runtime, so it — not `M_LOOP_REACHED` — is the honest
/// deliberate-termination anchor for the positive cases. It is an existing
/// production `eprintln!`; no instrumentation was added to obtain it.
const M_BASELINE_APPLIED: &str = "[binary-consensus] B5: applied restore baseline: snapshot_height=";
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
// Ordered-marker assertion helper
// ============================================================================

/// Assert every marker in `ordered` is present in `haystack` AND appears in the
/// given order (by first byte offset). Presence alone cannot establish a
/// startup ORDERING claim; this asserts the order explicitly.
fn assert_marker_order(haystack: &str, ordered: &[&str]) {
    let mut last_idx = 0usize;
    let mut last_marker = "<start>";
    for m in ordered {
        match haystack.find(m) {
            Some(idx) => {
                assert!(
                    idx >= last_idx,
                    "startup ordering violated: {m:?} (idx {idx}) precedes {last_marker:?} \
                     (idx {last_idx}); haystack=\n{haystack}"
                );
                last_idx = idx;
                last_marker = m;
            }
            None => panic!("expected ordered marker {m:?} not present; haystack=\n{haystack}"),
        }
    }
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
/// Observe the ordered startup markers THROUGH the post-baseline-application
/// observation (`M_BASELINE_APPLIED`), deliberately terminate the still-alive
/// process at that boundary, reap, then INDEPENDENTLY reopen the RocksDB stores
/// and assert the distinction between epoch-absence and explicit-zero.
///
/// Boundary honesty (Correction A): the deliberate-termination anchor is
/// `M_BASELINE_APPLIED`, the existing observation emitted AFTER
/// `engine.initialize_from_snapshot_baseline(...)` runs — NOT the earlier
/// `M_LOOP_REACHED`, which only marks entry into the LocalMesh startup
/// dispatch. Startup ORDER (not mere presence) is asserted, and the fixture
/// height/starting-view exposed by the existing diagnostics is asserted.
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
        // Anchor on the POST-baseline-application observation so termination
        // implies `initialize_from_snapshot_baseline` actually executed.
        child
            .observe_then_terminate(&[M_BASELINE_APPLIED], POSITIVE_DEADLINE)
            .expect_observed_then_terminated("B1-epoch-absent")
    };
    maybe_dump_child_stderr("B1-epoch-absent", &stderr_absent);
    // Assert the startup ORDER (not just presence): restore → B5 construct →
    // storage open → epoch-absent → LocalMesh dispatch entry → baseline applied.
    assert_marker_order(
        &stderr_absent,
        &[
            M_RESTORE_OK,
            M_B5,
            M_STORAGE_OPEN,
            M_EPOCH_ABSENT,
            M_LOOP_REACHED,
            M_BASELINE_APPLIED,
        ],
    );
    // Assert the fixture height/starting-view exposed by the existing
    // diagnostics (height 111 ⇒ starting_view 112), both at baseline
    // construction and at baseline application.
    assert!(
        stderr_absent
            .contains("[binary] B5: restore-aware consensus start enabled (snapshot_height=111, starting_view=112)"),
        "B5 construction diagnostic must expose the fixture height/starting-view; stderr=\n{}",
        stderr_absent
    );
    assert!(
        stderr_absent
            .contains("[binary-consensus] B5: applied restore baseline: snapshot_height=111 starting_view=112"),
        "baseline-application diagnostic must expose the fixture height/starting-view; stderr=\n{}",
        stderr_absent
    );
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
        child
            .observe_then_terminate(&[M_BASELINE_APPLIED], POSITIVE_DEADLINE)
            .expect_observed_then_terminated("B2-epoch-zero")
    };
    maybe_dump_child_stderr("B2-epoch-zero", &stderr_zero);
    // Startup ORDER: restore → B5 construct → storage open → epoch-persist →
    // LocalMesh dispatch entry → baseline applied.
    assert_marker_order(
        &stderr_zero,
        &[
            M_RESTORE_OK,
            M_B5,
            M_STORAGE_OPEN,
            M_EPOCH_PERSIST,
            M_LOOP_REACHED,
            M_BASELINE_APPLIED,
        ],
    );
    // Fixture height 222 ⇒ starting_view 223, exposed at both diagnostics.
    assert!(
        stderr_zero
            .contains("[binary] B5: restore-aware consensus start enabled (snapshot_height=222, starting_view=223)"),
        "B5 construction diagnostic must expose the fixture height/starting-view; stderr=\n{}",
        stderr_zero
    );
    assert!(
        stderr_zero
            .contains("[binary-consensus] B5: applied restore baseline: snapshot_height=222 starting_view=223"),
        "baseline-application diagnostic must expose the fixture height/starting-view; stderr=\n{}",
        stderr_zero
    );

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

    let (status, stderr, stderr_dropped) = {
        let mut child = DrainedChild::spawn(&args);
        let status = child.wait_natural_exit(NEGATIVE_DEADLINE);
        (status, child.stderr_snapshot(), child.stderr_dropped_bytes())
    };
    maybe_dump_child_stderr("C-epoch-conflict", &stderr);

    // Require the expected NATURAL exit code 1 (from `std::process::exit(1)`),
    // with the full ExitStatus preserved (code, not signal).
    assert_eq!(
        status.code(),
        Some(1),
        "epoch conflict must fail closed with natural exit code 1 (status={status:?}); stderr=\n{}",
        stderr
    );
    assert!(
        status.signal().is_none(),
        "fail-closed refusal must be a natural exit, not a signal (status={status:?}); stderr=\n{}",
        stderr
    );
    // Carry the epoch-conflict-SPECIFIC diagnostic (existing epoch 42 vs
    // snapshot epoch 7), not merely the generic Run 097 failure prefix.
    assert!(
        stderr.contains(M_EPOCH_FATAL),
        "must carry the Run 097 epoch-parity FATAL prefix; stderr=\n{}",
        stderr
    );
    assert!(
        stderr.contains("existing meta:current_epoch=42 but snapshot meta.json declares epoch=7"),
        "must carry the epoch-conflict-specific diagnostic (existing 42 vs snapshot 7); stderr=\n{}",
        stderr
    );
    // A "forbidden later marker absent" assertion is only valid on UNTRUNCATED
    // capture: truncation/capture-failure cannot support an absence claim.
    assert_eq!(
        stderr_dropped, 0,
        "stderr capture was truncated ({stderr_dropped} bytes dropped); cannot assert a \
         forbidden later marker was absent"
    );
    // The consensus loop-dispatch marker must NOT have been reached, and the
    // engine initializer must NOT have run (no baseline-applied observation).
    assert!(
        !stderr.contains(M_LOOP_REACHED),
        "consensus loop dispatch must NOT start when epoch parity fails; stderr=\n{}",
        stderr
    );
    assert!(
        !stderr.contains(M_BASELINE_APPLIED),
        "engine initializer must NOT run when epoch parity fails; stderr=\n{}",
        stderr
    );
    // Earlier stages up to storage-open were reached (rejection is at epoch
    // parity, AFTER restore + storage open). Assert their order too.
    assert_marker_order(&stderr, &[M_RESTORE_OK, M_B5, M_STORAGE_OPEN, M_EPOCH_FATAL]);

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

/// Case D — describe PRECISELY, with typed assertions, what THIS fixture
/// constructed and inspected, and separate observed values from source-backed
/// findings. The signing-state boundary conclusion is NOT-established; nothing
/// here is a universal absence proof.
///
/// Scope honesty (Correction C):
/// * The keyword denylists below are observations about the CONTENT of THIS
///   fixture's `meta.json` and restore marker — they are NOT a universal
///   absence of signing/locking material from any database or restore artifact,
///   and NOT a schema-level guarantee.
/// * `StateSnapshotMeta` is parsed with the EXISTING typed parser
///   (`StateSnapshotMeta::from_json`); no second parser is introduced. Its
///   structure is NOT merely height/block_hash/chain_id/epoch — it also carries
///   `created_at_unix_ms` and the optional Run 117/140 `authority_state` /
///   `authority_state_v2` carriers (omitted from JSON when `None`, as here).
/// * The account-state check is a SINGLE account lookup, not a full-store
///   inventory. The `meta:current_epoch` reads in cases B/C are single-key
///   reads and do not inventory all consensus-database keys.
///
/// Load-bearing negatives (preserved):
/// * Account-state rollback (case A/B) is NOT proof of conflicting signatures.
/// * Epoch equality (case B2) is NOT proof of signing-state continuity.
/// * The production binary performs NO signature demonstration during restore;
///   any signing demonstration (e.g. D7-D2's) is a separate fixture activity,
///   not a child-process observation.
#[test]
fn d7d3_d_signing_state_continuity_is_not_established_by_restore_path() {
    let chain_id = devnet_chain_id();
    let src_state = tempdir().expect("tempdir");
    let snap_root = tempdir().expect("tempdir");
    let data_dir = tempdir().expect("tempdir");
    let snapshot_dir = snap_root.path().join("snap-boundary");
    build_real_snapshot(src_state.path(), &snapshot_dir, chain_id, 444, 4242, Some(5));

    // (1) TYPED metadata inspection via the existing parser. This is the
    //     authoritative structural view; the raw-string denylist that follows
    //     is a scoped CONTENT observation only.
    let meta_bytes = std::fs::read(snapshot_dir.join("meta.json")).expect("read meta.json");
    let parsed = StateSnapshotMeta::from_json(&meta_bytes)
        .expect("meta.json parses with the existing StateSnapshotMeta parser");
    assert_eq!(parsed.height, 444, "typed height");
    assert_eq!(parsed.chain_id, chain_id, "typed chain_id");
    assert_eq!(parsed.epoch, Some(5), "typed epoch (fixture declaration)");
    // The metadata schema carries MORE than height/hash/chain/epoch: a creation
    // timestamp and optional authority-state carriers. In THIS fixture (built
    // with no authority marker) both carriers are absent — recorded honestly,
    // not generalized into a schema-wide claim.
    assert_eq!(parsed.created_at_unix_ms, 1_700_000_000_000, "typed created_at_unix_ms");
    assert!(
        parsed.authority_state.is_none(),
        "this fixture carries no v1 authority_state carrier (absent, not a schema guarantee)"
    );
    assert!(
        parsed.authority_state_v2.is_none(),
        "this fixture carries no v2 authority_state carrier (absent, not a schema guarantee)"
    );

    // (1b) Scoped CONTENT observation of THIS fixture's serialized meta.json:
    //      it contains no signing/vote/lock keyword. NOT a universal-absence or
    //      schema claim.
    let meta_json = String::from_utf8(meta_bytes).expect("meta.json utf8");
    for forbidden in ["signature", "signed_vote", "vote", "locked_qc", "signing", "secret"] {
        assert!(
            !meta_json.contains(forbidden),
            "this fixture's meta.json content carries no {forbidden:?} keyword: {meta_json}"
        );
    }
    assert!(meta_json.contains("\"height\""));
    assert!(meta_json.contains("\"chain_id\""));
    assert!(meta_json.contains("\"epoch\""));

    // (2) What the restore materializes + the audit marker records. Drive the
    //     library restore to inspect the on-disk marker (same content the
    //     binary writes). Again a scoped content observation of THIS marker.
    let outcome = restore_from_snapshot(&snapshot_dir, data_dir.path(), chain_id)
        .expect("restore for boundary inspection");
    let marker = std::fs::read_to_string(data_dir.path().join(RESTORE_MARKER_FILENAME))
        .expect("read restore marker");
    for forbidden in ["signature", "signed_vote", "locked_qc", "signing", "secret"] {
        assert!(
            !marker.contains(forbidden),
            "this restore audit marker's content carries no {forbidden:?} keyword: {marker}"
        );
    }

    // (3) OBSERVED account value: a SINGLE account lookup restores to the
    //     checkpoint value. This is one observed value, not a full-store
    //     inventory and not proof the store holds no other kind of state.
    let restored = RocksDbAccountState::open(&outcome.target_state_dir).expect("reopen restored");
    assert_eq!(restored.get_account_state(&ACCOUNT_ID), AccountState::new(7, 4242));

    // (4) SOURCE-BACKED finding (not a runtime inventory here): the restore
    //     baseline the binary hands to the engine initializer carries only
    //     `snapshot_height` + `snapshot_block_id` (`RestoreBaseline` /
    //     `initialize_from_snapshot_baseline`). Cases B/C observe, at the
    //     executable level, that the initializer ran (M_BASELINE_APPLIED); the
    //     recovery-interface finding that NO per-view vote latch or
    //     anti-equivocation record travels this path is source-traced (see
    //     Run 422 D7-D2), kept separate from the observed values above.
    //     Therefore account-state rollback and epoch equality do NOT establish
    //     signing-state continuity, which remains NOT-established.
    assert_eq!(outcome.meta.height, 444);
    // block_hash is the fixture-declared `[height as u8; 32]` (444 as u8 = 188).
    assert_eq!(outcome.meta.block_hash, [444u32 as u8; 32]);
    assert_eq!(outcome.meta.epoch, Some(5));
}

// ============================================================================
// Runner controls (test-only child command; NOT qbind-node protocol evidence)
// ============================================================================
//
// These cases exercise the OUTCOME CLASSIFICATION of the process runner itself
// using a tiny `sh -c` child, kept deliberately separate from the qbind-node
// protocol cases above. They assert that:
//   * a child that prints the expected marker then exits UNSUCCESSFULLY before
//     observation is REJECTED (not accepted as a positive), with its exit code
//     preserved;
//   * a child that prints the expected marker and stays ALIVE is correctly
//     identified as observed-then-deliberately-terminated;
//   * a missing-marker child hits the bounded deadline and is a FAILURE.
// No process-global environment is mutated, so these run safely in parallel.

/// Short bounded deadline for the runner-control cases (they must not depend on
/// the long protocol deadlines).
#[cfg(unix)]
const RUNNER_CONTROL_DEADLINE: Duration = Duration::from_secs(5);

#[cfg(unix)]
#[test]
fn runner_control_rejects_marker_then_unsuccessful_exit() {
    let marker = "runner-control-marker-A";
    // Print the marker to stderr, then exit unsuccessfully BEFORE observation.
    let script = format!("printf '%s\\n' '{marker}' 1>&2; exit 7");
    let mut child = DrainedChild::sh_child(&script);
    let outcome = child.observe_then_terminate(&[marker], RUNNER_CONTROL_DEADLINE);
    match outcome {
        PositiveObservation::ExitedBeforeDeliberateTermination { status, stderr } => {
            // Exit code preserved (not collapsed), and rejection stands EVEN
            // THOUGH the expected marker was captured.
            assert_eq!(status.code(), Some(7), "unsuccessful exit code preserved");
            assert!(
                stderr.contains(marker),
                "marker WAS captured, yet the already-exited child is still rejected; stderr=\n{stderr}"
            );
        }
        other => panic!("expected rejection of an already-exited positive child, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn runner_control_identifies_deliberate_termination_of_live_marked_child() {
    let marker = "runner-control-marker-B";
    // Print the marker, then stay alive well past the observation window.
    let script = format!("printf '%s\\n' '{marker}' 1>&2; sleep 30");
    let mut child = DrainedChild::sh_child(&script);
    let outcome = child.observe_then_terminate(&[marker], RUNNER_CONTROL_DEADLINE);
    match outcome {
        PositiveObservation::ObservedThenTerminated { stderr, term_signal } => {
            assert!(stderr.contains(marker), "marker observed; stderr=\n{stderr}");
            assert!(term_signal > 0, "deliberate termination carries a real signal");
        }
        other => panic!("expected deliberate-termination identification, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn runner_control_missing_marker_deadline_is_failure() {
    // Alive child that never prints the marker → bounded deadline is a failure.
    let mut child = DrainedChild::sh_child("sleep 30");
    let outcome =
        child.observe_then_terminate(&["never-emitted-marker"], RUNNER_CONTROL_DEADLINE);
    match outcome {
        PositiveObservation::Deadline {
            stderr,
            dropped_bytes,
        } => {
            // The never-emitted marker is genuinely absent, and the capture was
            // untruncated — so absence is a real observation, not a truncation
            // artifact.
            assert!(!stderr.contains("never-emitted-marker"));
            assert_eq!(dropped_bytes, 0, "runner-control child emitted nothing to drop");
        }
        other => panic!("expected a bounded-deadline failure, got {other:?}"),
    }
}