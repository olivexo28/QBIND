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

use std::io::{self, Read};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
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
use qbind_node::restore_completion::{
    publish_record, read_rtr, DestinationId, RestoreTransactionRecord, RtrReadResult, RtrState,
    RESTORE_LOCK_FILENAME, RTR_FILENAME,
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
    /// Terminal outcome of the draining reader loop for this stream.
    ///
    /// `None` while the drain thread is still running; `Some(Ok(()))` on a
    /// clean EOF; `Some(Err(desc))` when a non-`Interrupted` read error ended
    /// the loop. A read failure means the captured buffer is INCOMPLETE and
    /// must not be used to support an absence assertion. `desc` is a bounded
    /// diagnostic description (never the unbounded raw payload).
    read_outcome: Option<Result<(), String>>,
}

/// Lock a capture mutex, recovering the inner data even if a drain thread
/// panicked and poisoned it. This keeps best-effort cleanup (including `Drop`
/// during unwinding) from raising a second panic on a poisoned lock; a poisoned
/// lock is separately surfaced as a capture-thread failure via the join path.
fn lock_recover(m: &Mutex<CapturedStream>) -> MutexGuard<'_, CapturedStream> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Bounded, allocation-light description of a read error (kind only; never the
/// unbounded payload), suitable for diagnostics.
fn bounded_read_error_desc(e: &io::Error) -> String {
    let mut s = format!("read error: kind={:?}", e.kind());
    const MAX: usize = 200;
    if s.len() > MAX {
        s.truncate(MAX);
    }
    s
}

fn drain_into(mut reader: impl Read, sink: Arc<Mutex<CapturedStream>>) {
    let mut chunk = [0u8; 8192];
    // Distinguish successful EOF from a read failure and record it as the
    // stream's terminal outcome, so `stderr_dropped_bytes()==0` alone can no
    // longer be mistaken for complete capture.
    let terminal: Result<(), String> = loop {
        match reader.read(&mut chunk) {
            Ok(0) => break Ok(()),
            Ok(n) => {
                let text = String::from_utf8_lossy(&chunk[..n]);
                let mut guard = lock_recover(&sink);
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
            // A non-Interrupted read error ends capture with a recorded failure
            // (NOT a silent break): the buffer is incomplete from here on.
            Err(e) => break Err(bounded_read_error_desc(&e)),
        }
    };
    lock_recover(&sink).read_outcome = Some(terminal);
}

/// Completed capture integrity for a drained stream, resolvable only AFTER the
/// drain thread has been joined. Distinguishes a clean complete capture, a
/// bounded truncation, a read failure and a capture-thread (join) failure.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CaptureOutcome {
    /// Clean EOF and nothing dropped: the capture is complete and untruncated.
    Complete,
    /// Clean EOF but the ring cap forced some bytes to be dropped.
    Truncated { dropped_bytes: usize },
    /// The draining reader returned a non-`Interrupted` I/O error.
    ReadFailed { detail: String },
    /// The capture thread itself failed to join (it panicked).
    ThreadPanicked,
    /// The drain thread has not finished (outcome not yet recorded).
    StillDraining,
}

impl CaptureOutcome {
    /// Only a clean, complete, untruncated capture may support an assertion
    /// that a forbidden *later* marker was ABSENT.
    fn is_complete(&self) -> bool {
        matches!(self, CaptureOutcome::Complete)
    }
}

/// Classify a stream's completed capture integrity from its recorded terminal
/// outcome plus whether its capture thread failed to join. Pure over inputs so
/// it is deterministically unit-testable without a real child.
fn classify_capture(stream: &CapturedStream, thread_panicked: bool) -> CaptureOutcome {
    if thread_panicked {
        return CaptureOutcome::ThreadPanicked;
    }
    match &stream.read_outcome {
        None => CaptureOutcome::StillDraining,
        Some(Err(detail)) => CaptureOutcome::ReadFailed {
            detail: detail.clone(),
        },
        Some(Ok(())) => {
            if stream.dropped_bytes > 0 {
                CaptureOutcome::Truncated {
                    dropped_bytes: stream.dropped_bytes,
                }
            } else {
                CaptureOutcome::Complete
            }
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
    /// Set true if the stdout/stderr capture thread failed to join (panicked).
    /// A failed join means the corresponding capture is unreliable.
    #[allow(dead_code)]
    stdout_join_failed: bool,
    stderr_join_failed: bool,
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
            stdout_join_failed: false,
            stderr_join_failed: false,
            reaped: false,
        }
    }

    #[allow(dead_code)]
    fn stdout_snapshot(&self) -> String {
        lock_recover(&self.stdout).buf.clone()
    }
    fn stderr_snapshot(&self) -> String {
        lock_recover(&self.stderr).buf.clone()
    }

    /// Number of stderr bytes the capture had to DROP (ring cap). A nonzero
    /// value means the captured stderr is truncated, so it cannot support any
    /// assertion that a forbidden *later* marker was absent. This is a raw
    /// count only; use [`DrainedChild::stderr_capture`] for the full integrity
    /// classification (which also reflects read/join failures).
    #[allow(dead_code)]
    fn stderr_dropped_bytes(&self) -> usize {
        lock_recover(&self.stderr).dropped_bytes
    }

    /// Completed capture integrity for stderr. Only meaningful AFTER the drain
    /// threads have been joined (otherwise `StillDraining`). Reflects a read
    /// failure, a truncation, a capture-thread (join) failure, or a clean
    /// complete capture. A missing-marker/absence assertion must require
    /// [`CaptureOutcome::Complete`].
    fn stderr_capture(&self) -> CaptureOutcome {
        // Read the join flag WITHOUT locking first: if the capture thread
        // panicked the mutex may be poisoned, but `lock_recover` still yields
        // the inner data, so classification never itself panics.
        classify_capture(&lock_recover(&self.stderr), self.stderr_join_failed)
    }

    fn join_drain_threads(&mut self) {
        // Record (do not discard) capture-thread join failures: a panicked
        // drain thread means that stream's capture is unreliable.
        if let Some(h) = self.stdout_thread.take() {
            if h.join().is_err() {
                self.stdout_join_failed = true;
            }
        }
        if let Some(h) = self.stderr_thread.take() {
            if h.join().is_err() {
                self.stderr_join_failed = true;
            }
        }
    }

    fn kill_and_reap(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            // Only mark cleanup complete when reaping actually succeeded.
            if self.child.wait().is_ok() {
                self.reaped = true;
            }
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
    /// Reliability properties (Correction B1):
    ///
    /// * Liveness is checked FIRST each iteration, so an already-exited child
    ///   is rejected as [`PositiveObservation::ExitedBeforeDeliberateTermination`]
    ///   even if the expected markers were captured.
    /// * When markers are present and the child is alive we request the kill and
    ///   reap, preserving BOTH the termination-request result and the full
    ///   `ExitStatus`. Only a SUCCESSFUL kill request whose observed terminating
    ///   signal equals the expected SIGKILL is accepted
    ///   ([`PositiveObservation::ObservedThenTerminated`]). A natural exit (the
    ///   liveness/terminate race lost) ⇒
    ///   [`PositiveObservation::ExitedBeforeDeliberateTermination`]; a different
    ///   terminating signal or a failed kill request ⇒
    ///   [`PositiveObservation::UnexpectedTermination`]. Signals are preserved
    ///   via `ExitStatus`, never collapsed to an integer.
    /// * Wait errors are handled explicitly; cleanup is NOT marked complete when
    ///   reaping failed (so `Drop` retries).
    /// * Captured streams are drained and joined before the returned stderr is
    ///   snapshotted, and the capture integrity ([`CaptureOutcome`]) is carried
    ///   on the positive result so it cannot rest on truncated/failed capture.
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
                // Deliberate termination. Request the kill and reap, preserving
                // BOTH the termination-request result and the full ExitStatus.
                // Classify on the ACTUAL status: only a SUCCESSFUL kill request
                // whose observed terminating signal equals the expected SIGKILL
                // is an accepted deliberate termination. A natural exit (the
                // liveness/terminate race lost), a different terminating signal
                // (e.g. a crash), or a failed kill request are all rejected.
                let kill_res = self.child.kill();
                let wait_res = self.child.wait();
                match wait_res {
                    Ok(status) => {
                        // Reaping succeeded → cleanup complete.
                        self.reaped = true;
                        self.join_drain_threads();
                        let stderr = self.stderr_snapshot();
                        match classify_termination(
                            kill_res.is_ok(),
                            status,
                            EXPECTED_TERMINATION_SIGNAL,
                        ) {
                            TerminationClass::DeliberatelyTerminated { term_signal } => {
                                return PositiveObservation::ObservedThenTerminated {
                                    stderr,
                                    term_signal,
                                    capture: self.stderr_capture(),
                                };
                            }
                            TerminationClass::NaturalExit { .. } => {
                                return PositiveObservation::ExitedBeforeDeliberateTermination {
                                    status,
                                    stderr,
                                };
                            }
                            TerminationClass::UnexpectedSignal { term_signal } => {
                                return PositiveObservation::UnexpectedTermination {
                                    status,
                                    stderr,
                                    detail: format!(
                                        "terminating signal {term_signal} != expected \
                                         SIGKILL {EXPECTED_TERMINATION_SIGNAL}"
                                    ),
                                };
                            }
                            TerminationClass::KillRequestFailed => {
                                return PositiveObservation::UnexpectedTermination {
                                    status,
                                    stderr,
                                    detail: "kill request failed; termination not \
                                             attributable to the runner"
                                        .to_string(),
                                };
                            }
                        }
                    }
                    // Explicit wait-error handling: reaping failed, so cleanup
                    // is NOT marked complete (Drop retries).
                    Err(e) => {
                        self.join_drain_threads();
                        let stderr = self.stderr_snapshot();
                        panic!(
                            "TEST FAILURE: wait after kill errored (kill_ok={}): {e}; stderr=\n{}",
                            kill_res.is_ok(),
                            stderr
                        );
                    }
                }
            }

            // 3. Bounded deadline — timeout is failure.
            if start.elapsed() >= deadline {
                self.kill_and_reap();
                return PositiveObservation::Deadline {
                    stderr: self.stderr_snapshot(),
                    capture: self.stderr_capture(),
                };
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    /// Establish, via a bounded PROCESS-STATUS wait (repeated `try_wait`, NOT a
    /// fixed sleep hoping the child finished), that the child has actually
    /// exited. Returns the completed `ExitStatus`, which `std` also caches in
    /// the `Child`, so a following [`DrainedChild::observe_then_terminate`]
    /// deterministically takes its already-exited branch instead of racing the
    /// kill against a natural exit. Panics on deadline.
    fn establish_exit(&mut self, deadline: Duration) -> ExitStatus {
        let start = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return status,
                Ok(None) => {
                    if start.elapsed() >= deadline {
                        self.kill_and_reap();
                        panic!(
                            "TEST FAILURE: runner-control child did not exit within {deadline:?}"
                        );
                    }
                    // Poll interval only (a real status wait), not a fixed
                    // duration standing in for the child's completion.
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    self.kill_and_reap();
                    panic!("TEST FAILURE: try_wait errored while establishing exit: {e}");
                }
            }
        }
    }

    /// Wait until the child has emitted `marker` on stderr WHILE STILL ALIVE,
    /// using a bounded status/marker poll (not a fixed sleep). Returns `true`
    /// once the marker is observed with the child still running; returns `false`
    /// if the child exits before the marker appears or the deadline elapses.
    /// The child is left running on success so the caller can hold it (e.g. as a
    /// destination-lock owner) while spawning a competing process.
    fn wait_for_marker_alive(&mut self, marker: &str, deadline: Duration) -> bool {
        let start = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(_status)) => {
                    // Exited before the marker: not a live holder.
                    return false;
                }
                Ok(None) => {}
                Err(e) => {
                    self.kill_and_reap();
                    panic!("TEST FAILURE: try_wait errored while waiting for marker: {e}");
                }
            }
            if self.stderr_snapshot().contains(marker) {
                return true;
            }
            if start.elapsed() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(25));
        }
    }
}

/// Deliberate-termination classification result over a completed termination
/// request. Pure over its inputs so it is deterministically unit-testable with
/// constructed `ExitStatus` values (no scheduling dependence).
#[derive(Debug, PartialEq, Eq)]
enum TerminationClass {
    /// The requested kill succeeded AND the child terminated with exactly the
    /// expected signal — the only accepted deliberate termination.
    DeliberatelyTerminated { term_signal: i32 },
    /// The child exited naturally (an exit code, no terminating signal): the
    /// liveness/terminate race was lost. NOT a deliberate termination.
    NaturalExit { code: Option<i32> },
    /// The child terminated on a DIFFERENT signal than requested (e.g. a crash
    /// signal that arrived during the race). NOT accepted.
    UnexpectedSignal { term_signal: i32 },
    /// The kill request itself failed, so termination is not attributable to
    /// the runner. NEVER an accepted positive outcome, even if the observed
    /// signal happens to match.
    KillRequestFailed,
}

/// On Unix, `Child::kill()` sends SIGKILL (9). A deliberate termination is
/// accepted ONLY when the requested kill succeeded and the observed terminating
/// signal is exactly this value. (`std` has no SIGKILL constant; 9 is the
/// POSIX-fixed value.)
const EXPECTED_TERMINATION_SIGNAL: i32 = 9;

/// Classify a completed termination request. A natural exit is reported
/// regardless of the kill result; a terminating signal is accepted only when
/// the kill succeeded and the signal matches `expected_signal`.
fn classify_termination(
    kill_succeeded: bool,
    status: ExitStatus,
    expected_signal: i32,
) -> TerminationClass {
    match status.signal() {
        None => TerminationClass::NaturalExit {
            code: status.code(),
        },
        Some(_) if !kill_succeeded => TerminationClass::KillRequestFailed,
        Some(sig) if sig == expected_signal => {
            TerminationClass::DeliberatelyTerminated { term_signal: sig }
        }
        Some(sig) => TerminationClass::UnexpectedSignal { term_signal: sig },
    }
}

/// Classified outcome of [`DrainedChild::observe_then_terminate`].
///
/// Only [`PositiveObservation::ObservedThenTerminated`] is an accepted positive
/// result; the other variants are rejections that a positive case must fail on.
#[derive(Debug)]
enum PositiveObservation {
    /// All markers observed while the child was still alive; the runner then
    /// deliberately terminated it, the kill request succeeded, and the observed
    /// terminating signal matched the expected SIGKILL. `capture` records the
    /// stderr capture integrity so a positive result cannot silently rest on
    /// truncated/failed capture.
    ObservedThenTerminated {
        stderr: String,
        term_signal: i32,
        capture: CaptureOutcome,
    },
    /// The child exited on its own (natural) before deliberate termination —
    /// rejected even if the expected markers were captured. The full
    /// `ExitStatus` is preserved.
    ExitedBeforeDeliberateTermination { status: ExitStatus, stderr: String },
    /// The child terminated, but NOT as an accepted deliberate termination: a
    /// different terminating signal, or the kill request itself failed. Never a
    /// positive. The full `ExitStatus` and a bounded `detail` are preserved
    /// (surfaced via `Debug` in the caller's failure panic).
    #[allow(dead_code)]
    UnexpectedTermination {
        status: ExitStatus,
        stderr: String,
        detail: String,
    },
    /// The bounded deadline elapsed before all markers were observed.
    Deadline {
        stderr: String,
        capture: CaptureOutcome,
    },
}

impl PositiveObservation {
    /// Assert this is the accepted positive outcome (observed-while-alive then
    /// deliberately SIGKILL-terminated on a SUCCESSFUL kill request) AND the
    /// stderr capture was complete/untruncated, then return the captured
    /// stderr. Any other outcome — an already-exited child that had emitted the
    /// markers, a different terminating signal, a failed kill, a deadline, or a
    /// positive whose capture was truncated/failed — is a hard failure.
    fn expect_observed_then_terminated(self, tag: &str) -> String {
        match self {
            PositiveObservation::ObservedThenTerminated {
                stderr,
                term_signal,
                capture,
            } => {
                assert_eq!(
                    term_signal, EXPECTED_TERMINATION_SIGNAL,
                    "[{tag}] deliberate termination must carry the expected SIGKILL \
                     {EXPECTED_TERMINATION_SIGNAL}, got {term_signal}"
                );
                assert!(
                    capture.is_complete(),
                    "[{tag}] a positive observation requires complete, untruncated stderr \
                     capture; got {capture:?}"
                );
                stderr
            }
            other => panic!(
                "TEST FAILURE [{tag}]: expected observed-while-alive-then-deliberately-\
                 SIGKILL-terminated positive outcome with complete capture; got {other:?}"
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
/// Run 097 fail-closed epoch-parity FATAL diagnostic (legacy post-materialization
/// path). **Run 422 D7-D5:** the corrected binary no longer reaches this
/// diagnostic for a requested restore over a conflicting present epoch — it now
/// refuses earlier, before materialization (see [`M_D7D5_REJECT`]). This marker
/// is retained only to assert its ABSENCE in the corrected pre-materialization
/// rejection path.
const M_EPOCH_FATAL: &str = "[binary] FATAL: Run 097 snapshot epoch parity failed";
/// **Run 422 D7-D5.** The pre-materialization consensus epoch-conflict refusal
/// emitted by `main.rs` from the restore epoch-precheck closure BEFORE any
/// account-state materialization or audit-marker write. See
/// `crates/qbind-node/src/main.rs` and
/// `crates/qbind-node/src/production_consensus_storage.rs`
/// (`evaluate_restore_epoch_compatibility`).
const M_D7D5_REJECT: &str =
    "[restore] FATAL: refused by Run 422 D7-D5 consensus epoch-conflict check";
/// **Run 422 D7-D5.** The `RestoreError::ConsensusEpochConflict` `Display`
/// substring surfaced by `main.rs` as `[restore] ERROR: <this>` immediately
/// before `std::process::exit(1)`.
const M_D7D5_REJECT_ERROR: &str = "restore-from-snapshot refused by consensus epoch-conflict check";
/// D7-D4: ordinary-startup line printed when `--restore-from-snapshot` is NOT
/// requested (`apply_snapshot_restore_if_requested` returned `Ok(None)`).
const M_NO_RESTORE: &str = "[restore] no --restore-from-snapshot requested; normal startup.";
/// D7-D4: the `TargetStateNotEmpty` refusal diagnostic surfaced when the restore
/// flag is repeated over an already-restored (non-empty) `state_vm_v0` — the
/// `Display` string of `RestoreError::TargetStateNotEmpty` (see
/// `crates/qbind-node/src/snapshot_restore.rs`). Printed by `main.rs` as
/// `[restore] ERROR: <this>` immediately before `std::process::exit(1)`.
const M_TARGET_NOT_EMPTY: &str = "restore-from-snapshot target state directory is not empty:";
/// D7-D4: the honest last-observed boundary for an ordinary (no-baseline)
/// startup. Emitted at the START of `run_binary_consensus_loop_with_io`
/// (`crates/qbind-node/src/binary_consensus_loop.rs`) AFTER the (absent)
/// baseline branch, so its presence establishes that the consensus loop
/// function actually began running — while its `restore_baseline=false` field
/// confirms NO snapshot baseline was applied. It is NOT proof of engine
/// recovery of any mixed account/epoch state.
const M_CONSENSUS_LOOP_STARTED: &str = "[binary-consensus] Starting consensus loop:";

/// **Run 422 D7-D5 correction A.** The pre-storage-open refusal emitted by
/// `main.rs` when a requested `--restore-from-snapshot` is combined with any
/// CLI validation/apply exit mode (`cli_storage_exit_mode_active`). This
/// refusal fires BEFORE the early consensus-storage open, before account-state
/// materialization, and before any restore-marker write. See
/// `crates/qbind-node/src/main.rs`.
const M_D7D5_CLI_COMBO_REJECT: &str =
    "[binary] FATAL: refused by Run 422 D7-D5: --restore-from-snapshot is \
     unsupported in combination with the CLI validation/apply exit mode(s):";

/// **Run 422 D7-D8.** The durable-INTENT publication line printed by the
/// guarded restore before any account-state copy.
const M_D7D8_INTENT_PUBLISHED: &str = "[restore] D7-D8 durable INTENT published";

/// **Run 422 D7-D8.** The durable-COMPLETE publication line printed only after
/// every prerequisite effect (copy, sync, audit, epoch barrier) has succeeded.
const M_D7D8_COMPLETE_PUBLISHED: &str = "[restore] D7-D8 durable COMPLETE published";

/// **Run 422 D7-D8.** The ordinary-startup guard refusal over a tracked
/// interrupted restore (a valid final `INTENT`). INTENT may be observed but is
/// never admitted.
const M_D7D8_ORDINARY_REFUSE_INTENT: &str =
    "refused by Run 422 D7-D8 ordinary-startup guard: a tracked interrupted restore (INTENT)";

/// **Run 422 D7-D8.** The requested-restore precondition refusal when an RTR
/// (`INTENT` or `COMPLETE`) already occupies the destination.
const M_D7D8_PRECOND_OCCUPIED: &str =
    "refused by Run 422 D7-D8: a restore-transaction record is already present";

/// **Run 422 D7-D8 (Correction A/B).** The protected VM-v0 persistent
/// account-state open line. It is emitted ONLY for the VM-v0 execution profile
/// and, on a completed/ordinary-restart destination, strictly AFTER the durable
/// INTENT->COMPLETE completion boundary.
const M_VM_V0_OPENED: &str = "[vm-v0] opened persistent state at";

/// **Run 422 D7-D8 (Correction B).** The existing-only open mode suffix: a
/// COMPLETE-admitted destination must never create a missing restored database.
const M_VM_V0_MODE_EXISTING: &str = "(mode=existing-only)";

/// **Run 422 D7-D8 (Correction B).** The fail-closed VM-v0 open refusal emitted
/// when a COMPLETE-admitted destination's restored database cannot be opened
/// existing-only (absent/unrelated-only/unreadable) — no silent re-init.
const M_T164_ERROR: &str = "[T164] ERROR";

/// **Run 422 D7-D8 (Correction B).** The ordinary-startup guard refusal when a
/// COMPLETE record is present but the installed state is missing/empty.
const M_D7D8_MISSING_STATE: &str = "required installed state is missing/empty/unreadable";

/// **Run 422 D7-D8.** The ordinary-startup guard proceed line for a valid
/// COMPLETE whose installed state is present.
const M_D7D8_GUARD_PROCEED_COMPLETE: &str = "valid COMPLETE with installed state present";

/// **Run 422 D7-D8 (§5.5).** The advisory exclusive destination-lock acquisition
/// line, emitted once the process owns `<data_dir>/restore.lock`.
const M_D7D8_LOCK_ACQUIRED: &str =
    "Run 422 D7-D8: acquired advisory exclusive destination lock";

/// **Run 422 D7-D8 (§5.5).** The fail-closed lock-contention refusal emitted
/// when a competing process cannot acquire the destination lock. This is a
/// SPECIFIC lock-contention refusal, distinct from a port collision or generic
/// startup error.
const M_D7D8_LOCK_CONTENDED: &str =
    "could not acquire the advisory exclusive destination lock";

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

/// Base argv for an ORDINARY LocalMesh DevNet start — identical to
/// [`restore_localmesh_args`] except the `--restore-from-snapshot` option and
/// its argument are omitted (equivalent environment, network mode, and data
/// directory). Used by the D7-D4 WITHOUT-flag restart (case B) and the
/// fresh-directory control (case C).
fn ordinary_localmesh_args(data_dir: &Path) -> Vec<String> {
    vec![
        "--env".to_string(),
        "devnet".to_string(),
        "--network-mode".to_string(),
        "local-mesh".to_string(),
        "--data-dir".to_string(),
        data_dir.display().to_string(),
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
            M_STORAGE_OPEN,
            M_RESTORE_OK,
            M_B5,
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
            M_STORAGE_OPEN,
            M_RESTORE_OK,
            M_B5,
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

/// **Run 422 D7-D5 — compatible present-epoch controls (child-process,
/// release-binary).** Complements `d7d3_b` (None/None and Some(0)/None) with the
/// two remaining COMPATIBLE matrix rows that involve a present committed epoch:
///
///   * `Some(n)/None`  — a nonzero snapshot epoch into storage with no committed
///     epoch: restore SUCCEEDS, then persists `n` (CommittedEpoch(n)).
///   * `Some(n)/Some(n)` — matching present epochs: restore SUCCEEDS and the
///     matching epoch is NOT overwritten (persist is a no-op; epoch preserved).
///
/// Both must pass the D7-D5 pre-materialization compatibility check (they are
/// compatible), reach baseline application, and leave the expected committed
/// epoch. Evidence level: child-process/release-binary for restoration + staged
/// observation; independent in-process reopen for the post-process storage read.
#[test]
fn d7d5_b_compatible_present_epochs_reach_baseline() {
    let chain_id = devnet_chain_id();

    // ---- Some(n)/None : nonzero snapshot epoch into fresh storage ----------
    let src_n = tempdir().expect("tempdir");
    let snap_n_root = tempdir().expect("tempdir");
    let data_n = tempdir().expect("tempdir");
    let snap_n = snap_n_root.path().join("snap-n");
    build_real_snapshot(src_n.path(), &snap_n, chain_id, 555, 4242, Some(7));

    let args_n = restore_localmesh_args(data_n.path(), &snap_n);
    log_executable_provenance("D5-B-some-n-into-fresh", &args_n);
    let stderr_n = {
        let mut child = DrainedChild::spawn(&args_n);
        child
            .observe_then_terminate(&[M_BASELINE_APPLIED], POSITIVE_DEADLINE)
            .expect_observed_then_terminated("D5-B-some-n-into-fresh")
    };
    maybe_dump_child_stderr("D5-B-some-n-into-fresh", &stderr_n);
    // Compatible: restore → B5 → storage open → epoch-persist(7) → loop → baseline.
    assert_marker_order(
        &stderr_n,
        &[
            M_STORAGE_OPEN,
            M_RESTORE_OK,
            M_B5,
            M_EPOCH_PERSIST,
            M_LOOP_REACHED,
            M_BASELINE_APPLIED,
        ],
    );
    // The D7-D5 check must NOT have refused a compatible restore.
    assert!(
        !stderr_n.contains(M_D7D5_REJECT),
        "a compatible Some(n)/None restore must not be refused; stderr=\n{}",
        stderr_n
    );
    let (acct_n, obs_n) = observe_restored_data_dir(data_n.path());
    assert_eq!(acct_n, AccountState::new(7, 4242));
    assert_eq!(
        obs_n,
        ConsensusStorageObservation::CommittedEpoch(7),
        "nonzero snapshot epoch persisted into previously-uncommitted storage"
    );

    // ---- Some(n)/Some(n) : matching present epochs (not overwritten) -------
    let src_m = tempdir().expect("tempdir");
    let snap_m_root = tempdir().expect("tempdir");
    let data_m = tempdir().expect("tempdir");
    let snap_m = snap_m_root.path().join("snap-m");
    build_real_snapshot(src_m.path(), &snap_m, chain_id, 666, 4242, Some(7));
    // Pre-seed the consensus store with the SAME committed epoch (7).
    {
        let storage = RocksDbConsensusStorage::open(&data_m.path().join("consensus"))
            .expect("seed consensus");
        storage.put_current_epoch(7).expect("seed committed epoch 7");
    }

    let args_m = restore_localmesh_args(data_m.path(), &snap_m);
    log_executable_provenance("D5-B-matching-epochs", &args_m);
    let stderr_m = {
        let mut child = DrainedChild::spawn(&args_m);
        child
            .observe_then_terminate(&[M_BASELINE_APPLIED], POSITIVE_DEADLINE)
            .expect_observed_then_terminated("D5-B-matching-epochs")
    };
    maybe_dump_child_stderr("D5-B-matching-epochs", &stderr_m);
    // Compatible (matching): restore → B5 → storage open → loop → baseline.
    // No M_EPOCH_PERSIST: a matching epoch is NOT overwritten.
    assert_marker_order(
        &stderr_m,
        &[M_STORAGE_OPEN, M_RESTORE_OK, M_B5, M_LOOP_REACHED, M_BASELINE_APPLIED],
    );
    assert!(
        !stderr_m.contains(M_D7D5_REJECT),
        "matching present epochs must not be refused; stderr=\n{}",
        stderr_m
    );
    assert!(
        !stderr_m.contains(M_EPOCH_PERSIST),
        "a matching committed epoch must NOT be overwritten/re-persisted; stderr=\n{}",
        stderr_m
    );
    let (acct_m, obs_m) = observe_restored_data_dir(data_m.path());
    assert_eq!(acct_m, AccountState::new(7, 4242));
    assert_eq!(
        obs_m,
        ConsensusStorageObservation::CommittedEpoch(7),
        "matching committed epoch (7) preserved through a compatible restore"
    );
}

// ============================================================================
// C. Pre-materialization epoch-conflict rejection (child-process, release-binary)
//    **Run 422 D7-D5 migration of the historical D3 case C.**
// ============================================================================
//
// Historical note (kept honest): at the accepted D7-D3/D4 SHAs the binary
// restored `state_vm_v0` and wrote the restore audit marker BEFORE the Run 097
// epoch-parity rejection, leaving a *partial destination*. That historical
// effect ordering is documented in
// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` and is NOT reproduced here
// with the corrected executable. The corrected binary refuses the conflicting
// restore BEFORE any account-state materialization or audit-marker write, so no
// partial destination is created. This section asserts that corrected
// pre-materialization refusal; the D7-D4 continuations below operate over a
// clearly-labeled *legacy-layout fixture* constructed via library calls (not
// produced by the corrected executable).

/// A **legacy** partially-restored destination, constructed via library
/// materialization to imitate the on-disk layout that the *pre-fix* binary left
/// behind (restored `state_vm_v0` alongside a preserved, conflicting consensus
/// `CommittedEpoch(42)`). This is an imported/pre-fix layout fixture — it is
/// NOT produced by the corrected executable — used to characterize behavior of
/// the corrected binary when it encounters such a directory.
struct LegacyPartialRestoreDestination {
    _src_state: tempfile::TempDir,
    _snap_root: tempfile::TempDir,
    /// The legacy partial destination (`state_vm_v0` materialized + consensus
    /// `CommittedEpoch(42)`).
    data_dir: tempfile::TempDir,
    /// The snapshot directory declaring epoch 7 (reused by the WITH-flag retry).
    snapshot_dir: PathBuf,
    /// `<data_dir>/state_vm_v0` (materialized by the library restore).
    _state_dir: PathBuf,
    /// Full contents of `<data_dir>/RESTORED_FROM_SNAPSHOT.json` written by the
    /// library restore. Recorded so a later refused/ordinary start can be shown
    /// NOT to append or replace it.
    restore_marker: String,
}

/// Construct a legacy partial-restore destination WITHOUT the corrected binary:
/// seed the consensus store with a conflicting `CommittedEpoch(42)`, then drive
/// the existing library restore (`restore_from_snapshot`, which performs NO
/// consensus epoch check) to materialize `state_vm_v0` (account 7/4242) and the
/// restore audit marker. The result is exactly the pre-fix on-disk layout, built
/// from real snapshot/library materialization — not a failure produced by the
/// corrected executable.
fn build_legacy_partial_restore_destination(tag: &str) -> LegacyPartialRestoreDestination {
    let chain_id = devnet_chain_id();

    let src_state = tempdir().expect("tempdir");
    let snap_root = tempdir().expect("tempdir");
    let data_dir = tempdir().expect("tempdir");
    let snapshot_dir = snap_root.path().join("snap-legacy");
    // Snapshot declares epoch 7.
    build_real_snapshot(src_state.path(), &snapshot_dir, chain_id, 333, 4242, Some(7));

    // Seed ONLY the consensus store with a DIFFERENT committed epoch (42).
    let consensus_dir = data_dir.path().join("consensus");
    {
        let storage = RocksDbConsensusStorage::open(&consensus_dir).expect("seed consensus");
        storage.put_current_epoch(42).expect("seed committed epoch 42");
    }

    // Library materialization (no epoch check) → the legacy partial layout.
    let outcome = restore_from_snapshot(&snapshot_dir, data_dir.path(), chain_id)
        .expect("library restore materializes the legacy partial layout");
    let state_dir = outcome.target_state_dir.clone();

    let restore_marker = std::fs::read_to_string(data_dir.path().join(RESTORE_MARKER_FILENAME))
        .expect("read restore audit marker written by the library restore");
    assert!(
        !restore_marker.is_empty(),
        "[{tag}] the library restore writes a restore audit marker line"
    );

    // Confirm the constructed layout matches the pre-fix expectation.
    let (acct, obs) = observe_restored_data_dir(data_dir.path());
    assert_eq!(acct, AccountState::new(7, 4242), "[{tag}] legacy state materialized");
    assert_eq!(
        obs,
        ConsensusStorageObservation::CommittedEpoch(42),
        "[{tag}] legacy consensus epoch 42 present"
    );

    LegacyPartialRestoreDestination {
        _src_state: src_state,
        _snap_root: snap_root,
        data_dir,
        snapshot_dir,
        _state_dir: state_dir,
        restore_marker,
    }
}

/// **Run 422 D7-D5 (migrated D3 case C).** A fresh account-state destination is
/// seeded ONLY with a conflicting consensus `CommittedEpoch(42)`; the snapshot
/// declares epoch 7. The corrected binary WITH `--restore-from-snapshot` must
/// refuse the restore BEFORE any account-state materialization or audit-marker
/// write: natural exit 1, the D7-D5 epoch-conflict diagnostic, `state_vm_v0`
/// and the restore audit marker ABSENT, no successful-restore/baseline
/// observation, and the pre-existing consensus epoch (42) preserved.
///
/// Filesystem-absence checks are performed with `Path::exists()` BEFORE any
/// account accessor is invoked, so no RocksDB is created by the assertion.
#[test]
fn d7d3_c_binary_epoch_conflict_rejected_before_materialization() {
    let chain_id = devnet_chain_id();

    let src_state = tempdir().expect("tempdir");
    let snap_root = tempdir().expect("tempdir");
    let data_dir = tempdir().expect("tempdir");
    let snapshot_dir = snap_root.path().join("snap-conflict");
    build_real_snapshot(src_state.path(), &snapshot_dir, chain_id, 333, 4242, Some(7));

    // Pre-seed ONLY the consensus store with a conflicting committed epoch (42).
    let consensus_dir = data_dir.path().join("consensus");
    {
        let storage = RocksDbConsensusStorage::open(&consensus_dir).expect("seed consensus");
        storage.put_current_epoch(42).expect("seed committed epoch 42");
    }
    let state_dir = data_dir.path().join(VM_V0_STATE_SUBDIR);
    let marker_path = data_dir.path().join(RESTORE_MARKER_FILENAME);
    // Preconditions: account-state dir + restore marker absent.
    assert!(!state_dir.exists(), "precondition: state_vm_v0 absent before restore");
    assert!(!marker_path.exists(), "precondition: restore marker absent before restore");

    let args = restore_localmesh_args(data_dir.path(), &snapshot_dir);
    log_executable_provenance("D5-C-epoch-conflict", &args);
    let (status, stderr, capture) = {
        let mut child = DrainedChild::spawn(&args);
        let status = child.wait_natural_exit(NEGATIVE_DEADLINE);
        (status, child.stderr_snapshot(), child.stderr_capture())
    };
    maybe_dump_child_stderr("D5-C-epoch-conflict", &stderr);

    // Natural fail-closed exit 1 (from std::process::exit(1)), not a signal.
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
    // The NEW pre-materialization D7-D5 refusal, carrying the epoch-conflict
    // specific diagnostic (existing 42 vs snapshot 7).
    assert!(
        stderr.contains(M_D7D5_REJECT),
        "must carry the D7-D5 pre-materialization epoch-conflict refusal; stderr=\n{}",
        stderr
    );
    assert!(
        stderr.contains("existing meta:current_epoch=42 but snapshot meta.json declares epoch=7"),
        "must carry the epoch-conflict-specific diagnostic (existing 42 vs snapshot 7); stderr=\n{}",
        stderr
    );
    assert!(
        stderr.contains(M_D7D5_REJECT_ERROR),
        "must carry the RestoreError::ConsensusEpochConflict operator error line; stderr=\n{}",
        stderr
    );
    // The corrected binary must NOT reach the legacy post-materialization Run
    // 097 epoch-parity FATAL path.
    assert!(
        !stderr.contains(M_EPOCH_FATAL),
        "corrected binary must reject BEFORE the legacy Run 097 post-materialization \
         path; stderr=\n{}",
        stderr
    );
    // Complete capture is required before any absent-marker assertion.
    assert!(
        capture.is_complete(),
        "stderr capture was not complete ({capture:?}); cannot assert forbidden markers absent"
    );
    // No successful account-restore or baseline observation, and the consensus
    // loop must NOT be reached.
    for forbidden in [M_RESTORE_OK, M_B5, M_LOOP_REACHED, M_BASELINE_APPLIED, M_EPOCH_PERSIST] {
        assert!(
            !stderr.contains(forbidden),
            "pre-materialization rejection must not emit {forbidden:?}; stderr=\n{}",
            stderr
        );
    }
    // Ordering: storage was opened early (for the check) BEFORE the refusal.
    assert_marker_order(&stderr, &[M_STORAGE_OPEN, M_D7D5_REJECT]);

    // Filesystem-absence checks BEFORE any account accessor (no DB creation).
    assert!(
        !state_dir.exists(),
        "state_vm_v0 must remain ABSENT after a pre-materialization rejection"
    );
    assert!(
        !marker_path.exists(),
        "the restore audit marker must remain ABSENT after a pre-materialization rejection"
    );

    // Independent reopen: the pre-existing consensus epoch (42) is preserved.
    {
        let storage = RocksDbConsensusStorage::open(&consensus_dir).expect("reopen consensus");
        let obs = observe_consensus_storage(Some(&storage)).expect("observe");
        assert_eq!(
            obs,
            ConsensusStorageObservation::CommittedEpoch(42),
            "existing committed epoch must be preserved after a pre-materialization rejection"
        );
    }

    // Repeat the rejected request over the SAME destination: it must remain free
    // of restored account state; the first rejection must not manufacture an
    // occupied-target failure for the second attempt.
    let (status2, stderr2, capture2) = {
        let mut child = DrainedChild::spawn(&args);
        let status = child.wait_natural_exit(NEGATIVE_DEADLINE);
        (status, child.stderr_snapshot(), child.stderr_capture())
    };
    maybe_dump_child_stderr("D5-C-epoch-conflict-retry", &stderr2);
    assert_eq!(status2.code(), Some(1), "second attempt also fails closed; stderr=\n{stderr2}");
    assert!(status2.signal().is_none());
    assert!(
        stderr2.contains(M_D7D5_REJECT),
        "second attempt must ALSO reject on epoch conflict (not a manufactured \
         occupied-target failure); stderr=\n{}",
        stderr2
    );
    assert!(
        !stderr2.contains(M_TARGET_NOT_EMPTY),
        "the first rejection must NOT manufacture an occupied-target failure for \
         the second attempt; stderr=\n{}",
        stderr2
    );
    assert!(capture2.is_complete());
    assert!(!state_dir.exists(), "state_vm_v0 still absent after the second rejection");
    assert!(!marker_path.exists(), "restore marker still absent after the second rejection");
}

/// **Run 422 D7-D5.** Preservation of an already-existing restore audit marker
/// on a pre-materialization rejection. A pre-existing
/// `RESTORED_FROM_SNAPSHOT.json` is permitted by the preceding checks (the
/// epoch check runs before the occupied-target check and never touches the
/// restore marker), so the refused restore must leave that file byte-for-byte
/// unchanged.
#[test]
fn d7d5_c_preexisting_restore_marker_preserved_on_rejection() {
    let chain_id = devnet_chain_id();

    let src_state = tempdir().expect("tempdir");
    let snap_root = tempdir().expect("tempdir");
    let data_dir = tempdir().expect("tempdir");
    let snapshot_dir = snap_root.path().join("snap-conflict-marker");
    build_real_snapshot(src_state.path(), &snapshot_dir, chain_id, 333, 4242, Some(7));

    let consensus_dir = data_dir.path().join("consensus");
    {
        let storage = RocksDbConsensusStorage::open(&consensus_dir).expect("seed consensus");
        storage.put_current_epoch(42).expect("seed committed epoch 42");
    }
    // Pre-place a restore audit marker (a prior restore receipt). state_vm_v0
    // stays absent so the epoch check — not the occupied-target check — governs.
    let marker_path = data_dir.path().join(RESTORE_MARKER_FILENAME);
    let preexisting_marker = "{\"preexisting\":\"prior restore receipt\"}\n";
    std::fs::write(&marker_path, preexisting_marker).expect("write pre-existing marker");
    let state_dir = data_dir.path().join(VM_V0_STATE_SUBDIR);
    assert!(!state_dir.exists(), "precondition: state_vm_v0 absent");

    let args = restore_localmesh_args(data_dir.path(), &snapshot_dir);
    log_executable_provenance("D5-C-marker-preserved", &args);
    let (status, stderr, capture) = {
        let mut child = DrainedChild::spawn(&args);
        let status = child.wait_natural_exit(NEGATIVE_DEADLINE);
        (status, child.stderr_snapshot(), child.stderr_capture())
    };
    maybe_dump_child_stderr("D5-C-marker-preserved", &stderr);

    assert_eq!(status.code(), Some(1), "epoch conflict fails closed; stderr=\n{stderr}");
    assert!(status.signal().is_none());
    assert!(stderr.contains(M_D7D5_REJECT), "D7-D5 refusal expected; stderr=\n{stderr}");
    assert!(capture.is_complete());
    assert!(
        !state_dir.exists(),
        "state_vm_v0 must remain absent (rejection before materialization)"
    );
    // The pre-existing marker is byte-for-byte unchanged (never appended to or
    // replaced by the refused restore).
    let marker_after = std::fs::read_to_string(&marker_path).expect("read marker after rejection");
    assert_eq!(
        marker_after, preexisting_marker,
        "pre-existing restore audit marker must be preserved verbatim on rejection"
    );
}

// ============================================================================
// Correction A. Restore + CLI validation/apply exit-mode combination refusal
//               (child-process, release-binary). **Run 422 D7-D5.**
// ============================================================================
//
// A requested `--restore-from-snapshot` combined with ANY mode covered by
// `cli_storage_exit_mode_active` is unsupported and must be refused BEFORE the
// early consensus-storage open, before account-state materialization, and
// before any restore-marker write. Previously such a combination merely
// skipped the epoch precheck (`epoch_precheck=None`) yet still ran the restore
// pipeline; the absence of later consensus startup did not prevent account-
// state copying or marker writes. Every predicate — including its partial-
// configuration shapes — is exercised with a real restore request against a
// destination whose consensus storage already holds a committed epoch (42 for
// the conflicting-epoch cases, 7 for the matching-epoch case), and the
// pre-existing epoch is asserted to remain after the refusal. The refusal is
// shown to be independent of any epoch conflict: it fires identically whether
// the destination epoch conflicts with the snapshot epoch (7) or matches it.

/// One excluded-mode case: `flag_args` are the CLI validation/apply exit-mode
/// arguments appended to a real restore request; `dest_committed_epoch` is the
/// committed epoch seeded into the destination consensus storage before launch.
/// Returns nothing; panics on any deviation from the required pre-effect refusal
/// contract. The refusal fires regardless of whether the destination epoch
/// conflicts with the snapshot epoch (7) or matches it, because it precedes the
/// epoch precheck entirely.
fn assert_restore_plus_cli_mode_refused_before_effects(
    tag: &str,
    flag_args: &[&str],
    dest_committed_epoch: u64,
) {
    let chain_id = devnet_chain_id();

    let src_state = tempdir().expect("tempdir");
    let snap_root = tempdir().expect("tempdir");
    let data_dir = tempdir().expect("tempdir");
    let snapshot_dir = snap_root.path().join("snap-cli-combo");
    // Valid real snapshot declaring epoch 7.
    build_real_snapshot(src_state.path(), &snapshot_dir, chain_id, 333, 4242, Some(7));

    // Destination consensus storage already holds a committed epoch.
    let consensus_dir = data_dir.path().join("consensus");
    {
        let storage = RocksDbConsensusStorage::open(&consensus_dir).expect("seed consensus");
        storage
            .put_current_epoch(dest_committed_epoch)
            .expect("seed destination committed epoch");
    }
    let state_dir = data_dir.path().join(VM_V0_STATE_SUBDIR);
    let marker_path = data_dir.path().join(RESTORE_MARKER_FILENAME);
    assert!(!state_dir.exists(), "[{tag}] precondition: state_vm_v0 absent");
    assert!(!marker_path.exists(), "[{tag}] precondition: restore marker absent");

    // Restore request + the excluded CLI exit-mode flag(s).
    let mut args = restore_localmesh_args(data_dir.path(), &snapshot_dir);
    for a in flag_args {
        args.push((*a).to_string());
    }
    log_executable_provenance(tag, &args);
    let (status, stderr, capture) = {
        let mut child = DrainedChild::spawn(&args);
        let status = child.wait_natural_exit(NEGATIVE_DEADLINE);
        (status, child.stderr_snapshot(), child.stderr_capture())
    };
    maybe_dump_child_stderr(tag, &stderr);

    // Natural fail-closed exit 1 (std::process::exit(1)), not a signal.
    assert_eq!(
        status.code(),
        Some(1),
        "[{tag}] the unsupported restore+CLI-mode combination must fail closed with \
         natural exit code 1 (status={status:?}); stderr=\n{stderr}"
    );
    assert!(
        status.signal().is_none(),
        "[{tag}] the refusal must be a natural exit, not a signal (status={status:?}); \
         stderr=\n{stderr}"
    );
    // The specific combination refusal itself (NOT a later missing-file or
    // command-configuration error).
    assert!(
        stderr.contains(M_D7D5_CLI_COMBO_REJECT),
        "[{tag}] must carry the D7-D5 restore+CLI-mode combination refusal; stderr=\n{stderr}"
    );
    // Complete capture before any absence assertion.
    assert!(
        capture.is_complete(),
        "[{tag}] stderr capture was not complete ({capture:?}); cannot assert forbidden markers"
    );
    // The refusal precedes the early storage open, so NONE of these appear:
    // no storage-open log, no epoch-conflict refusal, no materialization, no
    // occupied-target refusal, no successful-restore/baseline observation.
    for forbidden in [
        M_STORAGE_OPEN,
        M_D7D5_REJECT,
        M_TARGET_NOT_EMPTY,
        M_RESTORE_OK,
        M_B5,
        M_LOOP_REACHED,
        M_BASELINE_APPLIED,
        M_EPOCH_PERSIST,
    ] {
        assert!(
            !stderr.contains(forbidden),
            "[{tag}] pre-open combination refusal must not emit {forbidden:?}; stderr=\n{stderr}"
        );
    }

    // Filesystem-absence checks BEFORE any account accessor (no DB creation).
    assert!(
        !state_dir.exists(),
        "[{tag}] state_vm_v0 must remain ABSENT (refusal before materialization)"
    );
    assert!(
        !marker_path.exists(),
        "[{tag}] the restore audit marker must remain ABSENT (refusal before any marker write)"
    );

    // Independent reopen: the pre-existing consensus epoch is preserved.
    {
        let storage = RocksDbConsensusStorage::open(&consensus_dir).expect("reopen consensus");
        let obs = observe_consensus_storage(Some(&storage)).expect("observe");
        assert_eq!(
            obs,
            ConsensusStorageObservation::CommittedEpoch(dest_committed_epoch),
            "[{tag}] the pre-existing committed epoch {dest_committed_epoch} must be preserved \
             after the refusal"
        );
    }
}

/// **Run 422 D7-D5 correction A.** Each excluded predicate — and each of the
/// peer-candidate hook's / reload-apply's partial-configuration shapes — is
/// exercised with a real restore request and must trigger the pre-effect
/// combination refusal.
#[test]
fn d7d5a_restore_with_reload_check_mode_refused_before_effects() {
    // Predicate 1: `p2p_trust_bundle_reload_check.is_some()`.
    assert_restore_plus_cli_mode_refused_before_effects(
        "D5-A-reload-check",
        &["--p2p-trust-bundle-reload-check", "/tmp/qbind-d5a-nonexistent-bundle.json"],
        42,
    );
}

#[test]
fn d7d5a_restore_with_peer_candidate_check_path_only_refused_before_effects() {
    // Predicate 2 (partial shape: path only) via `run077_hook_active`.
    assert_restore_plus_cli_mode_refused_before_effects(
        "D5-A-peer-candidate-path-only",
        &["--p2p-trust-bundle-peer-candidate-check", "/tmp/qbind-d5a-nonexistent-candidate.json"],
        42,
    );
}

#[test]
fn d7d5a_restore_with_peer_candidate_enabled_only_refused_before_effects() {
    // Predicate 2 (partial shape: enabled only) via `run077_hook_active`.
    assert_restore_plus_cli_mode_refused_before_effects(
        "D5-A-peer-candidate-enabled-only",
        &["--p2p-trust-bundle-peer-candidate-validation-enabled"],
        42,
    );
}

#[test]
fn d7d5a_restore_with_reload_apply_path_mode_refused_before_effects() {
    // Predicate 3: `p2p_trust_bundle_reload_apply_path.is_some()`.
    assert_restore_plus_cli_mode_refused_before_effects(
        "D5-A-reload-apply-path",
        &["--p2p-trust-bundle-reload-apply-path", "/tmp/qbind-d5a-nonexistent-apply.json"],
        42,
    );
}

#[test]
fn d7d5a_restore_with_reload_apply_enabled_mode_refused_before_effects() {
    // Predicate 4: `p2p_trust_bundle_reload_apply_enabled`.
    assert_restore_plus_cli_mode_refused_before_effects(
        "D5-A-reload-apply-enabled",
        &["--p2p-trust-bundle-reload-apply-enabled"],
        42,
    );
}

/// **Run 422 D7-D5 correction A — matching-epoch combination refusal.** The
/// restore+CLI-mode combination refusal is INDEPENDENT of any epoch conflict:
/// here the destination consensus storage already holds a committed epoch that
/// MATCHES the snapshot's declared epoch (7), so the epoch precheck — were it
/// reached — would PERMIT. The combination guard nonetheless refuses BEFORE the
/// early storage open, before account-state materialization, and before any
/// restore-marker write. This proves the refusal is triggered by the excluded
/// CLI mode itself, not by an epoch mismatch. Reuses the same
/// `--p2p-trust-bundle-reload-apply-enabled` predicate as the conflicting-epoch
/// case above with a matching destination `CommittedEpoch(7)`.
#[test]
fn d7d5a_restore_with_cli_mode_and_matching_epoch_refused_before_effects() {
    assert_restore_plus_cli_mode_refused_before_effects(
        "D5-A-reload-apply-enabled-matching-epoch",
        &["--p2p-trust-bundle-reload-apply-enabled"],
        7,
    );
}

/// **Run 422 D7-D5 correction A — deliberate-command-contract control.** A
/// restore request carrying NO CLI validation/apply exit-mode flag is NOT
/// refused by the combination guard: it reaches the normal restore path and
/// (over a fresh, compatible destination) materializes and persists epoch 7.
/// This demonstrates the refusal above is the deliberate contract for the
/// restore+CLI-mode combination specifically, not a blanket restore refusal.
/// (The full compatible-restore matrix is covered by
/// `d7d5_b_compatible_present_epochs_reach_baseline`.)
#[test]
fn d7d5a_restore_without_cli_exit_mode_is_permitted_control() {
    let chain_id = devnet_chain_id();
    let src_state = tempdir().expect("tempdir");
    let snap_root = tempdir().expect("tempdir");
    let data_dir = tempdir().expect("tempdir");
    let snapshot_dir = snap_root.path().join("snap-control");
    build_real_snapshot(src_state.path(), &snapshot_dir, chain_id, 777, 4242, Some(7));

    // Plain restore, no CLI validation/apply exit-mode flag.
    let args = restore_localmesh_args(data_dir.path(), &snapshot_dir);
    log_executable_provenance("D5-A-permitted-control", &args);
    let stderr = {
        let mut child = DrainedChild::spawn(&args);
        child
            .observe_then_terminate(&[M_BASELINE_APPLIED], POSITIVE_DEADLINE)
            .expect_observed_then_terminated("D5-A-permitted-control")
    };
    maybe_dump_child_stderr("D5-A-permitted-control", &stderr);
    // The combination guard must NOT fire for a restore without a CLI exit mode.
    assert!(
        !stderr.contains(M_D7D5_CLI_COMBO_REJECT),
        "a restore without a CLI exit mode must not be refused by the combination guard; \
         stderr=\n{stderr}"
    );
    // It reaches the normal restore path and persists epoch 7.
    assert_marker_order(
        &stderr,
        &[M_STORAGE_OPEN, M_RESTORE_OK, M_B5, M_EPOCH_PERSIST, M_LOOP_REACHED, M_BASELINE_APPLIED],
    );
    let (acct, obs) = observe_restored_data_dir(data_dir.path());
    assert_eq!(acct, AccountState::new(7, 4242));
    assert_eq!(obs, ConsensusStorageObservation::CommittedEpoch(7));
}

// ============================================================================
// Correction C. Occupied-target refusal AFTER the epoch precheck PERMITS
//               (child-process, release-binary). **Run 422 D7-D5.**
// ============================================================================
//
// Establishes the post-precheck materialization-refusal path through the
// corrected production binary (NOT a library entrypoint that passes no
// precheck): the destination consensus storage opens with NO committed epoch,
// so the epoch compatibility check PERMITS the restore attempt; but the
// destination `state_vm_v0` is already occupied with a known sentinel account,
// so the subsequent occupied-target check refuses materialization with the
// `TargetStateNotEmpty` diagnostic. Nothing is persisted, the sentinel is
// untouched, and no restore marker is written.

/// **Run 422 D7-D5 correction C.** Precheck permits, occupied-target refuses.
#[test]
fn d7d5c_occupied_target_refused_after_precheck_permits() {
    let chain_id = devnet_chain_id();

    let src_state = tempdir().expect("tempdir");
    let snap_root = tempdir().expect("tempdir");
    let data_dir = tempdir().expect("tempdir");
    let snapshot_dir = snap_root.path().join("snap-occupied");
    // Valid real snapshot with epoch Some(7).
    build_real_snapshot(src_state.path(), &snapshot_dir, chain_id, 888, 4242, Some(7));

    // Destination consensus storage opens successfully with NO committed epoch:
    // create the directory as an empty RocksDB (no put_current_epoch), so the
    // live precheck read returns None → PersistAfterMaterialization (permits).
    let consensus_dir = data_dir.path().join("consensus");
    {
        let _storage = RocksDbConsensusStorage::open(&consensus_dir).expect("open empty consensus");
    }

    // Destination state_vm_v0 is already occupied with a known sentinel account.
    const SENTINEL_ID: [u8; 32] = [0xAB; 32];
    let sentinel_value = AccountState::new(99, 123_456);
    let state_dir = data_dir.path().join(VM_V0_STATE_SUBDIR);
    {
        let occupied = RocksDbAccountState::open(&state_dir).expect("open occupied state_vm_v0");
        occupied
            .put_account_state(&SENTINEL_ID, &sentinel_value)
            .expect("seed sentinel account");
        occupied.flush().expect("flush sentinel");
    }
    let marker_path = data_dir.path().join(RESTORE_MARKER_FILENAME);
    assert!(!marker_path.exists(), "precondition: restore marker absent");

    // No CLI exclusion mode is selected — a plain restore request.
    let args = restore_localmesh_args(data_dir.path(), &snapshot_dir);
    log_executable_provenance("D5-C-occupied-target", &args);
    let (status, stderr, capture) = {
        let mut child = DrainedChild::spawn(&args);
        let status = child.wait_natural_exit(NEGATIVE_DEADLINE);
        (status, child.stderr_snapshot(), child.stderr_capture())
    };
    maybe_dump_child_stderr("D5-C-occupied-target", &stderr);

    // Natural fail-closed exit 1 with the SPECIFIC TargetStateNotEmpty diagnostic.
    assert_eq!(
        status.code(),
        Some(1),
        "occupied-target refusal must fail closed with natural exit code 1 (status={status:?}); \
         stderr=\n{stderr}"
    );
    assert!(status.signal().is_none());
    assert!(
        stderr.contains(M_TARGET_NOT_EMPTY),
        "must carry the TargetStateNotEmpty occupied-target refusal; stderr=\n{stderr}"
    );
    // The epoch precheck PERMITTED the attempt (no epoch conflict), so the D7-D5
    // epoch-conflict refusal must be ABSENT — this proves the occupied-target
    // check is what refused, on the production precheck path.
    assert!(
        !stderr.contains(M_D7D5_REJECT),
        "the epoch precheck must PERMIT (no conflict); the refusal must be occupied-target, \
         not epoch-conflict; stderr=\n{stderr}"
    );
    assert!(
        !stderr.contains(M_D7D5_CLI_COMBO_REJECT),
        "no CLI exit mode is selected; the combination guard must not fire; stderr=\n{stderr}"
    );
    // Storage was opened early (for the permitting precheck) BEFORE the refusal.
    assert_marker_order(&stderr, &[M_STORAGE_OPEN, M_TARGET_NOT_EMPTY]);
    // Complete capture before any absence / no-persistence assertion.
    assert!(
        capture.is_complete(),
        "stderr capture was not complete ({capture:?}); cannot assert forbidden markers"
    );
    // No successful restore, baseline application, or snapshot-epoch persistence.
    for forbidden in [M_RESTORE_OK, M_B5, M_LOOP_REACHED, M_BASELINE_APPLIED, M_EPOCH_PERSIST] {
        assert!(
            !stderr.contains(forbidden),
            "occupied-target refusal must not emit {forbidden:?}; stderr=\n{stderr}"
        );
    }

    // Run 422 D7-D8: the non-writing occupancy (target-eligibility) check runs
    // BEFORE any INTENT is published, so a rejected request against an ordinary
    // occupied destination must neither publish an INTENT nor create an RTR.
    assert!(
        !stderr.contains(M_D7D8_INTENT_PUBLISHED),
        "the occupied-target refusal must precede INTENT publication; stderr=\n{stderr}"
    );
    assert!(
        matches!(
            read_rtr(data_dir.path()).expect("read RTR after occupied-target refusal"),
            RtrReadResult::Absent
        ),
        "a rejected request against an ordinary occupied destination must not create an RTR; \
         stderr=\n{stderr}"
    );
    assert!(
        !data_dir.path().join(RTR_FILENAME).exists(),
        "no restore-transaction record file may exist after an occupied-target refusal"
    );
    assert!(
        !marker_path.exists(),
        "restore audit marker must remain absent after an occupied-target refusal"
    );

    // Independent reopen: consensus still reports PresentNoCommittedEpoch and the
    // sentinel account value is unchanged.
    {
        let storage = RocksDbConsensusStorage::open(&consensus_dir).expect("reopen consensus");
        let obs = observe_consensus_storage(Some(&storage)).expect("observe");
        assert_eq!(
            obs,
            ConsensusStorageObservation::PresentNoCommittedEpoch,
            "no snapshot epoch may be persisted when materialization is refused"
        );
    }
    {
        let occupied = RocksDbAccountState::open(&state_dir).expect("reopen occupied state_vm_v0");
        assert_eq!(
            occupied.get_account_state(&SENTINEL_ID),
            sentinel_value,
            "the pre-existing sentinel account value must remain unchanged"
        );
    }
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
// D7-D4. Behavior over a legacy (pre-fix) partially-restored directory
//        (child-process, release-binary). **Migrated for Run 422 D7-D5.**
// ============================================================================
//
// At the accepted D7-D3/D4 SHAs, the *pre-fix* binary produced a partially
// completed destination (restored `state_vm_v0` + preserved conflicting
// consensus `CommittedEpoch(42)`) because the epoch check ran only AFTER
// materialization. The corrected binary no longer produces that layout (see
// `d7d3_c_binary_epoch_conflict_rejected_before_materialization`). To keep the
// D7-D4 characterization of behavior OVER such a directory, these cases operate
// on a clearly-labeled *legacy-layout fixture*
// (`build_legacy_partial_restore_destination`) built via real
// snapshot/library materialization — an imported/pre-fix layout, NOT a failure
// produced by the corrected executable.
//
//   A. Repeat startup WITH `--restore-from-snapshot` over the legacy partial
//      directory. **Deliberate ordering change (Run 422 D7-D5):** the corrected
//      binary opens consensus storage early and runs the epoch-conflict check
//      BEFORE the materialization pipeline's occupied-target check. Because the
//      legacy directory carries a conflicting `CommittedEpoch(42)` vs the
//      snapshot's epoch 7, the refusal is now the D7-D5 epoch-conflict refusal
//      (pre-materialization), NOT `TargetStateNotEmpty`. The retry restores
//      nothing and leaves the account value, consensus epoch, and restore audit
//      marker untouched. (The occupied-target refusal itself remains covered by
//      the existing `b3_snapshot_restore_tests` suite.)
//   B. Ordinary startup WITHOUT the flag over the legacy partial directory.
//      `apply_snapshot_restore_if_requested` returns `Ok(None)` (fast-sync
//      disabled): NO restore/epoch check runs, and startup PROCEEDS to the
//      consensus loop over the mixed account/epoch state. **This path is
//      OUTSIDE this correction's protection** (D7-D5 guards only the requested
//      restore path); the observed limitation is recorded, not repaired.
//   C. A matched fresh-directory ordinary start, to distinguish legacy-directory
//      behavior from ordinary startup / unrelated config failure.
//
// Each continuation constructs an INDEPENDENT legacy fixture (its own tempdirs)
// so one start cannot change another's starting conditions; NONE hand-fabricates
// the layout (real library materialization + consensus setup is used). All
// RocksDB handles are closed before every child launch; stored logical values
// are read AFTER the child is reaped (a selected-value match is NOT claimed to
// be byte-identity of the directory).

/// D7-D4 case A — repeat WITH the restore flag over the legacy partial
/// directory. **Run 422 D7-D5:** the corrected binary refuses with the
/// pre-materialization epoch-conflict refusal (epoch check precedes the
/// occupied-target check). The retry restores nothing, materializes no new
/// state, and does not touch the pre-existing account value, consensus epoch, or
/// restore audit marker.
#[test]
fn d7d4_a_repeat_with_restore_flag_over_legacy_partial_rejects_epoch_conflict() {
    // 1. Independently construct the legacy partial layout via library
    //    materialization (NOT via the corrected binary).
    let partial = build_legacy_partial_restore_destination("D4-A-legacy");

    // Pre-retry independent reads (the values the refused attempt must not move).
    let (acct_before, obs_before) = observe_restored_data_dir(partial.data_dir.path());
    assert_eq!(acct_before, AccountState::new(7, 4242));
    assert_eq!(obs_before, ConsensusStorageObservation::CommittedEpoch(42));
    let marker_before = partial.restore_marker.clone();

    // 2. Restart the SAME partial destination WITH the same snapshot + flag and
    //    otherwise-equivalent arguments.
    let args = restore_localmesh_args(partial.data_dir.path(), &partial.snapshot_dir);
    log_executable_provenance("D4-A-retry-with-flag", &args);
    let (status, stderr, capture) = {
        let mut child = DrainedChild::spawn(&args);
        let status = child.wait_natural_exit(NEGATIVE_DEADLINE);
        (status, child.stderr_snapshot(), child.stderr_capture())
    };
    maybe_dump_child_stderr("D4-A-retry-with-flag", &stderr);

    // Natural failure exit with the actual expected code (1), not a signal.
    assert_eq!(
        status.code(),
        Some(1),
        "WITH-flag retry over the legacy partial directory must fail closed with \
         natural exit code 1 (status={status:?}); stderr=\n{}",
        stderr
    );
    assert!(
        status.signal().is_none(),
        "the refusal must be a natural exit, not a signal (status={status:?}); stderr=\n{}",
        stderr
    );
    // Run 422 D7-D5 deliberate ordering: the conflicting present epoch (42 vs 7)
    // is detected by the pre-materialization epoch check, which runs BEFORE the
    // materialization pipeline's occupied-target (`TargetStateNotEmpty`) check.
    // So the refusal is the D7-D5 epoch-conflict refusal, not TargetStateNotEmpty.
    assert!(
        stderr.contains(M_D7D5_REJECT),
        "must carry the D7-D5 pre-materialization epoch-conflict refusal; stderr=\n{}",
        stderr
    );
    assert!(
        !stderr.contains(M_TARGET_NOT_EMPTY),
        "the epoch check precedes the occupied-target check, so TargetStateNotEmpty \
         must NOT be the refusal here; stderr=\n{}",
        stderr
    );
    // Complete capture before any absent-marker claim below.
    assert!(
        capture.is_complete(),
        "stderr capture was not complete ({capture:?}); cannot assert forbidden markers absent"
    );
    // No NEW successful-restore or baseline observation from THIS invocation.
    // Storage IS opened early (for the epoch check) BEFORE the refusal, so
    // M_STORAGE_OPEN is expected present and is NOT in the forbidden set.
    for forbidden in [M_RESTORE_OK, M_B5, M_LOOP_REACHED, M_BASELINE_APPLIED, M_EPOCH_PERSIST] {
        assert!(
            !stderr.contains(forbidden),
            "refused WITH-flag retry must not emit {forbidden:?}; stderr=\n{}",
            stderr
        );
    }

    // 3. Independently reopened account value and consensus epoch remain at
    //    their pre-retry values.
    let (acct_after, obs_after) = observe_restored_data_dir(partial.data_dir.path());
    assert_eq!(
        acct_after, acct_before,
        "refused retry must not change the restored account value"
    );
    assert_eq!(
        obs_after, obs_before,
        "refused retry must not change the preserved consensus epoch (still 42)"
    );

    // 4. Existing restore audit-marker contents are NOT appended or replaced by
    //    the refused attempt (the epoch-conflict refusal precedes any
    //    materialization / `write_restore_marker`).
    let marker_after = std::fs::read_to_string(
        partial.data_dir.path().join(RESTORE_MARKER_FILENAME),
    )
    .expect("read restore audit marker after refused retry");
    assert_eq!(
        marker_after, marker_before,
        "the refused retry must not append to or replace the restore audit marker"
    );
}

/// D7-D4 case B — restart WITHOUT the restore flag over an independently
/// constructed legacy partial directory. Source trace (encoded, then verified
/// against the real
/// binary): `apply_snapshot_restore_if_requested` returns `Ok(None)` → the
/// "normal startup" line is printed, NO restore baseline is built, and the
/// Run 097 epoch block is skipped (`if let Some(outcome)`). Ordinary startup
/// then opens the canonical consensus storage (already holding epoch 42),
/// dispatches into `run_local_mesh_node`, and enters
/// `run_binary_consensus_loop_with_io` with `restore_baseline=None` (no baseline
/// application). The honest last-observed boundary is the existing
/// `[binary-consensus] Starting consensus loop:` line (exposing
/// `restore_baseline=false`), reached while the child is still alive.
///
/// **Observed limitation (recorded, not repaired):** ordinary startup PROCEEDS
/// over the mixed account/epoch destination. This is an observed limitation
/// requiring assessment before production activation; it is NOT coherent or safe
/// recovery, and this task does not repair it. **Run 422 D7-D5** guards only the
/// requested-restore path; ordinary startup over a legacy partial directory
/// remains outside this correction's protection.
#[test]
fn d7d4_b_restart_without_restore_flag_over_legacy_partial_proceeds() {
    let partial = build_legacy_partial_restore_destination("D4-B-legacy");
    let (acct_before, obs_before) = observe_restored_data_dir(partial.data_dir.path());
    assert_eq!(acct_before, AccountState::new(7, 4242));
    assert_eq!(obs_before, ConsensusStorageObservation::CommittedEpoch(42));
    let marker_before = partial.restore_marker.clone();

    // Ordinary start: equivalent env/network-mode/data-dir, NO restore flag.
    let args = ordinary_localmesh_args(partial.data_dir.path());
    log_executable_provenance("D4-B-ordinary-no-flag", &args);
    let stderr = {
        let mut child = DrainedChild::spawn(&args);
        // Anchor on the consensus-loop-start line (reached while alive), then
        // deliberately terminate. Complete capture + successful reap are
        // enforced by `expect_observed_then_terminated`.
        child
            .observe_then_terminate(&[M_CONSENSUS_LOOP_STARTED], POSITIVE_DEADLINE)
            .expect_observed_then_terminated("D4-B-ordinary-no-flag")
    };
    maybe_dump_child_stderr("D4-B-ordinary-no-flag", &stderr);

    // Observed branch: ordinary startup PROCEEDS. Assert the observed startup
    // observations in their actual order: normal-start → storage open →
    // LocalMesh dispatch → consensus loop started.
    assert!(
        stderr.contains(M_NO_RESTORE),
        "ordinary start must print the normal-startup line; stderr=\n{}",
        stderr
    );
    assert_marker_order(
        &stderr,
        &[M_NO_RESTORE, M_STORAGE_OPEN, M_LOOP_REACHED, M_CONSENSUS_LOOP_STARTED],
    );
    // No restore work: no successful-restore, no B5 baseline construction, no
    // baseline application. The loop reports `restore_baseline=false`.
    for forbidden in [M_RESTORE_OK, M_B5, M_BASELINE_APPLIED] {
        assert!(
            !stderr.contains(forbidden),
            "ordinary (no-flag) start must not emit {forbidden:?}; stderr=\n{}",
            stderr
        );
    }
    assert!(
        stderr.contains("restore_baseline=false"),
        "the consensus-loop-start line must confirm NO baseline was applied; stderr=\n{}",
        stderr
    );

    // Last-observed boundary is the consensus-loop-start line. We do NOT infer
    // engine recovery of the mixed account/epoch state from startup dispatch.

    // Independent post-process reads (after reap). Report honestly.
    let (acct_after, obs_after) = observe_restored_data_dir(partial.data_dir.path());
    assert_eq!(
        acct_after,
        AccountState::new(7, 4242),
        "restored account value observable after ordinary restart (unchanged at loop-start)"
    );
    // Observed limitation: the pre-existing consensus epoch is still present and
    // unchanged after ordinary startup proceeded over the mixed destination.
    assert_eq!(
        obs_after, obs_before,
        "ordinary startup proceeded over the mixed account/epoch destination; the \
         pre-existing consensus epoch is unchanged at the loop-start boundary \
         (observed limitation, not safe recovery)"
    );
    assert_eq!(obs_after, ConsensusStorageObservation::CommittedEpoch(42));
    // Ordinary startup writes no restore audit marker; the existing marker is
    // unchanged.
    let marker_after = std::fs::read_to_string(
        partial.data_dir.path().join(RESTORE_MARKER_FILENAME),
    )
    .expect("read restore audit marker after ordinary restart");
    assert_eq!(
        marker_after, marker_before,
        "ordinary (no-flag) restart must not append to or replace the restore audit marker"
    );
}

/// D7-D4 case C — matched fresh-directory ordinary-start control. Same
/// equivalent args as case B (no restore flag) over a fresh, unseeded data dir.
/// Purpose: distinguish partial-destination behavior from normal startup — the
/// control reaches the SAME consensus-loop-start boundary, but its
/// independently reopened consensus store shows `PresentNoCommittedEpoch`
/// (never the partial destination's `CommittedEpoch(42)`). A control that starts
/// establishes NO consensus progress, signing authorization, or recovery
/// correctness — only observed startup and storage behavior.
#[test]
fn d7d4_c_fresh_directory_ordinary_start_control() {
    let data_dir = tempdir().expect("tempdir");
    let args = ordinary_localmesh_args(data_dir.path());
    log_executable_provenance("D4-C-fresh-control", &args);
    let stderr = {
        let mut child = DrainedChild::spawn(&args);
        child
            .observe_then_terminate(&[M_CONSENSUS_LOOP_STARTED], POSITIVE_DEADLINE)
            .expect_observed_then_terminated("D4-C-fresh-control")
    };
    maybe_dump_child_stderr("D4-C-fresh-control", &stderr);

    // Same ordinary-start observations and order as case B.
    assert!(
        stderr.contains(M_NO_RESTORE),
        "fresh ordinary start must print the normal-startup line; stderr=\n{}",
        stderr
    );
    assert_marker_order(
        &stderr,
        &[M_NO_RESTORE, M_STORAGE_OPEN, M_LOOP_REACHED, M_CONSENSUS_LOOP_STARTED],
    );
    for forbidden in [M_RESTORE_OK, M_B5, M_BASELINE_APPLIED] {
        assert!(
            !stderr.contains(forbidden),
            "fresh ordinary start must not emit {forbidden:?}; stderr=\n{}",
            stderr
        );
    }
    assert!(
        stderr.contains("restore_baseline=false"),
        "the consensus-loop-start line must confirm NO baseline was applied; stderr=\n{}",
        stderr
    );

    // Independent post-process read: a fresh consensus store has NO committed
    // epoch — the distinguishing difference from the partial destination.
    let consensus_dir = data_dir.path().join("consensus");
    let obs = {
        let storage =
            RocksDbConsensusStorage::open(&consensus_dir).expect("reopen fresh consensus");
        observe_consensus_storage(Some(&storage)).expect("observe fresh consensus")
    };
    assert_eq!(
        obs,
        ConsensusStorageObservation::PresentNoCommittedEpoch,
        "fresh ordinary start has no committed epoch"
    );
    assert_ne!(
        obs,
        ConsensusStorageObservation::CommittedEpoch(42),
        "the control is distinct from the partial destination (which holds epoch 42)"
    );
}

// ============================================================================
// D7-D6. Late restore FAILURE (marker-open) and subsequent restart paths
//        (child-process, release-binary). **Run 422 D7-D6.**
// ============================================================================
//
// This section characterizes a DIFFERENT failure than D7-D4: not a legacy
// pre-fix layout imported via library calls, but a failure produced by the
// CORRECTED release executable itself during an otherwise-COMPATIBLE restore.
//
// Source-backed operation ordering (`snapshot_restore.rs`
// `materialize_validated_snapshot` and `main.rs` restore path):
//   1. `main.rs` opens the canonical `<data_dir>/consensus` storage early for a
//      requested restore (`M_STORAGE_OPEN`), reads the live committed epoch, and
//      runs the D5 pre-materialization epoch-compatibility precheck.
//   2. For a compatible snapshot (`Some(7)` into a destination with NO committed
//      epoch) the precheck PERMITS, and `materialize_validated_snapshot`:
//        a. creates `<data_dir>/state_vm_v0` and COPIES the snapshot account
//           state into it (`copy_dir_recursive`), THEN
//        b. calls `write_restore_marker`, which OPENS the
//           `RESTORE_MARKER_FILENAME` path with `OpenOptions::create(true)
//           .append(true).open(path)` to append one audit line.
//   3. The Run 097 snapshot-epoch persistence runs only AFTER a successful
//      restore outcome (`if let Some(outcome)` in `main.rs`).
//
// Deterministic failure mechanism: at the `RESTORE_MARKER_FILENAME` path we
// pre-create a DIRECTORY (containing a small fixed-byte sentinel file). Opening
// a directory as an appendable file fails with EISDIR ("Is a directory"), so
// step (2b) fails AFTER the account state was already copied in step (2a) and
// BEFORE the Run 097 epoch persistence in step (3). `main.rs` maps the
// `RestoreError::Io` to a fatal `[restore] ERROR: ...` and `std::process::exit(1)`.
// A directory (not a chmod) is used so the obstruction survives tests run as
// root, which a permission-only obstruction would not.
//
// This is an ORDINARY local I/O-failure characterization — NOT a power-loss
// simulation, malicious-rollback test, or durability proof. Reaching the
// consensus loop (case B) or preserving an account value is NOT signing-state
// continuity or safe recovery; the marker directory is NOT an "absent" marker
// (the obstruction exists; no successful audit record was written).

/// Fixed sentinel bytes written into the obstructing marker DIRECTORY. Their
/// preservation across each child run is asserted (the failed marker open must
/// not have mutated the obstruction).
const OBSTRUCTION_SENTINEL_BYTES: &[u8] = b"D7D6-marker-open-obstruction-sentinel-v1";
/// Name of the sentinel file placed INSIDE the obstructing marker directory.
const OBSTRUCTION_SENTINEL_FILENAME: &str = "obstruction_sentinel.bin";
/// Substring of the `write_restore_marker` open-failure message
/// (`snapshot_restore.rs`): `cannot open marker file <path>: <os error>`.
const M_MARKER_OPEN_FAIL: &str = "cannot open marker file";
/// The `RestoreError::Io` `Display` prefix surfaced by `main.rs` as
/// `[restore] ERROR: restore-from-snapshot IO error: ...`.
const M_RESTORE_IO_ERROR: &str = "restore-from-snapshot IO error:";

/// A destination left behind by a COMPATIBLE restore that copied account state
/// and then FAILED to open its audit marker (obstructed by a directory). The
/// tempdirs are retained so the continuation cases (B/C) can operate over the
/// exact failed directory without it being cleaned up.
struct MarkerObstructedFailedDestination {
    _src_state: tempfile::TempDir,
    _snap_root: tempfile::TempDir,
    /// The failed destination: restored `state_vm_v0` + `PresentNoCommittedEpoch`
    /// consensus + an obstructing marker DIRECTORY holding the sentinel.
    data_dir: tempfile::TempDir,
    /// Snapshot directory declaring epoch `Some(7)` (reused by the case-C retry).
    snapshot_dir: PathBuf,
    /// `<data_dir>/RESTORE_MARKER_FILENAME` — a DIRECTORY (the obstruction).
    marker_dir_path: PathBuf,
    /// `<marker_dir_path>/OBSTRUCTION_SENTINEL_FILENAME` — the fixed-byte sentinel.
    sentinel_path: PathBuf,
}

/// Produce AND verify the marker-obstructed failed destination through the
/// CORRECTED release executable (this is Run 422 D7-D6 scenario A, factored into
/// a reusable helper so B and C can each reproduce it independently with their
/// OWN temporary directories).
///
/// Fixture (task section 4):
///   * Real supported checkpoint, snapshot epoch `Some(7)`, known account
///     (`ACCOUNT_ID` = 7/4242).
///   * Destination consensus storage opened as `PresentNoCommittedEpoch`,
///     EXPLICITLY observed before launch.
///   * Account-state destination (`state_vm_v0`) initially ABSENT.
///   * No excluded CLI mode.
///   * At `RESTORE_MARKER_FILENAME`: a DIRECTORY containing a small sentinel
///     file with fixed bytes (obstructs the appendable-file open).
///   * All DB handles closed before the child launches.
///
/// Scenario-A requirements verified here: natural exit 1 (no signal); the
/// specific marker-open I/O failure naming the obstructed marker path; complete
/// capture; storage-open observed BEFORE the failure; NO CLI-combination or
/// epoch-conflict refusal; NO restore-success/baseline/consensus-loop/epoch
/// persistence; and, after reap, independent reads find the restored account and
/// `PresentNoCommittedEpoch`, with the marker path still a directory and the
/// sentinel bytes unchanged.
fn produce_and_verify_marker_obstructed_failure(
    tag: &str,
) -> MarkerObstructedFailedDestination {
    let chain_id = devnet_chain_id();

    let src_state = tempdir().expect("tempdir");
    let snap_root = tempdir().expect("tempdir");
    let data_dir = tempdir().expect("tempdir");
    let snapshot_dir = snap_root.path().join("snap-marker-obstructed");
    // Real supported checkpoint with snapshot epoch Some(7) and known account.
    build_real_snapshot(src_state.path(), &snapshot_dir, chain_id, 707, 4242, Some(7));

    // Destination consensus storage opens with NO committed epoch. Open+close so
    // the schema exists and the live precheck read returns None (PERMITS), then
    // EXPLICITLY observe PresentNoCommittedEpoch before launch.
    let consensus_dir = data_dir.path().join("consensus");
    {
        let storage =
            RocksDbConsensusStorage::open(&consensus_dir).expect("open empty consensus");
        let obs = observe_consensus_storage(Some(&storage)).expect("observe pre-launch consensus");
        assert_eq!(
            obs,
            ConsensusStorageObservation::PresentNoCommittedEpoch,
            "[{tag}] destination consensus must open as PresentNoCommittedEpoch before launch"
        );
    }

    // The account-state destination is initially ABSENT.
    let state_dir = data_dir.path().join(VM_V0_STATE_SUBDIR);
    assert!(
        !state_dir.exists(),
        "[{tag}] precondition: state_vm_v0 destination must be initially absent"
    );

    // Obstruction: at the RESTORE_MARKER_FILENAME path create a DIRECTORY holding
    // a fixed-byte sentinel file. A directory (not a permission bit) is used so
    // the obstruction survives a root test runner.
    let marker_dir_path = data_dir.path().join(RESTORE_MARKER_FILENAME);
    std::fs::create_dir(&marker_dir_path).expect("create obstructing marker directory");
    let sentinel_path = marker_dir_path.join(OBSTRUCTION_SENTINEL_FILENAME);
    std::fs::write(&sentinel_path, OBSTRUCTION_SENTINEL_BYTES).expect("write sentinel bytes");
    assert!(
        marker_dir_path.is_dir(),
        "[{tag}] precondition: marker path must be a directory (obstruction present)"
    );

    // No CLI exclusion mode is selected — a plain compatible restore request.
    let args = restore_localmesh_args(data_dir.path(), &snapshot_dir);
    log_executable_provenance(tag, &args);
    let (status, stderr, capture) = {
        let mut child = DrainedChild::spawn(&args);
        let status = child.wait_natural_exit(NEGATIVE_DEADLINE);
        (status, child.stderr_snapshot(), child.stderr_capture())
    };
    maybe_dump_child_stderr(tag, &stderr);

    // Natural fail-closed exit 1, NOT a terminating signal.
    assert_eq!(
        status.code(),
        Some(1),
        "[{tag}] late marker-open failure must fail closed with natural exit code 1 \
         (status={status:?}); stderr=\n{stderr}"
    );
    assert!(
        status.signal().is_none(),
        "[{tag}] the failure must be a natural exit, not a signal (status={status:?}); \
         stderr=\n{stderr}"
    );

    // The SPECIFIC marker-open I/O failure, naming the obstructed marker path.
    assert!(
        stderr.contains(M_MARKER_OPEN_FAIL),
        "[{tag}] must carry the specific marker-open failure {M_MARKER_OPEN_FAIL:?}; \
         stderr=\n{stderr}"
    );
    assert!(
        stderr.contains(M_RESTORE_IO_ERROR),
        "[{tag}] the failure must surface as a restore IO error; stderr=\n{stderr}"
    );
    assert!(
        stderr.contains(&marker_dir_path.display().to_string()),
        "[{tag}] the failure must identify the obstructed marker path {}; stderr=\n{stderr}",
        marker_dir_path.display()
    );
    assert!(
        stderr.contains("Is a directory") || stderr.contains("os error 21"),
        "[{tag}] the marker-open failure must be the EISDIR obstruction; stderr=\n{stderr}"
    );

    // Complete capture BEFORE any absent-marker claim.
    assert!(
        capture.is_complete(),
        "[{tag}] stderr capture was not complete ({capture:?}); cannot assert forbidden markers"
    );

    // Storage-open observation occurred BEFORE the marker-open failure.
    assert_marker_order(&stderr, &[M_STORAGE_OPEN, M_MARKER_OPEN_FAIL]);

    // No CLI-combination or epoch-conflict refusal — the restore was compatible
    // and no CLI exit mode is active; the failure is a late I/O failure.
    assert!(
        !stderr.contains(M_D7D5_REJECT),
        "[{tag}] a compatible restore must not be refused by the epoch-conflict check; \
         stderr=\n{stderr}"
    );
    assert!(
        !stderr.contains(M_D7D5_REJECT_ERROR),
        "[{tag}] the failure is a marker-open IO error, not an epoch-conflict refusal; \
         stderr=\n{stderr}"
    );
    assert!(
        !stderr.contains(M_D7D5_CLI_COMBO_REJECT),
        "[{tag}] no CLI exit mode is selected; the combination guard must not fire; \
         stderr=\n{stderr}"
    );
    assert!(
        !stderr.contains(M_TARGET_NOT_EMPTY),
        "[{tag}] the account-state destination was absent; TargetStateNotEmpty must not fire; \
         stderr=\n{stderr}"
    );

    // No restore-success, baseline, consensus-loop-entry, or epoch-persistence.
    for forbidden in [
        M_RESTORE_OK,
        M_B5,
        M_LOOP_REACHED,
        M_BASELINE_APPLIED,
        M_CONSENSUS_LOOP_STARTED,
        M_EPOCH_PERSIST,
        M_EPOCH_ABSENT,
        M_EPOCH_FATAL,
    ] {
        assert!(
            !stderr.contains(forbidden),
            "[{tag}] late marker-open failure must not emit {forbidden:?}; stderr=\n{stderr}"
        );
    }

    // After reap, INDEPENDENT reads: the account WAS copied before the marker
    // open failed, and no snapshot epoch was persisted.
    let (account, observation) = observe_restored_data_dir(data_dir.path());
    assert_eq!(
        account,
        AccountState::new(7, 4242),
        "[{tag}] the compatible restore copied account state BEFORE the marker-open failure"
    );
    assert_eq!(
        observation,
        ConsensusStorageObservation::PresentNoCommittedEpoch,
        "[{tag}] no snapshot epoch may be persisted when the restore failed before Run 097"
    );

    // The marker path remains a DIRECTORY (not an "absent" marker, not a written
    // audit file) and its sentinel bytes are unchanged.
    assert!(
        marker_dir_path.is_dir(),
        "[{tag}] the obstructing marker path must remain a directory after the failure"
    );
    let sentinel_after = std::fs::read(&sentinel_path).expect("read sentinel after failure");
    assert_eq!(
        sentinel_after.as_slice(),
        OBSTRUCTION_SENTINEL_BYTES,
        "[{tag}] the marker directory's sentinel bytes must remain unchanged"
    );

    // Run 422 D7-D8: a genuine attempt published a durable INTENT before the
    // account copy; the late marker-open failure retains that fail-closed
    // INTENT record (it is never promoted to COMPLETE and never auto-removed).
    assert!(
        stderr.contains(M_D7D8_INTENT_PUBLISHED),
        "[{tag}] the guarded restore must publish a durable INTENT before copying state; \
         stderr=\n{stderr}"
    );
    assert!(
        !stderr.contains(M_D7D8_COMPLETE_PUBLISHED),
        "[{tag}] a restore that fails at the audit marker must never publish COMPLETE; \
         stderr=\n{stderr}"
    );
    let rtr_after = read_rtr(data_dir.path()).expect("read RTR after failure");
    match rtr_after {
        RtrReadResult::Present(rec) => assert_eq!(
            rec.state,
            RtrState::Intent,
            "[{tag}] the retained restore-transaction record must be INTENT, never COMPLETE"
        ),
        other => panic!("[{tag}] expected a present INTENT RTR after failure, got {other:?}"),
    }

    MarkerObstructedFailedDestination {
        _src_state: src_state,
        _snap_root: snap_root,
        data_dir,
        snapshot_dir,
        marker_dir_path,
        sentinel_path,
    }
}

/// D7-D6 case A — a COMPATIBLE restore copies account state and then FAILS to
/// OPEN its audit marker (obstructed by a directory), exiting 1 after the account
/// copy and before Run 097 epoch persistence. The reusable helper both PRODUCES
/// and VERIFIES this failed destination against the corrected release executable;
/// case A asserts nothing further.
#[test]
fn d7d6_a_late_marker_open_failure() {
    let _failed = produce_and_verify_marker_obstructed_failure("D6-A-late-marker-open");
    // All scenario-A invariants are checked inside the helper: natural exit 1,
    // the specific marker-open EISDIR failure naming the obstructed path,
    // complete capture, storage-open-before-failure, no CLI/epoch refusal, no
    // restore-success/baseline/loop/epoch observations, and the post-reap
    // restored account + PresentNoCommittedEpoch + intact directory/sentinel.
}

/// D7-D6/D8 case B — ordinary restart WITHOUT `--restore-from-snapshot` over
/// the failed destination produced by case A, without deleting or repairing
/// anything.
///
/// **Run 422 D7-D8 containment.** Case A now leaves a durable `INTENT`
/// restore-transaction record. A no-flag restart therefore hits the
/// ordinary-startup guard, which observes the tracked interrupted restore and
/// REFUSES (natural exit 1) BEFORE opening the affected VM-v0 state or the
/// consensus storage and BEFORE entering the consensus loop. `INTENT` may be
/// observed but is never admitted. This is the exact D7-D6 failure the D8
/// mechanism contains: the previous run reached the consensus loop over the
/// incomplete destination; the guarded build now fails closed.
#[test]
fn d7d6_b_ordinary_restart_without_flag_over_marker_obstructed_failure() {
    let failed = produce_and_verify_marker_obstructed_failure("D6-B-pre-failure");

    // Pre-restart independent reads.
    let (acct_before, obs_before) = observe_restored_data_dir(failed.data_dir.path());
    assert_eq!(acct_before, AccountState::new(7, 4242));
    assert_eq!(obs_before, ConsensusStorageObservation::PresentNoCommittedEpoch);
    let sentinel_before =
        std::fs::read(&failed.sentinel_path).expect("read sentinel before restart");

    // Ordinary start: equivalent env/network-mode/data-dir, NO restore flag.
    let args = ordinary_localmesh_args(failed.data_dir.path());
    log_executable_provenance("D6-B-ordinary-no-flag", &args);
    let (status, stderr, capture) = {
        let mut child = DrainedChild::spawn(&args);
        let status = child.wait_natural_exit(NEGATIVE_DEADLINE);
        (status, child.stderr_snapshot(), child.stderr_capture())
    };
    maybe_dump_child_stderr("D6-B-ordinary-no-flag", &stderr);

    // D7-D8: ordinary startup now REFUSES over the tracked INTENT — natural
    // fail-closed exit 1, not a signal.
    assert_eq!(
        status.code(),
        Some(1),
        "no-flag restart over a tracked INTENT must fail closed with natural exit code 1 \
         (status={status:?}); stderr=\n{stderr}"
    );
    assert!(
        status.signal().is_none(),
        "the refusal must be a natural exit, not a signal (status={status:?}); stderr=\n{stderr}"
    );
    assert!(
        stderr.contains(M_D7D8_ORDINARY_REFUSE_INTENT),
        "the ordinary-startup guard must refuse over the tracked interrupted restore (INTENT); \
         stderr=\n{stderr}"
    );
    // A no-flag start still prints the normal-startup line (the restore branch
    // returned Ok(None)) BEFORE the guard refuses.
    assert!(
        stderr.contains(M_NO_RESTORE),
        "ordinary start prints the normal-startup line before the guard; stderr=\n{stderr}"
    );
    assert!(
        capture.is_complete(),
        "stderr capture was not complete ({capture:?}); cannot assert forbidden markers"
    );
    // The guard refuses BEFORE opening affected state or entering the loop.
    for forbidden in [
        M_CONSENSUS_LOOP_STARTED,
        M_LOOP_REACHED,
        M_RESTORE_OK,
        M_B5,
        M_BASELINE_APPLIED,
    ] {
        assert!(
            !stderr.contains(forbidden),
            "a refused no-flag restart must not emit {forbidden:?}; stderr=\n{stderr}"
        );
    }
    // A no-flag start attempts no marker write, so the marker-open failure must
    // NOT recur.
    assert!(
        !stderr.contains(M_MARKER_OPEN_FAIL),
        "a no-flag start writes no restore marker; the marker-open failure must not recur; \
         stderr=\n{stderr}"
    );

    // Independent post-process reads (after reap): the refusal changed nothing.
    let (acct_after, obs_after) = observe_restored_data_dir(failed.data_dir.path());
    assert_eq!(
        acct_after, acct_before,
        "the refused restart must not change the restored account value"
    );
    assert_eq!(
        obs_after, obs_before,
        "the refused restart must not persist any committed epoch (still \
         PresentNoCommittedEpoch)"
    );
    assert_eq!(obs_after, ConsensusStorageObservation::PresentNoCommittedEpoch);
    // The retained INTENT record is not removed to make startup pass.
    match read_rtr(failed.data_dir.path()).expect("read RTR after refused restart") {
        RtrReadResult::Present(rec) => assert_eq!(
            rec.state,
            RtrState::Intent,
            "the refused restart must retain the fail-closed INTENT record"
        ),
        other => panic!("expected a retained INTENT RTR, got {other:?}"),
    }
    // The obstructing marker directory and sentinel are unchanged.
    assert!(
        failed.marker_dir_path.is_dir(),
        "the refused restart must not repair or replace the obstructing marker directory"
    );
    let sentinel_after =
        std::fs::read(&failed.sentinel_path).expect("read sentinel after restart");
    assert_eq!(
        sentinel_after, sentinel_before,
        "the refused restart must not mutate the marker directory's sentinel bytes"
    );
}

/// D7-D6/D8 case C — repeat the ORIGINAL restore request WITH the flag over
/// the unchanged failed destination produced by case A.
///
/// **Run 422 D7-D8 containment.** Case A now leaves a durable `INTENT`
/// restore-transaction record. The requested-restore precondition
/// (`evaluate_requested_restore_precondition`) observes that existing record
/// FIRST — before D5 validation, the occupancy/target-eligibility check, or any
/// mutation — and REFUSES (natural exit 1): a requested restore never
/// overwrites or replaces an existing `INTENT`/`COMPLETE`. Because the refusal
/// now precedes `materialize_validated_snapshot`, neither the
/// `TargetStateNotEmpty` occupancy refusal NOR the marker-open failure recur.
#[test]
fn d7d6_c_repeated_restore_with_flag_over_marker_obstructed_failure() {
    let failed = produce_and_verify_marker_obstructed_failure("D6-C-pre-failure");

    // Pre-retry independent reads (the refused retry must not move these).
    let (acct_before, obs_before) = observe_restored_data_dir(failed.data_dir.path());
    assert_eq!(acct_before, AccountState::new(7, 4242));
    assert_eq!(obs_before, ConsensusStorageObservation::PresentNoCommittedEpoch);
    let sentinel_before = std::fs::read(&failed.sentinel_path).expect("read sentinel before retry");

    // Retry the SAME restore request over the unchanged destination.
    let args = restore_localmesh_args(failed.data_dir.path(), &failed.snapshot_dir);
    log_executable_provenance("D6-C-retry-with-flag", &args);
    let (status, stderr, capture) = {
        let mut child = DrainedChild::spawn(&args);
        let status = child.wait_natural_exit(NEGATIVE_DEADLINE);
        (status, child.stderr_snapshot(), child.stderr_capture())
    };
    maybe_dump_child_stderr("D6-C-retry-with-flag", &stderr);

    // Natural fail-closed exit 1 with the SPECIFIC RTR-precondition refusal.
    assert_eq!(
        status.code(),
        Some(1),
        "WITH-flag retry over a tracked INTENT must fail closed with natural exit code 1 \
         (status={status:?}); stderr=\n{stderr}"
    );
    assert!(
        status.signal().is_none(),
        "the refusal must be a natural exit, not a signal (status={status:?}); stderr=\n{stderr}"
    );
    assert!(
        stderr.contains(M_D7D8_PRECOND_OCCUPIED),
        "must carry the D7-D8 requested-restore precondition refusal over the existing RTR; \
         stderr=\n{stderr}"
    );
    assert!(
        stderr.contains("(INTENT)"),
        "the precondition refusal must name the existing INTENT record; stderr=\n{stderr}"
    );
    // The precondition refusal PRECEDES validation, occupancy and marker write,
    // so neither TargetStateNotEmpty nor the marker-open failure recur, and no
    // fresh INTENT is published for the refused retry.
    assert!(
        !stderr.contains(M_TARGET_NOT_EMPTY),
        "the RTR precondition refuses BEFORE the occupancy check; TargetStateNotEmpty must not \
         fire; stderr=\n{stderr}"
    );
    assert!(
        !stderr.contains(M_MARKER_OPEN_FAIL),
        "the RTR precondition refuses BEFORE write_restore_marker; the marker-open failure must \
         not recur; stderr=\n{stderr}"
    );
    assert!(
        !stderr.contains(M_D7D8_INTENT_PUBLISHED),
        "a refused retry must not publish a fresh INTENT over the existing record; stderr=\n{stderr}"
    );
    assert!(
        !stderr.contains(M_D7D5_CLI_COMBO_REJECT),
        "no CLI exit mode is selected; the combination guard must not fire; stderr=\n{stderr}"
    );
    // Complete capture before any forbidden-marker claim.
    assert!(
        capture.is_complete(),
        "stderr capture was not complete ({capture:?}); cannot assert forbidden markers"
    );
    // No new successful restore, baseline application, or epoch persistence.
    for forbidden in [M_RESTORE_OK, M_B5, M_LOOP_REACHED, M_BASELINE_APPLIED, M_EPOCH_PERSIST] {
        assert!(
            !stderr.contains(forbidden),
            "refused WITH-flag retry must not emit {forbidden:?}; stderr=\n{stderr}"
        );
    }

    // Independent post-process reads: account, missing committed epoch, the
    // retained INTENT record, and the obstruction/sentinel are all preserved.
    let (acct_after, obs_after) = observe_restored_data_dir(failed.data_dir.path());
    assert_eq!(
        acct_after, acct_before,
        "refused retry must not change the restored account value"
    );
    assert_eq!(
        obs_after, obs_before,
        "refused retry must not persist any committed epoch (still PresentNoCommittedEpoch)"
    );
    assert_eq!(obs_after, ConsensusStorageObservation::PresentNoCommittedEpoch);
    match read_rtr(failed.data_dir.path()).expect("read RTR after refused retry") {
        RtrReadResult::Present(rec) => assert_eq!(
            rec.state,
            RtrState::Intent,
            "the refused retry must retain the original fail-closed INTENT record"
        ),
        other => panic!("expected a retained INTENT RTR, got {other:?}"),
    }
    assert!(
        failed.marker_dir_path.is_dir(),
        "refused retry must not repair or replace the obstructing marker directory"
    );
    let sentinel_after = std::fs::read(&failed.sentinel_path).expect("read sentinel after retry");
    assert_eq!(
        sentinel_after, sentinel_before,
        "refused retry must not mutate the marker directory's sentinel bytes"
    );
}

// ============================================================================
// Runner controls (test-only child command; NOT qbind-node protocol evidence)
// ============================================================================
//
// These cases exercise the OUTCOME CLASSIFICATION and cleanup behavior of the
// process runner itself using a tiny single-process child, kept deliberately
// separate from the qbind-node protocol cases above. They assert that:
//   * a child that prints the expected marker then exits UNSUCCESSFULLY is
//     REJECTED (not accepted as a positive), with its exit code preserved —
//     and its completed exit is established via a bounded PROCESS-STATUS wait
//     (not a fixed sleep) before the already-exited path is exercised;
//   * a child that prints the expected marker and stays ALIVE is correctly
//     identified as observed-then-deliberately-SIGKILL-terminated, and cleanup
//     completes well within a generous outer bound (no surviving pipe-holding
//     descendant blocks the drain-thread joins);
//   * a missing-marker child hits the bounded deadline, is a FAILURE, and again
//     cleanup completes within the generous outer bound.
//
// Every control uses a SINGLE-PROCESS waiting child (`exec sleep` after the
// marker) so that killing it closes the captured pipes immediately — there is
// never a descendant still holding stdout/stderr. No process-global environment
// is mutated, so these run safely in parallel.

/// Short bounded deadline for the runner-control cases (they must not depend on
/// the long protocol deadlines).
#[cfg(unix)]
const RUNNER_CONTROL_DEADLINE: Duration = Duration::from_secs(5);

/// Generous outer bound for runner-control CLEANUP. If cleanup ever waited on a
/// surviving `sleep 30` descendant, the elapsed time would blow past this; it
/// is deliberately far below 30s but comfortable for a loaded CI host.
#[cfg(unix)]
const RUNNER_CONTROL_CLEANUP_OUTER_BOUND: Duration = Duration::from_secs(15);

/// Bounded process-status wait for `establish_exit` in the controls.
#[cfg(unix)]
const RUNNER_CONTROL_EXIT_WAIT: Duration = Duration::from_secs(10);

impl DrainedChild {
    /// A single-process control child that prints `marker` to stderr and then
    /// `exec sleep`s, so ONE process holds the captured pipes. Killing it
    /// closes the pipes immediately (no descendant survives to block joins).
    #[cfg(unix)]
    fn sh_marker_then_exec_sleep(marker: &str) -> Self {
        let script = format!("printf '%s\\n' '{marker}' 1>&2; exec sleep 30");
        Self::sh_child(&script)
    }
}

#[cfg(unix)]
#[test]
fn runner_control_rejects_marker_then_unsuccessful_exit() {
    let marker = "runner-control-marker-A";
    // Single-process child: `printf` is a shell builtin (no fork) and `exit 7`
    // exits the shell itself, so there is no pipe-holding descendant.
    let script = format!("printf '%s\\n' '{marker}' 1>&2; exit 7");
    let mut child = DrainedChild::sh_child(&script);

    // Establish the child's COMPLETED exit via a bounded process-status wait
    // (repeated `try_wait`, NOT a fixed sleep) BEFORE exercising the
    // already-exited observation path. This removes the scheduling race in
    // which the runner's kill could otherwise land first.
    let established = child.establish_exit(RUNNER_CONTROL_EXIT_WAIT);
    assert_eq!(
        established.code(),
        Some(7),
        "bounded status wait established the real exit code before observation"
    );

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
    // Single-process: `exec sleep` replaces the shell, so the ONLY process
    // holding the pipes is the sleep — killing it closes them at once.
    let mut child = DrainedChild::sh_marker_then_exec_sleep(marker);
    let start = Instant::now();
    let outcome = child.observe_then_terminate(&[marker], RUNNER_CONTROL_DEADLINE);
    let elapsed = start.elapsed();
    match outcome {
        PositiveObservation::ObservedThenTerminated {
            stderr,
            term_signal,
            capture,
        } => {
            assert!(stderr.contains(marker), "marker observed; stderr=\n{stderr}");
            assert_eq!(
                term_signal, EXPECTED_TERMINATION_SIGNAL,
                "deliberate termination carries the expected SIGKILL"
            );
            assert!(
                capture.is_complete(),
                "single-process control yields complete capture; got {capture:?}"
            );
        }
        other => panic!("expected deliberate-termination identification, got {other:?}"),
    }
    // Honest, bounded cleanup: because no descendant survives to hold the pipes,
    // the kill+reap+drain-join completes far below the surviving-sleep duration.
    assert!(
        elapsed < RUNNER_CONTROL_CLEANUP_OUTER_BOUND,
        "cleanup must not wait on a surviving descendant sleep; elapsed={elapsed:?} \
         (outer bound {RUNNER_CONTROL_CLEANUP_OUTER_BOUND:?})"
    );
}

#[cfg(unix)]
#[test]
fn runner_control_missing_marker_deadline_is_failure() {
    // Single-process alive child that never prints the marker (`exec sleep`, so
    // no pipe-holding descendant) → bounded deadline is a failure, and cleanup
    // does not wait on any surviving descendant.
    let mut child = DrainedChild::sh_child("exec sleep 30");
    let start = Instant::now();
    let outcome = child.observe_then_terminate(&["never-emitted-marker"], RUNNER_CONTROL_DEADLINE);
    let elapsed = start.elapsed();
    match outcome {
        PositiveObservation::Deadline { stderr, capture } => {
            // The never-emitted marker is genuinely absent, and the capture was
            // COMPLETE/untruncated — so absence is a real observation, not a
            // truncation or capture-failure artifact.
            assert!(!stderr.contains("never-emitted-marker"));
            assert!(
                capture.is_complete(),
                "runner-control child emitted nothing to drop; capture must be complete, \
                 got {capture:?}"
            );
        }
        other => panic!("expected a bounded-deadline failure, got {other:?}"),
    }
    // Deadline result plus cleanup must return within the generous outer bound;
    // a result returned only after the 30s descendant sleep would NOT be
    // bounded cleanup.
    assert!(
        elapsed < RUNNER_CONTROL_CLEANUP_OUTER_BOUND,
        "deadline+cleanup must return within the generous outer bound; elapsed={elapsed:?} \
         (outer bound {RUNNER_CONTROL_CLEANUP_OUTER_BOUND:?})"
    );
}

// ============================================================================
// Constructed classification controls (NOT real-child observations)
// ============================================================================
//
// The following tests exercise the runner's pure classification logic with
// CONSTRUCTED `ExitStatus` values and CONSTRUCTED capture state. They are
// deliberately distinguished from the real-child runner controls above and from
// the qbind-node protocol/evidence cases: they establish the decision table
// deterministically, without any process scheduling.

/// B1 classification table over constructed statuses (`ExitStatus::from_raw`):
/// only a successful kill request whose signal equals SIGKILL is accepted.
#[cfg(unix)]
#[test]
fn classify_termination_decision_table() {
    // (a) Successful requested termination with the expected signal ⇒ accepted.
    let sigkill = ExitStatus::from_raw(EXPECTED_TERMINATION_SIGNAL);
    assert_eq!(
        classify_termination(true, sigkill, EXPECTED_TERMINATION_SIGNAL),
        TerminationClass::DeliberatelyTerminated {
            term_signal: EXPECTED_TERMINATION_SIGNAL
        },
        "kill succeeded and signal matches SIGKILL ⇒ deliberate termination"
    );

    // (b) A DIFFERENT terminating signal (e.g. SIGABRT=6, a crash during the
    //     race) is rejected even though the kill request succeeded.
    let sigabrt = ExitStatus::from_raw(6);
    assert_eq!(
        classify_termination(true, sigabrt, EXPECTED_TERMINATION_SIGNAL),
        TerminationClass::UnexpectedSignal { term_signal: 6 },
        "a different terminating signal is NOT accepted as deliberate termination"
    );

    // (c) A FAILED kill request never becomes an accepted positive outcome,
    //     even if the observed signal happens to equal SIGKILL.
    assert_eq!(
        classify_termination(false, sigkill, EXPECTED_TERMINATION_SIGNAL),
        TerminationClass::KillRequestFailed,
        "a failed kill request is never an accepted positive outcome"
    );

    // (d) An already-exited child retains its ACTUAL natural exit status
    //     (code 7, no signal), regardless of the kill result.
    let exit7 = ExitStatus::from_raw(7 << 8);
    assert_eq!(exit7.code(), Some(7), "constructed natural exit code 7");
    assert_eq!(exit7.signal(), None, "constructed status has no terminating signal");
    assert_eq!(
        classify_termination(true, exit7, EXPECTED_TERMINATION_SIGNAL),
        TerminationClass::NaturalExit { code: Some(7) },
        "a natural exit retains its real code and is not a deliberate termination"
    );
    assert_eq!(
        classify_termination(false, exit7, EXPECTED_TERMINATION_SIGNAL),
        TerminationClass::NaturalExit { code: Some(7) },
        "a natural exit is a natural exit regardless of the kill result"
    );
}

/// B2 control: a test-local reader that yields bytes and then returns an I/O
/// error. `drain_into` must record the read FAILURE (not a silent break), so
/// the capture is classified `ReadFailed` and cannot support an absence claim.
#[test]
fn capture_read_error_is_propagated_not_silently_dropped() {
    struct ErringReader {
        emitted: bool,
    }
    impl Read for ErringReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.emitted {
                return Err(io::Error::other("injected read failure"));
            }
            self.emitted = true;
            let bytes = b"partial-before-error\n";
            let n = bytes.len().min(buf.len());
            buf[..n].copy_from_slice(&bytes[..n]);
            Ok(n)
        }
    }

    let sink = Arc::new(Mutex::new(CapturedStream::default()));
    drain_into(ErringReader { emitted: false }, sink.clone());

    let guard = lock_recover(&sink);
    assert!(
        guard.buf.contains("partial-before-error"),
        "the bytes emitted before the error were still captured"
    );
    // The read failure is recorded as the stream's terminal outcome, so
    // classification reports an INCOMPLETE capture — not a clean EOF.
    let outcome = classify_capture(&guard, /* thread_panicked */ false);
    match &outcome {
        CaptureOutcome::ReadFailed { detail } => {
            assert!(detail.contains("read error"), "bounded failure description: {detail}");
        }
        other => panic!("expected ReadFailed, got {other:?}"),
    }
    assert!(
        !outcome.is_complete(),
        "a read failure cannot support an absence assertion"
    );
}

/// B2 control (join-error path): a capture thread that panics must be recorded
/// as a join FAILURE, classified `ThreadPanicked`, and cannot support a
/// complete-capture claim. Exercises the exact `JoinHandle::join().is_err()`
/// branch `join_drain_threads` uses.
#[test]
fn capture_thread_join_failure_is_recorded() {
    // A thread that panics WITHOUT touching any capture mutex (so no poisoning
    // side effects): joining it yields Err, the recorded signal for a failed
    // capture thread.
    let panicking: JoinHandle<()> = thread::spawn(|| panic!("injected capture-thread failure"));
    assert!(
        panicking.join().is_err(),
        "a panicked capture thread joins with an error (the recorded join-failure signal)"
    );
    let ok: JoinHandle<()> = thread::spawn(|| {});
    assert!(ok.join().is_ok(), "a clean capture thread joins without error");

    // A thread failure classifies as ThreadPanicked regardless of buffered
    // bytes, and cannot support an absence assertion.
    let stream = CapturedStream {
        buf: "some-buffered-output".to_string(),
        dropped_bytes: 0,
        read_outcome: Some(Ok(())),
    };
    let outcome = classify_capture(&stream, /* thread_panicked */ true);
    assert_eq!(outcome, CaptureOutcome::ThreadPanicked);
    assert!(!outcome.is_complete(), "a capture-thread failure is not complete capture");
}

/// B2 truncation control: a reader that emits MORE than the ring cap then EOF.
/// The capture drops bytes, is classified `Truncated`, and an absence assertion
/// cannot rest on it — even though the read itself ended cleanly.
#[test]
fn capture_truncation_cannot_support_absence() {
    struct OverflowReader {
        remaining: usize,
    }
    impl Read for OverflowReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Ok(0); // clean EOF
            }
            let n = buf.len().min(self.remaining);
            for b in buf[..n].iter_mut() {
                *b = b'x';
            }
            self.remaining -= n;
            Ok(n)
        }
    }

    // Emit CAP + 4 KiB so the ring cap must drop bytes, then EOF cleanly.
    let overflow = OverflowReader {
        remaining: CAPTURE_CAP_BYTES + 4096,
    };
    let sink = Arc::new(Mutex::new(CapturedStream::default()));
    drain_into(overflow, sink.clone());

    let guard = lock_recover(&sink);
    assert_eq!(guard.buf.len(), CAPTURE_CAP_BYTES, "buffer capped at the ring bound");
    assert!(guard.dropped_bytes > 0, "overflow forced byte drops");
    let outcome = classify_capture(&guard, /* thread_panicked */ false);
    match outcome {
        CaptureOutcome::Truncated { dropped_bytes } => {
            assert_eq!(dropped_bytes, guard.dropped_bytes);
        }
        other => panic!("expected Truncated, got {other:?}"),
    }
    assert!(
        !classify_capture(&guard, false).is_complete(),
        "a truncated capture cannot support an absence assertion, despite a clean EOF"
    );
}

/// A clean, complete, untruncated capture is the ONLY outcome that supports an
/// absence assertion.
#[test]
fn complete_capture_is_the_only_absence_supporting_outcome() {
    let stream = CapturedStream {
        buf: "hello".to_string(),
        dropped_bytes: 0,
        read_outcome: Some(Ok(())),
    };
    assert_eq!(classify_capture(&stream, false), CaptureOutcome::Complete);
    assert!(classify_capture(&stream, false).is_complete());
}

// ============================================================================
// Run 422 D7-D8 — Correction A/B and completion-lifecycle release-binary cases
//
// These cases explicitly select the VM-v0 execution profile so the protected
// persistent account state is actually opened (the LocalMesh default-profile
// cases above never reach a VM-v0 open, so they cannot witness the ordering
// boundary Correction A establishes). Evidence level: child-process /
// release-binary for the ordered markers; independent in-process reopen for the
// post-process account read.
// ============================================================================

/// Append `--execution-profile vm-v0` to a base argv so the binary opens the
/// protected VM-v0 persistent account state.
fn with_vm_v0_profile(mut args: Vec<String>) -> Vec<String> {
    args.push("--execution-profile".to_string());
    args.push("vm-v0".to_string());
    args
}

/// Correction A — the protected VM-v0 account state is opened ONLY after the
/// durable restore-completion boundary (INTENT published -> durable epoch
/// barrier -> COMPLETE published). A restore that just completed opens the
/// restored database existing-only (Correction B).
#[test]
fn d7d8_correction_a_vm_v0_state_opens_only_after_durable_complete() {
    let chain_id = devnet_chain_id();
    let src = tempdir().expect("tempdir");
    let snap_root = tempdir().expect("tempdir");
    let data_dir = tempdir().expect("tempdir");
    let snapshot_dir = snap_root.path().join("snap-a");
    build_real_snapshot(src.path(), &snapshot_dir, chain_id, 210, 4242, Some(7));

    let args = with_vm_v0_profile(restore_localmesh_args(data_dir.path(), &snapshot_dir));
    log_executable_provenance("D7D8-A-order", &args);
    let stderr = {
        let mut child = DrainedChild::spawn(&args);
        child
            .observe_then_terminate(&[M_VM_V0_OPENED], POSITIVE_DEADLINE)
            .expect_observed_then_terminated("D7D8-A-order")
    };
    maybe_dump_child_stderr("D7D8-A-order", &stderr);

    // The protected VM-v0 state open must follow the entire durable completion
    // boundary: INTENT published -> Run 097 durable epoch effect -> COMPLETE
    // published -> only THEN the VM-v0 persistent-state open.
    assert_marker_order(
        &stderr,
        &[
            M_D7D8_INTENT_PUBLISHED,
            M_EPOCH_PERSIST,
            M_D7D8_COMPLETE_PUBLISHED,
            M_VM_V0_OPENED,
        ],
    );
    // A just-completed restore opens the restored database existing-only.
    assert!(
        stderr.contains(M_VM_V0_MODE_EXISTING),
        "a completed restore must open the protected state existing-only; stderr=\n{stderr}"
    );
}

/// Correction B (through the release binary) — a COMPLETE-admitted destination
/// whose restored database is absent/unrelated-only/empty must fail closed on
/// ordinary restart WITHOUT silently initializing a replacement database.
///
/// Phase 1 produces a genuine COMPLETE + real restored database through the
/// binary. Phase 2a replaces the database with an unrelated-only directory:
/// the structural pre-filter admits it, but the existing-only open fails closed
/// (`[T164] ERROR`) and no new database is initialized. Phase 2b empties the
/// directory: the ordinary-startup guard itself refuses (missing/empty state).
#[test]
fn d7d8_correction_b_missing_or_unrelated_state_refuses_via_binary() {
    let chain_id = devnet_chain_id();
    let src = tempdir().expect("tempdir");
    let snap_root = tempdir().expect("tempdir");
    let data_dir = tempdir().expect("tempdir");
    let snapshot_dir = snap_root.path().join("snap-b");
    build_real_snapshot(src.path(), &snapshot_dir, chain_id, 220, 4242, Some(7));

    // ---- Phase 1: produce a genuine COMPLETE + real restored database. ----
    let restore_args = with_vm_v0_profile(restore_localmesh_args(data_dir.path(), &snapshot_dir));
    log_executable_provenance("D7D8-B-phase1-restore", &restore_args);
    {
        let mut child = DrainedChild::spawn(&restore_args);
        child
            .observe_then_terminate(&[M_VM_V0_OPENED], POSITIVE_DEADLINE)
            .expect_observed_then_terminated("D7D8-B-phase1-restore");
    }
    let state_dir = data_dir.path().join(VM_V0_STATE_SUBDIR);
    assert!(
        state_dir.join("CURRENT").exists(),
        "phase 1 must leave a real RocksDB restored database (CURRENT present)"
    );

    // ---- Phase 2a: replace the DB with an unrelated-only directory. ----
    std::fs::remove_dir_all(&state_dir).expect("remove restored db");
    std::fs::create_dir_all(&state_dir).expect("recreate state dir");
    let sentinel = state_dir.join("UNRELATED.txt");
    let sentinel_bytes = b"not-a-rocksdb-sentinel";
    std::fs::write(&sentinel, sentinel_bytes).expect("write unrelated sentinel");

    let ordinary_args = with_vm_v0_profile(ordinary_localmesh_args(data_dir.path()));
    log_executable_provenance("D7D8-B-phase2a-unrelated", &ordinary_args);
    let (status_a, stderr_a) = {
        let mut child = DrainedChild::spawn(&ordinary_args);
        let status = child.wait_natural_exit(NEGATIVE_DEADLINE);
        (status, child.stderr_snapshot())
    };
    maybe_dump_child_stderr("D7D8-B-phase2a-unrelated", &stderr_a);
    assert_eq!(
        status_a.code(),
        Some(1),
        "unrelated-only state must fail closed with natural exit 1; stderr=\n{stderr_a}"
    );
    assert!(
        stderr_a.contains(M_T164_ERROR),
        "unrelated-only state must be refused at the existing-only VM-v0 open; stderr=\n{stderr_a}"
    );
    // No replacement database was initialized, and the sentinel is preserved.
    assert!(
        !state_dir.join("CURRENT").exists(),
        "a refused existing-only open must NOT initialize a new database (no CURRENT)"
    );
    assert_eq!(
        std::fs::read(&sentinel).expect("read sentinel"),
        sentinel_bytes,
        "the unrelated sentinel must be preserved byte-for-byte"
    );

    // ---- Phase 2b: empty the directory entirely. ----
    std::fs::remove_dir_all(&state_dir).expect("remove unrelated dir");
    std::fs::create_dir_all(&state_dir).expect("recreate empty state dir");
    log_executable_provenance("D7D8-B-phase2b-empty", &ordinary_args);
    let (status_b, stderr_b) = {
        let mut child = DrainedChild::spawn(&ordinary_args);
        let status = child.wait_natural_exit(NEGATIVE_DEADLINE);
        (status, child.stderr_snapshot())
    };
    maybe_dump_child_stderr("D7D8-B-phase2b-empty", &stderr_b);
    assert_eq!(
        status_b.code(),
        Some(1),
        "empty state must fail closed with natural exit 1; stderr=\n{stderr_b}"
    );
    assert!(
        stderr_b.contains(M_D7D8_MISSING_STATE),
        "empty state must be refused by the ordinary-startup guard; stderr=\n{stderr_b}"
    );
    assert!(
        !state_dir.join("CURRENT").exists(),
        "a guard refusal must NOT initialize a new database (no CURRENT)"
    );
}

/// Scenario A — a successful completion followed by an ordinary restart. The
/// restore publishes a real COMPLETE, and a later ordinary start (no restore
/// flag) is admitted through that COMPLETE, opens the SAME restored database
/// existing-only WITHOUT republishing INTENT/COMPLETE, and the restored account
/// value is preserved.
#[test]
fn d7d8_a_complete_then_ordinary_restart_preserves_state() {
    let chain_id = devnet_chain_id();
    let src = tempdir().expect("tempdir");
    let snap_root = tempdir().expect("tempdir");
    let data_dir = tempdir().expect("tempdir");
    let snapshot_dir = snap_root.path().join("snap-complete");
    build_real_snapshot(src.path(), &snapshot_dir, chain_id, 230, 4242, Some(7));

    // ---- Phase 1: real restore to durable COMPLETE. ----
    let restore_args = with_vm_v0_profile(restore_localmesh_args(data_dir.path(), &snapshot_dir));
    log_executable_provenance("D7D8-A-restart-phase1", &restore_args);
    let stderr1 = {
        let mut child = DrainedChild::spawn(&restore_args);
        child
            .observe_then_terminate(&[M_VM_V0_OPENED], POSITIVE_DEADLINE)
            .expect_observed_then_terminated("D7D8-A-restart-phase1")
    };
    maybe_dump_child_stderr("D7D8-A-restart-phase1", &stderr1);
    assert!(
        stderr1.contains(M_D7D8_COMPLETE_PUBLISHED),
        "phase 1 must publish a durable COMPLETE; stderr=\n{stderr1}"
    );

    // ---- Phase 2: ordinary restart (no restore flag) over the completed dir.
    let ordinary_args = with_vm_v0_profile(ordinary_localmesh_args(data_dir.path()));
    log_executable_provenance("D7D8-A-restart-phase2", &ordinary_args);
    let stderr2 = {
        let mut child = DrainedChild::spawn(&ordinary_args);
        child
            .observe_then_terminate(&[M_VM_V0_OPENED], POSITIVE_DEADLINE)
            .expect_observed_then_terminated("D7D8-A-restart-phase2")
    };
    maybe_dump_child_stderr("D7D8-A-restart-phase2", &stderr2);

    // The ordinary restart is admitted through the valid COMPLETE and opens the
    // restored database existing-only.
    assert!(
        stderr2.contains(M_D7D8_GUARD_PROCEED_COMPLETE),
        "ordinary restart must be admitted through the valid COMPLETE; stderr=\n{stderr2}"
    );
    assert!(
        stderr2.contains(M_VM_V0_MODE_EXISTING),
        "ordinary restart over a COMPLETE must open existing-only; stderr=\n{stderr2}"
    );
    // An ordinary restart is NOT a restore: it must not republish INTENT/COMPLETE.
    assert!(
        !stderr2.contains(M_D7D8_INTENT_PUBLISHED),
        "an ordinary restart must not republish INTENT; stderr=\n{stderr2}"
    );

    // The restored account value is preserved across the completion + restart.
    let (account, _observation) = observe_restored_data_dir(data_dir.path());
    assert_eq!(
        account,
        AccountState::new(7, 4242),
        "the completed + restarted destination preserves the restored account value"
    );
}

/// Scenario B — an occupied-target restore refusal followed by an ordinary
/// startup over the SAME legitimate (untracked) destination.
///
/// Phase 1: a requested restore against a destination whose `state_vm_v0` is
/// already occupied by a legitimate (non-RTR) database refuses at the
/// occupied-target check, WITHOUT publishing an INTENT, creating an RTR, or
/// applying the snapshot epoch. Phase 2: an ordinary startup over that same
/// destination proceeds through the ordinary lifecycle (RTR absent), preserving
/// the pre-existing account observation.
#[test]
fn d7d8_b_occupied_refusal_then_ordinary_start() {
    let chain_id = devnet_chain_id();
    let src = tempdir().expect("tempdir");
    let snap_root = tempdir().expect("tempdir");
    let data_dir = tempdir().expect("tempdir");
    let snapshot_dir = snap_root.path().join("snap-occupied-then-ordinary");
    build_real_snapshot(src.path(), &snapshot_dir, chain_id, 260, 4242, Some(7));

    // Pre-occupy the destination state_vm_v0 with a legitimate (untracked)
    // database carrying a known sentinel account.
    let state_dir = data_dir.path().join(VM_V0_STATE_SUBDIR);
    const SENTINEL_ID: [u8; 32] = [0x5B; 32];
    {
        let occupied = RocksDbAccountState::open(&state_dir).expect("open occupied state_vm_v0");
        occupied
            .put_account_state(&SENTINEL_ID, &AccountState::new(9, 999))
            .expect("seed sentinel");
        occupied.flush().expect("flush sentinel");
    }

    // ---- Phase 1: requested restore refuses at the occupied-target check. ----
    let restore_args = with_vm_v0_profile(restore_localmesh_args(data_dir.path(), &snapshot_dir));
    log_executable_provenance("D7D8-B-occupied", &restore_args);
    let (status1, stderr1) = {
        let mut child = DrainedChild::spawn(&restore_args);
        let status = child.wait_natural_exit(NEGATIVE_DEADLINE);
        (status, child.stderr_snapshot())
    };
    maybe_dump_child_stderr("D7D8-B-occupied", &stderr1);
    assert_eq!(
        status1.code(),
        Some(1),
        "occupied-target restore must fail closed with natural exit 1; stderr=\n{stderr1}"
    );
    assert!(
        stderr1.contains(M_TARGET_NOT_EMPTY),
        "the refusal must be the occupied-target check; stderr=\n{stderr1}"
    );
    // No INTENT published, no RTR created, no snapshot epoch applied.
    assert!(
        !stderr1.contains(M_D7D8_INTENT_PUBLISHED),
        "occupied-target refusal must precede INTENT publication; stderr=\n{stderr1}"
    );
    assert!(
        matches!(
            read_rtr(data_dir.path()).expect("read RTR after occupied refusal"),
            RtrReadResult::Absent
        ),
        "occupied-target refusal must not create an RTR"
    );
    assert!(
        !data_dir.path().join(RTR_FILENAME).exists(),
        "no restore-transaction record file may exist after an occupied-target refusal"
    );
    assert!(
        !stderr1.contains(M_EPOCH_PERSIST),
        "occupied-target refusal must not apply the snapshot epoch; stderr=\n{stderr1}"
    );

    // ---- Phase 2: ordinary startup over the same legitimate destination. ----
    let ordinary_args = with_vm_v0_profile(ordinary_localmesh_args(data_dir.path()));
    log_executable_provenance("D7D8-B-ordinary", &ordinary_args);
    let stderr2 = {
        let mut child = DrainedChild::spawn(&ordinary_args);
        child
            .observe_then_terminate(&[M_LOOP_REACHED], POSITIVE_DEADLINE)
            .expect_observed_then_terminated("D7D8-B-ordinary")
    };
    maybe_dump_child_stderr("D7D8-B-ordinary", &stderr2);
    // The ordinary lifecycle proceeds (RTR absent) — no INTENT/COMPLETE.
    assert!(
        !stderr2.contains(M_D7D8_INTENT_PUBLISHED) && !stderr2.contains(M_D7D8_COMPLETE_PUBLISHED),
        "an ordinary start over an untracked destination must not publish INTENT/COMPLETE; \
         stderr=\n{stderr2}"
    );
    assert!(
        matches!(
            read_rtr(data_dir.path()).expect("read RTR after ordinary start"),
            RtrReadResult::Absent
        ),
        "an ordinary start over an untracked destination must not create an RTR"
    );
    // The pre-existing sentinel account observation is preserved.
    let reopened = RocksDbAccountState::open(&state_dir).expect("reopen state_vm_v0");
    assert_eq!(
        reopened.get_account_state(&SENTINEL_ID),
        AccountState::new(9, 999),
        "the legitimate pre-existing account must be preserved across refusal + ordinary start"
    );
}

/// Scenario C — destination-lock contention, holder death, reacquisition
/// without deleting the lock file, and proof that reacquiring the lock does NOT
/// bypass an INTENT refusal.
///
/// All synchronization is deterministic (bounded marker/status polls, no
/// arbitrary sleeps) and the advisory lock file is NEVER deleted to make a step
/// pass.
#[test]
fn d7d8_c_destination_lock_contention_death_and_reacquire() {
    let data_dir = tempdir().expect("tempdir");
    let lock_path = data_dir.path().join(RESTORE_LOCK_FILENAME);

    // ---- Holder: process 1 acquires the lock and reaches the live loop. ----
    let holder_args = with_vm_v0_profile(ordinary_localmesh_args(data_dir.path()));
    log_executable_provenance("D7D8-C-holder", &holder_args);
    let mut holder = DrainedChild::spawn(&holder_args);
    assert!(
        holder.wait_for_marker_alive(M_D7D8_LOCK_ACQUIRED, POSITIVE_DEADLINE),
        "holder must acquire the destination lock while alive"
    );
    assert!(
        holder.wait_for_marker_alive(M_LOOP_REACHED, POSITIVE_DEADLINE),
        "holder must reach the consensus loop while holding the lock"
    );
    assert!(lock_path.exists(), "the advisory lock file must exist while held");

    // ---- Contender: process 2 refuses on lock contention before effects. ----
    let contender_args = with_vm_v0_profile(ordinary_localmesh_args(data_dir.path()));
    log_executable_provenance("D7D8-C-contender", &contender_args);
    let (c_status, c_stderr) = {
        let mut contender = DrainedChild::spawn(&contender_args);
        let status = contender.wait_natural_exit(NEGATIVE_DEADLINE);
        (status, contender.stderr_snapshot())
    };
    maybe_dump_child_stderr("D7D8-C-contender", &c_stderr);
    assert_eq!(
        c_status.code(),
        Some(1),
        "a competing process must fail closed with natural exit 1; stderr=\n{c_stderr}"
    );
    assert!(
        c_stderr.contains(M_D7D8_LOCK_CONTENDED),
        "the refusal must be SPECIFIC lock contention, not a port collision or generic error; \
         stderr=\n{c_stderr}"
    );
    // The contention refusal precedes protected effects: no consensus loop, no
    // INTENT publication for the contender.
    assert!(
        !c_stderr.contains(M_LOOP_REACHED),
        "the contender must refuse BEFORE reaching the consensus loop; stderr=\n{c_stderr}"
    );

    // ---- Holder death, then reacquisition WITHOUT deleting the lock file. ----
    holder.kill_and_reap();
    assert!(
        lock_path.exists(),
        "the advisory lock file must remain on disk after the holder dies (never unlinked)"
    );
    let successor_args = with_vm_v0_profile(ordinary_localmesh_args(data_dir.path()));
    log_executable_provenance("D7D8-C-successor", &successor_args);
    let s_stderr = {
        let mut successor = DrainedChild::spawn(&successor_args);
        let acquired = successor.wait_for_marker_alive(M_D7D8_LOCK_ACQUIRED, POSITIVE_DEADLINE);
        let snap = successor.stderr_snapshot();
        successor.kill_and_reap();
        assert!(acquired, "a successor must acquire the freed lock; stderr=\n{snap}");
        snap
    };
    assert!(
        s_stderr.contains(M_D7D8_LOCK_ACQUIRED),
        "the successor must acquire the lock without the file being deleted; stderr=\n{s_stderr}"
    );
    assert!(
        lock_path.exists(),
        "the advisory lock file must still exist after successor acquisition"
    );

    // ---- Reacquiring the lock does NOT bypass an INTENT refusal. ----
    // Publish a tracked INTENT for this destination, then start ordinarily: the
    // process acquires the (free) lock but the ordinary-startup guard still
    // refuses the tracked interrupted restore.
    let dest = DestinationId::canonicalize(data_dir.path()).expect("canonicalize dest");
    let intent = RestoreTransactionRecord::new_intent(&dest, [0x11; 32], [0x22; 16], Some(3));
    publish_record(data_dir.path(), &intent).expect("publish INTENT");
    let intent_args = with_vm_v0_profile(ordinary_localmesh_args(data_dir.path()));
    log_executable_provenance("D7D8-C-intent-not-bypassed", &intent_args);
    let (i_status, i_stderr) = {
        let mut child = DrainedChild::spawn(&intent_args);
        let status = child.wait_natural_exit(NEGATIVE_DEADLINE);
        (status, child.stderr_snapshot())
    };
    maybe_dump_child_stderr("D7D8-C-intent-not-bypassed", &i_stderr);
    assert_eq!(
        i_status.code(),
        Some(1),
        "an INTENT-occupied destination must refuse ordinary startup even after lock \
         reacquisition; stderr=\n{i_stderr}"
    );
    // The lock WAS acquired (proving reacquisition is possible) yet the INTENT
    // refusal still fires afterwards (reacquisition does not bypass it).
    assert_marker_order(&i_stderr, &[M_D7D8_LOCK_ACQUIRED, M_D7D8_ORDINARY_REFUSE_INTENT]);
    // The tracked INTENT is neither promoted nor removed.
    assert!(
        matches!(
            read_rtr(data_dir.path()).expect("read RTR after INTENT refusal"),
            RtrReadResult::Present(rec) if rec.state == RtrState::Intent
        ),
        "the tracked INTENT must be preserved (never auto-promoted or removed)"
    );
    assert!(lock_path.exists(), "the lock file must persist after the INTENT refusal");
}