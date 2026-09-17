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

    let (status, stderr, capture) = {
        let mut child = DrainedChild::spawn(&args);
        let status = child.wait_natural_exit(NEGATIVE_DEADLINE);
        (status, child.stderr_snapshot(), child.stderr_capture())
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
    // A "forbidden later marker absent" assertion is only valid on COMPLETE,
    // untruncated capture: truncation, a read failure, or a capture-thread
    // failure cannot support an absence claim.
    assert!(
        capture.is_complete(),
        "stderr capture was not complete ({capture:?}); cannot assert a forbidden later \
         marker was absent"
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