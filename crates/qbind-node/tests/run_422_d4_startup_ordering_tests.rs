//! Run 422 D4 — consensus-security preflight startup-ordering proof.
//!
//! These tests drive the real `qbind-node` binary via
//! `CARGO_BIN_EXE_qbind-node`. Because they run under the default Cargo test
//! profile, they are **process tests, not standalone release-binary
//! evidence** (see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D4_D5.md`).
//!
//! Scope of the boundary being proved (task section 7):
//! `run_p2p_consensus_security_preflight(...)` runs BEFORE the P2P service is
//! constructed (`builder.build()`), before any peer is dialed, and before the
//! consensus task starts. The FATAL signer/provider/suite/policy checks inside
//! the preflight therefore terminate the process before the
//! `"[binary] P2P transport up."` marker (printed only AFTER `builder.build()`
//! opens the listener). This is preflight-before-**P2P-service-construction**,
//! NOT before "any networking": the optional metrics HTTP task is started
//! earlier in `main`, before the per-mode P2P function is entered, and is
//! intentionally out of scope here.
//!
//! Positive control: every negative case asserts a preflight log marker
//! (`[binary] Run 032:` / `[binary] Run 033:`) IS present, proving the input
//! reached the preflight rather than failing only in CLI parsing or an
//! unrelated earlier check. Absence of the P2P-transport marker alone is
//! never treated as sufficient — it is interpreted together with the inspected
//! source ordering (the marker is printed only AFTER `builder.build()` opens
//! the listener). We do NOT claim that the absence of a single log line, on its
//! own, proves that no listener was ever opened.
//!
//! Resource discipline (corrected): every child is driven by a shared,
//! deadline-based [`DrainedChild`] runner. It uses an explicit finite deadline
//! measured with a monotonic clock ([`std::time::Instant`]), and it drains BOTH
//! stdout and stderr on dedicated threads WHILE the child runs so a full OS
//! pipe buffer can never block the child at startup. Negative cases wait for
//! the child to terminate naturally within the deadline; a timeout is a TEST
//! FAILURE, never an acceptable nonzero refusal. The positive case waits for
//! the intended readiness markers within the deadline. In all paths — deadline
//! expiry, successful positive observation, and assertion-driven unwinding —
//! the child is killed and reaped and the drain threads are joined via
//! [`DrainedChild::kill_and_reap`] / its `Drop` impl; an exited child still
//! requires an explicit `wait()` to reap the zombie, which is why reaping is
//! never skipped. Captured output is size-capped for bounded memory while
//! retaining a useful diagnostic prefix. The positive case binds a loopback
//! ephemeral port (`127.0.0.1:0`); metrics/other inherited environment
//! settings that could bind non-loopback endpoints or redirect fixtures are
//! cleared so each child is isolated. Temporary keystores use `0o700`/`0o600`
//! permissions and are removed on drop.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_ledger::{
    compute_canonical_genesis_hash, GenesisAllocation, GenesisConfig, GenesisCouncilConfig,
    GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy,
};

// ---------------------------------------------------------------------------
// Markers (kept in sync with crates/qbind-node/src/main.rs).
// ---------------------------------------------------------------------------

/// Positive controls: the preflight was entered (printed at the very start of
/// `run_p2p_consensus_security_preflight`, before any FATAL exit).
const PREFLIGHT_SIGNER_MARKER: &str = "[binary] Run 032:";
const PREFLIGHT_PROBE_MARKER: &str = "[binary] Run 033:";

/// The P2P service-construction boundary: printed ONLY after
/// `builder.build()` opens the listener. It must never appear when a preflight
/// FATAL fires.
const P2P_TRANSPORT_UP_MARKER: &str = "[binary] P2P transport up.";

/// Emitted when the Timeout/NewView verification context activates.
const TIMEOUT_ACTIVE_MARKER: &str = "timeout verification ACTIVE";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn qbind_node_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_qbind-node"))
}

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "qbind-run422-d4-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&p).expect("create temp dir");
    restrict_dir(&p);
    p
}

#[cfg(unix)]
fn restrict_dir(p: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
}
#[cfg(not(unix))]
fn restrict_dir(_p: &std::path::Path) {}

#[cfg(unix)]
fn restrict_file(p: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_file(_p: &std::path::Path) {}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn fresh_keypair() -> (String, Vec<u8>) {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
    (hex_lower(&pk), sk)
}

fn validator(addr_seed: u8, pk_hex: String) -> GenesisValidator {
    GenesisValidator::new(format!("{:02x}", addr_seed).repeat(32), pk_hex, 100_000u128)
}

/// A well-formed DevNet genesis with three validators (validator 0's key is
/// `v0_pk`). Accepted by the Run 102 boot verifier under DevNet policy.
fn devnet_genesis(v0_pk: String) -> GenesisConfig {
    let (pk1, _s1) = fresh_keypair();
    let (pk2, _s2) = fresh_keypair();
    GenesisConfig::new(
        "0000000051424e44",
        1_738_000_000_000,
        vec![GenesisAllocation::new(
            "0x1111111111111111111111111111111111111111",
            1_000_000u128,
        )],
        vec![validator(1, v0_pk), validator(2, pk1), validator(3, pk2)],
        GenesisCouncilConfig::new(
            vec![
                "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
                "0xdddddddddddddddddddddddddddddddddddddddd".to_string(),
                "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
            ],
            2,
        ),
        GenesisMonetaryConfig::mainnet_default(),
    )
}

/// Owned valid startup inputs. The temp dir is removed on drop.
struct ValidInputs {
    dir: PathBuf,
    genesis_path: PathBuf,
    expect_hash_hex: String,
    data_dir: PathBuf,
    keystore_dir: PathBuf,
    /// validator-0's genesis-committed public key (hex), matching the signer.
    v0_pk_hex: String,
}

impl Drop for ValidInputs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn valid_inputs(tag: &str) -> ValidInputs {
    let dir = tmpdir(tag);
    let (v0_pk, v0_sk) = fresh_keypair();
    let genesis = devnet_genesis(v0_pk.clone());

    let genesis_path = dir.join("genesis.json");
    std::fs::write(
        &genesis_path,
        serde_json::to_vec_pretty(&genesis).expect("serialize genesis"),
    )
    .expect("write genesis");

    let expect_hash = compute_canonical_genesis_hash(&genesis, NetworkEnvironmentPolicy::Devnet);
    let expect_hash_hex = format!("0x{}", hex_lower(&expect_hash));

    let data_dir = dir.join("data");
    std::fs::create_dir_all(&data_dir).expect("create data dir");

    let keystore_dir = dir.join("keystore");
    std::fs::create_dir_all(&keystore_dir).expect("create keystore dir");
    restrict_dir(&keystore_dir);
    let ks_file = keystore_dir.join("validator-0.json");
    std::fs::write(
        &ks_file,
        format!(
            "{{\n  \"suite_id\": 100,\n  \"private_key_hex\": \"{}\"\n}}\n",
            hex_lower(&v0_sk)
        ),
    )
    .expect("write keystore");
    restrict_file(&ks_file);

    ValidInputs {
        dir,
        genesis_path,
        expect_hash_hex,
        data_dir,
        keystore_dir,
        v0_pk_hex: v0_pk,
    }
}

// ---------------------------------------------------------------------------
// Shared, deadline-based process runner (Finding A).
//
// A single small runner is used by both the negative and positive cases. It
// deliberately does NOT pull in an async runtime or a subprocess-management
// crate: it is two blocking drain threads plus a monotonic-deadline poll loop
// over `try_wait`, which is all these process tests need.
// ---------------------------------------------------------------------------

/// Finite deadline for a negative case to refuse and terminate on its own. The
/// preflight refusal is near-instant; this bound exists only to convert a
/// regression that hangs startup into a hard FAILURE instead of an infinite
/// wait.
const NEGATIVE_DEADLINE: Duration = Duration::from_secs(30);

/// Finite deadline for the positive case to reach the P2P-transport readiness
/// markers.
const POSITIVE_DEADLINE: Duration = Duration::from_secs(30);

/// Upper bound on retained captured output per stream. Bytes past the cap are
/// counted but dropped so a chatty or wedged child cannot exhaust memory; the
/// drain thread keeps reading the pipe regardless so the child never blocks.
const CAPTURE_CAP_BYTES: usize = 512 * 1024;

/// Size-capped captured stream. Retains a bounded prefix for diagnostics.
#[derive(Default)]
struct CapturedStream {
    buf: String,
    dropped_bytes: usize,
}

/// Continuously drain `reader` into `sink` until EOF, appending up to
/// `CAPTURE_CAP_BYTES` and counting the remainder. Running this on its own
/// thread guarantees the child's stdout/stderr pipe never fills and blocks the
/// child at startup.
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

/// A spawned child whose stdout/stderr are drained on dedicated threads and
/// whose lifecycle (kill + reap + thread join) is always finalized, including
/// on assertion-driven unwinding via `Drop`.
struct DrainedChild {
    child: Child,
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
            // Isolate inherited environment: no metrics/other listener may bind
            // a non-loopback endpoint, and no external env may redirect the
            // fixture. The positive case explicitly binds `127.0.0.1:0`.
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

    /// Kill the child if it is still running, then reap it. An already-exited
    /// child is still a zombie until `wait()` reaps it, so `wait()` is always
    /// called. Drain threads are joined so the pipes are fully consumed.
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
                             never an acceptable refusal. Startup may no longer be refusing \
                             fail-closed. stderr so far=\n{}",
                            deadline, err
                        );
                    }
                    thread::sleep(Duration::from_millis(25));
                }
            }
        }
    }

    /// Wait until every marker in `markers` is present in captured stderr
    /// within `deadline`. If the child exits first, or the deadline expires,
    /// the case FAILS. On success the child is killed and reaped.
    fn wait_for_markers(&mut self, markers: &[&str], deadline: Duration) -> String {
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
                    "TEST FAILURE: positive child exited ({:?}) before emitting readiness \
                     markers {:?}; stderr=\n{}",
                    status.code(),
                    markers,
                    err
                );
            }
            if start.elapsed() >= deadline {
                let err = self.stderr_snapshot();
                self.kill_and_reap();
                panic!(
                    "TEST FAILURE: readiness markers {:?} not observed within {:?}; stderr=\n{}",
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

struct Run {
    code: i32,
    stderr: String,
    stdout: String,
}

/// Run a NEGATIVE case: spawn, drain, and require a natural (non-timeout) exit
/// within the deadline.
fn run(args: &[String]) -> Run {
    let mut child = DrainedChild::spawn(args);
    let code = child.wait_natural_exit(NEGATIVE_DEADLINE);
    Run {
        code,
        stderr: child.stderr_snapshot(),
        stdout: child.stdout_snapshot(),
    }
}

/// Base argv for a P2P-mode start with a loopback ephemeral listener. The
/// signer keystore is included by default; callers that test the missing-
/// signer path override it.
fn p2p_base_args(inp: &ValidInputs, with_signer: bool) -> Vec<String> {
    let mut a = vec![
        "--env".to_string(),
        "devnet".to_string(),
        "--data-dir".to_string(),
        inp.data_dir.display().to_string(),
        "--genesis-path".to_string(),
        inp.genesis_path.display().to_string(),
        "--expect-genesis-hash".to_string(),
        inp.expect_hash_hex.clone(),
        "--network-mode".to_string(),
        "p2p".to_string(),
        "--enable-p2p".to_string(),
        "--p2p-listen-addr".to_string(),
        "127.0.0.1:0".to_string(),
        "--validator-id".to_string(),
        "0".to_string(),
    ];
    if with_signer {
        a.push("--signer-keystore-path".to_string());
        a.push(inp.keystore_dir.display().to_string());
    }
    a
}

/// Assert the preflight was reached (positive control) and the P2P service
/// was NOT constructed (refusal precedes `builder.build()`).
fn assert_refused_before_p2p(r: &Run) {
    assert_ne!(r.code, 0, "must exit non-zero; stderr=\n{}", r.stderr);
    assert!(
        r.stderr.contains(PREFLIGHT_SIGNER_MARKER) || r.stderr.contains(PREFLIGHT_PROBE_MARKER),
        "positive control: the input must reach the preflight (Run 032/033 \
         marker); stderr=\n{}",
        r.stderr
    );
    assert!(
        !r.stderr.contains(P2P_TRANSPORT_UP_MARKER) && !r.stdout.contains(P2P_TRANSPORT_UP_MARKER),
        "P2P service must NOT be constructed before the preflight refusal; \
         stderr=\n{}",
        r.stderr
    );
}

// ---------------------------------------------------------------------------
// Negative cases — RequireOrFail refusal reaches the preflight and terminates
// before P2P service construction.
// ---------------------------------------------------------------------------

/// RequireOrFail + missing local signer (no `--signer-keystore-path`): the
/// preflight refuses fail-closed with a signer-specific diagnostic, before
/// the P2P service is constructed.
#[test]
fn require_or_fail_missing_local_signer_refused_before_p2p() {
    let inp = valid_inputs("missing-signer");
    let mut args = p2p_base_args(&inp, /* with_signer */ false);
    args.push("--require-timeout-verification".to_string());
    let r = run(&args);

    assert_refused_before_p2p(&r);
    assert!(
        r.stderr
            .contains("--require-timeout-verification was set but the local validator")
            && r.stderr.contains("signer could not be loaded"),
        "expected signer-load FATAL diagnostic; stderr=\n{}",
        r.stderr
    );
}

/// RequireOrFail + present signer but INVALID peer key-provider (malformed
/// `--validator-consensus-key` hex): the preflight builds the signer half, then
/// refuses on the peer-side provider, before the P2P service is constructed.
#[test]
fn require_or_fail_invalid_peer_key_provider_refused_before_p2p() {
    let inp = valid_inputs("bad-peer-key");
    let mut args = p2p_base_args(&inp, /* with_signer */ true);
    args.extend([
        "--require-timeout-verification".to_string(),
        // Malformed hex public key for validator 0.
        "--validator-consensus-key".to_string(),
        "0:100:zzzznothex".to_string(),
    ]);
    let r = run(&args);

    assert_refused_before_p2p(&r);
    assert!(
        r.stderr
            .contains("peer-side SuiteAwareValidatorKeyProvider could not be built"),
        "expected peer-key-provider FATAL diagnostic; stderr=\n{}",
        r.stderr
    );
}

/// RequireOrFail + present signer but an UNSUPPORTED consensus suite id in the
/// peer key-provider spec: the preflight refuses on the suite check, before the
/// P2P service is constructed.
#[test]
fn require_or_fail_unsupported_suite_refused_before_p2p() {
    let inp = valid_inputs("bad-suite");
    let mut args = p2p_base_args(&inp, /* with_signer */ true);
    args.extend([
        "--require-timeout-verification".to_string(),
        // Suite id 200 is not the supported ML-DSA-44 suite (100).
        "--validator-consensus-key".to_string(),
        format!("0:200:{}", inp.v0_pk_hex),
    ]);
    let r = run(&args);

    assert_refused_before_p2p(&r);
    assert!(
        r.stderr
            .contains("peer-side SuiteAwareValidatorKeyProvider could not be built"),
        "expected suite-rejection FATAL diagnostic; stderr=\n{}",
        r.stderr
    );
}

/// RequireOrFail + present signer but the local consensus key does NOT match
/// the loaded signer (membership/identity binding failure): the preflight
/// refuses before the P2P service is constructed.
#[test]
fn require_or_fail_local_key_mismatches_signer_refused_before_p2p() {
    let inp = valid_inputs("key-mismatch");
    // A different, non-matching public key for validator 0.
    let (other_pk, _sk) = fresh_keypair();
    let mut args = p2p_base_args(&inp, /* with_signer */ true);
    args.extend([
        "--require-timeout-verification".to_string(),
        "--validator-consensus-key".to_string(),
        format!("0:100:{}", other_pk),
    ]);
    let r = run(&args);

    assert_refused_before_p2p(&r);
    assert!(
        r.stderr
            .contains("peer-side SuiteAwareValidatorKeyProvider could not be built"),
        "expected local-key-mismatch FATAL diagnostic; stderr=\n{}",
        r.stderr
    );
}

// ---------------------------------------------------------------------------
// Positive case — a valid legacy configuration passes preflight and reaches
// P2P startup. Timeout authority is available as configured; Proposal/Vote
// authority remains absent (the D5 in-process tests prove the latter).
// ---------------------------------------------------------------------------

/// Valid legacy config: matching signer + a complete `--validator-consensus-key`
/// for the local validator (no static peers ⇒ single active validator). The
/// preflight activates the Timeout/NewView context and startup proceeds past
/// `builder.build()` to the P2P-transport boundary. This proves the prepared
/// preflight result is consumed by production wiring and that a valid legacy
/// Timeout configuration coexists with an absent Proposal/Vote authority.
///
/// The child is driven by the shared deadline-based [`DrainedChild`] runner:
/// stderr is drained on a dedicated thread while the child runs, the readiness
/// markers are awaited within [`POSITIVE_DEADLINE`], and the child is killed
/// and reaped on success, on deadline expiry, and on any assertion unwinding
/// (via `Drop`).
#[test]
fn valid_legacy_config_passes_preflight_and_reaches_p2p_startup() {
    let inp = valid_inputs("valid-legacy");
    let mut args = p2p_base_args(&inp, /* with_signer */ true);
    args.extend([
        "--require-timeout-verification".to_string(),
        // Local validator 0's consensus key matches the loaded signer.
        "--validator-consensus-key".to_string(),
        format!("0:100:{}", inp.v0_pk_hex),
    ]);

    let mut child = DrainedChild::spawn(&args);
    // Await both readiness markers within the deadline. The child keeps
    // running until observed, then is killed and reaped.
    let stderr = child.wait_for_markers(
        &[TIMEOUT_ACTIVE_MARKER, P2P_TRANSPORT_UP_MARKER],
        POSITIVE_DEADLINE,
    );

    assert!(
        stderr.contains(TIMEOUT_ACTIVE_MARKER),
        "valid legacy config must activate the Timeout/NewView context; \
         stderr=\n{}",
        stderr
    );
    assert!(
        stderr.contains(P2P_TRANSPORT_UP_MARKER),
        "valid legacy config must pass preflight and reach the P2P-transport \
         boundary; stderr=\n{}",
        stderr
    );
    assert!(
        !stderr.contains("refuses to start"),
        "valid legacy config must NOT trigger any preflight refusal; \
         stderr=\n{}",
        stderr
    );
}