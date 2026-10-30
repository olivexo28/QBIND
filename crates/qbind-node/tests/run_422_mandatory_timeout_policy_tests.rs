use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_ledger::{
    compute_canonical_genesis_hash, GenesisAllocation, GenesisConfig, GenesisCouncilConfig,
    GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy,
};

const CHILD_DEADLINE: Duration = Duration::from_secs(30);
const MAX_CAPTURE_BYTES: usize = 128 * 1024;
const TIMEOUT_PREFLIGHT_MARKER: &str = "[binary] Run 032:";
const TIMEOUT_ACTIVE_MARKER: &str = "timeout verification ACTIVE";
const P2P_TRANSPORT_UP_MARKER: &str = "[binary] P2P transport up.";

#[derive(Default)]
struct Capture {
    bytes: Vec<u8>,
}

fn drain<R: Read>(mut pipe: R, capture: Arc<Mutex<Capture>>) {
    let mut buffer = [0; 4096];
    loop {
        match pipe.read(&mut buffer) {
            Ok(0) => break,
            Ok(size) => {
                let mut capture = capture.lock().expect("capture lock");
                let remaining = MAX_CAPTURE_BYTES.saturating_sub(capture.bytes.len());
                capture
                    .bytes
                    .extend_from_slice(&buffer[..size.min(remaining)]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

struct SupervisedChild {
    child: Child,
    stdout: Arc<Mutex<Capture>>,
    stderr: Arc<Mutex<Capture>>,
    stdout_thread: Option<JoinHandle<()>>,
    stderr_thread: Option<JoinHandle<()>>,
    reaped: bool,
}

impl SupervisedChild {
    fn spawn(args: &[String]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_qbind-node"))
            .args(args)
            .env_remove("QBIND_METRICS_HTTP_ADDR")
            .env_remove("QBIND_MUTUAL_AUTH")
            .env_remove("QBIND_DRAIN_ONCE_DELAY_SECS")
            .env_remove("QBIND_DEVNET_FORGED_INJECTION")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn qbind-node");
        let stdout = Arc::new(Mutex::new(Capture::default()));
        let stderr = Arc::new(Mutex::new(Capture::default()));
        let stdout_pipe = child.stdout.take().expect("piped stdout");
        let stderr_pipe = child.stderr.take().expect("piped stderr");
        let out_capture = stdout.clone();
        let err_capture = stderr.clone();
        Self {
            child,
            stdout,
            stderr,
            stdout_thread: Some(thread::spawn(move || drain(stdout_pipe, out_capture))),
            stderr_thread: Some(thread::spawn(move || drain(stderr_pipe, err_capture))),
            reaped: false,
        }
    }

    fn stdout_snapshot(&self) -> String {
        String::from_utf8_lossy(&self.stdout.lock().expect("stdout capture lock").bytes)
            .into_owned()
    }

    fn stderr_snapshot(&self) -> String {
        String::from_utf8_lossy(&self.stderr.lock().expect("stderr capture lock").bytes)
            .into_owned()
    }

    fn join_drains(&mut self) {
        if let Some(thread) = self.stdout_thread.take() {
            thread.join().expect("join stdout drain");
        }
        if let Some(thread) = self.stderr_thread.take() {
            thread.join().expect("join stderr drain");
        }
    }

    fn observe_exit(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        if status.is_some() {
            self.reaped = true;
            self.join_drains();
        }
        Ok(status)
    }

    fn kill_and_reap(&mut self) -> io::Result<()> {
        if !self.reaped {
            if self.child.try_wait()?.is_none() {
                let _ = self.child.kill();
                let _status = self.child.wait()?;
            }
            self.reaped = true;
        }
        self.join_drains();
        Ok(())
    }

    fn wait_for_exit(&mut self, deadline: Duration) -> io::Result<ExitStatus> {
        let start = Instant::now();
        loop {
            if let Some(status) = self.observe_exit()? {
                return Ok(status);
            }
            if start.elapsed() >= deadline {
                let stderr = self.stderr_snapshot();
                self.kill_and_reap()?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("child did not exit within {deadline:?}; stderr:\n{stderr}"),
                ));
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn wait_for_stderr_marker(&mut self, marker: &str, deadline: Duration) -> io::Result<String> {
        let start = Instant::now();
        loop {
            let stderr = self.stderr_snapshot();
            if stderr.contains(marker) {
                return Ok(stderr);
            }
            if let Some(status) = self.observe_exit()? {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "child exited ({:?}) before marker {marker:?}; stderr:\n{}",
                        status.code(),
                        self.stderr_snapshot()
                    ),
                ));
            }
            if start.elapsed() >= deadline {
                let stderr = self.stderr_snapshot();
                self.kill_and_reap()?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "marker {marker:?} not observed within {deadline:?}; stderr:\n{stderr}"
                    ),
                ));
            }
            thread::sleep(Duration::from_millis(25));
        }
    }
}

impl Drop for SupervisedChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.kill_and_reap();
        } else {
            self.join_drains();
        }
    }
}

struct TempInputs {
    dir: PathBuf,
    genesis: PathBuf,
    data: PathBuf,
    keystore: PathBuf,
    hash: String,
    public_key_hex: String,
}

impl Drop for TempInputs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .expect("restrict temporary fixture permissions");
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &std::path::Path, _mode: u32) {}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn startup_inputs() -> TempInputs {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "qbind-run422-mandatory-timeout-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create isolated startup directory");
    restrict_permissions(&dir, 0o700);

    let (validator_zero_pk, validator_zero_sk) =
        MlDsa44Backend::generate_keypair().expect("validator zero ML-DSA-44 keygen");
    let mut validators = vec![GenesisValidator::new(
        "00".repeat(32),
        hex(&validator_zero_pk),
        100_000u128,
    )];
    for i in 1..3 {
        let (pk, _) = MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen");
        validators.push(GenesisValidator::new(
            format!("{i:02x}").repeat(32),
            hex(&pk),
            100_000u128,
        ));
    }
    let genesis = GenesisConfig::new(
        "0000000051424e44",
        1_738_000_000_000,
        vec![GenesisAllocation::new(
            "0x1111111111111111111111111111111111111111",
            1_000_000u128,
        )],
        validators,
        GenesisCouncilConfig::new(
            vec![
                "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
                "0xdddddddddddddddddddddddddddddddddddddddd".to_string(),
                "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
            ],
            2,
        ),
        GenesisMonetaryConfig::mainnet_default(),
    );
    let hash = compute_canonical_genesis_hash(&genesis, NetworkEnvironmentPolicy::Devnet);
    let genesis_path = dir.join("genesis.json");
    std::fs::write(
        &genesis_path,
        serde_json::to_vec_pretty(&genesis).expect("serialize genesis"),
    )
    .expect("write genesis");
    let data = dir.join("data");
    std::fs::create_dir_all(&data).expect("create data directory");
    let keystore = dir.join("keystore");
    std::fs::create_dir_all(&keystore).expect("create signer keystore");
    restrict_permissions(&keystore, 0o700);
    let signer_file = keystore.join("validator-0.json");
    std::fs::write(
        &signer_file,
        format!(
            "{{\n  \"suite_id\": 100,\n  \"private_key_hex\": \"{}\"\n}}\n",
            hex(&validator_zero_sk)
        ),
    )
    .expect("write temporary signer fixture");
    restrict_permissions(&signer_file, 0o600);

    TempInputs {
        dir,
        genesis: genesis_path,
        data,
        keystore,
        hash: format!("0x{}", hex(&hash)),
        public_key_hex: hex(&validator_zero_pk),
    }
}

fn p2p_args(input: &TempInputs, with_signer: bool) -> Vec<String> {
    let mut args = vec![
        "--env".to_string(),
        "devnet".to_string(),
        "--data-dir".to_string(),
        input.data.display().to_string(),
        "--genesis-path".to_string(),
        input.genesis.display().to_string(),
        "--expect-genesis-hash".to_string(),
        input.hash.clone(),
        "--network-mode".to_string(),
        "p2p".to_string(),
        "--enable-p2p".to_string(),
        "--p2p-listen-addr".to_string(),
        "127.0.0.1:0".to_string(),
        "--validator-id".to_string(),
        "0".to_string(),
    ];
    if with_signer {
        args.extend([
            "--signer-keystore-path".to_string(),
            input.keystore.display().to_string(),
            "--validator-consensus-key".to_string(),
            format!("0:100:{}", input.public_key_hex),
        ]);
    }
    args
}

#[test]
fn p2p_startup_without_timeout_context_refuses_even_without_compatibility_flag() {
    let input = startup_inputs();
    let mut child = SupervisedChild::spawn(&p2p_args(&input, false));
    let status = child
        .wait_for_exit(CHILD_DEADLINE)
        .unwrap_or_else(|error| panic!("bounded P2P refusal failed: {error}"));
    let stderr = child.stderr_snapshot();
    let stdout = child.stdout_snapshot();

    assert!(!status.success(), "P2P consensus must fail closed");
    assert!(
        stderr.contains("[binary] Run 032:"),
        "startup must reach the timeout-verification preflight, not fail earlier: {stderr}"
    );
    assert!(
        stderr.contains("P2P consensus requires timeout verification"),
        "refusal must identify the missing verification policy: {stderr}"
    );
    assert!(
        stderr.contains("local validator signer could not be loaded"),
        "refusal must identify the missing signer prerequisite: {stderr}"
    );
    assert!(
        !stderr.contains(P2P_TRANSPORT_UP_MARKER) && !stdout.contains(P2P_TRANSPORT_UP_MARKER),
        "P2P transport must not start without the context"
    );
}

#[test]
fn p2p_startup_accepts_valid_timeout_context_without_compatibility_flag() {
    let input = startup_inputs();
    let child_args = p2p_args(&input, true);
    assert!(
        !child_args
            .iter()
            .any(|arg| arg == "--require-timeout-verification"),
        "positive control must not rely on the compatibility flag"
    );
    let mut child = SupervisedChild::spawn(&child_args);
    let stderr = child
        .wait_for_stderr_marker(TIMEOUT_ACTIVE_MARKER, CHILD_DEADLINE)
        .unwrap_or_else(|error| panic!("bounded active-preflight control failed: {error}"));
    child
        .kill_and_reap()
        .expect("terminate and reap active-preflight child");

    assert!(
        stderr.contains(TIMEOUT_PREFLIGHT_MARKER),
        "positive control must pass through the same P2P timeout-verification preflight: {stderr}"
    );
    assert!(
        stderr.contains(TIMEOUT_ACTIVE_MARKER),
        "valid signer/key config must activate timeout verification: {stderr}"
    );
    assert!(
        !stderr.contains("P2P consensus requires timeout verification"),
        "valid timeout context must not trigger the missing-context refusal"
    );
    // This stops at the ACTIVE preflight marker. It proves preflight
    // acceptance, not that a P2P transport reached its later readiness marker.
}

#[test]
fn non_consensus_genesis_hash_operation_remains_available() {
    let input = startup_inputs();
    let args = vec![
        "--env".to_string(),
        "devnet".to_string(),
        "--genesis-path".to_string(),
        input.genesis.display().to_string(),
        "--print-genesis-hash".to_string(),
    ];
    let mut child = SupervisedChild::spawn(&args);
    let status = child
        .wait_for_exit(CHILD_DEADLINE)
        .unwrap_or_else(|error| panic!("bounded genesis-hash operation failed: {error}"));
    let stdout = child.stdout_snapshot();
    assert!(
        status.success(),
        "genesis hash remains available without consensus context; stdout={stdout}"
    );
    assert!(
        stdout.contains(&input.hash),
        "genesis hash output should match the canonical fixture hash"
    );
}
