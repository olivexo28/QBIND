use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_ledger::{
    compute_canonical_genesis_hash, GenesisAllocation, GenesisConfig, GenesisCouncilConfig,
    GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy,
};

const STARTUP_DEADLINE: Duration = Duration::from_secs(30);

struct OwnedChild {
    child: Child,
    reaped: bool,
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct TempInputs {
    dir: PathBuf,
    genesis: PathBuf,
    data: PathBuf,
    hash: String,
}

impl Drop for TempInputs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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

    let validators = (0..3)
        .map(|i| {
            let (pk, _) = MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen");
            GenesisValidator::new(format!("{i:02x}").repeat(32), hex(&pk), 100_000u128)
        })
        .collect();
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
    TempInputs {
        dir,
        genesis: genesis_path,
        data,
        hash: format!("0x{}", hex(&hash)),
    }
}

fn drain<R: Read>(mut pipe: R, output: std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
    let mut buffer = [0; 4096];
    while let Ok(size) = pipe.read(&mut buffer) {
        if size == 0 {
            break;
        }
        let mut output = output.lock().expect("output lock");
        let remaining = (128 * 1024usize).saturating_sub(output.len());
        output.extend_from_slice(&buffer[..size.min(remaining)]);
    }
}

#[test]
fn p2p_startup_without_timeout_context_refuses_even_without_compatibility_flag() {
    let input = startup_inputs();
    let child = Command::new(env!("CARGO_BIN_EXE_qbind-node"))
        .args([
            "--env",
            "devnet",
            "--data-dir",
            input.data.to_str().expect("data path"),
            "--genesis-path",
            input.genesis.to_str().expect("genesis path"),
            "--expect-genesis-hash",
            &input.hash,
            "--network-mode",
            "p2p",
            "--enable-p2p",
            "--p2p-listen-addr",
            "127.0.0.1:0",
            "--validator-id",
            "0",
        ])
        .env_remove("QBIND_METRICS_HTTP_ADDR")
        .env_remove("QBIND_MUTUAL_AUTH")
        .env_remove("QBIND_DRAIN_ONCE_DELAY_SECS")
        .env_remove("QBIND_DEVNET_FORGED_INJECTION")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn qbind-node");
    let mut child = OwnedChild {
        child,
        reaped: false,
    };
    let stdout = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let stderr = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let out = stdout.clone();
    let err = stderr.clone();
    let stdout_pipe = child.child.stdout.take().expect("stdout");
    let stderr_pipe = child.child.stderr.take().expect("stderr");
    let stdout_thread = thread::spawn(move || drain(stdout_pipe, out));
    let stderr_thread = thread::spawn(move || drain(stderr_pipe, err));

    let start = Instant::now();
    let status = loop {
        match child.child.try_wait().expect("wait for startup refusal") {
            Some(status) => {
                child.reaped = true;
                break status;
            }
            None if start.elapsed() < STARTUP_DEADLINE => {
                thread::sleep(Duration::from_millis(25));
            }
            None => {
                let _ = child.child.kill();
                let _ = child.child.wait();
                child.reaped = true;
                stdout_thread.join().expect("join stdout drain");
                stderr_thread.join().expect("join stderr drain");
                panic!("qbind-node did not refuse startup within {STARTUP_DEADLINE:?}");
            }
        }
    };
    stdout_thread.join().expect("join stdout drain");
    stderr_thread.join().expect("join stderr drain");
    let stderr_bytes = stderr.lock().expect("stderr lock");
    let stderr = String::from_utf8_lossy(&stderr_bytes);

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
        "refusal must state the missing signer prerequisite: {stderr}"
    );
    assert!(
        !stderr.contains("[binary] P2P transport up."),
        "P2P transport must not start without the context"
    );
}

#[test]
fn non_consensus_genesis_hash_operation_remains_available() {
    let input = startup_inputs();
    let output = Command::new(env!("CARGO_BIN_EXE_qbind-node"))
        .args([
            "--env",
            "devnet",
            "--genesis-path",
            input.genesis.to_str().expect("genesis path"),
            "--print-genesis-hash",
        ])
        .output()
        .expect("run non-consensus genesis hash operation");
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(&input.hash),
        "genesis hash should remain available without consensus verification context"
    );
}
