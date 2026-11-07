use std::fs;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use qbind_node::pqc_authority_state_reset::AuthorityResetInputs;

pub struct OwnedChild(pub Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub fn wait(child: &mut Child, timeout: Duration) -> ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "child timeout; OwnedChild kills/reaps"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub fn run(inputs: &AuthorityResetInputs, output_dir: &Path) -> (i32, String) {
    let stdout = output_dir.join("cli-stdout");
    let stderr = output_dir.join("cli-stderr");
    let mut command = Command::new(env!("CARGO_BIN_EXE_qbind-node"));
    command
        .env_remove("QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY")
        .args(["--authority-state-reset", "--env", "devnet"]);
    for (flag, path) in [
        ("--data-dir", inputs.data_dir.as_ref()),
        ("--genesis-path", inputs.genesis_path.as_ref()),
        ("--p2p-trust-bundle", inputs.trust_bundle_path.as_ref()),
        (
            "--p2p-trust-bundle-ratification",
            inputs.ratification_path.as_ref(),
        ),
        (
            "--authority-state-reset-output-audit",
            inputs.audit_output_path.as_ref(),
        ),
    ] {
        if let Some(path) = path {
            command.arg(flag).arg(path);
        }
    }
    if let Some(hash) = &inputs.expected_genesis_hash {
        command.arg("--expect-genesis-hash").arg(hash);
    }
    for spec in &inputs.bundle_signing_key_specs {
        command.arg("--p2p-trust-bundle-signing-key").arg(spec);
    }
    let mut child = OwnedChild(
        command
            .stdin(Stdio::null())
            .stdout(fs::File::create(&stdout).unwrap())
            .stderr(fs::File::create(&stderr).unwrap())
            .spawn()
            .unwrap(),
    );
    let status = wait(&mut child.0, Duration::from_secs(30));
    let code = status.code().expect("CLI was not terminated by signal");
    let diagnostic = fs::read_to_string(stderr).unwrap();
    assert!(fs::read(stdout).unwrap().is_empty());
    (code, diagnostic)
}
