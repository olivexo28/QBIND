//! Real CLI/real advisory lock, with owned subprocesses and synthetic files.
#![cfg(target_os = "linux")]

#[path = "support/authority_reset_cli.rs"]
mod cli;

use std::fs;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use qbind_node::pqc_authority_state::authority_state_file_path;
use qbind_node::pqc_authority_state_reset::{AuthorityResetAuditRecord, AuthorityResetInputs};
use qbind_node::restore_completion::acquire_destination_lock;
use qbind_types::NetworkEnvironment;

fn inputs(root: &std::path::Path) -> AuthorityResetInputs {
    AuthorityResetInputs {
        data_dir: Some(root.join("data")),
        genesis_path: Some(root.join("unused-genesis")),
        expected_genesis_hash: Some("ab".repeat(32)),
        trust_bundle_path: Some(root.join("unused-bundle")),
        bundle_signing_key_specs: Vec::new(),
        ratification_path: Some(root.join("unused-ratification")),
        audit_output_path: Some(root.join("audit.json")),
        environment: NetworkEnvironment::Devnet,
        operator_note: None,
        validation_time_secs: 0,
        updated_at_unix_secs: 0,
    }
}

#[test]
fn cooperating_lock_holder() {
    let Some(root) = std::env::var_os("QBIND_A33_LOCK_HOLDER") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let _lock = acquire_destination_lock(&root.join("data")).unwrap();
    fs::write(root.join("ready"), b"owned").unwrap();
    let mut byte = [0];
    std::io::stdin().read(&mut byte).unwrap();
}

#[test]
fn contender_refuses_then_release_allows_normal_verification() {
    let root = tempfile::tempdir().unwrap();
    let inputs = inputs(root.path());
    fs::create_dir(inputs.data_dir.as_ref().unwrap()).unwrap();
    let marker = authority_state_file_path(inputs.data_dir.as_ref().unwrap());
    fs::write(&marker, b"synthetic prior marker").unwrap();
    let audit = inputs.audit_output_path.as_ref().unwrap();
    fs::write(audit, b"synthetic prior audit").unwrap();
    let mut holder = cli::OwnedChild(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "cooperating_lock_holder", "--nocapture"])
            .env("QBIND_A33_LOCK_HOLDER", root.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !root.path().join("ready").exists() {
        assert!(Instant::now() < deadline, "holder readiness timeout");
        assert!(holder.0.try_wait().unwrap().is_none(), "holder exited");
        std::thread::sleep(Duration::from_millis(10));
    }
    let (code, diagnostic) = cli::run(&inputs, root.path());
    println!(
        "contended CLI exit={code}; marker_changed={}; audit_changed={}",
        fs::read(&marker).unwrap() != b"synthetic prior marker",
        fs::read(audit).unwrap() != b"synthetic prior audit"
    );
    println!("CLI diagnostic: {diagnostic}");
    assert_eq!(code, 1);
    assert!(diagnostic.contains("destination ownership"));
    assert_eq!(fs::read(audit).unwrap(), b"synthetic prior audit");
    assert_eq!(fs::read(&marker).unwrap(), b"synthetic prior marker");
    drop(holder.0.stdin.take());
    assert!(cli::wait(&mut holder.0, Duration::from_secs(10)).success());
    let (code, diagnostic) = cli::run(&inputs, root.path());
    assert_eq!(code, 1);
    assert!(diagnostic.contains("GenesisLoadFailed"));
    assert_eq!(fs::read(&marker).unwrap(), b"synthetic prior marker");
    let record: AuthorityResetAuditRecord =
        serde_json::from_slice(&fs::read(audit).unwrap()).unwrap();
    assert_eq!(record.result, "refused");
    println!("released CLI: verification refusal and separate refusal audit; marker unchanged");
}

#[test]
fn absent_explicit_destination_creates_only_ownership_artifacts_before_verification() {
    let root = tempfile::tempdir().unwrap();
    let inputs = inputs(root.path());
    let data = inputs.data_dir.as_ref().unwrap();
    assert!(!data.exists());
    let (code, diagnostic) = cli::run(&inputs, root.path());
    assert_eq!(code, 1);
    assert!(diagnostic.contains("GenesisLoadFailed"));
    assert!(data.join("restore.lock").is_file());
    assert_eq!(fs::read(data.join("restore.lock")).unwrap(), b"");
    assert!(!authority_state_file_path(data).exists());
    let audit: AuthorityResetAuditRecord =
        serde_json::from_slice(&fs::read(inputs.audit_output_path.unwrap()).unwrap()).unwrap();
    assert_eq!(audit.result, "refused");
    let _released = acquire_destination_lock(data).unwrap();
    println!("explicit absent destination: directory/empty stable lock created; verification refusal audit separate");
}

#[test]
fn missing_destination_and_unavailable_lock_refuse_without_reset_writes() {
    for case in ["missing", "lock-directory", "data-file"] {
        let root = tempfile::tempdir().unwrap();
        let mut inputs = inputs(root.path());
        match case {
            "missing" => inputs.data_dir = None,
            "lock-directory" => {
                fs::create_dir(inputs.data_dir.as_ref().unwrap()).unwrap();
                fs::create_dir(inputs.data_dir.as_ref().unwrap().join("restore.lock")).unwrap();
            }

            "data-file" => {
                fs::write(inputs.data_dir.as_ref().unwrap(), b"not a directory").unwrap()
            }
            _ => unreachable!(),
        }
        let (code, diagnostic) = cli::run(&inputs, root.path());
        assert_eq!(code, 1);
        assert!(diagnostic.contains("destination ownership"));
        assert!(!inputs.audit_output_path.unwrap().exists());
        assert!(!root.path().join("data/pqc_authority_state.json").exists());
        println!("{case}: ownership refusal; no reset marker/audit write");
    }
}

#[test]
fn reset_write_aliases_cannot_replace_destination_lock() {
    use std::os::unix::fs::{symlink, MetadataExt};
    for case in [
        "equal",
        "dot",
        "parent-symlink",
        "audit-hardlink",
        "audit-temp-hardlink",
        "marker-hardlink",
        "marker-temp-hardlink",
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut inputs = inputs(root.path());
        let data = inputs.data_dir.as_ref().unwrap();
        fs::create_dir(data).unwrap();
        let lock_path = data.join("restore.lock");
        fs::write(&lock_path, b"stable lock bytes").unwrap();
        let marker = authority_state_file_path(data);
        fs::write(&marker, b"synthetic prior marker").unwrap();
        match case {
            "equal" => inputs.audit_output_path = Some(lock_path.clone()),
            "dot" => inputs.audit_output_path = Some(data.join("./restore.lock")),
            "parent-symlink" => {
                symlink(data, root.path().join("alias")).unwrap();
                inputs.audit_output_path = Some(root.path().join("alias/restore.lock"));
            }
            "audit-hardlink" => {
                fs::hard_link(&lock_path, inputs.audit_output_path.as_ref().unwrap()).unwrap()
            }
            "audit-temp-hardlink" => fs::hard_link(
                &lock_path,
                inputs
                    .audit_output_path
                    .as_ref()
                    .unwrap()
                    .with_extension("json.tmp"),
            )
            .unwrap(),
            "marker-hardlink" => {
                fs::remove_file(&marker).unwrap();
                fs::hard_link(&lock_path, &marker).unwrap();
            }
            "marker-temp-hardlink" => {
                fs::hard_link(&lock_path, data.join("pqc_authority_state.json.tmp")).unwrap()
            }
            _ => unreachable!(),
        }
        let before = fs::read(&marker).unwrap();
        let inode = fs::metadata(&lock_path).unwrap().ino();
        let (code, diagnostic) = cli::run(&inputs, root.path());
        assert_eq!(code, 1, "{case}: {diagnostic}");
        assert!(
            diagnostic.contains("UnsafeAuditPath"),
            "{case}: {diagnostic}"
        );
        assert_eq!(fs::read(&marker).unwrap(), before);
        assert_eq!(fs::read(&lock_path).unwrap(), b"stable lock bytes");
        assert_eq!(fs::metadata(&lock_path).unwrap().ino(), inode);
        let _released = acquire_destination_lock(data).expect("CLI releases ownership at exit");
        println!("{case}: UnsafeAuditPath before verifier; lock inode/bytes and marker unchanged");
    }
}
