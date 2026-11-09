#![cfg(unix)]

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use qbind_node::restore_completion::{
    acquire_destination_lock, LockAcquireError, RESTORE_LOCK_FILENAME,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ObjectId {
    device: u64,
    inode: u64,
}

fn object_id(path: &Path) -> ObjectId {
    let metadata = fs::symlink_metadata(path).expect("fixture object metadata");
    assert!(
        metadata.file_type().is_file(),
        "fixture object must be a regular file"
    );
    ObjectId {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn fixture_data_dir(root: &Path) -> PathBuf {
    let canonical_root = fs::canonicalize(root).expect("canonical temporary root");
    let data_dir = root.join("data");
    fs::create_dir(&data_dir).expect("create fixture destination");
    let canonical_data_dir = fs::canonicalize(&data_dir).expect("canonical fixture destination");
    assert!(
        canonical_data_dir.starts_with(&canonical_root),
        "fixture destination must remain under its unique temporary root"
    );
    canonical_data_dir
}

struct LockWorker {
    child: Child,
    stdin: ChildStdin,
    result_path: PathBuf,
}

impl LockWorker {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn result(&self) -> String {
        wait_for_file(&self.result_path);
        fs::read_to_string(&self.result_path).expect("read worker result")
    }

    fn is_running(&mut self) -> bool {
        self.child
            .try_wait()
            .expect("check worker process")
            .is_none()
    }

    fn release_and_wait(&mut self) {
        self.stdin.write_all(b"x").expect("release worker");
        self.stdin.flush().expect("flush worker release");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().expect("wait for worker") {
                assert!(status.success(), "worker exited unsuccessfully: {status}");
                return;
            }
            assert!(Instant::now() < deadline, "worker release timed out");
            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for LockWorker {
    fn drop(&mut self) {
        if self
            .child
            .try_wait()
            .expect("check worker during cleanup")
            .is_none()
        {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn spawn_lock_worker(data_dir: &Path, result_path: &Path) -> LockWorker {
    let mut child = Command::new(std::env::current_exe().expect("test executable path"))
        .args(["--exact", "process_lock_worker", "--nocapture"])
        .env("QBIND_LOCK_WORKER_DATA_DIR", data_dir)
        .env("QBIND_LOCK_WORKER_RESULT", result_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn independent lock worker");
    let stdin = child.stdin.take().expect("worker stdin");
    LockWorker {
        child,
        stdin,
        result_path: result_path.to_path_buf(),
    }
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(5));
    }
}

fn worker_outcome(result: &str) -> &str {
    result
        .lines()
        .find_map(|line| line.strip_prefix("outcome="))
        .expect("worker outcome field")
}

#[test]
fn process_lock_worker() {
    let (Some(data_dir), Some(result_path)) = (
        std::env::var_os("QBIND_LOCK_WORKER_DATA_DIR"),
        std::env::var_os("QBIND_LOCK_WORKER_RESULT"),
    ) else {
        return;
    };
    let data_dir = PathBuf::from(data_dir);
    let result_path = PathBuf::from(result_path);
    let (outcome, _held_lock) = match acquire_destination_lock(&data_dir) {
        Ok(lock) => ("acquired".to_string(), Some(lock)),
        Err(LockAcquireError::Contended(_)) => ("contended".to_string(), None),
        Err(error) => (format!("error:{error}"), None),
    };
    fs::write(
        &result_path,
        format!("pid={}\noutcome={outcome}\n", std::process::id()),
    )
    .expect("publish worker result");

    let mut release = [0];
    std::io::stdin()
        .read_exact(&mut release)
        .expect("wait for parent release");
}

#[test]
fn same_lock_object_records_second_acquisition_outcome() {
    let root = tempfile::tempdir().expect("unique temporary root");
    let root_path = root.path().to_path_buf();
    let data_dir = fixture_data_dir(root.path());
    let lock_path = data_dir.join(RESTORE_LOCK_FILENAME);

    let first = acquire_destination_lock(&data_dir).expect("first lock acquisition");
    let first_object = object_id(&lock_path);
    let second_result = acquire_destination_lock(&data_dir);
    let path_after_second = object_id(&lock_path);

    assert_eq!(
        first_object, path_after_second,
        "the second call must observe the same underlying lock object"
    );

    match second_result {
        Ok(second) => {
            println!(
                "same-object observation: second call succeeded; first and second are \
                 separate opens in one process; first_handle_held=true; object={first_object:?}"
            );
            drop(second);
        }
        Err(LockAcquireError::Contended(_)) => println!(
            "same-object observation: second call contended; callers are separate opens in \
             one process; first_handle_held=true; object={first_object:?}"
        ),
        Err(error) => println!(
            "same-object observation: second call returned another error ({error:?}); \
             callers are separate opens in one process; first_handle_held=true; \
             object={first_object:?}"
        ),
    }
    drop(first);
    drop(root);
    assert!(!root_path.exists(), "temporary fixture must be cleaned up");
    println!("fixture cleanup: removed {}", root_path.display());
}

#[test]
fn separate_processes_contend_on_same_lock_object() {
    let root = tempfile::tempdir().expect("unique temporary root");
    let root_path = root.path().to_path_buf();
    let data_dir = fixture_data_dir(root.path());
    let lock_path = data_dir.join(RESTORE_LOCK_FILENAME);
    let first_result_path = root.path().join("first-result");
    let second_result_path = root.path().join("second-result");

    let mut first = spawn_lock_worker(&data_dir, &first_result_path);
    let first_result = first.result();
    assert_eq!(worker_outcome(&first_result), "acquired");
    let first_pid: u32 = first_result
        .lines()
        .find_map(|line| line.strip_prefix("pid="))
        .expect("first worker pid")
        .parse()
        .expect("parse first worker pid");
    assert_eq!(first.pid(), first_pid);
    assert_ne!(first_pid, std::process::id());
    assert!(first.is_running(), "first worker must hold its lock");
    let first_object = object_id(&lock_path);

    let mut second = spawn_lock_worker(&data_dir, &second_result_path);
    assert_ne!(
        first.pid(),
        second.pid(),
        "workers must be separate processes"
    );
    let second_result = second.result();
    let second_pid: u32 = second_result
        .lines()
        .find_map(|line| line.strip_prefix("pid="))
        .expect("second worker pid")
        .parse()
        .expect("parse second worker pid");
    assert_eq!(second.pid(), second_pid);
    assert_ne!(second_pid, first_pid);
    assert_ne!(second_pid, std::process::id());
    assert!(
        first.is_running(),
        "first worker must overlap second attempt"
    );
    assert!(second.is_running(), "second worker must remain observable");
    assert_eq!(object_id(&lock_path), first_object);

    let outcome = worker_outcome(&second_result);
    println!(
        "separate-process same-object observation: second outcome={outcome}; \
         first_pid={first_pid}; second_pid={second_pid}; overlapping=true; \
         path_metadata_object={first_object:?}"
    );
    second.release_and_wait();
    first.release_and_wait();
    drop(root);
    assert!(!root_path.exists(), "temporary fixture must be cleaned up");
    println!("fixture cleanup: removed {}", root_path.display());
}

#[test]
fn separate_processes_can_hold_locks_after_controlled_path_replacement() {
    let root = tempfile::tempdir().expect("unique temporary root");
    let root_path = root.path().to_path_buf();
    let data_dir = fixture_data_dir(root.path());
    let lock_path = data_dir.join(RESTORE_LOCK_FILENAME);
    let retired_path = data_dir.join("retained-original-lock");
    let first_result_path = root.path().join("first-result");
    let second_result_path = root.path().join("second-result");

    let mut first = spawn_lock_worker(&data_dir, &first_result_path);
    let first_result = first.result();
    assert_eq!(worker_outcome(&first_result), "acquired");
    let first_pid: u32 = first_result
        .lines()
        .find_map(|line| line.strip_prefix("pid="))
        .expect("first worker pid")
        .parse()
        .expect("parse first worker pid");
    assert_eq!(first.pid(), first_pid);
    assert_ne!(first_pid, std::process::id());
    assert!(first.is_running(), "first worker must hold its lock");
    let original_object = object_id(&lock_path);

    fs::rename(&lock_path, &retired_path).expect("rename lock path within fixture");
    assert_eq!(object_id(&retired_path), original_object);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .expect("create distinct replacement lock object");
    let replacement_object = object_id(&lock_path);
    assert_ne!(original_object, replacement_object);

    let mut second = spawn_lock_worker(&data_dir, &second_result_path);
    assert_ne!(
        first.pid(),
        second.pid(),
        "workers must be separate processes"
    );
    let second_result = second.result();
    let second_pid: u32 = second_result
        .lines()
        .find_map(|line| line.strip_prefix("pid="))
        .expect("second worker pid")
        .parse()
        .expect("parse second worker pid");
    assert_eq!(second.pid(), second_pid);
    assert_ne!(second_pid, first_pid);
    assert_ne!(second_pid, std::process::id());
    assert!(first.is_running(), "original lock holder must remain live");
    assert!(second.is_running(), "second process must remain observable");
    assert_eq!(object_id(&retired_path), original_object);
    assert_eq!(object_id(&lock_path), replacement_object);

    let outcome = worker_outcome(&second_result);
    println!(
        "separate-process replaced-path observation: second outcome={outcome}; \
         first_pid={first_pid}; second_pid={second_pid}; overlapping=true; \
         original_path_metadata_object={original_object:?}; \
         replacement_path_metadata_object={replacement_object:?}; \
         both_processes_hold_lock={}",
        outcome == "acquired"
    );
    second.release_and_wait();
    first.release_and_wait();
    drop(root);
    assert!(!root_path.exists(), "temporary fixture must be cleaned up");
    println!("fixture cleanup: removed {}", root_path.display());
}

#[test]
fn replaced_lock_path_records_acquisition_outcome_for_distinct_object() {
    let root = tempfile::tempdir().expect("unique temporary root");
    let root_path = root.path().to_path_buf();
    let data_dir = fixture_data_dir(root.path());
    let lock_path = data_dir.join(RESTORE_LOCK_FILENAME);
    let retired_path = data_dir.join("retained-original-lock");

    let first = acquire_destination_lock(&data_dir).expect("first lock acquisition");
    let first_object = object_id(&lock_path);

    fs::rename(&lock_path, &retired_path).expect("move original lock path within fixture");
    let retained_object = object_id(&retired_path);
    assert_eq!(
        first_object, retained_object,
        "renaming the fixture entry must preserve the original object identity"
    );

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .expect("create distinct replacement lock object");
    let replacement_object = object_id(&lock_path);
    assert_ne!(
        first_object, replacement_object,
        "replacement lock path must name a distinct underlying object"
    );

    let second_result = acquire_destination_lock(&data_dir);
    assert_eq!(
        object_id(&retired_path),
        first_object,
        "the original locked object must remain present while the first handle is held"
    );
    assert_eq!(
        object_id(&lock_path),
        replacement_object,
        "the API path must still identify the replacement object after acquisition"
    );

    match second_result {
        Ok(second) => {
            println!(
                "replaced-path observation: second call succeeded; both lock handles were \
                 held simultaneously in one process; original={first_object:?}; \
                 replacement={replacement_object:?}"
            );
            drop(second);
        }
        Err(LockAcquireError::Contended(_)) => println!(
            "replaced-path observation: second call contended; first handle remained held; \
             separate opens in one process; original={first_object:?}; \
             replacement={replacement_object:?}"
        ),
        Err(error) => println!(
            "replaced-path observation: second call returned another error ({error:?}); \
             first handle remained held; separate opens in one process; \
             original={first_object:?}; replacement={replacement_object:?}"
        ),
    }
    drop(first);
    drop(root);
    assert!(!root_path.exists(), "temporary fixture must be cleaned up");
    println!("fixture cleanup: removed {}", root_path.display());
}
