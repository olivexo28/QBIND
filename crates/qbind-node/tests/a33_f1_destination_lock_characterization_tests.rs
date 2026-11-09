#![cfg(unix)]

use std::fs::{self, OpenOptions};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

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
