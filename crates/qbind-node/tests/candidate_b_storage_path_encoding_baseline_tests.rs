use qbind_ledger::{AccountState, PersistentAccountState, RocksDbAccountState};
use qbind_node::storage::{ConsensusStorage, RocksDbConsensusStorage};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

const ACCOUNT_ID: [u8; 32] = [0x73; 32];

#[cfg(unix)]
fn raw_and_lossy_paths(root: &Path, leaf: &str) -> (PathBuf, PathBuf) {
    use std::os::unix::ffi::OsStringExt;

    let raw_component = std::ffi::OsString::from_vec(b"ancestor-\xff".to_vec());
    let lossy_component = raw_component.to_string_lossy().into_owned();
    (
        root.join(raw_component).join(leaf),
        root.join(lossy_component).join(leaf),
    )
}

#[cfg(unix)]
fn print_tree(label: &str, path: &Path) {
    println!("{label} {:?} exists={}", path, path.exists());
    if path.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(path)
            .expect("read test fixture directory")
            .map(|entry| entry.expect("read test fixture entry").file_name())
            .collect();
        entries.sort();
        for entry in entries {
            println!("  {entry:?}");
        }
    }
}

#[cfg(unix)]
#[test]
fn account_create_nonrepresentable_path_contract_baseline() {
    use std::os::unix::ffi::OsStrExt;

    let fixture = tempdir().expect("create isolated account-create fixture");
    let root = fixture.path();
    let (raw_db, lossy_db) = raw_and_lossy_paths(root, "state_vm_v0");
    println!(
        "account-create raw path bytes: {}",
        raw_db
            .as_os_str()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("")
    );
    println!("account-create raw database: {raw_db:?}");
    println!("account-create lossy database: {lossy_db:?}");
    println!(
        "account-create paths distinct: {}",
        raw_db.as_os_str().as_bytes() != lossy_db.as_os_str().as_bytes()
    );
    print_tree("raw ancestor before", raw_db.parent().unwrap());
    print_tree("lossy ancestor before", lossy_db.parent().unwrap());

    let opened = RocksDbAccountState::open(&raw_db);
    let open_succeeded = opened.is_ok();
    println!(
        "RocksDbAccountState::open(raw) result: {}",
        result_kind(&opened)
    );
    let expected_marker = AccountState::new(0x7171, 0x9292);
    if let Ok(db) = opened {
        db.put_account_state(&ACCOUNT_ID, &expected_marker)
            .expect("write baseline marker through raw-path API result");
        db.flush().expect("flush baseline account marker");
        drop(db);
    }

    print_tree("raw ancestor after", raw_db.parent().unwrap());
    print_tree("lossy ancestor after", lossy_db.parent().unwrap());
    print_tree("raw database after", &raw_db);
    print_tree("lossy database after", &lossy_db);
    let mut lossy_marker_matches = false;
    if lossy_db.exists() {
        let db = RocksDbAccountState::open_existing(&lossy_db)
            .expect("open lossy-path control after raw-path account open");
        let marker = db.get_account_state(&ACCOUNT_ID);
        println!(
            "lossy-path marker after account create call: nonce={} balance={}",
            marker.nonce, marker.balance
        );
        lossy_marker_matches =
            (marker.nonce, marker.balance) == (expected_marker.nonce, expected_marker.balance);
        drop(db);
    }
    println!("lossy-path database contains raw-call marker: {lossy_marker_matches}");

    assert!(
        raw_db.as_os_str().to_str().is_none(),
        "fixture must contain an invalid UTF-8 ancestor"
    );
    assert!(
        !open_succeeded || lossy_marker_matches,
        "raw-path account create did not expose the expected lossy-path marker"
    );
    assert!(
        !open_succeeded
            && !raw_db.parent().unwrap().exists()
            && !lossy_db.parent().unwrap().exists()
            && !raw_db.exists()
            && !lossy_db.exists(),
        "BASELINE CONTRACT FAILURE: account create did not refuse before observed effects"
    );
}

#[cfg(unix)]
#[test]
fn account_existing_only_nonrepresentable_path_contract_baseline() {
    use std::os::unix::ffi::OsStrExt;

    let fixture = tempdir().expect("create isolated account-existing fixture");
    let root = fixture.path();
    let (raw_db, lossy_db) = raw_and_lossy_paths(root, "state_vm_v0");
    let expected = AccountState::new(0x7373, 0xa4a4);
    let setup = RocksDbAccountState::open(&lossy_db).expect("create lossy-path marker database");
    setup
        .put_account_state(&ACCOUNT_ID, &expected)
        .expect("write lossy-path marker");
    setup.flush().expect("flush lossy-path marker");
    drop(setup);

    let before_lossy = list_entries(&lossy_db);
    println!(
        "account-existing raw path bytes: {}",
        raw_db
            .as_os_str()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("")
    );
    println!("account-existing raw database: {raw_db:?}");
    println!("account-existing lossy database: {lossy_db:?}");
    print_tree("raw ancestor before", raw_db.parent().unwrap());
    print_tree("lossy database before", &lossy_db);

    let opened = RocksDbAccountState::open_existing(&raw_db);
    println!(
        "RocksDbAccountState::open_existing(raw) result: {}",
        result_kind(&opened)
    );
    let (observed, expected_lossy_marker_returned) = match opened {
        Ok(db) => {
            let marker = db.get_account_state(&ACCOUNT_ID);
            println!(
                "marker returned by raw-path existing-only API: nonce={} balance={}",
                marker.nonce, marker.balance
            );
            let matched_lossy_marker =
                (marker.nonce, marker.balance) == (expected.nonce, expected.balance);
            drop(db);
            (Some(marker), matched_lossy_marker)
        }
        Err(_) => (None, false),
    };

    print_tree("raw ancestor after", raw_db.parent().unwrap());
    print_tree("raw database after", &raw_db);
    print_tree("lossy database after", &lossy_db);
    let after_lossy = list_entries(&lossy_db);
    println!(
        "lossy database entries unchanged: {}",
        before_lossy == after_lossy
    );
    println!("raw-path call returned distinct lossy marker: {expected_lossy_marker_returned}");
    println!("raw database exists after: {}", raw_db.exists());
    println!("lossy database exists after: {}", lossy_db.exists());

    assert!(
        raw_db.as_os_str().to_str().is_none(),
        "fixture must contain an invalid UTF-8 ancestor"
    );
    assert!(
        observed.is_none() || expected_lossy_marker_returned,
        "raw-path existing-only API returned unexpected data instead of the lossy control marker"
    );
    assert!(
        observed.is_none()
            && !raw_db.parent().unwrap().exists()
            && !raw_db.exists()
            && before_lossy == after_lossy,
        "BASELINE CONTRACT FAILURE: account existing-only open did not refuse before observed effects"
    );
}

#[cfg(unix)]
#[test]
fn consensus_nonrepresentable_path_contract_baseline() {
    use std::os::unix::ffi::OsStrExt;

    let fixture = tempdir().expect("create isolated consensus fixture");
    let root = fixture.path();
    let (raw_db, lossy_db) = raw_and_lossy_paths(root, "consensus");
    let expected_epoch = 0x1234_5678;
    let setup = RocksDbConsensusStorage::open(&lossy_db)
        .expect("create lossy-path consensus marker database");
    setup
        .put_current_epoch_synced(expected_epoch)
        .expect("write consensus epoch marker");
    drop(setup);

    let before_lossy = list_entries(&lossy_db);
    println!(
        "consensus raw path bytes: {}",
        raw_db
            .as_os_str()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("")
    );
    println!("consensus raw database: {raw_db:?}");
    println!("consensus lossy database: {lossy_db:?}");
    print_tree("raw ancestor before", raw_db.parent().unwrap());
    print_tree("lossy database before", &lossy_db);

    let opened = RocksDbConsensusStorage::open(&raw_db);
    println!(
        "RocksDbConsensusStorage::open(raw) result: {}",
        result_kind(&opened)
    );
    let observed_epoch = match opened {
        Ok(db) => {
            let epoch = db.get_current_epoch().expect("read opened consensus epoch");
            println!("epoch returned by raw-path consensus API: {epoch:?}");
            drop(db);
            epoch
        }
        Err(_) => None,
    };

    print_tree("raw ancestor after", raw_db.parent().unwrap());
    print_tree("raw database after", &raw_db);
    print_tree("lossy database after", &lossy_db);
    let after_lossy = list_entries(&lossy_db);
    println!(
        "lossy database entries unchanged: {}",
        before_lossy == after_lossy
    );
    println!("raw database exists after: {}", raw_db.exists());
    println!("lossy database exists after: {}", lossy_db.exists());

    assert!(
        raw_db.as_os_str().as_bytes().contains(&0xff),
        "fixture must contain invalid UTF-8 in an ancestor"
    );
    assert!(
        observed_epoch.is_none() || observed_epoch == Some(expected_epoch),
        "raw-path consensus API returned unexpected state instead of the lossy control epoch"
    );
    assert!(
        observed_epoch.is_none()
            && !raw_db.parent().unwrap().exists()
            && !raw_db.exists()
            && before_lossy == after_lossy,
        "BASELINE CONTRACT FAILURE: consensus open did not refuse before observed effects"
    );
}

#[cfg(unix)]
#[test]
fn representable_paths_and_ordinary_storage_errors_control() {
    let fixture = tempdir().expect("create positive-control fixture");
    let root = fixture.path();

    let account_path = root.join("utf8-account");
    let account = RocksDbAccountState::open(&account_path)
        .expect("representable account-create positive control");
    let marker = AccountState::new(0x1515, 0x2626);
    account
        .put_account_state(&ACCOUNT_ID, &marker)
        .expect("write account positive-control marker");
    account
        .flush()
        .expect("flush account positive-control marker");
    drop(account);
    let account = RocksDbAccountState::open_existing(&account_path)
        .expect("representable account existing-only positive control");
    let observed = account.get_account_state(&ACCOUNT_ID);
    assert_eq!(
        (observed.nonce, observed.balance),
        (marker.nonce, marker.balance)
    );
    drop(account);

    let consensus_path = root.join("utf8-consensus");
    let consensus = RocksDbConsensusStorage::open(&consensus_path)
        .expect("representable consensus positive control");
    consensus
        .put_current_epoch_synced(0x4567)
        .expect("write consensus positive-control epoch");
    drop(consensus);
    let consensus = RocksDbConsensusStorage::open(&consensus_path)
        .expect("reopen representable consensus positive control");
    assert_eq!(consensus.get_current_epoch().unwrap(), Some(0x4567));
    drop(consensus);

    let empty_existing = root.join("empty-account-existing");
    fs::create_dir(&empty_existing).expect("create empty existing-only error control");
    let existing_error = RocksDbAccountState::open_existing(&empty_existing);
    println!(
        "ordinary account existing-only empty-directory control: {}",
        result_kind(&existing_error)
    );
    assert!(existing_error.is_err());

    let blocker = root.join("regular-file");
    fs::write(&blocker, b"not a directory").expect("create path blocker");
    let account_create_error = RocksDbAccountState::open(blocker.join("account"));
    let consensus_error = RocksDbConsensusStorage::open(blocker.join("consensus"));
    println!(
        "ordinary account-create parent-file control: {}",
        result_kind(&account_create_error)
    );
    println!(
        "ordinary consensus parent-file control: {}",
        result_kind(&consensus_error)
    );
    assert!(account_create_error.is_err());
    assert!(consensus_error.is_err());
    println!("representable UTF-8 account/consensus positive controls: passed");
}

fn result_kind<T, E>(result: &Result<T, E>) -> &'static str {
    if result.is_ok() {
        "Ok"
    } else {
        "Err"
    }
}

fn list_entries(path: &Path) -> Vec<std::ffi::OsString> {
    if !path.is_dir() {
        return Vec::new();
    }
    let mut entries: Vec<_> = fs::read_dir(path)
        .expect("read database entries")
        .map(|entry| entry.expect("read database entry").file_name())
        .collect();
    entries.sort();
    entries
}
