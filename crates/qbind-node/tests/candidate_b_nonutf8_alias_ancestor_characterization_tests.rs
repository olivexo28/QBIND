use qbind_ledger::{AccountState, PersistentAccountState, RocksDbAccountState};
use qbind_node::restore_completion::DestinationId;
use qbind_types::AccountId;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn account_id(byte: u8) -> AccountId {
    [byte; 32]
}

fn print_entries(label: &str, path: &Path) {
    println!("{label} {:?}:", path);
    if !path.exists() {
        println!("  <absent>");
        return;
    }

    let mut entries: Vec<_> = fs::read_dir(path)
        .expect("read fixture path")
        .map(|entry| entry.expect("read fixture entry").file_name())
        .collect();
    entries.sort();
    for entry in entries {
        println!("  {entry:?}");
    }
}

#[cfg(unix)]
#[test]
fn nonutf8_symlink_spelling_canonicalizes_to_utf8_destination() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::symlink;

    let fixture = tempdir().expect("create unique symlink fixture root");
    let root = fixture.path();
    let target = root.join("utf8-destination");
    fs::create_dir(&target).expect("create UTF-8 destination");
    let alias_name = std::ffi::OsString::from_vec(b"alias-\xff".to_vec());
    let alias = root.join(&alias_name);

    match symlink(&target, &alias) {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied
                    | std::io::ErrorKind::Unsupported
                    | std::io::ErrorKind::Other
            ) =>
        {
            println!("INCONCLUSIVE: platform/filesystem did not permit fixture symlink: {error}");
            return;
        }
        Err(error) => panic!("create intended test symlink: {error}"),
    }

    let link_target = fs::read_link(&alias).expect("read intended symlink target");
    let resolved_target = fs::canonicalize(&alias).expect("resolve intended symlink target");
    let canonical_expected = fs::canonicalize(&target).expect("canonicalize UTF-8 target");
    assert_eq!(resolved_target, canonical_expected);
    assert!(resolved_target.starts_with(root));
    assert!(canonical_expected.to_str().is_some());

    println!("fixture root: {root:?}");
    println!(
        "original alias component bytes: {}",
        alias_name
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("")
    );
    println!("original alias component: {alias_name:?}");
    println!("stored symlink target: {link_target:?}");
    println!("verified resolved target before API call: {resolved_target:?}");
    println!("canonical UTF-8 target: {canonical_expected:?}");

    let result = DestinationId::canonicalize(&alias);
    match result {
        Ok(destination) => {
            println!(
                "DestinationId::canonicalize result: Ok({:?})",
                destination.as_str()
            );
            assert_eq!(destination.as_str(), canonical_expected.to_str().unwrap());
        }
        Err(error) => panic!("DestinationId::canonicalize unexpected refusal: {error}"),
    }
}

#[cfg(not(unix))]
#[test]
fn nonutf8_symlink_spelling_canonicalizes_to_utf8_destination() {
    println!("INCONCLUSIVE: this platform test does not construct arbitrary invalid path bytes");
}

#[cfg(unix)]
#[test]
fn account_database_under_nonutf8_ancestor_uses_lossy_database_path() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let fixture = tempdir().expect("create unique account-path fixture root");
    let root = fixture.path();
    let raw_ancestor = std::ffi::OsString::from_vec(b"ancestor-\xff".to_vec());
    let lossy_ancestor = raw_ancestor.to_string_lossy().into_owned();
    let raw_data_dir = root.join(&raw_ancestor);
    let lossy_data_dir = root.join(&lossy_ancestor);
    let raw_database = raw_data_dir.join("state_vm_v0");
    let lossy_database = lossy_data_dir.join("state_vm_v0");

    assert_ne!(
        raw_data_dir.as_os_str().as_bytes(),
        lossy_data_dir.as_os_str().as_bytes()
    );
    assert_ne!(raw_database, lossy_database);
    assert!(!raw_data_dir.exists());
    assert!(!lossy_database.exists());

    let account = account_id(0x73);
    let marker_state = AccountState::new(0x3456, 0x789a);
    {
        let created =
            RocksDbAccountState::open(&lossy_database).expect("create lossy ancestor database");
        created
            .put_account_state(&account, &marker_state)
            .expect("write synthetic ancestor marker");
        created.flush().expect("flush synthetic ancestor marker");
    }

    println!("fixture root: {root:?}");
    println!(
        "raw ancestor bytes: {}",
        raw_ancestor
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("")
    );
    println!(
        "lossy ancestor bytes: {}",
        lossy_ancestor
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("")
    );
    println!("raw database path: {raw_database:?}");
    println!("lossy database path: {lossy_database:?}");
    println!("fixture database handle released before observed open: true");
    println!(
        "path states before observed open: raw_database_exists={} lossy_database_exists={}",
        raw_database.exists(),
        lossy_database.exists()
    );
    print_entries(
        "lossy database entries before observed open",
        &lossy_database,
    );

    let opened = RocksDbAccountState::open_existing(&raw_database)
        .expect("open existing database through raw ancestor spelling");
    let observed = opened.get_account_state(&account);
    println!(
        "open_existing(raw ancestor + UTF-8 leaf) marker: nonce={} balance={}",
        observed.nonce, observed.balance
    );
    assert_eq!(observed.nonce, marker_state.nonce);
    assert_eq!(observed.balance, marker_state.balance);
    drop(opened);

    println!(
        "path states after observed open: raw_database_exists={} lossy_database_exists={}",
        raw_database.exists(),
        lossy_database.exists()
    );
    print_entries("raw data-dir entries after observed open", &raw_data_dir);
    print_entries("raw database entries after observed open", &raw_database);
    print_entries(
        "lossy database entries after observed open",
        &lossy_database,
    );
}

#[cfg(not(unix))]
#[test]
fn account_database_under_nonutf8_ancestor_uses_lossy_database_path() {
    println!("INCONCLUSIVE: this platform test does not construct arbitrary invalid path bytes");
}
