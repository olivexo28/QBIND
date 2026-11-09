use qbind_ledger::{AccountState, PersistentAccountState, RocksDbAccountState};
use qbind_types::AccountId;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn account_id(byte: u8) -> AccountId {
    [byte; 32]
}

fn tree_snapshot(root: &Path) -> Vec<String> {
    fn visit(root: &Path, path: &Path, out: &mut Vec<String>) {
        let mut entries: Vec<_> = fs::read_dir(path)
            .expect("read fixture directory")
            .map(|entry| entry.expect("read fixture entry").path())
            .collect();
        entries.sort();
        for entry in entries {
            let relative = entry.strip_prefix(root).expect("fixture path under root");
            let kind = if entry.is_dir() { "dir" } else { "file" };
            out.push(format!("{kind} {relative:?}"));
            if entry.is_dir() {
                visit(root, &entry, out);
            }
        }
    }

    let mut out = Vec::new();
    visit(root, root, &mut out);
    out
}

fn print_snapshot(label: &str, root: &Path) {
    println!("{label}:");
    for entry in tree_snapshot(root) {
        println!("  {entry}");
    }
}

#[test]
fn existing_only_missing_path_effects_and_database_control() {
    let fixture = tempdir().expect("create unique fixture root");
    let root = fixture.path();
    let missing = root.join("missing").join("state_vm_v0");

    println!("fixture root: {:?}", root);
    println!("missing target: {:?}", missing.strip_prefix(root).unwrap());
    println!("missing target exists before call: {}", missing.exists());
    print_snapshot("tree before missing-path call", root);

    let result = RocksDbAccountState::open_existing(&missing);
    match result {
        Ok(opened) => {
            println!("missing-path API result: Ok");
            drop(opened);
        }
        Err(error) => println!("missing-path API result: Err({error})"),
    }
    println!("missing target exists after call: {}", missing.exists());
    print_snapshot("tree after missing-path call", root);

    let valid = root.join("valid_db");
    let marker_account = account_id(0x71);
    let marker_state = AccountState::new(0x1234, 0x5678);
    {
        let created = RocksDbAccountState::open(&valid).expect("create valid fixture database");
        created
            .put_account_state(&marker_account, &marker_state)
            .expect("write valid fixture marker");
        created.flush().expect("flush valid fixture marker");
    }
    println!("valid control setup handle released before existing-only open: true");
    let control = RocksDbAccountState::open_existing(&valid)
        .expect("existing-only open valid fixture database");
    let observed = control.get_account_state(&marker_account);
    println!(
        "valid-database API result: Ok; marker nonce={} balance={}",
        observed.nonce, observed.balance
    );
    assert_eq!(observed.nonce, marker_state.nonce);
    assert_eq!(observed.balance, marker_state.balance);
    drop(control);
    print_snapshot("tree after valid-database control", root);
}

#[cfg(unix)]
#[test]
fn existing_only_non_utf8_path_and_lossy_database_control() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let fixture = tempdir().expect("create unique fixture root");
    let root = fixture.path();
    let raw_name = std::ffi::OsString::from_vec(b"db-\xff".to_vec());
    let raw_path = root.join(&raw_name);
    let lossy_name = raw_name.to_string_lossy().into_owned();
    let lossy_path = root.join(&lossy_name);

    assert_ne!(
        raw_path.as_os_str().as_bytes(),
        lossy_path.as_os_str().as_bytes()
    );
    assert!(
        !raw_path.exists(),
        "raw non-UTF-8 path must be absent before call"
    );
    assert!(
        !lossy_path.exists(),
        "lossy path must be absent before setup"
    );

    println!("fixture root: {:?}", root);
    println!("raw name debug: {:?}", raw_name);
    println!(
        "raw name bytes: {}",
        raw_name
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("")
    );
    println!("lossy name debug: {:?}", lossy_name);
    println!(
        "lossy name bytes: {}",
        lossy_name
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("")
    );

    let marker_account = account_id(0x72);
    let marker_state = AccountState::new(0x2345, 0x6789);
    {
        let created =
            RocksDbAccountState::open(&lossy_path).expect("create lossy-path fixture database");
        created
            .put_account_state(&marker_account, &marker_state)
            .expect("write lossy-path fixture marker");
        created.flush().expect("flush lossy-path fixture marker");
    }
    println!("lossy-path setup handle released before observed open: true");
    println!(
        "path states before observed open: raw_exists={} lossy_exists={}",
        raw_path.exists(),
        lossy_path.exists()
    );
    print_snapshot("tree before non-UTF-8 API call", root);

    let result = RocksDbAccountState::open_existing(&raw_path);
    match result {
        Ok(opened) => {
            let observed = opened.get_account_state(&marker_account);
            println!(
                "non-UTF-8 API result: Ok; marker nonce={} balance={}",
                observed.nonce, observed.balance
            );
            drop(opened);
        }
        Err(error) => println!("non-UTF-8 API result: Err({error})"),
    }
    println!(
        "path states after observed open: raw_exists={} lossy_exists={}",
        raw_path.exists(),
        lossy_path.exists()
    );
    print_snapshot("tree after non-UTF-8 API call", root);
}

#[cfg(not(unix))]
#[test]
fn existing_only_non_utf8_path_and_lossy_database_control() {
    println!(
        "non-UTF-8 path control: INCONCLUSIVE (platform path-byte construction is unavailable)"
    );
}
