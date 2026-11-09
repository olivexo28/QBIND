use qbind_ledger::{AccountState, PersistentAccountState, RocksDbAccountState};
use qbind_node::restore_completion::{
    evaluate_ordinary_startup, publish_record, DestinationId, OrdinaryStartupDecision,
    RestoreTransactionRecord,
};
use qbind_types::AccountId;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

const STATE_DIR: &str = "state_vm_v0";

fn account_id(byte: u8) -> AccountId {
    [byte; 32]
}

fn database_path(data_dir: &Path) -> PathBuf {
    data_dir.join(STATE_DIR)
}

fn write_database(data_dir: &Path, id: u8, state: &AccountState) {
    let path = database_path(data_dir);
    let db = RocksDbAccountState::open(&path).expect("create synthetic account database");
    db.put_account_state(&account_id(id), state)
        .expect("write synthetic account marker");
    db.flush().expect("flush synthetic account marker");
    drop(db);
}

fn complete_record(destination: &Path) -> RestoreTransactionRecord {
    let destination_id =
        DestinationId::canonicalize(destination).expect("canonicalize record destination");
    RestoreTransactionRecord::new_intent(&destination_id, [0x31; 32], [0x42; 16], Some(17))
        .into_complete()
}

fn publish_complete(destination: &Path, record: &RestoreTransactionRecord) {
    assert_eq!(
        record.state,
        qbind_node::restore_completion::RtrState::Complete
    );
    publish_record(destination, record).expect("publish synthetic COMPLETE record");
}

fn call_storage_only_if_permitted<T>(
    decision: &OrdinaryStartupDecision,
    open: impl FnOnce() -> T,
) -> Option<T> {
    if decision.permits_startup() {
        Some(open())
    } else {
        None
    }
}

fn print_entries(label: &str, path: &Path) {
    println!("{label} {:?}:", path);
    if !path.exists() {
        println!("  <absent>");
        return;
    }
    let mut entries: Vec<_> = fs::read_dir(path)
        .expect("read fixture directory")
        .map(|entry| entry.expect("read fixture entry").file_name())
        .collect();
    entries.sort();
    for entry in entries {
        println!("  {entry:?}");
    }
}

#[cfg(unix)]
#[test]
fn nonutf8_complete_alias_guard_then_account_storage_characterization() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::symlink;

    let fixture = tempdir().expect("create unique alias fixture root");
    let root = fixture.path();
    let intended = root.join("intended-destination");
    fs::create_dir(&intended).expect("create intended UTF-8 destination");
    let alias_component = std::ffi::OsString::from_vec(b"alias-\xff".to_vec());
    let alias = root.join(&alias_component);

    match symlink(&intended, &alias) {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Unsupported
            ) =>
        {
            println!("INCONCLUSIVE: fixture symlink unavailable: {error}");
            return;
        }
        Err(error) => panic!("create non-UTF-8 alias symlink: {error}"),
    }

    let canonical_intended =
        fs::canonicalize(&intended).expect("canonicalize intended destination");
    let canonical_alias = fs::canonicalize(&alias).expect("canonicalize alias");
    assert_eq!(canonical_alias, canonical_intended);
    assert!(canonical_alias.starts_with(root));
    assert!(canonical_intended.to_str().is_some());

    let lossy_component = alias_component.to_string_lossy().into_owned();
    let lossy_spelling = root.join(&lossy_component);
    let intended_db = database_path(&intended);
    let lossy_db = database_path(&lossy_spelling);
    assert_ne!(
        alias.as_os_str().as_bytes(),
        lossy_spelling.as_os_str().as_bytes()
    );
    assert_ne!(intended_db, lossy_db);

    let intended_marker = AccountState::new(0x1111, 0xaaaa);
    let lossy_marker = AccountState::new(0x2222, 0xbbbb);
    write_database(&intended, 0x51, &intended_marker);
    write_database(&lossy_spelling, 0x51, &lossy_marker);

    let record = complete_record(&intended);
    assert_eq!(record.destination_id, canonical_intended.to_str().unwrap());
    publish_complete(&intended, &record);

    let link_target = fs::read_link(&alias).expect("read alias target");
    let verified_target = fs::canonicalize(&alias).expect("verify alias target");
    assert_eq!(verified_target, canonical_intended);
    println!("fixture root: {root:?}");
    println!(
        "non-UTF-8 alias component bytes: {}",
        alias_component
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("")
    );
    println!("alias component: {alias_component:?}");
    println!("stored symlink target: {link_target:?}");
    println!("verified alias canonical target: {verified_target:?}");
    println!("COMPLETE destination_id: {:?}", record.destination_id);
    println!("raw alias data-dir: {alias:?}");
    println!("lossy spelling data-dir: {lossy_spelling:?}");
    println!("intended UTF-8 database: {intended_db:?}");
    println!("lossy-spelling database: {lossy_db:?}");
    println!(
        "database path bytes distinct: {}",
        intended_db.as_os_str().as_bytes() != lossy_db.as_os_str().as_bytes()
    );
    print_entries("intended database entries before guard", &intended_db);
    print_entries("lossy database entries before guard", &lossy_db);

    let decision = evaluate_ordinary_startup(&alias);
    println!("actual evaluate_ordinary_startup(raw alias) decision: {decision:?}");
    assert!(matches!(
        &decision,
        OrdinaryStartupDecision::ProceedComplete
    ));

    let mut storage_called = false;
    let observed_open = call_storage_only_if_permitted(&decision, || {
        storage_called = true;
        RocksDbAccountState::open_existing(&database_path(&alias))
    });
    assert!(storage_called);
    let opened = observed_open
        .expect("permitted COMPLETE decision calls storage")
        .expect("existing-only API opens database selected by wrapper");
    let observed_marker = opened.get_account_state(&account_id(0x51));
    println!(
        "account API result after permitted guard: Ok; marker nonce={} balance={}",
        observed_marker.nonce, observed_marker.balance
    );
    assert_eq!(observed_marker.nonce, lossy_marker.nonce);
    assert_eq!(observed_marker.balance, lossy_marker.balance);
    drop(opened);
    println!("storage API called after permitted decision: {storage_called}");
    print_entries("intended database entries after API call", &intended_db);
    print_entries(
        "raw alias target database entries after API call",
        &database_path(&alias),
    );
    print_entries("lossy-spelling database entries after API call", &lossy_db);
}

#[cfg(unix)]
#[test]
fn utf8_positive_control_and_real_guard_refusals_skip_storage() {
    let fixture = tempdir().expect("create unique controls fixture root");
    let root = fixture.path();

    let positive = root.join("utf8-positive");
    fs::create_dir(&positive).expect("create UTF-8 positive destination");
    let positive_marker = AccountState::new(0x3333, 0xcccc);
    write_database(&positive, 0x52, &positive_marker);
    let positive_record = complete_record(&positive);
    publish_complete(&positive, &positive_record);
    let positive_decision = evaluate_ordinary_startup(&positive);
    println!("UTF-8 positive control guard decision: {positive_decision:?}");
    assert!(matches!(
        &positive_decision,
        OrdinaryStartupDecision::ProceedComplete
    ));
    let mut positive_called = false;
    let positive_open = call_storage_only_if_permitted(&positive_decision, || {
        positive_called = true;
        RocksDbAccountState::open_existing(&database_path(&positive))
    });
    let positive_db = positive_open
        .expect("positive decision permits storage")
        .expect("open UTF-8 positive control");
    let positive_observed = positive_db.get_account_state(&account_id(0x52));
    println!(
        "UTF-8 positive control storage marker: nonce={} balance={}",
        positive_observed.nonce, positive_observed.balance
    );
    assert_eq!(positive_observed.nonce, positive_marker.nonce);
    assert_eq!(positive_observed.balance, positive_marker.balance);
    drop(positive_db);
    assert!(positive_called);

    let foreign = root.join("foreign-record");
    fs::create_dir(&foreign).expect("create foreign-record destination");
    write_database(&foreign, 0x53, &AccountState::new(0x4444, 0xdddd));
    let mut foreign_record = complete_record(&foreign);
    foreign_record.destination_id = root
        .join("different-destination")
        .to_string_lossy()
        .into_owned();
    publish_complete(&foreign, &foreign_record);
    let foreign_decision = evaluate_ordinary_startup(&foreign);
    println!("foreign COMPLETE guard decision: {foreign_decision:?}");
    assert!(matches!(
        &foreign_decision,
        OrdinaryStartupDecision::RefuseForeign { .. }
    ));
    let mut foreign_called = false;
    let foreign_open = call_storage_only_if_permitted(&foreign_decision, || {
        foreign_called = true;
        RocksDbAccountState::open_existing(&database_path(&foreign))
    });
    assert!(foreign_open.is_none());
    assert!(!foreign_called);
    println!("foreign refusal storage API called: {foreign_called}");

    let missing = root.join("missing-required-state");
    fs::create_dir(&missing).expect("create missing-state destination");
    let missing_record = complete_record(&missing);
    publish_complete(&missing, &missing_record);
    let missing_decision = evaluate_ordinary_startup(&missing);
    println!("missing-state COMPLETE guard decision: {missing_decision:?}");
    assert!(matches!(
        &missing_decision,
        OrdinaryStartupDecision::RefuseMissingState(_)
    ));
    let mut missing_called = false;
    let missing_open = call_storage_only_if_permitted(&missing_decision, || {
        missing_called = true;
        RocksDbAccountState::open_existing(&database_path(&missing))
    });
    assert!(missing_open.is_none());
    assert!(!missing_called);
    println!("missing-state refusal storage API called: {missing_called}");

    let empty = root.join("empty-required-state");
    fs::create_dir(&empty).expect("create empty-state destination");
    fs::create_dir(database_path(&empty)).expect("create empty required state directory");
    let empty_record = complete_record(&empty);
    publish_complete(&empty, &empty_record);
    let empty_decision = evaluate_ordinary_startup(&empty);
    println!("empty-state COMPLETE guard decision: {empty_decision:?}");
    assert!(matches!(
        &empty_decision,
        OrdinaryStartupDecision::RefuseMissingState(_)
    ));
    let mut empty_called = false;
    let empty_open = call_storage_only_if_permitted(&empty_decision, || {
        empty_called = true;
        RocksDbAccountState::open_existing(&database_path(&empty))
    });
    assert!(empty_open.is_none());
    assert!(!empty_called);
    println!("empty-state refusal storage API called: {empty_called}");
}

#[cfg(not(unix))]
#[test]
fn nonutf8_complete_alias_guard_then_account_storage_characterization() {
    println!("INCONCLUSIVE: platform cannot construct arbitrary non-UTF-8 path bytes");
}

#[cfg(not(unix))]
#[test]
fn utf8_positive_control_and_real_guard_refusals_skip_storage() {
    println!("INCONCLUSIVE: complete guard/refusal controls are part of Unix-only fixture");
}
