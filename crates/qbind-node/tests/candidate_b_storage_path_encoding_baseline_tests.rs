use qbind_ledger::{
    AccountState, NonceExecutionEngine, PersistentAccountState, RocksDbAccountState,
    TransferPayload,
};
use qbind_node::execution_adapter::{
    AsyncExecutionService, QbindBlock, SingleThreadExecutionService,
    SingleThreadExecutionServiceConfig,
};
use qbind_node::metrics::ExecutionMetrics;
use qbind_node::storage::{ConsensusStorage, RocksDbConsensusStorage};
use qbind_wire::consensus::{BlockHeader, BlockProposal};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
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
    let open_was_refused = consensus_open_is_refusal(&opened);
    match opened {
        Ok(db) => {
            let epoch = db.get_current_epoch().expect("read opened consensus epoch");
            println!("RocksDbConsensusStorage::open(raw) result: Ok; epoch={epoch:?}");
            assert!(
                epoch.is_none() || epoch == Some(expected_epoch),
                "raw-path consensus API returned unexpected state instead of the lossy control epoch"
            );
            drop(db);
        }
        Err(error) => {
            println!("RocksDbConsensusStorage::open(raw) result: Err; debug={error:?}");
            println!("RocksDbConsensusStorage::open(raw) display: {error}");
        }
    }

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
        open_was_refused
            && !raw_db.parent().unwrap().exists()
            && !raw_db.exists()
            && before_lossy == after_lossy,
        "BASELINE CONTRACT FAILURE: consensus open did not refuse before observed effects"
    );
}

#[cfg(unix)]
#[test]
fn consensus_refusal_oracle_rejects_successful_empty_database() {
    let fixture = tempdir().expect("create empty consensus sensitivity fixture");
    let path = fixture.path().join("empty-consensus");
    let opened = RocksDbConsensusStorage::open(&path);
    let database = opened
        .as_ref()
        .expect("create valid empty consensus database");
    let epoch = database
        .get_current_epoch()
        .expect("read absent epoch from successful empty database");
    assert_eq!(epoch, None);
    assert!(
        !consensus_open_is_refusal(&opened),
        "oracle sensitivity control must reject every successful open, including empty"
    );
    drop(opened);
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
    if let Err(error) = &existing_error {
        println!("ordinary account existing-only error debug: {error:?}");
        println!("ordinary account existing-only error display: {error}");
    }
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
    if let Err(error) = &account_create_error {
        println!("ordinary account-create error debug: {error:?}");
        println!("ordinary account-create error display: {error}");
    }
    if let Err(error) = &consensus_error {
        println!("ordinary consensus error debug: {error:?}");
        println!("ordinary consensus error display: {error}");
    }
    assert!(account_create_error.is_err());
    assert!(consensus_error.is_err());
    println!("representable UTF-8 account/consensus positive controls: passed");
}

#[cfg(unix)]
#[test]
fn execution_adapter_persistent_failure_falls_back_but_memory_is_explicit() {
    let fixture = tempdir().expect("create isolated adapter fixture");
    let root = fixture.path();
    let blocker = root.join("regular-file");
    fs::write(&blocker, b"not a directory").expect("create adapter path blocker");

    let failed_persistent_path = blocker.join("state_vm_v0");
    let persistent_metrics = Arc::new(ExecutionMetrics::new());
    let persistent_config =
        SingleThreadExecutionServiceConfig::vm_v0_persistent(&failed_persistent_path);
    let persistent_service = SingleThreadExecutionService::with_config(
        NonceExecutionEngine::new(),
        persistent_config,
        Some(Arc::clone(&persistent_metrics)),
    );
    persistent_service
        .submit_block(adapter_test_block(0x61))
        .expect("submit VM-v0 block after configured persistent open failure");
    wait_for_one_applied_transaction(&persistent_metrics);
    println!(
        "adapter configured persistent path open failure led to tx count={}",
        persistent_metrics.txs_applied_total()
    );
    persistent_service.shutdown();

    let memory_metrics = Arc::new(ExecutionMetrics::new());
    let memory_config = SingleThreadExecutionServiceConfig::vm_v0();
    let memory_service = SingleThreadExecutionService::with_config(
        NonceExecutionEngine::new(),
        memory_config,
        Some(Arc::clone(&memory_metrics)),
    );
    memory_service
        .submit_block(adapter_test_block(0x62))
        .expect("submit VM-v0 block in explicitly selected in-memory mode");
    wait_for_one_applied_transaction(&memory_metrics);
    println!(
        "adapter explicitly selected in-memory tx count={}",
        memory_metrics.txs_applied_total()
    );
    memory_service.shutdown();

    assert_eq!(persistent_metrics.txs_applied_total(), 1);
    assert_eq!(memory_metrics.txs_applied_total(), 1);
    assert!(!failed_persistent_path.exists());
}

#[cfg(unix)]
#[test]
fn execution_adapter_requested_persistent_failure_requires_refusal() {
    let fixture = tempdir().expect("create isolated adapter refusal fixture");
    let blocker = fixture.path().join("regular-file");
    fs::write(&blocker, b"not a directory").expect("create adapter path blocker");

    let failed_persistent_path = blocker.join("state_vm_v0");
    let metrics = Arc::new(ExecutionMetrics::new());
    let config =
        SingleThreadExecutionServiceConfig::vm_v0_persistent(&failed_persistent_path);
    let service = SingleThreadExecutionService::with_config(
        NonceExecutionEngine::new(),
        config,
        Some(Arc::clone(&metrics)),
    );
    service
        .submit_block(adapter_test_block(0x63))
        .expect("enqueue block with persistent storage requested");
    let applied = wait_for_applied_transactions(&metrics);
    println!(
        "adapter requested-persistent open failure observed applied tx count={applied}"
    );
    service.shutdown();

    assert_eq!(
        applied, 0,
        "BASELINE CONTRACT FAILURE: requested persistent storage failure must refuse, not execute in memory"
    );
}

#[cfg(unix)]
fn adapter_test_block(sender_byte: u8) -> QbindBlock {
    let sender = [sender_byte; 32];
    let recipient = [sender_byte.wrapping_add(1); 32];
    let proposal = Arc::new(BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1337,
            epoch: 0,
            height: 1,
            round: 0,
            parent_block_id: [0; 32],
            payload_hash: [sender_byte; 32],
            proposer_index: 0,
            suite_id: 0,
            tx_count: 1,
            timestamp: 1_704_067_200,
            payload_kind: 0,
            next_epoch: 0,
            batch_commitment: [0; 32],
        },
        qc: None,
        txs: Vec::new(),
        signature: Vec::new(),
    });
    QbindBlock::new(
        proposal,
        vec![qbind_ledger::QbindTransaction::new(
            sender,
            0,
            TransferPayload::new(recipient, 0).encode(),
        )],
    )
}

#[cfg(unix)]
fn wait_for_one_applied_transaction(metrics: &ExecutionMetrics) {
    assert_eq!(
        wait_for_applied_transactions(metrics),
        1,
        "worker did not apply test transaction"
    );
}

#[cfg(unix)]
fn wait_for_applied_transactions(metrics: &ExecutionMetrics) -> u64 {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while metrics.txs_applied_total() == 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    metrics.txs_applied_total()
}

#[cfg(unix)]
fn consensus_open_is_refusal<T, E>(result: &Result<T, E>) -> bool {
    matches!(result, Err(_))
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
