//! Run-020 reproducibility helper: deterministically seed a fresh
//! VM-v0 `RocksDbAccountState` with a single well-known account, exactly
//! matching the canonical `build_real_snapshot` helper used by the B3
//! integration tests in
//! `crates/qbind-node/tests/b3_snapshot_restore_tests.rs`. This is then
//! consumed by `qbind_state_snapshot` (in this same crate) to produce a
//! real RocksDB checkpoint via `StateSnapshotter::create_snapshot`.
//!
//! Why this exists: the qbind-node binary's binary-consensus loop does
//! not currently open a VM-v0 `RocksDbAccountState` at runtime, so no
//! live VM-v0 state is materialized on disk by a running validator
//! today. To still produce a *real-format* RocksDB checkpoint that the
//! supported B3 restore path can consume on the binary path, we seed a
//! local `RocksDbAccountState` here and snapshot it. The resulting
//! checkpoint is bit-for-bit a real RocksDB checkpoint (CURRENT,
//! MANIFEST-*, OPTIONS-*, IDENTITY, *.log/*.sst), produced by the same
//! `RocksDbAccountState::create_snapshot` impl that production paths
//! would use.

use std::path::PathBuf;
use std::process::ExitCode;

use qbind_ledger::{AccountState, PersistentAccountState, RocksDbAccountState};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let state_dir: PathBuf = match args.next() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("usage: qbind_seed_vm_v0_state <state_dir>");
            return ExitCode::from(2);
        }
    };

    if state_dir.exists() {
        eprintln!(
            "[qbind_seed_vm_v0_state] ERROR: state_dir must not pre-exist: {}",
            state_dir.display()
        );
        return ExitCode::from(2);
    }
    if let Some(parent) = state_dir.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }

    let storage = match RocksDbAccountState::open(&state_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[qbind_seed_vm_v0_state] open failed: {e:?}");
            return ExitCode::from(1);
        }
    };

    let account: [u8; 32] = [0xCD; 32];
    let state = AccountState::new(7, 4242);
    if let Err(e) = storage.put_account_state(&account, &state) {
        eprintln!("[qbind_seed_vm_v0_state] put_account_state failed: {e:?}");
        return ExitCode::from(1);
    }
    if let Err(e) = storage.flush() {
        eprintln!("[qbind_seed_vm_v0_state] flush failed: {e:?}");
        return ExitCode::from(1);
    }
    drop(storage);

    eprintln!(
        "[qbind_seed_vm_v0_state] OK: seeded {} account=cdcd...cd nonce=7 balance=4242",
        state_dir.display()
    );
    ExitCode::SUCCESS
}