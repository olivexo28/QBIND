//! Minimal production binary-path VM-v0 runtime state opener and snapshot trigger.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use qbind_ledger::{
    RocksDbAccountState, SnapshotStats, StateSnapshotError, StateSnapshotMeta, StateSnapshotter,
    StorageError,
};

use crate::metrics::NodeMetrics;
use crate::node_config::{ExecutionProfile, NodeConfig};

pub const VM_V0_STATE_DIR_NAME: &str = "state_vm_v0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotAnchor {
    pub height: u64,
    pub block_hash: [u8; 32],
}

#[derive(Debug, thiserror::Error)]
pub enum VmV0RuntimeError {
    #[error(
        "VM-v0 persistent state requires --data-dir when --execution-profile vm-v0 is selected"
    )]
    MissingDataDir,
    #[error("failed to open VM-v0 state at {path}: {source}")]
    OpenState { path: PathBuf, source: StorageError },
    #[error("snapshot trigger is disabled because snapshot_dir is not configured")]
    SnapshotDirMissing,
    #[error("snapshot anchor is not available yet; no committed block has been observed")]
    MissingSnapshotAnchor,
    #[error("snapshot creation failed at {path}: {source}")]
    SnapshotCreate {
        path: PathBuf,
        source: StateSnapshotError,
    },
    #[error("failed to prune old snapshots in {path}: {source}")]
    SnapshotPrune {
        path: PathBuf,
        source: std::io::Error,
    },
}

#[derive(Debug)]
pub struct VmV0RuntimeState {
    state_dir: PathBuf,
    snapshot_dir: Option<PathBuf>,
    max_snapshots: u32,
    state: Mutex<RocksDbAccountState>,
}

impl VmV0RuntimeState {
    pub fn open_from_config(config: &NodeConfig) -> Result<Option<Arc<Self>>, VmV0RuntimeError> {
        if config.execution_profile != ExecutionProfile::VmV0 {
            return Ok(None);
        }

        let data_dir = config
            .data_dir
            .as_ref()
            .ok_or(VmV0RuntimeError::MissingDataDir)?;
        let state_dir = vm_v0_state_dir(data_dir);
        let state = RocksDbAccountState::open(&state_dir).map_err(|source| {
            VmV0RuntimeError::OpenState {
                path: state_dir.clone(),
                source,
            }
        })?;
        eprintln!("[vm-v0] opened persistent state at {}", state_dir.display());

        Ok(Some(Arc::new(Self {
            state_dir,
            snapshot_dir: config.snapshot_config.snapshot_dir.clone(),
            max_snapshots: config.snapshot_config.max_snapshots.max(1),
            state: Mutex::new(state),
        })))
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub fn snapshot_dir(&self) -> Option<&Path> {
        self.snapshot_dir.as_deref()
    }

    pub fn create_snapshot(
        &self,
        anchor: SnapshotAnchor,
        chain_id: u64,
        metrics: &NodeMetrics,
    ) -> Result<SnapshotStats, VmV0RuntimeError> {
        let snapshot_dir = self
            .snapshot_dir
            .as_ref()
            .ok_or(VmV0RuntimeError::SnapshotDirMissing)?;
        if anchor.height == 0 {
            return Err(VmV0RuntimeError::MissingSnapshotAnchor);
        }

        let target = snapshot_dir.join(anchor.height.to_string());
        let meta = StateSnapshotMeta {
            height: anchor.height,
            block_hash: anchor.block_hash,
            created_at_unix_ms: StateSnapshotMeta::now_unix_ms(),
            chain_id,
        };

        eprintln!(
            "[snapshot] start: height={} path={}",
            anchor.height,
            target.display()
        );
        eprintln!(
            "[snapshot] invoking StateSnapshotter::create_snapshot height={} path={}",
            anchor.height,
            target.display()
        );
        metrics.snapshot().set_in_progress(true);
        let result = self
            .state
            .lock()
            .expect("VM-v0 runtime state mutex poisoned")
            .create_snapshot(&meta, &target)
            .map_err(|source| VmV0RuntimeError::SnapshotCreate {
                path: target.clone(),
                source,
            });

        match result {
            Ok(stats) => {
                if let Err(source) = prune_old_snapshots(snapshot_dir, self.max_snapshots) {
                    metrics.snapshot().record_failure();
                    return Err(VmV0RuntimeError::SnapshotPrune {
                        path: snapshot_dir.clone(),
                        source,
                    });
                }
                metrics.snapshot().record_success(
                    stats.height,
                    stats.duration_ms,
                    stats.size_bytes,
                );
                Ok(stats)
            }
            Err(e) => {
                metrics.snapshot().record_failure();
                Err(e)
            }
        }
    }
}

pub fn vm_v0_state_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(VM_V0_STATE_DIR_NAME)
}

fn prune_old_snapshots(snapshot_dir: &Path, max_snapshots: u32) -> Result<(), std::io::Error> {
    let mut numeric_dirs = Vec::new();
    if !snapshot_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(snapshot_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Ok(height) = name.parse::<u64>() {
            numeric_dirs.push((height, entry.path()));
        }
    }
    numeric_dirs.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, path) in numeric_dirs.into_iter().skip(max_snapshots as usize) {
        eprintln!("[snapshot] pruning old numeric snapshot {}", path.display());
        fs::remove_dir_all(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_ledger::{AccountState, PersistentAccountState, StateSnapshotter};
    use tempfile::TempDir;

    fn vm_v0_config(data_dir: &Path, snapshot_dir: Option<&Path>) -> NodeConfig {
        let mut config = NodeConfig::devnet_v0_preset();
        config.execution_profile = ExecutionProfile::VmV0;
        config.data_dir = Some(data_dir.to_path_buf());
        if let Some(dir) = snapshot_dir {
            config.snapshot_config =
                crate::node_config::SnapshotConfig::enabled(dir.to_path_buf(), 50_000, 3);
        }
        config
    }

    #[test]
    fn vm_v0_runtime_path_is_data_dir_state_vm_v0() {
        let data = PathBuf::from("/var/lib/qbind");
        assert_eq!(
            vm_v0_state_dir(&data),
            PathBuf::from("/var/lib/qbind/state_vm_v0")
        );
    }

    #[test]
    fn nonce_only_does_not_open_vm_v0_state() {
        let temp = TempDir::new().unwrap();
        let mut config = NodeConfig::devnet_v0_preset();
        config.execution_profile = ExecutionProfile::NonceOnly;
        config.data_dir = Some(temp.path().to_path_buf());

        let runtime = VmV0RuntimeState::open_from_config(&config).unwrap();

        assert!(runtime.is_none());
        assert!(!temp.path().join(VM_V0_STATE_DIR_NAME).exists());
    }

    #[test]
    fn vm_v0_opens_persistent_state_dir() {
        let temp = TempDir::new().unwrap();
        let config = vm_v0_config(temp.path(), None);

        let runtime = VmV0RuntimeState::open_from_config(&config)
            .unwrap()
            .unwrap();

        assert_eq!(runtime.state_dir(), &temp.path().join(VM_V0_STATE_DIR_NAME));
        assert!(runtime.state_dir().exists());
    }

    #[test]
    fn vm_v0_requires_data_dir_for_persistent_binary_path() {
        let mut config = NodeConfig::devnet_v0_preset();
        config.execution_profile = ExecutionProfile::VmV0;
        config.data_dir = None;

        let err = VmV0RuntimeState::open_from_config(&config).unwrap_err();

        assert!(matches!(err, VmV0RuntimeError::MissingDataDir));
    }

    #[test]
    fn vm_v0_snapshot_trigger_creates_real_snapshot_layout() {
        let data = TempDir::new().unwrap();
        let snapshots = TempDir::new().unwrap();
        let config = vm_v0_config(data.path(), Some(snapshots.path()));
        let runtime = VmV0RuntimeState::open_from_config(&config)
            .unwrap()
            .unwrap();
        let account = [0x24; 32];
        runtime
            .state
            .lock()
            .expect("VM-v0 runtime state mutex poisoned")
            .put_account_state(
                &account,
                &AccountState {
                    nonce: 1,
                    balance: 42,
                },
            )
            .unwrap();

        let metrics = NodeMetrics::new();
        let stats = runtime
            .create_snapshot(
                SnapshotAnchor {
                    height: 7,
                    block_hash: [0xAB; 32],
                },
                config.chain_id().as_u64(),
                &metrics,
            )
            .unwrap();

        assert_eq!(stats.height, 7);
        assert!(snapshots.path().join("7/meta.json").is_file());
        let checkpoint = snapshots.path().join("7/state");
        assert!(checkpoint.is_dir());
        assert!(checkpoint.join("CURRENT").is_file());
        let checkpoint_files: Vec<String> = fs::read_dir(&checkpoint)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(checkpoint_files
            .iter()
            .any(|name| name.starts_with("MANIFEST-")));
        assert!(checkpoint_files.iter().any(|name| name.ends_with(".sst")));
        assert!(checkpoint_files
            .iter()
            .any(|name| name.starts_with("OPTIONS-")));
        assert_eq!(metrics.snapshot().success_total(), 1);
        assert_eq!(metrics.snapshot().failure_total(), 0);
    }

    #[test]
    fn vm_v0_snapshot_trigger_prunes_only_old_numeric_dirs() {
        let data = TempDir::new().unwrap();
        let snapshots = TempDir::new().unwrap();
        let mut config = vm_v0_config(data.path(), Some(snapshots.path()));
        config.snapshot_config.max_snapshots = 2;
        let runtime = VmV0RuntimeState::open_from_config(&config)
            .unwrap()
            .unwrap();
        let metrics = NodeMetrics::new();
        fs::create_dir_all(snapshots.path().join("operator-notes")).unwrap();

        for height in 1..=3 {
            runtime
                .create_snapshot(
                    SnapshotAnchor {
                        height,
                        block_hash: [height as u8; 32],
                    },
                    config.chain_id().as_u64(),
                    &metrics,
                )
                .unwrap();
        }

        assert!(!snapshots.path().join("1").exists());
        assert!(snapshots.path().join("2").is_dir());
        assert!(snapshots.path().join("3").is_dir());
        assert!(snapshots.path().join("operator-notes").is_dir());
        assert_eq!(metrics.snapshot().success_total(), 3);
        assert_eq!(metrics.snapshot().failure_total(), 0);
    }

    #[test]
    fn vm_v0_snapshot_trigger_disabled_without_snapshot_dir() {
        let data = TempDir::new().unwrap();
        let config = vm_v0_config(data.path(), None);
        let runtime = VmV0RuntimeState::open_from_config(&config)
            .unwrap()
            .unwrap();
        let metrics = NodeMetrics::new();

        let err = runtime
            .create_snapshot(
                SnapshotAnchor {
                    height: 7,
                    block_hash: [0xAB; 32],
                },
                config.chain_id().as_u64(),
                &metrics,
            )
            .unwrap_err();

        assert!(matches!(err, VmV0RuntimeError::SnapshotDirMissing));
        assert_eq!(metrics.snapshot().success_total(), 0);
        assert_eq!(metrics.snapshot().failure_total(), 0);
    }

    #[test]
    fn restored_state_dir_is_opened_by_runtime() {
        let source = TempDir::new().unwrap();
        let restored = TempDir::new().unwrap();
        let source_db = RocksDbAccountState::open(source.path().join("state")).unwrap();
        let account = [0x42; 32];
        source_db
            .put_account_state(
                &account,
                &AccountState {
                    nonce: 3,
                    balance: 123,
                },
            )
            .unwrap();
        source_db.flush().unwrap();
        source_db
            .create_snapshot(
                &StateSnapshotMeta {
                    height: 11,
                    block_hash: [0x11; 32],
                    created_at_unix_ms: StateSnapshotMeta::now_unix_ms(),
                    chain_id: 1337,
                },
                &source.path().join("snapshot"),
            )
            .unwrap();
        fs::rename(
            source.path().join("snapshot/state"),
            restored.path().join(VM_V0_STATE_DIR_NAME),
        )
        .unwrap();

        let config = vm_v0_config(restored.path(), None);
        let runtime = VmV0RuntimeState::open_from_config(&config)
            .unwrap()
            .unwrap();
        let restored_state = runtime
            .state
            .lock()
            .expect("VM-v0 runtime state mutex poisoned")
            .get_account_state(&account);

        assert_eq!(restored_state.nonce, 3);
    }
}