//! Run-020 reproducibility helper: external invoker of the supported
//! `StateSnapshotter::create_snapshot` path against an existing VM-v0
//! RocksDB state directory.
//!
//! This is **not** a new snapshot format. It is a thin operator entry point
//! that calls the same `RocksDbAccountState::create_snapshot` used by the
//! `StateSnapshotter` trait impl in `crates/qbind-ledger/src/execution.rs`
//! and by the T215 integration tests
//! (`crates/qbind-ledger/tests/t215_state_snapshot_tests.rs`) and the B3
//! integration tests (`crates/qbind-node/tests/b3_snapshot_restore_tests.rs`,
//! helper `build_real_snapshot`). The output directory layout is exactly
//! what `validate_snapshot_dir` and `apply_snapshot_restore_if_requested`
//! expect:
//!
//! ```text
//! <snapshot_dir>/
//! ├── meta.json    # StateSnapshotMeta
//! └── state/       # RocksDB checkpoint (CURRENT, MANIFEST-*, SST, OPTIONS-*, IDENTITY)
//! ```
//!
//! The qbind-node binary does not currently expose an in-process trigger
//! for `StateSnapshotter::create_snapshot`. To produce a real RocksDB
//! checkpoint of a running validator's VM-v0 state for Run 020, the
//! validator must be paused (so RocksDB's exclusive write lock can be
//! acquired by this helper), this helper is invoked, and the validator is
//! resumed. The checkpoint produced is a real RocksDB checkpoint of the
//! validator's actual on-disk VM-v0 state at exactly the height the
//! validator last committed before pause. This is faithfully recorded in
//! the Run-020 evidence document; this helper does not bypass any
//! consensus, network, or restore behavior.
//!
//! Usage:
//!
//! ```sh
//! qbind_state_snapshot \
//!   --state-dir <path/to/data/state_vm_v0> \
//!   --snapshot-dir <path/to/snap-N> \
//!   --height <H> \
//!   --block-hash-hex <64-hex-chars> \
//!   --chain-id <u64-decimal-or-0x...>
//! ```
//!
//! Exits non-zero on any error. All output is written to stderr.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use qbind_ledger::{RocksDbAccountState, StateSnapshotMeta, StateSnapshotter};

#[derive(Debug)]
struct Args {
    state_dir: PathBuf,
    snapshot_dir: PathBuf,
    height: u64,
    block_hash: [u8; 32],
    chain_id: u64,
}

fn parse_u64(s: &str) -> Result<u64, String> {
    if let Some(stripped) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(stripped, 16).map_err(|e| format!("invalid hex u64 {s:?}: {e}"))
    } else {
        s.parse::<u64>()
            .map_err(|e| format!("invalid u64 {s:?}: {e}"))
    }
}

fn parse_hash32(s: &str) -> Result<[u8; 32], String> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.len() != 64 {
        return Err(format!("block-hash must be 64 hex chars, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
            .map_err(|e| format!("invalid hex byte at offset {i}: {e}"))?;
        out[i] = byte;
    }
    Ok(out)
}

fn parse_args() -> Result<Args, String> {
    let mut state_dir: Option<PathBuf> = None;
    let mut snapshot_dir: Option<PathBuf> = None;
    let mut height: Option<u64> = None;
    let mut block_hash: Option<[u8; 32]> = None;
    let mut chain_id: Option<u64> = None;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--state-dir" => {
                state_dir = Some(PathBuf::from(it.next().ok_or("--state-dir needs a value")?))
            }
            "--snapshot-dir" => {
                snapshot_dir =
                    Some(PathBuf::from(it.next().ok_or("--snapshot-dir needs a value")?))
            }
            "--height" => height = Some(parse_u64(&it.next().ok_or("--height needs a value")?)?),
            "--block-hash-hex" => {
                block_hash = Some(parse_hash32(&it.next().ok_or("--block-hash-hex needs a value")?)?)
            }
            "--chain-id" => {
                chain_id = Some(parse_u64(&it.next().ok_or("--chain-id needs a value")?)?)
            }
            "-h" | "--help" => {
                eprintln!(
                    "{}",
                    "qbind_state_snapshot --state-dir DIR --snapshot-dir DIR \
                     --height N --block-hash-hex HEX --chain-id N"
                );
                return Err("help".to_string());
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    Ok(Args {
        state_dir: state_dir.ok_or("--state-dir required")?,
        snapshot_dir: snapshot_dir.ok_or("--snapshot-dir required")?,
        height: height.ok_or("--height required")?,
        block_hash: block_hash.ok_or("--block-hash-hex required")?,
        chain_id: chain_id.ok_or("--chain-id required")?,
    })
}

fn run() -> Result<(), String> {
    let args = parse_args()?;

    if !args.state_dir.is_dir() {
        return Err(format!(
            "state-dir does not exist or is not a directory: {}",
            args.state_dir.display()
        ));
    }
    if args.snapshot_dir.exists() {
        return Err(format!(
            "snapshot-dir must not pre-exist (StateSnapshotter::create_snapshot refuses populated targets): {}",
            args.snapshot_dir.display()
        ));
    }

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let meta =
        StateSnapshotMeta::new(args.height, args.block_hash, now_ms, args.chain_id);

    eprintln!(
        "[qbind_state_snapshot] opening RocksDbAccountState at {}",
        args.state_dir.display()
    );
    let storage = RocksDbAccountState::open(&args.state_dir)
        .map_err(|e| format!("open state dir failed: {e:?}"))?;

    eprintln!(
        "[qbind_state_snapshot] invoking StateSnapshotter::create_snapshot meta={{height={},chain_id={:#x},block_hash={}}} target={}",
        meta.height,
        meta.chain_id,
        hex_encode(&meta.block_hash),
        args.snapshot_dir.display()
    );

    let stats = storage
        .create_snapshot(&meta, &args.snapshot_dir)
        .map_err(|e| format!("create_snapshot failed: {e:?}"))?;

    drop(storage);

    eprintln!(
        "[qbind_state_snapshot] OK: {} (size_bytes={}, duration_ms={})",
        stats, stats.size_bytes, stats.duration_ms
    );

    println!(
        "snapshot_dir={}\nheight={}\nchain_id={:#x}\nblock_hash={}\nsize_bytes={}\nduration_ms={}",
        args.snapshot_dir.display(),
        meta.height,
        meta.chain_id,
        hex_encode(&meta.block_hash),
        stats.size_bytes,
        stats.duration_ms
    );

    Ok(())
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        use std::fmt::Write;
        let _ = write!(s, "{byte:02x}");
    }
    s
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("[qbind_state_snapshot] ERROR: {msg}");
            ExitCode::from(1)
        }
    }
}