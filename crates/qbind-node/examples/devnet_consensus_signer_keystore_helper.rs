//! Run 048: minimal DevNet helper that mints N ML-DSA-44 consensus
//! signer keystores in the on-disk JSON format consumed by
//! `FsValidatorKeystore` (`{suite_id: 100, private_key_hex: "..."}`)
//! and writes them at `{outdir}/v{N}/validator-{N}.json` with mode
//! `0o600`.
//!
//! Usage:
//!   cargo run -p qbind-node --example devnet_consensus_signer_keystore_helper -- <outdir> <num_validators>
//!
//! This is an evidence/test helper only: it does not introduce any
//! new CLI surface on `qbind-node`, does not change protocol
//! behaviour, does not weaken signing, and never logs secret-key
//! material. Public-key fingerprints (first 4 hex bytes) are printed
//! so the operator can copy them into the per-node
//! `--validator-consensus-key VID:100:HEXPK` set without re-reading
//! the JSON. Public keys are also written separately to
//! `{outdir}/v{N}/validator-{N}.pk.hex` for convenience.

use std::fs;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use qbind_crypto::MlDsa44Backend;

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn fingerprint(pk: &[u8]) -> String {
    let take = pk.len().min(4);
    hex_lower(&pk[..take])
}

#[cfg(unix)]
fn set_mode_0600(path: &std::path::Path) -> std::io::Result<()> {
    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn set_mode_0600(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "usage: {} <outdir> <num_validators>",
            args.first().map(|s| s.as_str()).unwrap_or("helper")
        );
        std::process::exit(2);
    }
    let outdir = std::path::PathBuf::from(&args[1]);
    let n: u64 = args[2].parse().expect("num_validators must be a u64");
    if n == 0 || n > 64 {
        eprintln!("num_validators must be in 1..=64");
        std::process::exit(2);
    }

    fs::create_dir_all(&outdir).expect("create outdir");

    println!(
        "[devnet_consensus_signer_keystore_helper] DEVNET-EPHEMERAL: minting {} ML-DSA-44 \
         consensus signer keystore(s) under {}",
        n,
        outdir.display()
    );

    for vid in 0..n {
        let (pk, sk) =
            MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen failed");
        let vdir = outdir.join(format!("v{}", vid));
        fs::create_dir_all(&vdir).expect("create v{N} dir");
        let path = vdir.join(format!("validator-{}.json", vid));
        let json = format!(
            "{{\"suite_id\":100,\"private_key_hex\":\"{}\"}}",
            hex_lower(&sk)
        );
        fs::write(&path, json).expect("write keystore json");
        set_mode_0600(&path).expect("chmod 0600 keystore");
        let pk_path = vdir.join(format!("validator-{}.pk.hex", vid));
        fs::write(&pk_path, hex_lower(&pk)).expect("write pk hex");
        println!(
            "[devnet_consensus_signer_keystore_helper] V{} keystore_path={} pk_fp={} suite_id=100",
            vid,
            path.display(),
            fingerprint(&pk),
        );
        // sk is dropped here without ever being logged.
        let _ = sk;
    }
    println!(
        "[devnet_consensus_signer_keystore_helper] done; secret keys held in memory only, \
         keystore JSON files are mode 0o600"
    );
}