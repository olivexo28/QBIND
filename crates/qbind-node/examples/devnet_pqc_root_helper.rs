//! Run 037: offline / DevNet helper binary that mints a real
//! ML-DSA-44-signed PQC trust root + per-validator leaf delegation
//! certs.
//!
//! Usage:
//!   cargo run -p qbind-node --example devnet_pqc_root_helper -- <outdir> <num_validators> [validity_mode]
//!
//! `validity_mode` (Run 045, optional, defaults to `currently-valid`):
//!   - `currently-valid` — `not_before=0, not_after=u64::MAX` (default).
//!   - `expired` — `not_before=0, not_after=1` (guaranteed-expired,
//!                 for negative cert-validity-window smoke evidence).
//!   - `not-yet-valid` — `not_before=u64::MAX-1, not_after=u64::MAX`
//!                       (guaranteed not-yet-valid).
//!
//! Writes to `outdir`:
//!   root.id.hex             — 64 lowercase hex chars (root_key_id)
//!   root.pk.hex             — full ML-DSA-44 root public key, lowercase hex
//!   v<N>.cert.bin           — encoded NetworkDelegationCert for validator N
//!   v<N>.kem.sk.bin         — KEM secret key bytes corresponding to leaf cert
//!   trusted-root.spec       — single-line `--p2p-trusted-root` ready to copy
//!
//! **DevNet only**: the root signing key is generated fresh on every
//! invocation and never written to disk in any form. A fully
//! production CA flow with rotation / revocation is out of scope and
//! tracked under C4 in `docs/whitepaper/contradiction.md`.

use std::fs;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use qbind_crypto::{MlKem768Backend, KEM_SUITE_ML_KEM_768};
use qbind_node::pqc_devnet_helper::{
    encode_cert, issue_leaf_delegation_cert, mint_devnet_root, LeafCertSpec,
};
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;

fn vid_bytes(vid: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    let s = format!("qbind-val-{}", vid);
    let n = s.len().min(32);
    b[..n].copy_from_slice(&s.as_bytes()[..n]);
    b
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Run 045: select the validity-window mode for the minted leaf certs.
fn leaf_spec_for_mode(
    mode: &str,
    validator_id: [u8; 32],
    root_key_id: [u8; 32],
    leaf_kem_pk: Vec<u8>,
) -> LeafCertSpec {
    match mode {
        "currently-valid" => {
            LeafCertSpec::currently_valid(validator_id, root_key_id, leaf_kem_pk)
        }
        "expired" => LeafCertSpec::expired_for_test(validator_id, root_key_id, leaf_kem_pk),
        "not-yet-valid" => {
            LeafCertSpec::not_yet_valid_for_test(validator_id, root_key_id, leaf_kem_pk)
        }
        other => panic!(
            "unknown validity_mode `{}` (expected `currently-valid` / `expired` / `not-yet-valid`)",
            other
        ),
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let outdir = args
        .next()
        .expect("usage: devnet_pqc_root_helper <outdir> <num_validators> [validity_mode]");
    let num_validators: u64 = args
        .next()
        .expect("usage: devnet_pqc_root_helper <outdir> <num_validators> [validity_mode]")
        .parse()
        .expect("num_validators must be a u64");
    // Run 045: optional third argument selects the validity-window
    // shape of the minted leaf certs (default: currently-valid).
    let validity_mode = args.next().unwrap_or_else(|| "currently-valid".to_string());

    fs::create_dir_all(&outdir).expect("mkdir outdir");

    let root = mint_devnet_root().expect("root keygen");
    let root_id_hex = hex_lower(&root.root_key_id);
    let root_pk_hex = hex_lower(&root.root_pk);

    fs::write(format!("{}/root.id.hex", outdir), &root_id_hex).expect("write root.id.hex");
    fs::write(format!("{}/root.pk.hex", outdir), &root_pk_hex).expect("write root.pk.hex");

    let trusted_spec = format!(
        "{}:{}:{}",
        root_id_hex, PQC_TRANSPORT_SUITE_ML_DSA_44, root_pk_hex
    );
    fs::write(format!("{}/trusted-root.spec", outdir), &trusted_spec)
        .expect("write trusted-root.spec");

    for vid in 0..num_validators {
        let (kem_pk, kem_sk) = MlKem768Backend::generate_keypair().expect("ML-KEM-768 keygen");
        let spec = leaf_spec_for_mode(&validity_mode, vid_bytes(vid), root.root_key_id, kem_pk);
        let cert = issue_leaf_delegation_cert(&spec, &root.root_sk).expect("issue leaf cert");

        fs::write(format!("{}/v{}.cert.bin", outdir, vid), encode_cert(&cert)).expect("write cert");

        // KEM secret key bytes — the consumer wraps them in
        // `qbind_net::keys::KemPrivateKey` (zeroize-on-drop).
        let sk_path = format!("{}/v{}.kem.sk.bin", outdir, vid);
        fs::write(&sk_path, &kem_sk).expect("write kem sk");
        #[cfg(unix)]
        fs::set_permissions(&sk_path, fs::Permissions::from_mode(0o600))
            .expect("chmod kem sk 0600");
    }

    eprintln!(
        "[devnet_pqc_root_helper] DEVNET-EPHEMERAL: root_id={} sig_suite={} kem_suite={} kem=ml-kem-768 validators={} validity_mode={} outdir={}",
        root_id_hex,
        PQC_TRANSPORT_SUITE_ML_DSA_44,
        KEM_SUITE_ML_KEM_768,
        num_validators,
        validity_mode,
        outdir
    );
    eprintln!("[devnet_pqc_root_helper] root_sk was held in memory only; never written to disk.");

    // Print the spec line on stdout so callers can capture it
    // directly into a `--p2p-trusted-root` flag.
    println!("{}", trusted_spec);
}