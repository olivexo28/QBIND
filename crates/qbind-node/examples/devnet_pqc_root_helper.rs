//! Run 037: offline / DevNet helper binary that mints a real
//! ML-DSA-44-signed PQC trust root + per-validator leaf delegation
//! certs.
//!
//! Usage:
//!   cargo run -p qbind-node --example devnet_pqc_root_helper -- <outdir> <num_validators>
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

fn main() {
    let mut args = std::env::args().skip(1);
    let outdir = args
        .next()
        .expect("usage: devnet_pqc_root_helper <outdir> <num_validators>");
    let num_validators: u64 = args
        .next()
        .expect("usage: devnet_pqc_root_helper <outdir> <num_validators>")
        .parse()
        .expect("num_validators must be a u64");

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
        let cert = issue_leaf_delegation_cert(
            &LeafCertSpec {
                validator_id: vid_bytes(vid),
                root_key_id: root.root_key_id,
                leaf_kem_suite_id: KEM_SUITE_ML_KEM_768,
                leaf_kem_pk: kem_pk,
                not_before: 0,
                not_after: u64::MAX,
                ext_bytes: vec![],
            },
            &root.root_sk,
        )
        .expect("issue leaf cert");

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
        "[devnet_pqc_root_helper] DEVNET-EPHEMERAL: root_id={} sig_suite={} kem_suite={} kem=ml-kem-768 validators={} outdir={}",
        root_id_hex, PQC_TRANSPORT_SUITE_ML_DSA_44, KEM_SUITE_ML_KEM_768, num_validators, outdir
    );
    eprintln!("[devnet_pqc_root_helper] root_sk was held in memory only; never written to disk.");

    // Print the spec line on stdout so callers can capture it
    // directly into a `--p2p-trusted-root` flag.
    println!("{}", trusted_spec);
}