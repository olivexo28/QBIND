//! Run 050: DevNet-only helper that mints a real ML-DSA-44-signed
//! PQC trust root, generates per-validator leaf certs (delegating to
//! the existing Run 037 `devnet_pqc_root_helper` shape), AND emits a
//! Run 050 PQC trust-anchor bundle (`trust-bundle.json`) covering the
//! requested fixture mode.
//!
//! Usage:
//!   cargo run -p qbind-node --example devnet_pqc_trust_bundle_helper -- \
//!     <outdir> <num_validators> [bundle_mode]
//!
//! `bundle_mode` (optional, defaults to `valid`):
//!   - `valid`              — currently-valid DevNet bundle.
//!   - `wrong-environment`  — TestNet bundle (DevNet loader rejects).
//!   - `expired-bundle`     — `valid_until=1` (loader rejects as expired).
//!   - `expired-root`       — root `not_after=1` (loader rejects).
//!   - `root-revocation-listed` — root present in `revocations[]`
//!                                (loader accepts bundle but root is
//!                                excluded from the active set).
//!   - `root-status-revoked` — `roots[0].status = "revoked"`.
//!   - `duplicate-root`     — two `roots[]` entries with same id.
//!   - `unsupported-suite`  — `roots[0].suite_id = 99`.
//!
//! Writes to `outdir`:
//!   root.id.hex                — 64 lowercase hex chars (root_key_id)
//!   root.pk.hex                — full ML-DSA-44 root public key
//!   v<N>.cert.bin              — encoded NetworkDelegationCert
//!   v<N>.kem.sk.bin            — KEM secret key bytes (0o600)
//!   trusted-root.spec          — `--p2p-trusted-root` line (DevNet only)
//!   trust-bundle.json          — Run 050 PQC trust-anchor bundle
//!
//! **DevNet only**: the root signing key is generated fresh on every
//! invocation and never written to disk in any form. A fully-
//! production CA flow with rotation / revocation / signed bundle
//! verification is out of scope and tracked under C4 in
//! `docs/whitepaper/contradiction.md`.

use std::fs;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use qbind_crypto::{MlKem768Backend, KEM_SUITE_ML_KEM_768};
use qbind_node::pqc_devnet_helper::{
    encode_cert, issue_leaf_delegation_cert, mint_devnet_root, LeafCertSpec,
};
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_bundle::{build_helper_bundle, HelperBundleMode};

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

fn parse_bundle_mode(s: &str) -> HelperBundleMode {
    match s {
        "valid" => HelperBundleMode::Valid,
        "wrong-environment" => HelperBundleMode::WrongEnvironment,
        "expired-bundle" => HelperBundleMode::ExpiredBundle,
        "expired-root" => HelperBundleMode::ExpiredRoot,
        "root-revocation-listed" => HelperBundleMode::RootRevocationListed,
        "root-status-revoked" => HelperBundleMode::RootStatusRevoked,
        "duplicate-root" => HelperBundleMode::DuplicateRoot,
        "unsupported-suite" => HelperBundleMode::UnsupportedSuite,
        other => panic!(
            "unknown bundle_mode `{}` (expected one of: \
             valid / wrong-environment / expired-bundle / expired-root / \
             root-revocation-listed / root-status-revoked / duplicate-root / \
             unsupported-suite)",
            other
        ),
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let outdir = args
        .next()
        .expect("usage: devnet_pqc_trust_bundle_helper <outdir> <num_validators> [bundle_mode]");
    let num_validators: u64 = args
        .next()
        .expect("usage: devnet_pqc_trust_bundle_helper <outdir> <num_validators> [bundle_mode]")
        .parse()
        .expect("num_validators must be a u64");
    let bundle_mode_arg = args.next().unwrap_or_else(|| "valid".to_string());
    let bundle_mode = parse_bundle_mode(&bundle_mode_arg);

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
        let spec = LeafCertSpec::currently_valid(vid_bytes(vid), root.root_key_id, kem_pk);
        let cert = issue_leaf_delegation_cert(&spec, &root.root_sk).expect("issue leaf cert");

        fs::write(format!("{}/v{}.cert.bin", outdir, vid), encode_cert(&cert))
            .expect("write cert");

        let sk_path = format!("{}/v{}.kem.sk.bin", outdir, vid);
        fs::write(&sk_path, &kem_sk).expect("write kem sk");
        #[cfg(unix)]
        fs::set_permissions(&sk_path, fs::Permissions::from_mode(0o600))
            .expect("chmod kem sk 0600");
    }

    // Run 050: emit the trust bundle JSON.
    let generated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let bundle = build_helper_bundle(bundle_mode, &root_id_hex, &root_pk_hex, generated_at);
    let bundle_json = serde_json::to_vec_pretty(&bundle).expect("serialize trust bundle");
    let bundle_path = format!("{}/trust-bundle.json", outdir);
    fs::write(&bundle_path, &bundle_json).expect("write trust-bundle.json");

    let fp = qbind_node::pqc_trust_bundle::canonical_fingerprint(&bundle);
    let fp_hex = hex_lower(&fp);

    eprintln!(
        "[devnet_pqc_trust_bundle_helper] DEVNET-EPHEMERAL: root_id={} sig_suite={} kem_suite={} \
         validators={} bundle_mode={} bundle_fingerprint={} bundle_path={} outdir={}",
        root_id_hex,
        PQC_TRANSPORT_SUITE_ML_DSA_44,
        KEM_SUITE_ML_KEM_768,
        num_validators,
        bundle_mode_arg,
        fp_hex,
        bundle_path,
        outdir,
    );
    eprintln!(
        "[devnet_pqc_trust_bundle_helper] root_sk was held in memory only; never written to disk."
    );

    // Print the trusted-root spec on stdout for shell capture (matches
    // the Run 037 helper's contract); the bundle path is on stderr.
    println!("{}", trusted_spec);
}