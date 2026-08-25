//! Run 374: stable operator-facing **public DevNet identity-generation and
//! verification** helper.
//!
//! This example consolidates the pre-existing DevNet identity primitives
//! (`mint_devnet_root` + ML-KEM-768 leaf keygen + `issue_leaf_delegation_cert`
//! + `derive_node_id_from_pubkey` + `leaf_cert_fingerprint`) into a single,
//! documented command an external DevNet operator can run to generate,
//! inspect, and verify the identity material a `qbind-node` peer needs to join
//! a KEMTLS strict-auth (`PqcRootMode::PqcStaticRoot`) public DevNet.
//!
//! It is a **release-built example**, not a production runtime path. It adds
//! **no** production source change, **no** new CLI flag on `qbind-node`, and
//! performs **no** live deployment, admission-policy change, trust-bundle
//! apply, or wire-format change.
//!
//! ## Usage
//!
//! Generate identity material into an operator-selected output directory:
//!
//! ```text
//!   cargo run -p qbind-node --release \
//!     --example run_374_public_devnet_identity_generation_helper -- \
//!     generate <env> <role> <outdir> [validator_address]
//! ```
//!
//! - `env`   — MUST be `devnet`. Any other value (`testnet` / `mainnet` / …)
//!             is **refused** and the helper exits non-zero: this tooling is
//!             DevNet-only and creates no MainNet/TestNet custody.
//! - `role`  — one of `full-node` | `seed` | `validator-candidate`.
//! - `outdir` — operator-selected directory for the generated material. All
//!             **private** files are written here with `0600` perms (Unix);
//!             the operator is responsible for keeping this path out of any
//!             committed tree (see the identity package `SAFETY.md`).
//! - `validator_address` — optional; only meaningful for
//!             `validator-candidate`. A public identifier; recorded verbatim
//!             into the public identity JSON.
//!
//! Verify / print the public identity derivable from a generated leaf cert
//! (re-derives the NodeId + fingerprint from the cert bytes, so an operator or
//! reviewer can confirm the published values without any secret material):
//!
//! ```text
//!   cargo run -p qbind-node --release \
//!     --example run_374_public_devnet_identity_generation_helper -- \
//!     verify <leaf_cert_path>
//! ```
//!
//! ## Files written by `generate` (to `outdir`)
//!
//! | File | Public? | Content |
//! |------|---------|---------|
//! | `public-identity.json`  | **public** | Publishable identity (NodeId, fingerprints, root id/pk, trusted-root spec, suites). Also printed to stdout. |
//! | `leaf.cert.bin`         | public\*   | Encoded `NetworkDelegationCert` for `--p2p-leaf-cert`. Contains only public cert bytes. |
//! | `root.id.hex`           | public     | 64-hex root_key_id. |
//! | `root.pk.hex`           | public     | Root ML-DSA-44 public key hex. |
//! | `trusted-root.spec`     | public     | `--p2p-trusted-root` ready-to-copy line. |
//! | `leaf.kem.sk.bin`       | **PRIVATE**| ML-KEM-768 secret key for `--p2p-leaf-cert-key`. `0600`. NEVER publish. |
//!
//! \* the leaf cert is public transport material, but operators typically keep
//! the whole `outdir` private for convenience since it is co-located with the
//! secret KEM key.
//!
//! The **root signing key** (ML-DSA-44 secret) is generated fresh in memory on
//! every invocation and is **never written to disk in any form**, matching
//! `devnet_pqc_root_helper`. A production CA / custody / rotation / revocation
//! flow is out of scope and tracked under **C4/C5** in
//! `docs/whitepaper/contradiction.md`.

use std::fs;
use std::path::Path;
use std::process::exit;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use qbind_crypto::{MlKem768Backend, KEM_SUITE_ML_KEM_768};
use qbind_net::handshake::leaf_cert_fingerprint;
use qbind_node::pqc_devnet_helper::{
    encode_cert, issue_leaf_delegation_cert, mint_devnet_root, LeafCertSpec,
};
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_wire::io::WireDecode;
use qbind_wire::net::NetworkDelegationCert;

/// Public identity JSON schema version emitted by this helper. Kept in lockstep
/// with `docs/release/public-devnet/identity/OPERATOR_IDENTITY_SCHEMA.json`.
const IDENTITY_SCHEMA_VERSION: &str = "1";

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Stable per-index validator_id label bytes (public, deterministic). Mirrors the
/// deployed node's `validator_id_bytes_for_index` convention
/// (`crates/qbind-node/src/p2p_node_builder.rs`) so a generated leaf cert loads
/// directly as the node's own local leaf credential under `--validator-id <index>`
/// and lines up with the existing `devnet_pqc_root_helper` DevNet fixtures.
fn validator_id_bytes_for_index(index: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    let s = format!("qbind-val-{}", index);
    let n = s.len().min(32);
    b[..n].copy_from_slice(&s.as_bytes()[..n]);
    b
}

fn usage_and_exit() -> ! {
    eprintln!(
        "usage:\n  \
         run_374_public_devnet_identity_generation_helper generate <env> <role> <outdir> [validator_index]\n  \
         run_374_public_devnet_identity_generation_helper verify <leaf_cert_path>\n\n\
         env             : must be `devnet` (MainNet/TestNet are refused; DevNet-only tooling)\n\
         role            : full-node | seed | validator-candidate\n\
         validator_index : optional u64 (default 0); binds the leaf cert validator_id to\n\
         \x20                 `qbind-val-<index>` so the material loads under `--validator-id <index>`"
    );
    exit(2);
}

/// Minimal JSON string escaper (public identity fields are hex / short ASCII
/// labels; this keeps the helper dependency-free while staying correct).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Build the public identity JSON document. Contains **only** public material:
/// NodeId, fingerprints, root id/pk, suite ids, and the ready-to-copy
/// `--p2p-trusted-root` spec. It records the *paths* of private files but never
/// their contents.
#[allow(clippy::too_many_arguments)]
fn public_identity_json(
    role: &str,
    node_id_hex: &str,
    node_id_short: &str,
    leaf_fp_hex: &str,
    leaf_fp_short: &str,
    root_id_hex: &str,
    root_pk_fp_short: &str,
    trusted_root_spec: &str,
    validator_address: Option<&str>,
    leaf_cert_path: &str,
    leaf_kem_sk_path: &str,
) -> String {
    let validator_address_json = match validator_address {
        Some(a) => format!("\"{}\"", json_escape(a)),
        None => "null".to_string(),
    };
    format!(
        "{{\n  \
         \"schema_version\": \"{schema}\",\n  \
         \"environment\": \"devnet\",\n  \
         \"role\": \"{role}\",\n  \
         \"suite\": {{\n    \
         \"sig_suite_id\": {sig},\n    \
         \"sig_suite\": \"ml-dsa-44\",\n    \
         \"kem_suite_id\": {kem},\n    \
         \"kem_suite\": \"ml-kem-768\"\n  \
         }},\n  \
         \"node_id\": \"{node_id}\",\n  \
         \"node_id_short\": \"{node_id_short}\",\n  \
         \"peer_id\": \"{node_id}\",\n  \
         \"leaf_cert_fingerprint\": \"{leaf_fp}\",\n  \
         \"leaf_cert_fingerprint_short\": \"{leaf_fp_short}\",\n  \
         \"root_key_id\": \"{root_id}\",\n  \
         \"root_pk_fingerprint\": \"{root_pk_fp}\",\n  \
         \"trusted_root_spec\": \"{spec}\",\n  \
         \"validator_address\": {validator_address},\n  \
         \"transport_security_mode\": \"kemtls-mutual-auth-required\",\n  \
         \"pqc_suite\": \"ml-dsa-44\",\n  \
         \"private_material\": {{\n    \
         \"leaf_cert_path\": \"{leaf_cert_path}\",\n    \
         \"leaf_kem_sk_path\": \"{leaf_kem_sk_path}\",\n    \
         \"note\": \"leaf_kem_sk and the root signing key are SECRET and must NEVER be published; this block records paths only, not contents\"\n  \
         }},\n  \
         \"safety_label\": {{\n    \
         \"experimental\": true,\n    \
         \"resettable\": true,\n    \
         \"no_value\": true,\n    \
         \"no_mainnet_readiness_claim\": true,\n    \
         \"no_c4_c5_closure_claim\": true\n  \
         }},\n  \
         \"devnet_only\": true\n\
         }}\n",
        schema = IDENTITY_SCHEMA_VERSION,
        role = json_escape(role),
        sig = PQC_TRANSPORT_SUITE_ML_DSA_44,
        kem = KEM_SUITE_ML_KEM_768,
        node_id = node_id_hex,
        node_id_short = node_id_short,
        leaf_fp = leaf_fp_hex,
        leaf_fp_short = leaf_fp_short,
        root_id = root_id_hex,
        root_pk_fp = root_pk_fp_short,
        spec = json_escape(trusted_root_spec),
        validator_address = validator_address_json,
        leaf_cert_path = json_escape(leaf_cert_path),
        leaf_kem_sk_path = json_escape(leaf_kem_sk_path),
    )
}

fn cmd_generate(mut args: impl Iterator<Item = String>) {
    let env = args.next().unwrap_or_else(|| usage_and_exit());
    let role = args.next().unwrap_or_else(|| usage_and_exit());
    let outdir = args.next().unwrap_or_else(|| usage_and_exit());
    let validator_index: u64 = match args.next() {
        Some(s) => s.parse().unwrap_or_else(|_| {
            eprintln!("[run_374_identity_helper] REFUSED: validator_index must be a u64.");
            exit(3);
        }),
        None => 0,
    };

    // Fail closed on any non-DevNet environment. This tooling creates no
    // MainNet/TestNet custody and refuses to generate under those labels.
    if env != "devnet" {
        eprintln!(
            "[run_374_identity_helper] REFUSED: env `{}` is unsupported. This helper is DevNet-only \
             and creates no MainNet/TestNet identity or custody. Re-run with env `devnet`.",
            env
        );
        exit(3);
    }

    match role.as_str() {
        "full-node" | "seed" | "validator-candidate" => {}
        other => {
            eprintln!(
                "[run_374_identity_helper] REFUSED: unknown role `{}` (expected \
                 full-node | seed | validator-candidate).",
                other
            );
            exit(3);
        }
    }

    // `validator_address` is only meaningful for a validator candidate. On
    // DevNet it is the public fixture validator label bound into the leaf cert.
    let validator_address: Option<String> = if role == "validator-candidate" {
        Some(format!("qbind-val-{}", validator_index))
    } else {
        None
    };

    fs::create_dir_all(&outdir).expect("mkdir outdir");

    // 1. Mint a fresh DevNet root (ML-DSA-44). DevNet-ephemeral: the root
    //    signing key stays in memory and is never written to disk.
    let root = mint_devnet_root().expect("root keygen");
    let root_id_hex = hex_lower(&root.root_key_id);
    let root_pk_hex = hex_lower(&root.root_pk);
    let root_pk_fp_short = {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(&root.root_pk);
        hex_lower(&h.finalize()[..4])
    };

    // 2. Generate an ML-KEM-768 leaf keypair for this identity.
    let (kem_pk, kem_sk) = MlKem768Backend::generate_keypair().expect("ML-KEM-768 keygen");

    // 3. Issue a currently-valid leaf delegation cert signed by the root.
    let spec = LeafCertSpec::currently_valid(
        validator_id_bytes_for_index(validator_index),
        root.root_key_id,
        kem_pk.clone(),
    );
    let cert = issue_leaf_delegation_cert(&spec, &root.root_sk).expect("issue leaf cert");
    let cert_bytes = encode_cert(&cert);

    // 4. Derive the NodeId deterministically from the certified leaf ML-KEM-768
    //    public key — the exact value a deployed `PqcStaticRoot` listener
    //    registers an admitted peer under.
    let node_id = qbind_hash::derive_node_id_from_pubkey(&cert.leaf_kem_pk);
    let node_id_hex = hex_lower(&node_id);
    let node_id_short = hex_lower(&node_id[..8]);

    // 5. Compute the leaf cert fingerprint (SHA3-256 of canonical cert bytes).
    let leaf_fp = leaf_cert_fingerprint(&cert);
    let leaf_fp_hex = hex_lower(&leaf_fp);
    let leaf_fp_short = hex_lower(&leaf_fp[..4]);

    // 6. Write public material.
    let leaf_cert_path = format!("{}/leaf.cert.bin", outdir);
    let leaf_kem_sk_path = format!("{}/leaf.kem.sk.bin", outdir);
    let trusted_root_spec = format!(
        "{}:{}:{}",
        root_id_hex, PQC_TRANSPORT_SUITE_ML_DSA_44, root_pk_hex
    );

    fs::write(&leaf_cert_path, &cert_bytes).expect("write leaf cert");
    fs::write(format!("{}/root.id.hex", outdir), &root_id_hex).expect("write root.id.hex");
    fs::write(format!("{}/root.pk.hex", outdir), &root_pk_hex).expect("write root.pk.hex");
    fs::write(format!("{}/trusted-root.spec", outdir), &trusted_root_spec)
        .expect("write trusted-root.spec");

    // 7. Write the PRIVATE KEM secret key with 0600 perms (Unix). Never logged.
    fs::write(&leaf_kem_sk_path, &kem_sk).expect("write kem sk");
    #[cfg(unix)]
    fs::set_permissions(&leaf_kem_sk_path, fs::Permissions::from_mode(0o600))
        .expect("chmod kem sk 0600");

    // 8. Emit the public identity JSON (file + stdout).
    let json = public_identity_json(
        &role,
        &node_id_hex,
        &node_id_short,
        &leaf_fp_hex,
        &leaf_fp_short,
        &root_id_hex,
        &root_pk_fp_short,
        &trusted_root_spec,
        validator_address.as_deref(),
        &leaf_cert_path,
        &leaf_kem_sk_path,
    );
    let identity_path = format!("{}/public-identity.json", outdir);
    fs::write(&identity_path, &json).expect("write public-identity.json");

    eprintln!(
        "[run_374_identity_helper] DEVNET-EPHEMERAL: role={} validator_index={} node_id={} leaf_fp={} root_id={} \
         root_pk_fp={} sig_suite={} kem_suite={} outdir={}",
        role,
        validator_index,
        node_id_short,
        leaf_fp_short,
        root_id_hex,
        root_pk_fp_short,
        PQC_TRANSPORT_SUITE_ML_DSA_44,
        KEM_SUITE_ML_KEM_768,
        outdir
    );
    eprintln!(
        "[run_374_identity_helper] root signing key was held in memory only; never written to disk."
    );
    eprintln!(
        "[run_374_identity_helper] PRIVATE: {} (ML-KEM-768 secret key) — NEVER publish or commit.",
        leaf_kem_sk_path
    );

    // Public identity JSON on stdout so callers can capture it directly.
    print!("{}", json);
}

fn cmd_verify(mut args: impl Iterator<Item = String>) {
    let cert_path = args.next().unwrap_or_else(|| usage_and_exit());
    let bytes = fs::read(Path::new(&cert_path)).expect("read leaf cert file");
    let mut slice: &[u8] = &bytes;
    let cert = NetworkDelegationCert::decode(&mut slice).expect("decode leaf cert");

    // Re-derive the public identity from the cert bytes only — no secret
    // material is touched, so this is safe for reviewers to run on published
    // public material.
    let node_id = qbind_hash::derive_node_id_from_pubkey(&cert.leaf_kem_pk);
    let node_id_hex = hex_lower(&node_id);
    let node_id_short = hex_lower(&node_id[..8]);
    let leaf_fp = leaf_cert_fingerprint(&cert);
    let leaf_fp_hex = hex_lower(&leaf_fp);
    let leaf_fp_short = hex_lower(&leaf_fp[..4]);
    let root_id_hex = hex_lower(&cert.root_key_id);

    eprintln!(
        "[run_374_identity_helper] verify: cert={} node_id={} leaf_fp={} root_id={} kem_suite={}",
        cert_path, node_id_short, leaf_fp_short, root_id_hex, cert.leaf_kem_suite_id
    );

    // Print machine-readable derived public values on stdout.
    print!(
        "{{\n  \
         \"node_id\": \"{}\",\n  \
         \"node_id_short\": \"{}\",\n  \
         \"leaf_cert_fingerprint\": \"{}\",\n  \
         \"leaf_cert_fingerprint_short\": \"{}\",\n  \
         \"root_key_id\": \"{}\"\n\
         }}\n",
        node_id_hex, node_id_short, leaf_fp_hex, leaf_fp_short, root_id_hex
    );
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_else(|| usage_and_exit());
    match mode.as_str() {
        "generate" => cmd_generate(args),
        "verify" => cmd_verify(args),
        other => {
            eprintln!("[run_374_identity_helper] unknown mode `{}`", other);
            usage_and_exit();
        }
    }
}