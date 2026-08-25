//! Run 375: first-class `qbind-node identity` command surface.
//!
//! This module promotes the Run 374 operator-facing DevNet identity-generation
//! and verification workflow into a stable, first-class `qbind-node identity`
//! subcommand, **without** changing any default runtime behavior. It reuses the
//! exact pre-existing DevNet primitives Run 374 consolidated
//! (`mint_devnet_root` + ML-KEM-768 leaf keygen + `issue_leaf_delegation_cert`
//! + `derive_node_id_from_pubkey` + `leaf_cert_fingerprint`) and emits the same
//! files, the same schema-compatible public identity JSON, and the same safety
//! rules as the Run 374 helper — so Run 374 evidence stays reproducible while
//! operators gain a first-class command surface.
//!
//! ## Scope / safety (Route B — minimal first-class CLI addition)
//!
//! - **DevNet only.** `identity generate` refuses any environment other than
//!   `devnet` (MainNet/TestNet are fail-closed; no custody is created).
//! - **No new network behavior.** These subcommands never open a socket, never
//!   register a peer, never mutate trust/validator/epoch/sequence state, never
//!   change the P2P wire format, and never weaken peer admission. They are pure
//!   local key/cert generation + verification utilities.
//! - **No default behavior change.** The `identity` command is only reached when
//!   `identity` is the first CLI token; a normal `qbind-node …` invocation is
//!   completely unaffected.
//! - **Public vs private material.** The ML-KEM-768 secret key is written `0600`
//!   (Unix) to an operator-selected output directory only; the root ML-DSA-44
//!   signing key is held in memory and **never** written to disk. The public
//!   identity JSON records private-file *paths only*, never contents.
//!
//! ## Command surface
//!
//! ```text
//!   qbind-node identity generate <env> <role> <outdir> [validator_index]
//!   qbind-node identity verify <leaf_cert_path>
//!   qbind-node identity print-public <identity_dir>
//!   qbind-node identity seed-candidate <identity_dir>
//! ```
//!
//! `dispatch` returns a process exit code (`0` success, `2` usage, `3` refused /
//! bad input, `1` I/O failure) and never panics on operator-controlled input, so
//! invalid output paths fail safely.

use std::fs;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use qbind_crypto::{MlKem768Backend, KEM_SUITE_ML_KEM_768};
use qbind_net::handshake::leaf_cert_fingerprint;
use qbind_wire::io::WireDecode;
use qbind_wire::net::NetworkDelegationCert;

use crate::pqc_devnet_helper::{
    encode_cert, issue_leaf_delegation_cert, mint_devnet_root, LeafCertSpec,
};
use crate::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;

/// Public identity JSON schema version emitted by this command. Kept in lockstep
/// with `docs/release/public-devnet/identity/OPERATOR_IDENTITY_SCHEMA.json` and
/// the Run 374 helper.
pub const IDENTITY_SCHEMA_VERSION: &str = "1";

/// Exit code: usage error (missing / malformed subcommand or arguments).
const EXIT_USAGE: i32 = 2;
/// Exit code: fail-closed refusal (non-DevNet env, unknown role, bad index).
const EXIT_REFUSED: i32 = 3;
/// Exit code: I/O failure (invalid output path, unreadable cert, etc.).
const EXIT_IO: i32 = 1;

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
/// directly as the node's own local leaf credential under `--validator-id <index>`.
fn validator_id_bytes_for_index(index: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    let s = format!("qbind-val-{}", index);
    let n = s.len().min(32);
    b[..n].copy_from_slice(&s.as_bytes()[..n]);
    b
}

/// Minimal JSON string escaper (public identity fields are hex / short ASCII
/// labels; this keeps the command dependency-free while staying correct).
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

fn usage() -> i32 {
    eprintln!(
        "usage:\n  \
         qbind-node identity generate <env> <role> <outdir> [validator_index]\n  \
         qbind-node identity verify <leaf_cert_path>\n  \
         qbind-node identity print-public <identity_dir>\n  \
         qbind-node identity seed-candidate <identity_dir>\n\n\
         env             : must be `devnet` (MainNet/TestNet are refused; DevNet-only tooling)\n\
         role            : full-node | seed | validator-candidate\n\
         validator_index : optional u64 (default 0); binds the leaf cert validator_id to\n\
         \x20                 `qbind-val-<index>` so the material loads under `--validator-id <index>`"
    );
    EXIT_USAGE
}

/// Build the public identity JSON document. Contains **only** public material:
/// NodeId, fingerprints, root id/pk, suite ids, and the ready-to-copy
/// `--p2p-trusted-root` spec. It records the *paths* of private files but never
/// their contents. This is byte-compatible with the Run 374 helper output.
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

fn cmd_generate(mut args: impl Iterator<Item = String>) -> i32 {
    let env = match args.next() {
        Some(v) => v,
        None => return usage(),
    };
    let role = match args.next() {
        Some(v) => v,
        None => return usage(),
    };
    let outdir = match args.next() {
        Some(v) => v,
        None => return usage(),
    };
    let validator_index: u64 = match args.next() {
        Some(s) => match s.parse() {
            Ok(v) => v,
            Err(_) => {
                eprintln!("[qbind-node identity] REFUSED: validator_index must be a u64.");
                return EXIT_REFUSED;
            }
        },
        None => 0,
    };

    // Fail closed on any non-DevNet environment. This command creates no
    // MainNet/TestNet custody and refuses to generate under those labels.
    if env != "devnet" {
        eprintln!(
            "[qbind-node identity] REFUSED: env `{}` is unsupported. This command is DevNet-only \
             and creates no MainNet/TestNet identity or custody. Re-run with env `devnet`.",
            env
        );
        return EXIT_REFUSED;
    }

    match role.as_str() {
        "full-node" | "seed" | "validator-candidate" => {}
        other => {
            eprintln!(
                "[qbind-node identity] REFUSED: unknown role `{}` (expected \
                 full-node | seed | validator-candidate).",
                other
            );
            return EXIT_REFUSED;
        }
    }

    // `validator_address` is only meaningful for a validator candidate. On
    // DevNet it is the public fixture validator label bound into the leaf cert.
    let validator_address: Option<String> = if role == "validator-candidate" {
        Some(format!("qbind-val-{}", validator_index))
    } else {
        None
    };

    // Invalid output path fails safely (no panic, non-zero exit).
    if let Err(e) = fs::create_dir_all(&outdir) {
        eprintln!(
            "[qbind-node identity] ERROR: could not create output directory `{}`: {}",
            outdir, e
        );
        return EXIT_IO;
    }

    // 1. Mint a fresh DevNet root (ML-DSA-44). DevNet-ephemeral: the root
    //    signing key stays in memory and is never written to disk.
    let root = match mint_devnet_root() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[qbind-node identity] ERROR: root keygen failed: {}", e);
            return EXIT_IO;
        }
    };
    let root_id_hex = hex_lower(&root.root_key_id);
    let root_pk_hex = hex_lower(&root.root_pk);
    let root_pk_fp_short = {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(&root.root_pk);
        hex_lower(&h.finalize()[..4])
    };

    // 2. Generate an ML-KEM-768 leaf keypair for this identity.
    let (kem_pk, kem_sk) = match MlKem768Backend::generate_keypair() {
        Ok(kp) => kp,
        Err(e) => {
            eprintln!("[qbind-node identity] ERROR: ML-KEM-768 keygen failed: {:?}", e);
            return EXIT_IO;
        }
    };

    // 3. Issue a currently-valid leaf delegation cert signed by the root.
    let spec = LeafCertSpec::currently_valid(
        validator_id_bytes_for_index(validator_index),
        root.root_key_id,
        kem_pk.clone(),
    );
    let cert = match issue_leaf_delegation_cert(&spec, &root.root_sk) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[qbind-node identity] ERROR: issue leaf cert failed: {:?}", e);
            return EXIT_IO;
        }
    };
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

    macro_rules! write_or_fail {
        ($path:expr, $data:expr, $what:expr) => {
            if let Err(e) = fs::write($path, $data) {
                eprintln!(
                    "[qbind-node identity] ERROR: could not write {} (`{}`): {}",
                    $what, $path, e
                );
                return EXIT_IO;
            }
        };
    }

    write_or_fail!(&leaf_cert_path, &cert_bytes, "leaf cert");
    write_or_fail!(
        &format!("{}/root.id.hex", outdir),
        &root_id_hex,
        "root.id.hex"
    );
    write_or_fail!(
        &format!("{}/root.pk.hex", outdir),
        &root_pk_hex,
        "root.pk.hex"
    );
    write_or_fail!(
        &format!("{}/trusted-root.spec", outdir),
        &trusted_root_spec,
        "trusted-root.spec"
    );

    // 7. Write the PRIVATE KEM secret key with 0600 perms (Unix). Never logged.
    write_or_fail!(&leaf_kem_sk_path, &kem_sk, "kem secret key");
    #[cfg(unix)]
    if let Err(e) = fs::set_permissions(&leaf_kem_sk_path, fs::Permissions::from_mode(0o600)) {
        eprintln!(
            "[qbind-node identity] ERROR: could not chmod 0600 `{}`: {}",
            leaf_kem_sk_path, e
        );
        return EXIT_IO;
    }

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
    write_or_fail!(&identity_path, &json, "public-identity.json");

    eprintln!(
        "[qbind-node identity] DEVNET-EPHEMERAL: role={} validator_index={} node_id={} leaf_fp={} root_id={} \
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
        "[qbind-node identity] root signing key was held in memory only; never written to disk."
    );
    eprintln!(
        "[qbind-node identity] PRIVATE: {} (ML-KEM-768 secret key) — NEVER publish or commit.",
        leaf_kem_sk_path
    );

    // Public identity JSON on stdout so callers can capture it directly.
    print!("{}", json);
    0
}

fn cmd_verify(mut args: impl Iterator<Item = String>) -> i32 {
    let cert_path = match args.next() {
        Some(v) => v,
        None => return usage(),
    };
    let bytes = match fs::read(Path::new(&cert_path)) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "[qbind-node identity] ERROR: could not read leaf cert `{}`: {}",
                cert_path, e
            );
            return EXIT_IO;
        }
    };
    let mut slice: &[u8] = &bytes;
    let cert = match NetworkDelegationCert::decode(&mut slice) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "[qbind-node identity] REFUSED: could not decode leaf cert `{}`: {:?}",
                cert_path, e
            );
            return EXIT_REFUSED;
        }
    };

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
        "[qbind-node identity] verify: cert={} node_id={} leaf_fp={} root_id={} kem_suite={}",
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
    0
}

/// `print-public <identity_dir>` — re-print the generated public identity JSON
/// document from an existing identity directory. Reads only `public-identity.json`
/// (public material); never touches the secret key.
fn cmd_print_public(mut args: impl Iterator<Item = String>) -> i32 {
    let dir = match args.next() {
        Some(v) => v,
        None => return usage(),
    };
    let path = format!("{}/public-identity.json", dir);
    match fs::read_to_string(&path) {
        Ok(s) => {
            print!("{}", s);
            0
        }
        Err(e) => {
            eprintln!(
                "[qbind-node identity] ERROR: could not read `{}`: {}",
                path, e
            );
            EXIT_IO
        }
    }
}

/// `seed-candidate <identity_dir>` — emit a Run 357 seed-list `seed_node`
/// candidate object (planned, no reachability claim) derived from the generated
/// public identity, so an operator can paste it into a `devnet-seeds` document.
/// Endpoint fields are documented placeholders the operator must replace; this
/// command makes **no** live/reachability claim.
fn cmd_seed_candidate(mut args: impl Iterator<Item = String>) -> i32 {
    let dir = match args.next() {
        Some(v) => v,
        None => return usage(),
    };
    let path = format!("{}/public-identity.json", dir);
    let raw = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[qbind-node identity] ERROR: could not read `{}`: {}",
                path, e
            );
            return EXIT_IO;
        }
    };

    // Minimal, dependency-free extraction of the public fields we map into the
    // seed-list candidate. All values are public and already schema-validated by
    // `generate`; we only need the string values here.
    let node_id = json_string_field(&raw, "node_id");
    let peer_id = json_string_field(&raw, "peer_id");
    let transport = json_string_field(&raw, "transport_security_mode");
    let pqc_suite = json_string_field(&raw, "pqc_suite");
    let validator_address = json_value_field(&raw, "validator_address");

    match (node_id, peer_id, transport, pqc_suite, validator_address) {
        (Some(node_id), Some(peer_id), Some(transport), Some(pqc_suite), Some(validator_address)) => {
            // status=planned, last_reachability_evidence=null — no live claim.
            print!(
                "{{\n  \
                 \"node_id\": \"{node_id}\",\n  \
                 \"peer_id\": \"{peer_id}\",\n  \
                 \"validator_address\": {validator_address},\n  \
                 \"p2p_host\": \"REPLACE_WITH_OPERATOR_HOST\",\n  \
                 \"p2p_port\": 30333,\n  \
                 \"p2p_multiaddr\": \"REPLACE_WITH_OPERATOR_HOST:30333\",\n  \
                 \"transport_security_mode\": \"{transport}\",\n  \
                 \"pqc_suite\": \"{pqc_suite}\",\n  \
                 \"trust_bundle_required\": false,\n  \
                 \"expected_genesis_hash\": \"0x0000000000000000000000000000000000000000000000000000000000000000\",\n  \
                 \"operator\": \"REPLACE_WITH_OPERATOR\",\n  \
                 \"status\": \"planned\",\n  \
                 \"last_reachability_evidence\": null,\n  \
                 \"notes\": \"Run 375 generated candidate; not live. Replace p2p_host/p2p_multiaddr/operator/expected_genesis_hash with real DevNet values before use.\"\n\
                 }}\n",
                node_id = node_id,
                peer_id = peer_id,
                validator_address = validator_address,
                transport = transport,
                pqc_suite = pqc_suite,
            );
            0
        }
        _ => {
            eprintln!(
                "[qbind-node identity] ERROR: `{}` is missing required public identity fields.",
                path
            );
            EXIT_IO
        }
    }
}

/// Extract a top-level `"key": "value"` string field from the identity JSON
/// (which this module emits in a fixed, well-formed layout). Returns the raw
/// inner string (already JSON-escaped as emitted).
fn json_string_field(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\":", key);
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    let q1 = rest.find('"')? + 1;
    let after = &rest[q1..];
    let q2 = after.find('"')?;
    Some(after[..q2].to_string())
}

/// Extract a top-level field value verbatim (string with quotes, or `null`),
/// used for `validator_address` which may be `null` for full-node/seed roles.
fn json_value_field(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\":", key);
    let start = json.find(&needle)? + needle.len();
    let rest = json[start..].trim_start();
    if let Some(stripped) = rest.strip_prefix("null") {
        let _ = stripped;
        return Some("null".to_string());
    }
    if rest.starts_with('"') {
        let after = &rest[1..];
        let q2 = after.find('"')?;
        return Some(format!("\"{}\"", &after[..q2]));
    }
    None
}

/// Dispatch the `identity` subcommand. `args` MUST be the tokens **after** the
/// `identity` keyword (i.e. the subcommand and its arguments). Returns a process
/// exit code; never panics on operator-controlled input.
pub fn dispatch(mut args: impl Iterator<Item = String>) -> i32 {
    let sub = match args.next() {
        Some(v) => v,
        None => return usage(),
    };
    match sub.as_str() {
        "generate" => cmd_generate(args),
        "verify" => cmd_verify(args),
        "print-public" => cmd_print_public(args),
        "seed-candidate" => cmd_seed_candidate(args),
        "-h" | "--help" | "help" => {
            usage();
            0
        }
        other => {
            eprintln!("[qbind-node identity] unknown subcommand `{}`", other);
            usage()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_string_field_extracts_node_id() {
        let json = public_identity_json(
            "full-node",
            "aa",
            "bb",
            "cc",
            "dd",
            "ee",
            "ff",
            "rid:100:pk",
            None,
            "/tmp/x/leaf.cert.bin",
            "/tmp/x/leaf.kem.sk.bin",
        );
        assert_eq!(json_string_field(&json, "node_id").as_deref(), Some("aa"));
        assert_eq!(json_value_field(&json, "validator_address").as_deref(), Some("null"));
    }

    #[test]
    fn json_value_field_reads_validator_address() {
        let json = public_identity_json(
            "validator-candidate",
            "aa",
            "bb",
            "cc",
            "dd",
            "ee",
            "ff",
            "rid:100:pk",
            Some("qbind-val-3"),
            "/tmp/x/leaf.cert.bin",
            "/tmp/x/leaf.kem.sk.bin",
        );
        assert_eq!(
            json_value_field(&json, "validator_address").as_deref(),
            Some("\"qbind-val-3\"")
        );
    }

    #[test]
    fn unknown_env_is_refused() {
        let args = vec![
            "mainnet".to_string(),
            "full-node".to_string(),
            "/tmp/should-not-exist-run375".to_string(),
        ];
        assert_eq!(cmd_generate(args.into_iter()), EXIT_REFUSED);
        assert!(!std::path::Path::new("/tmp/should-not-exist-run375").exists());
    }

    #[test]
    fn unknown_role_is_refused() {
        let args = vec![
            "devnet".to_string(),
            "bogus-role".to_string(),
            "/tmp/should-not-exist-run375-role".to_string(),
        ];
        assert_eq!(cmd_generate(args.into_iter()), EXIT_REFUSED);
    }
}