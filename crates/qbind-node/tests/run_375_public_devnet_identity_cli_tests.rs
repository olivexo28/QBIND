//! Run 375 — first-class `qbind-node identity` command tests.
//!
//! These tests drive the real `qbind-node` release/debug binary (via
//! `CARGO_BIN_EXE_qbind-node`) through the first-class `identity` subcommand and
//! assert the Run 374 identity contract is preserved on the new command surface:
//! generation for all three DevNet roles, the exact output file set, a
//! schema-compatible `public-identity.json` (structurally validated here; full
//! JSON-Schema validation lives in the Run 375 harness), a `0600` KEM secret
//! key, no root signing key on disk, deterministic NodeId re-derivation via
//! `verify`, seed-list candidate mapping, and every fail-closed refusal
//! (MainNet/TestNet, unknown role, mismatched validator index, invalid output
//! path). No private material appears in any public output.
//!
//! Scope guard: these tests exercise a **local key/cert generation + verification
//! utility only**. They open no socket, register no peer, mutate no
//! trust/validator/epoch/sequence/marker state, change no P2P wire format, and
//! weaken no peer admission. Loopback strict-auth boot is covered by
//! `scripts/devnet/run_375_public_devnet_identity_cli.sh`.

use std::path::{Path, PathBuf};
use std::process::Command;

fn qbind_node_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_qbind-node"))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "qbind-run375-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&p).expect("create temp dir");
    p
}

struct Output {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_identity(args: &[&str]) -> Output {
    let out = Command::new(qbind_node_bin())
        .arg("identity")
        .args(args)
        .output()
        .expect("spawn qbind-node identity");
    Output {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

/// Generate into `dir` and return the parsed public-identity JSON string.
fn generate(role: &str, dir: &Path, extra: Option<&str>) -> Output {
    let dir_s = dir.to_str().unwrap();
    let mut args = vec!["generate", "devnet", role, dir_s];
    if let Some(e) = extra {
        args.push(e);
    }
    run_identity(&args)
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("read {}: {}", p.display(), e))
}

fn json_str<'a>(json: &'a serde_json::Value, key: &str) -> &'a str {
    json.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("missing string field `{}`", key))
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

// ---------------------------------------------------------------------------
// 1-4. generate for each role succeeds and emits the Run 374 file set.
// ---------------------------------------------------------------------------

fn assert_file_set(dir: &Path) {
    for f in [
        "public-identity.json",
        "leaf.cert.bin",
        "root.id.hex",
        "root.pk.hex",
        "trusted-root.spec",
        "leaf.kem.sk.bin",
    ] {
        assert!(dir.join(f).is_file(), "missing generated file: {}", f);
    }
    // 7. root signing key MUST NOT be written to disk in any form.
    for forbidden in ["root.sk", "root.sk.hex", "root.sk.bin", "root.key"] {
        assert!(
            !dir.join(forbidden).exists(),
            "root signing key file must not exist: {}",
            forbidden
        );
    }
}

#[test]
fn generate_full_node_seed_validator_candidate_succeed_with_run374_file_set() {
    let base = tmpdir("fileset");
    for role in ["full-node", "seed"] {
        let dir = base.join(role);
        let out = generate(role, &dir, None);
        assert_eq!(out.code, 0, "generate {role} failed: {}", out.stderr);
        assert_file_set(&dir);
    }
    // validator-candidate with explicit index.
    let vc = base.join("validator-candidate");
    let out = generate("validator-candidate", &vc, Some("2"));
    assert_eq!(out.code, 0, "generate validator-candidate failed: {}", out.stderr);
    assert_file_set(&vc);
}

// ---------------------------------------------------------------------------
// 5 / 16. public-identity.json is schema-shaped and carries only public material.
// ---------------------------------------------------------------------------

#[test]
fn public_identity_json_is_schema_shaped_and_public_only() {
    let dir = tmpdir("schema").join("full-node");
    let out = generate("full-node", &dir, None);
    assert_eq!(out.code, 0, "{}", out.stderr);

    let json: serde_json::Value =
        serde_json::from_str(&read(&dir.join("public-identity.json"))).expect("valid JSON");

    // Required top-level fields / enums (subset of OPERATOR_IDENTITY_SCHEMA.json).
    assert_eq!(json_str(&json, "schema_version"), "1");
    assert_eq!(json_str(&json, "environment"), "devnet");
    assert_eq!(json_str(&json, "role"), "full-node");
    assert!(is_hex(json_str(&json, "node_id"), 64));
    assert!(is_hex(json_str(&json, "node_id_short"), 16));
    assert!(is_hex(json_str(&json, "peer_id"), 64));
    assert_eq!(json_str(&json, "node_id"), json_str(&json, "peer_id"));
    assert!(is_hex(json_str(&json, "leaf_cert_fingerprint"), 64));
    assert!(is_hex(json_str(&json, "leaf_cert_fingerprint_short"), 8));
    assert!(is_hex(json_str(&json, "root_key_id"), 64));
    assert!(is_hex(json_str(&json, "root_pk_fingerprint"), 8));
    assert!(json.get("validator_address").expect("field").is_null());
    assert_eq!(json.get("devnet_only").and_then(|v| v.as_bool()), Some(true));

    let sl = json.get("safety_label").expect("safety_label");
    for flag in [
        "experimental",
        "resettable",
        "no_value",
        "no_mainnet_readiness_claim",
        "no_c4_c5_closure_claim",
    ] {
        assert_eq!(sl.get(flag).and_then(|v| v.as_bool()), Some(true), "{flag}");
    }

    // trusted_root_spec matches "<64hex>:<int>:<hex>".
    let spec = json_str(&json, "trusted_root_spec");
    let parts: Vec<&str> = spec.split(':').collect();
    assert_eq!(parts.len(), 3, "trusted_root_spec shape");
    assert!(is_hex(parts[0], 64));
    assert!(parts[1].bytes().all(|b| b.is_ascii_digit()));
    assert!(is_hex(parts[2], parts[2].len()) && !parts[2].is_empty());

    // 16. No private/secret material in the public JSON. private_material records
    // PATHS only; the raw string must not contain any secret-key bytes/labels.
    let raw = read(&dir.join("public-identity.json"));
    let lower = raw.to_lowercase();
    assert!(
        !lower.contains("secret_key") && !lower.contains("private_key") && !lower.contains("mnemonic"),
        "public JSON leaked a secret label"
    );
    // The KEM secret key bytes are never embedded (only a *_path reference).
    let sk_bytes = std::fs::read(dir.join("leaf.kem.sk.bin")).expect("read sk");
    let sk_prefix_hex: String = sk_bytes
        .iter()
        .take(16)
        .map(|b| format!("{:02x}", b))
        .collect();
    assert!(
        !raw.contains(&sk_prefix_hex),
        "public JSON contained KEM secret key bytes"
    );
}

// ---------------------------------------------------------------------------
// 6. private KEM key is mode 0600 on Unix.
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn kem_secret_key_is_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmpdir("perms").join("seed");
    let out = generate("seed", &dir, None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let mode = std::fs::metadata(dir.join("leaf.kem.sk.bin"))
        .expect("stat sk")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "leaf.kem.sk.bin perms = {:o}", mode);
}

// ---------------------------------------------------------------------------
// 8. verify re-derives the same NodeId from public cert bytes (deterministic).
// ---------------------------------------------------------------------------

#[test]
fn verify_rederives_same_node_id_for_all_roles() {
    let base = tmpdir("verify");
    for (role, extra) in [
        ("full-node", None),
        ("seed", None),
        ("validator-candidate", Some("0")),
    ] {
        let dir = base.join(role);
        let g = generate(role, &dir, extra);
        assert_eq!(g.code, 0, "{}", g.stderr);
        let gen: serde_json::Value =
            serde_json::from_str(&read(&dir.join("public-identity.json"))).unwrap();

        let v = run_identity(&["verify", dir.join("leaf.cert.bin").to_str().unwrap()]);
        assert_eq!(v.code, 0, "verify failed: {}", v.stderr);
        let ver: serde_json::Value = serde_json::from_str(&v.stdout).expect("verify stdout JSON");

        assert_eq!(json_str(&gen, "node_id"), json_str(&ver, "node_id"));
        assert_eq!(
            json_str(&gen, "leaf_cert_fingerprint"),
            json_str(&ver, "leaf_cert_fingerprint")
        );
        assert_eq!(json_str(&gen, "root_key_id"), json_str(&ver, "root_key_id"));
    }
}

// ---------------------------------------------------------------------------
// 9. generated identity maps into a seed-list candidate without schema violation
//    (structural check here; full JSON-Schema validation in the harness).
// ---------------------------------------------------------------------------

#[test]
fn seed_candidate_maps_public_identity_without_live_claim() {
    let dir = tmpdir("seedcand").join("seed");
    let g = generate("seed", &dir, None);
    assert_eq!(g.code, 0, "{}", g.stderr);
    let pub_json: serde_json::Value =
        serde_json::from_str(&read(&dir.join("public-identity.json"))).unwrap();

    let out = run_identity(&["seed-candidate", dir.to_str().unwrap()]);
    assert_eq!(out.code, 0, "seed-candidate failed: {}", out.stderr);
    let cand: serde_json::Value = serde_json::from_str(&out.stdout).expect("candidate JSON");

    assert_eq!(json_str(&cand, "node_id"), json_str(&pub_json, "node_id"));
    assert_eq!(json_str(&cand, "peer_id"), json_str(&pub_json, "peer_id"));
    assert_eq!(
        json_str(&cand, "transport_security_mode"),
        json_str(&pub_json, "transport_security_mode")
    );
    assert_eq!(json_str(&cand, "pqc_suite"), json_str(&pub_json, "pqc_suite"));
    // no live/reachability claim.
    assert_eq!(json_str(&cand, "status"), "planned");
    assert!(cand.get("last_reachability_evidence").unwrap().is_null());
    // seed_node required fields are all present.
    for f in [
        "node_id",
        "peer_id",
        "validator_address",
        "p2p_host",
        "p2p_port",
        "p2p_multiaddr",
        "transport_security_mode",
        "pqc_suite",
        "trust_bundle_required",
        "expected_genesis_hash",
        "operator",
        "status",
        "last_reachability_evidence",
        "notes",
    ] {
        assert!(cand.get(f).is_some(), "seed candidate missing `{}`", f);
    }
}

// ---------------------------------------------------------------------------
// 11. mismatched validator-id fails closed at node boot.
//     A validator-candidate leaf cert is bound to `qbind-val-<index>`; booting
//     the node with a different `--validator-id` must exit closed. This proves
//     the identity binding is enforced end-to-end without a full network.
// ---------------------------------------------------------------------------

#[test]
fn mismatched_validator_id_fails_closed_at_boot() {
    let dir = tmpdir("mismatch").join("vc");
    let g = generate("validator-candidate", &dir, Some("0"));
    assert_eq!(g.code, 0, "{}", g.stderr);
    let spec = read(&dir.join("trusted-root.spec"));
    let data_dir = tmpdir("mismatch-data");

    // Boot with mismatched --validator-id 9 (cert is bound to qbind-val-0).
    let out = Command::new(qbind_node_bin())
        .env("QBIND_METRICS_HTTP_ADDR", "127.0.0.1:0")
        .args([
            "--env",
            "devnet",
            "--network-mode",
            "p2p",
            "--enable-p2p",
            "--validator-id",
            "9",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--p2p-listen-addr",
            "127.0.0.1:0",
            "--p2p-mutual-auth",
            "required",
            "--p2p-pqc-root-mode",
            "pqc-static-root",
            "--p2p-trusted-root",
            spec.trim(),
            "--p2p-leaf-cert",
            dir.join("leaf.cert.bin").to_str().unwrap(),
            "--p2p-leaf-cert-key",
            dir.join("leaf.kem.sk.bin").to_str().unwrap(),
        ])
        .output()
        .expect("spawn node");
    assert!(
        !out.status.success(),
        "node must fail closed under mismatched --validator-id"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("validator_id does not match") || stderr.contains("does not match"),
        "expected validator-id mismatch error, got: {}",
        stderr
    );
}

// ---------------------------------------------------------------------------
// 12 / 13 / 14 / 15. fail-closed refusals.
// ---------------------------------------------------------------------------

#[test]
fn mainnet_generation_is_refused_and_writes_nothing() {
    let dir = tmpdir("mainnet").join("out");
    let out = run_identity(&["generate", "mainnet", "full-node", dir.to_str().unwrap()]);
    assert_eq!(out.code, 3, "mainnet must be refused (exit 3)");
    assert!(!dir.exists(), "mainnet generation must write no material");
}

#[test]
fn testnet_generation_is_refused_and_writes_nothing() {
    let dir = tmpdir("testnet").join("out");
    let out = run_identity(&["generate", "testnet", "seed", dir.to_str().unwrap()]);
    assert_eq!(out.code, 3, "testnet must be refused (exit 3)");
    assert!(!dir.exists(), "testnet generation must write no material");
}

#[test]
fn unknown_role_is_refused() {
    let dir = tmpdir("role").join("out");
    let out = run_identity(&["generate", "devnet", "super-node", dir.to_str().unwrap()]);
    assert_eq!(out.code, 3, "unknown role must be refused (exit 3)");
}

#[test]
fn invalid_output_path_fails_safely() {
    // A path under an existing regular file cannot be created as a directory.
    let base = tmpdir("badpath");
    let file = base.join("not-a-dir");
    std::fs::write(&file, b"x").unwrap();
    let bad = file.join("child");
    let out = run_identity(&["generate", "devnet", "full-node", bad.to_str().unwrap()]);
    assert_ne!(out.code, 0, "invalid output path must fail");
    // Must not panic (exit code is a clean I/O failure, not a Rust panic 101).
    assert_ne!(out.code, 101, "must not panic");
}

#[test]
fn non_u64_validator_index_is_refused() {
    let dir = tmpdir("badindex").join("out");
    let out = run_identity(&[
        "generate",
        "devnet",
        "validator-candidate",
        dir.to_str().unwrap(),
        "not-a-number",
    ]);
    assert_eq!(out.code, 3, "non-u64 index must be refused (exit 3)");
}

// ---------------------------------------------------------------------------
// 17. committed example public JSON contains no secret patterns.
// ---------------------------------------------------------------------------

#[test]
fn committed_example_identity_has_no_secret_material() {
    let example = workspace_root()
        .join("docs/release/public-devnet/identity/EXAMPLE_PUBLIC_IDENTITY.json");
    let raw = read(&example).to_lowercase();
    // `private_material.leaf_kem_sk_path` legitimately references the secret-key
    // *path*; the check targets embedded secret material, not path references.
    for forbidden in ["secret_key", "private_key", "mnemonic", "-----begin"] {
        assert!(
            !raw.contains(forbidden),
            "committed example identity contains forbidden secret pattern `{}`",
            forbidden
        );
    }
    // The example must still be schema-shaped public material.
    let json: serde_json::Value = serde_json::from_str(&read(&example)).expect("example JSON");
    assert_eq!(json.get("devnet_only").and_then(|v| v.as_bool()), Some(true));
}

// ---------------------------------------------------------------------------
// print-public round-trips the generated public identity from disk.
// ---------------------------------------------------------------------------

#[test]
fn print_public_round_trips_generated_identity() {
    let dir = tmpdir("printpub").join("full-node");
    let g = generate("full-node", &dir, None);
    assert_eq!(g.code, 0, "{}", g.stderr);
    let on_disk = read(&dir.join("public-identity.json"));
    let out = run_identity(&["print-public", dir.to_str().unwrap()]);
    assert_eq!(out.code, 0, "print-public failed: {}", out.stderr);
    assert_eq!(out.stdout, on_disk, "print-public must echo the stored identity");
}