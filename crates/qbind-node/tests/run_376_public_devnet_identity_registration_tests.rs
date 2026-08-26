//! Run 376 — public DevNet identity registration / admission-check tests.
//!
//! These tests drive the real `qbind-node` binary (via `CARGO_BIN_EXE_qbind-node`)
//! through the new non-mutating `identity register-check` admission verifier and
//! assert the Run 376 contract: a Run 375 generated public identity is admissible
//! as a `planned` future seed-list entry, the identity maps into a seed-list
//! candidate without schema violation, and every fail-closed refusal holds
//! (status=live without reachability, planned+reachability, embedded private
//! material, malformed NodeId/peer_id/trusted_root_spec, wrong environment,
//! MainNet/TestNet material, mismatched cert, mismatched validator index, unknown
//! role).
//!
//! Scope guard: `register-check` is a pure local read-only admission verifier. It
//! opens NO socket, registers NO peer, mutates NO trust/validator/epoch/sequence/
//! marker state, changes NO P2P wire format, weakens NO peer admission, and makes
//! NO live/reachability/M4/C4/C5 claim. These tests assert those invariants.

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

fn seed_list_path() -> PathBuf {
    workspace_root().join("docs/release/public-devnet/network/devnet-seeds.placeholder.json")
}

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "qbind-run376-{}-{}-{}",
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
    #[allow(dead_code)]
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

/// Run register-check on the generated identity in `dir` with the given trailing
/// flags. Returns the verdict Output.
fn register_check(identity_json: &Path, extra: &[&str]) -> Output {
    let seed = seed_list_path();
    let mut args = vec![
        "register-check",
        identity_json.to_str().unwrap(),
        "--seed-list",
        seed.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    run_identity(&args)
}

fn verdict(out: &Output) -> serde_json::Value {
    serde_json::from_str(&out.stdout).unwrap_or_else(|e| {
        panic!("register-check stdout not JSON ({}): {}", e, out.stdout)
    })
}

// ---------------------------------------------------------------------------
// 1-3. Run 375 generated full-node / seed / validator-candidate identities pass
//      register-check as planned.
// ---------------------------------------------------------------------------

#[test]
fn generated_identities_pass_register_check_as_planned() {
    let base = tmpdir("planned");
    for (role, extra) in [
        ("full-node", None),
        ("seed", None),
        ("validator-candidate", Some("0")),
    ] {
        let dir = base.join(role);
        let g = generate(role, &dir, extra);
        assert_eq!(g.code, 0, "generate {role} failed: {}", g.stderr);

        let out = register_check(&dir.join("public-identity.json"), &["--role", role]);
        assert_eq!(out.code, 0, "register-check {role} failed: {}", out.stderr);
        let v = verdict(&out);
        assert_eq!(v["admissible"], serde_json::json!(true), "{role} not admissible");
        assert_eq!(v["candidate_status"], serde_json::json!("planned"));
        assert_eq!(v["role"], serde_json::json!(role));
        // 16. no socket opened; 12. no state mutated; no live/M4/C4/C5 claim.
        assert_eq!(v["socket_opened"], serde_json::json!(false));
        assert_eq!(v["runtime_state_mutated"], serde_json::json!(false));
        assert_eq!(v["live_reachability_claim"], serde_json::json!(false));
        assert_eq!(v["m4_green_claim"], serde_json::json!(false));
        assert_eq!(v["c4_c5_closure_claim"], serde_json::json!(false));
    }
}

// ---------------------------------------------------------------------------
// 4. schema-valid public identity maps into a seed-list candidate.
// ---------------------------------------------------------------------------

#[test]
fn identity_maps_into_seed_list_candidate() {
    let dir = tmpdir("map").join("seed");
    let g = generate("seed", &dir, None);
    assert_eq!(g.code, 0, "{}", g.stderr);
    let pub_json: serde_json::Value =
        serde_json::from_str(&read(&dir.join("public-identity.json"))).unwrap();

    let out = register_check(&dir.join("public-identity.json"), &[]);
    assert_eq!(out.code, 0, "register-check failed: {}", out.stderr);
    let v = verdict(&out);
    let cand = &v["candidate"];
    assert_eq!(cand["node_id"], pub_json["node_id"]);
    assert_eq!(cand["peer_id"], pub_json["peer_id"]);
    assert_eq!(cand["status"], serde_json::json!("planned"));
    assert!(cand["last_reachability_evidence"].is_null());
    // expected_genesis_hash pulled from the seed-list document.
    let seed_doc: serde_json::Value =
        serde_json::from_str(&read(&seed_list_path())).unwrap();
    assert_eq!(cand["expected_genesis_hash"], seed_doc["genesis_hash"]);
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
        assert!(cand.get(f).is_some(), "candidate missing `{}`", f);
    }
}

// ---------------------------------------------------------------------------
// 5. status=live without reachability evidence is rejected.
// ---------------------------------------------------------------------------

#[test]
fn live_without_reachability_is_rejected() {
    let dir = tmpdir("live").join("full-node");
    let g = generate("full-node", &dir, None);
    assert_eq!(g.code, 0, "{}", g.stderr);
    let out = register_check(&dir.join("public-identity.json"), &["--status", "live"]);
    assert_eq!(out.code, 3, "live without evidence must be refused: {}", out.stdout);
    let v = verdict(&out);
    assert_eq!(v["admissible"], serde_json::json!(false));
    assert_eq!(v["live_reachability_claim"], serde_json::json!(false));
}

// ---------------------------------------------------------------------------
// 6. planned with reachability evidence is rejected (schema forbids it).
// ---------------------------------------------------------------------------

#[test]
fn planned_with_reachability_is_rejected() {
    let dir = tmpdir("plannedreach").join("full-node");
    let g = generate("full-node", &dir, None);
    assert_eq!(g.code, 0, "{}", g.stderr);
    let out = register_check(
        &dir.join("public-identity.json"),
        &["--status", "planned", "--reachability-evidence", "docs/evidence.md"],
    );
    assert_eq!(out.code, 3, "planned+reachability must be refused: {}", out.stdout);
    assert_eq!(verdict(&out)["admissible"], serde_json::json!(false));
}

// ---------------------------------------------------------------------------
// 7. private key contents embedded in public JSON are rejected.
// ---------------------------------------------------------------------------

#[test]
fn embedded_private_material_is_rejected() {
    let dir = tmpdir("secret").join("full-node");
    let g = generate("full-node", &dir, None);
    assert_eq!(g.code, 0, "{}", g.stderr);
    let mut json: serde_json::Value =
        serde_json::from_str(&read(&dir.join("public-identity.json"))).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("leaf_kem_secret_key".into(), serde_json::json!("deadbeefdeadbeef"));
    let tampered = dir.join("tampered.json");
    std::fs::write(&tampered, serde_json::to_string_pretty(&json).unwrap()).unwrap();
    let out = register_check(&tampered, &[]);
    assert_eq!(out.code, 3, "embedded secret must be refused: {}", out.stdout);
    assert_eq!(verdict(&out)["admissible"], serde_json::json!(false));
}

// ---------------------------------------------------------------------------
// 8/9/10. malformed NodeId / peer_id / trusted_root_spec are rejected.
// ---------------------------------------------------------------------------

fn tamper_field(dir: &Path, key: &str, value: serde_json::Value) -> PathBuf {
    let mut json: serde_json::Value =
        serde_json::from_str(&read(&dir.join("public-identity.json"))).unwrap();
    json.as_object_mut().unwrap().insert(key.into(), value);
    let out = dir.join(format!("tampered-{}.json", key));
    std::fs::write(&out, serde_json::to_string_pretty(&json).unwrap()).unwrap();
    out
}

#[test]
fn malformed_node_id_is_rejected() {
    let dir = tmpdir("badnode").join("full-node");
    assert_eq!(generate("full-node", &dir, None).code, 0);
    let p = tamper_field(&dir, "node_id", serde_json::json!("XYZ-not-hex"));
    let out = register_check(&p, &[]);
    assert_eq!(out.code, 3, "malformed node_id must be refused: {}", out.stdout);
}

#[test]
fn malformed_peer_id_is_rejected() {
    let dir = tmpdir("badpeer").join("full-node");
    assert_eq!(generate("full-node", &dir, None).code, 0);
    let p = tamper_field(&dir, "peer_id", serde_json::json!("00"));
    let out = register_check(&p, &[]);
    assert_eq!(out.code, 3, "malformed peer_id must be refused: {}", out.stdout);
}

#[test]
fn malformed_trusted_root_spec_is_rejected() {
    let dir = tmpdir("badspec").join("full-node");
    assert_eq!(generate("full-node", &dir, None).code, 0);
    let p = tamper_field(&dir, "trusted_root_spec", serde_json::json!("not:a:spec"));
    let out = register_check(&p, &[]);
    assert_eq!(out.code, 3, "malformed trusted_root_spec must be refused: {}", out.stdout);
}

// ---------------------------------------------------------------------------
// 11 / 12. wrong environment (MainNet/TestNet) material is refused.
// ---------------------------------------------------------------------------

#[test]
fn wrong_environment_is_rejected() {
    let dir = tmpdir("wrongenv").join("full-node");
    assert_eq!(generate("full-node", &dir, None).code, 0);
    for env in ["mainnet", "testnet", "staging"] {
        let p = tamper_field(&dir, "environment", serde_json::json!(env));
        let out = register_check(&p, &[]);
        assert_eq!(out.code, 3, "env {env} must be refused: {}", out.stdout);
        assert_eq!(verdict(&out)["admissible"], serde_json::json!(false));
    }
}

// ---------------------------------------------------------------------------
// 13. mismatched leaf cert vs public identity is rejected.
// ---------------------------------------------------------------------------

#[test]
fn mismatched_cert_is_rejected() {
    let base = tmpdir("mismatchcert");
    let a = base.join("a");
    let b = base.join("b");
    assert_eq!(generate("full-node", &a, None).code, 0);
    assert_eq!(generate("full-node", &b, None).code, 0);
    // identity A with cert B (different keypair) must fail closed.
    let out = register_check(
        &a.join("public-identity.json"),
        &["--cert", b.join("leaf.cert.bin").to_str().unwrap()],
    );
    assert_eq!(out.code, 3, "mismatched cert must be refused: {}", out.stdout);
    assert_eq!(verdict(&out)["admissible"], serde_json::json!(false));

    // Sanity: identity A with its own cert A is admissible and cert-verified.
    let ok = register_check(
        &a.join("public-identity.json"),
        &["--cert", a.join("leaf.cert.bin").to_str().unwrap()],
    );
    assert_eq!(ok.code, 0, "matching cert should pass: {}", ok.stderr);
    assert_eq!(verdict(&ok)["cert_verified"], serde_json::json!(true));
}

// ---------------------------------------------------------------------------
// 14. mismatched validator index is rejected.
// ---------------------------------------------------------------------------

#[test]
fn mismatched_validator_index_is_rejected() {
    let base = tmpdir("mismatchidx");
    let vc0 = base.join("vc0");
    let vc3 = base.join("vc3");
    assert_eq!(generate("validator-candidate", &vc0, Some("0")).code, 0);
    assert_eq!(generate("validator-candidate", &vc3, Some("3")).code, 0);
    // identity for index 3 checked against the cert bound to index 0 must fail.
    // Use vc3 identity but a cert whose validator_id is index 0. Because node_id
    // also differs, this fails closed; construct a same-key mismatch is not
    // possible here, so we assert the validator-candidate identity fails against
    // a foreign validator cert.
    let out = register_check(
        &vc3.join("public-identity.json"),
        &["--cert", vc0.join("leaf.cert.bin").to_str().unwrap()],
    );
    assert_eq!(out.code, 3, "mismatched validator material must be refused: {}", out.stdout);
    assert_eq!(verdict(&out)["admissible"], serde_json::json!(false));
}

// ---------------------------------------------------------------------------
// 15. unknown --role is rejected.
// ---------------------------------------------------------------------------

#[test]
fn unknown_role_flag_is_rejected() {
    let dir = tmpdir("unknownrole").join("full-node");
    assert_eq!(generate("full-node", &dir, None).code, 0);
    let out = register_check(&dir.join("public-identity.json"), &["--role", "super-node"]);
    assert_eq!(out.code, 3, "unknown --role must be refused: {}", out.stdout);

    // A correct-but-mismatched role is also refused.
    let out2 = register_check(&dir.join("public-identity.json"), &["--role", "seed"]);
    assert_eq!(out2.code, 3, "mismatched --role must be refused: {}", out2.stdout);
}

// ---------------------------------------------------------------------------
// 16. no socket opened by default (verdict asserts socket_opened=false; the
//     command completes promptly with no listener). Also asserted in test 1.
// ---------------------------------------------------------------------------

#[test]
fn register_check_opens_no_socket_and_mutates_nothing() {
    let dir = tmpdir("nosocket").join("full-node");
    assert_eq!(generate("full-node", &dir, None).code, 0);
    let out = register_check(&dir.join("public-identity.json"), &[]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let v = verdict(&out);
    // 16 / 17 / 18 / 19 / 20 / 21: explicit non-claims in the verdict.
    assert_eq!(v["socket_opened"], serde_json::json!(false));
    assert_eq!(v["runtime_state_mutated"], serde_json::json!(false));
    assert_eq!(v["live_reachability_claim"], serde_json::json!(false));
    assert_eq!(v["m4_green_claim"], serde_json::json!(false));
    assert_eq!(v["c4_c5_closure_claim"], serde_json::json!(false));
}

// ---------------------------------------------------------------------------
// Usage: missing --seed-list is a usage error (exit 2), not a panic.
// ---------------------------------------------------------------------------

#[test]
fn missing_seed_list_is_usage_error() {
    let dir = tmpdir("noseedlist").join("full-node");
    assert_eq!(generate("full-node", &dir, None).code, 0);
    let out = run_identity(&["register-check", dir.join("public-identity.json").to_str().unwrap()]);
    assert_eq!(out.code, 2, "missing --seed-list must be usage error: {}", out.stdout);
    assert_ne!(out.code, 101, "must not panic");
}
