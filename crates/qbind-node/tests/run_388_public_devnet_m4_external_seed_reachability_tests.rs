//! Run 388 — public DevNet M4 external seed reachability: live-admission tests.
//!
//! Run 388 lands **no production source change**: the
//! `qbind-node identity register-check --status live --reachability-evidence <ref>`
//! admission gate already exists (Run 376). These tests pin the Run 388 M4
//! evidence contract in CI against the Run 388 reachability-evidence reference:
//! the live admission gate accepts a live candidate ONLY when a reachability
//! reference is supplied, fails closed without it, and fails closed for a
//! `planned` candidate that falsely carries reachability evidence. They also
//! assert the command makes NO live/reachability/M4/C4/C5 claim even when it
//! admits a `live` candidate — the gate is a structural admission decision, not a
//! reachability proof.
//!
//! Scope guard: `register-check` is a pure local read-only admission verifier. It
//! opens NO socket, mutates NO state, changes NO wire format, weakens NO peer
//! admission. External reachability is proven only by real external
//! infrastructure, which is unavailable in this environment — the Run 388 harness
//! records a Route C (no safe external seed infrastructure) verdict, so M4 stays
//! Yellow.

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

fn live_candidate_path() -> PathBuf {
    workspace_root().join("docs/release/public-devnet/network/devnet-seeds.live-candidate.json")
}

fn reach_ref() -> String {
    "docs/release/public-devnet/network/reachability/RUN_388_qbind-devnet-seed-1.md".to_string()
}

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "qbind-run388-{}-{}-{}",
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

fn generate_seed(dir: &Path) -> Output {
    run_identity(&["generate", "devnet", "seed", dir.to_str().unwrap()])
}

fn register_check(identity_json: &Path, cert: &Path, extra: &[&str]) -> Output {
    let seed = live_candidate_path();
    let mut args = vec![
        "register-check",
        identity_json.to_str().unwrap(),
        "--seed-list",
        seed.to_str().unwrap(),
        "--role",
        "seed",
        "--cert",
        cert.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    run_identity(&args)
}

fn verdict(out: &Output) -> serde_json::Value {
    serde_json::from_str(&out.stdout)
        .unwrap_or_else(|e| panic!("register-check stdout not JSON ({}): {}", e, out.stdout))
}

// ---------------------------------------------------------------------------
// 1. --status live WITH the Run 388 reachability-evidence reference is admitted,
//    and the command still makes NO live/reachability/M4/C4/C5 claim.
// ---------------------------------------------------------------------------

#[test]
fn live_status_with_reachability_evidence_is_admitted() {
    let dir = tmpdir("live-accept");
    let g = generate_seed(&dir);
    assert_eq!(g.code, 0, "generate seed failed: {}", g.stderr);

    let out = register_check(
        &dir.join("public-identity.json"),
        &dir.join("leaf.cert.bin"),
        &["--status", "live", "--reachability-evidence", &reach_ref()],
    );
    assert_eq!(out.code, 0, "live register-check refused: {}", out.stderr);
    let v = verdict(&out);
    assert_eq!(v["admissible"], serde_json::json!(true));
    assert_eq!(v["candidate_status"], serde_json::json!("live"));
    assert_eq!(v["cert_verified"], serde_json::json!(true));
    // The gate is structural admission only — never a live/reachability/M4 claim.
    assert_eq!(v["socket_opened"], serde_json::json!(false));
    assert_eq!(v["runtime_state_mutated"], serde_json::json!(false));
    assert_eq!(v["live_reachability_claim"], serde_json::json!(false));
    assert_eq!(v["m4_green_claim"], serde_json::json!(false));
    assert_eq!(v["c4_c5_closure_claim"], serde_json::json!(false));
    // The live candidate carries the supplied Run 388 reachability reference.
    assert_eq!(
        v["candidate"]["last_reachability_evidence"],
        serde_json::json!(reach_ref())
    );
}

// ---------------------------------------------------------------------------
// 2. --status live WITHOUT reachability evidence fails closed.
// ---------------------------------------------------------------------------

#[test]
fn live_status_without_reachability_evidence_fails_closed() {
    let dir = tmpdir("live-reject");
    let g = generate_seed(&dir);
    assert_eq!(g.code, 0, "generate seed failed: {}", g.stderr);

    let out = register_check(
        &dir.join("public-identity.json"),
        &dir.join("leaf.cert.bin"),
        &["--status", "live"],
    );
    assert_ne!(out.code, 0, "live without evidence was NOT refused");
    let v = verdict(&out);
    assert_eq!(v["admissible"], serde_json::json!(false));
    assert_eq!(v["m4_green_claim"], serde_json::json!(false));
    assert_eq!(v["live_reachability_claim"], serde_json::json!(false));
}

// ---------------------------------------------------------------------------
// 3. --status planned WITH reachability evidence fails closed (schema forbids
//    reachability on non-live entries).
// ---------------------------------------------------------------------------

#[test]
fn planned_status_with_reachability_evidence_fails_closed() {
    let dir = tmpdir("planned-reject");
    let g = generate_seed(&dir);
    assert_eq!(g.code, 0, "generate seed failed: {}", g.stderr);

    let out = register_check(
        &dir.join("public-identity.json"),
        &dir.join("leaf.cert.bin"),
        &["--status", "planned", "--reachability-evidence", &reach_ref()],
    );
    assert_ne!(out.code, 0, "planned+reachability was NOT refused");
    let v = verdict(&out);
    assert_eq!(v["admissible"], serde_json::json!(false));
}

// ---------------------------------------------------------------------------
// 4. The committed live-candidate document remains a schema-honest preflight:
//    its single seed entry is NOT `live` and carries null reachability evidence
//    (external reachability was not proven — Route C; M4 stays Yellow).
// ---------------------------------------------------------------------------

#[test]
fn committed_live_candidate_is_not_falsely_live() {
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(live_candidate_path()).expect("read"))
            .expect("live-candidate is valid JSON");
    let seeds = doc["seed_nodes"].as_array().expect("seed_nodes array");
    assert!(!seeds.is_empty(), "expected at least one candidate entry");
    for n in seeds {
        assert_ne!(
            n["status"],
            serde_json::json!("live"),
            "committed entry must not be live while external reachability is unproven"
        );
        assert_eq!(
            n["last_reachability_evidence"],
            serde_json::Value::Null,
            "non-live entry must carry null reachability evidence"
        );
        assert!(n["node_id"].as_str().map(|s| !s.is_empty()).unwrap_or(false));
        assert!(n["peer_id"].as_str().map(|s| !s.is_empty()).unwrap_or(false));
    }
}