//! Run 422 containment correction — process-level startup-refusal proof.
//!
//! These tests drive the real `qbind-node` binary via `CARGO_BIN_EXE_qbind-node`.
//! Its profile follows Cargo: the recorded tests ran without `--release`.
//! They prove the single production startup guard:
//! when `--consensus-authority-from-genesis` is supplied during normal
//! startup, the binary exits non-zero with the precise "disabled pending
//! D4-D7" diagnostic, and it does so BEFORE the per-mode service-start
//! boundary — i.e. before any P2P transport / consensus loop or LocalMesh
//! consensus loop is started.
//!
//! Crucially, the inputs used here are VALID: a well-formed DevNet genesis
//! that the Run 102 boot-time verifier accepts (with the correct
//! `--expect-genesis-hash`) plus a matching local signer keystore. The
//! non-zero exit is therefore attributable to the activation guard itself and
//! NOT to a parser error, an invalid fixture, or a missing file. A companion
//! test confirms that with the flag ABSENT the same valid inputs are NOT
//! refused by this guard (they proceed past it into normal startup), so the
//! guard does not disturb existing behavior.

use std::path::{Path, PathBuf};
use std::process::Command;

use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_ledger::{
    compute_canonical_genesis_hash, GenesisAllocation, GenesisConfig, GenesisCouncilConfig,
    GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy,
};

// ---------------------------------------------------------------------------
// The exact substrings the guard must emit / must NOT emit.
// ---------------------------------------------------------------------------

/// The precise refusal diagnostic emitted by the single startup guard.
const REFUSAL_DIAGNOSTIC: &str = "genesis-authority activation is disabled pending D4-D7";

/// First log line of `run_p2p_node` — printed only once the P2P service-start
/// boundary is crossed. It must NEVER appear when the guard fires.
const P2P_SERVICE_START_MARKER: &str = "P2P mode: starting transport + consensus loop";

/// First log line of `run_local_mesh_node` — printed only once the LocalMesh
/// service-start boundary is crossed. It must NEVER appear when the guard
/// fires.
const LOCAL_MESH_SERVICE_START_MARKER: &str = "LocalMesh mode: starting consensus loop";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn qbind_node_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_qbind-node"))
}

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "qbind-run422-refusal-{}-{}-{}",
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

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Fresh ML-DSA-44 keypair: `(public_key_hex, secret_key_bytes)`.
fn fresh_keypair() -> (String, Vec<u8>) {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
    (hex_lower(&pk), sk)
}

fn validator(addr_seed: u8, pk_hex: String) -> GenesisValidator {
    GenesisValidator::new(format!("{:02x}", addr_seed).repeat(32), pk_hex, 100_000u128)
}

/// A well-formed DevNet genesis with three validators. Structurally identical
/// to the fixtures used by the Run 422 provider tests, so the Run 102 boot
/// verifier accepts it under DevNet policy.
fn devnet_genesis(v0_pk: String) -> GenesisConfig {
    let (pk1, _s1) = fresh_keypair();
    let (pk2, _s2) = fresh_keypair();
    GenesisConfig::new(
        "0000000051424e44",
        1_738_000_000_000,
        vec![GenesisAllocation::new(
            "0x1111111111111111111111111111111111111111",
            1_000_000u128,
        )],
        vec![validator(1, v0_pk), validator(2, pk1), validator(3, pk2)],
        GenesisCouncilConfig::new(
            vec![
                "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
                "0xdddddddddddddddddddddddddddddddddddddddd".to_string(),
                "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
            ],
            2,
        ),
        GenesisMonetaryConfig::mainnet_default(),
    )
}

/// Materialize valid startup inputs: a DevNet genesis file, its canonical
/// DevNet hash (for `--expect-genesis-hash`), a data dir, and a matching
/// local signer keystore for `validator-0`. Returns the owned temp dir (kept
/// alive by the caller) and the paths/values needed to build the argv.
struct ValidInputs {
    _dir: PathBuf,
    genesis_path: PathBuf,
    expect_hash_hex: String,
    data_dir: PathBuf,
    keystore_dir: PathBuf,
}

fn valid_inputs(tag: &str) -> ValidInputs {
    let dir = tmpdir(tag);
    // One keypair whose public key is committed for validator 0 and whose
    // secret key is placed in the local signer keystore — a genuinely
    // matching signer.
    let (v0_pk, v0_sk) = fresh_keypair();
    let genesis = devnet_genesis(v0_pk);

    let genesis_path = dir.join("genesis.json");
    std::fs::write(
        &genesis_path,
        serde_json::to_vec_pretty(&genesis).expect("serialize genesis"),
    )
    .expect("write genesis");

    let expect_hash =
        compute_canonical_genesis_hash(&genesis, NetworkEnvironmentPolicy::Devnet);
    let expect_hash_hex = format!("0x{}", hex_lower(&expect_hash));

    let data_dir = dir.join("data");
    std::fs::create_dir_all(&data_dir).expect("create data dir");

    // Matching local signer keystore: `validator-0.json` under the keystore
    // root. Suite id 100 is ML-DSA-44 (`EXPECTED_SUITE_ID`).
    let keystore_dir = dir.join("keystore");
    std::fs::create_dir_all(&keystore_dir).expect("create keystore dir");
    std::fs::write(
        keystore_dir.join("validator-0.json"),
        format!(
            "{{\n  \"suite_id\": 100,\n  \"private_key_hex\": \"{}\"\n}}\n",
            hex_lower(&v0_sk)
        ),
    )
    .expect("write keystore");

    ValidInputs {
        _dir: dir,
        genesis_path,
        expect_hash_hex,
        data_dir,
        keystore_dir,
    }
}

struct Run {
    code: i32,
    stderr: String,
    stdout: String,
}

fn run(args: &[String]) -> Run {
    let out = Command::new(qbind_node_bin())
        .args(args)
        .output()
        .expect("spawn qbind-node");
    Run {
        code: out.status.code().unwrap_or(-1),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
    }
}

/// Base argv (without the network-mode-specific bits and without the
/// activation flag) that supplies the valid DevNet inputs.
fn base_args(inp: &ValidInputs) -> Vec<String> {
    vec![
        "--env".to_string(),
        "devnet".to_string(),
        "--data-dir".to_string(),
        inp.data_dir.display().to_string(),
        "--genesis-path".to_string(),
        inp.genesis_path.display().to_string(),
        "--expect-genesis-hash".to_string(),
        inp.expect_hash_hex.clone(),
        "--signer-keystore-path".to_string(),
        inp.keystore_dir.display().to_string(),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Valid DevNet genesis + matching signer + the activation flag are refused
/// non-zero with the precise "disabled pending D4-D7" diagnostic, and the
/// refusal happens BEFORE the P2P service-start boundary.
#[test]
fn valid_genesis_and_signer_plus_flag_refused_before_p2p_service_start() {
    let inp = valid_inputs("p2p");
    let mut args = base_args(&inp);
    args.extend([
        "--network-mode".to_string(),
        "p2p".to_string(),
        "--enable-p2p".to_string(),
        "--consensus-authority-from-genesis".to_string(),
    ]);
    let r = run(&args);

    assert_ne!(r.code, 0, "must exit non-zero; stderr=\n{}", r.stderr);
    assert!(
        r.stderr.contains(REFUSAL_DIAGNOSTIC),
        "stderr must carry the disabled-pending-D4-D7 diagnostic; got:\n{}",
        r.stderr
    );
    assert!(
        r.stderr.contains("--consensus-authority-from-genesis"),
        "diagnostic must name the refused flag; got:\n{}",
        r.stderr
    );
    // The refusal precedes the service-start boundary: the P2P transport /
    // consensus loop must never have started.
    assert!(
        !r.stderr.contains(P2P_SERVICE_START_MARKER)
            && !r.stdout.contains(P2P_SERVICE_START_MARKER),
        "P2P service must NOT start before the refusal; stderr=\n{}",
        r.stderr
    );
}

/// The refusal also applies to LocalMesh startup — no other production mode
/// bypasses the guard, and the LocalMesh consensus loop never starts.
#[test]
fn local_mesh_mode_cannot_bypass_the_refusal() {
    let inp = valid_inputs("localmesh");
    let mut args = base_args(&inp);
    args.extend([
        "--network-mode".to_string(),
        "local-mesh".to_string(),
        "--consensus-authority-from-genesis".to_string(),
    ]);
    let r = run(&args);

    assert_ne!(r.code, 0, "must exit non-zero; stderr=\n{}", r.stderr);
    assert!(
        r.stderr.contains(REFUSAL_DIAGNOSTIC),
        "LocalMesh must be refused with the same diagnostic; got:\n{}",
        r.stderr
    );
    assert!(
        !r.stderr.contains(LOCAL_MESH_SERVICE_START_MARKER)
            && !r.stdout.contains(LOCAL_MESH_SERVICE_START_MARKER),
        "LocalMesh consensus loop must NOT start before the refusal; stderr=\n{}",
        r.stderr
    );
}

/// Flag absence preserves existing behavior: with the SAME valid inputs but
/// WITHOUT `--consensus-authority-from-genesis`, the activation guard does not
/// fire (its diagnostic is absent) and startup proceeds past the guard into
/// the LocalMesh service-start boundary. This proves the guard is scoped to
/// the explicit activation request and does not disturb the default path.
#[test]
fn flag_absent_is_not_refused_by_the_guard() {
    let inp = valid_inputs("noflag");
    let mut args = base_args(&inp);
    args.push("--network-mode".to_string());
    args.push("local-mesh".to_string());
    // Run the node briefly, then terminate: we only need to observe that it
    // crosses the service-start boundary without the refusal diagnostic.
    let mut child = Command::new(qbind_node_bin())
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn qbind-node");

    std::thread::sleep(std::time::Duration::from_secs(4));
    let _ = child.kill();
    let out = child.wait_with_output().expect("collect output");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

    assert!(
        !stderr.contains(REFUSAL_DIAGNOSTIC),
        "guard must NOT fire when the flag is absent; stderr=\n{}",
        stderr
    );
    assert!(
        stderr.contains(LOCAL_MESH_SERVICE_START_MARKER),
        "without the flag, startup must proceed to the LocalMesh service-start \
         boundary; stderr=\n{}",
        stderr
    );
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

/// `--help` behavior is preserved: it prints usage and exits zero, and never
/// triggers the activation refusal.
#[test]
fn help_behavior_is_preserved() {
    let _ = workspace_root(); // keep helper referenced even if unused elsewhere
    let r = run(&["--help".to_string()]);
    assert_eq!(r.code, 0, "--help must exit zero; stderr=\n{}", r.stderr);
    assert!(
        !r.stdout.contains(REFUSAL_DIAGNOSTIC) && !r.stderr.contains(REFUSAL_DIAGNOSTIC),
        "--help must not trigger the activation refusal"
    );
    assert!(
        r.stdout.contains("consensus-authority-from-genesis"),
        "--help should still document the flag"
    );
}
