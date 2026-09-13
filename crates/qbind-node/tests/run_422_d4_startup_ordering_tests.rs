//! Run 422 D4 — consensus-security preflight startup-ordering proof.
//!
//! These tests drive the real `qbind-node` binary via
//! `CARGO_BIN_EXE_qbind-node`. Because they run under the default Cargo test
//! profile, they are **process tests, not standalone release-binary
//! evidence** (see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D4_D5.md`).
//!
//! Scope of the boundary being proved (task section 7):
//! `run_p2p_consensus_security_preflight(...)` runs BEFORE the P2P service is
//! constructed (`builder.build()`), before any peer is dialed, and before the
//! consensus task starts. The FATAL signer/provider/suite/policy checks inside
//! the preflight therefore terminate the process before the
//! `"[binary] P2P transport up."` marker (printed only AFTER `builder.build()`
//! opens the listener). This is preflight-before-**P2P-service-construction**,
//! NOT before "any networking": the optional metrics HTTP task is started
//! earlier in `main`, before the per-mode P2P function is entered, and is
//! intentionally out of scope here.
//!
//! Positive control: every negative case asserts a preflight log marker
//! (`[binary] Run 032:` / `[binary] Run 033:`) IS present, proving the input
//! reached the preflight rather than failing only in CLI parsing or an
//! unrelated earlier check. Absence of the P2P-transport marker alone is
//! never treated as sufficient.
//!
//! Resource discipline: negative cases exit deterministically (the preflight
//! calls `std::process::exit(1)`), so no child needs reaping. The single
//! positive case that reaches P2P startup binds a loopback ephemeral port
//! (`127.0.0.1:0`), is bounded by a short sleep, and its child is killed and
//! reaped even on assertion failure via `ChildGuard`. Temporary keystores use
//! `0o700`/`0o600` permissions and are removed on drop.

use std::path::PathBuf;
use std::process::{Child, Command};

use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_ledger::{
    compute_canonical_genesis_hash, GenesisAllocation, GenesisConfig, GenesisCouncilConfig,
    GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy,
};

// ---------------------------------------------------------------------------
// Markers (kept in sync with crates/qbind-node/src/main.rs).
// ---------------------------------------------------------------------------

/// Positive controls: the preflight was entered (printed at the very start of
/// `run_p2p_consensus_security_preflight`, before any FATAL exit).
const PREFLIGHT_SIGNER_MARKER: &str = "[binary] Run 032:";
const PREFLIGHT_PROBE_MARKER: &str = "[binary] Run 033:";

/// The P2P service-construction boundary: printed ONLY after
/// `builder.build()` opens the listener. It must never appear when a preflight
/// FATAL fires.
const P2P_TRANSPORT_UP_MARKER: &str = "[binary] P2P transport up.";

/// Emitted when the Timeout/NewView verification context activates.
const TIMEOUT_ACTIVE_MARKER: &str = "timeout verification ACTIVE";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn qbind_node_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_qbind-node"))
}

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "qbind-run422-d4-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&p).expect("create temp dir");
    restrict_dir(&p);
    p
}

#[cfg(unix)]
fn restrict_dir(p: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
}
#[cfg(not(unix))]
fn restrict_dir(_p: &std::path::Path) {}

#[cfg(unix)]
fn restrict_file(p: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_file(_p: &std::path::Path) {}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn fresh_keypair() -> (String, Vec<u8>) {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
    (hex_lower(&pk), sk)
}

fn validator(addr_seed: u8, pk_hex: String) -> GenesisValidator {
    GenesisValidator::new(format!("{:02x}", addr_seed).repeat(32), pk_hex, 100_000u128)
}

/// A well-formed DevNet genesis with three validators (validator 0's key is
/// `v0_pk`). Accepted by the Run 102 boot verifier under DevNet policy.
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

/// Owned valid startup inputs. The temp dir is removed on drop.
struct ValidInputs {
    dir: PathBuf,
    genesis_path: PathBuf,
    expect_hash_hex: String,
    data_dir: PathBuf,
    keystore_dir: PathBuf,
    /// validator-0's genesis-committed public key (hex), matching the signer.
    v0_pk_hex: String,
}

impl Drop for ValidInputs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn valid_inputs(tag: &str) -> ValidInputs {
    let dir = tmpdir(tag);
    let (v0_pk, v0_sk) = fresh_keypair();
    let genesis = devnet_genesis(v0_pk.clone());

    let genesis_path = dir.join("genesis.json");
    std::fs::write(
        &genesis_path,
        serde_json::to_vec_pretty(&genesis).expect("serialize genesis"),
    )
    .expect("write genesis");

    let expect_hash = compute_canonical_genesis_hash(&genesis, NetworkEnvironmentPolicy::Devnet);
    let expect_hash_hex = format!("0x{}", hex_lower(&expect_hash));

    let data_dir = dir.join("data");
    std::fs::create_dir_all(&data_dir).expect("create data dir");

    let keystore_dir = dir.join("keystore");
    std::fs::create_dir_all(&keystore_dir).expect("create keystore dir");
    restrict_dir(&keystore_dir);
    let ks_file = keystore_dir.join("validator-0.json");
    std::fs::write(
        &ks_file,
        format!(
            "{{\n  \"suite_id\": 100,\n  \"private_key_hex\": \"{}\"\n}}\n",
            hex_lower(&v0_sk)
        ),
    )
    .expect("write keystore");
    restrict_file(&ks_file);

    ValidInputs {
        dir,
        genesis_path,
        expect_hash_hex,
        data_dir,
        keystore_dir,
        v0_pk_hex: v0_pk,
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

/// Base argv for a P2P-mode start with a loopback ephemeral listener. The
/// signer keystore is included by default; callers that test the missing-
/// signer path override it.
fn p2p_base_args(inp: &ValidInputs, with_signer: bool) -> Vec<String> {
    let mut a = vec![
        "--env".to_string(),
        "devnet".to_string(),
        "--data-dir".to_string(),
        inp.data_dir.display().to_string(),
        "--genesis-path".to_string(),
        inp.genesis_path.display().to_string(),
        "--expect-genesis-hash".to_string(),
        inp.expect_hash_hex.clone(),
        "--network-mode".to_string(),
        "p2p".to_string(),
        "--enable-p2p".to_string(),
        "--p2p-listen-addr".to_string(),
        "127.0.0.1:0".to_string(),
        "--validator-id".to_string(),
        "0".to_string(),
    ];
    if with_signer {
        a.push("--signer-keystore-path".to_string());
        a.push(inp.keystore_dir.display().to_string());
    }
    a
}

/// Assert the preflight was reached (positive control) and the P2P service
/// was NOT constructed (refusal precedes `builder.build()`).
fn assert_refused_before_p2p(r: &Run) {
    assert_ne!(r.code, 0, "must exit non-zero; stderr=\n{}", r.stderr);
    assert!(
        r.stderr.contains(PREFLIGHT_SIGNER_MARKER) || r.stderr.contains(PREFLIGHT_PROBE_MARKER),
        "positive control: the input must reach the preflight (Run 032/033 \
         marker); stderr=\n{}",
        r.stderr
    );
    assert!(
        !r.stderr.contains(P2P_TRANSPORT_UP_MARKER) && !r.stdout.contains(P2P_TRANSPORT_UP_MARKER),
        "P2P service must NOT be constructed before the preflight refusal; \
         stderr=\n{}",
        r.stderr
    );
}

// ---------------------------------------------------------------------------
// Negative cases — RequireOrFail refusal reaches the preflight and terminates
// before P2P service construction.
// ---------------------------------------------------------------------------

/// RequireOrFail + missing local signer (no `--signer-keystore-path`): the
/// preflight refuses fail-closed with a signer-specific diagnostic, before
/// the P2P service is constructed.
#[test]
fn require_or_fail_missing_local_signer_refused_before_p2p() {
    let inp = valid_inputs("missing-signer");
    let mut args = p2p_base_args(&inp, /* with_signer */ false);
    args.push("--require-timeout-verification".to_string());
    let r = run(&args);

    assert_refused_before_p2p(&r);
    assert!(
        r.stderr
            .contains("--require-timeout-verification was set but the local validator")
            && r.stderr.contains("signer could not be loaded"),
        "expected signer-load FATAL diagnostic; stderr=\n{}",
        r.stderr
    );
}

/// RequireOrFail + present signer but INVALID peer key-provider (malformed
/// `--validator-consensus-key` hex): the preflight builds the signer half, then
/// refuses on the peer-side provider, before the P2P service is constructed.
#[test]
fn require_or_fail_invalid_peer_key_provider_refused_before_p2p() {
    let inp = valid_inputs("bad-peer-key");
    let mut args = p2p_base_args(&inp, /* with_signer */ true);
    args.extend([
        "--require-timeout-verification".to_string(),
        // Malformed hex public key for validator 0.
        "--validator-consensus-key".to_string(),
        "0:100:zzzznothex".to_string(),
    ]);
    let r = run(&args);

    assert_refused_before_p2p(&r);
    assert!(
        r.stderr
            .contains("peer-side SuiteAwareValidatorKeyProvider could not be built"),
        "expected peer-key-provider FATAL diagnostic; stderr=\n{}",
        r.stderr
    );
}

/// RequireOrFail + present signer but an UNSUPPORTED consensus suite id in the
/// peer key-provider spec: the preflight refuses on the suite check, before the
/// P2P service is constructed.
#[test]
fn require_or_fail_unsupported_suite_refused_before_p2p() {
    let inp = valid_inputs("bad-suite");
    let mut args = p2p_base_args(&inp, /* with_signer */ true);
    args.extend([
        "--require-timeout-verification".to_string(),
        // Suite id 200 is not the supported ML-DSA-44 suite (100).
        "--validator-consensus-key".to_string(),
        format!("0:200:{}", inp.v0_pk_hex),
    ]);
    let r = run(&args);

    assert_refused_before_p2p(&r);
    assert!(
        r.stderr
            .contains("peer-side SuiteAwareValidatorKeyProvider could not be built"),
        "expected suite-rejection FATAL diagnostic; stderr=\n{}",
        r.stderr
    );
}

/// RequireOrFail + present signer but the local consensus key does NOT match
/// the loaded signer (membership/identity binding failure): the preflight
/// refuses before the P2P service is constructed.
#[test]
fn require_or_fail_local_key_mismatches_signer_refused_before_p2p() {
    let inp = valid_inputs("key-mismatch");
    // A different, non-matching public key for validator 0.
    let (other_pk, _sk) = fresh_keypair();
    let mut args = p2p_base_args(&inp, /* with_signer */ true);
    args.extend([
        "--require-timeout-verification".to_string(),
        "--validator-consensus-key".to_string(),
        format!("0:100:{}", other_pk),
    ]);
    let r = run(&args);

    assert_refused_before_p2p(&r);
    assert!(
        r.stderr
            .contains("peer-side SuiteAwareValidatorKeyProvider could not be built"),
        "expected local-key-mismatch FATAL diagnostic; stderr=\n{}",
        r.stderr
    );
}

// ---------------------------------------------------------------------------
// Positive case — a valid legacy configuration passes preflight and reaches
// P2P startup. Timeout authority is available as configured; Proposal/Vote
// authority remains absent (the D5 in-process tests prove the latter).
// ---------------------------------------------------------------------------

/// Kills and reaps the child on drop so a failed assertion never leaks a
/// bound listener or zombie process.
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Valid legacy config: matching signer + a complete `--validator-consensus-key`
/// for the local validator (no static peers ⇒ single active validator). The
/// preflight activates the Timeout/NewView context and startup proceeds past
/// `builder.build()` to the P2P-transport boundary. This proves the prepared
/// preflight result is consumed by production wiring and that a valid legacy
/// Timeout configuration coexists with an absent Proposal/Vote authority.
#[test]
fn valid_legacy_config_passes_preflight_and_reaches_p2p_startup() {
    let inp = valid_inputs("valid-legacy");
    let mut args = p2p_base_args(&inp, /* with_signer */ true);
    args.extend([
        "--require-timeout-verification".to_string(),
        // Local validator 0's consensus key matches the loaded signer.
        "--validator-consensus-key".to_string(),
        format!("0:100:{}", inp.v0_pk_hex),
    ]);

    let child = Command::new(qbind_node_bin())
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn qbind-node");
    let mut guard = ChildGuard(child);

    // Bounded observation window, then terminate and collect piped stderr.
    std::thread::sleep(std::time::Duration::from_secs(6));
    let _ = guard.0.kill();
    let _ = guard.0.wait();
    let stderr = {
        use std::io::Read;
        let mut buf = String::new();
        if let Some(mut err) = guard.0.stderr.take() {
            let _ = err.read_to_string(&mut buf);
        }
        buf
    };

    assert!(
        stderr.contains(TIMEOUT_ACTIVE_MARKER),
        "valid legacy config must activate the Timeout/NewView context; \
         stderr=\n{}",
        stderr
    );
    assert!(
        stderr.contains(P2P_TRANSPORT_UP_MARKER),
        "valid legacy config must pass preflight and reach the P2P-transport \
         boundary; stderr=\n{}",
        stderr
    );
    assert!(
        !stderr.contains("refuses to start"),
        "valid legacy config must NOT trigger any preflight refusal; \
         stderr=\n{}",
        stderr
    );
}