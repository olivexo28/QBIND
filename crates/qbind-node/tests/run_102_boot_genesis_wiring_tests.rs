//! Run 102 — release-binary boot-time canonical genesis verification
//! integration tests.
//!
//! These tests exercise the new
//! [`qbind_node::pqc_boot_genesis::run_boot_time_genesis_verification`]
//! entry point (the same call that `qbind-node`'s `main` makes after
//! T185 MainNet invariants validation and before any trust-bundle /
//! network / consensus startup) against representative `NodeConfig`
//! shapes. They are release-binary-facing in the sense that they go
//! through the same `NodeConfig` and `GenesisConfig` types the
//! production `qbind-node` binary links against, and reproduce the
//! fail-closed branches that the release-binary smoke evidence in
//! `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_102.md` records.
//!
//! Scope (matches `task/RUN_102_TASK.txt` §"Required tests"):
//!   * §A — Startup wiring tests (MainNet refusal scenarios + happy path).
//!   * §B — `--print-genesis-hash` canonical-hash sensitivity (covered
//!          by the in-module unit tests in `pqc_boot_genesis.rs::tests`).
//!   * §C — DevNet/TestNet preservation.
//!   * §E — Regression linkage (run alongside the Run 101 + T232/T233 suites).

use std::io::Write;
use std::path::PathBuf;

use qbind_ledger::{
    compute_canonical_genesis_hash, format_genesis_hash, parse_genesis_hash, GenesisAllocation,
    GenesisAuthorityConfig, GenesisAuthorityRoot, GenesisConfig, GenesisCouncilConfig,
    GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy,
    GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_BYTES, GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::node_config::{GenesisSourceConfig, NodeConfig};
use qbind_node::pqc_boot_genesis::{
    run_boot_time_genesis_verification, BootGenesisError, BootGenesisOutcome,
};
use qbind_types::NetworkEnvironment;

fn fingerprint(seed: u8) -> String {
    format!("{:02x}", seed).repeat(32)
}

/// Run 104: synthetic 1312-byte ML-DSA-44 public key for MainNet
/// bundle-signing-authority root fixtures.
fn synthetic_ml_dsa_44_pk(seed: u8) -> Vec<u8> {
    vec![seed; GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_BYTES]
}

fn mainnet_genesis_with_chain(chain_id: &str) -> GenesisConfig {
    let mut cfg = GenesisConfig::new(
        chain_id,
        1_738_000_000_000,
        vec![GenesisAllocation::new(
            "0x1111111111111111111111111111111111111111",
            1_000_000u128,
        )],
        vec![GenesisValidator::new(
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "pqc_key_validator_1",
            100_000u128,
        )],
        GenesisCouncilConfig::new(
            vec![
                "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
                "0xdddddddddddddddddddddddddddddddddddddddd".to_string(),
                "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
            ],
            2,
        ),
        GenesisMonetaryConfig::mainnet_default(),
    );
    // Run 104: full ML-DSA-44 public-key material is required on MainNet
    // for the bundle-signing-authority root.
    let mut auth = GenesisAuthorityConfig::new(vec![
        GenesisAuthorityRoot::with_public_key_bytes(
            GENESIS_AUTHORITY_SUITE_ML_DSA_44,
            &synthetic_ml_dsa_44_pk(0xab),
            "foundation-bundle-signer-1",
        ),
    ]);
    auth.pqc_transport_roots = vec![GenesisAuthorityRoot::new(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        fingerprint(0xcd),
        "foundation-transport-1",
    )];
    cfg.authority = Some(auth);
    cfg
}

fn write_tmp_genesis(cfg: &GenesisConfig, name: &str) -> PathBuf {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "qbind-run-102-it-{}-{}-{}.json",
        name,
        std::process::id(),
        rand_suffix()
    ));
    let mut f = std::fs::File::create(&path).expect("create tmp");
    let json = serde_json::to_string_pretty(cfg).expect("serialize");
    f.write_all(json.as_bytes()).expect("write");
    path
}

fn rand_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn mainnet_config_with_external(path: &PathBuf) -> NodeConfig {
    let mut config = NodeConfig::new(NetworkEnvironment::Mainnet);
    config.genesis_source = GenesisSourceConfig::external(path.clone());
    config
}

// ===========================================================================
// §A1 — MainNet missing expected hash rejects (fail-closed)
// ===========================================================================

#[test]
fn run_102_mainnet_missing_expected_hash_rejects() {
    let cfg = mainnet_genesis_with_chain("qbind-mainnet-v0");
    let path = write_tmp_genesis(&cfg, "missing_hash");

    let mut node_cfg = mainnet_config_with_external(&path);
    node_cfg.expected_genesis_hash = None; // simulate bypass of the T233 shield

    let err = run_boot_time_genesis_verification(&node_cfg)
        .expect_err("MainNet without expected_genesis_hash must fail closed in Run 102");
    let msg = err.to_string();
    assert!(
        msg.contains("expected canonical genesis hash"),
        "operator error must mention expected canonical genesis hash, got: {}",
        msg
    );
    let _ = std::fs::remove_file(path);
}

// ===========================================================================
// §A2 — MainNet expected-hash mismatch rejects
// ===========================================================================

#[test]
fn run_102_mainnet_hash_mismatch_rejects() {
    let cfg = mainnet_genesis_with_chain("qbind-mainnet-v0");
    let path = write_tmp_genesis(&cfg, "mismatch");

    let mut node_cfg = mainnet_config_with_external(&path);
    node_cfg.expected_genesis_hash = Some([0u8; 32]); // bogus

    let err = run_boot_time_genesis_verification(&node_cfg)
        .expect_err("MainNet with mismatched expected hash must fail closed");
    let msg = err.to_string();
    assert!(
        msg.contains("mismatch"),
        "operator error must mention hash mismatch, got: {}",
        msg
    );
    let _ = std::fs::remove_file(path);
}

// ===========================================================================
// §A3 — MainNet missing authority rejects (even with matching hash)
// ===========================================================================

#[test]
fn run_102_mainnet_missing_authority_rejects() {
    let mut cfg = mainnet_genesis_with_chain("qbind-mainnet-v0");
    cfg.authority = None;
    let h = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
    let path = write_tmp_genesis(&cfg, "no_auth");

    let mut node_cfg = mainnet_config_with_external(&path);
    node_cfg.expected_genesis_hash = Some(h);

    let err = run_boot_time_genesis_verification(&node_cfg)
        .expect_err("MainNet missing authority must fail closed even with a matching hash");
    let msg = err.to_string();
    assert!(
        msg.contains("authority"),
        "operator error must mention authority validation, got: {}",
        msg
    );
    let _ = std::fs::remove_file(path);
}

// ===========================================================================
// §A4 — MainNet empty authority roots rejects
// ===========================================================================

#[test]
fn run_102_mainnet_empty_authority_roots_rejects() {
    let mut cfg = mainnet_genesis_with_chain("qbind-mainnet-v0");
    cfg.authority.as_mut().unwrap().bundle_signing_authority_roots = vec![];
    let path = write_tmp_genesis(&cfg, "empty_roots");

    let mut node_cfg = mainnet_config_with_external(&path);
    // Hash is irrelevant here — structural validation fires first.
    node_cfg.expected_genesis_hash = Some([0u8; 32]);

    let err = run_boot_time_genesis_verification(&node_cfg)
        .expect_err("MainNet with empty bundle-signing authority roots must fail closed");
    let msg = err.to_string();
    assert!(
        msg.to_lowercase().contains("authority")
            || msg.to_lowercase().contains("bundle-signing"),
        "operator error must mention authority/bundle-signing, got: {}",
        msg
    );
    let _ = std::fs::remove_file(path);
}

// ===========================================================================
// §A5 — MainNet malformed authority root fingerprint rejects
// ===========================================================================

#[test]
fn run_102_mainnet_malformed_authority_root_rejects() {
    let mut cfg = mainnet_genesis_with_chain("qbind-mainnet-v0");
    cfg.authority.as_mut().unwrap().bundle_signing_authority_roots[0].key_fingerprint =
        "not-hex".into();
    let path = write_tmp_genesis(&cfg, "malformed_root");

    let mut node_cfg = mainnet_config_with_external(&path);
    node_cfg.expected_genesis_hash = Some([0u8; 32]);

    let err = run_boot_time_genesis_verification(&node_cfg)
        .expect_err("MainNet with malformed authority root must fail closed");
    let msg = err.to_string();
    assert!(
        msg.to_lowercase().contains("fingerprint")
            || msg.to_lowercase().contains("malformed")
            || msg.to_lowercase().contains("authority"),
        "operator error must indicate malformed root, got: {}",
        msg
    );
    let _ = std::fs::remove_file(path);
}

// ===========================================================================
// §A6 — MainNet env / chain_id mismatch rejects
// ===========================================================================

#[test]
fn run_102_mainnet_chain_environment_mismatch_rejects() {
    let cfg = mainnet_genesis_with_chain("qbind-devnet-v0"); // wrong env binding
    let h = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
    let path = write_tmp_genesis(&cfg, "env_mismatch");

    let mut node_cfg = mainnet_config_with_external(&path);
    node_cfg.expected_genesis_hash = Some(h);

    let err = run_boot_time_genesis_verification(&node_cfg)
        .expect_err("MainNet with non-mainnet chain_id must fail closed");
    let msg = err.to_string();
    assert!(
        msg.contains("chain_id") || msg.to_lowercase().contains("environment"),
        "operator error must mention chain_id/env binding, got: {}",
        msg
    );
    let _ = std::fs::remove_file(path);
}

// ===========================================================================
// §A7 — MainNet valid genesis + matching hash passes
// ===========================================================================

#[test]
fn run_102_mainnet_valid_genesis_passes() {
    let cfg = mainnet_genesis_with_chain("qbind-mainnet-v0");
    let h = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
    let path = write_tmp_genesis(&cfg, "valid");

    let mut node_cfg = mainnet_config_with_external(&path);
    node_cfg.expected_genesis_hash = Some(h);

    let outcome = run_boot_time_genesis_verification(&node_cfg)
        .expect("MainNet valid genesis + authority + matching hash must pass");
    match outcome {
        BootGenesisOutcome::Verified {
            canonical_hash,
            env,
            genesis_path,
        } => {
            assert_eq!(canonical_hash, h);
            assert_eq!(env, NetworkEnvironmentPolicy::Mainnet);
            assert_eq!(genesis_path, path);
        }
        BootGenesisOutcome::SkippedNoExternalGenesis { .. } => {
            panic!("MainNet must not skip Run 102 verification")
        }
    }
    let _ = std::fs::remove_file(path);
}

// ===========================================================================
// §A8 — MainNet malformed genesis file (not JSON) rejects
// ===========================================================================

#[test]
fn run_102_mainnet_malformed_genesis_file_rejects() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "qbind-run-102-malformed-{}-{}.json",
        std::process::id(),
        rand_suffix()
    ));
    std::fs::write(&path, b"{garbled").unwrap();

    let mut node_cfg = mainnet_config_with_external(&path);
    node_cfg.expected_genesis_hash = Some([0u8; 32]);

    let err = run_boot_time_genesis_verification(&node_cfg)
        .expect_err("MainNet with malformed genesis file must fail closed");
    match err {
        BootGenesisError::GenesisFileParseError { .. } => {}
        other => panic!("expected GenesisFileParseError, got: {}", other),
    }
    let _ = std::fs::remove_file(path);
}

// ===========================================================================
// §A9 — MainNet missing genesis file (I/O) rejects
// ===========================================================================

#[test]
fn run_102_mainnet_missing_genesis_file_rejects() {
    let bogus = PathBuf::from("/no/such/qbind-run-102-it-no-file.json");
    let mut node_cfg = mainnet_config_with_external(&bogus);
    node_cfg.expected_genesis_hash = Some([0u8; 32]);

    let err = run_boot_time_genesis_verification(&node_cfg)
        .expect_err("MainNet with missing genesis file must fail closed");
    match err {
        BootGenesisError::GenesisFileIoError { .. } => {}
        other => panic!("expected GenesisFileIoError, got: {}", other),
    }
}

// ===========================================================================
// §A10 — MainNet with no genesis_path (belt-and-braces fail-closed)
// ===========================================================================

#[test]
fn run_102_mainnet_no_genesis_path_rejects() {
    // Construct a MainNet NodeConfig with `use_external = true` but no path.
    let mut config = NodeConfig::new(NetworkEnvironment::Mainnet);
    config.genesis_source = GenesisSourceConfig::mainnet_default(); // use_external = true, path = None
    config.expected_genesis_hash = Some([0u8; 32]);

    let err = run_boot_time_genesis_verification(&config)
        .expect_err("MainNet without genesis_path must fail closed in Run 102");
    match err {
        BootGenesisError::GenesisPathMissing {
            env: NetworkEnvironmentPolicy::Mainnet,
        } => {}
        other => panic!("expected GenesisPathMissing, got: {}", other),
    }
}

// ===========================================================================
// §C1 — DevNet embedded genesis is preserved (Run 102 skips verification)
// ===========================================================================

#[test]
fn run_102_devnet_embedded_genesis_is_preserved() {
    let config = NodeConfig::devnet_v0_preset();
    let outcome = run_boot_time_genesis_verification(&config)
        .expect("DevNet embedded genesis path must remain usable");
    match outcome {
        BootGenesisOutcome::SkippedNoExternalGenesis {
            env: NetworkEnvironmentPolicy::Devnet,
        } => {}
        other => panic!(
            "DevNet without --genesis-path must SkippedNoExternalGenesis, got: {:?}",
            other
        ),
    }
}

// ===========================================================================
// §C2 — DevNet with explicit external genesis still verifies (permissive)
// ===========================================================================

#[test]
fn run_102_devnet_with_external_genesis_verifies() {
    let mut cfg = mainnet_genesis_with_chain("qbind-devnet-v0");
    cfg.authority = None; // DevNet permissive
    let path = write_tmp_genesis(&cfg, "devnet_external");

    let mut node_cfg = NodeConfig::new(NetworkEnvironment::Devnet);
    node_cfg.genesis_source = GenesisSourceConfig::external(path.clone());
    // No expected hash — DevNet allows missing.

    let outcome = run_boot_time_genesis_verification(&node_cfg)
        .expect("DevNet with external genesis (no authority, no expected hash) must pass");
    match outcome {
        BootGenesisOutcome::Verified { env, .. } => {
            assert_eq!(env, NetworkEnvironmentPolicy::Devnet);
        }
        other => panic!("expected Verified, got {:?}", other),
    }
    let _ = std::fs::remove_file(path);
}

// ===========================================================================
// §C3 — DevNet flags cannot bypass MainNet strictness
// ===========================================================================

#[test]
fn run_102_devnet_flag_does_not_bypass_mainnet_strictness() {
    // A MainNet `NodeConfig` with the DevNet-permissive-looking genesis
    // (no authority) must still be rejected — the verifier dispatches on
    // `config.environment`, not on operator-supplied genesis content.
    let mut cfg = mainnet_genesis_with_chain("qbind-mainnet-v0");
    cfg.authority = None; // a "DevNet-shaped" genesis
    let path = write_tmp_genesis(&cfg, "devnet_shaped_genesis_on_mainnet");

    let mut node_cfg = mainnet_config_with_external(&path);
    let h = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
    node_cfg.expected_genesis_hash = Some(h);

    let err = run_boot_time_genesis_verification(&node_cfg)
        .expect_err("MainNet must reject DevNet-shaped (no-authority) genesis");
    let msg = err.to_string();
    assert!(
        msg.to_lowercase().contains("authority"),
        "operator error must indicate missing authority, got: {}",
        msg
    );
    let _ = std::fs::remove_file(path);
}

// ===========================================================================
// §B parity — print-hash workflow uses a value pasteable into `--expect-genesis-hash`
// ===========================================================================

#[test]
fn run_102_print_then_expect_workflow_roundtrip() {
    let cfg = mainnet_genesis_with_chain("qbind-mainnet-v0");
    let path = write_tmp_genesis(&cfg, "roundtrip");

    // Step 1: operator runs `--print-genesis-hash` (same call as `main`).
    let printed = qbind_node::pqc_boot_genesis::compute_print_genesis_hash(
        &path,
        NetworkEnvironmentPolicy::Mainnet,
    )
    .unwrap();
    let printed_hex = format_genesis_hash(&printed);

    // Step 2: operator pastes the value into --expect-genesis-hash.
    let pinned = parse_genesis_hash(&printed_hex).expect("printed value must re-parse");

    // Step 3: subsequent startup invokes Run 102 verification with the pin.
    let mut node_cfg = mainnet_config_with_external(&path);
    node_cfg.expected_genesis_hash = Some(pinned);
    let outcome = run_boot_time_genesis_verification(&node_cfg)
        .expect("printed hash must be accepted by the verifier");
    assert_eq!(outcome.canonical_hash(), Some(&printed));

    let _ = std::fs::remove_file(path);
}