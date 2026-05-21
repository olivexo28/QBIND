//! Run 102 — release-binary boot-time canonical genesis verification wiring.
//!
//! This module is the **only** call site in `qbind-node` that loads the
//! external `GenesisConfig` JSON file at boot, computes the canonical
//! Run 101 genesis hash, and dispatches to
//! [`qbind_ledger::verify_boot_time_genesis`] under the appropriate
//! [`qbind_ledger::NetworkEnvironmentPolicy`].
//!
//! It is invoked from `qbind-node`'s `main` function **before** any
//! authority-dependent behavior begins — that is, before the Run 069
//! `--p2p-trust-bundle-reload-check` hook, before the Run 077 peer-
//! candidate check, before any trust-bundle / P2P / consensus startup.
//! Refusal here always fails closed.
//!
//! # Environment policy (Run 102, composing with Run 101 and T233)
//!
//! | env     | external genesis file | expected hash | authority |
//! |---------|----------------------|--------------|-----------|
//! | DevNet  | optional             | optional     | optional  |
//! | TestNet | optional             | optional     | optional (passes through Run 101 partial-positive policy) |
//! | MainNet | **required**         | **required** | **required** |
//!
//! When no external genesis file is configured (the embedded-genesis
//! DevNet/TestNet path), the boot verifier returns
//! [`BootGenesisOutcome::SkippedNoExternalGenesis`] with a clear log
//! line and the existing embedded-genesis path continues unchanged. On
//! MainNet the existing T233 [`crate::node_config::MainnetConfigError::
//! ExpectedGenesisHashMissing`] shield in
//! [`crate::node_config::NodeConfig::validate_mainnet_invariants`] —
//! together with the MainNet `genesis_source` precondition — already
//! refuses MainNet startup before this verifier runs when either the
//! genesis path or the expected hash is absent, so the MainNet-strict
//! arms below are reachable only on misconfiguration of those shields
//! and are still required to fail closed in their own right.
//!
//! # What this module does NOT do
//!
//! - It does not implement peer-driven authority apply.
//! - It does not implement signing-key rotation, revocation, custody,
//!   anti-rollback persistence beyond the boot-time hash binding, or
//!   governance.
//! - It does not introduce production source-code root anchors. The
//!   authority is read **only** from the operator-supplied genesis file.
//!
//! See `task/RUN_102_TASK.txt`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_102.md`,
//! and `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.

use std::fmt;
use std::path::{Path, PathBuf};

use qbind_ledger::{
    compute_canonical_genesis_hash, format_genesis_hash, verify_boot_time_genesis,
    BootGenesisVerification, BootGenesisVerificationError, GenesisConfig, GenesisHash,
    NetworkEnvironmentPolicy,
};
use qbind_types::NetworkEnvironment;

use crate::node_config::NodeConfig;

/// Map the runtime `NetworkEnvironment` to the policy enum
/// used by `qbind-ledger`'s Run 101 authority + canonical-hash API.
///
/// This is a 1:1 mapping that mirrors the scope tags used by
/// [`qbind_types::NetworkEnvironment::scope`] and
/// [`qbind_ledger::NetworkEnvironmentPolicy::scope`]; the two scope
/// methods return the same `"DEV"` / `"TST"` / `"MAIN"` strings so the
/// canonical hash binding is identical regardless of which side of the
/// crate boundary the value originates from.
pub fn map_environment(env: NetworkEnvironment) -> NetworkEnvironmentPolicy {
    match env {
        NetworkEnvironment::Devnet => NetworkEnvironmentPolicy::Devnet,
        NetworkEnvironment::Testnet => NetworkEnvironmentPolicy::Testnet,
        NetworkEnvironment::Mainnet => NetworkEnvironmentPolicy::Mainnet,
    }
}

/// Outcome of [`run_boot_time_genesis_verification`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootGenesisOutcome {
    /// External genesis file was configured, parsed, and verified against
    /// the (optional) expected canonical hash per environment policy.
    Verified {
        canonical_hash: GenesisHash,
        env: NetworkEnvironmentPolicy,
        genesis_path: PathBuf,
    },
    /// No external genesis file was configured (DevNet / TestNet embedded
    /// genesis path). Skipped intentionally — never reachable on MainNet
    /// because the MainNet preset / T185 shield refuse the absence of
    /// `genesis_source.genesis_path`.
    SkippedNoExternalGenesis {
        env: NetworkEnvironmentPolicy,
    },
}

impl BootGenesisOutcome {
    /// Returns the verified canonical hash if a verification actually ran.
    pub fn canonical_hash(&self) -> Option<&GenesisHash> {
        match self {
            BootGenesisOutcome::Verified { canonical_hash, .. } => Some(canonical_hash),
            BootGenesisOutcome::SkippedNoExternalGenesis { .. } => None,
        }
    }
}

/// Typed errors emitted by [`run_boot_time_genesis_verification`].
///
/// Every variant fails closed; the binary must exit non-zero on receipt.
#[derive(Debug)]
pub enum BootGenesisError {
    /// `genesis_source.use_external == true` but `genesis_path` is `None`.
    /// Only reachable on MainNet if the upstream T232/T185 shields are
    /// bypassed; we still refuse here as a belt-and-braces fail-closed.
    GenesisPathMissing { env: NetworkEnvironmentPolicy },
    /// I/O failure reading the genesis file (file not found, permission
    /// denied, etc.).
    GenesisFileIoError {
        path: PathBuf,
        error: std::io::Error,
    },
    /// The file at `genesis_path` did not parse as a valid `GenesisConfig`
    /// JSON document.
    GenesisFileParseError {
        path: PathBuf,
        error: serde_json::Error,
    },
    /// The Run 101 canonical verification API rejected the configuration.
    /// Forwards the precise variant from `qbind-ledger`.
    Verification(BootGenesisVerificationError),
}

impl fmt::Display for BootGenesisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BootGenesisError::GenesisPathMissing { env } => write!(
                f,
                "[run-102] genesis_source.genesis_path is required on environment {:?} \
                 but is absent — release binary refuses to start (no embedded MainNet/TestNet \
                 fallback). See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_102.md.",
                env
            ),
            BootGenesisError::GenesisFileIoError { path, error } => write!(
                f,
                "[run-102] failed to read genesis file {}: {}. Release binary refuses to start.",
                path.display(),
                error
            ),
            BootGenesisError::GenesisFileParseError { path, error } => write!(
                f,
                "[run-102] failed to parse genesis file {} as JSON GenesisConfig: {}. \
                 Release binary refuses to start. No fallback to defaults.",
                path.display(),
                error
            ),
            BootGenesisError::Verification(e) => write!(f, "[run-102] {}", e),
        }
    }
}

impl std::error::Error for BootGenesisError {}

impl From<BootGenesisVerificationError> for BootGenesisError {
    fn from(e: BootGenesisVerificationError) -> Self {
        BootGenesisError::Verification(e)
    }
}

/// Load and parse the external `GenesisConfig` JSON file referenced by
/// `config.genesis_source.genesis_path`.
///
/// Refuses (typed error) on:
///   * `genesis_source.use_external == false` and `genesis_path` is `None`
///     (caller should treat this as "no external genesis configured" and
///     skip the call entirely);
///   * missing/unreadable file;
///   * malformed JSON;
///   * any structural failure surfaced by `serde_json::from_str` (e.g.
///     unknown required fields).
///
/// No defaults are filled in; no embedded fallback is consulted.
pub fn load_external_genesis(path: &Path) -> Result<GenesisConfig, BootGenesisError> {
    let bytes = std::fs::read(path).map_err(|error| BootGenesisError::GenesisFileIoError {
        path: path.to_path_buf(),
        error,
    })?;
    let cfg: GenesisConfig =
        serde_json::from_slice(&bytes).map_err(|error| BootGenesisError::GenesisFileParseError {
            path: path.to_path_buf(),
            error,
        })?;
    Ok(cfg)
}

/// Run 102 — release-binary boot-time genesis verification entry point.
///
/// Ordering (matches `task/RUN_102_TASK.txt` "Expected ordering"):
///
/// ```text
/// load genesis (external file)
/// → canonicalize/hash parsed genesis
/// → verify expected genesis hash according to environment policy
/// → validate genesis authority fields according to environment policy
/// → only then continue to trust-bundle processing / networking / consensus startup
/// ```
///
/// The Run 101 [`verify_boot_time_genesis`] function performs steps
/// 2–4 in one atomic call (structural+authority validation first, then
/// chain_id check, then canonical hash, then expected-hash compare); this
/// wrapper only adds step 1 (file I/O + parse) and the
/// `NetworkEnvironment → NetworkEnvironmentPolicy` mapping.
///
/// On any failure this returns a typed [`BootGenesisError`] — callers
/// in `main` MUST exit non-zero with the `Display` rendering. There is
/// no silent continue.
pub fn run_boot_time_genesis_verification(
    config: &NodeConfig,
) -> Result<BootGenesisOutcome, BootGenesisError> {
    let env_policy = map_environment(config.environment);

    // Path 1: no external genesis file configured. This is the
    // DevNet/TestNet embedded-genesis path. The MainNet preset always
    // sets `use_external = true` and the T185/T232 shields reject
    // `MainNet + genesis_path.is_none()` *before* we get here, but we
    // still refuse MainNet here belt-and-braces.
    if !config.genesis_source.use_external || config.genesis_source.genesis_path.is_none() {
        if matches!(env_policy, NetworkEnvironmentPolicy::Mainnet) {
            return Err(BootGenesisError::GenesisPathMissing { env: env_policy });
        }
        return Ok(BootGenesisOutcome::SkippedNoExternalGenesis { env: env_policy });
    }

    // Path 2: external genesis file is configured. Load + parse + verify.
    let path = config
        .genesis_source
        .genesis_path
        .as_ref()
        .expect("checked above");
    let genesis = load_external_genesis(path)?;

    let expected = config.expected_genesis_hash.as_ref();
    let BootGenesisVerification { canonical_hash } =
        verify_boot_time_genesis(env_policy, &genesis, expected)?;

    Ok(BootGenesisOutcome::Verified {
        canonical_hash,
        env: env_policy,
        genesis_path: path.clone(),
    })
}

/// Compute (but do not verify) the canonical Run 101 genesis hash for
/// the `--print-genesis-hash` operator surface.
///
/// Loads the external genesis JSON at `path`, parses it strictly, and
/// returns the canonical hash under the supplied `env_policy`. Malformed
/// genesis files are rejected with a typed error — no raw-file-byte
/// fallback exists (that was the pre-Run-101 behavior described in the
/// scenario_5 evidence note). Authority validation is **not** performed
/// here on purpose; the operator workflow is:
///
///   1. `qbind-node --print-genesis-hash --genesis-path G.json --env mainnet`
///      → prints canonical hash.
///   2. Operator pins that hash into `--expect-genesis-hash` at startup.
///   3. Startup invokes `run_boot_time_genesis_verification`, which
///      performs the full Run 101 authority + chain_id + expected-hash
///      check.
///
/// We keep `--print-genesis-hash` permissive on authority so that
/// operators can use it to inspect *any* candidate genesis file (e.g. a
/// pre-authority bootstrap file) without first being forced to satisfy
/// MainNet authority constraints.
pub fn compute_print_genesis_hash(
    path: &Path,
    env_policy: NetworkEnvironmentPolicy,
) -> Result<GenesisHash, BootGenesisError> {
    let genesis = load_external_genesis(path)?;
    Ok(compute_canonical_genesis_hash(&genesis, env_policy))
}

/// Format the canonical hash as a `0x`-prefixed lowercase hex string
/// suitable for `--print-genesis-hash` stdout and for pinning into
/// `--expect-genesis-hash`. Delegates to
/// [`qbind_ledger::format_genesis_hash`] for byte-for-byte parity with
/// the existing T233 operator workflow.
pub fn format_for_operator(hash: &GenesisHash) -> String {
    format_genesis_hash(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_ledger::{
        GenesisAllocation, GenesisAuthorityConfig, GenesisAuthorityRoot, GenesisCouncilConfig,
        GenesisMonetaryConfig, GenesisValidator, GENESIS_AUTHORITY_SUITE_ML_DSA_44,
    };
    use std::io::Write;

    fn fingerprint(seed: u8) -> String {
        format!("{:02x}", seed).repeat(32)
    }

    fn mainnet_genesis() -> GenesisConfig {
        let mut cfg = GenesisConfig::new(
            "qbind-mainnet-v0",
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
        let mut auth = GenesisAuthorityConfig::new(vec![GenesisAuthorityRoot::new(
            GENESIS_AUTHORITY_SUITE_ML_DSA_44,
            fingerprint(0xab),
            "foundation-bundle-signer-1",
        )]);
        auth.pqc_transport_roots = vec![GenesisAuthorityRoot::new(
            GENESIS_AUTHORITY_SUITE_ML_DSA_44,
            fingerprint(0xcd),
            "foundation-transport-1",
        )];
        cfg.authority = Some(auth);
        cfg
    }

    fn write_genesis_to_tmp(cfg: &GenesisConfig, name: &str) -> PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("qbind-run-102-{}-{}.json", name, std::process::id()));
        let mut f = std::fs::File::create(&path).expect("create tmp");
        let json = serde_json::to_string_pretty(cfg).expect("serialize");
        f.write_all(json.as_bytes()).expect("write");
        path
    }

    #[test]
    fn map_environment_is_1to1() {
        assert_eq!(
            map_environment(NetworkEnvironment::Devnet),
            NetworkEnvironmentPolicy::Devnet
        );
        assert_eq!(
            map_environment(NetworkEnvironment::Testnet),
            NetworkEnvironmentPolicy::Testnet
        );
        assert_eq!(
            map_environment(NetworkEnvironment::Mainnet),
            NetworkEnvironmentPolicy::Mainnet
        );
        // Scope strings must agree byte-for-byte so the canonical hash
        // domain-separation is identical across the crate boundary.
        assert_eq!(
            NetworkEnvironment::Mainnet.scope(),
            NetworkEnvironmentPolicy::Mainnet.scope()
        );
        assert_eq!(
            NetworkEnvironment::Testnet.scope(),
            NetworkEnvironmentPolicy::Testnet.scope()
        );
        assert_eq!(
            NetworkEnvironment::Devnet.scope(),
            NetworkEnvironmentPolicy::Devnet.scope()
        );
    }

    #[test]
    fn print_hash_loads_and_canonicalizes_mainnet_genesis() {
        let cfg = mainnet_genesis();
        let path = write_genesis_to_tmp(&cfg, "print_hash_ok");
        let h = compute_print_genesis_hash(&path, NetworkEnvironmentPolicy::Mainnet).unwrap();
        let expected = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        assert_eq!(h, expected);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn print_hash_rejects_malformed_json() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "qbind-run-102-malformed-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, b"{not valid json").unwrap();
        let err = compute_print_genesis_hash(&path, NetworkEnvironmentPolicy::Mainnet).unwrap_err();
        match err {
            BootGenesisError::GenesisFileParseError { .. } => {}
            other => panic!("expected GenesisFileParseError, got {:?}", other.to_string()),
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn print_hash_rejects_missing_file() {
        let err = compute_print_genesis_hash(
            Path::new("/no/such/file/qbind-run-102-missing.json"),
            NetworkEnvironmentPolicy::Mainnet,
        )
        .unwrap_err();
        match err {
            BootGenesisError::GenesisFileIoError { .. } => {}
            other => panic!("expected GenesisFileIoError, got {:?}", other.to_string()),
        }
    }

    #[test]
    fn print_hash_differs_for_authority_field_change() {
        let cfg1 = mainnet_genesis();
        let mut cfg2 = mainnet_genesis();
        // Mutate authority only — same chain_id, env, validators, etc.
        cfg2.authority
            .as_mut()
            .unwrap()
            .bundle_signing_authority_roots[0]
            .key_fingerprint = fingerprint(0x12);
        let p1 = write_genesis_to_tmp(&cfg1, "auth_a");
        let p2 = write_genesis_to_tmp(&cfg2, "auth_b");
        let h1 = compute_print_genesis_hash(&p1, NetworkEnvironmentPolicy::Mainnet).unwrap();
        let h2 = compute_print_genesis_hash(&p2, NetworkEnvironmentPolicy::Mainnet).unwrap();
        assert_ne!(h1, h2, "authority change must change canonical hash");
        let _ = std::fs::remove_file(p1);
        let _ = std::fs::remove_file(p2);
    }

    #[test]
    fn print_hash_differs_for_chain_id_change() {
        let mut cfg1 = mainnet_genesis();
        cfg1.chain_id = "qbind-mainnet-v0".to_string();
        let mut cfg2 = mainnet_genesis();
        cfg2.chain_id = "qbind-mainnet-v1".to_string();
        let p1 = write_genesis_to_tmp(&cfg1, "chain_a");
        let p2 = write_genesis_to_tmp(&cfg2, "chain_b");
        let h1 = compute_print_genesis_hash(&p1, NetworkEnvironmentPolicy::Mainnet).unwrap();
        let h2 = compute_print_genesis_hash(&p2, NetworkEnvironmentPolicy::Mainnet).unwrap();
        assert_ne!(h1, h2);
        let _ = std::fs::remove_file(p1);
        let _ = std::fs::remove_file(p2);
    }

    #[test]
    fn print_hash_differs_across_environments() {
        let cfg = mainnet_genesis();
        let path = write_genesis_to_tmp(&cfg, "env_diff");
        let h_main = compute_print_genesis_hash(&path, NetworkEnvironmentPolicy::Mainnet).unwrap();
        let h_test = compute_print_genesis_hash(&path, NetworkEnvironmentPolicy::Testnet).unwrap();
        let h_dev = compute_print_genesis_hash(&path, NetworkEnvironmentPolicy::Devnet).unwrap();
        assert_ne!(h_main, h_test);
        assert_ne!(h_main, h_dev);
        assert_ne!(h_test, h_dev);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn print_hash_is_canonical_not_raw_file_bytes() {
        // Same canonical genesis, two different JSON formattings (compact
        // vs. pretty-printed). Canonical hash must be identical; raw
        // file-byte hash would differ.
        let cfg = mainnet_genesis();
        let dir = std::env::temp_dir();
        let p_compact = dir.join(format!(
            "qbind-run-102-compact-{}.json",
            std::process::id()
        ));
        let p_pretty = dir.join(format!(
            "qbind-run-102-pretty-{}.json",
            std::process::id()
        ));
        std::fs::write(&p_compact, serde_json::to_string(&cfg).unwrap()).unwrap();
        std::fs::write(&p_pretty, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
        let h_compact =
            compute_print_genesis_hash(&p_compact, NetworkEnvironmentPolicy::Mainnet).unwrap();
        let h_pretty =
            compute_print_genesis_hash(&p_pretty, NetworkEnvironmentPolicy::Mainnet).unwrap();
        assert_eq!(
            h_compact, h_pretty,
            "canonical (parsed) hash must ignore JSON formatting"
        );
        let raw_compact = qbind_ledger::compute_genesis_hash_bytes(
            &std::fs::read(&p_compact).unwrap(),
        );
        let raw_pretty = qbind_ledger::compute_genesis_hash_bytes(
            &std::fs::read(&p_pretty).unwrap(),
        );
        assert_ne!(
            raw_compact, raw_pretty,
            "raw file-byte hash differs across formattings — proves Run 102 is canonical"
        );
        let _ = std::fs::remove_file(p_compact);
        let _ = std::fs::remove_file(p_pretty);
    }
}