//! Run 105 — operator-supplied bundle-signing-key ratification input.
//!
//! This module is the **smallest** safe bridge between the operator-
//! supplied ratification artefact (a local JSON sidecar file produced
//! out-of-band by the genesis-bound bundle-signing authority) and the
//! Run 103/105 verifier surface in `qbind_ledger`.
//!
//! # Strict scope
//!
//! - **Local file only.** No network input. No peer / gossip input. No
//!   admin / RPC endpoint. The operator supplies a path to a JSON file
//!   they already control, identical to the trust assumption already
//!   used for `--p2p-trust-bundle`.
//! - **Read-only.** The loader reads the file once and parses it into
//!   a [`qbind_ledger::BundleSigningRatification`]. No file is written;
//!   no temp file is created; no on-disk persistence is touched.
//! - **No verification here.** Crypto / chain / environment / genesis
//!   / authority-root binding is performed by
//!   [`qbind_ledger::enforce_bundle_signing_key_ratification`]. This
//!   loader exists only to surface I/O / parse errors with operator-
//!   friendly typed reasons before the ratification ever reaches the
//!   verifier.
//! - **No defaulting.** A missing file is an error; an unreadable
//!   file is an error; an unparseable file is an error. There is no
//!   silent fallback to "no ratification".
//!
//! Run 105 is the **first** enforcement run for bundle-signing-key
//! ratification on non-mutating validation surfaces (startup
//! preflight, reload-check, peer-candidate-check). See
//! `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_105.md`.

use std::path::{Path, PathBuf};

use qbind_ledger::BundleSigningRatification;

/// Typed errors emitted by [`load_ratification_from_path`].
///
/// Every variant is precise enough to drive a fail-closed operator-log
/// line, in the same style as the Run 102/104 boot-genesis loader.
#[derive(Debug)]
pub enum RatificationInputError {
    /// I/O failure reading the sidecar JSON file (file not found,
    /// permission denied, etc.).
    Io {
        path: PathBuf,
        error: std::io::Error,
    },
    /// The file at `path` did not parse as a valid
    /// [`BundleSigningRatification`] JSON document.
    Parse {
        path: PathBuf,
        error: serde_json::Error,
    },
}

impl std::fmt::Display for RatificationInputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RatificationInputError::Io { path, error } => write!(
                f,
                "[run-105] failed to read bundle-signing ratification sidecar file {}: {}. \
                 Release binary refuses to proceed (no fallback).",
                path.display(),
                error
            ),
            RatificationInputError::Parse { path, error } => write!(
                f,
                "[run-105] failed to parse bundle-signing ratification sidecar JSON {}: {}. \
                 Release binary refuses to proceed (no fallback).",
                path.display(),
                error
            ),
        }
    }
}

impl std::error::Error for RatificationInputError {}

/// Load a ratification sidecar JSON file from a local path.
///
/// On success returns a fully-parsed [`BundleSigningRatification`]
/// object that is **structurally** valid (its fields decoded into the
/// declared types). The object has NOT been verified; callers MUST
/// pass it to [`qbind_ledger::enforce_bundle_signing_key_ratification`]
/// before treating it as authoritative.
pub fn load_ratification_from_path(
    path: &Path,
) -> Result<BundleSigningRatification, RatificationInputError> {
    let bytes = std::fs::read(path).map_err(|error| RatificationInputError::Io {
        path: path.to_path_buf(),
        error,
    })?;
    let r: BundleSigningRatification =
        serde_json::from_slice(&bytes).map_err(|error| RatificationInputError::Parse {
            path: path.to_path_buf(),
            error,
        })?;
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_crypto::MlDsa44Backend;
    use qbind_ledger::{
        compute_canonical_genesis_hash, BundleSigningRatification,
        NetworkEnvironmentPolicy, RatificationEnvironment,
    };
    use qbind_ledger::bundle_signing_ratification::test_helpers as ratification_helpers;
    use qbind_ledger::genesis::{
        GenesisAllocation, GenesisAuthorityConfig, GenesisAuthorityRoot, GenesisConfig,
        GenesisCouncilConfig, GenesisMonetaryConfig, GenesisValidator,
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
    };

    fn full_pk_hex(pk: &[u8]) -> String {
        let mut s = String::with_capacity(pk.len() * 2);
        for b in pk {
            use std::fmt::Write;
            let _ = write!(&mut s, "{:02x}", b);
        }
        s
    }

    fn mk_signed_ratification() -> BundleSigningRatification {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let mut cfg = GenesisConfig::new(
            "qbind-mainnet-v0",
            1_738_000_000_000,
            vec![GenesisAllocation::new(format!("0x{}", "11".repeat(32)), 100)],
            vec![GenesisValidator::new(
                format!("0x{}", "22".repeat(32)),
                "ab".repeat(32),
                100,
            )],
            GenesisCouncilConfig::new(
                vec![
                    format!("0x{}", "33".repeat(32)),
                    format!("0x{}", "44".repeat(32)),
                    format!("0x{}", "55".repeat(32)),
                ],
                2,
            ),
            GenesisMonetaryConfig::mainnet_default(),
        );
        let root = GenesisAuthorityRoot::new(
            GENESIS_AUTHORITY_SUITE_ML_DSA_44,
            &full_pk_hex(&auth_pk),
            "test-bundle-signing-1",
        );
        cfg.authority = Some(GenesisAuthorityConfig::new(vec![root]));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        ratification_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
        )
    }

    #[test]
    fn load_ratification_round_trips_through_json_file() {
        let r = mk_signed_ratification();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ratification.json");
        let json = serde_json::to_vec_pretty(&r).unwrap();
        std::fs::write(&path, &json).unwrap();
        let loaded = load_ratification_from_path(&path).expect("load ok");
        assert_eq!(loaded, r);
    }

    #[test]
    fn load_ratification_missing_file_is_typed_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let err = load_ratification_from_path(&path).unwrap_err();
        assert!(matches!(err, RatificationInputError::Io { .. }));
    }

    #[test]
    fn load_ratification_malformed_file_is_typed_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, b"{ this is not valid json").unwrap();
        let err = load_ratification_from_path(&path).unwrap_err();
        assert!(matches!(err, RatificationInputError::Parse { .. }));
    }
}