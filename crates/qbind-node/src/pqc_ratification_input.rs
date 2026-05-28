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

// ===========================================================================
// Run 132 — versioned sidecar loader/dispatcher
// ===========================================================================

/// Run 132 — typed result of versioned sidecar dispatch.
///
/// Allows validation-only surfaces to distinguish v1 and v2 ratification
/// sidecars after a single load, then dispatch to the correct verifier.
#[derive(Debug, Clone)]
pub enum VersionedRatificationSidecar {
    /// v1 sidecar (schema version 1). Uses the Run 103/105 verifier.
    V1(BundleSigningRatification),
    /// v2 sidecar (schema version 2). Uses the Run 130 verifier.
    V2(qbind_ledger::BundleSigningRatificationV2),
}

/// Run 132 — typed errors for versioned sidecar loading.
#[derive(Debug)]
pub enum VersionedRatificationInputError {
    /// I/O failure reading the sidecar JSON file.
    Io {
        path: std::path::PathBuf,
        error: std::io::Error,
    },
    /// The file at `path` did not parse as valid JSON.
    JsonParse {
        path: std::path::PathBuf,
        error: String,
    },
    /// The JSON object has no recognisable schema version field, or the
    /// version field is not a supported integer.
    UnknownSchemaVersion {
        path: std::path::PathBuf,
        got: Option<serde_json::Value>,
    },
    /// The schema version is a known integer but the full object does not
    /// parse into the expected typed struct.
    MalformedSidecar {
        path: std::path::PathBuf,
        schema_version: u32,
        error: String,
    },
}

impl std::fmt::Display for VersionedRatificationInputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, error } => write!(
                f,
                "[run-132] failed to read ratification sidecar file {}: {}. \
                 Release binary refuses to proceed (no fallback).",
                path.display(),
                error
            ),
            Self::JsonParse { path, error } => write!(
                f,
                "[run-132] failed to parse ratification sidecar JSON {}: {}. \
                 Release binary refuses to proceed (no fallback).",
                path.display(),
                error
            ),
            Self::UnknownSchemaVersion { path, got } => write!(
                f,
                "[run-132] ratification sidecar at {} has unknown or missing schema version \
                 (got {:?}). Only versions 1 and 2 are supported. Fail closed.",
                path.display(),
                got
            ),
            Self::MalformedSidecar {
                path,
                schema_version,
                error,
            } => write!(
                f,
                "[run-132] ratification sidecar at {} declared schema_version={} but \
                 failed to parse into the v{} typed struct: {}. Fail closed.",
                path.display(),
                schema_version,
                schema_version,
                error
            ),
        }
    }
}

impl std::error::Error for VersionedRatificationInputError {}

/// Run 132 — load a versioned ratification sidecar from a local JSON path.
///
/// Reads the file once, peeks at the schema version (v1 uses `version`,
/// v2 uses `schema_version`), and dispatches to the correct typed
/// deserialiser. Unknown versions fail closed.
///
/// # Guarantees
///
/// - No ambiguity between v1 and v2.
/// - Unknown schema version fails closed.
/// - Malformed sidecar fails closed.
/// - v1 deserialisation path is unchanged from [`load_ratification_from_path`].
/// - No file write, no persistence, no side effects.
pub fn load_versioned_ratification_from_path(
    path: &Path,
) -> Result<VersionedRatificationSidecar, VersionedRatificationInputError> {
    let bytes = std::fs::read(path).map_err(|error| VersionedRatificationInputError::Io {
        path: path.to_path_buf(),
        error,
    })?;

    // Parse as generic JSON value to peek at the version field.
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| VersionedRatificationInputError::JsonParse {
            path: path.to_path_buf(),
            error: e.to_string(),
        })?;

    // v2 uses `schema_version`, v1 uses `version`.
    let version_value = value.get("schema_version").or_else(|| value.get("version"));

    let version_int = match version_value.and_then(|v| v.as_u64()) {
        Some(v) => v as u32,
        None => {
            return Err(VersionedRatificationInputError::UnknownSchemaVersion {
                path: path.to_path_buf(),
                got: version_value.cloned(),
            });
        }
    };

    match version_int {
        1 => {
            let r: BundleSigningRatification = serde_json::from_value(value).map_err(|e| {
                VersionedRatificationInputError::MalformedSidecar {
                    path: path.to_path_buf(),
                    schema_version: 1,
                    error: e.to_string(),
                }
            })?;
            Ok(VersionedRatificationSidecar::V1(r))
        }
        2 => {
            let r: qbind_ledger::BundleSigningRatificationV2 = serde_json::from_value(value)
                .map_err(|e| VersionedRatificationInputError::MalformedSidecar {
                    path: path.to_path_buf(),
                    schema_version: 2,
                    error: e.to_string(),
                })?;
            Ok(VersionedRatificationSidecar::V2(r))
        }
        _ => Err(VersionedRatificationInputError::UnknownSchemaVersion {
            path: path.to_path_buf(),
            got: version_value.cloned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_crypto::MlDsa44Backend;
    use qbind_ledger::bundle_signing_ratification::test_helpers as ratification_helpers;
    use qbind_ledger::genesis::{
        GenesisAllocation, GenesisAuthorityConfig, GenesisAuthorityRoot, GenesisConfig,
        GenesisCouncilConfig, GenesisMonetaryConfig, GenesisValidator,
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
    };
    use qbind_ledger::{
        compute_canonical_genesis_hash, BundleSigningRatification, NetworkEnvironmentPolicy,
        RatificationEnvironment,
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
            vec![GenesisAllocation::new(
                format!("0x{}", "11".repeat(32)),
                100,
            )],
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

    // =========================================================================
    // Run 132 — versioned sidecar loader tests
    // =========================================================================

    #[test]
    fn run132_versioned_loader_dispatches_v1() {
        let r = mk_signed_ratification();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ratification_v1.json");
        let json = serde_json::to_vec_pretty(&r).unwrap();
        std::fs::write(&path, &json).unwrap();
        let loaded = load_versioned_ratification_from_path(&path).expect("load ok");
        assert!(matches!(loaded, VersionedRatificationSidecar::V1(_)));
        if let VersionedRatificationSidecar::V1(v1) = loaded {
            assert_eq!(v1.version, 1);
            assert_eq!(v1, r);
        }
    }

    #[test]
    fn run132_versioned_loader_dispatches_v2() {
        use qbind_ledger::bundle_signing_ratification::v2_test_helpers;
        use qbind_ledger::{BundleSigningRatificationV2Action, RatificationEnvironment};

        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let mut cfg = GenesisConfig::new(
            "qbind-mainnet-v0",
            1_738_000_000_000,
            vec![GenesisAllocation::new(
                format!("0x{}", "11".repeat(32)),
                100,
            )],
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

        let v2 = v2_test_helpers::build_signed_ratification_v2(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            1,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            1,
            BundleSigningRatificationV2Action::Ratify,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ratification_v2.json");
        let json = serde_json::to_vec_pretty(&v2).unwrap();
        std::fs::write(&path, &json).unwrap();
        let loaded = load_versioned_ratification_from_path(&path).expect("load ok");
        assert!(matches!(loaded, VersionedRatificationSidecar::V2(_)));
        if let VersionedRatificationSidecar::V2(loaded_v2) = loaded {
            assert_eq!(loaded_v2.schema_version, 2);
            assert_eq!(loaded_v2, v2);
        }
    }

    #[test]
    fn run132_versioned_loader_unknown_version_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ratification_v99.json");
        std::fs::write(&path, br#"{"version": 99, "chain_id": "test"}"#).unwrap();
        let err = load_versioned_ratification_from_path(&path).unwrap_err();
        assert!(matches!(
            err,
            VersionedRatificationInputError::UnknownSchemaVersion { .. }
        ));
    }

    #[test]
    fn run132_versioned_loader_malformed_json_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, b"{ this is not valid json").unwrap();
        let err = load_versioned_ratification_from_path(&path).unwrap_err();
        assert!(matches!(
            err,
            VersionedRatificationInputError::JsonParse { .. }
        ));
    }

    #[test]
    fn run132_versioned_loader_missing_version_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no_version.json");
        std::fs::write(&path, br#"{"chain_id": "test"}"#).unwrap();
        let err = load_versioned_ratification_from_path(&path).unwrap_err();
        assert!(matches!(
            err,
            VersionedRatificationInputError::UnknownSchemaVersion { .. }
        ));
    }

    #[test]
    fn run132_versioned_loader_missing_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let err = load_versioned_ratification_from_path(&path).unwrap_err();
        assert!(matches!(err, VersionedRatificationInputError::Io { .. }));
    }

    #[test]
    fn run132_v1_behavior_unchanged_through_versioned_loader() {
        // Verify that loading a v1 sidecar through the versioned loader
        // produces the same object as the original v1-only loader.
        let r = mk_signed_ratification();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ratification.json");
        let json = serde_json::to_vec_pretty(&r).unwrap();
        std::fs::write(&path, &json).unwrap();

        let v1_only = load_ratification_from_path(&path).expect("v1 load ok");
        let versioned = load_versioned_ratification_from_path(&path).expect("versioned load ok");
        if let VersionedRatificationSidecar::V1(v1) = versioned {
            assert_eq!(v1, v1_only);
        } else {
            panic!("expected V1 variant");
        }
    }
}
