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
    let version_value = value
        .get("schema_version")
        .or_else(|| value.get("version"));

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
            let r: qbind_ledger::BundleSigningRatificationV2 =
                serde_json::from_value(value).map_err(|e| {
                    VersionedRatificationInputError::MalformedSidecar {
                        path: path.to_path_buf(),
                        schema_version: 2,
                        error: e.to_string(),
                    }
                })?;
            Ok(VersionedRatificationSidecar::V2(r))
        }
        _ => Err(VersionedRatificationInputError::UnknownSchemaVersion {
            path: path.to_path_buf(),
            got: version_value.cloned(),
        }),
    }
}

// ===========================================================================
// Run 167 — additive optional governance-proof carrier on v2 sidecars
// ===========================================================================

use crate::pqc_governance_proof_wire::{
    GovernanceAuthorityProofWire, GovernanceProofLoadStatus, GovernanceProofWireParseError,
};

/// Run 167 — typed result of loading a v2 ratification sidecar together
/// with its optional [`GovernanceAuthorityProofWire`] sibling field.
///
/// The struct is purely additive: a v2 sidecar without the optional
/// `governance_authority_proof` JSON sibling continues to parse exactly
/// as it did before Run 167 and yields
/// [`GovernanceProofLoadStatus::Absent`]. A sidecar with a malformed
/// sibling yields [`GovernanceProofLoadStatus::Malformed`] (fail-closed
/// at the gate under any policy that requires a proof). A sidecar with
/// a well-formed sibling yields [`GovernanceProofLoadStatus::Available`]
/// carrying the typed Run 163
/// [`crate::pqc_governance_authority::GovernanceAuthorityProof`].
///
/// Run 167 does **NOT** mutate persisted state during parsing: no marker
/// write, no sequence write, no live trust swap, no session eviction.
#[derive(Debug, Clone)]
pub struct LoadedV2RatificationSidecar {
    pub ratification: qbind_ledger::BundleSigningRatificationV2,
    pub governance_proof: GovernanceProofLoadStatus,
}

/// Run 167 — load a v2 ratification sidecar JSON file and additionally
/// attempt to parse its optional
/// [`GovernanceAuthorityProofWire`] sibling field
/// (`governance_authority_proof`).
///
/// # Behaviour
///
/// * The optional sibling field is **strictly additive**. A v2 sidecar
///   without the field continues to parse as before Run 167 and yields
///   [`GovernanceProofLoadStatus::Absent`].
/// * A sibling that fails to deserialise as
///   [`GovernanceAuthorityProofWire`], or that carries an unknown
///   schema version, an empty required field, or an empty issuer
///   signature, yields [`GovernanceProofLoadStatus::Malformed`] —
///   never a partially-parsed proof. The v2 ratification itself is
///   still returned so the caller can fall through the policy/gate
///   pipeline (under `RequiredForLifecycleSensitive` the gate fails
///   closed; under `NotRequired` the gate is a no-op).
/// * A v1 sidecar at this path is rejected with
///   [`VersionedRatificationInputError::MalformedSidecar`] because the
///   Run 167 carrier is v2-only by design (the v1 verifier predates the
///   Run 159 lifecycle classification).
/// * No file write, no marker write, no sequence write, no live trust
///   swap, no session eviction.
pub fn load_v2_ratification_sidecar_with_governance_proof_from_path(
    path: &Path,
) -> Result<LoadedV2RatificationSidecar, VersionedRatificationInputError> {
    let bytes = std::fs::read(path).map_err(|error| VersionedRatificationInputError::Io {
        path: path.to_path_buf(),
        error,
    })?;

    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| VersionedRatificationInputError::JsonParse {
            path: path.to_path_buf(),
            error: e.to_string(),
        })?;

    let version_value = value
        .get("schema_version")
        .or_else(|| value.get("version"));
    let version_int = match version_value.and_then(|v| v.as_u64()) {
        Some(v) => v as u32,
        None => {
            return Err(VersionedRatificationInputError::UnknownSchemaVersion {
                path: path.to_path_buf(),
                got: version_value.cloned(),
            });
        }
    };
    if version_int != 2 {
        return Err(VersionedRatificationInputError::MalformedSidecar {
            path: path.to_path_buf(),
            schema_version: version_int,
            error: format!(
                "Run 167 governance-proof carrier requires v2 sidecar (got schema_version={})",
                version_int
            ),
        });
    }

    // Parse the optional sibling first so a malformed sibling does not
    // poison the v2 parse path. The optional sibling is a SEPARATE JSON
    // field; we extract it from the generic value, then re-deserialise
    // the rest into `BundleSigningRatificationV2`.
    let sibling = value.get("governance_authority_proof").cloned();
    let governance_proof = match sibling {
        None => GovernanceProofLoadStatus::Absent,
        Some(serde_json::Value::Null) => GovernanceProofLoadStatus::Absent,
        Some(raw) => match serde_json::from_value::<GovernanceAuthorityProofWire>(raw) {
            Ok(wire) => match wire.to_governance_authority_proof() {
                Ok(proof) => GovernanceProofLoadStatus::Available(proof),
                Err(e) => GovernanceProofLoadStatus::Malformed(e),
            },
            Err(e) => GovernanceProofLoadStatus::Malformed(GovernanceProofWireParseError::Json {
                error: e.to_string(),
            }),
        },
    };

    let ratification: qbind_ledger::BundleSigningRatificationV2 = serde_json::from_value(value)
        .map_err(|e| VersionedRatificationInputError::MalformedSidecar {
            path: path.to_path_buf(),
            schema_version: 2,
            error: e.to_string(),
        })?;

    Ok(LoadedV2RatificationSidecar {
        ratification,
        governance_proof,
    })
}

// ===========================================================================
// Run 169 — versioned dispatcher with optional governance-proof carrier
// ===========================================================================

/// Run 169 — typed result of dispatching a versioned ratification
/// sidecar AND, for v2 sidecars, parsing the optional Run 167
/// `governance_authority_proof` sibling.
///
/// v1 sidecars are unchanged (no governance-proof carrier was ever
/// defined for v1; the v1 verifier predates the Run 159 lifecycle
/// classification). v2 sidecars carry an additive
/// [`GovernanceProofLoadStatus`] alongside the typed
/// [`qbind_ledger::BundleSigningRatificationV2`].
#[derive(Debug, Clone)]
pub enum VersionedRatificationSidecarWithGovernanceProof {
    /// v1 sidecar (schema version 1). No governance-proof carrier.
    V1(BundleSigningRatification),
    /// v2 sidecar (schema version 2) with optional governance-proof
    /// carrier load status.
    V2 {
        ratification: qbind_ledger::BundleSigningRatificationV2,
        governance_proof: GovernanceProofLoadStatus,
    },
}

impl VersionedRatificationSidecarWithGovernanceProof {
    /// Project to the existing Run 132 [`VersionedRatificationSidecar`]
    /// for callers that do not consume governance-proof carrier data.
    /// The governance-proof load status is dropped.
    pub fn into_versioned_sidecar(self) -> VersionedRatificationSidecar {
        match self {
            Self::V1(r) => VersionedRatificationSidecar::V1(r),
            Self::V2 { ratification, .. } => VersionedRatificationSidecar::V2(ratification),
        }
    }

    /// Run 169 — return the governance-proof load status, or `Absent`
    /// for v1 sidecars (which never carry a Run 167 proof).
    pub fn governance_proof_load_status(&self) -> GovernanceProofLoadStatus {
        match self {
            Self::V1(_) => GovernanceProofLoadStatus::Absent,
            Self::V2 { governance_proof, .. } => governance_proof.clone(),
        }
    }
}

/// Run 169 — load a versioned ratification sidecar AND, for v2
/// sidecars, parse the optional Run 167 `governance_authority_proof`
/// sibling field. Drop-in successor for
/// [`load_versioned_ratification_from_path`] for callers that want the
/// typed Run 167 [`GovernanceProofLoadStatus`] available to the Run
/// 165 governance gate.
///
/// # Behaviour
///
/// * v1 sidecars: identical to [`load_versioned_ratification_from_path`].
/// * v2 sidecars: identical to
///   [`load_v2_ratification_sidecar_with_governance_proof_from_path`].
/// * Unknown schema version: fail closed
///   ([`VersionedRatificationInputError::UnknownSchemaVersion`]).
/// * Malformed sidecar: fail closed
///   ([`VersionedRatificationInputError::MalformedSidecar`]).
///
/// The optional `governance_authority_proof` sibling is **strictly
/// additive** — pre-Run-167 v2 sidecars continue to parse and yield
/// [`GovernanceProofLoadStatus::Absent`].
///
/// No file write, no marker write, no sequence write, no live trust
/// swap, no session eviction.
pub fn load_versioned_ratification_with_governance_proof_from_path(
    path: &Path,
) -> Result<VersionedRatificationSidecarWithGovernanceProof, VersionedRatificationInputError> {
    let bytes = std::fs::read(path).map_err(|error| VersionedRatificationInputError::Io {
        path: path.to_path_buf(),
        error,
    })?;

    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| VersionedRatificationInputError::JsonParse {
            path: path.to_path_buf(),
            error: e.to_string(),
        })?;

    let version_value = value
        .get("schema_version")
        .or_else(|| value.get("version"));
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
            Ok(VersionedRatificationSidecarWithGovernanceProof::V1(r))
        }
        2 => {
            // Reuse the Run 167 v2 loader by re-parsing via the
            // existing path-based entry to keep the governance-proof
            // sibling extraction logic single-sourced.
            let loaded = load_v2_ratification_sidecar_with_governance_proof_from_path(path)?;
            Ok(VersionedRatificationSidecarWithGovernanceProof::V2 {
                ratification: loaded.ratification,
                governance_proof: loaded.governance_proof,
            })
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
            None, None, None, None, None, None,
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
        assert!(matches!(
            err,
            VersionedRatificationInputError::Io { .. }
        ));
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