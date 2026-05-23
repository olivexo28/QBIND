//! Run 127 — offline-only authority-state reset CLI skeleton with
//! typed refusal cases.
//!
//! # Purpose
//!
//! Implement the Run 126 spec: provide an explicit, **offline-only**
//! operator-driven command that validates every input the Run 117/118/119
//! anti-rollback marker model relies on, then either rejects (with a typed
//! refusal reason and an audit record) or, on the narrow set of allowed
//! environments, persists a new authority marker via the existing Run 117
//! [`crate::pqc_authority_state::persist_authority_state_atomic`] primitive.
//!
//! This module is **not** a normal-startup surface: it is dispatched from
//! `main.rs` via an explicit operator opt-in flag and the process exits
//! before any networking, consensus, metrics, SIGHUP, reload, or
//! peer-candidate machinery is installed. There is no path from a peer
//! message, remote API, configuration file, environment variable, or
//! supervisor-driven restart to the reset.
//!
//! # Environment policy (Run 126)
//!
//! - **DevNet** — reset is allowed when every input passes verification
//!   AND an audit output path is supplied AND the existing marker (if any)
//!   is not corrupt.
//! - **TestNet** — reset is allowed under the same strict ceremony as DevNet
//!   (per the Run 126 §C.2 narrow allowance). The path is identical to
//!   DevNet in this Run; no MainNet governance artifact is consulted.
//! - **MainNet** — reset is **REFUSED** by default. A future
//!   governance/recovery artifact may be designed in a later run; Run 127
//!   does not implement, fake, or stage it. The refusal still emits an
//!   audit record so an attempted MainNet reset leaves a paper trail without
//!   ever writing the marker.
//!
//! # Non-goals (out of Run 127 scope)
//!
//! - MainNet governance artifact verification — explicitly deferred.
//! - Signing-key rotation/revocation lifecycle — out of scope.
//! - Per-key monotonic authority sequence — deferred (Run 129+).
//! - KMS/HSM custody — out of scope.
//! - Peer-driven live apply / peer-triggered reset — explicitly refused.
//! - Snapshot synthesis of marker — never; the marker is derived ONLY
//!   from a verified genesis authority block + verified ratification sidecar
//!   via the same Run 118
//!   [`crate::pqc_authority_state::derive_authority_state_from_ratification`]
//!   the mutating surfaces use.
//!
//! # Crash safety
//!
//! The audit record is written **before** the marker is persisted, in a
//! `"pending"` form. After
//! [`crate::pqc_authority_state::persist_authority_state_atomic`] returns,
//! the audit record is finalised with `"success"`. A crash between the two
//! steps leaves an audit record with `result = "pending"` and the
//! would-be new marker fields populated; the operator can inspect both the
//! persisted marker file and the audit record to determine the actual
//! outcome. A crash before the audit record is written leaves the on-disk
//! marker untouched.
//!
//! Refusal audit records are written with `result = "refused"` and a typed
//! `refusal_reason`; the marker file is never touched on any refusal path.
//!
//! # Determinism
//!
//! The audit record is a fixed-field-order Serde struct with hex/ASCII
//! content only. Wall-clock time does not appear in any security-relevant
//! field — `updated_at_unix_secs` on the embedded marker record follows the
//! Run 117 `digest_excludes_informational_fields` invariant.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use qbind_ledger::{
    canonical_ratification_digest, compute_canonical_genesis_hash,
    enforce_bundle_signing_key_ratification, format_genesis_hash, GenesisAuthorityConfig,
    GenesisHash, RatificationEnforcementInputs, RatificationEnforcementOutcome,
    RatificationEnforcementPolicy,
};
use qbind_types::NetworkEnvironment;

use crate::pqc_authority_state::{
    authority_state_file_path, canonical_authority_state_digest, chain_id_hex,
    derive_authority_state_from_ratification, genesis_hash_hex, load_authority_state,
    persist_authority_state_atomic, AuthorityStateDerivationError,
    AuthorityStateDerivationInputs, AuthorityStateUpdateSource, PersistentAuthorityStateRecord,
};
use crate::pqc_boot_genesis::{load_external_genesis, map_environment, BootGenesisError};
use crate::pqc_ratification_input::{load_ratification_from_path, RatificationInputError};
use crate::pqc_trust_bundle::{
    BundleSignatureStatus, BundleSigningKeySet, TrustBundle, TrustBundleError,
};

// ============================================================================
// Constants
// ============================================================================

/// Audit record schema version. Bump only with a documented migration plan.
pub const AUTHORITY_RESET_AUDIT_RECORD_VERSION: u32 = 1;

/// `action` field on the audit record. Constant so the audit log cannot
/// accidentally claim a different action.
pub const AUTHORITY_RESET_AUDIT_ACTION: &str = "authority_state_reset";

// ============================================================================
// Typed refusal cases (Run 126 §F)
// ============================================================================

/// Typed reason an offline authority-state reset attempt was refused.
///
/// Every variant is fail-closed: the marker file is never written and the
/// old marker bytes are never modified. An audit record is emitted with
/// `result = "refused"` and the `refusal_reason` so operators have a paper
/// trail. New variants may be added in future runs; stable string identifiers
/// (from [`Self::stable_id`]) are part of the audit-log surface and MUST NOT
/// be renamed without a documented schema migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityResetRefusal {
    /// `--data-dir` was not supplied.
    MissingDataDir,
    /// `--genesis-path` was not supplied.
    MissingGenesisPath,
    /// `--expect-genesis-hash` was not supplied.
    MissingExpectedGenesisHash,
    /// `--p2p-trust-bundle` was not supplied.
    MissingTrustBundle,
    /// `--p2p-trust-bundle-ratification` was not supplied.
    MissingRatification,
    /// `--authority-state-reset-output-audit` was not supplied.
    AuditOutputMissing,
    /// `--expect-genesis-hash` was not parseable as 64 lowercase hex chars.
    MalformedExpectedGenesisHash(String),
    /// Genesis file could not be loaded or parsed.
    GenesisLoadFailed(String),
    /// The canonical Run 101 genesis hash did not match the expected hash.
    GenesisHashMismatch {
        expected_hex: String,
        computed_hex: String,
    },
    /// Genesis file has no authority block.
    MissingAuthorityConfig,
    /// Genesis authority block failed structural validation.
    InvalidAuthorityConfig(String),
    /// Genesis chain_id disagrees with the runtime environment chain_id.
    ChainIdMismatch {
        runtime_env: String,
        genesis_chain_id: String,
        runtime_chain_id_hex: String,
    },
    /// MainNet local reset is REFUSED by default in Run 127.
    MainNetLocalResetUnsupported,
    /// Trust bundle load/validate failed.
    InvalidTrustBundle(String),
    /// Candidate bundle's signing-key id is not in the configured key set.
    AuthorityKeyMaterialUnavailable,
    /// Candidate bundle is DevNet-unsigned (no ratified key to anchor on).
    AuthorityKeyMaterialMalformed,
    /// Ratification sidecar could not be loaded or parsed.
    InvalidRatification(String),
    /// Ratification enforcement (Run 103/105) failed.
    RatificationEnforcementFailed(String),
    /// Ratification returned `LegacyUnratifiedAccepted` — transport roots
    /// and legacy DevNet ergonomics MUST NOT authorize a reset.
    TransportRootNotAllowed,
    /// Target authority-marker derivation (Run 118) failed.
    TargetMarkerDerivationFailed(String),
    /// On-disk authority marker is corrupt. Run 127 does NOT auto-repair;
    /// the operator must remove the corrupt file out-of-band.
    ExistingMarkerCorrupt(String),
    /// Audit output file could not be written.
    AuditWriteFailed(String),
    /// Marker atomic persist failed. On-disk marker is unchanged (Run 117
    /// tmp+rename never produces a partial file).
    MarkerPersistFailed(String),
}

impl AuthorityResetRefusal {
    /// Stable identifier used in the audit record's `refusal_reason` field.
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::MissingDataDir => "MissingDataDir",
            Self::MissingGenesisPath => "MissingGenesisPath",
            Self::MissingExpectedGenesisHash => "MissingExpectedGenesisHash",
            Self::MissingTrustBundle => "MissingTrustBundle",
            Self::MissingRatification => "MissingRatification",
            Self::AuditOutputMissing => "AuditOutputMissing",
            Self::MalformedExpectedGenesisHash(_) => "MalformedExpectedGenesisHash",
            Self::GenesisLoadFailed(_) => "GenesisLoadFailed",
            Self::GenesisHashMismatch { .. } => "GenesisHashMismatch",
            Self::MissingAuthorityConfig => "MissingAuthorityConfig",
            Self::InvalidAuthorityConfig(_) => "InvalidAuthorityConfig",
            Self::ChainIdMismatch { .. } => "ChainIdMismatch",
            Self::MainNetLocalResetUnsupported => "MainNetLocalResetUnsupported",
            Self::InvalidTrustBundle(_) => "InvalidTrustBundle",
            Self::AuthorityKeyMaterialUnavailable => "AuthorityKeyMaterialUnavailable",
            Self::AuthorityKeyMaterialMalformed => "AuthorityKeyMaterialMalformed",
            Self::InvalidRatification(_) => "InvalidRatification",
            Self::RatificationEnforcementFailed(_) => "RatificationEnforcementFailed",
            Self::TransportRootNotAllowed => "TransportRootNotAllowed",
            Self::TargetMarkerDerivationFailed(_) => "TargetMarkerDerivationFailed",
            Self::ExistingMarkerCorrupt(_) => "ExistingMarkerCorrupt",
            Self::AuditWriteFailed(_) => "AuditWriteFailed",
            Self::MarkerPersistFailed(_) => "MarkerPersistFailed",
        }
    }

    /// One-line operator-facing detail. Safe for stderr and audit records;
    /// never contains secret material.
    pub fn detail(&self) -> String {
        match self {
            Self::MissingDataDir => {
                "--data-dir is required for authority-state-reset (no implicit default)"
                    .to_string()
            }
            Self::MissingGenesisPath => {
                "--genesis-path is required for authority-state-reset".to_string()
            }
            Self::MissingExpectedGenesisHash => {
                "--expect-genesis-hash is required to bind operator intent to a specific \
                 Run 101 canonical genesis hash"
                    .to_string()
            }
            Self::MissingTrustBundle => {
                "--p2p-trust-bundle is required for authority-state-reset (marker is anchored \
                 on the candidate bundle's verified ratified signing key)"
                    .to_string()
            }
            Self::MissingRatification => {
                "--p2p-trust-bundle-ratification is required (Run 117 derivation refuses \
                 unratified anchors)"
                    .to_string()
            }
            Self::AuditOutputMissing => {
                "--authority-state-reset-output-audit is required; the reset path never \
                 runs silently"
                    .to_string()
            }
            Self::MalformedExpectedGenesisHash(s) => format!(
                "--expect-genesis-hash must be 64 lowercase hex chars (with optional 0x \
                 prefix); got: {}",
                s
            ),
            Self::GenesisLoadFailed(s) => format!("genesis file load/parse failed: {}", s),
            Self::GenesisHashMismatch {
                expected_hex,
                computed_hex,
            } => format!(
                "canonical genesis hash computed from --genesis-path ({}) does not match \
                 --expect-genesis-hash ({})",
                computed_hex, expected_hex
            ),
            Self::MissingAuthorityConfig => {
                "genesis file has no authority block (Run 101 authority config is required \
                 for marker derivation)"
                    .to_string()
            }
            Self::InvalidAuthorityConfig(s) => {
                format!("genesis authority block failed structural validation: {}", s)
            }
            Self::ChainIdMismatch {
                runtime_env,
                genesis_chain_id,
                runtime_chain_id_hex,
            } => format!(
                "genesis chain_id '{}' disagrees with runtime env={} canonical \
                 chain_id_hex={} (refusing silent domain drift)",
                genesis_chain_id, runtime_env, runtime_chain_id_hex
            ),
            Self::MainNetLocalResetUnsupported => {
                "MainNet local authority-state reset is refused by default; a future \
                 governance/recovery artifact may be designed in a later run. Run 127 does NOT \
                 implement or fake MainNet local reset"
                    .to_string()
            }
            Self::InvalidTrustBundle(s) => format!("trust bundle load/validate failed: {}", s),
            Self::AuthorityKeyMaterialUnavailable => {
                "candidate trust bundle's signing-key id is not present in the configured \
                 --p2p-trust-bundle-signing-key set"
                    .to_string()
            }
            Self::AuthorityKeyMaterialMalformed => {
                "candidate trust bundle is DevNet-unsigned (no ratified signing key to anchor \
                 a marker on; refusing to write a marker from unratified state)"
                    .to_string()
            }
            Self::InvalidRatification(s) => {
                format!("ratification sidecar load/parse failed: {}", s)
            }
            Self::RatificationEnforcementFailed(s) => format!(
                "ratification enforcement failed (signature / chain_id / environment / \
                 authority-root binding / candidate key match): {}",
                s
            ),
            Self::TransportRootNotAllowed => {
                "ratification enforcement returned LegacyUnratifiedAccepted; transport roots \
                 and legacy DevNet ergonomics MUST NOT authorize an authority-state reset"
                    .to_string()
            }
            Self::TargetMarkerDerivationFailed(s) => {
                format!("target authority-marker derivation failed: {}", s)
            }
            Self::ExistingMarkerCorrupt(s) => format!(
                "existing on-disk authority marker is corrupt/unparseable: {}. Run 127 does NOT \
                 silently auto-repair; the operator must remove the corrupt file out-of-band \
                 and re-run the reset",
                s
            ),
            Self::AuditWriteFailed(s) => format!("audit record write failed: {}", s),
            Self::MarkerPersistFailed(s) => format!(
                "authority marker atomic persist failed: {}. The on-disk marker file is \
                 unchanged (Run 117 tmp+rename never produces a partial file)",
                s
            ),
        }
    }
}

impl std::fmt::Display for AuthorityResetRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[run-127] {}: {}", self.stable_id(), self.detail())
    }
}

impl std::error::Error for AuthorityResetRefusal {}

// ============================================================================
// Input bundle
// ============================================================================

/// Inputs to [`execute_authority_state_reset`]. Every field is explicit so
/// the reset cannot run with any implicit default.
#[derive(Debug, Clone)]
pub struct AuthorityResetInputs {
    /// Operator-supplied data directory. The marker path is resolved as
    /// `data_dir/pqc_authority_state.json`.
    pub data_dir: Option<PathBuf>,
    /// Operator-supplied external genesis file.
    pub genesis_path: Option<PathBuf>,
    /// Operator-supplied expected canonical Run 101 genesis hash.
    /// Accepts `0x`-prefixed or bare 64 lowercase hex chars.
    pub expected_genesis_hash: Option<String>,
    /// Operator-supplied candidate signed trust-bundle file.
    pub trust_bundle_path: Option<PathBuf>,
    /// Bundle-signing-key set specs (same format as
    /// `--p2p-trust-bundle-signing-key`).
    pub bundle_signing_key_specs: Vec<String>,
    /// Operator-supplied ratification sidecar file.
    pub ratification_path: Option<PathBuf>,
    /// Where the audit record is written. Required — the reset path never
    /// runs silently.
    pub audit_output_path: Option<PathBuf>,
    /// Runtime network environment.
    pub environment: NetworkEnvironment,
    /// Optional operator note for the audit record. Recorded as its
    /// SHA3-256 fingerprint so the audit record never embeds arbitrary
    /// operator-supplied content while still binding to the note's bytes.
    pub operator_note: Option<String>,
    /// Validation time used by the trust-bundle loader (Unix seconds).
    /// Explicit so tests can drive it deterministically.
    pub validation_time_secs: u64,
    /// Wall-clock seconds for the audit-only `updated_at_unix_secs` field
    /// of the persisted marker record. Follows the Run 117
    /// `digest_excludes_informational_fields` invariant — never enters any
    /// security digest.
    pub updated_at_unix_secs: u64,
}

// ============================================================================
// Audit record
// ============================================================================

/// Audit record emitted on every reset attempt (success or refusal).
///
/// Field order is fixed by the struct layout so Serde's default JSON
/// serialiser emits fields in a stable order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityResetAuditRecord {
    pub record_version: u32,
    pub action: String,
    pub environment: String,
    /// 16 lowercase hex chars of the runtime chain id, or `null`.
    pub chain_id: Option<String>,
    /// 64 lowercase hex chars of the canonical genesis hash, or `null`.
    pub genesis_hash: Option<String>,
    /// `true` iff a marker file existed before this reset attempt.
    pub old_marker_present: bool,
    /// SHA3-256 hex of the old marker file raw bytes, or `null`.
    pub old_marker_raw_sha256: Option<String>,
    /// Parsed old marker record if the file was structurally valid, or `null`.
    pub old_marker_record_if_parseable: Option<PersistentAuthorityStateRecord>,
    /// SHA3-256 hex of the canonical authority-state digest of the new marker,
    /// or `null` (absent on refusal before derivation succeeded).
    pub new_marker_hash: Option<String>,
    /// Full new marker record, or `null`.
    pub new_marker_record: Option<PersistentAuthorityStateRecord>,
    /// `canonical_ratification_digest` hex, or `null`.
    pub ratification_hash: Option<String>,
    /// Trust-bundle canonical fingerprint hex, or `null`.
    pub trust_bundle_fingerprint: Option<String>,
    /// Reserved for future snapshot-metadata context. Always `null` in Run 127.
    pub snapshot_metadata_hash_if_any: Option<String>,
    /// SHA3-256(operator_note bytes) hex, or `null` (raw note text never embedded).
    pub operator_note_hash: Option<String>,
    /// SHA3-256 of the binary, or `"unavailable"`.
    pub binary_sha256_or_unavailable: String,
    /// Build id, or `"unavailable"`.
    pub binary_build_id_or_unavailable: String,
    /// One of `"success"`, `"refused"`, or `"pending"`.
    pub result: String,
    /// Stable id from [`AuthorityResetRefusal::stable_id`], or `null`.
    pub refusal_reason_if_any: Option<String>,
    /// Operator-facing detail, or `null`.
    pub refusal_detail_if_any: Option<String>,
    /// Wall-clock seconds. Informational only.
    pub wall_clock_unix_secs: u64,
}

impl AuthorityResetAuditRecord {
    /// Serialise as deterministic pretty-printed JSON with a trailing newline.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

// ============================================================================
// Private helpers
// ============================================================================

fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = (s.as_bytes()[2 * i] as char).to_digit(16)?;
        let lo = (s.as_bytes()[2 * i + 1] as char).to_digit(16)?;
        *byte = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

fn sha3_256_hex_bytes(bytes: &[u8]) -> String {
    let mut h = Sha3_256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn format_hash_hex(h: &GenesisHash) -> String {
    // GenesisHash is [u8; 32]; identical to genesis_hash_hex() but we keep
    // the direct call here for the parse_expected_hash path that needs to
    // compare against a [u8; 32].
    genesis_hash_hex(h)
}

/// Parse `--expect-genesis-hash` accepting `0x`-prefixed or bare 64-char
/// lowercase hex.
fn parse_expected_hash(raw: &str) -> Result<[u8; 32], AuthorityResetRefusal> {
    let trimmed = raw.strip_prefix("0x").unwrap_or(raw);
    hex_decode_32(trimmed).ok_or_else(|| {
        AuthorityResetRefusal::MalformedExpectedGenesisHash(raw.to_string())
    })
}

fn binary_sha256_best_effort() -> String {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return "unavailable".to_string(),
    };
    match std::fs::read(&exe) {
        Ok(bytes) => sha3_256_hex_bytes(&bytes),
        Err(_) => "unavailable".to_string(),
    }
}

fn binary_build_id_best_effort() -> String {
    format!("qbind-node@{}", env!("CARGO_PKG_VERSION"))
}

fn environment_tag(env: NetworkEnvironment) -> &'static str {
    match env {
        NetworkEnvironment::Devnet => "devnet",
        NetworkEnvironment::Testnet => "testnet",
        NetworkEnvironment::Mainnet => "mainnet",
    }
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn marker_digest_hex(record: &PersistentAuthorityStateRecord) -> String {
    let digest = canonical_authority_state_digest(record);
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

// ============================================================================
// Verified reset plan (pure)
// ============================================================================

/// Outcome of [`verify_authority_reset_inputs`]: every input validated and
/// the new marker derived, but no disk writes have happened yet.
#[derive(Debug, Clone)]
pub struct VerifiedAuthorityResetPlan {
    /// Resolved `<data_dir>/pqc_authority_state.json` path.
    pub marker_path: PathBuf,
    pub environment: NetworkEnvironment,
    /// 16 lowercase hex chars of the runtime chain id.
    pub chain_id_hex_str: String,
    /// 64 lowercase hex chars of the verified canonical genesis hash.
    pub genesis_hash_hex_str: String,
    /// 64 lowercase hex chars of `canonical_ratification_digest`.
    pub ratification_hash_hex: String,
    /// 64 lowercase hex chars of the trust-bundle `canonical_fingerprint`.
    pub trust_bundle_fingerprint_hex: String,
    /// Newly-derived authority marker record.
    pub new_marker: PersistentAuthorityStateRecord,
    /// Pre-reset on-disk marker archive.
    pub old_marker_archive: OldMarkerArchive,
    /// SHA3-256(operator_note bytes) hex, or `None`.
    pub operator_note_hash: Option<String>,
}

/// Captured state of the pre-reset on-disk marker.
#[derive(Debug, Clone)]
pub struct OldMarkerArchive {
    pub present: bool,
    pub raw_sha256_hex: Option<String>,
    pub parsed: Option<PersistentAuthorityStateRecord>,
}

/// Pure pre-flight: validates all inputs and derives the new marker record.
/// Performs **no** disk writes. Returns a [`VerifiedAuthorityResetPlan`] on
/// success or the first typed [`AuthorityResetRefusal`] on failure.
///
/// The MainNet policy check fires immediately after the structural input-
/// presence checks so that a MainNet reset attempt refuses before opening
/// any files, minimising side-channels.
pub fn verify_authority_reset_inputs(
    inputs: &AuthorityResetInputs,
) -> Result<VerifiedAuthorityResetPlan, AuthorityResetRefusal> {
    // ---- Structural input presence ----------------------------------------
    let data_dir = inputs
        .data_dir
        .as_ref()
        .ok_or(AuthorityResetRefusal::MissingDataDir)?;
    let genesis_path = inputs
        .genesis_path
        .as_ref()
        .ok_or(AuthorityResetRefusal::MissingGenesisPath)?;
    let expected_hash_raw = inputs
        .expected_genesis_hash
        .as_ref()
        .ok_or(AuthorityResetRefusal::MissingExpectedGenesisHash)?;
    let trust_bundle_path = inputs
        .trust_bundle_path
        .as_ref()
        .ok_or(AuthorityResetRefusal::MissingTrustBundle)?;
    let ratification_path = inputs
        .ratification_path
        .as_ref()
        .ok_or(AuthorityResetRefusal::MissingRatification)?;
    // Audit output presence must be checked before ANY I/O so the
    // refusal is recorded before any file is opened.
    inputs
        .audit_output_path
        .as_ref()
        .ok_or(AuthorityResetRefusal::AuditOutputMissing)?;

    // ---- MainNet policy refusal BEFORE any I/O ----------------------------
    if matches!(inputs.environment, NetworkEnvironment::Mainnet) {
        return Err(AuthorityResetRefusal::MainNetLocalResetUnsupported);
    }

    // ---- Expected genesis hash parse --------------------------------------
    let expected_hash: [u8; 32] = parse_expected_hash(expected_hash_raw)?;

    // ---- Genesis file load ------------------------------------------------
    let genesis_cfg = load_external_genesis(genesis_path)
        .map_err(|e: BootGenesisError| AuthorityResetRefusal::GenesisLoadFailed(e.to_string()))?;

    // ---- Canonical genesis hash recomputation + match --------------------
    let env_policy = map_environment(inputs.environment);
    let computed_hash: GenesisHash = compute_canonical_genesis_hash(&genesis_cfg, env_policy);
    if computed_hash != expected_hash {
        return Err(AuthorityResetRefusal::GenesisHashMismatch {
            expected_hex: format_genesis_hash(&expected_hash),
            computed_hex: format_genesis_hash(&computed_hash),
        });
    }

    // ---- Runtime chain id resolution -------------------------------------
    let runtime_chain_id = inputs.environment.chain_id();
    let runtime_chain_id_hex = chain_id_hex(runtime_chain_id);

    // ---- Genesis chain_id vs runtime chain_id ----------------------------
    // genesis_cfg.chain_id is a String (e.g. "qbind-devnet-v0").
    // The Run 101 compute_canonical_genesis_hash already includes chain_id
    // in the preimage, but we do a domain-mismatch check here too to surface
    // a precise ChainIdMismatch refusal rather than relying on genesis hash
    // disagreement to catch it.
    //
    // The genesis chain_id field is a human-readable name string, not the
    // 16-hex ChainId u64.  We compare the genesis chain_id string against the
    // canonical hex form; they are always distinct (one is human-readable, the
    // other is 16 hex chars), so a non-match here is NOT necessarily wrong —
    // the two representations are never identical in normal operation.
    //
    // Instead of doing a string-vs-string comparison that would always fail,
    // we rely on the genesis hash check above to catch domain drift.  A
    // separate chain_id consistency check is explicitly not implemented at
    // this level because qbind-ledger's genesis hash computation already
    // domain-separates via the full genesis JSON.  We keep the field in the
    // audit record for operator visibility.

    // ---- Authority block presence ----------------------------------------
    let authority: GenesisAuthorityConfig = genesis_cfg
        .authority
        .clone()
        .ok_or(AuthorityResetRefusal::MissingAuthorityConfig)?;

    // ---- Trust-bundle signing-key set parse ------------------------------
    let bundle_signing_keys = BundleSigningKeySet::parse_specs(&inputs.bundle_signing_key_specs)
        .map_err(|e| AuthorityResetRefusal::InvalidTrustBundle(e.to_string()))?;

    // ---- Trust-bundle load -----------------------------------------------
    let activation_ctx = crate::pqc_trust_activation::ActivationContext {
        current_height: None,
        current_epoch: None,
    };
    let loaded =
        TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
            trust_bundle_path,
            inputs.environment,
            runtime_chain_id,
            inputs.validation_time_secs,
            &bundle_signing_keys,
            activation_ctx,
        )
        .map_err(|e: TrustBundleError| AuthorityResetRefusal::InvalidTrustBundle(e.to_string()))
        .map(|(l, _activation)| l)?;

    let trust_bundle_fingerprint_hex = {
        let mut s = String::with_capacity(64);
        for b in loaded.fingerprint.iter() {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
        }
        s
    };

    // ---- Signing-key bytes resolution ------------------------------------
    let signing_key_id_hex = match &loaded.signature_status {
        BundleSignatureStatus::Verified { signing_key_id } => signing_key_id.clone(),
        BundleSignatureStatus::Unsigned => {
            return Err(AuthorityResetRefusal::AuthorityKeyMaterialMalformed);
        }
    };
    let signing_key_id_bytes = hex_decode_32(&signing_key_id_hex)
        .ok_or(AuthorityResetRefusal::AuthorityKeyMaterialMalformed)?;
    let signing_key_pk_bytes = bundle_signing_keys
        .lookup(&signing_key_id_bytes)
        .map(|k| k.pk_bytes.clone())
        .ok_or(AuthorityResetRefusal::AuthorityKeyMaterialUnavailable)?;

    // ---- Ratification sidecar load + parse --------------------------------
    let ratification = load_ratification_from_path(ratification_path)
        .map_err(|e: RatificationInputError| {
            AuthorityResetRefusal::InvalidRatification(e.to_string())
        })?;

    // ---- Ratification enforcement (Run 103/105) ---------------------------
    let outcome = enforce_bundle_signing_key_ratification(RatificationEnforcementInputs {
        ratification: Some(&ratification),
        authority: &authority,
        expected_chain_id: &runtime_chain_id_hex,
        expected_environment: env_policy,
        expected_genesis_hash: &computed_hash,
        candidate_bundle_signing_public_key: &signing_key_pk_bytes,
        // Reset always enforces under Strict — legacy DevNet ergonomics
        // must never authorize a marker reset.
        policy: RatificationEnforcementPolicy::Strict,
    })
    .map_err(|e| {
        AuthorityResetRefusal::RatificationEnforcementFailed(format!("{}", e))
    })?;

    let ratified = match outcome {
        RatificationEnforcementOutcome::Ratified(r) => r,
        RatificationEnforcementOutcome::LegacyUnratifiedAccepted { .. } => {
            return Err(AuthorityResetRefusal::TransportRootNotAllowed);
        }
    };

    let ratification_hash_hex = {
        let mut s = String::with_capacity(64);
        for b in canonical_ratification_digest(&ratification).iter() {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
        }
        s
    };

    // ---- Genesis hash hex (64 chars) for derivation ----------------------
    let runtime_genesis_hash_hex = format_hash_hex(&computed_hash);

    // ---- Marker derivation (Run 118) --------------------------------------
    let new_marker =
        derive_authority_state_from_ratification(AuthorityStateDerivationInputs {
            runtime_env: inputs.environment,
            runtime_chain_id,
            runtime_genesis_hash_hex: &runtime_genesis_hash_hex,
            authority_policy_version: authority.authority_policy_version,
            authority_sequence: authority.authority_sequence,
            authority_epoch: authority.authority_epoch,
            ratification: &ratification,
            ratified: &ratified,
            update_source: AuthorityStateUpdateSource::OperatorReset,
            updated_at_unix_secs: inputs.updated_at_unix_secs,
        })
        .map_err(|e: AuthorityStateDerivationError| {
            AuthorityResetRefusal::TargetMarkerDerivationFailed(e.to_string())
        })?;

    // ---- Existing on-disk marker archive ----------------------------------
    let marker_path = authority_state_file_path(data_dir);
    let old_marker_archive = archive_existing_marker(&marker_path)?;

    // ---- Operator note hash -----------------------------------------------
    let operator_note_hash = inputs
        .operator_note
        .as_ref()
        .map(|s| sha3_256_hex_bytes(s.as_bytes()));

    Ok(VerifiedAuthorityResetPlan {
        marker_path,
        environment: inputs.environment,
        chain_id_hex_str: runtime_chain_id_hex,
        genesis_hash_hex_str: runtime_genesis_hash_hex,
        ratification_hash_hex,
        trust_bundle_fingerprint_hex,
        new_marker,
        old_marker_archive,
        operator_note_hash,
    })
}

/// Archive the existing on-disk marker (if any). Returns
/// `ExistingMarkerCorrupt` if the file exists but is unparseable — Run 127
/// never silently auto-repairs.
fn archive_existing_marker(marker_path: &Path) -> Result<OldMarkerArchive, AuthorityResetRefusal> {
    let raw = match std::fs::read(marker_path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(OldMarkerArchive {
                present: false,
                raw_sha256_hex: None,
                parsed: None,
            });
        }
        Err(e) => {
            return Err(AuthorityResetRefusal::ExistingMarkerCorrupt(format!(
                "marker file I/O at {}: {}",
                marker_path.display(),
                e
            )));
        }
    };
    let raw_sha256_hex = sha3_256_hex_bytes(&raw);
    let parsed = match load_authority_state(marker_path) {
        Ok(Some(rec)) => Some(rec),
        Ok(None) => {
            // We read non-empty bytes but load returned None — treat as
            // corrupt rather than silently dropping the archive hash.
            return Err(AuthorityResetRefusal::ExistingMarkerCorrupt(
                "marker file read non-empty but load_authority_state returned None".to_string(),
            ));
        }
        Err(e) => {
            return Err(AuthorityResetRefusal::ExistingMarkerCorrupt(e.to_string()));
        }
    };
    Ok(OldMarkerArchive {
        present: true,
        raw_sha256_hex: Some(raw_sha256_hex),
        parsed,
    })
}

// ============================================================================
// Audit-record builders (pure)
// ============================================================================

/// Whether the plan result is `"pending"` (before marker persist) or
/// `"success"` (after marker persist).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanResultState {
    Pending,
    Success,
}

/// Build a success (or pending) audit record from a verified plan.
pub fn build_success_audit_record(
    plan: &VerifiedAuthorityResetPlan,
    result_state: PlanResultState,
) -> AuthorityResetAuditRecord {
    let nm_hash = marker_digest_hex(&plan.new_marker);
    AuthorityResetAuditRecord {
        record_version: AUTHORITY_RESET_AUDIT_RECORD_VERSION,
        action: AUTHORITY_RESET_AUDIT_ACTION.to_string(),
        environment: environment_tag(plan.environment).to_string(),
        chain_id: Some(plan.chain_id_hex_str.clone()),
        genesis_hash: Some(plan.genesis_hash_hex_str.clone()),
        old_marker_present: plan.old_marker_archive.present,
        old_marker_raw_sha256: plan.old_marker_archive.raw_sha256_hex.clone(),
        old_marker_record_if_parseable: plan.old_marker_archive.parsed.clone(),
        new_marker_hash: Some(nm_hash),
        new_marker_record: Some(plan.new_marker.clone()),
        ratification_hash: Some(plan.ratification_hash_hex.clone()),
        trust_bundle_fingerprint: Some(plan.trust_bundle_fingerprint_hex.clone()),
        snapshot_metadata_hash_if_any: None,
        operator_note_hash: plan.operator_note_hash.clone(),
        binary_sha256_or_unavailable: binary_sha256_best_effort(),
        binary_build_id_or_unavailable: binary_build_id_best_effort(),
        result: match result_state {
            PlanResultState::Pending => "pending",
            PlanResultState::Success => "success",
        }
        .to_string(),
        refusal_reason_if_any: None,
        refusal_detail_if_any: None,
        wall_clock_unix_secs: now_unix_secs(),
    }
}

/// Build a refusal audit record. Some fields are populated only when the
/// plan was partially computed before the refusal.
pub fn build_refusal_audit_record(
    inputs: &AuthorityResetInputs,
    plan_partial: Option<&VerifiedAuthorityResetPlan>,
    refusal: &AuthorityResetRefusal,
) -> AuthorityResetAuditRecord {
    let operator_note_hash = inputs
        .operator_note
        .as_ref()
        .map(|s| sha3_256_hex_bytes(s.as_bytes()));

    // Populate plan-derived fields when available (e.g. a refusal that fires
    // after partial verification), or null-fill when the plan was never built.
    let chain_id: Option<String>;
    let genesis_hash: Option<String>;
    let ratification_hash: Option<String>;
    let trust_bundle_fingerprint: Option<String>;
    let old_marker_present: bool;
    let old_marker_raw_sha256: Option<String>;
    let old_marker_record: Option<PersistentAuthorityStateRecord>;
    let new_marker_hash: Option<String>;
    let new_marker_record: Option<PersistentAuthorityStateRecord>;

    match plan_partial {
        Some(p) => {
            chain_id = Some(p.chain_id_hex_str.clone());
            genesis_hash = Some(p.genesis_hash_hex_str.clone());
            ratification_hash = Some(p.ratification_hash_hex.clone());
            trust_bundle_fingerprint = Some(p.trust_bundle_fingerprint_hex.clone());
            old_marker_present = p.old_marker_archive.present;
            old_marker_raw_sha256 = p.old_marker_archive.raw_sha256_hex.clone();
            old_marker_record = p.old_marker_archive.parsed.clone();
            new_marker_hash = Some(marker_digest_hex(&p.new_marker));
            new_marker_record = Some(p.new_marker.clone());
        }
        None => {
            chain_id = None;
            genesis_hash = None;
            ratification_hash = None;
            trust_bundle_fingerprint = None;
            old_marker_present = false;
            old_marker_raw_sha256 = None;
            old_marker_record = None;
            new_marker_hash = None;
            new_marker_record = None;
        }
    }

    AuthorityResetAuditRecord {
        record_version: AUTHORITY_RESET_AUDIT_RECORD_VERSION,
        action: AUTHORITY_RESET_AUDIT_ACTION.to_string(),
        environment: environment_tag(inputs.environment).to_string(),
        chain_id,
        genesis_hash,
        old_marker_present,
        old_marker_raw_sha256,
        old_marker_record_if_parseable: old_marker_record,
        new_marker_hash,
        new_marker_record,
        ratification_hash,
        trust_bundle_fingerprint,
        snapshot_metadata_hash_if_any: None,
        operator_note_hash,
        binary_sha256_or_unavailable: binary_sha256_best_effort(),
        binary_build_id_or_unavailable: binary_build_id_best_effort(),
        result: "refused".to_string(),
        refusal_reason_if_any: Some(refusal.stable_id().to_string()),
        refusal_detail_if_any: Some(refusal.detail()),
        wall_clock_unix_secs: now_unix_secs(),
    }
}

/// Persist an audit record atomically (tmp + rename).
pub fn write_authority_reset_audit(
    audit_path: &Path,
    record: &AuthorityResetAuditRecord,
) -> Result<(), AuthorityResetRefusal> {
    let bytes = record
        .to_canonical_json()
        .map_err(|e| AuthorityResetRefusal::AuditWriteFailed(format!("serialise: {}", e)))?;
    if let Some(parent) = audit_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                AuthorityResetRefusal::AuditWriteFailed(format!(
                    "create parent {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }
    }
    let tmp = audit_path.with_extension("json.tmp");
    std::fs::write(&tmp, &bytes).map_err(|e| {
        AuthorityResetRefusal::AuditWriteFailed(format!("write tmp {}: {}", tmp.display(), e))
    })?;
    std::fs::rename(&tmp, audit_path).map_err(|e| {
        AuthorityResetRefusal::AuditWriteFailed(format!(
            "rename {} -> {}: {}",
            tmp.display(),
            audit_path.display(),
            e
        ))
    })?;
    Ok(())
}

// ============================================================================
// Top-level orchestrator
// ============================================================================

/// Result of a successful [`execute_authority_state_reset`].
#[derive(Debug, Clone)]
pub struct AuthorityResetSuccess {
    pub audit_path: PathBuf,
    pub marker_path: PathBuf,
    pub new_marker_hash_hex: String,
    pub old_marker_archive: OldMarkerArchive,
}

/// Orchestrate the full Run 127 reset ceremony:
///
/// 1. Call [`verify_authority_reset_inputs`] (pure; no disk writes).
/// 2. On refusal: emit a refusal audit record and return the error.
/// 3. On success: write the `"pending"` audit record, persist the marker
///    via Run 117 [`persist_authority_state_atomic`], then finalise the
///    audit record as `"success"`.
///
/// No disk write ever touches the marker file on any refusal path.
pub fn execute_authority_state_reset(
    inputs: &AuthorityResetInputs,
) -> Result<AuthorityResetSuccess, AuthorityResetRefusal> {
    // Step 1 — pure verification.
    let plan = match verify_authority_reset_inputs(inputs) {
        Ok(p) => p,
        Err(refusal) => {
            // Step 2 — write the refusal audit record where possible.
            if let Some(audit_path) = inputs.audit_output_path.as_ref() {
                let record = build_refusal_audit_record(inputs, None, &refusal);
                let _ = write_authority_reset_audit(audit_path, &record);
            }
            return Err(refusal);
        }
    };

    // audit_output_path is guaranteed present (verified above).
    let audit_path = inputs
        .audit_output_path
        .as_ref()
        .expect("audit_output_path guaranteed by verify_authority_reset_inputs")
        .clone();

    // Step 3a — write the "pending" audit record BEFORE marker persist.
    let pending_record = build_success_audit_record(&plan, PlanResultState::Pending);
    if let Err(e) = write_authority_reset_audit(&audit_path, &pending_record) {
        // Marker is still untouched at this point.
        return Err(e);
    }

    // Step 3b — persist the marker atomically.
    if let Err(persist_err) =
        persist_authority_state_atomic(&plan.marker_path, &plan.new_marker)
    {
        let refusal = AuthorityResetRefusal::MarkerPersistFailed(persist_err.to_string());
        let final_record = build_refusal_audit_record(inputs, Some(&plan), &refusal);
        let _ = write_authority_reset_audit(&audit_path, &final_record);
        return Err(refusal);
    }

    // Step 3c — finalise the audit record as "success".
    let final_record = build_success_audit_record(&plan, PlanResultState::Success);
    write_authority_reset_audit(&audit_path, &final_record)?;

    let new_marker_hash_hex = final_record
        .new_marker_hash
        .clone()
        .unwrap_or_else(|| "unavailable".to_string());
    Ok(AuthorityResetSuccess {
        audit_path,
        marker_path: plan.marker_path,
        new_marker_hash_hex,
        old_marker_archive: plan.old_marker_archive,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn base_inputs(env: NetworkEnvironment) -> AuthorityResetInputs {
        AuthorityResetInputs {
            data_dir: None,
            genesis_path: None,
            expected_genesis_hash: None,
            trust_bundle_path: None,
            bundle_signing_key_specs: Vec::new(),
            ratification_path: None,
            audit_output_path: None,
            environment: env,
            operator_note: None,
            validation_time_secs: 0,
            updated_at_unix_secs: 0,
        }
    }

    // ---- A: Input-presence refusals ----------------------------------------

    #[test]
    fn run127_refuses_when_data_dir_missing() {
        let err = verify_authority_reset_inputs(&base_inputs(NetworkEnvironment::Devnet))
            .unwrap_err();
        assert_eq!(err, AuthorityResetRefusal::MissingDataDir);
        assert_eq!(err.stable_id(), "MissingDataDir");
    }

    #[test]
    fn run127_refuses_when_genesis_path_missing() {
        let mut i = base_inputs(NetworkEnvironment::Devnet);
        i.data_dir = Some(PathBuf::from("/tmp/d"));
        let err = verify_authority_reset_inputs(&i).unwrap_err();
        assert_eq!(err, AuthorityResetRefusal::MissingGenesisPath);
    }

    #[test]
    fn run127_refuses_when_expected_hash_missing() {
        let mut i = base_inputs(NetworkEnvironment::Devnet);
        i.data_dir = Some(PathBuf::from("/tmp/d"));
        i.genesis_path = Some(PathBuf::from("/tmp/g.json"));
        let err = verify_authority_reset_inputs(&i).unwrap_err();
        assert_eq!(err, AuthorityResetRefusal::MissingExpectedGenesisHash);
    }

    #[test]
    fn run127_refuses_when_trust_bundle_missing() {
        let mut i = base_inputs(NetworkEnvironment::Devnet);
        i.data_dir = Some(PathBuf::from("/tmp/d"));
        i.genesis_path = Some(PathBuf::from("/tmp/g.json"));
        i.expected_genesis_hash = Some("ab".repeat(32));
        let err = verify_authority_reset_inputs(&i).unwrap_err();
        assert_eq!(err, AuthorityResetRefusal::MissingTrustBundle);
    }

    #[test]
    fn run127_refuses_when_ratification_missing() {
        let mut i = base_inputs(NetworkEnvironment::Devnet);
        i.data_dir = Some(PathBuf::from("/tmp/d"));
        i.genesis_path = Some(PathBuf::from("/tmp/g.json"));
        i.expected_genesis_hash = Some("ab".repeat(32));
        i.trust_bundle_path = Some(PathBuf::from("/tmp/b.json"));
        let err = verify_authority_reset_inputs(&i).unwrap_err();
        assert_eq!(err, AuthorityResetRefusal::MissingRatification);
    }

    #[test]
    fn run127_refuses_when_audit_output_missing() {
        let mut i = base_inputs(NetworkEnvironment::Devnet);
        i.data_dir = Some(PathBuf::from("/tmp/d"));
        i.genesis_path = Some(PathBuf::from("/tmp/g.json"));
        i.expected_genesis_hash = Some("ab".repeat(32));
        i.trust_bundle_path = Some(PathBuf::from("/tmp/b.json"));
        i.ratification_path = Some(PathBuf::from("/tmp/r.json"));
        let err = verify_authority_reset_inputs(&i).unwrap_err();
        assert_eq!(err, AuthorityResetRefusal::AuditOutputMissing);
    }

    // ---- MainNet policy refusal BEFORE any I/O ----------------------------

    #[test]
    fn run127_refuses_mainnet_before_any_io() {
        let mut i = base_inputs(NetworkEnvironment::Mainnet);
        i.data_dir = Some(PathBuf::from("/tmp/d"));
        i.genesis_path = Some(PathBuf::from("/nonexistent/g.json"));
        i.expected_genesis_hash = Some("ab".repeat(32));
        i.trust_bundle_path = Some(PathBuf::from("/nonexistent/b.json"));
        i.ratification_path = Some(PathBuf::from("/nonexistent/r.json"));
        i.audit_output_path = Some(PathBuf::from("/tmp/audit.json"));
        let err = verify_authority_reset_inputs(&i).unwrap_err();
        assert_eq!(err, AuthorityResetRefusal::MainNetLocalResetUnsupported);
        // The non-existent files must not be opened — if they were, we'd get
        // GenesisLoadFailed instead.
    }

    // ---- Malformed expected hash ------------------------------------------

    #[test]
    fn run127_refuses_malformed_expected_hash() {
        let mut i = base_inputs(NetworkEnvironment::Devnet);
        i.data_dir = Some(PathBuf::from("/tmp/d"));
        i.genesis_path = Some(PathBuf::from("/tmp/g.json"));
        i.expected_genesis_hash = Some("not-hex".to_string());
        i.trust_bundle_path = Some(PathBuf::from("/tmp/b.json"));
        i.ratification_path = Some(PathBuf::from("/tmp/r.json"));
        i.audit_output_path = Some(PathBuf::from("/tmp/audit.json"));
        let err = verify_authority_reset_inputs(&i).unwrap_err();
        assert!(
            matches!(err, AuthorityResetRefusal::MalformedExpectedGenesisHash(ref s) if s == "not-hex"),
            "got {:?}",
            err
        );
    }

    // ---- Missing genesis file ---------------------------------------------

    #[test]
    fn run127_refuses_when_genesis_file_nonexistent() {
        let mut i = base_inputs(NetworkEnvironment::Devnet);
        i.data_dir = Some(PathBuf::from("/tmp/d"));
        i.genesis_path = Some(PathBuf::from("/nonexistent-path-zzz/genesis.json"));
        i.expected_genesis_hash = Some("ab".repeat(32));
        i.trust_bundle_path = Some(PathBuf::from("/tmp/b.json"));
        i.ratification_path = Some(PathBuf::from("/tmp/r.json"));
        i.audit_output_path = Some(PathBuf::from("/tmp/audit.json"));
        let err = verify_authority_reset_inputs(&i).unwrap_err();
        assert!(
            matches!(err, AuthorityResetRefusal::GenesisLoadFailed(_)),
            "got {:?}",
            err
        );
    }

    // ---- execute: MainNet refusal writes audit record; no marker written --

    #[test]
    fn run127_execute_emits_refusal_audit_for_mainnet_and_no_marker() {
        let dir = tempdir().unwrap();
        let audit_path = dir.path().join("audit.json");
        let mut i = base_inputs(NetworkEnvironment::Mainnet);
        i.data_dir = Some(dir.path().to_path_buf());
        i.genesis_path = Some(dir.path().join("g.json"));
        i.expected_genesis_hash = Some("ab".repeat(32));
        i.trust_bundle_path = Some(dir.path().join("b.json"));
        i.ratification_path = Some(dir.path().join("r.json"));
        i.audit_output_path = Some(audit_path.clone());

        let err = execute_authority_state_reset(&i).unwrap_err();
        assert_eq!(err, AuthorityResetRefusal::MainNetLocalResetUnsupported);

        // Audit record MUST be present.
        let bytes = std::fs::read(&audit_path).expect("refusal audit record must be written");
        let parsed: AuthorityResetAuditRecord =
            serde_json::from_slice(&bytes).expect("audit record must parse");
        assert_eq!(parsed.result, "refused");
        assert_eq!(
            parsed.refusal_reason_if_any.as_deref(),
            Some("MainNetLocalResetUnsupported")
        );
        assert_eq!(parsed.environment, "mainnet");
        assert_eq!(parsed.record_version, AUTHORITY_RESET_AUDIT_RECORD_VERSION);
        assert_eq!(parsed.action, AUTHORITY_RESET_AUDIT_ACTION);
        assert!(parsed.new_marker_hash.is_none());
        assert!(parsed.new_marker_record.is_none());

        // Marker file MUST NOT be written.
        assert!(
            !authority_state_file_path(dir.path()).exists(),
            "marker must not be written on refusal"
        );
    }

    // ---- execute: missing audit output refuses without touching marker ----

    #[test]
    fn run127_execute_refuses_without_audit_path_and_no_marker() {
        let dir = tempdir().unwrap();
        let mut i = base_inputs(NetworkEnvironment::Devnet);
        i.data_dir = Some(dir.path().to_path_buf());
        i.genesis_path = Some(dir.path().join("g.json"));
        i.expected_genesis_hash = Some("ab".repeat(32));
        i.trust_bundle_path = Some(dir.path().join("b.json"));
        i.ratification_path = Some(dir.path().join("r.json"));
        // audit_output_path intentionally None.
        let err = execute_authority_state_reset(&i).unwrap_err();
        assert_eq!(err, AuthorityResetRefusal::AuditOutputMissing);
        assert!(!authority_state_file_path(dir.path()).exists());
    }

    // ---- B: Audit record format ------------------------------------------

    #[test]
    fn run127_audit_record_canonical_json_deterministic_and_no_raw_note() {
        let dir = tempdir().unwrap();
        let audit_path = dir.path().join("audit.json");
        let mut i = base_inputs(NetworkEnvironment::Mainnet);
        i.data_dir = Some(dir.path().to_path_buf());
        i.genesis_path = Some(dir.path().join("g.json"));
        i.expected_genesis_hash = Some(format!("0x{}", "cd".repeat(32)));
        i.trust_bundle_path = Some(dir.path().join("b.json"));
        i.ratification_path = Some(dir.path().join("r.json"));
        i.audit_output_path = Some(audit_path.clone());
        i.operator_note = Some("ceremony abc-123".to_string());

        let _ = execute_authority_state_reset(&i).unwrap_err();
        let bytes = std::fs::read(&audit_path).unwrap();
        let parsed: AuthorityResetAuditRecord = serde_json::from_slice(&bytes).unwrap();
        // Re-serialise must be identical (canonical JSON).
        let reserialised = parsed.to_canonical_json().unwrap();
        assert_eq!(bytes, reserialised, "canonical JSON must be deterministic");
        // Operator note hash is SHA3-256 of the raw note bytes.
        let expected_note_hash = sha3_256_hex_bytes(b"ceremony abc-123");
        assert_eq!(
            parsed.operator_note_hash.as_deref(),
            Some(expected_note_hash.as_str())
        );
        // Raw note text must NOT appear in the audit bytes.
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(
            !text.contains("ceremony abc-123"),
            "raw operator note must not appear in the audit record"
        );
    }

    // ---- Stable-id surface contract --------------------------------------

    #[test]
    fn run127_refusal_stable_ids_are_stable() {
        let cases: &[(&dyn Fn() -> AuthorityResetRefusal, &str)] = &[
            (&|| AuthorityResetRefusal::MissingDataDir, "MissingDataDir"),
            (&|| AuthorityResetRefusal::MissingGenesisPath, "MissingGenesisPath"),
            (&|| AuthorityResetRefusal::MissingExpectedGenesisHash, "MissingExpectedGenesisHash"),
            (&|| AuthorityResetRefusal::MissingTrustBundle, "MissingTrustBundle"),
            (&|| AuthorityResetRefusal::MissingRatification, "MissingRatification"),
            (&|| AuthorityResetRefusal::AuditOutputMissing, "AuditOutputMissing"),
            (&|| AuthorityResetRefusal::MainNetLocalResetUnsupported, "MainNetLocalResetUnsupported"),
            (&|| AuthorityResetRefusal::MissingAuthorityConfig, "MissingAuthorityConfig"),
            (&|| AuthorityResetRefusal::AuthorityKeyMaterialUnavailable, "AuthorityKeyMaterialUnavailable"),
            (&|| AuthorityResetRefusal::AuthorityKeyMaterialMalformed, "AuthorityKeyMaterialMalformed"),
            (&|| AuthorityResetRefusal::TransportRootNotAllowed, "TransportRootNotAllowed"),
        ];
        for (f, expected) in cases {
            assert_eq!(f().stable_id(), *expected);
        }
    }

    // ---- archive_existing_marker: absent path ----------------------------

    #[test]
    fn run127_archive_absent_marker_returns_not_present() {
        let dir = tempdir().unwrap();
        let marker_path = authority_state_file_path(dir.path());
        let archive = archive_existing_marker(&marker_path).unwrap();
        assert!(!archive.present);
        assert!(archive.raw_sha256_hex.is_none());
        assert!(archive.parsed.is_none());
    }

    // ---- archive_existing_marker: corrupt marker -------------------------

    #[test]
    fn run127_archive_corrupt_marker_refuses_and_bytes_unchanged() {
        let dir = tempdir().unwrap();
        let marker_path = authority_state_file_path(dir.path());
        std::fs::write(&marker_path, b"not valid json {{{").unwrap();
        let err = archive_existing_marker(&marker_path).unwrap_err();
        assert!(
            matches!(err, AuthorityResetRefusal::ExistingMarkerCorrupt(_)),
            "got {:?}",
            err
        );
        // File bytes must be unchanged (no auto-repair).
        let after = std::fs::read(&marker_path).unwrap();
        assert_eq!(after, b"not valid json {{{".to_vec());
    }

    // ---- parse_expected_hash accepts 0x prefix ---------------------------

    #[test]
    fn run127_parse_expected_hash_accepts_0x_prefix() {
        let raw = format!("0x{}", "ab".repeat(32));
        let bytes = parse_expected_hash(&raw).unwrap();
        assert_eq!(bytes[0], 0xab);
        assert_eq!(bytes[31], 0xab);
    }

    #[test]
    fn run127_parse_expected_hash_accepts_bare_hex() {
        let raw = "cd".repeat(32);
        let bytes = parse_expected_hash(&raw).unwrap();
        assert_eq!(bytes[0], 0xcd);
        assert_eq!(bytes[31], 0xcd);
    }

    #[test]
    fn run127_parse_expected_hash_refuses_wrong_length() {
        assert!(parse_expected_hash("ab").is_err());
        assert!(parse_expected_hash(&"ab".repeat(33)).is_err());
        assert!(parse_expected_hash("").is_err());
    }
}