//! Run 117 (C4 piece: PQC authority anti-rollback persistence):
//! persistent, atomic record of the highest-accepted ratified
//! bundle-signing **authority state** observed by this node for a
//! given `(environment, chain_id, genesis_hash)` trust domain.
//!
//! # Purpose
//!
//! Prevent rollback to an older ratified bundle-signing authority
//! state after a node has already accepted a newer ratification.
//! This module is the **authority-level** counterpart to the Run 055
//! `pqc_trust_sequence` module, which records the per-trust-bundle
//! `sequence`. The two layers are intentionally distinct:
//!
//! - Run 055 anchors on the bundle `sequence: u64` carried in the
//!   signed trust-bundle envelope. It catches rollback of the
//!   *bundle*.
//! - Run 117 anchors on the **genesis-bound**
//!   [`crate::genesis::GenesisAuthorityConfig::authority_sequence`]
//!   (Run 101) plus the ratification-object content hash
//!   ([`canonical_ratification_digest`]). It catches rollback /
//!   conflict / corruption of the *ratified bundle-signing authority
//!   state* itself.
//!
//! Run 117 explicitly does **NOT** solve signing-key rotation: the
//! Run 103 [`BundleSigningRatification`] object does not yet carry a
//! per-key monotonic field (that schema bump is deferred to Run 120).
//! Until then, the monotonic anchor available to this module is the
//! genesis-bound `authority_sequence` — i.e. the marker can detect
//! authority-level rollback (re-issued genesis-authority bumps), but
//! cannot detect a key-level downgrade if a new ratification keeps
//! the same `authority_sequence`. The
//! [`AuthorityStateComparison::SameSequenceConflictingHash`] /
//! [`AuthorityStateComparison::SameSequenceConflictingKey`] variants
//! make the bounded protection explicit: at equal authority_sequence
//! a different ratification content / key is treated as a conflict
//! to be rejected, not as a silent upgrade.
//!
//! # Strict scope (anti-rollback persistence only)
//!
//! - Does NOT implement signing-key rotation lifecycle.
//! - Does NOT implement signing-key revocation lifecycle.
//! - Does NOT implement peer-driven live apply.
//! - Does NOT implement KMS / HSM custody.
//! - Does NOT change any wire format.
//! - Does NOT change Run 050–055 signed-bundle verification,
//!   Run 057 activation gating, or Run 065 minimum-margin policy.
//! - Does NOT wire itself into any production validation / apply
//!   surface — that is Run 118 scope. The Run 117 deliverable is
//!   strictly the storage / snapshot primitive plus typed comparison
//!   semantics.
//!
//! # Persistence format
//!
//! A single JSON file under the operator-supplied
//! `<data_dir>/pqc_authority_state.json` (file name matches the
//! Run 116 spec and the Run 101 source-comment forward reference
//! in `crates/qbind-ledger/src/genesis.rs`). The schema is:
//!
//! ```json
//! {
//!   "record_version": 1,
//!   "chain_id": "<16 lowercase hex chars>",
//!   "environment": "devnet" | "testnet" | "mainnet",
//!   "genesis_hash": "<64 lowercase hex chars>",
//!   "authority_policy_version": <u32>,
//!   "authority_sequence": <u64>,
//!   "authority_epoch": <u64 | null>,
//!   "authority_root_fingerprint": "<lowercase hex>",
//!   "ratified_bundle_signing_key_fingerprint": "<lowercase hex>",
//!   "ratification_object_hash": "<64 lowercase hex chars>",
//!   "last_update_source": "<short ascii tag>",
//!   "updated_at_unix_secs": <u64>
//! }
//! ```
//!
//! `record_version` is currently `1`; anything else fails closed.
//! `ratification_object_hash` is the 32-byte SHA3-256
//! [`canonical_ratification_digest`] of the
//! [`BundleSigningRatification`] object whose acceptance produced
//! this record. **No private key material is persisted** — only the
//! public-key fingerprint and the ratification content hash.
//!
//! # Canonical digest
//!
//! [`canonical_authority_state_digest`] produces a 32-byte SHA3-256
//! digest over a length-prefixed, big-endian preimage that begins
//! with the domain tag [`AUTHORITY_STATE_DOMAIN_V1`] = `b"QBIND:AUTHORITY-STATE:v1"`.
//! This is the digest a higher-level surface (Run 118) would use to
//! compare two markers without re-serialising JSON. The digest is
//! deterministic across platforms and includes every security-
//! relevant field; no JSON ordering ambiguity is possible.
//!
//! # Comparison semantics
//!
//! [`compare_authority_state`] is a pure function whose typed
//! outcome is [`AuthorityStateComparison`]. Eleven variants cover
//! the Run 116 / Run 117 specification:
//!
//! - `FirstLoad`: no prior marker — accept.
//! - `EqualIdempotent`: prior marker identical bit-for-bit — accept,
//!   no rewrite (matches the Run 055 "equal-sequence same-fingerprint
//!   no-op" pattern).
//! - `Upgrade { previous_sequence, new_sequence }`: candidate's
//!   `authority_sequence` is strictly higher — accept and rewrite.
//! - `RollbackRefused`: candidate's `authority_sequence` is strictly
//!   lower than persisted — reject.
//! - `SameSequenceConflictingHash`: equal `authority_sequence` but
//!   different `ratification_object_hash` — reject (cannot tell
//!   which ratification is canonical without a per-key monotonic
//!   field; Run 120 is the canonical path forward).
//! - `SameSequenceConflictingKey`: equal `authority_sequence` and
//!   equal authority root but different ratified-key fingerprint —
//!   reject.
//! - `ChainMismatch`: `chain_id` differs from runtime — reject.
//! - `EnvironmentMismatch`: `environment` differs from runtime —
//!   reject.
//! - `GenesisHashMismatch`: `genesis_hash` differs from runtime
//!   genesis — reject (catches wrong-data-dir / wrong-snapshot).
//! - `PolicyVersionRegression`: candidate's
//!   `authority_policy_version` is strictly lower than persisted —
//!   reject (cannot downgrade the schema).
//! - `Corrupt`: candidate or persisted record fails structural
//!   validation — reject (forwarded as a precondition; the typed
//!   outcome here is returned only when a successfully-loaded
//!   structurally-valid candidate disagrees with a structurally-
//!   valid persisted record in a way that does not fit any other
//!   variant).
//!
//! # Atomicity
//!
//! Writes go through a `tmp` sibling + rename + `sync_all` of the
//! tmp file (mirrors Run 055 [`crate::pqc_trust_sequence::atomic_write_record`])
//! and additionally `sync_all` the **parent directory** so that the
//! rename is durable in the directory entry. Any failure mid-write
//! leaves either the old record or a `.tmp` sibling — never a
//! corrupted destination file. The module never silently deletes,
//! truncates, or resets a corrupted persistence file; the operator
//! is expected to investigate the FATAL error rather than have
//! state silently rewritten.
//!
//! # Surface wiring
//!
//! Run 117 intentionally does not wire this module into any
//! production validation / apply surface. The marker primitive is
//! exposed so that Run 118 can wire it into:
//!
//! - startup-load (after Run 070 `commit_sequence`);
//! - process-start reload-apply (Run 112);
//! - SIGHUP live reload (Run 114);
//! - reload-check (validation-only);
//! - local peer-candidate check (validation-only);
//! - live inbound `0x05` peer-candidate validation (validation-only,
//!   Run 109 non-mutation contract preserved).
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_117.md` for the staged
//! Run 117 → Run 120 plan and `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
//! Run 116 update for the binding design decisions.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use qbind_ledger::{
    canonical_ratification_digest, canonical_ratification_v2_digest, AuthorityStateSnapshotMeta,
    BundleSigningRatification, BundleSigningRatificationV2, BundleSigningRatificationV2Action,
    RatifiedBundleSigningKey, RatifiedBundleSigningKeyV2,
};
use qbind_types::{ChainId, NetworkEnvironment};

use crate::pqc_trust_bundle::TrustBundleEnvironment;

/// Domain-separation tag for the canonical authority-state digest
/// preimage. Mirrors the project convention `QBIND:<SUBJECT>:vN`
/// (cf. `QBIND:GENESIS:v1`, `QBIND:BUNDLE-SIGNING-RATIFICATION:v1`).
/// Bumping the trailing `v1` invalidates every previously computed
/// authority-state digest.
pub const AUTHORITY_STATE_DOMAIN_V1: &[u8] = b"QBIND:AUTHORITY-STATE:v1";
/// Domain-separation tag for v2 authority-state marker digests.
pub const AUTHORITY_STATE_DOMAIN_V2: &[u8] = b"QBIND:AUTHORITY-STATE:v2";

/// Current `record_version` for the persisted authority-state file.
/// Any other value fails closed.
pub const AUTHORITY_STATE_RECORD_VERSION: u32 = 1;
/// Record version for the additive v2 authority-state marker schema.
pub const AUTHORITY_STATE_RECORD_VERSION_V2: u32 = 2;
/// Marker schema version for v2 monotonic semantics.
pub const AUTHORITY_STATE_SCHEMA_VERSION_V2: u32 = 2;

/// Default file name written under `<data_dir>/`.
pub const AUTHORITY_STATE_FILENAME: &str = "pqc_authority_state.json";

/// Resolve the canonical authority-state persistence path under a
/// node `data_dir`. Mirrors
/// [`crate::pqc_trust_sequence::sequence_file_path`].
pub fn authority_state_file_path(data_dir: &Path) -> PathBuf {
    data_dir.join(AUTHORITY_STATE_FILENAME)
}

/// Short ASCII tag identifying which Run 117/118 surface produced
/// the most recent write of an authority-state record. Stored
/// **informational-only** for operator audit and never used in any
/// policy decision (matching the Run 055 `updated_at_unix_secs`
/// precedent).
///
/// Run 117 itself never writes any record from a production surface
/// (Run 118 scope); this enum is provided so a Run 118 wiring can
/// record which mutating surface advanced the marker without
/// inventing a stringly-typed protocol later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityStateUpdateSource {
    /// Marker advanced by the startup-load path.
    StartupLoad,
    /// Marker advanced by the process-start reload-apply path (Run 112).
    ReloadApply,
    /// Marker advanced by the SIGHUP live-reload path (Run 114).
    SighupReload,
    /// Marker reset by the explicit operator-recovery flag
    /// (`--allow-authority-state-reset` per Run 116 design; gated
    /// to a Run 118+ binary surface).
    OperatorReset,
    /// Marker created or written by a non-binary tool (test helper
    /// in this crate, evidence fixture, etc.). Never used on
    /// production paths.
    TestOrFixture,
}

/// On-disk record of the highest-accepted ratified bundle-signing
/// authority state for one `(environment, chain_id, genesis_hash)`
/// trust domain. Serialised to JSON in
/// `<data_dir>/pqc_authority_state.json` (see module docs).
///
/// **No private keys** are persisted; the ratified bundle-signing
/// key is referenced only by its lowercase-hex SHA3-256
/// fingerprint, and the ratification object itself is captured
/// only as its 32-byte SHA3-256 [`canonical_ratification_digest`]
/// stored as 64 lowercase hex chars in
/// `ratification_object_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentAuthorityStateRecord {
    /// Schema version. Currently
    /// [`AUTHORITY_STATE_RECORD_VERSION`]; anything else fails
    /// closed via [`AuthorityStateError::UnsupportedRecordVersion`].
    pub record_version: u32,

    /// 16 lowercase hex chars (no `0x` / `chain_` prefix) of the
    /// runtime chain id this record applies to. Mirrors the form
    /// used by [`crate::pqc_trust_sequence::chain_id_hex`] so the
    /// two persistence layers share a single chain-id encoding.
    pub chain_id: String,

    /// Canonical trust-domain environment. Mirrors the
    /// [`TrustBundleEnvironment`] enum already used by Run 055 so
    /// no new environment encoding is introduced.
    pub environment: TrustBundleEnvironment,

    /// 64 lowercase hex chars of the canonical genesis hash this
    /// record is bound to. Equals
    /// `crate::genesis::compute_canonical_genesis_hash(...)` on the
    /// runtime genesis config when this record was written.
    pub genesis_hash: String,

    /// `authority_policy_version` of the genesis authority block
    /// at the moment of last successful ratification acceptance.
    /// Strictly monotonic (a downgrade is
    /// [`AuthorityStateComparison::PolicyVersionRegression`]).
    pub authority_policy_version: u32,

    /// Monotonic genesis-bound authority sequence anchor (Run 101
    /// [`crate::genesis::GenesisAuthorityConfig::authority_sequence`]).
    /// This is the **only** monotonic field Run 117 can rely on;
    /// per-key rotation monotonicity is deferred to Run 120.
    pub authority_sequence: u64,

    /// Optional genesis-bound authority epoch (Run 101
    /// [`crate::genesis::GenesisAuthorityConfig::authority_epoch`]).
    /// Hash-bound only; never inferred from block height / wall
    /// clock / activation epoch.
    pub authority_epoch: Option<u64>,

    /// Lowercase-hex fingerprint of the genesis-bound authority
    /// root that signed the most recently accepted ratification.
    /// Mirrors [`crate::pqc_trust_bundle`] / Run 103
    /// `authority_root_fingerprint` formatting.
    pub authority_root_fingerprint: String,

    /// Lowercase-hex SHA3-256 fingerprint of the **ratified**
    /// bundle-signing public key whose ratification produced this
    /// record. NOT the private key, NOT the full public key —
    /// fingerprint only.
    pub ratified_bundle_signing_key_fingerprint: String,

    /// 64 lowercase hex chars of the SHA3-256
    /// [`canonical_ratification_digest`] of the
    /// [`BundleSigningRatification`] object whose acceptance
    /// produced this record. This is the strongest content-bound
    /// anchor available pre-Run-120.
    pub ratification_object_hash: String,

    /// Informational tag identifying which mutating surface wrote
    /// this record. Never used in any policy decision (matching
    /// the Run 055 `updated_at_unix_secs` precedent).
    pub last_update_source: AuthorityStateUpdateSource,

    /// Wall-clock time at which the record was last written, in
    /// Unix seconds. Informational only — never used in any policy
    /// decision.
    pub updated_at_unix_secs: u64,
}

impl PersistentAuthorityStateRecord {
    /// Construct a fresh authority-state record. Validates nothing
    /// — callers MUST call [`Self::validate_structure`] before
    /// trusting a record loaded from disk.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id_hex: String,
        environment: TrustBundleEnvironment,
        genesis_hash_hex: String,
        authority_policy_version: u32,
        authority_sequence: u64,
        authority_epoch: Option<u64>,
        authority_root_fingerprint: String,
        ratified_bundle_signing_key_fingerprint: String,
        ratification_object_hash: String,
        last_update_source: AuthorityStateUpdateSource,
        updated_at_unix_secs: u64,
    ) -> Self {
        Self {
            record_version: AUTHORITY_STATE_RECORD_VERSION,
            chain_id: chain_id_hex,
            environment,
            genesis_hash: genesis_hash_hex,
            authority_policy_version,
            authority_sequence,
            authority_epoch,
            authority_root_fingerprint,
            ratified_bundle_signing_key_fingerprint,
            ratification_object_hash,
            last_update_source,
            updated_at_unix_secs,
        }
    }
}

/// Run 131: versioned authority marker representation that can carry either
/// legacy v1 marker state or additive v2 monotonic marker state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistentAuthorityStateRecordVersioned {
    V1(PersistentAuthorityStateRecord),
    V2(PersistentAuthorityStateRecordV2),
}

/// Run 131: additive v2 marker state for ratification-v2 monotonic semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentAuthorityStateRecordV2 {
    pub record_version: u32,
    pub authority_schema_version: u32,
    pub chain_id: String,
    pub environment: TrustBundleEnvironment,
    pub genesis_hash: String,
    pub authority_root_fingerprint: String,
    pub authority_root_suite_id: u8,
    pub active_bundle_signing_key_fingerprint: String,
    pub active_bundle_signing_key_suite_id: u8,
    pub latest_authority_domain_sequence: u64,
    pub latest_lifecycle_action: BundleSigningRatificationV2Action,
    pub previous_bundle_signing_key_fingerprint: Option<String>,
    pub latest_ratification_v2_digest: String,
    pub revoked_key_metadata: Option<String>,
    pub last_update_source: AuthorityStateUpdateSource,
    pub updated_at_unix_secs: u64,
}

impl PersistentAuthorityStateRecordV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id_hex: String,
        environment: TrustBundleEnvironment,
        genesis_hash_hex: String,
        authority_root_fingerprint: String,
        authority_root_suite_id: u8,
        active_bundle_signing_key_fingerprint: String,
        active_bundle_signing_key_suite_id: u8,
        latest_authority_domain_sequence: u64,
        latest_lifecycle_action: BundleSigningRatificationV2Action,
        previous_bundle_signing_key_fingerprint: Option<String>,
        latest_ratification_v2_digest: String,
        revoked_key_metadata: Option<String>,
        last_update_source: AuthorityStateUpdateSource,
        updated_at_unix_secs: u64,
    ) -> Self {
        Self {
            record_version: AUTHORITY_STATE_RECORD_VERSION_V2,
            authority_schema_version: AUTHORITY_STATE_SCHEMA_VERSION_V2,
            chain_id: chain_id_hex,
            environment,
            genesis_hash: genesis_hash_hex,
            authority_root_fingerprint,
            authority_root_suite_id,
            active_bundle_signing_key_fingerprint,
            active_bundle_signing_key_suite_id,
            latest_authority_domain_sequence,
            latest_lifecycle_action,
            previous_bundle_signing_key_fingerprint,
            latest_ratification_v2_digest,
            revoked_key_metadata,
            last_update_source,
            updated_at_unix_secs,
        }
    }

    pub fn validate_structure(&self) -> Result<(), AuthorityStateError> {
        if self.record_version != AUTHORITY_STATE_RECORD_VERSION_V2 {
            return Err(AuthorityStateError::UnsupportedRecordVersion(
                self.record_version,
            ));
        }
        if self.authority_schema_version != AUTHORITY_STATE_SCHEMA_VERSION_V2 {
            return Err(AuthorityStateError::Malformed(format!(
                "authority_schema_version must be {} for v2 markers (got {})",
                AUTHORITY_STATE_SCHEMA_VERSION_V2, self.authority_schema_version
            )));
        }
        if self.chain_id.len() != 16 || !is_lower_hex(&self.chain_id) {
            return Err(AuthorityStateError::Malformed(format!(
                "v2 chain_id must be exactly 16 lowercase hex chars (length {})",
                self.chain_id.len()
            )));
        }
        if self.genesis_hash.len() != 64 || !is_lower_hex(&self.genesis_hash) {
            return Err(AuthorityStateError::Malformed(format!(
                "v2 genesis_hash must be exactly 64 lowercase hex chars (length {})",
                self.genesis_hash.len()
            )));
        }
        if self.authority_root_fingerprint.is_empty()
            || !is_lower_hex(&self.authority_root_fingerprint)
        {
            return Err(AuthorityStateError::Malformed(format!(
                "v2 authority_root_fingerprint must be non-empty lowercase hex (length {})",
                self.authority_root_fingerprint.len()
            )));
        }
        if self.active_bundle_signing_key_fingerprint.is_empty()
            || !is_lower_hex(&self.active_bundle_signing_key_fingerprint)
        {
            return Err(AuthorityStateError::Malformed(format!(
                    "v2 active_bundle_signing_key_fingerprint must be non-empty lowercase hex (length {})",
                    self.active_bundle_signing_key_fingerprint.len()
                )));
        }
        if self.latest_authority_domain_sequence == 0 {
            return Err(AuthorityStateError::Malformed(
                "v2 latest_authority_domain_sequence must be >= 1".to_string(),
            ));
        }
        if self.latest_ratification_v2_digest.len() != 64
            || !is_lower_hex(&self.latest_ratification_v2_digest)
        {
            return Err(AuthorityStateError::Malformed(format!(
                    "v2 latest_ratification_v2_digest must be exactly 64 lowercase hex chars (length {})",
                    self.latest_ratification_v2_digest.len()
                )));
        }
        if let Some(prev) = self.previous_bundle_signing_key_fingerprint.as_ref() {
            if prev.is_empty() || !is_lower_hex(prev) {
                return Err(AuthorityStateError::Malformed(format!(
                        "v2 previous_bundle_signing_key_fingerprint must be non-empty lowercase hex (length {})",
                        prev.len()
                    )));
            }
        }
        if let Some(revoked) = self.revoked_key_metadata.as_ref() {
            if revoked.is_empty() || !is_lower_hex(revoked) {
                return Err(AuthorityStateError::Malformed(format!(
                    "v2 revoked_key_metadata must be non-empty lowercase hex (length {})",
                    revoked.len()
                )));
            }
        }

        match self.latest_lifecycle_action {
            BundleSigningRatificationV2Action::Ratify => {
                if self.previous_bundle_signing_key_fingerprint.is_some() {
                    return Err(AuthorityStateError::Malformed(
                        "v2 ratify marker must not carry previous_bundle_signing_key_fingerprint"
                            .to_string(),
                    ));
                }
                if self.revoked_key_metadata.is_some() {
                    return Err(AuthorityStateError::Malformed(
                        "v2 ratify marker must not carry revoked_key_metadata".to_string(),
                    ));
                }
            }
            BundleSigningRatificationV2Action::Rotate => {
                let Some(prev) = self.previous_bundle_signing_key_fingerprint.as_ref() else {
                    return Err(AuthorityStateError::Malformed(
                        "v2 rotate marker requires previous_bundle_signing_key_fingerprint"
                            .to_string(),
                    ));
                };
                if prev == &self.active_bundle_signing_key_fingerprint {
                    return Err(AuthorityStateError::Malformed(
                        "v2 rotate marker previous key must differ from active key".to_string(),
                    ));
                }
                if self.revoked_key_metadata.is_some() {
                    return Err(AuthorityStateError::Malformed(
                        "v2 rotate marker must not carry revoked_key_metadata".to_string(),
                    ));
                }
            }
            BundleSigningRatificationV2Action::Revoke => {
                if self.revoked_key_metadata.is_none() {
                    return Err(AuthorityStateError::Malformed(
                        "v2 revoke marker requires revoked_key_metadata placeholder".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Parse a persisted marker payload into a versioned marker record. v1 payloads
/// remain parse-compatible and unsupported versions fail closed.
pub fn parse_versioned_authority_state_record_bytes(
    bytes: &[u8],
) -> Result<PersistentAuthorityStateRecordVersioned, AuthorityStateError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| AuthorityStateError::Malformed(format!("{}", e)))?;
    let Some(record_version_u64) = value.get("record_version").and_then(|v| v.as_u64()) else {
        return Err(AuthorityStateError::Malformed(
            "missing numeric record_version".to_string(),
        ));
    };
    let record_version = u32::try_from(record_version_u64).map_err(|_| {
        AuthorityStateError::Malformed(format!(
            "record_version {} does not fit in u32",
            record_version_u64
        ))
    })?;
    match record_version {
        AUTHORITY_STATE_RECORD_VERSION => {
            let r: PersistentAuthorityStateRecord = serde_json::from_value(value)
                .map_err(|e| AuthorityStateError::Malformed(format!("{}", e)))?;
            r.validate_structure()?;
            Ok(PersistentAuthorityStateRecordVersioned::V1(r))
        }
        AUTHORITY_STATE_RECORD_VERSION_V2 => {
            let r: PersistentAuthorityStateRecordV2 = serde_json::from_value(value)
                .map_err(|e| AuthorityStateError::Malformed(format!("{}", e)))?;
            r.validate_structure()?;
            Ok(PersistentAuthorityStateRecordVersioned::V2(r))
        }
        v => Err(AuthorityStateError::UnsupportedRecordVersion(v)),
    }
}

/// Load a versioned authority marker from disk.
pub fn load_authority_state_versioned(
    path: &Path,
) -> Result<Option<PersistentAuthorityStateRecordVersioned>, AuthorityStateError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(AuthorityStateError::Io(format!(
                "{}: {}",
                path.display(),
                e.kind()
            )));
        }
    };
    parse_versioned_authority_state_record_bytes(&bytes).map(Some)
}

impl PersistentAuthorityStateRecord {
    /// Strict structural validation of a freshly-deserialised record.
    /// Returns the precise [`AuthorityStateError`] variant on any
    /// defect so the binary surface can fail closed with a precise
    /// reason.
    ///
    /// This does **not** check the record against runtime
    /// `(environment, chain_id, genesis_hash)` — call
    /// [`validate_record_for_domain`] for that.
    pub fn validate_structure(&self) -> Result<(), AuthorityStateError> {
        if self.record_version != AUTHORITY_STATE_RECORD_VERSION {
            return Err(AuthorityStateError::UnsupportedRecordVersion(
                self.record_version,
            ));
        }
        if self.chain_id.len() != 16 || !is_lower_hex(&self.chain_id) {
            return Err(AuthorityStateError::Malformed(format!(
                "chain_id must be exactly 16 lowercase hex chars (length {})",
                self.chain_id.len()
            )));
        }
        if self.genesis_hash.len() != 64 || !is_lower_hex(&self.genesis_hash) {
            return Err(AuthorityStateError::Malformed(format!(
                "genesis_hash must be exactly 64 lowercase hex chars (length {})",
                self.genesis_hash.len()
            )));
        }
        if self.authority_policy_version == 0 {
            return Err(AuthorityStateError::Malformed(
                "authority_policy_version must be >= 1 (Run 101 minimum)".to_string(),
            ));
        }
        if self.authority_root_fingerprint.is_empty()
            || !is_lower_hex(&self.authority_root_fingerprint)
        {
            return Err(AuthorityStateError::Malformed(format!(
                "authority_root_fingerprint must be non-empty lowercase hex (length {})",
                self.authority_root_fingerprint.len()
            )));
        }
        if self.ratified_bundle_signing_key_fingerprint.is_empty()
            || !is_lower_hex(&self.ratified_bundle_signing_key_fingerprint)
        {
            return Err(AuthorityStateError::Malformed(format!(
                "ratified_bundle_signing_key_fingerprint must be non-empty lowercase hex (length {})",
                self.ratified_bundle_signing_key_fingerprint.len()
            )));
        }
        if self.ratification_object_hash.len() != 64
            || !is_lower_hex(&self.ratification_object_hash)
        {
            return Err(AuthorityStateError::Malformed(format!(
                "ratification_object_hash must be exactly 64 lowercase hex chars (length {})",
                self.ratification_object_hash.len()
            )));
        }
        Ok(())
    }
}

/// Errors produced by the authority-state persistence layer. Every
/// variant is a fail-closed condition at the binary surface — the
/// caller MUST NOT advance authority state if this layer returned
/// an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityStateError {
    /// I/O error reading or writing the persistence file. The
    /// string carries the supplied path plus the OS error kind
    /// only; no file content is exposed in the message.
    Io(String),
    /// JSON parse error, missing field, malformed hex, or malformed
    /// structural invariant on a deserialised record.
    Malformed(String),
    /// Persisted `record_version` is not the one this binary
    /// supports. Run 117 supports only
    /// [`AUTHORITY_STATE_RECORD_VERSION`] = `1`.
    UnsupportedRecordVersion(u32),
    /// Persistence write failure. The caller MUST NOT advance
    /// authority state if this fires, otherwise a subsequent
    /// restart would silently lose the would-be-recorded state.
    PersistFailure(String),
}

impl std::fmt::Display for AuthorityStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "pqc authority-state io: {}", s),
            Self::Malformed(s) => {
                write!(f, "pqc authority-state malformed: {} (fail closed)", s)
            }
            Self::UnsupportedRecordVersion(v) => write!(
                f,
                "pqc authority-state record_version {} not supported (this binary supports {}) — fail closed",
                v, AUTHORITY_STATE_RECORD_VERSION
            ),
            Self::PersistFailure(s) => write!(
                f,
                "pqc authority-state persist failure: {} (fail closed; authority state MUST NOT be advanced if its record cannot be persisted)",
                s
            ),
        }
    }
}

impl std::error::Error for AuthorityStateError {}

/// Outcome of a [`compare_authority_state`] call. Every variant is
/// typed so callers cannot accidentally collapse "first load" with
/// "rollback refused" into a boolean. Reject variants carry the
/// data necessary to emit a precise operator log line without re-
/// inspecting the records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityStateComparison {
    /// No prior marker exists for this trust domain. The candidate
    /// would be the first-write on
    /// [`persist_authority_state_atomic`].
    FirstLoad,

    /// Prior marker exists and is bit-for-bit identical to the
    /// candidate. The caller SHOULD NOT rewrite the file (matches
    /// the Run 055 `EqualSequenceSameFingerprint` no-op precedent).
    EqualIdempotent,

    /// Prior marker exists and the candidate's `authority_sequence`
    /// is strictly higher. The caller MAY advance the persisted
    /// record (via [`persist_authority_state_atomic`]).
    Upgrade {
        previous_sequence: u64,
        new_sequence: u64,
    },

    /// Prior marker exists and the candidate's `authority_sequence`
    /// is strictly lower than persisted — rollback attempt. Reject.
    RollbackRefused {
        persisted_sequence: u64,
        attempted_sequence: u64,
    },

    /// Equal `authority_sequence` but different
    /// `ratification_object_hash`. Two structurally distinct
    /// ratifications cannot share the same authority sequence
    /// without a per-key monotonic field (deferred to Run 120) —
    /// reject.
    SameSequenceConflictingHash {
        sequence: u64,
        persisted_hash: String,
        attempted_hash: String,
    },

    /// Equal `authority_sequence`, equal `authority_root_fingerprint`,
    /// but different `ratified_bundle_signing_key_fingerprint`.
    /// Reject (cannot silently swap the ratified key at the same
    /// authority sequence).
    SameSequenceConflictingKey {
        sequence: u64,
        persisted_key_fingerprint: String,
        attempted_key_fingerprint: String,
    },

    /// Persisted or candidate `chain_id` does not match the
    /// runtime `(persisted, candidate)` pair the caller supplied —
    /// reject. The caller MAY have supplied the runtime chain id
    /// as the `expected` side; this variant fires when the marker
    /// itself disagrees.
    ChainMismatch {
        persisted_chain_id: String,
        candidate_chain_id: String,
    },

    /// Persisted or candidate `environment` does not match — reject.
    EnvironmentMismatch {
        persisted_environment: TrustBundleEnvironment,
        candidate_environment: TrustBundleEnvironment,
    },

    /// Persisted or candidate `genesis_hash` does not match — reject.
    /// Catches wrong-data-dir / wrong-snapshot copy where the
    /// `(env, chain_id)` may coincidentally match but the genesis
    /// authority surface differs.
    GenesisHashMismatch {
        persisted_genesis_hash: String,
        candidate_genesis_hash: String,
    },

    /// Candidate's `authority_policy_version` is strictly lower
    /// than persisted — reject (schema downgrade is unsafe).
    PolicyVersionRegression {
        persisted_policy_version: u32,
        candidate_policy_version: u32,
    },

    /// Catch-all for a logically corrupt record pair that survives
    /// structural validation but disagrees in a way no other
    /// variant captures. Returned only by [`compare_authority_state`];
    /// JSON-level corruption surfaces as
    /// [`AuthorityStateError::Malformed`] from [`load_authority_state`].
    Corrupt { reason: String },
}

impl AuthorityStateComparison {
    /// True iff this outcome means the caller is permitted to
    /// advance the persisted record (`FirstLoad` or `Upgrade`).
    /// `EqualIdempotent` is an accept but does **not** require
    /// a rewrite, mirroring the Run 055 same-fingerprint precedent.
    pub fn accept_advance(&self) -> bool {
        matches!(self, Self::FirstLoad | Self::Upgrade { .. })
    }

    /// True iff this outcome means the candidate is acceptable
    /// (the on-disk record may or may not need to be rewritten).
    pub fn is_accept(&self) -> bool {
        matches!(
            self,
            Self::FirstLoad | Self::EqualIdempotent | Self::Upgrade { .. }
        )
    }

    /// True iff this outcome is a rejection.
    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }
}

impl std::fmt::Display for AuthorityStateComparison {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FirstLoad => write!(f, "first-load (no prior authority marker)"),
            Self::EqualIdempotent => {
                write!(f, "equal-idempotent (authority marker unchanged)")
            }
            Self::Upgrade {
                previous_sequence,
                new_sequence,
            } => write!(
                f,
                "upgrade authority_sequence {} -> {}",
                previous_sequence, new_sequence
            ),
            Self::RollbackRefused {
                persisted_sequence,
                attempted_sequence,
            } => write!(
                f,
                "authority-state rollback rejected: attempted authority_sequence={} is lower than persisted authority_sequence={} (fail closed)",
                attempted_sequence, persisted_sequence
            ),
            Self::SameSequenceConflictingHash {
                sequence,
                persisted_hash,
                attempted_hash,
            } => write!(
                f,
                "authority-state same-sequence equivocation rejected: authority_sequence={} persisted_ratification_hash={} attempted_ratification_hash={} (fail closed; two distinct ratifications cannot share the same authority_sequence)",
                sequence, persisted_hash, attempted_hash
            ),
            Self::SameSequenceConflictingKey {
                sequence,
                persisted_key_fingerprint,
                attempted_key_fingerprint,
            } => write!(
                f,
                "authority-state same-sequence key conflict rejected: authority_sequence={} persisted_key_fingerprint={} attempted_key_fingerprint={} (fail closed; ratified bundle-signing key cannot be silently swapped at the same authority_sequence)",
                sequence, persisted_key_fingerprint, attempted_key_fingerprint
            ),
            Self::ChainMismatch {
                persisted_chain_id,
                candidate_chain_id,
            } => write!(
                f,
                "authority-state chain_id mismatch rejected: persisted={} candidate={} (fail closed)",
                persisted_chain_id, candidate_chain_id
            ),
            Self::EnvironmentMismatch {
                persisted_environment,
                candidate_environment,
            } => write!(
                f,
                "authority-state environment mismatch rejected: persisted={} candidate={} (fail closed)",
                persisted_environment, candidate_environment
            ),
            Self::GenesisHashMismatch {
                persisted_genesis_hash,
                candidate_genesis_hash,
            } => write!(
                f,
                "authority-state genesis_hash mismatch rejected: persisted={} candidate={} (fail closed)",
                persisted_genesis_hash, candidate_genesis_hash
            ),
            Self::PolicyVersionRegression {
                persisted_policy_version,
                candidate_policy_version,
            } => write!(
                f,
                "authority-state policy-version regression rejected: persisted={} candidate={} (fail closed)",
                persisted_policy_version, candidate_policy_version
            ),
            Self::Corrupt { reason } => {
                write!(f, "authority-state corruption rejected: {} (fail closed)", reason)
            }
        }
    }
}

// ===========================================================================
// Canonical preimage / digest
// ===========================================================================

/// Render a [`ChainId`] as the 16-char lowercase hex form persisted
/// in the record (no `0x` / `chain_` prefix — matches
/// [`crate::pqc_trust_sequence::chain_id_hex`]).
pub fn chain_id_hex(chain_id: ChainId) -> String {
    format!("{:016x}", chain_id.as_u64())
}

/// Render a 32-byte genesis hash as 64 lowercase hex chars.
pub fn genesis_hash_hex(h: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in h {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", b);
    }
    out
}

/// Canonical, deterministic, domain-separated preimage for an
/// authority-state record. Layout (all integers big-endian, all
/// variable-length fields prefixed with a `u32` byte length):
///
/// ```text
/// AUTHORITY_STATE_DOMAIN_V1
/// u32  record_version
/// u32  len(chain_id)                              | chain_id bytes (ascii)
/// u32  len(environment_tag)                       | environment_tag bytes (ascii)
/// u32  len(genesis_hash)                          | genesis_hash bytes (ascii)
/// u32  authority_policy_version
/// u64  authority_sequence
/// u8   authority_epoch_present (0 or 1)
/// u64  authority_epoch (present iff prev byte == 1; else absent)
/// u32  len(authority_root_fingerprint)            | authority_root_fingerprint bytes
/// u32  len(ratified_bundle_signing_key_fp)        | ratified_bundle_signing_key_fp bytes
/// u32  len(ratification_object_hash)              | ratification_object_hash bytes
/// ```
///
/// `last_update_source` and `updated_at_unix_secs` are intentionally
/// **not** included — both are informational-only audit fields and
/// must not contribute to the security digest (otherwise a benign
/// restart would change the digest without changing the security-
/// relevant state).
pub fn canonical_authority_state_preimage(r: &PersistentAuthorityStateRecord) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        AUTHORITY_STATE_DOMAIN_V1.len()
            + 4
            + 4
            + r.chain_id.len()
            + 4
            + r.environment.as_tag().len()
            + 4
            + r.genesis_hash.len()
            + 4
            + 8
            + 1
            + 8
            + 4
            + r.authority_root_fingerprint.len()
            + 4
            + r.ratified_bundle_signing_key_fingerprint.len()
            + 4
            + r.ratification_object_hash.len(),
    );
    buf.extend_from_slice(AUTHORITY_STATE_DOMAIN_V1);
    buf.extend_from_slice(&r.record_version.to_be_bytes());

    encode_length_prefixed(&mut buf, r.chain_id.as_bytes());
    encode_length_prefixed(&mut buf, r.environment.as_tag().as_bytes());
    encode_length_prefixed(&mut buf, r.genesis_hash.as_bytes());

    buf.extend_from_slice(&r.authority_policy_version.to_be_bytes());
    buf.extend_from_slice(&r.authority_sequence.to_be_bytes());

    match r.authority_epoch {
        Some(e) => {
            buf.push(1);
            buf.extend_from_slice(&e.to_be_bytes());
        }
        None => {
            buf.push(0);
        }
    }

    encode_length_prefixed(&mut buf, r.authority_root_fingerprint.as_bytes());
    encode_length_prefixed(
        &mut buf,
        r.ratified_bundle_signing_key_fingerprint.as_bytes(),
    );
    encode_length_prefixed(&mut buf, r.ratification_object_hash.as_bytes());

    buf
}

/// 32-byte SHA3-256 digest over
/// [`canonical_authority_state_preimage`]. Stable across platforms
/// and includes every security-relevant field.
pub fn canonical_authority_state_digest(r: &PersistentAuthorityStateRecord) -> [u8; 32] {
    qbind_hash::sha3_256(&canonical_authority_state_preimage(r))
}

/// Canonical deterministic preimage for a v2 marker record.
pub fn canonical_authority_state_v2_preimage(r: &PersistentAuthorityStateRecordV2) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        AUTHORITY_STATE_DOMAIN_V2.len()
            + 4
            + 4
            + 4
            + r.chain_id.len()
            + 4
            + r.environment.as_tag().len()
            + 4
            + r.genesis_hash.len()
            + 4
            + r.authority_root_fingerprint.len()
            + 1
            + 4
            + r.active_bundle_signing_key_fingerprint.len()
            + 1
            + 8
            + 1
            + 1
            + 4
            + r.previous_bundle_signing_key_fingerprint
                .as_ref()
                .map(|s| s.len())
                .unwrap_or(0)
            + 4
            + r.latest_ratification_v2_digest.len()
            + 1
            + 4
            + r.revoked_key_metadata
                .as_ref()
                .map(|s| s.len())
                .unwrap_or(0),
    );
    buf.extend_from_slice(AUTHORITY_STATE_DOMAIN_V2);
    buf.extend_from_slice(&r.record_version.to_be_bytes());
    buf.extend_from_slice(&r.authority_schema_version.to_be_bytes());
    encode_length_prefixed(&mut buf, r.chain_id.as_bytes());
    encode_length_prefixed(&mut buf, r.environment.as_tag().as_bytes());
    encode_length_prefixed(&mut buf, r.genesis_hash.as_bytes());
    encode_length_prefixed(&mut buf, r.authority_root_fingerprint.as_bytes());
    buf.push(r.authority_root_suite_id);
    encode_length_prefixed(&mut buf, r.active_bundle_signing_key_fingerprint.as_bytes());
    buf.push(r.active_bundle_signing_key_suite_id);
    buf.extend_from_slice(&r.latest_authority_domain_sequence.to_be_bytes());
    buf.push(r.latest_lifecycle_action.as_byte());
    if let Some(prev) = r.previous_bundle_signing_key_fingerprint.as_ref() {
        buf.push(1);
        encode_length_prefixed(&mut buf, prev.as_bytes());
    } else {
        buf.push(0);
    }
    encode_length_prefixed(&mut buf, r.latest_ratification_v2_digest.as_bytes());
    if let Some(revoked) = r.revoked_key_metadata.as_ref() {
        buf.push(1);
        encode_length_prefixed(&mut buf, revoked.as_bytes());
    } else {
        buf.push(0);
    }
    buf
}

/// Domain-separated SHA3-256 digest for a v2 marker.
pub fn canonical_authority_state_v2_digest(r: &PersistentAuthorityStateRecordV2) -> [u8; 32] {
    qbind_hash::sha3_256(&canonical_authority_state_v2_preimage(r))
}

fn encode_length_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn is_lower_hex(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// Convenience accessor on TrustBundleEnvironment — kept inside this
// module so we never reach across the public API of pqc_trust_bundle
// for what is a stable lowercase ascii tag.
trait TrustBundleEnvironmentTag {
    fn as_tag(&self) -> &'static str;
}

impl TrustBundleEnvironmentTag for TrustBundleEnvironment {
    fn as_tag(&self) -> &'static str {
        match *self {
            TrustBundleEnvironment::Devnet => "devnet",
            TrustBundleEnvironment::Testnet => "testnet",
            TrustBundleEnvironment::Mainnet => "mainnet",
        }
    }
}

// ===========================================================================
// Pure comparison
// ===========================================================================

/// Pure, side-effect-free comparison of a candidate authority-state
/// record against an optionally-persisted prior record. Returns a
/// typed [`AuthorityStateComparison`] outcome — never a boolean.
///
/// **Both** records must be structurally valid; callers are expected
/// to call [`PersistentAuthorityStateRecord::validate_structure`]
/// (or rely on [`load_authority_state`] which does so) before
/// invoking this function. If both records happen to be
/// structurally valid but disagree in a way none of the typed
/// variants captures, [`AuthorityStateComparison::Corrupt`] is
/// returned with a precise reason.
///
/// Comparison ordering (first match wins):
///
/// 1. `persisted` is `None` → `FirstLoad`.
/// 2. `ChainMismatch` if `chain_id` differs.
/// 3. `EnvironmentMismatch` if `environment` differs.
/// 4. `GenesisHashMismatch` if `genesis_hash` differs.
/// 5. `PolicyVersionRegression` if candidate's policy version is
///    strictly lower.
/// 6. `RollbackRefused` if candidate's authority_sequence is
///    strictly lower.
/// 7. At equal `authority_sequence`:
///    - identical record → `EqualIdempotent`,
///    - same authority_root, different ratified-key fingerprint →
///      `SameSequenceConflictingKey`,
///    - different ratification_object_hash → `SameSequenceConflictingHash`,
///    - otherwise → `Corrupt` (catch-all; should not occur).
/// 8. At strictly higher `authority_sequence` → `Upgrade`.
pub fn compare_authority_state(
    persisted: Option<&PersistentAuthorityStateRecord>,
    candidate: &PersistentAuthorityStateRecord,
) -> AuthorityStateComparison {
    let Some(prev) = persisted else {
        return AuthorityStateComparison::FirstLoad;
    };

    if prev.chain_id != candidate.chain_id {
        return AuthorityStateComparison::ChainMismatch {
            persisted_chain_id: prev.chain_id.clone(),
            candidate_chain_id: candidate.chain_id.clone(),
        };
    }
    if prev.environment != candidate.environment {
        return AuthorityStateComparison::EnvironmentMismatch {
            persisted_environment: prev.environment,
            candidate_environment: candidate.environment,
        };
    }
    if prev.genesis_hash != candidate.genesis_hash {
        return AuthorityStateComparison::GenesisHashMismatch {
            persisted_genesis_hash: prev.genesis_hash.clone(),
            candidate_genesis_hash: candidate.genesis_hash.clone(),
        };
    }
    if candidate.authority_policy_version < prev.authority_policy_version {
        return AuthorityStateComparison::PolicyVersionRegression {
            persisted_policy_version: prev.authority_policy_version,
            candidate_policy_version: candidate.authority_policy_version,
        };
    }
    if candidate.authority_sequence < prev.authority_sequence {
        return AuthorityStateComparison::RollbackRefused {
            persisted_sequence: prev.authority_sequence,
            attempted_sequence: candidate.authority_sequence,
        };
    }
    if candidate.authority_sequence == prev.authority_sequence {
        // Equal-sequence policy.
        let same_hash = prev.ratification_object_hash == candidate.ratification_object_hash;
        let same_root = prev.authority_root_fingerprint == candidate.authority_root_fingerprint;
        let same_key = prev.ratified_bundle_signing_key_fingerprint
            == candidate.ratified_bundle_signing_key_fingerprint;
        let same_epoch = prev.authority_epoch == candidate.authority_epoch;
        let same_policy_version =
            prev.authority_policy_version == candidate.authority_policy_version;

        if same_hash && same_root && same_key && same_epoch && same_policy_version {
            return AuthorityStateComparison::EqualIdempotent;
        }
        if same_root && !same_key {
            return AuthorityStateComparison::SameSequenceConflictingKey {
                sequence: prev.authority_sequence,
                persisted_key_fingerprint: prev.ratified_bundle_signing_key_fingerprint.clone(),
                attempted_key_fingerprint: candidate
                    .ratified_bundle_signing_key_fingerprint
                    .clone(),
            };
        }
        if !same_hash {
            return AuthorityStateComparison::SameSequenceConflictingHash {
                sequence: prev.authority_sequence,
                persisted_hash: prev.ratification_object_hash.clone(),
                attempted_hash: candidate.ratification_object_hash.clone(),
            };
        }
        // Same sequence, same hash, same root, same key, but
        // authority_epoch or authority_policy_version differs.
        // Treat as corrupt — these fields are hash-bound at the
        // ratification layer so they cannot legitimately drift
        // without a sequence change.
        return AuthorityStateComparison::Corrupt {
            reason: format!(
                "equal authority_sequence={} and equal ratification_object_hash but disagreeing authority_epoch/authority_policy_version: persisted_epoch={:?} candidate_epoch={:?} persisted_policy_version={} candidate_policy_version={}",
                prev.authority_sequence,
                prev.authority_epoch,
                candidate.authority_epoch,
                prev.authority_policy_version,
                candidate.authority_policy_version,
            ),
        };
    }

    // candidate.authority_sequence > prev.authority_sequence
    AuthorityStateComparison::Upgrade {
        previous_sequence: prev.authority_sequence,
        new_sequence: candidate.authority_sequence,
    }
}

// ===========================================================================
// Load / persist API
// ===========================================================================

/// Load the persisted authority-state record from `path` if it
/// exists.
///
/// - Returns `Ok(None)` if the file does not exist (first-load
///   case; this is **explicit absence**, not a synthetic empty
///   marker — the caller must treat it as "no prior authority
///   marker", never as "empty/permissive authority state").
/// - Returns `Ok(Some(record))` on a successful, structurally valid
///   load. The caller MUST still verify the record applies to the
///   runtime `(environment, chain_id, genesis_hash)` trust domain
///   via [`compare_authority_state`] (or
///   [`validate_record_for_domain`]) before relying on the value.
/// - Returns `Err(...)` on I/O, JSON, schema-version, or structural
///   defects. Fail closed.
///
/// Mirrors [`crate::pqc_trust_sequence::load_record`].
pub fn load_authority_state(
    path: &Path,
) -> Result<Option<PersistentAuthorityStateRecord>, AuthorityStateError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(AuthorityStateError::Io(format!(
                "{}: {}",
                path.display(),
                e.kind()
            )));
        }
    };
    let record: PersistentAuthorityStateRecord = serde_json::from_slice(&bytes)
        .map_err(|e| AuthorityStateError::Malformed(format!("{}", e)))?;
    record.validate_structure()?;
    Ok(Some(record))
}

/// Verify that a freshly-loaded record applies to the runtime
/// `(environment, chain_id, genesis_hash)` trust domain. Returns
/// the precise [`AuthorityStateComparison`] reject variant on
/// mismatch, or `Ok(())` on match. Run 117 exposes this as a
/// helper so Run 118 wiring can fail fast before invoking
/// [`compare_authority_state`].
pub fn validate_record_for_domain(
    record: &PersistentAuthorityStateRecord,
    expected_env: NetworkEnvironment,
    expected_chain_id: ChainId,
    expected_genesis_hash_hex: &str,
) -> Result<(), AuthorityStateComparison> {
    let expected_env_bundle = TrustBundleEnvironment::from_runtime(expected_env);
    if record.environment != expected_env_bundle {
        return Err(AuthorityStateComparison::EnvironmentMismatch {
            persisted_environment: record.environment,
            candidate_environment: expected_env_bundle,
        });
    }
    let expected_chain_hex = chain_id_hex(expected_chain_id);
    if record.chain_id != expected_chain_hex {
        return Err(AuthorityStateComparison::ChainMismatch {
            persisted_chain_id: record.chain_id.clone(),
            candidate_chain_id: expected_chain_hex,
        });
    }
    if record.genesis_hash != expected_genesis_hash_hex {
        return Err(AuthorityStateComparison::GenesisHashMismatch {
            persisted_genesis_hash: record.genesis_hash.clone(),
            candidate_genesis_hash: expected_genesis_hash_hex.to_string(),
        });
    }
    Ok(())
}

/// Atomically write `record` to `path` using a `tmp` sibling +
/// rename, with `sync_all` on both the tmp file and the parent
/// directory.
///
/// The flow is:
///
/// 1. Serialise `record` to canonical JSON (`serde_json`).
/// 2. Create the parent directory if it does not exist.
/// 3. Write the serialised bytes to `<path>.tmp`.
/// 4. `sync_all()` the tmp file.
/// 5. Rename `<path>.tmp` → `<path>`.
/// 6. `sync_all()` the parent directory (best-effort; on platforms
///    where directory `sync_all` is unsupported the error is
///    surfaced as [`AuthorityStateError::PersistFailure`] — Run 117
///    does not silently swallow a parent-dir fsync failure on
///    fail-closed paths).
///
/// On Windows, opening a directory with `OpenOptions::read(true)`
/// returns an error; the parent-dir fsync step is skipped on
/// non-Unix targets (best-effort), and the rename + tmp-file
/// fsync combination remains the durability anchor.
///
/// Any I/O failure surfaces as [`AuthorityStateError::PersistFailure`].
/// On a mid-write crash the destination file is left intact and
/// the `.tmp` sibling (if any) is harmless — the next load returns
/// the previously persisted record verbatim.
pub fn persist_authority_state_atomic(
    path: &Path,
    record: &PersistentAuthorityStateRecord,
) -> Result<(), AuthorityStateError> {
    use std::io::Write;
    record.validate_structure().map_err(|e| {
        AuthorityStateError::PersistFailure(format!("pre-write structural validation: {}", e))
    })?;
    let bytes = serde_json::to_vec(record)
        .map_err(|e| AuthorityStateError::PersistFailure(format!("serialise: {}", e)))?;
    let parent = path.parent();
    if let Some(parent) = parent {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                AuthorityStateError::PersistFailure(format!(
                    "create_dir_all {}: {}",
                    parent.display(),
                    e.kind()
                ))
            })?;
        }
    }
    let tmp_path = {
        let mut p = path.as_os_str().to_owned();
        p.push(".tmp");
        PathBuf::from(p)
    };
    {
        let mut f = std::fs::File::create(&tmp_path).map_err(|e| {
            AuthorityStateError::PersistFailure(format!(
                "create {}: {}",
                tmp_path.display(),
                e.kind()
            ))
        })?;
        f.write_all(&bytes).map_err(|e| {
            AuthorityStateError::PersistFailure(format!(
                "write {}: {}",
                tmp_path.display(),
                e.kind()
            ))
        })?;
        f.sync_all().map_err(|e| {
            AuthorityStateError::PersistFailure(format!(
                "sync_all {}: {}",
                tmp_path.display(),
                e.kind()
            ))
        })?;
    }
    std::fs::rename(&tmp_path, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        AuthorityStateError::PersistFailure(format!(
            "rename {} -> {}: {}",
            tmp_path.display(),
            path.display(),
            e.kind()
        ))
    })?;

    // Best-effort parent-directory fsync so that the rename is
    // durable in the directory entry, not just in the inode. We do
    // this only on Unix-like targets where opening a directory for
    // read + calling `sync_all` is supported.
    #[cfg(unix)]
    {
        if let Some(parent) = parent {
            if !parent.as_os_str().is_empty() {
                let dir = std::fs::File::open(parent).map_err(|e| {
                    AuthorityStateError::PersistFailure(format!(
                        "open parent dir {} for fsync: {}",
                        parent.display(),
                        e.kind()
                    ))
                })?;
                dir.sync_all().map_err(|e| {
                    AuthorityStateError::PersistFailure(format!(
                        "sync_all parent dir {}: {}",
                        parent.display(),
                        e.kind()
                    ))
                })?;
            }
        }
    }

    Ok(())
}

// ===========================================================================
// Run 118 — Marker derivation from a verified ratification
// ===========================================================================

/// Inputs required to derive a [`PersistentAuthorityStateRecord`] from a
/// verified ratification context.
///
/// Every field is supplied by the caller and is expected to come from
/// material that has **already** been verified by:
///
/// * the Run 102/104 boot-genesis loader for `runtime_env`, `runtime_chain_id`,
///   `runtime_genesis_hash_hex`, and `authority_policy_version` /
///   `authority_sequence` / `authority_epoch`;
/// * the Run 103 / Run 105 ratification verifier
///   ([`qbind_ledger::enforce_bundle_signing_key_ratification`]) for the
///   [`BundleSigningRatification`] object and the
///   [`RatifiedBundleSigningKey`] identity result.
///
/// Run 118 deliberately does NOT load these values from disk or recompute
/// them inside the helper — that would risk producing a marker out of step
/// with whatever the verifier just accepted. The helper is a pure derivation
/// step: it never returns a marker for an unverified ratification because it
/// has no surface for one.
#[derive(Debug, Clone)]
pub struct AuthorityStateDerivationInputs<'a> {
    /// Runtime network environment (e.g. from CLI / config). The derived
    /// marker carries the [`TrustBundleEnvironment`] mapping.
    pub runtime_env: NetworkEnvironment,
    /// Runtime chain id (Run 069+).
    pub runtime_chain_id: ChainId,
    /// 64 lowercase hex chars of the canonical genesis hash this node booted
    /// against. Equals `compute_canonical_genesis_hash(...)` on the runtime
    /// genesis config.
    pub runtime_genesis_hash_hex: &'a str,
    /// Genesis-bound authority-policy version (Run 101
    /// [`qbind_ledger::genesis::GenesisAuthorityConfig::authority_policy_version`]).
    pub authority_policy_version: u32,
    /// Genesis-bound authority sequence anchor (Run 101).
    pub authority_sequence: u64,
    /// Optional genesis-bound authority epoch (Run 101).
    pub authority_epoch: Option<u64>,
    /// The structurally-valid ratification object whose acceptance is being
    /// recorded. The helper computes `ratification_object_hash` directly
    /// from this object via [`canonical_ratification_digest`] so the marker
    /// can never disagree with the verifier on which ratification it bound.
    pub ratification: &'a BundleSigningRatification,
    /// The verifier's typed [`RatifiedBundleSigningKey`] result. Provides
    /// the `authority_root_fingerprint` and
    /// `ratified_bundle_signing_key_fingerprint` fields without re-deriving
    /// them from the [`BundleSigningRatification`] object.
    pub ratified: &'a RatifiedBundleSigningKey,
    /// Tag identifying which mutating surface triggered this derivation.
    /// Informational only; never participates in the security digest.
    pub update_source: AuthorityStateUpdateSource,
    /// Wall-clock time at which the marker is being derived, in Unix seconds.
    /// Informational only; never participates in the security digest.
    pub updated_at_unix_secs: u64,
}

/// Reasons the derivation step itself can refuse to produce a marker
/// **before** any persistence or comparison is attempted. Every variant
/// is a fail-closed precondition violation indicating that the caller fed
/// the helper a value that did not come out of the Run 102/104 boot path
/// or the Run 103/105 verifier surface (or that those surfaces produced
/// inconsistent values, which would itself be a bug worth tripping on).
///
/// The helper never tries to repair or relax these conditions; the binary
/// surface MUST treat any variant as a fail-closed condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityStateDerivationError {
    /// `runtime_genesis_hash_hex` was not exactly 64 lowercase hex chars.
    /// Indicates a caller bug (e.g. wrong format / `0x` prefix included).
    MalformedRuntimeGenesisHash(String),
    /// `ratification.environment` does not map to `runtime_env`. The Run 103
    /// verifier would already have rejected this pairing; if we see it here
    /// the caller wired the verifier output incorrectly. Fail closed.
    EnvironmentMismatch {
        ratification_env: String,
        runtime_env: String,
    },
    /// `ratification.chain_id` does not equal `runtime_chain_id` (rendered
    /// as the canonical 16-char lowercase hex). Same fail-closed bug class
    /// as `EnvironmentMismatch`.
    ChainIdMismatch {
        ratification_chain_id: String,
        runtime_chain_id_hex: String,
    },
    /// `ratification.authority_root_fingerprint` disagrees with
    /// `ratified.authority_root_fingerprint`. The Run 103 verifier produces
    /// both from the same source so this should be impossible — surface
    /// it explicitly rather than silently picking one.
    RatificationVerifierInconsistent(String),
    /// The derived record failed
    /// [`PersistentAuthorityStateRecord::validate_structure`] — e.g. an
    /// empty `authority_root_fingerprint`, a `0` `authority_policy_version`,
    /// or non-lowercase-hex characters in a fingerprint. Indicates upstream
    /// validation drift; fail closed.
    InvalidDerivedRecord(AuthorityStateError),
}

impl std::fmt::Display for AuthorityStateDerivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedRuntimeGenesisHash(s) => write!(
                f,
                "authority-state derivation: malformed runtime genesis_hash hex: {} (expected exactly 64 lowercase hex chars)",
                s
            ),
            Self::EnvironmentMismatch {
                ratification_env,
                runtime_env,
            } => write!(
                f,
                "authority-state derivation: ratification.environment={} disagrees with runtime env={} (fail closed; the verifier should have rejected this pairing)",
                ratification_env, runtime_env
            ),
            Self::ChainIdMismatch {
                ratification_chain_id,
                runtime_chain_id_hex,
            } => write!(
                f,
                "authority-state derivation: ratification.chain_id={} disagrees with runtime chain_id_hex={} (fail closed; the verifier should have rejected this pairing)",
                ratification_chain_id, runtime_chain_id_hex
            ),
            Self::RatificationVerifierInconsistent(s) => write!(
                f,
                "authority-state derivation: verifier-result inconsistency: {} (fail closed)",
                s
            ),
            Self::InvalidDerivedRecord(e) => write!(
                f,
                "authority-state derivation: derived record fails structural validation: {} (fail closed; upstream validator drift)",
                e
            ),
        }
    }
}

impl std::error::Error for AuthorityStateDerivationError {}

/// Render a 32-byte SHA3-256 digest as 64 lowercase hex chars. Used by the
/// derivation helper to render
/// [`canonical_ratification_digest`] for storage in
/// `ratification_object_hash`.
fn digest32_hex(d: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in d {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Derive a [`PersistentAuthorityStateRecord`] from a verified ratification
/// context.
///
/// This is the **only** Run 118 path that produces a marker from a
/// ratification: it binds the candidate record to:
///
/// * the runtime `(env, chain_id, genesis_hash)` trust domain (so a marker
///   for one trust domain can never be persisted under another);
/// * the genesis-bound `(authority_policy_version, authority_sequence,
///   authority_epoch)` triple (so the marker advances only via Run 101
///   genesis-authority bumps);
/// * the verifier's `RatifiedBundleSigningKey` identity (`authority_root_fp`,
///   `ratified_bundle_signing_key_fingerprint`);
/// * the `canonical_ratification_digest` of the [`BundleSigningRatification`]
///   object whose acceptance triggered this derivation.
///
/// The helper does NOT verify the ratification — it presumes the caller
/// already invoked [`qbind_ledger::enforce_bundle_signing_key_ratification`]
/// (or the Run 105 enforcement wrapper) and is only persisting the outcome.
/// To make caller misuse harder, the helper double-checks that
/// `ratification.environment` / `ratification.chain_id` agree with the
/// `runtime_env` / `runtime_chain_id` and that
/// `ratification.authority_root_fingerprint` agrees with
/// `ratified.authority_root_fingerprint`.
///
/// Deterministic: given identical inputs the helper produces a record whose
/// [`canonical_authority_state_digest`] is identical bit-for-bit. The only
/// informational drift between two calls is `update_source` and
/// `updated_at_unix_secs`, both of which are excluded from the digest by
/// construction.
pub fn derive_authority_state_from_ratification(
    inputs: AuthorityStateDerivationInputs<'_>,
) -> Result<PersistentAuthorityStateRecord, AuthorityStateDerivationError> {
    if inputs.runtime_genesis_hash_hex.len() != 64 || !is_lower_hex(inputs.runtime_genesis_hash_hex)
    {
        return Err(AuthorityStateDerivationError::MalformedRuntimeGenesisHash(
            inputs.runtime_genesis_hash_hex.to_string(),
        ));
    }

    // Cross-check verifier consistency: ratification.environment must map
    // to the runtime env, ratification.chain_id must equal the canonical
    // 16-char lowercase hex of the runtime chain id, and ratified.authority
    // _root_fingerprint must equal ratification.authority_root_fingerprint.
    let runtime_env_tag = match inputs.runtime_env {
        NetworkEnvironment::Devnet => "devnet",
        NetworkEnvironment::Testnet => "testnet",
        NetworkEnvironment::Mainnet => "mainnet",
    };
    if inputs.ratification.environment.tag() != runtime_env_tag {
        return Err(AuthorityStateDerivationError::EnvironmentMismatch {
            ratification_env: inputs.ratification.environment.tag().to_string(),
            runtime_env: runtime_env_tag.to_string(),
        });
    }

    let runtime_chain_id_hex = chain_id_hex(inputs.runtime_chain_id);
    if inputs.ratification.chain_id != runtime_chain_id_hex {
        return Err(AuthorityStateDerivationError::ChainIdMismatch {
            ratification_chain_id: inputs.ratification.chain_id.clone(),
            runtime_chain_id_hex,
        });
    }

    if inputs.ratification.authority_root_fingerprint != inputs.ratified.authority_root_fingerprint
    {
        return Err(
            AuthorityStateDerivationError::RatificationVerifierInconsistent(format!(
                "ratification.authority_root_fingerprint={} but RatifiedBundleSigningKey.authority_root_fingerprint={}",
                inputs.ratification.authority_root_fingerprint,
                inputs.ratified.authority_root_fingerprint,
            )),
        );
    }

    let environment = TrustBundleEnvironment::from_runtime(inputs.runtime_env);
    let ratification_digest = canonical_ratification_digest(inputs.ratification);
    let ratification_object_hash = digest32_hex(&ratification_digest);

    let record = PersistentAuthorityStateRecord::new(
        runtime_chain_id_hex,
        environment,
        inputs.runtime_genesis_hash_hex.to_string(),
        inputs.authority_policy_version,
        inputs.authority_sequence,
        inputs.authority_epoch,
        inputs.ratified.authority_root_fingerprint.clone(),
        inputs.ratified.fingerprint.clone(),
        ratification_object_hash,
        inputs.update_source,
        inputs.updated_at_unix_secs,
    );

    record
        .validate_structure()
        .map_err(AuthorityStateDerivationError::InvalidDerivedRecord)?;

    Ok(record)
}

/// Inputs required to derive a v2 marker from verified v2 ratification output.
#[derive(Debug, Clone)]
pub struct AuthorityStateDerivationV2Inputs<'a> {
    pub runtime_env: NetworkEnvironment,
    pub runtime_chain_id: ChainId,
    pub runtime_genesis_hash_hex: &'a str,
    pub ratification: &'a BundleSigningRatificationV2,
    pub ratified: &'a RatifiedBundleSigningKeyV2,
    pub update_source: AuthorityStateUpdateSource,
    pub updated_at_unix_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityStateDerivationV2Error {
    MalformedRuntimeGenesisHash(String),
    UnsupportedRatificationSchemaVersion(u32),
    EnvironmentMismatch {
        ratification_env: String,
        runtime_env: String,
    },
    ChainIdMismatch {
        ratification_chain_id: String,
        runtime_chain_id_hex: String,
    },
    GenesisHashMismatch {
        ratification_genesis_hash_hex: String,
        runtime_genesis_hash_hex: String,
    },
    AuthorityRootMismatch {
        ratification_authority_root_fingerprint: String,
        verifier_authority_root_fingerprint: String,
    },
    TargetKeyBindingMismatch {
        ratification_target_fingerprint: String,
        verifier_target_fingerprint: String,
    },
    TargetSuiteBindingMismatch {
        ratification_target_suite_id: u8,
        verifier_target_suite_id: u8,
    },
    SequenceBindingMismatch {
        ratification_sequence: u64,
        verifier_sequence: u64,
    },
    ActionBindingMismatch {
        ratification_action: BundleSigningRatificationV2Action,
        verifier_action: BundleSigningRatificationV2Action,
    },
    MissingPreviousKeyForRotate,
    MissingPreviousDigestForRotate,
    MalformedPreviousDigest(String),
    UnexpectedRotateFieldsForRatify,
    MissingRevokedMetadataForRevoke,
    InvalidDerivedRecord(AuthorityStateError),
}

impl std::fmt::Display for AuthorityStateDerivationV2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedRuntimeGenesisHash(s) => write!(
                f,
                "authority-state v2 derivation: malformed runtime genesis hash {} (expected 64 lowercase hex chars)",
                s
            ),
            Self::UnsupportedRatificationSchemaVersion(v) => write!(
                f,
                "authority-state v2 derivation: unsupported ratification schema version {} (expected 2)",
                v
            ),
            Self::EnvironmentMismatch {
                ratification_env,
                runtime_env,
            } => write!(
                f,
                "authority-state v2 derivation: ratification environment {} disagrees with runtime environment {}",
                ratification_env, runtime_env
            ),
            Self::ChainIdMismatch {
                ratification_chain_id,
                runtime_chain_id_hex,
            } => write!(
                f,
                "authority-state v2 derivation: ratification chain_id {} disagrees with runtime chain_id {}",
                ratification_chain_id, runtime_chain_id_hex
            ),
            Self::GenesisHashMismatch {
                ratification_genesis_hash_hex,
                runtime_genesis_hash_hex,
            } => write!(
                f,
                "authority-state v2 derivation: ratification genesis {} disagrees with runtime genesis {}",
                ratification_genesis_hash_hex, runtime_genesis_hash_hex
            ),
            Self::AuthorityRootMismatch {
                ratification_authority_root_fingerprint,
                verifier_authority_root_fingerprint,
            } => write!(
                f,
                "authority-state v2 derivation: authority-root binding mismatch ratification={} verifier={}",
                ratification_authority_root_fingerprint, verifier_authority_root_fingerprint
            ),
            Self::TargetKeyBindingMismatch {
                ratification_target_fingerprint,
                verifier_target_fingerprint,
            } => write!(
                f,
                "authority-state v2 derivation: target-key binding mismatch ratification={} verifier={}",
                ratification_target_fingerprint, verifier_target_fingerprint
            ),
            Self::TargetSuiteBindingMismatch {
                ratification_target_suite_id,
                verifier_target_suite_id,
            } => write!(
                f,
                "authority-state v2 derivation: target-suite binding mismatch ratification={} verifier={}",
                ratification_target_suite_id, verifier_target_suite_id
            ),
            Self::SequenceBindingMismatch {
                ratification_sequence,
                verifier_sequence,
            } => write!(
                f,
                "authority-state v2 derivation: sequence binding mismatch ratification={} verifier={}",
                ratification_sequence, verifier_sequence
            ),
            Self::ActionBindingMismatch {
                ratification_action,
                verifier_action,
            } => write!(
                f,
                "authority-state v2 derivation: action binding mismatch ratification={} verifier={}",
                ratification_action.tag(),
                verifier_action.tag()
            ),
            Self::MissingPreviousKeyForRotate => write!(
                f,
                "authority-state v2 derivation: rotate action requires previous key fingerprint"
            ),
            Self::MissingPreviousDigestForRotate => write!(
                f,
                "authority-state v2 derivation: rotate action requires previous ratification digest"
            ),
            Self::MalformedPreviousDigest(d) => write!(
                f,
                "authority-state v2 derivation: previous ratification digest {} must be 64 lowercase hex chars",
                d
            ),
            Self::UnexpectedRotateFieldsForRatify => write!(
                f,
                "authority-state v2 derivation: ratify action must not carry rotate linkage fields"
            ),
            Self::MissingRevokedMetadataForRevoke => write!(
                f,
                "authority-state v2 derivation: revoke action requires revocation metadata placeholder"
            ),
            Self::InvalidDerivedRecord(e) => write!(
                f,
                "authority-state v2 derivation: derived v2 marker is structurally invalid: {}",
                e
            ),
        }
    }
}

impl std::error::Error for AuthorityStateDerivationV2Error {}

/// Derive a v2 marker from a verified v2 ratification and typed verifier output.
pub fn derive_authority_state_v2_from_ratification(
    inputs: AuthorityStateDerivationV2Inputs<'_>,
) -> Result<PersistentAuthorityStateRecordV2, AuthorityStateDerivationV2Error> {
    if inputs.runtime_genesis_hash_hex.len() != 64 || !is_lower_hex(inputs.runtime_genesis_hash_hex)
    {
        return Err(
            AuthorityStateDerivationV2Error::MalformedRuntimeGenesisHash(
                inputs.runtime_genesis_hash_hex.to_string(),
            ),
        );
    }
    if inputs.ratification.schema_version != 2 {
        return Err(
            AuthorityStateDerivationV2Error::UnsupportedRatificationSchemaVersion(
                inputs.ratification.schema_version,
            ),
        );
    }
    let runtime_env_tag = match inputs.runtime_env {
        NetworkEnvironment::Devnet => "devnet",
        NetworkEnvironment::Testnet => "testnet",
        NetworkEnvironment::Mainnet => "mainnet",
    };
    if inputs.ratification.environment.tag() != runtime_env_tag {
        return Err(AuthorityStateDerivationV2Error::EnvironmentMismatch {
            ratification_env: inputs.ratification.environment.tag().to_string(),
            runtime_env: runtime_env_tag.to_string(),
        });
    }
    let runtime_chain_id_hex = chain_id_hex(inputs.runtime_chain_id);
    if inputs.ratification.chain_id != runtime_chain_id_hex {
        return Err(AuthorityStateDerivationV2Error::ChainIdMismatch {
            ratification_chain_id: inputs.ratification.chain_id.clone(),
            runtime_chain_id_hex,
        });
    }
    let ratification_genesis_hex = genesis_hash_hex(&inputs.ratification.genesis_hash);
    if ratification_genesis_hex != inputs.runtime_genesis_hash_hex {
        return Err(AuthorityStateDerivationV2Error::GenesisHashMismatch {
            ratification_genesis_hash_hex: ratification_genesis_hex,
            runtime_genesis_hash_hex: inputs.runtime_genesis_hash_hex.to_string(),
        });
    }
    if inputs.ratification.authority_root_fingerprint != inputs.ratified.authority_root_fingerprint
    {
        return Err(AuthorityStateDerivationV2Error::AuthorityRootMismatch {
            ratification_authority_root_fingerprint: inputs
                .ratification
                .authority_root_fingerprint
                .clone(),
            verifier_authority_root_fingerprint: inputs.ratified.authority_root_fingerprint.clone(),
        });
    }
    if inputs.ratification.target_bundle_signing_key_fingerprint != inputs.ratified.fingerprint {
        return Err(AuthorityStateDerivationV2Error::TargetKeyBindingMismatch {
            ratification_target_fingerprint: inputs
                .ratification
                .target_bundle_signing_key_fingerprint
                .clone(),
            verifier_target_fingerprint: inputs.ratified.fingerprint.clone(),
        });
    }
    if inputs.ratification.target_bundle_signing_key_suite_id != inputs.ratified.suite_id {
        return Err(
            AuthorityStateDerivationV2Error::TargetSuiteBindingMismatch {
                ratification_target_suite_id: inputs
                    .ratification
                    .target_bundle_signing_key_suite_id,
                verifier_target_suite_id: inputs.ratified.suite_id,
            },
        );
    }
    if inputs.ratification.authority_domain_sequence != inputs.ratified.authority_domain_sequence {
        return Err(AuthorityStateDerivationV2Error::SequenceBindingMismatch {
            ratification_sequence: inputs.ratification.authority_domain_sequence,
            verifier_sequence: inputs.ratified.authority_domain_sequence,
        });
    }
    if inputs.ratification.key_lifecycle_action != inputs.ratified.key_lifecycle_action {
        return Err(AuthorityStateDerivationV2Error::ActionBindingMismatch {
            ratification_action: inputs.ratification.key_lifecycle_action,
            verifier_action: inputs.ratified.key_lifecycle_action,
        });
    }

    let (previous_key, revoked_key_metadata) = match inputs.ratified.key_lifecycle_action {
        BundleSigningRatificationV2Action::Ratify => {
            if inputs.ratification.previous_key_fingerprint.is_some()
                || inputs.ratification.previous_ratification_digest.is_some()
            {
                return Err(AuthorityStateDerivationV2Error::UnexpectedRotateFieldsForRatify);
            }
            (None, None)
        }
        BundleSigningRatificationV2Action::Rotate => {
            let Some(previous_key) = inputs.ratification.previous_key_fingerprint.clone() else {
                return Err(AuthorityStateDerivationV2Error::MissingPreviousKeyForRotate);
            };
            let Some(previous_digest) = inputs.ratification.previous_ratification_digest.as_ref()
            else {
                return Err(AuthorityStateDerivationV2Error::MissingPreviousDigestForRotate);
            };
            if previous_digest.len() != 64 || !is_lower_hex(previous_digest) {
                return Err(AuthorityStateDerivationV2Error::MalformedPreviousDigest(
                    previous_digest.clone(),
                ));
            }
            (Some(previous_key), None)
        }
        BundleSigningRatificationV2Action::Revoke => {
            if inputs.ratification.revocation_reason.is_none()
                && inputs.ratification.capabilities_scope.is_none()
            {
                return Err(AuthorityStateDerivationV2Error::MissingRevokedMetadataForRevoke);
            }
            (None, Some(inputs.ratified.fingerprint.clone()))
        }
    };

    let digest_hex = digest32_hex(&canonical_ratification_v2_digest(inputs.ratification));
    let record = PersistentAuthorityStateRecordV2::new(
        chain_id_hex(inputs.runtime_chain_id),
        TrustBundleEnvironment::from_runtime(inputs.runtime_env),
        inputs.runtime_genesis_hash_hex.to_string(),
        inputs.ratified.authority_root_fingerprint.clone(),
        inputs.ratification.authority_root_suite_id,
        inputs.ratified.fingerprint.clone(),
        inputs.ratified.suite_id,
        inputs.ratified.authority_domain_sequence,
        inputs.ratified.key_lifecycle_action,
        previous_key,
        digest_hex,
        revoked_key_metadata,
        inputs.update_source,
        inputs.updated_at_unix_secs,
    );
    record
        .validate_structure()
        .map_err(AuthorityStateDerivationV2Error::InvalidDerivedRecord)?;
    Ok(record)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityMarkerV2ComparisonOutcome {
    LegacyV1(AuthorityStateComparison),
    FirstV2MarkerAccepted,
    SameV2MarkerIdempotent,
    HigherSequenceAccepted {
        persisted_sequence: u64,
        candidate_sequence: u64,
    },
    LowerSequenceRejected {
        persisted_sequence: u64,
        candidate_sequence: u64,
    },
    SameSequenceDifferentDigestRejected {
        sequence: u64,
        persisted_digest: String,
        candidate_digest: String,
    },
    WrongEnvironmentRejected {
        persisted_environment: TrustBundleEnvironment,
        candidate_environment: TrustBundleEnvironment,
    },
    WrongChainIdRejected {
        persisted_chain_id: String,
        candidate_chain_id: String,
    },
    WrongGenesisHashRejected {
        persisted_genesis_hash: String,
        candidate_genesis_hash: String,
    },
    WrongAuthorityRootRejected {
        persisted_authority_root: String,
        candidate_authority_root: String,
    },
    WrongKeyActionLinkageRejected {
        reason: String,
    },
    V1AfterV2Rejected,
    V2AfterV1ExplicitMigrationAllowed,
    MalformedOrUnsupportedMarkerRejected {
        reason: String,
    },
}

impl AuthorityMarkerV2ComparisonOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(
            self,
            Self::LegacyV1(c) if c.is_accept()
        ) || matches!(
            self,
            Self::FirstV2MarkerAccepted
                | Self::SameV2MarkerIdempotent
                | Self::HigherSequenceAccepted { .. }
                | Self::V2AfterV1ExplicitMigrationAllowed
        )
    }
}

pub fn migrate_authority_marker_v1_to_v2(
    persisted_v1: &PersistentAuthorityStateRecord,
    candidate_v2: &PersistentAuthorityStateRecordV2,
) -> AuthorityMarkerV2ComparisonOutcome {
    if let Err(e) = candidate_v2.validate_structure() {
        return AuthorityMarkerV2ComparisonOutcome::MalformedOrUnsupportedMarkerRejected {
            reason: e.to_string(),
        };
    }
    if persisted_v1.environment != candidate_v2.environment {
        return AuthorityMarkerV2ComparisonOutcome::WrongEnvironmentRejected {
            persisted_environment: persisted_v1.environment,
            candidate_environment: candidate_v2.environment,
        };
    }
    if persisted_v1.chain_id != candidate_v2.chain_id {
        return AuthorityMarkerV2ComparisonOutcome::WrongChainIdRejected {
            persisted_chain_id: persisted_v1.chain_id.clone(),
            candidate_chain_id: candidate_v2.chain_id.clone(),
        };
    }
    if persisted_v1.genesis_hash != candidate_v2.genesis_hash {
        return AuthorityMarkerV2ComparisonOutcome::WrongGenesisHashRejected {
            persisted_genesis_hash: persisted_v1.genesis_hash.clone(),
            candidate_genesis_hash: candidate_v2.genesis_hash.clone(),
        };
    }
    if persisted_v1.authority_root_fingerprint != candidate_v2.authority_root_fingerprint {
        return AuthorityMarkerV2ComparisonOutcome::WrongAuthorityRootRejected {
            persisted_authority_root: persisted_v1.authority_root_fingerprint.clone(),
            candidate_authority_root: candidate_v2.authority_root_fingerprint.clone(),
        };
    }
    AuthorityMarkerV2ComparisonOutcome::V2AfterV1ExplicitMigrationAllowed
}

pub fn compare_authority_marker_v2(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
) -> AuthorityMarkerV2ComparisonOutcome {
    if let Err(e) = candidate.validate_structure() {
        return AuthorityMarkerV2ComparisonOutcome::MalformedOrUnsupportedMarkerRejected {
            reason: e.to_string(),
        };
    }
    let Some(prev) = persisted else {
        return AuthorityMarkerV2ComparisonOutcome::FirstV2MarkerAccepted;
    };
    match prev {
        PersistentAuthorityStateRecordVersioned::V1(v1) => {
            migrate_authority_marker_v1_to_v2(v1, candidate)
        }
        PersistentAuthorityStateRecordVersioned::V2(v2) => {
            if let Err(e) = v2.validate_structure() {
                return AuthorityMarkerV2ComparisonOutcome::MalformedOrUnsupportedMarkerRejected {
                    reason: e.to_string(),
                };
            }
            if v2.environment != candidate.environment {
                return AuthorityMarkerV2ComparisonOutcome::WrongEnvironmentRejected {
                    persisted_environment: v2.environment,
                    candidate_environment: candidate.environment,
                };
            }
            if v2.chain_id != candidate.chain_id {
                return AuthorityMarkerV2ComparisonOutcome::WrongChainIdRejected {
                    persisted_chain_id: v2.chain_id.clone(),
                    candidate_chain_id: candidate.chain_id.clone(),
                };
            }
            if v2.genesis_hash != candidate.genesis_hash {
                return AuthorityMarkerV2ComparisonOutcome::WrongGenesisHashRejected {
                    persisted_genesis_hash: v2.genesis_hash.clone(),
                    candidate_genesis_hash: candidate.genesis_hash.clone(),
                };
            }
            if v2.authority_root_fingerprint != candidate.authority_root_fingerprint {
                return AuthorityMarkerV2ComparisonOutcome::WrongAuthorityRootRejected {
                    persisted_authority_root: v2.authority_root_fingerprint.clone(),
                    candidate_authority_root: candidate.authority_root_fingerprint.clone(),
                };
            }
            if v2.latest_authority_domain_sequence > candidate.latest_authority_domain_sequence {
                return AuthorityMarkerV2ComparisonOutcome::LowerSequenceRejected {
                    persisted_sequence: v2.latest_authority_domain_sequence,
                    candidate_sequence: candidate.latest_authority_domain_sequence,
                };
            }
            if v2.latest_authority_domain_sequence < candidate.latest_authority_domain_sequence {
                return AuthorityMarkerV2ComparisonOutcome::HigherSequenceAccepted {
                    persisted_sequence: v2.latest_authority_domain_sequence,
                    candidate_sequence: candidate.latest_authority_domain_sequence,
                };
            }
            if v2.latest_ratification_v2_digest != candidate.latest_ratification_v2_digest {
                return AuthorityMarkerV2ComparisonOutcome::SameSequenceDifferentDigestRejected {
                    sequence: v2.latest_authority_domain_sequence,
                    persisted_digest: v2.latest_ratification_v2_digest.clone(),
                    candidate_digest: candidate.latest_ratification_v2_digest.clone(),
                };
            }
            if v2.latest_lifecycle_action != candidate.latest_lifecycle_action
                || v2.active_bundle_signing_key_fingerprint
                    != candidate.active_bundle_signing_key_fingerprint
            {
                return AuthorityMarkerV2ComparisonOutcome::WrongKeyActionLinkageRejected {
                    reason: "equal sequence requires identical action and active key binding"
                        .to_string(),
                };
            }
            AuthorityMarkerV2ComparisonOutcome::SameV2MarkerIdempotent
        }
    }
}

pub fn prepare_v2_marker_for_acceptance(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordVersioned,
) -> AuthorityMarkerV2ComparisonOutcome {
    match candidate {
        PersistentAuthorityStateRecordVersioned::V1(v1) => match persisted {
            Some(PersistentAuthorityStateRecordVersioned::V2(_)) => {
                AuthorityMarkerV2ComparisonOutcome::V1AfterV2Rejected
            }
            Some(PersistentAuthorityStateRecordVersioned::V1(prev_v1)) => {
                AuthorityMarkerV2ComparisonOutcome::LegacyV1(compare_authority_state(
                    Some(prev_v1),
                    v1,
                ))
            }
            None => AuthorityMarkerV2ComparisonOutcome::LegacyV1(compare_authority_state(None, v1)),
        },
        PersistentAuthorityStateRecordVersioned::V2(v2) => {
            compare_authority_marker_v2(persisted, v2)
        }
    }
}

// ===========================================================================
// Run 118 — Compare-before-accept wrapper (load + domain-check + compare)
// ===========================================================================

/// Typed outcome of [`prepare_marker_for_acceptance`].
///
/// The wrapper folds three precondition failures (I/O, structural validation
/// of the on-disk record, runtime-domain mismatch on the on-disk record) and
/// the eleven [`AuthorityStateComparison`] outcomes into a single typed
/// surface so that mutating-surface callers can branch on one match without
/// re-implementing the load/validate/compare pipeline.
///
/// Variants split into three classes:
///
/// 1. **Accept (mutating surfaces SHOULD persist)** — [`Self::FirstWrite`],
///    [`Self::Upgrade`].
/// 2. **Accept (no rewrite)** — [`Self::AlreadyPersistedIdempotent`].
/// 3. **Reject (fail closed before any trust mutation)** —
///    [`Self::ConflictReject`], [`Self::LoadFailedFailClosed`],
///    [`Self::PersistedDomainMismatch`].
///
/// Validation-only callers (Run 118 §D) MUST treat every accept variant as
/// "pass" and every reject variant as "reject"; they MUST NOT persist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityStatePrepareOutcome {
    /// No prior marker file existed on disk and the candidate is
    /// structurally valid. Mutating surfaces SHOULD persist this candidate
    /// via [`persist_authority_state_atomic`] at the safest commit boundary;
    /// validation-only surfaces SHOULD treat this as "pass" without
    /// persisting (Run 118 §D).
    FirstWrite,

    /// A prior marker existed and the candidate is bit-for-bit identical
    /// (ignoring the audit-only `last_update_source` and
    /// `updated_at_unix_secs` fields per [`canonical_authority_state_digest`]).
    /// The caller SHOULD NOT rewrite the file (matches the Run 055
    /// `EqualSequenceSameFingerprint` no-op precedent).
    AlreadyPersistedIdempotent,

    /// A prior marker existed at a strictly lower `authority_sequence`.
    /// Mutating surfaces SHOULD persist the new candidate; validation-only
    /// surfaces SHOULD treat this as "pass" without persisting.
    Upgrade {
        previous_sequence: u64,
        new_sequence: u64,
    },

    /// The pure comparator returned a reject variant against a structurally-
    /// valid persisted record. Mutating and validation-only surfaces MUST
    /// fail closed before any trust mutation.
    ConflictReject(AuthorityStateComparison),

    /// `load_authority_state` returned a typed I/O / parse / unsupported-
    /// version / structural error. The on-disk marker is unusable and the
    /// surface MUST fail closed; the binary MUST NOT silently delete or
    /// overwrite the file (operator intervention via the Run 118 §C
    /// `--allow-authority-state-reset` flag, scoped to a Run 119+ binary
    /// surface, is the only recovery path).
    LoadFailedFailClosed(AuthorityStateError),

    /// The on-disk marker is structurally valid but belongs to a different
    /// `(environment, chain_id, genesis_hash)` trust domain than the running
    /// runtime. This is the wrong-data-dir / wrong-snapshot-copy case and
    /// MUST fail closed before any trust mutation.
    PersistedDomainMismatch(AuthorityStateComparison),
}

impl AuthorityStatePrepareOutcome {
    /// True iff this outcome means the candidate is acceptable (the on-disk
    /// record may or may not need to be rewritten).
    pub fn is_accept(&self) -> bool {
        matches!(
            self,
            Self::FirstWrite | Self::AlreadyPersistedIdempotent | Self::Upgrade { .. }
        )
    }

    /// True iff this outcome means a mutating surface SHOULD persist the
    /// candidate. False for both [`Self::AlreadyPersistedIdempotent`] (the
    /// record is unchanged) and for every reject variant.
    pub fn should_persist(&self) -> bool {
        matches!(self, Self::FirstWrite | Self::Upgrade { .. })
    }

    /// True iff this outcome is a rejection (every non-accept variant).
    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }
}

impl std::fmt::Display for AuthorityStatePrepareOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FirstWrite => write!(f, "first-write (no prior persisted authority marker)"),
            Self::AlreadyPersistedIdempotent => write!(
                f,
                "already-persisted-idempotent (authority marker unchanged; no rewrite)"
            ),
            Self::Upgrade {
                previous_sequence,
                new_sequence,
            } => write!(
                f,
                "upgrade authority_sequence {} -> {}",
                previous_sequence, new_sequence
            ),
            Self::ConflictReject(c) => write!(f, "conflict reject: {}", c),
            Self::LoadFailedFailClosed(e) => write!(f, "load failed fail-closed: {}", e),
            Self::PersistedDomainMismatch(c) => {
                write!(f, "persisted-marker domain mismatch: {}", c)
            }
        }
    }
}

/// Load the persisted marker (if any), confirm it applies to the runtime
/// `(env, chain_id, genesis_hash)` trust domain, and compare it against the
/// supplied candidate marker. Returns a single typed
/// [`AuthorityStatePrepareOutcome`] suitable for a mutating-surface match.
///
/// Ordering (first match wins):
///
/// 1. [`load_authority_state`] returns a fatal error → `LoadFailedFailClosed`.
/// 2. A persisted marker exists but its `(env, chain_id, genesis_hash)` does
///    not match the runtime → `PersistedDomainMismatch`. (Catches the
///    wrong-data-dir / wrong-snapshot-copy case before any sequence
///    comparison so the rejection reason is precise.)
/// 3. [`compare_authority_state`] returns:
///    - `FirstLoad` → `FirstWrite`;
///    - `EqualIdempotent` → `AlreadyPersistedIdempotent`;
///    - `Upgrade { .. }` → `Upgrade { .. }`;
///    - any reject variant → `ConflictReject(...)`.
///
/// The wrapper deliberately does not write anything to disk — Run 118
/// validation-only surfaces depend on that, and mutating surfaces are
/// expected to call [`persist_authority_state_atomic`] separately at the
/// safest commit boundary relative to the existing Run 070 `commit_sequence`
/// / root-merge / live-trust-swap ordering.
///
/// **Crash-consistency note for mutating surfaces.** This wrapper provides
/// the *compare* step. The persist step is intentionally separated so the
/// caller can choose whether to persist before or after its existing trust
/// mutation. Run 117 establishes that the on-disk marker is fail-closed
/// against corruption and torn writes (tmp + sync + rename + parent-dir
/// sync), so a crash between compare and persist leaves the previous
/// marker intact and the next boot re-runs this wrapper. A crash between
/// trust-mutation and persist is the genuinely risky window: callers MUST
/// document their chosen ordering in the surface-specific evidence.
pub fn prepare_marker_for_acceptance(
    marker_path: &Path,
    candidate: &PersistentAuthorityStateRecord,
    runtime_env: NetworkEnvironment,
    runtime_chain_id: ChainId,
    runtime_genesis_hash_hex: &str,
) -> AuthorityStatePrepareOutcome {
    // Step 1: load + structurally validate the persisted marker.
    let persisted = match load_authority_state(marker_path) {
        Ok(p) => p,
        Err(e) => return AuthorityStatePrepareOutcome::LoadFailedFailClosed(e),
    };

    // Step 2: if a persisted marker exists, verify it belongs to the
    // runtime trust domain BEFORE comparing it to the candidate. This
    // ensures the rejection reason is precise (wrong-data-dir / wrong-
    // snapshot-copy fires here, not as a generic ChainMismatch later).
    if let Some(prev) = persisted.as_ref() {
        if let Err(mismatch) = validate_record_for_domain(
            prev,
            runtime_env,
            runtime_chain_id,
            runtime_genesis_hash_hex,
        ) {
            return AuthorityStatePrepareOutcome::PersistedDomainMismatch(mismatch);
        }
    }

    // Step 3: pure comparison.
    match compare_authority_state(persisted.as_ref(), candidate) {
        AuthorityStateComparison::FirstLoad => AuthorityStatePrepareOutcome::FirstWrite,
        AuthorityStateComparison::EqualIdempotent => {
            AuthorityStatePrepareOutcome::AlreadyPersistedIdempotent
        }
        AuthorityStateComparison::Upgrade {
            previous_sequence,
            new_sequence,
        } => AuthorityStatePrepareOutcome::Upgrade {
            previous_sequence,
            new_sequence,
        },
        reject => AuthorityStatePrepareOutcome::ConflictReject(reject),
    }
}

// ===========================================================================
// Run 124 — Snapshot/restore authority marker conflict enforcement
// ===========================================================================

/// Inputs required to evaluate whether a snapshot can be restored without
/// silently downgrading, conflicting with, or erasing the locally persisted
/// ratified bundle-signing authority marker.
///
/// Run 124 deliberately keeps this pure: callers compute the runtime trust
/// domain (`runtime_env`, `runtime_chain_id`, `runtime_genesis_hash_hex`)
/// from the same canonical sources Run 102 / 105 already use, the `marker_path`
/// is the canonical `<data_dir>/pqc_authority_state.json` location from
/// [`authority_state_file_path`], and `snapshot_meta` is the additive
/// [`AuthorityStateSnapshotMeta`] block parsed out of the snapshot
/// `meta.json` by the Run 117 parser (`None` for legacy pre-Run-117
/// snapshots, `Some` for Run-117+ snapshots produced on a node that
/// observed a canonical authority marker at snapshot creation).
#[derive(Debug, Clone)]
pub struct SnapshotRestoreAuthorityCheckInputs<'a> {
    /// Canonical marker file path under the operator-supplied `--data-dir`.
    pub marker_path: &'a Path,
    /// Snapshot authority-state metadata if the snapshot carries it; `None`
    /// for pre-Run-117 legacy snapshots.
    pub snapshot_meta: Option<&'a AuthorityStateSnapshotMeta>,
    /// Runtime network environment.
    pub runtime_env: NetworkEnvironment,
    /// Runtime chain id (Run 069+).
    pub runtime_chain_id: ChainId,
    /// 64 lowercase hex chars of the canonical genesis hash this node booted
    /// against. Equals `compute_canonical_genesis_hash(...)` on the runtime
    /// genesis config.
    pub runtime_genesis_hash_hex: &'a str,
}

/// Typed outcome of [`verify_snapshot_authority_state_for_restore`]. Every
/// variant is a single deterministic decision suitable for a restore
/// surface to branch on. Reject variants carry the information necessary to
/// emit a precise operator log line without re-inspecting either marker.
///
/// Accept variants (`NoMarkerEitherSide`, `AcceptSnapshotMarkerNoLocal`,
/// `AcceptMatchingMarker`) explicitly mean **restore may proceed and the
/// local marker file MUST NOT be mutated or deleted**. Run 124 never
/// synthesises a local marker from a snapshot block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotRestoreAuthorityCheckOutcome {
    /// No local marker present and the snapshot carries no authority
    /// metadata. Legacy pre-Run-117 snapshot restoring into a fresh data
    /// directory; restore may proceed without authority enforcement on
    /// this surface (the next mutating surface will write the marker).
    NoMarkerEitherSide,

    /// No local marker present and the snapshot carries authority metadata
    /// that matches the runtime trust domain. Restore may proceed; the
    /// local marker is **not** synthesised from snapshot bytes (Run 124
    /// strict non-goal). The next mutating surface will derive and persist
    /// the canonical marker from a verified ratification.
    AcceptSnapshotMarkerNoLocal,

    /// Local marker and snapshot marker agree bit-for-bit on every
    /// security-relevant field. Restore may proceed; the local marker
    /// file MUST NOT be rewritten by the restore surface.
    AcceptMatchingMarker,

    /// A local marker exists and the snapshot does not carry authority
    /// metadata. Restore is rejected fail-closed: accepting would erase
    /// or silently roll back the local persisted authority state.
    /// Recovery is a future operator-recovery flag (Run 116 spec
    /// `--allow-authority-state-reset`), explicitly not implemented in
    /// Run 124.
    RejectMissingSnapshotMarker,

    /// Both a local marker and a snapshot marker exist but they disagree
    /// (rollback, equivocation, key conflict, policy regression, etc.).
    /// The embedded [`AuthorityStateComparison`] captures the precise
    /// reject reason.
    RejectConflict(AuthorityStateComparison),

    /// The on-disk local marker file is structurally invalid or the
    /// `record_version` is not supported by this binary. Restore is
    /// rejected fail-closed; the marker bytes on disk are preserved
    /// verbatim (Run 124 never silently overwrites a corrupt marker).
    RejectLocalMarkerCorrupt(AuthorityStateError),

    /// The local marker is structurally valid but belongs to a different
    /// `(environment, chain_id, genesis_hash)` trust domain than the
    /// running runtime — the wrong-data-dir case. Restore is rejected
    /// before any further comparison so the operator log line is
    /// precise.
    RejectLocalMarkerWrongDomain(AuthorityStateComparison),

    /// The snapshot authority metadata has the wrong `chain_id_hex`,
    /// `environment`, or `genesis_hash_hex` for the runtime trust
    /// domain. Restore is rejected fail-closed.
    RejectSnapshotMarkerWrongDomain { reason: String },
}

impl SnapshotRestoreAuthorityCheckOutcome {
    /// True iff this outcome means restore may proceed.
    pub fn is_accept(&self) -> bool {
        matches!(
            self,
            Self::NoMarkerEitherSide
                | Self::AcceptSnapshotMarkerNoLocal
                | Self::AcceptMatchingMarker
        )
    }

    /// True iff this outcome is a rejection. Equivalent to `!is_accept()`.
    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }
}

impl std::fmt::Display for SnapshotRestoreAuthorityCheckOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMarkerEitherSide => write!(
                f,
                "no local authority marker and no snapshot authority metadata (legacy snapshot, fresh data dir; restore may proceed without authority enforcement on the restore surface)"
            ),
            Self::AcceptSnapshotMarkerNoLocal => write!(
                f,
                "no local authority marker; snapshot authority metadata matches the runtime trust domain (restore may proceed; local marker is NOT synthesised from snapshot bytes)"
            ),
            Self::AcceptMatchingMarker => write!(
                f,
                "local authority marker matches snapshot authority metadata bit-for-bit (restore may proceed; local marker NOT rewritten)"
            ),
            Self::RejectMissingSnapshotMarker => write!(
                f,
                "snapshot restore rejected: local authority marker exists but snapshot carries no authority metadata (fail closed; accepting would silently erase or roll back the local persisted authority state)"
            ),
            Self::RejectConflict(c) => write!(
                f,
                "snapshot restore rejected: snapshot authority metadata conflicts with local marker: {} (fail closed)",
                c
            ),
            Self::RejectLocalMarkerCorrupt(e) => write!(
                f,
                "snapshot restore rejected: local authority marker is corrupt or unsupported: {} (fail closed; bytes preserved verbatim)",
                e
            ),
            Self::RejectLocalMarkerWrongDomain(c) => write!(
                f,
                "snapshot restore rejected: local authority marker belongs to a different trust domain than the running runtime: {} (fail closed; wrong-data-dir / wrong-snapshot-copy)",
                c
            ),
            Self::RejectSnapshotMarkerWrongDomain { reason } => write!(
                f,
                "snapshot restore rejected: snapshot authority metadata has wrong trust domain: {} (fail closed)",
                reason
            ),
        }
    }
}

/// Compare a snapshot's optional [`AuthorityStateSnapshotMeta`] against the
/// locally persisted [`PersistentAuthorityStateRecord`] (if any) and decide,
/// fail-closed, whether a snapshot restore may proceed without silently
/// downgrading or erasing the local marker.
///
/// This function is **pure**: it reads the local marker file via
/// [`load_authority_state`] and never writes, deletes, or otherwise mutates
/// any on-disk state. It is the Run 124 restore-side counterpart to the
/// Run 118 [`prepare_marker_for_acceptance`] wrapper used by mutating /
/// validation-only surfaces.
///
/// Ordering (first match wins):
///
/// 1. [`load_authority_state`] returns a fatal error → `RejectLocalMarkerCorrupt`.
/// 2. A persisted local marker exists but its `(env, chain_id, genesis_hash)`
///    does not match the runtime → `RejectLocalMarkerWrongDomain`.
/// 3. Both local and snapshot markers absent → `NoMarkerEitherSide`.
/// 4. Local absent, snapshot present:
///    - snapshot domain matches runtime → `AcceptSnapshotMarkerNoLocal`;
///    - snapshot domain mismatches runtime → `RejectSnapshotMarkerWrongDomain`.
/// 5. Local present, snapshot absent → `RejectMissingSnapshotMarker`.
/// 6. Both present:
///    - snapshot domain mismatches runtime → `RejectSnapshotMarkerWrongDomain`;
///    - reconstruct a candidate [`PersistentAuthorityStateRecord`] from
///      the snapshot metadata and route through [`compare_authority_state`]:
///      `EqualIdempotent` → `AcceptMatchingMarker`,
///      anything else → `RejectConflict(...)`.
pub fn verify_snapshot_authority_state_for_restore(
    inputs: SnapshotRestoreAuthorityCheckInputs<'_>,
) -> SnapshotRestoreAuthorityCheckOutcome {
    // Step 1: load + structurally validate the persisted local marker.
    let persisted = match load_authority_state(inputs.marker_path) {
        Ok(p) => p,
        Err(e) => return SnapshotRestoreAuthorityCheckOutcome::RejectLocalMarkerCorrupt(e),
    };

    // Step 2: if a local marker exists, it must belong to the runtime
    // trust domain BEFORE we look at the snapshot block.
    if let Some(prev) = persisted.as_ref() {
        if let Err(mismatch) = validate_record_for_domain(
            prev,
            inputs.runtime_env,
            inputs.runtime_chain_id,
            inputs.runtime_genesis_hash_hex,
        ) {
            return SnapshotRestoreAuthorityCheckOutcome::RejectLocalMarkerWrongDomain(mismatch);
        }
    }

    // Step 3-5: branch on (local, snapshot) presence.
    match (persisted.as_ref(), inputs.snapshot_meta) {
        (None, None) => SnapshotRestoreAuthorityCheckOutcome::NoMarkerEitherSide,
        (None, Some(snap)) => {
            if let Err(reason) = check_snapshot_meta_domain(
                snap,
                inputs.runtime_env,
                inputs.runtime_chain_id,
                inputs.runtime_genesis_hash_hex,
            ) {
                return SnapshotRestoreAuthorityCheckOutcome::RejectSnapshotMarkerWrongDomain {
                    reason,
                };
            }
            SnapshotRestoreAuthorityCheckOutcome::AcceptSnapshotMarkerNoLocal
        }
        (Some(_), None) => SnapshotRestoreAuthorityCheckOutcome::RejectMissingSnapshotMarker,
        (Some(prev), Some(snap)) => {
            if let Err(reason) = check_snapshot_meta_domain(
                snap,
                inputs.runtime_env,
                inputs.runtime_chain_id,
                inputs.runtime_genesis_hash_hex,
            ) {
                return SnapshotRestoreAuthorityCheckOutcome::RejectSnapshotMarkerWrongDomain {
                    reason,
                };
            }
            // Reconstruct a comparable PersistentAuthorityStateRecord from
            // the snapshot block. `last_update_source` and
            // `updated_at_unix_secs` are intentionally synthesised from a
            // neutral test-or-fixture tag plus the persisted marker's own
            // wall-clock; neither field participates in
            // canonical_authority_state_digest (Run 117 §canonical digest)
            // so this reconstruction is byte-equivalent to the persisted
            // record at the security-relevant layer iff every other field
            // agrees. compare_authority_state then returns EqualIdempotent
            // on a true match and a typed reject variant otherwise.
            let candidate = match snapshot_meta_to_record(snap) {
                Ok(c) => c,
                Err(e) => {
                    return SnapshotRestoreAuthorityCheckOutcome::RejectSnapshotMarkerWrongDomain {
                        reason: format!(
                            "snapshot authority block could not be reconstructed as a PersistentAuthorityStateRecord: {}",
                            e
                        ),
                    };
                }
            };
            match compare_authority_state(Some(prev), &candidate) {
                AuthorityStateComparison::EqualIdempotent => {
                    SnapshotRestoreAuthorityCheckOutcome::AcceptMatchingMarker
                }
                reject => SnapshotRestoreAuthorityCheckOutcome::RejectConflict(reject),
            }
        }
    }
}

/// Verify that a snapshot authority-state block carries the runtime trust
/// domain. Returns the precise reason on mismatch.
fn check_snapshot_meta_domain(
    snap: &AuthorityStateSnapshotMeta,
    runtime_env: NetworkEnvironment,
    runtime_chain_id: ChainId,
    runtime_genesis_hash_hex: &str,
) -> Result<(), String> {
    let expected_env_tag = match runtime_env {
        NetworkEnvironment::Devnet => "devnet",
        NetworkEnvironment::Testnet => "testnet",
        NetworkEnvironment::Mainnet => "mainnet",
    };
    if snap.environment != expected_env_tag {
        return Err(format!(
            "snapshot.environment={} runtime.environment={}",
            snap.environment, expected_env_tag
        ));
    }
    let expected_chain_hex = chain_id_hex(runtime_chain_id);
    if snap.chain_id_hex != expected_chain_hex {
        return Err(format!(
            "snapshot.chain_id_hex={} runtime.chain_id_hex={}",
            snap.chain_id_hex, expected_chain_hex
        ));
    }
    if snap.genesis_hash_hex != runtime_genesis_hash_hex {
        return Err(format!(
            "snapshot.genesis_hash_hex={} runtime.genesis_hash_hex={}",
            snap.genesis_hash_hex, runtime_genesis_hash_hex
        ));
    }
    Ok(())
}

/// Reconstruct a [`PersistentAuthorityStateRecord`] from a snapshot
/// [`AuthorityStateSnapshotMeta`] block so that the comparison can go
/// through the same [`compare_authority_state`] surface mutating callers
/// use. The two informational-only audit fields (`last_update_source`,
/// `updated_at_unix_secs`) are intentionally filled with neutral values
/// because neither participates in [`canonical_authority_state_digest`]
/// nor in [`compare_authority_state`]'s equality rules.
fn snapshot_meta_to_record(
    snap: &AuthorityStateSnapshotMeta,
) -> Result<PersistentAuthorityStateRecord, AuthorityStateError> {
    let environment = match snap.environment.as_str() {
        "devnet" => TrustBundleEnvironment::Devnet,
        "testnet" => TrustBundleEnvironment::Testnet,
        "mainnet" => TrustBundleEnvironment::Mainnet,
        other => {
            return Err(AuthorityStateError::Malformed(format!(
                "snapshot authority block has unknown environment tag {}",
                other
            )));
        }
    };
    let record = PersistentAuthorityStateRecord::new(
        snap.chain_id_hex.clone(),
        environment,
        snap.genesis_hash_hex.clone(),
        snap.authority_policy_version,
        snap.authority_sequence,
        snap.authority_epoch,
        snap.authority_root_fingerprint.clone(),
        snap.ratified_bundle_signing_key_fingerprint.clone(),
        snap.ratification_object_hash.clone(),
        AuthorityStateUpdateSource::TestOrFixture,
        0,
    );
    record.validate_structure()?;
    Ok(record)
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_types::{ChainId, NetworkEnvironment};
    use tempfile::TempDir;

    fn sample_record() -> PersistentAuthorityStateRecord {
        PersistentAuthorityStateRecord::new(
            "0000000000000001".to_string(),
            TrustBundleEnvironment::Devnet,
            "a".repeat(64),
            1,
            5,
            Some(2),
            "b".repeat(40),
            "c".repeat(40),
            "d".repeat(64),
            AuthorityStateUpdateSource::TestOrFixture,
            1_700_000_000,
        )
    }

    // -------- Serialization / digest tests --------

    #[test]
    fn digest_is_deterministic() {
        let r = sample_record();
        let d1 = canonical_authority_state_digest(&r);
        let d2 = canonical_authority_state_digest(&r);
        assert_eq!(d1, d2);
    }

    #[test]
    fn digest_preimage_starts_with_domain_tag() {
        let r = sample_record();
        let p = canonical_authority_state_preimage(&r);
        assert!(
            p.starts_with(AUTHORITY_STATE_DOMAIN_V1),
            "preimage must be domain-separated"
        );
    }

    #[test]
    fn digest_flips_on_each_security_relevant_field() {
        let base = sample_record();
        let base_digest = canonical_authority_state_digest(&base);

        let mut r = base.clone();
        r.chain_id = "0000000000000002".to_string();
        assert_ne!(canonical_authority_state_digest(&r), base_digest);

        let mut r = base.clone();
        r.environment = TrustBundleEnvironment::Mainnet;
        assert_ne!(canonical_authority_state_digest(&r), base_digest);

        let mut r = base.clone();
        r.genesis_hash = "e".repeat(64);
        assert_ne!(canonical_authority_state_digest(&r), base_digest);

        let mut r = base.clone();
        r.authority_policy_version = 2;
        assert_ne!(canonical_authority_state_digest(&r), base_digest);

        let mut r = base.clone();
        r.authority_sequence += 1;
        assert_ne!(canonical_authority_state_digest(&r), base_digest);

        let mut r = base.clone();
        r.authority_epoch = Some(99);
        assert_ne!(canonical_authority_state_digest(&r), base_digest);

        let mut r = base.clone();
        r.authority_epoch = None;
        assert_ne!(canonical_authority_state_digest(&r), base_digest);

        let mut r = base.clone();
        r.authority_root_fingerprint = "f".repeat(40);
        assert_ne!(canonical_authority_state_digest(&r), base_digest);

        let mut r = base.clone();
        r.ratified_bundle_signing_key_fingerprint = "9".repeat(40);
        assert_ne!(canonical_authority_state_digest(&r), base_digest);

        let mut r = base.clone();
        r.ratification_object_hash = "1".repeat(64);
        assert_ne!(canonical_authority_state_digest(&r), base_digest);
    }

    #[test]
    fn digest_excludes_informational_fields() {
        // `last_update_source` and `updated_at_unix_secs` are
        // audit-only and MUST NOT contribute to the security
        // digest. Otherwise a benign restart would change the
        // digest without changing security-relevant state.
        let base = sample_record();
        let base_digest = canonical_authority_state_digest(&base);

        let mut r = base.clone();
        r.updated_at_unix_secs = 9_999_999;
        assert_eq!(canonical_authority_state_digest(&r), base_digest);

        let mut r = base.clone();
        r.last_update_source = AuthorityStateUpdateSource::ReloadApply;
        assert_eq!(canonical_authority_state_digest(&r), base_digest);
    }

    // -------- Structural validation tests --------

    #[test]
    fn validate_structure_accepts_sample() {
        sample_record().validate_structure().unwrap();
    }

    #[test]
    fn validate_structure_rejects_wrong_version() {
        let mut r = sample_record();
        r.record_version = 99;
        match r.validate_structure() {
            Err(AuthorityStateError::UnsupportedRecordVersion(99)) => {}
            other => panic!("expected UnsupportedRecordVersion(99), got {:?}", other),
        }
    }

    #[test]
    fn validate_structure_rejects_bad_chain_id() {
        let mut r = sample_record();
        r.chain_id = "GGGG".to_string();
        assert!(matches!(
            r.validate_structure(),
            Err(AuthorityStateError::Malformed(_))
        ));
    }

    #[test]
    fn validate_structure_rejects_bad_genesis_hash() {
        let mut r = sample_record();
        r.genesis_hash = "short".to_string();
        assert!(matches!(
            r.validate_structure(),
            Err(AuthorityStateError::Malformed(_))
        ));
    }

    #[test]
    fn validate_structure_rejects_zero_policy_version() {
        let mut r = sample_record();
        r.authority_policy_version = 0;
        assert!(matches!(
            r.validate_structure(),
            Err(AuthorityStateError::Malformed(_))
        ));
    }

    #[test]
    fn validate_structure_rejects_uppercase_hex() {
        let mut r = sample_record();
        r.authority_root_fingerprint = "B".repeat(40);
        assert!(matches!(
            r.validate_structure(),
            Err(AuthorityStateError::Malformed(_))
        ));
    }

    // -------- Compare tests --------

    #[test]
    fn compare_first_load() {
        let cand = sample_record();
        assert_eq!(
            compare_authority_state(None, &cand),
            AuthorityStateComparison::FirstLoad
        );
    }

    #[test]
    fn compare_equal_idempotent() {
        let prev = sample_record();
        let cand = sample_record();
        assert_eq!(
            compare_authority_state(Some(&prev), &cand),
            AuthorityStateComparison::EqualIdempotent
        );
    }

    #[test]
    fn compare_equal_idempotent_ignores_informational_fields() {
        let prev = sample_record();
        let mut cand = sample_record();
        // Different informational fields must still result in
        // EqualIdempotent — they are audit-only.
        cand.updated_at_unix_secs = 99_999_999;
        cand.last_update_source = AuthorityStateUpdateSource::ReloadApply;
        assert_eq!(
            compare_authority_state(Some(&prev), &cand),
            AuthorityStateComparison::EqualIdempotent
        );
    }

    #[test]
    fn compare_upgrade() {
        let prev = sample_record();
        let mut cand = sample_record();
        cand.authority_sequence = prev.authority_sequence + 3;
        cand.ratification_object_hash = "1".repeat(64);
        match compare_authority_state(Some(&prev), &cand) {
            AuthorityStateComparison::Upgrade {
                previous_sequence,
                new_sequence,
            } => {
                assert_eq!(previous_sequence, prev.authority_sequence);
                assert_eq!(new_sequence, prev.authority_sequence + 3);
            }
            other => panic!("expected Upgrade, got {:?}", other),
        }
    }

    #[test]
    fn compare_rollback_refused() {
        let mut prev = sample_record();
        prev.authority_sequence = 10;
        let mut cand = sample_record();
        cand.authority_sequence = 9;
        assert!(matches!(
            compare_authority_state(Some(&prev), &cand),
            AuthorityStateComparison::RollbackRefused {
                persisted_sequence: 10,
                attempted_sequence: 9
            }
        ));
    }

    #[test]
    fn compare_same_sequence_conflicting_hash() {
        let prev = sample_record();
        let mut cand = sample_record();
        cand.ratification_object_hash = "1".repeat(64);
        match compare_authority_state(Some(&prev), &cand) {
            AuthorityStateComparison::SameSequenceConflictingHash {
                sequence,
                persisted_hash,
                attempted_hash,
            } => {
                assert_eq!(sequence, prev.authority_sequence);
                assert_eq!(persisted_hash, "d".repeat(64));
                assert_eq!(attempted_hash, "1".repeat(64));
            }
            other => panic!("expected SameSequenceConflictingHash, got {:?}", other),
        }
    }

    #[test]
    fn compare_same_sequence_conflicting_key() {
        // Same authority_root, different ratified-key fingerprint,
        // same authority_sequence. We also flip ratification_object_hash
        // because two distinct keys produce distinct ratifications;
        // the comparator must report the *key* conflict (the most
        // operator-actionable reason) rather than the hash conflict.
        let prev = sample_record();
        let mut cand = sample_record();
        cand.ratified_bundle_signing_key_fingerprint = "9".repeat(40);
        cand.ratification_object_hash = "2".repeat(64);
        match compare_authority_state(Some(&prev), &cand) {
            AuthorityStateComparison::SameSequenceConflictingKey {
                sequence,
                persisted_key_fingerprint,
                attempted_key_fingerprint,
            } => {
                assert_eq!(sequence, prev.authority_sequence);
                assert_eq!(persisted_key_fingerprint, "c".repeat(40));
                assert_eq!(attempted_key_fingerprint, "9".repeat(40));
            }
            other => panic!("expected SameSequenceConflictingKey, got {:?}", other),
        }
    }

    #[test]
    fn compare_chain_mismatch() {
        let prev = sample_record();
        let mut cand = sample_record();
        cand.chain_id = "0000000000000002".to_string();
        assert!(matches!(
            compare_authority_state(Some(&prev), &cand),
            AuthorityStateComparison::ChainMismatch { .. }
        ));
    }

    #[test]
    fn compare_environment_mismatch() {
        let prev = sample_record();
        let mut cand = sample_record();
        cand.environment = TrustBundleEnvironment::Mainnet;
        assert!(matches!(
            compare_authority_state(Some(&prev), &cand),
            AuthorityStateComparison::EnvironmentMismatch { .. }
        ));
    }

    #[test]
    fn compare_genesis_hash_mismatch() {
        let prev = sample_record();
        let mut cand = sample_record();
        cand.genesis_hash = "e".repeat(64);
        assert!(matches!(
            compare_authority_state(Some(&prev), &cand),
            AuthorityStateComparison::GenesisHashMismatch { .. }
        ));
    }

    #[test]
    fn compare_policy_version_regression() {
        let mut prev = sample_record();
        prev.authority_policy_version = 2;
        let mut cand = sample_record();
        cand.authority_policy_version = 1;
        assert!(matches!(
            compare_authority_state(Some(&prev), &cand),
            AuthorityStateComparison::PolicyVersionRegression {
                persisted_policy_version: 2,
                candidate_policy_version: 1
            }
        ));
    }

    #[test]
    fn compare_corrupt_equal_seq_equal_hash_drift_epoch() {
        // Equal sequence, equal ratification_object_hash, same root
        // and key, but disagreeing authority_epoch. These fields
        // are hash-bound at the ratification layer so they cannot
        // legitimately drift without a sequence change.
        let prev = sample_record();
        let mut cand = sample_record();
        cand.authority_epoch = Some(99);
        match compare_authority_state(Some(&prev), &cand) {
            AuthorityStateComparison::Corrupt { .. } => {}
            other => panic!("expected Corrupt, got {:?}", other),
        }
    }

    #[test]
    fn comparison_accept_classification() {
        assert!(AuthorityStateComparison::FirstLoad.is_accept());
        assert!(AuthorityStateComparison::FirstLoad.accept_advance());

        assert!(AuthorityStateComparison::EqualIdempotent.is_accept());
        assert!(!AuthorityStateComparison::EqualIdempotent.accept_advance());

        let upgrade = AuthorityStateComparison::Upgrade {
            previous_sequence: 1,
            new_sequence: 2,
        };
        assert!(upgrade.is_accept());
        assert!(upgrade.accept_advance());

        let rollback = AuthorityStateComparison::RollbackRefused {
            persisted_sequence: 5,
            attempted_sequence: 4,
        };
        assert!(!rollback.is_accept());
        assert!(rollback.is_reject());
    }

    // -------- validate_record_for_domain tests --------

    #[test]
    fn validate_record_for_domain_accepts_matching_runtime() {
        let r = sample_record();
        validate_record_for_domain(&r, NetworkEnvironment::Devnet, ChainId(1), &"a".repeat(64))
            .unwrap();
    }

    #[test]
    fn validate_record_for_domain_rejects_wrong_env() {
        let r = sample_record();
        let err = validate_record_for_domain(
            &r,
            NetworkEnvironment::Mainnet,
            ChainId(1),
            &"a".repeat(64),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            AuthorityStateComparison::EnvironmentMismatch { .. }
        ));
    }

    #[test]
    fn validate_record_for_domain_rejects_wrong_chain() {
        let r = sample_record();
        let err =
            validate_record_for_domain(&r, NetworkEnvironment::Devnet, ChainId(2), &"a".repeat(64))
                .unwrap_err();
        assert!(matches!(
            err,
            AuthorityStateComparison::ChainMismatch { .. }
        ));
    }

    #[test]
    fn validate_record_for_domain_rejects_wrong_genesis() {
        let r = sample_record();
        let err =
            validate_record_for_domain(&r, NetworkEnvironment::Devnet, ChainId(1), &"e".repeat(64))
                .unwrap_err();
        assert!(matches!(
            err,
            AuthorityStateComparison::GenesisHashMismatch { .. }
        ));
    }

    // -------- Persistence tests --------

    #[test]
    fn load_returns_none_when_file_absent() {
        let tmp = TempDir::new().unwrap();
        let path = authority_state_file_path(tmp.path());
        let loaded = load_authority_state(&path).unwrap();
        assert!(
            loaded.is_none(),
            "missing file must surface as None (explicit absence)"
        );
    }

    #[test]
    fn persist_then_load_round_trips() {
        let tmp = TempDir::new().unwrap();
        let path = authority_state_file_path(tmp.path());
        let r = sample_record();
        persist_authority_state_atomic(&path, &r).unwrap();
        let loaded = load_authority_state(&path).unwrap().unwrap();
        assert_eq!(loaded, r);
    }

    #[test]
    fn persist_overwrites_idempotently() {
        let tmp = TempDir::new().unwrap();
        let path = authority_state_file_path(tmp.path());
        let r = sample_record();
        persist_authority_state_atomic(&path, &r).unwrap();
        persist_authority_state_atomic(&path, &r).unwrap();
        let loaded = load_authority_state(&path).unwrap().unwrap();
        assert_eq!(loaded, r);
    }

    #[test]
    fn persist_creates_missing_parent_dir() {
        let tmp = TempDir::new().unwrap();
        let nested = tmp.path().join("a/b/c");
        let path = authority_state_file_path(&nested);
        persist_authority_state_atomic(&path, &sample_record()).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn load_fails_closed_on_corrupt_json() {
        let tmp = TempDir::new().unwrap();
        let path = authority_state_file_path(tmp.path());
        std::fs::write(&path, b"{not valid json").unwrap();
        let err = load_authority_state(&path).unwrap_err();
        assert!(matches!(err, AuthorityStateError::Malformed(_)));
    }

    #[test]
    fn load_fails_closed_on_unsupported_version() {
        let tmp = TempDir::new().unwrap();
        let path = authority_state_file_path(tmp.path());
        let mut r = sample_record();
        r.record_version = 99;
        // Bypass persist's structural validation by writing the
        // JSON directly.
        std::fs::write(&path, serde_json::to_vec(&r).unwrap()).unwrap();
        let err = load_authority_state(&path).unwrap_err();
        assert!(matches!(
            err,
            AuthorityStateError::UnsupportedRecordVersion(99)
        ));
    }

    #[test]
    fn load_fails_closed_on_truncated_record() {
        let tmp = TempDir::new().unwrap();
        let path = authority_state_file_path(tmp.path());
        std::fs::write(&path, b"{\"record_version\": 1}").unwrap();
        let err = load_authority_state(&path).unwrap_err();
        // Missing required fields surface as serde Malformed.
        assert!(matches!(err, AuthorityStateError::Malformed(_)));
    }

    #[test]
    fn persist_rejects_structurally_invalid_record() {
        let tmp = TempDir::new().unwrap();
        let path = authority_state_file_path(tmp.path());
        let mut r = sample_record();
        r.chain_id = "INVALID".to_string();
        let err = persist_authority_state_atomic(&path, &r).unwrap_err();
        assert!(matches!(err, AuthorityStateError::PersistFailure(_)));
        // No file should have been written.
        assert!(!path.exists());
    }

    #[test]
    fn no_tmp_file_leftover_on_successful_write() {
        let tmp = TempDir::new().unwrap();
        let path = authority_state_file_path(tmp.path());
        persist_authority_state_atomic(&path, &sample_record()).unwrap();
        let tmp_path = {
            let mut p = path.as_os_str().to_owned();
            p.push(".tmp");
            PathBuf::from(p)
        };
        assert!(!tmp_path.exists(), "tmp file must be renamed away");
    }

    #[test]
    fn chain_id_hex_format() {
        assert_eq!(chain_id_hex(ChainId(1)), "0000000000000001");
        assert_eq!(chain_id_hex(ChainId(0xdeadbeef)), "00000000deadbeef");
    }

    #[test]
    fn genesis_hash_hex_format() {
        let h = [0xabu8; 32];
        assert_eq!(genesis_hash_hex(&h), "ab".repeat(32));
    }

    // -------- Run 118: marker derivation tests --------

    mod run118 {
        use super::*;
        use qbind_crypto::MlDsa44Backend;
        use qbind_ledger::bundle_signing_ratification::test_helpers as ratification_helpers;
        use qbind_ledger::{pqc_public_key_fingerprint, RatificationEnvironment};

        fn full_pk_hex(pk: &[u8]) -> String {
            let mut s = String::with_capacity(pk.len() * 2);
            for b in pk {
                use std::fmt::Write;
                let _ = write!(&mut s, "{:02x}", b);
            }
            s
        }

        fn fixture_genesis_hash() -> [u8; 32] {
            let mut h = [0u8; 32];
            for (i, b) in h.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(7).wrapping_add(0x1f);
            }
            h
        }

        struct VerifiedFixture {
            ratification: BundleSigningRatification,
            ratified: RatifiedBundleSigningKey,
            genesis_hash_hex: String,
            authority_pk_hex: String,
        }

        /// Build a structurally-valid, signed ratification object and a
        /// matching `RatifiedBundleSigningKey` identity that mirrors what
        /// the production verifier emits. We construct the identity
        /// directly (rather than invoking the verifier) because the
        /// derivation helper only requires a structurally-consistent pair,
        /// and the tests in `qbind-ledger` already cover the verifier path
        /// end-to-end.
        fn build_verified_fixture(
            env: RatificationEnvironment,
            chain_id_hex: &str,
        ) -> VerifiedFixture {
            let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
            let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
            let gh = fixture_genesis_hash();
            let auth_pk_hex = full_pk_hex(&auth_pk);
            let ratification = ratification_helpers::build_signed_ratification(
                chain_id_hex,
                env,
                gh,
                &auth_pk_hex,
                &auth_sk,
                &bsk_pk,
            );
            let ratified = RatifiedBundleSigningKey {
                public_key: ratification.bundle_signing_public_key.clone(),
                fingerprint: pqc_public_key_fingerprint(&ratification.bundle_signing_public_key),
                signature_suite_id: ratification.signature_suite_id,
                authority_root_fingerprint: ratification.authority_root_fingerprint.clone(),
            };
            VerifiedFixture {
                ratification,
                ratified,
                genesis_hash_hex: genesis_hash_hex(&gh),
                authority_pk_hex: auth_pk_hex,
            }
        }

        fn devnet_inputs<'a>(
            f: &'a VerifiedFixture,
            seq: u64,
        ) -> AuthorityStateDerivationInputs<'a> {
            AuthorityStateDerivationInputs {
                runtime_env: NetworkEnvironment::Devnet,
                runtime_chain_id: ChainId(1),
                runtime_genesis_hash_hex: &f.genesis_hash_hex,
                authority_policy_version: 1,
                authority_sequence: seq,
                authority_epoch: Some(7),
                ratification: &f.ratification,
                ratified: &f.ratified,
                update_source: AuthorityStateUpdateSource::StartupLoad,
                updated_at_unix_secs: 1_700_000_000,
            }
        }

        // ----- Marker derivation tests (Run 118 §A) -----

        #[test]
        fn derive_same_ratification_same_marker() {
            let f = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            let r1 = derive_authority_state_from_ratification(devnet_inputs(&f, 5)).unwrap();
            let r2 = derive_authority_state_from_ratification(devnet_inputs(&f, 5)).unwrap();
            // Informational fields are excluded from the digest.
            assert_eq!(
                canonical_authority_state_digest(&r1),
                canonical_authority_state_digest(&r2)
            );
            // And in this fixture the records themselves are identical.
            assert_eq!(r1, r2);
            assert_eq!(r1.authority_root_fingerprint, f.authority_pk_hex);
            assert_eq!(
                r1.ratified_bundle_signing_key_fingerprint,
                f.ratified.fingerprint
            );
        }

        #[test]
        fn derive_chain_change_changes_marker() {
            let f1 = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            let f2 = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000002");
            let mut inputs2 = devnet_inputs(&f2, 5);
            inputs2.runtime_chain_id = ChainId(2);
            let r1 = derive_authority_state_from_ratification(devnet_inputs(&f1, 5)).unwrap();
            let r2 = derive_authority_state_from_ratification(inputs2).unwrap();
            assert_ne!(
                canonical_authority_state_digest(&r1),
                canonical_authority_state_digest(&r2)
            );
        }

        #[test]
        fn derive_environment_change_changes_marker() {
            let f_dev = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            let f_main =
                build_verified_fixture(RatificationEnvironment::Mainnet, "0000000000000001");
            let r_dev = derive_authority_state_from_ratification(devnet_inputs(&f_dev, 5)).unwrap();
            let mut inputs_main = devnet_inputs(&f_main, 5);
            inputs_main.runtime_env = NetworkEnvironment::Mainnet;
            let r_main = derive_authority_state_from_ratification(inputs_main).unwrap();
            assert_ne!(
                canonical_authority_state_digest(&r_dev),
                canonical_authority_state_digest(&r_main)
            );
            assert_eq!(r_dev.environment, TrustBundleEnvironment::Devnet);
            assert_eq!(r_main.environment, TrustBundleEnvironment::Mainnet);
        }

        #[test]
        fn derive_genesis_hash_change_changes_marker() {
            let f = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            let inputs_a = devnet_inputs(&f, 5);
            let r_a = derive_authority_state_from_ratification(inputs_a).unwrap();
            // Force a different runtime_genesis_hash_hex; the derivation
            // helper rejects a hex string that doesn't match the
            // ratification's bound genesis only via the verifier layer,
            // but we model "different genesis trust domain" by changing
            // the runtime hash. The helper accepts any well-formed hex,
            // so we exercise the digest flip directly.
            let alt = "ee".repeat(32);
            let mut inputs_b = devnet_inputs(&f, 5);
            inputs_b.runtime_genesis_hash_hex = &alt;
            let r_b = derive_authority_state_from_ratification(inputs_b).unwrap();
            assert_ne!(
                canonical_authority_state_digest(&r_a),
                canonical_authority_state_digest(&r_b)
            );
        }

        #[test]
        fn derive_authority_root_change_changes_marker() {
            // Two distinct verified fixtures use two distinct authority
            // root keypairs; the derived markers must differ on the
            // authority_root_fingerprint axis.
            let f1 = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            let f2 = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            assert_ne!(f1.authority_pk_hex, f2.authority_pk_hex);
            let r1 = derive_authority_state_from_ratification(devnet_inputs(&f1, 5)).unwrap();
            let r2 = derive_authority_state_from_ratification(devnet_inputs(&f2, 5)).unwrap();
            assert_ne!(
                canonical_authority_state_digest(&r1),
                canonical_authority_state_digest(&r2)
            );
            assert_ne!(r1.authority_root_fingerprint, r2.authority_root_fingerprint);
        }

        #[test]
        fn derive_ratified_key_change_changes_marker() {
            // Same authority root, different ratified bundle-signing key.
            let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
            let auth_pk_hex = full_pk_hex(&auth_pk);
            let gh = fixture_genesis_hash();
            let (bsk_pk_a, _) = MlDsa44Backend::generate_keypair().unwrap();
            let (bsk_pk_b, _) = MlDsa44Backend::generate_keypair().unwrap();
            assert_ne!(bsk_pk_a, bsk_pk_b);
            let mk = |bsk: &[u8]| -> VerifiedFixture {
                let chain_id = "0000000000000001";
                let r = ratification_helpers::build_signed_ratification(
                    chain_id,
                    RatificationEnvironment::Devnet,
                    gh,
                    &auth_pk_hex,
                    &auth_sk,
                    bsk,
                );
                let ratified = RatifiedBundleSigningKey {
                    public_key: r.bundle_signing_public_key.clone(),
                    fingerprint: pqc_public_key_fingerprint(&r.bundle_signing_public_key),
                    signature_suite_id: r.signature_suite_id,
                    authority_root_fingerprint: r.authority_root_fingerprint.clone(),
                };
                VerifiedFixture {
                    ratification: r,
                    ratified,
                    genesis_hash_hex: genesis_hash_hex(&gh),
                    authority_pk_hex: auth_pk_hex.clone(),
                }
            };
            let f_a = mk(&bsk_pk_a);
            let f_b = mk(&bsk_pk_b);
            let r_a = derive_authority_state_from_ratification(devnet_inputs(&f_a, 5)).unwrap();
            let r_b = derive_authority_state_from_ratification(devnet_inputs(&f_b, 5)).unwrap();
            assert_eq!(
                r_a.authority_root_fingerprint,
                r_b.authority_root_fingerprint
            );
            assert_ne!(
                r_a.ratified_bundle_signing_key_fingerprint,
                r_b.ratified_bundle_signing_key_fingerprint
            );
            assert_ne!(
                canonical_authority_state_digest(&r_a),
                canonical_authority_state_digest(&r_b)
            );
        }

        #[test]
        fn derive_ratification_digest_change_changes_marker() {
            // Two independent verified fixtures produce two different
            // canonical_ratification_digests (different signatures pin
            // different keys / bsk pairs).
            let f1 = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            let f2 = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            let r1 = derive_authority_state_from_ratification(devnet_inputs(&f1, 5)).unwrap();
            let r2 = derive_authority_state_from_ratification(devnet_inputs(&f2, 5)).unwrap();
            assert_ne!(r1.ratification_object_hash, r2.ratification_object_hash);
        }

        #[test]
        fn derive_digest_excludes_audit_fields() {
            let f = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            let mut inputs_a = devnet_inputs(&f, 5);
            let mut inputs_b = devnet_inputs(&f, 5);
            inputs_a.update_source = AuthorityStateUpdateSource::StartupLoad;
            inputs_a.updated_at_unix_secs = 1_700_000_000;
            inputs_b.update_source = AuthorityStateUpdateSource::SighupReload;
            inputs_b.updated_at_unix_secs = 1_900_000_000;
            let r_a = derive_authority_state_from_ratification(inputs_a).unwrap();
            let r_b = derive_authority_state_from_ratification(inputs_b).unwrap();
            assert_eq!(
                canonical_authority_state_digest(&r_a),
                canonical_authority_state_digest(&r_b),
                "audit-only fields must not influence the digest"
            );
        }

        #[test]
        fn derive_rejects_malformed_genesis_hash() {
            let f = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            let mut inputs = devnet_inputs(&f, 5);
            inputs.runtime_genesis_hash_hex = "deadbeef"; // too short
            assert!(matches!(
                derive_authority_state_from_ratification(inputs),
                Err(AuthorityStateDerivationError::MalformedRuntimeGenesisHash(
                    _
                ))
            ));
        }

        #[test]
        fn derive_rejects_runtime_env_disagreement() {
            // Ratification declares devnet but runtime claims mainnet.
            let f = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            let mut inputs = devnet_inputs(&f, 5);
            inputs.runtime_env = NetworkEnvironment::Mainnet;
            assert!(matches!(
                derive_authority_state_from_ratification(inputs),
                Err(AuthorityStateDerivationError::EnvironmentMismatch { .. })
            ));
        }

        #[test]
        fn derive_rejects_runtime_chain_disagreement() {
            // Ratification chain_id "0000000000000001" but runtime ChainId(2).
            let f = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            let mut inputs = devnet_inputs(&f, 5);
            inputs.runtime_chain_id = ChainId(2);
            assert!(matches!(
                derive_authority_state_from_ratification(inputs),
                Err(AuthorityStateDerivationError::ChainIdMismatch { .. })
            ));
        }

        #[test]
        fn derive_rejects_verifier_inconsistency() {
            // Fabricate an inconsistent (ratification, ratified) pair: the
            // ratified result claims a different authority root fingerprint
            // than the ratification embeds. The production verifier can
            // never emit this pairing, but the derivation helper must fail
            // closed if it ever sees one.
            let f = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            let mut bad_ratified = f.ratified.clone();
            bad_ratified.authority_root_fingerprint = "0".repeat(40);
            let inputs = AuthorityStateDerivationInputs {
                ratified: &bad_ratified,
                ..devnet_inputs(&f, 5)
            };
            assert!(matches!(
                derive_authority_state_from_ratification(inputs),
                Err(AuthorityStateDerivationError::RatificationVerifierInconsistent(_))
            ));
        }

        // ----- Compare-before-accept tests (Run 118 §B / §C / §D) -----

        #[test]
        fn prepare_first_write_when_no_persisted_marker() {
            let tmp = TempDir::new().unwrap();
            let path = authority_state_file_path(tmp.path());
            let f = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            let cand = derive_authority_state_from_ratification(devnet_inputs(&f, 5)).unwrap();
            let outcome = prepare_marker_for_acceptance(
                &path,
                &cand,
                NetworkEnvironment::Devnet,
                ChainId(1),
                &f.genesis_hash_hex,
            );
            assert_eq!(outcome, AuthorityStatePrepareOutcome::FirstWrite);
            assert!(outcome.is_accept());
            assert!(outcome.should_persist());
        }

        #[test]
        fn prepare_idempotent_after_first_persist() {
            let tmp = TempDir::new().unwrap();
            let path = authority_state_file_path(tmp.path());
            let f = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            let cand = derive_authority_state_from_ratification(devnet_inputs(&f, 5)).unwrap();
            persist_authority_state_atomic(&path, &cand).unwrap();
            // Re-derive with different audit fields — must still be
            // idempotent because the digest excludes audit fields.
            let mut inputs2 = devnet_inputs(&f, 5);
            inputs2.updated_at_unix_secs = 9_999_999_999;
            inputs2.update_source = AuthorityStateUpdateSource::ReloadApply;
            let cand2 = derive_authority_state_from_ratification(inputs2).unwrap();
            let outcome = prepare_marker_for_acceptance(
                &path,
                &cand2,
                NetworkEnvironment::Devnet,
                ChainId(1),
                &f.genesis_hash_hex,
            );
            assert_eq!(
                outcome,
                AuthorityStatePrepareOutcome::AlreadyPersistedIdempotent
            );
            assert!(outcome.is_accept());
            assert!(!outcome.should_persist());
        }

        #[test]
        fn prepare_upgrade_at_higher_sequence() {
            let tmp = TempDir::new().unwrap();
            let path = authority_state_file_path(tmp.path());
            let f = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            let prev = derive_authority_state_from_ratification(devnet_inputs(&f, 5)).unwrap();
            persist_authority_state_atomic(&path, &prev).unwrap();
            let cand = derive_authority_state_from_ratification(devnet_inputs(&f, 9)).unwrap();
            let outcome = prepare_marker_for_acceptance(
                &path,
                &cand,
                NetworkEnvironment::Devnet,
                ChainId(1),
                &f.genesis_hash_hex,
            );
            assert!(matches!(
                outcome,
                AuthorityStatePrepareOutcome::Upgrade {
                    previous_sequence: 5,
                    new_sequence: 9
                }
            ));
            assert!(outcome.should_persist());
        }

        #[test]
        fn prepare_rejects_rollback() {
            let tmp = TempDir::new().unwrap();
            let path = authority_state_file_path(tmp.path());
            let f = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            let prev = derive_authority_state_from_ratification(devnet_inputs(&f, 9)).unwrap();
            persist_authority_state_atomic(&path, &prev).unwrap();
            let cand = derive_authority_state_from_ratification(devnet_inputs(&f, 5)).unwrap();
            let outcome = prepare_marker_for_acceptance(
                &path,
                &cand,
                NetworkEnvironment::Devnet,
                ChainId(1),
                &f.genesis_hash_hex,
            );
            assert!(matches!(
                outcome,
                AuthorityStatePrepareOutcome::ConflictReject(
                    AuthorityStateComparison::RollbackRefused {
                        persisted_sequence: 9,
                        attempted_sequence: 5
                    }
                )
            ));
            assert!(outcome.is_reject());
            assert!(!outcome.should_persist());
        }

        #[test]
        fn prepare_rejects_same_sequence_conflicting_hash() {
            let tmp = TempDir::new().unwrap();
            let path = authority_state_file_path(tmp.path());
            // Two independent fixtures share the same runtime context but
            // produce distinct ratification_object_hash values.
            let f_a = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            let f_b = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            // Use the same genesis_hash on both fixtures (build_verified_fixture
            // already does), but force runtime hex to match fixture A so the
            // domain check passes for the persisted record.
            let prev = derive_authority_state_from_ratification(devnet_inputs(&f_a, 5)).unwrap();
            persist_authority_state_atomic(&path, &prev).unwrap();
            let cand = derive_authority_state_from_ratification(devnet_inputs(&f_b, 5)).unwrap();
            let outcome = prepare_marker_for_acceptance(
                &path,
                &cand,
                NetworkEnvironment::Devnet,
                ChainId(1),
                &f_a.genesis_hash_hex,
            );
            // Different authority roots → SameSequenceConflictingHash variant
            // (different authority_root_fingerprints means the SameSequenceConflictingKey
            // shortcut does not fire — it requires equal authority root).
            assert!(
                matches!(
                    &outcome,
                    AuthorityStatePrepareOutcome::ConflictReject(
                        AuthorityStateComparison::SameSequenceConflictingHash { .. }
                    )
                ),
                "expected SameSequenceConflictingHash, got {:?}",
                outcome
            );
        }

        #[test]
        fn prepare_rejects_persisted_domain_mismatch() {
            // Seed an on-disk marker that is structurally valid but belongs
            // to a different (env, chain_id, genesis_hash) — the
            // wrong-data-dir / wrong-snapshot-copy case.
            let tmp = TempDir::new().unwrap();
            let path = authority_state_file_path(tmp.path());
            let f = build_verified_fixture(RatificationEnvironment::Mainnet, "0000000000000002");
            // Construct a record for the (mainnet, chain=2) trust domain and
            // persist it. Then ask the wrapper for (devnet, chain=1).
            let mainnet_inputs = AuthorityStateDerivationInputs {
                runtime_env: NetworkEnvironment::Mainnet,
                runtime_chain_id: ChainId(2),
                runtime_genesis_hash_hex: &f.genesis_hash_hex,
                authority_policy_version: 1,
                authority_sequence: 5,
                authority_epoch: None,
                ratification: &f.ratification,
                ratified: &f.ratified,
                update_source: AuthorityStateUpdateSource::TestOrFixture,
                updated_at_unix_secs: 1_700_000_000,
            };
            let on_disk = derive_authority_state_from_ratification(mainnet_inputs).unwrap();
            persist_authority_state_atomic(&path, &on_disk).unwrap();

            // Build a devnet candidate for the wrapper.
            let f_dev = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            let cand = derive_authority_state_from_ratification(devnet_inputs(&f_dev, 5)).unwrap();
            let outcome = prepare_marker_for_acceptance(
                &path,
                &cand,
                NetworkEnvironment::Devnet,
                ChainId(1),
                &f_dev.genesis_hash_hex,
            );
            assert!(matches!(
                outcome,
                AuthorityStatePrepareOutcome::PersistedDomainMismatch(_)
            ));
            assert!(outcome.is_reject());
        }

        #[test]
        fn prepare_fails_closed_on_corrupt_persisted_marker() {
            let tmp = TempDir::new().unwrap();
            let path = authority_state_file_path(tmp.path());
            std::fs::write(&path, b"{ not valid json").unwrap();
            let f = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            let cand = derive_authority_state_from_ratification(devnet_inputs(&f, 5)).unwrap();
            let outcome = prepare_marker_for_acceptance(
                &path,
                &cand,
                NetworkEnvironment::Devnet,
                ChainId(1),
                &f.genesis_hash_hex,
            );
            assert!(matches!(
                outcome,
                AuthorityStatePrepareOutcome::LoadFailedFailClosed(_)
            ));
            // And the wrapper must not have rewritten/repaired the file —
            // operator intervention is the only recovery.
            let still_corrupt = std::fs::read(&path).unwrap();
            assert_eq!(still_corrupt, b"{ not valid json");
        }

        #[test]
        fn prepare_does_not_persist() {
            // The wrapper is pure: it must not write the candidate, even
            // on FirstWrite. Mutating surfaces are responsible for calling
            // persist_authority_state_atomic separately.
            let tmp = TempDir::new().unwrap();
            let path = authority_state_file_path(tmp.path());
            let f = build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            let cand = derive_authority_state_from_ratification(devnet_inputs(&f, 5)).unwrap();
            let outcome = prepare_marker_for_acceptance(
                &path,
                &cand,
                NetworkEnvironment::Devnet,
                ChainId(1),
                &f.genesis_hash_hex,
            );
            assert_eq!(outcome, AuthorityStatePrepareOutcome::FirstWrite);
            assert!(
                !path.exists(),
                "prepare_marker_for_acceptance must never write the marker file"
            );
        }

        #[test]
        fn outcome_classification_helpers() {
            assert!(AuthorityStatePrepareOutcome::FirstWrite.is_accept());
            assert!(AuthorityStatePrepareOutcome::FirstWrite.should_persist());

            assert!(AuthorityStatePrepareOutcome::AlreadyPersistedIdempotent.is_accept());
            assert!(!AuthorityStatePrepareOutcome::AlreadyPersistedIdempotent.should_persist());

            let upgrade = AuthorityStatePrepareOutcome::Upgrade {
                previous_sequence: 1,
                new_sequence: 2,
            };
            assert!(upgrade.is_accept());
            assert!(upgrade.should_persist());

            let reject = AuthorityStatePrepareOutcome::ConflictReject(
                AuthorityStateComparison::RollbackRefused {
                    persisted_sequence: 9,
                    attempted_sequence: 4,
                },
            );
            assert!(reject.is_reject());
            assert!(!reject.should_persist());

            let load_fail = AuthorityStatePrepareOutcome::LoadFailedFailClosed(
                AuthorityStateError::UnsupportedRecordVersion(99),
            );
            assert!(load_fail.is_reject());
            assert!(!load_fail.should_persist());
        }
    }

    // =======================================================================
    // Run 124 — snapshot/restore authority marker conflict tests
    // =======================================================================

    mod run124 {
        use super::*;

        // Runtime trust domain used by every test below.
        const RUNTIME_CHAIN_HEX: &str = "0000000000000001";
        const RUNTIME_GENESIS_HEX: &str =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        fn runtime_env() -> NetworkEnvironment {
            NetworkEnvironment::Devnet
        }

        fn runtime_chain() -> ChainId {
            ChainId::new(1)
        }

        fn matching_snapshot_meta() -> AuthorityStateSnapshotMeta {
            AuthorityStateSnapshotMeta {
                chain_id_hex: RUNTIME_CHAIN_HEX.to_string(),
                environment: "devnet".to_string(),
                genesis_hash_hex: RUNTIME_GENESIS_HEX.to_string(),
                authority_policy_version: 1,
                authority_sequence: 5,
                authority_epoch: Some(2),
                authority_root_fingerprint: "b".repeat(40),
                ratified_bundle_signing_key_fingerprint: "c".repeat(40),
                ratification_object_hash: "d".repeat(64),
            }
        }

        fn matching_local_record() -> PersistentAuthorityStateRecord {
            PersistentAuthorityStateRecord::new(
                RUNTIME_CHAIN_HEX.to_string(),
                TrustBundleEnvironment::Devnet,
                RUNTIME_GENESIS_HEX.to_string(),
                1,
                5,
                Some(2),
                "b".repeat(40),
                "c".repeat(40),
                "d".repeat(64),
                AuthorityStateUpdateSource::StartupLoad,
                1_700_000_000,
            )
        }

        fn run_check(
            marker_path: &Path,
            snapshot: Option<&AuthorityStateSnapshotMeta>,
        ) -> SnapshotRestoreAuthorityCheckOutcome {
            verify_snapshot_authority_state_for_restore(SnapshotRestoreAuthorityCheckInputs {
                marker_path,
                snapshot_meta: snapshot,
                runtime_env: runtime_env(),
                runtime_chain_id: runtime_chain(),
                runtime_genesis_hash_hex: RUNTIME_GENESIS_HEX,
            })
        }

        // --- Accept variants ---

        #[test]
        fn no_local_no_snapshot_is_legacy_accept() {
            let tmp = TempDir::new().unwrap();
            let outcome = run_check(&authority_state_file_path(tmp.path()), None);
            assert_eq!(
                outcome,
                SnapshotRestoreAuthorityCheckOutcome::NoMarkerEitherSide
            );
            assert!(outcome.is_accept());
            // Restore surface must not have created any marker.
            assert!(!authority_state_file_path(tmp.path()).exists());
        }

        #[test]
        fn no_local_snapshot_present_accepts_without_synthesising_local() {
            let tmp = TempDir::new().unwrap();
            let snap = matching_snapshot_meta();
            let outcome = run_check(&authority_state_file_path(tmp.path()), Some(&snap));
            assert_eq!(
                outcome,
                SnapshotRestoreAuthorityCheckOutcome::AcceptSnapshotMarkerNoLocal
            );
            // Run 124 strict non-goal: never synthesise a local marker from
            // snapshot bytes.
            assert!(!authority_state_file_path(tmp.path()).exists());
        }

        #[test]
        fn matching_local_and_snapshot_is_idempotent_accept() {
            let tmp = TempDir::new().unwrap();
            let path = authority_state_file_path(tmp.path());
            persist_authority_state_atomic(&path, &matching_local_record()).unwrap();
            let bytes_before = std::fs::read(&path).unwrap();
            let snap = matching_snapshot_meta();
            let outcome = run_check(&path, Some(&snap));
            assert_eq!(
                outcome,
                SnapshotRestoreAuthorityCheckOutcome::AcceptMatchingMarker
            );
            // Restore must not rewrite the local marker.
            let bytes_after = std::fs::read(&path).unwrap();
            assert_eq!(bytes_before, bytes_after, "marker bytes preserved");
        }

        // --- Reject variants ---

        #[test]
        fn local_present_snapshot_absent_rejects_fail_closed() {
            let tmp = TempDir::new().unwrap();
            let path = authority_state_file_path(tmp.path());
            persist_authority_state_atomic(&path, &matching_local_record()).unwrap();
            let bytes_before = std::fs::read(&path).unwrap();
            let outcome = run_check(&path, None);
            assert_eq!(
                outcome,
                SnapshotRestoreAuthorityCheckOutcome::RejectMissingSnapshotMarker
            );
            assert!(outcome.is_reject());
            // Local marker bytes must be byte-identical after a reject.
            assert_eq!(std::fs::read(&path).unwrap(), bytes_before);
        }

        #[test]
        fn rollback_snapshot_against_higher_local_rejects() {
            let tmp = TempDir::new().unwrap();
            let path = authority_state_file_path(tmp.path());
            let mut local = matching_local_record();
            local.authority_sequence = 9;
            persist_authority_state_atomic(&path, &local).unwrap();
            let snap = matching_snapshot_meta(); // authority_sequence = 5
            let outcome = run_check(&path, Some(&snap));
            match outcome {
                SnapshotRestoreAuthorityCheckOutcome::RejectConflict(
                    AuthorityStateComparison::RollbackRefused { .. },
                ) => {}
                other => panic!("expected RollbackRefused conflict, got {:?}", other),
            }
        }

        #[test]
        fn same_sequence_conflicting_hash_rejects() {
            let tmp = TempDir::new().unwrap();
            let path = authority_state_file_path(tmp.path());
            persist_authority_state_atomic(&path, &matching_local_record()).unwrap();
            let mut snap = matching_snapshot_meta();
            snap.ratification_object_hash = "e".repeat(64);
            let outcome = run_check(&path, Some(&snap));
            match outcome {
                SnapshotRestoreAuthorityCheckOutcome::RejectConflict(
                    AuthorityStateComparison::SameSequenceConflictingHash { .. },
                ) => {}
                other => panic!("expected SameSequenceConflictingHash, got {:?}", other),
            }
        }

        #[test]
        fn policy_version_regression_rejects() {
            let tmp = TempDir::new().unwrap();
            let path = authority_state_file_path(tmp.path());
            let mut local = matching_local_record();
            local.authority_policy_version = 5;
            persist_authority_state_atomic(&path, &local).unwrap();
            let snap = matching_snapshot_meta(); // policy_version=1
            let outcome = run_check(&path, Some(&snap));
            match outcome {
                SnapshotRestoreAuthorityCheckOutcome::RejectConflict(
                    AuthorityStateComparison::PolicyVersionRegression { .. },
                ) => {}
                other => panic!("expected PolicyVersionRegression, got {:?}", other),
            }
        }

        #[test]
        fn corrupt_local_marker_rejects_and_preserves_bytes() {
            let tmp = TempDir::new().unwrap();
            let path = authority_state_file_path(tmp.path());
            std::fs::write(&path, b"not valid json").unwrap();
            let bytes_before = std::fs::read(&path).unwrap();
            let snap = matching_snapshot_meta();
            let outcome = run_check(&path, Some(&snap));
            assert!(matches!(
                outcome,
                SnapshotRestoreAuthorityCheckOutcome::RejectLocalMarkerCorrupt(_)
            ));
            assert_eq!(std::fs::read(&path).unwrap(), bytes_before);
        }

        #[test]
        fn unsupported_record_version_local_rejects() {
            let tmp = TempDir::new().unwrap();
            let path = authority_state_file_path(tmp.path());
            let local = matching_local_record();
            // Forge a record_version through the serde layer.
            let mut json = serde_json::to_value(&local).unwrap();
            json["record_version"] = serde_json::json!(999);
            std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
            let outcome = run_check(&path, Some(&matching_snapshot_meta()));
            match outcome {
                SnapshotRestoreAuthorityCheckOutcome::RejectLocalMarkerCorrupt(
                    AuthorityStateError::UnsupportedRecordVersion(999),
                ) => {}
                other => panic!("expected UnsupportedRecordVersion(999), got {:?}", other),
            }
        }

        #[test]
        fn wrong_domain_local_marker_rejects_before_snapshot_compare() {
            let tmp = TempDir::new().unwrap();
            let path = authority_state_file_path(tmp.path());
            let mut local = matching_local_record();
            local.environment = TrustBundleEnvironment::Testnet;
            persist_authority_state_atomic(&path, &local).unwrap();
            let outcome = run_check(&path, Some(&matching_snapshot_meta()));
            assert!(matches!(
                outcome,
                SnapshotRestoreAuthorityCheckOutcome::RejectLocalMarkerWrongDomain(
                    AuthorityStateComparison::EnvironmentMismatch { .. }
                )
            ));
        }

        #[test]
        fn snapshot_marker_wrong_chain_rejects() {
            let tmp = TempDir::new().unwrap();
            let mut snap = matching_snapshot_meta();
            snap.chain_id_hex = "0000000000000099".to_string();
            let outcome = run_check(&authority_state_file_path(tmp.path()), Some(&snap));
            assert!(matches!(
                outcome,
                SnapshotRestoreAuthorityCheckOutcome::RejectSnapshotMarkerWrongDomain { .. }
            ));
        }

        #[test]
        fn snapshot_marker_wrong_genesis_rejects_even_without_local_marker() {
            let tmp = TempDir::new().unwrap();
            let mut snap = matching_snapshot_meta();
            snap.genesis_hash_hex = "f".repeat(64);
            let outcome = run_check(&authority_state_file_path(tmp.path()), Some(&snap));
            match outcome {
                SnapshotRestoreAuthorityCheckOutcome::RejectSnapshotMarkerWrongDomain {
                    reason,
                } => assert!(reason.contains("genesis_hash_hex")),
                other => panic!("expected snapshot wrong-domain, got {:?}", other),
            }
        }

        #[test]
        fn snapshot_marker_wrong_environment_rejects() {
            let tmp = TempDir::new().unwrap();
            let mut snap = matching_snapshot_meta();
            snap.environment = "mainnet".to_string();
            let outcome = run_check(&authority_state_file_path(tmp.path()), Some(&snap));
            assert!(matches!(
                outcome,
                SnapshotRestoreAuthorityCheckOutcome::RejectSnapshotMarkerWrongDomain { .. }
            ));
        }

        // --- Classification helpers ---

        #[test]
        fn outcome_classification_helpers() {
            assert!(SnapshotRestoreAuthorityCheckOutcome::NoMarkerEitherSide.is_accept());
            assert!(SnapshotRestoreAuthorityCheckOutcome::AcceptSnapshotMarkerNoLocal.is_accept());
            assert!(SnapshotRestoreAuthorityCheckOutcome::AcceptMatchingMarker.is_accept());
            assert!(SnapshotRestoreAuthorityCheckOutcome::RejectMissingSnapshotMarker.is_reject());
            assert!(SnapshotRestoreAuthorityCheckOutcome::RejectConflict(
                AuthorityStateComparison::RollbackRefused {
                    persisted_sequence: 9,
                    attempted_sequence: 4,
                },
            )
            .is_reject());
        }

        #[test]
        fn pure_helper_never_creates_marker_on_accept_paths() {
            // No-local + no-snapshot
            let tmp = TempDir::new().unwrap();
            let path = authority_state_file_path(tmp.path());
            let _ = run_check(&path, None);
            assert!(!path.exists());

            // No-local + snapshot present
            let tmp2 = TempDir::new().unwrap();
            let path2 = authority_state_file_path(tmp2.path());
            let snap = matching_snapshot_meta();
            let _ = run_check(&path2, Some(&snap));
            assert!(!path2.exists());
        }
    }

    // =======================================================================
    // Run 131 — marker v2 representation / comparison / migration
    // =======================================================================
    mod run131 {
        use super::*;
        use qbind_ledger::RatificationEnvironment;

        fn sample_v2_record() -> PersistentAuthorityStateRecordV2 {
            PersistentAuthorityStateRecordV2::new(
                "0000000000000001".to_string(),
                TrustBundleEnvironment::Devnet,
                "a".repeat(64),
                "b".repeat(40),
                100,
                "c".repeat(40),
                100,
                7,
                BundleSigningRatificationV2Action::Ratify,
                None,
                "d".repeat(64),
                None,
                AuthorityStateUpdateSource::TestOrFixture,
                1_700_000_123,
            )
        }

        fn sample_ratification_v2(
            action: BundleSigningRatificationV2Action,
        ) -> BundleSigningRatificationV2 {
            BundleSigningRatificationV2 {
                schema_version: 2,
                environment: RatificationEnvironment::Devnet,
                chain_id: "0000000000000001".to_string(),
                genesis_hash: [0xaa; 32],
                authority_policy_version: 1,
                authority_root_fingerprint: "b".repeat(40),
                authority_root_suite_id: 100,
                target_bundle_signing_key_fingerprint: "c".repeat(40),
                target_bundle_signing_key_suite_id: 100,
                target_bundle_signing_public_key: vec![0u8; 1312],
                authority_domain_sequence: 7,
                key_lifecycle_action: action,
                previous_key_fingerprint: None,
                previous_ratification_digest: None,
                valid_from_epoch: None,
                valid_until_epoch: None,
                revocation_reason: None,
                capabilities_scope: None,
                signature: vec![0u8; 2420],
            }
        }

        fn sample_ratifed_v2(
            action: BundleSigningRatificationV2Action,
        ) -> RatifiedBundleSigningKeyV2 {
            RatifiedBundleSigningKeyV2 {
                public_key: vec![0u8; 1312],
                fingerprint: "c".repeat(40),
                suite_id: 100,
                authority_root_fingerprint: "b".repeat(40),
                authority_policy_version: 1,
                authority_domain_sequence: 7,
                key_lifecycle_action: action,
            }
        }

        #[test]
        fn v2_digest_is_deterministic_and_domain_separated_from_v1() {
            let v2 = sample_v2_record();
            assert_eq!(
                canonical_authority_state_v2_digest(&v2),
                canonical_authority_state_v2_digest(&v2)
            );
            assert!(
                canonical_authority_state_v2_preimage(&v2).starts_with(AUTHORITY_STATE_DOMAIN_V2)
            );
            let v1 = sample_record();
            assert!(canonical_authority_state_preimage(&v1).starts_with(AUTHORITY_STATE_DOMAIN_V1));
            assert_ne!(
                canonical_authority_state_v2_digest(&v2),
                canonical_authority_state_digest(&v1)
            );
        }

        #[test]
        fn v2_digest_changes_with_security_fields() {
            let base = sample_v2_record();
            let base_digest = canonical_authority_state_v2_digest(&base);

            let mut r = base.clone();
            r.environment = TrustBundleEnvironment::Mainnet;
            assert_ne!(canonical_authority_state_v2_digest(&r), base_digest);

            let mut r = base.clone();
            r.chain_id = "0000000000000002".to_string();
            assert_ne!(canonical_authority_state_v2_digest(&r), base_digest);

            let mut r = base.clone();
            r.genesis_hash = "f".repeat(64);
            assert_ne!(canonical_authority_state_v2_digest(&r), base_digest);

            let mut r = base.clone();
            r.authority_root_fingerprint = "e".repeat(40);
            assert_ne!(canonical_authority_state_v2_digest(&r), base_digest);

            let mut r = base.clone();
            r.active_bundle_signing_key_fingerprint = "9".repeat(40);
            assert_ne!(canonical_authority_state_v2_digest(&r), base_digest);

            let mut r = base.clone();
            r.latest_authority_domain_sequence += 1;
            assert_ne!(canonical_authority_state_v2_digest(&r), base_digest);

            let mut r = base.clone();
            r.latest_lifecycle_action = BundleSigningRatificationV2Action::Revoke;
            r.revoked_key_metadata = Some("7".repeat(40));
            assert_ne!(canonical_authority_state_v2_digest(&r), base_digest);

            let mut r = base.clone();
            r.latest_ratification_v2_digest = "1".repeat(64);
            assert_ne!(canonical_authority_state_v2_digest(&r), base_digest);
        }

        #[test]
        fn derive_v2_marker_ratify_rotate_revoke_and_fail_closed_cases() {
            let ratify = sample_ratification_v2(BundleSigningRatificationV2Action::Ratify);
            let out =
                derive_authority_state_v2_from_ratification(AuthorityStateDerivationV2Inputs {
                    runtime_env: NetworkEnvironment::Devnet,
                    runtime_chain_id: ChainId::new(1),
                    runtime_genesis_hash_hex: &"aa".repeat(32),
                    ratification: &ratify,
                    ratified: &sample_ratifed_v2(BundleSigningRatificationV2Action::Ratify),
                    update_source: AuthorityStateUpdateSource::TestOrFixture,
                    updated_at_unix_secs: 1,
                })
                .expect("ratify derives");
            assert_eq!(
                out.latest_lifecycle_action,
                BundleSigningRatificationV2Action::Ratify
            );

            let mut rotate = sample_ratification_v2(BundleSigningRatificationV2Action::Rotate);
            rotate.previous_key_fingerprint = Some("d".repeat(40));
            rotate.previous_ratification_digest = Some("e".repeat(64));
            let out_rotate =
                derive_authority_state_v2_from_ratification(AuthorityStateDerivationV2Inputs {
                    runtime_env: NetworkEnvironment::Devnet,
                    runtime_chain_id: ChainId::new(1),
                    runtime_genesis_hash_hex: &"aa".repeat(32),
                    ratification: &rotate,
                    ratified: &sample_ratifed_v2(BundleSigningRatificationV2Action::Rotate),
                    update_source: AuthorityStateUpdateSource::TestOrFixture,
                    updated_at_unix_secs: 1,
                })
                .expect("rotate derives");
            assert_eq!(
                out_rotate.previous_bundle_signing_key_fingerprint,
                Some("d".repeat(40))
            );

            let mut revoke = sample_ratification_v2(BundleSigningRatificationV2Action::Revoke);
            revoke.revocation_reason = Some("compromised".to_string());
            let out_revoke =
                derive_authority_state_v2_from_ratification(AuthorityStateDerivationV2Inputs {
                    runtime_env: NetworkEnvironment::Devnet,
                    runtime_chain_id: ChainId::new(1),
                    runtime_genesis_hash_hex: &"aa".repeat(32),
                    ratification: &revoke,
                    ratified: &sample_ratifed_v2(BundleSigningRatificationV2Action::Revoke),
                    update_source: AuthorityStateUpdateSource::TestOrFixture,
                    updated_at_unix_secs: 1,
                })
                .expect("revoke derives");
            assert!(out_revoke.revoked_key_metadata.is_some());

            let mut rotate_missing_prev =
                sample_ratification_v2(BundleSigningRatificationV2Action::Rotate);
            rotate_missing_prev.previous_ratification_digest = Some("e".repeat(64));
            let err =
                derive_authority_state_v2_from_ratification(AuthorityStateDerivationV2Inputs {
                    runtime_env: NetworkEnvironment::Devnet,
                    runtime_chain_id: ChainId::new(1),
                    runtime_genesis_hash_hex: &"aa".repeat(32),
                    ratification: &rotate_missing_prev,
                    ratified: &sample_ratifed_v2(BundleSigningRatificationV2Action::Rotate),
                    update_source: AuthorityStateUpdateSource::TestOrFixture,
                    updated_at_unix_secs: 1,
                })
                .expect_err("missing rotate previous key must fail");
            assert!(matches!(
                err,
                AuthorityStateDerivationV2Error::MissingPreviousKeyForRotate
            ));

            let mut wrong_domain =
                sample_ratification_v2(BundleSigningRatificationV2Action::Ratify);
            wrong_domain.environment = RatificationEnvironment::Mainnet;
            let err =
                derive_authority_state_v2_from_ratification(AuthorityStateDerivationV2Inputs {
                    runtime_env: NetworkEnvironment::Devnet,
                    runtime_chain_id: ChainId::new(1),
                    runtime_genesis_hash_hex: &"aa".repeat(32),
                    ratification: &wrong_domain,
                    ratified: &sample_ratifed_v2(BundleSigningRatificationV2Action::Ratify),
                    update_source: AuthorityStateUpdateSource::TestOrFixture,
                    updated_at_unix_secs: 1,
                })
                .expect_err("wrong domain must fail");
            assert!(matches!(
                err,
                AuthorityStateDerivationV2Error::EnvironmentMismatch { .. }
            ));

            let mut wrong_target =
                sample_ratification_v2(BundleSigningRatificationV2Action::Ratify);
            wrong_target.target_bundle_signing_key_fingerprint = "f".repeat(40);
            let err =
                derive_authority_state_v2_from_ratification(AuthorityStateDerivationV2Inputs {
                    runtime_env: NetworkEnvironment::Devnet,
                    runtime_chain_id: ChainId::new(1),
                    runtime_genesis_hash_hex: &"aa".repeat(32),
                    ratification: &wrong_target,
                    ratified: &sample_ratifed_v2(BundleSigningRatificationV2Action::Ratify),
                    update_source: AuthorityStateUpdateSource::TestOrFixture,
                    updated_at_unix_secs: 1,
                })
                .expect_err("wrong target binding must fail");
            assert!(matches!(
                err,
                AuthorityStateDerivationV2Error::TargetKeyBindingMismatch { .. }
            ));
        }

        #[test]
        fn compare_v2_and_migration_rules() {
            let base = sample_v2_record();
            assert!(matches!(
                compare_authority_marker_v2(None, &base),
                AuthorityMarkerV2ComparisonOutcome::FirstV2MarkerAccepted
            ));
            assert!(matches!(
                compare_authority_marker_v2(
                    Some(&PersistentAuthorityStateRecordVersioned::V2(base.clone())),
                    &base
                ),
                AuthorityMarkerV2ComparisonOutcome::SameV2MarkerIdempotent
            ));

            let mut higher = base.clone();
            higher.latest_authority_domain_sequence += 1;
            higher.latest_ratification_v2_digest = "f".repeat(64);
            assert!(matches!(
                compare_authority_marker_v2(
                    Some(&PersistentAuthorityStateRecordVersioned::V2(base.clone())),
                    &higher
                ),
                AuthorityMarkerV2ComparisonOutcome::HigherSequenceAccepted { .. }
            ));

            assert!(matches!(
                compare_authority_marker_v2(
                    Some(&PersistentAuthorityStateRecordVersioned::V2(higher.clone())),
                    &base
                ),
                AuthorityMarkerV2ComparisonOutcome::LowerSequenceRejected { .. }
            ));

            let mut same_seq_diff_digest = base.clone();
            same_seq_diff_digest.latest_ratification_v2_digest = "1".repeat(64);
            assert!(matches!(
                compare_authority_marker_v2(
                    Some(&PersistentAuthorityStateRecordVersioned::V2(base.clone())),
                    &same_seq_diff_digest
                ),
                AuthorityMarkerV2ComparisonOutcome::SameSequenceDifferentDigestRejected { .. }
            ));

            let mut wrong_env = base.clone();
            wrong_env.environment = TrustBundleEnvironment::Mainnet;
            assert!(matches!(
                compare_authority_marker_v2(
                    Some(&PersistentAuthorityStateRecordVersioned::V2(base.clone())),
                    &wrong_env
                ),
                AuthorityMarkerV2ComparisonOutcome::WrongEnvironmentRejected { .. }
            ));

            let mut wrong_chain = base.clone();
            wrong_chain.chain_id = "0000000000000002".to_string();
            assert!(matches!(
                compare_authority_marker_v2(
                    Some(&PersistentAuthorityStateRecordVersioned::V2(base.clone())),
                    &wrong_chain
                ),
                AuthorityMarkerV2ComparisonOutcome::WrongChainIdRejected { .. }
            ));

            let mut wrong_genesis = base.clone();
            wrong_genesis.genesis_hash = "f".repeat(64);
            assert!(matches!(
                compare_authority_marker_v2(
                    Some(&PersistentAuthorityStateRecordVersioned::V2(base.clone())),
                    &wrong_genesis
                ),
                AuthorityMarkerV2ComparisonOutcome::WrongGenesisHashRejected { .. }
            ));

            let mut wrong_root = base.clone();
            wrong_root.authority_root_fingerprint = "9".repeat(40);
            assert!(matches!(
                compare_authority_marker_v2(
                    Some(&PersistentAuthorityStateRecordVersioned::V2(base.clone())),
                    &wrong_root
                ),
                AuthorityMarkerV2ComparisonOutcome::WrongAuthorityRootRejected { .. }
            ));

            let mut bad_version = base.clone();
            bad_version.record_version = 99;
            assert!(matches!(
                compare_authority_marker_v2(None, &bad_version),
                AuthorityMarkerV2ComparisonOutcome::MalformedOrUnsupportedMarkerRejected { .. }
            ));
        }

        #[test]
        fn versioned_parse_and_v1_v2_policy_paths() {
            let unsupported = br#"{"record_version": 999}"#;
            assert!(matches!(
                parse_versioned_authority_state_record_bytes(unsupported),
                Err(AuthorityStateError::UnsupportedRecordVersion(999))
            ));
            assert!(matches!(
                parse_versioned_authority_state_record_bytes(b"{not json"),
                Err(AuthorityStateError::Malformed(_))
            ));

            let v1_prev = sample_record();
            let v1_candidate = sample_record();
            let legacy = prepare_v2_marker_for_acceptance(
                Some(&PersistentAuthorityStateRecordVersioned::V1(
                    v1_prev.clone(),
                )),
                &PersistentAuthorityStateRecordVersioned::V1(v1_candidate.clone()),
            );
            assert_eq!(
                legacy,
                AuthorityMarkerV2ComparisonOutcome::LegacyV1(compare_authority_state(
                    Some(&v1_prev),
                    &v1_candidate
                ))
            );

            let v2_candidate = sample_v2_record();
            assert!(matches!(
                prepare_v2_marker_for_acceptance(
                    Some(&PersistentAuthorityStateRecordVersioned::V1(sample_record())),
                    &PersistentAuthorityStateRecordVersioned::V2(v2_candidate.clone()),
                ),
                AuthorityMarkerV2ComparisonOutcome::V2AfterV1ExplicitMigrationAllowed
            ));

            assert!(matches!(
                prepare_v2_marker_for_acceptance(
                    Some(&PersistentAuthorityStateRecordVersioned::V2(
                        v2_candidate.clone()
                    )),
                    &PersistentAuthorityStateRecordVersioned::V1(sample_record()),
                ),
                AuthorityMarkerV2ComparisonOutcome::V1AfterV2Rejected
            ));

            assert!(matches!(
                prepare_v2_marker_for_acceptance(
                    None,
                    &PersistentAuthorityStateRecordVersioned::V1(sample_record())
                ),
                AuthorityMarkerV2ComparisonOutcome::LegacyV1(AuthorityStateComparison::FirstLoad)
            ));
            assert!(matches!(
                prepare_v2_marker_for_acceptance(
                    None,
                    &PersistentAuthorityStateRecordVersioned::V2(sample_v2_record())
                ),
                AuthorityMarkerV2ComparisonOutcome::FirstV2MarkerAccepted
            ));
        }
    }
}