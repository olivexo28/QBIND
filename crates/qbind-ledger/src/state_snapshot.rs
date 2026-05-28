//! T215: State snapshots for fast sync and recovery.
//!
//! This module provides a state snapshot trait and supporting types for taking
//! point-in-time account-state snapshots from the canonical RocksDB state.
//! Snapshots are deterministic and local-only (no new consensus rules).
//!
//! # Design
//!
//! State snapshots capture the complete account state at a specific block height,
//! enabling:
//! - Fast node synchronization (boot from snapshot instead of genesis)
//! - Recovery from data corruption
//! - Archival node workflows
//!
//! # Snapshot Directory Layout
//!
//! ```text
//! snapshot_dir/
//! ├── meta.json           # Snapshot metadata (height, hash, chain_id, timestamp)
//! └── state/              # RocksDB checkpoint (SST files)
//! ```
//!
//! # Thread Safety
//!
//! Implementations should be thread-safe. Snapshot creation may run in a
//! background task while reads/writes continue on the main execution path.
//!
//! # Example
//!
//! ```rust,ignore
//! use qbind_ledger::{RocksDbAccountState, StateSnapshotter, StateSnapshotMeta};
//! use std::path::Path;
//!
//! let storage = RocksDbAccountState::open(Path::new("/data/state"))?;
//!
//! let meta = StateSnapshotMeta {
//!     height: 100_000,
//!     block_hash: [0xAA; 32],
//!     created_at_unix_ms: 1700000000000,
//!     chain_id: 0x51424E444D41494E,
//!     epoch: None, // Run 097: no canonical committed epoch observed
//!     authority_state: None, // Run 117: no canonical authority marker observed
//!     authority_state_v2: None, // Run 140: no v2 authority marker observed
//! };
//!
//! storage.create_snapshot(&meta, Path::new("/data/snapshots/100000"))?;
//! println!("Snapshot created at height {}", meta.height);
//! ```

use std::fmt;
use std::path::Path;
use std::time::Duration;

// ============================================================================
// Snapshot Metadata
// ============================================================================

/// Metadata describing a state snapshot (T215).
///
/// This struct captures all information needed to validate and restore
/// a snapshot:
/// - `height`: The block height at which the snapshot was taken
/// - `block_hash`: The hash of the block at this height
/// - `created_at_unix_ms`: Unix timestamp in milliseconds when snapshot was created
/// - `chain_id`: The chain ID to verify snapshot is from correct network
///
/// # Serialization
///
/// Metadata is stored as JSON in `meta.json` within the snapshot directory
/// for human readability and easy validation.
///
/// # Example
///
/// ```rust
/// use qbind_ledger::StateSnapshotMeta;
///
/// let meta = StateSnapshotMeta {
///     height: 100_000,
///     block_hash: [0xAA; 32],
///     created_at_unix_ms: 1700000000000,
///     chain_id: 0x51424E444D41494E, // MainNet chain ID
///     epoch: None, // Run 097: no canonical committed epoch observed
///     authority_state: None, // Run 117: no canonical authority marker observed
///     authority_state_v2: None, // Run 140: no v2 authority marker observed
/// };
///
/// assert_eq!(meta.height, 100_000);
/// assert_eq!(meta.epoch, None);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSnapshotMeta {
    /// Block height at which the snapshot was taken.
    ///
    /// The snapshot contains the complete account state after applying
    /// all transactions in this block.
    pub height: u64,

    /// Hash of the block at this height (32 bytes).
    ///
    /// Used to verify the snapshot corresponds to the expected chain state.
    /// During restore, nodes can verify this matches the block at `height`
    /// in their chain.
    pub block_hash: [u8; 32],

    /// Unix timestamp (milliseconds) when the snapshot was created.
    ///
    /// This is the wall-clock time when `create_snapshot()` was called,
    /// not the block timestamp. Useful for monitoring and diagnostics.
    pub created_at_unix_ms: u64,

    /// Chain ID identifying the network (MainNet, TestNet, DevNet).
    ///
    /// Prevents accidentally restoring a snapshot from a different network.
    /// Should match the node's configured chain ID.
    pub chain_id: u64,

    /// Run 097: optional canonical committed epoch at the moment of snapshot
    /// creation, sourced **only** from a canonical surface (e.g. the
    /// production `ConsensusStorage::get_current_epoch()` per Run 093/094).
    ///
    /// Semantics — see `task/RUN_097_TASK.txt`:
    ///
    /// - `Some(n)`: the snapshot was created on a node that observed
    ///   `CommittedEpoch(n)` in canonical consensus storage. Restore
    ///   uses this value to persist `meta:current_epoch = n` into the
    ///   restored node's canonical `<data_dir>/consensus` surface.
    /// - `None`: no canonical committed epoch was observable at snapshot
    ///   creation (e.g. pre-Run-094 node, no `data_dir`, or
    ///   `PresentNoCommittedEpoch` storage state). This is an
    ///   **explicit absence** and MUST NOT be coerced to `0`.
    ///
    /// Old snapshots predating Run 097 do not carry this field and parse
    /// as `epoch: None` (additive backward compatibility).
    ///
    /// Run 097 MUST NOT derive this value from block height, view number,
    /// wall-clock time, timer ticks, snapshot height, or directory name.
    pub epoch: Option<u64>,

    /// Run 117: optional ratified bundle-signing authority state at the
    /// moment of snapshot creation, sourced **only** from a canonical
    /// persisted authority marker (e.g. the `<data_dir>/pqc_authority_state.json`
    /// surface introduced by the Run 117 `pqc_authority_state` module).
    ///
    /// Semantics:
    ///
    /// - `Some(state)`: the snapshot was created on a node whose
    ///   canonical authority marker reported these `(authority_sequence,
    ///   ratification_object_hash, ...)` values. Run 117 lands this
    ///   field as an **additive metadata carrier** only — the restore
    ///   conflict-detection wiring is staged for Run 118 (see
    ///   `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_117.md`).
    /// - `None`: no canonical authority marker was observable at
    ///   snapshot creation (legacy snapshot pre-Run-117, or a Run-117+
    ///   node that never accepted a ratification yet). This is an
    ///   **explicit absence** and MUST NOT be coerced to a synthetic
    ///   "empty/permissive" authority state. Restore on a node with
    ///   an existing local authority marker MUST NOT silently accept a
    ///   snapshot whose authority_state is `None` as if it were a
    ///   match (Run 118 enforcement scope).
    ///
    /// Old snapshots predating Run 117 do not carry this field and
    /// parse as `authority_state: None` (additive backward
    /// compatibility). When `None`, the `"authority_state"` key is
    /// omitted entirely from the JSON output.
    ///
    /// Run 117 MUST NOT derive any field of this value from block
    /// height, wall-clock time, snapshot height, or directory name.
    /// Each field must come from a canonical authority-marker source.
    pub authority_state: Option<AuthorityStateSnapshotMeta>,

    /// Run 140: optional **additive** v2 authority-state metadata block.
    ///
    /// Mirrors the Run 117 [`Self::authority_state`] additive pattern but
    /// carries the v2 marker fields ([`AuthorityStateSnapshotMetaV2`])
    /// required by Run 140 snapshot/restore v2 authority-marker parity.
    /// `None` for snapshots whose authority marker is v1 (or whose source
    /// node never observed a v2 marker). Old snapshots predating Run 140
    /// do not carry this field and parse as `authority_state_v2: None`.
    ///
    /// When `Some(state_v2)`, the v1 [`Self::authority_state`] field MAY
    /// be `None` (a v2-only marker source) — Run 140 restore wiring
    /// dispatches on the v2 carrier first.
    ///
    /// When `None`, the `"authority_state_v2"` key is omitted entirely
    /// from the JSON output (backward compatible). Missing v2 marker
    /// state MUST NOT be silently coerced to a synthetic v2 state.
    pub authority_state_v2: Option<AuthorityStateSnapshotMetaV2>,
}

/// Run 140: additive v2-marker snapshot metadata carried in
/// [`StateSnapshotMeta`].
///
/// Mirrors the security-relevant fields of
/// `pqc_authority_state::PersistentAuthorityStateRecordV2` living in
/// `qbind-node`, but is defined here in `qbind-ledger` because
/// `qbind-ledger` cannot depend on `qbind-node`. Run 140 restore wiring
/// reconstructs a `PersistentAuthorityStateRecordV2` from this carrier
/// and routes it through the existing `compare_authority_marker_v2`
/// comparison surface (Run 131).
///
/// All hex / sequence fields use the same lowercase-ASCII canonical
/// form as the v1 carrier so on-disk JSON is stable across platforms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityStateSnapshotMetaV2 {
    /// 16 lowercase hex chars of the chain id (no `0x` prefix).
    pub chain_id_hex: String,

    /// Canonical lowercase-ascii environment tag
    /// (`"devnet"` / `"testnet"` / `"mainnet"`).
    pub environment: String,

    /// 64 lowercase hex chars of the canonical genesis hash this v2
    /// authority state is bound to.
    pub genesis_hash_hex: String,

    /// Lowercase-hex fingerprint of the authority root.
    pub authority_root_fingerprint: String,

    /// Authority-root signature suite id (Run 131).
    pub authority_root_suite_id: u8,

    /// Lowercase-hex fingerprint of the currently active bundle-signing
    /// key (NOT the private key, NOT the full public key — fingerprint
    /// only).
    pub active_bundle_signing_key_fingerprint: String,

    /// Active bundle-signing key signature suite id (Run 131).
    pub active_bundle_signing_key_suite_id: u8,

    /// Strictly monotonic v2 authority-domain sequence
    /// (Run 130 `latest_authority_domain_sequence`).
    pub latest_authority_domain_sequence: u64,

    /// Latest lifecycle action one-byte encoding
    /// (`Ratify = 0`, `Rotate = 1`, `Revoke = 2` — fixed by Run 130).
    pub latest_lifecycle_action_byte: u8,

    /// Optional lowercase-hex previous bundle-signing key fingerprint
    /// (present iff `Rotate`).
    pub previous_bundle_signing_key_fingerprint: Option<String>,

    /// 64 lowercase hex chars of the SHA3-256
    /// `canonical_ratification_v2_digest` of the
    /// `BundleSigningRatificationV2` object whose acceptance produced
    /// this v2 authority state.
    pub latest_ratification_v2_digest: String,

    /// Optional lowercase-hex revoked-key metadata placeholder
    /// (present iff `Revoke`).
    pub revoked_key_metadata: Option<String>,
}

/// Run 117: additive authority-state metadata carried in
/// [`StateSnapshotMeta`].
///
/// This carrier mirrors the security-relevant fields of the
/// Run 117 `pqc_authority_state::PersistentAuthorityStateRecord`
/// living in `qbind-node`, but is defined here in `qbind-ledger`
/// because `qbind-ledger` cannot depend on `qbind-node`. Run 118
/// restore wiring is expected to reconstruct a `PersistentAuthorityStateRecord`
/// from this carrier (or to perform an equivalent field-wise
/// comparison) when deciding whether a snapshot conflicts with the
/// node's existing persisted authority marker.
///
/// All fields are present as canonical lowercase-ASCII strings /
/// big-endian-tracked integers so the on-disk JSON form is stable
/// across platforms and serializers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityStateSnapshotMeta {
    /// 16 lowercase hex chars of the chain id (no `0x` prefix).
    /// Used to defence-in-depth a wrong-data-dir / wrong-network
    /// snapshot copy beyond the outer
    /// [`StateSnapshotMeta::chain_id`] check.
    pub chain_id_hex: String,

    /// Canonical lowercase-ascii environment tag
    /// (`"devnet"` / `"testnet"` / `"mainnet"`).
    pub environment: String,

    /// 64 lowercase hex chars of the canonical genesis hash this
    /// authority state is bound to.
    pub genesis_hash_hex: String,

    /// `authority_policy_version` of the genesis authority block.
    pub authority_policy_version: u32,

    /// Genesis-bound monotonic authority sequence
    /// (`GenesisAuthorityConfig::authority_sequence`, Run 101).
    pub authority_sequence: u64,

    /// Optional genesis-bound authority epoch
    /// (`GenesisAuthorityConfig::authority_epoch`, Run 101).
    pub authority_epoch: Option<u64>,

    /// Lowercase-hex fingerprint of the genesis-bound authority
    /// root that signed the most recently accepted ratification.
    pub authority_root_fingerprint: String,

    /// Lowercase-hex SHA3-256 fingerprint of the ratified
    /// bundle-signing public key (NOT the private key, NOT the
    /// full public key — fingerprint only).
    pub ratified_bundle_signing_key_fingerprint: String,

    /// 64 lowercase hex chars of the SHA3-256
    /// `canonical_ratification_digest` of the
    /// `BundleSigningRatification` object whose acceptance produced
    /// this authority state.
    pub ratification_object_hash: String,
}

impl StateSnapshotMeta {
    /// Create a new snapshot metadata instance.
    ///
    /// `epoch` defaults to `None`; use [`StateSnapshotMeta::with_epoch`]
    /// to populate it from a canonical committed-epoch source.
    pub fn new(height: u64, block_hash: [u8; 32], created_at_unix_ms: u64, chain_id: u64) -> Self {
        Self {
            height,
            block_hash,
            created_at_unix_ms,
            chain_id,
            epoch: None,
            authority_state: None,
            authority_state_v2: None,
        }
    }

    /// Run 097: builder-style setter for the optional canonical
    /// committed-epoch field. Pass `Some(n)` only when `n` was sourced
    /// from a canonical surface (e.g. the production `ConsensusStorage`
    /// `get_current_epoch()` probe). Pass `None` to keep absence
    /// explicit — missing epoch MUST NOT be silently coerced to `0`.
    pub fn with_epoch(mut self, epoch: Option<u64>) -> Self {
        self.epoch = epoch;
        self
    }

    /// Run 117: builder-style setter for the optional authority-state
    /// metadata field. Pass `Some(state)` only when each field was
    /// sourced from the canonical persisted authority marker
    /// (`<data_dir>/pqc_authority_state.json` per Run 117). Pass
    /// `None` to keep absence explicit — missing authority state MUST
    /// NOT be silently coerced to a synthetic empty/permissive state.
    pub fn with_authority_state(
        mut self,
        authority_state: Option<AuthorityStateSnapshotMeta>,
    ) -> Self {
        self.authority_state = authority_state;
        self
    }

    /// Run 140: builder-style setter for the optional **v2** authority-state
    /// metadata field. Pass `Some(state)` only when each field was sourced
    /// from the canonical persisted v2 authority marker
    /// (`<data_dir>/pqc_authority_state.json` parsed as
    /// `PersistentAuthorityStateRecordVersioned::V2`). Pass `None` to keep
    /// absence explicit — missing v2 authority state MUST NOT be silently
    /// coerced to a synthetic empty/permissive state.
    ///
    /// Run 140 restore wiring (source/test only) dispatches the v2 marker
    /// comparison through the existing `compare_authority_marker_v2`
    /// primitive in `qbind-node::pqc_authority_state`. Release-binary
    /// snapshot/restore v2 evidence is deferred to Run 141.
    pub fn with_authority_state_v2(
        mut self,
        authority_state_v2: Option<AuthorityStateSnapshotMetaV2>,
    ) -> Self {
        self.authority_state_v2 = authority_state_v2;
        self
    }

    /// Get the current Unix timestamp in milliseconds.
    pub fn now_unix_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Encode metadata to JSON bytes.
    ///
    /// Format (Run 097 additive `epoch` field):
    /// ```json
    /// {
    ///   "height": 100000,
    ///   "block_hash": "aaaa...aaaa",
    ///   "created_at_unix_ms": 1700000000000,
    ///   "chain_id": 5854693887968574798,
    ///   "epoch": 7
    /// }
    /// ```
    ///
    /// When `epoch` is `None` (e.g. pre-Run-097 snapshots, or snapshots
    /// taken without an observable canonical committed epoch) the
    /// `"epoch"` key is **omitted entirely** from the JSON output. This
    /// preserves additive backward compatibility: parsers older than
    /// Run 097 simply ignore the new key when present, and the new
    /// parser distinguishes "absent" (`None`) from "present and zero"
    /// (`Some(0)`).
    pub fn to_json(&self) -> Vec<u8> {
        let block_hash_hex: String = self
            .block_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let epoch_field = match self.epoch {
            Some(e) => format!(",\n  \"epoch\": {}", e),
            None => String::new(),
        };
        // Run 117: additive authority-state block. When `None`, the
        // entire `"authority_state"` key is omitted so pre-Run-117
        // parsers (including the Run 097 parser) continue to see
        // backward-compatible JSON. Field ordering is deterministic
        // so the serialised output is byte-stable across runs.
        let authority_state_field = match &self.authority_state {
            Some(a) => {
                let epoch_inner = match a.authority_epoch {
                    Some(e) => format!(",\n    \"authority_epoch\": {}", e),
                    None => String::new(),
                };
                format!(
                    ",\n  \"authority_state\": {{\n    \"chain_id_hex\": \"{}\",\n    \"environment\": \"{}\",\n    \"genesis_hash_hex\": \"{}\",\n    \"authority_policy_version\": {},\n    \"authority_sequence\": {}{},\n    \"authority_root_fingerprint\": \"{}\",\n    \"ratified_bundle_signing_key_fingerprint\": \"{}\",\n    \"ratification_object_hash\": \"{}\"\n  }}",
                    a.chain_id_hex,
                    a.environment,
                    a.genesis_hash_hex,
                    a.authority_policy_version,
                    a.authority_sequence,
                    epoch_inner,
                    a.authority_root_fingerprint,
                    a.ratified_bundle_signing_key_fingerprint,
                    a.ratification_object_hash,
                )
            }
            None => String::new(),
        };
        // Run 140: additive v2 authority-state block. When `None`, the
        // entire `"authority_state_v2"` key is omitted so pre-Run-140
        // parsers continue to see backward-compatible JSON. Field
        // ordering is deterministic so the serialised output is
        // byte-stable across runs.
        let authority_state_v2_field = match &self.authority_state_v2 {
            Some(a) => {
                let prev_field = match &a.previous_bundle_signing_key_fingerprint {
                    Some(p) => format!(
                        ",\n    \"previous_bundle_signing_key_fingerprint\": \"{}\"",
                        p
                    ),
                    None => String::new(),
                };
                let revoked_field = match &a.revoked_key_metadata {
                    Some(r) => format!(",\n    \"revoked_key_metadata\": \"{}\"", r),
                    None => String::new(),
                };
                format!(
                    ",\n  \"authority_state_v2\": {{\n    \"chain_id_hex\": \"{}\",\n    \"environment\": \"{}\",\n    \"genesis_hash_hex\": \"{}\",\n    \"authority_root_fingerprint\": \"{}\",\n    \"authority_root_suite_id\": {},\n    \"active_bundle_signing_key_fingerprint\": \"{}\",\n    \"active_bundle_signing_key_suite_id\": {},\n    \"latest_authority_domain_sequence\": {},\n    \"latest_lifecycle_action_byte\": {},\n    \"latest_ratification_v2_digest\": \"{}\"{}{}\n  }}",
                    a.chain_id_hex,
                    a.environment,
                    a.genesis_hash_hex,
                    a.authority_root_fingerprint,
                    a.authority_root_suite_id,
                    a.active_bundle_signing_key_fingerprint,
                    a.active_bundle_signing_key_suite_id,
                    a.latest_authority_domain_sequence,
                    a.latest_lifecycle_action_byte,
                    a.latest_ratification_v2_digest,
                    prev_field,
                    revoked_field,
                )
            }
            None => String::new(),
        };
        format!(
            "{{\n  \"height\": {},\n  \"block_hash\": \"{}\",\n  \"created_at_unix_ms\": {},\n  \"chain_id\": {}{}{}{}\n}}",
            self.height,
            block_hash_hex,
            self.created_at_unix_ms,
            self.chain_id,
            epoch_field,
            authority_state_field,
            authority_state_v2_field,
        )
        .into_bytes()
    }

    /// Parse metadata from JSON bytes.
    ///
    /// Returns `None` if parsing fails or required fields are missing.
    ///
    /// Run 097: the `"epoch"` field is **optional and additive**.
    ///
    /// - Absent key → `epoch: None` (pre-Run-097 snapshot, parses cleanly).
    /// - Present and numeric → `epoch: Some(n)` (Run 097+ snapshot).
    /// - Present but malformed (non-numeric, quoted, etc.) → returns
    ///   `None` from this function (fail-closed on the parse path so
    ///   `validate_snapshot_dir` surfaces `MissingMetadata`).
    ///
    /// Missing epoch MUST NOT be silently coerced to `0`.
    pub fn from_json(data: &[u8]) -> Option<Self> {
        let s = std::str::from_utf8(data).ok()?;

        // Simple JSON parsing without external dependencies
        let height = Self::extract_u64(s, "height")?;
        let block_hash_hex = Self::extract_string(s, "block_hash")?;
        let created_at_unix_ms = Self::extract_u64(s, "created_at_unix_ms")?;
        let chain_id = Self::extract_u64(s, "chain_id")?;
        let epoch = match Self::extract_optional_u64(s, "epoch") {
            Ok(opt) => opt,
            // Malformed epoch field (key present, value not a clean u64
            // literal). Fail closed — Run 097 must not silently treat
            // an unreadable epoch as absent.
            Err(_) => return None,
        };
        // Run 117: additive authority-state block. Absent → `None`
        // (pre-Run-117 snapshot, parses cleanly). Present but
        // malformed → `None` returned from this function (fail-closed
        // on the parse path so `validate_snapshot_dir` surfaces
        // `MissingMetadata`). Missing authority state MUST NOT be
        // silently coerced to a synthetic empty/permissive state.
        let authority_state = match Self::extract_optional_authority_state(s) {
            Ok(opt) => opt,
            Err(_) => return None,
        };
        // Run 140: additive v2 authority-state block. Absent → `None`
        // (pre-Run-140 snapshot). Present but malformed → `None`
        // returned from this function (fail-closed on the parse path so
        // `validate_snapshot_dir` surfaces `MissingMetadata`).
        let authority_state_v2 = match Self::extract_optional_authority_state_v2(s) {
            Ok(opt) => opt,
            Err(_) => return None,
        };

        // Parse block hash from hex
        if block_hash_hex.len() != 64 {
            return None;
        }
        let mut block_hash = [0u8; 32];
        for (i, chunk) in block_hash_hex.as_bytes().chunks(2).enumerate() {
            let hex_str = std::str::from_utf8(chunk).ok()?;
            block_hash[i] = u8::from_str_radix(hex_str, 16).ok()?;
        }

        Some(Self {
            height,
            block_hash,
            created_at_unix_ms,
            chain_id,
            epoch,
            authority_state,
            authority_state_v2,
        })
    }

    /// Run 117: extract the optional additive `"authority_state"`
    /// JSON object.
    ///
    /// Returns:
    /// - `Ok(None)` when the key is absent (pre-Run-117 snapshot;
    ///   additive backward compatibility).
    /// - `Ok(Some(meta))` when the key is present and every
    ///   required sub-field parses cleanly.
    /// - `Err(())` when the key is present but the value is not a
    ///   structurally valid authority-state object (missing field,
    ///   malformed, non-object, etc.). The caller MUST fail closed —
    ///   Run 117 does not silently downgrade a malformed
    ///   authority-state block to `None`.
    fn extract_optional_authority_state(s: &str) -> Result<Option<AuthorityStateSnapshotMeta>, ()> {
        let key_pattern = "\"authority_state\":";
        let Some(start) = s.find(key_pattern) else {
            return Ok(None);
        };
        let after_key = &s[start + key_pattern.len()..];
        let after_key = after_key.trim_start();
        // Forward compatibility: explicit `null` is treated as absent.
        if after_key.starts_with("null") {
            return Ok(None);
        }
        if !after_key.starts_with('{') {
            return Err(());
        }
        // Find the matching closing brace (simple depth counter; the
        // authority-state block does not contain nested objects in
        // the Run 117 schema).
        let bytes = after_key.as_bytes();
        let mut depth: i32 = 0;
        let mut end_idx: Option<usize> = None;
        for (i, &b) in bytes.iter().enumerate() {
            match b {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end_idx = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let end = end_idx.ok_or(())?;
        let block = &after_key[..=end];

        let chain_id_hex = Self::extract_string(block, "chain_id_hex").ok_or(())?;
        let environment = Self::extract_string(block, "environment").ok_or(())?;
        let genesis_hash_hex = Self::extract_string(block, "genesis_hash_hex").ok_or(())?;
        let authority_policy_version =
            Self::extract_u64(block, "authority_policy_version").ok_or(())?;
        if authority_policy_version > u32::MAX as u64 {
            return Err(());
        }
        let authority_policy_version = authority_policy_version as u32;
        let authority_sequence = Self::extract_u64(block, "authority_sequence").ok_or(())?;
        let authority_epoch = Self::extract_optional_u64(block, "authority_epoch")?;
        let authority_root_fingerprint =
            Self::extract_string(block, "authority_root_fingerprint").ok_or(())?;
        let ratified_bundle_signing_key_fingerprint =
            Self::extract_string(block, "ratified_bundle_signing_key_fingerprint").ok_or(())?;
        let ratification_object_hash =
            Self::extract_string(block, "ratification_object_hash").ok_or(())?;

        // Structural sanity. Run 117 deliberately fails closed on any
        // shape violation so the snapshot is not silently accepted
        // with a corrupted authority block.
        if chain_id_hex.len() != 16 || !Self::is_lower_hex_ascii(&chain_id_hex) {
            return Err(());
        }
        if genesis_hash_hex.len() != 64 || !Self::is_lower_hex_ascii(&genesis_hash_hex) {
            return Err(());
        }
        if ratification_object_hash.len() != 64
            || !Self::is_lower_hex_ascii(&ratification_object_hash)
        {
            return Err(());
        }
        if !matches!(environment.as_str(), "devnet" | "testnet" | "mainnet") {
            return Err(());
        }
        if authority_policy_version == 0 {
            return Err(());
        }
        if authority_root_fingerprint.is_empty()
            || !Self::is_lower_hex_ascii(&authority_root_fingerprint)
        {
            return Err(());
        }
        if ratified_bundle_signing_key_fingerprint.is_empty()
            || !Self::is_lower_hex_ascii(&ratified_bundle_signing_key_fingerprint)
        {
            return Err(());
        }

        Ok(Some(AuthorityStateSnapshotMeta {
            chain_id_hex,
            environment,
            genesis_hash_hex,
            authority_policy_version,
            authority_sequence,
            authority_epoch,
            authority_root_fingerprint,
            ratified_bundle_signing_key_fingerprint,
            ratification_object_hash,
        }))
    }

    /// Run 140: extract the optional additive `"authority_state_v2"`
    /// JSON object.
    ///
    /// Returns:
    /// - `Ok(None)` when the key is absent (pre-Run-140 snapshot;
    ///   additive backward compatibility).
    /// - `Ok(Some(meta))` when the key is present and every required
    ///   sub-field parses cleanly.
    /// - `Err(())` when the key is present but the value is not a
    ///   structurally valid v2 authority-state object. The caller MUST
    ///   fail closed — Run 140 does not silently downgrade a malformed
    ///   v2 authority-state block to `None`.
    fn extract_optional_authority_state_v2(
        s: &str,
    ) -> Result<Option<AuthorityStateSnapshotMetaV2>, ()> {
        let key_pattern = "\"authority_state_v2\":";
        let Some(start) = s.find(key_pattern) else {
            return Ok(None);
        };
        let after_key = &s[start + key_pattern.len()..];
        let after_key = after_key.trim_start();
        if after_key.starts_with("null") {
            return Ok(None);
        }
        if !after_key.starts_with('{') {
            return Err(());
        }
        let bytes = after_key.as_bytes();
        let mut depth: i32 = 0;
        let mut end_idx: Option<usize> = None;
        for (i, &b) in bytes.iter().enumerate() {
            match b {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end_idx = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let end = end_idx.ok_or(())?;
        let block = &after_key[..=end];

        let chain_id_hex = Self::extract_string(block, "chain_id_hex").ok_or(())?;
        let environment = Self::extract_string(block, "environment").ok_or(())?;
        let genesis_hash_hex = Self::extract_string(block, "genesis_hash_hex").ok_or(())?;
        let authority_root_fingerprint =
            Self::extract_string(block, "authority_root_fingerprint").ok_or(())?;
        let authority_root_suite_id =
            Self::extract_u64(block, "authority_root_suite_id").ok_or(())?;
        if authority_root_suite_id > u8::MAX as u64 {
            return Err(());
        }
        let authority_root_suite_id = authority_root_suite_id as u8;
        let active_bundle_signing_key_fingerprint =
            Self::extract_string(block, "active_bundle_signing_key_fingerprint").ok_or(())?;
        let active_bundle_signing_key_suite_id =
            Self::extract_u64(block, "active_bundle_signing_key_suite_id").ok_or(())?;
        if active_bundle_signing_key_suite_id > u8::MAX as u64 {
            return Err(());
        }
        let active_bundle_signing_key_suite_id = active_bundle_signing_key_suite_id as u8;
        let latest_authority_domain_sequence =
            Self::extract_u64(block, "latest_authority_domain_sequence").ok_or(())?;
        let latest_lifecycle_action_byte =
            Self::extract_u64(block, "latest_lifecycle_action_byte").ok_or(())?;
        if latest_lifecycle_action_byte > u8::MAX as u64 {
            return Err(());
        }
        let latest_lifecycle_action_byte = latest_lifecycle_action_byte as u8;
        let latest_ratification_v2_digest =
            Self::extract_string(block, "latest_ratification_v2_digest").ok_or(())?;
        let previous_bundle_signing_key_fingerprint =
            Self::extract_string(block, "previous_bundle_signing_key_fingerprint");
        let revoked_key_metadata = Self::extract_string(block, "revoked_key_metadata");

        // Structural sanity (defence-in-depth; the qbind-node side will
        // also run `PersistentAuthorityStateRecordV2::validate_structure`
        // before any restore decision is taken).
        if chain_id_hex.len() != 16 || !Self::is_lower_hex_ascii(&chain_id_hex) {
            return Err(());
        }
        if genesis_hash_hex.len() != 64 || !Self::is_lower_hex_ascii(&genesis_hash_hex) {
            return Err(());
        }
        if !matches!(environment.as_str(), "devnet" | "testnet" | "mainnet") {
            return Err(());
        }
        if authority_root_fingerprint.is_empty()
            || !Self::is_lower_hex_ascii(&authority_root_fingerprint)
        {
            return Err(());
        }
        if active_bundle_signing_key_fingerprint.is_empty()
            || !Self::is_lower_hex_ascii(&active_bundle_signing_key_fingerprint)
        {
            return Err(());
        }
        if latest_authority_domain_sequence == 0 {
            return Err(());
        }
        if latest_ratification_v2_digest.len() != 64
            || !Self::is_lower_hex_ascii(&latest_ratification_v2_digest)
        {
            return Err(());
        }
        if latest_lifecycle_action_byte > 2 {
            return Err(());
        }
        if let Some(prev) = previous_bundle_signing_key_fingerprint.as_ref() {
            if prev.is_empty() || !Self::is_lower_hex_ascii(prev) {
                return Err(());
            }
        }
        if let Some(rev) = revoked_key_metadata.as_ref() {
            if rev.is_empty() || !Self::is_lower_hex_ascii(rev) {
                return Err(());
            }
        }

        Ok(Some(AuthorityStateSnapshotMetaV2 {
            chain_id_hex,
            environment,
            genesis_hash_hex,
            authority_root_fingerprint,
            authority_root_suite_id,
            active_bundle_signing_key_fingerprint,
            active_bundle_signing_key_suite_id,
            latest_authority_domain_sequence,
            latest_lifecycle_action_byte,
            previous_bundle_signing_key_fingerprint,
            latest_ratification_v2_digest,
            revoked_key_metadata,
        }))
    }

    fn is_lower_hex_ascii(s: &str) -> bool {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    /// Extract a u64 value from JSON-like text.
    fn extract_u64(s: &str, key: &str) -> Option<u64> {
        let key_pattern = format!("\"{}\":", key);
        let start = s.find(&key_pattern)?;
        let value_start = start + key_pattern.len();
        let rest = &s[value_start..];
        let rest = rest.trim_start();

        // Find the end of the number (comma, newline, or closing brace)
        let end = rest.find([',', '\n', '}']).unwrap_or(rest.len());
        let num_str = rest[..end].trim();
        num_str.parse().ok()
    }

    /// Run 097: extract an *optional* u64 value from JSON-like text.
    ///
    /// Returns:
    /// - `Ok(None)` when the key is absent (additive compatibility
    ///   with pre-Run-097 snapshots).
    /// - `Ok(Some(n))` when the key is present and parses as a bare
    ///   u64 decimal literal.
    /// - `Err(())` when the key is present but the value is not a
    ///   valid u64 literal (malformed, quoted, negative, etc.). The
    ///   caller MUST fail closed — Run 097 does not silently downgrade
    ///   a malformed epoch field to `None`.
    fn extract_optional_u64(s: &str, key: &str) -> Result<Option<u64>, ()> {
        let key_pattern = format!("\"{}\":", key);
        let Some(start) = s.find(&key_pattern) else {
            return Ok(None);
        };
        let value_start = start + key_pattern.len();
        let rest = &s[value_start..];
        let rest = rest.trim_start();
        let end = rest.find([',', '\n', '}']).unwrap_or(rest.len());
        let num_str = rest[..end].trim();
        // Explicit `null` is treated as absent for forward compatibility.
        if num_str.eq_ignore_ascii_case("null") {
            return Ok(None);
        }
        match num_str.parse::<u64>() {
            Ok(n) => Ok(Some(n)),
            Err(_) => Err(()),
        }
    }

    /// Extract a string value from JSON-like text.
    fn extract_string(s: &str, key: &str) -> Option<String> {
        let key_pattern = format!("\"{}\":", key);
        let start = s.find(&key_pattern)?;
        let value_start = start + key_pattern.len();
        let rest = &s[value_start..];
        let rest = rest.trim_start();

        // Expect a quoted string
        if !rest.starts_with('"') {
            return None;
        }
        let rest = &rest[1..];
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    }
}

impl fmt::Display for StateSnapshotMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Snapshot(height={}, chain_id={:#x}, created={}ms)",
            self.height, self.chain_id, self.created_at_unix_ms
        )
    }
}

// ============================================================================
// Snapshot Errors
// ============================================================================

/// Error type for state snapshot operations (T215).
///
/// Categorizes errors into:
/// - Configuration/path errors
/// - IO errors
/// - Backend-specific errors (RocksDB)
/// - Validation errors
///
/// # Example
///
/// ```rust
/// use qbind_ledger::StateSnapshotError;
///
/// let err = StateSnapshotError::Io("permission denied".to_string());
/// assert!(err.to_string().contains("permission denied"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateSnapshotError {
    /// Configuration error (bad path, missing directory, permissions).
    ///
    /// This typically indicates operator error in specifying snapshot paths.
    Config(String),

    /// IO error during snapshot creation or restore.
    ///
    /// Examples: disk full, file not found, permission denied.
    Io(String),

    /// Backend-specific error (RocksDB checkpoint failure).
    ///
    /// This indicates an error in the underlying storage engine.
    Backend(String),

    /// Snapshot validation error.
    ///
    /// Examples: mismatched chain ID, corrupted metadata, missing files.
    Validation(String),

    /// Snapshot already exists at the target path.
    ///
    /// Prevents accidental overwriting of existing snapshots.
    AlreadyExists(String),
}

impl fmt::Display for StateSnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateSnapshotError::Config(msg) => write!(f, "snapshot config error: {}", msg),
            StateSnapshotError::Io(msg) => write!(f, "snapshot IO error: {}", msg),
            StateSnapshotError::Backend(msg) => write!(f, "snapshot backend error: {}", msg),
            StateSnapshotError::Validation(msg) => write!(f, "snapshot validation error: {}", msg),
            StateSnapshotError::AlreadyExists(path) => {
                write!(f, "snapshot already exists at: {}", path)
            }
        }
    }
}

impl std::error::Error for StateSnapshotError {}

// ============================================================================
// Snapshot Statistics
// ============================================================================

/// Statistics from a state snapshot operation (T215).
///
/// Captures telemetry data from a snapshot creation or restore,
/// useful for monitoring and performance tuning.
///
/// # Example
///
/// ```rust
/// use qbind_ledger::SnapshotStats;
/// use std::time::Duration;
///
/// let stats = SnapshotStats::new(
///     100_000,               // height
///     1024 * 1024 * 512,     // 512 MB size
///     Duration::from_secs(5) // 5 seconds
/// );
///
/// println!("Snapshot at height {} took {}ms", stats.height, stats.duration_ms);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SnapshotStats {
    /// Block height of the snapshot.
    pub height: u64,

    /// Approximate size of the snapshot in bytes.
    pub size_bytes: u64,

    /// Duration of the snapshot operation in milliseconds.
    pub duration_ms: u64,
}

impl SnapshotStats {
    /// Create new snapshot statistics.
    pub fn new(height: u64, size_bytes: u64, duration: Duration) -> Self {
        Self {
            height,
            size_bytes,
            duration_ms: duration.as_millis() as u64,
        }
    }

    /// Create snapshot statistics with duration in milliseconds.
    pub fn from_ms(height: u64, size_bytes: u64, duration_ms: u64) -> Self {
        Self {
            height,
            size_bytes,
            duration_ms,
        }
    }
}

impl fmt::Display for SnapshotStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let size_mb = self.size_bytes as f64 / (1024.0 * 1024.0);
        write!(
            f,
            "height={}, size={:.2}MB, duration={}ms",
            self.height, size_mb, self.duration_ms
        )
    }
}

// ============================================================================
// State Snapshotter Trait
// ============================================================================

/// Trait for state backends that support point-in-time snapshots (T215).
///
/// Implementations create logically consistent snapshots of account state
/// at a given block boundary. Snapshots are local-only and do not affect
/// consensus.
///
/// # Requirements
///
/// - Snapshot must be taken after a committed block (not mid-execution)
/// - All in-flight writes (memtable, WAL) must be flushed before snapshot
/// - Snapshot directory must not already exist
/// - Snapshot must be restorable to recreate the exact state
///
/// # Thread Safety
///
/// Implementations should be safe to call while reads/writes continue.
/// RocksDB checkpoints provide this guarantee by default.
///
/// # Example
///
/// ```rust,ignore
/// use qbind_ledger::{RocksDbAccountState, StateSnapshotter, StateSnapshotMeta};
/// use std::path::Path;
///
/// let storage = RocksDbAccountState::open(Path::new("/data/state"))?;
///
/// // Create metadata for height 100_000
/// let meta = StateSnapshotMeta {
///     height: 100_000,
///     block_hash: [0xAA; 32],
///     created_at_unix_ms: StateSnapshotMeta::now_unix_ms(),
///     chain_id: 0x51424E444D41494E,
///     epoch: None,
///     authority_state: None,
///     authority_state_v2: None,
/// };
///
/// // Create snapshot
/// let stats = storage.create_snapshot(&meta, Path::new("/data/snapshots/100000"))?;
/// println!("Snapshot created: {}", stats);
/// ```
pub trait StateSnapshotter {
    /// Create a point-in-time snapshot of the account state.
    ///
    /// # Arguments
    ///
    /// * `meta` - Snapshot metadata (height, block hash, chain ID)
    /// * `target_dir` - Directory to write snapshot files (must not exist)
    ///
    /// # Returns
    ///
    /// `Ok(SnapshotStats)` on success with statistics about the snapshot.
    /// `Err(StateSnapshotError)` on failure.
    ///
    /// # Errors
    ///
    /// - `Config`: Invalid target directory path
    /// - `AlreadyExists`: Target directory already exists
    /// - `Io`: File system errors
    /// - `Backend`: RocksDB checkpoint errors
    ///
    /// # Notes
    ///
    /// - Caller must ensure no block execution is in progress
    /// - WAL and memtable are flushed before checkpoint
    /// - Snapshot is atomic: either fully created or not at all
    fn create_snapshot(
        &self,
        meta: &StateSnapshotMeta,
        target_dir: &Path,
    ) -> Result<SnapshotStats, StateSnapshotError>;

    /// Estimate the current state size in bytes.
    ///
    /// Returns an approximate size of the state that would be captured
    /// in a snapshot. Useful for monitoring and capacity planning.
    ///
    /// # Returns
    ///
    /// `Some(size)` with estimated size in bytes.
    /// `None` if size cannot be determined.
    fn estimate_snapshot_size_bytes(&self) -> Option<u64>;
}

// ============================================================================
// Snapshot Validation
// ============================================================================

/// Result of validating a snapshot directory (T215).
///
/// Used by fast-sync to verify a snapshot before attempting restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotValidationResult {
    /// Snapshot is valid and can be restored.
    Valid(StateSnapshotMeta),

    /// Snapshot metadata is missing or corrupted.
    MissingMetadata(String),

    /// Snapshot state directory is missing or empty.
    MissingStateDir(String),

    /// Chain ID mismatch (snapshot from different network).
    ChainIdMismatch { expected: u64, actual: u64 },

    /// Snapshot height is invalid (e.g., zero or too old).
    InvalidHeight(u64),
}

impl fmt::Display for SnapshotValidationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotValidationResult::Valid(meta) => write!(f, "valid: {}", meta),
            SnapshotValidationResult::MissingMetadata(msg) => {
                write!(f, "missing metadata: {}", msg)
            }
            SnapshotValidationResult::MissingStateDir(msg) => {
                write!(f, "missing state dir: {}", msg)
            }
            SnapshotValidationResult::ChainIdMismatch { expected, actual } => {
                write!(
                    f,
                    "chain ID mismatch: expected {:#x}, got {:#x}",
                    expected, actual
                )
            }
            SnapshotValidationResult::InvalidHeight(h) => write!(f, "invalid height: {}", h),
        }
    }
}

/// Validate a snapshot directory for fast-sync restore (T215).
///
/// Checks that:
/// 1. `meta.json` exists and is parseable
/// 2. `state/` directory exists and is not empty
/// 3. Chain ID matches expected value
/// 4. Height is reasonable (> 0)
///
/// # Arguments
///
/// * `snapshot_dir` - Path to the snapshot directory
/// * `expected_chain_id` - The chain ID the node is configured for
///
/// # Returns
///
/// `SnapshotValidationResult` indicating validity or specific error.
///
/// # Example
///
/// ```rust,ignore
/// use qbind_ledger::validate_snapshot_dir;
///
/// let result = validate_snapshot_dir(
///     Path::new("/data/snapshots/100000"),
///     0x51424E444D41494E  // MainNet chain ID
/// );
///
/// match result {
///     SnapshotValidationResult::Valid(meta) => {
///         println!("Snapshot valid at height {}", meta.height);
///     }
///     other => {
///         eprintln!("Snapshot invalid: {}", other);
///     }
/// }
/// ```
pub fn validate_snapshot_dir(
    snapshot_dir: &Path,
    expected_chain_id: u64,
) -> SnapshotValidationResult {
    // Check meta.json exists
    let meta_path = snapshot_dir.join("meta.json");
    let meta_data = match std::fs::read(&meta_path) {
        Ok(data) => data,
        Err(e) => {
            return SnapshotValidationResult::MissingMetadata(format!(
                "cannot read meta.json: {}",
                e
            ));
        }
    };

    // Parse metadata
    let meta = match StateSnapshotMeta::from_json(&meta_data) {
        Some(m) => m,
        None => {
            return SnapshotValidationResult::MissingMetadata("cannot parse meta.json".to_string());
        }
    };

    // Check chain ID
    if meta.chain_id != expected_chain_id {
        return SnapshotValidationResult::ChainIdMismatch {
            expected: expected_chain_id,
            actual: meta.chain_id,
        };
    }

    // Check height is reasonable
    if meta.height == 0 {
        return SnapshotValidationResult::InvalidHeight(meta.height);
    }

    // Check state directory exists
    let state_dir = snapshot_dir.join("state");
    if !state_dir.exists() {
        return SnapshotValidationResult::MissingStateDir(
            "state/ directory does not exist".to_string(),
        );
    }

    // Check state directory is not empty
    match std::fs::read_dir(&state_dir) {
        Ok(mut entries) => {
            if entries.next().is_none() {
                return SnapshotValidationResult::MissingStateDir(
                    "state/ directory is empty".to_string(),
                );
            }
        }
        Err(e) => {
            return SnapshotValidationResult::MissingStateDir(format!(
                "cannot read state/ directory: {}",
                e
            ));
        }
    }

    SnapshotValidationResult::Valid(meta)
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_meta_new() {
        let meta = StateSnapshotMeta::new(100, [0xAA; 32], 1700000000000, 0x1234);
        assert_eq!(meta.height, 100);
        assert_eq!(meta.block_hash, [0xAA; 32]);
        assert_eq!(meta.created_at_unix_ms, 1700000000000);
        assert_eq!(meta.chain_id, 0x1234);
        // Run 097: new() must default epoch to None (explicit absence,
        // not silently coerced to 0).
        assert_eq!(meta.epoch, None);
    }

    #[test]
    fn test_snapshot_meta_json_roundtrip() {
        let meta = StateSnapshotMeta {
            height: 100_000,
            block_hash: [0xAB; 32],
            created_at_unix_ms: 1700000000000,
            chain_id: 0x51424E444D41494E,
            epoch: None,
            authority_state: None,
            authority_state_v2: None,
        };

        let json = meta.to_json();
        let parsed = StateSnapshotMeta::from_json(&json).expect("should parse");

        assert_eq!(parsed.height, meta.height);
        assert_eq!(parsed.block_hash, meta.block_hash);
        assert_eq!(parsed.created_at_unix_ms, meta.created_at_unix_ms);
        assert_eq!(parsed.chain_id, meta.chain_id);
        assert_eq!(parsed.epoch, None);
    }

    #[test]
    fn test_snapshot_meta_from_json_invalid() {
        assert!(StateSnapshotMeta::from_json(b"not json").is_none());
        assert!(StateSnapshotMeta::from_json(b"{}").is_none());
        assert!(StateSnapshotMeta::from_json(b"{\"height\": 100}").is_none());
    }

    #[test]
    fn test_snapshot_meta_display() {
        let meta = StateSnapshotMeta::new(100, [0; 32], 1700000000000, 0x1234);
        let s = format!("{}", meta);
        assert!(s.contains("height=100"));
        assert!(s.contains("chain_id=0x1234"));
    }

    #[test]
    fn test_snapshot_error_display() {
        let err = StateSnapshotError::Config("bad path".to_string());
        assert!(err.to_string().contains("config error"));
        assert!(err.to_string().contains("bad path"));

        let err = StateSnapshotError::Io("disk full".to_string());
        assert!(err.to_string().contains("IO error"));

        let err = StateSnapshotError::Backend("checkpoint failed".to_string());
        assert!(err.to_string().contains("backend error"));

        let err = StateSnapshotError::Validation("corrupted".to_string());
        assert!(err.to_string().contains("validation error"));

        let err = StateSnapshotError::AlreadyExists("/data/snap".to_string());
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn test_snapshot_stats_new() {
        let stats = SnapshotStats::new(100, 1024 * 1024, std::time::Duration::from_millis(500));
        assert_eq!(stats.height, 100);
        assert_eq!(stats.size_bytes, 1024 * 1024);
        assert_eq!(stats.duration_ms, 500);
    }

    #[test]
    fn test_snapshot_stats_from_ms() {
        let stats = SnapshotStats::from_ms(200, 2048, 100);
        assert_eq!(stats.height, 200);
        assert_eq!(stats.size_bytes, 2048);
        assert_eq!(stats.duration_ms, 100);
    }

    #[test]
    fn test_snapshot_stats_display() {
        let stats = SnapshotStats::new(100, 1024 * 1024, std::time::Duration::from_millis(500));
        let s = format!("{}", stats);
        assert!(s.contains("height=100"));
        assert!(s.contains("duration=500ms"));
    }

    #[test]
    fn test_validation_result_display() {
        let meta = StateSnapshotMeta::new(100, [0; 32], 1700000000000, 0x1234);
        let r = SnapshotValidationResult::Valid(meta);
        assert!(format!("{}", r).contains("valid"));

        let r = SnapshotValidationResult::MissingMetadata("test".to_string());
        assert!(format!("{}", r).contains("missing metadata"));

        let r = SnapshotValidationResult::ChainIdMismatch {
            expected: 1,
            actual: 2,
        };
        assert!(format!("{}", r).contains("chain ID mismatch"));
    }

    #[test]
    fn test_now_unix_ms() {
        let ts = StateSnapshotMeta::now_unix_ms();
        // Should be a reasonable recent timestamp (after year 2020)
        assert!(ts > 1577836800000); // 2020-01-01 00:00:00 UTC
    }

    // ========================================================================
    // Run 097 — additive snapshot epoch parity unit tests
    // ========================================================================

    /// Run 097: a snapshot meta with `epoch: Some(n)` serializes the epoch
    /// field into JSON and round-trips losslessly.
    #[test]
    fn run097_epoch_some_serializes_and_round_trips() {
        let meta = StateSnapshotMeta::new(100, [0x33; 32], 1700000000000, 0xC1).with_epoch(Some(7));
        let json = meta.to_json();
        let json_str = std::str::from_utf8(&json).unwrap();
        assert!(
            json_str.contains("\"epoch\": 7"),
            "epoch field must be emitted when Some: {json_str}"
        );
        let parsed = StateSnapshotMeta::from_json(&json).expect("parses");
        assert_eq!(parsed.epoch, Some(7));
        assert_eq!(parsed.height, 100);
        assert_eq!(parsed.chain_id, 0xC1);
    }

    /// Run 097: `epoch: None` MUST omit the field entirely so pre-Run-097
    /// parsers still accept the snapshot unchanged.
    #[test]
    fn run097_epoch_none_omits_field_for_backward_compatibility() {
        let meta = StateSnapshotMeta::new(100, [0x33; 32], 1700000000000, 0xC1);
        let json = meta.to_json();
        let json_str = std::str::from_utf8(&json).unwrap();
        assert!(
            !json_str.contains("epoch"),
            "epoch field must be omitted when None: {json_str}"
        );
        let parsed = StateSnapshotMeta::from_json(&json).expect("parses");
        assert_eq!(parsed.epoch, None);
    }

    /// Run 097: an old (pre-Run-097) snapshot JSON without `epoch`
    /// continues to parse cleanly and yields `epoch: None`. This is
    /// the explicit additive backward-compatibility contract.
    #[test]
    fn run097_old_snapshot_without_epoch_parses_as_none() {
        let legacy = b"{\n  \"height\": 5,\n  \"block_hash\": \"\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            \",\n  \"created_at_unix_ms\": 1700000000000,\n  \"chain_id\": 99\n}";
        let parsed = StateSnapshotMeta::from_json(legacy).expect("legacy parses");
        assert_eq!(parsed.epoch, None, "missing epoch must NOT be Some(0)");
        assert_eq!(parsed.height, 5);
        assert_eq!(parsed.chain_id, 99);
    }

    /// Run 097: an explicit `"epoch": 0` is a *committed-epoch-0* signal,
    /// not "no epoch". It must round-trip as `Some(0)`. This is the
    /// invariant Run 091/092 require so that absence cannot be silently
    /// conflated with a real CommittedEpoch(0).
    #[test]
    fn run097_epoch_zero_is_some_zero_not_none() {
        let meta = StateSnapshotMeta::new(1, [0; 32], 1700000000000, 1).with_epoch(Some(0));
        let json = meta.to_json();
        let json_str = std::str::from_utf8(&json).unwrap();
        assert!(json_str.contains("\"epoch\": 0"));
        let parsed = StateSnapshotMeta::from_json(&json).unwrap();
        assert_eq!(parsed.epoch, Some(0));
        assert_ne!(parsed.epoch, None);
    }

    /// Run 097: a malformed `epoch` value (non-numeric) fails closed —
    /// `from_json` returns `None` and downstream validation reports
    /// `MissingMetadata`. Run 097 does NOT silently downgrade a
    /// malformed epoch field to `None`.
    #[test]
    fn run097_malformed_epoch_fails_closed() {
        let bad_quoted = b"{\n  \"height\": 5,\n  \"block_hash\": \"\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            \",\n  \"created_at_unix_ms\": 1700000000000,\n  \"chain_id\": 99,\
            \n  \"epoch\": \"7\"\n}";
        assert!(
            StateSnapshotMeta::from_json(bad_quoted).is_none(),
            "quoted epoch must fail closed"
        );

        let bad_negative = b"{\n  \"height\": 5,\n  \"block_hash\": \"\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            \",\n  \"created_at_unix_ms\": 1700000000000,\n  \"chain_id\": 99,\
            \n  \"epoch\": -1\n}";
        assert!(
            StateSnapshotMeta::from_json(bad_negative).is_none(),
            "negative epoch must fail closed"
        );

        let bad_garbage = b"{\n  \"height\": 5,\n  \"block_hash\": \"\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            \",\n  \"created_at_unix_ms\": 1700000000000,\n  \"chain_id\": 99,\
            \n  \"epoch\": notanumber\n}";
        assert!(
            StateSnapshotMeta::from_json(bad_garbage).is_none(),
            "garbage epoch must fail closed"
        );
    }

    /// Run 097: explicit `"epoch": null` is treated as absence (forward
    /// compatibility with future serializers that may choose to keep
    /// the key but emit `null`). It is **not** an error.
    #[test]
    fn run097_epoch_explicit_null_is_treated_as_absent() {
        let payload = b"{\n  \"height\": 5,\n  \"block_hash\": \"\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            \",\n  \"created_at_unix_ms\": 1700000000000,\n  \"chain_id\": 99,\
            \n  \"epoch\": null\n}";
        let parsed = StateSnapshotMeta::from_json(payload).expect("null epoch parses");
        assert_eq!(parsed.epoch, None);
    }

    /// Run 097: serialization of a Run-097 snapshot with `epoch=Some(n)`
    /// is deterministic — repeated `to_json` calls produce byte-identical
    /// output.
    #[test]
    fn run097_serialization_is_deterministic() {
        let meta = StateSnapshotMeta::new(7, [0x42; 32], 1700000000000, 0xA).with_epoch(Some(11));
        let j1 = meta.to_json();
        let j2 = meta.to_json();
        assert_eq!(j1, j2);

        let meta2 = StateSnapshotMeta::new(7, [0x42; 32], 1700000000000, 0xA);
        let j3 = meta2.to_json();
        let j4 = meta2.to_json();
        assert_eq!(j3, j4);
    }

    /// Run 097: the epoch field MUST NOT be inferred from height by the
    /// metadata layer. Constructing meta with `height=100, epoch=None`
    /// must produce JSON that does not embed `100` as the epoch and
    /// must round-trip back to `epoch=None`.
    #[test]
    fn run097_epoch_is_not_derived_from_height() {
        let meta = StateSnapshotMeta::new(100, [0; 32], 1700000000000, 1);
        assert_eq!(meta.epoch, None);
        let json = meta.to_json();
        let parsed = StateSnapshotMeta::from_json(&json).unwrap();
        assert_eq!(parsed.epoch, None);
        assert_eq!(parsed.height, 100);
    }

    // ========================================================================
    // Run 117 — additive snapshot authority-state parity unit tests
    // ========================================================================

    fn sample_authority_state() -> AuthorityStateSnapshotMeta {
        AuthorityStateSnapshotMeta {
            chain_id_hex: "0000000000000001".to_string(),
            environment: "devnet".to_string(),
            genesis_hash_hex: "a".repeat(64),
            authority_policy_version: 1,
            authority_sequence: 7,
            authority_epoch: Some(3),
            authority_root_fingerprint: "b".repeat(40),
            ratified_bundle_signing_key_fingerprint: "c".repeat(40),
            ratification_object_hash: "d".repeat(64),
        }
    }

    /// Run 117: a snapshot meta with `authority_state: Some(_)` emits
    /// the authority_state JSON block and round-trips losslessly.
    #[test]
    fn run117_authority_state_some_serializes_and_round_trips() {
        let auth = sample_authority_state();
        let meta = StateSnapshotMeta::new(100, [0x33; 32], 1700000000000, 0xC1)
            .with_authority_state(Some(auth.clone()));
        let json = meta.to_json();
        let json_str = std::str::from_utf8(&json).unwrap();
        assert!(
            json_str.contains("\"authority_state\":"),
            "authority_state block must be emitted when Some: {json_str}"
        );
        assert!(json_str.contains("\"authority_sequence\": 7"));
        assert!(json_str.contains("\"authority_epoch\": 3"));
        assert!(json_str.contains("\"environment\": \"devnet\""));

        let parsed = StateSnapshotMeta::from_json(&json).expect("parses");
        assert_eq!(parsed.authority_state, Some(auth));
        assert_eq!(parsed.height, 100);
        assert_eq!(parsed.chain_id, 0xC1);
    }

    /// Run 117: `authority_state: None` MUST omit the field entirely
    /// so pre-Run-117 parsers still accept the snapshot unchanged.
    #[test]
    fn run117_authority_state_none_omits_field_for_backward_compatibility() {
        let meta = StateSnapshotMeta::new(100, [0x33; 32], 1700000000000, 0xC1);
        let json = meta.to_json();
        let json_str = std::str::from_utf8(&json).unwrap();
        assert!(
            !json_str.contains("authority_state"),
            "authority_state field must be omitted when None: {json_str}"
        );
        let parsed = StateSnapshotMeta::from_json(&json).expect("parses");
        assert_eq!(parsed.authority_state, None);
    }

    /// Run 117: an old (pre-Run-117) snapshot JSON without
    /// `authority_state` continues to parse cleanly and yields
    /// `authority_state: None`. This is the explicit additive
    /// backward-compatibility contract.
    #[test]
    fn run117_old_snapshot_without_authority_state_parses_as_none() {
        let legacy = b"{\n  \"height\": 5,\n  \"block_hash\": \"\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            \",\n  \"created_at_unix_ms\": 1700000000000,\n  \"chain_id\": 99\n}";
        let parsed = StateSnapshotMeta::from_json(legacy).expect("legacy parses");
        assert_eq!(parsed.authority_state, None);
        assert_eq!(parsed.epoch, None);
        assert_eq!(parsed.height, 5);
    }

    /// Run 117: a legacy snapshot carrying only `epoch` (Run 097
    /// vintage) still parses cleanly with `authority_state: None`,
    /// preserving the Run 097 contract.
    #[test]
    fn run117_run097_snapshot_with_epoch_only_parses_with_authority_none() {
        let legacy = b"{\n  \"height\": 5,\n  \"block_hash\": \"\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            \",\n  \"created_at_unix_ms\": 1700000000000,\n  \"chain_id\": 99,\
            \n  \"epoch\": 11\n}";
        let parsed = StateSnapshotMeta::from_json(legacy).expect("run097 snapshot parses");
        assert_eq!(parsed.epoch, Some(11));
        assert_eq!(parsed.authority_state, None);
    }

    /// Run 117: explicit `"authority_state": null` is treated as
    /// absence (forward compatibility with future serializers).
    #[test]
    fn run117_authority_state_explicit_null_is_treated_as_absent() {
        let payload = b"{\n  \"height\": 5,\n  \"block_hash\": \"\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            \",\n  \"created_at_unix_ms\": 1700000000000,\n  \"chain_id\": 99,\
            \n  \"authority_state\": null\n}";
        let parsed = StateSnapshotMeta::from_json(payload).expect("null authority_state parses");
        assert_eq!(parsed.authority_state, None);
    }

    /// Run 117: a malformed authority_state block (missing required
    /// field) fails closed — `from_json` returns `None` so downstream
    /// validation reports `MissingMetadata`. Run 117 does NOT silently
    /// downgrade a malformed authority block to `None`.
    #[test]
    fn run117_malformed_authority_state_fails_closed() {
        // Missing `ratification_object_hash`.
        let bad = b"{\n  \"height\": 5,\n  \"block_hash\": \"\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            \",\n  \"created_at_unix_ms\": 1700000000000,\n  \"chain_id\": 99,\
            \n  \"authority_state\": {\n    \"chain_id_hex\": \"0000000000000001\",\
            \n    \"environment\": \"devnet\",\
            \n    \"genesis_hash_hex\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\
            \n    \"authority_policy_version\": 1,\
            \n    \"authority_sequence\": 5,\
            \n    \"authority_root_fingerprint\": \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\
            \n    \"ratified_bundle_signing_key_fingerprint\": \"cccccccccccccccccccccccccccccccccccccccc\"\
            \n  }\n}";
        assert!(
            StateSnapshotMeta::from_json(bad).is_none(),
            "missing field must fail closed"
        );

        // Wrong environment tag.
        let bad_env = b"{\n  \"height\": 5,\n  \"block_hash\": \"\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            \",\n  \"created_at_unix_ms\": 1700000000000,\n  \"chain_id\": 99,\
            \n  \"authority_state\": {\n    \"chain_id_hex\": \"0000000000000001\",\
            \n    \"environment\": \"hacknet\",\
            \n    \"genesis_hash_hex\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\
            \n    \"authority_policy_version\": 1,\
            \n    \"authority_sequence\": 5,\
            \n    \"authority_root_fingerprint\": \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\
            \n    \"ratified_bundle_signing_key_fingerprint\": \"cccccccccccccccccccccccccccccccccccccccc\",\
            \n    \"ratification_object_hash\": \"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\"\
            \n  }\n}";
        assert!(
            StateSnapshotMeta::from_json(bad_env).is_none(),
            "unknown environment tag must fail closed"
        );

        // Wrong-length genesis_hash_hex.
        let bad_genesis = b"{\n  \"height\": 5,\n  \"block_hash\": \"\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            \",\n  \"created_at_unix_ms\": 1700000000000,\n  \"chain_id\": 99,\
            \n  \"authority_state\": {\n    \"chain_id_hex\": \"0000000000000001\",\
            \n    \"environment\": \"devnet\",\
            \n    \"genesis_hash_hex\": \"aaaa\",\
            \n    \"authority_policy_version\": 1,\
            \n    \"authority_sequence\": 5,\
            \n    \"authority_root_fingerprint\": \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\
            \n    \"ratified_bundle_signing_key_fingerprint\": \"cccccccccccccccccccccccccccccccccccccccc\",\
            \n    \"ratification_object_hash\": \"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\"\
            \n  }\n}";
        assert!(
            StateSnapshotMeta::from_json(bad_genesis).is_none(),
            "short genesis_hash must fail closed"
        );
    }

    /// Run 117: an `authority_state` block with `authority_epoch`
    /// **absent** parses as `Some(meta { authority_epoch: None })`
    /// — this is the explicit absence semantic, not a synthetic `0`.
    #[test]
    fn run117_authority_state_with_no_authority_epoch_parses_as_none() {
        let mut auth = sample_authority_state();
        auth.authority_epoch = None;
        let meta = StateSnapshotMeta::new(7, [0x42; 32], 1700000000000, 0xA)
            .with_authority_state(Some(auth.clone()));
        let json = meta.to_json();
        let parsed = StateSnapshotMeta::from_json(&json).expect("parses");
        assert_eq!(
            parsed.authority_state.as_ref().unwrap().authority_epoch,
            None
        );
        assert_eq!(parsed.authority_state, Some(auth));
    }

    /// Run 117: serialization of a Run-117 snapshot with
    /// `authority_state=Some(...)` is deterministic — repeated
    /// `to_json` calls produce byte-identical output.
    #[test]
    fn run117_authority_state_serialization_is_deterministic() {
        let meta = StateSnapshotMeta::new(7, [0x42; 32], 1700000000000, 0xA)
            .with_authority_state(Some(sample_authority_state()))
            .with_epoch(Some(11));
        let j1 = meta.to_json();
        let j2 = meta.to_json();
        assert_eq!(j1, j2);
    }

    /// Run 117: authority_state and epoch are independently
    /// additive. A snapshot may carry `epoch=Some, authority_state=None`,
    /// `epoch=None, authority_state=Some`, both, or neither, and
    /// each combination round-trips losslessly.
    #[test]
    fn run117_epoch_and_authority_state_are_independent() {
        // Both None.
        let m = StateSnapshotMeta::new(1, [0; 32], 0, 1);
        let p = StateSnapshotMeta::from_json(&m.to_json()).unwrap();
        assert_eq!(p.epoch, None);
        assert_eq!(p.authority_state, None);

        // Epoch only.
        let m = StateSnapshotMeta::new(1, [0; 32], 0, 1).with_epoch(Some(2));
        let p = StateSnapshotMeta::from_json(&m.to_json()).unwrap();
        assert_eq!(p.epoch, Some(2));
        assert_eq!(p.authority_state, None);

        // Authority only.
        let m = StateSnapshotMeta::new(1, [0; 32], 0, 1)
            .with_authority_state(Some(sample_authority_state()));
        let p = StateSnapshotMeta::from_json(&m.to_json()).unwrap();
        assert_eq!(p.epoch, None);
        assert_eq!(p.authority_state, Some(sample_authority_state()));

        // Both.
        let m = StateSnapshotMeta::new(1, [0; 32], 0, 1)
            .with_epoch(Some(2))
            .with_authority_state(Some(sample_authority_state()));
        let p = StateSnapshotMeta::from_json(&m.to_json()).unwrap();
        assert_eq!(p.epoch, Some(2));
        assert_eq!(p.authority_state, Some(sample_authority_state()));
    }
}
