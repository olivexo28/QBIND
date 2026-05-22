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

use qbind_types::{ChainId, NetworkEnvironment};

use crate::pqc_trust_bundle::TrustBundleEnvironment;

/// Domain-separation tag for the canonical authority-state digest
/// preimage. Mirrors the project convention `QBIND:<SUBJECT>:vN`
/// (cf. `QBIND:GENESIS:v1`, `QBIND:BUNDLE-SIGNING-RATIFICATION:v1`).
/// Bumping the trailing `v1` invalidates every previously computed
/// authority-state digest.
pub const AUTHORITY_STATE_DOMAIN_V1: &[u8] = b"QBIND:AUTHORITY-STATE:v1";

/// Current `record_version` for the persisted authority-state file.
/// Any other value fails closed.
pub const AUTHORITY_STATE_RECORD_VERSION: u32 = 1;

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
pub fn canonical_authority_state_preimage(
    r: &PersistentAuthorityStateRecord,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        AUTHORITY_STATE_DOMAIN_V1.len()
            + 4
            + 4 + r.chain_id.len()
            + 4 + r.environment.as_tag().len()
            + 4 + r.genesis_hash.len()
            + 4
            + 8
            + 1
            + 8
            + 4 + r.authority_root_fingerprint.len()
            + 4 + r.ratified_bundle_signing_key_fingerprint.len()
            + 4 + r.ratification_object_hash.len(),
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
pub fn canonical_authority_state_digest(
    r: &PersistentAuthorityStateRecord,
) -> [u8; 32] {
    qbind_hash::sha3_256(&canonical_authority_state_preimage(r))
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
        let same_root = prev.authority_root_fingerprint
            == candidate.authority_root_fingerprint;
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
                persisted_key_fingerprint: prev
                    .ratified_bundle_signing_key_fingerprint
                    .clone(),
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
    record
        .validate_structure()
        .map_err(|e| AuthorityStateError::PersistFailure(format!("pre-write structural validation: {}", e)))?;
    let bytes = serde_json::to_vec(record).map_err(|e| {
        AuthorityStateError::PersistFailure(format!("serialise: {}", e))
    })?;
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
            other => panic!(
                "expected SameSequenceConflictingHash, got {:?}",
                other
            ),
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
        validate_record_for_domain(
            &r,
            NetworkEnvironment::Devnet,
            ChainId(1),
            &"a".repeat(64),
        )
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
        let err = validate_record_for_domain(
            &r,
            NetworkEnvironment::Devnet,
            ChainId(2),
            &"a".repeat(64),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            AuthorityStateComparison::ChainMismatch { .. }
        ));
    }

    #[test]
    fn validate_record_for_domain_rejects_wrong_genesis() {
        let r = sample_record();
        let err = validate_record_for_domain(
            &r,
            NetworkEnvironment::Devnet,
            ChainId(1),
            &"e".repeat(64),
        )
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
        assert!(loaded.is_none(), "missing file must surface as None (explicit absence)");
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
}