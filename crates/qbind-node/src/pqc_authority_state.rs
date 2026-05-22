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
    canonical_ratification_digest, BundleSigningRatification, RatifiedBundleSigningKey,
};
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
    if inputs.runtime_genesis_hash_hex.len() != 64
        || !is_lower_hex(inputs.runtime_genesis_hash_hex)
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

    if inputs.ratification.authority_root_fingerprint
        != inputs.ratified.authority_root_fingerprint
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

    // -------- Run 118: marker derivation tests --------

    mod run118 {
        use super::*;
        use qbind_crypto::MlDsa44Backend;
        use qbind_ledger::bundle_signing_ratification::test_helpers as ratification_helpers;
        use qbind_ledger::{
            pqc_public_key_fingerprint, RatificationEnvironment,
        };

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
            assert_eq!(r1.ratified_bundle_signing_key_fingerprint, f.ratified.fingerprint);
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
            let f_dev =
                build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            let f_main =
                build_verified_fixture(RatificationEnvironment::Mainnet, "0000000000000001");
            let r_dev =
                derive_authority_state_from_ratification(devnet_inputs(&f_dev, 5)).unwrap();
            let mut inputs_main = devnet_inputs(&f_main, 5);
            inputs_main.runtime_env = NetworkEnvironment::Mainnet;
            let r_main =
                derive_authority_state_from_ratification(inputs_main).unwrap();
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
            assert_eq!(r_a.authority_root_fingerprint, r_b.authority_root_fingerprint);
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
                Err(AuthorityStateDerivationError::MalformedRuntimeGenesisHash(_))
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
            let cand =
                derive_authority_state_from_ratification(devnet_inputs(&f, 5)).unwrap();
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
            let cand =
                derive_authority_state_from_ratification(devnet_inputs(&f, 5)).unwrap();
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
            assert_eq!(outcome, AuthorityStatePrepareOutcome::AlreadyPersistedIdempotent);
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
            let prev =
                derive_authority_state_from_ratification(devnet_inputs(&f_a, 5)).unwrap();
            persist_authority_state_atomic(&path, &prev).unwrap();
            let cand =
                derive_authority_state_from_ratification(devnet_inputs(&f_b, 5)).unwrap();
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
            let f_dev =
                build_verified_fixture(RatificationEnvironment::Devnet, "0000000000000001");
            let cand =
                derive_authority_state_from_ratification(devnet_inputs(&f_dev, 5)).unwrap();
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
            let cand =
                derive_authority_state_from_ratification(devnet_inputs(&f, 5)).unwrap();
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
            let cand =
                derive_authority_state_from_ratification(devnet_inputs(&f, 5)).unwrap();
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
            assert!(
                !AuthorityStatePrepareOutcome::AlreadyPersistedIdempotent.should_persist()
            );

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
}