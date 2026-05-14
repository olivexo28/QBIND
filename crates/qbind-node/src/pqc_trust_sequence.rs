//! Run 055 (C4 piece: PQC trust-bundle anti-rollback persistence):
//! persistent, atomic record of the highest signed trust-bundle
//! sequence number accepted by this node for a given
//! (environment, chain_id) trust domain.
//!
//! # Purpose
//!
//! Prevent rollback to an older signed trust bundle after a node has
//! already accepted a newer trust bundle for the same chain/environment
//! trust domain. The Run 050/051/053 trust-bundle layer carries a
//! monotonic `sequence: u64` in its canonical envelope; without
//! persistence, a restarted node would happily re-accept an older
//! signed bundle from disk (replay) and silently undo a freshly
//! distributed rotation. This module persists the highest accepted
//! `sequence` for the local trust domain and rejects any subsequent
//! bundle whose sequence is strictly lower than the persisted value.
//!
//! # Strict scope (anti-rollback only)
//!
//! - This module does NOT implement activation epoch/height gating.
//! - This module does NOT implement signed-bundle verification (that
//!   lives in `pqc_trust_bundle`; Run 051).
//! - This module does NOT implement leaf-cert revocation (that lives
//!   in `pqc_trust_bundle`; Run 052).
//! - This module does NOT touch consensus, timeout verification,
//!   KEMTLS, or any wire format.
//! - This module does NOT silently fall back to `--p2p-trusted-root`
//!   or to `DummySig` / `DummyKem` / `DummyAead`. On any failure the
//!   caller is required to fail closed (see
//!   [`TrustBundleSequenceError`]).
//!
//! # Persistence format
//!
//! A single JSON file under the operator-supplied
//! `<data_dir>/pqc_trust_bundle_sequence.json`. The schema is:
//!
//! ```json
//! {
//!   "record_version": 1,
//!   "environment": "devnet" | "testnet" | "mainnet",
//!   "chain_id": "<16 lowercase hex chars>",
//!   "highest_sequence": <u64>,
//!   "bundle_fingerprint": "<64 lowercase hex chars>",
//!   "updated_at_unix_secs": <u64>
//! }
//! ```
//!
//! `record_version` is currently `1`; anything else fails closed.
//! `environment` is one of `devnet|testnet|mainnet` and MUST match the
//! runtime environment for the same persistence path; if it does not
//! match, loading fails closed (a stray DevNet sequence file cannot
//! affect a MainNet startup, or vice versa). `chain_id` is the
//! canonical 16-char lowercase hex form of the runtime chain id
//! (mirrors `pqc_trust_bundle::parse_bundle_chain_id`). The persisted
//! `chain_id` MUST match the runtime chain id at load time; if it
//! does not, loading fails closed.
//!
//! # Trust-domain key
//!
//! The persisted record is keyed by the `(environment, chain_id)`
//! tuple. The persistence file path is supplied by the caller (today
//! always `<data_dir>/pqc_trust_bundle_sequence.json`), so two
//! independent nodes operating on different `data_dir`s have
//! independent records. The in-file `(environment, chain_id)` pair
//! defence-in-depths against a stray file appearing under a freshly
//! configured `data_dir` whose environment or chain id does not
//! match.
//!
//! # Sequence semantics
//!
//! Let `record.highest_sequence` be the previously persisted highest
//! sequence for the trust domain, and let `new_sequence` /
//! `new_fingerprint` be the just-validated bundle's sequence and
//! canonical fingerprint:
//!
//! - **No prior record:** accept and persist `new_sequence` /
//!   `new_fingerprint` as the initial record.
//! - **`new_sequence > highest_sequence`:** accept and persist the
//!   updated `(new_sequence, new_fingerprint)` record.
//! - **`new_sequence < highest_sequence`:** REJECT — fail closed with
//!   [`TrustBundleSequenceError::SequenceRollback`].
//! - **`new_sequence == highest_sequence` AND `new_fingerprint == record.bundle_fingerprint`:**
//!   accept (no-op on the persisted record). This permits a restart
//!   with the same bundle the operator already accepted, which is
//!   the common steady-state case.
//! - **`new_sequence == highest_sequence` AND `new_fingerprint != record.bundle_fingerprint`:**
//!   REJECT — fail closed with
//!   [`TrustBundleSequenceError::EqualSequenceFingerprintMismatch`]. This
//!   catches equivocation / replay-with-different-content at the same
//!   sequence and is the strongest-safe equal-sequence policy.
//!
//! Sequence `0` is permitted by the schema but not invented by this
//! module: the helper that generates DevNet bundles emits `sequence:
//! 1` by default, and operators are expected to use strictly positive
//! sequences. We do not silently special-case sequence `0`.
//!
//! # Atomicity
//!
//! Writes go through a tmp file + rename, the standard atomic
//! filesystem pattern: any failure mid-write leaves either the old
//! record or a `.tmp` sibling, never a corrupted destination file.
//! See [`atomic_write_record`] for the exact flow.
//!
//! # Failure policy
//!
//! - Corrupt JSON / missing field / wrong `record_version` →
//!   [`TrustBundleSequenceError::Malformed`] (fail closed).
//! - Wrong `environment` for the configured path →
//!   [`TrustBundleSequenceError::WrongEnvironment`] (fail closed).
//! - Wrong `chain_id` for the configured path →
//!   [`TrustBundleSequenceError::WrongChainId`] (fail closed).
//! - Malformed persisted `bundle_fingerprint` (not 64 lowercase hex
//!   chars) → [`TrustBundleSequenceError::Malformed`] (fail closed).
//! - Persistence write failure →
//!   [`TrustBundleSequenceError::PersistFailure`] (fail closed; the
//!   caller MUST NOT proceed to merge bundle roots if the new highest
//!   sequence cannot be recorded — otherwise a subsequent restart
//!   would re-accept the same or older bundle without record).
//!
//! The module never silently deletes, truncates, or resets a
//! corrupted persistence file; the operator is expected to investigate
//! the FATAL error rather than have state silently rewritten.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use qbind_types::{ChainId, NetworkEnvironment};

use crate::pqc_trust_bundle::TrustBundleEnvironment;

/// Current `record_version` for the persisted sequence file. Any
/// other value fails closed.
pub const TRUST_BUNDLE_SEQUENCE_RECORD_VERSION: u32 = 1;

/// Default file name written under `<data_dir>/`.
pub const TRUST_BUNDLE_SEQUENCE_FILENAME: &str = "pqc_trust_bundle_sequence.json";

/// Resolve the canonical persistence path under a node `data_dir`.
pub fn sequence_file_path(data_dir: &Path) -> PathBuf {
    data_dir.join(TRUST_BUNDLE_SEQUENCE_FILENAME)
}

/// On-disk record of the highest accepted trust-bundle sequence for
/// one trust domain. Serialised to JSON in
/// `<data_dir>/pqc_trust_bundle_sequence.json` (see module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentTrustBundleSequenceRecord {
    /// Schema version. Currently
    /// [`TRUST_BUNDLE_SEQUENCE_RECORD_VERSION`]; anything else fails
    /// closed.
    pub record_version: u32,
    /// Canonical environment of the trust domain.
    pub environment: TrustBundleEnvironment,
    /// 16 lowercase hex chars (no `0x` / `chain_` prefix) of the
    /// runtime chain id this record applies to.
    pub chain_id: String,
    /// Highest signed-bundle `sequence` ever accepted for this trust
    /// domain on this node.
    pub highest_sequence: u64,
    /// 64 lowercase hex chars of the canonical bundle fingerprint
    /// (`pqc_trust_bundle::canonical_fingerprint`) of the bundle that
    /// established the current `highest_sequence`. Used by the
    /// equal-sequence policy to distinguish identical-bundle restart
    /// from equivocation.
    pub bundle_fingerprint: String,
    /// Wall-clock time at which the record was last written, in Unix
    /// seconds. Informational only — never used in any policy
    /// decision.
    pub updated_at_unix_secs: u64,
}

impl PersistentTrustBundleSequenceRecord {
    /// Construct a fresh record for an initial bundle acceptance.
    pub fn new(
        environment: TrustBundleEnvironment,
        chain_id_hex: String,
        highest_sequence: u64,
        bundle_fingerprint_hex: String,
        updated_at_unix_secs: u64,
    ) -> Self {
        Self {
            record_version: TRUST_BUNDLE_SEQUENCE_RECORD_VERSION,
            environment,
            chain_id: chain_id_hex,
            highest_sequence,
            bundle_fingerprint: bundle_fingerprint_hex,
            updated_at_unix_secs,
        }
    }

    /// Strict structural validation of a freshly-deserialised record.
    /// Returns the expected variant of [`TrustBundleSequenceError`]
    /// on any defect so the binary surface can fail closed with a
    /// precise reason.
    pub fn validate_structure(&self) -> Result<(), TrustBundleSequenceError> {
        if self.record_version != TRUST_BUNDLE_SEQUENCE_RECORD_VERSION {
            return Err(TrustBundleSequenceError::UnsupportedRecordVersion(
                self.record_version,
            ));
        }
        if self.chain_id.len() != 16 || !is_lower_hex(&self.chain_id) {
            return Err(TrustBundleSequenceError::Malformed(format!(
                "chain_id must be exactly 16 lowercase hex chars, got {:?}",
                self.chain_id
            )));
        }
        if self.bundle_fingerprint.len() != 64
            || !is_lower_hex(&self.bundle_fingerprint)
        {
            return Err(TrustBundleSequenceError::Malformed(format!(
                "bundle_fingerprint must be exactly 64 lowercase hex chars (length {})",
                self.bundle_fingerprint.len()
            )));
        }
        Ok(())
    }
}

/// Outcome of [`check_and_update_sequence`] on a successful path —
/// distinguishes "accepted, record updated" from "accepted, record
/// unchanged (equal-sequence same-fingerprint restart)" from
/// "accepted, first-load (record created)" so the caller can emit
/// honest logs and metrics without inventing a fresh decision tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SequenceCheckOutcome {
    /// No prior record existed; the supplied bundle's sequence has
    /// been persisted as the initial record.
    FirstLoad {
        persisted_sequence: u64,
        persisted_fingerprint_hex: String,
    },
    /// New bundle sequence is strictly higher than the persisted
    /// value; the record has been updated to the new value.
    Upgraded {
        previous_sequence: u64,
        new_sequence: u64,
        previous_fingerprint_hex: String,
        new_fingerprint_hex: String,
    },
    /// Equal sequence, same fingerprint as persisted — accepted, no
    /// write performed. (Common restart-with-same-bundle case.)
    EqualSequenceSameFingerprint {
        sequence: u64,
        fingerprint_hex: String,
    },
}

impl SequenceCheckOutcome {
    /// Returns the sequence value persisted in the record after this
    /// check.
    pub fn persisted_sequence(&self) -> u64 {
        match self {
            Self::FirstLoad {
                persisted_sequence, ..
            } => *persisted_sequence,
            Self::Upgraded { new_sequence, .. } => *new_sequence,
            Self::EqualSequenceSameFingerprint { sequence, .. } => *sequence,
        }
    }

    /// True iff the on-disk record was newly created or updated by
    /// this check (i.e. atomic write actually ran).
    pub fn record_written(&self) -> bool {
        matches!(self, Self::FirstLoad { .. } | Self::Upgraded { .. })
    }
}

/// Errors produced by the sequence persistence layer. Every variant
/// is a fail-closed condition at the binary surface — the caller
/// MUST NOT proceed to merge bundle roots if this layer returned an
/// error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustBundleSequenceError {
    /// I/O error reading or writing the persistence file. The string
    /// carries the supplied path plus the OS error kind only; no
    /// file content is exposed in the message.
    Io(String),
    /// JSON parse error, missing field, malformed hex, or malformed
    /// structural invariant on a deserialised record.
    Malformed(String),
    /// Persisted `record_version` is not the one this binary
    /// supports.
    UnsupportedRecordVersion(u32),
    /// Persisted `environment` does not match the runtime
    /// environment for this persistence path.
    WrongEnvironment {
        expected: TrustBundleEnvironment,
        found: TrustBundleEnvironment,
    },
    /// Persisted `chain_id` does not match the runtime chain id for
    /// this persistence path.
    WrongChainId { expected: String, found: String },
    /// The supplied bundle's `sequence` is strictly lower than the
    /// persisted `highest_sequence` — rollback attempt, fail closed.
    SequenceRollback {
        attempted_sequence: u64,
        persisted_highest_sequence: u64,
    },
    /// The supplied bundle's `sequence` equals the persisted
    /// `highest_sequence` but its canonical fingerprint differs from
    /// the persisted fingerprint — equivocation, fail closed.
    EqualSequenceFingerprintMismatch {
        sequence: u64,
        persisted_fingerprint_hex: String,
        new_fingerprint_hex: String,
    },
    /// Persistence write failure. The caller MUST NOT accept the
    /// bundle if this fires, otherwise a subsequent restart would
    /// silently lose the would-be-recorded state.
    PersistFailure(String),
}

impl std::fmt::Display for TrustBundleSequenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "pqc trust-bundle sequence io: {}", s),
            Self::Malformed(s) => {
                write!(f, "pqc trust-bundle sequence malformed: {}", s)
            }
            Self::UnsupportedRecordVersion(v) => write!(
                f,
                "pqc trust-bundle sequence record_version {} not supported (this binary supports {})",
                v, TRUST_BUNDLE_SEQUENCE_RECORD_VERSION
            ),
            Self::WrongEnvironment { expected, found } => write!(
                f,
                "pqc trust-bundle sequence environment mismatch (expected {}, persisted record declares {}) — fail closed",
                expected, found
            ),
            Self::WrongChainId { expected, found } => write!(
                f,
                "pqc trust-bundle sequence chain_id mismatch (expected {}, persisted record declares {}) — fail closed",
                expected, found
            ),
            Self::SequenceRollback {
                attempted_sequence,
                persisted_highest_sequence,
            } => write!(
                f,
                "pqc trust-bundle sequence rollback rejected: attempted_sequence={} is lower than persisted highest_sequence={} (fail closed; this node has already accepted a newer signed bundle for the same trust domain)",
                attempted_sequence, persisted_highest_sequence
            ),
            Self::EqualSequenceFingerprintMismatch {
                sequence,
                persisted_fingerprint_hex,
                new_fingerprint_hex,
            } => write!(
                f,
                "pqc trust-bundle equal-sequence equivocation rejected: sequence={} persisted_fingerprint={} attempted_fingerprint={} (fail closed; two distinct bundles cannot share the same sequence)",
                sequence, persisted_fingerprint_hex, new_fingerprint_hex
            ),
            Self::PersistFailure(s) => write!(
                f,
                "pqc trust-bundle sequence persist failure: {} (fail closed; bundle MUST NOT be accepted if its sequence cannot be recorded)",
                s
            ),
        }
    }
}

impl std::error::Error for TrustBundleSequenceError {}

/// Render a 32-byte canonical bundle fingerprint as the 64-char
/// lowercase hex form persisted in the record.
pub fn fingerprint_hex(fp: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in fp {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", b);
    }
    out
}

/// Render a runtime [`ChainId`] as the 16-char lowercase hex form
/// persisted in the record (no `0x` / `chain_` prefix — matches the
/// stripped form that
/// `pqc_trust_bundle::parse_bundle_chain_id` accepts).
pub fn chain_id_hex(chain_id: ChainId) -> String {
    format!("{:016x}", chain_id.as_u64())
}

/// Load the persisted sequence record from `path` if it exists.
///
/// - Returns `Ok(None)` if the file does not exist (first-load case).
/// - Returns `Ok(Some(record))` on a successful, structurally valid
///   load. The caller MUST still call
///   [`validate_record_for_domain`] to check
///   `(environment, chain_id)` before relying on the value.
/// - Returns `Err(...)` on I/O, JSON, schema-version, or structural
///   defects. Fail closed.
pub fn load_record(
    path: &Path,
) -> Result<Option<PersistentTrustBundleSequenceRecord>, TrustBundleSequenceError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(TrustBundleSequenceError::Io(format!(
                "{}: {}",
                path.display(),
                e.kind()
            )));
        }
    };
    let record: PersistentTrustBundleSequenceRecord = serde_json::from_slice(&bytes)
        .map_err(|e| TrustBundleSequenceError::Malformed(format!("{}", e)))?;
    record.validate_structure()?;
    Ok(Some(record))
}

/// Verify that a freshly-loaded record applies to the runtime
/// `(environment, chain_id)` trust domain. Returns the precise
/// fail-closed error when the persisted (environment, chain_id) does
/// not match.
pub fn validate_record_for_domain(
    record: &PersistentTrustBundleSequenceRecord,
    expected_env: NetworkEnvironment,
    expected_chain_id: ChainId,
) -> Result<(), TrustBundleSequenceError> {
    let expected_env_bundle = TrustBundleEnvironment::from_runtime(expected_env);
    if record.environment != expected_env_bundle {
        return Err(TrustBundleSequenceError::WrongEnvironment {
            expected: expected_env_bundle,
            found: record.environment,
        });
    }
    let expected_chain_hex = chain_id_hex(expected_chain_id);
    if record.chain_id != expected_chain_hex {
        return Err(TrustBundleSequenceError::WrongChainId {
            expected: expected_chain_hex,
            found: record.chain_id.clone(),
        });
    }
    Ok(())
}

/// Atomically write `record` to `path` using a `tmp` sibling + rename.
///
/// The flow is:
///
/// 1. Serialise `record` to canonical JSON.
/// 2. Create the parent directory if it does not exist (mirrors the
///    project's storage discipline; the data-dir is operator-supplied
///    and may or may not exist).
/// 3. Write the serialised bytes to `<path>.tmp`.
/// 4. `sync_all()` the tmp file (best-effort on all platforms).
/// 5. Rename `<path>.tmp` → `<path>`.
///
/// Any I/O failure surfaces as
/// [`TrustBundleSequenceError::PersistFailure`]. On a mid-write
/// crash the destination file is left intact and the `.tmp` sibling
/// (if any) is harmless — the next load returns the previously
/// persisted record verbatim.
pub fn atomic_write_record(
    path: &Path,
    record: &PersistentTrustBundleSequenceRecord,
) -> Result<(), TrustBundleSequenceError> {
    use std::io::Write;
    let bytes = serde_json::to_vec(record).map_err(|e| {
        TrustBundleSequenceError::PersistFailure(format!("serialise: {}", e))
    })?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                TrustBundleSequenceError::PersistFailure(format!(
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
            TrustBundleSequenceError::PersistFailure(format!(
                "create {}: {}",
                tmp_path.display(),
                e.kind()
            ))
        })?;
        f.write_all(&bytes).map_err(|e| {
            TrustBundleSequenceError::PersistFailure(format!(
                "write {}: {}",
                tmp_path.display(),
                e.kind()
            ))
        })?;
        f.sync_all().map_err(|e| {
            TrustBundleSequenceError::PersistFailure(format!(
                "sync_all {}: {}",
                tmp_path.display(),
                e.kind()
            ))
        })?;
    }
    std::fs::rename(&tmp_path, path).map_err(|e| {
        // Best effort to clean up the tmp file; ignore secondary errors
        // because the primary persist failure is what we surface.
        let _ = std::fs::remove_file(&tmp_path);
        TrustBundleSequenceError::PersistFailure(format!(
            "rename {} -> {}: {}",
            tmp_path.display(),
            path.display(),
            e.kind()
        ))
    })?;
    Ok(())
}

/// Run 055 entry point: enforce sequence monotonicity for a freshly
/// validated signed trust bundle and persist the new highest sequence
/// on a successful update.
///
/// Inputs:
///
/// - `path`: persistence path (typically
///   `<data_dir>/pqc_trust_bundle_sequence.json`).
/// - `expected_env`: runtime [`NetworkEnvironment`]; checked against
///   any pre-existing record.
/// - `expected_chain_id`: runtime [`ChainId`]; checked against any
///   pre-existing record.
/// - `new_sequence`: `bundle.sequence` of the just-validated bundle.
/// - `new_fingerprint`: `pqc_trust_bundle::canonical_fingerprint(...)`
///   of the just-validated bundle.
/// - `now_unix_secs`: wall-clock used only to populate the
///   informational `updated_at_unix_secs` field.
///
/// Returns [`SequenceCheckOutcome`] on success. Returns
/// [`TrustBundleSequenceError`] on any defect (rollback, equal-seq
/// equivocation, wrong env/chain, corrupt file, persistence write
/// failure). The caller MUST fail closed and MUST NOT merge bundle
/// roots if this function returns `Err(...)`.
///
/// Semantics are exactly as documented in the module-level docs
/// ("Sequence semantics").
pub fn check_and_update_sequence(
    path: &Path,
    expected_env: NetworkEnvironment,
    expected_chain_id: ChainId,
    new_sequence: u64,
    new_fingerprint: &[u8; 32],
    now_unix_secs: u64,
) -> Result<SequenceCheckOutcome, TrustBundleSequenceError> {
    let new_fp_hex = fingerprint_hex(new_fingerprint);
    let expected_env_bundle = TrustBundleEnvironment::from_runtime(expected_env);
    let expected_chain_hex = chain_id_hex(expected_chain_id);

    match load_record(path)? {
        None => {
            let record = PersistentTrustBundleSequenceRecord::new(
                expected_env_bundle,
                expected_chain_hex,
                new_sequence,
                new_fp_hex.clone(),
                now_unix_secs,
            );
            atomic_write_record(path, &record)?;
            Ok(SequenceCheckOutcome::FirstLoad {
                persisted_sequence: new_sequence,
                persisted_fingerprint_hex: new_fp_hex,
            })
        }
        Some(record) => {
            validate_record_for_domain(&record, expected_env, expected_chain_id)?;
            if new_sequence < record.highest_sequence {
                return Err(TrustBundleSequenceError::SequenceRollback {
                    attempted_sequence: new_sequence,
                    persisted_highest_sequence: record.highest_sequence,
                });
            }
            if new_sequence == record.highest_sequence {
                if record.bundle_fingerprint == new_fp_hex {
                    return Ok(SequenceCheckOutcome::EqualSequenceSameFingerprint {
                        sequence: new_sequence,
                        fingerprint_hex: new_fp_hex,
                    });
                }
                return Err(
                    TrustBundleSequenceError::EqualSequenceFingerprintMismatch {
                        sequence: new_sequence,
                        persisted_fingerprint_hex: record.bundle_fingerprint.clone(),
                        new_fingerprint_hex: new_fp_hex,
                    },
                );
            }
            // new_sequence > record.highest_sequence — upgrade.
            let previous_sequence = record.highest_sequence;
            let previous_fp_hex = record.bundle_fingerprint.clone();
            let updated = PersistentTrustBundleSequenceRecord::new(
                expected_env_bundle,
                expected_chain_hex,
                new_sequence,
                new_fp_hex.clone(),
                now_unix_secs,
            );
            atomic_write_record(path, &updated)?;
            Ok(SequenceCheckOutcome::Upgraded {
                previous_sequence,
                new_sequence,
                previous_fingerprint_hex: previous_fp_hex,
                new_fingerprint_hex: new_fp_hex,
            })
        }
    }
}

/// Outcome of a Run 069 read-only sequence peek — the validation-only
/// analogue of [`SequenceCheckOutcome`]. Distinguishes the three
/// accept-classifications without performing any persistence write.
///
/// The persisted on-disk record is read but never modified. Callers
/// that need to advance the persisted sequence MUST use
/// [`check_and_update_sequence`] instead — `peek_sequence` exists
/// specifically so a candidate trust bundle can be validated against
/// the current persisted state without "burning" a sequence number on
/// rejection or on a validation-only dry run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SequencePeekOutcome {
    /// No prior record exists on disk for this trust domain. The
    /// candidate would be a first-load on `check_and_update_sequence`.
    /// Reported separately so callers can surface "no anti-rollback
    /// baseline yet" honestly.
    NoPriorRecord {
        candidate_sequence: u64,
        candidate_fingerprint_hex: String,
    },
    /// A prior record exists and the candidate's sequence is strictly
    /// higher. On a real `check_and_update_sequence` call this would
    /// be an `Upgraded { .. }` outcome and the record would be
    /// rewritten — but `peek_sequence` deliberately performs NO
    /// write.
    WouldUpgrade {
        previous_sequence: u64,
        candidate_sequence: u64,
        previous_fingerprint_hex: String,
        candidate_fingerprint_hex: String,
    },
    /// A prior record exists and the candidate's sequence equals it
    /// AND the canonical fingerprints match. On a real call this
    /// would be an `EqualSequenceSameFingerprint` no-op acceptance.
    EqualSequenceSameFingerprint {
        sequence: u64,
        fingerprint_hex: String,
    },
}

impl SequencePeekOutcome {
    /// Returns the candidate sequence reported by this peek.
    pub fn candidate_sequence(&self) -> u64 {
        match self {
            Self::NoPriorRecord {
                candidate_sequence, ..
            } => *candidate_sequence,
            Self::WouldUpgrade {
                candidate_sequence, ..
            } => *candidate_sequence,
            Self::EqualSequenceSameFingerprint { sequence, .. } => *sequence,
        }
    }

    /// Returns the persisted sequence value as observed on disk before
    /// this peek (i.e. what would still be on disk after the peek,
    /// since the peek never writes). `None` when no record exists.
    pub fn persisted_sequence_before(&self) -> Option<u64> {
        match self {
            Self::NoPriorRecord { .. } => None,
            Self::WouldUpgrade {
                previous_sequence, ..
            } => Some(*previous_sequence),
            Self::EqualSequenceSameFingerprint { sequence, .. } => Some(*sequence),
        }
    }
}

/// Run 069 read-only counterpart of [`check_and_update_sequence`].
///
/// Validates a candidate bundle's `(sequence, fingerprint)` against
/// the persisted anti-rollback record at `path` using the exact same
/// fail-closed policy as [`check_and_update_sequence`], but performs
/// **no** persistence write:
///
/// - never calls [`atomic_write_record`];
/// - never creates or modifies `<data_dir>/pqc_trust_bundle_sequence.json`;
/// - never creates parent directories;
/// - returns an `Err(...)` for the rejection cases without burning a
///   sequence number;
/// - returns a [`SequencePeekOutcome`] variant for the three accept
///   classifications so a caller can report the "what would happen
///   if applied" status honestly.
///
/// This is the foundational primitive for the Run 069
/// disabled-by-default trust-bundle hot-reload validation/staging
/// boundary. It is reused by [`crate::pqc_trust_reload`] which adds
/// the bundle / activation / local-revocation checks on top.
///
/// Fail-closed parity with [`check_and_update_sequence`]:
///
/// - corrupt or wrong-schema persistence file
///   → [`TrustBundleSequenceError::Malformed`] /
///     [`TrustBundleSequenceError::UnsupportedRecordVersion`];
/// - wrong environment / wrong chain id record on disk
///   → [`TrustBundleSequenceError::WrongEnvironment`] /
///     [`TrustBundleSequenceError::WrongChainId`];
/// - candidate sequence strictly lower than persisted
///   → [`TrustBundleSequenceError::SequenceRollback`];
/// - equal candidate sequence + different fingerprint
///   → [`TrustBundleSequenceError::EqualSequenceFingerprintMismatch`];
/// - I/O error reading the persisted file
///   → [`TrustBundleSequenceError::Io`].
///
/// In none of those cases is the persisted file modified.
pub fn peek_sequence(
    path: &Path,
    expected_env: NetworkEnvironment,
    expected_chain_id: ChainId,
    candidate_sequence: u64,
    candidate_fingerprint: &[u8; 32],
) -> Result<SequencePeekOutcome, TrustBundleSequenceError> {
    let new_fp_hex = fingerprint_hex(candidate_fingerprint);
    match load_record(path)? {
        None => Ok(SequencePeekOutcome::NoPriorRecord {
            candidate_sequence,
            candidate_fingerprint_hex: new_fp_hex,
        }),
        Some(record) => {
            validate_record_for_domain(&record, expected_env, expected_chain_id)?;
            if candidate_sequence < record.highest_sequence {
                return Err(TrustBundleSequenceError::SequenceRollback {
                    attempted_sequence: candidate_sequence,
                    persisted_highest_sequence: record.highest_sequence,
                });
            }
            if candidate_sequence == record.highest_sequence {
                if record.bundle_fingerprint == new_fp_hex {
                    return Ok(SequencePeekOutcome::EqualSequenceSameFingerprint {
                        sequence: candidate_sequence,
                        fingerprint_hex: new_fp_hex,
                    });
                }
                return Err(
                    TrustBundleSequenceError::EqualSequenceFingerprintMismatch {
                        sequence: candidate_sequence,
                        persisted_fingerprint_hex: record.bundle_fingerprint.clone(),
                        new_fingerprint_hex: new_fp_hex,
                    },
                );
            }
            Ok(SequencePeekOutcome::WouldUpgrade {
                previous_sequence: record.highest_sequence,
                candidate_sequence,
                previous_fingerprint_hex: record.bundle_fingerprint.clone(),
                candidate_fingerprint_hex: new_fp_hex,
            })
        }
    }
}

fn is_lower_hex(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "qbind-run055-{}-{}-{}",
            tag,
            std::process::id(),
            // monotonic-ish unique counter per call
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        std::fs::create_dir_all(&p).expect("create_dir_all");
        p
    }

    fn fp(b: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.fill(b);
        out
    }

    fn devnet_chain_id() -> ChainId {
        NetworkEnvironment::Devnet.chain_id()
    }

    #[test]
    fn fingerprint_hex_is_64_lowercase_hex_chars() {
        let bytes = [0xabu8; 32];
        let s = fingerprint_hex(&bytes);
        assert_eq!(s.len(), 64);
        assert!(s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')));
    }

    #[test]
    fn chain_id_hex_is_16_lowercase_hex_chars() {
        let c = devnet_chain_id();
        let s = chain_id_hex(c);
        assert_eq!(s.len(), 16);
        assert!(s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')));
    }

    #[test]
    fn load_record_returns_none_when_file_missing() {
        let dir = tmpdir("missing");
        let path = sequence_file_path(&dir);
        let r = load_record(&path).expect("ok");
        assert!(r.is_none());
    }

    #[test]
    fn load_record_rejects_malformed_json() {
        let dir = tmpdir("malformed");
        let path = sequence_file_path(&dir);
        std::fs::write(&path, b"not json").unwrap();
        let err = load_record(&path).err().expect("err");
        assert!(matches!(err, TrustBundleSequenceError::Malformed(_)));
    }

    #[test]
    fn load_record_rejects_wrong_record_version() {
        let dir = tmpdir("wrongver");
        let path = sequence_file_path(&dir);
        let body = serde_json::json!({
            "record_version": 9999u32,
            "environment": "devnet",
            "chain_id": "0123456789abcdef",
            "highest_sequence": 1,
            "bundle_fingerprint": "00".repeat(32),
            "updated_at_unix_secs": 0,
        });
        std::fs::write(&path, body.to_string()).unwrap();
        let err = load_record(&path).err().expect("err");
        assert!(matches!(
            err,
            TrustBundleSequenceError::UnsupportedRecordVersion(9999)
        ));
    }

    #[test]
    fn load_record_rejects_missing_field() {
        let dir = tmpdir("missfield");
        let path = sequence_file_path(&dir);
        // Omit chain_id.
        let body = serde_json::json!({
            "record_version": 1,
            "environment": "devnet",
            "highest_sequence": 1,
            "bundle_fingerprint": "00".repeat(32),
            "updated_at_unix_secs": 0,
        });
        std::fs::write(&path, body.to_string()).unwrap();
        let err = load_record(&path).err().expect("err");
        assert!(matches!(err, TrustBundleSequenceError::Malformed(_)));
    }

    #[test]
    fn load_record_rejects_malformed_chain_id_hex() {
        let dir = tmpdir("badchain");
        let path = sequence_file_path(&dir);
        let body = serde_json::json!({
            "record_version": 1,
            "environment": "devnet",
            "chain_id": "ZZZZ", // too short + non-hex
            "highest_sequence": 1,
            "bundle_fingerprint": "00".repeat(32),
            "updated_at_unix_secs": 0,
        });
        std::fs::write(&path, body.to_string()).unwrap();
        let err = load_record(&path).err().expect("err");
        assert!(matches!(err, TrustBundleSequenceError::Malformed(_)));
    }

    #[test]
    fn load_record_rejects_malformed_fingerprint_hex() {
        let dir = tmpdir("badfp");
        let path = sequence_file_path(&dir);
        let body = serde_json::json!({
            "record_version": 1,
            "environment": "devnet",
            "chain_id": chain_id_hex(devnet_chain_id()),
            "highest_sequence": 1,
            "bundle_fingerprint": "deadbeef", // wrong length
            "updated_at_unix_secs": 0,
        });
        std::fs::write(&path, body.to_string()).unwrap();
        let err = load_record(&path).err().expect("err");
        assert!(matches!(err, TrustBundleSequenceError::Malformed(_)));
    }

    #[test]
    fn first_load_writes_record_and_returns_first_load_outcome() {
        let dir = tmpdir("first");
        let path = sequence_file_path(&dir);
        let outcome = check_and_update_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            5,
            &fp(0x11),
            1234,
        )
        .expect("first load");
        assert!(matches!(
            outcome,
            SequenceCheckOutcome::FirstLoad {
                persisted_sequence: 5,
                ..
            }
        ));
        assert!(outcome.record_written());

        let loaded = load_record(&path).expect("ok").expect("some");
        assert_eq!(loaded.record_version, TRUST_BUNDLE_SEQUENCE_RECORD_VERSION);
        assert_eq!(loaded.environment, TrustBundleEnvironment::Devnet);
        assert_eq!(loaded.highest_sequence, 5);
        assert_eq!(loaded.bundle_fingerprint, fingerprint_hex(&fp(0x11)));
        assert_eq!(loaded.updated_at_unix_secs, 1234);
        validate_record_for_domain(&loaded, NetworkEnvironment::Devnet, devnet_chain_id())
            .expect("domain ok");
    }

    #[test]
    fn higher_sequence_is_accepted_and_persists() {
        let dir = tmpdir("higher");
        let path = sequence_file_path(&dir);
        check_and_update_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            1,
            &fp(0xaa),
            0,
        )
        .unwrap();
        let outcome = check_and_update_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            2,
            &fp(0xbb),
            0,
        )
        .expect("upgrade");
        assert!(matches!(
            outcome,
            SequenceCheckOutcome::Upgraded {
                previous_sequence: 1,
                new_sequence: 2,
                ..
            }
        ));
        assert!(outcome.record_written());
        let loaded = load_record(&path).expect("ok").expect("some");
        assert_eq!(loaded.highest_sequence, 2);
        assert_eq!(loaded.bundle_fingerprint, fingerprint_hex(&fp(0xbb)));
    }

    #[test]
    fn lower_sequence_is_rejected_as_rollback() {
        let dir = tmpdir("rollback");
        let path = sequence_file_path(&dir);
        check_and_update_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            7,
            &fp(0x10),
            0,
        )
        .unwrap();
        let err = check_and_update_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            6,
            &fp(0x20),
            0,
        )
        .err()
        .expect("rollback");
        assert!(matches!(
            err,
            TrustBundleSequenceError::SequenceRollback {
                attempted_sequence: 6,
                persisted_highest_sequence: 7,
            }
        ));
        // Record must NOT have been overwritten.
        let loaded = load_record(&path).expect("ok").expect("some");
        assert_eq!(loaded.highest_sequence, 7);
        assert_eq!(loaded.bundle_fingerprint, fingerprint_hex(&fp(0x10)));
    }

    #[test]
    fn equal_sequence_same_fingerprint_is_accepted_without_write() {
        let dir = tmpdir("eq-same");
        let path = sequence_file_path(&dir);
        check_and_update_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            3,
            &fp(0x42),
            10,
        )
        .unwrap();
        let mtime_before = std::fs::metadata(&path).unwrap().modified().unwrap();
        // Sleep a hair to make a missing-write detectable via mtime if
        // the implementation ever changes; not strictly required for
        // correctness.
        std::thread::sleep(std::time::Duration::from_millis(10));
        let outcome = check_and_update_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            3,
            &fp(0x42),
            999,
        )
        .expect("equal same fp");
        assert!(matches!(
            outcome,
            SequenceCheckOutcome::EqualSequenceSameFingerprint {
                sequence: 3,
                ..
            }
        ));
        assert!(!outcome.record_written());
        let mtime_after = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(mtime_before, mtime_after, "record must not be rewritten");
        // updated_at_unix_secs MUST stay at its original value because we
        // did not rewrite the file.
        let loaded = load_record(&path).expect("ok").expect("some");
        assert_eq!(loaded.updated_at_unix_secs, 10);
        assert_eq!(loaded.highest_sequence, 3);
    }

    #[test]
    fn equal_sequence_different_fingerprint_is_rejected() {
        let dir = tmpdir("eq-diff");
        let path = sequence_file_path(&dir);
        check_and_update_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            4,
            &fp(0x33),
            0,
        )
        .unwrap();
        let err = check_and_update_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            4,
            &fp(0x44),
            0,
        )
        .err()
        .expect("equiv");
        assert!(matches!(
            err,
            TrustBundleSequenceError::EqualSequenceFingerprintMismatch {
                sequence: 4,
                ..
            }
        ));
        let loaded = load_record(&path).expect("ok").expect("some");
        assert_eq!(loaded.highest_sequence, 4);
        assert_eq!(loaded.bundle_fingerprint, fingerprint_hex(&fp(0x33)));
    }

    #[test]
    fn wrong_environment_in_record_fails_closed() {
        let dir = tmpdir("wrongenv");
        let path = sequence_file_path(&dir);
        // Write a TestNet record under the path that the runtime will
        // then load as DevNet.
        let record = PersistentTrustBundleSequenceRecord::new(
            TrustBundleEnvironment::Testnet,
            chain_id_hex(NetworkEnvironment::Testnet.chain_id()),
            1,
            fingerprint_hex(&fp(0xee)),
            0,
        );
        atomic_write_record(&path, &record).unwrap();
        let err = check_and_update_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            2,
            &fp(0xff),
            0,
        )
        .err()
        .expect("wrong env");
        assert!(matches!(
            err,
            TrustBundleSequenceError::WrongEnvironment {
                expected: TrustBundleEnvironment::Devnet,
                found: TrustBundleEnvironment::Testnet,
            }
        ));
        // Record must remain untouched.
        let loaded = load_record(&path).expect("ok").expect("some");
        assert_eq!(loaded.environment, TrustBundleEnvironment::Testnet);
        assert_eq!(loaded.highest_sequence, 1);
    }

    #[test]
    fn wrong_chain_id_in_record_fails_closed() {
        let dir = tmpdir("wrongchain");
        let path = sequence_file_path(&dir);
        let record = PersistentTrustBundleSequenceRecord::new(
            TrustBundleEnvironment::Devnet,
            "0000000000000001".to_string(),
            1,
            fingerprint_hex(&fp(0x88)),
            0,
        );
        atomic_write_record(&path, &record).unwrap();
        let err = check_and_update_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            2,
            &fp(0x99),
            0,
        )
        .err()
        .expect("wrong chain");
        assert!(matches!(err, TrustBundleSequenceError::WrongChainId { .. }));
    }

    #[test]
    fn atomic_write_then_load_round_trips() {
        let dir = tmpdir("rt");
        let path = sequence_file_path(&dir);
        let record = PersistentTrustBundleSequenceRecord::new(
            TrustBundleEnvironment::Mainnet,
            chain_id_hex(NetworkEnvironment::Mainnet.chain_id()),
            42,
            fingerprint_hex(&fp(0x7e)),
            1234567,
        );
        atomic_write_record(&path, &record).unwrap();
        let loaded = load_record(&path).expect("ok").expect("some");
        assert_eq!(loaded, record);
        // tmp sibling MUST not be left behind.
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        assert!(!Path::new(&tmp).exists());
    }

    #[test]
    fn atomic_write_creates_missing_parent_dir() {
        let dir = tmpdir("parent");
        let nested = dir.join("deep/inner");
        let path = sequence_file_path(&nested);
        let record = PersistentTrustBundleSequenceRecord::new(
            TrustBundleEnvironment::Devnet,
            chain_id_hex(devnet_chain_id()),
            1,
            fingerprint_hex(&fp(0x01)),
            0,
        );
        atomic_write_record(&path, &record).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn rollback_after_two_step_upgrade_still_fails() {
        let dir = tmpdir("rollback2");
        let path = sequence_file_path(&dir);
        for (seq, fp_byte) in [(1u64, 0x10u8), (2, 0x20), (3, 0x30)] {
            check_and_update_sequence(
                &path,
                NetworkEnvironment::Devnet,
                devnet_chain_id(),
                seq,
                &fp(fp_byte),
                0,
            )
            .unwrap();
        }
        let err = check_and_update_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            1,
            &fp(0x10),
            0,
        )
        .err()
        .expect("rollback");
        assert!(matches!(
            err,
            TrustBundleSequenceError::SequenceRollback {
                attempted_sequence: 1,
                persisted_highest_sequence: 3,
            }
        ));
    }

    #[test]
    fn persist_failure_when_path_is_a_directory() {
        let dir = tmpdir("isdir");
        // Use the directory itself as the "file" path — write must fail.
        let err = check_and_update_sequence(
            &dir,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            1,
            &fp(0x01),
            0,
        )
        .err()
        .expect("persist failure");
        // Could surface as Io (when read fails because path is a dir)
        // or as PersistFailure (when read returns empty/EISDIR depending
        // on platform). Either way fail-closed semantics are honoured.
        assert!(
            matches!(
                err,
                TrustBundleSequenceError::Io(_)
                    | TrustBundleSequenceError::PersistFailure(_)
                    | TrustBundleSequenceError::Malformed(_)
            ),
            "got {:?}",
            err
        );
    }

    #[test]
    fn equivocation_detail_carries_both_fingerprints() {
        let dir = tmpdir("equiv-detail");
        let path = sequence_file_path(&dir);
        check_and_update_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            7,
            &fp(0xa1),
            0,
        )
        .unwrap();
        let err = check_and_update_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            7,
            &fp(0xa2),
            0,
        )
        .err()
        .unwrap();
        let TrustBundleSequenceError::EqualSequenceFingerprintMismatch {
            sequence,
            persisted_fingerprint_hex,
            new_fingerprint_hex,
        } = err
        else {
            panic!("expected EqualSequenceFingerprintMismatch, got {:?}", err);
        };
        assert_eq!(sequence, 7);
        assert_eq!(persisted_fingerprint_hex, fingerprint_hex(&fp(0xa1)));
        assert_eq!(new_fingerprint_hex, fingerprint_hex(&fp(0xa2)));
    }

    #[test]
    fn display_messages_are_operator_actionable() {
        // Quick smoke: every Display variant produces a non-empty,
        // self-describing string. Operators rely on these in FATAL
        // logs at startup.
        let cases = vec![
            TrustBundleSequenceError::Io("/p: kind".into()),
            TrustBundleSequenceError::Malformed("bad json".into()),
            TrustBundleSequenceError::UnsupportedRecordVersion(7),
            TrustBundleSequenceError::WrongEnvironment {
                expected: TrustBundleEnvironment::Devnet,
                found: TrustBundleEnvironment::Mainnet,
            },
            TrustBundleSequenceError::WrongChainId {
                expected: "0123456789abcdef".into(),
                found: "fedcba9876543210".into(),
            },
            TrustBundleSequenceError::SequenceRollback {
                attempted_sequence: 1,
                persisted_highest_sequence: 5,
            },
            TrustBundleSequenceError::EqualSequenceFingerprintMismatch {
                sequence: 3,
                persisted_fingerprint_hex: "aa".repeat(32),
                new_fingerprint_hex: "bb".repeat(32),
            },
            TrustBundleSequenceError::PersistFailure("disk full".into()),
        ];
        for e in cases {
            let s = format!("{}", e);
            assert!(!s.is_empty());
            assert!(s.len() > 10, "message too short: {}", s);
        }
    }

    // Run 069 — peek_sequence (read-only) unit tests.
    //
    // The whole point of the peek is to *never* write the persistence
    // file. Each test below asserts both the returned variant and
    // that the on-disk record is unchanged after the peek.

    #[test]
    fn peek_sequence_no_prior_record_returns_no_prior_record() {
        let dir = tmpdir("peek-noprior");
        let path = sequence_file_path(&dir);
        let out = peek_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            5,
            &fp(0xaa),
        )
        .expect("peek ok");
        assert!(matches!(
            out,
            SequencePeekOutcome::NoPriorRecord { candidate_sequence: 5, .. }
        ));
        assert!(out.persisted_sequence_before().is_none());
        // File must NOT have been created by the peek.
        assert!(!path.exists(), "peek must not create persistence file");
    }

    #[test]
    fn peek_sequence_would_upgrade_for_higher_seq() {
        let dir = tmpdir("peek-upgrade");
        let path = sequence_file_path(&dir);
        // Establish baseline at seq=1, fingerprint=aa.
        check_and_update_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            1,
            &fp(0xaa),
            0,
        )
        .unwrap();
        let mtime_before = std::fs::metadata(&path).unwrap().modified().unwrap();
        let bytes_before = std::fs::read(&path).unwrap();

        let out = peek_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            2,
            &fp(0xbb),
        )
        .expect("peek ok");
        assert!(matches!(
            out,
            SequencePeekOutcome::WouldUpgrade {
                previous_sequence: 1,
                candidate_sequence: 2,
                ..
            }
        ));
        assert_eq!(out.persisted_sequence_before(), Some(1));
        // File MUST NOT have been rewritten.
        let bytes_after = std::fs::read(&path).unwrap();
        assert_eq!(bytes_before, bytes_after, "peek must not rewrite record");
        let mtime_after = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(mtime_before, mtime_after, "peek must not touch mtime");
        // Reload to be 100% sure the *content* did not change.
        let record = load_record(&path).unwrap().unwrap();
        assert_eq!(record.highest_sequence, 1);
        assert_eq!(record.bundle_fingerprint, fingerprint_hex(&fp(0xaa)));
    }

    #[test]
    fn peek_sequence_equal_same_fingerprint_returns_equal_no_op() {
        let dir = tmpdir("peek-equal");
        let path = sequence_file_path(&dir);
        check_and_update_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            7,
            &fp(0xcc),
            0,
        )
        .unwrap();
        let bytes_before = std::fs::read(&path).unwrap();

        let out = peek_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            7,
            &fp(0xcc),
        )
        .expect("peek ok");
        assert!(matches!(
            out,
            SequencePeekOutcome::EqualSequenceSameFingerprint { sequence: 7, .. }
        ));
        assert_eq!(out.persisted_sequence_before(), Some(7));
        let bytes_after = std::fs::read(&path).unwrap();
        assert_eq!(bytes_before, bytes_after);
    }

    #[test]
    fn peek_sequence_rejects_rollback_without_mutation() {
        let dir = tmpdir("peek-rollback");
        let path = sequence_file_path(&dir);
        check_and_update_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            5,
            &fp(0xaa),
            0,
        )
        .unwrap();
        let bytes_before = std::fs::read(&path).unwrap();

        let err = peek_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            4,
            &fp(0xbb),
        )
        .err()
        .expect("err");
        assert!(matches!(
            err,
            TrustBundleSequenceError::SequenceRollback {
                attempted_sequence: 4,
                persisted_highest_sequence: 5,
            }
        ));
        let bytes_after = std::fs::read(&path).unwrap();
        assert_eq!(bytes_before, bytes_after, "peek rollback must not write");
    }

    #[test]
    fn peek_sequence_rejects_equal_seq_fingerprint_mismatch_without_mutation() {
        let dir = tmpdir("peek-equivocation");
        let path = sequence_file_path(&dir);
        check_and_update_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            5,
            &fp(0xaa),
            0,
        )
        .unwrap();
        let bytes_before = std::fs::read(&path).unwrap();

        let err = peek_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            5,
            &fp(0xbb),
        )
        .err()
        .expect("err");
        assert!(matches!(
            err,
            TrustBundleSequenceError::EqualSequenceFingerprintMismatch {
                sequence: 5,
                ..
            }
        ));
        let bytes_after = std::fs::read(&path).unwrap();
        assert_eq!(bytes_before, bytes_after);
    }

    #[test]
    fn peek_sequence_rejects_wrong_environment_without_mutation() {
        let dir = tmpdir("peek-wrong-env");
        let path = sequence_file_path(&dir);
        check_and_update_sequence(
            &path,
            NetworkEnvironment::Devnet,
            devnet_chain_id(),
            1,
            &fp(0xaa),
            0,
        )
        .unwrap();
        let bytes_before = std::fs::read(&path).unwrap();
        // Peek against TestNet against a Devnet record.
        let err = peek_sequence(
            &path,
            NetworkEnvironment::Testnet,
            NetworkEnvironment::Testnet.chain_id(),
            2,
            &fp(0xbb),
        )
        .err()
        .expect("err");
        assert!(matches!(
            err,
            TrustBundleSequenceError::WrongEnvironment { .. }
        ));
        let bytes_after = std::fs::read(&path).unwrap();
        assert_eq!(bytes_before, bytes_after);
    }
}