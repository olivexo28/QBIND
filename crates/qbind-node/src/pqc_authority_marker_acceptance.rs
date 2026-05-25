//! Run 119 — shared mutating-surface accept-and-persist helper for the
//! Run 117/118 authority anti-rollback marker.
//!
//! # Purpose
//!
//! Compose the Run 118 derivation + compare primitives
//! ([`crate::pqc_authority_state::derive_authority_state_from_ratification`]
//! and [`crate::pqc_authority_state::prepare_marker_for_acceptance`])
//! with the Run 117 atomic persister
//! ([`crate::pqc_authority_state::persist_authority_state_atomic`])
//! into the smallest production-honest contract a mutating trust-bundle
//! surface needs to wire the marker:
//!
//! ```text
//!   verified ratification
//!   → derive marker (Run 118)
//!   → load + domain-validate persisted marker (Run 118)
//!   → compare candidate against persisted (Run 118)
//!   → typed accept-or-reject decision (Run 119)
//!   → [caller performs trust mutation + commit_sequence]
//!   → persist marker AFTER commit_sequence (Run 117/119)
//! ```
//!
//! The two halves are intentionally separate functions:
//!
//! * [`decide_marker_acceptance`] does compare-before-mutation and
//!   never writes to disk. Mutating surfaces MUST call this BEFORE any
//!   trust-state mutation begins.
//! * [`persist_accepted_marker_after_commit_boundary`] does the atomic
//!   write and is a strict no-op when the prior decision was an
//!   idempotent accept. Mutating surfaces MUST call this AFTER their
//!   existing `commit_sequence` boundary so a crash between the two
//!   leaves the authority marker stale-by-one (safely replayable as an
//!   `Upgrade` per Run 118 §D), never ahead of the trust-bundle
//!   sequence record.
//!
//! # Strict scope (Run 119)
//!
//! - Does NOT verify ratification — callers MUST run
//!   [`qbind_ledger::enforce_bundle_signing_key_ratification`] (or the
//!   Run 105 wrapper) first and pass the typed
//!   [`qbind_ledger::RatifiedBundleSigningKey`] result here.
//! - Does NOT mutate any trust state. The "mutation" in
//!   [`persist_accepted_marker_after_commit_boundary`] is restricted to
//!   the marker file itself.
//! - Does NOT implement signing-key rotation or revocation lifecycle.
//! - Does NOT invent a fake per-key monotonic authority sequence.
//! - Does NOT permit recovery of corrupt markers (no silent delete,
//!   no silent overwrite, no `--allow-authority-state-reset` here).
//! - Does NOT wire validation-only surfaces — Run 119 §scope.
//! - Persistence ordering follows the
//!   "**after `commit_sequence`**" rule from the task spec; a stronger
//!   ordering would require cross-store transactionality that the
//!   current storage layer does not provide.
//!
//! # Threading the helper into a mutating surface
//!
//! ```text
//!   // BEFORE mutation begins:
//!   let decision = decide_marker_acceptance(MarkerAcceptanceInputs { … })?;
//!
//!   // existing mutation pipeline (validate → snapshot → swap → evict
//!   // → commit_sequence) runs unchanged; if it fails, no marker
//!   // persistence happens because the decision is dropped.
//!
//!   // AFTER commit_sequence succeeds:
//!   persist_accepted_marker_after_commit_boundary(&decision)?;
//! ```
//!
//! If the caller does not have a verified ratification yet (e.g. the
//! ratification gate is `Skip` because DevNet did not opt in), it
//! simply skips both calls. New fields on the wiring layer are
//! `Option`-typed so behaviour is unchanged when the marker context
//! is not supplied.

use std::path::{Path, PathBuf};

use qbind_ledger::{BundleSigningRatification, RatifiedBundleSigningKey};
use qbind_types::{ChainId, NetworkEnvironment};

use crate::pqc_authority_state::{
    derive_authority_state_from_ratification, persist_authority_state_atomic,
    prepare_marker_for_acceptance, AuthorityStateComparison, AuthorityStateDerivationError,
    AuthorityStateDerivationInputs, AuthorityStateError, AuthorityStatePrepareOutcome,
    AuthorityStateUpdateSource, PersistentAuthorityStateRecord,
};

/// Run 119 — typed error returned by [`decide_marker_acceptance`] and
/// [`persist_accepted_marker_after_commit_boundary`]. Every variant is
/// a fail-closed condition; a mutating surface MUST refuse to begin
/// (or finish) trust mutation on any reject.
///
/// The variants are deliberately precise so the binary surface can
/// emit a single operator-facing log line that names the exact reason
/// rather than collapsing several distinct failure classes into a
/// generic "marker check failed".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutatingSurfaceMarkerError {
    /// Derivation refused before any persistence step — the verifier
    /// output was passed in inconsistently (caller bug) or the derived
    /// record failed Run 117 structural validation.
    DerivationFailed(AuthorityStateDerivationError),

    /// `load_authority_state` returned a fatal I/O / parse /
    /// unsupported-version / structural error on the on-disk record.
    /// The marker is unusable and MUST NOT be silently deleted or
    /// overwritten by this helper. Operator recovery is out of Run 119
    /// scope.
    LoadOrCorruption(AuthorityStateError),

    /// The on-disk marker is structurally valid but belongs to a
    /// different `(environment, chain_id, genesis_hash)` trust domain
    /// than the running runtime. Wrong-data-dir / wrong-snapshot-copy.
    PersistedDomainMismatch(AuthorityStateComparison),

    /// Authority-policy schema regression — persisted
    /// `authority_policy_version` is strictly higher than candidate's.
    /// Refuses the silent downgrade.
    PolicyVersionRegression {
        persisted_policy_version: u32,
        candidate_policy_version: u32,
    },

    /// Persisted `authority_sequence` is strictly higher than
    /// candidate's. Refuses the rollback.
    AuthoritySequenceRollback {
        persisted_sequence: u64,
        attempted_sequence: u64,
    },

    /// Equal `authority_sequence` but different
    /// `ratification_object_hash` — two distinct ratifications cannot
    /// share an authority_sequence without a per-key monotonic field
    /// (deferred to Run 120). Refuses the silent ratification swap.
    SameSequenceConflictingRatificationDigest {
        sequence: u64,
        persisted_hash: String,
        attempted_hash: String,
    },

    /// Equal `authority_sequence`, equal authority root, but different
    /// `ratified_bundle_signing_key_fingerprint`. Refuses the silent
    /// key swap.
    SameSequenceConflictingKey {
        sequence: u64,
        persisted_key_fingerprint: String,
        attempted_key_fingerprint: String,
    },

    /// Catch-all for any other [`AuthorityStateComparison`] reject
    /// variant that does not map to a more precise field above. The
    /// inner comparison carries the full reason text for the operator
    /// log line; the helper never silently turns a reject into an
    /// accept.
    Conflict(AuthorityStateComparison),

    /// Atomic persistence failed at the commit boundary. The candidate
    /// trust mutation has already landed; the marker is stale-by-one
    /// (safely replayable as an `Upgrade` per Run 118 §D) and the
    /// binary surface MUST surface the failure rather than silently
    /// pretending the marker was persisted.
    PersistFailure(AuthorityStateError),
}

impl std::fmt::Display for MutatingSurfaceMarkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DerivationFailed(e) => write!(
                f,
                "Run 119: authority-marker derivation refused: {} (fail closed; no trust mutation)",
                e
            ),
            Self::LoadOrCorruption(e) => write!(
                f,
                "Run 119: persisted authority-marker load/corruption: {} (fail closed; \
                 no trust mutation; this helper does NOT auto-recover corrupt markers)",
                e
            ),
            Self::PersistedDomainMismatch(c) => write!(
                f,
                "Run 119: persisted authority-marker belongs to a different trust domain: \
                 {} (fail closed; wrong-data-dir / wrong-snapshot-copy)",
                c
            ),
            Self::PolicyVersionRegression {
                persisted_policy_version,
                candidate_policy_version,
            } => write!(
                f,
                "Run 119: authority-marker policy-version regression rejected: persisted={} \
                 candidate={} (fail closed; schema downgrade is unsafe)",
                persisted_policy_version, candidate_policy_version
            ),
            Self::AuthoritySequenceRollback {
                persisted_sequence,
                attempted_sequence,
            } => write!(
                f,
                "Run 119: authority-marker rollback rejected: attempted authority_sequence={} \
                 is lower than persisted authority_sequence={} (fail closed)",
                attempted_sequence, persisted_sequence
            ),
            Self::SameSequenceConflictingRatificationDigest {
                sequence,
                persisted_hash,
                attempted_hash,
            } => write!(
                f,
                "Run 119: authority-marker same-sequence equivocation rejected: \
                 authority_sequence={} persisted_ratification_hash={} attempted_ratification_hash={} \
                 (fail closed; two distinct ratifications cannot share the same authority_sequence)",
                sequence, persisted_hash, attempted_hash
            ),
            Self::SameSequenceConflictingKey {
                sequence,
                persisted_key_fingerprint,
                attempted_key_fingerprint,
            } => write!(
                f,
                "Run 119: authority-marker same-sequence key conflict rejected: \
                 authority_sequence={} persisted_key_fingerprint={} attempted_key_fingerprint={} \
                 (fail closed; ratified bundle-signing key cannot be silently swapped at the \
                 same authority_sequence)",
                sequence, persisted_key_fingerprint, attempted_key_fingerprint
            ),
            Self::Conflict(c) => write!(
                f,
                "Run 119: authority-marker comparison rejected: {} (fail closed)",
                c
            ),
            Self::PersistFailure(e) => write!(
                f,
                "Run 119: authority-marker persist failure at commit boundary: {} \
                 (the trust-bundle mutation already committed; the on-disk authority marker \
                 is stale-by-one and will be re-derived on the next accepted mutation per the \
                 Run 118 §D crash-window rule. Operator MUST surface this failure)",
                e
            ),
        }
    }
}

impl std::error::Error for MutatingSurfaceMarkerError {}

/// Inputs to [`decide_marker_acceptance`]. Mirrors
/// [`AuthorityStateDerivationInputs`] but adds the marker-path and the
/// runtime trust-domain triple the prepare step needs.
///
/// Every field is required so the helper never falls back to ambient
/// state. The caller computes the values from its existing runtime
/// context (e.g. for the reload-apply binary path: the same values
/// already used by Run 105 to enforce ratification, plus the
/// `<data_dir>/pqc_authority_state.json` path).
#[derive(Debug, Clone)]
pub struct MarkerAcceptanceInputs<'a> {
    /// `<data_dir>/pqc_authority_state.json` per
    /// [`crate::pqc_authority_state::authority_state_file_path`].
    pub marker_path: &'a Path,
    /// Runtime network environment (e.g. from CLI / config).
    pub runtime_env: NetworkEnvironment,
    /// Runtime chain id.
    pub runtime_chain_id: ChainId,
    /// 64 lowercase hex chars of the canonical genesis hash this node
    /// booted against. Equals `compute_canonical_genesis_hash(...)` on
    /// the runtime genesis config.
    pub runtime_genesis_hash_hex: &'a str,
    /// Genesis-bound authority-policy version (Run 101).
    pub authority_policy_version: u32,
    /// Genesis-bound authority sequence anchor (Run 101).
    pub authority_sequence: u64,
    /// Optional genesis-bound authority epoch (Run 101).
    pub authority_epoch: Option<u64>,
    /// The verified ratification object whose acceptance is being
    /// recorded. Run 119 NEVER derives a marker from an unverified
    /// ratification because there is no path that produces a
    /// [`RatifiedBundleSigningKey`] without first calling Run 103/105.
    pub ratification: &'a BundleSigningRatification,
    /// The verifier's typed result identifying the ratified key.
    pub ratified: &'a RatifiedBundleSigningKey,
    /// Informational tag identifying which mutating surface called this
    /// helper. Never participates in the security digest.
    pub update_source: AuthorityStateUpdateSource,
    /// Wall-clock seconds for the audit-only `updated_at_unix_secs`
    /// field of the persisted record. Never participates in the
    /// security digest.
    pub updated_at_unix_secs: u64,
}

/// Result of [`decide_marker_acceptance`]. Carries the candidate
/// marker, the destination path, and a typed acceptance kind so the
/// caller can:
///
/// 1. Reject early on `is_reject == true` (which is exposed as `Err`
///    from [`decide_marker_acceptance`] itself — callers never see a
///    `MarkerAcceptDecision` on a reject path).
/// 2. Drop the decision if the existing mutation pipeline fails — no
///    marker persistence happens.
/// 3. Pass the decision to
///    [`persist_accepted_marker_after_commit_boundary`] after
///    `commit_sequence` succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkerAcceptDecision {
    /// Where the marker file lives. Owned so the decision can outlive
    /// the input borrow.
    marker_path: PathBuf,
    /// Candidate record derived from the verified ratification.
    candidate: PersistentAuthorityStateRecord,
    /// Whether [`persist_accepted_marker_after_commit_boundary`] should
    /// actually write the file. False on
    /// [`AuthorityStatePrepareOutcome::AlreadyPersistedIdempotent`] —
    /// the on-disk record is bit-for-bit identical so a rewrite would
    /// be wasted I/O AND a spurious change of the audit-only
    /// `updated_at_unix_secs` field.
    should_persist: bool,
    /// Typed kind for operator logging. Mirrors the
    /// [`AuthorityStatePrepareOutcome`] accept variants.
    kind: MarkerAcceptKind,
}

/// Audit-only acceptance kind retained on a [`MarkerAcceptDecision`]
/// for the binary's operator-log line. Mirrors the accept variants of
/// [`AuthorityStatePrepareOutcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerAcceptKind {
    /// No prior marker existed; this is a first-write.
    FirstWrite,
    /// A prior marker existed and matched bit-for-bit.
    Idempotent,
    /// A prior marker existed at a strictly lower `authority_sequence`.
    Upgrade {
        previous_sequence: u64,
        new_sequence: u64,
    },
}

impl std::fmt::Display for MarkerAcceptKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FirstWrite => write!(f, "first-write"),
            Self::Idempotent => write!(f, "idempotent"),
            Self::Upgrade {
                previous_sequence,
                new_sequence,
            } => write!(f, "upgrade {} -> {}", previous_sequence, new_sequence),
        }
    }
}

impl MarkerAcceptDecision {
    /// Destination marker file path.
    pub fn marker_path(&self) -> &Path {
        &self.marker_path
    }

    /// Derived candidate marker.
    pub fn candidate(&self) -> &PersistentAuthorityStateRecord {
        &self.candidate
    }

    /// Whether the post-commit persist step will actually write.
    pub fn should_persist(&self) -> bool {
        self.should_persist
    }

    /// Audit-only acceptance kind.
    pub fn kind(&self) -> MarkerAcceptKind {
        self.kind
    }
}

/// Run 119 — derive a candidate marker from a verified ratification,
/// load + domain-validate any persisted marker, compare the candidate
/// against the persisted marker, and produce a typed accept-or-reject
/// outcome.
///
/// This function performs **no** disk writes. It is safe to call
/// before the existing trust-mutation pipeline begins; if mutation
/// then fails, dropping the decision leaves the on-disk marker
/// untouched.
///
/// # Ordering
///
/// 1. Derive candidate via
///    [`derive_authority_state_from_ratification`]. A bug-class derivation
///    failure (e.g. the caller wired the verifier output incorrectly)
///    surfaces as [`MutatingSurfaceMarkerError::DerivationFailed`].
/// 2. Load + structurally validate any persisted marker via
///    [`prepare_marker_for_acceptance`]. Load failure →
///    [`MutatingSurfaceMarkerError::LoadOrCorruption`]; persisted-domain
///    mismatch → [`MutatingSurfaceMarkerError::PersistedDomainMismatch`].
/// 3. Compare. Accept variants → `Ok(decision)`; reject variants are
///    routed to the most precise error variant available so the
///    operator log line does not collapse e.g. a `PolicyVersionRegression`
///    into a generic `Conflict`.
///
/// # Fail-closed guarantees
///
/// - The function never silently turns a reject comparison into an
///   accept.
/// - The function never repairs, deletes, or overwrites a corrupt
///   persisted marker.
/// - The function never reads or writes any file other than the
///   supplied `marker_path`.
pub fn decide_marker_acceptance(
    inputs: MarkerAcceptanceInputs<'_>,
) -> Result<MarkerAcceptDecision, MutatingSurfaceMarkerError> {
    // Step 1: derive candidate marker from the verified ratification.
    let candidate = derive_authority_state_from_ratification(AuthorityStateDerivationInputs {
        runtime_env: inputs.runtime_env,
        runtime_chain_id: inputs.runtime_chain_id,
        runtime_genesis_hash_hex: inputs.runtime_genesis_hash_hex,
        authority_policy_version: inputs.authority_policy_version,
        authority_sequence: inputs.authority_sequence,
        authority_epoch: inputs.authority_epoch,
        ratification: inputs.ratification,
        ratified: inputs.ratified,
        update_source: inputs.update_source,
        updated_at_unix_secs: inputs.updated_at_unix_secs,
    })
    .map_err(MutatingSurfaceMarkerError::DerivationFailed)?;

    // Step 2 + 3: load + domain-validate + compare via the Run 118
    // helper. Single source of truth — Run 119 never re-implements the
    // comparison logic.
    let outcome = prepare_marker_for_acceptance(
        inputs.marker_path,
        &candidate,
        inputs.runtime_env,
        inputs.runtime_chain_id,
        inputs.runtime_genesis_hash_hex,
    );

    match outcome {
        AuthorityStatePrepareOutcome::FirstWrite => Ok(MarkerAcceptDecision {
            marker_path: inputs.marker_path.to_path_buf(),
            candidate,
            should_persist: true,
            kind: MarkerAcceptKind::FirstWrite,
        }),
        AuthorityStatePrepareOutcome::AlreadyPersistedIdempotent => Ok(MarkerAcceptDecision {
            marker_path: inputs.marker_path.to_path_buf(),
            candidate,
            should_persist: false,
            kind: MarkerAcceptKind::Idempotent,
        }),
        AuthorityStatePrepareOutcome::Upgrade {
            previous_sequence,
            new_sequence,
        } => Ok(MarkerAcceptDecision {
            marker_path: inputs.marker_path.to_path_buf(),
            candidate,
            should_persist: true,
            kind: MarkerAcceptKind::Upgrade {
                previous_sequence,
                new_sequence,
            },
        }),
        AuthorityStatePrepareOutcome::LoadFailedFailClosed(e) => {
            Err(MutatingSurfaceMarkerError::LoadOrCorruption(e))
        }
        AuthorityStatePrepareOutcome::PersistedDomainMismatch(c) => {
            Err(MutatingSurfaceMarkerError::PersistedDomainMismatch(c))
        }
        AuthorityStatePrepareOutcome::ConflictReject(c) => Err(map_conflict_to_error(c)),
    }
}

/// Map a [`AuthorityStateComparison`] reject variant into the most
/// precise [`MutatingSurfaceMarkerError`] available. Catches the
/// distinct fail-closed conditions called out in Run 119 §F (typed
/// error propagation):
///
/// * `RollbackRefused` → `AuthoritySequenceRollback`
/// * `SameSequenceConflictingHash` → `SameSequenceConflictingRatificationDigest`
/// * `SameSequenceConflictingKey` → `SameSequenceConflictingKey`
/// * `PolicyVersionRegression` → `PolicyVersionRegression`
/// * everything else (including domain-mismatch surfaced via the
///   compare path rather than the validate-domain path) → `Conflict`
fn map_conflict_to_error(c: AuthorityStateComparison) -> MutatingSurfaceMarkerError {
    match c {
        AuthorityStateComparison::RollbackRefused {
            persisted_sequence,
            attempted_sequence,
        } => MutatingSurfaceMarkerError::AuthoritySequenceRollback {
            persisted_sequence,
            attempted_sequence,
        },
        AuthorityStateComparison::SameSequenceConflictingHash {
            sequence,
            persisted_hash,
            attempted_hash,
        } => MutatingSurfaceMarkerError::SameSequenceConflictingRatificationDigest {
            sequence,
            persisted_hash,
            attempted_hash,
        },
        AuthorityStateComparison::SameSequenceConflictingKey {
            sequence,
            persisted_key_fingerprint,
            attempted_key_fingerprint,
        } => MutatingSurfaceMarkerError::SameSequenceConflictingKey {
            sequence,
            persisted_key_fingerprint,
            attempted_key_fingerprint,
        },
        AuthorityStateComparison::PolicyVersionRegression {
            persisted_policy_version,
            candidate_policy_version,
        } => MutatingSurfaceMarkerError::PolicyVersionRegression {
            persisted_policy_version,
            candidate_policy_version,
        },
        other => MutatingSurfaceMarkerError::Conflict(other),
    }
}

/// Run 119 — persist a previously-accepted marker after the existing
/// `commit_sequence` boundary.
///
/// This is the only place the helper layer touches disk. The function
/// is a no-op when [`MarkerAcceptDecision::should_persist`] is false
/// (i.e. the prior comparison was `AlreadyPersistedIdempotent`); the
/// caller may unconditionally invoke it after a successful mutation
/// without checking `should_persist` themselves.
///
/// On a persist failure the helper returns
/// [`MutatingSurfaceMarkerError::PersistFailure`]. The mutating
/// surface MUST surface that failure operatorially — the trust-bundle
/// sequence has already advanced, so the on-disk marker is now
/// stale-by-one. Per Run 118 §D this is intentionally safe to replay
/// as an `Upgrade` on the next accepted ratification, but the
/// operator must know it happened.
pub fn persist_accepted_marker_after_commit_boundary(
    decision: &MarkerAcceptDecision,
) -> Result<(), MutatingSurfaceMarkerError> {
    if !decision.should_persist {
        return Ok(());
    }
    persist_authority_state_atomic(&decision.marker_path, &decision.candidate)
        .map_err(MutatingSurfaceMarkerError::PersistFailure)
}

// =============================================================================
// Run 123 — validation-only authority marker conflict check helper
// =============================================================================

/// Run 123 — typed error returned by [`verify_marker_for_validation_only`].
/// Every variant is a fail-closed condition; a validation-only surface MUST
/// reject the candidate trust bundle / peer-candidate envelope when any
/// variant is returned.
///
/// This enum is deliberately a superset of the reject reasons
/// [`MutatingSurfaceMarkerError`] can produce, minus the persist-failure
/// variant (validation-only paths never persist). It shares the same precision
/// guarantee: the binary surface can emit a single operator-facing log line
/// that names the exact reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationOnlyMarkerError {
    /// Derivation refused — the verifier output was passed in inconsistently
    /// or the derived record failed Run 117 structural validation.
    DerivationFailed(AuthorityStateDerivationError),

    /// `load_authority_state` returned a fatal I/O / parse / unsupported-
    /// version / structural error on the on-disk record. The marker is
    /// unusable and MUST NOT be silently deleted or overwritten.
    LoadOrCorruption(AuthorityStateError),

    /// The on-disk marker is structurally valid but belongs to a different
    /// `(environment, chain_id, genesis_hash)` trust domain.
    PersistedDomainMismatch(AuthorityStateComparison),

    /// Authority-policy schema regression.
    PolicyVersionRegression {
        persisted_policy_version: u32,
        candidate_policy_version: u32,
    },

    /// Persisted `authority_sequence` is strictly higher than candidate's.
    AuthoritySequenceRollback {
        persisted_sequence: u64,
        attempted_sequence: u64,
    },

    /// Equal `authority_sequence` but different `ratification_object_hash`.
    SameSequenceConflictingRatificationDigest {
        sequence: u64,
        persisted_hash: String,
        attempted_hash: String,
    },

    /// Equal `authority_sequence`, equal authority root, but different
    /// `ratified_bundle_signing_key_fingerprint`.
    SameSequenceConflictingKey {
        sequence: u64,
        persisted_key_fingerprint: String,
        attempted_key_fingerprint: String,
    },

    /// Catch-all for any other reject variant.
    Conflict(AuthorityStateComparison),
}

impl std::fmt::Display for ValidationOnlyMarkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DerivationFailed(e) => write!(
                f,
                "Run 123: validation-only authority-marker derivation refused: {} \
                 (fail closed; candidate rejected; no marker persistence)",
                e
            ),
            Self::LoadOrCorruption(e) => write!(
                f,
                "Run 123: persisted authority-marker load/corruption: {} \
                 (fail closed; candidate rejected; no marker persistence; \
                 this helper does NOT auto-recover corrupt markers)",
                e
            ),
            Self::PersistedDomainMismatch(c) => write!(
                f,
                "Run 123: persisted authority-marker belongs to a different trust domain: \
                 {} (fail closed; candidate rejected; no marker persistence; \
                 wrong-data-dir / wrong-snapshot-copy)",
                c
            ),
            Self::PolicyVersionRegression {
                persisted_policy_version,
                candidate_policy_version,
            } => write!(
                f,
                "Run 123: authority-marker policy-version regression rejected: persisted={} \
                 candidate={} (fail closed; no marker persistence)",
                persisted_policy_version, candidate_policy_version
            ),
            Self::AuthoritySequenceRollback {
                persisted_sequence,
                attempted_sequence,
            } => write!(
                f,
                "Run 123: authority-marker rollback rejected: attempted authority_sequence={} \
                 is lower than persisted authority_sequence={} \
                 (fail closed; no marker persistence)",
                attempted_sequence, persisted_sequence
            ),
            Self::SameSequenceConflictingRatificationDigest {
                sequence,
                persisted_hash,
                attempted_hash,
            } => write!(
                f,
                "Run 123: authority-marker same-sequence equivocation rejected: \
                 authority_sequence={} persisted_ratification_hash={} \
                 attempted_ratification_hash={} \
                 (fail closed; no marker persistence)",
                sequence, persisted_hash, attempted_hash
            ),
            Self::SameSequenceConflictingKey {
                sequence,
                persisted_key_fingerprint,
                attempted_key_fingerprint,
            } => write!(
                f,
                "Run 123: authority-marker same-sequence key conflict rejected: \
                 authority_sequence={} persisted_key_fingerprint={} \
                 attempted_key_fingerprint={} (fail closed; no marker persistence)",
                sequence, persisted_key_fingerprint, attempted_key_fingerprint
            ),
            Self::Conflict(c) => write!(
                f,
                "Run 123: authority-marker comparison rejected: {} \
                 (fail closed; no marker persistence)",
                c
            ),
        }
    }
}

impl std::error::Error for ValidationOnlyMarkerError {}

/// Run 123 — typed outcome of [`verify_marker_for_validation_only`] on
/// the accept path. Distinguishes the reason validation passed so
/// operator log lines are precise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationOnlyMarkerAcceptReason {
    /// No persisted marker exists yet. The candidate is otherwise fully
    /// ratified; the validation-only surface allows it through because
    /// it cannot be expected to reject a valid candidate before any
    /// mutating surface has ever run. **No marker is written.**
    ///
    /// Policy decision (Run 123): missing local marker on a validation-
    /// only surface is treated as "first-seen pass" — the candidate
    /// cannot be compared against something that does not exist, and
    /// rejecting every candidate before the first mutating surface run
    /// would make operator workflows impossible. This is safe because:
    /// (a) the candidate is already fully ratified by Run 103/105;
    /// (b) no trust mutation occurs from a validation-only surface; and
    /// (c) the next mutating surface will write the marker and future
    /// validation-only checks will compare against it.
    NoPersistedMarkerYet,

    /// The derived candidate marker is identical to the persisted marker
    /// (ignoring audit-only fields). Safe to accept.
    Idempotent,

    /// The candidate's `authority_sequence` is strictly higher than the
    /// persisted marker. This represents a legitimate upgrade that a
    /// future mutating surface will persist. Validation passes.
    UpgradeCompatible {
        previous_sequence: u64,
        new_sequence: u64,
    },
}

impl std::fmt::Display for ValidationOnlyMarkerAcceptReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPersistedMarkerYet => write!(
                f,
                "no-persisted-marker-yet (first-seen pass; no marker persistence)"
            ),
            Self::Idempotent => write!(f, "idempotent (same marker; no marker persistence)"),
            Self::UpgradeCompatible {
                previous_sequence,
                new_sequence,
            } => write!(
                f,
                "upgrade-compatible {} -> {} (no marker persistence)",
                previous_sequence, new_sequence
            ),
        }
    }
}

/// Inputs to [`verify_marker_for_validation_only`]. Same shape as
/// [`MarkerAcceptanceInputs`] minus the `update_source` and
/// `updated_at_unix_secs` fields (which are audit-only and only
/// meaningful for persisting surfaces).
#[derive(Debug, Clone)]
pub struct ValidationOnlyMarkerInputs<'a> {
    /// `<data_dir>/pqc_authority_state.json`.
    pub marker_path: &'a Path,
    /// Runtime network environment.
    pub runtime_env: NetworkEnvironment,
    /// Runtime chain id.
    pub runtime_chain_id: ChainId,
    /// 64 lowercase hex chars of the canonical genesis hash.
    pub runtime_genesis_hash_hex: &'a str,
    /// Genesis-bound authority-policy version (Run 101).
    pub authority_policy_version: u32,
    /// Genesis-bound authority sequence anchor (Run 101).
    pub authority_sequence: u64,
    /// Optional genesis-bound authority epoch (Run 101).
    pub authority_epoch: Option<u64>,
    /// The verified ratification object.
    pub ratification: &'a BundleSigningRatification,
    /// The verifier's typed result identifying the ratified key.
    pub ratified: &'a RatifiedBundleSigningKey,
}

/// Run 123 — validation-only authority marker conflict check.
///
/// Composes:
///
/// 1. [`derive_authority_state_from_ratification`] — derive a candidate
///    marker from the verified ratification.
/// 2. [`prepare_marker_for_acceptance`] — load + domain-validate any
///    persisted marker and compare against the candidate.
/// 3. Map the outcome to a validation-only accept/reject result.
///
/// # Critical guarantees
///
/// - **Never persists marker.** There is no call to
///   [`persist_authority_state_atomic`] or any other disk write in this
///   function. The validation-only surface cannot advance the on-disk
///   marker state under any code path.
/// - **Fail-closed on conflict/corruption/wrong-domain.** Every
///   non-accept comparison outcome is surfaced as a typed error.
/// - **Missing marker → pass.** When no marker file exists, the
///   candidate is otherwise fully ratified and the validation-only
///   surface cannot be expected to reject it (see
///   [`ValidationOnlyMarkerAcceptReason::NoPersistedMarkerYet`] docs).
///
/// # Ordering in validation-only surfaces
///
/// Callers MUST invoke this AFTER ratification verification succeeds
/// and BEFORE emitting a validation-success verdict / granting
/// rebroadcast eligibility.
pub fn verify_marker_for_validation_only(
    inputs: ValidationOnlyMarkerInputs<'_>,
) -> Result<ValidationOnlyMarkerAcceptReason, ValidationOnlyMarkerError> {
    // Step 1: derive candidate marker. Use a placeholder update_source
    // and timestamp — they are excluded from the canonical digest and
    // never persisted from this path.
    let candidate = derive_authority_state_from_ratification(AuthorityStateDerivationInputs {
        runtime_env: inputs.runtime_env,
        runtime_chain_id: inputs.runtime_chain_id,
        runtime_genesis_hash_hex: inputs.runtime_genesis_hash_hex,
        authority_policy_version: inputs.authority_policy_version,
        authority_sequence: inputs.authority_sequence,
        authority_epoch: inputs.authority_epoch,
        ratification: inputs.ratification,
        ratified: inputs.ratified,
        update_source: AuthorityStateUpdateSource::TestOrFixture,
        updated_at_unix_secs: 0,
    })
    .map_err(ValidationOnlyMarkerError::DerivationFailed)?;

    // Step 2 + 3: load + domain-validate + compare via the Run 118
    // helper. Single source of truth.
    let outcome = prepare_marker_for_acceptance(
        inputs.marker_path,
        &candidate,
        inputs.runtime_env,
        inputs.runtime_chain_id,
        inputs.runtime_genesis_hash_hex,
    );

    match outcome {
        AuthorityStatePrepareOutcome::FirstWrite => {
            Ok(ValidationOnlyMarkerAcceptReason::NoPersistedMarkerYet)
        }
        AuthorityStatePrepareOutcome::AlreadyPersistedIdempotent => {
            Ok(ValidationOnlyMarkerAcceptReason::Idempotent)
        }
        AuthorityStatePrepareOutcome::Upgrade {
            previous_sequence,
            new_sequence,
        } => Ok(ValidationOnlyMarkerAcceptReason::UpgradeCompatible {
            previous_sequence,
            new_sequence,
        }),
        AuthorityStatePrepareOutcome::LoadFailedFailClosed(e) => {
            Err(ValidationOnlyMarkerError::LoadOrCorruption(e))
        }
        AuthorityStatePrepareOutcome::PersistedDomainMismatch(c) => {
            Err(ValidationOnlyMarkerError::PersistedDomainMismatch(c))
        }
        AuthorityStatePrepareOutcome::ConflictReject(c) => {
            Err(map_conflict_to_validation_only_error(c))
        }
    }
}

/// Map a [`AuthorityStateComparison`] reject variant into the most
/// precise [`ValidationOnlyMarkerError`] available.
fn map_conflict_to_validation_only_error(
    c: AuthorityStateComparison,
) -> ValidationOnlyMarkerError {
    match c {
        AuthorityStateComparison::RollbackRefused {
            persisted_sequence,
            attempted_sequence,
        } => ValidationOnlyMarkerError::AuthoritySequenceRollback {
            persisted_sequence,
            attempted_sequence,
        },
        AuthorityStateComparison::SameSequenceConflictingHash {
            sequence,
            persisted_hash,
            attempted_hash,
        } => ValidationOnlyMarkerError::SameSequenceConflictingRatificationDigest {
            sequence,
            persisted_hash,
            attempted_hash,
        },
        AuthorityStateComparison::SameSequenceConflictingKey {
            sequence,
            persisted_key_fingerprint,
            attempted_key_fingerprint,
        } => ValidationOnlyMarkerError::SameSequenceConflictingKey {
            sequence,
            persisted_key_fingerprint,
            attempted_key_fingerprint,
        },
        AuthorityStateComparison::PolicyVersionRegression {
            persisted_policy_version,
            candidate_policy_version,
        } => ValidationOnlyMarkerError::PolicyVersionRegression {
            persisted_policy_version,
            candidate_policy_version,
        },
        other => ValidationOnlyMarkerError::Conflict(other),
    }
}

// =============================================================================
// Run 132 — v2 validation-only typed failures and helpers
// =============================================================================

/// Run 132 — typed errors for v2 validation-only marker checks.
///
/// Precise enough for operator-facing log lines. Covers the v2 failure
/// taxonomy from Run 132 task §E. Every variant is a fail-closed condition;
/// the validation-only surface MUST reject the candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationOnlyMarkerV2Error {
    /// The sidecar file has an unknown or unsupported ratification schema
    /// version (not 1 or 2).
    UnknownRatificationSchema {
        got: Option<String>,
    },
    /// The sidecar file is structurally malformed for its declared schema
    /// version.
    MalformedSidecar {
        schema_version: u32,
        reason: String,
    },
    /// The v2 verifier (Run 130) rejected the ratification object.
    V2VerifierFailure(qbind_ledger::RatificationV2Failure),
    /// The v2 marker derivation (Run 131) failed.
    V2MarkerDerivationFailure(crate::pqc_authority_state::AuthorityStateDerivationV2Error),
    /// The v2 marker comparison (Run 131) rejected the candidate.
    V2MarkerComparisonFailure(crate::pqc_authority_state::AuthorityMarkerV2ComparisonOutcome),
    /// A v1 ratification was supplied but a v2 marker already exists on
    /// disk. This is the v1-after-v2 downgrade refusal (Run 129/131).
    V1AfterV2DowngradeRefused,
    /// The persisted marker has a lower v2 sequence than the candidate —
    /// this should be a pass, but recorded separately for audit when the
    /// comparison API returns an unexpected outcome.
    LowerV2SequenceRefused {
        persisted_sequence: u64,
        candidate_sequence: u64,
    },
    /// Same v2 authority_domain_sequence but different ratification v2
    /// digest — equivocation.
    SameSequenceDifferentDigestRefused {
        sequence: u64,
        persisted_digest: String,
        candidate_digest: String,
    },
    /// The local persisted marker is corrupt or an unsupported version.
    UnsupportedMarkerVersion {
        reason: String,
    },
    /// The local persisted marker could not be loaded (I/O or parse).
    CorruptLocalMarker(crate::pqc_authority_state::AuthorityStateError),
}

impl std::fmt::Display for ValidationOnlyMarkerV2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownRatificationSchema { got } => write!(
                f,
                "Run 132: unknown ratification schema version (got {:?}); fail closed",
                got
            ),
            Self::MalformedSidecar {
                schema_version,
                reason,
            } => write!(
                f,
                "Run 132: malformed sidecar (schema_version={}, reason={}); fail closed",
                schema_version, reason
            ),
            Self::V2VerifierFailure(e) => write!(
                f,
                "Run 132: v2 ratification verifier failure: {}; fail closed; \
                 no marker persistence",
                e
            ),
            Self::V2MarkerDerivationFailure(e) => write!(
                f,
                "Run 132: v2 marker derivation failure: {}; fail closed; \
                 no marker persistence",
                e
            ),
            Self::V2MarkerComparisonFailure(o) => write!(
                f,
                "Run 132: v2 marker comparison rejected: {:?}; fail closed; \
                 no marker persistence",
                o
            ),
            Self::V1AfterV2DowngradeRefused => write!(
                f,
                "Run 132: v1 ratification after v2 marker — downgrade refused; \
                 fail closed; no marker persistence"
            ),
            Self::LowerV2SequenceRefused {
                persisted_sequence,
                candidate_sequence,
            } => write!(
                f,
                "Run 132: v2 lower sequence refused: persisted={} candidate={}; \
                 fail closed; no marker persistence",
                persisted_sequence, candidate_sequence
            ),
            Self::SameSequenceDifferentDigestRefused {
                sequence,
                persisted_digest,
                candidate_digest,
            } => write!(
                f,
                "Run 132: v2 same-sequence different-digest refused: seq={} \
                 persisted_digest={} candidate_digest={}; fail closed; no marker persistence",
                sequence, persisted_digest, candidate_digest
            ),
            Self::UnsupportedMarkerVersion { reason } => write!(
                f,
                "Run 132: unsupported persisted marker version: {}; fail closed; \
                 no marker persistence",
                reason
            ),
            Self::CorruptLocalMarker(e) => write!(
                f,
                "Run 132: corrupt local marker: {}; fail closed; no marker persistence",
                e
            ),
        }
    }
}

impl std::error::Error for ValidationOnlyMarkerV2Error {}

/// Run 132 — typed accept reasons for v2 validation-only marker checks.
///
/// Analogous to [`ValidationOnlyMarkerAcceptReason`] for v1, but covers
/// v2 monotonic-sequence outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationOnlyMarkerV2AcceptReason {
    /// No persisted marker exists. The candidate is fully verified; the
    /// validation-only surface allows it through. No marker is written.
    NoPersistedMarkerYet,
    /// The derived v2 candidate marker is identical to the persisted v2
    /// marker. Safe idempotent pass.
    Idempotent,
    /// The candidate's `authority_domain_sequence` is strictly higher
    /// than the persisted marker. Legitimate upgrade; no persistence.
    UpgradeCompatible {
        previous_sequence: u64,
        new_sequence: u64,
    },
    /// A v2 candidate after a v1 persisted marker — explicit migration
    /// candidate. Validation-only surface accepts but does NOT persist
    /// the migration.
    V2AfterV1MigrationCandidate,
}

impl std::fmt::Display for ValidationOnlyMarkerV2AcceptReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPersistedMarkerYet => write!(
                f,
                "no-persisted-marker-yet (v2 first-seen pass; no marker persistence)"
            ),
            Self::Idempotent => write!(
                f,
                "v2 idempotent (same marker; no marker persistence)"
            ),
            Self::UpgradeCompatible {
                previous_sequence,
                new_sequence,
            } => write!(
                f,
                "v2 upgrade-compatible {} -> {} (no marker persistence)",
                previous_sequence, new_sequence
            ),
            Self::V2AfterV1MigrationCandidate => write!(
                f,
                "v2-after-v1 migration candidate (validation-only; no marker persistence)"
            ),
        }
    }
}

/// Inputs to [`verify_marker_for_validation_only_v2`].
#[derive(Debug, Clone)]
pub struct ValidationOnlyMarkerV2Inputs<'a> {
    /// `<data_dir>/pqc_authority_state.json`.
    pub marker_path: &'a Path,
    /// Runtime network environment.
    pub runtime_env: NetworkEnvironment,
    /// Runtime chain id.
    pub runtime_chain_id: ChainId,
    /// 64 lowercase hex chars of the canonical genesis hash.
    pub runtime_genesis_hash_hex: &'a str,
    /// The verified v2 ratification object.
    pub ratification: &'a qbind_ledger::BundleSigningRatificationV2,
    /// The verifier's typed result identifying the ratified key (v2).
    pub ratified: &'a qbind_ledger::RatifiedBundleSigningKeyV2,
}

/// Run 132 — validation-only v2 authority marker conflict check.
///
/// Composes:
///
/// 1. [`derive_authority_state_v2_from_ratification`] — derive a v2 candidate
///    marker from the verified v2 ratification.
/// 2. Load the persisted versioned marker.
/// 3. [`compare_authority_marker_v2`] — compare candidate against persisted.
/// 4. Map the outcome to a validation-only accept/reject result.
///
/// # Critical guarantees
///
/// - **Never persists marker.** There is no call to any disk write in this
///   function. The validation-only surface cannot advance the on-disk
///   marker state under any code path.
/// - **Fail-closed on conflict/corruption/wrong-domain.**
/// - **Missing marker → pass.**
pub fn verify_marker_for_validation_only_v2(
    inputs: ValidationOnlyMarkerV2Inputs<'_>,
) -> Result<ValidationOnlyMarkerV2AcceptReason, ValidationOnlyMarkerV2Error> {
    use crate::pqc_authority_state::{
        derive_authority_state_v2_from_ratification, load_authority_state_versioned,
        AuthorityMarkerV2ComparisonOutcome, AuthorityStateDerivationV2Inputs,
        AuthorityStateUpdateSource, compare_authority_marker_v2,
    };

    // Step 1: derive v2 candidate marker. Placeholder update_source and
    // timestamp — excluded from canonical digest and never persisted.
    let candidate = derive_authority_state_v2_from_ratification(
        AuthorityStateDerivationV2Inputs {
            runtime_env: inputs.runtime_env,
            runtime_chain_id: inputs.runtime_chain_id,
            runtime_genesis_hash_hex: inputs.runtime_genesis_hash_hex,
            ratification: inputs.ratification,
            ratified: inputs.ratified,
            update_source: AuthorityStateUpdateSource::TestOrFixture,
            updated_at_unix_secs: 0,
        },
    )
    .map_err(ValidationOnlyMarkerV2Error::V2MarkerDerivationFailure)?;

    // Step 2: load persisted versioned marker.
    let persisted = load_authority_state_versioned(inputs.marker_path)
        .map_err(ValidationOnlyMarkerV2Error::CorruptLocalMarker)?;

    // Step 3: compare v2 candidate against persisted.
    let outcome = compare_authority_marker_v2(persisted.as_ref(), &candidate);

    // Step 4: map outcome to validation-only accept/reject.
    match outcome {
        AuthorityMarkerV2ComparisonOutcome::FirstV2MarkerAccepted => {
            Ok(ValidationOnlyMarkerV2AcceptReason::NoPersistedMarkerYet)
        }
        AuthorityMarkerV2ComparisonOutcome::SameV2MarkerIdempotent => {
            Ok(ValidationOnlyMarkerV2AcceptReason::Idempotent)
        }
        AuthorityMarkerV2ComparisonOutcome::HigherSequenceAccepted {
            persisted_sequence,
            candidate_sequence,
        } => Ok(ValidationOnlyMarkerV2AcceptReason::UpgradeCompatible {
            previous_sequence: persisted_sequence,
            new_sequence: candidate_sequence,
        }),
        AuthorityMarkerV2ComparisonOutcome::V2AfterV1ExplicitMigrationAllowed => {
            Ok(ValidationOnlyMarkerV2AcceptReason::V2AfterV1MigrationCandidate)
        }
        // All reject outcomes:
        AuthorityMarkerV2ComparisonOutcome::LowerSequenceRejected {
            persisted_sequence,
            candidate_sequence,
        } => Err(ValidationOnlyMarkerV2Error::LowerV2SequenceRefused {
            persisted_sequence,
            candidate_sequence,
        }),
        AuthorityMarkerV2ComparisonOutcome::SameSequenceDifferentDigestRejected {
            sequence,
            persisted_digest,
            candidate_digest,
        } => Err(ValidationOnlyMarkerV2Error::SameSequenceDifferentDigestRefused {
            sequence,
            persisted_digest,
            candidate_digest,
        }),
        AuthorityMarkerV2ComparisonOutcome::V1AfterV2Rejected => {
            Err(ValidationOnlyMarkerV2Error::V1AfterV2DowngradeRefused)
        }
        AuthorityMarkerV2ComparisonOutcome::MalformedOrUnsupportedMarkerRejected { reason } => {
            Err(ValidationOnlyMarkerV2Error::UnsupportedMarkerVersion { reason })
        }
        // Legacy v1 comparison outcome — should not occur in v2 path,
        // but map defensively.
        AuthorityMarkerV2ComparisonOutcome::LegacyV1(_) => {
            Err(ValidationOnlyMarkerV2Error::V2MarkerComparisonFailure(outcome))
        }
        // Domain-mismatch rejects.
        other => Err(ValidationOnlyMarkerV2Error::V2MarkerComparisonFailure(other)),
    }
}

/// Run 132 — unified validation-only result for v1/v2 dispatch.
///
/// The validation-only surfaces use this to report the final outcome
/// after v1/v2 dispatch without leaking version specifics into the
/// surface wiring code.
#[derive(Debug)]
pub enum ValidationOnlyVersionedOutcome {
    V1Accept(ValidationOnlyMarkerAcceptReason),
    V2Accept(ValidationOnlyMarkerV2AcceptReason),
}

impl std::fmt::Display for ValidationOnlyVersionedOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V1Accept(r) => write!(f, "v1: {}", r),
            Self::V2Accept(r) => write!(f, "v2: {}", r),
        }
    }
}

/// Run 132 — unified validation-only error for v1/v2 dispatch.
#[derive(Debug)]
pub enum ValidationOnlyVersionedError {
    V1(ValidationOnlyMarkerError),
    V2(ValidationOnlyMarkerV2Error),
}

impl std::fmt::Display for ValidationOnlyVersionedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V1(e) => write!(f, "{}", e),
            Self::V2(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for ValidationOnlyVersionedError {}

// =============================================================================
// Run 134 — v2 mutating-surface accept-and-persist helpers
// =============================================================================
//
// These mirror the Run 119 v1 helpers (`decide_marker_acceptance` /
// `persist_accepted_marker_after_commit_boundary`) but operate on v2
// ratification objects and v2 authority markers.
//
// Strict scope:
//
// * Does NOT verify the v2 ratification — callers MUST run
//   [`qbind_ledger::verify_bundle_signing_key_ratification_v2`] first and
//   pass the typed [`qbind_ledger::RatifiedBundleSigningKeyV2`] result here.
// * Compare-before-mutation (Run 131 `compare_authority_marker_v2`); the
//   helper NEVER writes to disk in [`decide_marker_acceptance_v2`].
// * Post-commit persistence
//   ([`persist_accepted_v2_marker_after_commit_boundary`]) writes only when
//   the prior decision was a v2 first-write / v2 upgrade / explicit v1→v2
//   migration. Idempotent accepts are a strict no-op (no rewrite).
// * v1-after-v2 rejection is impossible by signature: this helper consumes
//   a v2 ratification, so v1 candidates cannot reach it. The dispatch at the
//   binary surface ensures the v1 path is taken when a v1 sidecar is
//   present, and a v2 marker on disk in front of a v1 sidecar is refused
//   on the v1 side via the existing v1 reload-apply route (Run 131
//   `prepare_v2_marker_for_acceptance` returns `V1AfterV2Rejected` when
//   the binary dispatches to the v2 path with a v1 candidate, which we
//   never do here).
// * Does NOT implement signing-key rotation / revocation lifecycle. The
//   helper accepts the typed Run 130 verifier outcome verbatim; the
//   marker layer preserves the lifecycle-action / previous-key linkage
//   that Run 131 derivation produced.

/// Run 134 — typed errors for v2 mutating-surface accept / persist.
///
/// Every variant is a fail-closed condition: the mutating surface MUST
/// refuse to begin (or finish) trust mutation on any reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutatingSurfaceMarkerV2Error {
    /// v2 marker derivation refused (caller bug or verifier output
    /// inconsistent with the candidate ratification).
    DerivationFailed(crate::pqc_authority_state::AuthorityStateDerivationV2Error),

    /// `load_authority_state_versioned` returned a fatal I/O / parse /
    /// unsupported-version / structural error. The on-disk marker is
    /// unusable; the helper MUST NOT silently delete or overwrite it.
    LoadOrCorruption(crate::pqc_authority_state::AuthorityStateError),

    /// On-disk marker belongs to a different trust domain
    /// (environment / chain_id / genesis_hash / authority_root_fingerprint).
    /// Wrong-data-dir / wrong-snapshot-copy.
    PersistedDomainMismatch(crate::pqc_authority_state::AuthorityMarkerV2ComparisonOutcome),

    /// Persisted v2 `authority_domain_sequence` is strictly higher than
    /// the candidate's. Refuses the rollback.
    LowerV2SequenceRefused {
        persisted_sequence: u64,
        attempted_sequence: u64,
    },

    /// Equal `authority_domain_sequence`, different ratification-v2 digest.
    /// Refuses the silent ratification swap.
    SameSequenceConflictingDigest {
        sequence: u64,
        persisted_digest: String,
        attempted_digest: String,
    },

    /// Equal `authority_domain_sequence`, equal digest, but mismatching
    /// active-key / lifecycle-action linkage. Refuses the silent linkage
    /// swap.
    SameSequenceConflictingKeyOrAction {
        reason: String,
    },

    /// A v1 ratification candidate landed on the v2 path. The dispatch
    /// SHOULD route v1 candidates to the v1 path; this variant exists
    /// as defence-in-depth in case a future caller bug routes the wrong
    /// schema here.
    V1AfterV2Rejected,

    /// The persisted marker is structurally malformed or carries an
    /// unsupported `record_version`. Operator recovery is out of Run 134
    /// scope.
    UnsupportedMarkerVersion {
        reason: String,
    },

    /// Catch-all for any other reject outcome from
    /// [`compare_authority_marker_v2`] that does not map to a more
    /// precise field above.
    Conflict(crate::pqc_authority_state::AuthorityMarkerV2ComparisonOutcome),

    /// Atomic v2 persistence failed at the commit boundary. The trust-
    /// bundle sequence has already committed; the on-disk v2 marker is
    /// stale-by-one (safely replayable per Run 118 §D / Run 131) but the
    /// operator MUST be told.
    PersistFailure(crate::pqc_authority_state::AuthorityStateError),
}

impl std::fmt::Display for MutatingSurfaceMarkerV2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DerivationFailed(e) => write!(
                f,
                "Run 134: v2 authority-marker derivation refused: {} \
                 (fail closed; no trust mutation)",
                e
            ),
            Self::LoadOrCorruption(e) => write!(
                f,
                "Run 134: persisted authority-marker load/corruption: {} \
                 (fail closed; no trust mutation; this helper does NOT \
                 auto-recover corrupt markers)",
                e
            ),
            Self::PersistedDomainMismatch(o) => write!(
                f,
                "Run 134: persisted authority-marker belongs to a different \
                 trust domain: {:?} (fail closed; wrong-data-dir / \
                 wrong-snapshot-copy)",
                o
            ),
            Self::LowerV2SequenceRefused {
                persisted_sequence,
                attempted_sequence,
            } => write!(
                f,
                "Run 134: v2 authority-marker rollback rejected: attempted \
                 authority_domain_sequence={} is lower than persisted \
                 authority_domain_sequence={} (fail closed)",
                attempted_sequence, persisted_sequence
            ),
            Self::SameSequenceConflictingDigest {
                sequence,
                persisted_digest,
                attempted_digest,
            } => write!(
                f,
                "Run 134: v2 authority-marker same-sequence equivocation \
                 rejected: authority_domain_sequence={} persisted_digest={} \
                 attempted_digest={} (fail closed; two distinct v2 \
                 ratifications cannot share the same \
                 authority_domain_sequence)",
                sequence, persisted_digest, attempted_digest
            ),
            Self::SameSequenceConflictingKeyOrAction { reason } => write!(
                f,
                "Run 134: v2 authority-marker same-sequence key/action \
                 conflict rejected: {} (fail closed)",
                reason
            ),
            Self::V1AfterV2Rejected => write!(
                f,
                "Run 134: v1 ratification candidate routed to v2 path \
                 (caller bug or invalid dispatch); fail closed; no trust \
                 mutation"
            ),
            Self::UnsupportedMarkerVersion { reason } => write!(
                f,
                "Run 134: persisted authority-marker unsupported version: \
                 {} (fail closed; no auto-recovery)",
                reason
            ),
            Self::Conflict(o) => write!(
                f,
                "Run 134: v2 authority-marker comparison rejected: {:?} \
                 (fail closed)",
                o
            ),
            Self::PersistFailure(e) => write!(
                f,
                "Run 134: v2 authority-marker persist failure at commit \
                 boundary: {} (the trust-bundle mutation already committed; \
                 the on-disk v2 authority marker is stale-by-one and will \
                 be re-derived on the next accepted mutation per the Run \
                 118 §D crash-window rule. Operator MUST surface this \
                 failure)",
                e
            ),
        }
    }
}

impl std::error::Error for MutatingSurfaceMarkerV2Error {}

/// Run 134 — inputs to [`decide_marker_acceptance_v2`].
///
/// Mirrors [`MarkerAcceptanceInputs`] but consumes the typed v2
/// ratification + verifier output. The runtime trust-domain triple is
/// required exactly as for v1 so the helper never falls back to ambient
/// state.
#[derive(Debug, Clone)]
pub struct MarkerAcceptanceV2Inputs<'a> {
    /// `<data_dir>/pqc_authority_state.json` per
    /// [`crate::pqc_authority_state::authority_state_file_path`].
    pub marker_path: &'a Path,
    /// Runtime network environment.
    pub runtime_env: NetworkEnvironment,
    /// Runtime chain id.
    pub runtime_chain_id: ChainId,
    /// 64 lowercase hex chars of the canonical genesis hash.
    pub runtime_genesis_hash_hex: &'a str,
    /// Verified v2 ratification object.
    pub ratification: &'a qbind_ledger::BundleSigningRatificationV2,
    /// Verifier's typed v2 result identifying the ratified key.
    pub ratified: &'a qbind_ledger::RatifiedBundleSigningKeyV2,
    /// Informational tag identifying which mutating surface called this
    /// helper. Never participates in the security digest.
    pub update_source: AuthorityStateUpdateSource,
    /// Wall-clock seconds for the audit-only `updated_at_unix_secs`
    /// field. Never participates in the security digest.
    pub updated_at_unix_secs: u64,
}

/// Run 134 — result of [`decide_marker_acceptance_v2`]. Carries the
/// derived v2 candidate marker and the typed accept kind. Identical
/// usage pattern to [`MarkerAcceptDecision`]: drop on apply failure,
/// pass to [`persist_accepted_v2_marker_after_commit_boundary`] after
/// `commit_sequence` succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkerAcceptDecisionV2 {
    marker_path: PathBuf,
    candidate: crate::pqc_authority_state::PersistentAuthorityStateRecordV2,
    should_persist: bool,
    kind: MarkerAcceptKindV2,
}

/// Run 134 — audit-only acceptance kind retained on a
/// [`MarkerAcceptDecisionV2`] for the binary's operator-log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarkerAcceptKindV2 {
    /// No prior marker existed; v2 first-write.
    FirstV2Write,
    /// Prior marker existed and matched bit-for-bit on v2 schema.
    Idempotent,
    /// Prior v2 marker existed at a strictly lower
    /// `authority_domain_sequence`.
    UpgradeV2 {
        previous_sequence: u64,
        new_sequence: u64,
    },
    /// Prior marker is v1; this is an explicit v1→v2 migration.
    V2AfterV1Migration,
}

impl std::fmt::Display for MarkerAcceptKindV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FirstV2Write => write!(f, "v2-first-write"),
            Self::Idempotent => write!(f, "v2-idempotent"),
            Self::UpgradeV2 {
                previous_sequence,
                new_sequence,
            } => write!(
                f,
                "v2-upgrade {} -> {}",
                previous_sequence, new_sequence
            ),
            Self::V2AfterV1Migration => write!(f, "v2-after-v1-migration"),
        }
    }
}

impl MarkerAcceptDecisionV2 {
    /// Destination marker file path.
    pub fn marker_path(&self) -> &Path {
        &self.marker_path
    }

    /// Derived v2 candidate marker.
    pub fn candidate(
        &self,
    ) -> &crate::pqc_authority_state::PersistentAuthorityStateRecordV2 {
        &self.candidate
    }

    /// Whether the post-commit persist step will actually write.
    pub fn should_persist(&self) -> bool {
        self.should_persist
    }

    /// Audit-only acceptance kind.
    pub fn kind(&self) -> &MarkerAcceptKindV2 {
        &self.kind
    }
}

/// Run 134 — derive a v2 candidate marker from a verified v2 ratification,
/// load any persisted versioned marker, compare candidate against
/// persisted, and produce a typed accept-or-reject outcome.
///
/// This function performs **no** disk writes. It is safe to call before
/// the existing trust-mutation pipeline begins; if mutation then fails,
/// dropping the decision leaves the on-disk marker untouched.
///
/// Ordering:
///
/// 1. Derive v2 candidate via
///    [`crate::pqc_authority_state::derive_authority_state_v2_from_ratification`].
/// 2. Load the persisted versioned marker via
///    [`crate::pqc_authority_state::load_authority_state_versioned`]. A
///    fatal load error → [`MutatingSurfaceMarkerV2Error::LoadOrCorruption`].
/// 3. Compare via [`crate::pqc_authority_state::compare_authority_marker_v2`].
///    Accept variants → `Ok(decision)`; reject variants are routed to the
///    most precise error variant available.
///
/// Fail-closed guarantees:
///
/// - Never silently turns a reject comparison into an accept.
/// - Never repairs, deletes, or overwrites a corrupt persisted marker.
/// - Never reads or writes any file other than `marker_path`.
pub fn decide_marker_acceptance_v2(
    inputs: MarkerAcceptanceV2Inputs<'_>,
) -> Result<MarkerAcceptDecisionV2, MutatingSurfaceMarkerV2Error> {
    use crate::pqc_authority_state::{
        compare_authority_marker_v2, derive_authority_state_v2_from_ratification,
        load_authority_state_versioned, AuthorityMarkerV2ComparisonOutcome,
        AuthorityStateDerivationV2Inputs, PersistentAuthorityStateRecordVersioned,
    };

    // Step 1: derive v2 candidate marker from the verified ratification.
    let candidate = derive_authority_state_v2_from_ratification(AuthorityStateDerivationV2Inputs {
        runtime_env: inputs.runtime_env,
        runtime_chain_id: inputs.runtime_chain_id,
        runtime_genesis_hash_hex: inputs.runtime_genesis_hash_hex,
        ratification: inputs.ratification,
        ratified: inputs.ratified,
        update_source: inputs.update_source,
        updated_at_unix_secs: inputs.updated_at_unix_secs,
    })
    .map_err(MutatingSurfaceMarkerV2Error::DerivationFailed)?;

    // Step 2: load persisted versioned marker.
    let persisted = load_authority_state_versioned(inputs.marker_path)
        .map_err(MutatingSurfaceMarkerV2Error::LoadOrCorruption)?;

    // Pre-step 3: detect persisted-domain mismatch on a v1 record before
    // routing through migrate (so the operator sees a clear "wrong trust
    // domain" reason rather than "v2-after-v1 migration allowed" on a
    // mis-targeted data dir).
    if let Some(PersistentAuthorityStateRecordVersioned::V1(ref v1)) = persisted {
        // Compute the runtime triple in the same shape the v1 record
        // serialises with. `validate_record_for_domain` exists for v1
        // records; reuse it to surface a precise domain-mismatch error.
        if let Err(comp) = crate::pqc_authority_state::validate_record_for_domain(
            v1,
            inputs.runtime_env,
            inputs.runtime_chain_id,
            inputs.runtime_genesis_hash_hex,
        ) {
            // Map the v1 comparison reject into the v2 outcome carrying
            // the same conflict information for the operator log.
            return Err(MutatingSurfaceMarkerV2Error::PersistedDomainMismatch(
                AuthorityMarkerV2ComparisonOutcome::LegacyV1(comp),
            ));
        }
    }

    // Step 3: compare v2 candidate against persisted (v1 / v2 / none).
    let outcome = compare_authority_marker_v2(persisted.as_ref(), &candidate);

    match outcome {
        AuthorityMarkerV2ComparisonOutcome::FirstV2MarkerAccepted => Ok(MarkerAcceptDecisionV2 {
            marker_path: inputs.marker_path.to_path_buf(),
            candidate,
            should_persist: true,
            kind: MarkerAcceptKindV2::FirstV2Write,
        }),
        AuthorityMarkerV2ComparisonOutcome::SameV2MarkerIdempotent => Ok(MarkerAcceptDecisionV2 {
            marker_path: inputs.marker_path.to_path_buf(),
            candidate,
            should_persist: false,
            kind: MarkerAcceptKindV2::Idempotent,
        }),
        AuthorityMarkerV2ComparisonOutcome::HigherSequenceAccepted {
            persisted_sequence,
            candidate_sequence,
        } => Ok(MarkerAcceptDecisionV2 {
            marker_path: inputs.marker_path.to_path_buf(),
            candidate,
            should_persist: true,
            kind: MarkerAcceptKindV2::UpgradeV2 {
                previous_sequence: persisted_sequence,
                new_sequence: candidate_sequence,
            },
        }),
        AuthorityMarkerV2ComparisonOutcome::V2AfterV1ExplicitMigrationAllowed => {
            Ok(MarkerAcceptDecisionV2 {
                marker_path: inputs.marker_path.to_path_buf(),
                candidate,
                should_persist: true,
                kind: MarkerAcceptKindV2::V2AfterV1Migration,
            })
        }
        AuthorityMarkerV2ComparisonOutcome::LowerSequenceRejected {
            persisted_sequence,
            candidate_sequence,
        } => Err(MutatingSurfaceMarkerV2Error::LowerV2SequenceRefused {
            persisted_sequence,
            attempted_sequence: candidate_sequence,
        }),
        AuthorityMarkerV2ComparisonOutcome::SameSequenceDifferentDigestRejected {
            sequence,
            persisted_digest,
            candidate_digest,
        } => Err(MutatingSurfaceMarkerV2Error::SameSequenceConflictingDigest {
            sequence,
            persisted_digest,
            attempted_digest: candidate_digest,
        }),
        AuthorityMarkerV2ComparisonOutcome::WrongKeyActionLinkageRejected { reason } => Err(
            MutatingSurfaceMarkerV2Error::SameSequenceConflictingKeyOrAction { reason },
        ),
        AuthorityMarkerV2ComparisonOutcome::V1AfterV2Rejected => {
            Err(MutatingSurfaceMarkerV2Error::V1AfterV2Rejected)
        }
        AuthorityMarkerV2ComparisonOutcome::MalformedOrUnsupportedMarkerRejected { reason } => {
            Err(MutatingSurfaceMarkerV2Error::UnsupportedMarkerVersion { reason })
        }
        other @ AuthorityMarkerV2ComparisonOutcome::WrongEnvironmentRejected { .. }
        | other @ AuthorityMarkerV2ComparisonOutcome::WrongChainIdRejected { .. }
        | other @ AuthorityMarkerV2ComparisonOutcome::WrongGenesisHashRejected { .. }
        | other @ AuthorityMarkerV2ComparisonOutcome::WrongAuthorityRootRejected { .. } => {
            Err(MutatingSurfaceMarkerV2Error::PersistedDomainMismatch(other))
        }
        // Legacy v1 outcome — should not occur on the v2-derive path since
        // the candidate is v2 and migrate produces V2AfterV1ExplicitMigrationAllowed,
        // but route defensively.
        other @ AuthorityMarkerV2ComparisonOutcome::LegacyV1(_) => {
            Err(MutatingSurfaceMarkerV2Error::Conflict(other))
        }
    }
}

/// Run 134 — persist a previously-accepted v2 marker after the existing
/// `commit_sequence` boundary.
///
/// This is the only place the v2 helper layer touches disk. The function
/// is a no-op when [`MarkerAcceptDecisionV2::should_persist`] is false
/// (idempotent case); callers may unconditionally invoke it after a
/// successful mutation without checking `should_persist` themselves.
///
/// On persist failure the helper returns
/// [`MutatingSurfaceMarkerV2Error::PersistFailure`]. The mutating surface
/// MUST surface that failure operatorially — the trust-bundle sequence
/// has already advanced, so the on-disk marker is stale-by-one. Per
/// Run 118 §D / Run 131 this is intentionally safe to replay as an
/// `Upgrade` on the next accepted ratification, but the operator must
/// know it happened.
pub fn persist_accepted_v2_marker_after_commit_boundary(
    decision: &MarkerAcceptDecisionV2,
) -> Result<(), MutatingSurfaceMarkerV2Error> {
    if !decision.should_persist {
        return Ok(());
    }
    crate::pqc_authority_state::persist_authority_state_v2_atomic(
        &decision.marker_path,
        &decision.candidate,
    )
    .map_err(MutatingSurfaceMarkerV2Error::PersistFailure)
}

// =============================================================================
// Unit tests — §A from task/RUN_119_TASK.txt
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqc_authority_state::{
        authority_state_file_path, canonical_authority_state_digest, load_authority_state,
    };
    use qbind_ledger::{
        canonical_ratification_digest, BundleSigningRatification, RatificationEnvironment,
        RatifiedBundleSigningKey, GENESIS_AUTHORITY_SUITE_ML_DSA_44,
    };
    use qbind_types::{ChainId, NetworkEnvironment};
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn chain_id_42() -> ChainId {
        ChainId(42)
    }

    fn chain_id_hex_42() -> String {
        // matches crate::pqc_trust_sequence::chain_id_hex / Run 117 chain_id_hex
        format!("{:016x}", 42_u64)
    }

    fn fingerprint_a() -> String {
        "1".repeat(40)
    }

    fn fingerprint_b() -> String {
        "2".repeat(40)
    }

    fn sample_ratification(
        env: RatificationEnvironment,
        chain_id_str: &str,
        genesis_hash: [u8; 32],
        signing_pk_byte: u8,
    ) -> BundleSigningRatification {
        // Carefully chosen — Run 119 NEVER verifies a ratification, so
        // the signature can be a fixed-size all-zero array. The
        // derivation step only reads `environment`, `chain_id`, and
        // `authority_root_fingerprint` for cross-checks; everything
        // else goes into `canonical_ratification_digest`.
        let pk = vec![signing_pk_byte; 1312];
        let fp = qbind_ledger::pqc_public_key_fingerprint(&pk);
        BundleSigningRatification {
            version: 1,
            chain_id: chain_id_str.to_string(),
            environment: env,
            genesis_hash,
            authority_root_fingerprint: fingerprint_a(),
            signature_suite_id: GENESIS_AUTHORITY_SUITE_ML_DSA_44,
            bundle_signing_public_key: pk,
            bundle_signing_public_key_fingerprint: fp,
            signature: vec![0u8; 2420],
        }
    }

    fn ratified_from(r: &BundleSigningRatification) -> RatifiedBundleSigningKey {
        RatifiedBundleSigningKey {
            public_key: r.bundle_signing_public_key.clone(),
            fingerprint: r.bundle_signing_public_key_fingerprint.clone(),
            signature_suite_id: r.signature_suite_id,
            authority_root_fingerprint: r.authority_root_fingerprint.clone(),
        }
    }

    fn devnet_inputs<'a>(
        marker_path: &'a Path,
        gh_hex: &'a str,
        ratification: &'a BundleSigningRatification,
        ratified: &'a RatifiedBundleSigningKey,
    ) -> MarkerAcceptanceInputs<'a> {
        MarkerAcceptanceInputs {
            marker_path,
            runtime_env: NetworkEnvironment::Devnet,
            runtime_chain_id: chain_id_42(),
            runtime_genesis_hash_hex: gh_hex,
            authority_policy_version: 1,
            authority_sequence: 5,
            authority_epoch: Some(2),
            ratification,
            ratified,
            update_source: AuthorityStateUpdateSource::ReloadApply,
            updated_at_unix_secs: 1_700_000_000,
        }
    }

    // The runtime_genesis_hash_hex must equal `hex(genesis_hash)` of
    // the ratification for the inner derivation cross-checks. Helper
    // returns the matched pair.
    fn matched_devnet_setup(
    ) -> (
        TempDir,
        PathBuf,
        BundleSigningRatification,
        RatifiedBundleSigningKey,
        String,
    ) {
        let dir = TempDir::new().unwrap();
        let marker_path = authority_state_file_path(dir.path());
        let mut gh = [0u8; 32];
        for (i, b) in gh.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        let mut gh_hex = String::with_capacity(64);
        for b in gh {
            use std::fmt::Write;
            let _ = write!(gh_hex, "{:02x}", b);
        }
        let ratification =
            sample_ratification(RatificationEnvironment::Devnet, &chain_id_hex_42(), gh, 0x01);
        let ratified = ratified_from(&ratification);
        (dir, marker_path, ratification, ratified, gh_hex)
    }

    fn make_inputs<'a>(
        marker_path: &'a Path,
        gh_hex: &'a str,
        ratification: &'a BundleSigningRatification,
        ratified: &'a RatifiedBundleSigningKey,
    ) -> MarkerAcceptanceInputs<'a> {
        devnet_inputs(marker_path, gh_hex, ratification, ratified)
    }

    // ----- §A.1: marker derivation uses verified ratification only -----

    #[test]
    fn decide_first_write_when_no_prior_marker() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        let decision =
            decide_marker_acceptance(make_inputs(&marker_path, &gh_hex, &ratification, &ratified))
                .expect("clean first-write should be Ok");
        assert!(matches!(decision.kind(), MarkerAcceptKind::FirstWrite));
        assert!(decision.should_persist());
        // Candidate marker carries the ratification digest verbatim.
        let expected_digest_hex = {
            let d = canonical_ratification_digest(&ratification);
            let mut s = String::with_capacity(64);
            for b in d {
                use std::fmt::Write;
                let _ = write!(s, "{:02x}", b);
            }
            s
        };
        assert_eq!(
            decision.candidate().ratification_object_hash,
            expected_digest_hex
        );
        // No file was written by decide_marker_acceptance.
        assert!(!marker_path.exists());
    }

    // ----- §A.2: wrong chain rejects -----

    #[test]
    fn decide_wrong_chain_rejects_via_derivation_error() {
        let (_dir, marker_path, mut ratification, _ratified, gh_hex) = matched_devnet_setup();
        // Mutate the ratification's chain_id so it no longer matches
        // the runtime chain_id_hex. The Run 105 verifier would have
        // refused this; the derivation helper double-checks.
        ratification.chain_id = "00000000deadbeef".to_string();
        let ratified = ratified_from(&ratification);
        let err = decide_marker_acceptance(make_inputs(
            &marker_path,
            &gh_hex,
            &ratification,
            &ratified,
        ))
        .expect_err("chain mismatch must reject");
        assert!(
            matches!(err, MutatingSurfaceMarkerError::DerivationFailed(_)),
            "got {:?}",
            err
        );
    }

    // ----- §A.3: wrong environment rejects -----

    #[test]
    fn decide_wrong_environment_rejects_via_derivation_error() {
        let (_dir, marker_path, mut ratification, _ratified, gh_hex) = matched_devnet_setup();
        // Runtime is DevNet but the ratification claims Mainnet.
        ratification.environment = RatificationEnvironment::Mainnet;
        let ratified = ratified_from(&ratification);
        let err = decide_marker_acceptance(make_inputs(
            &marker_path,
            &gh_hex,
            &ratification,
            &ratified,
        ))
        .expect_err("env mismatch must reject");
        assert!(
            matches!(err, MutatingSurfaceMarkerError::DerivationFailed(_)),
            "got {:?}",
            err
        );
    }

    // ----- §A.4: wrong genesis rejects (caught downstream) -----

    #[test]
    fn decide_with_wrong_but_well_formed_genesis_hex_does_not_falsely_reject() {
        // Sanity: when the runtime supplies a syntactically valid hex
        // that disagrees with the ratification's genesis_hash, the
        // helper has no other source of truth and produces a candidate
        // first-write. The Run 105/103 verifier is the layer that
        // would have refused this pairing (genesis hash mismatch); the
        // marker helper is not a substitute for that verifier and the
        // task spec is explicit about deferring to it. See module-
        // level doc-comment "Strict scope".
        let (_dir, marker_path, ratification, ratified, _gh_hex) = matched_devnet_setup();
        let wrong_gh_hex = "f".repeat(64);
        let decision = decide_marker_acceptance(make_inputs(
            &marker_path,
            &wrong_gh_hex,
            &ratification,
            &ratified,
        ))
        .expect("syntactically valid hex must reach first-write");
        assert!(matches!(decision.kind(), MarkerAcceptKind::FirstWrite));
    }

    #[test]
    fn decide_malformed_runtime_genesis_hex_rejects_via_derivation_error() {
        let (_dir, marker_path, ratification, ratified, _gh_hex) = matched_devnet_setup();
        // Uppercase hex — Run 118 derivation refuses.
        let bad_gh_hex = "AB".repeat(32);
        let err = decide_marker_acceptance(make_inputs(
            &marker_path,
            &bad_gh_hex,
            &ratification,
            &ratified,
        ))
        .expect_err("malformed runtime genesis hex must reject");
        assert!(
            matches!(err, MutatingSurfaceMarkerError::DerivationFailed(_)),
            "got {:?}",
            err
        );
    }

    // ----- §A.5: wrong root rejects (verifier inconsistency) -----

    #[test]
    fn decide_root_mismatch_rejects_via_derivation_error() {
        let (_dir, marker_path, ratification, mut ratified, gh_hex) = matched_devnet_setup();
        // Ratified.authority_root_fingerprint disagrees with
        // ratification.authority_root_fingerprint. The Run 103 verifier
        // produces both from the same source, so this is a fail-closed
        // verifier-output-inconsistency bug class.
        ratified.authority_root_fingerprint = fingerprint_b();
        let err = decide_marker_acceptance(make_inputs(
            &marker_path,
            &gh_hex,
            &ratification,
            &ratified,
        ))
        .expect_err("verifier-output inconsistency must reject");
        assert!(
            matches!(err, MutatingSurfaceMarkerError::DerivationFailed(_)),
            "got {:?}",
            err
        );
    }

    // ----- §A.6 + §A.7: same root/key but different ratification digest rejects -----

    #[test]
    fn decide_same_sequence_different_ratification_hash_rejects() {
        let (dir, marker_path, ratification1, ratified1, gh_hex) = matched_devnet_setup();
        // Persist a first marker.
        let d1 = decide_marker_acceptance(make_inputs(
            &marker_path,
            &gh_hex,
            &ratification1,
            &ratified1,
        ))
        .expect("first decision must accept");
        persist_accepted_marker_after_commit_boundary(&d1).expect("first persist must succeed");
        assert!(marker_path.exists());

        // Build a SECOND ratification with the same env/chain/(runtime)
        // genesis and SAME signing key, but a different inner field
        // that contributes to canonical_ratification_digest. The
        // ratification's own `genesis_hash` field is in the canonical
        // preimage but is NOT cross-checked against runtime_genesis
        // _hash_hex by the derivation helper, so this is the cleanest
        // way to construct two structurally-distinct ratifications
        // that share the same authority_sequence.
        let mut ratification2 = ratification1.clone();
        ratification2.genesis_hash[0] ^= 0xFF;
        let ratified2 = ratified_from(&ratification2);
        // Same authority_sequence (= 5 in helper).
        let err = decide_marker_acceptance(make_inputs(
            &marker_path,
            &gh_hex,
            &ratification2,
            &ratified2,
        ))
        .expect_err("same-sequence-different-digest must reject");
        assert!(
            matches!(
                err,
                MutatingSurfaceMarkerError::SameSequenceConflictingRatificationDigest { .. }
            ),
            "got {:?}",
            err
        );
        // The on-disk marker is unchanged.
        let on_disk = load_authority_state(&marker_path).unwrap().unwrap();
        assert_eq!(
            on_disk.ratification_object_hash,
            d1.candidate().ratification_object_hash
        );
        drop(dir);
    }

    // ----- §A.8: missing persisted marker produces first-write/accept -----

    #[test]
    fn decide_missing_marker_is_first_write() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        assert!(!marker_path.exists());
        let decision =
            decide_marker_acceptance(make_inputs(&marker_path, &gh_hex, &ratification, &ratified))
                .expect("missing marker = first-write");
        assert!(matches!(decision.kind(), MarkerAcceptKind::FirstWrite));
        assert!(decision.should_persist());
    }

    // ----- §A.9: corrupt persisted marker fails closed -----

    #[test]
    fn decide_corrupt_marker_fails_closed() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        // Write garbage JSON to the marker path so Run 117
        // load_authority_state returns Malformed.
        std::fs::create_dir_all(marker_path.parent().unwrap()).unwrap();
        std::fs::write(&marker_path, b"{ not valid json").unwrap();
        let err =
            decide_marker_acceptance(make_inputs(&marker_path, &gh_hex, &ratification, &ratified))
                .expect_err("corrupt marker must fail closed");
        assert!(
            matches!(err, MutatingSurfaceMarkerError::LoadOrCorruption(_)),
            "got {:?}",
            err
        );
        // The garbage on disk is NOT overwritten by the helper.
        let bytes = std::fs::read(&marker_path).unwrap();
        assert_eq!(bytes, b"{ not valid json");
    }

    // ----- §A.10: prepare step does not persist -----

    #[test]
    fn decide_does_not_persist() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        let _decision =
            decide_marker_acceptance(make_inputs(&marker_path, &gh_hex, &ratification, &ratified))
                .expect("first-write accepts");
        // No file written by decide alone.
        assert!(
            !marker_path.exists(),
            "decide_marker_acceptance must NOT write the marker file"
        );
    }

    // ----- Idempotent same-marker accept -----

    #[test]
    fn decide_idempotent_when_marker_matches_bitwise() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        let d1 = decide_marker_acceptance(make_inputs(
            &marker_path,
            &gh_hex,
            &ratification,
            &ratified,
        ))
        .expect("first-write accepts");
        persist_accepted_marker_after_commit_boundary(&d1).expect("persist ok");

        let d2 = decide_marker_acceptance(make_inputs(
            &marker_path,
            &gh_hex,
            &ratification,
            &ratified,
        ))
        .expect("idempotent accepts");
        assert!(matches!(d2.kind(), MarkerAcceptKind::Idempotent));
        assert!(!d2.should_persist());

        // Persist is a no-op.
        let before = std::fs::read(&marker_path).unwrap();
        persist_accepted_marker_after_commit_boundary(&d2).expect("idempotent persist no-op ok");
        let after = std::fs::read(&marker_path).unwrap();
        assert_eq!(before, after, "idempotent persist must NOT rewrite the file");
    }

    // ----- Upgrade path -----

    #[test]
    fn decide_upgrade_when_persisted_sequence_strictly_lower() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        // First write at authority_sequence = 4.
        let mut inputs_low = make_inputs(&marker_path, &gh_hex, &ratification, &ratified);
        inputs_low.authority_sequence = 4;
        let d_low = decide_marker_acceptance(inputs_low).expect("first-write accepts");
        persist_accepted_marker_after_commit_boundary(&d_low).expect("persist ok");

        // Now derive at authority_sequence = 5.
        let d_high = decide_marker_acceptance(make_inputs(
            &marker_path,
            &gh_hex,
            &ratification,
            &ratified,
        ))
        .expect("upgrade accepts");
        match d_high.kind() {
            MarkerAcceptKind::Upgrade {
                previous_sequence,
                new_sequence,
            } => {
                assert_eq!(previous_sequence, 4);
                assert_eq!(new_sequence, 5);
            }
            other => panic!("expected Upgrade, got {:?}", other),
        }
        assert!(d_high.should_persist());
    }

    // ----- Rollback path -----

    #[test]
    fn decide_rollback_rejected() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        // First write at authority_sequence = 9.
        let mut inputs_high = make_inputs(&marker_path, &gh_hex, &ratification, &ratified);
        inputs_high.authority_sequence = 9;
        let d_high = decide_marker_acceptance(inputs_high).expect("first-write accepts");
        persist_accepted_marker_after_commit_boundary(&d_high).expect("persist ok");

        // Attempt to lower the authority_sequence.
        let err = decide_marker_acceptance(make_inputs(
            &marker_path,
            &gh_hex,
            &ratification,
            &ratified,
        ))
        .expect_err("rollback must reject");
        assert!(
            matches!(err, MutatingSurfaceMarkerError::AuthoritySequenceRollback { .. }),
            "got {:?}",
            err
        );
    }

    // ----- Persisted-domain mismatch -----

    #[test]
    fn decide_persisted_domain_mismatch_rejected() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        // Manually persist a marker whose genesis_hash differs.
        let mut foreign = decide_marker_acceptance(make_inputs(
            &marker_path,
            &gh_hex,
            &ratification,
            &ratified,
        ))
        .expect("first-write accepts");
        // Mutate the on-disk file to claim a different genesis_hash.
        let mut foreign_record = foreign.candidate.clone();
        foreign_record.genesis_hash = "b".repeat(64);
        std::fs::create_dir_all(marker_path.parent().unwrap()).unwrap();
        std::fs::write(
            &marker_path,
            serde_json::to_vec_pretty(&foreign_record).unwrap(),
        )
        .unwrap();

        // Now decide against the runtime trust domain — persisted
        // marker is for a foreign genesis_hash.
        // Touch `foreign` to keep the variable in scope across the
        // file IO.
        foreign.should_persist = false;
        let err = decide_marker_acceptance(make_inputs(
            &marker_path,
            &gh_hex,
            &ratification,
            &ratified,
        ))
        .expect_err("foreign-domain marker must reject");
        assert!(
            matches!(err, MutatingSurfaceMarkerError::PersistedDomainMismatch(_)),
            "got {:?}",
            err
        );
    }

    // ----- persist_accepted_marker_after_commit_boundary persists on first-write -----

    #[test]
    fn persist_writes_first_write_marker() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        let d = decide_marker_acceptance(make_inputs(
            &marker_path,
            &gh_hex,
            &ratification,
            &ratified,
        ))
        .expect("first-write accepts");
        assert!(!marker_path.exists());
        persist_accepted_marker_after_commit_boundary(&d).expect("persist ok");
        let on_disk = load_authority_state(&marker_path)
            .expect("load ok")
            .expect("file present");
        assert_eq!(
            canonical_authority_state_digest(&on_disk),
            canonical_authority_state_digest(d.candidate())
        );
    }

    // ----- persist_accepted_marker_after_commit_boundary fails closed on I/O failure -----
    //
    // Note: simulating a "persist-only" failure (decide accepts, then
    // persist fails) in a portable way is awkward because the decide
    // step also reads the same path, and both `is-a-directory` and
    // `not-a-directory` errors at the load step are surfaced as
    // `LoadOrCorruption` before persist is reached. The Run 117
    // `persist_authority_state_atomic` failure modes are already
    // covered by Run 117's own tests, and the wrapping into
    // `MutatingSurfaceMarkerError::PersistFailure` is a one-line
    // `.map_err(...)` exercised by visual inspection of
    // [`persist_accepted_marker_after_commit_boundary`]. The trivial
    // mapping path is asserted here by constructing a decision whose
    // marker_path is a directory and confirming that the wrapping
    // produces `PersistFailure` (not panicking, not a different
    // variant).

    #[test]
    fn persist_failure_wraps_into_persist_failure_variant() {
        let (dir, _marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        // First, build an accepting decision using a normal marker
        // path so decide_marker_acceptance returns Ok(FirstWrite).
        let scratch = dir.path().join("scratch_marker.json");
        let d_ok = decide_marker_acceptance(make_inputs(
            &scratch,
            &gh_hex,
            &ratification,
            &ratified,
        ))
        .expect("clean decision");
        // Now rewrite the decision in-place so its persist target is
        // a directory we deliberately create. The persist step will
        // try to write `<dir>.tmp` (works) and rename it to `<dir>`
        // (fails because <dir> is a non-empty directory or because
        // the target already exists with a different kind). We mimic
        // this by creating a directory at the target path.
        let blocker_dir = dir.path().join("target_is_a_dir");
        std::fs::create_dir_all(&blocker_dir).unwrap();
        // Place a sentinel file inside so the directory is non-empty
        // and rename-over is refused on all platforms.
        std::fs::write(blocker_dir.join("sentinel"), b"x").unwrap();
        let mut d_bad = d_ok.clone();
        d_bad.marker_path = blocker_dir.clone();
        let err = persist_accepted_marker_after_commit_boundary(&d_bad)
            .expect_err("persist over a non-empty directory must fail closed");
        assert!(
            matches!(err, MutatingSurfaceMarkerError::PersistFailure(_)),
            "got {:?}",
            err
        );
    }

    // ----- helper-doesn't-touch-disk on a reject -----

    #[test]
    fn rejected_path_does_not_touch_disk() {
        let (_dir, marker_path, mut ratification, _ratified, gh_hex) = matched_devnet_setup();
        ratification.environment = RatificationEnvironment::Mainnet;
        let ratified = ratified_from(&ratification);
        let _err = decide_marker_acceptance(make_inputs(
            &marker_path,
            &gh_hex,
            &ratification,
            &ratified,
        ))
        .expect_err("env mismatch must reject");
        assert!(!marker_path.exists());
    }

    // (devnet_inputs is the underlying test-helper; make_inputs is the
    // in-test alias that delegates to it. Both stay live as long as
    // any test uses make_inputs.)

    // ----- §A (Run 120): startup surface uses StartupLoad audit tag -----

    /// Build an inputs struct tagged as a startup acceptance (Run 120
    /// surface). Mirrors `make_inputs` but uses
    /// `AuthorityStateUpdateSource::StartupLoad` so the persisted
    /// audit-only tag reflects the actual mutating surface.
    fn make_startup_inputs<'a>(
        marker_path: &'a Path,
        gh_hex: &'a str,
        ratification: &'a BundleSigningRatification,
        ratified: &'a RatifiedBundleSigningKey,
    ) -> MarkerAcceptanceInputs<'a> {
        let mut inputs = devnet_inputs(marker_path, gh_hex, ratification, ratified);
        inputs.update_source = AuthorityStateUpdateSource::StartupLoad;
        inputs
    }

    /// Run 120 §A.1 — first accepted startup ratification produces a
    /// `FirstWrite` decision, persisting the marker exactly once after
    /// the simulated commit boundary. The persisted record carries the
    /// `StartupLoad` audit tag (mirrors the Run 120 binary surface).
    #[test]
    fn run_120_startup_first_accepted_persists_marker() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        let decision = decide_marker_acceptance(make_startup_inputs(
            &marker_path,
            &gh_hex,
            &ratification,
            &ratified,
        ))
        .expect("first-write accepts");
        assert!(matches!(decision.kind(), MarkerAcceptKind::FirstWrite));
        // No file written by decide alone — proves compare happens
        // before any startup mutation/persistence.
        assert!(!marker_path.exists());
        // Persist after the simulated startup commit boundary.
        persist_accepted_marker_after_commit_boundary(&decision).expect("persist ok");
        let on_disk = load_authority_state(&marker_path)
            .expect("load ok")
            .expect("file present");
        assert_eq!(
            on_disk.last_update_source,
            AuthorityStateUpdateSource::StartupLoad,
            "Run 120 startup persists with the StartupLoad audit tag"
        );
        assert_eq!(
            canonical_authority_state_digest(&on_disk),
            canonical_authority_state_digest(decision.candidate())
        );
    }

    /// Run 120 §A.2 — same marker is idempotent across a simulated
    /// restart. The on-disk bytes are NOT rewritten (so the audit-only
    /// `updated_at_unix_secs` does not bump for no operator benefit).
    #[test]
    fn run_120_startup_same_marker_is_idempotent() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        let d1 = decide_marker_acceptance(make_startup_inputs(
            &marker_path,
            &gh_hex,
            &ratification,
            &ratified,
        ))
        .expect("first-write accepts");
        persist_accepted_marker_after_commit_boundary(&d1).expect("persist ok");

        let before = std::fs::read(&marker_path).unwrap();
        let d2 = decide_marker_acceptance(make_startup_inputs(
            &marker_path,
            &gh_hex,
            &ratification,
            &ratified,
        ))
        .expect("idempotent accepts");
        assert!(matches!(d2.kind(), MarkerAcceptKind::Idempotent));
        assert!(!d2.should_persist());
        persist_accepted_marker_after_commit_boundary(&d2).expect("idempotent persist no-op");
        let after = std::fs::read(&marker_path).unwrap();
        assert_eq!(before, after, "idempotent must NOT rewrite the file");
    }

    /// Run 120 §A.3 — conflicting marker (rollback to lower
    /// `authority_sequence`) rejects BEFORE any startup mutation; the
    /// on-disk marker is unchanged.
    #[test]
    fn run_120_startup_conflicting_marker_rejects_before_mutation() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        let mut high = make_startup_inputs(&marker_path, &gh_hex, &ratification, &ratified);
        high.authority_sequence = 9;
        let d_high = decide_marker_acceptance(high).expect("high first-write");
        persist_accepted_marker_after_commit_boundary(&d_high).expect("persist ok");
        let before = std::fs::read(&marker_path).unwrap();

        // Attempt to lower the authority_sequence at the next startup.
        let mut low = make_startup_inputs(&marker_path, &gh_hex, &ratification, &ratified);
        low.authority_sequence = 4;
        let err =
            decide_marker_acceptance(low).expect_err("rollback must reject before mutation");
        assert!(
            matches!(err, MutatingSurfaceMarkerError::AuthoritySequenceRollback { .. }),
            "got {:?}",
            err
        );
        // No marker mutation occurred.
        let after = std::fs::read(&marker_path).unwrap();
        assert_eq!(before, after, "rejected startup must not mutate marker");
    }

    /// Run 120 §A.4 — corrupt persisted marker fails closed BEFORE any
    /// startup mutation; the garbage on disk is NOT auto-overwritten
    /// (per Run 117 fail-closed corruption semantics).
    #[test]
    fn run_120_startup_corrupt_marker_fails_closed() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        std::fs::create_dir_all(marker_path.parent().unwrap()).unwrap();
        std::fs::write(&marker_path, b"{ garbage").unwrap();
        let err = decide_marker_acceptance(make_startup_inputs(
            &marker_path,
            &gh_hex,
            &ratification,
            &ratified,
        ))
        .expect_err("corrupt marker must fail closed at startup");
        assert!(
            matches!(err, MutatingSurfaceMarkerError::LoadOrCorruption(_)),
            "got {:?}",
            err
        );
        let bytes = std::fs::read(&marker_path).unwrap();
        assert_eq!(bytes, b"{ garbage", "Run 120 must NOT auto-overwrite corrupt marker");
    }

    /// Run 120 §A.5 — persisted-domain mismatch (wrong-data-dir /
    /// wrong-snapshot-copy) rejects startup BEFORE any mutation; the
    /// on-disk marker is unchanged.
    #[test]
    fn run_120_startup_wrong_domain_rejects_before_mutation() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        let foreign = decide_marker_acceptance(make_startup_inputs(
            &marker_path,
            &gh_hex,
            &ratification,
            &ratified,
        ))
        .expect("first-write accepts");
        // Mutate the on-disk record to claim a foreign genesis hash.
        let mut foreign_record = foreign.candidate().clone();
        foreign_record.genesis_hash = "b".repeat(64);
        std::fs::create_dir_all(marker_path.parent().unwrap()).unwrap();
        std::fs::write(
            &marker_path,
            serde_json::to_vec_pretty(&foreign_record).unwrap(),
        )
        .unwrap();
        let before = std::fs::read(&marker_path).unwrap();

        let err = decide_marker_acceptance(make_startup_inputs(
            &marker_path,
            &gh_hex,
            &ratification,
            &ratified,
        ))
        .expect_err("foreign-domain marker must reject startup");
        assert!(
            matches!(err, MutatingSurfaceMarkerError::PersistedDomainMismatch(_)),
            "got {:?}",
            err
        );
        let after = std::fs::read(&marker_path).unwrap();
        assert_eq!(before, after, "rejected startup must not mutate marker");
    }

    /// Run 120 §A.6 — upgrade from a strictly lower
    /// `authority_sequence` on a subsequent startup accepts and
    /// rewrites the marker. Mirrors operator workflow of rotating to a
    /// newer ratified bundle across restarts.
    #[test]
    fn run_120_startup_upgrade_accepts_strictly_higher_sequence() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        let mut low = make_startup_inputs(&marker_path, &gh_hex, &ratification, &ratified);
        low.authority_sequence = 4;
        let d_low = decide_marker_acceptance(low).expect("first-write");
        persist_accepted_marker_after_commit_boundary(&d_low).expect("persist ok");

        let mut high = make_startup_inputs(&marker_path, &gh_hex, &ratification, &ratified);
        high.authority_sequence = 7;
        let d_high = decide_marker_acceptance(high).expect("upgrade accepts");
        match d_high.kind() {
            MarkerAcceptKind::Upgrade {
                previous_sequence,
                new_sequence,
            } => {
                assert_eq!(previous_sequence, 4);
                assert_eq!(new_sequence, 7);
            }
            other => panic!("expected Upgrade, got {:?}", other),
        }
        persist_accepted_marker_after_commit_boundary(&d_high).expect("persist ok");
        let on_disk = load_authority_state(&marker_path)
            .expect("load ok")
            .expect("file present");
        assert_eq!(on_disk.authority_sequence, 7);
    }

    /// Run 120 §A.7 — same-`authority_sequence` ratification swap
    /// (e.g. silent replacement of one ratification object with
    /// another that shares the same authority_sequence) rejects.
    /// Refuses the silent equivocation at startup.
    #[test]
    fn run_120_startup_same_sequence_conflicting_digest_rejects() {
        let (_dir, marker_path, ratification1, ratified1, gh_hex) = matched_devnet_setup();
        let d1 = decide_marker_acceptance(make_startup_inputs(
            &marker_path,
            &gh_hex,
            &ratification1,
            &ratified1,
        ))
        .expect("first-write accepts");
        persist_accepted_marker_after_commit_boundary(&d1).expect("persist ok");

        let mut ratification2 = ratification1.clone();
        // Mutate a field in the canonical preimage so the digest
        // changes; keep authority_sequence and signing key identical.
        ratification2.genesis_hash[0] ^= 0xFF;
        let ratified2 = ratified_from(&ratification2);
        let err = decide_marker_acceptance(make_startup_inputs(
            &marker_path,
            &gh_hex,
            &ratification2,
            &ratified2,
        ))
        .expect_err("same-sequence-different-digest must reject");
        assert!(
            matches!(
                err,
                MutatingSurfaceMarkerError::SameSequenceConflictingRatificationDigest { .. }
            ),
            "got {:?}",
            err
        );
    }

    /// Run 120 §B — ordering proof: `decide_marker_acceptance` never
    /// touches disk, even on accept. This is what lets the startup
    /// binary surface call compare BEFORE the Run 055 sequence write
    /// and persist ONLY after that write has committed.
    #[test]
    fn run_120_decide_does_not_persist_on_startup_path() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        let _d = decide_marker_acceptance(make_startup_inputs(
            &marker_path,
            &gh_hex,
            &ratification,
            &ratified,
        ))
        .expect("first-write accepts");
        assert!(
            !marker_path.exists(),
            "decide_marker_acceptance must NOT persist on the Run 120 startup surface"
        );
    }

    /// Run 120 §B — ordering proof: dropping a decision (simulating a
    /// failure of the Run 055 sequence write AFTER preflight accepted
    /// the marker) leaves the on-disk marker file untouched. There is
    /// no path by which Run 120 persists a marker for a startup that
    /// did not actually commit.
    #[test]
    fn run_120_dropped_decision_does_not_persist_marker() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        assert!(!marker_path.exists());
        {
            let _decision = decide_marker_acceptance(make_startup_inputs(
                &marker_path,
                &gh_hex,
                &ratification,
                &ratified,
            ))
            .expect("first-write accepts");
            // Drop without calling persist (simulates the Err arm of
            // the Run 055 sequence write killing the process before
            // the persist step is reached).
        }
        assert!(
            !marker_path.exists(),
            "dropped Run 120 decision must NOT persist the marker"
        );
    }

    // =========================================================================
    // Run 123 — validation-only marker check tests
    // =========================================================================

    fn validation_only_inputs<'a>(
        marker_path: &'a Path,
        gh_hex: &'a str,
        ratification: &'a BundleSigningRatification,
        ratified: &'a RatifiedBundleSigningKey,
    ) -> super::ValidationOnlyMarkerInputs<'a> {
        super::ValidationOnlyMarkerInputs {
            marker_path,
            runtime_env: NetworkEnvironment::Devnet,
            runtime_chain_id: chain_id_42(),
            runtime_genesis_hash_hex: gh_hex,
            authority_policy_version: 1,
            authority_sequence: 5,
            authority_epoch: Some(2),
            ratification,
            ratified,
        }
    }

    #[test]
    fn run123_no_persisted_marker_passes_validation_only() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        let result = super::verify_marker_for_validation_only(validation_only_inputs(
            &marker_path,
            &gh_hex,
            &ratification,
            &ratified,
        ));
        assert!(result.is_ok());
        assert!(matches!(
            result.unwrap(),
            super::ValidationOnlyMarkerAcceptReason::NoPersistedMarkerYet
        ));
        // Critical: marker file was NOT created.
        assert!(
            !marker_path.exists(),
            "validation-only helper must NEVER persist marker"
        );
    }

    #[test]
    fn run123_idempotent_marker_passes_validation_only() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        // Pre-persist a matching marker via the mutating-surface helper.
        let decision =
            decide_marker_acceptance(make_inputs(&marker_path, &gh_hex, &ratification, &ratified))
                .expect("first-write accepts");
        persist_accepted_marker_after_commit_boundary(&decision).expect("persist ok");
        assert!(marker_path.exists());

        // Now the validation-only check should see idempotent.
        let result = super::verify_marker_for_validation_only(validation_only_inputs(
            &marker_path,
            &gh_hex,
            &ratification,
            &ratified,
        ));
        assert!(result.is_ok());
        assert!(matches!(
            result.unwrap(),
            super::ValidationOnlyMarkerAcceptReason::Idempotent
        ));
    }

    #[test]
    fn run123_upgrade_compatible_passes_validation_only() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        // Pre-persist a marker at authority_sequence=5.
        let decision =
            decide_marker_acceptance(make_inputs(&marker_path, &gh_hex, &ratification, &ratified))
                .expect("first-write accepts");
        persist_accepted_marker_after_commit_boundary(&decision).expect("persist ok");

        // Now check with authority_sequence=6 (upgrade).
        let mut inputs = validation_only_inputs(&marker_path, &gh_hex, &ratification, &ratified);
        inputs.authority_sequence = 6;
        let result = super::verify_marker_for_validation_only(inputs);
        assert!(result.is_ok());
        match result.unwrap() {
            super::ValidationOnlyMarkerAcceptReason::UpgradeCompatible {
                previous_sequence,
                new_sequence,
            } => {
                assert_eq!(previous_sequence, 5);
                assert_eq!(new_sequence, 6);
            }
            other => panic!("expected UpgradeCompatible, got {:?}", other),
        }
        // Marker unchanged on disk.
        let persisted = load_authority_state(&marker_path).unwrap().unwrap();
        assert_eq!(persisted.authority_sequence, 5);
    }

    #[test]
    fn run123_rollback_rejected_by_validation_only() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        // Pre-persist a marker at authority_sequence=5.
        let decision =
            decide_marker_acceptance(make_inputs(&marker_path, &gh_hex, &ratification, &ratified))
                .expect("first-write accepts");
        persist_accepted_marker_after_commit_boundary(&decision).expect("persist ok");

        // Now check with authority_sequence=3 (rollback).
        let mut inputs = validation_only_inputs(&marker_path, &gh_hex, &ratification, &ratified);
        inputs.authority_sequence = 3;
        let result = super::verify_marker_for_validation_only(inputs);
        assert!(result.is_err());
        match result.unwrap_err() {
            super::ValidationOnlyMarkerError::AuthoritySequenceRollback {
                persisted_sequence,
                attempted_sequence,
            } => {
                assert_eq!(persisted_sequence, 5);
                assert_eq!(attempted_sequence, 3);
            }
            other => panic!("expected AuthoritySequenceRollback, got {:?}", other),
        }
    }

    #[test]
    fn run123_corrupt_marker_rejected_by_validation_only() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        // Write corrupt data to the marker file.
        std::fs::write(&marker_path, b"not valid json").unwrap();

        let result = super::verify_marker_for_validation_only(validation_only_inputs(
            &marker_path,
            &gh_hex,
            &ratification,
            &ratified,
        ));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            super::ValidationOnlyMarkerError::LoadOrCorruption(_)
        ));
        // Corrupt marker NOT overwritten.
        let content = std::fs::read_to_string(&marker_path).unwrap();
        assert_eq!(content, "not valid json");
    }

    #[test]
    fn run123_wrong_domain_rejected_by_validation_only() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        // Pre-persist a marker at the correct domain.
        let decision =
            decide_marker_acceptance(make_inputs(&marker_path, &gh_hex, &ratification, &ratified))
                .expect("first-write accepts");
        persist_accepted_marker_after_commit_boundary(&decision).expect("persist ok");

        // Now check with a DIFFERENT genesis hash (wrong data-dir).
        let wrong_gh_hex = "ff".repeat(32);
        let wrong_gh = [0xff; 32];
        let wrong_ratification = sample_ratification(
            RatificationEnvironment::Devnet,
            &chain_id_hex_42(),
            wrong_gh,
            0x01,
        );
        let wrong_ratified = ratified_from(&wrong_ratification);
        let inputs = super::ValidationOnlyMarkerInputs {
            marker_path: &marker_path,
            runtime_env: NetworkEnvironment::Devnet,
            runtime_chain_id: chain_id_42(),
            runtime_genesis_hash_hex: &wrong_gh_hex,
            authority_policy_version: 1,
            authority_sequence: 5,
            authority_epoch: Some(2),
            ratification: &wrong_ratification,
            ratified: &wrong_ratified,
        };
        let result = super::verify_marker_for_validation_only(inputs);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            super::ValidationOnlyMarkerError::PersistedDomainMismatch(_)
        ));
    }

    #[test]
    fn run123_same_sequence_conflicting_hash_rejected() {
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        // Pre-persist a marker at authority_sequence=5.
        let decision =
            decide_marker_acceptance(make_inputs(&marker_path, &gh_hex, &ratification, &ratified))
                .expect("first-write accepts");
        persist_accepted_marker_after_commit_boundary(&decision).expect("persist ok");

        // Build a ratification with the SAME authority_sequence but a
        // DIFFERENT signing key (produces a different canonical digest).
        let gh = {
            let mut b = [0u8; 32];
            for (i, v) in b.iter_mut().enumerate() {
                *v = (i as u8).wrapping_mul(7);
            }
            b
        };
        let different_ratification = sample_ratification(
            RatificationEnvironment::Devnet,
            &chain_id_hex_42(),
            gh,
            0x02, // different signing key byte
        );
        let different_ratified = ratified_from(&different_ratification);
        let inputs = super::ValidationOnlyMarkerInputs {
            marker_path: &marker_path,
            runtime_env: NetworkEnvironment::Devnet,
            runtime_chain_id: chain_id_42(),
            runtime_genesis_hash_hex: &gh_hex,
            authority_policy_version: 1,
            authority_sequence: 5,
            authority_epoch: Some(2),
            ratification: &different_ratification,
            ratified: &different_ratified,
        };
        let result = super::verify_marker_for_validation_only(inputs);
        assert!(result.is_err());
        // Either SameSequenceConflictingRatificationDigest or
        // SameSequenceConflictingKey depending on which Run 117
        // comparator fires first.
        let err = result.unwrap_err();
        assert!(
            matches!(
                &err,
                super::ValidationOnlyMarkerError::SameSequenceConflictingRatificationDigest { .. }
                    | super::ValidationOnlyMarkerError::SameSequenceConflictingKey { .. }
            ),
            "expected equivocation rejection, got {:?}",
            err
        );
    }

    #[test]
    fn run123_validation_only_never_persists_on_any_outcome() {
        // Verify that across accept, reject, and upgrade outcomes the
        // marker file content is NEVER changed by the validation-only
        // helper.
        let (_dir, marker_path, ratification, ratified, gh_hex) = matched_devnet_setup();
        // Pre-persist a marker at authority_sequence=5.
        let decision =
            decide_marker_acceptance(make_inputs(&marker_path, &gh_hex, &ratification, &ratified))
                .expect("first-write accepts");
        persist_accepted_marker_after_commit_boundary(&decision).expect("persist ok");
        let original_bytes = std::fs::read(&marker_path).unwrap();

        // Idempotent check — file untouched.
        let _ = super::verify_marker_for_validation_only(validation_only_inputs(
            &marker_path,
            &gh_hex,
            &ratification,
            &ratified,
        ));
        assert_eq!(std::fs::read(&marker_path).unwrap(), original_bytes);

        // Upgrade check — file still untouched.
        let mut upgrade_inputs =
            validation_only_inputs(&marker_path, &gh_hex, &ratification, &ratified);
        upgrade_inputs.authority_sequence = 10;
        let _ = super::verify_marker_for_validation_only(upgrade_inputs);
        assert_eq!(std::fs::read(&marker_path).unwrap(), original_bytes);

        // Rollback check — file still untouched.
        let mut rollback_inputs =
            validation_only_inputs(&marker_path, &gh_hex, &ratification, &ratified);
        rollback_inputs.authority_sequence = 1;
        let _ = super::verify_marker_for_validation_only(rollback_inputs);
        assert_eq!(std::fs::read(&marker_path).unwrap(), original_bytes);
    }

    // =========================================================================
    // Run 132 — v2 validation-only marker check tests
    // =========================================================================

    mod run132_v2_tests {
        use super::*;
        use crate::pqc_authority_state::{
            authority_state_file_path, load_authority_state_versioned,
            persist_authority_state_atomic, AuthorityStateUpdateSource,
            PersistentAuthorityStateRecord,
            PersistentAuthorityStateRecordVersioned,
            derive_authority_state_v2_from_ratification, AuthorityStateDerivationV2Inputs,
        };
        use crate::pqc_trust_bundle::TrustBundleEnvironment;
        use qbind_ledger::{
            BundleSigningRatificationV2, BundleSigningRatificationV2Action,
            RatificationEnvironment, RatifiedBundleSigningKeyV2,
            GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        };
        use qbind_ledger::bundle_signing_ratification::v2_test_helpers;
        use qbind_ledger::genesis::{
            compute_canonical_genesis_hash, GenesisAllocation, GenesisAuthorityConfig,
            GenesisAuthorityRoot, GenesisConfig, GenesisCouncilConfig, GenesisMonetaryConfig,
            GenesisValidator,
        };
        use qbind_crypto::MlDsa44Backend;

        fn full_pk_hex(pk: &[u8]) -> String {
            let mut s = String::with_capacity(pk.len() * 2);
            for b in pk {
                use std::fmt::Write;
                let _ = write!(&mut s, "{:02x}", b);
            }
            s
        }

        fn gh_hex(gh: &qbind_ledger::GenesisHash) -> String {
            let mut s = String::with_capacity(64);
            for b in gh {
                use std::fmt::Write;
                let _ = write!(&mut s, "{:02x}", b);
            }
            s
        }

        struct V2TestFixture {
            authority_pk: Vec<u8>,
            authority_sk: Vec<u8>,
            bsk_pk: Vec<u8>,
            _genesis_cfg: GenesisConfig,
            authority: GenesisAuthorityConfig,
            canonical_hash: qbind_ledger::GenesisHash,
            canonical_hash_hex: String,
            /// Hex chain id for v2 ratification objects (16 hex chars).
            chain_id_hex: String,
            /// Typed runtime chain id.
            runtime_chain_id: ChainId,
        }

        impl V2TestFixture {
            fn new() -> Self {
                let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
                let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
                // Use hex chain_id that matches ChainId::new(1).
                let runtime_chain_id = ChainId::new(1);
                let chain_id_hex_str = format!("{:016x}", runtime_chain_id.as_u64());
                let auth_pk_hex = full_pk_hex(&auth_pk);
                // Genesis config uses the hex chain_id for v2 consistency.
                let mut cfg = GenesisConfig::new(
                    &chain_id_hex_str,
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
                    &auth_pk_hex,
                    "foundation-bundle-signing-1",
                );
                cfg.authority = Some(GenesisAuthorityConfig::new(vec![root]));
                let gh = compute_canonical_genesis_hash(
                    &cfg,
                    qbind_ledger::NetworkEnvironmentPolicy::Mainnet,
                );
                let authority = cfg.authority.clone().unwrap();
                let gh_hex_str = gh_hex(&gh);
                V2TestFixture {
                    authority_pk: auth_pk,
                    authority_sk: auth_sk,
                    bsk_pk,
                    _genesis_cfg: cfg,
                    authority,
                    canonical_hash: gh,
                    canonical_hash_hex: gh_hex_str,
                    chain_id_hex: chain_id_hex_str,
                    runtime_chain_id,
                }
            }

            fn build_v2_ratification(
                &self,
                sequence: u64,
                action: BundleSigningRatificationV2Action,
            ) -> BundleSigningRatificationV2 {
                v2_test_helpers::build_signed_ratification_v2(
                    &self.chain_id_hex,
                    RatificationEnvironment::Mainnet,
                    self.canonical_hash,
                    1,
                    &full_pk_hex(&self.authority_pk),
                    &self.authority_sk,
                    &self.bsk_pk,
                    sequence,
                    action,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            }

            fn verify_v2(
                &self,
                ratification: &BundleSigningRatificationV2,
            ) -> RatifiedBundleSigningKeyV2 {
                qbind_ledger::verify_bundle_signing_key_ratification_v2(
                    qbind_ledger::RatificationV2VerifierInputs {
                        ratification,
                        authority: &self.authority,
                        expected_chain_id: &self.chain_id_hex,
                        expected_environment: qbind_ledger::NetworkEnvironmentPolicy::Mainnet,
                        expected_genesis_hash: &self.canonical_hash,
                    },
                )
                .expect("v2 verification must succeed in test fixture")
            }

            fn v2_inputs<'a>(
                &'a self,
                marker_path: &'a std::path::Path,
                ratification: &'a BundleSigningRatificationV2,
                ratified: &'a RatifiedBundleSigningKeyV2,
            ) -> super::super::ValidationOnlyMarkerV2Inputs<'a> {
                super::super::ValidationOnlyMarkerV2Inputs {
                    marker_path,
                    runtime_env: NetworkEnvironment::Mainnet,
                    runtime_chain_id: self.runtime_chain_id,
                    runtime_genesis_hash_hex: &self.canonical_hash_hex,
                    ratification,
                    ratified,
                }
            }
        }

        #[test]
        fn run132_v2_no_marker_passes_no_persist() {
            let fix = V2TestFixture::new();
            let dir = tempfile::tempdir().unwrap();
            let marker_path = authority_state_file_path(dir.path());

            let rat = fix.build_v2_ratification(1, BundleSigningRatificationV2Action::Ratify);
            let ratified = fix.verify_v2(&rat);

            let result = super::super::verify_marker_for_validation_only_v2(
                fix.v2_inputs(&marker_path, &rat, &ratified),
            );
            assert!(result.is_ok());
            assert!(matches!(
                result.unwrap(),
                super::super::ValidationOnlyMarkerV2AcceptReason::NoPersistedMarkerYet
            ));
            // No marker file created.
            assert!(!marker_path.exists());
        }

        #[test]
        fn run132_v2_after_v1_marker_is_migration_candidate_no_persist() {
            let fix = V2TestFixture::new();
            let dir = tempfile::tempdir().unwrap();
            let marker_path = authority_state_file_path(dir.path());

            // Write a v1 marker.
            let v1_record = PersistentAuthorityStateRecord::new(
                fix.chain_id_hex.clone(),
                TrustBundleEnvironment::Mainnet,
                fix.canonical_hash_hex.clone(),
                1, // policy_version
                1, // sequence
                None,
                full_pk_hex(&fix.authority_pk),
                full_pk_hex(&fix.bsk_pk)[..64].to_string(),
                "aa".repeat(32),
                AuthorityStateUpdateSource::ReloadApply,
                1000,
            );
            persist_authority_state_atomic(&marker_path, &v1_record).unwrap();
            let original_bytes = std::fs::read(&marker_path).unwrap();

            let rat = fix.build_v2_ratification(2, BundleSigningRatificationV2Action::Ratify);
            let ratified = fix.verify_v2(&rat);

            let result = super::super::verify_marker_for_validation_only_v2(
                fix.v2_inputs(&marker_path, &rat, &ratified),
            );
            assert!(result.is_ok());
            assert!(matches!(
                result.unwrap(),
                super::super::ValidationOnlyMarkerV2AcceptReason::V2AfterV1MigrationCandidate
            ));
            // Marker file unchanged.
            assert_eq!(std::fs::read(&marker_path).unwrap(), original_bytes);
        }

        #[test]
        fn run132_v1_after_v2_marker_rejects() {
            // This test validates that the v1 path should reject when a
            // v2 marker is persisted. We use the v1 verify path here since
            // it's the v1-after-v2 scenario tested via prepare_v2_marker.
            let fix = V2TestFixture::new();
            let dir = tempfile::tempdir().unwrap();
            let marker_path = authority_state_file_path(dir.path());

            // Derive and write a v2 marker.
            let rat = fix.build_v2_ratification(1, BundleSigningRatificationV2Action::Ratify);
            let ratified = fix.verify_v2(&rat);
            let v2_record = derive_authority_state_v2_from_ratification(
                AuthorityStateDerivationV2Inputs {
                    runtime_env: NetworkEnvironment::Mainnet,
                    runtime_chain_id: fix.runtime_chain_id,
                    runtime_genesis_hash_hex: &fix.canonical_hash_hex.clone(),
                    ratification: &rat,
                    ratified: &ratified,
                    update_source: AuthorityStateUpdateSource::ReloadApply,
                    updated_at_unix_secs: 1000,
                },
            )
            .unwrap();

            // Write v2 marker as JSON.
            let v2_json = serde_json::to_vec_pretty(&v2_record).unwrap();
            std::fs::create_dir_all(marker_path.parent().unwrap()).ok();
            std::fs::write(&marker_path, &v2_json).unwrap();

            // Loading as versioned should yield V2.
            let loaded = load_authority_state_versioned(&marker_path).unwrap();
            assert!(loaded.is_some());
            assert!(matches!(
                loaded.as_ref().unwrap(),
                PersistentAuthorityStateRecordVersioned::V2(_)
            ));

            // Now use compare_authority_marker_v2 with a v1 candidate to verify
            // v1-after-v2 is rejected by prepare_v2_marker_for_acceptance.
            use crate::pqc_authority_state::prepare_v2_marker_for_acceptance;
            let v1_record = PersistentAuthorityStateRecord::new(
                fix.chain_id_hex.clone(),
                TrustBundleEnvironment::Mainnet,
                fix.canonical_hash_hex.clone(),
                1,
                1,
                None,
                full_pk_hex(&fix.authority_pk),
                full_pk_hex(&fix.bsk_pk)[..64].to_string(),
                "aa".repeat(32),
                AuthorityStateUpdateSource::ReloadApply,
                1000,
            );
            let outcome = prepare_v2_marker_for_acceptance(
                loaded.as_ref(),
                &PersistentAuthorityStateRecordVersioned::V1(v1_record),
            );
            assert!(matches!(
                outcome,
                crate::pqc_authority_state::AuthorityMarkerV2ComparisonOutcome::V1AfterV2Rejected
            ));
        }

        #[test]
        fn run132_v2_lower_sequence_rejects() {
            let fix = V2TestFixture::new();
            let dir = tempfile::tempdir().unwrap();
            let marker_path = authority_state_file_path(dir.path());

            // Write a v2 marker with sequence=5.
            let rat_high = fix.build_v2_ratification(5, BundleSigningRatificationV2Action::Ratify);
            let ratified_high = fix.verify_v2(&rat_high);
            let v2_high = derive_authority_state_v2_from_ratification(
                AuthorityStateDerivationV2Inputs {
                    runtime_env: NetworkEnvironment::Mainnet,
                    runtime_chain_id: fix.runtime_chain_id,
                    runtime_genesis_hash_hex: &fix.canonical_hash_hex.clone(),
                    ratification: &rat_high,
                    ratified: &ratified_high,
                    update_source: AuthorityStateUpdateSource::ReloadApply,
                    updated_at_unix_secs: 1000,
                },
            )
            .unwrap();
            let v2_json = serde_json::to_vec_pretty(&v2_high).unwrap();
            std::fs::create_dir_all(marker_path.parent().unwrap()).ok();
            std::fs::write(&marker_path, &v2_json).unwrap();

            // Candidate with sequence=3 — must be rejected.
            let rat_low = fix.build_v2_ratification(3, BundleSigningRatificationV2Action::Ratify);
            let ratified_low = fix.verify_v2(&rat_low);

            let result = super::super::verify_marker_for_validation_only_v2(
                fix.v2_inputs(&marker_path, &rat_low, &ratified_low),
            );
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                super::super::ValidationOnlyMarkerV2Error::LowerV2SequenceRefused { .. }
            ));
        }

        #[test]
        fn run132_v2_same_sequence_same_digest_passes() {
            let fix = V2TestFixture::new();
            let dir = tempfile::tempdir().unwrap();
            let marker_path = authority_state_file_path(dir.path());

            let rat = fix.build_v2_ratification(3, BundleSigningRatificationV2Action::Ratify);
            let ratified = fix.verify_v2(&rat);

            // Write v2 marker from same ratification.
            let v2_record = derive_authority_state_v2_from_ratification(
                AuthorityStateDerivationV2Inputs {
                    runtime_env: NetworkEnvironment::Mainnet,
                    runtime_chain_id: fix.runtime_chain_id,
                    runtime_genesis_hash_hex: &fix.canonical_hash_hex.clone(),
                    ratification: &rat,
                    ratified: &ratified,
                    update_source: AuthorityStateUpdateSource::ReloadApply,
                    updated_at_unix_secs: 1000,
                },
            )
            .unwrap();
            let v2_json = serde_json::to_vec_pretty(&v2_record).unwrap();
            std::fs::create_dir_all(marker_path.parent().unwrap()).ok();
            std::fs::write(&marker_path, &v2_json).unwrap();

            // Same ratification as candidate — must pass as idempotent.
            let result = super::super::verify_marker_for_validation_only_v2(
                fix.v2_inputs(&marker_path, &rat, &ratified),
            );
            assert!(result.is_ok());
            assert!(matches!(
                result.unwrap(),
                super::super::ValidationOnlyMarkerV2AcceptReason::Idempotent
            ));
        }

        #[test]
        fn run132_v2_same_sequence_different_digest_rejects() {
            let fix = V2TestFixture::new();
            let dir = tempfile::tempdir().unwrap();
            let marker_path = authority_state_file_path(dir.path());

            // Write v2 marker with sequence=3 from one ratification.
            let rat_a = fix.build_v2_ratification(3, BundleSigningRatificationV2Action::Ratify);
            let ratified_a = fix.verify_v2(&rat_a);
            let v2_a = derive_authority_state_v2_from_ratification(
                AuthorityStateDerivationV2Inputs {
                    runtime_env: NetworkEnvironment::Mainnet,
                    runtime_chain_id: fix.runtime_chain_id,
                    runtime_genesis_hash_hex: &fix.canonical_hash_hex.clone(),
                    ratification: &rat_a,
                    ratified: &ratified_a,
                    update_source: AuthorityStateUpdateSource::ReloadApply,
                    updated_at_unix_secs: 1000,
                },
            )
            .unwrap();
            let v2_json = serde_json::to_vec_pretty(&v2_a).unwrap();
            std::fs::create_dir_all(marker_path.parent().unwrap()).ok();
            std::fs::write(&marker_path, &v2_json).unwrap();

            // Different BSK with same sequence=3 — different digest.
            let (bsk2_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
            let rat_b = v2_test_helpers::build_signed_ratification_v2(
                &fix.chain_id_hex,
                RatificationEnvironment::Mainnet,
                fix.canonical_hash,
                1,
                &full_pk_hex(&fix.authority_pk),
                &fix.authority_sk,
                &bsk2_pk,
                3,
                BundleSigningRatificationV2Action::Ratify,
                None, None, None, None, None, None,
            );
            let ratified_b = qbind_ledger::verify_bundle_signing_key_ratification_v2(
                qbind_ledger::RatificationV2VerifierInputs {
                    ratification: &rat_b,
                    authority: &fix.authority,
                    expected_chain_id: &fix.chain_id_hex,
                    expected_environment: qbind_ledger::NetworkEnvironmentPolicy::Mainnet,
                    expected_genesis_hash: &fix.canonical_hash,
                },
            )
            .unwrap();

            let result = super::super::verify_marker_for_validation_only_v2(
                super::super::ValidationOnlyMarkerV2Inputs {
                    marker_path: &marker_path,
                    runtime_env: NetworkEnvironment::Mainnet,
                    runtime_chain_id: fix.runtime_chain_id,
                    runtime_genesis_hash_hex: &fix.canonical_hash_hex.clone(),
                    ratification: &rat_b,
                    ratified: &ratified_b,
                },
            );
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                super::super::ValidationOnlyMarkerV2Error::SameSequenceDifferentDigestRefused { .. }
            ));
        }

        #[test]
        fn run132_v2_higher_sequence_passes_no_persist() {
            let fix = V2TestFixture::new();
            let dir = tempfile::tempdir().unwrap();
            let marker_path = authority_state_file_path(dir.path());

            // Write v2 marker with sequence=1.
            let rat_low = fix.build_v2_ratification(1, BundleSigningRatificationV2Action::Ratify);
            let ratified_low = fix.verify_v2(&rat_low);
            let v2_low = derive_authority_state_v2_from_ratification(
                AuthorityStateDerivationV2Inputs {
                    runtime_env: NetworkEnvironment::Mainnet,
                    runtime_chain_id: fix.runtime_chain_id,
                    runtime_genesis_hash_hex: &fix.canonical_hash_hex.clone(),
                    ratification: &rat_low,
                    ratified: &ratified_low,
                    update_source: AuthorityStateUpdateSource::ReloadApply,
                    updated_at_unix_secs: 1000,
                },
            )
            .unwrap();
            let v2_json = serde_json::to_vec_pretty(&v2_low).unwrap();
            std::fs::create_dir_all(marker_path.parent().unwrap()).ok();
            std::fs::write(&marker_path, &v2_json).unwrap();
            let original_bytes = std::fs::read(&marker_path).unwrap();

            // Candidate with sequence=5 — must pass.
            let rat_high = fix.build_v2_ratification(5, BundleSigningRatificationV2Action::Ratify);
            let ratified_high = fix.verify_v2(&rat_high);

            let result = super::super::verify_marker_for_validation_only_v2(
                fix.v2_inputs(&marker_path, &rat_high, &ratified_high),
            );
            assert!(result.is_ok());
            match result.unwrap() {
                super::super::ValidationOnlyMarkerV2AcceptReason::UpgradeCompatible {
                    previous_sequence,
                    new_sequence,
                } => {
                    assert_eq!(previous_sequence, 1);
                    assert_eq!(new_sequence, 5);
                }
                other => panic!("expected UpgradeCompatible, got {:?}", other),
            }
            // Marker file unchanged.
            assert_eq!(std::fs::read(&marker_path).unwrap(), original_bytes);
        }

        #[test]
        fn run132_corrupt_local_marker_rejects() {
            let fix = V2TestFixture::new();
            let dir = tempfile::tempdir().unwrap();
            let marker_path = authority_state_file_path(dir.path());

            // Write corrupt marker.
            std::fs::create_dir_all(marker_path.parent().unwrap()).ok();
            std::fs::write(&marker_path, b"this is not valid json").unwrap();

            let rat = fix.build_v2_ratification(1, BundleSigningRatificationV2Action::Ratify);
            let ratified = fix.verify_v2(&rat);

            let result = super::super::verify_marker_for_validation_only_v2(
                fix.v2_inputs(&marker_path, &rat, &ratified),
            );
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                super::super::ValidationOnlyMarkerV2Error::CorruptLocalMarker(_)
            ));
        }

        #[test]
        fn run132_v2_no_marker_write_occurs_in_any_case() {
            let fix = V2TestFixture::new();
            let dir = tempfile::tempdir().unwrap();
            let marker_path = authority_state_file_path(dir.path());

            let rat = fix.build_v2_ratification(1, BundleSigningRatificationV2Action::Ratify);
            let ratified = fix.verify_v2(&rat);

            // First call: no marker exists.
            let _ = super::super::verify_marker_for_validation_only_v2(
                fix.v2_inputs(&marker_path, &rat, &ratified),
            );
            assert!(!marker_path.exists(), "marker file must not be created");

            // Create a v2 marker, check idempotent doesn't modify.
            let v2_record = derive_authority_state_v2_from_ratification(
                AuthorityStateDerivationV2Inputs {
                    runtime_env: NetworkEnvironment::Mainnet,
                    runtime_chain_id: fix.runtime_chain_id,
                    runtime_genesis_hash_hex: &fix.canonical_hash_hex.clone(),
                    ratification: &rat,
                    ratified: &ratified,
                    update_source: AuthorityStateUpdateSource::ReloadApply,
                    updated_at_unix_secs: 1000,
                },
            )
            .unwrap();
            let v2_json = serde_json::to_vec_pretty(&v2_record).unwrap();
            std::fs::create_dir_all(marker_path.parent().unwrap()).ok();
            std::fs::write(&marker_path, &v2_json).unwrap();
            let original_bytes = std::fs::read(&marker_path).unwrap();

            // Idempotent check.
            let _ = super::super::verify_marker_for_validation_only_v2(
                fix.v2_inputs(&marker_path, &rat, &ratified),
            );
            assert_eq!(std::fs::read(&marker_path).unwrap(), original_bytes);

            // Upgrade check.
            let rat_up = fix.build_v2_ratification(5, BundleSigningRatificationV2Action::Ratify);
            let ratified_up = fix.verify_v2(&rat_up);
            let _ = super::super::verify_marker_for_validation_only_v2(
                fix.v2_inputs(&marker_path, &rat_up, &ratified_up),
            );
            assert_eq!(std::fs::read(&marker_path).unwrap(), original_bytes);

            // Rollback check.
            // Sequence 0 is invalid for v2 derivation. Use sequence 2 < 5.
            let rat_low = fix.build_v2_ratification(2, BundleSigningRatificationV2Action::Ratify);
            let ratified_low = fix.verify_v2(&rat_low);
            let _ = super::super::verify_marker_for_validation_only_v2(
                fix.v2_inputs(&marker_path, &rat_low, &ratified_low),
            );
            assert_eq!(std::fs::read(&marker_path).unwrap(), original_bytes);
        }
    }

    // =========================================================================
    // Run 136 — v2 startup --p2p-trust-bundle mutating-surface tests
    // =========================================================================
    //
    // These tests exercise the v2 marker decide / persist composition with the
    // `AuthorityStateUpdateSource::StartupLoad` audit tag, matching the binary
    // surface the Run 136 wiring drives on startup. They mirror the Run 120
    // v1 startup test matrix (`run_120_startup_*`) but on the v2 path: a v2
    // first-write at startup persists exactly once, a v2-after-v1 migration
    // is allowed, idempotent v2 is a strict no-op, lower-sequence and same-
    // sequence/different-digest reject before mutation, a corrupt persisted
    // marker fails closed, and a dropped decision never persists.
    //
    // The Run 134 reload-apply v2 integration tests
    // (`tests/run_134_reload_apply_v2_authority_marker_tests.rs`) drive the
    // full Run 070 callback ordering against `FakeLiveTrustApplyContext`;
    // these Run 136 in-module tests focus on the marker decide/persist
    // contract that the startup binary wiring depends on.
    mod run136_v2_startup_tests {
        use super::*;
        use crate::pqc_authority_state::{
            authority_state_file_path, load_authority_state_versioned,
            persist_authority_state_atomic, AuthorityStateUpdateSource,
            PersistentAuthorityStateRecord, PersistentAuthorityStateRecordVersioned,
        };
        use crate::pqc_trust_bundle::TrustBundleEnvironment;
        use qbind_crypto::MlDsa44Backend;
        use qbind_ledger::bundle_signing_ratification::v2_test_helpers;
        use qbind_ledger::genesis::{
            compute_canonical_genesis_hash, GenesisAllocation, GenesisAuthorityConfig,
            GenesisAuthorityRoot, GenesisConfig, GenesisCouncilConfig, GenesisMonetaryConfig,
            GenesisValidator,
        };
        use qbind_ledger::{
            BundleSigningRatificationV2, BundleSigningRatificationV2Action,
            RatificationEnvironment, RatifiedBundleSigningKeyV2,
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

        fn gh_hex(gh: &qbind_ledger::GenesisHash) -> String {
            let mut s = String::with_capacity(64);
            for b in gh {
                use std::fmt::Write;
                let _ = write!(&mut s, "{:02x}", b);
            }
            s
        }

        /// Fixture mirroring `V2TestFixture` but isolated so this test
        /// module is self-contained.
        struct Fixture {
            authority_pk: Vec<u8>,
            authority_sk: Vec<u8>,
            bsk_pk: Vec<u8>,
            authority: GenesisAuthorityConfig,
            canonical_hash: qbind_ledger::GenesisHash,
            canonical_hash_hex: String,
            chain_id_hex: String,
            runtime_chain_id: ChainId,
        }

        impl Fixture {
            fn new() -> Self {
                let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
                let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
                let runtime_chain_id = ChainId::new(1);
                let chain_id_hex_str = format!("{:016x}", runtime_chain_id.as_u64());
                let auth_pk_hex = full_pk_hex(&auth_pk);
                let mut cfg = GenesisConfig::new(
                    &chain_id_hex_str,
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
                    &auth_pk_hex,
                    "foundation-bundle-signing-1",
                );
                cfg.authority = Some(GenesisAuthorityConfig::new(vec![root]));
                let gh = compute_canonical_genesis_hash(
                    &cfg,
                    qbind_ledger::NetworkEnvironmentPolicy::Mainnet,
                );
                let authority = cfg.authority.clone().unwrap();
                let gh_hex_str = gh_hex(&gh);
                Fixture {
                    authority_pk: auth_pk,
                    authority_sk: auth_sk,
                    bsk_pk,
                    authority,
                    canonical_hash: gh,
                    canonical_hash_hex: gh_hex_str,
                    chain_id_hex: chain_id_hex_str,
                    runtime_chain_id,
                }
            }

            fn build_v2_ratification(
                &self,
                sequence: u64,
                action: BundleSigningRatificationV2Action,
            ) -> BundleSigningRatificationV2 {
                v2_test_helpers::build_signed_ratification_v2(
                    &self.chain_id_hex,
                    RatificationEnvironment::Mainnet,
                    self.canonical_hash,
                    1,
                    &full_pk_hex(&self.authority_pk),
                    &self.authority_sk,
                    &self.bsk_pk,
                    sequence,
                    action,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            }

            fn verify_v2(
                &self,
                ratification: &BundleSigningRatificationV2,
            ) -> RatifiedBundleSigningKeyV2 {
                qbind_ledger::verify_bundle_signing_key_ratification_v2(
                    qbind_ledger::RatificationV2VerifierInputs {
                        ratification,
                        authority: &self.authority,
                        expected_chain_id: &self.chain_id_hex,
                        expected_environment: qbind_ledger::NetworkEnvironmentPolicy::Mainnet,
                        expected_genesis_hash: &self.canonical_hash,
                    },
                )
                .expect("v2 verification must succeed in fixture")
            }

            /// Build a `MarkerAcceptanceV2Inputs` tagged with the
            /// `StartupLoad` audit source so persisted records reflect
            /// the actual Run 136 startup surface.
            fn startup_inputs<'a>(
                &'a self,
                marker_path: &'a Path,
                ratification: &'a BundleSigningRatificationV2,
                ratified: &'a RatifiedBundleSigningKeyV2,
            ) -> MarkerAcceptanceV2Inputs<'a> {
                MarkerAcceptanceV2Inputs {
                    marker_path,
                    runtime_env: NetworkEnvironment::Mainnet,
                    runtime_chain_id: self.runtime_chain_id,
                    runtime_genesis_hash_hex: &self.canonical_hash_hex,
                    ratification,
                    ratified,
                    update_source: AuthorityStateUpdateSource::StartupLoad,
                    updated_at_unix_secs: 1_738_001_000,
                }
            }
        }

        /// Run 136 §A.1 — first accepted v2 startup ratification produces a
        /// `FirstV2Write` decision, persists exactly once after the
        /// simulated Run 055 commit boundary, with the `StartupLoad`
        /// audit tag.
        #[test]
        fn run136_first_v2_startup_accepted_persists_marker() {
            let fix = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let marker_path = authority_state_file_path(dir.path());

            let rat = fix.build_v2_ratification(1, BundleSigningRatificationV2Action::Ratify);
            let ratified = fix.verify_v2(&rat);

            let decision = decide_marker_acceptance_v2(fix.startup_inputs(
                &marker_path,
                &rat,
                &ratified,
            ))
            .expect("first v2 startup accepts");
            assert!(matches!(decision.kind(), MarkerAcceptKindV2::FirstV2Write));
            // No file written by decide alone — proves compare happens
            // before any startup mutation/persistence.
            assert!(!marker_path.exists());

            persist_accepted_v2_marker_after_commit_boundary(&decision).expect("persist ok");

            let loaded = load_authority_state_versioned(&marker_path)
                .expect("load ok")
                .expect("file present");
            match loaded {
                PersistentAuthorityStateRecordVersioned::V2(v2) => {
                    assert_eq!(
                        v2.last_update_source,
                        AuthorityStateUpdateSource::StartupLoad,
                        "Run 136 startup persists with StartupLoad audit tag"
                    );
                    assert_eq!(v2.latest_authority_domain_sequence, 1);
                }
                other => panic!("expected V2 record on disk, got {:?}", other),
            }
        }

        /// Run 136 §A.2 — same v2 marker is idempotent across a simulated
        /// restart; the on-disk bytes are NOT rewritten.
        #[test]
        fn run136_same_v2_marker_is_idempotent() {
            let fix = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let marker_path = authority_state_file_path(dir.path());

            let rat = fix.build_v2_ratification(1, BundleSigningRatificationV2Action::Ratify);
            let ratified = fix.verify_v2(&rat);

            let d1 = decide_marker_acceptance_v2(fix.startup_inputs(
                &marker_path,
                &rat,
                &ratified,
            ))
            .expect("first v2 startup accepts");
            persist_accepted_v2_marker_after_commit_boundary(&d1).expect("persist ok");
            let before = std::fs::read(&marker_path).unwrap();

            let d2 = decide_marker_acceptance_v2(fix.startup_inputs(
                &marker_path,
                &rat,
                &ratified,
            ))
            .expect("idempotent v2 startup accepts");
            assert!(matches!(d2.kind(), MarkerAcceptKindV2::Idempotent));
            assert!(!d2.should_persist());
            persist_accepted_v2_marker_after_commit_boundary(&d2)
                .expect("idempotent persist no-op");

            let after = std::fs::read(&marker_path).unwrap();
            assert_eq!(before, after, "idempotent v2 startup must NOT rewrite the file");
        }

        /// Run 136 §A.3 — higher v2 sequence at startup is an `UpgradeV2`
        /// accept; the persisted marker advances. Mirrors Run 120 §A.6.
        #[test]
        fn run136_upgrade_v2_accepts_strictly_higher_sequence() {
            let fix = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let marker_path = authority_state_file_path(dir.path());

            // Persist a v2 marker at sequence=1 first.
            let rat_low = fix.build_v2_ratification(1, BundleSigningRatificationV2Action::Ratify);
            let ratified_low = fix.verify_v2(&rat_low);
            let d1 = decide_marker_acceptance_v2(fix.startup_inputs(
                &marker_path,
                &rat_low,
                &ratified_low,
            ))
            .expect("first v2 startup accepts");
            persist_accepted_v2_marker_after_commit_boundary(&d1).expect("persist ok");

            // Restart with sequence=5.
            let rat_high =
                fix.build_v2_ratification(5, BundleSigningRatificationV2Action::Ratify);
            let ratified_high = fix.verify_v2(&rat_high);
            let d2 = decide_marker_acceptance_v2(fix.startup_inputs(
                &marker_path,
                &rat_high,
                &ratified_high,
            ))
            .expect("upgrade v2 startup accepts");
            match d2.kind() {
                MarkerAcceptKindV2::UpgradeV2 {
                    previous_sequence,
                    new_sequence,
                } => {
                    assert_eq!(*previous_sequence, 1);
                    assert_eq!(*new_sequence, 5);
                }
                other => panic!("expected UpgradeV2, got {:?}", other),
            }
            assert!(d2.should_persist());
            persist_accepted_v2_marker_after_commit_boundary(&d2).expect("persist ok");

            let loaded = load_authority_state_versioned(&marker_path)
                .expect("load ok")
                .expect("file present");
            match loaded {
                PersistentAuthorityStateRecordVersioned::V2(v2) => {
                    assert_eq!(v2.latest_authority_domain_sequence, 5);
                    assert_eq!(
                        v2.last_update_source,
                        AuthorityStateUpdateSource::StartupLoad
                    );
                }
                other => panic!("expected V2 record, got {:?}", other),
            }
        }

        /// Run 136 §A.4 — rollback to a lower v2 sequence rejects BEFORE
        /// any startup mutation; the on-disk marker is unchanged.
        #[test]
        fn run136_lower_v2_sequence_rejects_before_mutation() {
            let fix = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let marker_path = authority_state_file_path(dir.path());

            // Persist a v2 marker at sequence=7.
            let rat_high =
                fix.build_v2_ratification(7, BundleSigningRatificationV2Action::Ratify);
            let ratified_high = fix.verify_v2(&rat_high);
            let d_high = decide_marker_acceptance_v2(fix.startup_inputs(
                &marker_path,
                &rat_high,
                &ratified_high,
            ))
            .expect("first v2 startup accepts");
            persist_accepted_v2_marker_after_commit_boundary(&d_high).expect("persist ok");
            let before = std::fs::read(&marker_path).unwrap();

            // Attempt to lower sequence at the next startup.
            let rat_low = fix.build_v2_ratification(3, BundleSigningRatificationV2Action::Ratify);
            let ratified_low = fix.verify_v2(&rat_low);
            let err = decide_marker_acceptance_v2(fix.startup_inputs(
                &marker_path,
                &rat_low,
                &ratified_low,
            ))
            .expect_err("rollback must reject before mutation");
            match err {
                MutatingSurfaceMarkerV2Error::LowerV2SequenceRefused {
                    persisted_sequence,
                    attempted_sequence,
                } => {
                    assert_eq!(persisted_sequence, 7);
                    assert_eq!(attempted_sequence, 3);
                }
                other => panic!("expected LowerV2SequenceRefused, got {:?}", other),
            }
            let after = std::fs::read(&marker_path).unwrap();
            assert_eq!(
                before, after,
                "rejected v2 startup must not mutate marker"
            );
        }

        /// Run 136 §A.5 — same v2 sequence, different ratification digest
        /// rejects (equivocation) BEFORE any startup mutation.
        #[test]
        fn run136_same_v2_sequence_conflicting_digest_rejects() {
            let fix = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let marker_path = authority_state_file_path(dir.path());

            // Persist a v2 marker at sequence=5 with action=Ratify.
            let rat_a = fix.build_v2_ratification(5, BundleSigningRatificationV2Action::Ratify);
            let ratified_a = fix.verify_v2(&rat_a);
            let d_a = decide_marker_acceptance_v2(fix.startup_inputs(
                &marker_path,
                &rat_a,
                &ratified_a,
            ))
            .expect("first v2 startup accepts");
            persist_accepted_v2_marker_after_commit_boundary(&d_a).expect("persist ok");
            let before = std::fs::read(&marker_path).unwrap();

            // Attempt a different ratification at the same sequence by
            // changing the active key — produces a different
            // ratification digest at the same sequence number.
            let (bsk_pk_b, _) = MlDsa44Backend::generate_keypair().unwrap();
            let rat_b = v2_test_helpers::build_signed_ratification_v2(
                &fix.chain_id_hex,
                RatificationEnvironment::Mainnet,
                fix.canonical_hash,
                1,
                &full_pk_hex(&fix.authority_pk),
                &fix.authority_sk,
                &bsk_pk_b,
                5,
                BundleSigningRatificationV2Action::Ratify,
                None,
                None,
                None,
                None,
                None,
                None,
            );
            let ratified_b = fix.verify_v2(&rat_b);

            let err = decide_marker_acceptance_v2(fix.startup_inputs(
                &marker_path,
                &rat_b,
                &ratified_b,
            ))
            .expect_err("same-sequence different-digest must reject");
            // Allowed: SameSequenceConflictingDigest OR
            // SameSequenceConflictingKeyOrAction depending on which
            // mismatch the compare path surfaces first.
            assert!(
                matches!(
                    err,
                    MutatingSurfaceMarkerV2Error::SameSequenceConflictingDigest { .. }
                        | MutatingSurfaceMarkerV2Error::SameSequenceConflictingKeyOrAction { .. }
                ),
                "got {:?}",
                err
            );
            let after = std::fs::read(&marker_path).unwrap();
            assert_eq!(before, after, "rejected v2 startup must not mutate marker");
        }

        /// Run 136 §A.6 — corrupt persisted marker fails closed BEFORE any
        /// startup mutation; the garbage on disk is NOT auto-overwritten.
        #[test]
        fn run136_corrupt_marker_fails_closed() {
            let fix = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let marker_path = authority_state_file_path(dir.path());
            std::fs::create_dir_all(marker_path.parent().unwrap()).unwrap();
            std::fs::write(&marker_path, b"{ not valid json").unwrap();
            let original_bytes = std::fs::read(&marker_path).unwrap();

            let rat = fix.build_v2_ratification(1, BundleSigningRatificationV2Action::Ratify);
            let ratified = fix.verify_v2(&rat);

            let err = decide_marker_acceptance_v2(fix.startup_inputs(
                &marker_path,
                &rat,
                &ratified,
            ))
            .expect_err("corrupt marker must reject before mutation");
            assert!(
                matches!(err, MutatingSurfaceMarkerV2Error::LoadOrCorruption(_)),
                "got {:?}",
                err
            );
            // Garbage is NOT auto-overwritten.
            assert_eq!(std::fs::read(&marker_path).unwrap(), original_bytes);
        }

        /// Run 136 §A.7 — pre-persisted v1 marker → v2 startup ratification
        /// is an explicit `V2AfterV1Migration` accept; persisting the v2
        /// decision replaces the v1 record with a v2 record. Mirrors the
        /// Run 134 reload-apply §C.5 case for the startup surface.
        #[test]
        fn run136_v2_after_v1_migration_accepts_and_persists_v2() {
            let fix = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let marker_path = authority_state_file_path(dir.path());

            // Pre-persist a v1 marker (matching domain triple).
            let v1_record = PersistentAuthorityStateRecord::new(
                fix.chain_id_hex.clone(),
                TrustBundleEnvironment::Mainnet,
                fix.canonical_hash_hex.clone(),
                1,
                1,
                None,
                full_pk_hex(&fix.authority_pk),
                full_pk_hex(&fix.bsk_pk)[..64].to_string(),
                "aa".repeat(32),
                AuthorityStateUpdateSource::StartupLoad,
                1_000,
            );
            persist_authority_state_atomic(&marker_path, &v1_record).unwrap();

            // Now arrive at startup with a v2 sidecar at a higher sequence.
            let rat = fix.build_v2_ratification(2, BundleSigningRatificationV2Action::Ratify);
            let ratified = fix.verify_v2(&rat);
            let decision = decide_marker_acceptance_v2(fix.startup_inputs(
                &marker_path,
                &rat,
                &ratified,
            ))
            .expect("v2-after-v1 migration accepts at startup");
            assert!(matches!(
                decision.kind(),
                MarkerAcceptKindV2::V2AfterV1Migration
            ));
            assert!(decision.should_persist());
            persist_accepted_v2_marker_after_commit_boundary(&decision).expect("persist ok");

            // On-disk record is now V2 with the StartupLoad audit tag.
            let loaded = load_authority_state_versioned(&marker_path)
                .expect("load ok")
                .expect("file present");
            assert!(matches!(
                loaded,
                PersistentAuthorityStateRecordVersioned::V2(_)
            ));
            if let PersistentAuthorityStateRecordVersioned::V2(v2) = loaded {
                assert_eq!(v2.latest_authority_domain_sequence, 2);
                assert_eq!(
                    v2.last_update_source,
                    AuthorityStateUpdateSource::StartupLoad
                );
            }
        }

        /// Run 136 §A.8 — a dropped v2 decision (apply-failure simulation)
        /// must NOT persist the v2 marker, just like Run 120 §A.9 for v1.
        #[test]
        fn run136_dropped_decision_does_not_persist_v2_marker() {
            let fix = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let marker_path = authority_state_file_path(dir.path());
            assert!(!marker_path.exists());

            let rat = fix.build_v2_ratification(1, BundleSigningRatificationV2Action::Ratify);
            let ratified = fix.verify_v2(&rat);
            {
                let _decision = decide_marker_acceptance_v2(fix.startup_inputs(
                    &marker_path,
                    &rat,
                    &ratified,
                ))
                .expect("first v2 startup accepts");
                // Drop without calling persist (simulates the Err arm of
                // the Run 055 sequence write killing the process before
                // the v2 persist step is reached).
            }
            assert!(
                !marker_path.exists(),
                "dropped Run 136 v2 decision must NOT persist the marker"
            );
        }
    }
}