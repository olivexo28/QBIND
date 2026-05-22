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
}