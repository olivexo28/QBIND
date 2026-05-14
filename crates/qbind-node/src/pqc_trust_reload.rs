//! Run 069 (C4 piece: PQC trust-bundle hot-reload boundary —
//! validation/staging only, disabled-by-default): a safe,
//! **non-mutating** candidate-bundle validation pipeline that reuses
//! every Run 050–065 startup security check but applies **no** live
//! trust changes.
//!
//! # Strict scope (what this module is and is NOT)
//!
//! Run 069 is **only** the safest possible foundation under the
//! umbrella "trust-bundle hot reload" item in `docs/whitepaper/contradiction.md`
//! C4. It is intentionally minimal:
//!
//! - This module **validates** a candidate bundle (from a local file
//!   path) using the same fail-closed checks as startup.
//! - This module **stages** safe public metadata for that candidate.
//! - This module **does NOT** apply the candidate to live P2P trust
//!   state. The active roots, the active revocation lookup sets, the
//!   peer-handshake `LeafCertRevocationList`, and any existing KEMTLS
//!   session are completely untouched.
//! - This module **does NOT** persist the candidate's sequence
//!   number. Validation-only / rejected candidates **must not burn a
//!   sequence number** — that would equivocate the operator-visible
//!   anti-rollback contract from Run 055/056.
//! - This module **does NOT** accept peer-supplied or gossiped
//!   bundles. The only allowed source is a local file path the
//!   operator already controls (same trust assumption as the
//!   startup `--p2p-trust-bundle` flag).
//! - This module **does NOT** rotate the bundle-signing key, ratify
//!   a new signing key, integrate with KMS/HSM, or implement
//!   `activation_epoch` runtime sourcing. Those remain open under
//!   `docs/whitepaper/contradiction.md` C4.
//! - This module **does NOT** redesign KEMTLS, consensus, or the
//!   sequence persistence layer.
//!
//! Operators must read the Run 069 evidence document and the C4
//! contradiction entry: "candidate validated" does NOT mean the new
//! roots are in effect on this node. Applying a candidate requires a
//! future run that explicitly lands the live-apply path under a
//! separate review.
//!
//! # Reused validation
//!
//! Where possible this module calls the EXACT SAME functions the
//! startup binary calls:
//!
//! - parse + structural validation + ML-DSA-44 signature verification +
//!   environment binding + chain-id binding + activation-height
//!   gating + Run 065 min-activation-margin policy + revocation
//!   activation gating
//!   → [`crate::pqc_trust_bundle::TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation`];
//! - sequence anti-rollback read-only check
//!   → [`crate::pqc_trust_sequence::peek_sequence`] (Run 069
//!     read-only sibling of `check_and_update_sequence`; never
//!     writes the persistence file);
//! - local revoked-leaf self-check (Run 061 logic)
//!   → [`crate::pqc_trust_bundle::check_local_leaf_not_revoked`];
//! - local revoked-issuer-root self-check (Run 063 logic)
//!   → [`crate::pqc_trust_bundle::check_local_leaf_issuer_root_not_revoked`].
//!
//! No validation logic is forked or re-implemented here. If a future
//! run hardens any of those primitives, this module benefits
//! automatically.
//!
//! # Disabled by default
//!
//! There is no CLI flag enabled by default that drives this module.
//! The hidden, evidence-only CLI hook
//! `--p2p-trust-bundle-reload-check <PATH>` in `crates/qbind-node/src/cli.rs`
//! is the only operator-visible entry point on the binary surface,
//! and when present the binary runs **validation only** and exits
//! after reporting the verdict — it never starts the node and never
//! mutates live trust state. Tests use the library entry points
//! directly.
//!
//! # No new metrics
//!
//! Run 069 deliberately adds **no** `/metrics` families. The
//! validation-only / staging boundary runs at most once per process
//! start (via the hidden CLI flag) and the process exits immediately
//! afterwards — `/metrics` is never bound on that path, so a counter
//! family would never be scrapeable and would mislead operators into
//! thinking hot-apply is implemented. The verdict and staged
//! metadata are surfaced in operator logs only. This is the same
//! discipline followed in Run 061 / Run 063 startup self-checks (see
//! `crates/qbind-node/src/main.rs` block comments for those runs).

use std::path::{Path, PathBuf};

use qbind_types::{ChainId, NetworkEnvironment};

use crate::pqc_trust_activation::{ActivationCheckOutcome, ActivationContext};
use crate::pqc_trust_bundle::{
    self, BundleSigningKeySet, LoadedTrustBundle, LocalLeafIssuerRootSelfCheckError,
    LocalLeafSelfCheckError, TrustBundle, TrustBundleEnvironment, TrustBundleError,
};
use crate::pqc_trust_sequence::{
    self, SequencePeekOutcome, TrustBundleSequenceError,
};

/// Run 069 fail-closed errors. Every variant carries enough context
/// for operator logs without exposing any private material. A
/// rejected candidate **never** mutates live trust state or sequence
/// persistence.
#[derive(Debug)]
pub enum ReloadCheckError {
    /// The candidate bundle failed the Run 050/051/053/057/062/065
    /// structural / signature / environment / chain-id / activation /
    /// revocation-activation pipeline. The inner
    /// [`TrustBundleError`] is the same value the startup loader
    /// would have surfaced.
    Bundle(TrustBundleError),
    /// The candidate bundle failed the Run 055 anti-rollback
    /// read-only check against the persisted sequence record. The
    /// persistence file was NOT modified.
    Sequence(TrustBundleSequenceError),
    /// The candidate bundle's active revocation list contains the
    /// fingerprint of the locally-configured leaf cert (Run 061
    /// self-check semantics; bundle is unsafe to apply on this node).
    LocalLeafRevoked(LocalLeafSelfCheckError),
    /// The candidate bundle's active root-revocation list contains
    /// the root id that issued the locally-configured leaf cert
    /// (Run 063 self-check semantics).
    LocalIssuerRootRevoked(LocalLeafIssuerRootSelfCheckError),
}

impl std::fmt::Display for ReloadCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bundle(e) => write!(f, "candidate bundle invalid: {}", e),
            Self::Sequence(e) => write!(f, "candidate sequence rejected: {}", e),
            Self::LocalLeafRevoked(e) => write!(
                f,
                "candidate rejects local leaf via active revocation list: {}",
                e
            ),
            Self::LocalIssuerRootRevoked(e) => write!(
                f,
                "candidate rejects local issuer root via active root-revocation list: {}",
                e
            ),
        }
    }
}

impl std::error::Error for ReloadCheckError {}

/// Run 069 disabled-by-default validation/staging output for a
/// successfully validated candidate trust bundle.
///
/// All fields are *public, log-safe* metadata. Specifically:
///
/// - Full and short canonical fingerprints are derived from the
///   bundle's public JSON via SHA3-256, identical to the values
///   already surfaced on `/metrics` and in startup logs.
/// - `sequence`, `environment`, `chain_id_hex`, root and revocation
///   counts are public bundle envelope data.
/// - No private-key material, signing-key material, or KEM secret
///   is referenced. This struct intentionally does NOT carry
///   `LoadedTrustBundle` (its `active_roots` would be too easy to
///   confuse with "applied roots"); callers that genuinely need the
///   loaded structure for further test introspection get it via
///   [`validate_candidate_bundle_full`].
///
/// `staged_metadata_log_line` returns the canonical operator-log
/// line, matching the wording used by the hidden CLI hook in
/// `main.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCandidate {
    /// 64-char lowercase hex SHA3-256 fingerprint of the candidate
    /// bundle's canonical encoding (same value as the live
    /// `loaded.fingerprint_hex()`).
    pub fingerprint_hex: String,
    /// First 8 hex chars of `fingerprint_hex` (short log form).
    pub fingerprint_prefix: String,
    /// Bundle-declared sequence number. NOT yet persisted (Run 069
    /// is validation-only).
    pub sequence: u64,
    /// Canonical environment of the candidate bundle.
    pub environment: TrustBundleEnvironment,
    /// 16-char lowercase hex chain id of the candidate (no `0x` /
    /// `chain_` prefix).
    pub chain_id_hex: String,
    /// Number of bundle roots that would become active if this
    /// candidate were applied — NOT applied by this module.
    pub active_root_count: usize,
    /// Number of root ids that would be currently revoked if this
    /// candidate were applied.
    pub active_revoked_root_count: usize,
    /// Number of root ids in the candidate's `pending` revocation
    /// gate (declared with an `activation_height` not yet satisfied).
    pub pending_revoked_root_count: usize,
    /// Number of leaf fingerprints that would be currently revoked
    /// if applied.
    pub active_revoked_leaf_count: usize,
    /// Number of leaf fingerprints in the candidate's `pending`
    /// revocation gate.
    pub pending_revoked_leaf_count: usize,
    /// Whether the candidate's signature envelope was verified
    /// (Run 051). Unsigned DevNet bundles report `false`.
    pub signature_verified: bool,
    /// Activation outcome reported by the same gate used at startup
    /// — `required_height`, `current_height`, `required_epoch`,
    /// `current_epoch`. A future-dated candidate never reaches this
    /// struct: it would have been rejected as
    /// `ReloadCheckError::Bundle(TrustBundleError::Activation(_))`.
    pub activation: ActivationCheckOutcome,
    /// Run 055 read-only peek outcome. Reports "no prior record",
    /// "would-upgrade", or "equal-sequence same-fingerprint" without
    /// performing any write.
    pub sequence_peek: SequencePeekOutcome,
    /// Path of the persistence file the peek consulted (informational;
    /// useful for evidence logging).
    pub sequence_persistence_path: Option<PathBuf>,
}

impl ValidatedCandidate {
    /// Operator-log line matching the format used by the hidden CLI
    /// hook. **Single source of truth** for the validation-only /
    /// staging boundary message so tests and the binary agree.
    pub fn staged_metadata_log_line(&self) -> String {
        let seq_status = match &self.sequence_peek {
            SequencePeekOutcome::NoPriorRecord { .. } => {
                "sequence_peek=no-prior-record".to_string()
            }
            SequencePeekOutcome::WouldUpgrade {
                previous_sequence, ..
            } => format!(
                "sequence_peek=would-upgrade(persisted={} -> candidate={})",
                previous_sequence, self.sequence
            ),
            SequencePeekOutcome::EqualSequenceSameFingerprint { sequence, .. } => {
                format!(
                    "sequence_peek=equal-same-fingerprint(sequence={})",
                    sequence
                )
            }
        };
        format!(
            "[binary] Run 069: trust-bundle candidate validated; not applied; sequence not \
             persisted; live trust state unchanged \
             (candidate_fp={}.. env={} chain_id={} sequence={} signature_verified={} \
             active_roots={} active_revoked_roots={} pending_revoked_roots={} \
             active_revoked_leaves={} pending_revoked_leaves={} \
             activation_required_height={:?} activation_current_height={:?} \
             activation_required_epoch={:?} activation_current_epoch={:?} {})",
            self.fingerprint_prefix,
            self.environment,
            self.chain_id_hex,
            self.sequence,
            self.signature_verified,
            self.active_root_count,
            self.active_revoked_root_count,
            self.pending_revoked_root_count,
            self.active_revoked_leaf_count,
            self.pending_revoked_leaf_count,
            self.activation.required_height,
            self.activation.current_height,
            self.activation.required_epoch,
            self.activation.current_epoch,
            seq_status,
        )
    }
}

/// Inputs to the Run 069 validation-only pipeline.
///
/// Mirrors the runtime context the startup binary already has after
/// CLI parsing. None of these are mutated.
#[derive(Debug, Clone)]
pub struct ReloadCheckInputs<'a> {
    /// Candidate bundle file path (local only — no network input).
    pub candidate_path: &'a Path,
    /// Runtime environment (DevNet / TestNet / MainNet).
    pub environment: NetworkEnvironment,
    /// Runtime chain id.
    pub chain_id: ChainId,
    /// Wall-clock seconds used by the validity-window check. Same
    /// operational-freshness scope as the startup loader.
    pub validation_time_secs: u64,
    /// Bundle-signing key set. Must be non-empty on TestNet/MainNet
    /// (the same rule as the startup loader); failing to satisfy that
    /// rule surfaces as `TrustBundleError::UnsignedBundleNotAllowed`
    /// or `TrustBundleError::MissingSigningKey` from the inner
    /// validator — the same fail-closed verdict as startup.
    pub signing_keys: &'a BundleSigningKeySet,
    /// Activation runtime context (height + epoch sources). Pass
    /// [`ActivationContext::height_only`] / `unavailable()` exactly
    /// as the startup binary already does.
    pub activation_ctx: ActivationContext,
    /// Optional persistence file path. When `Some`, the candidate's
    /// `(sequence, fingerprint)` is checked against the persisted
    /// record using [`pqc_trust_sequence::peek_sequence`] — a
    /// **read-only** operation that never writes the file.
    /// When `None`, the sequence peek step is skipped and
    /// `sequence_peek` is reported as
    /// [`SequencePeekOutcome::NoPriorRecord`]. (Skipping is the same
    /// DevNet-without-`--data-dir` shape supported at startup; it is
    /// explicitly NOT a fallback because no live state is mutated
    /// either way in Run 069.)
    pub sequence_persistence_path: Option<&'a Path>,
    /// Optional local leaf cert bytes. When `Some`, the candidate's
    /// active leaf-revocation set is checked against the local leaf
    /// fingerprint (Run 061 semantics) and the candidate's active
    /// root-revocation set is checked against the local leaf's
    /// issuer root id (Run 063 semantics). When `None`, both checks
    /// are skipped — same conservative skip-when-not-available shape
    /// as the startup `(loaded, leaf_credentials)` guard in
    /// `main.rs`.
    pub local_leaf_cert_bytes: Option<&'a [u8]>,
}

/// Run 069 entry point: validate a candidate trust bundle without
/// mutating any live state. Returns [`ValidatedCandidate`] metadata
/// on success or [`ReloadCheckError`] on any fail-closed condition.
///
/// On either return path:
/// - the live PQC trust state of the running process (active roots,
///   active leaf revocation set, peer sessions, KEMTLS sessions) is
///   unchanged;
/// - the on-disk sequence persistence file is unchanged;
/// - no `/metrics` family is mutated;
/// - the candidate bundle file at `inputs.candidate_path` is only
///   read.
pub fn validate_candidate_bundle(
    inputs: ReloadCheckInputs<'_>,
) -> Result<ValidatedCandidate, ReloadCheckError> {
    let (loaded, _activation, candidate) = validate_candidate_bundle_full(inputs)?;
    // We retain `loaded` for future test introspection inside the
    // `_full` variant; drop it explicitly here so the public surface
    // doesn't promise live access to the loaded structure.
    let _ = loaded;
    Ok(candidate)
}

/// Run 069 entry point that additionally surfaces the inner
/// [`LoadedTrustBundle`] and [`ActivationCheckOutcome`] for tests
/// that want to assert against the reused startup validators. The
/// returned `LoadedTrustBundle` MUST NOT be merged into any live
/// trust state by the caller — the staging boundary is preserved
/// only when the caller treats the result as data, not as an apply
/// trigger.
pub fn validate_candidate_bundle_full(
    inputs: ReloadCheckInputs<'_>,
) -> Result<(LoadedTrustBundle, ActivationCheckOutcome, ValidatedCandidate), ReloadCheckError> {
    // 1. Run 050/051/053/057/062/065 reuse — exactly the same loader
    // the binary calls at startup, so any future hardening of any
    // sub-check (e.g. a new field in `TrustBundle`) automatically
    // applies to the candidate path too.
    let (loaded, activation) =
        TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
            inputs.candidate_path,
            inputs.environment,
            inputs.chain_id,
            inputs.validation_time_secs,
            inputs.signing_keys,
            inputs.activation_ctx,
        )
        .map_err(ReloadCheckError::Bundle)?;

    // 2. Run 055 anti-rollback peek — read-only by construction. We
    // never call `check_and_update_sequence` here.
    let sequence_peek = match inputs.sequence_persistence_path {
        Some(seq_path) => pqc_trust_sequence::peek_sequence(
            seq_path,
            inputs.environment,
            inputs.chain_id,
            loaded.bundle.sequence,
            &loaded.fingerprint,
        )
        .map_err(ReloadCheckError::Sequence)?,
        None => SequencePeekOutcome::NoPriorRecord {
            candidate_sequence: loaded.bundle.sequence,
            candidate_fingerprint_hex: loaded.fingerprint_hex(),
        },
    };

    // 3. Run 061 local-leaf revocation self-check against the
    // candidate's currently-active revoked-leaf set. We deliberately
    // do not consult `pending_revoked_leaf_fingerprints` — pending
    // entries are observability-only, not enforcement.
    if let Some(local_leaf_bytes) = inputs.local_leaf_cert_bytes {
        if !loaded.revoked_leaf_fingerprints.is_empty() {
            pqc_trust_bundle::check_local_leaf_not_revoked(
                local_leaf_bytes,
                &loaded.revoked_leaf_fingerprints,
                &loaded.fingerprint,
            )
            .map_err(ReloadCheckError::LocalLeafRevoked)?;
        }
        // 4. Run 063 local-issuer-root revocation self-check against
        // the candidate's currently-active revoked-root set. Pending
        // root revocations are explicitly excluded for the same
        // reason as Run 063 at startup.
        pqc_trust_bundle::check_local_leaf_issuer_root_not_revoked(
            local_leaf_bytes,
            &loaded.revoked_root_ids,
            &loaded.fingerprint,
        )
        .map_err(ReloadCheckError::LocalIssuerRootRevoked)?;
    }

    let fingerprint_hex = loaded.fingerprint_hex();
    let fingerprint_prefix = fingerprint_hex[..8].to_string();
    let chain_id_hex = pqc_trust_sequence::chain_id_hex(inputs.chain_id);
    let candidate = ValidatedCandidate {
        fingerprint_hex,
        fingerprint_prefix,
        sequence: loaded.bundle.sequence,
        environment: loaded.environment(),
        chain_id_hex,
        active_root_count: loaded.active_root_count(),
        active_revoked_root_count: loaded.revoked_root_count(),
        pending_revoked_root_count: loaded.pending_revoked_root_count(),
        active_revoked_leaf_count: loaded.revoked_leaf_fingerprint_count(),
        pending_revoked_leaf_count: loaded.pending_revoked_leaf_fingerprint_count(),
        signature_verified: loaded.signature_status.is_verified(),
        activation: activation.clone(),
        sequence_peek,
        sequence_persistence_path: inputs.sequence_persistence_path.map(PathBuf::from),
    };
    Ok((loaded, activation, candidate))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reload_check_error_display_is_operator_actionable() {
        // Smoke: every Display variant is non-empty and mentions
        // "candidate" so operator logs are unambiguous about scope.
        let cases: Vec<ReloadCheckError> = vec![
            ReloadCheckError::Bundle(TrustBundleError::Io("path: kind".into())),
            ReloadCheckError::Sequence(TrustBundleSequenceError::SequenceRollback {
                attempted_sequence: 1,
                persisted_highest_sequence: 5,
            }),
            ReloadCheckError::LocalLeafRevoked(LocalLeafSelfCheckError::Revoked {
                leaf_fingerprint_prefix: "aaaaaaaa".into(),
                bundle_fingerprint_prefix: "bbbbbbbb".into(),
            }),
            ReloadCheckError::LocalIssuerRootRevoked(
                LocalLeafIssuerRootSelfCheckError::IssuerRootRevoked {
                    root_id_prefix: "11111111".into(),
                    leaf_fingerprint_prefix: "22222222".into(),
                    bundle_fingerprint_prefix: "33333333".into(),
                },
            ),
        ];
        for e in cases {
            let s = format!("{}", e);
            assert!(s.to_lowercase().contains("candidate"), "msg: {}", s);
            assert!(s.len() > 20, "msg too short: {}", s);
        }
    }

    #[test]
    fn validated_candidate_log_line_marks_not_applied() {
        let v = ValidatedCandidate {
            fingerprint_hex: "ab".repeat(32),
            fingerprint_prefix: "abababab".into(),
            sequence: 7,
            environment: TrustBundleEnvironment::Devnet,
            chain_id_hex: "0123456789abcdef".into(),
            active_root_count: 1,
            active_revoked_root_count: 0,
            pending_revoked_root_count: 0,
            active_revoked_leaf_count: 0,
            pending_revoked_leaf_count: 0,
            signature_verified: true,
            activation: ActivationCheckOutcome {
                required_height: Some(10),
                current_height: Some(10),
                required_epoch: None,
                current_epoch: None,
            },
            sequence_peek: SequencePeekOutcome::NoPriorRecord {
                candidate_sequence: 7,
                candidate_fingerprint_hex: "ab".repeat(32),
            },
            sequence_persistence_path: None,
        };
        let line = v.staged_metadata_log_line();
        // The operator-facing line MUST clearly say:
        //   * validation-only / not applied;
        //   * sequence not persisted;
        //   * live trust state unchanged.
        assert!(line.contains("Run 069"), "{}", line);
        assert!(line.contains("not applied"), "{}", line);
        assert!(line.contains("sequence not persisted"), "{}", line);
        assert!(line.contains("live trust state unchanged"), "{}", line);
        assert!(line.contains("abababab"), "{}", line);
        assert!(line.contains("sequence=7"), "{}", line);
    }
}