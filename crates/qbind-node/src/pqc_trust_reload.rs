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

// ============================================================================
// Run 070 — local operator-triggered live trust-bundle apply
// ============================================================================
//
// Run 070 extends this module with the *first* live-apply path for a
// validated reload candidate. The Run 069 entry points
// ([`validate_candidate_bundle`] / [`validate_candidate_bundle_full`])
// remain bit-for-bit unchanged and continue to perform NO mutation of
// live trust state or sequence persistence; Run 070 builds on top of
// them, never as a replacement.
//
// **Strict scope.** Run 070 is still NOT:
//
// - peer-supplied / gossiped bundle acceptance (local file only);
// - automatic filesystem-watcher hot reload (operator-triggered only);
// - KMS / HSM custody;
// - bundle-signing-key ratification;
// - `activation_epoch` runtime sourcing;
// - selective session retention (the conservative v0 policy in
//   `task/RUN_070_TASK.txt` requires evicting all existing P2P
//   sessions on a successful live trust swap because pre-existing
//   sessions may have been authenticated under roots or leaves now
//   revoked or removed).
//
// **Architecture.** The running `qbind-node` binary currently bakes
// active PQC trust state into the immutable `ClientHandshakeConfig` /
// `ServerHandshakeConfig` structures constructed once inside
// `crates/qbind-node/src/p2p_node_builder.rs`. There is no
// process-wide mutable trust-context handle today, no session
// manager with an `evict_all` hook on the production-honest PQC
// path, and no way for an in-process actor to swap roots /
// revocations under a live handshake verifier. The task explicitly
// directs us NOT to fake hot reload in this situation:
//
// > If current code does not support mutable live trust context
// > safely: do not fake hot reload. Implement the smallest safe
// > "reload apply unsupported because immutable trust context"
// > boundary and document it.
//
// Accordingly, Run 070 introduces the apply *contract*
// ([`ApplyMode`], [`ReloadApplyError`], [`LiveTrustApplyContext`],
// [`apply_validated_candidate`]) as a library API whose semantics
// are fully proven by integration tests against a deterministic
// fake [`LiveTrustApplyContext`], and the running binary surfaces
// the [`ReloadApplyError::UnsupportedRuntimeContext`] boundary
// honestly to operators. A future run that lands a mutable
// process-wide trust handle + session-eviction hook can wire that
// handle into [`apply_validated_candidate`] without changing the
// security pipeline or sequencing here.
//
// **Sequencing contract.** Every successful live apply follows
// exactly this ordering:
//
//   1. Validate the candidate using the Run 069 pipeline.
//      Validation must NOT mutate live state. Validation failure
//      surfaces as [`ReloadApplyError::ValidationFailed`] with the
//      Run 069 reason inside, and NO swap, NO eviction, NO sequence
//      commit happen.
//   2. Take a snapshot of the current live trust state via
//      [`LiveTrustApplyContext::snapshot_active`] so it can be
//      rolled back if any subsequent step fails.
//   3. Atomically swap the active trust state via
//      [`LiveTrustApplyContext::swap_trust_state`]. Swap failure →
//      [`ReloadApplyError::StateSwapFailed`]; old live state remains
//      active (no rollback needed because no swap occurred); no
//      sequence commit.
//   4. Evict existing P2P / KEMTLS sessions via
//      [`LiveTrustApplyContext::evict_sessions`]. Eviction failure →
//      attempt rollback via
//      [`LiveTrustApplyContext::rollback_trust_state`] and surface
//      [`ReloadApplyError::SessionEvictionFailed`]. NO sequence
//      commit happens.
//   5. Commit the candidate's sequence to the persistence file via
//      [`LiveTrustApplyContext::commit_sequence`]. Commit failure
//      → attempt rollback; if rollback succeeds, surface
//      [`ReloadApplyError::SequenceCommitFailed`]; if rollback also
//      fails the live state is now ahead of persisted sequence and
//      the caller MUST treat the apply as fatal (the binary path
//      would stop the node). This is the safer choice mandated by
//      `task/RUN_070_TASK.txt` §"If sequence commit fails after
//      swap".
//
// This module *never* commits sequence before swap, *never*
// commits sequence on a validation failure, and *never* keeps the
// new live trust state while losing the sequence commit. Tests
// in `crates/qbind-node/tests/run_070_pqc_trust_bundle_reload_apply_tests.rs`
// drive each branch.
//
// **Session policy (v0, conservative).** Successful live trust
// swap mandates closing every existing P2P / KEMTLS session and
// forcing peers to reconnect under the new trust context. Pre-
// existing sessions may have been authenticated by roots or
// leaves that are now revoked or removed; selective retention is
// out of scope for Run 070. The evidence doc states this may
// cause a short liveness interruption but is safer than retaining
// possibly-stale trust.

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

// ============================================================================
// Run 070 — apply API (mode, errors, context trait, entry point).
// ============================================================================

/// Run 070 apply mode. Distinguishes a Run 069-equivalent
/// validation-only invocation from a true live-apply invocation,
/// so a single entry point can serve both with no behavioural
/// drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyMode {
    /// Same fail-closed behaviour as [`validate_candidate_bundle`].
    /// Live trust state is NOT touched. Sequence persistence is
    /// NOT touched. Sessions are NOT touched. The
    /// [`LiveTrustApplyContext`] passed in MAY be `None`. This mode
    /// exists so callers (notably tests) can drive the same entry
    /// point in dry-run shape.
    ValidateOnly,
    /// Live apply. After the Run 069 validation pipeline succeeds,
    /// the apply pipeline atomically swaps the live trust state,
    /// evicts existing P2P / KEMTLS sessions, and commits the
    /// candidate's sequence to the persistence file. Requires a
    /// non-`None` [`LiveTrustApplyContext`] handle; without one the
    /// caller receives [`ReloadApplyError::UnsupportedRuntimeContext`]
    /// (the same fail-closed outcome the production binary
    /// produces today because no mutable runtime trust handle
    /// exists yet — see module-level comment).
    ApplyLive,
}

/// Run 070 fail-closed apply errors. **Every** variant is a
/// safety-preserving outcome: either no live trust state has been
/// mutated, or any mutation has been rolled back, or the live
/// state is in a state the caller must treat as fatal (the
/// `SequenceCommitFailedRollbackAlsoFailed` variant) and stop the
/// node. **None** of these variants are silent fallbacks.
#[derive(Debug)]
pub enum ReloadApplyError {
    /// Candidate failed the Run 069 validation pipeline. Live trust
    /// state was NOT touched. Sequence persistence was NOT touched.
    /// Sessions were NOT touched. The inner [`ReloadCheckError`]
    /// carries the same fail-closed reason a Run 069 reload-check
    /// would surface.
    ValidationFailed(ReloadCheckError),
    /// Live apply was requested ([`ApplyMode::ApplyLive`]) but no
    /// [`LiveTrustApplyContext`] was supplied. The current
    /// `qbind-node` binary surfaces this error because the running
    /// process has no mutable live trust handle yet (see module-
    /// level comment); a future run that lands one wires it in
    /// without changing this contract.
    UnsupportedRuntimeContext(String),
    /// Live apply was requested but operator opt-in was missing
    /// (e.g. `--p2p-trust-bundle-reload-apply-enabled` was not
    /// supplied). Distinct from `UnsupportedRuntimeContext` so the
    /// operator sees the precise reason in logs.
    LiveReloadDisabled(String),
    /// [`LiveTrustApplyContext::swap_trust_state`] returned an
    /// error. Old live state remains active (no swap occurred).
    /// NO sequence commit happened. NO sessions were evicted.
    StateSwapFailed(String),
    /// [`LiveTrustApplyContext::evict_sessions`] returned an error
    /// **after** a successful swap. The implementation invoked
    /// [`LiveTrustApplyContext::rollback_trust_state`] to restore
    /// the pre-swap live state. NO sequence commit happened. The
    /// `rollback_ok` flag reflects whether the rollback itself
    /// succeeded; if `false`, the caller MUST treat the node as
    /// in a fatal state per `task/RUN_070_TASK.txt` policy.
    SessionEvictionFailed {
        message: String,
        rollback_ok: bool,
    },
    /// [`LiveTrustApplyContext::commit_sequence`] failed AFTER the
    /// state swap and session eviction succeeded. The
    /// implementation invoked
    /// [`LiveTrustApplyContext::rollback_trust_state`] to restore
    /// the pre-swap live state and the rollback succeeded; the
    /// node is back on its previous trust state and previous
    /// sequence record. The candidate was NOT applied.
    SequenceCommitFailed(String),
    /// [`LiveTrustApplyContext::commit_sequence`] failed AFTER the
    /// state swap and session eviction succeeded, AND the
    /// subsequent rollback attempt also failed. The live trust
    /// state is now ahead of the on-disk sequence record; the
    /// operator MUST stop the node and recover offline. This is
    /// the safest fail-closed outcome required by
    /// `task/RUN_070_TASK.txt` §"If sequence commit fails after
    /// swap".
    SequenceCommitFailedRollbackAlsoFailed {
        commit_message: String,
        rollback_message: String,
    },
}

impl std::fmt::Display for ReloadApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ValidationFailed(e) => write!(
                f,
                "Run 070 candidate apply rejected at validation stage; live trust state \
                 unchanged; sequence not committed; sessions untouched: {}",
                e
            ),
            Self::UnsupportedRuntimeContext(msg) => write!(
                f,
                "Run 070 candidate apply unsupported on this runtime — no mutable live trust \
                 context handle is available; live trust state unchanged; sequence not \
                 committed; sessions untouched: {}",
                msg
            ),
            Self::LiveReloadDisabled(msg) => write!(
                f,
                "Run 070 candidate apply refused — live reload-apply is disabled by default \
                 and operator opt-in flag was not supplied; live trust state unchanged; \
                 sequence not committed; sessions untouched: {}",
                msg
            ),
            Self::StateSwapFailed(msg) => write!(
                f,
                "Run 070 candidate apply failed at state-swap stage; live trust state \
                 unchanged (no swap occurred); sequence not committed; sessions untouched: \
                 {}",
                msg
            ),
            Self::SessionEvictionFailed {
                message,
                rollback_ok,
            } => write!(
                f,
                "Run 070 candidate apply failed at session-eviction stage AFTER state swap; \
                 rollback_ok={}; sequence not committed: {}",
                rollback_ok, message
            ),
            Self::SequenceCommitFailed(msg) => write!(
                f,
                "Run 070 candidate apply failed at sequence-commit stage AFTER state swap; \
                 rollback succeeded; live trust state restored to previous snapshot: {}",
                msg
            ),
            Self::SequenceCommitFailedRollbackAlsoFailed {
                commit_message,
                rollback_message,
            } => write!(
                f,
                "Run 070 FATAL: candidate apply sequence commit failed AND rollback also \
                 failed; live trust state may now be ahead of persisted sequence; the \
                 operator MUST stop the node and recover offline. commit_error={} \
                 rollback_error={}",
                commit_message, rollback_message
            ),
        }
    }
}

impl std::error::Error for ReloadApplyError {}

/// Run 070 abstraction over the mutable live trust-state handle a
/// production node would need to expose to safely apply a
/// validated candidate. The current `qbind-node` binary has NO
/// concrete implementation of this trait (see module-level
/// comment); the trait exists so:
///
///   - the apply sequencing contract is implemented and proven
///     once in [`apply_validated_candidate`];
///   - a future run that lands a mutable runtime trust handle +
///     a session-manager eviction hook can implement the trait
///     and the apply pipeline starts working with zero changes
///     to the security checks or sequencing here;
///   - integration tests can drive every success and failure
///     branch deterministically against a fake.
///
/// **Conservative session policy.** [`evict_sessions`](Self::evict_sessions)
/// is mandatory; selective retention is out of scope for Run 070.
pub trait LiveTrustApplyContext {
    /// Snapshot the current active live trust state so that the
    /// apply pipeline can roll back if any later step fails.
    /// MUST NOT mutate any state.
    fn snapshot_active(&mut self)
        -> Result<Box<dyn std::any::Any + Send + Sync>, String>;

    /// Atomically replace the active trust state with the
    /// validated candidate's roots / active revocation sets /
    /// sequence. MUST be all-or-nothing: on `Err`, the live trust
    /// state is unchanged. On `Ok`, the new state is in effect for
    /// subsequent handshake verifiers.
    fn swap_trust_state(
        &mut self,
        candidate: &LoadedTrustBundle,
    ) -> Result<(), String>;

    /// Close / evict all existing P2P / KEMTLS sessions so peers
    /// reconnect under the new trust context. MUST report success
    /// only when every existing session has been closed. Returns
    /// the eviction count on success for operator logs.
    fn evict_sessions(&mut self) -> Result<usize, String>;

    /// Persist the candidate's sequence to the on-disk record.
    /// MUST only be called by [`apply_validated_candidate`] AFTER a
    /// successful [`swap_trust_state`](Self::swap_trust_state) and
    /// successful [`evict_sessions`](Self::evict_sessions). Calling
    /// it earlier would burn the sequence on a rejected or partial
    /// apply (violates Run 055/070 anti-rollback contract).
    fn commit_sequence(
        &mut self,
        candidate: &LoadedTrustBundle,
    ) -> Result<(), String>;

    /// Restore the live trust state from the snapshot returned by
    /// [`snapshot_active`](Self::snapshot_active). Called only when
    /// a post-swap step fails. MUST be all-or-nothing.
    fn rollback_trust_state(
        &mut self,
        snapshot: Box<dyn std::any::Any + Send + Sync>,
    ) -> Result<(), String>;
}

/// Run 070 apply outcome on the success path. Carries the public,
/// log-safe metadata operators need to confirm the swap landed.
#[derive(Debug, Clone)]
pub struct AppliedCandidate {
    /// The validated metadata (same shape as Run 069), so a
    /// successful apply can be cross-checked against a prior
    /// reload-check verdict.
    pub validated: ValidatedCandidate,
    /// 8-char hex prefix of the *previous* fingerprint that was
    /// active before the swap. Empty string if the apply context
    /// reported no prior trust bundle.
    pub previous_fingerprint_prefix: String,
    /// Previous accepted sequence reported by the context, if any.
    pub previous_sequence: Option<u64>,
    /// Number of P2P / KEMTLS sessions evicted during the swap.
    pub session_evictions: usize,
}

impl AppliedCandidate {
    /// Operator-log line summarising a successful Run 070 live
    /// apply. Single source of truth so binary logs and tests
    /// agree.
    pub fn applied_log_line(&self) -> String {
        format!(
            "[binary] Run 070: trust-bundle candidate APPLIED live (operator-triggered local \
             reload-apply; conservative session-eviction v0 policy) \
             (old_fp={}.. new_fp={}.. old_sequence={:?} new_sequence={} env={} chain_id={} \
             active_roots={} active_revoked_roots={} active_revoked_leaves={} \
             session_evictions={} sequence_commit=ok)",
            self.previous_fingerprint_prefix,
            self.validated.fingerprint_prefix,
            self.previous_sequence,
            self.validated.sequence,
            self.validated.environment,
            self.validated.chain_id_hex,
            self.validated.active_root_count,
            self.validated.active_revoked_root_count,
            self.validated.active_revoked_leaf_count,
            self.session_evictions,
        )
    }
}

/// Run 070 entry point: validate, then apply if and only if
/// requested. See module-level documentation for the strict
/// validate → swap → evict → commit ordering and the fail-closed
/// guarantees.
///
/// * In [`ApplyMode::ValidateOnly`] mode this function is
///   behaviourally equivalent to [`validate_candidate_bundle`]: it
///   returns the [`ValidatedCandidate`] metadata on success and
///   returns [`ReloadApplyError::ValidationFailed`] on any
///   fail-closed condition. **No mutation** of any kind happens in
///   this mode, regardless of whether a `LiveTrustApplyContext` was
///   supplied. The Run 069 reload-check hook in `main.rs` continues
///   to call [`validate_candidate_bundle`] directly, so its
///   behaviour is bit-for-bit unchanged.
///
/// * In [`ApplyMode::ApplyLive`] mode this function requires a
///   non-`None` [`LiveTrustApplyContext`] handle; if `None`, returns
///   [`ReloadApplyError::UnsupportedRuntimeContext`] without
///   mutating any state.
pub fn apply_validated_candidate(
    inputs: ReloadCheckInputs<'_>,
    mode: ApplyMode,
    ctx: Option<&mut dyn LiveTrustApplyContext>,
) -> Result<AppliedCandidate, ReloadApplyError> {
    // 1. Validation stage — fully reuse Run 069. Validation MUST NOT
    // mutate live trust state or persistence; this property is
    // guaranteed by `validate_candidate_bundle_full` itself.
    let (loaded, _activation, validated) =
        validate_candidate_bundle_full(inputs).map_err(ReloadApplyError::ValidationFailed)?;

    // 2. ValidateOnly short-circuit. Live state is not touched even
    // if a context was supplied — this preserves the Run 069
    // staging boundary for callers that want a dry run.
    if matches!(mode, ApplyMode::ValidateOnly) {
        return Ok(AppliedCandidate {
            validated,
            previous_fingerprint_prefix: String::new(),
            previous_sequence: None,
            session_evictions: 0,
        });
    }

    // 3. ApplyLive requires a runtime handle.
    let ctx = match ctx {
        Some(c) => c,
        None => {
            return Err(ReloadApplyError::UnsupportedRuntimeContext(
                "ApplyMode::ApplyLive requires a LiveTrustApplyContext handle; current \
                 qbind-node binary has no mutable runtime trust-state handle yet"
                    .to_string(),
            ));
        }
    };

    // 4. Snapshot current live state for rollback. Snapshot failure
    // fails closed BEFORE any mutation.
    let snapshot = ctx
        .snapshot_active()
        .map_err(ReloadApplyError::StateSwapFailed)?;

    // 5. Atomic state swap. Swap failure leaves the old live trust
    // state untouched; no sequence commit.
    if let Err(msg) = ctx.swap_trust_state(&loaded) {
        // No rollback necessary because no swap occurred. Drop the
        // snapshot to release any temporary resources it holds.
        drop(snapshot);
        return Err(ReloadApplyError::StateSwapFailed(msg));
    }

    // 6. Session eviction (conservative v0 policy: evict all).
    let session_evictions = match ctx.evict_sessions() {
        Ok(n) => n,
        Err(msg) => {
            // Roll back the swap before reporting eviction failure
            // so the live trust state matches the previous
            // sequence record.
            let rollback_ok = ctx.rollback_trust_state(snapshot).is_ok();
            return Err(ReloadApplyError::SessionEvictionFailed {
                message: msg,
                rollback_ok,
            });
        }
    };

    // 7. Sequence commit. On failure, attempt rollback first; only
    // then surface the error.
    if let Err(commit_msg) = ctx.commit_sequence(&loaded) {
        match ctx.rollback_trust_state(snapshot) {
            Ok(()) => {
                return Err(ReloadApplyError::SequenceCommitFailed(commit_msg));
            }
            Err(rollback_msg) => {
                return Err(ReloadApplyError::SequenceCommitFailedRollbackAlsoFailed {
                    commit_message: commit_msg,
                    rollback_message: rollback_msg,
                });
            }
        }
    }

    // Snapshot is dropped here — apply succeeded so no rollback is
    // needed. The handle MAY surface previous-fingerprint /
    // previous-sequence metadata via the snapshot if the
    // implementation chose to expose it, but we report the
    // conservative "unknown" values here. Production
    // implementations are expected to capture this metadata
    // inside `swap_trust_state` before the swap and surface it to
    // the operator log.
    let _ = snapshot;

    Ok(AppliedCandidate {
        validated,
        previous_fingerprint_prefix: String::new(),
        previous_sequence: None,
        session_evictions,
    })
}

/// Run 070 entry point variant that additionally accepts pre-swap
/// "previous fingerprint prefix" and "previous sequence" metadata
/// for operator logs. Tests use this to assert the operator-log
/// line includes both old and new fingerprints; production
/// callers may pass the values they captured from the live
/// `LoadedTrustBundle` before invoking the apply pipeline.
///
/// Behaviourally identical to [`apply_validated_candidate`] except
/// the returned [`AppliedCandidate`] carries the operator-supplied
/// previous-state metadata. Validation, sequencing, and rollback
/// semantics are unchanged.
pub fn apply_validated_candidate_with_previous(
    inputs: ReloadCheckInputs<'_>,
    mode: ApplyMode,
    ctx: Option<&mut dyn LiveTrustApplyContext>,
    previous_fingerprint_prefix: String,
    previous_sequence: Option<u64>,
) -> Result<AppliedCandidate, ReloadApplyError> {
    let mut applied = apply_validated_candidate(inputs, mode, ctx)?;
    applied.previous_fingerprint_prefix = previous_fingerprint_prefix;
    applied.previous_sequence = previous_sequence;
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ====================================================================
    // Run 069 baseline tests (preserved).
    // ====================================================================

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

    // ====================================================================
    // Run 070 — apply API unit tests (errors / mode / log line).
    // Full sequencing proofs against a fake context live in
    // crates/qbind-node/tests/run_070_pqc_trust_bundle_reload_apply_tests.rs
    // because they need the test signing harness from the
    // integration test file.
    // ====================================================================

    #[test]
    fn reload_apply_error_display_marks_each_failure_stage_safely() {
        // Every Display variant MUST clearly state the stage that
        // failed AND that live state / sequence / sessions remain
        // safe — so operator logs are never ambiguous about whether
        // the candidate landed.
        let cases: Vec<ReloadApplyError> = vec![
            ReloadApplyError::ValidationFailed(ReloadCheckError::Bundle(
                TrustBundleError::Io("path: kind".into()),
            )),
            ReloadApplyError::UnsupportedRuntimeContext(
                "no mutable runtime trust handle".into(),
            ),
            ReloadApplyError::LiveReloadDisabled("flag not set".into()),
            ReloadApplyError::StateSwapFailed("write lock unavailable".into()),
            ReloadApplyError::SessionEvictionFailed {
                message: "session manager missing".into(),
                rollback_ok: true,
            },
            ReloadApplyError::SequenceCommitFailed("disk full".into()),
            ReloadApplyError::SequenceCommitFailedRollbackAlsoFailed {
                commit_message: "disk full".into(),
                rollback_message: "snapshot drained".into(),
            },
        ];
        for e in cases {
            let s = format!("{}", e);
            let lower = s.to_lowercase();
            assert!(lower.contains("run 070"), "msg: {}", s);
            // Variant-specific invariants.
            match &e {
                ReloadApplyError::ValidationFailed(_) => {
                    assert!(s.contains("live trust state unchanged"), "{}", s);
                    assert!(s.contains("sequence not committed"), "{}", s);
                    assert!(s.contains("sessions untouched"), "{}", s);
                }
                ReloadApplyError::UnsupportedRuntimeContext(_) => {
                    assert!(s.contains("no mutable live trust context"), "{}", s);
                    assert!(s.contains("live trust state unchanged"), "{}", s);
                    assert!(s.contains("sequence not committed"), "{}", s);
                }
                ReloadApplyError::LiveReloadDisabled(_) => {
                    assert!(s.contains("disabled by default"), "{}", s);
                    assert!(s.contains("live trust state unchanged"), "{}", s);
                }
                ReloadApplyError::StateSwapFailed(_) => {
                    assert!(s.contains("state-swap stage"), "{}", s);
                    assert!(s.contains("no swap occurred"), "{}", s);
                    assert!(s.contains("sequence not committed"), "{}", s);
                }
                ReloadApplyError::SessionEvictionFailed { rollback_ok, .. } => {
                    assert!(s.contains("session-eviction stage"), "{}", s);
                    assert!(s.contains("AFTER state swap"), "{}", s);
                    assert!(s.contains("sequence not committed"), "{}", s);
                    assert!(s.contains(&format!("rollback_ok={}", rollback_ok)), "{}", s);
                }
                ReloadApplyError::SequenceCommitFailed(_) => {
                    assert!(s.contains("sequence-commit stage"), "{}", s);
                    assert!(s.contains("rollback succeeded"), "{}", s);
                }
                ReloadApplyError::SequenceCommitFailedRollbackAlsoFailed { .. } => {
                    let upper = s.clone();
                    assert!(upper.contains("FATAL"), "{}", s);
                    assert!(s.contains("ahead of persisted sequence"), "{}", s);
                    assert!(s.contains("stop the node"), "{}", s);
                }
            }
        }
    }

    #[test]
    fn apply_mode_value_semantics_are_distinct() {
        assert_ne!(ApplyMode::ValidateOnly, ApplyMode::ApplyLive);
        let _copy: ApplyMode = ApplyMode::ApplyLive;
        let _clone = ApplyMode::ValidateOnly.clone();
    }

    #[test]
    fn applied_candidate_log_line_marks_applied_with_old_and_new_fingerprints() {
        let validated = ValidatedCandidate {
            fingerprint_hex: "cd".repeat(32),
            fingerprint_prefix: "cdcdcdcd".into(),
            sequence: 9,
            environment: TrustBundleEnvironment::Devnet,
            chain_id_hex: "0123456789abcdef".into(),
            active_root_count: 2,
            active_revoked_root_count: 0,
            pending_revoked_root_count: 0,
            active_revoked_leaf_count: 1,
            pending_revoked_leaf_count: 0,
            signature_verified: true,
            activation: ActivationCheckOutcome {
                required_height: Some(20),
                current_height: Some(25),
                required_epoch: None,
                current_epoch: None,
            },
            sequence_peek: SequencePeekOutcome::WouldUpgrade {
                previous_sequence: 7,
                previous_fingerprint_hex: "ab".repeat(32),
                candidate_sequence: 9,
                candidate_fingerprint_hex: "cd".repeat(32),
            },
            sequence_persistence_path: None,
        };
        let applied = AppliedCandidate {
            validated,
            previous_fingerprint_prefix: "abababab".into(),
            previous_sequence: Some(7),
            session_evictions: 3,
        };
        let line = applied.applied_log_line();
        assert!(line.contains("Run 070"), "{}", line);
        assert!(line.contains("APPLIED live"), "{}", line);
        assert!(line.contains("conservative session-eviction v0 policy"), "{}", line);
        assert!(line.contains("operator-triggered"), "{}", line);
        assert!(line.contains("old_fp=abababab"), "{}", line);
        assert!(line.contains("new_fp=cdcdcdcd"), "{}", line);
        assert!(line.contains("old_sequence=Some(7)"), "{}", line);
        assert!(line.contains("new_sequence=9"), "{}", line);
        assert!(line.contains("session_evictions=3"), "{}", line);
        assert!(line.contains("sequence_commit=ok"), "{}", line);
    }
}