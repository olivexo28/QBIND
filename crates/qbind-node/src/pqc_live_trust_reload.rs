//! Run 074 (C4 piece: PQC trust-anchor lifecycle — long-running
//! local operator-triggered live trust-bundle reload-apply trigger):
//! the smallest safe long-running-node trigger that drives the
//! Run 073 [`crate::pqc_live_trust_apply::ProductionLiveTrustApplyContext`]
//! against the **already-running** node's live
//! [`crate::pqc_live_trust::LivePqcTrustState`] handle and the live
//! [`crate::p2p_session_eviction::P2pSessionEvictor`]
//! implementation provided by
//! [`crate::p2p_tcp::TcpKemTlsP2pService`].
//!
//! # Strict scope (what Run 074 is and is NOT)
//!
//! Run 074 is **only** the long-running-node trigger blocker called
//! out under "what is NOT narrowed (Run 073)" in
//! `docs/whitepaper/contradiction.md` C4. It is intentionally
//! minimal:
//!
//! - This module introduces a [`LiveReloadController`] that the
//!   `qbind-node` binary builds AFTER P2P bring-up and holds across
//!   the lifetime of the running node. The controller owns:
//!   * an [`Arc<LivePqcTrustState>`] (Run 071) — the same handle
//!     installed on the [`crate::p2p_node_builder::P2pNodeBuilder`]
//!     via `with_live_pqc_trust(...)`;
//!   * an [`Arc<dyn P2pSessionEvictor>`] (Run 072) — the running
//!     [`crate::p2p_tcp::TcpKemTlsP2pService`] held by the node
//!     context (`P2pNodeContext::p2p_service`);
//!   * an [`Arc<crate::metrics::P2pMetrics>`] — the same metrics
//!     handle the running node already serves on `/metrics`;
//!   * a clonable [`LiveReloadConfig`] carrying the
//!     candidate path, environment, chain id, signing keys,
//!     activation context, sequence persistence path, optional
//!     local leaf cert bytes, and a per-trigger
//!     `now_unix_secs` source.
//! - The controller exposes a single public entry point,
//!   [`LiveReloadController::try_trigger`], which the binary's
//!   SIGHUP signal-handler task calls on each `SIGHUP`. The same
//!   entry point is what the Run 074 integration tests drive
//!   directly (no spawning of the binary, no signal traffic).
//! - Concurrent triggers are serialized via an
//!   `Arc<AtomicBool>` "in progress" guard: a second trigger
//!   arriving while a previous trigger has not yet returned is
//!   rejected with [`LiveReloadOutcome::AlreadyInProgress`] and a
//!   single bump on
//!   [`crate::metrics::P2pMetrics::record_live_reload_already_in_progress`].
//!   Triggers do **not** queue and do **not** re-enter the apply
//!   pipeline. This preserves the Run 070
//!   `validate → swap → evict → commit` atomicity guarantee under
//!   concurrent operator action.
//! - Run 074 NEVER falls back to `--p2p-trusted-root`; NEVER
//!   re-introduces `DummySig` / `DummyKem` / `DummyAead`; NEVER
//!   accepts a candidate that the Run 069 pipeline refused.
//!
//! Run 074 is **NOT**:
//!
//! - peer-supplied / gossiped bundle acceptance (local file only);
//! - automatic filesystem-watcher hot reload (operator-triggered
//!   only — SIGHUP at the binary surface, direct API call in tests);
//! - admin-API / RPC trigger (SIGHUP is the only binary-surface
//!   trigger in Run 074; a future run that lands an authenticated
//!   admin endpoint can call the SAME `try_trigger` entry point);
//! - KMS / HSM custody (signing keys remain operator-supplied via
//!   `--p2p-trust-bundle-signing-key`);
//! - bundle-signing-key ratification (the trusted set is still
//!   operator-distributed at startup);
//! - `activation_epoch` runtime sourcing (unchanged from
//!   Run 057/058: bundles that declare `activation_epoch` continue
//!   to fail closed);
//! - selective session retention — the v0 policy is "evict all"
//!   (Run 072) and is preserved bit-for-bit;
//! - fast-sync / consensus-storage restore parity on a partially
//!   restored long-running node.
//!
//! # Composition with Run 069/070/071/072/073
//!
//! Every trigger walks the SAME Run 070 entry point that the
//! Run 073 at-startup-time hook drives:
//!
//! 1. [`crate::pqc_trust_reload::validate_candidate_bundle_full`]
//!    (Run 069) validates the candidate at
//!    [`LiveReloadConfig::candidate_path`] — same parse + structural
//!    validation + ML-DSA-44 signature verification +
//!    environment binding + chain-id binding + activation-height
//!    gating + Run 065 min-activation-margin + revocation
//!    activation gating + Run 069 sequence-peek + Run 061/063
//!    local-leaf self-checks as startup. Validation refusal
//!    surfaces as [`LiveReloadOutcome::Invalid`] with no mutation
//!    of any kind.
//! 2. [`crate::pqc_trust_reload::apply_validated_candidate_with_previous`]
//!    (Run 070) drives the strict
//!    `snapshot → swap → evict → commit` pipeline against a
//!    [`crate::pqc_live_trust_apply::ProductionLiveTrustApplyContext`]
//!    that the controller builds for the trigger. The adapter
//!    captures the previous fingerprint prefix + sequence under a
//!    short read lock BEFORE the swap so the operator-log line
//!    shows both old and new fingerprints.
//! 3. The live `TcpKemTlsP2pService` evicts every authenticated
//!    KEMTLS session (Run 072) — peers must reconnect under the
//!    new trust context. The listener / dialer-retry tasks
//!    continue running.
//! 4. The atomic sequence writer
//!    ([`crate::pqc_trust_sequence::check_and_update_sequence`])
//!    persists the new `(sequence, fingerprint)` record under the
//!    same path the startup binary uses.
//! 5. On success the controller surfaces
//!    [`LiveReloadOutcome::Applied`] with the
//!    [`crate::pqc_trust_reload::AppliedCandidate`] (carries
//!    `applied_log_line` for canonical operator logging) and bumps
//!    the four Run 074 success counters
//!    (`live_reload_apply_success_total`,
//!    `live_reload_sessions_evicted_total`,
//!    `live_reload_last_applied_sequence` gauge, AND the
//!    Run 072 `qbind_p2p_session_eviction_*` family via the
//!    underlying `TcpKemTlsP2pService::evict_all_sessions` call).
//!    On any failure branch the controller surfaces
//!    [`LiveReloadOutcome::Invalid`] (validation / swap / evict /
//!    commit) or [`LiveReloadOutcome::Fatal`]
//!    (`SequenceCommitFailedRollbackAlsoFailed`) and bumps
//!    `live_reload_apply_failure_total`. Live trust state is
//!    rolled back to the captured snapshot whenever Run 070's
//!    apply pipeline calls `rollback_trust_state`. The on-disk
//!    sequence record is preserved across every failure branch
//!    because `check_and_update_sequence` is atomic.
//!
//! # Fatal-branch policy
//!
//! [`LiveReloadOutcome::Fatal`] arises ONLY from the
//! [`crate::pqc_trust_reload::ReloadApplyError::SequenceCommitFailedRollbackAlsoFailed`]
//! branch — the live trust state may be ahead of the on-disk
//! sequence record. The Run 074 controller does NOT panic and does
//! NOT exit the process on its own; it surfaces a `Fatal` outcome
//! so the caller (the binary's SIGHUP task in `main.rs`) can
//! initiate an operator-visible graceful shutdown. The integration
//! tests in `tests/run_074_pqc_trust_bundle_live_reload_tests.rs`
//! drive the same code path through `MockP2pSessionEvictor` +
//! injected commit failure to prove the outcome shape, without
//! actually killing the process.
//!
//! # No fabrication, no double-counting
//!
//! Run 074 reuses every Run 069/070/071/072/073 entry point
//! verbatim. The new metrics family
//! (`qbind_p2p_trust_bundle_live_reload_*`) is a SEPARATE rendering
//! row from the Run 072 `qbind_p2p_session_eviction_*` family;
//! eviction calls bump both families exactly once (the Run 072
//! family via the live `TcpKemTlsP2pService::evict_all_sessions`
//! call; the Run 074 family via `record_live_reload_apply_success`).
//! The controller NEVER writes the persistence file directly — it
//! always goes through `check_and_update_sequence` via the
//! Run 073 adapter so any future anti-rollback hardening applies
//! automatically.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use qbind_ledger::{
    enforce_bundle_signing_key_ratification, verify_bundle_signing_key_ratification_v2,
    BundleSigningRatificationV2, GenesisAuthorityConfig, GenesisHash, NetworkEnvironmentPolicy,
    RatificationEnforcementInputs, RatificationEnforcementOutcome, RatificationEnforcementPolicy,
    RatificationV2VerifierInputs,
};
use qbind_types::{ChainId, NetworkEnvironment};

use crate::metrics::P2pMetrics;
use crate::p2p_session_eviction::P2pSessionEvictor;
use crate::pqc_authority_marker_acceptance::{
    decide_marker_acceptance,
    persist_accepted_marker_after_commit_boundary,
    persist_accepted_v2_marker_after_commit_boundary, MarkerAcceptDecision,
    MarkerAcceptDecisionV2, MarkerAcceptanceInputs, MarkerAcceptanceV2Inputs,
    MutatingSurfaceMarkerError, MutatingSurfaceMarkerV2Error,
};
use crate::pqc_authority_state::{
    AuthorityMarkerV2ComparisonOutcome, AuthorityStateUpdateSource,
};
use crate::pqc_live_trust::LivePqcTrustState;
use crate::pqc_live_trust_apply::ProductionLiveTrustApplyContext;
use crate::pqc_ratification_input::{
    load_versioned_ratification_with_governance_proof_from_path,
    VersionedRatificationInputError,
    VersionedRatificationSidecarWithGovernanceProof,
};
use crate::pqc_trust_activation::ActivationContext;
use crate::pqc_trust_bundle::{
    BundleSignatureStatus, BundleSigningKeySet, TrustBundle, TrustBundleError,
};
use crate::pqc_trust_reload::{
    apply_validated_candidate_with_previous,
    apply_validated_candidate_with_previous_and_ratification, ApplyMode, AppliedCandidate,
    RatificationEnforcementContext, ReloadApplyError, ReloadCheckError, ReloadCheckInputs,
};

/// Run 074 — clonable bundle of every input needed to validate +
/// apply a candidate on the long-running-node trigger path.
///
/// The controller stores a single [`LiveReloadConfig`] for the
/// lifetime of the running node. Triggers do not mutate it. The
/// only per-trigger value not in this struct is `now_unix_secs`,
/// which the controller computes from `SystemTime::now()` at the
/// top of each trigger (tests inject a deterministic value via
/// [`LiveReloadController::try_trigger_with_now`]).
#[derive(Debug, Clone)]
pub struct LiveReloadConfig {
    /// Local file path of the candidate trust bundle. Re-read on
    /// every trigger so an operator can replace the file
    /// in-place between triggers without restarting the node.
    pub candidate_path: PathBuf,
    /// Runtime environment of the running node. MUST match the
    /// environment the candidate was minted under; bundles with
    /// the wrong environment surface a fail-closed
    /// [`crate::pqc_trust_bundle::TrustBundleError`] at validation.
    pub environment: NetworkEnvironment,
    /// Runtime chain id of the running node. Same parity rule as
    /// `environment`.
    pub chain_id: ChainId,
    /// Bundle-signing key set the running node has configured.
    /// MUST satisfy the same TestNet/MainNet refuse-unsigned
    /// policy as startup.
    pub signing_keys: BundleSigningKeySet,
    /// Activation runtime context. Captured once at controller
    /// construction; tests that want the controller to react to a
    /// changed `current_height` between triggers can use
    /// [`LiveReloadController::try_trigger_with_activation`].
    pub activation_ctx: ActivationContext,
    /// On-disk sequence persistence file path. `None` is allowed
    /// for DevNet without `--data-dir`; in that case the controller
    /// surfaces a clean fail-closed `Invalid` outcome on commit
    /// (mirroring the Run 073 adapter's
    /// `commit_sequence_without_data_dir` branch).
    pub sequence_path: Option<PathBuf>,
    /// Optional local leaf cert bytes. When `Some`, the Run 061
    /// (local-leaf-not-revoked) and Run 063 (local-leaf-issuer-
    /// root-not-revoked) self-checks fire against the candidate.
    pub local_leaf_cert_bytes: Option<Vec<u8>>,
    /// Run 114 — optional bundle-signing-key ratification
    /// enforcement context for the SIGHUP live reload path.
    ///
    /// When `Some(_)` the controller invokes the Run 105 / Run 103
    /// genesis-bound bundle-signing-key ratification gate BEFORE
    /// any live trust mutation. The Run 106 per-environment policy
    /// decision (MainNet/TestNet default-strict; DevNet only under
    /// `--p2p-trust-bundle-ratification-enforcement-enabled`) is
    /// made once at controller construction time and reflected in
    /// the `Some`/`None` shape of this field — the controller does
    /// not re-evaluate the gate decision per-trigger.
    ///
    /// When `None` the SIGHUP path preserves the pre-Run-114
    /// behaviour (Run 069/070/073/074 verbatim) — this is reachable
    /// only on DevNet without operator opt-in, and is never
    /// reachable on MainNet/TestNet (Run 106 invariant).
    ///
    /// The sidecar file (if `ratification_sidecar_path` is set) is
    /// re-read on every trigger so an operator can replace the
    /// sidecar JSON in-place between SIGHUPs without restarting
    /// the node. A missing / unreadable / unparseable sidecar
    /// fails closed BEFORE any snapshot / swap / eviction /
    /// commit step.
    pub ratification: Option<LiveReloadRatificationConfig>,
    /// Run 121 — optional authority anti-rollback marker
    /// accept-and-persist context for the SIGHUP live reload path.
    ///
    /// When `Some(_)` the controller invokes the Run 119
    /// `decide_marker_acceptance` helper BEFORE any snapshot / swap /
    /// eviction / commit of the existing apply pipeline, and the
    /// Run 119 `persist_accepted_marker_after_commit_boundary` helper
    /// AFTER the apply pipeline's `commit_sequence` boundary returns
    /// `Ok`. The marker is derived ONLY from verified ratification
    /// material — the field is populated by the binary surface only
    /// when (1) the ratification gate is `Invoke` (so a
    /// [`LiveReloadRatificationConfig`] is also `Some`) and (2) a
    /// `--data-dir` is configured.
    ///
    /// When `None` the SIGHUP path preserves the pre-Run-121 behaviour
    /// (Run 069/070/073/074/114 verbatim) — this is reachable on
    /// DevNet without operator opt-in (matching the Run 106 / Run 114
    /// gate-decision branch) and on operator configurations without a
    /// `--data-dir`. MainNet/TestNet always reach this branch with
    /// `Some(_)` populated (because the ratification gate is always
    /// `Invoke` and `--data-dir` is mandatory there).
    ///
    /// The marker file path is captured once at controller
    /// construction time. The controller does NOT re-resolve the
    /// `data_dir` per-trigger because the running node cannot change
    /// its `--data-dir` without a restart (same scope rule as the
    /// Run 074 `sequence_path` field).
    pub authority_marker: Option<LiveReloadAuthorityMarkerConfig>,

    /// Run 171 — active governance-proof policy for the SIGHUP live
    /// reload v2 marker-decision preflight (Run 169 surface shim).
    ///
    /// Defaults to
    /// [`crate::pqc_governance_authority::GovernanceProofPolicy::NotRequired`]
    /// when the binary's hidden
    /// `--p2p-trust-bundle-governance-proof-required` flag and the
    /// `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED` environment
    /// variable are both absent (preserves Run 138 SIGHUP behaviour
    /// bit-for-bit). When the operator sets either source, the
    /// binary populates this field with
    /// [`crate::pqc_governance_authority::GovernanceProofPolicy::RequiredForLifecycleSensitive`]
    /// and the SIGHUP preflight routes through the Run 169 shim under
    /// that policy.
    ///
    /// Non-MainNet-enabling. The Run 148/149/152 MainNet peer-driven
    /// apply refusal is upstream of this controller and is unchanged
    /// by Run 171.
    pub governance_proof_policy: crate::pqc_governance_authority::GovernanceProofPolicy,

    /// Run 182 — captured value of the hidden, disabled-by-default
    /// `--p2p-trust-bundle-onchain-governance-fixture-allowed` CLI
    /// flag at controller-construction time. OR-combined at preflight
    /// time with the `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`
    /// environment variable inside
    /// [`crate::pqc_onchain_governance_proof_surface::onchain_governance_proof_policy_from_cli_or_env`].
    /// Default `false` resolves to
    /// [`crate::pqc_onchain_governance_proof::OnChainGovernanceProofPolicy::Disabled`]
    /// and preserves the pre-Run-182 SIGHUP preflight flow bit-for-bit.
    /// Source/test only — never enables MainNet peer-driven apply.
    pub onchain_governance_fixture_allowed_selector: bool,
}

/// Run 114 — owned ratification enforcement inputs the
/// [`LiveReloadController`] re-uses across every SIGHUP trigger.
///
/// All fields except `ratification_sidecar_path` are immutable for
/// the lifetime of the controller. The sidecar JSON file at
/// `ratification_sidecar_path` is **re-read on every trigger** so
/// the operator can update the sidecar in-place between SIGHUPs
/// without restarting the node. A missing path (`None`) is passed
/// through to the verifier as "no ratification supplied" — under
/// [`RatificationEnforcementPolicy::Strict`] this surfaces a
/// `Missing` refusal BEFORE any mutation, exactly matching the
/// Run 112 reload-apply behaviour.
#[derive(Debug, Clone)]
pub struct LiveReloadRatificationConfig {
    /// Genesis-bound authority block (Run 101/104). The enforcer
    /// consults `bundle_signing_authority_roots` only.
    pub authority: GenesisAuthorityConfig,
    /// Canonical genesis hash the runtime computed at startup
    /// (Run 102).
    pub expected_genesis_hash: GenesisHash,
    /// Per-environment policy enum for the verifier (1:1 with
    /// `LiveReloadConfig::environment` mapped to
    /// [`NetworkEnvironmentPolicy`]).
    pub expected_environment_policy: NetworkEnvironmentPolicy,
    /// Hex-encoded chain-id string the verifier expects.
    pub expected_chain_id_str: String,
    /// Per-surface enforcement policy (Run 105/106): `Strict` on
    /// MainNet and on TestNet by default; `AllowLegacyUnratified`
    /// only when the operator additionally supplies
    /// `--p2p-trust-bundle-allow-unratified-testnet-devnet` on
    /// TestNet/DevNet. MainNet is always `Strict`.
    pub policy: RatificationEnforcementPolicy,
    /// Local sidecar JSON path produced by the genesis-bound
    /// bundle-signing authority. Re-read on every trigger.
    /// `None` means "no sidecar supplied" — the verifier surfaces
    /// the typed `Missing` failure under `Strict` policy.
    pub ratification_sidecar_path: Option<PathBuf>,
}

/// Run 121 — owned authority anti-rollback marker context the
/// [`LiveReloadController`] re-uses across every SIGHUP trigger when
/// the Run 119 `decide_marker_acceptance` /
/// `persist_accepted_marker_after_commit_boundary` helpers must be
/// invoked.
///
/// All fields are immutable for the lifetime of the controller. The
/// marker file at `marker_path` is read on every trigger (the Run 119
/// `decide_marker_acceptance` helper loads it via
/// [`crate::pqc_authority_state::load_authority_state`]) so an
/// operator-induced change (e.g. a backup restore between two
/// SIGHUPs) is observed by the next trigger without a node restart.
///
/// The marker file is NEVER read, written, or otherwise touched
/// unless the per-trigger ratification gate also produced a verified
/// [`qbind_ledger::RatifiedBundleSigningKey`] — derivation strictly
/// requires verified ratification material per Run 117/118/119.
///
/// This struct intentionally does NOT carry the
/// `GenesisAuthorityConfig`, `expected_genesis_hash`, or
/// `expected_environment_policy`: those live on the sibling
/// [`LiveReloadRatificationConfig`] and the SIGHUP marker preflight
/// reads them from there to avoid duplicating the per-environment
/// trust-domain triple in two places. This means
/// `LiveReloadAuthorityMarkerConfig` is only meaningful in
/// combination with a populated
/// `LiveReloadConfig::ratification`; the controller treats
/// `(ratification: None, authority_marker: Some(_))` as a no-op
/// (logs and falls through to the pre-Run-121 path) because a marker
/// cannot be derived without a verified ratification.
#[derive(Debug, Clone)]
pub struct LiveReloadAuthorityMarkerConfig {
    /// Path to `<data_dir>/pqc_authority_state.json` per
    /// [`crate::pqc_authority_state::authority_state_file_path`].
    /// Captured once at controller construction time.
    pub marker_path: PathBuf,
}

/// Run 074 — outcome of a single trigger.
///
/// Used by both the binary SIGHUP task (to choose a log shape and
/// exit code on the fatal branch) and the integration tests (to
/// assert the controller's contract without spinning up signals).
#[derive(Debug)]
pub enum LiveReloadOutcome {
    /// Validation + swap + evict + commit all succeeded. The
    /// embedded [`AppliedCandidate`] carries the canonical
    /// operator-log line via [`AppliedCandidate::applied_log_line`].
    Applied(AppliedCandidate),
    /// The "in progress" guard rejected this trigger because a
    /// previous trigger had not yet returned. No mutation occurred.
    AlreadyInProgress,
    /// A fail-closed branch (validation refusal, swap failure,
    /// session-eviction partial failure with successful rollback,
    /// or sequence-commit failure with successful rollback). The
    /// live trust state is consistent with the on-disk sequence
    /// record. The node continues running; the operator may
    /// re-trigger after correcting the candidate.
    Invalid(ReloadApplyError),
    /// The unrecoverable branch: sequence-commit failed AND the
    /// rollback ALSO failed. The live trust state may be ahead of
    /// the on-disk sequence record. The controller does NOT exit
    /// the process; the caller MUST initiate a graceful shutdown
    /// and the operator MUST recover offline before restarting the
    /// node.
    Fatal(ReloadApplyError),
    /// Run 121 — the Run 119 `decide_marker_acceptance` preflight
    /// refused the candidate BEFORE the existing apply pipeline
    /// began any snapshot / swap / eviction / commit. Live trust
    /// state, sessions, and the on-disk sequence record are all
    /// byte-identical to the pre-trigger state. The marker file is
    /// also byte-identical (the preflight never writes). The
    /// embedded [`MutatingSurfaceMarkerError`] carries the precise
    /// reject reason (rollback, same-sequence equivocation,
    /// persisted-domain mismatch, corrupt marker, …) so the
    /// operator log line names the exact failure class rather than
    /// collapsing into a generic "marker check failed".
    ///
    /// This variant is NEVER reachable unless both
    /// [`LiveReloadConfig::ratification`] and
    /// [`LiveReloadConfig::authority_marker`] were `Some(_)` at
    /// controller construction AND the per-trigger ratification gate
    /// produced a verified [`qbind_ledger::RatifiedBundleSigningKey`].
    /// The node continues running; the operator may re-trigger after
    /// correcting the candidate or the on-disk marker (the latter
    /// requires an out-of-band recovery procedure — Run 121 does
    /// NOT implement `--allow-authority-state-reset`).
    MarkerRejected(MutatingSurfaceMarkerError),
    /// Run 121 — the existing apply pipeline returned `Ok` and the
    /// trust-bundle sequence has already been committed, but the
    /// subsequent atomic write of the authority marker file failed.
    /// The on-disk authority marker is stale-by-one relative to the
    /// trust-bundle sequence (safely replayable as an `Upgrade` per
    /// Run 118 §D) but the operator MUST be told because the next
    /// SIGHUP / startup will need to either (a) succeed and replay
    /// the marker as an `Upgrade` or (b) be refused fail-closed if
    /// a conflict materialises in the meantime. The caller (the
    /// binary's SIGHUP task in `main.rs`) MUST initiate a graceful
    /// shutdown, matching the existing
    /// [`Self::Fatal`]-on-`SequenceCommitFailedRollbackAlsoFailed`
    /// shutdown semantics — this preserves the Run 074 single
    /// shutdown surface.
    ///
    /// [`AppliedCandidate`] is carried unchanged so operator logs
    /// still record the successful apply (live state DID advance);
    /// the embedded [`MutatingSurfaceMarkerError::PersistFailure`]
    /// carries the precise I/O reason.
    MarkerPersistFailureAfterCommit {
        applied: AppliedCandidate,
        marker_error: MutatingSurfaceMarkerError,
    },
    /// Run 138 — the v2 SIGHUP marker preflight refused the candidate
    /// BEFORE any apply pipeline mutation. v2 twin of
    /// [`Self::MarkerRejected`]: pre-mutation refusal, live trust
    /// state / sessions / on-disk sequence record / on-disk marker
    /// file all byte-identical to the pre-trigger state. The embedded
    /// [`MutatingSurfaceMarkerV2Error`] carries the precise reject
    /// reason (lower-sequence rollback, same-sequence equivocation,
    /// persisted-domain mismatch, v2 verifier failure mapped to
    /// `Conflict`, …).
    ///
    /// This variant is NEVER reachable unless the per-trigger
    /// ratification sidecar parsed as `schema_version=2` AND both
    /// [`LiveReloadConfig::ratification`] and
    /// [`LiveReloadConfig::authority_marker`] were `Some(_)` at
    /// controller construction. The node continues running; the
    /// operator may re-trigger after correcting the candidate or the
    /// on-disk marker.
    MarkerRejectedV2(MutatingSurfaceMarkerV2Error),
    /// Run 138 — the v2 SIGHUP path's apply pipeline returned `Ok`
    /// and the trust-bundle sequence already committed, but the
    /// subsequent atomic v2 marker write failed. v2 twin of
    /// [`Self::MarkerPersistFailureAfterCommit`].
    ///
    /// The on-disk v2 authority marker is stale-by-one relative to
    /// the trust-bundle sequence (safely replayable per Run 118 §D /
    /// Run 131 as an `UpgradeV2` on the next accepted v2 mutation),
    /// but the operator MUST be told. The caller (the binary's
    /// SIGHUP task in `main.rs`) MUST initiate a graceful shutdown,
    /// matching the existing
    /// [`Self::MarkerPersistFailureAfterCommit`] / [`Self::Fatal`]
    /// shutdown semantics — this preserves the Run 074 single
    /// shutdown surface.
    MarkerPersistFailureAfterCommitV2 {
        applied: AppliedCandidate,
        marker_error: MutatingSurfaceMarkerV2Error,
    },
}

impl LiveReloadOutcome {
    /// `true` iff the live trust state advanced as a result of this
    /// trigger.
    pub fn is_applied(&self) -> bool {
        matches!(
            self,
            LiveReloadOutcome::Applied(_)
                | LiveReloadOutcome::MarkerPersistFailureAfterCommit { .. }
                | LiveReloadOutcome::MarkerPersistFailureAfterCommitV2 { .. }
        )
    }

    /// `true` iff the trigger was rejected by the in-progress
    /// guard.
    pub fn is_already_in_progress(&self) -> bool {
        matches!(self, LiveReloadOutcome::AlreadyInProgress)
    }

    /// `true` iff the trigger surfaced a fatal branch requiring an
    /// operator-visible graceful shutdown. Run 074's original fatal
    /// branch is `SequenceCommitFailedRollbackAlsoFailed`; Run 121
    /// extends this to also cover an authority-marker persist
    /// failure that occurs AFTER the trust-bundle `commit_sequence`
    /// boundary — the trust-bundle sequence already advanced but
    /// the on-disk marker is stale-by-one, and the operator MUST be
    /// told via the same graceful-shutdown signal so a single
    /// fail-closed surface remains.
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            LiveReloadOutcome::Fatal(_)
                | LiveReloadOutcome::MarkerPersistFailureAfterCommit { .. }
                | LiveReloadOutcome::MarkerPersistFailureAfterCommitV2 { .. }
        )
    }

    /// `true` iff the Run 121 marker preflight refused the candidate
    /// BEFORE any apply pipeline mutation. Distinct from
    /// [`Self::is_fatal`] because the live trust state, sessions,
    /// and on-disk sequence/marker records are all byte-identical
    /// to the pre-trigger state — the operator may simply re-trigger
    /// after correcting the candidate or the on-disk marker.
    pub fn is_marker_rejected(&self) -> bool {
        matches!(
            self,
            LiveReloadOutcome::MarkerRejected(_) | LiveReloadOutcome::MarkerRejectedV2(_)
        )
    }

    /// Canonical Run 074 operator-log line summarising the
    /// outcome. Single source of truth so the binary's SIGHUP
    /// handler and the integration tests agree on the literal
    /// shape.
    pub fn log_line(&self) -> String {
        match self {
            LiveReloadOutcome::Applied(applied) => format!(
                "[binary] Run 074: VERDICT=applied (live trust-bundle apply on long-running \
                 node; session_evictions={}; sequence_commit=ok)",
                applied.session_evictions
            ),
            LiveReloadOutcome::AlreadyInProgress => {
                "[binary] Run 074: VERDICT=already-in-progress (a previous trigger has not \
                 yet returned; this trigger was rejected without touching live trust state, \
                 sessions, or the sequence record)"
                    .to_string()
            }
            LiveReloadOutcome::Invalid(e) => format!(
                "[binary] Run 074: VERDICT=invalid (candidate rejected at validation, swap, \
                 eviction, or commit stage; live trust state rolled back to previous snapshot \
                 where applicable; on-disk sequence record preserved). Reason: {}",
                e
            ),
            LiveReloadOutcome::Fatal(e) => format!(
                "[binary] Run 074: VERDICT=FATAL (sequence-commit failure AND rollback \
                 failure; live trust state may be ahead of the on-disk sequence record; \
                 graceful shutdown required; operator MUST recover offline). Reason: {}",
                e
            ),
            LiveReloadOutcome::MarkerRejected(e) => format!(
                "[binary] Run 121: VERDICT=marker-rejected (SIGHUP authority-marker preflight \
                 refused the candidate BEFORE any snapshot, swap, eviction, or sequence \
                 commit; live trust state, sessions, on-disk sequence record, and on-disk \
                 authority-marker file are all unchanged). Reason: {}",
                e
            ),
            LiveReloadOutcome::MarkerPersistFailureAfterCommit {
                applied,
                marker_error,
            } => format!(
                "[binary] Run 121: VERDICT=FATAL-marker-persist (live trust-bundle apply on \
                 long-running node succeeded — session_evictions={}, sequence_commit=ok — but \
                 authority-marker atomic persist FAILED AFTER the commit boundary; the \
                 on-disk marker is stale-by-one relative to the trust-bundle sequence \
                 (safely replayable as an Upgrade per Run 118 §D) but graceful shutdown is \
                 required so the operator can surface and recover the failure). Reason: {}",
                applied.session_evictions, marker_error
            ),
            LiveReloadOutcome::MarkerRejectedV2(e) => format!(
                "[binary] Run 138: VERDICT=marker-rejected-v2 (SIGHUP v2 authority-marker \
                 preflight refused the candidate BEFORE any snapshot, swap, eviction, or \
                 sequence commit; live trust state, sessions, on-disk sequence record, and \
                 on-disk authority-marker file are all unchanged). Reason: {}",
                e
            ),
            LiveReloadOutcome::MarkerPersistFailureAfterCommitV2 {
                applied,
                marker_error,
            } => format!(
                "[binary] Run 138: VERDICT=FATAL-marker-persist-v2 (live trust-bundle apply \
                 on long-running node succeeded — session_evictions={}, sequence_commit=ok — \
                 but v2 authority-marker atomic persist FAILED AFTER the commit boundary; \
                 the on-disk v2 marker is stale-by-one relative to the trust-bundle sequence \
                 (safely replayable as an UpgradeV2 per Run 118 §D / Run 131) but graceful \
                 shutdown is required so the operator can surface and recover the failure). \
                 Reason: {}",
                applied.session_evictions, marker_error
            ),
        }
    }
}

/// Run 074 — long-running local operator-triggered live trust-bundle
/// reload-apply controller. See module-level docs for the strict
/// scope and the fail-closed guarantees.
///
/// The controller is `Clone` — cloning it bumps the inner `Arc`
/// handles and shares the same in-progress guard with every clone.
/// The binary builds one controller per running node and hands a
/// clone to the SIGHUP signal-handler task.
#[derive(Clone)]
pub struct LiveReloadController {
    /// Shared live PQC trust-state handle (Run 071). Same handle
    /// the binary installs on `P2pNodeBuilder::with_live_pqc_trust`
    /// — readers continue to read through this handle for every
    /// inbound / outbound KEMTLS handshake.
    live: Arc<LivePqcTrustState>,
    /// Shared session-evictor handle (Run 072). On the live binary
    /// path this is the same `Arc<TcpKemTlsP2pService>` exposed via
    /// `P2pNodeContext::p2p_service`, upcast to
    /// `Arc<dyn P2pSessionEvictor>`. Tests use
    /// `Arc<MockP2pSessionEvictor>` so deterministic failure
    /// branches are reachable without spinning up real TCP.
    evictor: Arc<dyn P2pSessionEvictor>,
    /// Shared metrics handle. Bumped on every trigger (the trigger
    /// counter is always bumped; the apply counters are bumped
    /// after the apply pipeline returns; the in-progress counter is
    /// bumped when the guard rejects a trigger).
    metrics: Arc<P2pMetrics>,
    /// Per-controller configuration. Cloned on every trigger so the
    /// borrow of the controller is non-mutating.
    config: LiveReloadConfig,
    /// In-process serialization guard. `true` while a trigger is
    /// running through the apply pipeline; CAS'd back to `false`
    /// before [`LiveReloadController::try_trigger`] returns. Shared
    /// across every clone of the controller so the binary's SIGHUP
    /// task and a test-driven direct call cannot both enter the
    /// apply pipeline simultaneously.
    in_progress: Arc<AtomicBool>,
}

impl std::fmt::Debug for LiveReloadController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveReloadController")
            .field("config", &self.config)
            .field(
                "in_progress",
                &self.in_progress.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl LiveReloadController {
    /// Construct a Run 074 controller. All handles are stored
    /// as-is; no validation is performed at construction. The
    /// candidate bundle is NOT read here — it is read on every
    /// trigger so an operator can replace the file in-place
    /// between triggers.
    pub fn new(
        live: Arc<LivePqcTrustState>,
        evictor: Arc<dyn P2pSessionEvictor>,
        metrics: Arc<P2pMetrics>,
        config: LiveReloadConfig,
    ) -> Self {
        Self {
            live,
            evictor,
            metrics,
            config,
            in_progress: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Borrow the controller's static configuration (read-only).
    pub fn config(&self) -> &LiveReloadConfig {
        &self.config
    }

    /// `true` iff a trigger is currently running through the apply
    /// pipeline. Lock-free; useful for binary-side observability
    /// without taking the guard.
    pub fn is_in_progress(&self) -> bool {
        self.in_progress.load(Ordering::Relaxed)
    }

    /// **Test-only.** Atomically swap the in-progress guard to the
    /// requested value and return the previous value. Hidden from
    /// documentation because production code MUST NOT touch the
    /// guard directly — the guard's contract is owned by
    /// [`Self::try_trigger`]. Integration tests use this to simulate
    /// "another trigger is in flight" without spinning up a slow
    /// candidate or a second OS thread. Renaming this method is a
    /// breaking change to the Run 074 integration test surface.
    #[doc(hidden)]
    pub fn __test_in_progress_swap(&self, new: bool) -> bool {
        self.in_progress.swap(new, Ordering::AcqRel)
    }

    /// Run 074 entry point. Computes `now_unix_secs` from
    /// `SystemTime::now()` and delegates to
    /// [`Self::try_trigger_with_now`]. The binary's SIGHUP task
    /// calls this on every signal.
    pub fn try_trigger(&self) -> LiveReloadOutcome {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.try_trigger_with_now(now_secs)
    }

    /// Run 074 entry point with an explicit `now_unix_secs`.
    /// Integration tests use this to drive deterministic
    /// validity-window / `accepted_at` values.
    pub fn try_trigger_with_now(&self, now_unix_secs: u64) -> LiveReloadOutcome {
        self.try_trigger_with_activation(now_unix_secs, self.config.activation_ctx.clone())
    }

    /// Run 074 entry point with an explicit `now_unix_secs` and an
    /// override [`ActivationContext`]. Useful when the running node
    /// has progressed past the controller's captured activation
    /// height since construction (e.g. an integration test that
    /// applies a candidate at one height, lets the node commit a
    /// few blocks, and applies a second candidate at the new
    /// height).
    pub fn try_trigger_with_activation(
        &self,
        now_unix_secs: u64,
        activation_ctx: ActivationContext,
    ) -> LiveReloadOutcome {
        // Bump the trigger counter unconditionally — this is the
        // truthful "operator sent a signal" counter, BEFORE the
        // in-progress guard consults its CAS.
        self.metrics.record_live_reload_trigger();

        // CAS the in-progress guard: false → true. If another
        // trigger had already taken the guard, return immediately
        // without touching live trust state, sessions, or the
        // sequence record.
        if self
            .in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.metrics.record_live_reload_already_in_progress();
            return LiveReloadOutcome::AlreadyInProgress;
        }

        // The apply pipeline is synchronous and entirely fallible;
        // wrap it in a closure so the in-progress guard is always
        // released via the `defer`-style block below.
        let outcome = self.run_apply_pipeline(now_unix_secs, activation_ctx);

        // Release the guard BEFORE returning so any concurrent
        // trigger (the next SIGHUP, a follow-up programmatic call)
        // can proceed.
        self.in_progress.store(false, Ordering::Release);

        // Bump apply-side metrics from a single place so binary and
        // test paths agree on the counter shape.
        match &outcome {
            LiveReloadOutcome::Applied(applied) => {
                self.metrics.record_live_reload_apply_success(
                    applied.session_evictions as u64,
                    applied.validated.sequence,
                );
            }
            // Run 121 — the apply pipeline DID succeed; the trust-
            // bundle sequence committed; only the marker persist
            // step failed AFTER the commit boundary. Bump the
            // success counters (live state advanced; sessions were
            // evicted; sequence was committed) — the FATAL outcome
            // shape is carried in the variant itself and surfaced
            // by `is_fatal()` so the binary signals shutdown.
            LiveReloadOutcome::MarkerPersistFailureAfterCommit { applied, .. } => {
                self.metrics.record_live_reload_apply_success(
                    applied.session_evictions as u64,
                    applied.validated.sequence,
                );
            }
            // Run 138 — same shape as the v1 marker-persist-fatal
            // branch above. The trust-bundle sequence already
            // committed; the v2 marker write failed after the commit
            // boundary. Bump success counters; FATAL shape is carried
            // by the variant via `is_fatal()`.
            LiveReloadOutcome::MarkerPersistFailureAfterCommitV2 { applied, .. } => {
                self.metrics.record_live_reload_apply_success(
                    applied.session_evictions as u64,
                    applied.validated.sequence,
                );
            }
            LiveReloadOutcome::Invalid(_)
            | LiveReloadOutcome::Fatal(_)
            // Run 121 — marker preflight refused; no apply pipeline
            // step ran; live state, sessions, on-disk sequence, and
            // on-disk marker are all unchanged. Same counter shape
            // as any other pre-mutation refusal (Run 069 validation
            // refusal, Run 114 sidecar I/O failure).
            | LiveReloadOutcome::MarkerRejected(_)
            // Run 138 — v2 marker preflight refused (or v2 verifier
            // failure mapped to the marker error). Same pre-mutation
            // refusal counter shape as the v1 branch above.
            | LiveReloadOutcome::MarkerRejectedV2(_) => {
                self.metrics.record_live_reload_apply_failure();
            }
            // AlreadyInProgress is already accounted for above and
            // never reaches this match (we returned early).
            LiveReloadOutcome::AlreadyInProgress => {}
        }

        outcome
    }

    /// Inner apply-pipeline driver. Runs the same validate → swap →
    /// evict → commit pipeline the Run 073 at-startup-time hook
    /// drives, but against the running node's live trust handle
    /// and live session-evictor.
    ///
    /// Does NOT touch any metric: every counter update happens on
    /// the surrounding [`Self::try_trigger_with_activation`] so
    /// metric updates and outcome shape stay in lockstep.
    fn run_apply_pipeline(
        &self,
        now_unix_secs: u64,
        activation_ctx: ActivationContext,
    ) -> LiveReloadOutcome {
        let seq_path_ref: Option<&Path> = self.config.sequence_path.as_deref();
        let leaf_bytes_ref: Option<&[u8]> = self.config.local_leaf_cert_bytes.as_deref();

        // Capture pre-swap metadata under a short read lock BEFORE
        // building the apply context. The Run 073 adapter exposes
        // a helper for this so the operator-log line shows both
        // old and new fingerprints.
        let mut apply_ctx = ProductionLiveTrustApplyContext::new(
            self.live.clone(),
            self.evictor.clone(),
            self.config.environment,
            self.config.chain_id,
            self.config.sequence_path.clone(),
            now_unix_secs,
        );
        let (prev_fp_prefix, prev_seq) = apply_ctx.snapshot_previous_metadata();

        let inputs = ReloadCheckInputs {
            candidate_path: self.config.candidate_path.as_path(),
            environment: self.config.environment,
            chain_id: self.config.chain_id,
            validation_time_secs: now_unix_secs,
            signing_keys: &self.config.signing_keys,
            activation_ctx,
            sequence_persistence_path: seq_path_ref,
            local_leaf_cert_bytes: leaf_bytes_ref,
        };

        // Run 114 — SIGHUP live reload ratification enforcement.
        //
        // If the controller was constructed with a
        // `LiveReloadRatificationConfig` (Run 106 policy decided
        // `Invoke` at controller-construction time — always true on
        // MainNet/TestNet by default, DevNet only under explicit
        // operator opt-in), the candidate MUST pass the Run 105
        // genesis-bound bundle-signing-key ratification gate
        // BEFORE any snapshot / swap / eviction / commit. Sidecar
        // I/O / parse failures fail closed at the SAME point — no
        // live trust mutation, no session eviction, no sequence
        // write. See `task/RUN_114_TASK.txt`.
        match &self.config.ratification {
            Some(rcfg) => {
                // Run 132/138 — peek the sidecar schema version once
                // per trigger. v1 sidecars take the existing Run
                // 114/121 path verbatim. v2 sidecars take the Run 138
                // dispatch (Run 130 v2 verifier + Run 134/136 v2
                // marker decision + `apply_validated_candidate_with_previous`
                // without a v1 ratification context). `None` (no
                // sidecar) falls through to the existing v1
                // verifier path which surfaces the typed `Missing`
                // refusal under Strict policy.
                let ratification_obj_v1 = match rcfg.ratification_sidecar_path.as_ref() {
                    Some(path) => match load_versioned_ratification_with_governance_proof_from_path(path) {
                        Ok(VersionedRatificationSidecarWithGovernanceProof::V1(r)) => Some(r),
                        Ok(VersionedRatificationSidecarWithGovernanceProof::V2 {
                            ratification: r2,
                            governance_proof,
                        }) => {
                            // Run 138 — v2 dispatch. Skip the v1
                            // ratification context entirely; the v2
                            // verifier runs inside the preflight
                            // helper. Apply via
                            // `apply_validated_candidate_with_previous`
                            // (no v1 ratification ctx), mirroring the
                            // Run 134 reload-apply v2 branch.
                            // Run 169 — additionally feed the typed
                            // Run 167 `GovernanceProofLoadStatus`
                            // parsed from the same sidecar load into
                            // the SIGHUP preflight so the Run 165
                            // governance gate sees the actual proof
                            // carrier (Available / Absent / Malformed)
                            // instead of a hardcoded `Unavailable`.
                            let marker_decision_v2 =
                                match self.preflight_sighup_v2_marker_decision(
                                    rcfg,
                                    &r2,
                                    &governance_proof,
                                    now_unix_secs,
                                ) {
                                    Ok(opt) => opt,
                                    Err(e) => {
                                        return LiveReloadOutcome::MarkerRejectedV2(e);
                                    }
                                };

                            let apply_outcome = apply_validated_candidate_with_previous(
                                inputs,
                                ApplyMode::ApplyLive,
                                Some(&mut apply_ctx),
                                prev_fp_prefix,
                                prev_seq,
                            );

                            return match apply_outcome {
                                Ok(applied) => {
                                    if let Some(decision) = marker_decision_v2.as_ref() {
                                        if let Err(e) =
                                            persist_accepted_v2_marker_after_commit_boundary(
                                                decision,
                                            )
                                        {
                                            return LiveReloadOutcome::MarkerPersistFailureAfterCommitV2 {
                                                applied,
                                                marker_error: e,
                                            };
                                        }
                                    }
                                    LiveReloadOutcome::Applied(applied)
                                }
                                Err(
                                    e @ ReloadApplyError::SequenceCommitFailedRollbackAlsoFailed { .. },
                                ) => LiveReloadOutcome::Fatal(e),
                                Err(e) => LiveReloadOutcome::Invalid(e),
                            };
                        }
                        Err(e) => {
                            return LiveReloadOutcome::Invalid(
                                ReloadApplyError::ValidationFailed(
                                    ReloadCheckError::Bundle(TrustBundleError::Io(
                                        versioned_ratification_input_io_message(&e),
                                    )),
                                ),
                            );
                        }
                    },
                    None => None,
                };
                let ratification_obj = ratification_obj_v1;
                let ratification_ctx = RatificationEnforcementContext {
                    authority: &rcfg.authority,
                    expected_genesis_hash: &rcfg.expected_genesis_hash,
                    expected_environment_policy: rcfg.expected_environment_policy,
                    expected_chain_id_str: &rcfg.expected_chain_id_str,
                    ratification: ratification_obj.as_ref(),
                    policy: rcfg.policy,
                };

                // Run 121 — SIGHUP authority-marker accept-and-persist
                // preflight. Runs AFTER the sidecar load (so a missing
                // / unparseable sidecar still fails closed via the
                // Run 114 path above with no marker I/O) but BEFORE
                // any snapshot / swap / eviction / commit so a
                // rollback / same-sequence-equivocation / wrong-
                // domain / corrupt marker fail-closes the SIGHUP
                // operation without burning a sequence number or
                // mutating live trust state. The marker is derived
                // ONLY from verified ratification material — the
                // preflight re-runs the Run 105 enforcer (pure
                // function; the apply pipeline will re-run it again
                // internally for bit-identical results) to obtain a
                // verified `RatifiedBundleSigningKey`.
                //
                // Returns `Ok(None)` (no marker enforcement; pre-
                // Run-121 behaviour preserved bit-for-bit) when:
                //   * the controller was not configured with an
                //     `authority_marker` (DevNet no-opt-in / no
                //     `--data-dir`);
                //   * the candidate is DevNet-unsigned (no signing
                //     key to anchor a marker on);
                //   * the enforcer's outcome is `LegacyUnratifiedAccepted`
                //     (DevNet/TestNet legacy ergonomics — Run 105
                //     explicitly logs this as NOT a passed
                //     ratification, so no ratified key exists to
                //     anchor a marker on);
                //   * the candidate cannot be pre-loaded (the apply
                //     pipeline will surface the precise load error
                //     itself; the marker preflight does not
                //     double-report);
                //   * the per-trigger ratification object is missing
                //     under `AllowLegacyUnratified` policy (Run 105
                //     surfaces `LegacyUnratifiedAccepted`; same
                //     branch as above).
                //
                // See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_121.md.
                let marker_decision = match self.preflight_sighup_marker_decision(
                    rcfg,
                    ratification_obj.as_ref(),
                    now_unix_secs,
                ) {
                    Ok(opt) => opt,
                    Err(e) => return LiveReloadOutcome::MarkerRejected(e),
                };

                let apply_outcome = apply_validated_candidate_with_previous_and_ratification(
                    inputs,
                    &ratification_ctx,
                    ApplyMode::ApplyLive,
                    Some(&mut apply_ctx),
                    prev_fp_prefix,
                    prev_seq,
                );

                match apply_outcome {
                    Ok(applied) => {
                        // Run 121 — persist the previously-accepted
                        // marker AFTER the apply pipeline's
                        // `commit_sequence` boundary returned `Ok`.
                        // No-op when:
                        //   * preflight returned `None` (no marker
                        //     context applicable on this trigger);
                        //   * preflight decision was `Idempotent`
                        //     (the on-disk marker is bit-for-bit
                        //     identical; rewriting would only
                        //     update the audit-only
                        //     `updated_at_unix_secs` field for no
                        //     operator benefit).
                        //
                        // On persist failure: the trust-bundle
                        // sequence already advanced and the on-disk
                        // authority marker is stale-by-one (safely
                        // replayable as an `Upgrade` per Run 118 §D),
                        // but the operator MUST be told. We surface
                        // a Run 121
                        // `MarkerPersistFailureAfterCommit` outcome
                        // which `is_fatal()` returns `true` for, so
                        // the binary's SIGHUP signal-handler task
                        // routes it through the same graceful
                        // shutdown signal as the existing Run 074
                        // `SequenceCommitFailedRollbackAlsoFailed`
                        // branch.
                        if let Some(decision) = marker_decision.as_ref() {
                            if let Err(e) =
                                persist_accepted_marker_after_commit_boundary(decision)
                            {
                                return LiveReloadOutcome::MarkerPersistFailureAfterCommit {
                                    applied,
                                    marker_error: e,
                                };
                            }
                        }
                        LiveReloadOutcome::Applied(applied)
                    }
                    Err(e @ ReloadApplyError::SequenceCommitFailedRollbackAlsoFailed { .. }) => {
                        LiveReloadOutcome::Fatal(e)
                    }
                    Err(e) => LiveReloadOutcome::Invalid(e),
                }
            }
            None => {
                match apply_validated_candidate_with_previous(
                    inputs,
                    ApplyMode::ApplyLive,
                    Some(&mut apply_ctx),
                    prev_fp_prefix,
                    prev_seq,
                ) {
                    Ok(applied) => LiveReloadOutcome::Applied(applied),
                    Err(e @ ReloadApplyError::SequenceCommitFailedRollbackAlsoFailed { .. }) => {
                        LiveReloadOutcome::Fatal(e)
                    }
                    Err(e) => LiveReloadOutcome::Invalid(e),
                }
            }
        }
    }

    /// Run 121 — SIGHUP-specific marker accept-and-persist preflight.
    ///
    /// Mirrors the binary-side `preflight_run_119_marker_decision`
    /// (process-start reload-apply) and
    /// `preflight_run_120_marker_decision_for_startup` (startup
    /// `--p2p-trust-bundle`) helpers, but lives inside the
    /// controller because the SIGHUP trigger surface owns the
    /// per-trigger sidecar load / Run 114 ratification gate already
    /// and re-runs the enforcer here so a verified
    /// `RatifiedBundleSigningKey` is in hand for the Run 119
    /// `decide_marker_acceptance` step. Returns `Ok(None)` on every
    /// "marker enforcement is not applicable on this trigger"
    /// branch so SIGHUP behaviour is byte-identical to a Run-120
    /// build on those branches.
    ///
    /// Re-running the enforcer is safe because
    /// `enforce_bundle_signing_key_ratification` is a pure function
    /// (signature / chain_id / environment / authority-root binding
    /// / canonical genesis hash / candidate-key match) and the
    /// apply pipeline re-runs the SAME enforcer internally —
    /// results are bit-for-bit identical. The candidate is re-loaded
    /// via the SAME
    /// `TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation`
    /// loader the apply pipeline uses internally.
    fn preflight_sighup_marker_decision(
        &self,
        rcfg: &LiveReloadRatificationConfig,
        ratification_obj: Option<&qbind_ledger::BundleSigningRatification>,
        now_unix_secs: u64,
    ) -> Result<Option<MarkerAcceptDecision>, MutatingSurfaceMarkerError> {
        let marker_cfg = match &self.config.authority_marker {
            Some(c) => c,
            None => {
                // No authority-marker context wired (DevNet no-opt-in
                // / no `--data-dir`). Pre-Run-121 behaviour
                // preserved bit-for-bit.
                return Ok(None);
            }
        };

        // Re-load the candidate so the bundle-signing public key
        // bytes are available for the Run 105 enforcer. Activation
        // is height-only here (matches the controller's captured
        // `activation_ctx` for the height-source scope rule documented
        // on `LiveReloadConfig::activation_ctx`).
        let activation_ctx = ActivationContext {
            current_height: None,
            current_epoch: None,
        };
        let loaded = match TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
            self.config.candidate_path.as_path(),
            self.config.environment,
            self.config.chain_id,
            now_unix_secs,
            &self.config.signing_keys,
            activation_ctx,
        ) {
            Ok((loaded, _activation)) => loaded,
            Err(_e) => {
                // Defer to the apply pipeline's own typed reporting —
                // it will re-run the SAME loader and surface the
                // precise structural error. We do NOT double-report
                // and do NOT touch the marker file on this branch.
                return Ok(None);
            }
        };

        let signing_key_id_hex = match &loaded.signature_status {
            BundleSignatureStatus::Verified { signing_key_id } => signing_key_id.clone(),
            BundleSignatureStatus::Unsigned => {
                // DevNet-unsigned candidate — no signing key to
                // anchor a marker on. Same skip rule as Run 119/120.
                return Ok(None);
            }
        };

        let signing_key_id_bytes: [u8; 32] = match hex_decode_32_for_sighup(&signing_key_id_hex) {
            Some(b) => b,
            None => {
                // Unreachable: a `Verified` status implies the loader
                // wrote a 64-char lowercase hex signing_key_id.
                // Defer to the Run 105 enforcer's typed reporting.
                return Ok(None);
            }
        };
        let candidate_signing_pk_bytes =
            match self.config.signing_keys.lookup(&signing_key_id_bytes) {
                Some(k) => k.pk_bytes.clone(),
                None => {
                    // Unreachable: a `Verified` status implies the
                    // loader matched the signing_key_id against the
                    // configured set. Defer to the apply pipeline.
                    return Ok(None);
                }
            };

        // Run 105 enforcement — re-runs the precise verifier the
        // apply pipeline will run, so a verified ratification is in
        // hand for the marker derivation step.
        let outcome = match enforce_bundle_signing_key_ratification(
            RatificationEnforcementInputs {
                ratification: ratification_obj,
                authority: &rcfg.authority,
                expected_chain_id: &rcfg.expected_chain_id_str,
                expected_environment: rcfg.expected_environment_policy,
                expected_genesis_hash: &rcfg.expected_genesis_hash,
                candidate_bundle_signing_public_key: &candidate_signing_pk_bytes,
                policy: rcfg.policy,
            },
        ) {
            Ok(o) => o,
            Err(_e) => {
                // Defer to the apply pipeline's own typed reporting —
                // it will re-run the SAME enforcer and emit the
                // precise `RatificationEnforcementFailure` variant.
                // We do NOT double-report and we do NOT touch the
                // marker file on this branch.
                return Ok(None);
            }
        };
        let ratified = match outcome {
            RatificationEnforcementOutcome::Ratified(rk) => rk,
            RatificationEnforcementOutcome::LegacyUnratifiedAccepted { .. } => {
                // DevNet/TestNet legacy ergonomics — no ratified key
                // to anchor a marker on. Run 105 explicitly logs this
                // as NOT a passed ratification; the marker is simply
                // not written. Same skip rule as Run 119/120.
                return Ok(None);
            }
        };
        let ratification = match ratification_obj {
            Some(r) => r,
            None => {
                // Unreachable on the Ratified branch — Strict requires
                // a ratification object, and AllowLegacyUnratified
                // with no object returns LegacyUnratifiedAccepted
                // above.
                return Ok(None);
            }
        };

        // Compute the runtime genesis hash hex (Run 117 format — 64
        // lowercase hex chars).
        let mut runtime_genesis_hash_hex = String::with_capacity(64);
        for b in rcfg.expected_genesis_hash {
            use std::fmt::Write;
            let _ = write!(runtime_genesis_hash_hex, "{:02x}", b);
        }

        let decision = decide_marker_acceptance(MarkerAcceptanceInputs {
            marker_path: marker_cfg.marker_path.as_path(),
            runtime_env: self.config.environment,
            runtime_chain_id: self.config.chain_id,
            runtime_genesis_hash_hex: &runtime_genesis_hash_hex,
            authority_policy_version: rcfg.authority.authority_policy_version,
            authority_sequence: rcfg.authority.authority_sequence,
            authority_epoch: rcfg.authority.authority_epoch,
            ratification,
            ratified: &ratified,
            update_source: AuthorityStateUpdateSource::SighupReload,
            updated_at_unix_secs: now_unix_secs,
        })?;
        Ok(Some(decision))
    }

    /// Run 138 — SIGHUP-specific **v2** marker accept-and-persist
    /// preflight.
    ///
    /// v2 twin of [`Self::preflight_sighup_marker_decision`]. Mirrors
    /// the binary-side `preflight_run_134_v2_marker_decision`
    /// (process-start reload-apply) and
    /// `preflight_run_136_v2_marker_decision_for_startup` (startup
    /// `--p2p-trust-bundle`) helpers but lives inside the controller
    /// because the SIGHUP trigger surface owns the per-trigger
    /// versioned sidecar load already and re-runs the Run 130 v2
    /// verifier here so a verified
    /// [`qbind_ledger::RatifiedBundleSigningKeyV2`] is in hand for the
    /// Run 134 `decide_marker_acceptance_v2` step.
    ///
    /// Composes:
    ///   1. [`verify_bundle_signing_key_ratification_v2`] (Run 130 v2 verifier).
    ///   2. [`decide_marker_acceptance_v2`] (Run 134/136 v2 decision).
    ///
    /// Tags the persisted-record audit field with
    /// [`AuthorityStateUpdateSource::SighupReload`] — the exact
    /// existing enum variant the v1 SIGHUP marker path uses, per
    /// Run 138 §5. The task allows either a new `SighupLiveReload`
    /// variant OR the existing v1 SIGHUP variant; reusing the
    /// existing variant avoids `AuthorityStateUpdateSource` schema
    /// drift (forbidden by Run 138 strict scope).
    ///
    /// Returns `Ok(None)` when the controller was not configured
    /// with an `authority_marker` (DevNet no-opt-in / no
    /// `--data-dir`). On any v2 verifier failure, returns
    /// `Err(MutatingSurfaceMarkerV2Error::Conflict(MalformedOrUnsupportedMarkerRejected{reason}))`
    /// so the caller surfaces the precise reason in the
    /// `MarkerRejectedV2` outcome's log line — matching the Run
    /// 134/136 v2 verifier-failure-mapping shape.
    ///
    /// Performs **no** disk writes: every disk side-effect is
    /// deferred to
    /// [`persist_accepted_v2_marker_after_commit_boundary`], which
    /// the caller invokes only AFTER the apply pipeline's
    /// `commit_sequence` step succeeds.
    fn preflight_sighup_v2_marker_decision(
        &self,
        rcfg: &LiveReloadRatificationConfig,
        ratification_v2: &BundleSigningRatificationV2,
        governance_proof_load: &crate::pqc_governance_proof_wire::GovernanceProofLoadStatus,
        now_unix_secs: u64,
    ) -> Result<Option<MarkerAcceptDecisionV2>, MutatingSurfaceMarkerV2Error> {
        let marker_cfg = match &self.config.authority_marker {
            Some(c) => c,
            None => {
                // No authority-marker context wired (DevNet
                // no-opt-in / no `--data-dir`). Pre-Run-138
                // behaviour preserved bit-for-bit — the apply
                // pipeline still runs without v1 ratification
                // context (the v2 sidecar bypasses the v1 gate).
                return Ok(None);
            }
        };

        // Step 1 — Run 130 v2 verifier. Re-run here so a verified
        // ratified-key is in hand for the v2 marker derivation; the
        // verifier is a pure function and the binary's other v2
        // surfaces (Run 134/136) run the SAME verifier with
        // bit-identical results.
        let ratified_v2 = verify_bundle_signing_key_ratification_v2(
            RatificationV2VerifierInputs {
                ratification: ratification_v2,
                authority: &rcfg.authority,
                expected_chain_id: &rcfg.expected_chain_id_str,
                expected_environment: rcfg.expected_environment_policy,
                expected_genesis_hash: &rcfg.expected_genesis_hash,
            },
        )
        .map_err(|e| {
            // Map verifier failure into the typed marker error so
            // the SIGHUP operator log line names the exact failure
            // class. Mirrors the Run 134/136 v2 verifier-failure
            // mapping.
            MutatingSurfaceMarkerV2Error::Conflict(
                AuthorityMarkerV2ComparisonOutcome::MalformedOrUnsupportedMarkerRejected {
                    reason: format!("v2 ratification verifier failure: {}", e),
                },
            )
        })?;

        // Step 2 — runtime genesis hash hex.
        let mut runtime_genesis_hash_hex = String::with_capacity(64);
        for b in rcfg.expected_genesis_hash {
            use std::fmt::Write;
            let _ = write!(runtime_genesis_hash_hex, "{:02x}", b);
        }

        // Step 3 — Run 134/136 v2 marker decision (no disk write).
        // Run 169: route through the Run 169 governance-proof surface
        // shim so the typed Run 167 `GovernanceProofLoadStatus` parsed
        // from the SIGHUP-trigger sidecar load reaches the Run 165
        // governance gate.
        //
        // Run 171: the policy is now selected by the binary at
        // controller construction time from the hidden
        // `--p2p-trust-bundle-governance-proof-required` flag /
        // `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED` env var
        // (`LiveReloadConfig::governance_proof_policy`). Default
        // remains `NotRequired` so old no-proof v2 sidecars under
        // SIGHUP remain compatible bit-for-bit; under
        // `RequiredForLifecycleSensitive` a missing or invalid Run 167
        // proof on a `Rotate`/`Retire`/`Revoke`/`EmergencyRevoke`
        // sidecar fails closed before any Run 070 apply / live-trust
        // swap / session eviction / sequence write / marker persist.
        // The fixture verifier is the source/test issuer-signature
        // verifier; release-binary Required-policy production-surface
        // evidence is deferred to Run 172. MainNet peer-driven apply
        // remains refused at the calling surface regardless of
        // governance proof.
        let verifier =
            crate::pqc_governance_authority::fixture_issuer_signature_verifier();
        let decision = crate::pqc_governance_proof_surface::preflight_v2_marker_decision_with_governance_proof_load(
            MarkerAcceptanceV2Inputs {
                marker_path: marker_cfg.marker_path.as_path(),
                runtime_env: self.config.environment,
                runtime_chain_id: self.config.chain_id,
                runtime_genesis_hash_hex: &runtime_genesis_hash_hex,
                ratification: ratification_v2,
                ratified: &ratified_v2,
                update_source: AuthorityStateUpdateSource::SighupReload,
                updated_at_unix_secs: now_unix_secs,
            },
            self.config.governance_proof_policy,
            governance_proof_load,
            &verifier,
        )?;

        // Run 182 — production call-site reachability for the Run 180
        // OnChainGovernance per-surface preflight wrapper for SIGHUP
        // live trust-bundle reload mutating-preflight. Pure: no
        // marker write, no sequence write, no live trust swap, no
        // session eviction, no Run 070 invocation. Wire blocker:
        // current SIGHUP-trigger sidecar formats do not carry a
        // typed `OnChainGovernanceProof`; documented in
        // `pqc_onchain_governance_callsite_wiring.rs`.
        invoke_run_182_sighup_callsite_onchain_governance_marker_decision(
            &decision,
            self.config.onchain_governance_fixture_allowed_selector,
        );

        Ok(Some(decision))
    }
}

/// Run 182 — SIGHUP production call-site reachability hook.
fn invoke_run_182_sighup_callsite_onchain_governance_marker_decision(
    decision: &crate::pqc_authority_marker_acceptance::MarkerAcceptDecisionV2,
    onchain_governance_fixture_allowed_selector: bool,
) {
    use crate::pqc_authority_lifecycle::AuthorityTrustDomain;
    use crate::pqc_onchain_governance_callsite_wiring::{
        sighup_callsite_onchain_governance_marker_decision,
        OnChainGovernanceCallsiteContext,
    };
    use crate::pqc_onchain_governance_proof::EmptyOnChainGovernanceReplaySet;
    use crate::pqc_onchain_governance_proof_surface::onchain_governance_proof_policy_from_cli_or_env;

    let candidate = decision.candidate();
    let trust_domain = AuthorityTrustDomain::new(
        candidate.environment,
        candidate.chain_id.clone(),
        candidate.genesis_hash.clone(),
        candidate.authority_root_fingerprint.clone(),
        candidate.authority_root_suite_id,
    );
    let policy = onchain_governance_proof_policy_from_cli_or_env(
        onchain_governance_fixture_allowed_selector,
    );
    let ctx = OnChainGovernanceCallsiteContext {
        persisted: None,
        candidate,
        proof: None,
        trust_domain: &trust_domain,
        policy,
        expected_governance_domain_id: "",
        expected_governance_epoch: 0,
        expected_proposal_id: "",
        expected_proposal_digest: "",
        now_unix: 0,
        replay_set: &EmptyOnChainGovernanceReplaySet,
    };
    let _outcome = sighup_callsite_onchain_governance_marker_decision(&ctx);
}

/// Run 121 — decode a 64-char lowercase-hex string into a `[u8; 32]`.
/// Mirrors the `hex_decode_32` helper in `main.rs` used by the
/// Run 119/120 preflights; duplicated here so the library module
/// has no dependency on the binary crate.
fn hex_decode_32_for_sighup(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble_for_sighup(bytes[2 * i])?;
        let lo = hex_nibble_for_sighup(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble_for_sighup(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Run 138 — render a [`VersionedRatificationInputError`] (Run 132
/// versioned sidecar loader I/O / JSON / unknown version / malformed)
/// into the human-readable message embedded in a fail-closed
/// [`TrustBundleError::Io`]. The full `Display` form already contains
/// the typed `[run-132] ...` reason so we route it through unchanged;
/// the wrapping `TrustBundleError::Io` is purely a transport for the
/// existing `ReloadCheckError` enum shape. This is the v2 SIGHUP twin
/// of the pre-Run-138 v1-only `ratification_input_io_message` shape.
fn versioned_ratification_input_io_message(e: &VersionedRatificationInputError) -> String {
    format!(
        "[run-138] SIGHUP live reload refused — versioned ratification sidecar input error: {}",
        e
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p_session_eviction::{
        EvictionError, EvictionReason, EvictionReport, MockP2pSessionEvictor,
    };
    use crate::pqc_devnet_helper::mint_devnet_root;
    use crate::pqc_trust_bundle::{
        build_helper_bundle, HelperBundleMode, TrustBundle,
    };

    fn hex_lower(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", x);
        }
        s
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "qbind-run074-unit-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        std::fs::create_dir_all(&p).expect("create_dir_all");
        p
    }

    /// Build an unsigned-DevNet helper bundle on disk so a controller
    /// can be exercised end-to-end without minting an ML-DSA-44
    /// signing key. Returns the on-disk path + the helper bundle's
    /// active root metadata so the live trust state can be seeded
    /// from the SAME bytes.
    fn write_helper_bundle(
        dir: &Path,
        name: &str,
        sequence: u64,
        generated_at: u64,
    ) -> (PathBuf, [u8; 32], Vec<u8>) {
        let root = mint_devnet_root().expect("mint devnet root");
        let id_hex = hex_lower(&root.root_key_id);
        let pk_hex = hex_lower(&root.root_pk);
        let mut bundle =
            build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, generated_at);
        bundle.sequence = sequence;
        let bytes = serde_json::to_vec(&bundle).expect("serialise");
        let path = dir.join(name);
        std::fs::write(&path, &bytes).expect("write");
        (path, root.root_key_id, root.root_pk)
    }

    fn load_bundle(path: &Path) -> crate::pqc_trust_bundle::LoadedTrustBundle {
        let bytes = std::fs::read(path).expect("read");
        TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 200).expect("loads")
    }

    fn devnet_config(
        candidate_path: PathBuf,
        sequence_path: Option<PathBuf>,
    ) -> LiveReloadConfig {
        LiveReloadConfig {
            candidate_path,
            environment: NetworkEnvironment::Devnet,
            chain_id: NetworkEnvironment::Devnet.chain_id(),
            signing_keys: BundleSigningKeySet::default(),
            activation_ctx: ActivationContext::height_only(0),
            sequence_path,
            local_leaf_cert_bytes: None,
            ratification: None,
            authority_marker: None,
            governance_proof_policy:
                crate::pqc_governance_authority::GovernanceProofPolicy::NotRequired,
            onchain_governance_fixture_allowed_selector: false,
        }
    }

    /// Mock evictor that always returns an `Err(_)` from
    /// `evict_all_sessions` — used to drive the partial-failure /
    /// unsupported-runtime branch on the controller without
    /// spinning up real TCP.
    #[derive(Debug)]
    struct AlwaysUnsupportedEvictor;
    impl P2pSessionEvictor for AlwaysUnsupportedEvictor {
        fn connected_session_count(&self) -> usize {
            0
        }
        fn evict_all_sessions(
            &self,
            _reason: EvictionReason,
        ) -> Result<EvictionReport, EvictionError> {
            Err(EvictionError::UnsupportedSessionEviction(
                "unit-test induced unsupported runtime".to_string(),
            ))
        }
    }

    // ====================================================================
    // Controller construction + getters.
    // ====================================================================

    #[test]
    fn controller_construction_does_not_read_candidate_path() {
        // The controller MUST NOT read the candidate file on
        // construction — a typo-only candidate path that does not
        // exist yet must still allow the controller to exist; the
        // failure surfaces only when an operator triggers it.
        let dir = tmpdir("construct");
        let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(
            &load_bundle(&write_helper_bundle(&dir, "baseline.json", 1, 100).0),
        ));
        let metrics = Arc::new(P2pMetrics::new());
        let mock: Arc<dyn P2pSessionEvictor> = Arc::new(MockP2pSessionEvictor::new(0));
        let nonexistent = dir.join("does-not-exist-yet.json");
        let ctl = LiveReloadController::new(
            live,
            mock,
            metrics.clone(),
            devnet_config(nonexistent.clone(), None),
        );
        assert!(!nonexistent.exists());
        assert_eq!(ctl.config().candidate_path, nonexistent);
        assert!(!ctl.is_in_progress());
        // Trigger counter still 0 because no trigger has fired.
        assert_eq!(metrics.live_reload_trigger_total(), 0);
    }

    #[test]
    fn controller_is_clone_and_shares_in_progress_guard() {
        let dir = tmpdir("clone");
        let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(
            &load_bundle(&write_helper_bundle(&dir, "baseline.json", 1, 100).0),
        ));
        let metrics = Arc::new(P2pMetrics::new());
        let mock: Arc<dyn P2pSessionEvictor> = Arc::new(MockP2pSessionEvictor::new(0));
        let ctl = LiveReloadController::new(
            live,
            mock,
            metrics,
            devnet_config(dir.join("c.json"), None),
        );
        let clone = ctl.clone();
        // Flip in_progress through the original; the clone observes
        // the same shared flag.
        ctl.in_progress.store(true, Ordering::Relaxed);
        assert!(clone.is_in_progress());
        ctl.in_progress.store(false, Ordering::Relaxed);
        assert!(!clone.is_in_progress());
    }

    // ====================================================================
    // Trigger metric accounting.
    // ====================================================================

    #[test]
    fn trigger_with_nonexistent_candidate_path_returns_invalid_and_bumps_failure_counter() {
        // No candidate file at all → Run 069 validation fails with
        // a `TrustBundleError::Io`. The controller surfaces
        // `Invalid` and bumps `live_reload_apply_failure_total`.
        let dir = tmpdir("nofile");
        let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(
            &load_bundle(&write_helper_bundle(&dir, "baseline.json", 1, 100).0),
        ));
        let metrics = Arc::new(P2pMetrics::new());
        let mock: Arc<dyn P2pSessionEvictor> = Arc::new(MockP2pSessionEvictor::new(2));
        let ctl = LiveReloadController::new(
            live,
            mock,
            metrics.clone(),
            devnet_config(dir.join("does-not-exist.json"), None),
        );

        let out = ctl.try_trigger_with_now(200);
        assert!(matches!(out, LiveReloadOutcome::Invalid(_)));
        assert!(!ctl.is_in_progress());
        assert_eq!(metrics.live_reload_trigger_total(), 1);
        assert_eq!(metrics.live_reload_apply_success_total(), 0);
        assert_eq!(metrics.live_reload_apply_failure_total(), 1);
        assert_eq!(metrics.live_reload_already_in_progress_total(), 0);
        assert_eq!(metrics.live_reload_sessions_evicted_total(), 0);
        assert_eq!(metrics.live_reload_last_applied_sequence(), 0);
    }

    // ====================================================================
    // Outcome log-line shape.
    // ====================================================================

    #[test]
    fn outcome_log_line_marks_each_branch_with_run_074_prefix() {
        // AlreadyInProgress branch.
        let s = LiveReloadOutcome::AlreadyInProgress.log_line();
        assert!(s.starts_with("[binary] Run 074:"), "{}", s);
        assert!(s.contains("VERDICT=already-in-progress"), "{}", s);
        assert!(s.contains("without touching live trust state"), "{}", s);

        // Invalid branch with a synthetic error.
        let e = ReloadApplyError::UnsupportedRuntimeContext("test".into());
        let s = LiveReloadOutcome::Invalid(e).log_line();
        assert!(s.starts_with("[binary] Run 074:"), "{}", s);
        assert!(s.contains("VERDICT=invalid"), "{}", s);
        assert!(s.contains("rolled back"), "{}", s);

        // Fatal branch with a synthetic error.
        let e = ReloadApplyError::SequenceCommitFailedRollbackAlsoFailed {
            commit_message: "c".into(),
            rollback_message: "r".into(),
        };
        let s = LiveReloadOutcome::Fatal(e).log_line();
        assert!(s.starts_with("[binary] Run 074:"), "{}", s);
        assert!(s.contains("VERDICT=FATAL"), "{}", s);
        assert!(s.contains("recover offline"), "{}", s);
    }

    // ====================================================================
    // Unsupported-evictor surfaces a clean Invalid (no panic).
    // ====================================================================

    #[test]
    fn always_unsupported_evictor_surfaces_invalid_not_fatal() {
        // A misconfigured evictor that returns
        // `UnsupportedSessionEviction` from every call MUST be
        // surfaced as `Invalid` (rollback succeeded — live state
        // matches pre-trigger). The fatal branch is reserved for
        // SequenceCommitFailedRollbackAlsoFailed.
        let dir = tmpdir("unsup");
        let (baseline_path, _id, _pk) = write_helper_bundle(&dir, "baseline.json", 1, 100);
        let baseline_loaded = load_bundle(&baseline_path);
        let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(
            &baseline_loaded,
        ));
        let pre_swap_arc = live.snapshot().expect("snap");
        let metrics = Arc::new(P2pMetrics::new());
        let evictor: Arc<dyn P2pSessionEvictor> = Arc::new(AlwaysUnsupportedEvictor);
        // Candidate at sequence=2 (genuine forward step) so the
        // pipeline reaches the swap+evict stage before failing.
        let (candidate_path, _, _) = write_helper_bundle(&dir, "candidate.json", 2, 200);
        let ctl = LiveReloadController::new(
            live.clone(),
            evictor,
            metrics.clone(),
            devnet_config(candidate_path, None),
        );

        let out = ctl.try_trigger_with_now(200);
        match out {
            LiveReloadOutcome::Invalid(ReloadApplyError::SessionEvictionFailed {
                rollback_ok,
                ..
            }) => {
                assert!(rollback_ok, "rollback must succeed on this branch");
            }
            other => panic!("expected Invalid(SessionEvictionFailed), got {:?}", other),
        }
        // Rollback installs a fresh `Arc` whose contents match the
        // pre-swap snapshot (the Run 073 adapter deep-clones the
        // captured snapshot via `swap_snapshot`); assert the
        // operator-visible metadata reverted truthfully rather than
        // requiring Arc pointer equality.
        let post = live.snapshot().expect("snap");
        assert_eq!(post.fingerprint(), pre_swap_arc.fingerprint());
        assert_eq!(post.sequence(), pre_swap_arc.sequence());
        assert_eq!(metrics.live_reload_trigger_total(), 1);
        assert_eq!(metrics.live_reload_apply_success_total(), 0);
        assert_eq!(metrics.live_reload_apply_failure_total(), 1);
        assert_eq!(metrics.live_reload_sessions_evicted_total(), 0);
    }
}