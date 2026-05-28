//! Run 057 (C4 piece: PQC trust-bundle activation gating):
//! enforce optional `activation_height` / `activation_epoch` fields
//! on a freshly validated trust bundle so a structurally-valid, signed,
//! anti-rollback-checked bundle is **not accepted before its declared
//! activation condition is satisfied**.
//!
//! # Strict scope (activation gating only)
//!
//! - Adds NO consensus, KEMTLS, timeout-verification, or NewView wire
//!   format changes.
//! - Adds NO new metric families beyond the ones declared in
//!   `crates/qbind-node/src/metrics.rs` for this run; rejected events
//!   and the snapshot current/required height are surfaced through
//!   pre-existing `P2pMetrics`.
//! - Does NOT silently fall back to `--p2p-trusted-root`.
//! - Does NOT silently fall back to `DummySig` / `DummyKem` / `DummyAead`.
//! - Does NOT redesign the trust-bundle envelope or the sequence
//!   anti-rollback persistence layer (Run 055/056).
//! - Preserves the Run 050/051/052/053 fail-closed boundary for
//!   schema / environment / chain_id / validity / signature.
//!
//! # Where the gate runs
//!
//! Run 055 already pins the strict ordering at the caller (binary
//! `main.rs` trust-bundle path):
//!
//! ```text
//! 1. parse bundle JSON
//! 2. verify ML-DSA-44 signature
//! 3. validate environment / chain_id / root status / revocations / windows
//! 4. ACTIVATION GATING   <-- this module
//! 5. sequence anti-rollback persistence (pqc_trust_sequence)
//! 6. merge active roots into the live PQC trust set
//! ```
//!
//! The activation check runs **after** structural / signature /
//! revocation validation (so we never invoke this layer on a malformed
//! envelope) and **before** sequence persistence and root merge (so a
//! bundle whose declared activation gate is not yet satisfied
//! - MUST NOT advance the persisted highest sequence
//!   (would otherwise permanently burn a higher sequence on a bundle
//!   that has not yet taken effect — equivalent to a silent rollback
//!   on the next bundle that DOES satisfy activation), and
//! - MUST NOT be merged into the live trust set.
//!
//! # Semantics
//!
//! Both `activation_height` and `activation_epoch` are **inclusive**:
//! `current >= required` activates, `current < required` is not yet
//! active. Missing field on the bundle/root = no restriction from that
//! field.
//!
//! When both gates are present on the bundle, both must be satisfied
//! independently. Likewise for any per-root activation field.
//!
//! When activation gating is requested and the runtime source for the
//! corresponding field is unavailable (e.g. `current_height: None` on
//! a bundle with `activation_height: Some(...)`), the loader fails
//! closed with [`TrustBundleActivationError::CurrentHeightUnavailable`]
//! or [`TrustBundleActivationError::CurrentEpochUnavailable`]. We do
//! NOT silently treat unavailable-as-satisfied: that would create a
//! window in which a not-yet-active bundle could be merged on a
//! restore-baseline-less node start.
//!
//! # Runtime sources (chosen by the caller)
//!
//! Today (Run 057) the binary surface provides:
//!
//! - `current_height = Some(restore_outcome.meta.height)` when the
//!   node was started with `--restore-from-snapshot`, else
//!   `Some(0)` for a fresh-from-genesis node. This is the
//!   locally-committed height at startup, which is the only safe
//!   height source available **before** consensus participation
//!   begins (and therefore before trust roots are merged).
//! - `current_epoch = None`. There is no safe pre-consensus epoch
//!   source in this codebase as of Run 057: the epoch manager
//!   transitions only after consensus has begun committing blocks,
//!   so consulting it here would create a circular dependency
//!   (trust bundle is needed to verify peer transport before
//!   consensus can advance). Bundles that declare
//!   `activation_epoch: Some(...)` therefore fail closed under the
//!   present surface; epoch gating is recorded as remaining-open in
//!   `docs/whitepaper/contradiction.md` C4.

use crate::pqc_trust_bundle::{TrustBundle, TrustBundleEnvironment, TrustBundleRoot};

// ---------------------------------------------------------------------
// Run 065: per-environment minimum activation-height policy.
// ---------------------------------------------------------------------
//
// Run 057 enforced future-height gating on a bundle's *declared*
// activation_height: a bundle whose activation_height was greater than
// the runtime current_height failed closed. Run 062 added the same
// shape for per-entry revocation activation_height (active / pending
// split). Neither run constrained how *close* to current_height an
// operator could schedule activation.
//
// Run 065 closes that gap by introducing a deterministic, per-
// environment **minimum activation-margin**:
//
//   activation_height (when declared) MUST satisfy
//       activation_height >= current_height + MIN_<ENV>_ACTIVATION_MARGIN
//
//   When activation_height is not declared (`None`), Run 050/052/062
//   immediate behaviour is preserved exactly — this matters for
//   emergency root/leaf revocations, which intentionally do NOT carry
//   a scheduled activation_height (a revocation entry without
//   activation_height becomes active as soon as effective_from is
//   satisfied, exactly as in Run 050/052).
//
// Constants below are chosen to be **production-honest but evidence-
// realistic**: small enough that the Run 065 release-binary smokes
// can exercise both the negative (too-soon) and positive (sufficient
// margin) paths from `current_height = 0`, but strictly positive so
// that on TestNet/MainNet an operator cannot publish a signed bundle
// whose activation_height equals the current committed height (the
// "immediate cutover" path that Run 057/062 still admitted at the
// type level).
//
// DevNet keeps margin = 0 so that every prior Run 050–064 fixture
// (including activation_height = 0 / activation_height = current
// height) continues to load. This is deliberate: DevNet is the
// scaffolding environment for evidence runs and operator rehearsals,
// and tightening it would break Run 057/058/062/063 evidence shape
// without buying any production safety (DevNet roots never bind
// MainNet validators).

/// Minimum margin between `activation_height` and `current_height`
/// for a TestNet trust-bundle / scheduled-revocation entry. 8 blocks
/// is the smallest value that meaningfully blocks "immediate" /
/// "almost-immediate" production-like cutover while remaining small
/// enough to be cheaply exercised by Run 065 release-binary smokes
/// starting from `current_height = 0`.
pub const MIN_TESTNET_ACTIVATION_MARGIN: u64 = 8;

/// Minimum margin between `activation_height` and `current_height`
/// for a MainNet trust-bundle / scheduled-revocation entry. 32 blocks
/// is strictly stricter than TestNet so a MainNet bundle cannot be
/// scheduled tighter than a TestNet bundle.
pub const MIN_MAINNET_ACTIVATION_MARGIN: u64 = 32;

/// Margin used on DevNet. Zero by design — DevNet fixtures from
/// Run 050–064 continue to load with `activation_height = 0` or
/// `activation_height = current_height` (immediate cutover).
pub const MIN_DEVNET_ACTIVATION_MARGIN: u64 = 0;

/// Deterministic per-environment activation-margin policy. Today the
/// only knob is `minimum_activation_margin`; this struct is the
/// extension point if a future run needs e.g. a per-environment
/// maximum activation horizon. The values returned by
/// [`Self::for_environment`] are stable and signature-pinned by
/// [`policy_constants_are_deterministic`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationPolicy {
    /// Minimum margin between any declared `activation_height` and
    /// the runtime `current_height` at the moment of trust-bundle
    /// load. Applies to bundle-level + per-active-root activation,
    /// and to per-entry revocation activation (scheduled revocations
    /// only; revocations without `activation_height` are not
    /// constrained — see module docs above on emergency revocation).
    pub minimum_activation_margin: u64,
}

impl ActivationPolicy {
    /// Resolve the policy for a [`TrustBundleEnvironment`]. Pure
    /// function over the environment label; no I/O, no global state.
    pub const fn for_environment(env: TrustBundleEnvironment) -> Self {
        match env {
            TrustBundleEnvironment::Devnet => Self {
                minimum_activation_margin: MIN_DEVNET_ACTIVATION_MARGIN,
            },
            TrustBundleEnvironment::Testnet => Self {
                minimum_activation_margin: MIN_TESTNET_ACTIVATION_MARGIN,
            },
            TrustBundleEnvironment::Mainnet => Self {
                minimum_activation_margin: MIN_MAINNET_ACTIVATION_MARGIN,
            },
        }
    }
}

/// Convenience wrapper: return the minimum activation margin (in
/// blocks) for the given environment.
pub const fn minimum_activation_margin_for_environment(env: TrustBundleEnvironment) -> u64 {
    ActivationPolicy::for_environment(env).minimum_activation_margin
}

/// Runtime source for activation-gate evaluation. Both fields are
/// optional so callers without a safe source can express that
/// honestly; the validator then refuses any bundle/root that declares
/// a gate which depends on the missing source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ActivationContext {
    /// Locally-committed height at the moment of trust-bundle load.
    /// `None` means "no safe height source available": any
    /// `activation_height: Some(...)` field will fail closed with
    /// [`TrustBundleActivationError::CurrentHeightUnavailable`].
    pub current_height: Option<u64>,
    /// Locally-known epoch at the moment of trust-bundle load.
    /// `None` means "no safe epoch source available" (Run 057
    /// default): any `activation_epoch: Some(...)` field will fail
    /// closed with [`TrustBundleActivationError::CurrentEpochUnavailable`].
    pub current_epoch: Option<u64>,
}

impl ActivationContext {
    /// Construct an [`ActivationContext`] with neither source
    /// available. Bundles that declare any activation gate fail
    /// closed under this context.
    pub const fn unavailable() -> Self {
        Self {
            current_height: None,
            current_epoch: None,
        }
    }

    /// Construct an [`ActivationContext`] with only a height source.
    /// Bundles that declare `activation_epoch` fail closed.
    pub const fn height_only(current_height: u64) -> Self {
        Self {
            current_height: Some(current_height),
            current_epoch: None,
        }
    }
}

/// Errors produced by the activation-gating layer. Every variant is
/// a fail-closed condition at the binary surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustBundleActivationError {
    /// Bundle-level `activation_height` is set on the bundle but the
    /// supplied [`ActivationContext`] carried no `current_height`
    /// source. Run 057 surface: this only fires on bundles that
    /// explicitly declare a height gate; bundles without the field
    /// are unaffected.
    CurrentHeightUnavailable {
        required_height: u64,
        scope: ActivationScope,
    },
    /// Bundle-level / root-level `activation_epoch` is set but the
    /// supplied [`ActivationContext`] carried no `current_epoch`
    /// source. Run 057 surface: epoch gating is deferred and this
    /// fires for any bundle that declares an epoch gate today.
    CurrentEpochUnavailable {
        required_epoch: u64,
        scope: ActivationScope,
    },
    /// `current_height < required_height` — not yet active. Fail
    /// closed before sequence persistence and before root merge.
    ActivationHeightNotYetReached {
        current_height: u64,
        required_height: u64,
        scope: ActivationScope,
    },
    /// `current_epoch < required_epoch` — not yet active. Fail
    /// closed before sequence persistence and before root merge.
    ActivationEpochNotYetReached {
        current_epoch: u64,
        required_epoch: u64,
        scope: ActivationScope,
    },
    /// Run 065: bundle-level / per-active-root `activation_height`
    /// is declared but is closer to `current_height` than the
    /// per-environment minimum activation margin allows. Fail closed
    /// BEFORE sequence persistence and BEFORE root merge so a too-
    /// soon activation cannot burn a higher sequence on a not-yet-
    /// effective bundle. Carries the resolved `required_min_height`
    /// (= `current_height + margin`) for forensic logging.
    ActivationHeightBelowMinimumMargin {
        environment: TrustBundleEnvironment,
        current_height: u64,
        activation_height: u64,
        minimum_margin: u64,
        required_min_height: u64,
        scope: ActivationScope,
    },
    /// Run 065: a per-entry revocation `activation_height` is
    /// declared (scheduled revocation) but is closer to
    /// `current_height` than the per-environment minimum activation
    /// margin allows. Fail closed BEFORE sequence persistence and
    /// BEFORE root merge. Immediate revocations (revocation entries
    /// with `activation_height = None`) are NOT constrained — that
    /// preserves the Run 050/052/062 immediate emergency-revocation
    /// path. Carries the offending revocation's `root_id` and (if
    /// any) `leaf_cert_fingerprint` prefix in `scope` for forensic
    /// logging.
    RevocationActivationHeightBelowMinimumMargin {
        environment: TrustBundleEnvironment,
        current_height: u64,
        activation_height: u64,
        minimum_margin: u64,
        required_min_height: u64,
        scope: RevocationScope,
    },
}

/// Forensic scope for [`TrustBundleActivationError::RevocationActivationHeightBelowMinimumMargin`].
/// Carries enough information to identify the offending revocation
/// entry in operator logs without leaking any private material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationScope {
    /// Lowercase-hex root id of the revoked root (64 chars).
    pub root_id: String,
    /// Lowercase-hex leaf fingerprint if the revocation targets a
    /// leaf, else `None` for a root-scope revocation.
    pub leaf_fingerprint: Option<String>,
}

impl std::fmt::Display for RevocationScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.leaf_fingerprint {
            Some(fp) => write!(f, "revocation root_id={} leaf_fp={}", self.root_id, fp),
            None => write!(f, "revocation root_id={}", self.root_id),
        }
    }
}

/// Granularity for the activation field that triggered the error.
/// Carried in [`TrustBundleActivationError`] so operator-facing logs
/// can distinguish bundle-wide gates from per-root gates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivationScope {
    /// Whole-bundle activation gate (`TrustBundle::activation_height`
    /// or `TrustBundle::activation_epoch`).
    Bundle,
    /// Per-root activation gate (`TrustBundleRoot::activation_height`
    /// or `TrustBundleRoot::activation_epoch`); carries the 64-char
    /// lowercase-hex root_id for forensics.
    Root(String),
}

impl std::fmt::Display for ActivationScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bundle => f.write_str("bundle"),
            Self::Root(id) => write!(f, "root={}", id),
        }
    }
}

impl std::fmt::Display for TrustBundleActivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CurrentHeightUnavailable {
                required_height,
                scope,
            } => write!(
                f,
                "pqc trust-bundle activation height gating requires current_height but no \
                 runtime height source is available (scope={}, required_height={}); fail closed \
                 — runtime height source is needed to evaluate the gate",
                scope, required_height
            ),
            Self::CurrentEpochUnavailable {
                required_epoch,
                scope,
            } => write!(
                f,
                "pqc trust-bundle activation epoch gating requires current_epoch but no runtime \
                 epoch source is available in this build (scope={}, required_epoch={}); fail \
                 closed — epoch gating is deferred (see docs/whitepaper/contradiction.md C4)",
                scope, required_epoch
            ),
            Self::ActivationHeightNotYetReached {
                current_height,
                required_height,
                scope,
            } => write!(
                f,
                "pqc trust-bundle activation height not yet reached (scope={}, \
                 current_height={}, required_height={}); fail closed — bundle is structurally \
                 valid and properly signed but has not yet become effective at this committed \
                 height. No fallback to --p2p-trusted-root.",
                scope, current_height, required_height
            ),
            Self::ActivationEpochNotYetReached {
                current_epoch,
                required_epoch,
                scope,
            } => write!(
                f,
                "pqc trust-bundle activation epoch not yet reached (scope={}, current_epoch={}, \
                 required_epoch={}); fail closed — bundle is structurally valid and properly \
                 signed but has not yet become effective at this epoch. No fallback to \
                 --p2p-trusted-root.",
                scope, current_epoch, required_epoch
            ),
            Self::ActivationHeightBelowMinimumMargin {
                environment,
                current_height,
                activation_height,
                minimum_margin,
                required_min_height,
                scope,
            } => write!(
                f,
                "pqc trust-bundle minimum activation-height policy violation (scope={}, \
                 environment={}, current_height={}, activation_height={}, minimum_margin={}, \
                 required_min_height={}); fail closed — declared activation_height is too \
                 close to current_height for environment {}. Reschedule the bundle with \
                 activation_height >= {} (= current_height + minimum_margin). No fallback to \
                 --p2p-trusted-root.",
                scope,
                environment,
                current_height,
                activation_height,
                minimum_margin,
                required_min_height,
                environment,
                required_min_height
            ),
            Self::RevocationActivationHeightBelowMinimumMargin {
                environment,
                current_height,
                activation_height,
                minimum_margin,
                required_min_height,
                scope,
            } => write!(
                f,
                "pqc trust-bundle scheduled-revocation minimum activation-height policy \
                 violation ({}, environment={}, current_height={}, activation_height={}, \
                 minimum_margin={}, required_min_height={}); fail closed — scheduled \
                 revocation activation_height is too close to current_height for environment \
                 {}. Emergency revocations should be published without activation_height \
                 (immediate effect, preserved by Run 065). No fallback to --p2p-trusted-root.",
                scope,
                environment,
                current_height,
                activation_height,
                minimum_margin,
                required_min_height,
                environment
            ),
        }
    }
}

impl std::error::Error for TrustBundleActivationError {}

impl TrustBundleActivationError {
    /// Returns `true` if this error indicates the activation gate is
    /// future-dated (i.e. the bundle is structurally valid but
    /// declared activation has not yet been reached). Used by the
    /// caller to drive the `qbind_p2p_pqc_trust_bundle_activation_*`
    /// rejected counter family separately from the "no runtime
    /// source available" misconfiguration class.
    pub fn is_future_activation(&self) -> bool {
        matches!(
            self,
            Self::ActivationHeightNotYetReached { .. } | Self::ActivationEpochNotYetReached { .. }
        )
    }
}

/// Outcome of a successful activation check on a bundle/root pair.
/// Carries the resolved (required, current) gauges for the surfaces
/// that care (metrics, logs). Both `*_required` are `None` when no
/// gate is declared.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ActivationCheckOutcome {
    /// Highest declared `activation_height` across the bundle and
    /// any root entry. `None` if no `activation_height` field is set
    /// anywhere on the bundle. Surfaced on
    /// `qbind_p2p_pqc_trust_bundle_activation_height_required`.
    pub required_height: Option<u64>,
    /// Highest declared `activation_epoch` across the bundle and any
    /// root entry. `None` if no `activation_epoch` is set anywhere.
    /// Surfaced on
    /// `qbind_p2p_pqc_trust_bundle_activation_epoch_required`.
    pub required_epoch: Option<u64>,
    /// Echoed back from the supplied [`ActivationContext`] for
    /// observability — surfaced on
    /// `qbind_p2p_pqc_trust_bundle_activation_height_current` /
    /// `_epoch_current`. `None` means "runtime source not supplied
    /// in this call and no activation gate consulted it".
    pub current_height: Option<u64>,
    pub current_epoch: Option<u64>,
}

/// Evaluate the activation gate on a [`TrustBundle`].
///
/// The supplied `bundle` is expected to have already been validated
/// for schema / environment / chain_id / window / revocation /
/// signature (see [`TrustBundle::validate_at_with_signing_keys_and_chain_id`]).
/// This call performs ONLY the activation-gating step.
///
/// Returns `Ok(ActivationCheckOutcome)` if all declared gates are
/// satisfied (or no gates are declared at all). Returns
/// `Err(TrustBundleActivationError)` on any future-dated or
/// runtime-source-unavailable gate; the caller MUST fail closed and
/// MUST NOT advance sequence persistence or merge the bundle's roots.
pub fn check_bundle_activation(
    bundle: &TrustBundle,
    ctx: ActivationContext,
) -> Result<ActivationCheckOutcome, TrustBundleActivationError> {
    let mut required_height: Option<u64> = None;
    let mut required_epoch: Option<u64> = None;

    // Bundle-level gates first (the wider scope).
    if let Some(req) = bundle.activation_height {
        required_height = Some(req);
        match ctx.current_height {
            None => {
                return Err(TrustBundleActivationError::CurrentHeightUnavailable {
                    required_height: req,
                    scope: ActivationScope::Bundle,
                })
            }
            Some(cur) if cur < req => {
                return Err(TrustBundleActivationError::ActivationHeightNotYetReached {
                    current_height: cur,
                    required_height: req,
                    scope: ActivationScope::Bundle,
                })
            }
            Some(_) => { /* satisfied */ }
        }
    }
    if let Some(req) = bundle.activation_epoch {
        required_epoch = Some(req);
        match ctx.current_epoch {
            None => {
                return Err(TrustBundleActivationError::CurrentEpochUnavailable {
                    required_epoch: req,
                    scope: ActivationScope::Bundle,
                })
            }
            Some(cur) if cur < req => {
                return Err(TrustBundleActivationError::ActivationEpochNotYetReached {
                    current_epoch: cur,
                    required_epoch: req,
                    scope: ActivationScope::Bundle,
                })
            }
            Some(_) => { /* satisfied */ }
        }
    }

    // Per-root gates. We only consider roots that the bundle layer
    // would otherwise admit (status=Active); other roots are
    // already filtered out by `validate_at_*` so their activation
    // fields are advisory-only and not enforced (mirrors the
    // existing pattern for `not_before`/`not_after`, which is only
    // enforced on Active roots).
    for r in &bundle.roots {
        if !root_is_active_candidate(r) {
            continue;
        }
        if let Some(req) = r.activation_height {
            required_height = Some(required_height.map_or(req, |x| x.max(req)));
            match ctx.current_height {
                None => {
                    return Err(TrustBundleActivationError::CurrentHeightUnavailable {
                        required_height: req,
                        scope: ActivationScope::Root(r.root_id.clone()),
                    })
                }
                Some(cur) if cur < req => {
                    return Err(TrustBundleActivationError::ActivationHeightNotYetReached {
                        current_height: cur,
                        required_height: req,
                        scope: ActivationScope::Root(r.root_id.clone()),
                    })
                }
                Some(_) => {}
            }
        }
        if let Some(req) = r.activation_epoch {
            required_epoch = Some(required_epoch.map_or(req, |x| x.max(req)));
            match ctx.current_epoch {
                None => {
                    return Err(TrustBundleActivationError::CurrentEpochUnavailable {
                        required_epoch: req,
                        scope: ActivationScope::Root(r.root_id.clone()),
                    })
                }
                Some(cur) if cur < req => {
                    return Err(TrustBundleActivationError::ActivationEpochNotYetReached {
                        current_epoch: cur,
                        required_epoch: req,
                        scope: ActivationScope::Root(r.root_id.clone()),
                    })
                }
                Some(_) => {}
            }
        }
    }

    Ok(ActivationCheckOutcome {
        required_height,
        required_epoch,
        current_height: ctx.current_height,
        current_epoch: ctx.current_epoch,
    })
}

/// A root is "an active candidate" if its `status` is `Active`. Other
/// statuses are filtered out by `validate_at_*` before reaching the
/// trust set; their per-root activation gates are therefore not
/// enforced because they are not eligible to be merged anyway.
fn root_is_active_candidate(r: &TrustBundleRoot) -> bool {
    use crate::pqc_trust_bundle::RootStatus;
    matches!(r.status, RootStatus::Active)
}

/// Run 065: enforce the per-environment minimum activation-height
/// policy on a structurally-validated, signature-verified bundle.
///
/// Scope of enforcement (only triggers when `activation_height` is
/// **declared** AND is in the half-open window
/// `[current_height, current_height + minimum_margin)`; absent
/// fields and already-past activations preserve Run 050/052/062
/// immediate semantics):
///
/// * Bundle-level [`TrustBundle::activation_height`].
/// * Per-active-root [`TrustBundleRoot::activation_height`] on roots
///   whose `status == Active` (other statuses are filtered out by
///   `validate_at_*` and never reach the live trust set, mirroring
///   [`check_bundle_activation`]).
/// * Per-entry **scheduled-revocation** `activation_height`. An
///   immediate revocation (`activation_height = None`) is NOT
///   constrained — that path is reserved for emergency response
///   (Run 050/052 semantics preserved).
///
/// Rationale for the half-open window: a declared `activation_height`
/// strictly less than `current_height` is an **already-active**
/// schedule that was published earlier (operator was diligent at
/// publication time and `current_height` has since advanced). Run 065
/// MUST NOT retroactively reject such bundles — that would prevent a
/// fresh node from rejoining the network with a snapshot whose
/// `current_height` has crossed the activation point. The policy
/// therefore fires only on bundles that are **active now or
/// activating imminently** (`activation_height >= current_height`)
/// AND whose activation distance is **shorter than the per-
/// environment margin**. This composes cleanly with Run 057 future-
/// height gating: bundles further in the future than the margin
/// reach Run 057's "not yet reached" path, not Run 065's policy
/// rejection.
///
/// Returns `Ok(())` when:
///   * the environment's minimum margin is zero (DevNet today),
///   * the bundle/roots/revocations declare no `activation_height`,
///   * every declared `activation_height` is either strictly less
///     than `current_height` (already effective in the past) or at
///     least `current_height + margin` (sufficiently future-dated).
///
/// Returns `Err(TrustBundleActivationError::ActivationHeightBelowMinimumMargin)`
/// on a too-soon bundle/root, or
/// `Err(TrustBundleActivationError::RevocationActivationHeightBelowMinimumMargin)`
/// on a too-soon scheduled-revocation entry. The caller MUST fail
/// closed before sequence persistence and root merge.
///
/// `current_height = None` means "no runtime height source available
/// at all". Under that context this check returns `Ok(())` because
/// [`check_bundle_activation`] has already rejected any bundle that
/// declares a gate which depends on an unavailable runtime source —
/// the policy layer never receives such bundles. Callers that supply
/// `Some(_)` get the full Run 065 policy check.
pub fn check_min_activation_height_policy(
    bundle: &TrustBundle,
    env: TrustBundleEnvironment,
    current_height: Option<u64>,
) -> Result<(), TrustBundleActivationError> {
    let policy = ActivationPolicy::for_environment(env);
    let margin = policy.minimum_activation_margin;

    // Fast path: zero margin (DevNet) — by construction every
    // declared activation_height satisfies the margin. We still
    // return Ok(()) explicitly so the caller can rely on the
    // function being side-effect-free.
    if margin == 0 {
        return Ok(());
    }

    // If no runtime height source is supplied, defer to
    // `check_bundle_activation`, which has already rejected any
    // bundle/root that declares a height gate against a missing
    // source. We do not invent a policy decision here.
    let cur = match current_height {
        Some(h) => h,
        None => return Ok(()),
    };

    // `required_min_height = current_height + margin`, saturating on
    // overflow so a near-`u64::MAX` `current_height` cannot wrap and
    // silently turn a real-world "too-soon" check into "no
    // requirement" (defence in depth — `current_height` near
    // `u64::MAX` is not reachable today but we refuse to rely on
    // that for correctness).
    let required_min_height = cur.saturating_add(margin);

    // Helper: a declared activation_height violates the policy iff
    // it falls in the half-open window
    // `[current_height, required_min_height)`.
    let violates = |act: u64| act >= cur && act < required_min_height;

    // Bundle-level gate.
    if let Some(act) = bundle.activation_height {
        if violates(act) {
            return Err(
                TrustBundleActivationError::ActivationHeightBelowMinimumMargin {
                    environment: env,
                    current_height: cur,
                    activation_height: act,
                    minimum_margin: margin,
                    required_min_height,
                    scope: ActivationScope::Bundle,
                },
            );
        }
    }

    // Per-active-root gates.
    for r in &bundle.roots {
        if !root_is_active_candidate(r) {
            continue;
        }
        if let Some(act) = r.activation_height {
            if violates(act) {
                return Err(
                    TrustBundleActivationError::ActivationHeightBelowMinimumMargin {
                        environment: env,
                        current_height: cur,
                        activation_height: act,
                        minimum_margin: margin,
                        required_min_height,
                        scope: ActivationScope::Root(r.root_id.clone()),
                    },
                );
            }
        }
    }

    // Per-entry scheduled-revocation gates. Immediate revocations
    // (activation_height = None) intentionally skipped: the emergency
    // revocation path remains immediate. See module docs.
    for rev in &bundle.revocations {
        if let Some(act) = rev.activation_height {
            if violates(act) {
                return Err(
                    TrustBundleActivationError::RevocationActivationHeightBelowMinimumMargin {
                        environment: env,
                        current_height: cur,
                        activation_height: act,
                        minimum_margin: margin,
                        required_min_height,
                        scope: RevocationScope {
                            root_id: rev.root_id.clone(),
                            leaf_fingerprint: rev.leaf_cert_fingerprint.clone(),
                        },
                    },
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqc_devnet_helper::mint_devnet_root;
    use crate::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
    use crate::pqc_trust_bundle::{
        build_helper_bundle, HelperBundleMode, RootStatus, TrustBundle, TrustBundleRoot,
    };

    fn hex_lower(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", x);
        }
        s
    }

    fn fresh_bundle() -> TrustBundle {
        let r = mint_devnet_root().expect("mint root");
        let id = hex_lower(&r.root_key_id);
        let pk = hex_lower(&r.root_pk);
        build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0)
    }

    #[test]
    fn missing_activation_fields_accepted_with_no_runtime_source() {
        let b = fresh_bundle();
        let out = check_bundle_activation(&b, ActivationContext::unavailable()).expect("accepted");
        assert_eq!(out.required_height, None);
        assert_eq!(out.required_epoch, None);
        assert_eq!(out.current_height, None);
        assert_eq!(out.current_epoch, None);
    }

    #[test]
    fn missing_activation_fields_accepted_with_height_source() {
        let b = fresh_bundle();
        let out =
            check_bundle_activation(&b, ActivationContext::height_only(42)).expect("accepted");
        assert_eq!(out.required_height, None);
        assert_eq!(out.current_height, Some(42));
    }

    #[test]
    fn bundle_activation_height_satisfied_accepted() {
        let mut b = fresh_bundle();
        b.activation_height = Some(100);
        let out =
            check_bundle_activation(&b, ActivationContext::height_only(200)).expect("accepted");
        assert_eq!(out.required_height, Some(100));
        assert_eq!(out.current_height, Some(200));
    }

    #[test]
    fn bundle_activation_height_equal_accepted_inclusive() {
        let mut b = fresh_bundle();
        b.activation_height = Some(100);
        let out = check_bundle_activation(&b, ActivationContext::height_only(100))
            .expect("equal == active (inclusive)");
        assert_eq!(out.required_height, Some(100));
        assert_eq!(out.current_height, Some(100));
    }

    #[test]
    fn bundle_activation_height_future_rejected() {
        let mut b = fresh_bundle();
        b.activation_height = Some(100);
        let err = check_bundle_activation(&b, ActivationContext::height_only(99)).unwrap_err();
        match err {
            TrustBundleActivationError::ActivationHeightNotYetReached {
                current_height,
                required_height,
                ref scope,
            } => {
                assert_eq!(current_height, 99);
                assert_eq!(required_height, 100);
                assert!(matches!(scope, ActivationScope::Bundle));
            }
            other => panic!("expected ActivationHeightNotYetReached, got {:?}", other),
        }
        assert!(err.is_future_activation());
    }

    #[test]
    fn bundle_activation_height_requires_runtime_source() {
        let mut b = fresh_bundle();
        b.activation_height = Some(100);
        let err = check_bundle_activation(&b, ActivationContext::unavailable()).unwrap_err();
        assert!(matches!(
            err,
            TrustBundleActivationError::CurrentHeightUnavailable {
                required_height: 100,
                scope: ActivationScope::Bundle,
            }
        ));
        assert!(!err.is_future_activation());
    }

    #[test]
    fn bundle_activation_epoch_future_rejected_when_epoch_source_present() {
        let mut b = fresh_bundle();
        b.activation_epoch = Some(7);
        let ctx = ActivationContext {
            current_height: Some(0),
            current_epoch: Some(3),
        };
        let err = check_bundle_activation(&b, ctx).unwrap_err();
        match err {
            TrustBundleActivationError::ActivationEpochNotYetReached {
                current_epoch,
                required_epoch,
                scope,
            } => {
                assert_eq!(current_epoch, 3);
                assert_eq!(required_epoch, 7);
                assert!(matches!(scope, ActivationScope::Bundle));
            }
            other => panic!("expected ActivationEpochNotYetReached, got {:?}", other),
        }
    }

    #[test]
    fn bundle_activation_epoch_requires_runtime_source_today() {
        let mut b = fresh_bundle();
        b.activation_epoch = Some(7);
        // Even with a height source, an epoch source is required when
        // the bundle declares an epoch gate. This is what makes
        // "epoch gating is deferred" honest at the binary boundary.
        let err = check_bundle_activation(&b, ActivationContext::height_only(123_456)).unwrap_err();
        assert!(matches!(
            err,
            TrustBundleActivationError::CurrentEpochUnavailable {
                required_epoch: 7,
                scope: ActivationScope::Bundle,
            }
        ));
    }

    #[test]
    fn both_gates_satisfied_accepted() {
        let mut b = fresh_bundle();
        b.activation_height = Some(50);
        b.activation_epoch = Some(2);
        let ctx = ActivationContext {
            current_height: Some(60),
            current_epoch: Some(2),
        };
        let out = check_bundle_activation(&b, ctx).expect("both satisfied");
        assert_eq!(out.required_height, Some(50));
        assert_eq!(out.required_epoch, Some(2));
        assert_eq!(out.current_height, Some(60));
        assert_eq!(out.current_epoch, Some(2));
    }

    #[test]
    fn both_gates_one_future_rejected() {
        let mut b = fresh_bundle();
        b.activation_height = Some(50);
        b.activation_epoch = Some(2);
        let ctx = ActivationContext {
            current_height: Some(60), // height satisfied
            current_epoch: Some(1),   // epoch NOT satisfied
        };
        let err = check_bundle_activation(&b, ctx).unwrap_err();
        assert!(matches!(
            err,
            TrustBundleActivationError::ActivationEpochNotYetReached { .. }
        ));
    }

    #[test]
    fn root_level_activation_height_future_rejected() {
        let mut b = fresh_bundle();
        b.roots[0].activation_height = Some(1_000);
        let err = check_bundle_activation(&b, ActivationContext::height_only(999)).unwrap_err();
        match err {
            TrustBundleActivationError::ActivationHeightNotYetReached {
                current_height,
                required_height,
                scope,
            } => {
                assert_eq!(current_height, 999);
                assert_eq!(required_height, 1_000);
                match scope {
                    ActivationScope::Root(id) => {
                        assert_eq!(id, b.roots[0].root_id);
                    }
                    other => panic!("expected ActivationScope::Root, got {:?}", other),
                }
            }
            other => panic!("expected ActivationHeightNotYetReached, got {:?}", other),
        }
    }

    #[test]
    fn root_level_activation_only_enforced_on_active_status() {
        // A Retired root with a future activation_height is filtered
        // out by validate_at, so we don't enforce its activation gate
        // (mirrors not_before/not_after behaviour). The bundle-level
        // gate (None here) is the only thing that drives the result,
        // so the check passes despite the future root gate.
        let mut b = fresh_bundle();
        b.roots[0].status = RootStatus::Retired;
        b.roots[0].activation_height = Some(u64::MAX);
        let _ = check_bundle_activation(&b, ActivationContext::height_only(0))
            .expect("retired root activation field is advisory-only");
    }

    #[test]
    fn required_height_is_max_across_bundle_and_active_roots() {
        let r = mint_devnet_root().expect("mint root");
        let r2 = mint_devnet_root().expect("mint root2");
        let mut b = fresh_bundle();
        b.activation_height = Some(10);
        b.roots[0].activation_height = Some(20);
        b.roots.push(TrustBundleRoot {
            root_id: hex_lower(&r2.root_key_id),
            suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
            root_pk: hex_lower(&r2.root_pk),
            status: RootStatus::Active,
            not_before: 0,
            not_after: u64::MAX,
            activation_epoch: None,
            activation_height: Some(30),
        });
        let _ = r;
        let out = check_bundle_activation(&b, ActivationContext::height_only(100))
            .expect("all gates satisfied");
        assert_eq!(out.required_height, Some(30));
    }

    #[test]
    fn display_error_messages_carry_fail_closed_phrase() {
        let mut b = fresh_bundle();
        b.activation_height = Some(100);
        let err = check_bundle_activation(&b, ActivationContext::height_only(0)).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("activation height not yet reached"),
            "msg = {}",
            msg
        );
        assert!(msg.contains("No fallback to --p2p-trusted-root"));
    }

    // -----------------------------------------------------------------
    // Run 065: per-environment minimum activation-height policy tests.
    // -----------------------------------------------------------------

    use crate::pqc_trust_bundle::TrustBundleRevocation;

    fn testnet_bundle() -> TrustBundle {
        let mut b = fresh_bundle();
        b.environment = TrustBundleEnvironment::Testnet;
        b
    }

    fn mainnet_bundle() -> TrustBundle {
        let mut b = fresh_bundle();
        b.environment = TrustBundleEnvironment::Mainnet;
        b
    }

    /// Constants are deterministic and have the documented relative
    /// ordering: DevNet=0 < TestNet < MainNet. Pinning this prevents
    /// a future edit from accidentally widening DevNet or relaxing
    /// MainNet without an accompanying contradiction.md update.
    #[test]
    fn run065_policy_constants_are_deterministic() {
        assert_eq!(MIN_DEVNET_ACTIVATION_MARGIN, 0);
        assert_eq!(MIN_TESTNET_ACTIVATION_MARGIN, 8);
        assert_eq!(MIN_MAINNET_ACTIVATION_MARGIN, 32);
        assert!(MIN_DEVNET_ACTIVATION_MARGIN < MIN_TESTNET_ACTIVATION_MARGIN);
        assert!(MIN_TESTNET_ACTIVATION_MARGIN < MIN_MAINNET_ACTIVATION_MARGIN);
        assert_eq!(
            minimum_activation_margin_for_environment(TrustBundleEnvironment::Devnet),
            0
        );
        assert_eq!(
            minimum_activation_margin_for_environment(TrustBundleEnvironment::Testnet),
            8
        );
        assert_eq!(
            minimum_activation_margin_for_environment(TrustBundleEnvironment::Mainnet),
            32
        );
        assert_eq!(
            ActivationPolicy::for_environment(TrustBundleEnvironment::Mainnet)
                .minimum_activation_margin,
            32
        );
    }

    /// DevNet preserves Run 050–064 immediate-cutover behaviour:
    /// `activation_height = 0` against `current_height = 0` is
    /// accepted (no margin requirement on DevNet).
    #[test]
    fn run065_devnet_activation_height_zero_accepted() {
        let mut b = fresh_bundle();
        b.activation_height = Some(0);
        check_min_activation_height_policy(&b, TrustBundleEnvironment::Devnet, Some(0))
            .expect("DevNet accepts activation_height = 0");
    }

    /// DevNet preserves immediate cutover even when bundle declares
    /// `activation_height = current_height` (the path that Run 057
    /// already accepts under "inclusive" semantics).
    #[test]
    fn run065_devnet_activation_height_equals_current_accepted() {
        let mut b = fresh_bundle();
        b.activation_height = Some(100);
        check_min_activation_height_policy(&b, TrustBundleEnvironment::Devnet, Some(100))
            .expect("DevNet accepts immediate cutover");
    }

    /// A bundle that declares no `activation_height` is unaffected by
    /// the Run 065 policy (preserves Run 050/052/062 immediate
    /// semantics — emergency response path).
    #[test]
    fn run065_missing_activation_height_unaffected_on_mainnet() {
        let b = mainnet_bundle();
        assert!(b.activation_height.is_none());
        check_min_activation_height_policy(&b, TrustBundleEnvironment::Mainnet, Some(0))
            .expect("no declared activation_height -> no policy fire");
        check_min_activation_height_policy(&b, TrustBundleEnvironment::Mainnet, Some(1_000_000))
            .expect("no declared activation_height -> no policy fire");
    }

    /// TestNet: a bundle whose `activation_height` falls strictly
    /// inside `[current_height, current_height + margin)` is
    /// rejected with the scoped error.
    #[test]
    fn run065_testnet_activation_height_below_margin_rejected() {
        let mut b = testnet_bundle();
        // current = 0, margin = 8, activation = 7 -> 0 <= 7 < 8.
        b.activation_height = Some(MIN_TESTNET_ACTIVATION_MARGIN - 1);
        let err = check_min_activation_height_policy(&b, TrustBundleEnvironment::Testnet, Some(0))
            .unwrap_err();
        match err {
            TrustBundleActivationError::ActivationHeightBelowMinimumMargin {
                environment,
                current_height,
                activation_height,
                minimum_margin,
                required_min_height,
                ref scope,
            } => {
                assert_eq!(environment, TrustBundleEnvironment::Testnet);
                assert_eq!(current_height, 0);
                assert_eq!(activation_height, 7);
                assert_eq!(minimum_margin, MIN_TESTNET_ACTIVATION_MARGIN);
                assert_eq!(required_min_height, MIN_TESTNET_ACTIVATION_MARGIN);
                assert!(matches!(scope, ActivationScope::Bundle));
            }
            other => panic!(
                "expected ActivationHeightBelowMinimumMargin, got {:?}",
                other
            ),
        }
        let msg = format!("{}", err);
        assert!(msg.contains("minimum activation-height policy violation"));
        assert!(msg.contains("No fallback to --p2p-trusted-root"));
        assert!(!err.is_future_activation());
    }

    /// TestNet: immediate cutover (`activation_height == current_height`)
    /// is rejected. This is the worst case the policy is designed to
    /// block — a production-honest TestNet operator cannot ship a
    /// bundle that activates the same block it's published.
    #[test]
    fn run065_testnet_immediate_cutover_rejected() {
        let mut b = testnet_bundle();
        b.activation_height = Some(100);
        let err =
            check_min_activation_height_policy(&b, TrustBundleEnvironment::Testnet, Some(100))
                .unwrap_err();
        assert!(matches!(
            err,
            TrustBundleActivationError::ActivationHeightBelowMinimumMargin {
                activation_height: 100,
                current_height: 100,
                ..
            }
        ));
    }

    /// TestNet: activation_height exactly at the required minimum
    /// margin is ACCEPTED. Inclusive upper boundary on
    /// `[current_height, current_height + margin)`: the next height
    /// (current + margin) is the smallest permissible scheduling.
    #[test]
    fn run065_testnet_activation_height_at_margin_accepted() {
        let mut b = testnet_bundle();
        b.activation_height = Some(MIN_TESTNET_ACTIVATION_MARGIN); // 8
        check_min_activation_height_policy(&b, TrustBundleEnvironment::Testnet, Some(0))
            .expect("activation_height == current + margin (inclusive) is accepted");
    }

    /// TestNet: activation_height comfortably above the margin is
    /// accepted.
    #[test]
    fn run065_testnet_activation_height_above_margin_accepted() {
        let mut b = testnet_bundle();
        b.activation_height = Some(1_000_000);
        check_min_activation_height_policy(&b, TrustBundleEnvironment::Testnet, Some(0))
            .expect("activation_height >> current + margin is accepted");
    }

    /// TestNet: a bundle whose `activation_height` is strictly less
    /// than `current_height` (already-effective, published earlier
    /// when `current_height` was smaller) is NOT retroactively
    /// rejected. This is essential for snapshot-rejoin semantics —
    /// a fresh node rejoining at a high `current_height` must still
    /// be able to load older valid bundles whose activation has
    /// long passed.
    #[test]
    fn run065_testnet_already_effective_bundle_not_retroactively_rejected() {
        let mut b = testnet_bundle();
        b.activation_height = Some(5); // very old, current is now 1000
        check_min_activation_height_policy(&b, TrustBundleEnvironment::Testnet, Some(1000))
            .expect("already-effective bundle (activation_height < current_height) is accepted");
    }

    /// MainNet rejects a bundle inside its (stricter) reject window.
    /// Also proves the constants chain: a value that satisfies
    /// TestNet's 8-block margin is still rejected by MainNet's
    /// 32-block margin.
    #[test]
    fn run065_mainnet_activation_height_below_margin_rejected() {
        let mut b = mainnet_bundle();
        // 10 satisfies TestNet (>= 8) but is in MainNet's [0, 32) window.
        b.activation_height = Some(10);
        let err = check_min_activation_height_policy(&b, TrustBundleEnvironment::Mainnet, Some(0))
            .unwrap_err();
        match err {
            TrustBundleActivationError::ActivationHeightBelowMinimumMargin {
                environment,
                minimum_margin,
                required_min_height,
                ..
            } => {
                assert_eq!(environment, TrustBundleEnvironment::Mainnet);
                assert_eq!(minimum_margin, MIN_MAINNET_ACTIVATION_MARGIN);
                assert_eq!(required_min_height, MIN_MAINNET_ACTIVATION_MARGIN);
            }
            other => panic!(
                "expected ActivationHeightBelowMinimumMargin, got {:?}",
                other
            ),
        }
    }

    /// MainNet accepts activation_height at the (stricter) margin
    /// boundary `current_height + margin`.
    #[test]
    fn run065_mainnet_activation_height_at_margin_accepted() {
        let mut b = mainnet_bundle();
        b.activation_height = Some(MIN_MAINNET_ACTIVATION_MARGIN); // 32
        check_min_activation_height_policy(&b, TrustBundleEnvironment::Mainnet, Some(0))
            .expect("MainNet accepts activation_height == current + margin");
    }

    /// Per-root activation_height is also constrained by the policy
    /// (same enforcement scope as Run 057's `check_bundle_activation`).
    #[test]
    fn run065_root_level_activation_height_below_margin_rejected_on_testnet() {
        let mut b = testnet_bundle();
        b.roots[0].activation_height = Some(1); // in [0, 8)
        let err = check_min_activation_height_policy(&b, TrustBundleEnvironment::Testnet, Some(0))
            .unwrap_err();
        match err {
            TrustBundleActivationError::ActivationHeightBelowMinimumMargin {
                scope: ActivationScope::Root(id),
                ..
            } => {
                assert_eq!(id, b.roots[0].root_id);
            }
            other => panic!("expected Root scope, got {:?}", other),
        }
    }

    /// Per-root activation_height on a non-Active root is advisory-
    /// only (mirrors Run 057). Even an `activation_height` inside
    /// the MainNet reject window on a Retired root does not fire
    /// the Run 065 policy.
    #[test]
    fn run065_retired_root_activation_height_not_enforced() {
        use crate::pqc_trust_bundle::RootStatus;
        let mut b = mainnet_bundle();
        b.roots[0].status = RootStatus::Retired;
        b.roots[0].activation_height = Some(1); // would fail if Active
        check_min_activation_height_policy(&b, TrustBundleEnvironment::Mainnet, Some(0))
            .expect("retired root activation_height is advisory-only");
    }

    /// Immediate revocation (revocation entry with
    /// `activation_height = None`) is intentionally NOT constrained
    /// by the Run 065 policy — that path is reserved for emergency
    /// response. This test pins that boundary on MainNet, the
    /// strictest environment.
    #[test]
    fn run065_immediate_revocation_preserved_on_mainnet() {
        let mut b = mainnet_bundle();
        b.revocations.push(TrustBundleRevocation {
            root_id: b.roots[0].root_id.clone(),
            leaf_cert_fingerprint: None,
            reason: "compromise".to_string(),
            effective_from: 0,
            activation_height: None, // emergency: immediate
        });
        check_min_activation_height_policy(&b, TrustBundleEnvironment::Mainnet, Some(0))
            .expect("immediate revocation is not subject to the minimum margin policy");
    }

    /// A scheduled revocation entry with `activation_height` inside
    /// the reject window is rejected with the scoped error.
    /// Emergency immediate revocations remain available.
    #[test]
    fn run065_scheduled_revocation_below_margin_rejected_on_mainnet() {
        let mut b = mainnet_bundle();
        let target_root = b.roots[0].root_id.clone();
        b.revocations.push(TrustBundleRevocation {
            root_id: target_root.clone(),
            leaf_cert_fingerprint: Some("aa".repeat(32)),
            reason: "rotation".to_string(),
            effective_from: 0,
            activation_height: Some(10), // in [0, 32)
        });
        let err = check_min_activation_height_policy(&b, TrustBundleEnvironment::Mainnet, Some(0))
            .unwrap_err();
        match err {
            TrustBundleActivationError::RevocationActivationHeightBelowMinimumMargin {
                environment,
                current_height,
                activation_height,
                minimum_margin,
                required_min_height,
                ref scope,
            } => {
                assert_eq!(environment, TrustBundleEnvironment::Mainnet);
                assert_eq!(current_height, 0);
                assert_eq!(activation_height, 10);
                assert_eq!(minimum_margin, MIN_MAINNET_ACTIVATION_MARGIN);
                assert_eq!(required_min_height, MIN_MAINNET_ACTIVATION_MARGIN);
                assert_eq!(scope.root_id, target_root);
                assert!(scope.leaf_fingerprint.is_some());
            }
            other => panic!(
                "expected RevocationActivationHeightBelowMinimumMargin, got {:?}",
                other
            ),
        }
        let msg = format!("{}", err);
        assert!(msg.contains("scheduled-revocation minimum activation-height policy"));
        assert!(msg.contains("Emergency revocations should be published without activation_height"));
        assert!(msg.contains("No fallback to --p2p-trusted-root"));
    }

    /// Already-effective scheduled revocation
    /// (`activation_height < current_height`) is NOT retroactively
    /// rejected — preserves snapshot-rejoin semantics for older
    /// scheduled revocations that have long since activated.
    #[test]
    fn run065_already_effective_scheduled_revocation_not_retroactively_rejected() {
        let mut b = mainnet_bundle();
        b.revocations.push(TrustBundleRevocation {
            root_id: b.roots[0].root_id.clone(),
            leaf_cert_fingerprint: Some("dd".repeat(32)),
            reason: "rotation".to_string(),
            effective_from: 0,
            activation_height: Some(5), // already in the past
        });
        check_min_activation_height_policy(
            &b,
            TrustBundleEnvironment::Mainnet,
            Some(1000),
        )
        .expect(
            "already-effective scheduled revocation (activation_height < current_height) is accepted",
        );
    }

    /// Scheduled revocation activation_height at the margin is
    /// accepted (TestNet, inclusive upper boundary).
    #[test]
    fn run065_scheduled_revocation_at_margin_accepted_on_testnet() {
        let mut b = testnet_bundle();
        b.revocations.push(TrustBundleRevocation {
            root_id: b.roots[0].root_id.clone(),
            leaf_cert_fingerprint: Some("bb".repeat(32)),
            reason: "rotation".to_string(),
            effective_from: 0,
            activation_height: Some(MIN_TESTNET_ACTIVATION_MARGIN), // 8
        });
        check_min_activation_height_policy(&b, TrustBundleEnvironment::Testnet, Some(0))
            .expect("scheduled revocation at margin is accepted");
    }

    /// The policy honours a non-zero `current_height`: the required
    /// minimum is `current_height + margin`. This pins the
    /// `--restore-from-snapshot` use case (Run 057 height source).
    #[test]
    fn run065_required_min_is_current_plus_margin_on_restore() {
        let mut b = testnet_bundle();
        b.activation_height = Some(105); // in [100, 108)
        let err =
            check_min_activation_height_policy(&b, TrustBundleEnvironment::Testnet, Some(100))
                .unwrap_err();
        match err {
            TrustBundleActivationError::ActivationHeightBelowMinimumMargin {
                required_min_height: 108,
                current_height: 100,
                activation_height: 105,
                ..
            } => {}
            other => panic!("expected required_min_height=108, got {:?}", other),
        }
    }

    /// `current_height = None` (Run 057 "unavailable" surface) does
    /// not fire the policy on its own — that decision belongs to
    /// `check_bundle_activation`, which has already rejected any
    /// bundle whose gate depends on a missing source. The policy
    /// layer is silent under this combination.
    #[test]
    fn run065_no_current_height_source_does_not_fire_policy() {
        let mut b = mainnet_bundle();
        b.activation_height = Some(1);
        check_min_activation_height_policy(&b, TrustBundleEnvironment::Mainnet, None)
            .expect("policy is silent when current_height is unavailable");
    }

    /// `current_height` near `u64::MAX` plus a non-zero margin
    /// saturates rather than wrapping — defence in depth against a
    /// future runtime source that could push `current_height` close
    /// to the type's maximum. Without saturation, the policy would
    /// wrap to a near-zero `required_min_height` and silently admit
    /// every activation_height — a critical regression.
    #[test]
    fn run065_required_min_height_saturates_on_overflow() {
        let mut b = mainnet_bundle();
        b.activation_height = Some(u64::MAX); // accepted: equal to saturated required
        check_min_activation_height_policy(&b, TrustBundleEnvironment::Mainnet, Some(u64::MAX))
            .expect("saturating add keeps required_min_height at u64::MAX");

        // u64::MAX - 1 is in [u64::MAX, u64::MAX)? No: u64::MAX-1 < u64::MAX = current,
        // so it falls in the "already-effective" past path and is accepted.
        b.activation_height = Some(u64::MAX - 1);
        check_min_activation_height_policy(&b, TrustBundleEnvironment::Mainnet, Some(u64::MAX))
            .expect("activation < current is already-effective, accepted");
    }
}
