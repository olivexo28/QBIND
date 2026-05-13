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

use crate::pqc_trust_bundle::{TrustBundle, TrustBundleRoot};

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
            Self::CurrentHeightUnavailable { required_height, scope } => write!(
                f,
                "pqc trust-bundle activation height gating requires current_height but no \
                 runtime height source is available (scope={}, required_height={}); fail closed \
                 — runtime height source is needed to evaluate the gate",
                scope, required_height
            ),
            Self::CurrentEpochUnavailable { required_epoch, scope } => write!(
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
            Self::ActivationHeightNotYetReached { .. }
                | Self::ActivationEpochNotYetReached { .. }
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
                return Err(
                    TrustBundleActivationError::ActivationHeightNotYetReached {
                        current_height: cur,
                        required_height: req,
                        scope: ActivationScope::Bundle,
                    },
                )
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
                return Err(
                    TrustBundleActivationError::ActivationEpochNotYetReached {
                        current_epoch: cur,
                        required_epoch: req,
                        scope: ActivationScope::Bundle,
                    },
                )
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
                    return Err(
                        TrustBundleActivationError::ActivationHeightNotYetReached {
                            current_height: cur,
                            required_height: req,
                            scope: ActivationScope::Root(r.root_id.clone()),
                        },
                    )
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
                    return Err(
                        TrustBundleActivationError::ActivationEpochNotYetReached {
                            current_epoch: cur,
                            required_epoch: req,
                            scope: ActivationScope::Root(r.root_id.clone()),
                        },
                    )
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
        let out =
            check_bundle_activation(&b, ActivationContext::unavailable()).expect("accepted");
        assert_eq!(out.required_height, None);
        assert_eq!(out.required_epoch, None);
        assert_eq!(out.current_height, None);
        assert_eq!(out.current_epoch, None);
    }

    #[test]
    fn missing_activation_fields_accepted_with_height_source() {
        let b = fresh_bundle();
        let out = check_bundle_activation(&b, ActivationContext::height_only(42))
            .expect("accepted");
        assert_eq!(out.required_height, None);
        assert_eq!(out.current_height, Some(42));
    }

    #[test]
    fn bundle_activation_height_satisfied_accepted() {
        let mut b = fresh_bundle();
        b.activation_height = Some(100);
        let out = check_bundle_activation(&b, ActivationContext::height_only(200))
            .expect("accepted");
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
        let err = check_bundle_activation(&b, ActivationContext::height_only(123_456))
            .unwrap_err();
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
            current_height: Some(60),  // height satisfied
            current_epoch: Some(1),    // epoch NOT satisfied
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
        let err =
            check_bundle_activation(&b, ActivationContext::height_only(999)).unwrap_err();
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
}