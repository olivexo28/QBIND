//! Run 217 — source/test governance-execution runtime policy arming
//! wiring.
//!
//! Run 215 added the hidden, disabled-by-default governance-execution
//! policy selector (`--p2p-trust-bundle-governance-execution-policy` /
//! `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY`) and seven
//! per-surface preflight wrappers that bind a resolved
//! [`GovernanceExecutionPolicy`] into the Run 213 per-surface routing
//! helpers. Run 216 closed the release-binary selector-parsing evidence.
//! The limitation Run 216 recorded is that the resolved policy was not
//! yet consumed by the long-running runtime configuration paths that
//! construct the reload-check, reload-apply, startup
//! `--p2p-trust-bundle`, SIGHUP, local peer-candidate-check, live inbound
//! `0x05`, and peer-driven drain preflight contexts.
//!
//! Run 217 closes that gap at the **source/test level** by introducing a
//! single typed runtime-config carrier,
//! [`GovernanceExecutionRuntimeArmingConfig`], that:
//!
//! 1. resolves the selected [`GovernanceExecutionPolicy`] from the Run
//!    215 CLI/env resolver
//!    ([`governance_execution_policy_from_cli_or_env`]) — preserving
//!    CLI-over-env precedence and the fail-closed typed parse error for
//!    invalid selector values;
//! 2. carries the resolved policy through the long-running runtime config
//!    (it is `Copy` so it can be embedded in any runtime config struct,
//!    e.g. [`crate::pqc_live_trust_reload::LiveReloadConfig`]); and
//! 3. routes the carried policy into all seven Run 215 per-surface
//!    preflight wrappers.
//!
//! ## Defaults and fail-closed contract
//!
//! * Both selector sources absent ⇒
//!   [`GovernanceExecutionPolicy::Disabled`] (preserves Run 214
//!   compatibility for no-governance-execution payloads).
//! * An empty / unknown selector value (CLI **or** env) is surfaced as a
//!   typed [`GovernanceExecutionPolicySelectorParseError`] — the runtime
//!   config is **never** constructed with a silently-downgraded policy.
//!   The binary fails closed before any runtime mutation.
//! * The carried policy only ever *narrows* what each preflight wrapper
//!   accepts. It cannot enable MainNet peer-driven apply (the peer-driven
//!   drain wrapper refuses MainNet unconditionally), and it cannot make
//!   production / on-chain / MainNet governance execution available — Run
//!   211 has no real engine and fails those closed regardless.
//!
//! ## Live inbound `0x05` limitation (A8)
//!
//! The live inbound `0x05` decode path does not yet thread a
//! per-connection governance-execution policy from its live runtime
//! config; this module exposes the policy injection at the source/test
//! level so the selected policy reaches the Run 213 live inbound `0x05`
//! routing helper and an invalid live `0x05` governance-execution
//! candidate is not propagated, staged, or applied. Wiring the resolved
//! policy into the live `0x05` runtime config is part of the
//! release-binary runtime-arming evidence deferred to **Run 218**.
//!
//! Source/test only. Run 217 captures **no** release-binary evidence;
//! release-binary runtime-arming evidence is deferred to **Run 218**.

use crate::pqc_authority_lifecycle::AuthorityTrustDomain;
use crate::pqc_governance_execution_payload_carrying::{
    parse_optional_governance_execution_sibling_from_json_value, GovernanceExecutionLoadStatus,
    GovernanceExecutionPayloadCarryingDecisionOutcome,
};
use crate::pqc_governance_execution_policy::{
    GovernanceExecutionExpectations, GovernanceExecutionOutcome, GovernanceExecutionPolicy,
};
use crate::pqc_governance_execution_policy_surface::{
    governance_execution_policy_from_cli_or_env,
    preflight_v2_marker_governance_execution_for_live_inbound_0x05,
    preflight_v2_marker_governance_execution_for_local_peer_candidate_check,
    preflight_v2_marker_governance_execution_for_peer_driven_drain,
    preflight_v2_marker_governance_execution_for_reload_apply,
    preflight_v2_marker_governance_execution_for_reload_check,
    preflight_v2_marker_governance_execution_for_sighup,
    preflight_v2_marker_governance_execution_for_startup_p2p_trust_bundle,
    GovernanceExecutionPolicySelectorParseError,
};

// ===========================================================================
// Runtime preflight surface identifier
// ===========================================================================

/// Run 217 — the seven Run 213 / Run 215 production v2 marker-decision
/// preflight surfaces a long-running runtime config arms.
///
/// Used by [`GovernanceExecutionRuntimeArmingConfig::arm_surface`] so a
/// caller (or test) can drive the runtime config through any of the seven
/// per-surface preflight wrappers by name, and by the source-reachability
/// tests to prove the runtime config reaches every representable surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GovernanceExecutionRuntimeSurface {
    /// `--p2p-trust-bundle-reload-check` validation-only preflight.
    ReloadCheck,
    /// `--p2p-trust-bundle-reload-apply-*` mutating preflight.
    ReloadApply,
    /// Startup `--p2p-trust-bundle` mutating preflight.
    StartupP2pTrustBundle,
    /// SIGHUP live trust-bundle reload mutating preflight.
    Sighup,
    /// Local `--p2p-trust-bundle-peer-candidate-check` validation-only
    /// preflight.
    LocalPeerCandidateCheck,
    /// Live inbound `0x05` peer-candidate validation-only preflight
    /// (representable at source/test level only — see module docs).
    LiveInbound0x05,
    /// Run 150 peer-driven apply drain coordinator preflight (MainNet
    /// refused unconditionally).
    PeerDrivenDrain,
}

impl GovernanceExecutionRuntimeSurface {
    /// Stable short tag for operator logs and tests.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::ReloadCheck => "reload-check",
            Self::ReloadApply => "reload-apply",
            Self::StartupP2pTrustBundle => "startup-p2p-trust-bundle",
            Self::Sighup => "sighup",
            Self::LocalPeerCandidateCheck => "local-peer-candidate-check",
            Self::LiveInbound0x05 => "live-inbound-0x05",
            Self::PeerDrivenDrain => "peer-driven-drain",
        }
    }

    /// The seven surfaces in canonical order. Useful for tests that prove
    /// the runtime config reaches every representable preflight wrapper.
    pub const ALL: [GovernanceExecutionRuntimeSurface; 7] = [
        Self::ReloadCheck,
        Self::ReloadApply,
        Self::StartupP2pTrustBundle,
        Self::Sighup,
        Self::LocalPeerCandidateCheck,
        Self::LiveInbound0x05,
        Self::PeerDrivenDrain,
    ];
}

// ===========================================================================
// Runtime-arming config
// ===========================================================================

/// Run 217 — typed runtime-config carrier for the resolved
/// governance-execution policy.
///
/// This is the single source/test wiring point that bridges the Run 215
/// selector resolver to the long-running runtime preflight contexts. It
/// is intentionally `Copy` + small so it can be embedded directly in any
/// runtime config struct (for example
/// [`crate::pqc_live_trust_reload::LiveReloadConfig::governance_execution_policy`])
/// without restructuring those configs.
///
/// The default is [`GovernanceExecutionPolicy::Disabled`], preserving the
/// pre-Run-217 behaviour bit-for-bit: an absent selector arms `Disabled`,
/// under which an absent governance-execution carrier is accepted as a
/// legacy no-governance-execution payload and a present carrier is still
/// rejected as governance-execution-required-but-disabled by the Run 213
/// routing helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GovernanceExecutionRuntimeArmingConfig {
    governance_execution_policy: GovernanceExecutionPolicy,
}

impl Default for GovernanceExecutionRuntimeArmingConfig {
    fn default() -> Self {
        Self {
            governance_execution_policy: GovernanceExecutionPolicy::Disabled,
        }
    }
}

impl GovernanceExecutionRuntimeArmingConfig {
    /// Run 217 — the fail-closed default runtime arming: an absent
    /// selector resolves to [`GovernanceExecutionPolicy::Disabled`].
    pub const fn disabled() -> Self {
        Self {
            governance_execution_policy: GovernanceExecutionPolicy::Disabled,
        }
    }

    /// Run 217 — build a runtime arming config around an already-resolved
    /// policy (for callers that resolved the selector elsewhere, e.g. a
    /// runtime config that stores the resolved policy directly).
    pub const fn with_policy(policy: GovernanceExecutionPolicy) -> Self {
        Self {
            governance_execution_policy: policy,
        }
    }

    /// Run 217 — resolve the runtime arming config from the Run 215
    /// CLI/env selector.
    ///
    /// Precedence (Run 215): the CLI value wins when present; otherwise
    /// the `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY` env var is
    /// consulted; both absent resolves to
    /// [`GovernanceExecutionPolicy::Disabled`].
    ///
    /// An empty / unknown selector value from either source is propagated
    /// as a typed [`GovernanceExecutionPolicySelectorParseError`] — the
    /// runtime config is **never** constructed with a silently-downgraded
    /// policy. The binary surfaces this as a fail-closed startup/preflight
    /// error before any runtime mutation.
    pub fn from_cli_or_env(
        cli_value: Option<&str>,
    ) -> Result<Self, GovernanceExecutionPolicySelectorParseError> {
        Ok(Self::with_policy(governance_execution_policy_from_cli_or_env(
            cli_value,
        )?))
    }

    /// The resolved [`GovernanceExecutionPolicy`] this runtime config
    /// arms.
    pub const fn governance_execution_policy(&self) -> GovernanceExecutionPolicy {
        self.governance_execution_policy
    }

    /// `true` iff the armed policy is the default
    /// [`GovernanceExecutionPolicy::Disabled`].
    pub fn is_disabled(&self) -> bool {
        matches!(
            self.governance_execution_policy,
            GovernanceExecutionPolicy::Disabled
        )
    }

    // -----------------------------------------------------------------------
    // Per-surface preflight wrappers — inject the runtime-config policy
    // into each of the seven Run 215 per-surface preflight wrappers.
    // -----------------------------------------------------------------------

    /// Run 217 — drive the `--p2p-trust-bundle-reload-check`
    /// validation-only preflight under the armed policy. The caller MUST
    /// drop the returned outcome (no marker write, no sequence advance, no
    /// live trust swap, no session eviction, no Run 070 call).
    pub fn preflight_reload_check(
        &self,
        trust_domain: &AuthorityTrustDomain,
        expectations: &GovernanceExecutionExpectations,
        loaded: &GovernanceExecutionLoadStatus,
    ) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
        preflight_v2_marker_governance_execution_for_reload_check(
            trust_domain,
            expectations,
            self.governance_execution_policy,
            loaded,
        )
    }

    /// Run 217 — drive the `--p2p-trust-bundle-reload-apply-*` mutating
    /// preflight under the armed policy. A reject outcome MUST short
    /// circuit BEFORE any mutation; an accept outcome continues to honor
    /// sequence-before-marker ordering AFTER acceptance.
    pub fn preflight_reload_apply(
        &self,
        trust_domain: &AuthorityTrustDomain,
        expectations: &GovernanceExecutionExpectations,
        loaded: &GovernanceExecutionLoadStatus,
    ) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
        preflight_v2_marker_governance_execution_for_reload_apply(
            trust_domain,
            expectations,
            self.governance_execution_policy,
            loaded,
        )
    }

    /// Run 217 — drive the startup `--p2p-trust-bundle` mutating preflight
    /// under the armed policy.
    pub fn preflight_startup_p2p_trust_bundle(
        &self,
        trust_domain: &AuthorityTrustDomain,
        expectations: &GovernanceExecutionExpectations,
        loaded: &GovernanceExecutionLoadStatus,
    ) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
        preflight_v2_marker_governance_execution_for_startup_p2p_trust_bundle(
            trust_domain,
            expectations,
            self.governance_execution_policy,
            loaded,
        )
    }

    /// Run 217 — drive the SIGHUP live trust-bundle reload mutating
    /// preflight under the armed policy.
    pub fn preflight_sighup(
        &self,
        trust_domain: &AuthorityTrustDomain,
        expectations: &GovernanceExecutionExpectations,
        loaded: &GovernanceExecutionLoadStatus,
    ) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
        preflight_v2_marker_governance_execution_for_sighup(
            trust_domain,
            expectations,
            self.governance_execution_policy,
            loaded,
        )
    }

    /// Run 217 — drive the local `--p2p-trust-bundle-peer-candidate-check`
    /// validation-only preflight under the armed policy.
    pub fn preflight_local_peer_candidate_check(
        &self,
        trust_domain: &AuthorityTrustDomain,
        expectations: &GovernanceExecutionExpectations,
        loaded: &GovernanceExecutionLoadStatus,
    ) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
        preflight_v2_marker_governance_execution_for_local_peer_candidate_check(
            trust_domain,
            expectations,
            self.governance_execution_policy,
            loaded,
        )
    }

    /// Run 217 — drive the live inbound `0x05` peer-candidate
    /// validation-only preflight under the armed policy.
    ///
    /// **Live-config limitation (A8):** the live inbound `0x05` runtime
    /// path does not yet thread a per-connection governance-execution
    /// policy from its live config; this wrapper exposes the policy
    /// injection at the source/test level so the armed policy reaches the
    /// Run 213 live inbound `0x05` routing helper, and an invalid live
    /// `0x05` governance-execution candidate is not propagated, staged, or
    /// applied. Wiring the armed policy into the live `0x05` runtime
    /// config is part of the release-binary runtime-arming evidence
    /// deferred to Run 218.
    pub fn preflight_live_inbound_0x05(
        &self,
        trust_domain: &AuthorityTrustDomain,
        expectations: &GovernanceExecutionExpectations,
        loaded: &GovernanceExecutionLoadStatus,
    ) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
        preflight_v2_marker_governance_execution_for_live_inbound_0x05(
            trust_domain,
            expectations,
            self.governance_execution_policy,
            loaded,
        )
    }

    /// Run 217 — drive the Run 150 peer-driven apply drain coordinator
    /// preflight under the armed policy.
    ///
    /// **MainNet refusal preserved.** The underlying Run 213 routing
    /// helper refuses MainNet peer-driven apply unconditionally, even with
    /// `MainnetGovernanceRequired` and fully-valid fixture governance
    /// material. The armed policy cannot weaken this refusal.
    pub fn preflight_peer_driven_drain(
        &self,
        trust_domain: &AuthorityTrustDomain,
        expectations: &GovernanceExecutionExpectations,
        loaded: &GovernanceExecutionLoadStatus,
    ) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
        preflight_v2_marker_governance_execution_for_peer_driven_drain(
            trust_domain,
            expectations,
            self.governance_execution_policy,
            loaded,
        )
    }

    /// Run 217 — drive the named runtime preflight surface under the armed
    /// policy. Dispatches to the matching per-surface preflight wrapper so
    /// a caller (or source-reachability test) can prove the runtime config
    /// reaches every representable surface from a single entry point.
    pub fn arm_surface(
        &self,
        surface: GovernanceExecutionRuntimeSurface,
        trust_domain: &AuthorityTrustDomain,
        expectations: &GovernanceExecutionExpectations,
        loaded: &GovernanceExecutionLoadStatus,
    ) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
        match surface {
            GovernanceExecutionRuntimeSurface::ReloadCheck => {
                self.preflight_reload_check(trust_domain, expectations, loaded)
            }
            GovernanceExecutionRuntimeSurface::ReloadApply => {
                self.preflight_reload_apply(trust_domain, expectations, loaded)
            }
            GovernanceExecutionRuntimeSurface::StartupP2pTrustBundle => {
                self.preflight_startup_p2p_trust_bundle(trust_domain, expectations, loaded)
            }
            GovernanceExecutionRuntimeSurface::Sighup => {
                self.preflight_sighup(trust_domain, expectations, loaded)
            }
            GovernanceExecutionRuntimeSurface::LocalPeerCandidateCheck => {
                self.preflight_local_peer_candidate_check(trust_domain, expectations, loaded)
            }
            GovernanceExecutionRuntimeSurface::LiveInbound0x05 => {
                self.preflight_live_inbound_0x05(trust_domain, expectations, loaded)
            }
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain => {
                self.preflight_peer_driven_drain(trust_domain, expectations, loaded)
            }
        }
    }
}

// ===========================================================================
// Run 220 — runtime consumption of the arming outcome
// ===========================================================================

/// Run 220 — typed consumption decision a long-running runtime call site
/// derives from a Run 217 [`GovernanceExecutionPayloadCarryingDecisionOutcome`].
///
/// Run 217 wired the resolved policy into the seven per-surface preflight
/// wrappers, but the long-running runtime call sites (`main.rs` reload-check
/// / reload-apply / startup `--p2p-trust-bundle` / local
/// peer-candidate-check, and the `pqc_live_trust_reload.rs` SIGHUP hook)
/// **discarded** the returned outcome (`let _outcome = arming.arm_surface(..)`)
/// and forced [`GovernanceExecutionLoadStatus::Absent`]. Run 220 closes that
/// gap at the source/test level: a runtime call site now collapses the
/// outcome into this decision and **must act on it** — proceeding only on
/// `Proceed*`, and failing closed BEFORE any mutation on
/// [`Self::FailClosed`].
///
/// The three variants partition the Run 213 outcome space exactly:
///
/// * [`Self::ProceedLegacyBypass`] — the policy was
///   [`GovernanceExecutionPolicy::Disabled`] and the carrier was absent
///   ([`GovernanceExecutionPayloadCarryingDecisionOutcome::NoGovernanceExecutionSupplied`]).
///   The runtime path continues exactly as it did pre-Run-217 (Run 214
///   no-governance-execution payload compatibility).
/// * [`Self::ProceedAccepted`] — the armed policy routed a present carrier
///   through the Run 211 evaluator and it accepted. Carries the typed Run
///   211 [`GovernanceExecutionOutcome`].
/// * [`Self::FailClosed`] — every other outcome (malformed carrier,
///   required-but-absent, MainNet peer-driven apply refused, or any Run 211
///   reject). The runtime call site MUST NOT mutate: no Run 070 apply, no
///   live trust swap, no session eviction, no sequence write, no marker
///   write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceExecutionRuntimeConsumption {
    /// Disabled policy + absent carrier: legacy no-governance-execution
    /// payload compatibility. The runtime path continues unchanged.
    ProceedLegacyBypass,
    /// The armed policy accepted the routed governance-execution material.
    ProceedAccepted(GovernanceExecutionOutcome),
    /// Fail closed before any mutation. Carries the rejecting Run 213
    /// outcome so the caller can surface the precise operator reason.
    FailClosed(GovernanceExecutionPayloadCarryingDecisionOutcome),
}

impl GovernanceExecutionRuntimeConsumption {
    /// Run 220 — collapse a Run 217 per-surface outcome into the typed
    /// consumption decision. Pure; performs no mutation.
    pub fn from_outcome(outcome: GovernanceExecutionPayloadCarryingDecisionOutcome) -> Self {
        if outcome.is_bypassed() {
            Self::ProceedLegacyBypass
        } else if let Some(inner) = outcome.callsite_outcome().filter(|_| outcome.is_accept()) {
            Self::ProceedAccepted(inner.clone())
        } else {
            Self::FailClosed(outcome)
        }
    }

    /// `true` iff the runtime call site may continue (legacy bypass or an
    /// accepted policy outcome).
    pub fn is_proceed(&self) -> bool {
        matches!(self, Self::ProceedLegacyBypass | Self::ProceedAccepted(_))
    }

    /// `true` iff the runtime call site MUST fail closed before any
    /// mutation.
    pub fn is_fail_closed(&self) -> bool {
        matches!(self, Self::FailClosed(_))
    }

    /// `true` iff this is the pre-Run-217 legacy no-governance-execution
    /// payload bypass.
    pub fn is_legacy_bypass(&self) -> bool {
        matches!(self, Self::ProceedLegacyBypass)
    }

    /// Borrow the rejecting Run 213 outcome when this is a
    /// [`Self::FailClosed`] decision.
    pub fn rejecting_outcome(
        &self,
    ) -> Option<&GovernanceExecutionPayloadCarryingDecisionOutcome> {
        match self {
            Self::FailClosed(o) => Some(o),
            Self::ProceedLegacyBypass | Self::ProceedAccepted(_) => None,
        }
    }

    /// Operator-facing reason string for a [`Self::FailClosed`] decision;
    /// `None` for the proceed variants.
    pub fn fail_closed_reason(&self) -> Option<String> {
        self.rejecting_outcome().map(|o| match o {
            GovernanceExecutionPayloadCarryingDecisionOutcome::MalformedGovernanceExecutionPayload(
                e,
            ) => format!("malformed governance-execution carrier: {}", e),
            GovernanceExecutionPayloadCarryingDecisionOutcome::GovernanceExecutionRequiredButAbsent {
                policy,
            } => format!(
                "governance-execution material required by policy {:?} but the carrier is absent",
                policy
            ),
            GovernanceExecutionPayloadCarryingDecisionOutcome::MainNetPeerDrivenApplyRefused => {
                "MainNet peer-driven apply refused unconditionally".to_string()
            }
            GovernanceExecutionPayloadCarryingDecisionOutcome::Callsite(inner) => {
                format!("governance-execution evaluation rejected: {:?}", inner)
            }
            GovernanceExecutionPayloadCarryingDecisionOutcome::NoGovernanceExecutionSupplied => {
                // Not a reject; defensively reported for completeness.
                "no governance-execution supplied".to_string()
            }
        })
    }
}

impl GovernanceExecutionRuntimeArmingConfig {
    /// Run 220 — drive the named runtime preflight surface under the armed
    /// policy and **consume** the returned outcome into a typed
    /// [`GovernanceExecutionRuntimeConsumption`].
    ///
    /// This is the Run 220 replacement for the discarded
    /// `let _outcome = arming.arm_surface(..)` pattern at the long-running
    /// runtime call sites. The caller MUST act on the decision: proceed on
    /// `Proceed*`, fail closed BEFORE any mutation on `FailClosed`.
    pub fn consume_surface(
        &self,
        surface: GovernanceExecutionRuntimeSurface,
        trust_domain: &AuthorityTrustDomain,
        expectations: &GovernanceExecutionExpectations,
        loaded: &GovernanceExecutionLoadStatus,
    ) -> GovernanceExecutionRuntimeConsumption {
        GovernanceExecutionRuntimeConsumption::from_outcome(self.arm_surface(
            surface,
            trust_domain,
            expectations,
            loaded,
        ))
    }

    /// Run 220 — resolve the real governance-execution sidecar status from
    /// an optional in-memory sidecar JSON value (Run 213 parser) and
    /// consume it through the named runtime preflight surface.
    ///
    /// This is the Run 220 replacement for the forced
    /// [`GovernanceExecutionLoadStatus::Absent`] at runtime call sites that
    /// hold a representable sidecar value. A `None` sidecar (no operator
    /// sidecar supplied) remains `Absent`; a present sidecar becomes
    /// [`GovernanceExecutionLoadStatus::Absent`] (no sibling),
    /// [`GovernanceExecutionLoadStatus::Available`] (well-formed sibling),
    /// or [`GovernanceExecutionLoadStatus::Malformed`] (broken sibling) per
    /// the Run 213 sibling parser.
    pub fn consume_surface_from_optional_sidecar_value(
        &self,
        surface: GovernanceExecutionRuntimeSurface,
        trust_domain: &AuthorityTrustDomain,
        expectations: &GovernanceExecutionExpectations,
        sidecar: Option<&serde_json::Value>,
    ) -> GovernanceExecutionRuntimeConsumption {
        let loaded = governance_execution_load_status_from_optional_sidecar_value(sidecar);
        self.consume_surface(surface, trust_domain, expectations, &loaded)
    }
}

/// Run 220 — derive the real [`GovernanceExecutionLoadStatus`] from an
/// optional sidecar JSON value using the Run 213 sibling parser.
///
/// * `None` (no operator sidecar supplied at this surface) ⇒ `Absent`.
/// * `Some(value)` ⇒ the Run 213 sibling parse result (`Absent` /
///   `Available` / `Malformed`).
///
/// Pure — performs no I/O and no mutation. This is the single helper a
/// runtime call site uses instead of hardcoding
/// [`GovernanceExecutionLoadStatus::Absent`].
pub fn governance_execution_load_status_from_optional_sidecar_value(
    sidecar: Option<&serde_json::Value>,
) -> GovernanceExecutionLoadStatus {
    match sidecar {
        Some(value) => parse_optional_governance_execution_sibling_from_json_value(value),
        None => GovernanceExecutionLoadStatus::Absent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_runtime_arming_is_disabled() {
        assert_eq!(
            GovernanceExecutionRuntimeArmingConfig::default().governance_execution_policy(),
            GovernanceExecutionPolicy::Disabled
        );
        assert!(GovernanceExecutionRuntimeArmingConfig::disabled().is_disabled());
    }

    #[test]
    fn with_policy_carries_resolved_policy() {
        let cfg = GovernanceExecutionRuntimeArmingConfig::with_policy(
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        assert_eq!(
            cfg.governance_execution_policy(),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed
        );
        assert!(!cfg.is_disabled());
    }

    #[test]
    fn surface_tags_are_stable_and_cover_all_seven() {
        assert_eq!(GovernanceExecutionRuntimeSurface::ALL.len(), 7);
        assert_eq!(
            GovernanceExecutionRuntimeSurface::ReloadCheck.tag(),
            "reload-check"
        );
        assert_eq!(
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain.tag(),
            "peer-driven-drain"
        );
    }

    #[test]
    fn run_220_default_absent_consumes_legacy_bypass() {
        // Run 220 — default Disabled + absent carrier collapses to the
        // legacy no-governance-execution bypass (Run 214 compatibility).
        let cfg = GovernanceExecutionRuntimeArmingConfig::disabled();
        let consumption = GovernanceExecutionRuntimeConsumption::from_outcome(
            GovernanceExecutionPayloadCarryingDecisionOutcome::NoGovernanceExecutionSupplied,
        );
        assert!(consumption.is_proceed());
        assert!(consumption.is_legacy_bypass());
        assert!(cfg.is_disabled());
    }

    #[test]
    fn run_220_required_but_absent_consumes_fail_closed() {
        let outcome =
            GovernanceExecutionPayloadCarryingDecisionOutcome::GovernanceExecutionRequiredButAbsent {
                policy: GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            };
        let consumption = GovernanceExecutionRuntimeConsumption::from_outcome(outcome);
        assert!(consumption.is_fail_closed());
        assert!(consumption.fail_closed_reason().is_some());
    }

    #[test]
    fn run_220_optional_sidecar_value_none_is_absent() {
        assert!(matches!(
            governance_execution_load_status_from_optional_sidecar_value(None),
            GovernanceExecutionLoadStatus::Absent
        ));
    }
}