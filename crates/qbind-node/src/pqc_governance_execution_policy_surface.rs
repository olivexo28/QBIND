//! Run 215 — source/test hidden governance-execution policy selector and
//! production preflight integration.
//!
//! ## Strict scope (Run 215)
//!
//! * **Source/test only.** Run 215 does **not** capture release-binary
//!   evidence; release-binary governance-execution-policy selector
//!   evidence is deferred to **Run 216**.
//! * **Hidden selector only.** The selector is exposed via a hidden clap
//!   flag (`--p2p-trust-bundle-governance-execution-policy`,
//!   `hide = true`) and an equivalent environment variable
//!   (`QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY`). Operators
//!   reading `--help` see no new surface.
//! * **Disabled by default.** When the flag and env var are both absent
//!   the resolved policy is [`GovernanceExecutionPolicy::Disabled`]
//!   bit-for-bit. Legacy no-governance-execution payloads remain accepted
//!   exactly as they were before Run 215 (Run 213 compatibility).
//! * **No real governance execution engine.**
//!   `ProductionGovernanceRequired` and `MainnetGovernanceRequired`
//!   continue to fail closed as "unavailable" via the Run 211 evaluator
//!   regardless of selector. No real governance execution engine, no real
//!   on-chain governance proof verifier, no real KMS / HSM backend, no
//!   real RemoteSigner backend exists.
//! * **Fixture governance execution is DevNet/TestNet evidence-only.**
//!   `FixtureGovernanceAllowed` and `EmergencyCouncilFixtureAllowed`
//!   cannot satisfy MainNet production governance execution and cannot
//!   enable MainNet peer-driven apply.
//! * **Emergency council fixture is explicit and non-production.** The
//!   `EmergencyCouncilFixtureAllowed` policy authorizes only explicit
//!   emergency-council fixture governance and never satisfies MainNet
//!   production governance execution.
//! * **No MainNet peer-driven apply enablement.** The Run 147 / 148 /
//!   152 MainNet refusal at the peer-driven apply surface remains intact
//!   even with `MainnetGovernanceRequired` and fixture governance
//!   material.
//! * **No validator-set rotation, no autonomous apply, no apply on
//!   receipt, no peer-majority authority.**
//! * **No marker / sequence-file / authority-marker / trust-bundle
//!   core / wire / schema change.** Run 215 only adds source-level
//!   selector parsing and a thin shim around the Run 213 per-surface
//!   routing helpers that injects the resolved policy into the call-site
//!   context.
//!
//! Run 215 does **not** weaken any prior run (Runs 070, 130–214) and
//! does **not** claim full C4 or C5 closure.
//!
//! ## What this module adds
//!
//! 1. The hidden selector environment-variable name
//!    [`QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV`].
//! 2. A typed [`GovernanceExecutionPolicySelectorParseError`] that
//!    distinguishes an unknown selector value from an empty selector
//!    value.
//! 3. Pure parsers [`governance_execution_policy_from_selector`] and
//!    [`governance_execution_policy_env_selector`] together with the
//!    CLI/env resolver [`governance_execution_policy_from_cli_or_env`].
//! 4. Seven thin per-surface preflight wrappers
//!    ([`preflight_v2_marker_governance_execution_for_*`]) that bind the
//!    resolved [`GovernanceExecutionPolicy`] into the Run 213
//!    [`GovernanceExecutionCallsiteContext`] used by the matching Run 213
//!    `route_loaded_governance_execution_to_*_callsite_decision` routing
//!    helper. The wrappers exist so the Run 215 source-reachability claim
//!    ("the selected policy reaches all seven production-context
//!    helpers") is grep-verifiable from each surface.
//!
//! ## Pure / non-mutating
//!
//! The selector parsers perform a single read of the environment and no
//! other I/O. The per-surface preflight wrappers perform no I/O beyond
//! the underlying Run 213 routing helper composition: they write no
//! marker, write no sequence, swap no live trust state, evict no
//! sessions, and never invoke Run 070. Mutating callers (reload-apply /
//! startup `--p2p-trust-bundle` / SIGHUP / peer-driven drain) remain
//! responsible for honoring the existing `commit_sequence` →
//! `persist_accepted_v2_marker_after_commit_boundary`
//! sequence-before-marker ordering AFTER acceptance.
//!
//! ## Selector grammar
//!
//! The CLI flag and env var share the same value grammar
//! (case-insensitive; surrounding ASCII whitespace is trimmed). The tags
//! match [`GovernanceExecutionPolicy::tag`] exactly:
//!
//! | value                                | resolved policy                                            |
//! |--------------------------------------|------------------------------------------------------------|
//! | `disabled`                           | [`GovernanceExecutionPolicy::Disabled`]                    |
//! | `fixture-governance-allowed`         | [`GovernanceExecutionPolicy::FixtureGovernanceAllowed`]    |
//! | `emergency-council-fixture-allowed`  | [`GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed`] |
//! | `production-governance-required`     | [`GovernanceExecutionPolicy::ProductionGovernanceRequired`] |
//! | `mainnet-governance-required`        | [`GovernanceExecutionPolicy::MainnetGovernanceRequired`]   |
//!
//! Any other non-empty value fails closed with
//! [`GovernanceExecutionPolicySelectorParseError::UnknownValue`]; an
//! empty / whitespace-only value fails closed with
//! [`GovernanceExecutionPolicySelectorParseError::Empty`]. A selector
//! parse error is a typed startup/preflight error — the resolver never
//! silently downgrades to `Disabled` when an explicit value is present
//! but invalid.
//!
//! ## Precedence
//!
//! When both sources are supplied, the CLI flag wins. This mirrors the
//! Run 192 authority-custody policy selector, the Run 198 RemoteSigner
//! policy selector, and the Run 209 custody-attestation policy selector
//! precedence and the standard CLI/env convention: the operator-supplied
//! command line is the authoritative source for a single invocation. The
//! env var still propagates when the CLI flag is absent.

use crate::pqc_governance_execution_payload_carrying::{
    callsite_context_for_governance_execution,
    route_loaded_governance_execution_to_live_inbound_0x05_callsite_decision,
    route_loaded_governance_execution_to_local_peer_candidate_check_callsite_decision,
    route_loaded_governance_execution_to_peer_driven_drain_callsite_decision,
    route_loaded_governance_execution_to_reload_apply_callsite_decision,
    route_loaded_governance_execution_to_reload_check_callsite_decision,
    route_loaded_governance_execution_to_sighup_callsite_decision,
    route_loaded_governance_execution_to_startup_p2p_trust_bundle_callsite_decision,
    GovernanceExecutionCallsiteContext, GovernanceExecutionLoadStatus,
    GovernanceExecutionPayloadCarryingDecisionOutcome,
};
use crate::pqc_governance_execution_policy::{
    GovernanceExecutionExpectations, GovernanceExecutionPolicy,
};
use crate::pqc_authority_lifecycle::AuthorityTrustDomain;

// ===========================================================================
// Env-var name + canonical selector tags
// ===========================================================================

/// Run 215 — environment-variable name of the hidden,
/// disabled-by-default governance-execution policy selector. Accepts the
/// same value grammar as the equivalent CLI flag
/// `--p2p-trust-bundle-governance-execution-policy`.
///
/// Either source is sufficient to choose a non-default policy; both
/// sources absent / empty preserves the
/// [`GovernanceExecutionPolicy::Disabled`] default.
pub const QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV: &str =
    "QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY";

/// Run 215 — canonical selector tag for
/// [`GovernanceExecutionPolicy::Disabled`].
pub const GOVERNANCE_EXECUTION_POLICY_TAG_DISABLED: &str = "disabled";
/// Run 215 — canonical selector tag for
/// [`GovernanceExecutionPolicy::FixtureGovernanceAllowed`].
pub const GOVERNANCE_EXECUTION_POLICY_TAG_FIXTURE_GOVERNANCE_ALLOWED: &str =
    "fixture-governance-allowed";
/// Run 215 — canonical selector tag for
/// [`GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed`].
pub const GOVERNANCE_EXECUTION_POLICY_TAG_EMERGENCY_COUNCIL_FIXTURE_ALLOWED: &str =
    "emergency-council-fixture-allowed";
/// Run 215 — canonical selector tag for
/// [`GovernanceExecutionPolicy::ProductionGovernanceRequired`].
pub const GOVERNANCE_EXECUTION_POLICY_TAG_PRODUCTION_GOVERNANCE_REQUIRED: &str =
    "production-governance-required";
/// Run 215 — canonical selector tag for
/// [`GovernanceExecutionPolicy::MainnetGovernanceRequired`].
pub const GOVERNANCE_EXECUTION_POLICY_TAG_MAINNET_GOVERNANCE_REQUIRED: &str =
    "mainnet-governance-required";

// ===========================================================================
// Typed selector parse error
// ===========================================================================

/// Run 215 — typed selector parse error. A typed error makes the
/// fail-closed startup/preflight contract grep-verifiable: the resolver
/// never silently downgrades an unknown selector value to
/// [`GovernanceExecutionPolicy::Disabled`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceExecutionPolicySelectorParseError {
    /// The selector source supplied an empty / whitespace-only value. An
    /// empty explicit selector is rejected — the operator must either
    /// omit the source entirely (preserving the `Disabled` default) or
    /// supply a known tag.
    Empty,
    /// The selector source supplied a value that does not match any
    /// recognized tag. The recognized tags are enumerated in the
    /// module-level docs.
    UnknownValue { value: String },
}

impl GovernanceExecutionPolicySelectorParseError {
    /// Stable short tag used by error logs and tests.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::UnknownValue { .. } => "unknown-value",
        }
    }
}

impl std::fmt::Display for GovernanceExecutionPolicySelectorParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(
                f,
                "governance-execution policy selector value is empty (recognized tags: \
                 disabled | fixture-governance-allowed | emergency-council-fixture-allowed | \
                 production-governance-required | mainnet-governance-required)"
            ),
            Self::UnknownValue { value } => write!(
                f,
                "governance-execution policy selector value {value:?} is not recognized \
                 (recognized tags: disabled | fixture-governance-allowed | \
                 emergency-council-fixture-allowed | production-governance-required | \
                 mainnet-governance-required)"
            ),
        }
    }
}

impl std::error::Error for GovernanceExecutionPolicySelectorParseError {}

// ===========================================================================
// Selector parsers
// ===========================================================================

/// Run 215 — pure selector-string → [`GovernanceExecutionPolicy`]
/// parser.
///
/// The matcher is **case-insensitive** and trims surrounding ASCII
/// whitespace before matching. An empty / whitespace-only value returns
/// [`GovernanceExecutionPolicySelectorParseError::Empty`]; an unknown
/// non-empty value returns
/// [`GovernanceExecutionPolicySelectorParseError::UnknownValue`].
///
/// The parser is the single source of truth for both the CLI and env
/// surfaces: see [`governance_execution_policy_env_selector`] and
/// [`governance_execution_policy_from_cli_or_env`].
pub fn governance_execution_policy_from_selector(
    value: &str,
) -> Result<GovernanceExecutionPolicy, GovernanceExecutionPolicySelectorParseError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(GovernanceExecutionPolicySelectorParseError::Empty);
    }
    if trimmed.eq_ignore_ascii_case(GOVERNANCE_EXECUTION_POLICY_TAG_DISABLED) {
        Ok(GovernanceExecutionPolicy::Disabled)
    } else if trimmed
        .eq_ignore_ascii_case(GOVERNANCE_EXECUTION_POLICY_TAG_FIXTURE_GOVERNANCE_ALLOWED)
    {
        Ok(GovernanceExecutionPolicy::FixtureGovernanceAllowed)
    } else if trimmed
        .eq_ignore_ascii_case(GOVERNANCE_EXECUTION_POLICY_TAG_EMERGENCY_COUNCIL_FIXTURE_ALLOWED)
    {
        Ok(GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed)
    } else if trimmed
        .eq_ignore_ascii_case(GOVERNANCE_EXECUTION_POLICY_TAG_PRODUCTION_GOVERNANCE_REQUIRED)
    {
        Ok(GovernanceExecutionPolicy::ProductionGovernanceRequired)
    } else if trimmed
        .eq_ignore_ascii_case(GOVERNANCE_EXECUTION_POLICY_TAG_MAINNET_GOVERNANCE_REQUIRED)
    {
        Ok(GovernanceExecutionPolicy::MainnetGovernanceRequired)
    } else {
        Err(GovernanceExecutionPolicySelectorParseError::UnknownValue {
            value: trimmed.to_string(),
        })
    }
}

/// Run 215 — pure environment-variable readback for the hidden
/// governance-execution policy selector.
///
/// * Returns `Ok(None)` when the env var is unset (the operator has not
///   supplied an env-source selector).
/// * Returns `Ok(Some(policy))` when the env var is set to a recognized
///   tag.
/// * Returns `Err(error)` when the env var is set to an empty or unknown
///   value — the resolver MUST surface this as a typed
///   startup/preflight error rather than silently fall back to
///   `Disabled`.
///
/// This helper performs a single [`std::env::var`] read and is otherwise
/// pure. It is intentionally exposed (instead of inlined) so the Run 215
/// source-test matrix can drive the selector deterministically by
/// setting/unsetting the env var.
pub fn governance_execution_policy_env_selector(
) -> Result<Option<GovernanceExecutionPolicy>, GovernanceExecutionPolicySelectorParseError> {
    match std::env::var(QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY_ENV) {
        Ok(v) => governance_execution_policy_from_selector(&v).map(Some),
        Err(_) => Ok(None),
    }
}

/// Run 215 — CLI/env resolver. Precedence:
///
/// 1. If the CLI flag value is `Some`, parse it; result wins regardless
///    of the env var.
/// 2. Otherwise, read the env var via
///    [`governance_execution_policy_env_selector`].
/// 3. If both are absent, return [`GovernanceExecutionPolicy::Disabled`].
///
/// A parse error from either source is propagated as a typed
/// [`GovernanceExecutionPolicySelectorParseError`] — the resolver
/// **never** silently falls back to `Disabled` when an explicit value is
/// present but invalid.
pub fn governance_execution_policy_from_cli_or_env(
    cli_value: Option<&str>,
) -> Result<GovernanceExecutionPolicy, GovernanceExecutionPolicySelectorParseError> {
    if let Some(v) = cli_value {
        return governance_execution_policy_from_selector(v);
    }
    Ok(governance_execution_policy_env_selector()?.unwrap_or(GovernanceExecutionPolicy::Disabled))
}

// ===========================================================================
// Per-surface preflight wrappers — bind resolved policy to Run 213
// routing helpers for each of the seven production v2 marker-decision
// preflight contexts.
// ===========================================================================

/// Run 215 — internal helper: build a Run 213 callsite context with the
/// resolved governance-execution policy and dispatch to the supplied
/// per-surface routing helper. The dispatcher signature mirrors the seven
/// Run 213 `route_loaded_governance_execution_to_*_callsite_decision`
/// helpers exactly.
fn preflight_with_policy<F>(
    trust_domain: &AuthorityTrustDomain,
    expectations: &GovernanceExecutionExpectations,
    policy: GovernanceExecutionPolicy,
    loaded: &GovernanceExecutionLoadStatus,
    dispatch: F,
) -> GovernanceExecutionPayloadCarryingDecisionOutcome
where
    F: Fn(
        &GovernanceExecutionCallsiteContext<'_>,
        &GovernanceExecutionLoadStatus,
    ) -> GovernanceExecutionPayloadCarryingDecisionOutcome,
{
    let ctx = callsite_context_for_governance_execution(trust_domain, expectations, policy);
    dispatch(&ctx, loaded)
}

/// Run 215 — `--p2p-trust-bundle-reload-check` validation-only preflight
/// wrapper that injects the resolved [`GovernanceExecutionPolicy`] into
/// the Run 213 callsite context and delegates to
/// [`route_loaded_governance_execution_to_reload_check_callsite_decision`].
///
/// **Validation-only mutation contract:** the caller MUST drop the
/// returned outcome and MUST NOT persist a marker, advance the
/// bundle-signing sequence, swap live trust state, evict sessions, or
/// invoke Run 070.
pub fn preflight_v2_marker_governance_execution_for_reload_check(
    trust_domain: &AuthorityTrustDomain,
    expectations: &GovernanceExecutionExpectations,
    policy: GovernanceExecutionPolicy,
    loaded: &GovernanceExecutionLoadStatus,
) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
    preflight_with_policy(
        trust_domain,
        expectations,
        policy,
        loaded,
        route_loaded_governance_execution_to_reload_check_callsite_decision,
    )
}

/// Run 215 — `--p2p-trust-bundle-reload-apply-*` mutating-preflight
/// wrapper. Mutating callers continue to honor sequence-before-marker
/// ordering AFTER acceptance.
pub fn preflight_v2_marker_governance_execution_for_reload_apply(
    trust_domain: &AuthorityTrustDomain,
    expectations: &GovernanceExecutionExpectations,
    policy: GovernanceExecutionPolicy,
    loaded: &GovernanceExecutionLoadStatus,
) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
    preflight_with_policy(
        trust_domain,
        expectations,
        policy,
        loaded,
        route_loaded_governance_execution_to_reload_apply_callsite_decision,
    )
}

/// Run 215 — startup `--p2p-trust-bundle` mutating-preflight wrapper.
pub fn preflight_v2_marker_governance_execution_for_startup_p2p_trust_bundle(
    trust_domain: &AuthorityTrustDomain,
    expectations: &GovernanceExecutionExpectations,
    policy: GovernanceExecutionPolicy,
    loaded: &GovernanceExecutionLoadStatus,
) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
    preflight_with_policy(
        trust_domain,
        expectations,
        policy,
        loaded,
        route_loaded_governance_execution_to_startup_p2p_trust_bundle_callsite_decision,
    )
}

/// Run 215 — SIGHUP live trust-bundle reload mutating-preflight wrapper.
pub fn preflight_v2_marker_governance_execution_for_sighup(
    trust_domain: &AuthorityTrustDomain,
    expectations: &GovernanceExecutionExpectations,
    policy: GovernanceExecutionPolicy,
    loaded: &GovernanceExecutionLoadStatus,
) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
    preflight_with_policy(
        trust_domain,
        expectations,
        policy,
        loaded,
        route_loaded_governance_execution_to_sighup_callsite_decision,
    )
}

/// Run 215 — local `--p2p-trust-bundle-peer-candidate-check`
/// validation-only preflight wrapper.
pub fn preflight_v2_marker_governance_execution_for_local_peer_candidate_check(
    trust_domain: &AuthorityTrustDomain,
    expectations: &GovernanceExecutionExpectations,
    policy: GovernanceExecutionPolicy,
    loaded: &GovernanceExecutionLoadStatus,
) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
    preflight_with_policy(
        trust_domain,
        expectations,
        policy,
        loaded,
        route_loaded_governance_execution_to_local_peer_candidate_check_callsite_decision,
    )
}

/// Run 215 — live inbound `0x05` peer-candidate validation-only preflight
/// wrapper.
///
/// **Live-config limitation (A16):** the live inbound `0x05` decode path
/// does not yet thread a per-connection governance-execution policy from
/// its live config; this wrapper exposes the policy injection at the
/// source/test level so the selected policy reaches the Run 213 live
/// inbound `0x05` routing helper, and an invalid live `0x05`
/// governance-execution candidate is not propagated, staged, or applied.
/// Wiring the resolved policy into the live `0x05` runtime config is
/// deferred to the release-binary harness in Run 216.
pub fn preflight_v2_marker_governance_execution_for_live_inbound_0x05(
    trust_domain: &AuthorityTrustDomain,
    expectations: &GovernanceExecutionExpectations,
    policy: GovernanceExecutionPolicy,
    loaded: &GovernanceExecutionLoadStatus,
) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
    preflight_with_policy(
        trust_domain,
        expectations,
        policy,
        loaded,
        route_loaded_governance_execution_to_live_inbound_0x05_callsite_decision,
    )
}

/// Run 215 — Run 150 peer-driven apply drain coordinator preflight
/// wrapper.
///
/// **MainNet refusal preserved.** The underlying Run 213 routing helper
/// refuses MainNet peer-driven apply unconditionally, even with
/// `MainnetGovernanceRequired` and fully-valid fixture governance
/// material. The selector cannot weaken this refusal.
pub fn preflight_v2_marker_governance_execution_for_peer_driven_drain(
    trust_domain: &AuthorityTrustDomain,
    expectations: &GovernanceExecutionExpectations,
    policy: GovernanceExecutionPolicy,
    loaded: &GovernanceExecutionLoadStatus,
) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
    preflight_with_policy(
        trust_domain,
        expectations,
        policy,
        loaded,
        route_loaded_governance_execution_to_peer_driven_drain_callsite_decision,
    )
}

// ===========================================================================
// In-crate self-tests (smoke-level — full A1–A16 / R1–R40 coverage lives
// in `tests/run_215_governance_execution_policy_selector_tests.rs`).
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_canonical_tags() {
        assert_eq!(
            governance_execution_policy_from_selector("disabled").unwrap(),
            GovernanceExecutionPolicy::Disabled
        );
        assert_eq!(
            governance_execution_policy_from_selector("fixture-governance-allowed").unwrap(),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed
        );
        assert_eq!(
            governance_execution_policy_from_selector("emergency-council-fixture-allowed").unwrap(),
            GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed
        );
        assert_eq!(
            governance_execution_policy_from_selector("production-governance-required").unwrap(),
            GovernanceExecutionPolicy::ProductionGovernanceRequired
        );
        assert_eq!(
            governance_execution_policy_from_selector("mainnet-governance-required").unwrap(),
            GovernanceExecutionPolicy::MainnetGovernanceRequired
        );
    }

    #[test]
    fn canonical_tags_match_policy_tag_method() {
        assert_eq!(
            GOVERNANCE_EXECUTION_POLICY_TAG_DISABLED,
            GovernanceExecutionPolicy::Disabled.tag()
        );
        assert_eq!(
            GOVERNANCE_EXECUTION_POLICY_TAG_FIXTURE_GOVERNANCE_ALLOWED,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed.tag()
        );
        assert_eq!(
            GOVERNANCE_EXECUTION_POLICY_TAG_EMERGENCY_COUNCIL_FIXTURE_ALLOWED,
            GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed.tag()
        );
        assert_eq!(
            GOVERNANCE_EXECUTION_POLICY_TAG_PRODUCTION_GOVERNANCE_REQUIRED,
            GovernanceExecutionPolicy::ProductionGovernanceRequired.tag()
        );
        assert_eq!(
            GOVERNANCE_EXECUTION_POLICY_TAG_MAINNET_GOVERNANCE_REQUIRED,
            GovernanceExecutionPolicy::MainnetGovernanceRequired.tag()
        );
    }

    #[test]
    fn parser_is_case_insensitive_and_trims() {
        assert_eq!(
            governance_execution_policy_from_selector("  FIXTURE-GOVERNANCE-ALLOWED ").unwrap(),
            GovernanceExecutionPolicy::FixtureGovernanceAllowed
        );
        assert_eq!(
            governance_execution_policy_from_selector("Disabled").unwrap(),
            GovernanceExecutionPolicy::Disabled
        );
    }

    #[test]
    fn empty_value_is_typed_error() {
        assert_eq!(
            governance_execution_policy_from_selector("").unwrap_err(),
            GovernanceExecutionPolicySelectorParseError::Empty
        );
        assert_eq!(
            governance_execution_policy_from_selector("   ").unwrap_err(),
            GovernanceExecutionPolicySelectorParseError::Empty
        );
    }

    #[test]
    fn unknown_value_is_typed_error() {
        let e = governance_execution_policy_from_selector("totally-bogus").unwrap_err();
        assert!(matches!(
            e,
            GovernanceExecutionPolicySelectorParseError::UnknownValue { .. }
        ));
        assert_eq!(e.tag(), "unknown-value");
    }

    #[test]
    fn cli_or_env_disabled_when_cli_disabled() {
        // We cannot guarantee env is unset here in a parallel test run,
        // so only assert the explicit-cli=Some(disabled) case.
        assert_eq!(
            governance_execution_policy_from_cli_or_env(Some("disabled")).unwrap(),
            GovernanceExecutionPolicy::Disabled
        );
    }

    #[test]
    fn cli_some_invalid_is_typed_error() {
        assert!(matches!(
            governance_execution_policy_from_cli_or_env(Some("nope")).unwrap_err(),
            GovernanceExecutionPolicySelectorParseError::UnknownValue { .. }
        ));
    }
}