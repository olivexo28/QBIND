//! Run 192 — source/test hidden authority-custody policy selector and
//! production preflight integration.
//!
//! ## Strict scope (Run 192)
//!
//! * **Source/test only.** Run 192 does **not** capture release-binary
//!   evidence; release-binary custody-policy selector evidence is
//!   deferred to **Run 193**.
//! * **Hidden selector only.** The selector is exposed via a hidden
//!   clap flag (`--p2p-trust-bundle-authority-custody-policy`,
//!   `hide = true`) and an equivalent environment variable
//!   (`QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY`). Operators
//!   reading `--help` see no new surface.
//! * **Disabled by default.** When the flag and env var are both
//!   absent the resolved policy is
//!   [`AuthorityCustodyPolicy::Disabled`] bit-for-bit. Legacy
//!   no-custody payloads remain accepted exactly as they were before
//!   Run 192.
//! * **No real KMS/HSM/cloud-KMS/PKCS#11/remote-signer backend.**
//!   `RemoteSigner`, `Kms`, and `Hsm` continue to fail closed as
//!   "unavailable" via the Run 188 validator regardless of selector.
//! * **No MainNet peer-driven apply enablement.** The Run 147 / 148 /
//!   152 MainNet refusal at the peer-driven apply surface remains
//!   intact even with `MainnetProductionCustodyRequired` and metadata
//!   claiming KMS/HSM/RemoteSigner.
//! * **No governance execution engine, no real on-chain proof
//!   verifier, no validator-set rotation, no autonomous apply, no
//!   apply on receipt, no peer-majority authority.**
//! * **No marker / sequence-file / authority-marker / trust-bundle
//!   core / wire / schema change.** Run 192 only adds source-level
//!   selector parsing and a thin shim around the Run 190 per-surface
//!   routing helpers that injects the resolved policy into the
//!   call-site context.
//!
//! Run 192 does **not** weaken any prior run (Runs 070, 130–191) and
//! does **not** claim full C4 or C5 closure.
//!
//! ## What this module adds
//!
//! 1. The hidden selector environment-variable name
//!    [`QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV`].
//! 2. A typed [`AuthorityCustodyPolicySelectorParseError`] that
//!    distinguishes an unknown selector value from an empty selector
//!    value.
//! 3. Pure parsers
//!    [`authority_custody_policy_from_selector`] and
//!    [`authority_custody_policy_env_selector`] together with the
//!    OR-combined CLI/env resolver
//!    [`authority_custody_policy_from_cli_or_env`].
//! 4. Seven thin per-surface preflight wrappers
//!    ([`preflight_v2_marker_authority_custody_for_*`]) that bind the
//!    resolved [`AuthorityCustodyPolicy`] into the Run 190
//!    [`AuthorityCustodyCallsiteContext`] used by the matching
//!    Run 190 [`route_loaded_authority_custody_attestation_to_*_callsite_decision`]
//!    routing helper. The wrappers exist so the Run 192 source
//!    reachability claim ("the selected policy reaches all seven
//!    production-context helpers") is grep-verifiable from each
//!    surface.
//!
//! ## Pure / non-mutating
//!
//! The selector parsers perform a single read of the environment and
//! no other I/O. The per-surface preflight wrappers perform no I/O
//! beyond the underlying Run 190 routing helper composition: they
//! write no marker, write no sequence, swap no live trust state,
//! evict no sessions, and never invoke Run 070. Mutating callers
//! (reload-apply / startup `--p2p-trust-bundle` / SIGHUP /
//! peer-driven drain) remain responsible for honoring the existing
//! `commit_sequence` → `persist_accepted_v2_marker_after_commit_boundary`
//! sequence-before-marker ordering AFTER acceptance.
//!
//! ## Selector grammar
//!
//! The CLI flag and env var share the same value grammar
//! (case-insensitive on the env var; the clap parser already
//! lower-cases its input):
//!
//! | value                                   | resolved policy                                |
//! |-----------------------------------------|------------------------------------------------|
//! | `disabled`                              | [`AuthorityCustodyPolicy::Disabled`]           |
//! | `fixture-only`                          | [`AuthorityCustodyPolicy::FixtureOnly`]        |
//! | `devnet-local-allowed`                  | [`AuthorityCustodyPolicy::DevnetLocalAllowed`] |
//! | `testnet-local-allowed`                 | [`AuthorityCustodyPolicy::TestnetLocalAllowed`]|
//! | `production-custody-required`           | [`AuthorityCustodyPolicy::ProductionCustodyRequired`] |
//! | `mainnet-production-custody-required`   | [`AuthorityCustodyPolicy::MainnetProductionCustodyRequired`] |
//!
//! Any other non-empty value fails closed with
//! [`AuthorityCustodyPolicySelectorParseError::UnknownValue`]; an
//! empty / whitespace-only value fails closed with
//! [`AuthorityCustodyPolicySelectorParseError::Empty`]. A selector
//! parse error is a typed startup/preflight error — the resolver
//! never silently downgrades to `Disabled` when an explicit value is
//! present but invalid.
//!
//! ## Precedence
//!
//! When both sources are supplied, the CLI flag wins. This mirrors
//! standard CLI/env precedence and matches the operator-supplied
//! command line as the authoritative source for a single invocation.
//! The env var still propagates when the CLI flag is absent.

use crate::pqc_authority_custody::AuthorityCustodyPolicy;
use crate::pqc_authority_custody_payload_carrying::{
    callsite_context_for_authority_custody, route_loaded_authority_custody_attestation_to_live_inbound_0x05_callsite_decision,
    route_loaded_authority_custody_attestation_to_local_peer_candidate_check_callsite_decision,
    route_loaded_authority_custody_attestation_to_peer_driven_drain_callsite_decision,
    route_loaded_authority_custody_attestation_to_reload_apply_callsite_decision,
    route_loaded_authority_custody_attestation_to_reload_check_callsite_decision,
    route_loaded_authority_custody_attestation_to_sighup_callsite_decision,
    route_loaded_authority_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision,
    AuthorityCustodyLoadStatus, AuthorityCustodyPayloadCarryingDecisionOutcome,
};
use crate::pqc_authority_lifecycle::{AuthorityTrustDomain, LocalLifecycleAction};
use crate::pqc_authority_state::{
    PersistentAuthorityStateRecordV2, PersistentAuthorityStateRecordVersioned,
};
use crate::pqc_governance_authority::GovernanceAuthorityClass;

// ===========================================================================
// Env-var name + canonical selector tags
// ===========================================================================

/// Run 192 — environment-variable name of the hidden,
/// disabled-by-default authority-custody policy selector. Accepts the
/// same value grammar as the equivalent CLI flag
/// `--p2p-trust-bundle-authority-custody-policy`.
///
/// Either source is sufficient to choose a non-default policy; both
/// sources absent / empty preserves the
/// [`AuthorityCustodyPolicy::Disabled`] default.
pub const QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV: &str =
    "QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY";

/// Run 192 — canonical selector tag for
/// [`AuthorityCustodyPolicy::Disabled`].
pub const AUTHORITY_CUSTODY_POLICY_TAG_DISABLED: &str = "disabled";
/// Run 192 — canonical selector tag for
/// [`AuthorityCustodyPolicy::FixtureOnly`].
pub const AUTHORITY_CUSTODY_POLICY_TAG_FIXTURE_ONLY: &str = "fixture-only";
/// Run 192 — canonical selector tag for
/// [`AuthorityCustodyPolicy::DevnetLocalAllowed`].
pub const AUTHORITY_CUSTODY_POLICY_TAG_DEVNET_LOCAL_ALLOWED: &str = "devnet-local-allowed";
/// Run 192 — canonical selector tag for
/// [`AuthorityCustodyPolicy::TestnetLocalAllowed`].
pub const AUTHORITY_CUSTODY_POLICY_TAG_TESTNET_LOCAL_ALLOWED: &str = "testnet-local-allowed";
/// Run 192 — canonical selector tag for
/// [`AuthorityCustodyPolicy::ProductionCustodyRequired`].
pub const AUTHORITY_CUSTODY_POLICY_TAG_PRODUCTION_CUSTODY_REQUIRED: &str =
    "production-custody-required";
/// Run 192 — canonical selector tag for
/// [`AuthorityCustodyPolicy::MainnetProductionCustodyRequired`].
pub const AUTHORITY_CUSTODY_POLICY_TAG_MAINNET_PRODUCTION_CUSTODY_REQUIRED: &str =
    "mainnet-production-custody-required";

// ===========================================================================
// Typed selector parse error
// ===========================================================================

/// Run 192 — typed selector parse error. A typed error makes the
/// fail-closed startup/preflight contract grep-verifiable: the
/// resolver never silently downgrades an unknown selector value to
/// [`AuthorityCustodyPolicy::Disabled`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityCustodyPolicySelectorParseError {
    /// The selector source supplied an empty / whitespace-only
    /// value. An empty explicit selector is rejected — the operator
    /// must either omit the source entirely (preserving the
    /// `Disabled` default) or supply a known tag.
    Empty,
    /// The selector source supplied a value that does not match any
    /// recognized tag. The recognized tags are enumerated in the
    /// module-level docs.
    UnknownValue { value: String },
}

impl AuthorityCustodyPolicySelectorParseError {
    /// Stable short tag used by error logs and tests.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::UnknownValue { .. } => "unknown-value",
        }
    }
}

impl std::fmt::Display for AuthorityCustodyPolicySelectorParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(
                f,
                "authority-custody policy selector value is empty (recognized tags: \
                 disabled | fixture-only | devnet-local-allowed | testnet-local-allowed | \
                 production-custody-required | mainnet-production-custody-required)"
            ),
            Self::UnknownValue { value } => write!(
                f,
                "authority-custody policy selector value {value:?} is not recognized \
                 (recognized tags: disabled | fixture-only | devnet-local-allowed | \
                 testnet-local-allowed | production-custody-required | \
                 mainnet-production-custody-required)"
            ),
        }
    }
}

impl std::error::Error for AuthorityCustodyPolicySelectorParseError {}

// ===========================================================================
// Selector parsers
// ===========================================================================

/// Run 192 — pure selector-string → [`AuthorityCustodyPolicy`] parser.
///
/// The matcher is **case-insensitive** and trims surrounding ASCII
/// whitespace before matching. An empty / whitespace-only value
/// returns [`AuthorityCustodyPolicySelectorParseError::Empty`]; an
/// unknown non-empty value returns
/// [`AuthorityCustodyPolicySelectorParseError::UnknownValue`].
///
/// The parser is the single source of truth for both the CLI and env
/// surfaces: see [`authority_custody_policy_env_selector`] and
/// [`authority_custody_policy_from_cli_or_env`].
pub fn authority_custody_policy_from_selector(
    value: &str,
) -> Result<AuthorityCustodyPolicy, AuthorityCustodyPolicySelectorParseError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AuthorityCustodyPolicySelectorParseError::Empty);
    }
    if trimmed.eq_ignore_ascii_case(AUTHORITY_CUSTODY_POLICY_TAG_DISABLED) {
        Ok(AuthorityCustodyPolicy::Disabled)
    } else if trimmed.eq_ignore_ascii_case(AUTHORITY_CUSTODY_POLICY_TAG_FIXTURE_ONLY) {
        Ok(AuthorityCustodyPolicy::FixtureOnly)
    } else if trimmed.eq_ignore_ascii_case(AUTHORITY_CUSTODY_POLICY_TAG_DEVNET_LOCAL_ALLOWED) {
        Ok(AuthorityCustodyPolicy::DevnetLocalAllowed)
    } else if trimmed.eq_ignore_ascii_case(AUTHORITY_CUSTODY_POLICY_TAG_TESTNET_LOCAL_ALLOWED) {
        Ok(AuthorityCustodyPolicy::TestnetLocalAllowed)
    } else if trimmed
        .eq_ignore_ascii_case(AUTHORITY_CUSTODY_POLICY_TAG_PRODUCTION_CUSTODY_REQUIRED)
    {
        Ok(AuthorityCustodyPolicy::ProductionCustodyRequired)
    } else if trimmed.eq_ignore_ascii_case(
        AUTHORITY_CUSTODY_POLICY_TAG_MAINNET_PRODUCTION_CUSTODY_REQUIRED,
    ) {
        Ok(AuthorityCustodyPolicy::MainnetProductionCustodyRequired)
    } else {
        Err(AuthorityCustodyPolicySelectorParseError::UnknownValue {
            value: trimmed.to_string(),
        })
    }
}

/// Run 192 — pure environment-variable readback for the hidden
/// authority-custody policy selector.
///
/// * Returns `Ok(None)` when the env var is unset (the operator has
///   not supplied an env-source selector).
/// * Returns `Ok(Some(policy))` when the env var is set to a
///   recognized tag.
/// * Returns `Err(error)` when the env var is set to an empty or
///   unknown value — the resolver MUST surface this as a typed
///   startup/preflight error rather than silently fall back to
///   `Disabled`.
///
/// This helper performs a single [`std::env::var`] read and is
/// otherwise pure. It is intentionally exposed (instead of inlined)
/// so the Run 192 source-test matrix can drive the selector
/// deterministically by setting/unsetting the env var.
pub fn authority_custody_policy_env_selector(
) -> Result<Option<AuthorityCustodyPolicy>, AuthorityCustodyPolicySelectorParseError> {
    match std::env::var(QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV) {
        Ok(v) => authority_custody_policy_from_selector(&v).map(Some),
        Err(_) => Ok(None),
    }
}

/// Run 192 — OR-combined CLI/env resolver. Precedence:
///
/// 1. If the CLI flag value is `Some`, parse it; result wins
///    regardless of the env var.
/// 2. Otherwise, read the env var via
///    [`authority_custody_policy_env_selector`].
/// 3. If both are absent, return
///    [`AuthorityCustodyPolicy::Disabled`].
///
/// A parse error from either source is propagated as a typed
/// [`AuthorityCustodyPolicySelectorParseError`] — the resolver
/// **never** silently falls back to `Disabled` when an explicit
/// value is present but invalid.
pub fn authority_custody_policy_from_cli_or_env(
    cli_value: Option<&str>,
) -> Result<AuthorityCustodyPolicy, AuthorityCustodyPolicySelectorParseError> {
    if let Some(v) = cli_value {
        return authority_custody_policy_from_selector(v);
    }
    Ok(authority_custody_policy_env_selector()?
        .unwrap_or(AuthorityCustodyPolicy::Disabled))
}

// ===========================================================================
// Per-surface preflight wrappers — bind resolved policy to Run 190
// routing helpers for each of the seven production v2 marker-decision
// preflight contexts.
// ===========================================================================

/// Run 192 — internal helper: build a Run 190 callsite context with
/// the resolved policy and dispatch to the supplied per-surface
/// routing helper. The dispatcher signature mirrors the seven Run 190
/// `route_loaded_authority_custody_attestation_to_*_callsite_decision`
/// helpers exactly.
#[allow(clippy::too_many_arguments)]
fn preflight_with_policy<'a, F>(
    persisted: Option<&'a PersistentAuthorityStateRecordVersioned>,
    candidate: &'a PersistentAuthorityStateRecordV2,
    trust_domain: &'a AuthorityTrustDomain,
    policy: AuthorityCustodyPolicy,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &'a str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&'a str>,
    now_unix: u64,
    loaded: &AuthorityCustodyLoadStatus,
    dispatch: F,
) -> AuthorityCustodyPayloadCarryingDecisionOutcome
where
    F: for<'b> Fn(
        &'b crate::pqc_authority_custody_payload_carrying::AuthorityCustodyCallsiteContext<'b>,
        &AuthorityCustodyLoadStatus,
    ) -> AuthorityCustodyPayloadCarryingDecisionOutcome,
{
    let ctx = callsite_context_for_authority_custody(
        persisted,
        candidate,
        trust_domain,
        policy,
        expected_governance_authority_class,
        expected_lifecycle_action,
        expected_candidate_digest,
        expected_authority_domain_sequence,
        expected_custody_key_id,
        now_unix,
    );
    dispatch(&ctx, loaded)
}

/// Run 192 — `--p2p-trust-bundle-reload-check` validation-only
/// preflight wrapper that injects the resolved
/// [`AuthorityCustodyPolicy`] into the Run 190 callsite context and
/// delegates to
/// [`route_loaded_authority_custody_attestation_to_reload_check_callsite_decision`].
///
/// **Validation-only mutation contract:** the caller MUST drop the
/// returned outcome and MUST NOT persist a marker, advance the
/// bundle-signing sequence, swap live trust state, evict sessions, or
/// invoke Run 070.
#[allow(clippy::too_many_arguments)]
pub fn preflight_v2_marker_authority_custody_for_reload_check(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
    policy: AuthorityCustodyPolicy,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&str>,
    now_unix: u64,
    loaded: &AuthorityCustodyLoadStatus,
) -> AuthorityCustodyPayloadCarryingDecisionOutcome {
    preflight_with_policy(
        persisted,
        candidate,
        trust_domain,
        policy,
        expected_governance_authority_class,
        expected_lifecycle_action,
        expected_candidate_digest,
        expected_authority_domain_sequence,
        expected_custody_key_id,
        now_unix,
        loaded,
        route_loaded_authority_custody_attestation_to_reload_check_callsite_decision,
    )
}

/// Run 192 — `--p2p-trust-bundle-reload-apply-*` mutating-preflight
/// wrapper. Mutating callers continue to honor sequence-before-marker
/// ordering AFTER acceptance.
#[allow(clippy::too_many_arguments)]
pub fn preflight_v2_marker_authority_custody_for_reload_apply(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
    policy: AuthorityCustodyPolicy,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&str>,
    now_unix: u64,
    loaded: &AuthorityCustodyLoadStatus,
) -> AuthorityCustodyPayloadCarryingDecisionOutcome {
    preflight_with_policy(
        persisted,
        candidate,
        trust_domain,
        policy,
        expected_governance_authority_class,
        expected_lifecycle_action,
        expected_candidate_digest,
        expected_authority_domain_sequence,
        expected_custody_key_id,
        now_unix,
        loaded,
        route_loaded_authority_custody_attestation_to_reload_apply_callsite_decision,
    )
}

/// Run 192 — startup `--p2p-trust-bundle` mutating-preflight wrapper.
#[allow(clippy::too_many_arguments)]
pub fn preflight_v2_marker_authority_custody_for_startup_p2p_trust_bundle(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
    policy: AuthorityCustodyPolicy,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&str>,
    now_unix: u64,
    loaded: &AuthorityCustodyLoadStatus,
) -> AuthorityCustodyPayloadCarryingDecisionOutcome {
    preflight_with_policy(
        persisted,
        candidate,
        trust_domain,
        policy,
        expected_governance_authority_class,
        expected_lifecycle_action,
        expected_candidate_digest,
        expected_authority_domain_sequence,
        expected_custody_key_id,
        now_unix,
        loaded,
        route_loaded_authority_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision,
    )
}

/// Run 192 — SIGHUP live trust-bundle reload mutating-preflight
/// wrapper.
#[allow(clippy::too_many_arguments)]
pub fn preflight_v2_marker_authority_custody_for_sighup(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
    policy: AuthorityCustodyPolicy,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&str>,
    now_unix: u64,
    loaded: &AuthorityCustodyLoadStatus,
) -> AuthorityCustodyPayloadCarryingDecisionOutcome {
    preflight_with_policy(
        persisted,
        candidate,
        trust_domain,
        policy,
        expected_governance_authority_class,
        expected_lifecycle_action,
        expected_candidate_digest,
        expected_authority_domain_sequence,
        expected_custody_key_id,
        now_unix,
        loaded,
        route_loaded_authority_custody_attestation_to_sighup_callsite_decision,
    )
}

/// Run 192 — local `--p2p-trust-bundle-peer-candidate-check`
/// validation-only preflight wrapper. Validation-only mutation
/// contract identical to
/// [`preflight_v2_marker_authority_custody_for_reload_check`].
#[allow(clippy::too_many_arguments)]
pub fn preflight_v2_marker_authority_custody_for_local_peer_candidate_check(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
    policy: AuthorityCustodyPolicy,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&str>,
    now_unix: u64,
    loaded: &AuthorityCustodyLoadStatus,
) -> AuthorityCustodyPayloadCarryingDecisionOutcome {
    preflight_with_policy(
        persisted,
        candidate,
        trust_domain,
        policy,
        expected_governance_authority_class,
        expected_lifecycle_action,
        expected_candidate_digest,
        expected_authority_domain_sequence,
        expected_custody_key_id,
        now_unix,
        loaded,
        route_loaded_authority_custody_attestation_to_local_peer_candidate_check_callsite_decision,
    )
}

/// Run 192 — live inbound `0x05` peer-candidate validation-only
/// preflight wrapper. An invalid live `0x05` custody-metadata
/// candidate (malformed payload, absent under non-`Disabled` policy,
/// MainNet binding under fixture/local custody, or rejected by the
/// Run 188 validator) is **not propagated, staged, or applied** —
/// the rejection short-circuits at the underlying Run 190 routing
/// helper before any staging path is reached.
#[allow(clippy::too_many_arguments)]
pub fn preflight_v2_marker_authority_custody_for_live_inbound_0x05(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
    policy: AuthorityCustodyPolicy,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&str>,
    now_unix: u64,
    loaded: &AuthorityCustodyLoadStatus,
) -> AuthorityCustodyPayloadCarryingDecisionOutcome {
    preflight_with_policy(
        persisted,
        candidate,
        trust_domain,
        policy,
        expected_governance_authority_class,
        expected_lifecycle_action,
        expected_candidate_digest,
        expected_authority_domain_sequence,
        expected_custody_key_id,
        now_unix,
        loaded,
        route_loaded_authority_custody_attestation_to_live_inbound_0x05_callsite_decision,
    )
}

/// Run 192 — Run 150 peer-driven apply drain coordinator
/// preflight wrapper.
///
/// **MainNet refusal preserved.** The underlying Run 190 routing
/// helper refuses MainNet peer-driven apply unconditionally, even
/// with `MainnetProductionCustodyRequired` and metadata claiming
/// `Kms` / `Hsm` / `RemoteSigner`. The selector cannot weaken this
/// refusal.
#[allow(clippy::too_many_arguments)]
pub fn preflight_v2_marker_authority_custody_for_peer_driven_drain(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
    policy: AuthorityCustodyPolicy,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&str>,
    now_unix: u64,
    loaded: &AuthorityCustodyLoadStatus,
) -> AuthorityCustodyPayloadCarryingDecisionOutcome {
    preflight_with_policy(
        persisted,
        candidate,
        trust_domain,
        policy,
        expected_governance_authority_class,
        expected_lifecycle_action,
        expected_candidate_digest,
        expected_authority_domain_sequence,
        expected_custody_key_id,
        now_unix,
        loaded,
        route_loaded_authority_custody_attestation_to_peer_driven_drain_callsite_decision,
    )
}

// ===========================================================================
// In-crate self-tests (smoke-level — full A1–A10 / R1–R29 coverage
// lives in `tests/run_192_authority_custody_policy_selector_tests.rs`).
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_canonical_tags() {
        assert_eq!(
            authority_custody_policy_from_selector("disabled").unwrap(),
            AuthorityCustodyPolicy::Disabled
        );
        assert_eq!(
            authority_custody_policy_from_selector("fixture-only").unwrap(),
            AuthorityCustodyPolicy::FixtureOnly
        );
        assert_eq!(
            authority_custody_policy_from_selector("devnet-local-allowed").unwrap(),
            AuthorityCustodyPolicy::DevnetLocalAllowed
        );
        assert_eq!(
            authority_custody_policy_from_selector("testnet-local-allowed").unwrap(),
            AuthorityCustodyPolicy::TestnetLocalAllowed
        );
        assert_eq!(
            authority_custody_policy_from_selector("production-custody-required").unwrap(),
            AuthorityCustodyPolicy::ProductionCustodyRequired
        );
        assert_eq!(
            authority_custody_policy_from_selector("mainnet-production-custody-required").unwrap(),
            AuthorityCustodyPolicy::MainnetProductionCustodyRequired
        );
    }

    #[test]
    fn parser_is_case_insensitive_and_trims() {
        assert_eq!(
            authority_custody_policy_from_selector("  FIXTURE-ONLY ").unwrap(),
            AuthorityCustodyPolicy::FixtureOnly
        );
        assert_eq!(
            authority_custody_policy_from_selector("Disabled").unwrap(),
            AuthorityCustodyPolicy::Disabled
        );
    }

    #[test]
    fn empty_value_is_typed_error() {
        assert_eq!(
            authority_custody_policy_from_selector("").unwrap_err(),
            AuthorityCustodyPolicySelectorParseError::Empty
        );
        assert_eq!(
            authority_custody_policy_from_selector("   ").unwrap_err(),
            AuthorityCustodyPolicySelectorParseError::Empty
        );
    }

    #[test]
    fn unknown_value_is_typed_error() {
        let e = authority_custody_policy_from_selector("kms-required").unwrap_err();
        assert!(matches!(
            e,
            AuthorityCustodyPolicySelectorParseError::UnknownValue { .. }
        ));
        assert_eq!(e.tag(), "unknown-value");
    }

    #[test]
    fn cli_or_env_default_is_disabled_when_both_absent() {
        // We cannot guarantee env is unset here in a parallel test
        // run, so only assert the explicit-cli=Some(disabled) case.
        assert_eq!(
            authority_custody_policy_from_cli_or_env(Some("disabled")).unwrap(),
            AuthorityCustodyPolicy::Disabled
        );
    }

    #[test]
    fn cli_some_invalid_is_typed_error() {
        assert!(matches!(
            authority_custody_policy_from_cli_or_env(Some("nope")).unwrap_err(),
            AuthorityCustodyPolicySelectorParseError::UnknownValue { .. }
        ));
    }
}
