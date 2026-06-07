//! Run 209 — source/test hidden custody-attestation policy selector and
//! production preflight integration.
//!
//! ## Strict scope (Run 209)
//!
//! * **Source/test only.** Run 209 does **not** capture release-binary
//!   evidence; release-binary custody-attestation-policy selector
//!   evidence is deferred to **Run 210**.
//! * **Hidden selector only.** The selector is exposed via a hidden
//!   clap flag (`--p2p-trust-bundle-custody-attestation-policy`,
//!   `hide = true`) and an equivalent environment variable
//!   (`QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY`). Operators
//!   reading `--help` see no new surface.
//! * **Disabled by default.** When the flag and env var are both absent
//!   the resolved policy is [`CustodyAttestationPolicy::Disabled`]
//!   bit-for-bit. Legacy no-attestation payloads remain accepted exactly
//!   as they were before Run 209 (Run 207 compatibility).
//! * **No real attestation verifier.** `RemoteSignerAttestationRequired`,
//!   `KmsAttestationRequired`, `HsmAttestationRequired`,
//!   `ProductionAttestationRequired`, and
//!   `MainnetProductionAttestationRequired` continue to fail closed as
//!   "unavailable" via the Run 205 verifier regardless of selector. No
//!   real cloud-KMS / PKCS#11 / HSM-vendor attestation verifier, no real
//!   KMS / HSM backend, no real RemoteSigner backend, no networked signer
//!   daemon exists.
//! * **Fixture attestation is DevNet/TestNet evidence-only.**
//!   `FixtureAttestationAllowed` cannot satisfy MainNet production
//!   attestation and cannot enable MainNet peer-driven apply.
//! * **No MainNet peer-driven apply enablement.** The Run 147 / 148 /
//!   152 MainNet refusal at the peer-driven apply surface remains intact
//!   even with `MainnetProductionAttestationRequired` and fixture
//!   attestation material.
//! * **No governance execution engine, no real on-chain proof
//!   verifier, no validator-set rotation, no autonomous apply, no apply
//!   on receipt, no peer-majority authority.**
//! * **No marker / sequence-file / authority-marker / trust-bundle
//!   core / wire / schema change.** Run 209 only adds source-level
//!   selector parsing and a thin shim around the Run 207 per-surface
//!   routing helpers that injects the resolved policy into the call-site
//!   context.
//!
//! Run 209 does **not** weaken any prior run (Runs 070, 130–208) and
//! does **not** claim full C4 or C5 closure.
//!
//! ## What this module adds
//!
//! 1. The hidden selector environment-variable name
//!    [`QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY_ENV`].
//! 2. A typed [`CustodyAttestationPolicySelectorParseError`] that
//!    distinguishes an unknown selector value from an empty selector
//!    value.
//! 3. Pure parsers [`custody_attestation_policy_from_selector`] and
//!    [`custody_attestation_policy_env_selector`] together with the
//!    CLI/env resolver [`custody_attestation_policy_from_cli_or_env`].
//! 4. Seven thin per-surface preflight wrappers
//!    ([`preflight_v2_marker_custody_attestation_for_*`]) that bind the
//!    resolved [`CustodyAttestationPolicy`] into the Run 207
//!    [`CustodyAttestationCallsiteContext`] used by the matching Run 207
//!    `route_loaded_custody_attestation_to_*_callsite_decision` routing
//!    helper. The wrappers exist so the Run 209 source-reachability claim
//!    ("the selected policy reaches all seven production-context
//!    helpers") is grep-verifiable from each surface.
//!
//! ## Pure / non-mutating
//!
//! The selector parsers perform a single read of the environment and no
//! other I/O. The per-surface preflight wrappers perform no I/O beyond
//! the underlying Run 207 routing helper composition: they write no
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
//! match [`CustodyAttestationPolicy::tag`] exactly:
//!
//! | value                                      | resolved policy                                            |
//! |--------------------------------------------|------------------------------------------------------------|
//! | `disabled`                                 | [`CustodyAttestationPolicy::Disabled`]                     |
//! | `fixture-attestation-allowed`              | [`CustodyAttestationPolicy::FixtureAttestationAllowed`]    |
//! | `remote-signer-attestation-required`       | [`CustodyAttestationPolicy::RemoteSignerAttestationRequired`] |
//! | `kms-attestation-required`                 | [`CustodyAttestationPolicy::KmsAttestationRequired`]       |
//! | `hsm-attestation-required`                 | [`CustodyAttestationPolicy::HsmAttestationRequired`]       |
//! | `production-attestation-required`          | [`CustodyAttestationPolicy::ProductionAttestationRequired`] |
//! | `mainnet-production-attestation-required`  | [`CustodyAttestationPolicy::MainnetProductionAttestationRequired`] |
//!
//! Any other non-empty value fails closed with
//! [`CustodyAttestationPolicySelectorParseError::UnknownValue`]; an empty
//! / whitespace-only value fails closed with
//! [`CustodyAttestationPolicySelectorParseError::Empty`]. A selector
//! parse error is a typed startup/preflight error — the resolver never
//! silently downgrades to `Disabled` when an explicit value is present
//! but invalid.
//!
//! ## Precedence
//!
//! When both sources are supplied, the CLI flag wins. This mirrors the
//! Run 192 authority-custody policy selector and the Run 198
//! RemoteSigner policy selector precedence and the standard CLI/env
//! convention: the operator-supplied command line is the authoritative
//! source for a single invocation. The env var still propagates when the
//! CLI flag is absent.

use crate::pqc_authority_custody::{AuthorityCustodyAttestation, AuthorityCustodyPolicy};
use crate::pqc_authority_lifecycle::{AuthorityTrustDomain, LocalLifecycleAction};
use crate::pqc_authority_state::{
    PersistentAuthorityStateRecordV2, PersistentAuthorityStateRecordVersioned,
};
use crate::pqc_custody_attestation_payload_carrying::{
    callsite_context_for_custody_attestation,
    route_loaded_custody_attestation_to_live_inbound_0x05_callsite_decision,
    route_loaded_custody_attestation_to_local_peer_candidate_check_callsite_decision,
    route_loaded_custody_attestation_to_peer_driven_drain_callsite_decision,
    route_loaded_custody_attestation_to_reload_apply_callsite_decision,
    route_loaded_custody_attestation_to_reload_check_callsite_decision,
    route_loaded_custody_attestation_to_sighup_callsite_decision,
    route_loaded_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision,
    CustodyAttestationCallsiteContext, CustodyAttestationLoadStatus,
    CustodyAttestationPayloadCarryingDecisionOutcome,
};
use crate::pqc_custody_attestation_verifier::CustodyAttestationPolicy;
use crate::pqc_governance_authority::GovernanceAuthorityClass;

// ===========================================================================
// Env-var name + canonical selector tags
// ===========================================================================

/// Run 209 — environment-variable name of the hidden,
/// disabled-by-default custody-attestation policy selector. Accepts the
/// same value grammar as the equivalent CLI flag
/// `--p2p-trust-bundle-custody-attestation-policy`.
///
/// Either source is sufficient to choose a non-default policy; both
/// sources absent / empty preserves the
/// [`CustodyAttestationPolicy::Disabled`] default.
pub const QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY_ENV: &str =
    "QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY";

/// Run 209 — canonical selector tag for
/// [`CustodyAttestationPolicy::Disabled`].
pub const CUSTODY_ATTESTATION_POLICY_TAG_DISABLED: &str = "disabled";
/// Run 209 — canonical selector tag for
/// [`CustodyAttestationPolicy::FixtureAttestationAllowed`].
pub const CUSTODY_ATTESTATION_POLICY_TAG_FIXTURE_ATTESTATION_ALLOWED: &str =
    "fixture-attestation-allowed";
/// Run 209 — canonical selector tag for
/// [`CustodyAttestationPolicy::RemoteSignerAttestationRequired`].
pub const CUSTODY_ATTESTATION_POLICY_TAG_REMOTE_SIGNER_ATTESTATION_REQUIRED: &str =
    "remote-signer-attestation-required";
/// Run 209 — canonical selector tag for
/// [`CustodyAttestationPolicy::KmsAttestationRequired`].
pub const CUSTODY_ATTESTATION_POLICY_TAG_KMS_ATTESTATION_REQUIRED: &str =
    "kms-attestation-required";
/// Run 209 — canonical selector tag for
/// [`CustodyAttestationPolicy::HsmAttestationRequired`].
pub const CUSTODY_ATTESTATION_POLICY_TAG_HSM_ATTESTATION_REQUIRED: &str =
    "hsm-attestation-required";
/// Run 209 — canonical selector tag for
/// [`CustodyAttestationPolicy::ProductionAttestationRequired`].
pub const CUSTODY_ATTESTATION_POLICY_TAG_PRODUCTION_ATTESTATION_REQUIRED: &str =
    "production-attestation-required";
/// Run 209 — canonical selector tag for
/// [`CustodyAttestationPolicy::MainnetProductionAttestationRequired`].
pub const CUSTODY_ATTESTATION_POLICY_TAG_MAINNET_PRODUCTION_ATTESTATION_REQUIRED: &str =
    "mainnet-production-attestation-required";

// ===========================================================================
// Typed selector parse error
// ===========================================================================

/// Run 209 — typed selector parse error. A typed error makes the
/// fail-closed startup/preflight contract grep-verifiable: the resolver
/// never silently downgrades an unknown selector value to
/// [`CustodyAttestationPolicy::Disabled`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyAttestationPolicySelectorParseError {
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

impl CustodyAttestationPolicySelectorParseError {
    /// Stable short tag used by error logs and tests.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::UnknownValue { .. } => "unknown-value",
        }
    }
}

impl std::fmt::Display for CustodyAttestationPolicySelectorParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(
                f,
                "custody-attestation policy selector value is empty (recognized tags: \
                 disabled | fixture-attestation-allowed | remote-signer-attestation-required | \
                 kms-attestation-required | hsm-attestation-required | \
                 production-attestation-required | mainnet-production-attestation-required)"
            ),
            Self::UnknownValue { value } => write!(
                f,
                "custody-attestation policy selector value {value:?} is not recognized \
                 (recognized tags: disabled | fixture-attestation-allowed | \
                 remote-signer-attestation-required | kms-attestation-required | \
                 hsm-attestation-required | production-attestation-required | \
                 mainnet-production-attestation-required)"
            ),
        }
    }
}

impl std::error::Error for CustodyAttestationPolicySelectorParseError {}

// ===========================================================================
// Selector parsers
// ===========================================================================

/// Run 209 — pure selector-string → [`CustodyAttestationPolicy`] parser.
///
/// The matcher is **case-insensitive** and trims surrounding ASCII
/// whitespace before matching. An empty / whitespace-only value returns
/// [`CustodyAttestationPolicySelectorParseError::Empty`]; an unknown
/// non-empty value returns
/// [`CustodyAttestationPolicySelectorParseError::UnknownValue`].
///
/// The parser is the single source of truth for both the CLI and env
/// surfaces: see [`custody_attestation_policy_env_selector`] and
/// [`custody_attestation_policy_from_cli_or_env`].
pub fn custody_attestation_policy_from_selector(
    value: &str,
) -> Result<CustodyAttestationPolicy, CustodyAttestationPolicySelectorParseError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(CustodyAttestationPolicySelectorParseError::Empty);
    }
    if trimmed.eq_ignore_ascii_case(CUSTODY_ATTESTATION_POLICY_TAG_DISABLED) {
        Ok(CustodyAttestationPolicy::Disabled)
    } else if trimmed
        .eq_ignore_ascii_case(CUSTODY_ATTESTATION_POLICY_TAG_FIXTURE_ATTESTATION_ALLOWED)
    {
        Ok(CustodyAttestationPolicy::FixtureAttestationAllowed)
    } else if trimmed
        .eq_ignore_ascii_case(CUSTODY_ATTESTATION_POLICY_TAG_REMOTE_SIGNER_ATTESTATION_REQUIRED)
    {
        Ok(CustodyAttestationPolicy::RemoteSignerAttestationRequired)
    } else if trimmed.eq_ignore_ascii_case(CUSTODY_ATTESTATION_POLICY_TAG_KMS_ATTESTATION_REQUIRED)
    {
        Ok(CustodyAttestationPolicy::KmsAttestationRequired)
    } else if trimmed.eq_ignore_ascii_case(CUSTODY_ATTESTATION_POLICY_TAG_HSM_ATTESTATION_REQUIRED)
    {
        Ok(CustodyAttestationPolicy::HsmAttestationRequired)
    } else if trimmed
        .eq_ignore_ascii_case(CUSTODY_ATTESTATION_POLICY_TAG_PRODUCTION_ATTESTATION_REQUIRED)
    {
        Ok(CustodyAttestationPolicy::ProductionAttestationRequired)
    } else if trimmed.eq_ignore_ascii_case(
        CUSTODY_ATTESTATION_POLICY_TAG_MAINNET_PRODUCTION_ATTESTATION_REQUIRED,
    ) {
        Ok(CustodyAttestationPolicy::MainnetProductionAttestationRequired)
    } else {
        Err(CustodyAttestationPolicySelectorParseError::UnknownValue {
            value: trimmed.to_string(),
        })
    }
}

/// Run 209 — pure environment-variable readback for the hidden
/// custody-attestation policy selector.
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
/// pure. It is intentionally exposed (instead of inlined) so the Run 209
/// source-test matrix can drive the selector deterministically by
/// setting/unsetting the env var.
pub fn custody_attestation_policy_env_selector(
) -> Result<Option<CustodyAttestationPolicy>, CustodyAttestationPolicySelectorParseError> {
    match std::env::var(QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY_ENV) {
        Ok(v) => custody_attestation_policy_from_selector(&v).map(Some),
        Err(_) => Ok(None),
    }
}

/// Run 209 — CLI/env resolver. Precedence:
///
/// 1. If the CLI flag value is `Some`, parse it; result wins regardless
///    of the env var.
/// 2. Otherwise, read the env var via
///    [`custody_attestation_policy_env_selector`].
/// 3. If both are absent, return [`CustodyAttestationPolicy::Disabled`].
///
/// A parse error from either source is propagated as a typed
/// [`CustodyAttestationPolicySelectorParseError`] — the resolver
/// **never** silently falls back to `Disabled` when an explicit value is
/// present but invalid.
pub fn custody_attestation_policy_from_cli_or_env(
    cli_value: Option<&str>,
) -> Result<CustodyAttestationPolicy, CustodyAttestationPolicySelectorParseError> {
    if let Some(v) = cli_value {
        return custody_attestation_policy_from_selector(v);
    }
    Ok(custody_attestation_policy_env_selector()?.unwrap_or(CustodyAttestationPolicy::Disabled))
}

// ===========================================================================
// Per-surface preflight wrappers — bind resolved policy to Run 207
// routing helpers for each of the seven production v2 marker-decision
// preflight contexts.
// ===========================================================================

/// Run 209 — internal helper: build a Run 207 callsite context with the
/// resolved custody-attestation policy and dispatch to the supplied
/// per-surface routing helper. The dispatcher signature mirrors the seven
/// Run 207 `route_loaded_custody_attestation_to_*_callsite_decision`
/// helpers exactly.
#[allow(clippy::too_many_arguments)]
fn preflight_with_policy<F>(
    custody_attestation: &AuthorityCustodyAttestation,
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&str>,
    custody_policy: AuthorityCustodyPolicy,
    attestation_policy: CustodyAttestationPolicy,
    now_unix: u64,
    loaded: &CustodyAttestationLoadStatus,
    dispatch: F,
) -> CustodyAttestationPayloadCarryingDecisionOutcome
where
    F: Fn(
        &CustodyAttestationCallsiteContext<'_>,
        &CustodyAttestationLoadStatus,
    ) -> CustodyAttestationPayloadCarryingDecisionOutcome,
{
    let ctx = callsite_context_for_custody_attestation(
        custody_attestation,
        persisted,
        candidate,
        trust_domain,
        expected_governance_authority_class,
        expected_lifecycle_action,
        expected_candidate_digest,
        expected_authority_domain_sequence,
        expected_custody_key_id,
        custody_policy,
        attestation_policy,
        now_unix,
    );
    dispatch(&ctx, loaded)
}

/// Run 209 — `--p2p-trust-bundle-reload-check` validation-only preflight
/// wrapper that injects the resolved [`CustodyAttestationPolicy`] into
/// the Run 207 callsite context and delegates to
/// [`route_loaded_custody_attestation_to_reload_check_callsite_decision`].
///
/// **Validation-only mutation contract:** the caller MUST drop the
/// returned outcome and MUST NOT persist a marker, advance the
/// bundle-signing sequence, swap live trust state, evict sessions, or
/// invoke Run 070.
#[allow(clippy::too_many_arguments)]
pub fn preflight_v2_marker_custody_attestation_for_reload_check(
    custody_attestation: &AuthorityCustodyAttestation,
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&str>,
    custody_policy: AuthorityCustodyPolicy,
    attestation_policy: CustodyAttestationPolicy,
    now_unix: u64,
    loaded: &CustodyAttestationLoadStatus,
) -> CustodyAttestationPayloadCarryingDecisionOutcome {
    preflight_with_policy(
        custody_attestation,
        persisted,
        candidate,
        trust_domain,
        expected_governance_authority_class,
        expected_lifecycle_action,
        expected_candidate_digest,
        expected_authority_domain_sequence,
        expected_custody_key_id,
        custody_policy,
        attestation_policy,
        now_unix,
        loaded,
        route_loaded_custody_attestation_to_reload_check_callsite_decision,
    )
}

/// Run 209 — `--p2p-trust-bundle-reload-apply-*` mutating-preflight
/// wrapper. Mutating callers continue to honor sequence-before-marker
/// ordering AFTER acceptance.
#[allow(clippy::too_many_arguments)]
pub fn preflight_v2_marker_custody_attestation_for_reload_apply(
    custody_attestation: &AuthorityCustodyAttestation,
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&str>,
    custody_policy: AuthorityCustodyPolicy,
    attestation_policy: CustodyAttestationPolicy,
    now_unix: u64,
    loaded: &CustodyAttestationLoadStatus,
) -> CustodyAttestationPayloadCarryingDecisionOutcome {
    preflight_with_policy(
        custody_attestation,
        persisted,
        candidate,
        trust_domain,
        expected_governance_authority_class,
        expected_lifecycle_action,
        expected_candidate_digest,
        expected_authority_domain_sequence,
        expected_custody_key_id,
        custody_policy,
        attestation_policy,
        now_unix,
        loaded,
        route_loaded_custody_attestation_to_reload_apply_callsite_decision,
    )
}

/// Run 209 — startup `--p2p-trust-bundle` mutating-preflight wrapper.
#[allow(clippy::too_many_arguments)]
pub fn preflight_v2_marker_custody_attestation_for_startup_p2p_trust_bundle(
    custody_attestation: &AuthorityCustodyAttestation,
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&str>,
    custody_policy: AuthorityCustodyPolicy,
    attestation_policy: CustodyAttestationPolicy,
    now_unix: u64,
    loaded: &CustodyAttestationLoadStatus,
) -> CustodyAttestationPayloadCarryingDecisionOutcome {
    preflight_with_policy(
        custody_attestation,
        persisted,
        candidate,
        trust_domain,
        expected_governance_authority_class,
        expected_lifecycle_action,
        expected_candidate_digest,
        expected_authority_domain_sequence,
        expected_custody_key_id,
        custody_policy,
        attestation_policy,
        now_unix,
        loaded,
        route_loaded_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision,
    )
}

/// Run 209 — SIGHUP live trust-bundle reload mutating-preflight wrapper.
#[allow(clippy::too_many_arguments)]
pub fn preflight_v2_marker_custody_attestation_for_sighup(
    custody_attestation: &AuthorityCustodyAttestation,
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&str>,
    custody_policy: AuthorityCustodyPolicy,
    attestation_policy: CustodyAttestationPolicy,
    now_unix: u64,
    loaded: &CustodyAttestationLoadStatus,
) -> CustodyAttestationPayloadCarryingDecisionOutcome {
    preflight_with_policy(
        custody_attestation,
        persisted,
        candidate,
        trust_domain,
        expected_governance_authority_class,
        expected_lifecycle_action,
        expected_candidate_digest,
        expected_authority_domain_sequence,
        expected_custody_key_id,
        custody_policy,
        attestation_policy,
        now_unix,
        loaded,
        route_loaded_custody_attestation_to_sighup_callsite_decision,
    )
}

/// Run 209 — local `--p2p-trust-bundle-peer-candidate-check`
/// validation-only preflight wrapper. Validation-only mutation contract
/// identical to
/// [`preflight_v2_marker_custody_attestation_for_reload_check`].
#[allow(clippy::too_many_arguments)]
pub fn preflight_v2_marker_custody_attestation_for_local_peer_candidate_check(
    custody_attestation: &AuthorityCustodyAttestation,
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&str>,
    custody_policy: AuthorityCustodyPolicy,
    attestation_policy: CustodyAttestationPolicy,
    now_unix: u64,
    loaded: &CustodyAttestationLoadStatus,
) -> CustodyAttestationPayloadCarryingDecisionOutcome {
    preflight_with_policy(
        custody_attestation,
        persisted,
        candidate,
        trust_domain,
        expected_governance_authority_class,
        expected_lifecycle_action,
        expected_candidate_digest,
        expected_authority_domain_sequence,
        expected_custody_key_id,
        custody_policy,
        attestation_policy,
        now_unix,
        loaded,
        route_loaded_custody_attestation_to_local_peer_candidate_check_callsite_decision,
    )
}

/// Run 209 — live inbound `0x05` peer-candidate validation-only preflight
/// wrapper. An invalid live `0x05` custody-attestation candidate
/// (malformed payload, absent under non-`Disabled` policy, MainNet
/// binding under fixture attestation, or rejected by the Run 205
/// verifier) is **not propagated, staged, or applied** — the rejection
/// short-circuits at the underlying Run 207 routing helper before any
/// staging path is reached.
#[allow(clippy::too_many_arguments)]
pub fn preflight_v2_marker_custody_attestation_for_live_inbound_0x05(
    custody_attestation: &AuthorityCustodyAttestation,
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&str>,
    custody_policy: AuthorityCustodyPolicy,
    attestation_policy: CustodyAttestationPolicy,
    now_unix: u64,
    loaded: &CustodyAttestationLoadStatus,
) -> CustodyAttestationPayloadCarryingDecisionOutcome {
    preflight_with_policy(
        custody_attestation,
        persisted,
        candidate,
        trust_domain,
        expected_governance_authority_class,
        expected_lifecycle_action,
        expected_candidate_digest,
        expected_authority_domain_sequence,
        expected_custody_key_id,
        custody_policy,
        attestation_policy,
        now_unix,
        loaded,
        route_loaded_custody_attestation_to_live_inbound_0x05_callsite_decision,
    )
}

/// Run 209 — Run 150 peer-driven apply drain coordinator preflight
/// wrapper.
///
/// **MainNet refusal preserved.** The underlying Run 207 routing helper
/// refuses MainNet peer-driven apply unconditionally, even with
/// `MainnetProductionAttestationRequired` and fully-valid fixture
/// attestation material. The selector cannot weaken this refusal.
#[allow(clippy::too_many_arguments)]
pub fn preflight_v2_marker_custody_attestation_for_peer_driven_drain(
    custody_attestation: &AuthorityCustodyAttestation,
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&str>,
    custody_policy: AuthorityCustodyPolicy,
    attestation_policy: CustodyAttestationPolicy,
    now_unix: u64,
    loaded: &CustodyAttestationLoadStatus,
) -> CustodyAttestationPayloadCarryingDecisionOutcome {
    preflight_with_policy(
        custody_attestation,
        persisted,
        candidate,
        trust_domain,
        expected_governance_authority_class,
        expected_lifecycle_action,
        expected_candidate_digest,
        expected_authority_domain_sequence,
        expected_custody_key_id,
        custody_policy,
        attestation_policy,
        now_unix,
        loaded,
        route_loaded_custody_attestation_to_peer_driven_drain_callsite_decision,
    )
}

// ===========================================================================
// In-crate self-tests (smoke-level — full A1–A15 / R1–R40 coverage lives
// in `tests/run_209_custody_attestation_policy_selector_tests.rs`).
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_canonical_tags() {
        assert_eq!(
            custody_attestation_policy_from_selector("disabled").unwrap(),
            CustodyAttestationPolicy::Disabled
        );
        assert_eq!(
            custody_attestation_policy_from_selector("fixture-attestation-allowed").unwrap(),
            CustodyAttestationPolicy::FixtureAttestationAllowed
        );
        assert_eq!(
            custody_attestation_policy_from_selector("remote-signer-attestation-required").unwrap(),
            CustodyAttestationPolicy::RemoteSignerAttestationRequired
        );
        assert_eq!(
            custody_attestation_policy_from_selector("kms-attestation-required").unwrap(),
            CustodyAttestationPolicy::KmsAttestationRequired
        );
        assert_eq!(
            custody_attestation_policy_from_selector("hsm-attestation-required").unwrap(),
            CustodyAttestationPolicy::HsmAttestationRequired
        );
        assert_eq!(
            custody_attestation_policy_from_selector("production-attestation-required").unwrap(),
            CustodyAttestationPolicy::ProductionAttestationRequired
        );
        assert_eq!(
            custody_attestation_policy_from_selector("mainnet-production-attestation-required")
                .unwrap(),
            CustodyAttestationPolicy::MainnetProductionAttestationRequired
        );
    }

    #[test]
    fn canonical_tags_match_policy_tag_method() {
        assert_eq!(
            CUSTODY_ATTESTATION_POLICY_TAG_DISABLED,
            CustodyAttestationPolicy::Disabled.tag()
        );
        assert_eq!(
            CUSTODY_ATTESTATION_POLICY_TAG_FIXTURE_ATTESTATION_ALLOWED,
            CustodyAttestationPolicy::FixtureAttestationAllowed.tag()
        );
        assert_eq!(
            CUSTODY_ATTESTATION_POLICY_TAG_REMOTE_SIGNER_ATTESTATION_REQUIRED,
            CustodyAttestationPolicy::RemoteSignerAttestationRequired.tag()
        );
        assert_eq!(
            CUSTODY_ATTESTATION_POLICY_TAG_KMS_ATTESTATION_REQUIRED,
            CustodyAttestationPolicy::KmsAttestationRequired.tag()
        );
        assert_eq!(
            CUSTODY_ATTESTATION_POLICY_TAG_HSM_ATTESTATION_REQUIRED,
            CustodyAttestationPolicy::HsmAttestationRequired.tag()
        );
        assert_eq!(
            CUSTODY_ATTESTATION_POLICY_TAG_PRODUCTION_ATTESTATION_REQUIRED,
            CustodyAttestationPolicy::ProductionAttestationRequired.tag()
        );
        assert_eq!(
            CUSTODY_ATTESTATION_POLICY_TAG_MAINNET_PRODUCTION_ATTESTATION_REQUIRED,
            CustodyAttestationPolicy::MainnetProductionAttestationRequired.tag()
        );
    }

    #[test]
    fn parser_is_case_insensitive_and_trims() {
        assert_eq!(
            custody_attestation_policy_from_selector("  FIXTURE-ATTESTATION-ALLOWED ").unwrap(),
            CustodyAttestationPolicy::FixtureAttestationAllowed
        );
        assert_eq!(
            custody_attestation_policy_from_selector("Disabled").unwrap(),
            CustodyAttestationPolicy::Disabled
        );
    }

    #[test]
    fn empty_value_is_typed_error() {
        assert_eq!(
            custody_attestation_policy_from_selector("").unwrap_err(),
            CustodyAttestationPolicySelectorParseError::Empty
        );
        assert_eq!(
            custody_attestation_policy_from_selector("   ").unwrap_err(),
            CustodyAttestationPolicySelectorParseError::Empty
        );
    }

    #[test]
    fn unknown_value_is_typed_error() {
        let e = custody_attestation_policy_from_selector("totally-bogus").unwrap_err();
        assert!(matches!(
            e,
            CustodyAttestationPolicySelectorParseError::UnknownValue { .. }
        ));
        assert_eq!(e.tag(), "unknown-value");
    }

    #[test]
    fn cli_or_env_disabled_when_cli_disabled() {
        // We cannot guarantee env is unset here in a parallel test run,
        // so only assert the explicit-cli=Some(disabled) case.
        assert_eq!(
            custody_attestation_policy_from_cli_or_env(Some("disabled")).unwrap(),
            CustodyAttestationPolicy::Disabled
        );
    }

    #[test]
    fn cli_some_invalid_is_typed_error() {
        assert!(matches!(
            custody_attestation_policy_from_cli_or_env(Some("nope")).unwrap_err(),
            CustodyAttestationPolicySelectorParseError::UnknownValue { .. }
        ));
    }
}