//! Run 198 — source/test hidden RemoteSigner policy selector and
//! production preflight integration.
//!
//! ## Strict scope (Run 198)
//!
//! * **Source/test only.** Run 198 does **not** capture release-binary
//!   evidence; release-binary RemoteSigner-policy selector evidence is
//!   deferred to **Run 199**.
//! * **Hidden selector only.** The selector is exposed via a hidden
//!   clap flag (`--p2p-trust-bundle-remote-signer-policy`,
//!   `hide = true`) and an equivalent environment variable
//!   (`QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY`). Operators reading
//!   `--help` see no new surface.
//! * **Disabled by default.** When the flag and env var are both absent
//!   the resolved policy is [`RemoteSignerPolicy::Disabled`]
//!   bit-for-bit. Legacy no-RemoteSigner payloads remain accepted
//!   exactly as they were before Run 198 (Run 196 compatibility).
//! * **No real RemoteSigner backend.** `ProductionRemoteSignerRequired`
//!   and `MainnetProductionRemoteSignerRequired` continue to fail
//!   closed as "unavailable" via the Run 194 verifier regardless of
//!   selector. No networked signer service, no real
//!   KMS/HSM/cloud-KMS/PKCS#11 backend exists.
//! * **Fixture loopback is DevNet/TestNet evidence-only.**
//!   `FixtureLoopbackAllowed` cannot satisfy MainNet production
//!   RemoteSigner and cannot enable MainNet peer-driven apply.
//! * **No MainNet peer-driven apply enablement.** The Run 147 / 148 /
//!   152 MainNet refusal at the peer-driven apply surface remains
//!   intact even with `MainnetProductionRemoteSignerRequired` and
//!   fixture loopback material.
//! * **No governance execution engine, no real on-chain proof
//!   verifier, no validator-set rotation, no autonomous apply, no
//!   apply on receipt, no peer-majority authority.**
//! * **No marker / sequence-file / authority-marker / trust-bundle
//!   core / wire / schema change.** Run 198 only adds source-level
//!   selector parsing and a thin shim around the Run 196 per-surface
//!   routing helpers that injects the resolved policy into the
//!   call-site context.
//!
//! Run 198 does **not** weaken any prior run (Runs 070, 130–197) and
//! does **not** claim full C4 or C5 closure.
//!
//! ## What this module adds
//!
//! 1. The hidden selector environment-variable name
//!    [`QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY_ENV`].
//! 2. A typed [`RemoteSignerPolicySelectorParseError`] that
//!    distinguishes an unknown selector value from an empty selector
//!    value.
//! 3. Pure parsers [`remote_signer_policy_from_selector`] and
//!    [`remote_signer_policy_env_selector`] together with the
//!    CLI/env resolver [`remote_signer_policy_from_cli_or_env`].
//! 4. Seven thin per-surface preflight wrappers
//!    ([`preflight_v2_marker_remote_signer_for_*`]) that bind the
//!    resolved [`RemoteSignerPolicy`] into the Run 196
//!    [`RemoteSignerCallsiteContext`] used by the matching Run 196
//!    `route_loaded_remote_signer_attestation_to_*_callsite_decision`
//!    routing helper. The wrappers exist so the Run 198 source
//!    reachability claim ("the selected policy reaches all seven
//!    production-context helpers") is grep-verifiable from each
//!    surface.
//!
//! ## Pure / non-mutating
//!
//! The selector parsers perform a single read of the environment and
//! no other I/O. The per-surface preflight wrappers perform no I/O
//! beyond the underlying Run 196 routing helper composition: they
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
//! (case-insensitive; surrounding ASCII whitespace is trimmed). The
//! tags match [`RemoteSignerPolicy::tag`] exactly:
//!
//! | value                                      | resolved policy                                          |
//! |--------------------------------------------|----------------------------------------------------------|
//! | `disabled`                                 | [`RemoteSignerPolicy::Disabled`]                         |
//! | `fixture-loopback-allowed`                 | [`RemoteSignerPolicy::FixtureLoopbackAllowed`]           |
//! | `production-remote-signer-required`        | [`RemoteSignerPolicy::ProductionRemoteSignerRequired`]   |
//! | `mainnet-production-remote-signer-required`| [`RemoteSignerPolicy::MainnetProductionRemoteSignerRequired`] |
//!
//! Any other non-empty value fails closed with
//! [`RemoteSignerPolicySelectorParseError::UnknownValue`]; an empty /
//! whitespace-only value fails closed with
//! [`RemoteSignerPolicySelectorParseError::Empty`]. A selector parse
//! error is a typed startup/preflight error — the resolver never
//! silently downgrades to `Disabled` when an explicit value is present
//! but invalid.
//!
//! ## Precedence
//!
//! When both sources are supplied, the CLI flag wins. This mirrors
//! the Run 192 authority-custody policy selector precedence and the
//! standard CLI/env convention: the operator-supplied command line is
//! the authoritative source for a single invocation. The env var still
//! propagates when the CLI flag is absent.

use crate::pqc_authority_custody::{AuthorityCustodyAttestation, AuthorityCustodyPolicy};
use crate::pqc_authority_lifecycle::{AuthorityTrustDomain, LocalLifecycleAction};
use crate::pqc_authority_state::{
    PersistentAuthorityStateRecordV2, PersistentAuthorityStateRecordVersioned,
};
use crate::pqc_governance_authority::GovernanceAuthorityClass;
use crate::pqc_remote_authority_signer::{RemoteSignerExpectations, RemoteSignerPolicy};
use crate::pqc_remote_signer_payload_carrying::{
    callsite_context_for_remote_signer,
    route_loaded_remote_signer_attestation_to_live_inbound_0x05_callsite_decision,
    route_loaded_remote_signer_attestation_to_local_peer_candidate_check_callsite_decision,
    route_loaded_remote_signer_attestation_to_peer_driven_drain_callsite_decision,
    route_loaded_remote_signer_attestation_to_reload_apply_callsite_decision,
    route_loaded_remote_signer_attestation_to_reload_check_callsite_decision,
    route_loaded_remote_signer_attestation_to_sighup_callsite_decision,
    route_loaded_remote_signer_attestation_to_startup_p2p_trust_bundle_callsite_decision,
    RemoteSignerCallsiteContext, RemoteSignerLoadStatus,
    RemoteSignerPayloadCarryingDecisionOutcome,
};

// ===========================================================================
// Env-var name + canonical selector tags
// ===========================================================================

/// Run 198 — environment-variable name of the hidden,
/// disabled-by-default RemoteSigner policy selector. Accepts the same
/// value grammar as the equivalent CLI flag
/// `--p2p-trust-bundle-remote-signer-policy`.
///
/// Either source is sufficient to choose a non-default policy; both
/// sources absent / empty preserves the [`RemoteSignerPolicy::Disabled`]
/// default.
pub const QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY_ENV: &str =
    "QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY";

/// Run 198 — canonical selector tag for
/// [`RemoteSignerPolicy::Disabled`].
pub const REMOTE_SIGNER_POLICY_TAG_DISABLED: &str = "disabled";
/// Run 198 — canonical selector tag for
/// [`RemoteSignerPolicy::FixtureLoopbackAllowed`].
pub const REMOTE_SIGNER_POLICY_TAG_FIXTURE_LOOPBACK_ALLOWED: &str = "fixture-loopback-allowed";
/// Run 198 — canonical selector tag for
/// [`RemoteSignerPolicy::ProductionRemoteSignerRequired`].
pub const REMOTE_SIGNER_POLICY_TAG_PRODUCTION_REMOTE_SIGNER_REQUIRED: &str =
    "production-remote-signer-required";
/// Run 198 — canonical selector tag for
/// [`RemoteSignerPolicy::MainnetProductionRemoteSignerRequired`].
pub const REMOTE_SIGNER_POLICY_TAG_MAINNET_PRODUCTION_REMOTE_SIGNER_REQUIRED: &str =
    "mainnet-production-remote-signer-required";

// ===========================================================================
// Typed selector parse error
// ===========================================================================

/// Run 198 — typed selector parse error. A typed error makes the
/// fail-closed startup/preflight contract grep-verifiable: the resolver
/// never silently downgrades an unknown selector value to
/// [`RemoteSignerPolicy::Disabled`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteSignerPolicySelectorParseError {
    /// The selector source supplied an empty / whitespace-only value.
    /// An empty explicit selector is rejected — the operator must
    /// either omit the source entirely (preserving the `Disabled`
    /// default) or supply a known tag.
    Empty,
    /// The selector source supplied a value that does not match any
    /// recognized tag. The recognized tags are enumerated in the
    /// module-level docs.
    UnknownValue { value: String },
}

impl RemoteSignerPolicySelectorParseError {
    /// Stable short tag used by error logs and tests.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::UnknownValue { .. } => "unknown-value",
        }
    }
}

impl std::fmt::Display for RemoteSignerPolicySelectorParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(
                f,
                "remote-signer policy selector value is empty (recognized tags: \
                 disabled | fixture-loopback-allowed | production-remote-signer-required | \
                 mainnet-production-remote-signer-required)"
            ),
            Self::UnknownValue { value } => write!(
                f,
                "remote-signer policy selector value {value:?} is not recognized \
                 (recognized tags: disabled | fixture-loopback-allowed | \
                 production-remote-signer-required | \
                 mainnet-production-remote-signer-required)"
            ),
        }
    }
}

impl std::error::Error for RemoteSignerPolicySelectorParseError {}

// ===========================================================================
// Selector parsers
// ===========================================================================

/// Run 198 — pure selector-string → [`RemoteSignerPolicy`] parser.
///
/// The matcher is **case-insensitive** and trims surrounding ASCII
/// whitespace before matching. An empty / whitespace-only value returns
/// [`RemoteSignerPolicySelectorParseError::Empty`]; an unknown non-empty
/// value returns [`RemoteSignerPolicySelectorParseError::UnknownValue`].
///
/// The parser is the single source of truth for both the CLI and env
/// surfaces: see [`remote_signer_policy_env_selector`] and
/// [`remote_signer_policy_from_cli_or_env`].
pub fn remote_signer_policy_from_selector(
    value: &str,
) -> Result<RemoteSignerPolicy, RemoteSignerPolicySelectorParseError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(RemoteSignerPolicySelectorParseError::Empty);
    }
    if trimmed.eq_ignore_ascii_case(REMOTE_SIGNER_POLICY_TAG_DISABLED) {
        Ok(RemoteSignerPolicy::Disabled)
    } else if trimmed.eq_ignore_ascii_case(REMOTE_SIGNER_POLICY_TAG_FIXTURE_LOOPBACK_ALLOWED) {
        Ok(RemoteSignerPolicy::FixtureLoopbackAllowed)
    } else if trimmed
        .eq_ignore_ascii_case(REMOTE_SIGNER_POLICY_TAG_PRODUCTION_REMOTE_SIGNER_REQUIRED)
    {
        Ok(RemoteSignerPolicy::ProductionRemoteSignerRequired)
    } else if trimmed.eq_ignore_ascii_case(
        REMOTE_SIGNER_POLICY_TAG_MAINNET_PRODUCTION_REMOTE_SIGNER_REQUIRED,
    ) {
        Ok(RemoteSignerPolicy::MainnetProductionRemoteSignerRequired)
    } else {
        Err(RemoteSignerPolicySelectorParseError::UnknownValue {
            value: trimmed.to_string(),
        })
    }
}

/// Run 198 — pure environment-variable readback for the hidden
/// RemoteSigner policy selector.
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
/// pure. It is intentionally exposed (instead of inlined) so the
/// Run 198 source-test matrix can drive the selector deterministically
/// by setting/unsetting the env var.
pub fn remote_signer_policy_env_selector(
) -> Result<Option<RemoteSignerPolicy>, RemoteSignerPolicySelectorParseError> {
    match std::env::var(QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY_ENV) {
        Ok(v) => remote_signer_policy_from_selector(&v).map(Some),
        Err(_) => Ok(None),
    }
}

/// Run 198 — CLI/env resolver. Precedence:
///
/// 1. If the CLI flag value is `Some`, parse it; result wins regardless
///    of the env var.
/// 2. Otherwise, read the env var via
///    [`remote_signer_policy_env_selector`].
/// 3. If both are absent, return [`RemoteSignerPolicy::Disabled`].
///
/// A parse error from either source is propagated as a typed
/// [`RemoteSignerPolicySelectorParseError`] — the resolver **never**
/// silently falls back to `Disabled` when an explicit value is present
/// but invalid.
pub fn remote_signer_policy_from_cli_or_env(
    cli_value: Option<&str>,
) -> Result<RemoteSignerPolicy, RemoteSignerPolicySelectorParseError> {
    if let Some(v) = cli_value {
        return remote_signer_policy_from_selector(v);
    }
    Ok(remote_signer_policy_env_selector()?.unwrap_or(RemoteSignerPolicy::Disabled))
}

// ===========================================================================
// Per-surface preflight wrappers — bind resolved policy to Run 196
// routing helpers for each of the seven production v2 marker-decision
// preflight contexts.
// ===========================================================================

/// Run 198 — internal helper: build a Run 196 callsite context with the
/// resolved RemoteSigner policy and dispatch to the supplied per-surface
/// routing helper. The dispatcher signature mirrors the seven Run 196
/// `route_loaded_remote_signer_attestation_to_*_callsite_decision`
/// helpers exactly.
#[allow(clippy::too_many_arguments)]
fn preflight_with_policy<'a, F>(
    custody_attestation: &'a AuthorityCustodyAttestation,
    persisted: Option<&'a PersistentAuthorityStateRecordVersioned>,
    candidate: &'a PersistentAuthorityStateRecordV2,
    trust_domain: &'a AuthorityTrustDomain,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &'a str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&'a str>,
    custody_policy: AuthorityCustodyPolicy,
    remote_signer_expected: &'a RemoteSignerExpectations,
    remote_signer_policy: RemoteSignerPolicy,
    now_unix: u64,
    loaded: &RemoteSignerLoadStatus,
    dispatch: F,
) -> RemoteSignerPayloadCarryingDecisionOutcome
where
    F: for<'b> Fn(
        &'b RemoteSignerCallsiteContext<'b>,
        &RemoteSignerLoadStatus,
    ) -> RemoteSignerPayloadCarryingDecisionOutcome,
{
    let ctx = callsite_context_for_remote_signer(
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
        remote_signer_expected,
        remote_signer_policy,
        now_unix,
    );
    dispatch(&ctx, loaded)
}

/// Run 198 — `--p2p-trust-bundle-reload-check` validation-only preflight
/// wrapper that injects the resolved [`RemoteSignerPolicy`] into the
/// Run 196 callsite context and delegates to
/// [`route_loaded_remote_signer_attestation_to_reload_check_callsite_decision`].
///
/// **Validation-only mutation contract:** the caller MUST drop the
/// returned outcome and MUST NOT persist a marker, advance the
/// bundle-signing sequence, swap live trust state, evict sessions, or
/// invoke Run 070.
#[allow(clippy::too_many_arguments)]
pub fn preflight_v2_marker_remote_signer_for_reload_check(
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
    remote_signer_expected: &RemoteSignerExpectations,
    remote_signer_policy: RemoteSignerPolicy,
    now_unix: u64,
    loaded: &RemoteSignerLoadStatus,
) -> RemoteSignerPayloadCarryingDecisionOutcome {
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
        remote_signer_expected,
        remote_signer_policy,
        now_unix,
        loaded,
        route_loaded_remote_signer_attestation_to_reload_check_callsite_decision,
    )
}

/// Run 198 — `--p2p-trust-bundle-reload-apply-*` mutating-preflight
/// wrapper. Mutating callers continue to honor sequence-before-marker
/// ordering AFTER acceptance.
#[allow(clippy::too_many_arguments)]
pub fn preflight_v2_marker_remote_signer_for_reload_apply(
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
    remote_signer_expected: &RemoteSignerExpectations,
    remote_signer_policy: RemoteSignerPolicy,
    now_unix: u64,
    loaded: &RemoteSignerLoadStatus,
) -> RemoteSignerPayloadCarryingDecisionOutcome {
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
        remote_signer_expected,
        remote_signer_policy,
        now_unix,
        loaded,
        route_loaded_remote_signer_attestation_to_reload_apply_callsite_decision,
    )
}

/// Run 198 — startup `--p2p-trust-bundle` mutating-preflight wrapper.
#[allow(clippy::too_many_arguments)]
pub fn preflight_v2_marker_remote_signer_for_startup_p2p_trust_bundle(
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
    remote_signer_expected: &RemoteSignerExpectations,
    remote_signer_policy: RemoteSignerPolicy,
    now_unix: u64,
    loaded: &RemoteSignerLoadStatus,
) -> RemoteSignerPayloadCarryingDecisionOutcome {
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
        remote_signer_expected,
        remote_signer_policy,
        now_unix,
        loaded,
        route_loaded_remote_signer_attestation_to_startup_p2p_trust_bundle_callsite_decision,
    )
}

/// Run 198 — SIGHUP live trust-bundle reload mutating-preflight wrapper.
#[allow(clippy::too_many_arguments)]
pub fn preflight_v2_marker_remote_signer_for_sighup(
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
    remote_signer_expected: &RemoteSignerExpectations,
    remote_signer_policy: RemoteSignerPolicy,
    now_unix: u64,
    loaded: &RemoteSignerLoadStatus,
) -> RemoteSignerPayloadCarryingDecisionOutcome {
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
        remote_signer_expected,
        remote_signer_policy,
        now_unix,
        loaded,
        route_loaded_remote_signer_attestation_to_sighup_callsite_decision,
    )
}

/// Run 198 — local `--p2p-trust-bundle-peer-candidate-check`
/// validation-only preflight wrapper. Validation-only mutation contract
/// identical to [`preflight_v2_marker_remote_signer_for_reload_check`].
#[allow(clippy::too_many_arguments)]
pub fn preflight_v2_marker_remote_signer_for_local_peer_candidate_check(
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
    remote_signer_expected: &RemoteSignerExpectations,
    remote_signer_policy: RemoteSignerPolicy,
    now_unix: u64,
    loaded: &RemoteSignerLoadStatus,
) -> RemoteSignerPayloadCarryingDecisionOutcome {
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
        remote_signer_expected,
        remote_signer_policy,
        now_unix,
        loaded,
        route_loaded_remote_signer_attestation_to_local_peer_candidate_check_callsite_decision,
    )
}

/// Run 198 — live inbound `0x05` peer-candidate validation-only
/// preflight wrapper. An invalid live `0x05` RemoteSigner-attestation
/// candidate (malformed payload, absent under non-`Disabled` policy,
/// MainNet binding under fixture/local RemoteSigner, or rejected by the
/// Run 194 verifier) is **not propagated, staged, or applied** — the
/// rejection short-circuits at the underlying Run 196 routing helper
/// before any staging path is reached.
#[allow(clippy::too_many_arguments)]
pub fn preflight_v2_marker_remote_signer_for_live_inbound_0x05(
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
    remote_signer_expected: &RemoteSignerExpectations,
    remote_signer_policy: RemoteSignerPolicy,
    now_unix: u64,
    loaded: &RemoteSignerLoadStatus,
) -> RemoteSignerPayloadCarryingDecisionOutcome {
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
        remote_signer_expected,
        remote_signer_policy,
        now_unix,
        loaded,
        route_loaded_remote_signer_attestation_to_live_inbound_0x05_callsite_decision,
    )
}

/// Run 198 — Run 150 peer-driven apply drain coordinator preflight
/// wrapper.
///
/// **MainNet refusal preserved.** The underlying Run 196 routing helper
/// refuses MainNet peer-driven apply unconditionally, even with
/// `MainnetProductionRemoteSignerRequired` and fully-valid fixture
/// loopback material. The selector cannot weaken this refusal.
#[allow(clippy::too_many_arguments)]
pub fn preflight_v2_marker_remote_signer_for_peer_driven_drain(
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
    remote_signer_expected: &RemoteSignerExpectations,
    remote_signer_policy: RemoteSignerPolicy,
    now_unix: u64,
    loaded: &RemoteSignerLoadStatus,
) -> RemoteSignerPayloadCarryingDecisionOutcome {
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
        remote_signer_expected,
        remote_signer_policy,
        now_unix,
        loaded,
        route_loaded_remote_signer_attestation_to_peer_driven_drain_callsite_decision,
    )
}

// ===========================================================================
// In-crate self-tests (smoke-level — full A1–A11 / R1–R34 coverage
// lives in `tests/run_198_remote_signer_policy_selector_tests.rs`).
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_canonical_tags() {
        assert_eq!(
            remote_signer_policy_from_selector("disabled").unwrap(),
            RemoteSignerPolicy::Disabled
        );
        assert_eq!(
            remote_signer_policy_from_selector("fixture-loopback-allowed").unwrap(),
            RemoteSignerPolicy::FixtureLoopbackAllowed
        );
        assert_eq!(
            remote_signer_policy_from_selector("production-remote-signer-required").unwrap(),
            RemoteSignerPolicy::ProductionRemoteSignerRequired
        );
        assert_eq!(
            remote_signer_policy_from_selector("mainnet-production-remote-signer-required")
                .unwrap(),
            RemoteSignerPolicy::MainnetProductionRemoteSignerRequired
        );
    }

    #[test]
    fn canonical_tags_match_policy_tag_method() {
        assert_eq!(
            REMOTE_SIGNER_POLICY_TAG_DISABLED,
            RemoteSignerPolicy::Disabled.tag()
        );
        assert_eq!(
            REMOTE_SIGNER_POLICY_TAG_FIXTURE_LOOPBACK_ALLOWED,
            RemoteSignerPolicy::FixtureLoopbackAllowed.tag()
        );
        assert_eq!(
            REMOTE_SIGNER_POLICY_TAG_PRODUCTION_REMOTE_SIGNER_REQUIRED,
            RemoteSignerPolicy::ProductionRemoteSignerRequired.tag()
        );
        assert_eq!(
            REMOTE_SIGNER_POLICY_TAG_MAINNET_PRODUCTION_REMOTE_SIGNER_REQUIRED,
            RemoteSignerPolicy::MainnetProductionRemoteSignerRequired.tag()
        );
    }

    #[test]
    fn parser_is_case_insensitive_and_trims() {
        assert_eq!(
            remote_signer_policy_from_selector("  FIXTURE-LOOPBACK-ALLOWED ").unwrap(),
            RemoteSignerPolicy::FixtureLoopbackAllowed
        );
        assert_eq!(
            remote_signer_policy_from_selector("Disabled").unwrap(),
            RemoteSignerPolicy::Disabled
        );
    }

    #[test]
    fn empty_value_is_typed_error() {
        assert_eq!(
            remote_signer_policy_from_selector("").unwrap_err(),
            RemoteSignerPolicySelectorParseError::Empty
        );
        assert_eq!(
            remote_signer_policy_from_selector("   ").unwrap_err(),
            RemoteSignerPolicySelectorParseError::Empty
        );
    }

    #[test]
    fn unknown_value_is_typed_error() {
        let e = remote_signer_policy_from_selector("kms-required").unwrap_err();
        assert!(matches!(
            e,
            RemoteSignerPolicySelectorParseError::UnknownValue { .. }
        ));
        assert_eq!(e.tag(), "unknown-value");
    }

    #[test]
    fn cli_or_env_default_is_disabled_when_cli_disabled() {
        // We cannot guarantee env is unset here in a parallel test run,
        // so only assert the explicit-cli=Some(disabled) case.
        assert_eq!(
            remote_signer_policy_from_cli_or_env(Some("disabled")).unwrap(),
            RemoteSignerPolicy::Disabled
        );
    }

    #[test]
    fn cli_some_invalid_is_typed_error() {
        assert!(matches!(
            remote_signer_policy_from_cli_or_env(Some("nope")).unwrap_err(),
            RemoteSignerPolicySelectorParseError::UnknownValue { .. }
        ));
    }
}
