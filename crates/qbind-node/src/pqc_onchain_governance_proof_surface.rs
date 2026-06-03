//! Run 180 — source/test production marker-decision composition for the
//! Run 178 typed `OnChainGovernance` proof verifier.
//!
//! ## Strict scope (Run 180)
//!
//! * **Source/test only.** Run 180 does **not** capture release-binary
//!   evidence; release-binary `OnChainGovernance` production-surface
//!   evidence is deferred to Run 181.
//! * **Hidden DevNet/TestNet evidence policy only.** The default
//!   production policy remains
//!   [`crate::pqc_onchain_governance_proof::OnChainGovernanceProofPolicy::Disabled`].
//! * **No MainNet peer-driven apply enablement.** A successful
//!   DevNet/TestNet fixture acceptance never elevates into a MainNet
//!   apply path; the existing Run 147/Run 148/Run 152 MainNet refusal
//!   remains intact.
//! * **No governance execution engine.**
//! * **No real on-chain proof verifier.**
//! * **No bridge / light-client integration.**
//! * **No KMS/HSM custody implementation.**
//! * **No validator-set rotation.**
//! * **No autonomous apply / no automatic apply on receipt /
//!   no peer-majority authority.**
//! * **No marker / sequence-file / trust-bundle core / wire / schema
//!   change.** Run 180 is purely additive at the production library
//!   surface level (this module + a hidden CLI/env selector + named
//!   per-surface wrappers).
//!
//! Run 180 does **not** weaken any prior run (Runs 070, 130–179) and
//! does **not** claim full C4 closure or C5 closure.
//!
//! ## What this module adds
//!
//! Before Run 180 the typed
//! [`crate::pqc_onchain_governance_proof::verify_onchain_governance_proof`]
//! verifier and its combined-lifecycle wrapper
//! [`crate::pqc_onchain_governance_proof::validate_lifecycle_with_onchain_governance_proof`]
//! had no production callers under `crates/qbind-node/src/` — Run 178
//! shipped the typed proof format and the pure verifier behind
//! [`crate::pqc_onchain_governance_proof::OnChainGovernanceProofPolicy::Disabled`],
//! and Run 179 captured release-binary boundary evidence without
//! wiring the verifier into any production caller.
//!
//! Run 180 makes the verifier **production-source reachable**
//! through a single shared composed helper
//! ([`compose_onchain_governance_marker_decision`]) and seven named
//! per-surface preflight wrappers, all under the hidden
//! disabled-by-default
//! [`OnChainGovernanceProofPolicy::AllowFixtureSourceTest`] selector
//! (CLI flag `--p2p-trust-bundle-onchain-governance-fixture-allowed`
//! or env var
//! [`QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED_ENV`]).
//!
//! The shared helper composes, in order:
//!
//! 1. **anti-rollback marker decision** — the lifecycle/sequence
//!    monotonicity and rotation/retire/revoke ordering bound to the
//!    Run 159 v2 lifecycle validator (carried inside
//!    [`crate::pqc_onchain_governance_proof::validate_lifecycle_with_onchain_governance_proof`]);
//! 2. **Run 159 v2 lifecycle validation** — same;
//! 3. **Run 163 governance authority verification** — gated through
//!    the candidate's authority class, executed only when the class
//!    is
//!    [`crate::pqc_governance_authority::GovernanceAuthorityClass::OnChainGovernance`];
//! 4. **Run 178 `OnChainGovernance` fixture verifier** — invoked only
//!    when the active [`OnChainGovernanceProofPolicy`] is
//!    [`OnChainGovernanceProofPolicy::AllowFixtureSourceTest`] and a
//!    typed
//!    [`crate::pqc_onchain_governance_proof::OnChainGovernanceProof`]
//!    is supplied by the caller.
//!
//! ## Pure / non-mutating
//!
//! Every function in this module is **pure**: it performs no I/O,
//! writes no marker, writes no sequence, mutates no live trust
//! state, evicts no sessions, and never invokes Run 070. Mutating
//! callers must continue to honor the existing
//! `commit_sequence` → `persist_accepted_v2_marker_after_commit_boundary`
//! sequence-before-marker ordering (Runs 134/138/142/148/150/152
//! invariants).
//!
//! ## Per-surface named wrappers
//!
//! Run 180 exposes the same shared helper under seven distinct
//! names, one per production marker-decision surface, so each
//! production caller's reachability claim is grep-verifiable and so
//! a future run can specialise any individual surface without
//! changing the underlying composition:
//!
//! 1. [`reload_check_compose_onchain_governance_marker_decision`] —
//!    `--p2p-trust-bundle-reload-check` validation-only.
//! 2. [`reload_apply_compose_onchain_governance_marker_decision`] —
//!    `--p2p-trust-bundle-reload-apply-*` mutating-preflight.
//! 3. [`startup_p2p_trust_bundle_compose_onchain_governance_marker_decision`]
//!    — startup `--p2p-trust-bundle` mutating-preflight.
//! 4. [`sighup_compose_onchain_governance_marker_decision`] — SIGHUP
//!    live trust-bundle reload mutating-preflight.
//! 5. [`local_peer_candidate_check_compose_onchain_governance_marker_decision`]
//!    — local `--p2p-trust-bundle-peer-candidate-check`
//!    validation-only.
//! 6. [`live_inbound_0x05_compose_onchain_governance_marker_decision`]
//!    — live inbound `0x05` peer-candidate validation-only.
//! 7. [`peer_driven_drain_compose_onchain_governance_marker_decision`]
//!    — Run 150 peer-driven apply drain coordinator preflight.
//!
//! All seven wrappers delegate to
//! [`compose_onchain_governance_marker_decision`] verbatim — there
//! is exactly one composition path. Tests in
//! `crates/qbind-node/tests/run_180_onchain_governance_marker_integration_tests.rs`
//! exercise every wrapper plus the Disabled / Mainnet-refused /
//! wrong-binding / replayed / expired / quorum-failed /
//! threshold-failed / invalid-proof / malformed / unsupported-suite
//! cases.

use crate::pqc_authority_lifecycle::AuthorityTrustDomain;
use crate::pqc_authority_state::{
    PersistentAuthorityStateRecordV2, PersistentAuthorityStateRecordVersioned,
};
use crate::pqc_onchain_governance_proof::{
    validate_lifecycle_with_onchain_governance_proof,
    CombinedLifecycleOnChainGovernanceOutcome, OnChainGovernanceProof,
    OnChainGovernanceProofPolicy, OnChainGovernanceReplaySet,
};
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Hidden DevNet/TestNet selector — CLI flag + env variable
// ===========================================================================

/// Run 180 — environment-variable name of the hidden,
/// disabled-by-default DevNet/TestNet-safe `OnChainGovernance` fixture
/// proof selector. The selector accepts any of `1`, `true`, `TRUE`,
/// `yes`, `on` (case-insensitive) as enable values; any other value
/// (or unset) leaves the selector disabled and the active
/// [`OnChainGovernanceProofPolicy`] on its
/// [`OnChainGovernanceProofPolicy::Disabled`] default.
///
/// The flag-equivalent CLI surface is
/// `--p2p-trust-bundle-onchain-governance-fixture-allowed` (see
/// [`crate::cli::CliArgs::p2p_trust_bundle_onchain_governance_fixture_allowed`]).
/// Either source is sufficient — they are OR-combined by
/// [`onchain_governance_proof_policy_from_cli_or_env`].
///
/// **Non-MainNet-enabling.** Setting this env var to a truthy value
/// only flips the resolved [`OnChainGovernanceProofPolicy`] to
/// [`OnChainGovernanceProofPolicy::AllowFixtureSourceTest`]; the
/// Run 178 verifier still refuses MainNet with
/// `MainNetProductionProofUnavailable`, and the existing
/// Run 147/Run 148/Run 152 MainNet peer-driven-apply refusal at the
/// calling surface remains intact. The selector is **not** a
/// governance execution claim, **not** a real on-chain proof claim,
/// **not** a KMS/HSM claim, and **not** a validator-set rotation
/// claim.
pub const QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED_ENV: &str =
    "QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED";

/// Run 180 — pure environment-variable readback for the hidden
/// `OnChainGovernance` fixture selector. Returns `true` when the env
/// var is set to a recognized truthy value (`1`, `true`, `yes`, `on`
/// — case-insensitive); `false` otherwise.
///
/// Performs an [`std::env::var`] read and is otherwise pure. It is
/// intentionally exposed (instead of inlined) so the Run 180
/// source-test matrix can drive the selector deterministically from a
/// test process by setting/unsetting the env var.
pub fn onchain_governance_fixture_allowed_env_selector_enabled() -> bool {
    match std::env::var(QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED_ENV) {
        Ok(v) => {
            let s = v.trim();
            // Recognized truthy values; any other value (including
            // empty / "0" / "false") leaves the selector disabled.
            s.eq_ignore_ascii_case("1")
                || s.eq_ignore_ascii_case("true")
                || s.eq_ignore_ascii_case("yes")
                || s.eq_ignore_ascii_case("on")
        }
        Err(_) => false,
    }
}

/// Run 180 — translate the hidden selector boolean (CLI flag OR env
/// variable, OR-combined) into an [`OnChainGovernanceProofPolicy`]:
///
/// * `false` (default — flag unset and env var unset/falsey) →
///   [`OnChainGovernanceProofPolicy::Disabled`] (existing behavior;
///   every `OnChainGovernance` proof — fixture or otherwise — is
///   refused as `UnsupportedProductionOnChainGovernance`).
/// * `true` (flag set OR env var truthy) →
///   [`OnChainGovernanceProofPolicy::AllowFixtureSourceTest`]
///   (DevNet/TestNet fixture proofs may pass when every binding
///   matches; MainNet is still refused as
///   `MainNetProductionProofUnavailable`).
///
/// **Non-MainNet-enabling.** The returned policy never enables
/// MainNet peer-driven apply and never bypasses any per-environment
/// gate. The MainNet refusal lives at the calling surface (see
/// [`crate::pqc_peer_candidate_apply::ProductionV2MarkerCoordinator`])
/// and is unchanged by Run 180.
pub fn onchain_governance_proof_policy_from_selector(
    selector_enabled: bool,
) -> OnChainGovernanceProofPolicy {
    if selector_enabled {
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest
    } else {
        OnChainGovernanceProofPolicy::Disabled
    }
}

/// Run 180 — convenience wrapper that resolves the active
/// [`OnChainGovernanceProofPolicy`] from the OR-combination of an
/// explicit CLI-flag boolean and the
/// [`QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED_ENV`]
/// environment variable.
///
/// Either source is sufficient to enable the
/// [`OnChainGovernanceProofPolicy::AllowFixtureSourceTest`] policy;
/// both being absent / falsey preserves the
/// [`OnChainGovernanceProofPolicy::Disabled`] default.
pub fn onchain_governance_proof_policy_from_cli_or_env(
    cli_flag_set: bool,
) -> OnChainGovernanceProofPolicy {
    onchain_governance_proof_policy_from_selector(
        cli_flag_set || onchain_governance_fixture_allowed_env_selector_enabled(),
    )
}

// ===========================================================================
// MainNet refusal helper
// ===========================================================================

/// Run 180 — pure non-mutating assertion that even a fully-valid
/// Run 178 fixture `OnChainGovernance` proof MUST NOT enable MainNet
/// peer-driven apply.
///
/// Returns `true` iff the supplied environment is MainNet, in which
/// case the calling surface MUST refuse peer-driven apply regardless
/// of the active [`OnChainGovernanceProofPolicy`] or any
/// fixture-acceptance result. Provided so binary-side and library-
/// side MainNet refusal sites can grep-verifiably reach the Run 180
/// surface without re-implementing the rule.
pub fn mainnet_peer_driven_apply_remains_refused_for_onchain_governance(
    environment: TrustBundleEnvironment,
) -> bool {
    crate::pqc_onchain_governance_proof::mainnet_peer_driven_apply_remains_refused(
        environment,
        // The outcome is intentionally unused — Run 180's MainNet
        // refusal is unconditional with respect to the supplied
        // outcome (the Run 178 verifier itself returns
        // `MainNetProductionProofUnavailable` on MainNet, but the
        // refusal here is environment-driven).
        &crate::pqc_onchain_governance_proof::OnChainGovernanceProofVerificationOutcome::MainNetProductionProofUnavailable,
    )
}

// ===========================================================================
// Composed marker-decision outcome
// ===========================================================================

/// Run 180 — typed outcome of the shared composed marker-decision
/// helper [`compose_onchain_governance_marker_decision`] and of every
/// per-surface named wrapper that delegates to it.
///
/// The outcome is intentionally explicit so a calling surface can
/// distinguish "selector is disabled / policy refuses" from
/// "lifecycle rejected" from "fixture proof rejected" from
/// "accepted" without inspecting the inner enum representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnChainGovernanceMarkerDecisionOutcome {
    /// The composition reached the Run 178 verifier and the fixture
    /// proof passed every binding check. The carried
    /// [`CombinedLifecycleOnChainGovernanceOutcome::Accepted`]
    /// preserves the typed Run 159 lifecycle outcome and the typed
    /// Run 178 governance outcome for the operator-log line.
    ///
    /// **Acceptance is always of a fixture proof under
    /// [`OnChainGovernanceProofPolicy::AllowFixtureSourceTest`] for
    /// DevNet/TestNet.** It does NOT advance the on-disk authority
    /// marker, NOT advance the bundle-signing sequence, NOT cause a
    /// live trust swap, NOT enable MainNet apply, and NOT invoke
    /// Run 070 — the helper is pure.
    Accepted(CombinedLifecycleOnChainGovernanceOutcome),

    /// The active [`OnChainGovernanceProofPolicy`] is
    /// [`OnChainGovernanceProofPolicy::Disabled`] (Run 180 default).
    /// The Run 178 verifier was not invoked. Existing
    /// `GenesisBound` / `EmergencyCouncil` proof behavior is
    /// unchanged for non-`OnChainGovernance` candidates — callers
    /// outside the `OnChainGovernance` class continue to use their
    /// existing Run 169/173/176 paths and never reach this enum.
    PolicyDisabled,

    /// No typed [`OnChainGovernanceProof`] was supplied to the
    /// helper. The Run 178 verifier was not invoked. This is the
    /// expected control-flow outcome on the overwhelming majority of
    /// production candidates (which carry a `GenesisBound` or
    /// `EmergencyCouncil` authority class, not `OnChainGovernance`),
    /// and on every legacy v2 sidecar that predates the Run 178
    /// proof object.
    NoOnChainGovernanceProofSupplied,

    /// MainNet was rejected unconditionally. The Run 178 verifier
    /// itself returns `MainNetProductionProofUnavailable` on MainNet
    /// and Run 180 surfaces that as a distinct outcome so the
    /// calling surface can log a MainNet-refusal line without
    /// pattern-matching on the inner enum.
    MainNetRefused,

    /// The Run 178 verifier rejected the lifecycle or fixture proof.
    /// Carries the underlying typed
    /// [`CombinedLifecycleOnChainGovernanceOutcome`] (which is one of
    /// `LifecycleRejected` or `GovernanceRejected`).
    Rejected(CombinedLifecycleOnChainGovernanceOutcome),
}

impl OnChainGovernanceMarkerDecisionOutcome {
    /// Returns `true` iff the helper accepted the candidate.
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::Accepted(_))
    }

    /// Returns `true` iff the helper rejected the candidate (any
    /// reject variant — including MainNet refusal, lifecycle
    /// rejection, and Run 178 rejection).
    pub fn is_reject(&self) -> bool {
        matches!(self, Self::MainNetRefused | Self::Rejected(_))
    }

    /// Returns `true` iff the Run 178 verifier was bypassed because
    /// the policy is `Disabled` or no proof was supplied. This is
    /// the expected outcome on every production candidate that does
    /// not carry an `OnChainGovernance` proof.
    pub fn is_bypassed(&self) -> bool {
        matches!(
            self,
            Self::PolicyDisabled | Self::NoOnChainGovernanceProofSupplied
        )
    }
}

// ===========================================================================
// Shared composed helper
// ===========================================================================

/// Run 180 — single shared composed marker-decision helper for the
/// Run 178 typed `OnChainGovernance` fixture proof verifier.
///
/// **Composition order:**
///
/// 1. **Selector / policy gate** — when `policy ==
///    OnChainGovernanceProofPolicy::Disabled`, returns
///    [`OnChainGovernanceMarkerDecisionOutcome::PolicyDisabled`]
///    without calling the Run 178 verifier. This preserves the
///    Run 178/179 production-default fail-closed behavior at every
///    production caller that has not explicitly opted in via the
///    hidden Run 180 selector.
/// 2. **Optional-proof gate** — when no
///    [`OnChainGovernanceProof`] is supplied (the overwhelming
///    majority of v2 candidates), returns
///    [`OnChainGovernanceMarkerDecisionOutcome::NoOnChainGovernanceProofSupplied`]
///    without calling the Run 178 verifier. Existing
///    `GenesisBound` / `EmergencyCouncil` decisions remain on their
///    Run 169/173/176 paths.
/// 3. **MainNet refusal** — when the candidate, the trust domain, or
///    the proof is on MainNet, returns
///    [`OnChainGovernanceMarkerDecisionOutcome::MainNetRefused`].
///    Even with [`OnChainGovernanceProofPolicy::AllowFixtureSourceTest`]
///    and a fully-valid fixture proof, MainNet peer-driven apply is
///    not enabled by Run 180. The existing Run 147/Run 148/Run 152
///    MainNet refusal at peer-driven apply lives in the calling
///    surface and is unchanged.
/// 4. **Composed lifecycle + Run 178 verifier** — delegates to
///    [`validate_lifecycle_with_onchain_governance_proof`], which
///    runs the Run 159 v2 lifecycle validator (anti-rollback + the
///    rotation/retire/revoke ordering) and, on lifecycle accept,
///    runs the Run 178 fixture verifier (chain / genesis /
///    authority-root / governance-domain / governance-epoch /
///    proposal / outcome / lifecycle-action / candidate-digest /
///    sequence / freshness / replay-id / quorum / threshold / suite
///    / proof-bytes commitment).
///
/// **Pure / non-mutating.** Performs no I/O. Writes no marker.
/// Writes no sequence. Mutates no live trust state. Evicts no
/// sessions. Never invokes Run 070. Never extends the replay-id
/// set. Mutating callers continue to honor the existing
/// `commit_sequence` → `persist_accepted_v2_marker_after_commit_boundary`
/// sequence-before-marker ordering after acceptance.
///
/// **Out of scope.** Run 180 does not implement governance
/// execution, real on-chain proof verification, KMS/HSM custody,
/// validator-set rotation, autonomous apply, automatic apply on
/// receipt, peer-majority authority, or any wire/schema/metric
/// change. MainNet peer-driven apply remains refused.
#[allow(clippy::too_many_arguments)]
pub fn compose_onchain_governance_marker_decision<R: OnChainGovernanceReplaySet + ?Sized>(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    proof: Option<&OnChainGovernanceProof>,
    trust_domain: &AuthorityTrustDomain,
    policy: OnChainGovernanceProofPolicy,
    expected_governance_domain_id: &str,
    expected_governance_epoch: u64,
    expected_proposal_id: &str,
    expected_proposal_digest: &str,
    now_unix: u64,
    replay_set: &R,
) -> OnChainGovernanceMarkerDecisionOutcome {
    // ---- 1. Selector / policy gate ------------------------------------
    if policy == OnChainGovernanceProofPolicy::Disabled {
        return OnChainGovernanceMarkerDecisionOutcome::PolicyDisabled;
    }

    // ---- 2. Optional-proof gate ---------------------------------------
    let proof = match proof {
        Some(p) => p,
        None => {
            return OnChainGovernanceMarkerDecisionOutcome::NoOnChainGovernanceProofSupplied;
        }
    };

    // ---- 3. MainNet refusal -------------------------------------------
    // Fail-closed before invoking the Run 178 verifier. The verifier
    // itself also returns `MainNetProductionProofUnavailable` for any
    // MainNet binding, but Run 180 surfaces this as a distinct typed
    // outcome so the calling surface can emit a precise MainNet-
    // refusal operator log line without pattern-matching on the
    // inner enum. The two layers agree (verifier-level + surface-
    // level) — neither alone weakens the MainNet-refusal invariant.
    if proof.environment == TrustBundleEnvironment::Mainnet
        || trust_domain.environment == TrustBundleEnvironment::Mainnet
        || candidate.environment == TrustBundleEnvironment::Mainnet
    {
        return OnChainGovernanceMarkerDecisionOutcome::MainNetRefused;
    }

    // ---- 4. Composed lifecycle + Run 178 verifier ---------------------
    let combined = validate_lifecycle_with_onchain_governance_proof(
        persisted,
        candidate,
        proof,
        trust_domain,
        policy,
        expected_governance_domain_id,
        expected_governance_epoch,
        expected_proposal_id,
        expected_proposal_digest,
        now_unix,
        replay_set,
    );

    if combined.is_accept() {
        OnChainGovernanceMarkerDecisionOutcome::Accepted(combined)
    } else {
        OnChainGovernanceMarkerDecisionOutcome::Rejected(combined)
    }
}

// ===========================================================================
// Per-surface named wrappers (grep-verifiable production reachability)
// ===========================================================================

/// Run 180 — `--p2p-trust-bundle-reload-check` validation-only
/// preflight wrapper that delegates to
/// [`compose_onchain_governance_marker_decision`].
///
/// Validation-only: the caller MUST drop the returned outcome and
/// MUST NOT persist a marker, advance the bundle-signing sequence,
/// swap live trust state, evict sessions, or invoke Run 070. The
/// helper is pure and cannot itself differentiate validation-only
/// from mutating callers.
#[allow(clippy::too_many_arguments)]
pub fn reload_check_compose_onchain_governance_marker_decision<
    R: OnChainGovernanceReplaySet + ?Sized,
>(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    proof: Option<&OnChainGovernanceProof>,
    trust_domain: &AuthorityTrustDomain,
    policy: OnChainGovernanceProofPolicy,
    expected_governance_domain_id: &str,
    expected_governance_epoch: u64,
    expected_proposal_id: &str,
    expected_proposal_digest: &str,
    now_unix: u64,
    replay_set: &R,
) -> OnChainGovernanceMarkerDecisionOutcome {
    compose_onchain_governance_marker_decision(
        persisted,
        candidate,
        proof,
        trust_domain,
        policy,
        expected_governance_domain_id,
        expected_governance_epoch,
        expected_proposal_id,
        expected_proposal_digest,
        now_unix,
        replay_set,
    )
}

/// Run 180 — `--p2p-trust-bundle-reload-apply-*` mutating-preflight
/// wrapper that delegates to
/// [`compose_onchain_governance_marker_decision`].
///
/// Mutating-preflight: a successful return only means the candidate
/// passed every Run 178 binding check; the calling surface remains
/// responsible for honoring the existing
/// `commit_sequence` → `persist_accepted_v2_marker_after_commit_boundary`
/// sequence-before-marker ordering and the existing per-environment
/// peer-driven apply gate (Run 148). MainNet peer-driven apply
/// remains refused regardless of acceptance here (Run 152).
#[allow(clippy::too_many_arguments)]
pub fn reload_apply_compose_onchain_governance_marker_decision<
    R: OnChainGovernanceReplaySet + ?Sized,
>(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    proof: Option<&OnChainGovernanceProof>,
    trust_domain: &AuthorityTrustDomain,
    policy: OnChainGovernanceProofPolicy,
    expected_governance_domain_id: &str,
    expected_governance_epoch: u64,
    expected_proposal_id: &str,
    expected_proposal_digest: &str,
    now_unix: u64,
    replay_set: &R,
) -> OnChainGovernanceMarkerDecisionOutcome {
    compose_onchain_governance_marker_decision(
        persisted,
        candidate,
        proof,
        trust_domain,
        policy,
        expected_governance_domain_id,
        expected_governance_epoch,
        expected_proposal_id,
        expected_proposal_digest,
        now_unix,
        replay_set,
    )
}

/// Run 180 — startup `--p2p-trust-bundle` mutating-preflight wrapper
/// that delegates to [`compose_onchain_governance_marker_decision`].
///
/// Same mutation contract as the reload-apply wrapper: acceptance
/// here is preflight-only and the existing Run 134/Run 138 marker /
/// sequence persistence ordering at the calling surface remains
/// unchanged.
#[allow(clippy::too_many_arguments)]
pub fn startup_p2p_trust_bundle_compose_onchain_governance_marker_decision<
    R: OnChainGovernanceReplaySet + ?Sized,
>(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    proof: Option<&OnChainGovernanceProof>,
    trust_domain: &AuthorityTrustDomain,
    policy: OnChainGovernanceProofPolicy,
    expected_governance_domain_id: &str,
    expected_governance_epoch: u64,
    expected_proposal_id: &str,
    expected_proposal_digest: &str,
    now_unix: u64,
    replay_set: &R,
) -> OnChainGovernanceMarkerDecisionOutcome {
    compose_onchain_governance_marker_decision(
        persisted,
        candidate,
        proof,
        trust_domain,
        policy,
        expected_governance_domain_id,
        expected_governance_epoch,
        expected_proposal_id,
        expected_proposal_digest,
        now_unix,
        replay_set,
    )
}

/// Run 180 — SIGHUP live trust-bundle reload mutating-preflight
/// wrapper that delegates to
/// [`compose_onchain_governance_marker_decision`].
///
/// Same mutation contract as the reload-apply wrapper.
#[allow(clippy::too_many_arguments)]
pub fn sighup_compose_onchain_governance_marker_decision<
    R: OnChainGovernanceReplaySet + ?Sized,
>(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    proof: Option<&OnChainGovernanceProof>,
    trust_domain: &AuthorityTrustDomain,
    policy: OnChainGovernanceProofPolicy,
    expected_governance_domain_id: &str,
    expected_governance_epoch: u64,
    expected_proposal_id: &str,
    expected_proposal_digest: &str,
    now_unix: u64,
    replay_set: &R,
) -> OnChainGovernanceMarkerDecisionOutcome {
    compose_onchain_governance_marker_decision(
        persisted,
        candidate,
        proof,
        trust_domain,
        policy,
        expected_governance_domain_id,
        expected_governance_epoch,
        expected_proposal_id,
        expected_proposal_digest,
        now_unix,
        replay_set,
    )
}

/// Run 180 — local `--p2p-trust-bundle-peer-candidate-check`
/// validation-only wrapper that delegates to
/// [`compose_onchain_governance_marker_decision`].
///
/// Validation-only mutation contract identical to the reload-check
/// wrapper.
#[allow(clippy::too_many_arguments)]
pub fn local_peer_candidate_check_compose_onchain_governance_marker_decision<
    R: OnChainGovernanceReplaySet + ?Sized,
>(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    proof: Option<&OnChainGovernanceProof>,
    trust_domain: &AuthorityTrustDomain,
    policy: OnChainGovernanceProofPolicy,
    expected_governance_domain_id: &str,
    expected_governance_epoch: u64,
    expected_proposal_id: &str,
    expected_proposal_digest: &str,
    now_unix: u64,
    replay_set: &R,
) -> OnChainGovernanceMarkerDecisionOutcome {
    compose_onchain_governance_marker_decision(
        persisted,
        candidate,
        proof,
        trust_domain,
        policy,
        expected_governance_domain_id,
        expected_governance_epoch,
        expected_proposal_id,
        expected_proposal_digest,
        now_unix,
        replay_set,
    )
}

/// Run 180 — live inbound `0x05` peer-candidate validation-only
/// wrapper that delegates to
/// [`compose_onchain_governance_marker_decision`].
///
/// Validation-only mutation contract identical to the reload-check
/// wrapper. Live inbound `0x05` remains validation-only / staging-
/// only per existing policy; no apply-on-receipt is introduced. An
/// invalid live `0x05` `OnChainGovernance` proof candidate is not
/// propagated, staged, or applied — the rejection short-circuits at
/// this preflight before any staging path is reached.
#[allow(clippy::too_many_arguments)]
pub fn live_inbound_0x05_compose_onchain_governance_marker_decision<
    R: OnChainGovernanceReplaySet + ?Sized,
>(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    proof: Option<&OnChainGovernanceProof>,
    trust_domain: &AuthorityTrustDomain,
    policy: OnChainGovernanceProofPolicy,
    expected_governance_domain_id: &str,
    expected_governance_epoch: u64,
    expected_proposal_id: &str,
    expected_proposal_digest: &str,
    now_unix: u64,
    replay_set: &R,
) -> OnChainGovernanceMarkerDecisionOutcome {
    compose_onchain_governance_marker_decision(
        persisted,
        candidate,
        proof,
        trust_domain,
        policy,
        expected_governance_domain_id,
        expected_governance_epoch,
        expected_proposal_id,
        expected_proposal_digest,
        now_unix,
        replay_set,
    )
}

/// Run 180 — Run 150 peer-driven apply drain coordinator preflight
/// wrapper that delegates to
/// [`compose_onchain_governance_marker_decision`].
///
/// The peer-driven drain coordinator only consumes already-staged
/// candidates that already passed Run 142 v2 validation, Run 145
/// staging, Run 130 verifier, Run 132/142 marker pre-apply, Run 055
/// anti-rollback, and Run 065/091 activation gates. This wrapper
/// adds the Run 178 fixture proof check on top of those, behind the
/// hidden Run 180 selector. MainNet peer-driven apply remains
/// refused (Run 152) regardless of the outcome here.
#[allow(clippy::too_many_arguments)]
pub fn peer_driven_drain_compose_onchain_governance_marker_decision<
    R: OnChainGovernanceReplaySet + ?Sized,
>(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    proof: Option<&OnChainGovernanceProof>,
    trust_domain: &AuthorityTrustDomain,
    policy: OnChainGovernanceProofPolicy,
    expected_governance_domain_id: &str,
    expected_governance_epoch: u64,
    expected_proposal_id: &str,
    expected_proposal_digest: &str,
    now_unix: u64,
    replay_set: &R,
) -> OnChainGovernanceMarkerDecisionOutcome {
    compose_onchain_governance_marker_decision(
        persisted,
        candidate,
        proof,
        trust_domain,
        policy,
        expected_governance_domain_id,
        expected_governance_epoch,
        expected_proposal_id,
        expected_proposal_digest,
        now_unix,
        replay_set,
    )
}

// ===========================================================================
// In-crate self-tests for the pure helpers
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_default_is_disabled() {
        assert_eq!(
            onchain_governance_proof_policy_from_selector(false),
            OnChainGovernanceProofPolicy::Disabled
        );
    }

    #[test]
    fn selector_true_is_allow_fixture_source_test() {
        assert_eq!(
            onchain_governance_proof_policy_from_selector(true),
            OnChainGovernanceProofPolicy::AllowFixtureSourceTest
        );
    }

    #[test]
    fn cli_or_env_default_is_disabled() {
        // Ensure no env contamination across parallel tests.
        std::env::remove_var(QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED_ENV);
        assert_eq!(
            onchain_governance_proof_policy_from_cli_or_env(false),
            OnChainGovernanceProofPolicy::Disabled
        );
    }

    #[test]
    fn mainnet_refusal_helper_is_environment_driven() {
        assert!(mainnet_peer_driven_apply_remains_refused_for_onchain_governance(
            TrustBundleEnvironment::Mainnet
        ));
        assert!(!mainnet_peer_driven_apply_remains_refused_for_onchain_governance(
            TrustBundleEnvironment::Testnet
        ));
        assert!(!mainnet_peer_driven_apply_remains_refused_for_onchain_governance(
            TrustBundleEnvironment::Devnet
        ));
    }
}