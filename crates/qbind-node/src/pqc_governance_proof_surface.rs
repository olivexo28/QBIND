//! Run 169 — production marker-decision surface integration for the
//! Run 167 governance-proof loader.
//!
//! This module is the **smallest** library shim that lets every
//! production v2 marker-decision caller (reload-check, reload-apply,
//! startup `--p2p-trust-bundle`, SIGHUP live reload, live inbound
//! `0x05` validation, peer-driven drain / [`ProductionV2MarkerCoordinator`])
//! consume the typed
//! [`crate::pqc_governance_proof_wire::GovernanceProofLoadStatus`]
//! returned by
//! [`crate::pqc_ratification_input::load_v2_ratification_sidecar_with_governance_proof_from_path`]
//! and pass it to the Run 165 governance gate
//! ([`crate::pqc_authority_marker_acceptance::decide_v2_marker_acceptance_with_lifecycle_and_governance`]).
//!
//! # Strict scope (Run 169)
//!
//! * Source/test integration only. Release-binary proof-carrying
//!   production-surface evidence is deferred to Run 170.
//! * Additive: no marker / sequence-file / trust-bundle core / v2
//!   ratification / governance-proof-wire schema change.
//! * Production callers retain `GovernanceProofPolicy::NotRequired` by
//!   default, preserving every Run 134 / Run 138 / Run 142 / Run 148 /
//!   Run 150 / Run 152 / Run 161 / Run 165 / Run 167 invariant when no
//!   sibling proof is present (`Absent` -> `Unavailable` -> gate
//!   no-ops).
//! * `RequiredForLifecycleSensitive` is opt-in at the calling surface
//!   and is exercised in tests / DevNet/TestNet test hooks; production
//!   release-binary toggles for it are a Run 170 concern.
//! * No mutation here: this module performs **no** I/O. No marker
//!   write, no sequence write, no live trust swap, no session
//!   eviction, no Run 070 invocation. The mutating boundary is owned
//!   by the caller and remains gated by the existing
//!   `commit_sequence` -> `persist_accepted_v2_marker_after_commit_boundary`
//!   contract.
//! * MainNet peer-driven apply remains refused even when a valid
//!   governance proof is supplied. This module does not weaken the
//!   environment gate at any caller.
//! * `OnChainGovernance` remains unsupported / fail-closed (Run 163
//!   verifier).
//!
//! The shim is the single production source path through which the
//! Run 167 loader output reaches the Run 165 gate; it makes the
//! `load_v2_ratification_sidecar_with_governance_proof_from_path`
//! reachability claim grep-verifiable from each caller.

use crate::pqc_authority_marker_acceptance::{
    decide_v2_marker_acceptance_with_lifecycle_and_governance, MarkerAcceptDecisionV2,
    MarkerAcceptanceV2Inputs, MutatingSurfaceMarkerV2Error,
};
use crate::pqc_governance_authority::{
    GovernanceIssuerSignatureVerifier, GovernanceProofPolicy,
};
use crate::pqc_governance_proof_wire::GovernanceProofLoadStatus;

/// Run 169 — production-surface marker-decision preflight that
/// consumes a typed Run 167 [`GovernanceProofLoadStatus`] together
/// with a Run 165 [`GovernanceProofPolicy`] and a
/// [`GovernanceIssuerSignatureVerifier`] reference.
///
/// All four typed Run 167 load statuses are propagated:
///
/// * [`GovernanceProofLoadStatus::Absent`] — sidecar carried no
///   `governance_authority_proof` sibling. Under
///   [`GovernanceProofPolicy::NotRequired`] the gate no-ops; under
///   [`GovernanceProofPolicy::RequiredForLifecycleSensitive`] the gate
///   fails closed with
///   [`MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing`]
///   for `Rotate` / `Retire` / `Revoke` / `EmergencyRevoke`.
/// * [`GovernanceProofLoadStatus::Available`] — sidecar carried a
///   well-formed proof; the gate runs the Run 163
///   [`crate::pqc_governance_authority::verify_governance_authority_proof`]
///   composition through `verifier`. A valid proof passes; an invalid
///   proof fails closed with
///   [`MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected`].
/// * [`GovernanceProofLoadStatus::Malformed`] — sidecar carried an
///   un-parseable proof. Mapped to
///   [`crate::pqc_governance_authority::GovernanceProofContext::Unavailable`]
///   by [`GovernanceProofLoadStatus::governance_proof_context`] so the
///   gate fails closed under any policy that requires a proof for the
///   candidate's lifecycle action; under `NotRequired` the malformed
///   proof is treated as absent (Run 167 documented mapping).
///
/// # Mutation contract
///
/// Performs **no** disk writes. Writes no marker, no sequence,
/// mutates no live trust state, evicts no sessions, never invokes
/// Run 070. The caller persists the accepted marker via
/// [`crate::pqc_authority_marker_acceptance::persist_accepted_v2_marker_after_commit_boundary`]
/// **after** the existing Run 055 / Run 070 sequence-commit boundary —
/// Run 169 does not change that ordering at any caller.
///
/// # Non-MainNet-enabling
///
/// A valid governance proof does NOT enable MainNet peer-driven apply
/// and does NOT bypass any existing environment gate. Those gates
/// live in the calling surface (e.g. [`crate::pqc_peer_candidate_apply`])
/// and are unchanged by Run 169.
pub fn preflight_v2_marker_decision_with_governance_proof_load(
    inputs: MarkerAcceptanceV2Inputs<'_>,
    policy: GovernanceProofPolicy,
    proof_load: &GovernanceProofLoadStatus,
    verifier: &dyn GovernanceIssuerSignatureVerifier,
) -> Result<MarkerAcceptDecisionV2, MutatingSurfaceMarkerV2Error> {
    let context = proof_load.governance_proof_context(verifier);
    decide_v2_marker_acceptance_with_lifecycle_and_governance(inputs, policy, context)
}

/// Run 171 — environment-variable name of the hidden,
/// disabled-by-default DevNet/TestNet-safe governance-proof Required-
/// policy selector. The selector accepts any of `1`, `true`, `TRUE`,
/// `yes`, `on` (case-insensitive) as enable values; any other value
/// (or unset) leaves the selector disabled and the policy on its
/// `NotRequired` default.
///
/// The flag-equivalent CLI surface is
/// `--p2p-trust-bundle-governance-proof-required` (see
/// [`crate::cli::CliArgs::p2p_trust_bundle_governance_proof_required`]).
/// Either source is sufficient — they are OR-combined by
/// [`governance_proof_policy_from_selector`].
pub const QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED_ENV: &str =
    "QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED";

/// Run 171 — pure environment-variable readback for the hidden
/// governance-proof Required-policy selector. Returns `true` when the
/// env var is set to a recognized truthy value (`1`, `true`, `yes`,
/// `on` — case-insensitive); `false` otherwise.
///
/// This helper performs an [`std::env::var`] read and is otherwise
/// pure. It is intentionally exposed (instead of inlined) so the
/// Run 171 source-test matrix can drive the selector deterministically
/// from a test process by setting/unsetting the env var.
pub fn governance_proof_required_env_selector_enabled() -> bool {
    match std::env::var(QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED_ENV) {
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

/// Run 171 — translate the hidden Required-policy selector inputs
/// (CLI flag OR environment variable, OR-combined) into a
/// [`GovernanceProofPolicy`]:
///
/// * `false` (default — flag unset and env var unset/falsey) →
///   [`GovernanceProofPolicy::NotRequired`] (existing behavior; old
///   no-proof v2 sidecars remain compatible).
/// * `true` (flag set OR env var truthy) →
///   [`GovernanceProofPolicy::RequiredForLifecycleSensitive`]
///   (`Rotate` / `Retire` / `Revoke` / `EmergencyRevoke` require a
///   valid Run 167 governance authority proof).
///
/// **Non-MainNet-enabling.** A `RequiredForLifecycleSensitive` policy
/// returned by this helper does NOT enable MainNet peer-driven apply
/// and does NOT bypass any existing environment gate. The MainNet
/// refusal lives at the calling surface (e.g.
/// [`crate::pqc_peer_candidate_apply::ProductionV2MarkerCoordinator`]
/// upstream binary gate, covered by Run 152 tests) and is unchanged
/// by Run 171.
///
/// **Not a governance execution engine, KMS/HSM custody claim,
/// validator-set rotation primitive, on-chain governance proof, or
/// peer-majority authority claim.** Run 171 is source/test selector
/// wiring only; release-binary Required-policy production-surface
/// evidence is deferred to Run 172.
pub fn governance_proof_policy_from_selector(
    selector_enabled: bool,
) -> GovernanceProofPolicy {
    if selector_enabled {
        GovernanceProofPolicy::RequiredForLifecycleSensitive
    } else {
        GovernanceProofPolicy::NotRequired
    }
}

/// Run 171 — convenience wrapper that resolves the active
/// [`GovernanceProofPolicy`] from the OR-combination of an explicit
/// CLI-flag boolean and the
/// [`QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED_ENV`]
/// environment variable.
///
/// Either source is sufficient to enable the Required policy; both
/// being absent / falsey preserves the `NotRequired` default.
pub fn governance_proof_policy_from_cli_or_env(
    cli_flag_set: bool,
) -> GovernanceProofPolicy {
    governance_proof_policy_from_selector(
        cli_flag_set || governance_proof_required_env_selector_enabled(),
    )
}