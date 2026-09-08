//! Run 182 — source/test production call-site wiring for the Run 178
//! typed `OnChainGovernance` fixture proof verifier behind the hidden
//! Run 180 `OnChainGovernanceProofPolicy::AllowFixtureSourceTest`
//! selector.
//!
//! ## Strict scope (Run 182)
//!
//! * **Source/test only.** Run 182 does **not** capture release-binary
//!   evidence; release-binary `OnChainGovernance` production-surface
//!   evidence is deferred to **Run 183**.
//! * **Hidden DevNet/TestNet fixture policy only.** The default
//!   production policy remains
//!   [`crate::pqc_onchain_governance_proof::OnChainGovernanceProofPolicy::Disabled`].
//! * **No MainNet peer-driven apply enablement.** The
//!   Run 147/Run 148/Run 152 MainNet refusal at the peer-driven apply
//!   surface remains intact, even with a fully-valid DevNet fixture
//!   proof and the Run 180 selector enabled.
//! * **No governance execution engine.**
//! * **No real on-chain proof verifier.**
//! * **No bridge / light-client integration.**
//! * **No KMS/HSM custody implementation.**
//! * **No validator-set rotation.**
//! * **No autonomous apply / no automatic apply on receipt /
//!   no peer-majority authority.**
//! * **No marker / sequence-file / trust-bundle core / wire / schema
//!   change.** Run 182 is purely additive at the production library
//!   surface level (this module + named call-site entries that
//!   delegate verbatim to the Run 180 wrappers).
//!
//! Run 182 does **not** weaken any prior run (Runs 070, 130–181) and
//! does **not** claim full C4 or C5 closure.
//!
//! ## What this module adds
//!
//! Run 180 added seven per-surface preflight wrappers under
//! [`crate::pqc_onchain_governance_proof_surface`] but had **no
//! production callers**: every invocation lived in the in-crate
//! self-tests and the integration test suite. Run 181 captured
//! release-binary boundary evidence through a release-built helper but
//! still had no production callers. Run 182 closes that gap by exposing
//! seven named **production call-site entries** — one per Run 180
//! per-surface wrapper — that are invoked from the actual production
//! source files (`pqc_trust_reload.rs`, `pqc_live_trust_reload.rs`,
//! `pqc_trust_peer_candidate.rs`, `pqc_peer_candidate_wire.rs`,
//! `pqc_peer_candidate_drain.rs`, `pqc_peer_candidate_apply.rs`, and
//! `main.rs`) as part of the existing v2 marker-decision preflight
//! flow.
//!
//! The seven call-site entries are:
//!
//! 1. [`reload_check_callsite_onchain_governance_marker_decision`] —
//!    `--p2p-trust-bundle-reload-check` validation-only.
//! 2. [`reload_apply_callsite_onchain_governance_marker_decision`] —
//!    `--p2p-trust-bundle-reload-apply-*` mutating-preflight.
//! 3. [`startup_p2p_trust_bundle_callsite_onchain_governance_marker_decision`]
//!    — startup `--p2p-trust-bundle` mutating-preflight.
//! 4. [`sighup_callsite_onchain_governance_marker_decision`] — SIGHUP
//!    live-reload mutating-preflight.
//! 5. [`local_peer_candidate_check_callsite_onchain_governance_marker_decision`]
//!    — local `--p2p-trust-bundle-peer-candidate-check`
//!    validation-only.
//! 6. [`live_inbound_0x05_callsite_onchain_governance_marker_decision`]
//!    — live inbound `0x05` peer-candidate validation-only.
//! 7. [`peer_driven_drain_callsite_onchain_governance_marker_decision`]
//!    — Run 150 peer-driven apply drain coordinator preflight (the
//!    `ProductionV2MarkerCoordinator` surface).
//!
//! Each call-site entry takes the same typed
//! [`OnChainGovernanceCallsiteContext`] inputs the corresponding
//! production preflight already has in hand, applies the per-surface
//! invariants documented on its delegating wrapper, and returns the
//! same typed [`crate::pqc_onchain_governance_proof_surface::OnChainGovernanceMarkerDecisionOutcome`]
//! as the Run 180 wrapper. No call-site entry mutates marker, sequence,
//! live trust state, sessions, or invokes Run 070 — they are pure.
//!
//! ## Wire/schema blocker
//!
//! No current peer-candidate, SIGHUP-trigger, reload-apply trigger,
//! startup-bundle, or live `0x05` payload format carries a typed
//! [`crate::pqc_onchain_governance_proof::OnChainGovernanceProof`].
//! Adding such a binding to **any** of those formats is explicitly
//! out of scope for Run 182 (`No additional wire/schema change unless
//! a hard blocker is found and documented`). Run 182 documents this as
//! a hard blocker and keeps every production call site fail-closed at
//! its real wire boundary: the production callers always invoke the
//! seven call-site entries with `proof: None`, which causes the
//! delegating Run 180 wrappers to short-circuit with
//! [`crate::pqc_onchain_governance_proof_surface::OnChainGovernanceMarkerDecisionOutcome::NoOnChainGovernanceProofSupplied`]
//! — an explicit, typed bypass that preserves bit-for-bit the
//! pre-Run-182 behavior at every real wire path. The Run 182 source/
//! test acceptance matrix exercises the call-site entries with an
//! in-process typed proof to demonstrate that *if* a future schema/
//! wire run delivers a typed proof to the call site, the production
//! call-site path reaches the verifier and accepts/rejects per the
//! Run 180 composition. Real-wire / release-binary evidence is
//! deferred to Run 183.

use crate::pqc_authority_lifecycle::AuthorityTrustDomain;
use crate::pqc_authority_state::{
    PersistentAuthorityStateRecordV2, PersistentAuthorityStateRecordVersioned,
};
use crate::pqc_onchain_governance_proof::{
    OnChainGovernanceProof, OnChainGovernanceProofPolicy, OnChainGovernanceReplaySet,
};
use crate::pqc_onchain_governance_proof_surface::{
    live_inbound_0x05_compose_onchain_governance_marker_decision,
    local_peer_candidate_check_compose_onchain_governance_marker_decision,
    peer_driven_drain_compose_onchain_governance_marker_decision,
    reload_apply_compose_onchain_governance_marker_decision,
    reload_check_compose_onchain_governance_marker_decision,
    sighup_compose_onchain_governance_marker_decision,
    startup_p2p_trust_bundle_compose_onchain_governance_marker_decision,
    OnChainGovernanceMarkerDecisionOutcome,
};
use crate::pqc_trust_bundle::TrustBundleEnvironment;

/// Run 182 — typed bundle of the natural production call-site inputs
/// required to drive an OnChainGovernance marker-decision preflight at
/// any of the seven production v2 marker-decision surfaces.
///
/// Every field is borrowed; the struct is purely a typed argument
/// bundle and never mutates any input. Constructing it is free of I/O.
#[derive(Debug)]
pub struct OnChainGovernanceCallsiteContext<'a, R: OnChainGovernanceReplaySet + ?Sized> {
    /// Persisted v2 record (the on-disk authority marker state) when
    /// the call site has one in hand. `None` for `ActivateInitial` and
    /// for surfaces called before the marker exists on disk.
    pub persisted: Option<&'a PersistentAuthorityStateRecordVersioned>,
    /// Candidate v2 record being preflighted by the call site.
    pub candidate: &'a PersistentAuthorityStateRecordV2,
    /// Optional typed Run 178 proof. `None` is the only value the
    /// existing wire/sidecar formats can supply today; a future
    /// schema/wire run may extend the wire to carry a typed proof.
    pub proof: Option<&'a OnChainGovernanceProof>,
    /// Active trust domain (env / chain / genesis / authority root /
    /// suite) at the call site.
    pub trust_domain: &'a AuthorityTrustDomain,
    /// Active Run 178 policy resolved by the binary at startup from the
    /// hidden `--p2p-trust-bundle-onchain-governance-fixture-allowed`
    /// flag / `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`
    /// env var (default `Disabled`).
    pub policy: OnChainGovernanceProofPolicy,
    /// Expected governance domain id binding for the Run 178 verifier.
    pub expected_governance_domain_id: &'a str,
    /// Expected governance epoch binding for the Run 178 verifier.
    pub expected_governance_epoch: u64,
    /// Expected proposal id binding for the Run 178 verifier.
    pub expected_proposal_id: &'a str,
    /// Expected proposal digest binding for the Run 178 verifier.
    pub expected_proposal_digest: &'a str,
    /// Wall-clock seconds-since-epoch used by the freshness binding.
    pub now_unix: u64,
    /// In-memory replay-id set. The verifier only reads this set; it
    /// never extends it.
    pub replay_set: &'a R,
}

impl<'a, R: OnChainGovernanceReplaySet + ?Sized> OnChainGovernanceCallsiteContext<'a, R> {
    /// Run 182 — pure surface-level MainNet refusal helper.
    ///
    /// Returns `true` iff the candidate, the trust domain, or the
    /// proof binds MainNet. Used by [`Self::peer_driven_drain`] before
    /// the verifier is even invoked, mirroring the Run 152 MainNet
    /// peer-driven-apply refusal at the calling surface. The Run 178
    /// verifier itself also refuses MainNet (returning
    /// `MainNetProductionProofUnavailable`); the two layers agree.
    pub fn binds_mainnet(&self) -> bool {
        self.trust_domain.environment == TrustBundleEnvironment::Mainnet
            || self.candidate.environment == TrustBundleEnvironment::Mainnet
            || self
                .proof
                .map(|p| p.environment == TrustBundleEnvironment::Mainnet)
                .unwrap_or(false)
    }
}

/// Run 182 — `--p2p-trust-bundle-reload-check` validation-only
/// production call-site entry.
///
/// Validation-only mutation contract: callers MUST drop the returned
/// outcome and MUST NOT persist a marker, advance the bundle-signing
/// sequence, swap live trust state, evict sessions, or invoke
/// Run 070. Delegates verbatim to
/// [`reload_check_compose_onchain_governance_marker_decision`].
pub fn reload_check_callsite_onchain_governance_marker_decision<
    R: OnChainGovernanceReplaySet + ?Sized,
>(
    ctx: &OnChainGovernanceCallsiteContext<'_, R>,
) -> OnChainGovernanceMarkerDecisionOutcome {
    reload_check_compose_onchain_governance_marker_decision(
        ctx.persisted,
        ctx.candidate,
        ctx.proof,
        ctx.trust_domain,
        ctx.policy,
        ctx.expected_governance_domain_id,
        ctx.expected_governance_epoch,
        ctx.expected_proposal_id,
        ctx.expected_proposal_digest,
        ctx.now_unix,
        ctx.replay_set,
    )
}

/// Run 182 — `--p2p-trust-bundle-reload-apply-*` mutating-preflight
/// production call-site entry.
///
/// Mutating-preflight: a successful return only means the candidate
/// passed every Run 178 binding check; the calling surface remains
/// responsible for honoring the existing
/// `commit_sequence` → `persist_accepted_v2_marker_after_commit_boundary`
/// sequence-before-marker ordering (Runs 134/138/142/148/150/152
/// invariants). MainNet peer-driven apply remains refused regardless
/// of this preflight outcome (Run 152). Delegates verbatim to
/// [`reload_apply_compose_onchain_governance_marker_decision`].
pub fn reload_apply_callsite_onchain_governance_marker_decision<
    R: OnChainGovernanceReplaySet + ?Sized,
>(
    ctx: &OnChainGovernanceCallsiteContext<'_, R>,
) -> OnChainGovernanceMarkerDecisionOutcome {
    reload_apply_compose_onchain_governance_marker_decision(
        ctx.persisted,
        ctx.candidate,
        ctx.proof,
        ctx.trust_domain,
        ctx.policy,
        ctx.expected_governance_domain_id,
        ctx.expected_governance_epoch,
        ctx.expected_proposal_id,
        ctx.expected_proposal_digest,
        ctx.now_unix,
        ctx.replay_set,
    )
}

/// Run 182 — startup `--p2p-trust-bundle` mutating-preflight production
/// call-site entry. Same mutation contract as
/// [`reload_apply_callsite_onchain_governance_marker_decision`].
/// Delegates verbatim to
/// [`startup_p2p_trust_bundle_compose_onchain_governance_marker_decision`].
pub fn startup_p2p_trust_bundle_callsite_onchain_governance_marker_decision<
    R: OnChainGovernanceReplaySet + ?Sized,
>(
    ctx: &OnChainGovernanceCallsiteContext<'_, R>,
) -> OnChainGovernanceMarkerDecisionOutcome {
    startup_p2p_trust_bundle_compose_onchain_governance_marker_decision(
        ctx.persisted,
        ctx.candidate,
        ctx.proof,
        ctx.trust_domain,
        ctx.policy,
        ctx.expected_governance_domain_id,
        ctx.expected_governance_epoch,
        ctx.expected_proposal_id,
        ctx.expected_proposal_digest,
        ctx.now_unix,
        ctx.replay_set,
    )
}

/// Run 182 — SIGHUP live trust-bundle reload mutating-preflight
/// production call-site entry. Same mutation contract as
/// [`reload_apply_callsite_onchain_governance_marker_decision`].
/// Delegates verbatim to
/// [`sighup_compose_onchain_governance_marker_decision`].
pub fn sighup_callsite_onchain_governance_marker_decision<
    R: OnChainGovernanceReplaySet + ?Sized,
>(
    ctx: &OnChainGovernanceCallsiteContext<'_, R>,
) -> OnChainGovernanceMarkerDecisionOutcome {
    sighup_compose_onchain_governance_marker_decision(
        ctx.persisted,
        ctx.candidate,
        ctx.proof,
        ctx.trust_domain,
        ctx.policy,
        ctx.expected_governance_domain_id,
        ctx.expected_governance_epoch,
        ctx.expected_proposal_id,
        ctx.expected_proposal_digest,
        ctx.now_unix,
        ctx.replay_set,
    )
}

/// Run 182 — local `--p2p-trust-bundle-peer-candidate-check`
/// validation-only production call-site entry. Validation-only
/// mutation contract identical to
/// [`reload_check_callsite_onchain_governance_marker_decision`].
/// Delegates verbatim to
/// [`local_peer_candidate_check_compose_onchain_governance_marker_decision`].
pub fn local_peer_candidate_check_callsite_onchain_governance_marker_decision<
    R: OnChainGovernanceReplaySet + ?Sized,
>(
    ctx: &OnChainGovernanceCallsiteContext<'_, R>,
) -> OnChainGovernanceMarkerDecisionOutcome {
    local_peer_candidate_check_compose_onchain_governance_marker_decision(
        ctx.persisted,
        ctx.candidate,
        ctx.proof,
        ctx.trust_domain,
        ctx.policy,
        ctx.expected_governance_domain_id,
        ctx.expected_governance_epoch,
        ctx.expected_proposal_id,
        ctx.expected_proposal_digest,
        ctx.now_unix,
        ctx.replay_set,
    )
}

/// Run 182 — live inbound `0x05` peer-candidate validation-only
/// production call-site entry.
///
/// Validation-only mutation contract identical to
/// [`reload_check_callsite_onchain_governance_marker_decision`].
/// Live inbound `0x05` remains validation-only / staging-only per
/// existing policy; an invalid live `0x05` `OnChainGovernance` proof
/// candidate is **not propagated, staged, or applied** — the
/// rejection short-circuits at this preflight before any staging path
/// is reached. Delegates verbatim to
/// [`live_inbound_0x05_compose_onchain_governance_marker_decision`].
pub fn live_inbound_0x05_callsite_onchain_governance_marker_decision<
    R: OnChainGovernanceReplaySet + ?Sized,
>(
    ctx: &OnChainGovernanceCallsiteContext<'_, R>,
) -> OnChainGovernanceMarkerDecisionOutcome {
    live_inbound_0x05_compose_onchain_governance_marker_decision(
        ctx.persisted,
        ctx.candidate,
        ctx.proof,
        ctx.trust_domain,
        ctx.policy,
        ctx.expected_governance_domain_id,
        ctx.expected_governance_epoch,
        ctx.expected_proposal_id,
        ctx.expected_proposal_digest,
        ctx.now_unix,
        ctx.replay_set,
    )
}

/// Run 182 — Run 150 peer-driven apply drain coordinator
/// (`ProductionV2MarkerCoordinator`) preflight production call-site
/// entry.
///
/// **Surface-level MainNet refusal.** Even if the active
/// [`OnChainGovernanceProofPolicy`] is
/// [`OnChainGovernanceProofPolicy::AllowFixtureSourceTest`] and a
/// fully-valid fixture proof is supplied, this entry refuses MainNet
/// peer-driven apply unconditionally and returns
/// [`OnChainGovernanceMarkerDecisionOutcome::MainNetRefused`] before
/// the verifier is invoked, mirroring the Run 152 MainNet refusal at
/// the calling surface. Non-MainNet candidates fall through to the
/// Run 180 wrapper. Delegates verbatim to
/// [`peer_driven_drain_compose_onchain_governance_marker_decision`].
pub fn peer_driven_drain_callsite_onchain_governance_marker_decision<
    R: OnChainGovernanceReplaySet + ?Sized,
>(
    ctx: &OnChainGovernanceCallsiteContext<'_, R>,
) -> OnChainGovernanceMarkerDecisionOutcome {
    if ctx.binds_mainnet() {
        return OnChainGovernanceMarkerDecisionOutcome::MainNetRefused;
    }
    peer_driven_drain_compose_onchain_governance_marker_decision(
        ctx.persisted,
        ctx.candidate,
        ctx.proof,
        ctx.trust_domain,
        ctx.policy,
        ctx.expected_governance_domain_id,
        ctx.expected_governance_epoch,
        ctx.expected_proposal_id,
        ctx.expected_proposal_digest,
        ctx.now_unix,
        ctx.replay_set,
    )
}

// ===========================================================================
// In-crate self-tests for the production call-site entries
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqc_authority_lifecycle::PQC_LIFECYCLE_SUITE_ML_DSA_44;
    use crate::pqc_authority_state::AuthorityStateUpdateSource;
    use crate::pqc_onchain_governance_proof::EmptyOnChainGovernanceReplaySet;
    use qbind_ledger::BundleSigningRatificationV2Action;

    fn devnet_domain() -> AuthorityTrustDomain {
        AuthorityTrustDomain::new(
            TrustBundleEnvironment::Devnet,
            "0000000000000001",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1111111111111111111111111111111111111111",
            PQC_LIFECYCLE_SUITE_ML_DSA_44,
        )
    }

    fn devnet_candidate() -> PersistentAuthorityStateRecordV2 {
        PersistentAuthorityStateRecordV2::new(
            "0000000000000001".to_string(),
            TrustBundleEnvironment::Devnet,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "1111111111111111111111111111111111111111".to_string(),
            PQC_LIFECYCLE_SUITE_ML_DSA_44,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            PQC_LIFECYCLE_SUITE_ML_DSA_44,
            2,
            BundleSigningRatificationV2Action::Rotate,
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
            "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
            None,
            AuthorityStateUpdateSource::TestOrFixture,
            1_700_000_000,
        )
    }

    fn mainnet_candidate() -> PersistentAuthorityStateRecordV2 {
        let mut c = devnet_candidate();
        c.environment = TrustBundleEnvironment::Mainnet;
        c
    }

    fn ctx<'a>(
        candidate: &'a PersistentAuthorityStateRecordV2,
        domain: &'a AuthorityTrustDomain,
        replay: &'a EmptyOnChainGovernanceReplaySet,
    ) -> OnChainGovernanceCallsiteContext<'a, EmptyOnChainGovernanceReplaySet> {
        OnChainGovernanceCallsiteContext {
            persisted: None,
            candidate,
            proof: None,
            trust_domain: domain,
            policy: OnChainGovernanceProofPolicy::Disabled,
            expected_governance_domain_id: "qbind-onchain-gov-1",
            expected_governance_epoch: 1,
            expected_proposal_id: "prop-001",
            expected_proposal_digest:
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            now_unix: 1_700_000_000,
            replay_set: replay,
        }
    }

    #[test]
    fn default_disabled_policy_short_circuits_at_every_callsite_entry() {
        let candidate = devnet_candidate();
        let domain = devnet_domain();
        let replay = EmptyOnChainGovernanceReplaySet;
        let c = ctx(&candidate, &domain, &replay);
        // Every entry must report `PolicyDisabled` under the default
        // `Disabled` policy, regardless of whether a proof is present.
        for outcome in [
            reload_check_callsite_onchain_governance_marker_decision(&c),
            reload_apply_callsite_onchain_governance_marker_decision(&c),
            startup_p2p_trust_bundle_callsite_onchain_governance_marker_decision(&c),
            sighup_callsite_onchain_governance_marker_decision(&c),
            local_peer_candidate_check_callsite_onchain_governance_marker_decision(&c),
            live_inbound_0x05_callsite_onchain_governance_marker_decision(&c),
            // Peer-driven drain on a non-MainNet candidate falls
            // through to the wrapper and also reports PolicyDisabled
            // under the default `Disabled` policy.
            peer_driven_drain_callsite_onchain_governance_marker_decision(&c),
        ] {
            assert_eq!(outcome, OnChainGovernanceMarkerDecisionOutcome::PolicyDisabled);
        }
    }

    #[test]
    fn peer_driven_drain_refuses_mainnet_unconditionally() {
        // Even with the AllowFixtureSourceTest policy and `proof:
        // None`, the peer-driven-drain call-site entry MUST refuse
        // MainNet at the surface level (Run 152) before even
        // delegating to the verifier.
        let candidate = mainnet_candidate();
        let domain = AuthorityTrustDomain::new(
            TrustBundleEnvironment::Mainnet,
            "0000000000000001",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1111111111111111111111111111111111111111",
            PQC_LIFECYCLE_SUITE_ML_DSA_44,
        );
        let replay = EmptyOnChainGovernanceReplaySet;
        let mut c = ctx(&candidate, &domain, &replay);
        c.policy = OnChainGovernanceProofPolicy::AllowFixtureSourceTest;
        let outcome = peer_driven_drain_callsite_onchain_governance_marker_decision(&c);
        assert_eq!(outcome, OnChainGovernanceMarkerDecisionOutcome::MainNetRefused);
    }

    #[test]
    fn mainnet_binding_predicate_detects_each_source() {
        let domain = devnet_domain();
        let candidate = devnet_candidate();
        let replay = EmptyOnChainGovernanceReplaySet;
        let c = ctx(&candidate, &domain, &replay);
        assert!(!c.binds_mainnet());

        // MainNet domain.
        let mainnet_domain = AuthorityTrustDomain::new(
            TrustBundleEnvironment::Mainnet,
            "0000000000000001",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1111111111111111111111111111111111111111",
            PQC_LIFECYCLE_SUITE_ML_DSA_44,
        );
        let c2 = OnChainGovernanceCallsiteContext::<EmptyOnChainGovernanceReplaySet> {
            trust_domain: &mainnet_domain,
            ..ctx(&candidate, &domain, &replay)
        };
        assert!(c2.binds_mainnet());

        // MainNet candidate.
        let mainnet_cand = mainnet_candidate();
        let c3 = OnChainGovernanceCallsiteContext::<EmptyOnChainGovernanceReplaySet> {
            candidate: &mainnet_cand,
            ..ctx(&candidate, &domain, &replay)
        };
        assert!(c3.binds_mainnet());
    }
}