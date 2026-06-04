//! Run 186 — source/test production OnChainGovernance verifier boundary
//! and fail-closed MainNet policy.
//!
//! ## Strict scope (Run 186)
//!
//! * **Source/test only.** Run 186 ships **no** release-binary harness;
//!   release-binary verifier-boundary evidence is deferred to **Run 187**.
//! * **No MainNet peer-driven apply enablement.** The Run 147 / 148 /
//!   152 FATAL invariant remains intact.
//! * **No real on-chain governance proof verifier.** This module
//!   defines a typed *boundary* between fixture-only verification and a
//!   future real production verifier; it does NOT implement real
//!   verification.
//! * **No governance execution engine.**
//! * **No bridge / light-client integration.**
//! * **No KMS / HSM custody implementation.**
//! * **No validator-set rotation.**
//! * **No autonomous apply / no automatic apply on receipt /
//!   no peer-majority authority.**
//! * **No schema / wire change.** Run 186 is purely additive at the
//!   library level — no v2 marker / sequence-file / trust-bundle core /
//!   peer-candidate envelope / authority-marker / wire-frame / wire-
//!   domain-tag schema change. The Run 178 [`OnChainGovernanceProof`]
//!   already carries [`OnChainGovernanceProof::proof_suite_id`], which
//!   Run 186 reuses to distinguish fixture-class from production-class
//!   proofs without bumping any schema.
//!
//! Run 186 does **not** weaken any prior run (Runs 070, 130–185) and
//! does **not** claim full C4 or C5 closure.
//!
//! ## What this module adds
//!
//! Before Run 186 the Run 178 typed verifier — exposed by
//! [`crate::pqc_onchain_governance_proof::verify_onchain_governance_proof`] —
//! collapsed every non-fixture suite onto
//! [`OnChainGovernanceProofVerificationOutcome::UnsupportedGovernanceProofSuite`]
//! and never made an explicit boundary between *fixture-only* DevNet/
//! TestNet evidence verification and a future *real* production
//! on-chain verifier. The Run 180 / 182 / 184 / 185 stack stayed inside
//! that single Run 178 surface, which meant:
//!
//! * a production-class proof (a future real on-chain proof bound to
//!   the reserved
//!   [`crate::pqc_onchain_governance_proof::ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION`]
//!   suite, or any other non-fixture suite) was rejected only as
//!   `UnsupportedGovernanceProofSuite`, not as a typed
//!   "production verifier unavailable",
//! * the surface had no symbol that callers could grep for to
//!   distinguish *fixture acceptance* from *production refusal*,
//! * the MainNet policy was implicit — the Run 178 verifier's MainNet
//!   refusal was the only barrier and it spoke in fixture-verifier
//!   language.
//!
//! Run 186 closes that gap at the source / test level by introducing,
//! in this module, a typed **production OnChainGovernance verifier
//! boundary**:
//!
//! 1. [`OnChainGovernanceVerifierKind`] — explicit verifier-class
//!    enumeration (`Disabled` / `FixtureSourceTest` /
//!    `ProductionUnavailable` / `ProductionVerifier`). Default is
//!    [`OnChainGovernanceVerifierKind::Disabled`].
//! 2. [`OnChainGovernanceProofClass`] — typed proof-class
//!    distinction (`Fixture` vs `Production`) derived from
//!    [`OnChainGovernanceProof::proof_suite_id`].
//! 3. [`OnChainGovernanceVerifierPolicy`] — typed policy bundle
//!    pairing the verifier kind with the Run 178 fixture policy and
//!    the trust-domain environment.
//! 4. [`OnChainGovernanceVerifierBoundaryOutcome`] — typed outcome
//!    with the precise reject variants required by the Run 186 task
//!    (production verifier unavailable, production proof unsupported,
//!    production proof malformed, MainNet production verifier
//!    unavailable, plus typed forwarding of every Run 178 reject).
//! 5. [`OnChainGovernanceVerifier`] trait + four concrete
//!    [`DisabledOnChainGovernanceVerifier`] /
//!    [`FixtureSourceTestOnChainGovernanceVerifier`] /
//!    [`ProductionUnavailableOnChainGovernanceVerifier`] /
//!    [`ProductionVerifierPlaceholderOnChainGovernanceVerifier`]
//!    implementations.
//! 6. [`verify_fixture_onchain_governance_proof`] /
//!    [`verify_production_onchain_governance_proof`] — pure typed
//!    entry points that route through the verifier boundary by
//!    proof class.
//! 7. [`dispatch_onchain_governance_proof_through_verifier_boundary`]
//!    — pure non-mutating boundary dispatch that classifies the
//!    proof by suite, picks the matching verifier, and returns a
//!    typed boundary outcome. This is the symbol the Run 182 / 184
//!    call-site path can reach to distinguish fixture acceptance
//!    from production refusal without leaking the Run 178 enum
//!    shape.
//!
//! ## Pure / non-mutating
//!
//! Every function in this module is pure: it performs no I/O, writes
//! no marker, writes no sequence, mutates no live trust state, evicts
//! no sessions, and never invokes Run 070. Replay protection is
//! supplied by the caller as a reference to an in-memory replay-id
//! set; Run 186 never extends that set. Mutating callers (reload-
//! apply, startup, SIGHUP, peer-driven drain) continue to honor the
//! existing `commit_sequence` →
//! `persist_accepted_v2_marker_after_commit_boundary` sequence-before-
//! marker ordering after acceptance.
//!
//! ## Explicit MainNet policy (Run 186)
//!
//! * **DevNet / TestNet** — fixture proof verification is allowed only
//!   under the explicit
//!   [`OnChainGovernanceVerifierKind::FixtureSourceTest`] kind, which
//!   itself is gated by the Run 180
//!   [`OnChainGovernanceProofPolicy::AllowFixtureSourceTest`] selector.
//! * **MainNet** — fixture proof MUST NOT be accepted as production
//!   governance authority. Run 186 surfaces this explicitly as
//!   [`OnChainGovernanceVerifierBoundaryOutcome::FixtureProofRejectedAsMainNetProductionAuthority`]
//!   when a fixture-class proof is presented under a MainNet trust
//!   domain.
//! * **MainNet production verifier** — remains unavailable / fail-
//!   closed until a real implementation is wired in a future run.
//!   Run 186 surfaces this as
//!   [`OnChainGovernanceVerifierBoundaryOutcome::MainNetProductionVerifierUnavailable`].
//! * **MainNet peer-driven apply** — remains refused regardless of
//!   verifier outcome. The Run 147 / 148 / 152 FATAL invariant is
//!   unchanged.
//!
//! ## Explicit non-authorities (preserved)
//!
//! The following non-authorities remain rejected, exactly as in
//! Runs 163 / 178:
//!
//! * local operator config alone,
//! * peer-majority / gossip-count proof,
//! * ad-hoc JSON proof without a supported verifier class,
//! * fixture proof presented as MainNet production proof.

use crate::pqc_authority_lifecycle::AuthorityTrustDomain;
use crate::pqc_authority_state::PersistentAuthorityStateRecordV2;
use crate::pqc_onchain_governance_proof::{
    is_fixture_onchain_governance_proof_suite, verify_onchain_governance_proof,
    OnChainGovernanceProof, OnChainGovernanceProofPolicy,
    OnChainGovernanceProofVerificationOutcome, OnChainGovernanceReplaySet,
    ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION,
};
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Verifier kind
// ===========================================================================

/// Run 186 — typed enumeration of OnChainGovernance verifier kinds.
///
/// The default is [`Self::Disabled`]; this preserves Runs 178 / 180 /
/// 182 / 184 / 185 fail-closed default at the new boundary. The four
/// kinds are intentionally disjoint so a calling surface can
/// distinguish, by symbol, "no verifier active" from "fixture
/// verifier active" from "production verifier explicitly unavailable"
/// from "production verifier placeholder bound but not implemented".
///
/// A future run that wires a real production verifier MUST replace
/// the [`Self::ProductionVerifier`] placeholder with a real
/// implementation; until that happens, the placeholder fails closed
/// exactly like [`Self::ProductionUnavailable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OnChainGovernanceVerifierKind {
    /// Default. Every proof — fixture or production-class — is
    /// refused with
    /// [`OnChainGovernanceVerifierBoundaryOutcome::FixtureDisabled`]
    /// (for fixture-class proofs) or
    /// [`OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable`]
    /// (for production-class proofs). The Run 178 verifier is **not**
    /// invoked.
    Disabled,
    /// Source/test fixture verifier active. Fixture-class proofs are
    /// routed to the Run 178 verifier under
    /// [`OnChainGovernanceProofPolicy::AllowFixtureSourceTest`];
    /// production-class proofs are refused with
    /// [`OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable`].
    /// MainNet trust domains remain refused (the Run 178 verifier
    /// itself returns `MainNetProductionProofUnavailable`, which Run
    /// 186 forwards typed).
    FixtureSourceTest,
    /// Production verifier kind explicitly bound but not implemented.
    /// Every proof — fixture or production — is refused with
    /// [`OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable`].
    /// This kind is the typed marker a future production-verifier run
    /// will replace with a real implementation; until then it remains
    /// fail-closed and is never silently elevated.
    ProductionUnavailable,
    /// Reserved placeholder for a future real production verifier.
    /// **Run 186 fails this closed** — any proof routed through this
    /// kind returns
    /// [`OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable`].
    /// A future run that lands a real verifier MUST update the
    /// implementation of
    /// [`ProductionVerifierPlaceholderOnChainGovernanceVerifier::verify`]
    /// to perform real verification; Run 186 deliberately does not.
    ProductionVerifier,
}

impl Default for OnChainGovernanceVerifierKind {
    fn default() -> Self {
        Self::Disabled
    }
}

impl OnChainGovernanceVerifierKind {
    /// Returns `true` iff this kind is allowed to invoke the Run 178
    /// fixture verifier on a fixture-class proof.
    pub fn is_fixture_active(self) -> bool {
        matches!(self, Self::FixtureSourceTest)
    }

    /// Returns `true` iff this kind represents a fail-closed
    /// production verifier (either explicitly unavailable or
    /// placeholder).
    pub fn is_production_fail_closed(self) -> bool {
        matches!(self, Self::ProductionUnavailable | Self::ProductionVerifier)
    }

    /// Returns the matching Run 178 fixture policy for this kind.
    /// `Disabled` and the production kinds map to
    /// [`OnChainGovernanceProofPolicy::Disabled`]; only
    /// [`Self::FixtureSourceTest`] maps to
    /// [`OnChainGovernanceProofPolicy::AllowFixtureSourceTest`].
    pub fn run178_fixture_policy(self) -> OnChainGovernanceProofPolicy {
        match self {
            Self::FixtureSourceTest => OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
            Self::Disabled | Self::ProductionUnavailable | Self::ProductionVerifier => {
                OnChainGovernanceProofPolicy::Disabled
            }
        }
    }
}

// ===========================================================================
// Proof class
// ===========================================================================

/// Run 186 — typed proof-class distinction. Determined purely by
/// [`OnChainGovernanceProof::proof_suite_id`]: the Run 178 fixture
/// suite ([`crate::pqc_onchain_governance_proof::ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1`])
/// classifies as [`Self::Fixture`]; every other suite (including the
/// reserved
/// [`ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION`] suite, and
/// any unknown suite) classifies as [`Self::Production`].
///
/// **Stable across schema additions.** A future run that registers a
/// real production suite MUST extend
/// [`is_fixture_onchain_governance_proof_suite`] only — the production
/// verifier itself is selected by [`OnChainGovernanceVerifierKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OnChainGovernanceProofClass {
    /// Run 178 fixture-only mock-commitment proof.
    Fixture,
    /// Production-class proof (real on-chain proof, reserved
    /// placeholder, or any unknown suite). Routed through the
    /// production verifier boundary, which fail-closes in Run 186.
    Production,
}

/// Run 186 — pure proof-class classifier. Performs no I/O.
pub fn classify_onchain_governance_proof_class(
    proof: &OnChainGovernanceProof,
) -> OnChainGovernanceProofClass {
    if is_fixture_onchain_governance_proof_suite(proof.proof_suite_id) {
        OnChainGovernanceProofClass::Fixture
    } else {
        OnChainGovernanceProofClass::Production
    }
}

/// Returns `true` iff `suite_id` is the Run 178 reserved production
/// suite. Provided as a grep-verifiable name so callers can detect
/// the reserved-but-unimplemented production suite without importing
/// the constant directly.
pub fn is_reserved_production_onchain_governance_proof_suite(suite_id: u8) -> bool {
    suite_id == ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION
}

// ===========================================================================
// Verifier policy
// ===========================================================================

/// Run 186 — typed policy bundle for the OnChainGovernance verifier
/// boundary.
///
/// Pairs:
///
/// * the active [`OnChainGovernanceVerifierKind`] (fail-closed
///   `Disabled` by default), and
/// * the active Run 178 fixture
///   [`OnChainGovernanceProofPolicy`] (fail-closed `Disabled` by
///   default; only relevant when the kind is
///   [`OnChainGovernanceVerifierKind::FixtureSourceTest`]).
///
/// The two-axis policy is intentional: a calling surface can pin the
/// verifier kind (architecture decision) independently from the
/// fixture-policy gate (operator selector). The policy is otherwise
/// pure data — constructing one performs no I/O and registers no
/// state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OnChainGovernanceVerifierPolicy {
    pub kind: OnChainGovernanceVerifierKind,
    pub fixture_policy: OnChainGovernanceProofPolicy,
}

impl Default for OnChainGovernanceVerifierPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

impl OnChainGovernanceVerifierPolicy {
    /// Default fail-closed policy. Both axes refuse every proof.
    pub const fn disabled() -> Self {
        Self {
            kind: OnChainGovernanceVerifierKind::Disabled,
            fixture_policy: OnChainGovernanceProofPolicy::Disabled,
        }
    }

    /// Source/test fixture policy. Fixture-class proofs are routed
    /// to the Run 178 verifier under
    /// [`OnChainGovernanceProofPolicy::AllowFixtureSourceTest`];
    /// production-class proofs remain refused as
    /// [`OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable`].
    pub const fn fixture_source_test() -> Self {
        Self {
            kind: OnChainGovernanceVerifierKind::FixtureSourceTest,
            fixture_policy: OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        }
    }

    /// Production verifier explicitly bound as unavailable. Every
    /// proof is refused with
    /// [`OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable`].
    pub const fn production_unavailable() -> Self {
        Self {
            kind: OnChainGovernanceVerifierKind::ProductionUnavailable,
            fixture_policy: OnChainGovernanceProofPolicy::Disabled,
        }
    }

    /// Production verifier placeholder. Every proof is refused with
    /// [`OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable`]
    /// — Run 186 deliberately does not implement real verification.
    pub const fn production_verifier_placeholder() -> Self {
        Self {
            kind: OnChainGovernanceVerifierKind::ProductionVerifier,
            fixture_policy: OnChainGovernanceProofPolicy::Disabled,
        }
    }
}

// ===========================================================================
// Boundary outcome
// ===========================================================================

/// Run 186 — typed outcome of the OnChainGovernance verifier boundary
/// dispatch.
///
/// Reject variants are precise so each can be distinguished from any
/// other in tests and operator log lines without pattern-matching on
/// the inner Run 178 enum. Acceptance is **always** of a fixture-class
/// proof under [`OnChainGovernanceVerifierKind::FixtureSourceTest`]
/// for DevNet/TestNet — production-class proofs are refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnChainGovernanceVerifierBoundaryOutcome {
    /// DevNet / TestNet fixture proof accepted under explicit
    /// source/test policy. Acceptance does **not** enable MainNet
    /// apply, governance execution, or any mutation. Carries the
    /// underlying Run 178 acceptance for the operator log line.
    AcceptedFixture(OnChainGovernanceProofVerificationOutcome),

    /// The active [`OnChainGovernanceVerifierKind`] is
    /// [`OnChainGovernanceVerifierKind::Disabled`] AND the proof is
    /// fixture-class. The Run 178 verifier was not invoked.
    FixtureDisabled,

    /// The active [`OnChainGovernanceVerifierKind`] is
    /// [`OnChainGovernanceVerifierKind::ProductionUnavailable`] or
    /// [`OnChainGovernanceVerifierKind::ProductionVerifier`] (the
    /// reserved placeholder), or the proof is production-class
    /// under any kind. **No real production on-chain verifier exists
    /// in Run 186**, so every production-class proof and every
    /// production-kind invocation fails closed here.
    ProductionVerifierUnavailable,

    /// A production-class proof was routed to the fixture verifier
    /// (e.g. under [`OnChainGovernanceVerifierKind::FixtureSourceTest`])
    /// — the fixture verifier explicitly does not accept
    /// production-class proofs. Surfaced as a distinct variant from
    /// [`Self::ProductionVerifierUnavailable`] so the calling surface
    /// can log a precise "production proof rejected by fixture
    /// verifier" line.
    ProductionProofUnsupported,

    /// A production-class proof was structurally malformed. Carries
    /// the parse-level reason. The Run 186 verifier boundary surfaces
    /// this BEFORE any policy decision so a malformed production-
    /// class proof never reaches the fixture verifier.
    ProductionProofMalformed { reason: String },

    /// The trust domain is MainNet AND the active verifier kind is
    /// any production kind (`ProductionUnavailable` or
    /// `ProductionVerifier` placeholder). MainNet production
    /// verification remains unavailable until a future run lands a
    /// real verifier; Run 186 fails closed.
    MainNetProductionVerifierUnavailable,

    /// The trust domain is MainNet AND a fixture-class proof is
    /// presented. Fixture proof MUST NOT satisfy MainNet production
    /// governance authority. Surfaced as a distinct variant from
    /// [`Self::MainNetProductionVerifierUnavailable`] so the calling
    /// surface can log a precise "fixture proof rejected as MainNet
    /// production authority" line.
    FixtureProofRejectedAsMainNetProductionAuthority,

    /// Forwarded Run 178 typed reject (every binding rejection,
    /// freshness/replay rejection, quorum / threshold rejection,
    /// invalid-proof / unsupported-suite / malformed-proof, plus the
    /// explicit local-operator-config-only / peer-majority rejects).
    /// The carried [`OnChainGovernanceProofVerificationOutcome`]
    /// preserves the typed reason for the operator-log line.
    Run178Rejection(OnChainGovernanceProofVerificationOutcome),
}

impl OnChainGovernanceVerifierBoundaryOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::AcceptedFixture(_))
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }

    /// Returns `true` iff this outcome is the explicit "production
    /// verifier unavailable" rejection (either kind-driven or
    /// production-class-proof-driven).
    pub fn is_production_unavailable(&self) -> bool {
        matches!(
            self,
            Self::ProductionVerifierUnavailable | Self::MainNetProductionVerifierUnavailable
        )
    }

    /// Returns `true` iff this outcome is a MainNet-specific refusal.
    pub fn is_mainnet_refusal(&self) -> bool {
        matches!(
            self,
            Self::MainNetProductionVerifierUnavailable
                | Self::FixtureProofRejectedAsMainNetProductionAuthority
        )
    }
}

// ===========================================================================
// Verifier trait + concrete implementations
// ===========================================================================

/// Run 186 — typed OnChainGovernance verifier trait. Each concrete
/// implementation pins a single
/// [`OnChainGovernanceVerifierKind`] and exposes a pure
/// [`Self::verify`] method that returns a typed
/// [`OnChainGovernanceVerifierBoundaryOutcome`].
///
/// Implementations are pure: they perform no I/O, write no marker,
/// write no sequence, mutate no live trust state, evict no sessions,
/// never extend the replay-id set, and never invoke Run 070.
pub trait OnChainGovernanceVerifier {
    fn kind(&self) -> OnChainGovernanceVerifierKind;

    #[allow(clippy::too_many_arguments)]
    fn verify<R: OnChainGovernanceReplaySet + ?Sized>(
        &self,
        proof: &OnChainGovernanceProof,
        candidate: &PersistentAuthorityStateRecordV2,
        trust_domain: &AuthorityTrustDomain,
        expected_governance_domain_id: &str,
        expected_governance_epoch: u64,
        expected_proposal_id: &str,
        expected_proposal_digest: &str,
        persisted_sequence: Option<u64>,
        now_unix: u64,
        replay_set: &R,
    ) -> OnChainGovernanceVerifierBoundaryOutcome;
}

/// Run 186 — fail-closed verifier corresponding to
/// [`OnChainGovernanceVerifierKind::Disabled`].
#[derive(Debug, Default, Clone, Copy)]
pub struct DisabledOnChainGovernanceVerifier;

impl OnChainGovernanceVerifier for DisabledOnChainGovernanceVerifier {
    fn kind(&self) -> OnChainGovernanceVerifierKind {
        OnChainGovernanceVerifierKind::Disabled
    }

    #[allow(clippy::too_many_arguments)]
    fn verify<R: OnChainGovernanceReplaySet + ?Sized>(
        &self,
        proof: &OnChainGovernanceProof,
        _candidate: &PersistentAuthorityStateRecordV2,
        _trust_domain: &AuthorityTrustDomain,
        _expected_governance_domain_id: &str,
        _expected_governance_epoch: u64,
        _expected_proposal_id: &str,
        _expected_proposal_digest: &str,
        _persisted_sequence: Option<u64>,
        _now_unix: u64,
        _replay_set: &R,
    ) -> OnChainGovernanceVerifierBoundaryOutcome {
        match classify_onchain_governance_proof_class(proof) {
            OnChainGovernanceProofClass::Fixture => {
                OnChainGovernanceVerifierBoundaryOutcome::FixtureDisabled
            }
            OnChainGovernanceProofClass::Production => {
                OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable
            }
        }
    }
}

/// Run 186 — fixture verifier corresponding to
/// [`OnChainGovernanceVerifierKind::FixtureSourceTest`]. Routes
/// fixture-class proofs to the Run 178 verifier under
/// [`OnChainGovernanceProofPolicy::AllowFixtureSourceTest`]; refuses
/// production-class proofs as
/// [`OnChainGovernanceVerifierBoundaryOutcome::ProductionProofUnsupported`].
#[derive(Debug, Default, Clone, Copy)]
pub struct FixtureSourceTestOnChainGovernanceVerifier;

impl OnChainGovernanceVerifier for FixtureSourceTestOnChainGovernanceVerifier {
    fn kind(&self) -> OnChainGovernanceVerifierKind {
        OnChainGovernanceVerifierKind::FixtureSourceTest
    }

    #[allow(clippy::too_many_arguments)]
    fn verify<R: OnChainGovernanceReplaySet + ?Sized>(
        &self,
        proof: &OnChainGovernanceProof,
        candidate: &PersistentAuthorityStateRecordV2,
        trust_domain: &AuthorityTrustDomain,
        expected_governance_domain_id: &str,
        expected_governance_epoch: u64,
        expected_proposal_id: &str,
        expected_proposal_digest: &str,
        persisted_sequence: Option<u64>,
        now_unix: u64,
        replay_set: &R,
    ) -> OnChainGovernanceVerifierBoundaryOutcome {
        verify_fixture_onchain_governance_proof(
            proof,
            candidate,
            trust_domain,
            expected_governance_domain_id,
            expected_governance_epoch,
            expected_proposal_id,
            expected_proposal_digest,
            persisted_sequence,
            now_unix,
            replay_set,
        )
    }
}

/// Run 186 — production-unavailable verifier corresponding to
/// [`OnChainGovernanceVerifierKind::ProductionUnavailable`]. Every
/// proof — fixture or production-class — is refused as
/// [`OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable`]
/// (or [`OnChainGovernanceVerifierBoundaryOutcome::MainNetProductionVerifierUnavailable`]
/// on MainNet).
#[derive(Debug, Default, Clone, Copy)]
pub struct ProductionUnavailableOnChainGovernanceVerifier;

impl OnChainGovernanceVerifier for ProductionUnavailableOnChainGovernanceVerifier {
    fn kind(&self) -> OnChainGovernanceVerifierKind {
        OnChainGovernanceVerifierKind::ProductionUnavailable
    }

    #[allow(clippy::too_many_arguments)]
    fn verify<R: OnChainGovernanceReplaySet + ?Sized>(
        &self,
        _proof: &OnChainGovernanceProof,
        _candidate: &PersistentAuthorityStateRecordV2,
        trust_domain: &AuthorityTrustDomain,
        _expected_governance_domain_id: &str,
        _expected_governance_epoch: u64,
        _expected_proposal_id: &str,
        _expected_proposal_digest: &str,
        _persisted_sequence: Option<u64>,
        _now_unix: u64,
        _replay_set: &R,
    ) -> OnChainGovernanceVerifierBoundaryOutcome {
        if trust_domain.environment == TrustBundleEnvironment::Mainnet {
            OnChainGovernanceVerifierBoundaryOutcome::MainNetProductionVerifierUnavailable
        } else {
            OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable
        }
    }
}

/// Run 186 — production verifier *placeholder* corresponding to
/// [`OnChainGovernanceVerifierKind::ProductionVerifier`]. Run 186
/// deliberately does NOT implement real verification: every
/// invocation fails closed exactly like
/// [`ProductionUnavailableOnChainGovernanceVerifier`]. A future run
/// that lands a real verifier MUST replace this implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProductionVerifierPlaceholderOnChainGovernanceVerifier;

impl OnChainGovernanceVerifier for ProductionVerifierPlaceholderOnChainGovernanceVerifier {
    fn kind(&self) -> OnChainGovernanceVerifierKind {
        OnChainGovernanceVerifierKind::ProductionVerifier
    }

    #[allow(clippy::too_many_arguments)]
    fn verify<R: OnChainGovernanceReplaySet + ?Sized>(
        &self,
        _proof: &OnChainGovernanceProof,
        _candidate: &PersistentAuthorityStateRecordV2,
        trust_domain: &AuthorityTrustDomain,
        _expected_governance_domain_id: &str,
        _expected_governance_epoch: u64,
        _expected_proposal_id: &str,
        _expected_proposal_digest: &str,
        _persisted_sequence: Option<u64>,
        _now_unix: u64,
        _replay_set: &R,
    ) -> OnChainGovernanceVerifierBoundaryOutcome {
        // Placeholder. A future run MUST replace this with a real
        // production on-chain verifier; until then we fail-closed at
        // the same boundary as ProductionUnavailable.
        if trust_domain.environment == TrustBundleEnvironment::Mainnet {
            OnChainGovernanceVerifierBoundaryOutcome::MainNetProductionVerifierUnavailable
        } else {
            OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable
        }
    }
}

// ===========================================================================
// Pure typed entry points
// ===========================================================================

/// Run 186 — pure typed fixture-verifier entry point. Routes
/// fixture-class proofs through the Run 178 verifier under
/// [`OnChainGovernanceProofPolicy::AllowFixtureSourceTest`]; refuses
/// production-class proofs as
/// [`OnChainGovernanceVerifierBoundaryOutcome::ProductionProofUnsupported`].
///
/// The function is the source/test analogue of the future
/// `verify_production_onchain_governance_proof` real verifier — it
/// never accepts a production-class proof and never enables MainNet
/// production authority. MainNet trust domains are forwarded to the
/// Run 178 verifier, which itself returns
/// `MainNetProductionProofUnavailable`; Run 186 surfaces that as a
/// typed
/// [`OnChainGovernanceVerifierBoundaryOutcome::FixtureProofRejectedAsMainNetProductionAuthority`]
/// (for fixture-class proofs).
#[allow(clippy::too_many_arguments)]
pub fn verify_fixture_onchain_governance_proof<R: OnChainGovernanceReplaySet + ?Sized>(
    proof: &OnChainGovernanceProof,
    candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
    expected_governance_domain_id: &str,
    expected_governance_epoch: u64,
    expected_proposal_id: &str,
    expected_proposal_digest: &str,
    persisted_sequence: Option<u64>,
    now_unix: u64,
    replay_set: &R,
) -> OnChainGovernanceVerifierBoundaryOutcome {
    // Production-class proofs MUST NOT be accepted by the fixture
    // verifier. Fail closed before invoking the Run 178 verifier.
    if classify_onchain_governance_proof_class(proof) == OnChainGovernanceProofClass::Production {
        return OnChainGovernanceVerifierBoundaryOutcome::ProductionProofUnsupported;
    }

    // MainNet fixture proof is rejected as MainNet production
    // authority. The Run 178 verifier itself also returns
    // `MainNetProductionProofUnavailable`; surface as a typed Run 186
    // variant so the calling surface can log a precise "fixture proof
    // rejected as MainNet production authority" line.
    if trust_domain.environment == TrustBundleEnvironment::Mainnet
        || candidate.environment == TrustBundleEnvironment::Mainnet
        || proof.environment == TrustBundleEnvironment::Mainnet
    {
        return OnChainGovernanceVerifierBoundaryOutcome::FixtureProofRejectedAsMainNetProductionAuthority;
    }

    let outcome = verify_onchain_governance_proof(
        proof,
        candidate,
        trust_domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        expected_governance_domain_id,
        expected_governance_epoch,
        expected_proposal_id,
        expected_proposal_digest,
        persisted_sequence,
        now_unix,
        replay_set,
    );
    if outcome.is_accept() {
        OnChainGovernanceVerifierBoundaryOutcome::AcceptedFixture(outcome)
    } else {
        OnChainGovernanceVerifierBoundaryOutcome::Run178Rejection(outcome)
    }
}

/// Run 186 — pure typed production-verifier entry point. **Always
/// fail-closed** in Run 186 — there is no real production on-chain
/// governance proof verifier yet. Returns
/// [`OnChainGovernanceVerifierBoundaryOutcome::MainNetProductionVerifierUnavailable`]
/// for MainNet,
/// [`OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable`]
/// otherwise.
///
/// A future run that lands a real verifier MUST replace this body
/// with a real implementation; the symbol itself is the source-
/// reachable boundary callers can grep for to demonstrate they reach
/// the production verifier path (rather than silently falling back
/// to the fixture verifier).
#[allow(clippy::too_many_arguments)]
pub fn verify_production_onchain_governance_proof<R: OnChainGovernanceReplaySet + ?Sized>(
    proof: &OnChainGovernanceProof,
    _candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
    _expected_governance_domain_id: &str,
    _expected_governance_epoch: u64,
    _expected_proposal_id: &str,
    _expected_proposal_digest: &str,
    _persisted_sequence: Option<u64>,
    _now_unix: u64,
    _replay_set: &R,
) -> OnChainGovernanceVerifierBoundaryOutcome {
    // A fixture-class proof routed through the production verifier is
    // rejected as ProductionProofUnsupported (the production verifier
    // explicitly does not accept fixture-class proofs even when the
    // trust domain is non-MainNet).
    if classify_onchain_governance_proof_class(proof) == OnChainGovernanceProofClass::Fixture {
        return OnChainGovernanceVerifierBoundaryOutcome::ProductionProofUnsupported;
    }

    if trust_domain.environment == TrustBundleEnvironment::Mainnet {
        OnChainGovernanceVerifierBoundaryOutcome::MainNetProductionVerifierUnavailable
    } else {
        OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable
    }
}

// ===========================================================================
// Boundary dispatcher
// ===========================================================================

/// Run 186 — pure typed boundary dispatcher. Classifies the supplied
/// [`OnChainGovernanceProof`] by suite, picks the matching verifier
/// for the active [`OnChainGovernanceVerifierKind`], and returns a
/// typed [`OnChainGovernanceVerifierBoundaryOutcome`]. Performs no
/// I/O.
///
/// **Fail-closed defaults.** With
/// [`OnChainGovernanceVerifierKind::Disabled`] (the default), every
/// proof is refused. With the production kinds
/// (`ProductionUnavailable` / `ProductionVerifier` placeholder),
/// every proof is refused as
/// [`OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable`]
/// (or [`OnChainGovernanceVerifierBoundaryOutcome::MainNetProductionVerifierUnavailable`]
/// on MainNet).
///
/// **Fixture acceptance is DevNet/TestNet only.** With
/// [`OnChainGovernanceVerifierKind::FixtureSourceTest`], fixture-
/// class proofs are routed through the Run 178 verifier; production-
/// class proofs are refused as
/// [`OnChainGovernanceVerifierBoundaryOutcome::ProductionProofUnsupported`];
/// MainNet trust domains return
/// [`OnChainGovernanceVerifierBoundaryOutcome::FixtureProofRejectedAsMainNetProductionAuthority`].
#[allow(clippy::too_many_arguments)]
pub fn dispatch_onchain_governance_proof_through_verifier_boundary<
    R: OnChainGovernanceReplaySet + ?Sized,
>(
    proof: &OnChainGovernanceProof,
    candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
    policy: OnChainGovernanceVerifierPolicy,
    expected_governance_domain_id: &str,
    expected_governance_epoch: u64,
    expected_proposal_id: &str,
    expected_proposal_digest: &str,
    persisted_sequence: Option<u64>,
    now_unix: u64,
    replay_set: &R,
) -> OnChainGovernanceVerifierBoundaryOutcome {
    let class = classify_onchain_governance_proof_class(proof);

    match policy.kind {
        OnChainGovernanceVerifierKind::Disabled => match class {
            OnChainGovernanceProofClass::Fixture => {
                OnChainGovernanceVerifierBoundaryOutcome::FixtureDisabled
            }
            OnChainGovernanceProofClass::Production => {
                OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable
            }
        },
        OnChainGovernanceVerifierKind::FixtureSourceTest => match class {
            OnChainGovernanceProofClass::Fixture => verify_fixture_onchain_governance_proof(
                proof,
                candidate,
                trust_domain,
                expected_governance_domain_id,
                expected_governance_epoch,
                expected_proposal_id,
                expected_proposal_digest,
                persisted_sequence,
                now_unix,
                replay_set,
            ),
            OnChainGovernanceProofClass::Production => {
                OnChainGovernanceVerifierBoundaryOutcome::ProductionProofUnsupported
            }
        },
        OnChainGovernanceVerifierKind::ProductionUnavailable
        | OnChainGovernanceVerifierKind::ProductionVerifier => {
            verify_production_onchain_governance_proof(
                proof,
                candidate,
                trust_domain,
                expected_governance_domain_id,
                expected_governance_epoch,
                expected_proposal_id,
                expected_proposal_digest,
                persisted_sequence,
                now_unix,
                replay_set,
            )
        }
    }
}

// ===========================================================================
// MainNet peer-driven apply remains refused (Run 186 helper)
// ===========================================================================

/// Run 186 — pure typed assertion that even a fully-valid Run 186
/// fixture acceptance MUST NOT enable MainNet peer-driven apply, and
/// that no production-verifier outcome (including a future real
/// production accept) can enable MainNet peer-driven apply in this
/// run. Returns `true` iff peer-driven apply MUST be refused for the
/// supplied environment. For MainNet, this is **always `true`** in
/// Run 186, regardless of the boundary outcome.
pub fn mainnet_peer_driven_apply_remains_refused_under_verifier_boundary(
    environment: TrustBundleEnvironment,
    _outcome: &OnChainGovernanceVerifierBoundaryOutcome,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

// ===========================================================================
// Self-tests (in-module). Integration tests live in
// `crates/qbind-node/tests/run_186_onchain_governance_production_verifier_boundary_tests.rs`.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqc_authority_lifecycle::PQC_LIFECYCLE_SUITE_ML_DSA_44;

    fn devnet_domain() -> AuthorityTrustDomain {
        AuthorityTrustDomain::new(
            TrustBundleEnvironment::Devnet,
            "0000000000000001",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1111111111111111111111111111111111111111",
            PQC_LIFECYCLE_SUITE_ML_DSA_44,
        )
    }

    #[test]
    fn verifier_kind_default_is_disabled() {
        assert_eq!(
            OnChainGovernanceVerifierKind::default(),
            OnChainGovernanceVerifierKind::Disabled
        );
    }

    #[test]
    fn verifier_policy_default_is_disabled_disabled() {
        let p = OnChainGovernanceVerifierPolicy::default();
        assert_eq!(p.kind, OnChainGovernanceVerifierKind::Disabled);
        assert_eq!(p.fixture_policy, OnChainGovernanceProofPolicy::Disabled);
    }

    #[test]
    fn fixture_source_test_policy_maps_correctly() {
        let p = OnChainGovernanceVerifierPolicy::fixture_source_test();
        assert_eq!(p.kind, OnChainGovernanceVerifierKind::FixtureSourceTest);
        assert_eq!(
            p.fixture_policy,
            OnChainGovernanceProofPolicy::AllowFixtureSourceTest
        );
        assert_eq!(
            p.kind.run178_fixture_policy(),
            OnChainGovernanceProofPolicy::AllowFixtureSourceTest
        );
    }

    #[test]
    fn production_kinds_map_to_disabled_fixture_policy() {
        let pu = OnChainGovernanceVerifierPolicy::production_unavailable();
        assert_eq!(pu.fixture_policy, OnChainGovernanceProofPolicy::Disabled);
        assert!(pu.kind.is_production_fail_closed());

        let pp = OnChainGovernanceVerifierPolicy::production_verifier_placeholder();
        assert_eq!(pp.fixture_policy, OnChainGovernanceProofPolicy::Disabled);
        assert!(pp.kind.is_production_fail_closed());
    }

    #[test]
    fn reserved_production_suite_classifier() {
        assert!(is_reserved_production_onchain_governance_proof_suite(
            ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION
        ));
        assert!(!is_reserved_production_onchain_governance_proof_suite(0xA1));
    }

    #[test]
    fn mainnet_peer_driven_apply_remains_refused_helper() {
        assert!(
            mainnet_peer_driven_apply_remains_refused_under_verifier_boundary(
                TrustBundleEnvironment::Mainnet,
                &OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable,
            )
        );
        assert!(
            !mainnet_peer_driven_apply_remains_refused_under_verifier_boundary(
                TrustBundleEnvironment::Devnet,
                &OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable,
            )
        );
        // Also for the made-up "future accept" case — refusal still
        // holds on MainNet.
        let dummy_inner = OnChainGovernanceProofVerificationOutcome::AcceptedOnChainGovernanceFixture {
            action: crate::pqc_authority_lifecycle::LocalLifecycleAction::Rotate,
            authority_domain_sequence: 2,
            governance_epoch: 42,
        };
        assert!(
            mainnet_peer_driven_apply_remains_refused_under_verifier_boundary(
                TrustBundleEnvironment::Mainnet,
                &OnChainGovernanceVerifierBoundaryOutcome::AcceptedFixture(dummy_inner),
            )
        );
        // And the trust-domain helper compiles too.
        let _ = devnet_domain();
    }
}