//! Run 178 — source/test-only typed `OnChainGovernance` proof format and
//! fail-closed verifier boundary.
//!
//! ## Strict scope
//!
//! Source/test only. Run 178 does **not**:
//!
//! * enable MainNet peer-driven apply,
//! * implement a governance execution engine,
//! * implement real on-chain governance proof verification for MainNet,
//! * implement KMS/HSM custody,
//! * implement validator-set rotation,
//! * autonomously apply on receipt,
//! * accept peer-majority / gossip count as an OnChainGovernance proof,
//! * accept local operator config alone as an OnChainGovernance proof,
//! * change the v2 marker / sequence-file / trust-bundle core schema.
//!
//! Release-binary `OnChainGovernance` proof evidence is **deferred to
//! Run 179**.
//!
//! ## What this module adds
//!
//! Before Run 178 the Run 163
//! [`crate::pqc_governance_authority::GovernanceAuthorityClass::OnChainGovernance`]
//! authority class had only a single fail-closed outcome
//! (`UnsupportedOnChainGovernance`). Run 178 adds a typed, fixture-only
//! [`OnChainGovernanceProof`] object plus a pure verifier
//! [`verify_onchain_governance_proof`] that returns one of a fixed set of
//! typed outcomes:
//!
//! * [`OnChainGovernanceProofVerificationOutcome::AcceptedOnChainGovernanceFixture`]
//! * [`OnChainGovernanceProofVerificationOutcome::UnsupportedProductionOnChainGovernance`]
//! * [`OnChainGovernanceProofVerificationOutcome::MainNetProductionProofUnavailable`]
//! * `WrongEnvironment`, `WrongChain`, `WrongGenesis`, `WrongAuthorityRoot`
//! * `WrongGovernanceDomain`, `WrongGovernanceEpoch`, `WrongProposalDigest`,
//!   `WrongProposalOutcome`, `WrongLifecycleAction`, `WrongCandidateDigest`,
//!   `WrongAuthoritySequence`
//! * `ExpiredGovernanceProof`, `ReplayRejected`, `QuorumNotMet`,
//!   `ThresholdNotMet`
//! * `InvalidGovernanceProof`, `UnsupportedGovernanceProofSuite`,
//!   `MalformedOnChainProof`
//! * `LocalOperatorConfigOnlyRejected`, `PeerMajorityProofRejected`
//!
//! The proof itself is explicitly typed as a **fixture-only** object and
//! is bound to every domain/lifecycle/governance binding a future MainNet
//! production verifier would need. The fixture suite is a deterministic
//! mock commitment over those bindings; **production MainNet proofs are
//! refused** as `MainNetProductionProofUnavailable` regardless of policy.
//!
//! ## Pure / non-mutating
//!
//! The verifier performs no I/O, writes no marker, writes no sequence,
//! mutates no live trust state, and never elevates a fixture proof into a
//! MainNet apply. Replay protection is supplied by the caller as a
//! reference to an in-memory replay-id set; the verifier never extends
//! that set.
//!
//! ## Policy
//!
//! * [`OnChainGovernanceProofPolicy::Disabled`] — default. Every proof
//!   (well-formed or not) is refused as
//!   `UnsupportedProductionOnChainGovernance`.
//! * [`OnChainGovernanceProofPolicy::AllowFixtureSourceTest`] — explicit
//!   source/test policy. DevNet/TestNet fixture proofs may be accepted;
//!   MainNet remains refused as `MainNetProductionProofUnavailable`.

use serde::{Deserialize, Serialize};

use crate::pqc_authority_lifecycle::{
    is_pqc_lifecycle_suite, AuthorityTrustDomain, LocalLifecycleAction,
};
use crate::pqc_authority_state::PersistentAuthorityStateRecordV2;
use crate::pqc_governance_authority::{
    classify_candidate_lifecycle_action, GovernanceAuthorityClass, GovernanceThreshold,
};
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Suite IDs
// ===========================================================================

/// Fixture-only `OnChainGovernance` proof suite id.
///
/// This suite encodes a deterministic commitment over every binding the
/// proof claims (chain, environment, governance domain, proposal,
/// lifecycle, candidate digest, sequence, freshness, replay id). It is
/// **NOT** a real on-chain proof verifier; it exists so the
/// source/test fixture matrix has an end-to-end accept path that
/// exercises the typed verifier surface without inventing a production
/// proof format.
pub const ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1: u8 = 0xA1;

/// Reserved suite id for a future real on-chain governance proof
/// verifier. Run 178 rejects this suite as
/// [`OnChainGovernanceProofVerificationOutcome::UnsupportedGovernanceProofSuite`]
/// — a future run that wires a real verifier MUST register that
/// suite explicitly; Run 178 deliberately does not implement it.
pub const ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION: u8 = 0xA2;

/// Returns `true` iff `suite_id` is a Run 178 source/test fixture suite.
pub fn is_fixture_onchain_governance_proof_suite(suite_id: u8) -> bool {
    suite_id == ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1
}

// ===========================================================================
// Top-level policy
// ===========================================================================

/// Policy gate that decides whether `OnChainGovernance` fixture proofs
/// may be accepted at all.
///
/// Default is [`Self::Disabled`]: this preserves Run 163's fail-closed
/// behavior and ensures the new typed proof format does NOT silently
/// open an apply path on any production surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnChainGovernanceProofPolicy {
    /// `OnChainGovernance` is unsupported. Any proof — fixture or
    /// otherwise — returns
    /// [`OnChainGovernanceProofVerificationOutcome::UnsupportedProductionOnChainGovernance`].
    Disabled,
    /// Source/test policy: DevNet/TestNet fixture proofs may be accepted
    /// when every binding matches. MainNet still returns
    /// [`OnChainGovernanceProofVerificationOutcome::MainNetProductionProofUnavailable`]
    /// regardless of fixture validity.
    AllowFixtureSourceTest,
}

impl Default for OnChainGovernanceProofPolicy {
    fn default() -> Self {
        Self::Disabled
    }
}

// ===========================================================================
// Proof building blocks
// ===========================================================================

/// Outcome of the (mock) governance proposal that authorized a given
/// lifecycle action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OnChainGovernanceProposalOutcome {
    /// Proposal approved — proof may authorize the lifecycle action.
    Approved,
    /// Proposal rejected — verifier returns `WrongProposalOutcome`.
    Rejected,
}

/// Quorum metadata. The proof asserts that `voters_voted` of
/// `total_voters` voted, with `required_quorum` as the minimum for the
/// proposal to be considered quorate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnChainGovernanceQuorum {
    pub voters_voted: u32,
    pub total_voters: u32,
    pub required_quorum: u32,
}

impl OnChainGovernanceQuorum {
    pub fn is_well_formed(&self) -> bool {
        self.required_quorum >= 1
            && self.total_voters >= self.required_quorum
            && self.voters_voted <= self.total_voters
    }

    pub fn is_met(&self) -> bool {
        self.is_well_formed() && self.voters_voted >= self.required_quorum
    }
}

/// Inclusive proof-freshness window. The verifier accepts only when
/// `not_before_unix <= now_unix <= not_after_unix`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnChainGovernanceFreshnessWindow {
    pub not_before_unix: u64,
    pub not_after_unix: u64,
}

impl OnChainGovernanceFreshnessWindow {
    pub fn is_well_formed(&self) -> bool {
        self.not_before_unix <= self.not_after_unix
    }

    pub fn is_within(&self, now_unix: u64) -> bool {
        self.is_well_formed() && now_unix >= self.not_before_unix && now_unix <= self.not_after_unix
    }
}

// ===========================================================================
// Proof object
// ===========================================================================

/// Typed `OnChainGovernance` proof object.
///
/// Source/test fixture only. Carries every binding a future MainNet
/// real-on-chain verifier would need:
///
/// * trust-domain binding (`environment`, `chain_id`, `genesis_hash`,
///   `authority_root_fingerprint`);
/// * governance binding (`governance_domain_id`, `governance_epoch`,
///   `proposal_id`, `proposal_digest`, `proposal_outcome`, `quorum`,
///   `threshold`);
/// * lifecycle binding (`lifecycle_action`,
///   `active_bundle_signing_key_fingerprint`,
///   `new_bundle_signing_key_fingerprint`,
///   `revoked_bundle_signing_key_fingerprint`);
/// * sequence binding (`authority_domain_sequence`,
///   `candidate_v2_digest`);
/// * freshness window (`freshness`);
/// * replay-protection nonce (`unique_decision_id`);
/// * proof material (`proof_suite_id`, `proof_bytes`).
///
/// The proof carries the `GovernanceAuthorityClass::OnChainGovernance`
/// class implicitly — there is no other class for this object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnChainGovernanceProof {
    // ---- Trust-domain binding -----------------------------------------
    pub environment: TrustBundleEnvironment,
    pub chain_id: String,
    pub genesis_hash: String,
    pub authority_root_fingerprint: String,
    pub authority_root_suite_id: u8,

    // ---- Governance binding -------------------------------------------
    pub governance_domain_id: String,
    pub governance_epoch: u64,
    pub proposal_id: String,
    pub proposal_digest: String,
    pub proposal_outcome: OnChainGovernanceProposalOutcome,
    pub quorum: OnChainGovernanceQuorum,
    pub threshold: GovernanceThreshold,

    // ---- Lifecycle binding --------------------------------------------
    pub lifecycle_action: LocalLifecycleAction,
    pub active_bundle_signing_key_fingerprint: String,
    pub new_bundle_signing_key_fingerprint: Option<String>,
    pub revoked_bundle_signing_key_fingerprint: Option<String>,

    // ---- Sequence + digest binding ------------------------------------
    pub authority_domain_sequence: u64,
    pub candidate_v2_digest: String,

    // ---- Freshness + replay -------------------------------------------
    pub freshness: OnChainGovernanceFreshnessWindow,
    pub unique_decision_id: String,

    // ---- Proof material -----------------------------------------------
    pub proof_suite_id: u8,
    pub proof_bytes: Vec<u8>,
}

// ===========================================================================
// Outcomes
// ===========================================================================

/// Typed outcome of [`verify_onchain_governance_proof`].
///
/// Reject variants are precise so each can be distinguished from any
/// other in tests / operator log lines. Acceptance is **always** of a
/// fixture proof — production MainNet proofs are refused as
/// [`Self::MainNetProductionProofUnavailable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnChainGovernanceProofVerificationOutcome {
    /// DevNet/TestNet fixture proof accepted under explicit source/test
    /// policy. Acceptance does **not** enable MainNet apply, governance
    /// execution, or any mutation.
    AcceptedOnChainGovernanceFixture {
        action: LocalLifecycleAction,
        authority_domain_sequence: u64,
        governance_epoch: u64,
    },

    /// Policy is `Disabled`: any `OnChainGovernance` proof is refused.
    /// This is the default Run 163 behavior preserved by Run 178.
    UnsupportedProductionOnChainGovernance,

    /// Even under `AllowFixtureSourceTest` policy, MainNet
    /// `OnChainGovernance` proofs are refused — Run 178 has no real
    /// on-chain proof verifier and Run 178 explicitly does not enable
    /// MainNet apply.
    MainNetProductionProofUnavailable,

    // ---- Domain-binding rejects ---------------------------------------
    WrongEnvironment {
        expected: TrustBundleEnvironment,
        candidate: TrustBundleEnvironment,
    },
    WrongChain {
        expected: String,
        candidate: String,
    },
    WrongGenesis {
        expected: String,
        candidate: String,
    },
    WrongAuthorityRoot {
        expected: String,
        candidate: String,
    },

    // ---- Governance-binding rejects -----------------------------------
    WrongGovernanceDomain {
        expected: String,
        candidate: String,
    },
    WrongGovernanceEpoch {
        expected: u64,
        candidate: u64,
    },
    WrongProposalDigest {
        expected: String,
        candidate: String,
    },
    WrongProposalOutcome {
        candidate: OnChainGovernanceProposalOutcome,
    },

    // ---- Lifecycle / digest / sequence rejects ------------------------
    WrongLifecycleAction {
        expected: LocalLifecycleAction,
        candidate: LocalLifecycleAction,
    },
    WrongCandidateDigest {
        expected: String,
        candidate: String,
    },
    WrongAuthoritySequence {
        expected: u64,
        candidate: u64,
    },

    // ---- Freshness / replay -------------------------------------------
    ExpiredGovernanceProof {
        now_unix: u64,
        not_before_unix: u64,
        not_after_unix: u64,
    },
    ReplayRejected {
        unique_decision_id: String,
    },

    // ---- Quorum / threshold -------------------------------------------
    QuorumNotMet {
        voters_voted: u32,
        required_quorum: u32,
    },
    ThresholdNotMet {
        approvals: u32,
        required: u32,
    },

    // ---- Suite / structural / signature -------------------------------
    UnsupportedGovernanceProofSuite {
        suite_id: u8,
    },
    InvalidGovernanceProof {
        reason: String,
    },
    MalformedOnChainProof {
        reason: String,
    },

    // ---- Explicit non-authority rejects -------------------------------
    /// Local operator config alone is rejected as an
    /// `OnChainGovernance` proof.
    LocalOperatorConfigOnlyRejected,
    /// Peer-majority / gossip count is rejected as an
    /// `OnChainGovernance` proof.
    PeerMajorityProofRejected,
}

impl OnChainGovernanceProofVerificationOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::AcceptedOnChainGovernanceFixture { .. })
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }

    pub fn class(&self) -> GovernanceAuthorityClass {
        GovernanceAuthorityClass::OnChainGovernance
    }
}

// ===========================================================================
// Replay set
// ===========================================================================

/// Caller-owned replay-id set handed to the pure verifier.
///
/// The verifier reads from this set but never mutates it. Replay
/// detection is purely a function of the supplied set: the verifier
/// returns [`OnChainGovernanceProofVerificationOutcome::ReplayRejected`]
/// iff the proof's `unique_decision_id` is already present.
pub trait OnChainGovernanceReplaySet {
    fn contains(&self, unique_decision_id: &str) -> bool;
}

impl OnChainGovernanceReplaySet for &[String] {
    fn contains(&self, unique_decision_id: &str) -> bool {
        (*self).iter().any(|s| s == unique_decision_id)
    }
}

impl OnChainGovernanceReplaySet for Vec<String> {
    fn contains(&self, unique_decision_id: &str) -> bool {
        self.iter().any(|s| s == unique_decision_id)
    }
}

/// Empty replay set helper — convenient default for tests where replay
/// is not under exercise.
pub struct EmptyOnChainGovernanceReplaySet;

impl OnChainGovernanceReplaySet for EmptyOnChainGovernanceReplaySet {
    fn contains(&self, _unique_decision_id: &str) -> bool {
        false
    }
}

// ===========================================================================
// Mock fixture proof commitment
// ===========================================================================

/// Build the deterministic fixture-mock proof commitment bytes for the
/// supplied bindings.
///
/// This is the source/test analogue of "real on-chain proof
/// verification": the byte string is a canonical concatenation of every
/// binding the verifier checks, so a wrong-domain / wrong-proposal /
/// wrong-digest / wrong-sequence proof's `proof_bytes` will not equal
/// the expected commitment, and the verifier will reject it as
/// [`OnChainGovernanceProofVerificationOutcome::InvalidGovernanceProof`].
///
/// Source/test only. A future real on-chain verifier MUST replace this
/// with a real cryptographic proof check; Run 178 deliberately does not
/// implement that.
#[allow(clippy::too_many_arguments)]
pub fn fixture_onchain_governance_proof_bytes(
    environment: TrustBundleEnvironment,
    chain_id: &str,
    genesis_hash: &str,
    authority_root_fingerprint: &str,
    governance_domain_id: &str,
    governance_epoch: u64,
    proposal_id: &str,
    proposal_digest: &str,
    candidate_v2_digest: &str,
    authority_domain_sequence: u64,
    unique_decision_id: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"qbind-run178-onchain-gov:");
    out.extend_from_slice(environment_tag(environment).as_bytes());
    out.extend_from_slice(b":");
    out.extend_from_slice(chain_id.as_bytes());
    out.extend_from_slice(b":");
    out.extend_from_slice(genesis_hash.as_bytes());
    out.extend_from_slice(b":");
    out.extend_from_slice(authority_root_fingerprint.as_bytes());
    out.extend_from_slice(b":");
    out.extend_from_slice(governance_domain_id.as_bytes());
    out.extend_from_slice(b":");
    out.extend_from_slice(&governance_epoch.to_be_bytes());
    out.extend_from_slice(b":");
    out.extend_from_slice(proposal_id.as_bytes());
    out.extend_from_slice(b":");
    out.extend_from_slice(proposal_digest.as_bytes());
    out.extend_from_slice(b":");
    out.extend_from_slice(candidate_v2_digest.as_bytes());
    out.extend_from_slice(b":");
    out.extend_from_slice(&authority_domain_sequence.to_be_bytes());
    out.extend_from_slice(b":");
    out.extend_from_slice(unique_decision_id.as_bytes());
    out
}

const fn environment_tag(env: TrustBundleEnvironment) -> &'static str {
    match env {
        TrustBundleEnvironment::Mainnet => "mainnet",
        TrustBundleEnvironment::Testnet => "testnet",
        TrustBundleEnvironment::Devnet => "devnet",
    }
}

// ===========================================================================
// Pure verifier
// ===========================================================================

/// Pure typed `OnChainGovernance` proof verifier.
///
/// Performs **no I/O**. Never mutates persisted state, never extends the
/// replay set, never enables MainNet apply. The verifier checks every
/// binding (environment, chain, genesis, authority root, governance
/// domain, governance epoch, proposal id, proposal digest, proposal
/// outcome, lifecycle action, candidate digest, authority sequence,
/// freshness, replay id, quorum, threshold, suite, proof bytes) against
/// the candidate v2 record, the expected trust domain, and the policy.
///
/// Acceptance is always of a **fixture** proof under
/// [`OnChainGovernanceProofPolicy::AllowFixtureSourceTest`] for
/// DevNet/TestNet. MainNet always returns
/// [`OnChainGovernanceProofVerificationOutcome::MainNetProductionProofUnavailable`].
#[allow(clippy::too_many_arguments)]
pub fn verify_onchain_governance_proof<R: OnChainGovernanceReplaySet + ?Sized>(
    proof: &OnChainGovernanceProof,
    candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
    policy: OnChainGovernanceProofPolicy,
    expected_governance_domain_id: &str,
    expected_governance_epoch: u64,
    expected_proposal_id: &str,
    expected_proposal_digest: &str,
    persisted_sequence: Option<u64>,
    now_unix: u64,
    replay_set: &R,
) -> OnChainGovernanceProofVerificationOutcome {
    use OnChainGovernanceProofVerificationOutcome as O;

    // ---- Policy gate (Disabled = always fail closed) ------------------
    if policy == OnChainGovernanceProofPolicy::Disabled {
        return O::UnsupportedProductionOnChainGovernance;
    }

    // ---- MainNet always refused (no real verifier exists yet) ---------
    if proof.environment == TrustBundleEnvironment::Mainnet
        || trust_domain.environment == TrustBundleEnvironment::Mainnet
        || candidate.environment == TrustBundleEnvironment::Mainnet
    {
        return O::MainNetProductionProofUnavailable;
    }

    // ---- Suite enforcement --------------------------------------------
    if !is_fixture_onchain_governance_proof_suite(proof.proof_suite_id) {
        return O::UnsupportedGovernanceProofSuite {
            suite_id: proof.proof_suite_id,
        };
    }
    if !is_pqc_lifecycle_suite(proof.authority_root_suite_id) {
        return O::MalformedOnChainProof {
            reason: format!(
                "non-PQC authority_root_suite_id={} on OnChainGovernance proof",
                proof.authority_root_suite_id
            ),
        };
    }

    // ---- Structural well-formedness -----------------------------------
    if proof.chain_id.is_empty()
        || proof.genesis_hash.is_empty()
        || proof.authority_root_fingerprint.is_empty()
        || proof.governance_domain_id.is_empty()
        || proof.proposal_id.is_empty()
        || proof.proposal_digest.is_empty()
        || proof.active_bundle_signing_key_fingerprint.is_empty()
        || proof.candidate_v2_digest.is_empty()
        || proof.unique_decision_id.is_empty()
    {
        return O::MalformedOnChainProof {
            reason: "OnChainGovernance proof has empty required field".to_string(),
        };
    }
    if proof.proof_bytes.is_empty() {
        return O::MalformedOnChainProof {
            reason: "OnChainGovernance proof carries empty proof_bytes".to_string(),
        };
    }
    if !proof.freshness.is_well_formed() {
        return O::MalformedOnChainProof {
            reason: format!(
                "OnChainGovernance freshness window malformed: not_before={} not_after={}",
                proof.freshness.not_before_unix, proof.freshness.not_after_unix
            ),
        };
    }
    if !proof.quorum.is_well_formed() {
        return O::MalformedOnChainProof {
            reason: format!(
                "OnChainGovernance quorum malformed: voted={} total={} required={}",
                proof.quorum.voters_voted,
                proof.quorum.total_voters,
                proof.quorum.required_quorum
            ),
        };
    }
    if !proof.threshold.is_well_formed() {
        return O::MalformedOnChainProof {
            reason: format!(
                "OnChainGovernance threshold malformed: approvals={} required={} total={}",
                proof.threshold.approvals, proof.threshold.required, proof.threshold.total
            ),
        };
    }

    // ---- Trust-domain binding (proof side) ----------------------------
    if proof.environment != trust_domain.environment {
        return O::WrongEnvironment {
            expected: trust_domain.environment,
            candidate: proof.environment,
        };
    }
    if proof.chain_id != trust_domain.chain_id {
        return O::WrongChain {
            expected: trust_domain.chain_id.clone(),
            candidate: proof.chain_id.clone(),
        };
    }
    if proof.genesis_hash != trust_domain.genesis_hash {
        return O::WrongGenesis {
            expected: trust_domain.genesis_hash.clone(),
            candidate: proof.genesis_hash.clone(),
        };
    }
    if proof.authority_root_fingerprint != trust_domain.authority_root_fingerprint
        || proof.authority_root_suite_id != trust_domain.authority_root_suite_id
    {
        return O::WrongAuthorityRoot {
            expected: trust_domain.authority_root_fingerprint.clone(),
            candidate: proof.authority_root_fingerprint.clone(),
        };
    }

    // ---- Trust-domain binding (candidate side) ------------------------
    if candidate.environment != trust_domain.environment {
        return O::WrongEnvironment {
            expected: trust_domain.environment,
            candidate: candidate.environment,
        };
    }
    if candidate.chain_id != trust_domain.chain_id {
        return O::WrongChain {
            expected: trust_domain.chain_id.clone(),
            candidate: candidate.chain_id.clone(),
        };
    }
    if candidate.genesis_hash != trust_domain.genesis_hash {
        return O::WrongGenesis {
            expected: trust_domain.genesis_hash.clone(),
            candidate: candidate.genesis_hash.clone(),
        };
    }
    if candidate.authority_root_fingerprint != trust_domain.authority_root_fingerprint {
        return O::WrongAuthorityRoot {
            expected: trust_domain.authority_root_fingerprint.clone(),
            candidate: candidate.authority_root_fingerprint.clone(),
        };
    }

    // ---- Governance binding -------------------------------------------
    if proof.governance_domain_id != expected_governance_domain_id {
        return O::WrongGovernanceDomain {
            expected: expected_governance_domain_id.to_string(),
            candidate: proof.governance_domain_id.clone(),
        };
    }
    if proof.governance_epoch != expected_governance_epoch {
        return O::WrongGovernanceEpoch {
            expected: expected_governance_epoch,
            candidate: proof.governance_epoch,
        };
    }
    if proof.proposal_id != expected_proposal_id {
        return O::WrongProposalDigest {
            // proposal_id is a structural ID; mismatched proposal_id ==
            // mismatched proposal binding from the verifier's POV.
            expected: expected_proposal_id.to_string(),
            candidate: proof.proposal_id.clone(),
        };
    }
    if proof.proposal_digest != expected_proposal_digest {
        return O::WrongProposalDigest {
            expected: expected_proposal_digest.to_string(),
            candidate: proof.proposal_digest.clone(),
        };
    }
    if proof.proposal_outcome != OnChainGovernanceProposalOutcome::Approved {
        return O::WrongProposalOutcome {
            candidate: proof.proposal_outcome,
        };
    }

    // ---- Candidate binding (digest + sequence + lifecycle) ------------
    if proof.candidate_v2_digest != candidate.latest_ratification_v2_digest {
        return O::WrongCandidateDigest {
            expected: candidate.latest_ratification_v2_digest.clone(),
            candidate: proof.candidate_v2_digest.clone(),
        };
    }
    if proof.authority_domain_sequence != candidate.latest_authority_domain_sequence {
        return O::WrongAuthoritySequence {
            expected: candidate.latest_authority_domain_sequence,
            candidate: proof.authority_domain_sequence,
        };
    }
    let candidate_action_class = match classify_candidate_lifecycle_action(candidate) {
        Ok(a) => a,
        Err(reason) => return O::MalformedOnChainProof { reason },
    };
    if proof.lifecycle_action != candidate_action_class {
        return O::WrongLifecycleAction {
            expected: candidate_action_class,
            candidate: proof.lifecycle_action,
        };
    }
    if proof.active_bundle_signing_key_fingerprint
        != candidate.active_bundle_signing_key_fingerprint
    {
        return O::MalformedOnChainProof {
            reason: "OnChainGovernance proof active key fingerprint does not match candidate"
                .to_string(),
        };
    }
    match proof.lifecycle_action {
        LocalLifecycleAction::Rotate => {
            let cand_prev = candidate
                .previous_bundle_signing_key_fingerprint
                .as_deref()
                .unwrap_or("");
            if let Some(new_fp) = proof.new_bundle_signing_key_fingerprint.as_deref() {
                if new_fp != candidate.active_bundle_signing_key_fingerprint {
                    return O::MalformedOnChainProof {
                        reason: "rotate proof new key does not match candidate active key"
                            .to_string(),
                    };
                }
            }
            if let Some(rev_fp) = proof.revoked_bundle_signing_key_fingerprint.as_deref() {
                if rev_fp != cand_prev {
                    return O::MalformedOnChainProof {
                        reason: "rotate proof revoked key does not match candidate previous key"
                            .to_string(),
                    };
                }
            }
        }
        LocalLifecycleAction::Retire
        | LocalLifecycleAction::Revoke
        | LocalLifecycleAction::EmergencyRevoke => {
            let target = candidate
                .revoked_key_metadata
                .as_deref()
                .and_then(|m| m.get(2..))
                .unwrap_or("");
            if let Some(rev_fp) = proof.revoked_bundle_signing_key_fingerprint.as_deref() {
                if rev_fp != target {
                    return O::MalformedOnChainProof {
                        reason: "revoke-class proof revoked key does not match candidate metadata"
                            .to_string(),
                    };
                }
            }
        }
        LocalLifecycleAction::ActivateInitial => {}
    }

    // ---- Stale-lower-sequence replay ---------------------------------
    if let Some(prev_seq) = persisted_sequence {
        if proof.authority_domain_sequence < prev_seq {
            return O::ReplayRejected {
                unique_decision_id: proof.unique_decision_id.clone(),
            };
        }
    }
    // ---- Replay-id replay --------------------------------------------
    if replay_set.contains(&proof.unique_decision_id) {
        return O::ReplayRejected {
            unique_decision_id: proof.unique_decision_id.clone(),
        };
    }

    // ---- Freshness ----------------------------------------------------
    if !proof.freshness.is_within(now_unix) {
        return O::ExpiredGovernanceProof {
            now_unix,
            not_before_unix: proof.freshness.not_before_unix,
            not_after_unix: proof.freshness.not_after_unix,
        };
    }

    // ---- Quorum / threshold ------------------------------------------
    if !proof.quorum.is_met() {
        return O::QuorumNotMet {
            voters_voted: proof.quorum.voters_voted,
            required_quorum: proof.quorum.required_quorum,
        };
    }
    if !proof.threshold.is_met() {
        return O::ThresholdNotMet {
            approvals: proof.threshold.approvals,
            required: proof.threshold.required,
        };
    }

    // ---- Proof-bytes commitment (mock fixture verifier) ---------------
    let expected_bytes = fixture_onchain_governance_proof_bytes(
        proof.environment,
        &proof.chain_id,
        &proof.genesis_hash,
        &proof.authority_root_fingerprint,
        &proof.governance_domain_id,
        proof.governance_epoch,
        &proof.proposal_id,
        &proof.proposal_digest,
        &proof.candidate_v2_digest,
        proof.authority_domain_sequence,
        &proof.unique_decision_id,
    );
    if proof.proof_bytes != expected_bytes {
        return O::InvalidGovernanceProof {
            reason: "fixture-mock proof_bytes commitment does not match canonical bytes"
                .to_string(),
        };
    }

    // ---- Accept (DevNet/TestNet fixture) ------------------------------
    O::AcceptedOnChainGovernanceFixture {
        action: proof.lifecycle_action,
        authority_domain_sequence: proof.authority_domain_sequence,
        governance_epoch: proof.governance_epoch,
    }
}

// ===========================================================================
// Combined lifecycle + OnChainGovernance helper
// ===========================================================================

/// Combined typed decision returned by
/// [`validate_lifecycle_with_onchain_governance_proof`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CombinedLifecycleOnChainGovernanceOutcome {
    Accepted {
        lifecycle: crate::pqc_authority_lifecycle::AuthorityLifecycleTransitionOutcome,
        governance: OnChainGovernanceProofVerificationOutcome,
    },
    LifecycleRejected(crate::pqc_authority_lifecycle::AuthorityLifecycleTransitionOutcome),
    GovernanceRejected {
        lifecycle: crate::pqc_authority_lifecycle::AuthorityLifecycleTransitionOutcome,
        governance: OnChainGovernanceProofVerificationOutcome,
    },
}

impl CombinedLifecycleOnChainGovernanceOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }
}

/// Pure non-mutating helper that composes the Run 159 v2 lifecycle
/// validator with the Run 178 `OnChainGovernance` proof verifier into a
/// single typed [`CombinedLifecycleOnChainGovernanceOutcome`].
///
/// Performs no I/O. Writes no marker. Writes no sequence. Mutates no
/// live trust state. **Does NOT enable MainNet apply.**
#[allow(clippy::too_many_arguments)]
pub fn validate_lifecycle_with_onchain_governance_proof<R: OnChainGovernanceReplaySet + ?Sized>(
    persisted: Option<&crate::pqc_authority_state::PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    proof: &OnChainGovernanceProof,
    trust_domain: &AuthorityTrustDomain,
    policy: OnChainGovernanceProofPolicy,
    expected_governance_domain_id: &str,
    expected_governance_epoch: u64,
    expected_proposal_id: &str,
    expected_proposal_digest: &str,
    now_unix: u64,
    replay_set: &R,
) -> CombinedLifecycleOnChainGovernanceOutcome {
    use crate::pqc_authority_lifecycle::validate_v2_lifecycle_transition;

    let lifecycle = validate_v2_lifecycle_transition(persisted, candidate, trust_domain);
    if lifecycle.is_reject() {
        return CombinedLifecycleOnChainGovernanceOutcome::LifecycleRejected(lifecycle);
    }

    let persisted_sequence = match persisted {
        Some(crate::pqc_authority_state::PersistentAuthorityStateRecordVersioned::V2(v)) => {
            Some(v.latest_authority_domain_sequence)
        }
        _ => None,
    };

    let governance = verify_onchain_governance_proof(
        proof,
        candidate,
        trust_domain,
        policy,
        expected_governance_domain_id,
        expected_governance_epoch,
        expected_proposal_id,
        expected_proposal_digest,
        persisted_sequence,
        now_unix,
        replay_set,
    );
    if governance.is_reject() {
        return CombinedLifecycleOnChainGovernanceOutcome::GovernanceRejected {
            lifecycle,
            governance,
        };
    }

    CombinedLifecycleOnChainGovernanceOutcome::Accepted {
        lifecycle,
        governance,
    }
}

// ===========================================================================
// MainNet peer-driven apply remains refused
// ===========================================================================

/// Pure typed assertion that even a fully-valid Run 178 fixture
/// `OnChainGovernance` proof MUST NOT enable MainNet peer-driven apply.
///
/// Returns `true` iff a peer-driven apply may proceed under the supplied
/// environment + acceptance outcome. For MainNet, this is **always
/// `false`** in Run 178 — the fixture acceptance never elevates.
pub fn mainnet_peer_driven_apply_remains_refused(
    environment: TrustBundleEnvironment,
    _outcome: &OnChainGovernanceProofVerificationOutcome,
) -> bool {
    // MainNet peer-driven apply is unconditionally refused in Run 178,
    // regardless of any DevNet/TestNet fixture acceptance. There is no
    // toggle in this run that could elevate a fixture proof into a
    // MainNet apply. (DevNet/TestNet peer-driven apply toggles are an
    // entirely separate policy outside Run 178.)
    environment == TrustBundleEnvironment::Mainnet
}

// ===========================================================================
// Wire form (additive — additional optional sibling on the Run 167 carrier)
// ===========================================================================

/// Schema version for the Run 178 `OnChainGovernance` proof wire object.
///
/// Versioning is additive: a future run extending the wire shape MUST
/// bump this constant. Run 178 rejects unknown versions with
/// [`OnChainGovernanceProofWireParseError::UnknownSchemaVersion`].
pub const ONCHAIN_GOVERNANCE_PROOF_WIRE_SCHEMA_VERSION: u32 = 1;

/// Wire-safe encoding of [`OnChainGovernanceProof`].
///
/// Carried as an additional optional sibling field on the Run 167
/// governance-proof-carrying v2 ratification sidecar JSON. Old sidecars
/// (Runs 167–177) that do not carry this sibling continue to parse and
/// validate exactly as before — the sibling is `#[serde(default)]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnChainGovernanceProofWire {
    pub schema_version: u32,

    pub environment: TrustBundleEnvironment,
    pub chain_id: String,
    pub genesis_hash: String,
    pub authority_root_fingerprint: String,
    pub authority_root_suite_id: u8,

    pub governance_domain_id: String,
    pub governance_epoch: u64,
    pub proposal_id: String,
    pub proposal_digest: String,
    pub proposal_outcome: OnChainGovernanceProposalOutcome,
    pub quorum: OnChainGovernanceQuorum,
    pub threshold_approvals: u32,
    pub threshold_required: u32,
    pub threshold_total: u32,

    pub lifecycle_action: LocalLifecycleAction,
    pub active_bundle_signing_key_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_bundle_signing_key_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_bundle_signing_key_fingerprint: Option<String>,

    pub authority_domain_sequence: u64,
    pub candidate_v2_digest: String,

    pub freshness: OnChainGovernanceFreshnessWindow,
    pub unique_decision_id: String,

    pub proof_suite_id: u8,
    /// Lowercase hex-encoded `proof_bytes`.
    #[serde(with = "hex_bytes")]
    pub proof_bytes: Vec<u8>,
}

impl OnChainGovernanceProofWire {
    pub fn to_proof(&self) -> Result<OnChainGovernanceProof, OnChainGovernanceProofWireParseError> {
        if self.schema_version != ONCHAIN_GOVERNANCE_PROOF_WIRE_SCHEMA_VERSION {
            return Err(OnChainGovernanceProofWireParseError::UnknownSchemaVersion {
                got: self.schema_version,
                expected: ONCHAIN_GOVERNANCE_PROOF_WIRE_SCHEMA_VERSION,
            });
        }
        if self.chain_id.is_empty()
            || self.genesis_hash.is_empty()
            || self.authority_root_fingerprint.is_empty()
            || self.governance_domain_id.is_empty()
            || self.proposal_id.is_empty()
            || self.proposal_digest.is_empty()
            || self.active_bundle_signing_key_fingerprint.is_empty()
            || self.candidate_v2_digest.is_empty()
            || self.unique_decision_id.is_empty()
        {
            return Err(OnChainGovernanceProofWireParseError::EmptyRequiredField);
        }
        if self.proof_bytes.is_empty() {
            return Err(OnChainGovernanceProofWireParseError::EmptyProofBytes);
        }
        Ok(OnChainGovernanceProof {
            environment: self.environment,
            chain_id: self.chain_id.clone(),
            genesis_hash: self.genesis_hash.clone(),
            authority_root_fingerprint: self.authority_root_fingerprint.clone(),
            authority_root_suite_id: self.authority_root_suite_id,
            governance_domain_id: self.governance_domain_id.clone(),
            governance_epoch: self.governance_epoch,
            proposal_id: self.proposal_id.clone(),
            proposal_digest: self.proposal_digest.clone(),
            proposal_outcome: self.proposal_outcome,
            quorum: self.quorum.clone(),
            threshold: GovernanceThreshold::new(
                self.threshold_approvals,
                self.threshold_required,
                self.threshold_total,
            ),
            lifecycle_action: self.lifecycle_action,
            active_bundle_signing_key_fingerprint: self
                .active_bundle_signing_key_fingerprint
                .clone(),
            new_bundle_signing_key_fingerprint: self.new_bundle_signing_key_fingerprint.clone(),
            revoked_bundle_signing_key_fingerprint: self
                .revoked_bundle_signing_key_fingerprint
                .clone(),
            authority_domain_sequence: self.authority_domain_sequence,
            candidate_v2_digest: self.candidate_v2_digest.clone(),
            freshness: self.freshness,
            unique_decision_id: self.unique_decision_id.clone(),
            proof_suite_id: self.proof_suite_id,
            proof_bytes: self.proof_bytes.clone(),
        })
    }

    pub fn from_proof(p: &OnChainGovernanceProof) -> Self {
        Self {
            schema_version: ONCHAIN_GOVERNANCE_PROOF_WIRE_SCHEMA_VERSION,
            environment: p.environment,
            chain_id: p.chain_id.clone(),
            genesis_hash: p.genesis_hash.clone(),
            authority_root_fingerprint: p.authority_root_fingerprint.clone(),
            authority_root_suite_id: p.authority_root_suite_id,
            governance_domain_id: p.governance_domain_id.clone(),
            governance_epoch: p.governance_epoch,
            proposal_id: p.proposal_id.clone(),
            proposal_digest: p.proposal_digest.clone(),
            proposal_outcome: p.proposal_outcome,
            quorum: p.quorum.clone(),
            threshold_approvals: p.threshold.approvals,
            threshold_required: p.threshold.required,
            threshold_total: p.threshold.total,
            lifecycle_action: p.lifecycle_action,
            active_bundle_signing_key_fingerprint: p.active_bundle_signing_key_fingerprint.clone(),
            new_bundle_signing_key_fingerprint: p.new_bundle_signing_key_fingerprint.clone(),
            revoked_bundle_signing_key_fingerprint: p.revoked_bundle_signing_key_fingerprint.clone(),
            authority_domain_sequence: p.authority_domain_sequence,
            candidate_v2_digest: p.candidate_v2_digest.clone(),
            freshness: p.freshness,
            unique_decision_id: p.unique_decision_id.clone(),
            proof_suite_id: p.proof_suite_id,
            proof_bytes: p.proof_bytes.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnChainGovernanceProofWireParseError {
    UnknownSchemaVersion { got: u32, expected: u32 },
    EmptyRequiredField,
    EmptyProofBytes,
}

impl std::fmt::Display for OnChainGovernanceProofWireParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSchemaVersion { got, expected } => write!(
                f,
                "[run-178] unsupported onchain_governance_proof schema_version={} (expected {}). Fail closed.",
                got, expected
            ),
            Self::EmptyRequiredField => write!(
                f,
                "[run-178] onchain_governance_proof has an empty required field. Fail closed."
            ),
            Self::EmptyProofBytes => write!(
                f,
                "[run-178] onchain_governance_proof has empty proof_bytes. Fail closed."
            ),
        }
    }
}

impl std::error::Error for OnChainGovernanceProofWireParseError {}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write;
            let _ = write!(&mut out, "{:02x}", b);
        }
        s.serialize_str(&out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() % 2 != 0 {
            return Err(serde::de::Error::custom(
                "[run-178] proof_bytes hex string has odd length",
            ));
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hi = decode_nibble(bytes[i]).map_err(serde::de::Error::custom)?;
            let lo = decode_nibble(bytes[i + 1]).map_err(serde::de::Error::custom)?;
            out.push((hi << 4) | lo);
            i += 2;
        }
        Ok(out)
    }

    fn decode_nibble(b: u8) -> Result<u8, &'static str> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(10 + b - b'a'),
            b'A'..=b'F' => Ok(10 + b - b'A'),
            _ => Err("[run-178] proof_bytes contains non-hex byte"),
        }
    }
}