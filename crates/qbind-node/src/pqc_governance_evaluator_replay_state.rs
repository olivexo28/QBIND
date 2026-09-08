//! Run 230 — source/test governance evaluator **replay and freshness state
//! boundary**.
//!
//! Source/test only. Run 230 captures **no** release-binary evidence;
//! release-binary replay/freshness evidence is deferred to **Run 231**. Run
//! 230 does **not** implement a real governance execution engine, a real
//! on-chain governance proof verifier, MainNet governance enablement, MainNet
//! peer-driven apply enablement, validator-set rotation, a real KMS/HSM
//! backend, a real RemoteSigner backend, or any RocksDB/file/schema/migration
//! /marker/sequence/storage-format change.
//!
//! ## What this module adds
//!
//! Runs 220–229 proved, at the source/test level and then with release-binary
//! evidence, that evaluator requests / responses bind a replay nonce,
//! freshness window (`effective_epoch` / `expiry_epoch`), and expiry, and that
//! the representable runtime call sites route runtime consumption through the
//! Run 224 integration layer subject to the Run 222 evaluator interface.
//!
//! What was still missing was a typed **state boundary** that, *before* any
//! lifecycle mutation can happen, decides whether a given evaluator decision is
//! [`ReplayFreshnessState::Fresh`], not-yet-effective, expired, stale, a
//! replay, already consumed, superseded, or bound to the wrong domain. Run 230
//! adds exactly that boundary as a pure, fail-closed module:
//!
//! * [`EvaluatorReplayFreshnessInput`] — the typed replay/freshness inputs.
//! * [`EvaluatorReplayFreshnessExpectations`] — the canonical binding the
//!   input is checked against.
//! * [`PreviouslySeenState`] — the optional previously-seen decision state /
//!   reader availability.
//! * [`ReplayFreshnessState`] — the typed state classification.
//! * [`EvaluatorReplayFreshnessOutcome`] — the typed fail-closed/proceed
//!   outcome.
//! * [`classify_evaluator_replay_freshness`] /
//!   [`evaluate_evaluator_replay_freshness`] — the pure classification and
//!   outcome functions.
//! * Deterministic digest helpers: [`replay_state_key_digest`],
//!   [`replay_observation_digest`], [`consumed_decision_digest`],
//!   [`freshness_transcript_digest`].
//! * The [`GovernanceEvaluatorReplayStateReader`] /
//!   [`GovernanceEvaluatorReplayStateWriter`] boundary traits, a DevNet/TestNet
//!   source-test [`FixtureReplayStateStore`], and the callable-but-unavailable
//!   [`ProductionReplayStateReader`] / [`MainnetReplayStateReader`].
//!
//! ## Fail-closed / mutation-safety contract
//!
//! * Classification is a pure function: it performs no I/O, writes no marker,
//!   writes no sequence, swaps no live trust, evicts no sessions, and never
//!   invokes Run 070. Replay/freshness rejection therefore necessarily happens
//!   *before* any of those mutations.
//! * Only [`EvaluatorReplayFreshnessOutcome::ProceedFresh`] authorizes a
//!   mutation. [`EvaluatorReplayFreshnessOutcome::ProceedDeferred`] is **not**
//!   an approval for mutation; every other variant is a non-mutating
//!   fail-closed.
//! * The fixture writer records a consumed decision **only** when
//!   [`GovernanceEvaluatorReplayStateWriter::mark_consumed`] is explicitly
//!   called; read-only validation never marks consumed.
//! * Production / MainNet readers/writers are callable but always return an
//!   unavailable / fail-closed result.
//! * MainNet peer-driven apply remains refused unconditionally, even when the
//!   replay/freshness state would otherwise be fresh.
//! * Validator-set rotation and policy-change actions remain unsupported.
//!
//! ## What this module does NOT change
//!
//! * It adds **no** field to any production wire message.
//! * It alters **no** trust-bundle, authority-marker, or sequence schema.
//! * It introduces **no** RocksDB schema, file format, or database migration.
//! * It enables **no** MainNet peer-driven apply.
//! * It does **not** claim full C4 or C5 closure.

use crate::pqc_authority_lifecycle::LocalLifecycleAction;
use crate::pqc_governance_execution_evaluator::{
    DecisionSourceIdentity, EvaluatorRequest, EvaluatorResponse,
};
use crate::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use crate::pqc_trust_bundle::TrustBundleEnvironment;
use std::collections::HashMap;

/// Domain-separation tag for the Run 230 replay state key digest.
pub const REPLAY_STATE_KEY_DOMAIN_TAG: &str = "qbind.run230.governance.evaluator.replay.state.key.v1";
/// Domain-separation tag for the Run 230 replay observation digest.
pub const REPLAY_OBSERVATION_DOMAIN_TAG: &str =
    "qbind.run230.governance.evaluator.replay.observation.v1";
/// Domain-separation tag for the Run 230 consumed decision digest.
pub const CONSUMED_DECISION_DOMAIN_TAG: &str =
    "qbind.run230.governance.evaluator.replay.consumed.v1";
/// Domain-separation tag for the Run 230 freshness transcript digest.
pub const FRESHNESS_TRANSCRIPT_DOMAIN_TAG: &str =
    "qbind.run230.governance.evaluator.replay.freshness.transcript.v1";

// ===========================================================================
// Replay state policy
// ===========================================================================

/// Run 230 — the active replay/freshness state policy.
///
/// [`Self::Disabled`] means the replay-state boundary is **not wired**: prior
/// Run 220–228 layers behave exactly as before (Run 224 integration and Run
/// 228 peer-context compatibility). The fixture policies are DevNet/TestNet
/// source-test only. The production / MainNet policies are callable but their
/// backing readers/writers are always unavailable / fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplayStatePolicy {
    /// Replay-state boundary is not wired; prior layers are unchanged.
    Disabled,
    /// DevNet fixture replay state (source-test only).
    FixtureDevNet,
    /// TestNet fixture replay state (source-test only).
    FixtureTestNet,
    /// Production replay state (callable-but-unavailable / fail-closed).
    Production,
    /// MainNet replay state (callable-but-unavailable / fail-closed).
    MainNet,
}

impl ReplayStatePolicy {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureDevNet => "fixture-devnet",
            Self::FixtureTestNet => "fixture-testnet",
            Self::Production => "production",
            Self::MainNet => "mainnet",
        }
    }

    /// `true` iff the replay-state boundary is wired (any policy other than
    /// [`Self::Disabled`]).
    pub const fn is_wired(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// `true` iff this policy is a DevNet/TestNet source-test fixture policy.
    pub const fn is_fixture(self) -> bool {
        matches!(self, Self::FixtureDevNet | Self::FixtureTestNet)
    }
}

// ===========================================================================
// Previously-seen decision state / reader availability
// ===========================================================================

/// Run 230 — a previously-recorded decision state for one replay state key.
///
/// Pure data. The fixture store records and returns these; production / MainNet
/// readers never return one (they are unavailable). Used to classify
/// already-consumed / superseded / replayed decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenDecisionRecord {
    /// The replay state key digest this record was recorded under.
    pub state_key_digest: String,
    /// The replay nonce recorded.
    pub replay_nonce: String,
    /// The authority-domain sequence recorded.
    pub recorded_sequence: u64,
    /// The effective epoch recorded.
    pub recorded_effective_epoch: u64,
    /// The expiry epoch recorded.
    pub recorded_expiry_epoch: u64,
    /// How many times the decision has been observed (>= 1 when recorded).
    pub observation_count: u64,
    /// `true` iff the decision has been explicitly consumed (mutation applied).
    pub consumed: bool,
    /// `true` iff a newer decision has explicitly superseded this one.
    pub superseded: bool,
}

/// Run 230 — the optional previously-seen decision state plus reader
/// availability.
///
/// This is what a [`GovernanceEvaluatorReplayStateReader`] returns and what the
/// classifier consumes. The three unavailable variants keep production /
/// MainNet state callable-but-fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreviouslySeenState {
    /// No prior state recorded for this key — first-seen decision.
    FirstSeen,
    /// A prior decision state was recorded for this key.
    Seen(SeenDecisionRecord),
    /// The replay-state store is unavailable (generic fail-closed).
    Unavailable,
    /// Production replay state is unavailable (callable-but-fail-closed).
    ProductionUnavailable,
    /// MainNet replay state is unavailable (callable-but-fail-closed).
    MainNetUnavailable,
}

// ===========================================================================
// Replay/freshness inputs
// ===========================================================================

/// Run 230 — typed replay/freshness inputs for one evaluator decision.
///
/// Pure data. The digest fields are references into the Run 222 evaluator
/// material (source identity / request / response / transcript digests) and the
/// Run 211 decision digest — never copies of any wire payload. The `validation_
/// surface` is the Run 217 runtime surface the decision is being evaluated for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluatorReplayFreshnessInput {
    /// Evaluator source-identity digest.
    pub evaluator_source_identity_digest: String,
    /// Evaluator request digest.
    pub evaluator_request_digest: String,
    /// Evaluator response digest.
    pub evaluator_response_digest: String,
    /// Evaluator transcript digest.
    pub evaluator_transcript_digest: String,
    /// Governance execution decision digest.
    pub governance_execution_decision_digest: String,
    /// Governance proposal id.
    pub proposal_id: String,
    /// Governance decision id.
    pub decision_id: String,
    /// Lifecycle action.
    pub lifecycle_action: LocalLifecycleAction,
    /// Candidate digest.
    pub candidate_digest: String,
    /// Authority-domain sequence.
    pub authority_domain_sequence: u64,
    /// Effective / activation epoch (inclusive lower bound).
    pub effective_epoch: u64,
    /// Expiry epoch (exclusive upper bound).
    pub expiry_epoch: u64,
    /// Per-execution anti-replay nonce.
    pub replay_nonce: String,
    /// Trust-domain environment.
    pub environment: TrustBundleEnvironment,
    /// Trust-domain chain id.
    pub chain_id: String,
    /// Trust-domain genesis hash.
    pub genesis_hash: String,
    /// Validation surface this decision is being evaluated for.
    pub validation_surface: GovernanceExecutionRuntimeSurface,
    /// Current canonical epoch the freshness window is checked against.
    pub current_canonical_epoch: u64,
    /// Optional previously-seen decision state / reader availability.
    pub previously_seen: PreviouslySeenState,
}

impl EvaluatorReplayFreshnessInput {
    /// `true` iff every mandatory field is structurally present (non-empty).
    pub fn is_well_formed(&self) -> bool {
        !self.evaluator_source_identity_digest.is_empty()
            && !self.evaluator_request_digest.is_empty()
            && !self.evaluator_response_digest.is_empty()
            && !self.evaluator_transcript_digest.is_empty()
            && !self.governance_execution_decision_digest.is_empty()
            && !self.proposal_id.is_empty()
            && !self.decision_id.is_empty()
            && !self.candidate_digest.is_empty()
            && !self.replay_nonce.is_empty()
            && !self.chain_id.is_empty()
            && !self.genesis_hash.is_empty()
    }

    /// Compose a Run 230 input by **referencing** the Run 222 evaluator
    /// material. Every evaluator digest is derived from the supplied identity /
    /// request / response so the input is internally consistent with the
    /// material it binds.
    #[allow(clippy::too_many_arguments)]
    pub fn from_evaluator_material(
        identity: &DecisionSourceIdentity,
        request: &EvaluatorRequest,
        response: &EvaluatorResponse,
        evaluator_transcript_digest: impl Into<String>,
        governance_execution_decision_digest: impl Into<String>,
        environment: TrustBundleEnvironment,
        chain_id: impl Into<String>,
        genesis_hash: impl Into<String>,
        validation_surface: GovernanceExecutionRuntimeSurface,
        current_canonical_epoch: u64,
        previously_seen: PreviouslySeenState,
    ) -> Self {
        Self {
            evaluator_source_identity_digest: identity.source_identity_digest(),
            evaluator_request_digest: request.request_digest(),
            evaluator_response_digest: response.response_digest(),
            evaluator_transcript_digest: evaluator_transcript_digest.into(),
            governance_execution_decision_digest: governance_execution_decision_digest.into(),
            proposal_id: request.proposal_id.clone(),
            decision_id: request.decision_id.clone(),
            lifecycle_action: request.lifecycle_action,
            candidate_digest: request.candidate_digest.clone(),
            authority_domain_sequence: request.authority_domain_sequence,
            effective_epoch: request.effective_epoch,
            expiry_epoch: request.expiry_epoch,
            replay_nonce: request.replay_nonce.clone(),
            environment,
            chain_id: chain_id.into(),
            genesis_hash: genesis_hash.into(),
            validation_surface,
            current_canonical_epoch,
            previously_seen,
        }
    }
}

// ===========================================================================
// Replay/freshness expectations
// ===========================================================================

/// Run 230 — the canonical binding an [`EvaluatorReplayFreshnessInput`] is
/// checked against. A mismatch on any field is a typed, non-mutating
/// fail-closed (never a silent approval).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluatorReplayFreshnessExpectations {
    /// Expected evaluator source-identity digest.
    pub expected_evaluator_source_identity_digest: String,
    /// Expected evaluator request digest.
    pub expected_evaluator_request_digest: String,
    /// Expected evaluator response digest.
    pub expected_evaluator_response_digest: String,
    /// Expected evaluator transcript digest.
    pub expected_evaluator_transcript_digest: String,
    /// Expected governance execution decision digest.
    pub expected_governance_execution_decision_digest: String,
    /// Expected governance proposal id.
    pub expected_proposal_id: String,
    /// Expected governance decision id.
    pub expected_decision_id: String,
    /// Expected lifecycle action.
    pub expected_lifecycle_action: LocalLifecycleAction,
    /// Expected candidate digest.
    pub expected_candidate_digest: String,
    /// Expected authority-domain sequence.
    pub expected_authority_domain_sequence: u64,
    /// Expected effective / activation epoch.
    pub expected_effective_epoch: u64,
    /// Expected expiry epoch.
    pub expected_expiry_epoch: u64,
    /// Expected replay nonce.
    pub expected_replay_nonce: String,
    /// Expected trust-domain environment.
    pub expected_environment: TrustBundleEnvironment,
    /// Expected trust-domain chain id.
    pub expected_chain_id: String,
    /// Expected trust-domain genesis hash.
    pub expected_genesis_hash: String,
    /// Expected validation surface.
    pub expected_validation_surface: GovernanceExecutionRuntimeSurface,
}

impl EvaluatorReplayFreshnessExpectations {
    /// Derive the canonical expectations from the same Run 222 material an
    /// [`EvaluatorReplayFreshnessInput::from_evaluator_material`] would
    /// reference, so a faithfully-bound input always matches.
    #[allow(clippy::too_many_arguments)]
    pub fn from_evaluator_material(
        identity: &DecisionSourceIdentity,
        request: &EvaluatorRequest,
        response: &EvaluatorResponse,
        evaluator_transcript_digest: impl Into<String>,
        governance_execution_decision_digest: impl Into<String>,
        environment: TrustBundleEnvironment,
        chain_id: impl Into<String>,
        genesis_hash: impl Into<String>,
        validation_surface: GovernanceExecutionRuntimeSurface,
    ) -> Self {
        Self {
            expected_evaluator_source_identity_digest: identity.source_identity_digest(),
            expected_evaluator_request_digest: request.request_digest(),
            expected_evaluator_response_digest: response.response_digest(),
            expected_evaluator_transcript_digest: evaluator_transcript_digest.into(),
            expected_governance_execution_decision_digest: governance_execution_decision_digest
                .into(),
            expected_proposal_id: request.proposal_id.clone(),
            expected_decision_id: request.decision_id.clone(),
            expected_lifecycle_action: request.lifecycle_action,
            expected_candidate_digest: request.candidate_digest.clone(),
            expected_authority_domain_sequence: request.authority_domain_sequence,
            expected_effective_epoch: request.effective_epoch,
            expected_expiry_epoch: request.expiry_epoch,
            expected_replay_nonce: request.replay_nonce.clone(),
            expected_environment: environment,
            expected_chain_id: chain_id.into(),
            expected_genesis_hash: genesis_hash.into(),
            expected_validation_surface: validation_surface,
        }
    }
}

// ===========================================================================
// State classification
// ===========================================================================

/// Run 230 — typed replay/freshness state classification for one evaluator
/// decision. Every variant other than [`Self::Fresh`] and
/// [`Self::FreshButNotYetEffective`] is a fail-closed state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplayFreshnessState {
    /// First-seen decision within its effective window. Eligible to proceed.
    Fresh,
    /// First-seen decision whose effective epoch is in the future. Deferred,
    /// not approved for mutation.
    FreshButNotYetEffective,
    /// The decision's expiry epoch has passed.
    Expired,
    /// The decision's freshness window is degenerate / can never be fresh.
    Stale,
    /// The same decision was observed again before being consumed.
    ReplayDetected,
    /// The decision was already consumed (mutation already applied).
    AlreadyConsumed,
    /// A newer decision has superseded this one.
    Superseded,
    /// The effective / expiry epoch binding does not match the canonical
    /// expectation.
    WrongEpoch,
    /// The trust-domain environment binding does not match.
    WrongEnvironment,
    /// The trust-domain chain id binding does not match.
    WrongChain,
    /// The trust-domain genesis hash binding does not match.
    WrongGenesis,
    /// The validation surface binding does not match.
    WrongSurface,
    /// A binding field is structurally malformed or does not match the
    /// canonical decision binding.
    MalformedState,
    /// The replay-state store is unavailable (generic fail-closed).
    StateUnavailable,
    /// Production replay state is unavailable (callable-but-fail-closed).
    ProductionStateUnavailable,
    /// MainNet replay state is unavailable (callable-but-fail-closed).
    MainNetStateUnavailable,
}

impl ReplayFreshnessState {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::FreshButNotYetEffective => "fresh-but-not-yet-effective",
            Self::Expired => "expired",
            Self::Stale => "stale",
            Self::ReplayDetected => "replay-detected",
            Self::AlreadyConsumed => "already-consumed",
            Self::Superseded => "superseded",
            Self::WrongEpoch => "wrong-epoch",
            Self::WrongEnvironment => "wrong-environment",
            Self::WrongChain => "wrong-chain",
            Self::WrongGenesis => "wrong-genesis",
            Self::WrongSurface => "wrong-surface",
            Self::MalformedState => "malformed-state",
            Self::StateUnavailable => "state-unavailable",
            Self::ProductionStateUnavailable => "production-state-unavailable",
            Self::MainNetStateUnavailable => "mainnet-state-unavailable",
        }
    }

    /// `true` iff this state is one of the binding-mismatch / malformed states.
    pub const fn is_wrong_binding(self) -> bool {
        matches!(
            self,
            Self::WrongEpoch
                | Self::WrongEnvironment
                | Self::WrongChain
                | Self::WrongGenesis
                | Self::WrongSurface
                | Self::MalformedState
        )
    }
}

// ===========================================================================
// Outcome
// ===========================================================================

/// Run 230 — typed outcome of a replay/freshness state evaluation.
///
/// Only [`Self::ProceedFresh`] authorizes a lifecycle mutation.
/// [`Self::ProceedDeferred`] is **not** an approval for mutation. Every other
/// variant is a non-mutating fail-closed rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluatorReplayFreshnessOutcome {
    /// Fresh, first-seen decision within its effective window. The **only**
    /// mutation-authorizing outcome.
    ProceedFresh,
    /// Fresh but not yet effective — defer; not an approval for mutation.
    ProceedDeferred,
    /// Expired or stale decision. Carries the classified state. Non-mutating.
    FailClosedExpired(ReplayFreshnessState),
    /// Replay detected. Non-mutating.
    FailClosedReplay,
    /// Already-consumed decision. Non-mutating.
    FailClosedAlreadyConsumed,
    /// Superseded decision. Non-mutating.
    FailClosedSuperseded,
    /// A binding field is wrong / malformed. Carries the state and a reason.
    /// Non-mutating.
    FailClosedWrongBinding {
        /// The classified binding-mismatch state.
        state: ReplayFreshnessState,
        /// Operator-facing reason.
        reason: String,
    },
    /// The replay-state store is unavailable (generic). Non-mutating.
    FailClosedStateUnavailable,
    /// Production replay state is unavailable. Non-mutating.
    FailClosedProductionUnavailable,
    /// MainNet replay state is unavailable, or MainNet peer-driven apply is
    /// refused. Non-mutating.
    FailClosedMainNetUnavailable,
}

impl EvaluatorReplayFreshnessOutcome {
    /// `true` iff this outcome authorizes a lifecycle mutation. This is the
    /// **only** mutation-authorizing outcome ([`Self::ProceedFresh`]).
    pub fn authorizes_mutation(&self) -> bool {
        matches!(self, Self::ProceedFresh)
    }

    /// `true` iff this outcome is a deferral (proceed-but-not-yet-effective).
    /// A deferral does **not** authorize mutation.
    pub fn is_deferred(&self) -> bool {
        matches!(self, Self::ProceedDeferred)
    }

    /// `true` iff this outcome is a non-mutating fail-closed rejection.
    pub fn is_fail_closed(&self) -> bool {
        !matches!(self, Self::ProceedFresh | Self::ProceedDeferred)
    }

    /// `true` iff this rejection leaves the surface with no mutation (every
    /// outcome that does not authorize mutation, including a deferral).
    pub fn no_mutation(&self) -> bool {
        !self.authorizes_mutation()
    }

    /// Stable operator-facing tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::ProceedFresh => "proceed-fresh",
            Self::ProceedDeferred => "proceed-deferred",
            Self::FailClosedExpired(_) => "fail-closed-expired",
            Self::FailClosedReplay => "fail-closed-replay",
            Self::FailClosedAlreadyConsumed => "fail-closed-already-consumed",
            Self::FailClosedSuperseded => "fail-closed-superseded",
            Self::FailClosedWrongBinding { .. } => "fail-closed-wrong-binding",
            Self::FailClosedStateUnavailable => "fail-closed-state-unavailable",
            Self::FailClosedProductionUnavailable => "fail-closed-production-unavailable",
            Self::FailClosedMainNetUnavailable => "fail-closed-mainnet-unavailable",
        }
    }
}

/// Run 230 — gate result that keeps prior layers compatible when the
/// replay-state boundary is not wired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayStateGateOutcome {
    /// Policy is [`ReplayStatePolicy::Disabled`] — the replay-state boundary is
    /// not wired and prior Run 220–228 layers are unchanged.
    NotWired,
    /// The replay-state boundary was evaluated and produced an outcome.
    Evaluated(EvaluatorReplayFreshnessOutcome),
}

impl ReplayStateGateOutcome {
    /// `true` iff the boundary was not wired (policy Disabled).
    pub fn is_not_wired(&self) -> bool {
        matches!(self, Self::NotWired)
    }
}

// ===========================================================================
// Classification + evaluation
// ===========================================================================

/// Internal: detect a binding mismatch / structural malformation. Returns the
/// classified state and an operator-facing reason on the first mismatch.
fn binding_mismatch(
    input: &EvaluatorReplayFreshnessInput,
    expectations: &EvaluatorReplayFreshnessExpectations,
) -> Option<(ReplayFreshnessState, String)> {
    if !input.is_well_formed() {
        return Some((
            ReplayFreshnessState::MalformedState,
            "replay/freshness input is structurally malformed (empty mandatory field)".to_string(),
        ));
    }
    if input.environment != expectations.expected_environment {
        return Some((
            ReplayFreshnessState::WrongEnvironment,
            "trust-domain environment does not match expected binding".to_string(),
        ));
    }
    if input.chain_id != expectations.expected_chain_id {
        return Some((
            ReplayFreshnessState::WrongChain,
            "trust-domain chain id does not match expected binding".to_string(),
        ));
    }
    if input.genesis_hash != expectations.expected_genesis_hash {
        return Some((
            ReplayFreshnessState::WrongGenesis,
            "trust-domain genesis hash does not match expected binding".to_string(),
        ));
    }
    if input.validation_surface != expectations.expected_validation_surface {
        return Some((
            ReplayFreshnessState::WrongSurface,
            "validation surface does not match expected binding".to_string(),
        ));
    }
    if input.effective_epoch != expectations.expected_effective_epoch {
        return Some((
            ReplayFreshnessState::WrongEpoch,
            "effective epoch does not match expected binding".to_string(),
        ));
    }
    if input.expiry_epoch != expectations.expected_expiry_epoch {
        return Some((
            ReplayFreshnessState::WrongEpoch,
            "expiry epoch does not match expected binding".to_string(),
        ));
    }
    if input.evaluator_source_identity_digest
        != expectations.expected_evaluator_source_identity_digest
    {
        return Some((
            ReplayFreshnessState::MalformedState,
            "evaluator source identity digest does not match expected binding".to_string(),
        ));
    }
    if input.evaluator_request_digest != expectations.expected_evaluator_request_digest {
        return Some((
            ReplayFreshnessState::MalformedState,
            "evaluator request digest does not match expected binding".to_string(),
        ));
    }
    if input.evaluator_response_digest != expectations.expected_evaluator_response_digest {
        return Some((
            ReplayFreshnessState::MalformedState,
            "evaluator response digest does not match expected binding".to_string(),
        ));
    }
    if input.evaluator_transcript_digest != expectations.expected_evaluator_transcript_digest {
        return Some((
            ReplayFreshnessState::MalformedState,
            "evaluator transcript digest does not match expected binding".to_string(),
        ));
    }
    if input.governance_execution_decision_digest
        != expectations.expected_governance_execution_decision_digest
    {
        return Some((
            ReplayFreshnessState::MalformedState,
            "governance execution decision digest does not match expected binding".to_string(),
        ));
    }
    if input.proposal_id != expectations.expected_proposal_id {
        return Some((
            ReplayFreshnessState::MalformedState,
            "proposal id does not match expected binding".to_string(),
        ));
    }
    if input.decision_id != expectations.expected_decision_id {
        return Some((
            ReplayFreshnessState::MalformedState,
            "decision id does not match expected binding".to_string(),
        ));
    }
    if input.lifecycle_action != expectations.expected_lifecycle_action {
        return Some((
            ReplayFreshnessState::MalformedState,
            "lifecycle action does not match expected binding".to_string(),
        ));
    }
    if input.candidate_digest != expectations.expected_candidate_digest {
        return Some((
            ReplayFreshnessState::MalformedState,
            "candidate digest does not match expected binding".to_string(),
        ));
    }
    if input.authority_domain_sequence != expectations.expected_authority_domain_sequence {
        return Some((
            ReplayFreshnessState::MalformedState,
            "authority-domain sequence does not match expected binding".to_string(),
        ));
    }
    if input.replay_nonce != expectations.expected_replay_nonce {
        return Some((
            ReplayFreshnessState::MalformedState,
            "replay nonce does not match expected binding".to_string(),
        ));
    }
    None
}

/// Run 230 — classify the replay/freshness state of an evaluator decision.
///
/// Pure: performs no I/O and no mutation. The order is deterministic — binding
/// checks first (so a wrong-domain decision is rejected before any freshness or
/// replay reasoning), then reader availability, then previously-seen
/// replay/consumed/superseded reasoning, then the first-seen freshness window.
pub fn classify_evaluator_replay_freshness(
    input: &EvaluatorReplayFreshnessInput,
    expectations: &EvaluatorReplayFreshnessExpectations,
) -> ReplayFreshnessState {
    if let Some((state, _reason)) = binding_mismatch(input, expectations) {
        return state;
    }

    match &input.previously_seen {
        PreviouslySeenState::Unavailable => return ReplayFreshnessState::StateUnavailable,
        PreviouslySeenState::ProductionUnavailable => {
            return ReplayFreshnessState::ProductionStateUnavailable
        }
        PreviouslySeenState::MainNetUnavailable => {
            return ReplayFreshnessState::MainNetStateUnavailable
        }
        PreviouslySeenState::Seen(record) => {
            if record.consumed {
                return ReplayFreshnessState::AlreadyConsumed;
            }
            if record.superseded || record.recorded_sequence > input.authority_domain_sequence {
                return ReplayFreshnessState::Superseded;
            }
            return ReplayFreshnessState::ReplayDetected;
        }
        PreviouslySeenState::FirstSeen => {}
    }

    // First-seen freshness window classification.
    if input.expiry_epoch <= input.effective_epoch {
        // Degenerate window: the decision can never be fresh.
        return ReplayFreshnessState::Stale;
    }
    if input.current_canonical_epoch < input.effective_epoch {
        return ReplayFreshnessState::FreshButNotYetEffective;
    }
    if input.current_canonical_epoch >= input.expiry_epoch {
        return ReplayFreshnessState::Expired;
    }
    ReplayFreshnessState::Fresh
}

/// Run 230 — evaluate the replay/freshness state of an evaluator decision into
/// a typed outcome.
///
/// MainNet peer-driven apply remains refused unconditionally: a peer-driven
/// drain surface on a MainNet trust domain returns
/// [`EvaluatorReplayFreshnessOutcome::FailClosedMainNetUnavailable`] *before*
/// any freshness reasoning, so a fresh state can never authorize MainNet
/// peer-driven apply.
///
/// Pure: performs no I/O, writes no marker, writes no sequence, swaps no live
/// trust, evicts no sessions, and never invokes Run 070. Rejection therefore
/// happens before any mutation.
pub fn evaluate_evaluator_replay_freshness(
    input: &EvaluatorReplayFreshnessInput,
    expectations: &EvaluatorReplayFreshnessExpectations,
) -> EvaluatorReplayFreshnessOutcome {
    // MainNet peer-driven apply remains refused unconditionally — guard it
    // before classification so a fresh state can never bypass it.
    if input.environment == TrustBundleEnvironment::Mainnet
        && input.validation_surface == GovernanceExecutionRuntimeSurface::PeerDrivenDrain
    {
        return EvaluatorReplayFreshnessOutcome::FailClosedMainNetUnavailable;
    }

    // Recover the binding reason for a richer wrong-binding outcome.
    if let Some((state, reason)) = binding_mismatch(input, expectations) {
        return EvaluatorReplayFreshnessOutcome::FailClosedWrongBinding { state, reason };
    }

    match classify_evaluator_replay_freshness(input, expectations) {
        ReplayFreshnessState::Fresh => EvaluatorReplayFreshnessOutcome::ProceedFresh,
        ReplayFreshnessState::FreshButNotYetEffective => {
            EvaluatorReplayFreshnessOutcome::ProceedDeferred
        }
        state @ (ReplayFreshnessState::Expired | ReplayFreshnessState::Stale) => {
            EvaluatorReplayFreshnessOutcome::FailClosedExpired(state)
        }
        ReplayFreshnessState::ReplayDetected => EvaluatorReplayFreshnessOutcome::FailClosedReplay,
        ReplayFreshnessState::AlreadyConsumed => {
            EvaluatorReplayFreshnessOutcome::FailClosedAlreadyConsumed
        }
        ReplayFreshnessState::Superseded => EvaluatorReplayFreshnessOutcome::FailClosedSuperseded,
        state @ (ReplayFreshnessState::WrongEpoch
        | ReplayFreshnessState::WrongEnvironment
        | ReplayFreshnessState::WrongChain
        | ReplayFreshnessState::WrongGenesis
        | ReplayFreshnessState::WrongSurface
        | ReplayFreshnessState::MalformedState) => {
            EvaluatorReplayFreshnessOutcome::FailClosedWrongBinding {
                state,
                reason: format!("binding mismatch classified as {}", state.tag()),
            }
        }
        ReplayFreshnessState::StateUnavailable => {
            EvaluatorReplayFreshnessOutcome::FailClosedStateUnavailable
        }
        ReplayFreshnessState::ProductionStateUnavailable => {
            EvaluatorReplayFreshnessOutcome::FailClosedProductionUnavailable
        }
        ReplayFreshnessState::MainNetStateUnavailable => {
            EvaluatorReplayFreshnessOutcome::FailClosedMainNetUnavailable
        }
    }
}

/// Run 230 — gate the replay/freshness evaluation behind a
/// [`ReplayStatePolicy`].
///
/// When the policy is [`ReplayStatePolicy::Disabled`] the boundary is not wired
/// and prior Run 220–228 layers are unchanged ([`ReplayStateGateOutcome::NotWired`]).
/// Otherwise the boundary is evaluated.
pub fn gate_evaluator_replay_freshness(
    policy: ReplayStatePolicy,
    input: &EvaluatorReplayFreshnessInput,
    expectations: &EvaluatorReplayFreshnessExpectations,
) -> ReplayStateGateOutcome {
    if !policy.is_wired() {
        return ReplayStateGateOutcome::NotWired;
    }
    ReplayStateGateOutcome::Evaluated(evaluate_evaluator_replay_freshness(input, expectations))
}

// ===========================================================================
// Deterministic digest helpers
// ===========================================================================

fn hash_field(h: &mut sha3::Sha3_256, label: &[u8], value: &[u8]) {
    use sha3::Digest;
    h.update((label.len() as u64).to_le_bytes());
    h.update(label);
    h.update((value.len() as u64).to_le_bytes());
    h.update(value);
}

/// Run 230 — deterministic SHA3-256 hex replay **state key** digest.
///
/// Binds exactly: environment, chain id, genesis hash, evaluator source
/// identity digest, evaluator request digest, evaluator response digest,
/// proposal id, decision id, lifecycle action, candidate digest,
/// authority-domain sequence, and replay nonce (the run-scope A10 set). It does
/// **not** bind the freshness window or the current canonical epoch, so the key
/// is stable across epochs for a given decision.
pub fn replay_state_key_digest(input: &EvaluatorReplayFreshnessInput) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(REPLAY_STATE_KEY_DOMAIN_TAG.as_bytes());
    hash_field(&mut h, b"environment", &input.environment.metric_code().to_le_bytes());
    hash_field(&mut h, b"chain_id", input.chain_id.as_bytes());
    hash_field(&mut h, b"genesis_hash", input.genesis_hash.as_bytes());
    hash_field(
        &mut h,
        b"evaluator_source_identity_digest",
        input.evaluator_source_identity_digest.as_bytes(),
    );
    hash_field(
        &mut h,
        b"evaluator_request_digest",
        input.evaluator_request_digest.as_bytes(),
    );
    hash_field(
        &mut h,
        b"evaluator_response_digest",
        input.evaluator_response_digest.as_bytes(),
    );
    hash_field(&mut h, b"proposal_id", input.proposal_id.as_bytes());
    hash_field(&mut h, b"decision_id", input.decision_id.as_bytes());
    hash_field(&mut h, b"lifecycle_action", input.lifecycle_action.tag().as_bytes());
    hash_field(&mut h, b"candidate_digest", input.candidate_digest.as_bytes());
    hash_field(
        &mut h,
        b"authority_domain_sequence",
        &input.authority_domain_sequence.to_le_bytes(),
    );
    hash_field(&mut h, b"replay_nonce", input.replay_nonce.as_bytes());
    hex::encode(h.finalize())
}

/// Run 230 — deterministic SHA3-256 hex replay **observation** digest.
///
/// Binds the replay state key digest, the observation sequence number, and the
/// observation epoch. Two structurally-identical observations always produce
/// the same digest.
pub fn replay_observation_digest(
    input: &EvaluatorReplayFreshnessInput,
    observation_count: u64,
    observation_epoch: u64,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(REPLAY_OBSERVATION_DOMAIN_TAG.as_bytes());
    hash_field(&mut h, b"state_key", replay_state_key_digest(input).as_bytes());
    hash_field(&mut h, b"observation_count", &observation_count.to_le_bytes());
    hash_field(&mut h, b"observation_epoch", &observation_epoch.to_le_bytes());
    hex::encode(h.finalize())
}

/// Run 230 — deterministic SHA3-256 hex **consumed decision** digest.
///
/// Binds the replay state key digest and the epoch the decision was consumed
/// at. Recorded only when a decision is explicitly consumed.
pub fn consumed_decision_digest(input: &EvaluatorReplayFreshnessInput, consumed_epoch: u64) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(CONSUMED_DECISION_DOMAIN_TAG.as_bytes());
    hash_field(&mut h, b"state_key", replay_state_key_digest(input).as_bytes());
    hash_field(&mut h, b"consumed_epoch", &consumed_epoch.to_le_bytes());
    hex::encode(h.finalize())
}

/// Run 230 — deterministic SHA3-256 hex **freshness transcript** digest.
///
/// Binds the replay state key digest, the freshness window
/// (`effective_epoch` / `expiry_epoch`), the current canonical epoch, the
/// validation surface, and the classified state. Captures the full freshness
/// reasoning for one evaluation in a single stable digest.
pub fn freshness_transcript_digest(
    input: &EvaluatorReplayFreshnessInput,
    state: ReplayFreshnessState,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(FRESHNESS_TRANSCRIPT_DOMAIN_TAG.as_bytes());
    hash_field(&mut h, b"state_key", replay_state_key_digest(input).as_bytes());
    hash_field(&mut h, b"effective_epoch", &input.effective_epoch.to_le_bytes());
    hash_field(&mut h, b"expiry_epoch", &input.expiry_epoch.to_le_bytes());
    hash_field(
        &mut h,
        b"current_canonical_epoch",
        &input.current_canonical_epoch.to_le_bytes(),
    );
    hash_field(
        &mut h,
        b"validation_surface",
        input.validation_surface.tag().as_bytes(),
    );
    hash_field(&mut h, b"state", state.tag().as_bytes());
    hex::encode(h.finalize())
}

// ===========================================================================
// Reader / writer boundary traits
// ===========================================================================

/// Run 230 — pure read-only replay-state boundary.
///
/// A reader returns the previously-seen state for a replay state key. Reading
/// is **non-mutating**: it never marks a decision consumed.
pub trait GovernanceEvaluatorReplayStateReader {
    /// Read the previously-seen state for `state_key_digest`.
    fn read_previous_state(&self, state_key_digest: &str) -> PreviouslySeenState;
}

/// Run 230 — replay-state writer boundary.
///
/// Records observations and consumed decisions. For Run 230 a writer exists
/// only as a DevNet/TestNet source-test fixture; production / MainNet writers
/// are callable but fail closed.
pub trait GovernanceEvaluatorReplayStateWriter {
    /// Record that a decision was observed (non-consuming).
    fn record_observation(&mut self, state_key_digest: &str, replay_nonce: &str, sequence: u64);
    /// Explicitly mark a decision consumed. Returns `true` iff the write was
    /// accepted (always `false` for the fail-closed production / MainNet
    /// writers).
    fn mark_consumed(&mut self, state_key_digest: &str) -> bool;
}

// ===========================================================================
// DevNet/TestNet fixture store (source-test only)
// ===========================================================================

/// Run 230 — in-memory DevNet/TestNet **source-test** replay-state store.
///
/// This is the only reader/writer that records anything; it exists purely for
/// DevNet/TestNet source tests. It is bound to a [`TrustBundleEnvironment`] and
/// reads as [`PreviouslySeenState::Unavailable`] for a MainNet environment so
/// it can never be mistaken for a MainNet store. It introduces **no** RocksDB
/// schema, file format, or database migration — it is an in-process map only.
#[derive(Debug, Default)]
pub struct FixtureReplayStateStore {
    environment: Option<TrustBundleEnvironment>,
    records: HashMap<String, SeenDecisionRecord>,
}

impl FixtureReplayStateStore {
    /// Construct an empty fixture store for `environment` (DevNet/TestNet).
    pub fn new(environment: TrustBundleEnvironment) -> Self {
        Self {
            environment: Some(environment),
            records: HashMap::new(),
        }
    }

    /// `true` iff this fixture store may serve `environment` (DevNet/TestNet
    /// only; never MainNet).
    fn serves(&self, environment: TrustBundleEnvironment) -> bool {
        environment != TrustBundleEnvironment::Mainnet
            && self.environment == Some(environment)
    }

    /// Number of recorded decisions (test helper).
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` iff no decisions are recorded.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// `true` iff the decision under `state_key_digest` is recorded consumed.
    pub fn is_consumed(&self, state_key_digest: &str) -> bool {
        self.records
            .get(state_key_digest)
            .map(|r| r.consumed)
            .unwrap_or(false)
    }

    /// Read the previously-seen state for `input`, honouring the store's bound
    /// environment.
    pub fn read_for(&self, input: &EvaluatorReplayFreshnessInput) -> PreviouslySeenState {
        if !self.serves(input.environment) {
            return PreviouslySeenState::Unavailable;
        }
        self.read_previous_state(&replay_state_key_digest(input))
    }

    /// Record an observation for `input` (non-consuming). No-op for an
    /// environment the store does not serve.
    pub fn record_for(&mut self, input: &EvaluatorReplayFreshnessInput) {
        if !self.serves(input.environment) {
            return;
        }
        let key = replay_state_key_digest(input);
        self.record_observation(&key, &input.replay_nonce, input.authority_domain_sequence);
    }

    /// Explicitly mark `input`'s decision consumed. Returns `true` iff
    /// accepted. No-op for an environment the store does not serve.
    pub fn consume_for(&mut self, input: &EvaluatorReplayFreshnessInput) -> bool {
        if !self.serves(input.environment) {
            return false;
        }
        let key = replay_state_key_digest(input);
        self.mark_consumed(&key)
    }

    /// Mark a recorded decision superseded (test helper for the superseded
    /// path).
    pub fn mark_superseded(&mut self, state_key_digest: &str) -> bool {
        match self.records.get_mut(state_key_digest) {
            Some(record) => {
                record.superseded = true;
                true
            }
            None => false,
        }
    }
}

impl GovernanceEvaluatorReplayStateReader for FixtureReplayStateStore {
    fn read_previous_state(&self, state_key_digest: &str) -> PreviouslySeenState {
        match self.records.get(state_key_digest) {
            Some(record) => PreviouslySeenState::Seen(record.clone()),
            None => PreviouslySeenState::FirstSeen,
        }
    }
}

impl GovernanceEvaluatorReplayStateWriter for FixtureReplayStateStore {
    fn record_observation(&mut self, state_key_digest: &str, replay_nonce: &str, sequence: u64) {
        let entry = self
            .records
            .entry(state_key_digest.to_string())
            .or_insert_with(|| SeenDecisionRecord {
                state_key_digest: state_key_digest.to_string(),
                replay_nonce: replay_nonce.to_string(),
                recorded_sequence: sequence,
                recorded_effective_epoch: 0,
                recorded_expiry_epoch: 0,
                observation_count: 0,
                consumed: false,
                superseded: false,
            });
        entry.observation_count = entry.observation_count.saturating_add(1);
    }

    fn mark_consumed(&mut self, state_key_digest: &str) -> bool {
        match self.records.get_mut(state_key_digest) {
            Some(record) => {
                record.consumed = true;
                true
            }
            None => false,
        }
    }
}

// ===========================================================================
// Production / MainNet readers + writers (callable-but-unavailable)
// ===========================================================================

/// Run 230 — production replay-state reader. Callable, but always unavailable /
/// fail-closed. No real governance engine, on-chain verifier, or storage is
/// implemented.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProductionReplayStateReader;

impl GovernanceEvaluatorReplayStateReader for ProductionReplayStateReader {
    fn read_previous_state(&self, _state_key_digest: &str) -> PreviouslySeenState {
        PreviouslySeenState::ProductionUnavailable
    }
}

impl GovernanceEvaluatorReplayStateWriter for ProductionReplayStateReader {
    fn record_observation(&mut self, _state_key_digest: &str, _replay_nonce: &str, _sequence: u64) {
        // Fail-closed: production state is unavailable; nothing is recorded.
    }

    fn mark_consumed(&mut self, _state_key_digest: &str) -> bool {
        false
    }
}

/// Run 230 — MainNet replay-state reader. Callable, but always unavailable /
/// fail-closed. MainNet governance and MainNet peer-driven apply remain
/// disabled.
#[derive(Debug, Default, Clone, Copy)]
pub struct MainnetReplayStateReader;

impl GovernanceEvaluatorReplayStateReader for MainnetReplayStateReader {
    fn read_previous_state(&self, _state_key_digest: &str) -> PreviouslySeenState {
        PreviouslySeenState::MainNetUnavailable
    }
}

impl GovernanceEvaluatorReplayStateWriter for MainnetReplayStateReader {
    fn record_observation(&mut self, _state_key_digest: &str, _replay_nonce: &str, _sequence: u64) {
        // Fail-closed: MainNet state is unavailable; nothing is recorded.
    }

    fn mark_consumed(&mut self, _state_key_digest: &str) -> bool {
        false
    }
}

// ===========================================================================
// Explicit fail-closed helpers (grep-verifiable named symbols)
// ===========================================================================

/// Run 230 — explicit refusal helper.
///
/// Returns `true` iff MainNet peer-driven apply remains refused. Run 230 always
/// returns `true` for a MainNet environment: MainNet peer-driven apply remains
/// the Run 147 / 148 / 152 FATAL refusal regardless of any replay/freshness
/// state — even a fresh one.
pub fn mainnet_peer_driven_apply_remains_refused_under_replay_state(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 230 — explicit fail-closed helper.
///
/// Returns `true` iff a local operator key *cannot* satisfy a replay-state
/// policy. Run 230 always returns `true`: replay/freshness state is determined
/// by the authorized evaluator decision binding, never by a local operator key.
pub fn local_operator_cannot_satisfy_replay_state_policy() -> bool {
    true
}

/// Run 230 — explicit fail-closed helper.
///
/// Returns `true` iff peer-majority / gossip count *cannot* satisfy a
/// replay-state policy. Run 230 always returns `true`: replay/freshness state is
/// never satisfiable by counting peers.
pub fn peer_majority_cannot_satisfy_replay_state_policy() -> bool {
    true
}

/// Run 230 — explicit fail-closed helper.
///
/// Returns `true` iff validator-set rotation remains unsupported. Run 230 always
/// returns `true`: no validator-set rotation exists.
pub fn validator_set_rotation_remains_unsupported_under_replay_state() -> bool {
    true
}

/// Run 230 — explicit fail-closed helper.
///
/// Returns `true` iff policy-change actions remain unsupported under the
/// replay-state boundary. Run 230 always returns `true`: the boundary only
/// classifies trust-lifecycle evaluator decisions, never policy-change actions.
pub fn policy_change_action_remains_unsupported_under_replay_state() -> bool {
    true
}