//! Run 238 — source/test governance evaluator **durable replay state backend
//! boundary**.
//!
//! Source/test only. Run 238 captures **no** release-binary evidence;
//! release-binary durable-backend evidence is deferred to **Run 239**. Run 238
//! does **not** implement a real governance execution engine, a real mutation
//! engine, a real on-chain governance proof verifier, MainNet governance
//! enablement, MainNet peer-driven apply enablement, validator-set rotation, a
//! real KMS/HSM backend, a real RemoteSigner backend, or any RocksDB / file /
//! schema / migration / wire / marker / sequence / trust-bundle / storage-format
//! change.
//!
//! ## What this module adds
//!
//! Run 230 proved a typed, pure **replay/freshness state boundary**; Run 232
//! composed it into the evaluator-runtime integration path; Run 234 added a
//! typed **post-mutation consume boundary**; and Run 236 composed consume into
//! the runtime integration path. What was still missing was a typed **durable
//! backend contract** for replay-state persistence: every prior boundary keeps
//! its state in a source/test in-memory fixture only, and nothing yet specifies
//! the *durability*, *atomicity*, *crash-window* and *fail-closed* semantics a
//! real storage backend would have to honour. Run 238 closes that gap at the
//! source/test level — **before** any real storage is implemented — by defining
//! a pure backend contract plus a DevNet/TestNet in-memory fixture that models
//! restart durability through an explicit snapshot, never a file format.
//!
//! * [`DurableBackendDecisionInput`] / [`DurableBackendDecisionExpectations`] —
//!   the typed durable backend key/input binding and its canonical expectation.
//! * [`DurableRecordState`] — the typed durable record classification.
//! * [`DurableBackendOutcome`] — the typed read/observe operation outcome.
//! * [`DurableConsumeOutcome`] — the typed consume / compare-and-mark outcome.
//! * [`CrashWindow`] / [`CrashWindowObservation`] /
//!   [`classify_crash_window`] — the typed crash-window classification.
//! * Deterministic digest helpers: [`durable_backend_key_digest`],
//!   [`durable_record_digest`], [`durable_operation_transcript_digest`],
//!   [`crash_window_transcript_digest`].
//! * The [`GovernanceEvaluatorReplayDurableBackendReader`] /
//!   [`GovernanceEvaluatorReplayDurableBackendWriter`] /
//!   [`GovernanceEvaluatorReplayDurableBackendAtomic`] boundary traits, the
//!   DevNet/TestNet source-test [`FixtureDurableReplayBackend`] with an explicit
//!   [`DurableBackendSnapshot`] restart model, and the callable-but-unavailable
//!   [`ProductionDurableReplayBackend`] / [`MainnetDurableReplayBackend`].
//!
//! ## Fail-closed / durability contract
//!
//! * Every operation is a pure function over an in-memory fixture: it performs
//!   no real I/O, writes no marker, writes no sequence, swaps no live trust,
//!   evicts no sessions, and never invokes Run 070. A durable-backend rejection
//!   therefore necessarily happens *before* any of those mutations.
//! * Only [`DurableBackendOutcome::ProceedFirstSeen`] /
//!   [`DurableBackendOutcome::ProceedKnownFresh`] authorize proceeding;
//!   [`DurableBackendOutcome::ProceedDeferred`] is **not** an approval for
//!   mutation; every other variant is a non-mutating fail-closed.
//! * Consume is authorized **only** by [`DurableConsumeOutcome::ConsumedAfterSuccess`],
//!   and only when the decision was first observed and the mutation completed
//!   successfully. A consume before observe, before success, after a failed
//!   apply, after a rollback, or with a wrong compare-and-mark expected state is
//!   a non-consuming rejection.
//! * Restart durability is modeled **only** through
//!   [`FixtureDurableReplayBackend::restart_snapshot`] /
//!   [`FixtureDurableReplayBackend::from_snapshot`] — an in-process value clone,
//!   never a real file format, database, or migration.
//! * Production / MainNet durable backends are callable but always unavailable /
//!   fail-closed.
//! * MainNet peer-driven apply remains refused unconditionally, even when the
//!   durable backend fixture would otherwise read fresh.
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
use crate::pqc_governance_evaluator_replay_state::EvaluatorReplayFreshnessInput;
use crate::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use crate::pqc_trust_bundle::TrustBundleEnvironment;
use std::collections::HashMap;

/// Domain-separation tag for the Run 238 durable backend key digest.
pub const DURABLE_BACKEND_KEY_DOMAIN_TAG: &str =
    "qbind.run238.governance.evaluator.replay.durable.backend.key.v1";
/// Domain-separation tag for the Run 238 durable record digest.
pub const DURABLE_RECORD_DOMAIN_TAG: &str =
    "qbind.run238.governance.evaluator.replay.durable.record.v1";
/// Domain-separation tag for the Run 238 durable operation transcript digest.
pub const DURABLE_OPERATION_TRANSCRIPT_DOMAIN_TAG: &str =
    "qbind.run238.governance.evaluator.replay.durable.operation.transcript.v1";
/// Domain-separation tag for the Run 238 crash-window transcript digest.
pub const CRASH_WINDOW_TRANSCRIPT_DOMAIN_TAG: &str =
    "qbind.run238.governance.evaluator.replay.durable.crashwindow.transcript.v1";

// ===========================================================================
// Backend kind
// ===========================================================================

/// Run 238 — the durable replay-state backend kind.
///
/// The fixture kinds are DevNet/TestNet source-test only. The production /
/// MainNet kinds are callable but their backing storage is always unavailable /
/// fail-closed — no real persistence is implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableBackendKind {
    /// DevNet fixture durable backend (source-test only).
    FixtureDevNet,
    /// TestNet fixture durable backend (source-test only).
    FixtureTestNet,
    /// Production durable backend (callable-but-unavailable / fail-closed).
    Production,
    /// MainNet durable backend (callable-but-unavailable / fail-closed).
    MainNet,
}

impl DurableBackendKind {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::FixtureDevNet => "fixture-devnet",
            Self::FixtureTestNet => "fixture-testnet",
            Self::Production => "production",
            Self::MainNet => "mainnet",
        }
    }

    /// `true` iff this kind is a DevNet/TestNet source-test fixture backend.
    pub const fn is_fixture(self) -> bool {
        matches!(self, Self::FixtureDevNet | Self::FixtureTestNet)
    }
}

// ===========================================================================
// Durable backend key / input
// ===========================================================================

/// Run 238 — the typed durable backend key/input binding for one evaluator
/// decision.
///
/// Pure data. The digest fields reference the Run 222 evaluator material and the
/// Run 230 replay state binding — never copies of any wire payload. This single
/// structure binds the full Run 238 key set (replay state key digest plus every
/// identity / freshness-window / domain / surface field) so the durable backend
/// can key, classify, and crash-window-reason about a decision without any
/// storage-format change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableBackendDecisionInput {
    /// Run 230 replay state key digest the decision is recorded under.
    pub replay_state_key_digest: String,
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
    /// Validation surface the decision was validated for.
    pub validation_surface: GovernanceExecutionRuntimeSurface,
    /// Mutation surface the decision authorizes / attempted to mutate.
    pub mutation_surface: GovernanceExecutionRuntimeSurface,
    /// Current canonical epoch the freshness window is checked against.
    pub current_canonical_epoch: u64,
}

impl DurableBackendDecisionInput {
    /// `true` iff every mandatory field is structurally present (non-empty).
    pub fn is_well_formed(&self) -> bool {
        !self.replay_state_key_digest.is_empty()
            && !self.evaluator_source_identity_digest.is_empty()
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

    /// Compose a Run 238 durable input by **referencing** a Run 230
    /// [`EvaluatorReplayFreshnessInput`] plus the mutation surface. The replay
    /// state key digest is derived from the same Run 230 input, so the durable
    /// binding is internally consistent with the replay/freshness binding.
    pub fn from_freshness_input(
        freshness: &EvaluatorReplayFreshnessInput,
        mutation_surface: GovernanceExecutionRuntimeSurface,
    ) -> Self {
        Self {
            replay_state_key_digest:
                crate::pqc_governance_evaluator_replay_state::replay_state_key_digest(freshness),
            evaluator_source_identity_digest: freshness.evaluator_source_identity_digest.clone(),
            evaluator_request_digest: freshness.evaluator_request_digest.clone(),
            evaluator_response_digest: freshness.evaluator_response_digest.clone(),
            evaluator_transcript_digest: freshness.evaluator_transcript_digest.clone(),
            governance_execution_decision_digest: freshness
                .governance_execution_decision_digest
                .clone(),
            proposal_id: freshness.proposal_id.clone(),
            decision_id: freshness.decision_id.clone(),
            lifecycle_action: freshness.lifecycle_action,
            candidate_digest: freshness.candidate_digest.clone(),
            authority_domain_sequence: freshness.authority_domain_sequence,
            effective_epoch: freshness.effective_epoch,
            expiry_epoch: freshness.expiry_epoch,
            replay_nonce: freshness.replay_nonce.clone(),
            environment: freshness.environment,
            chain_id: freshness.chain_id.clone(),
            genesis_hash: freshness.genesis_hash.clone(),
            validation_surface: freshness.validation_surface,
            mutation_surface,
            current_canonical_epoch: freshness.current_canonical_epoch,
        }
    }
}

// ===========================================================================
// Durable backend expectations
// ===========================================================================

/// Run 238 — the canonical binding a [`DurableBackendDecisionInput`] is checked
/// against. A mismatch on any field is a typed, non-mutating fail-closed
/// ([`DurableRecordState::MalformedRecord`]) — never a silent approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableBackendDecisionExpectations {
    /// Expected Run 230 replay state key digest.
    pub expected_replay_state_key_digest: String,
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
    /// Expected mutation surface.
    pub expected_mutation_surface: GovernanceExecutionRuntimeSurface,
}

impl DurableBackendDecisionExpectations {
    /// Derive the canonical durable expectations from the same Run 230
    /// [`EvaluatorReplayFreshnessInput`] a faithfully-bound
    /// [`DurableBackendDecisionInput::from_freshness_input`] would reference,
    /// plus the expected mutation surface.
    pub fn from_freshness_input(
        freshness: &EvaluatorReplayFreshnessInput,
        expected_mutation_surface: GovernanceExecutionRuntimeSurface,
    ) -> Self {
        Self {
            expected_replay_state_key_digest:
                crate::pqc_governance_evaluator_replay_state::replay_state_key_digest(freshness),
            expected_evaluator_source_identity_digest: freshness
                .evaluator_source_identity_digest
                .clone(),
            expected_evaluator_request_digest: freshness.evaluator_request_digest.clone(),
            expected_evaluator_response_digest: freshness.evaluator_response_digest.clone(),
            expected_evaluator_transcript_digest: freshness.evaluator_transcript_digest.clone(),
            expected_governance_execution_decision_digest: freshness
                .governance_execution_decision_digest
                .clone(),
            expected_proposal_id: freshness.proposal_id.clone(),
            expected_decision_id: freshness.decision_id.clone(),
            expected_lifecycle_action: freshness.lifecycle_action,
            expected_candidate_digest: freshness.candidate_digest.clone(),
            expected_authority_domain_sequence: freshness.authority_domain_sequence,
            expected_effective_epoch: freshness.effective_epoch,
            expected_expiry_epoch: freshness.expiry_epoch,
            expected_replay_nonce: freshness.replay_nonce.clone(),
            expected_environment: freshness.environment,
            expected_chain_id: freshness.chain_id.clone(),
            expected_genesis_hash: freshness.genesis_hash.clone(),
            expected_validation_surface: freshness.validation_surface,
            expected_mutation_surface,
        }
    }
}

// ===========================================================================
// Durable record state
// ===========================================================================

/// Run 238 — typed durable record classification for one decision key.
///
/// Every variant other than [`Self::ObservedFresh`] / [`Self::ObservedDeferred`]
/// is a fail-closed-or-deferred state. [`Self::Missing`] is a first-seen key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableRecordState {
    /// No durable record exists for this key — first-seen decision.
    Missing,
    /// Observed, first-seen-fresh within its effective window.
    ObservedFresh,
    /// Observed but not yet effective — deferred, not an approval for mutation.
    ObservedDeferred,
    /// Observed but the expiry epoch has passed.
    ObservedExpired,
    /// Observed but the freshness window is degenerate / can never be fresh.
    ObservedStale,
    /// The decision has been explicitly consumed after a successful mutation.
    Consumed,
    /// The decision was observed again before being consumed.
    ReplayDetected,
    /// A newer decision has superseded this one.
    Superseded,
    /// The durable record is structurally malformed / binding mismatch.
    MalformedRecord,
    /// The durable backend is unavailable (generic fail-closed).
    BackendUnavailable,
    /// Production durable backend is unavailable (callable-but-fail-closed).
    ProductionBackendUnavailable,
    /// MainNet durable backend is unavailable (callable-but-fail-closed).
    MainNetBackendUnavailable,
}

impl DurableRecordState {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::ObservedFresh => "observed-fresh",
            Self::ObservedDeferred => "observed-deferred",
            Self::ObservedExpired => "observed-expired",
            Self::ObservedStale => "observed-stale",
            Self::Consumed => "consumed",
            Self::ReplayDetected => "replay-detected",
            Self::Superseded => "superseded",
            Self::MalformedRecord => "malformed-record",
            Self::BackendUnavailable => "backend-unavailable",
            Self::ProductionBackendUnavailable => "production-backend-unavailable",
            Self::MainNetBackendUnavailable => "mainnet-backend-unavailable",
        }
    }

    /// `true` iff the record represents an observed (but not consumed) state.
    pub const fn is_observed(self) -> bool {
        matches!(
            self,
            Self::ObservedFresh
                | Self::ObservedDeferred
                | Self::ObservedExpired
                | Self::ObservedStale
        )
    }
}

// ===========================================================================
// Durable backend operation outcome
// ===========================================================================

/// Run 238 — typed outcome of a durable backend read / observe operation.
///
/// Only [`Self::ProceedFirstSeen`] / [`Self::ProceedKnownFresh`] authorize
/// proceeding. [`Self::ProceedDeferred`] is **not** an approval for mutation.
/// Every other variant is a non-mutating fail-closed rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableBackendOutcome {
    /// First-seen decision recorded fresh. Eligible to proceed.
    ProceedFirstSeen,
    /// Already-observed fresh decision. Eligible to proceed (idempotent read).
    ProceedKnownFresh,
    /// Observed but not yet effective — deferred, not an approval for mutation.
    ProceedDeferred,
    /// The decision's expiry epoch has passed. Non-mutating.
    FailClosedExpired,
    /// The decision's freshness window is degenerate. Non-mutating.
    FailClosedStale,
    /// Replay detected (observed again before consume). Non-mutating.
    FailClosedReplay,
    /// The decision was already consumed. Non-mutating.
    FailClosedConsumed,
    /// A newer decision has superseded this one. Non-mutating.
    FailClosedSuperseded,
    /// The durable record is malformed / binding mismatch. Non-mutating.
    FailClosedMalformedRecord,
    /// The durable backend is unavailable (generic). Non-mutating.
    FailClosedBackendUnavailable,
    /// Production durable backend is unavailable. Non-mutating.
    FailClosedProductionUnavailable,
    /// MainNet durable backend is unavailable / refused. Non-mutating.
    FailClosedMainNetUnavailable,
}

impl DurableBackendOutcome {
    /// `true` iff this outcome authorizes proceeding (only
    /// [`Self::ProceedFirstSeen`] / [`Self::ProceedKnownFresh`]).
    pub const fn authorizes_proceed(self) -> bool {
        matches!(self, Self::ProceedFirstSeen | Self::ProceedKnownFresh)
    }

    /// `true` iff this outcome is a deferral (not an approval for mutation).
    pub const fn is_deferred(self) -> bool {
        matches!(self, Self::ProceedDeferred)
    }

    /// `true` iff this outcome is a non-mutating fail-closed rejection.
    pub const fn is_fail_closed(self) -> bool {
        !matches!(
            self,
            Self::ProceedFirstSeen | Self::ProceedKnownFresh | Self::ProceedDeferred
        )
    }

    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::ProceedFirstSeen => "proceed-first-seen",
            Self::ProceedKnownFresh => "proceed-known-fresh",
            Self::ProceedDeferred => "proceed-deferred",
            Self::FailClosedExpired => "fail-closed-expired",
            Self::FailClosedStale => "fail-closed-stale",
            Self::FailClosedReplay => "fail-closed-replay",
            Self::FailClosedConsumed => "fail-closed-consumed",
            Self::FailClosedSuperseded => "fail-closed-superseded",
            Self::FailClosedMalformedRecord => "fail-closed-malformed-record",
            Self::FailClosedBackendUnavailable => "fail-closed-backend-unavailable",
            Self::FailClosedProductionUnavailable => "fail-closed-production-unavailable",
            Self::FailClosedMainNetUnavailable => "fail-closed-mainnet-unavailable",
        }
    }
}

// ===========================================================================
// Durable consume outcome
// ===========================================================================

/// Run 238 — typed outcome of a durable backend consume /
/// compare-and-mark-consumed operation.
///
/// Only [`Self::ConsumedAfterSuccess`] authorizes a consume, and only when the
/// decision was first observed and the mutation completed successfully. Every
/// other variant is a non-consuming rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableConsumeOutcome {
    /// Consume authorized and recorded after a successful mutation (DevNet/
    /// TestNet source-test only). The **only** consume-authorizing outcome.
    ConsumedAfterSuccess,
    /// Consume attempted before the decision was observed. Non-consuming.
    RejectedNotObserved,
    /// Consume attempted before the mutation completed successfully.
    /// Non-consuming.
    RejectedNotSuccessfulMutation,
    /// Consume attempted after a failed apply. Non-consuming.
    RejectedApplyFailed,
    /// Consume attempted after a rollback. Non-consuming.
    RejectedRolledBack,
    /// Compare-and-mark-consumed attempted with a wrong expected state.
    /// Non-consuming.
    RejectedWrongExpectedState,
    /// The decision was already consumed. Non-consuming.
    RejectedAlreadyConsumed,
    /// The decision was superseded. Non-consuming.
    RejectedSuperseded,
    /// The durable record is malformed / binding mismatch. Non-consuming.
    RejectedMalformedRecord,
    /// The durable backend is unavailable (generic). Non-consuming.
    FailClosedBackendUnavailable,
    /// Production durable backend is unavailable. Non-consuming.
    FailClosedProductionUnavailable,
    /// MainNet durable backend is unavailable / refused. Non-consuming.
    FailClosedMainNetUnavailable,
}

impl DurableConsumeOutcome {
    /// `true` iff this outcome authorized a consume (only
    /// [`Self::ConsumedAfterSuccess`]).
    pub const fn authorizes_consume(self) -> bool {
        matches!(self, Self::ConsumedAfterSuccess)
    }

    /// `true` iff this outcome did **not** authorize a consume.
    pub const fn no_consume(self) -> bool {
        !self.authorizes_consume()
    }

    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::ConsumedAfterSuccess => "consumed-after-success",
            Self::RejectedNotObserved => "rejected-not-observed",
            Self::RejectedNotSuccessfulMutation => "rejected-not-successful-mutation",
            Self::RejectedApplyFailed => "rejected-apply-failed",
            Self::RejectedRolledBack => "rejected-rolled-back",
            Self::RejectedWrongExpectedState => "rejected-wrong-expected-state",
            Self::RejectedAlreadyConsumed => "rejected-already-consumed",
            Self::RejectedSuperseded => "rejected-superseded",
            Self::RejectedMalformedRecord => "rejected-malformed-record",
            Self::FailClosedBackendUnavailable => "fail-closed-backend-unavailable",
            Self::FailClosedProductionUnavailable => "fail-closed-production-unavailable",
            Self::FailClosedMainNetUnavailable => "fail-closed-mainnet-unavailable",
        }
    }
}

// ===========================================================================
// Mutation completion status (projected from Run 234)
// ===========================================================================

/// Run 238 — the mutation-completion status the durable consume operations gate
/// on. Mirrors the Run 234 phase but is re-declared here so the durable backend
/// boundary is self-contained. Only [`Self::AppliedSuccessfully`] permits a
/// consume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableMutationCompletion {
    /// No mutation was attempted.
    NotAttempted,
    /// The mutation was authorized but not applied.
    AuthorizedButNotApplied,
    /// The mutation was applied successfully. The only consume-eligible status.
    AppliedSuccessfully,
    /// The apply was attempted and failed.
    ApplyFailed,
    /// The mutation was applied then rolled back.
    RolledBack,
}

impl DurableMutationCompletion {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::NotAttempted => "not-attempted",
            Self::AuthorizedButNotApplied => "authorized-but-not-applied",
            Self::AppliedSuccessfully => "applied-successfully",
            Self::ApplyFailed => "apply-failed",
            Self::RolledBack => "rolled-back",
        }
    }

    /// `true` iff the mutation completed successfully.
    pub const fn is_applied_successfully(self) -> bool {
        matches!(self, Self::AppliedSuccessfully)
    }
}

// ===========================================================================
// Crash-window classification
// ===========================================================================

/// Run 238 — typed crash-window classification for a durable replay-state
/// operation sequence. Models *where* a crash could have occurred relative to
/// observe / mutation / consume so a recovery never silently approves an
/// in-flight decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CrashWindow {
    /// Crash before the decision was durably observed.
    BeforeObserve,
    /// Crash after observe but before mutation was attempted.
    AfterObserveBeforeMutation,
    /// Crash after a successful mutation but before the consume was recorded.
    /// Must be typed and never silently approved.
    AfterMutationBeforeConsume,
    /// Crash after the consume was recorded.
    AfterConsume,
    /// Crash after observe, with the mutation rolled back.
    RollbackAfterObserve,
    /// Crash after observe, with the apply failed.
    ApplyFailedAfterObserve,
    /// The crash window cannot be determined. Fail-closed.
    UnknownCrashWindow,
    /// Production crash-window classification is unavailable.
    ProductionCrashWindowUnavailable,
    /// MainNet crash-window classification is unavailable.
    MainNetCrashWindowUnavailable,
}

impl CrashWindow {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::BeforeObserve => "before-observe",
            Self::AfterObserveBeforeMutation => "after-observe-before-mutation",
            Self::AfterMutationBeforeConsume => "after-mutation-before-consume",
            Self::AfterConsume => "after-consume",
            Self::RollbackAfterObserve => "rollback-after-observe",
            Self::ApplyFailedAfterObserve => "apply-failed-after-observe",
            Self::UnknownCrashWindow => "unknown-crash-window",
            Self::ProductionCrashWindowUnavailable => "production-crash-window-unavailable",
            Self::MainNetCrashWindowUnavailable => "mainnet-crash-window-unavailable",
        }
    }

    /// `true` iff a recovery for this crash window must **not** silently approve
    /// the in-flight decision (every window except a recorded consume).
    pub const fn requires_fail_closed_recovery(self) -> bool {
        !matches!(self, Self::AfterConsume)
    }

    /// `true` iff this is the after-mutation-before-consume window, which is
    /// typed and must never be silently approved.
    pub const fn is_after_mutation_before_consume(self) -> bool {
        matches!(self, Self::AfterMutationBeforeConsume)
    }
}

/// Run 238 — the observed phase markers a [`CrashWindow`] is classified from.
///
/// Pure data describing what was durably recorded before a crash: whether the
/// decision was observed, whether a mutation was attempted / succeeded /
/// rolled back / failed, and whether the consume was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrashWindowObservation {
    /// The durable backend kind the crash window is classified for.
    pub backend_kind: DurableBackendKind,
    /// `true` iff the decision was durably observed before the crash.
    pub observed: bool,
    /// `true` iff a mutation was attempted before the crash.
    pub mutation_attempted: bool,
    /// `true` iff the mutation completed successfully before the crash.
    pub mutation_succeeded: bool,
    /// `true` iff the mutation was rolled back before the crash.
    pub rolled_back: bool,
    /// `true` iff the apply failed before the crash.
    pub apply_failed: bool,
    /// `true` iff the consume was durably recorded before the crash.
    pub consumed: bool,
}

/// Run 238 — classify the crash window of a durable replay-state operation
/// sequence.
///
/// Deterministic ordering: production / MainNet backends classify as
/// unavailable first (no real persistence), then the phase markers are resolved
/// from latest to earliest so a crash after consume is reported as such, an
/// after-mutation-before-consume crash is typed (never silently approved), and
/// an unobserved decision is classified before-observe.
pub fn classify_crash_window(obs: &CrashWindowObservation) -> CrashWindow {
    match obs.backend_kind {
        DurableBackendKind::Production => return CrashWindow::ProductionCrashWindowUnavailable,
        DurableBackendKind::MainNet => return CrashWindow::MainNetCrashWindowUnavailable,
        DurableBackendKind::FixtureDevNet | DurableBackendKind::FixtureTestNet => {}
    }

    if !obs.observed {
        return CrashWindow::BeforeObserve;
    }
    if obs.consumed {
        return CrashWindow::AfterConsume;
    }
    if obs.apply_failed {
        return CrashWindow::ApplyFailedAfterObserve;
    }
    if obs.rolled_back {
        return CrashWindow::RollbackAfterObserve;
    }
    if obs.mutation_succeeded {
        return CrashWindow::AfterMutationBeforeConsume;
    }
    if !obs.mutation_attempted {
        return CrashWindow::AfterObserveBeforeMutation;
    }
    // Mutation attempted but neither succeeded, failed, nor rolled back: the
    // window cannot be determined — fail closed.
    CrashWindow::UnknownCrashWindow
}

// ===========================================================================
// Binding mismatch
// ===========================================================================

/// Internal: detect a binding mismatch / structural malformation. Returns an
/// operator-facing reason on the first mismatch.
fn durable_binding_mismatch(
    input: &DurableBackendDecisionInput,
    expectations: &DurableBackendDecisionExpectations,
) -> Option<String> {
    if !input.is_well_formed() {
        return Some("durable input is structurally malformed (empty mandatory field)".to_string());
    }
    if input.replay_state_key_digest != expectations.expected_replay_state_key_digest {
        return Some("replay state key digest does not match expected binding".to_string());
    }
    if input.evaluator_source_identity_digest
        != expectations.expected_evaluator_source_identity_digest
    {
        return Some("evaluator source identity digest does not match expected binding".to_string());
    }
    if input.evaluator_request_digest != expectations.expected_evaluator_request_digest {
        return Some("evaluator request digest does not match expected binding".to_string());
    }
    if input.evaluator_response_digest != expectations.expected_evaluator_response_digest {
        return Some("evaluator response digest does not match expected binding".to_string());
    }
    if input.evaluator_transcript_digest != expectations.expected_evaluator_transcript_digest {
        return Some("evaluator transcript digest does not match expected binding".to_string());
    }
    if input.governance_execution_decision_digest
        != expectations.expected_governance_execution_decision_digest
    {
        return Some(
            "governance execution decision digest does not match expected binding".to_string(),
        );
    }
    if input.proposal_id != expectations.expected_proposal_id {
        return Some("proposal id does not match expected binding".to_string());
    }
    if input.decision_id != expectations.expected_decision_id {
        return Some("decision id does not match expected binding".to_string());
    }
    if input.lifecycle_action != expectations.expected_lifecycle_action {
        return Some("lifecycle action does not match expected binding".to_string());
    }
    if input.candidate_digest != expectations.expected_candidate_digest {
        return Some("candidate digest does not match expected binding".to_string());
    }
    if input.authority_domain_sequence != expectations.expected_authority_domain_sequence {
        return Some("authority-domain sequence does not match expected binding".to_string());
    }
    if input.effective_epoch != expectations.expected_effective_epoch {
        return Some("effective epoch does not match expected binding".to_string());
    }
    if input.expiry_epoch != expectations.expected_expiry_epoch {
        return Some("expiry epoch does not match expected binding".to_string());
    }
    if input.replay_nonce != expectations.expected_replay_nonce {
        return Some("replay nonce does not match expected binding".to_string());
    }
    if input.environment != expectations.expected_environment {
        return Some("trust-domain environment does not match expected binding".to_string());
    }
    if input.chain_id != expectations.expected_chain_id {
        return Some("trust-domain chain id does not match expected binding".to_string());
    }
    if input.genesis_hash != expectations.expected_genesis_hash {
        return Some("trust-domain genesis hash does not match expected binding".to_string());
    }
    if input.validation_surface != expectations.expected_validation_surface {
        return Some("validation surface does not match expected binding".to_string());
    }
    if input.mutation_surface != expectations.expected_mutation_surface {
        return Some("mutation surface does not match expected binding".to_string());
    }
    None
}

/// Internal: classify the first-seen freshness window of a durable input into
/// the observed record state it would be recorded under.
fn classify_first_seen_window(input: &DurableBackendDecisionInput) -> DurableRecordState {
    if input.expiry_epoch <= input.effective_epoch {
        return DurableRecordState::ObservedStale;
    }
    if input.current_canonical_epoch < input.effective_epoch {
        return DurableRecordState::ObservedDeferred;
    }
    if input.current_canonical_epoch >= input.expiry_epoch {
        return DurableRecordState::ObservedExpired;
    }
    DurableRecordState::ObservedFresh
}

/// Internal: `true` iff the input is a MainNet peer-driven apply that remains
/// refused unconditionally.
fn is_mainnet_peer_driven_refused(input: &DurableBackendDecisionInput) -> bool {
    input.environment == TrustBundleEnvironment::Mainnet
        && (input.validation_surface == GovernanceExecutionRuntimeSurface::PeerDrivenDrain
            || input.mutation_surface == GovernanceExecutionRuntimeSurface::PeerDrivenDrain)
}

// ===========================================================================
// Durable record + snapshot
// ===========================================================================

/// Run 238 — a single durable replay-state record.
///
/// Pure data held in the fixture backend's in-process map and copied verbatim
/// into a [`DurableBackendSnapshot`]. It carries **no** file format — it is an
/// in-memory value only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableBackendRecord {
    /// The durable backend key digest this record was recorded under.
    pub key_digest: String,
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
    /// The observed state recorded at observe time.
    pub observed_state: DurableRecordState,
    /// `true` iff the decision has been explicitly consumed.
    pub consumed: bool,
    /// `true` iff a newer decision has explicitly superseded this one.
    pub superseded: bool,
}

/// Run 238 — an in-process snapshot of a [`FixtureDurableReplayBackend`] used to
/// model restart durability **without** a real file format, database, or
/// migration. It is a value clone only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DurableBackendSnapshot {
    environment: Option<TrustBundleEnvironment>,
    records: HashMap<String, DurableBackendRecord>,
}

impl DurableBackendSnapshot {
    /// Number of recorded decisions in the snapshot.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` iff the snapshot holds no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

// ===========================================================================
// Backend traits
// ===========================================================================

/// Run 238 — pure read-only durable replay-state backend.
///
/// A reader returns the typed [`DurableRecordState`] for a durable backend key.
/// Reading is **non-mutating**: it never observes and never consumes.
pub trait GovernanceEvaluatorReplayDurableBackendReader {
    /// Read the durable record state for `key_digest`.
    fn read_durable_state(&self, key_digest: &str) -> DurableRecordState;
}

/// Run 238 — durable replay-state writer backend.
///
/// Records first-seen observations and consumed decisions. For Run 238 a writer
/// exists only as a DevNet/TestNet source-test fixture; production / MainNet
/// writers are callable but fail closed.
pub trait GovernanceEvaluatorReplayDurableBackendWriter {
    /// Observe a decision **only if absent**. Returns `true` iff a new record
    /// was inserted (first-seen); `false` iff a record already existed.
    fn observe_decision_if_absent(&mut self, record: &DurableBackendRecord) -> bool;
    /// Mark an observed decision consumed. Returns `true` iff the write was
    /// accepted (a record existed and was not already consumed / superseded).
    fn mark_consumed_after_success(&mut self, key_digest: &str) -> bool;
}

/// Run 238 — atomic compare-and-mark durable replay-state backend.
///
/// Models the atomicity a real backend must honour: a consume is recorded only
/// when the current record state equals the caller's expected state.
pub trait GovernanceEvaluatorReplayDurableBackendAtomic {
    /// Atomically mark consumed **only if** the current state equals
    /// `expected_state`. Returns `true` iff the compare-and-mark succeeded.
    fn compare_and_mark_consumed(
        &mut self,
        key_digest: &str,
        expected_state: DurableRecordState,
    ) -> bool;
}

// ===========================================================================
// DevNet/TestNet fixture durable backend (source-test only)
// ===========================================================================

/// Run 238 — in-memory DevNet/TestNet **source-test** durable replay-state
/// backend.
///
/// This is the only backend that records anything; it exists purely for
/// DevNet/TestNet source tests. It is bound to a [`TrustBundleEnvironment`] and
/// serves DevNet/TestNet only — never MainNet. It introduces **no** RocksDB
/// schema, file format, or database migration — it is an in-process map only.
/// Restart durability is modeled through [`Self::restart_snapshot`] /
/// [`Self::from_snapshot`], a value clone.
#[derive(Debug, Default, Clone)]
pub struct FixtureDurableReplayBackend {
    environment: Option<TrustBundleEnvironment>,
    records: HashMap<String, DurableBackendRecord>,
}

impl FixtureDurableReplayBackend {
    /// Construct an empty fixture durable backend for `environment` (DevNet/
    /// TestNet).
    pub fn new(environment: TrustBundleEnvironment) -> Self {
        Self {
            environment: Some(environment),
            records: HashMap::new(),
        }
    }

    /// `true` iff this fixture backend is bound to `environment` and may serve
    /// it (DevNet/TestNet only; never MainNet).
    pub fn serves(&self, environment: TrustBundleEnvironment) -> bool {
        environment != TrustBundleEnvironment::Mainnet && self.environment == Some(environment)
    }

    /// Number of recorded decisions (test helper).
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` iff no decisions are recorded.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// `true` iff the decision under `key_digest` is recorded consumed.
    pub fn is_consumed(&self, key_digest: &str) -> bool {
        self.records
            .get(key_digest)
            .map(|r| r.consumed)
            .unwrap_or(false)
    }

    /// `true` iff a record exists under `key_digest`.
    pub fn contains(&self, key_digest: &str) -> bool {
        self.records.contains_key(key_digest)
    }

    /// Produce an in-process restart snapshot modeling durability **without** a
    /// real file format, database, or migration.
    pub fn restart_snapshot(&self) -> DurableBackendSnapshot {
        DurableBackendSnapshot {
            environment: self.environment,
            records: self.records.clone(),
        }
    }

    /// Reconstruct a fixture backend from a [`DurableBackendSnapshot`], modeling
    /// a restart that recovers durably-recorded state.
    pub fn from_snapshot(snapshot: DurableBackendSnapshot) -> Self {
        Self {
            environment: snapshot.environment,
            records: snapshot.records,
        }
    }

    /// Mark a recorded decision superseded (test helper for the superseded
    /// path). Returns `true` iff a record existed.
    pub fn mark_superseded(&mut self, key_digest: &str) -> bool {
        match self.records.get_mut(key_digest) {
            Some(record) => {
                record.superseded = true;
                true
            }
            None => false,
        }
    }
}

impl GovernanceEvaluatorReplayDurableBackendReader for FixtureDurableReplayBackend {
    fn read_durable_state(&self, key_digest: &str) -> DurableRecordState {
        match self.records.get(key_digest) {
            None => DurableRecordState::Missing,
            Some(r) if r.consumed => DurableRecordState::Consumed,
            Some(r) if r.superseded => DurableRecordState::Superseded,
            Some(r) => r.observed_state,
        }
    }
}

impl GovernanceEvaluatorReplayDurableBackendWriter for FixtureDurableReplayBackend {
    fn observe_decision_if_absent(&mut self, record: &DurableBackendRecord) -> bool {
        if self.records.contains_key(&record.key_digest) {
            return false;
        }
        let mut stored = record.clone();
        stored.observation_count = stored.observation_count.max(1);
        self.records.insert(record.key_digest.clone(), stored);
        true
    }

    fn mark_consumed_after_success(&mut self, key_digest: &str) -> bool {
        match self.records.get_mut(key_digest) {
            Some(record) if !record.consumed && !record.superseded => {
                record.consumed = true;
                true
            }
            _ => false,
        }
    }
}

impl GovernanceEvaluatorReplayDurableBackendAtomic for FixtureDurableReplayBackend {
    fn compare_and_mark_consumed(
        &mut self,
        key_digest: &str,
        expected_state: DurableRecordState,
    ) -> bool {
        let current = self.read_durable_state(key_digest);
        if current != expected_state {
            return false;
        }
        if !current.is_observed() {
            return false;
        }
        self.mark_consumed_after_success(key_digest)
    }
}

// ===========================================================================
// Production / MainNet durable backends (callable-but-unavailable)
// ===========================================================================

/// Run 238 — production durable replay-state backend. Callable, but always
/// unavailable / fail-closed. No real governance engine, mutation engine,
/// on-chain verifier, RocksDB schema, file format, or migration is implemented.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProductionDurableReplayBackend;

impl GovernanceEvaluatorReplayDurableBackendReader for ProductionDurableReplayBackend {
    fn read_durable_state(&self, _key_digest: &str) -> DurableRecordState {
        DurableRecordState::ProductionBackendUnavailable
    }
}

impl GovernanceEvaluatorReplayDurableBackendWriter for ProductionDurableReplayBackend {
    fn observe_decision_if_absent(&mut self, _record: &DurableBackendRecord) -> bool {
        false
    }

    fn mark_consumed_after_success(&mut self, _key_digest: &str) -> bool {
        false
    }
}

impl GovernanceEvaluatorReplayDurableBackendAtomic for ProductionDurableReplayBackend {
    fn compare_and_mark_consumed(
        &mut self,
        _key_digest: &str,
        _expected_state: DurableRecordState,
    ) -> bool {
        false
    }
}

/// Run 238 — MainNet durable replay-state backend. Callable, but always
/// unavailable / fail-closed. MainNet governance and MainNet peer-driven apply
/// remain disabled.
#[derive(Debug, Default, Clone, Copy)]
pub struct MainnetDurableReplayBackend;

impl GovernanceEvaluatorReplayDurableBackendReader for MainnetDurableReplayBackend {
    fn read_durable_state(&self, _key_digest: &str) -> DurableRecordState {
        DurableRecordState::MainNetBackendUnavailable
    }
}

impl GovernanceEvaluatorReplayDurableBackendWriter for MainnetDurableReplayBackend {
    fn observe_decision_if_absent(&mut self, _record: &DurableBackendRecord) -> bool {
        false
    }

    fn mark_consumed_after_success(&mut self, _key_digest: &str) -> bool {
        false
    }
}

impl GovernanceEvaluatorReplayDurableBackendAtomic for MainnetDurableReplayBackend {
    fn compare_and_mark_consumed(
        &mut self,
        _key_digest: &str,
        _expected_state: DurableRecordState,
    ) -> bool {
        false
    }
}

// ===========================================================================
// High-level operations
// ===========================================================================

/// Build the [`DurableBackendRecord`] a first-seen observation of `input` would
/// record, classified into its observed state.
fn first_seen_record(input: &DurableBackendDecisionInput) -> DurableBackendRecord {
    DurableBackendRecord {
        key_digest: durable_backend_key_digest(input),
        replay_nonce: input.replay_nonce.clone(),
        recorded_sequence: input.authority_domain_sequence,
        recorded_effective_epoch: input.effective_epoch,
        recorded_expiry_epoch: input.expiry_epoch,
        observation_count: 1,
        observed_state: classify_first_seen_window(input),
        consumed: false,
        superseded: false,
    }
}

/// Internal: map a read [`DurableRecordState`] into a [`DurableBackendOutcome`].
fn outcome_from_state(state: DurableRecordState) -> DurableBackendOutcome {
    match state {
        DurableRecordState::Missing => DurableBackendOutcome::ProceedFirstSeen,
        DurableRecordState::ObservedFresh => DurableBackendOutcome::ProceedKnownFresh,
        DurableRecordState::ObservedDeferred => DurableBackendOutcome::ProceedDeferred,
        DurableRecordState::ObservedExpired => DurableBackendOutcome::FailClosedExpired,
        DurableRecordState::ObservedStale => DurableBackendOutcome::FailClosedStale,
        DurableRecordState::Consumed => DurableBackendOutcome::FailClosedConsumed,
        DurableRecordState::ReplayDetected => DurableBackendOutcome::FailClosedReplay,
        DurableRecordState::Superseded => DurableBackendOutcome::FailClosedSuperseded,
        DurableRecordState::MalformedRecord => DurableBackendOutcome::FailClosedMalformedRecord,
        DurableRecordState::BackendUnavailable => {
            DurableBackendOutcome::FailClosedBackendUnavailable
        }
        DurableRecordState::ProductionBackendUnavailable => {
            DurableBackendOutcome::FailClosedProductionUnavailable
        }
        DurableRecordState::MainNetBackendUnavailable => {
            DurableBackendOutcome::FailClosedMainNetUnavailable
        }
    }
}

/// Run 238 — guard a durable operation against MainNet refusal, binding
/// mismatch, and the (un)availability of the backend kind. Returns `Some(...)`
/// with the short-circuit outcome, or `None` when a fixture operation may
/// proceed.
fn guard_durable_operation(
    kind: DurableBackendKind,
    input: &DurableBackendDecisionInput,
    expectations: &DurableBackendDecisionExpectations,
) -> Option<DurableBackendOutcome> {
    if is_mainnet_peer_driven_refused(input) {
        return Some(DurableBackendOutcome::FailClosedMainNetUnavailable);
    }
    if durable_binding_mismatch(input, expectations).is_some() {
        return Some(DurableBackendOutcome::FailClosedMalformedRecord);
    }
    match kind {
        DurableBackendKind::Production => {
            Some(DurableBackendOutcome::FailClosedProductionUnavailable)
        }
        DurableBackendKind::MainNet => Some(DurableBackendOutcome::FailClosedMainNetUnavailable),
        DurableBackendKind::FixtureDevNet | DurableBackendKind::FixtureTestNet => {
            if input.environment == TrustBundleEnvironment::Mainnet {
                Some(DurableBackendOutcome::FailClosedBackendUnavailable)
            } else {
                None
            }
        }
    }
}

/// Run 238 — read the durable state of a decision (non-mutating).
///
/// Pure: never observes, never consumes, writes no marker / sequence, swaps no
/// live trust, evicts no sessions, and never invokes Run 070.
pub fn read_decision_state<B>(
    kind: DurableBackendKind,
    input: &DurableBackendDecisionInput,
    expectations: &DurableBackendDecisionExpectations,
    backend: &B,
) -> DurableBackendOutcome
where
    B: GovernanceEvaluatorReplayDurableBackendReader,
{
    if let Some(short_circuit) = guard_durable_operation(kind, input, expectations) {
        return short_circuit;
    }
    let key = durable_backend_key_digest(input);
    outcome_from_state(backend.read_durable_state(&key))
}

/// Run 238 — observe a decision **only if absent** in the durable backend.
///
/// A first-seen decision is recorded under its classified observed state and
/// resolves to [`DurableBackendOutcome::ProceedFirstSeen`] /
/// [`DurableBackendOutcome::ProceedDeferred`] / a fail-closed for an
/// expired / stale window. An already-present, not-consumed decision observed
/// again is a [`DurableBackendOutcome::FailClosedReplay`]; a consumed /
/// superseded decision fails closed accordingly.
///
/// Pure: writes no marker / sequence, swaps no live trust, evicts no sessions,
/// and never invokes Run 070. A rejection therefore happens before any mutation.
pub fn observe_decision_if_absent<B>(
    kind: DurableBackendKind,
    input: &DurableBackendDecisionInput,
    expectations: &DurableBackendDecisionExpectations,
    backend: &mut B,
) -> DurableBackendOutcome
where
    B: GovernanceEvaluatorReplayDurableBackendReader
        + GovernanceEvaluatorReplayDurableBackendWriter,
{
    if let Some(short_circuit) = guard_durable_operation(kind, input, expectations) {
        return short_circuit;
    }
    let key = durable_backend_key_digest(input);
    match backend.read_durable_state(&key) {
        DurableRecordState::Missing => {
            let record = first_seen_record(input);
            let observed_state = record.observed_state;
            backend.observe_decision_if_absent(&record);
            match observed_state {
                DurableRecordState::ObservedFresh => DurableBackendOutcome::ProceedFirstSeen,
                DurableRecordState::ObservedDeferred => DurableBackendOutcome::ProceedDeferred,
                DurableRecordState::ObservedExpired => DurableBackendOutcome::FailClosedExpired,
                DurableRecordState::ObservedStale => DurableBackendOutcome::FailClosedStale,
                _ => DurableBackendOutcome::FailClosedMalformedRecord,
            }
        }
        // A present, not-consumed, not-superseded observed record observed again
        // is a replay attempt.
        state if state.is_observed() => DurableBackendOutcome::FailClosedReplay,
        DurableRecordState::Consumed => DurableBackendOutcome::FailClosedConsumed,
        DurableRecordState::Superseded => DurableBackendOutcome::FailClosedSuperseded,
        DurableRecordState::ReplayDetected => DurableBackendOutcome::FailClosedReplay,
        other => outcome_from_state(other),
    }
}

/// Run 238 — guard a durable consume operation against MainNet refusal, binding
/// mismatch, and backend (un)availability. Returns `Some(...)` with the
/// short-circuit consume outcome, or `None` when a fixture consume may proceed.
fn guard_durable_consume(
    kind: DurableBackendKind,
    input: &DurableBackendDecisionInput,
    expectations: &DurableBackendDecisionExpectations,
) -> Option<DurableConsumeOutcome> {
    if is_mainnet_peer_driven_refused(input) {
        return Some(DurableConsumeOutcome::FailClosedMainNetUnavailable);
    }
    if durable_binding_mismatch(input, expectations).is_some() {
        return Some(DurableConsumeOutcome::RejectedMalformedRecord);
    }
    match kind {
        DurableBackendKind::Production => {
            Some(DurableConsumeOutcome::FailClosedProductionUnavailable)
        }
        DurableBackendKind::MainNet => Some(DurableConsumeOutcome::FailClosedMainNetUnavailable),
        DurableBackendKind::FixtureDevNet | DurableBackendKind::FixtureTestNet => {
            if input.environment == TrustBundleEnvironment::Mainnet {
                Some(DurableConsumeOutcome::FailClosedBackendUnavailable)
            } else {
                None
            }
        }
    }
}

/// Internal: map the current record state into the consume rejection it implies
/// (for a non-observed / already-resolved record).
fn consume_rejection_for_state(state: DurableRecordState) -> DurableConsumeOutcome {
    match state {
        DurableRecordState::Missing => DurableConsumeOutcome::RejectedNotObserved,
        DurableRecordState::Consumed => DurableConsumeOutcome::RejectedAlreadyConsumed,
        DurableRecordState::Superseded => DurableConsumeOutcome::RejectedSuperseded,
        DurableRecordState::MalformedRecord => DurableConsumeOutcome::RejectedMalformedRecord,
        DurableRecordState::ProductionBackendUnavailable => {
            DurableConsumeOutcome::FailClosedProductionUnavailable
        }
        DurableRecordState::MainNetBackendUnavailable => {
            DurableConsumeOutcome::FailClosedMainNetUnavailable
        }
        DurableRecordState::BackendUnavailable => {
            DurableConsumeOutcome::FailClosedBackendUnavailable
        }
        // Observed states are handled by the caller; any remaining state is a
        // generic non-consuming rejection.
        _ => DurableConsumeOutcome::RejectedNotObserved,
    }
}

/// Internal: reject a consume whose mutation did not complete successfully.
fn consume_rejection_for_completion(
    completion: DurableMutationCompletion,
) -> Option<DurableConsumeOutcome> {
    match completion {
        DurableMutationCompletion::AppliedSuccessfully => None,
        DurableMutationCompletion::ApplyFailed => Some(DurableConsumeOutcome::RejectedApplyFailed),
        DurableMutationCompletion::RolledBack => Some(DurableConsumeOutcome::RejectedRolledBack),
        DurableMutationCompletion::NotAttempted
        | DurableMutationCompletion::AuthorizedButNotApplied => {
            Some(DurableConsumeOutcome::RejectedNotSuccessfulMutation)
        }
    }
}

/// Run 238 — mark a decision consumed **after a successful mutation only**.
///
/// The decision must have been first observed (a record must exist and be in an
/// observed, not-consumed, not-superseded state) and `completion` must be
/// [`DurableMutationCompletion::AppliedSuccessfully`]. Otherwise the consume is
/// rejected and **no** consume is recorded.
///
/// Pure: writes no marker / sequence, swaps no live trust, evicts no sessions,
/// and never invokes Run 070.
pub fn mark_consumed_after_success<B>(
    kind: DurableBackendKind,
    input: &DurableBackendDecisionInput,
    expectations: &DurableBackendDecisionExpectations,
    completion: DurableMutationCompletion,
    backend: &mut B,
) -> DurableConsumeOutcome
where
    B: GovernanceEvaluatorReplayDurableBackendReader
        + GovernanceEvaluatorReplayDurableBackendWriter,
{
    if let Some(short_circuit) = guard_durable_consume(kind, input, expectations) {
        return short_circuit;
    }
    if let Some(rejection) = consume_rejection_for_completion(completion) {
        return rejection;
    }
    let key = durable_backend_key_digest(input);
    let state = backend.read_durable_state(&key);
    if state != DurableRecordState::ObservedFresh {
        return consume_rejection_for_state(state);
    }
    if backend.mark_consumed_after_success(&key) {
        DurableConsumeOutcome::ConsumedAfterSuccess
    } else {
        DurableConsumeOutcome::FailClosedBackendUnavailable
    }
}

/// Run 238 — atomically compare-and-mark a decision consumed.
///
/// The consume is recorded **only if** the current durable record state equals
/// `expected_state`, that state is an observed (consume-eligible) state, and
/// `completion` is [`DurableMutationCompletion::AppliedSuccessfully`]. A wrong
/// expected state is rejected ([`DurableConsumeOutcome::RejectedWrongExpectedState`]).
///
/// Pure: writes no marker / sequence, swaps no live trust, evicts no sessions,
/// and never invokes Run 070.
pub fn compare_and_mark_consumed<B>(
    kind: DurableBackendKind,
    input: &DurableBackendDecisionInput,
    expectations: &DurableBackendDecisionExpectations,
    expected_state: DurableRecordState,
    completion: DurableMutationCompletion,
    backend: &mut B,
) -> DurableConsumeOutcome
where
    B: GovernanceEvaluatorReplayDurableBackendReader
        + GovernanceEvaluatorReplayDurableBackendWriter
        + GovernanceEvaluatorReplayDurableBackendAtomic,
{
    if let Some(short_circuit) = guard_durable_consume(kind, input, expectations) {
        return short_circuit;
    }
    if let Some(rejection) = consume_rejection_for_completion(completion) {
        return rejection;
    }
    let key = durable_backend_key_digest(input);
    let current = backend.read_durable_state(&key);
    if current != expected_state {
        return DurableConsumeOutcome::RejectedWrongExpectedState;
    }
    if current != DurableRecordState::ObservedFresh {
        return consume_rejection_for_state(current);
    }
    if backend.compare_and_mark_consumed(&key, expected_state) {
        DurableConsumeOutcome::ConsumedAfterSuccess
    } else {
        DurableConsumeOutcome::FailClosedBackendUnavailable
    }
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

/// Internal: bind the Run 238 durable key field set into `h`. Binds the stable
/// identity fields only (never the freshness window, current epoch, or surface)
/// so the key is stable across epochs and surfaces for a given decision.
fn hash_durable_key(h: &mut sha3::Sha3_256, input: &DurableBackendDecisionInput) {
    hash_field(h, b"replay_state_key_digest", input.replay_state_key_digest.as_bytes());
    hash_field(h, b"environment", &input.environment.metric_code().to_le_bytes());
    hash_field(h, b"chain_id", input.chain_id.as_bytes());
    hash_field(h, b"genesis_hash", input.genesis_hash.as_bytes());
    hash_field(
        h,
        b"evaluator_source_identity_digest",
        input.evaluator_source_identity_digest.as_bytes(),
    );
    hash_field(h, b"evaluator_request_digest", input.evaluator_request_digest.as_bytes());
    hash_field(h, b"evaluator_response_digest", input.evaluator_response_digest.as_bytes());
    hash_field(
        h,
        b"evaluator_transcript_digest",
        input.evaluator_transcript_digest.as_bytes(),
    );
    hash_field(
        h,
        b"governance_execution_decision_digest",
        input.governance_execution_decision_digest.as_bytes(),
    );
    hash_field(h, b"proposal_id", input.proposal_id.as_bytes());
    hash_field(h, b"decision_id", input.decision_id.as_bytes());
    hash_field(h, b"lifecycle_action", input.lifecycle_action.tag().as_bytes());
    hash_field(h, b"candidate_digest", input.candidate_digest.as_bytes());
    hash_field(
        h,
        b"authority_domain_sequence",
        &input.authority_domain_sequence.to_le_bytes(),
    );
    hash_field(h, b"replay_nonce", input.replay_nonce.as_bytes());
}

/// Run 238 — deterministic SHA3-256 hex durable **backend key** digest.
///
/// Binds the stable identity field set (replay state key digest, environment,
/// chain id, genesis hash, evaluator source identity / request / response /
/// transcript / decision digests, proposal id, decision id, lifecycle action,
/// candidate digest, authority-domain sequence, and replay nonce). It does
/// **not** bind the freshness window, current canonical epoch, or surfaces, so
/// the key is stable across epochs for a given decision.
pub fn durable_backend_key_digest(input: &DurableBackendDecisionInput) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(DURABLE_BACKEND_KEY_DOMAIN_TAG.as_bytes());
    hash_durable_key(&mut h, input);
    hex::encode(h.finalize())
}

/// Run 238 — deterministic SHA3-256 hex durable **record** digest.
///
/// Binds the durable backend key digest, the record state, the observation
/// count, and the recorded freshness window. Two structurally-identical records
/// always produce the same digest.
pub fn durable_record_digest(
    input: &DurableBackendDecisionInput,
    state: DurableRecordState,
    observation_count: u64,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(DURABLE_RECORD_DOMAIN_TAG.as_bytes());
    hash_field(&mut h, b"key", durable_backend_key_digest(input).as_bytes());
    hash_field(&mut h, b"state", state.tag().as_bytes());
    hash_field(&mut h, b"observation_count", &observation_count.to_le_bytes());
    hash_field(&mut h, b"effective_epoch", &input.effective_epoch.to_le_bytes());
    hash_field(&mut h, b"expiry_epoch", &input.expiry_epoch.to_le_bytes());
    hex::encode(h.finalize())
}

/// Run 238 — deterministic SHA3-256 hex durable **operation transcript** digest.
///
/// Binds the durable backend key digest, an operation label, and the resolved
/// outcome tag — the full durable operation reasoning for one evaluation in a
/// single stable digest.
pub fn durable_operation_transcript_digest(
    input: &DurableBackendDecisionInput,
    operation_label: &str,
    outcome_tag: &str,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(DURABLE_OPERATION_TRANSCRIPT_DOMAIN_TAG.as_bytes());
    hash_field(&mut h, b"key", durable_backend_key_digest(input).as_bytes());
    hash_field(&mut h, b"operation", operation_label.as_bytes());
    hash_field(&mut h, b"outcome", outcome_tag.as_bytes());
    hex::encode(h.finalize())
}

/// Run 238 — deterministic SHA3-256 hex **crash-window transcript** digest.
///
/// Binds the durable backend key digest, the crash-window phase markers, and the
/// classified crash window. Captures the full crash-window reasoning for one
/// sequence in a single stable digest.
pub fn crash_window_transcript_digest(
    input: &DurableBackendDecisionInput,
    obs: &CrashWindowObservation,
    crash_window: CrashWindow,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(CRASH_WINDOW_TRANSCRIPT_DOMAIN_TAG.as_bytes());
    hash_field(&mut h, b"key", durable_backend_key_digest(input).as_bytes());
    hash_field(&mut h, b"backend_kind", obs.backend_kind.tag().as_bytes());
    hash_field(&mut h, b"observed", &[obs.observed as u8]);
    hash_field(&mut h, b"mutation_attempted", &[obs.mutation_attempted as u8]);
    hash_field(&mut h, b"mutation_succeeded", &[obs.mutation_succeeded as u8]);
    hash_field(&mut h, b"rolled_back", &[obs.rolled_back as u8]);
    hash_field(&mut h, b"apply_failed", &[obs.apply_failed as u8]);
    hash_field(&mut h, b"consumed", &[obs.consumed as u8]);
    hash_field(&mut h, b"crash_window", crash_window.tag().as_bytes());
    hex::encode(h.finalize())
}

// ===========================================================================
// Explicit fail-closed helpers (grep-verifiable named symbols)
// ===========================================================================

/// Run 238 — explicit refusal helper.
///
/// Returns `true` iff MainNet peer-driven apply remains refused under the
/// durable backend boundary. Run 238 always returns `true` for a MainNet
/// environment: MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL
/// refusal and never proceeds or consumes, regardless of any durable backend
/// state — even a fresh one.
pub fn mainnet_peer_driven_apply_remains_refused_under_durable_backend(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 238 — explicit invariant helper.
///
/// Returns `true`: a durable consume is allowed only after a successful mutation
/// completion. Provided as a grep-verifiable statement of the after-success-only
/// contract.
pub fn durable_consume_only_after_successful_mutation() -> bool {
    true
}

/// Run 238 — explicit fail-closed helper.
///
/// Returns `true`: production and MainNet durable backends remain unavailable /
/// fail-closed. No real durable storage, RocksDB schema, file format, or
/// migration is implemented.
pub fn production_mainnet_durable_backend_remains_unavailable() -> bool {
    true
}

/// Run 238 — explicit invariant helper.
///
/// Returns `true`: restart durability is modeled only through a source/test
/// fixture snapshot, never a real file format, database, or migration.
pub fn restart_durability_is_fixture_snapshot_only() -> bool {
    true
}

/// Run 238 — explicit fail-closed helper.
///
/// Returns `true` iff a local operator key *cannot* satisfy a durable replay
/// backend policy. Run 238 always returns `true`: durable backend eligibility is
/// determined by the authorized evaluator decision binding and a successful
/// mutation, never by a local operator key.
pub fn local_operator_cannot_satisfy_durable_backend_policy() -> bool {
    true
}

/// Run 238 — explicit fail-closed helper.
///
/// Returns `true` iff peer-majority / gossip count *cannot* satisfy a durable
/// replay backend policy. Run 238 always returns `true`: durable backend state
/// is never satisfiable by counting peers.
pub fn peer_majority_cannot_satisfy_durable_backend_policy() -> bool {
    true
}

/// Run 238 — explicit fail-closed helper.
///
/// Returns `true` iff validator-set rotation remains unsupported under the
/// durable backend boundary. Run 238 always returns `true`: no validator-set
/// rotation exists.
pub fn validator_set_rotation_remains_unsupported_under_durable_backend() -> bool {
    true
}

/// Run 238 — explicit fail-closed helper.
///
/// Returns `true` iff policy-change actions remain unsupported under the durable
/// backend boundary. Run 238 always returns `true`: the boundary only governs
/// trust-lifecycle evaluator decisions, never policy-change actions.
pub fn policy_change_action_remains_unsupported_under_durable_backend() -> bool {
    true
}

/// Run 238 — explicit non-implementation helper.
///
/// Returns `true`: Run 238 introduces no RocksDB schema, file format, database
/// migration, or storage-format change. The durable backend boundary is a pure
/// contract plus an in-memory fixture only.
pub fn no_rocksdb_file_schema_migration_change_under_durable_backend() -> bool {
    true
}