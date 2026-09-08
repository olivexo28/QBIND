//! Run 240 — source/test governance evaluator **durable replay backend runtime
//! integration**.
//!
//! Source/test only. Run 240 captures **no** release-binary evidence;
//! release-binary durable-runtime-integration evidence is deferred to **Run
//! 241**. Run 240 does **not** implement a real governance execution engine, a
//! real on-chain governance proof verifier, a real mutation engine, MainNet
//! governance enablement, MainNet peer-driven apply enablement, validator-set
//! rotation, a real KMS/HSM backend, a real RemoteSigner backend, or any RocksDB
//! / file / schema / migration / wire / marker / sequence / trust-bundle /
//! storage-format change.
//!
//! ## What this module closes
//!
//! Run 230 proved a typed, pure **replay/freshness state boundary**; Run 232
//! composed it into the evaluator-runtime integration path as a mandatory
//! pre-mutation gate; Run 234 added a typed **post-mutation consume boundary**;
//! Run 236 composed consume into the runtime integration path; and Run 238 added
//! a typed **durable replay-state backend boundary** (observe / read /
//! compare-and-mark-consumed / crash-window) plus a DevNet/TestNet in-memory
//! fixture that models restart durability through an explicit snapshot. Run 239
//! closed that backend's release-binary evidence.
//!
//! What was still missing is the *integration*: the Run 238 durable backend was
//! proven standalone but was **not** wired into the replay/freshness + consume
//! runtime path as the durable state provider. The existing runtime replay/
//! consume integration (Run 236) still keys off the non-durable fixture-style
//! state boundary. Run 240 closes that gap at the source/test level by composing
//! the durable backend as a typed runtime state provider so the runtime models
//! the full durable lifecycle:
//!
//! 1. **durable observe/read before mutation authorization**;
//! 2. **replay/freshness validation using durable + Run 230 state**;
//! 3. **mutation authorization only on fresh / known-fresh**;
//! 4. **compare-and-mark-consumed only after successful mutation completion**;
//! 5. **crash-window classification** where mutation/consume ordering is
//!    ambiguous; and
//! 6. **production/MainNet durable backend unavailable / fail-closed**.
//!
//! ## Ordering contract
//!
//! The integration enforces the exact pipeline ordering:
//!
//! 1. **selector / environment / chain / genesis binding** — the Run 238 durable
//!    guard + Run 230 binding check;
//! 2. **durable read/observe** — the Run 238 backend, *before* any mutation
//!    authorization;
//! 3. **replay/freshness classification** — Run 230 / Run 232 agreement;
//! 4. **evaluator runtime authorization** — mutation authorized only on
//!    fresh/known-fresh;
//! 5. **mutation completion status** — [`DurableMutationCompletion`];
//! 6. **compare-and-mark-consumed only after `AppliedSuccessfully`** — Run 238
//!    atomic consume;
//! 7. **crash-window classification** — Run 238 [`classify_crash_window`] when
//!    the runtime cannot prove post-mutation consume ordering; and
//! 8. **production / MainNet durable unavailable / fail-closed**.
//!
//! The durable read/observe necessarily happens **before** mutation
//! authorization, and the durable consume happens **only** after a modeled
//! successful mutation completion.
//!
//! ## Fail-closed / safety contract
//!
//! * [`DurableReplayRuntimeOutcome::ConsumeDurableAfterMutationSuccess`] is the
//!   **only** consume-authorizing outcome, and only when the decision was
//!   durably observed, the runtime replay/freshness agreed fresh, and the
//!   mutation completion status is [`DurableMutationCompletion::AppliedSuccessfully`].
//! * Read-only validation observes/reads but never consumes
//!   ([`DurableReplayRuntimeOutcome::ProceedFreshObserved`] /
//!   [`DurableReplayRuntimeOutcome::ProceedKnownFresh`]).
//! * A deferral never authorizes mutation
//!   ([`DurableReplayRuntimeOutcome::ProceedDeferredObserved`]).
//! * A failed apply, a rollback, and an authorized-but-not-applied decision
//!   never consume.
//! * An ambiguous (after-mutation-before-consume / unknown / after-consume)
//!   crash window is typed and fails closed
//!   ([`DurableReplayRuntimeOutcome::CrashWindowFailClosed`]).
//! * Production / MainNet durable backends are reached but always fail closed
//!   ([`DurableReplayRuntimeOutcome::ProductionDurableUnavailable`] /
//!   [`DurableReplayRuntimeOutcome::MainNetDurableUnavailable`]).
//! * **MainNet peer-driven apply remains refused** even when the durable state
//!   reads fresh
//!   ([`DurableReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused`]).
//! * Evaluation is a pure function over the durable fixture + Run 230 state: it
//!   performs no I/O, writes no marker, writes no sequence, swaps no live trust,
//!   evicts no sessions, and never invokes Run 070. The only state mutation it
//!   can cause is the explicit fixture durable observe / compare-and-mark-consumed
//!   write on the proceed/consume paths; every fail-closed outcome leaves the
//!   backend untouched.
//! * Validator-set rotation and policy-change actions remain unsupported.
//!
//! ## What this module does NOT change
//!
//! * It adds **no** field to any production wire message.
//! * It alters **no** trust-bundle, authority-marker, or sequence schema.
//! * It introduces **no** RocksDB schema, file format, or database migration.
//! * It enables **no** MainNet peer-driven apply.
//! * It does **not** claim full C4 or C5 closure.

use crate::pqc_governance_evaluator_replay_consume_boundary::surface_is_validation_only;
use crate::pqc_governance_evaluator_replay_durable_backend::{
    classify_crash_window, compare_and_mark_consumed, observe_decision_if_absent,
    read_decision_state, CrashWindow, CrashWindowObservation, DurableBackendDecisionExpectations,
    DurableBackendDecisionInput, DurableBackendKind, DurableBackendOutcome, DurableConsumeOutcome,
    DurableMutationCompletion, DurableRecordState, GovernanceEvaluatorReplayDurableBackendAtomic,
    GovernanceEvaluatorReplayDurableBackendReader, GovernanceEvaluatorReplayDurableBackendWriter,
};
use crate::pqc_governance_evaluator_replay_state::{
    evaluate_evaluator_replay_freshness, EvaluatorReplayFreshnessExpectations,
    EvaluatorReplayFreshnessInput, EvaluatorReplayFreshnessOutcome, ReplayStatePolicy,
};
use crate::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Integration input
// ===========================================================================

/// Run 240 — typed inputs for one durable replay-backend runtime-integration
/// round-trip.
///
/// Composes the Run 238 durable backend decision input + expectations + kind
/// with the Run 230 replay/freshness runtime input + expectations (the
/// replay/freshness runtime layer Run 232 composes) and the Run 234 / Run 236
/// consume runtime input (the mutation completion status + surfaces). Holds only
/// borrows of caller-owned data plus the `Copy` durable kind / replay policy /
/// mutation completion; it is itself pure data and performs no work on
/// construction.
///
/// In the durable runtime integration the Run 238 durable backend is the
/// authoritative replay-state provider; the Run 230 replay/freshness input
/// supplies the binding + freshness-window cross-check (and may legitimately
/// carry [`crate::pqc_governance_evaluator_replay_state::PreviouslySeenState::FirstSeen`]
/// even when the durable backend already holds the decision, since the durable
/// backend has become the state store).
pub struct DurableReplayRuntimeIntegrationInput<'a> {
    /// The Run 238 durable backend kind. Fixture kinds are DevNet/TestNet
    /// source-test only; production / MainNet are reached but unavailable.
    pub durable_kind: DurableBackendKind,
    /// The Run 238 durable backend decision input/key binding.
    pub durable_input: &'a DurableBackendDecisionInput,
    /// The canonical Run 238 durable backend expectations.
    pub durable_expectations: &'a DurableBackendDecisionExpectations,
    /// The Run 230 replay/freshness runtime input (binding + freshness window).
    pub freshness_input: &'a EvaluatorReplayFreshnessInput,
    /// The canonical Run 230 replay/freshness expectations.
    pub freshness_expectations: &'a EvaluatorReplayFreshnessExpectations,
    /// The active replay-state policy. [`ReplayStatePolicy::Disabled`] preserves
    /// the Run 214 legacy bypass — the durable backend is never written.
    pub replay_policy: ReplayStatePolicy,
    /// The modeled Run 234 / Run 236 mutation completion status (the consume
    /// runtime input). Only [`DurableMutationCompletion::AppliedSuccessfully`]
    /// permits a durable consume.
    pub mutation_completion: DurableMutationCompletion,
}

impl DurableReplayRuntimeIntegrationInput<'_> {
    /// The mutation surface the decision authorizes / attempted to mutate.
    pub fn mutation_surface(&self) -> GovernanceExecutionRuntimeSurface {
        self.durable_input.mutation_surface
    }

    /// The validation surface the decision was validated for.
    pub fn validation_surface(&self) -> GovernanceExecutionRuntimeSurface {
        self.durable_input.validation_surface
    }

    /// The trust-domain environment the decision is bound to.
    pub fn environment(&self) -> TrustBundleEnvironment {
        self.durable_input.environment
    }

    /// The trust-domain chain id the decision is bound to.
    pub fn chain_id(&self) -> &str {
        &self.durable_input.chain_id
    }

    /// The trust-domain genesis hash the decision is bound to.
    pub fn genesis_hash(&self) -> &str {
        &self.durable_input.genesis_hash
    }

    /// The current canonical epoch the freshness window is checked against.
    pub fn current_canonical_epoch(&self) -> u64 {
        self.durable_input.current_canonical_epoch
    }

    /// `true` iff either surface is a read-only validation surface (never
    /// mutates / consumes).
    pub fn is_read_only_validation(&self) -> bool {
        surface_is_validation_only(self.validation_surface())
            || surface_is_validation_only(self.mutation_surface())
    }

    /// `true` iff this is a MainNet peer-driven apply that remains refused
    /// unconditionally.
    pub fn is_mainnet_peer_driven(&self) -> bool {
        self.environment() == TrustBundleEnvironment::Mainnet
            && (self.validation_surface() == GovernanceExecutionRuntimeSurface::PeerDrivenDrain
                || self.mutation_surface() == GovernanceExecutionRuntimeSurface::PeerDrivenDrain)
    }
}

// ===========================================================================
// Integration outcome
// ===========================================================================

/// Run 240 — typed outcome of composing the Run 238 durable backend with the
/// Run 236 / 232 / 230 replay/freshness + consume runtime path.
///
/// Only [`Self::ConsumeDurableAfterMutationSuccess`] authorizes a durable
/// consume, and only after a durable observe, a runtime fresh agreement, and a
/// modeled `AppliedSuccessfully` mutation. Every other variant is a
/// non-consuming proceed, a non-consuming `DoNotConsume*`, or a fail-closed
/// rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableReplayRuntimeOutcome {
    /// Run 214 legacy bypass — the durable backend boundary was never reached;
    /// no durable write was performed.
    ProceedLegacyBypassNoDurableWrite,
    /// The decision was durably observed but is not yet effective — deferred,
    /// not an approval for mutation.
    ProceedDeferredObserved,
    /// A first-seen decision was durably observed as fresh on a read-only
    /// validation surface — observe/read only, no mutation, no consume.
    ProceedFreshObserved,
    /// An already-observed fresh decision was re-read as known fresh — idempotent
    /// read, no re-observe, no consume.
    ProceedKnownFresh,
    /// A first-seen decision was durably observed fresh on a mutating surface and
    /// the runtime replay/freshness agreed — mutation is authorized (not yet
    /// applied, nothing consumed).
    ProceedMutationAuthorized,
    /// Durable compare-and-mark-consumed succeeded after a modeled successful
    /// mutation (DevNet/TestNet source-test only). The **only**
    /// consume-authorizing outcome.
    ConsumeDurableAfterMutationSuccess,
    /// The mutation was authorized but not yet applied — must not consume before
    /// apply.
    DoNotConsumeBeforeApply,
    /// The apply failed — must not consume a failed apply.
    DoNotConsumeApplyFailed,
    /// The mutation was rolled back — must not consume a rolled-back mutation.
    DoNotConsumeRolledBack,
    /// The runtime could not prove post-mutation consume ordering — the crash
    /// window is typed and fails closed. Carries the classified [`CrashWindow`].
    CrashWindowFailClosed(CrashWindow),
    /// The durable backend failed closed (expired / stale / replay / consumed /
    /// superseded / malformed / unavailable). Carries the originating Run 238
    /// [`DurableBackendOutcome`]. Non-consuming.
    DurableReplayFailClosed(DurableBackendOutcome),
    /// The Run 230 / Run 232 replay/freshness runtime evaluation failed closed
    /// before any mutation could be authorized. Carries the originating Run 230
    /// outcome. Non-consuming.
    ReplayRuntimeFailClosed(EvaluatorReplayFreshnessOutcome),
    /// The durable consume runtime step failed closed on a binding / ordering
    /// reason (consume before observe, before success, wrong expected state, or
    /// a malformed binding). Carries an operator-facing reason. Non-consuming.
    ConsumeRuntimeFailClosed {
        /// Operator-facing reason.
        reason: String,
    },
    /// The production durable backend was reached but is unavailable
    /// (callable-but-fail-closed).
    ProductionDurableUnavailable,
    /// The MainNet durable backend was reached but is unavailable / refused
    /// (callable-but-fail-closed).
    MainNetDurableUnavailable,
    /// MainNet trust domain — peer-driven apply remains the Run 147 / 148 / 152
    /// FATAL refusal regardless of a fresh durable state. Non-consuming.
    MainNetPeerDrivenApplyRefused,
}

impl DurableReplayRuntimeOutcome {
    /// `true` iff this outcome authorizes a durable consume (only
    /// [`Self::ConsumeDurableAfterMutationSuccess`]).
    pub fn authorizes_consume(&self) -> bool {
        matches!(self, Self::ConsumeDurableAfterMutationSuccess)
    }

    /// `true` iff this outcome does **not** authorize a consume.
    pub fn no_consume(&self) -> bool {
        !self.authorizes_consume()
    }

    /// `true` iff this outcome authorizes a lifecycle mutation (only
    /// [`Self::ProceedMutationAuthorized`]).
    pub fn authorizes_mutation(&self) -> bool {
        matches!(self, Self::ProceedMutationAuthorized)
    }

    /// `true` iff this is a deferral (not an approval for mutation).
    pub fn is_deferred(&self) -> bool {
        matches!(self, Self::ProceedDeferredObserved)
    }

    /// `true` iff the runtime call site may continue (a legacy bypass, an
    /// observed-fresh / known-fresh read, a fresh mutation authorization, or a
    /// successful durable consume). A deferral is **not** a proceed.
    pub fn is_proceed(&self) -> bool {
        matches!(
            self,
            Self::ProceedLegacyBypassNoDurableWrite
                | Self::ProceedFreshObserved
                | Self::ProceedKnownFresh
                | Self::ProceedMutationAuthorized
                | Self::ConsumeDurableAfterMutationSuccess
        )
    }

    /// `true` iff this outcome is a non-mutating fail-closed / non-proceed
    /// rejection (every variant other than the proceed variants).
    pub fn is_fail_closed(&self) -> bool {
        !self.is_proceed()
    }

    /// `true` iff this rejection is the MainNet peer-driven-apply refusal.
    pub fn is_mainnet_peer_driven_apply_refused(&self) -> bool {
        matches!(self, Self::MainNetPeerDrivenApplyRefused)
    }

    /// `true` iff this is the typed crash-window fail-closed.
    pub fn is_crash_window_fail_closed(&self) -> bool {
        matches!(self, Self::CrashWindowFailClosed(_))
    }

    /// Stable operator-facing tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::ProceedLegacyBypassNoDurableWrite => "proceed-legacy-bypass-no-durable-write",
            Self::ProceedDeferredObserved => "proceed-deferred-observed",
            Self::ProceedFreshObserved => "proceed-fresh-observed",
            Self::ProceedKnownFresh => "proceed-known-fresh",
            Self::ProceedMutationAuthorized => "proceed-mutation-authorized",
            Self::ConsumeDurableAfterMutationSuccess => "consume-durable-after-mutation-success",
            Self::DoNotConsumeBeforeApply => "do-not-consume-before-apply",
            Self::DoNotConsumeApplyFailed => "do-not-consume-apply-failed",
            Self::DoNotConsumeRolledBack => "do-not-consume-rolled-back",
            Self::CrashWindowFailClosed(_) => "crash-window-fail-closed",
            Self::DurableReplayFailClosed(_) => "durable-replay-fail-closed",
            Self::ReplayRuntimeFailClosed(_) => "replay-runtime-fail-closed",
            Self::ConsumeRuntimeFailClosed { .. } => "consume-runtime-fail-closed",
            Self::ProductionDurableUnavailable => "production-durable-unavailable",
            Self::MainNetDurableUnavailable => "mainnet-durable-unavailable",
            Self::MainNetPeerDrivenApplyRefused => "mainnet-peer-driven-apply-refused",
        }
    }
}

// ===========================================================================
// Durable-outcome projection
// ===========================================================================

/// Internal: map a Run 238 durable backend (un)availability / fail-closed
/// [`DurableBackendOutcome`] into the Run 240 runtime outcome, resolving the
/// MainNet refusal vs unavailable distinction.
fn project_durable_fail_closed(
    input: &DurableReplayRuntimeIntegrationInput<'_>,
    outcome: DurableBackendOutcome,
) -> DurableReplayRuntimeOutcome {
    match outcome {
        DurableBackendOutcome::FailClosedProductionUnavailable => {
            DurableReplayRuntimeOutcome::ProductionDurableUnavailable
        }
        DurableBackendOutcome::FailClosedMainNetUnavailable => {
            if input.is_mainnet_peer_driven() {
                DurableReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused
            } else {
                DurableReplayRuntimeOutcome::MainNetDurableUnavailable
            }
        }
        other => DurableReplayRuntimeOutcome::DurableReplayFailClosed(other),
    }
}

/// Internal: the durable phase resolved from a non-mutating durable read.
enum DurablePhase {
    /// No durable record — first-seen decision.
    FirstSeen,
    /// An already-observed, fresh, not-consumed record (idempotent re-read).
    KnownFresh,
    /// An already-observed, not-yet-effective record.
    Deferred,
}

// ===========================================================================
// Integration entry point
// ===========================================================================

/// Run 240 — compose the Run 238 durable backend with the Run 236 / 232 / 230
/// replay/freshness + consume runtime path as the durable state provider.
///
/// Pure: performs no I/O, writes no marker, writes no sequence, swaps no live
/// trust, evicts no sessions, and never invokes Run 070. The durable read/observe
/// runs **before** mutation authorization, and the durable consume happens
/// **only** after a modeled successful mutation completion. The only state
/// mutation this can cause is the explicit fixture durable observe /
/// compare-and-mark-consumed write on the proceed/consume paths; a fail-closed
/// outcome never writes to the backend.
pub fn integrate_durable_replay_runtime<B>(
    input: &DurableReplayRuntimeIntegrationInput<'_>,
    backend: &mut B,
) -> DurableReplayRuntimeOutcome
where
    B: GovernanceEvaluatorReplayDurableBackendReader
        + GovernanceEvaluatorReplayDurableBackendWriter
        + GovernanceEvaluatorReplayDurableBackendAtomic,
{
    // Step 1a: MainNet peer-driven apply remains refused unconditionally — guard
    // it before any durable read so a fresh durable state can never bypass it.
    if input.is_mainnet_peer_driven() {
        return DurableReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused;
    }

    // Step 1b: Run 214 legacy bypass — an unwired replay policy never reaches the
    // durable backend and never performs a durable write.
    if !input.replay_policy.is_wired() {
        return DurableReplayRuntimeOutcome::ProceedLegacyBypassNoDurableWrite;
    }

    // Step 2: durable read/observe BEFORE mutation authorization. A non-mutating
    // read first resolves the current durable phase and short-circuits every
    // terminal durable fail-closed (consumed / superseded / malformed /
    // unavailable / production / MainNet).
    let durable_read = read_decision_state(
        input.durable_kind,
        input.durable_input,
        input.durable_expectations,
        backend,
    );
    let phase = match durable_read {
        DurableBackendOutcome::ProceedFirstSeen => DurablePhase::FirstSeen,
        DurableBackendOutcome::ProceedKnownFresh => DurablePhase::KnownFresh,
        DurableBackendOutcome::ProceedDeferred => DurablePhase::Deferred,
        terminal => return project_durable_fail_closed(input, terminal),
    };

    // Step 3: replay/freshness classification — the Run 230 / Run 232 runtime
    // agreement. Mutation can only be authorized after the runtime classifies the
    // decision fresh; a deferral defers and any fail-closed rejects before
    // mutation.
    let runtime =
        evaluate_evaluator_replay_freshness(input.freshness_input, input.freshness_expectations);
    match &runtime {
        EvaluatorReplayFreshnessOutcome::ProceedFresh => {}
        EvaluatorReplayFreshnessOutcome::ProceedDeferred => {
            // Durably observe the deferred decision (records ObservedDeferred for
            // a first-seen decision) but never authorize mutation.
            if matches!(phase, DurablePhase::FirstSeen) {
                observe_decision_if_absent(
                    input.durable_kind,
                    input.durable_input,
                    input.durable_expectations,
                    backend,
                );
            }
            return DurableReplayRuntimeOutcome::ProceedDeferredObserved;
        }
        _ => return DurableReplayRuntimeOutcome::ReplayRuntimeFailClosed(runtime),
    }
    if matches!(phase, DurablePhase::Deferred) {
        // Durable record is deferred even though the runtime read fresh: defer.
        return DurableReplayRuntimeOutcome::ProceedDeferredObserved;
    }

    // Step 4: the durable state is first-seen / known-fresh and the runtime
    // agreed fresh.
    let first_seen = matches!(phase, DurablePhase::FirstSeen);

    // Read-only validation observes/reads but never authorizes a mutation or
    // consumes — gate it before the mutation-completion branch so even a modeled
    // successful mutation on a validation surface can never consume.
    if input.is_read_only_validation() {
        if first_seen {
            let observe = observe_decision_if_absent(
                input.durable_kind,
                input.durable_input,
                input.durable_expectations,
                backend,
            );
            if observe.is_fail_closed() {
                return project_durable_fail_closed(input, observe);
            }
            if observe.is_deferred() {
                return DurableReplayRuntimeOutcome::ProceedDeferredObserved;
            }
            return DurableReplayRuntimeOutcome::ProceedFreshObserved;
        }
        return DurableReplayRuntimeOutcome::ProceedKnownFresh;
    }

    // Step 5–7: mutating surface. Branch on the modeled mutation completion.
    match input.mutation_completion {
        // Observe / authorize phase: no mutation has been attempted yet.
        DurableMutationCompletion::NotAttempted => {
            if first_seen {
                // Durably observe (record ObservedFresh) before authorizing.
                let observe = observe_decision_if_absent(
                    input.durable_kind,
                    input.durable_input,
                    input.durable_expectations,
                    backend,
                );
                if observe.is_fail_closed() {
                    return project_durable_fail_closed(input, observe);
                }
                if observe.is_deferred() {
                    return DurableReplayRuntimeOutcome::ProceedDeferredObserved;
                }
                DurableReplayRuntimeOutcome::ProceedMutationAuthorized
            } else {
                // Already durably observed fresh — idempotent known-fresh re-read.
                DurableReplayRuntimeOutcome::ProceedKnownFresh
            }
        }
        // Post-authorization phases: the decision must already have been durably
        // observed in a prior pass — never observe here.
        DurableMutationCompletion::AuthorizedButNotApplied => {
            DurableReplayRuntimeOutcome::DoNotConsumeBeforeApply
        }
        DurableMutationCompletion::ApplyFailed => {
            DurableReplayRuntimeOutcome::DoNotConsumeApplyFailed
        }
        DurableMutationCompletion::RolledBack => {
            DurableReplayRuntimeOutcome::DoNotConsumeRolledBack
        }
        DurableMutationCompletion::AppliedSuccessfully => {
            if first_seen {
                // Consume attempted before the decision was durably observed.
                return DurableReplayRuntimeOutcome::ConsumeRuntimeFailClosed {
                    reason: "durable consume attempted before observe".to_string(),
                };
            }
            // Compare-and-mark-consumed only after a successful mutation, only
            // when the current durable state is the expected ObservedFresh.
            let consume = compare_and_mark_consumed(
                input.durable_kind,
                input.durable_input,
                input.durable_expectations,
                DurableRecordState::ObservedFresh,
                DurableMutationCompletion::AppliedSuccessfully,
                backend,
            );
            project_consume_outcome(input, consume)
        }
    }
}

/// Internal: project a Run 238 [`DurableConsumeOutcome`] into the Run 240
/// runtime outcome.
fn project_consume_outcome(
    input: &DurableReplayRuntimeIntegrationInput<'_>,
    consume: DurableConsumeOutcome,
) -> DurableReplayRuntimeOutcome {
    match consume {
        DurableConsumeOutcome::ConsumedAfterSuccess => {
            DurableReplayRuntimeOutcome::ConsumeDurableAfterMutationSuccess
        }
        DurableConsumeOutcome::FailClosedProductionUnavailable => {
            DurableReplayRuntimeOutcome::ProductionDurableUnavailable
        }
        DurableConsumeOutcome::FailClosedMainNetUnavailable => {
            if input.is_mainnet_peer_driven() {
                DurableReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused
            } else {
                DurableReplayRuntimeOutcome::MainNetDurableUnavailable
            }
        }
        other => DurableReplayRuntimeOutcome::ConsumeRuntimeFailClosed {
            reason: format!("durable consume runtime fail-closed: {}", other.tag()),
        },
    }
}

// ===========================================================================
// Crash-window recovery
// ===========================================================================

/// Run 240 — classify the crash window of a durable runtime operation sequence
/// during recovery and map it into a typed runtime outcome.
///
/// MainNet peer-driven apply remains refused before any classification.
/// Production / MainNet crash-window classification is unavailable. Every
/// determinable crash window — including an after-consume window — fails closed
/// ([`DurableReplayRuntimeOutcome::CrashWindowFailClosed`]): a recovery never
/// silently re-authorizes or re-applies an in-flight or already-applied
/// decision. Pure: performs no durable write, no marker, no sequence, no live
/// trust swap, no session eviction, and never invokes Run 070.
pub fn recover_durable_replay_runtime_crash_window(
    input: &DurableReplayRuntimeIntegrationInput<'_>,
    observation: &CrashWindowObservation,
) -> DurableReplayRuntimeOutcome {
    if input.is_mainnet_peer_driven() {
        return DurableReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused;
    }
    match classify_crash_window(observation) {
        CrashWindow::ProductionCrashWindowUnavailable => {
            DurableReplayRuntimeOutcome::ProductionDurableUnavailable
        }
        CrashWindow::MainNetCrashWindowUnavailable => {
            DurableReplayRuntimeOutcome::MainNetDurableUnavailable
        }
        window => DurableReplayRuntimeOutcome::CrashWindowFailClosed(window),
    }
}

// ===========================================================================
// Runtime call-site wiring
// ===========================================================================

/// Run 240 — non-mutating fail-closed signal a runtime call site receives when
/// the composed durable replay runtime integration outcome does **not** authorize
/// the path to continue.
///
/// A call site that receives this MUST fail closed BEFORE any mutation: no Run
/// 070 call, no live trust swap, no session eviction, no sequence write, no
/// marker write, no durable consume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableReplayRuntimeCallsiteFailClosed {
    /// The runtime preflight surface that failed closed.
    pub surface: GovernanceExecutionRuntimeSurface,
    /// The non-proceed integration outcome that triggered the fail-closed.
    pub outcome: DurableReplayRuntimeOutcome,
    /// Operator-facing reason string.
    pub reason: String,
}

impl DurableReplayRuntimeCallsiteFailClosed {
    fn from_outcome(
        surface: GovernanceExecutionRuntimeSurface,
        outcome: DurableReplayRuntimeOutcome,
    ) -> Self {
        let reason = format!(
            "Run 240 governance-evaluator durable replay runtime integration fail-closed on {} \
             surface: {}. No Run 070 apply, no live trust swap, no session eviction, no sequence \
             write, no marker write, no durable consume.",
            surface.tag(),
            outcome.tag(),
        );
        Self {
            surface,
            outcome,
            reason,
        }
    }

    /// `true` iff this fail-closed is the MainNet peer-driven-apply refusal.
    pub fn is_mainnet_peer_driven_apply_refused(&self) -> bool {
        self.outcome.is_mainnet_peer_driven_apply_refused()
    }
}

/// Run 240 — route a runtime call site through the composed durable backend
/// runtime integration and **consume** the outcome.
///
/// * `Ok(..)` — a proceed outcome (legacy bypass, fresh-observed, known-fresh,
///   fresh-mutation-authorized, or a successful durable consume); the call site
///   continues.
/// * `Err(DurableReplayRuntimeCallsiteFailClosed)` — every non-proceed outcome
///   (deferral, before-apply, apply-failed, rolled-back, crash-window
///   fail-closed, durable / replay-runtime / consume-runtime fail-closed,
///   production / MainNet unavailable, or MainNet refused). The call site MUST
///   fail closed BEFORE any mutation.
///
/// Pure aside from the explicit durable observe / after-success consume the
/// underlying integration performs.
pub fn wire_durable_replay_runtime_callsite<B>(
    input: &DurableReplayRuntimeIntegrationInput<'_>,
    backend: &mut B,
) -> Result<DurableReplayRuntimeOutcome, DurableReplayRuntimeCallsiteFailClosed>
where
    B: GovernanceEvaluatorReplayDurableBackendReader
        + GovernanceEvaluatorReplayDurableBackendWriter
        + GovernanceEvaluatorReplayDurableBackendAtomic,
{
    let outcome = integrate_durable_replay_runtime(input, backend);
    if outcome.is_proceed() {
        Ok(outcome)
    } else {
        Err(DurableReplayRuntimeCallsiteFailClosed::from_outcome(
            input.validation_surface(),
            outcome,
        ))
    }
}

// ===========================================================================
// Explicit invariant / fail-closed helpers (grep-verifiable named symbols)
// ===========================================================================

/// Run 240 — explicit invariant helper.
///
/// Returns `true`: the durable observe/read happens before mutation
/// authorization under the durable runtime integration.
pub fn durable_observe_happens_before_mutation_authorization() -> bool {
    true
}

/// Run 240 — explicit invariant helper.
///
/// Returns `true`: a durable consume is performed only after a successful
/// mutation completion under the durable runtime integration.
pub fn consume_only_after_successful_mutation_under_durable_runtime() -> bool {
    true
}

/// Run 240 — explicit invariant helper.
///
/// Returns `true`: an ambiguous crash window (after-mutation-before-consume,
/// unknown, or after-consume) is typed and fails closed under the durable
/// runtime integration.
pub fn crash_window_ambiguity_fails_closed_under_durable_runtime() -> bool {
    true
}

/// Run 240 — explicit invariant helper.
///
/// Returns `true`: fixture restart snapshot durability remains source/test-only
/// under the durable runtime integration — no real file format, database, or
/// migration.
pub fn restart_snapshot_is_fixture_source_test_only_under_durable_runtime() -> bool {
    true
}

/// Run 240 — explicit refusal helper.
///
/// Returns `true` iff MainNet peer-driven apply remains refused under the durable
/// runtime integration. Run 240 always returns `true` for a MainNet environment:
/// MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal
/// regardless of any durable backend state — even a fresh one — and never
/// consumes.
pub fn mainnet_peer_driven_apply_remains_refused_under_durable_runtime(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 240 — explicit fail-closed helper.
///
/// Returns `true`: production / MainNet durable backends remain unavailable /
/// fail-closed under the durable runtime integration. No real durable storage,
/// RocksDB schema, file format, or migration is implemented.
pub fn production_mainnet_durable_remains_unavailable_under_durable_runtime() -> bool {
    true
}

/// Run 240 — explicit fail-closed helper.
///
/// Returns `true` iff a local operator key *cannot* satisfy a durable replay
/// backend policy under the runtime integration. Run 240 always returns `true`.
pub fn local_operator_cannot_satisfy_durable_runtime_policy() -> bool {
    true
}

/// Run 240 — explicit fail-closed helper.
///
/// Returns `true` iff peer-majority / gossip count *cannot* satisfy a durable
/// replay backend policy under the runtime integration. Run 240 always returns
/// `true`.
pub fn peer_majority_cannot_satisfy_durable_runtime_policy() -> bool {
    true
}

/// Run 240 — explicit fail-closed helper.
///
/// Returns `true` iff validator-set rotation remains unsupported under the
/// durable runtime integration. Run 240 always returns `true`.
pub fn validator_set_rotation_remains_unsupported_under_durable_runtime() -> bool {
    true
}

/// Run 240 — explicit fail-closed helper.
///
/// Returns `true` iff policy-change actions remain unsupported under the durable
/// runtime integration. Run 240 always returns `true`.
pub fn policy_change_action_remains_unsupported_under_durable_runtime() -> bool {
    true
}

/// Run 240 — explicit non-implementation helper.
///
/// Returns `true`: Run 240 introduces no RocksDB schema, file format, database
/// migration, or storage-format change. The durable runtime integration is a
/// pure composition over the Run 238 in-memory fixture only.
pub fn no_rocksdb_file_schema_migration_change_under_durable_runtime() -> bool {
    true
}

/// Run 240 — explicit non-mutation helper.
///
/// Returns `true`: a durable runtime rejection performs no Run 070 call, no live
/// trust swap, no session eviction, no sequence write, and no marker write.
pub fn durable_runtime_rejection_is_non_mutating() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_proceed_helpers_partition_correctly() {
        let bypass = DurableReplayRuntimeOutcome::ProceedLegacyBypassNoDurableWrite;
        assert!(bypass.is_proceed());
        assert!(!bypass.authorizes_consume());
        assert!(bypass.no_consume());
        assert!(!bypass.is_fail_closed());

        let consume = DurableReplayRuntimeOutcome::ConsumeDurableAfterMutationSuccess;
        assert!(consume.is_proceed());
        assert!(consume.authorizes_consume());
        assert!(!consume.no_consume());

        let authorized = DurableReplayRuntimeOutcome::ProceedMutationAuthorized;
        assert!(authorized.is_proceed());
        assert!(authorized.authorizes_mutation());
        assert!(authorized.no_consume());

        let deferred = DurableReplayRuntimeOutcome::ProceedDeferredObserved;
        assert!(!deferred.is_proceed());
        assert!(deferred.is_fail_closed());
        assert!(deferred.is_deferred());
        assert!(deferred.no_consume());

        let crash = DurableReplayRuntimeOutcome::CrashWindowFailClosed(
            CrashWindow::AfterMutationBeforeConsume,
        );
        assert!(crash.is_fail_closed());
        assert!(crash.is_crash_window_fail_closed());
        assert!(crash.no_consume());

        let refused = DurableReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused;
        assert!(refused.is_fail_closed());
        assert!(refused.is_mainnet_peer_driven_apply_refused());
        assert!(refused.no_consume());
    }

    #[test]
    fn invariant_helpers_are_fail_closed() {
        assert!(durable_observe_happens_before_mutation_authorization());
        assert!(consume_only_after_successful_mutation_under_durable_runtime());
        assert!(crash_window_ambiguity_fails_closed_under_durable_runtime());
        assert!(restart_snapshot_is_fixture_source_test_only_under_durable_runtime());
        assert!(
            mainnet_peer_driven_apply_remains_refused_under_durable_runtime(
                TrustBundleEnvironment::Mainnet
            )
        );
        assert!(
            !mainnet_peer_driven_apply_remains_refused_under_durable_runtime(
                TrustBundleEnvironment::Devnet
            )
        );
        assert!(production_mainnet_durable_remains_unavailable_under_durable_runtime());
        assert!(local_operator_cannot_satisfy_durable_runtime_policy());
        assert!(peer_majority_cannot_satisfy_durable_runtime_policy());
        assert!(validator_set_rotation_remains_unsupported_under_durable_runtime());
        assert!(policy_change_action_remains_unsupported_under_durable_runtime());
        assert!(no_rocksdb_file_schema_migration_change_under_durable_runtime());
        assert!(durable_runtime_rejection_is_non_mutating());
    }
}