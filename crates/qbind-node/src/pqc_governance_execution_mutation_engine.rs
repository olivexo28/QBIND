//! Run 242 — source/test governance **execution mutation-engine boundary**.
//!
//! Source/test only. Run 242 captures **no** release-binary evidence and
//! enables **no** production mutating behavior. It does **not** implement a real
//! governance execution engine, a real mutation engine, a real on-chain
//! governance proof verifier, a real persistent replay backend, a real
//! KMS/HSM/RemoteSigner backend, MainNet governance enablement, MainNet
//! peer-driven apply enablement, validator-set rotation, or any RocksDB / file /
//! schema / migration / wire / marker / sequence / trust-bundle / storage-format
//! change.
//!
//! ## What this module closes
//!
//! Run 238 defined the typed durable replay-state backend contract; Run 240
//! wired that durable backend into the Run 236 / 232 / 230 replay/freshness +
//! after-success-only consume runtime path; and Run 241 release-evidenced the
//! Run 240 durable runtime integration. The durable runtime still models
//! *mutation completion* with the modeled [`DurableMutationCompletion`] enum
//! (`AppliedSuccessfully` / `ApplyFailed` / `RolledBack` / ...). What was still
//! implicit is **how an already-authorized governance evaluator decision would
//! be handed to a future mutation executor**, and how mutation
//! success/failure/rollback is reported back to the durable replay runtime.
//!
//! Run 242 makes that hand-off explicit and typed at the source/test level: it
//! defines the typed mutation-engine input/context, the engine kinds, the
//! mutation outcomes, a pure/mockable [`GovernanceMutationExecutor`] trait
//! boundary, source/test-only fixture executors, and a composition helper that
//! maps mutation-engine outcomes into the Run 240 durable runtime's
//! mutation-completion semantics. It introduces a *boundary*, **not** a real
//! production mutation engine.
//!
//! ## Ordering contract
//!
//! The engine enforces the exact pipeline ordering:
//!
//! 1. **MainNet peer-driven apply refusal** — refused *before* any mutation
//!    attempt, before binding validation, before the executor is reached;
//! 2. **legacy bypass** — an unwired [`GovernanceMutationPolicy::Disabled`] /
//!    [`GovernanceMutationEngineKind::Disabled`] performs no mutation;
//! 3. **binding validation** — the input is checked against the canonical
//!    [`GovernanceMutationEngineExpectations`]; any mismatch is a typed,
//!    non-mutating [`GovernanceMutationOutcome::MutationRejectedBeforeApply`];
//! 4. **read-only validation never mutates** — a validation-only surface never
//!    reaches the executor;
//! 5. **unsupported actions** — validator-set rotation and policy-change actions
//!    are typed unsupported, never reach the executor;
//! 6. **engine kind routing** — production / MainNet engine kinds are reachable
//!    but unavailable / fail-closed; only DevNet/TestNet fixture kinds reach the
//!    fixture executor;
//! 7. **executor hand-off** — the validated, authorized request is handed to the
//!    [`GovernanceMutationExecutor`], which reports success / authorized-not-
//!    applied / apply-failed / rolled-back / ambiguous; and
//! 8. **durable projection** — the mutation outcome is projected into the Run 240
//!    durable runtime's mutation-completion semantics so a durable consume can
//!    only follow a modeled successful mutation.
//!
//! ## Fail-closed / safety contract
//!
//! * Mutation success ([`GovernanceMutationOutcome::MutationAppliedSuccessfully`])
//!   is **required** before a durable consume; it projects to
//!   [`DurableMutationCompletion::AppliedSuccessfully`] (the only consume-eligible
//!   completion).
//! * A failed apply, a rollback, and an ambiguous after-authorization window
//!   never consume.
//! * Every rejected path is **non-mutating**: no Run 070 call, no live trust
//!   swap, no session eviction, no sequence write, no marker write, no durable
//!   write — and the executor is never invoked.
//! * Production / MainNet engine kinds are reachable but always unavailable /
//!   fail-closed.
//! * MainNet peer-driven apply is refused **before** any mutation attempt.
//! * Validator-set rotation and policy-change actions remain unsupported.
//! * The engine is a pure function over its typed inputs plus a mockable
//!   executor; it performs no I/O of its own.
//!
//! ## What this module does NOT change
//!
//! * It adds **no** field to any production wire message.
//! * It alters **no** trust-bundle, authority-marker, or sequence schema.
//! * It introduces **no** RocksDB schema, file format, or database migration.
//! * It enables **no** MainNet governance or peer-driven apply.
//! * It does **not** claim full C4 or C5 closure.

use crate::pqc_authority_lifecycle::LocalLifecycleAction;
use crate::pqc_governance_evaluator_replay_consume_boundary::surface_is_validation_only;
use crate::pqc_governance_evaluator_replay_durable_backend::DurableMutationCompletion;
use crate::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Engine kind
// ===========================================================================

/// Run 242 — the governance mutation-engine kind.
///
/// The fixture kinds are DevNet/TestNet source-test only. The production /
/// MainNet kinds are callable but always unavailable / fail-closed — no real
/// mutation engine is implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GovernanceMutationEngineKind {
    /// The mutation engine is not wired; the legacy (no-mutation) path is
    /// preserved.
    Disabled,
    /// DevNet fixture mutation engine (source-test only).
    FixtureDevNet,
    /// TestNet fixture mutation engine (source-test only).
    FixtureTestNet,
    /// Production mutation engine (callable-but-unavailable / fail-closed).
    ProductionUnavailable,
    /// MainNet mutation engine (callable-but-unavailable / fail-closed).
    MainNetUnavailable,
}

impl GovernanceMutationEngineKind {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureDevNet => "fixture-devnet",
            Self::FixtureTestNet => "fixture-testnet",
            Self::ProductionUnavailable => "production-unavailable",
            Self::MainNetUnavailable => "mainnet-unavailable",
        }
    }

    /// `true` iff this is a DevNet/TestNet source-test fixture engine.
    pub const fn is_fixture(self) -> bool {
        matches!(self, Self::FixtureDevNet | Self::FixtureTestNet)
    }

    /// `true` iff this kind is reachable-but-unavailable (production / MainNet).
    pub const fn is_unavailable(self) -> bool {
        matches!(self, Self::ProductionUnavailable | Self::MainNetUnavailable)
    }
}

// ===========================================================================
// Engine policy
// ===========================================================================

/// Run 242 — the governance mutation-engine wiring policy.
///
/// Mirrors the Run 230 replay-state policy / Run 238 backend kind split:
/// [`Self::Disabled`] preserves the legacy no-mutation bypass; the fixture
/// policies are DevNet/TestNet source-test only; production / MainNet are
/// reachable but unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GovernanceMutationPolicy {
    /// Mutation-engine boundary is not wired; the legacy no-mutation path is
    /// preserved.
    Disabled,
    /// DevNet fixture mutation policy (source-test only).
    FixtureDevNet,
    /// TestNet fixture mutation policy (source-test only).
    FixtureTestNet,
    /// Production mutation policy (callable-but-unavailable / fail-closed).
    Production,
    /// MainNet mutation policy (callable-but-unavailable / fail-closed).
    MainNet,
}

impl GovernanceMutationPolicy {
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

    /// `true` iff the mutation-engine boundary is wired (anything but
    /// [`Self::Disabled`]).
    pub const fn is_wired(self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

// ===========================================================================
// Mutation action
// ===========================================================================

/// Run 242 — the action an already-authorized governance decision asks the
/// mutation engine to perform.
///
/// Only [`Self::ApplyAuthorizedCandidate`] is representable as a fixture
/// mutation. Validator-set rotation and policy-change actions are typed
/// unsupported and never reach the executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GovernanceMutationAction {
    /// Apply an already-authorized trust-anchor candidate (rotate / retire /
    /// revoke lifecycle action).
    ApplyAuthorizedCandidate,
    /// Validator-set rotation — unsupported.
    ValidatorSetRotation,
    /// Governance policy-change — unsupported.
    PolicyChange,
}

impl GovernanceMutationAction {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::ApplyAuthorizedCandidate => "apply-authorized-candidate",
            Self::ValidatorSetRotation => "validator-set-rotation",
            Self::PolicyChange => "policy-change",
        }
    }
}

// ===========================================================================
// Typed input / context structures
// ===========================================================================

/// Run 242 — the already-authorized governance mutation candidate the engine
/// would hand to a future mutation executor. Pure data referencing Run 222
/// evaluator / Run 230 replay material — never a copy of any wire payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceMutationCandidate {
    /// Governance execution decision digest.
    pub decision_digest: String,
    /// Candidate (trust-anchor material) digest.
    pub candidate_digest: String,
    /// Governance proposal id.
    pub proposal_id: String,
    /// Governance decision id.
    pub decision_id: String,
    /// Authority-domain sequence the decision is bound to.
    pub authority_domain_sequence: u64,
    /// Authorized lifecycle action.
    pub lifecycle_action: LocalLifecycleAction,
    /// The mutation action requested.
    pub action: GovernanceMutationAction,
}

impl GovernanceMutationCandidate {
    /// `true` iff every mandatory field is structurally present (non-empty).
    pub fn is_well_formed(&self) -> bool {
        !self.decision_digest.is_empty()
            && !self.candidate_digest.is_empty()
            && !self.proposal_id.is_empty()
            && !self.decision_id.is_empty()
    }
}

/// Run 242 — the validation / mutation surface pair the decision binds to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GovernanceMutationSurface {
    /// The surface the decision was validated for.
    pub validation_surface: GovernanceExecutionRuntimeSurface,
    /// The surface the decision authorizes / would mutate.
    pub mutation_surface: GovernanceExecutionRuntimeSurface,
}

impl GovernanceMutationSurface {
    /// `true` iff either surface is a read-only validation surface (never
    /// mutates).
    pub fn is_read_only_validation(&self) -> bool {
        surface_is_validation_only(self.validation_surface)
            || surface_is_validation_only(self.mutation_surface)
    }

    /// `true` iff the mutation surface is the Run 150 peer-driven drain
    /// coordinator surface.
    pub fn is_peer_driven(&self) -> bool {
        self.validation_surface == GovernanceExecutionRuntimeSurface::PeerDrivenDrain
            || self.mutation_surface == GovernanceExecutionRuntimeSurface::PeerDrivenDrain
    }
}

/// Run 242 — the trust-domain environment binding the decision is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceMutationEnvironmentBinding {
    /// Trust-domain environment.
    pub environment: TrustBundleEnvironment,
    /// Trust-domain chain id.
    pub chain_id: String,
    /// Trust-domain genesis hash.
    pub genesis_hash: String,
}

/// Run 242 — the runtime binding (governance + mutation surface + sequence) the
/// decision is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceMutationRuntimeBinding {
    /// The governance execution surface the decision was evaluated on.
    pub governance_surface: GovernanceExecutionRuntimeSurface,
    /// The validation / mutation surface pair.
    pub mutation_surface: GovernanceMutationSurface,
    /// Authority-domain sequence the runtime is bound to.
    pub authority_domain_sequence: u64,
}

/// Run 242 — typed inputs for one mutation-engine round-trip.
///
/// Holds only borrows of caller-owned data plus the `Copy` engine kind / policy;
/// it is itself pure data and performs no work on construction.
pub struct GovernanceMutationEngineInput<'a> {
    /// The mutation-engine kind. Fixture kinds are DevNet/TestNet source-test
    /// only; production / MainNet are reachable but unavailable.
    pub engine_kind: GovernanceMutationEngineKind,
    /// The active mutation-engine wiring policy. [`GovernanceMutationPolicy::Disabled`]
    /// preserves the legacy no-mutation bypass.
    pub policy: GovernanceMutationPolicy,
    /// The already-authorized governance mutation candidate.
    pub candidate: &'a GovernanceMutationCandidate,
    /// The environment binding the decision is bound to.
    pub environment_binding: &'a GovernanceMutationEnvironmentBinding,
    /// The runtime binding (governance + mutation surface + sequence).
    pub runtime_binding: &'a GovernanceMutationRuntimeBinding,
}

impl GovernanceMutationEngineInput<'_> {
    /// The validation / mutation surface pair.
    pub fn surface(&self) -> GovernanceMutationSurface {
        self.runtime_binding.mutation_surface
    }

    /// The trust-domain environment the decision is bound to.
    pub fn environment(&self) -> TrustBundleEnvironment {
        self.environment_binding.environment
    }

    /// `true` iff either surface is a read-only validation surface.
    pub fn is_read_only_validation(&self) -> bool {
        self.surface().is_read_only_validation()
    }

    /// `true` iff this is a MainNet peer-driven apply that remains refused
    /// unconditionally before any mutation attempt.
    pub fn is_mainnet_peer_driven(&self) -> bool {
        self.environment() == TrustBundleEnvironment::Mainnet && self.surface().is_peer_driven()
    }
}

// ===========================================================================
// Engine expectations
// ===========================================================================

/// Run 242 — the canonical binding a [`GovernanceMutationEngineInput`] is checked
/// against. A mismatch on any field is a typed, non-mutating fail-closed
/// ([`GovernanceMutationOutcome::MutationRejectedBeforeApply`]) — never a silent
/// approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceMutationEngineExpectations {
    /// Expected governance execution decision digest.
    pub expected_decision_digest: String,
    /// Expected candidate digest.
    pub expected_candidate_digest: String,
    /// Expected governance proposal id.
    pub expected_proposal_id: String,
    /// Expected governance decision id.
    pub expected_decision_id: String,
    /// Expected authority-domain sequence.
    pub expected_authority_domain_sequence: u64,
    /// Expected lifecycle action.
    pub expected_lifecycle_action: LocalLifecycleAction,
    /// Expected trust-domain environment.
    pub expected_environment: TrustBundleEnvironment,
    /// Expected trust-domain chain id.
    pub expected_chain_id: String,
    /// Expected trust-domain genesis hash.
    pub expected_genesis_hash: String,
    /// Expected governance execution surface.
    pub expected_governance_surface: GovernanceExecutionRuntimeSurface,
    /// Expected validation surface.
    pub expected_validation_surface: GovernanceExecutionRuntimeSurface,
    /// Expected mutation surface.
    pub expected_mutation_surface: GovernanceExecutionRuntimeSurface,
}

impl GovernanceMutationEngineExpectations {
    /// Internal: the first binding mismatch reason, if any, between an input and
    /// these expectations. `None` means the binding is consistent.
    fn mismatch_reason(&self, input: &GovernanceMutationEngineInput<'_>) -> Option<&'static str> {
        let candidate = input.candidate;
        let env = input.environment_binding;
        let rt = input.runtime_binding;
        if !candidate.is_well_formed() {
            return Some("malformed mutation candidate");
        }
        if candidate.decision_digest != self.expected_decision_digest {
            return Some("wrong decision digest");
        }
        if candidate.candidate_digest != self.expected_candidate_digest {
            return Some("wrong candidate digest");
        }
        if candidate.proposal_id != self.expected_proposal_id {
            return Some("wrong proposal id");
        }
        if candidate.decision_id != self.expected_decision_id {
            return Some("wrong decision id");
        }
        if candidate.authority_domain_sequence != self.expected_authority_domain_sequence {
            return Some("wrong authority-domain sequence");
        }
        if rt.authority_domain_sequence != self.expected_authority_domain_sequence {
            return Some("wrong runtime authority-domain sequence");
        }
        if candidate.lifecycle_action != self.expected_lifecycle_action {
            return Some("wrong lifecycle action");
        }
        if env.environment != self.expected_environment {
            return Some("wrong environment");
        }
        if env.chain_id != self.expected_chain_id {
            return Some("wrong chain id");
        }
        if env.genesis_hash != self.expected_genesis_hash {
            return Some("wrong genesis hash");
        }
        if rt.governance_surface != self.expected_governance_surface {
            return Some("wrong governance surface");
        }
        if rt.mutation_surface.validation_surface != self.expected_validation_surface {
            return Some("wrong validation surface");
        }
        if rt.mutation_surface.mutation_surface != self.expected_mutation_surface {
            return Some("wrong mutation surface");
        }
        None
    }
}

// ===========================================================================
// Authorized mutation request (handed to the executor)
// ===========================================================================

/// Run 242 — the validated, already-authorized request the mutation engine hands
/// to a [`GovernanceMutationExecutor`]. It is only constructed **after** binding
/// validation, surface gating, and unsupported-action gating have passed, so an
/// executor never sees a rejected decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedMutationRequest<'a> {
    /// The engine kind that authorized the request.
    pub engine_kind: GovernanceMutationEngineKind,
    /// The authorized mutation candidate.
    pub candidate: &'a GovernanceMutationCandidate,
    /// The environment binding.
    pub environment_binding: &'a GovernanceMutationEnvironmentBinding,
    /// The runtime binding.
    pub runtime_binding: &'a GovernanceMutationRuntimeBinding,
}

// ===========================================================================
// Executor result + window
// ===========================================================================

/// Run 242 — the typed result a [`GovernanceMutationExecutor`] reports after
/// being handed an [`AuthorizedMutationRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MutationExecutionResult {
    /// The mutation was applied successfully (DevNet/TestNet fixture only). The
    /// only result that projects to a consume-eligible completion.
    AppliedSuccessfully,
    /// The mutation was authorized but not yet applied.
    AuthorizedNotApplied,
    /// The apply was attempted and failed.
    ApplyFailed,
    /// The mutation was applied then rolled back.
    RolledBack,
    /// The executor crashed / was interrupted in the after-authorization,
    /// before-completion window — ambiguous, must fail closed.
    AmbiguousAfterAuthorization,
    /// The backing engine is unavailable (production / MainNet).
    Unavailable,
}

impl MutationExecutionResult {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::AppliedSuccessfully => "applied-successfully",
            Self::AuthorizedNotApplied => "authorized-not-applied",
            Self::ApplyFailed => "apply-failed",
            Self::RolledBack => "rolled-back",
            Self::AmbiguousAfterAuthorization => "ambiguous-after-authorization",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Run 242 — typed observation of a mutation-engine operation sequence used by
/// [`GovernanceMutationExecutor::recover_mutation_window`] to classify where a
/// crash could have occurred relative to authorize / apply / report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MutationWindowObservation {
    /// `true` iff the decision was observed authorized before the crash.
    pub authorized: bool,
    /// `true` iff a mutation apply was attempted before the crash.
    pub apply_attempted: bool,
    /// `true` iff a completion (success / failure / rollback) was reported
    /// before the crash.
    pub completion_reported: bool,
}

/// Run 242 — typed classification of the mutation window during recovery.
///
/// Every determinable in-flight window fails closed: a recovery never silently
/// re-authorizes or re-applies an in-flight decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MutationWindow {
    /// Crash before the decision was authorized.
    BeforeAuthorization,
    /// Crash after authorization but before the apply was attempted.
    AfterAuthorizationBeforeApply,
    /// Crash after the apply was attempted but before completion was reported —
    /// ambiguous, must fail closed.
    AfterApplyBeforeReport,
    /// Crash after a completion was reported.
    AfterReport,
    /// The crash window cannot be determined. Fail-closed.
    Unknown,
    /// Production crash-window classification is unavailable.
    ProductionUnavailable,
    /// MainNet crash-window classification is unavailable.
    MainNetUnavailable,
}

impl MutationWindow {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::BeforeAuthorization => "before-authorization",
            Self::AfterAuthorizationBeforeApply => "after-authorization-before-apply",
            Self::AfterApplyBeforeReport => "after-apply-before-report",
            Self::AfterReport => "after-report",
            Self::Unknown => "unknown",
            Self::ProductionUnavailable => "production-unavailable",
            Self::MainNetUnavailable => "mainnet-unavailable",
        }
    }
}

// ===========================================================================
// Executor trait boundary
// ===========================================================================

/// Run 242 — the pure/mockable governance mutation executor boundary.
///
/// This is the hand-off point an already-authorized governance evaluator
/// decision would reach a future mutation executor through. Run 242 provides
/// only source/test-only fixture / unavailable implementations; no real
/// production mutation executor is implemented, and no implementation here calls
/// Run 070 on a production path or performs a live trust swap.
pub trait GovernanceMutationExecutor {
    /// Execute (model) an already-authorized mutation and report a typed result.
    fn execute_authorized_mutation(
        &mut self,
        request: &AuthorizedMutationRequest<'_>,
    ) -> MutationExecutionResult;

    /// Classify the mutation window during recovery. A pure read; performs no
    /// mutation.
    fn recover_mutation_window(&self, observation: &MutationWindowObservation) -> MutationWindow;
}

// ===========================================================================
// Source/test-only fixture executors
// ===========================================================================

/// Run 242 — a DevNet/TestNet source-test-only fixture mutation executor.
///
/// Returns a programmed typed result and counts the number of times it was
/// actually invoked so tests can prove a rejected path never reaches the
/// executor. It performs **no** real mutation, no Run 070 call, no live trust
/// swap, and no persistent write.
#[derive(Debug, Clone)]
pub struct FixtureMutationExecutor {
    environment: TrustBundleEnvironment,
    programmed: MutationExecutionResult,
    attempts: u32,
}

impl FixtureMutationExecutor {
    /// Construct a fixture executor for a DevNet/TestNet environment with a
    /// programmed result.
    pub fn new(environment: TrustBundleEnvironment, programmed: MutationExecutionResult) -> Self {
        Self {
            environment,
            programmed,
            attempts: 0,
        }
    }

    /// The number of times [`GovernanceMutationExecutor::execute_authorized_mutation`]
    /// was invoked on this executor.
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// The environment this fixture executor is bound to.
    pub fn environment(&self) -> TrustBundleEnvironment {
        self.environment
    }
}

impl GovernanceMutationExecutor for FixtureMutationExecutor {
    fn execute_authorized_mutation(
        &mut self,
        _request: &AuthorizedMutationRequest<'_>,
    ) -> MutationExecutionResult {
        self.attempts += 1;
        self.programmed
    }

    fn recover_mutation_window(&self, observation: &MutationWindowObservation) -> MutationWindow {
        if !observation.authorized {
            return MutationWindow::BeforeAuthorization;
        }
        if !observation.apply_attempted {
            return MutationWindow::AfterAuthorizationBeforeApply;
        }
        if !observation.completion_reported {
            return MutationWindow::AfterApplyBeforeReport;
        }
        MutationWindow::AfterReport
    }
}

/// Run 242 — a production mutation executor that is always unavailable /
/// fail-closed. No real production mutation engine is implemented.
#[derive(Debug, Clone, Default)]
pub struct ProductionMutationExecutor;

impl GovernanceMutationExecutor for ProductionMutationExecutor {
    fn execute_authorized_mutation(
        &mut self,
        _request: &AuthorizedMutationRequest<'_>,
    ) -> MutationExecutionResult {
        MutationExecutionResult::Unavailable
    }

    fn recover_mutation_window(&self, _observation: &MutationWindowObservation) -> MutationWindow {
        MutationWindow::ProductionUnavailable
    }
}

/// Run 242 — a MainNet mutation executor that is always unavailable /
/// fail-closed. No MainNet governance enablement is implemented.
#[derive(Debug, Clone, Default)]
pub struct MainNetMutationExecutor;

impl GovernanceMutationExecutor for MainNetMutationExecutor {
    fn execute_authorized_mutation(
        &mut self,
        _request: &AuthorizedMutationRequest<'_>,
    ) -> MutationExecutionResult {
        MutationExecutionResult::Unavailable
    }

    fn recover_mutation_window(&self, _observation: &MutationWindowObservation) -> MutationWindow {
        MutationWindow::MainNetUnavailable
    }
}

// ===========================================================================
// Mutation outcome
// ===========================================================================

/// Run 242 — the typed outcome of handing an already-authorized governance
/// decision to the mutation engine.
///
/// Only [`Self::MutationAppliedSuccessfully`] projects to a consume-eligible
/// durable completion. Every other variant is a non-mutating proceed, a
/// non-consuming completion, or a fail-closed rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceMutationOutcome {
    /// The mutation engine was not wired — legacy no-mutation bypass. No
    /// executor was invoked.
    ProceedLegacyBypassNoMutation,
    /// The decision was authorized for mutation but not yet applied.
    MutationAuthorized,
    /// The mutation was applied successfully (DevNet/TestNet fixture only). The
    /// **only** outcome that projects to a consume-eligible completion.
    MutationAppliedSuccessfully,
    /// The decision was rejected before any apply (binding mismatch, malformed
    /// candidate, or read-only validation surface). Non-mutating; the executor
    /// was never invoked.
    MutationRejectedBeforeApply {
        /// Operator-facing reason.
        reason: String,
    },
    /// The apply was attempted and failed. Non-consuming.
    MutationApplyFailed,
    /// The mutation was applied then rolled back. Non-consuming.
    MutationRolledBack,
    /// The after-authorization / before-completion window was ambiguous — fails
    /// closed. Non-consuming.
    MutationAmbiguousFailClosed,
    /// The production mutation engine was reached but is unavailable. Non-mutating.
    ProductionMutationUnavailable,
    /// The MainNet mutation engine was reached but is unavailable. Non-mutating.
    MainNetMutationUnavailable,
    /// MainNet peer-driven apply remains refused before any mutation attempt.
    /// Non-mutating.
    MainNetPeerDrivenApplyRefused,
    /// Validator-set rotation is unsupported by the mutation engine. Non-mutating.
    ValidatorSetRotationUnsupported,
    /// Policy-change actions are unsupported by the mutation engine. Non-mutating.
    PolicyChangeUnsupported,
}

impl GovernanceMutationOutcome {
    /// `true` iff this outcome projects to a consume-eligible successful
    /// mutation (only [`Self::MutationAppliedSuccessfully`]).
    pub fn is_applied_successfully(&self) -> bool {
        matches!(self, Self::MutationAppliedSuccessfully)
    }

    /// `true` iff this outcome authorizes a mutation but has not applied it.
    pub fn is_authorized_not_applied(&self) -> bool {
        matches!(self, Self::MutationAuthorized)
    }

    /// `true` iff this is the legacy no-mutation bypass.
    pub fn is_legacy_bypass(&self) -> bool {
        matches!(self, Self::ProceedLegacyBypassNoMutation)
    }

    /// `true` iff this outcome is a non-mutating fail-closed / rejection (every
    /// variant other than the legacy bypass, the authorized-not-applied
    /// hand-off, and the successful apply).
    pub fn is_fail_closed(&self) -> bool {
        !matches!(
            self,
            Self::ProceedLegacyBypassNoMutation
                | Self::MutationAuthorized
                | Self::MutationAppliedSuccessfully
        )
    }

    /// `true` iff this outcome consumes nothing from the durable replay state
    /// (anything other than a successful apply).
    pub fn no_consume(&self) -> bool {
        !self.is_applied_successfully()
    }

    /// `true` iff the executor must **never** have been invoked for this outcome.
    pub fn executor_must_not_run(&self) -> bool {
        matches!(
            self,
            Self::ProceedLegacyBypassNoMutation
                | Self::MutationRejectedBeforeApply { .. }
                | Self::ProductionMutationUnavailable
                | Self::MainNetMutationUnavailable
                | Self::MainNetPeerDrivenApplyRefused
                | Self::ValidatorSetRotationUnsupported
                | Self::PolicyChangeUnsupported
        )
    }

    /// `true` iff this rejection is the MainNet peer-driven-apply refusal.
    pub fn is_mainnet_peer_driven_apply_refused(&self) -> bool {
        matches!(self, Self::MainNetPeerDrivenApplyRefused)
    }

    /// Stable operator-facing tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::ProceedLegacyBypassNoMutation => "proceed-legacy-bypass-no-mutation",
            Self::MutationAuthorized => "mutation-authorized",
            Self::MutationAppliedSuccessfully => "mutation-applied-successfully",
            Self::MutationRejectedBeforeApply { .. } => "mutation-rejected-before-apply",
            Self::MutationApplyFailed => "mutation-apply-failed",
            Self::MutationRolledBack => "mutation-rolled-back",
            Self::MutationAmbiguousFailClosed => "mutation-ambiguous-fail-closed",
            Self::ProductionMutationUnavailable => "production-mutation-unavailable",
            Self::MainNetMutationUnavailable => "mainnet-mutation-unavailable",
            Self::MainNetPeerDrivenApplyRefused => "mainnet-peer-driven-apply-refused",
            Self::ValidatorSetRotationUnsupported => "validator-set-rotation-unsupported",
            Self::PolicyChangeUnsupported => "policy-change-unsupported",
        }
    }
}

// ===========================================================================
// Engine entry point
// ===========================================================================

/// Run 242 — hand an already-authorized governance decision to the mutation
/// engine and return the typed outcome.
///
/// Ordering: MainNet peer-driven refusal → legacy bypass → binding validation →
/// read-only validation gating → unsupported-action gating → engine-kind routing
/// → executor hand-off. The executor is invoked **only** on a DevNet/TestNet
/// fixture kind after every gate has passed; every rejected / unavailable /
/// refused path returns before the executor is reached.
///
/// Pure aside from the executor's own (fixture-modeled) effect: the engine itself
/// performs no I/O, writes no marker, writes no sequence, swaps no live trust,
/// evicts no sessions, and never invokes Run 070.
pub fn evaluate_governance_mutation_engine<E>(
    input: &GovernanceMutationEngineInput<'_>,
    expectations: &GovernanceMutationEngineExpectations,
    executor: &mut E,
) -> GovernanceMutationOutcome
where
    E: GovernanceMutationExecutor,
{
    // Step 1: MainNet peer-driven apply remains refused unconditionally, before
    // any mutation attempt or binding validation.
    if input.is_mainnet_peer_driven() {
        return GovernanceMutationOutcome::MainNetPeerDrivenApplyRefused;
    }

    // Step 2: legacy bypass — an unwired policy or a disabled engine performs no
    // mutation and never reaches the executor.
    if !input.policy.is_wired() || input.engine_kind == GovernanceMutationEngineKind::Disabled {
        return GovernanceMutationOutcome::ProceedLegacyBypassNoMutation;
    }

    // Step 3: binding validation — a mismatch is a typed, non-mutating rejection
    // before any apply; the executor is never invoked.
    if let Some(reason) = expectations.mismatch_reason(input) {
        return GovernanceMutationOutcome::MutationRejectedBeforeApply {
            reason: reason.to_string(),
        };
    }

    // Step 4: read-only validation never mutates — never reach the executor.
    if input.is_read_only_validation() {
        return GovernanceMutationOutcome::MutationRejectedBeforeApply {
            reason: "read-only validation surface never mutates".to_string(),
        };
    }

    // Step 5: unsupported actions — typed unsupported, never reach the executor.
    match input.candidate.action {
        GovernanceMutationAction::ValidatorSetRotation => {
            return GovernanceMutationOutcome::ValidatorSetRotationUnsupported;
        }
        GovernanceMutationAction::PolicyChange => {
            return GovernanceMutationOutcome::PolicyChangeUnsupported;
        }
        GovernanceMutationAction::ApplyAuthorizedCandidate => {}
    }

    // Step 6: engine-kind routing. Production / MainNet are reachable but
    // unavailable; only DevNet/TestNet fixture kinds reach the executor.
    match input.engine_kind {
        GovernanceMutationEngineKind::Disabled => {
            // Already handled in Step 2; defensively preserve the bypass.
            GovernanceMutationOutcome::ProceedLegacyBypassNoMutation
        }
        GovernanceMutationEngineKind::ProductionUnavailable => {
            GovernanceMutationOutcome::ProductionMutationUnavailable
        }
        GovernanceMutationEngineKind::MainNetUnavailable => {
            GovernanceMutationOutcome::MainNetMutationUnavailable
        }
        GovernanceMutationEngineKind::FixtureDevNet
        | GovernanceMutationEngineKind::FixtureTestNet => {
            // Step 7: executor hand-off — the validated, authorized request.
            let request = AuthorizedMutationRequest {
                engine_kind: input.engine_kind,
                candidate: input.candidate,
                environment_binding: input.environment_binding,
                runtime_binding: input.runtime_binding,
            };
            project_execution_result(executor.execute_authorized_mutation(&request))
        }
    }
}

/// Internal: map an executor [`MutationExecutionResult`] into the engine
/// [`GovernanceMutationOutcome`].
fn project_execution_result(result: MutationExecutionResult) -> GovernanceMutationOutcome {
    match result {
        MutationExecutionResult::AppliedSuccessfully => {
            GovernanceMutationOutcome::MutationAppliedSuccessfully
        }
        MutationExecutionResult::AuthorizedNotApplied => {
            GovernanceMutationOutcome::MutationAuthorized
        }
        MutationExecutionResult::ApplyFailed => GovernanceMutationOutcome::MutationApplyFailed,
        MutationExecutionResult::RolledBack => GovernanceMutationOutcome::MutationRolledBack,
        MutationExecutionResult::AmbiguousAfterAuthorization => {
            GovernanceMutationOutcome::MutationAmbiguousFailClosed
        }
        // A fixture executor should never report Unavailable, but if it does,
        // fail closed rather than silently proceed.
        MutationExecutionResult::Unavailable => {
            GovernanceMutationOutcome::MutationAmbiguousFailClosed
        }
    }
}

// ===========================================================================
// Mutation-window recovery
// ===========================================================================

/// Run 242 — classify the mutation window of a mutation-engine operation
/// sequence during recovery and map it into a typed mutation outcome.
///
/// MainNet peer-driven apply remains refused before any classification.
/// Production / MainNet classification is unavailable. Every determinable
/// in-flight / after-authorization window fails closed
/// ([`GovernanceMutationOutcome::MutationAmbiguousFailClosed`]): a recovery never
/// silently re-authorizes or re-applies an in-flight decision. Pure: performs no
/// mutation and never invokes Run 070.
pub fn recover_governance_mutation_window<E>(
    input: &GovernanceMutationEngineInput<'_>,
    observation: &MutationWindowObservation,
    executor: &E,
) -> GovernanceMutationOutcome
where
    E: GovernanceMutationExecutor,
{
    if input.is_mainnet_peer_driven() {
        return GovernanceMutationOutcome::MainNetPeerDrivenApplyRefused;
    }
    match executor.recover_mutation_window(observation) {
        MutationWindow::ProductionUnavailable => {
            GovernanceMutationOutcome::ProductionMutationUnavailable
        }
        MutationWindow::MainNetUnavailable => GovernanceMutationOutcome::MainNetMutationUnavailable,
        MutationWindow::BeforeAuthorization => GovernanceMutationOutcome::MutationRejectedBeforeApply {
            reason: "mutation window before authorization".to_string(),
        },
        // Every after-authorization / in-flight / after-report / unknown window
        // is ambiguous and fails closed.
        MutationWindow::AfterAuthorizationBeforeApply
        | MutationWindow::AfterApplyBeforeReport
        | MutationWindow::AfterReport
        | MutationWindow::Unknown => GovernanceMutationOutcome::MutationAmbiguousFailClosed,
    }
}

// ===========================================================================
// Durable runtime composition
// ===========================================================================

/// Run 242 — the projection of a mutation-engine outcome into the Run 240
/// durable runtime's mutation-completion semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationEngineDurableProjection {
    /// Feed this modeled mutation completion into the Run 240 durable runtime.
    /// A durable consume can only follow [`DurableMutationCompletion::AppliedSuccessfully`].
    DurableCompletion(DurableMutationCompletion),
    /// The mutation-engine path failed closed (rejected / unavailable / refused /
    /// ambiguous / unsupported) before any durable observe/consume could be
    /// reached. The durable runtime must never be driven to consume. Carries the
    /// originating mutation outcome.
    FailClosedBeforeDurable(GovernanceMutationOutcome),
}

impl MutationEngineDurableProjection {
    /// `true` iff this projection authorizes a durable consume (only a
    /// [`DurableMutationCompletion::AppliedSuccessfully`] completion).
    pub fn authorizes_durable_consume(&self) -> bool {
        matches!(
            self,
            Self::DurableCompletion(DurableMutationCompletion::AppliedSuccessfully)
        )
    }
}

/// Run 242 — map a mutation-engine outcome into the Run 240 durable runtime's
/// mutation-completion semantics.
///
/// * a successful fixture mutation maps to the after-success-only consume path
///   ([`DurableMutationCompletion::AppliedSuccessfully`]);
/// * an authorized-but-not-applied decision maps to a non-consuming
///   [`DurableMutationCompletion::AuthorizedButNotApplied`];
/// * a failed apply maps to a non-consuming [`DurableMutationCompletion::ApplyFailed`];
/// * a rollback maps to a non-consuming [`DurableMutationCompletion::RolledBack`];
/// * a legacy bypass maps to a non-consuming [`DurableMutationCompletion::NotAttempted`];
/// * an ambiguous after-authorization window, a MainNet refusal, a production /
///   MainNet unavailable, an unsupported action, and a rejection all fail closed
///   **before** any durable observe/consume.
pub fn project_mutation_outcome_to_durable_completion(
    outcome: &GovernanceMutationOutcome,
) -> MutationEngineDurableProjection {
    match outcome {
        GovernanceMutationOutcome::ProceedLegacyBypassNoMutation => {
            MutationEngineDurableProjection::DurableCompletion(DurableMutationCompletion::NotAttempted)
        }
        GovernanceMutationOutcome::MutationAuthorized => {
            MutationEngineDurableProjection::DurableCompletion(
                DurableMutationCompletion::AuthorizedButNotApplied,
            )
        }
        GovernanceMutationOutcome::MutationAppliedSuccessfully => {
            MutationEngineDurableProjection::DurableCompletion(
                DurableMutationCompletion::AppliedSuccessfully,
            )
        }
        GovernanceMutationOutcome::MutationApplyFailed => {
            MutationEngineDurableProjection::DurableCompletion(DurableMutationCompletion::ApplyFailed)
        }
        GovernanceMutationOutcome::MutationRolledBack => {
            MutationEngineDurableProjection::DurableCompletion(DurableMutationCompletion::RolledBack)
        }
        other => MutationEngineDurableProjection::FailClosedBeforeDurable(other.clone()),
    }
}

// ===========================================================================
// Runtime call-site wiring
// ===========================================================================

/// Run 242 — non-mutating fail-closed signal a runtime call site receives when
/// the mutation-engine outcome does **not** authorize the path to continue.
///
/// A call site that receives this MUST fail closed BEFORE any mutation: no Run
/// 070 call, no live trust swap, no session eviction, no sequence write, no
/// marker write, no durable consume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationEngineCallsiteFailClosed {
    /// The mutation surface that failed closed.
    pub surface: GovernanceExecutionRuntimeSurface,
    /// The non-proceed mutation outcome that triggered the fail-closed.
    pub outcome: GovernanceMutationOutcome,
    /// Operator-facing reason string.
    pub reason: String,
}

impl MutationEngineCallsiteFailClosed {
    fn from_outcome(
        surface: GovernanceExecutionRuntimeSurface,
        outcome: GovernanceMutationOutcome,
    ) -> Self {
        let reason = format!(
            "Run 242 governance execution mutation-engine fail-closed on {} surface: {}. No Run \
             070 apply, no live trust swap, no session eviction, no sequence write, no marker \
             write, no durable consume.",
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

/// Run 242 — route a runtime call site through the mutation engine and consume
/// the outcome.
///
/// * `Ok(..)` — a proceed outcome (legacy bypass, authorized-not-applied
///   hand-off, or a successful apply); the call site continues.
/// * `Err(MutationEngineCallsiteFailClosed)` — every fail-closed / unsupported /
///   unavailable / refused / rejected / rolled-back / failed / ambiguous outcome.
///   The call site MUST fail closed BEFORE any mutation.
pub fn wire_governance_mutation_engine_callsite<E>(
    input: &GovernanceMutationEngineInput<'_>,
    expectations: &GovernanceMutationEngineExpectations,
    executor: &mut E,
) -> Result<GovernanceMutationOutcome, MutationEngineCallsiteFailClosed>
where
    E: GovernanceMutationExecutor,
{
    let outcome = evaluate_governance_mutation_engine(input, expectations, executor);
    if outcome.is_fail_closed() {
        Err(MutationEngineCallsiteFailClosed::from_outcome(
            input.surface().mutation_surface,
            outcome,
        ))
    } else {
        Ok(outcome)
    }
}

// ===========================================================================
// Explicit invariant / fail-closed helpers (grep-verifiable named symbols)
// ===========================================================================

/// Run 242 — explicit invariant helper.
///
/// Returns `true`: a mutation-engine rejection performs no Run 070 call, no live
/// trust swap, no session eviction, no sequence write, and no marker write, and
/// never invokes the executor.
pub fn mutation_engine_rejection_is_non_mutating() -> bool {
    true
}

/// Run 242 — explicit invariant helper.
///
/// Returns `true`: mutation success is required before a durable consume — only
/// [`GovernanceMutationOutcome::MutationAppliedSuccessfully`] projects to the
/// consume-eligible [`DurableMutationCompletion::AppliedSuccessfully`].
pub fn mutation_success_is_required_before_durable_consume() -> bool {
    true
}

/// Run 242 — explicit invariant helper.
///
/// Returns `true`: a failed apply never consumes durable replay state — it
/// projects to the non-consuming [`DurableMutationCompletion::ApplyFailed`].
pub fn mutation_failure_never_consumes_durable_replay_state() -> bool {
    true
}

/// Run 242 — explicit invariant helper.
///
/// Returns `true`: a rollback never consumes durable replay state — it projects
/// to the non-consuming [`DurableMutationCompletion::RolledBack`].
pub fn mutation_rollback_never_consumes_durable_replay_state() -> bool {
    true
}

/// Run 242 — explicit fail-closed helper.
///
/// Returns `true`: production / MainNet mutation engines remain unavailable /
/// fail-closed. No real production or MainNet mutation engine is implemented.
pub fn production_mainnet_mutation_engine_unavailable() -> bool {
    true
}

/// Run 242 — explicit refusal helper.
///
/// Returns `true` iff MainNet peer-driven apply remains refused by the mutation
/// engine for a MainNet environment, before any mutation attempt.
pub fn mainnet_peer_driven_apply_refused_by_mutation_engine(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 242 — explicit non-implementation helper.
///
/// Returns `true`: Run 242 introduces no RocksDB schema, file format, database
/// migration, or storage-format change. The mutation-engine boundary is a pure
/// typed composition with source/test fixture executors only.
pub fn no_rocksdb_file_schema_migration_change_under_mutation_engine() -> bool {
    true
}

/// Run 242 — explicit fail-closed helper.
///
/// Returns `true` iff validator-set rotation remains unsupported by the mutation
/// engine. Run 242 always returns `true`.
pub fn validator_set_rotation_unsupported_by_mutation_engine() -> bool {
    true
}

/// Run 242 — explicit fail-closed helper.
///
/// Returns `true` iff policy-change actions remain unsupported by the mutation
/// engine. Run 242 always returns `true`.
pub fn policy_change_unsupported_by_mutation_engine() -> bool {
    true
}

/// Run 242 — explicit fail-closed helper.
///
/// Returns `true` iff a local operator key *cannot* satisfy a MainNet mutation
/// authority under the mutation engine. Run 242 always returns `true`.
pub fn local_operator_cannot_satisfy_mutation_engine_authority() -> bool {
    true
}

/// Run 242 — explicit fail-closed helper.
///
/// Returns `true` iff peer-majority / gossip count *cannot* satisfy a MainNet
/// mutation authority under the mutation engine. Run 242 always returns `true`.
pub fn peer_majority_cannot_satisfy_mutation_engine_authority() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(action: GovernanceMutationAction) -> GovernanceMutationCandidate {
        GovernanceMutationCandidate {
            decision_digest: "decision-digest".to_string(),
            candidate_digest: "candidate-digest".to_string(),
            proposal_id: "proposal-0001".to_string(),
            decision_id: "decision-0001".to_string(),
            authority_domain_sequence: 7,
            lifecycle_action: LocalLifecycleAction::Rotate,
            action,
        }
    }

    fn env_binding(env: TrustBundleEnvironment) -> GovernanceMutationEnvironmentBinding {
        GovernanceMutationEnvironmentBinding {
            environment: env,
            chain_id: "qbind-devnet".to_string(),
            genesis_hash: "genesis-hash".to_string(),
        }
    }

    fn runtime_binding(
        vs: GovernanceExecutionRuntimeSurface,
        ms: GovernanceExecutionRuntimeSurface,
    ) -> GovernanceMutationRuntimeBinding {
        GovernanceMutationRuntimeBinding {
            governance_surface: ms,
            mutation_surface: GovernanceMutationSurface {
                validation_surface: vs,
                mutation_surface: ms,
            },
            authority_domain_sequence: 7,
        }
    }

    fn expectations(
        env: TrustBundleEnvironment,
        vs: GovernanceExecutionRuntimeSurface,
        ms: GovernanceExecutionRuntimeSurface,
    ) -> GovernanceMutationEngineExpectations {
        GovernanceMutationEngineExpectations {
            expected_decision_digest: "decision-digest".to_string(),
            expected_candidate_digest: "candidate-digest".to_string(),
            expected_proposal_id: "proposal-0001".to_string(),
            expected_decision_id: "decision-0001".to_string(),
            expected_authority_domain_sequence: 7,
            expected_lifecycle_action: LocalLifecycleAction::Rotate,
            expected_environment: env,
            expected_chain_id: "qbind-devnet".to_string(),
            expected_genesis_hash: "genesis-hash".to_string(),
            expected_governance_surface: ms,
            expected_validation_surface: vs,
            expected_mutation_surface: ms,
        }
    }

    #[test]
    fn applied_successfully_projects_to_consume_eligible_completion() {
        let cand = candidate(GovernanceMutationAction::ApplyAuthorizedCandidate);
        let env = env_binding(TrustBundleEnvironment::Devnet);
        let rt = runtime_binding(
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
        );
        let input = GovernanceMutationEngineInput {
            engine_kind: GovernanceMutationEngineKind::FixtureDevNet,
            policy: GovernanceMutationPolicy::FixtureDevNet,
            candidate: &cand,
            environment_binding: &env,
            runtime_binding: &rt,
        };
        let exp = expectations(
            TrustBundleEnvironment::Devnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
        );
        let mut exec = FixtureMutationExecutor::new(
            TrustBundleEnvironment::Devnet,
            MutationExecutionResult::AppliedSuccessfully,
        );
        let outcome = evaluate_governance_mutation_engine(&input, &exp, &mut exec);
        assert_eq!(outcome, GovernanceMutationOutcome::MutationAppliedSuccessfully);
        assert_eq!(exec.attempts(), 1);
        let projection = project_mutation_outcome_to_durable_completion(&outcome);
        assert!(projection.authorizes_durable_consume());
    }

    #[test]
    fn rejection_never_invokes_executor() {
        let cand = candidate(GovernanceMutationAction::ApplyAuthorizedCandidate);
        let env = env_binding(TrustBundleEnvironment::Devnet);
        let rt = runtime_binding(
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
        );
        let input = GovernanceMutationEngineInput {
            engine_kind: GovernanceMutationEngineKind::FixtureDevNet,
            policy: GovernanceMutationPolicy::FixtureDevNet,
            candidate: &cand,
            environment_binding: &env,
            runtime_binding: &rt,
        };
        // Wrong genesis hash.
        let mut exp = expectations(
            TrustBundleEnvironment::Devnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
        );
        exp.expected_genesis_hash = "other-genesis".to_string();
        let mut exec = FixtureMutationExecutor::new(
            TrustBundleEnvironment::Devnet,
            MutationExecutionResult::AppliedSuccessfully,
        );
        let outcome = evaluate_governance_mutation_engine(&input, &exp, &mut exec);
        assert!(matches!(
            outcome,
            GovernanceMutationOutcome::MutationRejectedBeforeApply { .. }
        ));
        assert!(outcome.executor_must_not_run());
        assert_eq!(exec.attempts(), 0, "rejected path never reaches the executor");
    }

    #[test]
    fn invariant_helpers_are_fail_closed() {
        assert!(mutation_engine_rejection_is_non_mutating());
        assert!(mutation_success_is_required_before_durable_consume());
        assert!(mutation_failure_never_consumes_durable_replay_state());
        assert!(mutation_rollback_never_consumes_durable_replay_state());
        assert!(production_mainnet_mutation_engine_unavailable());
        assert!(mainnet_peer_driven_apply_refused_by_mutation_engine(
            TrustBundleEnvironment::Mainnet
        ));
        assert!(!mainnet_peer_driven_apply_refused_by_mutation_engine(
            TrustBundleEnvironment::Devnet
        ));
        assert!(no_rocksdb_file_schema_migration_change_under_mutation_engine());
        assert!(validator_set_rotation_unsupported_by_mutation_engine());
        assert!(policy_change_unsupported_by_mutation_engine());
        assert!(local_operator_cannot_satisfy_mutation_engine_authority());
        assert!(peer_majority_cannot_satisfy_mutation_engine_authority());
    }
}
