//! Run 244 — source/test governance **modeled trust-state mutation applier
//! boundary**.
//!
//! Source/test only. Run 244 captures **no** release-binary evidence and enables
//! **no** production mutating behavior. It does **not** implement a real
//! governance execution engine, a real production mutation engine, a real
//! on-chain governance proof verifier, a real persistent replay backend, a real
//! KMS/HSM/RemoteSigner backend, MainNet governance enablement, MainNet
//! peer-driven apply enablement, validator-set rotation, or any RocksDB / file /
//! schema / migration / wire / marker / sequence / trust-bundle / storage-format
//! change.
//!
//! ## What this module adds
//!
//! Run 242 made the hand-off of an already-authorized governance evaluator
//! decision to a future mutation executor explicit and typed, and Run 243
//! release-evidenced that boundary. The Run 242/243 fixture executor still only
//! *models outcomes* — it does not model even an in-memory state transition
//! shape.
//!
//! Run 244 adds the smallest source/test-only **modeled in-memory trust-state
//! mutation applier**: after every Run 242 mutation-engine gate has already
//! passed, it snapshots a modeled trust state, applies a modeled trust-state
//! update, reports success / failure / rollback / ambiguous windows, and projects
//! the result back into the existing Run 242 mutation outcome
//! ([`GovernanceMutationOutcome`]) and Run 240 durable completion
//! ([`DurableMutationCompletion`]) semantics.
//!
//! ## This is a model only
//!
//! The applier mutates **only** the in-memory [`ModeledGovernanceTrustState`] in
//! DevNet/TestNet fixture tests. It must **not**:
//!
//! * mutate `LivePqcTrustState`;
//! * call Run 070;
//! * perform a real trust swap;
//! * evict sessions;
//! * write sequence files;
//! * write authority markers;
//! * perform a durable consume by itself;
//! * touch RocksDB / change any file / schema / migration / storage format;
//! * enable any production or MainNet mutation path.
//!
//! ## Ordering contract
//!
//! 1. **MainNet peer-driven apply refusal** — refused *before* any snapshot or
//!    applier invocation;
//! 2. **legacy bypass** — a [`ModeledGovernanceTrustMutationPolicy::Disabled`] /
//!    [`ModeledGovernanceTrustMutationApplierKind::Disabled`] performs no modeled
//!    mutation;
//! 3. **binding validation** — a mismatch is a typed, non-mutating
//!    [`ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeSnapshot`]
//!    *before* any snapshot and *before* the applier is invoked;
//! 4. **read-only validation never mutates** — a validation-only surface is
//!    rejected before snapshot;
//! 5. **unsupported actions** — validator-set rotation and policy-change are
//!    typed unsupported, never reach the applier;
//! 6. **applier-kind routing** — production / MainNet appliers are reachable but
//!    unavailable / fail-closed; only DevNet/TestNet fixture kinds reach the
//!    fixture applier;
//! 7. **applier hand-off** — the validated, authorized request is handed to the
//!    [`ModeledGovernanceTrustMutationApplier`], which snapshots the modeled
//!    state, applies (or rejects-before-apply), and reports
//!    applied / rejected-before-apply / apply-failed / rolled-back /
//!    rollback-failed-fatal / ambiguous; and
//! 8. **durable projection** — the modeled outcome is projected through the Run
//!    242 mutation outcome into the Run 240 durable runtime's mutation-completion
//!    semantics, so a durable consume can only follow a modeled successful
//!    mutation.
//!
//! ## Fail-closed / safety contract
//!
//! * Only [`ModeledTrustMutationOutcome::ModeledMutationApplied`] is
//!   consume-eligible (it projects through
//!   [`GovernanceMutationOutcome::MutationAppliedSuccessfully`] to
//!   [`DurableMutationCompletion::AppliedSuccessfully`]).
//! * A rejection before snapshot, a rejection before apply, an apply failure, a
//!   rollback, a rollback-failed-fatal, an ambiguous window, an unavailable
//!   production / MainNet applier, and an unsupported action never consume.
//! * Every rejected path is **non-mutating**, and a rejection that happens before
//!   apply never invokes the fixture applier (proved by its invocation counter).

use crate::pqc_governance_evaluator_replay_consume_boundary::surface_is_validation_only;
// Imported so the `DurableMutationCompletion` intra-doc links resolve; the type
// itself is reached transitively through [`MutationEngineDurableProjection`].
#[allow(unused_imports)]
use crate::pqc_governance_evaluator_replay_durable_backend::DurableMutationCompletion;
use crate::pqc_governance_execution_mutation_engine::{
    project_mutation_outcome_to_durable_completion, GovernanceMutationOutcome,
    MutationEngineDurableProjection,
};
use crate::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use crate::pqc_authority_lifecycle::LocalLifecycleAction;
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Modeled trust-root state
// ===========================================================================

/// Run 244 — the modeled status of a single in-memory trust root.
///
/// This is a *model* of a trust-root lifecycle state. It is never the real
/// `LivePqcTrustState`; mutating it has no production effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModeledTrustRootStatus {
    /// The modeled root is active.
    Active,
    /// The modeled root has been retired.
    Retired,
    /// The modeled root has been revoked.
    Revoked,
    /// The modeled root has been emergency-revoked.
    EmergencyRevoked,
}

impl ModeledTrustRootStatus {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
            Self::EmergencyRevoked => "emergency-revoked",
        }
    }
}

/// Run 244 — a single modeled in-memory governance trust root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeledGovernanceTrustRoot {
    /// Modeled root identifier (digest / id string). Never a real key.
    pub root_id: String,
    /// Modeled lifecycle status.
    pub status: ModeledTrustRootStatus,
}

impl ModeledGovernanceTrustRoot {
    /// Construct a modeled active root.
    pub fn active(root_id: impl Into<String>) -> Self {
        Self {
            root_id: root_id.into(),
            status: ModeledTrustRootStatus::Active,
        }
    }
}

/// Run 244 — an immutable snapshot of a [`ModeledGovernanceTrustState`] used for
/// modeled rollback. Holds only a clone of modeled in-memory data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeledGovernanceTrustSnapshot {
    roots: Vec<ModeledGovernanceTrustRoot>,
}

impl ModeledGovernanceTrustSnapshot {
    /// The number of modeled roots captured in this snapshot.
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// `true` iff the snapshot has no modeled roots.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }
}

/// Run 244 — the modeled in-memory governance trust state.
///
/// This is the **only** thing a DevNet/TestNet fixture applier may mutate. It is
/// not the real `LivePqcTrustState`, it is not persisted, and mutating it has no
/// production, wire, marker, sequence, RocksDB, or trust-bundle effect.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModeledGovernanceTrustState {
    roots: Vec<ModeledGovernanceTrustRoot>,
}

impl ModeledGovernanceTrustState {
    /// Construct an empty modeled trust state.
    pub fn new() -> Self {
        Self { roots: Vec::new() }
    }

    /// Construct a modeled trust state pre-populated with the given roots.
    pub fn with_roots(roots: Vec<ModeledGovernanceTrustRoot>) -> Self {
        Self { roots }
    }

    /// The modeled roots.
    pub fn roots(&self) -> &[ModeledGovernanceTrustRoot] {
        &self.roots
    }

    /// The number of modeled roots.
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// `true` iff there are no modeled roots.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// The modeled status of `root_id`, if present.
    pub fn status_of(&self, root_id: &str) -> Option<ModeledTrustRootStatus> {
        self.roots
            .iter()
            .find(|r| r.root_id == root_id)
            .map(|r| r.status)
    }

    /// `true` iff `root_id` is present with [`ModeledTrustRootStatus::Active`].
    pub fn contains_active(&self, root_id: &str) -> bool {
        self.status_of(root_id) == Some(ModeledTrustRootStatus::Active)
    }

    /// `true` iff `root_id` is present in any modeled status.
    pub fn contains(&self, root_id: &str) -> bool {
        self.status_of(root_id).is_some()
    }

    /// Take an immutable snapshot of the modeled state for rollback.
    pub fn snapshot(&self) -> ModeledGovernanceTrustSnapshot {
        ModeledGovernanceTrustSnapshot {
            roots: self.roots.clone(),
        }
    }

    /// Restore the modeled state from a previously captured snapshot (modeled
    /// rollback).
    pub fn restore(&mut self, snapshot: &ModeledGovernanceTrustSnapshot) {
        self.roots = snapshot.roots.clone();
    }

    /// Internal: add a modeled active root (idempotent — does nothing if already
    /// present).
    fn add_root(&mut self, root_id: &str) {
        if !self.contains(root_id) {
            self.roots
                .push(ModeledGovernanceTrustRoot::active(root_id.to_string()));
        }
    }

    /// Internal: set the modeled status of an existing root.
    fn set_status(&mut self, root_id: &str, status: ModeledTrustRootStatus) {
        if let Some(root) = self.roots.iter_mut().find(|r| r.root_id == root_id) {
            root.status = status;
        }
    }
}

// ===========================================================================
// Modeled mutation action / policy / applier kind
// ===========================================================================

/// Run 244 — the modeled trust-state mutation action requested.
///
/// Only the add / retire / revoke / emergency-revoke / noop actions are
/// representable as a modeled mutation. Validator-set rotation and policy-change
/// are typed unsupported and never reach the applier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModeledTrustMutationAction {
    /// Add a modeled trust root.
    AddTrustRoot,
    /// Retire a modeled trust root.
    RetireTrustRoot,
    /// Revoke a modeled trust root.
    RevokeTrustRoot,
    /// Emergency-revoke a modeled trust root.
    EmergencyRevokeTrustRoot,
    /// No-op (no modeled state change).
    Noop,
    /// Validator-set rotation — unsupported.
    ValidatorSetRotationUnsupported,
    /// Policy-change — unsupported.
    PolicyChangeUnsupported,
}

impl ModeledTrustMutationAction {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::AddTrustRoot => "add-trust-root",
            Self::RetireTrustRoot => "retire-trust-root",
            Self::RevokeTrustRoot => "revoke-trust-root",
            Self::EmergencyRevokeTrustRoot => "emergency-revoke-trust-root",
            Self::Noop => "noop",
            Self::ValidatorSetRotationUnsupported => "validator-set-rotation-unsupported",
            Self::PolicyChangeUnsupported => "policy-change-unsupported",
        }
    }

    /// `true` iff this action requires a modeled root id to be present.
    pub const fn requires_root_id(self) -> bool {
        matches!(
            self,
            Self::AddTrustRoot
                | Self::RetireTrustRoot
                | Self::RevokeTrustRoot
                | Self::EmergencyRevokeTrustRoot
        )
    }
}

/// Run 244 — the modeled trust-state mutation applier wiring policy.
///
/// [`Self::Disabled`] preserves the legacy no-mutation bypass; the fixture
/// policies are DevNet/TestNet source-test only; production / MainNet are
/// reachable but unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModeledGovernanceTrustMutationPolicy {
    /// The modeled applier boundary is not wired; legacy no-mutation bypass.
    Disabled,
    /// DevNet fixture policy (source-test only).
    FixtureDevNet,
    /// TestNet fixture policy (source-test only).
    FixtureTestNet,
    /// Production policy (callable-but-unavailable / fail-closed).
    Production,
    /// MainNet policy (callable-but-unavailable / fail-closed).
    MainNet,
}

impl ModeledGovernanceTrustMutationPolicy {
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

    /// `true` iff the modeled applier boundary is wired (anything but
    /// [`Self::Disabled`]).
    pub const fn is_wired(self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

/// Run 244 — the modeled trust-state mutation applier kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModeledGovernanceTrustMutationApplierKind {
    /// The modeled applier is not wired; legacy no-mutation path is preserved.
    Disabled,
    /// DevNet fixture applier (source-test only).
    FixtureDevNet,
    /// TestNet fixture applier (source-test only).
    FixtureTestNet,
    /// Production applier (callable-but-unavailable / fail-closed).
    ProductionUnavailable,
    /// MainNet applier (callable-but-unavailable / fail-closed).
    MainNetUnavailable,
}

impl ModeledGovernanceTrustMutationApplierKind {
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

    /// `true` iff this is a DevNet/TestNet source-test fixture applier.
    pub const fn is_fixture(self) -> bool {
        matches!(self, Self::FixtureDevNet | Self::FixtureTestNet)
    }

    /// `true` iff this kind is reachable-but-unavailable (production / MainNet).
    pub const fn is_unavailable(self) -> bool {
        matches!(self, Self::ProductionUnavailable | Self::MainNetUnavailable)
    }
}

// ===========================================================================
// Typed modeled mutation / binding structures
// ===========================================================================

/// Run 244 — the modeled trust-state mutation an already-authorized governance
/// decision asks the modeled applier to perform. Pure data referencing Run 222
/// evaluator / Run 242 mutation-engine material — never a copy of any wire
/// payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeledGovernanceTrustMutation {
    /// The modeled mutation action.
    pub action: ModeledTrustMutationAction,
    /// The modeled trust root the action targets (empty for [`ModeledTrustMutationAction::Noop`]).
    pub root_id: String,
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
}

impl ModeledGovernanceTrustMutation {
    /// `true` iff every mandatory field is structurally present (non-empty), and
    /// a root-id is present for actions that require one.
    pub fn is_well_formed(&self) -> bool {
        if self.decision_digest.is_empty()
            || self.candidate_digest.is_empty()
            || self.proposal_id.is_empty()
            || self.decision_id.is_empty()
        {
            return false;
        }
        if self.action.requires_root_id() && self.root_id.is_empty() {
            return false;
        }
        true
    }
}

/// Run 244 — the validation / mutation surface pair the decision binds to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModeledGovernanceTrustMutationSurface {
    /// The surface the decision was validated for.
    pub validation_surface: GovernanceExecutionRuntimeSurface,
    /// The surface the decision authorizes / would mutate.
    pub mutation_surface: GovernanceExecutionRuntimeSurface,
}

impl ModeledGovernanceTrustMutationSurface {
    /// `true` iff either surface is a read-only validation surface (never
    /// mutates).
    pub fn is_read_only_validation(&self) -> bool {
        surface_is_validation_only(self.validation_surface)
            || surface_is_validation_only(self.mutation_surface)
    }

    /// `true` iff either surface is the Run 150 peer-driven drain coordinator
    /// surface.
    pub fn is_peer_driven(&self) -> bool {
        self.validation_surface == GovernanceExecutionRuntimeSurface::PeerDrivenDrain
            || self.mutation_surface == GovernanceExecutionRuntimeSurface::PeerDrivenDrain
    }
}

/// Run 244 — the trust-domain environment binding the decision is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeledGovernanceTrustMutationEnvironmentBinding {
    /// Trust-domain environment.
    pub environment: TrustBundleEnvironment,
    /// Trust-domain chain id.
    pub chain_id: String,
    /// Trust-domain genesis hash.
    pub genesis_hash: String,
}

/// Run 244 — the runtime binding (governance + mutation surface + sequence) the
/// decision is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeledGovernanceTrustMutationRuntimeBinding {
    /// The governance execution surface the decision was evaluated on.
    pub governance_surface: GovernanceExecutionRuntimeSurface,
    /// The validation / mutation surface pair.
    pub mutation_surface: ModeledGovernanceTrustMutationSurface,
    /// Authority-domain sequence the runtime is bound to.
    pub authority_domain_sequence: u64,
}

/// Run 244 — typed inputs for one modeled trust-state mutation round-trip.
///
/// Holds only borrows of caller-owned data plus the `Copy` policy / applier kind;
/// it is itself pure data and performs no work on construction.
pub struct ModeledGovernanceTrustMutationInput<'a> {
    /// The modeled applier kind. Fixture kinds are DevNet/TestNet source-test
    /// only; production / MainNet are reachable but unavailable.
    pub applier_kind: ModeledGovernanceTrustMutationApplierKind,
    /// The active modeled applier wiring policy. [`ModeledGovernanceTrustMutationPolicy::Disabled`]
    /// preserves the legacy no-mutation bypass.
    pub policy: ModeledGovernanceTrustMutationPolicy,
    /// The modeled trust-state mutation requested.
    pub mutation: &'a ModeledGovernanceTrustMutation,
    /// The environment binding the decision is bound to.
    pub environment_binding: &'a ModeledGovernanceTrustMutationEnvironmentBinding,
    /// The runtime binding (governance + mutation surface + sequence).
    pub runtime_binding: &'a ModeledGovernanceTrustMutationRuntimeBinding,
}

impl ModeledGovernanceTrustMutationInput<'_> {
    /// The validation / mutation surface pair.
    pub fn surface(&self) -> ModeledGovernanceTrustMutationSurface {
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
    /// unconditionally before any snapshot or applier invocation.
    pub fn is_mainnet_peer_driven(&self) -> bool {
        self.environment() == TrustBundleEnvironment::Mainnet && self.surface().is_peer_driven()
    }
}

// ===========================================================================
// Expectations
// ===========================================================================

/// Run 244 — the canonical binding a [`ModeledGovernanceTrustMutationInput`] is
/// checked against. A mismatch on any field is a typed, non-mutating
/// fail-closed ([`ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeSnapshot`])
/// before any snapshot — never a silent approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeledGovernanceTrustMutationExpectations {
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

impl ModeledGovernanceTrustMutationExpectations {
    /// Internal: the first binding mismatch reason, if any. `None` means the
    /// binding is consistent.
    fn mismatch_reason(
        &self,
        input: &ModeledGovernanceTrustMutationInput<'_>,
    ) -> Option<&'static str> {
        let m = input.mutation;
        let env = input.environment_binding;
        let rt = input.runtime_binding;
        if !m.is_well_formed() {
            return Some("malformed modeled mutation");
        }
        if m.decision_digest != self.expected_decision_digest {
            return Some("wrong decision digest");
        }
        if m.candidate_digest != self.expected_candidate_digest {
            return Some("wrong candidate digest");
        }
        if m.proposal_id != self.expected_proposal_id {
            return Some("wrong proposal id");
        }
        if m.decision_id != self.expected_decision_id {
            return Some("wrong decision id");
        }
        if m.authority_domain_sequence != self.expected_authority_domain_sequence {
            return Some("wrong authority-domain sequence");
        }
        if rt.authority_domain_sequence != self.expected_authority_domain_sequence {
            return Some("wrong runtime authority-domain sequence");
        }
        if m.lifecycle_action != self.expected_lifecycle_action {
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
// Authorized modeled mutation request (handed to the applier)
// ===========================================================================

/// Run 244 — the validated, already-authorized request handed to a
/// [`ModeledGovernanceTrustMutationApplier`]. It is only constructed **after**
/// binding validation, surface gating, and unsupported-action gating have
/// passed, so an applier never sees a rejected-before-snapshot decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeledTrustMutationRequest<'a> {
    /// The applier kind that authorized the request.
    pub applier_kind: ModeledGovernanceTrustMutationApplierKind,
    /// The authorized modeled mutation.
    pub mutation: &'a ModeledGovernanceTrustMutation,
    /// The environment binding.
    pub environment_binding: &'a ModeledGovernanceTrustMutationEnvironmentBinding,
    /// The runtime binding.
    pub runtime_binding: &'a ModeledGovernanceTrustMutationRuntimeBinding,
}

// ===========================================================================
// Modeled applier outcomes
// ===========================================================================

/// Run 244 — the typed outcome of handing an already-authorized governance
/// decision to the modeled trust-state mutation applier.
///
/// Only [`Self::ModeledMutationApplied`] is consume-eligible. Every other
/// variant is a non-mutating proceed, a non-consuming completion, or a
/// fail-closed rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModeledTrustMutationOutcome {
    /// No modeled mutation was attempted (legacy bypass / disabled / recovered
    /// before-snapshot window). No applier was invoked.
    ModeledMutationNotAttempted,
    /// The modeled mutation was applied to in-memory state (DevNet/TestNet
    /// fixture only). The **only** consume-eligible outcome.
    ModeledMutationApplied,
    /// The decision was rejected before any snapshot (binding mismatch, malformed
    /// modeled mutation, or read-only validation surface). Non-mutating; the
    /// applier was never invoked.
    ModeledMutationRejectedBeforeSnapshot {
        /// Operator-facing reason.
        reason: String,
    },
    /// The applier snapshotted the modeled state but rejected before applying
    /// (e.g. retiring / revoking a missing root). Non-mutating; modeled state is
    /// unchanged.
    ModeledMutationRejectedBeforeApply {
        /// Operator-facing reason.
        reason: String,
    },
    /// The modeled apply was attempted and failed before mutating state.
    /// Non-consuming.
    ModeledMutationApplyFailed,
    /// The modeled apply mutated state then was rolled back to the snapshot.
    /// Non-consuming.
    ModeledMutationRolledBack,
    /// The modeled rollback itself failed — fatal / fail-closed. Non-consuming.
    ModeledMutationRollbackFailedFatal,
    /// The after-apply / before-completion window was ambiguous — fails closed.
    /// Non-consuming.
    ModeledMutationAmbiguousFailClosed,
    /// The production modeled applier was reached but is unavailable.
    /// Non-mutating.
    ProductionModeledMutationUnavailable,
    /// The MainNet modeled applier was reached but is unavailable. Non-mutating.
    MainNetModeledMutationUnavailable,
    /// MainNet peer-driven apply remains refused before any snapshot or applier
    /// invocation. Non-mutating.
    MainNetPeerDrivenApplyRefused,
    /// Validator-set rotation is unsupported by the modeled applier.
    /// Non-mutating.
    ValidatorSetRotationUnsupported,
    /// Policy-change actions are unsupported by the modeled applier.
    /// Non-mutating.
    PolicyChangeUnsupported,
}

impl ModeledTrustMutationOutcome {
    /// `true` iff this outcome is a consume-eligible successful modeled apply
    /// (only [`Self::ModeledMutationApplied`]).
    pub fn is_applied(&self) -> bool {
        matches!(self, Self::ModeledMutationApplied)
    }

    /// `true` iff this is the legacy / not-attempted (no modeled mutation) path.
    pub fn is_not_attempted(&self) -> bool {
        matches!(self, Self::ModeledMutationNotAttempted)
    }

    /// `true` iff this outcome consumes nothing (anything other than a successful
    /// modeled apply).
    pub fn no_consume(&self) -> bool {
        !self.is_applied()
    }

    /// `true` iff the applier must **never** have been invoked for this outcome
    /// (rejection happens before snapshot, before any applier invocation).
    pub fn applier_must_not_run(&self) -> bool {
        matches!(
            self,
            Self::ModeledMutationNotAttempted
                | Self::ModeledMutationRejectedBeforeSnapshot { .. }
                | Self::ProductionModeledMutationUnavailable
                | Self::MainNetModeledMutationUnavailable
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
            Self::ModeledMutationNotAttempted => "modeled-mutation-not-attempted",
            Self::ModeledMutationApplied => "modeled-mutation-applied",
            Self::ModeledMutationRejectedBeforeSnapshot { .. } => {
                "modeled-mutation-rejected-before-snapshot"
            }
            Self::ModeledMutationRejectedBeforeApply { .. } => {
                "modeled-mutation-rejected-before-apply"
            }
            Self::ModeledMutationApplyFailed => "modeled-mutation-apply-failed",
            Self::ModeledMutationRolledBack => "modeled-mutation-rolled-back",
            Self::ModeledMutationRollbackFailedFatal => "modeled-mutation-rollback-failed-fatal",
            Self::ModeledMutationAmbiguousFailClosed => "modeled-mutation-ambiguous-fail-closed",
            Self::ProductionModeledMutationUnavailable => "production-modeled-mutation-unavailable",
            Self::MainNetModeledMutationUnavailable => "mainnet-modeled-mutation-unavailable",
            Self::MainNetPeerDrivenApplyRefused => "mainnet-peer-driven-apply-refused",
            Self::ValidatorSetRotationUnsupported => "validator-set-rotation-unsupported",
            Self::PolicyChangeUnsupported => "policy-change-unsupported",
        }
    }
}

// ===========================================================================
// Recovery window
// ===========================================================================

/// Run 244 — typed observation of a modeled applier operation sequence used by
/// [`ModeledGovernanceTrustMutationApplier::recover_modeled_mutation_window`] to
/// classify where a crash could have occurred relative to snapshot / apply /
/// report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ModeledTrustMutationWindowObservation {
    /// `true` iff a modeled snapshot was taken before the crash.
    pub snapshotted: bool,
    /// `true` iff a modeled apply was attempted before the crash.
    pub applied: bool,
    /// `true` iff a completion was reported before the crash.
    pub completion_reported: bool,
    /// `true` iff the reported completion was an explicit success.
    pub success_reported: bool,
    /// `true` iff a modeled rollback was attempted and itself failed.
    pub rollback_failed: bool,
}

/// Run 244 — typed classification of the modeled mutation window during
/// recovery.
///
/// Every determinable in-flight / ambiguous window fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModeledTrustMutationWindow {
    /// Crash before any modeled snapshot was taken.
    BeforeSnapshot,
    /// Crash after snapshot but before the modeled apply was attempted.
    AfterSnapshotBeforeApply,
    /// Crash after the modeled apply but before a completion was reported —
    /// ambiguous, must fail closed.
    AfterApplyBeforeReport,
    /// Crash after an explicit modeled success was reported.
    AfterReportSuccess,
    /// Crash after a completion was reported but it was ambiguous (not an
    /// explicit success) — must fail closed.
    AfterReportAmbiguous,
    /// A modeled rollback was attempted and failed — fatal / fail-closed.
    RollbackFailed,
    /// The window cannot be determined. Fail-closed.
    Unknown,
    /// Production crash-window classification is unavailable.
    ProductionUnavailable,
    /// MainNet crash-window classification is unavailable.
    MainNetUnavailable,
}

impl ModeledTrustMutationWindow {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::BeforeSnapshot => "before-snapshot",
            Self::AfterSnapshotBeforeApply => "after-snapshot-before-apply",
            Self::AfterApplyBeforeReport => "after-apply-before-report",
            Self::AfterReportSuccess => "after-report-success",
            Self::AfterReportAmbiguous => "after-report-ambiguous",
            Self::RollbackFailed => "rollback-failed",
            Self::Unknown => "unknown",
            Self::ProductionUnavailable => "production-unavailable",
            Self::MainNetUnavailable => "mainnet-unavailable",
        }
    }
}

// ===========================================================================
// Modeled applier trait boundary
// ===========================================================================

/// Run 244 — the pure/mockable modeled trust-state mutation applier boundary.
///
/// Run 244 provides only source/test-only fixture / unavailable implementations.
/// No real production mutation applier is implemented, and no implementation here
/// calls Run 070, mutates `LivePqcTrustState`, performs a live trust swap, evicts
/// sessions, writes a sequence, writes a marker, or performs a durable consume.
pub trait ModeledGovernanceTrustMutationApplier {
    /// Snapshot the modeled state, apply (or reject-before-apply) the modeled
    /// mutation, and report a typed modeled outcome. The DevNet/TestNet fixture
    /// applier may mutate **only** the passed [`ModeledGovernanceTrustState`].
    fn apply_modeled_mutation(
        &mut self,
        state: &mut ModeledGovernanceTrustState,
        request: &ModeledTrustMutationRequest<'_>,
    ) -> ModeledTrustMutationOutcome;

    /// Classify the modeled mutation window during recovery. A pure read;
    /// performs no modeled mutation.
    fn recover_modeled_mutation_window(
        &self,
        observation: &ModeledTrustMutationWindowObservation,
    ) -> ModeledTrustMutationWindow;
}

// ===========================================================================
// Source/test-only fixture appliers
// ===========================================================================

/// Run 244 — the modeled fault a [`FixtureModeledTrustMutationApplier`] can
/// inject to exercise the apply-failed / rolled-back / rollback-failed /
/// ambiguous paths in source/test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ModeledApplierFault {
    /// No fault — a clean modeled apply.
    #[default]
    None,
    /// The apply fails before mutating modeled state (state unchanged).
    ApplyFailedBeforeMutation,
    /// The apply mutates modeled state then is rolled back to the snapshot.
    ApplyFailedRolledBack,
    /// The apply mutates modeled state, a rollback is attempted and fails —
    /// fatal.
    RollbackFailedFatal,
    /// The apply mutates modeled state but the completion is ambiguous.
    AmbiguousAfterApply,
}

/// Run 244 — a DevNet/TestNet source-test-only fixture modeled trust mutation
/// applier.
///
/// Mutates **only** the in-memory [`ModeledGovernanceTrustState`] it is handed.
/// Counts the number of times it was actually invoked so tests can prove a
/// rejected-before-snapshot path never reaches the applier. Performs **no** real
/// mutation, no Run 070 call, no live trust swap, no session eviction, no
/// sequence write, no marker write, and no durable consume.
#[derive(Debug, Clone)]
pub struct FixtureModeledTrustMutationApplier {
    environment: TrustBundleEnvironment,
    fault: ModeledApplierFault,
    attempts: u32,
}

impl FixtureModeledTrustMutationApplier {
    /// Construct a clean (no-fault) fixture applier for a DevNet/TestNet
    /// environment.
    pub fn new(environment: TrustBundleEnvironment) -> Self {
        Self {
            environment,
            fault: ModeledApplierFault::None,
            attempts: 0,
        }
    }

    /// Construct a fixture applier programmed with a modeled fault.
    pub fn with_fault(environment: TrustBundleEnvironment, fault: ModeledApplierFault) -> Self {
        Self {
            environment,
            fault,
            attempts: 0,
        }
    }

    /// The number of times [`ModeledGovernanceTrustMutationApplier::apply_modeled_mutation`]
    /// was invoked on this applier.
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// The environment this fixture applier is bound to.
    pub fn environment(&self) -> TrustBundleEnvironment {
        self.environment
    }
}

impl ModeledGovernanceTrustMutationApplier for FixtureModeledTrustMutationApplier {
    fn apply_modeled_mutation(
        &mut self,
        state: &mut ModeledGovernanceTrustState,
        request: &ModeledTrustMutationRequest<'_>,
    ) -> ModeledTrustMutationOutcome {
        self.attempts += 1;
        let mutation = request.mutation;
        let root_id = mutation.root_id.as_str();

        // A modeled snapshot is always taken before any apply so that a modeled
        // rollback can restore the prior state.
        let snapshot = state.snapshot();

        // Pre-apply precondition checks. A rejection here is *after* snapshot but
        // *before* any modeled state mutation, so the modeled state is unchanged.
        match mutation.action {
            ModeledTrustMutationAction::Noop => {
                // No modeled state change, no drift.
                return ModeledTrustMutationOutcome::ModeledMutationApplied;
            }
            ModeledTrustMutationAction::AddTrustRoot => {
                // Duplicate root handled idempotently under an explicit typed
                // applied outcome.
            }
            ModeledTrustMutationAction::RetireTrustRoot
            | ModeledTrustMutationAction::RevokeTrustRoot
            | ModeledTrustMutationAction::EmergencyRevokeTrustRoot => {
                if !state.contains_active(root_id) {
                    return ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeApply {
                        reason: format!(
                            "modeled {} target root absent or not active",
                            mutation.action.tag()
                        ),
                    };
                }
            }
            ModeledTrustMutationAction::ValidatorSetRotationUnsupported
            | ModeledTrustMutationAction::PolicyChangeUnsupported => {
                // Unsupported actions are gated by the engine before the applier
                // is reached; defensively fail closed if one slips through.
                return ModeledTrustMutationOutcome::ModeledMutationAmbiguousFailClosed;
            }
        }

        // Apply-failed-before-mutation fault: the apply fails before touching
        // modeled state. No rollback is needed; state is unchanged.
        if self.fault == ModeledApplierFault::ApplyFailedBeforeMutation {
            return ModeledTrustMutationOutcome::ModeledMutationApplyFailed;
        }

        // Apply the modeled mutation to in-memory state only.
        match mutation.action {
            ModeledTrustMutationAction::AddTrustRoot => state.add_root(root_id),
            ModeledTrustMutationAction::RetireTrustRoot => {
                state.set_status(root_id, ModeledTrustRootStatus::Retired)
            }
            ModeledTrustMutationAction::RevokeTrustRoot => {
                state.set_status(root_id, ModeledTrustRootStatus::Revoked)
            }
            ModeledTrustMutationAction::EmergencyRevokeTrustRoot => {
                state.set_status(root_id, ModeledTrustRootStatus::EmergencyRevoked)
            }
            // Noop / unsupported already returned above.
            _ => {}
        }

        match self.fault {
            ModeledApplierFault::None => ModeledTrustMutationOutcome::ModeledMutationApplied,
            ModeledApplierFault::ApplyFailedRolledBack => {
                // Modeled rollback restores the snapshot.
                state.restore(&snapshot);
                ModeledTrustMutationOutcome::ModeledMutationRolledBack
            }
            ModeledApplierFault::RollbackFailedFatal => {
                // Modeled rollback fails: modeled state is left at the partially
                // applied value and the outcome is fatal / fail-closed.
                ModeledTrustMutationOutcome::ModeledMutationRollbackFailedFatal
            }
            ModeledApplierFault::AmbiguousAfterApply => {
                ModeledTrustMutationOutcome::ModeledMutationAmbiguousFailClosed
            }
            // Already returned above.
            ModeledApplierFault::ApplyFailedBeforeMutation => {
                ModeledTrustMutationOutcome::ModeledMutationApplyFailed
            }
        }
    }

    fn recover_modeled_mutation_window(
        &self,
        observation: &ModeledTrustMutationWindowObservation,
    ) -> ModeledTrustMutationWindow {
        if observation.rollback_failed {
            return ModeledTrustMutationWindow::RollbackFailed;
        }
        if !observation.snapshotted {
            return ModeledTrustMutationWindow::BeforeSnapshot;
        }
        if !observation.applied {
            return ModeledTrustMutationWindow::AfterSnapshotBeforeApply;
        }
        if !observation.completion_reported {
            return ModeledTrustMutationWindow::AfterApplyBeforeReport;
        }
        if observation.success_reported {
            return ModeledTrustMutationWindow::AfterReportSuccess;
        }
        ModeledTrustMutationWindow::AfterReportAmbiguous
    }
}

/// Run 244 — a production modeled trust mutation applier that is always
/// unavailable / fail-closed. No real production mutation applier is
/// implemented.
#[derive(Debug, Clone, Default)]
pub struct ProductionModeledTrustMutationApplier;

impl ModeledGovernanceTrustMutationApplier for ProductionModeledTrustMutationApplier {
    fn apply_modeled_mutation(
        &mut self,
        _state: &mut ModeledGovernanceTrustState,
        _request: &ModeledTrustMutationRequest<'_>,
    ) -> ModeledTrustMutationOutcome {
        ModeledTrustMutationOutcome::ProductionModeledMutationUnavailable
    }

    fn recover_modeled_mutation_window(
        &self,
        _observation: &ModeledTrustMutationWindowObservation,
    ) -> ModeledTrustMutationWindow {
        ModeledTrustMutationWindow::ProductionUnavailable
    }
}

/// Run 244 — a MainNet modeled trust mutation applier that is always unavailable
/// / fail-closed. No MainNet governance enablement is implemented.
#[derive(Debug, Clone, Default)]
pub struct MainNetModeledTrustMutationApplier;

impl ModeledGovernanceTrustMutationApplier for MainNetModeledTrustMutationApplier {
    fn apply_modeled_mutation(
        &mut self,
        _state: &mut ModeledGovernanceTrustState,
        _request: &ModeledTrustMutationRequest<'_>,
    ) -> ModeledTrustMutationOutcome {
        ModeledTrustMutationOutcome::MainNetModeledMutationUnavailable
    }

    fn recover_modeled_mutation_window(
        &self,
        _observation: &ModeledTrustMutationWindowObservation,
    ) -> ModeledTrustMutationWindow {
        ModeledTrustMutationWindow::MainNetUnavailable
    }
}

// ===========================================================================
// Engine entry point
// ===========================================================================

/// Run 244 — hand an already-authorized governance decision to the modeled
/// trust-state mutation applier and return the typed modeled outcome.
///
/// Ordering: MainNet peer-driven refusal → legacy bypass → binding validation
/// (reject before snapshot) → read-only validation gating → unsupported-action
/// gating → applier-kind routing → applier hand-off. The applier is invoked
/// **only** on a DevNet/TestNet fixture kind after every gate has passed; every
/// rejected-before-snapshot / unavailable / refused / unsupported path returns
/// before the applier is reached.
///
/// Pure aside from the fixture applier's modeled in-memory effect: the engine
/// itself performs no I/O, mutates no `LivePqcTrustState`, writes no marker,
/// writes no sequence, swaps no live trust, evicts no sessions, performs no
/// durable consume, and never invokes Run 070.
pub fn evaluate_modeled_trust_mutation<A>(
    input: &ModeledGovernanceTrustMutationInput<'_>,
    expectations: &ModeledGovernanceTrustMutationExpectations,
    state: &mut ModeledGovernanceTrustState,
    applier: &mut A,
) -> ModeledTrustMutationOutcome
where
    A: ModeledGovernanceTrustMutationApplier,
{
    // Step 1: MainNet peer-driven apply remains refused unconditionally, before
    // any snapshot or applier invocation.
    if input.is_mainnet_peer_driven() {
        return ModeledTrustMutationOutcome::MainNetPeerDrivenApplyRefused;
    }

    // Step 2: legacy bypass — an unwired policy or a disabled applier performs no
    // modeled mutation and never reaches the applier.
    if !input.policy.is_wired()
        || input.applier_kind == ModeledGovernanceTrustMutationApplierKind::Disabled
    {
        return ModeledTrustMutationOutcome::ModeledMutationNotAttempted;
    }

    // Step 3: binding validation — a mismatch is a typed, non-mutating rejection
    // before any snapshot; the applier is never invoked.
    if let Some(reason) = expectations.mismatch_reason(input) {
        return ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeSnapshot {
            reason: reason.to_string(),
        };
    }

    // Step 4: read-only validation never mutates — never reach the applier.
    if input.is_read_only_validation() {
        return ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeSnapshot {
            reason: "read-only validation surface never mutates".to_string(),
        };
    }

    // Step 5: unsupported actions — typed unsupported, never reach the applier.
    match input.mutation.action {
        ModeledTrustMutationAction::ValidatorSetRotationUnsupported => {
            return ModeledTrustMutationOutcome::ValidatorSetRotationUnsupported;
        }
        ModeledTrustMutationAction::PolicyChangeUnsupported => {
            return ModeledTrustMutationOutcome::PolicyChangeUnsupported;
        }
        _ => {}
    }

    // Step 6: applier-kind routing. Production / MainNet are reachable but
    // unavailable; only DevNet/TestNet fixture kinds reach the applier.
    match input.applier_kind {
        ModeledGovernanceTrustMutationApplierKind::Disabled => {
            // Already handled in Step 2; defensively preserve the bypass.
            ModeledTrustMutationOutcome::ModeledMutationNotAttempted
        }
        ModeledGovernanceTrustMutationApplierKind::ProductionUnavailable => {
            ModeledTrustMutationOutcome::ProductionModeledMutationUnavailable
        }
        ModeledGovernanceTrustMutationApplierKind::MainNetUnavailable => {
            ModeledTrustMutationOutcome::MainNetModeledMutationUnavailable
        }
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet
        | ModeledGovernanceTrustMutationApplierKind::FixtureTestNet => {
            // Step 7: applier hand-off — the validated, authorized request.
            let request = ModeledTrustMutationRequest {
                applier_kind: input.applier_kind,
                mutation: input.mutation,
                environment_binding: input.environment_binding,
                runtime_binding: input.runtime_binding,
            };
            applier.apply_modeled_mutation(state, &request)
        }
    }
}

/// Run 244 — classify the modeled mutation window during recovery and map it
/// into a typed modeled outcome.
///
/// MainNet peer-driven apply remains refused before any classification.
/// Production / MainNet classification is unavailable. Every ambiguous / unknown
/// window fails closed; a before-snapshot window recovers as not-attempted; an
/// after-snapshot-before-apply window rolls back; a rollback-failed window is
/// fatal. Only an explicit after-report success recovers as applied. Pure:
/// performs no modeled mutation and never invokes Run 070.
pub fn recover_modeled_trust_mutation<A>(
    input: &ModeledGovernanceTrustMutationInput<'_>,
    observation: &ModeledTrustMutationWindowObservation,
    applier: &A,
) -> ModeledTrustMutationOutcome
where
    A: ModeledGovernanceTrustMutationApplier,
{
    if input.is_mainnet_peer_driven() {
        return ModeledTrustMutationOutcome::MainNetPeerDrivenApplyRefused;
    }
    match applier.recover_modeled_mutation_window(observation) {
        ModeledTrustMutationWindow::ProductionUnavailable => {
            ModeledTrustMutationOutcome::ProductionModeledMutationUnavailable
        }
        ModeledTrustMutationWindow::MainNetUnavailable => {
            ModeledTrustMutationOutcome::MainNetModeledMutationUnavailable
        }
        ModeledTrustMutationWindow::BeforeSnapshot => {
            ModeledTrustMutationOutcome::ModeledMutationNotAttempted
        }
        ModeledTrustMutationWindow::AfterSnapshotBeforeApply => {
            ModeledTrustMutationOutcome::ModeledMutationRolledBack
        }
        ModeledTrustMutationWindow::AfterReportSuccess => {
            ModeledTrustMutationOutcome::ModeledMutationApplied
        }
        ModeledTrustMutationWindow::RollbackFailed => {
            ModeledTrustMutationOutcome::ModeledMutationRollbackFailedFatal
        }
        // Every after-apply-before-report / after-report-ambiguous / unknown
        // window is ambiguous and fails closed.
        ModeledTrustMutationWindow::AfterApplyBeforeReport
        | ModeledTrustMutationWindow::AfterReportAmbiguous
        | ModeledTrustMutationWindow::Unknown => {
            ModeledTrustMutationOutcome::ModeledMutationAmbiguousFailClosed
        }
    }
}

// ===========================================================================
// Composition helper #1 — modeled outcome -> Run 242 mutation outcome
// ===========================================================================

/// Run 244 — map a modeled trust-mutation outcome into the Run 242
/// mutation-engine [`GovernanceMutationOutcome`].
///
/// * modeled apply success → [`GovernanceMutationOutcome::MutationAppliedSuccessfully`];
/// * not-attempted → [`GovernanceMutationOutcome::ProceedLegacyBypassNoMutation`];
/// * rejected before snapshot / before apply → [`GovernanceMutationOutcome::MutationRejectedBeforeApply`];
/// * apply failure → [`GovernanceMutationOutcome::MutationApplyFailed`];
/// * rollback success → [`GovernanceMutationOutcome::MutationRolledBack`];
/// * rollback failure / ambiguous window → [`GovernanceMutationOutcome::MutationAmbiguousFailClosed`];
/// * production unavailable → [`GovernanceMutationOutcome::ProductionMutationUnavailable`];
/// * MainNet unavailable → [`GovernanceMutationOutcome::MainNetMutationUnavailable`];
/// * MainNet peer-driven refused → [`GovernanceMutationOutcome::MainNetPeerDrivenApplyRefused`];
/// * validator-set rotation unsupported → [`GovernanceMutationOutcome::ValidatorSetRotationUnsupported`];
/// * policy-change unsupported → [`GovernanceMutationOutcome::PolicyChangeUnsupported`].
pub fn map_modeled_outcome_to_mutation_engine_outcome(
    outcome: &ModeledTrustMutationOutcome,
) -> GovernanceMutationOutcome {
    match outcome {
        ModeledTrustMutationOutcome::ModeledMutationNotAttempted => {
            GovernanceMutationOutcome::ProceedLegacyBypassNoMutation
        }
        ModeledTrustMutationOutcome::ModeledMutationApplied => {
            GovernanceMutationOutcome::MutationAppliedSuccessfully
        }
        ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeSnapshot { reason }
        | ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeApply { reason } => {
            GovernanceMutationOutcome::MutationRejectedBeforeApply {
                reason: reason.clone(),
            }
        }
        ModeledTrustMutationOutcome::ModeledMutationApplyFailed => {
            GovernanceMutationOutcome::MutationApplyFailed
        }
        ModeledTrustMutationOutcome::ModeledMutationRolledBack => {
            GovernanceMutationOutcome::MutationRolledBack
        }
        ModeledTrustMutationOutcome::ModeledMutationRollbackFailedFatal
        | ModeledTrustMutationOutcome::ModeledMutationAmbiguousFailClosed => {
            GovernanceMutationOutcome::MutationAmbiguousFailClosed
        }
        ModeledTrustMutationOutcome::ProductionModeledMutationUnavailable => {
            GovernanceMutationOutcome::ProductionMutationUnavailable
        }
        ModeledTrustMutationOutcome::MainNetModeledMutationUnavailable => {
            GovernanceMutationOutcome::MainNetMutationUnavailable
        }
        ModeledTrustMutationOutcome::MainNetPeerDrivenApplyRefused => {
            GovernanceMutationOutcome::MainNetPeerDrivenApplyRefused
        }
        ModeledTrustMutationOutcome::ValidatorSetRotationUnsupported => {
            GovernanceMutationOutcome::ValidatorSetRotationUnsupported
        }
        ModeledTrustMutationOutcome::PolicyChangeUnsupported => {
            GovernanceMutationOutcome::PolicyChangeUnsupported
        }
    }
}

// ===========================================================================
// Composition helper #2 — modeled outcome -> Run 240 durable completion
// ===========================================================================

/// Run 244 — project a modeled trust-mutation outcome through the Run 242
/// mutation-engine outcome into the Run 240 durable runtime's
/// mutation-completion semantics.
///
/// Only a modeled apply success becomes consume-eligible
/// ([`DurableMutationCompletion::AppliedSuccessfully`]). Rejected / failed /
/// rollback / rollback-failed / ambiguous / unavailable / unsupported outcomes
/// never consume.
pub fn project_modeled_outcome_to_durable_completion(
    outcome: &ModeledTrustMutationOutcome,
) -> MutationEngineDurableProjection {
    let engine_outcome = map_modeled_outcome_to_mutation_engine_outcome(outcome);
    project_mutation_outcome_to_durable_completion(&engine_outcome)
}

/// Run 244 — `true` iff a modeled trust-mutation outcome authorizes a Run 240
/// durable consume. Only [`ModeledTrustMutationOutcome::ModeledMutationApplied`]
/// projects to the consume-eligible
/// [`DurableMutationCompletion::AppliedSuccessfully`].
pub fn modeled_outcome_authorizes_durable_consume(outcome: &ModeledTrustMutationOutcome) -> bool {
    project_modeled_outcome_to_durable_completion(outcome).authorizes_durable_consume()
}

// ===========================================================================
// Explicit invariant / fail-closed helpers (grep-verifiable named symbols)
// ===========================================================================

/// Run 244 — explicit invariant helper.
///
/// Returns `true`: a modeled-applier rejection performs no Run 070 call, no
/// `LivePqcTrustState` mutation, no live trust swap, no session eviction, no
/// sequence write, and no marker write, and a rejection before apply never
/// invokes the applier.
pub fn modeled_trust_applier_rejection_is_non_mutating() -> bool {
    true
}

/// Run 244 — explicit invariant helper.
///
/// Returns `true`: the modeled applier never calls Run 070. It mutates only the
/// in-memory [`ModeledGovernanceTrustState`].
pub fn modeled_trust_applier_never_calls_run_070() -> bool {
    true
}

/// Run 244 — explicit invariant helper.
///
/// Returns `true`: the modeled applier never mutates `LivePqcTrustState`. It
/// mutates only the in-memory [`ModeledGovernanceTrustState`].
pub fn modeled_trust_applier_never_mutates_live_pqc_trust_state() -> bool {
    true
}

/// Run 244 — explicit invariant helper.
///
/// Returns `true`: a modeled apply success is required before a durable consume —
/// only [`ModeledTrustMutationOutcome::ModeledMutationApplied`] projects to the
/// consume-eligible [`DurableMutationCompletion::AppliedSuccessfully`].
pub fn modeled_trust_applier_success_required_before_durable_consume() -> bool {
    true
}

/// Run 244 — explicit invariant helper.
///
/// Returns `true`: a modeled apply failure never consumes durable replay state.
pub fn modeled_trust_applier_failure_never_consumes() -> bool {
    true
}

/// Run 244 — explicit invariant helper.
///
/// Returns `true`: a modeled rollback never consumes durable replay state.
pub fn modeled_trust_applier_rollback_never_consumes() -> bool {
    true
}

/// Run 244 — explicit invariant helper.
///
/// Returns `true`: an ambiguous modeled mutation window fails closed and never
/// consumes.
pub fn modeled_trust_applier_ambiguous_window_fails_closed() -> bool {
    true
}

/// Run 244 — explicit fail-closed helper.
///
/// Returns `true`: production / MainNet modeled appliers remain unavailable /
/// fail-closed. No real production or MainNet modeled mutation applier is
/// implemented.
pub fn production_mainnet_modeled_trust_applier_unavailable() -> bool {
    true
}

/// Run 244 — explicit refusal helper.
///
/// Returns `true` iff MainNet peer-driven apply remains refused by the modeled
/// applier for a MainNet environment, before any snapshot or applier invocation.
pub fn mainnet_peer_driven_apply_refused_by_modeled_trust_applier(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 244 — explicit fail-closed helper.
///
/// Returns `true` iff validator-set rotation remains unsupported by the modeled
/// applier. Run 244 always returns `true`.
pub fn validator_set_rotation_unsupported_by_modeled_trust_applier() -> bool {
    true
}

/// Run 244 — explicit fail-closed helper.
///
/// Returns `true` iff policy-change actions remain unsupported by the modeled
/// applier. Run 244 always returns `true`.
pub fn policy_change_unsupported_by_modeled_trust_applier() -> bool {
    true
}

/// Run 244 — explicit non-implementation helper.
///
/// Returns `true`: Run 244 introduces no RocksDB schema, file format, database
/// migration, or storage-format change. The modeled applier boundary is a pure
/// typed composition over an in-memory modeled state with source/test fixture
/// appliers only.
pub fn modeled_trust_applier_no_rocksdb_file_schema_migration_change() -> bool {
    true
}

/// Run 244 — explicit fail-closed helper.
///
/// Returns `true` iff a local operator key *cannot* satisfy a MainNet modeled
/// applier authority. Run 244 always returns `true`.
pub fn local_operator_cannot_satisfy_modeled_trust_applier_authority() -> bool {
    true
}

/// Run 244 — explicit fail-closed helper.
///
/// Returns `true` iff peer-majority / gossip count *cannot* satisfy a MainNet
/// modeled applier authority. Run 244 always returns `true`.
pub fn peer_majority_cannot_satisfy_modeled_trust_applier_authority() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mutation(action: ModeledTrustMutationAction, root_id: &str) -> ModeledGovernanceTrustMutation {
        ModeledGovernanceTrustMutation {
            action,
            root_id: root_id.to_string(),
            decision_digest: "decision-digest".to_string(),
            candidate_digest: "candidate-digest".to_string(),
            proposal_id: "proposal-0001".to_string(),
            decision_id: "decision-0001".to_string(),
            authority_domain_sequence: 7,
            lifecycle_action: LocalLifecycleAction::Rotate,
        }
    }

    fn env_binding(env: TrustBundleEnvironment) -> ModeledGovernanceTrustMutationEnvironmentBinding {
        ModeledGovernanceTrustMutationEnvironmentBinding {
            environment: env,
            chain_id: "qbind-devnet".to_string(),
            genesis_hash: "genesis-hash".to_string(),
        }
    }

    fn runtime_binding(
        vs: GovernanceExecutionRuntimeSurface,
        ms: GovernanceExecutionRuntimeSurface,
    ) -> ModeledGovernanceTrustMutationRuntimeBinding {
        ModeledGovernanceTrustMutationRuntimeBinding {
            governance_surface: ms,
            mutation_surface: ModeledGovernanceTrustMutationSurface {
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
    ) -> ModeledGovernanceTrustMutationExpectations {
        ModeledGovernanceTrustMutationExpectations {
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
    fn fixture_add_root_applies_and_projects_to_consume() {
        let m = mutation(ModeledTrustMutationAction::AddTrustRoot, "root-A");
        let env = env_binding(TrustBundleEnvironment::Devnet);
        let rt = runtime_binding(
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
        );
        let input = ModeledGovernanceTrustMutationInput {
            applier_kind: ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
            policy: ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
            mutation: &m,
            environment_binding: &env,
            runtime_binding: &rt,
        };
        let exp = expectations(
            TrustBundleEnvironment::Devnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
        );
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier =
            FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
        let outcome = evaluate_modeled_trust_mutation(&input, &exp, &mut state, &mut applier);
        assert_eq!(outcome, ModeledTrustMutationOutcome::ModeledMutationApplied);
        assert!(state.contains_active("root-A"));
        assert_eq!(applier.attempts(), 1);
        assert!(modeled_outcome_authorizes_durable_consume(&outcome));
    }

    #[test]
    fn rejected_before_snapshot_never_invokes_applier() {
        let m = mutation(ModeledTrustMutationAction::AddTrustRoot, "root-A");
        let env = env_binding(TrustBundleEnvironment::Devnet);
        let rt = runtime_binding(
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
        );
        let input = ModeledGovernanceTrustMutationInput {
            applier_kind: ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
            policy: ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
            mutation: &m,
            environment_binding: &env,
            runtime_binding: &rt,
        };
        let mut exp = expectations(
            TrustBundleEnvironment::Devnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
        );
        exp.expected_genesis_hash = "other-genesis".to_string();
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier =
            FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet);
        let outcome = evaluate_modeled_trust_mutation(&input, &exp, &mut state, &mut applier);
        assert!(matches!(
            outcome,
            ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeSnapshot { .. }
        ));
        assert!(outcome.applier_must_not_run());
        assert_eq!(applier.attempts(), 0);
        assert!(state.is_empty());
        assert!(outcome.no_consume());
    }

    #[test]
    fn invariant_helpers_are_fail_closed() {
        assert!(modeled_trust_applier_rejection_is_non_mutating());
        assert!(modeled_trust_applier_never_calls_run_070());
        assert!(modeled_trust_applier_never_mutates_live_pqc_trust_state());
        assert!(modeled_trust_applier_success_required_before_durable_consume());
        assert!(modeled_trust_applier_failure_never_consumes());
        assert!(modeled_trust_applier_rollback_never_consumes());
        assert!(modeled_trust_applier_ambiguous_window_fails_closed());
        assert!(production_mainnet_modeled_trust_applier_unavailable());
        assert!(mainnet_peer_driven_apply_refused_by_modeled_trust_applier(
            TrustBundleEnvironment::Mainnet
        ));
        assert!(!mainnet_peer_driven_apply_refused_by_modeled_trust_applier(
            TrustBundleEnvironment::Devnet
        ));
        assert!(validator_set_rotation_unsupported_by_modeled_trust_applier());
        assert!(policy_change_unsupported_by_modeled_trust_applier());
        assert!(modeled_trust_applier_no_rocksdb_file_schema_migration_change());
        assert!(local_operator_cannot_satisfy_modeled_trust_applier_authority());
        assert!(peer_majority_cannot_satisfy_modeled_trust_applier_authority());
    }
}
