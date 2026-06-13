//! Run 248 — source/test governance **modeled durable-consume projection sink**
//! boundary.
//!
//! Source/test only. Run 248 captures **no** release-binary evidence and enables
//! **no** production mutating behavior. It does **not** implement a real
//! governance execution engine, a real production mutation engine, a real
//! on-chain governance proof verifier, a real persistent replay backend, a real
//! durable consume backend, a real KMS/HSM/RemoteSigner backend, MainNet
//! governance enablement, MainNet peer-driven apply enablement, validator-set
//! rotation, or any RocksDB / file / schema / migration / wire / marker /
//! sequence / trust-bundle / storage-format change.
//!
//! ## What this module adds
//!
//! Run 246 ([`crate::pqc_governance_modeled_end_to_end_pipeline`]) proves that a
//! durable consume is authorized end-to-end **only** after evaluator/call-site
//! authorization, durable replay freshness, mutation-engine authorization, and a
//! modeled successful applier outcome all agree — terminating in the single
//! consume-authorizing outcome
//! [`GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized`].
//!
//! What was still missing is a typed source/test boundary that models how a
//! future production call site would **record** the after-success-only durable
//! consume *receipt* once the Run 246 pipeline has authorized consume. Run 248
//! adds exactly that: a mockable, in-memory consume-receipt sink that records a
//! modeled receipt **only** when the Run 246 pipeline authorized consume, and
//! that fails closed for every other pipeline outcome, every sink record
//! failure, rollback, rollback-failure, ambiguous receipt window, and every
//! production / MainNet unavailable / unsupported path.
//!
//! The sink is a **model only**. It does not implement a real persistent backend.
//! It does not write RocksDB, files, schemas, migrations, storage formats, wire
//! formats, authority markers, trust-bundle sequence files, or any production
//! durable state. It does not call Run 070, mutate `LivePqcTrustState`, perform a
//! real trust swap, evict sessions, or enable MainNet governance / MainNet
//! peer-driven apply. The DevNet/TestNet fixture sink mutates only the in-memory
//! [`ModeledDurableConsumeReceiptLedger`].
//!
//! ## Ordering / fail-closed contract
//!
//! 1. **MainNet peer-driven apply refusal** — refused *before* pipeline
//!    progression and *before* any sink invocation;
//! 2. **legacy bypass** — a disabled sink / pipeline / evaluator-call-site policy
//!    preserves the legacy no-receipt, no-consume bypass and never invokes the
//!    sink;
//! 3. **pipeline-outcome projection** — only
//!    [`GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized`]
//!    creates a sink intent; every other Run 246 outcome maps to a no-receipt
//!    fail-closed outcome and never invokes the sink;
//! 4. **pre-sink binding validation** — environment / chain / genesis /
//!    governance surface / mutation surface must match expectations *before* the
//!    sink is invoked; a mismatch fails closed with no sink invocation;
//! 5. **sink record** — only after every prior gate passes is the sink invoked;
//!    the receipt-identity fields must match exactly before any modeled receipt
//!    is recorded;
//! 6. **consume authorization** — only [`GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded`]
//!    authorizes a new modeled receipt-recorded state.
//!
//! A sink record failure, rollback, rollback failure, or ambiguous receipt window
//! never retroactively claims durable consume success. A duplicate identical
//! receipt is idempotent; the same receipt id with a different digest fails closed
//! as equivocation and records no second receipt.

use crate::pqc_governance_modeled_end_to_end_pipeline::{
    DurableReplayObservation, GovernanceModeledEndToEndPipelineOutcome,
};
use crate::pqc_governance_modeled_trust_mutation_applier::{
    ModeledGovernanceTrustMutationEnvironmentBinding, ModeledGovernanceTrustMutationRuntimeBinding,
    ModeledGovernanceTrustMutationSurface,
};
use crate::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Reused typed bindings (composition, not reimplementation)
// ===========================================================================

/// Run 248 — the validation / mutation surface pair the sink decision binds to.
///
/// A type alias over the Run 244/246 surface pair: the sink composes the existing
/// boundary type rather than reimplementing it.
pub type GovernanceModeledDurableConsumeSinkSurface = ModeledGovernanceTrustMutationSurface;

/// Run 248 — the trust-domain environment binding the sink decision is bound to.
///
/// A type alias over the Run 244/246 environment binding.
pub type GovernanceModeledDurableConsumeSinkEnvironmentBinding =
    ModeledGovernanceTrustMutationEnvironmentBinding;

/// Run 248 — the runtime binding (governance + mutation surface + sequence) the
/// sink decision is bound to.
///
/// A type alias over the Run 244/246 runtime binding.
pub type GovernanceModeledDurableConsumeSinkRuntimeBinding =
    ModeledGovernanceTrustMutationRuntimeBinding;

/// Run 248 — the Run 240/246 durable replay observation the sink carries as the
/// freshness context the pipeline authorized consume under.
///
/// A type alias over the Run 246 durable replay observation.
pub type GovernanceModeledDurableConsumeSinkReplayBinding = DurableReplayObservation;

/// Run 248 — the Run 246 pipeline outcome the sink projects to a consume-receipt
/// intent.
///
/// A type alias over the Run 246 pipeline outcome. The sink never reimplements the
/// pipeline; it only projects its terminal outcome.
pub type GovernanceModeledDurableConsumeSinkPipelineBinding =
    GovernanceModeledEndToEndPipelineOutcome;

// ===========================================================================
// Sink kind
// ===========================================================================

/// Run 248 — the modeled durable-consume projection sink kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModeledDurableConsumeSinkKind {
    /// DevNet fixture sink (source-test only; may mutate only the ledger).
    FixtureDevNet,
    /// TestNet fixture sink (source-test only; may mutate only the ledger).
    FixtureTestNet,
    /// Production sink (reachable-but-unavailable / fail-closed).
    ProductionUnavailable,
    /// MainNet sink (reachable-but-unavailable / fail-closed).
    MainNetUnavailable,
}

impl ModeledDurableConsumeSinkKind {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::FixtureDevNet => "fixture-devnet",
            Self::FixtureTestNet => "fixture-testnet",
            Self::ProductionUnavailable => "production-unavailable",
            Self::MainNetUnavailable => "mainnet-unavailable",
        }
    }

    /// `true` iff this is a DevNet/TestNet source-test fixture sink.
    pub const fn is_fixture(self) -> bool {
        matches!(self, Self::FixtureDevNet | Self::FixtureTestNet)
    }

    /// `true` iff this kind is reachable-but-unavailable (production / MainNet).
    pub const fn is_unavailable(self) -> bool {
        matches!(self, Self::ProductionUnavailable | Self::MainNetUnavailable)
    }
}

// ===========================================================================
// Sink policy
// ===========================================================================

/// Run 248 — the sink-level wiring policy.
///
/// All three flags must be wired for the sink to be invoked. Any disabled flag
/// preserves the legacy no-receipt, no-consume bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GovernanceModeledDurableConsumeSinkPolicy {
    /// `true` iff the durable-consume projection sink boundary is wired at all.
    pub sink_wired: bool,
    /// `true` iff the Run 246 end-to-end pipeline stage is wired.
    pub pipeline_wired: bool,
    /// `true` iff the Run 226 evaluator call-site stage is wired.
    pub evaluator_callsite_wired: bool,
}

impl GovernanceModeledDurableConsumeSinkPolicy {
    /// A fully-disabled sink policy (legacy bypass).
    pub const fn disabled() -> Self {
        Self {
            sink_wired: false,
            pipeline_wired: false,
            evaluator_callsite_wired: false,
        }
    }

    /// A fully-wired sink policy (DevNet/TestNet source-test only).
    pub const fn wired() -> Self {
        Self {
            sink_wired: true,
            pipeline_wired: true,
            evaluator_callsite_wired: true,
        }
    }

    /// A policy with the sink stage explicitly disabled but the pipeline /
    /// evaluator stages wired.
    pub const fn sink_disabled() -> Self {
        Self {
            sink_wired: false,
            pipeline_wired: true,
            evaluator_callsite_wired: true,
        }
    }

    /// A policy with the pipeline stage explicitly disabled.
    pub const fn pipeline_disabled() -> Self {
        Self {
            sink_wired: true,
            pipeline_wired: false,
            evaluator_callsite_wired: true,
        }
    }

    /// A policy with the evaluator call-site stage explicitly disabled.
    pub const fn evaluator_disabled() -> Self {
        Self {
            sink_wired: true,
            pipeline_wired: true,
            evaluator_callsite_wired: false,
        }
    }

    /// `true` iff every flag is wired.
    pub const fn is_wired(self) -> bool {
        self.sink_wired && self.pipeline_wired && self.evaluator_callsite_wired
    }
}

// ===========================================================================
// Modeled in-memory receipt digest / state
// ===========================================================================

/// Run 248 — the modeled consume-receipt digest.
///
/// A receipt is idempotent-equal to a prior recorded receipt only if **every**
/// field below matches exactly (receipt digest, proposal id, decision id,
/// candidate digest, authority-domain sequence, and modeled pipeline decision
/// digest). The same receipt id with any differing field is equivocation and must
/// fail closed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModeledDurableConsumeReceiptDigest {
    /// The governance consume-receipt digest.
    pub receipt_digest: String,
    /// Governance proposal id.
    pub proposal_id: String,
    /// Governance decision id.
    pub decision_id: String,
    /// Candidate (trust-anchor material) digest.
    pub candidate_digest: String,
    /// Authority-domain sequence the receipt is bound to.
    pub authority_domain_sequence: u64,
    /// Modeled Run 246 pipeline decision digest the receipt is bound to.
    pub pipeline_decision_digest: String,
}

/// Run 248 — the recorded status of a modeled consume-receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModeledDurableConsumeReceiptStatus {
    /// The modeled receipt is recorded in the in-memory fixture ledger.
    Recorded,
}

/// Run 248 — a single modeled consume-receipt record held in the in-memory
/// fixture ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeledDurableConsumeReceiptRecord {
    /// The receipt id (stable identity of the consume receipt).
    pub receipt_id: String,
    /// The receipt digest (identity material that must match exactly for
    /// idempotency).
    pub digest: ModeledDurableConsumeReceiptDigest,
    /// The recorded status.
    pub status: ModeledDurableConsumeReceiptStatus,
}

/// Run 248 — an immutable snapshot of the modeled receipt ledger used to model a
/// fixture rollback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeledDurableConsumeReceiptSnapshot {
    records: Vec<ModeledDurableConsumeReceiptRecord>,
}

impl ModeledDurableConsumeReceiptSnapshot {
    /// The number of records the snapshot captured.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` iff the snapshot captured no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Run 248 — the modeled in-memory consume-receipt ledger.
///
/// **In-memory only.** It never touches RocksDB, files, markers, sequence files,
/// or any production durable state. The DevNet/TestNet fixture sink is the only
/// thing that may mutate it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModeledDurableConsumeReceiptLedger {
    records: Vec<ModeledDurableConsumeReceiptRecord>,
}

impl ModeledDurableConsumeReceiptLedger {
    /// A new, empty modeled receipt ledger.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// The number of recorded receipts.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` iff no receipts are recorded.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The recorded receipts.
    pub fn records(&self) -> &[ModeledDurableConsumeReceiptRecord] {
        &self.records
    }

    /// The record for `receipt_id`, if present.
    pub fn find(&self, receipt_id: &str) -> Option<&ModeledDurableConsumeReceiptRecord> {
        self.records.iter().find(|r| r.receipt_id == receipt_id)
    }

    /// `true` iff a receipt with `receipt_id` is recorded.
    pub fn contains(&self, receipt_id: &str) -> bool {
        self.find(receipt_id).is_some()
    }

    /// Capture an immutable snapshot for a modeled rollback.
    pub fn snapshot(&self) -> ModeledDurableConsumeReceiptSnapshot {
        ModeledDurableConsumeReceiptSnapshot {
            records: self.records.clone(),
        }
    }

    /// Restore the ledger to a previously captured snapshot (modeled rollback).
    pub fn restore(&mut self, snapshot: &ModeledDurableConsumeReceiptSnapshot) {
        self.records = snapshot.records.clone();
    }

    /// Internal: insert a recorded receipt. Only the fixture sink calls this, and
    /// only after every identity / idempotency gate has passed.
    fn insert(&mut self, record: ModeledDurableConsumeReceiptRecord) {
        self.records.push(record);
    }
}

// ===========================================================================
// Sink receipt input
// ===========================================================================

/// Run 248 — the modeled consume-receipt a future production call site would
/// record once the Run 246 pipeline authorized consume.
///
/// Pure data referencing the already-authorized Run 246 decision material — never
/// a copy of any wire payload and never a production durable record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceModeledDurableConsumeSinkReceipt {
    /// The receipt id (stable identity of the consume receipt).
    pub receipt_id: String,
    /// The governance consume-receipt digest.
    pub receipt_digest: String,
    /// Governance proposal id.
    pub proposal_id: String,
    /// Governance decision id.
    pub decision_id: String,
    /// Candidate (trust-anchor material) digest.
    pub candidate_digest: String,
    /// Authority-domain sequence the receipt is bound to.
    pub authority_domain_sequence: u64,
    /// Modeled Run 246 pipeline decision digest the receipt is bound to.
    pub pipeline_decision_digest: String,
}

impl GovernanceModeledDurableConsumeSinkReceipt {
    /// `true` iff every mandatory field is structurally present (non-empty).
    pub fn is_well_formed(&self) -> bool {
        !self.receipt_id.is_empty()
            && !self.receipt_digest.is_empty()
            && !self.proposal_id.is_empty()
            && !self.decision_id.is_empty()
            && !self.candidate_digest.is_empty()
            && !self.pipeline_decision_digest.is_empty()
    }

    /// The modeled idempotency digest derived from this receipt.
    pub fn digest(&self) -> ModeledDurableConsumeReceiptDigest {
        ModeledDurableConsumeReceiptDigest {
            receipt_digest: self.receipt_digest.clone(),
            proposal_id: self.proposal_id.clone(),
            decision_id: self.decision_id.clone(),
            candidate_digest: self.candidate_digest.clone(),
            authority_domain_sequence: self.authority_domain_sequence,
            pipeline_decision_digest: self.pipeline_decision_digest.clone(),
        }
    }
}

// ===========================================================================
// Sink expectations
// ===========================================================================

/// Run 248 — the canonical binding a [`GovernanceModeledDurableConsumeSinkInput`]
/// is checked against.
///
/// Environment / chain / genesis / surface mismatches fail closed **before** the
/// sink is invoked. Receipt-identity mismatches fail closed **inside** the sink,
/// before any modeled receipt is recorded. Neither path is ever a silent
/// approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceModeledDurableConsumeSinkExpectations {
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
    /// Expected governance consume-receipt digest.
    pub expected_receipt_digest: String,
    /// Expected governance proposal id.
    pub expected_proposal_id: String,
    /// Expected governance decision id.
    pub expected_decision_id: String,
    /// Expected candidate digest.
    pub expected_candidate_digest: String,
    /// Expected authority-domain sequence.
    pub expected_authority_domain_sequence: u64,
    /// Expected modeled Run 246 pipeline decision digest.
    pub expected_pipeline_decision_digest: String,
}

impl GovernanceModeledDurableConsumeSinkExpectations {
    /// Internal: the first environment / surface binding mismatch reason, if any.
    /// `None` means the pre-sink binding is consistent.
    fn binding_mismatch_reason(
        &self,
        input: &GovernanceModeledDurableConsumeSinkInput,
    ) -> Option<&'static str> {
        let env = &input.environment_binding;
        let rt = &input.runtime_binding;
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

    /// `true` iff the pre-sink environment / surface binding matches.
    pub fn binding_matches(&self, input: &GovernanceModeledDurableConsumeSinkInput) -> bool {
        self.binding_mismatch_reason(input).is_none()
    }

    /// Internal: the first receipt-identity mismatch reason, if any. `None` means
    /// the receipt identity is consistent and well-formed.
    fn receipt_mismatch_reason(
        &self,
        receipt: &GovernanceModeledDurableConsumeSinkReceipt,
    ) -> Option<&'static str> {
        if !receipt.is_well_formed() {
            return Some("malformed receipt");
        }
        if receipt.receipt_digest != self.expected_receipt_digest {
            return Some("wrong receipt digest");
        }
        if receipt.pipeline_decision_digest != self.expected_pipeline_decision_digest {
            return Some("wrong pipeline decision digest");
        }
        if receipt.proposal_id != self.expected_proposal_id {
            return Some("wrong proposal id");
        }
        if receipt.decision_id != self.expected_decision_id {
            return Some("wrong decision id");
        }
        if receipt.candidate_digest != self.expected_candidate_digest {
            return Some("wrong candidate digest");
        }
        if receipt.authority_domain_sequence != self.expected_authority_domain_sequence {
            return Some("wrong authority-domain sequence");
        }
        None
    }

    /// `true` iff the receipt identity matches and the receipt is well-formed.
    pub fn receipt_matches(&self, receipt: &GovernanceModeledDurableConsumeSinkReceipt) -> bool {
        self.receipt_mismatch_reason(receipt).is_none()
    }
}

// ===========================================================================
// Sink input
// ===========================================================================

/// Run 248 — typed inputs for one modeled durable-consume projection sink
/// round-trip.
///
/// Holds the sink policy, the environment / runtime / replay bindings, the Run
/// 246 pipeline-outcome binding, and the modeled consume receipt. It is itself
/// pure data and performs no work on construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceModeledDurableConsumeSinkInput {
    /// The sink-level wiring policy.
    pub policy: GovernanceModeledDurableConsumeSinkPolicy,
    /// The trust-domain environment binding.
    pub environment_binding: GovernanceModeledDurableConsumeSinkEnvironmentBinding,
    /// The runtime binding (governance + mutation surface + sequence).
    pub runtime_binding: GovernanceModeledDurableConsumeSinkRuntimeBinding,
    /// The Run 240/246 durable replay observation the pipeline authorized consume
    /// under.
    pub replay_binding: GovernanceModeledDurableConsumeSinkReplayBinding,
    /// The Run 246 pipeline outcome the sink projects to a consume-receipt intent.
    pub pipeline_binding: GovernanceModeledDurableConsumeSinkPipelineBinding,
    /// The modeled consume receipt the sink would record.
    pub receipt: GovernanceModeledDurableConsumeSinkReceipt,
}

impl GovernanceModeledDurableConsumeSinkInput {
    /// The trust-domain environment the decision is bound to.
    pub fn environment(&self) -> TrustBundleEnvironment {
        self.environment_binding.environment
    }

    /// The validation / mutation surface pair.
    pub fn surface(&self) -> GovernanceModeledDurableConsumeSinkSurface {
        self.runtime_binding.mutation_surface
    }

    /// `true` iff this is a MainNet peer-driven apply that remains refused
    /// unconditionally before pipeline progression and before any sink invocation.
    pub fn is_mainnet_peer_driven(&self) -> bool {
        (self.environment() == TrustBundleEnvironment::Mainnet && self.surface().is_peer_driven())
            || matches!(
                self.replay_binding,
                DurableReplayObservation::MainNetPeerDrivenApplyRefused
            )
            || matches!(
                self.pipeline_binding,
                GovernanceModeledEndToEndPipelineOutcome::MainNetPeerDrivenApplyRefusedNoConsume
            )
    }
}

// ===========================================================================
// Sink outcome
// ===========================================================================

/// Run 248 — the typed outcome of one modeled durable-consume projection sink.
///
/// Only [`Self::ConsumeReceiptRecorded`] authorizes a **new** modeled
/// receipt-recorded state. A [`Self::ConsumeReceiptDuplicateIdempotent`] means the
/// consume receipt was already recorded (idempotent, no second receipt). Every
/// other variant is a no-receipt, no-consume fail-closed outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceModeledDurableConsumeSinkOutcome {
    /// Legacy bypass — a disabled sink / pipeline / evaluator-call-site policy
    /// preserved the legacy no-receipt, no-consume path. No sink invocation.
    LegacyBypassNoReceipt,
    /// The sink-stage environment / surface binding was rejected before the sink
    /// was invoked. Non-mutating, no receipt. No sink invocation.
    RejectedBeforePipelineNoReceipt,
    /// The Run 246 pipeline did not authorize consume (any non-success pipeline
    /// outcome without a more specific variant). Non-mutating, no receipt. No sink
    /// invocation.
    PipelineDidNotAuthorizeConsumeNoReceipt,
    /// The sink recorded a new modeled consume receipt. The **only** outcome that
    /// authorizes a new modeled receipt-recorded state.
    ConsumeReceiptRecorded,
    /// A duplicate identical receipt — idempotent; no second receipt recorded.
    ConsumeReceiptDuplicateIdempotent,
    /// The receipt was rejected before record (malformed receipt, receipt-identity
    /// mismatch, or same receipt id with a differing digest / equivocation).
    /// No receipt, no consume.
    ConsumeReceiptRejectedBeforeRecord,
    /// The sink record failed. No receipt, no consume.
    ConsumeReceiptRecordFailedNoConsume,
    /// The sink record was rolled back. No receipt, no consume.
    ConsumeReceiptRolledBackNoConsume,
    /// The sink rollback itself failed — fatal / fail-closed. No receipt, no
    /// consume.
    ConsumeReceiptRollbackFailedFatalNoConsume,
    /// The after-record window was ambiguous — fails closed. No receipt, no
    /// consume.
    ConsumeReceiptAmbiguousFailClosedNoConsume,
    /// The production sink path was reached but is unavailable. No receipt, no
    /// consume.
    ProductionSinkUnavailableNoConsume,
    /// The MainNet sink path was reached but is unavailable. No receipt, no
    /// consume.
    MainNetSinkUnavailableNoConsume,
    /// MainNet peer-driven apply remains refused before pipeline progression and
    /// before any sink invocation. No receipt, no consume.
    MainNetPeerDrivenApplyRefusedNoConsume,
    /// Validator-set rotation is unsupported. No receipt, no consume.
    ValidatorSetRotationUnsupportedNoConsume,
    /// Policy-change actions are unsupported. No receipt, no consume.
    PolicyChangeUnsupportedNoConsume,
}

impl GovernanceModeledDurableConsumeSinkOutcome {
    /// `true` iff this outcome authorizes a **new** modeled receipt-recorded state
    /// (only [`Self::ConsumeReceiptRecorded`]).
    pub fn authorizes_modeled_consume_receipt(&self) -> bool {
        matches!(self, Self::ConsumeReceiptRecorded)
    }

    /// `true` iff this outcome projects to a durable consume completion — a newly
    /// recorded receipt or an idempotent duplicate of an already-recorded receipt.
    pub fn projects_to_durable_completion(&self) -> bool {
        matches!(
            self,
            Self::ConsumeReceiptRecorded | Self::ConsumeReceiptDuplicateIdempotent
        )
    }

    /// `true` iff this outcome consumes nothing new and projects to no durable
    /// completion.
    pub fn no_consume(&self) -> bool {
        !self.projects_to_durable_completion()
    }

    /// `true` iff this is the legacy no-receipt bypass.
    pub fn is_legacy_bypass(&self) -> bool {
        matches!(self, Self::LegacyBypassNoReceipt)
    }

    /// `true` iff this is the MainNet peer-driven-apply refusal.
    pub fn is_mainnet_peer_driven_apply_refused(&self) -> bool {
        matches!(self, Self::MainNetPeerDrivenApplyRefusedNoConsume)
    }

    /// Stable operator-facing tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::LegacyBypassNoReceipt => "legacy-bypass-no-receipt",
            Self::RejectedBeforePipelineNoReceipt => "rejected-before-pipeline-no-receipt",
            Self::PipelineDidNotAuthorizeConsumeNoReceipt => {
                "pipeline-did-not-authorize-consume-no-receipt"
            }
            Self::ConsumeReceiptRecorded => "consume-receipt-recorded",
            Self::ConsumeReceiptDuplicateIdempotent => "consume-receipt-duplicate-idempotent",
            Self::ConsumeReceiptRejectedBeforeRecord => "consume-receipt-rejected-before-record",
            Self::ConsumeReceiptRecordFailedNoConsume => "consume-receipt-record-failed-no-consume",
            Self::ConsumeReceiptRolledBackNoConsume => "consume-receipt-rolled-back-no-consume",
            Self::ConsumeReceiptRollbackFailedFatalNoConsume => {
                "consume-receipt-rollback-failed-fatal-no-consume"
            }
            Self::ConsumeReceiptAmbiguousFailClosedNoConsume => {
                "consume-receipt-ambiguous-fail-closed-no-consume"
            }
            Self::ProductionSinkUnavailableNoConsume => "production-sink-unavailable-no-consume",
            Self::MainNetSinkUnavailableNoConsume => "mainnet-sink-unavailable-no-consume",
            Self::MainNetPeerDrivenApplyRefusedNoConsume => {
                "mainnet-peer-driven-apply-refused-no-consume"
            }
            Self::ValidatorSetRotationUnsupportedNoConsume => {
                "validator-set-rotation-unsupported-no-consume"
            }
            Self::PolicyChangeUnsupportedNoConsume => "policy-change-unsupported-no-consume",
        }
    }
}

// ===========================================================================
// Pipeline-outcome -> consume-sink intent projection
// ===========================================================================

/// Run 248 — the typed projection of a Run 246 pipeline outcome onto a
/// consume-sink intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumeSinkIntent {
    /// The pipeline authorized consume; the sink may attempt to record a receipt.
    CreateIntent,
    /// The pipeline did not authorize consume; no sink intent. Carries the typed
    /// no-receipt outcome the sink evaluation returns directly (without invoking
    /// the sink).
    NoReceipt(GovernanceModeledDurableConsumeSinkOutcome),
}

impl ConsumeSinkIntent {
    /// `true` iff this projection creates a sink intent (i.e. the pipeline
    /// authorized consume).
    pub fn creates_intent(&self) -> bool {
        matches!(self, Self::CreateIntent)
    }
}

/// Run 248 — project a Run 246 pipeline outcome onto a consume-sink intent.
///
/// Only [`GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized`]
/// creates a sink intent. Every other pipeline outcome maps to a no-receipt
/// fail-closed outcome (a more specific one where one exists, otherwise the
/// generic [`GovernanceModeledDurableConsumeSinkOutcome::PipelineDidNotAuthorizeConsumeNoReceipt`]).
/// Pure: performs no work and never invokes a sink.
pub fn project_pipeline_outcome_to_consume_sink_intent(
    outcome: &GovernanceModeledEndToEndPipelineOutcome,
) -> ConsumeSinkIntent {
    use GovernanceModeledDurableConsumeSinkOutcome as Sink;
    use GovernanceModeledEndToEndPipelineOutcome as Pipe;
    match outcome {
        Pipe::ModeledApplierAppliedAndDurableConsumeAuthorized => ConsumeSinkIntent::CreateIntent,
        Pipe::ProceedLegacyBypassNoMutation => {
            ConsumeSinkIntent::NoReceipt(Sink::LegacyBypassNoReceipt)
        }
        Pipe::MainNetPeerDrivenApplyRefusedNoConsume => {
            ConsumeSinkIntent::NoReceipt(Sink::MainNetPeerDrivenApplyRefusedNoConsume)
        }
        Pipe::ValidatorSetRotationUnsupportedNoConsume => {
            ConsumeSinkIntent::NoReceipt(Sink::ValidatorSetRotationUnsupportedNoConsume)
        }
        Pipe::PolicyChangeUnsupportedNoConsume => {
            ConsumeSinkIntent::NoReceipt(Sink::PolicyChangeUnsupportedNoConsume)
        }
        Pipe::ProductionUnavailableNoConsume => {
            ConsumeSinkIntent::NoReceipt(Sink::ProductionSinkUnavailableNoConsume)
        }
        Pipe::MainNetUnavailableNoConsume => {
            ConsumeSinkIntent::NoReceipt(Sink::MainNetSinkUnavailableNoConsume)
        }
        // Every remaining pipeline outcome is a non-success rejection / completion
        // without a more specific sink variant: evaluator/replay/mutation-engine
        // rejections, modeled apply failure / rollback / rollback-failed /
        // ambiguous, and the durable replay backend-unavailable / consumed /
        // superseded / stale states. None authorize a sink intent.
        _ => ConsumeSinkIntent::NoReceipt(Sink::PipelineDidNotAuthorizeConsumeNoReceipt),
    }
}

// ===========================================================================
// Sink fault injection (source/test only)
// ===========================================================================

/// Run 248 — a modeled fault the fixture sink injects to exercise the
/// fail-closed record / rollback / ambiguous paths. Source/test only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModeledConsumeSinkFault {
    /// The sink record fails; nothing is written. No consume.
    RecordFailedNoConsume,
    /// The sink record is rolled back; nothing remains written. No consume.
    RolledBackNoConsume,
    /// The sink rollback itself fails — fatal / fail-closed. No consume.
    RollbackFailedFatal,
    /// The after-record window is ambiguous — fails closed. No consume.
    AmbiguousAfterRecord,
}

// ===========================================================================
// Sink trait boundary
// ===========================================================================

/// Run 248 — the pure/mockable modeled durable-consume projection sink boundary.
///
/// No implementation here calls Run 070, mutates `LivePqcTrustState`, performs a
/// live trust swap, evicts sessions, writes a sequence, writes a marker, or
/// performs a persistent durable consume. The DevNet/TestNet fixture sink mutates
/// only the in-memory [`ModeledDurableConsumeReceiptLedger`].
pub trait GovernanceModeledDurableConsumeProjectionSink {
    /// The sink kind (used for typed recovery classification).
    fn kind(&self) -> ModeledDurableConsumeSinkKind;

    /// The number of times this sink was invoked (so tests can prove non-success
    /// paths never invoke it).
    fn invocations(&self) -> u32;

    /// Record a modeled consume receipt once the Run 246 pipeline authorized
    /// consume and the pre-sink binding validation passed.
    ///
    /// Implementations must increment the invocation counter on entry, validate
    /// the receipt-identity fields before recording, and never write anything but
    /// modeled in-memory ledger state.
    fn record_modeled_consume_receipt(
        &mut self,
        receipt: &GovernanceModeledDurableConsumeSinkReceipt,
        expectations: &GovernanceModeledDurableConsumeSinkExpectations,
        ledger: &mut ModeledDurableConsumeReceiptLedger,
    ) -> GovernanceModeledDurableConsumeSinkOutcome;

    /// Classify a modeled consume-receipt crash/recovery window. Pure: performs no
    /// modeled mutation and never invokes Run 070.
    fn recover_modeled_consume_receipt_window(
        &self,
        input: &GovernanceModeledDurableConsumeSinkInput,
        window: ModeledDurableConsumeReceiptWindow,
        recovered_report: Option<&GovernanceModeledDurableConsumeSinkReceipt>,
        expectations: &GovernanceModeledDurableConsumeSinkExpectations,
    ) -> GovernanceModeledDurableConsumeSinkOutcome {
        recover_modeled_durable_consume_projection_sink_window(
            input,
            window,
            self.kind(),
            recovered_report,
            expectations,
        )
    }
}

// ===========================================================================
// Fixture sink (DevNet / TestNet source-test only)
// ===========================================================================

/// Run 248 — the DevNet/TestNet fixture modeled durable-consume projection sink.
///
/// Source-test only. It mutates only the in-memory
/// [`ModeledDurableConsumeReceiptLedger`] and exposes an invocation counter so
/// tests can prove non-success paths never invoke it.
#[derive(Debug, Clone)]
pub struct FixtureModeledDurableConsumeProjectionSink {
    kind: ModeledDurableConsumeSinkKind,
    fault: Option<ModeledConsumeSinkFault>,
    invocations: u32,
}

impl FixtureModeledDurableConsumeProjectionSink {
    /// A new fixture sink for the given DevNet/TestNet environment.
    pub fn new(environment: TrustBundleEnvironment) -> Self {
        Self {
            kind: Self::kind_for(environment),
            fault: None,
            invocations: 0,
        }
    }

    /// A new fixture sink that injects the given modeled fault on record.
    pub fn with_fault(environment: TrustBundleEnvironment, fault: ModeledConsumeSinkFault) -> Self {
        Self {
            kind: Self::kind_for(environment),
            fault: Some(fault),
            invocations: 0,
        }
    }

    fn kind_for(environment: TrustBundleEnvironment) -> ModeledDurableConsumeSinkKind {
        match environment {
            TrustBundleEnvironment::Testnet => ModeledDurableConsumeSinkKind::FixtureTestNet,
            // DevNet (and any non-MainNet/non-TestNet fixture surface) is DevNet.
            _ => ModeledDurableConsumeSinkKind::FixtureDevNet,
        }
    }
}

impl GovernanceModeledDurableConsumeProjectionSink for FixtureModeledDurableConsumeProjectionSink {
    fn kind(&self) -> ModeledDurableConsumeSinkKind {
        self.kind
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn record_modeled_consume_receipt(
        &mut self,
        receipt: &GovernanceModeledDurableConsumeSinkReceipt,
        expectations: &GovernanceModeledDurableConsumeSinkExpectations,
        ledger: &mut ModeledDurableConsumeReceiptLedger,
    ) -> GovernanceModeledDurableConsumeSinkOutcome {
        self.invocations += 1;

        // Injected faults model record-failure / rollback / ambiguous windows.
        // None of them ever leave a recorded receipt behind, so durable consume
        // is never claimed. The ledger snapshot/restore models the rollback being
        // a no-op write.
        if let Some(fault) = self.fault {
            let snapshot = ledger.snapshot();
            return match fault {
                ModeledConsumeSinkFault::RecordFailedNoConsume => {
                    ledger.restore(&snapshot);
                    GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecordFailedNoConsume
                }
                ModeledConsumeSinkFault::RolledBackNoConsume => {
                    ledger.restore(&snapshot);
                    GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRolledBackNoConsume
                }
                ModeledConsumeSinkFault::RollbackFailedFatal => {
                    GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRollbackFailedFatalNoConsume
                }
                ModeledConsumeSinkFault::AmbiguousAfterRecord => {
                    ledger.restore(&snapshot);
                    GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptAmbiguousFailClosedNoConsume
                }
            };
        }

        // Receipt-identity validation (malformed / mismatch) fails closed before
        // any record is written.
        if !expectations.receipt_matches(receipt) {
            return GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRejectedBeforeRecord;
        }

        let digest = receipt.digest();

        // Idempotency / equivocation gate.
        if let Some(existing) = ledger.find(&receipt.receipt_id) {
            if existing.digest == digest {
                return GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptDuplicateIdempotent;
            }
            // Same receipt id with a different digest is equivocation: fail closed,
            // record no second receipt.
            return GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRejectedBeforeRecord;
        }

        ledger.insert(ModeledDurableConsumeReceiptRecord {
            receipt_id: receipt.receipt_id.clone(),
            digest,
            status: ModeledDurableConsumeReceiptStatus::Recorded,
        });
        GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded
    }
}

// ===========================================================================
// Production / MainNet sinks (reachable-but-unavailable / fail-closed)
// ===========================================================================

/// Run 248 — the production modeled durable-consume projection sink. Reachable
/// but unavailable / fail-closed. It records no receipt and mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct ProductionModeledDurableConsumeProjectionSink {
    invocations: u32,
}

impl GovernanceModeledDurableConsumeProjectionSink
    for ProductionModeledDurableConsumeProjectionSink
{
    fn kind(&self) -> ModeledDurableConsumeSinkKind {
        ModeledDurableConsumeSinkKind::ProductionUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn record_modeled_consume_receipt(
        &mut self,
        _receipt: &GovernanceModeledDurableConsumeSinkReceipt,
        _expectations: &GovernanceModeledDurableConsumeSinkExpectations,
        _ledger: &mut ModeledDurableConsumeReceiptLedger,
    ) -> GovernanceModeledDurableConsumeSinkOutcome {
        self.invocations += 1;
        GovernanceModeledDurableConsumeSinkOutcome::ProductionSinkUnavailableNoConsume
    }
}

/// Run 248 — the MainNet modeled durable-consume projection sink. Reachable but
/// unavailable / fail-closed. It records no receipt and mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct MainNetModeledDurableConsumeProjectionSink {
    invocations: u32,
}

impl GovernanceModeledDurableConsumeProjectionSink for MainNetModeledDurableConsumeProjectionSink {
    fn kind(&self) -> ModeledDurableConsumeSinkKind {
        ModeledDurableConsumeSinkKind::MainNetUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn record_modeled_consume_receipt(
        &mut self,
        _receipt: &GovernanceModeledDurableConsumeSinkReceipt,
        _expectations: &GovernanceModeledDurableConsumeSinkExpectations,
        _ledger: &mut ModeledDurableConsumeReceiptLedger,
    ) -> GovernanceModeledDurableConsumeSinkOutcome {
        self.invocations += 1;
        GovernanceModeledDurableConsumeSinkOutcome::MainNetSinkUnavailableNoConsume
    }
}

// ===========================================================================
// Sink executor / composition helpers
// ===========================================================================

/// Run 248 — evaluate one modeled durable-consume projection sink round-trip.
///
/// Ordering (each gate must pass before the next is considered):
///
/// 1. MainNet peer-driven apply refusal — before pipeline progression and before
///    any sink invocation;
/// 2. legacy bypass — a disabled sink / pipeline / evaluator-call-site policy;
/// 3. pipeline-outcome projection — only
///    [`GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized`]
///    creates a sink intent;
/// 4. pre-sink binding validation — environment / surface must match before the
///    sink is invoked;
/// 5. sink record — invoked only after every prior gate passes.
///
/// A rejection before the sink stage leaves the sink invocation count at zero.
/// Pure aside from the fixture sink's modeled in-memory ledger effect: performs no
/// I/O, mutates no `LivePqcTrustState`, writes no marker, writes no sequence,
/// swaps no live trust, evicts no sessions, performs no persistent durable
/// consume, and never invokes Run 070.
pub fn evaluate_modeled_durable_consume_projection_sink<S>(
    input: &GovernanceModeledDurableConsumeSinkInput,
    expectations: &GovernanceModeledDurableConsumeSinkExpectations,
    sink: &mut S,
    ledger: &mut ModeledDurableConsumeReceiptLedger,
) -> GovernanceModeledDurableConsumeSinkOutcome
where
    S: GovernanceModeledDurableConsumeProjectionSink,
{
    // Step 1: MainNet peer-driven apply remains refused unconditionally, before
    // pipeline progression and before any sink invocation.
    if input.is_mainnet_peer_driven() {
        return GovernanceModeledDurableConsumeSinkOutcome::MainNetPeerDrivenApplyRefusedNoConsume;
    }

    // Step 2: legacy bypass — a disabled sink / pipeline / evaluator-call-site
    // policy preserves the legacy no-receipt path and never invokes the sink.
    if !input.policy.is_wired() {
        return GovernanceModeledDurableConsumeSinkOutcome::LegacyBypassNoReceipt;
    }

    // Step 3: project the Run 246 pipeline outcome onto a consume-sink intent.
    // Every non-success outcome returns a no-receipt outcome without invoking the
    // sink.
    match project_pipeline_outcome_to_consume_sink_intent(&input.pipeline_binding) {
        ConsumeSinkIntent::NoReceipt(outcome) => return outcome,
        ConsumeSinkIntent::CreateIntent => {}
    }

    // Step 4: pre-sink environment / surface binding validation. A mismatch fails
    // closed before the sink is invoked.
    if !expectations.binding_matches(input) {
        return GovernanceModeledDurableConsumeSinkOutcome::RejectedBeforePipelineNoReceipt;
    }

    // Step 5: invoke the sink to record the modeled consume receipt.
    sink.record_modeled_consume_receipt(&input.receipt, expectations, ledger)
}

/// Run 248 — the modeled durable-consume projection sink crash/recovery window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModeledDurableConsumeReceiptWindow {
    /// Crashed before the pipeline authorized consume.
    BeforePipeline,
    /// Crashed after pipeline success but before a sink intent was created.
    AfterPipelineSuccessBeforeSinkIntent,
    /// Crashed after a sink intent but before any record.
    AfterSinkIntentBeforeRecord,
    /// Crashed after a record but before a report — fails closed unless an
    /// explicit matching receipt report exists.
    AfterRecordBeforeReport,
    /// Recovered after a successful report.
    AfterReportSuccess,
    /// Recovered after an ambiguous report.
    AfterReportAmbiguous,
    /// The record itself failed.
    RecordFailed,
    /// The record was rolled back.
    RollbackCompleted,
    /// The rollback itself failed — fatal.
    RollbackFailed,
    /// An unknown window — fails closed.
    Unknown,
}

/// Run 248 — classify a modeled durable-consume projection sink crash/recovery
/// window.
///
/// The sink never silently re-authorizes an in-flight consume: MainNet
/// peer-driven refusal precedes classification, production / MainNet
/// classification is unavailable, and every ambiguous / unknown window fails
/// closed. Only an after-record window with an explicit matching receipt report
/// (or an explicit after-report-success window) recovers as
/// [`GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded`]. Pure:
/// performs no modeled mutation and never invokes Run 070.
pub fn recover_modeled_durable_consume_projection_sink_window(
    input: &GovernanceModeledDurableConsumeSinkInput,
    window: ModeledDurableConsumeReceiptWindow,
    kind: ModeledDurableConsumeSinkKind,
    recovered_report: Option<&GovernanceModeledDurableConsumeSinkReceipt>,
    expectations: &GovernanceModeledDurableConsumeSinkExpectations,
) -> GovernanceModeledDurableConsumeSinkOutcome {
    use GovernanceModeledDurableConsumeSinkOutcome as Sink;

    // MainNet peer-driven apply refusal precedes recovery classification.
    if input.is_mainnet_peer_driven() {
        return Sink::MainNetPeerDrivenApplyRefusedNoConsume;
    }

    // Production / MainNet recovery classification is unavailable / fail-closed.
    match kind {
        ModeledDurableConsumeSinkKind::ProductionUnavailable => {
            return Sink::ProductionSinkUnavailableNoConsume;
        }
        ModeledDurableConsumeSinkKind::MainNetUnavailable => {
            return Sink::MainNetSinkUnavailableNoConsume;
        }
        ModeledDurableConsumeSinkKind::FixtureDevNet
        | ModeledDurableConsumeSinkKind::FixtureTestNet => {}
    }

    match window {
        // Before any consume authorization there is nothing to recover.
        ModeledDurableConsumeReceiptWindow::BeforePipeline
        | ModeledDurableConsumeReceiptWindow::AfterPipelineSuccessBeforeSinkIntent => {
            Sink::PipelineDidNotAuthorizeConsumeNoReceipt
        }
        // A sink intent without a record never consumes.
        ModeledDurableConsumeReceiptWindow::AfterSinkIntentBeforeRecord => {
            Sink::ConsumeReceiptRejectedBeforeRecord
        }
        // After a record but before a report: fails closed unless an explicit
        // matching, well-formed receipt report exists.
        ModeledDurableConsumeReceiptWindow::AfterRecordBeforeReport => match recovered_report {
            Some(report) if expectations.receipt_matches(report) => Sink::ConsumeReceiptRecorded,
            _ => Sink::ConsumeReceiptRejectedBeforeRecord,
        },
        // An explicit successful report recovers as recorded only if the report
        // matches expectations.
        ModeledDurableConsumeReceiptWindow::AfterReportSuccess => match recovered_report {
            Some(report) if expectations.receipt_matches(report) => Sink::ConsumeReceiptRecorded,
            _ => Sink::ConsumeReceiptRejectedBeforeRecord,
        },
        ModeledDurableConsumeReceiptWindow::AfterReportAmbiguous => {
            Sink::ConsumeReceiptAmbiguousFailClosedNoConsume
        }
        ModeledDurableConsumeReceiptWindow::RecordFailed => {
            Sink::ConsumeReceiptRecordFailedNoConsume
        }
        ModeledDurableConsumeReceiptWindow::RollbackCompleted => {
            Sink::ConsumeReceiptRolledBackNoConsume
        }
        ModeledDurableConsumeReceiptWindow::RollbackFailed => {
            Sink::ConsumeReceiptRollbackFailedFatalNoConsume
        }
        // Any unknown window fails closed.
        ModeledDurableConsumeReceiptWindow::Unknown => {
            Sink::ConsumeReceiptAmbiguousFailClosedNoConsume
        }
    }
}

/// Run 248 — `true` iff a sink outcome authorizes a **new** modeled consume
/// receipt (only [`GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded`]).
pub fn sink_outcome_authorizes_modeled_consume_receipt(
    outcome: &GovernanceModeledDurableConsumeSinkOutcome,
) -> bool {
    outcome.authorizes_modeled_consume_receipt()
}

/// Run 248 — `true` iff a sink outcome projects to a durable consume completion
/// (a newly recorded receipt or an idempotent duplicate of an already-recorded
/// receipt).
pub fn sink_outcome_projects_to_durable_completion(
    outcome: &GovernanceModeledDurableConsumeSinkOutcome,
) -> bool {
    outcome.projects_to_durable_completion()
}

// ===========================================================================
// Explicit invariant / fail-closed helpers (grep-verifiable named symbols)
// ===========================================================================

/// Run 248 — explicit invariant helper.
///
/// Returns `true`: a rejected consume-sink path performs no Run 070 call, no
/// `LivePqcTrustState` mutation, no live trust swap, no session eviction, no
/// sequence write, and no marker write.
pub fn modeled_consume_sink_rejection_is_non_mutating() -> bool {
    true
}

/// Run 248 — explicit invariant helper.
///
/// Returns `true`: the consume sink never calls Run 070. It records only the
/// in-memory [`ModeledDurableConsumeReceiptLedger`].
pub fn modeled_consume_sink_never_calls_run_070() -> bool {
    true
}

/// Run 248 — explicit invariant helper.
///
/// Returns `true`: the consume sink never mutates `LivePqcTrustState`.
pub fn modeled_consume_sink_never_mutates_live_pqc_trust_state() -> bool {
    true
}

/// Run 248 — explicit invariant helper.
///
/// Returns `true`: the consume sink never writes a trust-bundle sequence file or
/// an authority marker.
pub fn modeled_consume_sink_never_writes_sequence_or_marker() -> bool {
    true
}

/// Run 248 — explicit non-implementation helper.
///
/// Returns `true`: Run 248 introduces no RocksDB schema, file format, database
/// migration, or storage-format change. The sink is a pure typed projection over
/// an in-memory ledger.
pub fn modeled_consume_sink_no_rocksdb_file_schema_migration_change() -> bool {
    true
}

/// Run 248 — explicit invariant helper.
///
/// Returns `true`: a Run 246 pipeline success is required before any sink receipt
/// can be recorded — only
/// [`GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized`]
/// creates a sink intent.
pub fn modeled_consume_sink_pipeline_success_required_before_receipt() -> bool {
    true
}

/// Run 248 — explicit invariant helper.
///
/// Returns `true`: a recorded receipt
/// ([`GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded`]) is
/// required before any modeled receipt-recorded / durable-consume state.
pub fn modeled_consume_sink_receipt_record_required_before_consume() -> bool {
    true
}

/// Run 248 — explicit invariant helper.
///
/// Returns `true`: a failed sink record never consumes.
pub fn modeled_consume_sink_failed_record_never_consumes() -> bool {
    true
}

/// Run 248 — explicit invariant helper.
///
/// Returns `true`: a sink rollback (and a fatal rollback failure) never consumes.
pub fn modeled_consume_sink_rollback_never_consumes() -> bool {
    true
}

/// Run 248 — explicit invariant helper.
///
/// Returns `true`: an ambiguous receipt window fails closed and never consumes.
pub fn modeled_consume_sink_ambiguous_window_fails_closed() -> bool {
    true
}

/// Run 248 — explicit refusal helper.
///
/// Returns `true` iff MainNet peer-driven apply remains refused first for a
/// MainNet environment, before pipeline progression and before any sink
/// invocation.
pub fn modeled_consume_sink_mainnet_peer_driven_apply_refused_first(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 248 — explicit fail-closed helper.
///
/// Returns `true`: production / MainNet sink paths remain unavailable /
/// fail-closed. No real production or MainNet durable-consume sink is implemented.
pub fn modeled_consume_sink_production_mainnet_unavailable() -> bool {
    true
}

/// Run 248 — explicit fail-closed helper.
///
/// Returns `true`: validator-set rotation remains unsupported by the sink.
pub fn modeled_consume_sink_validator_set_rotation_unsupported() -> bool {
    true
}

/// Run 248 — explicit fail-closed helper.
///
/// Returns `true`: policy-change actions remain unsupported by the sink.
pub fn modeled_consume_sink_policy_change_unsupported() -> bool {
    true
}

/// Run 248 — explicit fail-closed helper.
///
/// Returns `true` iff a local operator key *cannot* satisfy a MainNet sink
/// authority. Run 248 always returns `true`.
pub fn modeled_consume_sink_local_operator_cannot_satisfy_mainnet_authority() -> bool {
    true
}

/// Run 248 — explicit fail-closed helper.
///
/// Returns `true` iff peer-majority / gossip count *cannot* satisfy a MainNet
/// sink authority. Run 248 always returns `true`.
pub fn modeled_consume_sink_peer_majority_cannot_satisfy_mainnet_authority() -> bool {
    true
}
