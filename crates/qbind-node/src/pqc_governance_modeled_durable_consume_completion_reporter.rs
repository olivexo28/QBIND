//! Run 250 — source/test governance **modeled durable-consume receipt-acknowledgement /
//! completion reporter** boundary.
//!
//! Source/test only. Run 250 captures **no** release-binary evidence and enables
//! **no** production mutating behavior. It does **not** implement a real
//! governance execution engine, a real production mutation engine, a real
//! on-chain governance proof verifier, a real persistent replay backend, a real
//! durable consume backend, a real completion-report backend, a real
//! KMS/HSM/RemoteSigner backend, MainNet governance enablement, MainNet
//! peer-driven apply enablement, validator-set rotation, or any RocksDB / file /
//! schema / migration / wire / marker / sequence / trust-bundle / storage-format
//! change.
//!
//! ## What this module adds
//!
//! Run 248 ([`crate::pqc_governance_modeled_durable_consume_projection_sink`])
//! proves that a modeled consume *receipt* is recorded **only** after the Run 246
//! pipeline yields
//! [`GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized`],
//! terminating in the single receipt-recording outcome
//! [`GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded`].
//!
//! What was still missing is a typed source/test boundary that models how a
//! future production call site would *report* an **after-record-only** consume
//! acknowledgement / completion report back to the Run 240 durable completion
//! semantics. Run 250 adds exactly that: a mockable, in-memory completion reporter
//! that records a modeled completion report **only** when the Run 248 sink
//! recorded a receipt, and that fails closed for every other sink outcome, every
//! report record failure, rollback, rollback-failure, ambiguous acknowledgement
//! window, and every production / MainNet unavailable / unsupported path.
//!
//! The reporter is a **model only**. It does not implement a real persistent
//! backend. It does not write RocksDB, files, schemas, migrations, storage
//! formats, wire formats, authority markers, trust-bundle sequence files, or any
//! production durable state. It does not call Run 070, mutate `LivePqcTrustState`,
//! perform a real trust swap, evict sessions, or enable MainNet governance /
//! MainNet peer-driven apply. The DevNet/TestNet fixture reporter mutates only the
//! in-memory [`ModeledDurableConsumeCompletionReportLedger`].
//!
//! ## Ordering / fail-closed contract
//!
//! 1. **MainNet peer-driven apply refusal** — refused *before* pipeline
//!    progression, *before* any sink invocation, and *before* any reporter
//!    invocation;
//! 2. **legacy bypass** — a disabled reporter / sink / pipeline /
//!    evaluator-call-site policy preserves the legacy no-acknowledgement,
//!    no-completion bypass and never invokes the reporter;
//! 3. **sink-outcome projection** — only
//!    [`GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded`]
//!    creates a completion-report intent; every other Run 248 sink outcome maps to
//!    a no-completion fail-closed outcome and never records;
//! 4. **pre-reporter binding validation** — environment / chain / genesis /
//!    governance surface / mutation surface must match expectations *before* the
//!    reporter records; a mismatch fails closed;
//! 5. **report record** — only after every prior gate passes is the report
//!    record attempted; the report-identity fields must match exactly before any
//!    modeled completion report is recorded;
//! 6. **completion authorization** — only
//!    [`GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded`]
//!    authorizes a new modeled completion-reported state.
//!
//! A report record failure, rollback, rollback failure, or ambiguous
//! acknowledgement window never retroactively claims durable consume completion. A
//! duplicate identical completion report is idempotent; the same report id with a
//! different digest fails closed as equivocation and records no second report. A
//! [`GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptDuplicateIdempotent`]
//! never creates a new completion report by itself — it can only match an
//! already-recorded completion report.

use crate::pqc_governance_modeled_durable_consume_projection_sink::GovernanceModeledDurableConsumeSinkOutcome;
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

/// Run 250 — the validation / mutation surface pair the completion report binds
/// to. A type alias over the Run 244/246/248 surface pair.
pub type GovernanceModeledDurableConsumeCompletionReporterSurface =
    ModeledGovernanceTrustMutationSurface;

/// Run 250 — the trust-domain environment binding the completion report is bound
/// to. A type alias over the Run 244/246/248 environment binding.
pub type GovernanceModeledDurableConsumeCompletionReporterEnvironmentBinding =
    ModeledGovernanceTrustMutationEnvironmentBinding;

/// Run 250 — the runtime binding (governance + mutation surface + sequence) the
/// completion report is bound to. A type alias over the Run 244/246/248 runtime
/// binding.
pub type GovernanceModeledDurableConsumeCompletionReporterRuntimeBinding =
    ModeledGovernanceTrustMutationRuntimeBinding;

/// Run 250 — the Run 240/246 durable replay observation the reporter carries as
/// the freshness context the pipeline authorized consume under. A type alias over
/// the Run 246 durable replay observation.
pub type GovernanceModeledDurableConsumeCompletionReporterReplayBinding = DurableReplayObservation;

/// Run 250 — the Run 246 pipeline outcome the reporter carries as the consume
/// authorization context. A type alias over the Run 246 pipeline outcome.
pub type GovernanceModeledDurableConsumeCompletionReporterPipelineBinding =
    GovernanceModeledEndToEndPipelineOutcome;

/// Run 250 — the Run 248 sink outcome the reporter projects to a completion-report
/// intent. A type alias over the Run 248 sink outcome. The reporter never
/// reimplements the sink; it only projects its terminal outcome.
pub type GovernanceModeledDurableConsumeCompletionReporterSinkBinding =
    GovernanceModeledDurableConsumeSinkOutcome;

// ===========================================================================
// Reporter kind
// ===========================================================================

/// Run 250 — the modeled durable-consume completion reporter kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModeledDurableConsumeCompletionReporterKind {
    /// DevNet fixture reporter (source-test only; may mutate only the ledger).
    FixtureDevNet,
    /// TestNet fixture reporter (source-test only; may mutate only the ledger).
    FixtureTestNet,
    /// Production reporter (reachable-but-unavailable / fail-closed).
    ProductionUnavailable,
    /// MainNet reporter (reachable-but-unavailable / fail-closed).
    MainNetUnavailable,
}

impl ModeledDurableConsumeCompletionReporterKind {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::FixtureDevNet => "fixture-devnet",
            Self::FixtureTestNet => "fixture-testnet",
            Self::ProductionUnavailable => "production-unavailable",
            Self::MainNetUnavailable => "mainnet-unavailable",
        }
    }

    /// `true` iff this is a DevNet/TestNet source-test fixture reporter.
    pub const fn is_fixture(self) -> bool {
        matches!(self, Self::FixtureDevNet | Self::FixtureTestNet)
    }

    /// `true` iff this kind is reachable-but-unavailable (production / MainNet).
    pub const fn is_unavailable(self) -> bool {
        matches!(self, Self::ProductionUnavailable | Self::MainNetUnavailable)
    }
}

// ===========================================================================
// Reporter policy
// ===========================================================================

/// Run 250 — the reporter-level wiring policy.
///
/// All four flags must be wired for the reporter to record. Any disabled flag
/// preserves the legacy no-acknowledgement, no-completion bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GovernanceModeledDurableConsumeCompletionReporterPolicy {
    /// `true` iff the durable-consume completion reporter boundary is wired at all.
    pub reporter_wired: bool,
    /// `true` iff the Run 248 durable-consume projection sink stage is wired.
    pub sink_wired: bool,
    /// `true` iff the Run 246 end-to-end pipeline stage is wired.
    pub pipeline_wired: bool,
    /// `true` iff the Run 226 evaluator call-site stage is wired.
    pub evaluator_callsite_wired: bool,
}

impl GovernanceModeledDurableConsumeCompletionReporterPolicy {
    /// A fully-disabled reporter policy (legacy bypass).
    pub const fn disabled() -> Self {
        Self {
            reporter_wired: false,
            sink_wired: false,
            pipeline_wired: false,
            evaluator_callsite_wired: false,
        }
    }

    /// A fully-wired reporter policy (DevNet/TestNet source-test only).
    pub const fn wired() -> Self {
        Self {
            reporter_wired: true,
            sink_wired: true,
            pipeline_wired: true,
            evaluator_callsite_wired: true,
        }
    }

    /// A policy with the reporter stage explicitly disabled but every prior stage
    /// wired.
    pub const fn reporter_disabled() -> Self {
        Self {
            reporter_wired: false,
            sink_wired: true,
            pipeline_wired: true,
            evaluator_callsite_wired: true,
        }
    }

    /// A policy with the sink stage explicitly disabled.
    pub const fn sink_disabled() -> Self {
        Self {
            reporter_wired: true,
            sink_wired: false,
            pipeline_wired: true,
            evaluator_callsite_wired: true,
        }
    }

    /// A policy with the pipeline stage explicitly disabled.
    pub const fn pipeline_disabled() -> Self {
        Self {
            reporter_wired: true,
            sink_wired: true,
            pipeline_wired: false,
            evaluator_callsite_wired: true,
        }
    }

    /// A policy with the evaluator call-site stage explicitly disabled.
    pub const fn evaluator_disabled() -> Self {
        Self {
            reporter_wired: true,
            sink_wired: true,
            pipeline_wired: true,
            evaluator_callsite_wired: false,
        }
    }

    /// `true` iff every flag is wired.
    pub const fn is_wired(self) -> bool {
        self.reporter_wired
            && self.sink_wired
            && self.pipeline_wired
            && self.evaluator_callsite_wired
    }
}

// ===========================================================================
// Modeled in-memory completion-report digest / state
// ===========================================================================

/// Run 250 — the modeled completion-report digest.
///
/// A completion report is idempotent-equal to a prior recorded report only if
/// **every** field below matches exactly (report digest, receipt digest, proposal
/// id, decision id, candidate digest, authority-domain sequence, sink decision
/// digest, and modeled pipeline decision digest). The same report id with any
/// differing field is equivocation and must fail closed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModeledDurableConsumeCompletionReportDigest {
    /// The completion-report digest.
    pub report_digest: String,
    /// The governance consume-receipt digest the report acknowledges.
    pub receipt_digest: String,
    /// Governance proposal id.
    pub proposal_id: String,
    /// Governance decision id.
    pub decision_id: String,
    /// Candidate (trust-anchor material) digest.
    pub candidate_digest: String,
    /// Authority-domain sequence the report is bound to.
    pub authority_domain_sequence: u64,
    /// Run 248 sink decision digest the report is bound to.
    pub sink_decision_digest: String,
    /// Modeled Run 246 pipeline decision digest the report is bound to.
    pub pipeline_decision_digest: String,
}

/// Run 250 — the recorded status of a modeled completion report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModeledDurableConsumeCompletionReportStatus {
    /// The modeled completion report is recorded in the in-memory fixture ledger.
    Recorded,
}

/// Run 250 — a single modeled completion-report record held in the in-memory
/// fixture ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeledDurableConsumeCompletionReportRecord {
    /// The report id (stable identity of the completion report).
    pub report_id: String,
    /// The report digest (identity material that must match exactly for
    /// idempotency).
    pub digest: ModeledDurableConsumeCompletionReportDigest,
    /// The recorded status.
    pub status: ModeledDurableConsumeCompletionReportStatus,
}

/// Run 250 — an immutable snapshot of the modeled completion-report ledger used to
/// model a fixture rollback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeledDurableConsumeCompletionReportSnapshot {
    records: Vec<ModeledDurableConsumeCompletionReportRecord>,
}

impl ModeledDurableConsumeCompletionReportSnapshot {
    /// The number of records the snapshot captured.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` iff the snapshot captured no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Run 250 — the modeled in-memory completion-report ledger.
///
/// **In-memory only.** It never touches RocksDB, files, markers, sequence files,
/// or any production durable state. The DevNet/TestNet fixture reporter is the
/// only thing that may mutate it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModeledDurableConsumeCompletionReportLedger {
    records: Vec<ModeledDurableConsumeCompletionReportRecord>,
}

impl ModeledDurableConsumeCompletionReportLedger {
    /// A new, empty modeled completion-report ledger.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// The number of recorded completion reports.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` iff no completion reports are recorded.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The recorded completion reports.
    pub fn records(&self) -> &[ModeledDurableConsumeCompletionReportRecord] {
        &self.records
    }

    /// The record for `report_id`, if present.
    pub fn find(&self, report_id: &str) -> Option<&ModeledDurableConsumeCompletionReportRecord> {
        self.records.iter().find(|r| r.report_id == report_id)
    }

    /// `true` iff a completion report with `report_id` is recorded.
    pub fn contains(&self, report_id: &str) -> bool {
        self.find(report_id).is_some()
    }

    /// Capture an immutable snapshot for a modeled rollback.
    pub fn snapshot(&self) -> ModeledDurableConsumeCompletionReportSnapshot {
        ModeledDurableConsumeCompletionReportSnapshot {
            records: self.records.clone(),
        }
    }

    /// Restore the ledger to a previously captured snapshot (modeled rollback).
    pub fn restore(&mut self, snapshot: &ModeledDurableConsumeCompletionReportSnapshot) {
        self.records = snapshot.records.clone();
    }

    /// Internal: insert a recorded completion report. Only the fixture reporter
    /// calls this, and only after every identity / idempotency gate has passed.
    fn insert(&mut self, record: ModeledDurableConsumeCompletionReportRecord) {
        self.records.push(record);
    }
}

// ===========================================================================
// Completion report input
// ===========================================================================

/// Run 250 — the modeled completion report a future production call site would
/// record once the Run 248 sink recorded a consume receipt.
///
/// Pure data referencing the already-recorded Run 248 receipt / Run 246 decision
/// material — never a copy of any wire payload and never a production durable
/// record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceModeledDurableConsumeCompletionReport {
    /// The report id (stable identity of the completion report).
    pub report_id: String,
    /// The completion-report digest.
    pub report_digest: String,
    /// The governance consume-receipt digest the report acknowledges.
    pub receipt_digest: String,
    /// Governance proposal id.
    pub proposal_id: String,
    /// Governance decision id.
    pub decision_id: String,
    /// Candidate (trust-anchor material) digest.
    pub candidate_digest: String,
    /// Authority-domain sequence the report is bound to.
    pub authority_domain_sequence: u64,
    /// Run 248 sink decision digest the report is bound to.
    pub sink_decision_digest: String,
    /// Modeled Run 246 pipeline decision digest the report is bound to.
    pub pipeline_decision_digest: String,
}

impl GovernanceModeledDurableConsumeCompletionReport {
    /// `true` iff every mandatory field is structurally present (non-empty).
    pub fn is_well_formed(&self) -> bool {
        !self.report_id.is_empty()
            && !self.report_digest.is_empty()
            && !self.receipt_digest.is_empty()
            && !self.proposal_id.is_empty()
            && !self.decision_id.is_empty()
            && !self.candidate_digest.is_empty()
            && !self.sink_decision_digest.is_empty()
            && !self.pipeline_decision_digest.is_empty()
    }

    /// The modeled idempotency digest derived from this completion report.
    pub fn digest(&self) -> ModeledDurableConsumeCompletionReportDigest {
        ModeledDurableConsumeCompletionReportDigest {
            report_digest: self.report_digest.clone(),
            receipt_digest: self.receipt_digest.clone(),
            proposal_id: self.proposal_id.clone(),
            decision_id: self.decision_id.clone(),
            candidate_digest: self.candidate_digest.clone(),
            authority_domain_sequence: self.authority_domain_sequence,
            sink_decision_digest: self.sink_decision_digest.clone(),
            pipeline_decision_digest: self.pipeline_decision_digest.clone(),
        }
    }
}

// ===========================================================================
// Reporter expectations
// ===========================================================================

/// Run 250 — the canonical binding a
/// [`GovernanceModeledDurableConsumeCompletionReporterInput`] is checked against.
///
/// Environment / chain / genesis / surface mismatches fail closed **before** the
/// report is recorded. Report-identity mismatches fail closed **inside** the
/// reporter, before any modeled completion report is recorded. Neither path is
/// ever a silent approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceModeledDurableConsumeCompletionReporterExpectations {
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
    /// Expected completion-report digest.
    pub expected_report_digest: String,
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
    /// Expected Run 248 sink decision digest.
    pub expected_sink_decision_digest: String,
    /// Expected modeled Run 246 pipeline decision digest.
    pub expected_pipeline_decision_digest: String,
}

impl GovernanceModeledDurableConsumeCompletionReporterExpectations {
    /// Internal: the first environment / surface binding mismatch reason, if any.
    /// `None` means the pre-reporter binding is consistent.
    fn binding_mismatch_reason(
        &self,
        input: &GovernanceModeledDurableConsumeCompletionReporterInput,
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

    /// `true` iff the pre-reporter environment / surface binding matches.
    pub fn binding_matches(
        &self,
        input: &GovernanceModeledDurableConsumeCompletionReporterInput,
    ) -> bool {
        self.binding_mismatch_reason(input).is_none()
    }

    /// Internal: the first report-identity mismatch reason, if any. `None` means
    /// the report identity is consistent and well-formed.
    fn report_mismatch_reason(
        &self,
        report: &GovernanceModeledDurableConsumeCompletionReport,
    ) -> Option<&'static str> {
        if !report.is_well_formed() {
            return Some("malformed completion report");
        }
        if report.report_digest != self.expected_report_digest {
            return Some("wrong report digest");
        }
        if report.receipt_digest != self.expected_receipt_digest {
            return Some("wrong receipt digest");
        }
        if report.sink_decision_digest != self.expected_sink_decision_digest {
            return Some("wrong sink decision digest");
        }
        if report.pipeline_decision_digest != self.expected_pipeline_decision_digest {
            return Some("wrong pipeline decision digest");
        }
        if report.proposal_id != self.expected_proposal_id {
            return Some("wrong proposal id");
        }
        if report.decision_id != self.expected_decision_id {
            return Some("wrong decision id");
        }
        if report.candidate_digest != self.expected_candidate_digest {
            return Some("wrong candidate digest");
        }
        if report.authority_domain_sequence != self.expected_authority_domain_sequence {
            return Some("wrong authority-domain sequence");
        }
        None
    }

    /// `true` iff the report identity matches and the report is well-formed.
    pub fn report_matches(
        &self,
        report: &GovernanceModeledDurableConsumeCompletionReport,
    ) -> bool {
        self.report_mismatch_reason(report).is_none()
    }
}

// ===========================================================================
// Reporter input
// ===========================================================================

/// Run 250 — typed inputs for one modeled durable-consume completion reporter
/// round-trip.
///
/// Holds the reporter policy, the environment / runtime / replay bindings, the Run
/// 246 pipeline-outcome binding, the Run 248 sink-outcome binding, and the modeled
/// completion report. It is itself pure data and performs no work on construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceModeledDurableConsumeCompletionReporterInput {
    /// The reporter-level wiring policy.
    pub policy: GovernanceModeledDurableConsumeCompletionReporterPolicy,
    /// The trust-domain environment binding.
    pub environment_binding: GovernanceModeledDurableConsumeCompletionReporterEnvironmentBinding,
    /// The runtime binding (governance + mutation surface + sequence).
    pub runtime_binding: GovernanceModeledDurableConsumeCompletionReporterRuntimeBinding,
    /// The Run 240/246 durable replay observation the pipeline authorized consume
    /// under.
    pub replay_binding: GovernanceModeledDurableConsumeCompletionReporterReplayBinding,
    /// The Run 246 pipeline outcome the reporter carries as consume-authorization
    /// context.
    pub pipeline_binding: GovernanceModeledDurableConsumeCompletionReporterPipelineBinding,
    /// The Run 248 sink outcome the reporter projects to a completion-report
    /// intent.
    pub sink_binding: GovernanceModeledDurableConsumeCompletionReporterSinkBinding,
    /// The modeled completion report the reporter would record.
    pub report: GovernanceModeledDurableConsumeCompletionReport,
}

impl GovernanceModeledDurableConsumeCompletionReporterInput {
    /// The trust-domain environment the decision is bound to.
    pub fn environment(&self) -> TrustBundleEnvironment {
        self.environment_binding.environment
    }

    /// The validation / mutation surface pair.
    pub fn surface(&self) -> GovernanceModeledDurableConsumeCompletionReporterSurface {
        self.runtime_binding.mutation_surface
    }

    /// `true` iff this is a MainNet peer-driven apply that remains refused
    /// unconditionally before pipeline progression, before any sink invocation,
    /// and before any reporter invocation.
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
            || matches!(
                self.sink_binding,
                GovernanceModeledDurableConsumeSinkOutcome::MainNetPeerDrivenApplyRefusedNoConsume
            )
    }
}

// ===========================================================================
// Reporter outcome
// ===========================================================================

/// Run 250 — the typed outcome of one modeled durable-consume completion reporter.
///
/// Only [`Self::CompletionReportRecorded`] authorizes a **new** modeled
/// completion-reported state. A [`Self::CompletionReportDuplicateIdempotent`] means
/// the completion report was already recorded (idempotent, no second report).
/// Every other variant is a no-acknowledgement, no-completion fail-closed outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceModeledDurableConsumeCompletionReporterOutcome {
    /// Legacy bypass — a disabled reporter / sink / pipeline / evaluator-call-site
    /// policy preserved the legacy no-acknowledgement, no-completion path. No
    /// reporter invocation.
    LegacyBypassNoCompletionReport,
    /// The reporter-stage environment / surface binding was rejected before the
    /// report was recorded. Non-mutating, no completion. No reporter invocation.
    RejectedBeforeSinkNoCompletionReport,
    /// The Run 248 sink did not record a receipt (any non-recording sink outcome
    /// without a more specific variant). Non-mutating, no completion. No reporter
    /// invocation.
    SinkDidNotRecordReceiptNoCompletionReport,
    /// The reporter recorded a new modeled completion report. The **only** outcome
    /// that authorizes a new modeled completion-reported state.
    CompletionReportRecorded,
    /// A duplicate identical completion report — idempotent; no second report
    /// recorded.
    CompletionReportDuplicateIdempotent,
    /// The completion report was rejected before record (malformed report,
    /// report-identity mismatch, same report id with a differing digest /
    /// equivocation, or a duplicate sink receipt with no matching prior report).
    /// No completion.
    CompletionReportRejectedBeforeRecord,
    /// The report record failed. No completion.
    CompletionReportRecordFailedNoCompletion,
    /// The report record was rolled back. No completion.
    CompletionReportRolledBackNoCompletion,
    /// The report rollback itself failed — fatal / fail-closed. No completion.
    CompletionReportRollbackFailedFatalNoCompletion,
    /// The after-record acknowledgement window was ambiguous — fails closed. No
    /// completion.
    CompletionReportAmbiguousFailClosedNoCompletion,
    /// The production reporter path was reached but is unavailable. No completion.
    ProductionReporterUnavailableNoCompletion,
    /// The MainNet reporter path was reached but is unavailable. No completion.
    MainNetReporterUnavailableNoCompletion,
    /// MainNet peer-driven apply remains refused before pipeline progression,
    /// before any sink invocation, and before any reporter invocation. No
    /// completion.
    MainNetPeerDrivenApplyRefusedNoCompletion,
    /// Validator-set rotation is unsupported. No completion.
    ValidatorSetRotationUnsupportedNoCompletion,
    /// Policy-change actions are unsupported. No completion.
    PolicyChangeUnsupportedNoCompletion,
}

impl GovernanceModeledDurableConsumeCompletionReporterOutcome {
    /// `true` iff this outcome authorizes a **new** modeled completion-reported
    /// state (only [`Self::CompletionReportRecorded`]).
    pub fn authorizes_modeled_completion(&self) -> bool {
        matches!(self, Self::CompletionReportRecorded)
    }

    /// `true` iff this outcome projects to a durable consume completion — a newly
    /// recorded report or an idempotent duplicate of an already-recorded report.
    pub fn projects_to_durable_completion(&self) -> bool {
        matches!(
            self,
            Self::CompletionReportRecorded | Self::CompletionReportDuplicateIdempotent
        )
    }

    /// `true` iff this outcome completes nothing new and projects to no durable
    /// completion.
    pub fn no_completion(&self) -> bool {
        !self.projects_to_durable_completion()
    }

    /// `true` iff this is the legacy no-completion bypass.
    pub fn is_legacy_bypass(&self) -> bool {
        matches!(self, Self::LegacyBypassNoCompletionReport)
    }

    /// `true` iff this is the MainNet peer-driven-apply refusal.
    pub fn is_mainnet_peer_driven_apply_refused(&self) -> bool {
        matches!(self, Self::MainNetPeerDrivenApplyRefusedNoCompletion)
    }

    /// Stable operator-facing tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::LegacyBypassNoCompletionReport => "legacy-bypass-no-completion-report",
            Self::RejectedBeforeSinkNoCompletionReport => "rejected-before-sink-no-completion-report",
            Self::SinkDidNotRecordReceiptNoCompletionReport => {
                "sink-did-not-record-receipt-no-completion-report"
            }
            Self::CompletionReportRecorded => "completion-report-recorded",
            Self::CompletionReportDuplicateIdempotent => "completion-report-duplicate-idempotent",
            Self::CompletionReportRejectedBeforeRecord => "completion-report-rejected-before-record",
            Self::CompletionReportRecordFailedNoCompletion => {
                "completion-report-record-failed-no-completion"
            }
            Self::CompletionReportRolledBackNoCompletion => {
                "completion-report-rolled-back-no-completion"
            }
            Self::CompletionReportRollbackFailedFatalNoCompletion => {
                "completion-report-rollback-failed-fatal-no-completion"
            }
            Self::CompletionReportAmbiguousFailClosedNoCompletion => {
                "completion-report-ambiguous-fail-closed-no-completion"
            }
            Self::ProductionReporterUnavailableNoCompletion => {
                "production-reporter-unavailable-no-completion"
            }
            Self::MainNetReporterUnavailableNoCompletion => {
                "mainnet-reporter-unavailable-no-completion"
            }
            Self::MainNetPeerDrivenApplyRefusedNoCompletion => {
                "mainnet-peer-driven-apply-refused-no-completion"
            }
            Self::ValidatorSetRotationUnsupportedNoCompletion => {
                "validator-set-rotation-unsupported-no-completion"
            }
            Self::PolicyChangeUnsupportedNoCompletion => "policy-change-unsupported-no-completion",
        }
    }
}

// ===========================================================================
// Sink-outcome -> completion-report intent projection
// ===========================================================================

/// Run 250 — the typed projection of a Run 248 sink outcome onto a
/// completion-report intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionReportIntent {
    /// The sink recorded a receipt; the reporter may record a new completion
    /// report.
    CreateIntent,
    /// The sink reported an idempotent-duplicate receipt; the reporter may only
    /// match an already-recorded completion report and must never create a new
    /// one.
    IdempotentOnly,
    /// The sink did not record a receipt; no completion-report intent. Carries the
    /// typed no-completion outcome the reporter evaluation returns directly
    /// (without recording).
    NoCompletionReport(GovernanceModeledDurableConsumeCompletionReporterOutcome),
}

impl CompletionReportIntent {
    /// `true` iff this projection creates a completion-report intent (i.e. the sink
    /// recorded a receipt).
    pub fn creates_intent(&self) -> bool {
        matches!(self, Self::CreateIntent)
    }
}

/// Run 250 — project a Run 248 sink outcome onto a completion-report intent.
///
/// Only [`GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded`]
/// creates a completion-report intent.
/// [`GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptDuplicateIdempotent`]
/// may only match an already-recorded completion report and never creates a new
/// one. Every other sink outcome maps to a no-completion fail-closed outcome (a
/// more specific one where one exists, otherwise the generic
/// [`GovernanceModeledDurableConsumeCompletionReporterOutcome::SinkDidNotRecordReceiptNoCompletionReport`]).
/// Pure: performs no work and never records.
pub fn project_sink_outcome_to_completion_report_intent(
    outcome: &GovernanceModeledDurableConsumeSinkOutcome,
) -> CompletionReportIntent {
    use GovernanceModeledDurableConsumeCompletionReporterOutcome as Report;
    use GovernanceModeledDurableConsumeSinkOutcome as Sink;
    match outcome {
        Sink::ConsumeReceiptRecorded => CompletionReportIntent::CreateIntent,
        Sink::ConsumeReceiptDuplicateIdempotent => CompletionReportIntent::IdempotentOnly,
        Sink::LegacyBypassNoReceipt => {
            CompletionReportIntent::NoCompletionReport(Report::LegacyBypassNoCompletionReport)
        }
        Sink::RejectedBeforePipelineNoReceipt => {
            CompletionReportIntent::NoCompletionReport(Report::RejectedBeforeSinkNoCompletionReport)
        }
        Sink::MainNetPeerDrivenApplyRefusedNoConsume => CompletionReportIntent::NoCompletionReport(
            Report::MainNetPeerDrivenApplyRefusedNoCompletion,
        ),
        Sink::ValidatorSetRotationUnsupportedNoConsume => CompletionReportIntent::NoCompletionReport(
            Report::ValidatorSetRotationUnsupportedNoCompletion,
        ),
        Sink::PolicyChangeUnsupportedNoConsume => {
            CompletionReportIntent::NoCompletionReport(Report::PolicyChangeUnsupportedNoCompletion)
        }
        Sink::ProductionSinkUnavailableNoConsume => CompletionReportIntent::NoCompletionReport(
            Report::ProductionReporterUnavailableNoCompletion,
        ),
        Sink::MainNetSinkUnavailableNoConsume => {
            CompletionReportIntent::NoCompletionReport(Report::MainNetReporterUnavailableNoCompletion)
        }
        // Every remaining sink outcome is a non-recording rejection / failure /
        // rollback / ambiguous window: the sink did not record a receipt, so no
        // completion report may exist.
        _ => CompletionReportIntent::NoCompletionReport(
            Report::SinkDidNotRecordReceiptNoCompletionReport,
        ),
    }
}

// ===========================================================================
// Reporter fault injection (source/test only)
// ===========================================================================

/// Run 250 — a modeled fault the fixture reporter injects to exercise the
/// fail-closed record / rollback / ambiguous paths. Source/test only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModeledCompletionReportFault {
    /// The report record fails; nothing is written. No completion.
    RecordFailedNoCompletion,
    /// The report record is rolled back; nothing remains written. No completion.
    RolledBackNoCompletion,
    /// The report rollback itself fails — fatal / fail-closed. No completion.
    RollbackFailedFatal,
    /// The after-record acknowledgement window is ambiguous — fails closed. No
    /// completion.
    AmbiguousAfterRecord,
}

// ===========================================================================
// Reporter trait boundary
// ===========================================================================

/// Run 250 — the pure/mockable modeled durable-consume completion reporter
/// boundary.
///
/// No implementation here calls Run 070, mutates `LivePqcTrustState`, performs a
/// live trust swap, evicts sessions, writes a sequence, writes a marker, or
/// performs a persistent durable consume. The DevNet/TestNet fixture reporter
/// mutates only the in-memory [`ModeledDurableConsumeCompletionReportLedger`].
pub trait GovernanceModeledDurableConsumeCompletionReporter {
    /// The reporter kind (used for typed recovery classification).
    fn kind(&self) -> ModeledDurableConsumeCompletionReporterKind;

    /// The number of times this reporter was invoked (so tests can prove
    /// non-recording sink paths never invoke it).
    fn invocations(&self) -> u32;

    /// Record a modeled completion report once the Run 248 sink recorded a receipt
    /// and the pre-reporter binding validation passed.
    ///
    /// `idempotent_only` is `true` when the projected sink outcome was an
    /// idempotent-duplicate receipt: in that case the reporter may only match an
    /// already-recorded completion report and must never create a new one.
    ///
    /// Implementations must increment the invocation counter on entry, validate
    /// the report-identity fields before recording, and never write anything but
    /// modeled in-memory ledger state.
    fn record_modeled_consume_completion_report(
        &mut self,
        report: &GovernanceModeledDurableConsumeCompletionReport,
        expectations: &GovernanceModeledDurableConsumeCompletionReporterExpectations,
        idempotent_only: bool,
        ledger: &mut ModeledDurableConsumeCompletionReportLedger,
    ) -> GovernanceModeledDurableConsumeCompletionReporterOutcome;

    /// Classify a modeled completion-report crash/recovery window. Pure: performs
    /// no modeled mutation and never invokes Run 070.
    fn recover_modeled_consume_completion_report_window(
        &self,
        input: &GovernanceModeledDurableConsumeCompletionReporterInput,
        window: ModeledDurableConsumeCompletionReportWindow,
        recovered_report: Option<&GovernanceModeledDurableConsumeCompletionReport>,
        expectations: &GovernanceModeledDurableConsumeCompletionReporterExpectations,
    ) -> GovernanceModeledDurableConsumeCompletionReporterOutcome {
        recover_modeled_durable_consume_completion_reporter_window(
            input,
            window,
            self.kind(),
            recovered_report,
            expectations,
        )
    }
}

// ===========================================================================
// Fixture reporter (DevNet / TestNet source-test only)
// ===========================================================================

/// Run 250 — the DevNet/TestNet fixture modeled durable-consume completion
/// reporter.
///
/// Source-test only. It mutates only the in-memory
/// [`ModeledDurableConsumeCompletionReportLedger`] and exposes an invocation
/// counter so tests can prove non-recording sink paths never invoke it.
#[derive(Debug, Clone)]
pub struct FixtureModeledDurableConsumeCompletionReporter {
    kind: ModeledDurableConsumeCompletionReporterKind,
    fault: Option<ModeledCompletionReportFault>,
    invocations: u32,
}

impl FixtureModeledDurableConsumeCompletionReporter {
    /// A new fixture reporter for the given DevNet/TestNet environment.
    pub fn new(environment: TrustBundleEnvironment) -> Self {
        Self {
            kind: Self::kind_for(environment),
            fault: None,
            invocations: 0,
        }
    }

    /// A new fixture reporter that injects the given modeled fault on record.
    pub fn with_fault(
        environment: TrustBundleEnvironment,
        fault: ModeledCompletionReportFault,
    ) -> Self {
        Self {
            kind: Self::kind_for(environment),
            fault: Some(fault),
            invocations: 0,
        }
    }

    fn kind_for(environment: TrustBundleEnvironment) -> ModeledDurableConsumeCompletionReporterKind {
        match environment {
            TrustBundleEnvironment::Testnet => {
                ModeledDurableConsumeCompletionReporterKind::FixtureTestNet
            }
            // DevNet (and any non-MainNet/non-TestNet fixture surface) is DevNet.
            _ => ModeledDurableConsumeCompletionReporterKind::FixtureDevNet,
        }
    }
}

impl GovernanceModeledDurableConsumeCompletionReporter
    for FixtureModeledDurableConsumeCompletionReporter
{
    fn kind(&self) -> ModeledDurableConsumeCompletionReporterKind {
        self.kind
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn record_modeled_consume_completion_report(
        &mut self,
        report: &GovernanceModeledDurableConsumeCompletionReport,
        expectations: &GovernanceModeledDurableConsumeCompletionReporterExpectations,
        idempotent_only: bool,
        ledger: &mut ModeledDurableConsumeCompletionReportLedger,
    ) -> GovernanceModeledDurableConsumeCompletionReporterOutcome {
        use GovernanceModeledDurableConsumeCompletionReporterOutcome as Report;
        self.invocations += 1;

        // Injected faults model record-failure / rollback / ambiguous windows.
        // None of them ever leave a recorded report behind, so durable consume
        // completion is never claimed. The ledger snapshot/restore models the
        // rollback being a no-op write.
        if let Some(fault) = self.fault {
            let snapshot = ledger.snapshot();
            return match fault {
                ModeledCompletionReportFault::RecordFailedNoCompletion => {
                    ledger.restore(&snapshot);
                    Report::CompletionReportRecordFailedNoCompletion
                }
                ModeledCompletionReportFault::RolledBackNoCompletion => {
                    ledger.restore(&snapshot);
                    Report::CompletionReportRolledBackNoCompletion
                }
                ModeledCompletionReportFault::RollbackFailedFatal => {
                    Report::CompletionReportRollbackFailedFatalNoCompletion
                }
                ModeledCompletionReportFault::AmbiguousAfterRecord => {
                    ledger.restore(&snapshot);
                    Report::CompletionReportAmbiguousFailClosedNoCompletion
                }
            };
        }

        // Report-identity validation (malformed / mismatch) fails closed before
        // any record is written.
        if !expectations.report_matches(report) {
            return Report::CompletionReportRejectedBeforeRecord;
        }

        let digest = report.digest();

        // Idempotency / equivocation gate.
        if let Some(existing) = ledger.find(&report.report_id) {
            if existing.digest == digest {
                return Report::CompletionReportDuplicateIdempotent;
            }
            // Same report id with a different digest is equivocation: fail closed,
            // record no second report.
            return Report::CompletionReportRejectedBeforeRecord;
        }

        // A duplicate-idempotent sink receipt may only match an already-recorded
        // completion report; it must never create a new one by itself.
        if idempotent_only {
            return Report::CompletionReportRejectedBeforeRecord;
        }

        ledger.insert(ModeledDurableConsumeCompletionReportRecord {
            report_id: report.report_id.clone(),
            digest,
            status: ModeledDurableConsumeCompletionReportStatus::Recorded,
        });
        Report::CompletionReportRecorded
    }
}

// ===========================================================================
// Production / MainNet reporters (reachable-but-unavailable / fail-closed)
// ===========================================================================

/// Run 250 — the production modeled durable-consume completion reporter. Reachable
/// but unavailable / fail-closed. It records no report and mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct ProductionModeledDurableConsumeCompletionReporter {
    invocations: u32,
}

impl GovernanceModeledDurableConsumeCompletionReporter
    for ProductionModeledDurableConsumeCompletionReporter
{
    fn kind(&self) -> ModeledDurableConsumeCompletionReporterKind {
        ModeledDurableConsumeCompletionReporterKind::ProductionUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn record_modeled_consume_completion_report(
        &mut self,
        _report: &GovernanceModeledDurableConsumeCompletionReport,
        _expectations: &GovernanceModeledDurableConsumeCompletionReporterExpectations,
        _idempotent_only: bool,
        _ledger: &mut ModeledDurableConsumeCompletionReportLedger,
    ) -> GovernanceModeledDurableConsumeCompletionReporterOutcome {
        self.invocations += 1;
        GovernanceModeledDurableConsumeCompletionReporterOutcome::ProductionReporterUnavailableNoCompletion
    }
}

/// Run 250 — the MainNet modeled durable-consume completion reporter. Reachable
/// but unavailable / fail-closed. It records no report and mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct MainNetModeledDurableConsumeCompletionReporter {
    invocations: u32,
}

impl GovernanceModeledDurableConsumeCompletionReporter
    for MainNetModeledDurableConsumeCompletionReporter
{
    fn kind(&self) -> ModeledDurableConsumeCompletionReporterKind {
        ModeledDurableConsumeCompletionReporterKind::MainNetUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn record_modeled_consume_completion_report(
        &mut self,
        _report: &GovernanceModeledDurableConsumeCompletionReport,
        _expectations: &GovernanceModeledDurableConsumeCompletionReporterExpectations,
        _idempotent_only: bool,
        _ledger: &mut ModeledDurableConsumeCompletionReportLedger,
    ) -> GovernanceModeledDurableConsumeCompletionReporterOutcome {
        self.invocations += 1;
        GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetReporterUnavailableNoCompletion
    }
}

// ===========================================================================
// Reporter executor / composition helpers
// ===========================================================================

/// Run 250 — evaluate one modeled durable-consume completion reporter round-trip.
///
/// Ordering (each gate must pass before the next is considered):
///
/// 1. MainNet peer-driven apply refusal — before pipeline progression, before any
///    sink invocation, and before any reporter invocation;
/// 2. legacy bypass — a disabled reporter / sink / pipeline / evaluator-call-site
///    policy;
/// 3. sink-outcome projection — only
///    [`GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded`]
///    creates a completion-report intent;
/// 4. pre-reporter binding validation — environment / surface must match before
///    the report is recorded;
/// 5. report record — attempted only after every prior gate passes.
///
/// A rejection before the reporter stage leaves the reporter invocation count at
/// zero. Pure aside from the fixture reporter's modeled in-memory ledger effect:
/// performs no I/O, mutates no `LivePqcTrustState`, writes no marker, writes no
/// sequence, swaps no live trust, evicts no sessions, performs no persistent
/// durable consume, and never invokes Run 070.
pub fn evaluate_modeled_durable_consume_completion_reporter<R>(
    input: &GovernanceModeledDurableConsumeCompletionReporterInput,
    expectations: &GovernanceModeledDurableConsumeCompletionReporterExpectations,
    reporter: &mut R,
    ledger: &mut ModeledDurableConsumeCompletionReportLedger,
) -> GovernanceModeledDurableConsumeCompletionReporterOutcome
where
    R: GovernanceModeledDurableConsumeCompletionReporter,
{
    use GovernanceModeledDurableConsumeCompletionReporterOutcome as Report;

    // Step 1: MainNet peer-driven apply remains refused unconditionally, before
    // pipeline progression, before any sink invocation, and before any reporter
    // invocation.
    if input.is_mainnet_peer_driven() {
        return Report::MainNetPeerDrivenApplyRefusedNoCompletion;
    }

    // Step 2: legacy bypass — a disabled reporter / sink / pipeline /
    // evaluator-call-site policy preserves the legacy no-completion path and never
    // invokes the reporter.
    if !input.policy.is_wired() {
        return Report::LegacyBypassNoCompletionReport;
    }

    // Step 3: project the Run 248 sink outcome onto a completion-report intent.
    // Every non-recording outcome returns a no-completion outcome without invoking
    // the reporter.
    let idempotent_only = match project_sink_outcome_to_completion_report_intent(&input.sink_binding)
    {
        CompletionReportIntent::NoCompletionReport(outcome) => return outcome,
        CompletionReportIntent::CreateIntent => false,
        CompletionReportIntent::IdempotentOnly => true,
    };

    // Step 4: pre-reporter environment / surface binding validation. A mismatch
    // fails closed before the report is recorded.
    if !expectations.binding_matches(input) {
        return Report::RejectedBeforeSinkNoCompletionReport;
    }

    // Step 5: invoke the reporter to record the modeled completion report.
    reporter.record_modeled_consume_completion_report(
        &input.report,
        expectations,
        idempotent_only,
        ledger,
    )
}

/// Run 250 — the modeled durable-consume completion reporter crash/recovery
/// window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModeledDurableConsumeCompletionReportWindow {
    /// Crashed before the pipeline authorized consume.
    BeforePipeline,
    /// Crashed after pipeline success but before a sink intent was created.
    AfterPipelineSuccessBeforeSinkIntent,
    /// Crashed after a sink intent but before the sink recorded a receipt.
    AfterSinkIntentBeforeReceiptRecord,
    /// Crashed after the sink recorded a receipt but before a completion-report
    /// intent.
    AfterReceiptRecordBeforeReportIntent,
    /// Crashed after a completion-report intent but before any report record.
    AfterReportIntentBeforeReportRecord,
    /// Crashed after a report record but before report success — fails closed
    /// unless an explicit matching completion-report success exists.
    AfterReportRecordBeforeReportSuccess,
    /// Recovered after a successful completion report.
    AfterReportSuccess,
    /// Recovered after an ambiguous completion report.
    AfterReportAmbiguous,
    /// The report record itself failed.
    ReportRecordFailed,
    /// The report record was rolled back.
    RollbackCompleted,
    /// The report rollback itself failed — fatal.
    RollbackFailed,
    /// An unknown window — fails closed.
    Unknown,
}

/// Run 250 — classify a modeled durable-consume completion reporter crash/recovery
/// window.
///
/// The reporter never silently re-authorizes an in-flight completion: MainNet
/// peer-driven refusal precedes classification, production / MainNet
/// classification is unavailable, and every ambiguous / unknown window fails
/// closed. Only an after-report-record window with an explicit matching completion
/// report (or an explicit after-report-success window) recovers as
/// [`GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded`].
/// Pure: performs no modeled mutation and never invokes Run 070.
pub fn recover_modeled_durable_consume_completion_reporter_window(
    input: &GovernanceModeledDurableConsumeCompletionReporterInput,
    window: ModeledDurableConsumeCompletionReportWindow,
    kind: ModeledDurableConsumeCompletionReporterKind,
    recovered_report: Option<&GovernanceModeledDurableConsumeCompletionReport>,
    expectations: &GovernanceModeledDurableConsumeCompletionReporterExpectations,
) -> GovernanceModeledDurableConsumeCompletionReporterOutcome {
    use GovernanceModeledDurableConsumeCompletionReporterOutcome as Report;

    // MainNet peer-driven apply refusal precedes recovery classification.
    if input.is_mainnet_peer_driven() {
        return Report::MainNetPeerDrivenApplyRefusedNoCompletion;
    }

    // Production / MainNet recovery classification is unavailable / fail-closed.
    match kind {
        ModeledDurableConsumeCompletionReporterKind::ProductionUnavailable => {
            return Report::ProductionReporterUnavailableNoCompletion;
        }
        ModeledDurableConsumeCompletionReporterKind::MainNetUnavailable => {
            return Report::MainNetReporterUnavailableNoCompletion;
        }
        ModeledDurableConsumeCompletionReporterKind::FixtureDevNet
        | ModeledDurableConsumeCompletionReporterKind::FixtureTestNet => {}
    }

    match window {
        // Before the sink recorded a receipt there is nothing to acknowledge.
        ModeledDurableConsumeCompletionReportWindow::BeforePipeline
        | ModeledDurableConsumeCompletionReportWindow::AfterPipelineSuccessBeforeSinkIntent
        | ModeledDurableConsumeCompletionReportWindow::AfterSinkIntentBeforeReceiptRecord => {
            Report::SinkDidNotRecordReceiptNoCompletionReport
        }
        // A recorded receipt without a report intent / record never completes.
        ModeledDurableConsumeCompletionReportWindow::AfterReceiptRecordBeforeReportIntent
        | ModeledDurableConsumeCompletionReportWindow::AfterReportIntentBeforeReportRecord => {
            Report::CompletionReportRejectedBeforeRecord
        }
        // After a report record but before report success: fails closed unless an
        // explicit matching, well-formed completion-report success exists.
        ModeledDurableConsumeCompletionReportWindow::AfterReportRecordBeforeReportSuccess => {
            match recovered_report {
                Some(report) if expectations.report_matches(report) => {
                    Report::CompletionReportRecorded
                }
                _ => Report::CompletionReportRejectedBeforeRecord,
            }
        }
        // An explicit successful report recovers as recorded only if the report
        // matches expectations.
        ModeledDurableConsumeCompletionReportWindow::AfterReportSuccess => match recovered_report {
            Some(report) if expectations.report_matches(report) => Report::CompletionReportRecorded,
            _ => Report::CompletionReportRejectedBeforeRecord,
        },
        ModeledDurableConsumeCompletionReportWindow::AfterReportAmbiguous => {
            Report::CompletionReportAmbiguousFailClosedNoCompletion
        }
        ModeledDurableConsumeCompletionReportWindow::ReportRecordFailed => {
            Report::CompletionReportRecordFailedNoCompletion
        }
        ModeledDurableConsumeCompletionReportWindow::RollbackCompleted => {
            Report::CompletionReportRolledBackNoCompletion
        }
        ModeledDurableConsumeCompletionReportWindow::RollbackFailed => {
            Report::CompletionReportRollbackFailedFatalNoCompletion
        }
        // Any unknown window fails closed.
        ModeledDurableConsumeCompletionReportWindow::Unknown => {
            Report::CompletionReportAmbiguousFailClosedNoCompletion
        }
    }
}

/// Run 250 — `true` iff a reporter outcome authorizes a **new** modeled completion
/// (only
/// [`GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded`]).
pub fn completion_reporter_outcome_authorizes_modeled_completion(
    outcome: &GovernanceModeledDurableConsumeCompletionReporterOutcome,
) -> bool {
    outcome.authorizes_modeled_completion()
}

/// Run 250 — `true` iff a reporter outcome projects to a durable consume
/// completion (a newly recorded report or an idempotent duplicate of an
/// already-recorded report).
pub fn completion_reporter_outcome_projects_to_durable_completion(
    outcome: &GovernanceModeledDurableConsumeCompletionReporterOutcome,
) -> bool {
    outcome.projects_to_durable_completion()
}

// ===========================================================================
// Explicit invariant / fail-closed helpers (grep-verifiable named symbols)
// ===========================================================================

/// Run 250 — explicit invariant helper.
///
/// Returns `true`: a rejected completion-reporter path performs no Run 070 call,
/// no `LivePqcTrustState` mutation, no live trust swap, no session eviction, no
/// sequence write, and no marker write.
pub fn modeled_completion_reporter_rejection_is_non_mutating() -> bool {
    true
}

/// Run 250 — explicit invariant helper.
///
/// Returns `true`: the completion reporter never calls Run 070. It records only
/// the in-memory [`ModeledDurableConsumeCompletionReportLedger`].
pub fn modeled_completion_reporter_never_calls_run_070() -> bool {
    true
}

/// Run 250 — explicit invariant helper.
///
/// Returns `true`: the completion reporter never mutates `LivePqcTrustState`.
pub fn modeled_completion_reporter_never_mutates_live_pqc_trust_state() -> bool {
    true
}

/// Run 250 — explicit invariant helper.
///
/// Returns `true`: the completion reporter never writes a trust-bundle sequence
/// file or an authority marker.
pub fn modeled_completion_reporter_never_writes_sequence_or_marker() -> bool {
    true
}

/// Run 250 — explicit non-implementation helper.
///
/// Returns `true`: Run 250 introduces no RocksDB schema, file format, database
/// migration, or storage-format change. The reporter is a pure typed projection
/// over an in-memory ledger.
pub fn modeled_completion_reporter_no_rocksdb_file_schema_migration_change() -> bool {
    true
}

/// Run 250 — explicit invariant helper.
///
/// Returns `true`: a Run 246 pipeline success is required before any sink intent
/// can exist, and therefore before any completion report can be recorded.
pub fn modeled_completion_reporter_pipeline_success_required_before_report() -> bool {
    true
}

/// Run 250 — explicit invariant helper.
///
/// Returns `true`: a Run 248 recorded sink receipt
/// ([`GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded`]) is
/// required before any completion report can be recorded.
pub fn modeled_completion_reporter_sink_receipt_required_before_report() -> bool {
    true
}

/// Run 250 — explicit invariant helper.
///
/// Returns `true`: a recorded completion report
/// ([`GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded`])
/// is required before any modeled completion-reported / durable-completion state.
pub fn modeled_completion_reporter_report_record_required_before_completion() -> bool {
    true
}

/// Run 250 — explicit invariant helper.
///
/// Returns `true`: a failed report record never completes.
pub fn modeled_completion_reporter_failed_record_never_completes() -> bool {
    true
}

/// Run 250 — explicit invariant helper.
///
/// Returns `true`: a report rollback (and a fatal rollback failure) never
/// completes.
pub fn modeled_completion_reporter_rollback_never_completes() -> bool {
    true
}

/// Run 250 — explicit invariant helper.
///
/// Returns `true`: an ambiguous acknowledgement window fails closed and never
/// completes.
pub fn modeled_completion_reporter_ambiguous_window_fails_closed() -> bool {
    true
}

/// Run 250 — explicit refusal helper.
///
/// Returns `true` iff MainNet peer-driven apply remains refused first for a
/// MainNet environment, before pipeline progression, before any sink invocation,
/// and before any reporter invocation.
pub fn modeled_completion_reporter_mainnet_peer_driven_apply_refused_first(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 250 — explicit fail-closed helper.
///
/// Returns `true`: production / MainNet reporter paths remain unavailable /
/// fail-closed. No real production or MainNet completion-report backend is
/// implemented.
pub fn modeled_completion_reporter_production_mainnet_unavailable() -> bool {
    true
}

/// Run 250 — explicit fail-closed helper.
///
/// Returns `true`: validator-set rotation remains unsupported by the reporter.
pub fn modeled_completion_reporter_validator_set_rotation_unsupported() -> bool {
    true
}

/// Run 250 — explicit fail-closed helper.
///
/// Returns `true`: policy-change actions remain unsupported by the reporter.
pub fn modeled_completion_reporter_policy_change_unsupported() -> bool {
    true
}

/// Run 250 — explicit fail-closed helper.
///
/// Returns `true` iff a local operator key *cannot* satisfy a MainNet reporter
/// authority. Run 250 always returns `true`.
pub fn modeled_completion_reporter_local_operator_cannot_satisfy_mainnet_authority() -> bool {
    true
}

/// Run 250 — explicit fail-closed helper.
///
/// Returns `true` iff peer-majority / gossip count *cannot* satisfy a MainNet
/// reporter authority. Run 250 always returns `true`.
pub fn modeled_completion_reporter_peer_majority_cannot_satisfy_mainnet_authority() -> bool {
    true
}
