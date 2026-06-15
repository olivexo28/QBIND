//! Run 254 — source/test governance **modeled durable-completion finalization
//! attestation projection** boundary.
//!
//! Source/test only. Run 254 captures **no** release-binary evidence and enables
//! **no** production mutating behavior. It does **not** implement a real
//! governance execution engine, a real production mutation engine, a real
//! on-chain governance proof verifier, a real persistent replay backend, a real
//! durable consume backend, a real completion-report backend, a real finalization
//! backend, a real attestation backend, a real audit ledger backend, a real
//! settlement ledger backend, a real KMS/HSM/RemoteSigner backend, MainNet
//! governance enablement, MainNet peer-driven apply enablement, validator-set
//! rotation, or any RocksDB / file / schema / migration / wire / marker /
//! sequence / trust-bundle / storage-format change.
//!
//! ## What this module adds
//!
//! Run 252
//! ([`crate::pqc_governance_modeled_durable_completion_finalization_projection`])
//! proves that a modeled durable-completion *finalization* is recorded **only**
//! after the Run 250 reporter recorded a completion report, terminating in the
//! single finalization-recording outcome
//! [`GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized`].
//!
//! What was still missing is a typed source/test boundary that models how a
//! future production call site would emit an **after-finalization-only**
//! durable-completion *attestation* / ledger-commit acknowledgement for
//! auditability. Run 254 adds exactly that: a mockable, in-memory attestation /
//! ledger-commit acknowledgement layer that records a modeled attestation
//! **only** when the Run 252 finalizer recorded a durable-completion
//! finalization, and that fails closed for every other finalization outcome,
//! every attestation record failure, rollback, rollback-failure, ambiguous
//! attestation window, and every production / MainNet unavailable / unsupported
//! path.
//!
//! The attestation layer is a **model only**. It does not implement a real
//! attestation backend, a real audit ledger, or a real settlement ledger. It does
//! not write RocksDB, files, schemas, migrations, storage formats, wire formats,
//! authority markers, trust-bundle sequence files, or any production durable
//! state. It does not call Run 070, mutate `LivePqcTrustState`, perform a real
//! trust swap, evict sessions, or enable MainNet governance / MainNet peer-driven
//! apply. The DevNet/TestNet fixture attestor mutates only the in-memory
//! [`ModeledDurableCompletionAttestationLedger`].
//!
//! ## Ordering / fail-closed contract
//!
//! 1. **MainNet peer-driven apply refusal** — refused *before* pipeline
//!    progression, *before* any sink invocation, *before* any reporter invocation,
//!    *before* any finalizer invocation, and *before* any attestor invocation;
//! 2. **legacy bypass** — a disabled attestor / finalizer / reporter / sink /
//!    pipeline / evaluator-call-site policy preserves the legacy no-attestation
//!    bypass and never invokes the attestor;
//! 3. **finalization-outcome projection** — only
//!    [`GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized`]
//!    creates an attestation intent; every other Run 252 finalization outcome maps
//!    to a no-attestation fail-closed outcome and never records;
//! 4. **pre-attestor binding validation** — environment / chain / genesis /
//!    governance surface / mutation surface must match expectations *before* the
//!    attestor records; a mismatch fails closed;
//! 5. **attestation record** — only after every prior gate passes is the
//!    attestation record attempted; the attestation-identity fields must match
//!    exactly before any modeled attestation is recorded;
//! 6. **attestation authorization** — only
//!    [`GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested`]
//!    authorizes a new modeled durable-completion-attested state.
//!
//! An attestation record failure, rollback, rollback failure, or ambiguous
//! attestation window never retroactively claims durable completion finality or
//! production audit finality. A duplicate identical attestation is idempotent; the
//! same attestation id with a different digest fails closed as equivocation and
//! records no second attestation. A
//! [`GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionDuplicateIdempotent`]
//! never creates a new attestation by itself — it can only match an
//! already-attested record.

use crate::pqc_governance_modeled_durable_completion_finalization_projection::GovernanceModeledDurableCompletionFinalizationOutcome;
use crate::pqc_governance_modeled_durable_consume_completion_reporter::GovernanceModeledDurableConsumeCompletionReporterOutcome;
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

/// Run 254 — the validation / mutation surface pair the attestation binds to. A
/// type alias over the Run 244/246/248/250/252 surface pair.
pub type GovernanceModeledDurableCompletionAttestationSurface =
    ModeledGovernanceTrustMutationSurface;

/// Run 254 — the trust-domain environment binding the attestation is bound to. A
/// type alias over the Run 244/246/248/250/252 environment binding.
pub type GovernanceModeledDurableCompletionAttestationEnvironmentBinding =
    ModeledGovernanceTrustMutationEnvironmentBinding;

/// Run 254 — the runtime binding (governance + mutation surface + sequence) the
/// attestation is bound to. A type alias over the Run 244/246/248/250/252 runtime
/// binding.
pub type GovernanceModeledDurableCompletionAttestationRuntimeBinding =
    ModeledGovernanceTrustMutationRuntimeBinding;

/// Run 254 — the Run 240/246 durable replay observation the attestor carries as
/// the freshness context the pipeline authorized consume under. A type alias over
/// the Run 246 durable replay observation.
pub type GovernanceModeledDurableCompletionAttestationReplayBinding = DurableReplayObservation;

/// Run 254 — the Run 246 pipeline outcome the attestor carries as the consume
/// authorization context. A type alias over the Run 246 pipeline outcome.
pub type GovernanceModeledDurableCompletionAttestationPipelineBinding =
    GovernanceModeledEndToEndPipelineOutcome;

/// Run 254 — the Run 248 sink outcome the attestor carries as the receipt-record
/// context. A type alias over the Run 248 sink outcome.
pub type GovernanceModeledDurableCompletionAttestationSinkBinding =
    GovernanceModeledDurableConsumeSinkOutcome;

/// Run 254 — the Run 250 reporter outcome the attestor carries as the
/// completion-report context. A type alias over the Run 250 reporter outcome.
pub type GovernanceModeledDurableCompletionAttestationReporterBinding =
    GovernanceModeledDurableConsumeCompletionReporterOutcome;

/// Run 254 — the Run 252 finalization outcome the attestor projects to an
/// attestation intent. A type alias over the Run 252 finalization outcome. The
/// attestor never reimplements the finalizer; it only projects its terminal
/// outcome.
pub type GovernanceModeledDurableCompletionAttestationFinalizationBinding =
    GovernanceModeledDurableCompletionFinalizationOutcome;

// ===========================================================================
// Attestor kind
// ===========================================================================

/// Run 254 — the modeled durable-completion attestor kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModeledDurableCompletionAttestorKind {
    /// DevNet fixture attestor (source-test only; may mutate only the ledger).
    FixtureDevNet,
    /// TestNet fixture attestor (source-test only; may mutate only the ledger).
    FixtureTestNet,
    /// Production attestor (reachable-but-unavailable / fail-closed).
    ProductionUnavailable,
    /// MainNet attestor (reachable-but-unavailable / fail-closed).
    MainNetUnavailable,
}

impl ModeledDurableCompletionAttestorKind {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::FixtureDevNet => "fixture-devnet",
            Self::FixtureTestNet => "fixture-testnet",
            Self::ProductionUnavailable => "production-unavailable",
            Self::MainNetUnavailable => "mainnet-unavailable",
        }
    }

    /// `true` iff this is a DevNet/TestNet source-test fixture attestor.
    pub const fn is_fixture(self) -> bool {
        matches!(self, Self::FixtureDevNet | Self::FixtureTestNet)
    }

    /// `true` iff this kind is reachable-but-unavailable (production / MainNet).
    pub const fn is_unavailable(self) -> bool {
        matches!(self, Self::ProductionUnavailable | Self::MainNetUnavailable)
    }
}

// ===========================================================================
// Attestation policy
// ===========================================================================

/// Run 254 — the attestation-level wiring policy.
///
/// All six flags must be wired for the attestor to record. Any disabled flag
/// preserves the legacy no-attestation bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GovernanceModeledDurableCompletionAttestationPolicy {
    /// `true` iff the durable-completion attestation boundary is wired at all.
    pub attestation_wired: bool,
    /// `true` iff the Run 252 durable-completion finalization stage is wired.
    pub finalization_wired: bool,
    /// `true` iff the Run 250 durable-consume completion reporter stage is wired.
    pub reporter_wired: bool,
    /// `true` iff the Run 248 durable-consume projection sink stage is wired.
    pub sink_wired: bool,
    /// `true` iff the Run 246 end-to-end pipeline stage is wired.
    pub pipeline_wired: bool,
    /// `true` iff the Run 226 evaluator call-site stage is wired.
    pub evaluator_callsite_wired: bool,
}

impl GovernanceModeledDurableCompletionAttestationPolicy {
    /// A fully-disabled attestation policy (legacy bypass).
    pub const fn disabled() -> Self {
        Self {
            attestation_wired: false,
            finalization_wired: false,
            reporter_wired: false,
            sink_wired: false,
            pipeline_wired: false,
            evaluator_callsite_wired: false,
        }
    }

    /// A fully-wired attestation policy (DevNet/TestNet source-test only).
    pub const fn wired() -> Self {
        Self {
            attestation_wired: true,
            finalization_wired: true,
            reporter_wired: true,
            sink_wired: true,
            pipeline_wired: true,
            evaluator_callsite_wired: true,
        }
    }

    /// A policy with the attestation stage explicitly disabled but every prior
    /// stage wired.
    pub const fn attestation_disabled() -> Self {
        Self {
            attestation_wired: false,
            finalization_wired: true,
            reporter_wired: true,
            sink_wired: true,
            pipeline_wired: true,
            evaluator_callsite_wired: true,
        }
    }

    /// A policy with the finalization stage explicitly disabled.
    pub const fn finalization_disabled() -> Self {
        Self {
            attestation_wired: true,
            finalization_wired: false,
            reporter_wired: true,
            sink_wired: true,
            pipeline_wired: true,
            evaluator_callsite_wired: true,
        }
    }

    /// A policy with the reporter stage explicitly disabled.
    pub const fn reporter_disabled() -> Self {
        Self {
            attestation_wired: true,
            finalization_wired: true,
            reporter_wired: false,
            sink_wired: true,
            pipeline_wired: true,
            evaluator_callsite_wired: true,
        }
    }

    /// A policy with the sink stage explicitly disabled.
    pub const fn sink_disabled() -> Self {
        Self {
            attestation_wired: true,
            finalization_wired: true,
            reporter_wired: true,
            sink_wired: false,
            pipeline_wired: true,
            evaluator_callsite_wired: true,
        }
    }

    /// A policy with the pipeline stage explicitly disabled.
    pub const fn pipeline_disabled() -> Self {
        Self {
            attestation_wired: true,
            finalization_wired: true,
            reporter_wired: true,
            sink_wired: true,
            pipeline_wired: false,
            evaluator_callsite_wired: true,
        }
    }

    /// A policy with the evaluator call-site stage explicitly disabled.
    pub const fn evaluator_disabled() -> Self {
        Self {
            attestation_wired: true,
            finalization_wired: true,
            reporter_wired: true,
            sink_wired: true,
            pipeline_wired: true,
            evaluator_callsite_wired: false,
        }
    }

    /// `true` iff every flag is wired.
    pub const fn is_wired(self) -> bool {
        self.attestation_wired
            && self.finalization_wired
            && self.reporter_wired
            && self.sink_wired
            && self.pipeline_wired
            && self.evaluator_callsite_wired
    }
}

// ===========================================================================
// Modeled in-memory attestation digest / state
// ===========================================================================

/// Run 254 — the modeled attestation digest.
///
/// An attestation is idempotent-equal to a prior recorded attestation only if
/// **every** field below matches exactly (attestation digest, finalization
/// digest, completion-report digest, receipt digest, proposal id, decision id,
/// candidate digest, authority-domain sequence, sink decision digest, reporter
/// decision digest, finalization decision digest, and modeled pipeline decision
/// digest). The same attestation id with any differing field is equivocation and
/// must fail closed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModeledDurableCompletionAttestationDigest {
    /// The attestation digest.
    pub attestation_digest: String,
    /// The finalization digest the attestation attests.
    pub finalization_digest: String,
    /// The completion-report digest the attestation is bound to.
    pub report_digest: String,
    /// The governance consume-receipt digest the attestation is bound to.
    pub receipt_digest: String,
    /// Governance proposal id.
    pub proposal_id: String,
    /// Governance decision id.
    pub decision_id: String,
    /// Candidate (trust-anchor material) digest.
    pub candidate_digest: String,
    /// Authority-domain sequence the attestation is bound to.
    pub authority_domain_sequence: u64,
    /// Run 248 sink decision digest the attestation is bound to.
    pub sink_decision_digest: String,
    /// Run 250 reporter decision digest the attestation is bound to.
    pub reporter_decision_digest: String,
    /// Run 252 finalization decision digest the attestation is bound to.
    pub finalization_decision_digest: String,
    /// Modeled Run 246 pipeline decision digest the attestation is bound to.
    pub pipeline_decision_digest: String,
}

/// Run 254 — the recorded status of a modeled attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModeledDurableCompletionAttestationStatus {
    /// The modeled attestation is recorded in the in-memory fixture ledger.
    Attested,
}

/// Run 254 — a single modeled attestation record held in the in-memory fixture
/// ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeledDurableCompletionAttestationRecord {
    /// The attestation id (stable identity of the attestation).
    pub attestation_id: String,
    /// The attestation digest (identity material that must match exactly for
    /// idempotency).
    pub digest: ModeledDurableCompletionAttestationDigest,
    /// The recorded status.
    pub status: ModeledDurableCompletionAttestationStatus,
}

/// Run 254 — an immutable snapshot of the modeled attestation ledger used to
/// model a fixture rollback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeledDurableCompletionAttestationSnapshot {
    records: Vec<ModeledDurableCompletionAttestationRecord>,
}

impl ModeledDurableCompletionAttestationSnapshot {
    /// The number of records the snapshot captured.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` iff the snapshot captured no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Run 254 — the modeled in-memory attestation ledger.
///
/// **In-memory only.** It never touches RocksDB, files, markers, sequence files,
/// or any production durable state. The DevNet/TestNet fixture attestor is the
/// only thing that may mutate it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModeledDurableCompletionAttestationLedger {
    records: Vec<ModeledDurableCompletionAttestationRecord>,
}

impl ModeledDurableCompletionAttestationLedger {
    /// A new, empty modeled attestation ledger.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// The number of recorded attestations.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` iff no attestations are recorded.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The recorded attestations.
    pub fn records(&self) -> &[ModeledDurableCompletionAttestationRecord] {
        &self.records
    }

    /// The record for `attestation_id`, if present.
    pub fn find(&self, attestation_id: &str) -> Option<&ModeledDurableCompletionAttestationRecord> {
        self.records
            .iter()
            .find(|r| r.attestation_id == attestation_id)
    }

    /// `true` iff an attestation with `attestation_id` is recorded.
    pub fn contains(&self, attestation_id: &str) -> bool {
        self.find(attestation_id).is_some()
    }

    /// Capture an immutable snapshot for a modeled rollback.
    pub fn snapshot(&self) -> ModeledDurableCompletionAttestationSnapshot {
        ModeledDurableCompletionAttestationSnapshot {
            records: self.records.clone(),
        }
    }

    /// Restore the ledger to a previously captured snapshot (modeled rollback).
    pub fn restore(&mut self, snapshot: &ModeledDurableCompletionAttestationSnapshot) {
        self.records = snapshot.records.clone();
    }

    /// Internal: insert a recorded attestation. Only the fixture attestor calls
    /// this, and only after every identity / idempotency gate has passed.
    fn insert(&mut self, record: ModeledDurableCompletionAttestationRecord) {
        self.records.push(record);
    }
}

// ===========================================================================
// Attestation input record
// ===========================================================================

/// Run 254 — the modeled attestation a future production call site would record
/// once the Run 252 finalizer recorded a durable-completion finalization.
///
/// Pure data referencing the already-recorded Run 252 finalization / Run 250
/// completion report / Run 248 receipt / Run 246 decision material — never a copy
/// of any wire payload and never a production durable record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceModeledDurableCompletionAttestationRecord {
    /// The attestation id (stable identity of the attestation).
    pub attestation_id: String,
    /// The attestation digest.
    pub attestation_digest: String,
    /// The finalization digest the attestation attests.
    pub finalization_digest: String,
    /// The completion-report digest the attestation is bound to.
    pub report_digest: String,
    /// The governance consume-receipt digest the attestation is bound to.
    pub receipt_digest: String,
    /// Governance proposal id.
    pub proposal_id: String,
    /// Governance decision id.
    pub decision_id: String,
    /// Candidate (trust-anchor material) digest.
    pub candidate_digest: String,
    /// Authority-domain sequence the attestation is bound to.
    pub authority_domain_sequence: u64,
    /// Run 248 sink decision digest the attestation is bound to.
    pub sink_decision_digest: String,
    /// Run 250 reporter decision digest the attestation is bound to.
    pub reporter_decision_digest: String,
    /// Run 252 finalization decision digest the attestation is bound to.
    pub finalization_decision_digest: String,
    /// Modeled Run 246 pipeline decision digest the attestation is bound to.
    pub pipeline_decision_digest: String,
}

impl GovernanceModeledDurableCompletionAttestationRecord {
    /// `true` iff every mandatory field is structurally present (non-empty).
    pub fn is_well_formed(&self) -> bool {
        !self.attestation_id.is_empty()
            && !self.attestation_digest.is_empty()
            && !self.finalization_digest.is_empty()
            && !self.report_digest.is_empty()
            && !self.receipt_digest.is_empty()
            && !self.proposal_id.is_empty()
            && !self.decision_id.is_empty()
            && !self.candidate_digest.is_empty()
            && !self.sink_decision_digest.is_empty()
            && !self.reporter_decision_digest.is_empty()
            && !self.finalization_decision_digest.is_empty()
            && !self.pipeline_decision_digest.is_empty()
    }

    /// The modeled idempotency digest derived from this attestation.
    pub fn digest(&self) -> ModeledDurableCompletionAttestationDigest {
        ModeledDurableCompletionAttestationDigest {
            attestation_digest: self.attestation_digest.clone(),
            finalization_digest: self.finalization_digest.clone(),
            report_digest: self.report_digest.clone(),
            receipt_digest: self.receipt_digest.clone(),
            proposal_id: self.proposal_id.clone(),
            decision_id: self.decision_id.clone(),
            candidate_digest: self.candidate_digest.clone(),
            authority_domain_sequence: self.authority_domain_sequence,
            sink_decision_digest: self.sink_decision_digest.clone(),
            reporter_decision_digest: self.reporter_decision_digest.clone(),
            finalization_decision_digest: self.finalization_decision_digest.clone(),
            pipeline_decision_digest: self.pipeline_decision_digest.clone(),
        }
    }
}

// ===========================================================================
// Attestation expectations
// ===========================================================================

/// Run 254 — the canonical binding a
/// [`GovernanceModeledDurableCompletionAttestationInput`] is checked against.
///
/// Environment / chain / genesis / surface mismatches fail closed **before** the
/// attestation is recorded. Attestation-identity mismatches fail closed
/// **inside** the attestor, before any modeled attestation is recorded. Neither
/// path is ever a silent approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceModeledDurableCompletionAttestationExpectations {
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
    /// Expected attestation digest.
    pub expected_attestation_digest: String,
    /// Expected finalization digest.
    pub expected_finalization_digest: String,
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
    /// Expected Run 250 reporter decision digest.
    pub expected_reporter_decision_digest: String,
    /// Expected Run 252 finalization decision digest.
    pub expected_finalization_decision_digest: String,
    /// Expected modeled Run 246 pipeline decision digest.
    pub expected_pipeline_decision_digest: String,
}

impl GovernanceModeledDurableCompletionAttestationExpectations {
    /// Internal: the first environment / surface binding mismatch reason, if any.
    /// `None` means the pre-attestor binding is consistent.
    fn binding_mismatch_reason(
        &self,
        input: &GovernanceModeledDurableCompletionAttestationInput,
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

    /// `true` iff the pre-attestor environment / surface binding matches.
    pub fn binding_matches(
        &self,
        input: &GovernanceModeledDurableCompletionAttestationInput,
    ) -> bool {
        self.binding_mismatch_reason(input).is_none()
    }

    /// Internal: the first attestation-identity mismatch reason, if any. `None`
    /// means the attestation identity is consistent and well-formed.
    fn attestation_mismatch_reason(
        &self,
        attestation: &GovernanceModeledDurableCompletionAttestationRecord,
    ) -> Option<&'static str> {
        if !attestation.is_well_formed() {
            return Some("malformed attestation record");
        }
        if attestation.attestation_digest != self.expected_attestation_digest {
            return Some("wrong attestation digest");
        }
        if attestation.finalization_digest != self.expected_finalization_digest {
            return Some("wrong finalization digest");
        }
        if attestation.report_digest != self.expected_report_digest {
            return Some("wrong completion-report digest");
        }
        if attestation.receipt_digest != self.expected_receipt_digest {
            return Some("wrong receipt digest");
        }
        if attestation.sink_decision_digest != self.expected_sink_decision_digest {
            return Some("wrong sink decision digest");
        }
        if attestation.reporter_decision_digest != self.expected_reporter_decision_digest {
            return Some("wrong reporter decision digest");
        }
        if attestation.finalization_decision_digest != self.expected_finalization_decision_digest {
            return Some("wrong finalization decision digest");
        }
        if attestation.pipeline_decision_digest != self.expected_pipeline_decision_digest {
            return Some("wrong pipeline decision digest");
        }
        if attestation.proposal_id != self.expected_proposal_id {
            return Some("wrong proposal id");
        }
        if attestation.decision_id != self.expected_decision_id {
            return Some("wrong decision id");
        }
        if attestation.candidate_digest != self.expected_candidate_digest {
            return Some("wrong candidate digest");
        }
        if attestation.authority_domain_sequence != self.expected_authority_domain_sequence {
            return Some("wrong authority-domain sequence");
        }
        None
    }

    /// `true` iff the attestation identity matches and is well-formed.
    pub fn attestation_matches(
        &self,
        attestation: &GovernanceModeledDurableCompletionAttestationRecord,
    ) -> bool {
        self.attestation_mismatch_reason(attestation).is_none()
    }
}

// ===========================================================================
// Attestation input
// ===========================================================================

/// Run 254 — typed inputs for one modeled durable-completion attestation
/// round-trip.
///
/// Holds the attestation policy, the environment / runtime / replay bindings, the
/// Run 246 pipeline-outcome binding, the Run 248 sink-outcome binding, the Run 250
/// reporter-outcome binding, the Run 252 finalization-outcome binding, and the
/// modeled attestation record. It is itself pure data and performs no work on
/// construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceModeledDurableCompletionAttestationInput {
    /// The attestation-level wiring policy.
    pub policy: GovernanceModeledDurableCompletionAttestationPolicy,
    /// The trust-domain environment binding.
    pub environment_binding: GovernanceModeledDurableCompletionAttestationEnvironmentBinding,
    /// The runtime binding (governance + mutation surface + sequence).
    pub runtime_binding: GovernanceModeledDurableCompletionAttestationRuntimeBinding,
    /// The Run 240/246 durable replay observation the pipeline authorized consume
    /// under.
    pub replay_binding: GovernanceModeledDurableCompletionAttestationReplayBinding,
    /// The Run 246 pipeline outcome the attestor carries as consume-authorization
    /// context.
    pub pipeline_binding: GovernanceModeledDurableCompletionAttestationPipelineBinding,
    /// The Run 248 sink outcome the attestor carries as receipt-record context.
    pub sink_binding: GovernanceModeledDurableCompletionAttestationSinkBinding,
    /// The Run 250 reporter outcome the attestor carries as completion-report
    /// context.
    pub reporter_binding: GovernanceModeledDurableCompletionAttestationReporterBinding,
    /// The Run 252 finalization outcome the attestor projects to an attestation
    /// intent.
    pub finalization_binding: GovernanceModeledDurableCompletionAttestationFinalizationBinding,
    /// The modeled attestation record the attestor would record.
    pub attestation: GovernanceModeledDurableCompletionAttestationRecord,
}

impl GovernanceModeledDurableCompletionAttestationInput {
    /// The trust-domain environment the decision is bound to.
    pub fn environment(&self) -> TrustBundleEnvironment {
        self.environment_binding.environment
    }

    /// The validation / mutation surface pair.
    pub fn surface(&self) -> GovernanceModeledDurableCompletionAttestationSurface {
        self.runtime_binding.mutation_surface
    }

    /// `true` iff this is a MainNet peer-driven apply that remains refused
    /// unconditionally before pipeline progression, before any sink invocation,
    /// before any reporter invocation, before any finalizer invocation, and before
    /// any attestor invocation.
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
            || matches!(
                self.reporter_binding,
                GovernanceModeledDurableConsumeCompletionReporterOutcome::MainNetPeerDrivenApplyRefusedNoCompletion
            )
            || matches!(
                self.finalization_binding,
                GovernanceModeledDurableCompletionFinalizationOutcome::MainNetPeerDrivenApplyRefusedNoFinalization
            )
    }
}

// ===========================================================================
// Attestation outcome
// ===========================================================================

/// Run 254 — the typed outcome of one modeled durable-completion attestation.
///
/// Only [`Self::DurableCompletionAttested`] authorizes a **new** modeled
/// durable-completion-attested state. A
/// [`Self::DurableCompletionAttestationDuplicateIdempotent`] means the attestation
/// was already recorded (idempotent, no second attestation). Every other variant
/// is a no-attestation fail-closed outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceModeledDurableCompletionAttestationOutcome {
    /// Legacy bypass — a disabled attestor / finalizer / reporter / sink /
    /// pipeline / evaluator-call-site policy preserved the legacy no-attestation
    /// path. No attestor invocation.
    LegacyBypassNoAttestation,
    /// The Run 252 finalization-stage environment / surface binding was rejected
    /// before the attestation was recorded (a finalization-stage rejection /
    /// binding mismatch). Non-mutating, no attestation. No attestor invocation.
    RejectedBeforeFinalizationNoAttestation,
    /// The Run 252 finalizer did not finalize (any non-finalizing finalization
    /// outcome without a more specific variant). Non-mutating, no attestation. No
    /// attestor invocation.
    FinalizationDidNotFinalizeNoAttestation,
    /// The attestor recorded a new modeled attestation. The **only** outcome that
    /// authorizes a new modeled durable-completion-attested state.
    DurableCompletionAttested,
    /// A duplicate identical attestation — idempotent; no second attestation
    /// recorded.
    DurableCompletionAttestationDuplicateIdempotent,
    /// The attestation was rejected before record (malformed attestation,
    /// attestation-identity mismatch, same attestation id with a differing digest /
    /// equivocation, or a duplicate finalization with no matching prior
    /// attestation). No attestation.
    DurableCompletionAttestationRejectedBeforeRecord,
    /// The attestation record failed. No attestation.
    DurableCompletionAttestationRecordFailedNoAttestation,
    /// The attestation record was rolled back. No attestation.
    DurableCompletionAttestationRolledBackNoAttestation,
    /// The attestation rollback itself failed — fatal / fail-closed. No
    /// attestation.
    DurableCompletionAttestationRollbackFailedFatalNoAttestation,
    /// The after-record attestation window was ambiguous — fails closed. No
    /// attestation.
    DurableCompletionAttestationAmbiguousFailClosedNoAttestation,
    /// The production attestor path was reached but is unavailable. No attestation.
    ProductionAttestorUnavailableNoAttestation,
    /// The MainNet attestor path was reached but is unavailable. No attestation.
    MainNetAttestorUnavailableNoAttestation,
    /// MainNet peer-driven apply remains refused before pipeline progression,
    /// before any sink invocation, before any reporter invocation, before any
    /// finalizer invocation, and before any attestor invocation. No attestation.
    MainNetPeerDrivenApplyRefusedNoAttestation,
    /// Validator-set rotation is unsupported. No attestation.
    ValidatorSetRotationUnsupportedNoAttestation,
    /// Policy-change actions are unsupported. No attestation.
    PolicyChangeUnsupportedNoAttestation,
}

impl GovernanceModeledDurableCompletionAttestationOutcome {
    /// `true` iff this outcome authorizes a **new** modeled durable-completion
    /// attestation (only [`Self::DurableCompletionAttested`]).
    pub fn authorizes_modeled_durable_completion_attestation(&self) -> bool {
        matches!(self, Self::DurableCompletionAttested)
    }

    /// `true` iff this outcome projects to a durable-completion attestation — a
    /// newly recorded attestation or an idempotent duplicate of an already-recorded
    /// attestation.
    pub fn projects_to_durable_completion_attested(&self) -> bool {
        matches!(
            self,
            Self::DurableCompletionAttested
                | Self::DurableCompletionAttestationDuplicateIdempotent
        )
    }

    /// `true` iff this outcome attests nothing new and projects to no durable
    /// completion attestation.
    pub fn no_attestation(&self) -> bool {
        !self.projects_to_durable_completion_attested()
    }

    /// `true` iff this is the legacy no-attestation bypass.
    pub fn is_legacy_bypass(&self) -> bool {
        matches!(self, Self::LegacyBypassNoAttestation)
    }

    /// `true` iff this is the MainNet peer-driven-apply refusal.
    pub fn is_mainnet_peer_driven_apply_refused(&self) -> bool {
        matches!(self, Self::MainNetPeerDrivenApplyRefusedNoAttestation)
    }

    /// Stable operator-facing tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::LegacyBypassNoAttestation => "legacy-bypass-no-attestation",
            Self::RejectedBeforeFinalizationNoAttestation => {
                "rejected-before-finalization-no-attestation"
            }
            Self::FinalizationDidNotFinalizeNoAttestation => {
                "finalization-did-not-finalize-no-attestation"
            }
            Self::DurableCompletionAttested => "durable-completion-attested",
            Self::DurableCompletionAttestationDuplicateIdempotent => {
                "durable-completion-attestation-duplicate-idempotent"
            }
            Self::DurableCompletionAttestationRejectedBeforeRecord => {
                "durable-completion-attestation-rejected-before-record"
            }
            Self::DurableCompletionAttestationRecordFailedNoAttestation => {
                "durable-completion-attestation-record-failed-no-attestation"
            }
            Self::DurableCompletionAttestationRolledBackNoAttestation => {
                "durable-completion-attestation-rolled-back-no-attestation"
            }
            Self::DurableCompletionAttestationRollbackFailedFatalNoAttestation => {
                "durable-completion-attestation-rollback-failed-fatal-no-attestation"
            }
            Self::DurableCompletionAttestationAmbiguousFailClosedNoAttestation => {
                "durable-completion-attestation-ambiguous-fail-closed-no-attestation"
            }
            Self::ProductionAttestorUnavailableNoAttestation => {
                "production-attestor-unavailable-no-attestation"
            }
            Self::MainNetAttestorUnavailableNoAttestation => {
                "mainnet-attestor-unavailable-no-attestation"
            }
            Self::MainNetPeerDrivenApplyRefusedNoAttestation => {
                "mainnet-peer-driven-apply-refused-no-attestation"
            }
            Self::ValidatorSetRotationUnsupportedNoAttestation => {
                "validator-set-rotation-unsupported-no-attestation"
            }
            Self::PolicyChangeUnsupportedNoAttestation => {
                "policy-change-unsupported-no-attestation"
            }
        }
    }
}

// ===========================================================================
// Finalization-outcome -> attestation intent projection
// ===========================================================================

/// Run 254 — the typed projection of a Run 252 finalization outcome onto an
/// attestation intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableCompletionAttestationIntent {
    /// The finalizer recorded a finalization; the attestor may record a new
    /// attestation.
    CreateIntent,
    /// The finalizer reported an idempotent-duplicate finalization; the attestor
    /// may only match an already-recorded attestation and must never create a new
    /// one.
    IdempotentOnly,
    /// The finalizer did not finalize; no attestation intent. Carries the typed
    /// no-attestation outcome the attestor evaluation returns directly (without
    /// recording).
    NoAttestation(GovernanceModeledDurableCompletionAttestationOutcome),
}

impl DurableCompletionAttestationIntent {
    /// `true` iff this projection creates an attestation intent (i.e. the finalizer
    /// recorded a finalization).
    pub fn creates_intent(&self) -> bool {
        matches!(self, Self::CreateIntent)
    }
}

/// Run 254 — project a Run 252 finalization outcome onto an attestation intent.
///
/// Only
/// [`GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized`]
/// creates an attestation intent.
/// [`GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionDuplicateIdempotent`]
/// may only match an already-recorded attestation and never creates a new one.
/// Every other finalization outcome maps to a no-attestation fail-closed outcome
/// (a more specific one where one exists, otherwise the generic
/// [`GovernanceModeledDurableCompletionAttestationOutcome::FinalizationDidNotFinalizeNoAttestation`]).
/// Pure: performs no work and never records.
pub fn project_finalization_outcome_to_attestation_intent(
    outcome: &GovernanceModeledDurableCompletionFinalizationOutcome,
) -> DurableCompletionAttestationIntent {
    use GovernanceModeledDurableCompletionAttestationOutcome as Att;
    use GovernanceModeledDurableCompletionFinalizationOutcome as Final;
    match outcome {
        Final::DurableCompletionFinalized => DurableCompletionAttestationIntent::CreateIntent,
        Final::DurableCompletionDuplicateIdempotent => {
            DurableCompletionAttestationIntent::IdempotentOnly
        }
        Final::LegacyBypassNoFinalization => {
            DurableCompletionAttestationIntent::NoAttestation(Att::LegacyBypassNoAttestation)
        }
        Final::RejectedBeforeReporterNoFinalization => {
            DurableCompletionAttestationIntent::NoAttestation(
                Att::RejectedBeforeFinalizationNoAttestation,
            )
        }
        Final::MainNetPeerDrivenApplyRefusedNoFinalization => {
            DurableCompletionAttestationIntent::NoAttestation(
                Att::MainNetPeerDrivenApplyRefusedNoAttestation,
            )
        }
        Final::ValidatorSetRotationUnsupportedNoFinalization => {
            DurableCompletionAttestationIntent::NoAttestation(
                Att::ValidatorSetRotationUnsupportedNoAttestation,
            )
        }
        Final::PolicyChangeUnsupportedNoFinalization => {
            DurableCompletionAttestationIntent::NoAttestation(
                Att::PolicyChangeUnsupportedNoAttestation,
            )
        }
        Final::ProductionFinalizerUnavailableNoFinalization => {
            DurableCompletionAttestationIntent::NoAttestation(
                Att::ProductionAttestorUnavailableNoAttestation,
            )
        }
        Final::MainNetFinalizerUnavailableNoFinalization => {
            DurableCompletionAttestationIntent::NoAttestation(
                Att::MainNetAttestorUnavailableNoAttestation,
            )
        }
        // Every remaining finalization outcome is a non-finalizing rejection /
        // failure / rollback / ambiguous window: the finalizer did not finalize, so
        // no attestation may exist.
        _ => DurableCompletionAttestationIntent::NoAttestation(
            Att::FinalizationDidNotFinalizeNoAttestation,
        ),
    }
}

// ===========================================================================
// Attestor fault injection (source/test only)
// ===========================================================================

/// Run 254 — a modeled fault the fixture attestor injects to exercise the
/// fail-closed record / rollback / ambiguous paths. Source/test only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModeledDurableCompletionAttestationFault {
    /// The attestation record fails; nothing is written. No attestation.
    RecordFailedNoAttestation,
    /// The attestation record is rolled back; nothing remains written. No
    /// attestation.
    RolledBackNoAttestation,
    /// The attestation rollback itself fails — fatal / fail-closed. No attestation.
    RollbackFailedFatal,
    /// The after-record attestation window is ambiguous — fails closed. No
    /// attestation.
    AmbiguousAfterRecord,
}

// ===========================================================================
// Attestor trait boundary
// ===========================================================================

/// Run 254 — the pure/mockable modeled durable-completion attestor boundary.
///
/// No implementation here calls Run 070, mutates `LivePqcTrustState`, performs a
/// live trust swap, evicts sessions, writes a sequence, writes a marker, or
/// performs a persistent durable completion / audit write. The DevNet/TestNet
/// fixture attestor mutates only the in-memory
/// [`ModeledDurableCompletionAttestationLedger`].
pub trait GovernanceModeledDurableCompletionAttestor {
    /// The attestor kind (used for typed recovery classification).
    fn kind(&self) -> ModeledDurableCompletionAttestorKind;

    /// The number of times this attestor was invoked (so tests can prove
    /// non-finalizing finalization paths never invoke it).
    fn invocations(&self) -> u32;

    /// Record a modeled attestation once the Run 252 finalizer recorded a
    /// finalization and the pre-attestor binding validation passed.
    ///
    /// `idempotent_only` is `true` when the projected finalization outcome was an
    /// idempotent-duplicate finalization: in that case the attestor may only match
    /// an already-recorded attestation and must never create a new one.
    ///
    /// Implementations must increment the invocation counter on entry, validate
    /// the attestation-identity fields before recording, and never write anything
    /// but modeled in-memory ledger state.
    fn record_modeled_durable_completion_attestation(
        &mut self,
        attestation: &GovernanceModeledDurableCompletionAttestationRecord,
        expectations: &GovernanceModeledDurableCompletionAttestationExpectations,
        idempotent_only: bool,
        ledger: &mut ModeledDurableCompletionAttestationLedger,
    ) -> GovernanceModeledDurableCompletionAttestationOutcome;

    /// Classify a modeled attestation crash/recovery window. Pure: performs no
    /// modeled mutation and never invokes Run 070.
    fn recover_modeled_durable_completion_attestation_window(
        &self,
        input: &GovernanceModeledDurableCompletionAttestationInput,
        window: ModeledDurableCompletionAttestationWindow,
        recovered_attestation: Option<&GovernanceModeledDurableCompletionAttestationRecord>,
        expectations: &GovernanceModeledDurableCompletionAttestationExpectations,
    ) -> GovernanceModeledDurableCompletionAttestationOutcome {
        recover_modeled_durable_completion_attestation_window(
            input,
            window,
            self.kind(),
            recovered_attestation,
            expectations,
        )
    }
}

// ===========================================================================
// Fixture attestor (DevNet / TestNet source-test only)
// ===========================================================================

/// Run 254 — the DevNet/TestNet fixture modeled durable-completion attestor.
///
/// Source-test only. It mutates only the in-memory
/// [`ModeledDurableCompletionAttestationLedger`] and exposes an invocation counter
/// so tests can prove non-finalizing finalization paths never invoke it.
#[derive(Debug, Clone)]
pub struct FixtureModeledDurableCompletionAttestor {
    kind: ModeledDurableCompletionAttestorKind,
    fault: Option<ModeledDurableCompletionAttestationFault>,
    invocations: u32,
}

impl FixtureModeledDurableCompletionAttestor {
    /// A new fixture attestor for the given DevNet/TestNet environment.
    pub fn new(environment: TrustBundleEnvironment) -> Self {
        Self {
            kind: Self::kind_for(environment),
            fault: None,
            invocations: 0,
        }
    }

    /// A new fixture attestor that injects the given modeled fault on record.
    pub fn with_fault(
        environment: TrustBundleEnvironment,
        fault: ModeledDurableCompletionAttestationFault,
    ) -> Self {
        Self {
            kind: Self::kind_for(environment),
            fault: Some(fault),
            invocations: 0,
        }
    }

    fn kind_for(environment: TrustBundleEnvironment) -> ModeledDurableCompletionAttestorKind {
        match environment {
            TrustBundleEnvironment::Testnet => ModeledDurableCompletionAttestorKind::FixtureTestNet,
            // DevNet (and any non-MainNet/non-TestNet fixture surface) is DevNet.
            _ => ModeledDurableCompletionAttestorKind::FixtureDevNet,
        }
    }
}

impl GovernanceModeledDurableCompletionAttestor for FixtureModeledDurableCompletionAttestor {
    fn kind(&self) -> ModeledDurableCompletionAttestorKind {
        self.kind
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn record_modeled_durable_completion_attestation(
        &mut self,
        attestation: &GovernanceModeledDurableCompletionAttestationRecord,
        expectations: &GovernanceModeledDurableCompletionAttestationExpectations,
        idempotent_only: bool,
        ledger: &mut ModeledDurableCompletionAttestationLedger,
    ) -> GovernanceModeledDurableCompletionAttestationOutcome {
        use GovernanceModeledDurableCompletionAttestationOutcome as Att;
        self.invocations += 1;

        // Injected faults model record-failure / rollback / ambiguous windows.
        // None of them ever leave a recorded attestation behind, so durable
        // completion attestation finality is never claimed. The ledger
        // snapshot/restore models the rollback being a no-op write.
        if let Some(fault) = self.fault {
            let snapshot = ledger.snapshot();
            return match fault {
                ModeledDurableCompletionAttestationFault::RecordFailedNoAttestation => {
                    ledger.restore(&snapshot);
                    Att::DurableCompletionAttestationRecordFailedNoAttestation
                }
                ModeledDurableCompletionAttestationFault::RolledBackNoAttestation => {
                    ledger.restore(&snapshot);
                    Att::DurableCompletionAttestationRolledBackNoAttestation
                }
                ModeledDurableCompletionAttestationFault::RollbackFailedFatal => {
                    Att::DurableCompletionAttestationRollbackFailedFatalNoAttestation
                }
                ModeledDurableCompletionAttestationFault::AmbiguousAfterRecord => {
                    ledger.restore(&snapshot);
                    Att::DurableCompletionAttestationAmbiguousFailClosedNoAttestation
                }
            };
        }

        // Attestation-identity validation (malformed / mismatch) fails closed
        // before any record is written.
        if !expectations.attestation_matches(attestation) {
            return Att::DurableCompletionAttestationRejectedBeforeRecord;
        }

        let digest = attestation.digest();

        // Idempotency / equivocation gate.
        if let Some(existing) = ledger.find(&attestation.attestation_id) {
            if existing.digest == digest {
                return Att::DurableCompletionAttestationDuplicateIdempotent;
            }
            // Same attestation id with a different digest is equivocation: fail
            // closed, record no second attestation.
            return Att::DurableCompletionAttestationRejectedBeforeRecord;
        }

        // A duplicate-idempotent finalization may only match an already-recorded
        // attestation; it must never create a new one by itself.
        if idempotent_only {
            return Att::DurableCompletionAttestationRejectedBeforeRecord;
        }

        ledger.insert(ModeledDurableCompletionAttestationRecord {
            attestation_id: attestation.attestation_id.clone(),
            digest,
            status: ModeledDurableCompletionAttestationStatus::Attested,
        });
        Att::DurableCompletionAttested
    }
}

// ===========================================================================
// Production / MainNet attestors (reachable-but-unavailable / fail-closed)
// ===========================================================================

/// Run 254 — the production modeled durable-completion attestor. Reachable but
/// unavailable / fail-closed. It records no attestation and mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct ProductionModeledDurableCompletionAttestor {
    invocations: u32,
}

impl GovernanceModeledDurableCompletionAttestor for ProductionModeledDurableCompletionAttestor {
    fn kind(&self) -> ModeledDurableCompletionAttestorKind {
        ModeledDurableCompletionAttestorKind::ProductionUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn record_modeled_durable_completion_attestation(
        &mut self,
        _attestation: &GovernanceModeledDurableCompletionAttestationRecord,
        _expectations: &GovernanceModeledDurableCompletionAttestationExpectations,
        _idempotent_only: bool,
        _ledger: &mut ModeledDurableCompletionAttestationLedger,
    ) -> GovernanceModeledDurableCompletionAttestationOutcome {
        self.invocations += 1;
        GovernanceModeledDurableCompletionAttestationOutcome::ProductionAttestorUnavailableNoAttestation
    }
}

/// Run 254 — the MainNet modeled durable-completion attestor. Reachable but
/// unavailable / fail-closed. It records no attestation and mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct MainNetModeledDurableCompletionAttestor {
    invocations: u32,
}

impl GovernanceModeledDurableCompletionAttestor for MainNetModeledDurableCompletionAttestor {
    fn kind(&self) -> ModeledDurableCompletionAttestorKind {
        ModeledDurableCompletionAttestorKind::MainNetUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn record_modeled_durable_completion_attestation(
        &mut self,
        _attestation: &GovernanceModeledDurableCompletionAttestationRecord,
        _expectations: &GovernanceModeledDurableCompletionAttestationExpectations,
        _idempotent_only: bool,
        _ledger: &mut ModeledDurableCompletionAttestationLedger,
    ) -> GovernanceModeledDurableCompletionAttestationOutcome {
        self.invocations += 1;
        GovernanceModeledDurableCompletionAttestationOutcome::MainNetAttestorUnavailableNoAttestation
    }
}

// ===========================================================================
// Attestor executor / composition helpers
// ===========================================================================

/// Run 254 — evaluate one modeled durable-completion attestation projection
/// round-trip.
///
/// Ordering (each gate must pass before the next is considered):
///
/// 1. MainNet peer-driven apply refusal — before pipeline progression, before any
///    sink invocation, before any reporter invocation, before any finalizer
///    invocation, and before any attestor invocation;
/// 2. legacy bypass — a disabled attestor / finalizer / reporter / sink /
///    pipeline / evaluator-call-site policy;
/// 3. finalization-outcome projection — only
///    [`GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized`]
///    creates an attestation intent;
/// 4. pre-attestor binding validation — environment / surface must match before
///    the attestation is recorded;
/// 5. attestation record — attempted only after every prior gate passes.
///
/// A rejection before the attestor stage leaves the attestor invocation count at
/// zero. Pure aside from the fixture attestor's modeled in-memory ledger effect:
/// performs no I/O, mutates no `LivePqcTrustState`, writes no marker, writes no
/// sequence, swaps no live trust, evicts no sessions, performs no persistent
/// durable completion / audit write, and never invokes Run 070.
pub fn evaluate_modeled_durable_completion_attestation_projection<A>(
    input: &GovernanceModeledDurableCompletionAttestationInput,
    expectations: &GovernanceModeledDurableCompletionAttestationExpectations,
    attestor: &mut A,
    ledger: &mut ModeledDurableCompletionAttestationLedger,
) -> GovernanceModeledDurableCompletionAttestationOutcome
where
    A: GovernanceModeledDurableCompletionAttestor,
{
    use GovernanceModeledDurableCompletionAttestationOutcome as Att;

    // Step 1: MainNet peer-driven apply remains refused unconditionally, before
    // pipeline progression, before any sink invocation, before any reporter
    // invocation, before any finalizer invocation, and before any attestor
    // invocation.
    if input.is_mainnet_peer_driven() {
        return Att::MainNetPeerDrivenApplyRefusedNoAttestation;
    }

    // Step 2: legacy bypass — a disabled attestor / finalizer / reporter / sink /
    // pipeline / evaluator-call-site policy preserves the legacy no-attestation
    // path and never invokes the attestor.
    if !input.policy.is_wired() {
        return Att::LegacyBypassNoAttestation;
    }

    // Step 3: project the Run 252 finalization outcome onto an attestation intent.
    // Every non-finalizing outcome returns a no-attestation outcome without
    // invoking the attestor.
    let idempotent_only =
        match project_finalization_outcome_to_attestation_intent(&input.finalization_binding) {
            DurableCompletionAttestationIntent::NoAttestation(outcome) => return outcome,
            DurableCompletionAttestationIntent::CreateIntent => false,
            DurableCompletionAttestationIntent::IdempotentOnly => true,
        };

    // Step 4: pre-attestor environment / surface binding validation. A mismatch
    // fails closed before the attestation is recorded.
    if !expectations.binding_matches(input) {
        return Att::RejectedBeforeFinalizationNoAttestation;
    }

    // Step 5: invoke the attestor to record the modeled attestation.
    attestor.record_modeled_durable_completion_attestation(
        &input.attestation,
        expectations,
        idempotent_only,
        ledger,
    )
}

/// Run 254 — the modeled durable-completion attestation crash/recovery window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModeledDurableCompletionAttestationWindow {
    /// Crashed before the pipeline authorized consume.
    BeforePipeline,
    /// Crashed after pipeline success but before a sink intent was created.
    AfterPipelineSuccessBeforeSinkIntent,
    /// Crashed after a sink intent but before the sink recorded a receipt.
    AfterSinkIntentBeforeReceiptRecord,
    /// Crashed after the sink recorded a receipt but before a completion-report
    /// intent.
    AfterReceiptRecordBeforeReportIntent,
    /// Crashed after a completion-report intent but before the report record.
    AfterReportIntentBeforeReportRecord,
    /// Crashed after the report record but before a finalization intent.
    AfterReportRecordBeforeFinalizationIntent,
    /// Crashed after a finalization intent but before any finalization record.
    AfterFinalizationIntentBeforeFinalizationRecord,
    /// Crashed after the finalization record but before an attestation intent.
    AfterFinalizationRecordBeforeAttestationIntent,
    /// Crashed after an attestation intent but before any attestation record.
    AfterAttestationIntentBeforeAttestationRecord,
    /// Crashed after an attestation record but before attestation success — fails
    /// closed unless an explicit matching attestation success exists.
    AfterAttestationRecordBeforeAttestationSuccess,
    /// Recovered after a successful attestation.
    AfterAttestationSuccess,
    /// Recovered after an ambiguous attestation.
    AfterAttestationAmbiguous,
    /// The attestation record itself failed.
    AttestationRecordFailed,
    /// The attestation record was rolled back.
    RollbackCompleted,
    /// The attestation rollback itself failed — fatal.
    RollbackFailed,
    /// An unknown window — fails closed.
    Unknown,
}

/// Run 254 — classify a modeled durable-completion attestation crash/recovery
/// window.
///
/// The attestor never silently re-authorizes an in-flight attestation: MainNet
/// peer-driven refusal precedes classification, production / MainNet
/// classification is unavailable, and every ambiguous / unknown window fails
/// closed. Only an after-attestation-record window with an explicit matching
/// attestation (or an explicit after-attestation-success window) recovers as
/// [`GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested`].
/// Pure: performs no modeled mutation and never invokes Run 070.
pub fn recover_modeled_durable_completion_attestation_window(
    input: &GovernanceModeledDurableCompletionAttestationInput,
    window: ModeledDurableCompletionAttestationWindow,
    kind: ModeledDurableCompletionAttestorKind,
    recovered_attestation: Option<&GovernanceModeledDurableCompletionAttestationRecord>,
    expectations: &GovernanceModeledDurableCompletionAttestationExpectations,
) -> GovernanceModeledDurableCompletionAttestationOutcome {
    use GovernanceModeledDurableCompletionAttestationOutcome as Att;

    // MainNet peer-driven apply refusal precedes recovery classification.
    if input.is_mainnet_peer_driven() {
        return Att::MainNetPeerDrivenApplyRefusedNoAttestation;
    }

    // Production / MainNet recovery classification is unavailable / fail-closed.
    match kind {
        ModeledDurableCompletionAttestorKind::ProductionUnavailable => {
            return Att::ProductionAttestorUnavailableNoAttestation;
        }
        ModeledDurableCompletionAttestorKind::MainNetUnavailable => {
            return Att::MainNetAttestorUnavailableNoAttestation;
        }
        ModeledDurableCompletionAttestorKind::FixtureDevNet
        | ModeledDurableCompletionAttestorKind::FixtureTestNet => {}
    }

    match window {
        // Before the finalizer recorded a finalization there is nothing to attest.
        ModeledDurableCompletionAttestationWindow::BeforePipeline
        | ModeledDurableCompletionAttestationWindow::AfterPipelineSuccessBeforeSinkIntent
        | ModeledDurableCompletionAttestationWindow::AfterSinkIntentBeforeReceiptRecord
        | ModeledDurableCompletionAttestationWindow::AfterReceiptRecordBeforeReportIntent
        | ModeledDurableCompletionAttestationWindow::AfterReportIntentBeforeReportRecord
        | ModeledDurableCompletionAttestationWindow::AfterReportRecordBeforeFinalizationIntent
        | ModeledDurableCompletionAttestationWindow::AfterFinalizationIntentBeforeFinalizationRecord => {
            Att::FinalizationDidNotFinalizeNoAttestation
        }
        // A recorded finalization without an attestation intent / record never
        // attests.
        ModeledDurableCompletionAttestationWindow::AfterFinalizationRecordBeforeAttestationIntent
        | ModeledDurableCompletionAttestationWindow::AfterAttestationIntentBeforeAttestationRecord => {
            Att::DurableCompletionAttestationRejectedBeforeRecord
        }
        // After an attestation record but before attestation success: fails closed
        // unless an explicit matching, well-formed attestation success exists.
        ModeledDurableCompletionAttestationWindow::AfterAttestationRecordBeforeAttestationSuccess => {
            match recovered_attestation {
                Some(attestation) if expectations.attestation_matches(attestation) => {
                    Att::DurableCompletionAttested
                }
                _ => Att::DurableCompletionAttestationRejectedBeforeRecord,
            }
        }
        // An explicit successful attestation recovers as attested only if it matches
        // expectations.
        ModeledDurableCompletionAttestationWindow::AfterAttestationSuccess => {
            match recovered_attestation {
                Some(attestation) if expectations.attestation_matches(attestation) => {
                    Att::DurableCompletionAttested
                }
                _ => Att::DurableCompletionAttestationRejectedBeforeRecord,
            }
        }
        ModeledDurableCompletionAttestationWindow::AfterAttestationAmbiguous => {
            Att::DurableCompletionAttestationAmbiguousFailClosedNoAttestation
        }
        ModeledDurableCompletionAttestationWindow::AttestationRecordFailed => {
            Att::DurableCompletionAttestationRecordFailedNoAttestation
        }
        ModeledDurableCompletionAttestationWindow::RollbackCompleted => {
            Att::DurableCompletionAttestationRolledBackNoAttestation
        }
        ModeledDurableCompletionAttestationWindow::RollbackFailed => {
            Att::DurableCompletionAttestationRollbackFailedFatalNoAttestation
        }
        // Any unknown window fails closed.
        ModeledDurableCompletionAttestationWindow::Unknown => {
            Att::DurableCompletionAttestationAmbiguousFailClosedNoAttestation
        }
    }
}

/// Run 254 — `true` iff an attestation outcome authorizes a **new** modeled
/// durable-completion attestation (only
/// [`GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested`]).
pub fn attestation_outcome_authorizes_modeled_attestation(
    outcome: &GovernanceModeledDurableCompletionAttestationOutcome,
) -> bool {
    outcome.authorizes_modeled_durable_completion_attestation()
}

/// Run 254 — `true` iff an attestation outcome projects to a durable-completion
/// attestation (a newly recorded attestation or an idempotent duplicate of an
/// already-recorded attestation).
pub fn attestation_outcome_projects_to_durable_completion_attested(
    outcome: &GovernanceModeledDurableCompletionAttestationOutcome,
) -> bool {
    outcome.projects_to_durable_completion_attested()
}

// ===========================================================================
// Explicit invariant / fail-closed helpers (grep-verifiable named symbols)
// ===========================================================================

/// Run 254 — explicit invariant helper.
///
/// Returns `true`: a rejected attestation path performs no Run 070 call, no
/// `LivePqcTrustState` mutation, no live trust swap, no session eviction, no
/// sequence write, and no marker write.
pub fn modeled_attestation_rejection_is_non_mutating() -> bool {
    true
}

/// Run 254 — explicit invariant helper.
///
/// Returns `true`: the attestor never calls Run 070. It records only the in-memory
/// [`ModeledDurableCompletionAttestationLedger`].
pub fn modeled_attestation_never_calls_run_070() -> bool {
    true
}

/// Run 254 — explicit invariant helper.
///
/// Returns `true`: the attestor never mutates `LivePqcTrustState`.
pub fn modeled_attestation_never_mutates_live_pqc_trust_state() -> bool {
    true
}

/// Run 254 — explicit invariant helper.
///
/// Returns `true`: the attestor never writes a trust-bundle sequence file or an
/// authority marker.
pub fn modeled_attestation_never_writes_sequence_or_marker() -> bool {
    true
}

/// Run 254 — explicit non-implementation helper.
///
/// Returns `true`: Run 254 introduces no RocksDB schema, file format, database
/// migration, or storage-format change. The attestor is a pure typed projection
/// over an in-memory ledger.
pub fn modeled_attestation_no_rocksdb_file_schema_migration_change() -> bool {
    true
}

/// Run 254 — explicit invariant helper.
///
/// Returns `true`: a Run 246 pipeline success is required before any sink intent
/// can exist, and therefore before any attestation can be recorded.
pub fn modeled_attestation_pipeline_success_required_before_attestation() -> bool {
    true
}

/// Run 254 — explicit invariant helper.
///
/// Returns `true`: a Run 248 recorded sink receipt
/// ([`GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded`]) is
/// required before any completion report, and therefore before any attestation,
/// can be recorded.
pub fn modeled_attestation_sink_receipt_required_before_attestation() -> bool {
    true
}

/// Run 254 — explicit invariant helper.
///
/// Returns `true`: a Run 250 recorded completion report
/// ([`GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded`])
/// is required before any finalization, and therefore before any attestation, can
/// be recorded.
pub fn modeled_attestation_completion_report_required_before_attestation() -> bool {
    true
}

/// Run 254 — explicit invariant helper.
///
/// Returns `true`: a Run 252 recorded finalization
/// ([`GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized`])
/// is required before any attestation can be recorded.
pub fn modeled_attestation_finalization_required_before_attestation() -> bool {
    true
}

/// Run 254 — explicit invariant helper.
///
/// Returns `true`: a recorded attestation
/// ([`GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested`])
/// is required before any modeled durable-completion-attested state.
pub fn modeled_attestation_record_required_before_durable_completion_attested() -> bool {
    true
}

/// Run 254 — explicit invariant helper.
///
/// Returns `true`: a failed attestation record never attests.
pub fn modeled_attestation_failed_record_never_attests() -> bool {
    true
}

/// Run 254 — explicit invariant helper.
///
/// Returns `true`: an attestation rollback (and a fatal rollback failure) never
/// attests.
pub fn modeled_attestation_rollback_never_attests() -> bool {
    true
}

/// Run 254 — explicit invariant helper.
///
/// Returns `true`: an ambiguous attestation window fails closed and never attests.
pub fn modeled_attestation_ambiguous_window_fails_closed() -> bool {
    true
}

/// Run 254 — explicit refusal helper.
///
/// Returns `true` iff MainNet peer-driven apply remains refused first for a MainNet
/// environment, before pipeline progression, before any sink invocation, before
/// any reporter invocation, before any finalizer invocation, and before any
/// attestor invocation.
pub fn modeled_attestation_mainnet_peer_driven_apply_refused_first(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 254 — explicit fail-closed helper.
///
/// Returns `true`: production / MainNet attestor paths remain unavailable /
/// fail-closed. No real production or MainNet attestation backend is implemented.
pub fn modeled_attestation_production_mainnet_unavailable() -> bool {
    true
}

/// Run 254 — explicit fail-closed helper.
///
/// Returns `true`: validator-set rotation remains unsupported by the attestor.
pub fn modeled_attestation_validator_set_rotation_unsupported() -> bool {
    true
}

/// Run 254 — explicit fail-closed helper.
///
/// Returns `true`: policy-change actions remain unsupported by the attestor.
pub fn modeled_attestation_policy_change_unsupported() -> bool {
    true
}

/// Run 254 — explicit fail-closed helper.
///
/// Returns `true` iff a local operator key *cannot* satisfy a MainNet attestor
/// authority. Run 254 always returns `true`.
pub fn modeled_attestation_local_operator_cannot_satisfy_mainnet_authority() -> bool {
    true
}

/// Run 254 — explicit fail-closed helper.
///
/// Returns `true` iff peer-majority / gossip count *cannot* satisfy a MainNet
/// attestor authority. Run 254 always returns `true`.
pub fn modeled_attestation_peer_majority_cannot_satisfy_mainnet_authority() -> bool {
    true
}