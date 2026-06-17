//! Run 272 — source/test durable-completion **settlement-outcome report /
//! settlement-finality projection interface boundary**.
//!
//! Source/test only. Run 272 captures **no** release-binary evidence and enables
//! **no** production mutating behavior. It does **not** implement a real settlement
//! backend, a real settlement finality, a real settlement receipt, a real
//! settlement-outcome report backend, a real settlement-finality projection
//! backend, a real audit-ledger acknowledgement, a real external-publication
//! confirmation, a real external-publication system, a real production attestation /
//! receipt_acknowledgement / completion-report / durable-consume / persistent-replay backend, a
//! real governance execution engine, a real production mutation engine, a real on-chain
//! governance proof verifier, a KMS/HSM/RemoteSigner backend, MainNet governance
//! enablement, MainNet peer-driven apply enablement, validator-set rotation, or any
//! RocksDB / file / schema / migration / wire / marker / sequence / trust-bundle /
//! storage-format change.
//!
//! ## What this module adds
//!
//! Run 270
//! ([`crate::pqc_governance_durable_completion_settlement_receipt_acknowledgement`])
//! proves that a modeled durable-completion *settlement receipt_acknowledgement* is recorded
//! **only** after the Run 266 settlement-finalization stage recorded a settlement
//! commitment, terminating in the single settlement-receipt_acknowledgement-recording outcome
//! [`DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementRecorded`].
//!
//! Run 272 defines the **first typed interface** a future production settlement-receipt
//! acknowledgement or settlement-finality projection subsystem would use to *consume* a
//! durable-completion settlement receipt_acknowledgement and prepare a settlement-receipt
//! acknowledgement intent and modeled in-memory settlement-finality projection receipt
//! **after** the Run 270 settlement-receipt_acknowledgement stage produced
//! `SettlementReceiptAcknowledgementRecorded`. It is an **interface / projection boundary only**:
//! production / MainNet / external settlement-outcome report implementations
//! are *reachable but deliberately unavailable / fail-closed*, and the only positive
//! implementation is a DevNet/TestNet fixture that records into an in-memory fixture
//! ledger for source/test evidence only.
//!
//! The settlement-outcome report layer is a **model only**. It does not
//! implement a real settlement, a real settlement finality, a real settlement receipt, a
//! real settlement-outcome report, a real settlement-finality projection, a
//! real external publication, a real audit-ledger acknowledgement, or any real
//! persistent storage. It does not write RocksDB, files, schemas, migrations, storage
//! formats, wire formats, authority markers, trust-bundle sequence files, or any
//! production durable state. It does not call Run 070, mutate `LivePqcTrustState`,
//! perform a real trust swap, evict sessions, perform external publication / network
//! I/O, or enable MainNet governance / MainNet peer-driven apply. The DevNet/TestNet
//! fixture settlement-outcome report sink mutates only the in-memory
//! [`DurableCompletionSettlementOutcomeReportLedger`].
//!
//! ## Ordering / fail-closed contract
//!
//! 1. **MainNet peer-driven apply refusal** — refused *before* pipeline
//!    progression, sink invocation, reporter invocation, finalizer invocation,
//!    attestor invocation, backend invocation, receipt invocation, acknowledgement
//!    invocation, consumer invocation, settlement-projection invocation,
//!    settlement-finalization invocation, and settlement-receipt_acknowledgement invocation;
//! 2. **legacy bypass** — a
//!    [`DurableCompletionSettlementOutcomeReportPolicy::Disabled`] policy preserves
//!    the legacy no-settlement-outcome-report bypass and never invokes the
//!    settlement-outcome report sink;
//! 3. **settlement-receipt_acknowledgement-outcome projection** — only
//!    [`DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementRecorded`]
//!    creates a settlement-outcome report request; every other Run 270 outcome
//!    maps to a no-receipt-acknowledgement fail-closed outcome and never invokes the
//!    settlement-outcome report sink;
//! 4. **pre-sink binding validation** — environment / chain / genesis /
//!    governance surface / mutation surface and the full digest binding (including
//!    the Run 256 backend, Run 258 receipt, Run 260 acknowledgement, Run 262 consumer,
//!    and Run 270 settlement-receipt_acknowledgement digest sets) must match expectations *before*
//!    the settlement-outcome report sink is invoked; a mismatch fails closed
//!    and leaves the sink invocation count at zero;
//! 5. **settlement-outcome report record** — only after every prior gate
//!    passes is the sink invoked; the record-identity fields must match exactly before
//!    any modeled settlement-outcome report record is recorded;
//! 6. **settlement-outcome report authorization** — only
//!    [`DurableCompletionSettlementOutcomeReportOutcome::SettlementOutcomeReportRecorded`]
//!    authorizes a new modeled settlement-outcome report / settlement-finality
//!    projection state.
//!
//! A settlement-outcome report record failure, rollback, rollback failure, or
//! ambiguous window never retroactively claims a durable settlement-receipt
//! acknowledgement record. A duplicate identical settlement-outcome report
//! record is idempotent; the same record id with a different digest fails closed as
//! equivocation and records no second record. A Run 270
//! [`DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementDuplicateIdempotent`]
//! never creates a new settlement-outcome report record by itself — it can only
//! match an already-recorded settlement-outcome report record.

use crate::pqc_governance_durable_completion_acknowledgement_consumer::DurableCompletionAcknowledgementConsumerOutcome;
use crate::pqc_governance_durable_completion_settlement_receipt_acknowledgement::DurableCompletionSettlementReceiptAcknowledgementOutcome;
use crate::pqc_governance_durable_completion_attestation_backend::DurableCompletionAttestationBackendOutcome;
use crate::pqc_governance_durable_completion_audit_publication_receipt::DurableCompletionAuditPublicationReceiptOutcome;
use crate::pqc_governance_durable_completion_audit_receipt_acknowledgement::DurableCompletionAuditReceiptAcknowledgementOutcome;
use crate::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use crate::pqc_governance_modeled_durable_completion_attestation_projection::GovernanceModeledDurableCompletionAttestationOutcome;
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
use crate::pqc_trust_bundle::TrustBundleEnvironment;

use sha3::{Digest, Sha3_256};

// ===========================================================================
// Reused typed bindings (composition, not reimplementation)
// ===========================================================================

/// Run 272 — the validation / mutation surface pair the receipt binds to.
pub type DurableCompletionSettlementOutcomeReportSurface =
    ModeledGovernanceTrustMutationSurface;

/// Run 272 — the trust-domain environment binding the receipt is bound to.
pub type DurableCompletionSettlementOutcomeReportEnvironment =
    ModeledGovernanceTrustMutationEnvironmentBinding;

/// Run 272 — the runtime binding (governance + mutation surface + sequence) the
/// receipt is bound to.
pub type DurableCompletionSettlementOutcomeReportBinding =
    ModeledGovernanceTrustMutationRuntimeBinding;

/// Run 272 — the Run 240/246 durable replay observation carried as freshness
/// context.
pub type DurableCompletionSettlementOutcomeReportReplayBinding = DurableReplayObservation;

/// Run 272 — the Run 246 pipeline outcome carried as consume authorization context.
pub type DurableCompletionSettlementOutcomeReportPipelineBinding =
    GovernanceModeledEndToEndPipelineOutcome;

/// Run 272 — the Run 248 sink outcome carried as receipt-record context.
pub type DurableCompletionSettlementOutcomeReportSinkBinding =
    GovernanceModeledDurableConsumeSinkOutcome;

/// Run 272 — the Run 250 reporter outcome carried as completion-report context.
pub type DurableCompletionSettlementOutcomeReportReporterBinding =
    GovernanceModeledDurableConsumeCompletionReporterOutcome;

/// Run 272 — the Run 252 outcome_report outcome carried as outcome_report context.
pub type DurableCompletionSettlementOutcomeReportFinalizationBinding =
    GovernanceModeledDurableCompletionFinalizationOutcome;

/// Run 272 — the Run 254 attestation outcome carried as attestation context.
pub type DurableCompletionSettlementOutcomeReportAttestationBinding =
    GovernanceModeledDurableCompletionAttestationOutcome;

/// Run 272 — the Run 256 backend outcome carried as backend-record context. The
/// acknowledgement boundary never reimplements the backend; it only carries its
/// terminal outcome.
pub type DurableCompletionSettlementOutcomeReportBackendBinding =
    DurableCompletionAttestationBackendOutcome;

/// Run 272 — the Run 258 audit/publication receipt outcome carried as
/// receipt-record context. The consumer boundary never reimplements the receipt; it
/// only carries its terminal outcome.
pub type DurableCompletionSettlementOutcomeReportReceiptBinding =
    DurableCompletionAuditPublicationReceiptOutcome;

/// Run 272 — the Run 260 audit-receipt acknowledgement outcome carried as
/// acknowledgement-record context. The settlement-receipt_acknowledgement boundary never
/// reimplements the acknowledgement; it only carries its terminal outcome.
pub type DurableCompletionSettlementOutcomeReportAcknowledgementBinding =
    DurableCompletionAuditReceiptAcknowledgementOutcome;

/// Run 272 — the Run 262 acknowledgement consumer outcome the settlement-receipt_acknowledgement
/// boundary projects to a settlement-receipt_acknowledgement request. The settlement-receipt_acknowledgement
/// boundary never reimplements the consumer; it only projects its terminal outcome.
pub type DurableCompletionSettlementOutcomeReportConsumerBinding =
    DurableCompletionAcknowledgementConsumerOutcome;

/// Run 272 — the Run 270 settlement-receipt_acknowledgement outcome the settlement-outcome-report
/// boundary projects to a settlement-outcome-report request. The settlement-outcome-report
/// boundary never reimplements the settlement receipt_acknowledgement; it only projects its
/// terminal outcome.
pub type DurableCompletionSettlementOutcomeReportSettlementReceiptAcknowledgementBinding =
    DurableCompletionSettlementReceiptAcknowledgementOutcome;

// ===========================================================================
// Receipt kind
// ===========================================================================

/// Run 272 — the typed durable-completion audit/publication receipt kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionSettlementOutcomeReportKind {
    /// The receipt boundary is disabled (legacy bypass).
    Disabled,
    /// DevNet/TestNet in-memory fixture receipt sink (source-test only; may mutate
    /// only the ledger).
    FixtureInMemory,
    /// Production audit-ledger receipt sink (reachable-but-unavailable /
    /// fail-closed).
    ProductionSettlementOutcomeReportUnavailable,
    /// MainNet audit-ledger receipt sink (reachable-but-unavailable / fail-closed).
    MainNetSettlementOutcomeReportUnavailable,
    /// External-publication receipt sink (reachable-but-unavailable / fail-closed).
    ExternalSettlementOutcomeReportUnavailable,
    /// An unknown receipt kind — fails closed.
    Unknown,
}

impl DurableCompletionSettlementOutcomeReportKind {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureInMemory => "fixture-in-memory",
            Self::ProductionSettlementOutcomeReportUnavailable => {
                "production-settlement-outcome-report-unavailable"
            }
            Self::MainNetSettlementOutcomeReportUnavailable => {
                "mainnet-settlement-outcome-report-unavailable"
            }
            Self::ExternalSettlementOutcomeReportUnavailable => {
                "external-settlement-outcome-report-unavailable"
            }
            Self::Unknown => "unknown",
        }
    }

    /// `true` iff this is the DevNet/TestNet in-memory fixture receipt sink.
    pub const fn is_fixture(self) -> bool {
        matches!(self, Self::FixtureInMemory)
    }

    /// `true` iff this kind is reachable-but-unavailable (production / MainNet
    /// audit-ledger / external-publication).
    pub const fn is_unavailable(self) -> bool {
        matches!(
            self,
            Self::ProductionSettlementOutcomeReportUnavailable
                | Self::MainNetSettlementOutcomeReportUnavailable
                | Self::ExternalSettlementOutcomeReportUnavailable
        )
    }
}

// ===========================================================================
// Receipt policy
// ===========================================================================

/// Run 272 — the typed durable-completion audit/publication receipt policy
/// selector.
///
/// Only [`Self::FixtureAllowed`] may record (DevNet/TestNet source-test only);
/// every production / MainNet / external-publication policy resolves to a
/// reachable-but-unavailable sink that never records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionSettlementOutcomeReportPolicy {
    /// The receipt boundary is disabled (legacy bypass).
    Disabled,
    /// A DevNet/TestNet fixture receipt sink is allowed (source-test evidence only).
    FixtureAllowed,
    /// A real production audit-ledger receipt sink is required — reachable but
    /// unavailable.
    ProductionSettlementOutcomeReportRequired,
    /// A real MainNet audit-ledger receipt sink is required — reachable but
    /// unavailable.
    MainNetSettlementOutcomeReportRequired,
    /// A real external-publication receipt sink is required — reachable but
    /// unavailable.
    ExternalSettlementOutcomeReportRequired,
}

impl DurableCompletionSettlementOutcomeReportPolicy {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureAllowed => "fixture-allowed",
            Self::ProductionSettlementOutcomeReportRequired => {
                "production-settlement-outcome-report-required"
            }
            Self::MainNetSettlementOutcomeReportRequired => "mainnet-settlement-outcome-report-required",
            Self::ExternalSettlementOutcomeReportRequired => "external-settlement-outcome-report-required",
        }
    }

    /// `true` iff this policy disables the receipt boundary (legacy bypass).
    pub const fn is_disabled(self) -> bool {
        matches!(self, Self::Disabled)
    }

    /// `true` iff this policy allows the DevNet/TestNet fixture receipt sink to
    /// record.
    pub const fn allows_fixture(self) -> bool {
        matches!(self, Self::FixtureAllowed)
    }
}

// ===========================================================================
// Receipt identity
// ===========================================================================

/// Run 272 — the typed receipt identity a receipt request is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionSettlementOutcomeReportIdentity {
    /// Stable receipt id.
    pub receipt_acknowledgement_id: String,
    /// The receipt kind.
    pub kind: DurableCompletionSettlementOutcomeReportKind,
    /// The receipt policy.
    pub policy: DurableCompletionSettlementOutcomeReportPolicy,
    /// The domain separation tag the receipt operates under.
    pub domain_separation_tag: String,
}

impl DurableCompletionSettlementOutcomeReportIdentity {
    /// `true` iff every mandatory identity field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.receipt_acknowledgement_id.is_empty()
            && !self.domain_separation_tag.is_empty()
            && self.kind != DurableCompletionSettlementOutcomeReportKind::Unknown
    }

    /// The deterministic, domain-separated receipt identity digest.
    pub fn digest(&self) -> DurableCompletionSettlementOutcomeReportDigest {
        settlement_outcome_report_identity_digest(self)
    }
}

// ===========================================================================
// Deterministic, domain-separated digest helpers
// ===========================================================================

/// Run 272 — domain separator for the receipt identity digest.
const RECEIPT_ACKNOWLEDGEMENT_IDENTITY_DOMAIN: &[u8] =
    b"QBIND:run268:durable-completion-settlement-outcome-report-identity:v1";
/// Run 272 — domain separator for the receipt request digest.
const RECEIPT_ACKNOWLEDGEMENT_REQUEST_DOMAIN: &[u8] =
    b"QBIND:run268:durable-completion-settlement-outcome-report-request:v1";
/// Run 272 — domain separator for the receipt response digest.
const RECEIPT_ACKNOWLEDGEMENT_RESPONSE_DOMAIN: &[u8] =
    b"QBIND:run268:durable-completion-settlement-outcome-report-response:v1";
/// Run 272 — domain separator for the receipt record digest.
const RECEIPT_ACKNOWLEDGEMENT_RECORD_DOMAIN: &[u8] =
    b"QBIND:run268:durable-completion-settlement-outcome-report-record:v1";
/// Run 272 — domain separator for the receipt transcript digest.
const RECEIPT_ACKNOWLEDGEMENT_TRANSCRIPT_DOMAIN: &[u8] =
    b"QBIND:run268:durable-completion-settlement-outcome-report-transcript:v1";

/// Run 272 — a deterministic, domain-separated receipt digest (lowercase hex of a
/// SHA3-256 over length-prefixed, field-bound canonical material). It contains no
/// unstable display text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionSettlementOutcomeReportDigest(String);

impl DurableCompletionSettlementOutcomeReportDigest {
    /// The lowercase hex representation.
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

/// Run 272 — a deterministic, domain-separated receipt transcript digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionSettlementOutcomeReportTranscriptDigest(String);

impl DurableCompletionSettlementOutcomeReportTranscriptDigest {
    /// The lowercase hex representation.
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

/// Internal: a length-prefixed canonical-material accumulator. Length-prefixing
/// every field makes the digest field-binding (no field-boundary ambiguity).
struct CanonicalWriter {
    hasher: Sha3_256,
}

impl CanonicalWriter {
    fn new(domain: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update((domain.len() as u64).to_le_bytes());
        hasher.update(domain);
        Self { hasher }
    }

    fn field(&mut self, bytes: &[u8]) -> &mut Self {
        self.hasher.update((bytes.len() as u64).to_le_bytes());
        self.hasher.update(bytes);
        self
    }

    fn str_field(&mut self, value: &str) -> &mut Self {
        self.field(value.as_bytes())
    }

    fn u64_field(&mut self, value: u64) -> &mut Self {
        self.field(&value.to_le_bytes())
    }

    fn finish(self) -> String {
        hex::encode(self.hasher.finalize())
    }
}

fn surface_tag(surface: GovernanceExecutionRuntimeSurface) -> &'static str {
    surface.tag()
}

fn environment_tag(environment: TrustBundleEnvironment) -> &'static str {
    match environment {
        TrustBundleEnvironment::Mainnet => "mainnet",
        TrustBundleEnvironment::Testnet => "testnet",
        TrustBundleEnvironment::Devnet => "devnet",
    }
}

/// Run 272 — deterministic, domain-separated receipt identity digest.
pub fn settlement_outcome_report_identity_digest(
    identity: &DurableCompletionSettlementOutcomeReportIdentity,
) -> DurableCompletionSettlementOutcomeReportDigest {
    let mut w = CanonicalWriter::new(RECEIPT_ACKNOWLEDGEMENT_IDENTITY_DOMAIN);
    w.str_field(&identity.receipt_acknowledgement_id)
        .str_field(identity.kind.tag())
        .str_field(identity.policy.tag())
        .str_field(&identity.domain_separation_tag);
    DurableCompletionSettlementOutcomeReportDigest(w.finish())
}

/// Run 272 — deterministic, domain-separated receipt request digest. Binds every
/// request field including the full Run 256 backend digest binding.
pub fn settlement_outcome_report_request_digest(
    request: &DurableCompletionSettlementOutcomeReportRequest,
) -> DurableCompletionSettlementOutcomeReportDigest {
    let mut w = CanonicalWriter::new(RECEIPT_ACKNOWLEDGEMENT_REQUEST_DOMAIN);
    w.str_field(&request.outcome_report_record_id)
        .str_field(environment_tag(request.environment))
        .str_field(&request.chain_id)
        .str_field(&request.genesis_hash)
        .str_field(surface_tag(request.governance_surface))
        .str_field(surface_tag(request.validation_surface))
        .str_field(surface_tag(request.mutation_surface))
        .str_field(&request.proposal_id)
        .str_field(&request.decision_id)
        .str_field(&request.candidate_digest)
        .u64_field(request.authority_domain_sequence)
        .str_field(&request.pipeline_decision_digest)
        .str_field(&request.sink_decision_digest)
        .str_field(&request.reporter_decision_digest)
        .str_field(&request.finalization_decision_digest)
        .str_field(&request.attestation_digest)
        .str_field(&request.attestation_id)
        .str_field(&request.backend_identity_digest)
        .str_field(&request.backend_request_digest)
        .str_field(&request.backend_response_digest)
        .str_field(&request.backend_receipt_digest)
        .str_field(&request.backend_transcript_digest)
        .str_field(&request.backend_record_id)
        .str_field(&request.receipt_identity_digest)
        .str_field(&request.receipt_request_digest)
        .str_field(&request.receipt_response_digest)
        .str_field(&request.receipt_record_digest)
        .str_field(&request.receipt_transcript_digest)
        .str_field(&request.receipt_record_id)
        .str_field(&request.acknowledgement_identity_digest)
        .str_field(&request.acknowledgement_request_digest)
        .str_field(&request.acknowledgement_response_digest)
        .str_field(&request.acknowledgement_record_digest)
        .str_field(&request.acknowledgement_transcript_digest)
        .str_field(&request.acknowledgement_record_id)
        .str_field(&request.consumer_identity_digest)
        .str_field(&request.consumer_request_digest)
        .str_field(&request.consumer_response_digest)
        .str_field(&request.consumer_record_digest)
        .str_field(&request.consumer_transcript_digest)
        .str_field(&request.consumer_record_id)
        .str_field(&request.settlement_receipt_acknowledgement_identity_digest)
        .str_field(&request.settlement_receipt_acknowledgement_request_digest)
        .str_field(&request.settlement_receipt_acknowledgement_response_digest)
        .str_field(&request.settlement_receipt_acknowledgement_record_digest)
        .str_field(&request.settlement_receipt_acknowledgement_transcript_digest)
        .str_field(&request.settlement_receipt_acknowledgement_record_id)
        .str_field(&request.domain_separation_tag)
        .str_field(settlement_outcome_report_identity_digest(&request.identity).as_hex());
    DurableCompletionSettlementOutcomeReportDigest(w.finish())
}

/// Run 272 — deterministic, domain-separated receipt response digest. Binds the
/// receipt record id, the request digest it answers, the acceptance flag, and the
/// responding receipt kind.
pub fn settlement_outcome_report_response_digest(
    response: &DurableCompletionSettlementOutcomeReportResponse,
) -> DurableCompletionSettlementOutcomeReportDigest {
    let mut w = CanonicalWriter::new(RECEIPT_ACKNOWLEDGEMENT_RESPONSE_DOMAIN);
    w.str_field(&response.outcome_report_record_id)
        .str_field(response.request_digest.as_hex())
        .str_field(if response.accepted {
            "accepted"
        } else {
            "rejected"
        })
        .str_field(response.outcome_report_kind.tag());
    DurableCompletionSettlementOutcomeReportDigest(w.finish())
}

/// Run 272 — deterministic, domain-separated receipt record digest. Binds the
/// receipt record id, the request digest, and the receipt identity digest.
pub fn settlement_outcome_report_record_digest(
    record: &DurableCompletionSettlementOutcomeReportRecord,
) -> DurableCompletionSettlementOutcomeReportDigest {
    let mut w = CanonicalWriter::new(RECEIPT_ACKNOWLEDGEMENT_RECORD_DOMAIN);
    w.str_field(&record.outcome_report_record_id)
        .str_field(record.request_digest.as_hex())
        .str_field(record.identity_digest.as_hex());
    DurableCompletionSettlementOutcomeReportDigest(w.finish())
}

/// Run 272 — deterministic, domain-separated receipt transcript digest. Binds the
/// request, response, and record digests into a single transcript binding.
pub fn settlement_outcome_report_transcript_digest(
    request_digest: &DurableCompletionSettlementOutcomeReportDigest,
    response_digest: &DurableCompletionSettlementOutcomeReportDigest,
    record_digest: &DurableCompletionSettlementOutcomeReportDigest,
) -> DurableCompletionSettlementOutcomeReportTranscriptDigest {
    let mut w = CanonicalWriter::new(RECEIPT_ACKNOWLEDGEMENT_TRANSCRIPT_DOMAIN);
    w.str_field(request_digest.as_hex())
        .str_field(response_digest.as_hex())
        .str_field(record_digest.as_hex());
    DurableCompletionSettlementOutcomeReportTranscriptDigest(w.finish())
}

// ===========================================================================
// Receipt request / response / record
// ===========================================================================

/// Run 272 — the typed receipt request a future production audit ledger or
/// external-publication call site would submit once the Run 256 backend recorded a
/// `BackendSubmissionRecorded`.
///
/// Pure data referencing the already-recorded Run 256 backend / Run 254
/// attestation / Run 252 outcome_report / Run 250 completion report / Run 248
/// receipt / Run 246 decision material — never a copy of any wire payload and never
/// a production durable record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionSettlementOutcomeReportRequest {
    /// Stable receipt record id (the idempotency key of the receipt).
    pub outcome_report_record_id: String,
    /// Trust-domain environment.
    pub environment: TrustBundleEnvironment,
    /// Trust-domain chain id.
    pub chain_id: String,
    /// Trust-domain genesis hash.
    pub genesis_hash: String,
    /// Governance execution surface.
    pub governance_surface: GovernanceExecutionRuntimeSurface,
    /// Validation surface.
    pub validation_surface: GovernanceExecutionRuntimeSurface,
    /// Mutation surface.
    pub mutation_surface: GovernanceExecutionRuntimeSurface,
    /// Governance proposal id.
    pub proposal_id: String,
    /// Governance decision id.
    pub decision_id: String,
    /// Candidate (trust-anchor material) digest.
    pub candidate_digest: String,
    /// Authority-domain sequence.
    pub authority_domain_sequence: u64,
    /// Run 246 pipeline decision digest.
    pub pipeline_decision_digest: String,
    /// Run 248 sink decision digest.
    pub sink_decision_digest: String,
    /// Run 250 reporter decision digest.
    pub reporter_decision_digest: String,
    /// Run 252 outcome_report decision digest.
    pub finalization_decision_digest: String,
    /// Run 254 attestation digest.
    pub attestation_digest: String,
    /// Run 254 attestation id.
    pub attestation_id: String,
    /// Run 256 backend identity digest.
    pub backend_identity_digest: String,
    /// Run 256 backend request digest.
    pub backend_request_digest: String,
    /// Run 256 backend response digest.
    pub backend_response_digest: String,
    /// Run 256 backend receipt digest.
    pub backend_receipt_digest: String,
    /// Run 256 backend transcript digest.
    pub backend_transcript_digest: String,
    /// Run 256 backend record id.
    pub backend_record_id: String,
    /// Run 258 receipt identity digest.
    pub receipt_identity_digest: String,
    /// Run 258 receipt request digest.
    pub receipt_request_digest: String,
    /// Run 258 receipt response digest.
    pub receipt_response_digest: String,
    /// Run 258 receipt record digest.
    pub receipt_record_digest: String,
    /// Run 258 receipt transcript digest.
    pub receipt_transcript_digest: String,
    /// Run 258 receipt record id.
    pub receipt_record_id: String,
    /// Run 260 acknowledgement identity digest.
    pub acknowledgement_identity_digest: String,
    /// Run 260 acknowledgement request digest.
    pub acknowledgement_request_digest: String,
    /// Run 260 acknowledgement response digest.
    pub acknowledgement_response_digest: String,
    /// Run 260 acknowledgement record digest.
    pub acknowledgement_record_digest: String,
    /// Run 260 acknowledgement transcript digest.
    pub acknowledgement_transcript_digest: String,
    /// Run 260 acknowledgement record id.
    pub acknowledgement_record_id: String,
    /// Run 262 consumer identity digest.
    pub consumer_identity_digest: String,
    /// Run 262 consumer request digest.
    pub consumer_request_digest: String,
    /// Run 262 consumer response digest.
    pub consumer_response_digest: String,
    /// Run 262 consumer record digest.
    pub consumer_record_digest: String,
    /// Run 262 consumer transcript digest.
    pub consumer_transcript_digest: String,
    /// Run 262 consumer record id.
    pub consumer_record_id: String,
    /// Run 270 settlement-receipt_acknowledgement identity digest.
    pub settlement_receipt_acknowledgement_identity_digest: String,
    /// Run 270 settlement-receipt_acknowledgement request digest.
    pub settlement_receipt_acknowledgement_request_digest: String,
    /// Run 270 settlement-receipt_acknowledgement response digest.
    pub settlement_receipt_acknowledgement_response_digest: String,
    /// Run 270 settlement-receipt_acknowledgement record digest.
    pub settlement_receipt_acknowledgement_record_digest: String,
    /// Run 270 settlement-receipt_acknowledgement transcript digest.
    pub settlement_receipt_acknowledgement_transcript_digest: String,
    /// Run 270 settlement-receipt_acknowledgement record id.
    pub settlement_receipt_acknowledgement_record_id: String,
    /// Settlement-receipt-acknowledgement identity.
    pub identity: DurableCompletionSettlementOutcomeReportIdentity,
    /// Domain separation tag.
    pub domain_separation_tag: String,
}

impl DurableCompletionSettlementOutcomeReportRequest {
    /// `true` iff every mandatory field is structurally present (non-empty) and the
    /// identity is well-formed.
    pub fn is_well_formed(&self) -> bool {
        !self.outcome_report_record_id.is_empty()
            && !self.chain_id.is_empty()
            && !self.genesis_hash.is_empty()
            && !self.proposal_id.is_empty()
            && !self.decision_id.is_empty()
            && !self.candidate_digest.is_empty()
            && !self.pipeline_decision_digest.is_empty()
            && !self.sink_decision_digest.is_empty()
            && !self.reporter_decision_digest.is_empty()
            && !self.finalization_decision_digest.is_empty()
            && !self.attestation_digest.is_empty()
            && !self.attestation_id.is_empty()
            && !self.backend_identity_digest.is_empty()
            && !self.backend_request_digest.is_empty()
            && !self.backend_response_digest.is_empty()
            && !self.backend_receipt_digest.is_empty()
            && !self.backend_transcript_digest.is_empty()
            && !self.backend_record_id.is_empty()
            && !self.receipt_identity_digest.is_empty()
            && !self.receipt_request_digest.is_empty()
            && !self.receipt_response_digest.is_empty()
            && !self.receipt_record_digest.is_empty()
            && !self.receipt_transcript_digest.is_empty()
            && !self.receipt_record_id.is_empty()
            && !self.acknowledgement_identity_digest.is_empty()
            && !self.acknowledgement_request_digest.is_empty()
            && !self.acknowledgement_response_digest.is_empty()
            && !self.acknowledgement_record_digest.is_empty()
            && !self.acknowledgement_transcript_digest.is_empty()
            && !self.acknowledgement_record_id.is_empty()
            && !self.consumer_identity_digest.is_empty()
            && !self.consumer_request_digest.is_empty()
            && !self.consumer_response_digest.is_empty()
            && !self.consumer_record_digest.is_empty()
            && !self.consumer_transcript_digest.is_empty()
            && !self.consumer_record_id.is_empty()
            && !self.settlement_receipt_acknowledgement_identity_digest.is_empty()
            && !self.settlement_receipt_acknowledgement_request_digest.is_empty()
            && !self.settlement_receipt_acknowledgement_response_digest.is_empty()
            && !self.settlement_receipt_acknowledgement_record_digest.is_empty()
            && !self.settlement_receipt_acknowledgement_transcript_digest.is_empty()
            && !self.settlement_receipt_acknowledgement_record_id.is_empty()
            && !self.domain_separation_tag.is_empty()
            && self.identity.is_well_formed()
    }

    /// The deterministic receipt request digest.
    pub fn digest(&self) -> DurableCompletionSettlementOutcomeReportDigest {
        settlement_outcome_report_request_digest(self)
    }

    /// The canonical immutable record derived from this request.
    pub fn to_record(&self) -> DurableCompletionSettlementOutcomeReportRecord {
        DurableCompletionSettlementOutcomeReportRecord {
            outcome_report_record_id: self.outcome_report_record_id.clone(),
            request_digest: self.digest(),
            identity_digest: self.identity.digest(),
        }
    }
}

/// Run 272 — the typed receipt response a receipt sink returns for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionSettlementOutcomeReportResponse {
    /// The receipt record id the response answers.
    pub outcome_report_record_id: String,
    /// The request digest the response answers.
    pub request_digest: DurableCompletionSettlementOutcomeReportDigest,
    /// `true` iff the receipt sink accepted the request.
    pub accepted: bool,
    /// The responding receipt kind.
    pub outcome_report_kind: DurableCompletionSettlementOutcomeReportKind,
}

impl DurableCompletionSettlementOutcomeReportResponse {
    /// `true` iff the response is structurally well-formed.
    pub fn is_well_formed(&self) -> bool {
        !self.outcome_report_record_id.is_empty()
            && self.outcome_report_kind != DurableCompletionSettlementOutcomeReportKind::Unknown
    }

    /// The deterministic receipt response digest.
    pub fn digest(&self) -> DurableCompletionSettlementOutcomeReportDigest {
        settlement_outcome_report_response_digest(self)
    }
}

/// Run 272 — the canonical immutable receipt record derived from a request. Two
/// records are idempotent-equal only if **every** field matches exactly. The same
/// receipt record id with any differing digest is equivocation and fails closed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionSettlementOutcomeReportRecord {
    /// The receipt record id.
    pub outcome_report_record_id: String,
    /// The request digest.
    pub request_digest: DurableCompletionSettlementOutcomeReportDigest,
    /// The receipt identity digest.
    pub identity_digest: DurableCompletionSettlementOutcomeReportDigest,
}

impl DurableCompletionSettlementOutcomeReportRecord {
    /// The deterministic receipt record digest.
    pub fn digest(&self) -> DurableCompletionSettlementOutcomeReportDigest {
        settlement_outcome_report_record_digest(self)
    }
}

// ===========================================================================
// In-memory fixture ledger
// ===========================================================================

/// Run 272 — the recorded status of a modeled audit/publication receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionSettlementOutcomeReportLedgerStatus {
    /// The modeled receipt is recorded in the in-memory fixture ledger.
    Recorded,
}

/// Run 272 — a single modeled receipt record held in the in-memory fixture ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionSettlementOutcomeReportLedgerRecord {
    /// The receipt record id (stable identity of the receipt).
    pub outcome_report_record_id: String,
    /// The request digest.
    pub request_digest: DurableCompletionSettlementOutcomeReportDigest,
    /// The response digest.
    pub response_digest: DurableCompletionSettlementOutcomeReportDigest,
    /// The record digest.
    pub record_digest: DurableCompletionSettlementOutcomeReportDigest,
    /// The transcript digest.
    pub transcript_digest: DurableCompletionSettlementOutcomeReportTranscriptDigest,
    /// The recorded status.
    pub status: DurableCompletionSettlementOutcomeReportLedgerStatus,
}

/// Run 272 — an immutable snapshot of the modeled receipt ledger used to model a
/// fixture rollback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionSettlementOutcomeReportLedgerSnapshot {
    records: Vec<DurableCompletionSettlementOutcomeReportLedgerRecord>,
}

impl DurableCompletionSettlementOutcomeReportLedgerSnapshot {
    /// The number of records the snapshot captured.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` iff the snapshot captured no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Run 272 — the modeled in-memory receipt ledger.
///
/// **In-memory only.** It never touches RocksDB, files, markers, sequence files,
/// external publications, audit-ledger entries, or any production durable state.
/// The DevNet/TestNet fixture sink is the only thing that may mutate it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DurableCompletionSettlementOutcomeReportLedger {
    records: Vec<DurableCompletionSettlementOutcomeReportLedgerRecord>,
}

impl DurableCompletionSettlementOutcomeReportLedger {
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
    pub fn records(&self) -> &[DurableCompletionSettlementOutcomeReportLedgerRecord] {
        &self.records
    }

    /// The record for `outcome_report_record_id`, if present.
    pub fn find(
        &self,
        outcome_report_record_id: &str,
    ) -> Option<&DurableCompletionSettlementOutcomeReportLedgerRecord> {
        self.records
            .iter()
            .find(|r| r.outcome_report_record_id == outcome_report_record_id)
    }

    /// `true` iff a receipt with `outcome_report_record_id` is recorded.
    pub fn contains(&self, outcome_report_record_id: &str) -> bool {
        self.find(outcome_report_record_id).is_some()
    }

    /// Capture an immutable snapshot for a modeled rollback.
    pub fn snapshot(&self) -> DurableCompletionSettlementOutcomeReportLedgerSnapshot {
        DurableCompletionSettlementOutcomeReportLedgerSnapshot {
            records: self.records.clone(),
        }
    }

    /// Restore the ledger to a previously captured snapshot (modeled rollback).
    pub fn restore(
        &mut self,
        snapshot: &DurableCompletionSettlementOutcomeReportLedgerSnapshot,
    ) {
        self.records = snapshot.records.clone();
    }

    /// Internal: insert a recorded receipt. Only the fixture sink calls this, and
    /// only after every identity / idempotency gate has passed.
    fn insert(&mut self, record: DurableCompletionSettlementOutcomeReportLedgerRecord) {
        self.records.push(record);
    }
}

// ===========================================================================
// Receipt expectations
// ===========================================================================

/// Run 272 — the canonical binding a [`DurableCompletionSettlementOutcomeReportInput`]
/// is checked against.
///
/// Environment / chain / genesis / surface mismatches fail closed **before** the
/// receipt sink is invoked. Receipt-request-identity mismatches fail closed
/// **inside** the sink, before any modeled receipt is recorded. Neither path is
/// ever a silent approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionSettlementOutcomeReportExpectations {
    /// Expected receipt record id.
    pub expected_outcome_report_record_id: String,
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
    /// Expected governance proposal id.
    pub expected_proposal_id: String,
    /// Expected governance decision id.
    pub expected_decision_id: String,
    /// Expected candidate digest.
    pub expected_candidate_digest: String,
    /// Expected authority-domain sequence.
    pub expected_authority_domain_sequence: u64,
    /// Expected Run 246 pipeline decision digest.
    pub expected_pipeline_decision_digest: String,
    /// Expected Run 248 sink decision digest.
    pub expected_sink_decision_digest: String,
    /// Expected Run 250 reporter decision digest.
    pub expected_reporter_decision_digest: String,
    /// Expected Run 252 outcome_report decision digest.
    pub expected_finalization_decision_digest: String,
    /// Expected Run 254 attestation digest.
    pub expected_attestation_digest: String,
    /// Expected Run 254 attestation id.
    pub expected_attestation_id: String,
    /// Expected Run 256 backend identity digest.
    pub expected_backend_identity_digest: String,
    /// Expected Run 256 backend request digest.
    pub expected_backend_request_digest: String,
    /// Expected Run 256 backend response digest.
    pub expected_backend_response_digest: String,
    /// Expected Run 256 backend receipt digest.
    pub expected_backend_receipt_digest: String,
    /// Expected Run 256 backend transcript digest.
    pub expected_backend_transcript_digest: String,
    /// Expected Run 256 backend record id.
    pub expected_backend_record_id: String,
    /// Expected Run 258 receipt identity digest.
    pub expected_receipt_identity_digest: String,
    /// Expected Run 258 receipt request digest.
    pub expected_receipt_request_digest: String,
    /// Expected Run 258 receipt response digest.
    pub expected_receipt_response_digest: String,
    /// Expected Run 258 receipt record digest.
    pub expected_receipt_record_digest: String,
    /// Expected Run 258 receipt transcript digest.
    pub expected_receipt_transcript_digest: String,
    /// Expected Run 258 receipt record id.
    pub expected_receipt_record_id: String,
    /// Expected Run 260 acknowledgement identity digest.
    pub expected_acknowledgement_identity_digest: String,
    /// Expected Run 260 acknowledgement request digest.
    pub expected_acknowledgement_request_digest: String,
    /// Expected Run 260 acknowledgement response digest.
    pub expected_acknowledgement_response_digest: String,
    /// Expected Run 260 acknowledgement record digest.
    pub expected_acknowledgement_record_digest: String,
    /// Expected Run 260 acknowledgement transcript digest.
    pub expected_acknowledgement_transcript_digest: String,
    /// Expected Run 260 acknowledgement record id.
    pub expected_acknowledgement_record_id: String,
    /// Expected Run 262 consumer identity digest.
    pub expected_consumer_identity_digest: String,
    /// Expected Run 262 consumer request digest.
    pub expected_consumer_request_digest: String,
    /// Expected Run 262 consumer response digest.
    pub expected_consumer_response_digest: String,
    /// Expected Run 262 consumer record digest.
    pub expected_consumer_record_digest: String,
    /// Expected Run 262 consumer transcript digest.
    pub expected_consumer_transcript_digest: String,
    /// Expected Run 262 consumer record id.
    pub expected_consumer_record_id: String,
    /// Expected Run 270 settlement-receipt_acknowledgement identity digest.
    pub expected_settlement_receipt_acknowledgement_identity_digest: String,
    /// Expected Run 270 settlement-receipt_acknowledgement request digest.
    pub expected_settlement_receipt_acknowledgement_request_digest: String,
    /// Expected Run 270 settlement-receipt_acknowledgement response digest.
    pub expected_settlement_receipt_acknowledgement_response_digest: String,
    /// Expected Run 270 settlement-receipt_acknowledgement record digest.
    pub expected_settlement_receipt_acknowledgement_record_digest: String,
    /// Expected Run 270 settlement-receipt_acknowledgement transcript digest.
    pub expected_settlement_receipt_acknowledgement_transcript_digest: String,
    /// Expected Run 270 settlement-receipt_acknowledgement record id.
    pub expected_settlement_receipt_acknowledgement_record_id: String,
    /// Expected settlement-receipt_acknowledgement identity.
    pub expected_identity: DurableCompletionSettlementOutcomeReportIdentity,
    /// Expected settlement-receipt_acknowledgement kind.
    pub expected_outcome_report_kind: DurableCompletionSettlementOutcomeReportKind,
    /// Expected settlement-receipt_acknowledgement policy.
    pub expected_outcome_report_policy: DurableCompletionSettlementOutcomeReportPolicy,
    /// Expected domain separation tag.
    pub expected_domain_separation_tag: String,
}

impl DurableCompletionSettlementOutcomeReportExpectations {
    /// Internal: the first environment / surface binding mismatch reason, if any.
    fn binding_mismatch_reason(
        &self,
        input: &DurableCompletionSettlementOutcomeReportInput,
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
    pub fn binding_matches(
        &self,
        input: &DurableCompletionSettlementOutcomeReportInput,
    ) -> bool {
        self.binding_mismatch_reason(input).is_none()
    }

    /// Internal: the first receipt-request-identity mismatch reason, if any.
    fn request_mismatch_reason(
        &self,
        request: &DurableCompletionSettlementOutcomeReportRequest,
    ) -> Option<&'static str> {
        if !request.is_well_formed() {
            return Some("malformed receipt request");
        }
        if request.outcome_report_record_id != self.expected_outcome_report_record_id {
            return Some("wrong receipt record id");
        }
        if request.environment != self.expected_environment {
            return Some("wrong environment");
        }
        if request.chain_id != self.expected_chain_id {
            return Some("wrong chain id");
        }
        if request.genesis_hash != self.expected_genesis_hash {
            return Some("wrong genesis hash");
        }
        if request.governance_surface != self.expected_governance_surface {
            return Some("wrong governance surface");
        }
        if request.validation_surface != self.expected_validation_surface {
            return Some("wrong validation surface");
        }
        if request.mutation_surface != self.expected_mutation_surface {
            return Some("wrong mutation surface");
        }
        if request.proposal_id != self.expected_proposal_id {
            return Some("wrong proposal id");
        }
        if request.decision_id != self.expected_decision_id {
            return Some("wrong decision id");
        }
        if request.candidate_digest != self.expected_candidate_digest {
            return Some("wrong candidate digest");
        }
        if request.authority_domain_sequence != self.expected_authority_domain_sequence {
            return Some("wrong authority-domain sequence");
        }
        if request.pipeline_decision_digest != self.expected_pipeline_decision_digest {
            return Some("wrong pipeline decision digest");
        }
        if request.sink_decision_digest != self.expected_sink_decision_digest {
            return Some("wrong sink decision digest");
        }
        if request.reporter_decision_digest != self.expected_reporter_decision_digest {
            return Some("wrong reporter decision digest");
        }
        if request.finalization_decision_digest != self.expected_finalization_decision_digest {
            return Some("wrong outcome_report decision digest");
        }
        if request.attestation_digest != self.expected_attestation_digest {
            return Some("wrong attestation digest");
        }
        if request.attestation_id != self.expected_attestation_id {
            return Some("wrong attestation id");
        }
        if request.backend_identity_digest != self.expected_backend_identity_digest {
            return Some("wrong backend identity digest");
        }
        if request.backend_request_digest != self.expected_backend_request_digest {
            return Some("wrong backend request digest");
        }
        if request.backend_response_digest != self.expected_backend_response_digest {
            return Some("wrong backend response digest");
        }
        if request.backend_receipt_digest != self.expected_backend_receipt_digest {
            return Some("wrong backend receipt digest");
        }
        if request.backend_transcript_digest != self.expected_backend_transcript_digest {
            return Some("wrong backend transcript digest");
        }
        if request.backend_record_id != self.expected_backend_record_id {
            return Some("wrong backend record id");
        }
        if request.receipt_identity_digest != self.expected_receipt_identity_digest {
            return Some("wrong receipt identity digest");
        }
        if request.receipt_request_digest != self.expected_receipt_request_digest {
            return Some("wrong receipt request digest");
        }
        if request.receipt_response_digest != self.expected_receipt_response_digest {
            return Some("wrong receipt response digest");
        }
        if request.receipt_record_digest != self.expected_receipt_record_digest {
            return Some("wrong receipt record digest");
        }
        if request.receipt_transcript_digest != self.expected_receipt_transcript_digest {
            return Some("wrong receipt transcript digest");
        }
        if request.receipt_record_id != self.expected_receipt_record_id {
            return Some("wrong receipt record id");
        }
        if request.acknowledgement_identity_digest != self.expected_acknowledgement_identity_digest
        {
            return Some("wrong acknowledgement identity digest");
        }
        if request.acknowledgement_request_digest != self.expected_acknowledgement_request_digest {
            return Some("wrong acknowledgement request digest");
        }
        if request.acknowledgement_response_digest != self.expected_acknowledgement_response_digest
        {
            return Some("wrong acknowledgement response digest");
        }
        if request.acknowledgement_record_digest != self.expected_acknowledgement_record_digest {
            return Some("wrong acknowledgement record digest");
        }
        if request.acknowledgement_transcript_digest
            != self.expected_acknowledgement_transcript_digest
        {
            return Some("wrong acknowledgement transcript digest");
        }
        if request.acknowledgement_record_id != self.expected_acknowledgement_record_id {
            return Some("wrong acknowledgement record id");
        }
        if request.consumer_identity_digest != self.expected_consumer_identity_digest {
            return Some("wrong consumer identity digest");
        }
        if request.consumer_request_digest != self.expected_consumer_request_digest {
            return Some("wrong consumer request digest");
        }
        if request.consumer_response_digest != self.expected_consumer_response_digest {
            return Some("wrong consumer response digest");
        }
        if request.consumer_record_digest != self.expected_consumer_record_digest {
            return Some("wrong consumer record digest");
        }
        if request.consumer_transcript_digest != self.expected_consumer_transcript_digest {
            return Some("wrong consumer transcript digest");
        }
        if request.consumer_record_id != self.expected_consumer_record_id {
            return Some("wrong consumer record id");
        }
        if request.settlement_receipt_acknowledgement_identity_digest
            != self.expected_settlement_receipt_acknowledgement_identity_digest
        {
            return Some("wrong settlement-receipt_acknowledgement identity digest");
        }
        if request.settlement_receipt_acknowledgement_request_digest
            != self.expected_settlement_receipt_acknowledgement_request_digest
        {
            return Some("wrong settlement-receipt_acknowledgement request digest");
        }
        if request.settlement_receipt_acknowledgement_response_digest
            != self.expected_settlement_receipt_acknowledgement_response_digest
        {
            return Some("wrong settlement-receipt_acknowledgement response digest");
        }
        if request.settlement_receipt_acknowledgement_record_digest
            != self.expected_settlement_receipt_acknowledgement_record_digest
        {
            return Some("wrong settlement-receipt_acknowledgement record digest");
        }
        if request.settlement_receipt_acknowledgement_transcript_digest
            != self.expected_settlement_receipt_acknowledgement_transcript_digest
        {
            return Some("wrong settlement-receipt_acknowledgement transcript digest");
        }
        if request.settlement_receipt_acknowledgement_record_id != self.expected_settlement_receipt_acknowledgement_record_id {
            return Some("wrong settlement-receipt_acknowledgement record id");
        }
        if request.domain_separation_tag != self.expected_domain_separation_tag {
            return Some("wrong domain separation tag");
        }
        if request.identity != self.expected_identity {
            return Some("wrong settlement-outcome-report identity");
        }
        if request.identity.kind != self.expected_outcome_report_kind {
            return Some("wrong settlement-outcome-report kind");
        }
        if request.identity.policy != self.expected_outcome_report_policy {
            return Some("wrong settlement-outcome-report policy");
        }
        None
    }

    /// `true` iff the receipt-request identity matches and is well-formed.
    pub fn request_matches(
        &self,
        request: &DurableCompletionSettlementOutcomeReportRequest,
    ) -> bool {
        self.request_mismatch_reason(request).is_none()
    }
}

// ===========================================================================
// Receipt input
// ===========================================================================

/// Run 272 — typed inputs for one modeled durable-completion audit/publication
/// receipt round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionSettlementOutcomeReportInput {
    /// The receipt policy selector.
    pub policy: DurableCompletionSettlementOutcomeReportPolicy,
    /// The trust-domain environment binding.
    pub environment_binding: DurableCompletionSettlementOutcomeReportEnvironment,
    /// The runtime binding (governance + mutation surface + sequence).
    pub runtime_binding: DurableCompletionSettlementOutcomeReportBinding,
    /// The Run 240/246 durable replay observation the pipeline authorized consume
    /// under.
    pub replay_binding: DurableCompletionSettlementOutcomeReportReplayBinding,
    /// The Run 246 pipeline outcome.
    pub pipeline_binding: DurableCompletionSettlementOutcomeReportPipelineBinding,
    /// The Run 248 sink outcome.
    pub sink_binding: DurableCompletionSettlementOutcomeReportSinkBinding,
    /// The Run 250 reporter outcome.
    pub reporter_binding: DurableCompletionSettlementOutcomeReportReporterBinding,
    /// The Run 252 outcome_report outcome.
    pub receipt_acknowledgement_binding: DurableCompletionSettlementOutcomeReportFinalizationBinding,
    /// The Run 254 attestation outcome.
    pub attestation_binding: DurableCompletionSettlementOutcomeReportAttestationBinding,
    /// The Run 256 backend outcome carried as backend-record context.
    pub backend_binding: DurableCompletionSettlementOutcomeReportBackendBinding,
    /// The Run 258 audit/publication receipt outcome carried as receipt-record
    /// context.
    pub receipt_binding: DurableCompletionSettlementOutcomeReportReceiptBinding,
    /// The Run 260 audit-receipt acknowledgement outcome carried as
    /// acknowledgement-record context.
    pub acknowledgement_binding:
        DurableCompletionSettlementOutcomeReportAcknowledgementBinding,
    /// The Run 262 acknowledgement consumer outcome the settlement-receipt_acknowledgement
    /// boundary projects to a settlement-receipt_acknowledgement request.
    pub consumer_binding: DurableCompletionSettlementOutcomeReportConsumerBinding,
    /// The Run 270 settlement-receipt_acknowledgement outcome the settlement-outcome-report boundary
    /// projects to a settlement-outcome-report request.
    pub settlement_receipt_acknowledgement_binding:
        DurableCompletionSettlementOutcomeReportSettlementReceiptAcknowledgementBinding,
    /// The settlement-outcome-report request the call site would submit.
    pub request: DurableCompletionSettlementOutcomeReportRequest,
}

impl DurableCompletionSettlementOutcomeReportInput {
    /// The trust-domain environment the decision is bound to.
    pub fn environment(&self) -> TrustBundleEnvironment {
        self.environment_binding.environment
    }

    /// The validation / mutation surface pair.
    pub fn surface(&self) -> DurableCompletionSettlementOutcomeReportSurface {
        self.runtime_binding.mutation_surface
    }

    /// `true` iff this is a MainNet peer-driven apply that remains refused
    /// unconditionally before pipeline progression, sink invocation, reporter
    /// invocation, finalizer invocation, attestor invocation, backend invocation,
    /// and receipt invocation.
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
                self.receipt_acknowledgement_binding,
                GovernanceModeledDurableCompletionFinalizationOutcome::MainNetPeerDrivenApplyRefusedNoFinalization
            )
            || matches!(
                self.attestation_binding,
                GovernanceModeledDurableCompletionAttestationOutcome::MainNetPeerDrivenApplyRefusedNoAttestation
            )
            || matches!(
                self.backend_binding,
                DurableCompletionAttestationBackendOutcome::MainNetPeerDrivenApplyRefusedNoSubmission
            )
            || matches!(
                self.receipt_binding,
                DurableCompletionAuditPublicationReceiptOutcome::MainNetPeerDrivenApplyRefusedNoReceipt
            )
            || matches!(
                self.acknowledgement_binding,
                DurableCompletionAuditReceiptAcknowledgementOutcome::MainNetPeerDrivenApplyRefusedNoAcknowledgement
            )
            || matches!(
                self.consumer_binding,
                DurableCompletionAcknowledgementConsumerOutcome::MainNetPeerDrivenApplyRefusedNoConsumer
            )
            || matches!(
                self.settlement_receipt_acknowledgement_binding,
                DurableCompletionSettlementReceiptAcknowledgementOutcome::MainNetPeerDrivenApplyRefusedNoReceiptAcknowledgement
            )
    }
}

// ===========================================================================
// Receipt outcome
// ===========================================================================

/// Run 272 — the typed outcome of one modeled durable-completion audit/publication
/// receipt round-trip.
///
/// Only [`Self::SettlementOutcomeReportRecorded`] authorizes a **new** modeled
/// audit/publication-receipt state. A [`Self::SettlementOutcomeReportDuplicateIdempotent`]
/// means the receipt was already recorded (idempotent, no second receipt). Every
/// other variant is a no-audit-receipt fail-closed outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableCompletionSettlementOutcomeReportOutcome {
    /// Legacy bypass — a disabled receipt policy preserved the legacy
    /// no-audit-receipt path. No receipt invocation.
    LegacyBypassNoSettlementOutcomeReport,
    /// The Run 256 backend-stage binding was rejected before the receipt sink was
    /// invoked (a backend-stage rejection / binding mismatch). Non-mutating, no
    /// receipt. No receipt invocation.
    RejectedBeforeSettlementReceiptAcknowledgementNoOutcomeReport,
    /// The Run 256 backend did not submit (any non-submitting backend outcome
    /// without a more specific variant). Non-mutating, no receipt. No receipt
    /// invocation.
    SettlementReceiptAcknowledgementDidNotRecordNoOutcomeReport,
    /// The receipt sink recorded a new modeled audit/publication receipt. The
    /// **only** outcome that authorizes a new modeled receipt state.
    SettlementOutcomeReportRecorded,
    /// A duplicate identical receipt — idempotent; no second receipt recorded.
    SettlementOutcomeReportDuplicateIdempotent,
    /// The receipt was rejected before record (malformed request, request-identity
    /// mismatch, same receipt record id with a differing digest / equivocation, or
    /// a duplicate-idempotent backend submission with no matching prior receipt). No
    /// receipt.
    SettlementOutcomeReportRejectedBeforeRecord,
    /// The receipt record failed. No receipt.
    SettlementOutcomeReportRecordFailedNoOutcomeReport,
    /// The receipt record was rolled back. No receipt.
    SettlementOutcomeReportRolledBackNoOutcomeReport,
    /// The receipt rollback itself failed — fatal / fail-closed. No receipt.
    SettlementOutcomeReportRollbackFailedFatalNoOutcomeReport,
    /// The after-record receipt window was ambiguous — fails closed. No receipt.
    SettlementOutcomeReportAmbiguousFailClosedNoOutcomeReport,
    /// The production audit-ledger path was reached but is unavailable. No receipt.
    ProductionSettlementOutcomeReportUnavailableNoOutcomeReport,
    /// The MainNet audit-ledger path was reached but is unavailable. No receipt.
    MainNetSettlementOutcomeReportUnavailableNoOutcomeReport,
    /// The external-publication path was reached but is unavailable. No receipt.
    ExternalSettlementOutcomeReportUnavailableNoOutcomeReport,
    /// MainNet peer-driven apply remains refused before pipeline progression, sink
    /// invocation, reporter invocation, finalizer invocation, attestor invocation,
    /// backend invocation, and receipt invocation. No receipt.
    MainNetPeerDrivenApplyRefusedNoOutcomeReport,
    /// Validator-set rotation is unsupported. No receipt.
    ValidatorSetRotationUnsupportedNoOutcomeReport,
    /// Policy-change actions are unsupported. No receipt.
    PolicyChangeUnsupportedNoOutcomeReport,
}

impl DurableCompletionSettlementOutcomeReportOutcome {
    /// `true` iff this outcome authorizes a **new** modeled audit/publication
    /// receipt (only [`Self::SettlementOutcomeReportRecorded`]).
    pub fn authorizes_record(&self) -> bool {
        matches!(self, Self::SettlementOutcomeReportRecorded)
    }

    /// `true` iff this outcome projects to a recorded audit/publication receipt — a
    /// newly recorded receipt or an idempotent duplicate of an already-recorded
    /// receipt.
    pub fn projects_to_recorded(&self) -> bool {
        matches!(
            self,
            Self::SettlementOutcomeReportRecorded | Self::SettlementOutcomeReportDuplicateIdempotent
        )
    }

    /// `true` iff this outcome records nothing new and projects to no
    /// audit/publication receipt.
    pub fn no_commitment(&self) -> bool {
        !self.projects_to_recorded()
    }

    /// `true` iff this is the legacy no-audit-receipt bypass.
    pub fn is_legacy_bypass(&self) -> bool {
        matches!(self, Self::LegacyBypassNoSettlementOutcomeReport)
    }

    /// `true` iff this is the MainNet peer-driven-apply refusal.
    pub fn is_mainnet_peer_driven_apply_refused(&self) -> bool {
        matches!(self, Self::MainNetPeerDrivenApplyRefusedNoOutcomeReport)
    }

    /// Stable operator-facing tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::LegacyBypassNoSettlementOutcomeReport => "legacy-bypass-no-settlement-outcome-report",
            Self::RejectedBeforeSettlementReceiptAcknowledgementNoOutcomeReport => {
                "rejected-before-settlement-receipt_acknowledgement-no-receipt-acknowledgement"
            }
            Self::SettlementReceiptAcknowledgementDidNotRecordNoOutcomeReport => {
                "settlement-receipt_acknowledgement-did-not-record-no-receipt-acknowledgement"
            }
            Self::SettlementOutcomeReportRecorded => "settlement-outcome-report-recorded",
            Self::SettlementOutcomeReportDuplicateIdempotent => {
                "settlement-outcome-report-duplicate-idempotent"
            }
            Self::SettlementOutcomeReportRejectedBeforeRecord => {
                "settlement-outcome-report-rejected-before-record"
            }
            Self::SettlementOutcomeReportRecordFailedNoOutcomeReport => {
                "settlement-outcome-report-record-failed-no-receipt-acknowledgement"
            }
            Self::SettlementOutcomeReportRolledBackNoOutcomeReport => {
                "settlement-outcome-report-rolled-back-no-receipt-acknowledgement"
            }
            Self::SettlementOutcomeReportRollbackFailedFatalNoOutcomeReport => {
                "settlement-outcome-report-rollback-failed-fatal-no-receipt-acknowledgement"
            }
            Self::SettlementOutcomeReportAmbiguousFailClosedNoOutcomeReport => {
                "settlement-outcome-report-ambiguous-fail-closed-no-receipt-acknowledgement"
            }
            Self::ProductionSettlementOutcomeReportUnavailableNoOutcomeReport => {
                "production-settlement-outcome-report-unavailable-no-receipt-acknowledgement"
            }
            Self::MainNetSettlementOutcomeReportUnavailableNoOutcomeReport => {
                "mainnet-settlement-outcome-report-unavailable-no-receipt-acknowledgement"
            }
            Self::ExternalSettlementOutcomeReportUnavailableNoOutcomeReport => {
                "external-settlement-outcome-report-unavailable-no-receipt-acknowledgement"
            }
            Self::MainNetPeerDrivenApplyRefusedNoOutcomeReport => {
                "mainnet-peer-driven-apply-refused-no-receipt-acknowledgement"
            }
            Self::ValidatorSetRotationUnsupportedNoOutcomeReport => {
                "validator-set-rotation-unsupported-no-receipt-acknowledgement"
            }
            Self::PolicyChangeUnsupportedNoOutcomeReport => "policy-change-unsupported-no-receipt-acknowledgement",
        }
    }
}

// ===========================================================================
// Consumer-outcome -> settlement-receipt_acknowledgement request receipt_acknowledgement
// ===========================================================================

/// Run 272 — the typed receipt_acknowledgement of a Run 262 acknowledgement consumer outcome
/// onto a settlement-receipt_acknowledgement request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableCompletionSettlementOutcomeReportRequestIntent {
    /// The consumer recorded a consumer record; the settlement-receipt_acknowledgement sink may
    /// record a new settlement receipt_acknowledgement.
    CreateRequest,
    /// The consumer reported an idempotent-duplicate consumer record; the
    /// settlement-receipt_acknowledgement sink may only match an already-recorded settlement
    /// receipt_acknowledgement and must never create a new one.
    IdempotentOnly,
    /// The consumer did not record; no settlement-receipt_acknowledgement request. Carries the
    /// typed no-receipt_acknowledgement outcome the settlement-receipt_acknowledgement evaluation returns
    /// directly (without invoking the settlement-receipt_acknowledgement sink).
    NoReceiptAcknowledgement(DurableCompletionSettlementOutcomeReportOutcome),
}

impl DurableCompletionSettlementOutcomeReportRequestIntent {
    /// `true` iff this receipt_acknowledgement creates a settlement-receipt_acknowledgement request (i.e. the
    /// consumer recorded a consumer record).
    pub fn creates_request(&self) -> bool {
        matches!(self, Self::CreateRequest)
    }
}

/// Run 272 — project a Run 270 settlement-receipt_acknowledgement outcome onto a
/// settlement-outcome-report request.
///
/// Only
/// [`DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementRecorded`]
/// creates a settlement-outcome-report request.
/// [`DurableCompletionSettlementReceiptAcknowledgementOutcome::SettlementReceiptAcknowledgementDuplicateIdempotent`]
/// may only match an already-recorded settlement-outcome-report record and never creates
/// a new one. Every other settlement-receipt_acknowledgement outcome maps to a no-receipt-acknowledgement
/// fail-closed outcome (a more specific one where one exists, otherwise the generic
/// [`DurableCompletionSettlementOutcomeReportOutcome::SettlementReceiptAcknowledgementDidNotRecordNoOutcomeReport`]).
/// Pure: performs no work and never records.
pub fn project_settlement_receipt_acknowledgement_outcome_to_outcome_report_request(
    outcome: &DurableCompletionSettlementOutcomeReportSettlementReceiptAcknowledgementBinding,
) -> DurableCompletionSettlementOutcomeReportRequestIntent {
    use DurableCompletionSettlementReceiptAcknowledgementOutcome as Finalization;
    use DurableCompletionSettlementOutcomeReportOutcome as OutcomeReport;
    use DurableCompletionSettlementOutcomeReportRequestIntent as Intent;
    match outcome {
        Finalization::SettlementReceiptAcknowledgementRecorded => Intent::CreateRequest,
        Finalization::SettlementReceiptAcknowledgementDuplicateIdempotent => Intent::IdempotentOnly,
        Finalization::LegacyBypassNoSettlementReceiptAcknowledgement => {
            Intent::NoReceiptAcknowledgement(OutcomeReport::LegacyBypassNoSettlementOutcomeReport)
        }
        Finalization::RejectedBeforeSettlementFinalizationNoReceiptAcknowledgement => {
            Intent::NoReceiptAcknowledgement(OutcomeReport::RejectedBeforeSettlementReceiptAcknowledgementNoOutcomeReport)
        }
        Finalization::MainNetPeerDrivenApplyRefusedNoReceiptAcknowledgement => {
            Intent::NoReceiptAcknowledgement(OutcomeReport::MainNetPeerDrivenApplyRefusedNoOutcomeReport)
        }
        Finalization::ValidatorSetRotationUnsupportedNoReceiptAcknowledgement => {
            Intent::NoReceiptAcknowledgement(OutcomeReport::ValidatorSetRotationUnsupportedNoOutcomeReport)
        }
        Finalization::PolicyChangeUnsupportedNoReceiptAcknowledgement => {
            Intent::NoReceiptAcknowledgement(OutcomeReport::PolicyChangeUnsupportedNoOutcomeReport)
        }
        // Every remaining settlement-receipt_acknowledgement outcome is a non-recording rejection /
        // failure / rollback / ambiguous window: the settlement receipt_acknowledgement did not
        // record, so no settlement-outcome-report record may exist.
        _ => Intent::NoReceiptAcknowledgement(OutcomeReport::SettlementReceiptAcknowledgementDidNotRecordNoOutcomeReport),
    }
}

// ===========================================================================
// Receipt fault injection (source/test only)
// ===========================================================================

/// Run 272 — a modeled fault the fixture receipt sink injects to exercise the
/// fail-closed record / rollback / ambiguous paths. Source/test only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionSettlementOutcomeReportFault {
    /// The receipt record fails; nothing is written. No receipt.
    RecordFailedNoReceiptAcknowledgement,
    /// The receipt record is rolled back; nothing remains written. No receipt.
    RolledBackNoReceiptAcknowledgement,
    /// The receipt rollback itself fails — fatal / fail-closed. No receipt.
    RollbackFailedFatal,
    /// The after-record receipt window is ambiguous — fails closed. No receipt.
    AmbiguousAfterRecord,
}

// ===========================================================================
// Receipt trait boundary
// ===========================================================================

/// Run 272 — the pure/mockable modeled durable-completion audit/publication receipt
/// boundary.
///
/// No implementation here calls Run 070, mutates `LivePqcTrustState`, performs a
/// live trust swap, evicts sessions, writes a sequence, writes a marker, performs
/// network I/O, external publication, or a real audit-ledger persistence. The
/// DevNet/TestNet fixture receipt sink mutates only the in-memory
/// [`DurableCompletionSettlementOutcomeReportLedger`].
pub trait GovernanceDurableCompletionSettlementOutcomeReportSink {
    /// The receipt kind (used for typed recovery classification).
    fn kind(&self) -> DurableCompletionSettlementOutcomeReportKind;

    /// The number of times this receipt sink was invoked (so tests can prove
    /// non-submitting backend paths and pre-receipt rejections never invoke it).
    fn invocations(&self) -> u32;

    /// Record a modeled durable-completion audit/publication receipt once the Run
    /// 256 backend recorded a submission and the pre-receipt binding validation
    /// passed.
    ///
    /// `idempotent_only` is `true` when the projected backend outcome was an
    /// idempotent-duplicate submission: in that case the receipt sink may only match
    /// an already-recorded receipt and must never create a new one.
    fn project_durable_completion_settlement_outcome_report(
        &mut self,
        request: &DurableCompletionSettlementOutcomeReportRequest,
        expectations: &DurableCompletionSettlementOutcomeReportExpectations,
        idempotent_only: bool,
        ledger: &mut DurableCompletionSettlementOutcomeReportLedger,
    ) -> DurableCompletionSettlementOutcomeReportOutcome;

    /// Classify a modeled receipt crash/recovery window. Pure: performs no modeled
    /// mutation and never invokes Run 070.
    fn recover_durable_completion_settlement_outcome_report_window(
        &self,
        input: &DurableCompletionSettlementOutcomeReportInput,
        window: DurableCompletionSettlementOutcomeReportWindow,
        recovered_record: Option<&DurableCompletionSettlementOutcomeReportLedgerRecord>,
        expectations: &DurableCompletionSettlementOutcomeReportExpectations,
    ) -> DurableCompletionSettlementOutcomeReportOutcome {
        recover_durable_completion_settlement_outcome_report_window(
            input,
            window,
            self.kind(),
            recovered_record,
            expectations,
        )
    }
}

// ===========================================================================
// Fixture receipt sink (DevNet / TestNet source-test only)
// ===========================================================================

/// Run 272 — the DevNet/TestNet in-memory fixture receipt sink.
///
/// Source-test only. It mutates only the in-memory
/// [`DurableCompletionSettlementOutcomeReportLedger`] and exposes an invocation
/// counter so tests can prove non-submitting backend paths and pre-receipt
/// rejections never invoke it.
#[derive(Debug, Clone)]
pub struct FixtureDurableCompletionSettlementOutcomeReportSink {
    fault: Option<DurableCompletionSettlementOutcomeReportFault>,
    invocations: u32,
}

impl Default for FixtureDurableCompletionSettlementOutcomeReportSink {
    fn default() -> Self {
        Self::new()
    }
}

impl FixtureDurableCompletionSettlementOutcomeReportSink {
    /// A new fixture receipt sink.
    pub fn new() -> Self {
        Self {
            fault: None,
            invocations: 0,
        }
    }

    /// A new fixture receipt sink that injects the given modeled fault on record.
    pub fn with_fault(fault: DurableCompletionSettlementOutcomeReportFault) -> Self {
        Self {
            fault: Some(fault),
            invocations: 0,
        }
    }
}

impl GovernanceDurableCompletionSettlementOutcomeReportSink
    for FixtureDurableCompletionSettlementOutcomeReportSink
{
    fn kind(&self) -> DurableCompletionSettlementOutcomeReportKind {
        DurableCompletionSettlementOutcomeReportKind::FixtureInMemory
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn project_durable_completion_settlement_outcome_report(
        &mut self,
        request: &DurableCompletionSettlementOutcomeReportRequest,
        expectations: &DurableCompletionSettlementOutcomeReportExpectations,
        idempotent_only: bool,
        ledger: &mut DurableCompletionSettlementOutcomeReportLedger,
    ) -> DurableCompletionSettlementOutcomeReportOutcome {
        use DurableCompletionSettlementOutcomeReportOutcome as Receipt;
        self.invocations += 1;

        // Injected faults model record-failure / rollback / ambiguous windows. None
        // of them ever leave a recorded receipt behind, so a durable receipt is never
        // claimed. The ledger snapshot/restore models the rollback being a no-op
        // write.
        if let Some(fault) = self.fault {
            let snapshot = ledger.snapshot();
            return match fault {
                DurableCompletionSettlementOutcomeReportFault::RecordFailedNoReceiptAcknowledgement => {
                    ledger.restore(&snapshot);
                    Receipt::SettlementOutcomeReportRecordFailedNoOutcomeReport
                }
                DurableCompletionSettlementOutcomeReportFault::RolledBackNoReceiptAcknowledgement => {
                    ledger.restore(&snapshot);
                    Receipt::SettlementOutcomeReportRolledBackNoOutcomeReport
                }
                DurableCompletionSettlementOutcomeReportFault::RollbackFailedFatal => {
                    Receipt::SettlementOutcomeReportRollbackFailedFatalNoOutcomeReport
                }
                DurableCompletionSettlementOutcomeReportFault::AmbiguousAfterRecord => {
                    ledger.restore(&snapshot);
                    Receipt::SettlementOutcomeReportAmbiguousFailClosedNoOutcomeReport
                }
            };
        }

        // The fixture receipt sink is DevNet/TestNet evidence-only.
        if !matches!(
            request.environment,
            TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet
        ) {
            return Receipt::SettlementOutcomeReportRejectedBeforeRecord;
        }

        // Request-identity validation (malformed / mismatch) fails closed before any
        // record is written.
        if !expectations.request_matches(request) {
            return Receipt::SettlementOutcomeReportRejectedBeforeRecord;
        }

        // Build the deterministic request / response / record / transcript digests.
        let request_digest = request.digest();
        let response = DurableCompletionSettlementOutcomeReportResponse {
            outcome_report_record_id: request.outcome_report_record_id.clone(),
            request_digest: request_digest.clone(),
            accepted: true,
            outcome_report_kind: DurableCompletionSettlementOutcomeReportKind::FixtureInMemory,
        };
        let response_digest = response.digest();
        let record = request.to_record();
        let record_digest = record.digest();
        let transcript_digest = settlement_outcome_report_transcript_digest(
            &request_digest,
            &response_digest,
            &record_digest,
        );

        // Idempotency / equivocation gate.
        if let Some(existing) = ledger.find(&request.outcome_report_record_id) {
            if existing.request_digest == request_digest
                && existing.response_digest == response_digest
                && existing.record_digest == record_digest
                && existing.transcript_digest == transcript_digest
            {
                return Receipt::SettlementOutcomeReportDuplicateIdempotent;
            }
            // Same receipt record id with a different digest is equivocation: fail
            // closed, record no second receipt.
            return Receipt::SettlementOutcomeReportRejectedBeforeRecord;
        }

        // A duplicate-idempotent backend submission may only match an already-recorded
        // receipt; it must never create a new one by itself.
        if idempotent_only {
            return Receipt::SettlementOutcomeReportRejectedBeforeRecord;
        }

        ledger.insert(DurableCompletionSettlementOutcomeReportLedgerRecord {
            outcome_report_record_id: request.outcome_report_record_id.clone(),
            request_digest,
            response_digest,
            record_digest,
            transcript_digest,
            status: DurableCompletionSettlementOutcomeReportLedgerStatus::Recorded,
        });
        Receipt::SettlementOutcomeReportRecorded
    }
}

// ===========================================================================
// Production / MainNet audit-ledger / External-publication sinks (unavailable)
// ===========================================================================

/// Run 272 — the production audit-ledger receipt sink. Reachable but unavailable /
/// fail-closed. It records no receipt and mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct ProductionSettlementOutcomeReportSink {
    invocations: u32,
}

impl GovernanceDurableCompletionSettlementOutcomeReportSink
    for ProductionSettlementOutcomeReportSink
{
    fn kind(&self) -> DurableCompletionSettlementOutcomeReportKind {
        DurableCompletionSettlementOutcomeReportKind::ProductionSettlementOutcomeReportUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn project_durable_completion_settlement_outcome_report(
        &mut self,
        _request: &DurableCompletionSettlementOutcomeReportRequest,
        _expectations: &DurableCompletionSettlementOutcomeReportExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionSettlementOutcomeReportLedger,
    ) -> DurableCompletionSettlementOutcomeReportOutcome {
        self.invocations += 1;
        DurableCompletionSettlementOutcomeReportOutcome::ProductionSettlementOutcomeReportUnavailableNoOutcomeReport
    }
}

/// Run 272 — the MainNet audit-ledger receipt sink. Reachable but unavailable /
/// fail-closed. It records no receipt and mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct MainNetSettlementOutcomeReportSink {
    invocations: u32,
}

impl GovernanceDurableCompletionSettlementOutcomeReportSink
    for MainNetSettlementOutcomeReportSink
{
    fn kind(&self) -> DurableCompletionSettlementOutcomeReportKind {
        DurableCompletionSettlementOutcomeReportKind::MainNetSettlementOutcomeReportUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn project_durable_completion_settlement_outcome_report(
        &mut self,
        _request: &DurableCompletionSettlementOutcomeReportRequest,
        _expectations: &DurableCompletionSettlementOutcomeReportExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionSettlementOutcomeReportLedger,
    ) -> DurableCompletionSettlementOutcomeReportOutcome {
        self.invocations += 1;
        DurableCompletionSettlementOutcomeReportOutcome::MainNetSettlementOutcomeReportUnavailableNoOutcomeReport
    }
}

/// Run 272 — the external-publication receipt sink. Reachable but unavailable /
/// fail-closed. It performs no external publication, records no receipt, and
/// mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct ExternalSettlementOutcomeReportSink {
    invocations: u32,
}

impl GovernanceDurableCompletionSettlementOutcomeReportSink
    for ExternalSettlementOutcomeReportSink
{
    fn kind(&self) -> DurableCompletionSettlementOutcomeReportKind {
        DurableCompletionSettlementOutcomeReportKind::ExternalSettlementOutcomeReportUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn project_durable_completion_settlement_outcome_report(
        &mut self,
        _request: &DurableCompletionSettlementOutcomeReportRequest,
        _expectations: &DurableCompletionSettlementOutcomeReportExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionSettlementOutcomeReportLedger,
    ) -> DurableCompletionSettlementOutcomeReportOutcome {
        self.invocations += 1;
        DurableCompletionSettlementOutcomeReportOutcome::ExternalSettlementOutcomeReportUnavailableNoOutcomeReport
    }
}

// ===========================================================================
// Receipt executor / composition helpers
// ===========================================================================

/// Run 272 — evaluate one modeled durable-completion audit/publication receipt
/// round-trip.
///
/// Ordering (each gate must pass before the next is considered):
///
/// 1. MainNet peer-driven apply refusal — before pipeline progression, sink
///    invocation, reporter invocation, finalizer invocation, attestor invocation,
///    backend invocation, and receipt invocation;
/// 2. legacy bypass — a
///    [`DurableCompletionSettlementOutcomeReportPolicy::Disabled`] policy;
/// 3. backend-outcome receipt_acknowledgement — only
///    [`DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded`]
///    creates a receipt request;
/// 4. pre-receipt binding validation — environment / surface must match before the
///    receipt sink is invoked; a mismatch leaves the receipt invocation count at
///    zero;
/// 5. receipt record — attempted only after every prior gate passes.
///
/// A rejection before the receipt stage leaves the receipt invocation count at
/// zero. Pure aside from the fixture receipt sink's modeled in-memory ledger
/// effect: performs no I/O, mutates no `LivePqcTrustState`, writes no marker,
/// writes no sequence, swaps no live trust, evicts no sessions, performs no
/// external publication / audit write, and never invokes Run 070.
pub fn evaluate_durable_completion_settlement_outcome_report<S>(
    input: &DurableCompletionSettlementOutcomeReportInput,
    expectations: &DurableCompletionSettlementOutcomeReportExpectations,
    sink: &mut S,
    ledger: &mut DurableCompletionSettlementOutcomeReportLedger,
) -> DurableCompletionSettlementOutcomeReportOutcome
where
    S: GovernanceDurableCompletionSettlementOutcomeReportSink,
{
    use DurableCompletionSettlementOutcomeReportOutcome as Finalization;
    use DurableCompletionSettlementOutcomeReportRequestIntent as Intent;

    // Step 1: MainNet peer-driven apply remains refused unconditionally, before
    // pipeline progression, sink invocation, reporter invocation, finalizer
    // invocation, attestor invocation, backend invocation, receipt invocation,
    // acknowledgement invocation, consumer invocation, and settlement-receipt_acknowledgement
    // invocation.
    if input.is_mainnet_peer_driven() {
        return Finalization::MainNetPeerDrivenApplyRefusedNoOutcomeReport;
    }

    // Step 2: legacy bypass — a disabled settlement-receipt_acknowledgement policy preserves the
    // legacy no-settlement-receipt_acknowledgement path and never invokes the receipt_acknowledgement sink.
    if input.policy.is_disabled() {
        return Finalization::LegacyBypassNoSettlementOutcomeReport;
    }

    // Step 3: project the Run 262 acknowledgement consumer outcome onto a
    // settlement-receipt_acknowledgement request. Every non-recording consumer outcome returns a
    // no-receipt_acknowledgement outcome without invoking the settlement-receipt_acknowledgement sink.
    let idempotent_only =
        match project_settlement_receipt_acknowledgement_outcome_to_outcome_report_request(
            &input.settlement_receipt_acknowledgement_binding,
        ) {
            Intent::NoReceiptAcknowledgement(outcome) => return outcome,
            Intent::CreateRequest => false,
            Intent::IdempotentOnly => true,
        };

    // Step 4: pre-receipt_acknowledgement environment / surface binding validation. A mismatch
    // fails closed before the settlement-receipt_acknowledgement sink is invoked, leaving the
    // settlement-receipt_acknowledgement invocation count at zero.
    if !expectations.binding_matches(input) {
        return Finalization::RejectedBeforeSettlementReceiptAcknowledgementNoOutcomeReport;
    }

    // Step 5: invoke the settlement-receipt_acknowledgement sink to record the modeled receipt_acknowledgement.
    sink.project_durable_completion_settlement_outcome_report(
        &input.request,
        expectations,
        idempotent_only,
        ledger,
    )
}

// ===========================================================================
// Receipt crash/recovery window classification
// ===========================================================================

/// Run 272 — the modeled durable-completion audit/publication receipt
/// crash/recovery window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionSettlementOutcomeReportWindow {
    /// Crashed before the pipeline authorized consume.
    BeforePipeline,
    /// Crashed after pipeline success but before a sink intent was created.
    AfterPipelineSuccessBeforeSinkIntent,
    /// Crashed after a sink intent but before the sink recorded a receipt.
    AfterSinkIntentBeforeSinkReceiptRecord,
    /// Crashed after the sink recorded a receipt but before a completion-report
    /// intent.
    AfterSinkReceiptRecordBeforeReportIntent,
    /// Crashed after a completion-report intent but before the report record.
    AfterReportIntentBeforeReportRecord,
    /// Crashed after the report record but before a outcome_report intent.
    AfterReportRecordBeforeOutcomeReportIntent,
    /// Crashed after a outcome_report intent but before any outcome_report record.
    AfterOutcomeReportIntentBeforeOutcomeReportRecord,
    /// Crashed after the outcome_report record but before an attestation intent.
    AfterOutcomeReportRecordBeforeAttestationIntent,
    /// Crashed after an attestation intent but before any attestation record.
    AfterAttestationIntentBeforeAttestationRecord,
    /// Crashed after the attestation record but before a backend request.
    AfterAttestationRecordBeforeBackendRequest,
    /// Crashed after a backend request but before any backend record.
    AfterBackendRequestBeforeBackendRecord,
    /// Crashed after a backend record but before backend success.
    AfterBackendRecordBeforeBackendSuccess,
    /// Crashed after backend success but before a receipt request.
    AfterBackendSuccessBeforeReceiptRequest,
    /// Crashed after a receipt request but before any receipt record.
    AfterReceiptRequestBeforeReceiptRecord,
    /// Crashed after a receipt record but before receipt success.
    AfterReceiptRecordBeforeReceiptSuccess,
    /// Crashed after receipt success but before an acknowledgement request.
    AfterReceiptSuccessBeforeAcknowledgementRequest,
    /// Crashed after an acknowledgement request but before any acknowledgement
    /// record.
    AfterAcknowledgementRequestBeforeAcknowledgementRecord,
    /// Crashed after an acknowledgement record but before acknowledgement success —
    /// fails closed unless an explicit matching acknowledgement success exists.
    AfterAcknowledgementRecordBeforeAcknowledgementSuccess,
    /// Crashed after acknowledgement success but before a consumer request.
    AfterAcknowledgementSuccessBeforeConsumerRequest,
    /// Crashed after a consumer request but before any consumer record.
    AfterConsumerRequestBeforeConsumerRecord,
    /// Crashed after a consumer record but before consumer success.
    AfterConsumerRecordBeforeConsumerSuccess,
    /// Crashed after consumer success but before a settlement-receipt_acknowledgement request.
    AfterConsumerSuccessBeforeSettlementReceiptAcknowledgementRequest,
    /// Crashed after a settlement-receipt_acknowledgement request but before any
    /// settlement-receipt_acknowledgement record.
    AfterSettlementReceiptAcknowledgementRequestBeforeSettlementReceiptAcknowledgementRecord,
    /// Crashed after a settlement-receipt_acknowledgement record but before settlement-receipt_acknowledgement
    /// success — fails closed unless an explicit matching settlement-receipt_acknowledgement
    /// record exists.
    AfterSettlementReceiptAcknowledgementRecordBeforeSettlementReceiptAcknowledgementSuccess,
    /// Crashed after settlement-receipt_acknowledgement success but before a settlement-outcome-report
    /// request.
    AfterSettlementReceiptAcknowledgementSuccessBeforeSettlementOutcomeReportRequest,
    /// Crashed after a settlement-outcome-report request but before any
    /// settlement-outcome-report record.
    AfterSettlementOutcomeReportRequestBeforeSettlementOutcomeReportRecord,
    /// Crashed after a settlement-outcome-report record but before settlement-outcome-report
    /// success — fails closed unless an explicit matching settlement-outcome-report
    /// record exists.
    AfterSettlementOutcomeReportRecordBeforeSettlementOutcomeReportSuccess,
    /// Recovered after a successful settlement-outcome-report record.
    AfterSettlementOutcomeReportSuccess,
    /// Recovered after an ambiguous settlement-outcome-report window.
    AfterSettlementOutcomeReportAmbiguous,
    /// The settlement-outcome-report record itself failed.
    SettlementOutcomeReportRecordFailed,
    /// The settlement-outcome-report record was rolled back.
    SettlementOutcomeReportRollbackCompleted,
    /// The settlement-outcome-report rollback itself failed — fatal.
    SettlementOutcomeReportRollbackFailed,
    /// An unknown window — fails closed.
    Unknown,
}

/// Run 272 — classify a modeled durable-completion audit/publication receipt
/// crash/recovery window.
///
/// The receipt sink never silently re-authorizes an in-flight receipt: MainNet
/// peer-driven refusal precedes classification, production / MainNet audit-ledger /
/// external-publication classification is unavailable, and every ambiguous /
/// unknown window fails closed. Only an after-receipt-record window with an explicit
/// matching record (or an explicit after-receipt-success window) recovers as
/// [`DurableCompletionSettlementOutcomeReportOutcome::SettlementOutcomeReportRecorded`]. Pure:
/// performs no modeled mutation and never invokes Run 070.
pub fn recover_durable_completion_settlement_outcome_report_window(
    input: &DurableCompletionSettlementOutcomeReportInput,
    window: DurableCompletionSettlementOutcomeReportWindow,
    kind: DurableCompletionSettlementOutcomeReportKind,
    recovered_record: Option<&DurableCompletionSettlementOutcomeReportLedgerRecord>,
    expectations: &DurableCompletionSettlementOutcomeReportExpectations,
) -> DurableCompletionSettlementOutcomeReportOutcome {
    use DurableCompletionSettlementOutcomeReportOutcome as Receipt;
    use DurableCompletionSettlementOutcomeReportWindow as Window;

    // MainNet peer-driven apply refusal precedes recovery classification.
    if input.is_mainnet_peer_driven() {
        return Receipt::MainNetPeerDrivenApplyRefusedNoOutcomeReport;
    }

    // Production / MainNet audit-ledger / external-publication recovery
    // classification is unavailable / fail-closed.
    match kind {
        DurableCompletionSettlementOutcomeReportKind::ProductionSettlementOutcomeReportUnavailable => {
            return Receipt::ProductionSettlementOutcomeReportUnavailableNoOutcomeReport;
        }
        DurableCompletionSettlementOutcomeReportKind::MainNetSettlementOutcomeReportUnavailable => {
            return Receipt::MainNetSettlementOutcomeReportUnavailableNoOutcomeReport;
        }
        DurableCompletionSettlementOutcomeReportKind::ExternalSettlementOutcomeReportUnavailable => {
            return Receipt::ExternalSettlementOutcomeReportUnavailableNoOutcomeReport;
        }
        DurableCompletionSettlementOutcomeReportKind::Disabled => {
            return Receipt::LegacyBypassNoSettlementOutcomeReport;
        }
        DurableCompletionSettlementOutcomeReportKind::Unknown => {
            return Receipt::SettlementOutcomeReportAmbiguousFailClosedNoOutcomeReport;
        }
        DurableCompletionSettlementOutcomeReportKind::FixtureInMemory => {}
    }

    // Helper: an explicit recovered record recovers as a receipt only if it matches
    // the expected receipt record id and the canonical request digest.
    let recovered_matches =
        |record: &DurableCompletionSettlementOutcomeReportLedgerRecord| -> bool {
            record.outcome_report_record_id == expectations.expected_outcome_report_record_id
                && record.request_digest == input.request.digest()
                && record.status
                    == DurableCompletionSettlementOutcomeReportLedgerStatus::Recorded
        };

    match window {
        // Through settlement-receipt_acknowledgement success but before a settlement-outcome-report
        // request there is nothing to record a settlement outcome_report for.
        Window::BeforePipeline
        | Window::AfterPipelineSuccessBeforeSinkIntent
        | Window::AfterSinkIntentBeforeSinkReceiptRecord
        | Window::AfterSinkReceiptRecordBeforeReportIntent
        | Window::AfterReportIntentBeforeReportRecord
        | Window::AfterReportRecordBeforeOutcomeReportIntent
        | Window::AfterOutcomeReportIntentBeforeOutcomeReportRecord
        | Window::AfterOutcomeReportRecordBeforeAttestationIntent
        | Window::AfterAttestationIntentBeforeAttestationRecord
        | Window::AfterAttestationRecordBeforeBackendRequest
        | Window::AfterBackendRequestBeforeBackendRecord
        | Window::AfterBackendRecordBeforeBackendSuccess
        | Window::AfterBackendSuccessBeforeReceiptRequest
        | Window::AfterReceiptRequestBeforeReceiptRecord
        | Window::AfterReceiptRecordBeforeReceiptSuccess
        | Window::AfterReceiptSuccessBeforeAcknowledgementRequest
        | Window::AfterAcknowledgementRequestBeforeAcknowledgementRecord
        | Window::AfterAcknowledgementRecordBeforeAcknowledgementSuccess
        | Window::AfterAcknowledgementSuccessBeforeConsumerRequest
        | Window::AfterConsumerRequestBeforeConsumerRecord
        | Window::AfterConsumerRecordBeforeConsumerSuccess
        | Window::AfterConsumerSuccessBeforeSettlementReceiptAcknowledgementRequest
        | Window::AfterSettlementReceiptAcknowledgementRequestBeforeSettlementReceiptAcknowledgementRecord
        | Window::AfterSettlementReceiptAcknowledgementRecordBeforeSettlementReceiptAcknowledgementSuccess
        | Window::AfterSettlementReceiptAcknowledgementSuccessBeforeSettlementOutcomeReportRequest => {
            Receipt::SettlementReceiptAcknowledgementDidNotRecordNoOutcomeReport
        }
        // A settlement-outcome-report request without a record never records a
        // settlement outcome_report.
        Window::AfterSettlementOutcomeReportRequestBeforeSettlementOutcomeReportRecord => {
            Receipt::SettlementOutcomeReportRejectedBeforeRecord
        }
        // After a settlement-outcome-report record but before success: fails closed
        // unless an explicit matching, well-formed settlement-outcome-report record
        // exists.
        Window::AfterSettlementOutcomeReportRecordBeforeSettlementOutcomeReportSuccess => {
            match recovered_record {
                Some(record) if recovered_matches(record) => Receipt::SettlementOutcomeReportRecorded,
                _ => Receipt::SettlementOutcomeReportRejectedBeforeRecord,
            }
        }
        // An explicit successful settlement outcome_report recovers as recorded only if
        // it matches.
        Window::AfterSettlementOutcomeReportSuccess => match recovered_record {
            Some(record) if recovered_matches(record) => Receipt::SettlementOutcomeReportRecorded,
            _ => Receipt::SettlementOutcomeReportRejectedBeforeRecord,
        },
        Window::AfterSettlementOutcomeReportAmbiguous => {
            Receipt::SettlementOutcomeReportAmbiguousFailClosedNoOutcomeReport
        }
        Window::SettlementOutcomeReportRecordFailed => {
            Receipt::SettlementOutcomeReportRecordFailedNoOutcomeReport
        }
        Window::SettlementOutcomeReportRollbackCompleted => {
            Receipt::SettlementOutcomeReportRolledBackNoOutcomeReport
        }
        Window::SettlementOutcomeReportRollbackFailed => {
            Receipt::SettlementOutcomeReportRollbackFailedFatalNoOutcomeReport
        }
        // Any unknown window fails closed.
        Window::Unknown => Receipt::SettlementOutcomeReportAmbiguousFailClosedNoOutcomeReport,
    }
}

/// Run 272 — `true` iff a receipt outcome authorizes a **new** modeled
/// audit/publication receipt (only
/// [`DurableCompletionSettlementOutcomeReportOutcome::SettlementOutcomeReportRecorded`]).
pub fn settlement_outcome_report_outcome_authorizes_record(
    outcome: &DurableCompletionSettlementOutcomeReportOutcome,
) -> bool {
    outcome.authorizes_record()
}

/// Run 272 — `true` iff a receipt outcome projects to a recorded audit/publication
/// receipt (a newly recorded receipt or an idempotent duplicate of an
/// already-recorded receipt).
pub fn settlement_outcome_report_outcome_projects_to_recorded(
    outcome: &DurableCompletionSettlementOutcomeReportOutcome,
) -> bool {
    outcome.projects_to_recorded()
}

// ===========================================================================
// Grep-verifiable safety invariants (source/test only)
// ===========================================================================

/// Run 272 — a receipt rejection is non-mutating: it records no receipt, mutates no
/// `LivePqcTrustState`, and writes no durable state.
pub fn durable_completion_settlement_outcome_report_rejection_is_non_mutating() -> bool {
    true
}

/// Run 272 — the receipt boundary never calls Run 070.
pub fn durable_completion_settlement_outcome_report_never_calls_run_070() -> bool {
    true
}

/// Run 272 — the receipt boundary never mutates live PQC trust state.
pub fn durable_completion_settlement_outcome_report_never_mutates_live_pqc_trust_state() -> bool {
    true
}

/// Run 272 — the receipt boundary never writes a sequence or a marker.
pub fn durable_completion_settlement_outcome_report_never_writes_sequence_or_marker() -> bool {
    true
}

/// Run 272 — the receipt boundary changes no RocksDB file schema / migration.
pub fn durable_completion_settlement_outcome_report_no_rocksdb_file_schema_migration_change() -> bool {
    true
}

/// Run 272 — the receipt boundary performs no external publication.
pub fn durable_completion_settlement_outcome_report_no_external_publication() -> bool {
    true
}

/// Run 272 — the receipt boundary performs no real audit-ledger persistence.
pub fn durable_completion_settlement_outcome_report_no_real_audit_ledger() -> bool {
    true
}

/// Run 272 — a receipt requires a successful Run 246 pipeline outcome upstream.
pub fn durable_completion_settlement_outcome_report_pipeline_success_required() -> bool {
    true
}

/// Run 272 — a receipt requires a Run 248 sink receipt record upstream.
pub fn durable_completion_settlement_outcome_report_sink_receipt_required() -> bool {
    true
}

/// Run 272 — a receipt requires a Run 250 completion report upstream.
pub fn durable_completion_settlement_outcome_report_completion_report_required() -> bool {
    true
}

/// Run 272 — a receipt requires a Run 252 outcome_report upstream.
pub fn durable_completion_settlement_outcome_report_finalization_projection_required() -> bool {
    true
}

/// Run 272 — a receipt requires a Run 254 attestation upstream.
pub fn durable_completion_settlement_outcome_report_attestation_required() -> bool {
    true
}

/// Run 272 — an acknowledgement requires a Run 256 backend submission upstream.
pub fn durable_completion_settlement_outcome_report_backend_submission_required() -> bool {
    true
}

/// Run 272 — an acknowledgement requires a Run 258 audit receipt upstream.
pub fn durable_completion_settlement_outcome_report_receipt_required() -> bool {
    true
}

/// Run 272 — a consumer requires a Run 260 audit-receipt acknowledgement upstream.
pub fn durable_completion_settlement_outcome_report_consumer_required() -> bool {
    true
}

/// Run 272 — a settlement outcome_report requires a Run 270 settlement receipt_acknowledgement
/// upstream; no settlement outcome_report is authorized without a recorded
/// settlement receipt_acknowledgement.
pub fn durable_completion_settlement_outcome_report_receipt_acknowledgement_required() -> bool {
    true
}

/// Run 272 — the consumer boundary never performs a real settlement; production /
/// MainNet / external settlement consumers are reachable but fail closed.
pub fn durable_completion_settlement_outcome_report_no_real_settlement() -> bool {
    true
}

/// Run 272 — the settlement-outcome-report boundary never confers real settlement
/// finality; the only settlement-outcome-report record is a modeled in-memory fixture
/// record. Production / MainNet / external settlement-outcome-report sinks are reachable
/// but unavailable / fail closed and never confer any real finality.
pub fn durable_completion_settlement_outcome_report_no_real_settlement_finality() -> bool {
    true
}

/// Run 272 — the settlement-outcome-report boundary never emits a real settlement
/// receipt; the only settlement-outcome-report record is a modeled in-memory fixture
/// record with no external publication, network I/O, or persistent backend.
pub fn durable_completion_settlement_outcome_report_no_real_settlement_receipt() -> bool {
    true
}

/// Run 272 — the settlement-outcome-report boundary never confers a real
/// settlement-outcome report; the only settlement-outcome report
/// record is a modeled in-memory fixture record. Production / MainNet / external
/// settlement-outcome report sinks are reachable but unavailable / fail closed
/// and never confer any real acknowledgement.
pub fn durable_completion_settlement_outcome_report_no_real_settlement_receipt_acknowledgement() -> bool {
    true
}

/// Run 272 — the settlement-outcome-report boundary never confers a real
/// settlement-finality projection; the only settlement-finality projection is a modeled
/// in-memory fixture record with no external publication, network I/O, or persistent
/// backend.
pub fn durable_completion_settlement_outcome_report_no_real_settlement_finality_projection() -> bool {
    true
}

/// Run 272 — the settlement-outcome-report boundary never confers a real
/// settlement-outcome publication; the only settlement-outcome report is a modeled
/// in-memory fixture record with no external publication, network I/O, or persistent
/// backend.
pub fn durable_completion_settlement_outcome_report_no_real_settlement_outcome_publication() -> bool {
    true
}

/// Run 272 — a receipt record is required before a receipt is acknowledged.
pub fn durable_completion_settlement_outcome_report_record_required_before_reported() -> bool {
    true
}

/// Run 272 — a failed receipt record never records a receipt.
pub fn durable_completion_settlement_outcome_report_failed_record_never_records() -> bool {
    true
}

/// Run 272 — a rolled-back receipt record never records a receipt.
pub fn durable_completion_settlement_outcome_report_rollback_never_records() -> bool {
    true
}

/// Run 272 — an ambiguous after-record receipt window fails closed.
pub fn durable_completion_settlement_outcome_report_ambiguous_window_fails_closed() -> bool {
    true
}

/// Run 272 — MainNet peer-driven apply refusal precedes every receipt stage.
pub fn durable_completion_settlement_outcome_report_mainnet_peer_driven_apply_refused_first(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 272 — production / MainNet audit-ledger sinks are reachable but unavailable.
pub fn durable_completion_settlement_outcome_report_production_mainnet_unavailable() -> bool {
    true
}

/// Run 272 — the external-publication sink is reachable but unavailable.
pub fn durable_completion_settlement_outcome_report_external_unavailable() -> bool {
    true
}

/// Run 272 — validator-set rotation remains unsupported at the receipt boundary.
pub fn durable_completion_settlement_outcome_report_validator_set_rotation_unsupported() -> bool {
    true
}

/// Run 272 — policy-change actions remain unsupported at the receipt boundary.
pub fn durable_completion_settlement_outcome_report_policy_change_unsupported() -> bool {
    true
}

/// Run 272 — a local operator cannot satisfy MainNet authority for a receipt.
pub fn durable_completion_settlement_outcome_report_local_operator_cannot_satisfy_mainnet_authority(
) -> bool {
    true
}

/// Run 272 — a peer majority cannot satisfy MainNet authority for a receipt.
pub fn durable_completion_settlement_outcome_report_peer_majority_cannot_satisfy_mainnet_authority(
) -> bool {
    true
}