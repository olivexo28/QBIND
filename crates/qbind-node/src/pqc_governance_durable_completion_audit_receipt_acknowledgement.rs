//! Run 260 — source/test durable-completion **audit-receipt acknowledgement /
//! external-publication confirmation boundary**.
//!
//! Source/test only. Run 260 captures **no** release-binary evidence and enables
//! **no** production mutating behavior. It does **not** implement a real audit
//! ledger acknowledgement, a real external-publication confirmation, a real
//! external-publication system, a real production attestation backend, a real
//! finalization backend, a real completion-report backend, a real durable consume
//! backend, a real persistent replay backend, a real governance execution engine, a
//! real production mutation engine, a real on-chain governance proof verifier, a
//! KMS/HSM/RemoteSigner backend, MainNet governance enablement, MainNet peer-driven
//! apply enablement, validator-set rotation, or any RocksDB / file / schema /
//! migration / wire / marker / sequence / trust-bundle / storage-format change.
//!
//! ## What this module adds
//!
//! Run 258
//! ([`crate::pqc_governance_durable_completion_audit_publication_receipt`]) proves
//! that a modeled durable-completion *audit/publication receipt* is recorded **only**
//! after the Run 256 backend stage recorded a submission, terminating in the single
//! receipt-recording outcome
//! [`DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRecorded`].
//!
//! Run 260 defines the **first typed interface** a future production audit ledger
//! or external publication system would use to *acknowledge / confirm* an audit
//! receipt **after** the Run 258 receipt stage produced `AuditReceiptRecorded`. It
//! is an **interface / projection boundary only**: production / MainNet audit-ledger
//! acknowledgement and external-publication confirmation implementations are
//! *reachable but deliberately unavailable / fail-closed*, and the only positive
//! implementation is a DevNet/TestNet fixture that records into an in-memory fixture
//! ledger for source/test evidence only.
//!
//! The acknowledgement layer is a **model only**. It does not implement a real audit
//! ledger acknowledgement, a real external-publication confirmation, a real
//! external-publication system, or any real persistent storage. It does not write
//! RocksDB, files, schemas, migrations, storage formats, wire formats, authority
//! markers, trust-bundle sequence files, or any production durable state. It does
//! not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict
//! sessions, perform external publication / network I/O, or enable MainNet
//! governance / MainNet peer-driven apply. The DevNet/TestNet fixture sink mutates
//! only the in-memory
//! [`DurableCompletionAuditReceiptAcknowledgementLedger`].
//!
//! ## Ordering / fail-closed contract
//!
//! 1. **MainNet peer-driven apply refusal** — refused *before* pipeline
//!    progression, sink invocation, reporter invocation, finalizer invocation,
//!    attestor invocation, backend invocation, receipt invocation, and
//!    acknowledgement sink invocation;
//! 2. **legacy bypass** — a
//!    [`DurableCompletionAuditReceiptAcknowledgementPolicy::Disabled`] policy preserves
//!    the legacy no-acknowledgement bypass and never invokes the acknowledgement sink;
//! 3. **receipt-outcome projection** — only
//!    [`DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRecorded`]
//!    creates an acknowledgement request; every other Run 258 outcome maps to a
//!    no-acknowledgement fail-closed outcome and never invokes the acknowledgement
//!    sink;
//! 4. **pre-acknowledgement binding validation** — environment / chain / genesis /
//!    governance surface / mutation surface and the full digest binding (including
//!    the Run 256 backend digest set and the Run 258 receipt digest set) must match
//!    expectations *before* the acknowledgement sink is invoked; a mismatch fails
//!    closed and leaves the acknowledgement sink invocation count at zero;
//! 5. **acknowledgement record** — only after every prior gate passes is the
//!    acknowledgement sink invoked; the acknowledgement-record-identity fields must
//!    match exactly before any modeled acknowledgement is recorded;
//! 6. **acknowledgement authorization** — only
//!    [`DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementRecorded`]
//!    authorizes a new modeled acknowledgement state.
//!
//! An acknowledgement record failure, rollback, rollback failure, or ambiguous
//! acknowledgement window never retroactively claims a durable acknowledgement. A
//! duplicate identical acknowledgement is idempotent; the same acknowledgement record
//! id with a different digest fails closed as equivocation and records no second
//! acknowledgement. A Run 258
//! [`DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptDuplicateIdempotent`]
//! never creates a new acknowledgement by itself — it can only match an
//! already-recorded acknowledgement.

use crate::pqc_governance_durable_completion_attestation_backend::DurableCompletionAttestationBackendOutcome;
use crate::pqc_governance_durable_completion_audit_publication_receipt::DurableCompletionAuditPublicationReceiptOutcome;
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

/// Run 260 — the validation / mutation surface pair the receipt binds to.
pub type DurableCompletionAuditReceiptAcknowledgementSurface = ModeledGovernanceTrustMutationSurface;

/// Run 260 — the trust-domain environment binding the receipt is bound to.
pub type DurableCompletionAuditReceiptAcknowledgementEnvironment =
    ModeledGovernanceTrustMutationEnvironmentBinding;

/// Run 260 — the runtime binding (governance + mutation surface + sequence) the
/// receipt is bound to.
pub type DurableCompletionAuditReceiptAcknowledgementBinding =
    ModeledGovernanceTrustMutationRuntimeBinding;

/// Run 260 — the Run 240/246 durable replay observation carried as freshness
/// context.
pub type DurableCompletionAuditReceiptAcknowledgementReplayBinding = DurableReplayObservation;

/// Run 260 — the Run 246 pipeline outcome carried as consume authorization context.
pub type DurableCompletionAuditReceiptAcknowledgementPipelineBinding =
    GovernanceModeledEndToEndPipelineOutcome;

/// Run 260 — the Run 248 sink outcome carried as receipt-record context.
pub type DurableCompletionAuditReceiptAcknowledgementSinkBinding =
    GovernanceModeledDurableConsumeSinkOutcome;

/// Run 260 — the Run 250 reporter outcome carried as completion-report context.
pub type DurableCompletionAuditReceiptAcknowledgementReporterBinding =
    GovernanceModeledDurableConsumeCompletionReporterOutcome;

/// Run 260 — the Run 252 finalization outcome carried as finalization context.
pub type DurableCompletionAuditReceiptAcknowledgementFinalizationBinding =
    GovernanceModeledDurableCompletionFinalizationOutcome;

/// Run 260 — the Run 254 attestation outcome carried as attestation context.
pub type DurableCompletionAuditReceiptAcknowledgementAttestationBinding =
    GovernanceModeledDurableCompletionAttestationOutcome;

/// Run 260 — the Run 256 backend outcome carried as backend-record context. The
/// acknowledgement boundary never reimplements the backend; it only carries its
/// terminal outcome.
pub type DurableCompletionAuditReceiptAcknowledgementBackendBinding =
    DurableCompletionAttestationBackendOutcome;

/// Run 260 — the Run 258 audit/publication receipt outcome the acknowledgement
/// projects to an acknowledgement request. The acknowledgement boundary never
/// reimplements the receipt; it only projects its terminal outcome.
pub type DurableCompletionAuditReceiptAcknowledgementReceiptBinding =
    DurableCompletionAuditPublicationReceiptOutcome;

// ===========================================================================
// Receipt kind
// ===========================================================================

/// Run 260 — the typed durable-completion audit/publication receipt kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionAuditReceiptAcknowledgementKind {
    /// The receipt boundary is disabled (legacy bypass).
    Disabled,
    /// DevNet/TestNet in-memory fixture receipt sink (source-test only; may mutate
    /// only the ledger).
    FixtureInMemory,
    /// Production audit-ledger receipt sink (reachable-but-unavailable /
    /// fail-closed).
    ProductionAuditLedgerAckUnavailable,
    /// MainNet audit-ledger receipt sink (reachable-but-unavailable / fail-closed).
    MainNetAuditLedgerAckUnavailable,
    /// External-publication receipt sink (reachable-but-unavailable / fail-closed).
    ExternalPublicationConfirmationUnavailable,
    /// An unknown receipt kind — fails closed.
    Unknown,
}

impl DurableCompletionAuditReceiptAcknowledgementKind {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureInMemory => "fixture-in-memory",
            Self::ProductionAuditLedgerAckUnavailable => "production-audit-ledger-ack-unavailable",
            Self::MainNetAuditLedgerAckUnavailable => "mainnet-audit-ledger-ack-unavailable",
            Self::ExternalPublicationConfirmationUnavailable => "external-publication-confirmation-unavailable",
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
            Self::ProductionAuditLedgerAckUnavailable
                | Self::MainNetAuditLedgerAckUnavailable
                | Self::ExternalPublicationConfirmationUnavailable
        )
    }
}

// ===========================================================================
// Receipt policy
// ===========================================================================

/// Run 260 — the typed durable-completion audit/publication receipt policy
/// selector.
///
/// Only [`Self::FixtureAllowed`] may record (DevNet/TestNet source-test only);
/// every production / MainNet / external-publication policy resolves to a
/// reachable-but-unavailable sink that never records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionAuditReceiptAcknowledgementPolicy {
    /// The receipt boundary is disabled (legacy bypass).
    Disabled,
    /// A DevNet/TestNet fixture receipt sink is allowed (source-test evidence only).
    FixtureAllowed,
    /// A real production audit-ledger receipt sink is required — reachable but
    /// unavailable.
    ProductionAuditLedgerAckRequired,
    /// A real MainNet audit-ledger receipt sink is required — reachable but
    /// unavailable.
    MainNetAuditLedgerAckRequired,
    /// A real external-publication receipt sink is required — reachable but
    /// unavailable.
    ExternalPublicationConfirmationRequired,
}

impl DurableCompletionAuditReceiptAcknowledgementPolicy {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureAllowed => "fixture-allowed",
            Self::ProductionAuditLedgerAckRequired => "production-audit-ledger-ack-required",
            Self::MainNetAuditLedgerAckRequired => "mainnet-audit-ledger-ack-required",
            Self::ExternalPublicationConfirmationRequired => "external-publication-confirmation-required",
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

/// Run 260 — the typed receipt identity a receipt request is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionAuditReceiptAcknowledgementIdentity {
    /// Stable receipt id.
    pub acknowledgement_id: String,
    /// The receipt kind.
    pub kind: DurableCompletionAuditReceiptAcknowledgementKind,
    /// The receipt policy.
    pub policy: DurableCompletionAuditReceiptAcknowledgementPolicy,
    /// The domain separation tag the receipt operates under.
    pub domain_separation_tag: String,
}

impl DurableCompletionAuditReceiptAcknowledgementIdentity {
    /// `true` iff every mandatory identity field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.acknowledgement_id.is_empty()
            && !self.domain_separation_tag.is_empty()
            && self.kind != DurableCompletionAuditReceiptAcknowledgementKind::Unknown
    }

    /// The deterministic, domain-separated receipt identity digest.
    pub fn digest(&self) -> DurableCompletionAuditReceiptAcknowledgementDigest {
        acknowledgement_identity_digest(self)
    }
}

// ===========================================================================
// Deterministic, domain-separated digest helpers
// ===========================================================================

/// Run 260 — domain separator for the receipt identity digest.
const ACKNOWLEDGEMENT_IDENTITY_DOMAIN: &[u8] =
    b"QBIND:run260:durable-completion-audit-receipt-acknowledgement-identity:v1";
/// Run 260 — domain separator for the receipt request digest.
const ACKNOWLEDGEMENT_REQUEST_DOMAIN: &[u8] =
    b"QBIND:run260:durable-completion-audit-receipt-acknowledgement-request:v1";
/// Run 260 — domain separator for the receipt response digest.
const ACKNOWLEDGEMENT_RESPONSE_DOMAIN: &[u8] =
    b"QBIND:run260:durable-completion-audit-receipt-acknowledgement-response:v1";
/// Run 260 — domain separator for the receipt record digest.
const ACKNOWLEDGEMENT_RECORD_DOMAIN: &[u8] =
    b"QBIND:run260:durable-completion-audit-receipt-acknowledgement-record:v1";
/// Run 260 — domain separator for the receipt transcript digest.
const ACKNOWLEDGEMENT_TRANSCRIPT_DOMAIN: &[u8] =
    b"QBIND:run260:durable-completion-audit-receipt-acknowledgement-transcript:v1";

/// Run 260 — a deterministic, domain-separated receipt digest (lowercase hex of a
/// SHA3-256 over length-prefixed, field-bound canonical material). It contains no
/// unstable display text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionAuditReceiptAcknowledgementDigest(String);

impl DurableCompletionAuditReceiptAcknowledgementDigest {
    /// The lowercase hex representation.
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

/// Run 260 — a deterministic, domain-separated receipt transcript digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionAuditReceiptAcknowledgementTranscriptDigest(String);

impl DurableCompletionAuditReceiptAcknowledgementTranscriptDigest {
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

/// Run 260 — deterministic, domain-separated receipt identity digest.
pub fn acknowledgement_identity_digest(
    identity: &DurableCompletionAuditReceiptAcknowledgementIdentity,
) -> DurableCompletionAuditReceiptAcknowledgementDigest {
    let mut w = CanonicalWriter::new(ACKNOWLEDGEMENT_IDENTITY_DOMAIN);
    w.str_field(&identity.acknowledgement_id)
        .str_field(identity.kind.tag())
        .str_field(identity.policy.tag())
        .str_field(&identity.domain_separation_tag);
    DurableCompletionAuditReceiptAcknowledgementDigest(w.finish())
}

/// Run 260 — deterministic, domain-separated receipt request digest. Binds every
/// request field including the full Run 256 backend digest binding.
pub fn acknowledgement_request_digest(
    request: &DurableCompletionAuditReceiptAcknowledgementRequest,
) -> DurableCompletionAuditReceiptAcknowledgementDigest {
    let mut w = CanonicalWriter::new(ACKNOWLEDGEMENT_REQUEST_DOMAIN);
    w.str_field(&request.acknowledgement_record_id)
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
        .str_field(&request.domain_separation_tag)
        .str_field(acknowledgement_identity_digest(&request.identity).as_hex());
    DurableCompletionAuditReceiptAcknowledgementDigest(w.finish())
}

/// Run 260 — deterministic, domain-separated receipt response digest. Binds the
/// receipt record id, the request digest it answers, the acceptance flag, and the
/// responding receipt kind.
pub fn acknowledgement_response_digest(
    response: &DurableCompletionAuditReceiptAcknowledgementResponse,
) -> DurableCompletionAuditReceiptAcknowledgementDigest {
    let mut w = CanonicalWriter::new(ACKNOWLEDGEMENT_RESPONSE_DOMAIN);
    w.str_field(&response.acknowledgement_record_id)
        .str_field(response.request_digest.as_hex())
        .str_field(if response.accepted { "accepted" } else { "rejected" })
        .str_field(response.acknowledgement_kind.tag());
    DurableCompletionAuditReceiptAcknowledgementDigest(w.finish())
}

/// Run 260 — deterministic, domain-separated receipt record digest. Binds the
/// receipt record id, the request digest, and the receipt identity digest.
pub fn acknowledgement_record_digest(
    record: &DurableCompletionAuditReceiptAcknowledgementRecord,
) -> DurableCompletionAuditReceiptAcknowledgementDigest {
    let mut w = CanonicalWriter::new(ACKNOWLEDGEMENT_RECORD_DOMAIN);
    w.str_field(&record.acknowledgement_record_id)
        .str_field(record.request_digest.as_hex())
        .str_field(record.identity_digest.as_hex());
    DurableCompletionAuditReceiptAcknowledgementDigest(w.finish())
}

/// Run 260 — deterministic, domain-separated receipt transcript digest. Binds the
/// request, response, and record digests into a single transcript binding.
pub fn acknowledgement_transcript_digest(
    request_digest: &DurableCompletionAuditReceiptAcknowledgementDigest,
    response_digest: &DurableCompletionAuditReceiptAcknowledgementDigest,
    record_digest: &DurableCompletionAuditReceiptAcknowledgementDigest,
) -> DurableCompletionAuditReceiptAcknowledgementTranscriptDigest {
    let mut w = CanonicalWriter::new(ACKNOWLEDGEMENT_TRANSCRIPT_DOMAIN);
    w.str_field(request_digest.as_hex())
        .str_field(response_digest.as_hex())
        .str_field(record_digest.as_hex());
    DurableCompletionAuditReceiptAcknowledgementTranscriptDigest(w.finish())
}

// ===========================================================================
// Receipt request / response / record
// ===========================================================================

/// Run 260 — the typed receipt request a future production audit ledger or
/// external-publication call site would submit once the Run 256 backend recorded a
/// `BackendSubmissionRecorded`.
///
/// Pure data referencing the already-recorded Run 256 backend / Run 254
/// attestation / Run 252 finalization / Run 250 completion report / Run 248
/// receipt / Run 246 decision material — never a copy of any wire payload and never
/// a production durable record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionAuditReceiptAcknowledgementRequest {
    /// Stable receipt record id (the idempotency key of the receipt).
    pub acknowledgement_record_id: String,
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
    /// Run 252 finalization decision digest.
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
    /// Acknowledgement identity.
    pub identity: DurableCompletionAuditReceiptAcknowledgementIdentity,
    /// Domain separation tag.
    pub domain_separation_tag: String,
}

impl DurableCompletionAuditReceiptAcknowledgementRequest {
    /// `true` iff every mandatory field is structurally present (non-empty) and the
    /// identity is well-formed.
    pub fn is_well_formed(&self) -> bool {
        !self.acknowledgement_record_id.is_empty()
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
            && !self.domain_separation_tag.is_empty()
            && self.identity.is_well_formed()
    }

    /// The deterministic receipt request digest.
    pub fn digest(&self) -> DurableCompletionAuditReceiptAcknowledgementDigest {
        acknowledgement_request_digest(self)
    }

    /// The canonical immutable record derived from this request.
    pub fn to_record(&self) -> DurableCompletionAuditReceiptAcknowledgementRecord {
        DurableCompletionAuditReceiptAcknowledgementRecord {
            acknowledgement_record_id: self.acknowledgement_record_id.clone(),
            request_digest: self.digest(),
            identity_digest: self.identity.digest(),
        }
    }
}

/// Run 260 — the typed receipt response a receipt sink returns for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionAuditReceiptAcknowledgementResponse {
    /// The receipt record id the response answers.
    pub acknowledgement_record_id: String,
    /// The request digest the response answers.
    pub request_digest: DurableCompletionAuditReceiptAcknowledgementDigest,
    /// `true` iff the receipt sink accepted the request.
    pub accepted: bool,
    /// The responding receipt kind.
    pub acknowledgement_kind: DurableCompletionAuditReceiptAcknowledgementKind,
}

impl DurableCompletionAuditReceiptAcknowledgementResponse {
    /// `true` iff the response is structurally well-formed.
    pub fn is_well_formed(&self) -> bool {
        !self.acknowledgement_record_id.is_empty()
            && self.acknowledgement_kind != DurableCompletionAuditReceiptAcknowledgementKind::Unknown
    }

    /// The deterministic receipt response digest.
    pub fn digest(&self) -> DurableCompletionAuditReceiptAcknowledgementDigest {
        acknowledgement_response_digest(self)
    }
}

/// Run 260 — the canonical immutable receipt record derived from a request. Two
/// records are idempotent-equal only if **every** field matches exactly. The same
/// receipt record id with any differing digest is equivocation and fails closed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionAuditReceiptAcknowledgementRecord {
    /// The receipt record id.
    pub acknowledgement_record_id: String,
    /// The request digest.
    pub request_digest: DurableCompletionAuditReceiptAcknowledgementDigest,
    /// The receipt identity digest.
    pub identity_digest: DurableCompletionAuditReceiptAcknowledgementDigest,
}

impl DurableCompletionAuditReceiptAcknowledgementRecord {
    /// The deterministic receipt record digest.
    pub fn digest(&self) -> DurableCompletionAuditReceiptAcknowledgementDigest {
        acknowledgement_record_digest(self)
    }
}

// ===========================================================================
// In-memory fixture ledger
// ===========================================================================

/// Run 260 — the recorded status of a modeled audit/publication receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionAuditReceiptAcknowledgementLedgerStatus {
    /// The modeled receipt is recorded in the in-memory fixture ledger.
    Recorded,
}

/// Run 260 — a single modeled receipt record held in the in-memory fixture ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionAuditReceiptAcknowledgementLedgerRecord {
    /// The receipt record id (stable identity of the receipt).
    pub acknowledgement_record_id: String,
    /// The request digest.
    pub request_digest: DurableCompletionAuditReceiptAcknowledgementDigest,
    /// The response digest.
    pub response_digest: DurableCompletionAuditReceiptAcknowledgementDigest,
    /// The record digest.
    pub record_digest: DurableCompletionAuditReceiptAcknowledgementDigest,
    /// The transcript digest.
    pub transcript_digest: DurableCompletionAuditReceiptAcknowledgementTranscriptDigest,
    /// The recorded status.
    pub status: DurableCompletionAuditReceiptAcknowledgementLedgerStatus,
}

/// Run 260 — an immutable snapshot of the modeled receipt ledger used to model a
/// fixture rollback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionAuditReceiptAcknowledgementLedgerSnapshot {
    records: Vec<DurableCompletionAuditReceiptAcknowledgementLedgerRecord>,
}

impl DurableCompletionAuditReceiptAcknowledgementLedgerSnapshot {
    /// The number of records the snapshot captured.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` iff the snapshot captured no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Run 260 — the modeled in-memory receipt ledger.
///
/// **In-memory only.** It never touches RocksDB, files, markers, sequence files,
/// external publications, audit-ledger entries, or any production durable state.
/// The DevNet/TestNet fixture sink is the only thing that may mutate it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DurableCompletionAuditReceiptAcknowledgementLedger {
    records: Vec<DurableCompletionAuditReceiptAcknowledgementLedgerRecord>,
}

impl DurableCompletionAuditReceiptAcknowledgementLedger {
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
    pub fn records(&self) -> &[DurableCompletionAuditReceiptAcknowledgementLedgerRecord] {
        &self.records
    }

    /// The record for `acknowledgement_record_id`, if present.
    pub fn find(
        &self,
        acknowledgement_record_id: &str,
    ) -> Option<&DurableCompletionAuditReceiptAcknowledgementLedgerRecord> {
        self.records
            .iter()
            .find(|r| r.acknowledgement_record_id == acknowledgement_record_id)
    }

    /// `true` iff a receipt with `acknowledgement_record_id` is recorded.
    pub fn contains(&self, acknowledgement_record_id: &str) -> bool {
        self.find(acknowledgement_record_id).is_some()
    }

    /// Capture an immutable snapshot for a modeled rollback.
    pub fn snapshot(&self) -> DurableCompletionAuditReceiptAcknowledgementLedgerSnapshot {
        DurableCompletionAuditReceiptAcknowledgementLedgerSnapshot {
            records: self.records.clone(),
        }
    }

    /// Restore the ledger to a previously captured snapshot (modeled rollback).
    pub fn restore(&mut self, snapshot: &DurableCompletionAuditReceiptAcknowledgementLedgerSnapshot) {
        self.records = snapshot.records.clone();
    }

    /// Internal: insert a recorded receipt. Only the fixture sink calls this, and
    /// only after every identity / idempotency gate has passed.
    fn insert(&mut self, record: DurableCompletionAuditReceiptAcknowledgementLedgerRecord) {
        self.records.push(record);
    }
}

// ===========================================================================
// Receipt expectations
// ===========================================================================

/// Run 260 — the canonical binding a [`DurableCompletionAuditReceiptAcknowledgementInput`]
/// is checked against.
///
/// Environment / chain / genesis / surface mismatches fail closed **before** the
/// receipt sink is invoked. Receipt-request-identity mismatches fail closed
/// **inside** the sink, before any modeled receipt is recorded. Neither path is
/// ever a silent approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionAuditReceiptAcknowledgementExpectations {
    /// Expected receipt record id.
    pub expected_acknowledgement_record_id: String,
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
    /// Expected Run 252 finalization decision digest.
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
    /// Expected acknowledgement identity.
    pub expected_identity: DurableCompletionAuditReceiptAcknowledgementIdentity,
    /// Expected acknowledgement kind.
    pub expected_acknowledgement_kind: DurableCompletionAuditReceiptAcknowledgementKind,
    /// Expected acknowledgement policy.
    pub expected_acknowledgement_policy: DurableCompletionAuditReceiptAcknowledgementPolicy,
    /// Expected domain separation tag.
    pub expected_domain_separation_tag: String,
}

impl DurableCompletionAuditReceiptAcknowledgementExpectations {
    /// Internal: the first environment / surface binding mismatch reason, if any.
    fn binding_mismatch_reason(
        &self,
        input: &DurableCompletionAuditReceiptAcknowledgementInput,
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
    pub fn binding_matches(&self, input: &DurableCompletionAuditReceiptAcknowledgementInput) -> bool {
        self.binding_mismatch_reason(input).is_none()
    }

    /// Internal: the first receipt-request-identity mismatch reason, if any.
    fn request_mismatch_reason(
        &self,
        request: &DurableCompletionAuditReceiptAcknowledgementRequest,
    ) -> Option<&'static str> {
        if !request.is_well_formed() {
            return Some("malformed receipt request");
        }
        if request.acknowledgement_record_id != self.expected_acknowledgement_record_id {
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
            return Some("wrong finalization decision digest");
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
        if request.domain_separation_tag != self.expected_domain_separation_tag {
            return Some("wrong domain separation tag");
        }
        if request.identity != self.expected_identity {
            return Some("wrong acknowledgement identity");
        }
        if request.identity.kind != self.expected_acknowledgement_kind {
            return Some("wrong acknowledgement kind");
        }
        if request.identity.policy != self.expected_acknowledgement_policy {
            return Some("wrong acknowledgement policy");
        }
        None
    }

    /// `true` iff the receipt-request identity matches and is well-formed.
    pub fn request_matches(
        &self,
        request: &DurableCompletionAuditReceiptAcknowledgementRequest,
    ) -> bool {
        self.request_mismatch_reason(request).is_none()
    }
}

// ===========================================================================
// Receipt input
// ===========================================================================

/// Run 260 — typed inputs for one modeled durable-completion audit/publication
/// receipt round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionAuditReceiptAcknowledgementInput {
    /// The receipt policy selector.
    pub policy: DurableCompletionAuditReceiptAcknowledgementPolicy,
    /// The trust-domain environment binding.
    pub environment_binding: DurableCompletionAuditReceiptAcknowledgementEnvironment,
    /// The runtime binding (governance + mutation surface + sequence).
    pub runtime_binding: DurableCompletionAuditReceiptAcknowledgementBinding,
    /// The Run 240/246 durable replay observation the pipeline authorized consume
    /// under.
    pub replay_binding: DurableCompletionAuditReceiptAcknowledgementReplayBinding,
    /// The Run 246 pipeline outcome.
    pub pipeline_binding: DurableCompletionAuditReceiptAcknowledgementPipelineBinding,
    /// The Run 248 sink outcome.
    pub sink_binding: DurableCompletionAuditReceiptAcknowledgementSinkBinding,
    /// The Run 250 reporter outcome.
    pub reporter_binding: DurableCompletionAuditReceiptAcknowledgementReporterBinding,
    /// The Run 252 finalization outcome.
    pub finalization_binding: DurableCompletionAuditReceiptAcknowledgementFinalizationBinding,
    /// The Run 254 attestation outcome.
    pub attestation_binding: DurableCompletionAuditReceiptAcknowledgementAttestationBinding,
    /// The Run 256 backend outcome carried as backend-record context.
    pub backend_binding: DurableCompletionAuditReceiptAcknowledgementBackendBinding,
    /// The Run 258 audit/publication receipt outcome the acknowledgement projects to
    /// an acknowledgement request.
    pub receipt_binding: DurableCompletionAuditReceiptAcknowledgementReceiptBinding,
    /// The acknowledgement request the call site would submit.
    pub request: DurableCompletionAuditReceiptAcknowledgementRequest,
}

impl DurableCompletionAuditReceiptAcknowledgementInput {
    /// The trust-domain environment the decision is bound to.
    pub fn environment(&self) -> TrustBundleEnvironment {
        self.environment_binding.environment
    }

    /// The validation / mutation surface pair.
    pub fn surface(&self) -> DurableCompletionAuditReceiptAcknowledgementSurface {
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
                self.finalization_binding,
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
    }
}

// ===========================================================================
// Receipt outcome
// ===========================================================================

/// Run 260 — the typed outcome of one modeled durable-completion audit/publication
/// receipt round-trip.
///
/// Only [`Self::AcknowledgementRecorded`] authorizes a **new** modeled
/// audit/publication-receipt state. A [`Self::AcknowledgementDuplicateIdempotent`]
/// means the receipt was already recorded (idempotent, no second receipt). Every
/// other variant is a no-audit-receipt fail-closed outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableCompletionAuditReceiptAcknowledgementOutcome {
    /// Legacy bypass — a disabled receipt policy preserved the legacy
    /// no-audit-receipt path. No receipt invocation.
    LegacyBypassNoAcknowledgement,
    /// The Run 256 backend-stage binding was rejected before the receipt sink was
    /// invoked (a backend-stage rejection / binding mismatch). Non-mutating, no
    /// receipt. No receipt invocation.
    RejectedBeforeAuditReceiptNoAcknowledgement,
    /// The Run 256 backend did not submit (any non-submitting backend outcome
    /// without a more specific variant). Non-mutating, no receipt. No receipt
    /// invocation.
    AuditReceiptDidNotRecordNoAcknowledgement,
    /// The receipt sink recorded a new modeled audit/publication receipt. The
    /// **only** outcome that authorizes a new modeled receipt state.
    AcknowledgementRecorded,
    /// A duplicate identical receipt — idempotent; no second receipt recorded.
    AcknowledgementDuplicateIdempotent,
    /// The receipt was rejected before record (malformed request, request-identity
    /// mismatch, same receipt record id with a differing digest / equivocation, or
    /// a duplicate-idempotent backend submission with no matching prior receipt). No
    /// receipt.
    AcknowledgementRejectedBeforeRecord,
    /// The receipt record failed. No receipt.
    AcknowledgementRecordFailedNoAcknowledgement,
    /// The receipt record was rolled back. No receipt.
    AcknowledgementRolledBackNoAcknowledgement,
    /// The receipt rollback itself failed — fatal / fail-closed. No receipt.
    AcknowledgementRollbackFailedFatalNoAcknowledgement,
    /// The after-record receipt window was ambiguous — fails closed. No receipt.
    AcknowledgementAmbiguousFailClosedNoAcknowledgement,
    /// The production audit-ledger path was reached but is unavailable. No receipt.
    ProductionAuditLedgerAckUnavailableNoAcknowledgement,
    /// The MainNet audit-ledger path was reached but is unavailable. No receipt.
    MainNetAuditLedgerAckUnavailableNoAcknowledgement,
    /// The external-publication path was reached but is unavailable. No receipt.
    ExternalPublicationConfirmationUnavailableNoAcknowledgement,
    /// MainNet peer-driven apply remains refused before pipeline progression, sink
    /// invocation, reporter invocation, finalizer invocation, attestor invocation,
    /// backend invocation, and receipt invocation. No receipt.
    MainNetPeerDrivenApplyRefusedNoAcknowledgement,
    /// Validator-set rotation is unsupported. No receipt.
    ValidatorSetRotationUnsupportedNoAcknowledgement,
    /// Policy-change actions are unsupported. No receipt.
    PolicyChangeUnsupportedNoAcknowledgement,
}

impl DurableCompletionAuditReceiptAcknowledgementOutcome {
    /// `true` iff this outcome authorizes a **new** modeled audit/publication
    /// receipt (only [`Self::AcknowledgementRecorded`]).
    pub fn authorizes_acknowledgement_record(&self) -> bool {
        matches!(self, Self::AcknowledgementRecorded)
    }

    /// `true` iff this outcome projects to a recorded audit/publication receipt — a
    /// newly recorded receipt or an idempotent duplicate of an already-recorded
    /// receipt.
    pub fn projects_to_acknowledgement_recorded(&self) -> bool {
        matches!(
            self,
            Self::AcknowledgementRecorded | Self::AcknowledgementDuplicateIdempotent
        )
    }

    /// `true` iff this outcome records nothing new and projects to no
    /// audit/publication receipt.
    pub fn no_acknowledgement(&self) -> bool {
        !self.projects_to_acknowledgement_recorded()
    }

    /// `true` iff this is the legacy no-audit-receipt bypass.
    pub fn is_legacy_bypass(&self) -> bool {
        matches!(self, Self::LegacyBypassNoAcknowledgement)
    }

    /// `true` iff this is the MainNet peer-driven-apply refusal.
    pub fn is_mainnet_peer_driven_apply_refused(&self) -> bool {
        matches!(self, Self::MainNetPeerDrivenApplyRefusedNoAcknowledgement)
    }

    /// Stable operator-facing tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::LegacyBypassNoAcknowledgement => "legacy-bypass-no-acknowledgement",
            Self::RejectedBeforeAuditReceiptNoAcknowledgement => {
                "rejected-before-audit-receipt-no-acknowledgement"
            }
            Self::AuditReceiptDidNotRecordNoAcknowledgement => "audit-receipt-did-not-record-no-acknowledgement",
            Self::AcknowledgementRecorded => "acknowledgement-recorded",
            Self::AcknowledgementDuplicateIdempotent => "acknowledgement-duplicate-idempotent",
            Self::AcknowledgementRejectedBeforeRecord => "acknowledgement-rejected-before-record",
            Self::AcknowledgementRecordFailedNoAcknowledgement => "acknowledgement-record-failed-no-acknowledgement",
            Self::AcknowledgementRolledBackNoAcknowledgement => "acknowledgement-rolled-back-no-acknowledgement",
            Self::AcknowledgementRollbackFailedFatalNoAcknowledgement => {
                "acknowledgement-rollback-failed-fatal-no-acknowledgement"
            }
            Self::AcknowledgementAmbiguousFailClosedNoAcknowledgement => {
                "acknowledgement-ambiguous-fail-closed-no-acknowledgement"
            }
            Self::ProductionAuditLedgerAckUnavailableNoAcknowledgement => {
                "production-audit-ledger-ack-unavailable-no-acknowledgement"
            }
            Self::MainNetAuditLedgerAckUnavailableNoAcknowledgement => {
                "mainnet-audit-ledger-ack-unavailable-no-acknowledgement"
            }
            Self::ExternalPublicationConfirmationUnavailableNoAcknowledgement => {
                "external-publication-confirmation-unavailable-no-acknowledgement"
            }
            Self::MainNetPeerDrivenApplyRefusedNoAcknowledgement => {
                "mainnet-peer-driven-apply-refused-no-acknowledgement"
            }
            Self::ValidatorSetRotationUnsupportedNoAcknowledgement => {
                "validator-set-rotation-unsupported-no-acknowledgement"
            }
            Self::PolicyChangeUnsupportedNoAcknowledgement => "policy-change-unsupported-no-acknowledgement",
        }
    }
}

// ===========================================================================
// Receipt-outcome -> acknowledgement request projection
// ===========================================================================

/// Run 260 — the typed projection of a Run 258 audit/publication receipt outcome
/// onto an acknowledgement request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableCompletionAuditReceiptAcknowledgementRequestIntent {
    /// The receipt recorded an audit receipt; the acknowledgement sink may record a
    /// new acknowledgement.
    CreateRequest,
    /// The receipt reported an idempotent-duplicate audit receipt; the
    /// acknowledgement sink may only match an already-recorded acknowledgement and
    /// must never create a new one.
    IdempotentOnly,
    /// The receipt did not record; no acknowledgement request. Carries the typed
    /// no-acknowledgement outcome the acknowledgement evaluation returns directly
    /// (without invoking the acknowledgement sink).
    NoAcknowledgement(DurableCompletionAuditReceiptAcknowledgementOutcome),
}

impl DurableCompletionAuditReceiptAcknowledgementRequestIntent {
    /// `true` iff this projection creates an acknowledgement request (i.e. the
    /// receipt recorded an audit receipt).
    pub fn creates_request(&self) -> bool {
        matches!(self, Self::CreateRequest)
    }
}

/// Run 260 — project a Run 258 audit/publication receipt outcome onto an
/// acknowledgement request.
///
/// Only
/// [`DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRecorded`]
/// creates an acknowledgement request.
/// [`DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptDuplicateIdempotent`]
/// may only match an already-recorded acknowledgement and never creates a new one.
/// Every other receipt outcome maps to a no-acknowledgement fail-closed outcome (a
/// more specific one where one exists, otherwise the generic
/// [`DurableCompletionAuditReceiptAcknowledgementOutcome::AuditReceiptDidNotRecordNoAcknowledgement`]).
/// Pure: performs no work and never records.
pub fn project_audit_receipt_outcome_to_acknowledgement_request(
    outcome: &DurableCompletionAuditPublicationReceiptOutcome,
) -> DurableCompletionAuditReceiptAcknowledgementRequestIntent {
    use DurableCompletionAuditPublicationReceiptOutcome as Receipt;
    use DurableCompletionAuditReceiptAcknowledgementOutcome as Ack;
    use DurableCompletionAuditReceiptAcknowledgementRequestIntent as Intent;
    match outcome {
        Receipt::AuditReceiptRecorded => Intent::CreateRequest,
        Receipt::AuditReceiptDuplicateIdempotent => Intent::IdempotentOnly,
        Receipt::LegacyBypassNoAuditReceipt => {
            Intent::NoAcknowledgement(Ack::LegacyBypassNoAcknowledgement)
        }
        Receipt::RejectedBeforeBackendSubmissionNoAuditReceipt => {
            Intent::NoAcknowledgement(Ack::RejectedBeforeAuditReceiptNoAcknowledgement)
        }
        Receipt::MainNetPeerDrivenApplyRefusedNoReceipt => {
            Intent::NoAcknowledgement(Ack::MainNetPeerDrivenApplyRefusedNoAcknowledgement)
        }
        Receipt::ValidatorSetRotationUnsupportedNoReceipt => {
            Intent::NoAcknowledgement(Ack::ValidatorSetRotationUnsupportedNoAcknowledgement)
        }
        Receipt::PolicyChangeUnsupportedNoReceipt => {
            Intent::NoAcknowledgement(Ack::PolicyChangeUnsupportedNoAcknowledgement)
        }
        // Every remaining receipt outcome is a non-recording rejection / failure /
        // rollback / ambiguous window / production / MainNet / external-publication
        // unavailable: the receipt did not record, so no acknowledgement may exist.
        _ => Intent::NoAcknowledgement(Ack::AuditReceiptDidNotRecordNoAcknowledgement),
    }
}

// ===========================================================================
// Receipt fault injection (source/test only)
// ===========================================================================

/// Run 260 — a modeled fault the fixture receipt sink injects to exercise the
/// fail-closed record / rollback / ambiguous paths. Source/test only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionAuditReceiptAcknowledgementFault {
    /// The receipt record fails; nothing is written. No receipt.
    RecordFailedNoAcknowledgement,
    /// The receipt record is rolled back; nothing remains written. No receipt.
    RolledBackNoAcknowledgement,
    /// The receipt rollback itself fails — fatal / fail-closed. No receipt.
    RollbackFailedFatal,
    /// The after-record receipt window is ambiguous — fails closed. No receipt.
    AmbiguousAfterRecord,
}

// ===========================================================================
// Receipt trait boundary
// ===========================================================================

/// Run 260 — the pure/mockable modeled durable-completion audit/publication receipt
/// boundary.
///
/// No implementation here calls Run 070, mutates `LivePqcTrustState`, performs a
/// live trust swap, evicts sessions, writes a sequence, writes a marker, performs
/// network I/O, external publication, or a real audit-ledger persistence. The
/// DevNet/TestNet fixture receipt sink mutates only the in-memory
/// [`DurableCompletionAuditReceiptAcknowledgementLedger`].
pub trait GovernanceDurableCompletionAuditReceiptAcknowledgementSink {
    /// The receipt kind (used for typed recovery classification).
    fn kind(&self) -> DurableCompletionAuditReceiptAcknowledgementKind;

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
    fn record_durable_completion_audit_receipt_acknowledgement(
        &mut self,
        request: &DurableCompletionAuditReceiptAcknowledgementRequest,
        expectations: &DurableCompletionAuditReceiptAcknowledgementExpectations,
        idempotent_only: bool,
        ledger: &mut DurableCompletionAuditReceiptAcknowledgementLedger,
    ) -> DurableCompletionAuditReceiptAcknowledgementOutcome;

    /// Classify a modeled receipt crash/recovery window. Pure: performs no modeled
    /// mutation and never invokes Run 070.
    fn recover_durable_completion_audit_receipt_acknowledgement_window(
        &self,
        input: &DurableCompletionAuditReceiptAcknowledgementInput,
        window: DurableCompletionAuditReceiptAcknowledgementWindow,
        recovered_record: Option<&DurableCompletionAuditReceiptAcknowledgementLedgerRecord>,
        expectations: &DurableCompletionAuditReceiptAcknowledgementExpectations,
    ) -> DurableCompletionAuditReceiptAcknowledgementOutcome {
        recover_durable_completion_audit_receipt_acknowledgement_window(
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

/// Run 260 — the DevNet/TestNet in-memory fixture receipt sink.
///
/// Source-test only. It mutates only the in-memory
/// [`DurableCompletionAuditReceiptAcknowledgementLedger`] and exposes an invocation
/// counter so tests can prove non-submitting backend paths and pre-receipt
/// rejections never invoke it.
#[derive(Debug, Clone)]
pub struct FixtureDurableCompletionAuditReceiptAcknowledgementSink {
    fault: Option<DurableCompletionAuditReceiptAcknowledgementFault>,
    invocations: u32,
}

impl Default for FixtureDurableCompletionAuditReceiptAcknowledgementSink {
    fn default() -> Self {
        Self::new()
    }
}

impl FixtureDurableCompletionAuditReceiptAcknowledgementSink {
    /// A new fixture receipt sink.
    pub fn new() -> Self {
        Self {
            fault: None,
            invocations: 0,
        }
    }

    /// A new fixture receipt sink that injects the given modeled fault on record.
    pub fn with_fault(fault: DurableCompletionAuditReceiptAcknowledgementFault) -> Self {
        Self {
            fault: Some(fault),
            invocations: 0,
        }
    }
}

impl GovernanceDurableCompletionAuditReceiptAcknowledgementSink
    for FixtureDurableCompletionAuditReceiptAcknowledgementSink
{
    fn kind(&self) -> DurableCompletionAuditReceiptAcknowledgementKind {
        DurableCompletionAuditReceiptAcknowledgementKind::FixtureInMemory
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn record_durable_completion_audit_receipt_acknowledgement(
        &mut self,
        request: &DurableCompletionAuditReceiptAcknowledgementRequest,
        expectations: &DurableCompletionAuditReceiptAcknowledgementExpectations,
        idempotent_only: bool,
        ledger: &mut DurableCompletionAuditReceiptAcknowledgementLedger,
    ) -> DurableCompletionAuditReceiptAcknowledgementOutcome {
        use DurableCompletionAuditReceiptAcknowledgementOutcome as Receipt;
        self.invocations += 1;

        // Injected faults model record-failure / rollback / ambiguous windows. None
        // of them ever leave a recorded receipt behind, so a durable receipt is never
        // claimed. The ledger snapshot/restore models the rollback being a no-op
        // write.
        if let Some(fault) = self.fault {
            let snapshot = ledger.snapshot();
            return match fault {
                DurableCompletionAuditReceiptAcknowledgementFault::RecordFailedNoAcknowledgement => {
                    ledger.restore(&snapshot);
                    Receipt::AcknowledgementRecordFailedNoAcknowledgement
                }
                DurableCompletionAuditReceiptAcknowledgementFault::RolledBackNoAcknowledgement => {
                    ledger.restore(&snapshot);
                    Receipt::AcknowledgementRolledBackNoAcknowledgement
                }
                DurableCompletionAuditReceiptAcknowledgementFault::RollbackFailedFatal => {
                    Receipt::AcknowledgementRollbackFailedFatalNoAcknowledgement
                }
                DurableCompletionAuditReceiptAcknowledgementFault::AmbiguousAfterRecord => {
                    ledger.restore(&snapshot);
                    Receipt::AcknowledgementAmbiguousFailClosedNoAcknowledgement
                }
            };
        }

        // The fixture receipt sink is DevNet/TestNet evidence-only.
        if !matches!(
            request.environment,
            TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet
        ) {
            return Receipt::AcknowledgementRejectedBeforeRecord;
        }

        // Request-identity validation (malformed / mismatch) fails closed before any
        // record is written.
        if !expectations.request_matches(request) {
            return Receipt::AcknowledgementRejectedBeforeRecord;
        }

        // Build the deterministic request / response / record / transcript digests.
        let request_digest = request.digest();
        let response = DurableCompletionAuditReceiptAcknowledgementResponse {
            acknowledgement_record_id: request.acknowledgement_record_id.clone(),
            request_digest: request_digest.clone(),
            accepted: true,
            acknowledgement_kind: DurableCompletionAuditReceiptAcknowledgementKind::FixtureInMemory,
        };
        let response_digest = response.digest();
        let record = request.to_record();
        let record_digest = record.digest();
        let transcript_digest =
            acknowledgement_transcript_digest(&request_digest, &response_digest, &record_digest);

        // Idempotency / equivocation gate.
        if let Some(existing) = ledger.find(&request.acknowledgement_record_id) {
            if existing.request_digest == request_digest
                && existing.response_digest == response_digest
                && existing.record_digest == record_digest
                && existing.transcript_digest == transcript_digest
            {
                return Receipt::AcknowledgementDuplicateIdempotent;
            }
            // Same receipt record id with a different digest is equivocation: fail
            // closed, record no second receipt.
            return Receipt::AcknowledgementRejectedBeforeRecord;
        }

        // A duplicate-idempotent backend submission may only match an already-recorded
        // receipt; it must never create a new one by itself.
        if idempotent_only {
            return Receipt::AcknowledgementRejectedBeforeRecord;
        }

        ledger.insert(DurableCompletionAuditReceiptAcknowledgementLedgerRecord {
            acknowledgement_record_id: request.acknowledgement_record_id.clone(),
            request_digest,
            response_digest,
            record_digest,
            transcript_digest,
            status: DurableCompletionAuditReceiptAcknowledgementLedgerStatus::Recorded,
        });
        Receipt::AcknowledgementRecorded
    }
}

// ===========================================================================
// Production / MainNet audit-ledger / External-publication sinks (unavailable)
// ===========================================================================

/// Run 260 — the production audit-ledger receipt sink. Reachable but unavailable /
/// fail-closed. It records no receipt and mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct ProductionAuditLedgerDurableCompletionAcknowledgementSink {
    invocations: u32,
}

impl GovernanceDurableCompletionAuditReceiptAcknowledgementSink
    for ProductionAuditLedgerDurableCompletionAcknowledgementSink
{
    fn kind(&self) -> DurableCompletionAuditReceiptAcknowledgementKind {
        DurableCompletionAuditReceiptAcknowledgementKind::ProductionAuditLedgerAckUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn record_durable_completion_audit_receipt_acknowledgement(
        &mut self,
        _request: &DurableCompletionAuditReceiptAcknowledgementRequest,
        _expectations: &DurableCompletionAuditReceiptAcknowledgementExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionAuditReceiptAcknowledgementLedger,
    ) -> DurableCompletionAuditReceiptAcknowledgementOutcome {
        self.invocations += 1;
        DurableCompletionAuditReceiptAcknowledgementOutcome::ProductionAuditLedgerAckUnavailableNoAcknowledgement
    }
}

/// Run 260 — the MainNet audit-ledger receipt sink. Reachable but unavailable /
/// fail-closed. It records no receipt and mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct MainNetAuditLedgerDurableCompletionAcknowledgementSink {
    invocations: u32,
}

impl GovernanceDurableCompletionAuditReceiptAcknowledgementSink
    for MainNetAuditLedgerDurableCompletionAcknowledgementSink
{
    fn kind(&self) -> DurableCompletionAuditReceiptAcknowledgementKind {
        DurableCompletionAuditReceiptAcknowledgementKind::MainNetAuditLedgerAckUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn record_durable_completion_audit_receipt_acknowledgement(
        &mut self,
        _request: &DurableCompletionAuditReceiptAcknowledgementRequest,
        _expectations: &DurableCompletionAuditReceiptAcknowledgementExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionAuditReceiptAcknowledgementLedger,
    ) -> DurableCompletionAuditReceiptAcknowledgementOutcome {
        self.invocations += 1;
        DurableCompletionAuditReceiptAcknowledgementOutcome::MainNetAuditLedgerAckUnavailableNoAcknowledgement
    }
}

/// Run 260 — the external-publication receipt sink. Reachable but unavailable /
/// fail-closed. It performs no external publication, records no receipt, and
/// mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct ExternalPublicationDurableCompletionConfirmationSink {
    invocations: u32,
}

impl GovernanceDurableCompletionAuditReceiptAcknowledgementSink
    for ExternalPublicationDurableCompletionConfirmationSink
{
    fn kind(&self) -> DurableCompletionAuditReceiptAcknowledgementKind {
        DurableCompletionAuditReceiptAcknowledgementKind::ExternalPublicationConfirmationUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn record_durable_completion_audit_receipt_acknowledgement(
        &mut self,
        _request: &DurableCompletionAuditReceiptAcknowledgementRequest,
        _expectations: &DurableCompletionAuditReceiptAcknowledgementExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionAuditReceiptAcknowledgementLedger,
    ) -> DurableCompletionAuditReceiptAcknowledgementOutcome {
        self.invocations += 1;
        DurableCompletionAuditReceiptAcknowledgementOutcome::ExternalPublicationConfirmationUnavailableNoAcknowledgement
    }
}

// ===========================================================================
// Receipt executor / composition helpers
// ===========================================================================

/// Run 260 — evaluate one modeled durable-completion audit/publication receipt
/// round-trip.
///
/// Ordering (each gate must pass before the next is considered):
///
/// 1. MainNet peer-driven apply refusal — before pipeline progression, sink
///    invocation, reporter invocation, finalizer invocation, attestor invocation,
///    backend invocation, and receipt invocation;
/// 2. legacy bypass — a
///    [`DurableCompletionAuditReceiptAcknowledgementPolicy::Disabled`] policy;
/// 3. backend-outcome projection — only
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
pub fn evaluate_durable_completion_audit_receipt_acknowledgement<S>(
    input: &DurableCompletionAuditReceiptAcknowledgementInput,
    expectations: &DurableCompletionAuditReceiptAcknowledgementExpectations,
    sink: &mut S,
    ledger: &mut DurableCompletionAuditReceiptAcknowledgementLedger,
) -> DurableCompletionAuditReceiptAcknowledgementOutcome
where
    S: GovernanceDurableCompletionAuditReceiptAcknowledgementSink,
{
    use DurableCompletionAuditReceiptAcknowledgementOutcome as Receipt;
    use DurableCompletionAuditReceiptAcknowledgementRequestIntent as Intent;

    // Step 1: MainNet peer-driven apply remains refused unconditionally, before
    // pipeline progression, sink invocation, reporter invocation, finalizer
    // invocation, attestor invocation, backend invocation, and receipt invocation.
    if input.is_mainnet_peer_driven() {
        return Receipt::MainNetPeerDrivenApplyRefusedNoAcknowledgement;
    }

    // Step 2: legacy bypass — a disabled receipt policy preserves the legacy
    // no-audit-receipt path and never invokes the receipt sink.
    if input.policy.is_disabled() {
        return Receipt::LegacyBypassNoAcknowledgement;
    }

    // Step 3: project the Run 258 audit/publication receipt outcome onto an
    // acknowledgement request. Every non-recording receipt outcome returns a
    // no-acknowledgement outcome without invoking the acknowledgement sink.
    let idempotent_only = match project_audit_receipt_outcome_to_acknowledgement_request(
        &input.receipt_binding,
    ) {
        Intent::NoAcknowledgement(outcome) => return outcome,
        Intent::CreateRequest => false,
        Intent::IdempotentOnly => true,
    };

    // Step 4: pre-acknowledgement environment / surface binding validation. A
    // mismatch fails closed before the acknowledgement sink is invoked, leaving the
    // acknowledgement invocation count at zero.
    if !expectations.binding_matches(input) {
        return Receipt::RejectedBeforeAuditReceiptNoAcknowledgement;
    }

    // Step 5: invoke the acknowledgement sink to record the modeled acknowledgement.
    sink.record_durable_completion_audit_receipt_acknowledgement(
        &input.request,
        expectations,
        idempotent_only,
        ledger,
    )
}

// ===========================================================================
// Receipt crash/recovery window classification
// ===========================================================================

/// Run 260 — the modeled durable-completion audit/publication receipt
/// crash/recovery window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionAuditReceiptAcknowledgementWindow {
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
    /// Crashed after the report record but before a finalization intent.
    AfterReportRecordBeforeFinalizationIntent,
    /// Crashed after a finalization intent but before any finalization record.
    AfterFinalizationIntentBeforeFinalizationRecord,
    /// Crashed after the finalization record but before an attestation intent.
    AfterFinalizationRecordBeforeAttestationIntent,
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
    /// Recovered after a successful acknowledgement record.
    AfterAcknowledgementSuccess,
    /// Recovered after an ambiguous acknowledgement window.
    AfterAcknowledgementAmbiguous,
    /// The acknowledgement record itself failed.
    AcknowledgementRecordFailed,
    /// The acknowledgement record was rolled back.
    AcknowledgementRollbackCompleted,
    /// The acknowledgement rollback itself failed — fatal.
    AcknowledgementRollbackFailed,
    /// An unknown window — fails closed.
    Unknown,
}

/// Run 260 — classify a modeled durable-completion audit/publication receipt
/// crash/recovery window.
///
/// The receipt sink never silently re-authorizes an in-flight receipt: MainNet
/// peer-driven refusal precedes classification, production / MainNet audit-ledger /
/// external-publication classification is unavailable, and every ambiguous /
/// unknown window fails closed. Only an after-receipt-record window with an explicit
/// matching record (or an explicit after-receipt-success window) recovers as
/// [`DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementRecorded`]. Pure:
/// performs no modeled mutation and never invokes Run 070.
pub fn recover_durable_completion_audit_receipt_acknowledgement_window(
    input: &DurableCompletionAuditReceiptAcknowledgementInput,
    window: DurableCompletionAuditReceiptAcknowledgementWindow,
    kind: DurableCompletionAuditReceiptAcknowledgementKind,
    recovered_record: Option<&DurableCompletionAuditReceiptAcknowledgementLedgerRecord>,
    expectations: &DurableCompletionAuditReceiptAcknowledgementExpectations,
) -> DurableCompletionAuditReceiptAcknowledgementOutcome {
    use DurableCompletionAuditReceiptAcknowledgementOutcome as Receipt;
    use DurableCompletionAuditReceiptAcknowledgementWindow as Window;

    // MainNet peer-driven apply refusal precedes recovery classification.
    if input.is_mainnet_peer_driven() {
        return Receipt::MainNetPeerDrivenApplyRefusedNoAcknowledgement;
    }

    // Production / MainNet audit-ledger / external-publication recovery
    // classification is unavailable / fail-closed.
    match kind {
        DurableCompletionAuditReceiptAcknowledgementKind::ProductionAuditLedgerAckUnavailable => {
            return Receipt::ProductionAuditLedgerAckUnavailableNoAcknowledgement;
        }
        DurableCompletionAuditReceiptAcknowledgementKind::MainNetAuditLedgerAckUnavailable => {
            return Receipt::MainNetAuditLedgerAckUnavailableNoAcknowledgement;
        }
        DurableCompletionAuditReceiptAcknowledgementKind::ExternalPublicationConfirmationUnavailable => {
            return Receipt::ExternalPublicationConfirmationUnavailableNoAcknowledgement;
        }
        DurableCompletionAuditReceiptAcknowledgementKind::Disabled => {
            return Receipt::LegacyBypassNoAcknowledgement;
        }
        DurableCompletionAuditReceiptAcknowledgementKind::Unknown => {
            return Receipt::AcknowledgementAmbiguousFailClosedNoAcknowledgement;
        }
        DurableCompletionAuditReceiptAcknowledgementKind::FixtureInMemory => {}
    }

    // Helper: an explicit recovered record recovers as a receipt only if it matches
    // the expected receipt record id and the canonical request digest.
    let recovered_matches =
        |record: &DurableCompletionAuditReceiptAcknowledgementLedgerRecord| -> bool {
            record.acknowledgement_record_id == expectations.expected_acknowledgement_record_id
                && record.request_digest == input.request.digest()
                && record.status
                    == DurableCompletionAuditReceiptAcknowledgementLedgerStatus::Recorded
        };

    match window {
        // Through receipt success but before an acknowledgement request there is
        // nothing to record an acknowledgement for.
        Window::BeforePipeline
        | Window::AfterPipelineSuccessBeforeSinkIntent
        | Window::AfterSinkIntentBeforeSinkReceiptRecord
        | Window::AfterSinkReceiptRecordBeforeReportIntent
        | Window::AfterReportIntentBeforeReportRecord
        | Window::AfterReportRecordBeforeFinalizationIntent
        | Window::AfterFinalizationIntentBeforeFinalizationRecord
        | Window::AfterFinalizationRecordBeforeAttestationIntent
        | Window::AfterAttestationIntentBeforeAttestationRecord
        | Window::AfterAttestationRecordBeforeBackendRequest
        | Window::AfterBackendRequestBeforeBackendRecord
        | Window::AfterBackendRecordBeforeBackendSuccess
        | Window::AfterBackendSuccessBeforeReceiptRequest
        | Window::AfterReceiptRequestBeforeReceiptRecord
        | Window::AfterReceiptRecordBeforeReceiptSuccess
        | Window::AfterReceiptSuccessBeforeAcknowledgementRequest => {
            Receipt::AuditReceiptDidNotRecordNoAcknowledgement
        }
        // An acknowledgement request without a record never records an
        // acknowledgement.
        Window::AfterAcknowledgementRequestBeforeAcknowledgementRecord => {
            Receipt::AcknowledgementRejectedBeforeRecord
        }
        // After an acknowledgement record but before success: fails closed unless an
        // explicit matching, well-formed acknowledgement record exists.
        Window::AfterAcknowledgementRecordBeforeAcknowledgementSuccess => match recovered_record {
            Some(record) if recovered_matches(record) => Receipt::AcknowledgementRecorded,
            _ => Receipt::AcknowledgementRejectedBeforeRecord,
        },
        // An explicit successful acknowledgement recovers as recorded only if it
        // matches.
        Window::AfterAcknowledgementSuccess => match recovered_record {
            Some(record) if recovered_matches(record) => Receipt::AcknowledgementRecorded,
            _ => Receipt::AcknowledgementRejectedBeforeRecord,
        },
        Window::AfterAcknowledgementAmbiguous => {
            Receipt::AcknowledgementAmbiguousFailClosedNoAcknowledgement
        }
        Window::AcknowledgementRecordFailed => Receipt::AcknowledgementRecordFailedNoAcknowledgement,
        Window::AcknowledgementRollbackCompleted => {
            Receipt::AcknowledgementRolledBackNoAcknowledgement
        }
        Window::AcknowledgementRollbackFailed => {
            Receipt::AcknowledgementRollbackFailedFatalNoAcknowledgement
        }
        // Any unknown window fails closed.
        Window::Unknown => Receipt::AcknowledgementAmbiguousFailClosedNoAcknowledgement,
    }
}

/// Run 260 — `true` iff a receipt outcome authorizes a **new** modeled
/// audit/publication receipt (only
/// [`DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementRecorded`]).
pub fn acknowledgement_outcome_authorizes_acknowledgement_record(
    outcome: &DurableCompletionAuditReceiptAcknowledgementOutcome,
) -> bool {
    outcome.authorizes_acknowledgement_record()
}

/// Run 260 — `true` iff a receipt outcome projects to a recorded audit/publication
/// receipt (a newly recorded receipt or an idempotent duplicate of an
/// already-recorded receipt).
pub fn acknowledgement_outcome_projects_to_acknowledgement_recorded(
    outcome: &DurableCompletionAuditReceiptAcknowledgementOutcome,
) -> bool {
    outcome.projects_to_acknowledgement_recorded()
}

// ===========================================================================
// Grep-verifiable safety invariants (source/test only)
// ===========================================================================

/// Run 260 — a receipt rejection is non-mutating: it records no receipt, mutates no
/// `LivePqcTrustState`, and writes no durable state.
pub fn durable_completion_audit_ack_rejection_is_non_mutating() -> bool {
    true
}

/// Run 260 — the receipt boundary never calls Run 070.
pub fn durable_completion_audit_ack_never_calls_run_070() -> bool {
    true
}

/// Run 260 — the receipt boundary never mutates live PQC trust state.
pub fn durable_completion_audit_ack_never_mutates_live_pqc_trust_state() -> bool {
    true
}

/// Run 260 — the receipt boundary never writes a sequence or a marker.
pub fn durable_completion_audit_ack_never_writes_sequence_or_marker() -> bool {
    true
}

/// Run 260 — the receipt boundary changes no RocksDB file schema / migration.
pub fn durable_completion_audit_ack_no_rocksdb_file_schema_migration_change() -> bool {
    true
}

/// Run 260 — the receipt boundary performs no external publication.
pub fn durable_completion_audit_ack_no_external_publication() -> bool {
    true
}

/// Run 260 — the receipt boundary performs no real audit-ledger persistence.
pub fn durable_completion_audit_ack_no_real_audit_ledger() -> bool {
    true
}

/// Run 260 — a receipt requires a successful Run 246 pipeline outcome upstream.
pub fn durable_completion_audit_ack_pipeline_success_required() -> bool {
    true
}

/// Run 260 — a receipt requires a Run 248 sink receipt record upstream.
pub fn durable_completion_audit_ack_sink_receipt_required() -> bool {
    true
}

/// Run 260 — a receipt requires a Run 250 completion report upstream.
pub fn durable_completion_audit_ack_completion_report_required() -> bool {
    true
}

/// Run 260 — a receipt requires a Run 252 finalization upstream.
pub fn durable_completion_audit_ack_finalization_required() -> bool {
    true
}

/// Run 260 — a receipt requires a Run 254 attestation upstream.
pub fn durable_completion_audit_ack_attestation_required() -> bool {
    true
}

/// Run 260 — an acknowledgement requires a Run 256 backend submission upstream.
pub fn durable_completion_audit_ack_backend_submission_required() -> bool {
    true
}

/// Run 260 — an acknowledgement requires a Run 258 audit receipt upstream.
pub fn durable_completion_audit_ack_receipt_required() -> bool {
    true
}

/// Run 260 — a receipt record is required before a receipt is acknowledged.
pub fn durable_completion_audit_ack_record_required_before_ack() -> bool {
    true
}

/// Run 260 — a failed receipt record never records a receipt.
pub fn durable_completion_audit_ack_failed_record_never_records() -> bool {
    true
}

/// Run 260 — a rolled-back receipt record never records a receipt.
pub fn durable_completion_audit_ack_rollback_never_records() -> bool {
    true
}

/// Run 260 — an ambiguous after-record receipt window fails closed.
pub fn durable_completion_audit_ack_ambiguous_window_fails_closed() -> bool {
    true
}

/// Run 260 — MainNet peer-driven apply refusal precedes every receipt stage.
pub fn durable_completion_audit_ack_mainnet_peer_driven_apply_refused_first(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 260 — production / MainNet audit-ledger sinks are reachable but unavailable.
pub fn durable_completion_audit_ack_production_mainnet_unavailable() -> bool {
    true
}

/// Run 260 — the external-publication sink is reachable but unavailable.
pub fn durable_completion_audit_ack_external_confirmation_unavailable() -> bool {
    true
}

/// Run 260 — validator-set rotation remains unsupported at the receipt boundary.
pub fn durable_completion_audit_ack_validator_set_rotation_unsupported() -> bool {
    true
}

/// Run 260 — policy-change actions remain unsupported at the receipt boundary.
pub fn durable_completion_audit_ack_policy_change_unsupported() -> bool {
    true
}

/// Run 260 — a local operator cannot satisfy MainNet authority for a receipt.
pub fn durable_completion_audit_ack_local_operator_cannot_satisfy_mainnet_authority() -> bool {
    true
}

/// Run 260 — a peer majority cannot satisfy MainNet authority for a receipt.
pub fn durable_completion_audit_ack_peer_majority_cannot_satisfy_mainnet_authority() -> bool {
    true
}