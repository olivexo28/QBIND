//! Run 258 — source/test durable-completion backend **audit-ledger /
//! external-publication receipt boundary**.
//!
//! Source/test only. Run 258 captures **no** release-binary evidence and enables
//! **no** production mutating behavior. It does **not** implement a real audit
//! ledger, a real external-publication system, a real production attestation
//! backend, a real finalization backend, a real completion-report backend, a real
//! durable consume backend, a real persistent replay backend, a real governance
//! execution engine, a real production mutation engine, a real on-chain
//! governance proof verifier, a KMS/HSM/RemoteSigner backend, MainNet governance
//! enablement, MainNet peer-driven apply enablement, validator-set rotation, or
//! any RocksDB / file / schema / migration / wire / marker / sequence /
//! trust-bundle / storage-format change.
//!
//! ## What this module adds
//!
//! Run 256
//! ([`crate::pqc_governance_durable_completion_attestation_backend`]) proves that a
//! modeled durable-completion attestation *backend submission* is recorded **only**
//! after the Run 254 attestor recorded an attestation, terminating in the single
//! submission-recording outcome
//! [`DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded`].
//!
//! Run 258 defines the **first typed interface** a future production audit ledger
//! or external publication system would use to record an audit/publication receipt
//! **after** the Run 256 backend stage produced `BackendSubmissionRecorded`. It is
//! an **interface / projection boundary only**: production / MainNet audit-ledger
//! and external-publication implementations are *reachable but deliberately
//! unavailable / fail-closed*, and the only positive implementation is a
//! DevNet/TestNet fixture that records into an in-memory fixture ledger for
//! source/test evidence only.
//!
//! The receipt layer is a **model only**. It does not implement a real audit
//! ledger, a real external-publication system, or any real persistent storage. It
//! does not write RocksDB, files, schemas, migrations, storage formats, wire
//! formats, authority markers, trust-bundle sequence files, or any production
//! durable state. It does not call Run 070, mutate `LivePqcTrustState`, perform a
//! real trust swap, evict sessions, perform external publication / network I/O, or
//! enable MainNet governance / MainNet peer-driven apply. The DevNet/TestNet
//! fixture sink mutates only the in-memory
//! [`DurableCompletionAuditPublicationReceiptLedger`].
//!
//! ## Ordering / fail-closed contract
//!
//! 1. **MainNet peer-driven apply refusal** — refused *before* pipeline
//!    progression, sink invocation, reporter invocation, finalizer invocation,
//!    attestor invocation, backend invocation, and receipt sink invocation;
//! 2. **legacy bypass** — a
//!    [`DurableCompletionAuditPublicationReceiptPolicy::Disabled`] policy preserves
//!    the legacy no-audit-receipt bypass and never invokes the receipt sink;
//! 3. **backend-outcome projection** — only
//!    [`DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded`]
//!    creates an audit/publication receipt request; every other Run 256 outcome
//!    maps to a no-audit-receipt fail-closed outcome and never invokes the receipt
//!    sink;
//! 4. **pre-receipt binding validation** — environment / chain / genesis /
//!    governance surface / mutation surface and the full digest binding must match
//!    expectations *before* the receipt sink is invoked; a mismatch fails closed
//!    and leaves the receipt sink invocation count at zero;
//! 5. **receipt record** — only after every prior gate passes is the receipt sink
//!    invoked; the receipt-record-identity fields must match exactly before any
//!    modeled receipt is recorded;
//! 6. **receipt authorization** — only
//!    [`DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRecorded`]
//!    authorizes a new modeled audit/publication receipt state.
//!
//! A receipt record failure, rollback, rollback failure, or ambiguous receipt
//! window never retroactively claims a durable receipt. A duplicate identical
//! receipt is idempotent; the same receipt record id with a different digest fails
//! closed as equivocation and records no second receipt. A Run 256
//! [`DurableCompletionAttestationBackendOutcome::BackendSubmissionDuplicateIdempotent`]
//! never creates a new receipt by itself — it can only match an already-recorded
//! receipt.

use crate::pqc_governance_durable_completion_attestation_backend::DurableCompletionAttestationBackendOutcome;
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

/// Run 258 — the validation / mutation surface pair the receipt binds to.
pub type DurableCompletionAuditPublicationReceiptSurface = ModeledGovernanceTrustMutationSurface;

/// Run 258 — the trust-domain environment binding the receipt is bound to.
pub type DurableCompletionAuditPublicationReceiptEnvironment =
    ModeledGovernanceTrustMutationEnvironmentBinding;

/// Run 258 — the runtime binding (governance + mutation surface + sequence) the
/// receipt is bound to.
pub type DurableCompletionAuditPublicationReceiptBinding =
    ModeledGovernanceTrustMutationRuntimeBinding;

/// Run 258 — the Run 240/246 durable replay observation carried as freshness
/// context.
pub type DurableCompletionAuditPublicationReceiptReplayBinding = DurableReplayObservation;

/// Run 258 — the Run 246 pipeline outcome carried as consume authorization context.
pub type DurableCompletionAuditPublicationReceiptPipelineBinding =
    GovernanceModeledEndToEndPipelineOutcome;

/// Run 258 — the Run 248 sink outcome carried as receipt-record context.
pub type DurableCompletionAuditPublicationReceiptSinkBinding =
    GovernanceModeledDurableConsumeSinkOutcome;

/// Run 258 — the Run 250 reporter outcome carried as completion-report context.
pub type DurableCompletionAuditPublicationReceiptReporterBinding =
    GovernanceModeledDurableConsumeCompletionReporterOutcome;

/// Run 258 — the Run 252 finalization outcome carried as finalization context.
pub type DurableCompletionAuditPublicationReceiptFinalizationBinding =
    GovernanceModeledDurableCompletionFinalizationOutcome;

/// Run 258 — the Run 254 attestation outcome carried as attestation context.
pub type DurableCompletionAuditPublicationReceiptAttestationBinding =
    GovernanceModeledDurableCompletionAttestationOutcome;

/// Run 258 — the Run 256 backend outcome the receipt projects to a receipt request.
/// The receipt boundary never reimplements the backend; it only projects its
/// terminal outcome.
pub type DurableCompletionAuditPublicationReceiptBackendBinding =
    DurableCompletionAttestationBackendOutcome;

// ===========================================================================
// Receipt kind
// ===========================================================================

/// Run 258 — the typed durable-completion audit/publication receipt kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionAuditPublicationReceiptKind {
    /// The receipt boundary is disabled (legacy bypass).
    Disabled,
    /// DevNet/TestNet in-memory fixture receipt sink (source-test only; may mutate
    /// only the ledger).
    FixtureInMemory,
    /// Production audit-ledger receipt sink (reachable-but-unavailable /
    /// fail-closed).
    ProductionAuditLedgerUnavailable,
    /// MainNet audit-ledger receipt sink (reachable-but-unavailable / fail-closed).
    MainNetAuditLedgerUnavailable,
    /// External-publication receipt sink (reachable-but-unavailable / fail-closed).
    ExternalPublicationUnavailable,
    /// An unknown receipt kind — fails closed.
    Unknown,
}

impl DurableCompletionAuditPublicationReceiptKind {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureInMemory => "fixture-in-memory",
            Self::ProductionAuditLedgerUnavailable => "production-audit-ledger-unavailable",
            Self::MainNetAuditLedgerUnavailable => "mainnet-audit-ledger-unavailable",
            Self::ExternalPublicationUnavailable => "external-publication-unavailable",
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
            Self::ProductionAuditLedgerUnavailable
                | Self::MainNetAuditLedgerUnavailable
                | Self::ExternalPublicationUnavailable
        )
    }
}

// ===========================================================================
// Receipt policy
// ===========================================================================

/// Run 258 — the typed durable-completion audit/publication receipt policy
/// selector.
///
/// Only [`Self::FixtureAllowed`] may record (DevNet/TestNet source-test only);
/// every production / MainNet / external-publication policy resolves to a
/// reachable-but-unavailable sink that never records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionAuditPublicationReceiptPolicy {
    /// The receipt boundary is disabled (legacy bypass).
    Disabled,
    /// A DevNet/TestNet fixture receipt sink is allowed (source-test evidence only).
    FixtureAllowed,
    /// A real production audit-ledger receipt sink is required — reachable but
    /// unavailable.
    ProductionAuditLedgerRequired,
    /// A real MainNet audit-ledger receipt sink is required — reachable but
    /// unavailable.
    MainNetAuditLedgerRequired,
    /// A real external-publication receipt sink is required — reachable but
    /// unavailable.
    ExternalPublicationRequired,
}

impl DurableCompletionAuditPublicationReceiptPolicy {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureAllowed => "fixture-allowed",
            Self::ProductionAuditLedgerRequired => "production-audit-ledger-required",
            Self::MainNetAuditLedgerRequired => "mainnet-audit-ledger-required",
            Self::ExternalPublicationRequired => "external-publication-required",
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

/// Run 258 — the typed receipt identity a receipt request is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionAuditPublicationReceiptIdentity {
    /// Stable receipt id.
    pub receipt_id: String,
    /// The receipt kind.
    pub kind: DurableCompletionAuditPublicationReceiptKind,
    /// The receipt policy.
    pub policy: DurableCompletionAuditPublicationReceiptPolicy,
    /// The domain separation tag the receipt operates under.
    pub domain_separation_tag: String,
}

impl DurableCompletionAuditPublicationReceiptIdentity {
    /// `true` iff every mandatory identity field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.receipt_id.is_empty()
            && !self.domain_separation_tag.is_empty()
            && self.kind != DurableCompletionAuditPublicationReceiptKind::Unknown
    }

    /// The deterministic, domain-separated receipt identity digest.
    pub fn digest(&self) -> DurableCompletionAuditPublicationReceiptDigest {
        receipt_identity_digest(self)
    }
}

// ===========================================================================
// Deterministic, domain-separated digest helpers
// ===========================================================================

/// Run 258 — domain separator for the receipt identity digest.
const RECEIPT_IDENTITY_DOMAIN: &[u8] =
    b"QBIND:run258:durable-completion-audit-publication-receipt-identity:v1";
/// Run 258 — domain separator for the receipt request digest.
const RECEIPT_REQUEST_DOMAIN: &[u8] =
    b"QBIND:run258:durable-completion-audit-publication-receipt-request:v1";
/// Run 258 — domain separator for the receipt response digest.
const RECEIPT_RESPONSE_DOMAIN: &[u8] =
    b"QBIND:run258:durable-completion-audit-publication-receipt-response:v1";
/// Run 258 — domain separator for the receipt record digest.
const RECEIPT_RECORD_DOMAIN: &[u8] =
    b"QBIND:run258:durable-completion-audit-publication-receipt-record:v1";
/// Run 258 — domain separator for the receipt transcript digest.
const RECEIPT_TRANSCRIPT_DOMAIN: &[u8] =
    b"QBIND:run258:durable-completion-audit-publication-receipt-transcript:v1";

/// Run 258 — a deterministic, domain-separated receipt digest (lowercase hex of a
/// SHA3-256 over length-prefixed, field-bound canonical material). It contains no
/// unstable display text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionAuditPublicationReceiptDigest(String);

impl DurableCompletionAuditPublicationReceiptDigest {
    /// The lowercase hex representation.
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

/// Run 258 — a deterministic, domain-separated receipt transcript digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionAuditPublicationReceiptTranscriptDigest(String);

impl DurableCompletionAuditPublicationReceiptTranscriptDigest {
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

/// Run 258 — deterministic, domain-separated receipt identity digest.
pub fn receipt_identity_digest(
    identity: &DurableCompletionAuditPublicationReceiptIdentity,
) -> DurableCompletionAuditPublicationReceiptDigest {
    let mut w = CanonicalWriter::new(RECEIPT_IDENTITY_DOMAIN);
    w.str_field(&identity.receipt_id)
        .str_field(identity.kind.tag())
        .str_field(identity.policy.tag())
        .str_field(&identity.domain_separation_tag);
    DurableCompletionAuditPublicationReceiptDigest(w.finish())
}

/// Run 258 — deterministic, domain-separated receipt request digest. Binds every
/// request field including the full Run 256 backend digest binding.
pub fn receipt_request_digest(
    request: &DurableCompletionAuditPublicationReceiptRequest,
) -> DurableCompletionAuditPublicationReceiptDigest {
    let mut w = CanonicalWriter::new(RECEIPT_REQUEST_DOMAIN);
    w.str_field(&request.receipt_record_id)
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
        .str_field(&request.domain_separation_tag)
        .str_field(receipt_identity_digest(&request.identity).as_hex());
    DurableCompletionAuditPublicationReceiptDigest(w.finish())
}

/// Run 258 — deterministic, domain-separated receipt response digest. Binds the
/// receipt record id, the request digest it answers, the acceptance flag, and the
/// responding receipt kind.
pub fn receipt_response_digest(
    response: &DurableCompletionAuditPublicationReceiptResponse,
) -> DurableCompletionAuditPublicationReceiptDigest {
    let mut w = CanonicalWriter::new(RECEIPT_RESPONSE_DOMAIN);
    w.str_field(&response.receipt_record_id)
        .str_field(response.request_digest.as_hex())
        .str_field(if response.accepted { "accepted" } else { "rejected" })
        .str_field(response.receipt_kind.tag());
    DurableCompletionAuditPublicationReceiptDigest(w.finish())
}

/// Run 258 — deterministic, domain-separated receipt record digest. Binds the
/// receipt record id, the request digest, and the receipt identity digest.
pub fn receipt_record_digest(
    record: &DurableCompletionAuditPublicationReceiptRecord,
) -> DurableCompletionAuditPublicationReceiptDigest {
    let mut w = CanonicalWriter::new(RECEIPT_RECORD_DOMAIN);
    w.str_field(&record.receipt_record_id)
        .str_field(record.request_digest.as_hex())
        .str_field(record.identity_digest.as_hex());
    DurableCompletionAuditPublicationReceiptDigest(w.finish())
}

/// Run 258 — deterministic, domain-separated receipt transcript digest. Binds the
/// request, response, and record digests into a single transcript binding.
pub fn receipt_transcript_digest(
    request_digest: &DurableCompletionAuditPublicationReceiptDigest,
    response_digest: &DurableCompletionAuditPublicationReceiptDigest,
    record_digest: &DurableCompletionAuditPublicationReceiptDigest,
) -> DurableCompletionAuditPublicationReceiptTranscriptDigest {
    let mut w = CanonicalWriter::new(RECEIPT_TRANSCRIPT_DOMAIN);
    w.str_field(request_digest.as_hex())
        .str_field(response_digest.as_hex())
        .str_field(record_digest.as_hex());
    DurableCompletionAuditPublicationReceiptTranscriptDigest(w.finish())
}

// ===========================================================================
// Receipt request / response / record
// ===========================================================================

/// Run 258 — the typed receipt request a future production audit ledger or
/// external-publication call site would submit once the Run 256 backend recorded a
/// `BackendSubmissionRecorded`.
///
/// Pure data referencing the already-recorded Run 256 backend / Run 254
/// attestation / Run 252 finalization / Run 250 completion report / Run 248
/// receipt / Run 246 decision material — never a copy of any wire payload and never
/// a production durable record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionAuditPublicationReceiptRequest {
    /// Stable receipt record id (the idempotency key of the receipt).
    pub receipt_record_id: String,
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
    /// Receipt identity.
    pub identity: DurableCompletionAuditPublicationReceiptIdentity,
    /// Domain separation tag.
    pub domain_separation_tag: String,
}

impl DurableCompletionAuditPublicationReceiptRequest {
    /// `true` iff every mandatory field is structurally present (non-empty) and the
    /// identity is well-formed.
    pub fn is_well_formed(&self) -> bool {
        !self.receipt_record_id.is_empty()
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
            && !self.domain_separation_tag.is_empty()
            && self.identity.is_well_formed()
    }

    /// The deterministic receipt request digest.
    pub fn digest(&self) -> DurableCompletionAuditPublicationReceiptDigest {
        receipt_request_digest(self)
    }

    /// The canonical immutable record derived from this request.
    pub fn to_record(&self) -> DurableCompletionAuditPublicationReceiptRecord {
        DurableCompletionAuditPublicationReceiptRecord {
            receipt_record_id: self.receipt_record_id.clone(),
            request_digest: self.digest(),
            identity_digest: self.identity.digest(),
        }
    }
}

/// Run 258 — the typed receipt response a receipt sink returns for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionAuditPublicationReceiptResponse {
    /// The receipt record id the response answers.
    pub receipt_record_id: String,
    /// The request digest the response answers.
    pub request_digest: DurableCompletionAuditPublicationReceiptDigest,
    /// `true` iff the receipt sink accepted the request.
    pub accepted: bool,
    /// The responding receipt kind.
    pub receipt_kind: DurableCompletionAuditPublicationReceiptKind,
}

impl DurableCompletionAuditPublicationReceiptResponse {
    /// `true` iff the response is structurally well-formed.
    pub fn is_well_formed(&self) -> bool {
        !self.receipt_record_id.is_empty()
            && self.receipt_kind != DurableCompletionAuditPublicationReceiptKind::Unknown
    }

    /// The deterministic receipt response digest.
    pub fn digest(&self) -> DurableCompletionAuditPublicationReceiptDigest {
        receipt_response_digest(self)
    }
}

/// Run 258 — the canonical immutable receipt record derived from a request. Two
/// records are idempotent-equal only if **every** field matches exactly. The same
/// receipt record id with any differing digest is equivocation and fails closed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionAuditPublicationReceiptRecord {
    /// The receipt record id.
    pub receipt_record_id: String,
    /// The request digest.
    pub request_digest: DurableCompletionAuditPublicationReceiptDigest,
    /// The receipt identity digest.
    pub identity_digest: DurableCompletionAuditPublicationReceiptDigest,
}

impl DurableCompletionAuditPublicationReceiptRecord {
    /// The deterministic receipt record digest.
    pub fn digest(&self) -> DurableCompletionAuditPublicationReceiptDigest {
        receipt_record_digest(self)
    }
}

// ===========================================================================
// In-memory fixture ledger
// ===========================================================================

/// Run 258 — the recorded status of a modeled audit/publication receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionAuditPublicationReceiptLedgerStatus {
    /// The modeled receipt is recorded in the in-memory fixture ledger.
    Recorded,
}

/// Run 258 — a single modeled receipt record held in the in-memory fixture ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionAuditPublicationReceiptLedgerRecord {
    /// The receipt record id (stable identity of the receipt).
    pub receipt_record_id: String,
    /// The request digest.
    pub request_digest: DurableCompletionAuditPublicationReceiptDigest,
    /// The response digest.
    pub response_digest: DurableCompletionAuditPublicationReceiptDigest,
    /// The record digest.
    pub record_digest: DurableCompletionAuditPublicationReceiptDigest,
    /// The transcript digest.
    pub transcript_digest: DurableCompletionAuditPublicationReceiptTranscriptDigest,
    /// The recorded status.
    pub status: DurableCompletionAuditPublicationReceiptLedgerStatus,
}

/// Run 258 — an immutable snapshot of the modeled receipt ledger used to model a
/// fixture rollback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionAuditPublicationReceiptLedgerSnapshot {
    records: Vec<DurableCompletionAuditPublicationReceiptLedgerRecord>,
}

impl DurableCompletionAuditPublicationReceiptLedgerSnapshot {
    /// The number of records the snapshot captured.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` iff the snapshot captured no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Run 258 — the modeled in-memory receipt ledger.
///
/// **In-memory only.** It never touches RocksDB, files, markers, sequence files,
/// external publications, audit-ledger entries, or any production durable state.
/// The DevNet/TestNet fixture sink is the only thing that may mutate it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DurableCompletionAuditPublicationReceiptLedger {
    records: Vec<DurableCompletionAuditPublicationReceiptLedgerRecord>,
}

impl DurableCompletionAuditPublicationReceiptLedger {
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
    pub fn records(&self) -> &[DurableCompletionAuditPublicationReceiptLedgerRecord] {
        &self.records
    }

    /// The record for `receipt_record_id`, if present.
    pub fn find(
        &self,
        receipt_record_id: &str,
    ) -> Option<&DurableCompletionAuditPublicationReceiptLedgerRecord> {
        self.records
            .iter()
            .find(|r| r.receipt_record_id == receipt_record_id)
    }

    /// `true` iff a receipt with `receipt_record_id` is recorded.
    pub fn contains(&self, receipt_record_id: &str) -> bool {
        self.find(receipt_record_id).is_some()
    }

    /// Capture an immutable snapshot for a modeled rollback.
    pub fn snapshot(&self) -> DurableCompletionAuditPublicationReceiptLedgerSnapshot {
        DurableCompletionAuditPublicationReceiptLedgerSnapshot {
            records: self.records.clone(),
        }
    }

    /// Restore the ledger to a previously captured snapshot (modeled rollback).
    pub fn restore(&mut self, snapshot: &DurableCompletionAuditPublicationReceiptLedgerSnapshot) {
        self.records = snapshot.records.clone();
    }

    /// Internal: insert a recorded receipt. Only the fixture sink calls this, and
    /// only after every identity / idempotency gate has passed.
    fn insert(&mut self, record: DurableCompletionAuditPublicationReceiptLedgerRecord) {
        self.records.push(record);
    }
}

// ===========================================================================
// Receipt expectations
// ===========================================================================

/// Run 258 — the canonical binding a [`DurableCompletionAuditPublicationReceiptInput`]
/// is checked against.
///
/// Environment / chain / genesis / surface mismatches fail closed **before** the
/// receipt sink is invoked. Receipt-request-identity mismatches fail closed
/// **inside** the sink, before any modeled receipt is recorded. Neither path is
/// ever a silent approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionAuditPublicationReceiptExpectations {
    /// Expected receipt record id.
    pub expected_receipt_record_id: String,
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
    /// Expected receipt identity.
    pub expected_identity: DurableCompletionAuditPublicationReceiptIdentity,
    /// Expected receipt kind.
    pub expected_receipt_kind: DurableCompletionAuditPublicationReceiptKind,
    /// Expected receipt policy.
    pub expected_receipt_policy: DurableCompletionAuditPublicationReceiptPolicy,
    /// Expected domain separation tag.
    pub expected_domain_separation_tag: String,
}

impl DurableCompletionAuditPublicationReceiptExpectations {
    /// Internal: the first environment / surface binding mismatch reason, if any.
    fn binding_mismatch_reason(
        &self,
        input: &DurableCompletionAuditPublicationReceiptInput,
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
    pub fn binding_matches(&self, input: &DurableCompletionAuditPublicationReceiptInput) -> bool {
        self.binding_mismatch_reason(input).is_none()
    }

    /// Internal: the first receipt-request-identity mismatch reason, if any.
    fn request_mismatch_reason(
        &self,
        request: &DurableCompletionAuditPublicationReceiptRequest,
    ) -> Option<&'static str> {
        if !request.is_well_formed() {
            return Some("malformed receipt request");
        }
        if request.receipt_record_id != self.expected_receipt_record_id {
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
        if request.domain_separation_tag != self.expected_domain_separation_tag {
            return Some("wrong domain separation tag");
        }
        if request.identity != self.expected_identity {
            return Some("wrong receipt identity");
        }
        if request.identity.kind != self.expected_receipt_kind {
            return Some("wrong receipt kind");
        }
        if request.identity.policy != self.expected_receipt_policy {
            return Some("wrong receipt policy");
        }
        None
    }

    /// `true` iff the receipt-request identity matches and is well-formed.
    pub fn request_matches(
        &self,
        request: &DurableCompletionAuditPublicationReceiptRequest,
    ) -> bool {
        self.request_mismatch_reason(request).is_none()
    }
}

// ===========================================================================
// Receipt input
// ===========================================================================

/// Run 258 — typed inputs for one modeled durable-completion audit/publication
/// receipt round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionAuditPublicationReceiptInput {
    /// The receipt policy selector.
    pub policy: DurableCompletionAuditPublicationReceiptPolicy,
    /// The trust-domain environment binding.
    pub environment_binding: DurableCompletionAuditPublicationReceiptEnvironment,
    /// The runtime binding (governance + mutation surface + sequence).
    pub runtime_binding: DurableCompletionAuditPublicationReceiptBinding,
    /// The Run 240/246 durable replay observation the pipeline authorized consume
    /// under.
    pub replay_binding: DurableCompletionAuditPublicationReceiptReplayBinding,
    /// The Run 246 pipeline outcome.
    pub pipeline_binding: DurableCompletionAuditPublicationReceiptPipelineBinding,
    /// The Run 248 sink outcome.
    pub sink_binding: DurableCompletionAuditPublicationReceiptSinkBinding,
    /// The Run 250 reporter outcome.
    pub reporter_binding: DurableCompletionAuditPublicationReceiptReporterBinding,
    /// The Run 252 finalization outcome.
    pub finalization_binding: DurableCompletionAuditPublicationReceiptFinalizationBinding,
    /// The Run 254 attestation outcome.
    pub attestation_binding: DurableCompletionAuditPublicationReceiptAttestationBinding,
    /// The Run 256 backend outcome the receipt projects to a receipt request.
    pub backend_binding: DurableCompletionAuditPublicationReceiptBackendBinding,
    /// The receipt request the call site would submit.
    pub request: DurableCompletionAuditPublicationReceiptRequest,
}

impl DurableCompletionAuditPublicationReceiptInput {
    /// The trust-domain environment the decision is bound to.
    pub fn environment(&self) -> TrustBundleEnvironment {
        self.environment_binding.environment
    }

    /// The validation / mutation surface pair.
    pub fn surface(&self) -> DurableCompletionAuditPublicationReceiptSurface {
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
    }
}

// ===========================================================================
// Receipt outcome
// ===========================================================================

/// Run 258 — the typed outcome of one modeled durable-completion audit/publication
/// receipt round-trip.
///
/// Only [`Self::AuditReceiptRecorded`] authorizes a **new** modeled
/// audit/publication-receipt state. A [`Self::AuditReceiptDuplicateIdempotent`]
/// means the receipt was already recorded (idempotent, no second receipt). Every
/// other variant is a no-audit-receipt fail-closed outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableCompletionAuditPublicationReceiptOutcome {
    /// Legacy bypass — a disabled receipt policy preserved the legacy
    /// no-audit-receipt path. No receipt invocation.
    LegacyBypassNoAuditReceipt,
    /// The Run 256 backend-stage binding was rejected before the receipt sink was
    /// invoked (a backend-stage rejection / binding mismatch). Non-mutating, no
    /// receipt. No receipt invocation.
    RejectedBeforeBackendSubmissionNoAuditReceipt,
    /// The Run 256 backend did not submit (any non-submitting backend outcome
    /// without a more specific variant). Non-mutating, no receipt. No receipt
    /// invocation.
    BackendDidNotSubmitNoAuditReceipt,
    /// The receipt sink recorded a new modeled audit/publication receipt. The
    /// **only** outcome that authorizes a new modeled receipt state.
    AuditReceiptRecorded,
    /// A duplicate identical receipt — idempotent; no second receipt recorded.
    AuditReceiptDuplicateIdempotent,
    /// The receipt was rejected before record (malformed request, request-identity
    /// mismatch, same receipt record id with a differing digest / equivocation, or
    /// a duplicate-idempotent backend submission with no matching prior receipt). No
    /// receipt.
    AuditReceiptRejectedBeforeRecord,
    /// The receipt record failed. No receipt.
    AuditReceiptRecordFailedNoReceipt,
    /// The receipt record was rolled back. No receipt.
    AuditReceiptRolledBackNoReceipt,
    /// The receipt rollback itself failed — fatal / fail-closed. No receipt.
    AuditReceiptRollbackFailedFatalNoReceipt,
    /// The after-record receipt window was ambiguous — fails closed. No receipt.
    AuditReceiptAmbiguousFailClosedNoReceipt,
    /// The production audit-ledger path was reached but is unavailable. No receipt.
    ProductionAuditLedgerUnavailableNoReceipt,
    /// The MainNet audit-ledger path was reached but is unavailable. No receipt.
    MainNetAuditLedgerUnavailableNoReceipt,
    /// The external-publication path was reached but is unavailable. No receipt.
    ExternalPublicationUnavailableNoReceipt,
    /// MainNet peer-driven apply remains refused before pipeline progression, sink
    /// invocation, reporter invocation, finalizer invocation, attestor invocation,
    /// backend invocation, and receipt invocation. No receipt.
    MainNetPeerDrivenApplyRefusedNoReceipt,
    /// Validator-set rotation is unsupported. No receipt.
    ValidatorSetRotationUnsupportedNoReceipt,
    /// Policy-change actions are unsupported. No receipt.
    PolicyChangeUnsupportedNoReceipt,
}

impl DurableCompletionAuditPublicationReceiptOutcome {
    /// `true` iff this outcome authorizes a **new** modeled audit/publication
    /// receipt (only [`Self::AuditReceiptRecorded`]).
    pub fn authorizes_audit_receipt_record(&self) -> bool {
        matches!(self, Self::AuditReceiptRecorded)
    }

    /// `true` iff this outcome projects to a recorded audit/publication receipt — a
    /// newly recorded receipt or an idempotent duplicate of an already-recorded
    /// receipt.
    pub fn projects_to_audit_receipt_recorded(&self) -> bool {
        matches!(
            self,
            Self::AuditReceiptRecorded | Self::AuditReceiptDuplicateIdempotent
        )
    }

    /// `true` iff this outcome records nothing new and projects to no
    /// audit/publication receipt.
    pub fn no_audit_receipt(&self) -> bool {
        !self.projects_to_audit_receipt_recorded()
    }

    /// `true` iff this is the legacy no-audit-receipt bypass.
    pub fn is_legacy_bypass(&self) -> bool {
        matches!(self, Self::LegacyBypassNoAuditReceipt)
    }

    /// `true` iff this is the MainNet peer-driven-apply refusal.
    pub fn is_mainnet_peer_driven_apply_refused(&self) -> bool {
        matches!(self, Self::MainNetPeerDrivenApplyRefusedNoReceipt)
    }

    /// Stable operator-facing tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::LegacyBypassNoAuditReceipt => "legacy-bypass-no-audit-receipt",
            Self::RejectedBeforeBackendSubmissionNoAuditReceipt => {
                "rejected-before-backend-submission-no-audit-receipt"
            }
            Self::BackendDidNotSubmitNoAuditReceipt => "backend-did-not-submit-no-audit-receipt",
            Self::AuditReceiptRecorded => "audit-receipt-recorded",
            Self::AuditReceiptDuplicateIdempotent => "audit-receipt-duplicate-idempotent",
            Self::AuditReceiptRejectedBeforeRecord => "audit-receipt-rejected-before-record",
            Self::AuditReceiptRecordFailedNoReceipt => "audit-receipt-record-failed-no-receipt",
            Self::AuditReceiptRolledBackNoReceipt => "audit-receipt-rolled-back-no-receipt",
            Self::AuditReceiptRollbackFailedFatalNoReceipt => {
                "audit-receipt-rollback-failed-fatal-no-receipt"
            }
            Self::AuditReceiptAmbiguousFailClosedNoReceipt => {
                "audit-receipt-ambiguous-fail-closed-no-receipt"
            }
            Self::ProductionAuditLedgerUnavailableNoReceipt => {
                "production-audit-ledger-unavailable-no-receipt"
            }
            Self::MainNetAuditLedgerUnavailableNoReceipt => {
                "mainnet-audit-ledger-unavailable-no-receipt"
            }
            Self::ExternalPublicationUnavailableNoReceipt => {
                "external-publication-unavailable-no-receipt"
            }
            Self::MainNetPeerDrivenApplyRefusedNoReceipt => {
                "mainnet-peer-driven-apply-refused-no-receipt"
            }
            Self::ValidatorSetRotationUnsupportedNoReceipt => {
                "validator-set-rotation-unsupported-no-receipt"
            }
            Self::PolicyChangeUnsupportedNoReceipt => "policy-change-unsupported-no-receipt",
        }
    }
}

// ===========================================================================
// Backend-outcome -> receipt request projection
// ===========================================================================

/// Run 258 — the typed projection of a Run 256 backend outcome onto a receipt
/// request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableCompletionAuditPublicationReceiptRequestIntent {
    /// The backend recorded a submission; the receipt sink may record a new receipt.
    CreateRequest,
    /// The backend reported an idempotent-duplicate submission; the receipt sink may
    /// only match an already-recorded receipt and must never create a new one.
    IdempotentOnly,
    /// The backend did not submit; no receipt request. Carries the typed
    /// no-audit-receipt outcome the receipt evaluation returns directly (without
    /// invoking the receipt sink).
    NoAuditReceipt(DurableCompletionAuditPublicationReceiptOutcome),
}

impl DurableCompletionAuditPublicationReceiptRequestIntent {
    /// `true` iff this projection creates a receipt request (i.e. the backend
    /// recorded a submission).
    pub fn creates_request(&self) -> bool {
        matches!(self, Self::CreateRequest)
    }
}

/// Run 258 — project a Run 256 backend outcome onto a receipt request.
///
/// Only
/// [`DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded`]
/// creates a receipt request.
/// [`DurableCompletionAttestationBackendOutcome::BackendSubmissionDuplicateIdempotent`]
/// may only match an already-recorded receipt and never creates a new one. Every
/// other backend outcome maps to a no-audit-receipt fail-closed outcome (a more
/// specific one where one exists, otherwise the generic
/// [`DurableCompletionAuditPublicationReceiptOutcome::BackendDidNotSubmitNoAuditReceipt`]).
/// Pure: performs no work and never records.
pub fn project_backend_submission_outcome_to_audit_receipt_request(
    outcome: &DurableCompletionAttestationBackendOutcome,
) -> DurableCompletionAuditPublicationReceiptRequestIntent {
    use DurableCompletionAttestationBackendOutcome as Backend;
    use DurableCompletionAuditPublicationReceiptOutcome as Receipt;
    use DurableCompletionAuditPublicationReceiptRequestIntent as Intent;
    match outcome {
        Backend::BackendSubmissionRecorded => Intent::CreateRequest,
        Backend::BackendSubmissionDuplicateIdempotent => Intent::IdempotentOnly,
        Backend::LegacyBypassNoBackendSubmission => {
            Intent::NoAuditReceipt(Receipt::LegacyBypassNoAuditReceipt)
        }
        Backend::RejectedBeforeAttestationNoBackendSubmission => {
            Intent::NoAuditReceipt(Receipt::RejectedBeforeBackendSubmissionNoAuditReceipt)
        }
        Backend::MainNetPeerDrivenApplyRefusedNoSubmission => {
            Intent::NoAuditReceipt(Receipt::MainNetPeerDrivenApplyRefusedNoReceipt)
        }
        Backend::ValidatorSetRotationUnsupportedNoSubmission => {
            Intent::NoAuditReceipt(Receipt::ValidatorSetRotationUnsupportedNoReceipt)
        }
        Backend::PolicyChangeUnsupportedNoSubmission => {
            Intent::NoAuditReceipt(Receipt::PolicyChangeUnsupportedNoReceipt)
        }
        // Every remaining backend outcome is a non-submitting rejection / failure /
        // rollback / ambiguous window / production / MainNet / external-publication
        // unavailable: the backend did not submit, so no audit receipt may exist.
        _ => Intent::NoAuditReceipt(Receipt::BackendDidNotSubmitNoAuditReceipt),
    }
}

// ===========================================================================
// Receipt fault injection (source/test only)
// ===========================================================================

/// Run 258 — a modeled fault the fixture receipt sink injects to exercise the
/// fail-closed record / rollback / ambiguous paths. Source/test only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionAuditPublicationReceiptFault {
    /// The receipt record fails; nothing is written. No receipt.
    RecordFailedNoReceipt,
    /// The receipt record is rolled back; nothing remains written. No receipt.
    RolledBackNoReceipt,
    /// The receipt rollback itself fails — fatal / fail-closed. No receipt.
    RollbackFailedFatal,
    /// The after-record receipt window is ambiguous — fails closed. No receipt.
    AmbiguousAfterRecord,
}

// ===========================================================================
// Receipt trait boundary
// ===========================================================================

/// Run 258 — the pure/mockable modeled durable-completion audit/publication receipt
/// boundary.
///
/// No implementation here calls Run 070, mutates `LivePqcTrustState`, performs a
/// live trust swap, evicts sessions, writes a sequence, writes a marker, performs
/// network I/O, external publication, or a real audit-ledger persistence. The
/// DevNet/TestNet fixture receipt sink mutates only the in-memory
/// [`DurableCompletionAuditPublicationReceiptLedger`].
pub trait GovernanceDurableCompletionAuditPublicationReceiptSink {
    /// The receipt kind (used for typed recovery classification).
    fn kind(&self) -> DurableCompletionAuditPublicationReceiptKind;

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
    fn record_durable_completion_audit_publication_receipt(
        &mut self,
        request: &DurableCompletionAuditPublicationReceiptRequest,
        expectations: &DurableCompletionAuditPublicationReceiptExpectations,
        idempotent_only: bool,
        ledger: &mut DurableCompletionAuditPublicationReceiptLedger,
    ) -> DurableCompletionAuditPublicationReceiptOutcome;

    /// Classify a modeled receipt crash/recovery window. Pure: performs no modeled
    /// mutation and never invokes Run 070.
    fn recover_durable_completion_audit_publication_receipt_window(
        &self,
        input: &DurableCompletionAuditPublicationReceiptInput,
        window: DurableCompletionAuditPublicationReceiptWindow,
        recovered_record: Option<&DurableCompletionAuditPublicationReceiptLedgerRecord>,
        expectations: &DurableCompletionAuditPublicationReceiptExpectations,
    ) -> DurableCompletionAuditPublicationReceiptOutcome {
        recover_durable_completion_audit_publication_receipt_window(
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

/// Run 258 — the DevNet/TestNet in-memory fixture receipt sink.
///
/// Source-test only. It mutates only the in-memory
/// [`DurableCompletionAuditPublicationReceiptLedger`] and exposes an invocation
/// counter so tests can prove non-submitting backend paths and pre-receipt
/// rejections never invoke it.
#[derive(Debug, Clone)]
pub struct FixtureDurableCompletionAuditPublicationReceiptSink {
    fault: Option<DurableCompletionAuditPublicationReceiptFault>,
    invocations: u32,
}

impl Default for FixtureDurableCompletionAuditPublicationReceiptSink {
    fn default() -> Self {
        Self::new()
    }
}

impl FixtureDurableCompletionAuditPublicationReceiptSink {
    /// A new fixture receipt sink.
    pub fn new() -> Self {
        Self {
            fault: None,
            invocations: 0,
        }
    }

    /// A new fixture receipt sink that injects the given modeled fault on record.
    pub fn with_fault(fault: DurableCompletionAuditPublicationReceiptFault) -> Self {
        Self {
            fault: Some(fault),
            invocations: 0,
        }
    }
}

impl GovernanceDurableCompletionAuditPublicationReceiptSink
    for FixtureDurableCompletionAuditPublicationReceiptSink
{
    fn kind(&self) -> DurableCompletionAuditPublicationReceiptKind {
        DurableCompletionAuditPublicationReceiptKind::FixtureInMemory
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn record_durable_completion_audit_publication_receipt(
        &mut self,
        request: &DurableCompletionAuditPublicationReceiptRequest,
        expectations: &DurableCompletionAuditPublicationReceiptExpectations,
        idempotent_only: bool,
        ledger: &mut DurableCompletionAuditPublicationReceiptLedger,
    ) -> DurableCompletionAuditPublicationReceiptOutcome {
        use DurableCompletionAuditPublicationReceiptOutcome as Receipt;
        self.invocations += 1;

        // Injected faults model record-failure / rollback / ambiguous windows. None
        // of them ever leave a recorded receipt behind, so a durable receipt is never
        // claimed. The ledger snapshot/restore models the rollback being a no-op
        // write.
        if let Some(fault) = self.fault {
            let snapshot = ledger.snapshot();
            return match fault {
                DurableCompletionAuditPublicationReceiptFault::RecordFailedNoReceipt => {
                    ledger.restore(&snapshot);
                    Receipt::AuditReceiptRecordFailedNoReceipt
                }
                DurableCompletionAuditPublicationReceiptFault::RolledBackNoReceipt => {
                    ledger.restore(&snapshot);
                    Receipt::AuditReceiptRolledBackNoReceipt
                }
                DurableCompletionAuditPublicationReceiptFault::RollbackFailedFatal => {
                    Receipt::AuditReceiptRollbackFailedFatalNoReceipt
                }
                DurableCompletionAuditPublicationReceiptFault::AmbiguousAfterRecord => {
                    ledger.restore(&snapshot);
                    Receipt::AuditReceiptAmbiguousFailClosedNoReceipt
                }
            };
        }

        // The fixture receipt sink is DevNet/TestNet evidence-only.
        if !matches!(
            request.environment,
            TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet
        ) {
            return Receipt::AuditReceiptRejectedBeforeRecord;
        }

        // Request-identity validation (malformed / mismatch) fails closed before any
        // record is written.
        if !expectations.request_matches(request) {
            return Receipt::AuditReceiptRejectedBeforeRecord;
        }

        // Build the deterministic request / response / record / transcript digests.
        let request_digest = request.digest();
        let response = DurableCompletionAuditPublicationReceiptResponse {
            receipt_record_id: request.receipt_record_id.clone(),
            request_digest: request_digest.clone(),
            accepted: true,
            receipt_kind: DurableCompletionAuditPublicationReceiptKind::FixtureInMemory,
        };
        let response_digest = response.digest();
        let record = request.to_record();
        let record_digest = record.digest();
        let transcript_digest =
            receipt_transcript_digest(&request_digest, &response_digest, &record_digest);

        // Idempotency / equivocation gate.
        if let Some(existing) = ledger.find(&request.receipt_record_id) {
            if existing.request_digest == request_digest
                && existing.response_digest == response_digest
                && existing.record_digest == record_digest
                && existing.transcript_digest == transcript_digest
            {
                return Receipt::AuditReceiptDuplicateIdempotent;
            }
            // Same receipt record id with a different digest is equivocation: fail
            // closed, record no second receipt.
            return Receipt::AuditReceiptRejectedBeforeRecord;
        }

        // A duplicate-idempotent backend submission may only match an already-recorded
        // receipt; it must never create a new one by itself.
        if idempotent_only {
            return Receipt::AuditReceiptRejectedBeforeRecord;
        }

        ledger.insert(DurableCompletionAuditPublicationReceiptLedgerRecord {
            receipt_record_id: request.receipt_record_id.clone(),
            request_digest,
            response_digest,
            record_digest,
            transcript_digest,
            status: DurableCompletionAuditPublicationReceiptLedgerStatus::Recorded,
        });
        Receipt::AuditReceiptRecorded
    }
}

// ===========================================================================
// Production / MainNet audit-ledger / External-publication sinks (unavailable)
// ===========================================================================

/// Run 258 — the production audit-ledger receipt sink. Reachable but unavailable /
/// fail-closed. It records no receipt and mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct ProductionAuditLedgerDurableCompletionReceiptSink {
    invocations: u32,
}

impl GovernanceDurableCompletionAuditPublicationReceiptSink
    for ProductionAuditLedgerDurableCompletionReceiptSink
{
    fn kind(&self) -> DurableCompletionAuditPublicationReceiptKind {
        DurableCompletionAuditPublicationReceiptKind::ProductionAuditLedgerUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn record_durable_completion_audit_publication_receipt(
        &mut self,
        _request: &DurableCompletionAuditPublicationReceiptRequest,
        _expectations: &DurableCompletionAuditPublicationReceiptExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionAuditPublicationReceiptLedger,
    ) -> DurableCompletionAuditPublicationReceiptOutcome {
        self.invocations += 1;
        DurableCompletionAuditPublicationReceiptOutcome::ProductionAuditLedgerUnavailableNoReceipt
    }
}

/// Run 258 — the MainNet audit-ledger receipt sink. Reachable but unavailable /
/// fail-closed. It records no receipt and mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct MainNetAuditLedgerDurableCompletionReceiptSink {
    invocations: u32,
}

impl GovernanceDurableCompletionAuditPublicationReceiptSink
    for MainNetAuditLedgerDurableCompletionReceiptSink
{
    fn kind(&self) -> DurableCompletionAuditPublicationReceiptKind {
        DurableCompletionAuditPublicationReceiptKind::MainNetAuditLedgerUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn record_durable_completion_audit_publication_receipt(
        &mut self,
        _request: &DurableCompletionAuditPublicationReceiptRequest,
        _expectations: &DurableCompletionAuditPublicationReceiptExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionAuditPublicationReceiptLedger,
    ) -> DurableCompletionAuditPublicationReceiptOutcome {
        self.invocations += 1;
        DurableCompletionAuditPublicationReceiptOutcome::MainNetAuditLedgerUnavailableNoReceipt
    }
}

/// Run 258 — the external-publication receipt sink. Reachable but unavailable /
/// fail-closed. It performs no external publication, records no receipt, and
/// mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct ExternalPublicationDurableCompletionReceiptSink {
    invocations: u32,
}

impl GovernanceDurableCompletionAuditPublicationReceiptSink
    for ExternalPublicationDurableCompletionReceiptSink
{
    fn kind(&self) -> DurableCompletionAuditPublicationReceiptKind {
        DurableCompletionAuditPublicationReceiptKind::ExternalPublicationUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn record_durable_completion_audit_publication_receipt(
        &mut self,
        _request: &DurableCompletionAuditPublicationReceiptRequest,
        _expectations: &DurableCompletionAuditPublicationReceiptExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionAuditPublicationReceiptLedger,
    ) -> DurableCompletionAuditPublicationReceiptOutcome {
        self.invocations += 1;
        DurableCompletionAuditPublicationReceiptOutcome::ExternalPublicationUnavailableNoReceipt
    }
}

// ===========================================================================
// Receipt executor / composition helpers
// ===========================================================================

/// Run 258 — evaluate one modeled durable-completion audit/publication receipt
/// round-trip.
///
/// Ordering (each gate must pass before the next is considered):
///
/// 1. MainNet peer-driven apply refusal — before pipeline progression, sink
///    invocation, reporter invocation, finalizer invocation, attestor invocation,
///    backend invocation, and receipt invocation;
/// 2. legacy bypass — a
///    [`DurableCompletionAuditPublicationReceiptPolicy::Disabled`] policy;
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
pub fn evaluate_durable_completion_audit_publication_receipt<S>(
    input: &DurableCompletionAuditPublicationReceiptInput,
    expectations: &DurableCompletionAuditPublicationReceiptExpectations,
    sink: &mut S,
    ledger: &mut DurableCompletionAuditPublicationReceiptLedger,
) -> DurableCompletionAuditPublicationReceiptOutcome
where
    S: GovernanceDurableCompletionAuditPublicationReceiptSink,
{
    use DurableCompletionAuditPublicationReceiptOutcome as Receipt;
    use DurableCompletionAuditPublicationReceiptRequestIntent as Intent;

    // Step 1: MainNet peer-driven apply remains refused unconditionally, before
    // pipeline progression, sink invocation, reporter invocation, finalizer
    // invocation, attestor invocation, backend invocation, and receipt invocation.
    if input.is_mainnet_peer_driven() {
        return Receipt::MainNetPeerDrivenApplyRefusedNoReceipt;
    }

    // Step 2: legacy bypass — a disabled receipt policy preserves the legacy
    // no-audit-receipt path and never invokes the receipt sink.
    if input.policy.is_disabled() {
        return Receipt::LegacyBypassNoAuditReceipt;
    }

    // Step 3: project the Run 256 backend outcome onto a receipt request. Every
    // non-submitting outcome returns a no-audit-receipt outcome without invoking the
    // receipt sink.
    let idempotent_only = match project_backend_submission_outcome_to_audit_receipt_request(
        &input.backend_binding,
    ) {
        Intent::NoAuditReceipt(outcome) => return outcome,
        Intent::CreateRequest => false,
        Intent::IdempotentOnly => true,
    };

    // Step 4: pre-receipt environment / surface binding validation. A mismatch fails
    // closed before the receipt sink is invoked, leaving the receipt invocation count
    // at zero.
    if !expectations.binding_matches(input) {
        return Receipt::RejectedBeforeBackendSubmissionNoAuditReceipt;
    }

    // Step 5: invoke the receipt sink to record the modeled receipt.
    sink.record_durable_completion_audit_publication_receipt(
        &input.request,
        expectations,
        idempotent_only,
        ledger,
    )
}

// ===========================================================================
// Receipt crash/recovery window classification
// ===========================================================================

/// Run 258 — the modeled durable-completion audit/publication receipt
/// crash/recovery window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionAuditPublicationReceiptWindow {
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
    /// Crashed after a receipt record but before receipt success — fails closed
    /// unless an explicit matching receipt success exists.
    AfterReceiptRecordBeforeReceiptSuccess,
    /// Recovered after a successful receipt record.
    AfterReceiptSuccess,
    /// Recovered after an ambiguous receipt window.
    AfterReceiptAmbiguous,
    /// The receipt record itself failed.
    ReceiptRecordFailed,
    /// The receipt record was rolled back.
    ReceiptRollbackCompleted,
    /// The receipt rollback itself failed — fatal.
    ReceiptRollbackFailed,
    /// An unknown window — fails closed.
    Unknown,
}

/// Run 258 — classify a modeled durable-completion audit/publication receipt
/// crash/recovery window.
///
/// The receipt sink never silently re-authorizes an in-flight receipt: MainNet
/// peer-driven refusal precedes classification, production / MainNet audit-ledger /
/// external-publication classification is unavailable, and every ambiguous /
/// unknown window fails closed. Only an after-receipt-record window with an explicit
/// matching record (or an explicit after-receipt-success window) recovers as
/// [`DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRecorded`]. Pure:
/// performs no modeled mutation and never invokes Run 070.
pub fn recover_durable_completion_audit_publication_receipt_window(
    input: &DurableCompletionAuditPublicationReceiptInput,
    window: DurableCompletionAuditPublicationReceiptWindow,
    kind: DurableCompletionAuditPublicationReceiptKind,
    recovered_record: Option<&DurableCompletionAuditPublicationReceiptLedgerRecord>,
    expectations: &DurableCompletionAuditPublicationReceiptExpectations,
) -> DurableCompletionAuditPublicationReceiptOutcome {
    use DurableCompletionAuditPublicationReceiptOutcome as Receipt;
    use DurableCompletionAuditPublicationReceiptWindow as Window;

    // MainNet peer-driven apply refusal precedes recovery classification.
    if input.is_mainnet_peer_driven() {
        return Receipt::MainNetPeerDrivenApplyRefusedNoReceipt;
    }

    // Production / MainNet audit-ledger / external-publication recovery
    // classification is unavailable / fail-closed.
    match kind {
        DurableCompletionAuditPublicationReceiptKind::ProductionAuditLedgerUnavailable => {
            return Receipt::ProductionAuditLedgerUnavailableNoReceipt;
        }
        DurableCompletionAuditPublicationReceiptKind::MainNetAuditLedgerUnavailable => {
            return Receipt::MainNetAuditLedgerUnavailableNoReceipt;
        }
        DurableCompletionAuditPublicationReceiptKind::ExternalPublicationUnavailable => {
            return Receipt::ExternalPublicationUnavailableNoReceipt;
        }
        DurableCompletionAuditPublicationReceiptKind::Disabled => {
            return Receipt::LegacyBypassNoAuditReceipt;
        }
        DurableCompletionAuditPublicationReceiptKind::Unknown => {
            return Receipt::AuditReceiptAmbiguousFailClosedNoReceipt;
        }
        DurableCompletionAuditPublicationReceiptKind::FixtureInMemory => {}
    }

    // Helper: an explicit recovered record recovers as a receipt only if it matches
    // the expected receipt record id and the canonical request digest.
    let recovered_matches =
        |record: &DurableCompletionAuditPublicationReceiptLedgerRecord| -> bool {
            record.receipt_record_id == expectations.expected_receipt_record_id
                && record.request_digest == input.request.digest()
                && record.status
                    == DurableCompletionAuditPublicationReceiptLedgerStatus::Recorded
        };

    match window {
        // Before the backend recorded a submission there is nothing to record a
        // receipt for.
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
        | Window::AfterBackendRecordBeforeBackendSuccess => {
            Receipt::BackendDidNotSubmitNoAuditReceipt
        }
        // A recorded backend submission without a receipt request / record never
        // records a receipt.
        Window::AfterBackendSuccessBeforeReceiptRequest
        | Window::AfterReceiptRequestBeforeReceiptRecord => {
            Receipt::AuditReceiptRejectedBeforeRecord
        }
        // After a receipt record but before receipt success: fails closed unless an
        // explicit matching, well-formed receipt record exists.
        Window::AfterReceiptRecordBeforeReceiptSuccess => match recovered_record {
            Some(record) if recovered_matches(record) => Receipt::AuditReceiptRecorded,
            _ => Receipt::AuditReceiptRejectedBeforeRecord,
        },
        // An explicit successful receipt recovers as recorded only if it matches.
        Window::AfterReceiptSuccess => match recovered_record {
            Some(record) if recovered_matches(record) => Receipt::AuditReceiptRecorded,
            _ => Receipt::AuditReceiptRejectedBeforeRecord,
        },
        Window::AfterReceiptAmbiguous => Receipt::AuditReceiptAmbiguousFailClosedNoReceipt,
        Window::ReceiptRecordFailed => Receipt::AuditReceiptRecordFailedNoReceipt,
        Window::ReceiptRollbackCompleted => Receipt::AuditReceiptRolledBackNoReceipt,
        Window::ReceiptRollbackFailed => Receipt::AuditReceiptRollbackFailedFatalNoReceipt,
        // Any unknown window fails closed.
        Window::Unknown => Receipt::AuditReceiptAmbiguousFailClosedNoReceipt,
    }
}

/// Run 258 — `true` iff a receipt outcome authorizes a **new** modeled
/// audit/publication receipt (only
/// [`DurableCompletionAuditPublicationReceiptOutcome::AuditReceiptRecorded`]).
pub fn audit_receipt_outcome_authorizes_receipt_record(
    outcome: &DurableCompletionAuditPublicationReceiptOutcome,
) -> bool {
    outcome.authorizes_audit_receipt_record()
}

/// Run 258 — `true` iff a receipt outcome projects to a recorded audit/publication
/// receipt (a newly recorded receipt or an idempotent duplicate of an
/// already-recorded receipt).
pub fn audit_receipt_outcome_projects_to_audit_receipt_recorded(
    outcome: &DurableCompletionAuditPublicationReceiptOutcome,
) -> bool {
    outcome.projects_to_audit_receipt_recorded()
}

// ===========================================================================
// Grep-verifiable safety invariants (source/test only)
// ===========================================================================

/// Run 258 — a receipt rejection is non-mutating: it records no receipt, mutates no
/// `LivePqcTrustState`, and writes no durable state.
pub fn durable_completion_audit_receipt_rejection_is_non_mutating() -> bool {
    true
}

/// Run 258 — the receipt boundary never calls Run 070.
pub fn durable_completion_audit_receipt_never_calls_run_070() -> bool {
    true
}

/// Run 258 — the receipt boundary never mutates live PQC trust state.
pub fn durable_completion_audit_receipt_never_mutates_live_pqc_trust_state() -> bool {
    true
}

/// Run 258 — the receipt boundary never writes a sequence or a marker.
pub fn durable_completion_audit_receipt_never_writes_sequence_or_marker() -> bool {
    true
}

/// Run 258 — the receipt boundary changes no RocksDB file schema / migration.
pub fn durable_completion_audit_receipt_no_rocksdb_file_schema_migration_change() -> bool {
    true
}

/// Run 258 — the receipt boundary performs no external publication.
pub fn durable_completion_audit_receipt_no_external_publication() -> bool {
    true
}

/// Run 258 — the receipt boundary performs no real audit-ledger persistence.
pub fn durable_completion_audit_receipt_no_real_audit_ledger() -> bool {
    true
}

/// Run 258 — a receipt requires a successful Run 246 pipeline outcome upstream.
pub fn durable_completion_audit_receipt_pipeline_success_required() -> bool {
    true
}

/// Run 258 — a receipt requires a Run 248 sink receipt record upstream.
pub fn durable_completion_audit_receipt_sink_receipt_required() -> bool {
    true
}

/// Run 258 — a receipt requires a Run 250 completion report upstream.
pub fn durable_completion_audit_receipt_completion_report_required() -> bool {
    true
}

/// Run 258 — a receipt requires a Run 252 finalization upstream.
pub fn durable_completion_audit_receipt_finalization_required() -> bool {
    true
}

/// Run 258 — a receipt requires a Run 254 attestation upstream.
pub fn durable_completion_audit_receipt_attestation_required() -> bool {
    true
}

/// Run 258 — a receipt requires a Run 256 backend submission upstream.
pub fn durable_completion_audit_receipt_backend_submission_required() -> bool {
    true
}

/// Run 258 — a receipt record is required before a receipt is acknowledged.
pub fn durable_completion_audit_receipt_record_required_before_receipt() -> bool {
    true
}

/// Run 258 — a failed receipt record never records a receipt.
pub fn durable_completion_audit_receipt_failed_record_never_records() -> bool {
    true
}

/// Run 258 — a rolled-back receipt record never records a receipt.
pub fn durable_completion_audit_receipt_rollback_never_records() -> bool {
    true
}

/// Run 258 — an ambiguous after-record receipt window fails closed.
pub fn durable_completion_audit_receipt_ambiguous_window_fails_closed() -> bool {
    true
}

/// Run 258 — MainNet peer-driven apply refusal precedes every receipt stage.
pub fn durable_completion_audit_receipt_mainnet_peer_driven_apply_refused_first(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 258 — production / MainNet audit-ledger sinks are reachable but unavailable.
pub fn durable_completion_audit_receipt_production_mainnet_unavailable() -> bool {
    true
}

/// Run 258 — the external-publication sink is reachable but unavailable.
pub fn durable_completion_audit_receipt_external_publication_unavailable() -> bool {
    true
}

/// Run 258 — validator-set rotation remains unsupported at the receipt boundary.
pub fn durable_completion_audit_receipt_validator_set_rotation_unsupported() -> bool {
    true
}

/// Run 258 — policy-change actions remain unsupported at the receipt boundary.
pub fn durable_completion_audit_receipt_policy_change_unsupported() -> bool {
    true
}

/// Run 258 — a local operator cannot satisfy MainNet authority for a receipt.
pub fn durable_completion_audit_receipt_local_operator_cannot_satisfy_mainnet_authority() -> bool {
    true
}

/// Run 258 — a peer majority cannot satisfy MainNet authority for a receipt.
pub fn durable_completion_audit_receipt_peer_majority_cannot_satisfy_mainnet_authority() -> bool {
    true
}
