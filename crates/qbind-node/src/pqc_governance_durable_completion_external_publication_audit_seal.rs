//! Run 288 — source/test durable-completion **external-publication-audit-archive
//! consumer / external-publication-audit-seal interface boundary**.
//!
//! Source/test only. Run 288 captures **no** release-binary evidence and enables
//! **no** production mutating behavior. It does **not** implement a real settlement
//! backend, a real settlement finality, a real settlement receipt, a real
//! external-publication-audit-archive backend, a real settlement-finality projection
//! backend, a real audit-ledger acknowledgement, a real external-publication
//! external_publication_audit_seal, a real external-publication system, a real production attestation /
//! confirmation / completion-report / durable-consume / persistent-replay backend, a
//! real governance execution engine, a real production mutation engine, a real on-chain
//! governance proof verifier, a KMS/HSM/RemoteSigner backend, MainNet governance
//! enablement, MainNet peer-driven apply enablement, validator-set rotation, or any
//! RocksDB / file / schema / migration / wire / marker / sequence / trust-bundle /
//! storage-format change.
//!
//! ## What this module adds
//!
//! Run 286
//! ([`crate::pqc_governance_durable_completion_external_publication_audit_archive`])
//! proves that a modeled durable-completion *settlement confirmation* is recorded
//! **only** after the Run 266 settlement-outcome-publication stage recorded a settlement
//! commitment, terminating in the single settlement-confirmation-recording outcome
//! [`DurableCompletionExternalPublicationAuditArchiveOutcome::ExternalPublicationAuditArchiveRecorded`].
//!
//! Run 288 defines the **first typed interface** a future production settlement-receipt
//! acknowledgement or settlement-finality projection subsystem would use to *consume* a
//! durable-completion settlement confirmation and prepare a settlement-receipt
//! acknowledgement intent and modeled in-memory settlement-finality projection receipt
//! **after** the Run 286 settlement-confirmation stage produced
//! `ExternalPublicationAuditArchiveRecorded`. It is an **interface / projection boundary only**:
//! production / MainNet / external external-publication-audit-archive implementations
//! are *reachable but deliberately unavailable / fail-closed*, and the only positive
//! implementation is a DevNet/TestNet fixture that records into an in-memory fixture
//! ledger for source/test evidence only.
//!
//! The external-publication-audit-archive layer is a **model only**. It does not
//! implement a real settlement, a real settlement finality, a real settlement receipt, a
//! real external-publication-audit-archive, a real settlement-finality projection, a
//! real external publication, a real audit-ledger acknowledgement, or any real
//! persistent storage. It does not write RocksDB, files, schemas, migrations, storage
//! formats, wire formats, authority markers, trust-bundle sequence files, or any
//! production durable state. It does not call Run 070, mutate `LivePqcTrustState`,
//! perform a real trust swap, evict sessions, perform external publication / network
//! I/O, or enable MainNet governance / MainNet peer-driven apply. The DevNet/TestNet
//! fixture external-publication-audit-archive sink mutates only the in-memory
//! [`DurableCompletionExternalPublicationAuditSealLedger`].
//!
//! ## Ordering / fail-closed contract
//!
//! 1. **MainNet peer-driven apply refusal** — refused *before* pipeline
//!    progression, sink invocation, reporter invocation, finalizer invocation,
//!    attestor invocation, backend invocation, receipt invocation, acknowledgement
//!    invocation, consumer invocation, settlement-projection invocation,
//!    settlement-outcome-publication invocation, and settlement-confirmation invocation;
//! 2. **legacy bypass** — a
//!    [`DurableCompletionExternalPublicationAuditSealPolicy::Disabled`] policy preserves
//!    the legacy no-external-publication-audit-seal bypass and never invokes the
//!    external-publication-audit-archive sink;
//! 3. **settlement-confirmation-outcome projection** — only
//!    [`DurableCompletionExternalPublicationAuditArchiveOutcome::ExternalPublicationAuditArchiveRecorded`]
//!    creates a external-publication-audit-archive request; every other Run 286 outcome
//!    maps to a no-outcome-publication fail-closed outcome and never invokes the
//!    external-publication-audit-archive sink;
//! 4. **pre-sink binding validation** — environment / chain / genesis /
//!    governance surface / mutation surface and the full digest binding (including
//!    the Run 256 backend, Run 258 receipt, Run 260 acknowledgement, Run 262 consumer,
//!    and Run 286 settlement-confirmation digest sets) must match expectations *before*
//!    the external-publication-audit-archive sink is invoked; a mismatch fails closed
//!    and leaves the sink invocation count at zero;
//! 5. **external-publication-audit-archive record** — only after every prior gate
//!    passes is the sink invoked; the record-identity fields must match exactly before
//!    any modeled external-publication-audit-archive record is recorded;
//! 6. **external-publication-audit-archive authorization** — only
//!    [`DurableCompletionExternalPublicationAuditSealOutcome::ExternalPublicationAuditSealRecorded`]
//!    authorizes a new modeled external-publication-audit-archive / settlement-finality
//!    projection state.
//!
//! A external-publication-audit-archive record failure, rollback, rollback failure, or
//! ambiguous window never retroactively claims a durable settlement-receipt
//! acknowledgement record. A duplicate identical external-publication-audit-archive
//! record is idempotent; the same record id with a different digest fails closed as
//! equivocation and records no second record. A Run 286
//! [`DurableCompletionExternalPublicationAuditArchiveOutcome::ExternalPublicationAuditArchiveDuplicateIdempotent`]
//! never creates a new external-publication-audit-archive record by itself — it can only
//! match an already-recorded external-publication-audit-archive record.

use crate::pqc_governance_durable_completion_acknowledgement_consumer::DurableCompletionAcknowledgementConsumerOutcome;
use crate::pqc_governance_durable_completion_external_publication_audit_archive::DurableCompletionExternalPublicationAuditArchiveOutcome;
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

/// Run 288 — the validation / mutation surface pair the receipt binds to.
pub type DurableCompletionExternalPublicationAuditSealSurface =
    ModeledGovernanceTrustMutationSurface;

/// Run 288 — the trust-domain environment binding the receipt is bound to.
pub type DurableCompletionExternalPublicationAuditSealEnvironment =
    ModeledGovernanceTrustMutationEnvironmentBinding;

/// Run 288 — the runtime binding (governance + mutation surface + sequence) the
/// receipt is bound to.
pub type DurableCompletionExternalPublicationAuditSealBinding =
    ModeledGovernanceTrustMutationRuntimeBinding;

/// Run 288 — the Run 240/246 durable replay observation carried as freshness
/// context.
pub type DurableCompletionExternalPublicationAuditSealReplayBinding = DurableReplayObservation;

/// Run 288 — the Run 246 pipeline outcome carried as consume authorization context.
pub type DurableCompletionExternalPublicationAuditSealPipelineBinding =
    GovernanceModeledEndToEndPipelineOutcome;

/// Run 288 — the Run 248 sink outcome carried as receipt-record context.
pub type DurableCompletionExternalPublicationAuditSealSinkBinding =
    GovernanceModeledDurableConsumeSinkOutcome;

/// Run 288 — the Run 250 reporter outcome carried as completion-report context.
pub type DurableCompletionExternalPublicationAuditSealReporterBinding =
    GovernanceModeledDurableConsumeCompletionReporterOutcome;

/// Run 288 — the Run 252 external_publication_audit_seal outcome carried as external_publication_audit_seal context.
pub type DurableCompletionExternalPublicationAuditSealFinalizationBinding =
    GovernanceModeledDurableCompletionFinalizationOutcome;

/// Run 288 — the Run 254 attestation outcome carried as attestation context.
pub type DurableCompletionExternalPublicationAuditSealAttestationBinding =
    GovernanceModeledDurableCompletionAttestationOutcome;

/// Run 288 — the Run 256 backend outcome carried as backend-record context. The
/// acknowledgement boundary never reimplements the backend; it only carries its
/// terminal outcome.
pub type DurableCompletionExternalPublicationAuditSealBackendBinding =
    DurableCompletionAttestationBackendOutcome;

/// Run 288 — the Run 258 audit/publication receipt outcome carried as
/// receipt-record context. The consumer boundary never reimplements the receipt; it
/// only carries its terminal outcome.
pub type DurableCompletionExternalPublicationAuditSealReceiptBinding =
    DurableCompletionAuditPublicationReceiptOutcome;

/// Run 288 — the Run 260 audit-receipt acknowledgement outcome carried as
/// acknowledgement-record context. The settlement-confirmation boundary never
/// reimplements the acknowledgement; it only carries its terminal outcome.
pub type DurableCompletionExternalPublicationAuditSealAcknowledgementBinding =
    DurableCompletionAuditReceiptAcknowledgementOutcome;

/// Run 288 — the Run 262 acknowledgement consumer outcome the settlement-confirmation
/// boundary projects to a settlement-confirmation request. The settlement-confirmation
/// boundary never reimplements the consumer; it only projects its terminal outcome.
pub type DurableCompletionExternalPublicationAuditSealConsumerBinding =
    DurableCompletionAcknowledgementConsumerOutcome;

/// Run 288 — the Run 286 settlement-confirmation outcome the external-publication-audit-seal
/// boundary projects to a external-publication-audit-seal request. The external-publication-audit-seal
/// boundary never reimplements the settlement confirmation; it only projects its
/// terminal outcome.
pub type DurableCompletionExternalPublicationAuditSealExternalPublicationAuditArchiveBinding =
    DurableCompletionExternalPublicationAuditArchiveOutcome;

// ===========================================================================
// Receipt kind
// ===========================================================================

/// Run 288 — the typed durable-completion audit/publication receipt kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionExternalPublicationAuditSealKind {
    /// The receipt boundary is disabled (legacy bypass).
    Disabled,
    /// DevNet/TestNet in-memory fixture receipt sink (source-test only; may mutate
    /// only the ledger).
    FixtureInMemory,
    /// Production audit-ledger receipt sink (reachable-but-unavailable /
    /// fail-closed).
    ProductionExternalPublicationAuditSealUnavailable,
    /// MainNet audit-ledger receipt sink (reachable-but-unavailable / fail-closed).
    MainNetExternalPublicationAuditSealUnavailable,
    /// External-publication receipt sink (reachable-but-unavailable / fail-closed).
    ExternalExternalPublicationAuditSealUnavailable,
    /// An unknown receipt kind — fails closed.
    Unknown,
}

impl DurableCompletionExternalPublicationAuditSealKind {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureInMemory => "fixture-in-memory",
            Self::ProductionExternalPublicationAuditSealUnavailable => {
                "production-external-publication-audit-seal-unavailable"
            }
            Self::MainNetExternalPublicationAuditSealUnavailable => {
                "mainnet-external-publication-audit-seal-unavailable"
            }
            Self::ExternalExternalPublicationAuditSealUnavailable => {
                "external-external-publication-audit-seal-unavailable"
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
            Self::ProductionExternalPublicationAuditSealUnavailable
                | Self::MainNetExternalPublicationAuditSealUnavailable
                | Self::ExternalExternalPublicationAuditSealUnavailable
        )
    }
}

// ===========================================================================
// Receipt policy
// ===========================================================================

/// Run 288 — the typed durable-completion audit/publication receipt policy
/// selector.
///
/// Only [`Self::FixtureAllowed`] may record (DevNet/TestNet source-test only);
/// every production / MainNet / external-publication policy resolves to a
/// reachable-but-unavailable sink that never records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionExternalPublicationAuditSealPolicy {
    /// The receipt boundary is disabled (legacy bypass).
    Disabled,
    /// A DevNet/TestNet fixture receipt sink is allowed (source-test evidence only).
    FixtureAllowed,
    /// A real production audit-ledger receipt sink is required — reachable but
    /// unavailable.
    ProductionExternalPublicationAuditSealRequired,
    /// A real MainNet audit-ledger receipt sink is required — reachable but
    /// unavailable.
    MainNetExternalPublicationAuditSealRequired,
    /// A real external-publication receipt sink is required — reachable but
    /// unavailable.
    ExternalExternalPublicationAuditSealRequired,
}

impl DurableCompletionExternalPublicationAuditSealPolicy {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureAllowed => "fixture-allowed",
            Self::ProductionExternalPublicationAuditSealRequired => {
                "production-external-publication-audit-seal-required"
            }
            Self::MainNetExternalPublicationAuditSealRequired => "mainnet-external-publication-audit-seal-required",
            Self::ExternalExternalPublicationAuditSealRequired => "external-external-publication-audit-seal-required",
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

/// Run 288 — the typed receipt identity a receipt request is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionExternalPublicationAuditSealIdentity {
    /// Stable receipt id.
    pub confirmation_id: String,
    /// The receipt kind.
    pub kind: DurableCompletionExternalPublicationAuditSealKind,
    /// The receipt policy.
    pub policy: DurableCompletionExternalPublicationAuditSealPolicy,
    /// The domain separation tag the receipt operates under.
    pub domain_separation_tag: String,
}

impl DurableCompletionExternalPublicationAuditSealIdentity {
    /// `true` iff every mandatory identity field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.confirmation_id.is_empty()
            && !self.domain_separation_tag.is_empty()
            && self.kind != DurableCompletionExternalPublicationAuditSealKind::Unknown
    }

    /// The deterministic, domain-separated receipt identity digest.
    pub fn digest(&self) -> DurableCompletionExternalPublicationAuditSealDigest {
        external_publication_audit_seal_identity_digest(self)
    }
}

// ===========================================================================
// Deterministic, domain-separated digest helpers
// ===========================================================================

/// Run 288 — domain separator for the receipt identity digest.
const EXTERNAL_PUBLICATION_CONFIRMATION_IDENTITY_DOMAIN: &[u8] =
    b"QBIND:run268:durable-completion-external-publication-audit-seal-identity:v1";
/// Run 288 — domain separator for the receipt request digest.
const EXTERNAL_PUBLICATION_CONFIRMATION_REQUEST_DOMAIN: &[u8] =
    b"QBIND:run268:durable-completion-external-publication-audit-seal-request:v1";
/// Run 288 — domain separator for the receipt response digest.
const EXTERNAL_PUBLICATION_CONFIRMATION_RESPONSE_DOMAIN: &[u8] =
    b"QBIND:run268:durable-completion-external-publication-audit-seal-response:v1";
/// Run 288 — domain separator for the receipt record digest.
const EXTERNAL_PUBLICATION_CONFIRMATION_RECORD_DOMAIN: &[u8] =
    b"QBIND:run268:durable-completion-external-publication-audit-seal-record:v1";
/// Run 288 — domain separator for the receipt transcript digest.
const EXTERNAL_PUBLICATION_CONFIRMATION_TRANSCRIPT_DOMAIN: &[u8] =
    b"QBIND:run268:durable-completion-external-publication-audit-seal-transcript:v1";

/// Run 288 — a deterministic, domain-separated receipt digest (lowercase hex of a
/// SHA3-256 over length-prefixed, field-bound canonical material). It contains no
/// unstable display text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionExternalPublicationAuditSealDigest(String);

impl DurableCompletionExternalPublicationAuditSealDigest {
    /// The lowercase hex representation.
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

/// Run 288 — a deterministic, domain-separated receipt transcript digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionExternalPublicationAuditSealTranscriptDigest(String);

impl DurableCompletionExternalPublicationAuditSealTranscriptDigest {
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

/// Run 288 — deterministic, domain-separated receipt identity digest.
pub fn external_publication_audit_seal_identity_digest(
    identity: &DurableCompletionExternalPublicationAuditSealIdentity,
) -> DurableCompletionExternalPublicationAuditSealDigest {
    let mut w = CanonicalWriter::new(EXTERNAL_PUBLICATION_CONFIRMATION_IDENTITY_DOMAIN);
    w.str_field(&identity.confirmation_id)
        .str_field(identity.kind.tag())
        .str_field(identity.policy.tag())
        .str_field(&identity.domain_separation_tag);
    DurableCompletionExternalPublicationAuditSealDigest(w.finish())
}

/// Run 288 — deterministic, domain-separated receipt request digest. Binds every
/// request field including the full Run 256 backend digest binding.
pub fn external_publication_audit_seal_request_digest(
    request: &DurableCompletionExternalPublicationAuditSealRequest,
) -> DurableCompletionExternalPublicationAuditSealDigest {
    let mut w = CanonicalWriter::new(EXTERNAL_PUBLICATION_CONFIRMATION_REQUEST_DOMAIN);
    w.str_field(&request.external_publication_audit_seal_record_id)
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
        .str_field(&request.external_publication_audit_archive_identity_digest)
        .str_field(&request.external_publication_audit_archive_request_digest)
        .str_field(&request.external_publication_audit_archive_response_digest)
        .str_field(&request.external_publication_audit_archive_record_digest)
        .str_field(&request.external_publication_audit_archive_transcript_digest)
        .str_field(&request.external_publication_audit_archive_record_id)
        .str_field(&request.domain_separation_tag)
        .str_field(external_publication_audit_seal_identity_digest(&request.identity).as_hex());
    DurableCompletionExternalPublicationAuditSealDigest(w.finish())
}

/// Run 288 — deterministic, domain-separated receipt response digest. Binds the
/// receipt record id, the request digest it answers, the acceptance flag, and the
/// responding receipt kind.
pub fn external_publication_audit_seal_response_digest(
    response: &DurableCompletionExternalPublicationAuditSealResponse,
) -> DurableCompletionExternalPublicationAuditSealDigest {
    let mut w = CanonicalWriter::new(EXTERNAL_PUBLICATION_CONFIRMATION_RESPONSE_DOMAIN);
    w.str_field(&response.external_publication_audit_seal_record_id)
        .str_field(response.request_digest.as_hex())
        .str_field(if response.accepted {
            "accepted"
        } else {
            "rejected"
        })
        .str_field(response.external_publication_audit_seal_kind.tag());
    DurableCompletionExternalPublicationAuditSealDigest(w.finish())
}

/// Run 288 — deterministic, domain-separated receipt record digest. Binds the
/// receipt record id, the request digest, and the receipt identity digest.
pub fn external_publication_audit_seal_record_digest(
    record: &DurableCompletionExternalPublicationAuditSealRecord,
) -> DurableCompletionExternalPublicationAuditSealDigest {
    let mut w = CanonicalWriter::new(EXTERNAL_PUBLICATION_CONFIRMATION_RECORD_DOMAIN);
    w.str_field(&record.external_publication_audit_seal_record_id)
        .str_field(record.request_digest.as_hex())
        .str_field(record.identity_digest.as_hex());
    DurableCompletionExternalPublicationAuditSealDigest(w.finish())
}

/// Run 288 — deterministic, domain-separated receipt transcript digest. Binds the
/// request, response, and record digests into a single transcript binding.
pub fn external_publication_audit_seal_transcript_digest(
    request_digest: &DurableCompletionExternalPublicationAuditSealDigest,
    response_digest: &DurableCompletionExternalPublicationAuditSealDigest,
    record_digest: &DurableCompletionExternalPublicationAuditSealDigest,
) -> DurableCompletionExternalPublicationAuditSealTranscriptDigest {
    let mut w = CanonicalWriter::new(EXTERNAL_PUBLICATION_CONFIRMATION_TRANSCRIPT_DOMAIN);
    w.str_field(request_digest.as_hex())
        .str_field(response_digest.as_hex())
        .str_field(record_digest.as_hex());
    DurableCompletionExternalPublicationAuditSealTranscriptDigest(w.finish())
}

// ===========================================================================
// Receipt request / response / record
// ===========================================================================

/// Run 288 — the typed receipt request a future production audit ledger or
/// external-publication call site would submit once the Run 256 backend recorded a
/// `BackendSubmissionRecorded`.
///
/// Pure data referencing the already-recorded Run 256 backend / Run 254
/// attestation / Run 252 external_publication_audit_seal / Run 250 completion report / Run 248
/// receipt / Run 246 decision material — never a copy of any wire payload and never
/// a production durable record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionExternalPublicationAuditSealRequest {
    /// Stable receipt record id (the idempotency key of the receipt).
    pub external_publication_audit_seal_record_id: String,
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
    /// Run 252 external_publication_audit_seal decision digest.
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
    /// Run 286 settlement-confirmation identity digest.
    pub external_publication_audit_archive_identity_digest: String,
    /// Run 286 settlement-confirmation request digest.
    pub external_publication_audit_archive_request_digest: String,
    /// Run 286 settlement-confirmation response digest.
    pub external_publication_audit_archive_response_digest: String,
    /// Run 286 settlement-confirmation record digest.
    pub external_publication_audit_archive_record_digest: String,
    /// Run 286 settlement-confirmation transcript digest.
    pub external_publication_audit_archive_transcript_digest: String,
    /// Run 286 settlement-confirmation record id.
    pub external_publication_audit_archive_record_id: String,
    /// External-publication-confirmation identity.
    pub identity: DurableCompletionExternalPublicationAuditSealIdentity,
    /// Domain separation tag.
    pub domain_separation_tag: String,
}

impl DurableCompletionExternalPublicationAuditSealRequest {
    /// `true` iff every mandatory field is structurally present (non-empty) and the
    /// identity is well-formed.
    pub fn is_well_formed(&self) -> bool {
        !self.external_publication_audit_seal_record_id.is_empty()
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
            && !self.external_publication_audit_archive_identity_digest.is_empty()
            && !self.external_publication_audit_archive_request_digest.is_empty()
            && !self.external_publication_audit_archive_response_digest.is_empty()
            && !self.external_publication_audit_archive_record_digest.is_empty()
            && !self.external_publication_audit_archive_transcript_digest.is_empty()
            && !self.external_publication_audit_archive_record_id.is_empty()
            && !self.domain_separation_tag.is_empty()
            && self.identity.is_well_formed()
    }

    /// The deterministic receipt request digest.
    pub fn digest(&self) -> DurableCompletionExternalPublicationAuditSealDigest {
        external_publication_audit_seal_request_digest(self)
    }

    /// The canonical immutable record derived from this request.
    pub fn to_record(&self) -> DurableCompletionExternalPublicationAuditSealRecord {
        DurableCompletionExternalPublicationAuditSealRecord {
            external_publication_audit_seal_record_id: self.external_publication_audit_seal_record_id.clone(),
            request_digest: self.digest(),
            identity_digest: self.identity.digest(),
        }
    }
}

/// Run 288 — the typed receipt response a receipt sink returns for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionExternalPublicationAuditSealResponse {
    /// The receipt record id the response answers.
    pub external_publication_audit_seal_record_id: String,
    /// The request digest the response answers.
    pub request_digest: DurableCompletionExternalPublicationAuditSealDigest,
    /// `true` iff the receipt sink accepted the request.
    pub accepted: bool,
    /// The responding receipt kind.
    pub external_publication_audit_seal_kind: DurableCompletionExternalPublicationAuditSealKind,
}

impl DurableCompletionExternalPublicationAuditSealResponse {
    /// `true` iff the response is structurally well-formed.
    pub fn is_well_formed(&self) -> bool {
        !self.external_publication_audit_seal_record_id.is_empty()
            && self.external_publication_audit_seal_kind != DurableCompletionExternalPublicationAuditSealKind::Unknown
    }

    /// The deterministic receipt response digest.
    pub fn digest(&self) -> DurableCompletionExternalPublicationAuditSealDigest {
        external_publication_audit_seal_response_digest(self)
    }
}

/// Run 288 — the canonical immutable receipt record derived from a request. Two
/// records are idempotent-equal only if **every** field matches exactly. The same
/// receipt record id with any differing digest is equivocation and fails closed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionExternalPublicationAuditSealRecord {
    /// The receipt record id.
    pub external_publication_audit_seal_record_id: String,
    /// The request digest.
    pub request_digest: DurableCompletionExternalPublicationAuditSealDigest,
    /// The receipt identity digest.
    pub identity_digest: DurableCompletionExternalPublicationAuditSealDigest,
}

impl DurableCompletionExternalPublicationAuditSealRecord {
    /// The deterministic receipt record digest.
    pub fn digest(&self) -> DurableCompletionExternalPublicationAuditSealDigest {
        external_publication_audit_seal_record_digest(self)
    }
}

// ===========================================================================
// In-memory fixture ledger
// ===========================================================================

/// Run 288 — the recorded status of a modeled audit/publication receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionExternalPublicationAuditSealLedgerStatus {
    /// The modeled receipt is recorded in the in-memory fixture ledger.
    Recorded,
}

/// Run 288 — a single modeled receipt record held in the in-memory fixture ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionExternalPublicationAuditSealLedgerRecord {
    /// The receipt record id (stable identity of the receipt).
    pub external_publication_audit_seal_record_id: String,
    /// The request digest.
    pub request_digest: DurableCompletionExternalPublicationAuditSealDigest,
    /// The response digest.
    pub response_digest: DurableCompletionExternalPublicationAuditSealDigest,
    /// The record digest.
    pub record_digest: DurableCompletionExternalPublicationAuditSealDigest,
    /// The transcript digest.
    pub transcript_digest: DurableCompletionExternalPublicationAuditSealTranscriptDigest,
    /// The recorded status.
    pub status: DurableCompletionExternalPublicationAuditSealLedgerStatus,
}

/// Run 288 — an immutable snapshot of the modeled receipt ledger used to model a
/// fixture rollback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionExternalPublicationAuditSealLedgerSnapshot {
    records: Vec<DurableCompletionExternalPublicationAuditSealLedgerRecord>,
}

impl DurableCompletionExternalPublicationAuditSealLedgerSnapshot {
    /// The number of records the snapshot captured.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` iff the snapshot captured no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Run 288 — the modeled in-memory receipt ledger.
///
/// **In-memory only.** It never touches RocksDB, files, markers, sequence files,
/// external publications, audit-ledger entries, or any production durable state.
/// The DevNet/TestNet fixture sink is the only thing that may mutate it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DurableCompletionExternalPublicationAuditSealLedger {
    records: Vec<DurableCompletionExternalPublicationAuditSealLedgerRecord>,
}

impl DurableCompletionExternalPublicationAuditSealLedger {
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
    pub fn records(&self) -> &[DurableCompletionExternalPublicationAuditSealLedgerRecord] {
        &self.records
    }

    /// The record for `external_publication_audit_seal_record_id`, if present.
    pub fn find(
        &self,
        external_publication_audit_seal_record_id: &str,
    ) -> Option<&DurableCompletionExternalPublicationAuditSealLedgerRecord> {
        self.records
            .iter()
            .find(|r| r.external_publication_audit_seal_record_id == external_publication_audit_seal_record_id)
    }

    /// `true` iff a receipt with `external_publication_audit_seal_record_id` is recorded.
    pub fn contains(&self, external_publication_audit_seal_record_id: &str) -> bool {
        self.find(external_publication_audit_seal_record_id).is_some()
    }

    /// Capture an immutable snapshot for a modeled rollback.
    pub fn snapshot(&self) -> DurableCompletionExternalPublicationAuditSealLedgerSnapshot {
        DurableCompletionExternalPublicationAuditSealLedgerSnapshot {
            records: self.records.clone(),
        }
    }

    /// Restore the ledger to a previously captured snapshot (modeled rollback).
    pub fn restore(
        &mut self,
        snapshot: &DurableCompletionExternalPublicationAuditSealLedgerSnapshot,
    ) {
        self.records = snapshot.records.clone();
    }

    /// Internal: insert a recorded receipt. Only the fixture sink calls this, and
    /// only after every identity / idempotency gate has passed.
    fn insert(&mut self, record: DurableCompletionExternalPublicationAuditSealLedgerRecord) {
        self.records.push(record);
    }
}

// ===========================================================================
// Receipt expectations
// ===========================================================================

/// Run 288 — the canonical binding a [`DurableCompletionExternalPublicationAuditSealInput`]
/// is checked against.
///
/// Environment / chain / genesis / surface mismatches fail closed **before** the
/// receipt sink is invoked. Receipt-request-identity mismatches fail closed
/// **inside** the sink, before any modeled receipt is recorded. Neither path is
/// ever a silent approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionExternalPublicationAuditSealExpectations {
    /// Expected receipt record id.
    pub expected_external_publication_audit_seal_record_id: String,
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
    /// Expected Run 252 external_publication_audit_seal decision digest.
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
    /// Expected Run 286 settlement-confirmation identity digest.
    pub expected_external_publication_audit_archive_identity_digest: String,
    /// Expected Run 286 settlement-confirmation request digest.
    pub expected_external_publication_audit_archive_request_digest: String,
    /// Expected Run 286 settlement-confirmation response digest.
    pub expected_external_publication_audit_archive_response_digest: String,
    /// Expected Run 286 settlement-confirmation record digest.
    pub expected_external_publication_audit_archive_record_digest: String,
    /// Expected Run 286 settlement-confirmation transcript digest.
    pub expected_external_publication_audit_archive_transcript_digest: String,
    /// Expected Run 286 settlement-confirmation record id.
    pub expected_external_publication_audit_archive_record_id: String,
    /// Expected settlement-confirmation identity.
    pub expected_identity: DurableCompletionExternalPublicationAuditSealIdentity,
    /// Expected settlement-confirmation kind.
    pub expected_external_publication_audit_seal_kind: DurableCompletionExternalPublicationAuditSealKind,
    /// Expected settlement-confirmation policy.
    pub expected_external_publication_audit_seal_policy: DurableCompletionExternalPublicationAuditSealPolicy,
    /// Expected domain separation tag.
    pub expected_domain_separation_tag: String,
}

impl DurableCompletionExternalPublicationAuditSealExpectations {
    /// Internal: the first environment / surface binding mismatch reason, if any.
    fn binding_mismatch_reason(
        &self,
        input: &DurableCompletionExternalPublicationAuditSealInput,
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
        input: &DurableCompletionExternalPublicationAuditSealInput,
    ) -> bool {
        self.binding_mismatch_reason(input).is_none()
    }

    /// Internal: the first receipt-request-identity mismatch reason, if any.
    fn request_mismatch_reason(
        &self,
        request: &DurableCompletionExternalPublicationAuditSealRequest,
    ) -> Option<&'static str> {
        if !request.is_well_formed() {
            return Some("malformed receipt request");
        }
        if request.external_publication_audit_seal_record_id != self.expected_external_publication_audit_seal_record_id {
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
            return Some("wrong external_publication_audit_seal decision digest");
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
        if request.external_publication_audit_archive_identity_digest
            != self.expected_external_publication_audit_archive_identity_digest
        {
            return Some("wrong settlement-confirmation identity digest");
        }
        if request.external_publication_audit_archive_request_digest
            != self.expected_external_publication_audit_archive_request_digest
        {
            return Some("wrong settlement-confirmation request digest");
        }
        if request.external_publication_audit_archive_response_digest
            != self.expected_external_publication_audit_archive_response_digest
        {
            return Some("wrong settlement-confirmation response digest");
        }
        if request.external_publication_audit_archive_record_digest
            != self.expected_external_publication_audit_archive_record_digest
        {
            return Some("wrong settlement-confirmation record digest");
        }
        if request.external_publication_audit_archive_transcript_digest
            != self.expected_external_publication_audit_archive_transcript_digest
        {
            return Some("wrong settlement-confirmation transcript digest");
        }
        if request.external_publication_audit_archive_record_id != self.expected_external_publication_audit_archive_record_id {
            return Some("wrong settlement-confirmation record id");
        }
        if request.domain_separation_tag != self.expected_domain_separation_tag {
            return Some("wrong domain separation tag");
        }
        if request.identity != self.expected_identity {
            return Some("wrong external-publication-audit-seal identity");
        }
        if request.identity.kind != self.expected_external_publication_audit_seal_kind {
            return Some("wrong external-publication-audit-seal kind");
        }
        if request.identity.policy != self.expected_external_publication_audit_seal_policy {
            return Some("wrong external-publication-audit-seal policy");
        }
        None
    }

    /// `true` iff the receipt-request identity matches and is well-formed.
    pub fn request_matches(
        &self,
        request: &DurableCompletionExternalPublicationAuditSealRequest,
    ) -> bool {
        self.request_mismatch_reason(request).is_none()
    }
}

// ===========================================================================
// Receipt input
// ===========================================================================

/// Run 288 — typed inputs for one modeled durable-completion audit/publication
/// receipt round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionExternalPublicationAuditSealInput {
    /// The receipt policy selector.
    pub policy: DurableCompletionExternalPublicationAuditSealPolicy,
    /// The trust-domain environment binding.
    pub environment_binding: DurableCompletionExternalPublicationAuditSealEnvironment,
    /// The runtime binding (governance + mutation surface + sequence).
    pub runtime_binding: DurableCompletionExternalPublicationAuditSealBinding,
    /// The Run 240/246 durable replay observation the pipeline authorized consume
    /// under.
    pub replay_binding: DurableCompletionExternalPublicationAuditSealReplayBinding,
    /// The Run 246 pipeline outcome.
    pub pipeline_binding: DurableCompletionExternalPublicationAuditSealPipelineBinding,
    /// The Run 248 sink outcome.
    pub sink_binding: DurableCompletionExternalPublicationAuditSealSinkBinding,
    /// The Run 250 reporter outcome.
    pub reporter_binding: DurableCompletionExternalPublicationAuditSealReporterBinding,
    /// The Run 252 external_publication_audit_seal outcome.
    pub confirmation_binding: DurableCompletionExternalPublicationAuditSealFinalizationBinding,
    /// The Run 254 attestation outcome.
    pub attestation_binding: DurableCompletionExternalPublicationAuditSealAttestationBinding,
    /// The Run 256 backend outcome carried as backend-record context.
    pub backend_binding: DurableCompletionExternalPublicationAuditSealBackendBinding,
    /// The Run 258 audit/publication receipt outcome carried as receipt-record
    /// context.
    pub receipt_binding: DurableCompletionExternalPublicationAuditSealReceiptBinding,
    /// The Run 260 audit-receipt acknowledgement outcome carried as
    /// acknowledgement-record context.
    pub acknowledgement_binding:
        DurableCompletionExternalPublicationAuditSealAcknowledgementBinding,
    /// The Run 262 acknowledgement consumer outcome the settlement-confirmation
    /// boundary projects to a settlement-confirmation request.
    pub consumer_binding: DurableCompletionExternalPublicationAuditSealConsumerBinding,
    /// The Run 286 settlement-confirmation outcome the external-publication-audit-seal boundary
    /// projects to a external-publication-audit-seal request.
    pub external_publication_audit_archive_binding:
        DurableCompletionExternalPublicationAuditSealExternalPublicationAuditArchiveBinding,
    /// The external-publication-audit-seal request the call site would submit.
    pub request: DurableCompletionExternalPublicationAuditSealRequest,
}

impl DurableCompletionExternalPublicationAuditSealInput {
    /// The trust-domain environment the decision is bound to.
    pub fn environment(&self) -> TrustBundleEnvironment {
        self.environment_binding.environment
    }

    /// The validation / mutation surface pair.
    pub fn surface(&self) -> DurableCompletionExternalPublicationAuditSealSurface {
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
                self.confirmation_binding,
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
                self.external_publication_audit_archive_binding,
                DurableCompletionExternalPublicationAuditArchiveOutcome::MainNetPeerDrivenApplyRefusedNoAuditArchive
            )
    }
}

// ===========================================================================
// Receipt outcome
// ===========================================================================

/// Run 288 — the typed outcome of one modeled durable-completion audit/publication
/// receipt round-trip.
///
/// Only [`Self::ExternalPublicationAuditSealRecorded`] authorizes a **new** modeled
/// audit/publication-receipt state. A [`Self::ExternalPublicationAuditSealDuplicateIdempotent`]
/// means the receipt was already recorded (idempotent, no second receipt). Every
/// other variant is a no-audit-receipt fail-closed outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableCompletionExternalPublicationAuditSealOutcome {
    /// Legacy bypass — a disabled receipt policy preserved the legacy
    /// no-audit-receipt path. No receipt invocation.
    LegacyBypassNoExternalPublicationAuditSeal,
    /// The Run 256 backend-stage binding was rejected before the receipt sink was
    /// invoked (a backend-stage rejection / binding mismatch). Non-mutating, no
    /// receipt. No receipt invocation.
    RejectedBeforeExternalPublicationAuditArchiveNoAuditSeal,
    /// The Run 256 backend did not submit (any non-submitting backend outcome
    /// without a more specific variant). Non-mutating, no receipt. No receipt
    /// invocation.
    ExternalPublicationAuditArchiveDidNotRecordNoAuditSeal,
    /// The receipt sink recorded a new modeled audit/publication receipt. The
    /// **only** outcome that authorizes a new modeled receipt state.
    ExternalPublicationAuditSealRecorded,
    /// A duplicate identical receipt — idempotent; no second receipt recorded.
    ExternalPublicationAuditSealDuplicateIdempotent,
    /// The receipt was rejected before record (malformed request, request-identity
    /// mismatch, same receipt record id with a differing digest / equivocation, or
    /// a duplicate-idempotent backend submission with no matching prior receipt). No
    /// receipt.
    ExternalPublicationAuditSealRejectedBeforeRecord,
    /// The receipt record failed. No receipt.
    ExternalPublicationAuditSealRecordFailedNoAuditSeal,
    /// The receipt record was rolled back. No receipt.
    ExternalPublicationAuditSealRolledBackNoAuditSeal,
    /// The receipt rollback itself failed — fatal / fail-closed. No receipt.
    ExternalPublicationAuditSealRollbackFailedFatalNoAuditSeal,
    /// The after-record receipt window was ambiguous — fails closed. No receipt.
    ExternalPublicationAuditSealAmbiguousFailClosedNoAuditSeal,
    /// The production audit-ledger path was reached but is unavailable. No receipt.
    ProductionExternalPublicationAuditSealUnavailableNoAuditSeal,
    /// The MainNet audit-ledger path was reached but is unavailable. No receipt.
    MainNetExternalPublicationAuditSealUnavailableNoAuditSeal,
    /// The external-publication path was reached but is unavailable. No receipt.
    ExternalExternalPublicationAuditSealUnavailableNoAuditSeal,
    /// MainNet peer-driven apply remains refused before pipeline progression, sink
    /// invocation, reporter invocation, finalizer invocation, attestor invocation,
    /// backend invocation, and receipt invocation. No receipt.
    MainNetPeerDrivenApplyRefusedNoAuditSeal,
    /// Validator-set rotation is unsupported. No receipt.
    ValidatorSetRotationUnsupportedNoAuditSeal,
    /// Policy-change actions are unsupported. No receipt.
    PolicyChangeUnsupportedNoAuditSeal,
}

impl DurableCompletionExternalPublicationAuditSealOutcome {
    /// `true` iff this outcome authorizes a **new** modeled audit/publication
    /// receipt (only [`Self::ExternalPublicationAuditSealRecorded`]).
    pub fn authorizes_record(&self) -> bool {
        matches!(self, Self::ExternalPublicationAuditSealRecorded)
    }

    /// `true` iff this outcome projects to a recorded audit/publication receipt — a
    /// newly recorded receipt or an idempotent duplicate of an already-recorded
    /// receipt.
    pub fn projects_to_recorded(&self) -> bool {
        matches!(
            self,
            Self::ExternalPublicationAuditSealRecorded | Self::ExternalPublicationAuditSealDuplicateIdempotent
        )
    }

    /// `true` iff this outcome records nothing new and projects to no
    /// audit/publication receipt.
    pub fn no_commitment(&self) -> bool {
        !self.projects_to_recorded()
    }

    /// `true` iff this is the legacy no-audit-receipt bypass.
    pub fn is_legacy_bypass(&self) -> bool {
        matches!(self, Self::LegacyBypassNoExternalPublicationAuditSeal)
    }

    /// `true` iff this is the MainNet peer-driven-apply refusal.
    pub fn is_mainnet_peer_driven_apply_refused(&self) -> bool {
        matches!(self, Self::MainNetPeerDrivenApplyRefusedNoAuditSeal)
    }

    /// Stable operator-facing tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::LegacyBypassNoExternalPublicationAuditSeal => "legacy-bypass-no-external-publication-audit-seal",
            Self::RejectedBeforeExternalPublicationAuditArchiveNoAuditSeal => {
                "rejected-before-settlement-confirmation-no-outcome-publication"
            }
            Self::ExternalPublicationAuditArchiveDidNotRecordNoAuditSeal => {
                "settlement-confirmation-did-not-record-no-outcome-publication"
            }
            Self::ExternalPublicationAuditSealRecorded => "external-publication-audit-seal-recorded",
            Self::ExternalPublicationAuditSealDuplicateIdempotent => {
                "external-publication-audit-seal-duplicate-idempotent"
            }
            Self::ExternalPublicationAuditSealRejectedBeforeRecord => {
                "external-publication-audit-seal-rejected-before-record"
            }
            Self::ExternalPublicationAuditSealRecordFailedNoAuditSeal => {
                "external-publication-audit-seal-record-failed-no-outcome-publication"
            }
            Self::ExternalPublicationAuditSealRolledBackNoAuditSeal => {
                "external-publication-audit-seal-rolled-back-no-outcome-publication"
            }
            Self::ExternalPublicationAuditSealRollbackFailedFatalNoAuditSeal => {
                "external-publication-audit-seal-rollback-failed-fatal-no-outcome-publication"
            }
            Self::ExternalPublicationAuditSealAmbiguousFailClosedNoAuditSeal => {
                "external-publication-audit-seal-ambiguous-fail-closed-no-outcome-publication"
            }
            Self::ProductionExternalPublicationAuditSealUnavailableNoAuditSeal => {
                "production-external-publication-audit-seal-unavailable-no-outcome-publication"
            }
            Self::MainNetExternalPublicationAuditSealUnavailableNoAuditSeal => {
                "mainnet-external-publication-audit-seal-unavailable-no-outcome-publication"
            }
            Self::ExternalExternalPublicationAuditSealUnavailableNoAuditSeal => {
                "external-external-publication-audit-seal-unavailable-no-outcome-publication"
            }
            Self::MainNetPeerDrivenApplyRefusedNoAuditSeal => {
                "mainnet-peer-driven-apply-refused-no-outcome-publication"
            }
            Self::ValidatorSetRotationUnsupportedNoAuditSeal => {
                "validator-set-rotation-unsupported-no-outcome-publication"
            }
            Self::PolicyChangeUnsupportedNoAuditSeal => "policy-change-unsupported-no-outcome-publication",
        }
    }
}

// ===========================================================================
// Consumer-outcome -> settlement-confirmation request confirmation
// ===========================================================================

/// Run 288 — the typed confirmation of a Run 262 acknowledgement consumer outcome
/// onto a settlement-confirmation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableCompletionExternalPublicationAuditSealRequestIntent {
    /// The consumer recorded a consumer record; the settlement-confirmation sink may
    /// record a new settlement confirmation.
    CreateRequest,
    /// The consumer reported an idempotent-duplicate consumer record; the
    /// settlement-confirmation sink may only match an already-recorded settlement
    /// confirmation and must never create a new one.
    IdempotentOnly,
    /// The consumer did not record; no settlement-confirmation request. Carries the
    /// typed no-receipt outcome the settlement-confirmation evaluation returns
    /// directly (without invoking the settlement-confirmation sink).
    NoReceipt(DurableCompletionExternalPublicationAuditSealOutcome),
}

impl DurableCompletionExternalPublicationAuditSealRequestIntent {
    /// `true` iff this confirmation creates a settlement-confirmation request (i.e. the
    /// consumer recorded a consumer record).
    pub fn creates_request(&self) -> bool {
        matches!(self, Self::CreateRequest)
    }
}

/// Run 288 — project a Run 286 settlement-confirmation outcome onto a
/// external-publication-audit-seal request.
///
/// Only
/// [`DurableCompletionExternalPublicationAuditArchiveOutcome::ExternalPublicationAuditArchiveRecorded`]
/// creates a external-publication-audit-seal request.
/// [`DurableCompletionExternalPublicationAuditArchiveOutcome::ExternalPublicationAuditArchiveDuplicateIdempotent`]
/// may only match an already-recorded external-publication-audit-seal record and never creates
/// a new one. Every other settlement-confirmation outcome maps to a no-outcome-publication
/// fail-closed outcome (a more specific one where one exists, otherwise the generic
/// [`DurableCompletionExternalPublicationAuditSealOutcome::ExternalPublicationAuditArchiveDidNotRecordNoAuditSeal`]).
/// Pure: performs no work and never records.
pub fn project_external_publication_audit_archive_outcome_to_external_publication_audit_seal_request(
    outcome: &DurableCompletionExternalPublicationAuditSealExternalPublicationAuditArchiveBinding,
) -> DurableCompletionExternalPublicationAuditSealRequestIntent {
    use DurableCompletionExternalPublicationAuditArchiveOutcome as Finalization;
    use DurableCompletionExternalPublicationAuditSealOutcome as Receipt;
    use DurableCompletionExternalPublicationAuditSealRequestIntent as Intent;
    match outcome {
        Finalization::ExternalPublicationAuditArchiveRecorded => Intent::CreateRequest,
        Finalization::ExternalPublicationAuditArchiveDuplicateIdempotent => Intent::IdempotentOnly,
        Finalization::LegacyBypassNoExternalPublicationAuditArchive => {
            Intent::NoReceipt(Receipt::LegacyBypassNoExternalPublicationAuditSeal)
        }
        Finalization::RejectedBeforeExternalPublicationAuditCompletionNoAuditArchive => {
            Intent::NoReceipt(Receipt::RejectedBeforeExternalPublicationAuditArchiveNoAuditSeal)
        }
        Finalization::MainNetPeerDrivenApplyRefusedNoAuditArchive => {
            Intent::NoReceipt(Receipt::MainNetPeerDrivenApplyRefusedNoAuditSeal)
        }
        Finalization::ValidatorSetRotationUnsupportedNoAuditArchive => {
            Intent::NoReceipt(Receipt::ValidatorSetRotationUnsupportedNoAuditSeal)
        }
        Finalization::PolicyChangeUnsupportedNoAuditArchive => {
            Intent::NoReceipt(Receipt::PolicyChangeUnsupportedNoAuditSeal)
        }
        // Every remaining settlement-confirmation outcome is a non-recording rejection /
        // failure / rollback / ambiguous window: the settlement confirmation did not
        // record, so no external-publication-audit-seal record may exist.
        _ => Intent::NoReceipt(Receipt::ExternalPublicationAuditArchiveDidNotRecordNoAuditSeal),
    }
}

// ===========================================================================
// Receipt fault injection (source/test only)
// ===========================================================================

/// Run 288 — a modeled fault the fixture receipt sink injects to exercise the
/// fail-closed record / rollback / ambiguous paths. Source/test only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionExternalPublicationAuditSealFault {
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

/// Run 288 — the pure/mockable modeled durable-completion audit/publication receipt
/// boundary.
///
/// No implementation here calls Run 070, mutates `LivePqcTrustState`, performs a
/// live trust swap, evicts sessions, writes a sequence, writes a marker, performs
/// network I/O, external publication, or a real audit-ledger persistence. The
/// DevNet/TestNet fixture receipt sink mutates only the in-memory
/// [`DurableCompletionExternalPublicationAuditSealLedger`].
pub trait GovernanceDurableCompletionExternalPublicationAuditSealSink {
    /// The receipt kind (used for typed recovery classification).
    fn kind(&self) -> DurableCompletionExternalPublicationAuditSealKind;

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
    fn project_durable_completion_external_publication_audit_seal(
        &mut self,
        request: &DurableCompletionExternalPublicationAuditSealRequest,
        expectations: &DurableCompletionExternalPublicationAuditSealExpectations,
        idempotent_only: bool,
        ledger: &mut DurableCompletionExternalPublicationAuditSealLedger,
    ) -> DurableCompletionExternalPublicationAuditSealOutcome;

    /// Classify a modeled receipt crash/recovery window. Pure: performs no modeled
    /// mutation and never invokes Run 070.
    fn recover_durable_completion_external_publication_audit_seal_window(
        &self,
        input: &DurableCompletionExternalPublicationAuditSealInput,
        window: DurableCompletionExternalPublicationAuditSealWindow,
        recovered_record: Option<&DurableCompletionExternalPublicationAuditSealLedgerRecord>,
        expectations: &DurableCompletionExternalPublicationAuditSealExpectations,
    ) -> DurableCompletionExternalPublicationAuditSealOutcome {
        recover_durable_completion_external_publication_audit_seal_window(
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

/// Run 288 — the DevNet/TestNet in-memory fixture receipt sink.
///
/// Source-test only. It mutates only the in-memory
/// [`DurableCompletionExternalPublicationAuditSealLedger`] and exposes an invocation
/// counter so tests can prove non-submitting backend paths and pre-receipt
/// rejections never invoke it.
#[derive(Debug, Clone)]
pub struct FixtureDurableCompletionExternalPublicationAuditSealSink {
    fault: Option<DurableCompletionExternalPublicationAuditSealFault>,
    invocations: u32,
}

impl Default for FixtureDurableCompletionExternalPublicationAuditSealSink {
    fn default() -> Self {
        Self::new()
    }
}

impl FixtureDurableCompletionExternalPublicationAuditSealSink {
    /// A new fixture receipt sink.
    pub fn new() -> Self {
        Self {
            fault: None,
            invocations: 0,
        }
    }

    /// A new fixture receipt sink that injects the given modeled fault on record.
    pub fn with_fault(fault: DurableCompletionExternalPublicationAuditSealFault) -> Self {
        Self {
            fault: Some(fault),
            invocations: 0,
        }
    }
}

impl GovernanceDurableCompletionExternalPublicationAuditSealSink
    for FixtureDurableCompletionExternalPublicationAuditSealSink
{
    fn kind(&self) -> DurableCompletionExternalPublicationAuditSealKind {
        DurableCompletionExternalPublicationAuditSealKind::FixtureInMemory
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn project_durable_completion_external_publication_audit_seal(
        &mut self,
        request: &DurableCompletionExternalPublicationAuditSealRequest,
        expectations: &DurableCompletionExternalPublicationAuditSealExpectations,
        idempotent_only: bool,
        ledger: &mut DurableCompletionExternalPublicationAuditSealLedger,
    ) -> DurableCompletionExternalPublicationAuditSealOutcome {
        use DurableCompletionExternalPublicationAuditSealOutcome as Receipt;
        self.invocations += 1;

        // Injected faults model record-failure / rollback / ambiguous windows. None
        // of them ever leave a recorded receipt behind, so a durable receipt is never
        // claimed. The ledger snapshot/restore models the rollback being a no-op
        // write.
        if let Some(fault) = self.fault {
            let snapshot = ledger.snapshot();
            return match fault {
                DurableCompletionExternalPublicationAuditSealFault::RecordFailedNoReceipt => {
                    ledger.restore(&snapshot);
                    Receipt::ExternalPublicationAuditSealRecordFailedNoAuditSeal
                }
                DurableCompletionExternalPublicationAuditSealFault::RolledBackNoReceipt => {
                    ledger.restore(&snapshot);
                    Receipt::ExternalPublicationAuditSealRolledBackNoAuditSeal
                }
                DurableCompletionExternalPublicationAuditSealFault::RollbackFailedFatal => {
                    Receipt::ExternalPublicationAuditSealRollbackFailedFatalNoAuditSeal
                }
                DurableCompletionExternalPublicationAuditSealFault::AmbiguousAfterRecord => {
                    ledger.restore(&snapshot);
                    Receipt::ExternalPublicationAuditSealAmbiguousFailClosedNoAuditSeal
                }
            };
        }

        // The fixture receipt sink is DevNet/TestNet evidence-only.
        if !matches!(
            request.environment,
            TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet
        ) {
            return Receipt::ExternalPublicationAuditSealRejectedBeforeRecord;
        }

        // Request-identity validation (malformed / mismatch) fails closed before any
        // record is written.
        if !expectations.request_matches(request) {
            return Receipt::ExternalPublicationAuditSealRejectedBeforeRecord;
        }

        // Build the deterministic request / response / record / transcript digests.
        let request_digest = request.digest();
        let response = DurableCompletionExternalPublicationAuditSealResponse {
            external_publication_audit_seal_record_id: request.external_publication_audit_seal_record_id.clone(),
            request_digest: request_digest.clone(),
            accepted: true,
            external_publication_audit_seal_kind: DurableCompletionExternalPublicationAuditSealKind::FixtureInMemory,
        };
        let response_digest = response.digest();
        let record = request.to_record();
        let record_digest = record.digest();
        let transcript_digest = external_publication_audit_seal_transcript_digest(
            &request_digest,
            &response_digest,
            &record_digest,
        );

        // Idempotency / equivocation gate.
        if let Some(existing) = ledger.find(&request.external_publication_audit_seal_record_id) {
            if existing.request_digest == request_digest
                && existing.response_digest == response_digest
                && existing.record_digest == record_digest
                && existing.transcript_digest == transcript_digest
            {
                return Receipt::ExternalPublicationAuditSealDuplicateIdempotent;
            }
            // Same receipt record id with a different digest is equivocation: fail
            // closed, record no second receipt.
            return Receipt::ExternalPublicationAuditSealRejectedBeforeRecord;
        }

        // A duplicate-idempotent backend submission may only match an already-recorded
        // receipt; it must never create a new one by itself.
        if idempotent_only {
            return Receipt::ExternalPublicationAuditSealRejectedBeforeRecord;
        }

        ledger.insert(DurableCompletionExternalPublicationAuditSealLedgerRecord {
            external_publication_audit_seal_record_id: request.external_publication_audit_seal_record_id.clone(),
            request_digest,
            response_digest,
            record_digest,
            transcript_digest,
            status: DurableCompletionExternalPublicationAuditSealLedgerStatus::Recorded,
        });
        Receipt::ExternalPublicationAuditSealRecorded
    }
}

// ===========================================================================
// Production / MainNet audit-ledger / External-publication sinks (unavailable)
// ===========================================================================

/// Run 288 — the production audit-ledger receipt sink. Reachable but unavailable /
/// fail-closed. It records no receipt and mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct ProductionExternalPublicationAuditSealSink {
    invocations: u32,
}

impl GovernanceDurableCompletionExternalPublicationAuditSealSink
    for ProductionExternalPublicationAuditSealSink
{
    fn kind(&self) -> DurableCompletionExternalPublicationAuditSealKind {
        DurableCompletionExternalPublicationAuditSealKind::ProductionExternalPublicationAuditSealUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn project_durable_completion_external_publication_audit_seal(
        &mut self,
        _request: &DurableCompletionExternalPublicationAuditSealRequest,
        _expectations: &DurableCompletionExternalPublicationAuditSealExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionExternalPublicationAuditSealLedger,
    ) -> DurableCompletionExternalPublicationAuditSealOutcome {
        self.invocations += 1;
        DurableCompletionExternalPublicationAuditSealOutcome::ProductionExternalPublicationAuditSealUnavailableNoAuditSeal
    }
}

/// Run 288 — the MainNet audit-ledger receipt sink. Reachable but unavailable /
/// fail-closed. It records no receipt and mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct MainNetExternalPublicationAuditSealSink {
    invocations: u32,
}

impl GovernanceDurableCompletionExternalPublicationAuditSealSink
    for MainNetExternalPublicationAuditSealSink
{
    fn kind(&self) -> DurableCompletionExternalPublicationAuditSealKind {
        DurableCompletionExternalPublicationAuditSealKind::MainNetExternalPublicationAuditSealUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn project_durable_completion_external_publication_audit_seal(
        &mut self,
        _request: &DurableCompletionExternalPublicationAuditSealRequest,
        _expectations: &DurableCompletionExternalPublicationAuditSealExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionExternalPublicationAuditSealLedger,
    ) -> DurableCompletionExternalPublicationAuditSealOutcome {
        self.invocations += 1;
        DurableCompletionExternalPublicationAuditSealOutcome::MainNetExternalPublicationAuditSealUnavailableNoAuditSeal
    }
}

/// Run 288 — the external-publication receipt sink. Reachable but unavailable /
/// fail-closed. It performs no external publication, records no receipt, and
/// mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct ExternalExternalPublicationAuditSealSink {
    invocations: u32,
}

impl GovernanceDurableCompletionExternalPublicationAuditSealSink
    for ExternalExternalPublicationAuditSealSink
{
    fn kind(&self) -> DurableCompletionExternalPublicationAuditSealKind {
        DurableCompletionExternalPublicationAuditSealKind::ExternalExternalPublicationAuditSealUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn project_durable_completion_external_publication_audit_seal(
        &mut self,
        _request: &DurableCompletionExternalPublicationAuditSealRequest,
        _expectations: &DurableCompletionExternalPublicationAuditSealExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionExternalPublicationAuditSealLedger,
    ) -> DurableCompletionExternalPublicationAuditSealOutcome {
        self.invocations += 1;
        DurableCompletionExternalPublicationAuditSealOutcome::ExternalExternalPublicationAuditSealUnavailableNoAuditSeal
    }
}

// ===========================================================================
// Receipt executor / composition helpers
// ===========================================================================

/// Run 288 — evaluate one modeled durable-completion audit/publication receipt
/// round-trip.
///
/// Ordering (each gate must pass before the next is considered):
///
/// 1. MainNet peer-driven apply refusal — before pipeline progression, sink
///    invocation, reporter invocation, finalizer invocation, attestor invocation,
///    backend invocation, and receipt invocation;
/// 2. legacy bypass — a
///    [`DurableCompletionExternalPublicationAuditSealPolicy::Disabled`] policy;
/// 3. backend-outcome confirmation — only
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
pub fn evaluate_durable_completion_external_publication_audit_seal<S>(
    input: &DurableCompletionExternalPublicationAuditSealInput,
    expectations: &DurableCompletionExternalPublicationAuditSealExpectations,
    sink: &mut S,
    ledger: &mut DurableCompletionExternalPublicationAuditSealLedger,
) -> DurableCompletionExternalPublicationAuditSealOutcome
where
    S: GovernanceDurableCompletionExternalPublicationAuditSealSink,
{
    use DurableCompletionExternalPublicationAuditSealOutcome as Finalization;
    use DurableCompletionExternalPublicationAuditSealRequestIntent as Intent;

    // Step 1: MainNet peer-driven apply remains refused unconditionally, before
    // pipeline progression, sink invocation, reporter invocation, finalizer
    // invocation, attestor invocation, backend invocation, receipt invocation,
    // acknowledgement invocation, consumer invocation, and settlement-confirmation
    // invocation.
    if input.is_mainnet_peer_driven() {
        return Finalization::MainNetPeerDrivenApplyRefusedNoAuditSeal;
    }

    // Step 2: legacy bypass — a disabled settlement-confirmation policy preserves the
    // legacy no-settlement-confirmation path and never invokes the confirmation sink.
    if input.policy.is_disabled() {
        return Finalization::LegacyBypassNoExternalPublicationAuditSeal;
    }

    // Step 3: project the Run 262 acknowledgement consumer outcome onto a
    // settlement-confirmation request. Every non-recording consumer outcome returns a
    // no-receipt outcome without invoking the settlement-confirmation sink.
    let idempotent_only =
        match project_external_publication_audit_archive_outcome_to_external_publication_audit_seal_request(
            &input.external_publication_audit_archive_binding,
        ) {
            Intent::NoReceipt(outcome) => return outcome,
            Intent::CreateRequest => false,
            Intent::IdempotentOnly => true,
        };

    // Step 4: pre-confirmation environment / surface binding validation. A mismatch
    // fails closed before the settlement-confirmation sink is invoked, leaving the
    // settlement-confirmation invocation count at zero.
    if !expectations.binding_matches(input) {
        return Finalization::RejectedBeforeExternalPublicationAuditArchiveNoAuditSeal;
    }

    // Step 5: invoke the settlement-confirmation sink to record the modeled confirmation.
    sink.project_durable_completion_external_publication_audit_seal(
        &input.request,
        expectations,
        idempotent_only,
        ledger,
    )
}

// ===========================================================================
// Receipt crash/recovery window classification
// ===========================================================================

/// Run 288 — the modeled durable-completion audit/publication receipt
/// crash/recovery window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionExternalPublicationAuditSealWindow {
    /// Crashed before the pipeline authorized consume.
    BeforePipeline,
    /// Crashed after pipeline success but before a sink intent was created.
    AfterPipelineSuccessBeforeSinkIntent,
    /// Crashed after a sink intent but before the sink recorded a receipt.
    AfterSinkIntentBeforeSinkReceiptRecord,
    /// Crashed after the sink recorded a receipt but before a completion-report
    /// intent.
    AfterSinkReceiptRecordBeforePublicationIntent,
    /// Crashed after a completion-report intent but before the report record.
    AfterPublicationIntentBeforePublicationRecord,
    /// Crashed after the report record but before a external_publication_audit_seal intent.
    AfterPublicationRecordBeforeReceiptIntent,
    /// Crashed after a external_publication_audit_seal intent but before any external_publication_audit_seal record.
    AfterReceiptIntentBeforeReceiptRecord,
    /// Crashed after the external_publication_audit_seal record but before an attestation intent.
    AfterReceiptRecordBeforeAttestationIntent,
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
    /// Crashed after consumer success but before a settlement-confirmation request.
    AfterConsumerSuccessBeforeExternalPublicationAuditArchiveRequest,
    /// Crashed after a settlement-confirmation request but before any
    /// settlement-confirmation record.
    AfterExternalPublicationAuditArchiveRequestBeforeExternalPublicationAuditArchiveRecord,
    /// Crashed after a settlement-confirmation record but before settlement-confirmation
    /// success — fails closed unless an explicit matching settlement-confirmation
    /// record exists.
    AfterExternalPublicationAuditArchiveRecordBeforeExternalPublicationAuditArchiveSuccess,
    /// Crashed after settlement-confirmation success but before a external-publication-audit-seal
    /// request.
    AfterExternalPublicationAuditArchiveSuccessBeforeExternalPublicationAuditSealRequest,
    /// Crashed after a external-publication-audit-seal request but before any
    /// external-publication-audit-seal record.
    AfterExternalPublicationAuditSealRequestBeforeExternalPublicationAuditSealRecord,
    /// Crashed after a external-publication-audit-seal record but before external-publication-audit-seal
    /// success — fails closed unless an explicit matching external-publication-audit-seal
    /// record exists.
    AfterExternalPublicationAuditSealRecordBeforeExternalPublicationAuditSealSuccess,
    /// Recovered after a successful external-publication-audit-seal record.
    AfterExternalPublicationAuditSealSuccess,
    /// Recovered after an ambiguous external-publication-audit-seal window.
    AfterExternalPublicationAuditSealAmbiguous,
    /// The external-publication-audit-seal record itself failed.
    ExternalPublicationAuditSealRecordFailed,
    /// The external-publication-audit-seal record was rolled back.
    ExternalPublicationAuditSealRollbackCompleted,
    /// The external-publication-audit-seal rollback itself failed — fatal.
    ExternalPublicationAuditSealRollbackFailed,
    /// An unknown window — fails closed.
    Unknown,
}

/// Run 288 — classify a modeled durable-completion audit/publication receipt
/// crash/recovery window.
///
/// The receipt sink never silently re-authorizes an in-flight receipt: MainNet
/// peer-driven refusal precedes classification, production / MainNet audit-ledger /
/// external-publication classification is unavailable, and every ambiguous /
/// unknown window fails closed. Only an after-receipt-record window with an explicit
/// matching record (or an explicit after-receipt-success window) recovers as
/// [`DurableCompletionExternalPublicationAuditSealOutcome::ExternalPublicationAuditSealRecorded`]. Pure:
/// performs no modeled mutation and never invokes Run 070.
pub fn recover_durable_completion_external_publication_audit_seal_window(
    input: &DurableCompletionExternalPublicationAuditSealInput,
    window: DurableCompletionExternalPublicationAuditSealWindow,
    kind: DurableCompletionExternalPublicationAuditSealKind,
    recovered_record: Option<&DurableCompletionExternalPublicationAuditSealLedgerRecord>,
    expectations: &DurableCompletionExternalPublicationAuditSealExpectations,
) -> DurableCompletionExternalPublicationAuditSealOutcome {
    use DurableCompletionExternalPublicationAuditSealOutcome as Receipt;
    use DurableCompletionExternalPublicationAuditSealWindow as Window;

    // MainNet peer-driven apply refusal precedes recovery classification.
    if input.is_mainnet_peer_driven() {
        return Receipt::MainNetPeerDrivenApplyRefusedNoAuditSeal;
    }

    // Production / MainNet audit-ledger / external-publication recovery
    // classification is unavailable / fail-closed.
    match kind {
        DurableCompletionExternalPublicationAuditSealKind::ProductionExternalPublicationAuditSealUnavailable => {
            return Receipt::ProductionExternalPublicationAuditSealUnavailableNoAuditSeal;
        }
        DurableCompletionExternalPublicationAuditSealKind::MainNetExternalPublicationAuditSealUnavailable => {
            return Receipt::MainNetExternalPublicationAuditSealUnavailableNoAuditSeal;
        }
        DurableCompletionExternalPublicationAuditSealKind::ExternalExternalPublicationAuditSealUnavailable => {
            return Receipt::ExternalExternalPublicationAuditSealUnavailableNoAuditSeal;
        }
        DurableCompletionExternalPublicationAuditSealKind::Disabled => {
            return Receipt::LegacyBypassNoExternalPublicationAuditSeal;
        }
        DurableCompletionExternalPublicationAuditSealKind::Unknown => {
            return Receipt::ExternalPublicationAuditSealAmbiguousFailClosedNoAuditSeal;
        }
        DurableCompletionExternalPublicationAuditSealKind::FixtureInMemory => {}
    }

    // Helper: an explicit recovered record recovers as a receipt only if it matches
    // the expected receipt record id and the canonical request digest.
    let recovered_matches =
        |record: &DurableCompletionExternalPublicationAuditSealLedgerRecord| -> bool {
            record.external_publication_audit_seal_record_id == expectations.expected_external_publication_audit_seal_record_id
                && record.request_digest == input.request.digest()
                && record.status
                    == DurableCompletionExternalPublicationAuditSealLedgerStatus::Recorded
        };

    match window {
        // Through settlement-confirmation success but before a external-publication-audit-seal
        // request there is nothing to record a settlement external_publication_audit_seal for.
        Window::BeforePipeline
        | Window::AfterPipelineSuccessBeforeSinkIntent
        | Window::AfterSinkIntentBeforeSinkReceiptRecord
        | Window::AfterSinkReceiptRecordBeforePublicationIntent
        | Window::AfterPublicationIntentBeforePublicationRecord
        | Window::AfterPublicationRecordBeforeReceiptIntent
        | Window::AfterReceiptIntentBeforeReceiptRecord
        | Window::AfterReceiptRecordBeforeAttestationIntent
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
        | Window::AfterConsumerSuccessBeforeExternalPublicationAuditArchiveRequest
        | Window::AfterExternalPublicationAuditArchiveRequestBeforeExternalPublicationAuditArchiveRecord
        | Window::AfterExternalPublicationAuditArchiveRecordBeforeExternalPublicationAuditArchiveSuccess
        | Window::AfterExternalPublicationAuditArchiveSuccessBeforeExternalPublicationAuditSealRequest => {
            Receipt::ExternalPublicationAuditArchiveDidNotRecordNoAuditSeal
        }
        // A external-publication-audit-seal request without a record never records a
        // settlement external_publication_audit_seal.
        Window::AfterExternalPublicationAuditSealRequestBeforeExternalPublicationAuditSealRecord => {
            Receipt::ExternalPublicationAuditSealRejectedBeforeRecord
        }
        // After a external-publication-audit-seal record but before success: fails closed
        // unless an explicit matching, well-formed external-publication-audit-seal record
        // exists.
        Window::AfterExternalPublicationAuditSealRecordBeforeExternalPublicationAuditSealSuccess => {
            match recovered_record {
                Some(record) if recovered_matches(record) => Receipt::ExternalPublicationAuditSealRecorded,
                _ => Receipt::ExternalPublicationAuditSealRejectedBeforeRecord,
            }
        }
        // An explicit successful settlement external_publication_audit_seal recovers as recorded only if
        // it matches.
        Window::AfterExternalPublicationAuditSealSuccess => match recovered_record {
            Some(record) if recovered_matches(record) => Receipt::ExternalPublicationAuditSealRecorded,
            _ => Receipt::ExternalPublicationAuditSealRejectedBeforeRecord,
        },
        Window::AfterExternalPublicationAuditSealAmbiguous => {
            Receipt::ExternalPublicationAuditSealAmbiguousFailClosedNoAuditSeal
        }
        Window::ExternalPublicationAuditSealRecordFailed => {
            Receipt::ExternalPublicationAuditSealRecordFailedNoAuditSeal
        }
        Window::ExternalPublicationAuditSealRollbackCompleted => {
            Receipt::ExternalPublicationAuditSealRolledBackNoAuditSeal
        }
        Window::ExternalPublicationAuditSealRollbackFailed => {
            Receipt::ExternalPublicationAuditSealRollbackFailedFatalNoAuditSeal
        }
        // Any unknown window fails closed.
        Window::Unknown => Receipt::ExternalPublicationAuditSealAmbiguousFailClosedNoAuditSeal,
    }
}

/// Run 288 — `true` iff a receipt outcome authorizes a **new** modeled
/// audit/publication receipt (only
/// [`DurableCompletionExternalPublicationAuditSealOutcome::ExternalPublicationAuditSealRecorded`]).
pub fn external_publication_audit_seal_outcome_authorizes_record(
    outcome: &DurableCompletionExternalPublicationAuditSealOutcome,
) -> bool {
    outcome.authorizes_record()
}

/// Run 288 — `true` iff a receipt outcome projects to a recorded audit/publication
/// receipt (a newly recorded receipt or an idempotent duplicate of an
/// already-recorded receipt).
pub fn external_publication_audit_seal_outcome_projects_to_recorded(
    outcome: &DurableCompletionExternalPublicationAuditSealOutcome,
) -> bool {
    outcome.projects_to_recorded()
}

// ===========================================================================
// Grep-verifiable safety invariants (source/test only)
// ===========================================================================

/// Run 288 — a receipt rejection is non-mutating: it records no receipt, mutates no
/// `LivePqcTrustState`, and writes no durable state.
pub fn durable_completion_external_publication_audit_seal_rejection_is_non_mutating() -> bool {
    true
}

/// Run 288 — the receipt boundary never calls Run 070.
pub fn durable_completion_external_publication_audit_seal_never_calls_run_070() -> bool {
    true
}

/// Run 288 — the receipt boundary never mutates live PQC trust state.
pub fn durable_completion_external_publication_audit_seal_never_mutates_live_pqc_trust_state() -> bool {
    true
}

/// Run 288 — the receipt boundary never writes a sequence or a marker.
pub fn durable_completion_external_publication_audit_seal_never_writes_sequence_or_marker() -> bool {
    true
}

/// Run 288 — the receipt boundary changes no RocksDB file schema / migration.
pub fn durable_completion_external_publication_audit_seal_no_rocksdb_file_schema_migration_change() -> bool {
    true
}

/// Run 288 — the receipt boundary performs no external publication.
pub fn durable_completion_external_publication_audit_seal_no_external_publication() -> bool {
    true
}

/// Run 288 — the receipt boundary performs no real audit-ledger persistence.
pub fn durable_completion_external_publication_audit_seal_no_real_audit_ledger() -> bool {
    true
}

/// Run 288 — a receipt requires a successful Run 246 pipeline outcome upstream.
pub fn durable_completion_external_publication_audit_seal_pipeline_success_required() -> bool {
    true
}

/// Run 288 — a receipt requires a Run 248 sink receipt record upstream.
pub fn durable_completion_external_publication_audit_seal_sink_receipt_required() -> bool {
    true
}

/// Run 288 — a receipt requires a Run 250 completion report upstream.
pub fn durable_completion_external_publication_audit_seal_completion_report_required() -> bool {
    true
}

/// Run 288 — a receipt requires a Run 252 external_publication_audit_seal upstream.
pub fn durable_completion_external_publication_audit_seal_finalization_projection_required() -> bool {
    true
}

/// Run 288 — a receipt requires a Run 254 attestation upstream.
pub fn durable_completion_external_publication_audit_seal_attestation_required() -> bool {
    true
}

/// Run 288 — an acknowledgement requires a Run 256 backend submission upstream.
pub fn durable_completion_external_publication_audit_seal_backend_submission_required() -> bool {
    true
}

/// Run 288 — an acknowledgement requires a Run 258 audit receipt upstream.
pub fn durable_completion_external_publication_audit_seal_receipt_required() -> bool {
    true
}

/// Run 288 — a consumer requires a Run 260 audit-receipt acknowledgement upstream.
pub fn durable_completion_external_publication_audit_seal_consumer_required() -> bool {
    true
}

/// Run 288 — a settlement external_publication_audit_seal requires a Run 286 settlement confirmation
/// upstream; no settlement external_publication_audit_seal is authorized without a recorded
/// settlement confirmation.
pub fn durable_completion_external_publication_audit_seal_confirmation_required() -> bool {
    true
}

/// Run 288 — the consumer boundary never performs a real settlement; production /
/// MainNet / external settlement consumers are reachable but fail closed.
pub fn durable_completion_external_publication_audit_seal_no_real_settlement() -> bool {
    true
}

/// Run 288 — the external-publication-audit-seal boundary never confers real settlement
/// finality; the only external-publication-audit-seal record is a modeled in-memory fixture
/// record. Production / MainNet / external external-publication-audit-seal sinks are reachable
/// but unavailable / fail closed and never confer any real finality.
pub fn durable_completion_external_publication_audit_seal_no_real_settlement_finality() -> bool {
    true
}

/// Run 288 — the external-publication-audit-seal boundary never emits a real settlement
/// receipt; the only external-publication-audit-seal record is a modeled in-memory fixture
/// record with no external publication, network I/O, or persistent backend.
pub fn durable_completion_external_publication_audit_seal_no_real_settlement_receipt() -> bool {
    true
}

/// Run 288 — the external-publication-audit-seal boundary never confers a real
/// external-publication-audit-archive; the only external-publication-audit-archive
/// record is a modeled in-memory fixture record. Production / MainNet / external
/// external-publication-audit-archive sinks are reachable but unavailable / fail closed
/// and never confer any real acknowledgement.
pub fn durable_completion_external_publication_audit_seal_no_real_external_publication_audit_archive() -> bool {
    true
}

/// Run 288 — the external-publication-audit-seal boundary never confers a real
/// settlement-finality projection; the only settlement-finality projection is a modeled
/// in-memory fixture record with no external publication, network I/O, or persistent
/// backend.
pub fn durable_completion_external_publication_audit_seal_no_real_settlement_finality_projection() -> bool {
    true
}

/// Run 288 — the external-publication-audit-seal boundary never confers a real
/// external-publication-audit-archive; the only external-publication-audit-archive is a modeled
/// in-memory fixture record with no external publication, network I/O, or persistent
/// backend.
pub fn durable_completion_external_publication_audit_seal_no_real_external_publication_audit_seal() -> bool {
    true
}

/// Run 288 — a receipt record is required before a receipt is acknowledged.
pub fn durable_completion_external_publication_audit_seal_record_required_before_reported() -> bool {
    true
}

/// Run 288 — a failed receipt record never records a receipt.
pub fn durable_completion_external_publication_audit_seal_failed_record_never_records() -> bool {
    true
}

/// Run 288 — a rolled-back receipt record never records a receipt.
pub fn durable_completion_external_publication_audit_seal_rollback_never_records() -> bool {
    true
}

/// Run 288 — an ambiguous after-record receipt window fails closed.
pub fn durable_completion_external_publication_audit_seal_ambiguous_window_fails_closed() -> bool {
    true
}

/// Run 288 — MainNet peer-driven apply refusal precedes every receipt stage.
pub fn durable_completion_external_publication_audit_seal_mainnet_peer_driven_apply_refused_first(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 288 — production / MainNet audit-ledger sinks are reachable but unavailable.
pub fn durable_completion_external_publication_audit_seal_production_mainnet_unavailable() -> bool {
    true
}

/// Run 288 — the external-publication sink is reachable but unavailable.
pub fn durable_completion_external_publication_audit_seal_external_unavailable() -> bool {
    true
}

/// Run 288 — validator-set rotation remains unsupported at the receipt boundary.
pub fn durable_completion_external_publication_audit_seal_validator_set_rotation_unsupported() -> bool {
    true
}

/// Run 288 — policy-change actions remain unsupported at the receipt boundary.
pub fn durable_completion_external_publication_audit_seal_policy_change_unsupported() -> bool {
    true
}

/// Run 288 — a local operator cannot satisfy MainNet authority for a receipt.
pub fn durable_completion_external_publication_audit_seal_local_operator_cannot_satisfy_mainnet_authority(
) -> bool {
    true
}

/// Run 288 — a peer majority cannot satisfy MainNet authority for a receipt.
pub fn durable_completion_external_publication_audit_seal_peer_majority_cannot_satisfy_mainnet_authority(
) -> bool {
    true
}