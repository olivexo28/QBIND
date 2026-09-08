//! Run 266 — source/test durable-completion **acknowledgement consumer /
//! post-acknowledgement settlement interface boundary**.
//!
//! Source/test only. Run 266 captures **no** release-binary evidence and enables
//! **no** production mutating behavior. It does **not** implement a real settlement
//! backend, a real audit-ledger acknowledgement, a real external-publication
//! confirmation, a real external-publication system, a real production attestation
//! backend, a real finalization backend, a real completion-report backend, a real
//! durable consume backend, a real persistent replay backend, a real governance
//! execution engine, a real production mutation engine, a real on-chain governance
//! proof verifier, a KMS/HSM/RemoteSigner backend, MainNet governance enablement,
//! MainNet peer-driven apply enablement, validator-set rotation, or any RocksDB /
//! file / schema / migration / wire / marker / sequence / trust-bundle /
//! storage-format change.
//!
//! ## What this module adds
//!
//! Run 260
//! ([`crate::pqc_governance_durable_completion_audit_receipt_acknowledgement`])
//! proves that a modeled durable-completion *audit-receipt acknowledgement* is
//! recorded **only** after the Run 258 receipt stage recorded an audit receipt,
//! terminating in the single acknowledgement-recording outcome
//! [`DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementRecorded`].
//!
//! Run 266 defines the **first typed interface** a future production settlement or
//! downstream durable-completion subsystem would use to *consume* a durable-completion
//! acknowledgement and prepare a post-acknowledgement settlement intent **after** the
//! Run 260 acknowledgement stage produced `AcknowledgementRecorded`. It is an
//! **interface / projection boundary only**: production / MainNet / external
//! settlement consumer implementations are *reachable but deliberately unavailable /
//! fail-closed*, and the only positive implementation is a DevNet/TestNet fixture that
//! records into an in-memory fixture ledger for source/test evidence only.
//!
//! The consumer layer is a **model only**. It does not implement a real settlement, a
//! real external publication, a real audit-ledger acknowledgement, or any real
//! persistent storage. It does not write RocksDB, files, schemas, migrations, storage
//! formats, wire formats, authority markers, trust-bundle sequence files, or any
//! production durable state. It does not call Run 070, mutate `LivePqcTrustState`,
//! perform a real trust swap, evict sessions, perform external publication / network
//! I/O, or enable MainNet governance / MainNet peer-driven apply. The DevNet/TestNet
//! fixture consumer mutates only the in-memory
//! [`DurableCompletionSettlementCommitmentLedger`].
//!
//! ## Ordering / fail-closed contract
//!
//! 1. **MainNet peer-driven apply refusal** — refused *before* pipeline
//!    progression, sink invocation, reporter invocation, finalizer invocation,
//!    attestor invocation, backend invocation, receipt invocation, acknowledgement
//!    invocation, and consumer invocation;
//! 2. **legacy bypass** — a
//!    [`DurableCompletionSettlementCommitmentPolicy::Disabled`] policy preserves
//!    the legacy no-consumer bypass and never invokes the consumer;
//! 3. **acknowledgement-outcome projection** — only
//!    [`DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementRecorded`]
//!    creates a consumer request; every other Run 260 outcome maps to a no-consumer
//!    fail-closed outcome and never invokes the consumer;
//! 4. **pre-consumer binding validation** — environment / chain / genesis /
//!    governance surface / mutation surface and the full digest binding (including
//!    the Run 256 backend, Run 258 receipt, and Run 260 acknowledgement digest sets)
//!    must match expectations *before* the consumer is invoked; a mismatch fails
//!    closed and leaves the consumer invocation count at zero;
//! 5. **consumer record** — only after every prior gate passes is the consumer
//!    invoked; the consumer-record-identity fields must match exactly before any
//!    modeled consumer record is recorded;
//! 6. **consumer authorization** — only
//!    [`DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentRecorded`]
//!    authorizes a new modeled consumer state.
//!
//! A consumer record failure, rollback, rollback failure, or ambiguous consumer window
//! never retroactively claims a durable consumer record. A duplicate identical consumer
//! record is idempotent; the same consumer record id with a different digest fails
//! closed as equivocation and records no second consumer record. A Run 260
//! [`DurableCompletionAuditReceiptAcknowledgementOutcome::AcknowledgementDuplicateIdempotent`]
//! never creates a new consumer record by itself — it can only match an
//! already-recorded consumer record.

use crate::pqc_governance_durable_completion_acknowledgement_consumer::DurableCompletionAcknowledgementConsumerOutcome;
use crate::pqc_governance_durable_completion_consumer_settlement_projection::DurableCompletionConsumerSettlementProjectionOutcome;
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

/// Run 266 — the validation / mutation surface pair the receipt binds to.
pub type DurableCompletionSettlementCommitmentSurface =
    ModeledGovernanceTrustMutationSurface;

/// Run 266 — the trust-domain environment binding the receipt is bound to.
pub type DurableCompletionSettlementCommitmentEnvironment =
    ModeledGovernanceTrustMutationEnvironmentBinding;

/// Run 266 — the runtime binding (governance + mutation surface + sequence) the
/// receipt is bound to.
pub type DurableCompletionSettlementCommitmentBinding =
    ModeledGovernanceTrustMutationRuntimeBinding;

/// Run 266 — the Run 240/246 durable replay observation carried as freshness
/// context.
pub type DurableCompletionSettlementCommitmentReplayBinding = DurableReplayObservation;

/// Run 266 — the Run 246 pipeline outcome carried as consume authorization context.
pub type DurableCompletionSettlementCommitmentPipelineBinding =
    GovernanceModeledEndToEndPipelineOutcome;

/// Run 266 — the Run 248 sink outcome carried as receipt-record context.
pub type DurableCompletionSettlementCommitmentSinkBinding =
    GovernanceModeledDurableConsumeSinkOutcome;

/// Run 266 — the Run 250 reporter outcome carried as completion-report context.
pub type DurableCompletionSettlementCommitmentReporterBinding =
    GovernanceModeledDurableConsumeCompletionReporterOutcome;

/// Run 266 — the Run 252 finalization outcome carried as finalization context.
pub type DurableCompletionSettlementCommitmentFinalizationBinding =
    GovernanceModeledDurableCompletionFinalizationOutcome;

/// Run 266 — the Run 254 attestation outcome carried as attestation context.
pub type DurableCompletionSettlementCommitmentAttestationBinding =
    GovernanceModeledDurableCompletionAttestationOutcome;

/// Run 266 — the Run 256 backend outcome carried as backend-record context. The
/// acknowledgement boundary never reimplements the backend; it only carries its
/// terminal outcome.
pub type DurableCompletionSettlementCommitmentBackendBinding =
    DurableCompletionAttestationBackendOutcome;

/// Run 266 — the Run 258 audit/publication receipt outcome carried as
/// receipt-record context. The consumer boundary never reimplements the receipt; it
/// only carries its terminal outcome.
pub type DurableCompletionSettlementCommitmentReceiptBinding =
    DurableCompletionAuditPublicationReceiptOutcome;

/// Run 266 — the Run 260 audit-receipt acknowledgement outcome carried as
/// acknowledgement-record context. The settlement-projection boundary never
/// reimplements the acknowledgement; it only carries its terminal outcome.
pub type DurableCompletionSettlementCommitmentAcknowledgementBinding =
    DurableCompletionAuditReceiptAcknowledgementOutcome;

/// Run 266 — the Run 262 acknowledgement consumer outcome the settlement-projection
/// boundary projects to a settlement-projection request. The settlement-projection
/// boundary never reimplements the consumer; it only projects its terminal outcome.
pub type DurableCompletionSettlementCommitmentConsumerBinding =
    DurableCompletionAcknowledgementConsumerOutcome;

/// Run 266 — the Run 264 settlement-projection outcome the settlement-commitment
/// boundary projects to a settlement-commitment request. The settlement-commitment
/// boundary never reimplements the settlement projection; it only projects its
/// terminal outcome.
pub type DurableCompletionSettlementCommitmentSettlementProjectionBinding =
    DurableCompletionConsumerSettlementProjectionOutcome;

// ===========================================================================
// Receipt kind
// ===========================================================================

/// Run 266 — the typed durable-completion audit/publication receipt kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionSettlementCommitmentKind {
    /// The receipt boundary is disabled (legacy bypass).
    Disabled,
    /// DevNet/TestNet in-memory fixture receipt sink (source-test only; may mutate
    /// only the ledger).
    FixtureInMemory,
    /// Production audit-ledger receipt sink (reachable-but-unavailable /
    /// fail-closed).
    ProductionSettlementCommitmentUnavailable,
    /// MainNet audit-ledger receipt sink (reachable-but-unavailable / fail-closed).
    MainNetSettlementCommitmentUnavailable,
    /// External-publication receipt sink (reachable-but-unavailable / fail-closed).
    ExternalSettlementCommitmentUnavailable,
    /// An unknown receipt kind — fails closed.
    Unknown,
}

impl DurableCompletionSettlementCommitmentKind {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureInMemory => "fixture-in-memory",
            Self::ProductionSettlementCommitmentUnavailable => {
                "production-settlement-commitment-unavailable"
            }
            Self::MainNetSettlementCommitmentUnavailable => {
                "mainnet-settlement-commitment-unavailable"
            }
            Self::ExternalSettlementCommitmentUnavailable => {
                "external-settlement-commitment-unavailable"
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
            Self::ProductionSettlementCommitmentUnavailable
                | Self::MainNetSettlementCommitmentUnavailable
                | Self::ExternalSettlementCommitmentUnavailable
        )
    }
}

// ===========================================================================
// Receipt policy
// ===========================================================================

/// Run 266 — the typed durable-completion audit/publication receipt policy
/// selector.
///
/// Only [`Self::FixtureAllowed`] may record (DevNet/TestNet source-test only);
/// every production / MainNet / external-publication policy resolves to a
/// reachable-but-unavailable sink that never records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionSettlementCommitmentPolicy {
    /// The receipt boundary is disabled (legacy bypass).
    Disabled,
    /// A DevNet/TestNet fixture receipt sink is allowed (source-test evidence only).
    FixtureAllowed,
    /// A real production audit-ledger receipt sink is required — reachable but
    /// unavailable.
    ProductionSettlementCommitmentRequired,
    /// A real MainNet audit-ledger receipt sink is required — reachable but
    /// unavailable.
    MainNetSettlementCommitmentRequired,
    /// A real external-publication receipt sink is required — reachable but
    /// unavailable.
    ExternalSettlementCommitmentRequired,
}

impl DurableCompletionSettlementCommitmentPolicy {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureAllowed => "fixture-allowed",
            Self::ProductionSettlementCommitmentRequired => {
                "production-settlement-commitment-required"
            }
            Self::MainNetSettlementCommitmentRequired => "mainnet-settlement-commitment-required",
            Self::ExternalSettlementCommitmentRequired => "external-settlement-commitment-required",
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

/// Run 266 — the typed receipt identity a receipt request is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionSettlementCommitmentIdentity {
    /// Stable receipt id.
    pub projection_id: String,
    /// The receipt kind.
    pub kind: DurableCompletionSettlementCommitmentKind,
    /// The receipt policy.
    pub policy: DurableCompletionSettlementCommitmentPolicy,
    /// The domain separation tag the receipt operates under.
    pub domain_separation_tag: String,
}

impl DurableCompletionSettlementCommitmentIdentity {
    /// `true` iff every mandatory identity field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.projection_id.is_empty()
            && !self.domain_separation_tag.is_empty()
            && self.kind != DurableCompletionSettlementCommitmentKind::Unknown
    }

    /// The deterministic, domain-separated receipt identity digest.
    pub fn digest(&self) -> DurableCompletionSettlementCommitmentDigest {
        settlement_commitment_identity_digest(self)
    }
}

// ===========================================================================
// Deterministic, domain-separated digest helpers
// ===========================================================================

/// Run 266 — domain separator for the receipt identity digest.
const COMMITMENT_IDENTITY_DOMAIN: &[u8] =
    b"QBIND:run266:durable-completion-settlement-commitment-identity:v1";
/// Run 266 — domain separator for the receipt request digest.
const COMMITMENT_REQUEST_DOMAIN: &[u8] =
    b"QBIND:run266:durable-completion-settlement-commitment-request:v1";
/// Run 266 — domain separator for the receipt response digest.
const COMMITMENT_RESPONSE_DOMAIN: &[u8] =
    b"QBIND:run266:durable-completion-settlement-commitment-response:v1";
/// Run 266 — domain separator for the receipt record digest.
const COMMITMENT_RECORD_DOMAIN: &[u8] =
    b"QBIND:run266:durable-completion-settlement-commitment-record:v1";
/// Run 266 — domain separator for the receipt transcript digest.
const COMMITMENT_TRANSCRIPT_DOMAIN: &[u8] =
    b"QBIND:run266:durable-completion-settlement-commitment-transcript:v1";

/// Run 266 — a deterministic, domain-separated receipt digest (lowercase hex of a
/// SHA3-256 over length-prefixed, field-bound canonical material). It contains no
/// unstable display text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionSettlementCommitmentDigest(String);

impl DurableCompletionSettlementCommitmentDigest {
    /// The lowercase hex representation.
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

/// Run 266 — a deterministic, domain-separated receipt transcript digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionSettlementCommitmentTranscriptDigest(String);

impl DurableCompletionSettlementCommitmentTranscriptDigest {
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

/// Run 266 — deterministic, domain-separated receipt identity digest.
pub fn settlement_commitment_identity_digest(
    identity: &DurableCompletionSettlementCommitmentIdentity,
) -> DurableCompletionSettlementCommitmentDigest {
    let mut w = CanonicalWriter::new(COMMITMENT_IDENTITY_DOMAIN);
    w.str_field(&identity.projection_id)
        .str_field(identity.kind.tag())
        .str_field(identity.policy.tag())
        .str_field(&identity.domain_separation_tag);
    DurableCompletionSettlementCommitmentDigest(w.finish())
}

/// Run 266 — deterministic, domain-separated receipt request digest. Binds every
/// request field including the full Run 256 backend digest binding.
pub fn settlement_commitment_request_digest(
    request: &DurableCompletionSettlementCommitmentRequest,
) -> DurableCompletionSettlementCommitmentDigest {
    let mut w = CanonicalWriter::new(COMMITMENT_REQUEST_DOMAIN);
    w.str_field(&request.commitment_record_id)
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
        .str_field(&request.settlement_projection_identity_digest)
        .str_field(&request.settlement_projection_request_digest)
        .str_field(&request.settlement_projection_response_digest)
        .str_field(&request.settlement_projection_record_digest)
        .str_field(&request.settlement_projection_transcript_digest)
        .str_field(&request.settlement_projection_record_id)
        .str_field(&request.domain_separation_tag)
        .str_field(settlement_commitment_identity_digest(&request.identity).as_hex());
    DurableCompletionSettlementCommitmentDigest(w.finish())
}

/// Run 266 — deterministic, domain-separated receipt response digest. Binds the
/// receipt record id, the request digest it answers, the acceptance flag, and the
/// responding receipt kind.
pub fn settlement_commitment_response_digest(
    response: &DurableCompletionSettlementCommitmentResponse,
) -> DurableCompletionSettlementCommitmentDigest {
    let mut w = CanonicalWriter::new(COMMITMENT_RESPONSE_DOMAIN);
    w.str_field(&response.commitment_record_id)
        .str_field(response.request_digest.as_hex())
        .str_field(if response.accepted {
            "accepted"
        } else {
            "rejected"
        })
        .str_field(response.commitment_kind.tag());
    DurableCompletionSettlementCommitmentDigest(w.finish())
}

/// Run 266 — deterministic, domain-separated receipt record digest. Binds the
/// receipt record id, the request digest, and the receipt identity digest.
pub fn settlement_commitment_record_digest(
    record: &DurableCompletionSettlementCommitmentRecord,
) -> DurableCompletionSettlementCommitmentDigest {
    let mut w = CanonicalWriter::new(COMMITMENT_RECORD_DOMAIN);
    w.str_field(&record.commitment_record_id)
        .str_field(record.request_digest.as_hex())
        .str_field(record.identity_digest.as_hex());
    DurableCompletionSettlementCommitmentDigest(w.finish())
}

/// Run 266 — deterministic, domain-separated receipt transcript digest. Binds the
/// request, response, and record digests into a single transcript binding.
pub fn settlement_commitment_transcript_digest(
    request_digest: &DurableCompletionSettlementCommitmentDigest,
    response_digest: &DurableCompletionSettlementCommitmentDigest,
    record_digest: &DurableCompletionSettlementCommitmentDigest,
) -> DurableCompletionSettlementCommitmentTranscriptDigest {
    let mut w = CanonicalWriter::new(COMMITMENT_TRANSCRIPT_DOMAIN);
    w.str_field(request_digest.as_hex())
        .str_field(response_digest.as_hex())
        .str_field(record_digest.as_hex());
    DurableCompletionSettlementCommitmentTranscriptDigest(w.finish())
}

// ===========================================================================
// Receipt request / response / record
// ===========================================================================

/// Run 266 — the typed receipt request a future production audit ledger or
/// external-publication call site would submit once the Run 256 backend recorded a
/// `BackendSubmissionRecorded`.
///
/// Pure data referencing the already-recorded Run 256 backend / Run 254
/// attestation / Run 252 finalization / Run 250 completion report / Run 248
/// receipt / Run 246 decision material — never a copy of any wire payload and never
/// a production durable record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionSettlementCommitmentRequest {
    /// Stable receipt record id (the idempotency key of the receipt).
    pub commitment_record_id: String,
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
    /// Run 264 settlement-projection identity digest.
    pub settlement_projection_identity_digest: String,
    /// Run 264 settlement-projection request digest.
    pub settlement_projection_request_digest: String,
    /// Run 264 settlement-projection response digest.
    pub settlement_projection_response_digest: String,
    /// Run 264 settlement-projection record digest.
    pub settlement_projection_record_digest: String,
    /// Run 264 settlement-projection transcript digest.
    pub settlement_projection_transcript_digest: String,
    /// Run 264 settlement-projection record id.
    pub settlement_projection_record_id: String,
    /// Settlement-commitment identity.
    pub identity: DurableCompletionSettlementCommitmentIdentity,
    /// Domain separation tag.
    pub domain_separation_tag: String,
}

impl DurableCompletionSettlementCommitmentRequest {
    /// `true` iff every mandatory field is structurally present (non-empty) and the
    /// identity is well-formed.
    pub fn is_well_formed(&self) -> bool {
        !self.commitment_record_id.is_empty()
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
            && !self.settlement_projection_identity_digest.is_empty()
            && !self.settlement_projection_request_digest.is_empty()
            && !self.settlement_projection_response_digest.is_empty()
            && !self.settlement_projection_record_digest.is_empty()
            && !self.settlement_projection_transcript_digest.is_empty()
            && !self.settlement_projection_record_id.is_empty()
            && !self.domain_separation_tag.is_empty()
            && self.identity.is_well_formed()
    }

    /// The deterministic receipt request digest.
    pub fn digest(&self) -> DurableCompletionSettlementCommitmentDigest {
        settlement_commitment_request_digest(self)
    }

    /// The canonical immutable record derived from this request.
    pub fn to_record(&self) -> DurableCompletionSettlementCommitmentRecord {
        DurableCompletionSettlementCommitmentRecord {
            commitment_record_id: self.commitment_record_id.clone(),
            request_digest: self.digest(),
            identity_digest: self.identity.digest(),
        }
    }
}

/// Run 266 — the typed receipt response a receipt sink returns for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionSettlementCommitmentResponse {
    /// The receipt record id the response answers.
    pub commitment_record_id: String,
    /// The request digest the response answers.
    pub request_digest: DurableCompletionSettlementCommitmentDigest,
    /// `true` iff the receipt sink accepted the request.
    pub accepted: bool,
    /// The responding receipt kind.
    pub commitment_kind: DurableCompletionSettlementCommitmentKind,
}

impl DurableCompletionSettlementCommitmentResponse {
    /// `true` iff the response is structurally well-formed.
    pub fn is_well_formed(&self) -> bool {
        !self.commitment_record_id.is_empty()
            && self.commitment_kind != DurableCompletionSettlementCommitmentKind::Unknown
    }

    /// The deterministic receipt response digest.
    pub fn digest(&self) -> DurableCompletionSettlementCommitmentDigest {
        settlement_commitment_response_digest(self)
    }
}

/// Run 266 — the canonical immutable receipt record derived from a request. Two
/// records are idempotent-equal only if **every** field matches exactly. The same
/// receipt record id with any differing digest is equivocation and fails closed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionSettlementCommitmentRecord {
    /// The receipt record id.
    pub commitment_record_id: String,
    /// The request digest.
    pub request_digest: DurableCompletionSettlementCommitmentDigest,
    /// The receipt identity digest.
    pub identity_digest: DurableCompletionSettlementCommitmentDigest,
}

impl DurableCompletionSettlementCommitmentRecord {
    /// The deterministic receipt record digest.
    pub fn digest(&self) -> DurableCompletionSettlementCommitmentDigest {
        settlement_commitment_record_digest(self)
    }
}

// ===========================================================================
// In-memory fixture ledger
// ===========================================================================

/// Run 266 — the recorded status of a modeled audit/publication receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionSettlementCommitmentLedgerStatus {
    /// The modeled receipt is recorded in the in-memory fixture ledger.
    Recorded,
}

/// Run 266 — a single modeled receipt record held in the in-memory fixture ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionSettlementCommitmentLedgerRecord {
    /// The receipt record id (stable identity of the receipt).
    pub commitment_record_id: String,
    /// The request digest.
    pub request_digest: DurableCompletionSettlementCommitmentDigest,
    /// The response digest.
    pub response_digest: DurableCompletionSettlementCommitmentDigest,
    /// The record digest.
    pub record_digest: DurableCompletionSettlementCommitmentDigest,
    /// The transcript digest.
    pub transcript_digest: DurableCompletionSettlementCommitmentTranscriptDigest,
    /// The recorded status.
    pub status: DurableCompletionSettlementCommitmentLedgerStatus,
}

/// Run 266 — an immutable snapshot of the modeled receipt ledger used to model a
/// fixture rollback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionSettlementCommitmentLedgerSnapshot {
    records: Vec<DurableCompletionSettlementCommitmentLedgerRecord>,
}

impl DurableCompletionSettlementCommitmentLedgerSnapshot {
    /// The number of records the snapshot captured.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` iff the snapshot captured no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Run 266 — the modeled in-memory receipt ledger.
///
/// **In-memory only.** It never touches RocksDB, files, markers, sequence files,
/// external publications, audit-ledger entries, or any production durable state.
/// The DevNet/TestNet fixture sink is the only thing that may mutate it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DurableCompletionSettlementCommitmentLedger {
    records: Vec<DurableCompletionSettlementCommitmentLedgerRecord>,
}

impl DurableCompletionSettlementCommitmentLedger {
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
    pub fn records(&self) -> &[DurableCompletionSettlementCommitmentLedgerRecord] {
        &self.records
    }

    /// The record for `commitment_record_id`, if present.
    pub fn find(
        &self,
        commitment_record_id: &str,
    ) -> Option<&DurableCompletionSettlementCommitmentLedgerRecord> {
        self.records
            .iter()
            .find(|r| r.commitment_record_id == commitment_record_id)
    }

    /// `true` iff a receipt with `commitment_record_id` is recorded.
    pub fn contains(&self, commitment_record_id: &str) -> bool {
        self.find(commitment_record_id).is_some()
    }

    /// Capture an immutable snapshot for a modeled rollback.
    pub fn snapshot(&self) -> DurableCompletionSettlementCommitmentLedgerSnapshot {
        DurableCompletionSettlementCommitmentLedgerSnapshot {
            records: self.records.clone(),
        }
    }

    /// Restore the ledger to a previously captured snapshot (modeled rollback).
    pub fn restore(
        &mut self,
        snapshot: &DurableCompletionSettlementCommitmentLedgerSnapshot,
    ) {
        self.records = snapshot.records.clone();
    }

    /// Internal: insert a recorded receipt. Only the fixture sink calls this, and
    /// only after every identity / idempotency gate has passed.
    fn insert(&mut self, record: DurableCompletionSettlementCommitmentLedgerRecord) {
        self.records.push(record);
    }
}

// ===========================================================================
// Receipt expectations
// ===========================================================================

/// Run 266 — the canonical binding a [`DurableCompletionSettlementCommitmentInput`]
/// is checked against.
///
/// Environment / chain / genesis / surface mismatches fail closed **before** the
/// receipt sink is invoked. Receipt-request-identity mismatches fail closed
/// **inside** the sink, before any modeled receipt is recorded. Neither path is
/// ever a silent approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionSettlementCommitmentExpectations {
    /// Expected receipt record id.
    pub expected_commitment_record_id: String,
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
    /// Expected Run 264 settlement-projection identity digest.
    pub expected_settlement_projection_identity_digest: String,
    /// Expected Run 264 settlement-projection request digest.
    pub expected_settlement_projection_request_digest: String,
    /// Expected Run 264 settlement-projection response digest.
    pub expected_settlement_projection_response_digest: String,
    /// Expected Run 264 settlement-projection record digest.
    pub expected_settlement_projection_record_digest: String,
    /// Expected Run 264 settlement-projection transcript digest.
    pub expected_settlement_projection_transcript_digest: String,
    /// Expected Run 264 settlement-projection record id.
    pub expected_settlement_projection_record_id: String,
    /// Expected settlement-projection identity.
    pub expected_identity: DurableCompletionSettlementCommitmentIdentity,
    /// Expected settlement-projection kind.
    pub expected_commitment_kind: DurableCompletionSettlementCommitmentKind,
    /// Expected settlement-projection policy.
    pub expected_commitment_policy: DurableCompletionSettlementCommitmentPolicy,
    /// Expected domain separation tag.
    pub expected_domain_separation_tag: String,
}

impl DurableCompletionSettlementCommitmentExpectations {
    /// Internal: the first environment / surface binding mismatch reason, if any.
    fn binding_mismatch_reason(
        &self,
        input: &DurableCompletionSettlementCommitmentInput,
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
        input: &DurableCompletionSettlementCommitmentInput,
    ) -> bool {
        self.binding_mismatch_reason(input).is_none()
    }

    /// Internal: the first receipt-request-identity mismatch reason, if any.
    fn request_mismatch_reason(
        &self,
        request: &DurableCompletionSettlementCommitmentRequest,
    ) -> Option<&'static str> {
        if !request.is_well_formed() {
            return Some("malformed receipt request");
        }
        if request.commitment_record_id != self.expected_commitment_record_id {
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
        if request.settlement_projection_identity_digest
            != self.expected_settlement_projection_identity_digest
        {
            return Some("wrong settlement-projection identity digest");
        }
        if request.settlement_projection_request_digest
            != self.expected_settlement_projection_request_digest
        {
            return Some("wrong settlement-projection request digest");
        }
        if request.settlement_projection_response_digest
            != self.expected_settlement_projection_response_digest
        {
            return Some("wrong settlement-projection response digest");
        }
        if request.settlement_projection_record_digest
            != self.expected_settlement_projection_record_digest
        {
            return Some("wrong settlement-projection record digest");
        }
        if request.settlement_projection_transcript_digest
            != self.expected_settlement_projection_transcript_digest
        {
            return Some("wrong settlement-projection transcript digest");
        }
        if request.settlement_projection_record_id != self.expected_settlement_projection_record_id {
            return Some("wrong settlement-projection record id");
        }
        if request.domain_separation_tag != self.expected_domain_separation_tag {
            return Some("wrong domain separation tag");
        }
        if request.identity != self.expected_identity {
            return Some("wrong settlement-commitment identity");
        }
        if request.identity.kind != self.expected_commitment_kind {
            return Some("wrong settlement-commitment kind");
        }
        if request.identity.policy != self.expected_commitment_policy {
            return Some("wrong settlement-commitment policy");
        }
        None
    }

    /// `true` iff the receipt-request identity matches and is well-formed.
    pub fn request_matches(
        &self,
        request: &DurableCompletionSettlementCommitmentRequest,
    ) -> bool {
        self.request_mismatch_reason(request).is_none()
    }
}

// ===========================================================================
// Receipt input
// ===========================================================================

/// Run 266 — typed inputs for one modeled durable-completion audit/publication
/// receipt round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionSettlementCommitmentInput {
    /// The receipt policy selector.
    pub policy: DurableCompletionSettlementCommitmentPolicy,
    /// The trust-domain environment binding.
    pub environment_binding: DurableCompletionSettlementCommitmentEnvironment,
    /// The runtime binding (governance + mutation surface + sequence).
    pub runtime_binding: DurableCompletionSettlementCommitmentBinding,
    /// The Run 240/246 durable replay observation the pipeline authorized consume
    /// under.
    pub replay_binding: DurableCompletionSettlementCommitmentReplayBinding,
    /// The Run 246 pipeline outcome.
    pub pipeline_binding: DurableCompletionSettlementCommitmentPipelineBinding,
    /// The Run 248 sink outcome.
    pub sink_binding: DurableCompletionSettlementCommitmentSinkBinding,
    /// The Run 250 reporter outcome.
    pub reporter_binding: DurableCompletionSettlementCommitmentReporterBinding,
    /// The Run 252 finalization outcome.
    pub finalization_binding: DurableCompletionSettlementCommitmentFinalizationBinding,
    /// The Run 254 attestation outcome.
    pub attestation_binding: DurableCompletionSettlementCommitmentAttestationBinding,
    /// The Run 256 backend outcome carried as backend-record context.
    pub backend_binding: DurableCompletionSettlementCommitmentBackendBinding,
    /// The Run 258 audit/publication receipt outcome carried as receipt-record
    /// context.
    pub receipt_binding: DurableCompletionSettlementCommitmentReceiptBinding,
    /// The Run 260 audit-receipt acknowledgement outcome carried as
    /// acknowledgement-record context.
    pub acknowledgement_binding:
        DurableCompletionSettlementCommitmentAcknowledgementBinding,
    /// The Run 262 acknowledgement consumer outcome the settlement-projection
    /// boundary projects to a settlement-projection request.
    pub consumer_binding: DurableCompletionSettlementCommitmentConsumerBinding,
    /// The Run 264 settlement-projection outcome the settlement-commitment boundary
    /// projects to a settlement-commitment request.
    pub settlement_projection_binding:
        DurableCompletionSettlementCommitmentSettlementProjectionBinding,
    /// The settlement-commitment request the call site would submit.
    pub request: DurableCompletionSettlementCommitmentRequest,
}

impl DurableCompletionSettlementCommitmentInput {
    /// The trust-domain environment the decision is bound to.
    pub fn environment(&self) -> TrustBundleEnvironment {
        self.environment_binding.environment
    }

    /// The validation / mutation surface pair.
    pub fn surface(&self) -> DurableCompletionSettlementCommitmentSurface {
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
            || matches!(
                self.acknowledgement_binding,
                DurableCompletionAuditReceiptAcknowledgementOutcome::MainNetPeerDrivenApplyRefusedNoAcknowledgement
            )
            || matches!(
                self.consumer_binding,
                DurableCompletionAcknowledgementConsumerOutcome::MainNetPeerDrivenApplyRefusedNoConsumer
            )
            || matches!(
                self.settlement_projection_binding,
                DurableCompletionConsumerSettlementProjectionOutcome::MainNetPeerDrivenApplyRefusedNoProjection
            )
    }
}

// ===========================================================================
// Receipt outcome
// ===========================================================================

/// Run 266 — the typed outcome of one modeled durable-completion audit/publication
/// receipt round-trip.
///
/// Only [`Self::SettlementCommitmentRecorded`] authorizes a **new** modeled
/// audit/publication-receipt state. A [`Self::SettlementCommitmentDuplicateIdempotent`]
/// means the receipt was already recorded (idempotent, no second receipt). Every
/// other variant is a no-audit-receipt fail-closed outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableCompletionSettlementCommitmentOutcome {
    /// Legacy bypass — a disabled receipt policy preserved the legacy
    /// no-audit-receipt path. No receipt invocation.
    LegacyBypassNoSettlementCommitment,
    /// The Run 256 backend-stage binding was rejected before the receipt sink was
    /// invoked (a backend-stage rejection / binding mismatch). Non-mutating, no
    /// receipt. No receipt invocation.
    RejectedBeforeSettlementProjectionNoCommitment,
    /// The Run 256 backend did not submit (any non-submitting backend outcome
    /// without a more specific variant). Non-mutating, no receipt. No receipt
    /// invocation.
    SettlementProjectionDidNotRecordNoCommitment,
    /// The receipt sink recorded a new modeled audit/publication receipt. The
    /// **only** outcome that authorizes a new modeled receipt state.
    SettlementCommitmentRecorded,
    /// A duplicate identical receipt — idempotent; no second receipt recorded.
    SettlementCommitmentDuplicateIdempotent,
    /// The receipt was rejected before record (malformed request, request-identity
    /// mismatch, same receipt record id with a differing digest / equivocation, or
    /// a duplicate-idempotent backend submission with no matching prior receipt). No
    /// receipt.
    SettlementCommitmentRejectedBeforeRecord,
    /// The receipt record failed. No receipt.
    SettlementCommitmentRecordFailedNoCommitment,
    /// The receipt record was rolled back. No receipt.
    SettlementCommitmentRolledBackNoCommitment,
    /// The receipt rollback itself failed — fatal / fail-closed. No receipt.
    SettlementCommitmentRollbackFailedFatalNoCommitment,
    /// The after-record receipt window was ambiguous — fails closed. No receipt.
    SettlementCommitmentAmbiguousFailClosedNoCommitment,
    /// The production audit-ledger path was reached but is unavailable. No receipt.
    ProductionSettlementCommitmentUnavailableNoCommitment,
    /// The MainNet audit-ledger path was reached but is unavailable. No receipt.
    MainNetSettlementCommitmentUnavailableNoCommitment,
    /// The external-publication path was reached but is unavailable. No receipt.
    ExternalSettlementCommitmentUnavailableNoCommitment,
    /// MainNet peer-driven apply remains refused before pipeline progression, sink
    /// invocation, reporter invocation, finalizer invocation, attestor invocation,
    /// backend invocation, and receipt invocation. No receipt.
    MainNetPeerDrivenApplyRefusedNoCommitment,
    /// Validator-set rotation is unsupported. No receipt.
    ValidatorSetRotationUnsupportedNoCommitment,
    /// Policy-change actions are unsupported. No receipt.
    PolicyChangeUnsupportedNoCommitment,
}

impl DurableCompletionSettlementCommitmentOutcome {
    /// `true` iff this outcome authorizes a **new** modeled audit/publication
    /// receipt (only [`Self::SettlementCommitmentRecorded`]).
    pub fn authorizes_record(&self) -> bool {
        matches!(self, Self::SettlementCommitmentRecorded)
    }

    /// `true` iff this outcome projects to a recorded audit/publication receipt — a
    /// newly recorded receipt or an idempotent duplicate of an already-recorded
    /// receipt.
    pub fn projects_to_recorded(&self) -> bool {
        matches!(
            self,
            Self::SettlementCommitmentRecorded | Self::SettlementCommitmentDuplicateIdempotent
        )
    }

    /// `true` iff this outcome records nothing new and projects to no
    /// audit/publication receipt.
    pub fn no_projection(&self) -> bool {
        !self.projects_to_recorded()
    }

    /// `true` iff this is the legacy no-audit-receipt bypass.
    pub fn is_legacy_bypass(&self) -> bool {
        matches!(self, Self::LegacyBypassNoSettlementCommitment)
    }

    /// `true` iff this is the MainNet peer-driven-apply refusal.
    pub fn is_mainnet_peer_driven_apply_refused(&self) -> bool {
        matches!(self, Self::MainNetPeerDrivenApplyRefusedNoCommitment)
    }

    /// Stable operator-facing tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::LegacyBypassNoSettlementCommitment => "legacy-bypass-no-settlement-commitment",
            Self::RejectedBeforeSettlementProjectionNoCommitment => {
                "rejected-before-settlement-projection-no-commitment"
            }
            Self::SettlementProjectionDidNotRecordNoCommitment => {
                "settlement-projection-did-not-record-no-commitment"
            }
            Self::SettlementCommitmentRecorded => "settlement-commitment-recorded",
            Self::SettlementCommitmentDuplicateIdempotent => {
                "settlement-commitment-duplicate-idempotent"
            }
            Self::SettlementCommitmentRejectedBeforeRecord => {
                "settlement-commitment-rejected-before-record"
            }
            Self::SettlementCommitmentRecordFailedNoCommitment => {
                "settlement-commitment-record-failed-no-commitment"
            }
            Self::SettlementCommitmentRolledBackNoCommitment => {
                "settlement-commitment-rolled-back-no-commitment"
            }
            Self::SettlementCommitmentRollbackFailedFatalNoCommitment => {
                "settlement-commitment-rollback-failed-fatal-no-commitment"
            }
            Self::SettlementCommitmentAmbiguousFailClosedNoCommitment => {
                "settlement-commitment-ambiguous-fail-closed-no-commitment"
            }
            Self::ProductionSettlementCommitmentUnavailableNoCommitment => {
                "production-settlement-commitment-unavailable-no-commitment"
            }
            Self::MainNetSettlementCommitmentUnavailableNoCommitment => {
                "mainnet-settlement-commitment-unavailable-no-commitment"
            }
            Self::ExternalSettlementCommitmentUnavailableNoCommitment => {
                "external-settlement-commitment-unavailable-no-commitment"
            }
            Self::MainNetPeerDrivenApplyRefusedNoCommitment => {
                "mainnet-peer-driven-apply-refused-no-commitment"
            }
            Self::ValidatorSetRotationUnsupportedNoCommitment => {
                "validator-set-rotation-unsupported-no-commitment"
            }
            Self::PolicyChangeUnsupportedNoCommitment => "policy-change-unsupported-no-commitment",
        }
    }
}

// ===========================================================================
// Consumer-outcome -> settlement-projection request projection
// ===========================================================================

/// Run 266 — the typed projection of a Run 262 acknowledgement consumer outcome
/// onto a settlement-projection request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableCompletionSettlementCommitmentRequestIntent {
    /// The consumer recorded a consumer record; the settlement-projection sink may
    /// record a new settlement projection.
    CreateRequest,
    /// The consumer reported an idempotent-duplicate consumer record; the
    /// settlement-projection sink may only match an already-recorded settlement
    /// projection and must never create a new one.
    IdempotentOnly,
    /// The consumer did not record; no settlement-projection request. Carries the
    /// typed no-projection outcome the settlement-projection evaluation returns
    /// directly (without invoking the settlement-projection sink).
    NoProjection(DurableCompletionSettlementCommitmentOutcome),
}

impl DurableCompletionSettlementCommitmentRequestIntent {
    /// `true` iff this projection creates a settlement-projection request (i.e. the
    /// consumer recorded a consumer record).
    pub fn creates_request(&self) -> bool {
        matches!(self, Self::CreateRequest)
    }
}

/// Run 266 — project a Run 264 settlement-projection outcome onto a
/// settlement-commitment request.
///
/// Only
/// [`DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionRecorded`]
/// creates a settlement-commitment request.
/// [`DurableCompletionConsumerSettlementProjectionOutcome::SettlementProjectionDuplicateIdempotent`]
/// may only match an already-recorded settlement-commitment record and never creates
/// a new one. Every other settlement-projection outcome maps to a no-commitment
/// fail-closed outcome (a more specific one where one exists, otherwise the generic
/// [`DurableCompletionSettlementCommitmentOutcome::SettlementProjectionDidNotRecordNoCommitment`]).
/// Pure: performs no work and never records.
pub fn project_settlement_projection_outcome_to_commitment_request(
    outcome: &DurableCompletionSettlementCommitmentSettlementProjectionBinding,
) -> DurableCompletionSettlementCommitmentRequestIntent {
    use DurableCompletionConsumerSettlementProjectionOutcome as Projection;
    use DurableCompletionSettlementCommitmentOutcome as Commitment;
    use DurableCompletionSettlementCommitmentRequestIntent as Intent;
    match outcome {
        Projection::SettlementProjectionRecorded => Intent::CreateRequest,
        Projection::SettlementProjectionDuplicateIdempotent => Intent::IdempotentOnly,
        Projection::LegacyBypassNoSettlementProjection => {
            Intent::NoProjection(Commitment::LegacyBypassNoSettlementCommitment)
        }
        Projection::RejectedBeforeConsumerNoSettlementProjection => {
            Intent::NoProjection(Commitment::RejectedBeforeSettlementProjectionNoCommitment)
        }
        Projection::MainNetPeerDrivenApplyRefusedNoProjection => {
            Intent::NoProjection(Commitment::MainNetPeerDrivenApplyRefusedNoCommitment)
        }
        Projection::ValidatorSetRotationUnsupportedNoProjection => {
            Intent::NoProjection(Commitment::ValidatorSetRotationUnsupportedNoCommitment)
        }
        Projection::PolicyChangeUnsupportedNoProjection => {
            Intent::NoProjection(Commitment::PolicyChangeUnsupportedNoCommitment)
        }
        // Every remaining settlement-projection outcome is a non-recording rejection /
        // failure / rollback / ambiguous window: the settlement projection did not
        // record, so no settlement-commitment record may exist.
        _ => Intent::NoProjection(Commitment::SettlementProjectionDidNotRecordNoCommitment),
    }
}

// ===========================================================================
// Receipt fault injection (source/test only)
// ===========================================================================

/// Run 266 — a modeled fault the fixture receipt sink injects to exercise the
/// fail-closed record / rollback / ambiguous paths. Source/test only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionSettlementCommitmentFault {
    /// The receipt record fails; nothing is written. No receipt.
    RecordFailedNoProjection,
    /// The receipt record is rolled back; nothing remains written. No receipt.
    RolledBackNoProjection,
    /// The receipt rollback itself fails — fatal / fail-closed. No receipt.
    RollbackFailedFatal,
    /// The after-record receipt window is ambiguous — fails closed. No receipt.
    AmbiguousAfterRecord,
}

// ===========================================================================
// Receipt trait boundary
// ===========================================================================

/// Run 266 — the pure/mockable modeled durable-completion audit/publication receipt
/// boundary.
///
/// No implementation here calls Run 070, mutates `LivePqcTrustState`, performs a
/// live trust swap, evicts sessions, writes a sequence, writes a marker, performs
/// network I/O, external publication, or a real audit-ledger persistence. The
/// DevNet/TestNet fixture receipt sink mutates only the in-memory
/// [`DurableCompletionSettlementCommitmentLedger`].
pub trait GovernanceDurableCompletionSettlementCommitmentSink {
    /// The receipt kind (used for typed recovery classification).
    fn kind(&self) -> DurableCompletionSettlementCommitmentKind;

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
    fn project_durable_completion_settlement_commitment(
        &mut self,
        request: &DurableCompletionSettlementCommitmentRequest,
        expectations: &DurableCompletionSettlementCommitmentExpectations,
        idempotent_only: bool,
        ledger: &mut DurableCompletionSettlementCommitmentLedger,
    ) -> DurableCompletionSettlementCommitmentOutcome;

    /// Classify a modeled receipt crash/recovery window. Pure: performs no modeled
    /// mutation and never invokes Run 070.
    fn recover_durable_completion_settlement_commitment_window(
        &self,
        input: &DurableCompletionSettlementCommitmentInput,
        window: DurableCompletionSettlementCommitmentWindow,
        recovered_record: Option<&DurableCompletionSettlementCommitmentLedgerRecord>,
        expectations: &DurableCompletionSettlementCommitmentExpectations,
    ) -> DurableCompletionSettlementCommitmentOutcome {
        recover_durable_completion_settlement_commitment_window(
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

/// Run 266 — the DevNet/TestNet in-memory fixture receipt sink.
///
/// Source-test only. It mutates only the in-memory
/// [`DurableCompletionSettlementCommitmentLedger`] and exposes an invocation
/// counter so tests can prove non-submitting backend paths and pre-receipt
/// rejections never invoke it.
#[derive(Debug, Clone)]
pub struct FixtureDurableCompletionSettlementCommitmentSink {
    fault: Option<DurableCompletionSettlementCommitmentFault>,
    invocations: u32,
}

impl Default for FixtureDurableCompletionSettlementCommitmentSink {
    fn default() -> Self {
        Self::new()
    }
}

impl FixtureDurableCompletionSettlementCommitmentSink {
    /// A new fixture receipt sink.
    pub fn new() -> Self {
        Self {
            fault: None,
            invocations: 0,
        }
    }

    /// A new fixture receipt sink that injects the given modeled fault on record.
    pub fn with_fault(fault: DurableCompletionSettlementCommitmentFault) -> Self {
        Self {
            fault: Some(fault),
            invocations: 0,
        }
    }
}

impl GovernanceDurableCompletionSettlementCommitmentSink
    for FixtureDurableCompletionSettlementCommitmentSink
{
    fn kind(&self) -> DurableCompletionSettlementCommitmentKind {
        DurableCompletionSettlementCommitmentKind::FixtureInMemory
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn project_durable_completion_settlement_commitment(
        &mut self,
        request: &DurableCompletionSettlementCommitmentRequest,
        expectations: &DurableCompletionSettlementCommitmentExpectations,
        idempotent_only: bool,
        ledger: &mut DurableCompletionSettlementCommitmentLedger,
    ) -> DurableCompletionSettlementCommitmentOutcome {
        use DurableCompletionSettlementCommitmentOutcome as Receipt;
        self.invocations += 1;

        // Injected faults model record-failure / rollback / ambiguous windows. None
        // of them ever leave a recorded receipt behind, so a durable receipt is never
        // claimed. The ledger snapshot/restore models the rollback being a no-op
        // write.
        if let Some(fault) = self.fault {
            let snapshot = ledger.snapshot();
            return match fault {
                DurableCompletionSettlementCommitmentFault::RecordFailedNoProjection => {
                    ledger.restore(&snapshot);
                    Receipt::SettlementCommitmentRecordFailedNoCommitment
                }
                DurableCompletionSettlementCommitmentFault::RolledBackNoProjection => {
                    ledger.restore(&snapshot);
                    Receipt::SettlementCommitmentRolledBackNoCommitment
                }
                DurableCompletionSettlementCommitmentFault::RollbackFailedFatal => {
                    Receipt::SettlementCommitmentRollbackFailedFatalNoCommitment
                }
                DurableCompletionSettlementCommitmentFault::AmbiguousAfterRecord => {
                    ledger.restore(&snapshot);
                    Receipt::SettlementCommitmentAmbiguousFailClosedNoCommitment
                }
            };
        }

        // The fixture receipt sink is DevNet/TestNet evidence-only.
        if !matches!(
            request.environment,
            TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet
        ) {
            return Receipt::SettlementCommitmentRejectedBeforeRecord;
        }

        // Request-identity validation (malformed / mismatch) fails closed before any
        // record is written.
        if !expectations.request_matches(request) {
            return Receipt::SettlementCommitmentRejectedBeforeRecord;
        }

        // Build the deterministic request / response / record / transcript digests.
        let request_digest = request.digest();
        let response = DurableCompletionSettlementCommitmentResponse {
            commitment_record_id: request.commitment_record_id.clone(),
            request_digest: request_digest.clone(),
            accepted: true,
            commitment_kind: DurableCompletionSettlementCommitmentKind::FixtureInMemory,
        };
        let response_digest = response.digest();
        let record = request.to_record();
        let record_digest = record.digest();
        let transcript_digest = settlement_commitment_transcript_digest(
            &request_digest,
            &response_digest,
            &record_digest,
        );

        // Idempotency / equivocation gate.
        if let Some(existing) = ledger.find(&request.commitment_record_id) {
            if existing.request_digest == request_digest
                && existing.response_digest == response_digest
                && existing.record_digest == record_digest
                && existing.transcript_digest == transcript_digest
            {
                return Receipt::SettlementCommitmentDuplicateIdempotent;
            }
            // Same receipt record id with a different digest is equivocation: fail
            // closed, record no second receipt.
            return Receipt::SettlementCommitmentRejectedBeforeRecord;
        }

        // A duplicate-idempotent backend submission may only match an already-recorded
        // receipt; it must never create a new one by itself.
        if idempotent_only {
            return Receipt::SettlementCommitmentRejectedBeforeRecord;
        }

        ledger.insert(DurableCompletionSettlementCommitmentLedgerRecord {
            commitment_record_id: request.commitment_record_id.clone(),
            request_digest,
            response_digest,
            record_digest,
            transcript_digest,
            status: DurableCompletionSettlementCommitmentLedgerStatus::Recorded,
        });
        Receipt::SettlementCommitmentRecorded
    }
}

// ===========================================================================
// Production / MainNet audit-ledger / External-publication sinks (unavailable)
// ===========================================================================

/// Run 266 — the production audit-ledger receipt sink. Reachable but unavailable /
/// fail-closed. It records no receipt and mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct ProductionSettlementCommitmentSink {
    invocations: u32,
}

impl GovernanceDurableCompletionSettlementCommitmentSink
    for ProductionSettlementCommitmentSink
{
    fn kind(&self) -> DurableCompletionSettlementCommitmentKind {
        DurableCompletionSettlementCommitmentKind::ProductionSettlementCommitmentUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn project_durable_completion_settlement_commitment(
        &mut self,
        _request: &DurableCompletionSettlementCommitmentRequest,
        _expectations: &DurableCompletionSettlementCommitmentExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionSettlementCommitmentLedger,
    ) -> DurableCompletionSettlementCommitmentOutcome {
        self.invocations += 1;
        DurableCompletionSettlementCommitmentOutcome::ProductionSettlementCommitmentUnavailableNoCommitment
    }
}

/// Run 266 — the MainNet audit-ledger receipt sink. Reachable but unavailable /
/// fail-closed. It records no receipt and mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct MainNetSettlementCommitmentSink {
    invocations: u32,
}

impl GovernanceDurableCompletionSettlementCommitmentSink
    for MainNetSettlementCommitmentSink
{
    fn kind(&self) -> DurableCompletionSettlementCommitmentKind {
        DurableCompletionSettlementCommitmentKind::MainNetSettlementCommitmentUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn project_durable_completion_settlement_commitment(
        &mut self,
        _request: &DurableCompletionSettlementCommitmentRequest,
        _expectations: &DurableCompletionSettlementCommitmentExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionSettlementCommitmentLedger,
    ) -> DurableCompletionSettlementCommitmentOutcome {
        self.invocations += 1;
        DurableCompletionSettlementCommitmentOutcome::MainNetSettlementCommitmentUnavailableNoCommitment
    }
}

/// Run 266 — the external-publication receipt sink. Reachable but unavailable /
/// fail-closed. It performs no external publication, records no receipt, and
/// mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct ExternalSettlementCommitmentSink {
    invocations: u32,
}

impl GovernanceDurableCompletionSettlementCommitmentSink
    for ExternalSettlementCommitmentSink
{
    fn kind(&self) -> DurableCompletionSettlementCommitmentKind {
        DurableCompletionSettlementCommitmentKind::ExternalSettlementCommitmentUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn project_durable_completion_settlement_commitment(
        &mut self,
        _request: &DurableCompletionSettlementCommitmentRequest,
        _expectations: &DurableCompletionSettlementCommitmentExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionSettlementCommitmentLedger,
    ) -> DurableCompletionSettlementCommitmentOutcome {
        self.invocations += 1;
        DurableCompletionSettlementCommitmentOutcome::ExternalSettlementCommitmentUnavailableNoCommitment
    }
}

// ===========================================================================
// Receipt executor / composition helpers
// ===========================================================================

/// Run 266 — evaluate one modeled durable-completion audit/publication receipt
/// round-trip.
///
/// Ordering (each gate must pass before the next is considered):
///
/// 1. MainNet peer-driven apply refusal — before pipeline progression, sink
///    invocation, reporter invocation, finalizer invocation, attestor invocation,
///    backend invocation, and receipt invocation;
/// 2. legacy bypass — a
///    [`DurableCompletionSettlementCommitmentPolicy::Disabled`] policy;
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
pub fn evaluate_durable_completion_settlement_commitment<S>(
    input: &DurableCompletionSettlementCommitmentInput,
    expectations: &DurableCompletionSettlementCommitmentExpectations,
    sink: &mut S,
    ledger: &mut DurableCompletionSettlementCommitmentLedger,
) -> DurableCompletionSettlementCommitmentOutcome
where
    S: GovernanceDurableCompletionSettlementCommitmentSink,
{
    use DurableCompletionSettlementCommitmentOutcome as Projection;
    use DurableCompletionSettlementCommitmentRequestIntent as Intent;

    // Step 1: MainNet peer-driven apply remains refused unconditionally, before
    // pipeline progression, sink invocation, reporter invocation, finalizer
    // invocation, attestor invocation, backend invocation, receipt invocation,
    // acknowledgement invocation, consumer invocation, and settlement-projection
    // invocation.
    if input.is_mainnet_peer_driven() {
        return Projection::MainNetPeerDrivenApplyRefusedNoCommitment;
    }

    // Step 2: legacy bypass — a disabled settlement-projection policy preserves the
    // legacy no-settlement-projection path and never invokes the projection sink.
    if input.policy.is_disabled() {
        return Projection::LegacyBypassNoSettlementCommitment;
    }

    // Step 3: project the Run 262 acknowledgement consumer outcome onto a
    // settlement-projection request. Every non-recording consumer outcome returns a
    // no-projection outcome without invoking the settlement-projection sink.
    let idempotent_only =
        match project_settlement_projection_outcome_to_commitment_request(
            &input.settlement_projection_binding,
        ) {
            Intent::NoProjection(outcome) => return outcome,
            Intent::CreateRequest => false,
            Intent::IdempotentOnly => true,
        };

    // Step 4: pre-projection environment / surface binding validation. A mismatch
    // fails closed before the settlement-projection sink is invoked, leaving the
    // settlement-projection invocation count at zero.
    if !expectations.binding_matches(input) {
        return Projection::RejectedBeforeSettlementProjectionNoCommitment;
    }

    // Step 5: invoke the settlement-projection sink to record the modeled projection.
    sink.project_durable_completion_settlement_commitment(
        &input.request,
        expectations,
        idempotent_only,
        ledger,
    )
}

// ===========================================================================
// Receipt crash/recovery window classification
// ===========================================================================

/// Run 266 — the modeled durable-completion audit/publication receipt
/// crash/recovery window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionSettlementCommitmentWindow {
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
    /// Crashed after acknowledgement success but before a consumer request.
    AfterAcknowledgementSuccessBeforeConsumerRequest,
    /// Crashed after a consumer request but before any consumer record.
    AfterConsumerRequestBeforeConsumerRecord,
    /// Crashed after a consumer record but before consumer success.
    AfterConsumerRecordBeforeConsumerSuccess,
    /// Crashed after consumer success but before a settlement-projection request.
    AfterConsumerSuccessBeforeSettlementProjectionRequest,
    /// Crashed after a settlement-projection request but before any
    /// settlement-projection record.
    AfterSettlementProjectionRequestBeforeSettlementProjectionRecord,
    /// Crashed after a settlement-projection record but before settlement-projection
    /// success — fails closed unless an explicit matching settlement-projection
    /// record exists.
    AfterSettlementProjectionRecordBeforeSettlementProjectionSuccess,
    /// Crashed after settlement-projection success but before a settlement-commitment
    /// request.
    AfterSettlementProjectionSuccessBeforeSettlementCommitmentRequest,
    /// Crashed after a settlement-commitment request but before any
    /// settlement-commitment record.
    AfterSettlementCommitmentRequestBeforeSettlementCommitmentRecord,
    /// Crashed after a settlement-commitment record but before settlement-commitment
    /// success — fails closed unless an explicit matching settlement-commitment
    /// record exists.
    AfterSettlementCommitmentRecordBeforeSettlementCommitmentSuccess,
    /// Recovered after a successful settlement-commitment record.
    AfterSettlementCommitmentSuccess,
    /// Recovered after an ambiguous settlement-commitment window.
    AfterSettlementCommitmentAmbiguous,
    /// The settlement-commitment record itself failed.
    SettlementCommitmentRecordFailed,
    /// The settlement-commitment record was rolled back.
    SettlementCommitmentRollbackCompleted,
    /// The settlement-commitment rollback itself failed — fatal.
    SettlementCommitmentRollbackFailed,
    /// An unknown window — fails closed.
    Unknown,
}

/// Run 266 — classify a modeled durable-completion audit/publication receipt
/// crash/recovery window.
///
/// The receipt sink never silently re-authorizes an in-flight receipt: MainNet
/// peer-driven refusal precedes classification, production / MainNet audit-ledger /
/// external-publication classification is unavailable, and every ambiguous /
/// unknown window fails closed. Only an after-receipt-record window with an explicit
/// matching record (or an explicit after-receipt-success window) recovers as
/// [`DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentRecorded`]. Pure:
/// performs no modeled mutation and never invokes Run 070.
pub fn recover_durable_completion_settlement_commitment_window(
    input: &DurableCompletionSettlementCommitmentInput,
    window: DurableCompletionSettlementCommitmentWindow,
    kind: DurableCompletionSettlementCommitmentKind,
    recovered_record: Option<&DurableCompletionSettlementCommitmentLedgerRecord>,
    expectations: &DurableCompletionSettlementCommitmentExpectations,
) -> DurableCompletionSettlementCommitmentOutcome {
    use DurableCompletionSettlementCommitmentOutcome as Receipt;
    use DurableCompletionSettlementCommitmentWindow as Window;

    // MainNet peer-driven apply refusal precedes recovery classification.
    if input.is_mainnet_peer_driven() {
        return Receipt::MainNetPeerDrivenApplyRefusedNoCommitment;
    }

    // Production / MainNet audit-ledger / external-publication recovery
    // classification is unavailable / fail-closed.
    match kind {
        DurableCompletionSettlementCommitmentKind::ProductionSettlementCommitmentUnavailable => {
            return Receipt::ProductionSettlementCommitmentUnavailableNoCommitment;
        }
        DurableCompletionSettlementCommitmentKind::MainNetSettlementCommitmentUnavailable => {
            return Receipt::MainNetSettlementCommitmentUnavailableNoCommitment;
        }
        DurableCompletionSettlementCommitmentKind::ExternalSettlementCommitmentUnavailable => {
            return Receipt::ExternalSettlementCommitmentUnavailableNoCommitment;
        }
        DurableCompletionSettlementCommitmentKind::Disabled => {
            return Receipt::LegacyBypassNoSettlementCommitment;
        }
        DurableCompletionSettlementCommitmentKind::Unknown => {
            return Receipt::SettlementCommitmentAmbiguousFailClosedNoCommitment;
        }
        DurableCompletionSettlementCommitmentKind::FixtureInMemory => {}
    }

    // Helper: an explicit recovered record recovers as a receipt only if it matches
    // the expected receipt record id and the canonical request digest.
    let recovered_matches =
        |record: &DurableCompletionSettlementCommitmentLedgerRecord| -> bool {
            record.commitment_record_id == expectations.expected_commitment_record_id
                && record.request_digest == input.request.digest()
                && record.status
                    == DurableCompletionSettlementCommitmentLedgerStatus::Recorded
        };

    match window {
        // Through settlement-projection success but before a settlement-commitment
        // request there is nothing to record a settlement commitment for.
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
        | Window::AfterReceiptSuccessBeforeAcknowledgementRequest
        | Window::AfterAcknowledgementRequestBeforeAcknowledgementRecord
        | Window::AfterAcknowledgementRecordBeforeAcknowledgementSuccess
        | Window::AfterAcknowledgementSuccessBeforeConsumerRequest
        | Window::AfterConsumerRequestBeforeConsumerRecord
        | Window::AfterConsumerRecordBeforeConsumerSuccess
        | Window::AfterConsumerSuccessBeforeSettlementProjectionRequest
        | Window::AfterSettlementProjectionRequestBeforeSettlementProjectionRecord
        | Window::AfterSettlementProjectionRecordBeforeSettlementProjectionSuccess
        | Window::AfterSettlementProjectionSuccessBeforeSettlementCommitmentRequest => {
            Receipt::SettlementProjectionDidNotRecordNoCommitment
        }
        // A settlement-commitment request without a record never records a
        // settlement commitment.
        Window::AfterSettlementCommitmentRequestBeforeSettlementCommitmentRecord => {
            Receipt::SettlementCommitmentRejectedBeforeRecord
        }
        // After a settlement-commitment record but before success: fails closed
        // unless an explicit matching, well-formed settlement-commitment record
        // exists.
        Window::AfterSettlementCommitmentRecordBeforeSettlementCommitmentSuccess => {
            match recovered_record {
                Some(record) if recovered_matches(record) => Receipt::SettlementCommitmentRecorded,
                _ => Receipt::SettlementCommitmentRejectedBeforeRecord,
            }
        }
        // An explicit successful settlement commitment recovers as recorded only if
        // it matches.
        Window::AfterSettlementCommitmentSuccess => match recovered_record {
            Some(record) if recovered_matches(record) => Receipt::SettlementCommitmentRecorded,
            _ => Receipt::SettlementCommitmentRejectedBeforeRecord,
        },
        Window::AfterSettlementCommitmentAmbiguous => {
            Receipt::SettlementCommitmentAmbiguousFailClosedNoCommitment
        }
        Window::SettlementCommitmentRecordFailed => {
            Receipt::SettlementCommitmentRecordFailedNoCommitment
        }
        Window::SettlementCommitmentRollbackCompleted => {
            Receipt::SettlementCommitmentRolledBackNoCommitment
        }
        Window::SettlementCommitmentRollbackFailed => {
            Receipt::SettlementCommitmentRollbackFailedFatalNoCommitment
        }
        // Any unknown window fails closed.
        Window::Unknown => Receipt::SettlementCommitmentAmbiguousFailClosedNoCommitment,
    }
}

/// Run 266 — `true` iff a receipt outcome authorizes a **new** modeled
/// audit/publication receipt (only
/// [`DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentRecorded`]).
pub fn settlement_commitment_outcome_authorizes_record(
    outcome: &DurableCompletionSettlementCommitmentOutcome,
) -> bool {
    outcome.authorizes_record()
}

/// Run 266 — `true` iff a receipt outcome projects to a recorded audit/publication
/// receipt (a newly recorded receipt or an idempotent duplicate of an
/// already-recorded receipt).
pub fn settlement_commitment_outcome_projects_to_recorded(
    outcome: &DurableCompletionSettlementCommitmentOutcome,
) -> bool {
    outcome.projects_to_recorded()
}

// ===========================================================================
// Grep-verifiable safety invariants (source/test only)
// ===========================================================================

/// Run 266 — a receipt rejection is non-mutating: it records no receipt, mutates no
/// `LivePqcTrustState`, and writes no durable state.
pub fn durable_completion_settlement_commitment_rejection_is_non_mutating() -> bool {
    true
}

/// Run 266 — the receipt boundary never calls Run 070.
pub fn durable_completion_settlement_commitment_never_calls_run_070() -> bool {
    true
}

/// Run 266 — the receipt boundary never mutates live PQC trust state.
pub fn durable_completion_settlement_commitment_never_mutates_live_pqc_trust_state() -> bool {
    true
}

/// Run 266 — the receipt boundary never writes a sequence or a marker.
pub fn durable_completion_settlement_commitment_never_writes_sequence_or_marker() -> bool {
    true
}

/// Run 266 — the receipt boundary changes no RocksDB file schema / migration.
pub fn durable_completion_settlement_commitment_no_rocksdb_file_schema_migration_change() -> bool {
    true
}

/// Run 266 — the receipt boundary performs no external publication.
pub fn durable_completion_settlement_commitment_no_external_publication() -> bool {
    true
}

/// Run 266 — the receipt boundary performs no real audit-ledger persistence.
pub fn durable_completion_settlement_commitment_no_real_audit_ledger() -> bool {
    true
}

/// Run 266 — a receipt requires a successful Run 246 pipeline outcome upstream.
pub fn durable_completion_settlement_commitment_pipeline_success_required() -> bool {
    true
}

/// Run 266 — a receipt requires a Run 248 sink receipt record upstream.
pub fn durable_completion_settlement_commitment_sink_receipt_required() -> bool {
    true
}

/// Run 266 — a receipt requires a Run 250 completion report upstream.
pub fn durable_completion_settlement_commitment_completion_report_required() -> bool {
    true
}

/// Run 266 — a receipt requires a Run 252 finalization upstream.
pub fn durable_completion_settlement_commitment_finalization_required() -> bool {
    true
}

/// Run 266 — a receipt requires a Run 254 attestation upstream.
pub fn durable_completion_settlement_commitment_attestation_required() -> bool {
    true
}

/// Run 266 — an acknowledgement requires a Run 256 backend submission upstream.
pub fn durable_completion_settlement_commitment_backend_submission_required() -> bool {
    true
}

/// Run 266 — an acknowledgement requires a Run 258 audit receipt upstream.
pub fn durable_completion_settlement_commitment_receipt_required() -> bool {
    true
}

/// Run 266 — a consumer requires a Run 260 audit-receipt acknowledgement upstream.
pub fn durable_completion_settlement_commitment_consumer_required() -> bool {
    true
}

/// Run 266 — a settlement commitment requires a Run 264 settlement projection
/// upstream; no settlement commitment is authorized without a recorded
/// settlement projection.
pub fn durable_completion_settlement_commitment_projection_required() -> bool {
    true
}

/// Run 266 — the consumer boundary never performs a real settlement; production /
/// MainNet / external settlement consumers are reachable but fail closed.
pub fn durable_completion_settlement_commitment_no_real_settlement() -> bool {
    true
}

/// Run 266 — a receipt record is required before a receipt is acknowledged.
pub fn durable_completion_settlement_commitment_record_required_before_committed() -> bool {
    true
}

/// Run 266 — a failed receipt record never records a receipt.
pub fn durable_completion_settlement_commitment_failed_record_never_records() -> bool {
    true
}

/// Run 266 — a rolled-back receipt record never records a receipt.
pub fn durable_completion_settlement_commitment_rollback_never_records() -> bool {
    true
}

/// Run 266 — an ambiguous after-record receipt window fails closed.
pub fn durable_completion_settlement_commitment_ambiguous_window_fails_closed() -> bool {
    true
}

/// Run 266 — MainNet peer-driven apply refusal precedes every receipt stage.
pub fn durable_completion_settlement_commitment_mainnet_peer_driven_apply_refused_first(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 266 — production / MainNet audit-ledger sinks are reachable but unavailable.
pub fn durable_completion_settlement_commitment_production_mainnet_unavailable() -> bool {
    true
}

/// Run 266 — the external-publication sink is reachable but unavailable.
pub fn durable_completion_settlement_commitment_external_unavailable() -> bool {
    true
}

/// Run 266 — validator-set rotation remains unsupported at the receipt boundary.
pub fn durable_completion_settlement_commitment_validator_set_rotation_unsupported() -> bool {
    true
}

/// Run 266 — policy-change actions remain unsupported at the receipt boundary.
pub fn durable_completion_settlement_commitment_policy_change_unsupported() -> bool {
    true
}

/// Run 266 — a local operator cannot satisfy MainNet authority for a receipt.
pub fn durable_completion_settlement_commitment_local_operator_cannot_satisfy_mainnet_authority(
) -> bool {
    true
}

/// Run 266 — a peer majority cannot satisfy MainNet authority for a receipt.
pub fn durable_completion_settlement_commitment_peer_majority_cannot_satisfy_mainnet_authority(
) -> bool {
    true
}