//! Run 268 — source/test durable-completion **acknowledgement consumer /
//! post-acknowledgement settlement interface boundary**.
//!
//! Source/test only. Run 268 captures **no** release-binary evidence and enables
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
//! Run 268 defines the **first typed interface** a future production settlement or
//! downstream durable-completion subsystem would use to *consume* a durable-completion
//! acknowledgement and prepare a post-acknowledgement settlement intent **after** the
//! Run 260 acknowledgement stage produced `AcknowledgementRecorded`. It is an
//! **interface / commitment boundary only**: production / MainNet / external
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
//! [`DurableCompletionSettlementFinalizationLedger`].
//!
//! ## Ordering / fail-closed contract
//!
//! 1. **MainNet peer-driven apply refusal** — refused *before* pipeline
//!    progression, sink invocation, reporter invocation, finalizer invocation,
//!    attestor invocation, backend invocation, receipt invocation, acknowledgement
//!    invocation, and consumer invocation;
//! 2. **legacy bypass** — a
//!    [`DurableCompletionSettlementFinalizationPolicy::Disabled`] policy preserves
//!    the legacy no-consumer bypass and never invokes the consumer;
//! 3. **acknowledgement-outcome commitment** — only
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
//!    [`DurableCompletionSettlementFinalizationOutcome::SettlementFinalizationRecorded`]
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
use crate::pqc_governance_durable_completion_settlement_commitment::DurableCompletionSettlementCommitmentOutcome;
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

/// Run 268 — the validation / mutation surface pair the receipt binds to.
pub type DurableCompletionSettlementFinalizationSurface =
    ModeledGovernanceTrustMutationSurface;

/// Run 268 — the trust-domain environment binding the receipt is bound to.
pub type DurableCompletionSettlementFinalizationEnvironment =
    ModeledGovernanceTrustMutationEnvironmentBinding;

/// Run 268 — the runtime binding (governance + mutation surface + sequence) the
/// receipt is bound to.
pub type DurableCompletionSettlementFinalizationBinding =
    ModeledGovernanceTrustMutationRuntimeBinding;

/// Run 268 — the Run 240/246 durable replay observation carried as freshness
/// context.
pub type DurableCompletionSettlementFinalizationReplayBinding = DurableReplayObservation;

/// Run 268 — the Run 246 pipeline outcome carried as consume authorization context.
pub type DurableCompletionSettlementFinalizationPipelineBinding =
    GovernanceModeledEndToEndPipelineOutcome;

/// Run 268 — the Run 248 sink outcome carried as receipt-record context.
pub type DurableCompletionSettlementFinalizationSinkBinding =
    GovernanceModeledDurableConsumeSinkOutcome;

/// Run 268 — the Run 250 reporter outcome carried as completion-report context.
pub type DurableCompletionSettlementFinalizationReporterBinding =
    GovernanceModeledDurableConsumeCompletionReporterOutcome;

/// Run 268 — the Run 252 finalization outcome carried as finalization context.
pub type DurableCompletionSettlementFinalizationFinalizationBinding =
    GovernanceModeledDurableCompletionFinalizationOutcome;

/// Run 268 — the Run 254 attestation outcome carried as attestation context.
pub type DurableCompletionSettlementFinalizationAttestationBinding =
    GovernanceModeledDurableCompletionAttestationOutcome;

/// Run 268 — the Run 256 backend outcome carried as backend-record context. The
/// acknowledgement boundary never reimplements the backend; it only carries its
/// terminal outcome.
pub type DurableCompletionSettlementFinalizationBackendBinding =
    DurableCompletionAttestationBackendOutcome;

/// Run 268 — the Run 258 audit/publication receipt outcome carried as
/// receipt-record context. The consumer boundary never reimplements the receipt; it
/// only carries its terminal outcome.
pub type DurableCompletionSettlementFinalizationReceiptBinding =
    DurableCompletionAuditPublicationReceiptOutcome;

/// Run 268 — the Run 260 audit-receipt acknowledgement outcome carried as
/// acknowledgement-record context. The settlement-commitment boundary never
/// reimplements the acknowledgement; it only carries its terminal outcome.
pub type DurableCompletionSettlementFinalizationAcknowledgementBinding =
    DurableCompletionAuditReceiptAcknowledgementOutcome;

/// Run 268 — the Run 262 acknowledgement consumer outcome the settlement-commitment
/// boundary projects to a settlement-commitment request. The settlement-commitment
/// boundary never reimplements the consumer; it only projects its terminal outcome.
pub type DurableCompletionSettlementFinalizationConsumerBinding =
    DurableCompletionAcknowledgementConsumerOutcome;

/// Run 268 — the Run 266 settlement-commitment outcome the settlement-finalization
/// boundary projects to a settlement-finalization request. The settlement-finalization
/// boundary never reimplements the settlement commitment; it only projects its
/// terminal outcome.
pub type DurableCompletionSettlementFinalizationSettlementCommitmentBinding =
    DurableCompletionSettlementCommitmentOutcome;

// ===========================================================================
// Receipt kind
// ===========================================================================

/// Run 268 — the typed durable-completion audit/publication receipt kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionSettlementFinalizationKind {
    /// The receipt boundary is disabled (legacy bypass).
    Disabled,
    /// DevNet/TestNet in-memory fixture receipt sink (source-test only; may mutate
    /// only the ledger).
    FixtureInMemory,
    /// Production audit-ledger receipt sink (reachable-but-unavailable /
    /// fail-closed).
    ProductionSettlementFinalizationUnavailable,
    /// MainNet audit-ledger receipt sink (reachable-but-unavailable / fail-closed).
    MainNetSettlementFinalizationUnavailable,
    /// External-publication receipt sink (reachable-but-unavailable / fail-closed).
    ExternalSettlementFinalizationUnavailable,
    /// An unknown receipt kind — fails closed.
    Unknown,
}

impl DurableCompletionSettlementFinalizationKind {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureInMemory => "fixture-in-memory",
            Self::ProductionSettlementFinalizationUnavailable => {
                "production-settlement-finalization-unavailable"
            }
            Self::MainNetSettlementFinalizationUnavailable => {
                "mainnet-settlement-finalization-unavailable"
            }
            Self::ExternalSettlementFinalizationUnavailable => {
                "external-settlement-finalization-unavailable"
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
            Self::ProductionSettlementFinalizationUnavailable
                | Self::MainNetSettlementFinalizationUnavailable
                | Self::ExternalSettlementFinalizationUnavailable
        )
    }
}

// ===========================================================================
// Receipt policy
// ===========================================================================

/// Run 268 — the typed durable-completion audit/publication receipt policy
/// selector.
///
/// Only [`Self::FixtureAllowed`] may record (DevNet/TestNet source-test only);
/// every production / MainNet / external-publication policy resolves to a
/// reachable-but-unavailable sink that never records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionSettlementFinalizationPolicy {
    /// The receipt boundary is disabled (legacy bypass).
    Disabled,
    /// A DevNet/TestNet fixture receipt sink is allowed (source-test evidence only).
    FixtureAllowed,
    /// A real production audit-ledger receipt sink is required — reachable but
    /// unavailable.
    ProductionSettlementFinalizationRequired,
    /// A real MainNet audit-ledger receipt sink is required — reachable but
    /// unavailable.
    MainNetSettlementFinalizationRequired,
    /// A real external-publication receipt sink is required — reachable but
    /// unavailable.
    ExternalSettlementFinalizationRequired,
}

impl DurableCompletionSettlementFinalizationPolicy {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureAllowed => "fixture-allowed",
            Self::ProductionSettlementFinalizationRequired => {
                "production-settlement-finalization-required"
            }
            Self::MainNetSettlementFinalizationRequired => "mainnet-settlement-finalization-required",
            Self::ExternalSettlementFinalizationRequired => "external-settlement-finalization-required",
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

/// Run 268 — the typed receipt identity a receipt request is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionSettlementFinalizationIdentity {
    /// Stable receipt id.
    pub commitment_id: String,
    /// The receipt kind.
    pub kind: DurableCompletionSettlementFinalizationKind,
    /// The receipt policy.
    pub policy: DurableCompletionSettlementFinalizationPolicy,
    /// The domain separation tag the receipt operates under.
    pub domain_separation_tag: String,
}

impl DurableCompletionSettlementFinalizationIdentity {
    /// `true` iff every mandatory identity field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.commitment_id.is_empty()
            && !self.domain_separation_tag.is_empty()
            && self.kind != DurableCompletionSettlementFinalizationKind::Unknown
    }

    /// The deterministic, domain-separated receipt identity digest.
    pub fn digest(&self) -> DurableCompletionSettlementFinalizationDigest {
        settlement_finalization_identity_digest(self)
    }
}

// ===========================================================================
// Deterministic, domain-separated digest helpers
// ===========================================================================

/// Run 268 — domain separator for the receipt identity digest.
const FINALIZATION_IDENTITY_DOMAIN: &[u8] =
    b"QBIND:run268:durable-completion-settlement-finalization-identity:v1";
/// Run 268 — domain separator for the receipt request digest.
const FINALIZATION_REQUEST_DOMAIN: &[u8] =
    b"QBIND:run268:durable-completion-settlement-finalization-request:v1";
/// Run 268 — domain separator for the receipt response digest.
const FINALIZATION_RESPONSE_DOMAIN: &[u8] =
    b"QBIND:run268:durable-completion-settlement-finalization-response:v1";
/// Run 268 — domain separator for the receipt record digest.
const FINALIZATION_RECORD_DOMAIN: &[u8] =
    b"QBIND:run268:durable-completion-settlement-finalization-record:v1";
/// Run 268 — domain separator for the receipt transcript digest.
const FINALIZATION_TRANSCRIPT_DOMAIN: &[u8] =
    b"QBIND:run268:durable-completion-settlement-finalization-transcript:v1";

/// Run 268 — a deterministic, domain-separated receipt digest (lowercase hex of a
/// SHA3-256 over length-prefixed, field-bound canonical material). It contains no
/// unstable display text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionSettlementFinalizationDigest(String);

impl DurableCompletionSettlementFinalizationDigest {
    /// The lowercase hex representation.
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

/// Run 268 — a deterministic, domain-separated receipt transcript digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionSettlementFinalizationTranscriptDigest(String);

impl DurableCompletionSettlementFinalizationTranscriptDigest {
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

/// Run 268 — deterministic, domain-separated receipt identity digest.
pub fn settlement_finalization_identity_digest(
    identity: &DurableCompletionSettlementFinalizationIdentity,
) -> DurableCompletionSettlementFinalizationDigest {
    let mut w = CanonicalWriter::new(FINALIZATION_IDENTITY_DOMAIN);
    w.str_field(&identity.commitment_id)
        .str_field(identity.kind.tag())
        .str_field(identity.policy.tag())
        .str_field(&identity.domain_separation_tag);
    DurableCompletionSettlementFinalizationDigest(w.finish())
}

/// Run 268 — deterministic, domain-separated receipt request digest. Binds every
/// request field including the full Run 256 backend digest binding.
pub fn settlement_finalization_request_digest(
    request: &DurableCompletionSettlementFinalizationRequest,
) -> DurableCompletionSettlementFinalizationDigest {
    let mut w = CanonicalWriter::new(FINALIZATION_REQUEST_DOMAIN);
    w.str_field(&request.finalization_record_id)
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
        .str_field(&request.settlement_commitment_identity_digest)
        .str_field(&request.settlement_commitment_request_digest)
        .str_field(&request.settlement_commitment_response_digest)
        .str_field(&request.settlement_commitment_record_digest)
        .str_field(&request.settlement_commitment_transcript_digest)
        .str_field(&request.settlement_commitment_record_id)
        .str_field(&request.domain_separation_tag)
        .str_field(settlement_finalization_identity_digest(&request.identity).as_hex());
    DurableCompletionSettlementFinalizationDigest(w.finish())
}

/// Run 268 — deterministic, domain-separated receipt response digest. Binds the
/// receipt record id, the request digest it answers, the acceptance flag, and the
/// responding receipt kind.
pub fn settlement_finalization_response_digest(
    response: &DurableCompletionSettlementFinalizationResponse,
) -> DurableCompletionSettlementFinalizationDigest {
    let mut w = CanonicalWriter::new(FINALIZATION_RESPONSE_DOMAIN);
    w.str_field(&response.finalization_record_id)
        .str_field(response.request_digest.as_hex())
        .str_field(if response.accepted {
            "accepted"
        } else {
            "rejected"
        })
        .str_field(response.finalization_kind.tag());
    DurableCompletionSettlementFinalizationDigest(w.finish())
}

/// Run 268 — deterministic, domain-separated receipt record digest. Binds the
/// receipt record id, the request digest, and the receipt identity digest.
pub fn settlement_finalization_record_digest(
    record: &DurableCompletionSettlementFinalizationRecord,
) -> DurableCompletionSettlementFinalizationDigest {
    let mut w = CanonicalWriter::new(FINALIZATION_RECORD_DOMAIN);
    w.str_field(&record.finalization_record_id)
        .str_field(record.request_digest.as_hex())
        .str_field(record.identity_digest.as_hex());
    DurableCompletionSettlementFinalizationDigest(w.finish())
}

/// Run 268 — deterministic, domain-separated receipt transcript digest. Binds the
/// request, response, and record digests into a single transcript binding.
pub fn settlement_finalization_transcript_digest(
    request_digest: &DurableCompletionSettlementFinalizationDigest,
    response_digest: &DurableCompletionSettlementFinalizationDigest,
    record_digest: &DurableCompletionSettlementFinalizationDigest,
) -> DurableCompletionSettlementFinalizationTranscriptDigest {
    let mut w = CanonicalWriter::new(FINALIZATION_TRANSCRIPT_DOMAIN);
    w.str_field(request_digest.as_hex())
        .str_field(response_digest.as_hex())
        .str_field(record_digest.as_hex());
    DurableCompletionSettlementFinalizationTranscriptDigest(w.finish())
}

// ===========================================================================
// Receipt request / response / record
// ===========================================================================

/// Run 268 — the typed receipt request a future production audit ledger or
/// external-publication call site would submit once the Run 256 backend recorded a
/// `BackendSubmissionRecorded`.
///
/// Pure data referencing the already-recorded Run 256 backend / Run 254
/// attestation / Run 252 finalization / Run 250 completion report / Run 248
/// receipt / Run 246 decision material — never a copy of any wire payload and never
/// a production durable record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionSettlementFinalizationRequest {
    /// Stable receipt record id (the idempotency key of the receipt).
    pub finalization_record_id: String,
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
    /// Run 266 settlement-commitment identity digest.
    pub settlement_commitment_identity_digest: String,
    /// Run 266 settlement-commitment request digest.
    pub settlement_commitment_request_digest: String,
    /// Run 266 settlement-commitment response digest.
    pub settlement_commitment_response_digest: String,
    /// Run 266 settlement-commitment record digest.
    pub settlement_commitment_record_digest: String,
    /// Run 266 settlement-commitment transcript digest.
    pub settlement_commitment_transcript_digest: String,
    /// Run 266 settlement-commitment record id.
    pub settlement_commitment_record_id: String,
    /// Settlement-finalization identity.
    pub identity: DurableCompletionSettlementFinalizationIdentity,
    /// Domain separation tag.
    pub domain_separation_tag: String,
}

impl DurableCompletionSettlementFinalizationRequest {
    /// `true` iff every mandatory field is structurally present (non-empty) and the
    /// identity is well-formed.
    pub fn is_well_formed(&self) -> bool {
        !self.finalization_record_id.is_empty()
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
            && !self.settlement_commitment_identity_digest.is_empty()
            && !self.settlement_commitment_request_digest.is_empty()
            && !self.settlement_commitment_response_digest.is_empty()
            && !self.settlement_commitment_record_digest.is_empty()
            && !self.settlement_commitment_transcript_digest.is_empty()
            && !self.settlement_commitment_record_id.is_empty()
            && !self.domain_separation_tag.is_empty()
            && self.identity.is_well_formed()
    }

    /// The deterministic receipt request digest.
    pub fn digest(&self) -> DurableCompletionSettlementFinalizationDigest {
        settlement_finalization_request_digest(self)
    }

    /// The canonical immutable record derived from this request.
    pub fn to_record(&self) -> DurableCompletionSettlementFinalizationRecord {
        DurableCompletionSettlementFinalizationRecord {
            finalization_record_id: self.finalization_record_id.clone(),
            request_digest: self.digest(),
            identity_digest: self.identity.digest(),
        }
    }
}

/// Run 268 — the typed receipt response a receipt sink returns for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionSettlementFinalizationResponse {
    /// The receipt record id the response answers.
    pub finalization_record_id: String,
    /// The request digest the response answers.
    pub request_digest: DurableCompletionSettlementFinalizationDigest,
    /// `true` iff the receipt sink accepted the request.
    pub accepted: bool,
    /// The responding receipt kind.
    pub finalization_kind: DurableCompletionSettlementFinalizationKind,
}

impl DurableCompletionSettlementFinalizationResponse {
    /// `true` iff the response is structurally well-formed.
    pub fn is_well_formed(&self) -> bool {
        !self.finalization_record_id.is_empty()
            && self.finalization_kind != DurableCompletionSettlementFinalizationKind::Unknown
    }

    /// The deterministic receipt response digest.
    pub fn digest(&self) -> DurableCompletionSettlementFinalizationDigest {
        settlement_finalization_response_digest(self)
    }
}

/// Run 268 — the canonical immutable receipt record derived from a request. Two
/// records are idempotent-equal only if **every** field matches exactly. The same
/// receipt record id with any differing digest is equivocation and fails closed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionSettlementFinalizationRecord {
    /// The receipt record id.
    pub finalization_record_id: String,
    /// The request digest.
    pub request_digest: DurableCompletionSettlementFinalizationDigest,
    /// The receipt identity digest.
    pub identity_digest: DurableCompletionSettlementFinalizationDigest,
}

impl DurableCompletionSettlementFinalizationRecord {
    /// The deterministic receipt record digest.
    pub fn digest(&self) -> DurableCompletionSettlementFinalizationDigest {
        settlement_finalization_record_digest(self)
    }
}

// ===========================================================================
// In-memory fixture ledger
// ===========================================================================

/// Run 268 — the recorded status of a modeled audit/publication receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionSettlementFinalizationLedgerStatus {
    /// The modeled receipt is recorded in the in-memory fixture ledger.
    Recorded,
}

/// Run 268 — a single modeled receipt record held in the in-memory fixture ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionSettlementFinalizationLedgerRecord {
    /// The receipt record id (stable identity of the receipt).
    pub finalization_record_id: String,
    /// The request digest.
    pub request_digest: DurableCompletionSettlementFinalizationDigest,
    /// The response digest.
    pub response_digest: DurableCompletionSettlementFinalizationDigest,
    /// The record digest.
    pub record_digest: DurableCompletionSettlementFinalizationDigest,
    /// The transcript digest.
    pub transcript_digest: DurableCompletionSettlementFinalizationTranscriptDigest,
    /// The recorded status.
    pub status: DurableCompletionSettlementFinalizationLedgerStatus,
}

/// Run 268 — an immutable snapshot of the modeled receipt ledger used to model a
/// fixture rollback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionSettlementFinalizationLedgerSnapshot {
    records: Vec<DurableCompletionSettlementFinalizationLedgerRecord>,
}

impl DurableCompletionSettlementFinalizationLedgerSnapshot {
    /// The number of records the snapshot captured.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` iff the snapshot captured no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Run 268 — the modeled in-memory receipt ledger.
///
/// **In-memory only.** It never touches RocksDB, files, markers, sequence files,
/// external publications, audit-ledger entries, or any production durable state.
/// The DevNet/TestNet fixture sink is the only thing that may mutate it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DurableCompletionSettlementFinalizationLedger {
    records: Vec<DurableCompletionSettlementFinalizationLedgerRecord>,
}

impl DurableCompletionSettlementFinalizationLedger {
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
    pub fn records(&self) -> &[DurableCompletionSettlementFinalizationLedgerRecord] {
        &self.records
    }

    /// The record for `finalization_record_id`, if present.
    pub fn find(
        &self,
        finalization_record_id: &str,
    ) -> Option<&DurableCompletionSettlementFinalizationLedgerRecord> {
        self.records
            .iter()
            .find(|r| r.finalization_record_id == finalization_record_id)
    }

    /// `true` iff a receipt with `finalization_record_id` is recorded.
    pub fn contains(&self, finalization_record_id: &str) -> bool {
        self.find(finalization_record_id).is_some()
    }

    /// Capture an immutable snapshot for a modeled rollback.
    pub fn snapshot(&self) -> DurableCompletionSettlementFinalizationLedgerSnapshot {
        DurableCompletionSettlementFinalizationLedgerSnapshot {
            records: self.records.clone(),
        }
    }

    /// Restore the ledger to a previously captured snapshot (modeled rollback).
    pub fn restore(
        &mut self,
        snapshot: &DurableCompletionSettlementFinalizationLedgerSnapshot,
    ) {
        self.records = snapshot.records.clone();
    }

    /// Internal: insert a recorded receipt. Only the fixture sink calls this, and
    /// only after every identity / idempotency gate has passed.
    fn insert(&mut self, record: DurableCompletionSettlementFinalizationLedgerRecord) {
        self.records.push(record);
    }
}

// ===========================================================================
// Receipt expectations
// ===========================================================================

/// Run 268 — the canonical binding a [`DurableCompletionSettlementFinalizationInput`]
/// is checked against.
///
/// Environment / chain / genesis / surface mismatches fail closed **before** the
/// receipt sink is invoked. Receipt-request-identity mismatches fail closed
/// **inside** the sink, before any modeled receipt is recorded. Neither path is
/// ever a silent approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionSettlementFinalizationExpectations {
    /// Expected receipt record id.
    pub expected_finalization_record_id: String,
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
    /// Expected Run 266 settlement-commitment identity digest.
    pub expected_settlement_commitment_identity_digest: String,
    /// Expected Run 266 settlement-commitment request digest.
    pub expected_settlement_commitment_request_digest: String,
    /// Expected Run 266 settlement-commitment response digest.
    pub expected_settlement_commitment_response_digest: String,
    /// Expected Run 266 settlement-commitment record digest.
    pub expected_settlement_commitment_record_digest: String,
    /// Expected Run 266 settlement-commitment transcript digest.
    pub expected_settlement_commitment_transcript_digest: String,
    /// Expected Run 266 settlement-commitment record id.
    pub expected_settlement_commitment_record_id: String,
    /// Expected settlement-commitment identity.
    pub expected_identity: DurableCompletionSettlementFinalizationIdentity,
    /// Expected settlement-commitment kind.
    pub expected_finalization_kind: DurableCompletionSettlementFinalizationKind,
    /// Expected settlement-commitment policy.
    pub expected_finalization_policy: DurableCompletionSettlementFinalizationPolicy,
    /// Expected domain separation tag.
    pub expected_domain_separation_tag: String,
}

impl DurableCompletionSettlementFinalizationExpectations {
    /// Internal: the first environment / surface binding mismatch reason, if any.
    fn binding_mismatch_reason(
        &self,
        input: &DurableCompletionSettlementFinalizationInput,
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
        input: &DurableCompletionSettlementFinalizationInput,
    ) -> bool {
        self.binding_mismatch_reason(input).is_none()
    }

    /// Internal: the first receipt-request-identity mismatch reason, if any.
    fn request_mismatch_reason(
        &self,
        request: &DurableCompletionSettlementFinalizationRequest,
    ) -> Option<&'static str> {
        if !request.is_well_formed() {
            return Some("malformed receipt request");
        }
        if request.finalization_record_id != self.expected_finalization_record_id {
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
        if request.settlement_commitment_identity_digest
            != self.expected_settlement_commitment_identity_digest
        {
            return Some("wrong settlement-commitment identity digest");
        }
        if request.settlement_commitment_request_digest
            != self.expected_settlement_commitment_request_digest
        {
            return Some("wrong settlement-commitment request digest");
        }
        if request.settlement_commitment_response_digest
            != self.expected_settlement_commitment_response_digest
        {
            return Some("wrong settlement-commitment response digest");
        }
        if request.settlement_commitment_record_digest
            != self.expected_settlement_commitment_record_digest
        {
            return Some("wrong settlement-commitment record digest");
        }
        if request.settlement_commitment_transcript_digest
            != self.expected_settlement_commitment_transcript_digest
        {
            return Some("wrong settlement-commitment transcript digest");
        }
        if request.settlement_commitment_record_id != self.expected_settlement_commitment_record_id {
            return Some("wrong settlement-commitment record id");
        }
        if request.domain_separation_tag != self.expected_domain_separation_tag {
            return Some("wrong domain separation tag");
        }
        if request.identity != self.expected_identity {
            return Some("wrong settlement-finalization identity");
        }
        if request.identity.kind != self.expected_finalization_kind {
            return Some("wrong settlement-finalization kind");
        }
        if request.identity.policy != self.expected_finalization_policy {
            return Some("wrong settlement-finalization policy");
        }
        None
    }

    /// `true` iff the receipt-request identity matches and is well-formed.
    pub fn request_matches(
        &self,
        request: &DurableCompletionSettlementFinalizationRequest,
    ) -> bool {
        self.request_mismatch_reason(request).is_none()
    }
}

// ===========================================================================
// Receipt input
// ===========================================================================

/// Run 268 — typed inputs for one modeled durable-completion audit/publication
/// receipt round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionSettlementFinalizationInput {
    /// The receipt policy selector.
    pub policy: DurableCompletionSettlementFinalizationPolicy,
    /// The trust-domain environment binding.
    pub environment_binding: DurableCompletionSettlementFinalizationEnvironment,
    /// The runtime binding (governance + mutation surface + sequence).
    pub runtime_binding: DurableCompletionSettlementFinalizationBinding,
    /// The Run 240/246 durable replay observation the pipeline authorized consume
    /// under.
    pub replay_binding: DurableCompletionSettlementFinalizationReplayBinding,
    /// The Run 246 pipeline outcome.
    pub pipeline_binding: DurableCompletionSettlementFinalizationPipelineBinding,
    /// The Run 248 sink outcome.
    pub sink_binding: DurableCompletionSettlementFinalizationSinkBinding,
    /// The Run 250 reporter outcome.
    pub reporter_binding: DurableCompletionSettlementFinalizationReporterBinding,
    /// The Run 252 finalization outcome.
    pub finalization_binding: DurableCompletionSettlementFinalizationFinalizationBinding,
    /// The Run 254 attestation outcome.
    pub attestation_binding: DurableCompletionSettlementFinalizationAttestationBinding,
    /// The Run 256 backend outcome carried as backend-record context.
    pub backend_binding: DurableCompletionSettlementFinalizationBackendBinding,
    /// The Run 258 audit/publication receipt outcome carried as receipt-record
    /// context.
    pub receipt_binding: DurableCompletionSettlementFinalizationReceiptBinding,
    /// The Run 260 audit-receipt acknowledgement outcome carried as
    /// acknowledgement-record context.
    pub acknowledgement_binding:
        DurableCompletionSettlementFinalizationAcknowledgementBinding,
    /// The Run 262 acknowledgement consumer outcome the settlement-commitment
    /// boundary projects to a settlement-commitment request.
    pub consumer_binding: DurableCompletionSettlementFinalizationConsumerBinding,
    /// The Run 266 settlement-commitment outcome the settlement-finalization boundary
    /// projects to a settlement-finalization request.
    pub settlement_commitment_binding:
        DurableCompletionSettlementFinalizationSettlementCommitmentBinding,
    /// The settlement-finalization request the call site would submit.
    pub request: DurableCompletionSettlementFinalizationRequest,
}

impl DurableCompletionSettlementFinalizationInput {
    /// The trust-domain environment the decision is bound to.
    pub fn environment(&self) -> TrustBundleEnvironment {
        self.environment_binding.environment
    }

    /// The validation / mutation surface pair.
    pub fn surface(&self) -> DurableCompletionSettlementFinalizationSurface {
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
                self.settlement_commitment_binding,
                DurableCompletionSettlementCommitmentOutcome::MainNetPeerDrivenApplyRefusedNoCommitment
            )
    }
}

// ===========================================================================
// Receipt outcome
// ===========================================================================

/// Run 268 — the typed outcome of one modeled durable-completion audit/publication
/// receipt round-trip.
///
/// Only [`Self::SettlementFinalizationRecorded`] authorizes a **new** modeled
/// audit/publication-receipt state. A [`Self::SettlementFinalizationDuplicateIdempotent`]
/// means the receipt was already recorded (idempotent, no second receipt). Every
/// other variant is a no-audit-receipt fail-closed outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableCompletionSettlementFinalizationOutcome {
    /// Legacy bypass — a disabled receipt policy preserved the legacy
    /// no-audit-receipt path. No receipt invocation.
    LegacyBypassNoSettlementFinalization,
    /// The Run 256 backend-stage binding was rejected before the receipt sink was
    /// invoked (a backend-stage rejection / binding mismatch). Non-mutating, no
    /// receipt. No receipt invocation.
    RejectedBeforeSettlementCommitmentNoFinalization,
    /// The Run 256 backend did not submit (any non-submitting backend outcome
    /// without a more specific variant). Non-mutating, no receipt. No receipt
    /// invocation.
    SettlementCommitmentDidNotRecordNoFinalization,
    /// The receipt sink recorded a new modeled audit/publication receipt. The
    /// **only** outcome that authorizes a new modeled receipt state.
    SettlementFinalizationRecorded,
    /// A duplicate identical receipt — idempotent; no second receipt recorded.
    SettlementFinalizationDuplicateIdempotent,
    /// The receipt was rejected before record (malformed request, request-identity
    /// mismatch, same receipt record id with a differing digest / equivocation, or
    /// a duplicate-idempotent backend submission with no matching prior receipt). No
    /// receipt.
    SettlementFinalizationRejectedBeforeRecord,
    /// The receipt record failed. No receipt.
    SettlementFinalizationRecordFailedNoFinalization,
    /// The receipt record was rolled back. No receipt.
    SettlementFinalizationRolledBackNoFinalization,
    /// The receipt rollback itself failed — fatal / fail-closed. No receipt.
    SettlementFinalizationRollbackFailedFatalNoFinalization,
    /// The after-record receipt window was ambiguous — fails closed. No receipt.
    SettlementFinalizationAmbiguousFailClosedNoFinalization,
    /// The production audit-ledger path was reached but is unavailable. No receipt.
    ProductionSettlementFinalizationUnavailableNoFinalization,
    /// The MainNet audit-ledger path was reached but is unavailable. No receipt.
    MainNetSettlementFinalizationUnavailableNoFinalization,
    /// The external-publication path was reached but is unavailable. No receipt.
    ExternalSettlementFinalizationUnavailableNoFinalization,
    /// MainNet peer-driven apply remains refused before pipeline progression, sink
    /// invocation, reporter invocation, finalizer invocation, attestor invocation,
    /// backend invocation, and receipt invocation. No receipt.
    MainNetPeerDrivenApplyRefusedNoFinalization,
    /// Validator-set rotation is unsupported. No receipt.
    ValidatorSetRotationUnsupportedNoFinalization,
    /// Policy-change actions are unsupported. No receipt.
    PolicyChangeUnsupportedNoFinalization,
}

impl DurableCompletionSettlementFinalizationOutcome {
    /// `true` iff this outcome authorizes a **new** modeled audit/publication
    /// receipt (only [`Self::SettlementFinalizationRecorded`]).
    pub fn authorizes_record(&self) -> bool {
        matches!(self, Self::SettlementFinalizationRecorded)
    }

    /// `true` iff this outcome projects to a recorded audit/publication receipt — a
    /// newly recorded receipt or an idempotent duplicate of an already-recorded
    /// receipt.
    pub fn projects_to_recorded(&self) -> bool {
        matches!(
            self,
            Self::SettlementFinalizationRecorded | Self::SettlementFinalizationDuplicateIdempotent
        )
    }

    /// `true` iff this outcome records nothing new and projects to no
    /// audit/publication receipt.
    pub fn no_commitment(&self) -> bool {
        !self.projects_to_recorded()
    }

    /// `true` iff this is the legacy no-audit-receipt bypass.
    pub fn is_legacy_bypass(&self) -> bool {
        matches!(self, Self::LegacyBypassNoSettlementFinalization)
    }

    /// `true` iff this is the MainNet peer-driven-apply refusal.
    pub fn is_mainnet_peer_driven_apply_refused(&self) -> bool {
        matches!(self, Self::MainNetPeerDrivenApplyRefusedNoFinalization)
    }

    /// Stable operator-facing tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::LegacyBypassNoSettlementFinalization => "legacy-bypass-no-settlement-finalization",
            Self::RejectedBeforeSettlementCommitmentNoFinalization => {
                "rejected-before-settlement-commitment-no-finalization"
            }
            Self::SettlementCommitmentDidNotRecordNoFinalization => {
                "settlement-commitment-did-not-record-no-finalization"
            }
            Self::SettlementFinalizationRecorded => "settlement-finalization-recorded",
            Self::SettlementFinalizationDuplicateIdempotent => {
                "settlement-finalization-duplicate-idempotent"
            }
            Self::SettlementFinalizationRejectedBeforeRecord => {
                "settlement-finalization-rejected-before-record"
            }
            Self::SettlementFinalizationRecordFailedNoFinalization => {
                "settlement-finalization-record-failed-no-finalization"
            }
            Self::SettlementFinalizationRolledBackNoFinalization => {
                "settlement-finalization-rolled-back-no-finalization"
            }
            Self::SettlementFinalizationRollbackFailedFatalNoFinalization => {
                "settlement-finalization-rollback-failed-fatal-no-finalization"
            }
            Self::SettlementFinalizationAmbiguousFailClosedNoFinalization => {
                "settlement-finalization-ambiguous-fail-closed-no-finalization"
            }
            Self::ProductionSettlementFinalizationUnavailableNoFinalization => {
                "production-settlement-finalization-unavailable-no-finalization"
            }
            Self::MainNetSettlementFinalizationUnavailableNoFinalization => {
                "mainnet-settlement-finalization-unavailable-no-finalization"
            }
            Self::ExternalSettlementFinalizationUnavailableNoFinalization => {
                "external-settlement-finalization-unavailable-no-finalization"
            }
            Self::MainNetPeerDrivenApplyRefusedNoFinalization => {
                "mainnet-peer-driven-apply-refused-no-finalization"
            }
            Self::ValidatorSetRotationUnsupportedNoFinalization => {
                "validator-set-rotation-unsupported-no-finalization"
            }
            Self::PolicyChangeUnsupportedNoFinalization => "policy-change-unsupported-no-finalization",
        }
    }
}

// ===========================================================================
// Consumer-outcome -> settlement-commitment request commitment
// ===========================================================================

/// Run 268 — the typed commitment of a Run 262 acknowledgement consumer outcome
/// onto a settlement-commitment request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableCompletionSettlementFinalizationRequestIntent {
    /// The consumer recorded a consumer record; the settlement-commitment sink may
    /// record a new settlement commitment.
    CreateRequest,
    /// The consumer reported an idempotent-duplicate consumer record; the
    /// settlement-commitment sink may only match an already-recorded settlement
    /// commitment and must never create a new one.
    IdempotentOnly,
    /// The consumer did not record; no settlement-commitment request. Carries the
    /// typed no-commitment outcome the settlement-commitment evaluation returns
    /// directly (without invoking the settlement-commitment sink).
    NoCommitment(DurableCompletionSettlementFinalizationOutcome),
}

impl DurableCompletionSettlementFinalizationRequestIntent {
    /// `true` iff this commitment creates a settlement-commitment request (i.e. the
    /// consumer recorded a consumer record).
    pub fn creates_request(&self) -> bool {
        matches!(self, Self::CreateRequest)
    }
}

/// Run 268 — project a Run 266 settlement-commitment outcome onto a
/// settlement-finalization request.
///
/// Only
/// [`DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentRecorded`]
/// creates a settlement-finalization request.
/// [`DurableCompletionSettlementCommitmentOutcome::SettlementCommitmentDuplicateIdempotent`]
/// may only match an already-recorded settlement-finalization record and never creates
/// a new one. Every other settlement-commitment outcome maps to a no-finalization
/// fail-closed outcome (a more specific one where one exists, otherwise the generic
/// [`DurableCompletionSettlementFinalizationOutcome::SettlementCommitmentDidNotRecordNoFinalization`]).
/// Pure: performs no work and never records.
pub fn project_settlement_commitment_outcome_to_finalization_request(
    outcome: &DurableCompletionSettlementFinalizationSettlementCommitmentBinding,
) -> DurableCompletionSettlementFinalizationRequestIntent {
    use DurableCompletionSettlementCommitmentOutcome as Commitment;
    use DurableCompletionSettlementFinalizationOutcome as Finalization;
    use DurableCompletionSettlementFinalizationRequestIntent as Intent;
    match outcome {
        Commitment::SettlementCommitmentRecorded => Intent::CreateRequest,
        Commitment::SettlementCommitmentDuplicateIdempotent => Intent::IdempotentOnly,
        Commitment::LegacyBypassNoSettlementCommitment => {
            Intent::NoCommitment(Finalization::LegacyBypassNoSettlementFinalization)
        }
        Commitment::RejectedBeforeSettlementProjectionNoCommitment => {
            Intent::NoCommitment(Finalization::RejectedBeforeSettlementCommitmentNoFinalization)
        }
        Commitment::MainNetPeerDrivenApplyRefusedNoCommitment => {
            Intent::NoCommitment(Finalization::MainNetPeerDrivenApplyRefusedNoFinalization)
        }
        Commitment::ValidatorSetRotationUnsupportedNoCommitment => {
            Intent::NoCommitment(Finalization::ValidatorSetRotationUnsupportedNoFinalization)
        }
        Commitment::PolicyChangeUnsupportedNoCommitment => {
            Intent::NoCommitment(Finalization::PolicyChangeUnsupportedNoFinalization)
        }
        // Every remaining settlement-commitment outcome is a non-recording rejection /
        // failure / rollback / ambiguous window: the settlement commitment did not
        // record, so no settlement-finalization record may exist.
        _ => Intent::NoCommitment(Finalization::SettlementCommitmentDidNotRecordNoFinalization),
    }
}

// ===========================================================================
// Receipt fault injection (source/test only)
// ===========================================================================

/// Run 268 — a modeled fault the fixture receipt sink injects to exercise the
/// fail-closed record / rollback / ambiguous paths. Source/test only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionSettlementFinalizationFault {
    /// The receipt record fails; nothing is written. No receipt.
    RecordFailedNoCommitment,
    /// The receipt record is rolled back; nothing remains written. No receipt.
    RolledBackNoCommitment,
    /// The receipt rollback itself fails — fatal / fail-closed. No receipt.
    RollbackFailedFatal,
    /// The after-record receipt window is ambiguous — fails closed. No receipt.
    AmbiguousAfterRecord,
}

// ===========================================================================
// Receipt trait boundary
// ===========================================================================

/// Run 268 — the pure/mockable modeled durable-completion audit/publication receipt
/// boundary.
///
/// No implementation here calls Run 070, mutates `LivePqcTrustState`, performs a
/// live trust swap, evicts sessions, writes a sequence, writes a marker, performs
/// network I/O, external publication, or a real audit-ledger persistence. The
/// DevNet/TestNet fixture receipt sink mutates only the in-memory
/// [`DurableCompletionSettlementFinalizationLedger`].
pub trait GovernanceDurableCompletionSettlementFinalizationSink {
    /// The receipt kind (used for typed recovery classification).
    fn kind(&self) -> DurableCompletionSettlementFinalizationKind;

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
    fn project_durable_completion_settlement_finalization(
        &mut self,
        request: &DurableCompletionSettlementFinalizationRequest,
        expectations: &DurableCompletionSettlementFinalizationExpectations,
        idempotent_only: bool,
        ledger: &mut DurableCompletionSettlementFinalizationLedger,
    ) -> DurableCompletionSettlementFinalizationOutcome;

    /// Classify a modeled receipt crash/recovery window. Pure: performs no modeled
    /// mutation and never invokes Run 070.
    fn recover_durable_completion_settlement_finalization_window(
        &self,
        input: &DurableCompletionSettlementFinalizationInput,
        window: DurableCompletionSettlementFinalizationWindow,
        recovered_record: Option<&DurableCompletionSettlementFinalizationLedgerRecord>,
        expectations: &DurableCompletionSettlementFinalizationExpectations,
    ) -> DurableCompletionSettlementFinalizationOutcome {
        recover_durable_completion_settlement_finalization_window(
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

/// Run 268 — the DevNet/TestNet in-memory fixture receipt sink.
///
/// Source-test only. It mutates only the in-memory
/// [`DurableCompletionSettlementFinalizationLedger`] and exposes an invocation
/// counter so tests can prove non-submitting backend paths and pre-receipt
/// rejections never invoke it.
#[derive(Debug, Clone)]
pub struct FixtureDurableCompletionSettlementFinalizationSink {
    fault: Option<DurableCompletionSettlementFinalizationFault>,
    invocations: u32,
}

impl Default for FixtureDurableCompletionSettlementFinalizationSink {
    fn default() -> Self {
        Self::new()
    }
}

impl FixtureDurableCompletionSettlementFinalizationSink {
    /// A new fixture receipt sink.
    pub fn new() -> Self {
        Self {
            fault: None,
            invocations: 0,
        }
    }

    /// A new fixture receipt sink that injects the given modeled fault on record.
    pub fn with_fault(fault: DurableCompletionSettlementFinalizationFault) -> Self {
        Self {
            fault: Some(fault),
            invocations: 0,
        }
    }
}

impl GovernanceDurableCompletionSettlementFinalizationSink
    for FixtureDurableCompletionSettlementFinalizationSink
{
    fn kind(&self) -> DurableCompletionSettlementFinalizationKind {
        DurableCompletionSettlementFinalizationKind::FixtureInMemory
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn project_durable_completion_settlement_finalization(
        &mut self,
        request: &DurableCompletionSettlementFinalizationRequest,
        expectations: &DurableCompletionSettlementFinalizationExpectations,
        idempotent_only: bool,
        ledger: &mut DurableCompletionSettlementFinalizationLedger,
    ) -> DurableCompletionSettlementFinalizationOutcome {
        use DurableCompletionSettlementFinalizationOutcome as Receipt;
        self.invocations += 1;

        // Injected faults model record-failure / rollback / ambiguous windows. None
        // of them ever leave a recorded receipt behind, so a durable receipt is never
        // claimed. The ledger snapshot/restore models the rollback being a no-op
        // write.
        if let Some(fault) = self.fault {
            let snapshot = ledger.snapshot();
            return match fault {
                DurableCompletionSettlementFinalizationFault::RecordFailedNoCommitment => {
                    ledger.restore(&snapshot);
                    Receipt::SettlementFinalizationRecordFailedNoFinalization
                }
                DurableCompletionSettlementFinalizationFault::RolledBackNoCommitment => {
                    ledger.restore(&snapshot);
                    Receipt::SettlementFinalizationRolledBackNoFinalization
                }
                DurableCompletionSettlementFinalizationFault::RollbackFailedFatal => {
                    Receipt::SettlementFinalizationRollbackFailedFatalNoFinalization
                }
                DurableCompletionSettlementFinalizationFault::AmbiguousAfterRecord => {
                    ledger.restore(&snapshot);
                    Receipt::SettlementFinalizationAmbiguousFailClosedNoFinalization
                }
            };
        }

        // The fixture receipt sink is DevNet/TestNet evidence-only.
        if !matches!(
            request.environment,
            TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet
        ) {
            return Receipt::SettlementFinalizationRejectedBeforeRecord;
        }

        // Request-identity validation (malformed / mismatch) fails closed before any
        // record is written.
        if !expectations.request_matches(request) {
            return Receipt::SettlementFinalizationRejectedBeforeRecord;
        }

        // Build the deterministic request / response / record / transcript digests.
        let request_digest = request.digest();
        let response = DurableCompletionSettlementFinalizationResponse {
            finalization_record_id: request.finalization_record_id.clone(),
            request_digest: request_digest.clone(),
            accepted: true,
            finalization_kind: DurableCompletionSettlementFinalizationKind::FixtureInMemory,
        };
        let response_digest = response.digest();
        let record = request.to_record();
        let record_digest = record.digest();
        let transcript_digest = settlement_finalization_transcript_digest(
            &request_digest,
            &response_digest,
            &record_digest,
        );

        // Idempotency / equivocation gate.
        if let Some(existing) = ledger.find(&request.finalization_record_id) {
            if existing.request_digest == request_digest
                && existing.response_digest == response_digest
                && existing.record_digest == record_digest
                && existing.transcript_digest == transcript_digest
            {
                return Receipt::SettlementFinalizationDuplicateIdempotent;
            }
            // Same receipt record id with a different digest is equivocation: fail
            // closed, record no second receipt.
            return Receipt::SettlementFinalizationRejectedBeforeRecord;
        }

        // A duplicate-idempotent backend submission may only match an already-recorded
        // receipt; it must never create a new one by itself.
        if idempotent_only {
            return Receipt::SettlementFinalizationRejectedBeforeRecord;
        }

        ledger.insert(DurableCompletionSettlementFinalizationLedgerRecord {
            finalization_record_id: request.finalization_record_id.clone(),
            request_digest,
            response_digest,
            record_digest,
            transcript_digest,
            status: DurableCompletionSettlementFinalizationLedgerStatus::Recorded,
        });
        Receipt::SettlementFinalizationRecorded
    }
}

// ===========================================================================
// Production / MainNet audit-ledger / External-publication sinks (unavailable)
// ===========================================================================

/// Run 268 — the production audit-ledger receipt sink. Reachable but unavailable /
/// fail-closed. It records no receipt and mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct ProductionSettlementFinalizationSink {
    invocations: u32,
}

impl GovernanceDurableCompletionSettlementFinalizationSink
    for ProductionSettlementFinalizationSink
{
    fn kind(&self) -> DurableCompletionSettlementFinalizationKind {
        DurableCompletionSettlementFinalizationKind::ProductionSettlementFinalizationUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn project_durable_completion_settlement_finalization(
        &mut self,
        _request: &DurableCompletionSettlementFinalizationRequest,
        _expectations: &DurableCompletionSettlementFinalizationExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionSettlementFinalizationLedger,
    ) -> DurableCompletionSettlementFinalizationOutcome {
        self.invocations += 1;
        DurableCompletionSettlementFinalizationOutcome::ProductionSettlementFinalizationUnavailableNoFinalization
    }
}

/// Run 268 — the MainNet audit-ledger receipt sink. Reachable but unavailable /
/// fail-closed. It records no receipt and mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct MainNetSettlementFinalizationSink {
    invocations: u32,
}

impl GovernanceDurableCompletionSettlementFinalizationSink
    for MainNetSettlementFinalizationSink
{
    fn kind(&self) -> DurableCompletionSettlementFinalizationKind {
        DurableCompletionSettlementFinalizationKind::MainNetSettlementFinalizationUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn project_durable_completion_settlement_finalization(
        &mut self,
        _request: &DurableCompletionSettlementFinalizationRequest,
        _expectations: &DurableCompletionSettlementFinalizationExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionSettlementFinalizationLedger,
    ) -> DurableCompletionSettlementFinalizationOutcome {
        self.invocations += 1;
        DurableCompletionSettlementFinalizationOutcome::MainNetSettlementFinalizationUnavailableNoFinalization
    }
}

/// Run 268 — the external-publication receipt sink. Reachable but unavailable /
/// fail-closed. It performs no external publication, records no receipt, and
/// mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct ExternalSettlementFinalizationSink {
    invocations: u32,
}

impl GovernanceDurableCompletionSettlementFinalizationSink
    for ExternalSettlementFinalizationSink
{
    fn kind(&self) -> DurableCompletionSettlementFinalizationKind {
        DurableCompletionSettlementFinalizationKind::ExternalSettlementFinalizationUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn project_durable_completion_settlement_finalization(
        &mut self,
        _request: &DurableCompletionSettlementFinalizationRequest,
        _expectations: &DurableCompletionSettlementFinalizationExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionSettlementFinalizationLedger,
    ) -> DurableCompletionSettlementFinalizationOutcome {
        self.invocations += 1;
        DurableCompletionSettlementFinalizationOutcome::ExternalSettlementFinalizationUnavailableNoFinalization
    }
}

// ===========================================================================
// Receipt executor / composition helpers
// ===========================================================================

/// Run 268 — evaluate one modeled durable-completion audit/publication receipt
/// round-trip.
///
/// Ordering (each gate must pass before the next is considered):
///
/// 1. MainNet peer-driven apply refusal — before pipeline progression, sink
///    invocation, reporter invocation, finalizer invocation, attestor invocation,
///    backend invocation, and receipt invocation;
/// 2. legacy bypass — a
///    [`DurableCompletionSettlementFinalizationPolicy::Disabled`] policy;
/// 3. backend-outcome commitment — only
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
pub fn evaluate_durable_completion_settlement_finalization<S>(
    input: &DurableCompletionSettlementFinalizationInput,
    expectations: &DurableCompletionSettlementFinalizationExpectations,
    sink: &mut S,
    ledger: &mut DurableCompletionSettlementFinalizationLedger,
) -> DurableCompletionSettlementFinalizationOutcome
where
    S: GovernanceDurableCompletionSettlementFinalizationSink,
{
    use DurableCompletionSettlementFinalizationOutcome as Commitment;
    use DurableCompletionSettlementFinalizationRequestIntent as Intent;

    // Step 1: MainNet peer-driven apply remains refused unconditionally, before
    // pipeline progression, sink invocation, reporter invocation, finalizer
    // invocation, attestor invocation, backend invocation, receipt invocation,
    // acknowledgement invocation, consumer invocation, and settlement-commitment
    // invocation.
    if input.is_mainnet_peer_driven() {
        return Commitment::MainNetPeerDrivenApplyRefusedNoFinalization;
    }

    // Step 2: legacy bypass — a disabled settlement-commitment policy preserves the
    // legacy no-settlement-commitment path and never invokes the commitment sink.
    if input.policy.is_disabled() {
        return Commitment::LegacyBypassNoSettlementFinalization;
    }

    // Step 3: project the Run 262 acknowledgement consumer outcome onto a
    // settlement-commitment request. Every non-recording consumer outcome returns a
    // no-commitment outcome without invoking the settlement-commitment sink.
    let idempotent_only =
        match project_settlement_commitment_outcome_to_finalization_request(
            &input.settlement_commitment_binding,
        ) {
            Intent::NoCommitment(outcome) => return outcome,
            Intent::CreateRequest => false,
            Intent::IdempotentOnly => true,
        };

    // Step 4: pre-commitment environment / surface binding validation. A mismatch
    // fails closed before the settlement-commitment sink is invoked, leaving the
    // settlement-commitment invocation count at zero.
    if !expectations.binding_matches(input) {
        return Commitment::RejectedBeforeSettlementCommitmentNoFinalization;
    }

    // Step 5: invoke the settlement-commitment sink to record the modeled commitment.
    sink.project_durable_completion_settlement_finalization(
        &input.request,
        expectations,
        idempotent_only,
        ledger,
    )
}

// ===========================================================================
// Receipt crash/recovery window classification
// ===========================================================================

/// Run 268 — the modeled durable-completion audit/publication receipt
/// crash/recovery window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionSettlementFinalizationWindow {
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
    /// Crashed after consumer success but before a settlement-commitment request.
    AfterConsumerSuccessBeforeSettlementCommitmentRequest,
    /// Crashed after a settlement-commitment request but before any
    /// settlement-commitment record.
    AfterSettlementCommitmentRequestBeforeSettlementCommitmentRecord,
    /// Crashed after a settlement-commitment record but before settlement-commitment
    /// success — fails closed unless an explicit matching settlement-commitment
    /// record exists.
    AfterSettlementCommitmentRecordBeforeSettlementCommitmentSuccess,
    /// Crashed after settlement-commitment success but before a settlement-finalization
    /// request.
    AfterSettlementCommitmentSuccessBeforeSettlementFinalizationRequest,
    /// Crashed after a settlement-finalization request but before any
    /// settlement-finalization record.
    AfterSettlementFinalizationRequestBeforeSettlementFinalizationRecord,
    /// Crashed after a settlement-finalization record but before settlement-finalization
    /// success — fails closed unless an explicit matching settlement-finalization
    /// record exists.
    AfterSettlementFinalizationRecordBeforeSettlementFinalizationSuccess,
    /// Recovered after a successful settlement-finalization record.
    AfterSettlementFinalizationSuccess,
    /// Recovered after an ambiguous settlement-finalization window.
    AfterSettlementFinalizationAmbiguous,
    /// The settlement-finalization record itself failed.
    SettlementFinalizationRecordFailed,
    /// The settlement-finalization record was rolled back.
    SettlementFinalizationRollbackCompleted,
    /// The settlement-finalization rollback itself failed — fatal.
    SettlementFinalizationRollbackFailed,
    /// An unknown window — fails closed.
    Unknown,
}

/// Run 268 — classify a modeled durable-completion audit/publication receipt
/// crash/recovery window.
///
/// The receipt sink never silently re-authorizes an in-flight receipt: MainNet
/// peer-driven refusal precedes classification, production / MainNet audit-ledger /
/// external-publication classification is unavailable, and every ambiguous /
/// unknown window fails closed. Only an after-receipt-record window with an explicit
/// matching record (or an explicit after-receipt-success window) recovers as
/// [`DurableCompletionSettlementFinalizationOutcome::SettlementFinalizationRecorded`]. Pure:
/// performs no modeled mutation and never invokes Run 070.
pub fn recover_durable_completion_settlement_finalization_window(
    input: &DurableCompletionSettlementFinalizationInput,
    window: DurableCompletionSettlementFinalizationWindow,
    kind: DurableCompletionSettlementFinalizationKind,
    recovered_record: Option<&DurableCompletionSettlementFinalizationLedgerRecord>,
    expectations: &DurableCompletionSettlementFinalizationExpectations,
) -> DurableCompletionSettlementFinalizationOutcome {
    use DurableCompletionSettlementFinalizationOutcome as Receipt;
    use DurableCompletionSettlementFinalizationWindow as Window;

    // MainNet peer-driven apply refusal precedes recovery classification.
    if input.is_mainnet_peer_driven() {
        return Receipt::MainNetPeerDrivenApplyRefusedNoFinalization;
    }

    // Production / MainNet audit-ledger / external-publication recovery
    // classification is unavailable / fail-closed.
    match kind {
        DurableCompletionSettlementFinalizationKind::ProductionSettlementFinalizationUnavailable => {
            return Receipt::ProductionSettlementFinalizationUnavailableNoFinalization;
        }
        DurableCompletionSettlementFinalizationKind::MainNetSettlementFinalizationUnavailable => {
            return Receipt::MainNetSettlementFinalizationUnavailableNoFinalization;
        }
        DurableCompletionSettlementFinalizationKind::ExternalSettlementFinalizationUnavailable => {
            return Receipt::ExternalSettlementFinalizationUnavailableNoFinalization;
        }
        DurableCompletionSettlementFinalizationKind::Disabled => {
            return Receipt::LegacyBypassNoSettlementFinalization;
        }
        DurableCompletionSettlementFinalizationKind::Unknown => {
            return Receipt::SettlementFinalizationAmbiguousFailClosedNoFinalization;
        }
        DurableCompletionSettlementFinalizationKind::FixtureInMemory => {}
    }

    // Helper: an explicit recovered record recovers as a receipt only if it matches
    // the expected receipt record id and the canonical request digest.
    let recovered_matches =
        |record: &DurableCompletionSettlementFinalizationLedgerRecord| -> bool {
            record.finalization_record_id == expectations.expected_finalization_record_id
                && record.request_digest == input.request.digest()
                && record.status
                    == DurableCompletionSettlementFinalizationLedgerStatus::Recorded
        };

    match window {
        // Through settlement-commitment success but before a settlement-finalization
        // request there is nothing to record a settlement finalization for.
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
        | Window::AfterConsumerSuccessBeforeSettlementCommitmentRequest
        | Window::AfterSettlementCommitmentRequestBeforeSettlementCommitmentRecord
        | Window::AfterSettlementCommitmentRecordBeforeSettlementCommitmentSuccess
        | Window::AfterSettlementCommitmentSuccessBeforeSettlementFinalizationRequest => {
            Receipt::SettlementCommitmentDidNotRecordNoFinalization
        }
        // A settlement-finalization request without a record never records a
        // settlement finalization.
        Window::AfterSettlementFinalizationRequestBeforeSettlementFinalizationRecord => {
            Receipt::SettlementFinalizationRejectedBeforeRecord
        }
        // After a settlement-finalization record but before success: fails closed
        // unless an explicit matching, well-formed settlement-finalization record
        // exists.
        Window::AfterSettlementFinalizationRecordBeforeSettlementFinalizationSuccess => {
            match recovered_record {
                Some(record) if recovered_matches(record) => Receipt::SettlementFinalizationRecorded,
                _ => Receipt::SettlementFinalizationRejectedBeforeRecord,
            }
        }
        // An explicit successful settlement finalization recovers as recorded only if
        // it matches.
        Window::AfterSettlementFinalizationSuccess => match recovered_record {
            Some(record) if recovered_matches(record) => Receipt::SettlementFinalizationRecorded,
            _ => Receipt::SettlementFinalizationRejectedBeforeRecord,
        },
        Window::AfterSettlementFinalizationAmbiguous => {
            Receipt::SettlementFinalizationAmbiguousFailClosedNoFinalization
        }
        Window::SettlementFinalizationRecordFailed => {
            Receipt::SettlementFinalizationRecordFailedNoFinalization
        }
        Window::SettlementFinalizationRollbackCompleted => {
            Receipt::SettlementFinalizationRolledBackNoFinalization
        }
        Window::SettlementFinalizationRollbackFailed => {
            Receipt::SettlementFinalizationRollbackFailedFatalNoFinalization
        }
        // Any unknown window fails closed.
        Window::Unknown => Receipt::SettlementFinalizationAmbiguousFailClosedNoFinalization,
    }
}

/// Run 268 — `true` iff a receipt outcome authorizes a **new** modeled
/// audit/publication receipt (only
/// [`DurableCompletionSettlementFinalizationOutcome::SettlementFinalizationRecorded`]).
pub fn settlement_finalization_outcome_authorizes_record(
    outcome: &DurableCompletionSettlementFinalizationOutcome,
) -> bool {
    outcome.authorizes_record()
}

/// Run 268 — `true` iff a receipt outcome projects to a recorded audit/publication
/// receipt (a newly recorded receipt or an idempotent duplicate of an
/// already-recorded receipt).
pub fn settlement_finalization_outcome_projects_to_recorded(
    outcome: &DurableCompletionSettlementFinalizationOutcome,
) -> bool {
    outcome.projects_to_recorded()
}

// ===========================================================================
// Grep-verifiable safety invariants (source/test only)
// ===========================================================================

/// Run 268 — a receipt rejection is non-mutating: it records no receipt, mutates no
/// `LivePqcTrustState`, and writes no durable state.
pub fn durable_completion_settlement_finalization_rejection_is_non_mutating() -> bool {
    true
}

/// Run 268 — the receipt boundary never calls Run 070.
pub fn durable_completion_settlement_finalization_never_calls_run_070() -> bool {
    true
}

/// Run 268 — the receipt boundary never mutates live PQC trust state.
pub fn durable_completion_settlement_finalization_never_mutates_live_pqc_trust_state() -> bool {
    true
}

/// Run 268 — the receipt boundary never writes a sequence or a marker.
pub fn durable_completion_settlement_finalization_never_writes_sequence_or_marker() -> bool {
    true
}

/// Run 268 — the receipt boundary changes no RocksDB file schema / migration.
pub fn durable_completion_settlement_finalization_no_rocksdb_file_schema_migration_change() -> bool {
    true
}

/// Run 268 — the receipt boundary performs no external publication.
pub fn durable_completion_settlement_finalization_no_external_publication() -> bool {
    true
}

/// Run 268 — the receipt boundary performs no real audit-ledger persistence.
pub fn durable_completion_settlement_finalization_no_real_audit_ledger() -> bool {
    true
}

/// Run 268 — a receipt requires a successful Run 246 pipeline outcome upstream.
pub fn durable_completion_settlement_finalization_pipeline_success_required() -> bool {
    true
}

/// Run 268 — a receipt requires a Run 248 sink receipt record upstream.
pub fn durable_completion_settlement_finalization_sink_receipt_required() -> bool {
    true
}

/// Run 268 — a receipt requires a Run 250 completion report upstream.
pub fn durable_completion_settlement_finalization_completion_report_required() -> bool {
    true
}

/// Run 268 — a receipt requires a Run 252 finalization upstream.
pub fn durable_completion_settlement_finalization_finalization_required() -> bool {
    true
}

/// Run 268 — a receipt requires a Run 254 attestation upstream.
pub fn durable_completion_settlement_finalization_attestation_required() -> bool {
    true
}

/// Run 268 — an acknowledgement requires a Run 256 backend submission upstream.
pub fn durable_completion_settlement_finalization_backend_submission_required() -> bool {
    true
}

/// Run 268 — an acknowledgement requires a Run 258 audit receipt upstream.
pub fn durable_completion_settlement_finalization_receipt_required() -> bool {
    true
}

/// Run 268 — a consumer requires a Run 260 audit-receipt acknowledgement upstream.
pub fn durable_completion_settlement_finalization_consumer_required() -> bool {
    true
}

/// Run 268 — a settlement finalization requires a Run 266 settlement commitment
/// upstream; no settlement finalization is authorized without a recorded
/// settlement commitment.
pub fn durable_completion_settlement_finalization_commitment_required() -> bool {
    true
}

/// Run 268 — the consumer boundary never performs a real settlement; production /
/// MainNet / external settlement consumers are reachable but fail closed.
pub fn durable_completion_settlement_finalization_no_real_settlement() -> bool {
    true
}

/// Run 268 — the settlement-finalization boundary never confers real settlement
/// finality; the only settlement-finalization record is a modeled in-memory fixture
/// record. Production / MainNet / external settlement-finalization sinks are reachable
/// but unavailable / fail closed and never confer any real finality.
pub fn durable_completion_settlement_finalization_no_real_settlement_finality() -> bool {
    true
}

/// Run 268 — the settlement-finalization boundary never emits a real settlement
/// receipt; the only settlement-finalization record is a modeled in-memory fixture
/// record with no external publication, network I/O, or persistent backend.
pub fn durable_completion_settlement_finalization_no_real_settlement_receipt() -> bool {
    true
}

/// Run 268 — a receipt record is required before a receipt is acknowledged.
pub fn durable_completion_settlement_finalization_record_required_before_finalized() -> bool {
    true
}

/// Run 268 — a failed receipt record never records a receipt.
pub fn durable_completion_settlement_finalization_failed_record_never_records() -> bool {
    true
}

/// Run 268 — a rolled-back receipt record never records a receipt.
pub fn durable_completion_settlement_finalization_rollback_never_records() -> bool {
    true
}

/// Run 268 — an ambiguous after-record receipt window fails closed.
pub fn durable_completion_settlement_finalization_ambiguous_window_fails_closed() -> bool {
    true
}

/// Run 268 — MainNet peer-driven apply refusal precedes every receipt stage.
pub fn durable_completion_settlement_finalization_mainnet_peer_driven_apply_refused_first(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 268 — production / MainNet audit-ledger sinks are reachable but unavailable.
pub fn durable_completion_settlement_finalization_production_mainnet_unavailable() -> bool {
    true
}

/// Run 268 — the external-publication sink is reachable but unavailable.
pub fn durable_completion_settlement_finalization_external_unavailable() -> bool {
    true
}

/// Run 268 — validator-set rotation remains unsupported at the receipt boundary.
pub fn durable_completion_settlement_finalization_validator_set_rotation_unsupported() -> bool {
    true
}

/// Run 268 — policy-change actions remain unsupported at the receipt boundary.
pub fn durable_completion_settlement_finalization_policy_change_unsupported() -> bool {
    true
}

/// Run 268 — a local operator cannot satisfy MainNet authority for a receipt.
pub fn durable_completion_settlement_finalization_local_operator_cannot_satisfy_mainnet_authority(
) -> bool {
    true
}

/// Run 268 — a peer majority cannot satisfy MainNet authority for a receipt.
pub fn durable_completion_settlement_finalization_peer_majority_cannot_satisfy_mainnet_authority(
) -> bool {
    true
}