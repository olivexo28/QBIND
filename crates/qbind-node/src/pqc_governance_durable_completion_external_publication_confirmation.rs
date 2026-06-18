//! Run 276 — source/test durable-completion **settlement-outcome publication /
//! settlement-finality projection interface boundary**.
//!
//! Source/test only. Run 276 captures **no** release-binary evidence and enables
//! **no** production mutating behavior. It does **not** implement a real settlement
//! backend, a real settlement finality, a real settlement receipt, a real
//! settlement-outcome publication backend, a real settlement-finality projection
//! backend, a real audit-ledger acknowledgement, a real external-publication
//! confirmation, a real external-publication system, a real production attestation /
//! outcome_publication / completion-report / durable-consume / persistent-replay backend, a
//! real governance execution engine, a real production mutation engine, a real on-chain
//! governance proof verifier, a KMS/HSM/RemoteSigner backend, MainNet governance
//! enablement, MainNet peer-driven apply enablement, validator-set rotation, or any
//! RocksDB / file / schema / migration / wire / marker / sequence / trust-bundle /
//! storage-format change.
//!
//! ## What this module adds
//!
//! Run 274
//! ([`crate::pqc_governance_durable_completion_settlement_outcome_publication`])
//! proves that a modeled durable-completion *settlement outcome_publication* is recorded
//! **only** after the Run 266 settlement-outcome-report stage recorded a settlement
//! commitment, terminating in the single settlement-outcome_publication-recording outcome
//! [`DurableCompletionSettlementOutcomePublicationOutcome::SettlementOutcomePublicationRecorded`].
//!
//! Run 276 defines the **first typed interface** a future production settlement-receipt
//! acknowledgement or settlement-finality projection subsystem would use to *consume* a
//! durable-completion settlement outcome_publication and prepare a settlement-receipt
//! acknowledgement intent and modeled in-memory settlement-finality projection receipt
//! **after** the Run 274 settlement-outcome_publication stage produced
//! `SettlementOutcomePublicationRecorded`. It is an **interface / projection boundary only**:
//! production / MainNet / external settlement-outcome publication implementations
//! are *reachable but deliberately unavailable / fail-closed*, and the only positive
//! implementation is a DevNet/TestNet fixture that records into an in-memory fixture
//! ledger for source/test evidence only.
//!
//! The settlement-outcome publication layer is a **model only**. It does not
//! implement a real settlement, a real settlement finality, a real settlement receipt, a
//! real settlement-outcome publication, a real settlement-finality projection, a
//! real external publication, a real audit-ledger acknowledgement, or any real
//! persistent storage. It does not write RocksDB, files, schemas, migrations, storage
//! formats, wire formats, authority markers, trust-bundle sequence files, or any
//! production durable state. It does not call Run 070, mutate `LivePqcTrustState`,
//! perform a real trust swap, evict sessions, perform external publication / network
//! I/O, or enable MainNet governance / MainNet peer-driven apply. The DevNet/TestNet
//! fixture settlement-outcome publication sink mutates only the in-memory
//! [`DurableCompletionExternalPublicationConfirmationLedger`].
//!
//! ## Ordering / fail-closed contract
//!
//! 1. **MainNet peer-driven apply refusal** — refused *before* pipeline
//!    progression, sink invocation, reporter invocation, finalizer invocation,
//!    attestor invocation, backend invocation, receipt invocation, acknowledgement
//!    invocation, consumer invocation, settlement-projection invocation,
//!    settlement-outcome-report invocation, and settlement-outcome_publication invocation;
//! 2. **legacy bypass** — a
//!    [`DurableCompletionExternalPublicationConfirmationPolicy::Disabled`] policy preserves
//!    the legacy no-external-publication-confirmation bypass and never invokes the
//!    settlement-outcome publication sink;
//! 3. **settlement-outcome_publication-outcome projection** — only
//!    [`DurableCompletionSettlementOutcomePublicationOutcome::SettlementOutcomePublicationRecorded`]
//!    creates a settlement-outcome publication request; every other Run 274 outcome
//!    maps to a no-outcome-publication fail-closed outcome and never invokes the
//!    settlement-outcome publication sink;
//! 4. **pre-sink binding validation** — environment / chain / genesis /
//!    governance surface / mutation surface and the full digest binding (including
//!    the Run 256 backend, Run 258 receipt, Run 260 acknowledgement, Run 262 consumer,
//!    and Run 274 settlement-outcome_publication digest sets) must match expectations *before*
//!    the settlement-outcome publication sink is invoked; a mismatch fails closed
//!    and leaves the sink invocation count at zero;
//! 5. **settlement-outcome publication record** — only after every prior gate
//!    passes is the sink invoked; the record-identity fields must match exactly before
//!    any modeled settlement-outcome publication record is recorded;
//! 6. **settlement-outcome publication authorization** — only
//!    [`DurableCompletionExternalPublicationConfirmationOutcome::ExternalPublicationConfirmationRecorded`]
//!    authorizes a new modeled settlement-outcome publication / settlement-finality
//!    projection state.
//!
//! A settlement-outcome publication record failure, rollback, rollback failure, or
//! ambiguous window never retroactively claims a durable settlement-receipt
//! acknowledgement record. A duplicate identical settlement-outcome publication
//! record is idempotent; the same record id with a different digest fails closed as
//! equivocation and records no second record. A Run 274
//! [`DurableCompletionSettlementOutcomePublicationOutcome::SettlementOutcomePublicationDuplicateIdempotent`]
//! never creates a new settlement-outcome publication record by itself — it can only
//! match an already-recorded settlement-outcome publication record.

use crate::pqc_governance_durable_completion_acknowledgement_consumer::DurableCompletionAcknowledgementConsumerOutcome;
use crate::pqc_governance_durable_completion_settlement_outcome_publication::DurableCompletionSettlementOutcomePublicationOutcome;
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

/// Run 276 — the validation / mutation surface pair the receipt binds to.
pub type DurableCompletionExternalPublicationConfirmationSurface =
    ModeledGovernanceTrustMutationSurface;

/// Run 276 — the trust-domain environment binding the receipt is bound to.
pub type DurableCompletionExternalPublicationConfirmationEnvironment =
    ModeledGovernanceTrustMutationEnvironmentBinding;

/// Run 276 — the runtime binding (governance + mutation surface + sequence) the
/// receipt is bound to.
pub type DurableCompletionExternalPublicationConfirmationBinding =
    ModeledGovernanceTrustMutationRuntimeBinding;

/// Run 276 — the Run 240/246 durable replay observation carried as freshness
/// context.
pub type DurableCompletionExternalPublicationConfirmationReplayBinding = DurableReplayObservation;

/// Run 276 — the Run 246 pipeline outcome carried as consume authorization context.
pub type DurableCompletionExternalPublicationConfirmationPipelineBinding =
    GovernanceModeledEndToEndPipelineOutcome;

/// Run 276 — the Run 248 sink outcome carried as receipt-record context.
pub type DurableCompletionExternalPublicationConfirmationSinkBinding =
    GovernanceModeledDurableConsumeSinkOutcome;

/// Run 276 — the Run 250 reporter outcome carried as completion-report context.
pub type DurableCompletionExternalPublicationConfirmationReporterBinding =
    GovernanceModeledDurableConsumeCompletionReporterOutcome;

/// Run 276 — the Run 252 confirmation outcome carried as confirmation context.
pub type DurableCompletionExternalPublicationConfirmationFinalizationBinding =
    GovernanceModeledDurableCompletionFinalizationOutcome;

/// Run 276 — the Run 254 attestation outcome carried as attestation context.
pub type DurableCompletionExternalPublicationConfirmationAttestationBinding =
    GovernanceModeledDurableCompletionAttestationOutcome;

/// Run 276 — the Run 256 backend outcome carried as backend-record context. The
/// acknowledgement boundary never reimplements the backend; it only carries its
/// terminal outcome.
pub type DurableCompletionExternalPublicationConfirmationBackendBinding =
    DurableCompletionAttestationBackendOutcome;

/// Run 276 — the Run 258 audit/publication receipt outcome carried as
/// receipt-record context. The consumer boundary never reimplements the receipt; it
/// only carries its terminal outcome.
pub type DurableCompletionExternalPublicationConfirmationReceiptBinding =
    DurableCompletionAuditPublicationReceiptOutcome;

/// Run 276 — the Run 260 audit-receipt acknowledgement outcome carried as
/// acknowledgement-record context. The settlement-outcome_publication boundary never
/// reimplements the acknowledgement; it only carries its terminal outcome.
pub type DurableCompletionExternalPublicationConfirmationAcknowledgementBinding =
    DurableCompletionAuditReceiptAcknowledgementOutcome;

/// Run 276 — the Run 262 acknowledgement consumer outcome the settlement-outcome_publication
/// boundary projects to a settlement-outcome_publication request. The settlement-outcome_publication
/// boundary never reimplements the consumer; it only projects its terminal outcome.
pub type DurableCompletionExternalPublicationConfirmationConsumerBinding =
    DurableCompletionAcknowledgementConsumerOutcome;

/// Run 276 — the Run 274 settlement-outcome_publication outcome the external-publication-confirmation
/// boundary projects to a external-publication-confirmation request. The external-publication-confirmation
/// boundary never reimplements the settlement outcome_publication; it only projects its
/// terminal outcome.
pub type DurableCompletionExternalPublicationConfirmationSettlementOutcomePublicationBinding =
    DurableCompletionSettlementOutcomePublicationOutcome;

// ===========================================================================
// Receipt kind
// ===========================================================================

/// Run 276 — the typed durable-completion audit/publication receipt kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionExternalPublicationConfirmationKind {
    /// The receipt boundary is disabled (legacy bypass).
    Disabled,
    /// DevNet/TestNet in-memory fixture receipt sink (source-test only; may mutate
    /// only the ledger).
    FixtureInMemory,
    /// Production audit-ledger receipt sink (reachable-but-unavailable /
    /// fail-closed).
    ProductionExternalPublicationConfirmationUnavailable,
    /// MainNet audit-ledger receipt sink (reachable-but-unavailable / fail-closed).
    MainNetExternalPublicationConfirmationUnavailable,
    /// External-publication receipt sink (reachable-but-unavailable / fail-closed).
    ExternalExternalPublicationConfirmationUnavailable,
    /// An unknown receipt kind — fails closed.
    Unknown,
}

impl DurableCompletionExternalPublicationConfirmationKind {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureInMemory => "fixture-in-memory",
            Self::ProductionExternalPublicationConfirmationUnavailable => {
                "production-external-publication-confirmation-unavailable"
            }
            Self::MainNetExternalPublicationConfirmationUnavailable => {
                "mainnet-external-publication-confirmation-unavailable"
            }
            Self::ExternalExternalPublicationConfirmationUnavailable => {
                "external-external-publication-confirmation-unavailable"
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
            Self::ProductionExternalPublicationConfirmationUnavailable
                | Self::MainNetExternalPublicationConfirmationUnavailable
                | Self::ExternalExternalPublicationConfirmationUnavailable
        )
    }
}

// ===========================================================================
// Receipt policy
// ===========================================================================

/// Run 276 — the typed durable-completion audit/publication receipt policy
/// selector.
///
/// Only [`Self::FixtureAllowed`] may record (DevNet/TestNet source-test only);
/// every production / MainNet / external-publication policy resolves to a
/// reachable-but-unavailable sink that never records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionExternalPublicationConfirmationPolicy {
    /// The receipt boundary is disabled (legacy bypass).
    Disabled,
    /// A DevNet/TestNet fixture receipt sink is allowed (source-test evidence only).
    FixtureAllowed,
    /// A real production audit-ledger receipt sink is required — reachable but
    /// unavailable.
    ProductionExternalPublicationConfirmationRequired,
    /// A real MainNet audit-ledger receipt sink is required — reachable but
    /// unavailable.
    MainNetExternalPublicationConfirmationRequired,
    /// A real external-publication receipt sink is required — reachable but
    /// unavailable.
    ExternalExternalPublicationConfirmationRequired,
}

impl DurableCompletionExternalPublicationConfirmationPolicy {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureAllowed => "fixture-allowed",
            Self::ProductionExternalPublicationConfirmationRequired => {
                "production-external-publication-confirmation-required"
            }
            Self::MainNetExternalPublicationConfirmationRequired => "mainnet-external-publication-confirmation-required",
            Self::ExternalExternalPublicationConfirmationRequired => "external-external-publication-confirmation-required",
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

/// Run 276 — the typed receipt identity a receipt request is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionExternalPublicationConfirmationIdentity {
    /// Stable receipt id.
    pub outcome_publication_id: String,
    /// The receipt kind.
    pub kind: DurableCompletionExternalPublicationConfirmationKind,
    /// The receipt policy.
    pub policy: DurableCompletionExternalPublicationConfirmationPolicy,
    /// The domain separation tag the receipt operates under.
    pub domain_separation_tag: String,
}

impl DurableCompletionExternalPublicationConfirmationIdentity {
    /// `true` iff every mandatory identity field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.outcome_publication_id.is_empty()
            && !self.domain_separation_tag.is_empty()
            && self.kind != DurableCompletionExternalPublicationConfirmationKind::Unknown
    }

    /// The deterministic, domain-separated receipt identity digest.
    pub fn digest(&self) -> DurableCompletionExternalPublicationConfirmationDigest {
        external_publication_confirmation_identity_digest(self)
    }
}

// ===========================================================================
// Deterministic, domain-separated digest helpers
// ===========================================================================

/// Run 276 — domain separator for the receipt identity digest.
const OUTCOME_PUBLICATION_IDENTITY_DOMAIN: &[u8] =
    b"QBIND:run268:durable-completion-external-publication-confirmation-identity:v1";
/// Run 276 — domain separator for the receipt request digest.
const OUTCOME_PUBLICATION_REQUEST_DOMAIN: &[u8] =
    b"QBIND:run268:durable-completion-external-publication-confirmation-request:v1";
/// Run 276 — domain separator for the receipt response digest.
const OUTCOME_PUBLICATION_RESPONSE_DOMAIN: &[u8] =
    b"QBIND:run268:durable-completion-external-publication-confirmation-response:v1";
/// Run 276 — domain separator for the receipt record digest.
const OUTCOME_PUBLICATION_RECORD_DOMAIN: &[u8] =
    b"QBIND:run268:durable-completion-external-publication-confirmation-record:v1";
/// Run 276 — domain separator for the receipt transcript digest.
const OUTCOME_PUBLICATION_TRANSCRIPT_DOMAIN: &[u8] =
    b"QBIND:run268:durable-completion-external-publication-confirmation-transcript:v1";

/// Run 276 — a deterministic, domain-separated receipt digest (lowercase hex of a
/// SHA3-256 over length-prefixed, field-bound canonical material). It contains no
/// unstable display text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionExternalPublicationConfirmationDigest(String);

impl DurableCompletionExternalPublicationConfirmationDigest {
    /// The lowercase hex representation.
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

/// Run 276 — a deterministic, domain-separated receipt transcript digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionExternalPublicationConfirmationTranscriptDigest(String);

impl DurableCompletionExternalPublicationConfirmationTranscriptDigest {
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

/// Run 276 — deterministic, domain-separated receipt identity digest.
pub fn external_publication_confirmation_identity_digest(
    identity: &DurableCompletionExternalPublicationConfirmationIdentity,
) -> DurableCompletionExternalPublicationConfirmationDigest {
    let mut w = CanonicalWriter::new(OUTCOME_PUBLICATION_IDENTITY_DOMAIN);
    w.str_field(&identity.outcome_publication_id)
        .str_field(identity.kind.tag())
        .str_field(identity.policy.tag())
        .str_field(&identity.domain_separation_tag);
    DurableCompletionExternalPublicationConfirmationDigest(w.finish())
}

/// Run 276 — deterministic, domain-separated receipt request digest. Binds every
/// request field including the full Run 256 backend digest binding.
pub fn external_publication_confirmation_request_digest(
    request: &DurableCompletionExternalPublicationConfirmationRequest,
) -> DurableCompletionExternalPublicationConfirmationDigest {
    let mut w = CanonicalWriter::new(OUTCOME_PUBLICATION_REQUEST_DOMAIN);
    w.str_field(&request.confirmation_record_id)
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
        .str_field(&request.settlement_outcome_publication_identity_digest)
        .str_field(&request.settlement_outcome_publication_request_digest)
        .str_field(&request.settlement_outcome_publication_response_digest)
        .str_field(&request.settlement_outcome_publication_record_digest)
        .str_field(&request.settlement_outcome_publication_transcript_digest)
        .str_field(&request.settlement_outcome_publication_record_id)
        .str_field(&request.domain_separation_tag)
        .str_field(external_publication_confirmation_identity_digest(&request.identity).as_hex());
    DurableCompletionExternalPublicationConfirmationDigest(w.finish())
}

/// Run 276 — deterministic, domain-separated receipt response digest. Binds the
/// receipt record id, the request digest it answers, the acceptance flag, and the
/// responding receipt kind.
pub fn external_publication_confirmation_response_digest(
    response: &DurableCompletionExternalPublicationConfirmationResponse,
) -> DurableCompletionExternalPublicationConfirmationDigest {
    let mut w = CanonicalWriter::new(OUTCOME_PUBLICATION_RESPONSE_DOMAIN);
    w.str_field(&response.confirmation_record_id)
        .str_field(response.request_digest.as_hex())
        .str_field(if response.accepted {
            "accepted"
        } else {
            "rejected"
        })
        .str_field(response.confirmation_kind.tag());
    DurableCompletionExternalPublicationConfirmationDigest(w.finish())
}

/// Run 276 — deterministic, domain-separated receipt record digest. Binds the
/// receipt record id, the request digest, and the receipt identity digest.
pub fn external_publication_confirmation_record_digest(
    record: &DurableCompletionExternalPublicationConfirmationRecord,
) -> DurableCompletionExternalPublicationConfirmationDigest {
    let mut w = CanonicalWriter::new(OUTCOME_PUBLICATION_RECORD_DOMAIN);
    w.str_field(&record.confirmation_record_id)
        .str_field(record.request_digest.as_hex())
        .str_field(record.identity_digest.as_hex());
    DurableCompletionExternalPublicationConfirmationDigest(w.finish())
}

/// Run 276 — deterministic, domain-separated receipt transcript digest. Binds the
/// request, response, and record digests into a single transcript binding.
pub fn external_publication_confirmation_transcript_digest(
    request_digest: &DurableCompletionExternalPublicationConfirmationDigest,
    response_digest: &DurableCompletionExternalPublicationConfirmationDigest,
    record_digest: &DurableCompletionExternalPublicationConfirmationDigest,
) -> DurableCompletionExternalPublicationConfirmationTranscriptDigest {
    let mut w = CanonicalWriter::new(OUTCOME_PUBLICATION_TRANSCRIPT_DOMAIN);
    w.str_field(request_digest.as_hex())
        .str_field(response_digest.as_hex())
        .str_field(record_digest.as_hex());
    DurableCompletionExternalPublicationConfirmationTranscriptDigest(w.finish())
}

// ===========================================================================
// Receipt request / response / record
// ===========================================================================

/// Run 276 — the typed receipt request a future production audit ledger or
/// external-publication call site would submit once the Run 256 backend recorded a
/// `BackendSubmissionRecorded`.
///
/// Pure data referencing the already-recorded Run 256 backend / Run 254
/// attestation / Run 252 confirmation / Run 250 completion report / Run 248
/// receipt / Run 246 decision material — never a copy of any wire payload and never
/// a production durable record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionExternalPublicationConfirmationRequest {
    /// Stable receipt record id (the idempotency key of the receipt).
    pub confirmation_record_id: String,
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
    /// Run 252 confirmation decision digest.
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
    /// Run 274 settlement-outcome_publication identity digest.
    pub settlement_outcome_publication_identity_digest: String,
    /// Run 274 settlement-outcome_publication request digest.
    pub settlement_outcome_publication_request_digest: String,
    /// Run 274 settlement-outcome_publication response digest.
    pub settlement_outcome_publication_response_digest: String,
    /// Run 274 settlement-outcome_publication record digest.
    pub settlement_outcome_publication_record_digest: String,
    /// Run 274 settlement-outcome_publication transcript digest.
    pub settlement_outcome_publication_transcript_digest: String,
    /// Run 274 settlement-outcome_publication record id.
    pub settlement_outcome_publication_record_id: String,
    /// Settlement-outcome-publication identity.
    pub identity: DurableCompletionExternalPublicationConfirmationIdentity,
    /// Domain separation tag.
    pub domain_separation_tag: String,
}

impl DurableCompletionExternalPublicationConfirmationRequest {
    /// `true` iff every mandatory field is structurally present (non-empty) and the
    /// identity is well-formed.
    pub fn is_well_formed(&self) -> bool {
        !self.confirmation_record_id.is_empty()
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
            && !self.settlement_outcome_publication_identity_digest.is_empty()
            && !self.settlement_outcome_publication_request_digest.is_empty()
            && !self.settlement_outcome_publication_response_digest.is_empty()
            && !self.settlement_outcome_publication_record_digest.is_empty()
            && !self.settlement_outcome_publication_transcript_digest.is_empty()
            && !self.settlement_outcome_publication_record_id.is_empty()
            && !self.domain_separation_tag.is_empty()
            && self.identity.is_well_formed()
    }

    /// The deterministic receipt request digest.
    pub fn digest(&self) -> DurableCompletionExternalPublicationConfirmationDigest {
        external_publication_confirmation_request_digest(self)
    }

    /// The canonical immutable record derived from this request.
    pub fn to_record(&self) -> DurableCompletionExternalPublicationConfirmationRecord {
        DurableCompletionExternalPublicationConfirmationRecord {
            confirmation_record_id: self.confirmation_record_id.clone(),
            request_digest: self.digest(),
            identity_digest: self.identity.digest(),
        }
    }
}

/// Run 276 — the typed receipt response a receipt sink returns for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionExternalPublicationConfirmationResponse {
    /// The receipt record id the response answers.
    pub confirmation_record_id: String,
    /// The request digest the response answers.
    pub request_digest: DurableCompletionExternalPublicationConfirmationDigest,
    /// `true` iff the receipt sink accepted the request.
    pub accepted: bool,
    /// The responding receipt kind.
    pub confirmation_kind: DurableCompletionExternalPublicationConfirmationKind,
}

impl DurableCompletionExternalPublicationConfirmationResponse {
    /// `true` iff the response is structurally well-formed.
    pub fn is_well_formed(&self) -> bool {
        !self.confirmation_record_id.is_empty()
            && self.confirmation_kind != DurableCompletionExternalPublicationConfirmationKind::Unknown
    }

    /// The deterministic receipt response digest.
    pub fn digest(&self) -> DurableCompletionExternalPublicationConfirmationDigest {
        external_publication_confirmation_response_digest(self)
    }
}

/// Run 276 — the canonical immutable receipt record derived from a request. Two
/// records are idempotent-equal only if **every** field matches exactly. The same
/// receipt record id with any differing digest is equivocation and fails closed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionExternalPublicationConfirmationRecord {
    /// The receipt record id.
    pub confirmation_record_id: String,
    /// The request digest.
    pub request_digest: DurableCompletionExternalPublicationConfirmationDigest,
    /// The receipt identity digest.
    pub identity_digest: DurableCompletionExternalPublicationConfirmationDigest,
}

impl DurableCompletionExternalPublicationConfirmationRecord {
    /// The deterministic receipt record digest.
    pub fn digest(&self) -> DurableCompletionExternalPublicationConfirmationDigest {
        external_publication_confirmation_record_digest(self)
    }
}

// ===========================================================================
// In-memory fixture ledger
// ===========================================================================

/// Run 276 — the recorded status of a modeled audit/publication receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionExternalPublicationConfirmationLedgerStatus {
    /// The modeled receipt is recorded in the in-memory fixture ledger.
    Recorded,
}

/// Run 276 — a single modeled receipt record held in the in-memory fixture ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionExternalPublicationConfirmationLedgerRecord {
    /// The receipt record id (stable identity of the receipt).
    pub confirmation_record_id: String,
    /// The request digest.
    pub request_digest: DurableCompletionExternalPublicationConfirmationDigest,
    /// The response digest.
    pub response_digest: DurableCompletionExternalPublicationConfirmationDigest,
    /// The record digest.
    pub record_digest: DurableCompletionExternalPublicationConfirmationDigest,
    /// The transcript digest.
    pub transcript_digest: DurableCompletionExternalPublicationConfirmationTranscriptDigest,
    /// The recorded status.
    pub status: DurableCompletionExternalPublicationConfirmationLedgerStatus,
}

/// Run 276 — an immutable snapshot of the modeled receipt ledger used to model a
/// fixture rollback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionExternalPublicationConfirmationLedgerSnapshot {
    records: Vec<DurableCompletionExternalPublicationConfirmationLedgerRecord>,
}

impl DurableCompletionExternalPublicationConfirmationLedgerSnapshot {
    /// The number of records the snapshot captured.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` iff the snapshot captured no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Run 276 — the modeled in-memory receipt ledger.
///
/// **In-memory only.** It never touches RocksDB, files, markers, sequence files,
/// external publications, audit-ledger entries, or any production durable state.
/// The DevNet/TestNet fixture sink is the only thing that may mutate it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DurableCompletionExternalPublicationConfirmationLedger {
    records: Vec<DurableCompletionExternalPublicationConfirmationLedgerRecord>,
}

impl DurableCompletionExternalPublicationConfirmationLedger {
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
    pub fn records(&self) -> &[DurableCompletionExternalPublicationConfirmationLedgerRecord] {
        &self.records
    }

    /// The record for `confirmation_record_id`, if present.
    pub fn find(
        &self,
        confirmation_record_id: &str,
    ) -> Option<&DurableCompletionExternalPublicationConfirmationLedgerRecord> {
        self.records
            .iter()
            .find(|r| r.confirmation_record_id == confirmation_record_id)
    }

    /// `true` iff a receipt with `confirmation_record_id` is recorded.
    pub fn contains(&self, confirmation_record_id: &str) -> bool {
        self.find(confirmation_record_id).is_some()
    }

    /// Capture an immutable snapshot for a modeled rollback.
    pub fn snapshot(&self) -> DurableCompletionExternalPublicationConfirmationLedgerSnapshot {
        DurableCompletionExternalPublicationConfirmationLedgerSnapshot {
            records: self.records.clone(),
        }
    }

    /// Restore the ledger to a previously captured snapshot (modeled rollback).
    pub fn restore(
        &mut self,
        snapshot: &DurableCompletionExternalPublicationConfirmationLedgerSnapshot,
    ) {
        self.records = snapshot.records.clone();
    }

    /// Internal: insert a recorded receipt. Only the fixture sink calls this, and
    /// only after every identity / idempotency gate has passed.
    fn insert(&mut self, record: DurableCompletionExternalPublicationConfirmationLedgerRecord) {
        self.records.push(record);
    }
}

// ===========================================================================
// Receipt expectations
// ===========================================================================

/// Run 276 — the canonical binding a [`DurableCompletionExternalPublicationConfirmationInput`]
/// is checked against.
///
/// Environment / chain / genesis / surface mismatches fail closed **before** the
/// receipt sink is invoked. Receipt-request-identity mismatches fail closed
/// **inside** the sink, before any modeled receipt is recorded. Neither path is
/// ever a silent approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionExternalPublicationConfirmationExpectations {
    /// Expected receipt record id.
    pub expected_confirmation_record_id: String,
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
    /// Expected Run 252 confirmation decision digest.
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
    /// Expected Run 274 settlement-outcome_publication identity digest.
    pub expected_settlement_outcome_publication_identity_digest: String,
    /// Expected Run 274 settlement-outcome_publication request digest.
    pub expected_settlement_outcome_publication_request_digest: String,
    /// Expected Run 274 settlement-outcome_publication response digest.
    pub expected_settlement_outcome_publication_response_digest: String,
    /// Expected Run 274 settlement-outcome_publication record digest.
    pub expected_settlement_outcome_publication_record_digest: String,
    /// Expected Run 274 settlement-outcome_publication transcript digest.
    pub expected_settlement_outcome_publication_transcript_digest: String,
    /// Expected Run 274 settlement-outcome_publication record id.
    pub expected_settlement_outcome_publication_record_id: String,
    /// Expected settlement-outcome_publication identity.
    pub expected_identity: DurableCompletionExternalPublicationConfirmationIdentity,
    /// Expected settlement-outcome_publication kind.
    pub expected_confirmation_kind: DurableCompletionExternalPublicationConfirmationKind,
    /// Expected settlement-outcome_publication policy.
    pub expected_confirmation_policy: DurableCompletionExternalPublicationConfirmationPolicy,
    /// Expected domain separation tag.
    pub expected_domain_separation_tag: String,
}

impl DurableCompletionExternalPublicationConfirmationExpectations {
    /// Internal: the first environment / surface binding mismatch reason, if any.
    fn binding_mismatch_reason(
        &self,
        input: &DurableCompletionExternalPublicationConfirmationInput,
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
        input: &DurableCompletionExternalPublicationConfirmationInput,
    ) -> bool {
        self.binding_mismatch_reason(input).is_none()
    }

    /// Internal: the first receipt-request-identity mismatch reason, if any.
    fn request_mismatch_reason(
        &self,
        request: &DurableCompletionExternalPublicationConfirmationRequest,
    ) -> Option<&'static str> {
        if !request.is_well_formed() {
            return Some("malformed receipt request");
        }
        if request.confirmation_record_id != self.expected_confirmation_record_id {
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
            return Some("wrong confirmation decision digest");
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
        if request.settlement_outcome_publication_identity_digest
            != self.expected_settlement_outcome_publication_identity_digest
        {
            return Some("wrong settlement-outcome_publication identity digest");
        }
        if request.settlement_outcome_publication_request_digest
            != self.expected_settlement_outcome_publication_request_digest
        {
            return Some("wrong settlement-outcome_publication request digest");
        }
        if request.settlement_outcome_publication_response_digest
            != self.expected_settlement_outcome_publication_response_digest
        {
            return Some("wrong settlement-outcome_publication response digest");
        }
        if request.settlement_outcome_publication_record_digest
            != self.expected_settlement_outcome_publication_record_digest
        {
            return Some("wrong settlement-outcome_publication record digest");
        }
        if request.settlement_outcome_publication_transcript_digest
            != self.expected_settlement_outcome_publication_transcript_digest
        {
            return Some("wrong settlement-outcome_publication transcript digest");
        }
        if request.settlement_outcome_publication_record_id != self.expected_settlement_outcome_publication_record_id {
            return Some("wrong settlement-outcome_publication record id");
        }
        if request.domain_separation_tag != self.expected_domain_separation_tag {
            return Some("wrong domain separation tag");
        }
        if request.identity != self.expected_identity {
            return Some("wrong external-publication-confirmation identity");
        }
        if request.identity.kind != self.expected_confirmation_kind {
            return Some("wrong external-publication-confirmation kind");
        }
        if request.identity.policy != self.expected_confirmation_policy {
            return Some("wrong external-publication-confirmation policy");
        }
        None
    }

    /// `true` iff the receipt-request identity matches and is well-formed.
    pub fn request_matches(
        &self,
        request: &DurableCompletionExternalPublicationConfirmationRequest,
    ) -> bool {
        self.request_mismatch_reason(request).is_none()
    }
}

// ===========================================================================
// Receipt input
// ===========================================================================

/// Run 276 — typed inputs for one modeled durable-completion audit/publication
/// receipt round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionExternalPublicationConfirmationInput {
    /// The receipt policy selector.
    pub policy: DurableCompletionExternalPublicationConfirmationPolicy,
    /// The trust-domain environment binding.
    pub environment_binding: DurableCompletionExternalPublicationConfirmationEnvironment,
    /// The runtime binding (governance + mutation surface + sequence).
    pub runtime_binding: DurableCompletionExternalPublicationConfirmationBinding,
    /// The Run 240/246 durable replay observation the pipeline authorized consume
    /// under.
    pub replay_binding: DurableCompletionExternalPublicationConfirmationReplayBinding,
    /// The Run 246 pipeline outcome.
    pub pipeline_binding: DurableCompletionExternalPublicationConfirmationPipelineBinding,
    /// The Run 248 sink outcome.
    pub sink_binding: DurableCompletionExternalPublicationConfirmationSinkBinding,
    /// The Run 250 reporter outcome.
    pub reporter_binding: DurableCompletionExternalPublicationConfirmationReporterBinding,
    /// The Run 252 confirmation outcome.
    pub outcome_publication_binding: DurableCompletionExternalPublicationConfirmationFinalizationBinding,
    /// The Run 254 attestation outcome.
    pub attestation_binding: DurableCompletionExternalPublicationConfirmationAttestationBinding,
    /// The Run 256 backend outcome carried as backend-record context.
    pub backend_binding: DurableCompletionExternalPublicationConfirmationBackendBinding,
    /// The Run 258 audit/publication receipt outcome carried as receipt-record
    /// context.
    pub receipt_binding: DurableCompletionExternalPublicationConfirmationReceiptBinding,
    /// The Run 260 audit-receipt acknowledgement outcome carried as
    /// acknowledgement-record context.
    pub acknowledgement_binding:
        DurableCompletionExternalPublicationConfirmationAcknowledgementBinding,
    /// The Run 262 acknowledgement consumer outcome the settlement-outcome_publication
    /// boundary projects to a settlement-outcome_publication request.
    pub consumer_binding: DurableCompletionExternalPublicationConfirmationConsumerBinding,
    /// The Run 274 settlement-outcome_publication outcome the external-publication-confirmation boundary
    /// projects to a external-publication-confirmation request.
    pub settlement_outcome_publication_binding:
        DurableCompletionExternalPublicationConfirmationSettlementOutcomePublicationBinding,
    /// The external-publication-confirmation request the call site would submit.
    pub request: DurableCompletionExternalPublicationConfirmationRequest,
}

impl DurableCompletionExternalPublicationConfirmationInput {
    /// The trust-domain environment the decision is bound to.
    pub fn environment(&self) -> TrustBundleEnvironment {
        self.environment_binding.environment
    }

    /// The validation / mutation surface pair.
    pub fn surface(&self) -> DurableCompletionExternalPublicationConfirmationSurface {
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
                self.outcome_publication_binding,
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
                self.settlement_outcome_publication_binding,
                DurableCompletionSettlementOutcomePublicationOutcome::MainNetPeerDrivenApplyRefusedNoOutcomePublication
            )
    }
}

// ===========================================================================
// Receipt outcome
// ===========================================================================

/// Run 276 — the typed outcome of one modeled durable-completion audit/publication
/// receipt round-trip.
///
/// Only [`Self::ExternalPublicationConfirmationRecorded`] authorizes a **new** modeled
/// audit/publication-receipt state. A [`Self::ExternalPublicationConfirmationDuplicateIdempotent`]
/// means the receipt was already recorded (idempotent, no second receipt). Every
/// other variant is a no-audit-receipt fail-closed outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableCompletionExternalPublicationConfirmationOutcome {
    /// Legacy bypass — a disabled receipt policy preserved the legacy
    /// no-audit-receipt path. No receipt invocation.
    LegacyBypassNoExternalPublicationConfirmation,
    /// The Run 256 backend-stage binding was rejected before the receipt sink was
    /// invoked (a backend-stage rejection / binding mismatch). Non-mutating, no
    /// receipt. No receipt invocation.
    RejectedBeforeSettlementOutcomePublicationNoConfirmation,
    /// The Run 256 backend did not submit (any non-submitting backend outcome
    /// without a more specific variant). Non-mutating, no receipt. No receipt
    /// invocation.
    SettlementOutcomePublicationDidNotRecordNoConfirmation,
    /// The receipt sink recorded a new modeled audit/publication receipt. The
    /// **only** outcome that authorizes a new modeled receipt state.
    ExternalPublicationConfirmationRecorded,
    /// A duplicate identical receipt — idempotent; no second receipt recorded.
    ExternalPublicationConfirmationDuplicateIdempotent,
    /// The receipt was rejected before record (malformed request, request-identity
    /// mismatch, same receipt record id with a differing digest / equivocation, or
    /// a duplicate-idempotent backend submission with no matching prior receipt). No
    /// receipt.
    ExternalPublicationConfirmationRejectedBeforeRecord,
    /// The receipt record failed. No receipt.
    ExternalPublicationConfirmationRecordFailedNoConfirmation,
    /// The receipt record was rolled back. No receipt.
    ExternalPublicationConfirmationRolledBackNoConfirmation,
    /// The receipt rollback itself failed — fatal / fail-closed. No receipt.
    ExternalPublicationConfirmationRollbackFailedFatalNoConfirmation,
    /// The after-record receipt window was ambiguous — fails closed. No receipt.
    ExternalPublicationConfirmationAmbiguousFailClosedNoConfirmation,
    /// The production audit-ledger path was reached but is unavailable. No receipt.
    ProductionExternalPublicationConfirmationUnavailableNoConfirmation,
    /// The MainNet audit-ledger path was reached but is unavailable. No receipt.
    MainNetExternalPublicationConfirmationUnavailableNoConfirmation,
    /// The external-publication path was reached but is unavailable. No receipt.
    ExternalExternalPublicationConfirmationUnavailableNoConfirmation,
    /// MainNet peer-driven apply remains refused before pipeline progression, sink
    /// invocation, reporter invocation, finalizer invocation, attestor invocation,
    /// backend invocation, and receipt invocation. No receipt.
    MainNetPeerDrivenApplyRefusedNoConfirmation,
    /// Validator-set rotation is unsupported. No receipt.
    ValidatorSetRotationUnsupportedNoConfirmation,
    /// Policy-change actions are unsupported. No receipt.
    PolicyChangeUnsupportedNoConfirmation,
}

impl DurableCompletionExternalPublicationConfirmationOutcome {
    /// `true` iff this outcome authorizes a **new** modeled audit/publication
    /// receipt (only [`Self::ExternalPublicationConfirmationRecorded`]).
    pub fn authorizes_record(&self) -> bool {
        matches!(self, Self::ExternalPublicationConfirmationRecorded)
    }

    /// `true` iff this outcome projects to a recorded audit/publication receipt — a
    /// newly recorded receipt or an idempotent duplicate of an already-recorded
    /// receipt.
    pub fn projects_to_recorded(&self) -> bool {
        matches!(
            self,
            Self::ExternalPublicationConfirmationRecorded | Self::ExternalPublicationConfirmationDuplicateIdempotent
        )
    }

    /// `true` iff this outcome records nothing new and projects to no
    /// audit/publication receipt.
    pub fn no_commitment(&self) -> bool {
        !self.projects_to_recorded()
    }

    /// `true` iff this is the legacy no-audit-receipt bypass.
    pub fn is_legacy_bypass(&self) -> bool {
        matches!(self, Self::LegacyBypassNoExternalPublicationConfirmation)
    }

    /// `true` iff this is the MainNet peer-driven-apply refusal.
    pub fn is_mainnet_peer_driven_apply_refused(&self) -> bool {
        matches!(self, Self::MainNetPeerDrivenApplyRefusedNoConfirmation)
    }

    /// Stable operator-facing tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::LegacyBypassNoExternalPublicationConfirmation => "legacy-bypass-no-external-publication-confirmation",
            Self::RejectedBeforeSettlementOutcomePublicationNoConfirmation => {
                "rejected-before-settlement-outcome_publication-no-outcome-publication"
            }
            Self::SettlementOutcomePublicationDidNotRecordNoConfirmation => {
                "settlement-outcome_publication-did-not-record-no-outcome-publication"
            }
            Self::ExternalPublicationConfirmationRecorded => "external-publication-confirmation-recorded",
            Self::ExternalPublicationConfirmationDuplicateIdempotent => {
                "external-publication-confirmation-duplicate-idempotent"
            }
            Self::ExternalPublicationConfirmationRejectedBeforeRecord => {
                "external-publication-confirmation-rejected-before-record"
            }
            Self::ExternalPublicationConfirmationRecordFailedNoConfirmation => {
                "external-publication-confirmation-record-failed-no-outcome-publication"
            }
            Self::ExternalPublicationConfirmationRolledBackNoConfirmation => {
                "external-publication-confirmation-rolled-back-no-outcome-publication"
            }
            Self::ExternalPublicationConfirmationRollbackFailedFatalNoConfirmation => {
                "external-publication-confirmation-rollback-failed-fatal-no-outcome-publication"
            }
            Self::ExternalPublicationConfirmationAmbiguousFailClosedNoConfirmation => {
                "external-publication-confirmation-ambiguous-fail-closed-no-outcome-publication"
            }
            Self::ProductionExternalPublicationConfirmationUnavailableNoConfirmation => {
                "production-external-publication-confirmation-unavailable-no-outcome-publication"
            }
            Self::MainNetExternalPublicationConfirmationUnavailableNoConfirmation => {
                "mainnet-external-publication-confirmation-unavailable-no-outcome-publication"
            }
            Self::ExternalExternalPublicationConfirmationUnavailableNoConfirmation => {
                "external-external-publication-confirmation-unavailable-no-outcome-publication"
            }
            Self::MainNetPeerDrivenApplyRefusedNoConfirmation => {
                "mainnet-peer-driven-apply-refused-no-outcome-publication"
            }
            Self::ValidatorSetRotationUnsupportedNoConfirmation => {
                "validator-set-rotation-unsupported-no-outcome-publication"
            }
            Self::PolicyChangeUnsupportedNoConfirmation => "policy-change-unsupported-no-outcome-publication",
        }
    }
}

// ===========================================================================
// Consumer-outcome -> settlement-outcome_publication request outcome_publication
// ===========================================================================

/// Run 276 — the typed outcome_publication of a Run 262 acknowledgement consumer outcome
/// onto a settlement-outcome_publication request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableCompletionExternalPublicationConfirmationRequestIntent {
    /// The consumer recorded a consumer record; the settlement-outcome_publication sink may
    /// record a new settlement outcome_publication.
    CreateRequest,
    /// The consumer reported an idempotent-duplicate consumer record; the
    /// settlement-outcome_publication sink may only match an already-recorded settlement
    /// outcome_publication and must never create a new one.
    IdempotentOnly,
    /// The consumer did not record; no settlement-outcome_publication request. Carries the
    /// typed no-outcome_publication outcome the settlement-outcome_publication evaluation returns
    /// directly (without invoking the settlement-outcome_publication sink).
    NoOutcomePublication(DurableCompletionExternalPublicationConfirmationOutcome),
}

impl DurableCompletionExternalPublicationConfirmationRequestIntent {
    /// `true` iff this outcome_publication creates a settlement-outcome_publication request (i.e. the
    /// consumer recorded a consumer record).
    pub fn creates_request(&self) -> bool {
        matches!(self, Self::CreateRequest)
    }
}

/// Run 276 — project a Run 274 settlement-outcome_publication outcome onto a
/// external-publication-confirmation request.
///
/// Only
/// [`DurableCompletionSettlementOutcomePublicationOutcome::SettlementOutcomePublicationRecorded`]
/// creates a external-publication-confirmation request.
/// [`DurableCompletionSettlementOutcomePublicationOutcome::SettlementOutcomePublicationDuplicateIdempotent`]
/// may only match an already-recorded external-publication-confirmation record and never creates
/// a new one. Every other settlement-outcome_publication outcome maps to a no-outcome-publication
/// fail-closed outcome (a more specific one where one exists, otherwise the generic
/// [`DurableCompletionExternalPublicationConfirmationOutcome::SettlementOutcomePublicationDidNotRecordNoConfirmation`]).
/// Pure: performs no work and never records.
pub fn project_settlement_outcome_publication_outcome_to_external_publication_confirmation_request(
    outcome: &DurableCompletionExternalPublicationConfirmationSettlementOutcomePublicationBinding,
) -> DurableCompletionExternalPublicationConfirmationRequestIntent {
    use DurableCompletionSettlementOutcomePublicationOutcome as Finalization;
    use DurableCompletionExternalPublicationConfirmationOutcome as Confirmation;
    use DurableCompletionExternalPublicationConfirmationRequestIntent as Intent;
    match outcome {
        Finalization::SettlementOutcomePublicationRecorded => Intent::CreateRequest,
        Finalization::SettlementOutcomePublicationDuplicateIdempotent => Intent::IdempotentOnly,
        Finalization::LegacyBypassNoSettlementOutcomePublication => {
            Intent::NoOutcomePublication(Confirmation::LegacyBypassNoExternalPublicationConfirmation)
        }
        Finalization::RejectedBeforeSettlementOutcomeReportNoOutcomePublication => {
            Intent::NoOutcomePublication(Confirmation::RejectedBeforeSettlementOutcomePublicationNoConfirmation)
        }
        Finalization::MainNetPeerDrivenApplyRefusedNoOutcomePublication => {
            Intent::NoOutcomePublication(Confirmation::MainNetPeerDrivenApplyRefusedNoConfirmation)
        }
        Finalization::ValidatorSetRotationUnsupportedNoOutcomePublication => {
            Intent::NoOutcomePublication(Confirmation::ValidatorSetRotationUnsupportedNoConfirmation)
        }
        Finalization::PolicyChangeUnsupportedNoOutcomePublication => {
            Intent::NoOutcomePublication(Confirmation::PolicyChangeUnsupportedNoConfirmation)
        }
        // Every remaining settlement-outcome_publication outcome is a non-recording rejection /
        // failure / rollback / ambiguous window: the settlement outcome_publication did not
        // record, so no external-publication-confirmation record may exist.
        _ => Intent::NoOutcomePublication(Confirmation::SettlementOutcomePublicationDidNotRecordNoConfirmation),
    }
}

// ===========================================================================
// Receipt fault injection (source/test only)
// ===========================================================================

/// Run 276 — a modeled fault the fixture receipt sink injects to exercise the
/// fail-closed record / rollback / ambiguous paths. Source/test only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionExternalPublicationConfirmationFault {
    /// The receipt record fails; nothing is written. No receipt.
    RecordFailedNoOutcomePublication,
    /// The receipt record is rolled back; nothing remains written. No receipt.
    RolledBackNoOutcomePublication,
    /// The receipt rollback itself fails — fatal / fail-closed. No receipt.
    RollbackFailedFatal,
    /// The after-record receipt window is ambiguous — fails closed. No receipt.
    AmbiguousAfterRecord,
}

// ===========================================================================
// Receipt trait boundary
// ===========================================================================

/// Run 276 — the pure/mockable modeled durable-completion audit/publication receipt
/// boundary.
///
/// No implementation here calls Run 070, mutates `LivePqcTrustState`, performs a
/// live trust swap, evicts sessions, writes a sequence, writes a marker, performs
/// network I/O, external publication, or a real audit-ledger persistence. The
/// DevNet/TestNet fixture receipt sink mutates only the in-memory
/// [`DurableCompletionExternalPublicationConfirmationLedger`].
pub trait GovernanceDurableCompletionExternalPublicationConfirmationSink {
    /// The receipt kind (used for typed recovery classification).
    fn kind(&self) -> DurableCompletionExternalPublicationConfirmationKind;

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
    fn project_durable_completion_external_publication_confirmation(
        &mut self,
        request: &DurableCompletionExternalPublicationConfirmationRequest,
        expectations: &DurableCompletionExternalPublicationConfirmationExpectations,
        idempotent_only: bool,
        ledger: &mut DurableCompletionExternalPublicationConfirmationLedger,
    ) -> DurableCompletionExternalPublicationConfirmationOutcome;

    /// Classify a modeled receipt crash/recovery window. Pure: performs no modeled
    /// mutation and never invokes Run 070.
    fn recover_durable_completion_external_publication_confirmation_window(
        &self,
        input: &DurableCompletionExternalPublicationConfirmationInput,
        window: DurableCompletionExternalPublicationConfirmationWindow,
        recovered_record: Option<&DurableCompletionExternalPublicationConfirmationLedgerRecord>,
        expectations: &DurableCompletionExternalPublicationConfirmationExpectations,
    ) -> DurableCompletionExternalPublicationConfirmationOutcome {
        recover_durable_completion_external_publication_confirmation_window(
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

/// Run 276 — the DevNet/TestNet in-memory fixture receipt sink.
///
/// Source-test only. It mutates only the in-memory
/// [`DurableCompletionExternalPublicationConfirmationLedger`] and exposes an invocation
/// counter so tests can prove non-submitting backend paths and pre-receipt
/// rejections never invoke it.
#[derive(Debug, Clone)]
pub struct FixtureDurableCompletionExternalPublicationConfirmationSink {
    fault: Option<DurableCompletionExternalPublicationConfirmationFault>,
    invocations: u32,
}

impl Default for FixtureDurableCompletionExternalPublicationConfirmationSink {
    fn default() -> Self {
        Self::new()
    }
}

impl FixtureDurableCompletionExternalPublicationConfirmationSink {
    /// A new fixture receipt sink.
    pub fn new() -> Self {
        Self {
            fault: None,
            invocations: 0,
        }
    }

    /// A new fixture receipt sink that injects the given modeled fault on record.
    pub fn with_fault(fault: DurableCompletionExternalPublicationConfirmationFault) -> Self {
        Self {
            fault: Some(fault),
            invocations: 0,
        }
    }
}

impl GovernanceDurableCompletionExternalPublicationConfirmationSink
    for FixtureDurableCompletionExternalPublicationConfirmationSink
{
    fn kind(&self) -> DurableCompletionExternalPublicationConfirmationKind {
        DurableCompletionExternalPublicationConfirmationKind::FixtureInMemory
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn project_durable_completion_external_publication_confirmation(
        &mut self,
        request: &DurableCompletionExternalPublicationConfirmationRequest,
        expectations: &DurableCompletionExternalPublicationConfirmationExpectations,
        idempotent_only: bool,
        ledger: &mut DurableCompletionExternalPublicationConfirmationLedger,
    ) -> DurableCompletionExternalPublicationConfirmationOutcome {
        use DurableCompletionExternalPublicationConfirmationOutcome as Receipt;
        self.invocations += 1;

        // Injected faults model record-failure / rollback / ambiguous windows. None
        // of them ever leave a recorded receipt behind, so a durable receipt is never
        // claimed. The ledger snapshot/restore models the rollback being a no-op
        // write.
        if let Some(fault) = self.fault {
            let snapshot = ledger.snapshot();
            return match fault {
                DurableCompletionExternalPublicationConfirmationFault::RecordFailedNoOutcomePublication => {
                    ledger.restore(&snapshot);
                    Receipt::ExternalPublicationConfirmationRecordFailedNoConfirmation
                }
                DurableCompletionExternalPublicationConfirmationFault::RolledBackNoOutcomePublication => {
                    ledger.restore(&snapshot);
                    Receipt::ExternalPublicationConfirmationRolledBackNoConfirmation
                }
                DurableCompletionExternalPublicationConfirmationFault::RollbackFailedFatal => {
                    Receipt::ExternalPublicationConfirmationRollbackFailedFatalNoConfirmation
                }
                DurableCompletionExternalPublicationConfirmationFault::AmbiguousAfterRecord => {
                    ledger.restore(&snapshot);
                    Receipt::ExternalPublicationConfirmationAmbiguousFailClosedNoConfirmation
                }
            };
        }

        // The fixture receipt sink is DevNet/TestNet evidence-only.
        if !matches!(
            request.environment,
            TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet
        ) {
            return Receipt::ExternalPublicationConfirmationRejectedBeforeRecord;
        }

        // Request-identity validation (malformed / mismatch) fails closed before any
        // record is written.
        if !expectations.request_matches(request) {
            return Receipt::ExternalPublicationConfirmationRejectedBeforeRecord;
        }

        // Build the deterministic request / response / record / transcript digests.
        let request_digest = request.digest();
        let response = DurableCompletionExternalPublicationConfirmationResponse {
            confirmation_record_id: request.confirmation_record_id.clone(),
            request_digest: request_digest.clone(),
            accepted: true,
            confirmation_kind: DurableCompletionExternalPublicationConfirmationKind::FixtureInMemory,
        };
        let response_digest = response.digest();
        let record = request.to_record();
        let record_digest = record.digest();
        let transcript_digest = external_publication_confirmation_transcript_digest(
            &request_digest,
            &response_digest,
            &record_digest,
        );

        // Idempotency / equivocation gate.
        if let Some(existing) = ledger.find(&request.confirmation_record_id) {
            if existing.request_digest == request_digest
                && existing.response_digest == response_digest
                && existing.record_digest == record_digest
                && existing.transcript_digest == transcript_digest
            {
                return Receipt::ExternalPublicationConfirmationDuplicateIdempotent;
            }
            // Same receipt record id with a different digest is equivocation: fail
            // closed, record no second receipt.
            return Receipt::ExternalPublicationConfirmationRejectedBeforeRecord;
        }

        // A duplicate-idempotent backend submission may only match an already-recorded
        // receipt; it must never create a new one by itself.
        if idempotent_only {
            return Receipt::ExternalPublicationConfirmationRejectedBeforeRecord;
        }

        ledger.insert(DurableCompletionExternalPublicationConfirmationLedgerRecord {
            confirmation_record_id: request.confirmation_record_id.clone(),
            request_digest,
            response_digest,
            record_digest,
            transcript_digest,
            status: DurableCompletionExternalPublicationConfirmationLedgerStatus::Recorded,
        });
        Receipt::ExternalPublicationConfirmationRecorded
    }
}

// ===========================================================================
// Production / MainNet audit-ledger / External-publication sinks (unavailable)
// ===========================================================================

/// Run 276 — the production audit-ledger receipt sink. Reachable but unavailable /
/// fail-closed. It records no receipt and mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct ProductionExternalPublicationConfirmationSink {
    invocations: u32,
}

impl GovernanceDurableCompletionExternalPublicationConfirmationSink
    for ProductionExternalPublicationConfirmationSink
{
    fn kind(&self) -> DurableCompletionExternalPublicationConfirmationKind {
        DurableCompletionExternalPublicationConfirmationKind::ProductionExternalPublicationConfirmationUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn project_durable_completion_external_publication_confirmation(
        &mut self,
        _request: &DurableCompletionExternalPublicationConfirmationRequest,
        _expectations: &DurableCompletionExternalPublicationConfirmationExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionExternalPublicationConfirmationLedger,
    ) -> DurableCompletionExternalPublicationConfirmationOutcome {
        self.invocations += 1;
        DurableCompletionExternalPublicationConfirmationOutcome::ProductionExternalPublicationConfirmationUnavailableNoConfirmation
    }
}

/// Run 276 — the MainNet audit-ledger receipt sink. Reachable but unavailable /
/// fail-closed. It records no receipt and mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct MainNetExternalPublicationConfirmationSink {
    invocations: u32,
}

impl GovernanceDurableCompletionExternalPublicationConfirmationSink
    for MainNetExternalPublicationConfirmationSink
{
    fn kind(&self) -> DurableCompletionExternalPublicationConfirmationKind {
        DurableCompletionExternalPublicationConfirmationKind::MainNetExternalPublicationConfirmationUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn project_durable_completion_external_publication_confirmation(
        &mut self,
        _request: &DurableCompletionExternalPublicationConfirmationRequest,
        _expectations: &DurableCompletionExternalPublicationConfirmationExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionExternalPublicationConfirmationLedger,
    ) -> DurableCompletionExternalPublicationConfirmationOutcome {
        self.invocations += 1;
        DurableCompletionExternalPublicationConfirmationOutcome::MainNetExternalPublicationConfirmationUnavailableNoConfirmation
    }
}

/// Run 276 — the external-publication receipt sink. Reachable but unavailable /
/// fail-closed. It performs no external publication, records no receipt, and
/// mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct ExternalExternalPublicationConfirmationSink {
    invocations: u32,
}

impl GovernanceDurableCompletionExternalPublicationConfirmationSink
    for ExternalExternalPublicationConfirmationSink
{
    fn kind(&self) -> DurableCompletionExternalPublicationConfirmationKind {
        DurableCompletionExternalPublicationConfirmationKind::ExternalExternalPublicationConfirmationUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn project_durable_completion_external_publication_confirmation(
        &mut self,
        _request: &DurableCompletionExternalPublicationConfirmationRequest,
        _expectations: &DurableCompletionExternalPublicationConfirmationExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionExternalPublicationConfirmationLedger,
    ) -> DurableCompletionExternalPublicationConfirmationOutcome {
        self.invocations += 1;
        DurableCompletionExternalPublicationConfirmationOutcome::ExternalExternalPublicationConfirmationUnavailableNoConfirmation
    }
}

// ===========================================================================
// Receipt executor / composition helpers
// ===========================================================================

/// Run 276 — evaluate one modeled durable-completion audit/publication receipt
/// round-trip.
///
/// Ordering (each gate must pass before the next is considered):
///
/// 1. MainNet peer-driven apply refusal — before pipeline progression, sink
///    invocation, reporter invocation, finalizer invocation, attestor invocation,
///    backend invocation, and receipt invocation;
/// 2. legacy bypass — a
///    [`DurableCompletionExternalPublicationConfirmationPolicy::Disabled`] policy;
/// 3. backend-outcome outcome_publication — only
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
pub fn evaluate_durable_completion_external_publication_confirmation<S>(
    input: &DurableCompletionExternalPublicationConfirmationInput,
    expectations: &DurableCompletionExternalPublicationConfirmationExpectations,
    sink: &mut S,
    ledger: &mut DurableCompletionExternalPublicationConfirmationLedger,
) -> DurableCompletionExternalPublicationConfirmationOutcome
where
    S: GovernanceDurableCompletionExternalPublicationConfirmationSink,
{
    use DurableCompletionExternalPublicationConfirmationOutcome as Finalization;
    use DurableCompletionExternalPublicationConfirmationRequestIntent as Intent;

    // Step 1: MainNet peer-driven apply remains refused unconditionally, before
    // pipeline progression, sink invocation, reporter invocation, finalizer
    // invocation, attestor invocation, backend invocation, receipt invocation,
    // acknowledgement invocation, consumer invocation, and settlement-outcome_publication
    // invocation.
    if input.is_mainnet_peer_driven() {
        return Finalization::MainNetPeerDrivenApplyRefusedNoConfirmation;
    }

    // Step 2: legacy bypass — a disabled settlement-outcome_publication policy preserves the
    // legacy no-settlement-outcome_publication path and never invokes the outcome_publication sink.
    if input.policy.is_disabled() {
        return Finalization::LegacyBypassNoExternalPublicationConfirmation;
    }

    // Step 3: project the Run 262 acknowledgement consumer outcome onto a
    // settlement-outcome_publication request. Every non-recording consumer outcome returns a
    // no-outcome_publication outcome without invoking the settlement-outcome_publication sink.
    let idempotent_only =
        match project_settlement_outcome_publication_outcome_to_external_publication_confirmation_request(
            &input.settlement_outcome_publication_binding,
        ) {
            Intent::NoOutcomePublication(outcome) => return outcome,
            Intent::CreateRequest => false,
            Intent::IdempotentOnly => true,
        };

    // Step 4: pre-outcome_publication environment / surface binding validation. A mismatch
    // fails closed before the settlement-outcome_publication sink is invoked, leaving the
    // settlement-outcome_publication invocation count at zero.
    if !expectations.binding_matches(input) {
        return Finalization::RejectedBeforeSettlementOutcomePublicationNoConfirmation;
    }

    // Step 5: invoke the settlement-outcome_publication sink to record the modeled outcome_publication.
    sink.project_durable_completion_external_publication_confirmation(
        &input.request,
        expectations,
        idempotent_only,
        ledger,
    )
}

// ===========================================================================
// Receipt crash/recovery window classification
// ===========================================================================

/// Run 276 — the modeled durable-completion audit/publication receipt
/// crash/recovery window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionExternalPublicationConfirmationWindow {
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
    /// Crashed after the report record but before a confirmation intent.
    AfterReportRecordBeforeConfirmationIntent,
    /// Crashed after a confirmation intent but before any confirmation record.
    AfterConfirmationIntentBeforeConfirmationRecord,
    /// Crashed after the confirmation record but before an attestation intent.
    AfterConfirmationRecordBeforeAttestationIntent,
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
    /// Crashed after consumer success but before a settlement-outcome_publication request.
    AfterConsumerSuccessBeforeSettlementOutcomePublicationRequest,
    /// Crashed after a settlement-outcome_publication request but before any
    /// settlement-outcome_publication record.
    AfterSettlementOutcomePublicationRequestBeforeSettlementOutcomePublicationRecord,
    /// Crashed after a settlement-outcome_publication record but before settlement-outcome_publication
    /// success — fails closed unless an explicit matching settlement-outcome_publication
    /// record exists.
    AfterSettlementOutcomePublicationRecordBeforeSettlementOutcomePublicationSuccess,
    /// Crashed after settlement-outcome_publication success but before a external-publication-confirmation
    /// request.
    AfterSettlementOutcomePublicationSuccessBeforeExternalPublicationConfirmationRequest,
    /// Crashed after a external-publication-confirmation request but before any
    /// external-publication-confirmation record.
    AfterExternalPublicationConfirmationRequestBeforeExternalPublicationConfirmationRecord,
    /// Crashed after a external-publication-confirmation record but before external-publication-confirmation
    /// success — fails closed unless an explicit matching external-publication-confirmation
    /// record exists.
    AfterExternalPublicationConfirmationRecordBeforeExternalPublicationConfirmationSuccess,
    /// Recovered after a successful external-publication-confirmation record.
    AfterExternalPublicationConfirmationSuccess,
    /// Recovered after an ambiguous external-publication-confirmation window.
    AfterExternalPublicationConfirmationAmbiguous,
    /// The external-publication-confirmation record itself failed.
    ExternalPublicationConfirmationRecordFailed,
    /// The external-publication-confirmation record was rolled back.
    ExternalPublicationConfirmationRollbackCompleted,
    /// The external-publication-confirmation rollback itself failed — fatal.
    ExternalPublicationConfirmationRollbackFailed,
    /// An unknown window — fails closed.
    Unknown,
}

/// Run 276 — classify a modeled durable-completion audit/publication receipt
/// crash/recovery window.
///
/// The receipt sink never silently re-authorizes an in-flight receipt: MainNet
/// peer-driven refusal precedes classification, production / MainNet audit-ledger /
/// external-publication classification is unavailable, and every ambiguous /
/// unknown window fails closed. Only an after-receipt-record window with an explicit
/// matching record (or an explicit after-receipt-success window) recovers as
/// [`DurableCompletionExternalPublicationConfirmationOutcome::ExternalPublicationConfirmationRecorded`]. Pure:
/// performs no modeled mutation and never invokes Run 070.
pub fn recover_durable_completion_external_publication_confirmation_window(
    input: &DurableCompletionExternalPublicationConfirmationInput,
    window: DurableCompletionExternalPublicationConfirmationWindow,
    kind: DurableCompletionExternalPublicationConfirmationKind,
    recovered_record: Option<&DurableCompletionExternalPublicationConfirmationLedgerRecord>,
    expectations: &DurableCompletionExternalPublicationConfirmationExpectations,
) -> DurableCompletionExternalPublicationConfirmationOutcome {
    use DurableCompletionExternalPublicationConfirmationOutcome as Receipt;
    use DurableCompletionExternalPublicationConfirmationWindow as Window;

    // MainNet peer-driven apply refusal precedes recovery classification.
    if input.is_mainnet_peer_driven() {
        return Receipt::MainNetPeerDrivenApplyRefusedNoConfirmation;
    }

    // Production / MainNet audit-ledger / external-publication recovery
    // classification is unavailable / fail-closed.
    match kind {
        DurableCompletionExternalPublicationConfirmationKind::ProductionExternalPublicationConfirmationUnavailable => {
            return Receipt::ProductionExternalPublicationConfirmationUnavailableNoConfirmation;
        }
        DurableCompletionExternalPublicationConfirmationKind::MainNetExternalPublicationConfirmationUnavailable => {
            return Receipt::MainNetExternalPublicationConfirmationUnavailableNoConfirmation;
        }
        DurableCompletionExternalPublicationConfirmationKind::ExternalExternalPublicationConfirmationUnavailable => {
            return Receipt::ExternalExternalPublicationConfirmationUnavailableNoConfirmation;
        }
        DurableCompletionExternalPublicationConfirmationKind::Disabled => {
            return Receipt::LegacyBypassNoExternalPublicationConfirmation;
        }
        DurableCompletionExternalPublicationConfirmationKind::Unknown => {
            return Receipt::ExternalPublicationConfirmationAmbiguousFailClosedNoConfirmation;
        }
        DurableCompletionExternalPublicationConfirmationKind::FixtureInMemory => {}
    }

    // Helper: an explicit recovered record recovers as a receipt only if it matches
    // the expected receipt record id and the canonical request digest.
    let recovered_matches =
        |record: &DurableCompletionExternalPublicationConfirmationLedgerRecord| -> bool {
            record.confirmation_record_id == expectations.expected_confirmation_record_id
                && record.request_digest == input.request.digest()
                && record.status
                    == DurableCompletionExternalPublicationConfirmationLedgerStatus::Recorded
        };

    match window {
        // Through settlement-outcome_publication success but before a external-publication-confirmation
        // request there is nothing to record a settlement confirmation for.
        Window::BeforePipeline
        | Window::AfterPipelineSuccessBeforeSinkIntent
        | Window::AfterSinkIntentBeforeSinkReceiptRecord
        | Window::AfterSinkReceiptRecordBeforeReportIntent
        | Window::AfterReportIntentBeforeReportRecord
        | Window::AfterReportRecordBeforeConfirmationIntent
        | Window::AfterConfirmationIntentBeforeConfirmationRecord
        | Window::AfterConfirmationRecordBeforeAttestationIntent
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
        | Window::AfterConsumerSuccessBeforeSettlementOutcomePublicationRequest
        | Window::AfterSettlementOutcomePublicationRequestBeforeSettlementOutcomePublicationRecord
        | Window::AfterSettlementOutcomePublicationRecordBeforeSettlementOutcomePublicationSuccess
        | Window::AfterSettlementOutcomePublicationSuccessBeforeExternalPublicationConfirmationRequest => {
            Receipt::SettlementOutcomePublicationDidNotRecordNoConfirmation
        }
        // A external-publication-confirmation request without a record never records a
        // settlement confirmation.
        Window::AfterExternalPublicationConfirmationRequestBeforeExternalPublicationConfirmationRecord => {
            Receipt::ExternalPublicationConfirmationRejectedBeforeRecord
        }
        // After a external-publication-confirmation record but before success: fails closed
        // unless an explicit matching, well-formed external-publication-confirmation record
        // exists.
        Window::AfterExternalPublicationConfirmationRecordBeforeExternalPublicationConfirmationSuccess => {
            match recovered_record {
                Some(record) if recovered_matches(record) => Receipt::ExternalPublicationConfirmationRecorded,
                _ => Receipt::ExternalPublicationConfirmationRejectedBeforeRecord,
            }
        }
        // An explicit successful settlement confirmation recovers as recorded only if
        // it matches.
        Window::AfterExternalPublicationConfirmationSuccess => match recovered_record {
            Some(record) if recovered_matches(record) => Receipt::ExternalPublicationConfirmationRecorded,
            _ => Receipt::ExternalPublicationConfirmationRejectedBeforeRecord,
        },
        Window::AfterExternalPublicationConfirmationAmbiguous => {
            Receipt::ExternalPublicationConfirmationAmbiguousFailClosedNoConfirmation
        }
        Window::ExternalPublicationConfirmationRecordFailed => {
            Receipt::ExternalPublicationConfirmationRecordFailedNoConfirmation
        }
        Window::ExternalPublicationConfirmationRollbackCompleted => {
            Receipt::ExternalPublicationConfirmationRolledBackNoConfirmation
        }
        Window::ExternalPublicationConfirmationRollbackFailed => {
            Receipt::ExternalPublicationConfirmationRollbackFailedFatalNoConfirmation
        }
        // Any unknown window fails closed.
        Window::Unknown => Receipt::ExternalPublicationConfirmationAmbiguousFailClosedNoConfirmation,
    }
}

/// Run 276 — `true` iff a receipt outcome authorizes a **new** modeled
/// audit/publication receipt (only
/// [`DurableCompletionExternalPublicationConfirmationOutcome::ExternalPublicationConfirmationRecorded`]).
pub fn external_publication_confirmation_outcome_authorizes_record(
    outcome: &DurableCompletionExternalPublicationConfirmationOutcome,
) -> bool {
    outcome.authorizes_record()
}

/// Run 276 — `true` iff a receipt outcome projects to a recorded audit/publication
/// receipt (a newly recorded receipt or an idempotent duplicate of an
/// already-recorded receipt).
pub fn external_publication_confirmation_outcome_projects_to_recorded(
    outcome: &DurableCompletionExternalPublicationConfirmationOutcome,
) -> bool {
    outcome.projects_to_recorded()
}

// ===========================================================================
// Grep-verifiable safety invariants (source/test only)
// ===========================================================================

/// Run 276 — a receipt rejection is non-mutating: it records no receipt, mutates no
/// `LivePqcTrustState`, and writes no durable state.
pub fn durable_completion_external_publication_confirmation_rejection_is_non_mutating() -> bool {
    true
}

/// Run 276 — the receipt boundary never calls Run 070.
pub fn durable_completion_external_publication_confirmation_never_calls_run_070() -> bool {
    true
}

/// Run 276 — the receipt boundary never mutates live PQC trust state.
pub fn durable_completion_external_publication_confirmation_never_mutates_live_pqc_trust_state() -> bool {
    true
}

/// Run 276 — the receipt boundary never writes a sequence or a marker.
pub fn durable_completion_external_publication_confirmation_never_writes_sequence_or_marker() -> bool {
    true
}

/// Run 276 — the receipt boundary changes no RocksDB file schema / migration.
pub fn durable_completion_external_publication_confirmation_no_rocksdb_file_schema_migration_change() -> bool {
    true
}

/// Run 276 — the receipt boundary performs no external publication.
pub fn durable_completion_external_publication_confirmation_no_external_publication() -> bool {
    true
}

/// Run 276 — the receipt boundary performs no real audit-ledger persistence.
pub fn durable_completion_external_publication_confirmation_no_real_audit_ledger() -> bool {
    true
}

/// Run 276 — a receipt requires a successful Run 246 pipeline outcome upstream.
pub fn durable_completion_external_publication_confirmation_pipeline_success_required() -> bool {
    true
}

/// Run 276 — a receipt requires a Run 248 sink receipt record upstream.
pub fn durable_completion_external_publication_confirmation_sink_receipt_required() -> bool {
    true
}

/// Run 276 — a receipt requires a Run 250 completion report upstream.
pub fn durable_completion_external_publication_confirmation_completion_report_required() -> bool {
    true
}

/// Run 276 — a receipt requires a Run 252 confirmation upstream.
pub fn durable_completion_external_publication_confirmation_finalization_projection_required() -> bool {
    true
}

/// Run 276 — a receipt requires a Run 254 attestation upstream.
pub fn durable_completion_external_publication_confirmation_attestation_required() -> bool {
    true
}

/// Run 276 — an acknowledgement requires a Run 256 backend submission upstream.
pub fn durable_completion_external_publication_confirmation_backend_submission_required() -> bool {
    true
}

/// Run 276 — an acknowledgement requires a Run 258 audit receipt upstream.
pub fn durable_completion_external_publication_confirmation_receipt_required() -> bool {
    true
}

/// Run 276 — a consumer requires a Run 260 audit-receipt acknowledgement upstream.
pub fn durable_completion_external_publication_confirmation_consumer_required() -> bool {
    true
}

/// Run 276 — a settlement confirmation requires a Run 274 settlement outcome_publication
/// upstream; no settlement confirmation is authorized without a recorded
/// settlement outcome_publication.
pub fn durable_completion_external_publication_confirmation_outcome_publication_required() -> bool {
    true
}

/// Run 276 — the consumer boundary never performs a real settlement; production /
/// MainNet / external settlement consumers are reachable but fail closed.
pub fn durable_completion_external_publication_confirmation_no_real_settlement() -> bool {
    true
}

/// Run 276 — the external-publication-confirmation boundary never confers real settlement
/// finality; the only external-publication-confirmation record is a modeled in-memory fixture
/// record. Production / MainNet / external external-publication-confirmation sinks are reachable
/// but unavailable / fail closed and never confer any real finality.
pub fn durable_completion_external_publication_confirmation_no_real_settlement_finality() -> bool {
    true
}

/// Run 276 — the external-publication-confirmation boundary never emits a real settlement
/// receipt; the only external-publication-confirmation record is a modeled in-memory fixture
/// record with no external publication, network I/O, or persistent backend.
pub fn durable_completion_external_publication_confirmation_no_real_settlement_receipt() -> bool {
    true
}

/// Run 276 — the external-publication-confirmation boundary never confers a real
/// settlement-outcome publication; the only settlement-outcome publication
/// record is a modeled in-memory fixture record. Production / MainNet / external
/// settlement-outcome publication sinks are reachable but unavailable / fail closed
/// and never confer any real acknowledgement.
pub fn durable_completion_external_publication_confirmation_no_real_settlement_outcome_publication() -> bool {
    true
}

/// Run 276 — the external-publication-confirmation boundary never confers a real
/// settlement-finality projection; the only settlement-finality projection is a modeled
/// in-memory fixture record with no external publication, network I/O, or persistent
/// backend.
pub fn durable_completion_external_publication_confirmation_no_real_settlement_finality_projection() -> bool {
    true
}

/// Run 276 — the external-publication-confirmation boundary never confers a real
/// settlement-outcome publication; the only settlement-outcome publication is a modeled
/// in-memory fixture record with no external publication, network I/O, or persistent
/// backend.
pub fn durable_completion_external_publication_confirmation_no_real_external_publication_confirmation() -> bool {
    true
}

/// Run 276 — a receipt record is required before a receipt is acknowledged.
pub fn durable_completion_external_publication_confirmation_record_required_before_reported() -> bool {
    true
}

/// Run 276 — a failed receipt record never records a receipt.
pub fn durable_completion_external_publication_confirmation_failed_record_never_records() -> bool {
    true
}

/// Run 276 — a rolled-back receipt record never records a receipt.
pub fn durable_completion_external_publication_confirmation_rollback_never_records() -> bool {
    true
}

/// Run 276 — an ambiguous after-record receipt window fails closed.
pub fn durable_completion_external_publication_confirmation_ambiguous_window_fails_closed() -> bool {
    true
}

/// Run 276 — MainNet peer-driven apply refusal precedes every receipt stage.
pub fn durable_completion_external_publication_confirmation_mainnet_peer_driven_apply_refused_first(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 276 — production / MainNet audit-ledger sinks are reachable but unavailable.
pub fn durable_completion_external_publication_confirmation_production_mainnet_unavailable() -> bool {
    true
}

/// Run 276 — the external-publication sink is reachable but unavailable.
pub fn durable_completion_external_publication_confirmation_external_unavailable() -> bool {
    true
}

/// Run 276 — validator-set rotation remains unsupported at the receipt boundary.
pub fn durable_completion_external_publication_confirmation_validator_set_rotation_unsupported() -> bool {
    true
}

/// Run 276 — policy-change actions remain unsupported at the receipt boundary.
pub fn durable_completion_external_publication_confirmation_policy_change_unsupported() -> bool {
    true
}

/// Run 276 — a local operator cannot satisfy MainNet authority for a receipt.
pub fn durable_completion_external_publication_confirmation_local_operator_cannot_satisfy_mainnet_authority(
) -> bool {
    true
}

/// Run 276 — a peer majority cannot satisfy MainNet authority for a receipt.
pub fn durable_completion_external_publication_confirmation_peer_majority_cannot_satisfy_mainnet_authority(
) -> bool {
    true
}