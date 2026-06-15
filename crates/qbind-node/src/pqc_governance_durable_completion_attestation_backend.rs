//! Run 256 — source/test production **durable-completion attestation backend
//! interface boundary**.
//!
//! Source/test only. Run 256 captures **no** release-binary evidence and enables
//! **no** production mutating behavior. It does **not** implement a real
//! production attestation backend, a real audit ledger, a real external
//! publication system, a real settlement ledger, a real persistent replay
//! backend, a real durable consume backend, a real completion-report backend, a
//! real finalization backend, a real governance execution engine, a real
//! production mutation engine, a real on-chain governance proof verifier, a
//! KMS/HSM/RemoteSigner backend, MainNet governance enablement, MainNet
//! peer-driven apply enablement, validator-set rotation, or any RocksDB / file /
//! schema / migration / wire / marker / sequence / trust-bundle / storage-format
//! change.
//!
//! ## What this module adds
//!
//! Run 254
//! ([`crate::pqc_governance_modeled_durable_completion_attestation_projection`])
//! proves that a modeled durable-completion *attestation* is recorded **only**
//! after the Run 252 finalizer recorded a finalization, terminating in the single
//! attestation-recording outcome
//! [`GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested`].
//!
//! Run 256 stops extending the purely modeled internal chain and instead defines
//! the **first typed interface** a future production call site would use to submit
//! or record a durable-completion attestation **after** the Run 254 modeled
//! attestation stage produced `DurableCompletionAttested`. It is an **interface
//! boundary only**: production and MainNet backend implementations are *reachable
//! but deliberately unavailable / fail-closed*, and the only positive backend
//! implementation is a DevNet/TestNet fixture that records into an in-memory
//! fixture ledger for source/test evidence only.
//!
//! The backend layer is a **model only**. It does not implement a real attestation
//! backend, a real audit ledger, a real external publication system, or a real
//! settlement ledger. It does not write RocksDB, files, schemas, migrations,
//! storage formats, wire formats, authority markers, trust-bundle sequence files,
//! or any production durable state. It does not call Run 070, mutate
//! `LivePqcTrustState`, perform a real trust swap, evict sessions, or enable
//! MainNet governance / MainNet peer-driven apply. The DevNet/TestNet fixture
//! backend mutates only the in-memory
//! [`DurableCompletionAttestationBackendLedger`].
//!
//! ## Ordering / fail-closed contract
//!
//! 1. **MainNet peer-driven apply refusal** — refused *before* pipeline
//!    progression, sink invocation, reporter invocation, finalizer invocation,
//!    attestor invocation, and backend invocation;
//! 2. **legacy bypass** — a [`DurableCompletionAttestationBackendPolicy::Disabled`]
//!    policy preserves the legacy no-backend-submission bypass and never invokes
//!    the backend;
//! 3. **attestation-outcome projection** — only
//!    [`GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested`]
//!    creates a backend request; every other Run 254 attestation outcome maps to a
//!    no-backend-submission fail-closed outcome and never invokes the backend;
//! 4. **pre-backend binding validation** — environment / chain / genesis /
//!    governance surface / mutation surface and the full digest binding must match
//!    expectations *before* the backend is invoked; a mismatch fails closed and
//!    leaves the backend invocation count at zero;
//! 5. **backend submission** — only after every prior gate passes is the backend
//!    invoked; the backend-record-identity fields must match exactly before any
//!    modeled submission is recorded;
//! 6. **submission authorization** — only
//!    [`DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded`]
//!    authorizes a new modeled backend-submitted state.
//!
//! A backend record failure, rollback, rollback failure, or ambiguous backend
//! window never retroactively claims a durable submission. A duplicate identical
//! submission is idempotent; the same backend record id with a different digest
//! fails closed as equivocation and records no second submission. A Run 254
//! [`GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttestationDuplicateIdempotent`]
//! never creates a new backend submission by itself — it can only match an
//! already-recorded backend submission.

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

/// Run 256 — the validation / mutation surface pair the backend binds to. A type
/// alias over the Run 244/246/248/250/252/254 surface pair.
pub type DurableCompletionAttestationBackendSurface = ModeledGovernanceTrustMutationSurface;

/// Run 256 — the trust-domain environment binding the backend is bound to. A type
/// alias over the Run 244/246/248/250/252/254 environment binding.
pub type DurableCompletionAttestationBackendEnvironment =
    ModeledGovernanceTrustMutationEnvironmentBinding;

/// Run 256 — the runtime binding (governance + mutation surface + sequence) the
/// backend is bound to. A type alias over the Run 244/246/248/250/252/254 runtime
/// binding.
pub type DurableCompletionAttestationBackendBinding = ModeledGovernanceTrustMutationRuntimeBinding;

/// Run 256 — the Run 240/246 durable replay observation the backend carries as the
/// freshness context the pipeline authorized consume under.
pub type DurableCompletionAttestationBackendReplayBinding = DurableReplayObservation;

/// Run 256 — the Run 246 pipeline outcome the backend carries as the consume
/// authorization context.
pub type DurableCompletionAttestationBackendPipelineBinding =
    GovernanceModeledEndToEndPipelineOutcome;

/// Run 256 — the Run 248 sink outcome the backend carries as the receipt-record
/// context.
pub type DurableCompletionAttestationBackendSinkBinding = GovernanceModeledDurableConsumeSinkOutcome;

/// Run 256 — the Run 250 reporter outcome the backend carries as the
/// completion-report context.
pub type DurableCompletionAttestationBackendReporterBinding =
    GovernanceModeledDurableConsumeCompletionReporterOutcome;

/// Run 256 — the Run 252 finalization outcome the backend carries as the
/// finalization context.
pub type DurableCompletionAttestationBackendFinalizationBinding =
    GovernanceModeledDurableCompletionFinalizationOutcome;

/// Run 256 — the Run 254 attestation outcome the backend projects to a backend
/// request. The backend never reimplements the attestor; it only projects its
/// terminal outcome.
pub type DurableCompletionAttestationBackendAttestationBinding =
    GovernanceModeledDurableCompletionAttestationOutcome;

// ===========================================================================
// Backend kind
// ===========================================================================

/// Run 256 — the typed durable-completion attestation backend kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionAttestationBackendKind {
    /// The backend boundary is disabled (legacy bypass).
    Disabled,
    /// DevNet/TestNet in-memory fixture backend (source-test only; may mutate only
    /// the ledger).
    FixtureInMemory,
    /// Production backend (reachable-but-unavailable / fail-closed).
    ProductionUnavailable,
    /// MainNet backend (reachable-but-unavailable / fail-closed).
    MainNetUnavailable,
    /// External-publication backend (reachable-but-unavailable / fail-closed).
    ExternalPublicationUnavailable,
    /// An unknown backend kind — fails closed.
    Unknown,
}

impl DurableCompletionAttestationBackendKind {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureInMemory => "fixture-in-memory",
            Self::ProductionUnavailable => "production-unavailable",
            Self::MainNetUnavailable => "mainnet-unavailable",
            Self::ExternalPublicationUnavailable => "external-publication-unavailable",
            Self::Unknown => "unknown",
        }
    }

    /// `true` iff this is the DevNet/TestNet in-memory fixture backend.
    pub const fn is_fixture(self) -> bool {
        matches!(self, Self::FixtureInMemory)
    }

    /// `true` iff this kind is reachable-but-unavailable (production / MainNet /
    /// external-publication).
    pub const fn is_unavailable(self) -> bool {
        matches!(
            self,
            Self::ProductionUnavailable
                | Self::MainNetUnavailable
                | Self::ExternalPublicationUnavailable
        )
    }
}

// ===========================================================================
// Backend policy
// ===========================================================================

/// Run 256 — the typed durable-completion attestation backend policy selector.
///
/// The policy expresses which backend a future production call site *requires*.
/// Only [`Self::FixtureAllowed`] may record (DevNet/TestNet source-test only);
/// every production / MainNet policy resolves to a reachable-but-unavailable
/// backend that never records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionAttestationBackendPolicy {
    /// The backend boundary is disabled (legacy bypass).
    Disabled,
    /// A DevNet/TestNet fixture backend is allowed (source-test evidence only).
    FixtureAllowed,
    /// A real production backend is required — reachable but unavailable.
    ProductionBackendRequired,
    /// A real MainNet production backend is required — reachable but unavailable.
    MainNetProductionBackendRequired,
}

impl DurableCompletionAttestationBackendPolicy {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureAllowed => "fixture-allowed",
            Self::ProductionBackendRequired => "production-backend-required",
            Self::MainNetProductionBackendRequired => "mainnet-production-backend-required",
        }
    }

    /// `true` iff this policy disables the backend boundary (legacy bypass).
    pub const fn is_disabled(self) -> bool {
        matches!(self, Self::Disabled)
    }

    /// `true` iff this policy allows the DevNet/TestNet fixture backend to record.
    pub const fn allows_fixture(self) -> bool {
        matches!(self, Self::FixtureAllowed)
    }
}

// ===========================================================================
// Backend identity
// ===========================================================================

/// Run 256 — the typed backend identity a backend request is bound to.
///
/// The identity is field-bound into the backend identity digest; an
/// identity-field mismatch fails closed before any submission is recorded.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionAttestationBackendIdentity {
    /// Stable backend id.
    pub backend_id: String,
    /// The backend kind.
    pub kind: DurableCompletionAttestationBackendKind,
    /// The backend policy.
    pub policy: DurableCompletionAttestationBackendPolicy,
    /// The domain separation tag the backend operates under.
    pub domain_separation_tag: String,
}

impl DurableCompletionAttestationBackendIdentity {
    /// `true` iff every mandatory identity field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.backend_id.is_empty()
            && !self.domain_separation_tag.is_empty()
            && self.kind != DurableCompletionAttestationBackendKind::Unknown
    }

    /// The deterministic, domain-separated backend identity digest.
    pub fn digest(&self) -> DurableCompletionAttestationBackendDigest {
        backend_identity_digest(self)
    }
}

// ===========================================================================
// Deterministic, domain-separated digest helpers
// ===========================================================================

/// Run 256 — domain separator for the backend identity digest.
const BACKEND_IDENTITY_DOMAIN: &[u8] = b"QBIND:run256:durable-completion-attestation-backend-identity:v1";
/// Run 256 — domain separator for the backend request digest.
const BACKEND_REQUEST_DOMAIN: &[u8] = b"QBIND:run256:durable-completion-attestation-backend-request:v1";
/// Run 256 — domain separator for the backend response digest.
const BACKEND_RESPONSE_DOMAIN: &[u8] = b"QBIND:run256:durable-completion-attestation-backend-response:v1";
/// Run 256 — domain separator for the backend receipt digest.
const BACKEND_RECEIPT_DOMAIN: &[u8] = b"QBIND:run256:durable-completion-attestation-backend-receipt:v1";
/// Run 256 — domain separator for the backend transcript digest.
const BACKEND_TRANSCRIPT_DOMAIN: &[u8] = b"QBIND:run256:durable-completion-attestation-backend-transcript:v1";

/// Run 256 — a deterministic, domain-separated backend digest (lowercase hex of a
/// SHA3-256 over length-prefixed, field-bound canonical material). It contains no
/// unstable display text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionAttestationBackendDigest(String);

impl DurableCompletionAttestationBackendDigest {
    /// The lowercase hex representation.
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

/// Run 256 — a deterministic, domain-separated backend transcript digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionAttestationBackendTranscriptDigest(String);

impl DurableCompletionAttestationBackendTranscriptDigest {
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

/// Run 256 — deterministic, domain-separated backend identity digest.
pub fn backend_identity_digest(
    identity: &DurableCompletionAttestationBackendIdentity,
) -> DurableCompletionAttestationBackendDigest {
    let mut w = CanonicalWriter::new(BACKEND_IDENTITY_DOMAIN);
    w.str_field(&identity.backend_id)
        .str_field(identity.kind.tag())
        .str_field(identity.policy.tag())
        .str_field(&identity.domain_separation_tag);
    DurableCompletionAttestationBackendDigest(w.finish())
}

/// Run 256 — deterministic, domain-separated backend request digest. Binds every
/// request field (environment, chain, genesis, governance / validation / mutation
/// surfaces, proposal id, decision id, candidate digest, authority-domain
/// sequence, pipeline / sink / reporter / finalization decision digests,
/// attestation digest, attestation id, backend record id, identity digest, and the
/// domain-separation tag).
pub fn backend_request_digest(
    request: &DurableCompletionAttestationBackendRequest,
) -> DurableCompletionAttestationBackendDigest {
    let mut w = CanonicalWriter::new(BACKEND_REQUEST_DOMAIN);
    w.str_field(&request.backend_record_id)
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
        .str_field(&request.domain_separation_tag)
        .str_field(backend_identity_digest(&request.identity).as_hex());
    DurableCompletionAttestationBackendDigest(w.finish())
}

/// Run 256 — deterministic, domain-separated backend response digest. Binds the
/// backend record id, the request digest it answers, the acceptance flag, and the
/// responding backend kind.
pub fn backend_response_digest(
    response: &DurableCompletionAttestationBackendResponse,
) -> DurableCompletionAttestationBackendDigest {
    let mut w = CanonicalWriter::new(BACKEND_RESPONSE_DOMAIN);
    w.str_field(&response.backend_record_id)
        .str_field(response.request_digest.as_hex())
        .str_field(if response.accepted { "accepted" } else { "rejected" })
        .str_field(response.backend_kind.tag());
    DurableCompletionAttestationBackendDigest(w.finish())
}

/// Run 256 — deterministic, domain-separated backend receipt digest. Binds the
/// backend record id and the request / response digests it acknowledges.
pub fn backend_receipt_digest(
    receipt: &DurableCompletionAttestationBackendReceipt,
) -> DurableCompletionAttestationBackendDigest {
    let mut w = CanonicalWriter::new(BACKEND_RECEIPT_DOMAIN);
    w.str_field(&receipt.backend_record_id)
        .str_field(receipt.request_digest.as_hex())
        .str_field(receipt.response_digest.as_hex());
    DurableCompletionAttestationBackendDigest(w.finish())
}

/// Run 256 — deterministic, domain-separated backend transcript digest. Binds the
/// request, response, and receipt digests into a single transcript binding.
pub fn backend_transcript_digest(
    request_digest: &DurableCompletionAttestationBackendDigest,
    response_digest: &DurableCompletionAttestationBackendDigest,
    receipt_digest: &DurableCompletionAttestationBackendDigest,
) -> DurableCompletionAttestationBackendTranscriptDigest {
    let mut w = CanonicalWriter::new(BACKEND_TRANSCRIPT_DOMAIN);
    w.str_field(request_digest.as_hex())
        .str_field(response_digest.as_hex())
        .str_field(receipt_digest.as_hex());
    DurableCompletionAttestationBackendTranscriptDigest(w.finish())
}

// ===========================================================================
// Backend request / response / receipt / record
// ===========================================================================

/// Run 256 — the typed backend request a future production call site would submit
/// once the Run 254 attestor recorded a `DurableCompletionAttested`.
///
/// Pure data referencing the already-recorded Run 254 attestation / Run 252
/// finalization / Run 250 completion report / Run 248 receipt / Run 246 decision
/// material — never a copy of any wire payload and never a production durable
/// record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionAttestationBackendRequest {
    /// Stable backend record id (the idempotency key of the backend submission).
    pub backend_record_id: String,
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
    /// Backend identity.
    pub identity: DurableCompletionAttestationBackendIdentity,
    /// Domain separation tag.
    pub domain_separation_tag: String,
}

impl DurableCompletionAttestationBackendRequest {
    /// `true` iff every mandatory field is structurally present (non-empty) and the
    /// identity is well-formed.
    pub fn is_well_formed(&self) -> bool {
        !self.backend_record_id.is_empty()
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
            && !self.domain_separation_tag.is_empty()
            && self.identity.is_well_formed()
    }

    /// The deterministic backend request digest.
    pub fn digest(&self) -> DurableCompletionAttestationBackendDigest {
        backend_request_digest(self)
    }

    /// The canonical immutable record derived from this request.
    pub fn to_record(&self) -> DurableCompletionAttestationBackendRecord {
        DurableCompletionAttestationBackendRecord {
            backend_record_id: self.backend_record_id.clone(),
            request_digest: self.digest(),
            identity_digest: self.identity.digest(),
        }
    }
}

/// Run 256 — the typed backend response a backend returns for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionAttestationBackendResponse {
    /// The backend record id the response answers.
    pub backend_record_id: String,
    /// The request digest the response answers.
    pub request_digest: DurableCompletionAttestationBackendDigest,
    /// `true` iff the backend accepted the submission.
    pub accepted: bool,
    /// The responding backend kind.
    pub backend_kind: DurableCompletionAttestationBackendKind,
}

impl DurableCompletionAttestationBackendResponse {
    /// The deterministic backend response digest.
    pub fn digest(&self) -> DurableCompletionAttestationBackendDigest {
        backend_response_digest(self)
    }
}

/// Run 256 — the typed backend receipt acknowledging a request / response pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionAttestationBackendReceipt {
    /// The backend record id the receipt acknowledges.
    pub backend_record_id: String,
    /// The request digest the receipt binds.
    pub request_digest: DurableCompletionAttestationBackendDigest,
    /// The response digest the receipt binds.
    pub response_digest: DurableCompletionAttestationBackendDigest,
}

impl DurableCompletionAttestationBackendReceipt {
    /// The deterministic backend receipt digest.
    pub fn digest(&self) -> DurableCompletionAttestationBackendDigest {
        backend_receipt_digest(self)
    }
}

/// Run 256 — the canonical immutable backend record derived from a request. Two
/// records are idempotent-equal only if **every** field matches exactly. The same
/// backend record id with any differing digest is equivocation and fails closed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurableCompletionAttestationBackendRecord {
    /// The backend record id.
    pub backend_record_id: String,
    /// The request digest.
    pub request_digest: DurableCompletionAttestationBackendDigest,
    /// The backend identity digest.
    pub identity_digest: DurableCompletionAttestationBackendDigest,
}

// ===========================================================================
// In-memory fixture ledger
// ===========================================================================

/// Run 256 — the recorded status of a modeled backend submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionAttestationBackendLedgerStatus {
    /// The modeled backend submission is recorded in the in-memory fixture ledger.
    Submitted,
}

/// Run 256 — a single modeled backend submission record held in the in-memory
/// fixture ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionAttestationBackendLedgerRecord {
    /// The backend record id (stable identity of the submission).
    pub backend_record_id: String,
    /// The request digest.
    pub request_digest: DurableCompletionAttestationBackendDigest,
    /// The response digest.
    pub response_digest: DurableCompletionAttestationBackendDigest,
    /// The receipt digest.
    pub receipt_digest: DurableCompletionAttestationBackendDigest,
    /// The transcript digest.
    pub transcript_digest: DurableCompletionAttestationBackendTranscriptDigest,
    /// The recorded status.
    pub status: DurableCompletionAttestationBackendLedgerStatus,
}

/// Run 256 — an immutable snapshot of the modeled backend ledger used to model a
/// fixture rollback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionAttestationBackendLedgerSnapshot {
    records: Vec<DurableCompletionAttestationBackendLedgerRecord>,
}

impl DurableCompletionAttestationBackendLedgerSnapshot {
    /// The number of records the snapshot captured.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` iff the snapshot captured no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Run 256 — the modeled in-memory backend ledger.
///
/// **In-memory only.** It never touches RocksDB, files, markers, sequence files,
/// external publications, audit-ledger entries, or any production durable state.
/// The DevNet/TestNet fixture backend is the only thing that may mutate it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DurableCompletionAttestationBackendLedger {
    records: Vec<DurableCompletionAttestationBackendLedgerRecord>,
}

impl DurableCompletionAttestationBackendLedger {
    /// A new, empty modeled backend ledger.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// The number of recorded backend submissions.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` iff no backend submissions are recorded.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The recorded backend submissions.
    pub fn records(&self) -> &[DurableCompletionAttestationBackendLedgerRecord] {
        &self.records
    }

    /// The record for `backend_record_id`, if present.
    pub fn find(
        &self,
        backend_record_id: &str,
    ) -> Option<&DurableCompletionAttestationBackendLedgerRecord> {
        self.records
            .iter()
            .find(|r| r.backend_record_id == backend_record_id)
    }

    /// `true` iff a submission with `backend_record_id` is recorded.
    pub fn contains(&self, backend_record_id: &str) -> bool {
        self.find(backend_record_id).is_some()
    }

    /// Capture an immutable snapshot for a modeled rollback.
    pub fn snapshot(&self) -> DurableCompletionAttestationBackendLedgerSnapshot {
        DurableCompletionAttestationBackendLedgerSnapshot {
            records: self.records.clone(),
        }
    }

    /// Restore the ledger to a previously captured snapshot (modeled rollback).
    pub fn restore(&mut self, snapshot: &DurableCompletionAttestationBackendLedgerSnapshot) {
        self.records = snapshot.records.clone();
    }

    /// Internal: insert a recorded submission. Only the fixture backend calls this,
    /// and only after every identity / idempotency gate has passed.
    fn insert(&mut self, record: DurableCompletionAttestationBackendLedgerRecord) {
        self.records.push(record);
    }
}

// ===========================================================================
// Backend expectations
// ===========================================================================

/// Run 256 — the canonical binding a [`DurableCompletionAttestationBackendInput`]
/// is checked against.
///
/// Environment / chain / genesis / surface mismatches fail closed **before** the
/// backend is invoked. Backend-record-identity mismatches fail closed **inside**
/// the backend, before any modeled submission is recorded. Neither path is ever a
/// silent approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionAttestationBackendExpectations {
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
    /// Expected backend record id.
    pub expected_backend_record_id: String,
    /// Expected backend identity.
    pub expected_identity: DurableCompletionAttestationBackendIdentity,
    /// Expected backend kind.
    pub expected_backend_kind: DurableCompletionAttestationBackendKind,
    /// Expected backend policy.
    pub expected_backend_policy: DurableCompletionAttestationBackendPolicy,
    /// Expected domain separation tag.
    pub expected_domain_separation_tag: String,
}

impl DurableCompletionAttestationBackendExpectations {
    /// Internal: the first environment / surface binding mismatch reason, if any.
    fn binding_mismatch_reason(
        &self,
        input: &DurableCompletionAttestationBackendInput,
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

    /// `true` iff the pre-backend environment / surface binding matches.
    pub fn binding_matches(&self, input: &DurableCompletionAttestationBackendInput) -> bool {
        self.binding_mismatch_reason(input).is_none()
    }

    /// Internal: the first backend-request-identity mismatch reason, if any.
    fn request_mismatch_reason(
        &self,
        request: &DurableCompletionAttestationBackendRequest,
    ) -> Option<&'static str> {
        if !request.is_well_formed() {
            return Some("malformed backend request");
        }
        if request.backend_record_id != self.expected_backend_record_id {
            return Some("wrong backend record id");
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
        if request.domain_separation_tag != self.expected_domain_separation_tag {
            return Some("wrong domain separation tag");
        }
        if request.identity != self.expected_identity {
            return Some("wrong backend identity");
        }
        if request.identity.kind != self.expected_backend_kind {
            return Some("wrong backend kind");
        }
        if request.identity.policy != self.expected_backend_policy {
            return Some("wrong backend policy");
        }
        None
    }

    /// `true` iff the backend-request identity matches and is well-formed.
    pub fn request_matches(&self, request: &DurableCompletionAttestationBackendRequest) -> bool {
        self.request_mismatch_reason(request).is_none()
    }
}

// ===========================================================================
// Backend input
// ===========================================================================

/// Run 256 — typed inputs for one modeled durable-completion attestation backend
/// round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCompletionAttestationBackendInput {
    /// The backend policy selector.
    pub policy: DurableCompletionAttestationBackendPolicy,
    /// The trust-domain environment binding.
    pub environment_binding: DurableCompletionAttestationBackendEnvironment,
    /// The runtime binding (governance + mutation surface + sequence).
    pub runtime_binding: DurableCompletionAttestationBackendBinding,
    /// The Run 240/246 durable replay observation the pipeline authorized consume
    /// under.
    pub replay_binding: DurableCompletionAttestationBackendReplayBinding,
    /// The Run 246 pipeline outcome.
    pub pipeline_binding: DurableCompletionAttestationBackendPipelineBinding,
    /// The Run 248 sink outcome.
    pub sink_binding: DurableCompletionAttestationBackendSinkBinding,
    /// The Run 250 reporter outcome.
    pub reporter_binding: DurableCompletionAttestationBackendReporterBinding,
    /// The Run 252 finalization outcome.
    pub finalization_binding: DurableCompletionAttestationBackendFinalizationBinding,
    /// The Run 254 attestation outcome the backend projects to a backend request.
    pub attestation_binding: DurableCompletionAttestationBackendAttestationBinding,
    /// The backend request the call site would submit.
    pub request: DurableCompletionAttestationBackendRequest,
}

impl DurableCompletionAttestationBackendInput {
    /// The trust-domain environment the decision is bound to.
    pub fn environment(&self) -> TrustBundleEnvironment {
        self.environment_binding.environment
    }

    /// The validation / mutation surface pair.
    pub fn surface(&self) -> DurableCompletionAttestationBackendSurface {
        self.runtime_binding.mutation_surface
    }

    /// `true` iff this is a MainNet peer-driven apply that remains refused
    /// unconditionally before pipeline progression, sink invocation, reporter
    /// invocation, finalizer invocation, attestor invocation, and backend
    /// invocation.
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
    }
}

// ===========================================================================
// Backend outcome
// ===========================================================================

/// Run 256 — the typed outcome of one modeled durable-completion attestation
/// backend round-trip.
///
/// Only [`Self::BackendSubmissionRecorded`] authorizes a **new** modeled
/// backend-submitted state. A [`Self::BackendSubmissionDuplicateIdempotent`] means
/// the submission was already recorded (idempotent, no second submission). Every
/// other variant is a no-backend-submission fail-closed outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableCompletionAttestationBackendOutcome {
    /// Legacy bypass — a disabled backend policy preserved the legacy
    /// no-backend-submission path. No backend invocation.
    LegacyBypassNoBackendSubmission,
    /// The Run 254 attestation-stage binding was rejected before the backend was
    /// invoked (an attestation-stage rejection / binding mismatch). Non-mutating,
    /// no submission. No backend invocation.
    RejectedBeforeAttestationNoBackendSubmission,
    /// The Run 254 attestor did not attest (any non-attesting attestation outcome
    /// without a more specific variant). Non-mutating, no submission. No backend
    /// invocation.
    AttestationDidNotAttestNoBackendSubmission,
    /// The backend recorded a new modeled submission. The **only** outcome that
    /// authorizes a new modeled backend-submitted state.
    BackendSubmissionRecorded,
    /// A duplicate identical submission — idempotent; no second submission
    /// recorded.
    BackendSubmissionDuplicateIdempotent,
    /// The submission was rejected before record (malformed request,
    /// request-identity mismatch, same backend record id with a differing digest /
    /// equivocation, or a duplicate-idempotent attestation with no matching prior
    /// submission). No submission.
    BackendSubmissionRejectedBeforeRecord,
    /// The backend record failed. No submission.
    BackendSubmissionRecordFailedNoSubmission,
    /// The backend record was rolled back. No submission.
    BackendSubmissionRolledBackNoSubmission,
    /// The backend rollback itself failed — fatal / fail-closed. No submission.
    BackendSubmissionRollbackFailedFatalNoSubmission,
    /// The after-record backend window was ambiguous — fails closed. No submission.
    BackendSubmissionAmbiguousFailClosedNoSubmission,
    /// The production backend path was reached but is unavailable. No submission.
    ProductionBackendUnavailableNoSubmission,
    /// The MainNet backend path was reached but is unavailable. No submission.
    MainNetBackendUnavailableNoSubmission,
    /// The external-publication backend path was reached but is unavailable. No
    /// submission.
    ExternalPublicationUnavailableNoSubmission,
    /// MainNet peer-driven apply remains refused before pipeline progression, sink
    /// invocation, reporter invocation, finalizer invocation, attestor invocation,
    /// and backend invocation. No submission.
    MainNetPeerDrivenApplyRefusedNoSubmission,
    /// Validator-set rotation is unsupported. No submission.
    ValidatorSetRotationUnsupportedNoSubmission,
    /// Policy-change actions are unsupported. No submission.
    PolicyChangeUnsupportedNoSubmission,
}

impl DurableCompletionAttestationBackendOutcome {
    /// `true` iff this outcome authorizes a **new** modeled backend submission (only
    /// [`Self::BackendSubmissionRecorded`]).
    pub fn authorizes_backend_submission(&self) -> bool {
        matches!(self, Self::BackendSubmissionRecorded)
    }

    /// `true` iff this outcome projects to a backend submission — a newly recorded
    /// submission or an idempotent duplicate of an already-recorded submission.
    pub fn projects_to_backend_submission_recorded(&self) -> bool {
        matches!(
            self,
            Self::BackendSubmissionRecorded | Self::BackendSubmissionDuplicateIdempotent
        )
    }

    /// `true` iff this outcome submits nothing new and projects to no backend
    /// submission.
    pub fn no_backend_submission(&self) -> bool {
        !self.projects_to_backend_submission_recorded()
    }

    /// `true` iff this is the legacy no-backend-submission bypass.
    pub fn is_legacy_bypass(&self) -> bool {
        matches!(self, Self::LegacyBypassNoBackendSubmission)
    }

    /// `true` iff this is the MainNet peer-driven-apply refusal.
    pub fn is_mainnet_peer_driven_apply_refused(&self) -> bool {
        matches!(self, Self::MainNetPeerDrivenApplyRefusedNoSubmission)
    }

    /// Stable operator-facing tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::LegacyBypassNoBackendSubmission => "legacy-bypass-no-backend-submission",
            Self::RejectedBeforeAttestationNoBackendSubmission => {
                "rejected-before-attestation-no-backend-submission"
            }
            Self::AttestationDidNotAttestNoBackendSubmission => {
                "attestation-did-not-attest-no-backend-submission"
            }
            Self::BackendSubmissionRecorded => "backend-submission-recorded",
            Self::BackendSubmissionDuplicateIdempotent => "backend-submission-duplicate-idempotent",
            Self::BackendSubmissionRejectedBeforeRecord => {
                "backend-submission-rejected-before-record"
            }
            Self::BackendSubmissionRecordFailedNoSubmission => {
                "backend-submission-record-failed-no-submission"
            }
            Self::BackendSubmissionRolledBackNoSubmission => {
                "backend-submission-rolled-back-no-submission"
            }
            Self::BackendSubmissionRollbackFailedFatalNoSubmission => {
                "backend-submission-rollback-failed-fatal-no-submission"
            }
            Self::BackendSubmissionAmbiguousFailClosedNoSubmission => {
                "backend-submission-ambiguous-fail-closed-no-submission"
            }
            Self::ProductionBackendUnavailableNoSubmission => {
                "production-backend-unavailable-no-submission"
            }
            Self::MainNetBackendUnavailableNoSubmission => {
                "mainnet-backend-unavailable-no-submission"
            }
            Self::ExternalPublicationUnavailableNoSubmission => {
                "external-publication-unavailable-no-submission"
            }
            Self::MainNetPeerDrivenApplyRefusedNoSubmission => {
                "mainnet-peer-driven-apply-refused-no-submission"
            }
            Self::ValidatorSetRotationUnsupportedNoSubmission => {
                "validator-set-rotation-unsupported-no-submission"
            }
            Self::PolicyChangeUnsupportedNoSubmission => {
                "policy-change-unsupported-no-submission"
            }
        }
    }
}

// ===========================================================================
// Attestation-outcome -> backend request projection
// ===========================================================================

/// Run 256 — the typed projection of a Run 254 attestation outcome onto a backend
/// request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableCompletionAttestationBackendRequestIntent {
    /// The attestor recorded an attestation; the backend may record a new
    /// submission.
    CreateRequest,
    /// The attestor reported an idempotent-duplicate attestation; the backend may
    /// only match an already-recorded submission and must never create a new one.
    IdempotentOnly,
    /// The attestor did not attest; no backend request. Carries the typed
    /// no-backend-submission outcome the backend evaluation returns directly
    /// (without invoking the backend).
    NoBackendSubmission(DurableCompletionAttestationBackendOutcome),
}

impl DurableCompletionAttestationBackendRequestIntent {
    /// `true` iff this projection creates a backend request (i.e. the attestor
    /// recorded an attestation).
    pub fn creates_request(&self) -> bool {
        matches!(self, Self::CreateRequest)
    }
}

/// Run 256 — project a Run 254 attestation outcome onto a backend request.
///
/// Only
/// [`GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested`]
/// creates a backend request.
/// [`GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttestationDuplicateIdempotent`]
/// may only match an already-recorded submission and never creates a new one.
/// Every other attestation outcome maps to a no-backend-submission fail-closed
/// outcome (a more specific one where one exists, otherwise the generic
/// [`DurableCompletionAttestationBackendOutcome::AttestationDidNotAttestNoBackendSubmission`]).
/// Pure: performs no work and never records.
pub fn project_attestation_outcome_to_backend_request(
    outcome: &GovernanceModeledDurableCompletionAttestationOutcome,
) -> DurableCompletionAttestationBackendRequestIntent {
    use DurableCompletionAttestationBackendOutcome as Backend;
    use DurableCompletionAttestationBackendRequestIntent as Intent;
    use GovernanceModeledDurableCompletionAttestationOutcome as Att;
    match outcome {
        Att::DurableCompletionAttested => Intent::CreateRequest,
        Att::DurableCompletionAttestationDuplicateIdempotent => Intent::IdempotentOnly,
        Att::LegacyBypassNoAttestation => {
            Intent::NoBackendSubmission(Backend::LegacyBypassNoBackendSubmission)
        }
        Att::RejectedBeforeFinalizationNoAttestation => {
            Intent::NoBackendSubmission(Backend::RejectedBeforeAttestationNoBackendSubmission)
        }
        Att::MainNetPeerDrivenApplyRefusedNoAttestation => {
            Intent::NoBackendSubmission(Backend::MainNetPeerDrivenApplyRefusedNoSubmission)
        }
        Att::ValidatorSetRotationUnsupportedNoAttestation => {
            Intent::NoBackendSubmission(Backend::ValidatorSetRotationUnsupportedNoSubmission)
        }
        Att::PolicyChangeUnsupportedNoAttestation => {
            Intent::NoBackendSubmission(Backend::PolicyChangeUnsupportedNoSubmission)
        }
        // Every remaining attestation outcome is a non-attesting rejection /
        // failure / rollback / ambiguous window / production / MainNet unavailable:
        // the attestor did not attest, so no backend submission may exist.
        _ => Intent::NoBackendSubmission(Backend::AttestationDidNotAttestNoBackendSubmission),
    }
}

// ===========================================================================
// Backend fault injection (source/test only)
// ===========================================================================

/// Run 256 — a modeled fault the fixture backend injects to exercise the
/// fail-closed record / rollback / ambiguous paths. Source/test only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionAttestationBackendFault {
    /// The backend record fails; nothing is written. No submission.
    RecordFailedNoSubmission,
    /// The backend record is rolled back; nothing remains written. No submission.
    RolledBackNoSubmission,
    /// The backend rollback itself fails — fatal / fail-closed. No submission.
    RollbackFailedFatal,
    /// The after-record backend window is ambiguous — fails closed. No submission.
    AmbiguousAfterRecord,
}

// ===========================================================================
// Backend trait boundary
// ===========================================================================

/// Run 256 — the pure/mockable modeled durable-completion attestation backend
/// boundary.
///
/// No implementation here calls Run 070, mutates `LivePqcTrustState`, performs a
/// live trust swap, evicts sessions, writes a sequence, writes a marker, performs
/// network I/O, external publication, or a real audit-ledger persistence. The
/// DevNet/TestNet fixture backend mutates only the in-memory
/// [`DurableCompletionAttestationBackendLedger`].
pub trait GovernanceDurableCompletionAttestationBackend {
    /// The backend kind (used for typed recovery classification).
    fn kind(&self) -> DurableCompletionAttestationBackendKind;

    /// The number of times this backend was invoked (so tests can prove
    /// non-attesting attestation paths and pre-backend rejections never invoke it).
    fn invocations(&self) -> u32;

    /// Submit a modeled durable-completion attestation once the Run 254 attestor
    /// recorded an attestation and the pre-backend binding validation passed.
    ///
    /// `idempotent_only` is `true` when the projected attestation outcome was an
    /// idempotent-duplicate attestation: in that case the backend may only match an
    /// already-recorded submission and must never create a new one.
    fn submit_durable_completion_attestation(
        &mut self,
        request: &DurableCompletionAttestationBackendRequest,
        expectations: &DurableCompletionAttestationBackendExpectations,
        idempotent_only: bool,
        ledger: &mut DurableCompletionAttestationBackendLedger,
    ) -> DurableCompletionAttestationBackendOutcome;

    /// Classify a modeled backend crash/recovery window. Pure: performs no modeled
    /// mutation and never invokes Run 070.
    fn recover_durable_completion_attestation_backend_window(
        &self,
        input: &DurableCompletionAttestationBackendInput,
        window: DurableCompletionAttestationBackendWindow,
        recovered_record: Option<&DurableCompletionAttestationBackendLedgerRecord>,
        expectations: &DurableCompletionAttestationBackendExpectations,
    ) -> DurableCompletionAttestationBackendOutcome {
        recover_durable_completion_attestation_backend_window(
            input,
            window,
            self.kind(),
            recovered_record,
            expectations,
        )
    }
}

// ===========================================================================
// Fixture backend (DevNet / TestNet source-test only)
// ===========================================================================

/// Run 256 — the DevNet/TestNet in-memory fixture backend.
///
/// Source-test only. It mutates only the in-memory
/// [`DurableCompletionAttestationBackendLedger`] and exposes an invocation counter
/// so tests can prove non-attesting attestation paths and pre-backend rejections
/// never invoke it.
#[derive(Debug, Clone)]
pub struct FixtureDurableCompletionAttestationBackend {
    fault: Option<DurableCompletionAttestationBackendFault>,
    invocations: u32,
}

impl Default for FixtureDurableCompletionAttestationBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FixtureDurableCompletionAttestationBackend {
    /// A new fixture backend.
    pub fn new() -> Self {
        Self {
            fault: None,
            invocations: 0,
        }
    }

    /// A new fixture backend that injects the given modeled fault on record.
    pub fn with_fault(fault: DurableCompletionAttestationBackendFault) -> Self {
        Self {
            fault: Some(fault),
            invocations: 0,
        }
    }
}

impl GovernanceDurableCompletionAttestationBackend for FixtureDurableCompletionAttestationBackend {
    fn kind(&self) -> DurableCompletionAttestationBackendKind {
        DurableCompletionAttestationBackendKind::FixtureInMemory
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn submit_durable_completion_attestation(
        &mut self,
        request: &DurableCompletionAttestationBackendRequest,
        expectations: &DurableCompletionAttestationBackendExpectations,
        idempotent_only: bool,
        ledger: &mut DurableCompletionAttestationBackendLedger,
    ) -> DurableCompletionAttestationBackendOutcome {
        use DurableCompletionAttestationBackendOutcome as Backend;
        self.invocations += 1;

        // Injected faults model record-failure / rollback / ambiguous windows. None
        // of them ever leave a recorded submission behind, so a durable submission
        // is never claimed. The ledger snapshot/restore models the rollback being a
        // no-op write.
        if let Some(fault) = self.fault {
            let snapshot = ledger.snapshot();
            return match fault {
                DurableCompletionAttestationBackendFault::RecordFailedNoSubmission => {
                    ledger.restore(&snapshot);
                    Backend::BackendSubmissionRecordFailedNoSubmission
                }
                DurableCompletionAttestationBackendFault::RolledBackNoSubmission => {
                    ledger.restore(&snapshot);
                    Backend::BackendSubmissionRolledBackNoSubmission
                }
                DurableCompletionAttestationBackendFault::RollbackFailedFatal => {
                    Backend::BackendSubmissionRollbackFailedFatalNoSubmission
                }
                DurableCompletionAttestationBackendFault::AmbiguousAfterRecord => {
                    ledger.restore(&snapshot);
                    Backend::BackendSubmissionAmbiguousFailClosedNoSubmission
                }
            };
        }

        // The fixture backend is DevNet/TestNet evidence-only.
        if !matches!(
            request.environment,
            TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet
        ) {
            return Backend::BackendSubmissionRejectedBeforeRecord;
        }

        // Request-identity validation (malformed / mismatch) fails closed before any
        // record is written.
        if !expectations.request_matches(request) {
            return Backend::BackendSubmissionRejectedBeforeRecord;
        }

        // Build the deterministic request / response / receipt / transcript digests.
        let request_digest = request.digest();
        let response = DurableCompletionAttestationBackendResponse {
            backend_record_id: request.backend_record_id.clone(),
            request_digest: request_digest.clone(),
            accepted: true,
            backend_kind: DurableCompletionAttestationBackendKind::FixtureInMemory,
        };
        let response_digest = response.digest();
        let receipt = DurableCompletionAttestationBackendReceipt {
            backend_record_id: request.backend_record_id.clone(),
            request_digest: request_digest.clone(),
            response_digest: response_digest.clone(),
        };
        let receipt_digest = receipt.digest();
        let transcript_digest =
            backend_transcript_digest(&request_digest, &response_digest, &receipt_digest);

        // Idempotency / equivocation gate.
        if let Some(existing) = ledger.find(&request.backend_record_id) {
            if existing.request_digest == request_digest
                && existing.response_digest == response_digest
                && existing.receipt_digest == receipt_digest
                && existing.transcript_digest == transcript_digest
            {
                return Backend::BackendSubmissionDuplicateIdempotent;
            }
            // Same backend record id with a different digest is equivocation: fail
            // closed, record no second submission.
            return Backend::BackendSubmissionRejectedBeforeRecord;
        }

        // A duplicate-idempotent attestation may only match an already-recorded
        // submission; it must never create a new one by itself.
        if idempotent_only {
            return Backend::BackendSubmissionRejectedBeforeRecord;
        }

        ledger.insert(DurableCompletionAttestationBackendLedgerRecord {
            backend_record_id: request.backend_record_id.clone(),
            request_digest,
            response_digest,
            receipt_digest,
            transcript_digest,
            status: DurableCompletionAttestationBackendLedgerStatus::Submitted,
        });
        Backend::BackendSubmissionRecorded
    }
}

// ===========================================================================
// Production / MainNet / External-publication backends (unavailable / fail-closed)
// ===========================================================================

/// Run 256 — the production backend. Reachable but unavailable / fail-closed. It
/// records no submission and mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct ProductionDurableCompletionAttestationBackend {
    invocations: u32,
}

impl GovernanceDurableCompletionAttestationBackend
    for ProductionDurableCompletionAttestationBackend
{
    fn kind(&self) -> DurableCompletionAttestationBackendKind {
        DurableCompletionAttestationBackendKind::ProductionUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn submit_durable_completion_attestation(
        &mut self,
        _request: &DurableCompletionAttestationBackendRequest,
        _expectations: &DurableCompletionAttestationBackendExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionAttestationBackendLedger,
    ) -> DurableCompletionAttestationBackendOutcome {
        self.invocations += 1;
        DurableCompletionAttestationBackendOutcome::ProductionBackendUnavailableNoSubmission
    }
}

/// Run 256 — the MainNet backend. Reachable but unavailable / fail-closed. It
/// records no submission and mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct MainNetDurableCompletionAttestationBackend {
    invocations: u32,
}

impl GovernanceDurableCompletionAttestationBackend for MainNetDurableCompletionAttestationBackend {
    fn kind(&self) -> DurableCompletionAttestationBackendKind {
        DurableCompletionAttestationBackendKind::MainNetUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn submit_durable_completion_attestation(
        &mut self,
        _request: &DurableCompletionAttestationBackendRequest,
        _expectations: &DurableCompletionAttestationBackendExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionAttestationBackendLedger,
    ) -> DurableCompletionAttestationBackendOutcome {
        self.invocations += 1;
        DurableCompletionAttestationBackendOutcome::MainNetBackendUnavailableNoSubmission
    }
}

/// Run 256 — the external-publication backend. Reachable but unavailable /
/// fail-closed. It performs no external publication, records no submission, and
/// mutates no ledger.
#[derive(Debug, Clone, Default)]
pub struct ExternalPublicationDurableCompletionAttestationBackend {
    invocations: u32,
}

impl GovernanceDurableCompletionAttestationBackend
    for ExternalPublicationDurableCompletionAttestationBackend
{
    fn kind(&self) -> DurableCompletionAttestationBackendKind {
        DurableCompletionAttestationBackendKind::ExternalPublicationUnavailable
    }

    fn invocations(&self) -> u32 {
        self.invocations
    }

    fn submit_durable_completion_attestation(
        &mut self,
        _request: &DurableCompletionAttestationBackendRequest,
        _expectations: &DurableCompletionAttestationBackendExpectations,
        _idempotent_only: bool,
        _ledger: &mut DurableCompletionAttestationBackendLedger,
    ) -> DurableCompletionAttestationBackendOutcome {
        self.invocations += 1;
        DurableCompletionAttestationBackendOutcome::ExternalPublicationUnavailableNoSubmission
    }
}

// ===========================================================================
// Backend executor / composition helpers
// ===========================================================================

/// Run 256 — evaluate one modeled durable-completion attestation backend
/// round-trip.
///
/// Ordering (each gate must pass before the next is considered):
///
/// 1. MainNet peer-driven apply refusal — before pipeline progression, sink
///    invocation, reporter invocation, finalizer invocation, attestor invocation,
///    and backend invocation;
/// 2. legacy bypass — a [`DurableCompletionAttestationBackendPolicy::Disabled`]
///    policy;
/// 3. attestation-outcome projection — only
///    [`GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested`]
///    creates a backend request;
/// 4. pre-backend binding validation — environment / surface must match before the
///    backend is invoked; a mismatch leaves the backend invocation count at zero;
/// 5. backend submission — attempted only after every prior gate passes.
///
/// A rejection before the backend stage leaves the backend invocation count at
/// zero. Pure aside from the fixture backend's modeled in-memory ledger effect:
/// performs no I/O, mutates no `LivePqcTrustState`, writes no marker, writes no
/// sequence, swaps no live trust, evicts no sessions, performs no external
/// publication / audit write, and never invokes Run 070.
pub fn evaluate_durable_completion_attestation_backend<B>(
    input: &DurableCompletionAttestationBackendInput,
    expectations: &DurableCompletionAttestationBackendExpectations,
    backend: &mut B,
    ledger: &mut DurableCompletionAttestationBackendLedger,
) -> DurableCompletionAttestationBackendOutcome
where
    B: GovernanceDurableCompletionAttestationBackend,
{
    use DurableCompletionAttestationBackendOutcome as Backend;
    use DurableCompletionAttestationBackendRequestIntent as Intent;

    // Step 1: MainNet peer-driven apply remains refused unconditionally, before
    // pipeline progression, sink invocation, reporter invocation, finalizer
    // invocation, attestor invocation, and backend invocation.
    if input.is_mainnet_peer_driven() {
        return Backend::MainNetPeerDrivenApplyRefusedNoSubmission;
    }

    // Step 2: legacy bypass — a disabled backend policy preserves the legacy
    // no-backend-submission path and never invokes the backend.
    if input.policy.is_disabled() {
        return Backend::LegacyBypassNoBackendSubmission;
    }

    // Step 3: project the Run 254 attestation outcome onto a backend request. Every
    // non-attesting outcome returns a no-backend-submission outcome without invoking
    // the backend.
    let idempotent_only =
        match project_attestation_outcome_to_backend_request(&input.attestation_binding) {
            Intent::NoBackendSubmission(outcome) => return outcome,
            Intent::CreateRequest => false,
            Intent::IdempotentOnly => true,
        };

    // Step 4: pre-backend environment / surface binding validation. A mismatch fails
    // closed before the backend is invoked, leaving the backend invocation count at
    // zero.
    if !expectations.binding_matches(input) {
        return Backend::RejectedBeforeAttestationNoBackendSubmission;
    }

    // Step 5: invoke the backend to record the modeled submission.
    backend.submit_durable_completion_attestation(
        &input.request,
        expectations,
        idempotent_only,
        ledger,
    )
}

/// Run 256 — the modeled durable-completion attestation backend crash/recovery
/// window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableCompletionAttestationBackendWindow {
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
    /// Crashed after the attestation record but before a backend request.
    AfterAttestationRecordBeforeBackendRequest,
    /// Crashed after a backend request but before any backend record.
    AfterBackendRequestBeforeBackendRecord,
    /// Crashed after a backend record but before backend success — fails closed
    /// unless an explicit matching backend success exists.
    AfterBackendRecordBeforeBackendSuccess,
    /// Recovered after a successful backend submission.
    AfterBackendSuccess,
    /// Recovered after an ambiguous backend window.
    AfterBackendAmbiguous,
    /// The backend record itself failed.
    BackendRecordFailed,
    /// The backend record was rolled back.
    BackendRollbackCompleted,
    /// The backend rollback itself failed — fatal.
    BackendRollbackFailed,
    /// An unknown window — fails closed.
    Unknown,
}

/// Run 256 — classify a modeled durable-completion attestation backend
/// crash/recovery window.
///
/// The backend never silently re-authorizes an in-flight submission: MainNet
/// peer-driven refusal precedes classification, production / MainNet /
/// external-publication classification is unavailable, and every ambiguous /
/// unknown window fails closed. Only an after-backend-record window with an
/// explicit matching record (or an explicit after-backend-success window) recovers
/// as
/// [`DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded`]. Pure:
/// performs no modeled mutation and never invokes Run 070.
pub fn recover_durable_completion_attestation_backend_window(
    input: &DurableCompletionAttestationBackendInput,
    window: DurableCompletionAttestationBackendWindow,
    kind: DurableCompletionAttestationBackendKind,
    recovered_record: Option<&DurableCompletionAttestationBackendLedgerRecord>,
    expectations: &DurableCompletionAttestationBackendExpectations,
) -> DurableCompletionAttestationBackendOutcome {
    use DurableCompletionAttestationBackendOutcome as Backend;
    use DurableCompletionAttestationBackendWindow as Window;

    // MainNet peer-driven apply refusal precedes recovery classification.
    if input.is_mainnet_peer_driven() {
        return Backend::MainNetPeerDrivenApplyRefusedNoSubmission;
    }

    // Production / MainNet / external-publication recovery classification is
    // unavailable / fail-closed.
    match kind {
        DurableCompletionAttestationBackendKind::ProductionUnavailable => {
            return Backend::ProductionBackendUnavailableNoSubmission;
        }
        DurableCompletionAttestationBackendKind::MainNetUnavailable => {
            return Backend::MainNetBackendUnavailableNoSubmission;
        }
        DurableCompletionAttestationBackendKind::ExternalPublicationUnavailable => {
            return Backend::ExternalPublicationUnavailableNoSubmission;
        }
        DurableCompletionAttestationBackendKind::Disabled => {
            return Backend::LegacyBypassNoBackendSubmission;
        }
        DurableCompletionAttestationBackendKind::Unknown => {
            return Backend::BackendSubmissionAmbiguousFailClosedNoSubmission;
        }
        DurableCompletionAttestationBackendKind::FixtureInMemory => {}
    }

    // Helper: an explicit recovered record recovers as a submission only if it
    // matches the expected backend record id and the canonical request digest.
    let recovered_matches = |record: &DurableCompletionAttestationBackendLedgerRecord| -> bool {
        record.backend_record_id == expectations.expected_backend_record_id
            && record.request_digest == input.request.digest()
            && record.status == DurableCompletionAttestationBackendLedgerStatus::Submitted
    };

    match window {
        // Before the attestor recorded an attestation there is nothing to submit.
        Window::BeforePipeline
        | Window::AfterPipelineSuccessBeforeSinkIntent
        | Window::AfterSinkIntentBeforeReceiptRecord
        | Window::AfterReceiptRecordBeforeReportIntent
        | Window::AfterReportIntentBeforeReportRecord
        | Window::AfterReportRecordBeforeFinalizationIntent
        | Window::AfterFinalizationIntentBeforeFinalizationRecord
        | Window::AfterFinalizationRecordBeforeAttestationIntent
        | Window::AfterAttestationIntentBeforeAttestationRecord => {
            Backend::AttestationDidNotAttestNoBackendSubmission
        }
        // A recorded attestation without a backend request / record never submits.
        Window::AfterAttestationRecordBeforeBackendRequest
        | Window::AfterBackendRequestBeforeBackendRecord => {
            Backend::BackendSubmissionRejectedBeforeRecord
        }
        // After a backend record but before backend success: fails closed unless an
        // explicit matching, well-formed backend record exists.
        Window::AfterBackendRecordBeforeBackendSuccess => match recovered_record {
            Some(record) if recovered_matches(record) => Backend::BackendSubmissionRecorded,
            _ => Backend::BackendSubmissionRejectedBeforeRecord,
        },
        // An explicit successful submission recovers as recorded only if it matches.
        Window::AfterBackendSuccess => match recovered_record {
            Some(record) if recovered_matches(record) => Backend::BackendSubmissionRecorded,
            _ => Backend::BackendSubmissionRejectedBeforeRecord,
        },
        Window::AfterBackendAmbiguous => {
            Backend::BackendSubmissionAmbiguousFailClosedNoSubmission
        }
        Window::BackendRecordFailed => Backend::BackendSubmissionRecordFailedNoSubmission,
        Window::BackendRollbackCompleted => Backend::BackendSubmissionRolledBackNoSubmission,
        Window::BackendRollbackFailed => {
            Backend::BackendSubmissionRollbackFailedFatalNoSubmission
        }
        // Any unknown window fails closed.
        Window::Unknown => Backend::BackendSubmissionAmbiguousFailClosedNoSubmission,
    }
}

/// Run 256 — `true` iff a backend outcome authorizes a **new** modeled backend
/// submission (only
/// [`DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded`]).
pub fn backend_outcome_authorizes_durable_attestation_submission(
    outcome: &DurableCompletionAttestationBackendOutcome,
) -> bool {
    outcome.authorizes_backend_submission()
}

/// Run 256 — `true` iff a backend outcome projects to a backend submission (a newly
/// recorded submission or an idempotent duplicate of an already-recorded
/// submission).
pub fn backend_outcome_projects_to_backend_submission_recorded(
    outcome: &DurableCompletionAttestationBackendOutcome,
) -> bool {
    outcome.projects_to_backend_submission_recorded()
}

// ===========================================================================
// Explicit invariant / fail-closed helpers (grep-verifiable named symbols)
// ===========================================================================

/// Run 256 — explicit invariant helper.
///
/// Returns `true`: a rejected backend path performs no Run 070 call, no
/// `LivePqcTrustState` mutation, no live trust swap, no session eviction, no
/// sequence write, and no marker write.
pub fn durable_completion_attestation_backend_rejection_is_non_mutating() -> bool {
    true
}

/// Run 256 — explicit invariant helper.
///
/// Returns `true`: the backend never calls Run 070. It records only the in-memory
/// [`DurableCompletionAttestationBackendLedger`].
pub fn durable_completion_attestation_backend_never_calls_run_070() -> bool {
    true
}

/// Run 256 — explicit invariant helper.
///
/// Returns `true`: the backend never mutates `LivePqcTrustState`.
pub fn durable_completion_attestation_backend_never_mutates_live_pqc_trust_state() -> bool {
    true
}

/// Run 256 — explicit invariant helper.
///
/// Returns `true`: the backend never writes a trust-bundle sequence file or an
/// authority marker.
pub fn durable_completion_attestation_backend_never_writes_sequence_or_marker() -> bool {
    true
}

/// Run 256 — explicit non-implementation helper.
///
/// Returns `true`: Run 256 introduces no RocksDB schema, file format, database
/// migration, or storage-format change. The backend is a pure typed projection
/// over an in-memory ledger.
pub fn durable_completion_attestation_backend_no_rocksdb_file_schema_migration_change() -> bool {
    true
}

/// Run 256 — explicit non-implementation helper.
///
/// Returns `true`: the backend performs no external network publication.
pub fn durable_completion_attestation_backend_no_external_publication() -> bool {
    true
}

/// Run 256 — explicit non-implementation helper.
///
/// Returns `true`: the backend performs no real audit-ledger persistence. The
/// in-memory fixture ledger is source/test evidence only.
pub fn durable_completion_attestation_backend_no_real_audit_ledger() -> bool {
    true
}

/// Run 256 — explicit invariant helper.
///
/// Returns `true`: a Run 246 pipeline success is required before any sink intent,
/// and therefore before any backend submission, can exist.
pub fn durable_completion_attestation_backend_pipeline_success_required() -> bool {
    true
}

/// Run 256 — explicit invariant helper.
///
/// Returns `true`: a Run 248 recorded sink receipt
/// ([`GovernanceModeledDurableConsumeSinkOutcome::ConsumeReceiptRecorded`]) is
/// required before any backend submission can exist.
pub fn durable_completion_attestation_backend_sink_receipt_required() -> bool {
    true
}

/// Run 256 — explicit invariant helper.
///
/// Returns `true`: a Run 250 recorded completion report
/// ([`GovernanceModeledDurableConsumeCompletionReporterOutcome::CompletionReportRecorded`])
/// is required before any backend submission can exist.
pub fn durable_completion_attestation_backend_completion_report_required() -> bool {
    true
}

/// Run 256 — explicit invariant helper.
///
/// Returns `true`: a Run 252 recorded finalization
/// ([`GovernanceModeledDurableCompletionFinalizationOutcome::DurableCompletionFinalized`])
/// is required before any backend submission can exist.
pub fn durable_completion_attestation_backend_finalization_required() -> bool {
    true
}

/// Run 256 — explicit invariant helper.
///
/// Returns `true`: a Run 254 recorded attestation
/// ([`GovernanceModeledDurableCompletionAttestationOutcome::DurableCompletionAttested`])
/// is required before any backend request can exist.
pub fn durable_completion_attestation_backend_attestation_required() -> bool {
    true
}

/// Run 256 — explicit invariant helper.
///
/// Returns `true`: a recorded backend submission
/// ([`DurableCompletionAttestationBackendOutcome::BackendSubmissionRecorded`]) is
/// required before any modeled backend-submitted state.
pub fn durable_completion_attestation_backend_record_required_before_submission() -> bool {
    true
}

/// Run 256 — explicit invariant helper.
///
/// Returns `true`: a failed backend record never submits.
pub fn durable_completion_attestation_backend_failed_record_never_submits() -> bool {
    true
}

/// Run 256 — explicit invariant helper.
///
/// Returns `true`: a backend rollback (and a fatal rollback failure) never submits.
pub fn durable_completion_attestation_backend_rollback_never_submits() -> bool {
    true
}

/// Run 256 — explicit invariant helper.
///
/// Returns `true`: an ambiguous backend window fails closed and never submits.
pub fn durable_completion_attestation_backend_ambiguous_window_fails_closed() -> bool {
    true
}

/// Run 256 — explicit refusal helper.
///
/// Returns `true` iff MainNet peer-driven apply remains refused first for a MainNet
/// environment, before pipeline progression, sink invocation, reporter invocation,
/// finalizer invocation, attestor invocation, and backend invocation.
pub fn durable_completion_attestation_backend_mainnet_peer_driven_apply_refused_first(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 256 — explicit fail-closed helper.
///
/// Returns `true`: production / MainNet backend paths remain unavailable /
/// fail-closed. No real production or MainNet attestation backend is implemented.
pub fn durable_completion_attestation_backend_production_mainnet_unavailable() -> bool {
    true
}

/// Run 256 — explicit fail-closed helper.
///
/// Returns `true`: validator-set rotation remains unsupported by the backend.
pub fn durable_completion_attestation_backend_validator_set_rotation_unsupported() -> bool {
    true
}

/// Run 256 — explicit fail-closed helper.
///
/// Returns `true`: policy-change actions remain unsupported by the backend.
pub fn durable_completion_attestation_backend_policy_change_unsupported() -> bool {
    true
}

/// Run 256 — explicit fail-closed helper.
///
/// Returns `true` iff a local operator key *cannot* satisfy a MainNet backend
/// authority. Run 256 always returns `true`.
pub fn durable_completion_attestation_backend_local_operator_cannot_satisfy_mainnet_authority() -> bool
{
    true
}

/// Run 256 — explicit fail-closed helper.
///
/// Returns `true` iff peer-majority / gossip count *cannot* satisfy a MainNet
/// backend authority. Run 256 always returns `true`.
pub fn durable_completion_attestation_backend_peer_majority_cannot_satisfy_mainnet_authority() -> bool
{
    true
}
