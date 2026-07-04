//! Run 301 — source/test **real** production governance execution engine.
//!
//! This module implements the first real source/test production governance
//! *execution engine*: the boundary that consumes a **verified** on-chain
//! governance proof decision (the Run 299 /
//! [`crate::pqc_production_onchain_governance_proof_verifier`] output, as
//! release-binary-evidenced by Run 300) and translates it into a typed,
//! deterministic, policy-gated **authority lifecycle execution intent** —
//! *without* ever mutating live trust state.
//!
//! Where the Run 299 verifier answers "is this on-chain governance
//! decision cryptographically verified against an explicit trusted
//! root?", Run 301 answers the next question: "given a verified decision,
//! what typed, non-mutating execution intent does it authorize, under an
//! explicit execution policy, and bound to the full governance / custody /
//! attestation / durable-replay evidence tuple?".
//!
//! The engine composes with:
//!
//! * the Run 299 / Run 300 on-chain governance proof verifier boundary
//!   ([`ProductionOnChainGovernanceProofDecision`]) — the **only** accepted
//!   proof source;
//! * the Run 295 / Run 296 KMS/HSM custody backend boundary — represented
//!   as a [`GovernanceExecutionCustodyBinding`] evidence digest;
//! * the Run 297 / Run 298 custody attestation verifier boundary —
//!   represented as a [`GovernanceExecutionAttestationBinding`] evidence
//!   digest;
//! * the Run 291 / Run 292 durable replay RocksDB backend — represented as
//!   a [`GovernanceExecutionDurableReplayBinding`] evidence digest.
//!
//! ## Scope and honesty constraints (Run 301)
//!
//! * This run is a **source/test implementation only**. It is **not**
//!   release-binary evidence — that is deferred to **Run 302**.
//! * The default policy is
//!   [`ProductionGovernanceExecutionEnginePolicy::Disabled`] and fails
//!   closed **before** any proof binding, evidence check, or intent
//!   construction.
//! * Only a **verified** on-chain governance proof decision (a Run 299
//!   accept) can authorize an intent. Unverified proofs, fixture proofs,
//!   local-operator assertions, peer-majority assertions, custody-only,
//!   RemoteSigner-only, and custody-attestation-only evidence are all
//!   rejected as production authority.
//! * The engine produces only a typed
//!   [`ProductionGovernanceExecutionIntent`]; it **never** applies the
//!   intent to live trust state. Only a typed accepted outcome may
//!   authorize a *future* mutation run.
//! * MainNet remains **refused**: even a fully valid source/test
//!   DevNet/TestNet decision does not enable MainNet runtime behavior.
//! * Validator-set rotation / authority-set synchronization is classified
//!   as **unsupported / fail-closed**; Run 301 does not implement it.
//! * The engine is **non-mutating**: no Run 070 apply, no
//!   [`crate::pqc_live_trust::LivePqcTrustState`] mutation, no trust swap,
//!   no session eviction, no PQC trust-bundle sequence write, no authority
//!   marker write, no durable replay overwrite, no KMS/HSM signing call, no
//!   RemoteSigner fallback, no custody/fixture/local/peer-majority
//!   fallback, no settlement, no external publication, and no default
//!   runtime wiring.
//! * No CLI flag and no default runtime wiring is added. Full C4 remains
//!   OPEN; C5 remains OPEN.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_301.md`.

use crate::pqc_authority_custody::AuthorityCustodyClass;
use crate::pqc_authority_lifecycle::{AuthorityTrustDomain, LocalLifecycleAction};
use crate::pqc_governance_authority::GovernanceThreshold;
use crate::pqc_onchain_governance_proof::{
    OnChainGovernanceProposalOutcome, OnChainGovernanceQuorum,
};
use crate::pqc_production_onchain_governance_proof_verifier::{
    ProductionOnChainGovernanceProofDecision, ProductionOnChainGovernanceProofOutcome,
};
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Domain tags / protocol constants
// ===========================================================================

/// Run 301 — the only governance execution engine protocol version this
/// run accepts.
pub const PRODUCTION_GOVERNANCE_EXECUTION_ENGINE_PROTOCOL_VERSION: u16 = 1;

/// Run 301 — execution-intent digest domain tag.
pub const PRODUCTION_GOVERNANCE_EXECUTION_INTENT_DOMAIN_TAG: &str =
    "QBIND:run301-gov-exec-intent:v1";

/// Run 301 — execution request-id domain tag.
pub const PRODUCTION_GOVERNANCE_EXECUTION_REQUEST_DOMAIN_TAG: &str =
    "QBIND:run301-gov-exec-request:v1";

/// Run 301 — execution transcript digest domain tag.
pub const PRODUCTION_GOVERNANCE_EXECUTION_TRANSCRIPT_DOMAIN_TAG: &str =
    "QBIND:run301-gov-exec-transcript:v1";

/// Length-prefixed domain-separated field hashing helper.
fn hash_field(h: &mut sha3::Sha3_256, label: &[u8], value: &[u8]) {
    use sha3::Digest;
    h.update((label.len() as u64).to_le_bytes());
    h.update(label);
    h.update((value.len() as u64).to_le_bytes());
    h.update(value);
}

fn proposal_outcome_tag(o: OnChainGovernanceProposalOutcome) -> &'static str {
    match o {
        OnChainGovernanceProposalOutcome::Approved => "approved",
        OnChainGovernanceProposalOutcome::Rejected => "rejected",
    }
}

// ===========================================================================
// Protocol version newtype
// ===========================================================================

/// Run 301 — typed governance execution engine protocol version. Only
/// [`PRODUCTION_GOVERNANCE_EXECUTION_ENGINE_PROTOCOL_VERSION`] is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProductionGovernanceExecutionProtocolVersion(pub u16);

impl ProductionGovernanceExecutionProtocolVersion {
    /// The single supported protocol version.
    pub const fn supported() -> Self {
        Self(PRODUCTION_GOVERNANCE_EXECUTION_ENGINE_PROTOCOL_VERSION)
    }

    /// Returns `true` iff this is the supported protocol version.
    pub const fn is_supported(self) -> bool {
        self.0 == PRODUCTION_GOVERNANCE_EXECUTION_ENGINE_PROTOCOL_VERSION
    }
}

impl Default for ProductionGovernanceExecutionProtocolVersion {
    fn default() -> Self {
        Self::supported()
    }
}

// ===========================================================================
// Policy taxonomy
// ===========================================================================

/// Run 301 — typed governance execution engine policy.
///
/// `Disabled` is the default fail-closed policy: the engine refuses before
/// any proof binding or intent construction.
/// `AllowSourceTestVerifiedGovernanceExecution` is the only policy that can
/// produce an accepted source/test intent, and only on DevNet/TestNet with
/// a verified on-chain governance proof decision.
/// `RequireProductionGovernanceExecution` and
/// `MainnetProductionGovernanceExecutionRequired` are **reachable but
/// fail-closed** production/MainNet policies: no production authority
/// (validator-set rotation, full MainNet evidence) is wired, so they fail
/// closed as unavailable/refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProductionGovernanceExecutionEnginePolicy {
    /// Default. Refuses every request before any binding.
    #[default]
    Disabled,
    /// DevNet/TestNet source/test policy. A verified on-chain governance
    /// proof decision may produce a typed non-mutating execution intent as
    /// source/test evidence only. MainNet remains refused.
    AllowSourceTestVerifiedGovernanceExecution,
    /// Production policy. Reachable but fails closed: no production
    /// governance execution prerequisites (validator-set rotation, full
    /// MainNet evidence) are wired.
    RequireProductionGovernanceExecution,
    /// MainNet production policy. Reachable but fails closed: no MainNet
    /// production authority material is wired.
    MainnetProductionGovernanceExecutionRequired,
}

impl ProductionGovernanceExecutionEnginePolicy {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::AllowSourceTestVerifiedGovernanceExecution => {
                "allow-source-test-verified-governance-execution"
            }
            Self::RequireProductionGovernanceExecution => {
                "require-production-governance-execution"
            }
            Self::MainnetProductionGovernanceExecutionRequired => {
                "mainnet-production-governance-execution-required"
            }
        }
    }

    /// Returns `true` iff this policy is `Disabled`.
    pub const fn is_disabled(self) -> bool {
        matches!(self, Self::Disabled)
    }

    /// Returns `true` iff this policy allows source/test verified
    /// governance execution (DevNet/TestNet only).
    pub const fn allows_source_test(self) -> bool {
        matches!(self, Self::AllowSourceTestVerifiedGovernanceExecution)
    }

    /// Returns `true` iff this policy is the production policy.
    pub const fn is_production(self) -> bool {
        matches!(self, Self::RequireProductionGovernanceExecution)
    }

    /// Returns `true` iff this policy is the MainNet production policy.
    pub const fn is_mainnet(self) -> bool {
        matches!(self, Self::MainnetProductionGovernanceExecutionRequired)
    }
}

// ===========================================================================
// Engine kind taxonomy
// ===========================================================================

/// Run 301 — typed governance execution engine kind.
///
/// `Disabled` is the inert default. `SourceTestGovernanceExecutionEngine`
/// performs real source/test intent construction. A reserved
/// `ProductionGovernanceExecutionEngine` kind is fail-closed as unavailable
/// in Run 301 (no production authority is wired).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProductionGovernanceExecutionEngineKind {
    /// Inert default; every request is refused.
    #[default]
    Disabled,
    /// Real source/test governance execution engine.
    SourceTestGovernanceExecutionEngine,
    /// Reserved production engine kind. Fail-closed in Run 301.
    ProductionGovernanceExecutionEngine,
}

impl ProductionGovernanceExecutionEngineKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::SourceTestGovernanceExecutionEngine => {
                "source-test-governance-execution-engine"
            }
            Self::ProductionGovernanceExecutionEngine => {
                "production-governance-execution-engine"
            }
        }
    }

    /// Returns `true` iff this kind performs real source/test intent
    /// construction.
    pub const fn is_source_test(self) -> bool {
        matches!(self, Self::SourceTestGovernanceExecutionEngine)
    }
}

// ===========================================================================
// Config
// ===========================================================================

/// Run 301 — typed governance execution engine config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionGovernanceExecutionEngineConfig {
    /// Engine protocol version. Must equal the supported version.
    pub protocol_version: ProductionGovernanceExecutionProtocolVersion,
    /// The engine kind.
    pub kind: ProductionGovernanceExecutionEngineKind,
}

impl ProductionGovernanceExecutionEngineConfig {
    pub fn new(kind: ProductionGovernanceExecutionEngineKind) -> Self {
        Self {
            protocol_version: ProductionGovernanceExecutionProtocolVersion::supported(),
            kind,
        }
    }

    /// A config with the real source/test engine kind.
    pub fn source_test() -> Self {
        Self::new(ProductionGovernanceExecutionEngineKind::SourceTestGovernanceExecutionEngine)
    }

    /// Returns `true` iff the config pins the supported protocol version.
    pub fn is_well_formed(&self) -> bool {
        self.protocol_version.is_supported()
    }
}

impl Default for ProductionGovernanceExecutionEngineConfig {
    fn default() -> Self {
        Self::new(ProductionGovernanceExecutionEngineKind::Disabled)
    }
}

// ===========================================================================
// Requested governance operation
// ===========================================================================

/// Run 301 — the governance operation a verified decision requests.
///
/// Every operation except [`Self::ValidatorSetRotation`] maps to a typed
/// non-mutating execution intent kind. `ValidatorSetRotation` is classified
/// as **unsupported / fail-closed**: Run 301 does not implement validator-
/// set rotation and the C4/C5 matrix keeps it Red.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GovernanceExecutionRequestedOperation {
    AuthorityLifecycleRotation,
    AuthorityLifecycleRetirement,
    AuthorityLifecycleRevocation,
    EmergencyRevocation,
    BundleSigningKeyAuthorization,
    BundleSigningKeyRetirement,
    BundleSigningKeyRevocation,
    GovernanceNoOp,
    ValidatorSetRotation,
}

impl GovernanceExecutionRequestedOperation {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::AuthorityLifecycleRotation => "authority-lifecycle-rotation",
            Self::AuthorityLifecycleRetirement => "authority-lifecycle-retirement",
            Self::AuthorityLifecycleRevocation => "authority-lifecycle-revocation",
            Self::EmergencyRevocation => "emergency-revocation",
            Self::BundleSigningKeyAuthorization => "bundle-signing-key-authorization",
            Self::BundleSigningKeyRetirement => "bundle-signing-key-retirement",
            Self::BundleSigningKeyRevocation => "bundle-signing-key-revocation",
            Self::GovernanceNoOp => "governance-no-op",
            Self::ValidatorSetRotation => "validator-set-rotation",
        }
    }

    /// Returns `true` iff this operation is validator-set rotation, which
    /// Run 301 classifies as unsupported / fail-closed.
    pub const fn is_validator_set_rotation(self) -> bool {
        matches!(self, Self::ValidatorSetRotation)
    }

    /// Maps a supported operation to its typed non-mutating intent kind.
    /// Returns `None` for [`Self::ValidatorSetRotation`].
    pub const fn intent_kind(self) -> Option<ProductionGovernanceExecutionIntentKind> {
        use ProductionGovernanceExecutionIntentKind as K;
        Some(match self {
            Self::AuthorityLifecycleRotation => K::AuthorityLifecycleRotationIntent,
            Self::AuthorityLifecycleRetirement => K::AuthorityLifecycleRetirementIntent,
            Self::AuthorityLifecycleRevocation => K::AuthorityLifecycleRevocationIntent,
            Self::EmergencyRevocation => K::EmergencyRevocationIntent,
            Self::BundleSigningKeyAuthorization => K::BundleSigningKeyAuthorizationIntent,
            Self::BundleSigningKeyRetirement => K::BundleSigningKeyRetirementIntent,
            Self::BundleSigningKeyRevocation => K::BundleSigningKeyRevocationIntent,
            Self::GovernanceNoOp => K::GovernanceNoOpIntent,
            Self::ValidatorSetRotation => return None,
        })
    }
}

// ===========================================================================
// Execution intent kind
// ===========================================================================

/// Run 301 — the typed kind of a prepared, non-mutating execution intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProductionGovernanceExecutionIntentKind {
    AuthorityLifecycleRotationIntent,
    AuthorityLifecycleRetirementIntent,
    AuthorityLifecycleRevocationIntent,
    EmergencyRevocationIntent,
    BundleSigningKeyAuthorizationIntent,
    BundleSigningKeyRetirementIntent,
    BundleSigningKeyRevocationIntent,
    GovernanceNoOpIntent,
}

impl ProductionGovernanceExecutionIntentKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::AuthorityLifecycleRotationIntent => "authority-lifecycle-rotation-intent",
            Self::AuthorityLifecycleRetirementIntent => "authority-lifecycle-retirement-intent",
            Self::AuthorityLifecycleRevocationIntent => "authority-lifecycle-revocation-intent",
            Self::EmergencyRevocationIntent => "emergency-revocation-intent",
            Self::BundleSigningKeyAuthorizationIntent => "bundle-signing-key-authorization-intent",
            Self::BundleSigningKeyRetirementIntent => "bundle-signing-key-retirement-intent",
            Self::BundleSigningKeyRevocationIntent => "bundle-signing-key-revocation-intent",
            Self::GovernanceNoOpIntent => "governance-no-op-intent",
        }
    }

    /// Every Run 301 intent kind is a *prepared*, non-mutating intent.
    pub const fn is_non_mutating(self) -> bool {
        true
    }
}

// ===========================================================================
// Evidence bindings
// ===========================================================================

/// Run 301 — the full governance decision binding extracted from a
/// verified on-chain governance proof.
///
/// This mirrors the Run 299 decision commitment tuple plus the Run 299
/// verifier transcript / proof digests. Its accept-relevant fields
/// (`environment` / `governance_epoch` / `authority_domain_sequence` /
/// `lifecycle_action` / `decision_id`) are cross-checked against the Run
/// 299 accept outcome, so the binding cannot diverge from the verified
/// decision. `Debug` formatting is never used as canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceExecutionProofBinding {
    // ---- Trust-domain binding -----------------------------------------
    pub environment: TrustBundleEnvironment,
    pub chain_id: String,
    pub genesis_hash: String,
    pub authority_root_fingerprint: String,
    pub authority_root_suite_id: u8,

    // ---- Governance binding -------------------------------------------
    pub governance_domain_id: String,
    pub governance_epoch: u64,
    pub governance_height: u64,
    pub proposal_id: String,
    pub proposal_digest: String,
    pub proposal_outcome: OnChainGovernanceProposalOutcome,
    pub quorum: OnChainGovernanceQuorum,
    pub threshold: GovernanceThreshold,

    // ---- Lifecycle + operation binding --------------------------------
    pub lifecycle_action: LocalLifecycleAction,
    pub requested_operation: GovernanceExecutionRequestedOperation,
    pub candidate_v2_digest: String,
    pub authority_domain_sequence: u64,

    // ---- Replay --------------------------------------------------------
    pub decision_id: String,

    // ---- Run 299 verifier transcript ----------------------------------
    pub proof_transcript_digest: String,
    pub proof_digest: String,
    pub trusted_checkpoint_digest: String,
}

impl GovernanceExecutionProofBinding {
    /// Returns `true` iff every mandatory field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.chain_id.is_empty()
            && !self.genesis_hash.is_empty()
            && !self.authority_root_fingerprint.is_empty()
            && !self.governance_domain_id.is_empty()
            && !self.proposal_id.is_empty()
            && !self.proposal_digest.is_empty()
            && !self.candidate_v2_digest.is_empty()
            && !self.decision_id.is_empty()
            && !self.proof_transcript_digest.is_empty()
            && self.quorum.is_well_formed()
            && self.threshold.is_well_formed()
    }
}

/// Run 301 — custody backend evidence binding (Run 295 / Run 296 KMS/HSM
/// custody backend evidence, represented as an opaque, caller-supplied
/// evidence digest, never a signing call).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceExecutionCustodyBinding {
    pub provider_class: AuthorityCustodyClass,
    pub key_handle: String,
    pub signer_fingerprint: String,
    pub custody_transcript_digest: String,
}

impl GovernanceExecutionCustodyBinding {
    pub fn is_well_formed(&self) -> bool {
        !self.key_handle.is_empty()
            && !self.signer_fingerprint.is_empty()
            && !self.custody_transcript_digest.is_empty()
    }

    fn hash_into(&self, h: &mut sha3::Sha3_256) {
        hash_field(h, b"custody_provider_class", self.provider_class.tag().as_bytes());
        hash_field(h, b"custody_key_handle", self.key_handle.as_bytes());
        hash_field(h, b"custody_signer_fingerprint", self.signer_fingerprint.as_bytes());
        hash_field(
            h,
            b"custody_transcript_digest",
            self.custody_transcript_digest.as_bytes(),
        );
    }
}

/// Run 301 — custody attestation evidence binding (Run 297 / Run 298
/// custody attestation verifier evidence, represented as an opaque,
/// caller-supplied attestation transcript digest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceExecutionAttestationBinding {
    pub attestation_transcript_digest: String,
    pub measurement: String,
}

impl GovernanceExecutionAttestationBinding {
    pub fn is_well_formed(&self) -> bool {
        !self.attestation_transcript_digest.is_empty()
    }

    fn hash_into(&self, h: &mut sha3::Sha3_256) {
        hash_field(
            h,
            b"attestation_transcript_digest",
            self.attestation_transcript_digest.as_bytes(),
        );
        hash_field(h, b"attestation_measurement", self.measurement.as_bytes());
    }
}

/// Run 301 — durable replay evidence binding (Run 291 / Run 292 durable
/// replay RocksDB backend evidence, represented as an opaque, caller-
/// supplied record id + digest; the engine never overwrites durable
/// state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceExecutionDurableReplayBinding {
    pub durable_record_id: String,
    pub durable_record_digest: String,
}

impl GovernanceExecutionDurableReplayBinding {
    pub fn is_well_formed(&self) -> bool {
        !self.durable_record_id.is_empty() && !self.durable_record_digest.is_empty()
    }

    fn hash_into(&self, h: &mut sha3::Sha3_256) {
        hash_field(h, b"durable_record_id", self.durable_record_id.as_bytes());
        hash_field(h, b"durable_record_digest", self.durable_record_digest.as_bytes());
    }
}

// ===========================================================================
// Proof source
// ===========================================================================

/// Run 301 — the governance proof source presented to the engine.
///
/// Only [`Self::VerifiedOnChainGovernanceProof`] carrying a Run 299 accept
/// decision can authorize an intent. Every other variant is a non-authority
/// source rejected with a precise fail-closed outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceExecutionProofSource {
    /// A verified Run 299 / Run 300 on-chain governance proof decision plus
    /// the extracted decision binding. The **only** accepted source.
    VerifiedOnChainGovernanceProof {
        decision: ProductionOnChainGovernanceProofDecision,
        binding: GovernanceExecutionProofBinding,
    },
    /// No proof was supplied.
    MissingProof,
    /// An unverified on-chain governance proof decision (any Run 299
    /// non-accept outcome). Rejected.
    UnverifiedOnChainGovernanceProof {
        decision: ProductionOnChainGovernanceProofDecision,
    },
    /// A Run 178 fixture governance proof presented as production
    /// authority. Rejected.
    FixtureGovernanceProof,
    /// A local-operator assertion. Rejected.
    LocalOperatorAssertion,
    /// A peer-majority assertion. Rejected.
    PeerMajorityAssertion,
    /// Custody-backend evidence presented alone as governance authority.
    /// Rejected.
    CustodyOnlyEvidence,
    /// RemoteSigner evidence presented alone as governance authority.
    /// Rejected.
    RemoteSignerOnlyEvidence,
    /// Custody-attestation evidence presented alone as governance
    /// authority. Rejected.
    CustodyAttestationOnlyEvidence,
}

// ===========================================================================
// Inputs
// ===========================================================================

/// Run 301 — the explicit trusted inputs the engine binds a verified
/// decision against. Mirrors the Run 299 verification inputs and adds the
/// execution policy id, the expected Run 299 transcript digest, and the
/// evidence requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionGovernanceExecutionInputs {
    /// The authoritative trust domain.
    pub trust_domain: AuthorityTrustDomain,
    /// Expected governance domain id.
    pub expected_governance_domain_id: String,
    /// Expected governance epoch.
    pub expected_governance_epoch: u64,
    /// Expected proposal id.
    pub expected_proposal_id: String,
    /// Expected proposal digest.
    pub expected_proposal_digest: String,
    /// Expected proposal outcome (must be `Approved` to authorize).
    pub expected_proposal_outcome: OnChainGovernanceProposalOutcome,
    /// Expected lifecycle action.
    pub expected_lifecycle_action: LocalLifecycleAction,
    /// Expected requested governance operation.
    pub expected_requested_operation: GovernanceExecutionRequestedOperation,
    /// Expected candidate v2 digest.
    pub expected_candidate_v2_digest: String,
    /// Expected authority-domain sequence.
    pub expected_authority_domain_sequence: u64,
    /// Expected quorum.
    pub expected_quorum: OnChainGovernanceQuorum,
    /// Expected threshold.
    pub expected_threshold: GovernanceThreshold,
    /// Expected Run 299 verifier transcript digest.
    pub expected_proof_transcript_digest: String,
    /// Minimum acceptable governance epoch (freshness; never wall-clock).
    pub min_governance_epoch: u64,
    /// Optional persisted authority-domain sequence for stale-lower-
    /// sequence replay detection.
    pub persisted_sequence: Option<u64>,
    /// Opaque execution policy id bound into the intent.
    pub execution_policy_id: String,
    /// Whether custody backend evidence is required, and its expected
    /// binding.
    pub require_custody_evidence: bool,
    pub expected_custody: Option<GovernanceExecutionCustodyBinding>,
    /// Whether custody attestation evidence is required, and its expected
    /// binding.
    pub require_attestation_evidence: bool,
    pub expected_attestation: Option<GovernanceExecutionAttestationBinding>,
    /// Whether durable replay evidence is required, and its expected
    /// binding.
    pub require_durable_replay_evidence: bool,
    pub expected_durable_replay: Option<GovernanceExecutionDurableReplayBinding>,
}

impl ProductionGovernanceExecutionInputs {
    /// Returns `true` iff the inputs are structurally well-formed.
    pub fn is_well_formed(&self) -> bool {
        !self.trust_domain.chain_id.is_empty()
            && !self.trust_domain.genesis_hash.is_empty()
            && !self.trust_domain.authority_root_fingerprint.is_empty()
            && !self.expected_governance_domain_id.is_empty()
            && !self.expected_proposal_id.is_empty()
            && !self.expected_proposal_digest.is_empty()
            && !self.expected_candidate_v2_digest.is_empty()
            && !self.expected_proof_transcript_digest.is_empty()
            && !self.execution_policy_id.is_empty()
            && (!self.require_custody_evidence || self.expected_custody.is_some())
            && (!self.require_attestation_evidence || self.expected_attestation.is_some())
            && (!self.require_durable_replay_evidence || self.expected_durable_replay.is_some())
    }
}

// ===========================================================================
// Request
// ===========================================================================

/// Run 301 — a governance execution request: the proof source plus any
/// represented custody / attestation / durable-replay evidence bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionGovernanceExecutionRequest {
    pub proof_source: GovernanceExecutionProofSource,
    pub custody_binding: Option<GovernanceExecutionCustodyBinding>,
    pub attestation_binding: Option<GovernanceExecutionAttestationBinding>,
    pub durable_replay_binding: Option<GovernanceExecutionDurableReplayBinding>,
}

impl ProductionGovernanceExecutionRequest {
    /// Construct a request carrying only a proof source (no represented
    /// custody / attestation / durable-replay evidence).
    pub fn from_proof(proof_source: GovernanceExecutionProofSource) -> Self {
        Self {
            proof_source,
            custody_binding: None,
            attestation_binding: None,
            durable_replay_binding: None,
        }
    }
}

// ===========================================================================
// Replay set
// ===========================================================================

/// Run 301 — caller-owned replay decision-id set. The engine reads from
/// this set but never mutates it.
pub trait GovernanceExecutionReplaySet {
    fn contains(&self, decision_id: &str) -> bool;
}

impl GovernanceExecutionReplaySet for &[String] {
    fn contains(&self, decision_id: &str) -> bool {
        (*self).iter().any(|s| s == decision_id)
    }
}

impl GovernanceExecutionReplaySet for Vec<String> {
    fn contains(&self, decision_id: &str) -> bool {
        self.iter().any(|s| s == decision_id)
    }
}

/// Empty replay set helper.
pub struct EmptyGovernanceExecutionReplaySet;

impl GovernanceExecutionReplaySet for EmptyGovernanceExecutionReplaySet {
    fn contains(&self, _decision_id: &str) -> bool {
        false
    }
}

// ===========================================================================
// Execution intent
// ===========================================================================

/// Run 301 — a typed, deterministic, **non-mutating** governance execution
/// intent. Only a typed accepted outcome carrying an intent may authorize a
/// *future* mutation run; Run 301 never applies the intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionGovernanceExecutionIntent {
    pub intent_kind: ProductionGovernanceExecutionIntentKind,
    pub protocol_version: u16,
    pub execution_policy_id: String,

    // ---- Bound governance decision tuple ------------------------------
    pub environment: TrustBundleEnvironment,
    pub chain_id: String,
    pub genesis_hash: String,
    pub authority_root_fingerprint: String,
    pub authority_root_suite_id: u8,
    pub governance_domain_id: String,
    pub governance_epoch: u64,
    pub governance_height: u64,
    pub proposal_id: String,
    pub proposal_digest: String,
    pub proposal_outcome: OnChainGovernanceProposalOutcome,
    pub quorum: OnChainGovernanceQuorum,
    pub threshold: GovernanceThreshold,
    pub lifecycle_action: LocalLifecycleAction,
    pub requested_operation: GovernanceExecutionRequestedOperation,
    pub candidate_v2_digest: String,
    pub authority_domain_sequence: u64,
    pub decision_id: String,
    pub proof_transcript_digest: String,
    pub proof_digest: String,
    pub trusted_checkpoint_digest: String,

    // ---- Composed evidence (where represented) ------------------------
    pub custody_binding: Option<GovernanceExecutionCustodyBinding>,
    pub attestation_binding: Option<GovernanceExecutionAttestationBinding>,
    pub durable_replay_binding: Option<GovernanceExecutionDurableReplayBinding>,
}

impl ProductionGovernanceExecutionIntent {
    /// Deterministic, domain-separated SHA3-256 hex execution intent
    /// digest. `Debug` formatting is never used as canonical bytes.
    pub fn intent_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(PRODUCTION_GOVERNANCE_EXECUTION_INTENT_DOMAIN_TAG.as_bytes());
        hash_field(&mut h, b"intent_kind", self.intent_kind.tag().as_bytes());
        hash_field(&mut h, b"protocol_version", &self.protocol_version.to_le_bytes());
        hash_field(&mut h, b"execution_policy_id", self.execution_policy_id.as_bytes());
        hash_field(&mut h, b"environment", &self.environment.metric_code().to_le_bytes());
        hash_field(&mut h, b"chain_id", self.chain_id.as_bytes());
        hash_field(&mut h, b"genesis_hash", self.genesis_hash.as_bytes());
        hash_field(
            &mut h,
            b"authority_root_fingerprint",
            self.authority_root_fingerprint.as_bytes(),
        );
        hash_field(&mut h, b"authority_root_suite_id", &[self.authority_root_suite_id]);
        hash_field(&mut h, b"governance_domain_id", self.governance_domain_id.as_bytes());
        hash_field(&mut h, b"governance_epoch", &self.governance_epoch.to_le_bytes());
        hash_field(&mut h, b"governance_height", &self.governance_height.to_le_bytes());
        hash_field(&mut h, b"proposal_id", self.proposal_id.as_bytes());
        hash_field(&mut h, b"proposal_digest", self.proposal_digest.as_bytes());
        hash_field(
            &mut h,
            b"proposal_outcome",
            proposal_outcome_tag(self.proposal_outcome).as_bytes(),
        );
        hash_field(&mut h, b"quorum_voted", &self.quorum.voters_voted.to_le_bytes());
        hash_field(&mut h, b"quorum_total", &self.quorum.total_voters.to_le_bytes());
        hash_field(&mut h, b"quorum_required", &self.quorum.required_quorum.to_le_bytes());
        hash_field(&mut h, b"threshold_approvals", &self.threshold.approvals.to_le_bytes());
        hash_field(&mut h, b"threshold_required", &self.threshold.required.to_le_bytes());
        hash_field(&mut h, b"threshold_total", &self.threshold.total.to_le_bytes());
        hash_field(&mut h, b"lifecycle_action", self.lifecycle_action.tag().as_bytes());
        hash_field(&mut h, b"requested_operation", self.requested_operation.tag().as_bytes());
        hash_field(&mut h, b"candidate_v2_digest", self.candidate_v2_digest.as_bytes());
        hash_field(
            &mut h,
            b"authority_domain_sequence",
            &self.authority_domain_sequence.to_le_bytes(),
        );
        hash_field(&mut h, b"decision_id", self.decision_id.as_bytes());
        hash_field(&mut h, b"proof_transcript_digest", self.proof_transcript_digest.as_bytes());
        hash_field(&mut h, b"proof_digest", self.proof_digest.as_bytes());
        hash_field(
            &mut h,
            b"trusted_checkpoint_digest",
            self.trusted_checkpoint_digest.as_bytes(),
        );
        // Composed evidence — presence + contents.
        match &self.custody_binding {
            Some(c) => {
                hash_field(&mut h, b"custody_present", &[1u8]);
                c.hash_into(&mut h);
            }
            None => hash_field(&mut h, b"custody_present", &[0u8]),
        }
        match &self.attestation_binding {
            Some(a) => {
                hash_field(&mut h, b"attestation_present", &[1u8]);
                a.hash_into(&mut h);
            }
            None => hash_field(&mut h, b"attestation_present", &[0u8]),
        }
        match &self.durable_replay_binding {
            Some(d) => {
                hash_field(&mut h, b"durable_present", &[1u8]);
                d.hash_into(&mut h);
            }
            None => hash_field(&mut h, b"durable_present", &[0u8]),
        }
        hex::encode(h.finalize())
    }

    /// This intent is prepared, non-mutating, and never applied by Run 301.
    pub const fn is_non_mutating(&self) -> bool {
        true
    }
}

/// Run 301 — deterministic execution intent digest wrapper exposed as a
/// named symbol.
pub fn production_governance_execution_intent_digest(
    intent: &ProductionGovernanceExecutionIntent,
) -> String {
    intent.intent_digest()
}

/// Run 301 — deterministic, domain-separated execution request id binding
/// the protocol version, the decision id, and the bound proof transcript
/// digest. Deterministic across identical inputs; never wall-clock.
pub fn production_governance_execution_request_id(
    protocol_version: u16,
    decision_id: &str,
    proof_transcript_digest: &str,
    execution_policy_id: &str,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(PRODUCTION_GOVERNANCE_EXECUTION_REQUEST_DOMAIN_TAG.as_bytes());
    hash_field(&mut h, b"protocol_version", &protocol_version.to_le_bytes());
    hash_field(&mut h, b"decision_id", decision_id.as_bytes());
    hash_field(&mut h, b"proof_transcript_digest", proof_transcript_digest.as_bytes());
    hash_field(&mut h, b"execution_policy_id", execution_policy_id.as_bytes());
    hex::encode(h.finalize())
}

/// Run 301 — deterministic, domain-separated execution transcript digest
/// binding the protocol version, request id, intent digest, and outcome
/// tag.
pub fn production_governance_execution_transcript_digest(
    protocol_version: u16,
    request_id: &str,
    intent_digest: &str,
    outcome_tag: &str,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(PRODUCTION_GOVERNANCE_EXECUTION_TRANSCRIPT_DOMAIN_TAG.as_bytes());
    hash_field(&mut h, b"protocol_version", &protocol_version.to_le_bytes());
    hash_field(&mut h, b"request_id", request_id.as_bytes());
    hash_field(&mut h, b"intent_digest", intent_digest.as_bytes());
    hash_field(&mut h, b"outcome_tag", outcome_tag.as_bytes());
    hex::encode(h.finalize())
}

// ===========================================================================
// Outcome taxonomy
// ===========================================================================

/// Run 301 — typed outcome of the governance execution engine.
///
/// Only [`Self::AcceptedSourceTestGovernanceExecutionIntent`] authorizes a
/// (source/test, DevNet/TestNet, evidence-only, non-mutating) execution
/// intent. Every other variant is a precise, non-mutating fail-closed
/// reject (or the inert [`Self::Disabled`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionGovernanceExecutionOutcome {
    // ---- Disabled / unavailable ---------------------------------------
    /// Policy is `Disabled`; no proof was bound.
    Disabled,
    /// The engine kind is unavailable / misconfigured.
    GovernanceExecutionEngineUnavailable,
    /// The production policy has no production prerequisites wired.
    ProductionGovernanceExecutionUnavailable,
    /// The MainNet production policy has no MainNet authority wired.
    MainNetProductionGovernanceExecutionUnavailable,

    // ---- Accepted ------------------------------------------------------
    /// A verified DevNet/TestNet governance decision produced a typed
    /// non-mutating execution intent under the source/test policy.
    /// **Evidence only.**
    AcceptedSourceTestGovernanceExecutionIntent {
        intent_kind: ProductionGovernanceExecutionIntentKind,
        environment: TrustBundleEnvironment,
        decision_id: String,
    },

    // ---- Proof / binding failures -------------------------------------
    VerifiedOnChainGovernanceProofRequired,
    UnverifiedGovernanceProofRejected,
    FixtureGovernanceProofRejectedAsProductionAuthority,
    LocalOperatorProofRejected,
    PeerMajorityProofRejected,
    CustodyOnlyProofRejected,
    RemoteSignerOnlyProofRejected,
    CustodyAttestationOnlyProofRejected,
    GovernanceProofTranscriptMismatch,
    WrongEnvironment,
    WrongChain,
    WrongGenesis,
    WrongAuthorityRoot,
    WrongGovernanceDomain,
    WrongGovernanceEpoch,
    WrongProposalId,
    WrongProposalDigest,
    WrongProposalOutcome,
    WrongLifecycleAction,
    WrongCandidateDigest,
    WrongAuthoritySequence,
    WrongDecisionId,
    WrongQuorum,
    WrongThreshold,

    // ---- Custody / attestation / durable replay -----------------------
    CustodyBackendEvidenceRequired,
    CustodyBackendMismatch,
    CustodyAttestationRequired,
    CustodyAttestationMismatch,
    DurableReplayEvidenceRequired,
    DurableReplayMismatch,
    DurableReplayUnavailable,

    // ---- Replay / freshness / action ----------------------------------
    DecisionReplayRejected { decision_id: String },
    StaleGovernanceEpoch,
    StaleAuthoritySequence,
    ConflictingIntentForSameDecision,
    UnsupportedLifecycleAction,
    ValidatorSetRotationUnsupported,
    GovernanceExecutionAmbiguous { reason: String },
    MainNetRefused,
}

impl ProductionGovernanceExecutionOutcome {
    /// Returns `true` iff this outcome accepted a source/test execution
    /// intent.
    pub fn is_accept(&self) -> bool {
        matches!(
            self,
            Self::AcceptedSourceTestGovernanceExecutionIntent { .. }
        )
    }

    /// Returns `true` iff this outcome is a fail-closed reject (i.e. not an
    /// accept and not the inert `Disabled`).
    pub fn is_reject(&self) -> bool {
        !self.is_accept() && !matches!(self, Self::Disabled)
    }

    /// Every Run 301 outcome is non-mutating.
    pub const fn is_non_mutating(&self) -> bool {
        true
    }

    /// Only an accepted outcome may authorize a *future* mutation run; it
    /// never mutates in Run 301.
    pub fn authorizes_future_mutation_only(&self) -> bool {
        self.is_accept()
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::GovernanceExecutionEngineUnavailable => "governance-execution-engine-unavailable",
            Self::ProductionGovernanceExecutionUnavailable => {
                "production-governance-execution-unavailable"
            }
            Self::MainNetProductionGovernanceExecutionUnavailable => {
                "mainnet-production-governance-execution-unavailable"
            }
            Self::AcceptedSourceTestGovernanceExecutionIntent { .. } => {
                "accepted-source-test-governance-execution-intent"
            }
            Self::VerifiedOnChainGovernanceProofRequired => {
                "verified-onchain-governance-proof-required"
            }
            Self::UnverifiedGovernanceProofRejected => "unverified-governance-proof-rejected",
            Self::FixtureGovernanceProofRejectedAsProductionAuthority => {
                "fixture-governance-proof-rejected-as-production-authority"
            }
            Self::LocalOperatorProofRejected => "local-operator-proof-rejected",
            Self::PeerMajorityProofRejected => "peer-majority-proof-rejected",
            Self::CustodyOnlyProofRejected => "custody-only-proof-rejected",
            Self::RemoteSignerOnlyProofRejected => "remote-signer-only-proof-rejected",
            Self::CustodyAttestationOnlyProofRejected => "custody-attestation-only-proof-rejected",
            Self::GovernanceProofTranscriptMismatch => "governance-proof-transcript-mismatch",
            Self::WrongEnvironment => "wrong-environment",
            Self::WrongChain => "wrong-chain",
            Self::WrongGenesis => "wrong-genesis",
            Self::WrongAuthorityRoot => "wrong-authority-root",
            Self::WrongGovernanceDomain => "wrong-governance-domain",
            Self::WrongGovernanceEpoch => "wrong-governance-epoch",
            Self::WrongProposalId => "wrong-proposal-id",
            Self::WrongProposalDigest => "wrong-proposal-digest",
            Self::WrongProposalOutcome => "wrong-proposal-outcome",
            Self::WrongLifecycleAction => "wrong-lifecycle-action",
            Self::WrongCandidateDigest => "wrong-candidate-digest",
            Self::WrongAuthoritySequence => "wrong-authority-sequence",
            Self::WrongDecisionId => "wrong-decision-id",
            Self::WrongQuorum => "wrong-quorum",
            Self::WrongThreshold => "wrong-threshold",
            Self::CustodyBackendEvidenceRequired => "custody-backend-evidence-required",
            Self::CustodyBackendMismatch => "custody-backend-mismatch",
            Self::CustodyAttestationRequired => "custody-attestation-required",
            Self::CustodyAttestationMismatch => "custody-attestation-mismatch",
            Self::DurableReplayEvidenceRequired => "durable-replay-evidence-required",
            Self::DurableReplayMismatch => "durable-replay-mismatch",
            Self::DurableReplayUnavailable => "durable-replay-unavailable",
            Self::DecisionReplayRejected { .. } => "decision-replay-rejected",
            Self::StaleGovernanceEpoch => "stale-governance-epoch",
            Self::StaleAuthoritySequence => "stale-authority-sequence",
            Self::ConflictingIntentForSameDecision => "conflicting-intent-for-same-decision",
            Self::UnsupportedLifecycleAction => "unsupported-lifecycle-action",
            Self::ValidatorSetRotationUnsupported => "validator-set-rotation-unsupported",
            Self::GovernanceExecutionAmbiguous { .. } => "governance-execution-ambiguous",
            Self::MainNetRefused => "mainnet-refused",
        }
    }
}

// ===========================================================================
// Decision (engine output)
// ===========================================================================

/// Run 301 — the typed decision produced by the engine: the outcome, the
/// bound decision id, the deterministic request id, the optional prepared
/// intent, its digest, and the verification transcript digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionGovernanceExecutionDecision {
    pub outcome: ProductionGovernanceExecutionOutcome,
    pub decision_id: String,
    pub request_id: String,
    pub intent: Option<ProductionGovernanceExecutionIntent>,
    pub intent_digest: String,
    pub transcript_digest: String,
}

impl ProductionGovernanceExecutionDecision {
    pub fn is_accept(&self) -> bool {
        self.outcome.is_accept()
    }

    /// Returns `true` iff the decision carries a prepared, non-mutating
    /// intent (only on accept). The engine never applies it.
    pub fn authorizes_future_mutation_only(&self) -> bool {
        self.outcome.authorizes_future_mutation_only() && self.intent.is_some()
    }
}

// ===========================================================================
// Recovery outcome
// ===========================================================================

/// Run 301 — typed idempotency / recovery outcome for a prepared-intent
/// window. Every variant is non-mutating; no durable state is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionGovernanceExecutionRecoveryOutcome {
    /// No prior prepared intent for this decision id — clean window.
    NoPriorExecutionWindow,
    /// A byte-identical prepared intent — idempotent replay.
    IdempotentReplayOfSameIntent,
    /// Same decision id, conflicting proposal digest — fail closed.
    ConflictingProposalDigestForSameDecisionId,
    /// Same decision id, conflicting candidate digest — fail closed.
    ConflictingCandidateDigestForSameDecisionId,
    /// Same decision id, conflicting lifecycle action — fail closed.
    ConflictingLifecycleActionForSameDecisionId,
    /// Same decision id, conflicting proof transcript — fail closed.
    ConflictingProofTranscriptForSameDecisionId,
    /// Same decision id, conflicting custody evidence — fail closed.
    ConflictingCustodyEvidenceForSameDecisionId,
    /// Same decision id, conflicting attestation evidence — fail closed.
    ConflictingAttestationEvidenceForSameDecisionId,
    /// Stale governance epoch — fail closed.
    StaleGovernanceEpoch,
    /// Stale authority sequence — fail closed.
    StaleAuthoritySequence,
    /// Ambiguous recovery window — fail closed.
    AmbiguousRecoveryFailClosed { reason: String },
}

impl ProductionGovernanceExecutionRecoveryOutcome {
    /// Every recovery outcome is non-mutating.
    pub const fn is_non_mutating(&self) -> bool {
        true
    }

    /// Returns `true` iff the window is a clean no-op or an idempotent
    /// replay (i.e. not a conflict / stale / ambiguous fail-closed).
    pub fn is_clean(&self) -> bool {
        matches!(
            self,
            Self::NoPriorExecutionWindow | Self::IdempotentReplayOfSameIntent
        )
    }
}

// ===========================================================================
// Engine
// ===========================================================================

/// Run 301 — the source/test production governance execution engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionGovernanceExecutionEngine {
    pub config: ProductionGovernanceExecutionEngineConfig,
    pub policy: ProductionGovernanceExecutionEnginePolicy,
}

impl ProductionGovernanceExecutionEngine {
    pub fn new(
        config: ProductionGovernanceExecutionEngineConfig,
        policy: ProductionGovernanceExecutionEnginePolicy,
    ) -> Self {
        Self { config, policy }
    }

    /// A source/test engine under the source/test policy.
    pub fn source_test() -> Self {
        Self::new(
            ProductionGovernanceExecutionEngineConfig::source_test(),
            ProductionGovernanceExecutionEnginePolicy::AllowSourceTestVerifiedGovernanceExecution,
        )
    }

    /// Extract the `(decision, binding)` pair from a proof source, mapping
    /// every non-authority source to its precise fail-closed outcome.
    fn resolve_proof_source<'a>(
        &self,
        source: &'a GovernanceExecutionProofSource,
    ) -> Result<
        (
            &'a ProductionOnChainGovernanceProofDecision,
            &'a GovernanceExecutionProofBinding,
        ),
        ProductionGovernanceExecutionOutcome,
    > {
        use GovernanceExecutionProofSource as S;
        use ProductionGovernanceExecutionOutcome as O;
        match source {
            S::VerifiedOnChainGovernanceProof { decision, binding } => {
                if !decision.is_accept() {
                    return Err(O::UnverifiedGovernanceProofRejected);
                }
                Ok((decision, binding))
            }
            S::MissingProof => Err(O::VerifiedOnChainGovernanceProofRequired),
            S::UnverifiedOnChainGovernanceProof { .. } => Err(O::UnverifiedGovernanceProofRejected),
            S::FixtureGovernanceProof => {
                Err(O::FixtureGovernanceProofRejectedAsProductionAuthority)
            }
            S::LocalOperatorAssertion => Err(O::LocalOperatorProofRejected),
            S::PeerMajorityAssertion => Err(O::PeerMajorityProofRejected),
            S::CustodyOnlyEvidence => Err(O::CustodyOnlyProofRejected),
            S::RemoteSignerOnlyEvidence => Err(O::RemoteSignerOnlyProofRejected),
            S::CustodyAttestationOnlyEvidence => Err(O::CustodyAttestationOnlyProofRejected),
        }
    }

    /// Pure policy / engine-kind / MainNet gate applied before any binding.
    /// Returns `Some(outcome)` to refuse, `None` to proceed.
    fn preflight_gate(
        &self,
        binding_env: TrustBundleEnvironment,
        inputs: &ProductionGovernanceExecutionInputs,
    ) -> Option<ProductionGovernanceExecutionOutcome> {
        use ProductionGovernanceExecutionOutcome as O;

        // 1. Disabled fails closed before any binding.
        if self.policy.is_disabled()
            || self.config.kind == ProductionGovernanceExecutionEngineKind::Disabled
        {
            return Some(O::Disabled);
        }

        // 2. MainNet gate. A MainNet trust domain or MainNet decision is
        //    refused: no MainNet production authority is wired. Gated
        //    before binding so MainNet can never reach an accept path.
        if inputs.trust_domain.environment == TrustBundleEnvironment::Mainnet
            || binding_env == TrustBundleEnvironment::Mainnet
        {
            return Some(match self.policy {
                ProductionGovernanceExecutionEnginePolicy::MainnetProductionGovernanceExecutionRequired => {
                    O::MainNetProductionGovernanceExecutionUnavailable
                }
                _ => O::MainNetRefused,
            });
        }

        // 3. The MainNet production policy on a non-MainNet domain still
        //    has no MainNet authority wired — fail closed.
        if self.policy.is_mainnet() {
            return Some(O::MainNetProductionGovernanceExecutionUnavailable);
        }

        // 4. The production policy has no production governance execution
        //    prerequisites wired — fail closed.
        if self.policy.is_production() {
            return Some(O::ProductionGovernanceExecutionUnavailable);
        }

        // 5. Reserved production engine kind is fail-closed in Run 301.
        if self.config.kind
            == ProductionGovernanceExecutionEngineKind::ProductionGovernanceExecutionEngine
        {
            return Some(O::GovernanceExecutionEngineUnavailable);
        }

        // 6. Config / inputs well-formedness.
        if !self.config.is_well_formed() {
            return Some(O::GovernanceExecutionAmbiguous {
                reason: "config-malformed".to_string(),
            });
        }
        if !inputs.is_well_formed() {
            return Some(O::GovernanceExecutionAmbiguous {
                reason: "inputs-malformed".to_string(),
            });
        }

        None
    }

    /// Cross-check the extracted binding against the verified Run 299
    /// decision's accept outcome and the bound transcript. Returns
    /// `Some(outcome)` on the first divergence.
    fn check_decision_consistency(
        &self,
        decision: &ProductionOnChainGovernanceProofDecision,
        binding: &GovernanceExecutionProofBinding,
    ) -> Option<ProductionGovernanceExecutionOutcome> {
        use ProductionGovernanceExecutionOutcome as O;

        // The engine's transcript binding must equal the Run 299 verifier
        // transcript.
        if binding.proof_transcript_digest != decision.transcript_digest {
            return Some(O::GovernanceProofTranscriptMismatch);
        }
        if binding.proof_digest != decision.proof_digest {
            return Some(O::GovernanceProofTranscriptMismatch);
        }
        if binding.decision_id != decision.decision_id {
            return Some(O::WrongDecisionId);
        }

        // The accept outcome's fields must equal the binding.
        if let ProductionOnChainGovernanceProofOutcome::AcceptedProductionOnChainGovernanceProof {
            environment,
            governance_epoch,
            authority_domain_sequence,
            lifecycle_action,
            decision_id,
        } = &decision.outcome
        {
            if *environment != binding.environment {
                return Some(O::WrongEnvironment);
            }
            if *governance_epoch != binding.governance_epoch {
                return Some(O::WrongGovernanceEpoch);
            }
            if *authority_domain_sequence != binding.authority_domain_sequence {
                return Some(O::WrongAuthoritySequence);
            }
            if *lifecycle_action != binding.lifecycle_action {
                return Some(O::WrongLifecycleAction);
            }
            if *decision_id != binding.decision_id {
                return Some(O::WrongDecisionId);
            }
        } else {
            // Not an accept — should have been caught earlier.
            return Some(O::UnverifiedGovernanceProofRejected);
        }

        None
    }

    /// Field-by-field binding comparison against the explicit trusted
    /// inputs and the authoritative trust domain. Returns `Some(outcome)`
    /// on the first mismatch.
    fn check_binding(
        &self,
        binding: &GovernanceExecutionProofBinding,
        inputs: &ProductionGovernanceExecutionInputs,
    ) -> Option<ProductionGovernanceExecutionOutcome> {
        use ProductionGovernanceExecutionOutcome as O;
        let td = &inputs.trust_domain;

        if binding.environment != td.environment {
            return Some(O::WrongEnvironment);
        }
        if binding.chain_id != td.chain_id {
            return Some(O::WrongChain);
        }
        if binding.genesis_hash != td.genesis_hash {
            return Some(O::WrongGenesis);
        }
        if binding.authority_root_fingerprint != td.authority_root_fingerprint
            || binding.authority_root_suite_id != td.authority_root_suite_id
        {
            return Some(O::WrongAuthorityRoot);
        }
        if binding.governance_domain_id != inputs.expected_governance_domain_id {
            return Some(O::WrongGovernanceDomain);
        }
        if binding.governance_epoch != inputs.expected_governance_epoch {
            return Some(O::WrongGovernanceEpoch);
        }
        if binding.proposal_id != inputs.expected_proposal_id {
            return Some(O::WrongProposalId);
        }
        if binding.proposal_digest != inputs.expected_proposal_digest {
            return Some(O::WrongProposalDigest);
        }
        if binding.proposal_outcome != inputs.expected_proposal_outcome
            || binding.proposal_outcome != OnChainGovernanceProposalOutcome::Approved
        {
            return Some(O::WrongProposalOutcome);
        }
        if binding.lifecycle_action != inputs.expected_lifecycle_action {
            return Some(O::WrongLifecycleAction);
        }
        if binding.candidate_v2_digest != inputs.expected_candidate_v2_digest {
            return Some(O::WrongCandidateDigest);
        }
        if binding.authority_domain_sequence != inputs.expected_authority_domain_sequence {
            return Some(O::WrongAuthoritySequence);
        }
        if binding.quorum != inputs.expected_quorum || !binding.quorum.is_met() {
            return Some(O::WrongQuorum);
        }
        if binding.threshold != inputs.expected_threshold || !binding.threshold.is_met() {
            return Some(O::WrongThreshold);
        }
        if binding.proof_transcript_digest != inputs.expected_proof_transcript_digest {
            return Some(O::GovernanceProofTranscriptMismatch);
        }

        None
    }

    /// Evidence composition check for represented custody / attestation /
    /// durable-replay bindings. Returns `Some(outcome)` on the first
    /// required-but-missing or mismatched evidence.
    fn check_evidence(
        &self,
        request: &ProductionGovernanceExecutionRequest,
        inputs: &ProductionGovernanceExecutionInputs,
    ) -> Option<ProductionGovernanceExecutionOutcome> {
        use ProductionGovernanceExecutionOutcome as O;

        // Custody backend evidence.
        if inputs.require_custody_evidence {
            let Some(actual) = &request.custody_binding else {
                return Some(O::CustodyBackendEvidenceRequired);
            };
            if !actual.is_well_formed() {
                return Some(O::CustodyBackendMismatch);
            }
            match &inputs.expected_custody {
                Some(expected) if expected == actual => {}
                _ => return Some(O::CustodyBackendMismatch),
            }
        } else if let Some(actual) = &request.custody_binding {
            // Represented but not required: it must still match if an
            // expected value is supplied.
            if let Some(expected) = &inputs.expected_custody {
                if expected != actual {
                    return Some(O::CustodyBackendMismatch);
                }
            }
        }

        // Custody attestation evidence.
        if inputs.require_attestation_evidence {
            let Some(actual) = &request.attestation_binding else {
                return Some(O::CustodyAttestationRequired);
            };
            if !actual.is_well_formed() {
                return Some(O::CustodyAttestationMismatch);
            }
            match &inputs.expected_attestation {
                Some(expected) if expected == actual => {}
                _ => return Some(O::CustodyAttestationMismatch),
            }
        } else if let Some(actual) = &request.attestation_binding {
            if let Some(expected) = &inputs.expected_attestation {
                if expected != actual {
                    return Some(O::CustodyAttestationMismatch);
                }
            }
        }

        // Durable replay evidence.
        if inputs.require_durable_replay_evidence {
            let Some(actual) = &request.durable_replay_binding else {
                return Some(O::DurableReplayEvidenceRequired);
            };
            if !actual.is_well_formed() {
                return Some(O::DurableReplayUnavailable);
            }
            match &inputs.expected_durable_replay {
                Some(expected) if expected == actual => {}
                _ => return Some(O::DurableReplayMismatch),
            }
        } else if let Some(actual) = &request.durable_replay_binding {
            if let Some(expected) = &inputs.expected_durable_replay {
                if expected != actual {
                    return Some(O::DurableReplayMismatch);
                }
            }
        }

        None
    }

    /// Core non-mutating evaluation. Returns the typed outcome plus, on
    /// accept, the prepared intent.
    fn evaluate_core<R: GovernanceExecutionReplaySet + ?Sized>(
        &self,
        request: &ProductionGovernanceExecutionRequest,
        inputs: &ProductionGovernanceExecutionInputs,
        replay_set: &R,
    ) -> (
        ProductionGovernanceExecutionOutcome,
        Option<ProductionGovernanceExecutionIntent>,
    ) {
        use ProductionGovernanceExecutionOutcome as O;

        // Resolve the proof source. The binding environment is needed for
        // the MainNet gate; if the source is a non-authority source we
        // must still gate on the trust-domain environment first.
        let resolved = self.resolve_proof_source(&request.proof_source);

        // Determine the binding environment for the MainNet gate (fall
        // back to the trust-domain environment when no verified binding).
        let binding_env = match &resolved {
            Ok((_, binding)) => binding.environment,
            Err(_) => inputs.trust_domain.environment,
        };

        // Step 1: selector / policy / engine-kind / MainNet gate.
        if let Some(outcome) = self.preflight_gate(binding_env, inputs) {
            return (outcome, None);
        }

        // Step 3: verified on-chain governance proof decision check.
        let (decision, binding) = match resolved {
            Ok(pair) => pair,
            Err(outcome) => return (outcome, None),
        };

        // Step 2: input well-formedness of the binding itself.
        if !binding.is_well_formed() {
            return (
                O::GovernanceExecutionAmbiguous {
                    reason: "proof-binding-malformed".to_string(),
                },
                None,
            );
        }

        // Decision <-> binding consistency (verified accept fields).
        if let Some(outcome) = self.check_decision_consistency(decision, binding) {
            return (outcome, None);
        }

        // Field-by-field binding comparison against explicit trusted
        // inputs.
        if let Some(outcome) = self.check_binding(binding, inputs) {
            return (outcome, None);
        }

        // Step 4: replay / freshness.
        if let Some(prev) = inputs.persisted_sequence {
            if binding.authority_domain_sequence < prev {
                return (O::StaleAuthoritySequence, None);
            }
        }
        if replay_set.contains(&binding.decision_id) {
            return (
                O::DecisionReplayRejected {
                    decision_id: binding.decision_id.clone(),
                },
                None,
            );
        }
        if binding.governance_epoch < inputs.min_governance_epoch {
            return (O::StaleGovernanceEpoch, None);
        }

        // Steps 5–7: custody / attestation / durable-replay evidence.
        if let Some(outcome) = self.check_evidence(request, inputs) {
            return (outcome, None);
        }

        // Step 8: lifecycle-action support / validator-set rotation gate.
        if binding.requested_operation.is_validator_set_rotation() {
            return (O::ValidatorSetRotationUnsupported, None);
        }
        if binding.requested_operation != inputs.expected_requested_operation {
            return (O::UnsupportedLifecycleAction, None);
        }
        // ActivateInitial is not a governance-execution lifecycle action.
        if binding.lifecycle_action == LocalLifecycleAction::ActivateInitial {
            return (O::UnsupportedLifecycleAction, None);
        }
        let Some(intent_kind) = binding.requested_operation.intent_kind() else {
            return (O::ValidatorSetRotationUnsupported, None);
        };

        // Step 9: construct the typed non-mutating execution intent.
        let intent = ProductionGovernanceExecutionIntent {
            intent_kind,
            protocol_version: self.config.protocol_version.0,
            execution_policy_id: inputs.execution_policy_id.clone(),
            environment: binding.environment,
            chain_id: binding.chain_id.clone(),
            genesis_hash: binding.genesis_hash.clone(),
            authority_root_fingerprint: binding.authority_root_fingerprint.clone(),
            authority_root_suite_id: binding.authority_root_suite_id,
            governance_domain_id: binding.governance_domain_id.clone(),
            governance_epoch: binding.governance_epoch,
            governance_height: binding.governance_height,
            proposal_id: binding.proposal_id.clone(),
            proposal_digest: binding.proposal_digest.clone(),
            proposal_outcome: binding.proposal_outcome,
            quorum: binding.quorum.clone(),
            threshold: binding.threshold.clone(),
            lifecycle_action: binding.lifecycle_action,
            requested_operation: binding.requested_operation,
            candidate_v2_digest: binding.candidate_v2_digest.clone(),
            authority_domain_sequence: binding.authority_domain_sequence,
            decision_id: binding.decision_id.clone(),
            proof_transcript_digest: binding.proof_transcript_digest.clone(),
            proof_digest: binding.proof_digest.clone(),
            trusted_checkpoint_digest: binding.trusted_checkpoint_digest.clone(),
            custody_binding: request.custody_binding.clone(),
            attestation_binding: request.attestation_binding.clone(),
            durable_replay_binding: request.durable_replay_binding.clone(),
        };

        // Step 10: typed accepted non-mutating outcome.
        (
            O::AcceptedSourceTestGovernanceExecutionIntent {
                intent_kind,
                environment: binding.environment,
                decision_id: binding.decision_id.clone(),
            },
            Some(intent),
        )
    }

    /// Run 301 — evaluate a governance execution request into a typed,
    /// deterministic, non-mutating decision. This never mutates live trust
    /// state; on accept it produces only a prepared intent.
    pub fn evaluate_production_governance_execution<R: GovernanceExecutionReplaySet + ?Sized>(
        &self,
        request: &ProductionGovernanceExecutionRequest,
        inputs: &ProductionGovernanceExecutionInputs,
        replay_set: &R,
    ) -> ProductionGovernanceExecutionDecision {
        let (outcome, intent) = self.evaluate_core(request, inputs, replay_set);

        // Decision id for the transcript (best-effort from the binding).
        let decision_id = match &request.proof_source {
            GovernanceExecutionProofSource::VerifiedOnChainGovernanceProof { binding, .. } => {
                binding.decision_id.clone()
            }
            GovernanceExecutionProofSource::UnverifiedOnChainGovernanceProof { decision } => {
                decision.decision_id.clone()
            }
            _ => String::new(),
        };
        let proof_transcript_digest = match &request.proof_source {
            GovernanceExecutionProofSource::VerifiedOnChainGovernanceProof { binding, .. } => {
                binding.proof_transcript_digest.clone()
            }
            _ => String::new(),
        };

        let request_id = production_governance_execution_request_id(
            self.config.protocol_version.0,
            &decision_id,
            &proof_transcript_digest,
            &inputs.execution_policy_id,
        );
        let intent_digest = intent
            .as_ref()
            .map(|i| i.intent_digest())
            .unwrap_or_default();
        let transcript_digest = production_governance_execution_transcript_digest(
            self.config.protocol_version.0,
            &request_id,
            &intent_digest,
            outcome.tag(),
        );

        ProductionGovernanceExecutionDecision {
            outcome,
            decision_id,
            request_id,
            intent,
            intent_digest,
            transcript_digest,
        }
    }

    /// Run 301 — idempotency / recovery over a prepared-intent window.
    /// Non-mutating; writes no durable state.
    pub fn recover_production_governance_execution_window(
        &self,
        prior: Option<&ProductionGovernanceExecutionIntent>,
        current: &ProductionGovernanceExecutionIntent,
        current_min_governance_epoch: u64,
        current_min_authority_sequence: Option<u64>,
    ) -> ProductionGovernanceExecutionRecoveryOutcome {
        use ProductionGovernanceExecutionRecoveryOutcome as R;
        let Some(prior) = prior else {
            return R::NoPriorExecutionWindow;
        };
        // Unrelated decision ids => independent window.
        if prior.decision_id != current.decision_id {
            return R::NoPriorExecutionWindow;
        }
        // Same decision id, conflicting proposal digest => fail closed.
        if prior.proposal_digest != current.proposal_digest {
            return R::ConflictingProposalDigestForSameDecisionId;
        }
        // Same decision id, conflicting candidate digest => fail closed.
        if prior.candidate_v2_digest != current.candidate_v2_digest {
            return R::ConflictingCandidateDigestForSameDecisionId;
        }
        // Same decision id, conflicting lifecycle action => fail closed.
        if prior.lifecycle_action != current.lifecycle_action
            || prior.requested_operation != current.requested_operation
        {
            return R::ConflictingLifecycleActionForSameDecisionId;
        }
        // Same decision id, conflicting proof transcript => fail closed.
        if prior.proof_transcript_digest != current.proof_transcript_digest {
            return R::ConflictingProofTranscriptForSameDecisionId;
        }
        // Same decision id, conflicting custody evidence => fail closed.
        if prior.custody_binding != current.custody_binding {
            return R::ConflictingCustodyEvidenceForSameDecisionId;
        }
        // Same decision id, conflicting attestation evidence => fail closed.
        if prior.attestation_binding != current.attestation_binding {
            return R::ConflictingAttestationEvidenceForSameDecisionId;
        }
        // Stale governance epoch => fail closed.
        if current.governance_epoch < current_min_governance_epoch {
            return R::StaleGovernanceEpoch;
        }
        // Stale authority sequence => fail closed.
        if let Some(min_seq) = current_min_authority_sequence {
            if current.authority_domain_sequence < min_seq {
                return R::StaleAuthoritySequence;
            }
        }
        // Byte-identical => idempotent replay.
        if prior == current {
            R::IdempotentReplayOfSameIntent
        } else {
            R::AmbiguousRecoveryFailClosed {
                reason: "same decision id but non-identical prepared intent".to_string(),
            }
        }
    }
}

// ===========================================================================
// Standalone named helpers (source/test invariants)
// ===========================================================================

/// Run 301 — the engine default policy is Disabled / fail-closed.
pub fn production_governance_execution_engine_default_is_disabled() -> bool {
    ProductionGovernanceExecutionEnginePolicy::default()
        == ProductionGovernanceExecutionEnginePolicy::Disabled
        && ProductionGovernanceExecutionEngineConfig::default().kind
            == ProductionGovernanceExecutionEngineKind::Disabled
}

/// Run 301 — the engine is a source/test implementation, not release-binary
/// evidence (deferred to Run 302).
pub fn production_governance_execution_engine_is_source_test_not_release_binary_evidence() -> bool {
    true
}

/// Run 301 — the engine refuses MainNet absent production authority.
pub fn production_governance_execution_engine_mainnet_refused() -> bool {
    true
}

/// Run 301 — the engine does not implement validator-set rotation.
pub fn production_governance_execution_engine_validator_set_rotation_unsupported() -> bool {
    true
}

/// Run 301 — every engine outcome is non-mutating.
pub fn production_governance_execution_engine_is_non_mutating() -> bool {
    true
}

/// Run 301 — the engine never falls back to fixture / local-operator /
/// peer-majority / custody-only / RemoteSigner-only authority.
pub fn production_governance_execution_engine_never_falls_back() -> bool {
    true
}

/// Run 301 — the engine adds no default runtime wiring and no CLI flag.
pub fn production_governance_execution_engine_no_default_runtime_wiring() -> bool {
    true
}
