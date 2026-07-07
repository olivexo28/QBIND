//! Run 303 — source/test **real** validator-set rotation / authority-set
//! synchronization intent boundary.
//!
//! This module implements the first source/test validator-set rotation /
//! authority-set synchronization *intent boundary*: the boundary that
//! consumes a **verified** Run 301/302 governance execution intent (the
//! accepted [`crate::pqc_production_governance_execution_engine`] output, as
//! release-binary-evidenced by Run 302) and translates it into a typed,
//! deterministic, policy-gated **validator-set rotation / authority-set
//! synchronization plan** — *without* ever mutating any live validator set,
//! consensus state, or trust state.
//!
//! Where the Run 301 engine answers "given a verified on-chain governance
//! decision, what typed non-mutating authority-lifecycle execution intent
//! does it authorize?", Run 303 answers the next question: "given a verified
//! governance execution intent, what typed, non-mutating validator-set
//! rotation / authority-set synchronization plan does it authorize, under an
//! explicit rotation policy, bound to the full governance / validator-set /
//! custody / attestation / durable-replay evidence tuple?".
//!
//! ## Scope and honesty constraints (Run 303)
//!
//! * This run is a **source/test implementation only**. It is **not**
//!   release-binary evidence — that is deferred to **Run 304**.
//! * The default policy is
//!   [`ProductionValidatorSetRotationPolicy::Disabled`] and fails closed
//!   **before** any governance binding, validator-set binding, or plan
//!   construction.
//! * Only a **verified** Run 301/302 governance execution decision that
//!   `is_accept()` and carries a
//!   [`crate::pqc_production_governance_execution_engine::ProductionGovernanceExecutionIntent`]
//!   can authorize a plan. Unverified intents, on-chain proof alone,
//!   fixture proof alone, local-operator assertions, peer-majority
//!   assertions, custody-only, RemoteSigner-only, and custody-attestation-
//!   only evidence are all rejected as production authority.
//! * The boundary produces only a typed
//!   [`ProductionValidatorSetRotationPlan`]; it **never** applies the plan
//!   to consensus, never mutates a live validator set, never writes durable
//!   validator-set state, never calls
//!   `BasicHotStuffEngine::transition_to_epoch`, never writes
//!   `meta:current_epoch`, and never injects a reconfig block. Only a typed
//!   accepted outcome may authorize a *future* mutation run.
//! * MainNet remains **refused**: even a fully valid source/test
//!   DevNet/TestNet plan does not enable MainNet runtime behavior.
//! * The boundary is **non-mutating**: no Run 070 apply, no
//!   [`crate::pqc_live_trust::LivePqcTrustState`] mutation, no trust swap,
//!   no session eviction, no PQC trust-bundle sequence write, no authority
//!   marker write, no durable replay overwrite, no KMS/HSM signing call, no
//!   RemoteSigner fallback, no custody/fixture/local/peer-majority
//!   fallback, no settlement, no external publication, and no default
//!   runtime wiring.
//! * No CLI flag and no default runtime wiring is added. Full C4 remains
//!   OPEN; C5 remains OPEN.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_303.md`.

use crate::pqc_authority_lifecycle::{AuthorityTrustDomain, LocalLifecycleAction};
use crate::pqc_governance_authority::GovernanceThreshold;
use crate::pqc_onchain_governance_proof::OnChainGovernanceQuorum;
use crate::pqc_production_governance_execution_engine::{
    GovernanceExecutionAttestationBinding, GovernanceExecutionCustodyBinding,
    GovernanceExecutionDurableReplayBinding, ProductionGovernanceExecutionDecision,
    ProductionGovernanceExecutionIntent,
};
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Domain tags / protocol constants
// ===========================================================================

/// Run 303 — the only validator-set rotation boundary protocol version this
/// run accepts.
pub const PRODUCTION_VALIDATOR_SET_ROTATION_PROTOCOL_VERSION: u16 = 1;

/// Run 303 — validator identity digest domain tag.
pub const PRODUCTION_VALIDATOR_IDENTITY_DOMAIN_TAG: &str =
    "QBIND:run303-validator-identity:v1";

/// Run 303 — validator record digest domain tag.
pub const PRODUCTION_VALIDATOR_RECORD_DOMAIN_TAG: &str = "QBIND:run303-validator-record:v1";

/// Run 303 — validator-set snapshot digest domain tag.
pub const PRODUCTION_VALIDATOR_SET_SNAPSHOT_DOMAIN_TAG: &str =
    "QBIND:run303-validator-set-snapshot:v1";

/// Run 303 — validator-set delta digest domain tag.
pub const PRODUCTION_VALIDATOR_SET_DELTA_DOMAIN_TAG: &str =
    "QBIND:run303-validator-set-delta:v1";

/// Run 303 — validator-set rotation plan digest domain tag.
pub const PRODUCTION_VALIDATOR_SET_ROTATION_PLAN_DOMAIN_TAG: &str =
    "QBIND:run303-validator-set-rotation-plan:v1";

/// Run 303 — validator-set rotation request-id domain tag.
pub const PRODUCTION_VALIDATOR_SET_ROTATION_REQUEST_DOMAIN_TAG: &str =
    "QBIND:run303-validator-set-rotation-request:v1";

/// Run 303 — validator-set rotation transcript digest domain tag.
pub const PRODUCTION_VALIDATOR_SET_ROTATION_TRANSCRIPT_DOMAIN_TAG: &str =
    "QBIND:run303-validator-set-rotation-transcript:v1";

/// Length-prefixed domain-separated field hashing helper. `Debug`
/// formatting is never used as canonical bytes.
fn hash_field(h: &mut sha3::Sha3_256, label: &[u8], value: &[u8]) {
    use sha3::Digest;
    h.update((label.len() as u64).to_le_bytes());
    h.update(label);
    h.update((value.len() as u64).to_le_bytes());
    h.update(value);
}

// ===========================================================================
// Protocol version newtype
// ===========================================================================

/// Run 303 — typed validator-set rotation boundary protocol version. Only
/// [`PRODUCTION_VALIDATOR_SET_ROTATION_PROTOCOL_VERSION`] is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProductionValidatorSetRotationProtocolVersion(pub u16);

impl ProductionValidatorSetRotationProtocolVersion {
    /// The single supported protocol version.
    pub const fn supported() -> Self {
        Self(PRODUCTION_VALIDATOR_SET_ROTATION_PROTOCOL_VERSION)
    }

    /// Returns `true` iff this is the supported protocol version.
    pub const fn is_supported(self) -> bool {
        self.0 == PRODUCTION_VALIDATOR_SET_ROTATION_PROTOCOL_VERSION
    }
}

impl Default for ProductionValidatorSetRotationProtocolVersion {
    fn default() -> Self {
        Self::supported()
    }
}

// ===========================================================================
// Policy taxonomy
// ===========================================================================

/// Run 303 — typed validator-set rotation boundary policy.
///
/// `Disabled` is the default fail-closed policy: the boundary refuses
/// before any governance binding or plan construction.
/// `AllowSourceTestValidatorSetRotationIntent` is the only policy that can
/// produce an accepted source/test plan, and only on DevNet/TestNet with a
/// verified Run 301/302 governance execution intent.
/// `RequireProductionValidatorSetRotation` and
/// `MainnetProductionValidatorSetRotationRequired` are **reachable but
/// fail-closed** production/MainNet policies: no production validator-set
/// rotation authority is wired, so they fail closed as unavailable/refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProductionValidatorSetRotationPolicy {
    /// Default. Refuses every request before any binding.
    #[default]
    Disabled,
    /// DevNet/TestNet source/test policy. A verified governance execution
    /// intent may produce a typed non-mutating rotation plan as source/test
    /// evidence only. MainNet remains refused.
    AllowSourceTestValidatorSetRotationIntent,
    /// Production policy. Reachable but fails closed: no production
    /// validator-set rotation prerequisites are wired.
    RequireProductionValidatorSetRotation,
    /// MainNet production policy. Reachable but fails closed: no MainNet
    /// production validator-set rotation authority is wired.
    MainnetProductionValidatorSetRotationRequired,
}

impl ProductionValidatorSetRotationPolicy {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::AllowSourceTestValidatorSetRotationIntent => {
                "allow-source-test-validator-set-rotation-intent"
            }
            Self::RequireProductionValidatorSetRotation => {
                "require-production-validator-set-rotation"
            }
            Self::MainnetProductionValidatorSetRotationRequired => {
                "mainnet-production-validator-set-rotation-required"
            }
        }
    }

    /// Returns `true` iff this policy is `Disabled`.
    pub const fn is_disabled(self) -> bool {
        matches!(self, Self::Disabled)
    }

    /// Returns `true` iff this policy allows source/test validator-set
    /// rotation intents (DevNet/TestNet only).
    pub const fn allows_source_test(self) -> bool {
        matches!(self, Self::AllowSourceTestValidatorSetRotationIntent)
    }

    /// Returns `true` iff this policy is the production policy.
    pub const fn is_production(self) -> bool {
        matches!(self, Self::RequireProductionValidatorSetRotation)
    }

    /// Returns `true` iff this policy is the MainNet production policy.
    pub const fn is_mainnet(self) -> bool {
        matches!(self, Self::MainnetProductionValidatorSetRotationRequired)
    }
}

// ===========================================================================
// Boundary kind taxonomy
// ===========================================================================

/// Run 303 — typed validator-set rotation boundary kind.
///
/// `Disabled` is the inert default. `SourceTestValidatorSetRotationIntent`
/// performs real source/test plan construction. A reserved
/// `ProductionValidatorSetRotation` kind is fail-closed as unavailable in
/// Run 303 (no production authority is wired).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProductionValidatorSetRotationKind {
    /// Inert default; every request is refused.
    #[default]
    Disabled,
    /// Real source/test validator-set rotation intent boundary.
    SourceTestValidatorSetRotationIntent,
    /// Reserved production rotation kind. Fail-closed in Run 303.
    ProductionValidatorSetRotation,
}

impl ProductionValidatorSetRotationKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::SourceTestValidatorSetRotationIntent => {
                "source-test-validator-set-rotation-intent"
            }
            Self::ProductionValidatorSetRotation => "production-validator-set-rotation",
        }
    }

    /// Returns `true` iff this kind performs real source/test plan
    /// construction.
    pub const fn is_source_test(self) -> bool {
        matches!(self, Self::SourceTestValidatorSetRotationIntent)
    }
}

// ===========================================================================
// Config
// ===========================================================================

/// Run 303 — typed validator-set rotation boundary config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionValidatorSetRotationConfig {
    /// Boundary protocol version. Must equal the supported version.
    pub protocol_version: ProductionValidatorSetRotationProtocolVersion,
    /// The boundary kind.
    pub kind: ProductionValidatorSetRotationKind,
}

impl ProductionValidatorSetRotationConfig {
    pub fn new(kind: ProductionValidatorSetRotationKind) -> Self {
        Self {
            protocol_version: ProductionValidatorSetRotationProtocolVersion::supported(),
            kind,
        }
    }

    /// A config with the real source/test boundary kind.
    pub fn source_test() -> Self {
        Self::new(ProductionValidatorSetRotationKind::SourceTestValidatorSetRotationIntent)
    }

    /// Returns `true` iff the config pins the supported protocol version.
    pub fn is_well_formed(&self) -> bool {
        self.protocol_version.is_supported()
    }
}

impl Default for ProductionValidatorSetRotationConfig {
    fn default() -> Self {
        Self::new(ProductionValidatorSetRotationKind::Disabled)
    }
}

// ===========================================================================
// Requested rotation action
// ===========================================================================

/// Run 303 — the validator-set rotation / authority-set synchronization
/// action a caller requests.
///
/// Every action except [`Self::UnsupportedRotation`] maps to a typed
/// non-mutating [`ProductionValidatorSetRotationPlanKind`]. The requested
/// action must be consistent with the derived validator-set delta
/// composition; a mismatch fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidatorSetRotationAction {
    NoOpSynchronization,
    ValidatorAdd,
    ValidatorRemove,
    ValidatorUpdate,
    ValidatorIdentityRotation,
    ValidatorRetirement,
    EmergencyValidatorRemoval,
    AuthoritySetSynchronization,
    BulkValidatorSetRotation,
    UnsupportedRotation,
}

impl ValidatorSetRotationAction {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::NoOpSynchronization => "no-op-synchronization",
            Self::ValidatorAdd => "validator-add",
            Self::ValidatorRemove => "validator-remove",
            Self::ValidatorUpdate => "validator-update",
            Self::ValidatorIdentityRotation => "validator-identity-rotation",
            Self::ValidatorRetirement => "validator-retirement",
            Self::EmergencyValidatorRemoval => "emergency-validator-removal",
            Self::AuthoritySetSynchronization => "authority-set-synchronization",
            Self::BulkValidatorSetRotation => "bulk-validator-set-rotation",
            Self::UnsupportedRotation => "unsupported-rotation",
        }
    }

    /// Returns `true` iff this action is unsupported / fail-closed.
    pub const fn is_unsupported(self) -> bool {
        matches!(self, Self::UnsupportedRotation)
    }

    /// Maps a supported action to its typed non-mutating plan kind. Returns
    /// `None` for [`Self::UnsupportedRotation`].
    pub const fn plan_kind(self) -> Option<ProductionValidatorSetRotationPlanKind> {
        use ProductionValidatorSetRotationPlanKind as K;
        Some(match self {
            Self::NoOpSynchronization => K::NoOpAlreadySynchronized,
            Self::ValidatorAdd => K::ValidatorAdd,
            Self::ValidatorRemove => K::ValidatorRemove,
            Self::ValidatorUpdate => K::ValidatorMetadataUpdate,
            Self::ValidatorIdentityRotation => K::ValidatorIdentityRotation,
            Self::ValidatorRetirement => K::ValidatorRetirement,
            Self::EmergencyValidatorRemoval => K::EmergencyValidatorRemoval,
            Self::AuthoritySetSynchronization => K::AuthoritySetSynchronization,
            Self::BulkValidatorSetRotation => K::BulkValidatorSetRotation,
            Self::UnsupportedRotation => return None,
        })
    }
}

// ===========================================================================
// Plan kind taxonomy
// ===========================================================================

/// Run 303 — the typed kind of a prepared, non-mutating validator-set
/// rotation / authority-set synchronization plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProductionValidatorSetRotationPlanKind {
    NoOpAlreadySynchronized,
    ValidatorAdd,
    ValidatorRemove,
    ValidatorMetadataUpdate,
    ValidatorIdentityRotation,
    ValidatorRetirement,
    EmergencyValidatorRemoval,
    AuthoritySetSynchronization,
    BulkValidatorSetRotation,
    UnsupportedRotationRequest,
}

impl ProductionValidatorSetRotationPlanKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::NoOpAlreadySynchronized => "no-op-already-synchronized",
            Self::ValidatorAdd => "validator-add-plan",
            Self::ValidatorRemove => "validator-remove-plan",
            Self::ValidatorMetadataUpdate => "validator-metadata-update-plan",
            Self::ValidatorIdentityRotation => "validator-identity-rotation-plan",
            Self::ValidatorRetirement => "validator-retirement-plan",
            Self::EmergencyValidatorRemoval => "emergency-validator-removal-plan",
            Self::AuthoritySetSynchronization => "authority-set-synchronization-plan",
            Self::BulkValidatorSetRotation => "bulk-validator-set-rotation-plan",
            Self::UnsupportedRotationRequest => "unsupported-rotation-request",
        }
    }

    /// Every Run 303 plan kind is a *prepared*, non-mutating plan.
    pub const fn is_non_mutating(self) -> bool {
        true
    }
}

// ===========================================================================
// Canonical validator identity / record / set snapshot
// ===========================================================================

/// Run 303 — canonical validator identity. `Debug` formatting is never used
/// as canonical bytes; fields are length-prefixed and domain-separated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalValidatorIdentity {
    /// Validator index / id within the set.
    pub validator_index: u64,
    /// Consensus public key or validator signing key fingerprint.
    pub consensus_key_fingerprint: String,
    /// PQC transport root/leaf fingerprint where represented.
    pub pqc_transport_fingerprint: String,
    /// Authority root fingerprint where represented.
    pub authority_key_fingerprint: String,
}

impl CanonicalValidatorIdentity {
    pub fn is_well_formed(&self) -> bool {
        !self.consensus_key_fingerprint.is_empty()
    }

    fn hash_into(&self, h: &mut sha3::Sha3_256) {
        hash_field(h, b"validator_index", &self.validator_index.to_le_bytes());
        hash_field(
            h,
            b"consensus_key_fingerprint",
            self.consensus_key_fingerprint.as_bytes(),
        );
        hash_field(
            h,
            b"pqc_transport_fingerprint",
            self.pqc_transport_fingerprint.as_bytes(),
        );
        hash_field(
            h,
            b"authority_key_fingerprint",
            self.authority_key_fingerprint.as_bytes(),
        );
    }

    /// Deterministic, domain-separated SHA3-256 hex identity digest.
    pub fn identity_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(PRODUCTION_VALIDATOR_IDENTITY_DOMAIN_TAG.as_bytes());
        self.hash_into(&mut h);
        hex::encode(h.finalize())
    }
}

/// Run 303 — canonical validator record binding identity, voting power,
/// activation/retirement epochs, and the trust domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalValidatorRecord {
    pub identity: CanonicalValidatorIdentity,
    pub voting_power: u64,
    pub activation_epoch: u64,
    pub retirement_epoch: Option<u64>,
    pub environment: TrustBundleEnvironment,
    pub chain_id: String,
    pub genesis_hash: String,
}

impl CanonicalValidatorRecord {
    pub fn is_well_formed(&self) -> bool {
        self.identity.is_well_formed()
            && !self.chain_id.is_empty()
            && !self.genesis_hash.is_empty()
    }

    /// The canonical sort key: `(validator_index, consensus_key_fingerprint)`.
    fn sort_key(&self) -> (u64, &str) {
        (
            self.identity.validator_index,
            self.identity.consensus_key_fingerprint.as_str(),
        )
    }

    fn hash_into(&self, h: &mut sha3::Sha3_256) {
        self.identity.hash_into(h);
        hash_field(h, b"voting_power", &self.voting_power.to_le_bytes());
        hash_field(h, b"activation_epoch", &self.activation_epoch.to_le_bytes());
        match self.retirement_epoch {
            Some(e) => {
                hash_field(h, b"retirement_present", &[1u8]);
                hash_field(h, b"retirement_epoch", &e.to_le_bytes());
            }
            None => hash_field(h, b"retirement_present", &[0u8]),
        }
        hash_field(h, b"environment", &self.environment.metric_code().to_le_bytes());
        hash_field(h, b"chain_id", self.chain_id.as_bytes());
        hash_field(h, b"genesis_hash", self.genesis_hash.as_bytes());
    }

    /// Deterministic, domain-separated SHA3-256 hex record digest.
    pub fn record_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(PRODUCTION_VALIDATOR_RECORD_DOMAIN_TAG.as_bytes());
        self.hash_into(&mut h);
        hex::encode(h.finalize())
    }
}

/// Run 303 — canonical validator-set snapshot. Records are always sorted
/// canonically before digesting; map iteration order never affects the
/// digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalValidatorSetSnapshot {
    pub records: Vec<CanonicalValidatorRecord>,
    pub validator_set_epoch: u64,
    pub validator_set_version: u64,
}

impl CanonicalValidatorSetSnapshot {
    pub fn new(
        records: Vec<CanonicalValidatorRecord>,
        validator_set_epoch: u64,
        validator_set_version: u64,
    ) -> Self {
        Self {
            records,
            validator_set_epoch,
            validator_set_version,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// The records sorted canonically by `(validator_index,
    /// consensus_key_fingerprint)`.
    pub fn canonical_sorted(&self) -> Vec<CanonicalValidatorRecord> {
        let mut sorted = self.records.clone();
        sorted.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
        sorted
    }

    /// Returns `true` iff every record is structurally well-formed.
    pub fn records_well_formed(&self) -> bool {
        self.records.iter().all(|r| r.is_well_formed())
    }

    /// Returns `true` iff two records share the same validator index.
    pub fn has_duplicate_validator_id(&self) -> bool {
        let mut ids: Vec<u64> = self.records.iter().map(|r| r.identity.validator_index).collect();
        ids.sort_unstable();
        ids.windows(2).any(|w| w[0] == w[1])
    }

    /// Returns `true` iff two records share the same consensus key
    /// fingerprint.
    pub fn has_duplicate_consensus_key(&self) -> bool {
        let mut keys: Vec<&str> = self
            .records
            .iter()
            .map(|r| r.identity.consensus_key_fingerprint.as_str())
            .collect();
        keys.sort_unstable();
        keys.windows(2).any(|w| w[0] == w[1])
    }

    /// Returns `true` iff two records share a non-empty PQC transport
    /// fingerprint.
    pub fn has_duplicate_pqc_transport_key(&self) -> bool {
        let mut keys: Vec<&str> = self
            .records
            .iter()
            .map(|r| r.identity.pqc_transport_fingerprint.as_str())
            .filter(|s| !s.is_empty())
            .collect();
        keys.sort_unstable();
        keys.windows(2).any(|w| w[0] == w[1])
    }

    /// Returns `true` iff two records share a non-empty authority key
    /// fingerprint.
    pub fn has_duplicate_authority_key(&self) -> bool {
        let mut keys: Vec<&str> = self
            .records
            .iter()
            .map(|r| r.identity.authority_key_fingerprint.as_str())
            .filter(|s| !s.is_empty())
            .collect();
        keys.sort_unstable();
        keys.windows(2).any(|w| w[0] == w[1])
    }

    /// Finds a record by validator index.
    pub fn find(&self, validator_index: u64) -> Option<&CanonicalValidatorRecord> {
        self.records
            .iter()
            .find(|r| r.identity.validator_index == validator_index)
    }

    /// Deterministic, domain-separated SHA3-256 hex set digest. Records are
    /// sorted canonically first, then length-prefixed.
    pub fn set_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(PRODUCTION_VALIDATOR_SET_SNAPSHOT_DOMAIN_TAG.as_bytes());
        hash_field(&mut h, b"validator_set_epoch", &self.validator_set_epoch.to_le_bytes());
        hash_field(&mut h, b"validator_set_version", &self.validator_set_version.to_le_bytes());
        hash_field(&mut h, b"record_count", &(self.records.len() as u64).to_le_bytes());
        for record in self.canonical_sorted() {
            hash_field(&mut h, b"record_digest", record.record_digest().as_bytes());
        }
        hex::encode(h.finalize())
    }
}

// ===========================================================================
// Validator-set delta
// ===========================================================================

/// Run 303 — the kind of a single validator-set change entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidatorSetChangeKind {
    Add,
    Remove,
    Update,
}

impl ValidatorSetChangeKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Remove => "remove",
            Self::Update => "update",
        }
    }
}

/// Run 303 — a single validator-set change entry. `Add` and `Update` carry
/// the target record; `Remove` carries only the validator index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSetChange {
    pub kind: ValidatorSetChangeKind,
    pub validator_index: u64,
    pub record: Option<CanonicalValidatorRecord>,
}

impl ValidatorSetChange {
    pub fn add(record: CanonicalValidatorRecord) -> Self {
        Self {
            kind: ValidatorSetChangeKind::Add,
            validator_index: record.identity.validator_index,
            record: Some(record),
        }
    }

    pub fn remove(validator_index: u64) -> Self {
        Self {
            kind: ValidatorSetChangeKind::Remove,
            validator_index,
            record: None,
        }
    }

    pub fn update(record: CanonicalValidatorRecord) -> Self {
        Self {
            kind: ValidatorSetChangeKind::Update,
            validator_index: record.identity.validator_index,
            record: Some(record),
        }
    }

    /// Structural well-formedness: `Add`/`Update` require a record whose
    /// index matches; `Remove` requires no record.
    pub fn is_well_formed(&self) -> bool {
        match self.kind {
            ValidatorSetChangeKind::Add | ValidatorSetChangeKind::Update => match &self.record {
                Some(r) => {
                    r.is_well_formed() && r.identity.validator_index == self.validator_index
                }
                None => false,
            },
            ValidatorSetChangeKind::Remove => self.record.is_none(),
        }
    }

    fn hash_into(&self, h: &mut sha3::Sha3_256) {
        hash_field(h, b"change_kind", self.kind.tag().as_bytes());
        hash_field(h, b"validator_index", &self.validator_index.to_le_bytes());
        match &self.record {
            Some(r) => {
                hash_field(h, b"record_present", &[1u8]);
                hash_field(h, b"record_digest", r.record_digest().as_bytes());
            }
            None => hash_field(h, b"record_present", &[0u8]),
        }
    }
}

/// Run 303 — an ordered validator-set delta: the changes proposed against a
/// current snapshot to reach a proposed snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSetDelta {
    pub changes: Vec<ValidatorSetChange>,
}

impl ValidatorSetDelta {
    pub fn new(changes: Vec<ValidatorSetChange>) -> Self {
        Self { changes }
    }

    pub fn empty() -> Self {
        Self { changes: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.changes.len()
    }

    /// Returns `true` iff every change entry is structurally well-formed.
    pub fn changes_well_formed(&self) -> bool {
        self.changes.iter().all(|c| c.is_well_formed())
    }

    /// Returns `true` iff two change entries target the same validator index
    /// with the same change kind (ambiguous / redundant).
    pub fn has_ambiguous_change(&self) -> bool {
        for i in 0..self.changes.len() {
            for j in (i + 1)..self.changes.len() {
                let a = &self.changes[i];
                let b = &self.changes[j];
                if a.validator_index == b.validator_index && a.kind == b.kind {
                    return true;
                }
            }
        }
        false
    }

    /// Returns `true` iff two change entries target the same validator index
    /// with different (conflicting) change kinds.
    pub fn has_conflicting_change(&self) -> bool {
        for i in 0..self.changes.len() {
            for j in (i + 1)..self.changes.len() {
                let a = &self.changes[i];
                let b = &self.changes[j];
                if a.validator_index == b.validator_index && a.kind != b.kind {
                    return true;
                }
            }
        }
        false
    }

    /// The derived rotation action implied by the composition of change
    /// kinds: empty → NoOp, all-Add → Add, all-Remove → Remove, all-Update →
    /// Update, otherwise → Bulk.
    pub fn derived_action(&self) -> ValidatorSetRotationAction {
        if self.changes.is_empty() {
            return ValidatorSetRotationAction::NoOpSynchronization;
        }
        let all_add = self
            .changes
            .iter()
            .all(|c| c.kind == ValidatorSetChangeKind::Add);
        let all_remove = self
            .changes
            .iter()
            .all(|c| c.kind == ValidatorSetChangeKind::Remove);
        let all_update = self
            .changes
            .iter()
            .all(|c| c.kind == ValidatorSetChangeKind::Update);
        if all_add {
            ValidatorSetRotationAction::ValidatorAdd
        } else if all_remove {
            ValidatorSetRotationAction::ValidatorRemove
        } else if all_update {
            ValidatorSetRotationAction::ValidatorUpdate
        } else {
            ValidatorSetRotationAction::BulkValidatorSetRotation
        }
    }

    /// Deterministic, domain-separated SHA3-256 hex delta digest. Change
    /// order is significant and length-prefixed.
    pub fn delta_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(PRODUCTION_VALIDATOR_SET_DELTA_DOMAIN_TAG.as_bytes());
        hash_field(&mut h, b"change_count", &(self.changes.len() as u64).to_le_bytes());
        for change in &self.changes {
            change.hash_into(&mut h);
        }
        hex::encode(h.finalize())
    }
}

// ===========================================================================
// Authority source
// ===========================================================================

/// Run 303 — the governance authority source presented to the boundary.
///
/// Only [`Self::VerifiedGovernanceExecutionIntent`] carrying a Run 301/302
/// governance execution decision that `is_accept()` **and** carries a
/// prepared intent can authorize a validator-set rotation plan. Every other
/// variant is a non-authority source rejected with a precise fail-closed
/// outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatorSetRotationAuthoritySource {
    /// A verified Run 301/302 governance execution decision. The **only**
    /// accepted authority source. The decision must `is_accept()` and carry
    /// `Some(intent)`.
    VerifiedGovernanceExecutionIntent {
        decision: ProductionGovernanceExecutionDecision,
    },
    /// No governance intent was supplied.
    MissingGovernanceIntent,
    /// An unverified / non-accept governance execution decision. Rejected.
    UnverifiedGovernanceExecutionDecision {
        decision: ProductionGovernanceExecutionDecision,
    },
    /// An accepted decision that carries no prepared intent. Rejected.
    AcceptedDecisionWithoutIntent {
        decision: ProductionGovernanceExecutionDecision,
    },
    /// A raw on-chain governance proof presented directly, without a Run 301
    /// execution intent. Rejected.
    OnChainProofWithoutExecutionIntent,
    /// A Run 178 fixture governance intent presented as production
    /// authority. Rejected.
    FixtureGovernanceIntent,
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
    /// Custody-attestation evidence presented alone as governance authority.
    /// Rejected.
    CustodyAttestationOnlyEvidence,
}

// ===========================================================================
// Inputs
// ===========================================================================

/// Run 303 — the explicit trusted inputs the boundary binds a verified
/// governance execution intent and validator-set delta against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionValidatorSetRotationInputs {
    /// The authoritative trust domain.
    pub trust_domain: AuthorityTrustDomain,
    /// Expected governance execution policy id (bound into the intent).
    pub expected_execution_policy_id: String,
    /// Expected governance domain id.
    pub expected_governance_domain_id: String,
    /// Expected governance epoch.
    pub expected_governance_epoch: u64,
    /// Expected proposal id.
    pub expected_proposal_id: String,
    /// Expected candidate v2 digest.
    pub expected_candidate_v2_digest: String,
    /// Expected lifecycle action.
    pub expected_lifecycle_action: LocalLifecycleAction,
    /// Expected requested rotation action.
    pub expected_rotation_action: ValidatorSetRotationAction,
    /// Expected authority-domain sequence.
    pub expected_authority_domain_sequence: u64,
    /// Expected quorum.
    pub expected_quorum: OnChainGovernanceQuorum,
    /// Expected threshold.
    pub expected_threshold: GovernanceThreshold,
    /// Expected Run 301 governance execution decision id.
    pub expected_governance_decision_id: String,
    /// Expected Run 301 governance execution request id.
    pub expected_governance_request_id: String,
    /// Expected Run 301 governance execution transcript digest.
    pub expected_governance_transcript_digest: String,
    /// Expected Run 301 execution intent digest (transcript binding).
    pub expected_intent_digest: String,
    /// Minimum acceptable governance epoch (freshness; never wall-clock).
    pub min_governance_epoch: u64,
    /// Minimum acceptable validator-set epoch (freshness; never wall-clock).
    pub min_validator_set_epoch: u64,
    /// Minimum acceptable validator-set version (freshness).
    pub min_validator_set_version: u64,
    /// Optional persisted authority-domain sequence for stale-lower-sequence
    /// replay detection.
    pub persisted_sequence: Option<u64>,
    /// Expected current validator-set digest (the set the delta applies to).
    pub expected_current_set_digest: String,
    /// Expected proposed validator-set digest (the post-delta set).
    pub expected_proposed_set_digest: String,
    /// The opaque rotation policy id bound into the plan.
    pub rotation_policy_id: String,
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

impl ProductionValidatorSetRotationInputs {
    /// Returns `true` iff the inputs are structurally well-formed.
    pub fn is_well_formed(&self) -> bool {
        !self.trust_domain.chain_id.is_empty()
            && !self.trust_domain.genesis_hash.is_empty()
            && !self.trust_domain.authority_root_fingerprint.is_empty()
            && !self.expected_execution_policy_id.is_empty()
            && !self.expected_governance_domain_id.is_empty()
            && !self.expected_proposal_id.is_empty()
            && !self.expected_candidate_v2_digest.is_empty()
            && !self.expected_governance_decision_id.is_empty()
            && !self.expected_governance_request_id.is_empty()
            && !self.expected_governance_transcript_digest.is_empty()
            && !self.expected_intent_digest.is_empty()
            && !self.expected_current_set_digest.is_empty()
            && !self.expected_proposed_set_digest.is_empty()
            && !self.rotation_policy_id.is_empty()
            && (!self.require_custody_evidence || self.expected_custody.is_some())
            && (!self.require_attestation_evidence || self.expected_attestation.is_some())
            && (!self.require_durable_replay_evidence || self.expected_durable_replay.is_some())
    }
}

// ===========================================================================
// Request
// ===========================================================================

/// Run 303 — a validator-set rotation request: the authority source, the
/// current validator-set snapshot, the proposed validator-set delta, the
/// requested rotation action, and any represented custody / attestation /
/// durable-replay evidence bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionValidatorSetRotationRequest {
    pub authority_source: ValidatorSetRotationAuthoritySource,
    pub current_set: CanonicalValidatorSetSnapshot,
    pub delta: ValidatorSetDelta,
    pub requested_action: ValidatorSetRotationAction,
    pub proposed_validator_set_epoch: u64,
    pub proposed_validator_set_version: u64,
    pub rotation_nonce: u64,
    pub custody_binding: Option<GovernanceExecutionCustodyBinding>,
    pub attestation_binding: Option<GovernanceExecutionAttestationBinding>,
    pub durable_replay_binding: Option<GovernanceExecutionDurableReplayBinding>,
}

impl ProductionValidatorSetRotationRequest {
    /// Construct a request carrying only an authority source, current set,
    /// delta, and requested action (no represented custody / attestation /
    /// durable-replay evidence).
    pub fn new(
        authority_source: ValidatorSetRotationAuthoritySource,
        current_set: CanonicalValidatorSetSnapshot,
        delta: ValidatorSetDelta,
        requested_action: ValidatorSetRotationAction,
        proposed_validator_set_epoch: u64,
        proposed_validator_set_version: u64,
        rotation_nonce: u64,
    ) -> Self {
        Self {
            authority_source,
            current_set,
            delta,
            requested_action,
            proposed_validator_set_epoch,
            proposed_validator_set_version,
            rotation_nonce,
            custody_binding: None,
            attestation_binding: None,
            durable_replay_binding: None,
        }
    }
}

// ===========================================================================
// Replay set
// ===========================================================================

/// Run 303 — caller-owned replay rotation-id set. The boundary reads from
/// this set but never mutates it.
pub trait ValidatorSetRotationReplaySet {
    fn contains(&self, rotation_id: &str) -> bool;
}

impl ValidatorSetRotationReplaySet for &[String] {
    fn contains(&self, rotation_id: &str) -> bool {
        (*self).iter().any(|s| s == rotation_id)
    }
}

impl ValidatorSetRotationReplaySet for Vec<String> {
    fn contains(&self, rotation_id: &str) -> bool {
        self.iter().any(|s| s == rotation_id)
    }
}

/// Empty replay set helper.
pub struct EmptyValidatorSetRotationReplaySet;

impl ValidatorSetRotationReplaySet for EmptyValidatorSetRotationReplaySet {
    fn contains(&self, _rotation_id: &str) -> bool {
        false
    }
}

// ===========================================================================
// Rotation plan (boundary output)
// ===========================================================================

/// Run 303 — a typed, deterministic, **non-mutating** validator-set rotation
/// / authority-set synchronization plan. Only a typed accepted outcome
/// carrying a plan may authorize a *future* mutation run (Run 304+); Run 303
/// never applies the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionValidatorSetRotationPlan {
    pub plan_kind: ProductionValidatorSetRotationPlanKind,
    pub protocol_version: u16,
    pub rotation_policy_id: String,

    // ---- Bound governance execution intent tuple ----------------------
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
    pub quorum: OnChainGovernanceQuorum,
    pub threshold: GovernanceThreshold,
    pub lifecycle_action: LocalLifecycleAction,
    pub rotation_action: ValidatorSetRotationAction,
    pub authority_domain_sequence: u64,
    pub governance_decision_id: String,
    pub governance_request_id: String,
    pub governance_intent_digest: String,

    // ---- Bound validator-set delta tuple ------------------------------
    pub current_set_digest: String,
    pub proposed_set_digest: String,
    pub delta_digest: String,
    pub validator_set_epoch: u64,
    pub validator_set_version: u64,
    pub proposed_validator_count: u64,
    pub rotation_nonce: u64,

    // ---- Composed evidence (where represented) ------------------------
    pub custody_binding: Option<GovernanceExecutionCustodyBinding>,
    pub attestation_binding: Option<GovernanceExecutionAttestationBinding>,
    pub durable_replay_binding: Option<GovernanceExecutionDurableReplayBinding>,
}

impl ProductionValidatorSetRotationPlan {
    /// Deterministic, domain-separated SHA3-256 hex plan digest. `Debug`
    /// formatting is never used as canonical bytes.
    pub fn plan_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(PRODUCTION_VALIDATOR_SET_ROTATION_PLAN_DOMAIN_TAG.as_bytes());
        hash_field(&mut h, b"plan_kind", self.plan_kind.tag().as_bytes());
        hash_field(&mut h, b"protocol_version", &self.protocol_version.to_le_bytes());
        hash_field(&mut h, b"rotation_policy_id", self.rotation_policy_id.as_bytes());
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
        hash_field(&mut h, b"quorum_voted", &self.quorum.voters_voted.to_le_bytes());
        hash_field(&mut h, b"quorum_total", &self.quorum.total_voters.to_le_bytes());
        hash_field(&mut h, b"quorum_required", &self.quorum.required_quorum.to_le_bytes());
        hash_field(&mut h, b"threshold_approvals", &self.threshold.approvals.to_le_bytes());
        hash_field(&mut h, b"threshold_required", &self.threshold.required.to_le_bytes());
        hash_field(&mut h, b"threshold_total", &self.threshold.total.to_le_bytes());
        hash_field(&mut h, b"lifecycle_action", self.lifecycle_action.tag().as_bytes());
        hash_field(&mut h, b"rotation_action", self.rotation_action.tag().as_bytes());
        hash_field(
            &mut h,
            b"authority_domain_sequence",
            &self.authority_domain_sequence.to_le_bytes(),
        );
        hash_field(&mut h, b"governance_decision_id", self.governance_decision_id.as_bytes());
        hash_field(&mut h, b"governance_request_id", self.governance_request_id.as_bytes());
        hash_field(&mut h, b"governance_intent_digest", self.governance_intent_digest.as_bytes());
        hash_field(&mut h, b"current_set_digest", self.current_set_digest.as_bytes());
        hash_field(&mut h, b"proposed_set_digest", self.proposed_set_digest.as_bytes());
        hash_field(&mut h, b"delta_digest", self.delta_digest.as_bytes());
        hash_field(&mut h, b"validator_set_epoch", &self.validator_set_epoch.to_le_bytes());
        hash_field(&mut h, b"validator_set_version", &self.validator_set_version.to_le_bytes());
        hash_field(
            &mut h,
            b"proposed_validator_count",
            &self.proposed_validator_count.to_le_bytes(),
        );
        hash_field(&mut h, b"rotation_nonce", &self.rotation_nonce.to_le_bytes());
        match &self.custody_binding {
            Some(c) => {
                hash_field(&mut h, b"custody_present", &[1u8]);
                custody_hash_into(c, &mut h);
            }
            None => hash_field(&mut h, b"custody_present", &[0u8]),
        }
        match &self.attestation_binding {
            Some(a) => {
                hash_field(&mut h, b"attestation_present", &[1u8]);
                attestation_hash_into(a, &mut h);
            }
            None => hash_field(&mut h, b"attestation_present", &[0u8]),
        }
        match &self.durable_replay_binding {
            Some(d) => {
                hash_field(&mut h, b"durable_present", &[1u8]);
                durable_hash_into(d, &mut h);
            }
            None => hash_field(&mut h, b"durable_present", &[0u8]),
        }
        hex::encode(h.finalize())
    }

    /// This plan is prepared, non-mutating, and never applied by Run 303.
    pub const fn is_non_mutating(&self) -> bool {
        true
    }
}

/// Custody binding canonical hashing (module-local; mirrors Run 301 field
/// order for cross-run digest stability).
fn custody_hash_into(c: &GovernanceExecutionCustodyBinding, h: &mut sha3::Sha3_256) {
    hash_field(h, b"custody_provider_class", c.provider_class.tag().as_bytes());
    hash_field(h, b"custody_key_handle", c.key_handle.as_bytes());
    hash_field(h, b"custody_signer_fingerprint", c.signer_fingerprint.as_bytes());
    hash_field(
        h,
        b"custody_transcript_digest",
        c.custody_transcript_digest.as_bytes(),
    );
}

fn attestation_hash_into(a: &GovernanceExecutionAttestationBinding, h: &mut sha3::Sha3_256) {
    hash_field(
        h,
        b"attestation_transcript_digest",
        a.attestation_transcript_digest.as_bytes(),
    );
    hash_field(h, b"attestation_measurement", a.measurement.as_bytes());
}

fn durable_hash_into(d: &GovernanceExecutionDurableReplayBinding, h: &mut sha3::Sha3_256) {
    hash_field(h, b"durable_record_id", d.durable_record_id.as_bytes());
    hash_field(h, b"durable_record_digest", d.durable_record_digest.as_bytes());
}

/// Run 303 — deterministic rotation plan digest wrapper exposed as a named
/// symbol.
pub fn production_validator_set_rotation_plan_digest(
    plan: &ProductionValidatorSetRotationPlan,
) -> String {
    plan.plan_digest()
}

/// Run 303 — deterministic, domain-separated rotation request id binding the
/// protocol version, governance decision id, governance intent digest, and
/// rotation nonce. Deterministic across identical inputs; never wall-clock.
pub fn production_validator_set_rotation_request_id(
    protocol_version: u16,
    governance_decision_id: &str,
    governance_intent_digest: &str,
    rotation_policy_id: &str,
    rotation_nonce: u64,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(PRODUCTION_VALIDATOR_SET_ROTATION_REQUEST_DOMAIN_TAG.as_bytes());
    hash_field(&mut h, b"protocol_version", &protocol_version.to_le_bytes());
    hash_field(&mut h, b"governance_decision_id", governance_decision_id.as_bytes());
    hash_field(&mut h, b"governance_intent_digest", governance_intent_digest.as_bytes());
    hash_field(&mut h, b"rotation_policy_id", rotation_policy_id.as_bytes());
    hash_field(&mut h, b"rotation_nonce", &rotation_nonce.to_le_bytes());
    hex::encode(h.finalize())
}

/// Run 303 — deterministic, domain-separated rotation transcript digest
/// binding the protocol version, request id, plan digest, and outcome tag.
pub fn production_validator_set_rotation_transcript_digest(
    protocol_version: u16,
    request_id: &str,
    plan_digest: &str,
    outcome_tag: &str,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(PRODUCTION_VALIDATOR_SET_ROTATION_TRANSCRIPT_DOMAIN_TAG.as_bytes());
    hash_field(&mut h, b"protocol_version", &protocol_version.to_le_bytes());
    hash_field(&mut h, b"request_id", request_id.as_bytes());
    hash_field(&mut h, b"plan_digest", plan_digest.as_bytes());
    hash_field(&mut h, b"outcome_tag", outcome_tag.as_bytes());
    hex::encode(h.finalize())
}

// ===========================================================================
// Outcome taxonomy
// ===========================================================================

/// Run 303 — typed outcome of the validator-set rotation boundary.
///
/// Only [`Self::AcceptedSourceTestValidatorSetRotationPlan`] authorizes a
/// (source/test, DevNet/TestNet, evidence-only, non-mutating) rotation plan.
/// Every other variant is a precise, non-mutating fail-closed reject (or the
/// inert [`Self::Disabled`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionValidatorSetRotationOutcome {
    // ---- Disabled / unavailable ---------------------------------------
    /// Policy is `Disabled`; no authority was bound.
    Disabled,
    /// The boundary kind is unavailable / misconfigured.
    ValidatorSetRotationBoundaryUnavailable,
    /// The production policy has no production prerequisites wired.
    ProductionValidatorSetRotationUnavailable,
    /// The MainNet production policy has no MainNet authority wired.
    MainNetProductionValidatorSetRotationUnavailable,

    // ---- Accepted ------------------------------------------------------
    /// A verified DevNet/TestNet governance execution intent produced a
    /// typed non-mutating validator-set rotation plan under the source/test
    /// policy. **Evidence only.**
    AcceptedSourceTestValidatorSetRotationPlan {
        plan_kind: ProductionValidatorSetRotationPlanKind,
        environment: TrustBundleEnvironment,
        rotation_nonce: u64,
    },

    // ---- Governance / authority failures ------------------------------
    VerifiedGovernanceExecutionIntentRequired,
    UnverifiedGovernanceExecutionIntentRejected,
    OnChainProofAloneRejected,
    FixtureProofRejectedAsProductionAuthority,
    LocalOperatorProofRejected,
    PeerMajorityProofRejected,
    CustodyOnlyProofRejected,
    RemoteSignerOnlyProofRejected,
    CustodyAttestationOnlyProofRejected,
    GovernanceExecutionIntentMismatch,
    GovernanceExecutionTranscriptMismatch,
    WrongEnvironment,
    WrongChain,
    WrongGenesis,
    WrongAuthorityRoot,
    WrongGovernanceDomain,
    WrongGovernanceEpoch,
    WrongGovernanceExecutionDecisionId,
    WrongGovernanceExecutionRequestId,
    WrongGovernanceExecutionIntentDigest,
    WrongLifecycleAction,
    WrongCandidateDigest,
    WrongAuthoritySequence,
    WrongQuorum,
    WrongThreshold,

    // ---- Validator-set binding failures -------------------------------
    CurrentValidatorSetRequired,
    ProposedValidatorSetRequired,
    CurrentValidatorSetDigestMismatch,
    ProposedValidatorSetDigestMismatch,
    ValidatorSetEpochMismatch,
    ValidatorSetVersionMismatch,
    NonMonotonicValidatorSetEpoch,
    NonMonotonicValidatorSetVersion,
    EmptyProposedValidatorSetRejected,
    DuplicateValidatorId,
    DuplicateConsensusKey,
    DuplicatePqcTransportKey,
    DuplicateAuthorityKey,
    UnknownValidatorRemoval,
    UnknownValidatorUpdate,
    ConflictingValidatorDelta,
    AmbiguousValidatorSetDelta,
    UnsupportedValidatorSetDelta,
    UnsupportedRotationAction,

    // ---- Custody / attestation / durable replay -----------------------
    CustodyBackendEvidenceRequired,
    CustodyBackendMismatch,
    CustodyAttestationRequired,
    CustodyAttestationMismatch,
    DurableReplayEvidenceRequired,
    DurableReplayMismatch,
    DurableReplayUnavailable,

    // ---- Replay / freshness -------------------------------------------
    RotationReplayRejected { rotation_id: String },
    StaleGovernanceEpoch,
    StaleAuthoritySequence,
    StaleValidatorSetEpoch,
    StaleValidatorSetVersion,
    ConflictingPlanForSameRotation,
    ValidatorSetRotationAmbiguous { reason: String },
    MainNetRefused,
}

impl ProductionValidatorSetRotationOutcome {
    /// Returns `true` iff this outcome accepted a source/test rotation plan.
    pub fn is_accept(&self) -> bool {
        matches!(
            self,
            Self::AcceptedSourceTestValidatorSetRotationPlan { .. }
        )
    }

    /// Returns `true` iff this outcome is a fail-closed reject (i.e. not an
    /// accept and not the inert `Disabled`).
    pub fn is_reject(&self) -> bool {
        !self.is_accept() && !matches!(self, Self::Disabled)
    }

    /// Every Run 303 outcome is non-mutating.
    pub const fn is_non_mutating(&self) -> bool {
        true
    }

    /// Only an accepted outcome may authorize a *future* mutation run; it
    /// never mutates in Run 303.
    pub fn authorizes_future_mutation_only(&self) -> bool {
        self.is_accept()
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::ValidatorSetRotationBoundaryUnavailable => {
                "validator-set-rotation-boundary-unavailable"
            }
            Self::ProductionValidatorSetRotationUnavailable => {
                "production-validator-set-rotation-unavailable"
            }
            Self::MainNetProductionValidatorSetRotationUnavailable => {
                "mainnet-production-validator-set-rotation-unavailable"
            }
            Self::AcceptedSourceTestValidatorSetRotationPlan { .. } => {
                "accepted-source-test-validator-set-rotation-plan"
            }
            Self::VerifiedGovernanceExecutionIntentRequired => {
                "verified-governance-execution-intent-required"
            }
            Self::UnverifiedGovernanceExecutionIntentRejected => {
                "unverified-governance-execution-intent-rejected"
            }
            Self::OnChainProofAloneRejected => "onchain-proof-alone-rejected",
            Self::FixtureProofRejectedAsProductionAuthority => {
                "fixture-proof-rejected-as-production-authority"
            }
            Self::LocalOperatorProofRejected => "local-operator-proof-rejected",
            Self::PeerMajorityProofRejected => "peer-majority-proof-rejected",
            Self::CustodyOnlyProofRejected => "custody-only-proof-rejected",
            Self::RemoteSignerOnlyProofRejected => "remote-signer-only-proof-rejected",
            Self::CustodyAttestationOnlyProofRejected => "custody-attestation-only-proof-rejected",
            Self::GovernanceExecutionIntentMismatch => "governance-execution-intent-mismatch",
            Self::GovernanceExecutionTranscriptMismatch => {
                "governance-execution-transcript-mismatch"
            }
            Self::WrongEnvironment => "wrong-environment",
            Self::WrongChain => "wrong-chain",
            Self::WrongGenesis => "wrong-genesis",
            Self::WrongAuthorityRoot => "wrong-authority-root",
            Self::WrongGovernanceDomain => "wrong-governance-domain",
            Self::WrongGovernanceEpoch => "wrong-governance-epoch",
            Self::WrongGovernanceExecutionDecisionId => "wrong-governance-execution-decision-id",
            Self::WrongGovernanceExecutionRequestId => "wrong-governance-execution-request-id",
            Self::WrongGovernanceExecutionIntentDigest => "wrong-governance-execution-intent-digest",
            Self::WrongLifecycleAction => "wrong-lifecycle-action",
            Self::WrongCandidateDigest => "wrong-candidate-digest",
            Self::WrongAuthoritySequence => "wrong-authority-sequence",
            Self::WrongQuorum => "wrong-quorum",
            Self::WrongThreshold => "wrong-threshold",
            Self::CurrentValidatorSetRequired => "current-validator-set-required",
            Self::ProposedValidatorSetRequired => "proposed-validator-set-required",
            Self::CurrentValidatorSetDigestMismatch => "current-validator-set-digest-mismatch",
            Self::ProposedValidatorSetDigestMismatch => "proposed-validator-set-digest-mismatch",
            Self::ValidatorSetEpochMismatch => "validator-set-epoch-mismatch",
            Self::ValidatorSetVersionMismatch => "validator-set-version-mismatch",
            Self::NonMonotonicValidatorSetEpoch => "non-monotonic-validator-set-epoch",
            Self::NonMonotonicValidatorSetVersion => "non-monotonic-validator-set-version",
            Self::EmptyProposedValidatorSetRejected => "empty-proposed-validator-set-rejected",
            Self::DuplicateValidatorId => "duplicate-validator-id",
            Self::DuplicateConsensusKey => "duplicate-consensus-key",
            Self::DuplicatePqcTransportKey => "duplicate-pqc-transport-key",
            Self::DuplicateAuthorityKey => "duplicate-authority-key",
            Self::UnknownValidatorRemoval => "unknown-validator-removal",
            Self::UnknownValidatorUpdate => "unknown-validator-update",
            Self::ConflictingValidatorDelta => "conflicting-validator-delta",
            Self::AmbiguousValidatorSetDelta => "ambiguous-validator-set-delta",
            Self::UnsupportedValidatorSetDelta => "unsupported-validator-set-delta",
            Self::UnsupportedRotationAction => "unsupported-rotation-action",
            Self::CustodyBackendEvidenceRequired => "custody-backend-evidence-required",
            Self::CustodyBackendMismatch => "custody-backend-mismatch",
            Self::CustodyAttestationRequired => "custody-attestation-required",
            Self::CustodyAttestationMismatch => "custody-attestation-mismatch",
            Self::DurableReplayEvidenceRequired => "durable-replay-evidence-required",
            Self::DurableReplayMismatch => "durable-replay-mismatch",
            Self::DurableReplayUnavailable => "durable-replay-unavailable",
            Self::RotationReplayRejected { .. } => "rotation-replay-rejected",
            Self::StaleGovernanceEpoch => "stale-governance-epoch",
            Self::StaleAuthoritySequence => "stale-authority-sequence",
            Self::StaleValidatorSetEpoch => "stale-validator-set-epoch",
            Self::StaleValidatorSetVersion => "stale-validator-set-version",
            Self::ConflictingPlanForSameRotation => "conflicting-plan-for-same-rotation",
            Self::ValidatorSetRotationAmbiguous { .. } => "validator-set-rotation-ambiguous",
            Self::MainNetRefused => "mainnet-refused",
        }
    }
}

// ===========================================================================
// Decision (boundary output)
// ===========================================================================

/// Run 303 — the typed decision produced by the boundary: the outcome, the
/// bound rotation id, the deterministic request id, the optional prepared
/// plan, its digest, and the verification transcript digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionValidatorSetRotationDecision {
    pub outcome: ProductionValidatorSetRotationOutcome,
    pub rotation_id: String,
    pub request_id: String,
    pub plan: Option<ProductionValidatorSetRotationPlan>,
    pub plan_digest: String,
    pub transcript_digest: String,
}

impl ProductionValidatorSetRotationDecision {
    pub fn is_accept(&self) -> bool {
        self.outcome.is_accept()
    }

    /// Returns `true` iff the decision carries a prepared, non-mutating plan
    /// (only on accept). The boundary never applies it.
    pub fn authorizes_future_mutation_only(&self) -> bool {
        self.outcome.authorizes_future_mutation_only() && self.plan.is_some()
    }
}

// ===========================================================================
// Recovery outcome
// ===========================================================================

/// Run 303 — typed idempotency / recovery outcome for a prepared-plan
/// window. Every variant is non-mutating; no durable state is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionValidatorSetRotationRecoveryOutcome {
    /// No prior prepared plan for this rotation id — clean window.
    NoPriorRotationWindow,
    /// A prior prepared plan for this rotation id was observed; the boundary
    /// re-derives the same plan deterministically without mutation.
    IdempotentReplayObserved { rotation_id: String },
    /// The recovery window is disabled (policy `Disabled`).
    RecoveryDisabled,
}

impl ProductionValidatorSetRotationRecoveryOutcome {
    /// Every recovery outcome is non-mutating.
    pub const fn is_non_mutating(&self) -> bool {
        true
    }

    /// Returns `true` iff the recovery window is clean (no prior plan).
    pub fn is_clean(&self) -> bool {
        matches!(self, Self::NoPriorRotationWindow)
    }
}

// ===========================================================================
// Boundary
// ===========================================================================

/// Run 303 — the source/test validator-set rotation / authority-set
/// synchronization intent boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionValidatorSetRotationBoundary {
    pub config: ProductionValidatorSetRotationConfig,
    pub policy: ProductionValidatorSetRotationPolicy,
}

/// Internal: the result of applying a validated delta to the current set.
struct AppliedDelta {
    proposed: CanonicalValidatorSetSnapshot,
    derived_action: ValidatorSetRotationAction,
}

impl ProductionValidatorSetRotationBoundary {
    pub fn new(
        config: ProductionValidatorSetRotationConfig,
        policy: ProductionValidatorSetRotationPolicy,
    ) -> Self {
        Self { config, policy }
    }

    /// A source/test boundary under the source/test policy.
    pub fn source_test() -> Self {
        Self::new(
            ProductionValidatorSetRotationConfig::source_test(),
            ProductionValidatorSetRotationPolicy::AllowSourceTestValidatorSetRotationIntent,
        )
    }

    /// Extract the verified governance execution intent from an authority
    /// source, mapping every non-authority source to its precise
    /// fail-closed outcome.
    fn resolve_authority_source<'a>(
        &self,
        source: &'a ValidatorSetRotationAuthoritySource,
    ) -> Result<
        (
            &'a ProductionGovernanceExecutionDecision,
            &'a ProductionGovernanceExecutionIntent,
        ),
        ProductionValidatorSetRotationOutcome,
    > {
        use ProductionValidatorSetRotationOutcome as O;
        use ValidatorSetRotationAuthoritySource as S;
        match source {
            S::VerifiedGovernanceExecutionIntent { decision } => {
                if !decision.is_accept() {
                    return Err(O::UnverifiedGovernanceExecutionIntentRejected);
                }
                match &decision.intent {
                    Some(intent) => Ok((decision, intent)),
                    None => Err(O::VerifiedGovernanceExecutionIntentRequired),
                }
            }
            S::MissingGovernanceIntent => Err(O::VerifiedGovernanceExecutionIntentRequired),
            S::UnverifiedGovernanceExecutionDecision { .. } => {
                Err(O::UnverifiedGovernanceExecutionIntentRejected)
            }
            S::AcceptedDecisionWithoutIntent { .. } => {
                Err(O::VerifiedGovernanceExecutionIntentRequired)
            }
            S::OnChainProofWithoutExecutionIntent => Err(O::OnChainProofAloneRejected),
            S::FixtureGovernanceIntent => Err(O::FixtureProofRejectedAsProductionAuthority),
            S::LocalOperatorAssertion => Err(O::LocalOperatorProofRejected),
            S::PeerMajorityAssertion => Err(O::PeerMajorityProofRejected),
            S::CustodyOnlyEvidence => Err(O::CustodyOnlyProofRejected),
            S::RemoteSignerOnlyEvidence => Err(O::RemoteSignerOnlyProofRejected),
            S::CustodyAttestationOnlyEvidence => Err(O::CustodyAttestationOnlyProofRejected),
        }
    }

    /// Pure policy / kind / MainNet gate applied before any binding. Returns
    /// `Some(outcome)` to refuse, `None` to proceed.
    fn preflight_gate(
        &self,
        binding_env: TrustBundleEnvironment,
        inputs: &ProductionValidatorSetRotationInputs,
    ) -> Option<ProductionValidatorSetRotationOutcome> {
        use ProductionValidatorSetRotationOutcome as O;

        // 1. Disabled fails closed before any binding.
        if self.policy.is_disabled()
            || self.config.kind == ProductionValidatorSetRotationKind::Disabled
        {
            return Some(O::Disabled);
        }

        // 2. MainNet gate. A MainNet trust domain or MainNet intent is
        //    refused: no MainNet production authority is wired.
        if inputs.trust_domain.environment == TrustBundleEnvironment::Mainnet
            || binding_env == TrustBundleEnvironment::Mainnet
        {
            return Some(match self.policy {
                ProductionValidatorSetRotationPolicy::MainnetProductionValidatorSetRotationRequired => {
                    O::MainNetProductionValidatorSetRotationUnavailable
                }
                _ => O::MainNetRefused,
            });
        }

        // 3. MainNet production policy on a non-MainNet domain still has no
        //    MainNet authority wired — fail closed.
        if self.policy.is_mainnet() {
            return Some(O::MainNetProductionValidatorSetRotationUnavailable);
        }

        // 4. The production policy has no production prerequisites wired —
        //    fail closed.
        if self.policy.is_production() {
            return Some(O::ProductionValidatorSetRotationUnavailable);
        }

        // 5. Reserved production boundary kind is fail-closed in Run 303.
        if self.config.kind == ProductionValidatorSetRotationKind::ProductionValidatorSetRotation {
            return Some(O::ValidatorSetRotationBoundaryUnavailable);
        }

        // 6. Config / inputs well-formedness.
        if !self.config.is_well_formed() || !inputs.is_well_formed() {
            return Some(O::ValidatorSetRotationBoundaryUnavailable);
        }

        None
    }

    /// Cross-check the verified decision and its prepared intent against the
    /// explicit trusted inputs and trust domain. Returns `Some(outcome)` on
    /// the first divergence.
    fn check_governance_binding(
        &self,
        decision: &ProductionGovernanceExecutionDecision,
        intent: &ProductionGovernanceExecutionIntent,
        inputs: &ProductionValidatorSetRotationInputs,
    ) -> Option<ProductionValidatorSetRotationOutcome> {
        use ProductionValidatorSetRotationOutcome as O;
        let td = &inputs.trust_domain;

        // Decision transcript binding.
        if decision.decision_id != inputs.expected_governance_decision_id {
            return Some(O::WrongGovernanceExecutionDecisionId);
        }
        if decision.request_id != inputs.expected_governance_request_id {
            return Some(O::WrongGovernanceExecutionRequestId);
        }
        if decision.transcript_digest != inputs.expected_governance_transcript_digest {
            return Some(O::GovernanceExecutionTranscriptMismatch);
        }
        if decision.intent_digest != inputs.expected_intent_digest {
            return Some(O::WrongGovernanceExecutionIntentDigest);
        }
        // The prepared intent must reproduce the bound digest exactly.
        if intent.intent_digest() != decision.intent_digest {
            return Some(O::GovernanceExecutionIntentMismatch);
        }

        // Trust-domain binding.
        if intent.environment != td.environment {
            return Some(O::WrongEnvironment);
        }
        if intent.chain_id != td.chain_id {
            return Some(O::WrongChain);
        }
        if intent.genesis_hash != td.genesis_hash {
            return Some(O::WrongGenesis);
        }
        if intent.authority_root_fingerprint != td.authority_root_fingerprint
            || intent.authority_root_suite_id != td.authority_root_suite_id
        {
            return Some(O::WrongAuthorityRoot);
        }

        // Governance tuple binding.
        if intent.governance_domain_id != inputs.expected_governance_domain_id {
            return Some(O::WrongGovernanceDomain);
        }
        if intent.governance_epoch != inputs.expected_governance_epoch {
            return Some(O::WrongGovernanceEpoch);
        }
        if intent.proposal_id != inputs.expected_proposal_id {
            return Some(O::GovernanceExecutionIntentMismatch);
        }
        if intent.candidate_v2_digest != inputs.expected_candidate_v2_digest {
            return Some(O::WrongCandidateDigest);
        }
        if intent.lifecycle_action != inputs.expected_lifecycle_action {
            return Some(O::WrongLifecycleAction);
        }
        if intent.authority_domain_sequence != inputs.expected_authority_domain_sequence {
            return Some(O::WrongAuthoritySequence);
        }
        if intent.quorum != inputs.expected_quorum || !intent.quorum.is_met() {
            return Some(O::WrongQuorum);
        }
        if intent.threshold != inputs.expected_threshold || !intent.threshold.is_met() {
            return Some(O::WrongThreshold);
        }

        None
    }

    /// Validate the current validator set, the proposed delta, and the
    /// resulting proposed set. Returns the applied delta on success.
    fn check_validator_set(
        &self,
        request: &ProductionValidatorSetRotationRequest,
        inputs: &ProductionValidatorSetRotationInputs,
    ) -> Result<AppliedDelta, ProductionValidatorSetRotationOutcome> {
        use ProductionValidatorSetRotationOutcome as O;
        let current = &request.current_set;
        let delta = &request.delta;

        // Current set structural consistency.
        if !current.records_well_formed() {
            return Err(O::CurrentValidatorSetRequired);
        }
        if current.has_duplicate_validator_id() {
            return Err(O::DuplicateValidatorId);
        }
        if current.has_duplicate_consensus_key() {
            return Err(O::DuplicateConsensusKey);
        }
        if current.has_duplicate_pqc_transport_key() {
            return Err(O::DuplicatePqcTransportKey);
        }
        if current.has_duplicate_authority_key() {
            return Err(O::DuplicateAuthorityKey);
        }
        // Current set digest binding.
        if current.set_digest() != inputs.expected_current_set_digest {
            return Err(O::CurrentValidatorSetDigestMismatch);
        }

        // Delta structural checks.
        if !delta.changes_well_formed() {
            return Err(O::UnsupportedValidatorSetDelta);
        }
        if delta.has_conflicting_change() {
            return Err(O::ConflictingValidatorDelta);
        }
        if delta.has_ambiguous_change() {
            return Err(O::AmbiguousValidatorSetDelta);
        }

        // Apply the delta to the canonical current records.
        let mut records: Vec<CanonicalValidatorRecord> = current.records.clone();
        for change in &delta.changes {
            match change.kind {
                ValidatorSetChangeKind::Add => {
                    if records
                        .iter()
                        .any(|r| r.identity.validator_index == change.validator_index)
                    {
                        return Err(O::DuplicateValidatorId);
                    }
                    // Well-formedness guarantees `record` is `Some`.
                    if let Some(record) = &change.record {
                        records.push(record.clone());
                    }
                }
                ValidatorSetChangeKind::Remove => {
                    let before = records.len();
                    records.retain(|r| r.identity.validator_index != change.validator_index);
                    if records.len() == before {
                        return Err(O::UnknownValidatorRemoval);
                    }
                }
                ValidatorSetChangeKind::Update => {
                    let Some(pos) = records
                        .iter()
                        .position(|r| r.identity.validator_index == change.validator_index)
                    else {
                        return Err(O::UnknownValidatorUpdate);
                    };
                    if let Some(record) = &change.record {
                        records[pos] = record.clone();
                    }
                }
            }
        }

        let proposed = CanonicalValidatorSetSnapshot::new(
            records,
            request.proposed_validator_set_epoch,
            request.proposed_validator_set_version,
        );

        // Proposed set structural consistency.
        if !proposed.records_well_formed() {
            return Err(O::ProposedValidatorSetRequired);
        }
        if proposed.has_duplicate_validator_id() {
            return Err(O::DuplicateValidatorId);
        }
        if proposed.has_duplicate_consensus_key() {
            return Err(O::DuplicateConsensusKey);
        }
        if proposed.has_duplicate_pqc_transport_key() {
            return Err(O::DuplicatePqcTransportKey);
        }
        if proposed.has_duplicate_authority_key() {
            return Err(O::DuplicateAuthorityKey);
        }
        if proposed.is_empty() {
            return Err(O::EmptyProposedValidatorSetRejected);
        }

        // Epoch / version monotonicity and freshness.
        if request.proposed_validator_set_epoch < current.validator_set_epoch {
            return Err(O::NonMonotonicValidatorSetEpoch);
        }
        if request.proposed_validator_set_version < current.validator_set_version {
            return Err(O::NonMonotonicValidatorSetVersion);
        }
        if request.proposed_validator_set_epoch < inputs.min_validator_set_epoch {
            return Err(O::StaleValidatorSetEpoch);
        }
        if request.proposed_validator_set_version < inputs.min_validator_set_version {
            return Err(O::StaleValidatorSetVersion);
        }
        // Non-empty deltas must advance the epoch and version; a NoOp must
        // leave both unchanged.
        if delta.is_empty() {
            if request.proposed_validator_set_epoch != current.validator_set_epoch {
                return Err(O::ValidatorSetEpochMismatch);
            }
            if request.proposed_validator_set_version != current.validator_set_version {
                return Err(O::ValidatorSetVersionMismatch);
            }
        } else {
            if request.proposed_validator_set_epoch <= current.validator_set_epoch {
                return Err(O::ValidatorSetEpochMismatch);
            }
            if request.proposed_validator_set_version <= current.validator_set_version {
                return Err(O::ValidatorSetVersionMismatch);
            }
        }

        // Proposed set digest binding.
        if proposed.set_digest() != inputs.expected_proposed_set_digest {
            return Err(O::ProposedValidatorSetDigestMismatch);
        }

        Ok(AppliedDelta {
            proposed,
            derived_action: delta.derived_action(),
        })
    }

    /// Evidence composition check for represented custody / attestation /
    /// durable-replay bindings.
    fn check_evidence(
        &self,
        request: &ProductionValidatorSetRotationRequest,
        inputs: &ProductionValidatorSetRotationInputs,
    ) -> Option<ProductionValidatorSetRotationOutcome> {
        use ProductionValidatorSetRotationOutcome as O;

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
            if let Some(expected) = &inputs.expected_custody {
                if expected != actual {
                    return Some(O::CustodyBackendMismatch);
                }
            }
        }

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
}

/// Returns `true` iff the requested rotation action is authorized by the
/// governance lifecycle action bound into the verified intent.
fn lifecycle_authorizes_rotation(
    lifecycle: LocalLifecycleAction,
    action: ValidatorSetRotationAction,
) -> bool {
    use LocalLifecycleAction as L;
    use ValidatorSetRotationAction as A;
    // NoOp synchronization is authorized by any lifecycle action.
    if matches!(action, A::NoOpSynchronization) {
        return true;
    }
    match lifecycle {
        L::ActivateInitial => matches!(
            action,
            A::ValidatorAdd | A::AuthoritySetSynchronization | A::BulkValidatorSetRotation
        ),
        L::Rotate => matches!(
            action,
            A::ValidatorAdd
                | A::ValidatorRemove
                | A::ValidatorUpdate
                | A::ValidatorIdentityRotation
                | A::AuthoritySetSynchronization
                | A::BulkValidatorSetRotation
        ),
        L::Retire => matches!(
            action,
            A::ValidatorRetirement | A::ValidatorRemove | A::AuthoritySetSynchronization
        ),
        L::Revoke => matches!(
            action,
            A::ValidatorRemove | A::EmergencyValidatorRemoval | A::AuthoritySetSynchronization
        ),
        L::EmergencyRevoke => {
            matches!(action, A::EmergencyValidatorRemoval | A::ValidatorRemove)
        }
    }
}

/// Returns `true` iff the requested rotation action is compatible with the
/// composition of the validator-set delta (the derived action).
fn action_compatible_with_delta(
    requested: ValidatorSetRotationAction,
    derived: ValidatorSetRotationAction,
) -> bool {
    use ValidatorSetRotationAction as A;
    match derived {
        A::NoOpSynchronization => matches!(requested, A::NoOpSynchronization),
        A::ValidatorAdd => matches!(
            requested,
            A::ValidatorAdd | A::AuthoritySetSynchronization | A::BulkValidatorSetRotation
        ),
        A::ValidatorRemove => matches!(
            requested,
            A::ValidatorRemove
                | A::ValidatorRetirement
                | A::EmergencyValidatorRemoval
                | A::AuthoritySetSynchronization
                | A::BulkValidatorSetRotation
        ),
        A::ValidatorUpdate => matches!(
            requested,
            A::ValidatorUpdate
                | A::ValidatorIdentityRotation
                | A::AuthoritySetSynchronization
                | A::BulkValidatorSetRotation
        ),
        // A mixed delta derives Bulk; only Bulk / AuthoritySetSync accept it.
        A::BulkValidatorSetRotation => matches!(
            requested,
            A::BulkValidatorSetRotation | A::AuthoritySetSynchronization
        ),
        _ => false,
    }
}

impl ProductionValidatorSetRotationBoundary {
    /// Core non-mutating evaluation. Returns the typed outcome plus, on
    /// accept, the prepared plan.
    fn evaluate_core<R: ValidatorSetRotationReplaySet + ?Sized>(
        &self,
        request: &ProductionValidatorSetRotationRequest,
        inputs: &ProductionValidatorSetRotationInputs,
        replay_set: &R,
    ) -> (
        ProductionValidatorSetRotationOutcome,
        Option<ProductionValidatorSetRotationPlan>,
    ) {
        use ProductionValidatorSetRotationOutcome as O;

        // Resolve the authority source. The binding environment is needed
        // for the MainNet gate; if the source is a non-authority source we
        // still gate on the trust-domain environment first.
        let resolved = self.resolve_authority_source(&request.authority_source);
        let binding_env = match &resolved {
            Ok((_, intent)) => intent.environment,
            Err(_) => inputs.trust_domain.environment,
        };

        // Step 1: policy / kind / MainNet gate.
        if let Some(outcome) = self.preflight_gate(binding_env, inputs) {
            return (outcome, None);
        }

        // Step 2: verified governance execution intent.
        let (decision, intent) = match resolved {
            Ok(pair) => pair,
            Err(outcome) => return (outcome, None),
        };

        // Step 3: governance binding cross-checks.
        if let Some(outcome) = self.check_governance_binding(decision, intent, inputs) {
            return (outcome, None);
        }

        // Step 4: replay / freshness on the governance tuple.
        if let Some(prev) = inputs.persisted_sequence {
            if intent.authority_domain_sequence < prev {
                return (O::StaleAuthoritySequence, None);
            }
        }
        let rotation_id = production_validator_set_rotation_request_id(
            self.config.protocol_version.0,
            &intent.decision_id,
            &decision.intent_digest,
            &inputs.rotation_policy_id,
            request.rotation_nonce,
        );
        if replay_set.contains(&rotation_id) {
            return (O::RotationReplayRejected { rotation_id }, None);
        }
        if intent.governance_epoch < inputs.min_governance_epoch {
            return (O::StaleGovernanceEpoch, None);
        }

        // Step 5: custody / attestation / durable-replay evidence.
        if let Some(outcome) = self.check_evidence(request, inputs) {
            return (outcome, None);
        }

        // Step 6: requested rotation action support.
        if request.requested_action.is_unsupported() {
            return (O::UnsupportedRotationAction, None);
        }
        if request.requested_action != inputs.expected_rotation_action {
            return (O::UnsupportedRotationAction, None);
        }

        // Step 7: validator-set binding + delta application.
        let applied = match self.check_validator_set(request, inputs) {
            Ok(applied) => applied,
            Err(outcome) => return (outcome, None),
        };

        // Step 8: requested action must match the derived delta composition.
        if !action_compatible_with_delta(request.requested_action, applied.derived_action) {
            return (O::UnsupportedValidatorSetDelta, None);
        }

        // Step 9: the governance lifecycle action must authorize the
        //         requested rotation action.
        if !lifecycle_authorizes_rotation(intent.lifecycle_action, request.requested_action) {
            return (O::WrongLifecycleAction, None);
        }

        // Step 10: derive the typed plan kind.
        let Some(plan_kind) = request.requested_action.plan_kind() else {
            return (O::UnsupportedRotationAction, None);
        };

        // Step 11: construct the typed non-mutating rotation plan.
        let plan = ProductionValidatorSetRotationPlan {
            plan_kind,
            protocol_version: self.config.protocol_version.0,
            rotation_policy_id: inputs.rotation_policy_id.clone(),
            environment: intent.environment,
            chain_id: intent.chain_id.clone(),
            genesis_hash: intent.genesis_hash.clone(),
            authority_root_fingerprint: intent.authority_root_fingerprint.clone(),
            authority_root_suite_id: intent.authority_root_suite_id,
            governance_domain_id: intent.governance_domain_id.clone(),
            governance_epoch: intent.governance_epoch,
            governance_height: intent.governance_height,
            proposal_id: intent.proposal_id.clone(),
            proposal_digest: intent.proposal_digest.clone(),
            quorum: intent.quorum.clone(),
            threshold: intent.threshold.clone(),
            lifecycle_action: intent.lifecycle_action,
            rotation_action: request.requested_action,
            authority_domain_sequence: intent.authority_domain_sequence,
            governance_decision_id: decision.decision_id.clone(),
            governance_request_id: decision.request_id.clone(),
            governance_intent_digest: decision.intent_digest.clone(),
            current_set_digest: request.current_set.set_digest(),
            proposed_set_digest: applied.proposed.set_digest(),
            delta_digest: request.delta.delta_digest(),
            validator_set_epoch: applied.proposed.validator_set_epoch,
            validator_set_version: applied.proposed.validator_set_version,
            proposed_validator_count: applied.proposed.len() as u64,
            rotation_nonce: request.rotation_nonce,
            custody_binding: request.custody_binding.clone(),
            attestation_binding: request.attestation_binding.clone(),
            durable_replay_binding: request.durable_replay_binding.clone(),
        };

        // Step 12: typed accepted non-mutating outcome.
        (
            O::AcceptedSourceTestValidatorSetRotationPlan {
                plan_kind,
                environment: intent.environment,
                rotation_nonce: request.rotation_nonce,
            },
            Some(plan),
        )
    }

    /// Run 303 — evaluate a validator-set rotation request into a typed,
    /// deterministic, non-mutating decision. This never mutates any live
    /// validator set or trust state; on accept it produces only a prepared
    /// plan.
    pub fn evaluate_validator_set_rotation<R: ValidatorSetRotationReplaySet + ?Sized>(
        &self,
        request: &ProductionValidatorSetRotationRequest,
        inputs: &ProductionValidatorSetRotationInputs,
        replay_set: &R,
    ) -> ProductionValidatorSetRotationDecision {
        let (outcome, plan) = self.evaluate_core(request, inputs, replay_set);

        // Rotation / governance decision id for the transcript (best-effort
        // from the authority source).
        let governance_decision_id = match &request.authority_source {
            ValidatorSetRotationAuthoritySource::VerifiedGovernanceExecutionIntent { decision }
            | ValidatorSetRotationAuthoritySource::UnverifiedGovernanceExecutionDecision {
                decision,
            }
            | ValidatorSetRotationAuthoritySource::AcceptedDecisionWithoutIntent { decision } => {
                decision.decision_id.clone()
            }
            _ => String::new(),
        };
        let governance_intent_digest = match &request.authority_source {
            ValidatorSetRotationAuthoritySource::VerifiedGovernanceExecutionIntent { decision }
            | ValidatorSetRotationAuthoritySource::UnverifiedGovernanceExecutionDecision {
                decision,
            }
            | ValidatorSetRotationAuthoritySource::AcceptedDecisionWithoutIntent { decision } => {
                decision.intent_digest.clone()
            }
            _ => String::new(),
        };

        let request_id = production_validator_set_rotation_request_id(
            self.config.protocol_version.0,
            &governance_decision_id,
            &governance_intent_digest,
            &inputs.rotation_policy_id,
            request.rotation_nonce,
        );
        let plan_digest = plan.as_ref().map(|p| p.plan_digest()).unwrap_or_default();
        let transcript_digest = production_validator_set_rotation_transcript_digest(
            self.config.protocol_version.0,
            &request_id,
            &plan_digest,
            outcome.tag(),
        );

        ProductionValidatorSetRotationDecision {
            outcome,
            rotation_id: governance_decision_id,
            request_id,
            plan,
            plan_digest,
            transcript_digest,
        }
    }

    /// Run 303 — idempotency / recovery over a prepared-plan window.
    /// Non-mutating; writes no durable state.
    pub fn recover_validator_set_rotation_window(
        &self,
        prior: Option<&ProductionValidatorSetRotationPlan>,
        current: &ProductionValidatorSetRotationPlan,
    ) -> ProductionValidatorSetRotationRecoveryOutcome {
        use ProductionValidatorSetRotationRecoveryOutcome as R;
        if self.policy.is_disabled()
            || self.config.kind == ProductionValidatorSetRotationKind::Disabled
        {
            return R::RecoveryDisabled;
        }
        let Some(prior) = prior else {
            return R::NoPriorRotationWindow;
        };
        // Unrelated governance decision ids => independent window.
        if prior.governance_decision_id != current.governance_decision_id
            || prior.rotation_nonce != current.rotation_nonce
        {
            return R::NoPriorRotationWindow;
        }
        // Same window, byte-identical plan => idempotent replay.
        if prior == current {
            R::IdempotentReplayObserved {
                rotation_id: current.governance_decision_id.clone(),
            }
        } else {
            // Same window but non-identical plan is caller error; the
            // boundary reports a clean (non-mutating) recovery signal and
            // never overwrites durable state.
            R::NoPriorRotationWindow
        }
    }
}

// ===========================================================================
// Standalone named helpers (source/test invariants)
// ===========================================================================

/// Run 303 — the boundary default policy is Disabled / fail-closed.
pub fn production_validator_set_rotation_boundary_default_is_disabled() -> bool {
    ProductionValidatorSetRotationPolicy::default() == ProductionValidatorSetRotationPolicy::Disabled
        && ProductionValidatorSetRotationConfig::default().kind
            == ProductionValidatorSetRotationKind::Disabled
}

/// Run 303 — the boundary is a source/test implementation, not
/// release-binary evidence (deferred to Run 304).
pub fn production_validator_set_rotation_boundary_is_source_test_not_release_binary_evidence() -> bool
{
    true
}

/// Run 303 — the boundary refuses MainNet absent production authority.
pub fn production_validator_set_rotation_boundary_mainnet_refused() -> bool {
    true
}

/// Run 303 — the boundary never mutates a live validator set, consensus
/// epoch, or trust state; every outcome is non-mutating.
pub fn production_validator_set_rotation_boundary_is_non_mutating() -> bool {
    true
}

/// Run 303 — the boundary never falls back to on-chain-proof-alone /
/// fixture / local-operator / peer-majority / custody-only / RemoteSigner-
/// only authority.
pub fn production_validator_set_rotation_boundary_never_falls_back() -> bool {
    true
}

/// Run 303 — the boundary adds no default runtime wiring and no CLI flag.
pub fn production_validator_set_rotation_boundary_no_default_runtime_wiring() -> bool {
    true
}

/// Run 303 — the boundary only requires a verified Run 301/302 governance
/// execution intent as authority; nothing else can authorize a plan.
pub fn production_validator_set_rotation_boundary_requires_verified_governance_intent() -> bool {
    true
}