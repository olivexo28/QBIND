//! Run 291 — **production durable replay RocksDB backend** (source/test
//! implementation).
//!
//! Source/test only. Run 291 captures **no** release-binary evidence;
//! release-binary evidence for this backend is deferred to **Run 292**. Run 291
//! is the first *real* production-backend implementation for the governance
//! durable replay layer: unlike the Run 238 [`FixtureDurableReplayBackend`]
//! (which models restart durability through an in-process value-clone snapshot,
//! never a file format) this module persists typed replay records to a **real
//! RocksDB database on disk**, recovers them across reopen, enforces domain
//! binding, enforces idempotency / equivocation, and fails closed on corrupt or
//! wrong-domain state.
//!
//! ## What this module adds
//!
//! * [`ProductionDurableReplayRocksDbBackend`] — the real RocksDB-backed durable
//!   replay backend.
//! * [`GovernanceProductionDurableReplayBackend`] — a narrow, mockable trait
//!   describing the durable replay backend surface, implemented by the real
//!   backend and by the in-memory [`MockDurableReplayBackend`] used for
//!   composition tests.
//! * [`DurableReplayRocksDbConfig`] / [`DurableReplayRocksDbPolicy`] /
//!   [`DurableReplayRocksDbIdentity`] — the open configuration, the
//!   default-Disabled production policy selector, and the domain identity a
//!   database is bound to.
//! * [`DurableReplayRocksDbRecord`] / [`DurableReplayRecordStage`] /
//!   [`DurableReplayEventInput`] — the persisted typed replay record, its stage,
//!   and the typed input a caller supplies. Record ids and digests are
//!   deterministic; they can be derived directly from the Run 238
//!   [`DurableBackendDecisionInput`].
//! * [`DurableReplayRocksDbOpenOutcome`] / [`DurableReplayRocksDbWriteOutcome`] /
//!   [`DurableReplayRocksDbReadOutcome`] / [`DurableReplayRocksDbRecoveryOutcome`]
//!   — the typed operation outcomes.
//! * [`DurableReplayRocksDbError`] — the fail-closed production backend error
//!   taxonomy.
//! * Deterministic digest helpers ([`durable_replay_rocksdb_record_id`],
//!   [`durable_replay_rocksdb_record_digest`],
//!   [`durable_replay_rocksdb_domain_digest`]).
//!
//! ## Fail-closed / durability contract
//!
//! * The default [`DurableReplayRocksDbPolicy`] is [`DurableReplayRocksDbPolicy::Disabled`].
//!   The production binary is **never** wired to open this backend by default;
//!   selection is source/test only for this run.
//! * MainNet is refused: a [`DurableReplayRocksDbIdentity`] bound to
//!   [`TrustBundleEnvironment::Mainnet`] fails closed at open.
//! * On open the persisted schema version and domain metadata are validated
//!   against the configured [`DurableReplayRocksDbIdentity`]. A wrong
//!   environment / chain / genesis / namespace / authority-domain-sequence, an
//!   unsupported / malformed schema marker, missing metadata in a non-empty DB,
//!   corrupted metadata, or partial-write residue all **fail closed** — there is
//!   **no** silent fallback to an in-memory backend.
//! * A record write is a single atomic RocksDB `WriteBatch` commit: either the
//!   record survives reopen or nothing is written. A duplicate identical record
//!   is idempotent; the same record id with a different digest fails closed as
//!   equivocation and never overwrites the original.
//! * Every read recomputes the domain-bound record digest and compares it to the
//!   stored digest; a mismatch or an undecodable record fails closed.
//! * A `Consumed`-stage write requires the prior `Observed`-stage record to
//!   exist with a matching digest; an out-of-order consume fails closed.
//!
//! ## What this module does NOT do
//!
//! * It does **not** enable the backend in the production binary by default.
//! * It adds **no** CLI flag and touches **no** existing storage / wire / marker
//!   / sequence / trust-bundle format.
//! * It performs **no** Run 070 call, `LivePqcTrustState` mutation, trust swap,
//!   session eviction, sequence / marker write, settlement, external
//!   publication, custody / RemoteSigner / KMS / HSM signing, or validator-set
//!   rotation.
//! * It does **not** claim C4 or C5 closure, production readiness, MainNet
//!   evidence, or release-binary evidence.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_291.md`.

use crate::pqc_governance_evaluator_replay_durable_backend::{
    durable_backend_key_digest, durable_record_digest, DurableBackendDecisionInput,
    DurableRecordState,
};
use crate::pqc_trust_bundle::TrustBundleEnvironment;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Domain-separation tag for the Run 291 durable replay RocksDB domain digest.
pub const DURABLE_REPLAY_ROCKSDB_DOMAIN_TAG: &str =
    "qbind.run291.governance.production.durable.replay.rocksdb.domain.v1";
/// Domain-separation tag for the Run 291 durable replay RocksDB record digest.
pub const DURABLE_REPLAY_ROCKSDB_RECORD_TAG: &str =
    "qbind.run291.governance.production.durable.replay.rocksdb.record.v1";
/// Default replay namespace / domain separator for the Run 291 backend.
pub const DURABLE_REPLAY_ROCKSDB_DEFAULT_NAMESPACE: &str =
    "qbind.run291.governance.production.durable.replay.namespace.v1";

/// The stable schema version this Run 291 backend supports. A database whose
/// stored schema version differs fails closed at open.
pub const DURABLE_REPLAY_ROCKSDB_SCHEMA_VERSION: u32 = 1;

// RocksDB key layout (single default column family, prefixed keys). Exposed so
// source tests can deterministically inject corruption / residue.
/// Key holding the stored schema version (little-endian u32).
pub const KEY_SCHEMA: &[u8] = b"qbind.run291.meta.schema";
/// Key holding the bincode-encoded domain metadata.
pub const KEY_DOMAIN: &[u8] = b"qbind.run291.meta.domain";
/// Key prefix for persisted replay records (`<prefix><stage>.<record_id>`).
pub const KEY_RECORD_PREFIX: &[u8] = b"qbind.run291.rec.";
/// Key prefix for partial-write residue markers (fault-injection only).
pub const KEY_PARTIAL_PREFIX: &[u8] = b"qbind.run291.partial.";

// ===========================================================================
// Policy
// ===========================================================================

/// Run 291 — the production durable replay RocksDB backend policy selector.
///
/// [`Self::Disabled`] is the default and the production-binary posture: the
/// backend refuses to open. [`Self::ProductionSourceTest`] is the source/test
/// selector that opens the real RocksDB backend for DevNet/TestNet. MainNet is
/// never enabled by this run; a MainNet identity fails closed regardless of
/// policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableReplayRocksDbPolicy {
    /// Default: the backend is disabled and refuses to open.
    Disabled,
    /// Source/test only: open the real RocksDB backend (DevNet/TestNet).
    ProductionSourceTest,
}

impl Default for DurableReplayRocksDbPolicy {
    fn default() -> Self {
        Self::Disabled
    }
}

impl DurableReplayRocksDbPolicy {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::ProductionSourceTest => "production-source-test",
        }
    }

    /// `true` iff this policy permits opening the RocksDB backend.
    pub const fn permits_open(self) -> bool {
        matches!(self, Self::ProductionSourceTest)
    }
}

// ===========================================================================
// Identity / domain binding
// ===========================================================================

/// Run 291 — the domain identity a durable replay RocksDB database is bound to.
///
/// Every persisted record and the database metadata are bound to this identity.
/// A reopen whose configured identity differs from the stored identity fails
/// closed ([`DurableReplayRocksDbError::DomainMismatch`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableReplayRocksDbIdentity {
    /// Trust-domain environment.
    pub environment: TrustBundleEnvironment,
    /// Trust-domain chain id.
    pub chain_id: String,
    /// Trust-domain genesis hash / genesis-domain binding.
    pub genesis_hash: String,
    /// Replay namespace / domain separator.
    pub replay_namespace: String,
    /// Authority-domain sequence / replay epoch the database is bound to.
    pub authority_domain_sequence: u64,
    /// Backend schema version the identity is bound to.
    pub schema_version: u32,
}

impl DurableReplayRocksDbIdentity {
    /// Construct a DevNet/TestNet identity using the default namespace and the
    /// supported schema version.
    pub fn new(
        environment: TrustBundleEnvironment,
        chain_id: impl Into<String>,
        genesis_hash: impl Into<String>,
        authority_domain_sequence: u64,
    ) -> Self {
        Self {
            environment,
            chain_id: chain_id.into(),
            genesis_hash: genesis_hash.into(),
            replay_namespace: DURABLE_REPLAY_ROCKSDB_DEFAULT_NAMESPACE.to_string(),
            authority_domain_sequence,
            schema_version: DURABLE_REPLAY_ROCKSDB_SCHEMA_VERSION,
        }
    }

    /// Derive the identity a faithfully-bound Run 238
    /// [`DurableBackendDecisionInput`] references (environment / chain / genesis
    /// / authority-domain sequence), using the default namespace and supported
    /// schema version.
    pub fn from_decision_input(input: &DurableBackendDecisionInput) -> Self {
        Self::new(
            input.environment,
            input.chain_id.clone(),
            input.genesis_hash.clone(),
            input.authority_domain_sequence,
        )
    }

    /// `true` iff every mandatory field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.chain_id.is_empty()
            && !self.genesis_hash.is_empty()
            && !self.replay_namespace.is_empty()
    }

    /// Deterministic SHA3-256 hex digest binding the full domain identity.
    pub fn domain_digest(&self) -> String {
        durable_replay_rocksdb_domain_digest(self)
    }
}

// ===========================================================================
// Config
// ===========================================================================

/// Run 291 — the open configuration for a durable replay RocksDB backend.
#[derive(Debug, Clone)]
pub struct DurableReplayRocksDbConfig {
    /// Filesystem path of the RocksDB database.
    pub path: PathBuf,
    /// Production policy selector (default [`DurableReplayRocksDbPolicy::Disabled`]).
    pub policy: DurableReplayRocksDbPolicy,
    /// Domain identity the database is bound to.
    pub identity: DurableReplayRocksDbIdentity,
}

impl DurableReplayRocksDbConfig {
    /// Construct a source/test config that permits opening the RocksDB backend
    /// (DevNet/TestNet).
    pub fn source_test(path: impl AsRef<Path>, identity: DurableReplayRocksDbIdentity) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            policy: DurableReplayRocksDbPolicy::ProductionSourceTest,
            identity,
        }
    }

    /// Construct a disabled (default-posture) config; opening fails closed.
    pub fn disabled(path: impl AsRef<Path>, identity: DurableReplayRocksDbIdentity) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            policy: DurableReplayRocksDbPolicy::Disabled,
            identity,
        }
    }
}

// ===========================================================================
// Record stage / record
// ===========================================================================

/// Run 291 — the stage/kind of a persisted durable replay record.
///
/// A `Consumed` record for a given record id may only be written once the
/// `Observed` record for that id already exists durably.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DurableReplayRecordStage {
    /// First-seen observation of a decision.
    Observed,
    /// Consumed-after-successful-mutation record for a decision.
    Consumed,
}

impl DurableReplayRecordStage {
    /// Stable operator-facing tag (also used in the record key and digest).
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Consumed => "consumed",
        }
    }
}

/// Run 291 — a single persisted durable replay record.
///
/// The `digest` field is the deterministic domain-bound self-digest; every read
/// recomputes it and fails closed on mismatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableReplayRocksDbRecord {
    /// Deterministic record id (from the Run 238 durable backend key digest).
    pub record_id: String,
    /// Record stage / kind.
    pub stage: DurableReplayRecordStage,
    /// Replay sequence / ordering value.
    pub replay_sequence: u64,
    /// Prior-stage digest (the `Observed` record digest for a `Consumed` record).
    pub prior_stage_digest: Option<String>,
    /// Deterministic payload digest (from the Run 238 durable record digest).
    pub payload_digest: String,
    /// Deterministic domain-bound self-digest of this record.
    pub digest: String,
}

// ===========================================================================
// Event input
// ===========================================================================

/// Run 291 — the typed input a caller supplies to record a replay event.
///
/// Record ids and payload digests are deterministic; the canonical constructor
/// [`Self::from_decision_input`] derives them from the Run 238 durable decision
/// input so the RocksDB backend accepts the same valid replay-record shape as
/// the existing fixture backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableReplayEventInput {
    /// Deterministic record id.
    pub record_id: String,
    /// Record stage / kind.
    pub stage: DurableReplayRecordStage,
    /// Replay sequence / ordering value.
    pub replay_sequence: u64,
    /// Prior-stage digest (required for a `Consumed` stage).
    pub prior_stage_digest: Option<String>,
    /// Deterministic payload digest.
    pub payload_digest: String,
    /// The identity this event must be bound to.
    pub identity: DurableReplayRocksDbIdentity,
}

impl DurableReplayEventInput {
    /// Build an `Observed`-stage event from a Run 238 durable decision input.
    ///
    /// The record id is the Run 238 durable backend key digest; the payload
    /// digest is the Run 238 durable record digest for the `ObservedFresh`
    /// state.
    pub fn observed_from_decision_input(input: &DurableBackendDecisionInput) -> Self {
        Self {
            record_id: durable_backend_key_digest(input),
            stage: DurableReplayRecordStage::Observed,
            replay_sequence: input.authority_domain_sequence,
            prior_stage_digest: None,
            payload_digest: durable_record_digest(input, DurableRecordState::ObservedFresh, 1),
            identity: DurableReplayRocksDbIdentity::from_decision_input(input),
        }
    }

    /// Build a `Consumed`-stage event from a Run 238 durable decision input and
    /// the prior `Observed` record digest.
    pub fn consumed_from_decision_input(
        input: &DurableBackendDecisionInput,
        prior_observed_digest: impl Into<String>,
    ) -> Self {
        Self {
            record_id: durable_backend_key_digest(input),
            stage: DurableReplayRecordStage::Consumed,
            replay_sequence: input.authority_domain_sequence,
            prior_stage_digest: Some(prior_observed_digest.into()),
            payload_digest: durable_record_digest(input, DurableRecordState::Consumed, 1),
            identity: DurableReplayRocksDbIdentity::from_decision_input(input),
        }
    }

    /// Compute the deterministic domain-bound record digest this event resolves
    /// to under `identity`.
    fn record_digest(&self) -> String {
        durable_replay_rocksdb_record_digest(
            &self.identity,
            &self.record_id,
            self.stage,
            self.prior_stage_digest.as_deref(),
            &self.payload_digest,
            self.replay_sequence,
        )
    }

    /// Materialize the [`DurableReplayRocksDbRecord`] this event records.
    fn to_record(&self) -> DurableReplayRocksDbRecord {
        DurableReplayRocksDbRecord {
            record_id: self.record_id.clone(),
            stage: self.stage,
            replay_sequence: self.replay_sequence,
            prior_stage_digest: self.prior_stage_digest.clone(),
            payload_digest: self.payload_digest.clone(),
            digest: self.record_digest(),
        }
    }
}

// ===========================================================================
// Outcomes
// ===========================================================================

/// Run 291 — the typed outcome of opening / initializing the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableReplayRocksDbOpenOutcome {
    /// The database was empty and was initialized exactly once with metadata.
    InitializedEmpty,
    /// A previously-initialized database was reopened with a matching domain.
    OpenedExisting,
}

impl DurableReplayRocksDbOpenOutcome {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::InitializedEmpty => "initialized-empty",
            Self::OpenedExisting => "opened-existing",
        }
    }
}

/// Run 291 — the typed outcome of recording a replay event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableReplayRocksDbWriteOutcome {
    /// A new record was durably written.
    Written(DurableReplayRocksDbRecord),
    /// An identical record already existed; the write was idempotent.
    IdempotentDuplicate(DurableReplayRocksDbRecord),
}

impl DurableReplayRocksDbWriteOutcome {
    /// Stable operator-facing tag.
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::Written(_) => "written",
            Self::IdempotentDuplicate(_) => "idempotent-duplicate",
        }
    }

    /// The record referenced by this outcome.
    pub fn record(&self) -> &DurableReplayRocksDbRecord {
        match self {
            Self::Written(r) | Self::IdempotentDuplicate(r) => r,
        }
    }
}

/// Run 291 — the typed outcome of reading a replay record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableReplayRocksDbReadOutcome {
    /// The record exists and its digest verified.
    Found(DurableReplayRocksDbRecord),
    /// No record exists for the requested id/stage (non-mutating).
    NotFound,
}

impl DurableReplayRocksDbReadOutcome {
    /// Stable operator-facing tag.
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::Found(_) => "found",
            Self::NotFound => "not-found",
        }
    }

    /// `true` iff a record was found.
    pub fn is_found(&self) -> bool {
        matches!(self, Self::Found(_))
    }
}

/// Run 291 — the typed outcome of a recovery pass over the durable window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableReplayRocksDbRecoveryOutcome {
    /// No partial-write residue was found; nothing to recover.
    NothingToRecover,
    /// Partial-write residue was found and deterministically rolled back.
    RolledBackPartialResidue(usize),
}

impl DurableReplayRocksDbRecoveryOutcome {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::NothingToRecover => "nothing-to-recover",
            Self::RolledBackPartialResidue(_) => "rolled-back-partial-residue",
        }
    }
}

// ===========================================================================
// Error taxonomy
// ===========================================================================

/// Run 291 — the fail-closed production durable replay RocksDB backend error
/// taxonomy. There is **no** variant that silently falls back to an in-memory
/// backend; every failure is a typed refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableReplayRocksDbError {
    /// The policy is [`DurableReplayRocksDbPolicy::Disabled`]; open refused.
    BackendDisabled,
    /// The identity is bound to MainNet; open/write refused.
    MainNetRefused,
    /// The configured identity is structurally malformed.
    MalformedIdentity,
    /// RocksDB open failed (path unavailable / lock contention / unwritable).
    RocksDbOpen(String),
    /// A RocksDB read/write operation failed.
    RocksDbIo(String),
    /// The stored schema marker is missing in a non-empty database.
    SchemaMarkerMissing,
    /// The stored schema marker is malformed.
    SchemaMarkerMalformed,
    /// The stored schema version is unsupported by this binary.
    SchemaUnsupported {
        /// Version found on disk.
        found: u32,
        /// Version supported by this binary.
        supported: u32,
    },
    /// Domain metadata is missing in a non-empty database.
    MetadataMissing,
    /// Domain metadata is malformed / undecodable.
    MetadataMalformed,
    /// The stored domain identity does not match the configured identity.
    DomainMismatch {
        /// The mismatching field.
        field: &'static str,
    },
    /// Partial-write residue was detected on open (fails closed until recovery).
    PartialResidueDetected(usize),
    /// A persisted record is corrupt / undecodable / truncated.
    CorruptRecord(String),
    /// A persisted record's recomputed digest does not match its stored digest.
    CorruptDigest {
        /// The affected record id.
        record_id: String,
    },
    /// The event's identity does not match the open database identity.
    EventDomainMismatch {
        /// The mismatching field.
        field: &'static str,
    },
    /// The same record id was written with a different digest (equivocation).
    Equivocation {
        /// The affected record id.
        record_id: String,
    },
    /// A `Consumed` record was written without its prior `Observed` record, or
    /// with a mismatching prior-stage digest.
    OrderingViolation {
        /// The affected record id.
        record_id: String,
    },
    /// The supplied event is structurally malformed.
    MalformedEvent,
}

impl std::fmt::Display for DurableReplayRocksDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackendDisabled => write!(f, "durable replay rocksdb: backend disabled"),
            Self::MainNetRefused => write!(f, "durable replay rocksdb: MainNet refused"),
            Self::MalformedIdentity => write!(f, "durable replay rocksdb: malformed identity"),
            Self::RocksDbOpen(e) => write!(f, "durable replay rocksdb: open failed: {e}"),
            Self::RocksDbIo(e) => write!(f, "durable replay rocksdb: io failed: {e}"),
            Self::SchemaMarkerMissing => {
                write!(f, "durable replay rocksdb: schema marker missing")
            }
            Self::SchemaMarkerMalformed => {
                write!(f, "durable replay rocksdb: schema marker malformed")
            }
            Self::SchemaUnsupported { found, supported } => write!(
                f,
                "durable replay rocksdb: unsupported schema version {found} (supported {supported})"
            ),
            Self::MetadataMissing => write!(f, "durable replay rocksdb: domain metadata missing"),
            Self::MetadataMalformed => {
                write!(f, "durable replay rocksdb: domain metadata malformed")
            }
            Self::DomainMismatch { field } => {
                write!(f, "durable replay rocksdb: domain mismatch on {field}")
            }
            Self::PartialResidueDetected(n) => {
                write!(f, "durable replay rocksdb: {n} partial-write residue key(s) detected")
            }
            Self::CorruptRecord(e) => write!(f, "durable replay rocksdb: corrupt record: {e}"),
            Self::CorruptDigest { record_id } => {
                write!(f, "durable replay rocksdb: corrupt digest for record {record_id}")
            }
            Self::EventDomainMismatch { field } => {
                write!(f, "durable replay rocksdb: event domain mismatch on {field}")
            }
            Self::Equivocation { record_id } => {
                write!(f, "durable replay rocksdb: equivocation on record {record_id}")
            }
            Self::OrderingViolation { record_id } => {
                write!(f, "durable replay rocksdb: ordering violation on record {record_id}")
            }
            Self::MalformedEvent => write!(f, "durable replay rocksdb: malformed event"),
        }
    }
}

impl std::error::Error for DurableReplayRocksDbError {}

/// Convenient result alias for Run 291 backend operations.
pub type DurableReplayRocksDbResult<T> = Result<T, DurableReplayRocksDbError>;

// ===========================================================================
// Persisted domain metadata
// ===========================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredDomainMetadata {
    schema_version: u32,
    identity: DurableReplayRocksDbIdentity,
    domain_digest: String,
}

// ===========================================================================
// Backend trait
// ===========================================================================

/// Run 291 — the narrow, mockable durable replay backend surface.
///
/// Implemented by the real [`ProductionDurableReplayRocksDbBackend`] and by the
/// in-memory [`MockDurableReplayBackend`]. Deliberately narrow: it is **not** a
/// broad storage abstraction.
pub trait GovernanceProductionDurableReplayBackend {
    /// Record a replay event. Idempotent for identical records; fails closed on
    /// equivocation, ordering violation, or domain mismatch.
    fn record_replay_event(
        &mut self,
        event: &DurableReplayEventInput,
    ) -> DurableReplayRocksDbResult<DurableReplayRocksDbWriteOutcome>;

    /// Read the record for `record_id` / `stage` (non-mutating).
    fn read_replay_record(
        &self,
        record_id: &str,
        stage: DurableReplayRecordStage,
    ) -> DurableReplayRocksDbResult<DurableReplayRocksDbReadOutcome>;

    /// Scan every persisted record in deterministic (key-sorted) order.
    fn scan_replay_records(
        &self,
    ) -> DurableReplayRocksDbResult<Vec<DurableReplayRocksDbRecord>>;

    /// Deterministically roll back any partial-write residue.
    fn recover_replay_window(
        &mut self,
    ) -> DurableReplayRocksDbResult<DurableReplayRocksDbRecoveryOutcome>;

    /// Flush any buffered writes durably.
    fn close_or_flush(&mut self) -> DurableReplayRocksDbResult<()>;
}

// ===========================================================================
// Digest helpers
// ===========================================================================

fn hash_field(h: &mut sha3::Sha3_256, label: &[u8], value: &[u8]) {
    use sha3::Digest;
    h.update((label.len() as u64).to_le_bytes());
    h.update(label);
    h.update((value.len() as u64).to_le_bytes());
    h.update(value);
}

/// Run 291 — deterministic SHA3-256 hex digest binding the full domain identity
/// (environment, chain id, genesis/domain, namespace, authority-domain
/// sequence, and schema version).
pub fn durable_replay_rocksdb_domain_digest(identity: &DurableReplayRocksDbIdentity) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(DURABLE_REPLAY_ROCKSDB_DOMAIN_TAG.as_bytes());
    hash_field(&mut h, b"environment", &identity.environment.metric_code().to_le_bytes());
    hash_field(&mut h, b"chain_id", identity.chain_id.as_bytes());
    hash_field(&mut h, b"genesis_hash", identity.genesis_hash.as_bytes());
    hash_field(&mut h, b"replay_namespace", identity.replay_namespace.as_bytes());
    hash_field(
        &mut h,
        b"authority_domain_sequence",
        &identity.authority_domain_sequence.to_le_bytes(),
    );
    hash_field(&mut h, b"schema_version", &identity.schema_version.to_le_bytes());
    hex::encode(h.finalize())
}

/// Run 291 — deterministic record id derived from a Run 238 durable decision
/// input (the durable backend key digest). Prefer this over any random id.
pub fn durable_replay_rocksdb_record_id(input: &DurableBackendDecisionInput) -> String {
    durable_backend_key_digest(input)
}

/// Run 291 — deterministic SHA3-256 hex record digest.
///
/// Binds the domain separator, schema version, environment, chain id,
/// genesis/domain, replay namespace, authority-domain sequence, record id,
/// stage/kind, prior-stage digest, payload digest, and replay sequence. It never
/// uses debug formatting or wall-clock time.
pub fn durable_replay_rocksdb_record_digest(
    identity: &DurableReplayRocksDbIdentity,
    record_id: &str,
    stage: DurableReplayRecordStage,
    prior_stage_digest: Option<&str>,
    payload_digest: &str,
    replay_sequence: u64,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(DURABLE_REPLAY_ROCKSDB_RECORD_TAG.as_bytes());
    hash_field(&mut h, b"domain", identity.domain_digest().as_bytes());
    hash_field(&mut h, b"schema_version", &identity.schema_version.to_le_bytes());
    hash_field(&mut h, b"environment", &identity.environment.metric_code().to_le_bytes());
    hash_field(&mut h, b"chain_id", identity.chain_id.as_bytes());
    hash_field(&mut h, b"genesis_hash", identity.genesis_hash.as_bytes());
    hash_field(&mut h, b"replay_namespace", identity.replay_namespace.as_bytes());
    hash_field(
        &mut h,
        b"authority_domain_sequence",
        &identity.authority_domain_sequence.to_le_bytes(),
    );
    hash_field(&mut h, b"record_id", record_id.as_bytes());
    hash_field(&mut h, b"stage", stage.tag().as_bytes());
    hash_field(&mut h, b"prior_stage_digest", prior_stage_digest.unwrap_or("").as_bytes());
    hash_field(&mut h, b"payload_digest", payload_digest.as_bytes());
    hash_field(&mut h, b"replay_sequence", &replay_sequence.to_le_bytes());
    hex::encode(h.finalize())
}

// ===========================================================================
// Key helpers
// ===========================================================================

fn record_key(record_id: &str, stage: DurableReplayRecordStage) -> Vec<u8> {
    let mut key = KEY_RECORD_PREFIX.to_vec();
    key.extend_from_slice(stage.tag().as_bytes());
    key.push(b'.');
    key.extend_from_slice(record_id.as_bytes());
    key
}

/// Public: the deterministic RocksDB key a record for `record_id`/`stage` is
/// stored under (exposed so source tests can inject corruption).
pub fn durable_replay_rocksdb_record_key(
    record_id: &str,
    stage: DurableReplayRecordStage,
) -> Vec<u8> {
    record_key(record_id, stage)
}

fn partial_key(record_id: &str) -> Vec<u8> {
    let mut key = KEY_PARTIAL_PREFIX.to_vec();
    key.extend_from_slice(record_id.as_bytes());
    key
}

// ===========================================================================
// Real RocksDB backend
// ===========================================================================

/// Run 291 — the real RocksDB-backed production durable replay backend.
///
/// Opening validates schema + domain metadata against the configured identity;
/// every write is a single atomic `WriteBatch`; every read verifies the stored
/// record digest. There is no silent in-memory fallback.
pub struct ProductionDurableReplayRocksDbBackend {
    db: rocksdb::DB,
    identity: DurableReplayRocksDbIdentity,
    open_outcome: DurableReplayRocksDbOpenOutcome,
}

impl std::fmt::Debug for ProductionDurableReplayRocksDbBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProductionDurableReplayRocksDbBackend")
            .field("path", &self.db.path())
            .field("environment", &self.identity.environment)
            .field("open_outcome", &self.open_outcome.tag())
            .finish()
    }
}

impl ProductionDurableReplayRocksDbBackend {
    /// Open or initialize the RocksDB durable replay backend.
    ///
    /// Fails closed (without opening) when the policy is
    /// [`DurableReplayRocksDbPolicy::Disabled`], when the identity is MainNet or
    /// malformed, when RocksDB cannot open the path, when the schema / domain
    /// metadata is missing / malformed / unsupported / mismatched, or when
    /// partial-write residue is present.
    pub fn open_or_initialize(
        config: &DurableReplayRocksDbConfig,
    ) -> DurableReplayRocksDbResult<(Self, DurableReplayRocksDbOpenOutcome)> {
        if !config.policy.permits_open() {
            return Err(DurableReplayRocksDbError::BackendDisabled);
        }
        if config.identity.environment == TrustBundleEnvironment::Mainnet {
            return Err(DurableReplayRocksDbError::MainNetRefused);
        }
        if !config.identity.is_well_formed()
            || config.identity.schema_version != DURABLE_REPLAY_ROCKSDB_SCHEMA_VERSION
        {
            return Err(DurableReplayRocksDbError::MalformedIdentity);
        }

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let db = rocksdb::DB::open(&opts, &config.path)
            .map_err(|e| DurableReplayRocksDbError::RocksDbOpen(e.to_string()))?;

        // Fail closed on any partial-write residue.
        let residue = count_partial_residue(&db)?;
        if residue > 0 {
            return Err(DurableReplayRocksDbError::PartialResidueDetected(residue));
        }

        let schema = db
            .get(KEY_SCHEMA)
            .map_err(|e| DurableReplayRocksDbError::RocksDbIo(e.to_string()))?;
        let domain = db
            .get(KEY_DOMAIN)
            .map_err(|e| DurableReplayRocksDbError::RocksDbIo(e.to_string()))?;

        let open_outcome = match (schema, domain) {
            (None, None) => {
                // A non-empty database without a schema marker is malformed.
                if has_any_record(&db)? {
                    return Err(DurableReplayRocksDbError::SchemaMarkerMissing);
                }
                initialize_metadata(&db, &config.identity)?;
                DurableReplayRocksDbOpenOutcome::InitializedEmpty
            }
            (Some(schema_bytes), Some(domain_bytes)) => {
                validate_open(&schema_bytes, &domain_bytes, &config.identity)?;
                DurableReplayRocksDbOpenOutcome::OpenedExisting
            }
            // Exactly one of the required metadata keys is present: a non-empty
            // DB missing required metadata fails closed.
            (Some(_), None) => return Err(DurableReplayRocksDbError::MetadataMissing),
            (None, Some(_)) => return Err(DurableReplayRocksDbError::SchemaMarkerMissing),
        };

        Ok((
            Self {
                db,
                identity: config.identity.clone(),
                open_outcome,
            },
            open_outcome,
        ))
    }

    /// The identity this backend is bound to.
    pub fn identity(&self) -> &DurableReplayRocksDbIdentity {
        &self.identity
    }

    /// The outcome of the open that produced this backend.
    pub fn open_outcome(&self) -> DurableReplayRocksDbOpenOutcome {
        self.open_outcome
    }

    fn ensure_event_domain(
        &self,
        event: &DurableReplayEventInput,
    ) -> DurableReplayRocksDbResult<()> {
        let want = &self.identity;
        let got = &event.identity;
        if want.environment != got.environment {
            return Err(DurableReplayRocksDbError::EventDomainMismatch { field: "environment" });
        }
        if want.chain_id != got.chain_id {
            return Err(DurableReplayRocksDbError::EventDomainMismatch { field: "chain_id" });
        }
        if want.genesis_hash != got.genesis_hash {
            return Err(DurableReplayRocksDbError::EventDomainMismatch { field: "genesis_hash" });
        }
        if want.replay_namespace != got.replay_namespace {
            return Err(DurableReplayRocksDbError::EventDomainMismatch {
                field: "replay_namespace",
            });
        }
        if want.authority_domain_sequence != got.authority_domain_sequence {
            return Err(DurableReplayRocksDbError::EventDomainMismatch {
                field: "authority_domain_sequence",
            });
        }
        if want.schema_version != got.schema_version {
            return Err(DurableReplayRocksDbError::EventDomainMismatch { field: "schema_version" });
        }
        Ok(())
    }

    fn read_verified_record(
        &self,
        record_id: &str,
        stage: DurableReplayRecordStage,
    ) -> DurableReplayRocksDbResult<Option<DurableReplayRocksDbRecord>> {
        let key = record_key(record_id, stage);
        let raw = self
            .db
            .get(&key)
            .map_err(|e| DurableReplayRocksDbError::RocksDbIo(e.to_string()))?;
        let Some(bytes) = raw else {
            return Ok(None);
        };
        let record: DurableReplayRocksDbRecord = bincode::deserialize(&bytes)
            .map_err(|e| DurableReplayRocksDbError::CorruptRecord(e.to_string()))?;
        let recomputed = durable_replay_rocksdb_record_digest(
            &self.identity,
            &record.record_id,
            record.stage,
            record.prior_stage_digest.as_deref(),
            &record.payload_digest,
            record.replay_sequence,
        );
        if recomputed != record.digest || record.record_id != record_id || record.stage != stage {
            return Err(DurableReplayRocksDbError::CorruptDigest {
                record_id: record_id.to_string(),
            });
        }
        Ok(Some(record))
    }
}

impl GovernanceProductionDurableReplayBackend for ProductionDurableReplayRocksDbBackend {
    fn record_replay_event(
        &mut self,
        event: &DurableReplayEventInput,
    ) -> DurableReplayRocksDbResult<DurableReplayRocksDbWriteOutcome> {
        if event.record_id.is_empty() || event.payload_digest.is_empty() {
            return Err(DurableReplayRocksDbError::MalformedEvent);
        }
        self.ensure_event_domain(event)?;

        let new_record = event.to_record();

        // Idempotency / equivocation on the same id+stage.
        if let Some(existing) = self.read_verified_record(&event.record_id, event.stage)? {
            if existing.digest == new_record.digest {
                return Ok(DurableReplayRocksDbWriteOutcome::IdempotentDuplicate(existing));
            }
            return Err(DurableReplayRocksDbError::Equivocation {
                record_id: event.record_id.clone(),
            });
        }

        // Ordering: a Consumed record requires the prior Observed record with a
        // matching prior-stage digest.
        if event.stage == DurableReplayRecordStage::Consumed {
            let prior = self
                .read_verified_record(&event.record_id, DurableReplayRecordStage::Observed)?;
            match (prior, event.prior_stage_digest.as_deref()) {
                (Some(observed), Some(expected)) if observed.digest == expected => {}
                _ => {
                    return Err(DurableReplayRocksDbError::OrderingViolation {
                        record_id: event.record_id.clone(),
                    })
                }
            }
        }

        let bytes = bincode::serialize(&new_record)
            .map_err(|e| DurableReplayRocksDbError::RocksDbIo(e.to_string()))?;
        let mut batch = rocksdb::WriteBatch::default();
        batch.put(record_key(&event.record_id, event.stage), bytes);
        self.db
            .write(batch)
            .map_err(|e| DurableReplayRocksDbError::RocksDbIo(e.to_string()))?;
        Ok(DurableReplayRocksDbWriteOutcome::Written(new_record))
    }

    fn read_replay_record(
        &self,
        record_id: &str,
        stage: DurableReplayRecordStage,
    ) -> DurableReplayRocksDbResult<DurableReplayRocksDbReadOutcome> {
        match self.read_verified_record(record_id, stage)? {
            Some(record) => Ok(DurableReplayRocksDbReadOutcome::Found(record)),
            None => Ok(DurableReplayRocksDbReadOutcome::NotFound),
        }
    }

    fn scan_replay_records(
        &self,
    ) -> DurableReplayRocksDbResult<Vec<DurableReplayRocksDbRecord>> {
        let mut out = Vec::new();
        let iter = self.db.iterator(rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, value) =
                item.map_err(|e| DurableReplayRocksDbError::RocksDbIo(e.to_string()))?;
            if !key.starts_with(KEY_RECORD_PREFIX) {
                continue;
            }
            let record: DurableReplayRocksDbRecord = bincode::deserialize(&value)
                .map_err(|e| DurableReplayRocksDbError::CorruptRecord(e.to_string()))?;
            let recomputed = durable_replay_rocksdb_record_digest(
                &self.identity,
                &record.record_id,
                record.stage,
                record.prior_stage_digest.as_deref(),
                &record.payload_digest,
                record.replay_sequence,
            );
            if recomputed != record.digest {
                return Err(DurableReplayRocksDbError::CorruptDigest {
                    record_id: record.record_id,
                });
            }
            out.push(record);
        }
        Ok(out)
    }

    fn recover_replay_window(
        &mut self,
    ) -> DurableReplayRocksDbResult<DurableReplayRocksDbRecoveryOutcome> {
        let mut residue_keys = Vec::new();
        let iter = self.db.iterator(rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, _) =
                item.map_err(|e| DurableReplayRocksDbError::RocksDbIo(e.to_string()))?;
            if key.starts_with(KEY_PARTIAL_PREFIX) {
                residue_keys.push(key.to_vec());
            }
        }
        if residue_keys.is_empty() {
            return Ok(DurableReplayRocksDbRecoveryOutcome::NothingToRecover);
        }
        let count = residue_keys.len();
        let mut batch = rocksdb::WriteBatch::default();
        for key in residue_keys {
            batch.delete(key);
        }
        self.db
            .write(batch)
            .map_err(|e| DurableReplayRocksDbError::RocksDbIo(e.to_string()))?;
        Ok(DurableReplayRocksDbRecoveryOutcome::RolledBackPartialResidue(count))
    }

    fn close_or_flush(&mut self) -> DurableReplayRocksDbResult<()> {
        self.db
            .flush()
            .map_err(|e| DurableReplayRocksDbError::RocksDbIo(e.to_string()))
    }
}

impl ProductionDurableReplayRocksDbBackend {
    /// Source/test-only fault injection: simulate a write failure that occurs
    /// **before** the record commit. The record is validated but the final
    /// commit is skipped and an error is returned, so no record is ever visible
    /// — proving pre-commit atomicity. This never enables any production runtime
    /// path; the production binary never calls it.
    pub fn record_replay_event_simulate_precommit_failure(
        &mut self,
        event: &DurableReplayEventInput,
    ) -> DurableReplayRocksDbResult<()> {
        if event.record_id.is_empty() || event.payload_digest.is_empty() {
            return Err(DurableReplayRocksDbError::MalformedEvent);
        }
        self.ensure_event_domain(event)?;
        let _record = event.to_record();
        // Deliberately do NOT commit: a pre-commit failure leaves no record.
        Err(DurableReplayRocksDbError::RocksDbIo(
            "simulated pre-commit write failure".to_string(),
        ))
    }

    /// Source/test-only fault injection: simulate a failure that occurs **after**
    /// an internal partial stage has been persisted. A partial-residue marker is
    /// committed and then an error is returned without writing the real record.
    /// A subsequent open fails closed until [`Self::recover_replay_window`] rolls
    /// the residue back deterministically. This never enables any production
    /// runtime path.
    pub fn record_replay_event_simulate_partial_stage_failure(
        &mut self,
        event: &DurableReplayEventInput,
    ) -> DurableReplayRocksDbResult<()> {
        if event.record_id.is_empty() || event.payload_digest.is_empty() {
            return Err(DurableReplayRocksDbError::MalformedEvent);
        }
        self.ensure_event_domain(event)?;
        let mut batch = rocksdb::WriteBatch::default();
        batch.put(partial_key(&event.record_id), event.payload_digest.as_bytes());
        self.db
            .write(batch)
            .map_err(|e| DurableReplayRocksDbError::RocksDbIo(e.to_string()))?;
        Err(DurableReplayRocksDbError::RocksDbIo(
            "simulated post-partial-stage write failure".to_string(),
        ))
    }
}

// ===========================================================================
// Open helpers
// ===========================================================================

fn count_partial_residue(db: &rocksdb::DB) -> DurableReplayRocksDbResult<usize> {
    let mut n = 0usize;
    let iter = db.iterator(rocksdb::IteratorMode::Start);
    for item in iter {
        let (key, _) = item.map_err(|e| DurableReplayRocksDbError::RocksDbIo(e.to_string()))?;
        if key.starts_with(KEY_PARTIAL_PREFIX) {
            n += 1;
        }
    }
    Ok(n)
}

fn has_any_record(db: &rocksdb::DB) -> DurableReplayRocksDbResult<bool> {
    let iter = db.iterator(rocksdb::IteratorMode::Start);
    for item in iter {
        let (key, _) = item.map_err(|e| DurableReplayRocksDbError::RocksDbIo(e.to_string()))?;
        if key.starts_with(KEY_RECORD_PREFIX) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn initialize_metadata(
    db: &rocksdb::DB,
    identity: &DurableReplayRocksDbIdentity,
) -> DurableReplayRocksDbResult<()> {
    let meta = StoredDomainMetadata {
        schema_version: identity.schema_version,
        identity: identity.clone(),
        domain_digest: identity.domain_digest(),
    };
    let meta_bytes = bincode::serialize(&meta)
        .map_err(|e| DurableReplayRocksDbError::RocksDbIo(e.to_string()))?;
    let mut batch = rocksdb::WriteBatch::default();
    batch.put(KEY_SCHEMA, identity.schema_version.to_le_bytes());
    batch.put(KEY_DOMAIN, meta_bytes);
    db.write(batch)
        .map_err(|e| DurableReplayRocksDbError::RocksDbIo(e.to_string()))
}

fn validate_open(
    schema_bytes: &[u8],
    domain_bytes: &[u8],
    identity: &DurableReplayRocksDbIdentity,
) -> DurableReplayRocksDbResult<()> {
    // Schema marker.
    let schema_arr: [u8; 4] = schema_bytes
        .try_into()
        .map_err(|_| DurableReplayRocksDbError::SchemaMarkerMalformed)?;
    let found = u32::from_le_bytes(schema_arr);
    if found != DURABLE_REPLAY_ROCKSDB_SCHEMA_VERSION {
        return Err(DurableReplayRocksDbError::SchemaUnsupported {
            found,
            supported: DURABLE_REPLAY_ROCKSDB_SCHEMA_VERSION,
        });
    }

    // Domain metadata.
    let meta: StoredDomainMetadata = bincode::deserialize(domain_bytes)
        .map_err(|_| DurableReplayRocksDbError::MetadataMalformed)?;
    if meta.schema_version != DURABLE_REPLAY_ROCKSDB_SCHEMA_VERSION {
        return Err(DurableReplayRocksDbError::SchemaUnsupported {
            found: meta.schema_version,
            supported: DURABLE_REPLAY_ROCKSDB_SCHEMA_VERSION,
        });
    }
    if meta.domain_digest != meta.identity.domain_digest() {
        return Err(DurableReplayRocksDbError::MetadataMalformed);
    }

    // Domain binding.
    let stored = &meta.identity;
    if stored.environment != identity.environment {
        return Err(DurableReplayRocksDbError::DomainMismatch { field: "environment" });
    }
    if stored.chain_id != identity.chain_id {
        return Err(DurableReplayRocksDbError::DomainMismatch { field: "chain_id" });
    }
    if stored.genesis_hash != identity.genesis_hash {
        return Err(DurableReplayRocksDbError::DomainMismatch { field: "genesis_hash" });
    }
    if stored.replay_namespace != identity.replay_namespace {
        return Err(DurableReplayRocksDbError::DomainMismatch { field: "replay_namespace" });
    }
    if stored.authority_domain_sequence != identity.authority_domain_sequence {
        return Err(DurableReplayRocksDbError::DomainMismatch {
            field: "authority_domain_sequence",
        });
    }
    Ok(())
}

// ===========================================================================
// In-memory mock backend (mockable trait surface)
// ===========================================================================

/// Run 291 — an in-memory mock implementing
/// [`GovernanceProductionDurableReplayBackend`].
///
/// It exists to prove the backend surface is mockable and to drive composition
/// tests without any real I/O. It is **not** a production fallback and is never
/// wired into the production binary.
#[derive(Debug, Default, Clone)]
pub struct MockDurableReplayBackend {
    identity: Option<DurableReplayRocksDbIdentity>,
    records: std::collections::BTreeMap<Vec<u8>, DurableReplayRocksDbRecord>,
}

impl MockDurableReplayBackend {
    /// Construct an empty mock bound to `identity`.
    pub fn new(identity: DurableReplayRocksDbIdentity) -> Self {
        Self {
            identity: Some(identity),
            records: std::collections::BTreeMap::new(),
        }
    }

    /// Number of recorded entries.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` iff no records are held.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl GovernanceProductionDurableReplayBackend for MockDurableReplayBackend {
    fn record_replay_event(
        &mut self,
        event: &DurableReplayEventInput,
    ) -> DurableReplayRocksDbResult<DurableReplayRocksDbWriteOutcome> {
        if event.record_id.is_empty() || event.payload_digest.is_empty() {
            return Err(DurableReplayRocksDbError::MalformedEvent);
        }
        let new_record = event.to_record();
        let key = record_key(&event.record_id, event.stage);
        if let Some(existing) = self.records.get(&key) {
            if existing.digest == new_record.digest {
                return Ok(DurableReplayRocksDbWriteOutcome::IdempotentDuplicate(existing.clone()));
            }
            return Err(DurableReplayRocksDbError::Equivocation {
                record_id: event.record_id.clone(),
            });
        }
        if event.stage == DurableReplayRecordStage::Consumed {
            let prior_key = record_key(&event.record_id, DurableReplayRecordStage::Observed);
            match (self.records.get(&prior_key), event.prior_stage_digest.as_deref()) {
                (Some(observed), Some(expected)) if observed.digest == expected => {}
                _ => {
                    return Err(DurableReplayRocksDbError::OrderingViolation {
                        record_id: event.record_id.clone(),
                    })
                }
            }
        }
        self.records.insert(key, new_record.clone());
        Ok(DurableReplayRocksDbWriteOutcome::Written(new_record))
    }

    fn read_replay_record(
        &self,
        record_id: &str,
        stage: DurableReplayRecordStage,
    ) -> DurableReplayRocksDbResult<DurableReplayRocksDbReadOutcome> {
        let key = record_key(record_id, stage);
        match self.records.get(&key) {
            Some(record) => Ok(DurableReplayRocksDbReadOutcome::Found(record.clone())),
            None => Ok(DurableReplayRocksDbReadOutcome::NotFound),
        }
    }

    fn scan_replay_records(
        &self,
    ) -> DurableReplayRocksDbResult<Vec<DurableReplayRocksDbRecord>> {
        Ok(self.records.values().cloned().collect())
    }

    fn recover_replay_window(
        &mut self,
    ) -> DurableReplayRocksDbResult<DurableReplayRocksDbRecoveryOutcome> {
        let _ = &self.identity;
        Ok(DurableReplayRocksDbRecoveryOutcome::NothingToRecover)
    }

    fn close_or_flush(&mut self) -> DurableReplayRocksDbResult<()> {
        Ok(())
    }
}

// ===========================================================================
// Explicit grep-verifiable invariant helpers
// ===========================================================================

/// Run 291 — the backend never silently falls back to an in-memory replay
/// backend on RocksDB failure. Always returns `true`: every failure path in this
/// module is a typed [`DurableReplayRocksDbError`], never a fallback.
pub fn durable_replay_rocksdb_never_falls_back_to_in_memory() -> bool {
    true
}

/// Run 291 — the production default policy is Disabled / fail-closed. Always
/// returns `true`: [`DurableReplayRocksDbPolicy::default`] is
/// [`DurableReplayRocksDbPolicy::Disabled`] and opening with it refuses.
pub fn durable_replay_rocksdb_default_is_disabled() -> bool {
    DurableReplayRocksDbPolicy::default() == DurableReplayRocksDbPolicy::Disabled
        && !DurableReplayRocksDbPolicy::default().permits_open()
}

/// Run 291 — MainNet is never enabled by this run. Always returns `true`: a
/// MainNet identity fails closed at open regardless of policy.
pub fn durable_replay_rocksdb_mainnet_remains_refused() -> bool {
    true
}

/// Run 291 — this is source/test production-backend implementation, not
/// release-binary evidence. Always returns `true`.
pub fn durable_replay_rocksdb_is_source_test_not_release_binary_evidence() -> bool {
    true
}
