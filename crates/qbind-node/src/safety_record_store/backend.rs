//! Run 422 D7-D14 — the safety-specific RocksDB backend adapter.
//!
//! This backend is **disabled by default** and is **never instantiated on any
//! production startup / consensus / signing path**. It owns its own key
//! namespace (`safetyrec:`) and reuses the atomic-plus-sync publication pattern
//! demonstrated by `put_signing_record_and_metadata_synced`; it never routes
//! writes through the signing-journal or epoch APIs.
//!
//! Every handle attached to one [`SafetyBackend`] instance shares a single
//! write-serialization domain (`Arc<Mutex<..>>`), so there is exactly one
//! serialization domain per backend instance — not a per-handle advisory mutex.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use super::error::SafetyStoreError;
use crate::pqc_trust_bundle::TrustBundleEnvironment;
use crate::storage::signing_journal_crc32;

/// The metadata key (one per backend DB).
const META_KEY: &[u8] = b"safetyrec:meta:v1";
/// The authoritative-record key (record + embedded supporting material).
const RECORD_KEY: &[u8] = b"safetyrec:record:v1";

/// Component gating (§ 13.1). `Disabled` is the default and refuses to open;
/// `EnabledForTesting` is a **non-default**, test/isolation-only policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SafetyBackendPolicy {
    /// Default: the component refuses to open. Production selects this.
    #[default]
    Disabled,
    /// Non-default, test/isolation-only activation.
    EnabledForTesting,
}

/// Test-only injected-fault selector. Values are only ever set through the
/// cfg-gated [`SafetyBackend::set_inject`]; in production the field stays `0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectFault {
    /// No fault.
    None = 0,
    /// Refuse before the batch is submitted (no bytes written).
    FailBeforeSubmit = 1,
    /// The batch write itself returns an error (ambiguous: may or may not have
    /// reached stable storage).
    WriteErrors = 2,
    /// The batch write durably succeeds, but the caller is told the outcome is
    /// uncertain (success acknowledgement is lost after the durable write).
    UncertainAfterWrite = 3,
}

/// A shared serialization domain. The owned guard proves the single-writer
/// boundary is held for a check-then-write sequence. The inner field is private
/// so this type is **not** publicly constructible: a caller cannot fabricate a
/// `SerializationDomain` (or a guard over one) to forge ownership of a backend.
#[derive(Debug)]
pub struct SerializationDomain(());

/// The safety backend: an `Arc`-shared RocksDB handle plus the single
/// serialization domain shared by every attached handle.
#[derive(Clone)]
pub struct SafetyBackend {
    db: Arc<rocksdb::DB>,
    domain: Arc<Mutex<SerializationDomain>>,
    inject: Arc<AtomicU8>,
    /// Shared, in-process **effectiveness / acknowledgement** latch (§ 13.4 /
    /// § 13.5). A freshly opened backend starts **not effective** (`false`): a
    /// newly opened established store carries **no inherited acknowledgement
    /// knowledge**, so dependent O4 publication is blocked until a fresh
    /// durability acknowledgement is established by an acknowledged O1
    /// initialization or a successful O5 recovery. An ambiguous write error or
    /// an uncertain-but-durable outcome also clears it. It can never be inferred
    /// effective from readable bytes, and a reopen cannot bypass it. Observed by
    /// **every** attached handle.
    effective: Arc<AtomicBool>,
}

impl std::fmt::Debug for SafetyBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SafetyBackend")
            .field("inject", &self.inject.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl SafetyBackend {
    /// Open (creating if necessary) the safety backend at `path`.
    ///
    /// Refuses when the policy is `Disabled` (the default) or when the
    /// environment is MainNet; neither path is reachable from production because
    /// the component is never constructed there.
    pub fn open_or_initialize<P: AsRef<std::path::Path>>(
        path: P,
        policy: SafetyBackendPolicy,
        env: TrustBundleEnvironment,
    ) -> Result<Self, SafetyStoreError> {
        if policy == SafetyBackendPolicy::Disabled {
            return Err(SafetyStoreError::BackendDisabled);
        }
        if matches!(env, TrustBundleEnvironment::Mainnet) {
            return Err(SafetyStoreError::MainNetRefused);
        }
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let db = rocksdb::DB::open(&opts, path)
            .map_err(|e| SafetyStoreError::WriteFailed(format!("open: {e}")))?;
        Ok(SafetyBackend {
            db: Arc::new(db),
            domain: Arc::new(Mutex::new(SerializationDomain(()))),
            inject: Arc::new(AtomicU8::new(InjectFault::None as u8)),
            // A freshly opened backend is NOT effective: dependent O4 is blocked
            // until an acknowledged O1 or a successful O5 establishes a fresh
            // durability acknowledgement (§ 13.4 / § 13.5).
            effective: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Acquire the single shared serialization domain for a check-then-write
    /// sequence. Every attached handle contends on the same lock. Crate-internal:
    /// the guard is only ever produced for, and consumed by, this backend's own
    /// enforced operations.
    pub(crate) fn lock_domain(&self) -> MutexGuard<'_, SerializationDomain> {
        self.domain
            .lock()
            .expect("safety serialization domain poisoned")
    }

    /// Read the raw (CRC-verified) metadata bytes, if present.
    pub fn read_meta(&self) -> Result<Option<Vec<u8>>, SafetyStoreError> {
        self.read_checksummed(META_KEY, "meta")
    }

    /// Read the raw (CRC-verified) record bytes, if present.
    pub fn read_record(&self) -> Result<Option<Vec<u8>>, SafetyStoreError> {
        self.read_checksummed(RECORD_KEY, "record")
    }

    /// Bounded classification of the component-owned `safetyrec:` namespace for
    /// O1 (§ 13.3A). Returns the first key found within the namespace that is
    /// **not** one of the two recognized current-format keys (metadata/record).
    /// Such a key denotes established-but-unknown, legacy, partial, or malformed
    /// safety state that O1 must refuse over — **without** migration, deletion,
    /// repair, or initialization. The scan is bounded to the `safetyrec:` prefix
    /// (an ordered iterator that stops at the first out-of-prefix key) and to a
    /// hard cap, so it never scans unrelated database contents unboundedly.
    pub fn first_unrecognized_safety_key(&self) -> Result<Option<Vec<u8>>, SafetyStoreError> {
        const SAFETY_PREFIX: &[u8] = b"safetyrec:";
        // Hard cap on inspected keys: the component only ever owns a small fixed
        // set of current-format keys, so any growth beyond this bound is itself
        // treated as unknown safety state rather than scanned without limit.
        const MAX_SCAN: usize = 64;
        let mode = rocksdb::IteratorMode::From(SAFETY_PREFIX, rocksdb::Direction::Forward);
        let mut seen = 0usize;
        for item in self.db.iterator(mode) {
            let (key, _value) =
                item.map_err(|e| SafetyStoreError::ReadFailed(format!("namespace scan: {e}")))?;
            if !key.starts_with(SAFETY_PREFIX) {
                break; // left the component namespace: nothing unrelated is scanned.
            }
            seen += 1;
            if seen > MAX_SCAN {
                // More keys than the component could legitimately own: treat the
                // excess as unknown safety state (bounded refusal).
                return Ok(Some(key.to_vec()));
            }
            if key.as_ref() != META_KEY && key.as_ref() != RECORD_KEY {
                return Ok(Some(key.to_vec()));
            }
        }
        Ok(None)
    }

    fn read_checksummed(
        &self,
        key: &[u8],
        what: &str,
    ) -> Result<Option<Vec<u8>>, SafetyStoreError> {
        match self.db.get(key) {
            Ok(None) => Ok(None),
            Ok(Some(raw)) => {
                if raw.len() < 4 {
                    return Err(SafetyStoreError::ReadFailed(format!(
                        "{what}: envelope too short"
                    )));
                }
                let (crc_bytes, payload) = raw.split_at(4);
                let stored =
                    u32::from_be_bytes([crc_bytes[0], crc_bytes[1], crc_bytes[2], crc_bytes[3]]);
                if signing_journal_crc32(payload) != stored {
                    return Err(SafetyStoreError::ReadFailed(format!(
                        "{what}: CRC envelope mismatch"
                    )));
                }
                Ok(Some(payload.to_vec()))
            }
            Err(e) => Err(SafetyStoreError::ReadFailed(format!("{what}: {e}"))),
        }
    }

    fn wrap(payload: &[u8]) -> Vec<u8> {
        let crc = signing_journal_crc32(payload);
        let mut out = Vec::with_capacity(4 + payload.len());
        out.extend_from_slice(&crc.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// Atomically and synchronously publish metadata + authoritative record (and
    /// its embedded supporting material) as one same-database unit under an
    /// already-held serialization-domain guard.
    ///
    /// `_guard` statically witnesses that the caller holds the single
    /// serialization domain. Returns the outcome distinguishing a pre-write
    /// refusal, an ambiguous write error, an uncertain-but-durable outcome, and
    /// an acknowledged durable success.
    ///
    /// **Crate-internal**: raw mutation is reachable only through the enforced
    /// O1/O4/O5 owner paths. There is no public raw-publication entry point, and
    /// the guard type is not publicly constructible, so a caller cannot submit a
    /// raw batch or present a guard from another mutex/backend to forge ownership.
    pub(crate) fn publish_atomic(
        &self,
        _guard: &MutexGuard<'_, SerializationDomain>,
        meta: &[u8],
        record: &[u8],
    ) -> PublishOutcome {
        if self.injected() == InjectFault::FailBeforeSubmit {
            return PublishOutcome::PreWriteRefused("injected pre-submit refusal".into());
        }

        let mut batch = rocksdb::WriteBatch::default();
        batch.put(META_KEY, Self::wrap(meta));
        batch.put(RECORD_KEY, Self::wrap(record));
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);

        if self.injected() == InjectFault::WriteErrors {
            self.mark_not_effective();
            return PublishOutcome::WriteError("injected write error (ambiguous)".into());
        }

        match self.db.write_opt(batch, &write_opts) {
            Ok(()) => {
                if self.injected() == InjectFault::UncertainAfterWrite {
                    // Durable write happened, but the success acknowledgement is
                    // lost: the caller must treat the outcome as uncertain and
                    // must NOT assume the predecessor remained stored. Clear the
                    // shared effectiveness latch so every handle blocks further
                    // dependent publication until recovery (O5) re-establishes it.
                    self.mark_not_effective();
                    PublishOutcome::UncertainDurable
                } else {
                    PublishOutcome::DurableAcknowledged
                }
            }
            Err(e) => {
                self.mark_not_effective();
                PublishOutcome::WriteError(e.to_string())
            }
        }
    }

    /// Whether a fresh durability acknowledgement is required before dependent
    /// publication: either the shared state has never been acknowledged in this
    /// process (a freshly opened established store) or a prior ambiguous/uncertain
    /// publication cleared it. Observed by every attached handle.
    pub fn recovery_required(&self) -> bool {
        !self.effective.load(Ordering::SeqCst)
    }

    /// Mark the shared state **effective**. Crate-internal: reachable only from
    /// the enforced acknowledged O1 initialization and successful O5 recovery
    /// paths (and an acknowledged O4 success), never from a raw public call.
    pub(crate) fn mark_effective(&self) {
        self.effective.store(true, Ordering::SeqCst);
    }

    /// Clear the shared effectiveness latch (ambiguous/uncertain outcome).
    fn mark_not_effective(&self) {
        self.effective.store(false, Ordering::SeqCst);
    }

    fn injected(&self) -> InjectFault {
        match self.inject.load(Ordering::SeqCst) {
            1 => InjectFault::FailBeforeSubmit,
            2 => InjectFault::WriteErrors,
            3 => InjectFault::UncertainAfterWrite,
            _ => InjectFault::None,
        }
    }

    /// Source/test-only: install an injected fault. This never enables any
    /// production runtime path; the production binary never constructs this
    /// backend and so never calls it. Gated behind `test-utils` so it is not a
    /// production-reachable escape.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_inject(&self, fault: InjectFault) {
        self.inject.store(fault as u8, Ordering::SeqCst);
    }

    /// Source/test-only: overwrite the stored record bytes out-of-band (wrapped
    /// in the CRC envelope), simulating a surviving divergent publication. Never
    /// called by production; used only to exercise O5 byte-for-byte refusal.
    /// Gated behind `test-utils` so it is not a production-reachable escape.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn debug_overwrite_record(&self, record_bytes: &[u8]) -> Result<(), SafetyStoreError> {
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);
        self.db
            .put_opt(RECORD_KEY, Self::wrap(record_bytes), &write_opts)
            .map_err(|e| SafetyStoreError::WriteFailed(e.to_string()))
    }

    /// Source/test-only: write an arbitrary raw key/value into the backing
    /// database, used to plant an unknown/legacy/partial key in the `safetyrec:`
    /// namespace for the bounded-classification regressions (§ 13.3A). Never
    /// called by production; gated behind `test-utils`.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn debug_put_raw(&self, key: &[u8], value: &[u8]) -> Result<(), SafetyStoreError> {
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);
        self.db
            .put_opt(key, value, &write_opts)
            .map_err(|e| SafetyStoreError::WriteFailed(e.to_string()))
    }
}

/// The distinguished outcomes of an atomic publication (§ 13.4 O4 / § 13.5).
/// Validation refusal, write failure, uncertain publication, and acknowledged
/// durable success are kept strictly separate; a complete successor may survive
/// despite the caller receiving no success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishOutcome {
    /// Refused before any bytes were submitted; prior state is intact.
    PreWriteRefused(String),
    /// The write returned an error; the durable outcome is ambiguous and the
    /// predecessor must not be assumed to have survived.
    WriteError(String),
    /// The write durably succeeded but no success was delivered to the caller.
    UncertainDurable,
    /// The write durably succeeded and was acknowledged.
    DurableAcknowledged,
}