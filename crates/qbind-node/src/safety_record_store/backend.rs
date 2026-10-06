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

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use super::error::SafetyStoreError;
use crate::pqc_trust_bundle::TrustBundleEnvironment;
use crate::storage::signing_journal_crc32;

/// Process-local **ownership-incarnation** source. Each successful backend open
/// draws a fresh, strictly increasing value. It is an in-process ownership nonce
/// — NOT a persistent identifier, cryptographic identity, protocol domain, or
/// stored schema field — used only to bind an O3-minted recovery capability to
/// the exact backend/ownership incarnation that produced it (§ 13.4 / § 13.5).
/// Two distinct opens (including a reopen of the same DB) get distinct values,
/// so a recovery token from one incarnation is never honoured by another.
static OWNERSHIP_INCARNATION: AtomicU64 = AtomicU64::new(1);

/// The metadata key (one per backend DB).
const META_KEY: &[u8] = b"safetyrec:meta:v1";
/// The authoritative-record key (record + embedded supporting material).
const RECORD_KEY: &[u8] = b"safetyrec:record:v1";
/// Exact encoded length of the fixed metadata payload (`2 + 32 + 8`). The
/// metadata envelope payload can never legitimately exceed this; it is the
/// applicable read bound enforced on the backend-internal view before any
/// component-owned copy of the metadata is created.
pub(crate) const META_ENCODED_LEN: u128 = 2 + 32 + 8;

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
    /// The ownership-incarnation nonce drawn at this backend's open. Shared by
    /// every attached handle / clone of this instance (a `Copy` value, identical
    /// across clones), and distinct from any other open — including a reopen of
    /// the same DB path. It binds an O3-minted recovery capability to the exact
    /// backend incarnation that produced it; O5 refuses a token whose incarnation
    /// differs from the backend it is presented to.
    incarnation: u64,
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
            // Draw a fresh ownership incarnation for this open (and reopen).
            incarnation: OWNERSHIP_INCARNATION.fetch_add(1, Ordering::SeqCst),
        })
    }

    /// This backend instance's ownership-incarnation nonce (§ 13.4 / § 13.5).
    /// Crate-internal: used by O3 to stamp a minted recovery capability and by O5
    /// to refuse a capability drawn under a different backend incarnation.
    pub(crate) fn incarnation(&self) -> u64 {
        self.incarnation
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

    /// Read the raw (CRC-verified) metadata bytes, if present. `max_payload` is
    /// the applicable record-size bound enforced on the backend-internal view
    /// **before** any component-owned copy is made.
    pub fn read_meta(&self, max_payload: u128) -> Result<Option<Vec<u8>>, SafetyStoreError> {
        self.read_checksummed(META_KEY, "meta", max_payload)
    }

    /// Read the raw (CRC-verified) record bytes, if present. `max_payload` is the
    /// applicable record-size bound enforced on the backend-internal view
    /// **before** any component-owned copy is made.
    pub fn read_record(&self, max_payload: u128) -> Result<Option<Vec<u8>>, SafetyStoreError> {
        self.read_checksummed(RECORD_KEY, "record", max_payload)
    }

    /// Bounded classification of the component-owned `safetyrec:` namespace for
    /// O1 (§ 13.3A). Returns the **byte length** of the first key found within
    /// the namespace that is **not** one of the two recognized current-format
    /// keys (metadata/record). Such a key denotes established-but-unknown,
    /// legacy, partial, or malformed safety state that O1 must refuse over —
    /// **without** migration, deletion, repair, or initialization. Returning only
    /// the length (never the key bytes, and never any value bytes) keeps the
    /// classification's application-owned allocation bounded to zero: it answers
    /// *whether* an unknown safety key exists without copying it.
    ///
    /// The scan is bounded two ways (§ 13.3A): by **work performed** — an ordered
    /// raw iterator seeked to the `safetyrec:` prefix that stops at the first
    /// out-of-prefix key and at a hard `MAX_SCAN` key cap — and by
    /// **application-owned bytes** — it inspects only borrowed key slices and
    /// never materializes a value, so no value copy is ever taken merely to
    /// decide existence.
    pub fn first_unrecognized_safety_key(&self) -> Result<Option<usize>, SafetyStoreError> {
        const SAFETY_PREFIX: &[u8] = b"safetyrec:";
        // Hard cap on inspected keys: the component only ever owns a small fixed
        // set of current-format keys, so any growth beyond this bound is itself
        // treated as unknown safety state rather than scanned without limit.
        const MAX_SCAN: usize = 64;
        // A raw iterator exposes borrowed key/value slices without forcing a
        // value copy; we only ever read `.key()`, never `.value()`.
        let mut iter = self.db.raw_iterator();
        iter.seek(SAFETY_PREFIX);
        let mut seen = 0usize;
        while iter.valid() {
            let key = match iter.key() {
                Some(k) => k,
                None => break,
            };
            if !key.starts_with(SAFETY_PREFIX) {
                break; // left the component namespace: nothing unrelated is scanned.
            }
            seen += 1;
            if seen > MAX_SCAN {
                // More keys than the component could legitimately own: treat the
                // excess as unknown safety state (bounded refusal). Report the
                // length of the offending key without copying it.
                return Ok(Some(key.len()));
            }
            if key != META_KEY && key != RECORD_KEY {
                return Ok(Some(key.len()));
            }
            iter.next();
        }
        // Surface a storage-layer iteration error rather than silently treating
        // it as "namespace clean".
        iter.status()
            .map_err(|e| SafetyStoreError::ReadFailed(format!("namespace scan: {e}")))?;
        Ok(None)
    }

    fn read_checksummed(
        &self,
        key: &[u8],
        what: &str,
        max_payload: u128,
    ) -> Result<Option<Vec<u8>>, SafetyStoreError> {
        // `get_pinned` returns a borrowed view into backend-internal (RocksDB-
        // owned) memory, NOT a component-owned `Vec`. We enforce the CRC envelope
        // and the applicable record-size bound against this borrowed view and
        // only copy the payload into a component-owned buffer once it is known to
        // be within bound — so an over-bound stored value never forces an
        // unbounded application-owned allocation.
        match self.db.get_pinned(key) {
            Ok(None) => Ok(None),
            Ok(Some(raw)) => {
                let raw: &[u8] = raw.as_ref();
                if raw.len() < 4 {
                    return Err(SafetyStoreError::ReadFailed(format!(
                        "{what}: envelope too short"
                    )));
                }
                // Bound the payload length BEFORE copying it out of backend memory.
                let payload_len = (raw.len() - 4) as u128;
                if payload_len > max_payload {
                    return Err(SafetyStoreError::Oversize {
                        len: payload_len,
                        max: max_payload,
                    });
                }
                let (crc_bytes, payload) = raw.split_at(4);
                let stored =
                    u32::from_be_bytes([crc_bytes[0], crc_bytes[1], crc_bytes[2], crc_bytes[3]]);
                if signing_journal_crc32(payload) != stored {
                    return Err(SafetyStoreError::ReadFailed(format!(
                        "{what}: CRC envelope mismatch"
                    )));
                }
                // Now within bound and CRC-valid: take the single component-owned copy.
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