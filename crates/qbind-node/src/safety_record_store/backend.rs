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

use std::sync::atomic::{AtomicU8, Ordering};
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
/// boundary is held for a check-then-write sequence.
#[derive(Debug, Default)]
pub struct SerializationDomain;

/// The safety backend: an `Arc`-shared RocksDB handle plus the single
/// serialization domain shared by every attached handle.
#[derive(Clone)]
pub struct SafetyBackend {
    db: Arc<rocksdb::DB>,
    domain: Arc<Mutex<SerializationDomain>>,
    inject: Arc<AtomicU8>,
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
            domain: Arc::new(Mutex::new(SerializationDomain)),
            inject: Arc::new(AtomicU8::new(InjectFault::None as u8)),
        })
    }

    /// Acquire the single shared serialization domain for a check-then-write
    /// sequence. Every attached handle contends on the same lock.
    pub fn lock_domain(&self) -> MutexGuard<'_, SerializationDomain> {
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
    pub fn publish_atomic(
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
            return PublishOutcome::WriteError("injected write error (ambiguous)".into());
        }

        match self.db.write_opt(batch, &write_opts) {
            Ok(()) => {
                if self.injected() == InjectFault::UncertainAfterWrite {
                    // Durable write happened, but the success acknowledgement is
                    // lost: the caller must treat the outcome as uncertain and
                    // must NOT assume the predecessor remained stored.
                    PublishOutcome::UncertainDurable
                } else {
                    PublishOutcome::DurableAcknowledged
                }
            }
            Err(e) => PublishOutcome::WriteError(e.to_string()),
        }
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
    /// backend and so never calls it.
    pub fn set_inject(&self, fault: InjectFault) {
        self.inject.store(fault as u8, Ordering::SeqCst);
    }

    /// Source/test-only: overwrite the stored record bytes out-of-band (wrapped
    /// in the CRC envelope), simulating a surviving divergent publication. Never
    /// called by production; used only to exercise O5 byte-for-byte refusal.
    pub fn debug_overwrite_record(&self, record_bytes: &[u8]) -> Result<(), SafetyStoreError> {
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);
        self.db
            .put_opt(RECORD_KEY, Self::wrap(record_bytes), &write_opts)
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