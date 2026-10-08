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

use super::accounting::{AggregateAuthority, SharedAccountant};
use super::error::{EnvelopeFailureKind, ReadFailedDetail, ReadWhat, SafetyStoreError};
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

// Test-only publication-staging observation (Run 422 D7-D14 Item D). At the
// real `publish_atomic` boundary the two CRC-wrapped staging envelopes
// (`wrap(record)`, `wrap(meta)`) are genuinely component-owned allocations that
// coexist with the read-back, transient decode, metadata payload, and retained
// proof. This records their ACTUAL backing capacities so a focused test can
// verify the `publication_staging_charge` reservation covers them INDEPENDENTLY
// of that charge function. It is a boundary marker only — not a total-allocation
// meter — and is absent from default production builds.
#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static PUBLISH_STAGING_OBS: std::cell::Cell<Option<(usize, usize)>> =
        const { std::cell::Cell::new(None) };
}

/// Test-only: arm/reset the publication-staging envelope observation for the
/// current thread. Call immediately before the O4/O5 operation to observe.
#[cfg(any(test, feature = "test-utils"))]
pub fn arm_publish_staging_observation() {
    PUBLISH_STAGING_OBS.with(|c| c.set(None));
    PUBLISH_RESERVATION_OBS.with(|c| c.set(None));
}

/// Test-only: read the `(record_envelope_capacity, meta_envelope_capacity)`
/// observed at the most recent `publish_atomic` submit boundary on this thread,
/// or `None` if no publish reached the boundary since arming.
#[cfg(any(test, feature = "test-utils"))]
pub fn observed_publish_staging() -> Option<(usize, usize)> {
    PUBLISH_STAGING_OBS.with(|c| c.get())
}

// Test-only publication-boundary reservation observation (RUN 422 D7-D14 L2).
// Complementary to `PUBLISH_STAGING_OBS` above: at the SAME `publish_atomic`
// submit boundary — while the two CRC envelopes coexist with the read-back,
// transient decode, metadata payload, and retained proof — this records the
// ACTIVE `(operational_current, aggregate_current)` reservations. It is a
// point-in-time BOUNDARY measurement, not a historical peak, so a reservation
// released before the publish (e.g. the O5 `_o5_res` dropped before its
// `publish_atomic`) collapses the observed operational value. Absent from
// default production builds.
#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static PUBLISH_RESERVATION_OBS: std::cell::Cell<Option<(u128, u128)>> =
        const { std::cell::Cell::new(None) };
}

/// Test-only: read the `(operational_current, aggregate_current)` active
/// reservations observed at the most recent `publish_atomic` submit boundary on
/// this thread — the live component reservations WHILE both CRC envelopes coexist
/// with the rest of the live set (RUN 422 D7-D14 L2). A point-in-time boundary
/// measurement, NOT a historical peak. `None` if no publish reached the boundary
/// since arming.
#[cfg(any(test, feature = "test-utils"))]
pub fn observed_publish_reservations() -> Option<(u128, u128)> {
    PUBLISH_RESERVATION_OBS.with(|c| c.get())
}

// Test-only ACTUAL O5 publication-boundary live-object-charge observation (RUN 422
// D7-D14 M2). Distinct from the reservation observation above — which reads the
// RESERVATION amounts `(operational_current, aggregate_current)` — this records the
// ACTUAL simultaneously component-owned OBJECTS alive at the `publish_atomic`
// boundary. The owner (`reacknowledge`) supplies a BOUNDED SCALAR snapshot of the
// objects it holds live through the boundary (the retained proof's encoded buffer,
// retained representation + nested backings, holder handle, the fresh read-back
// buffer, the transient decoded object, and the metadata payload buffer); this
// backend boundary adds the two CRC staging envelopes it is about to allocate. The
// result is the real combined O5 live charge, measured object-by-object. Scalars
// only — no measured object graph is cloned here. Absent from production builds.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct O5LiveObjectCharge {
    /// Retained O3 proof's original encoded publication buffer capacity.
    pub retained_encoded_cap: u128,
    /// Retained representation (inline `RetainedRecord`) + its nested evidence
    /// backings (`Vec::capacity()` of each owned backing).
    pub retained_generation_charge: u128,
    /// Contract-charged inline holder/handle representation of the proof.
    pub holder_handle: u128,
    /// O5's fresh stored-record read-back buffer capacity.
    pub readback_cap: u128,
    /// Fresh transient decoded object: inline + every nested backing, measured in
    /// place (no clone).
    pub transient_decoded_charge: u128,
    /// Metadata payload buffer (`meta.encode()`) capacity.
    pub metadata_payload_cap: u128,
    /// Actual record envelope capacity (`wrap` over the republished record bytes).
    pub record_envelope_cap: u128,
    /// Actual metadata envelope capacity (`wrap` over the metadata payload).
    pub metadata_envelope_cap: u128,
}

#[cfg(any(test, feature = "test-utils"))]
impl O5LiveObjectCharge {
    /// The total simultaneously component-owned live charge at the O5 boundary.
    pub fn total(&self) -> u128 {
        [
            self.retained_encoded_cap,
            self.retained_generation_charge,
            self.holder_handle,
            self.readback_cap,
            self.transient_decoded_charge,
            self.metadata_payload_cap,
            self.record_envelope_cap,
            self.metadata_envelope_cap,
        ]
        .into_iter()
        .fold(0u128, |a, b| a.saturating_add(b))
    }
}

// Owner-supplied bounded scalar snapshot of the live O5 objects, set by
// `reacknowledge` immediately before `publish_atomic`:
// (retained_encoded_cap, retained_generation_charge, holder_handle,
//  readback_cap, transient_decoded_charge, metadata_payload_cap).
#[cfg(any(test, feature = "test-utils"))]
type O5OwnerSnapshot = (u128, u128, u128, u128, u128, u128);

/// Test-only (RUN 422 D7-D14 S2): a bounded typed marker that the O5
/// live-object observation could NOT be constructed because one of its
/// component measurements failed. It is NOT a production refusal and never
/// changes storage behaviour: the real `publish_atomic` proceeds exactly as
/// before. Its only effect is that the consuming test observes an invalid
/// observation (no valid partial total, no stale successful snapshot) instead of
/// a silently zero-substituted one.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum O5ObservationError {
    /// `evidence_backing_capacity` of the retained proof's evidence failed, so the
    /// retained-generation charge could not be measured.
    RetainedBackingMeasurementFailed,
    /// `decoded_working_set_charge` of the fresh read-back decode failed, so the
    /// transient decoded charge could not be measured.
    TransientDecodeMeasurementFailed,
}

#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static O5_OWNER_SNAPSHOT: std::cell::Cell<Option<O5OwnerSnapshot>> =
        const { std::cell::Cell::new(None) };
    static O5_LIVE_OBJECT_OBS: std::cell::Cell<Option<O5LiveObjectCharge>> =
        const { std::cell::Cell::new(None) };
    static O5_OBS_INVALID: std::cell::Cell<Option<O5ObservationError>> =
        const { std::cell::Cell::new(None) };
}

/// Test-only: arm/reset the O5 publication-boundary live-object-charge observation
/// for the current thread. Call immediately before the O5 `reacknowledge`.
#[cfg(any(test, feature = "test-utils"))]
pub fn arm_o5_live_object_observation() {
    O5_OWNER_SNAPSHOT.with(|c| c.set(None));
    O5_LIVE_OBJECT_OBS.with(|c| c.set(None));
    O5_OBS_INVALID.with(|c| c.set(None));
}

/// Crate/test-only: the owner records its live-object scalar snapshot here, while
/// those objects are all alive, immediately before `publish_atomic`.
#[cfg(any(test, feature = "test-utils"))]
pub(crate) fn set_o5_owner_live_snapshot(
    retained_encoded_cap: u128,
    retained_generation_charge: u128,
    holder_handle: u128,
    readback_cap: u128,
    transient_decoded_charge: u128,
    metadata_payload_cap: u128,
) {
    O5_OWNER_SNAPSHOT.with(|c| {
        c.set(Some((
            retained_encoded_cap,
            retained_generation_charge,
            holder_handle,
            readback_cap,
            transient_decoded_charge,
            metadata_payload_cap,
        )))
    });
}

/// Crate/test-only (RUN 422 D7-D14 S2): the owner records that it could NOT build
/// a live-object snapshot because a component measurement failed. This FAIL-CLOSES
/// the observation: it suppresses any owner snapshot the boundary would combine
/// (so no valid partial total is published), clears any earlier successful
/// observation (so a failed measurement can never reuse a preceding success), and
/// records the typed failure for the consuming test. No zero is substituted.
#[cfg(any(test, feature = "test-utils"))]
pub(crate) fn invalidate_o5_live_object_observation(err: O5ObservationError) {
    O5_OWNER_SNAPSHOT.with(|c| c.set(None));
    O5_LIVE_OBJECT_OBS.with(|c| c.set(None));
    O5_OBS_INVALID.with(|c| c.set(Some(err)));
}

/// Test-only: the ACTUAL combined O5 live-object charge observed at the most recent
/// `publish_atomic` boundary where a VALID owner snapshot was supplied, or `None`
/// (not reached, or the observation was invalidated by a failed measurement).
#[cfg(any(test, feature = "test-utils"))]
pub fn observed_o5_live_object_charge() -> Option<O5LiveObjectCharge> {
    O5_LIVE_OBJECT_OBS.with(|c| c.get())
}

/// Test-only (RUN 422 D7-D14 S2): the typed O5 observation failure recorded at the
/// most recent `reacknowledge`, or `None` if the observation was not invalidated.
#[cfg(any(test, feature = "test-utils"))]
pub fn observed_o5_observation_error() -> Option<O5ObservationError> {
    O5_OBS_INVALID.with(|c| c.get())
}

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
    /// Test-only: the O1 legacy-namespace scan's raw-iterator status reports a
    /// storage-layer iteration error. A real RocksDB raw iterator cannot be forced
    /// to fail its status deterministically, so this narrowly test-gated fault
    /// drives the exact post-scan error branch of
    /// [`SafetyBackend::first_unrecognized_safety_key`] (the typed, allocation-free
    /// `ReadFailedDetail::NamespaceScan` refusal) through the real O1 path.
    FailNamespaceScan = 4,
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
    /// The shared aggregate allocation accountant (§ 13.7 / § 13.7B). Shared by
    /// every attached handle / clone of this instance (the inner `Arc` is cloned,
    /// never re-created), so attaching a second handle cannot open an independent
    /// budget that bypasses the aggregate ceiling. Bound to the per-context
    /// ceiling the first attached handle supplies.
    accounting: SharedAccountant,
    /// The dedicated **context-ownership** accountant (§ 13.7B). Shared by every
    /// attached handle / clone of this instance (the inner `Arc` is cloned, never
    /// re-created). It charges each *distinct* retained pinned-context allocation
    /// taken by an independent `attach()` — a genuinely separate validator-vector
    /// backing + context struct value + shared-allocation overhead — held for the
    /// clone-shared lifetime of that context and released on final drop. Kept
    /// separate from the operational `accounting` pool so a context charge does
    /// not perturb the O1–O5 working-set/holder measurements, while still bounding
    /// the concurrent distinct context owners (`MAX_CONCURRENT_CONTEXT_OWNERS`).
    context_accounting: SharedAccountant,
    /// Source/test-only: a deterministic hook fired by the owner at the exact
    /// point **after** an atomic publication has returned its durability
    /// acknowledgement but **before** the component performs its in-memory
    /// effectiveness transition (`mark_effective`). It exists to coordinate the
    /// post-acknowledgement / pre-effectiveness crash boundary (§ 13.5): a child
    /// process installs a hook that terminates there, proving termination precedes
    /// the effectiveness transition. It is compiled only under `test`/`test-utils`
    /// and is therefore unreachable in a default/release production build.
    #[cfg(any(test, feature = "test-utils"))]
    pre_effective_hook: PreEffectiveHook,
}

/// Source/test-only: the shared, cloneable slot holding the optional
/// pre-effectiveness crash-boundary hook (see [`SafetyBackend`]).
#[cfg(any(test, feature = "test-utils"))]
type PreEffectiveHook = Arc<Mutex<Option<PreEffectiveHookFn>>>;

/// Source/test-only: the pre-effectiveness crash-boundary callback, invoked with
/// the operation label and the acknowledged revision reached.
#[cfg(any(test, feature = "test-utils"))]
type PreEffectiveHookFn = Arc<dyn Fn(&str, u64) + Send + Sync>;

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
        // One aggregate admission authority per backend open, shared by both the
        // operational and the context-ownership partitions so their combined live
        // charge is bounded by the accepted component aggregate ceiling (§ 13.7,
        // finding #4). Cloning the handle below shares the single inner guard.
        let aggregate = AggregateAuthority::new();
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
            // A fresh, unbound operational accountant partition; the first
            // attached handle binds its per-context operational sub-ceiling.
            accounting: SharedAccountant::new(aggregate.clone()),
            // A fresh, unbound dedicated context-ownership accountant partition;
            // the first attached handle binds its per-profile context sub-ceiling
            // (§ 13.7B). It shares the SAME aggregate authority as the operational
            // partition, so neither partition can admit beyond the accepted
            // combined coexistence budget.
            context_accounting: SharedAccountant::new(aggregate),
            // No crash-boundary hook installed unless a test installs one.
            #[cfg(any(test, feature = "test-utils"))]
            pre_effective_hook: Arc::new(Mutex::new(None)),
        })
    }

    /// This backend instance's ownership-incarnation nonce (§ 13.4 / § 13.5).
    /// Crate-internal: used by O3 to stamp a minted recovery capability and by O5
    /// to refuse a capability drawn under a different backend incarnation.
    pub(crate) fn incarnation(&self) -> u64 {
        self.incarnation
    }

    /// The shared aggregate allocation accountant (§ 13.7 / § 13.7B), observed by
    /// every attached handle. Crate-internal: reservations are taken only by the
    /// enforced O1/O3/O4/O5 operations.
    pub(crate) fn accounting(&self) -> &SharedAccountant {
        &self.accounting
    }

    /// The dedicated context-ownership accountant (§ 13.7B), observed by every
    /// attached handle. Crate-internal: reservations are taken only by `attach()`
    /// when it accepts ownership of a distinct retained pinned context.
    pub(crate) fn context_accounting(&self) -> &SharedAccountant {
        &self.context_accounting
    }

    /// Source/test-only: the shared accountant's observed peak, so a regression
    /// can assert that a real operation actually reserved against the shared
    /// budget (not a synthetic counter). Gated behind `test-utils`.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn accounting_peak(&self) -> u128 {
        self.accounting.peak()
    }
    /// Source/test-only: the shared accountant's current charged total.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn accounting_current(&self) -> u128 {
        self.accounting.current()
    }
    /// Source/test-only: the shared accountant's bound ceiling (if bound).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn accounting_cap(&self) -> Option<u128> {
        self.accounting.cap()
    }
    /// Source/test-only: the dedicated context-ownership accountant's current
    /// charged total / observed peak / bound ceiling, so the context-ownership
    /// regressions observe the real shared context accountant (not a mock).
    /// Gated behind `test-utils`.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn context_accounting_current(&self) -> u128 {
        self.context_accounting.current()
    }
    /// Source/test-only: see [`SafetyBackend::context_accounting_current`].
    #[cfg(any(test, feature = "test-utils"))]
    pub fn context_accounting_peak(&self) -> u128 {
        self.context_accounting.peak()
    }
    /// Source/test-only: see [`SafetyBackend::context_accounting_current`].
    #[cfg(any(test, feature = "test-utils"))]
    pub fn context_accounting_cap(&self) -> Option<u128> {
        self.context_accounting.cap()
    }
    /// Source/test-only: the shared **aggregate** admission authority's current
    /// combined charge / observed peak / bound ceiling across BOTH the
    /// operational and context partitions (§ 13.7, finding #4). The combined
    /// regression asserts the aggregate ceiling equals the accepted
    /// profile-derived operational aggregate (`agg_cap == op_cap`), **not** the
    /// sum of the two sub-ceilings (`op_cap + ctx_cap > agg_cap`; that surplus is
    /// deliberately unreachable), and that the live combined charge never exceeds
    /// it.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn accounting_aggregate_current(&self) -> u128 {
        self.accounting.aggregate().current()
    }
    /// Source/test-only: see [`SafetyBackend::accounting_aggregate_current`].
    #[cfg(any(test, feature = "test-utils"))]
    pub fn accounting_aggregate_peak(&self) -> u128 {
        self.accounting.aggregate().peak()
    }
    /// Source/test-only: see [`SafetyBackend::accounting_aggregate_current`].
    #[cfg(any(test, feature = "test-utils"))]
    pub fn accounting_aggregate_cap(&self) -> Option<u128> {
        self.accounting.aggregate().cap()
    }

    /// Source/test-only: take a standing reservation against the shared budget to
    /// model concurrent peers / retained holders consuming the aggregate ceiling,
    /// so capacity-refusal regressions exercise the real shared accountant rather
    /// than a mock. Gated behind `test-utils`.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn reserve_standing_for_test(
        &self,
        charge: u128,
    ) -> Result<super::accounting::Reservation, SafetyStoreError> {
        self.accounting.reserve(charge)
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
        self.read_checksummed(META_KEY, ReadWhat::Metadata, max_payload)
    }

    /// Read the raw (CRC-verified) record bytes, if present. `max_payload` is the
    /// applicable record-size bound enforced on the backend-internal view
    /// **before** any component-owned copy is made.
    pub fn read_record(&self, max_payload: u128) -> Result<Option<Vec<u8>>, SafetyStoreError> {
        self.read_checksummed(RECORD_KEY, ReadWhat::Record, max_payload)
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
        let status = iter.status();
        // Test-only: a real raw-iterator status cannot be forced to fail
        // deterministically, so the narrowly test-gated `FailNamespaceScan` fault
        // drives this exact post-scan error branch — the typed, allocation-free
        // `NamespaceScan` refusal the real status-failure path constructs — through
        // the live O1 operation.
        if self.injected() == InjectFault::FailNamespaceScan {
            return Err(SafetyStoreError::ReadFailed(
                ReadFailedDetail::NamespaceScan,
            ));
        }
        status.map_err(|_e| SafetyStoreError::ReadFailed(ReadFailedDetail::NamespaceScan))?;
        Ok(None)
    }

    fn read_checksummed(
        &self,
        key: &[u8],
        what: ReadWhat,
        max_payload: u128,
    ) -> Result<Option<Vec<u8>>, SafetyStoreError> {
        // `get_pinned` returns a borrowed view into backend-internal (RocksDB-
        // owned) memory, NOT a component-owned `Vec`. We enforce the CRC envelope
        // and the applicable record-size bound against this borrowed view and
        // only copy the payload into a component-owned buffer once it is known to
        // be within bound — so an over-bound stored value never forces an
        // unbounded application-owned allocation.
        //
        // Every refusal below is a typed, **allocation-free** `ReadFailedDetail`
        // (§ 13.7P, D7-D14 Finding B): these diagnostics are constructed *inside*
        // the active O2–O5 read reservation, so embedding an unbounded backend
        // `Display` (the previous `format!("{what}: {e}")`) or even a bounded-but-
        // allocating `format!` would peak a component-owned `String` above the
        // admitted charge. The typed `Copy` payload copies no backend text.
        match self.db.get_pinned(key) {
            Ok(None) => Ok(None),
            Ok(Some(raw)) => {
                let raw: &[u8] = raw.as_ref();
                if raw.len() < 4 {
                    return Err(SafetyStoreError::ReadFailed(ReadFailedDetail::Envelope {
                        what,
                        kind: EnvelopeFailureKind::EnvelopeTooShort,
                    }));
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
                    return Err(SafetyStoreError::ReadFailed(ReadFailedDetail::Envelope {
                        what,
                        kind: EnvelopeFailureKind::CrcMismatch,
                    }));
                }
                // Now within bound and CRC-valid: take the single component-owned copy.
                Ok(Some(payload.to_vec()))
            }
            Err(_e) => Err(SafetyStoreError::ReadFailed(ReadFailedDetail::Envelope {
                what,
                kind: EnvelopeFailureKind::BackendGet,
            })),
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
        // Materialize the two CRC-wrapped staging envelopes as named locals so
        // the real component-owned backing capacities can be observed at this
        // boundary (Item D). Behaviour is unchanged: they are `put` into the
        // same batch exactly as before. The observation call is cfg-gated and
        // absent from production builds.
        let meta_envelope = Self::wrap(meta);
        let record_envelope = Self::wrap(record);
        #[cfg(any(test, feature = "test-utils"))]
        {
            let caps = (record_envelope.capacity(), meta_envelope.capacity());
            PUBLISH_STAGING_OBS.with(|c| c.set(Some(caps)));
            // L2: sample the active operational + aggregate reservations at this
            // same boundary, while both CRC envelopes coexist with the rest of the
            // live set, so a reservation released before `publish_atomic` is detected.
            let reservations = (
                self.accounting().current(),
                self.accounting_aggregate_current(),
            );
            PUBLISH_RESERVATION_OBS.with(|c| c.set(Some(reservations)));
            // M2: if the owner supplied its live-object snapshot (O5 `reacknowledge`),
            // combine it with the two CRC staging envelope capacities measured here —
            // while both envelopes coexist with the read-back, transient decode,
            // metadata payload, and retained proof — to record the ACTUAL combined O5
            // live-object charge. No-op for O1/O4 (no snapshot supplied).
            if let Some((
                retained_encoded_cap,
                retained_generation_charge,
                holder_handle,
                readback_cap,
                transient_decoded_charge,
                metadata_payload_cap,
            )) = O5_OWNER_SNAPSHOT.with(|c| c.get())
            {
                let obs = O5LiveObjectCharge {
                    retained_encoded_cap,
                    retained_generation_charge,
                    holder_handle,
                    readback_cap,
                    transient_decoded_charge,
                    metadata_payload_cap,
                    record_envelope_cap: record_envelope.capacity() as u128,
                    metadata_envelope_cap: meta_envelope.capacity() as u128,
                };
                O5_LIVE_OBJECT_OBS.with(|c| c.set(Some(obs)));
            }
        }
        batch.put(META_KEY, meta_envelope);
        batch.put(RECORD_KEY, record_envelope);
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
            Err(_e) => {
                self.mark_not_effective();
                // The write's durable outcome is ambiguous. The backend error's
                // variable-length `Display` text is deliberately NOT copied into the
                // outcome: this `WriteError` is constructed while the O1/O4/O5
                // publication reservation is still live, so embedding an unbounded
                // backend string would peak a component-owned allocation above the
                // admitted charge (§ 13.7P, D7-D14 Finding B). The fail-closed
                // ambiguous-write distinction is preserved as this bounded,
                // fixed-length outcome.
                PublishOutcome::WriteError("backend write error (ambiguous durable outcome)".into())
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

    /// Source/test-only: install the deterministic post-acknowledgement /
    /// pre-effectiveness crash-boundary hook (§ 13.5). The owner invokes it from
    /// [`crate::safety_record_store::owner`] at the exact point after an atomic
    /// publication has returned its durability acknowledgement but before
    /// `mark_effective`. Gated behind `test-utils`; the production binary never
    /// constructs this backend and so never installs or runs a hook.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_pre_effective_hook(&self, hook: PreEffectiveHookFn) {
        *self.pre_effective_hook.lock().expect("hook slot poisoned") = Some(hook);
    }

    /// Crate/test-only: run the installed pre-effectiveness hook (if any) at the
    /// post-acknowledgement / pre-effectiveness boundary, passing the operation
    /// label and the acknowledged revision so a parent can verify the exact phase
    /// reached. A no-op when no hook is installed.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn run_pre_effective_hook(&self, op: &str, revision: u64) {
        let hook = self
            .pre_effective_hook
            .lock()
            .expect("hook slot poisoned")
            .clone();
        if let Some(hook) = hook {
            hook(op, revision);
        }
    }

    fn injected(&self) -> InjectFault {
        match self.inject.load(Ordering::SeqCst) {
            1 => InjectFault::FailBeforeSubmit,
            2 => InjectFault::WriteErrors,
            3 => InjectFault::UncertainAfterWrite,
            4 => InjectFault::FailNamespaceScan,
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