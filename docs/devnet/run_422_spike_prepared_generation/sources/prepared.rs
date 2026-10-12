//! RUN 422 — **generation-only** prepared-decision L0 evidence retention
//! (§ 13.6), an isolated executable experiment.
//!
//! # What this is
//!
//! A bounded registry that retains, for a prepared signing decision, **only the
//! decoded evidence generation** of a successfully read-validated proof plus the
//! provenance required to rebind it — *not* the original encoded publication
//! record. A captured entry therefore charges only:
//!
//! * one (possibly **shared**) generation backing, measured in place from the
//!   moved [`RetainedRecord`] as the **actual** `GenerationBacking` allocation:
//!   a generation-**core** charge (the real retained generation inline + the live
//!   evidence heap backings + one shared-allocation overhead,
//!   [`super::accounting::prepared_generation_charge`], non-cloning) plus a
//!   holder/**control** charge for the wrapper's provenance + inline reservation
//!   + padding ([`super::accounting::prepared_holder_control_charge`]); together
//!   they cover every live byte of the `Arc<GenerationBacking>`, and
//! * the registry-storage charge for the containing slot array (counting the
//!   embedded entry once) and an owning-pin charge per outstanding pin.
//!
//! Both terms are already reserved by the accepted aggregate ceiling
//! ([`super::profile::max_aggregate_retained_bytes`]): its holder term budgets
//! `MAX_OUTSTANDING_PREPARED_L0 × (identity + arc_handle)` and its generation
//! term budgets `(prepared + 1 + candidate)` distinct generations, while its
//! encoded-buffer term budgets **no** publication buffer for a prepared holder.
//! A generation-only entry therefore fits with **no ceiling increase** — the
//! defect of a full-proof holder (which re-charged the encoded buffer) is that
//! it consumed budget the ceiling never reserved for prepared retention.
//!
//! # What this is NOT
//!
//! Capture is **non-authorizing**: it establishes no engine decision timing, no
//! verification, no freshness, and no activation. `BootstrapNoLock` is left
//! explicitly unresolved (a Locked-only experiment). The component stays
//! disabled-by-default and is constructed only from its own focused tests.
//!
//! # Lock ordering
//!
//! The backend serialization domain ([`super::backend::SafetyBackend::lock_domain`])
//! is the **outer** lock; the registry mutex is a **leaf** taken under it during
//! capture (capture is linearized with publication). Release and automatic
//! abandonment take **only** the registry mutex, never re-entering the domain,
//! so no lock cycle is possible.

use std::sync::{Arc, Mutex};

use super::accounting::Reservation;
use super::profile::{ARC_CTRL, MAX_OUTSTANDING_PREPARED_L0};
use super::record::{EvidenceStatus, RetainedRecord, SafetyRecord};

/// The per-entry prepared-decision L0 charge in bytes (§ 13.6): identity (40) +
/// arc-handle (8) = 48, the single source of truth shared with the aggregate's
/// holder budget. Re-exported here for the capture path and its tests.
pub fn prepared_entry_charge_bytes() -> u128 {
    super::profile::prepared_entry_charge()
}

/// The number of concurrently outstanding prepared-decision L0 holders the
/// registry admits — the accepted `MAX_OUTSTANDING_PREPARED_L0` (§ 13.6), used
/// here as the fixed inline slot count so the registry owns no growable backing.
pub const PREPARED_SLOTS: usize = MAX_OUTSTANDING_PREPARED_L0 as usize;

/// The pinned restriction identity a prepared generation carries (§ 13.6): the
/// `lock_block_id` (32) + `lock_view` (8) of the retained `Locked` record. This
/// is exactly the `PREPARED_IDENTITY_BYTES` the aggregate budgets per holder.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GenerationIdentity {
    pub lock_block_id: [u8; 32],
    pub lock_view: u64,
}

impl GenerationIdentity {
    /// Derive the identity of a retained generation, or `None` for a
    /// `BootstrapNoLock` record (which prepared retention refuses).
    pub fn from_retained(retained: &RetainedRecord) -> Option<Self> {
        match &retained.record {
            SafetyRecord::Locked(l) => Some(GenerationIdentity {
                lock_block_id: l.lock_block_id,
                lock_view: l.lock_view,
            }),
            SafetyRecord::BootstrapNoLock { .. } => None,
        }
    }
}

/// Why a capture was refused. Every refusal returns the original proof intact
/// (including its original bytes and reservation); none mints authorization,
/// freshness, durability acknowledgement, or verified-evidence status.
#[derive(Debug)]
pub enum CaptureRefusal {
    /// The backend requires a successful recovery before dependent work.
    RecoveryRequired,
    /// The proof carries no O5 recovery capability for *this* backend
    /// incarnation — a standalone/uncharged proof (`None`) or one minted by a
    /// foreign backend incarnation. Catches both.
    ForeignOrUncharged,
    /// The proof was sealed under a different pinned-context digest.
    ForeignContext,
    /// The proof is a `BootstrapNoLock` record; prepared retention is a
    /// Locked-only experiment and leaves bootstrap explicitly unresolved.
    BootstrapUnresolved,
    /// The proof's publication revision is not the current authoritative
    /// revision read under the serialization domain.
    StaleRevision { expected: u64, found: u64 },
    /// All prepared slots are occupied; refused **without eviction**.
    RegistryFull,
    /// The generation serial counter is exhausted; refused **before** any
    /// mutation (never wraps or reuses an identity).
    CounterExhausted,
    /// The per-entry or generation admission was refused by the shared
    /// accountant (aggregate or partition ceiling).
    Admission(super::error::SafetyStoreError),
    /// The authoritative metadata could not be read under the domain.
    MetadataUnavailable(super::error::SafetyStoreError),
}

/// The outcome of releasing a prepared entry.
#[derive(Debug, PartialEq, Eq)]
pub enum ReleaseOutcome {
    /// The entry was found (incarnation + serial matched) and removed.
    Released,
    /// No matching entry (already released, abandoned, or a stale serial).
    NotFound,
    /// The handle was minted under a different backend incarnation.
    ForeignIncarnation,
}

/// A **non-owning** identifier for a prepared entry. `Copy`, owns nothing: a
/// handle alone can neither keep an entry alive nor release it twice. It carries
/// the backend incarnation it was minted under so a foreign/stale handle is
/// refused on lookup **and** release.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PreparedHandle {
    slot: usize,
    serial: u64,
    incarnation: u64,
}

impl PreparedHandle {
    /// The backend ownership-incarnation this handle was minted under.
    pub fn incarnation(&self) -> u64 {
        self.incarnation
    }
    /// The entry serial this handle refers to.
    pub fn serial(&self) -> u64 {
        self.serial
    }
}

/// The retained generation backing shared by one or more prepared entries. It
/// owns the **moved** decoded generation (never a clone) and the single
/// generation-only reservation; when the **last** entry sharing it drops, the
/// reservation drops and the generation charge is released. A prior (first)
/// drop merely decrements the shared `Arc` and retains the charge.
///
/// Every field is retained **by design** — the §13.6 provenance a prepared
/// decision must carry to rebind safely (and the RAII reservations). Several are
/// read only through the test-gated inspector, so `dead_code` is allowed here.
#[allow(dead_code)]
#[derive(Debug)]
struct GenerationBacking {
    retained: RetainedRecord,
    origin_context_digest: [u8; 32],
    recovery_backend_incarnation: u64,
    evidence_status: EvidenceStatus,
    captured_revision: u64,
    /// The generation **core** charge: the actual `RetainedRecord` inline + the
    /// evidence backings + one shared-allocation (`Arc`) overhead, bounded by the
    /// generation sub-ceiling. Its lifetime **is** the accounting (RAII); never
    /// read directly outside test accessors.
    gen_reservation: Reservation,
    /// The generation **holder/control** charge: the live `GenerationBacking`
    /// inline bytes **beyond** the retained core — the provenance fields, the
    /// inline `gen_reservation` itself, and layout padding — counted once inside
    /// this containing allocation. Held here so it is released together with the
    /// generation on the **last** share drop (RAII); never read directly.
    control_reservation: Reservation,
}

/// An **opaque** crate-visible token for a shareable live generation backing,
/// returned by [`PreparedRegistry::shareable_backing_for`] and consumed by
/// [`PreparedRegistry::insert_shared`]. It keeps [`GenerationBacking`] private
/// while letting the owner capture path pass a found backing back for sharing.
pub struct SharedGenerationBacking(Arc<GenerationBacking>);

/// One prepared-decision L0 entry **embedded** in the registry's inline slot
/// array: the pinned identity, its serial, and a (possibly shared) `Arc` share of
/// the generation backing. The entry's own inline bytes (identity + serial +
/// arc-handle + padding) are covered **once** by the registry-storage charge that
/// counts this containing allocation; dropping the entry drops its backing share
/// and, if it held the **last** share, releases the generation core + control
/// charges (RAII).
///
/// `identity` is retained for the registry's shareable/metadata role and read by
/// the test-gated inspector; `dead_code` is allowed for that reason.
#[allow(dead_code)]
#[derive(Debug)]
struct PreparedEntry {
    identity: GenerationIdentity,
    serial: u64,
    backing: Arc<GenerationBacking>,
}

/// The bounded prepared-decision L0 registry: a fixed inline slot array (no
/// growable backing — its inline size already includes its embedded slots and
/// entries), a monotonic serial counter, and the backend incarnation it belongs
/// to. The whole registry is **lazily allocated** — it does not exist at backend
/// open or ordinary attachment. It is created only by the first prepared capture,
/// **after** that capture has admitted the registry-storage charge, and is then
/// installed **once** behind a shared `Arc<Mutex<..>>` (under the backend
/// serialization domain, so concurrent handles cannot install bypass registries).
/// Once installed, the registry — and the [`Reservation`] it owns from
/// construction — persists for the **entire lifetime of the allocation**,
/// including periods with zero live entries, and is released only when the last
/// owner of the allocation (the backend slot and any outstanding
/// [`PreparedPin`]) drops. The reservation lifetime therefore follows the
/// registry's **actual shared ownership**, so a pin that outlives its owner
/// handle keeps the allocation (and its covering reservation) alive.
#[derive(Debug)]
pub struct PreparedRegistry {
    slots: [Option<PreparedEntry>; PREPARED_SLOTS],
    next_serial: u64,
    incarnation: u64,
    /// The **registry-storage** charge (the whole `Mutex<PreparedRegistry>` cell
    /// value + its shared-allocation overhead), covering this container and its
    /// embedded entry slots **once**. It is admitted by the capture path **before**
    /// the allocation is created and moved in here at construction, so its lifetime
    /// **is** the allocation's lifetime (RAII): it stays charged for as long as the
    /// registry allocation is retained — including while empty — and is released
    /// exactly when the allocation is destroyed (its last owner drops). It is never
    /// dropped on an empty→occupied→empty cycle; deallocation-whenever-empty is not
    /// required and is deliberately not done.
    ///
    /// `#[allow(dead_code)]`: the field is held purely for its RAII `Drop` (the
    /// reservation is released when the allocation is destroyed) and is read only
    /// by the `test-utils` accessor below, so the default build sees no reader.
    #[allow(dead_code)]
    registry_reservation: Reservation,
}

impl PreparedRegistry {
    /// A fresh empty registry bound to a backend incarnation, consuming the
    /// already-admitted registry-storage [`Reservation`] (admission precedes this
    /// allocation). The reservation is owned for the allocation's whole lifetime.
    pub fn new(incarnation: u64, registry_reservation: Reservation) -> Self {
        PreparedRegistry {
            slots: Default::default(),
            next_serial: 0,
            incarnation,
            registry_reservation,
        }
    }

    /// The number of occupied slots.
    pub fn occupied(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    /// Whether every slot is occupied (a further capture is refused without
    /// eviction).
    pub fn is_full(&self) -> bool {
        self.slots.iter().all(|s| s.is_some())
    }

    /// The first free slot index, or `None` when full.
    fn first_free(&self) -> Option<usize> {
        self.slots.iter().position(|s| s.is_none())
    }

    /// Find a live backing whose retained generation equals `retained`, so a new
    /// entry can **share** one generation charge. Equality is a non-cloning
    /// structural compare of the moved retained generation.
    fn find_shared_backing(&self, retained: &RetainedRecord) -> Option<Arc<GenerationBacking>> {
        for slot in self.slots.iter().flatten() {
            if &slot.backing.retained == retained {
                return Some(Arc::clone(&slot.backing));
            }
        }
        None
    }

    /// The next serial value **without** mutating the counter, failing closed if
    /// the counter is exhausted (never wraps or reuses an identity).
    fn peek_serial(&self) -> Option<u64> {
        // The next serial is `next_serial`; the counter advances to
        // `next_serial + 1` on a successful insert. Exhaustion is when that
        // advance would overflow.
        self.next_serial.checked_add(1).map(|_| self.next_serial)
    }

    /// Remove the entry a handle refers to, verifying backend incarnation first
    /// (foreign/stale handle refused) then the slot + serial.
    pub fn release_by_handle(&mut self, handle: PreparedHandle) -> ReleaseOutcome {
        if handle.incarnation != self.incarnation {
            return ReleaseOutcome::ForeignIncarnation;
        }
        if handle.slot >= self.slots.len() {
            return ReleaseOutcome::NotFound;
        }
        let matches = self.slots[handle.slot]
            .as_ref()
            .map(|e| e.serial == handle.serial)
            .unwrap_or(false);
        if matches {
            // Dropping the entry drops its `Arc<GenerationBacking>` share and, if
            // this was the last share, the generation core + control charges
            // (RAII). The registry-storage reservation is **not** touched here: it
            // stays charged for the entire allocation lifetime (including this
            // empty period) and is released only when the allocation is destroyed
            // (its last owner — the backend slot and any outstanding pin — drops).
            self.slots[handle.slot] = None;
            ReleaseOutcome::Released
        } else {
            ReleaseOutcome::NotFound
        }
    }

    // ---- test seams (gated; no hidden allocations in measured intervals) ----

    /// Test-only: look up a live entry by handle (incarnation-checked), exposing
    /// read-only measurements. Returns `None` for a foreign/stale handle.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn inspect(&self, handle: PreparedHandle) -> Option<PreparedEntryView> {
        if handle.incarnation != self.incarnation {
            return None;
        }
        let e = self.slots.get(handle.slot)?.as_ref()?;
        if e.serial != handle.serial {
            return None;
        }
        Some(PreparedEntryView {
            identity: e.identity,
            serial: e.serial,
            generation_core_charge: e.backing.gen_reservation.charge(),
            generation_control_charge: e.backing.control_reservation.charge(),
            backing_shares: Arc::strong_count(&e.backing),
            captured_revision: e.backing.captured_revision,
            recovery_backend_incarnation: e.backing.recovery_backend_incarnation,
            origin_context_digest: e.backing.origin_context_digest,
            evidence_status: e.backing.evidence_status,
            // Measurement failure is surfaced explicitly (panic), never silently
            // substituted with 0.
            evidence_backing_capacity: e
                .backing
                .retained
                .evidence_backing_capacity()
                .expect("evidence backing capacity measurement failed"),
        })
    }

    /// Test-only: the current serial counter.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn next_serial_for_test(&self) -> u64 {
        self.next_serial
    }

    /// Test-only: the standing registry-storage reservation charge this
    /// allocation holds for its whole lifetime (covers the cell once, retained
    /// even while empty). Observes the reservation directly, independent of entry
    /// state.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn registry_reservation_charge(&self) -> u128 {
        self.registry_reservation.charge()
    }

    /// Test-only bounded seam: drive the serial counter to the brink of
    /// exhaustion so the fail-closed path is reachable deterministically.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn force_next_serial(&mut self, v: u64) {
        self.next_serial = v;
    }
}

/// Test-only read-only view of a live prepared entry's measurements, taken
/// independently of any reservation **counter** (the strong-count and charges
/// establish object coverage, not reservation state).
#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug, Clone)]
pub struct PreparedEntryView {
    pub identity: GenerationIdentity,
    pub serial: u64,
    /// The generation **core** reservation (RetainedRecord inline + backings + Arc).
    pub generation_core_charge: u128,
    /// The generation **holder/control** reservation (GenerationBacking inline
    /// beyond the retained core: provenance + inline reservation + padding).
    pub generation_control_charge: u128,
    pub backing_shares: usize,
    pub captured_revision: u64,
    pub recovery_backend_incarnation: u64,
    pub origin_context_digest: [u8; 32],
    pub evidence_status: EvidenceStatus,
    pub evidence_backing_capacity: usize,
}

/// The **owning, non-`Copy`** guard returned by a successful capture. Its `Drop`
/// provides automatic abandonment cleanup: an abandoned (never explicitly
/// released) pin releases its entry — and, if the last share, its generation
/// charge — when it goes out of scope, while the backend stays alive. Explicit
/// [`PreparedPin::release`] is the normal-completion path; dropping the returned
/// outcome is a no-op because the pin marks itself released.
pub struct PreparedPin {
    registry: Arc<Mutex<PreparedRegistry>>,
    handle: PreparedHandle,
    released: bool,
    /// The **owning-pin** charge covering this guard's own live bytes
    /// (`size_of::<PreparedPin>()`, which includes this field). Released (RAII)
    /// when the pin is released or dropped.
    _pin_reservation: Reservation,
}

impl std::fmt::Debug for PreparedPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedPin")
            .field("handle", &self.handle)
            .field("released", &self.released)
            .finish()
    }
}

impl PreparedPin {
    /// Crate-internal: build a pin over an inserted entry.
    pub(crate) fn new(
        registry: Arc<Mutex<PreparedRegistry>>,
        handle: PreparedHandle,
        pin_reservation: Reservation,
    ) -> Self {
        PreparedPin {
            registry,
            handle,
            released: false,
            _pin_reservation: pin_reservation,
        }
    }

    /// The non-owning handle for this entry (for inspection / handle-based APIs).
    pub fn handle(&self) -> PreparedHandle {
        self.handle
    }

    fn release_inner(&mut self) -> ReleaseOutcome {
        if self.released {
            return ReleaseOutcome::NotFound;
        }
        self.released = true;
        let mut reg = self.registry.lock().expect("prepared registry poisoned");
        reg.release_by_handle(self.handle)
    }

    /// Normal completion: release this entry explicitly, consuming the pin.
    pub fn release(mut self) -> ReleaseOutcome {
        self.release_inner()
    }
}

impl Drop for PreparedPin {
    fn drop(&mut self) {
        // Automatic abandonment cleanup — releases the entry (and, if last
        // share, the generation charge) with the backend still alive.
        let _ = self.release_inner();
    }
}

// ---- measurement helpers (test-gated; no hidden allocations) ----

/// Test-only: `size_of` the registry container value (its inline slots + serial
/// counter + incarnation), counted once. Its inline size already includes the
/// embedded slots and entries.
#[cfg(any(test, feature = "test-utils"))]
pub fn size_of_prepared_registry() -> usize {
    std::mem::size_of::<PreparedRegistry>()
}

/// Test-only: `size_of` one prepared entry value.
#[cfg(any(test, feature = "test-utils"))]
pub fn size_of_prepared_entry() -> usize {
    std::mem::size_of::<PreparedEntry>()
}

/// Test-only: `size_of` one generation backing value.
#[cfg(any(test, feature = "test-utils"))]
pub fn size_of_generation_backing() -> usize {
    std::mem::size_of::<GenerationBacking>()
}

/// Test-only: `size_of` the non-owning handle.
#[cfg(any(test, feature = "test-utils"))]
pub fn size_of_prepared_handle() -> usize {
    std::mem::size_of::<PreparedHandle>()
}

/// The actual inline size of the private [`GenerationBacking`] wrapper value
/// (`size_of::<GenerationBacking>()`). Crate-internal: supplied to
/// [`super::accounting::prepared_holder_control_charge`] by the capture path,
/// which cannot see the private layout, so the holder/control charge is derived
/// from the **actual** wrapper size rather than a synthetic wrapper.
pub(crate) fn generation_backing_struct_size() -> u128 {
    std::mem::size_of::<GenerationBacking>() as u128
}

/// The **registry-storage** charge: the whole `Mutex<PreparedRegistry>` cell value
/// (container + its embedded entry slots + serial + incarnation + the inline
/// registry reservation, counted **once**) plus the shared-allocation (`Arc`)
/// overhead. Admitted by the first prepared capture **before** the registry
/// allocation is created, then retained for the allocation's whole lifetime.
pub(crate) fn registry_cell_charge() -> u128 {
    std::mem::size_of::<Mutex<PreparedRegistry>>() as u128 + ARC_CTRL
}

/// The **owning-pin** charge: the inline size of a [`PreparedPin`] guard value
/// (`size_of::<PreparedPin>()`, which already includes its inline reservation
/// field), charged per live outstanding pin.
pub(crate) fn pin_charge() -> u128 {
    std::mem::size_of::<PreparedPin>() as u128
}

/// Test-only: the registry-storage charge (`registry_cell_charge`).
#[cfg(any(test, feature = "test-utils"))]
pub fn registry_cell_charge_bytes() -> u128 {
    registry_cell_charge()
}

/// Test-only: the owning-pin charge (`pin_charge`).
#[cfg(any(test, feature = "test-utils"))]
pub fn pin_charge_bytes() -> u128 {
    pin_charge()
}

/// Test-only: the actual inline size of the private `GenerationBacking` wrapper.
#[cfg(any(test, feature = "test-utils"))]
pub fn generation_backing_struct_size_bytes() -> u128 {
    generation_backing_struct_size()
}

/// Test-only: `size_of` the `Mutex<PreparedRegistry>` cell value whose storage the
/// registry charge covers (container + embedded entry slots, counted once).
#[cfg(any(test, feature = "test-utils"))]
pub fn size_of_prepared_registry_cell() -> usize {
    std::mem::size_of::<Mutex<PreparedRegistry>>()
}

/// Test-only: `size_of` the owning [`PreparedPin`] guard value.
#[cfg(any(test, feature = "test-utils"))]
pub fn size_of_prepared_pin() -> usize {
    std::mem::size_of::<PreparedPin>()
}

// ---- crate-internal construction primitives used by the owner capture path --

impl PreparedRegistry {
    /// Crate-internal: insert a **new, un-shared** generation backing plus its
    /// entry, consuming the pre-taken reservations. Caller guarantees a free slot
    /// (via a prior [`PreparedRegistry::first_free`] check) and a non-exhausted
    /// serial (via [`PreparedRegistry::peek_serial`]); both are re-checked here so
    /// insertion cannot silently overwrite or wrap.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn insert_fresh(
        &mut self,
        identity: GenerationIdentity,
        retained: RetainedRecord,
        origin_context_digest: [u8; 32],
        recovery_backend_incarnation: u64,
        evidence_status: EvidenceStatus,
        captured_revision: u64,
        gen_reservation: Reservation,
        control_reservation: Reservation,
    ) -> Option<PreparedHandle> {
        let backing = Arc::new(GenerationBacking {
            retained,
            origin_context_digest,
            recovery_backend_incarnation,
            evidence_status,
            captured_revision,
            gen_reservation,
            control_reservation,
        });
        self.place(identity, backing)
    }

    /// Crate-internal: insert an entry that **shares** an existing backing (one
    /// generation charge), consuming only the per-entry reservation.
    pub(crate) fn insert_shared(
        &mut self,
        identity: GenerationIdentity,
        backing: SharedGenerationBacking,
    ) -> Option<PreparedHandle> {
        self.place(identity, backing.0)
    }

    /// Crate-internal: find a shareable backing (equal retained generation).
    pub(crate) fn shareable_backing_for(
        &self,
        retained: &RetainedRecord,
    ) -> Option<SharedGenerationBacking> {
        self.find_shared_backing(retained).map(SharedGenerationBacking)
    }

    /// Crate-internal: a free slot index, or `None` when full.
    pub(crate) fn free_slot(&self) -> Option<usize> {
        self.first_free()
    }

    /// Crate-internal: the next serial, failing closed on exhaustion.
    pub(crate) fn next_serial_checked(&self) -> Option<u64> {
        self.peek_serial()
    }

    /// Crate-internal: the backend incarnation this registry is bound to.
    #[allow(dead_code)]
    pub(crate) fn incarnation(&self) -> u64 {
        self.incarnation
    }

    fn place(
        &mut self,
        identity: GenerationIdentity,
        backing: Arc<GenerationBacking>,
    ) -> Option<PreparedHandle> {
        let slot = self.first_free()?;
        let serial = self.peek_serial()?;
        let next = self.next_serial.checked_add(1)?;
        // The registry-storage reservation was admitted and moved in at
        // construction (admission precedes allocation); it is retained for the
        // allocation's whole lifetime, so nothing is adopted or charged here.
        self.slots[slot] = Some(PreparedEntry {
            identity,
            serial,
            backing,
        });
        self.next_serial = next;
        Some(PreparedHandle {
            slot,
            serial,
            incarnation: self.incarnation,
        })
    }
}
