//! Private ownership and admission support for isolated received-Vote evidence.
//! This module verifies borrowed Vote inputs but does not connect to consensus
//! event execution.
#![allow(dead_code)]

use std::alloc::{alloc, dealloc, Layout};
use std::marker::PhantomData;
use std::mem::{size_of, ManuallyDrop};
use std::ptr::NonNull;
use std::sync::atomic::{fence, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use qbind_crypto::{
    ml_dsa44::MlDsa44Backend, ConsensusSigSuiteId, ML_DSA_44_PUBLIC_KEY_SIZE,
    ML_DSA_44_SIGNATURE_SIZE, SUITE_PQ_RESERVED_1,
};
use qbind_types::ChainId;
use qbind_wire::{consensus::Vote, pv_signing_domain::ProposalVoteSigningDomainV2};

const MAX_CONTEXTS: usize = 16;
const MAX_REPORTS: usize = 1024;
const MAX_MEMBERS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvidenceAllocError {
    Layout,
    ZeroSizedType,
    Allocation,
    Capacity,
    Arithmetic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LedgerError {
    Admission,
    Allocation,
    Arithmetic,
    Quota,
    WrongReservationKind,
    InsufficientCoverage,
    Invariant,
}

/// Only types whose destruction and thread-safety properties have been
/// reviewed for this private component may use `ExactBuffer`.
trait EvidenceElement: Send + Sync + 'static {}

impl EvidenceElement for u8 {}
impl EvidenceElement for Vec<u8> {}
impl EvidenceElement for SnapshotMember {}

#[cfg(test)]
impl EvidenceElement for () {}

#[cfg(test)]
thread_local! {
    static FAIL_ALLOCATION_AFTER: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
    static ALLOCATION_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static ALLOCATION_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static DEALLOCATION_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static BUDGET_FINAL_DROPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CONTEXT_FINAL_DROPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
struct AllocationFaultScope(Option<usize>);

#[cfg(test)]
impl AllocationFaultScope {
    fn fail_after(successful_allocations: usize) -> Self {
        let previous =
            FAIL_ALLOCATION_AFTER.with(|slot| slot.replace(Some(successful_allocations)));
        Self(previous)
    }
}

#[cfg(test)]
impl Drop for AllocationFaultScope {
    fn drop(&mut self) {
        FAIL_ALLOCATION_AFTER.with(|slot| slot.set(self.0));
    }
}

#[cfg(test)]
pub(crate) fn with_allocation_failure_after<T>(
    successful_allocations: usize,
    operation: impl FnOnce() -> T,
) -> T {
    let _fault = AllocationFaultScope::fail_after(successful_allocations);
    operation()
}

#[cfg(test)]
pub(crate) fn budget_final_drop_count_for_test() -> usize {
    BUDGET_FINAL_DROPS.with(std::cell::Cell::get)
}

fn try_alloc(layout: Layout) -> Result<NonNull<u8>, EvidenceAllocError> {
    if layout.size() == 0 || layout.size() > isize::MAX as usize {
        return Err(EvidenceAllocError::Layout);
    }
    #[cfg(test)]
    {
        ALLOCATION_ATTEMPTS.with(|count| count.set(count.get() + 1));
        let should_fail = FAIL_ALLOCATION_AFTER.with(|slot| match slot.get() {
            None => false,
            Some(0) => true,
            Some(remaining) => {
                slot.set(Some(remaining - 1));
                false
            }
        });
        if should_fail {
            return Err(EvidenceAllocError::Allocation);
        }
        ALLOCATION_COUNT.with(|count| count.set(count.get() + 1));
    }
    // SAFETY: `Layout` is validated by its constructor and the size check
    // above; null is handled by the caller.
    NonNull::new(unsafe { alloc(layout) }).ok_or(EvidenceAllocError::Allocation)
}

unsafe fn dealloc_exact(ptr: NonNull<u8>, layout: Layout) {
    #[cfg(test)]
    DEALLOCATION_COUNT.with(|count| count.set(count.get() + 1));
    // SAFETY: the caller must supply the original global-allocator pointer and
    // the exact Layout passed to `try_alloc`.
    unsafe { dealloc(ptr.as_ptr(), layout) };
}

struct AllocationGuard {
    ptr: NonNull<u8>,
    layout: Layout,
}

impl Drop for AllocationGuard {
    fn drop(&mut self) {
        // SAFETY: this guard is created only for one live allocation and owns
        // its unique deallocation responsibility.
        unsafe { dealloc_exact(self.ptr, self.layout) };
    }
}

/// Fixed-capacity initialized prefix. There is deliberately no growth API.
///
/// The pointer/layout/initialized-prefix relation is upheld by this module's
/// private methods. `into_vec` is private and transfers only a fully valid
/// global-allocator allocation with its exact capacity.
struct ExactBuffer<T: EvidenceElement> {
    ptr: NonNull<T>,
    layout: Option<Layout>,
    initialized: usize,
    capacity: usize,
    _marker: PhantomData<T>,
}

impl<T: EvidenceElement> std::fmt::Debug for ExactBuffer<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExactBuffer")
            .field("initialized", &self.initialized)
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl<T: EvidenceElement> ExactBuffer<T> {
    fn layout_for(capacity: usize) -> Result<Option<Layout>, EvidenceAllocError> {
        if size_of::<T>() == 0 {
            return Err(EvidenceAllocError::ZeroSizedType);
        }
        if capacity == 0 {
            return Ok(None);
        }
        let layout = Layout::array::<T>(capacity).map_err(|_| EvidenceAllocError::Layout)?;
        if layout.size() > isize::MAX as usize || !layout.align().is_power_of_two() {
            return Err(EvidenceAllocError::Layout);
        }
        Ok(Some(layout))
    }

    fn try_with_capacity(capacity: usize) -> Result<Self, EvidenceAllocError> {
        let layout = Self::layout_for(capacity)?;
        let ptr = match layout {
            None => NonNull::dangling(),
            Some(layout) => try_alloc(layout)?.cast::<T>(),
        };
        Ok(Self {
            ptr,
            layout,
            initialized: 0,
            capacity,
            _marker: PhantomData,
        })
    }

    fn capacity(&self) -> usize {
        self.capacity
    }

    fn len(&self) -> usize {
        self.initialized
    }

    fn as_slice(&self) -> &[T] {
        // SAFETY: exactly `initialized` values were written, and the buffer
        // owns the allocation for the returned borrow's lifetime.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.initialized) }
    }

    fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: exactly `initialized` values were written and `&mut self`
        // provides exclusive access to the allocation.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.initialized) }
    }

    fn try_push(&mut self, value: T) -> Result<(), T> {
        let Some(next) = self.initialized.checked_add(1) else {
            return Err(value);
        };
        if next > self.capacity {
            return Err(value);
        }
        // SAFETY: next is within capacity and this slot is not initialized.
        unsafe { self.ptr.as_ptr().add(self.initialized).write(value) };
        self.initialized = next;
        Ok(())
    }

    /// Test-only proof of exact allocator ownership transfer; production never
    /// exposes a growth-capable `Vec` for admitted evidence backing.
    #[cfg(test)]
    fn into_vec(self) -> Vec<T> {
        if self.capacity == 0 {
            return Vec::new();
        }
        let mut this = ManuallyDrop::new(self);
        let ptr = this.ptr.as_ptr();
        let len = this.initialized;
        let capacity = this.capacity;
        // Prevent `ExactBuffer::drop` from destroying or deallocating the
        // transferred allocation. The `Vec` takes both duties.
        this.initialized = 0;
        this.layout = None;
        // SAFETY: `ptr` came from the global allocator with
        // `Layout::array::<T>(capacity)`, exactly `len` values are initialized,
        // and this is the sole ownership transfer. The private recipient must
        // not grow beyond the admitted capacity.
        unsafe { Vec::from_raw_parts(ptr, len, capacity) }
    }
}

unsafe impl<T: EvidenceElement> Send for ExactBuffer<T> {}
// SAFETY: shared access exposes only `&[T]`; mutation requires `&mut self`.
unsafe impl<T: EvidenceElement> Sync for ExactBuffer<T> {}

impl<T: EvidenceElement> Drop for ExactBuffer<T> {
    fn drop(&mut self) {
        let Some(layout) = self.layout.take() else {
            return;
        };
        let initialized = std::mem::replace(&mut self.initialized, 0);
        let allocation = AllocationGuard {
            ptr: self.ptr.cast::<u8>(),
            layout,
        };
        if initialized != 0 {
            // SAFETY: the prefix contains exactly `initialized` initialized
            // elements; the guard frees its backing even if a destructor
            // unwinds. Slice drop glue handles the remaining elements during
            // ordinary single-panic unwinding.
            unsafe {
                std::ptr::drop_in_place(std::ptr::slice_from_raw_parts_mut(
                    self.ptr.as_ptr(),
                    initialized,
                ));
            }
        }
        drop(allocation);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReservationClass {
    Bytes,
    Context,
    Report,
}

#[derive(Debug)]
#[cfg_attr(test, derive(Clone, Copy, PartialEq, Eq))]
struct EvidenceLedger {
    cap: u64,
    committed_bytes: u64,
    pending_bytes: u64,
    committed_contexts: usize,
    pending_contexts: usize,
    committed_reports: usize,
    pending_reports: usize,
}

impl EvidenceLedger {
    fn new(cap: u64, initial_occupancy: u64, budget_cell_bytes: u64) -> Option<Self> {
        let committed_bytes = initial_occupancy.checked_add(budget_cell_bytes)?;
        (committed_bytes <= cap).then_some(Self {
            cap,
            committed_bytes,
            pending_bytes: 0,
            committed_contexts: 0,
            pending_contexts: 0,
            committed_reports: 0,
            pending_reports: 0,
        })
    }

    fn reserve(&mut self, bytes: u64, class: ReservationClass) -> Result<(), LedgerError> {
        let occupancy = self
            .committed_bytes
            .checked_add(self.pending_bytes)
            .ok_or(LedgerError::Arithmetic)?;
        let projected = occupancy
            .checked_add(bytes)
            .ok_or(LedgerError::Arithmetic)?;
        if projected > self.cap {
            return Err(LedgerError::Admission);
        }

        let (pending_count, committed_count, max_count) = match class {
            ReservationClass::Bytes => (None, None, None),
            ReservationClass::Context => (
                Some(self.pending_contexts),
                Some(self.committed_contexts),
                Some(MAX_CONTEXTS),
            ),
            ReservationClass::Report => (
                Some(self.pending_reports),
                Some(self.committed_reports),
                Some(MAX_REPORTS),
            ),
        };
        if let (Some(pending), Some(committed), Some(max)) =
            (pending_count, committed_count, max_count)
        {
            if pending
                .checked_add(committed)
                .ok_or(LedgerError::Arithmetic)?
                >= max
            {
                return Err(LedgerError::Quota);
            }
        }

        let next_pending_bytes = self
            .pending_bytes
            .checked_add(bytes)
            .ok_or(LedgerError::Arithmetic)?;
        let next_pending_class = match class {
            ReservationClass::Bytes => None,
            ReservationClass::Context => Some(
                self.pending_contexts
                    .checked_add(1)
                    .ok_or(LedgerError::Arithmetic)?,
            ),
            ReservationClass::Report => Some(
                self.pending_reports
                    .checked_add(1)
                    .ok_or(LedgerError::Arithmetic)?,
            ),
        };

        self.pending_bytes = next_pending_bytes;
        match (class, next_pending_class) {
            (ReservationClass::Context, Some(value)) => self.pending_contexts = value,
            (ReservationClass::Report, Some(value)) => self.pending_reports = value,
            _ => {}
        }
        Ok(())
    }

    fn commit(&mut self, bytes: u64, class: ReservationClass) -> Result<(), LedgerError> {
        let next_pending_bytes = self
            .pending_bytes
            .checked_sub(bytes)
            .ok_or(LedgerError::Invariant)?;
        let next_committed_bytes = self
            .committed_bytes
            .checked_add(bytes)
            .ok_or(LedgerError::Arithmetic)?;
        let next_counts = match class {
            ReservationClass::Bytes => None,
            ReservationClass::Context => Some((
                self.pending_contexts
                    .checked_sub(1)
                    .ok_or(LedgerError::Invariant)?,
                self.committed_contexts
                    .checked_add(1)
                    .ok_or(LedgerError::Arithmetic)?,
            )),
            ReservationClass::Report => Some((
                self.pending_reports
                    .checked_sub(1)
                    .ok_or(LedgerError::Invariant)?,
                self.committed_reports
                    .checked_add(1)
                    .ok_or(LedgerError::Arithmetic)?,
            )),
        };

        self.pending_bytes = next_pending_bytes;
        self.committed_bytes = next_committed_bytes;
        match (class, next_counts) {
            (ReservationClass::Context, Some((pending, committed))) => {
                self.pending_contexts = pending;
                self.committed_contexts = committed;
            }
            (ReservationClass::Report, Some((pending, committed))) => {
                self.pending_reports = pending;
                self.committed_reports = committed;
            }
            _ => {}
        }
        Ok(())
    }

    fn release_pending(&mut self, bytes: u64, class: ReservationClass) -> Result<(), LedgerError> {
        let next_bytes = self
            .pending_bytes
            .checked_sub(bytes)
            .ok_or(LedgerError::Invariant)?;
        let next_count = match class {
            ReservationClass::Bytes => None,
            ReservationClass::Context => Some(
                self.pending_contexts
                    .checked_sub(1)
                    .ok_or(LedgerError::Invariant)?,
            ),
            ReservationClass::Report => Some(
                self.pending_reports
                    .checked_sub(1)
                    .ok_or(LedgerError::Invariant)?,
            ),
        };
        self.pending_bytes = next_bytes;
        match (class, next_count) {
            (ReservationClass::Context, Some(value)) => self.pending_contexts = value,
            (ReservationClass::Report, Some(value)) => self.pending_reports = value,
            _ => {}
        }
        Ok(())
    }

    fn release_committed(
        &mut self,
        bytes: u64,
        class: ReservationClass,
    ) -> Result<(), LedgerError> {
        let next_bytes = self
            .committed_bytes
            .checked_sub(bytes)
            .ok_or(LedgerError::Invariant)?;
        let next_count = match class {
            ReservationClass::Bytes => None,
            ReservationClass::Context => Some(
                self.committed_contexts
                    .checked_sub(1)
                    .ok_or(LedgerError::Invariant)?,
            ),
            ReservationClass::Report => Some(
                self.committed_reports
                    .checked_sub(1)
                    .ok_or(LedgerError::Invariant)?,
            ),
        };
        self.committed_bytes = next_bytes;
        match (class, next_count) {
            (ReservationClass::Context, Some(value)) => self.committed_contexts = value,
            (ReservationClass::Report, Some(value)) => self.committed_reports = value,
            _ => {}
        }
        Ok(())
    }
}

struct BudgetCell {
    refs: AtomicUsize,
    ledger: Mutex<EvidenceLedger>,
}

struct BudgetHandle(NonNull<BudgetCell>);

impl std::fmt::Debug for BudgetHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("BudgetHandle").field(&self.0).finish()
    }
}

// SAFETY: `BudgetCell` is accessed only through atomics and its ledger mutex;
// it contains no thread-affine data.
unsafe impl Send for BudgetHandle {}
// SAFETY: ledger mutation is serialized by its mutex and refcounts are atomic.
unsafe impl Sync for BudgetHandle {}

impl BudgetHandle {
    fn try_new(cap: u64, initial_occupancy: u64) -> Result<Self, LedgerError> {
        let layout = Layout::new::<BudgetCell>();
        if layout.size() > isize::MAX as usize {
            return Err(LedgerError::Arithmetic);
        }
        let standing_bytes = u64::try_from(layout.size())
            .map_err(|_| LedgerError::Arithmetic)?
            .checked_add(
                u64::try_from(size_of::<BudgetHandle>()).map_err(|_| LedgerError::Arithmetic)?,
            )
            .ok_or(LedgerError::Arithmetic)?;
        let ledger = EvidenceLedger::new(cap, initial_occupancy, standing_bytes)
            .ok_or(LedgerError::Admission)?;
        let ptr = try_alloc(layout)
            .map_err(|_| LedgerError::Admission)?
            .cast::<BudgetCell>();
        // All fallible validation and allocation precede initialization. Moving
        // the already-built ledger and observer into this cell cannot fail.
        unsafe {
            ptr.as_ptr().write(BudgetCell {
                refs: AtomicUsize::new(1),
                ledger: Mutex::new(ledger),
            });
        }
        Ok(Self(ptr))
    }

    fn try_clone(&self) -> Result<Self, LedgerError> {
        // SAFETY: this live handle keeps the allocation alive.
        let refs = unsafe { &self.0.as_ref().refs };
        let mut current = refs.load(Ordering::Relaxed);
        loop {
            let next = current.checked_add(1).ok_or(LedgerError::Arithmetic)?;
            match refs.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return Ok(Self(self.0)),
                Err(observed) => current = observed,
            }
        }
    }

    fn lock(&self) -> MutexGuard<'_, EvidenceLedger> {
        // Critical sections below perform only checked scalar calculations and
        // assignments; they never allocate, call user code, or drop payloads.
        // Thus poisoning cannot arise from a supported unwind path. Recovering
        // the guard is safe only under that private invariant, not by itself.
        // SAFETY: this live handle keeps the allocation alive.
        unsafe { &self.0.as_ref().ledger }
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn reserve(&self, bytes: u64, class: ReservationClass) -> Result<PendingCharge, LedgerError> {
        // Acquire the owned handle before mutating ledger state. Every refusal
        // below drops it without leaving a reservation behind.
        let owned = self.try_clone()?;
        let result = self.lock().reserve(bytes, class);
        match result {
            Ok(()) => Ok(PendingCharge {
                budget: owned,
                bytes,
                class,
                active: true,
            }),
            Err(error) => {
                drop(owned);
                Err(error)
            }
        }
    }

    fn occupancy(&self) -> (u64, u64, usize, usize, usize, usize) {
        let ledger = self.lock();
        (
            ledger.committed_bytes,
            ledger.pending_bytes,
            ledger.committed_contexts,
            ledger.pending_contexts,
            ledger.committed_reports,
            ledger.pending_reports,
        )
    }

    fn lower_cap(&self, cap: u64) {
        self.lock().cap = cap;
    }

    #[cfg(test)]
    fn set_refcount_for_test(&self, value: usize) {
        // SAFETY: the test holds the only reference and restores it before
        // destruction.
        unsafe { self.0.as_ref().refs.store(value, Ordering::Relaxed) };
    }
}

impl Drop for BudgetHandle {
    fn drop(&mut self) {
        // SAFETY: private non-cloneable handles increment once and decrement
        // once. A live borrowed handle prevents its owner from being dropped.
        let previous = unsafe { self.0.as_ref() }
            .refs
            .fetch_sub(1, Ordering::Release);
        if previous == 0 {
            std::process::abort();
        }
        if previous == 1 {
            fence(Ordering::Acquire);
            let layout = Layout::new::<BudgetCell>();
            #[cfg(test)]
            BUDGET_FINAL_DROPS.with(|count| count.set(count.get() + 1));
            // SAFETY: this is the final reference; no ledger owner or lease
            // remains. No payload charge release is needed after the ledger
            // itself ceases to exist.
            unsafe {
                std::ptr::drop_in_place(self.0.as_ptr());
                dealloc_exact(self.0.cast::<u8>(), layout);
            }
        }
    }
}

struct PendingCharge {
    budget: BudgetHandle,
    bytes: u64,
    class: ReservationClass,
    active: bool,
}

impl std::fmt::Debug for PendingCharge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingCharge")
            .field("bytes", &self.bytes)
            .field("class", &self.class)
            .field("active", &self.active)
            .finish()
    }
}

impl PendingCharge {
    fn commit(self) -> Result<CommittedCharge, (Self, LedgerError)> {
        let result = self.budget.lock().commit(self.bytes, self.class);
        if let Err(error) = result {
            return Err((self, error));
        }
        let mut this = ManuallyDrop::new(self);
        this.active = false;
        // SAFETY: this is the single handle owned by the reservation. The
        // ledger transition succeeded and ManuallyDrop suppresses rollback.
        let budget = unsafe { std::ptr::read(&this.budget) };
        Ok(CommittedCharge {
            budget,
            bytes: this.bytes,
            class: this.class,
        })
    }

    fn commit_unleased(self) -> Result<(), (Self, LedgerError)> {
        if self.class != ReservationClass::Bytes {
            return Err((self, LedgerError::WrongReservationKind));
        }
        let result = self.budget.lock().commit(self.bytes, self.class);
        if let Err(error) = result {
            return Err((self, error));
        }
        let mut this = ManuallyDrop::new(self);
        this.active = false;
        // SAFETY: successful commit transfers the byte ownership to the map;
        // suppressing Drop prevents rollback, and this moves the sole handle.
        let budget = unsafe { std::ptr::read(&this.budget) };
        drop(budget);
        Ok(())
    }
}

impl Drop for PendingCharge {
    fn drop(&mut self) {
        if self.active {
            if self
                .budget
                .lock()
                .release_pending(self.bytes, self.class)
                .is_err()
            {
                std::process::abort();
            }
            self.active = false;
        }
    }
}

struct CommittedCharge {
    budget: BudgetHandle,
    bytes: u64,
    class: ReservationClass,
}

impl std::fmt::Debug for CommittedCharge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommittedCharge")
            .field("bytes", &self.bytes)
            .field("class", &self.class)
            .finish()
    }
}

impl Drop for CommittedCharge {
    fn drop(&mut self) {
        if self
            .budget
            .lock()
            .release_committed(self.bytes, self.class)
            .is_err()
        {
            std::process::abort();
        }
        // `budget` drops after the covered owner has dropped this lease.
    }
}

/// The backing field is declared before the lease: Rust drops fields in
/// declaration order, so the allocation guard runs before the charge releases.
#[derive(Debug)]
struct ChargedBuffer<T: EvidenceElement> {
    backing: ExactBuffer<T>,
    _lease: CommittedCharge,
}

impl<T: EvidenceElement> ChargedBuffer<T> {
    fn try_new(
        budget: &BudgetHandle,
        capacity: usize,
        class: ReservationClass,
    ) -> Result<Self, LedgerError> {
        let layout = ExactBuffer::<T>::layout_for(capacity).map_err(|_| LedgerError::Arithmetic)?;
        let backing_bytes = layout
            .map(|layout| u64::try_from(layout.size()).map_err(|_| LedgerError::Arithmetic))
            .transpose()?
            .unwrap_or(0);
        let total = u64::try_from(size_of::<Self>())
            .map_err(|_| LedgerError::Arithmetic)?
            .checked_add(backing_bytes)
            .ok_or(LedgerError::Arithmetic)?;
        let pending = budget.reserve(total, class)?;
        let backing =
            ExactBuffer::try_with_capacity(capacity).map_err(|_| LedgerError::Admission)?;
        let lease = match pending.commit() {
            Ok(lease) => lease,
            Err((pending, _error)) => {
                drop(backing);
                drop(pending);
                return Err(LedgerError::Invariant);
            }
        };
        Ok(Self {
            backing,
            _lease: lease,
        })
    }
}

#[cfg_attr(test, derive(Clone, Debug, PartialEq, Eq))]
pub(crate) struct SnapshotMember {
    validator_id: u64,
    voting_power: u64,
    public_key: Vec<u8>,
}

impl SnapshotMember {
    pub(crate) fn new(validator_id: u64, voting_power: u64, public_key: Vec<u8>) -> Self {
        Self {
            validator_id,
            voting_power,
            public_key,
        }
    }

    pub(crate) fn validator_id(&self) -> u64 {
        self.validator_id
    }

    pub(crate) fn voting_power(&self) -> u64 {
        self.voting_power
    }

    pub(crate) fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub(crate) fn public_key_capacity(&self) -> usize {
        self.public_key.capacity()
    }
}

#[cfg_attr(test, derive(Clone, Debug, PartialEq, Eq))]
struct SnapshotPayload {
    runtime_chain_id: ChainId,
    authorized_epoch: u64,
    suite_id: ConsensusSigSuiteId,
    domain: ProposalVoteSigningDomainV2,
    members: Vec<SnapshotMember>,
}

/// Owned, allocation-preserving facade over the exact snapshot payload used
/// by the context cell. Refusal returns this same payload by move.
#[cfg_attr(test, derive(Debug))]
pub(crate) struct VoteContextInput(SnapshotPayload);

impl VoteContextInput {
    pub(crate) fn new(
        runtime_chain_id: ChainId,
        authorized_epoch: u64,
        suite_id: ConsensusSigSuiteId,
        domain: ProposalVoteSigningDomainV2,
        members: Vec<SnapshotMember>,
    ) -> Self {
        Self(SnapshotPayload {
            runtime_chain_id,
            authorized_epoch,
            suite_id,
            domain,
            members,
        })
    }

    pub(crate) fn runtime_chain_id(&self) -> ChainId {
        self.0.runtime_chain_id
    }

    pub(crate) fn authorized_epoch(&self) -> u64 {
        self.0.authorized_epoch
    }

    pub(crate) fn suite_id(&self) -> ConsensusSigSuiteId {
        self.0.suite_id
    }

    pub(crate) fn domain(&self) -> &ProposalVoteSigningDomainV2 {
        &self.0.domain
    }

    pub(crate) fn members(&self) -> &[SnapshotMember] {
        &self.0.members
    }

    pub(crate) fn members_capacity(&self) -> usize {
        self.0.members.capacity()
    }

    pub(crate) fn within_profile_capacity(&self) -> bool {
        self.0.members.capacity() <= MAX_MEMBERS
    }

    pub(crate) fn checked_charge(&self) -> Result<u64, ContextInstallError> {
        self.0.checked_charge().map_err(map_ledger_install_error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContextInstallError {
    AlreadyInstalled,
    InvalidContext,
    Budget,
    ContextQuota,
    Arithmetic,
    Allocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VoteAdmissionError {
    NoContext,
    SenderIndexMismatch,
    EpochMismatch,
    DomainMismatch,
    SuiteMismatch,
    SignatureShape,
    InvalidSignature,
    Budget,
    Arithmetic,
}

pub(crate) struct ContextInstallRefusal {
    pub(crate) input: VoteContextInput,
    pub(crate) error: ContextInstallError,
}

impl std::fmt::Debug for ContextInstallRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContextInstallRefusal")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

pub(crate) struct VoteAdmissionRefusal {
    pub(crate) vote: Vote,
    pub(crate) error: VoteAdmissionError,
}

impl std::fmt::Debug for VoteAdmissionRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VoteAdmissionRefusal")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
/// Opaque shared authority. Its raw handle and all unrestricted reservation
/// operations remain private to this module.
#[derive(Debug)]
pub(crate) struct EvidenceBudget {
    inner: BudgetHandle,
}

impl EvidenceBudget {
    pub(crate) fn try_new(
        cap: u64,
        initial_map_qc_bytes: u64,
    ) -> Result<Self, ContextInstallError> {
        BudgetHandle::try_new(cap, initial_map_qc_bytes)
            .map(|inner| Self { inner })
            .map_err(map_ledger_install_error)
    }

    pub(crate) fn try_clone(&self) -> Result<Self, ContextInstallError> {
        self.inner
            .try_clone()
            .map(|inner| Self { inner })
            .map_err(map_ledger_install_error)
    }

    pub(crate) fn lower_cap(&self, cap: u64) {
        self.inner.lower_cap(cap);
    }

    pub(crate) fn occupancy(&self) -> (u64, u64, usize, usize) {
        let (committed, pending, contexts, pending_contexts, _, _) = self.inner.occupancy();
        (committed, pending, contexts, pending_contexts)
    }

    pub(crate) fn same_authority(&self, other: &Self) -> bool {
        self.inner.0 == other.inner.0
    }

    pub(crate) fn reserve_qc_replacement(
        &self,
        state_id: u64,
        old_bytes: u64,
        new_bytes: u64,
    ) -> Result<QcReplacement, EvidenceAccountingError> {
        let delta = if new_bytes > old_bytes {
            new_bytes
                .checked_sub(old_bytes)
                .ok_or(EvidenceAccountingError::Arithmetic)?
        } else {
            0
        };
        let (committed, pending, _, _, _, _) = self.inner.occupancy();
        let total = committed
            .checked_add(pending)
            .ok_or(EvidenceAccountingError::Arithmetic)?;
        let projected = total
            .checked_sub(old_bytes)
            .and_then(|bytes| bytes.checked_add(new_bytes))
            .ok_or(EvidenceAccountingError::Arithmetic)?;
        let cap = self.inner.lock().cap;
        if projected > cap {
            return Err(EvidenceAccountingError::Admission);
        }
        let authority = self
            .inner
            .try_clone()
            .map_err(|_| EvidenceAccountingError::Arithmetic)?;
        let pending_charge = if delta == 0 {
            None
        } else {
            Some(
                self.inner
                    .reserve(delta, ReservationClass::Bytes)
                    .map_err(map_accounting_error)?,
            )
        };
        Ok(QcReplacement {
            authority,
            state_id,
            old_bytes,
            new_bytes,
            pending: pending_charge,
        })
    }

    pub(crate) fn commit_qc_replacement(
        &self,
        mut replacement: QcReplacement,
        state_id: u64,
        old_bytes: u64,
        new_bytes: u64,
    ) {
        if !self.qc_replacement_matches(&replacement, state_id, old_bytes, new_bytes) {
            std::process::abort();
        }
        if let Some(pending) = replacement.pending.take() {
            if pending.commit_unleased().is_err() {
                std::process::abort();
            }
        } else if old_bytes > new_bytes {
            if self
                .inner
                .lock()
                .release_committed(old_bytes - new_bytes, ReservationClass::Bytes)
                .is_err()
            {
                std::process::abort();
            }
        }
    }

    pub(crate) fn qc_replacement_matches(
        &self,
        replacement: &QcReplacement,
        state_id: u64,
        old_bytes: u64,
        new_bytes: u64,
    ) -> bool {
        replacement.state_id == state_id
            && replacement.old_bytes == old_bytes
            && replacement.new_bytes == new_bytes
            && replacement.authority.0 == self.inner.0
    }

    pub(crate) fn release_qc_bytes(&self, bytes: u64) {
        if bytes != 0
            && self
                .inner
                .lock()
                .release_committed(bytes, ReservationClass::Bytes)
                .is_err()
        {
            std::process::abort();
        }
    }

    pub(crate) fn projected_qc_replacement(
        &self,
        old_bytes: u64,
        new_bytes: u64,
    ) -> Result<bool, EvidenceAccountingError> {
        let (committed, pending, _, _, _, _) = self.inner.occupancy();
        let total = committed
            .checked_add(pending)
            .ok_or(EvidenceAccountingError::Arithmetic)?;
        let projected = total
            .checked_sub(old_bytes)
            .and_then(|bytes| bytes.checked_add(new_bytes))
            .ok_or(EvidenceAccountingError::Arithmetic)?;
        Ok(projected <= self.inner.lock().cap)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvidenceAccountingError {
    Admission,
    Arithmetic,
    Invariant,
}

#[derive(Debug)]
pub(crate) struct QcReplacement {
    authority: BudgetHandle,
    state_id: u64,
    old_bytes: u64,
    new_bytes: u64,
    pending: Option<PendingCharge>,
}

impl Drop for QcReplacement {
    fn drop(&mut self) {
        // Any still-pending positive delta is cancelled by PendingCharge.
    }
}

fn map_accounting_error(error: LedgerError) -> EvidenceAccountingError {
    match error {
        LedgerError::Admission | LedgerError::Quota => EvidenceAccountingError::Admission,
        LedgerError::Allocation => EvidenceAccountingError::Invariant,
        LedgerError::Arithmetic | LedgerError::WrongReservationKind => {
            EvidenceAccountingError::Arithmetic
        }
        LedgerError::InsufficientCoverage | LedgerError::Invariant => {
            EvidenceAccountingError::Invariant
        }
    }
}

fn map_ledger_install_error(error: LedgerError) -> ContextInstallError {
    match error {
        LedgerError::Admission => ContextInstallError::Budget,
        LedgerError::Quota => ContextInstallError::ContextQuota,
        LedgerError::Allocation => ContextInstallError::Allocation,
        LedgerError::Arithmetic => ContextInstallError::Arithmetic,
        _ => ContextInstallError::Allocation,
    }
}

pub(crate) struct ActiveVoteContext {
    context: ContextHandle,
    _wrapper_charge: CommittedCharge,
}

impl std::fmt::Debug for ActiveVoteContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActiveVoteContext")
            .field("context", &"<installed>")
            .finish_non_exhaustive()
    }
}

pub(crate) struct VerifiedVoteToken {
    vote: Vote,
    context: ContextHandle,
    _charge: CommittedCharge,
}

impl std::fmt::Debug for VerifiedVoteToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedVoteToken")
            .field("vote", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl VerifiedVoteToken {
    #[cfg(test)]
    pub(crate) fn vote(&self) -> &Vote {
        &self.vote
    }
}

impl ActiveVoteContext {
    pub(crate) fn try_install(
        budget: &EvidenceBudget,
        input: VoteContextInput,
    ) -> Result<Self, (VoteContextInput, ContextInstallError)> {
        let VoteContextInput(payload) = input;
        let context_bytes = match payload.checked_charge() {
            Ok(bytes) => bytes,
            Err(error) => return Err((VoteContextInput(payload), map_ledger_install_error(error))),
        };
        let wrapper_bytes = match u64::try_from(size_of::<Option<Self>>()) {
            Ok(bytes) => bytes,
            Err(_) => return Err((VoteContextInput(payload), ContextInstallError::Arithmetic)),
        };
        let context_pending = match budget
            .inner
            .reserve(context_bytes, ReservationClass::Context)
        {
            Ok(pending) => pending,
            Err(error) => return Err((VoteContextInput(payload), map_ledger_install_error(error))),
        };
        let wrapper_pending = match budget.inner.reserve(wrapper_bytes, ReservationClass::Bytes) {
            Ok(pending) => pending,
            Err(error) => {
                drop(context_pending);
                return Err((VoteContextInput(payload), map_ledger_install_error(error)));
            }
        };
        let wrapper_charge = match wrapper_pending.commit() {
            Ok(charge) => charge,
            Err((pending, error)) => {
                drop(pending);
                drop(context_pending);
                return Err((VoteContextInput(payload), map_ledger_install_error(error)));
            }
        };
        match ContextHandle::try_new(payload, context_pending) {
            Ok(context) => Ok(Self {
                context,
                _wrapper_charge: wrapper_charge,
            }),
            Err((payload, pending, error)) => {
                drop(pending);
                drop(wrapper_charge);
                Err((VoteContextInput(payload), map_ledger_install_error(error)))
            }
        }
    }

    #[cfg(test)]
    fn first_key_ptr(&self) -> *const u8 {
        let payload = unsafe { &self.context.0.as_ref().payload };
        payload.members[0].public_key.as_ptr()
    }

    pub(crate) fn try_admit_vote(
        &self,
        claimed_sender: u64,
        vote: Vote,
        current_engine_epoch: u64,
    ) -> Result<VerifiedVoteToken, (Vote, VoteAdmissionError)> {
        let payload = unsafe { &self.context.0.as_ref().payload };
        if vote.validator_index as usize >= payload.members.len()
            || payload.members[vote.validator_index as usize].validator_id != claimed_sender
            || vote.validator_index as u64 != claimed_sender
        {
            return Err((vote, VoteAdmissionError::SenderIndexMismatch));
        }
        if vote.epoch != payload.authorized_epoch || vote.epoch != current_engine_epoch {
            return Err((vote, VoteAdmissionError::EpochMismatch));
        }
        if vote.suite_id != SUITE_PQ_RESERVED_1.0 || payload.suite_id != SUITE_PQ_RESERVED_1 {
            return Err((vote, VoteAdmissionError::SuiteMismatch));
        }
        if vote.chain_id != payload.domain.expected_wire_chain_id() {
            return Err((vote, VoteAdmissionError::DomainMismatch));
        }
        let member = &payload.members[vote.validator_index as usize];
        if member.public_key.len() != ML_DSA_44_PUBLIC_KEY_SIZE
            || member.public_key.capacity() != ML_DSA_44_PUBLIC_KEY_SIZE
            || vote.signature.len() != ML_DSA_44_SIGNATURE_SIZE
            || vote.signature.capacity() != ML_DSA_44_SIGNATURE_SIZE
        {
            return Err((vote, VoteAdmissionError::SignatureShape));
        }
        let context = match self.context.try_clone() {
            Ok(context) => context,
            Err(_) => return Err((vote, VoteAdmissionError::Arithmetic)),
        };
        let token_bytes = match u64::try_from(size_of::<VerifiedVoteToken>())
            .ok()
            .and_then(|bytes| {
                u64::try_from(vote.signature.capacity())
                    .ok()
                    .and_then(|signature_bytes| bytes.checked_add(signature_bytes))
            })
        {
            Some(bytes) => bytes,
            None => {
                drop(context);
                return Err((vote, VoteAdmissionError::Arithmetic));
            }
        };
        let pending = match context_budget(&self.context)
            .and_then(|budget| budget.reserve(token_bytes, ReservationClass::Bytes))
        {
            Ok(pending) => pending,
            Err(error) => {
                drop(context);
                return Err((vote, map_vote_budget_error(error)));
            }
        };
        let preimage = payload.domain.vote_preimage(&vote);
        if MlDsa44Backend::verify(&member.public_key, &preimage, &vote.signature).is_err() {
            drop(pending);
            drop(context);
            return Err((vote, VoteAdmissionError::InvalidSignature));
        }
        let charge = match pending.commit() {
            Ok(charge) => charge,
            Err((pending, _)) => {
                drop(pending);
                drop(context);
                return Err((vote, VoteAdmissionError::Arithmetic));
            }
        };
        Ok(VerifiedVoteToken {
            vote,
            context,
            _charge: charge,
        })
    }
}

fn context_budget(context: &ContextHandle) -> Result<&BudgetHandle, LedgerError> {
    // SAFETY: a live context keeps its cell and committed lease alive.
    let lease = unsafe { &context.0.as_ref().lease };
    Ok(&lease.budget)
}

fn map_vote_budget_error(error: LedgerError) -> VoteAdmissionError {
    match error {
        LedgerError::Admission | LedgerError::Quota => VoteAdmissionError::Budget,
        LedgerError::Allocation => VoteAdmissionError::Arithmetic,
        _ => VoteAdmissionError::Arithmetic,
    }
}

impl SnapshotPayload {
    fn checked_charge(&self) -> Result<u64, LedgerError> {
        if self.suite_id != SUITE_PQ_RESERVED_1 || self.members.is_empty() {
            return Err(LedgerError::Admission);
        }
        if self.members.len() > MAX_MEMBERS
            || self.runtime_chain_id != self.domain.runtime_chain_id()
        {
            return Err(LedgerError::Admission);
        }
        let mut power = 0u64;
        let mut bytes = u64::try_from(size_of::<ContextCell>())
            .map_err(|_| LedgerError::Arithmetic)?
            .checked_add(
                u64::try_from(self.members.capacity())
                    .map_err(|_| LedgerError::Arithmetic)?
                    .checked_mul(
                        u64::try_from(size_of::<SnapshotMember>())
                            .map_err(|_| LedgerError::Arithmetic)?,
                    )
                    .ok_or(LedgerError::Arithmetic)?,
            )
            .ok_or(LedgerError::Arithmetic)?;
        if self.members.capacity() < self.members.len() {
            return Err(LedgerError::Admission);
        }
        for (index, member) in self.members.iter().enumerate() {
            if member.validator_id != index as u64
                || member.voting_power == 0
                || member.public_key.len() != ML_DSA_44_PUBLIC_KEY_SIZE
                || member.public_key.capacity() != ML_DSA_44_PUBLIC_KEY_SIZE
            {
                return Err(LedgerError::Admission);
            }
            power = power
                .checked_add(member.voting_power)
                .ok_or(LedgerError::Arithmetic)?;
            bytes = bytes
                .checked_add(
                    u64::try_from(member.public_key.capacity())
                        .map_err(|_| LedgerError::Arithmetic)?,
                )
                .ok_or(LedgerError::Arithmetic)?;
        }
        if power == 0 || power > u64::MAX / 2 {
            return Err(LedgerError::Admission);
        }
        Ok(bytes)
    }
}

#[repr(C)]
struct ContextCell {
    refs: AtomicUsize,
    payload: ManuallyDrop<SnapshotPayload>,
    lease: ManuallyDrop<CommittedCharge>,
}

struct ContextHandle(NonNull<ContextCell>);

impl std::fmt::Debug for ContextHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ContextHandle").field(&self.0).finish()
    }
}

// SAFETY: a context payload is immutable once installed, and its fields
// (`ChainId`, domain, scalar roster values, and Vec<u8> keys) are Send+Sync.
unsafe impl Send for ContextHandle {}
// SAFETY: shared access never exposes mutable snapshot state; references are
// protected by the atomic context count.
unsafe impl Sync for ContextHandle {}

struct CellDeallocationGuard<T> {
    ptr: NonNull<T>,
    layout: Layout,
}

impl<T> Drop for CellDeallocationGuard<T> {
    fn drop(&mut self) {
        // SAFETY: the final owner moved all owning fields out before this guard
        // runs, and this is the unique cell allocation.
        unsafe { dealloc_exact(self.ptr.cast::<u8>(), self.layout) };
    }
}

impl ContextHandle {
    fn try_new(
        payload: SnapshotPayload,
        pending: PendingCharge,
    ) -> Result<Self, (SnapshotPayload, PendingCharge, LedgerError)> {
        let required = match payload.checked_charge() {
            Ok(required) => required,
            Err(error) => return Err((payload, pending, error)),
        };
        if pending.class != ReservationClass::Context {
            return Err((payload, pending, LedgerError::WrongReservationKind));
        }
        if pending.bytes < required {
            return Err((payload, pending, LedgerError::InsufficientCoverage));
        }
        let layout = Layout::new::<ContextCell>();
        let raw = match try_alloc(layout) {
            Ok(ptr) => ptr.cast::<ContextCell>(),
            Err(_) => return Err((payload, pending, LedgerError::Allocation)),
        };
        let lease = match pending.commit() {
            Ok(lease) => lease,
            Err((pending, error)) => {
                // SAFETY: raw was just allocated with this exact layout and
                // contains no initialized ContextCell yet.
                unsafe { dealloc_exact(raw.cast::<u8>(), layout) };
                return Err((payload, pending, error));
            }
        };
        // Pending coverage was converted to exactly one committed lease. This
        // move-only initialization cannot allocate or fail.
        unsafe {
            raw.as_ptr().write(ContextCell {
                refs: AtomicUsize::new(1),
                payload: ManuallyDrop::new(payload),
                lease: ManuallyDrop::new(lease),
            });
        }
        Ok(Self(raw))
    }

    fn try_clone(&self) -> Result<Self, LedgerError> {
        // SAFETY: this live handle keeps the allocation alive.
        let refs = unsafe { &self.0.as_ref().refs };
        let mut current = refs.load(Ordering::Relaxed);
        loop {
            let next = current.checked_add(1).ok_or(LedgerError::Arithmetic)?;
            match refs.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return Ok(Self(self.0)),
                Err(observed) => current = observed,
            }
        }
    }

    fn ptr_eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }

    #[cfg(test)]
    fn epoch(&self) -> u64 {
        unsafe { &self.0.as_ref().payload }.authorized_epoch
    }

    #[cfg(test)]
    fn suite(&self) -> ConsensusSigSuiteId {
        unsafe { &self.0.as_ref().payload }.suite_id
    }

    #[cfg(test)]
    fn domain_wire_chain(&self) -> u32 {
        unsafe { &self.0.as_ref().payload }
            .domain
            .expected_wire_chain_id()
    }
}

impl Drop for ContextHandle {
    fn drop(&mut self) {
        // SAFETY: handles are private, non-Clone, and each successful
        // `try_clone` increments exactly once.
        let previous = unsafe { self.0.as_ref() }
            .refs
            .fetch_sub(1, Ordering::Release);
        if previous == 0 {
            std::process::abort();
        }
        if previous == 1 {
            fence(Ordering::Acquire);
            #[cfg(test)]
            CONTEXT_FINAL_DROPS.with(|count| count.set(count.get() + 1));
            // Move the lease out before payload destruction. On unwind, local
            // drop order deallocates the cell before releasing the lease.
            let lease = unsafe {
                ManuallyDrop::into_inner(std::ptr::read(std::ptr::addr_of!(
                    (*self.0.as_ptr()).lease
                )))
            };
            let deallocation = CellDeallocationGuard {
                ptr: self.0,
                layout: Layout::new::<ContextCell>(),
            };
            unsafe {
                std::ptr::drop_in_place(
                    std::ptr::addr_of_mut!((*self.0.as_ptr()).payload).cast::<SnapshotPayload>(),
                );
            }
            drop(deallocation);
            drop(lease);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::Arc;
    use std::thread;

    impl EvidenceElement for DropProbe {}
    impl EvidenceElement for PanicProbe {}
    impl EvidenceElement for Option<TableTokenFixture> {}

    #[derive(Debug)]
    struct DropProbe(Arc<AtomicUsize>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[derive(Debug)]
    struct PanicProbe {
        drops: Arc<AtomicUsize>,
        panic_once: Arc<AtomicBool>,
    }

    impl Drop for PanicProbe {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
            if self.panic_once.swap(false, Ordering::Relaxed) {
                panic!("injected element destructor panic");
            }
        }
    }

    #[derive(Debug)]
    struct ObserveRelease {
        budget: BudgetHandle,
        expected_bytes: u64,
        drops: Arc<AtomicUsize>,
        covered_drops: Arc<AtomicUsize>,
        panic_once: Option<Arc<AtomicBool>>,
    }

    impl EvidenceElement for ObserveRelease {}

    impl Drop for ObserveRelease {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
            if self.budget.occupancy() == (self.expected_bytes, 0, 0, 0, 0, 0) {
                self.covered_drops.fetch_add(1, Ordering::Relaxed);
            }
            if let Some(panic_once) = &self.panic_once {
                if panic_once.swap(false, Ordering::Relaxed) {
                    panic!("injected charged element destructor panic");
                }
            }
        }
    }

    #[derive(Debug)]
    struct TableTokenFixture {
        signature: ExactBuffer<u8>,
        _lease: CommittedCharge,
    }

    fn budget(cap: u64) -> BudgetHandle {
        BudgetHandle::try_new(cap, 0).expect("budget allocation")
    }

    fn budget_baseline() -> u64 {
        u64::try_from(size_of::<BudgetCell>() + size_of::<BudgetHandle>()).unwrap()
    }

    fn domain() -> ProposalVoteSigningDomainV2 {
        ProposalVoteSigningDomainV2::try_new(ChainId::new(42), 7, [1; 32], [2; 32])
            .expect("valid v2 domain")
    }

    fn snapshot(epoch: u64, members: usize) -> SnapshotPayload {
        let members = (0..members)
            .map(|validator_id| SnapshotMember {
                validator_id: validator_id as u64,
                voting_power: 1,
                public_key: vec![0xA5; ML_DSA_44_PUBLIC_KEY_SIZE],
            })
            .collect();
        SnapshotPayload {
            runtime_chain_id: ChainId::new(42),
            authorized_epoch: epoch,
            suite_id: SUITE_PQ_RESERVED_1,
            domain: domain(),
            members,
        }
    }

    fn install_context(
        budget: &BudgetHandle,
        payload: SnapshotPayload,
    ) -> Result<ContextHandle, LedgerError> {
        let bytes = payload.checked_charge()?;
        let pending = budget.reserve(bytes, ReservationClass::Context)?;
        match ContextHandle::try_new(payload, pending) {
            Ok(context) => Ok(context),
            Err((payload, pending, error)) => {
                drop(payload);
                drop(pending);
                Err(error)
            }
        }
    }

    fn with_global_counts<R>(f: impl FnOnce() -> R) -> (R, usize, usize) {
        let allocations_before = ALLOCATION_COUNT.with(std::cell::Cell::get);
        let deallocations_before = DEALLOCATION_COUNT.with(std::cell::Cell::get);
        let result = f();
        let allocations = ALLOCATION_COUNT
            .with(std::cell::Cell::get)
            .saturating_sub(allocations_before);
        let deallocations = DEALLOCATION_COUNT
            .with(std::cell::Cell::get)
            .saturating_sub(deallocations_before);
        (result, allocations, deallocations)
    }

    fn assert_context_refusal(
        payload: SnapshotPayload,
        bytes: u64,
        class: ReservationClass,
        expected_error: LedgerError,
    ) {
        let budget = budget(100_000);
        let baseline = *budget.lock();
        let pending = budget.reserve(bytes, class).unwrap();
        let before = *budget.lock();
        let original = payload.clone();
        let members_ptr = payload.members.as_ptr();
        let members_capacity = payload.members.capacity();
        let keys: Vec<_> = payload
            .members
            .iter()
            .map(|member| (member.public_key.as_ptr(), member.public_key.capacity()))
            .collect();
        let pending_identity = (
            pending.budget.0,
            pending.bytes,
            pending.class,
            pending.active,
        );
        let refs = unsafe { budget.0.as_ref().refs.load(Ordering::Relaxed) };
        let attempts = ALLOCATION_ATTEMPTS.with(std::cell::Cell::get);
        let (returned, pending, error) = ContextHandle::try_new(payload, pending).unwrap_err();
        assert_eq!(error, expected_error);
        assert_eq!(ALLOCATION_ATTEMPTS.with(std::cell::Cell::get), attempts);
        assert_eq!(*budget.lock(), before);
        assert_eq!(
            unsafe { budget.0.as_ref().refs.load(Ordering::Relaxed) },
            refs
        );
        assert_eq!(returned, original);
        assert_eq!(returned.members.as_ptr(), members_ptr);
        assert_eq!(returned.members.capacity(), members_capacity);
        for (member, (ptr, capacity)) in returned.members.iter().zip(keys) {
            assert_eq!(member.public_key.as_ptr(), ptr);
            assert_eq!(member.public_key.capacity(), capacity);
        }
        assert_eq!(
            (
                pending.budget.0,
                pending.bytes,
                pending.class,
                pending.active
            ),
            pending_identity,
        );
        drop(returned);
        assert_eq!(*budget.lock(), before);
        drop(pending);
        assert_eq!(*budget.lock(), baseline);
    }

    #[test]
    fn received_vote_evidence_context_constructor_refuses_zero_coverage() {
        assert_context_refusal(
            snapshot(1, 1),
            0,
            ReservationClass::Context,
            LedgerError::InsufficientCoverage,
        );
    }

    #[test]
    fn received_vote_evidence_context_constructor_refuses_one_byte_short() {
        let payload = snapshot(1, 1);
        let required = payload.checked_charge().unwrap();
        assert_context_refusal(
            payload,
            required - 1,
            ReservationClass::Context,
            LedgerError::InsufficientCoverage,
        );
    }

    #[test]
    fn received_vote_evidence_context_constructor_refuses_bytes_reservation() {
        let payload = snapshot(1, 1);
        let required = payload.checked_charge().unwrap();
        assert_context_refusal(
            payload,
            required,
            ReservationClass::Bytes,
            LedgerError::WrongReservationKind,
        );
    }

    #[test]
    fn received_vote_evidence_context_constructor_refuses_report_reservation() {
        let payload = snapshot(1, 1);
        let required = payload.checked_charge().unwrap();
        assert_context_refusal(
            payload,
            required,
            ReservationClass::Report,
            LedgerError::WrongReservationKind,
        );
    }

    #[test]
    fn received_vote_evidence_context_constructor_refuses_invalid_payload() {
        let mut payload = snapshot(1, 1);
        let required = payload.checked_charge().unwrap();
        payload.members[0].voting_power = 0;
        assert_context_refusal(
            payload,
            required,
            ReservationClass::Context,
            LedgerError::Admission,
        );
    }

    #[test]
    fn received_vote_evidence_context_constructor_commits_exact_coverage() {
        let budget = budget(100_000);
        let baseline = *budget.lock();
        let payload = snapshot(1, 1);
        let required = payload.checked_charge().unwrap();
        let pending = budget.reserve(required, ReservationClass::Context).unwrap();
        assert_eq!(
            budget.occupancy(),
            (budget_baseline(), required, 0, 1, 0, 0)
        );
        let attempts = ALLOCATION_ATTEMPTS.with(std::cell::Cell::get);
        let context = ContextHandle::try_new(payload, pending).unwrap();
        assert_eq!(ALLOCATION_ATTEMPTS.with(std::cell::Cell::get), attempts + 1);
        assert_eq!(
            budget.occupancy(),
            (budget_baseline() + required, 0, 1, 0, 0, 0)
        );
        drop(context);
        assert_eq!(*budget.lock(), baseline);
    }

    #[test]
    fn received_vote_evidence_layout_capacity_and_zst_policy() {
        assert_eq!(
            ExactBuffer::<u8>::layout_for(usize::MAX).unwrap_err(),
            EvidenceAllocError::Layout
        );
        assert_eq!(
            ExactBuffer::<()>::try_with_capacity(0).unwrap_err(),
            EvidenceAllocError::ZeroSizedType
        );

        #[repr(align(64))]
        #[derive(Debug)]
        struct Aligned(u64);
        impl EvidenceElement for Aligned {}
        let mut aligned = ExactBuffer::<Aligned>::try_with_capacity(2).unwrap();
        assert_eq!((aligned.ptr.as_ptr() as usize) % 64, 0);
        aligned.try_push(Aligned(1)).unwrap();
        assert_eq!(aligned.as_slice()[0].0, 1);

        let (zero, allocations, deallocations) =
            with_global_counts(|| ExactBuffer::<u8>::try_with_capacity(0).unwrap());
        assert_eq!(zero.capacity(), 0);
        assert_eq!(zero.ptr.as_ptr() as usize % std::mem::align_of::<u8>(), 0);
        drop(zero);
        assert_eq!((allocations, deallocations), (0, 0));
    }

    #[test]
    fn received_vote_evidence_null_allocation_and_push_refusal_are_lossless() {
        let _fault = AllocationFaultScope::fail_after(0);
        assert_eq!(
            ExactBuffer::<u8>::try_with_capacity(4).unwrap_err(),
            EvidenceAllocError::Allocation
        );
        drop(_fault);

        let mut buffer = ExactBuffer::<u8>::try_with_capacity(1).unwrap();
        buffer.try_push(9).unwrap();
        assert_eq!(buffer.try_push(17), Err(17));
        assert_eq!(buffer.as_slice(), &[9]);
    }

    #[test]
    fn received_vote_evidence_budget_and_backing_allocation_failures_release_coverage() {
        {
            let _fault = AllocationFaultScope::fail_after(0);
            assert_eq!(
                BudgetHandle::try_new(4096, 0).unwrap_err(),
                LedgerError::Admission
            );
        }

        let budget = budget(4096);
        {
            let _fault = AllocationFaultScope::fail_after(0);
            assert_eq!(
                ChargedBuffer::<u8>::try_new(&budget, 8, ReservationClass::Bytes).unwrap_err(),
                LedgerError::Admission
            );
        }
        assert_eq!(budget.occupancy(), (budget_baseline(), 0, 0, 0, 0, 0));
    }

    #[test]
    fn received_vote_evidence_partial_initialization_and_exact_vec_transfer() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut buffer = ExactBuffer::<DropProbe>::try_with_capacity(3).unwrap();
        buffer.try_push(DropProbe(Arc::clone(&drops))).unwrap();
        buffer.try_push(DropProbe(Arc::clone(&drops))).unwrap();
        drop(buffer);
        assert_eq!(drops.load(Ordering::Relaxed), 2);

        let mut buffer = ExactBuffer::<u8>::try_with_capacity(6).unwrap();
        for byte in [1, 2, 3] {
            buffer.try_push(byte).unwrap();
        }
        let ptr = buffer.ptr.as_ptr();
        let vec = buffer.into_vec();
        assert_eq!(vec.as_ptr(), ptr);
        assert_eq!(vec.len(), 3);
        assert_eq!(vec.capacity(), 6);
        assert_eq!(vec, [1, 2, 3]);
        drop(vec);
    }

    #[test]
    fn received_vote_evidence_deallocation_guard_survives_destructor_unwind() {
        let drops = Arc::new(AtomicUsize::new(0));
        let panic_once = Arc::new(AtomicBool::new(true));
        let mut buffer = ExactBuffer::<PanicProbe>::try_with_capacity(3).unwrap();
        for _ in 0..3 {
            buffer
                .try_push(PanicProbe {
                    drops: Arc::clone(&drops),
                    panic_once: Arc::clone(&panic_once),
                })
                .unwrap();
        }
        let before = DEALLOCATION_COUNT.with(std::cell::Cell::get);
        let result = catch_unwind(AssertUnwindSafe(|| drop(buffer)));
        assert!(result.is_err());
        assert_eq!(drops.load(Ordering::Relaxed), 3);
        assert_eq!(DEALLOCATION_COUNT.with(std::cell::Cell::get), before + 1);
    }

    #[test]
    fn received_vote_evidence_reservation_cancel_commit_and_cap_lowering() {
        let budget = budget(4096);
        let baseline = budget.occupancy().0;
        let cancelled = budget.reserve(128, ReservationClass::Report).unwrap();
        assert_eq!(budget.occupancy().1, 128);
        drop(cancelled);
        assert_eq!(budget.occupancy(), (baseline, 0, 0, 0, 0, 0));

        let pending = budget.reserve(128, ReservationClass::Report).unwrap();
        let lease = pending.commit().unwrap();
        assert_eq!(budget.occupancy(), (baseline + 128, 0, 0, 0, 1, 0));
        budget.lower_cap(baseline + 64);
        assert_eq!(
            budget.reserve(1, ReservationClass::Bytes).unwrap_err(),
            LedgerError::Admission
        );
        drop(lease);
        assert_eq!(budget.occupancy(), (baseline, 0, 0, 0, 0, 0));
        let retry = budget.reserve(64, ReservationClass::Bytes).unwrap();
        drop(retry);
    }

    #[test]
    fn received_vote_evidence_charged_buffer_drops_backing_before_lease() {
        let budget = budget(4096);
        let drops = Arc::new(AtomicUsize::new(0));
        let covered_drops = Arc::new(AtomicUsize::new(0));
        let capacity = 1;
        let layout = ExactBuffer::<ObserveRelease>::layout_for(capacity)
            .unwrap()
            .unwrap();
        let charge = (size_of::<ChargedBuffer<ObserveRelease>>() + layout.size()) as u64;
        let pending = budget.reserve(charge, ReservationClass::Bytes).unwrap();
        let mut backing = ExactBuffer::try_with_capacity(capacity).unwrap();
        backing
            .try_push(ObserveRelease {
                budget: budget.try_clone().unwrap(),
                expected_bytes: budget_baseline() + charge,
                drops: Arc::clone(&drops),
                covered_drops: Arc::clone(&covered_drops),
                panic_once: None,
            })
            .unwrap();
        let lease = pending.commit().unwrap();
        let owner = ChargedBuffer {
            backing,
            _lease: lease,
        };
        assert_eq!(
            budget.occupancy(),
            (budget_baseline() + charge, 0, 0, 0, 0, 0)
        );
        let before = DEALLOCATION_COUNT.with(std::cell::Cell::get);
        drop(owner);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(covered_drops.load(Ordering::Relaxed), 1);
        assert_eq!(budget.occupancy(), (budget_baseline(), 0, 0, 0, 0, 0));
        assert_eq!(DEALLOCATION_COUNT.with(std::cell::Cell::get), before + 1);
    }

    #[test]
    fn received_vote_evidence_charged_buffer_unwind_destroys_before_release() {
        let budget = budget(4096);
        let drops = Arc::new(AtomicUsize::new(0));
        let covered_drops = Arc::new(AtomicUsize::new(0));
        let panic_once = Arc::new(AtomicBool::new(true));
        let mut owner =
            ChargedBuffer::<ObserveRelease>::try_new(&budget, 3, ReservationClass::Bytes).unwrap();
        let expected_bytes = budget_baseline() + owner._lease.bytes;
        for _ in 0..3 {
            owner
                .backing
                .try_push(ObserveRelease {
                    budget: budget.try_clone().unwrap(),
                    expected_bytes,
                    drops: Arc::clone(&drops),
                    covered_drops: Arc::clone(&covered_drops),
                    panic_once: Some(Arc::clone(&panic_once)),
                })
                .unwrap();
        }
        let before = DEALLOCATION_COUNT.with(std::cell::Cell::get);
        assert!(catch_unwind(AssertUnwindSafe(|| drop(owner))).is_err());
        assert_eq!(drops.load(Ordering::Relaxed), 3);
        assert_eq!(covered_drops.load(Ordering::Relaxed), 3);
        assert_eq!(DEALLOCATION_COUNT.with(std::cell::Cell::get), before + 1);
        assert_eq!(budget.occupancy(), (budget_baseline(), 0, 0, 0, 0, 0));
    }

    #[test]
    fn received_vote_evidence_context_construction_stages_and_cleanup() {
        let budget = budget(100_000);
        let payload = snapshot(3, 1);
        let charge = payload.checked_charge().unwrap();
        let pending = budget.reserve(charge, ReservationClass::Context).unwrap();

        let _fault = AllocationFaultScope::fail_after(0);
        let failure = ContextHandle::try_new(payload, pending);
        drop(_fault);
        let (payload, pending, error) = failure.unwrap_err();
        assert_eq!(error, LedgerError::Allocation);
        assert_eq!(payload.authorized_epoch, 3);
        drop(payload);
        drop(pending);
        assert_eq!(budget.occupancy(), (budget_baseline(), 0, 0, 0, 0, 0));

        let context = install_context(&budget, snapshot(3, 1)).unwrap();
        assert_eq!(context.epoch(), 3);
        assert_eq!(context.suite(), SUITE_PQ_RESERVED_1);
        assert_eq!(context.domain_wire_chain(), 7);
        drop(context);
        assert_eq!(budget.occupancy(), (budget_baseline(), 0, 0, 0, 0, 0));
    }

    #[test]
    fn received_vote_evidence_context_handles_share_budget_across_invalidation() {
        let budget = budget(100_000);
        let old_active = install_context(&budget, snapshot(1, 1)).unwrap();
        let detached_token_context = old_active.try_clone().unwrap();
        let (_, _, old_count, _, _, _) = budget.occupancy();
        assert_eq!(old_count, 1);

        // Foundation fixture for engine invalidation: release the active
        // context handle while a detached token still owns the old context.
        drop(old_active);
        let new_active = install_context(&budget, snapshot(2, 1)).unwrap();
        assert!(!detached_token_context.ptr_eq(&new_active));
        assert_eq!(detached_token_context.epoch(), 1);
        assert_eq!(new_active.epoch(), 2);
        assert_eq!(budget.occupancy().2, 2);

        let before = budget.occupancy().0;
        budget.lower_cap(before);
        assert_eq!(
            budget.reserve(1, ReservationClass::Bytes).unwrap_err(),
            LedgerError::Admission
        );
        drop(detached_token_context);
        assert_eq!(budget.occupancy().2, 1);
        drop(new_active);
        assert_eq!(budget.occupancy(), (budget_baseline(), 0, 0, 0, 0, 0));
    }

    #[test]
    fn received_vote_evidence_report_quota_and_final_budget_observation() {
        let final_drops_before = BUDGET_FINAL_DROPS.with(std::cell::Cell::get);
        let budget = BudgetHandle::try_new(4096, 0).unwrap();
        let pending = budget.reserve(64, ReservationClass::Report).unwrap();
        let lease = pending.commit().unwrap();
        assert_eq!(budget.occupancy().4, 1);
        drop(lease);
        assert_eq!(budget.occupancy().4, 0);
        drop(budget);
        assert_eq!(
            BUDGET_FINAL_DROPS.with(std::cell::Cell::get),
            final_drops_before + 1
        );
    }

    #[test]
    fn received_vote_evidence_report_quota_refuses_and_recovers() {
        let budget = budget(u64::MAX);
        let mut reports = Vec::with_capacity(MAX_REPORTS);
        for _ in 0..MAX_REPORTS {
            reports.push(
                budget
                    .reserve(1, ReservationClass::Report)
                    .unwrap()
                    .commit()
                    .unwrap(),
            );
        }
        assert_eq!(budget.occupancy().4, MAX_REPORTS);
        assert_eq!(
            budget.reserve(1, ReservationClass::Report).unwrap_err(),
            LedgerError::Quota
        );
        drop(reports.pop());
        assert_eq!(
            budget
                .reserve(1, ReservationClass::Report)
                .unwrap()
                .commit()
                .unwrap()
                .class,
            ReservationClass::Report
        );
        drop(reports);
        assert_eq!(budget.occupancy().4, 0);
    }

    #[test]
    fn received_vote_evidence_refcount_overflow_does_not_mutate_count() {
        let budget = budget(4096);
        budget.set_refcount_for_test(usize::MAX);
        assert_eq!(budget.try_clone().unwrap_err(), LedgerError::Arithmetic);
        assert_eq!(
            unsafe { budget.0.as_ref().refs.load(Ordering::Relaxed) },
            usize::MAX
        );
        budget.set_refcount_for_test(1);
        drop(budget);
    }

    #[test]
    fn received_vote_evidence_context_refcount_overflow_does_not_mutate_count() {
        let budget = budget(100_000);
        let context = install_context(&budget, snapshot(1, 1)).unwrap();
        unsafe { context.0.as_ref().refs.store(usize::MAX, Ordering::Relaxed) };
        assert_eq!(context.try_clone().unwrap_err(), LedgerError::Arithmetic);
        assert_eq!(
            unsafe { context.0.as_ref().refs.load(Ordering::Relaxed) },
            usize::MAX
        );
        unsafe { context.0.as_ref().refs.store(1, Ordering::Relaxed) };
        drop(context);
        assert_eq!(budget.occupancy(), (budget_baseline(), 0, 0, 0, 0, 0));
    }

    #[test]
    fn received_vote_evidence_concurrent_clone_reserve_and_release() {
        let budget = Arc::new(budget(1_000_000));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let shared = Arc::clone(&budget);
            workers.push(thread::spawn(move || {
                let handle = shared.try_clone().unwrap();
                for _ in 0..200 {
                    let pending = handle.reserve(8, ReservationClass::Report).unwrap();
                    let charge = pending.commit().unwrap();
                    drop(charge);
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(budget.occupancy(), (budget_baseline(), 0, 0, 0, 0, 0));
    }

    #[test]
    fn received_vote_evidence_concurrent_context_cloning_and_final_release() {
        let budget = budget(1_000_000);
        let context = Arc::new(install_context(&budget, snapshot(9, 1)).unwrap());
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let context = Arc::clone(&context);
                thread::spawn(move || {
                    for _ in 0..200 {
                        drop(context.try_clone().unwrap());
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        drop(context);
        assert_eq!(budget.occupancy(), (budget_baseline(), 0, 0, 0, 0, 0));
    }

    #[test]
    fn received_vote_evidence_foundation_surviving_context_final_drop_on_worker() {
        let budget = budget(100_000);
        let active = install_context(&budget, snapshot(9, 1)).unwrap();
        let survivor = active.try_clone().unwrap();
        let expected = budget.occupancy();
        let ready = Arc::new(std::sync::Barrier::new(2));
        let worker_ready = Arc::clone(&ready);
        let worker = thread::spawn(move || {
            worker_ready.wait();
            assert_eq!(survivor.epoch(), 9);
            assert_eq!(
                unsafe { survivor.0.as_ref().lease.budget.occupancy() },
                expected
            );
            assert_eq!(
                unsafe {
                    survivor
                        .0
                        .as_ref()
                        .lease
                        .budget
                        .0
                        .as_ref()
                        .refs
                        .load(Ordering::Relaxed)
                },
                1
            );
            let contexts_before = CONTEXT_FINAL_DROPS.with(std::cell::Cell::get);
            let budgets_before = BUDGET_FINAL_DROPS.with(std::cell::Cell::get);
            let deallocations_before = DEALLOCATION_COUNT.with(std::cell::Cell::get);
            drop(survivor);
            assert_eq!(
                CONTEXT_FINAL_DROPS.with(std::cell::Cell::get),
                contexts_before + 1
            );
            assert_eq!(
                BUDGET_FINAL_DROPS.with(std::cell::Cell::get),
                budgets_before + 1
            );
            assert_eq!(
                DEALLOCATION_COUNT.with(std::cell::Cell::get),
                deallocations_before + 2
            );
        });
        // Foundation ownership fixture, not engine invalidation integration.
        drop(active);
        drop(budget);
        ready.wait();
        worker.join().unwrap();
    }

    #[test]
    fn received_vote_evidence_compiler_layouts_and_accounting_equations() {
        macro_rules! layout {
            ($ty:ty) => {
                println!(
                    "{}: size={} align={}",
                    stringify!($ty),
                    size_of::<$ty>(),
                    std::mem::align_of::<$ty>()
                );
            };
        }
        layout!(BudgetCell);
        layout!(EvidenceLedger);
        layout!(BudgetHandle);
        layout!(ContextCell);
        layout!(SnapshotPayload);
        layout!(SnapshotMember);
        layout!(ContextHandle);
        layout!(Option<ActiveVoteContext>);
        layout!(VerifiedVoteToken);
        layout!(ExactBuffer<u8>);
        layout!(ChargedBuffer<u8>);
        layout!(PendingCharge);
        layout!(CommittedCharge);
        layout!(AllocationGuard);
        layout!(CellDeallocationGuard<ContextCell>);
        layout!(Result<ContextHandle, (SnapshotPayload, PendingCharge, LedgerError)>);
        layout!(Option<TableTokenFixture>);

        let budget = budget(100_000);
        let payload = snapshot(1, 1);
        let member_bytes = payload.members.capacity() * size_of::<SnapshotMember>();
        let key_bytes: usize = payload
            .members
            .iter()
            .map(|m| m.public_key.capacity())
            .sum();
        let required = payload.checked_charge().unwrap();
        assert_eq!(
            required,
            (size_of::<ContextCell>() + member_bytes + key_bytes) as u64
        );
        println!(
            "B={} context={} (cell={} members={} keys={})",
            budget_baseline(),
            required,
            size_of::<ContextCell>(),
            member_bytes,
            key_bytes
        );
        let context = install_context(&budget, payload).unwrap();
        let buffer = ChargedBuffer::<u8>::try_new(&budget, 32, ReservationClass::Bytes).unwrap();
        let buffer_charge = (size_of::<ChargedBuffer<u8>>() + 32) as u64;
        assert_eq!(buffer._lease.bytes, buffer_charge);
        assert_eq!(
            budget.occupancy(),
            (budget_baseline() + required + buffer_charge, 0, 1, 0, 0, 0)
        );
        drop(buffer);
        drop(context);
        assert_eq!(budget.occupancy(), (budget_baseline(), 0, 0, 0, 0, 0));
    }

    #[test]
    fn received_vote_evidence_context_limit_and_same_budget_reinstall() {
        let budget = budget(2_000_000);
        let mut contexts = Vec::new();
        for epoch in 0..MAX_CONTEXTS {
            contexts.push(install_context(&budget, snapshot(epoch as u64, 1)).unwrap());
        }
        assert_eq!(
            install_context(&budget, snapshot(99, 1)).unwrap_err(),
            LedgerError::Quota
        );
        drop(contexts);
        assert_eq!(budget.occupancy().2, 0);
        let reinstalled = install_context(&budget, snapshot(100, 1)).unwrap();
        assert_eq!(reinstalled.epoch(), 100);
        drop(reinstalled);
    }

    #[test]
    fn received_vote_evidence_slot_and_signature_backing_accounting_fixture() {
        let budget = budget(100_000);
        let table_bytes = Layout::array::<Option<TableTokenFixture>>(1024)
            .unwrap()
            .size() as u64;
        let table_owner = size_of::<ChargedBuffer<Option<TableTokenFixture>>>() as u64;
        let mut table = ChargedBuffer::<Option<TableTokenFixture>>::try_new(
            &budget,
            1024,
            ReservationClass::Bytes,
        )
        .unwrap();
        assert_eq!(
            budget.occupancy().0,
            budget_baseline() + table_owner + table_bytes
        );
        let signature_pending = budget.reserve(32, ReservationClass::Bytes).unwrap();
        let signature = ExactBuffer::<u8>::try_with_capacity(32).unwrap();
        let signature_charge = signature_pending.commit().unwrap();
        table
            .backing
            .try_push(Some(TableTokenFixture {
                signature,
                _lease: signature_charge,
            }))
            .unwrap();
        assert_eq!(table.backing.capacity(), 1024);
        assert_eq!(table.backing.len(), 1);
        assert_eq!(
            budget.occupancy().0,
            budget_baseline() + table_owner + table_bytes + 32
        );
        // The slot charge already covers the token's inline fields; only its
        // signature backing has its separate lease.
        drop(table);
        assert_eq!(budget.occupancy(), (budget_baseline(), 0, 0, 0, 0, 0));
    }

    #[test]
    fn qc_replacement_projection_obeys_cap_for_equal_and_shrinking_changes() {
        let baseline = budget_baseline() as u64;
        let budget = EvidenceBudget::try_new(baseline + 100, 0).unwrap();
        let admission = budget
            .reserve_qc_replacement(7, 0, 100)
            .expect("new evidence fits");
        budget.commit_qc_replacement(admission, 7, 0, 100);
        assert_eq!(budget.occupancy().0, baseline + 100);

        budget.lower_cap(baseline + 80);
        assert_eq!(
            budget.reserve_qc_replacement(7, 100, 100).unwrap_err(),
            EvidenceAccountingError::Admission,
            "equal replacement above cap refuses"
        );
        assert_eq!(
            budget.reserve_qc_replacement(7, 100, 90).unwrap_err(),
            EvidenceAccountingError::Admission,
            "shrink that remains above cap refuses"
        );
        let admission = budget
            .reserve_qc_replacement(7, 100, 80)
            .expect("shrink projected within cap");
        budget.commit_qc_replacement(admission, 7, 100, 80);
        assert_eq!(budget.occupancy().0, baseline + 80);
    }

    #[test]
    fn qc_growth_new_admission_and_reclamation_are_distinct() {
        let baseline = budget_baseline() as u64;
        let budget = EvidenceBudget::try_new(baseline + 150, 0).unwrap();
        let first = budget.reserve_qc_replacement(3, 0, 100).unwrap();
        budget.commit_qc_replacement(first, 3, 0, 100);
        let growth = budget.reserve_qc_replacement(3, 100, 120).unwrap();
        budget.commit_qc_replacement(growth, 3, 100, 120);
        assert_eq!(budget.occupancy().0, baseline + 120);
        assert_eq!(
            budget.reserve_qc_replacement(4, 0, 40).unwrap_err(),
            EvidenceAccountingError::Admission,
            "new evidence refuses without headroom"
        );

        budget.lower_cap(baseline + 50);
        budget.release_qc_bytes(120);
        assert_eq!(
            budget.occupancy().0,
            baseline,
            "legacy replacement/removal may reclaim while over cap"
        );
        let new = budget.reserve_qc_replacement(4, 0, 40).unwrap();
        budget.commit_qc_replacement(new, 4, 0, 40);
        assert_eq!(budget.occupancy().0, baseline + 40);
    }

    #[test]
    fn qc_replacement_reservation_cancels_during_controlled_unwind() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let baseline = budget_baseline() as u64;
        let budget = EvidenceBudget::try_new(baseline + 256, 0).unwrap();
        let initial = budget.occupancy();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _reservation = budget.reserve_qc_replacement(7, 0, 128).unwrap();
            assert_eq!(budget.occupancy(), (baseline, 128, 0, 0));
            panic!("controlled unwind with pending QC replacement");
        }));
        assert!(result.is_err());
        assert_eq!(budget.occupancy(), initial);
    }

    #[test]
    fn context_adoption_preserves_allocations_and_refusal_restores_occupancy() {
        let budget = budget(100_000);
        let baseline = budget.occupancy();
        let input = snapshot(1, 1);
        let key_ptr = input.members[0].public_key.as_ptr();
        let context = ActiveVoteContext::try_install(
            &EvidenceBudget {
                inner: budget.try_clone().unwrap(),
            },
            VoteContextInput(input),
        )
        .unwrap();
        assert_eq!(context.first_key_ptr(), key_ptr);
        drop(context);
        assert_eq!(budget.occupancy(), baseline);

        let input = snapshot(1, 1);
        let roster_ptr = input.members.as_ptr();
        let key_ptr = input.members[0].public_key.as_ptr();
        let roster_capacity = input.members.capacity();
        let key_capacity = input.members[0].public_key.capacity();
        let _fault = AllocationFaultScope::fail_after(0);
        let refusal = ActiveVoteContext::try_install(
            &EvidenceBudget {
                inner: budget.try_clone().unwrap(),
            },
            VoteContextInput(input),
        )
        .expect_err("context-cell allocation fault refuses");
        assert_eq!(refusal.0 .0.members.as_ptr(), roster_ptr);
        assert_eq!(refusal.0 .0.members.capacity(), roster_capacity);
        assert_eq!(refusal.0 .0.members[0].public_key.as_ptr(), key_ptr);
        assert_eq!(refusal.0 .0.members[0].public_key.capacity(), key_capacity);
        assert_eq!(budget.occupancy(), baseline);
    }

    #[test]
    fn context_owner_final_release_is_safe_on_another_thread() {
        let budget = budget(100_000);
        let context = install_context(&budget, snapshot(1, 1)).unwrap();
        assert_eq!(budget.occupancy().2, 1);
        std::thread::spawn(move || drop(context))
            .join()
            .expect("context owner thread completes");
        assert_eq!(budget.occupancy(), (budget_baseline(), 0, 0, 0, 0, 0));
    }
}
