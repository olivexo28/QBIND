//! Private memory-ownership foundation for the isolated received-Vote evidence
//! design. This module does not verify Votes or connect to engine execution.
#![allow(dead_code)]

use std::alloc::{alloc, dealloc, Layout};
use std::marker::PhantomData;
use std::mem::{size_of, ManuallyDrop};
use std::ptr::NonNull;
use std::sync::atomic::{fence, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use qbind_crypto::{ConsensusSigSuiteId, ML_DSA_44_PUBLIC_KEY_SIZE, SUITE_PQ_RESERVED_1};
use qbind_types::ChainId;
use qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2;

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
    Arithmetic,
    Quota,
    WrongReservationKind,
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
    static DEALLOCATION_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static BUDGET_FINAL_DROPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
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

fn try_alloc(layout: Layout) -> Result<NonNull<u8>, EvidenceAllocError> {
    if layout.size() == 0 || layout.size() > isize::MAX as usize {
        return Err(EvidenceAllocError::Layout);
    }
    #[cfg(test)]
    {
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

struct SnapshotMember {
    validator_id: u64,
    voting_power: u64,
    public_key: Vec<u8>,
}

struct SnapshotPayload {
    runtime_chain_id: ChainId,
    authorized_epoch: u64,
    suite_id: ConsensusSigSuiteId,
    domain: ProposalVoteSigningDomainV2,
    members: Vec<SnapshotMember>,
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
                || member.public_key.capacity() > ML_DSA_44_PUBLIC_KEY_SIZE
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
        if power == 0 {
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
        let layout = Layout::new::<ContextCell>();
        let raw = match try_alloc(layout) {
            Ok(ptr) => ptr.cast::<ContextCell>(),
            Err(_) => return Err((payload, pending, LedgerError::Admission)),
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
        #[derive(Debug)]
        struct ObserveRelease {
            budget: BudgetHandle,
            saw_charge_live: Arc<AtomicBool>,
        }
        impl EvidenceElement for ObserveRelease {}
        impl Drop for ObserveRelease {
            fn drop(&mut self) {
                self.saw_charge_live
                    .store(self.budget.occupancy().0 > 0, Ordering::Relaxed);
            }
        }
        let budget = budget(4096);
        let live = Arc::new(AtomicBool::new(false));
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
                saw_charge_live: Arc::clone(&live),
            })
            .unwrap();
        let lease = pending.commit().unwrap();
        let owner = ChargedBuffer {
            backing,
            _lease: lease,
        };
        drop(owner);
        assert!(live.load(Ordering::Relaxed));
        assert_eq!(budget.occupancy().0, budget_baseline());
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
        assert_eq!(error, LedgerError::Admission);
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
    fn received_vote_evidence_slot_and_detached_owner_accounting_fixture() {
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
}
