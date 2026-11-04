#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
compile_error!("A21-F1 allocator evidence is reviewed only for Linux x86_64 GNU");

use qbind_wire::consensus::{
    BlockHeader, BlockProposal, QuorumCertificate, MSG_TYPE_BLOCK_PROPOSAL,
};
use qbind_wire::error::WireError;
use qbind_wire::io::{WireDecode, WireEncode};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{IntoRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::time::{Duration, Instant};

const EVENT_LIMIT: usize = 256;
const REQUEST_LIMIT: u64 = 65_536;
const BYTE_LIMIT: u64 = 262_144;
const RECORD_LEN: usize = 128;
const EVENT_HEADER_LEN: usize = 32;
const EVENT_LEN: usize = 32;
const EVIDENCE_MAX: usize = RECORD_LEN * 3;
const EVENT_FILE_MAX: usize = EVENT_HEADER_LEN + EVENT_LIMIT * EVENT_LEN;
const WALL_LIMIT: Duration = Duration::from_secs(10);
const CPU_LIMIT: u64 = 5;
const ADDRESS_LIMIT: u64 = 536_870_912;
const MAGIC: &[u8; 4] = b"A21R";
const EVENT_MAGIC: &[u8; 4] = b"A21E";

const REC_ENTRY: u8 = 1;
const REC_SETUP: u8 = 2;
const REC_COMPLETE: u8 = 3;
const REC_GUARD: u8 = 4;

const OP_ALLOC: u8 = 1;
const OP_ALLOC_ZEROED: u8 = 2;
const OP_REALLOC: u8 = 3;

const GUARD_SINGLE_REQUEST: u32 = 1;
const GUARD_CUMULATIVE_BYTES: u32 = 2;
const GUARD_EVENT_CAPACITY: u32 = 3;
const GUARD_REENTRANCY: u32 = 4;
const GUARD_MALFORMED_STATE: u32 = 5;
const GUARD_COUNTER_OVERFLOW: u32 = 6;
const GUARD_OTHER: u32 = 7;

const CASE_SINGLE_ALLOWED: u32 = 1;
const CASE_SINGLE_REJECTED: u32 = 2;
const CASE_BYTES_ALLOWED: u32 = 3;
const CASE_BYTES_REJECTED: u32 = 4;
const CASE_EVENTS_ALLOWED: u32 = 5;
const CASE_EVENTS_REJECTED: u32 = 6;
const CASE_BASELINE_TWO: u32 = 10;
const CASE_BASELINE_EIGHT: u32 = 11;
const CASE_LARGE_COUNT: u32 = 20;
const CASE_ZERO: u32 = 21;
const CASE_EMPTY_TX: u32 = 22;
const CASE_NONEMPTY_TX: u32 = 23;
const CASE_MIXED_TX: u32 = 24;
const CASE_TRUNCATED_PREFIX_0: u32 = 30;
const CASE_TRUNCATED_PREFIX_1: u32 = 31;
const CASE_TRUNCATED_PREFIX_2: u32 = 32;
const CASE_TRUNCATED_PREFIX_3: u32 = 33;
const CASE_TRUNCATED_BODY: u32 = 34;
const CASE_COUNT_MISMATCH: u32 = 35;
const CASE_SIGNATURE_PREFIX_0: u32 = 36;
const CASE_SIGNATURE_PREFIX_1: u32 = 37;
const CASE_SIGNATURE_BODY: u32 = 38;
const CASE_SIGNATURE_AFTER_TX: u32 = 39;
const CASE_TRAILING: u32 = 40;
const CASE_PRESENT_QC: u32 = 41;
const CASE_BAD_QC: u32 = 42;
const CASE_BAD_HEADER: u32 = 43;
const CASE_WRAPPED_NET: u32 = 44;
const CASE_LARGE_TX_LEN: u32 = 46;
const CASE_MAX_SIGNATURE_LEN: u32 = 47;

thread_local! {
    static OBSERVER_OWNER: Cell<bool> = const { Cell::new(false) };
    static OBSERVER_REENTRANT: Cell<bool> = const { Cell::new(false) };
}

struct EventSlot {
    operation: AtomicU8,
    size: AtomicU64,
    alignment: AtomicU64,
    order: AtomicU64,
}

impl EventSlot {
    const fn new() -> Self {
        Self {
            operation: AtomicU8::new(0),
            size: AtomicU64::new(0),
            alignment: AtomicU64::new(0),
            order: AtomicU64::new(0),
        }
    }
}

static ACTIVE: AtomicBool = AtomicBool::new(false);
static EVENT_COUNT: AtomicU64 = AtomicU64::new(0);
static REQUESTED_BYTES: AtomicU64 = AtomicU64::new(0);
static EVENTS: [EventSlot; EVENT_LIMIT] = [const { EventSlot::new() }; EVENT_LIMIT];
static EVIDENCE_FD: AtomicI32 = AtomicI32::new(-1);
static EVENT_FD: AtomicI32 = AtomicI32::new(-1);
static RECORD_STATE: AtomicU8 = AtomicU8::new(0);
static INVOCATION: [AtomicU8; 16] = [const { AtomicU8::new(0) }; 16];
static CASE_ID: AtomicU32 = AtomicU32::new(0);

struct ObservingAllocator;

#[global_allocator]
static GLOBAL: ObservingAllocator = ObservingAllocator;

unsafe impl GlobalAlloc for ObservingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        observe(OP_ALLOC, layout.size(), layout.align());
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        observe(OP_ALLOC_ZEROED, layout.size(), layout.align());
        System.alloc_zeroed(layout)
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        observe(OP_REALLOC, new_size, layout.align());
        System.realloc(pointer, layout, new_size)
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        System.dealloc(pointer, layout);
    }
}

fn abort_without_unwind() -> ! {
    unsafe { libc_abort() }
}

unsafe extern "C" {
    #[link_name = "abort"]
    fn libc_abort() -> !;
    fn prctl(option: i32, ...) -> i32;
    fn pwrite(fd: i32, buffer: *const u8, count: usize, offset: i64) -> isize;
    fn __errno_location() -> *mut i32;
}

fn write_record_raw(fd: RawFd, record: &[u8; RECORD_LEN], offset: i64) -> bool {
    let mut written = 0usize;
    let mut calls = 0u8;
    while written < record.len() && calls < 8 {
        calls += 1;
        let result = unsafe {
            pwrite(
                fd,
                record[written..].as_ptr(),
                record.len() - written,
                offset + written as i64,
            )
        };
        if result > 0 {
            written += result as usize;
        } else if result < 0 && unsafe { *__errno_location() } == 4 {
            continue;
        } else {
            return false;
        }
    }
    written == record.len()
}

fn encode_base_record(kind: u8, sequence: u8) -> [u8; RECORD_LEN] {
    let mut record = [0u8; RECORD_LEN];
    record[..4].copy_from_slice(MAGIC);
    record[4] = 1;
    record[5] = kind;
    record[6] = sequence;
    for (index, byte) in INVOCATION.iter().enumerate() {
        record[8 + index] = byte.load(Ordering::Relaxed);
    }
    record[24..28].copy_from_slice(&CASE_ID.load(Ordering::Relaxed).to_le_bytes());
    record
}

fn write_record(kind: u8, sequence: u8, fill: impl FnOnce(&mut [u8; RECORD_LEN])) -> bool {
    if RECORD_STATE
        .compare_exchange(sequence, sequence + 1, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return false;
    }
    let fd = EVIDENCE_FD.load(Ordering::Relaxed);
    if fd < 0 {
        return false;
    }
    let mut record = encode_base_record(kind, sequence);
    fill(&mut record);
    if !write_record_raw(fd, &record, i64::from(sequence) * RECORD_LEN as i64) {
        return false;
    }
    true
}

fn write_guard_record(
    reason: u32,
    operation: u8,
    requested: u64,
    alignment: u64,
    prior_events: u64,
    prior_bytes: u64,
    prospective_events: u64,
    prospective_bytes: u64,
    invalid_prospective: bool,
) -> bool {
    if RECORD_STATE.load(Ordering::Relaxed) != 2 {
        return false;
    }
    write_record(REC_GUARD, 2, |record| {
        record[28..32].copy_from_slice(&reason.to_le_bytes());
        record[32] = operation;
        record[33] = u8::from(invalid_prospective);
        record[40..48].copy_from_slice(&requested.to_le_bytes());
        record[48..56].copy_from_slice(&alignment.to_le_bytes());
        record[56..64].copy_from_slice(&prior_events.to_le_bytes());
        record[64..72].copy_from_slice(&prior_bytes.to_le_bytes());
        record[72..80].copy_from_slice(&prospective_events.to_le_bytes());
        record[80..88].copy_from_slice(&prospective_bytes.to_le_bytes());
        record[88..96].copy_from_slice(
            &if invalid_prospective {
                0
            } else {
                prospective_events
            }
            .to_le_bytes(),
        );
    })
}

fn guard_and_abort(
    reason: u32,
    operation: u8,
    requested: u64,
    alignment: u64,
    prior_events: u64,
    prior_bytes: u64,
    prospective_events: u64,
    prospective_bytes: u64,
    invalid_prospective: bool,
) -> ! {
    if !write_guard_record(
        reason,
        operation,
        requested,
        alignment,
        prior_events,
        prior_bytes,
        prospective_events,
        prospective_bytes,
        invalid_prospective,
    ) {
        abort_without_unwind();
    }
    abort_without_unwind()
}

fn known_guard_reason(reason: u32) -> bool {
    matches!(
        reason,
        GUARD_SINGLE_REQUEST
            | GUARD_CUMULATIVE_BYTES
            | GUARD_EVENT_CAPACITY
            | GUARD_REENTRANCY
            | GUARD_MALFORMED_STATE
            | GUARD_COUNTER_OVERFLOW
            | GUARD_OTHER
    )
}

fn observe(operation: u8, requested: usize, alignment: usize) {
    let owner = OBSERVER_OWNER
        .try_with(|owner| owner.get())
        .unwrap_or(false);
    if !owner || !ACTIVE.load(Ordering::Relaxed) {
        return;
    }
    let reentrant = OBSERVER_REENTRANT
        .try_with(|in_hook| if in_hook.replace(true) { true } else { false })
        .unwrap_or(true);
    if reentrant {
        let prior_events = EVENT_COUNT.load(Ordering::Relaxed);
        let prior_bytes = REQUESTED_BYTES.load(Ordering::Relaxed);
        let prospective_events = prior_events.checked_add(1);
        let requested_u64 = u64::try_from(requested).ok();
        let prospective_bytes = requested_u64.and_then(|size| prior_bytes.checked_add(size));
        let invalid = prospective_events.is_none() || prospective_bytes.is_none();
        guard_and_abort(
            GUARD_REENTRANCY,
            operation,
            requested_u64.unwrap_or(0),
            alignment as u64,
            prior_events,
            prior_bytes,
            prospective_events.unwrap_or(0),
            prospective_bytes.unwrap_or(0),
            invalid,
        );
    }

    let prior_events = EVENT_COUNT.load(Ordering::Relaxed);
    let prior_bytes = REQUESTED_BYTES.load(Ordering::Relaxed);
    if prior_events > EVENT_LIMIT as u64
        || prior_bytes > BYTE_LIMIT
        || RECORD_STATE.load(Ordering::Relaxed) != 2
        || (prior_events == 0 && prior_bytes != 0)
    {
        let prospective_events = prior_events.checked_add(1);
        let prospective_bytes = u64::try_from(requested)
            .ok()
            .and_then(|size| prior_bytes.checked_add(size));
        guard_and_abort(
            GUARD_MALFORMED_STATE,
            operation,
            u64::try_from(requested).unwrap_or(0),
            alignment as u64,
            prior_events,
            prior_bytes,
            prospective_events.unwrap_or(0),
            prospective_bytes.unwrap_or(0),
            prospective_events.is_none() || prospective_bytes.is_none(),
        );
    }
    let requested_u64 = match u64::try_from(requested) {
        Ok(value) => value,
        Err(_) => guard_and_abort(
            GUARD_COUNTER_OVERFLOW,
            operation,
            0,
            alignment as u64,
            prior_events,
            prior_bytes,
            0,
            0,
            true,
        ),
    };
    let alignment_u64 = match u64::try_from(alignment) {
        Ok(value) => value,
        Err(_) => guard_and_abort(
            GUARD_COUNTER_OVERFLOW,
            operation,
            requested_u64,
            0,
            prior_events,
            prior_bytes,
            0,
            0,
            true,
        ),
    };
    let prospective_events = match prior_events.checked_add(1) {
        Some(value) => value,
        None => guard_and_abort(
            GUARD_COUNTER_OVERFLOW,
            operation,
            requested_u64,
            alignment_u64,
            prior_events,
            prior_bytes,
            0,
            0,
            true,
        ),
    };
    let prospective_bytes = match prior_bytes.checked_add(requested_u64) {
        Some(value) => value,
        None => guard_and_abort(
            GUARD_COUNTER_OVERFLOW,
            operation,
            requested_u64,
            alignment_u64,
            prior_events,
            prior_bytes,
            prospective_events,
            0,
            true,
        ),
    };

    let reason = if requested_u64 > REQUEST_LIMIT {
        Some(GUARD_SINGLE_REQUEST)
    } else if prospective_bytes > BYTE_LIMIT {
        Some(GUARD_CUMULATIVE_BYTES)
    } else if prospective_events > EVENT_LIMIT as u64 {
        Some(GUARD_EVENT_CAPACITY)
    } else {
        None
    };
    if let Some(reason) = reason {
        guard_and_abort(
            reason,
            operation,
            requested_u64,
            alignment_u64,
            prior_events,
            prior_bytes,
            prospective_events,
            prospective_bytes,
            false,
        );
    }

    let slot = &EVENTS[prior_events as usize];
    if slot.operation.load(Ordering::Relaxed) != 0 {
        guard_and_abort(
            GUARD_MALFORMED_STATE,
            operation,
            requested_u64,
            alignment_u64,
            prior_events,
            prior_bytes,
            prospective_events,
            prospective_bytes,
            false,
        );
    }
    slot.operation.store(operation, Ordering::Relaxed);
    slot.size.store(requested_u64, Ordering::Relaxed);
    slot.alignment.store(alignment_u64, Ordering::Relaxed);
    slot.order.store(prospective_events, Ordering::Relaxed);
    REQUESTED_BYTES.store(prospective_bytes, Ordering::Relaxed);
    EVENT_COUNT.store(prospective_events, Ordering::Relaxed);
    let _ = OBSERVER_REENTRANT.try_with(|in_hook| in_hook.set(false));
}

struct ObservationGuard {
    armed: bool,
}

impl ObservationGuard {
    fn arm() -> Self {
        if ACTIVE
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            guard_and_abort(
                GUARD_MALFORMED_STATE,
                0,
                0,
                0,
                EVENT_COUNT.load(Ordering::Relaxed),
                REQUESTED_BYTES.load(Ordering::Relaxed),
                0,
                0,
                true,
            );
        }
        Self { armed: true }
    }

    fn disarm(&mut self) {
        if self.armed {
            ACTIVE.store(false, Ordering::SeqCst);
            self.armed = false;
        }
    }
}

impl Drop for ObservationGuard {
    fn drop(&mut self) {
        self.disarm();
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Snapshot {
    count: u64,
    bytes: u64,
}

fn reset_observer() {
    ACTIVE.store(false, Ordering::SeqCst);
    EVENT_COUNT.store(0, Ordering::Relaxed);
    REQUESTED_BYTES.store(0, Ordering::Relaxed);
    for event in &EVENTS {
        event.operation.store(0, Ordering::Relaxed);
        event.size.store(0, Ordering::Relaxed);
        event.alignment.store(0, Ordering::Relaxed);
        event.order.store(0, Ordering::Relaxed);
    }
    OBSERVER_OWNER.with(|owner| owner.set(true));
    OBSERVER_REENTRANT.with(|inside| inside.set(false));
}

fn snapshot() -> Snapshot {
    Snapshot {
        count: EVENT_COUNT.load(Ordering::Relaxed),
        bytes: REQUESTED_BYTES.load(Ordering::Relaxed),
    }
}

fn write_event_snapshot() -> Result<(), String> {
    let count = EVENT_COUNT.load(Ordering::Relaxed);
    if count > EVENT_LIMIT as u64 {
        return Err("event count exceeds fixed buffer".into());
    }
    let mut data = [0u8; EVENT_FILE_MAX];
    data[..4].copy_from_slice(EVENT_MAGIC);
    data[4] = 1;
    for (index, byte) in INVOCATION.iter().enumerate() {
        data[8 + index] = byte.load(Ordering::Relaxed);
    }
    data[24..28].copy_from_slice(&CASE_ID.load(Ordering::Relaxed).to_le_bytes());
    data[28..32].copy_from_slice(&(count as u32).to_le_bytes());
    for index in 0..count as usize {
        let start = EVENT_HEADER_LEN + index * EVENT_LEN;
        data[start] = EVENTS[index].operation.load(Ordering::Relaxed);
        data[start + 8..start + 16]
            .copy_from_slice(&EVENTS[index].size.load(Ordering::Relaxed).to_le_bytes());
        data[start + 16..start + 24].copy_from_slice(
            &EVENTS[index]
                .alignment
                .load(Ordering::Relaxed)
                .to_le_bytes(),
        );
        data[start + 24..start + 32]
            .copy_from_slice(&EVENTS[index].order.load(Ordering::Relaxed).to_le_bytes());
    }
    let fd = EVENT_FD.load(Ordering::Relaxed);
    if fd < 0 {
        return Err("event snapshot descriptor is unavailable".into());
    }
    let length = EVENT_HEADER_LEN + count as usize * EVENT_LEN;
    let mut written = 0usize;
    let mut calls = 0;
    while written < length && calls < 8 {
        calls += 1;
        let result = unsafe {
            pwrite(
                fd,
                data[written..length].as_ptr(),
                length - written,
                written as i64,
            )
        };
        if result > 0 {
            written += result as usize;
        } else if result < 0 && unsafe { *__errno_location() } == 4 {
            continue;
        } else {
            return Err("event snapshot write failed".into());
        }
    }
    if written != length {
        return Err("event snapshot write was incomplete".into());
    }
    Ok(())
}

fn write_entry_and_setup() -> Result<(), String> {
    if !write_record(REC_ENTRY, 0, |_| {}) {
        return Err("ENTRY record write failed".into());
    }

    let limits = fs::read_to_string("/proc/self/limits")
        .map_err(|error| format!("cannot read /proc/self/limits: {error}"))?;
    let cpu = parse_limit(&limits, "Max cpu time")?;
    let address = parse_limit(&limits, "Max address space")?;
    let core = parse_limit(&limits, "Max core file size")?;
    if cpu != (CPU_LIMIT, CPU_LIMIT) || address != (ADDRESS_LIMIT, ADDRESS_LIMIT) || core != (0, 0)
    {
        return Err("child resource limits do not match requested soft/hard limits".into());
    }

    let set_result = unsafe {
        prctl(
            4,
            0 as std::os::raw::c_ulong,
            0 as std::os::raw::c_ulong,
            0 as std::os::raw::c_ulong,
            0 as std::os::raw::c_ulong,
        )
    };
    if set_result != 0 {
        let errno = if set_result == -1 {
            unsafe { *__errno_location() }
        } else {
            0
        };
        return Err(format!(
            "PR_SET_DUMPABLE failed, result={set_result}, errno={errno}"
        ));
    }
    let get_result = unsafe {
        prctl(
            3,
            0 as std::os::raw::c_ulong,
            0 as std::os::raw::c_ulong,
            0 as std::os::raw::c_ulong,
            0 as std::os::raw::c_ulong,
        )
    };
    if get_result != 0 {
        let errno = if get_result == -1 {
            unsafe { *__errno_location() }
        } else {
            0
        };
        return Err(format!(
            "PR_GET_DUMPABLE returned {get_result}, expected 0, errno={errno}"
        ));
    }

    if !write_record(REC_SETUP, 1, |record| {
        record[32..40].copy_from_slice(&cpu.0.to_le_bytes());
        record[40..48].copy_from_slice(&cpu.1.to_le_bytes());
        record[48..56].copy_from_slice(&address.0.to_le_bytes());
        record[56..64].copy_from_slice(&address.1.to_le_bytes());
        record[64..72].copy_from_slice(&core.0.to_le_bytes());
        record[72..80].copy_from_slice(&core.1.to_le_bytes());
        record[80..88].copy_from_slice(&0u64.to_le_bytes());
    }) {
        return Err("SETUP record write failed".into());
    }
    reset_observer();
    Ok(())
}

fn parse_limit(contents: &str, name: &str) -> Result<(u64, u64), String> {
    let line = contents
        .lines()
        .find(|line| line.starts_with(name))
        .ok_or_else(|| format!("{name} is absent from /proc/self/limits"))?;
    let values: Vec<&str> = line[name.len()..].split_whitespace().collect();
    if values.len() < 2 {
        return Err(format!("{name} has malformed limits"));
    }
    let parse = |value: &str| {
        if value == "unlimited" {
            Ok(u64::MAX)
        } else {
            value
                .parse::<u64>()
                .map_err(|_| format!("{name} has invalid limit value"))
        }
    };
    Ok((parse(values[0])?, parse(values[1])?))
}

fn finish_normal(assertion_set: u32, observed: Snapshot) -> Result<(), String> {
    if ACTIVE.load(Ordering::Relaxed) {
        return Err("observer was still armed before completion".into());
    }
    write_event_snapshot()?;
    if !write_record(REC_COMPLETE, 2, |record| {
        record[28..32].copy_from_slice(&assertion_set.to_le_bytes());
        record[32..40].copy_from_slice(&observed.count.to_le_bytes());
        record[40..48].copy_from_slice(&observed.bytes.to_le_bytes());
    }) {
        return Err("COMPLETE record write failed".into());
    }
    Ok(())
}

#[derive(Clone)]
struct ChildCase {
    name: &'static str,
    id: u32,
    terminal: u8,
    guard_reason: u32,
    expected_events: Option<u64>,
    expected_bytes: Option<u64>,
    expected_assertions: u32,
}

fn case_by_name(name: &str) -> Option<ChildCase> {
    let (id, terminal, reason, events, bytes, assertions) = match name {
        "single_allowed" => (
            CASE_SINGLE_ALLOWED,
            REC_COMPLETE,
            0,
            Some(1),
            Some(65_536),
            1,
        ),
        "single_rejected" => (
            CASE_SINGLE_REJECTED,
            REC_GUARD,
            GUARD_SINGLE_REQUEST,
            None,
            None,
            0,
        ),
        "bytes_allowed" => (
            CASE_BYTES_ALLOWED,
            REC_COMPLETE,
            0,
            Some(64),
            Some(262_144),
            1,
        ),
        "bytes_rejected" => (
            CASE_BYTES_REJECTED,
            REC_GUARD,
            GUARD_CUMULATIVE_BYTES,
            None,
            None,
            0,
        ),
        "events_allowed" => (
            CASE_EVENTS_ALLOWED,
            REC_COMPLETE,
            0,
            Some(256),
            Some(256),
            1,
        ),
        "events_rejected" => (
            CASE_EVENTS_REJECTED,
            REC_GUARD,
            GUARD_EVENT_CAPACITY,
            None,
            None,
            0,
        ),
        "baseline_two" => (CASE_BASELINE_TWO, REC_COMPLETE, 0, None, None, 2),
        "baseline_eight" => (CASE_BASELINE_EIGHT, REC_COMPLETE, 0, None, None, 2),
        "large_count" => (CASE_LARGE_COUNT, REC_COMPLETE, 0, Some(0), Some(0), 3),
        "zero" => (CASE_ZERO, REC_COMPLETE, 0, Some(0), Some(0), 4),
        "empty_tx" => (CASE_EMPTY_TX, REC_COMPLETE, 0, None, None, 4),
        "nonempty_tx" => (CASE_NONEMPTY_TX, REC_COMPLETE, 0, None, None, 4),
        "mixed_tx" => (CASE_MIXED_TX, REC_COMPLETE, 0, None, None, 4),
        "prefix_0" => (
            CASE_TRUNCATED_PREFIX_0,
            REC_COMPLETE,
            0,
            Some(0),
            Some(0),
            3,
        ),
        "prefix_1" => (
            CASE_TRUNCATED_PREFIX_1,
            REC_COMPLETE,
            0,
            Some(0),
            Some(0),
            3,
        ),
        "prefix_2" => (
            CASE_TRUNCATED_PREFIX_2,
            REC_COMPLETE,
            0,
            Some(0),
            Some(0),
            3,
        ),
        "prefix_3" => (
            CASE_TRUNCATED_PREFIX_3,
            REC_COMPLETE,
            0,
            Some(0),
            Some(0),
            3,
        ),
        "body_truncated" => (CASE_TRUNCATED_BODY, REC_COMPLETE, 0, Some(0), Some(0), 3),
        "count_mismatch" => (CASE_COUNT_MISMATCH, REC_COMPLETE, 0, Some(0), Some(0), 3),
        "signature_prefix_0" => (
            CASE_SIGNATURE_PREFIX_0,
            REC_COMPLETE,
            0,
            Some(0),
            Some(0),
            3,
        ),
        "signature_prefix_1" => (
            CASE_SIGNATURE_PREFIX_1,
            REC_COMPLETE,
            0,
            Some(0),
            Some(0),
            3,
        ),
        "signature_body" => (CASE_SIGNATURE_BODY, REC_COMPLETE, 0, Some(0), Some(0), 3),
        "signature_after_tx" => (
            CASE_SIGNATURE_AFTER_TX,
            REC_COMPLETE,
            0,
            Some(0),
            Some(0),
            3,
        ),
        "trailing" => (CASE_TRAILING, REC_COMPLETE, 0, None, None, 4),
        "present_qc" => (CASE_PRESENT_QC, REC_COMPLETE, 0, None, None, 4),
        "bad_qc" => (CASE_BAD_QC, REC_COMPLETE, 0, None, None, 3),
        "bad_header" => (CASE_BAD_HEADER, REC_COMPLETE, 0, None, None, 3),
        "wrapped_net" => (CASE_WRAPPED_NET, REC_COMPLETE, 0, Some(0), Some(0), 3),
        "large_tx_len" => (CASE_LARGE_TX_LEN, REC_COMPLETE, 0, Some(0), Some(0), 3),
        "max_signature_len" => (CASE_MAX_SIGNATURE_LEN, REC_COMPLETE, 0, Some(0), Some(0), 3),
        _ => return None,
    };
    Some(ChildCase {
        name: match name {
            "single_allowed" => "single_allowed",
            "single_rejected" => "single_rejected",
            "bytes_allowed" => "bytes_allowed",
            "bytes_rejected" => "bytes_rejected",
            "events_allowed" => "events_allowed",
            "events_rejected" => "events_rejected",
            "baseline_two" => "baseline_two",
            "baseline_eight" => "baseline_eight",
            "large_count" => "large_count",
            "zero" => "zero",
            "empty_tx" => "empty_tx",
            "nonempty_tx" => "nonempty_tx",
            "mixed_tx" => "mixed_tx",
            "prefix_0" => "prefix_0",
            "prefix_1" => "prefix_1",
            "prefix_2" => "prefix_2",
            "prefix_3" => "prefix_3",
            "body_truncated" => "body_truncated",
            "count_mismatch" => "count_mismatch",
            "signature_prefix_0" => "signature_prefix_0",
            "signature_prefix_1" => "signature_prefix_1",
            "signature_body" => "signature_body",
            "signature_after_tx" => "signature_after_tx",
            "trailing" => "trailing",
            "present_qc" => "present_qc",
            "bad_qc" => "bad_qc",
            "bad_header" => "bad_header",
            "wrapped_net" => "wrapped_net",
            "large_tx_len" => "large_tx_len",
            "max_signature_len" => "max_signature_len",
            _ => unreachable!(),
        },
        id,
        terminal,
        guard_reason: reason,
        expected_events: events,
        expected_bytes: bytes,
        expected_assertions: assertions,
    })
}

fn isolated_child_entry_impl() -> Result<(), String> {
    let invocation = std::env::var("QBIND_A21_INVOCATION")
        .map_err(|_| "missing child invocation ID".to_string())?;
    let selector = std::env::var("QBIND_A21_CHILD_CASE")
        .map_err(|_| "missing child case selector".to_string())?;
    let case = case_by_name(&selector).ok_or_else(|| "unknown child case selector".to_string())?;
    let passed_id = std::env::var("QBIND_A21_CASE_ID")
        .map_err(|_| "missing child numeric case ID".to_string())?
        .parse::<u32>()
        .map_err(|_| "invalid numeric case ID".to_string())?;
    if passed_id != case.id || invocation.len() != 32 {
        return Err("case ID or invocation ID has invalid format".into());
    }
    let mut id = [0u8; 16];
    for (index, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&invocation[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invocation ID is not hexadecimal".to_string())?;
        INVOCATION[index].store(*byte, Ordering::Relaxed);
    }
    CASE_ID.store(case.id, Ordering::Relaxed);

    let evidence_path = std::env::var("QBIND_A21_EVIDENCE_FILE")
        .map_err(|_| "missing evidence path".to_string())?;
    let event_path =
        std::env::var("QBIND_A21_EVENT_FILE").map_err(|_| "missing event path".to_string())?;
    let evidence = OpenOptions::new()
        .write(true)
        .open(evidence_path)
        .map_err(|error| format!("cannot open evidence file: {error}"))?;
    let event_file = OpenOptions::new()
        .write(true)
        .open(event_path)
        .map_err(|error| format!("cannot open event file: {error}"))?;
    let evidence_metadata = evidence.metadata().map_err(|e| e.to_string())?;
    let event_metadata = event_file.metadata().map_err(|e| e.to_string())?;
    if !evidence_metadata.is_file()
        || evidence_metadata.nlink() != 1
        || evidence_metadata.mode() & 0o777 != 0o600
        || evidence_metadata.len() != 0
        || !event_metadata.is_file()
        || event_metadata.nlink() != 1
        || event_metadata.mode() & 0o777 != 0o600
        || event_metadata.len() != 0
    {
        return Err("child result destinations are not fresh regular files".into());
    }
    EVIDENCE_FD.store(evidence.into_raw_fd(), Ordering::Relaxed);
    EVENT_FD.store(event_file.into_raw_fd(), Ordering::Relaxed);
    if let Err(error) = write_entry_and_setup() {
        return Err(format!("child setup failed before observation: {error}"));
    }

    let observed = run_child_case(&case)?;
    if case.terminal == REC_GUARD {
        return Err("guarded request returned instead of aborting".into());
    }
    if let Some(expected) = case.expected_events {
        if observed.count != expected {
            return Err(format!(
                "observed {} allocation events, expected {expected}",
                observed.count
            ));
        }
    }
    if let Some(expected) = case.expected_bytes {
        if observed.bytes != expected {
            return Err(format!(
                "observed {} requested bytes, expected {expected}",
                observed.bytes
            ));
        }
    }
    finish_normal(case.expected_assertions, observed)?;
    Ok(())
}

fn run_child_case(case: &ChildCase) -> Result<Snapshot, String> {
    match case.id {
        CASE_SINGLE_ALLOWED => allocation_calibration(case, &[65_536]),
        CASE_SINGLE_REJECTED => allocation_calibration(case, &[65_537]),
        CASE_BYTES_ALLOWED => allocation_calibration(case, &[4_096; 64]),
        CASE_BYTES_REJECTED => allocation_calibration(case, &[4_096; 65]),
        CASE_EVENTS_ALLOWED => allocation_calibration(case, &[1; 256]),
        CASE_EVENTS_REJECTED => allocation_calibration(case, &[1; 257]),
        CASE_BASELINE_TWO | CASE_BASELINE_EIGHT => baseline_case(case),
        _ => decoder_case(case),
    }
}

fn allocation_calibration(_case: &ChildCase, sizes: &[usize]) -> Result<Snapshot, String> {
    let layouts: Vec<Layout> = sizes
        .iter()
        .map(|size| Layout::from_size_align(*size, 1).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    let mut guard = ObservationGuard::arm();
    for layout in &layouts {
        let pointer = unsafe { GLOBAL.alloc(*layout) };
        if pointer.is_null() {
            guard.disarm();
            return Err("System allocator returned null during permitted calibration".into());
        }
        unsafe { GLOBAL.dealloc(pointer, *layout) };
    }
    guard.disarm();
    Ok(snapshot())
}

fn baseline_case(case: &ChildCase) -> Result<Snapshot, String> {
    let count = if case.id == CASE_BASELINE_TWO { 2 } else { 8 };
    let fixture = malformed_after_one_transaction(count, false);
    if fixture.len() > 4_096 {
        return Err("baseline fixture exceeds the reviewed 4 KiB ceiling".into());
    }
    let mut input = fixture.as_slice();
    let mut guard = ObservationGuard::arm();
    let decoded = BlockProposal::decode(&mut input);
    guard.disarm();
    if decoded != Err(WireError::UnexpectedEof) || !input.is_empty() {
        return Err("baseline modest truncation result/cursor differed".into());
    }
    let observed = snapshot();
    let events = event_values(observed.count as usize)?;
    let expected_reservation = Layout::array::<Vec<u8>>(count as usize)
        .map_err(|error| error.to_string())?
        .size();
    if events.len() < 2
        || events[0].0 != OP_ALLOC
        || events[1].0 != OP_ALLOC
        || events[0].1 != expected_reservation as u64
        || events[1].1 != 3
    {
        return Err(format!(
            "baseline source-order reservation/copy not observable: {:?}, expected reservation {} then 3-byte copy",
            events, expected_reservation
        ));
    }
    Ok(observed)
}

fn decoder_case(case: &ChildCase) -> Result<Snapshot, String> {
    let (bytes, expected, expected_remaining) = decoder_fixture(case)?;
    if bytes.len() > 4_096 {
        return Err("encoded fixture exceeds the reviewed 4 KiB ceiling".into());
    }
    if case.id == CASE_WRAPPED_NET {
        let mut wrapped = vec![qbind_wire::net::MSG_TYPE_NET_BLOCK_PROPOSAL];
        wrapped.extend_from_slice(&bytes);
        let mut input = wrapped.as_slice();
        let mut guard = ObservationGuard::arm();
        let result = qbind_wire::net::NetMessage::decode(&mut input).map(|_| ());
        guard.disarm();
        let remaining = input.to_vec();
        let first = snapshot();
        let error = result
            .err()
            .ok_or_else(|| "malformed wrapped proposal decoded".to_string())?;
        if error != WireError::UnexpectedEof || remaining != expected_remaining {
            return Err("wrapped NetMessage error/cursor did not preserve delegation".into());
        }
        if first.count != 0 {
            return Err("wrapped malformed proposal allocated before structural validation".into());
        }
        reset_observer();
        let mut guard = ObservationGuard::arm();
        let result = qbind_wire::net::NetMessage::decode_from_slice(&wrapped);
        guard.disarm();
        if result != Err(WireError::UnexpectedEof) {
            return Err("decode_from_slice wrapper changed the delegated decode result".into());
        }
        let observed = snapshot();
        if observed.count != 0 {
            return Err("wrapped slice decoder allocated before structural validation".into());
        }
        return Ok(observed);
    }
    let mut guard = ObservationGuard::arm();
    let mut input = bytes.as_slice();
    let result = BlockProposal::decode(&mut input);
    guard.disarm();
    let remaining = input.to_vec();
    let observed = snapshot();
    check_decoder_result(case, result, &remaining, expected, expected_remaining)?;
    let events = event_values(observed.count as usize)?;
    if should_have_no_transaction_allocation(case.id) && !events.is_empty() {
        return Err(format!(
            "malformed allocation-attribution case observed {} allocator events",
            events.len()
        ));
    }
    if matches!(case.id, CASE_EMPTY_TX | CASE_NONEMPTY_TX | CASE_MIXED_TX) {
        let count = if case.id == CASE_MIXED_TX { 3 } else { 1 };
        let expected_reservation = Layout::array::<Vec<u8>>(count)
            .map_err(|error| error.to_string())?
            .size();
        let expected_event_count = match case.id {
            CASE_EMPTY_TX => 1,
            CASE_MIXED_TX => 3,
            _ => 2,
        };
        if events.len() != expected_event_count
            || events[0].0 != OP_ALLOC
            || events[0].1 != expected_reservation as u64
            || (case.id != CASE_EMPTY_TX && events[1].0 != OP_ALLOC)
            || (case.id == CASE_NONEMPTY_TX && events[1].1 != 3)
            || (case.id == CASE_MIXED_TX && events[1].1 != 2)
            || (case.id == CASE_MIXED_TX && events[2].1 != 1)
        {
            return Err(format!(
                "valid materialization order was not observable: {:?}",
                events
            ));
        }
    }
    Ok(observed)
}

fn decoder_fixture(case: &ChildCase) -> Result<(Vec<u8>, Result<(), WireError>, Vec<u8>), String> {
    let mut bytes = proposal_prefix(0);
    let mut expected = Ok(());
    let mut remaining = Vec::new();
    match case.id {
        CASE_LARGE_COUNT => {
            bytes = proposal_prefix(u32::MAX);
            bytes.extend_from_slice(&[0x01, 0x02, 0x03]);
            expected = Err(WireError::UnexpectedEof);
            remaining = vec![0x01, 0x02, 0x03];
        }
        CASE_ZERO => {
            bytes.extend_from_slice(&[0, 0, 0]);
            remaining = vec![0];
        }
        CASE_EMPTY_TX => {
            bytes = proposal_prefix(1);
            bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        }
        CASE_NONEMPTY_TX => {
            bytes = proposal_prefix(1);
            append_tx(&mut bytes, &[0xA1, 0xB2, 0xC3]);
            bytes.extend_from_slice(&[0, 0]);
        }
        CASE_MIXED_TX => {
            bytes = proposal_prefix(3);
            append_tx(&mut bytes, &[]);
            append_tx(&mut bytes, &[4, 5]);
            append_tx(&mut bytes, &[]);
            bytes.extend_from_slice(&[1, 0, 0xEE]);
        }
        CASE_TRUNCATED_PREFIX_0..=CASE_TRUNCATED_PREFIX_3 => {
            let prefix_len = (case.id - CASE_TRUNCATED_PREFIX_0) as usize;
            bytes = proposal_prefix(1);
            bytes.extend(std::iter::repeat_n(0xAA, prefix_len));
            expected = Err(WireError::UnexpectedEof);
            remaining = vec![0xAA; prefix_len];
        }
        CASE_TRUNCATED_BODY => {
            bytes = proposal_prefix(1);
            bytes.extend_from_slice(&5u32.to_le_bytes());
            bytes.extend_from_slice(&[0xAA, 0xBB]);
            expected = Err(WireError::UnexpectedEof);
            remaining = vec![0xAA, 0xBB];
        }
        CASE_COUNT_MISMATCH => {
            bytes = proposal_prefix(2);
            append_tx(&mut bytes, &[0xAA]);
            expected = Err(WireError::UnexpectedEof);
            remaining = vec![];
        }
        CASE_SIGNATURE_PREFIX_0 | CASE_SIGNATURE_PREFIX_1 => {
            bytes.extend(std::iter::repeat_n(
                0xCC,
                (case.id - CASE_SIGNATURE_PREFIX_0) as usize,
            ));
            expected = Err(WireError::UnexpectedEof);
            remaining = vec![0xCC; (case.id - CASE_SIGNATURE_PREFIX_0) as usize];
        }
        CASE_SIGNATURE_BODY => {
            bytes.extend_from_slice(&3u16.to_le_bytes());
            bytes.extend_from_slice(&[0xAA]);
            expected = Err(WireError::UnexpectedEof);
            remaining = vec![0xAA];
        }
        CASE_SIGNATURE_AFTER_TX => {
            bytes = proposal_prefix(1);
            append_tx(&mut bytes, &[0x31, 0x32]);
            bytes.extend_from_slice(&[3, 0, 0xAA]);
            expected = Err(WireError::UnexpectedEof);
            remaining = vec![0xAA];
        }
        CASE_TRAILING => {
            bytes.extend_from_slice(&[0, 0, 0xFE, 0xED]);
            remaining = vec![0xFE, 0xED];
        }
        CASE_PRESENT_QC => {
            let qc = simple_qc_bytes();
            bytes = proposal_prefix_with_qc(0, &qc);
            bytes.extend_from_slice(&[0, 0]);
        }
        CASE_BAD_QC => {
            bytes = proposal_prefix_with_qc(0, &[0x02]);
            expected = Err(WireError::UnexpectedEof);
            remaining = Vec::new();
        }
        CASE_BAD_HEADER => {
            bytes = vec![0xFF, 0x01];
            expected = Err(WireError::InvalidValue(
                "unexpected msg_type for BlockProposal",
            ));
            remaining = bytes[1..].to_vec();
        }
        CASE_WRAPPED_NET => {
            bytes = proposal_prefix(1);
            bytes.extend_from_slice(&[1, 0, 0xAA]);
            expected = Err(WireError::UnexpectedEof);
            remaining = vec![1, 0, 0xAA];
        }
        CASE_LARGE_TX_LEN => {
            bytes = proposal_prefix(1);
            bytes.extend_from_slice(&u32::MAX.to_le_bytes());
            expected = Err(WireError::UnexpectedEof);
        }
        CASE_MAX_SIGNATURE_LEN => {
            bytes.extend_from_slice(&u16::MAX.to_le_bytes());
            expected = Err(WireError::UnexpectedEof);
        }
        _ => return Err(format!("unsupported decoder case {}", case.name)),
    }
    Ok((bytes, expected, remaining))
}

fn check_decoder_result(
    case: &ChildCase,
    result: Result<BlockProposal, WireError>,
    remaining: &[u8],
    expected: Result<(), WireError>,
    expected_remaining: Vec<u8>,
) -> Result<(), String> {
    match expected {
        Ok(()) => {
            let proposal = result.map_err(|error| format!("valid proposal rejected: {error:?}"))?;
            if remaining != expected_remaining {
                return Err(format!(
                    "successful remaining cursor {:?} did not equal expected {:?}",
                    remaining, expected_remaining
                ));
            }
            if case.id == CASE_ZERO && (!proposal.txs.is_empty() || !proposal.signature.is_empty())
            {
                return Err("zero-transaction decoded fields differ".into());
            }
            if case.id == CASE_EMPTY_TX && proposal.txs != vec![vec![]] {
                return Err("empty transaction was not preserved".into());
            }
            if case.id == CASE_NONEMPTY_TX && proposal.txs != vec![vec![0xA1, 0xB2, 0xC3]] {
                return Err("nonempty transaction was not preserved".into());
            }
            if case.id == CASE_MIXED_TX
                && (proposal.txs != vec![vec![], vec![4, 5], vec![]]
                    || proposal.signature != vec![0xEE])
            {
                return Err("mixed empty/nonempty values were not preserved".into());
            }
            if case.id == CASE_TRAILING && remaining != [0xFE, 0xED] {
                return Err("direct decoder trailing bytes changed".into());
            }
            if case.id == CASE_PRESENT_QC && proposal.qc.is_none() {
                return Err("present optional QC was not decoded".into());
            }
            Ok(())
        }
        Err(expected_error) => {
            let actual = result
                .err()
                .ok_or_else(|| "malformed proposal decoded".to_string())?;
            if actual != expected_error {
                return Err(format!("expected {expected_error:?}, got {actual:?}"));
            }
            if remaining != expected_remaining {
                return Err(format!(
                    "remaining cursor {:?} did not equal expected {:?}",
                    remaining, expected_remaining
                ));
            }
            Ok(())
        }
    }
}

fn should_have_no_transaction_allocation(case: u32) -> bool {
    matches!(
        case,
        CASE_LARGE_COUNT | CASE_TRUNCATED_PREFIX_0
            ..=CASE_TRUNCATED_PREFIX_3
                | CASE_TRUNCATED_BODY
                | CASE_COUNT_MISMATCH
                | CASE_SIGNATURE_PREFIX_0
                | CASE_SIGNATURE_PREFIX_1
                | CASE_SIGNATURE_BODY
                | CASE_SIGNATURE_AFTER_TX
                | CASE_BAD_HEADER
                | CASE_WRAPPED_NET
                | CASE_LARGE_TX_LEN
                | CASE_MAX_SIGNATURE_LEN
    )
}

fn event_values(count: usize) -> Result<Vec<(u8, u64, u64, u64)>, String> {
    if count > EVENT_LIMIT {
        return Err("snapshot count exceeds event storage".into());
    }
    let mut result = Vec::with_capacity(count);
    for event in EVENTS.iter().take(count) {
        result.push((
            event.operation.load(Ordering::Relaxed),
            event.size.load(Ordering::Relaxed),
            event.alignment.load(Ordering::Relaxed),
            event.order.load(Ordering::Relaxed),
        ));
    }
    Ok(result)
}

fn proposal_prefix(tx_count: u32) -> Vec<u8> {
    proposal_prefix_with_qc(tx_count, &[])
}

fn proposal_prefix_with_qc(tx_count: u32, qc: &[u8]) -> Vec<u8> {
    let header = BlockHeader {
        version: 1,
        chain_id: 7,
        epoch: 2,
        height: 3,
        round: 4,
        parent_block_id: [0x11; 32],
        payload_hash: [0x22; 32],
        proposer_index: 5,
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        tx_count,
        timestamp: 6,
        payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
        next_epoch: 0,
        batch_commitment: [0x33; 32],
    };
    let mut prefix = Vec::with_capacity(159 + qc.len());
    prefix.push(MSG_TYPE_BLOCK_PROPOSAL);
    prefix.push(header.version);
    prefix.extend_from_slice(&header.chain_id.to_le_bytes());
    prefix.extend_from_slice(&header.epoch.to_le_bytes());
    prefix.extend_from_slice(&header.height.to_le_bytes());
    prefix.extend_from_slice(&header.round.to_le_bytes());
    prefix.extend_from_slice(&header.parent_block_id);
    prefix.extend_from_slice(&header.payload_hash);
    prefix.extend_from_slice(&header.proposer_index.to_le_bytes());
    prefix.extend_from_slice(&header.suite_id.to_le_bytes());
    prefix.extend_from_slice(&tx_count.to_le_bytes());
    prefix.extend_from_slice(&header.timestamp.to_le_bytes());
    prefix.push(header.payload_kind);
    prefix.extend_from_slice(&header.next_epoch.to_le_bytes());
    prefix.extend_from_slice(&header.batch_commitment);
    prefix.extend_from_slice(&(qc.len() as u32).to_le_bytes());
    prefix.extend_from_slice(qc);
    prefix
}

fn append_tx(bytes: &mut Vec<u8>, tx: &[u8]) {
    bytes.extend_from_slice(&(tx.len() as u32).to_le_bytes());
    bytes.extend_from_slice(tx);
}

fn malformed_after_one_transaction(count: u32, complete_body: bool) -> Vec<u8> {
    let mut bytes = proposal_prefix(count);
    if complete_body {
        append_tx(&mut bytes, &[0xA1, 0xB2, 0xC3]);
    } else {
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&[0xA1, 0xB2, 0xC3]);
    }
    bytes
}

fn simple_qc_bytes() -> Vec<u8> {
    let qc = QuorumCertificate {
        version: 1,
        chain_id: 7,
        epoch: 2,
        height: 3,
        round: 4,
        step: 1,
        block_id: [0x44; 32],
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signer_bitmap: vec![],
        signatures: vec![],
    };
    let mut bytes = Vec::new();
    qc.encode(&mut bytes);
    bytes.push(0x99);
    bytes
}

#[derive(Debug)]
struct ChildOutcome {
    status: ExitStatus,
    elapsed_ms: u128,
    timed_out: bool,
    killed: bool,
    reaped: bool,
}

fn launch_child(case: &ChildCase, evidence_root: &std::path::Path) -> Result<ChildOutcome, String> {
    let mut invocation = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut invocation))
        .map_err(|error| format!("cannot obtain fresh invocation ID: {error}"))?;
    let invocation_hex: String = invocation
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let directory = evidence_root.join(format!("{}-{}", case.id, invocation_hex));
    fs::create_dir(&directory)
        .map_err(|error| format!("cannot create private run dir: {error}"))?;
    fs::set_permissions(
        &directory,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .map_err(|error| format!("cannot protect private run dir: {error}"))?;
    let evidence_path = directory.join("records.bin");
    let event_path = directory.join("events.bin");
    create_private_file(&evidence_path)?;
    create_private_file(&event_path)?;
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let start = Instant::now();
    let mut child = Command::new("/usr/bin/prlimit")
        .args(["--cpu=5:5", "--as=536870912:536870912", "--core=0:0", "--"])
        .arg(executable)
        .args([
            "--exact",
            "isolated_child_entry",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("QBIND_A21_INVOCATION", &invocation_hex)
        .env("QBIND_A21_CASE_ID", case.id.to_string())
        .env("QBIND_A21_CHILD_CASE", case.name)
        .env("QBIND_A21_EVIDENCE_FILE", &evidence_path)
        .env("QBIND_A21_EVENT_FILE", &event_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("cannot spawn contained child: {error}"))?;
    let outcome = wait_bounded(&mut child, start)?;
    let evidence = read_bounded(&evidence_path, EVIDENCE_MAX + 1)?;
    let events = read_bounded(&event_path, EVENT_FILE_MAX + 1)?;
    #[cfg(target_os = "linux")]
    use std::os::unix::process::ExitStatusExt;
    append_parent_log(
        evidence_root,
        &format!(
            "case={} id={} invocation={} exit_code={:?} signal={:?} elapsed_ms={} timed_out={} killed={} reaped={} evidence={} events={}\n",
            case.name,
            case.id,
            invocation_hex,
            outcome.status.code(),
            outcome.status.signal(),
            outcome.elapsed_ms,
            outcome.timed_out,
            outcome.killed,
            outcome.reaped,
            evidence.len(),
            events.len()
        ),
    )?;
    validate_child_evidence(case, &invocation, &outcome, &evidence, &events)?;
    Ok(outcome)
}

fn create_private_file(path: &std::path::Path) -> Result<(), String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map(|_| ())
        .map_err(|error| format!("cannot create fresh private evidence file: {error}"))
}

fn wait_bounded(child: &mut Child, start: Instant) -> Result<ChildOutcome, String> {
    let deadline = start + WALL_LIMIT;
    let mut timed_out = false;
    let mut killed = false;
    loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            return Ok(ChildOutcome {
                status,
                elapsed_ms: start.elapsed().as_millis(),
                timed_out,
                killed,
                reaped: true,
            });
        }
        if Instant::now() >= deadline {
            timed_out = true;
            if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
                return Ok(ChildOutcome {
                    status,
                    elapsed_ms: start.elapsed().as_millis(),
                    timed_out,
                    killed,
                    reaped: true,
                });
            }
            child
                .kill()
                .map_err(|error| format!("deadline kill failed: {error}"))?;
            killed = true;
            let status = child
                .wait()
                .map_err(|error| format!("child reap failed: {error}"))?;
            return Ok(ChildOutcome {
                status,
                elapsed_ms: start.elapsed().as_millis(),
                timed_out,
                killed,
                reaped: true,
            });
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn read_bounded(path: &std::path::Path, maximum: usize) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err("child result path is not a private regular file".into());
    }
    let mut bytes = Vec::with_capacity(maximum);
    file.take(maximum as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() == maximum {
        return Err("child result exceeds bounded read maximum".into());
    }
    Ok(bytes)
}

fn validate_child_evidence(
    case: &ChildCase,
    invocation: &[u8; 16],
    outcome: &ChildOutcome,
    records: &[u8],
    events: &[u8],
) -> Result<(), String> {
    if outcome.timed_out || outcome.killed || !outcome.reaped {
        return Err(format!(
            "child did not complete within deadline: {outcome:?}"
        ));
    }
    if records.len() != EVIDENCE_MAX {
        return Err(format!(
            "child evidence has {} bytes, expected {EVIDENCE_MAX}",
            records.len()
        ));
    }
    for sequence in 0..3 {
        let record = &records[sequence * RECORD_LEN..(sequence + 1) * RECORD_LEN];
        if &record[..4] != MAGIC
            || record[4] != 1
            || record[6] != sequence as u8
            || record[7] != 0
            || &record[8..24] != invocation
            || u32::from_le_bytes(record[24..28].try_into().unwrap()) != case.id
        {
            return Err(format!("record {sequence} identity/header mismatch"));
        }
    }
    if records[5] != REC_ENTRY || records[28..RECORD_LEN].iter().any(|byte| *byte != 0) {
        return Err("ENTRY kind or reserved padding is invalid".into());
    }
    let setup = &records[RECORD_LEN..2 * RECORD_LEN];
    if setup[5] != REC_SETUP
        || setup[28..32].iter().any(|byte| *byte != 0)
        || u64_at(setup, 32) != CPU_LIMIT
        || u64_at(setup, 40) != CPU_LIMIT
        || u64_at(setup, 48) != ADDRESS_LIMIT
        || u64_at(setup, 56) != ADDRESS_LIMIT
        || u64_at(setup, 64) != 0
        || u64_at(setup, 72) != 0
        || u64_at(setup, 80) != 0
        || setup[88..].iter().any(|byte| *byte != 0)
    {
        return Err("child setup record did not verify limits and dumpability".into());
    }
    let terminal = &records[2 * RECORD_LEN..];
    if terminal[5] != case.terminal {
        return Err("child terminal record kind mismatch".into());
    }
    if case.terminal == REC_COMPLETE {
        let actual_events = u64_at(terminal, 32);
        let actual_bytes = u64_at(terminal, 40);
        if !outcome.status.success()
            || terminal[48..].iter().any(|byte| *byte != 0)
            || u32::from_le_bytes(terminal[28..32].try_into().unwrap()) != case.expected_assertions
            || actual_events > EVENT_LIMIT as u64
            || actual_bytes > BYTE_LIMIT
            || case
                .expected_events
                .is_some_and(|expected| expected != actual_events)
            || case
                .expected_bytes
                .is_some_and(|expected| expected != actual_bytes)
        {
            return Err("child did not complete the exact expected assertions".into());
        }
        validate_event_snapshot(
            case,
            invocation,
            events,
            u64_at(terminal, 32),
            u64_at(terminal, 40),
        )?;
    } else {
        if outcome.status.signal() != Some(6) {
            return Err("guard record did not accompany SIGABRT".into());
        }
        let reason = u32::from_le_bytes(terminal[28..32].try_into().unwrap());
        if !known_guard_reason(reason)
            || reason != case.guard_reason
            || terminal[34..40].iter().any(|byte| *byte != 0)
            || u64_at(terminal, 88) != u64_at(terminal, 72)
            || terminal[96..].iter().any(|byte| *byte != 0)
        {
            return Err("guard reason did not match the calibration case".into());
        }
        if !events.is_empty() {
            return Err("abort calibration unexpectedly wrote a normal event snapshot".into());
        }
        validate_guard_counters(case.id, terminal)?;
    }
    Ok(())
}

fn validate_event_snapshot(
    case: &ChildCase,
    invocation: &[u8; 16],
    events: &[u8],
    count: u64,
    bytes: u64,
) -> Result<(), String> {
    if events.len() < EVENT_HEADER_LEN
        || &events[..4] != EVENT_MAGIC
        || events[4] != 1
        || &events[8..24] != invocation
        || u32::from_le_bytes(events[24..28].try_into().unwrap()) != case.id
        || u32::from_le_bytes(events[28..32].try_into().unwrap()) as u64 != count
        || events[5..8].iter().any(|byte| *byte != 0)
        || events.len() != EVENT_HEADER_LEN + count as usize * EVENT_LEN
    {
        return Err("event snapshot identity, count or length mismatch".into());
    }
    let mut sum = 0u64;
    for index in 0..count as usize {
        let entry = &events[EVENT_HEADER_LEN + index * EVENT_LEN..][..EVENT_LEN];
        if !matches!(entry[0], OP_ALLOC | OP_ALLOC_ZEROED | OP_REALLOC)
            || entry[1..8].iter().any(|byte| *byte != 0)
            || u64_at(entry, 24) != index as u64 + 1
            || u64_at(entry, 8) > REQUEST_LIMIT
            || u64_at(entry, 16) == 0
            || !u64_at(entry, 16).is_power_of_two()
        {
            return Err("event snapshot contains an invalid operation/order".into());
        }
        sum = sum
            .checked_add(u64_at(entry, 8))
            .ok_or_else(|| "event snapshot byte sum overflow".to_string())?;
    }
    if sum != bytes {
        return Err("event snapshot byte sum mismatch".into());
    }
    if count > EVENT_LIMIT as u64 || bytes > BYTE_LIMIT {
        return Err("event snapshot exceeds the inclusive observer ceilings".into());
    }
    if matches!(
        case.id,
        CASE_SINGLE_ALLOWED | CASE_BYTES_ALLOWED | CASE_EVENTS_ALLOWED
    ) {
        let expected = match case.id {
            CASE_SINGLE_ALLOWED => (1usize, 65_536u64),
            CASE_BYTES_ALLOWED => (64usize, 4_096u64),
            CASE_EVENTS_ALLOWED => (256usize, 1u64),
            _ => unreachable!(),
        };
        if count as usize != expected.0
            || (0..expected.0).any(|index| {
                let entry = &events[EVENT_HEADER_LEN + index * EVENT_LEN..][..EVENT_LEN];
                entry[0] != OP_ALLOC || u64_at(entry, 8) != expected.1 || u64_at(entry, 16) != 1
            })
        {
            return Err("inclusive calibration event sequence did not match exactly".into());
        }
    }
    Ok(())
}

fn validate_guard_counters(case_id: u32, record: &[u8]) -> Result<(), String> {
    let (prior_events, prior_bytes, prospective_events, prospective_bytes, requested) =
        match case_id {
            CASE_SINGLE_REJECTED => (0, 0, 1, 65_537, 65_537),
            CASE_BYTES_REJECTED => (64, 262_144, 65, 266_240, 4_096),
            CASE_EVENTS_REJECTED => (256, 256, 257, 257, 1),
            _ => return Err("guard result used for a non-guard case".into()),
        };
    if record[32] != OP_ALLOC
        || record[33] != 0
        || u64_at(record, 40) != requested
        || u64_at(record, 48) != 1
        || u64_at(record, 56) != prior_events
        || u64_at(record, 64) != prior_bytes
        || u64_at(record, 72) != prospective_events
        || u64_at(record, 80) != prospective_bytes
        || u64_at(record, 88) != prospective_events
    {
        return Err("guard record does not contain exact prior/prospective counters".into());
    }
    Ok(())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn append_parent_log(root: &std::path::Path, line: &str) -> Result<(), String> {
    let path = root.join("parent-results.log");
    let mut log = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| error.to_string())?;
    log.write_all(line.as_bytes())
        .and_then(|_| log.sync_all())
        .map_err(|error| error.to_string())
}

fn run_cases(names: &[&str], phase: &str) -> Result<(), String> {
    let root = evidence_root(phase)?;
    for name in names {
        let case = case_by_name(name).ok_or_else(|| format!("unknown parent case {name}"))?;
        launch_child(&case, &root)?;
    }
    Ok(())
}

fn evidence_root(phase: &str) -> Result<std::path::PathBuf, String> {
    let root = std::env::var_os("QBIND_A21_EVIDENCE_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("qbind-a21-f1-evidence"));
    let root = root.join(phase);
    fs::create_dir_all(&root).map_err(|error| format!("cannot create evidence root: {error}"))?;
    fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .map_err(|error| format!("cannot protect evidence root: {error}"))?;
    Ok(root)
}

#[test]
fn instrumentation_calibration() {
    run_cases(
        &[
            "single_allowed",
            "single_rejected",
            "bytes_allowed",
            "bytes_rejected",
            "events_allowed",
            "events_rejected",
        ],
        "instrumentation",
    )
    .unwrap();
}

#[test]
fn candidate_acceptance_matrix() {
    run_cases(
        &[
            "large_count",
            "zero",
            "empty_tx",
            "nonempty_tx",
            "mixed_tx",
            "prefix_0",
            "prefix_1",
            "prefix_2",
            "prefix_3",
            "body_truncated",
            "count_mismatch",
            "signature_prefix_0",
            "signature_prefix_1",
            "signature_body",
            "signature_after_tx",
            "trailing",
            "present_qc",
            "bad_qc",
            "bad_header",
            "wrapped_net",
            "large_tx_len",
            "max_signature_len",
        ],
        "candidate",
    )
    .unwrap();
    target_layout_boundaries().unwrap();
}

#[test]
fn protocol_negative_controls() {
    let root = evidence_root("protocol-negative").unwrap();
    let invocation = [0x5Au8; 16];
    let valid = make_protocol_records(CASE_SINGLE_REJECTED, &invocation);
    if parse_protocol_sequence(
        &valid,
        CASE_SINGLE_REJECTED,
        &invocation,
        REC_GUARD,
        GUARD_SINGLE_REQUEST,
    )
    .is_err()
    {
        panic!("well-formed calibrated guard evidence was rejected");
    }
    let mut malformed = vec![
        valid[..2 * RECORD_LEN].to_vec(),
        [valid.as_slice(), &[0u8; RECORD_LEN]].concat(),
    ];
    let mut duplicate = valid;
    duplicate[RECORD_LEN + 5] = REC_GUARD;
    malformed.push(duplicate);
    let mut stale_id = make_protocol_records(CASE_SINGLE_REJECTED, &invocation);
    stale_id[8] ^= 1;
    malformed.push(stale_id);
    let mut wrong_case = make_protocol_records(CASE_SINGLE_REJECTED, &invocation);
    wrong_case[24] ^= 1;
    malformed.push(wrong_case);
    let mut wrong_reason = make_protocol_records(CASE_SINGLE_REJECTED, &invocation);
    wrong_reason[2 * RECORD_LEN + 28] ^= 1;
    malformed.push(wrong_reason);
    let mut out_of_order = make_protocol_records(CASE_SINGLE_REJECTED, &invocation);
    out_of_order[RECORD_LEN + 6] = 2;
    malformed.push(out_of_order);
    for candidate in malformed {
        if parse_protocol_sequence(
            &candidate,
            CASE_SINGLE_REJECTED,
            &invocation,
            REC_GUARD,
            GUARD_SINGLE_REQUEST,
        )
        .is_ok()
        {
            panic!("malformed/stale/duplicate evidence sequence was accepted");
        }
    }
    for (selector, filter, expected_code) in [
        (None, "isolated_child_entry", false),
        (Some("unknown"), "isolated_child_entry", false),
        (Some("single_allowed"), "isolated_child_entri", true),
        (Some("single_allowed"), "no_such_child_test", true),
    ] {
        verify_dispatch_negative(selector, filter, expected_code, &root).unwrap();
    }
}

#[test]
#[ignore]
fn baseline_small_controls() {
    run_cases(&["baseline_two", "baseline_eight"], "baseline").unwrap();
}

#[test]
#[ignore]
fn isolated_child_entry() {
    if let Err(error) = isolated_child_entry_impl() {
        eprintln!("isolated child failed: {error}");
        panic!("isolated child did not satisfy its selected case");
    }
}

fn parse_protocol_sequence(
    bytes: &[u8],
    case_id: u32,
    invocation: &[u8; 16],
    terminal_kind: u8,
    expected_reason: u32,
) -> Result<(), String> {
    if bytes.len() != EVIDENCE_MAX {
        return Err("record length is invalid".into());
    }
    for sequence in 0..3 {
        let record = &bytes[sequence * RECORD_LEN..][..RECORD_LEN];
        if &record[..4] != MAGIC
            || record[4] != 1
            || record[6] != sequence as u8
            || record[7] != 0
            || &record[8..24] != invocation
            || u32::from_le_bytes(record[24..28].try_into().unwrap()) != case_id
        {
            return Err("record sequence is invalid".into());
        }
    }
    if bytes[5] != REC_ENTRY
        || bytes[RECORD_LEN + 5] != REC_SETUP
        || bytes[2 * RECORD_LEN + 5] != terminal_kind
        || bytes[28..RECORD_LEN].iter().any(|byte| *byte != 0)
        || bytes[RECORD_LEN + 28..RECORD_LEN + 32]
            .iter()
            .any(|byte| *byte != 0)
        || bytes[RECORD_LEN + 88..2 * RECORD_LEN]
            .iter()
            .any(|byte| *byte != 0)
        || !matches!(terminal_kind, REC_COMPLETE | REC_GUARD)
        || u64_at(bytes, RECORD_LEN + 32) != CPU_LIMIT
        || u64_at(bytes, RECORD_LEN + 40) != CPU_LIMIT
        || u64_at(bytes, RECORD_LEN + 48) != ADDRESS_LIMIT
        || u64_at(bytes, RECORD_LEN + 56) != ADDRESS_LIMIT
        || u64_at(bytes, RECORD_LEN + 64) != 0
        || u64_at(bytes, RECORD_LEN + 72) != 0
        || u64_at(bytes, RECORD_LEN + 80) != 0
    {
        return Err("record setup or terminal state is invalid".into());
    }
    if terminal_kind == REC_GUARD
        && (u32::from_le_bytes(
            bytes[2 * RECORD_LEN + 28..2 * RECORD_LEN + 32]
                .try_into()
                .unwrap(),
        ) != expected_reason
            || !known_guard_reason(expected_reason))
    {
        return Err("guard reason is invalid".into());
    }
    if terminal_kind == REC_GUARD {
        validate_guard_counters(case_id, &bytes[2 * RECORD_LEN..])?;
        if bytes[2 * RECORD_LEN + 34..2 * RECORD_LEN + 40]
            .iter()
            .any(|byte| *byte != 0)
            || bytes[2 * RECORD_LEN + 96..].iter().any(|byte| *byte != 0)
        {
            return Err("guard record padding is invalid".into());
        }
    }
    if terminal_kind == REC_COMPLETE
        && u32::from_le_bytes(
            bytes[2 * RECORD_LEN + 28..2 * RECORD_LEN + 32]
                .try_into()
                .unwrap(),
        ) == 0
    {
        return Err("completion assertion set is empty".into());
    }
    Ok(())
}

fn make_protocol_records(case_id: u32, invocation: &[u8; 16]) -> Vec<u8> {
    let mut records = vec![0u8; EVIDENCE_MAX];
    for (sequence, kind) in [REC_ENTRY, REC_SETUP, REC_GUARD].into_iter().enumerate() {
        let record = &mut records[sequence * RECORD_LEN..(sequence + 1) * RECORD_LEN];
        record[..4].copy_from_slice(MAGIC);
        record[4] = 1;
        record[5] = kind;
        record[6] = sequence as u8;
        record[8..24].copy_from_slice(invocation);
        record[24..28].copy_from_slice(&case_id.to_le_bytes());
    }
    let setup = &mut records[RECORD_LEN..2 * RECORD_LEN];
    setup[32..40].copy_from_slice(&CPU_LIMIT.to_le_bytes());
    setup[40..48].copy_from_slice(&CPU_LIMIT.to_le_bytes());
    setup[48..56].copy_from_slice(&ADDRESS_LIMIT.to_le_bytes());
    setup[56..64].copy_from_slice(&ADDRESS_LIMIT.to_le_bytes());
    let guard = &mut records[2 * RECORD_LEN..];
    guard[28..32].copy_from_slice(&GUARD_SINGLE_REQUEST.to_le_bytes());
    guard[32] = OP_ALLOC;
    guard[40..48].copy_from_slice(&65_537u64.to_le_bytes());
    guard[48..56].copy_from_slice(&1u64.to_le_bytes());
    guard[72..80].copy_from_slice(&1u64.to_le_bytes());
    guard[80..88].copy_from_slice(&65_537u64.to_le_bytes());
    guard[88..96].copy_from_slice(&1u64.to_le_bytes());
    records
}

fn verify_dispatch_negative(
    selector: Option<&str>,
    test_filter: &str,
    expect_zero_matches: bool,
    root: &std::path::Path,
) -> Result<(), String> {
    let mut invocation = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut invocation))
        .map_err(|error| error.to_string())?;
    let invocation_hex: String = invocation
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let directory = root.join(format!("dispatch-{}", invocation_hex));
    fs::create_dir(&directory).map_err(|error| error.to_string())?;
    fs::set_permissions(
        &directory,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .map_err(|error| error.to_string())?;
    let evidence_path = directory.join("records.bin");
    let event_path = directory.join("events.bin");
    create_private_file(&evidence_path)?;
    create_private_file(&event_path)?;
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let mut command = Command::new("/usr/bin/prlimit");
    command
        .args(["--cpu=5:5", "--as=536870912:536870912", "--core=0:0", "--"])
        .arg(executable)
        .args([
            "--exact",
            test_filter,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("QBIND_A21_INVOCATION", &invocation_hex)
        .env("QBIND_A21_CASE_ID", CASE_SINGLE_ALLOWED.to_string())
        .env("QBIND_A21_EVIDENCE_FILE", &evidence_path)
        .env("QBIND_A21_EVENT_FILE", &event_path)
        .env_remove("QBIND_A21_CHILD_CASE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(selector) = selector {
        command.env("QBIND_A21_CHILD_CASE", selector);
    }
    let start = Instant::now();
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    let outcome = wait_bounded(&mut child, start)?;
    let records = read_bounded(&evidence_path, EVIDENCE_MAX + 1)?;
    let events = read_bounded(&event_path, EVENT_FILE_MAX + 1)?;
    if outcome.timed_out
        || outcome.killed
        || !outcome.reaped
        || !records.is_empty()
        || !events.is_empty()
    {
        return Err("invalid child dispatch unexpectedly entered or failed containment".into());
    }
    if expect_zero_matches != outcome.status.success() {
        return Err("zero-match test filter did not have its reviewed exit outcome".into());
    }
    if !expect_zero_matches && outcome.status.success() {
        return Err("missing/unknown selector was accepted".into());
    }
    append_parent_log(
        root,
        &format!(
            "dispatch selector={selector:?} filter={test_filter} zero_matches={expect_zero_matches} exit_code={:?} signal={:?} records={} elapsed_ms={} timed_out={} killed={} reaped={}\n",
            outcome.status.code(),
            outcome.status.signal(),
            records.len(),
            outcome.elapsed_ms,
            outcome.timed_out,
            outcome.killed,
            outcome.reaped
        ),
    )
}

fn target_layout_boundaries() -> Result<(), String> {
    let count = usize::try_from(u32::MAX).map_err(|_| "u32 does not fit usize".to_string())?;
    let layout = Layout::array::<Vec<u8>>(count)
        .map_err(|error| format!("target Vec layout boundary: {error}"))?;
    append_parent_log(
        &evidence_root("candidate")?,
        &format!(
            "target_layout usize_bits={} vec_size={} vec_align={} count={} layout_size={} layout_align={} representable=true allocation_attempted=false 32bit_execution=false\n",
            usize::BITS,
            std::mem::size_of::<Vec<u8>>(),
            std::mem::align_of::<Vec<u8>>(),
            count,
            layout.size(),
            layout.align()
        ),
    )
}
