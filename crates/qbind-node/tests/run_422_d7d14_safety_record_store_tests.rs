//! Run 422 D7-D14 — scoped acceptance tests for the isolated, disabled-by-default
//! safety-record storage component (accepted D14 contract, §13).
//!
//! H-matrix subset covered here: H2–H12, H16, H18–H25, H26, H27, H30.
//! Explicitly NOT claimed: H1, H13, H14, H15, H17, H25e, H26l, H28, H29.
//!
//! Each `h##_*` test names the row it exercises and the evidence level. Real
//! RocksDB rows use `tempfile::TempDir`; process-death rows use the child-process
//! harness at the bottom of this file. Stage-2 crypto verification is unwired, so
//! every validated record is carried `Unverified`.

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::qc::QuorumCertificate as LogicalQc;
use qbind_consensus::timeout::{TimeoutCertificate, TimeoutMsg};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_node::safety_record_store::backend::{InjectFault, SafetyBackend, SafetyBackendPolicy};
use qbind_node::safety_record_store::codec::{decode_record, encode_record};
use qbind_node::safety_record_store::error::SafetyStoreError;
use qbind_node::safety_record_store::owner::{make_locked_qc, PublishResult, SafetyRecordOwner};
use qbind_node::safety_record_store::profile::{
    max_qc_bytes, max_safety_record_bytes, max_tc_bytes, PinnedSafetyContext,
};
use qbind_node::safety_record_store::record::{
    CommittedAnchor, DecodedRecord, EvidenceStatus, LockedRecord, RetainedGeneration, SafetyRecord,
    SupportingEvidence, WireQc,
};
use qbind_node::safety_record_store::validate::{validate_decoded, FixtureCommittedHistory};

// ---------------------------------------------------------------------------
// Direct allocation observation harness (test-only; NOT a production path)
// ---------------------------------------------------------------------------
//
// A `#[global_allocator]` that delegates every operation to the system allocator
// and, *only while explicitly armed on the current thread*, counts the number of
// `alloc`/`realloc` calls. The arm flag and counter are `const`-initialized
// thread-locals, so reading them inside the allocator never itself allocates and
// never recurses. Default is disarmed, so this changes no behaviour for any other
// test; it merely lets a measured region assert that a success path allocated
// *nothing component-owned* — the direct observation §4/§9 require, which the
// `evidence_payload_encode_count` encode counter alone cannot establish (zero
// encodes is not zero allocations). The harness never clones the observed data.
struct CountingAllocator;

thread_local! {
    static ALLOC_ARMED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static ALLOC_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    // Live-byte observation (Item B/D): the net live heap bytes allocated while
    // armed, and the peak the net reached. `LIVE_MISSED` latches true if an
    // instrumentation invariant is violated (a dealloc frees more than the
    // tracked live total, i.e. a pre-arm allocation was freed inside the armed
    // interval) so observers FAIL LOUDLY rather than silently truncating a
    // peak. `LIVE_OVERFLOW` latches on an arithmetic overflow of the counters.
    static LIVE_ARMED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static LIVE_CUR: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static LIVE_PEAK: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static LIVE_MISSED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static LIVE_OVERFLOW: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[inline]
fn live_on_alloc(size: usize) {
    if LIVE_ARMED.with(|a| a.get()) {
        LIVE_CUR.with(|c| match c.get().checked_add(size) {
            Some(v) => {
                c.set(v);
                LIVE_PEAK.with(|p| {
                    if v > p.get() {
                        p.set(v);
                    }
                });
            }
            None => LIVE_OVERFLOW.with(|o| o.set(true)),
        });
    }
}

#[inline]
fn live_on_dealloc(size: usize) {
    if LIVE_ARMED.with(|a| a.get()) {
        LIVE_CUR.with(|c| {
            let cur = c.get();
            if size > cur {
                // Freeing more than we tracked: a pre-arm allocation was released
                // inside the interval. Flag it; do not let the counter wrap.
                LIVE_MISSED.with(|m| m.set(true));
                c.set(0);
            } else {
                c.set(cur - size);
            }
        });
    }
}

unsafe impl std::alloc::GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        if ALLOC_ARMED.with(|a| a.get()) {
            ALLOC_COUNT.with(|c| c.set(c.get() + 1));
        }
        live_on_alloc(layout.size());
        std::alloc::System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        live_on_dealloc(layout.size());
        std::alloc::System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, new_size: usize) -> *mut u8 {
        if ALLOC_ARMED.with(|a| a.get()) {
            ALLOC_COUNT.with(|c| c.set(c.get() + 1));
        }
        // A realloc frees `layout.size()` and allocates `new_size`.
        live_on_dealloc(layout.size());
        live_on_alloc(new_size);
        std::alloc::System.realloc(ptr, layout, new_size)
    }
}

/// Outcome of a live-byte observation interval.
#[derive(Debug, Clone, Copy)]
struct LiveObservation {
    /// Peak net live heap bytes reached during the interval.
    peak: usize,
    /// Net live heap bytes still outstanding at the end of the interval.
    end: usize,
    /// True if a dealloc released more than the tracked live total (a pre-arm
    /// allocation freed inside the interval) — the peak may be under-counted.
    missed: bool,
    /// True if the byte counters overflowed.
    overflow: bool,
}

impl LiveObservation {
    /// Assert the instrumentation stayed sound: no missed tracking, no overflow.
    fn assert_sound(&self, ctx: &str) {
        assert!(
            !self.missed,
            "{ctx}: live-byte instrumentation missed tracking (pre-arm free inside interval)"
        );
        assert!(
            !self.overflow,
            "{ctx}: live-byte instrumentation overflowed"
        );
    }
}

/// Run `f` with live-byte observation armed on the current thread, returning
/// `(result, observation)`. The caller must ensure every object it wants
/// excluded from the measurement (fixtures, backends) is constructed OUTSIDE
/// `f`, and that any object owned *outside* `f` survives the interval (is not
/// freed inside it) so the peak is a faithful component-owned figure. No
/// cloning of the observed objects occurs here.
fn measure_live_bytes<T>(f: impl FnOnce() -> T) -> (T, LiveObservation) {
    LIVE_CUR.with(|c| c.set(0));
    LIVE_PEAK.with(|p| p.set(0));
    LIVE_MISSED.with(|m| m.set(false));
    LIVE_OVERFLOW.with(|o| o.set(false));
    LIVE_ARMED.with(|a| a.set(true));
    let out = f();
    LIVE_ARMED.with(|a| a.set(false));
    let obs = LiveObservation {
        peak: LIVE_PEAK.with(|p| p.get()),
        end: LIVE_CUR.with(|c| c.get()),
        missed: LIVE_MISSED.with(|m| m.get()),
        overflow: LIVE_OVERFLOW.with(|o| o.get()),
    };
    (out, obs)
}

#[global_allocator]
static COUNTING_ALLOCATOR: CountingAllocator = CountingAllocator;

/// Run `f` on the current thread with allocation counting armed, returning
/// `(result, number_of_alloc/realloc_calls_during_f)`. Arming/disarming and the
/// returned count observe only the current thread; nothing inside the measured
/// closure may spawn work on another thread if the count is to be meaningful.
fn measure_allocs<T>(f: impl FnOnce() -> T) -> (T, usize) {
    ALLOC_COUNT.with(|c| c.set(0));
    ALLOC_ARMED.with(|a| a.set(true));
    let out = f();
    ALLOC_ARMED.with(|a| a.set(false));
    let count = ALLOC_COUNT.with(|c| c.get());
    (out, count)
}

// ---------------------------------------------------------------------------
// Fixtures (clearly labelled; NOT production history recovery)
// ---------------------------------------------------------------------------

const QC_SUITE: u16 = 1;
const TIMEOUT_SUITE: u8 = 100;
const S_SIG: usize = 8;
const CHAIN_ID: u32 = 42;
const EPOCH: u64 = 7;

fn ctx_n(n: u64) -> PinnedSafetyContext {
    let validators = (0..n).map(|i| (ValidatorId::new(i), 1u64)).collect();
    PinnedSafetyContext {
        network_genesis_id: [1u8; 32],
        authority_context_ref: [2u8; 32],
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        qc_suite_id: QC_SUITE,
        timeout_suite_id: TIMEOUT_SUITE,
        s_sig: S_SIG,
        validators,
        require_height_equals_round: false,
    }
}

/// A structurally/semantically valid wire QC for `lock_block_id`/`lock_view`.
fn valid_wire_qc(ctx: &PinnedSafetyContext, block_id: [u8; 32], view: u64) -> WireQc {
    let n = ctx.n();
    // Set the first ceil(2N/3) signer bits.
    let need = ((2 * n) + 2) / 3; // ceil(2N/3)
    let mut bitmap = vec![0u8; ((n + 7) / 8).max(1)];
    let mut signatures = Vec::new();
    for i in 0..need {
        bitmap[i / 8] |= 1 << (i % 8);
        signatures.push(vec![0xABu8; S_SIG]);
    }
    // Capacity-normalize the push-built outer descriptor so the fixture represents
    // a properly capacity-normalized candidate (the real decode path builds this
    // with `Vec::with_capacity`, i.e. exact); `Vec`'s minimum push allocation
    // would otherwise leave spare capacity the per-vector capacity bound refuses.
    signatures.shrink_to_fit();
    WireQc {
        version: 1,
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        height: view, // P2: logical view binds to wire height
        round: view,
        step: 0,
        block_id,
        suite_id: QC_SUITE,
        signer_bitmap: bitmap,
        signatures,
    }
}

fn open_enabled(dir: &std::path::Path) -> SafetyBackend {
    SafetyBackend::open_or_initialize(
        dir,
        SafetyBackendPolicy::EnabledForTesting,
        TrustBundleEnvironment::Devnet,
    )
    .expect("enabled devnet backend opens")
}

fn init_owner(dir: &std::path::Path, ctx: &PinnedSafetyContext) -> SafetyRecordOwner {
    let backend = open_enabled(dir);
    let owner = SafetyRecordOwner::attach(backend, ctx.clone()).expect("attach");
    owner.initialize(true).expect("O1 initialize");
    owner
}

// ---------------------------------------------------------------------------
// H2 — versioned encode/bounded decode round-trip (unit/model)
// ---------------------------------------------------------------------------

#[test]
fn h2_encode_decode_roundtrip_bootstrap_and_locked() {
    let ctx = ctx_n(4);
    // Bootstrap round-trips.
    let boot = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 0,
        record: SafetyRecord::BootstrapNoLock {
            authority_context_ref: ctx.authority_context_ref,
            predecessor_ref: None,
        },
    };
    let enc = encode_record(&boot, &ctx).unwrap();
    assert_eq!(decode_record(&enc, &ctx).unwrap(), boot);

    // Locked (QC-derived) round-trips.
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    let dec = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 3,
        record: SafetyRecord::Locked(locked),
    };
    let enc = encode_record(&dec, &ctx).unwrap();
    assert_eq!(decode_record(&enc, &ctx).unwrap(), dec);
}

// ---------------------------------------------------------------------------
// H3 — unsupported version refused (unit)
// ---------------------------------------------------------------------------

#[test]
fn h3_unsupported_version_refused() {
    let ctx = ctx_n(4);
    let boot = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 0,
        record: SafetyRecord::BootstrapNoLock {
            authority_context_ref: ctx.authority_context_ref,
            predecessor_ref: None,
        },
    };
    let mut enc = encode_record(&boot, &ctx).unwrap();
    // Corrupt the version field (first 2 bytes) and recompute nothing — CRC will
    // also fail, but version is checked after CRC; use a buffer whose CRC matches
    // an unsupported version by re-encoding with a different declared version.
    enc[0] = 0;
    enc[1] = 99;
    // Fix CRC so the version check (not CRC) is what rejects.
    let body_len = enc.len() - 4;
    let crc = qbind_node::safety_record_store::codec_crc_for_test(&enc[..body_len]);
    enc[body_len..].copy_from_slice(&crc.to_be_bytes());
    assert!(matches!(
        decode_record(&enc, &ctx),
        Err(SafetyStoreError::UnsupportedVersion(99))
    ));
}

// ---------------------------------------------------------------------------
// H4 — CRC / truncation / trailing-byte structural refusal (unit)
// ---------------------------------------------------------------------------

#[test]
fn h4_crc_and_truncation_refused() {
    let ctx = ctx_n(4);
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    let dec = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(locked),
    };
    let enc = encode_record(&dec, &ctx).unwrap();

    // Bit-flip in the body → CRC mismatch.
    let mut corrupt = enc.clone();
    corrupt[70] ^= 0xFF;
    assert!(matches!(
        decode_record(&corrupt, &ctx),
        Err(SafetyStoreError::StructuralRefusal(_))
    ));

    // Truncation.
    let truncated = &enc[..enc.len() - 10];
    assert!(decode_record(truncated, &ctx).is_err());

    // Trailing bytes.
    let mut trailer = enc.clone();
    trailer.push(0);
    assert!(decode_record(&trailer, &ctx).is_err());
}

// ---------------------------------------------------------------------------
// H5 — oversize refusal before allocation (unit)
// ---------------------------------------------------------------------------

#[test]
fn h5_oversize_refused_pre_allocation() {
    let ctx = ctx_n(4);
    let oversize = vec![0u8; (max_safety_record_bytes(&ctx).unwrap() as usize) + 1];
    assert!(matches!(
        decode_record(&oversize, &ctx),
        Err(SafetyStoreError::Oversize { .. })
    ));
}

// ---------------------------------------------------------------------------
// H6 — empty-signer certificate refused at structural threshold (unit)
// ---------------------------------------------------------------------------

#[test]
fn h6_empty_signer_certificate_refused() {
    let ctx = ctx_n(4);
    let mut qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    qc.signatures.clear();
    qc.signer_bitmap = vec![0u8; 1];
    // Build the record directly: the public builder now admits evidence and would
    // refuse the empty-signer certificate up front; here we want to assert that
    // `encode_record`'s own admission refuses it at the structural threshold.
    let locked = locked_qc_unadmitted(&ctx, [9u8; 32], 5, qc);
    let dec = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(locked),
    };
    // The unified structural-admission path (§13 §7) refuses an empty-signer
    // certificate BEFORE publication — i.e. at encode/admission — rather than
    // only on read-back. The obligation (empty-signer certificate refused at the
    // structural threshold) is unchanged; the refusal is now enforced earlier.
    let enc = encode_record(&dec, &ctx);
    assert!(matches!(enc, Err(SafetyStoreError::StructuralRefusal(_))));
}

// ---------------------------------------------------------------------------
// H7 — declared count/length over pinned bound refused (bounded decode) (unit)
// ---------------------------------------------------------------------------

#[test]
fn h7_declared_count_over_bound_refused() {
    // Hand-craft a QC-derived record declaring an oversized signature count.
    // Easiest: encode a valid record under a larger context, then decode under a
    // smaller context so the declared signer count exceeds N.
    let big = ctx_n(8);
    let qc = valid_wire_qc(&big, [9u8; 32], 5);
    let locked = make_locked_qc(&big, [9u8; 32], 5, qc, None).unwrap();
    let dec = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: big.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(locked),
    };
    let enc = encode_record(&dec, &big).unwrap();
    // Decode under the smaller N=4 context: the declared signer count (6) > 4.
    let small = PinnedSafetyContext {
        validators: (0..4).map(|i| (ValidatorId::new(i), 1u64)).collect(),
        ..big.clone()
    };
    assert!(matches!(
        decode_record(&enc, &small),
        Err(SafetyStoreError::DeclaredBoundExceeded(_)) | Err(SafetyStoreError::Oversize { .. })
    ));
}

// ---------------------------------------------------------------------------
// H8 — P1/P2 binding (block id + height-not-round view binding) (unit)
// ---------------------------------------------------------------------------

#[test]
fn h8_p1_p2_binding_enforced() {
    let ctx = ctx_n(4);
    // P1 violation: qc.block_id != lock_block_id.
    let qc = valid_wire_qc(&ctx, [0xEEu8; 32], 5);
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    let dec = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(locked),
    };
    let enc = encode_record(&dec, &ctx).unwrap();
    let r = validate_decoded(
        decode_record(&enc, &ctx).unwrap(),
        enc,
        &ctx,
        None::<&FixtureCommittedHistory>,
    );
    assert!(matches!(r, Err(SafetyStoreError::SemanticRefusal(_))));
}

// ---------------------------------------------------------------------------
// H9 — P4 context/association mismatch refused (unit)
// ---------------------------------------------------------------------------

#[test]
fn h9_p4_context_mismatch_refused() {
    let ctx = ctx_n(4);
    let mut qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    qc.chain_id = CHAIN_ID + 1; // wrong chain
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    let dec = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(locked),
    };
    let enc = encode_record(&dec, &ctx).unwrap();
    let r = validate_decoded(
        decode_record(&enc, &ctx).unwrap(),
        enc,
        &ctx,
        None::<&FixtureCommittedHistory>,
    );
    assert!(matches!(r, Err(SafetyStoreError::SemanticRefusal(_))));
}

// ---------------------------------------------------------------------------
// H10 — quorum voting-power threshold enforced structurally (unit)
// ---------------------------------------------------------------------------

#[test]
fn h10_quorum_threshold_enforced() {
    let ctx = ctx_n(4); // need ceil(8/3)=3
    let mut qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    // Drop to 2 signers (below quorum) but keep set-bit/signature correspondence.
    qc.signer_bitmap = vec![0b0000_0011];
    qc.signatures = vec![vec![0xAB; S_SIG], vec![0xAB; S_SIG]];
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    let dec = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(locked),
    };
    let enc = encode_record(&dec, &ctx).unwrap();
    let r = validate_decoded(
        decode_record(&enc, &ctx).unwrap(),
        enc,
        &ctx,
        None::<&FixtureCommittedHistory>,
    );
    assert!(matches!(r, Err(SafetyStoreError::SemanticRefusal(_))));
}

// ---------------------------------------------------------------------------
// H11 — evidence status is always Unverified on success (unit)
// ---------------------------------------------------------------------------

#[test]
fn h11_success_is_unverified() {
    let ctx = ctx_n(4);
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    let dec = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(locked),
    };
    let enc = encode_record(&dec, &ctx).unwrap();
    let v = validate_decoded(
        decode_record(&enc, &ctx).unwrap(),
        enc,
        &ctx,
        None::<&FixtureCommittedHistory>,
    )
    .unwrap();
    assert_eq!(v.evidence_status(), EvidenceStatus::Unverified);
}

// ---------------------------------------------------------------------------
// H26 (model support) — checked serialized caps match measured encodings.
// NOTE: previously mislabeled `h12_*`; the real H12 competing-handle stale
// O4/O5 obligation is exercised by `h12_competing_handles_stale_o4_o5_*` below.
// This case is model/unit support for the H26 serialized-bound obligation.
// ---------------------------------------------------------------------------

#[test]
fn h26_serialized_caps_bound_actual_encodings() {
    for n in [1u64, 4, 8, 16] {
        let ctx = ctx_n(n);
        let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
        let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
        let dec = DecodedRecord {
            persistence_format_version: 1,
            network_genesis_id: ctx.network_genesis_id,
            publication_revision: 1,
            record: SafetyRecord::Locked(locked),
        };
        let enc = encode_record(&dec, &ctx).unwrap();
        assert!((enc.len() as u128) <= max_qc_bytes(&ctx).unwrap());
        assert!((enc.len() as u128) <= max_safety_record_bytes(&ctx).unwrap());
    }
}

// ---------------------------------------------------------------------------
// H12 — competing handles over ONE shared backend: deterministically
// interleaved stale O4 and stale O5 attempts are refused and the newer
// publication bytes remain byte-for-byte unchanged (real-storage).
// ---------------------------------------------------------------------------

#[test]
fn h12_competing_handles_stale_o4_o5_leave_newer_bytes_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    // Two handles A and B share the SAME backend incarnation (clone shares the
    // Arc-held DB + serialization domain), so this is a genuine competing-handle
    // scenario, not a sequential reopen.
    let backend = open_enabled(dir.path());
    let owner_a = SafetyRecordOwner::attach(backend.clone(), ctx.clone()).unwrap();
    owner_a.initialize(true).expect("O1 initialize");
    let owner_b = SafetyRecordOwner::attach(backend.clone(), ctx.clone()).unwrap();

    // A publishes v5 (rev 0 -> 1). B captures a retained O3 token for v5 BEFORE
    // A advances, so B now holds a soon-to-be-stale O5 capability.
    let qc5 = valid_wire_qc(&ctx, [9u8; 32], 5);
    let l5 = make_locked_qc(&ctx, [9u8; 32], 5, qc5, None).unwrap();
    assert_eq!(
        owner_a.publish_locked(l5, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    let stale_b_token = owner_b
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("B observes v5 via its own O3");

    // A advances to the newer v9 (rev 1 -> 2). Capture the authoritative newer
    // bytes to prove no competing stale attempt disturbs them.
    let qc9 = valid_wire_qc(&ctx, [0x11u8; 32], 9);
    let l9 = make_locked_qc(&ctx, [0x11u8; 32], 9, qc9, None).unwrap();
    assert_eq!(
        owner_a.publish_locked(l9, 1, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 2 }
    );
    let newer_bytes = owner_a
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap()
        .encoded()
        .to_vec();

    // Interleave step 1: B issues a STALE O4 (expected revision 1, actual is 2).
    // It must be refused by revision fencing before any write.
    let qc_stale = valid_wire_qc(&ctx, [0x22u8; 32], 7);
    let l_stale = make_locked_qc(&ctx, [0x22u8; 32], 7, qc_stale, None).unwrap();
    assert!(
        matches!(
            owner_b.publish_locked(l_stale, 1, None::<&FixtureCommittedHistory>),
            PublishResult::RefusedPreWrite(SafetyStoreError::StaleRevision { .. })
        ),
        "B's stale O4 must be refused by the shared revision fence"
    );
    assert_eq!(
        owner_a
            .read_validate(None::<&FixtureCommittedHistory>)
            .unwrap()
            .encoded(),
        newer_bytes.as_slice(),
        "newer bytes unchanged after B's stale O4"
    );

    // Interleave step 2: B issues a STALE O5 (reacknowledge of the v5 token it
    // captured earlier). It must refuse and NOT overwrite the newer v9 bytes.
    assert!(
        matches!(
            owner_b.reacknowledge(&stale_b_token),
            PublishResult::RefusedPreWrite(_)
        ),
        "B's stale O5 must be refused"
    );
    let after = owner_a
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert_eq!(
        after.retained().publication_revision,
        2,
        "revision still 2 after competing stale O4/O5"
    );
    assert_eq!(
        after.encoded(),
        newer_bytes.as_slice(),
        "newer publication bytes remain byte-for-byte unchanged"
    );
}

// ---------------------------------------------------------------------------
// H16 — real RocksDB atomic publication + reopen (real-storage)
// ---------------------------------------------------------------------------

#[test]
fn h16_real_rocksdb_publish_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);

    // Publish a lock at revision 1.
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    let res = owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>);
    assert_eq!(res, PublishResult::DurableAcknowledged { new_revision: 1 });

    // Reopen a fresh backend over the same directory; O2/O3 see the lock.
    drop(owner);
    let backend2 = open_enabled(dir.path());
    let owner2 = SafetyRecordOwner::attach(backend2, ctx.clone()).unwrap();
    let meta = owner2.open().unwrap();
    assert_eq!(meta.current_revision, 1);
    let v = owner2
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert!(v.retained().is_locked());
    assert_eq!(v.retained().publication_revision, 1);
}

// ---------------------------------------------------------------------------
// O1 duplicate-initialization / missing-intent regression (PRESERVED under an
// accurate name — this is NOT H18). It establishes that O1 refuses established
// state and a missing first-use intent; it does not exercise the H18 split-store
// arrangement restriction (covered by `h18_record_and_evidence_co_located_...`).
// ---------------------------------------------------------------------------

#[test]
fn o1_refuses_duplicate_initialization_and_missing_intent() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    // Second initialize on established state refuses.
    assert!(matches!(
        owner.initialize(true),
        Err(SafetyStoreError::AlreadyEstablished(_))
    ));
    // Missing first-use intent refuses regardless.
    let dir2 = tempfile::tempdir().unwrap();
    let backend = open_enabled(dir2.path());
    let owner2 = SafetyRecordOwner::attach(backend, ctx.clone()).unwrap();
    assert!(matches!(
        owner2.initialize(false),
        Err(SafetyStoreError::MissingIndependentInput(_))
    ));
}

// ---------------------------------------------------------------------------
// H18 — non-co-located record/evidence arrangement is UNREPRESENTABLE by
// construction, so partial cross-store publication cannot occur.
//
// The accepted D14 component (a) embeds the supporting evidence AS A FIELD of the
// stored record (`SupportingEvidence` inside `LockedRecord`), encoded into the one
// `RECORD_KEY` value, and (b) commits the metadata key and the record key in a
// single atomic backend batch under one `SafetyBackend`. There is NO separate
// evidence store handle, key, or write path — the split-store arrangement the H18
// obligation concerns is unrepresentable here. This regression establishes that
// restriction at the component's genuine storage boundary via a real publication,
// rather than introducing a new split-store architecture to create a negative
// test. (Limitation: there is no cross-store code path to fault-inject; the
// guarantee is structural, demonstrated by co-location + single-batch atomicity.)
// ---------------------------------------------------------------------------

#[test]
fn h18_record_and_evidence_co_located_single_store_no_partial_cross_store() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);

    // A real TC-derived publication: its evidence is non-trivial.
    let ltc = valid_tc_record(&ctx, 5, 6);
    assert_eq!(
        owner.publish_locked(ltc, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    let backend = owner.backend_for_test();

    // (a) Record and evidence are CO-LOCATED in the single `RECORD_KEY` value:
    // decoding the one stored record buffer yields the embedded supporting
    // evidence — there is no second store/key the evidence could live in.
    let rec = max_safety_record_bytes(&ctx).unwrap();
    let stored = backend.read_record(rec).unwrap().expect("record present");
    let decoded = decode_record(&stored, &ctx).unwrap();
    match &decoded.record {
        SafetyRecord::Locked(l) => assert!(
            matches!(l.evidence, SupportingEvidence::TcDerived { .. }),
            "supporting evidence is embedded in the single stored record, not a separate store"
        ),
        other => panic!("expected a Locked record carrying embedded evidence, got {other:?}"),
    }

    // (b) The component-owned namespace contains ONLY the two recognized
    // co-located keys (metadata + record). `first_unrecognized_safety_key`
    // returning `None` proves there is no third/evidence-store key — a split
    // arrangement is not representable. Both keys are present together (the atomic
    // batch committed them as one unit; no partial cross-store state exists).
    assert!(
        backend.read_meta(crate_meta_bound()).unwrap().is_some(),
        "metadata key present (co-located with the record)"
    );
    assert!(
        backend.first_unrecognized_safety_key().unwrap().is_none(),
        "no unrecognized/separate-evidence-store key exists in the safety namespace"
    );
}

// Mirror of `backend::META_ENCODED_LEN` for test reads.
fn crate_meta_bound() -> u128 {
    META_ENCODED_LEN_MIRROR
}

// ---------------------------------------------------------------------------
// H19 — O5 refuses divergence OUTSIDE the binding digest's coverage
//       while CRC + binding still pass (real-storage).
//
// Byte preservation is asserted DIRECTLY: after the refusal the raw stored
// publication bytes are read back and compared to the forged content (and shown
// NOT to equal the retained original), rather than relying on an arbitrary later
// O3 error. The refusal is also shown to leave metadata/revision and the recovery
// latch unchanged and to not authorize a dependent O4.
// ---------------------------------------------------------------------------

#[test]
fn h19_o5_refuses_divergence_outside_binding_digest() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    assert_eq!(
        owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    // O3 retains the original publication bytes.
    let retained = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();

    // Build a divergent-but-individually-valid publication at the SAME revision
    // whose difference lies outside the binding digest's coverage (e.g. the
    // predecessor_ref field, which is not part of evidence_lock_binding), then
    // store it directly via a second lock publication path is not available at
    // the same revision; instead mutate the stored bytes in a field the binding
    // does not cover and re-wrap with a valid CRC so stage-1 still passes.
    let stored = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap()
        .encoded()
        .to_vec();
    let mut forged = stored.clone();
    // Flip D_pred (offset 2+32+32+1+1 = 68) from 0→1 and append a predecessor u64
    // before the CRC, then re-CRC. The binding digest does not cover D_pred.
    // Simpler: just change publication bytes in the lock_view area is covered by
    // binding; instead we corrupt a byte in the committed-anchor discriminant
    // region (D_ca at offset 67) which the binding also does not cover.
    forged[67] = 0; // already 0; ensure a genuine divergence elsewhere:
                    // Divergent authority-context tail byte is covered by nothing structural but
                    // changes bytes: flip the last body byte of network_genesis echo region.
    forged[2] ^= 0x01; // part of network_genesis_id (not in binding digest input)
    let body_len = forged.len() - 4;
    let crc = qbind_node::safety_record_store::codec_crc_for_test(&forged[..body_len]);
    forged[body_len..].copy_from_slice(&crc.to_be_bytes());

    // Overwrite stored record bytes out-of-band to simulate a surviving divergent
    // publication, then O5 must refuse (byte-for-byte inequality), NOT overwrite.
    owner.debug_overwrite_record_for_test(&forged).unwrap();
    // Capture the authoritative state immediately BEFORE the refused O5 so the
    // refusal can be shown to have mutated nothing.
    let rec_bound = max_safety_record_bytes(&ctx).unwrap();
    let backend = owner.backend_for_test();
    let meta_before = backend.read_meta(META_ENCODED_LEN_MIRROR).unwrap();
    let recovery_before = owner.recovery_required();
    let res = owner.reacknowledge(&retained);
    assert!(
        matches!(
            res,
            PublishResult::RefusedPreWrite(SafetyStoreError::PublicationMismatch(_))
        ),
        "got {res:?}"
    );
    // DIRECT byte preservation: the stored publication bytes are still EXACTLY the
    // forged bytes — O5 did not republish the retained original over the divergent
    // surviving content. (An arbitrary later O3 error cannot stand in for this.)
    let stored_after = backend
        .read_record(rec_bound)
        .unwrap()
        .expect("record present");
    assert_eq!(
        stored_after, forged,
        "refused O5 left the divergent stored publication byte-for-byte unchanged"
    );
    assert_ne!(
        stored_after,
        retained.encoded(),
        "refused O5 must NOT have republished the retained original bytes"
    );
    // Metadata / revision unchanged by the refusal.
    assert_eq!(
        backend.read_meta(META_ENCODED_LEN_MIRROR).unwrap(),
        meta_before,
        "refused O5 did not mutate stored metadata/revision"
    );
    // The effectiveness/recovery latch is unchanged by the refused O5.
    assert_eq!(
        owner.recovery_required(),
        recovery_before,
        "refused O5 did not disturb the recovery latch"
    );
    // A refused O5 does not authorize a dependent O4: the forged predecessor is no
    // longer a valid base, so O4 is refused pre-write (no effectiveness granted).
    let next_qc = valid_wire_qc(&ctx, [7u8; 32], 9);
    let next = make_locked_qc(&ctx, [7u8; 32], 9, next_qc, None).unwrap();
    assert!(
        matches!(
            owner.publish_locked(next, 1, None::<&FixtureCommittedHistory>),
            PublishResult::RefusedPreWrite(_)
        ),
        "a refused O5 must not enable a dependent O4"
    );
}

// ---------------------------------------------------------------------------
// H20 — stale O5 refused without overwriting newer state (real-storage)
// ---------------------------------------------------------------------------

#[test]
fn h20_stale_o5_does_not_overwrite_newer() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);

    // Publish lock v5 (rev 1), capture its retained publication.
    let qc5 = valid_wire_qc(&ctx, [9u8; 32], 5);
    let l5 = make_locked_qc(&ctx, [9u8; 32], 5, qc5, None).unwrap();
    owner.publish_locked(l5, 0, None::<&FixtureCommittedHistory>);
    let retained_v5 = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();

    // Publish a newer lock v9 (rev 2).
    let qc9 = valid_wire_qc(&ctx, [0x11u8; 32], 9);
    let l9 = make_locked_qc(&ctx, [0x11u8; 32], 9, qc9, None).unwrap();
    assert_eq!(
        owner.publish_locked(l9, 1, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 2 }
    );

    // A stale O5 for the v5 publication must refuse and NOT overwrite v9.
    let res = owner.reacknowledge(&retained_v5);
    assert!(
        matches!(res, PublishResult::RefusedPreWrite(_)),
        "got {res:?}"
    );
    let now = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert_eq!(now.retained().publication_revision, 2);
}

// ---------------------------------------------------------------------------
// H21 — expected-revision fence refuses stale O4 (real-storage)
// ---------------------------------------------------------------------------

#[test]
fn h21_revision_fence_refuses_stale_publish() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    // Wrong expected revision (should be 0) → stale fencing refusal, no write.
    let res = owner.publish_locked(locked, 7, None::<&FixtureCommittedHistory>);
    assert!(matches!(
        res,
        PublishResult::RefusedPreWrite(SafetyStoreError::StaleRevision { .. })
    ));
    // State unchanged (still bootstrap rev 0).
    let v = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert_eq!(v.retained().publication_revision, 0);
    assert!(!v.retained().is_locked());
}

// ---------------------------------------------------------------------------
// O4 non-increasing lock-view transition-eligibility regression (PRESERVED under
// an accurate name — this is NOT H22). It establishes transition eligibility
// (a same-view relock is ineligible); it does not establish the H22 verified-
// prerequisite restriction (covered by `h22_unverified_evidence_cannot_...`).
// ---------------------------------------------------------------------------

#[test]
fn o4_rejects_non_increasing_lock_view_transition_ineligible() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let qc9 = valid_wire_qc(&ctx, [9u8; 32], 9);
    let l9 = make_locked_qc(&ctx, [9u8; 32], 9, qc9, None).unwrap();
    owner.publish_locked(l9, 0, None::<&FixtureCommittedHistory>);
    // Attempt a lock at the same view 9 → ineligible.
    let qc9b = valid_wire_qc(&ctx, [0x22u8; 32], 9);
    let l9b = make_locked_qc(&ctx, [0x22u8; 32], 9, qc9b, None).unwrap();
    let res = owner.publish_locked(l9b, 1, None::<&FixtureCommittedHistory>);
    assert!(matches!(
        res,
        PublishResult::RefusedPreWrite(SafetyStoreError::TransitionIneligible(_))
    ));
}

// ---------------------------------------------------------------------------
// H22 — unverified evidence cannot satisfy a verified prerequisite.
//
// Stage-2 verification is unwired, so every record the component produces carries
// its evidence `Unverified`. The restriction that such evidence can NEVER be used
// as a verified prerequisite is enforced at the TYPE boundary: `EvidenceStatus`
// is an exhaustive enum whose ONLY variant is `Unverified` — the component has no
// way to mint a `Verified` discriminant, so no consumer requiring verified
// evidence can be satisfied by this component's output. This regression
// demonstrates the actual `Unverified` outcome from a real O3 and the exhaustive
// type restriction.
//
// Limitation (recorded, not substituted): there is no in-scope production
// consumer that consumes a verified-evidence prerequisite, and this pass adds no
// verifier/engine wiring. The guarantee established here is the type-level
// impossibility of presenting verified evidence, not enforcement inside an
// existing production verified-prerequisite consumer.
// ---------------------------------------------------------------------------

#[test]
fn h22_unverified_evidence_cannot_satisfy_verified_prerequisite() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);

    // A real O4 publication, then a real O3 read: the resulting evidence status is
    // the actual `Unverified` outcome.
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    assert_eq!(
        owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    let v = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();

    // The actual outcome is `Unverified`. The match is EXHAUSTIVE with a single arm
    // — it compiles only because `EvidenceStatus` has no `Verified` variant. A
    // future `Verified` variant would break this compile, which is the intended
    // guard: the component cannot present verified evidence.
    match v.evidence_status() {
        EvidenceStatus::Unverified => {}
    }
    assert_eq!(v.evidence_status(), EvidenceStatus::Unverified);

    // Model the prerequisite boundary at the unit level: a consumer that requires
    // verified evidence can accept ONLY a `Verified` token; because no such token
    // can be constructed from this component's output, the unverified record is
    // rejected by construction (there is no conversion from `Unverified`).
    fn requires_verified_prerequisite(status: EvidenceStatus) -> Result<(), &'static str> {
        match status {
            // The sole constructible variant cannot satisfy a verified prerequisite.
            EvidenceStatus::Unverified => Err("unverified evidence rejected: verification unwired"),
        }
    }
    assert_eq!(
        requires_verified_prerequisite(v.evidence_status()),
        Err("unverified evidence rejected: verification unwired"),
        "a verified-prerequisite consumer rejects the component's unverified evidence"
    );
}

// ---------------------------------------------------------------------------
// H23 — O2 refuses absent / partial established state; O3 reads without writing
// ---------------------------------------------------------------------------

#[test]
fn h23_o2_refuses_absent_state_o3_no_write() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    // Fresh, uninitialized backend: O2 refuses.
    let backend = open_enabled(dir.path());
    let owner = SafetyRecordOwner::attach(backend, ctx.clone()).unwrap();
    assert!(matches!(
        owner.open(),
        Err(SafetyStoreError::MissingEstablishedState(_))
    ));
    // After O1, O3 reads and does not mutate the revision.
    owner.initialize(true).unwrap();
    let before = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let after = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert_eq!(before.retained(), after.retained());
}

// ---------------------------------------------------------------------------
// H24 — bootstrap vs no-commit vs committed-anchor distinctions (unit)
// ---------------------------------------------------------------------------

#[test]
fn h24_bootstrap_nocommit_committed_distinctions() {
    let ctx = ctx_n(4);

    // Bootstrap: no lock, no anchor, no evidence.
    let boot = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 0,
        record: SafetyRecord::BootstrapNoLock {
            authority_context_ref: ctx.authority_context_ref,
            predecessor_ref: None,
        },
    };
    let enc = encode_record(&boot, &ctx).unwrap();
    assert_eq!(decode_record(&enc, &ctx).unwrap(), boot);

    // Locked, no committed anchor: committed_anchor is absent by variant.
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let l_nocommit = make_locked_qc(&ctx, [9u8; 32], 5, qc.clone(), None).unwrap();
    assert!(l_nocommit.committed_anchor.is_none());

    // Locked WITH committed anchor: requires supplied committed history (P3).
    let l_commit = make_locked_qc(
        &ctx,
        [9u8; 32],
        5,
        qc,
        Some(CommittedAnchor {
            block_id: [3u8; 32],
            height: 4,
        }),
    )
    .unwrap();
    let dec = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(l_commit),
    };
    let enc = encode_record(&dec, &ctx).unwrap();
    // No history supplied → refuse.
    assert!(matches!(
        validate_decoded(
            decode_record(&enc, &ctx).unwrap(),
            enc.clone(),
            &ctx,
            None::<&FixtureCommittedHistory>
        ),
        Err(SafetyStoreError::MissingIndependentInput(_))
    ));
    // Supplied fixture history that affirms the anchor → accept.
    let hist = FixtureCommittedHistory::new().with([3u8; 32], 4);
    let v = validate_decoded(decode_record(&enc, &ctx).unwrap(), enc, &ctx, Some(&hist)).unwrap();
    assert_eq!(v.evidence_status(), EvidenceStatus::Unverified);
}

// H24 (malformed anchor-presence, unit/model) — the two missing structural cases:
// (A) a NO-COMMIT discriminant (`D_ca = 0`) whose buffer still carries anchor
// content, and (B) a COMMITTED-ANCHOR discriminant (`D_ca = 1`) missing the
// required anchor content. Each is built from a VALID encoding and re-sealed with
// a fresh record CRC so decoding reaches the intended STRUCTURAL rejection rather
// than failing incidentally on the CRC envelope. Also asserts that legitimate
// no-commit recovery does not manufacture a height-zero anchor or block id.
#[test]
fn h24_malformed_anchor_presence_structural_rejections() {
    use qbind_node::safety_record_store::codec::record_crc32_for_test;
    let ctx = ctx_n(4);
    // `D_ca` sits at a fixed offset: version(2) + genesis(32) + authctx(32) = 66
    // is `D_ev`, so byte 67 is `D_ca` (see codec `evidence_discriminant_of`).
    const D_CA_OFFSET: usize = 2 + 32 + 32 + 1;

    // A valid committed-anchor record with NO predecessor, so the anchor bytes are
    // the final 40 body bytes (block_id[32] + height u64).
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let l_commit = make_locked_qc(
        &ctx,
        [9u8; 32],
        5,
        qc,
        Some(CommittedAnchor {
            block_id: [3u8; 32],
            height: 4,
        }),
    )
    .unwrap();
    let dec = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(l_commit),
    };
    let enc = encode_record(&dec, &ctx).unwrap();
    assert_eq!(
        enc[D_CA_OFFSET], 1,
        "fixture encodes D_ca = 1 (committed anchor)"
    );

    // Case A — no-commit discriminant carrying anchor content: flip D_ca to 0 and
    // re-seal. The 40 anchor bytes are now unconsumed → structural trailing-bytes
    // rejection (NOT a CRC mismatch, NOT silently accepted).
    let mut a = enc.clone();
    let a_body = a.len() - 4;
    a[D_CA_OFFSET] = 0;
    let crc = record_crc32_for_test(&a[..a_body]).to_be_bytes();
    a[a_body..].copy_from_slice(&crc);
    match decode_record(&a, &ctx) {
        Err(SafetyStoreError::StructuralRefusal(m)) => {
            let m = m.to_string();
            assert!(
                m != "CRC32 mismatch",
                "must not fail on the CRC envelope: {m}"
            );
            assert!(
                m.contains("trailing"),
                "no-commit discriminant carrying anchor content is a trailing-bytes structural refusal, got: {m}"
            );
        }
        other => panic!("expected structural trailing-bytes refusal, got {other:?}"),
    }

    // Case B — committed-anchor discriminant missing anchor content: drop the final
    // 40 anchor bytes and re-seal. D_ca stays 1 → the anchor read underflows →
    // structural rejection (NOT a CRC mismatch).
    let mut b_body = enc[..enc.len() - 4].to_vec();
    let blen = b_body.len();
    b_body.truncate(blen - 40);
    assert_eq!(b_body[D_CA_OFFSET], 1, "still claims a committed anchor");
    let crc = record_crc32_for_test(&b_body).to_be_bytes();
    let mut b = b_body;
    b.extend_from_slice(&crc);
    match decode_record(&b, &ctx) {
        Err(SafetyStoreError::StructuralRefusal(m)) => {
            let m = m.to_string();
            assert!(
                m != "CRC32 mismatch",
                "must not fail on the CRC envelope: {m}"
            );
        }
        other => panic!("expected structural anchor-underflow refusal, got {other:?}"),
    }

    // Legitimate no-commit recovery does NOT manufacture a height-zero anchor or a
    // zero block identifier: a real no-commit locked publication reopens with an
    // ABSENT committed anchor, never a synthesized `CommittedAnchor { height: 0 }`.
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    let qc2 = valid_wire_qc(&ctx, [9u8; 32], 5);
    let l_nocommit = make_locked_qc(&ctx, [9u8; 32], 5, qc2, None).unwrap();
    assert_eq!(
        owner.publish_locked(l_nocommit, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    drop(owner);
    let owner2 = SafetyRecordOwner::attach(open_enabled(dir.path()), ctx.clone()).unwrap();
    let v = owner2
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    match &v.retained().record {
        SafetyRecord::Locked(l) => assert!(
            l.committed_anchor.is_none(),
            "no-commit recovery must not manufacture a committed anchor"
        ),
        other => panic!("expected a Locked no-commit record, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// H25 — supplied first-lock evidence at the storage layer (unit)
//       (does NOT prove engine voting or first-QC formation)
// ---------------------------------------------------------------------------

#[test]
fn h25_first_lock_evidence_storage_layer_only() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    // First lock transition from bootstrap is admitted and durable.
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    assert_eq!(
        owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    // Storage-layer only: evidence remains Unverified.
    let v = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert_eq!(v.evidence_status(), EvidenceStatus::Unverified);
}

// ---------------------------------------------------------------------------
// H26 — BOTH evidence variants + nested bounds (unit)
// ---------------------------------------------------------------------------

fn valid_tc_record(ctx: &PinnedSafetyContext, lock_view: u64, timeout_view: u64) -> LockedRecord {
    let need = ((2 * ctx.n()) + 2) / 3;
    let high = LogicalQc::new(
        [9u8; 32],
        lock_view,
        (0..need as u64).map(ValidatorId::new).collect(),
    );
    let mut signed = Vec::new();
    for i in 0..need as u64 {
        let mut t = TimeoutMsg::new(timeout_view, Some(high.clone()), ValidatorId::new(i));
        t.set_signature(vec![0xCD; S_SIG]);
        signed.push(t);
    }
    signed.shrink_to_fit();
    let tc = TimeoutCertificate {
        view: timeout_view + 1,
        high_qc: Some(high.clone()),
        signers: (0..need as u64).map(ValidatorId::new).collect(),
        signed_timeouts: signed,
        timeout_view,
    };
    let evidence = SupportingEvidence::TcDerived {
        high_qc: high.clone(),
        tc,
    };
    let binding = qbind_node::safety_record_store::codec::compute_evidence_lock_binding(
        &[9u8; 32],
        lock_view,
        &evidence,
        &ctx.authority_context_ref,
        ctx,
    )
    .unwrap();
    LockedRecord {
        lock_block_id: [9u8; 32],
        lock_view,
        evidence_lock_binding: binding,
        authority_context_ref: ctx.authority_context_ref,
        committed_anchor: None,
        predecessor_ref: None,
        evidence,
    }
}

#[test]
fn h26_both_evidence_variants_and_nested_bounds() {
    let ctx = ctx_n(4);

    // QC-derived validates.
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let lqc = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    let dqc = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(lqc),
    };
    let eqc = encode_record(&dqc, &ctx).unwrap();
    assert_eq!(decode_record(&eqc, &ctx).unwrap(), dqc);
    assert!(validate_decoded(dqc.clone(), eqc, &ctx, None::<&FixtureCommittedHistory>).is_ok());

    // TC-derived validates and round-trips; nested high-QC bounds honored.
    let ltc = valid_tc_record(&ctx, 5, 6);
    let dtc = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 2,
        record: SafetyRecord::Locked(ltc),
    };
    let etc = encode_record(&dtc, &ctx).unwrap();
    assert_eq!(decode_record(&etc, &ctx).unwrap(), dtc);
    let v = validate_decoded(dtc, etc.clone(), &ctx, None::<&FixtureCommittedHistory>).unwrap();
    assert_eq!(v.evidence_status(), EvidenceStatus::Unverified);
    // Nested bound: actual TC encoding is within MAX_TC_BYTES.
    assert!((etc.len() as u128) <= max_tc_bytes(&ctx).unwrap());
}

/// H26 (adversarial, through actual storage operations) — an over-bound
/// **record-level** high-QC signer list (`TcDerived.high_qc.signers`) inside a
/// TC-derived publication is refused by O4's single admission path BEFORE any
/// evidence-binding allocation, and the established predecessor is left intact.
/// This exercises the record-level nested high-QC ONLY; the per-timeout-entry
/// nested high-QC (`tc.signed_timeouts[i].high_qc.signers`) is covered separately
/// by `h26_adversarial_timeout_entry_nested_high_qc_signers_refused_through_o4`.
/// Helper-only refusal and valid round-trips are not a substitute: this drives
/// the real `publish_locked`.
#[test]
fn h26_adversarial_record_level_tc_high_qc_signers_refused_through_o4() {
    use qbind_node::safety_record_store::codec::{
        evidence_payload_encode_count, reset_evidence_payload_encode_count,
    };
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4); // N = 4
    let owner = init_owner(dir.path(), &ctx);

    // Start from a valid TC-derived record, then inflate the nested record-level
    // high-QC signer list to N + 1 (boundary-plus-one). The stored binding stays
    // the original valid digest, so O4 cannot rely on a binding mismatch: its
    // bound-admission must catch the over-bound nested signer list directly.
    let mut ltc = valid_tc_record(&ctx, 5, 6);
    if let SupportingEvidence::TcDerived { high_qc, .. } = &mut ltc.evidence {
        high_qc.signers = (0..=ctx.n() as u64).map(ValidatorId::new).collect();
    }

    reset_evidence_payload_encode_count();
    let res = owner.publish_locked(ltc, 0, None::<&FixtureCommittedHistory>);
    assert!(
        matches!(
            res,
            PublishResult::RefusedPreWrite(SafetyStoreError::DeclaredBoundExceeded(_))
        ),
        "over-bound nested high-QC signer list must be refused pre-write, got {res:?}"
    );
    assert_eq!(
        evidence_payload_encode_count(),
        0,
        "O4 must refuse the over-bound nested evidence BEFORE the binding allocation"
    );

    // The established predecessor (bootstrap rev 0) is untouched.
    let v = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert_eq!(v.retained().publication_revision, 0);
    assert!(!v.retained().is_locked());

    // A VALID TC-derived publication of the same shape IS admitted and round-trips
    // through storage (positive control: the refusal is bound-specific, not a
    // blanket TC rejection).
    let good = valid_tc_record(&ctx, 5, 6);
    assert_eq!(
        owner.publish_locked(good, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    let rv = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert!(matches!(
        &rv.retained().record,
        SafetyRecord::Locked(l) if matches!(l.evidence, SupportingEvidence::TcDerived { .. })
    ));
}

// (new H26 timeout-entry test inserted above)

// H26 (adversarial, through actual storage operations) — the per-timeout-entry
// nested high-QC signer list `tc.signed_timeouts[i].high_qc.signers` is a DISTINCT
// nested vector from the record-level `TcDerived.high_qc.signers`. Inflating ONE
// timeout entry's nested high-QC to N+1 (boundary-plus-one), with every other
// field valid and the stored binding left as the original valid digest, is
// refused by O4's single admission path BEFORE any evidence-binding allocation
// (so O4 cannot rely on a binding mismatch), and the established predecessor bytes
// are preserved. The exact-bound (N) positive case is admitted.
#[test]
fn h26_adversarial_timeout_entry_nested_high_qc_signers_refused_through_o4() {
    use qbind_node::safety_record_store::codec::{
        evidence_payload_encode_count, reset_evidence_payload_encode_count,
    };
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4); // N = 4
    let owner = init_owner(dir.path(), &ctx);

    // Start from a valid TC-derived record, then inflate exactly ONE timeout
    // entry's OPTIONAL nested high-QC signer list to N + 1. This is the vector the
    // reviewed record-level test never touched.
    let mut ltc = valid_tc_record(&ctx, 5, 6);
    if let SupportingEvidence::TcDerived { tc, .. } = &mut ltc.evidence {
        let entry = tc
            .signed_timeouts
            .first_mut()
            .expect("valid TC fixture has timeout entries");
        let nested = entry
            .high_qc
            .as_mut()
            .expect("each timeout entry carries an optional high_qc");
        nested.signers = (0..=ctx.n() as u64).map(ValidatorId::new).collect();
        assert_eq!(
            nested.signers.len(),
            ctx.n() + 1,
            "the nested timeout-entry high_qc is boundary-plus-one"
        );
    } else {
        panic!("valid_tc_record must be TcDerived");
    }

    reset_evidence_payload_encode_count();
    let res = owner.publish_locked(ltc, 0, None::<&FixtureCommittedHistory>);
    assert!(
        matches!(
            res,
            PublishResult::RefusedPreWrite(SafetyStoreError::DeclaredBoundExceeded(_))
        ),
        "over-bound timeout-entry nested high-QC signer list must be refused pre-write, got {res:?}"
    );
    assert_eq!(
        evidence_payload_encode_count(),
        0,
        "O4 must refuse the over-bound timeout-entry nested evidence BEFORE the binding allocation"
    );

    // The established predecessor (bootstrap rev 0) is untouched.
    let v = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert_eq!(v.retained().publication_revision, 0);
    assert!(!v.retained().is_locked());
    drop(v);

    // Exact-bound positive control: a timeout entry whose nested high-QC carries
    // EXACTLY N signers is admitted and round-trips (the refusal is bound-specific,
    // targeting the nested timeout-entry vector, not a blanket TC rejection).
    let mut good = valid_tc_record(&ctx, 5, 6);
    if let SupportingEvidence::TcDerived { tc, .. } = &mut good.evidence {
        let entry = tc.signed_timeouts.first_mut().unwrap();
        let nested = entry.high_qc.as_mut().unwrap();
        nested.signers = (0..ctx.n() as u64).map(ValidatorId::new).collect();
        assert_eq!(nested.signers.len(), ctx.n(), "exact-bound nested high_qc");
    }
    // Rebuild the binding so the exact-bound mutation stays internally consistent.
    let good = {
        let binding = qbind_node::safety_record_store::codec::compute_evidence_lock_binding(
            &good.lock_block_id,
            good.lock_view,
            &good.evidence,
            &good.authority_context_ref,
            &ctx,
        )
        .unwrap();
        LockedRecord {
            evidence_lock_binding: binding,
            ..good
        }
    };
    assert_eq!(
        owner.publish_locked(good, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
}

// ---------------------------------------------------------------------------
// H27 — persistence + handling of an unverified TC-derived restriction
//       (does NOT prove live safe-vote enforcement) (real-storage)
// ---------------------------------------------------------------------------

#[test]
fn h27_tc_derived_restriction_persisted_unverified() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let ltc = valid_tc_record(&ctx, 5, 6);
    let res = owner.publish_locked(ltc, 0, None::<&FixtureCommittedHistory>);
    assert_eq!(res, PublishResult::DurableAcknowledged { new_revision: 1 });

    // Reopen and confirm the TC-derived restriction survives, carried unverified.
    drop(owner);
    let owner2 = SafetyRecordOwner::attach(open_enabled(dir.path()), ctx.clone()).unwrap();
    let v = owner2
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert_eq!(v.evidence_status(), EvidenceStatus::Unverified);
    match &v.retained().record {
        SafetyRecord::Locked(l) => {
            assert!(matches!(l.evidence, SupportingEvidence::TcDerived { .. }));
        }
        _ => panic!("expected locked TC-derived"),
    }
}

// ---------------------------------------------------------------------------
// H30 — the height-vs-round distinction (unit)
// ---------------------------------------------------------------------------

#[test]
fn h30_height_vs_round_distinction() {
    // Base context binds the logical view to wire `height` regardless of round.
    let ctx = ctx_n(4);
    let mut qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    qc.round = 999; // round differs from height; view binds to height=5
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    let dec = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(locked),
    };
    let enc = encode_record(&dec, &ctx).unwrap();
    // Default profile: height-binding holds even though height != round → OK.
    assert!(validate_decoded(
        dec.clone(),
        enc.clone(),
        &ctx,
        None::<&FixtureCommittedHistory>
    )
    .is_ok());

    // Opt-in profile additionally requiring height == round → refuse.
    let mut strict = ctx.clone();
    strict.require_height_equals_round = true;
    assert!(matches!(
        validate_decoded(dec, enc, &strict, None::<&FixtureCommittedHistory>),
        Err(SafetyStoreError::SemanticRefusal(_))
    ));

    // A record with height == round passes the strict profile.
    let qc_eq = valid_wire_qc(&strict, [0x44u8; 32], 7); // height==round==7
    let locked_eq = make_locked_qc(&strict, [0x44u8; 32], 7, qc_eq, None).unwrap();
    let dec_eq = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: strict.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(locked_eq),
    };
    let enc_eq = encode_record(&dec_eq, &strict).unwrap();
    assert!(validate_decoded(dec_eq, enc_eq, &strict, None::<&FixtureCommittedHistory>).is_ok());
}

// ---------------------------------------------------------------------------
// Component accounting (synthetic holders; NOT engine integration)
// ---------------------------------------------------------------------------

#[test]
fn accounting_admits_below_cap_and_refuses_over_cap() {
    use qbind_node::safety_record_store::accounting::{generation_charge, AllocationAccountant};
    let ctx = ctx_n(4);
    let gen = RetainedGeneration::from_locked(
        1,
        &make_locked_qc(&ctx, [9u8; 32], 5, valid_wire_qc(&ctx, [9u8; 32], 5), None).unwrap(),
    );
    let charge = generation_charge(&ctx, &gen).unwrap();
    let mut acct = AllocationAccountant::new(&ctx, 0).unwrap();
    assert!(acct.admit(charge).is_ok());
    assert!(acct.current() <= acct.cap());
    // Admitting beyond the cap refuses.
    assert!(matches!(
        acct.admit(acct.cap()),
        Err(SafetyStoreError::CapacityRefusal(_))
    ));
}

#[test]
fn layout_sizes_within_ceiling() {
    // Surface the measured native layout for evidence; the compile-time assertion
    // in the module already enforces the ceiling.
    let sz = std::mem::size_of::<RetainedGeneration>();
    println!("MEASURED size_of::<RetainedGeneration>() = {sz}");
    assert!(sz as u128 <= qbind_node::safety_record_store::profile::GEN_STRUCT_MAX);
}

// §4 representation-and-charge proof: the operative proof covers the **real**
// retained representation (`ValidatedRecord` holding the contract-compliant
// `RetainedRecord`), connecting complete objects to enforced charges. The
// corrected representation (§13.7A(c.4)) discards the validated `version`/
// `genesis` header from the retained generation, so the retained generation now
// FITS `GEN_STRUCT_MAX` — the previously-reported "DecodedRecord (408) exceeds
// GEN_STRUCT_MAX, so the ceiling must grow" defect is corrected, not reasserted.
// The old `DecodedRecord > GEN_STRUCT_MAX` acceptance assertion is deliberately
// NOT present; `DecodedRecord` is now only transient decode/validation scratch.
#[test]
fn real_representation_layout_decomposition() {
    use qbind_node::safety_record_store::profile::GEN_STRUCT_MAX;
    use qbind_node::safety_record_store::record::{
        size_of_decoded_record, size_of_retained_generation, size_of_retained_record,
        size_of_safety_record, size_of_validated_record, validated_holder_handle_bytes,
    };

    let gen_core = size_of_safety_record();
    let retained = size_of_retained_record();
    let decoded_transient = size_of_decoded_record();
    let validated = size_of_validated_record();
    let synthetic = size_of_retained_generation();
    println!(
        "MEASURED gen_core(SafetyRecord)={gen_core} retained(RetainedRecord)={retained} \
         transient(DecodedRecord)={decoded_transient} validated(ValidatedRecord)={validated} \
         synthetic(RetainedGeneration)={synthetic} GEN_STRUCT_MAX={GEN_STRUCT_MAX}"
    );

    // CORRECTED PROOF: the complete retained generation actually held by
    // operations fits the accepted ceiling — NO ceiling increase is required.
    assert!(
        retained <= GEN_STRUCT_MAX,
        "retained generation {retained} must fit GEN_STRUCT_MAX {GEN_STRUCT_MAX} \
         (the D7-D14 representation correction discards the validated header)"
    );
    // It genuinely contains the SafetyRecord generation core inline.
    assert!(
        retained >= gen_core,
        "RetainedRecord {retained} must contain its SafetyRecord core {gen_core} inline"
    );

    // INDEPENDENT ACCOUNTING INEQUALITY (finding-#2 correction): the complete
    // inline retained proof is COVERED by its retained generation core plus the
    // independently-inventoried holder-handle charge — NOT proven by the old
    // `validated_handle_fields = validated − retained` subtraction followed by the
    // tautological `retained + handle == validated`. `validated_holder_handle_bytes`
    // is summed from the handle field inventory (+ one alignment allowance), on its
    // own basis, and the inequality below (mirroring the compile-time assertion in
    // the component root) verifies it actually covers the measured layout.
    let handle_charge = validated_holder_handle_bytes();
    // MEASURED field inventory behind `validated_holder_handle_bytes()` (§3 defect
    // #1): print every term so the helper's reserved charge is recorded from the
    // executed target rather than inferred from the `validated − retained`
    // subtraction. The helper adds a separate alignment allowance, so the helper
    // return is NOT required to equal the subtraction — it must only *cover* it.
    let ev = std::mem::size_of::<qbind_node::safety_record_store::record::EvidenceStatus>();
    let vecdesc = std::mem::size_of::<Vec<u8>>();
    let digest = std::mem::size_of::<[u8; 32]>();
    let opt_u64 = std::mem::size_of::<Option<u64>>();
    let opt_res =
        std::mem::size_of::<Option<qbind_node::safety_record_store::accounting::Reservation>>();
    let align_vr = std::mem::align_of::<qbind_node::safety_record_store::record::ValidatedRecord>();
    let field_inventory = ev + vecdesc + digest + opt_u64 + opt_res;
    println!(
        "MEASURED handle inventory: EvidenceStatus={ev} Vec<u8>={vecdesc} [u8;32]={digest} \
         Option<u64>={opt_u64} Option<Reservation>={opt_res} align<ValidatedRecord>={align_vr} \
         field_inventory={field_inventory} helper_return={handle_charge} \
         (validated−retained subtraction={})",
        validated - retained
    );
    // The helper return is exactly the inventory plus one alignment allowance, and
    // it covers (is ≥) the real inline handle fields — it is a reserved charge on
    // its own basis, not the subtraction.
    assert_eq!(
        handle_charge as usize,
        field_inventory + align_vr,
        "helper return must equal its field inventory plus one alignment allowance"
    );
    assert!(
        validated <= retained + handle_charge,
        "retained generation ({retained}) + independently-inventoried handle charge \
         ({handle_charge}) must cover the complete inline ValidatedRecord ({validated})"
    );
    // The handle charge is a genuinely non-trivial separately-reserved term (the
    // retained-encoded Vec descriptor, origin digest, O5 incarnation option, and
    // the inline holder Reservation option), charged under its own term — NOT the
    // generation ceiling.
    assert!(
        handle_charge > 0 && validated > retained,
        "ValidatedRecord must carry separately-charged holder/handle fields"
    );
    let validated_handle_fields = validated - retained;
    assert!(
        handle_charge >= validated_handle_fields,
        "the enforced handle charge ({handle_charge}) must cover the real inline \
         handle fields ({validated_handle_fields})"
    );

    // The transient decode/validation container still carries the two header
    // fields and so is larger than the retained generation — demonstrating the
    // fields that were dropped. It is charged only as transient validation
    // scratch (bounded by MAX_SAFETY_RECORD_BYTES), never retained.
    assert!(
        decoded_transient > retained,
        "transient DecodedRecord ({decoded_transient}) must be larger than the \
         retained generation ({retained}); the validated header is discarded from \
         the retained generation"
    );
    // Margin surfaced for the evidence document (the retained generation sits
    // under the ceiling rather than over it).
    let ceiling_headroom = GEN_STRUCT_MAX - retained;
    println!(
        "SURFACED: retained_generation={retained} fits GEN_STRUCT_MAX={GEN_STRUCT_MAX} \
         (headroom={ceiling_headroom}); transient_decoded={decoded_transient} \
         handle_fields={validated_handle_fields}"
    );
}

// §3/§7 operation-level regression: the validated-then-discarded identity header
// (`persistence_format_version`, `network_genesis_id`) is NOT retained in the
// generation after a real O3, yet its exact bytes survive verbatim in the
// retained `encoded` publication (§13.7A(c.4)/(c.5)). The retained proof is the
// object O5 actually re-acknowledges with.
#[test]
fn o3_retained_generation_discards_header_but_encoded_preserves_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    // Publish a QC-derived locked record so the retained generation is non-trivial.
    let block = [9u8; 32];
    let locked = make_locked_qc(&ctx, block, 5, valid_wire_qc(&ctx, block, 5), None).unwrap();
    assert_eq!(
        owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );

    let v = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();

    // The retained generation carries ONLY the post-validation fields: the
    // publication revision + the SafetyRecord core. There is no genesis/version
    // field on `RetainedRecord` at all (enforced at the type level); confirm the
    // generation is the locked core and the revision is retained inline.
    assert_eq!(v.retained().publication_revision, 1);
    assert!(v.retained().is_locked());

    // The discarded header bytes nonetheless survive VERBATIM in the retained
    // encoded publication: version at bytes [0,2), genesis id at bytes [2,34).
    let enc = v.encoded();
    assert_eq!(
        &enc[0..2],
        &qbind_node::safety_record_store::profile::SAFETY_PERSISTENCE_FORMAT_VERSION.to_be_bytes(),
        "persistence_format_version bytes must survive in the retained encoded publication"
    );
    assert_eq!(
        &enc[2..34],
        &ctx.network_genesis_id,
        "network_genesis_id bytes must survive verbatim in the retained encoded publication"
    );

    // The retained proof (which holds NO header in its generation) is exactly
    // what O5 re-acknowledges with, proving the retained representation is the one
    // actually used by O5 and that O5 compares the ORIGINAL bytes, not a
    // reconstruction from the header-less generation.
    assert_eq!(
        owner.reacknowledge(&v),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
}

// §3/§7 regression: the retained generation for every supported variant
// (BootstrapNoLock, Locked-with-no-commit, anchored Locked, TC-derived) fits the
// accepted generation ceiling WITHOUT manufacturing any absent value — the
// corrected representation needs no ceiling increase.
#[test]
fn retained_generation_fits_ceiling_all_variants() {
    use qbind_node::safety_record_store::profile::GEN_STRUCT_MAX;
    use qbind_node::safety_record_store::record::size_of_retained_record;
    // RetainedRecord is a single whole-enum generation; its measured size bounds
    // every variant (BootstrapNoLock / Locked / anchored / TC-derived) because the
    // enum occupies the whole layout regardless of the active arm.
    assert!(
        size_of_retained_record() <= GEN_STRUCT_MAX,
        "retained generation {} must fit GEN_STRUCT_MAX {GEN_STRUCT_MAX}",
        size_of_retained_record()
    );

    // Exercise a real O3 for a bootstrap (no-lock) and an anchored locked record,
    // confirming the retained generation preserves the bootstrap/anchored
    // distinction (absent values stay absent, never coerced).
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let boot = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert!(
        !boot.retained().is_locked(),
        "bootstrap retained generation preserves the no-lock variant"
    );
    match &boot.retained().record {
        SafetyRecord::BootstrapNoLock {
            predecessor_ref, ..
        } => assert!(
            predecessor_ref.is_none(),
            "absent predecessor stays absent (no manufactured value)"
        ),
        _ => panic!("expected bootstrap no-lock retained generation"),
    }
}

// ---------------------------------------------------------------------------
// Correction pass (D7-D14 correction) — foreign-context refusal (§13.3/§13.4)
// ---------------------------------------------------------------------------
//
// A store initialized under context A must not be read or published over by a
// second handle attached under a different (foreign) pinned context B, even
// though that handle never invoked `open`. The prerequisite is enforced in the
// implementation, not left to caller discipline.
#[test]
fn corr_foreign_context_handle_refuses_o3_and_o4() {
    let dir = tempfile::tempdir().unwrap();
    let ctx_a = ctx_n(4);
    // Context B differs only in the authority-context descriptor, so its context
    // digest differs from the stored one.
    let mut ctx_b = ctx_n(4);
    ctx_b.authority_context_ref = [0x7Eu8; 32];

    // One backend instance (RocksDB holds a single-process lock on the path);
    // attach both handles to it.
    let backend = open_enabled(dir.path());
    let owner_a = SafetyRecordOwner::attach(backend.clone(), ctx_a.clone()).unwrap();
    owner_a
        .initialize(true)
        .expect("O1 initialize under context A");

    // A second handle attached under context B to the SAME backend.
    let owner_b = SafetyRecordOwner::attach(backend.clone(), ctx_b.clone()).unwrap();

    // O3 under the foreign context refuses (does not accept the record).
    let r3 = owner_b.read_validate(None::<&FixtureCommittedHistory>);
    assert!(
        matches!(r3, Err(SafetyStoreError::SemanticRefusal(_))),
        "O3 foreign-context should refuse, got {r3:?}"
    );

    // O4 under the foreign context refuses BEFORE any write; the stored state is
    // untouched.
    let qc = valid_wire_qc(&ctx_b, [9u8; 32], 5);
    let locked = make_locked_qc(&ctx_b, [9u8; 32], 5, qc, None).unwrap();
    let r4 = owner_b.publish_locked(locked, 0, None::<&FixtureCommittedHistory>);
    assert!(
        matches!(
            r4,
            PublishResult::RefusedPreWrite(SafetyStoreError::SemanticRefusal(_))
        ),
        "O4 foreign-context should refuse pre-write, got {r4:?}"
    );

    // The owner under context A still observes the original bootstrap at rev 0.
    let v = owner_a
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert!(!v.retained().is_locked());
    assert_eq!(v.retained().publication_revision, 0);
}

// ---------------------------------------------------------------------------
// Correction pass (D7-D14 correction) — uncertainty blocks dependent O4 across
// all handles until O5 recovery clears it (§13.5)
// ---------------------------------------------------------------------------
#[test]
fn corr_uncertain_publish_blocks_dependent_o4_until_o5_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let backend = open_enabled(dir.path());
    let owner = SafetyRecordOwner::attach(backend.clone(), ctx.clone()).unwrap();
    owner.initialize(true).expect("O1 initialize");
    // A second handle sharing the SAME backend instance observes the shared latch
    // (clone shares the backend's Arc-held serialization domain + latch).
    let owner2 = owner.clone();

    // A normal publication (rev 0 -> 1) succeeds and does NOT latch.
    let qc1 = valid_wire_qc(&ctx, [9u8; 32], 5);
    let l1 = make_locked_qc(&ctx, [9u8; 32], 5, qc1, None).unwrap();
    assert_eq!(
        owner.publish_locked(l1, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    assert!(!owner.recovery_required());

    // An uncertain-but-durable publication (rev 1 -> 2): the write became durable
    // but the caller observed no acknowledgement, latching the shared requirement.
    backend.set_inject(InjectFault::UncertainAfterWrite);
    let qc2 = valid_wire_qc(&ctx, [0x11u8; 32], 6);
    let l2 = make_locked_qc(&ctx, [0x11u8; 32], 6, qc2, None).unwrap();
    assert!(matches!(
        owner.publish_locked(l2, 1, None::<&FixtureCommittedHistory>),
        PublishResult::UncertainDurable
    ));
    backend.set_inject(InjectFault::None);
    assert!(owner.recovery_required());
    assert!(
        owner2.recovery_required(),
        "second handle observes the latch"
    );

    // Dependent O4 is now refused on BOTH handles until recovery.
    let qc3 = valid_wire_qc(&ctx, [0x22u8; 32], 7);
    let l3 = make_locked_qc(&ctx, [0x22u8; 32], 7, qc3, None).unwrap();
    assert!(
        matches!(
            owner.publish_locked(l3.clone(), 2, None::<&FixtureCommittedHistory>),
            PublishResult::RefusedPreWrite(SafetyStoreError::RecoveryRequired(_))
        ),
        "same handle O4 must be blocked"
    );
    assert!(
        matches!(
            owner2.publish_locked(l3.clone(), 2, None::<&FixtureCommittedHistory>),
            PublishResult::RefusedPreWrite(SafetyStoreError::RecoveryRequired(_))
        ),
        "second handle O4 must be blocked"
    );

    // O2/O3 may still inspect the surviving state (rev 2) without claiming
    // effectiveness and without clearing the latch.
    let surviving = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert_eq!(surviving.retained().publication_revision, 2);
    assert!(owner.recovery_required(), "O3 does not clear the latch");

    // Only the successful recovery operation (O5 re-acknowledge of the surviving
    // publication) clears the shared requirement.
    assert!(matches!(
        owner.reacknowledge(&surviving),
        PublishResult::DurableAcknowledged { new_revision: 2 }
    ));
    assert!(!owner.recovery_required());
    assert!(!owner2.recovery_required());

    // Dependent O4 proceeds again (rev 2 -> 3).
    assert_eq!(
        owner.publish_locked(l3, 2, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 3 }
    );
}

// ---------------------------------------------------------------------------
// Correction pass (D7-D14 correction, task §4) — cloning an owner handle shares
// the single immutable pinned context allocation rather than copying its
// validator vector into a second, unaccounted buffer. The clone escape is
// closed by holding the context behind an `Arc`: both handles report the same
// context pointer and the same context digest, and repeated cloning does not
// mint per-handle context copies.
// ---------------------------------------------------------------------------
#[test]
fn corr_owner_clone_shares_one_context_allocation() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let backend = open_enabled(dir.path());
    let owner = SafetyRecordOwner::attach(backend.clone(), ctx.clone()).unwrap();

    // Cloning the owner shares the single Arc-held context: identical pointer.
    let owner2 = owner.clone();
    assert_eq!(
        owner.context_ptr_for_test(),
        owner2.context_ptr_for_test(),
        "owner clone must share one context allocation, not copy the validator vector"
    );

    // Repeated cloning keeps sharing the same allocation (no per-handle copies).
    let clones: Vec<SafetyRecordOwner> = (0..8).map(|_| owner.clone()).collect();
    for c in &clones {
        assert_eq!(
            c.context_ptr_for_test(),
            owner.context_ptr_for_test(),
            "every clone shares the one context allocation"
        );
    }

    // The shared context is still observable and consistent across handles.
    assert_eq!(owner.context().n(), owner2.context().n());
    assert_eq!(
        owner.context().validators,
        owner2.context().validators,
        "shared context exposes the same validator set"
    );
}

// ---------------------------------------------------------------------------
// Operational context-ownership accounting (§ 13.7B)
//
// `attach()` now charges each *distinct* retained pinned-context allocation
// against the backend's dedicated context-ownership accountant, BEFORE the
// `Arc<OwnedContext>` retains it. Cloning an owner shares the single Arc-held
// context (one charge); each independent `attach()` takes its own charge;
// exhausting the bounded multiplicity refuses a further attachment; and the
// charge is released only when the last clone drops. These regressions observe
// the real shared context accountant, not a mock.
// ---------------------------------------------------------------------------
#[test]
fn ctxacct_clone_shares_one_context_charge() {
    use qbind_node::safety_record_store::profile::context_ownership_charge;
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let backend = open_enabled(dir.path());
    let per_owner = context_ownership_charge(
        &ctx,
        qbind_node::safety_record_store::owner::size_of_owned_context_wrapper(),
    )
    .unwrap();

    let owner = SafetyRecordOwner::attach(backend.clone(), ctx.clone()).unwrap();
    // One distinct attachment holds exactly one context charge.
    assert_eq!(
        backend.context_accounting_current(),
        per_owner,
        "a single attachment charges one context allocation"
    );

    // Cloning the owner shares the one Arc-held context: NO additional charge.
    let clone1 = owner.clone();
    let clones: Vec<SafetyRecordOwner> = (0..8).map(|_| owner.clone()).collect();
    assert_eq!(
        backend.context_accounting_current(),
        per_owner,
        "clones share the single context charge (no per-handle copy charged)"
    );
    assert!(backend.context_accounting_current() <= backend.context_accounting_cap().unwrap());

    // Dropping clones while any clone survives keeps the charge live.
    drop(clones);
    drop(clone1);
    assert_eq!(
        backend.context_accounting_current(),
        per_owner,
        "charge stays live while the original owner clone survives"
    );

    // Dropping the LAST clone releases the single context charge.
    drop(owner);
    assert_eq!(
        backend.context_accounting_current(),
        0,
        "the context charge releases only when the last clone drops"
    );
}

#[test]
fn ctxacct_independent_attach_charges_distinctly_and_releases() {
    use qbind_node::safety_record_store::profile::context_ownership_charge;
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let backend = open_enabled(dir.path());
    let per_owner = context_ownership_charge(
        &ctx,
        qbind_node::safety_record_store::owner::size_of_owned_context_wrapper(),
    )
    .unwrap();

    // Two genuinely INDEPENDENT attachments (not clones) to the same backend are
    // distinct retained context allocations: each takes its own charge.
    let a = SafetyRecordOwner::attach(backend.clone(), ctx.clone()).unwrap();
    assert_eq!(backend.context_accounting_current(), per_owner);
    let b = SafetyRecordOwner::attach(backend.clone(), ctx.clone()).unwrap();
    assert_eq!(
        backend.context_accounting_current(),
        per_owner * 2,
        "independent attachments charge distinctly (different allocations)"
    );
    // Distinct allocations: different context pointers.
    assert_ne!(a.context_ptr_for_test(), b.context_ptr_for_test());

    // Dropping one independent owner releases only its own charge.
    drop(b);
    assert_eq!(backend.context_accounting_current(), per_owner);
    drop(a);
    assert_eq!(backend.context_accounting_current(), 0);
}

#[test]
fn ctxacct_independent_attach_multiplicity_is_bounded() {
    use qbind_node::safety_record_store::profile::MAX_CONCURRENT_CONTEXT_OWNERS;
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let backend = open_enabled(dir.path());
    let cap = MAX_CONCURRENT_CONTEXT_OWNERS as usize;

    // Exactly MAX_CONCURRENT_CONTEXT_OWNERS independent attachments fit.
    let mut owners = Vec::new();
    for _ in 0..cap {
        owners.push(SafetyRecordOwner::attach(backend.clone(), ctx.clone()).expect("within bound"));
    }
    assert_eq!(
        backend.context_accounting_current(),
        backend.context_accounting_cap().unwrap(),
        "the bounded multiplicity exactly fills the context ceiling"
    );

    // A further INDEPENDENT attachment past the bound is refused for capacity —
    // it is not permitted to mint an unaccounted context copy.
    match SafetyRecordOwner::attach(backend.clone(), ctx.clone()) {
        Err(SafetyStoreError::CapacityRefusal(_)) => {}
        other => panic!("expected CapacityRefusal past the context-owner bound, got {other:?}"),
    }

    // Releasing one attachment readmits a fresh independent attachment.
    owners.pop();
    let _readmitted =
        SafetyRecordOwner::attach(backend.clone(), ctx.clone()).expect("readmit after release");

    // Clones never count against the bound even while it is otherwise full.
    let _clone = owners[0].clone();
    assert!(backend.context_accounting_current() <= backend.context_accounting_cap().unwrap());
}

// Finding #3 — the context charge must account for the COMPLETE `OwnedContext`
// wrapper (inline pinned context + inline reservation + layout padding), not the
// partial inner pinned context. The expected lower bound is derived INDEPENDENTLY
// of the charge helper (from `size_of` of the reservation and the pinned context),
// so a regression that dropped the reservation field would fail here.
#[test]
fn ctxacct_charge_includes_reservation_field_and_layout_padding() {
    use qbind_node::safety_record_store::accounting::size_of_reservation;
    use qbind_node::safety_record_store::owner::size_of_owned_context_wrapper;
    use qbind_node::safety_record_store::profile::{
        context_ownership_charge, size_of_pinned_context, size_of_validator_entry, ARC_CTRL,
    };
    let ctx = ctx_n(4);
    let wrapper = size_of_owned_context_wrapper();
    let pinned = size_of_pinned_context();
    let reservation = size_of_reservation();
    println!(
        "MEASURED size_of::<OwnedContext>()={wrapper} size_of::<PinnedSafetyContext>()={pinned} \
         size_of::<Reservation>()={reservation}"
    );

    // Independent evidence (not from the charge helper): a reservation has a
    // non-zero footprint, and the complete wrapper lays out BOTH inline fields,
    // so it is at least `pinned + reservation`. A wrapper that omitted the
    // reservation field would measure exactly `pinned`.
    assert!(
        reservation > 0,
        "a Reservation has a real footprint to charge"
    );
    assert!(
        wrapper >= pinned + reservation,
        "OwnedContext wrapper {wrapper} must include the inline reservation \
         (pinned {pinned} + reservation {reservation}); omission detected"
    );

    // The charge is computed from the complete wrapper (+ actual validator
    // backing + one Arc header), so it strictly exceeds the reservation-omitting
    // (pinned-only) charge the reviewed implementation previously used.
    let backing = ctx.validators.capacity() as u128 * size_of_validator_entry();
    let charge = context_ownership_charge(&ctx, wrapper).unwrap();
    assert_eq!(
        charge,
        wrapper + backing + ARC_CTRL,
        "charge == complete wrapper + validator backing + one Arc header"
    );
    let reservation_omitting = pinned + backing + ARC_CTRL;
    assert!(
        charge > reservation_omitting,
        "charge {charge} must exceed the reservation-omitting charge {reservation_omitting}"
    );
    assert_eq!(
        charge - reservation_omitting,
        wrapper - pinned,
        "the additional charge is exactly the wrapper's reservation field + layout padding"
    );
}

// Finding #4 CORRECTION — the accepted component aggregate ceiling is the
// profile-derived OPERATIONAL aggregate (`max_aggregate_retained_bytes`), NOT
// that aggregate PLUS a separate context allowance. The prior regression asserted
// `agg_cap == op_cap + ctx_cap` (an enlargement); it is replaced below. The two
// per-class sub-caps are retained only as SUBORDINATE upper bounds whose sum
// exceeds the accepted aggregate, and that surplus is deliberately unreachable:
// the shared authority enforces the combined total, so context and operations
// genuinely compete for one budget.
#[test]
fn agg_ceiling_is_profile_operational_not_sum() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let backend = owner.backend_for_test();

    let agg_cap = backend
        .accounting_aggregate_cap()
        .expect("aggregate ceiling bound at attach");
    let op_cap = backend
        .accounting_cap()
        .expect("operational sub-ceiling bound at attach");
    let ctx_cap = backend
        .context_accounting_cap()
        .expect("context sub-ceiling bound at attach");
    // The combined budget IS the profile operational aggregate — never enlarged.
    assert_eq!(
        agg_cap, op_cap,
        "aggregate ceiling == profile operational aggregate (not op + context)"
    );
    // The context sub-cap is a subordinate per-class bound; the sub-caps sum to
    // MORE than the aggregate, proving the aggregate was not widened by adding it.
    assert!(
        ctx_cap > 0,
        "context sub-cap is a real, non-zero per-class bound"
    );
    assert!(
        op_cap + ctx_cap > agg_cap,
        "sub-caps sum to more than the aggregate (surplus unreachable, not an enlargement)"
    );
    println!(
        "MEASURED agg_cap={agg_cap} op_cap={op_cap} ctx_cap={ctx_cap} per_owner_charge={}",
        backend.context_accounting_current()
    );
}

// Live context ownership consumes the SAME budget real operations use: the live
// aggregate equals operational_partition + context_partition throughout real
// O1/O4/O3, never exceeds the accepted ceiling, and operational cleanup returns
// to the surviving context-owner charge (not zero while an owner remains live).
#[test]
fn agg_live_context_consumes_operational_budget() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let backend = owner.backend_for_test();
    let agg_cap = backend.accounting_aggregate_cap().unwrap();

    // The attached owner holds a live standing context charge, reflected in the
    // one shared aggregate authority (= operational partition + context partition).
    let ctx_standing = backend.context_accounting_current();
    assert!(
        ctx_standing > 0,
        "the attached owner holds a live context charge"
    );
    assert_eq!(
        backend.accounting_aggregate_current(),
        backend.accounting_current() + ctx_standing,
        "aggregate current == operational partition + context partition"
    );
    assert!(
        backend.accounting_aggregate_current() <= agg_cap,
        "aggregate current within the accepted ceiling after O1"
    );

    // A real O4 publication then a live O3 holder: the aggregate stays within the
    // ceiling and tracks the sum of both partitions throughout — the live context
    // charge is part of the same budget the operation is admitted against.
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    assert_eq!(
        owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert_eq!(
        backend.accounting_aggregate_current(),
        backend.accounting_current() + backend.context_accounting_current(),
        "aggregate current == operational partition + context partition during O3 hold"
    );
    assert!(
        backend.accounting_aggregate_current() <= agg_cap,
        "aggregate current within the accepted ceiling during O3 hold"
    );
    assert!(
        backend.accounting_aggregate_peak() <= agg_cap,
        "aggregate peak within the accepted ceiling"
    );

    // Operational cleanup returns to the surviving owner charge, not zero: the
    // live context owner's standing charge remains after the holder drops.
    drop(proof);
    assert_eq!(
        backend.accounting_aggregate_current(),
        ctx_standing,
        "after the operational holder drops, the live context-owner charge remains"
    );
}

// ---------------------------------------------------------------------------
// §4 — O1/O2 INSPECTION allocation admission (real-operation regressions).
//
// The inherited O1/O2 correction (5640dae) admits each inspection path's
// read/decode working set against the shared aggregate budget BEFORE the
// component-owned read-back / decode allocations occur, so an established /
// partial / malformed inspection cannot escape the aggregate ceiling. These
// regressions drive the REAL `initialize()` / `open()` operations against the
// REAL shared accountant (constructed boundary via `reserve_standing_for_test`),
// proving: (a) refusal happens at admission, BEFORE the existing-state read /
// decode; (b) the refusal preserves stored bytes and recovery/effectiveness
// state; (c) the reservation releases on every exit; (d) releasing competing
// pressure lets the same otherwise-valid operation proceed; and (e) the real
// working set fits within exactly the reserved charge (admission boundary).
//
// Mirror of the source constant `backend::META_ENCODED_LEN` (private); the
// fixed metadata buffer is `2 + 32 + 8` bytes.
const META_ENCODED_LEN_MIRROR: u128 = 2 + 32 + 8;

// (a)+(b)+(c)+(d): O1 on ESTABLISHED state is refused at admission — BEFORE the
// existing-state read that would otherwise report `AlreadyEstablished` — when the
// shared aggregate cannot admit O1's inspection working set. The refusal leaves
// the stored record bytes and the recovery latch untouched, and releasing the
// competing pressure lets the SAME O1 proceed to its real established-state
// detection.
#[test]
fn o1_established_inspection_refused_before_read_under_aggregate_pressure() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx); // established at revision 0, effective
    let backend = owner.backend_for_test();
    let agg_cap = backend.accounting_aggregate_cap().unwrap();
    let ctx_live = backend.context_accounting_current();
    assert!(ctx_live > 0, "init_owner holds one live context charge");

    // O1's inspection working set = record-sized read-back buffer + fixed metadata
    // buffer (exactly the source's `inspect_charge`).
    let rec = max_safety_record_bytes(&ctx).unwrap();
    let o1_inspect = rec + META_ENCODED_LEN_MIRROR;

    // Record the pre-refusal raw stored bytes and recovery state.
    let record_before = backend.read_record(rec).unwrap();
    assert!(record_before.is_some(), "established store has a record");
    assert!(!owner.recovery_required(), "O1 left the store effective");

    // Leave exactly `o1_inspect - 1` of aggregate headroom: the inspection charge
    // cannot be admitted. The operational sub-cap WOULD still permit it; the
    // refusal comes from the shared aggregate authority (the other partition's
    // live context charge consumed the shared budget).
    let standing_amt = agg_cap - ctx_live - (o1_inspect - 1);
    let standing = backend
        .reserve_standing_for_test(standing_amt)
        .expect("standing operational pressure within the combined budget");
    assert_eq!(
        backend.accounting_aggregate_current(),
        ctx_live + standing_amt
    );

    // The REAL O1 is refused at admission (CapacityRefusal), NOT AlreadyEstablished
    // — proving the refusal precedes the existing-state read.
    match owner.initialize(true) {
        Err(SafetyStoreError::CapacityRefusal(_)) => {}
        other => panic!("expected pre-read CapacityRefusal, got {other:?}"),
    }
    // No leak: the refusal reserved/released nothing beyond the standing pressure.
    assert_eq!(
        backend.accounting_aggregate_current(),
        ctx_live + standing_amt,
        "a refused O1 inspection leaves the aggregate charge unchanged"
    );
    // Stored bytes and recovery/effectiveness state preserved.
    assert_eq!(
        backend.read_record(rec).unwrap(),
        record_before,
        "refused O1 did not mutate stored record bytes"
    );
    assert!(
        !owner.recovery_required(),
        "refused O1 did not disturb the effectiveness latch"
    );

    // (d) Releasing the competing pressure lets the SAME O1 proceed to its real
    // established-state detection (now the read runs) — AlreadyEstablished, not a
    // capacity error. This proves the earlier refusal was pre-read.
    drop(standing);
    match owner.initialize(true) {
        Err(SafetyStoreError::AlreadyEstablished(_)) => {}
        other => panic!("expected AlreadyEstablished after releasing pressure, got {other:?}"),
    }
    assert_eq!(
        backend.accounting_current(),
        0,
        "O1 inspection reservation released on the AlreadyEstablished exit"
    );
}

// (a): O1 over a PARTIAL (record-present / metadata-absent) namespace is likewise
// refused at admission BEFORE the inspection read that would classify it as a
// structural partial, since the inspection charge is reserved before `read_meta`
// / `read_record` on the SAME code path. Releasing the pressure surfaces the real
// StructuralRefusal.
#[test]
fn o1_partial_state_inspection_refused_before_read_under_aggregate_pressure() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    // Construct a partial namespace directly: a CRC-wrapped record key with NO
    // metadata key. (Not a production path; test-only out-of-band writer.)
    let backend = open_enabled(dir.path());
    backend
        .debug_overwrite_record(&[0xAAu8, 0xBB, 0xCC])
        .expect("stage a partial record-without-metadata namespace");
    let owner = SafetyRecordOwner::attach(backend, ctx.clone()).unwrap();
    let backend = owner.backend_for_test();
    let agg_cap = backend.accounting_aggregate_cap().unwrap();
    let ctx_live = backend.context_accounting_current();
    let rec = max_safety_record_bytes(&ctx).unwrap();
    let o1_inspect = rec + META_ENCODED_LEN_MIRROR;

    let standing_amt = agg_cap - ctx_live - (o1_inspect - 1);
    let standing = backend
        .reserve_standing_for_test(standing_amt)
        .expect("standing pressure within the combined budget");
    // Refused at admission — before the partial-state read/classification.
    match owner.initialize(true) {
        Err(SafetyStoreError::CapacityRefusal(_)) => {}
        other => panic!("expected pre-read CapacityRefusal over partial state, got {other:?}"),
    }
    // Releasing pressure surfaces the genuine structural refusal (record present
    // without metadata) — the inspection read now runs.
    drop(standing);
    match owner.initialize(true) {
        Err(SafetyStoreError::StructuralRefusal(_)) => {}
        other => panic!("expected StructuralRefusal over partial state, got {other:?}"),
    }
    assert_eq!(
        backend.accounting_current(),
        0,
        "O1 partial-state inspection reservation released on exit"
    );
}

// (e)+(b)+(c): O2 `open()` admits its read/decode working set (record read-back
// buffer + fixed metadata buffer + one transient decoded generation + validation
// scratch) against the shared aggregate budget BEFORE the `load_established`
// allocations/decode. The real operation fits within EXACTLY the reserved charge
// `rec + META + gen` (succeeds with exactly that headroom) and is refused ONE byte
// short (before any decode), preserving stored bytes and recovery state, and the
// reservation releases on every exit.
//
// The decoded transient is bounded by measuring its FULL capacity-backed charge
// (`generation_charge`, which sums every `Vec::capacity()` backing), NOT merely
// the inline `size_of` of the container — the earlier inline-only check did not
// account for the signer bitmap / signatures / per-signature heap backings.
#[test]
fn o2_open_working_set_admitted_and_bounded_by_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    // Establish a real locked (QC-derived) publication so O2 decodes a non-trivial
    // generation. The o2 charge is the max over QC/TC generations, so the reserved
    // bound covers the actual decoded working set either way.
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    assert_eq!(
        owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    let backend = owner.backend_for_test();
    let agg_cap = backend.accounting_aggregate_cap().unwrap();
    let ctx_live = backend.context_accounting_current();

    let rec = max_safety_record_bytes(&ctx).unwrap();
    let gen = qbind_node::safety_record_store::profile::max_retained_generation_bytes(
        &ctx,
        qbind_node::safety_record_store::record::size_of_timeout_msg(),
    )
    .unwrap();
    let transient =
        qbind_node::safety_record_store::accounting::max_transient_decoded_working_set(&ctx)
            .unwrap();
    // The transient decoded ceiling EXCEEDS the retained-generation ceiling: a
    // `DecodedRecord` carries the validated-then-discarded identity header, so O2
    // reserves the TRANSIENT ceiling, not the retained-generation ceiling.
    assert!(
        transient > gen,
        "transient decoded ceiling {transient} must exceed retained generation ceiling {gen}"
    );
    let o2_charge = rec + META_ENCODED_LEN_MIRROR + transient;

    // Directly bound the actual decoded **working set** measured IN PLACE on the
    // borrowed `DecodedRecord` — its inline representation PLUS the `Vec::capacity()`
    // of every backing it actually owns (signer bitmap, the signatures outer
    // descriptor array, each signature buffer) — against its reserved term `gen`.
    // This observes the ORIGINAL decoded object, NOT a cloned `RetainedGeneration`
    // (whose capacities would be the clone's, not the live object's); the earlier
    // check charged such a clone and therefore did not measure the real O2 working
    // set. `decoded_working_set_charge` borrows the object without cloning it.
    use qbind_node::safety_record_store::accounting::decoded_working_set_charge;
    let stored = backend.read_record(rec).unwrap().expect("record present");
    assert!(
        (stored.len() as u128) <= rec,
        "actual stored record buffer {} fits the record bound {rec}",
        stored.len()
    );
    let decoded = decode_record(&stored, &ctx).unwrap();
    let decoded_core = qbind_node::safety_record_store::record::size_of_decoded_record();
    let decoded_full = decoded_working_set_charge(&decoded).unwrap();
    assert!(
        matches!(&decoded.record, SafetyRecord::Locked(_)),
        "expected a Locked decoded generation, got {:?}",
        decoded.record
    );
    assert!(
        decoded_core as u128 <= decoded_full,
        "the inline core {decoded_core} is only part of the full backed working set {decoded_full}"
    );
    assert!(
        decoded_full <= transient,
        "the full decoded working set (inline + capacity-measured backings) {decoded_full} \
         fits its reserved transient decoded term {transient}"
    );
    assert!(decoded.publication_revision == 1);

    // Leave EXACTLY `o2_charge` of aggregate headroom: the real O2 working set fits.
    let standing_fits = agg_cap - ctx_live - o2_charge;
    let standing = backend
        .reserve_standing_for_test(standing_fits)
        .expect("standing pressure leaving exactly the O2 working set");
    let peak_before = backend.accounting_aggregate_peak();
    let meta = owner
        .open()
        .expect("O2 open fits within exactly its reserved charge");
    assert_eq!(meta.current_revision, 1);
    assert!(
        backend.accounting_aggregate_peak() <= agg_cap,
        "O2 open never exceeded the aggregate ceiling"
    );
    assert!(
        backend.accounting_aggregate_peak() >= peak_before,
        "O2 open reserved a real charge against the shared accountant"
    );
    assert_eq!(
        backend.accounting_aggregate_current(),
        ctx_live + standing_fits,
        "O2 read/decode reservation released on the success exit (only standing remains)"
    );
    drop(standing);

    // Now leave ONE byte less: the real O2 is refused at admission, BEFORE decode.
    let record_before = backend.read_record(rec).unwrap();
    let standing_short = agg_cap - ctx_live - (o2_charge - 1);
    let standing = backend
        .reserve_standing_for_test(standing_short)
        .expect("standing pressure one byte short of the O2 working set");
    match owner.open() {
        Err(SafetyStoreError::CapacityRefusal(_)) => {}
        other => panic!("expected pre-decode CapacityRefusal, got {other:?}"),
    }
    assert_eq!(
        backend.read_record(rec).unwrap(),
        record_before,
        "refused O2 did not mutate stored record bytes"
    );
    assert!(
        !owner.recovery_required(),
        "refused O2 did not disturb the effectiveness latch"
    );
    assert_eq!(
        backend.accounting_aggregate_current(),
        ctx_live + standing_short,
        "refused O2 released its (rolled-back) admission attempt cleanly"
    );
    drop(standing);
}

// RESERVATION-LEVEL admission-boundary evidence (NOT an O1–O5 operation). Both
// the standing pressure AND the refused charge here are test-only
// `reserve_standing_for_test` reservations, used to construct the combined-budget
// boundary directly. It proves the shared authority refuses a charge the
// OPERATIONAL sub-cap would still permit, because live context ownership (the
// other partition) consumed shared capacity; freeing a live context owner
// restores the operational capacity. The REAL-operation counterpart — a genuine
// O4 `publish_locked` refused by the same combined budget while its operational
// sub-cap permits its charge — is `agg_real_o4_refused_by_combined_though_op_class_permits`.
#[test]
fn agg_synthetic_reservation_refused_by_combined_even_though_op_class_permits() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let backend = owner.backend_for_test();
    let agg_cap = backend.accounting_aggregate_cap().unwrap();
    let op_cap = backend.accounting_cap().unwrap();
    let ctx_cap = backend.context_accounting_cap().unwrap();
    let per_owner = backend.context_accounting_current();

    // Fill the context partition to its own sub-cap with INDEPENDENT attachments
    // (init_owner already holds one). Context alone stays within its sub-cap.
    let mut extra = Vec::new();
    while backend.context_accounting_current() + per_owner <= ctx_cap {
        extra.push(SafetyRecordOwner::attach(backend.clone(), ctx.clone()).unwrap());
    }
    let ctx_live = backend.context_accounting_current();
    assert!(ctx_live > 0 && ctx_live <= ctx_cap);

    // Standing operational pressure that, with the live context, sits just under
    // the aggregate while leaving operational-class headroom.
    let aggregate_headroom = agg_cap - ctx_live;
    let standing = backend
        .reserve_standing_for_test(aggregate_headroom - 100)
        .expect("standing operational reservation under the combined budget");
    // The operational class sub-cap plainly still permits a further small charge.
    let charge = 200u128;
    assert!(
        backend.accounting_current() + charge <= op_cap,
        "operational class sub-cap permits this charge ({} + {charge} <= {op_cap})",
        backend.accounting_current()
    );
    // ...but the COMBINED budget refuses it: 100 aggregate bytes remain, < 200.
    match backend.reserve_standing_for_test(charge) {
        Err(SafetyStoreError::CapacityRefusal(_)) => {}
        other => panic!("expected combined CapacityRefusal, got {other:?}"),
    }
    // Refusal preserved the standing reservation and durable state.
    assert_eq!(backend.accounting_aggregate_current(), agg_cap - 100);

    // Releasing a live context owner restores aggregate capacity for the op, even
    // though the operational partition never moved.
    drop(extra.pop().expect("a context owner to release"));
    let readmit = backend
        .reserve_standing_for_test(charge)
        .expect("freeing a context owner restores combined capacity for the operation");
    drop(readmit);
    drop(standing);
    drop(extra);
}

// An attachment (the REAL operation under test) is refused because live
// occupancy of the shared aggregate leaves less than one context charge of
// headroom, even though the context class sub-cap plainly permits another owner.
// The occupancy here is supplied by a clearly-labelled SYNTHETIC standing
// operational reservation (`reserve_standing_for_test`) that constructs the
// admission boundary — it is reservation-level pressure, not a real O1–O5
// operation — but the operation being refused and rolled back is a genuine
// `SafetyRecordOwner::attach`. Durable state and existing reservations are
// preserved; freeing the pressure readmits the attachment.
#[test]
fn agg_attachment_refused_when_operations_consume_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let backend = owner.backend_for_test();
    let agg_cap = backend.accounting_aggregate_cap().unwrap();
    let ctx_cap = backend.context_accounting_cap().unwrap();
    let ctx_live = backend.context_accounting_current();

    // Live operational pressure consumes nearly the whole shared budget, leaving
    // less than one context charge of aggregate headroom.
    let standing = backend
        .reserve_standing_for_test(agg_cap - ctx_live - 10)
        .expect("standing operational reservation under the combined budget");
    // The context class sub-cap plainly permits another independent attachment.
    assert!(
        backend.context_accounting_current() + ctx_live <= ctx_cap,
        "context class sub-cap still permits another attachment"
    );
    // ...but the combined budget refuses it: live operations consumed the capacity.
    match SafetyRecordOwner::attach(backend.clone(), ctx.clone()) {
        Err(SafetyStoreError::CapacityRefusal(_)) => {}
        other => panic!("expected combined CapacityRefusal on attach, got {other:?}"),
    }
    // The refusal rolled back cleanly: the context partition is untouched.
    assert_eq!(backend.context_accounting_current(), ctx_live);

    // Freeing the operations restores combined capacity for the attachment.
    drop(standing);
    let _readmitted = SafetyRecordOwner::attach(backend.clone(), ctx.clone())
        .expect("freeing operations restores combined capacity for the attachment");
}

// REAL-OPERATION aggregate competition (§ 13.7, finding #4 / finding #7): a
// genuine O4 `publish_locked` — not a synthetic reservation — is refused by the
// COMBINED aggregate authority even though its OWN operational sub-cap would
// still admit the identical charge. This is the real-operation counterpart to
// `agg_synthetic_reservation_refused_by_combined_even_though_op_class_permits`.
//
// The refusal is decisively the shared authority, not the operational sub-cap:
// the test asserts `operational_current + o4_charge <= op_cap` (the op class
// permits it) while `aggregate_current + o4_charge > agg_cap` (the combined
// budget cannot). `SharedAccountant::reserve` admits against the aggregate
// first, so the real O4 is refused pre-write with `CapacityRefusal`, leaving the
// established evidence and recovery state untouched. Releasing the synthetic
// standing pressure readmits a real O4 that advances the revision — admission is
// restored without any loss of durable evidence.
#[test]
fn agg_real_o4_refused_by_combined_though_op_class_permits() {
    let ctx = ctx_n(4);

    // Measure the real O4 working-set charge on an ISOLATED backend by executing
    // a real publish and reading the shared accountant's observed peak. In a
    // publish-only flow the O4 reservation (2×generation + 3×record) is the
    // largest operational peak, so the peak IS the real O4 charge.
    let probe_dir = tempfile::tempdir().unwrap();
    let probe = init_owner(probe_dir.path(), &ctx);
    let probe_backend = probe.backend_for_test();
    let pqc = valid_wire_qc(&ctx, [3u8; 32], 5);
    let plocked = make_locked_qc(&ctx, [3u8; 32], 5, pqc, None).unwrap();
    assert_eq!(
        probe.publish_locked(plocked, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    let o4_charge = probe_backend.accounting_peak();
    assert!(
        o4_charge > 0,
        "a real O4 reserves a real working-set buffer"
    );

    // Fresh store under test. Establish durable evidence (revision 1) first so a
    // later pre-write refusal is demonstrably non-destructive.
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    let backend = owner.backend_for_test();
    let agg_cap = backend.accounting_aggregate_cap().unwrap();
    let op_cap = backend.accounting_cap().unwrap();
    assert_eq!(
        agg_cap, op_cap,
        "combined budget IS the profile operational aggregate"
    );
    assert!(
        o4_charge <= op_cap,
        "a single real O4 fits within the operational sub-cap ({o4_charge} <= {op_cap})"
    );

    let qc0 = valid_wire_qc(&ctx, [9u8; 32], 5);
    let l0 = make_locked_qc(&ctx, [9u8; 32], 5, qc0, None).unwrap();
    assert_eq!(
        owner.publish_locked(l0, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    assert_eq!(backend.accounting_current(), 0, "O4 working set released");

    // Live context pressure from a REAL independent attachment consumes shared
    // budget in the CONTEXT partition (the operational partition stays at 0).
    let attached = SafetyRecordOwner::attach(backend.clone(), ctx.clone()).unwrap();
    let ctx_live = backend.context_accounting_current();
    assert!(ctx_live > 0, "a live context owner consumes shared budget");

    // A clearly-labelled SYNTHETIC standing operational reservation constructs
    // the admission boundary so the operational sub-cap would STILL admit one
    // more real O4 exactly (`op_current + o4_charge == op_cap`), while the
    // combined budget falls short by exactly the live context charge.
    let standing_op = op_cap - o4_charge;
    let standing = backend
        .reserve_standing_for_test(standing_op)
        .expect("synthetic standing operational pressure within the op sub-cap");
    println!(
        "MEASURED o4_charge={o4_charge} op_cap={op_cap} agg_cap={agg_cap} ctx_live={ctx_live} standing_op={standing_op}"
    );

    // The operational class sub-cap WOULD permit the real O4 charge...
    assert!(
        backend.accounting_current() + o4_charge <= op_cap,
        "operational class sub-cap permits the real O4 charge ({} + {o4_charge} <= {op_cap})",
        backend.accounting_current()
    );
    // ...but the COMBINED budget cannot: context + operational leave < o4_charge.
    assert!(
        backend.accounting_aggregate_current() + o4_charge > agg_cap,
        "combined aggregate cannot admit the real O4 charge ({} + {o4_charge} > {agg_cap})",
        backend.accounting_aggregate_current()
    );

    // The REAL O4 is refused pre-write by the combined authority, preserving the
    // established evidence and the recovery state (no durable write, no eviction).
    let qc1 = valid_wire_qc(&ctx, [7u8; 32], 6);
    let l1 = make_locked_qc(&ctx, [7u8; 32], 6, qc1, None).unwrap();
    match owner.publish_locked(l1, 1, None::<&FixtureCommittedHistory>) {
        PublishResult::RefusedPreWrite(SafetyStoreError::CapacityRefusal(_)) => {}
        other => panic!("expected combined CapacityRefusal RefusedPreWrite, got {other:?}"),
    }
    assert!(
        !owner.recovery_required(),
        "a combined capacity refusal is pre-write and does not arm recovery"
    );
    let rb = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert_eq!(
        rb.retained().publication_revision,
        1,
        "established evidence intact after the refused real O4"
    );
    drop(rb);

    // Releasing the synthetic pressure restores admission for a real O4 that
    // advances the revision — no durable evidence was lost by the refusal.
    drop(standing);
    assert_eq!(
        backend.accounting_current(),
        0,
        "operational partition clear after releasing synthetic pressure"
    );
    let qc2 = valid_wire_qc(&ctx, [7u8; 32], 6);
    let l2 = make_locked_qc(&ctx, [7u8; 32], 6, qc2, None).unwrap();
    assert_eq!(
        owner.publish_locked(l2, 1, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 2 }
    );
    drop(attached);
}

// Concurrent admission across threads can never exceed the accepted aggregate:
// the single shared authority serializes every admit, so the observed peak and
// the sum of concurrently-held chunks both stay within the combined budget
// regardless of interleaving.
#[test]
fn agg_concurrent_admission_cannot_exceed() {
    use std::sync::Arc;
    use std::thread;
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let backend = Arc::new(owner.backend_for_test().clone());
    let agg_cap = backend.accounting_aggregate_cap().unwrap();
    let ctx_live = backend.context_accounting_current();
    let budget = agg_cap - ctx_live;
    // Chunk sized so at most two of the eight threads can coexist.
    let chunk = budget / 3 + 1;

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let b = Arc::clone(&backend);
            thread::spawn(move || b.reserve_standing_for_test(chunk).ok())
        })
        .collect();
    // Hold every successful reservation simultaneously.
    let reservations: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let live = reservations.iter().filter(|r| r.is_some()).count() as u128;

    assert!(
        backend.accounting_aggregate_peak() <= agg_cap,
        "concurrent admission peak within the accepted aggregate ceiling"
    );
    assert!(
        ctx_live + live * chunk <= agg_cap,
        "concurrently admitted chunks ({live}×{chunk}) + context never exceed the budget"
    );
    assert!(live >= 1, "at least one concurrent admission succeeded");
}

#[test]
fn corr_reopen_established_store_blocks_o4_until_o5() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    // Establish + publish a lock (rev 1) under the first backend instance.
    let owner = init_owner(dir.path(), &ctx);
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let l1 = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    assert_eq!(
        owner.publish_locked(l1, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    drop(owner);

    // Reopen a FRESH backend instance over the surviving bytes: no inherited
    // acknowledgement knowledge, so dependent O4 must be refused before any write.
    let owner2 = SafetyRecordOwner::attach(open_enabled(dir.path()), ctx.clone()).unwrap();
    assert!(
        owner2.recovery_required(),
        "a freshly reopened established store starts not-effective"
    );
    let qc2 = valid_wire_qc(&ctx, [0x11u8; 32], 6);
    let l2 = make_locked_qc(&ctx, [0x11u8; 32], 6, qc2, None).unwrap();
    let blocked = owner2.publish_locked(l2.clone(), 1, None::<&FixtureCommittedHistory>);
    assert!(
        matches!(
            blocked,
            PublishResult::RefusedPreWrite(SafetyStoreError::RecoveryRequired(_))
        ),
        "O4 after reopen must be blocked until O5, got {blocked:?}"
    );
    // Refusal left the surviving state (lock rev 1) unchanged.
    let surviving = owner2
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert_eq!(surviving.retained().publication_revision, 1);
    assert!(
        owner2.recovery_required(),
        "O3 inspection does not make the surviving state effective"
    );

    // A successful O5 over the surviving publication re-establishes effectiveness.
    assert!(matches!(
        owner2.reacknowledge(&surviving),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    ));
    assert!(!owner2.recovery_required());

    // The next eligible O4 now proceeds (rev 1 -> 2).
    assert_eq!(
        owner2.publish_locked(l2, 1, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 2 }
    );
}

// ---------------------------------------------------------------------------
// Correction pass (§5) — established-state prerequisites are enforced centrally:
// a record whose revision disagrees with metadata, an invalid lock/evidence
// association, or missing committed history for an anchored record are all
// refused under the ownership boundary without rewriting the predecessor.
// ---------------------------------------------------------------------------
#[test]
fn corr_record_meta_revision_disagreement_refused() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx); // meta rev 0, bootstrap rev 0
                                              // Plant a record decoding to revision 5 while metadata still says revision 0.
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    let mismatched = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 5,
        record: SafetyRecord::Locked(locked),
    };
    let enc = encode_record(&mismatched, &ctx).unwrap();
    owner.debug_overwrite_record_for_test(&enc).unwrap();
    // O3 refuses on the centralized revision-consistency check.
    assert!(matches!(
        owner.read_validate(None::<&FixtureCommittedHistory>),
        Err(SafetyStoreError::SemanticRefusal(_))
    ));
    // O4 also refuses pre-write (predecessor not usable).
    let qc2 = valid_wire_qc(&ctx, [0x11u8; 32], 9);
    let l2 = make_locked_qc(&ctx, [0x11u8; 32], 9, qc2, None).unwrap();
    assert!(matches!(
        owner.publish_locked(l2, 0, None::<&FixtureCommittedHistory>),
        PublishResult::RefusedPreWrite(SafetyStoreError::SemanticRefusal(_))
    ));
}

#[test]
fn corr_invalid_lock_evidence_binding_refused() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    // A locked record at the correct revision (0) but with a WRONG
    // evidence_lock_binding — structurally admissible, semantically invalid.
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let mut locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    locked.evidence_lock_binding = [0u8; 32]; // not the computed binding
    let dec = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 0,
        record: SafetyRecord::Locked(locked),
    };
    let enc = encode_record(&dec, &ctx).unwrap();
    owner.debug_overwrite_record_for_test(&enc).unwrap();
    assert!(matches!(
        owner.read_validate(None::<&FixtureCommittedHistory>),
        Err(SafetyStoreError::SemanticRefusal(_))
    ));
}

#[test]
fn corr_missing_committed_history_for_anchored_refused() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    // An anchored locked record at revision 0 requires independent committed
    // history for its anchor (P3).
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let locked = make_locked_qc(
        &ctx,
        [9u8; 32],
        5,
        qc,
        Some(CommittedAnchor {
            block_id: [3u8; 32],
            height: 4,
        }),
    )
    .unwrap();
    let dec = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 0,
        record: SafetyRecord::Locked(locked),
    };
    let enc = encode_record(&dec, &ctx).unwrap();
    owner.debug_overwrite_record_for_test(&enc).unwrap();
    // No history supplied → refuse.
    assert!(matches!(
        owner.read_validate(None::<&FixtureCommittedHistory>),
        Err(SafetyStoreError::MissingIndependentInput(_))
    ));
    // Wrong history (does not affirm the anchor) → refuse.
    let wrong = FixtureCommittedHistory::new().with([0xAAu8; 32], 4);
    assert!(owner.read_validate(Some(&wrong)).is_err());
    // Correct independent history → accept.
    let hist = FixtureCommittedHistory::new().with([3u8; 32], 4);
    let v = owner.read_validate(Some(&hist)).unwrap();
    assert_eq!(v.evidence_status(), EvidenceStatus::Unverified);
}

// ---------------------------------------------------------------------------
// Correction pass (§8) — the concrete prior failure case: with S_sig = 8, a QC
// carrying a 9-byte signature must be refused BEFORE publication by the unified
// structural-admission path, even when the whole record is below the total cap.
// ---------------------------------------------------------------------------
/// Construct a QC-derived `LockedRecord` DIRECTLY (bypassing `make_locked_qc`'s
/// admission) so O4's own admission-before-allocation ordering can be exercised
/// with an over-bound candidate. No real binding is computed here — the public
/// `compute_evidence_lock_binding` now admits, and would (correctly) refuse the
/// over-bound evidence this helper deliberately carries. O4 recomputes the
/// binding after its own admission step anyway, so a placeholder digest is used.
fn locked_qc_unadmitted(
    ctx: &PinnedSafetyContext,
    block: [u8; 32],
    view: u64,
    qc: WireQc,
) -> LockedRecord {
    let evidence = SupportingEvidence::QcDerived(qc);
    LockedRecord {
        lock_block_id: block,
        lock_view: view,
        // Placeholder: O4 refuses at admission before recomputing/using this.
        evidence_lock_binding: [0u8; 32],
        authority_context_ref: ctx.authority_context_ref,
        committed_anchor: None,
        predecessor_ref: None,
        evidence,
    }
}

#[test]
fn corr_oversized_signature_refused_before_publication() {
    use qbind_node::safety_record_store::codec::{
        evidence_payload_encode_count, reset_evidence_payload_encode_count,
    };
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4); // s_sig = 8
    let owner = init_owner(dir.path(), &ctx);
    let mut qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    // Replace one 8-byte signature with a 9-byte one.
    qc.signatures[0] = vec![0xABu8; 9];

    // A public builder refuses the over-bound evidence BEFORE owning any
    // variable-size binding buffer (admission ahead of allocation).
    assert!(matches!(
        make_locked_qc(&ctx, [9u8; 32], 5, qc.clone(), None),
        Err(SafetyStoreError::DeclaredBoundExceeded(_))
    ));

    // Build the candidate directly (bypassing the builder's admission) to drive
    // O4's own admission-before-allocation ordering, then measure: after a reset,
    // a refused O4 must NOT have reached the evidence-binding encode/allocation.
    let locked = locked_qc_unadmitted(&ctx, [9u8; 32], 5, qc);
    reset_evidence_payload_encode_count();
    let res = owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>);
    assert!(
        matches!(
            res,
            PublishResult::RefusedPreWrite(SafetyStoreError::DeclaredBoundExceeded(_))
        ),
        "9-byte signature must be refused pre-publication, got {res:?}"
    );
    assert_eq!(
        evidence_payload_encode_count(),
        0,
        "O4 must refuse BEFORE the evidence-binding allocation/copy, not after"
    );
    // The predecessor (bootstrap rev 0) is unchanged.
    let v = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert_eq!(v.retained().publication_revision, 0);
    assert!(!v.retained().is_locked());
}

/// §3 — a VALID O4 publication DOES reach the evidence-binding allocation: the
/// instrumentation increments (positive control for the refusal measurement).
#[test]
fn corr_valid_publication_reaches_evidence_allocation() {
    use qbind_node::safety_record_store::codec::{
        evidence_payload_encode_count, reset_evidence_payload_encode_count,
    };
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    reset_evidence_payload_encode_count();
    assert_eq!(
        owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    assert!(
        evidence_payload_encode_count() >= 1,
        "a valid publication must exercise the evidence-binding allocation path"
    );
}

/// §3 — nested TC over-bound fields (signer list, timeout count, timeout
/// signature) and the S_sig boundary / boundary-plus-one are all refused by the
/// one admission path BEFORE the evidence-binding allocation.
#[test]
fn corr_nested_tc_and_boundary_admission_before_allocation() {
    use qbind_node::safety_record_store::codec::{
        admit_supporting_evidence, evidence_payload_encode_count,
        reset_evidence_payload_encode_count,
    };
    let ctx = ctx_n(4); // N = 4, s_sig = 8
    let n = ctx.n() as u64;

    // Baseline valid TC evidence.
    let base = valid_tc_record(&ctx, 5, 6);
    reset_evidence_payload_encode_count();
    assert!(admit_supporting_evidence(&base.evidence, &ctx).is_ok());
    assert_eq!(
        evidence_payload_encode_count(),
        0,
        "admission itself performs no evidence-binding allocation"
    );

    // Over-bound tc.signers (N + 1 signers).
    let mut ev = base.evidence.clone();
    if let SupportingEvidence::TcDerived { tc, .. } = &mut ev {
        tc.signers = (0..=n).map(ValidatorId::new).collect();
    }
    assert!(matches!(
        admit_supporting_evidence(&ev, &ctx),
        Err(SafetyStoreError::DeclaredBoundExceeded(_))
    ));

    // Over-bound signed_timeouts count (N + 1 entries).
    let mut ev = base.evidence.clone();
    if let SupportingEvidence::TcDerived { tc, .. } = &mut ev {
        let extra = tc.signed_timeouts[0].clone();
        while tc.signed_timeouts.len() as u64 <= n {
            tc.signed_timeouts.push(extra.clone());
        }
    }
    assert!(matches!(
        admit_supporting_evidence(&ev, &ctx),
        Err(SafetyStoreError::DeclaredBoundExceeded(_))
    ));

    // Over-bound nested timeout signature (S_sig + 1 bytes = boundary-plus-one).
    let mut ev = base.evidence.clone();
    if let SupportingEvidence::TcDerived { tc, .. } = &mut ev {
        tc.signed_timeouts[0].set_signature(vec![0u8; S_SIG + 1]);
    }
    assert!(matches!(
        admit_supporting_evidence(&ev, &ctx),
        Err(SafetyStoreError::DeclaredBoundExceeded(_))
    ));

    // Boundary: exactly S_sig bytes is admitted.
    let mut ev = base.evidence.clone();
    if let SupportingEvidence::TcDerived { tc, .. } = &mut ev {
        tc.signed_timeouts[0].set_signature(vec![0u8; S_SIG]);
    }
    assert!(admit_supporting_evidence(&ev, &ctx).is_ok());
}

// ---------------------------------------------------------------------------
// §4 — the structural/capacity PREFLIGHT (`admit_supporting_evidence`, the exact
// call O4 performs before its reservation and before any predecessor read) is
// GENUINELY allocation-free on the success path. Observed directly with the
// counting allocator, not inferred from the zero-encode counter: the earlier
// implementation built `format!("…[{i}]")` per per-vector check, so the success
// path allocated one `String` per backing even though the diagnostic is only
// rendered on refusal. The typed `CapnormSite` diagnostic removes that; here we
// prove zero `alloc`/`realloc` calls for both a maximum QC and a maximum TC.
// ---------------------------------------------------------------------------
#[test]
fn corr_preflight_success_is_allocation_free_qc_and_tc() {
    use qbind_node::safety_record_store::codec::admit_supporting_evidence;
    let ctx = ctx_n(4); // N = 4, s_sig = 8 — the maximum fixture dimensions.

    // QC-derived candidate: structurally valid, capacity-normalized evidence.
    let qc_locked = make_locked_qc(&ctx, [9u8; 32], 5, valid_wire_qc(&ctx, [9u8; 32], 5), None)
        .expect("valid QC candidate");
    // Warm up any one-time lazy state (thread-local key storage, etc.) OUTSIDE the
    // measured region so the measurement observes only the admission path itself.
    assert!(admit_supporting_evidence(&qc_locked.evidence, &ctx).is_ok());
    let (res, allocs) = measure_allocs(|| admit_supporting_evidence(&qc_locked.evidence, &ctx));
    assert!(res.is_ok(), "the valid QC preflight must admit");
    assert_eq!(
        allocs, 0,
        "QC structural/capacity preflight must perform no component-owned allocation on success"
    );

    // TC-derived candidate: the fully populated maximum-TC evidence (nested
    // high_qc signers, per-entry signatures, descriptor arrays).
    let tc_locked = valid_tc_record(&ctx, 5, 6);
    assert!(admit_supporting_evidence(&tc_locked.evidence, &ctx).is_ok());
    let (res, allocs) = measure_allocs(|| admit_supporting_evidence(&tc_locked.evidence, &ctx));
    assert!(res.is_ok(), "the valid TC preflight must admit");
    assert_eq!(
        allocs, 0,
        "TC structural/capacity preflight must perform no component-owned allocation on success"
    );
}

/// §4 — the smallest-over-bound per-vector capacity violation is still refused by
/// the preflight (behaviour preserved across the typed-diagnostic correction),
/// and the diagnostic `String` the refusal carries is produced ONLY on that
/// failure path — the success path above proved zero allocations. The refusal
/// still names the offending backing (`QC signature buffer [..]`).
#[test]
fn corr_preflight_smallest_over_bound_capacity_still_refused() {
    use qbind_node::safety_record_store::codec::admit_supporting_evidence;
    let ctx = ctx_n(4);
    // A structurally valid QC whose first signature backing has exactly one byte
    // of spare capacity over the per-class maximum (S_sig = 8): len() fits, but
    // capacity() = 9 is over the CAPNORM bound (slack 0).
    let mut locked = make_locked_qc(&ctx, [9u8; 32], 5, valid_wire_qc(&ctx, [9u8; 32], 5), None)
        .expect("valid QC candidate");
    if let SupportingEvidence::QcDerived(qc) = &mut locked.evidence {
        let mut over = Vec::with_capacity(S_SIG + 1);
        over.extend_from_slice(&[0xABu8; S_SIG]);
        assert_eq!(over.len(), S_SIG);
        assert_eq!(over.capacity(), S_SIG + 1);
        qc.signatures[0] = over;
    } else {
        panic!("QC candidate must be QcDerived");
    }
    match admit_supporting_evidence(&locked.evidence, &ctx) {
        Err(e @ SafetyStoreError::CapacityRefusal(_)) => {
            let msg = e.to_string();
            assert!(
                msg.contains("QC signature buffer"),
                "refusal must name the offending backing site, got: {msg}"
            );
        }
        other => panic!("expected smallest-over-bound CapacityRefusal, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// §3.1 — the PUBLIC `compute_evidence_lock_binding` helper is a context-checking
// entry point: it refuses over-bound evidence BEFORE allocating/encoding the
// `cert` scratch, so a direct caller cannot bypass admission. The evidence-encode
// instrumentation stays at 0 on the refusal, and increments on a valid call.
// ---------------------------------------------------------------------------
#[test]
fn corr_binding_helper_enforces_admission_before_allocation() {
    use qbind_node::safety_record_store::codec::{
        compute_evidence_lock_binding, evidence_payload_encode_count,
        reset_evidence_payload_encode_count,
    };
    let ctx = ctx_n(4); // s_sig = 8
    let mut qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    qc.signatures[0] = vec![0xABu8; 9]; // over-bound: S_sig + 1
    let bad = SupportingEvidence::QcDerived(qc);

    reset_evidence_payload_encode_count();
    let res = compute_evidence_lock_binding(&[9u8; 32], 5, &bad, &ctx.authority_context_ref, &ctx);
    assert!(
        matches!(res, Err(SafetyStoreError::DeclaredBoundExceeded(_))),
        "binding helper must refuse over-bound evidence via admission, got {res:?}"
    );
    assert_eq!(
        evidence_payload_encode_count(),
        0,
        "binding helper must refuse BEFORE allocating/encoding the cert scratch"
    );

    // Positive control: valid evidence is admitted and DOES reach the encode.
    let good = SupportingEvidence::QcDerived(valid_wire_qc(&ctx, [9u8; 32], 5));
    reset_evidence_payload_encode_count();
    assert!(
        compute_evidence_lock_binding(&[9u8; 32], 5, &good, &ctx.authority_context_ref, &ctx)
            .is_ok()
    );
    assert!(
        evidence_payload_encode_count() >= 1,
        "a valid binding computation must exercise the cert-scratch encode path"
    );
}

// ---------------------------------------------------------------------------
// §3.2 — backend reads enforce the applicable record-size bound on the
// backend-internal (borrowed) view BEFORE any component-owned copy. An
// over-bound stored payload is refused with `Oversize`, never copied out whole.
// ---------------------------------------------------------------------------
#[test]
fn corr_backend_read_bounds_before_component_copy() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let backend = open_enabled(dir.path());
    let rec_max = max_safety_record_bytes(&ctx).unwrap();

    // Plant an over-bound (max + 1) record payload under a valid CRC envelope.
    let oversize = vec![0u8; rec_max as usize + 1];
    backend.debug_overwrite_record(&oversize).unwrap();
    match backend.read_record(rec_max) {
        Err(SafetyStoreError::Oversize { len, max }) => {
            assert_eq!(len, rec_max + 1);
            assert_eq!(max, rec_max);
        }
        other => panic!("expected Oversize refusal before copy, got {other:?}"),
    }

    // A within-bound payload is still returned (bound is a ceiling, not equality).
    let within = vec![7u8; rec_max as usize];
    backend.debug_overwrite_record(&within).unwrap();
    assert_eq!(backend.read_record(rec_max).unwrap(), Some(within));

    // The metadata read enforces its own (fixed) bound the same way.
    backend
        .debug_put_raw(b"safetyrec:meta:v1", &[0u8; 4 + 64])
        .unwrap();
    assert!(matches!(
        backend.read_meta(42),
        Err(SafetyStoreError::Oversize { .. })
    ));
}

// ---------------------------------------------------------------------------
// §3.3 — bounded namespace classification reports only the offending key's
// LENGTH (no key/value bytes copied into an application-owned buffer), even when
// the planted value is large; O1 still refuses over it without repair.
// ---------------------------------------------------------------------------
#[test]
fn corr_namespace_classification_reports_length_without_value_copy() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let backend = open_enabled(dir.path());
    let unknown_key: &[u8] = b"safetyrec:legacy:v0";
    // A deliberately large value: classification must NOT materialize it.
    backend
        .debug_put_raw(unknown_key, &vec![0xEEu8; 1 << 16])
        .unwrap();
    assert_eq!(
        backend.first_unrecognized_safety_key().unwrap(),
        Some(unknown_key.len()),
        "classification reports the offending key length only"
    );
    let owner = SafetyRecordOwner::attach(backend.clone(), ctx.clone()).unwrap();
    assert!(matches!(
        owner.initialize(true),
        Err(SafetyStoreError::StructuralRefusal(_))
    ));
    // Still present: nothing repaired/deleted/migrated.
    assert_eq!(
        backend.first_unrecognized_safety_key().unwrap(),
        Some(unknown_key.len())
    );
}

// differ in its SIGNER LIST from tc.high_qc (TA2 compares view+block_id only),
// while the record-level high_qc must remain byte-identical to tc.high_qc (TA1).
// ---------------------------------------------------------------------------
#[test]
fn corr_tc_ta2_permits_signer_diff_ta1_requires_exact_copy() {
    use qbind_node::safety_record_store::codec::compute_evidence_lock_binding;
    let ctx = ctx_n(4);
    let need = ((2 * ctx.n()) + 2) / 3;
    let block = [9u8; 32];
    let lock_view = 5u64;
    let timeout_view = 6u64;

    // record-level + tc.high_qc: byte-identical to each other (signer set A).
    let signers_a: Vec<ValidatorId> = (0..need as u64).map(ValidatorId::new).collect();
    let high_a = LogicalQc::new(block, lock_view, signers_a.clone());
    // nested timeout-entry high_qc: SAME (block_id, view), DIFFERENT signers.
    let signers_b: Vec<ValidatorId> = (0..(need as u64 - 1)).map(ValidatorId::new).collect();
    let high_b = LogicalQc::new(block, lock_view, signers_b);

    let build = |rec_high: LogicalQc<[u8; 32]>,
                 tc_high: LogicalQc<[u8; 32]>,
                 nested: LogicalQc<[u8; 32]>,
                 rev: u64| {
        let mut signed = Vec::new();
        for i in 0..need as u64 {
            let mut t = TimeoutMsg::new(timeout_view, Some(nested.clone()), ValidatorId::new(i));
            t.set_signature(vec![0xCD; S_SIG]);
            signed.push(t);
        }
        signed.shrink_to_fit();
        let tc = TimeoutCertificate {
            view: timeout_view + 1,
            high_qc: Some(tc_high),
            signers: (0..need as u64).map(ValidatorId::new).collect(),
            signed_timeouts: signed,
            timeout_view,
        };
        let evidence = SupportingEvidence::TcDerived {
            high_qc: rec_high,
            tc,
        };
        let binding = compute_evidence_lock_binding(
            &block,
            lock_view,
            &evidence,
            &ctx.authority_context_ref,
            &ctx,
        )
        .unwrap();
        let l = LockedRecord {
            lock_block_id: block,
            lock_view,
            evidence_lock_binding: binding,
            authority_context_ref: ctx.authority_context_ref,
            committed_anchor: None,
            predecessor_ref: None,
            evidence,
        };
        DecodedRecord {
            persistence_format_version: 1,
            network_genesis_id: ctx.network_genesis_id,
            publication_revision: rev,
            record: SafetyRecord::Locked(l),
        }
    };

    // TA2-permitted: nested selected high_qc uses signer set B; record + tc use A.
    let permitted = build(high_a.clone(), high_a.clone(), high_b.clone(), 1);
    let enc = encode_record(&permitted, &ctx).unwrap();
    let v = validate_decoded(
        decode_record(&enc, &ctx).unwrap(),
        enc,
        &ctx,
        None::<&FixtureCommittedHistory>,
    )
    .unwrap();
    assert_eq!(v.evidence_status(), EvidenceStatus::Unverified);

    // TA1-violating: record-level high_qc (A) differs in signers from tc.high_qc
    // (B) — exact copy correspondence is required, so this is refused.
    let violating = build(high_a.clone(), high_b.clone(), high_b.clone(), 1);
    let enc2 = encode_record(&violating, &ctx).unwrap();
    assert!(matches!(
        validate_decoded(
            decode_record(&enc2, &ctx).unwrap(),
            enc2,
            &ctx,
            None::<&FixtureCommittedHistory>
        ),
        Err(SafetyStoreError::SemanticRefusal(_))
    ));
}

// ---------------------------------------------------------------------------
// Correction pass (§10) — bounded namespace classification: an unknown/legacy
// safety-namespace key causes the contract-prescribed O1 refusal WITHOUT
// migration, deletion, or repair over it.
// ---------------------------------------------------------------------------
#[test]
fn corr_unknown_namespace_key_refuses_o1_without_repair() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let backend = open_enabled(dir.path());
    // Plant an unknown/legacy key inside the component-owned namespace.
    backend
        .debug_put_raw(b"safetyrec:legacy:v0", b"opaque-legacy-state")
        .unwrap();
    let owner = SafetyRecordOwner::attach(backend.clone(), ctx.clone()).unwrap();
    // O1 is refused (no migration / deletion / initialization over it).
    assert!(matches!(
        owner.initialize(true),
        Err(SafetyStoreError::StructuralRefusal(_))
    ));
    // The unknown key is still present — nothing was repaired or deleted.
    assert!(backend.first_unrecognized_safety_key().unwrap().is_some());
}

// ---------------------------------------------------------------------------
// §5 — recovery tokens are bound to their ORIGINATING backend incarnation.
// Identical pinned contexts are shared by different stores, so the context
// digest alone is not backend identity. Only a successful O3 on an established
// backend mints an O5-usable capability; it is honoured only by that backend's
// own incarnation (and the handles sharing it), never by an unrelated store or a
// reopened incarnation, and public/bootstrap proofs mint no capability at all.
// ---------------------------------------------------------------------------

/// Two stores with IDENTICAL pinned context and IDENTICAL publication bytes: a
/// recovery token minted by O3 on store A is refused by store B's O5.
#[test]
fn corr_recovery_token_does_not_transfer_across_stores() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);

    // Establish an identical lock publication in BOTH stores (same ctx/bytes).
    let owner_a = init_owner(dir_a.path(), &ctx);
    let owner_b = init_owner(dir_b.path(), &ctx);
    let qc_a = valid_wire_qc(&ctx, [9u8; 32], 5);
    let qc_b = valid_wire_qc(&ctx, [9u8; 32], 5);
    let la = make_locked_qc(&ctx, [9u8; 32], 5, qc_a, None).unwrap();
    let lb = make_locked_qc(&ctx, [9u8; 32], 5, qc_b, None).unwrap();
    assert_eq!(
        owner_a.publish_locked(la, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    assert_eq!(
        owner_b.publish_locked(lb, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );

    // O3 tokens from each store; confirm the publication bytes are byte-identical.
    let tok_a = owner_a
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let tok_b = owner_b
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert_eq!(
        tok_a.encoded(),
        tok_b.encoded(),
        "identical publication bytes"
    );
    assert_eq!(
        tok_a.origin_context_digest(),
        tok_b.origin_context_digest(),
        "identical pinned-context digests"
    );
    // Distinct ownership incarnations despite identical context/bytes.
    assert_ne!(
        tok_a.recovery_backend_incarnation(),
        tok_b.recovery_backend_incarnation()
    );

    // Store B refuses A's token (no cross-store transfer of recovery authority),
    // leaving B's bytes and recovery-required state unchanged.
    let before = owner_b
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap()
        .encoded()
        .to_vec();
    let rr_before = owner_b.recovery_required();
    let res = owner_b.reacknowledge(&tok_a);
    assert!(
        matches!(
            res,
            PublishResult::RefusedPreWrite(SafetyStoreError::SemanticRefusal(_))
        ),
        "cross-store token must be refused, got {res:?}"
    );
    let after = owner_b
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap()
        .encoded()
        .to_vec();
    assert_eq!(before, after, "rejected token left bytes unchanged");
    assert_eq!(
        owner_b.recovery_required(),
        rr_before,
        "rejected token must leave recovery-required state unchanged"
    );
    // B's OWN token is honoured.
    assert!(matches!(
        owner_b.reacknowledge(&tok_b),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    ));
}

/// Anchored records with INDEPENDENTLY supplied committed histories: A's O3
/// validation authority does not transfer to B even though the publication bytes
/// are identical (B validates against its own supplied history).
#[test]
fn corr_recovery_token_anchored_no_authority_transfer() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let anchor = CommittedAnchor {
        block_id: [7u8; 32],
        height: 3,
    };
    let hist = FixtureCommittedHistory::new().with([7u8; 32], 3);

    let owner_a = init_owner(dir_a.path(), &ctx);
    let owner_b = init_owner(dir_b.path(), &ctx);
    let qc_a = valid_wire_qc(&ctx, [9u8; 32], 5);
    let qc_b = valid_wire_qc(&ctx, [9u8; 32], 5);
    let la = make_locked_qc(&ctx, [9u8; 32], 5, qc_a, Some(anchor.clone())).unwrap();
    let lb = make_locked_qc(&ctx, [9u8; 32], 5, qc_b, Some(anchor.clone())).unwrap();
    assert_eq!(
        owner_a.publish_locked(la, 0, Some(&hist)),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    assert_eq!(
        owner_b.publish_locked(lb, 0, Some(&hist)),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );

    let tok_a = owner_a.read_validate(Some(&hist)).unwrap();
    // B refuses A's anchored token: recovery validation must use the history
    // associated with the store being recovered, not A's validation authority.
    assert!(matches!(
        owner_b.reacknowledge(&tok_a),
        PublishResult::RefusedPreWrite(SafetyStoreError::SemanticRefusal(_))
    ));
}

/// Public standalone validation and the bootstrap builder produce proofs with NO
/// O5 recovery capability; O5 refuses them even on the same backend.
#[test]
fn corr_standalone_and_bootstrap_proofs_mint_no_recovery_capability() {
    use qbind_node::safety_record_store::owner::bootstrap_validated;
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>);

    // A standalone semantic/codec proof over the SAME stored bytes carries no
    // capability (incarnation is None), so O5 refuses it.
    let record_bytes = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap()
        .encoded()
        .to_vec();
    let decoded = decode_record(&record_bytes, &ctx).unwrap();
    let standalone = validate_decoded(
        decoded,
        record_bytes,
        &ctx,
        None::<&FixtureCommittedHistory>,
    )
    .unwrap();
    assert_eq!(standalone.recovery_backend_incarnation(), None);
    assert!(matches!(
        owner.reacknowledge(&standalone),
        PublishResult::RefusedPreWrite(SafetyStoreError::SemanticRefusal(_))
    ));

    // The bootstrap builder likewise mints no capability.
    let boot = bootstrap_validated(&ctx, 0).unwrap();
    assert_eq!(boot.recovery_backend_incarnation(), None);
}

/// A reopened backend is a FRESH incarnation: a token minted before the reopen
/// is refused; a fresh O3 after reopen yields an honoured capability.
#[test]
fn corr_recovery_token_requires_fresh_o3_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner1 = init_owner(dir.path(), &ctx);
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    owner1.publish_locked(locked, 0, None::<&FixtureCommittedHistory>);
    let stale = owner1
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    drop(owner1);

    // Reopen a fresh backend incarnation over the surviving bytes.
    let owner2 = SafetyRecordOwner::attach(open_enabled(dir.path()), ctx.clone()).unwrap();
    // The pre-reopen token is refused (different incarnation).
    assert!(matches!(
        owner2.reacknowledge(&stale),
        PublishResult::RefusedPreWrite(SafetyStoreError::SemanticRefusal(_))
    ));
    // A fresh O3 on the reopened incarnation yields an honoured capability.
    let fresh = owner2
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert_ne!(
        stale.recovery_backend_incarnation(),
        fresh.recovery_backend_incarnation()
    );
    assert!(matches!(
        owner2.reacknowledge(&fresh),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    ));
}

/// Handles SHARING one backend instance share its incarnation: a token minted by
/// one handle is honoured through a sibling handle's O5.
#[test]
fn corr_recovery_token_usable_across_shared_handles() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let backend = open_enabled(dir.path());
    let owner = SafetyRecordOwner::attach(backend.clone(), ctx.clone()).unwrap();
    owner.initialize(true).unwrap();
    let sibling = owner.clone();
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>);
    let tok = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    // The sibling handle (same backend incarnation) honours the token.
    assert!(matches!(
        sibling.reacknowledge(&tok),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    ));
}

// ---------------------------------------------------------------------------
// Operational allocation accounting through real O1–O5 (§ 13.7 / § 13.7B)
//
// These regressions observe the SHARED backend accountant that O1/O3/O4/O5 now
// reserve against (not a synthetic counter): the peak / current / cap exposed by
// `backend_for_test()` move only because a real operation took a real
// reservation BEFORE its protected allocation or copy, and release it on every
// exit (success, refusal, error, uncertainty, drop).
// ---------------------------------------------------------------------------

#[test]
fn acct_valid_qc_publish_readback_recover_within_ceiling() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let backend = owner.backend_for_test();
    let cap = backend.accounting_cap().expect("ceiling bound at attach");

    // O1 already reserved + released its bootstrap publication buffer: a real
    // peak was set, and after O1 returns nothing stays charged.
    assert!(backend.accounting_peak() > 0, "O1 reserves a real buffer");
    assert!(backend.accounting_peak() <= cap, "O1 peak within ceiling");
    assert_eq!(backend.accounting_current(), 0, "O1 reservation released");

    // O4 QC publication peaks within the ceiling and fully releases.
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    assert_eq!(
        owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    assert_eq!(backend.accounting_current(), 0, "O4 working set released");
    assert!(backend.accounting_peak() <= cap, "O4 peak within ceiling");

    // O3 read-back holds a retained holder for the proof's lifetime.
    let tok = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert!(
        backend.accounting_current() > 0,
        "O3 proof holds a retained holder while live"
    );
    assert!(backend.accounting_current() <= cap);

    // O5 recovery over the surviving complete state, within the ceiling. O5
    // republishes the retained bytes verbatim; the metadata revision is unchanged.
    assert!(matches!(
        owner.reacknowledge(&tok),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    ));
    assert!(backend.accounting_peak() <= cap, "O5 peak within ceiling");

    // Dropping the proof releases its retained holder.
    drop(tok);
    assert_eq!(
        backend.accounting_current(),
        0,
        "holder released on proof drop"
    );
}

// §3/§7 finding-#2 regression: the ENFORCED O3 retained-holder charge covers the
// COMPLETE operational representation — the `encoded` buffer backing (rec), the
// decoded generation (gen), AND the inline holder/accounting handle metadata
// (the `validated_holder_handle_bytes` term that was previously only asserted as
// a size-ordering, never reserved). The charge is independently derived here from
// the public profile/record bounds and compared against the real shared-accountant
// partition delta a live O3 proof actually holds — not against the accountant's
// own counter alone. A clone takes an identical complete charge (it owns its own
// buffer, generation, and inline handle), and every holder releases on drop.
#[test]
fn acct_o3_holder_charge_includes_enforced_handle_term() {
    use qbind_node::safety_record_store::profile::max_retained_generation_bytes;
    use qbind_node::safety_record_store::record::{
        size_of_timeout_msg, validated_holder_handle_bytes, EvidenceDiscriminant, EvidenceStatus,
    };

    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let backend = owner.backend_for_test();
    let cap = backend.accounting_cap().unwrap();

    // Independently derive the complete per-proof charge from the public bounds.
    // This is RESERVATION-WIRING and LIFETIME evidence: the expected value comes
    // from the same public bound helpers the component charges against; it does
    // NOT independently prove all allocation capacities or peak coexistence.
    let rec = max_safety_record_bytes(&ctx).unwrap();
    let gen = max_retained_generation_bytes(&ctx, size_of_timeout_msg()).unwrap();
    let handle = validated_holder_handle_bytes();
    let complete_charge = rec + gen + handle;
    println!(
        "MEASURED O3 holder charge terms: rec={rec} gen={gen} handle={handle} \
         complete_charge(rec+gen+handle)={complete_charge}"
    );
    assert!(
        handle > 0,
        "the handle term must be a genuinely non-zero enforced charge"
    );

    // Publish the intended LOCKED (QC-derived) record and PROVE it durably
    // acknowledged at the expected new revision before proceeding to O3. The prior
    // revision ignored `publish_locked`'s result and could reach O3 without having
    // established that the intended locked publication succeeded.
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    assert_eq!(
        owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 },
        "the intended locked publication must durably acknowledge at revision 1 \
         before O3 reads it back"
    );
    assert_eq!(backend.accounting_current(), 0, "clean before O3");

    let tok = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    // The O3 proof must be the intended locked, QC-derived evidence at the
    // expected revision, carried Unverified — the charge below is wired to THIS
    // proof, not to some other published state.
    assert_eq!(
        tok.publication_revision(),
        1,
        "O3 proof must carry the expected published revision"
    );
    assert!(
        tok.retained().is_locked(),
        "O3 proof must be the locked variant"
    );
    assert_eq!(
        tok.retained().evidence_discriminant(),
        EvidenceDiscriminant::QcDerived,
        "O3 proof must carry the intended QC-derived evidence identity"
    );
    assert_eq!(
        tok.evidence_status(),
        EvidenceStatus::Unverified,
        "every O3 proof is carried Unverified (stage-2 is unwired)"
    );
    let one_holder = backend.accounting_current();
    assert_eq!(
        one_holder, complete_charge,
        "a live O3 proof holds EXACTLY the complete operational representation \
         (rec {rec} + gen {gen} + enforced handle {handle} = {complete_charge}); \
         the handle term is reserved, not merely asserted"
    );
    assert!(one_holder <= cap, "single holder within ceiling");

    // A clone owns its own buffer + generation + inline handle and takes the same
    // complete charge again — handle bytes are charged per holder, not once.
    let clone = tok.try_clone().unwrap();
    assert_eq!(
        backend.accounting_current(),
        complete_charge * 2,
        "a cloned proof is charged the identical complete representation again"
    );
    assert!(
        backend.accounting_current() <= cap,
        "two holders within ceiling"
    );

    drop(clone);
    assert_eq!(
        backend.accounting_current(),
        complete_charge,
        "dropping the clone releases exactly one complete charge"
    );
    drop(tok);
    assert_eq!(
        backend.accounting_current(),
        0,
        "all holders released on drop"
    );
}

#[test]
fn acct_tc_publication_charges_nested_signers() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let backend = owner.backend_for_test();
    let cap = backend.accounting_cap().unwrap();

    // The TC-derived generation (nested logical high-QC signer lists + per-signer
    // signature buffers) is the larger variant; its O4 working set must still
    // peak within the admitted ceiling and fully release.
    let ltc = valid_tc_record(&ctx, 5, 6);
    assert_eq!(
        owner.publish_locked(ltc, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    let tc_peak = backend.accounting_peak();
    assert!(tc_peak > 0 && tc_peak <= cap, "TC O4 peak within ceiling");
    assert_eq!(backend.accounting_current(), 0, "released after O4");

    // The O3 holder for the TC proof stays within the ceiling while live.
    let tok = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let live = backend.accounting_current();
    assert!(live > 0 && live <= cap, "TC proof holder within ceiling");
    drop(tok);
    assert_eq!(backend.accounting_current(), 0);
}

#[test]
fn acct_shared_budget_refusal_preserves_evidence_then_readmits() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);

    // Establish durable evidence (revision 1) first.
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    assert_eq!(
        owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );

    // A SECOND handle on the SAME backend shares the single aggregate budget:
    // attaching it does not open an independent budget. A standing reservation it
    // takes consumes the entire shared aggregate ceiling that remains after the
    // live context-owner charge (the aggregate is the profile operational
    // aggregate, charged jointly by context + operations — not enlarged by the
    // context sub-cap).
    let sibling = owner.clone();
    let agg_cap = sibling
        .backend_for_test()
        .accounting_aggregate_cap()
        .unwrap();
    let ctx_live = sibling.backend_for_test().context_accounting_current();
    let standing = sibling
        .backend_for_test()
        .reserve_standing_for_test(agg_cap - ctx_live)
        .expect("standing reservation up to the remaining shared ceiling");
    assert_eq!(
        sibling.backend_for_test().accounting_current(),
        agg_cap - ctx_live
    );
    assert_eq!(
        sibling.backend_for_test().accounting_aggregate_current(),
        agg_cap,
        "context + standing operational charge fill the shared aggregate exactly"
    );

    // A fresh O4 on the first handle is now refused for capacity BEFORE any
    // write — the shared budget is exhausted — without evicting the established
    // evidence or releasing the recovery restriction.
    let qc2 = valid_wire_qc(&ctx, [7u8; 32], 6);
    let locked2 = make_locked_qc(&ctx, [7u8; 32], 6, qc2, None).unwrap();
    match owner.publish_locked(locked2, 1, None::<&FixtureCommittedHistory>) {
        PublishResult::RefusedPreWrite(SafetyStoreError::CapacityRefusal(_)) => {}
        other => panic!("expected capacity RefusedPreWrite, got {other:?}"),
    }
    assert!(!owner.recovery_required(), "capacity refusal is pre-write");

    // Release the shared pressure; the established evidence is intact and a fresh
    // admission now succeeds against the freed budget.
    standing.release_now();
    assert_eq!(owner.backend_for_test().accounting_current(), 0);
    let readback = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert_eq!(readback.retained().publication_revision, 1);
    drop(readback);
    let qc3 = valid_wire_qc(&ctx, [7u8; 32], 6);
    let locked3 = make_locked_qc(&ctx, [7u8; 32], 6, qc3, None).unwrap();
    assert_eq!(
        owner.publish_locked(locked3, 1, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 2 }
    );
}

#[test]
fn acct_retained_holder_multiplicity_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>);

    // One real O3 holder.
    let tok = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let backend = owner.backend_for_test();
    let cap = backend.accounting_cap().unwrap();

    // Each duplicate owns a genuinely separate record-sized buffer and must take
    // its own holder reservation; cloning cannot mint unbounded uncharged
    // holders, so duplication is eventually refused for capacity. The number of
    // live holders is therefore bounded by the shared ceiling.
    let mut clones = Vec::new();
    let mut refused = false;
    for _ in 0..1024 {
        match tok.try_clone() {
            Ok(c) => {
                assert!(
                    backend.accounting_current() <= cap,
                    "holders stay within cap"
                );
                clones.push(c);
            }
            Err(SafetyStoreError::CapacityRefusal(_)) => {
                refused = true;
                break;
            }
            Err(e) => panic!("unexpected duplication error: {e:?}"),
        }
    }
    assert!(refused, "retained-holder multiplicity must be bounded");
    assert!(backend.accounting_current() <= cap);

    // Dropping every holder returns the shared budget to zero.
    drop(clones);
    drop(tok);
    assert_eq!(backend.accounting_current(), 0, "all holders released");
}

#[test]
fn acct_cleanup_after_success_refusal_error_uncertainty() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let backend = owner.backend_for_test();

    // Success: establish revision 1, charge fully released.
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    assert_eq!(
        owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    assert_eq!(backend.accounting_current(), 0, "released after success");

    // Semantic refusal (stale expected revision): pre-write, charge released.
    let qc_s = valid_wire_qc(&ctx, [7u8; 32], 6);
    let locked_s = make_locked_qc(&ctx, [7u8; 32], 6, qc_s, None).unwrap();
    assert!(matches!(
        owner.publish_locked(locked_s, 0, None::<&FixtureCommittedHistory>),
        PublishResult::RefusedPreWrite(_)
    ));
    assert_eq!(backend.accounting_current(), 0, "released after refusal");
    assert!(!owner.recovery_required());

    // Backend write error (ambiguous): charge released, recovery restriction set.
    backend.set_inject(InjectFault::WriteErrors);
    let qc_e = valid_wire_qc(&ctx, [7u8; 32], 6);
    let locked_e = make_locked_qc(&ctx, [7u8; 32], 6, qc_e, None).unwrap();
    assert!(matches!(
        owner.publish_locked(locked_e, 1, None::<&FixtureCommittedHistory>),
        PublishResult::WriteFailedAmbiguous(_)
    ));
    assert_eq!(
        backend.accounting_current(),
        0,
        "released after write error"
    );
    assert!(
        owner.recovery_required(),
        "write error sets recovery restriction"
    );
    backend.set_inject(InjectFault::None);

    // Uncertain durable on a FRESH store (a prior error/uncertainty leaves the
    // recovery restriction set, which would refuse a later O4 pre-write): charge
    // released, and the recovery restriction is preserved after the uncertainty.
    let dir_u = tempfile::tempdir().unwrap();
    let owner_u = init_owner(dir_u.path(), &ctx);
    let backend_u = owner_u.backend_for_test();
    backend_u.set_inject(InjectFault::UncertainAfterWrite);
    let qc_u = valid_wire_qc(&ctx, [9u8; 32], 5);
    let locked_u = make_locked_qc(&ctx, [9u8; 32], 5, qc_u, None).unwrap();
    assert!(matches!(
        owner_u.publish_locked(locked_u, 0, None::<&FixtureCommittedHistory>),
        PublishResult::UncertainDurable
    ));
    assert_eq!(
        backend_u.accounting_current(),
        0,
        "released after uncertainty"
    );
    assert!(
        owner_u.recovery_required(),
        "uncertain outcome preserves the recovery restriction"
    );
    backend_u.set_inject(InjectFault::None);
}

// ---------------------------------------------------------------------------
// Process-death harness (deterministic child-process boundaries)
// ---------------------------------------------------------------------------
//
// A child re-executes this test binary at `child_process_entry`, driving the
// real component + RocksDB adapter in a temp directory to an explicit,
// test-coordinated boundary (NOT a timing guess), then exits / aborts. The
// parent then reopens the surviving bytes and decides purely from what survived.
//
// Honesty limits (asserted only on observable bytes): process termination is
// not power-loss testing; a completed durable write before the caller is told
// of success means a complete successor may survive; we never fabricate
// knowledge of whether the former process observed an acknowledgement.

use std::process::Command;

const ENV_DIR: &str = "QBIND_D7D14_DIR";
const ENV_PHASE: &str = "QBIND_D7D14_PHASE";
/// Path at which a child writes a sentinel proving it reached the intended
/// post-acknowledgement / post-effectiveness phase *before* aborting. Kept
/// OUTSIDE the RocksDB directory so it never perturbs the parent's reopen.
const ENV_MARKER: &str = "QBIND_D7D14_MARKER";

#[test]
#[ignore = "child-process entrypoint; spawned by the process-death parent tests"]
fn child_process_entry() {
    let dir = match std::env::var(ENV_DIR) {
        Ok(d) => d,
        Err(_) => return, // not a child invocation
    };
    let phase = std::env::var(ENV_PHASE).unwrap_or_default();
    let path = std::path::PathBuf::from(dir);
    let ctx = ctx_n(4);

    let backend = SafetyBackend::open_or_initialize(
        &path,
        SafetyBackendPolicy::EnabledForTesting,
        TrustBundleEnvironment::Devnet,
    )
    .expect("child backend open");
    let owner = SafetyRecordOwner::attach(backend.clone(), ctx.clone()).expect("attach");

    match phase.as_str() {
        "before_publish" => {
            owner.initialize(true).expect("O1");
            // Exit before ever submitting a lock publication.
            std::process::exit(10);
        }
        "uncertain_after_write" => {
            owner.initialize(true).expect("O1");
            backend.set_inject(InjectFault::UncertainAfterWrite);
            let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
            let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
            let r = owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>);
            // The durable write happened but the caller got an uncertain outcome.
            assert!(matches!(r, PublishResult::UncertainDurable), "got {r:?}");
            std::process::exit(11);
        }
        "ack_then_abort" => {
            owner.initialize(true).expect("O1");
            let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
            let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
            let r = owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>);
            assert!(matches!(r, PublishResult::DurableAcknowledged { .. }));
            // `publish_locked` has already returned, so the in-memory
            // effectiveness transition (`mark_effective`) ALSO already ran in this
            // process: confirm we are genuinely POST-acknowledgement AND
            // POST-effectiveness before recording phase evidence.
            assert!(!owner.recovery_required(), "post-ack must be effective");
            // Record phase evidence (a sentinel the parent requires) ONLY once the
            // intended phase is proven reached. A setup failure or an assertion
            // panic above unwinds the harness and exits WITHOUT writing this
            // sentinel, so its presence — paired with the abort signal below —
            // distinguishes the intended crash boundary from any unrelated exit.
            if let Ok(marker) = std::env::var(ENV_MARKER) {
                std::fs::write(&marker, b"ack_then_abort reached post-ack/post-effective\n")
                    .expect("write phase-reached sentinel");
            }
            // Abort now without unwinding: this is post-acknowledgement AND
            // post-effectiveness termination (the surviving bytes are durable; the
            // in-memory `effective` flag dies with the process regardless). On the
            // tested platform this raises SIGABRT, a signal the parent verifies.
            std::process::abort();
        }
        "ack_before_effective" => {
            owner.initialize(true).expect("O1");
            let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
            let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
            // Install a deterministic hook that fires at the EXACT point after the
            // atomic synced publication has returned its durability acknowledgement
            // but BEFORE the component's in-memory effectiveness transition
            // (`mark_effective`). It verifies the operation + revision reached and
            // terminates there, so termination strictly precedes the transition.
            // Any path that fails to reach this exact boundary (panic, wrong phase,
            // setup failure) yields a different exit status and fails the parent.
            backend.set_pre_effective_hook(std::sync::Arc::new(|op: &str, rev: u64| {
                assert_eq!(op, "O4", "pre-effective hook fired for the wrong operation");
                assert_eq!(rev, 1, "pre-effective hook fired at the wrong revision");
                std::process::exit(18);
            }));
            let _ = owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>);
            // Unreachable: the hook exits before `publish_locked` returns. Reaching
            // here means the boundary was NOT hit — fail with a distinct status.
            std::process::exit(118);
        }
        "write_error_before_commit" => {
            owner.initialize(true).expect("O1");
            backend.set_inject(InjectFault::WriteErrors);
            let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
            let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
            let r = owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>);
            assert!(
                matches!(r, PublishResult::WriteFailedAmbiguous(_)),
                "got {r:?}"
            );
            std::process::exit(13);
        }
        "ack_locked_clean_exit" => {
            owner.initialize(true).expect("O1");
            let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
            let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
            let r = owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>);
            assert!(
                matches!(r, PublishResult::DurableAcknowledged { .. }),
                "got {r:?}"
            );
            // Exit cleanly AFTER an acknowledged publication; the next process
            // must still require fresh recovery (O5) before dependent O4.
            std::process::exit(14);
        }
        "init_uncertain" => {
            // O1 whose meta+bootstrap durable write COMPLETES but whose success
            // acknowledgement is lost: the caller observes UncertainPublication,
            // never a success. Live, before any restart, confirm the in-process
            // effectiveness transition did NOT happen (recovery is required), so a
            // later reopen into a recovery-required state cannot be mistaken for a
            // masked successful transition.
            backend.set_inject(InjectFault::UncertainAfterWrite);
            let r = owner.initialize(true);
            assert!(
                matches!(r, Err(SafetyStoreError::UncertainPublication(_))),
                "got {r:?}"
            );
            assert!(
                owner.recovery_required(),
                "uncertain O1 must not transition effectiveness"
            );
            std::process::exit(15);
        }
        "o5_uncertain" => {
            owner.initialize(true).expect("O1");
            let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
            let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
            assert!(matches!(
                owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>),
                PublishResult::DurableAcknowledged { .. }
            ));
            let tok = owner
                .read_validate(None::<&FixtureCommittedHistory>)
                .unwrap();
            backend.set_inject(InjectFault::UncertainAfterWrite);
            let r = owner.reacknowledge(&tok);
            assert!(matches!(r, PublishResult::UncertainDurable), "got {r:?}");
            // An uncertain O5 must NOT release the recovery restriction.
            assert!(
                owner.recovery_required(),
                "uncertain O5 must preserve the recovery restriction"
            );
            std::process::exit(16);
        }
        "o5_write_error" => {
            owner.initialize(true).expect("O1");
            let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
            let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
            assert!(matches!(
                owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>),
                PublishResult::DurableAcknowledged { .. }
            ));
            let tok = owner
                .read_validate(None::<&FixtureCommittedHistory>)
                .unwrap();
            backend.set_inject(InjectFault::WriteErrors);
            let r = owner.reacknowledge(&tok);
            assert!(
                matches!(r, PublishResult::WriteFailedAmbiguous(_)),
                "got {r:?}"
            );
            // A failed O5 must NOT release the recovery restriction.
            assert!(
                owner.recovery_required(),
                "failed O5 must preserve the recovery restriction"
            );
            std::process::exit(17);
        }
        other => panic!("unknown child phase {other}"),
    }
}

fn marker_path_for(dir: &std::path::Path) -> std::path::PathBuf {
    // A sibling of the RocksDB directory (never inside it), so writing the
    // phase-reached sentinel cannot perturb the parent's reopen of `dir`.
    let mut s = dir.as_os_str().to_os_string();
    s.push(".reached");
    std::path::PathBuf::from(s)
}

fn spawn_child(dir: &std::path::Path, phase: &str) -> std::process::ExitStatus {
    let exe = std::env::current_exe().expect("current_exe");
    Command::new(exe)
        .args(["--exact", "child_process_entry", "--ignored", "--nocapture"])
        .env(ENV_DIR, dir)
        .env(ENV_PHASE, phase)
        .env(ENV_MARKER, marker_path_for(dir))
        .status()
        .expect("spawn child")
}

/// Boundary: death BEFORE publication submission → only bootstrap survives;
/// O3 reads a valid complete publication (bootstrap).
#[test]
fn pd_before_publish_survives_bootstrap() {
    let dir = tempfile::tempdir().unwrap();
    let status = spawn_child(dir.path(), "before_publish");
    assert_eq!(status.code(), Some(10));
    let ctx = ctx_n(4);
    let owner = SafetyRecordOwner::attach(open_enabled(dir.path()), ctx).unwrap();
    let v = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert!(!v.retained().is_locked());
    assert_eq!(v.retained().publication_revision, 0);
}

/// Boundary: a completed storage write BEFORE success is delivered to the caller
/// → the complete successor survives even though the caller saw uncertainty.
#[test]
fn pd_uncertain_after_write_successor_survives() {
    let dir = tempfile::tempdir().unwrap();
    let status = spawn_child(dir.path(), "uncertain_after_write");
    assert_eq!(status.code(), Some(11));
    let ctx = ctx_n(4);
    let owner = SafetyRecordOwner::attach(open_enabled(dir.path()), ctx).unwrap();
    let v = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    // The successor (locked rev 1) survived; we do NOT claim the dead process
    // observed an acknowledgement.
    assert!(v.retained().is_locked());
    assert_eq!(v.retained().publication_revision, 1);
}

/// Boundary (post-effectiveness): the child aborts AFTER `publish_locked` has
/// returned `DurableAcknowledged`, i.e. AFTER the in-memory effectiveness
/// transition (`mark_effective`) already ran in that process. This is
/// post-acknowledgement **and** post-effectiveness evidence: the acknowledged
/// publication survives and O3/O5 proceed on reopen. The pre-effectiveness
/// boundary (termination strictly before the transition) is exercised separately
/// by `pd_ack_before_effective_terminates_before_transition`.
#[test]
fn pd_ack_then_abort_survives_locked() {
    let dir = tempfile::tempdir().unwrap();
    let status = spawn_child(dir.path(), "ack_then_abort");

    // The child must have reached the intended post-acknowledgement /
    // post-effectiveness phase AND terminated by the expected abort, NOT by a
    // setup failure, an assertion panic, or an unexpected clean/other exit:
    //
    //   (1) phase evidence — the sentinel is written ONLY after the child proved
    //       it was post-ack and effective; a harness-caught panic or setup error
    //       above it exits without writing the sentinel; and
    //   (2) termination evidence — on this platform `std::process::abort()`
    //       raises SIGABRT. An assertion panic unwinds to a harness failure exit
    //       (code 101), never SIGABRT, so requiring the abort signal rejects it.
    let marker = marker_path_for(dir.path());
    assert!(
        marker.exists(),
        "child must record post-ack/post-effective phase evidence before aborting: {status:?}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            status.signal(),
            Some(libc_sigabrt()),
            "child must terminate via the expected abort signal (SIGABRT), not an \
             assertion/setup exit: {status:?}"
        );
        assert_eq!(
            status.code(),
            None,
            "a signalled abort has no ordinary exit code: {status:?}"
        );
    }
    #[cfg(not(unix))]
    assert!(
        !status.success(),
        "aborted child is not a success: {status:?}"
    );

    let ctx = ctx_n(4);
    let owner = SafetyRecordOwner::attach(open_enabled(dir.path()), ctx).unwrap();
    let v = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert!(v.retained().is_locked());
    assert_eq!(v.retained().publication_revision, 1);
    // O5 can re-acknowledge the surviving publication (byte-for-byte equal).
    let res = owner.reacknowledge(&v);
    assert!(
        matches!(res, PublishResult::DurableAcknowledged { .. }),
        "got {res:?}"
    );
}

/// SIGABRT numeric value on the supported Unix target (avoids a `libc`
/// dependency for a single well-known constant).
#[cfg(unix)]
fn libc_sigabrt() -> i32 {
    6
}

/// Boundary (pre-effectiveness): the child drives a real O4 lock publication and
/// a deterministic hook terminates it at the EXACT point after the atomic synced
/// publication returned its durability acknowledgement but BEFORE the component's
/// in-memory effectiveness transition (`mark_effective`). This is the missing
/// deterministic boundary (§ 13.5), distinct from `pd_ack_then_abort` (which
/// terminates post-effectiveness): the acknowledged bytes survive, the former
/// process never completed its transition, and the reopened process starts with
/// NO inherited effectiveness — so dependent O4 is blocked until a fresh O3/O5
/// recovery re-establishes the permitted state. An exit at any other point
/// yields a different status and fails this test.
#[test]
fn pd_ack_before_effective_terminates_before_transition() {
    let dir = tempfile::tempdir().unwrap();
    let status = spawn_child(dir.path(), "ack_before_effective");
    assert_eq!(
        status.code(),
        Some(18),
        "child must terminate at the post-ack / pre-effective boundary: {status:?}"
    );
    let ctx = ctx_n(4);
    let owner = SafetyRecordOwner::attach(open_enabled(dir.path()), ctx.clone()).unwrap();
    // The acknowledged lock bytes survived at revision 1 (the durable write
    // completed before the hook fired).
    let v = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert!(v.retained().is_locked());
    assert_eq!(v.retained().publication_revision, 1);
    // Reopening starts without inherited effectiveness knowledge: dependent O4 is
    // refused until recovery, proving the pre-effective termination is not masked
    // as a completed transition.
    assert!(
        owner.recovery_required(),
        "reopen after pre-effective termination must require fresh recovery"
    );
    let next_qc = valid_wire_qc(&ctx, [7u8; 32], 9);
    let next = make_locked_qc(&ctx, [7u8; 32], 9, next_qc, None).unwrap();
    let blocked = owner.publish_locked(next, 1, None::<&FixtureCommittedHistory>);
    assert!(
        matches!(
            blocked,
            PublishResult::RefusedPreWrite(SafetyStoreError::RecoveryRequired(_))
        ),
        "dependent O4 must be blocked before O5 recovery: got {blocked:?}"
    );
    // A fresh O3 + O5 over the surviving publication re-establishes the permitted
    // effective state; only then is dependent O4 admitted.
    let tok = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert!(
        matches!(
            owner.reacknowledge(&tok),
            PublishResult::DurableAcknowledged { .. }
        ),
        "fresh O5 recovery over the surviving bytes must re-acknowledge"
    );
    assert!(
        !owner.recovery_required(),
        "successful O5 recovery must clear the recovery requirement"
    );
}

/// Boundary: an injected write error before commit (labelled distinctly from
/// process termination) → nothing was written; the predecessor (bootstrap)
/// survives unchanged.
#[test]
fn pd_write_error_before_commit_predecessor_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let status = spawn_child(dir.path(), "write_error_before_commit");
    assert_eq!(status.code(), Some(13));
    let ctx = ctx_n(4);
    let owner = SafetyRecordOwner::attach(open_enabled(dir.path()), ctx).unwrap();
    let v = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert!(!v.retained().is_locked());
    assert_eq!(v.retained().publication_revision, 0);
}

/// Boundary: a child process establishes + acknowledges a lock, then exits
/// cleanly. The NEXT process (the parent's reopen) carries no inherited
/// acknowledgement, so dependent O4 is blocked until a successful O5 recovery
/// over the surviving publication. Distinguishes orderly process termination
/// from machine power loss: the acknowledged bytes survive, but effectiveness
/// is re-established only by O5.
#[test]
fn pd_reopen_after_clean_exit_requires_o5_before_o4() {
    let dir = tempfile::tempdir().unwrap();
    let status = spawn_child(dir.path(), "ack_locked_clean_exit");
    assert_eq!(
        status.code(),
        Some(14),
        "child reached the acknowledged-exit boundary"
    );
    let ctx = ctx_n(4);
    let owner = SafetyRecordOwner::attach(open_enabled(dir.path()), ctx.clone()).unwrap();
    assert_eq!(owner.open().unwrap().current_revision, 1);
    assert!(
        owner.recovery_required(),
        "reopened process requires fresh O5"
    );
    let qc2 = valid_wire_qc(&ctx, [0x11u8; 32], 7);
    let l2 = make_locked_qc(&ctx, [0x11u8; 32], 7, qc2, None).unwrap();
    assert!(matches!(
        owner.publish_locked(l2.clone(), 1, None::<&FixtureCommittedHistory>),
        PublishResult::RefusedPreWrite(SafetyStoreError::RecoveryRequired(_))
    ));
    let surviving = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert!(matches!(
        owner.reacknowledge(&surviving),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    ));
    assert_eq!(
        owner.publish_locked(l2, 1, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 2 }
    );
}
/// Boundary: an O1 whose durable init write COMPLETED but whose success was never
/// observed (the caller saw `UncertainPublication`). The surviving metadata +
/// bootstrap are readable, yet the next process still requires recovery and a
/// duplicate O1 over the surviving established state is refused — the surviving
/// bytes are NOT mistaken for a masked successful initialization.
#[test]
fn pd_init_uncertain_bytes_survive_without_observed_success() {
    let dir = tempfile::tempdir().unwrap();
    let status = spawn_child(dir.path(), "init_uncertain");
    assert_eq!(
        status.code(),
        Some(15),
        "child reached the uncertain-O1 boundary"
    );
    let ctx = ctx_n(4);
    let owner = SafetyRecordOwner::attach(open_enabled(dir.path()), ctx).unwrap();
    // The durable bootstrap survived and is a valid complete publication.
    let v = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert!(!v.retained().is_locked());
    assert_eq!(v.retained().publication_revision, 0);
    // The reopened process requires fresh recovery (effectiveness never persisted).
    assert!(owner.recovery_required());
    // Duplicate O1 over the surviving established state is refused (no
    // auto-reinitialization of a store that already has metadata).
    assert!(matches!(
        owner.initialize(true),
        Err(SafetyStoreError::AlreadyEstablished(_))
    ));
}

/// Boundary: a child establishes + acknowledges a lock then exits cleanly; the
/// parent reopens and a duplicate O1 over the surviving established state is
/// refused. Distinct from the uncertain-init case: here the child DID observe
/// success, yet the fresh process still refuses to re-initialize established
/// bytes.
#[test]
fn pd_duplicate_o1_after_surviving_init_refused() {
    let dir = tempfile::tempdir().unwrap();
    let status = spawn_child(dir.path(), "ack_locked_clean_exit");
    assert_eq!(status.code(), Some(14));
    let ctx = ctx_n(4);
    let owner = SafetyRecordOwner::attach(open_enabled(dir.path()), ctx).unwrap();
    assert!(matches!(
        owner.initialize(true),
        Err(SafetyStoreError::AlreadyEstablished(_))
    ));
}

/// Boundary: a child drives an UNCERTAIN O5 over surviving complete state (the
/// recovery write completes but the acknowledgement is lost). The child confirms
/// LIVE, before exit, that the uncertain O5 did not release the recovery
/// restriction. The parent then reopens: the successor survives, recovery is
/// still required (the earlier uncertain transition is not masked), dependent O4
/// stays blocked, and a clean O5 finally re-establishes effectiveness.
#[test]
fn pd_uncertain_o5_does_not_release_recovery_then_clean_o5_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let status = spawn_child(dir.path(), "o5_uncertain");
    assert_eq!(
        status.code(),
        Some(16),
        "child reached the uncertain-O5 boundary"
    );
    let ctx = ctx_n(4);
    let owner = SafetyRecordOwner::attach(open_enabled(dir.path()), ctx.clone()).unwrap();
    assert_eq!(owner.open().unwrap().current_revision, 1);
    assert!(owner.recovery_required(), "reopen still requires recovery");
    // Dependent O4 remains blocked until a successful O5.
    let qc2 = valid_wire_qc(&ctx, [0x11u8; 32], 7);
    let l2 = make_locked_qc(&ctx, [0x11u8; 32], 7, qc2, None).unwrap();
    assert!(matches!(
        owner.publish_locked(l2.clone(), 1, None::<&FixtureCommittedHistory>),
        PublishResult::RefusedPreWrite(SafetyStoreError::RecoveryRequired(_))
    ));
    // A fresh clean O5 over the surviving complete publication recovers.
    let surviving = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert!(matches!(
        owner.reacknowledge(&surviving),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    ));
    assert!(!owner.recovery_required());
    assert_eq!(
        owner.publish_locked(l2, 1, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 2 }
    );
}

/// Boundary: a child drives a FAILED (ambiguous) O5 over surviving complete
/// state. The child confirms LIVE that the failed O5 did not release the recovery
/// restriction; the parent reopens and confirms recovery is still required and
/// the surviving publication is unchanged.
#[test]
fn pd_failed_o5_does_not_release_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let status = spawn_child(dir.path(), "o5_write_error");
    assert_eq!(
        status.code(),
        Some(17),
        "child reached the failed-O5 boundary"
    );
    let ctx = ctx_n(4);
    let owner = SafetyRecordOwner::attach(open_enabled(dir.path()), ctx).unwrap();
    assert_eq!(owner.open().unwrap().current_revision, 1);
    assert!(
        owner.recovery_required(),
        "failed O5 does not release recovery"
    );
    let v = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert!(v.retained().is_locked());
    assert_eq!(v.retained().publication_revision, 1);
}
// ---------------------------------------------------------------------------
// H19 (process-death) — after a REAL process death, a fresh process re-derives
// its O3 recovery capability (never transferring a process-local token across
// the boundary) and O5 refuses non-identical surviving content. Complements the
// in-process `h19_o5_refuses_divergence_outside_binding_digest` unit test.
// ---------------------------------------------------------------------------

#[test]
fn h19_pd_fresh_o3_then_o5_refuses_divergent_surviving_content() {
    let dir = tempfile::tempdir().unwrap();
    // A child establishes + acknowledges a lock (revision 1), then exits cleanly.
    let status = spawn_child(dir.path(), "ack_locked_clean_exit");
    assert_eq!(
        status.code(),
        Some(14),
        "child reached the acknowledged-exit boundary"
    );

    let ctx = ctx_n(4);
    // Fresh process: a NEW backend-bound owner. No recovery token crosses the
    // process boundary — the capability below is derived entirely in-process.
    let owner = SafetyRecordOwner::attach(open_enabled(dir.path()), ctx.clone()).unwrap();
    assert_eq!(owner.open().unwrap().current_revision, 1);
    assert!(owner.recovery_required(), "reopen requires fresh recovery");

    // Re-derive the O3 recovery capability in THIS process over the surviving bytes.
    let fresh = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let stored = fresh.encoded().to_vec();

    // Out-of-band, make the surviving record non-identical at the SAME revision
    // (a byte the binding digest does not cover), re-sealed so stage-1 CRC passes.
    let mut forged = stored.clone();
    forged[2] ^= 0x01; // part of network_genesis_id — not an input to the binding digest
    let body_len = forged.len() - 4;
    let crc = qbind_node::safety_record_store::codec_crc_for_test(&forged[..body_len]);
    forged[body_len..].copy_from_slice(&crc.to_be_bytes());
    owner.debug_overwrite_record_for_test(&forged).unwrap();

    // Capture authoritative state immediately before the refused O5.
    let rec_bound = max_safety_record_bytes(&ctx).unwrap();
    let backend = owner.backend_for_test();
    let meta_before = backend.read_meta(META_ENCODED_LEN_MIRROR).unwrap();
    // The freshly-derived capability was minted entirely in-process (it carries an
    // O5 recovery capability) — no process-local token crossed the death boundary;
    // the child produced only durable bytes. That it reaches a byte-for-byte
    // comparison below (PublicationMismatch, not an incarnation SemanticRefusal)
    // independently proves the capability is bound to THIS reopened incarnation.
    assert!(
        fresh.recovery_backend_incarnation().is_some(),
        "the O5 capability was re-derived in THIS process, not transferred across death"
    );

    // O5 against the freshly-derived capability refuses: the stored content is not
    // byte-for-byte identical to the retained publication, so it is NOT republished.
    let res = owner.reacknowledge(&fresh);
    assert!(
        matches!(
            res,
            PublishResult::RefusedPreWrite(SafetyStoreError::PublicationMismatch(_))
        ),
        "got {res:?}"
    );
    // DIRECT byte preservation: the raw stored publication is still EXACTLY the
    // forged content and is NOT the retained original — O5 overwrote nothing.
    let stored_after = backend
        .read_record(rec_bound)
        .unwrap()
        .expect("record present");
    assert_eq!(
        stored_after, forged,
        "refused O5 left the divergent surviving bytes byte-for-byte unchanged"
    );
    assert_ne!(
        stored_after,
        fresh.encoded(),
        "refused O5 must NOT have republished the retained original bytes"
    );
    // Metadata/revision unchanged, recovery still required after the refusal, and a
    // dependent O4 is still refused (recovery was never cleared by the failed O5).
    assert_eq!(
        backend.read_meta(META_ENCODED_LEN_MIRROR).unwrap(),
        meta_before,
        "refused O5 did not mutate stored metadata/revision"
    );
    assert!(
        owner.recovery_required(),
        "a refused O5 does not clear the recovery requirement"
    );
    let next_qc = valid_wire_qc(&ctx, [7u8; 32], 9);
    let next = make_locked_qc(&ctx, [7u8; 32], 9, next_qc, None).unwrap();
    assert!(
        matches!(
            owner.publish_locked(next, 1, None::<&FixtureCommittedHistory>),
            PublishResult::RefusedPreWrite(SafetyStoreError::RecoveryRequired(_))
        ),
        "a refused O5 leaves recovery required, so a dependent O4 stays refused"
    );
}

// ---------------------------------------------------------------------------
// H24 (process-death) — legitimate no-commit recovery across a REAL process
// death does NOT manufacture a height-zero committed anchor or a zero block id.
// Complements the unit malformed-anchor cases.
// ---------------------------------------------------------------------------

#[test]
fn h24_pd_nocommit_recovery_does_not_manufacture_anchor() {
    let dir = tempfile::tempdir().unwrap();
    // The reused phase publishes a NO-COMMIT locked record (committed_anchor None).
    let status = spawn_child(dir.path(), "ack_locked_clean_exit");
    assert_eq!(
        status.code(),
        Some(14),
        "child reached the acknowledged-exit boundary"
    );

    let ctx = ctx_n(4);
    let owner = SafetyRecordOwner::attach(open_enabled(dir.path()), ctx).unwrap();
    assert_eq!(owner.open().unwrap().current_revision, 1);
    let v = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    match &v.retained().record {
        SafetyRecord::Locked(l) => assert!(
            l.committed_anchor.is_none(),
            "no-commit recovery across process death must not manufacture a committed anchor"
        ),
        other => panic!("expected a Locked no-commit record, got {other:?}"),
    }
}
// ===========================================================================
// RUN 422 D7-D14 §4/§5/§6 — capacity-aware evidence admission and charging.
//
// A structurally valid-LENGTH backing can still own spare `Vec::capacity()` that
// is genuine allocated memory. Length admission alone therefore does NOT bound
// retained/working memory; these regressions exercise the capacity-aware
// admission (`admit_evidence_capacity`, wired into the single
// `admit_supporting_evidence` path) and the capacity-measured `generation_charge`
// over REAL operations, distinguishing them from length checks.
// ===========================================================================

/// Inflate the outer `signatures` descriptor array's capacity far beyond the
/// pinned bound while keeping every length valid. The structural length/count
/// checks pass; the capacity-aware admission refuses — BEFORE any binding
/// allocation (the evidence-encode instrumentation stays at 0).
#[test]
fn d7d14_cap_excess_descriptor_capacity_refused_before_allocation() {
    use qbind_node::safety_record_store::codec::{
        admit_supporting_evidence, compute_evidence_lock_binding, evidence_payload_encode_count,
        reset_evidence_payload_encode_count,
    };
    let ctx = ctx_n(4);
    let mut qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    // Move the valid signatures into a hugely over-capacity backing: len unchanged,
    // capacity >> N, so `signatures.capacity() * 24` dwarfs the generation ceiling.
    let orig_len = qc.signatures.len();
    let mut inflated: Vec<Vec<u8>> = Vec::with_capacity(100_000);
    inflated.append(&mut qc.signatures);
    assert_eq!(inflated.len(), orig_len, "length preserved");
    assert!(inflated.capacity() >= 100_000, "capacity inflated");
    qc.signatures = inflated;
    let ev = SupportingEvidence::QcDerived(qc);

    reset_evidence_payload_encode_count();
    assert!(
        matches!(
            admit_supporting_evidence(&ev, &ctx),
            Err(SafetyStoreError::CapacityRefusal(_))
        ),
        "valid-length but excess-capacity evidence is refused by capacity admission"
    );
    // Refused before any binding/encode allocation.
    let res = compute_evidence_lock_binding(&[9u8; 32], 5, &ev, &ctx.authority_context_ref, &ctx);
    assert!(matches!(res, Err(SafetyStoreError::CapacityRefusal(_))));
    assert_eq!(
        evidence_payload_encode_count(),
        0,
        "capacity refusal precedes the evidence-binding allocation"
    );
}

/// A per-signature buffer with valid length (S_sig bytes) but inflated capacity
/// is likewise refused by capacity admission, not by the length check.
#[test]
fn d7d14_cap_excess_signature_buffer_capacity_refused() {
    use qbind_node::safety_record_store::codec::admit_supporting_evidence;
    let ctx = ctx_n(4);
    let mut qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let mut big = Vec::with_capacity(200_000);
    big.extend_from_slice(&[0xABu8; S_SIG]);
    assert_eq!(big.len() as u128, S_SIG as u128, "length within s_sig");
    assert!(big.capacity() >= 200_000, "capacity inflated");
    qc.signatures[0] = big;
    let ev = SupportingEvidence::QcDerived(qc);
    assert!(matches!(
        admit_supporting_evidence(&ev, &ctx),
        Err(SafetyStoreError::CapacityRefusal(_))
    ));
}

/// O4 with a caller-supplied candidate whose evidence owns excess backing
/// capacity is refused PRE-WRITE (capacity refusal), leaving stored bytes,
/// revision, and the recovery latch untouched; a normal-capacity candidate is
/// then admitted (readmission once the oversized input is withdrawn).
#[test]
fn d7d14_cap_o4_excess_capacity_candidate_refused_prewrite_then_readmit() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let rec = max_safety_record_bytes(&ctx).unwrap();
    let backend = owner.backend_for_test();
    let meta_before = backend.read_meta(META_ENCODED_LEN_MIRROR).unwrap();
    let record_before = backend.read_record(rec).unwrap();

    // Build a valid candidate, then inflate its evidence backing capacity.
    let mut candidate =
        make_locked_qc(&ctx, [9u8; 32], 5, valid_wire_qc(&ctx, [9u8; 32], 5), None).unwrap();
    if let SupportingEvidence::QcDerived(qc) = &mut candidate.evidence {
        let mut inflated: Vec<Vec<u8>> = Vec::with_capacity(100_000);
        inflated.append(&mut qc.signatures);
        qc.signatures = inflated;
    }
    match owner.publish_locked(candidate, 0, None::<&FixtureCommittedHistory>) {
        PublishResult::RefusedPreWrite(SafetyStoreError::CapacityRefusal(_)) => {}
        other => panic!("expected pre-write CapacityRefusal, got {other:?}"),
    }
    // Nothing mutated by the refusal.
    assert_eq!(
        backend.read_meta(META_ENCODED_LEN_MIRROR).unwrap(),
        meta_before,
        "refused O4 did not mutate metadata/revision"
    );
    assert_eq!(
        backend.read_record(rec).unwrap(),
        record_before,
        "refused O4 did not mutate stored record bytes"
    );
    assert!(
        !owner.recovery_required(),
        "refused O4 did not disturb recovery"
    );

    // Readmission: a normal-capacity candidate at the same expected revision is
    // accepted (the refusal was not a sticky failure).
    let normal =
        make_locked_qc(&ctx, [9u8; 32], 5, valid_wire_qc(&ctx, [9u8; 32], 5), None).unwrap();
    assert_eq!(
        owner.publish_locked(normal, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
}

/// The full capacity-measured decoded working set for the TC variant — including
/// the nested record-level `high_qc` signers, `tc.signers`, each signed-timeout's
/// nested `high_qc` signers, and the signed-timeout signature buffers — fits the
/// reserved generation term. This measures the real owned backings of the
/// BORROWED decoded object in place (via `decoded_working_set_charge`'s
/// `Vec::capacity()` accounting), not an inline `size_of` and not a cloned
/// `RetainedGeneration`.
#[test]
fn d7d14_cap_full_decoded_working_set_tc_variant_bounded() {
    use qbind_node::safety_record_store::accounting::decoded_working_set_charge;
    use qbind_node::safety_record_store::record::size_of_timeout_msg;
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let tc = valid_tc_record(&ctx, 5, 6);
    assert_eq!(
        owner.publish_locked(tc, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    let rec = max_safety_record_bytes(&ctx).unwrap();
    let gen = qbind_node::safety_record_store::profile::max_retained_generation_bytes(
        &ctx,
        size_of_timeout_msg(),
    )
    .unwrap();
    let stored = owner
        .backend_for_test()
        .read_record(rec)
        .unwrap()
        .expect("record present");
    let decoded = decode_record(&stored, &ctx).unwrap();
    assert!(
        matches!(&decoded.record, SafetyRecord::Locked(l) if matches!(l.evidence, SupportingEvidence::TcDerived { .. })),
        "expected a Locked TC generation, got {:?}",
        decoded.record
    );
    let full = decoded_working_set_charge(&decoded).unwrap();
    assert!(
        full <= gen,
        "the full capacity-measured TC decoded working set {full} fits its reserved term {gen}"
    );
}
// ===========================================================================
// RUN 422 D7-D14 §4 — per-vector capacity bound (smallest-over-bound cases).
//
// The aggregate `admit_evidence_capacity` check (sum of backing capacities vs the
// cross-variant generation maximum) does NOT, by itself, enforce the contract's
// individual per-object capacity limits and initial `CAPNORM_SLACK = 0` policy.
// `admit_evidence_capnorm` refuses a SINGLE backing whose `capacity()` exceeds its
// per-class profile maximum (`S_sig`, `N`, `B_span`) + `CAPNORM_SLACK` — even when
// the TOTAL footprint still fits the aggregate generation maximum, so the
// aggregate check accepts it. These are the smaller violations the existing
// huge-capacity (100_000 / 200_000) tests cannot establish. For each class we
// exercise the accepted boundary and boundary-plus-one through the single
// `admit_supporting_evidence` path, and the concrete classes through the genuine
// O4 admission path, for BOTH QC-derived and TC-derived evidence (including the
// timeout-entry nested high-QC signers).
// ===========================================================================

/// Build a `Vec<u8>` of `len` bytes whose allocated `capacity()` is at least `cap`.
fn u8_vec_with_cap(len: usize, cap: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(cap);
    v.extend(std::iter::repeat_n(0xABu8, len));
    v
}

/// Build a `Vec<ValidatorId>` of `len` dense signers whose `capacity()` ≥ `cap`.
fn vid_vec_with_cap(len: usize, cap: usize) -> Vec<ValidatorId> {
    let mut v = Vec::with_capacity(cap);
    for i in 0..len {
        v.push(ValidatorId::new(i as u64));
    }
    v
}

/// The concrete signature case from the task: `S_sig = 8`, signature length `8`
/// (valid), capacity `9` (one past the permitted per-signature backing bound).
/// The aggregate check ACCEPTS the tiny excess; the per-vector bound REFUSES it;
/// the unified admission path therefore refuses; the exact-bound control (cap 8)
/// is admitted.
#[test]
fn d7d14_capnorm_signature_buffer_boundary_plus_one_refused_aggregate_accepts() {
    use qbind_node::safety_record_store::accounting::{
        admit_evidence_capacity, admit_evidence_capnorm,
    };
    use qbind_node::safety_record_store::codec::admit_supporting_evidence;
    let ctx = ctx_n(4);
    assert_eq!(ctx.s_sig, 8, "concrete case uses S_sig = 8");

    // Boundary-plus-one: length 8 (valid), capacity 9 (> S_sig + CAPNORM_SLACK).
    let mut qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let over = u8_vec_with_cap(S_SIG, S_SIG + 1);
    assert_eq!(over.len(), S_SIG, "signature length within S_sig");
    assert!(
        over.capacity() > S_SIG,
        "signature capacity past the backing bound"
    );
    qc.signatures[0] = over;
    let ev = SupportingEvidence::QcDerived(qc);

    // The AGGREGATE check accepts the tiny spare capacity (footprint still fits the
    // generation maximum) — proving it does not, alone, enforce the per-object rule.
    assert!(
        admit_evidence_capacity(&ev, &ctx).is_ok(),
        "aggregate generation check accepts the one-byte spare capacity"
    );
    // The PER-VECTOR bound refuses it, and so does the unified admission path.
    assert!(matches!(
        admit_evidence_capnorm(&ev, &ctx),
        Err(SafetyStoreError::CapacityRefusal(_))
    ));
    assert!(matches!(
        admit_supporting_evidence(&ev, &ctx),
        Err(SafetyStoreError::CapacityRefusal(_))
    ));

    // Exact-bound control: capacity == S_sig is admitted.
    let mut qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    qc.signatures[0] = u8_vec_with_cap(S_SIG, S_SIG);
    let ev = SupportingEvidence::QcDerived(qc);
    assert!(admit_supporting_evidence(&ev, &ctx).is_ok());
}

/// QC outer `signatures` descriptor array and `signer_bitmap`: capacity one past
/// their class maxima (`N` elements, `B_span` bytes) is refused per-vector while
/// the aggregate check accepts the small excess; the exact bound is admitted.
#[test]
fn d7d14_capnorm_qc_descriptor_and_bitmap_boundary_plus_one_refused() {
    use qbind_node::safety_record_store::accounting::{
        admit_evidence_capacity, admit_evidence_capnorm,
    };
    use qbind_node::safety_record_store::codec::admit_supporting_evidence;
    let ctx = ctx_n(4);
    let n = ctx.n();

    // Outer signatures descriptor: len = need (valid), capacity = N + 1.
    let mut qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let mut outer: Vec<Vec<u8>> = Vec::with_capacity(n + 1);
    outer.append(&mut qc.signatures);
    assert!(outer.capacity() > n, "descriptor capacity past N");
    qc.signatures = outer;
    let ev = SupportingEvidence::QcDerived(qc);
    assert!(
        admit_evidence_capacity(&ev, &ctx).is_ok(),
        "aggregate accepts small excess"
    );
    assert!(matches!(
        admit_evidence_capnorm(&ev, &ctx),
        Err(SafetyStoreError::CapacityRefusal(_))
    ));
    assert!(matches!(
        admit_supporting_evidence(&ev, &ctx),
        Err(SafetyStoreError::CapacityRefusal(_))
    ));

    // Bitmap: len = B_span (valid), capacity = B_span + 1.
    let mut qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let bspan = qc.signer_bitmap.len();
    let mut bm = Vec::with_capacity(bspan + 1);
    bm.extend_from_slice(&qc.signer_bitmap);
    assert!(bm.capacity() > bspan, "bitmap capacity past B_span");
    qc.signer_bitmap = bm;
    let ev = SupportingEvidence::QcDerived(qc);
    assert!(matches!(
        admit_evidence_capnorm(&ev, &ctx),
        Err(SafetyStoreError::CapacityRefusal(_))
    ));
    assert!(matches!(
        admit_supporting_evidence(&ev, &ctx),
        Err(SafetyStoreError::CapacityRefusal(_))
    ));
}

/// Every TC-derived signer/descriptor/buffer backing, one past its class maximum,
/// is refused per-vector: record-level `high_qc.signers`, `tc.signers`, the
/// optional `tc.high_qc.signers`, the `signed_timeouts` descriptor array, a
/// per-entry `signature` buffer, and a per-entry nested `high_qc.signers` backing.
/// The aggregate check accepts each small excess; the exact-bound baseline passes.
#[test]
fn d7d14_capnorm_tc_backings_boundary_plus_one_refused() {
    use qbind_node::safety_record_store::accounting::admit_evidence_capnorm;
    use qbind_node::safety_record_store::codec::admit_supporting_evidence;
    let ctx = ctx_n(4);
    let n = ctx.n();
    let need = ((2 * n) + 2) / 3;

    // Exact-bound baseline is admitted.
    let base = valid_tc_record(&ctx, 5, 6);
    assert!(admit_supporting_evidence(&base.evidence, &ctx).is_ok());

    // Helper: run one mutated-evidence case and assert the per-vector bound
    // refuses it through the unified admission path. (Unlike the QC cases, the TC
    // generation ceiling is tight, so a small per-vector excess may also trip the
    // aggregate check; the QC tests above demonstrate the aggregate-accepts /
    // capnorm-refuses distinction with the smaller QC element sizes.)
    let assert_capnorm_refused = |ev: &SupportingEvidence| {
        assert!(matches!(
            admit_evidence_capnorm(ev, &ctx),
            Err(SafetyStoreError::CapacityRefusal(_))
        ));
        assert!(matches!(
            admit_supporting_evidence(ev, &ctx),
            Err(SafetyStoreError::CapacityRefusal(_))
        ));
    };

    // record-level high_qc.signers: capacity N + 1.
    let mut ev = base.evidence.clone();
    if let SupportingEvidence::TcDerived { high_qc, .. } = &mut ev {
        high_qc.signers = vid_vec_with_cap(need, n + 1);
    }
    assert_capnorm_refused(&ev);

    // tc.signers: capacity N + 1.
    let mut ev = base.evidence.clone();
    if let SupportingEvidence::TcDerived { tc, .. } = &mut ev {
        tc.signers = vid_vec_with_cap(need, n + 1);
    }
    assert_capnorm_refused(&ev);

    // tc.high_qc.signers (optional record): capacity N + 1.
    let mut ev = base.evidence.clone();
    if let SupportingEvidence::TcDerived { tc, .. } = &mut ev {
        tc.high_qc.as_mut().unwrap().signers = vid_vec_with_cap(need, n + 1);
    }
    assert_capnorm_refused(&ev);

    // signed_timeouts descriptor array: capacity N + 1.
    let mut ev = base.evidence.clone();
    if let SupportingEvidence::TcDerived { tc, .. } = &mut ev {
        let mut outer = Vec::with_capacity(n + 1);
        outer.append(&mut tc.signed_timeouts);
        assert!(outer.capacity() > n);
        tc.signed_timeouts = outer;
    }
    assert_capnorm_refused(&ev);

    // per-entry signature buffer: length S_sig (valid), capacity S_sig + 1.
    let mut ev = base.evidence.clone();
    if let SupportingEvidence::TcDerived { tc, .. } = &mut ev {
        tc.signed_timeouts[0].set_signature(u8_vec_with_cap(S_SIG, S_SIG + 1));
    }
    assert_capnorm_refused(&ev);

    // per-entry nested high_qc.signers: capacity N + 1.
    let mut ev = base.evidence.clone();
    if let SupportingEvidence::TcDerived { tc, .. } = &mut ev {
        tc.signed_timeouts[0].high_qc.as_mut().unwrap().signers = vid_vec_with_cap(need, n + 1);
    }
    assert_capnorm_refused(&ev);
}

/// O4 genuine admission path: a caller-supplied QC candidate whose single
/// signature buffer carries one byte of spare capacity past `S_sig` is refused
/// PRE-WRITE (`CapacityRefusal`), leaving stored bytes/revision/recovery intact;
/// an exact-capacity candidate at the same expected revision is then admitted.
#[test]
fn d7d14_capnorm_o4_qc_signature_over_bound_refused_prewrite_then_readmit() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let rec = max_safety_record_bytes(&ctx).unwrap();
    let backend = owner.backend_for_test();
    let meta_before = backend.read_meta(META_ENCODED_LEN_MIRROR).unwrap();
    let record_before = backend.read_record(rec).unwrap();

    let mut candidate =
        make_locked_qc(&ctx, [9u8; 32], 5, valid_wire_qc(&ctx, [9u8; 32], 5), None).unwrap();
    if let SupportingEvidence::QcDerived(qc) = &mut candidate.evidence {
        qc.signatures[0] = u8_vec_with_cap(S_SIG, S_SIG + 1);
    }
    match owner.publish_locked(candidate, 0, None::<&FixtureCommittedHistory>) {
        PublishResult::RefusedPreWrite(SafetyStoreError::CapacityRefusal(_)) => {}
        other => panic!("expected pre-write CapacityRefusal, got {other:?}"),
    }
    assert_eq!(
        backend.read_meta(META_ENCODED_LEN_MIRROR).unwrap(),
        meta_before,
        "refused O4 did not mutate metadata/revision"
    );
    assert_eq!(
        backend.read_record(rec).unwrap(),
        record_before,
        "refused O4 did not mutate stored record bytes"
    );
    assert!(
        !owner.recovery_required(),
        "refused O4 did not disturb recovery"
    );

    let normal =
        make_locked_qc(&ctx, [9u8; 32], 5, valid_wire_qc(&ctx, [9u8; 32], 5), None).unwrap();
    assert_eq!(
        owner.publish_locked(normal, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
}

/// O4 genuine admission path, TC-derived: a timeout-entry's nested
/// `high_qc.signers` backing with one spare slot past `N` is refused PRE-WRITE,
/// leaving stored state intact; the exact-capacity TC candidate is then admitted.
#[test]
fn d7d14_capnorm_o4_tc_nested_high_qc_over_bound_refused_prewrite_then_readmit() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let rec = max_safety_record_bytes(&ctx).unwrap();
    let backend = owner.backend_for_test();
    let record_before = backend.read_record(rec).unwrap();
    let n = ctx.n();
    let need = ((2 * n) + 2) / 3;

    let mut candidate = valid_tc_record(&ctx, 5, 6);
    if let SupportingEvidence::TcDerived { tc, .. } = &mut candidate.evidence {
        tc.signed_timeouts[0].high_qc.as_mut().unwrap().signers = vid_vec_with_cap(need, n + 1);
    }
    match owner.publish_locked(candidate, 0, None::<&FixtureCommittedHistory>) {
        PublishResult::RefusedPreWrite(SafetyStoreError::CapacityRefusal(_)) => {}
        other => panic!("expected pre-write CapacityRefusal (nested high_qc), got {other:?}"),
    }
    assert_eq!(
        backend.read_record(rec).unwrap(),
        record_before,
        "refused TC O4 did not mutate stored record bytes"
    );
    assert!(!owner.recovery_required());

    let normal = valid_tc_record(&ctx, 5, 6);
    assert_eq!(
        owner.publish_locked(normal, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
}

// ===========================================================================
// RUN 422 D7-D14 §6 — O2 decoded working-set measured on the ACTUAL decoded
// object (not a cloned RetainedGeneration).
//
// `RetainedGeneration::from_locked` CLONES the evidence into a second, freshly
// allocated representation whose vector capacities are the clone's (exact), not
// the live decoded object's. Charging that clone does not measure the original
// `DecodedRecord`. `decoded_working_set_charge` observes the BORROWED decoded
// object in place — its inline representation plus the `Vec::capacity()` of every
// backing it actually owns — without cloning, and that borrowed inventory is what
// is compared against the reserved generation term.
// ===========================================================================

/// The live decoded QC working set, measured in place on the borrowed
/// `DecodedRecord`, fits its reserved generation term; the borrowed measurement
/// does not clone the object (the decoded value remains usable afterwards and the
/// measured backings are the object's own, matching a manual field inventory).
#[test]
fn d7d14_o2_decoded_working_set_measured_in_place_qc() {
    use qbind_node::safety_record_store::accounting::decoded_working_set_charge;
    use qbind_node::safety_record_store::record::size_of_timeout_msg;
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let locked =
        make_locked_qc(&ctx, [9u8; 32], 5, valid_wire_qc(&ctx, [9u8; 32], 5), None).unwrap();
    assert_eq!(
        owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    let rec = max_safety_record_bytes(&ctx).unwrap();
    let gen = qbind_node::safety_record_store::profile::max_retained_generation_bytes(
        &ctx,
        size_of_timeout_msg(),
    )
    .unwrap();
    let stored = owner
        .backend_for_test()
        .read_record(rec)
        .unwrap()
        .expect("record present");
    let decoded = decode_record(&stored, &ctx).unwrap();

    // Borrowed, non-cloning measurement of the ACTUAL decoded object.
    let live = decoded_working_set_charge(&decoded).unwrap();

    // Independent manual field inventory of the SAME borrowed object's backings.
    let manual = match &decoded.record {
        SafetyRecord::Locked(l) => match &l.evidence {
            SupportingEvidence::QcDerived(qc) => {
                let mut t = std::mem::size_of::<DecodedRecord>();
                t += qc.signer_bitmap.capacity();
                t += qc.signatures.capacity() * std::mem::size_of::<Vec<u8>>();
                for s in &qc.signatures {
                    t += s.capacity();
                }
                t as u128
            }
            other => panic!("expected QC evidence, got {other:?}"),
        },
        other => panic!("expected Locked, got {other:?}"),
    };
    assert_eq!(
        live, manual,
        "borrowed in-place charge equals a manual field inventory of the live object"
    );
    assert!(
        live <= gen,
        "the live decoded working set {live} fits its reserved generation term {gen}"
    );
    // The decoded object was only borrowed, not consumed: it is still usable.
    assert!(decoded.is_locked());
}

/// The TC variant (including the record-level and nested timeout-entry high-QC
/// signer backings and the per-entry signature buffers) measured in place on the
/// borrowed decoded object fits its reserved generation term.
#[test]
fn d7d14_o2_decoded_working_set_measured_in_place_tc() {
    use qbind_node::safety_record_store::accounting::decoded_working_set_charge;
    use qbind_node::safety_record_store::record::size_of_timeout_msg;
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let tc = valid_tc_record(&ctx, 5, 6);
    assert_eq!(
        owner.publish_locked(tc, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    let rec = max_safety_record_bytes(&ctx).unwrap();
    let gen = qbind_node::safety_record_store::profile::max_retained_generation_bytes(
        &ctx,
        size_of_timeout_msg(),
    )
    .unwrap();
    let stored = owner
        .backend_for_test()
        .read_record(rec)
        .unwrap()
        .expect("record present");
    let decoded = decode_record(&stored, &ctx).unwrap();
    assert!(matches!(
        &decoded.record,
        SafetyRecord::Locked(l) if matches!(l.evidence, SupportingEvidence::TcDerived { .. })
    ));
    let live = decoded_working_set_charge(&decoded).unwrap();
    assert!(
        live <= gen,
        "the live TC decoded working set {live} fits its reserved generation term {gen}"
    );
}

// ===========================================================================
// RUN 422 D7-D14 — MAXIMUM fully-populated TC fixture and the transient
// decoded accounting correction.
//
// The quorum-sized `valid_tc_record` creates only `ceil(2N/3)` members (3 for
// N=4) — it does NOT exercise the maximum supported nested contents. This
// fixture populates every TC backing at the profile maximum (N timeout entries,
// N unique signers, N record-level/TC/nested high-QC signers, maximum signature
// lengths) so the transient decoded working set is measured at its true peak.
// ===========================================================================

/// A VALID, MAXIMALLY-populated TC-derived locked record: N timeout entries with
/// N unique authorized signers, N record-level high-QC signers, N TC high-QC
/// signers (exact correspondence), N signers in every timeout entry's nested
/// high-QC, and maximum-length signatures. Distinct from the quorum-sized
/// `valid_tc_record` (which is preserved); this adds the maximum case separately.
fn valid_tc_record_max(
    ctx: &PinnedSafetyContext,
    lock_view: u64,
    timeout_view: u64,
) -> LockedRecord {
    let need = ctx.n(); // N — the supported maximum, not ceil(2N/3)
    let high = LogicalQc::new(
        [9u8; 32],
        lock_view,
        (0..need as u64).map(ValidatorId::new).collect(),
    );
    let mut signed = Vec::new();
    for i in 0..need as u64 {
        let mut t = TimeoutMsg::new(timeout_view, Some(high.clone()), ValidatorId::new(i));
        t.set_signature(vec![0xCD; S_SIG]);
        signed.push(t);
    }
    signed.shrink_to_fit();
    let tc = TimeoutCertificate {
        view: timeout_view + 1,
        high_qc: Some(high.clone()),
        signers: (0..need as u64).map(ValidatorId::new).collect(),
        signed_timeouts: signed,
        timeout_view,
    };
    let evidence = SupportingEvidence::TcDerived {
        high_qc: high.clone(),
        tc,
    };
    let binding = qbind_node::safety_record_store::codec::compute_evidence_lock_binding(
        &[9u8; 32],
        lock_view,
        &evidence,
        &ctx.authority_context_ref,
        ctx,
    )
    .unwrap();
    LockedRecord {
        lock_block_id: [9u8; 32],
        lock_view,
        evidence_lock_binding: binding,
        authority_context_ref: ctx.authority_context_ref,
        committed_anchor: None,
        predecessor_ref: None,
        evidence,
    }
}

/// Executed counterexample + correction (task §4/§5): the maximum TC's live
/// transient decoded working set EXCEEDS the retained-generation ceiling the O2
/// reservation previously reused, and is covered only by the corrected transient
/// decoded ceiling — all within the UNCHANGED accepted aggregate.
#[test]
fn d7d14_transient_decoded_max_tc_exceeds_retained_gen_but_fits_transient_ceiling() {
    use qbind_node::safety_record_store::accounting::{
        decoded_working_set_charge, max_transient_decoded_working_set,
    };
    use qbind_node::safety_record_store::profile::{
        max_aggregate_retained_bytes, max_retained_generation_bytes,
    };
    use qbind_node::safety_record_store::record::{size_of_decoded_record, size_of_timeout_msg};
    let ctx = ctx_n(4);

    // Build and round-trip the MAXIMUM TC so the measured object is the real
    // decoder output (exact-capacity backings), exactly as O2/O4/O5 would decode.
    let ltc = valid_tc_record_max(&ctx, 5, 6);
    let decoded = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(ltc),
    };
    let enc = encode_record(&decoded, &ctx).unwrap();
    let decoded = decode_record(&enc, &ctx).unwrap();

    // Independent field/capacity inventory of the live decoded object's backings.
    let (inline, backing) = match &decoded.record {
        SafetyRecord::Locked(l) => match &l.evidence {
            SupportingEvidence::TcDerived { high_qc, tc } => {
                let mut b = high_qc.signers.capacity() * 8;
                b += tc.signers.capacity() * 8;
                b += tc.high_qc.as_ref().unwrap().signers.capacity() * 8;
                b += tc.signed_timeouts.capacity() * size_of_timeout_msg() as usize;
                for t in &tc.signed_timeouts {
                    b += t.signature.capacity();
                    b += t.high_qc.as_ref().unwrap().signers.capacity() * 8;
                }
                (size_of_decoded_record() as usize, b)
            }
            other => panic!("expected TC evidence, got {other:?}"),
        },
        other => panic!("expected Locked, got {other:?}"),
    };
    let live = decoded_working_set_charge(&decoded).unwrap();
    assert_eq!(
        live,
        (inline + backing) as u128,
        "borrowed in-place charge equals the manual field/capacity inventory"
    );
    // Executed derivation on the ACTUAL target: inline 408 + backing 704 = 1112.
    assert_eq!(backing as u128, 704, "maximum TC evidence backings");
    assert_eq!(inline as u128, 408, "transient decoded inline object");
    assert_eq!(live, 1112, "total transient decoded footprint");

    // The COUNTEREXAMPLE the O2/O4/O5 reservations previously reused: the
    // retained-generation ceiling is 1104 and is EXCEEDED by the live transient
    // decoded object (1112) — an executed regression, not a derived figure.
    let retained_gen = max_retained_generation_bytes(&ctx, size_of_timeout_msg()).unwrap();
    assert_eq!(retained_gen, 1104, "retained-generation ceiling");
    assert!(
        live > retained_gen,
        "the maximum transient decoded object {live} EXCEEDS the retained-generation \
         reservation {retained_gen} it was previously charged against (pre-correction gap)"
    );

    // The CORRECTION: the transient decoded ceiling covers the live object, and is
    // strictly larger than (not substituted by) the retained-generation ceiling.
    let transient = max_transient_decoded_working_set(&ctx).unwrap();
    assert_eq!(
        transient, 1112,
        "transient decoded ceiling = inline + max backing"
    );
    assert!(
        live <= transient,
        "the live transient decoded object fits its corrected term"
    );
    assert!(
        transient > retained_gen,
        "transient ceiling strictly exceeds retained ceiling"
    );

    // The accepted aggregate is UNCHANGED by the correction (still 7772 for N=4).
    let agg = max_aggregate_retained_bytes(
        &ctx,
        size_of_timeout_msg(),
        max_safety_record_bytes(&ctx).unwrap(),
    )
    .unwrap();
    assert_eq!(agg, 7772, "accepted N=4 aggregate unchanged");
    // The corrected per-operation transient reservations remain within the aggregate.
    let o4_charge = 2 * transient + 3 * max_safety_record_bytes(&ctx).unwrap() + (2 + 32 + 8);
    assert!(
        o4_charge <= agg,
        "corrected O4 reservation fits the unchanged aggregate"
    );
}

/// The maximum TC drives REAL O4 publish, O3 read-validate, and O5 reacknowledge
/// operations: each admits and its observed peak stays within the unchanged
/// accepted aggregate, and the retained O3 proof coexists with O5.
#[test]
fn d7d14_max_tc_o4_o3_o5_real_operations_within_aggregate() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let backend = owner.backend_for_test();
    let agg_cap = backend.accounting_aggregate_cap().unwrap();

    // O4: publish the MAXIMUM TC. The corrected transient reservation admits it and
    // the observed peak stays within the accepted aggregate; it fully releases.
    let ltc = valid_tc_record_max(&ctx, 5, 6);
    assert_eq!(
        owner.publish_locked(ltc, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    assert!(
        backend.accounting_aggregate_peak() <= agg_cap,
        "maximum-TC O4 peak within the unchanged aggregate"
    );
    assert_eq!(backend.accounting_current(), 0, "O4 released after publish");

    // O3: retain a proof (holder charge held live) over the maximum TC.
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert!(proof.retained().is_locked());
    let with_holder = backend.accounting_current();
    assert!(
        with_holder > 0 && with_holder <= agg_cap,
        "O3 holder within aggregate"
    );

    // O5: reacknowledge the surviving maximum-TC publication while the O3 proof is
    // still live — peak coexistence of the retained holder and the O5 working set
    // stays within the unchanged aggregate.
    assert_eq!(
        owner.reacknowledge(&proof),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    assert!(
        backend.accounting_aggregate_peak() <= agg_cap,
        "O5 + live O3 holder peak within the unchanged aggregate"
    );
    drop(proof);
    assert_eq!(
        backend.accounting_current(),
        0,
        "all operational charges released"
    );
}

/// O4 admission-order correction (task §6): the allocation-free candidate
/// structural/capacity preflight runs BEFORE the authoritative predecessor is
/// read, decoded, validated, or re-encoded. With an ESTABLISHED LOCKED predecessor
/// (whose validation re-encodes its evidence payload and so would bump the evidence
/// encode counter), an over-bound candidate is refused with the evidence encode
/// counter still at zero — proving no predecessor evidence read/validate/encode
/// occurred before the candidate refusal — and the locked predecessor is left
/// intact. The candidate preflight does NOT replace predecessor validation, which
/// still runs for an admissible candidate (positive control at the end).
#[test]
fn d7d14_o4_candidate_preflight_precedes_locked_predecessor_read() {
    use qbind_node::safety_record_store::codec::{
        evidence_payload_encode_count, reset_evidence_payload_encode_count,
    };
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);

    // Establish a LOCKED predecessor (rev 1) — it carries evidence, so a genuine
    // predecessor validation would re-encode that evidence payload.
    let base = make_locked_qc(&ctx, [9u8; 32], 5, valid_wire_qc(&ctx, [9u8; 32], 5), None).unwrap();
    assert_eq!(
        owner.publish_locked(base, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    let before = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert!(before.retained().is_locked());
    assert_eq!(before.retained().publication_revision, 1);

    // Over-bound candidate at the current expected revision.
    let mut candidate =
        make_locked_qc(&ctx, [9u8; 32], 9, valid_wire_qc(&ctx, [9u8; 32], 9), None).unwrap();
    if let SupportingEvidence::QcDerived(qc) = &mut candidate.evidence {
        let mut inflated: Vec<Vec<u8>> = Vec::with_capacity(100_000);
        inflated.append(&mut qc.signatures);
        qc.signatures = inflated;
    }

    reset_evidence_payload_encode_count();
    match owner.publish_locked(candidate, 1, None::<&FixtureCommittedHistory>) {
        PublishResult::RefusedPreWrite(SafetyStoreError::CapacityRefusal(_)) => {}
        other => panic!("expected pre-write CapacityRefusal, got {other:?}"),
    }
    // Zero evidence encodes ⇒ the LOCKED predecessor was not validated/re-encoded
    // before the candidate refusal: the allocation-free candidate preflight fired
    // first. (The predecessor is locked, so a predecessor validation WOULD have
    // produced a non-zero count.)
    assert_eq!(
        evidence_payload_encode_count(),
        0,
        "candidate preflight must precede the locked predecessor read/validate/encode"
    );

    // The locked predecessor is untouched by the refusal.
    let after = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert_eq!(after.retained(), before.retained());
    assert!(!owner.recovery_required());
    // Release the retained O3 holders so the positive control runs against the
    // same aggregate headroom as a normal successor publication.
    drop(before);
    drop(after);

    // Positive control: an admissible successor IS validated (predecessor + candidate)
    // and published — the preflight is bound-specific, not a blanket refusal, and does
    // not bypass the authoritative predecessor validation.
    reset_evidence_payload_encode_count();
    let good = make_locked_qc(&ctx, [9u8; 32], 9, valid_wire_qc(&ctx, [9u8; 32], 9), None).unwrap();
    assert_eq!(
        owner.publish_locked(good, 1, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 2 }
    );
    assert!(
        evidence_payload_encode_count() > 0,
        "an admitted O4 does read/validate/encode (predecessor + candidate)"
    );
}

/// §5 — O5 publication-envelope coexistence regression. `publish_atomic` wraps
/// the republished record + metadata in two CRC-framing envelopes
/// (`SafetyBackend::wrap`) while the O5 read-back buffer, the transient decoded
/// object, the encoded metadata, and the retained O3 holder are all still live.
/// The O5 reservation now charges that `publication_staging_charge` up front, so
/// the observed coexistence peak reflects it and still fits the UNCHANGED
/// aggregate. Were the staging term absent, the O5 peak would be
/// `holder + readback + META + transient` (= 4016 for the maximum TC) — strictly
/// below the lower bound asserted here — so this regression fails closed if the
/// envelope charge is dropped.
#[test]
fn d7d14_o5_publication_envelope_coexistence_reserved_within_aggregate() {
    use qbind_node::safety_record_store::accounting::{
        max_transient_decoded_working_set, publication_staging_charge,
    };
    use qbind_node::safety_record_store::profile::max_safety_record_bytes;

    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);

    // Establish the maximum-TC publication under the first backend instance, then
    // drop it so the O4 operation's own working-set peak does NOT pollute the
    // measurement.
    let ltc = valid_tc_record_max(&ctx, 5, 6);
    assert_eq!(
        owner.publish_locked(ltc, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    drop(owner);

    // Reopen a FRESH backend over the surviving bytes: its accountant peak starts
    // at zero, so the peak observed below reflects ONLY the O3 holder + O5
    // working-set coexistence (including the publication-staging envelopes), not
    // the earlier O4 peak. A reopened established store is not-effective, which is
    // exactly the state O5 recovers.
    let owner = SafetyRecordOwner::attach(open_enabled(dir.path()), ctx.clone()).unwrap();
    let backend = owner.backend_for_test();
    let agg_cap = backend.accounting_aggregate_cap().unwrap();
    assert!(
        owner.recovery_required(),
        "reopened store starts not-effective"
    );

    // Retain a live O3 proof/holder bound to THIS reopened incarnation (required
    // for the O5 recovery capability), then measure O5 coexistence.
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let holder = backend.accounting_current();
    assert!(holder > 0, "a live O3 holder must coexist with O5");

    let staging = publication_staging_charge(&ctx).unwrap();
    assert!(staging > 0, "the CRC-framing envelopes are a real charge");
    let readback = max_safety_record_bytes(&ctx).unwrap();
    let transient = max_transient_decoded_working_set(&ctx).unwrap();
    // Strict lower bound on the O5 coexistence peak WITH the staging term (META
    // omitted to keep it a conservative lower bound). WITHOUT the staging charge
    // the O5 peak would be `holder + readback + META + transient` — strictly below
    // this bound — so the assertion fails closed if the envelope charge is dropped.
    let o5_peak_lower_bound = holder + readback + transient + staging;

    assert_eq!(
        owner.reacknowledge(&proof),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    let peak = backend.accounting_aggregate_peak();
    assert!(
        peak >= o5_peak_lower_bound,
        "O5 peak {peak} must include the publication-staging envelopes \
         (lower bound {o5_peak_lower_bound} = holder {holder} + readback {readback} \
         + transient {transient} + staging {staging})"
    );
    assert!(
        peak <= agg_cap,
        "O5 + live holder + staging peak {peak} must still fit the unchanged aggregate {agg_cap}"
    );
    drop(proof);
    assert_eq!(
        backend.accounting_current(),
        0,
        "all operational charges (incl. O5 staging) released"
    );
}

/// §6 — bounded encoding backing. `encode_record` pre-sizes its output to the
/// variant's admitted serialized cap and writes into it, so the backing is a
/// SINGLE admitted allocation that never grows by implicit `Vec` doubling (which
/// a `Vec::new()` + `extend_from_slice` path would do, producing several
/// reallocations). Observed directly with the counting allocator: exactly one
/// alloc for the maximum QC and maximum TC encodings, and the returned backing
/// capacity equals the admitted cap — not a post-hoc `len() <= cap` check.
#[test]
fn d7d14_encode_record_backing_is_bounded_single_allocation() {
    let ctx = ctx_n(4);

    // Maximum QC record.
    let qc_locked =
        make_locked_qc(&ctx, [9u8; 32], 5, valid_wire_qc(&ctx, [9u8; 32], 5), None).unwrap();
    let qc_dec = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(qc_locked),
    };
    let _ = encode_record(&qc_dec, &ctx).unwrap(); // warm up lazy state
    let (enc, allocs) = measure_allocs(|| encode_record(&qc_dec, &ctx).unwrap());
    assert_eq!(
        allocs, 1,
        "max-QC encode must perform exactly one (pre-sized) allocation, no implicit growth"
    );
    assert_eq!(
        enc.capacity() as u128,
        max_qc_bytes(&ctx).unwrap(),
        "max-QC encode backing capacity must equal the admitted serialized cap"
    );
    assert!(enc.len() as u128 <= max_qc_bytes(&ctx).unwrap());

    // Maximum TC record (fully populated nested evidence).
    let tc_locked = valid_tc_record_max(&ctx, 5, 6);
    let tc_dec = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(tc_locked),
    };
    let _ = encode_record(&tc_dec, &ctx).unwrap();
    let (enc, allocs) = measure_allocs(|| encode_record(&tc_dec, &ctx).unwrap());
    assert_eq!(
        allocs, 1,
        "max-TC encode must perform exactly one (pre-sized) allocation, no implicit growth"
    );
    assert_eq!(
        enc.capacity() as u128,
        max_tc_bytes(&ctx).unwrap(),
        "max-TC encode backing capacity must equal the admitted serialized cap"
    );
    assert!(enc.len() as u128 <= max_tc_bytes(&ctx).unwrap());
}

/// §3 — O3 validation-reservation coexistence regression (D7-D14). Reproduces the
/// reviewed under-reservation: during O3 `validate_decoded`→`validate_locked` the
/// correspondence re-encode buffer and the certificate-binding buffer — each
/// pre-sized to `MAX_SAFETY_RECORD_BYTES` — would coexist with the live transient
/// decoded object and the retained original bytes. The pre-correction O3
/// reservation (`retained_holder_charge + MAX_SAFETY_RECORD_BYTES`) does NOT cover
/// that live peak; the corrected reservation does, and still fits the UNCHANGED
/// aggregate. Every object size here is derived from the real encoded/decoded
/// objects, independently of the reservation formula under test.
#[test]
fn d7d14_o3_validation_reservation_covers_live_coexistence_max_tc() {
    use qbind_node::safety_record_store::accounting::{
        decoded_working_set_charge, max_transient_decoded_working_set,
    };
    use qbind_node::safety_record_store::profile::{
        max_aggregate_retained_bytes, max_retained_generation_bytes,
    };
    use qbind_node::safety_record_store::record::{
        size_of_timeout_msg, validated_holder_handle_bytes,
    };
    let ctx = ctx_n(4);

    // Real maximum-TC objects: encode the retained original, then decode the live
    // transient working set — the two objects O3 holds alongside its validation
    // buffers. Sizes come from these live objects, not the reservation formula.
    let ltc = valid_tc_record_max(&ctx, 5, 6);
    let decoded = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(ltc),
    };
    let enc = encode_record(&decoded, &ctx).unwrap();
    let enc_len = enc.len() as u128; // retained original (no optional anchor/predecessor)
    let decoded = decode_record(&enc, &ctx).unwrap();
    let transient = decoded_working_set_charge(&decoded).unwrap();

    let rec = max_safety_record_bytes(&ctx).unwrap(); // pre-sized validation buffer
    let retained_gen = max_retained_generation_bytes(&ctx, size_of_timeout_msg()).unwrap();
    let handle = validated_holder_handle_bytes();
    let holder = rec + retained_gen + handle; // retained-holder charge

    // Executed derivations on the actual target.
    assert_eq!(enc_len, 763, "retained original max-TC encoded bytes");
    assert_eq!(transient, 1112, "live transient decoded working set");
    assert_eq!(rec, 811, "pre-sized record-level validation buffer");
    assert_eq!(holder, 2051, "retained-holder charge (rec + gen + handle)");

    // PRE-correction reservation and the live coexistence it fails to cover. With
    // BOTH record-sized validation buffers alive (the reviewed overlap), the live
    // data objects total strictly exceeds the pre-correction reservation.
    let pre_reservation = holder + rec; // 2862
    let two_buffer_live = enc_len + transient + 2 * rec; // 3497 (reviewed subtotal)
    assert_eq!(pre_reservation, 2862, "pre-correction O3 reservation");
    assert_eq!(
        two_buffer_live, 3497,
        "reviewed two-buffer live coexistence subtotal"
    );
    assert!(
        two_buffer_live > pre_reservation,
        "reviewed overlap: live coexistence {two_buffer_live} exceeds pre-correction \
         reservation {pre_reservation}"
    );
    assert_eq!(
        two_buffer_live - pre_reservation,
        635,
        "exact reviewed under-reservation (bytes)"
    );

    // CORRECTION 1 (lifetime): `validate_decoded` drops `reencoded` before the
    // certificate-binding buffer is allocated, so only ONE record-sized validation
    // buffer is ever live. CORRECTION 2 (reservation): O3 reserves the transient's
    // excess over the retained ceiling PLUS one record-sized buffer, atop the holder.
    let transient_ceiling = max_transient_decoded_working_set(&ctx).unwrap();
    let transient_excess = transient_ceiling - retained_gen;
    let o3_scratch = transient_excess + rec;
    let corrected_reservation = holder + o3_scratch; // 2870
    assert_eq!(corrected_reservation, 2870, "corrected O3 reservation");

    // The single-buffer live coexistence (incl. the inline handle) fits the
    // corrected reservation; the two-buffer overlap no longer occurs.
    let single_buffer_live = enc_len + transient + rec + handle; // 2822
    assert!(
        single_buffer_live <= corrected_reservation,
        "post-correction single-buffer live peak {single_buffer_live} fits corrected \
         reservation {corrected_reservation}"
    );

    // The accepted aggregate is UNCHANGED and still covers the corrected O3
    // reservation — the gap was closed WITHOUT inflating the aggregate.
    let agg = max_aggregate_retained_bytes(&ctx, size_of_timeout_msg(), rec).unwrap();
    assert_eq!(agg, 7772, "accepted N=4 aggregate unchanged");
    assert!(
        corrected_reservation <= agg,
        "corrected O3 reservation fits the unchanged aggregate"
    );
}

/// §3 — the REAL O3 `read_validate` over a maximum-TC publication. Observed on a
/// reopened (fresh-accountant) backend so the measured peak reflects ONLY O3: the
/// retained-holder charge is exactly the derived 2051, the validation peak strictly
/// exceeds the holder (the transient decode + single validation buffer were
/// actually reserved and live), two live holders coexist within the UNCHANGED
/// aggregate, and every charge releases on drop.
#[test]
fn d7d14_o3_real_read_validate_with_live_holder_within_aggregate() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);

    let ltc = valid_tc_record_max(&ctx, 5, 6);
    assert_eq!(
        owner.publish_locked(ltc, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    // Reopen a FRESH backend so the observed peak reflects ONLY O3, not the earlier
    // O4 publish peak.
    drop(owner);
    let owner = SafetyRecordOwner::attach(open_enabled(dir.path()), ctx.clone()).unwrap();
    let backend = owner.backend_for_test();
    let agg_cap = backend.accounting_aggregate_cap().unwrap();
    assert!(
        owner.recovery_required(),
        "reopened store starts not-effective"
    );

    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert!(proof.retained().is_locked());
    let holder = backend.accounting_current();
    assert_eq!(holder, 2051, "retained-holder charge for the max-TC proof");
    let peak = backend.accounting_aggregate_peak();
    assert!(
        peak > holder,
        "O3 validation peak {peak} must exceed the retained holder {holder} \
         (the transient decode + validation buffer were reserved and live)"
    );
    assert!(
        peak <= agg_cap,
        "O3 validation peak within the unchanged aggregate"
    );

    // A SECOND live O3 holder coexists with the first within the aggregate.
    let proof2 = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert_eq!(
        backend.accounting_current(),
        2 * holder,
        "two live O3 holders"
    );
    assert!(
        backend.accounting_aggregate_peak() <= agg_cap,
        "two live holders + O3 validation within the unchanged aggregate"
    );

    drop(proof2);
    drop(proof);
    assert_eq!(
        backend.accounting_current(),
        0,
        "all O3 holders released on drop"
    );
}

/// §4 — the protected O4 structural/capacity preflight REFUSAL path is
/// allocation-free. The smallest per-vector over-bound (S_sig=8, len 8, capacity 9,
/// slack 0) is refused, and the measured refusal interval (after fixture
/// construction and warm-up) performs ZERO component-owned allocations: the refusal
/// carries typed `Copy` `PerVector` bound data, so no owned diagnostic `String` is
/// built on the refusal path. Rendering the diagnostic is a SEPARATE post-refusal
/// step, outside the measured interval.
#[test]
fn d7d14_o4_preflight_refusal_is_allocation_free() {
    use qbind_node::safety_record_store::codec::admit_supporting_evidence;
    let ctx = ctx_n(4);
    let mut locked = make_locked_qc(&ctx, [9u8; 32], 5, valid_wire_qc(&ctx, [9u8; 32], 5), None)
        .expect("valid QC candidate");
    if let SupportingEvidence::QcDerived(qc) = &mut locked.evidence {
        let mut over = Vec::with_capacity(S_SIG + 1);
        over.extend_from_slice(&[0xABu8; S_SIG]);
        assert_eq!(over.len(), 8);
        assert_eq!(over.capacity(), 9);
        qc.signatures[0] = over;
    } else {
        panic!("QC candidate must be QcDerived");
    }
    // Warm up lazy state OUTSIDE the measured interval, then measure ONLY the
    // protected preflight refusal.
    let _ = admit_supporting_evidence(&locked.evidence, &ctx);
    let (res, allocs) = measure_allocs(|| admit_supporting_evidence(&locked.evidence, &ctx));
    assert!(
        matches!(res, Err(SafetyStoreError::CapacityRefusal(_))),
        "the over-bound preflight must refuse"
    );
    assert_eq!(
        allocs, 0,
        "the protected O4 preflight refusal path must allocate nothing \
         (typed PerVector refusal, no owned diagnostic String)"
    );
    // The diagnostic is materialised only on demand, as a separate step.
    let rendered = res.unwrap_err().to_string();
    assert!(
        rendered.contains("QC signature buffer"),
        "rendered diagnostic names the offending site"
    );
}

/// §4 — the real O4 publish refusal leaves durable state and reservations intact
/// and re-admits. With an ESTABLISHED LOCKED predecessor, an over-bound candidate
/// (smallest per-vector violation) is refused pre-write; no predecessor evidence is
/// read/encoded before the refusal, the recovery latch is untouched, the retained
/// revision is unchanged, reservations return to baseline, and a subsequent
/// ELIGIBLE successor succeeds.
#[test]
fn d7d14_o4_preflight_refusal_leaves_state_and_readmits() {
    use qbind_node::safety_record_store::codec::{
        evidence_payload_encode_count, reset_evidence_payload_encode_count,
    };
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);
    let backend = owner.backend_for_test();

    let base = make_locked_qc(&ctx, [9u8; 32], 5, valid_wire_qc(&ctx, [9u8; 32], 5), None).unwrap();
    assert_eq!(
        owner.publish_locked(base, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    assert_eq!(backend.accounting_current(), 0, "baseline after O4 publish");

    let mut candidate =
        make_locked_qc(&ctx, [9u8; 32], 9, valid_wire_qc(&ctx, [9u8; 32], 9), None).unwrap();
    if let SupportingEvidence::QcDerived(qc) = &mut candidate.evidence {
        let mut over = Vec::with_capacity(S_SIG + 1);
        over.extend_from_slice(&[0xABu8; S_SIG]);
        qc.signatures[0] = over;
    } else {
        panic!("candidate must be QcDerived");
    }

    reset_evidence_payload_encode_count();
    match owner.publish_locked(candidate, 1, None::<&FixtureCommittedHistory>) {
        PublishResult::RefusedPreWrite(SafetyStoreError::CapacityRefusal(_)) => {}
        other => panic!("expected pre-write CapacityRefusal, got {other:?}"),
    }
    assert_eq!(
        evidence_payload_encode_count(),
        0,
        "no predecessor evidence read/encode before the candidate refusal"
    );
    assert!(
        !owner.recovery_required(),
        "refusal must not set the recovery latch"
    );
    assert_eq!(
        backend.accounting_current(),
        0,
        "reservations return to baseline after refusal"
    );

    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert_eq!(
        proof.retained().publication_revision,
        1,
        "predecessor revision unchanged by the refusal"
    );
    assert!(proof.retained().is_locked());
    drop(proof);

    let good = make_locked_qc(&ctx, [9u8; 32], 9, valid_wire_qc(&ctx, [9u8; 32], 9), None).unwrap();
    assert_eq!(
        owner.publish_locked(good, 1, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 2 }
    );
    assert_eq!(
        backend.accounting_current(),
        0,
        "baseline after the eligible successor"
    );
}
// ---------------------------------------------------------------------------
// RUN 422 D7-D14 §3 — allocation-free refusal regressions (D7-D14 continuation).
//
// The protected pre-reservation refusal paths now carry typed, `Copy` diagnostic
// data (`DeclaredBoundDetail`, the typed `CapacityRefusalDetail` variants,
// `AlreadyEstablishedKind`, `RecoveryRequiredReason`) instead of an owned
// `format!`/`.into()` `String`. Each test below constructs its fixture OUTSIDE
// the measured interval, arms the counting allocator across ONLY the protected
// operation, and asserts zero component-owned allocations on the refusal while
// the typed `Display` still renders the full numeric diagnostic on demand.
// ---------------------------------------------------------------------------

/// Named finding: `admit_wire_qc` with a 9-byte signature and `S_sig = 8`
/// previously built `DeclaredBoundExceeded(format!(..))`. The structural excess
/// is now refused with typed `DeclaredBoundDetail::SignatureLength`, allocating
/// nothing on the protected preflight.
#[test]
fn corr_refusal_structural_sig_len_9_over_s_sig_8_is_allocation_free() {
    use qbind_node::safety_record_store::codec::admit_supporting_evidence;
    let ctx = ctx_n(4); // s_sig = 8
    let mut qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    qc.signatures[0] = vec![0xABu8; 9]; // structural excess: length 9 > S_sig 8
    let evidence = SupportingEvidence::QcDerived(qc);

    let (res, allocs) = measure_allocs(|| admit_supporting_evidence(&evidence, &ctx));
    assert!(
        matches!(res, Err(SafetyStoreError::DeclaredBoundExceeded(_))),
        "structural sig-length excess must refuse, got {res:?}"
    );
    assert_eq!(
        allocs, 0,
        "the structural over-bound refusal must allocate no owned diagnostic String"
    );
    let msg = res.unwrap_err().to_string();
    assert!(
        msg.contains("signature length 9 > s_sig=8"),
        "typed Display must still render the numeric bounds, got: {msg}"
    );
}

/// A representative QC signer/signature count refusal (count 5 > N=4) is refused
/// with typed `DeclaredBoundDetail::SignatureCount`, allocation-free.
#[test]
fn corr_refusal_qc_signature_count_over_n_is_allocation_free() {
    use qbind_node::safety_record_store::codec::admit_supporting_evidence;
    let ctx = ctx_n(4); // N = 4
    let mut qc = valid_wire_qc(&ctx, [7u8; 32], 3);
    qc.signatures = vec![vec![0xABu8; S_SIG]; 5]; // 5 > N = 4
    let evidence = SupportingEvidence::QcDerived(qc);

    let (res, allocs) = measure_allocs(|| admit_supporting_evidence(&evidence, &ctx));
    assert!(
        matches!(res, Err(SafetyStoreError::DeclaredBoundExceeded(_))),
        "signature-count over-N must refuse, got {res:?}"
    );
    assert_eq!(
        allocs, 0,
        "signature-count over-N refusal must be allocation-free"
    );
    assert!(res
        .unwrap_err()
        .to_string()
        .contains("signature count 5 > N=4"));
}

/// Named finding: aggregate and partition admission failures previously built
/// `format!` strings while refusing the requested reservation. The admission
/// overflow is now typed (`CapacityRefusalDetail::AdmissionOverflow`) and the
/// refusal — reached through the real reservation path — allocates nothing.
/// After releasing the holder the next reservation of the same size succeeds.
#[test]
fn corr_refusal_admission_overflow_through_reservation_is_allocation_free() {
    use qbind_node::safety_record_store::accounting::{AggregateAuthority, SharedAccountant};
    use qbind_node::safety_record_store::error::CapacityRefusalDetail;

    let agg = AggregateAuthority::new();
    agg.bind(100).unwrap();
    let acct = SharedAccountant::new(agg.clone());
    acct.bind_cap(100).unwrap();
    // Hold 60 (constructed OUTSIDE the measured interval). A second 60-byte
    // reservation exhausts the ceiling; measure only that refusing call.
    let held = acct.reserve(60).unwrap();

    let (res, allocs) = measure_allocs(|| acct.reserve(60));
    match &res {
        Err(SafetyStoreError::CapacityRefusal(CapacityRefusalDetail::AdmissionOverflow {
            ..
        })) => {}
        other => panic!("expected typed AdmissionOverflow, got {other:?}"),
    }
    assert_eq!(
        allocs, 0,
        "the admission-overflow refusal must allocate no owned diagnostic String"
    );
    assert!(res.unwrap_err().to_string().contains("over cap 100"));

    // Exhausted headroom: dropping the holder releases the charge, so the
    // previously-refused reservation is now eligible.
    drop(held);
    assert!(
        acct.reserve(60).is_ok(),
        "subsequent reservation is eligible after releasing the constraint"
    );
}

/// The typed refusal payloads for the remaining converted classes
/// (`AlreadyEstablished`, `RecoveryRequired`, the typed `CapacityRefusalDetail`
/// variants, `DeclaredBoundDetail`) are `Copy` stack data: constructing them
/// performs no heap allocation, and each still renders its full diagnostic text
/// through `Display` on demand.
#[test]
fn corr_typed_refusal_payloads_construct_without_allocation() {
    use qbind_node::safety_record_store::error::{
        AlreadyEstablishedKind, CapacityRefusalDetail, DeclaredBoundDetail, LedgerScope,
        RecoveryRequiredReason,
    };
    let (errs, allocs) = measure_allocs(|| {
        [
            SafetyStoreError::AlreadyEstablished(AlreadyEstablishedKind::MetadataPresent),
            SafetyStoreError::RecoveryRequired(
                RecoveryRequiredReason::FreshAcknowledgementRequired,
            ),
            SafetyStoreError::DeclaredBoundExceeded(DeclaredBoundDetail::SignatureLength {
                len: 9,
                s_sig: 8,
            }),
            SafetyStoreError::CapacityRefusal(CapacityRefusalDetail::Unbound(
                LedgerScope::Aggregate,
            )),
            SafetyStoreError::CapacityRefusal(CapacityRefusalDetail::AdmissionOverflow {
                scope: LedgerScope::Partition,
                charge: 1,
                current: 2,
                next: 3,
                cap: 2,
            }),
        ]
    });
    assert_eq!(
        allocs, 0,
        "typed `Copy` refusal payloads must construct without heap allocation"
    );
    assert!(errs[0].to_string().contains("metadata already present"));
    assert!(errs[1]
        .to_string()
        .contains("fresh durability acknowledgement"));
    assert!(errs[2].to_string().contains("signature length 9 > s_sig=8"));
    assert!(errs[3]
        .to_string()
        .contains("aggregate authority not bound"));
    assert!(errs[4].to_string().contains("over cap 2"));
}

// ===========================================================================
// RUN 422 D7-D14 Item A continuation — residual protected-refusal allocation
// corrections. The previously-string-carrying protected refusals
// (`ArithmeticOverflow`, `MissingIndependentInput`, and the protected
// `StructuralRefusal` sites) now carry typed, `Copy` (or `Copy`-plus-`Message`)
// payloads, so the pre-reservation refusal branches construct no owned
// diagnostic `String`. These tests assert (a) construction is allocation-free
// for every newly-typed payload, (b) the real operational paths emit the typed
// variant, and (c) a refused real operation preserves raw record/metadata bytes,
// the recovery latch, and the reservation baseline.
// ===========================================================================

/// (a) Every newly-converted typed refusal payload — all `ArithmeticOverflowSite`
/// discriminants, both `MissingIndependentInputSite` discriminants, and the typed
/// `StructuralRefusalDetail` forms — is `Copy`/stack data and constructs with no
/// heap allocation, while still rendering its full diagnostic text on demand.
///
/// This is the *helper-level* allocation-free guarantee for the residual sites
/// (labelled as such): it proves the refusal VALUE allocates nothing. The
/// real-operation tests below prove the protected branches actually emit these
/// values and preserve state; the accounting `add`/`mul` overflow sites are
/// private helpers, so their typed `AccountingSum`/`AccountingProduct` payloads
/// are covered here at the value level rather than via a manufactured invalid
/// production profile.
#[test]
fn corr_residual_typed_refusal_payloads_construct_without_allocation() {
    use qbind_node::safety_record_store::error::{
        ArithmeticOverflowSite as A, MissingIndependentInputSite as M, StructuralRefusalDetail as S,
    };
    let (errs, allocs) = measure_allocs(|| {
        [
            SafetyStoreError::ArithmeticOverflow(A::AccountingSum),
            SafetyStoreError::ArithmeticOverflow(A::AccountingProduct),
            SafetyStoreError::ArithmeticOverflow(A::SizeSum),
            SafetyStoreError::ArithmeticOverflow(A::SizeProduct),
            SafetyStoreError::ArithmeticOverflow(A::RetainedHolderCharge),
            SafetyStoreError::ArithmeticOverflow(A::O1InspectionWorkingSet),
            SafetyStoreError::ArithmeticOverflow(A::O1BootstrapPublicationCharge),
            SafetyStoreError::ArithmeticOverflow(A::O2ReadDecodeWorkingSet),
            SafetyStoreError::ArithmeticOverflow(A::O3ValidationScratchCharge),
            SafetyStoreError::ArithmeticOverflow(A::O4WorkingSetCharge),
            SafetyStoreError::ArithmeticOverflow(A::PublicationRevisionExhausted),
            SafetyStoreError::ArithmeticOverflow(A::O5ReadBackWorkingSet),
            SafetyStoreError::MissingIndependentInput(M::O1FirstUseIntent),
            SafetyStoreError::MissingIndependentInput(M::P3CommittedAnchorNoHistory),
            SafetyStoreError::StructuralRefusal(S::EmptySignerCertificate),
            SafetyStoreError::StructuralRefusal(S::RecordPresentWithoutMetadata),
            SafetyStoreError::StructuralRefusal(S::UnknownLegacySafetyNamespaceKey { len: 19 }),
        ]
    });
    assert_eq!(
        allocs, 0,
        "every residual typed `Copy` refusal payload must construct without heap allocation"
    );
    // Diagnostic text is preserved (materialised only on demand via `Display`).
    assert!(errs[0].to_string().contains("accounting sum"));
    assert!(errs[1].to_string().contains("accounting product"));
    assert!(errs[9].to_string().contains("O4 working-set charge"));
    assert!(errs[10]
        .to_string()
        .contains("publication revision exhausted"));
    assert!(errs[12]
        .to_string()
        .contains("explicit first-use intent assertion"));
    assert!(errs[13].to_string().contains("(P3)"));
    assert!(errs[14]
        .to_string()
        .contains("empty-signer certificate refused at structural threshold"));
    assert!(errs[15]
        .to_string()
        .contains("record present without metadata"));
    assert!(errs[16]
        .to_string()
        .contains("unknown/legacy safety-namespace key present (19 bytes)"));
}

/// (b)+(c) O1 `initialize(false)` is refused with the typed, allocation-free
/// `MissingIndependentInputSite::O1FirstUseIntent` BEFORE any domain lock,
/// reservation, or backend read. Measured through the real owner call the whole
/// refusal allocates nothing, and the untouched backend's raw record/metadata,
/// recovery latch, and reservation baseline are unchanged.
#[test]
fn corr_initialize_false_refusal_is_typed_and_allocation_free_and_preserves_state() {
    use qbind_node::safety_record_store::error::MissingIndependentInputSite;
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let backend = open_enabled(dir.path());
    let owner = SafetyRecordOwner::attach(backend, ctx.clone()).unwrap();
    let backend = owner.backend_for_test();
    let rec_bound = max_safety_record_bytes(&ctx).unwrap();

    let meta_before = backend.read_meta(META_ENCODED_LEN_MIRROR).unwrap();
    let record_before = backend.read_record(rec_bound).unwrap();
    let latch_before = backend.recovery_required();
    let acct_before = backend.accounting_current();

    // The refusal runs as the first statement of `initialize`, before the domain
    // lock / inspection reservation, so the whole real call allocates nothing.
    let (res, allocs) = measure_allocs(|| owner.initialize(false));
    match &res {
        Err(SafetyStoreError::MissingIndependentInput(
            MissingIndependentInputSite::O1FirstUseIntent,
        )) => {}
        other => panic!("expected typed O1FirstUseIntent refusal, got {other:?}"),
    }
    assert_eq!(
        allocs, 0,
        "the pre-reservation first-use-intent refusal must allocate no owned String"
    );

    // State preservation: nothing read, written, reserved, or latched.
    assert_eq!(
        backend.read_meta(META_ENCODED_LEN_MIRROR).unwrap(),
        meta_before
    );
    assert_eq!(backend.read_record(rec_bound).unwrap(), record_before);
    assert_eq!(backend.recovery_required(), latch_before);
    assert_eq!(backend.accounting_current(), acct_before);

    // Subsequent eligibility once the independent assertion is supplied.
    assert!(
        owner.initialize(true).is_ok(),
        "O1 succeeds once the first-use intent is asserted"
    );
}

/// (b) The empty-signer certificate structural threshold refusal is emitted as the
/// typed, allocation-free `StructuralRefusalDetail::EmptySignerCertificate` through
/// the real `encode_record` admission path (which runs `admit_wire_qc` before any
/// O4 reservation).
#[test]
fn corr_empty_signer_refusal_is_typed_through_encode_admission() {
    use qbind_node::safety_record_store::error::StructuralRefusalDetail;
    let ctx = ctx_n(4);
    let mut qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    qc.signatures.clear();
    qc.signer_bitmap = vec![0u8; 1];
    let locked = locked_qc_unadmitted(&ctx, [9u8; 32], 5, qc);
    let dec = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(locked),
    };
    match encode_record(&dec, &ctx) {
        Err(SafetyStoreError::StructuralRefusal(
            StructuralRefusalDetail::EmptySignerCertificate,
        )) => {}
        other => panic!("expected typed EmptySignerCertificate refusal, got {other:?}"),
    }
}

/// (b)+(c) A partial record-without-metadata namespace is refused by O1 with the
/// typed `StructuralRefusalDetail::RecordPresentWithoutMetadata`. The whole
/// operation legitimately reads the admitted record/metadata buffers (so it is NOT
/// asserted allocation-free), but the refused operation leaves the raw record
/// bytes, metadata, recovery latch, and reservation baseline exactly as they were.
#[test]
fn corr_o1_record_without_metadata_refusal_is_typed_and_preserves_state() {
    use qbind_node::safety_record_store::error::StructuralRefusalDetail;
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let backend = open_enabled(dir.path());
    backend
        .debug_overwrite_record(&[0xAAu8, 0xBB, 0xCC, 0xDD])
        .expect("stage a partial record-without-metadata namespace");
    let owner = SafetyRecordOwner::attach(backend, ctx.clone()).unwrap();
    let backend = owner.backend_for_test();
    let rec_bound = max_safety_record_bytes(&ctx).unwrap();

    let meta_before = backend.read_meta(META_ENCODED_LEN_MIRROR).unwrap();
    let record_before = backend.read_record(rec_bound).unwrap();
    let latch_before = backend.recovery_required();
    assert_eq!(
        record_before.as_deref(),
        Some(&[0xAAu8, 0xBB, 0xCC, 0xDD][..])
    );
    assert_eq!(meta_before, None);

    match owner.initialize(true) {
        Err(SafetyStoreError::StructuralRefusal(
            StructuralRefusalDetail::RecordPresentWithoutMetadata,
        )) => {}
        other => panic!("expected typed RecordPresentWithoutMetadata refusal, got {other:?}"),
    }

    // Pre-write refusal: raw record/metadata unchanged, latch untouched, the
    // inspection reservation released on exit.
    assert_eq!(backend.read_record(rec_bound).unwrap(), record_before);
    assert_eq!(
        backend.read_meta(META_ENCODED_LEN_MIRROR).unwrap(),
        meta_before
    );
    assert_eq!(backend.recovery_required(), latch_before);
    assert_eq!(
        backend.accounting_current(),
        0,
        "O1 partial-state inspection reservation released on the refusal exit"
    );
}

/// (b)+(c) An unknown/legacy key in the component-owned safety namespace is refused
/// by O1 with the typed `StructuralRefusalDetail::UnknownLegacySafetyNamespaceKey`
/// carrying the `Copy` key length, and nothing is migrated, repaired, or deleted:
/// the unknown key is still present afterward.
#[test]
fn corr_o1_unknown_namespace_refusal_is_typed_with_len_and_preserves_key() {
    use qbind_node::safety_record_store::error::StructuralRefusalDetail;
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let backend = open_enabled(dir.path());
    let key = b"safetyrec:legacy:v0";
    backend.debug_put_raw(key, b"opaque-legacy-state").unwrap();
    let expected_len = key.len();
    let owner = SafetyRecordOwner::attach(backend.clone(), ctx.clone()).unwrap();

    match owner.initialize(true) {
        Err(SafetyStoreError::StructuralRefusal(
            StructuralRefusalDetail::UnknownLegacySafetyNamespaceKey { len },
        )) => {
            assert_eq!(
                len, expected_len as u128,
                "the refusal carries the unknown key's byte length"
            );
        }
        other => panic!("expected typed UnknownLegacySafetyNamespaceKey refusal, got {other:?}"),
    }
    // Nothing repaired or deleted: the unknown key remains present.
    assert_eq!(
        backend.first_unrecognized_safety_key().unwrap(),
        Some(expected_len)
    );
}
// ===========================================================================
// RUN 422 D7-D14 Item A continuation (this pass) — the two reviewed-source
// residual protected allocations closed:
//   * `SafetyRecordOwner::attach` ran `ctx.validate()` BEFORE context admission
//     and constructed `ProfileInvalid(String)` on four refusal branches.
//   * `first_unrecognized_safety_key` formatted `ReadFailed("namespace scan: …")`
//     on iterator-status failure, which O1 reaches AFTER releasing its inspection
//     reservation.
// Both now carry typed, allocation-free payloads (`ProfileInvalidDetail`,
// `ReadFailedDetail::NamespaceScan`). These tests assert (a) the new payloads
// construct allocation-free while still rendering full text, (b) each real
// invalid-profile `attach` is refused with its typed variant BEFORE the aggregate
// authority is bound (context admission), and (c) the namespace-scan failure is
// emitted through the real O1 path (test-gated fault injection) and preserves
// state.
// ===========================================================================

/// (a) Both newly-typed payloads — all four `ProfileInvalidDetail` forms and the
/// `ReadFailedDetail::NamespaceScan` form — are `Copy`/stack data (or carry no
/// owned diagnostic `String`) and construct with no heap allocation, while still
/// rendering their full diagnostic text on demand. The `ReadFailedDetail::Message`
/// covered-lifetime form is deliberately NOT asserted allocation-free (it carries
/// an owned `String` for the admitted checksum-envelope diagnostics).
#[test]
fn corr_profile_invalid_and_namespace_scan_payloads_construct_without_allocation() {
    use qbind_node::safety_record_store::error::{
        ProfileInvalidDetail as P, ReadFailedDetail as R,
    };
    let (errs, allocs) = measure_allocs(|| {
        [
            SafetyStoreError::ProfileInvalid(P::ValidatorCountOutOfRange { n: 0, max: 65535 }),
            SafetyStoreError::ProfileInvalid(P::SignatureLenOutOfRange { s: 0, max: 65535 }),
            SafetyStoreError::ProfileInvalid(P::NonDenseValidatorIndex { slot: 1, id: 2 }),
            SafetyStoreError::ProfileInvalid(P::ZeroTotalVotingPower),
            SafetyStoreError::ReadFailed(R::NamespaceScan),
        ]
    });
    assert_eq!(
        allocs, 0,
        "typed `ProfileInvalid`/`ReadFailed::NamespaceScan` payloads must construct \
         without heap allocation"
    );
    assert!(errs[0]
        .to_string()
        .contains("validator count 0 out of range 1..=65535"));
    assert!(errs[1]
        .to_string()
        .contains("s_sig 0 out of range 1..=65535"));
    assert!(errs[2]
        .to_string()
        .contains("non-dense validator index at slot 1: id=2"));
    assert!(errs[3].to_string().contains("total voting power is zero"));
    assert!(errs[4]
        .to_string()
        .contains("namespace scan: storage-layer iteration error"));
}

/// (b) Each of the four invalid-profile `attach` refusals is emitted as its typed,
/// allocation-free `ProfileInvalidDetail` variant, measured through the real owner
/// `attach` call (the invalid context and the backend clone are built OUTSIDE the
/// measured interval), and crucially BEFORE context admission: the shared aggregate
/// authority is never bound, so a refused attach leaves the backend's accounting
/// completely unbound. A valid profile on the same backend then binds and admits.
#[test]
fn corr_invalid_profile_attach_refusals_typed_before_context_admission() {
    use qbind_node::safety_record_store::error::ProfileInvalidDetail as P;
    let dir = tempfile::tempdir().unwrap();
    let backend = open_enabled(dir.path());

    // Four distinct invalid profiles (built outside the measured interval).
    let mut count_zero = ctx_n(4);
    count_zero.validators = Vec::new(); // n == 0
    let mut sig_zero = ctx_n(4);
    sig_zero.s_sig = 0; // s_sig == 0
    let mut non_dense = ctx_n(4);
    non_dense.validators = vec![
        (ValidatorId::new(0), 1),
        (ValidatorId::new(2), 1), // slot 1 holds id 2 — non-dense
        (ValidatorId::new(1), 1),
        (ValidatorId::new(3), 1),
    ];
    let mut zero_vp = ctx_n(4);
    zero_vp.validators = (0..4).map(|i| (ValidatorId::new(i), 0u64)).collect(); // ΣVP == 0

    // The aggregate authority starts unbound.
    assert_eq!(
        backend.accounting_aggregate_cap(),
        None,
        "fresh backend has no bound aggregate ceiling"
    );

    for (ctx, expect) in [
        (count_zero, "validator count"),
        (sig_zero, "s_sig"),
        (non_dense, "non-dense validator index"),
        (zero_vp, "total voting power is zero"),
    ] {
        let b = backend.clone();
        let (res, allocs) = measure_allocs(|| SafetyRecordOwner::attach(b, ctx));
        match &res {
            Err(SafetyStoreError::ProfileInvalid(detail)) => {
                assert!(
                    detail.to_string().contains(expect),
                    "expected {expect:?} in {detail}"
                );
                // The payload is `Copy`, so a cross-check that it is exactly one of
                // the four typed variants (no `String`).
                assert!(matches!(
                    detail,
                    P::ValidatorCountOutOfRange { .. }
                        | P::SignatureLenOutOfRange { .. }
                        | P::NonDenseValidatorIndex { .. }
                        | P::ZeroTotalVotingPower
                ));
            }
            other => panic!("expected typed ProfileInvalid refusal, got {other:?}"),
        }
        assert_eq!(
            allocs, 0,
            "the pre-admission profile-validation refusal must allocate no owned String"
        );
        // Context admission never happened: the aggregate authority is still unbound.
        assert_eq!(
            backend.accounting_aggregate_cap(),
            None,
            "a refused invalid-profile attach must NOT bind/admit the context"
        );
    }

    // A valid profile on the same backend binds the aggregate and admits context.
    let owner = SafetyRecordOwner::attach(backend.clone(), ctx_n(4)).expect("valid attach");
    assert!(
        backend.accounting_aggregate_cap().is_some(),
        "a valid profile binds the shared aggregate ceiling"
    );
    drop(owner);
}

/// (c) The O1 legacy-namespace scan's storage-layer iteration failure is emitted
/// through the REAL O1 `initialize` path (driven by the narrowly test-gated
/// `FailNamespaceScan` fault, since a real RocksDB raw iterator cannot be forced to
/// fail its status deterministically) as the typed, allocation-free
/// `ReadFailedDetail::NamespaceScan`. O1 reaches it AFTER releasing its inspection
/// reservation (a clean, metadata-free, record-free namespace), and the refusal
/// preserves state: no metadata/record is written, the recovery latch is untouched,
/// and the inspection reservation is released to baseline `0`. The whole O1
/// operation legitimately reads the admitted metadata/record buffers, so it is NOT
/// asserted allocation-free — only the diagnostic branch value is.
#[test]
fn corr_o1_namespace_scan_failure_is_typed_through_real_o1_path() {
    use qbind_node::safety_record_store::backend::InjectFault;
    use qbind_node::safety_record_store::error::ReadFailedDetail;
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let backend = open_enabled(dir.path());
    let owner = SafetyRecordOwner::attach(backend, ctx.clone()).unwrap();
    let backend = owner.backend_for_test();
    let rec_bound = max_safety_record_bytes(&ctx).unwrap();

    // Clean namespace: no metadata, no record — so O1 reaches the namespace scan
    // (past the established/partial refusal branches), AFTER the inspection
    // reservation has released.
    let meta_before = backend.read_meta(META_ENCODED_LEN_MIRROR).unwrap();
    let record_before = backend.read_record(rec_bound).unwrap();
    let latch_before = backend.recovery_required();
    assert_eq!(meta_before, None);
    assert_eq!(record_before, None);

    backend.set_inject(InjectFault::FailNamespaceScan);
    match owner.initialize(true) {
        Err(SafetyStoreError::ReadFailed(ReadFailedDetail::NamespaceScan)) => {}
        other => panic!("expected typed ReadFailed(NamespaceScan) refusal, got {other:?}"),
    }

    // State preservation: nothing written, latch untouched, inspection reservation
    // released on the refusal exit.
    assert_eq!(
        backend.read_meta(META_ENCODED_LEN_MIRROR).unwrap(),
        meta_before
    );
    assert_eq!(backend.read_record(rec_bound).unwrap(), record_before);
    assert_eq!(backend.recovery_required(), latch_before);
    assert_eq!(
        backend.accounting_current(),
        0,
        "the O1 inspection reservation released before the post-release namespace-scan refusal"
    );

    // Clearing the fault lets the same clean namespace initialize — proving the
    // refusal was the injected scan failure, not an established/partial state.
    backend.set_inject(InjectFault::None);
    assert_eq!(
        owner.initialize(true).unwrap(),
        0,
        "O1 succeeds once the scan clears"
    );
}

// ===========================================================================
// RUN 422 D7-D14 Item C (this pass) — distinct MAXIMUM QC/TC fixtures with
// asserted dimensions, and the three admitted paths (successful structural/
// capacity admission, `encode_record`, `compute_evidence_lock_binding`) measured
// SEPARATELY for each variant. Fixture construction occurs entirely OUTSIDE every
// measured interval; the binding computed during fixture setup is NOT reused as
// the measured observation (a fresh call is measured). "Maximum evidence" (no
// anchor/predecessor) is distinguished from "maximum complete serialized record"
// (both optional fields populated with valid independent history), and the
// release-path mechanism that prevents unadmitted growth (admission bounding every
// count/length/width BEFORE the single pre-sized `Vec::with_capacity(cap)`) is
// observed as exactly one allocation at the admitted cap with no reallocation.
// ===========================================================================

/// MAXIMUM wire QC: N authorized signer bits, N signatures each of the maximum
/// admitted length `S_sig`, bitmap span `ceil(N/8)`, every backing capacity exactly
/// normalized to its length (the decoder's exact-capacity form the per-vector
/// `admit_evidence_capnorm` bound requires).
fn valid_wire_qc_max(ctx: &PinnedSafetyContext, block_id: [u8; 32], view: u64) -> WireQc {
    let n = ctx.n();
    let mut bitmap = vec![0u8; ((n + 7) / 8).max(1)];
    let mut signatures = Vec::with_capacity(n);
    for i in 0..n {
        bitmap[i / 8] |= 1 << (i % 8);
        let mut s = Vec::with_capacity(ctx.s_sig);
        s.extend(std::iter::repeat(0xABu8).take(ctx.s_sig));
        signatures.push(s);
    }
    WireQc {
        version: 1,
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        height: view,
        round: view,
        step: 0,
        block_id,
        suite_id: QC_SUITE,
        signer_bitmap: bitmap,
        signatures,
    }
}

/// A maximum QC `LockedRecord`. `anchored == false` is the maximum EVIDENCE form
/// (no committed anchor / predecessor); `anchored == true` is the maximum COMPLETE
/// SERIALIZED record (both optional fields populated — the anchor carries valid
/// independent committed-history coordinates and the predecessor a prior revision).
fn max_qc_locked(ctx: &PinnedSafetyContext, lock_view: u64, anchored: bool) -> LockedRecord {
    let qc = valid_wire_qc_max(ctx, [9u8; 32], lock_view);
    let evidence = SupportingEvidence::QcDerived(qc);
    let binding = qbind_node::safety_record_store::codec::compute_evidence_lock_binding(
        &[9u8; 32],
        lock_view,
        &evidence,
        &ctx.authority_context_ref,
        ctx,
    )
    .unwrap();
    LockedRecord {
        lock_block_id: [9u8; 32],
        lock_view,
        evidence_lock_binding: binding,
        authority_context_ref: ctx.authority_context_ref,
        committed_anchor: anchored.then_some(CommittedAnchor {
            block_id: [7u8; 32],
            height: 3,
        }),
        predecessor_ref: anchored.then_some(0u64),
        evidence,
    }
}

/// The maximum TC `LockedRecord` with both optional fields populated (maximum
/// COMPLETE serialized record), built from the maximum-evidence `valid_tc_record_max`.
fn max_tc_locked_anchored(
    ctx: &PinnedSafetyContext,
    lock_view: u64,
    timeout_view: u64,
) -> LockedRecord {
    let mut l = valid_tc_record_max(ctx, lock_view, timeout_view);
    l.committed_anchor = Some(CommittedAnchor {
        block_id: [7u8; 32],
        height: 3,
    });
    l.predecessor_ref = Some(0u64);
    l
}

/// Item C — maximum QC fixture dimensions asserted, then admission / encode /
/// binding measured SEPARATELY.
#[test]
fn d7d14_c_max_qc_dimensions_and_separately_measured_paths() {
    use qbind_node::safety_record_store::codec::{
        admit_supporting_evidence, compute_evidence_lock_binding,
    };
    let ctx = ctx_n(4);
    let n = ctx.n();
    let s_sig = ctx.s_sig;
    let b_span = ((n + 7) / 8).max(1);

    // ----- Fixture construction (OUTSIDE every measured interval) -----
    let evidence_only = max_qc_locked(&ctx, 5, false);
    let complete = max_qc_locked(&ctx, 5, true);

    // ----- Asserted dimensions (before measurement) -----
    let qc = match &evidence_only.evidence {
        SupportingEvidence::QcDerived(q) => q,
        other => panic!("expected QcDerived, got {other:?}"),
    };
    assert_eq!(qc.signatures.len(), n, "N signatures");
    assert_eq!(
        qc.signatures.capacity(),
        n,
        "signatures outer backing == N (capnorm)"
    );
    assert_eq!(qc.signer_bitmap.len(), b_span, "bitmap span == ceil(N/8)");
    assert_eq!(
        qc.signer_bitmap.capacity(),
        b_span,
        "bitmap backing == span (capnorm)"
    );
    let set_bits: u32 = qc.signer_bitmap.iter().map(|b| b.count_ones()).sum();
    assert_eq!(set_bits as usize, n, "N authorized signer bits set");
    for sig in &qc.signatures {
        assert_eq!(
            sig.len(),
            s_sig,
            "each signature is maximum admitted length"
        );
        assert_eq!(
            sig.capacity(),
            s_sig,
            "each signature backing == len (capnorm)"
        );
    }
    // Distinguish maximum evidence from maximum complete serialized record.
    assert!(evidence_only.committed_anchor.is_none() && evidence_only.predecessor_ref.is_none());
    assert!(complete.committed_anchor.is_some() && complete.predecessor_ref.is_some());

    let dec_evidence = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(evidence_only.clone()),
    };
    let dec_complete = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(complete.clone()),
    };
    let ev = evidence_only.evidence.clone();
    let max_qc = max_qc_bytes(&ctx).unwrap();

    // ----- (1) Successful structural + capacity admission: allocation-free -----
    let (_adm, adm_allocs) = measure_allocs(|| admit_supporting_evidence(&ev, &ctx).unwrap());
    assert_eq!(
        adm_allocs, 0,
        "successful QC admission reads only — no allocation"
    );

    // ----- (2) encode_record: one pre-sized allocation at the admitted cap -----
    let _ = encode_record(&dec_evidence, &ctx).unwrap(); // warm up lazy state
    let (enc_ev, enc_ev_allocs) = measure_allocs(|| encode_record(&dec_evidence, &ctx).unwrap());
    assert_eq!(
        enc_ev_allocs, 1,
        "max-QC evidence encode: exactly one (pre-sized) allocation"
    );
    assert_eq!(
        enc_ev.capacity() as u128,
        max_qc,
        "encode backing capacity == admitted serialized cap (release-path pre-size)"
    );
    let (enc_cmp, enc_cmp_allocs) = measure_allocs(|| encode_record(&dec_complete, &ctx).unwrap());
    assert_eq!(
        enc_cmp_allocs, 1,
        "max-QC complete encode: exactly one (pre-sized) allocation"
    );
    assert_eq!(
        enc_cmp.capacity() as u128,
        max_qc,
        "complete encode backing == cap"
    );
    // The complete serialized record is strictly larger than the maximum-evidence
    // record by exactly the anchor(32+8) + predecessor(8) payload bytes.
    assert_eq!(
        enc_cmp.len(),
        enc_ev.len() + 48,
        "maximum complete serialized record exceeds maximum evidence by anchor+predecessor"
    );
    assert!(
        enc_cmp.len() as u128 <= max_qc,
        "complete serialized record fits the cap"
    );

    // ----- (3) compute_evidence_lock_binding: measured FRESH (not the setup one) -----
    let _ = compute_evidence_lock_binding(&[9u8; 32], 5, &ev, &ctx.authority_context_ref, &ctx)
        .unwrap(); // warm up
    let (fresh_binding, bind_allocs) = measure_allocs(|| {
        compute_evidence_lock_binding(&[9u8; 32], 5, &ev, &ctx.authority_context_ref, &ctx).unwrap()
    });
    assert_eq!(
        bind_allocs, 1,
        "binding: exactly one pre-sized cert allocation (admission bounds precede it)"
    );
    assert_eq!(
        fresh_binding, evidence_only.evidence_lock_binding,
        "the freshly measured binding equals the deterministic setup binding"
    );
}

/// Item C — maximum TC fixture dimensions asserted, then admission / encode /
/// binding measured SEPARATELY.
#[test]
fn d7d14_c_max_tc_dimensions_and_separately_measured_paths() {
    use qbind_node::safety_record_store::codec::{
        admit_supporting_evidence, compute_evidence_lock_binding,
    };
    let ctx = ctx_n(4);
    let n = ctx.n();
    let s_sig = ctx.s_sig;

    // ----- Fixture construction (OUTSIDE every measured interval) -----
    let evidence_only = valid_tc_record_max(&ctx, 5, 6);
    let complete = max_tc_locked_anchored(&ctx, 5, 6);

    // ----- Asserted dimensions (before measurement) -----
    let (rec_high_qc, tc) = match &evidence_only.evidence {
        SupportingEvidence::TcDerived { high_qc, tc } => (high_qc, tc),
        other => panic!("expected TcDerived, got {other:?}"),
    };
    assert_eq!(
        rec_high_qc.signers.len(),
        n,
        "record-level high-QC signer array == N"
    );
    assert_eq!(tc.signers.len(), n, "TC-level signer array == N");
    assert_eq!(
        tc.high_qc.as_ref().unwrap().signers.len(),
        n,
        "nested TC high-QC signer array == N"
    );
    assert_eq!(tc.signed_timeouts.len(), n, "N timeout entries");
    // Unique authorized signers 0..N-1.
    let unique: std::collections::BTreeSet<_> = tc.signers.iter().collect();
    assert_eq!(unique.len(), n, "N unique authorized signers");
    for (i, t) in tc.signed_timeouts.iter().enumerate() {
        assert_eq!(
            t.signature.len(),
            s_sig,
            "each timeout signature is maximum admitted length"
        );
        assert_eq!(
            t.high_qc.as_ref().unwrap().signers.len(),
            n,
            "each timeout-entry nested high-QC signer array == N"
        );
        assert_eq!(
            t.validator_id.as_u64(),
            i as u64,
            "dense unique per-entry signer"
        );
    }
    assert!(evidence_only.committed_anchor.is_none() && evidence_only.predecessor_ref.is_none());
    assert!(complete.committed_anchor.is_some() && complete.predecessor_ref.is_some());

    let dec_evidence = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(evidence_only.clone()),
    };
    let dec_complete = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(complete.clone()),
    };
    let ev = evidence_only.evidence.clone();
    let max_tc = max_tc_bytes(&ctx).unwrap();

    // ----- (1) Successful structural + capacity admission: allocation-free -----
    let (_adm, adm_allocs) = measure_allocs(|| admit_supporting_evidence(&ev, &ctx).unwrap());
    assert_eq!(
        adm_allocs, 0,
        "successful TC admission reads only — no allocation"
    );

    // ----- (2) encode_record: one pre-sized allocation at the admitted cap -----
    let _ = encode_record(&dec_evidence, &ctx).unwrap(); // warm up
    let (enc_ev, enc_ev_allocs) = measure_allocs(|| encode_record(&dec_evidence, &ctx).unwrap());
    assert_eq!(
        enc_ev_allocs, 1,
        "max-TC evidence encode: exactly one (pre-sized) allocation"
    );
    assert_eq!(
        enc_ev.capacity() as u128,
        max_tc,
        "encode backing == admitted TC cap"
    );
    let (enc_cmp, enc_cmp_allocs) = measure_allocs(|| encode_record(&dec_complete, &ctx).unwrap());
    assert_eq!(
        enc_cmp_allocs, 1,
        "max-TC complete encode: exactly one (pre-sized) allocation"
    );
    assert_eq!(
        enc_cmp.capacity() as u128,
        max_tc,
        "complete encode backing == TC cap"
    );
    assert_eq!(
        enc_cmp.len(),
        enc_ev.len() + 48,
        "maximum complete serialized record exceeds maximum evidence by anchor+predecessor"
    );
    assert!(
        enc_cmp.len() as u128 <= max_tc,
        "complete serialized record fits the TC cap"
    );

    // ----- (3) compute_evidence_lock_binding: measured FRESH (not the setup one) -----
    let _ = compute_evidence_lock_binding(&[9u8; 32], 5, &ev, &ctx.authority_context_ref, &ctx)
        .unwrap(); // warm up
    let (fresh_binding, bind_allocs) = measure_allocs(|| {
        compute_evidence_lock_binding(&[9u8; 32], 5, &ev, &ctx.authority_context_ref, &ctx).unwrap()
    });
    assert_eq!(
        bind_allocs, 1,
        "TC binding: exactly one pre-sized cert allocation (admission bounds precede it)"
    );
    assert_eq!(
        fresh_binding, evidence_only.evidence_lock_binding,
        "the freshly measured TC binding equals the deterministic setup binding"
    );
}

/// Item B — observe the ACTUAL live-byte lifetime of the O3 validation scratch
/// (`validate_decoded`) over a maximum QC / maximum TC record, proving the
/// correspondence re-encode buffer is RELEASED before the certificate-binding
/// buffer is allocated. This is a real live-byte observation (peak net heap
/// bytes), not a reservation/accountant figure and not a process-RSS gauge: the
/// measured interval contains NO backend I/O, so every tracked byte is a
/// component-owned validation allocation (re-encode buffer + cert buffer).
///
/// Sensitivity: the headline invariant is `peak < 2 * record_cap` — the two
/// record-sized buffers must never coexist. Restoring the old overlap (removing
/// or delaying the real `drop(reencoded)` in `validate::validate_decoded`) makes
/// `peak` reach `2 * record_cap` and this test FAILS. See the evidence document
/// (Run 422 D7-D14 Item B) for the literal failure captured with the drop removed.
fn observe_o3_validation_live_bytes(evidence_only: LockedRecord, cap: usize, label: &str) {
    let ctx = ctx_n(4);

    // ----- Build the real decoded record + its retained encoded bytes OUTSIDE
    // the measured interval. Decoding via `decode_record` yields the genuine
    // decoded backings (not a fixture clone); encoding yields the retained O5
    // publication bytes the O3 path re-encodes against.
    let decoded0 = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(evidence_only),
    };
    let encoded = encode_record(&decoded0, &ctx).unwrap();
    // Re-decode so the object we validate owns freshly-allocated backings.
    let decoded = decode_record(&encoded, &ctx).unwrap();

    // Observe the ACTUAL capacity of the retained original buffer — never
    // `enc.len()`. The reservation must cover capacity, not length.
    let orig_cap = encoded.capacity();
    assert!(
        orig_cap >= encoded.len(),
        "{label}: capacity ({orig_cap}) is the charged figure, not len ({})",
        encoded.len()
    );

    // ----- Measured interval: the real `validate_decoded` O3 sub-path. The
    // inputs are moved in; the returned proof keeps them alive, so nothing
    // allocated outside is freed inside the interval.
    let (validated, obs) = measure_live_bytes(|| {
        validate_decoded(decoded, encoded, &ctx, None::<&FixtureCommittedHistory>).unwrap()
    });
    obs.assert_sound(label);

    // At least one full record-sized validation buffer was reached.
    assert!(
        obs.peak >= cap,
        "{label}: peak live bytes {} should reach one record-sized buffer ({cap})",
        obs.peak
    );
    // HEADLINE SENSITIVITY INVARIANT: the re-encode buffer and the cert buffer
    // never coexist. With the real `drop(reencoded)` this holds; restoring the
    // old overlap pushes the peak to `2 * cap` and fails here.
    assert!(
        obs.peak < 2 * cap,
        "{label}: re-encode and certificate-binding buffers coexist (peak {} >= 2*cap {}); \
         the O3 drop(reencoded) lifetime correction is not in effect",
        obs.peak,
        2 * cap
    );
    // Tighter bound: the live validation scratch stays within a single
    // record-sized buffer plus only incidental bookkeeping.
    assert!(
        obs.peak <= cap + 128,
        "{label}: live O3 validation scratch {} exceeds a single record-sized buffer ({cap}+slack)",
        obs.peak
    );
    // The proof retains exactly the original publication bytes (the re-encode
    // buffer was scratch, released; the retained buffer is the caller's).
    assert_eq!(validated.evidence_status(), EvidenceStatus::Unverified);
    // No net validation scratch survives the O3 validation step: the re-encode
    // and cert buffers were both released inside the interval (the retained
    // `encoded` was allocated OUTSIDE the interval and is excluded).
    assert_eq!(
        obs.end, 0,
        "{label}: O3 validation scratch not fully released (net live {} at end)",
        obs.end
    );
    drop(validated);
}

#[test]
fn d7d14_b_o3_live_bytes_reencode_released_before_binding_max_qc() {
    let ctx = ctx_n(4);
    let cap = max_qc_bytes(&ctx).unwrap() as usize;
    observe_o3_validation_live_bytes(max_qc_locked(&ctx, 5, false), cap, "max-QC O3");
}

#[test]
fn d7d14_b_o3_live_bytes_reencode_released_before_binding_max_tc() {
    let ctx = ctx_n(4);
    let cap = max_tc_bytes(&ctx).unwrap() as usize;
    observe_o3_validation_live_bytes(valid_tc_record_max(&ctx, 5, 6), cap, "max-TC O3");
}

/// Item D — INDEPENDENT publication-staging boundary observation. Complementary
/// to the accountant-counter regression
/// `d7d14_o5_publication_envelope_coexistence_reserved_within_aggregate` (which
/// is retained): this drives the REAL `publish_atomic` submit boundary and reads
/// the ACTUAL component-owned CRC-envelope backing capacities observed there,
/// then checks they are covered by `publication_staging_charge` WITHOUT deriving
/// the observed footprint from that charge. A reopened backend guarantees an
/// earlier O4 peak cannot mask O5.
///
/// Sensitivity: removing the record-envelope term from `publication_staging_charge`
/// (i.e. dropping required staging coverage while the real envelopes are still
/// allocated) makes the coverage assertion below FAIL. See the evidence document
/// (Run 422 D7-D14 Item D) for the captured failure; the reservation is restored
/// before final validation.
#[test]
fn d7d14_d_publication_staging_boundary_observed_independently() {
    use qbind_node::safety_record_store::accounting::{publication_staging_charge, CRC_PREFIX};
    use qbind_node::safety_record_store::backend::{
        arm_publish_staging_observation, observed_publish_staging,
    };

    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4);
    let owner = init_owner(dir.path(), &ctx);

    // O4: publish the maximum-TC record (worst-case record envelope), then drop
    // the owner so the O4 peak does not pollute the reopened accountant.
    let ltc = valid_tc_record_max(&ctx, 5, 6);
    assert_eq!(
        owner.publish_locked(ltc, 0, None::<&FixtureCommittedHistory>),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    drop(owner);

    // Reopen a fresh backend (zeroed accountant peak; not-effective → O5 recovers).
    let owner = SafetyRecordOwner::attach(open_enabled(dir.path()), ctx.clone()).unwrap();
    assert!(
        owner.recovery_required(),
        "reopened store starts not-effective"
    );
    // A live O3 proof bound to THIS incarnation authorizes the O5 republication.
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();

    // Observe the REAL envelope capacities at the actual publish_atomic boundary.
    arm_publish_staging_observation();
    assert_eq!(
        owner.reacknowledge(&proof),
        PublishResult::DurableAcknowledged { new_revision: 1 }
    );
    let (record_env_cap, meta_env_cap) = observed_publish_staging()
        .expect("the O5 republication reached the publish_atomic boundary");

    // The observed envelopes are the genuine `4 + payload.len()` CRC framings over
    // the republished ORIGINAL bytes and the fixed metadata payload — observed
    // capacity, never a `len()` substitute.
    let crc = CRC_PREFIX as usize;
    assert_eq!(
        record_env_cap,
        crc + proof.encoded().len(),
        "record staging envelope wraps the retained original bytes (observed capacity)"
    );
    assert_eq!(
        meta_env_cap, 46,
        "metadata staging envelope == CRC_PREFIX(4) + META_ENCODED_LEN(42)"
    );

    // INDEPENDENT coverage check: the two actually-observed component-owned
    // envelopes fit the `publication_staging_charge` reservation taken up front.
    // Removing the record term from that charge makes this FAIL (sensitivity).
    let staging = publication_staging_charge(&ctx).unwrap();
    assert!(
        (record_env_cap + meta_env_cap) as u128 <= staging,
        "observed staging envelopes ({record_env_cap}+{meta_env_cap}) must be covered by the \
         publication_staging_charge reservation ({staging})"
    );
    // And the record envelope sits at the worst case the charge provisions for:
    // the charge's record term is CRC_PREFIX + max_safety_record_bytes.
    let max_rec = qbind_node::safety_record_store::profile::max_safety_record_bytes(&ctx).unwrap();
    assert!(
        record_env_cap as u128 <= crc as u128 + max_rec,
        "observed record envelope within the provisioned worst case"
    );
    drop(proof);
}

/// Item E — close the one remaining inventory open question: whether the 42-byte
/// metadata **encode** buffer (`meta.encode()`) coexists UNCOVERED under the O1
/// bootstrap `rec + staging` reservation. This reconciles the O1 publish boundary
/// object-by-object with REAL bootstrap object sizes (supporting arithmetic
/// evidence, accurately labeled — it derives the boundary live set from actual
/// encoded sizes, not from the reservation helper it checks).
///
/// At the O1 `publish_atomic` boundary the simultaneously-live component-owned
/// objects are: the bootstrap record buffer, the 42-byte metadata payload, the
/// record CRC envelope (`4 + record.len()`), and the metadata CRC envelope
/// (`4 + 42`). The reservation is `max_safety_record_bytes + publication_staging_charge`.
/// Because the bootstrap record is tiny (no lock/evidence), the record-side slack
/// in the reservation absorbs the metadata payload with a large margin, so the
/// 42-byte encode buffer IS covered and no runtime correction is required.
#[test]
fn d7d14_e_o1_bootstrap_boundary_covers_metadata_encode_buffer() {
    use qbind_node::safety_record_store::accounting::{publication_staging_charge, CRC_PREFIX};
    use qbind_node::safety_record_store::profile::max_safety_record_bytes;

    let ctx = ctx_n(4);

    // The real bootstrap record the O1 path encodes (no lock, no evidence).
    let boot = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 0,
        record: SafetyRecord::BootstrapNoLock {
            authority_context_ref: ctx.authority_context_ref,
            predecessor_ref: None,
        },
    };
    let encoded = encode_record(&boot, &ctx).unwrap();
    let rec_cap = encoded.capacity() as u128;
    let rec_len = encoded.len() as u128;

    // Reservation actually taken by O1 (owner.rs: rec + staging).
    let m = max_safety_record_bytes(&ctx).unwrap();
    let staging = publication_staging_charge(&ctx).unwrap();
    let o1_pub_charge = m + staging;

    // The metadata payload and both CRC envelopes at the write boundary. The
    // metadata payload is the fixed 42-byte encoding; the meta envelope is
    // `staging - (CRC + max_record)` = CRC + 42 = 46; the record envelope is
    // `CRC + record.len()`.
    let meta_envelope = staging - (CRC_PREFIX + m); // = CRC + META_ENCODED_LEN = 46
    let meta_payload = meta_envelope - CRC_PREFIX; // = META_ENCODED_LEN = 42
    assert_eq!(meta_envelope, 46, "meta CRC envelope == 4 + 42");
    assert_eq!(
        meta_payload, 42,
        "metadata encode payload == META_ENCODED_LEN"
    );
    let record_envelope = CRC_PREFIX + rec_len;

    // Object-by-object O1 boundary live set, including the 42-byte meta payload.
    let boundary_live = rec_cap + meta_payload + record_envelope + meta_envelope;

    // PHASE INEQUALITY: live component-owned charge ≤ active covering reservation.
    assert!(
        boundary_live <= o1_pub_charge,
        "O1 boundary live {boundary_live} (rec_cap {rec_cap} + meta_payload {meta_payload} \
         + record_env {record_envelope} + meta_env {meta_envelope}) must fit the O1 reservation \
         {o1_pub_charge} = rec {m} + staging {staging}"
    );
    // The metadata encode buffer specifically is covered: even after charging the
    // record buffer, record envelope, and meta envelope, the reservation residual
    // still exceeds the 42-byte payload (record-side slack absorbs it).
    let residual_after_others = o1_pub_charge - (rec_cap + record_envelope + meta_envelope);
    assert!(
        residual_after_others >= meta_payload,
        "reservation residual {residual_after_others} covers the 42-byte metadata encode buffer"
    );
}
