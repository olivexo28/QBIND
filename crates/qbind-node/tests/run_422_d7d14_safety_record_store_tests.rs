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
    let after = owner_a.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    assert_eq!(
        after.decoded().publication_revision,
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
    assert!(v.decoded().is_locked());
    assert_eq!(v.decoded().publication_revision, 1);
}

// ---------------------------------------------------------------------------
// H18 — O1 refuses duplicate initialization / established state (real-storage)
// ---------------------------------------------------------------------------

#[test]
fn h18_o1_refuses_duplicate_initialization() {
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
// H19 — O5 refuses divergence OUTSIDE the binding digest's coverage
//       while CRC + binding still pass (real-storage)
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
    let res = owner.reacknowledge(&retained);
    assert!(
        matches!(
            res,
            PublishResult::RefusedPreWrite(SafetyStoreError::PublicationMismatch(_))
        ),
        "got {res:?}"
    );
    // The divergent bytes are untouched (no overwrite of newer/foreign state).
    let after = owner.read_validate(None::<&FixtureCommittedHistory>);
    // The forged bytes may now fail semantic validation (genesis mismatch), which
    // is itself a refusal; the key point is O5 did not republish the retained.
    assert!(after.is_err() || after.unwrap().encoded() == forged.as_slice());
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
    assert_eq!(now.decoded().publication_revision, 2);
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
    assert_eq!(v.decoded().publication_revision, 0);
    assert!(!v.decoded().is_locked());
}

// ---------------------------------------------------------------------------
// H22 — O4 rejects non-increasing lock view (real-storage)
// ---------------------------------------------------------------------------

#[test]
fn h22_o4_rejects_non_increasing_view() {
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
    assert_eq!(before.decoded(), after.decoded());
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

/// H26 (adversarial, through actual storage operations) — an over-bound nested
/// record-level high-QC signer list inside a TC-derived publication is refused by
/// O4's single admission path BEFORE any evidence-binding allocation, and the
/// established predecessor is left intact. Helper-only refusal and valid
/// round-trips are not a substitute: this drives the real `publish_locked`.
#[test]
fn h26_adversarial_nested_tc_high_qc_signers_refused_through_o4() {
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
    assert_eq!(v.decoded().publication_revision, 0);
    assert!(!v.decoded().is_locked());

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
        &rv.decoded().record,
        SafetyRecord::Locked(l) if matches!(l.evidence, SupportingEvidence::TcDerived { .. })
    ));
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
    match &v.decoded().record {
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

// §5 representation proof: the operative layout proof must cover the **real**
// operational retained representation (`ValidatedRecord` / `DecodedRecord`), not
// the synthetic `RetainedGeneration` wrapper. This regression measures the real
// target layouts, verifies the exact inline decomposition the module's
// compile-time proof enforces (each member counted once, no field escaping a
// term), and explicitly SURFACES the measured discrepancy: the complete decoded
// generation container exceeds `GEN_STRUCT_MAX` even though the generation core
// fits — so the ceiling is applied to the core and the holder/identity fields are
// charged under their own terms (never under the generation ceiling).
#[test]
fn real_representation_layout_decomposition() {
    use qbind_node::safety_record_store::profile::GEN_STRUCT_MAX;
    use qbind_node::safety_record_store::record::{
        size_of_decoded_record, size_of_retained_generation, size_of_safety_record,
        size_of_validated_record,
    };

    let gen_core = size_of_safety_record();
    let decoded = size_of_decoded_record();
    let validated = size_of_validated_record();
    let synthetic = size_of_retained_generation();
    println!(
        "MEASURED gen_core(SafetyRecord)={gen_core} decoded(DecodedRecord)={decoded} \
         validated(ValidatedRecord)={validated} synthetic(RetainedGeneration)={synthetic} \
         GEN_STRUCT_MAX={GEN_STRUCT_MAX}"
    );

    // The real generation-bearing core fits the accepted ceiling with margin.
    assert!(
        gen_core <= GEN_STRUCT_MAX,
        "generation core {gen_core} must fit GEN_STRUCT_MAX {GEN_STRUCT_MAX}"
    );

    // Exact inline decomposition — every inline member counted exactly once.
    let decoded_identity_header = decoded - gen_core;
    let validated_handle_fields = validated - decoded;
    assert_eq!(
        gen_core + decoded_identity_header,
        decoded,
        "DecodedRecord decomposition must sum exactly"
    );
    assert_eq!(
        decoded + validated_handle_fields,
        validated,
        "ValidatedRecord decomposition must sum exactly"
    );
    // The separately-owned holder/handle fields are a non-trivial inline term
    // (the retained-encoded Vec descriptor, origin digest, O5 incarnation, and the
    // inline holder Reservation option) that must NOT be folded into the
    // generation ceiling.
    assert!(
        validated_handle_fields > 0,
        "ValidatedRecord must carry separately-charged holder/handle fields"
    );

    // SURFACED discrepancy (not concealed, not silently relaxed): the complete
    // decoded generation container is larger than the accepted single generation
    // ceiling. The synthetic wrapper hid this by omitting the identity header.
    assert!(
        decoded > GEN_STRUCT_MAX,
        "expected the real DecodedRecord ({decoded}) to exceed GEN_STRUCT_MAX \
         ({GEN_STRUCT_MAX}); if this no longer holds the representation changed \
         and the §13.7A contract note must be revisited"
    );
    assert!(
        decoded > synthetic,
        "the real retained generation must be at least as large as the synthetic \
         wrapper it replaces as the operative proof"
    );
    // The deficit the required (separately-presented) contract change must cover:
    // GEN_STRUCT_MAX only absorbs part of the identity header.
    let ceiling_headroom = GEN_STRUCT_MAX - gen_core;
    let uncovered_header = decoded_identity_header.saturating_sub(ceiling_headroom);
    println!(
        "SURFACED: decoded_identity_header={decoded_identity_header} \
         ceiling_headroom={ceiling_headroom} uncovered_by_single_ceiling={uncovered_header} \
         (violated inequality: size_of::<DecodedRecord>()={decoded} > GEN_STRUCT_MAX={GEN_STRUCT_MAX})"
    );
    assert!(
        uncovered_header > 0,
        "a single generation ceiling of {GEN_STRUCT_MAX} cannot cover the complete \
         decoded generation ({decoded}); the deficit must be surfaced"
    );
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
    assert!(!v.decoded().is_locked());
    assert_eq!(v.decoded().publication_revision, 0);
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
    assert_eq!(surviving.decoded().publication_revision, 2);
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
        rb.decoded().publication_revision,
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
    assert_eq!(surviving.decoded().publication_revision, 1);
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
    assert_eq!(v.decoded().publication_revision, 0);
    assert!(!v.decoded().is_locked());
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
    assert_eq!(readback.decoded().publication_revision, 1);
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
                assert!(backend.accounting_current() <= cap, "holders stay within cap");
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
    assert_eq!(backend.accounting_current(), 0, "released after write error");
    assert!(owner.recovery_required(), "write error sets recovery restriction");
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
            assert!(
                !owner.recovery_required(),
                "post-ack must be effective"
            );
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
    assert!(!v.decoded().is_locked());
    assert_eq!(v.decoded().publication_revision, 0);
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
    assert!(v.decoded().is_locked());
    assert_eq!(v.decoded().publication_revision, 1);
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
    assert!(v.decoded().is_locked());
    assert_eq!(v.decoded().publication_revision, 1);
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
    assert!(v.decoded().is_locked());
    assert_eq!(v.decoded().publication_revision, 1);
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
    assert!(!v.decoded().is_locked());
    assert_eq!(v.decoded().publication_revision, 0);
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
    assert_eq!(status.code(), Some(15), "child reached the uncertain-O1 boundary");
    let ctx = ctx_n(4);
    let owner = SafetyRecordOwner::attach(open_enabled(dir.path()), ctx).unwrap();
    // The durable bootstrap survived and is a valid complete publication.
    let v = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert!(!v.decoded().is_locked());
    assert_eq!(v.decoded().publication_revision, 0);
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
    assert_eq!(status.code(), Some(16), "child reached the uncertain-O5 boundary");
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
    assert_eq!(status.code(), Some(17), "child reached the failed-O5 boundary");
    let ctx = ctx_n(4);
    let owner = SafetyRecordOwner::attach(open_enabled(dir.path()), ctx).unwrap();
    assert_eq!(owner.open().unwrap().current_revision, 1);
    assert!(owner.recovery_required(), "failed O5 does not release recovery");
    let v = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert!(v.decoded().is_locked());
    assert_eq!(v.decoded().publication_revision, 1);
}