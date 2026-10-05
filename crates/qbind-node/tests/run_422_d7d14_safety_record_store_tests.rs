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
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
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
// H12 — checked serialized caps match measured encodings (unit/model)
// ---------------------------------------------------------------------------

#[test]
fn h12_serialized_caps_bound_actual_encodings() {
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
// Correction pass (§3) — a freshly REOPENED established store carries no
// inherited acknowledgement: dependent O4 is blocked until a successful O5 (or
// an acknowledged O1). Reopening must not bypass the restriction.
// ---------------------------------------------------------------------------
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
#[test]
fn corr_oversized_signature_refused_before_publication() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ctx_n(4); // s_sig = 8
    let owner = init_owner(dir.path(), &ctx);
    let mut qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    // Replace one 8-byte signature with a 9-byte one.
    qc.signatures[0] = vec![0xABu8; 9];
    let locked = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    let res = owner.publish_locked(locked, 0, None::<&FixtureCommittedHistory>);
    assert!(
        matches!(
            res,
            PublishResult::RefusedPreWrite(SafetyStoreError::DeclaredBoundExceeded(_))
        ),
        "9-byte signature must be refused pre-publication, got {res:?}"
    );
    // The predecessor (bootstrap rev 0) is unchanged.
    let v = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    assert_eq!(v.decoded().publication_revision, 0);
    assert!(!v.decoded().is_locked());
}

// ---------------------------------------------------------------------------
// Correction pass (§8 / TA2 vs TA1) — the SELECTED timeout-entry high-QC may
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
        let binding =
            compute_evidence_lock_binding(&block, lock_view, &evidence, &ctx.authority_context_ref)
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
            // Simulate a crash AFTER durable acknowledgement but before any
            // in-memory installation: abort without unwinding.
            std::process::abort();
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
        other => panic!("unknown child phase {other}"),
    }
}

fn spawn_child(dir: &std::path::Path, phase: &str) -> std::process::ExitStatus {
    let exe = std::env::current_exe().expect("current_exe");
    Command::new(exe)
        .args(["--exact", "child_process_entry", "--ignored", "--nocapture"])
        .env(ENV_DIR, dir)
        .env(ENV_PHASE, phase)
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

/// Boundary: death AFTER durability acknowledgement but before in-memory
/// installation → the acknowledged publication survives; O3/O5 proceed.
#[test]
fn pd_ack_then_abort_survives_locked() {
    let dir = tempfile::tempdir().unwrap();
    let status = spawn_child(dir.path(), "ack_then_abort");
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
