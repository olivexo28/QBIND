//! Reviewed R/D/S/M slice: synthetic cryptographic verification and explicit
//! test-only admission/model sensitivity, not production recovery/binding.

mod binding_sensitivity_support;

use binding_sensitivity_support::*;
use qbind_consensus::proposal_vote_verify::{
    verify_proposal_msg_with_domain, verify_vote_msg_with_domain, ProposalVoteVerifyError,
};
use qbind_consensus::qc_verify_domain::{
    verify_quorum_certificate_with_domain, QcDomainVerifyError,
};
use qbind_consensus::ValidatorId;
use qbind_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier};
use qbind_types::ChainId;
use qbind_wire::consensus::BlockProposal;
use qbind_wire::pv_signing_domain::{
    ProposalVoteMessageFamily, ProposalVoteSigningDomainV2, PV_SIGNING_DOMAIN_V2_TAG,
};

fn proposal_verify(f: &Fixture, proposal: &BlockProposal) -> Result<(), ProposalVoteVerifyError> {
    verify_proposal_msg_with_domain(
        proposal,
        ValidatorId(0),
        &f.validators,
        &f.keys,
        &f.registry,
        &f.domain,
    )
}

#[test]
fn r_encoded_accounting_and_retained_duplicates_are_separate() {
    let f = Fixture::new();
    let segments = f.segments();
    assert_eq!(
        f.qcs
            .iter()
            .flat_map(|qc| &qc.signatures)
            .map(Vec::len)
            .sum::<usize>(),
        21_780
    );
    assert_eq!(
        segments.each_ref().map(Vec::len),
        [7_336, 7_336, 7_336, 7_750, 2_420, 448]
    );
    let actual = segments.iter().map(Vec::len).sum::<usize>() + FRAME_BYTES;
    assert_eq!(actual, 32_674);
    assert_eq!(3 * 7_336 + 7_750 + 2_420 + 512, 32_690);
    assert!(actual <= 32_690 && actual < ENCODED_CAP);
    let retained_results: Vec<_> = f.qcs.iter().map(|qc| f.qc(qc).unwrap()).collect();
    assert_eq!(f.backend.calls(), (9, 0));
    let cloned_sig_bytes = retained_results
        .iter()
        .flat_map(|result| &result.certificate().signatures)
        .map(Vec::len)
        .sum::<usize>();
    assert_eq!(cloned_sig_bytes, 21_780);
    f.retained_inventory();
    println!(
        "R ACCOUNTING encoded_segments_plus_framing={actual} reviewed_max=32690 cap=65536 \
         segment_capacities={} simultaneously_retained_result_signature_lengths={cloned_sig_bytes}; \
         encoded+decoded+results coexist, NO total-memory bound",
        segments.iter().map(Vec::capacity).sum::<usize>(),
    );
}

#[test]
fn r_proposal_own_signature_excluded_embedded_signatures_included() {
    let f = Fixture::new();
    let original_body = f.proposal.canonical_body();
    assert_eq!(proposal_verify(&f, &f.proposal), Ok(()));
    assert_eq!(f.backend.calls(), (0, 1));
    let mut altered = f.proposal.clone();
    altered.signature[0] ^= 1;
    assert_eq!(altered.canonical_body(), original_body);
    assert_eq!(
        proposal_verify(&f, &altered),
        Err(ProposalVoteVerifyError::InvalidSignature(ValidatorId(0)))
    );
    altered = f.proposal.clone();
    altered.qc.as_mut().unwrap().signatures[0][0] ^= 1;
    assert_ne!(altered.canonical_body(), original_body);
    assert_eq!(
        proposal_verify(&f, &altered),
        Err(ProposalVoteVerifyError::InvalidSignature(ValidatorId(0)))
    );
    assert_eq!(proposal_verify(&f, &f.proposal), Ok(()));
    assert_eq!(f.backend.calls(), (0, 4));
    println!("R Proposal already allocated: original/restored Ok, mutations InvalidSignature; backend proposal_calls=4");
}

#[test]
fn r_proposal_parent_and_content_mutations_use_same_checker() {
    let f = Fixture::new();
    for kind in 0..2 {
        let mut changed = f.proposal.clone();
        if kind == 0 {
            changed.header.parent_block_id[31] ^= 1;
        } else {
            changed.txs[0][0] ^= 1;
        }
        assert_eq!(
            proposal_verify(&f, &changed),
            Err(ProposalVoteVerifyError::InvalidSignature(ValidatorId(0)))
        );
        assert_eq!(proposal_verify(&f, &f.proposal), Ok(()));
    }
    assert_eq!(f.backend.calls(), (0, 4));
}

#[test]
fn r_each_qc_verifies_three_distinct_real_signatures() {
    let f = Fixture::new();
    for qc in &f.qcs {
        let result = f.qc(qc).unwrap();
        assert_eq!(result.verified_voting_power(), 3);
        assert_eq!(result.threshold(), 3);
        assert_eq!(
            result.signers(),
            &[ValidatorId(0), ValidatorId(1), ValidatorId(2)]
        );
    }
    assert_eq!(f.backend.calls(), (9, 0));
    println!(
        "R decoded QCs: 3 owning results, 9 real verify_vote calls, weight=3 threshold=3 each"
    );
}

#[test]
fn r_insufficient_weight_restored_third_signer() {
    let f = Fixture::new();
    let mut qc = f.qcs[0].clone();
    qc.signer_bitmap[0] = 0b11;
    qc.signatures.pop();
    assert!(matches!(
        f.qc(&qc),
        Err(QcDomainVerifyError::InsufficientVotingPower { have: 2, need: 3 })
    ));
    assert_eq!(f.backend.calls(), (2, 0));
    f.qc(&f.qcs[0]).unwrap();
    assert_eq!(f.backend.calls(), (5, 0));
}

#[test]
fn r_signed_vote_fields_fail_and_restore() {
    let f = Fixture::new();
    for kind in 0..4 {
        let mut qc = f.qcs[0].clone();
        match kind {
            0 => qc.block_id[0] ^= 1,
            1 => qc.height += 1,
            2 => qc.round += 1,
            _ => qc.step += 1,
        }
        assert!(matches!(
            f.qc(&qc),
            Err(QcDomainVerifyError::InvalidSignature(ValidatorId(0)))
        ));
        f.qc(&f.qcs[0]).unwrap();
    }
    assert_eq!(f.backend.calls(), (16, 0));
}

#[test]
fn r_wire_chain_and_authorized_epoch_fail_before_crypto() {
    let f = Fixture::new();
    let mut qc = f.qcs[0].clone();
    qc.chain_id += 1;
    assert!(matches!(
        f.qc(&qc),
        Err(QcDomainVerifyError::WireChainMismatch { .. })
    ));
    assert_eq!(f.backend.calls(), (0, 0));
    qc = f.qcs[0].clone();
    qc.epoch = 1;
    assert!(matches!(
        f.qc(&qc),
        Err(QcDomainVerifyError::EpochMismatch {
            expected: 0,
            actual: 1
        })
    ));
    assert_eq!(f.backend.calls(), (0, 0));
    f.qc(&f.qcs[0]).unwrap();
    assert_eq!(f.backend.calls(), (3, 0));
}

#[test]
fn r_genesis_authority_runtime_domains_fail_signature_verification() {
    let f = Fixture::new();
    let domains = [
        ProposalVoteSigningDomainV2::try_new(ChainId(0xABCD_0000_0000_0001), 5, [3; 32], [2; 32])
            .unwrap(),
        ProposalVoteSigningDomainV2::try_new(ChainId(0xABCD_0000_0000_0001), 5, [1; 32], [3; 32])
            .unwrap(),
        ProposalVoteSigningDomainV2::try_new(ChainId(0xABCD_0000_0000_0002), 5, [1; 32], [2; 32])
            .unwrap(),
    ];
    for changed in domains {
        assert!(matches!(
            verify_quorum_certificate_with_domain(
                &f.qcs[0],
                &changed,
                0,
                &f.validators,
                &f.keys,
                &f.registry
            ),
            Err(QcDomainVerifyError::InvalidSignature(ValidatorId(0)))
        ));
        f.qc(&f.qcs[0]).unwrap();
    }
    assert_eq!(f.backend.calls(), (12, 0));
}

#[test]
fn r_outbound_helpers_and_inbound_message_recomputation_are_distinct() {
    let f = Fixture::new();
    let original = vote(&f.qcs[0], 0, f.qcs[0].signatures[0].clone());
    let captured = f.domain.vote_preimage(&original);
    let mut changed = original.clone();
    changed.height += 1;
    assert_ne!(captured, f.domain.vote_preimage(&changed));
    // The public inbound API has no caller-supplied-preimage parameter.
    assert_eq!(
        verify_vote_msg_with_domain(
            &changed,
            ValidatorId(0),
            &f.validators,
            &f.keys,
            &f.registry,
            &f.domain
        ),
        Err(ProposalVoteVerifyError::InvalidSignature(ValidatorId(0)))
    );
    assert_eq!(
        verify_vote_msg_with_domain(
            &original,
            ValidatorId(0),
            &f.validators,
            &f.keys,
            &f.registry,
            &f.domain
        ),
        Ok(())
    );
    assert_ne!(f.domain.proposal_preimage(&f.proposal), captured);
    let mut wrong_version = original.clone();
    wrong_version.version += 1;
    assert_eq!(
        verify_vote_msg_with_domain(
            &wrong_version,
            ValidatorId(0),
            &f.validators,
            &f.keys,
            &f.registry,
            &f.domain
        ),
        Err(ProposalVoteVerifyError::InvalidSignature(ValidatorId(0)))
    );
    assert_eq!(f.backend.calls(), (3, 0));
}

#[test]
fn r_unauthorized_sparse_member_and_swapped_signature_refuse() {
    let f = Fixture::new();
    let sparse = validators(&[0, 1, 3, 4]);
    assert!(matches!(
        verify_quorum_certificate_with_domain(
            &f.qcs[0],
            &f.domain,
            0,
            &sparse,
            &f.keys,
            &f.registry
        ),
        Err(QcDomainVerifyError::UnknownSigner(ValidatorId(2)))
    ));
    assert_eq!(f.backend.calls(), (2, 0));
    let mut swapped = f.qcs[0].clone();
    swapped.signatures.swap(0, 1);
    assert!(matches!(
        f.qc(&swapped),
        Err(QcDomainVerifyError::InvalidSignature(ValidatorId(0)))
    ));
    f.qc(&f.qcs[0]).unwrap();
    assert_eq!(f.backend.calls(), (6, 0));
}

#[test]
fn r_message_purpose_and_signing_format_bytes_are_authenticated() {
    let f = Fixture::new();
    let original = vote(&f.qcs[0], 0, f.qcs[0].signatures[0].clone());
    let preimage = f.domain.vote_preimage(&original);
    let public = &f.keys.public[&ValidatorId(0)];
    for offset in [
        PV_SIGNING_DOMAIN_V2_TAG.len(),
        PV_SIGNING_DOMAIN_V2_TAG.len() + 1,
    ] {
        let mut changed = preimage.clone();
        if offset == PV_SIGNING_DOMAIN_V2_TAG.len() {
            changed[offset] += 1;
        } else {
            changed[offset] = ProposalVoteMessageFamily::Proposal.tag();
        }
        assert!(matches!(
            f.backend
                .verify_vote(0, public, &changed, &original.signature),
            Err(ConsensusSigError::InvalidSignature)
        ));
        f.backend
            .verify_vote(0, public, &preimage, &original.signature)
            .unwrap();
    }
    assert_eq!(f.backend.calls(), (4, 0));
    println!("R direct real backend: purpose/format byte mutations refuse, originals restore; not a future B/C parser or signer");
}

#[test]
fn d_duplicate_entry_and_invalid_extra_signature_are_not_quorum_passes() {
    let f = Fixture::new();
    let mut duplicate = f.qcs[0].clone();
    duplicate.signatures.push(duplicate.signatures[0].clone());
    assert!(matches!(
        f.qc(&duplicate),
        Err(QcDomainVerifyError::SignatureCountMismatch {
            popcount: 3,
            signatures: 4
        })
    ));
    assert_eq!(f.backend.calls(), (0, 0));
    let mut extra = f.qcs[0].clone();
    extra.signer_bitmap[0] = 0b1111;
    extra.signatures.push(f.fourth_signature.clone());
    extra.signatures[3][0] ^= 1;
    assert!(matches!(
        f.qc(&extra),
        Err(QcDomainVerifyError::InvalidSignature(ValidatorId(3)))
    ));
    assert_eq!(f.backend.calls(), (4, 0));
    extra.signatures[3] = f.fourth_signature.clone();
    assert_eq!(f.qc(&extra).unwrap().verified_voting_power(), 4);
    assert_eq!(f.backend.calls(), (8, 0));
}

#[test]
fn d_allocated_late_oversize_signature_refuses_before_any_backend_call() {
    let f = Fixture::new();
    for index in [0, 2] {
        let mut qc = f.qcs[0].clone();
        qc.signatures[index] = vec![0; 65_536];
        let allocated_lengths =
            qc.signatures.iter().map(Vec::len).sum::<usize>() + qc.signer_bitmap.len();
        assert_eq!(allocated_lengths, 70_377);
        assert!(allocated_lengths < D_BYTE_LENGTH_CAP);
        let allocated_capacity = qc.signatures.iter().map(Vec::capacity).sum::<usize>();
        let outer_capacity = qc.signatures.capacity() * std::mem::size_of::<Vec<u8>>();
        f.backend.reset();
        assert!(
            matches!(f.qc(&qc), Err(QcDomainVerifyError::MalformedSignature(id)) if id == ValidatorId(index as u64))
        );
        assert_eq!(f.backend.calls(), (0, 0));
        qc.signatures[index] = f.qcs[0].signatures[index].clone();
        f.qc(&qc).unwrap();
        assert_eq!(f.backend.calls(), (3, 0));
        println!(
            "D already allocated byte lengths=70377 signature_capacity={allocated_capacity} \
                  outer_vector_storage={outer_capacity} offending_index={index}: \
                  MalformedSignature with zero backend calls; NOT pre-input-allocation"
        );
    }
}

#[test]
fn s_announced_oversize_overflow_and_whole_gate_bypass_sensitivity() {
    let mut materializations = 0;
    for (lengths, expected) in [
        (
            [65_537, 0, 0, 0, 0, 0],
            AdmissionError::EncodedBudgetExceeded,
        ),
        ([usize::MAX, 1, 0, 0, 0, 0], AdmissionError::LengthOverflow),
    ] {
        assert_eq!(
            test_admit_fixture_segments(lengths, false, || {
                materializations += 1;
            }),
            Err(expected)
        );
        assert_eq!(materializations, 0);
        // Deliberately defective test-only gate: sentinel callback, no payload.
        assert_eq!(
            test_admit_fixture_segments(lengths, true, || {
                materializations += 1;
            }),
            Ok(())
        );
        assert_eq!(materializations, 1);
        materializations = 0;
    }
    assert_eq!(
        test_admit_fixture_segments([ENCODED_CAP - FRAME_BYTES, 0, 0, 0, 0, 0], false, || {
            materializations += 1;
        }),
        Ok(())
    );
    assert_eq!(materializations, 1);
    println!("S lengths-only boundary: rejects before callback; exact length cap only passes length gate; bypass defect observed");
}

#[test]
fn s_borrowed_valid_segments_scan_before_real_qc_decoding() {
    let f = Fixture::new();
    let segments = f.segments();
    let mut callbacks = 0;
    let mut decoders = 0;
    test_admit_fixture_segments(segments.each_ref().map(Vec::len), false, || {
        callbacks += 1;
    })
    .unwrap();
    test_scan_then_decode(segments.each_ref().map(Vec::as_slice), false, &mut decoders).unwrap();
    assert_eq!((callbacks, decoders), (1, 3));
    assert_eq!(f.backend.calls(), (0, 0));
}

#[test]
fn s_borrowed_nested_malformed_truncated_and_padding_prevent_decoding() {
    let f = Fixture::new();
    for kind in 0..4 {
        let mut segments = f.segments();
        let expected = match kind {
            0 => {
                segments[0][65..67].copy_from_slice(&2u16.to_le_bytes());
                AdmissionError::NestedLengthExceeded
            }
            1 => {
                segments[1].pop();
                AdmissionError::TruncatedSegment
            }
            2 => {
                segments[3][7_490..7_494].copy_from_slice(&257u32.to_le_bytes());
                AdmissionError::NestedLengthExceeded
            }
            _ => {
                segments[2].push(0);
                AdmissionError::TrailingBytes
            }
        };
        let mut decoders = 0;
        assert_eq!(
            test_scan_then_decode(segments.each_ref().map(Vec::as_slice), false, &mut decoders),
            Err(expected)
        );
        assert_eq!(decoders, 0);
        let restored = f.segments();
        test_scan_then_decode(restored.each_ref().map(Vec::as_slice), false, &mut decoders)
            .unwrap();
        assert_eq!(decoders, 3);
    }
}

#[test]
fn s_whole_scanner_bypass_is_detected_not_production_security_evidence() {
    let f = Fixture::new();
    let mut segments = f.segments();
    // Existing WireDecode can decode four entries; the R scanner must reject.
    segments[0][68..70].copy_from_slice(&4u16.to_le_bytes());
    let mut decoders = 0;
    assert_eq!(
        test_scan_then_decode(segments.each_ref().map(Vec::as_slice), false, &mut decoders),
        Err(AdmissionError::ShapeMismatch)
    );
    assert_eq!(decoders, 0);
    assert_eq!(
        test_scan_then_decode(segments.each_ref().map(Vec::as_slice), true, &mut decoders),
        Err(AdmissionError::DecoderFailure(
            qbind_wire::error::WireError::UnexpectedEof
        ))
    );
    assert_eq!(decoders, 1);
    println!("S deliberately defective scanner bypass invoked decoder=1; defect detected, not a production security pass");
}

fn model(
    records: &[Record; 4],
    oracle: &[Record; 4],
    summaries: &[Option<Summary>; 3],
    content: &[u8],
    expected_content: &[u8],
    baseline: Record,
    endpoint: Id,
    bypass: bool,
) -> (Result<Id, ModelError>, ModelTrace) {
    let mut trace = ModelTrace::default();
    let result = test_check_gpb_associations(
        ModelInput {
            records,
            summaries,
            oracle,
            content,
            expected_content,
            baseline,
            endpoint,
        },
        bypass,
        &mut trace,
    );
    (result, trace)
}

#[test]
fn m_fixed_g_coherent_baselines_reach_same_monotonic_predicate() {
    let f = Fixture::new();
    let summaries = f.summaries().map(Some);
    let content = &f.proposal.txs[0];
    for (baseline, expected) in [
        (f.records[0], Ok(f.records[1].id)),
        (f.records[1], Err(ModelError::NonMonotonicEndpoint)),
        (f.records[2], Err(ModelError::NonMonotonicEndpoint)),
        (f.records[0], Ok(f.records[1].id)),
    ] {
        let (result, trace) = model(
            &f.records,
            &f.records,
            &summaries,
            content,
            content,
            baseline,
            f.records[1].id,
            false,
        );
        assert_eq!(result, expected);
        assert!(trace.earlier_passed);
        assert_eq!(trace.monotonic_reached, 1);
        println!(
            "M fixed G=(10,10) coherent baseline=({},{}) outcome={result:?} \
                  earlier_passed=true monotonic_reached=1",
            baseline.height, baseline.view
        );
    }
    for baseline in [f.records[1], f.records[2]] {
        let (result, trace) = model(
            &f.records,
            &f.records,
            &summaries,
            content,
            content,
            baseline,
            f.records[1].id,
            true,
        );
        assert_eq!(result, Ok(f.records[1].id));
        assert!(trace.earlier_passed);
        assert_eq!(trace.monotonic_reached, 1);
        assert_ne!(result, Err(ModelError::NonMonotonicEndpoint));
    }
    assert_eq!(f.backend.calls(), (0, 0));
    println!("M whole-predicate bypass deliberately accepts both negatives: refusal assertion would fail; no engine invoked");
}

#[test]
fn m_missing_qcs_parent_views_endpoint_and_epoch_controls() {
    let f = Fixture::new();
    let original = f.summaries().map(Some);
    let content = &f.proposal.txs[0];
    for index in 0..3 {
        let mut summaries = original;
        summaries[index] = None;
        let (result, trace) = model(
            &f.records,
            &f.records,
            &summaries,
            content,
            content,
            f.records[0],
            f.records[1].id,
            false,
        );
        assert_eq!(result, Err(ModelError::MissingOwnQc));
        assert!(!trace.earlier_passed);
        assert_eq!(trace.monotonic_reached, 0);
    }
    for defect in 0..3 {
        let mut records = f.records;
        let mut summaries = original;
        let expected = match defect {
            0 => {
                records[2].parent = records[0].id;
                ModelError::ParentLinkMismatch
            }
            1 => {
                records[2].view = records[1].view;
                summaries[1].as_mut().unwrap().view = records[2].view;
                ModelError::ViewsNotIncreasing
            }
            _ => {
                records[2].epoch = 1;
                ModelError::UnsupportedTransition
            }
        };
        // Update explicit oracle only to isolate graph/epoch predicates.
        let (result, trace) = model(
            &records,
            &records,
            &summaries,
            content,
            content,
            records[0],
            records[1].id,
            false,
        );
        assert_eq!(result, Err(expected));
        assert_eq!(trace.monotonic_reached, 0);
    }
    let (result, trace) = model(
        &f.records,
        &f.records,
        &original,
        content,
        content,
        f.records[0],
        f.records[3].id,
        false,
    );
    assert_eq!(result, Err(ModelError::UnprovenEndpoint));
    assert_eq!(trace.monotonic_reached, 0);
    let (restored, trace) = model(
        &f.records,
        &f.records,
        &original,
        content,
        content,
        f.records[0],
        f.records[1].id,
        false,
    );
    assert_eq!(restored, Ok(f.records[1].id));
    assert_eq!(trace.monotonic_reached, 1);
    assert_eq!(f.backend.calls(), (0, 0));
}

#[test]
fn r_m_qc_does_not_authenticate_external_parent_or_content_oracle() {
    let f = Fixture::new();
    let summaries = f.summaries().map(Some);
    let content = &f.proposal.txs[0];
    let mut records = f.records;
    records[1].parent[31] ^= 1;
    assert_eq!(fixture_id(10, records[1].parent), f.records[1].id);
    f.qc(&f.qcs[0]).unwrap();
    let (result, _) = model(
        &records,
        &f.records,
        &summaries,
        content,
        content,
        f.records[0],
        f.records[1].id,
        false,
    );
    assert_eq!(result, Err(ModelError::ParentAssociationMismatch));
    let mut substituted = content.clone();
    substituted[0] ^= 1;
    f.qc(&f.qcs[0]).unwrap();
    let (result, _) = model(
        &f.records,
        &f.records,
        &summaries,
        &substituted,
        content,
        f.records[0],
        f.records[1].id,
        false,
    );
    assert_eq!(result, Err(ModelError::ContentAssociationMismatch));
    let (restored, _) = model(
        &f.records,
        &f.records,
        &summaries,
        content,
        content,
        f.records[0],
        f.records[1].id,
        false,
    );
    assert_eq!(restored, Ok(f.records[1].id));
    assert_eq!(f.backend.calls(), (6, 0));
    println!("R/M QC remained valid for unchanged signed bytes; explicit unauthenticated test oracle rejected substitutions");
}

#[test]
fn isolation_sentinel_oracles_and_test_only_support_have_no_protected_caller() {
    let mut oracle = EffectOracle::default();
    assert!(oracle.isolated());
    for kind in 0..6 {
        oracle.sentinel_attempt(kind);
        assert!(!oracle.isolated());
        oracle.attempts[kind] = 0;
    }
    assert!(oracle.isolated());
    println!("ISOLATION sentinel-only effect oracle: application/store/network/signing-authority/clear/resume=0; \
              each attempted-effect sentinel detected; no real effect API connected");
}
