//! Isolated R/D/S/M support. No production caller, signer authority, stores,
//! delivery, clearance or resume APIs. Model/oracle checks are not proofs.

use std::collections::BTreeMap;
use std::mem::size_of;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use qbind_consensus::crypto_verifier::SimpleBackendRegistry;
use qbind_consensus::key_registry::SuiteAwareValidatorKeyProvider;
use qbind_consensus::qc_verify_domain::{
    verify_quorum_certificate_with_domain, QcDomainVerifyError, VerifiedQuorumCertificate,
};
use qbind_consensus::validator_set::{ConsensusValidatorSet, ValidatorSetEntry};
use qbind_consensus::ValidatorId;
use qbind_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier};
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::{
    ConsensusSigSuiteId, ML_DSA_44_PUBLIC_KEY_SIZE, ML_DSA_44_SECRET_KEY_SIZE,
    ML_DSA_44_SIGNATURE_SIZE, SUITE_PQ_RESERVED_1,
};
use qbind_types::ChainId;
use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate as WireQc, Vote};
use qbind_wire::io::{WireDecode, WireEncode};
use qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2;

pub const ENCODED_CAP: usize = 65_536;
pub const D_BYTE_LENGTH_CAP: usize = 131_072;
pub const FRAME_BYTES: usize = 6 * 8;
pub const SIG: usize = ML_DSA_44_SIGNATURE_SIZE;
pub type Id = [u8; 32];

#[derive(Default)]
pub struct CountingRealBackend {
    pub votes: AtomicUsize,
    pub proposals: AtomicUsize,
}

impl CountingRealBackend {
    pub fn reset(&self) {
        self.votes.store(0, Ordering::SeqCst);
        self.proposals.store(0, Ordering::SeqCst);
    }

    pub fn calls(&self) -> (usize, usize) {
        (
            self.votes.load(Ordering::SeqCst),
            self.proposals.load(Ordering::SeqCst),
        )
    }
}

impl ConsensusSigVerifier for CountingRealBackend {
    fn verify_vote(
        &self,
        id: u64,
        pk: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), ConsensusSigError> {
        self.votes.fetch_add(1, Ordering::SeqCst);
        MlDsa44Backend.verify_vote(id, pk, message, signature)
    }

    fn verify_proposal(
        &self,
        id: u64,
        pk: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), ConsensusSigError> {
        self.proposals.fetch_add(1, Ordering::SeqCst);
        MlDsa44Backend.verify_proposal(id, pk, message, signature)
    }
}

#[derive(Debug, Default)]
pub struct Keys {
    pub public: BTreeMap<ValidatorId, Vec<u8>>,
    pub returned_clones: AtomicUsize,
}

impl SuiteAwareValidatorKeyProvider for Keys {
    fn get_suite_and_key(&self, id: ValidatorId) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        self.public.get(&id).map(|pk| {
            self.returned_clones.fetch_add(1, Ordering::SeqCst);
            (SUITE_PQ_RESERVED_1, pk.clone())
        })
    }
}

pub fn domain() -> ProposalVoteSigningDomainV2 {
    ProposalVoteSigningDomainV2::try_new(ChainId(0xABCD_0000_0000_0001), 5, [1; 32], [2; 32])
        .expect("synthetic trusted domain")
}

pub fn validators(ids: &[u64]) -> ConsensusValidatorSet {
    ConsensusValidatorSet::new(
        ids.iter()
            .map(|id| ValidatorSetEntry {
                id: ValidatorId(*id),
                voting_power: 1,
            })
            .collect::<Vec<_>>(),
    )
    .expect("synthetic equal-weight authority")
}

// Test arithmetic matching pinned derive_block_id_from_header; not a call to
// that private engine function and not a replacement identity construction.
pub fn fixture_id(view: u64, parent: Id) -> Id {
    let mut id = [0; 32];
    id[..8].copy_from_slice(&0u64.to_le_bytes());
    id[8..16].copy_from_slice(&view.to_le_bytes());
    id[16..].copy_from_slice(&parent[..16]);
    id
}

pub fn vote(qc: &WireQc, signer: u16, signature: Vec<u8>) -> Vote {
    Vote {
        version: qc.version,
        chain_id: qc.chain_id,
        epoch: qc.epoch,
        height: qc.height,
        round: qc.round,
        step: qc.step,
        block_id: qc.block_id,
        validator_index: signer,
        suite_id: qc.suite_id,
        signature,
    }
}

pub struct Fixture {
    pub domain: ProposalVoteSigningDomainV2,
    pub validators: ConsensusValidatorSet,
    pub keys: Keys,
    pub backend: Arc<CountingRealBackend>,
    pub registry: SimpleBackendRegistry,
    pub qcs: [WireQc; 3],
    pub proposal: BlockProposal,
    pub fourth_signature: Vec<u8>,
    pub records: [Record; 4],
}

impl Fixture {
    pub fn new() -> Self {
        let domain = domain();
        let validators = validators(&[0, 1, 2, 3]);
        let mut keys = Keys::default();
        let mut setup_secret_keys = Vec::new();
        for id in 0..4 {
            let (pk, sk) = MlDsa44Backend::generate_keypair().expect("synthetic keygen");
            keys.public.insert(ValidatorId(id), pk);
            setup_secret_keys.push(sk);
        }
        assert_eq!(keys.public.values().map(Vec::len).sum::<usize>(), 5_248);
        assert_eq!(
            setup_secret_keys.iter().map(Vec::len).sum::<usize>(),
            10_240
        );
        println!(
            "SETUP synthetic_pk_lengths={} synthetic_sk_lengths={} pk_capacity={} sk_capacity={} \
             keygen/backend/allocator/stack working memory=UNMEASURED; no total-memory bound",
            4 * ML_DSA_44_PUBLIC_KEY_SIZE,
            4 * ML_DSA_44_SECRET_KEY_SIZE,
            keys.public.values().map(Vec::capacity).sum::<usize>(),
            setup_secret_keys.iter().map(Vec::capacity).sum::<usize>(),
        );
        let anchor = [9; 32];
        let g = fixture_id(10, anchor);
        let p = fixture_id(11, g);
        let b = fixture_id(12, p);
        let records = [
            Record {
                id: anchor,
                parent: [0; 32],
                height: 9,
                view: 9,
                epoch: 0,
            },
            Record {
                id: g,
                parent: anchor,
                height: 10,
                view: 10,
                epoch: 0,
            },
            Record {
                id: p,
                parent: g,
                height: 11,
                view: 11,
                epoch: 0,
            },
            Record {
                id: b,
                parent: p,
                height: 12,
                view: 12,
                epoch: 0,
            },
        ];
        let qcs = std::array::from_fn(|index| {
            let record = records[index + 1];
            let mut qc = WireQc {
                version: 1,
                chain_id: 5,
                epoch: 0,
                height: record.height,
                round: record.view,
                step: 1,
                block_id: record.id,
                suite_id: 100,
                signer_bitmap: vec![0b111],
                signatures: Vec::new(),
            };
            for signer in 0..3 {
                let message = vote(&qc, signer, Vec::new());
                qc.signatures.push(
                    MlDsa44Backend::sign(
                        &setup_secret_keys[usize::from(signer)],
                        &domain.vote_preimage(&message),
                    )
                    .expect("synthetic constituent signature"),
                );
            }
            qc
        });
        let fourth_signature = MlDsa44Backend::sign(
            &setup_secret_keys[3],
            &domain.vote_preimage(&vote(&qcs[0], 3, Vec::new())),
        )
        .expect("synthetic D extra-signature control");
        let mut proposal = BlockProposal {
            header: BlockHeader {
                version: 1,
                chain_id: 5,
                epoch: 0,
                height: 11,
                round: 11,
                parent_block_id: g,
                payload_hash: [8; 32],
                proposer_index: 0,
                suite_id: 100,
                tx_count: 1,
                timestamp: 0,
                payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
                next_epoch: 0,
                batch_commitment: [0; 32],
            },
            qc: Some(qcs[0].clone()),
            txs: vec![vec![7; 256]],
            signature: Vec::new(),
        };
        proposal.signature =
            MlDsa44Backend::sign(&setup_secret_keys[0], &domain.proposal_preimage(&proposal))
                .expect("synthetic proposer signature");
        for sk in &mut setup_secret_keys {
            sk.fill(0);
        }
        drop(setup_secret_keys);
        let backend = Arc::new(CountingRealBackend::default());
        let registry = SimpleBackendRegistry::with_backend(SUITE_PQ_RESERVED_1, backend.clone());
        Self {
            domain,
            validators,
            keys,
            backend,
            registry,
            qcs,
            proposal,
            fourth_signature,
            records,
        }
    }

    pub fn qc(&self, qc: &WireQc) -> Result<VerifiedQuorumCertificate, QcDomainVerifyError> {
        verify_quorum_certificate_with_domain(
            qc,
            &self.domain,
            0,
            &self.validators,
            &self.keys,
            &self.registry,
        )
    }

    pub fn segments(&self) -> [Vec<u8>; 6] {
        let mut segments: [Vec<u8>; 6] = std::array::from_fn(|_| Vec::new());
        for (out, qc) in segments[..3].iter_mut().zip(&self.qcs) {
            qc.encode(out);
        }
        segments[3] = self.proposal.canonical_body();
        segments[4] = self.proposal.signature.clone();
        // Existing encodings plus test-only graph metadata, not a wire proposal.
        for record in &self.records {
            segments[5].extend_from_slice(&record.id);
            segments[5].extend_from_slice(&record.parent);
            segments[5].extend_from_slice(&record.height.to_le_bytes());
            segments[5].extend_from_slice(&record.view.to_le_bytes());
            segments[5].extend_from_slice(&record.epoch.to_le_bytes());
            segments[5].extend_from_slice(&5u32.to_le_bytes());
        }
        segments[5].extend_from_slice(&self.records[0].id);
        segments[5].extend_from_slice(&9u64.to_le_bytes());
        segments[5].extend_from_slice(&9u64.to_le_bytes());
        segments[5].extend_from_slice(self.domain.genesis_identity());
        assert_eq!(segments[5].len(), 448);
        segments
    }

    pub fn summaries(&self) -> [Summary; 3] {
        let summaries = std::array::from_fn(|index| {
            let verified = self.qc(&self.qcs[index]).expect("R verified summary setup");
            let qc = verified.certificate();
            Summary {
                id: qc.block_id,
                height: qc.height,
                view: qc.round,
                epoch: qc.epoch,
            }
        });
        self.backend.reset();
        summaries
    }

    pub fn retained_inventory(&self) {
        fn qc_capacity(qc: &WireQc) -> usize {
            qc.signer_bitmap.capacity()
                + qc.signatures.capacity() * size_of::<Vec<u8>>()
                + qc.signatures.iter().map(Vec::capacity).sum::<usize>()
        }
        println!(
            "RETAINED measured_vector_storage qcs={} embedded_qc={} proposal_sig={} \
             tx_outer={} tx_bytes={} public_keys={} fourth_D_signature={} \
             inline_fixture={} provider_key_clones_so_far={}; \
             backend stack/heap, allocator overhead, temporary preimages=UNMEASURED; \
             total-memory/runtime/cancellation/network guarantee=NONE",
            self.qcs.iter().map(qc_capacity).sum::<usize>(),
            qc_capacity(self.proposal.qc.as_ref().expect("embedded QC")),
            self.proposal.signature.capacity(),
            self.proposal.txs.capacity() * size_of::<Vec<u8>>(),
            self.proposal.txs.iter().map(Vec::capacity).sum::<usize>(),
            self.keys.public.values().map(Vec::capacity).sum::<usize>(),
            self.fourth_signature.capacity(),
            size_of::<Self>(),
            self.keys.returned_clones.load(Ordering::SeqCst),
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub id: Id,
    pub parent: Id,
    pub height: u64,
    pub view: u64,
    pub epoch: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Summary {
    pub id: Id,
    pub height: u64,
    pub view: u64,
    pub epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelError {
    MissingOwnQc,
    ParentLinkMismatch,
    ViewsNotIncreasing,
    NonContinuousHeight,
    UnsupportedTransition,
    ParentAssociationMismatch,
    ContentAssociationMismatch,
    IncoherentBaseline,
    UnprovenEndpoint,
    NonMonotonicEndpoint,
}

#[derive(Default, Debug)]
pub struct ModelTrace {
    pub earlier_passed: bool,
    pub monotonic_reached: usize,
}

pub struct ModelInput<'a> {
    pub records: &'a [Record; 4],
    pub summaries: &'a [Option<Summary>; 3],
    pub oracle: &'a [Record; 4],
    pub content: &'a [u8],
    pub expected_content: &'a [u8],
    pub baseline: Record,
    pub endpoint: Id,
}

pub fn test_check_gpb_associations(
    input: ModelInput<'_>,
    bypass_whole_monotonic_predicate: bool,
    trace: &mut ModelTrace,
) -> Result<Id, ModelError> {
    let records = input.records;
    for (index, record) in records.iter().enumerate() {
        if record.epoch != 0 {
            return Err(ModelError::UnsupportedTransition);
        }
        if record.id != input.oracle[index].id || record.parent != input.oracle[index].parent {
            return Err(ModelError::ParentAssociationMismatch);
        }
    }
    if input.content != input.expected_content {
        return Err(ModelError::ContentAssociationMismatch);
    }
    for index in 0..3 {
        let record = records[index + 1];
        let summary = input.summaries[index].ok_or(ModelError::MissingOwnQc)?;
        if summary.id != record.id
            || summary.height != record.height
            || summary.view != record.view
            || summary.epoch != record.epoch
        {
            return Err(ModelError::MissingOwnQc);
        }
        if record.parent != records[index].id {
            return Err(ModelError::ParentLinkMismatch);
        }
        if records[index].height.checked_add(1) != Some(record.height) {
            return Err(ModelError::NonContinuousHeight);
        }
    }
    let g = records[1];
    if !(g.view < records[2].view && records[2].view < records[3].view) {
        return Err(ModelError::ViewsNotIncreasing);
    }
    if input.endpoint != g.id {
        return Err(ModelError::UnprovenEndpoint);
    }
    if !records.iter().any(|record| *record == input.baseline) {
        return Err(ModelError::IncoherentBaseline);
    }
    trace.earlier_passed = true;
    trace.monotonic_reached += 1;
    if !bypass_whole_monotonic_predicate
        && !(g.height > input.baseline.height
            && g.view > input.baseline.view
            && g.id != input.baseline.id)
    {
        return Err(ModelError::NonMonotonicEndpoint);
    }
    Ok(g.id)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    EncodedBudgetExceeded,
    LengthOverflow,
    TruncatedSegment,
    NestedLengthExceeded,
    ShapeMismatch,
    TrailingBytes,
    DecoderFailure(qbind_wire::error::WireError),
}

pub fn test_admit_fixture_segments<T>(
    lengths: [usize; 6],
    bypass_length_gate: bool,
    materialize: impl FnOnce() -> T,
) -> Result<T, AdmissionError> {
    if !bypass_length_gate {
        let total = lengths.into_iter().try_fold(FRAME_BYTES, |sum, length| {
            sum.checked_add(length)
                .ok_or(AdmissionError::LengthOverflow)
        })?;
        if total > ENCODED_CAP {
            return Err(AdmissionError::EncodedBudgetExceeded);
        }
    }
    Ok(materialize())
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], AdmissionError> {
        if length > self.0.len() {
            return Err(AdmissionError::TruncatedSegment);
        }
        let (part, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(part)
    }

    fn u16(&mut self) -> Result<usize, AdmissionError> {
        let bytes: [u8; 2] = self.take(2)?.try_into().expect("checked size");
        Ok(usize::from(u16::from_le_bytes(bytes)))
    }

    fn u32(&mut self) -> Result<usize, AdmissionError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().expect("checked size");
        usize::try_from(u32::from_le_bytes(bytes)).map_err(|_| AdmissionError::LengthOverflow)
    }

    fn end(self) -> Result<(), AdmissionError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(AdmissionError::TrailingBytes)
        }
    }
}

fn scan_qc(bytes: &[u8]) -> Result<(), AdmissionError> {
    let mut cursor = Cursor(bytes);
    cursor.take(65)?;
    if cursor.u16()? != 1 {
        return Err(AdmissionError::NestedLengthExceeded);
    }
    let bitmap = cursor.take(1)?[0];
    if bitmap.count_ones() != 3 || bitmap & !0b1111 != 0 || cursor.u16()? != 3 {
        return Err(AdmissionError::ShapeMismatch);
    }
    for _ in 0..3 {
        if cursor.u16()? != SIG {
            return Err(AdmissionError::NestedLengthExceeded);
        }
        cursor.take(SIG)?;
    }
    cursor.end()
}

fn scan_proposal_body(bytes: &[u8]) -> Result<(), AdmissionError> {
    let mut cursor = Cursor(bytes);
    cursor.take(97)?;
    if cursor.u32()? != 1 {
        return Err(AdmissionError::ShapeMismatch);
    }
    cursor.take(49)?;
    let qc_length = cursor.u32()?;
    if qc_length != 7_336 {
        return Err(AdmissionError::NestedLengthExceeded);
    }
    scan_qc(cursor.take(qc_length)?)?;
    let tx_length = cursor.u32()?;
    if tx_length > 256 {
        return Err(AdmissionError::NestedLengthExceeded);
    }
    cursor.take(tx_length)?;
    cursor.end()
}

pub fn test_scan_then_decode(
    segments: [&[u8]; 6],
    bypass_scanner: bool,
    decoder_calls: &mut usize,
) -> Result<(), AdmissionError> {
    if !bypass_scanner {
        test_admit_fixture_segments(segments.map(<[u8]>::len), false, || ())?;
        for segment in &segments[..3] {
            scan_qc(segment)?;
        }
        scan_proposal_body(segments[3])?;
        if segments[4].len() != SIG || segments[5].len() != 448 {
            return Err(AdmissionError::ShapeMismatch);
        }
    }
    for segment in &segments[..3] {
        *decoder_calls += 1;
        let mut input = *segment;
        WireQc::decode(&mut input).map_err(AdmissionError::DecoderFailure)?;
        if !input.is_empty() {
            return Err(AdmissionError::TrailingBytes);
        }
    }
    Ok(())
}

#[derive(Default)]
pub struct EffectOracle {
    pub attempts: [usize; 6],
}

impl EffectOracle {
    pub fn isolated(&self) -> bool {
        self.attempts == [0; 6]
    }

    pub fn sentinel_attempt(&mut self, kind: usize) {
        self.attempts[kind] += 1;
    }
}
