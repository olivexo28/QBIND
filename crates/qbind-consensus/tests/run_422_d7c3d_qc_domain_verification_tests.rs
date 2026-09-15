//! Run 422 D7-C3D — pure, dormant D6-compatible QuorumCertificate verification.
//!
//! Focused behavioral tests for
//! [`qbind_consensus::verify_quorum_certificate_with_domain`]. Cryptographic
//! positive and negative controls use the **real** ML-DSA-44 backend
//! (`MlDsa44Backend`), reusing the D6 fixtures/registry interfaces. A
//! [`CountingVerifier`] adapter that *delegates to the real backend* is used to
//! assert, by direct backend-invocation count, that rejections claimed to
//! happen "before crypto" really do.
//!
//! Every negative cryptographic case has a matching same-key positive control
//! and changes only the boundary under test. Generated keys are fixtures, never
//! operational credentials.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use qbind_consensus::crypto_verifier::SimpleBackendRegistry;
use qbind_consensus::ids::ValidatorId;
use qbind_consensus::key_registry::SuiteAwareValidatorKeyProvider;
use qbind_consensus::qc_verify_domain::{
    verify_quorum_certificate_with_domain, QcDomainVerifyError, MAX_BITMAP_LEN, MAX_SIGNATURE_LEN,
};
use qbind_consensus::validator_set::{ConsensusValidatorSet, ValidatorSetEntry};
use qbind_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier};
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::{ConsensusSigSuiteId, SUITE_PQ_RESERVED_1, SUITE_TOY_SHA3};
use qbind_hash::consensus::vote_digest;
use qbind_types::ChainId;
use qbind_wire::consensus::{QuorumCertificate, Vote};
use qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2;

const TEST_SUITE: ConsensusSigSuiteId = SUITE_PQ_RESERVED_1; // 100 = ML-DSA-44
const TEST_SUITE_U16: u16 = 100;
const WIRE_CHAIN: u32 = 5;
const EPOCH: u64 = 0;

// ---------------------------------------------------------------------------
// Counting verifier adapter: delegates to the REAL backend, counts calls.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct CountingVerifier {
    inner: Arc<dyn ConsensusSigVerifier>,
    vote_calls: Arc<AtomicUsize>,
}

impl CountingVerifier {
    fn new(inner: Arc<dyn ConsensusSigVerifier>) -> Self {
        Self {
            inner,
            vote_calls: Arc::new(AtomicUsize::new(0)),
        }
    }
    fn counter(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.vote_calls)
    }
}

impl ConsensusSigVerifier for CountingVerifier {
    fn verify_vote(
        &self,
        validator_id: u64,
        pk: &[u8],
        preimage: &[u8],
        signature: &[u8],
    ) -> Result<(), ConsensusSigError> {
        self.vote_calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .verify_vote(validator_id, pk, preimage, signature)
    }
    fn verify_proposal(
        &self,
        validator_id: u64,
        pk: &[u8],
        preimage: &[u8],
        signature: &[u8],
    ) -> Result<(), ConsensusSigError> {
        self.inner
            .verify_proposal(validator_id, pk, preimage, signature)
    }
}

// A backend that is registered but always faults with a backend error (not a
// plain invalid/malformed signature).
struct FaultingVerifier;
impl ConsensusSigVerifier for FaultingVerifier {
    fn verify_vote(
        &self,
        _validator_id: u64,
        _pk: &[u8],
        _preimage: &[u8],
        _signature: &[u8],
    ) -> Result<(), ConsensusSigError> {
        Err(ConsensusSigError::Other(
            "simulated backend fault".to_string(),
        ))
    }
    fn verify_proposal(
        &self,
        _validator_id: u64,
        _pk: &[u8],
        _preimage: &[u8],
        _signature: &[u8],
    ) -> Result<(), ConsensusSigError> {
        Err(ConsensusSigError::Other(
            "simulated backend fault".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Key provider (per-validator suite + pk), matching the D6 fixture shape.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct TestKeyProvider {
    keys: HashMap<ValidatorId, (ConsensusSigSuiteId, Vec<u8>)>,
}
impl SuiteAwareValidatorKeyProvider for TestKeyProvider {
    fn get_suite_and_key(&self, id: ValidatorId) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        self.keys.get(&id).cloned()
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    validators: ConsensusValidatorSet,
    kp: TestKeyProvider,
    sks: HashMap<ValidatorId, Vec<u8>>,
}

/// Build a fixture where validator `ids[i]` has voting power `powers[i]` and a
/// freshly generated ML-DSA-44 keypair under the ML-DSA-44 suite.
fn make_fixture(ids: &[u64], powers: &[u64]) -> Fixture {
    assert_eq!(ids.len(), powers.len());
    let mut keys = HashMap::new();
    let mut sks = HashMap::new();
    let mut entries = Vec::new();
    for (&id, &power) in ids.iter().zip(powers.iter()) {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
        keys.insert(ValidatorId(id), (TEST_SUITE, pk));
        sks.insert(ValidatorId(id), sk);
        entries.push(ValidatorSetEntry {
            id: ValidatorId(id),
            voting_power: power,
        });
    }
    Fixture {
        validators: ConsensusValidatorSet::new(entries).expect("valid set"),
        kp: TestKeyProvider { keys },
        sks,
    }
}

fn uniform_fixture(n: u64) -> Fixture {
    let ids: Vec<u64> = (0..n).collect();
    let powers: Vec<u64> = vec![1; n as usize];
    make_fixture(&ids, &powers)
}

fn genesis_id(seed: u8) -> [u8; 32] {
    let mut g = [0u8; 32];
    for (i, b) in g.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8).wrapping_add(1);
    }
    g
}
fn commitment(seed: u8) -> [u8; 32] {
    let mut c = [0u8; 32];
    for (i, b) in c.iter_mut().enumerate() {
        *b = seed.wrapping_mul(5).wrapping_add(i as u8).wrapping_add(3);
    }
    c
}

fn domain(runtime: u64, wire: u32, g: [u8; 32], c: [u8; 32]) -> ProposalVoteSigningDomainV2 {
    ProposalVoteSigningDomainV2::try_new(ChainId(runtime), wire, g, c).expect("domain")
}

/// The canonical trusted domain used by positive controls.
fn base_domain() -> ProposalVoteSigningDomainV2 {
    domain(
        0xABCD_0000_0000_0001,
        WIRE_CHAIN,
        genesis_id(1),
        commitment(1),
    )
}

fn base_block_id() -> [u8; 32] {
    [7u8; 32]
}

/// An unsigned QC skeleton (fields shared by every constituent Vote).
fn unsigned_qc() -> QuorumCertificate {
    QuorumCertificate {
        version: 1,
        chain_id: WIRE_CHAIN,
        epoch: EPOCH,
        height: 9,
        round: 9,
        step: 1,
        block_id: base_block_id(),
        suite_id: TEST_SUITE_U16,
        signer_bitmap: vec![],
        signatures: vec![],
    }
}

/// Reconstruct the constituent Vote for `signer_index` from a QC skeleton
/// (exactly how the verifier reconstructs it).
fn constituent_vote(qc: &QuorumCertificate, signer_index: u16) -> Vote {
    Vote {
        version: qc.version,
        chain_id: qc.chain_id,
        epoch: qc.epoch,
        height: qc.height,
        round: qc.round,
        step: qc.step,
        block_id: qc.block_id,
        validator_index: signer_index,
        suite_id: qc.suite_id,
        signature: vec![],
    }
}

fn set_bit(bitmap: &mut Vec<u8>, index: u16) {
    let byte = (index / 8) as usize;
    let bit = index % 8;
    if bitmap.len() <= byte {
        bitmap.resize(byte + 1, 0);
    }
    bitmap[byte] |= 1u8 << bit;
}

/// Build a QC signed under `d` by the given signer indices (must be ascending
/// and distinct). Signatures are the real ML-DSA-44 signatures over the v2
/// vote preimage of each reconstructed constituent Vote.
fn build_signed_qc(
    f: &Fixture,
    d: &ProposalVoteSigningDomainV2,
    signers: &[u16],
) -> QuorumCertificate {
    let mut qc = unsigned_qc();
    let mut bitmap: Vec<u8> = Vec::new();
    let mut sigs: Vec<Vec<u8>> = Vec::new();
    for &s in signers {
        set_bit(&mut bitmap, s);
        let vote = constituent_vote(&qc, s);
        let pre = d.vote_preimage(&vote);
        let sk = f.sks.get(&ValidatorId(s as u64)).expect("sk");
        sigs.push(MlDsa44Backend::sign(sk, &pre).expect("sign"));
    }
    qc.signer_bitmap = bitmap;
    qc.signatures = sigs;
    qc
}

fn real_registry() -> SimpleBackendRegistry {
    SimpleBackendRegistry::with_backend(TEST_SUITE, Arc::new(MlDsa44Backend))
}

fn verify(
    f: &Fixture,
    qc: &QuorumCertificate,
    d: &ProposalVoteSigningDomainV2,
    br: &SimpleBackendRegistry,
) -> Result<qbind_consensus::VerifiedQuorumCertificate, QcDomainVerifyError> {
    verify_quorum_certificate_with_domain(qc, d, EPOCH, &f.validators, &f.kp, br)
}

// ===========================================================================
// 1. Valid D6-signed QC with a genuine quorum; verify the returned evidence.
// ===========================================================================

#[test]
fn c3d_1_valid_quorum_returns_associated_evidence() {
    let f = uniform_fixture(4); // total power 4, threshold ceil(8/3)=3
    let d = base_domain();
    let qc = build_signed_qc(&f, &d, &[0, 1, 2]); // power 3 >= 3
    let br = real_registry();
    let ev = verify(&f, &qc, &d, &br).expect("valid quorum verifies");
    assert_eq!(
        ev.signers(),
        &[ValidatorId(0), ValidatorId(1), ValidatorId(2)]
    );
    assert_eq!(ev.verified_voting_power(), 3);
    assert_eq!(ev.threshold(), 3);
    assert_eq!(ev.expected_wire_chain_id(), WIRE_CHAIN);
    assert_eq!(ev.authorized_epoch(), EPOCH);
    // Certificate is associated (owned) and matches the verified input.
    assert_eq!(ev.certificate(), &qc);
    assert_eq!(ev.domain(), &d);
}

#[test]
fn c3d_1_exact_quorum_all_signers() {
    let f = uniform_fixture(3); // total 3, threshold ceil(6/3)=2
    let d = base_domain();
    let qc = build_signed_qc(&f, &d, &[0, 1]);
    let br = real_registry();
    let ev = verify(&f, &qc, &d, &br).expect("verifies");
    assert_eq!(ev.verified_voting_power(), 2);
    assert_eq!(ev.threshold(), 2);
}

// ===========================================================================
// 2. Nonuniform voting powers: accept at threshold, reject below.
// ===========================================================================

#[test]
fn c3d_2_nonuniform_accept_at_threshold_reject_below() {
    // powers: [5,1,1,1,1] total 9 -> threshold ceil(18/3)=6.
    let f = make_fixture(&[0, 1, 2, 3, 4], &[5, 1, 1, 1, 1]);
    let d = base_domain();
    let br = real_registry();

    // Signer 0 alone = 5 < 6 -> reject below.
    let qc_below = build_signed_qc(&f, &d, &[0]);
    match verify(&f, &qc_below, &d, &br) {
        Err(QcDomainVerifyError::InsufficientVotingPower { have, need }) => {
            assert_eq!(have, 5);
            assert_eq!(need, 6);
        }
        other => panic!("expected InsufficientVotingPower, got {:?}", other),
    }

    // Signer 0 + signer 1 = 6 == threshold -> accept at threshold.
    let qc_at = build_signed_qc(&f, &d, &[0, 1]);
    let ev = verify(&f, &qc_at, &d, &br).expect("at threshold verifies");
    assert_eq!(ev.verified_voting_power(), 6);
    assert_eq!(ev.threshold(), 6);
}

// ===========================================================================
// 3. Sparse/reordered membership -> lookup by ValidatorId, not vector position.
// ===========================================================================

#[test]
fn c3d_3_sparse_reordered_membership_lookup_by_validator_id() {
    // Membership ids are sparse and NOT in ascending vector order. Vector
    // position != ValidatorId. Bit i must identify ValidatorId(i).
    let f = make_fixture(&[9, 2, 5, 0], &[1, 1, 1, 1]); // total 4, threshold 3
    let d = base_domain();
    let br = real_registry();
    // Signers by ValidatorId: 0, 2, 5 (three distinct members) -> power 3.
    let qc = build_signed_qc(&f, &d, &[0, 2, 5]);
    let ev = verify(&f, &qc, &d, &br).expect("verifies by ValidatorId");
    assert_eq!(
        ev.signers(),
        &[ValidatorId(0), ValidatorId(2), ValidatorId(5)]
    );
    assert_eq!(ev.verified_voting_power(), 3);

    // A bit at index 1 (vector position 1 holds ValidatorId(2), but bit 1
    // identifies ValidatorId(1) which is NOT a member) must be UnknownSigner,
    // proving position is not used.
    let qc_pos = build_signed_qc_unknown(&f, &d, &[1]);
    match verify(&f, &qc_pos, &d, &br) {
        Err(QcDomainVerifyError::UnknownSigner(id)) => assert_eq!(id, ValidatorId(1)),
        other => panic!("expected UnknownSigner(1), got {:?}", other),
    }
}

/// Build a QC whose set bits may reference non-members; signatures are signed
/// by a throwaway key so the failure is attributable to membership, not crypto
/// (though membership is checked before crypto anyway).
fn build_signed_qc_unknown(
    _f: &Fixture,
    d: &ProposalVoteSigningDomainV2,
    signers: &[u16],
) -> QuorumCertificate {
    let mut qc = unsigned_qc();
    let mut bitmap: Vec<u8> = Vec::new();
    let mut sigs: Vec<Vec<u8>> = Vec::new();
    let (_pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
    for &s in signers {
        set_bit(&mut bitmap, s);
        let vote = constituent_vote(&qc, s);
        let pre = d.vote_preimage(&vote);
        sigs.push(MlDsa44Backend::sign(&sk, &pre).expect("sign"));
    }
    qc.signer_bitmap = bitmap;
    qc.signatures = sigs;
    qc
}

// ===========================================================================
// 4. Correct-key, wrong-domain negatives (runtime id / genesis / authority),
//    each with a same-key positive control.
// ===========================================================================

#[test]
fn c3d_4_wrong_domain_runtime_id_rejected_with_control() {
    let f = uniform_fixture(4);
    let br = real_registry();
    let signing = base_domain();
    let qc = build_signed_qc(&f, &signing, &[0, 1, 2]);

    // Positive control: same domain verifies.
    verify(&f, &qc, &signing, &br).expect("control verifies");

    // Wrong runtime chain id only (same wire, genesis, commitment) -> invalid.
    let wrong = domain(
        0x9999_0000_0000_0002,
        WIRE_CHAIN,
        genesis_id(1),
        commitment(1),
    );
    match verify(&f, &qc, &wrong, &br) {
        Err(QcDomainVerifyError::InvalidSignature(_)) => {}
        other => panic!("expected InvalidSignature, got {:?}", other),
    }
}

#[test]
fn c3d_4_wrong_domain_genesis_identity_rejected_with_control() {
    let f = uniform_fixture(4);
    let br = real_registry();
    let signing = base_domain();
    let qc = build_signed_qc(&f, &signing, &[0, 1, 2]);
    verify(&f, &qc, &signing, &br).expect("control verifies");

    let wrong = domain(
        0xABCD_0000_0000_0001,
        WIRE_CHAIN,
        genesis_id(2),
        commitment(1),
    );
    match verify(&f, &qc, &wrong, &br) {
        Err(QcDomainVerifyError::InvalidSignature(_)) => {}
        other => panic!("expected InvalidSignature, got {:?}", other),
    }
}

#[test]
fn c3d_4_wrong_domain_authority_commitment_rejected_with_control() {
    let f = uniform_fixture(4);
    let br = real_registry();
    let signing = base_domain();
    let qc = build_signed_qc(&f, &signing, &[0, 1, 2]);
    verify(&f, &qc, &signing, &br).expect("control verifies");

    let wrong = domain(
        0xABCD_0000_0000_0001,
        WIRE_CHAIN,
        genesis_id(1),
        commitment(2),
    );
    match verify(&f, &qc, &wrong, &br) {
        Err(QcDomainVerifyError::InvalidSignature(_)) => {}
        other => panic!("expected InvalidSignature, got {:?}", other),
    }
}

// ===========================================================================
// 5. Wire-chain mismatch and genuinely-signed wrong-epoch QC: rejected BEFORE
//    crypto (asserted by zero backend calls).
// ===========================================================================

#[test]
fn c3d_5_wire_chain_mismatch_rejected_before_crypto() {
    let f = uniform_fixture(4);
    let d = base_domain();
    let counting = CountingVerifier::new(Arc::new(MlDsa44Backend));
    let counter = counting.counter();
    let br = SimpleBackendRegistry::with_backend(TEST_SUITE, Arc::new(counting));

    let mut qc = build_signed_qc(&f, &d, &[0, 1, 2]);
    qc.chain_id = WIRE_CHAIN + 1; // disagrees with domain expected wire chain
    match verify(&f, &qc, &d, &br) {
        Err(QcDomainVerifyError::WireChainMismatch { expected, actual }) => {
            assert_eq!(expected, WIRE_CHAIN);
            assert_eq!(actual, WIRE_CHAIN + 1);
        }
        other => panic!("expected WireChainMismatch, got {:?}", other),
    }
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "no crypto before wire gate"
    );
}

#[test]
fn c3d_5_wrong_epoch_rejected_before_crypto_with_control() {
    let f = uniform_fixture(4);
    let d = base_domain();

    // A genuinely-signed QC at epoch 3 (all fields consistent, real sigs).
    let mut qc = unsigned_qc();
    qc.epoch = 3;
    let mut bitmap = Vec::new();
    let mut sigs = Vec::new();
    for s in [0u16, 1, 2] {
        set_bit(&mut bitmap, s);
        let vote = constituent_vote(&qc, s);
        let pre = d.vote_preimage(&vote);
        let sk = f.sks.get(&ValidatorId(s as u64)).unwrap();
        sigs.push(MlDsa44Backend::sign(sk, &pre).expect("sign"));
    }
    qc.signer_bitmap = bitmap;
    qc.signatures = sigs;

    // Positive control: authorized epoch 3 verifies.
    let ev =
        verify_quorum_certificate_with_domain(&qc, &d, 3, &f.validators, &f.kp, &real_registry())
            .expect("epoch-3 control verifies");
    assert_eq!(ev.authorized_epoch(), 3);

    // Authorized epoch 0 (!= qc.epoch 3): rejected before crypto.
    let counting = CountingVerifier::new(Arc::new(MlDsa44Backend));
    let counter = counting.counter();
    let br = SimpleBackendRegistry::with_backend(TEST_SUITE, Arc::new(counting));
    match verify_quorum_certificate_with_domain(&qc, &d, 0, &f.validators, &f.kp, &br) {
        Err(QcDomainVerifyError::EpochMismatch { expected, actual }) => {
            assert_eq!(expected, 0);
            assert_eq!(actual, 3);
        }
        other => panic!("expected EpochMismatch, got {:?}", other),
    }
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "no crypto before epoch gate"
    );
}

// ===========================================================================
// 6. Legacy vote_digest signatures rejected by the D6 boundary (with control).
// ===========================================================================

#[test]
fn c3d_6_legacy_vote_digest_signatures_rejected_by_d6() {
    let f = uniform_fixture(4);
    let d = base_domain();
    let br = real_registry();

    // Positive control: proper D6 signatures verify.
    let good = build_signed_qc(&f, &d, &[0, 1, 2]);
    verify(&f, &good, &d, &br).expect("D6 control verifies");

    // Same keys, same suite, same membership: sign the LEGACY vote_digest
    // instead of the D6 v2 preimage. The failure must be InvalidSignature
    // (signed-input incompatibility), NOT a suite/key/backend error.
    let mut qc = unsigned_qc();
    let mut bitmap = Vec::new();
    let mut sigs = Vec::new();
    for s in [0u16, 1, 2] {
        set_bit(&mut bitmap, s);
        let vote = constituent_vote(&qc, s);
        let digest = vote_digest(&vote); // legacy signed input
        let sk = f.sks.get(&ValidatorId(s as u64)).unwrap();
        sigs.push(MlDsa44Backend::sign(sk, &digest).expect("sign"));
    }
    qc.signer_bitmap = bitmap;
    qc.signatures = sigs;
    match verify(&f, &qc, &d, &br) {
        Err(QcDomainVerifyError::InvalidSignature(id)) => assert_eq!(id, ValidatorId(0)),
        other => panic!(
            "expected InvalidSignature from legacy digest, got {:?}",
            other
        ),
    }
}

// ===========================================================================
// 7. Structural: empty / popcount-mismatch / overlong bitmap, unknown ids,
//    index representability, signature reordering, incorrect association.
// ===========================================================================

#[test]
fn c3d_7_empty_bitmap_no_signers_insufficient_power() {
    let f = uniform_fixture(4);
    let d = base_domain();
    let br = real_registry();
    let qc = unsigned_qc(); // empty bitmap, no sigs
    match verify(&f, &qc, &d, &br) {
        Err(QcDomainVerifyError::InsufficientVotingPower { have, need }) => {
            assert_eq!(have, 0);
            assert_eq!(need, 3);
        }
        other => panic!("expected InsufficientVotingPower, got {:?}", other),
    }
}

#[test]
fn c3d_7_popcount_mismatch_more_bits_than_sigs() {
    let f = uniform_fixture(4);
    let d = base_domain();
    let br = real_registry();
    let mut qc = build_signed_qc(&f, &d, &[0, 1, 2]);
    qc.signatures.pop(); // 3 bits, 2 sigs
    match verify(&f, &qc, &d, &br) {
        Err(QcDomainVerifyError::SignatureCountMismatch {
            popcount,
            signatures,
        }) => {
            assert_eq!(popcount, 3);
            assert_eq!(signatures, 2);
        }
        other => panic!("expected SignatureCountMismatch, got {:?}", other),
    }
}

#[test]
fn c3d_7_popcount_mismatch_more_sigs_than_bits() {
    let f = uniform_fixture(4);
    let d = base_domain();
    let br = real_registry();
    let mut qc = build_signed_qc(&f, &d, &[0, 1]);
    qc.signatures.push(vec![9u8; 10]); // 2 bits, 3 sigs
    match verify(&f, &qc, &d, &br) {
        Err(QcDomainVerifyError::SignatureCountMismatch {
            popcount,
            signatures,
        }) => {
            assert_eq!(popcount, 2);
            assert_eq!(signatures, 3);
        }
        other => panic!("expected SignatureCountMismatch, got {:?}", other),
    }
}

#[test]
fn c3d_7_overlong_bitmap_rejected() {
    let f = uniform_fixture(4);
    let d = base_domain();
    let br = real_registry();
    let mut qc = unsigned_qc();
    qc.signer_bitmap = vec![0u8; MAX_BITMAP_LEN + 1];
    match verify(&f, &qc, &d, &br) {
        Err(QcDomainVerifyError::BitmapTooLong { len, max }) => {
            assert_eq!(len, MAX_BITMAP_LEN + 1);
            assert_eq!(max, MAX_BITMAP_LEN);
        }
        other => panic!("expected BitmapTooLong, got {:?}", other),
    }
}

#[test]
fn c3d_7_max_len_bitmap_all_zero_is_within_bounds() {
    // A maximum-length all-zero bitmap is structurally accepted (0 signers ->
    // insufficient power), demonstrating the boundary is inclusive of
    // MAX_BITMAP_LEN and that representability is exactly u16::MAX.
    let f = uniform_fixture(4);
    let d = base_domain();
    let br = real_registry();
    let mut qc = unsigned_qc();
    qc.signer_bitmap = vec![0u8; MAX_BITMAP_LEN];
    match verify(&f, &qc, &d, &br) {
        Err(QcDomainVerifyError::InsufficientVotingPower { .. }) => {}
        other => panic!("expected InsufficientVotingPower, got {:?}", other),
    }
}

#[test]
fn c3d_7_unknown_signer_id_rejected() {
    let f = uniform_fixture(3); // members 0,1,2
    let d = base_domain();
    let br = real_registry();
    // Bit 5 -> ValidatorId(5), not a member.
    let qc = build_signed_qc_unknown(&f, &d, &[5]);
    match verify(&f, &qc, &d, &br) {
        Err(QcDomainVerifyError::UnknownSigner(id)) => assert_eq!(id, ValidatorId(5)),
        other => panic!("expected UnknownSigner(5), got {:?}", other),
    }
}

#[test]
fn c3d_7_membership_id_not_representable_rejected() {
    // A membership containing an id > u16::MAX is rejected before any signer
    // work (u16 wire index cannot represent it in this bounded phase).
    let f = make_fixture(&[0, 1, 70_000], &[1, 1, 1]);
    let d = base_domain();
    let br = real_registry();
    let qc = build_signed_qc(&f, &d, &[0, 1]);
    match verify(&f, &qc, &d, &br) {
        Err(QcDomainVerifyError::MembershipIdNotRepresentable(id)) => {
            assert_eq!(id, ValidatorId(70_000))
        }
        other => panic!("expected MembershipIdNotRepresentable, got {:?}", other),
    }
}

#[test]
fn c3d_7_signature_reordering_rejected_with_control() {
    let f = uniform_fixture(4);
    let d = base_domain();
    let br = real_registry();
    let qc = build_signed_qc(&f, &d, &[0, 1, 2]);
    verify(&f, &qc, &d, &br).expect("control verifies");

    // Swap two signatures: they are now associated with the wrong set bits, so
    // each verifies against the wrong signer's preimage -> InvalidSignature.
    let mut swapped = qc.clone();
    swapped.signatures.swap(0, 1);
    match verify(&f, &swapped, &d, &br) {
        Err(QcDomainVerifyError::InvalidSignature(_)) => {}
        other => panic!("expected InvalidSignature after reorder, got {:?}", other),
    }
}

#[test]
fn c3d_7_incorrect_association_wrong_signer_signature() {
    // Signer 0's bit carries signer 3's signature (over signer 3's preimage):
    // verifies against signer 0's key/preimage -> InvalidSignature.
    let f = uniform_fixture(4);
    let d = base_domain();
    let br = real_registry();
    let mut qc = build_signed_qc(&f, &d, &[0, 1, 2]);
    let vote3 = constituent_vote(&qc, 3);
    let pre3 = d.vote_preimage(&vote3);
    let sk3 = f.sks.get(&ValidatorId(3)).unwrap();
    qc.signatures[0] = MlDsa44Backend::sign(sk3, &pre3).expect("sign");
    match verify(&f, &qc, &d, &br) {
        Err(QcDomainVerifyError::InvalidSignature(id)) => assert_eq!(id, ValidatorId(0)),
        other => panic!("expected InvalidSignature(0), got {:?}", other),
    }
}

// ===========================================================================
// 8. Missing/truncated/excessive signatures; header tampering; valid quorum +
//    invalid extra signature.
// ===========================================================================

#[test]
fn c3d_8_empty_signature_for_set_bit_missing() {
    let f = uniform_fixture(4);
    let d = base_domain();
    let br = real_registry();
    let mut qc = build_signed_qc(&f, &d, &[0, 1, 2]);
    qc.signatures[1] = vec![]; // empty (unsigned) for a set bit
    match verify(&f, &qc, &d, &br) {
        Err(QcDomainVerifyError::MissingSignature(id)) => assert_eq!(id, ValidatorId(1)),
        other => panic!("expected MissingSignature(1), got {:?}", other),
    }
}

#[test]
fn c3d_8_truncated_signature_rejected() {
    let f = uniform_fixture(4);
    let d = base_domain();
    let br = real_registry();
    let mut qc = build_signed_qc(&f, &d, &[0, 1, 2]);
    qc.signatures[0].truncate(10); // malformed length for ML-DSA-44
    match verify(&f, &qc, &d, &br) {
        Err(QcDomainVerifyError::MalformedSignature(id))
        | Err(QcDomainVerifyError::InvalidSignature(id)) => assert_eq!(id, ValidatorId(0)),
        other => panic!("expected malformed/invalid signature, got {:?}", other),
    }
}

#[test]
fn c3d_8_overlong_signature_rejected() {
    let f = uniform_fixture(4);
    let d = base_domain();
    let br = real_registry();
    let mut qc = build_signed_qc(&f, &d, &[0, 1, 2]);
    qc.signatures[2] = vec![0u8; MAX_SIGNATURE_LEN + 1];
    match verify(&f, &qc, &d, &br) {
        Err(QcDomainVerifyError::MalformedSignature(id)) => assert_eq!(id, ValidatorId(2)),
        other => panic!("expected MalformedSignature(2), got {:?}", other),
    }
}

#[test]
fn c3d_8_header_field_tampering_rejected_with_control() {
    let f = uniform_fixture(4);
    let d = base_domain();
    let br = real_registry();
    let qc = build_signed_qc(&f, &d, &[0, 1, 2]);
    verify(&f, &qc, &d, &br).expect("control verifies");

    // Tamper a shared header field (height) after signing: the recomputed
    // preimage no longer matches the signatures -> InvalidSignature. Fields are
    // NOT rewritten to trusted values to force a pass.
    let mut tampered = qc.clone();
    tampered.height = 10;
    match verify(&f, &tampered, &d, &br) {
        Err(QcDomainVerifyError::InvalidSignature(_)) => {}
        other => panic!("expected InvalidSignature after tamper, got {:?}", other),
    }
}

#[test]
fn c3d_8_valid_quorum_plus_invalid_extra_signature_rejects() {
    // total 5, threshold ceil(10/3)=4. Signers 0..3 already meet quorum (4);
    // an additional signer 4 with an INVALID signature must still reject —
    // every declared signature is verified, not short-circuited at quorum.
    let f = uniform_fixture(5);
    let d = base_domain();
    let counting = CountingVerifier::new(Arc::new(MlDsa44Backend));
    let counter = counting.counter();
    let br = SimpleBackendRegistry::with_backend(TEST_SUITE, Arc::new(counting));

    let mut qc = build_signed_qc(&f, &d, &[0, 1, 2, 3, 4]);
    // Corrupt the last (5th) signature after quorum is already reached by the
    // first four.
    let last = qc.signatures.len() - 1;
    qc.signatures[last] = vec![0u8; qc.signatures[last].len()];
    match verify(&f, &qc, &d, &br) {
        Err(QcDomainVerifyError::InvalidSignature(id))
        | Err(QcDomainVerifyError::MalformedSignature(id)) => assert_eq!(id, ValidatorId(4)),
        other => panic!("expected failure on extra signature, got {:?}", other),
    }
    // All five signatures were reached by crypto (the fifth is the failing one).
    assert_eq!(counter.load(Ordering::SeqCst), 5);
}

// ===========================================================================
// 9. Missing key, governed-suite mismatch, unsupported backend, faulting
//    backend: distinct outcomes.
// ===========================================================================

#[test]
fn c3d_9_missing_key_rejected() {
    let mut f = uniform_fixture(4);
    let d = base_domain();
    let br = real_registry();
    let qc = build_signed_qc(&f, &d, &[0, 1, 2]);
    // Remove signer 1's key AFTER signing.
    f.kp.keys.remove(&ValidatorId(1));
    match verify(&f, &qc, &d, &br) {
        Err(QcDomainVerifyError::MissingKey(id)) => assert_eq!(id, ValidatorId(1)),
        other => panic!("expected MissingKey(1), got {:?}", other),
    }
}

#[test]
fn c3d_9_governed_suite_mismatch_rejected() {
    let mut f = uniform_fixture(4);
    let d = base_domain();
    let br = real_registry();
    let qc = build_signed_qc(&f, &d, &[0, 1, 2]);
    // Change signer 2's GOVERNED suite to something != QC wire suite.
    let (_old, pk) = f.kp.keys.get(&ValidatorId(2)).unwrap().clone();
    f.kp.keys.insert(ValidatorId(2), (SUITE_TOY_SHA3, pk));
    match verify(&f, &qc, &d, &br) {
        Err(QcDomainVerifyError::SuiteMismatch {
            validator_id,
            wire_suite,
            governance_suite,
        }) => {
            assert_eq!(validator_id, ValidatorId(2));
            assert_eq!(wire_suite, TEST_SUITE);
            assert_eq!(governance_suite, SUITE_TOY_SHA3);
        }
        other => panic!("expected SuiteMismatch, got {:?}", other),
    }
}

#[test]
fn c3d_9_unsupported_backend_rejected() {
    let f = uniform_fixture(4);
    let d = base_domain();
    // Registry has NO backend for the governed suite.
    let br = SimpleBackendRegistry::new();
    let qc = build_signed_qc(&f, &d, &[0, 1, 2]);
    match verify(&f, &qc, &d, &br) {
        Err(QcDomainVerifyError::UnsupportedBackend {
            validator_id,
            governance_suite,
        }) => {
            assert_eq!(validator_id, ValidatorId(0));
            assert_eq!(governance_suite, TEST_SUITE);
        }
        other => panic!("expected UnsupportedBackend, got {:?}", other),
    }
}

#[test]
fn c3d_9_faulting_backend_rejected_as_backend_error() {
    let f = uniform_fixture(4);
    let d = base_domain();
    let br = SimpleBackendRegistry::with_backend(TEST_SUITE, Arc::new(FaultingVerifier));
    let qc = build_signed_qc(&f, &d, &[0, 1, 2]);
    match verify(&f, &qc, &d, &br) {
        Err(QcDomainVerifyError::BackendError(id, msg)) => {
            assert_eq!(id, ValidatorId(0));
            assert!(msg.contains("simulated backend fault"));
        }
        other => panic!("expected BackendError, got {:?}", other),
    }
}

// ===========================================================================
// 10. Zero total power, safe threshold near arithmetic limits, no wraparound.
// ===========================================================================

#[test]
fn c3d_10_zero_total_power_rejected() {
    let f = make_fixture(&[0, 1, 2], &[0, 0, 0]);
    let d = base_domain();
    let br = real_registry();
    let qc = build_signed_qc(&f, &d, &[0, 1]);
    match verify(&f, &qc, &d, &br) {
        Err(QcDomainVerifyError::ZeroTotalVotingPower) => {}
        other => panic!("expected ZeroTotalVotingPower, got {:?}", other),
    }
}

#[test]
fn c3d_10_total_power_overflow_rejected() {
    // Two validators whose powers overflow u64 when summed with checked
    // arithmetic. The cached (saturating) total would silently clamp; we
    // reject. This also proves the later per-signer accumulation overflow is
    // mathematically excluded: a total that could overflow never reaches the
    // signer loop.
    let f = make_fixture(&[0, 1], &[u64::MAX, 1]);
    let d = base_domain();
    let br = real_registry();
    let qc = build_signed_qc(&f, &d, &[0, 1]);
    match verify(&f, &qc, &d, &br) {
        Err(QcDomainVerifyError::TotalVotingPowerOverflow) => {}
        other => panic!("expected TotalVotingPowerOverflow, got {:?}", other),
    }
}

#[test]
fn c3d_10_threshold_near_u64_limit_no_wraparound() {
    // A single validator with a very large power near u64::MAX. The threshold
    // ceil(2W/3) must be computed with wide arithmetic (no 2*W u64 wraparound)
    // and the single genuine signature must meet it.
    let w = u64::MAX / 2; // 2*w does not overflow u64 here, but pick a big value
    let f = make_fixture(&[0], &[w]);
    let d = base_domain();
    let br = real_registry();
    let qc = build_signed_qc(&f, &d, &[0]);
    let ev = verify(&f, &qc, &d, &br).expect("large-power quorum verifies");
    // ceil(2W/3) computed in u128 then cast; equals the reference computation.
    let expected_threshold = ((2u128 * w as u128).div_ceil(3)) as u64;
    assert_eq!(ev.threshold(), expected_threshold);
    assert_eq!(ev.verified_voting_power(), w);
    assert!(ev.verified_voting_power() >= ev.threshold());
}

#[test]
fn c3d_10_threshold_above_u64_half_no_wraparound() {
    // W > u64::MAX/2 so `2 * total` in plain u64 WOULD overflow. The checked
    // u128 threshold must not wrap; the genuine full-power signature meets it.
    let w = u64::MAX - 10;
    let f = make_fixture(&[0], &[w]);
    let d = base_domain();
    let br = real_registry();
    let qc = build_signed_qc(&f, &d, &[0]);
    let ev = verify(&f, &qc, &d, &br).expect("verifies without wraparound");
    let expected_threshold = ((2u128 * w as u128).div_ceil(3)) as u64;
    assert_eq!(ev.threshold(), expected_threshold);
    assert!(ev.verified_voting_power() >= ev.threshold());
}

// ===========================================================================
// 11. No partial result on failure; bounded Display/Debug diagnostics.
// ===========================================================================

#[test]
fn c3d_11_no_partial_result_on_failure() {
    // A failing verification returns Err (no VerifiedQuorumCertificate is
    // constructible on any failure path — the type has no public constructor).
    let f = uniform_fixture(4);
    let d = base_domain();
    let br = real_registry();
    let mut qc = build_signed_qc(&f, &d, &[0, 1, 2]);
    qc.signatures[2] = vec![0u8; qc.signatures[2].len()];
    let r = verify(&f, &qc, &d, &br);
    assert!(r.is_err());
}

#[test]
fn c3d_11_bounded_backend_error_diagnostics() {
    // A backend that faults with a very long message; the error's Display/Debug
    // must be bounded (truncated), never echoing an unbounded backend string.
    struct LongFault;
    impl ConsensusSigVerifier for LongFault {
        fn verify_vote(
            &self,
            _v: u64,
            _pk: &[u8],
            _pre: &[u8],
            _sig: &[u8],
        ) -> Result<(), ConsensusSigError> {
            Err(ConsensusSigError::Other("x".repeat(10_000)))
        }
        fn verify_proposal(
            &self,
            _v: u64,
            _pk: &[u8],
            _pre: &[u8],
            _sig: &[u8],
        ) -> Result<(), ConsensusSigError> {
            Err(ConsensusSigError::Other("x".repeat(10_000)))
        }
    }
    let f = uniform_fixture(4);
    let d = base_domain();
    let br = SimpleBackendRegistry::with_backend(TEST_SUITE, Arc::new(LongFault));
    let qc = build_signed_qc(&f, &d, &[0, 1, 2]);
    let err = verify(&f, &qc, &d, &br).expect_err("faults");
    let display = format!("{}", err);
    let debug = format!("{:?}", err);
    assert!(display.len() < 200, "display bounded: {}", display.len());
    assert!(debug.len() < 300, "debug bounded: {}", debug.len());
}

#[test]
fn c3d_11_debug_does_not_dump_signatures_on_success() {
    // The success evidence Debug is a bounded summary (no signature bytes).
    let f = uniform_fixture(4);
    let d = base_domain();
    let br = real_registry();
    let qc = build_signed_qc(&f, &d, &[0, 1, 2]);
    let ev = verify(&f, &qc, &d, &br).expect("verifies");
    let dbg = format!("{:?}", ev);
    assert!(dbg.contains("VerifiedQuorumCertificate"));
    assert!(dbg.contains("signer_count"));
    // ML-DSA-44 signatures are ~2420 bytes each; a dump of three would be huge.
    assert!(dbg.len() < 400, "debug bounded: {}", dbg.len());
}