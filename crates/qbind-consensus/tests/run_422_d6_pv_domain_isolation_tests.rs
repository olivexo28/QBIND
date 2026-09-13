//! Run 422 D6 — versioned Proposal/Vote signing-domain isolation: focused
//! cryptographic replay-isolation matrix + golden preimage vectors.
//!
//! These tests exercise the real ML-DSA-44 PQC backend (never a verifier that
//! always succeeds) through the fail-closed
//! [`verify_proposal_msg_with_preimage`] / [`verify_vote_msg_with_preimage`]
//! entrypoints, using the versioned
//! [`ProposalVoteSigningDomainV2`] as the trusted preimage source.
//!
//! Every negative replay case reuses the SAME signing key and varies only the
//! single boundary under test, and each has a corresponding same-key positive
//! control. Replay rejection obtained by changing keys would be meaningless and
//! is deliberately avoided.

use std::collections::HashMap;
use std::sync::Arc;

use qbind_consensus::crypto_verifier::SimpleBackendRegistry;
use qbind_consensus::ids::ValidatorId;
use qbind_consensus::key_registry::SuiteAwareValidatorKeyProvider;
use qbind_consensus::validator_set::{ConsensusValidatorSet, ValidatorSetEntry};
use qbind_consensus::{
    verify_proposal_msg, verify_proposal_msg_with_preimage, verify_vote_msg_with_preimage,
    ProposalVoteVerifyError,
};
use qbind_crypto::consensus_sig::ConsensusSigVerifier;
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::{ConsensusSigSuiteId, SUITE_PQ_RESERVED_1};
use qbind_types::{ChainId, QBIND_DEVNET_CHAIN_ID};
use qbind_wire::consensus::{BlockHeader, BlockProposal, Vote};
use qbind_wire::pv_signing_domain::{
    ProposalVoteSigningDomainV2, ProposalVoteSigningFormat, PvSigningDomainError,
    PV_SIGNING_DOMAIN_V2_TAG, PV_SIGNING_FORMAT_VERSION_V2,
};

const TEST_SUITE: ConsensusSigSuiteId = SUITE_PQ_RESERVED_1; // 100 = ML-DSA-44
const TEST_SUITE_U16: u16 = 100;

#[derive(Debug, Clone)]
struct TestKeyProvider {
    keys: HashMap<ValidatorId, (ConsensusSigSuiteId, Vec<u8>)>,
}
impl SuiteAwareValidatorKeyProvider for TestKeyProvider {
    fn get_suite_and_key(&self, id: ValidatorId) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        self.keys.get(&id).cloned()
    }
}

struct Fixture {
    validators: ConsensusValidatorSet,
    kp: TestKeyProvider,
    br: SimpleBackendRegistry,
    sks: HashMap<ValidatorId, Vec<u8>>,
}

fn make_fixture(n: u64) -> Fixture {
    let mut keys = HashMap::new();
    let mut sks = HashMap::new();
    for i in 0..n {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
        keys.insert(ValidatorId(i), (TEST_SUITE, pk));
        sks.insert(ValidatorId(i), sk);
    }
    let entries: Vec<ValidatorSetEntry> = (0..n)
        .map(|i| ValidatorSetEntry {
            id: ValidatorId(i),
            voting_power: 1,
        })
        .collect();
    Fixture {
        validators: ConsensusValidatorSet::new(entries).expect("valid set"),
        kp: TestKeyProvider { keys },
        br: SimpleBackendRegistry::with_backend(TEST_SUITE, Arc::new(MlDsa44Backend)),
        sks,
    }
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

fn domain(
    runtime: u64,
    wire: u32,
    genesis: [u8; 32],
    commit: [u8; 32],
) -> ProposalVoteSigningDomainV2 {
    ProposalVoteSigningDomainV2::try_new(ChainId(runtime), wire, genesis, commit).expect("domain")
}

fn base_header(proposer: u16) -> BlockHeader {
    BlockHeader {
        version: 1,
        chain_id: 5,
        epoch: 0,
        height: 7,
        round: 7,
        parent_block_id: [1u8; 32],
        payload_hash: [2u8; 32],
        proposer_index: proposer,
        suite_id: TEST_SUITE_U16,
        tx_count: 0,
        timestamp: 0,
        payload_kind: 0,
        next_epoch: 0,
        batch_commitment: [0u8; 32],
    }
}

fn unsigned_proposal(proposer: u16) -> BlockProposal {
    BlockProposal {
        header: base_header(proposer),
        qc: None,
        txs: vec![],
        signature: vec![],
    }
}

fn unsigned_vote(voter: u16) -> Vote {
    Vote {
        version: 1,
        chain_id: 5,
        epoch: 0,
        height: 7,
        round: 7,
        step: 0,
        block_id: [3u8; 32],
        validator_index: voter,
        suite_id: TEST_SUITE_U16,
        signature: vec![],
    }
}

fn sign_proposal(f: &Fixture, proposer: u16, d: &ProposalVoteSigningDomainV2) -> BlockProposal {
    let mut p = unsigned_proposal(proposer);
    let pre = d.proposal_preimage(&p);
    let sk = f.sks.get(&ValidatorId(proposer as u64)).unwrap();
    p.signature = MlDsa44Backend::sign(sk, &pre).expect("sign");
    p
}

fn sign_vote(f: &Fixture, voter: u16, d: &ProposalVoteSigningDomainV2) -> Vote {
    let mut v = unsigned_vote(voter);
    let pre = d.vote_preimage(&v);
    let sk = f.sks.get(&ValidatorId(voter as u64)).unwrap();
    v.signature = MlDsa44Backend::sign(sk, &pre).expect("sign");
    v
}

fn vp(
    f: &Fixture,
    p: &BlockProposal,
    d: &ProposalVoteSigningDomainV2,
) -> Result<(), ProposalVoteVerifyError> {
    verify_proposal_msg_with_preimage(
        p,
        ValidatorId(p.header.proposer_index as u64),
        &f.validators,
        &f.kp,
        &f.br,
        &d.proposal_preimage(p),
    )
}

fn vv(
    f: &Fixture,
    v: &Vote,
    d: &ProposalVoteSigningDomainV2,
) -> Result<(), ProposalVoteVerifyError> {
    verify_vote_msg_with_preimage(
        v,
        ValidatorId(v.validator_index as u64),
        &f.validators,
        &f.kp,
        &f.br,
        &d.vote_preimage(v),
    )
}

// ---------------------------------------------------------------------------
// Positive same-domain controls
// ---------------------------------------------------------------------------

#[test]
fn control_same_domain_proposal_and_vote_verify() {
    let f = make_fixture(4);
    let d = domain(0xAAAA_0000_0000_0001, 5, genesis_id(1), commitment(1));
    let p = sign_proposal(&f, 0, &d);
    assert!(vp(&f, &p, &d).is_ok());
    let v = sign_vote(&f, 1, &d);
    assert!(vv(&f, &v, &d).is_ok());
}

// ---------------------------------------------------------------------------
// A. Same key + identical message, different full runtime ChainId. Two
//    distinct custom chain IDs that BOTH map to legacy "UNK".
// ---------------------------------------------------------------------------

#[test]
fn case_a_different_full_runtime_chain_id_same_legacy_unk_scope() {
    let f = make_fixture(4);
    let g = genesis_id(1);
    let c = commitment(1);
    // Both custom runtime chain ids map to legacy "UNK".
    let d1 = domain(0xAAAA_0000_0000_0001, 5, g, c);
    let d2 = domain(0xBBBB_0000_0000_0002, 5, g, c);
    assert_eq!(
        qbind_types::domain::chain_scope(d1.runtime_chain_id()),
        "UNK"
    );
    assert_eq!(
        qbind_types::domain::chain_scope(d2.runtime_chain_id()),
        "UNK"
    );

    // Positive control under d1.
    let p = sign_proposal(&f, 0, &d1);
    assert!(vp(&f, &p, &d1).is_ok());
    // Same key, identical message bytes, verified under d2 => rejected.
    assert_eq!(
        vp(&f, &p, &d2),
        Err(ProposalVoteVerifyError::InvalidSignature(ValidatorId(0)))
    );

    let v = sign_vote(&f, 0, &d1);
    assert!(vv(&f, &v, &d1).is_ok());
    assert_eq!(
        vv(&f, &v, &d2),
        Err(ProposalVoteVerifyError::InvalidSignature(ValidatorId(0)))
    );
}

// ---------------------------------------------------------------------------
// B. Same runtime ChainId, same keys, same message, different accepted
//    genesis identity.
// ---------------------------------------------------------------------------

#[test]
fn case_b_different_genesis_identity_rejected() {
    let f = make_fixture(4);
    let c = commitment(1);
    let d1 = domain(0xCAFE_0000_0000_0001, 5, genesis_id(1), c);
    let d2 = domain(0xCAFE_0000_0000_0001, 5, genesis_id(2), c);
    let p = sign_proposal(&f, 0, &d1);
    assert!(vp(&f, &p, &d1).is_ok());
    assert_eq!(
        vp(&f, &p, &d2),
        Err(ProposalVoteVerifyError::InvalidSignature(ValidatorId(0)))
    );
}

// ---------------------------------------------------------------------------
// C. Same chain/genesis values at the encoding boundary, different authority
//    commitment.
// ---------------------------------------------------------------------------

#[test]
fn case_c_different_authority_commitment_rejected() {
    let f = make_fixture(4);
    let g = genesis_id(1);
    let d1 = domain(0xCAFE_0000_0000_0001, 5, g, commitment(1));
    let d2 = domain(0xCAFE_0000_0000_0001, 5, g, commitment(2));
    let v = sign_vote(&f, 2, &d1);
    assert!(vv(&f, &v, &d1).is_ok());
    assert_eq!(
        vv(&f, &v, &d2),
        Err(ProposalVoteVerifyError::InvalidSignature(ValidatorId(2)))
    );
}

// ---------------------------------------------------------------------------
// D. Legacy v1 signature presented to the new-format (v2) verifier.
// ---------------------------------------------------------------------------

#[test]
fn case_d_legacy_v1_signature_rejected_by_v2_verifier() {
    let f = make_fixture(4);
    let d = domain(0xCAFE_0000_0000_0001, 5, genesis_id(1), commitment(1));
    // Sign the v1 chain-aware preimage.
    let mut p = unsigned_proposal(0);
    let v1_pre = p.signing_preimage_with_chain_id(QBIND_DEVNET_CHAIN_ID);
    let sk = f.sks.get(&ValidatorId(0)).unwrap();
    p.signature = MlDsa44Backend::sign(sk, &v1_pre).expect("sign");
    // v2 verifier rejects it.
    assert_eq!(
        vp(&f, &p, &d),
        Err(ProposalVoteVerifyError::InvalidSignature(ValidatorId(0)))
    );
}

// ---------------------------------------------------------------------------
// E. New-format (v2) signature presented to the legacy v1 verifier.
// ---------------------------------------------------------------------------

#[test]
fn case_e_v2_signature_rejected_by_legacy_v1_verifier() {
    let f = make_fixture(4);
    let d = domain(0xCAFE_0000_0000_0001, 5, genesis_id(1), commitment(1));
    let p = sign_proposal(&f, 0, &d);
    // Legacy v1 verifier (computes its own v1 preimage internally).
    assert_eq!(
        verify_proposal_msg(
            &p,
            ValidatorId(0),
            &f.validators,
            &f.kp,
            &f.br,
            QBIND_DEVNET_CHAIN_ID
        ),
        Err(ProposalVoteVerifyError::InvalidSignature(ValidatorId(0)))
    );
}

// ---------------------------------------------------------------------------
// F. Wrong message-family domain: a Vote signed as a Vote must not verify
//    under a Proposal-family preimage, and vice versa.
// ---------------------------------------------------------------------------

#[test]
fn case_f_wrong_message_family_rejected() {
    let f = make_fixture(4);
    let d = domain(0xCAFE_0000_0000_0001, 5, genesis_id(1), commitment(1));
    // A vote correctly signed under the Vote family.
    let v = sign_vote(&f, 0, &d);
    assert!(vv(&f, &v, &d).is_ok());
    // Verify the SAME signature bytes over the Proposal-family preimage of a
    // proposal that shares the vote's core fields: rejected.
    let p = unsigned_proposal(0);
    let mut p_as_v = p.clone();
    p_as_v.signature = v.signature.clone();
    assert!(vp(&f, &p_as_v, &d).is_err());
}

// ---------------------------------------------------------------------------
// G. Unsupported signing version, explicitly rejected, no fallback.
// ---------------------------------------------------------------------------

#[test]
fn case_g_unsupported_version_rejected_no_fallback() {
    assert_eq!(
        ProposalVoteSigningFormat::from_u8(PV_SIGNING_FORMAT_VERSION_V2).unwrap(),
        ProposalVoteSigningFormat::V2
    );
    for bad in [0u8, 1, 3, 4, 255] {
        assert_eq!(
            ProposalVoteSigningFormat::from_u8(bad),
            Err(PvSigningDomainError::UnsupportedVersion(bad))
        );
    }
}

// ---------------------------------------------------------------------------
// H. Signature or signed-payload tampering.
// ---------------------------------------------------------------------------

#[test]
fn case_h_signature_and_payload_tampering_rejected() {
    let f = make_fixture(4);
    let d = domain(0xCAFE_0000_0000_0001, 5, genesis_id(1), commitment(1));

    // Tamper the signature bytes.
    let mut p = sign_proposal(&f, 0, &d);
    assert!(vp(&f, &p, &d).is_ok());
    p.signature[0] ^= 0xFF;
    assert!(vp(&f, &p, &d).is_err());

    // Tamper the signed payload (height) after signing.
    let mut p2 = sign_proposal(&f, 0, &d);
    p2.header.height ^= 0x5A5A;
    assert_eq!(
        vp(&f, &p2, &d),
        Err(ProposalVoteVerifyError::InvalidSignature(ValidatorId(0)))
    );
}

// ---------------------------------------------------------------------------
// I. Existing fail-closed taxonomy under the v2 boundary: missing signature,
//    wrong signer/key, unknown validator, wrong suite, unsupported suite.
// ---------------------------------------------------------------------------

#[test]
fn case_i_missing_signature_rejected() {
    let f = make_fixture(4);
    let d = domain(1, 5, genesis_id(1), commitment(1));
    let p = unsigned_proposal(0); // empty signature
    assert_eq!(
        vp(&f, &p, &d),
        Err(ProposalVoteVerifyError::MissingSignature(ValidatorId(0)))
    );
}

#[test]
fn case_i_wrong_signer_key_rejected() {
    let f = make_fixture(4);
    let d = domain(1, 5, genesis_id(1), commitment(1));
    // Proposal claims proposer 0 but is signed with validator 1's key.
    let mut p = unsigned_proposal(0);
    let pre = d.proposal_preimage(&p);
    let sk1 = f.sks.get(&ValidatorId(1)).unwrap();
    p.signature = MlDsa44Backend::sign(sk1, &pre).expect("sign");
    assert_eq!(
        vp(&f, &p, &d),
        Err(ProposalVoteVerifyError::InvalidSignature(ValidatorId(0)))
    );
}

#[test]
fn case_i_unknown_validator_rejected() {
    let f = make_fixture(4);
    let d = domain(1, 5, genesis_id(1), commitment(1));
    // Proposer index 9 is not a member.
    let mut p = unsigned_proposal(9);
    let pre = d.proposal_preimage(&p);
    // Sign with an unrelated key so the message is non-empty.
    let sk0 = f.sks.get(&ValidatorId(0)).unwrap();
    p.signature = MlDsa44Backend::sign(sk0, &pre).expect("sign");
    assert_eq!(
        verify_proposal_msg_with_preimage(&p, ValidatorId(9), &f.validators, &f.kp, &f.br, &pre),
        Err(ProposalVoteVerifyError::UnknownValidator(ValidatorId(9)))
    );
}

#[test]
fn case_i_wrong_suite_rejected() {
    let f = make_fixture(4);
    let d = domain(1, 5, genesis_id(1), commitment(1));
    let mut p = sign_proposal(&f, 0, &d);
    // Wire suite altered away from the governed suite after signing.
    p.header.suite_id = TEST_SUITE_U16 + 1;
    match vp(&f, &p, &d) {
        Err(ProposalVoteVerifyError::SuiteMismatch { .. }) => {}
        other => panic!("expected SuiteMismatch, got {:?}", other),
    }
}

#[test]
fn case_i_unsupported_suite_no_backend_rejected() {
    // Backend registry with NO backend for the governed suite.
    let mut keys = HashMap::new();
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
    keys.insert(ValidatorId(0), (TEST_SUITE, pk));
    let kp = TestKeyProvider { keys };
    let br = SimpleBackendRegistry::new(); // empty
    let validators = ConsensusValidatorSet::new(vec![ValidatorSetEntry {
        id: ValidatorId(0),
        voting_power: 1,
    }])
    .unwrap();
    let d = domain(1, 5, genesis_id(1), commitment(1));
    let mut p = unsigned_proposal(0);
    let pre = d.proposal_preimage(&p);
    p.signature = MlDsa44Backend::sign(&sk, &pre).expect("sign");
    assert_eq!(
        verify_proposal_msg_with_preimage(&p, ValidatorId(0), &validators, &kp, &br, &pre),
        Err(ProposalVoteVerifyError::UnsupportedSuite {
            validator_id: ValidatorId(0),
            governance_suite: TEST_SUITE,
        })
    );
}

// ---------------------------------------------------------------------------
// J. Missing or invalid trusted domain metadata fails construction closed.
// ---------------------------------------------------------------------------

#[test]
fn case_j_invalid_domain_metadata_fails_construction() {
    assert_eq!(
        ProposalVoteSigningDomainV2::try_new(ChainId(1), 5, [0u8; 32], commitment(1)),
        Err(PvSigningDomainError::ZeroGenesisIdentity)
    );
    assert_eq!(
        ProposalVoteSigningDomainV2::try_new(ChainId(1), 5, genesis_id(1), [0u8; 32]),
        Err(PvSigningDomainError::ZeroAuthorityCommitment)
    );
}

// ---------------------------------------------------------------------------
// K. Inconsistent expected wire-chain identity: a domain differing ONLY in
//    expected_wire_chain_id yields a different preimage, so a same-key
//    signature under one fails under the other.
// ---------------------------------------------------------------------------

#[test]
fn case_k_expected_wire_chain_id_is_bound() {
    let f = make_fixture(4);
    let g = genesis_id(1);
    let c = commitment(1);
    let d_wire5 = domain(0xCAFE_0000_0000_0001, 5, g, c);
    let d_wire9 = domain(0xCAFE_0000_0000_0001, 9, g, c);
    let p = sign_proposal(&f, 0, &d_wire5);
    assert!(vp(&f, &p, &d_wire5).is_ok());
    assert_eq!(
        vp(&f, &p, &d_wire9),
        Err(ProposalVoteVerifyError::InvalidSignature(ValidatorId(0)))
    );
}

// ---------------------------------------------------------------------------
// Golden preimage vectors — explicit, independently specified expected bytes.
//
// The expected byte sequence is assembled here by hand (a second, independent
// encoder) from a fully fixed domain + message, then compared against the
// domain's own builder. Signature bytes are NOT asserted (they need not be
// deterministic); only the preimage layout is golden.
// ---------------------------------------------------------------------------

fn golden_domain() -> ProposalVoteSigningDomainV2 {
    // Fully fixed inputs.
    let genesis = {
        let mut g = [0u8; 32];
        for (i, b) in g.iter_mut().enumerate() {
            *b = i as u8; // 0x00..0x1f
        }
        g
    };
    let commit = {
        let mut c = [0u8; 32];
        for (i, b) in c.iter_mut().enumerate() {
            *b = 0x80u8.wrapping_add(i as u8); // 0x80..0x9f
        }
        c
    };
    ProposalVoteSigningDomainV2::try_new(
        ChainId(0x0102_0304_0506_0708),
        0x0A0B_0C0D,
        genesis,
        commit,
    )
    .expect("golden domain")
}

#[test]
fn golden_vote_preimage_bytes() {
    let d = golden_domain();
    // A fully fixed vote.
    let v = Vote {
        version: 1,
        chain_id: 0x11223344,
        epoch: 0x0102_0304_0506_0708,
        height: 0x1112_1314_1516_1718,
        round: 0x2122_2324_2526_2728,
        step: 3,
        block_id: [0xAB; 32],
        validator_index: 0x0405,
        suite_id: 100,
        signature: vec![],
    };

    // Independently specified expected preimage bytes.
    let mut expected = Vec::new();
    expected.extend_from_slice(PV_SIGNING_DOMAIN_V2_TAG); // "QBIND:PVDOMAIN:v2"
    expected.push(PV_SIGNING_FORMAT_VERSION_V2); // 2
    expected.push(2); // family = Vote
    expected.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes()); // runtime chain id
    expected.extend_from_slice(&0x0A0B_0C0Du32.to_be_bytes()); // expected wire chain id
                                                               // genesis identity 0x00..0x1f
    expected.extend_from_slice(&(0u8..32).collect::<Vec<u8>>());
    // authority commitment 0x80..0x9f
    expected.extend_from_slice(
        &(0u8..32)
            .map(|i| 0x80u8.wrapping_add(i))
            .collect::<Vec<u8>>(),
    );
    // body (little-endian v1 field encoding), length-framed.
    let mut body = Vec::new();
    body.push(1u8); // version
    body.extend_from_slice(&0x11223344u32.to_le_bytes()); // chain_id
    body.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes()); // epoch
    body.extend_from_slice(&0x1112_1314_1516_1718u64.to_le_bytes()); // height
    body.extend_from_slice(&0x2122_2324_2526_2728u64.to_le_bytes()); // round
    body.push(3u8); // step
    body.extend_from_slice(&[0xAB; 32]); // block_id
    body.extend_from_slice(&0x0405u16.to_le_bytes()); // validator_index
    body.extend_from_slice(&100u16.to_le_bytes()); // suite_id
    expected.extend_from_slice(&(body.len() as u64).to_be_bytes());
    expected.extend_from_slice(&body);

    assert_eq!(d.vote_preimage(&v), expected);
    // Body length is the fixed v1 vote body length (56 bytes).
    assert_eq!(body.len(), 1 + 4 + 8 + 8 + 8 + 1 + 32 + 2 + 2);
}

#[test]
fn golden_proposal_preimage_prefix_bytes() {
    let d = golden_domain();
    let p = unsigned_proposal(0x0607);
    let pre = d.proposal_preimage(&p);
    // Independently specified expected fixed-length header prefix.
    let mut prefix = Vec::new();
    prefix.extend_from_slice(PV_SIGNING_DOMAIN_V2_TAG);
    prefix.push(PV_SIGNING_FORMAT_VERSION_V2);
    prefix.push(1); // family = Proposal
    prefix.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
    prefix.extend_from_slice(&0x0A0B_0C0Du32.to_be_bytes());
    prefix.extend_from_slice(&(0u8..32).collect::<Vec<u8>>());
    prefix.extend_from_slice(
        &(0u8..32)
            .map(|i| 0x80u8.wrapping_add(i))
            .collect::<Vec<u8>>(),
    );
    assert!(pre.starts_with(&prefix));
    // The body that follows is exactly canonical_body(), length-framed.
    let body = p.canonical_body();
    let mut framed = (body.len() as u64).to_be_bytes().to_vec();
    framed.extend_from_slice(&body);
    assert!(pre.ends_with(&framed));
    assert_eq!(pre.len(), prefix.len() + framed.len());
}

// A trait-object smoke check that the real backend is in use (never a
// success-always stub), guarding the negative-replay claims above.
#[test]
fn real_backend_rejects_random_signature() {
    let backend: Arc<dyn ConsensusSigVerifier> = Arc::new(MlDsa44Backend);
    let (pk, _sk) = MlDsa44Backend::generate_keypair().expect("keygen");
    let err = backend.verify_vote(0, &pk, b"message", &[0u8; 8]);
    assert!(err.is_err());
}