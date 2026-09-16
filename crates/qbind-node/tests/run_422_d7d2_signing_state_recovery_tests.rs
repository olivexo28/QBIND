//! RUN 422 D7-D2 — signing-state continuity characterization across restart
//! and snapshot restore.
//!
//! This is a **bounded characterization** of what the *existing* consensus
//! recovery entrypoints preserve, reconstruct, or lose after an uncommitted
//! signing decision. It adds no production behavior, no public getters, no new
//! persistence mechanism, and no authority activation. It exercises the real
//! recovery entrypoints and the real ML-DSA-44 backend only; a passing test
//! here confirms *missing* protection — it never establishes signing-state
//! continuity or any safety property.
//!
//! Selected test location (task §2): the three scenarios exercise only the
//! existing *public* recovery entrypoints
//! (`BasicHotStuffEngine::{initialize_from_restart, initialize_from_snapshot_baseline,
//! on_proposal_event}`, `NodeHotstuffHarness::load_persisted_state`,
//! `observe_consensus_storage`) together with the real D6 verifier
//! (`verify_vote_msg_with_domain`) and the real ML-DSA-44 backend. Because every
//! reused path is public, a single dedicated integration target (the one
//! sanctioned by the task) is sufficient and keeps the change isolated from the
//! large production consensus-loop module. The minimal validator/key fixture
//! below is built exclusively from public constructors and is explicitly test
//! fixture setup; it is not a production route.
//!
//! Scenario map (task §4):
//!   A. Ordinary restart after an uncommitted signing decision.
//!   B. Restore a snapshot captured before the decision.
//!   C. Existing committed-state recovery control (real reader
//!      `load_persisted_state` + `observe_consensus_storage`).
//!
//! Evidence-strength boundaries (task §5) are kept explicit. The engine's
//! `on_proposal_event` return is an *engine decision* (an unsigned
//! `BroadcastVote` action); *completed signature bytes* are produced separately
//! by the real signer and verified independently by the real D6 verifier. No
//! facade handoff or network transmission is exercised by these tests.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use qbind_consensus::crypto_verifier::SimpleBackendRegistry;
use qbind_consensus::driver::ConsensusEngineAction;
use qbind_consensus::key_registry::SuiteAwareValidatorKeyProvider;
use qbind_consensus::validator_set::{ConsensusValidatorSet, ValidatorSetEntry};
use qbind_consensus::{verify_vote_msg_with_domain, BasicHotStuffEngine, ValidatorId};
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::{ConsensusSigSuiteId, SUITE_PQ_RESERVED_1};
use qbind_types::ChainId;
use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate, Vote};
use qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2;

// ---------------------------------------------------------------------------
// Minimal signing fixture (public constructors only; test fixture setup).
// Mirrors the shape of the existing private `make_fixture`/`signed_vote`
// helpers in `binary_consensus_loop.rs` but uses only exported types so the
// characterization can live in a single dedicated integration target.
// ---------------------------------------------------------------------------

const TEST_SUITE: ConsensusSigSuiteId = SUITE_PQ_RESERVED_1; // 100 = ML-DSA-44
const TEST_SUITE_U16: u16 = 100;

#[derive(Debug, Clone)]
struct D7d2KeyProvider {
    keys: HashMap<ValidatorId, (ConsensusSigSuiteId, Vec<u8>)>,
}
impl SuiteAwareValidatorKeyProvider for D7d2KeyProvider {
    fn get_suite_and_key(&self, id: ValidatorId) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        self.keys.get(&id).cloned()
    }
}

struct SignFixture {
    validators: ConsensusValidatorSet,
    kp: D7d2KeyProvider,
    br: SimpleBackendRegistry,
    /// Real ML-DSA-44 secret keys, per validator. Test fixture material.
    sks: HashMap<ValidatorId, Vec<u8>>,
}

fn make_validators(n: u64) -> ConsensusValidatorSet {
    let entries: Vec<ValidatorSetEntry> = (0..n)
        .map(|i| ValidatorSetEntry {
            id: ValidatorId(i),
            voting_power: 1,
        })
        .collect();
    ConsensusValidatorSet::new(entries).expect("valid set")
}

fn make_fixture(n: u64) -> SignFixture {
    let mut keys: HashMap<ValidatorId, (ConsensusSigSuiteId, Vec<u8>)> = HashMap::new();
    let mut sks: HashMap<ValidatorId, Vec<u8>> = HashMap::new();
    for i in 0..n {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
        keys.insert(ValidatorId(i), (TEST_SUITE, pk));
        sks.insert(ValidatorId(i), sk);
    }
    SignFixture {
        validators: make_validators(n),
        kp: D7d2KeyProvider { keys },
        br: SimpleBackendRegistry::with_backend(TEST_SUITE, Arc::new(MlDsa44Backend)),
        sks,
    }
}

/// The control v2 signing domain. `expected_wire_chain_id = 0` matches the
/// `chain_id = 0` carried by the votes signed below.
fn control_domain() -> ProposalVoteSigningDomainV2 {
    ProposalVoteSigningDomainV2::try_new(
        ChainId(0xD7D2_0000_0000_0001),
        0,
        [0x7Du8; 32],
        [0xD2u8; 32],
    )
    .expect("valid d7d2 control domain")
}

fn base_vote(voter: u16, height: u64, block_id: [u8; 32]) -> Vote {
    Vote {
        version: 1,
        chain_id: 0,
        epoch: 0,
        height,
        round: height,
        step: 1,
        block_id,
        validator_index: voter,
        suite_id: TEST_SUITE_U16,
        signature: vec![],
    }
}

/// Produce a vote carrying **completed** ML-DSA-44 signature bytes over the
/// mandatory v2 control-domain preimage, using the existing real signer.
fn signed_vote(voter: u16, height: u64, block_id: [u8; 32], fixture: &SignFixture) -> Vote {
    let mut v = base_vote(voter, height, block_id);
    let preimage = control_domain().vote_preimage(&v);
    let sk = fixture
        .sks
        .get(&ValidatorId(voter as u64))
        .expect("signer key present");
    v.signature = MlDsa44Backend::sign(sk, &preimage).expect("sign");
    v
}

/// Independently verify a vote's completed signature via the real D6 verifier
/// and the real backend registry.
fn verify_completed_vote(v: &Vote, voter: u16, fixture: &SignFixture) -> bool {
    verify_vote_msg_with_domain(
        v,
        ValidatorId(voter as u64),
        &fixture.validators,
        &fixture.kp,
        &fixture.br,
        &control_domain(),
    )
    .is_ok()
}

fn make_engine(local: u64, n: u64) -> BasicHotStuffEngine<[u8; 32]> {
    BasicHotStuffEngine::new(ValidatorId(local), make_validators(n))
}

/// A leader proposal at `height` from `leader`, with the given opaque parent.
/// The engine derives its own block id from `(leader, height, parent)`, so two
/// proposals at the same height that differ only in `parent` produce distinct
/// block ids (i.e. conflicting candidates at the same voting position).
fn leader_proposal(leader: u16, height: u64, parent: [u8; 32]) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 0,
            epoch: 0,
            height,
            round: height,
            parent_block_id: parent,
            payload_hash: [9u8; 32],
            proposer_index: leader,
            suite_id: TEST_SUITE_U16,
            tx_count: 0,
            timestamp: 0,
            payload_kind: 0,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    }
}

/// Extract the engine's emitted vote decision (an unsigned `BroadcastVote`
/// action), if any.
fn emitted_vote(action: Option<ConsensusEngineAction<ValidatorId>>) -> Option<Vote> {
    match action {
        Some(ConsensusEngineAction::BroadcastVote(v)) => Some(v),
        _ => None,
    }
}

// ===========================================================================
// Scenario A — ordinary restart after an uncommitted signing decision.
// ===========================================================================
//
// Observed boundaries:
//   * engine decision/action: `on_proposal_event` returns `BroadcastVote`.
//   * completed signature bytes: `signed_vote` + `verify_completed_vote`.
//   * facade handoff / network transmission: NOT exercised.
#[test]
fn d7d2_a_uncommitted_vote_lost_and_latch_reset_permits_conflicting_vote_after_restart() {
    let fixture = make_fixture(4);

    // --- Pre-crash engine at view 1. ---
    let mut engine = make_engine(0, 4);
    // The proposal at height 1 advances the fresh engine (view 0 -> 1); the
    // leader for view 1 is deterministic.
    let leader = engine.leader_for_view(1);
    let leader_u16 = leader.0 as u16;

    // (1) ENGINE DECISION: deliver a valid leader proposal for block X.
    let p_x = leader_proposal(leader_u16, 1, [0xFFu8; 32]); // no-parent sentinel
    let vote_x = emitted_vote(engine.on_proposal_event(leader, &p_x))
        .expect("engine votes for the first valid proposal at view 1");
    assert_eq!(vote_x.height, 1, "the uncommitted decision is at view 1");
    let block_x = vote_x.block_id;

    // (2) SAME-PROCESS CONTROL: a conflicting leader proposal for block Y at the
    // SAME view is refused in-process by the engine's per-view vote latch. This
    // is the existing guard that prevents equivocation while the process lives.
    let p_y = leader_proposal(leader_u16, 1, [0x22u8; 32]);
    let control = engine.on_proposal_event(leader, &p_y);
    assert!(
        emitted_vote(control).is_none(),
        "in-process vote latch refuses a second (conflicting) vote at the same view"
    );

    // (3) COMPLETED SIGNATURE BYTES boundary (distinct from the unsigned engine
    // action): the existing signer produces real ML-DSA-44 bytes over the vote
    // position, and the real D6 verifier accepts them independently.
    let signed_x = signed_vote(leader_u16, 1, block_x, &fixture);
    assert!(!signed_x.signature.is_empty(), "completed signature bytes exist");
    assert!(
        verify_completed_vote(&signed_x, leader_u16, &fixture),
        "the real backend independently verifies the completed vote signature"
    );

    // --- Restart. A fresh engine is initialized from ONLY the committed
    // baseline the real writer persists. The uncommitted view-1 vote was never
    // committed and no writer persisted it, so it cannot be an input here. We
    // model "nothing above genesis was committed" (committed_height = 0, no
    // stored QC -> no reconstructed lock). ---
    let mut restarted = make_engine(0, 4);
    restarted.initialize_from_restart([0x00u8; 32], 0, None);

    // Committed-state recovery observed via public getters: the baseline is
    // restored, the resume view is committed_height + 1, and there is NO lock
    // (no QC was persisted for the committed baseline).
    assert_eq!(restarted.committed_height(), Some(0));
    assert_eq!(restarted.current_view(), 1);
    assert!(
        restarted.locked_qc().is_none(),
        "no locked QC is reconstructed when the writer persisted none"
    );

    // (4) After restart the per-view latch is reset (a fresh process carries no
    // record of the pre-crash vote). Delivering the conflicting proposal for
    // block Y at the SAME view 1 now succeeds: the engine emits a vote for Y.
    let leader2 = restarted.leader_for_view(1);
    assert_eq!(leader2, leader, "leader for view 1 is deterministic");
    let vote_y = emitted_vote(restarted.on_proposal_event(leader2, &p_y))
        .expect("after restart the reset latch permits voting again at view 1");
    let block_y = vote_y.block_id;

    // The two engine decisions are for DIFFERENT blocks at the SAME view: the
    // in-process guard that prevented this did not survive the restart because
    // the vote was uncommitted and unpersisted.
    assert_ne!(
        block_x, block_y,
        "conflicting block ids voted at the same view across the restart"
    );
    assert_eq!(vote_x.height, vote_y.height);

    // The signer likewise will produce completed, independently-verified
    // signatures for BOTH conflicting positions (same validator, domain, epoch
    // and voting position; different signed messages). This establishes the
    // fixture-level capability to produce conflicting signatures; the missing
    // protection is that no persisted anti-equivocation record is consumed by
    // any recovery entrypoint. The facade/network transmission boundary is not
    // exercised.
    let signed_y = signed_vote(leader_u16, 1, block_y, &fixture);
    assert!(verify_completed_vote(&signed_x, leader_u16, &fixture));
    assert!(verify_completed_vote(&signed_y, leader_u16, &fixture));
    assert_ne!(
        signed_x.signature, signed_y.signature,
        "the two completed signatures cover different messages"
    );
}

// ===========================================================================
// Scenario B — restore a snapshot captured before the decision.
// ===========================================================================
//
// Scope: this exercises the initializer-level snapshot baseline
// (`initialize_from_snapshot_baseline`, the binary B5 restore-aware start
// hook), NOT an end-to-end binary RocksDB restore. The artifact a
// `StateSnapshotMeta` carries today is only `(block_hash, height)`. A FRESH
// engine instance is used for the restore, as the startup contract requires;
// fields are not reset on the live engine.
#[test]
fn d7d2_b_snapshot_baseline_before_decision_omits_intervening_vote() {
    let fixture = make_fixture(4);

    // Snapshot captured BEFORE the decision: committed baseline at height 5.
    let snap_id = [0x01u8; 32];
    let snap_height = 5u64;

    // Live engine restored to the pre-decision baseline, then makes an
    // uncommitted signing decision at view 6.
    let mut engine = make_engine(0, 4);
    engine.initialize_from_snapshot_baseline(snap_id, snap_height);
    assert_eq!(engine.committed_height(), Some(snap_height));
    assert_eq!(engine.current_view(), snap_height + 1);

    let leader = engine.leader_for_view(snap_height + 1);
    let leader_u16 = leader.0 as u16;
    let p_x = leader_proposal(leader_u16, snap_height + 1, snap_id);
    let vote_x = emitted_vote(engine.on_proposal_event(leader, &p_x))
        .expect("engine votes at view 6 after the pre-decision snapshot baseline");
    let block_x = vote_x.block_id;
    // Real completed signature for the decision.
    let signed_x = signed_vote(leader_u16, snap_height + 1, block_x, &fixture);
    assert!(verify_completed_vote(&signed_x, leader_u16, &fixture));

    // Restore the EARLIER artifact on a FRESH engine/process-equivalent
    // instance through the existing restore path.
    let mut restored = make_engine(0, 4);
    restored.initialize_from_snapshot_baseline(snap_id, snap_height);

    // The artifact contains only (block id, height): the baseline is restored,
    // but there is no QC/lock and no record of the intervening vote.
    assert_eq!(restored.committed_height(), Some(snap_height));
    assert_eq!(restored.current_view(), snap_height + 1);
    assert!(
        restored.locked_qc().is_none(),
        "snapshot baseline carries no QC/lock history"
    );

    // A conflicting proposal for block Y at the SAME view 6 is admitted, because
    // the restore carries no record of the earlier decision.
    let p_y = leader_proposal(leader_u16, snap_height + 1, [0x33u8; 32]);
    let leader_r = restored.leader_for_view(snap_height + 1);
    let vote_y = emitted_vote(restored.on_proposal_event(leader_r, &p_y))
        .expect("restored-from-snapshot engine votes again at view 6");
    assert_ne!(
        block_x, vote_y.block_id,
        "snapshot restore does not carry the intervening signing decision"
    );

    // Epoch comparison kept explicit: both engines are at epoch 0. An UNCHANGED
    // epoch does NOT establish preservation of the intervening decision; the
    // decision is simply absent from the artifact.
    let signed_y = signed_vote(leader_u16, snap_height + 1, vote_y.block_id, &fixture);
    assert!(verify_completed_vote(&signed_y, leader_u16, &fixture));
    assert_ne!(signed_x.signature, signed_y.signature);
}

// ===========================================================================
// Scenario C — existing committed-state recovery control.
// ===========================================================================
//
// Exercises the REAL committed-state reader `NodeHotstuffHarness::load_persisted_state`
// (not a reproduction) and asserts the actual storage observation via
// `observe_consensus_storage`. This control recovers committed state ONLY; it
// establishes recovery of neither the latest uncommitted vote, nor the latest
// pre-crash lock, nor C3F retained evidence.
mod committed_state_recovery_control {
    use super::*;

    use qbind_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
    use qbind_net::{
        ClientConnectionConfig, ClientHandshakeConfig, KemPrivateKey, MutualAuthMode,
        ServerConnectionConfig, ServerHandshakeConfig,
    };
    use qbind_node::consensus_storage_observation::{
        observe_consensus_storage, ConsensusStorageObservation,
    };
    use qbind_node::hotstuff_node_sim::NodeHotstuffHarness;
    use qbind_node::storage::{ConsensusStorage, InMemoryConsensusStorage};
    use qbind_node::validator_config::{make_test_local_validator_config, NodeValidatorConfig};
    use qbind_wire::io::WireEncode;
    use qbind_wire::net::NetworkDelegationCert;

    // ---- Minimal handshake test setup (copied pattern from
    // persistence_integration_tests.rs; test fixture material only). ----

    struct DummyKem {
        suite_id: u8,
    }
    impl KemSuite for DummyKem {
        fn suite_id(&self) -> u8 {
            self.suite_id
        }
        fn public_key_len(&self) -> usize {
            32
        }
        fn secret_key_len(&self) -> usize {
            32
        }
        fn ciphertext_len(&self) -> usize {
            48
        }
        fn shared_secret_len(&self) -> usize {
            48
        }
        fn encaps(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
            let mut ct = pk.to_vec();
            ct.extend_from_slice(b"ct-padding-bytes");
            ct.truncate(self.ciphertext_len());
            while ct.len() < self.ciphertext_len() {
                ct.push(0);
            }
            let mut ss = pk.to_vec();
            ss.extend_from_slice(b"ss-padding-bytes");
            ss.truncate(self.shared_secret_len());
            while ss.len() < self.shared_secret_len() {
                ss.push(0);
            }
            Ok((ct, ss))
        }
        fn decaps(&self, _sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
            let pk = &ct[..self.public_key_len().min(ct.len())];
            let mut ss = pk.to_vec();
            ss.extend_from_slice(b"ss-padding-bytes");
            ss.truncate(self.shared_secret_len());
            while ss.len() < self.shared_secret_len() {
                ss.push(0);
            }
            Ok(ss)
        }
    }

    struct DummySig {
        suite_id: u8,
    }
    impl SignatureSuite for DummySig {
        fn suite_id(&self) -> u8 {
            self.suite_id
        }
        fn public_key_len(&self) -> usize {
            32
        }
        fn signature_len(&self) -> usize {
            64
        }
        fn verify(&self, _pk: &[u8], _msg_digest: &[u8; 32], _sig: &[u8]) -> Result<(), CryptoError> {
            Ok(())
        }
    }

    struct DummyAead {
        suite_id: u8,
    }
    impl AeadSuite for DummyAead {
        fn suite_id(&self) -> u8 {
            self.suite_id
        }
        fn key_len(&self) -> usize {
            32
        }
        fn nonce_len(&self) -> usize {
            12
        }
        fn tag_len(&self) -> usize {
            1
        }
        fn seal(
            &self,
            key: &[u8],
            _nonce: &[u8],
            _aad: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, CryptoError> {
            let xor_byte = key.first().copied().unwrap_or(0);
            let mut ciphertext: Vec<u8> = plaintext.iter().map(|b| b ^ xor_byte).collect();
            let tag = ciphertext.iter().fold(0u8, |acc, &b| acc ^ b);
            ciphertext.push(tag);
            Ok(ciphertext)
        }
        fn open(
            &self,
            key: &[u8],
            _nonce: &[u8],
            _aad: &[u8],
            ciphertext_and_tag: &[u8],
        ) -> Result<Vec<u8>, CryptoError> {
            if ciphertext_and_tag.is_empty() {
                return Err(CryptoError::InvalidCiphertext);
            }
            let (ciphertext, tag_slice) =
                ciphertext_and_tag.split_at(ciphertext_and_tag.len() - 1);
            let expected_tag = ciphertext.iter().fold(0u8, |acc, &b| acc ^ b);
            if tag_slice[0] != expected_tag {
                return Err(CryptoError::InvalidCiphertext);
            }
            let xor_byte = key.first().copied().unwrap_or(0);
            let plaintext: Vec<u8> = ciphertext.iter().map(|b| b ^ xor_byte).collect();
            Ok(plaintext)
        }
    }

    fn make_test_provider() -> StaticCryptoProvider {
        StaticCryptoProvider::new()
            .with_kem_suite(Arc::new(DummyKem { suite_id: 1 }))
            .with_aead_suite(Arc::new(DummyAead { suite_id: 2 }))
            .with_signature_suite(Arc::new(DummySig { suite_id: 3 }))
    }

    struct TestSetup {
        client_cfg: ClientConnectionConfig,
        server_cfg: ServerConnectionConfig,
    }

    fn create_test_setup() -> TestSetup {
        let kem_suite_id: u8 = 1;
        let aead_suite_id: u8 = 2;
        let sig_suite_id: u8 = 3;
        let provider = Arc::new(make_test_provider());

        let mut validator_id = [0u8; 32];
        validator_id[0..6].copy_from_slice(b"val-42");
        let mut root_key_id = [0u8; 32];
        root_key_id[0..8].copy_from_slice(b"root-key");

        let server_kem_pk: Vec<u8> = (0..32).collect();
        let server_kem_sk: Vec<u8> = (0..32).map(|x| x ^ 0xFF).collect();

        let cert = NetworkDelegationCert {
            version: 1,
            validator_id,
            root_key_id,
            leaf_kem_suite_id: kem_suite_id,
            leaf_kem_pk: server_kem_pk.clone(),
            not_before: 0,
            not_after: u64::MAX,
            ext_bytes: Vec::new(),
            sig_suite_id,
            sig_bytes: vec![0u8; 64],
        };
        let mut cert_bytes = Vec::new();
        cert.encode(&mut cert_bytes);

        let root_network_pk: Vec<u8> = vec![0u8; 32];
        let mut client_random = [0u8; 32];
        client_random[0..6].copy_from_slice(b"client");
        let mut server_random = [0u8; 32];
        server_random[0..6].copy_from_slice(b"server");

        let client_handshake_cfg = ClientHandshakeConfig {
            kem_suite_id,
            aead_suite_id,
            crypto: provider.clone(),
            peer_root_network_pk: root_network_pk.clone(),
            kem_metrics: None,
            local_delegation_cert: None,
            cert_verify_metrics: None,
            leaf_cert_revocations: None,
        };
        let server_handshake_cfg = ServerHandshakeConfig {
            kem_suite_id,
            aead_suite_id,
            crypto: provider.clone(),
            local_root_network_pk: root_network_pk,
            local_delegation_cert: cert_bytes,
            local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
            kem_metrics: None,
            cookie_config: None,
            local_validator_id: validator_id,
            mutual_auth_mode: MutualAuthMode::Disabled,
            trusted_client_roots: None,
            cert_verify_metrics: None,
            leaf_cert_revocations: None,
        };
        let client_cfg = ClientConnectionConfig {
            handshake_config: client_handshake_cfg,
            client_random,
            validator_id,
            peer_kem_pk: server_kem_pk,
        };
        let server_cfg = ServerConnectionConfig {
            handshake_config: server_handshake_cfg,
            server_random,
        };
        TestSetup {
            client_cfg,
            server_cfg,
        }
    }

    fn node_cfg() -> NodeValidatorConfig {
        NodeValidatorConfig {
            local: make_test_local_validator_config(
                ValidatorId::new(1),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                vec![],
            ),
            remotes: vec![],
        }
    }

    /// A committed block proposal at `height`, and a matching wire QC recorded
    /// for it (as the on-disk writer would). Returns `(block_id, block, qc)`.
    fn committed_block_and_qc(height: u64) -> ([u8; 32], BlockProposal, QuorumCertificate) {
        let block_id = [0x77u8; 32];
        let block = leader_proposal(1, height, [0x00u8; 32]);
        let qc = QuorumCertificate {
            version: 1,
            chain_id: 0,
            epoch: 0,
            height,
            round: height,
            step: 1,
            block_id,
            suite_id: TEST_SUITE_U16,
            signer_bitmap: vec![0x0F],
            signatures: vec![],
        };
        (block_id, block, qc)
    }

    /// C1: committed block present, but NO `meta:current_epoch` seeded. The
    /// storage observation must be `PresentNoCommittedEpoch` (a committed block
    /// does not imply a committed-epoch key), and the real reader reconstructs
    /// the committed baseline and a lock from the stored QC.
    #[test]
    fn d7d2_c_load_persisted_state_recovers_committed_baseline_present_no_committed_epoch() {
        let setup = create_test_setup();
        let storage = Arc::new(InMemoryConsensusStorage::new());

        let committed_height = 7u64;
        let (block_id, block, qc) = committed_block_and_qc(committed_height);
        storage.put_block(&block_id, &block).expect("put_block");
        storage.put_qc(&block_id, &qc).expect("put_qc");
        storage
            .put_last_committed(&block_id)
            .expect("put_last_committed");
        // No put_current_epoch: a committed block does not seed meta:current_epoch.

        // Actual storage observation (asserted, not assumed).
        let obs = observe_consensus_storage(Some(storage.as_ref())).expect("observe");
        assert_eq!(obs, ConsensusStorageObservation::PresentNoCommittedEpoch);

        // Exercise the REAL reader.
        let cfg = node_cfg();
        let mut harness = NodeHotstuffHarness::new_from_validator_config(
            &cfg,
            setup.client_cfg,
            setup.server_cfg,
            None,
        )
        .expect("create harness")
        .with_storage(storage.clone() as Arc<dyn ConsensusStorage>);

        let loaded = harness.load_persisted_state().expect("load_persisted_state");
        assert_eq!(
            loaded,
            Some(block_id),
            "the committed block id is recovered from storage"
        );

        // Committed baseline + resume view.
        assert_eq!(harness.driver().engine().committed_height(), Some(committed_height));
        assert_eq!(harness.current_view(), committed_height + 1);

        // Reconstructed lock: the stored QC (height 7) becomes the locked QC
        // (view 7). This is a lock reconstructed from the committed/stored QC —
        // NOT the latest pre-crash lock.
        let locked = harness.driver().engine().locked_qc();
        assert!(locked.is_some(), "a lock is reconstructed from the stored QC");
        assert_eq!(locked.unwrap().view, committed_height);

        // Boundary statement: this control recovers committed state only. It
        // does NOT recover the latest uncommitted vote, the latest pre-crash
        // lock, or C3F retained verified-justification evidence.
    }

    /// C2: same committed baseline, but with `put_current_epoch(0)` seeded
    /// (explicit fixture setup). The observation is now `CommittedEpoch(0)`,
    /// distinct from `PresentNoCommittedEpoch`. Epoch 0 takes no epoch-restore
    /// branch, and the committed baseline is still recovered.
    #[test]
    fn d7d2_c_committed_epoch_zero_observed_distinctly_as_fixture_setup() {
        let setup = create_test_setup();
        let storage = Arc::new(InMemoryConsensusStorage::new());

        let committed_height = 7u64;
        let (block_id, block, qc) = committed_block_and_qc(committed_height);
        storage.put_block(&block_id, &block).expect("put_block");
        storage.put_qc(&block_id, &qc).expect("put_qc");
        storage
            .put_last_committed(&block_id)
            .expect("put_last_committed");
        // Explicit fixture setup: seed committed epoch 0.
        storage.put_current_epoch(0).expect("put_current_epoch");

        let obs = observe_consensus_storage(Some(storage.as_ref())).expect("observe");
        assert_eq!(obs, ConsensusStorageObservation::CommittedEpoch(0));
        // Distinct from the absent-epoch observation.
        assert_ne!(obs, ConsensusStorageObservation::PresentNoCommittedEpoch);

        let cfg = node_cfg();
        let mut harness = NodeHotstuffHarness::new_from_validator_config(
            &cfg,
            setup.client_cfg,
            setup.server_cfg,
            None,
        )
        .expect("create harness")
        .with_storage(storage.clone() as Arc<dyn ConsensusStorage>);

        let loaded = harness.load_persisted_state().expect("load_persisted_state");
        assert_eq!(loaded, Some(block_id));
        assert_eq!(harness.driver().engine().committed_height(), Some(committed_height));
        assert_eq!(harness.current_view(), committed_height + 1);
    }

    /// Fresh-node control: no persisted state -> the reader returns None and no
    /// baseline is recovered. Establishes that the recovered content above is
    /// genuinely storage-derived.
    #[test]
    fn d7d2_c_fresh_node_recovers_nothing() {
        let setup = create_test_setup();
        let storage = Arc::new(InMemoryConsensusStorage::new());

        let obs = observe_consensus_storage(Some(storage.as_ref())).expect("observe");
        assert_eq!(obs, ConsensusStorageObservation::PresentNoCommittedEpoch);

        let cfg = node_cfg();
        let mut harness = NodeHotstuffHarness::new_from_validator_config(
            &cfg,
            setup.client_cfg,
            setup.server_cfg,
            None,
        )
        .expect("create harness")
        .with_storage(storage.clone() as Arc<dyn ConsensusStorage>);

        let loaded = harness.load_persisted_state().expect("load_persisted_state");
        assert_eq!(loaded, None, "a fresh node recovers no committed baseline");
        assert_eq!(harness.committed_height(), None);
    }
}