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
//! `BroadcastVote` action); *completed signature bytes* are produced by a
//! test-local adapter (`complete_signature_over_emitted_vote`) that consumes
//! that ACTUAL emitted `Vote`, applies the documented suite selection, and
//! signs it with the local validator's real key — mirroring the production
//! `sign_vote_for_broadcast` preparation — and are verified independently by
//! the real D6 verifier. No facade handoff or network transmission is exercised
//! by these tests.

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
// Mirrors the shape of the existing private `make_fixture` helper in
// `binary_consensus_loop.rs` but uses only exported types so the
// characterization can live in a single dedicated integration target. The
// completed signature is produced by `complete_signature_over_emitted_vote`
// below, which adapts the engine's ACTUAL emitted `Vote` rather than
// reconstructing a separate one.
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

/// The explicitly-declared fixture signing domain (task §2). Its
/// `expected_wire_chain_id = 1` matches the wire `chain_id = 1` the engine
/// stamps on every emitted `Vote` (see `BasicHotStuffEngine::ingest_proposal`,
/// `crates/qbind-consensus/src/basic_hotstuff_engine.rs`). This is trusted
/// fixture configuration; it is **not** derived from any incoming message and
/// activates no production runtime→wire mapping.
fn fixture_domain() -> ProposalVoteSigningDomainV2 {
    ProposalVoteSigningDomainV2::try_new(
        ChainId(0xD7D2_0000_0000_0001),
        1, // matches the preserved emitted wire chain_id (see engine).
        [0x7Du8; 32],
        [0xD2u8; 32],
    )
    .expect("valid d7d2 fixture domain")
}

/// Test-local signing adapter over the engine's **actual** emitted `Vote`
/// (task §2). It deliberately mirrors the production outbound signing
/// preparation `sign_vote_for_broadcast` in
/// `crates/qbind-node/src/binary_consensus_loop.rs`:
///
/// 1. Documented suite selection — overwrite **only** the placeholder
///    `suite_id` the engine emits (`DEFAULT_CONSENSUS_SUITE_ID = 0`) with the
///    signer's configured real suite (`signer.suite_id()` in production; the
///    ML-DSA-44 `TEST_SUITE_U16` here). This is distinct from changing the
///    voting identity or position.
/// 2. Compute the mandatory v2 preimage over the emitted domain.
/// 3. Assign **completed** signature bytes produced by the **local** validator's
///    real ML-DSA-44 key (the emitted `validator_index`), never the
///    proposer/leader's key.
///
/// It preserves the emitted version, validator index, wire chain, epoch,
/// height, round, step and block id; it reconstructs no separate `Vote` from
/// selected fields.
fn complete_signature_over_emitted_vote(
    emitted: &Vote,
    domain: &ProposalVoteSigningDomainV2,
    fixture: &SignFixture,
) -> Vote {
    let signer = ValidatorId(emitted.validator_index as u64);
    let sk = fixture
        .sks
        .get(&signer)
        .expect("local validator signing key present");
    let mut completed = emitted.clone();
    // (1) Documented suite selection over the emitted Vote.
    completed.suite_id = TEST_SUITE_U16;
    // (2)+(3) Real v2 preimage + completed signature bytes from the local key.
    let preimage = domain.vote_preimage(&completed);
    completed.signature = MlDsa44Backend::sign(sk, &preimage).expect("sign");
    completed
}

/// Assert the completed signature changed **only** the documented suite
/// selection and the newly-assigned signature bytes; every other emitted field
/// (voting identity, wire chain, epoch, height, round, step, block id) is
/// preserved unchanged (task §2).
fn assert_only_suite_and_signature_changed(emitted: &Vote, completed: &Vote) {
    assert_eq!(completed.version, emitted.version, "version preserved");
    assert_eq!(completed.chain_id, emitted.chain_id, "wire chain preserved");
    assert_eq!(completed.epoch, emitted.epoch, "epoch preserved");
    assert_eq!(completed.height, emitted.height, "height preserved");
    assert_eq!(completed.round, emitted.round, "round preserved");
    assert_eq!(completed.step, emitted.step, "step preserved");
    assert_eq!(completed.block_id, emitted.block_id, "block id preserved");
    assert_eq!(
        completed.validator_index, emitted.validator_index,
        "voting identity preserved"
    );
    assert_eq!(
        emitted.suite_id,
        qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        "the engine emits the placeholder suite"
    );
    assert_eq!(
        completed.suite_id, TEST_SUITE_U16,
        "the configured real signing suite is selected"
    );
    assert!(emitted.signature.is_empty(), "engine decision is unsigned");
    assert!(
        !completed.signature.is_empty(),
        "completed signature bytes are assigned"
    );
}

/// Independently verify a completed vote via the existing D6 message-bound
/// verifier and the real backend registry. `claimed` is taken from the vote's
/// own `validator_index` (the engine's local validator).
fn verify_completed_vote(
    v: &Vote,
    domain: &ProposalVoteSigningDomainV2,
    fixture: &SignFixture,
) -> bool {
    verify_vote_msg_with_domain(
        v,
        ValidatorId(v.validator_index as u64),
        &fixture.validators,
        &fixture.kp,
        &fixture.br,
        domain,
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
// Both the pre-decision engine and the restarted engine are initialized from
// the SAME explicit baseline inputs (task §3): committed block id, committed
// height, an explicitly-absent lock/QC, the local validator + membership, and
// epoch/view. Baseline state is asserted BEFORE and AFTER initialization, not
// merely the resulting view.
//
// Observed boundaries:
//   * engine decision/action: `on_proposal_event` returns `BroadcastVote`.
//   * fixture signer invocation + completed signature bytes:
//     `complete_signature_over_emitted_vote` + `verify_completed_vote`.
//   * facade handoff / network transmission: NOT exercised. This correction
//     does not exercise or establish production authorization or transmission.
#[test]
fn d7d2_a_uncommitted_vote_lost_and_latch_reset_permits_conflicting_vote_after_restart() {
    let fixture = make_fixture(4);
    let domain = fixture_domain();

    // Explicit shared baseline inputs, reused for BOTH engines below.
    let baseline_committed_id = [0x00u8; 32];
    let baseline_committed_height = 0u64;
    // Explicitly-absent lock/QC is part of THIS fixture's baseline.

    // --- Pre-decision engine, initialized from the shared baseline. ---
    let mut engine = make_engine(0, 4);
    assert_eq!(
        engine.committed_height(),
        None,
        "baseline BEFORE init: fresh engine has no committed baseline"
    );
    engine.initialize_from_restart(baseline_committed_id, baseline_committed_height, None);
    // Baseline AFTER init (asserted state, not merely the view).
    assert_eq!(engine.committed_height(), Some(0));
    assert_eq!(engine.current_view(), 1);
    assert!(
        engine.locked_qc().is_none(),
        "explicitly-absent lock/QC baseline"
    );
    assert_eq!(engine.current_epoch(), 0, "baseline epoch is explicitly 0");

    let leader = engine.leader_for_view(1);
    let leader_u16 = leader.0 as u16;

    // (1) ENGINE DECISION: the engine emits its OWN `BroadcastVote` for block X.
    let p_x = leader_proposal(leader_u16, 1, [0xFFu8; 32]); // no-parent sentinel
    let emitted_x = emitted_vote(engine.on_proposal_event(leader, &p_x))
        .expect("engine votes for the first valid proposal at view 1");
    assert_eq!(emitted_x.height, 1, "the uncommitted decision is at view 1");
    assert_eq!(
        emitted_x.validator_index, 0,
        "the emitted decision is the LOCAL validator's vote, not the leader's"
    );
    let block_x = emitted_x.block_id;

    // (2) SAME-PROCESS CONTROL: a conflicting leader proposal for block Y at the
    // SAME view is refused in-process by the engine's per-view vote latch.
    let p_y = leader_proposal(leader_u16, 1, [0x22u8; 32]);
    assert!(
        emitted_vote(engine.on_proposal_event(leader, &p_y)).is_none(),
        "in-process vote latch refuses a second (conflicting) vote at the same view"
    );

    // (3) FIXTURE SIGNER INVOCATION + COMPLETED SIGNATURE over the ACTUAL
    // emitted decision (distinct from the unsigned engine action). All other
    // emitted fields are preserved; the real D6 verifier accepts it.
    let signed_x = complete_signature_over_emitted_vote(&emitted_x, &domain, &fixture);
    assert_only_suite_and_signature_changed(&emitted_x, &signed_x);
    assert!(
        verify_completed_vote(&signed_x, &domain, &fixture),
        "the real backend independently verifies the completed vote over the engine's decision"
    );

    // --- Restart: a FRESH engine initialized from the SAME explicit baseline.
    // The uncommitted view-1 vote was never committed and no writer persisted
    // it, so it cannot be an input here. ---
    let mut restarted = make_engine(0, 4);
    assert_eq!(
        restarted.committed_height(),
        None,
        "baseline BEFORE init: fresh restart engine"
    );
    restarted.initialize_from_restart(baseline_committed_id, baseline_committed_height, None);
    assert_eq!(restarted.committed_height(), Some(0));
    assert_eq!(restarted.current_view(), 1);
    assert!(
        restarted.locked_qc().is_none(),
        "no locked QC is reconstructed from an absent baseline QC"
    );
    assert_eq!(restarted.current_epoch(), 0);

    // (4) After restart the per-view latch is reset (a fresh process carries no
    // record of the pre-crash vote). Delivering the conflicting proposal for
    // block Y at the SAME view 1 now yields a decision.
    let leader2 = restarted.leader_for_view(1);
    assert_eq!(leader2, leader, "leader for view 1 is deterministic");
    let emitted_y = emitted_vote(restarted.on_proposal_event(leader2, &p_y))
        .expect("after restart the reset latch permits voting again at view 1");
    let block_y = emitted_y.block_id;
    assert_eq!(emitted_y.validator_index, 0, "still the LOCAL validator's vote");

    // The two engine decisions are for DIFFERENT blocks at the SAME voting
    // position: the in-process guard did not survive the restart because the
    // vote was uncommitted and unpersisted. Same key/domain/epoch/position.
    assert_ne!(
        block_x, block_y,
        "conflicting block ids voted at the same view across the restart"
    );
    assert_eq!(emitted_x.height, emitted_y.height, "same voting height");
    assert_eq!(emitted_x.round, emitted_y.round, "same round");
    assert_eq!(emitted_x.step, emitted_y.step, "same step");
    assert_eq!(emitted_x.epoch, emitted_y.epoch, "same epoch");
    assert_eq!(emitted_x.chain_id, emitted_y.chain_id, "same wire chain");
    assert_eq!(
        emitted_x.validator_index, emitted_y.validator_index,
        "same voting identity"
    );

    // Completed signature over the SECOND emitted decision. Both signatures use
    // the SAME key/domain/epoch/voting position but cover DIFFERENT signed
    // message bodies (different block ids). Both pass D6 verification. The
    // facade/network transmission boundary is not exercised.
    let signed_y = complete_signature_over_emitted_vote(&emitted_y, &domain, &fixture);
    assert_only_suite_and_signature_changed(&emitted_y, &signed_y);
    assert!(verify_completed_vote(&signed_x, &domain, &fixture));
    assert!(verify_completed_vote(&signed_y, &domain, &fixture));
    // The signed message BODIES differ — different signature bytes alone would
    // not establish conflicting messages.
    assert_ne!(
        domain.vote_preimage(&signed_x),
        domain.vote_preimage(&signed_y),
        "the two completed signatures cover DIFFERENT signed messages"
    );
    assert_ne!(signed_x.signature, signed_y.signature);
}

// ===========================================================================
// Scenario B — replay the same pre-decision snapshot baseline inputs.
// ===========================================================================
//
// Scope (task §4): this test replays the SAME declared pre-decision
// initializer inputs into a fresh engine and exercises
// `initialize_from_snapshot_baseline` ONLY. It does NOT exercise snapshot
// creation, serialization, filesystem restoration, RocksDB recovery, or the
// full binary startup path.
//
// `StateSnapshotMeta` (crates/qbind-ledger/src/state_snapshot.rs) actually
// carries a COMPLETE metadata structure: `height`, `block_hash`,
// `created_at_unix_ms`, `chain_id`, `epoch: Option<u64>`,
// `authority_state: Option<..>` and `authority_state_v2: Option<..>`. The
// engine initializer `initialize_from_snapshot_baseline` consumes ONLY TWO of
// these — `block_hash` (reused as an opaque parent id) and `height`. The
// epoch/chain/authority metadata is NOT recovered by this initializer and is
// NOT recovered Proposal/Vote signing history or current authorization.
//
// A FRESH engine instance is used for the replay, as the startup contract
// requires; fields are not reset on the live engine.
#[test]
fn d7d2_b_snapshot_baseline_before_decision_omits_intervening_vote() {
    let fixture = make_fixture(4);
    let domain = fixture_domain();

    // Declared pre-decision initializer inputs (the two `StateSnapshotMeta`
    // fields this initializer consumes).
    let snap_id = [0x01u8; 32];
    let snap_height = 5u64;

    // Live engine restored to the pre-decision baseline, then makes an
    // uncommitted signing decision at view 6.
    let mut engine = make_engine(0, 4);
    assert_eq!(
        engine.committed_height(),
        None,
        "baseline BEFORE init: fresh engine"
    );
    engine.initialize_from_snapshot_baseline(snap_id, snap_height);
    assert_eq!(engine.committed_height(), Some(snap_height));
    assert_eq!(engine.current_view(), snap_height + 1);
    assert!(
        engine.locked_qc().is_none(),
        "snapshot baseline carries no QC/lock"
    );
    assert_eq!(engine.current_epoch(), 0, "baseline epoch is explicitly 0");

    let leader = engine.leader_for_view(snap_height + 1);
    let leader_u16 = leader.0 as u16;
    let p_x = leader_proposal(leader_u16, snap_height + 1, snap_id);
    let emitted_x = emitted_vote(engine.on_proposal_event(leader, &p_x))
        .expect("engine votes at view 6 after the pre-decision snapshot baseline");
    assert_eq!(emitted_x.validator_index, 0, "the LOCAL validator's vote");
    let block_x = emitted_x.block_id;

    // SAME-PROCESS CONTROL (task §3): a conflicting proposal for block Y at the
    // SAME view 6 is refused in-process by the per-view vote latch.
    let p_y = leader_proposal(leader_u16, snap_height + 1, [0x33u8; 32]);
    assert!(
        emitted_vote(engine.on_proposal_event(leader, &p_y)).is_none(),
        "in-process vote latch refuses a second (conflicting) vote at the same view"
    );

    // Completed signature over the ACTUAL emitted decision.
    let signed_x = complete_signature_over_emitted_vote(&emitted_x, &domain, &fixture);
    assert_only_suite_and_signature_changed(&emitted_x, &signed_x);
    assert!(verify_completed_vote(&signed_x, &domain, &fixture));

    // Replay the SAME declared inputs into a FRESH engine/process-equivalent
    // instance through the same initializer.
    let mut restored = make_engine(0, 4);
    assert_eq!(
        restored.committed_height(),
        None,
        "baseline BEFORE init: fresh replay engine"
    );
    restored.initialize_from_snapshot_baseline(snap_id, snap_height);

    // The initializer restores only (block id, height): the baseline is
    // restored, but there is no QC/lock and no record of the intervening vote.
    assert_eq!(restored.committed_height(), Some(snap_height));
    assert_eq!(restored.current_view(), snap_height + 1);
    assert!(
        restored.locked_qc().is_none(),
        "snapshot baseline carries no QC/lock history"
    );
    assert_eq!(restored.current_epoch(), 0, "replayed baseline epoch is explicitly 0");

    // A conflicting proposal for block Y at the SAME view 6 is admitted, because
    // the replay carries no record of the earlier decision.
    let leader_r = restored.leader_for_view(snap_height + 1);
    let emitted_y = emitted_vote(restored.on_proposal_event(leader_r, &p_y))
        .expect("engine re-initialized from the same baseline votes again at view 6");
    assert_ne!(
        block_x, emitted_y.block_id,
        "the baseline replay does not carry the intervening signing decision"
    );

    // Epoch comparison kept explicit for BOTH engines: an UNCHANGED epoch does
    // NOT establish preservation of the intervening decision; the decision is
    // simply absent from the replayed baseline.
    assert_eq!(engine.current_epoch(), 0);
    assert_eq!(restored.current_epoch(), 0);

    let signed_y = complete_signature_over_emitted_vote(&emitted_y, &domain, &fixture);
    assert_only_suite_and_signature_changed(&emitted_y, &signed_y);
    assert!(verify_completed_vote(&signed_y, &domain, &fixture));
    assert_ne!(
        domain.vote_preimage(&signed_x),
        domain.vote_preimage(&signed_y),
        "the two completed signatures cover DIFFERENT signed messages"
    );
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
    ///
    /// The QC is an **unverified storage/reconstruction fixture**: it carries an
    /// empty `signatures` vector (no constituent signatures). Its successful
    /// loading by the reader establishes reader/reconstruction behavior only —
    /// NOT authenticated quorum evidence or recovery safety.
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
            signatures: vec![], // unverified fixture: no constituent signatures.
        };
        (block_id, block, qc)
    }

    /// C1: committed block present, but NO `meta:current_epoch` seeded. The
    /// storage observation must be `PresentNoCommittedEpoch` (a committed block
    /// does not imply a committed-epoch key). The real reader reconstructs the
    /// committed baseline and a lock from the stored/embedded QC — this is a
    /// lock reconstructed from the committed/stored QC, NOT recovery of the
    /// exact latest pre-crash lock.
    ///
    /// Correction D: the C1 observation is asserted BEFORE and AFTER the harness
    /// read; the harness reader's own missing-epoch fallback (which defaults to
    /// 0) is recorded SEPARATELY from C1's explicit-absence observation.
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

        // Actual storage observation BEFORE the harness read (asserted).
        let obs_before = observe_consensus_storage(Some(storage.as_ref())).expect("observe");
        assert_eq!(obs_before, ConsensusStorageObservation::PresentNoCommittedEpoch);

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
        // (view 7). This is a lock reconstructed from the committed/stored QC
        // (an unverified fixture, no constituent signatures) — NOT the exact
        // latest pre-crash lock.
        let locked = harness.driver().engine().locked_qc();
        assert!(locked.is_some(), "a lock is reconstructed from the stored QC");
        assert_eq!(locked.unwrap().view, committed_height);

        // Correction D — the C1 observation is re-checked AFTER the reader ran.
        // The harness reader is read-only w.r.t. the committed-epoch key: no
        // epoch record was written, so C1 still reports the explicit absence.
        let obs_after = observe_consensus_storage(Some(storage.as_ref())).expect("observe after");
        assert_eq!(
            obs_after,
            ConsensusStorageObservation::PresentNoCommittedEpoch,
            "C1 still observes no committed epoch after the harness read"
        );

        // Recorded SEPARATELY: the harness/async-runner reader's OWN epoch
        // fallback (`storage.get_current_epoch()?.unwrap_or(0)` in
        // `hotstuff_node_sim.rs`) defaults the MISSING epoch to 0 in the
        // resulting engine. This is that reader's behavior only — it is NOT
        // C1's explicit-absence observation, and it does NOT imply the entire
        // recovery path never defaults a missing epoch to zero.
        assert_eq!(
            harness.driver().engine().current_epoch(),
            0,
            "the harness reader defaults the missing epoch to 0 in the engine"
        );

        // Boundary statement: this control recovers committed state only. It
        // does NOT recover the latest uncommitted vote, the exact latest
        // pre-crash lock, or C3F retained verified-justification evidence.
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

        let obs_before = observe_consensus_storage(Some(storage.as_ref())).expect("observe");
        assert_eq!(obs_before, ConsensusStorageObservation::CommittedEpoch(0));
        // Distinct from the absent-epoch observation.
        assert_ne!(obs_before, ConsensusStorageObservation::PresentNoCommittedEpoch);

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

        // Correction D — the explicit `put_current_epoch(0)` fixture yields the
        // distinct `CommittedEpoch(0)` observation, still present after the
        // read. Epoch 0 takes no epoch-restore branch, so the resulting engine
        // epoch is 0 — here from the seeded committed epoch, distinct from the
        // missing-epoch fallback exercised in the C1 test above.
        let obs_after = observe_consensus_storage(Some(storage.as_ref())).expect("observe after");
        assert_eq!(obs_after, ConsensusStorageObservation::CommittedEpoch(0));
        assert_eq!(harness.driver().engine().current_epoch(), 0);
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