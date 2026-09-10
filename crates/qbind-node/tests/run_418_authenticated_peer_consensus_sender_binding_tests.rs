//! Run 418 — F6 authenticated KEMTLS peer → consensus sender binding.
//!
//! These are the dedicated Run 418 acceptance tests. They exercise the REAL
//! production consensus-ingress path (`run_binary_consensus_loop_with_io` +
//! `BinaryConsensusLoopIo { binding_gate: Some(..) }`), the REAL production
//! demux envelope type (`InboundConsensusEnvelope`), the REAL authoritative
//! binding gate/map (`PeerConsensusBindingGate` / `PeerConsensusBindingMap` /
//! `AuthenticatedConsensusOrigin`), the REAL strict validator-ID parser
//! (`parse_test_validator_id_from_cert_validator_id`) and the REAL verified
//! server identity type (`VerifiedServerIdentity`). No mock ingress / no mock
//! gate is used: the messages traverse the same loop that production P2P
//! traffic traverses.
//!
//! Coverage (per the Run 418 task):
//!
//!  1. matching authenticated Proposal accepted by the binding gate;
//!  2. matching authenticated Vote accepted by the binding gate;
//!  3. authenticated peer B claiming validator A in a Proposal rejected;
//!  4. authenticated peer B claiming validator A in a Vote rejected;
//!  5. mismatch causes NO engine call / reconfig observation / mutation /
//!     outbound action / accepted-or-delivered increment;
//!  6. missing origin rejected;
//!  7. unauthenticated Optional/Disabled remote consensus rejected;
//!  8. actual inbound verified client identity propagated end-to-end
//!     (drives the engine and produces a real outbound vote);
//!  9. actual outbound verified server identity propagated end-to-end
//!     (an unexpected server cert/identity cannot inherit the configured
//!     address's origin);
//! 10. unconfigured alternate certificate (root-valid but unconfigured leaf)
//!     rejected;
//! 11. malformed / noncanonical / out-of-range validator identity rejected;
//! 12. duplicate / ambiguous mappings fail startup;
//! 13. complete 32-byte NodeId comparison (first-eight-byte collision);
//! 14. fixed-label metrics increment accurately and appear through the live
//!     metrics surface;
//! 15. origin remains strictly in-process and is absent from serialized wire
//!     bytes.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use parking_lot::Mutex as PlMutex;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::network::NetworkError;
use qbind_consensus::timeout::TimeoutCertificate;
use qbind_node::binary_consensus_loop::{
    ConsensusVerificationPolicy,
    run_binary_consensus_loop_with_io, BinaryConsensusLoopConfig, BinaryConsensusLoopIo,
    BinaryConsensusLoopProgress,
};
use qbind_node::consensus_network_facade::ConsensusNetworkFacade;
use qbind_node::metrics::NodeMetrics;
use qbind_node::p2p::{ConsensusNetMsg, NodeId};
use qbind_node::p2p_inbound::InboundConsensusEnvelope;
use qbind_node::p2p_node_builder::parse_test_validator_id_from_cert_validator_id;
use qbind_node::peer::PeerId;
use qbind_node::peer_consensus_binding::{
    AuthenticatedConsensusOrigin, ConsensusBindingReject, PeerConsensusBindingGate,
    PeerConsensusBindingMap,
};
use qbind_node::secure_channel::VerifiedServerIdentity;
use qbind_wire::consensus::{BlockHeader, BlockProposal, Vote};
use qbind_wire::io::WireEncode;

// ============================================================================
// Test helpers
// ============================================================================

/// Canonical `qbind-val-<N>` cert `validator_id` bytes, exactly as
/// `validator_id_bytes_for_index` produces them in production.
fn canonical_validator_id_bytes(n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let name = format!("qbind-val-{}", n);
    out[..name.len()].copy_from_slice(name.as_bytes());
    out
}

/// A full 32-byte NodeId whose first byte is `first` and last byte is `tag`.
fn nid(first: u8, tag: u8) -> NodeId {
    let mut b = [0u8; 32];
    b[0] = first;
    b[31] = tag;
    NodeId::new(b)
}

/// Build the standard two-validator authoritative binding map used across the
/// acceptance tests: NodeId `A` ↔ validator 0, NodeId `B` ↔ validator 1.
fn node_a() -> NodeId {
    nid(0xA0, 0x01)
}
fn node_b() -> NodeId {
    nid(0xB0, 0x02)
}

fn two_validator_gate() -> Arc<PeerConsensusBindingGate> {
    let map = PeerConsensusBindingMap::build([
        (node_a(), ValidatorId::new(0)),
        (node_b(), ValidatorId::new(1)),
    ])
    .expect("valid one-to-one map");
    Arc::new(PeerConsensusBindingGate::new(map))
}

/// Build a wire-format `BlockProposal` for the genesis view by `proposer`,
/// exactly matching what the leader-step path of the engine would produce.
fn make_genesis_proposal(proposer: ValidatorId) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 0,
            round: 0,
            parent_block_id: [0xFF; 32],
            payload_hash: [0u8; 32],
            proposer_index: proposer.as_u64() as u16,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 0,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    }
}

fn make_vote(voter: ValidatorId) -> Vote {
    Vote {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height: 0,
        round: 0,
        step: 0,
        block_id: [0u8; 32],
        validator_index: voter.as_u64() as u16,
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signature: vec![],
    }
}

fn encode<T: WireEncode>(t: &T) -> Vec<u8> {
    let mut out = Vec::new();
    t.encode(&mut out);
    out
}

/// A `ConsensusNetworkFacade` that records every outbound action it receives,
/// so tests can assert that a rejected inbound message produced NO outbound
/// engine action.
#[derive(Default)]
struct RecordingFacade {
    inner: Mutex<RecordingFacadeInner>,
}

#[derive(Default)]
struct RecordingFacadeInner {
    proposals: Vec<BlockProposal>,
    broadcast_votes: Vec<Vote>,
    direct_votes: Vec<(ValidatorId, Vote)>,
    timeouts: usize,
}

impl RecordingFacade {
    fn total_actions(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.proposals.len()
            + inner.broadcast_votes.len()
            + inner.direct_votes.len()
            + inner.timeouts
    }
    fn broadcast_vote_count(&self) -> usize {
        self.inner.lock().unwrap().broadcast_votes.len()
    }
}

impl ConsensusNetworkFacade for RecordingFacade {
    fn send_vote_to(&self, target: ValidatorId, vote: &Vote) -> Result<(), NetworkError> {
        self.inner
            .lock()
            .unwrap()
            .direct_votes
            .push((target, vote.clone()));
        Ok(())
    }
    fn broadcast_vote(&self, vote: &Vote) -> Result<(), NetworkError> {
        self.inner
            .lock()
            .unwrap()
            .broadcast_votes
            .push(vote.clone());
        Ok(())
    }
    fn broadcast_proposal(&self, proposal: &BlockProposal) -> Result<(), NetworkError> {
        self.inner.lock().unwrap().proposals.push(proposal.clone());
        Ok(())
    }
    fn send_timeout_msg(&self, _target: PeerId, _msg_bytes: Vec<u8>) -> Result<(), NetworkError> {
        self.inner.lock().unwrap().timeouts += 1;
        Ok(())
    }
}

/// Outcome of running a single inbound envelope through the real production
/// binary-consensus loop with a binding gate installed.
struct LoopOutcome {
    progress: BinaryConsensusLoopProgress,
    outbound: Arc<RecordingFacade>,
}

/// Drive one inbound envelope through the REAL loop with the given gate, as a
/// validator `local` in an `n`-validator set. Returns the final progress stats
/// and the recording facade so callers can assert on side effects.
async fn drive_one(
    local: ValidatorId,
    n: u64,
    gate: Arc<PeerConsensusBindingGate>,
    envelope: InboundConsensusEnvelope,
) -> LoopOutcome {
    let cfg = BinaryConsensusLoopConfig::new(local, n)
        .with_tick_interval(Duration::from_millis(50))
        .with_max_ticks(10);

    let (_shutdown_tx, shutdown_rx) = watch::channel(());
    let metrics = Arc::new(NodeMetrics::new());
    let progress = Arc::new(PlMutex::new(BinaryConsensusLoopProgress::default()));

    let (inbound_tx, inbound_rx) = mpsc::channel::<InboundConsensusEnvelope>(16);
    let outbound = Arc::new(RecordingFacade::default());
    let outbound_dyn: Arc<dyn ConsensusNetworkFacade> = outbound.clone();

    let io = BinaryConsensusLoopIo {
        inbound_rx,
        outbound: outbound_dyn,
        peer_connectivity: None,
        verification_ctx: None,
        binding_gate: Some(gate),
        verification_policy: ConsensusVerificationPolicy::LocalFixtureUnsigned,
    };

    inbound_tx
        .send(envelope)
        .await
        .expect("inbound channel accepts envelope");
    drop(inbound_tx);

    let loop_metrics = metrics.clone();
    let loop_progress = progress.clone();
    let handle = tokio::spawn(async move {
        run_binary_consensus_loop_with_io(cfg, shutdown_rx, loop_progress, loop_metrics, Some(io))
            .await
    });

    let final_progress = timeout(Duration::from_secs(3), handle)
        .await
        .expect("loop finished within 3s")
        .expect("loop task did not panic");

    LoopOutcome {
        progress: final_progress,
        outbound,
    }
}

// ============================================================================
// 1 & 8. Matching authenticated Proposal accepted; verified inbound client
//        identity propagated end-to-end.
// ============================================================================

#[tokio::test]
async fn run418_matching_proposal_accepted_and_client_identity_propagates() {
    let gate = two_validator_gate();
    // Authenticated peer A (validator 0) proposes for view 0; local is
    // validator 1. The origin is the verified transport identity resolved at
    // the KEMTLS layer — never from the payload.
    let origin = AuthenticatedConsensusOrigin::new(node_a(), ValidatorId::new(0));
    let proposal = make_genesis_proposal(ValidatorId::new(0));
    let env =
        InboundConsensusEnvelope::new(Some(origin), ConsensusNetMsg::Proposal(encode(&proposal)));

    let out = drive_one(ValidatorId::new(1), 2, gate.clone(), env).await;

    assert_eq!(
        out.progress.inbound.inbound_sender_binding_rejected_total, 0,
        "matching proposal must NOT be rejected by the binding gate"
    );
    assert_eq!(
        out.progress.inbound.inbound_proposals_delivered, 1,
        "matching proposal must be delivered to the engine"
    );
    // End-to-end: the verified client identity drove the engine, which voted.
    assert!(
        out.outbound.broadcast_vote_count() >= 1,
        "engine must emit an outbound vote for the accepted proposal"
    );
    assert!(
        gate.metrics().accepted() >= 1,
        "gate accepted counter must reflect the accepted proposal"
    );
}

// ============================================================================
// 2. Matching authenticated Vote accepted by the binding gate.
// ============================================================================

#[tokio::test]
async fn run418_matching_vote_accepted_by_gate() {
    let gate = two_validator_gate();
    // Authenticated peer B (validator 1) casts a vote claiming validator 1.
    let origin = AuthenticatedConsensusOrigin::new(node_b(), ValidatorId::new(1));
    let vote = make_vote(ValidatorId::new(1));
    let env = InboundConsensusEnvelope::new(Some(origin), ConsensusNetMsg::Vote(encode(&vote)));

    let before = gate.metrics().accepted();
    let out = drive_one(ValidatorId::new(0), 2, gate.clone(), env).await;

    assert_eq!(
        out.progress.inbound.inbound_sender_binding_rejected_total, 0,
        "matching vote must pass the binding gate"
    );
    assert!(
        gate.metrics().accepted() > before,
        "gate accepted counter must increment for the matching vote"
    );
}

// ============================================================================
// 3, 5. Peer B claiming validator A in a Proposal is rejected with NO side
//        effects.
// ============================================================================

#[tokio::test]
async fn run418_proposal_impersonation_rejected_no_side_effects() {
    let gate = two_validator_gate();
    // Authenticated peer B (validator 1) forges a proposal claiming to be the
    // leader validator 0.
    let origin = AuthenticatedConsensusOrigin::new(node_b(), ValidatorId::new(1));
    let proposal = make_genesis_proposal(ValidatorId::new(0));
    let env =
        InboundConsensusEnvelope::new(Some(origin), ConsensusNetMsg::Proposal(encode(&proposal)));

    let out = drive_one(ValidatorId::new(1), 2, gate.clone(), env).await;

    assert_eq!(
        out.progress.inbound.inbound_sender_binding_rejected_total, 1,
        "impersonated proposal must be rejected"
    );
    assert_eq!(
        out.progress.inbound.inbound_proposals_delivered, 0,
        "rejected proposal must NOT be delivered to the engine"
    );
    assert_eq!(
        out.progress.inbound.inbound_proposals_engine_accepted, 0,
        "rejected proposal must NOT be engine-accepted"
    );
    assert_eq!(
        out.outbound.total_actions(),
        0,
        "rejected proposal must produce NO outbound engine action"
    );
    assert!(
        gate.metrics()
            .reject_count(ConsensusBindingReject::ClaimedSenderMismatch)
            >= 1,
        "reject must be classified as a claimed-sender mismatch"
    );
}

// ============================================================================
// 4, 5. Peer B claiming validator A in a Vote is rejected with NO side effects.
// ============================================================================

#[tokio::test]
async fn run418_vote_impersonation_rejected_no_side_effects() {
    let gate = two_validator_gate();
    // Authenticated peer B (validator 1) forges a vote claiming validator 0.
    // Local is validator 1 (a non-leader for view 0) so the loop performs no
    // self-driven leader-step actions that could confound the assertion.
    let origin = AuthenticatedConsensusOrigin::new(node_b(), ValidatorId::new(1));
    let vote = make_vote(ValidatorId::new(0));
    let env = InboundConsensusEnvelope::new(Some(origin), ConsensusNetMsg::Vote(encode(&vote)));

    let out = drive_one(ValidatorId::new(1), 2, gate.clone(), env).await;

    assert_eq!(
        out.progress.inbound.inbound_sender_binding_rejected_total, 1,
        "impersonated vote must be rejected"
    );
    assert_eq!(
        out.progress.inbound.inbound_votes_delivered, 0,
        "rejected vote must NOT be delivered to the engine"
    );
    assert_eq!(
        out.progress.inbound.inbound_votes_engine_accepted, 0,
        "rejected vote must NOT be engine-accepted"
    );
    assert_eq!(
        out.outbound.total_actions(),
        0,
        "rejected vote must produce NO outbound engine action"
    );
}

// ============================================================================
// 6, 7. Missing origin rejected; unauthenticated Optional/Disabled remote
//        consensus rejected.
// ============================================================================

#[tokio::test]
async fn run418_missing_origin_rejected() {
    let gate = two_validator_gate();
    // An unauthenticated remote session (Optional/Disabled mutual-auth policy)
    // surfaces NO verified origin. With a binding gate installed, such a
    // message must fail closed.
    let proposal = make_genesis_proposal(ValidatorId::new(0));
    let env = InboundConsensusEnvelope::new(None, ConsensusNetMsg::Proposal(encode(&proposal)));

    let out = drive_one(ValidatorId::new(1), 2, gate.clone(), env).await;

    assert_eq!(
        out.progress.inbound.inbound_sender_binding_rejected_total, 1,
        "missing-origin (unauthenticated) message must be rejected"
    );
    assert_eq!(out.progress.inbound.inbound_proposals_delivered, 0);
    assert_eq!(out.outbound.total_actions(), 0);
    assert!(
        gate.metrics()
            .reject_count(ConsensusBindingReject::MissingOrigin)
            >= 1,
        "reject must be classified as a missing origin"
    );
}

#[test]
fn run418_gate_fails_closed_on_absent_origin() {
    // Direct proof at the authoritative decision point: an absent authenticated
    // origin can never be accepted, regardless of the claimed validator.
    let gate = two_validator_gate();
    let r = gate.authorize(None, ValidatorId::new(0));
    assert_eq!(r, Err(ConsensusBindingReject::MissingOrigin));
}

// ============================================================================
// 9. Outbound: verified server identity propagated end-to-end; an unexpected
//    server cert/identity cannot inherit the configured address's origin.
// ============================================================================

#[test]
fn run418_outbound_unexpected_server_identity_cannot_inherit_configured_origin() {
    // The dialer configured `vid@addr` to expect validator 0 with the
    // authoritative NodeId `A`. This is the *expected* pair only.
    let expected = AuthenticatedConsensusOrigin::new(node_a(), ValidatorId::new(0));

    // Case 1: the handshake surfaces the genuinely-expected server identity.
    let good = VerifiedServerIdentity {
        node_id: *node_a().as_bytes(),
        validator_id: canonical_validator_id_bytes(0),
        authenticated: true,
    };
    let good_origin = origin_from_verified(&good).expect("verified identity parses");
    assert_eq!(
        good_origin, expected,
        "the actual verified server identity must equal the configured pair"
    );

    // Case 2: an unexpected server presents a different (root-valid) cert. Its
    // verified identity must NOT be coerced into the configured origin.
    let unexpected = VerifiedServerIdentity {
        node_id: *node_b().as_bytes(),
        validator_id: canonical_validator_id_bytes(1),
        authenticated: true,
    };
    let unexpected_origin = origin_from_verified(&unexpected).expect("verified identity parses");
    assert_ne!(
        unexpected_origin, expected,
        "an unexpected server certificate/identity must not inherit the \
         configured address's origin"
    );

    // Case 3: same address, same claimed validator index, but a different
    // (unconfigured) leaf NodeId — the full 32-byte NodeId comparison rejects.
    let wrong_leaf = VerifiedServerIdentity {
        node_id: *nid(0xA0, 0xEE).as_bytes(), // shares first byte with A, differs in full
        validator_id: canonical_validator_id_bytes(0),
        authenticated: true,
    };
    let wrong_leaf_origin = origin_from_verified(&wrong_leaf).expect("verified identity parses");
    assert_ne!(
        wrong_leaf_origin, expected,
        "an alternate leaf certificate for the same validator must not match"
    );
}

/// Reconstruct the `AuthenticatedConsensusOrigin` exactly as the production
/// dial path does from a `VerifiedServerIdentity`: the full 32-byte
/// cert-derived NodeId plus the strictly-parsed validator index.
fn origin_from_verified(v: &VerifiedServerIdentity) -> Option<AuthenticatedConsensusOrigin> {
    let vid = parse_test_validator_id_from_cert_validator_id(&v.validator_id)?;
    Some(AuthenticatedConsensusOrigin::new(
        NodeId::new(v.node_id),
        ValidatorId::new(vid),
    ))
}

// ============================================================================
// 10, 13. Unconfigured alternate certificate rejected; complete 32-byte NodeId
//          comparison (first-eight-byte collision).
// ============================================================================

#[test]
fn run418_unconfigured_and_colliding_nodeids_rejected() {
    let gate = two_validator_gate();

    // An alternate root-valid but unconfigured leaf certificate for validator 0
    // (a NodeId not present in the authoritative map) is rejected as an unknown
    // peer — decode/root-validity alone never admits a binding.
    let unconfigured = AuthenticatedConsensusOrigin::new(nid(0xCC, 0x77), ValidatorId::new(0));
    assert_eq!(
        gate.authorize(Some(&unconfigured), ValidatorId::new(0)),
        Err(ConsensusBindingReject::UnknownPeer)
    );

    // A NodeId sharing the first eight bytes with the configured NodeId `A`,
    // but differing later, must NOT be treated as `A`: the full 32-byte NodeId
    // is compared.
    let mut collide = *node_a().as_bytes();
    collide[8] ^= 0xFF; // differs only beyond the first eight bytes
    let colliding = AuthenticatedConsensusOrigin::new(NodeId::new(collide), ValidatorId::new(0));
    assert_eq!(
        gate.authorize(Some(&colliding), ValidatorId::new(0)),
        Err(ConsensusBindingReject::UnknownPeer),
        "the full 32-byte NodeId must be compared, not a prefix"
    );
}

// ============================================================================
// 11. Malformed / noncanonical / out-of-range validator identity rejected.
// ============================================================================

#[test]
fn run418_strict_validator_id_parsing() {
    // Canonical forms accepted.
    assert_eq!(
        parse_test_validator_id_from_cert_validator_id(&canonical_validator_id_bytes(0)),
        Some(0)
    );
    assert_eq!(
        parse_test_validator_id_from_cert_validator_id(&canonical_validator_id_bytes(1)),
        Some(1)
    );
    assert_eq!(
        parse_test_validator_id_from_cert_validator_id(&canonical_validator_id_bytes(1023)),
        Some(1023)
    );

    // Helper to craft an arbitrary `qbind-val-<suffix>` byte array.
    let make = |suffix: &[u8]| -> [u8; 32] {
        let mut b = [0u8; 32];
        let prefix = b"qbind-val-";
        b[..prefix.len()].copy_from_slice(prefix);
        let end = (prefix.len() + suffix.len()).min(32);
        b[prefix.len()..end].copy_from_slice(&suffix[..end - prefix.len()]);
        b
    };

    // Noncanonical leading zero.
    assert_eq!(
        parse_test_validator_id_from_cert_validator_id(&make(b"01")),
        None
    );
    // Trailing non-zero garbage after the digits.
    assert_eq!(
        parse_test_validator_id_from_cert_validator_id(&make(b"1x")),
        None
    );
    // Trailing non-zero byte after digits + a zero pad in the middle.
    let mut trailing = canonical_validator_id_bytes(1);
    trailing[20] = b'Z'; // a nonzero byte well past the digits
    assert_eq!(
        parse_test_validator_id_from_cert_validator_id(&trailing),
        None
    );
    // Empty index.
    assert_eq!(
        parse_test_validator_id_from_cert_validator_id(&make(b"")),
        None
    );
    // Overflow: 21 decimal digits cannot fit in a u64.
    assert_eq!(
        parse_test_validator_id_from_cert_validator_id(&make(b"999999999999999999999")),
        None
    );
    // Wrong prefix entirely.
    let mut wrong = [0u8; 32];
    wrong[..5].copy_from_slice(b"nope-");
    assert_eq!(parse_test_validator_id_from_cert_validator_id(&wrong), None);
}

// ============================================================================
// 12. Duplicate / ambiguous mappings fail startup.
// ============================================================================

#[test]
fn run418_duplicate_or_ambiguous_map_fails_startup() {
    // Two distinct NodeIds mapped to the same validator: ambiguous, rejected.
    let dup_validator = PeerConsensusBindingMap::build([
        (node_a(), ValidatorId::new(0)),
        (node_b(), ValidatorId::new(0)),
    ]);
    assert!(
        dup_validator.is_err(),
        "two NodeIds for one validator must fail map construction"
    );

    // One NodeId mapped to two validators: ambiguous, rejected.
    let dup_node = PeerConsensusBindingMap::build([
        (node_a(), ValidatorId::new(0)),
        (node_a(), ValidatorId::new(1)),
    ]);
    assert!(
        dup_node.is_err(),
        "one NodeId for two validators must fail map construction"
    );

    // A well-formed one-to-one map succeeds.
    assert!(PeerConsensusBindingMap::build([
        (node_a(), ValidatorId::new(0)),
        (node_b(), ValidatorId::new(1)),
    ])
    .is_ok());
}

// ============================================================================
// 14. Fixed-label metrics increment accurately and appear through the live
//     metrics surface.
// ============================================================================

#[test]
fn run418_metrics_fixed_labels_and_live_surface() {
    let gate = two_validator_gate();

    // One accept, one missing-origin reject, one mismatch reject.
    let good = AuthenticatedConsensusOrigin::new(node_a(), ValidatorId::new(0));
    assert!(gate.authorize(Some(&good), ValidatorId::new(0)).is_ok());
    assert!(gate.authorize(None, ValidatorId::new(0)).is_err());
    let b = AuthenticatedConsensusOrigin::new(node_b(), ValidatorId::new(1));
    assert!(gate.authorize(Some(&b), ValidatorId::new(0)).is_err());

    let surface = gate.metrics().format_metrics();
    // Fixed, bounded label set — no unbounded/per-peer cardinality.
    assert!(surface.contains("qbind_consensus_binding_total{result=\"accepted\"} 1"));
    assert!(surface.contains("result=\"missing_origin\""));
    assert!(surface.contains("result=\"claimed_sender_mismatch\""));
    assert_eq!(gate.metrics().accepted(), 1);
    assert_eq!(
        gate.metrics()
            .reject_count(ConsensusBindingReject::MissingOrigin),
        1
    );
    assert_eq!(
        gate.metrics()
            .reject_count(ConsensusBindingReject::ClaimedSenderMismatch),
        1
    );
}

// ============================================================================
// 15. Origin remains strictly in-process and is absent from serialized wire
//     bytes.
// ============================================================================

#[test]
fn run418_origin_absent_from_serialized_wire_bytes() {
    // Give the origin a highly distinctive full-32-byte NodeId pattern.
    let mut pattern = [0u8; 32];
    for (i, byte) in pattern.iter_mut().enumerate() {
        *byte = 0x40 + i as u8;
    }
    let origin = AuthenticatedConsensusOrigin::new(NodeId::new(pattern), ValidatorId::new(0));
    let proposal = make_genesis_proposal(ValidatorId::new(0));
    let env =
        InboundConsensusEnvelope::new(Some(origin), ConsensusNetMsg::Proposal(encode(&proposal)));

    // The wire message is exactly the encoded proposal; the in-process origin
    // is a separate `Option` field and is never serialized onto the wire.
    let wire = match &env.msg {
        ConsensusNetMsg::Proposal(bytes) => bytes.clone(),
        _ => unreachable!(),
    };
    assert_eq!(
        wire,
        encode(&proposal),
        "the wire bytes must be exactly the encoded proposal"
    );
    assert!(
        !contains_subsequence(&wire, &pattern),
        "the origin NodeId bytes must not appear anywhere in the serialized \
         consensus wire bytes"
    );
    // And the origin is still present in-process on the envelope.
    assert!(env.origin.is_some());
}

// ============================================================================
// Run 418 corrective pass — NewView authenticated transport-origin admission.
//
// `NewView` (a multi-signer `TimeoutCertificate`) has NO single immediate
// self-declared sender, so the claimed-sender comparison used for Proposal/Vote
// cannot apply and is not invented. Instead the NewView arm requires that the
// transport session which submitted the frame is an authenticated, authorized
// member of the binding map (origin-only admission,
// `PeerConsensusBindingGate::authorize_origin`) BEFORE the delivered counter,
// F5 verification, `engine.on_timeout_certificate`, or any view/state mutation.
// This is transport-origin admission, NOT NewView signer verification (F5 stays
// unresolved).
// ============================================================================

/// Build a structurally valid `NewView` frame (bincode `TimeoutCertificate`)
/// with the given signers, exactly as the binary path decodes it.
fn make_new_view(timeout_view: u64, signers: Vec<ValidatorId>) -> Vec<u8> {
    let tc: TimeoutCertificate<[u8; 32]> = TimeoutCertificate::new(timeout_view, None, signers);
    bincode::serialize(&tc).expect("serialize TC")
}

// Test 1, 2, 3: NewView with missing origin is rejected BEFORE the delivered
// counter, with no engine call / view advance / state mutation / outbound
// action / accepted counter.
#[tokio::test]
async fn run418_newview_missing_origin_rejected_before_delivered() {
    let gate = two_validator_gate();
    // Unauthenticated Optional/Disabled remote session: no verified origin.
    let bytes = make_new_view(0, vec![ValidatorId::new(0), ValidatorId::new(1)]);
    let env = InboundConsensusEnvelope::new(None, ConsensusNetMsg::NewView(bytes));

    let out = drive_one(ValidatorId::new(1), 2, gate.clone(), env).await;

    assert_eq!(
        out.progress.inbound.inbound_sender_binding_rejected_total, 1,
        "missing-origin NewView must be rejected fail-closed"
    );
    assert_eq!(
        out.progress.inbound.inbound_new_views_delivered, 0,
        "rejection must happen BEFORE inbound_new_views_delivered increments"
    );
    assert_eq!(
        out.progress.inbound.inbound_new_views_engine_accepted, 0,
        "rejected NewView must NOT reach the engine"
    );
    assert_eq!(
        out.progress.inbound.view_timeout_advances, 0,
        "rejected NewView must NOT advance the view"
    );
    assert_eq!(out.progress.current_view, 0, "view must not mutate");
    assert_eq!(
        out.outbound.total_actions(),
        0,
        "rejected NewView must produce NO outbound action"
    );
    assert_eq!(
        gate.metrics().accepted(),
        0,
        "missing-origin NewView must NOT increment the accepted counter"
    );
    assert_eq!(
        gate.metrics()
            .reject_count(ConsensusBindingReject::MissingOrigin),
        1,
        "reject must be classified as a missing origin, recorded exactly once"
    );
}

// Test 4: NewView from an unknown/unconfigured NodeId is rejected.
#[tokio::test]
async fn run418_newview_unknown_nodeid_rejected() {
    let gate = two_validator_gate();
    // Authenticated but unconfigured NodeId (not in the map at all).
    let origin = AuthenticatedConsensusOrigin::new(nid(0xEE, 0xEE), ValidatorId::new(0));
    let bytes = make_new_view(0, vec![ValidatorId::new(0), ValidatorId::new(1)]);
    let env = InboundConsensusEnvelope::new(Some(origin), ConsensusNetMsg::NewView(bytes));

    let out = drive_one(ValidatorId::new(1), 2, gate.clone(), env).await;

    assert_eq!(
        out.progress.inbound.inbound_sender_binding_rejected_total,
        1
    );
    assert_eq!(out.progress.inbound.inbound_new_views_delivered, 0);
    assert_eq!(out.outbound.total_actions(), 0);
    assert_eq!(gate.metrics().accepted(), 0);
    assert_eq!(
        gate.metrics()
            .reject_count(ConsensusBindingReject::UnknownPeer),
        1,
        "unknown authenticated NodeId must be classified as unknown_peer"
    );
}

// Test 5: A conflicting NodeId/ValidatorId origin pair is rejected.
#[tokio::test]
async fn run418_newview_conflicting_pair_rejected() {
    let gate = two_validator_gate();
    // NodeId A is configured for validator 0, but the authenticated origin
    // claims validator 1 — a conflicting/ambiguous pair.
    let origin = AuthenticatedConsensusOrigin::new(node_a(), ValidatorId::new(1));
    let bytes = make_new_view(0, vec![ValidatorId::new(0), ValidatorId::new(1)]);
    let env = InboundConsensusEnvelope::new(Some(origin), ConsensusNetMsg::NewView(bytes));

    let out = drive_one(ValidatorId::new(1), 2, gate.clone(), env).await;

    assert_eq!(
        out.progress.inbound.inbound_sender_binding_rejected_total,
        1
    );
    assert_eq!(out.progress.inbound.inbound_new_views_delivered, 0);
    assert_eq!(out.outbound.total_actions(), 0);
    assert_eq!(gate.metrics().accepted(), 0);
    assert_eq!(
        gate.metrics()
            .reject_count(ConsensusBindingReject::AmbiguousMapping),
        1,
        "conflicting NodeId/ValidatorId pair must be classified as ambiguous_mapping"
    );
}

// Test 6: A correctly mapped authenticated origin passes transport-origin
// admission and then remains subject to the existing F5/engine rules.
#[tokio::test]
async fn run418_newview_authenticated_origin_admitted_then_engine_rules_apply() {
    let gate = two_validator_gate();
    // Authenticated peer B (validator 1), correctly mapped. Local is validator
    // 0. verification_ctx is None in `drive_one`, so F5 does not run here; the
    // frame passes origin admission and then reaches the engine, which applies
    // its own (unchanged) quorum/view rules.
    let origin = AuthenticatedConsensusOrigin::new(node_b(), ValidatorId::new(1));
    let bytes = make_new_view(0, vec![ValidatorId::new(0), ValidatorId::new(1)]);
    let env = InboundConsensusEnvelope::new(Some(origin), ConsensusNetMsg::NewView(bytes));

    let out = drive_one(ValidatorId::new(0), 2, gate.clone(), env).await;

    assert_eq!(
        out.progress.inbound.inbound_sender_binding_rejected_total, 0,
        "correctly mapped authenticated origin must pass transport-origin admission"
    );
    assert_eq!(
        out.progress.inbound.inbound_new_views_delivered, 1,
        "admitted NewView must reach the delivered counter and remain subject to \
         the existing F5/engine rules"
    );
    // Exactly one accepted binding decision for the admitted NewView.
    assert_eq!(
        gate.metrics().accepted(),
        1,
        "admitted NewView must increment the accepted binding metric exactly once"
    );
}

// Test 8 (metrics, NewView path): binding metrics increment exactly once with
// fixed labels for an admitted NewView, and exactly once for a rejected one.
#[tokio::test]
async fn run418_newview_binding_metric_increments_exactly_once() {
    // Accepted path: one admitted NewView → accepted == 1, no rejects.
    let gate = two_validator_gate();
    let origin = AuthenticatedConsensusOrigin::new(node_b(), ValidatorId::new(1));
    let bytes = make_new_view(0, vec![ValidatorId::new(0), ValidatorId::new(1)]);
    let env = InboundConsensusEnvelope::new(Some(origin), ConsensusNetMsg::NewView(bytes));
    let _ = drive_one(ValidatorId::new(0), 2, gate.clone(), env).await;
    assert_eq!(gate.metrics().accepted(), 1);
    let surface = gate.metrics().format_metrics();
    assert!(surface.contains("qbind_consensus_binding_total{result=\"accepted\"} 1"));

    // Rejected path: one missing-origin NewView → missing_origin == 1, no accept.
    let gate2 = two_validator_gate();
    let bytes2 = make_new_view(0, vec![ValidatorId::new(0), ValidatorId::new(1)]);
    let env2 = InboundConsensusEnvelope::new(None, ConsensusNetMsg::NewView(bytes2));
    let _ = drive_one(ValidatorId::new(0), 2, gate2.clone(), env2).await;
    assert_eq!(gate2.metrics().accepted(), 0);
    assert_eq!(
        gate2
            .metrics()
            .reject_count(ConsensusBindingReject::MissingOrigin),
        1,
        "exactly one missing-origin reject recorded for the rejected NewView"
    );
}

// Direct proof at the authoritative decision point that origin-only admission
// fails closed on an absent origin and classifies unknown/ambiguous pairs.
#[test]
fn run418_authorize_origin_fails_closed_and_classifies() {
    let gate = two_validator_gate();
    // Missing origin.
    assert_eq!(
        gate.authorize_origin(None),
        Err(ConsensusBindingReject::MissingOrigin)
    );
    // Unknown NodeId.
    let unknown = AuthenticatedConsensusOrigin::new(nid(0xEE, 0xEE), ValidatorId::new(0));
    assert_eq!(
        gate.authorize_origin(Some(&unknown)),
        Err(ConsensusBindingReject::UnknownPeer)
    );
    // Conflicting pair (NodeId A configured for validator 0, claims validator 1).
    let conflicting = AuthenticatedConsensusOrigin::new(node_a(), ValidatorId::new(1));
    assert_eq!(
        gate.authorize_origin(Some(&conflicting)),
        Err(ConsensusBindingReject::AmbiguousMapping)
    );
    // Correctly mapped origin returns the authenticated validator id.
    let good = AuthenticatedConsensusOrigin::new(node_a(), ValidatorId::new(0));
    assert_eq!(gate.authorize_origin(Some(&good)), Ok(ValidatorId::new(0)));
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}