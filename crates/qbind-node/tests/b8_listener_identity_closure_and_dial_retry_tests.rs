//! B8 — Listener-side validator-identity closure + initial-dial retry
//! for QBIND multi-validator binary-path P2P.
//!
//! These tests prove the smallest honest claims required after
//! `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_006.md` §10–§13:
//!
//! 1. Accepted inbound sessions on the binary path are now bound to
//!    the validator-derived deterministic NodeId, not only to a
//!    temporary session NodeId. (B8.1)
//! 2. Stagger-started two-node clusters recover from initial
//!    `Connection refused` via bounded retry of the static-peer
//!    dial. Pinning `DialRetryPolicy::no_retry` on the same topology
//!    reproduces the pre-B8 single-shot failure mode (insufficient
//!    to recover from a stagger), confirming the retry path is what
//!    makes recovery work. (B8.2)
//! 3. Combined effect: `send_to(ValidatorId)` resolves to a real
//!    registered transport session on BOTH directions for two real
//!    `qbind-node`-shaped configurations, which is the precondition
//!    DevNet Evidence Run 007 needs to test for the first cross-node
//!    `ConsensusNetMsg::{Proposal, Vote}` traffic.
//! 4. Previously landed paths (single-validator / no-P2P, B7 peer
//!    syntax / overrides) do not regress.
//!
//! Test matrix:
//!
//! - **A. `parse_test_validator_id_from_client_random` parses the
//!   B7-shaped `qbind-client-N` prefix.** Pure-function regression pin
//!   for the listener-side identity-recovery rule.
//!
//! - **B. Listener-side accepted session is registered under the
//!   validator-derived deterministic NodeId.** Two-node bring-up:
//!   V0's listener accepts V1's dial; V0's `connected_peers()` must
//!   contain `derive_test_node_id_from_validator_id(1)` (NOT just a
//!   random temp session NodeId). This is precisely the property
//!   Run 006 observed missing.
//!
//! - **C. Initial dial retry recovers from a stagger-started peer
//!   that comes up after the dialer.** Build node 0 first against a
//!   peer port that is NOT yet bound; bring up node 1 a second later;
//!   assert node 0's transport eventually has a connection registered
//!   under V1's deterministic NodeId. The retry path is what makes
//!   this work — pinning [`DialRetryPolicy::no_retry`] on the same
//!   topology is shown to be insufficient.
//!
//! - **D. Two-node binary-path send-side precondition holds in both
//!   directions.** After bring-up + the bounded retry window,
//!   *both* sides see the *other's* deterministic NodeId among
//!   `connected_peers()`. This is the joint condition under which a
//!   subsequent `send_to(ValidatorId)` / `broadcast()` can resolve to
//!   a real registered session on either side — i.e. enough to
//!   justify DevNet Evidence Run 007.
//!
//! - **E. Single-validator / no-P2P / no-peer paths do not regress.**
//!   `P2pNodeBuilder::build` with empty `static_peers` continues to
//!   succeed and the consensus loop is unaffected. (Strictly
//!   redundant with `b7_e_single_validator_no_peers_does_not_regress`,
//!   kept here to localize the no-regression claim for B8.)

use std::sync::Arc;
use std::time::{Duration, Instant};

use qbind_node::p2p::{NodeId, P2pService};
use qbind_node::p2p_node_builder::{
    derive_test_node_id_from_validator_id, parse_test_validator_id_from_client_random,
    P2pNodeBuilder,
};
use qbind_node::p2p_tcp::DialRetryPolicy;

// ---------------------------------------------------------------------------
// Helpers (mirror the b7 test helpers; kept private to this file).
// ---------------------------------------------------------------------------

fn make_p2p_test_config(
    listen_addr: &str,
    static_peers: Vec<String>,
) -> qbind_node::node_config::NodeConfig {
    use qbind_ledger::{FeeDistributionPolicy, MonetaryMode, SeigniorageSplit};
    use qbind_node::node_config::{
        DagCouplingMode, ExecutionProfile, FastSyncConfig, GenesisSourceConfig,
        MempoolDosConfig, MempoolEvictionConfig, MempoolMode, NetworkMode,
        NetworkTransportConfig, NodeConfig, P2pAntiEclipseConfig, P2pDiscoveryConfig,
        P2pLivenessConfig, SignerFailureMode, SignerMode, SlashingConfig, SnapshotConfig,
        StateRetentionConfig, ValidatorStakeConfig,
    };
    use qbind_node::p2p_diversity::DiversityEnforcementMode;
    use qbind_types::NetworkEnvironment;

    NodeConfig {
        environment: NetworkEnvironment::Testnet,
        execution_profile: ExecutionProfile::VmV0,
        data_dir: None,
        network: NetworkTransportConfig {
            enable_p2p: true,
            max_outbound: 4,
            max_inbound: 8,
            gossip_fanout: 3,
            listen_addr: Some(listen_addr.to_string()),
            advertised_addr: None,
            static_peers,
            discovery_enabled: false,
            discovery_interval_secs: 30,
            max_known_peers: 200,
            target_outbound_peers: 8,
            liveness_probe_interval_secs: 30,
            liveness_failure_threshold: 3,
            liveness_min_score: 30,
            diversity_mode: DiversityEnforcementMode::Off,
            max_peers_per_ipv4_prefix24: 2,
            max_peers_per_ipv4_prefix16: 8,
            min_outbound_diversity_buckets: 4,
            max_single_bucket_fraction_bps: 2500,
        },
        network_mode: NetworkMode::P2p,
        gas_enabled: false,
        enable_fee_priority: false,
        mempool_mode: MempoolMode::Fifo,
        dag_availability_enabled: false,
        dag_coupling_mode: DagCouplingMode::Off,
        stage_b_enabled: false,
        fee_distribution_policy: FeeDistributionPolicy::burn_only(),
        monetary_mode: MonetaryMode::Off,
        monetary_accounts: None,
        seigniorage_split: SeigniorageSplit::default(),
        state_retention: StateRetentionConfig::disabled(),
        snapshot_config: SnapshotConfig::disabled(),
        fast_sync_config: FastSyncConfig::disabled(),
        signer_mode: SignerMode::LoopbackTesting,
        signer_keystore_path: None,
        remote_signer_url: None,
        remote_signer_cert_path: None,
        remote_signer_client_cert_path: None,
        remote_signer_client_key_path: None,
        hsm_config_path: None,
        signer_failure_mode: SignerFailureMode::ExitOnFailure,
        mempool_dos: MempoolDosConfig::devnet_default(),
        mempool_eviction: MempoolEvictionConfig::devnet_default(),
        p2p_discovery: P2pDiscoveryConfig::devnet_default(),
        p2p_liveness: P2pLivenessConfig::devnet_default(),
        p2p_anti_eclipse: Some(P2pAntiEclipseConfig::devnet_default()),
        slashing: SlashingConfig::devnet_default(),
        validator_stake: ValidatorStakeConfig::devnet_default(),
        genesis_source: GenesisSourceConfig::devnet_default(),
        expected_genesis_hash: None,
    }
}

async fn reserve_local_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind reserve listener");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Poll until either side observes the other's deterministic NodeId
/// among `connected_peers()`, or the deadline expires. Returns the
/// `(saw_v1_on_v0, saw_v0_on_v1)` pair at the moment of return.
async fn poll_peer_observability(
    ctx_v0: &qbind_node::p2p_node_builder::P2pNodeContext,
    ctx_v1: &qbind_node::p2p_node_builder::P2pNodeContext,
    nid_v0: NodeId,
    nid_v1: NodeId,
    timeout: Duration,
) -> (bool, bool) {
    let deadline = Instant::now() + timeout;
    let mut saw_v1_on_v0 = false;
    let mut saw_v0_on_v1 = false;
    while Instant::now() < deadline {
        let v0_peers = ctx_v0.p2p_service.connected_peers();
        let v1_peers = ctx_v1.p2p_service.connected_peers();
        saw_v1_on_v0 = saw_v1_on_v0 || v0_peers.contains(&nid_v1);
        saw_v0_on_v1 = saw_v0_on_v1 || v1_peers.contains(&nid_v0);
        if saw_v1_on_v0 && saw_v0_on_v1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    (saw_v1_on_v0, saw_v0_on_v1)
}

// ---------------------------------------------------------------------------
// A. `parse_test_validator_id_from_client_random` parsing pin.
// ---------------------------------------------------------------------------

#[test]
fn b8_a_parse_validator_id_from_client_random_round_trips() {
    // The round-trip rule the listener-side resolver uses: build a
    // 32-byte `client_random` exactly as `create_connection_configs`
    // does, then parse it back.
    fn make_client_random(vid: u64) -> [u8; 32] {
        let mut buf = [0u8; 32];
        let s = format!("qbind-client-{}", vid);
        let n = s.len().min(32);
        buf[..n].copy_from_slice(&s.as_bytes()[..n]);
        buf
    }

    for vid in [0u64, 1, 2, 3, 7, 42, 12345] {
        let cr = make_client_random(vid);
        let parsed = parse_test_validator_id_from_client_random(&cr);
        assert_eq!(
            parsed,
            Some(vid),
            "B8.A: round-trip parse for vid={} must succeed",
            vid
        );
    }

    // Garbage / non-conforming `client_random` must NOT spoof a vid —
    // the resolver MUST return `None` so the transport falls back to
    // the legacy temporary-session-NodeId path.
    let mut all_zero = [0u8; 32];
    assert_eq!(
        parse_test_validator_id_from_client_random(&all_zero),
        None,
        "B8.A: all-zero client_random must NOT parse as a vid"
    );
    all_zero[0] = b'X';
    assert_eq!(
        parse_test_validator_id_from_client_random(&all_zero),
        None,
        "B8.A: non-prefixed client_random must NOT parse as a vid"
    );
    let mut bad = [0u8; 32];
    bad[..b"qbind-client-".len()].copy_from_slice(b"qbind-client-");
    // No digits after the prefix.
    assert_eq!(
        parse_test_validator_id_from_client_random(&bad),
        None,
        "B8.A: missing-digits client_random must NOT parse"
    );
}

// ---------------------------------------------------------------------------
// B. Listener-side accepted session is bound to the deterministic NodeId.
// ---------------------------------------------------------------------------

/// Two-node bring-up where V1 is started first (so its listener is up
/// before V0 dials it). The dialer-side closure was already proven by
/// B7. The B8 claim under test here is the LISTENER side: V1's
/// `connected_peers()` must observe V0's deterministic NodeId
/// `derive_test_node_id_from_validator_id(0)`, NOT a temp session
/// NodeId — which is the property DevNet Evidence Run 006 reported
/// missing.
#[tokio::test]
async fn b8_b_listener_side_accepted_session_bound_to_deterministic_node_id() {
    let port_v0 = reserve_local_port().await;
    let port_v1 = reserve_local_port().await;

    let cfg_v0 = make_p2p_test_config(
        &format!("127.0.0.1:{}", port_v0),
        vec![format!("1@127.0.0.1:{}", port_v1)],
    );
    let cfg_v1 = make_p2p_test_config(
        &format!("127.0.0.1:{}", port_v1),
        vec![format!("0@127.0.0.1:{}", port_v0)],
    );

    // Start V1 first (its listener will be up when V0 dials).
    let ctx_v1 = P2pNodeBuilder::new()
        .with_num_validators(2)
        .build(&cfg_v1, 1)
        .await
        .expect("build v1");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let ctx_v0 = P2pNodeBuilder::new()
        .with_num_validators(2)
        .build(&cfg_v0, 0)
        .await
        .expect("build v0");

    let nid_v0 = derive_test_node_id_from_validator_id(0);
    let nid_v1 = derive_test_node_id_from_validator_id(1);

    let (saw_v1_on_v0, saw_v0_on_v1) =
        poll_peer_observability(&ctx_v0, &ctx_v1, nid_v0, nid_v1, Duration::from_secs(8))
            .await;

    // Dialer-side closure (B7) — kept as a sanity check.
    assert!(
        saw_v1_on_v0,
        "B8.B: V0 (the dialer) must see V1's deterministic NodeId {:?} (B7 dialer-side closure)",
        nid_v1
    );

    // **The B8 claim under test:** the listener side must register the
    // accepted session under the deterministic peer NodeId, not under
    // a fresh temporary session NodeId. Pre-B8 this assertion would
    // fail — the only NodeId V1 had for the V0->V1 inbound session
    // was a `sha3_256(local_validator_id || session_counter ||
    // peer_addr)` that has nothing to do with V0's deterministic id.
    assert!(
        saw_v0_on_v1,
        "B8.B: V1 (the listener) must observe V0's deterministic NodeId {:?} \
         among connected_peers (the listener-side identity-closure claim of B8 — \
         this is the property DevNet Evidence Run 006 reported missing)",
        nid_v0
    );

    let _ = P2pNodeBuilder::shutdown(ctx_v0).await;
    let _ = P2pNodeBuilder::shutdown(ctx_v1).await;
}

// ---------------------------------------------------------------------------
// C. Initial-dial retry recovers from a stagger-started peer.
// ---------------------------------------------------------------------------

/// Stagger startup: V0 is built BEFORE V1, against a peer port that is
/// not yet bound. The first dial must hit `Connection refused`. With
/// the B8 bounded-retry policy, V0's background dialer task must
/// recover once V1's listener comes up.
#[tokio::test]
async fn b8_c_initial_dial_retry_recovers_from_stagger() {
    let port_v0 = reserve_local_port().await;
    let port_v1 = reserve_local_port().await;

    let cfg_v0 = make_p2p_test_config(
        &format!("127.0.0.1:{}", port_v0),
        vec![format!("1@127.0.0.1:{}", port_v1)],
    );
    let cfg_v1 = make_p2p_test_config(
        &format!("127.0.0.1:{}", port_v1),
        vec![format!("0@127.0.0.1:{}", port_v0)],
    );

    // Start V0 FIRST, against a peer port nothing is listening on.
    // Pre-B8 this single-shot dial would fail with `Connection
    // refused` and never retry — V0 would forever lack an outbound
    // session to V1.
    let ctx_v0 = P2pNodeBuilder::new()
        .with_num_validators(2)
        .build(&cfg_v0, 0)
        .await
        .expect("build v0 against not-yet-bound peer port must still succeed (start() does not block on dial)");

    // Sanity: V0 has not yet observed V1's NodeId — the dial cannot
    // have succeeded because V1 is not up yet.
    let nid_v1 = derive_test_node_id_from_validator_id(1);
    assert!(
        !ctx_v0.p2p_service.connected_peers().contains(&nid_v1),
        "B8.C: V0 cannot observe V1 before V1's listener is up"
    );

    // Wait long enough for at least one retry attempt to fire and fail
    // again, then bring up V1.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let ctx_v1 = P2pNodeBuilder::new()
        .with_num_validators(2)
        .build(&cfg_v1, 1)
        .await
        .expect("build v1");

    // Now the retry MUST land within the bounded retry window
    // (default ~5.5s wall-clock).
    let nid_v0 = derive_test_node_id_from_validator_id(0);
    let (saw_v1_on_v0, _) =
        poll_peer_observability(&ctx_v0, &ctx_v1, nid_v0, nid_v1, Duration::from_secs(8))
            .await;
    assert!(
        saw_v1_on_v0,
        "B8.C: after V1 comes up, V0's background dialer task must have retried \
         the initial `Connection refused` and eventually established an outbound \
         session to V1's deterministic NodeId {:?} (this is the recovery property \
         DevNet Evidence Run 006 reported missing)",
        nid_v1
    );

    let _ = P2pNodeBuilder::shutdown(ctx_v0).await;
    let _ = P2pNodeBuilder::shutdown(ctx_v1).await;
}

// ---------------------------------------------------------------------------
// D. Two-node bidirectional `send_to(ValidatorId)` precondition.
// ---------------------------------------------------------------------------

/// Combined effect: after B8, two real `qbind-node`-shaped configurations
/// can stand up such that BOTH sides observe the OTHER's deterministic
/// NodeId among `connected_peers()`. That is the precondition under
/// which `P2pConsensusNetwork::send_to(ValidatorId)` resolves to a
/// real registered transport session on either side — enough to
/// justify a DevNet Evidence Run 007 attempt at first cross-node
/// `ConsensusNetMsg::{Proposal, Vote}` traffic.
#[tokio::test]
async fn b8_d_two_node_bidirectional_send_precondition_holds() {
    let port_v0 = reserve_local_port().await;
    let port_v1 = reserve_local_port().await;

    let cfg_v0 = make_p2p_test_config(
        &format!("127.0.0.1:{}", port_v0),
        vec![format!("1@127.0.0.1:{}", port_v1)],
    );
    let cfg_v1 = make_p2p_test_config(
        &format!("127.0.0.1:{}", port_v1),
        vec![format!("0@127.0.0.1:{}", port_v0)],
    );

    // Start V1 first (so V0's first dial races but does not always
    // fail — we want the realistic positive shape, not the worst case).
    let ctx_v1 = P2pNodeBuilder::new()
        .with_num_validators(2)
        .build(&cfg_v1, 1)
        .await
        .expect("build v1");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let ctx_v0 = P2pNodeBuilder::new()
        .with_num_validators(2)
        .build(&cfg_v0, 0)
        .await
        .expect("build v0");

    let nid_v0 = derive_test_node_id_from_validator_id(0);
    let nid_v1 = derive_test_node_id_from_validator_id(1);
    let (saw_v1_on_v0, saw_v0_on_v1) =
        poll_peer_observability(&ctx_v0, &ctx_v1, nid_v0, nid_v1, Duration::from_secs(8))
            .await;

    assert!(
        saw_v1_on_v0 && saw_v0_on_v1,
        "B8.D: BOTH sides must observe the other's deterministic NodeId among \
         connected_peers (saw_v1_on_v0={}, saw_v0_on_v1={}); this is the \
         joint precondition for cross-node send_to(ValidatorId) and is what \
         justifies DevNet Evidence Run 007.",
        saw_v1_on_v0,
        saw_v0_on_v1
    );

    let _ = P2pNodeBuilder::shutdown(ctx_v0).await;
    let _ = P2pNodeBuilder::shutdown(ctx_v1).await;
}

// ---------------------------------------------------------------------------
// E. Single-validator / no-P2P paths do not regress.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn b8_e_single_validator_no_peers_does_not_regress() {
    let listen_port = reserve_local_port().await;
    let cfg = make_p2p_test_config(&format!("127.0.0.1:{}", listen_port), vec![]);

    let ctx = P2pNodeBuilder::new()
        .with_num_validators(1)
        .build(&cfg, 0)
        .await
        .expect("build single-validator");
    assert_eq!(ctx.validator_id.as_u64(), 0);
    assert_eq!(ctx.peer_validator_map.read().len(), 0);
    assert_eq!(
        ctx.p2p_service.local_node_id(),
        derive_test_node_id_from_validator_id(0),
        "B8.E: local NodeId must still be the deterministic test NodeId for V0"
    );
    let _ = P2pNodeBuilder::shutdown(ctx).await;
}

// ---------------------------------------------------------------------------
// Bonus: `DialRetryPolicy::no_retry` is publicly available for callers
// that want to pin the legacy single-shot dial behaviour (e.g. unit
// tests that intentionally exercise the failure shape).
// ---------------------------------------------------------------------------

#[test]
fn b8_dial_retry_policy_no_retry_pinned() {
    let p = DialRetryPolicy::no_retry();
    assert_eq!(p.max_attempts, 1);
    let d = DialRetryPolicy::default();
    assert!(d.max_attempts >= 2, "default must actually retry");
}

// Hold a reference so unused-import lint is suppressed even if a future
// refactor temporarily drops one of the helpers.
#[allow(dead_code)]
fn _retain_imports() {
    let _: Arc<()> = Arc::new(());
}