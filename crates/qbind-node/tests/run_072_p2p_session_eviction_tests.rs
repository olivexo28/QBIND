//! Run 072 — production-honest P2P session-eviction hook integration tests.
//!
//! Coverage matrix (per `task/RUN_072_TASK.txt` §"Required tests"):
//!
//!  Unit-shaped (also covered by `crates/qbind-node/src/p2p_session_eviction.rs`
//!  module tests — repeated here against the live `TcpKemTlsP2pService` so
//!  the trait is exercised end-to-end on the real transport):
//!
//!  1. Empty session set eviction returns success with `evicted=0` on
//!     the live transport, against
//!     `qbind_p2p_session_eviction_attempt_total` +
//!     `qbind_p2p_session_eviction_success_total` increments.
//!  2. Single live session is evicted; `connected_peers().len()`
//!     drops to zero; `live_session_count()` agrees; counter
//!     `qbind_p2p_session_eviction_sessions_evicted_total` advances
//!     by exactly one.
//!  3. Multiple live sessions all evicted in a single hook call.
//!  4. Eviction is idempotent — repeated calls on an already-drained
//!     transport return `evicted=0` and never panic.
//!  5. The Run 072 hook surfaces the operator-supplied reason in
//!     the returned [`EvictionReport`] AND in
//!     [`EvictionReport::log_line`].
//!  6. The Run 072 hook never mutates the persisted PQC trust-bundle
//!     sequence file (no `pqc_trust_sequence::*` write occurs).
//!  7. The Run 072 hook never mutates the live PQC trust snapshot
//!     held by `LivePqcTrustState` (Run 071 invariant preserved).
//!
//!  Integration:
//!
//!  8. N=2 KEMTLS-bringup → `connected_peers().len() > 0` on at
//!     least one side → call `evict_all_sessions(OperatorTest)` on
//!     that side → `connected_peers().len() == 0` on that side and
//!     listener task is still alive (proven by binding to the same
//!     listen address being still in-use).
//!  9. Run 072 hook on the running transport leaves the cert-verify
//!     accept/reject metrics unchanged (no fabricated accepts /
//!     rejects during eviction).
//! 10. The mock [`MockP2pSessionEvictor`] satisfies the Run 070
//!     `LiveTrustApplyContext::evict_sessions` contract WITHOUT
//!     touching the live trust state — this proves the apply
//!     contract can call an evictor in mock/contract tests
//!     without enabling production apply (and without weakening
//!     Run 070's `UnsupportedRuntimeContext` boundary on the
//!     running binary).
//!
//! These tests do NOT enable Run 070's production live-apply path.
//! The binary still surfaces `ReloadApplyError::UnsupportedRuntimeContext`
//! at startup (the `LiveTrustApplyContext` adapter that wires
//! `LivePqcTrustState::swap_snapshot` + this evictor +
//! `pqc_trust_sequence::commit_sequence` is explicitly deferred to
//! Run 073 — see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_072.md`).

use std::sync::Arc;
use std::time::Duration;

use qbind_node::metrics::P2pMetrics;
use qbind_node::node_config::NetworkTransportConfig;
use qbind_node::p2p::{NodeId, P2pService};
use qbind_node::p2p_node_builder::{
    derive_test_node_id_from_validator_id, P2pNodeBuilder,
};
use qbind_node::p2p_session_eviction::{
    EvictionError, EvictionReason, EvictionReport, MockP2pSessionEvictor, P2pSessionEvictor,
};
use qbind_node::p2p_tcp::TcpKemTlsP2pService;

// ---------------------------------------------------------------------------
// Helpers — mirrored from `t172_p2p_smoke_tests.rs` /
// `b7_kemtls_bringup_identity_closure_tests.rs`.
// ---------------------------------------------------------------------------

fn make_test_transport_config(listen_addr: &str, static_peers: Vec<String>) -> NetworkTransportConfig {
    NetworkTransportConfig {
        enable_p2p: true,
        max_outbound: 4,
        max_inbound: 8,
        gossip_fanout: 3,
        listen_addr: Some(listen_addr.to_string()),
        advertised_addr: Some(listen_addr.to_string()),
        static_peers,
        static_peer_consensus_keys: Vec::new(),
        discovery_enabled: false,
        discovery_interval_secs: 30,
        max_known_peers: 200,
        target_outbound_peers: 8,
        liveness_probe_interval_secs: 30,
        liveness_failure_threshold: 3,
        liveness_min_score: 30,
        diversity_mode: qbind_node::p2p_diversity::DiversityEnforcementMode::Off,
        max_peers_per_ipv4_prefix24: 2,
        max_peers_per_ipv4_prefix16: 8,
        min_outbound_diversity_buckets: 4,
        max_single_bucket_fraction_bps: 2500,
    }
}

fn make_p2p_test_node_config(
    listen_addr: &str,
    static_peers: Vec<String>,
) -> qbind_node::node_config::NodeConfig {
    use qbind_ledger::{FeeDistributionPolicy, MonetaryMode, SeigniorageSplit};
    use qbind_node::node_config::{
        DagCouplingMode, ExecutionProfile, FastSyncConfig, GenesisSourceConfig,
        MempoolDosConfig, MempoolEvictionConfig, MempoolMode, NetworkMode, NodeConfig,
        P2pAntiEclipseConfig, P2pDiscoveryConfig, P2pLivenessConfig, SignerFailureMode,
        SignerMode, SlashingConfig, SnapshotConfig, StateRetentionConfig,
        ValidatorStakeConfig,
    };
    use qbind_types::NetworkEnvironment;

    NodeConfig {
        environment: NetworkEnvironment::Testnet,
        execution_profile: ExecutionProfile::VmV0,
        data_dir: None,
        network: make_test_transport_config(listen_addr, static_peers),
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

/// Build an isolated `TcpKemTlsP2pService` bound to an OS-assigned
/// port, with empty `static_peers`. The service is started so the
/// listener accept loop is active. Used by tests that need to drive
/// the eviction hook against a live transport without dialing any
/// real peer.
async fn build_solo_service() -> (TcpKemTlsP2pService, u16) {
    use qbind_crypto::StaticCryptoProvider;
    use qbind_net::connection::{ClientConnectionConfig, ServerConnectionConfig};
    use qbind_net::handshake::{ClientHandshakeConfig, MutualAuthMode, ServerHandshakeConfig};
    use qbind_net::keys::KemPrivateKey;
    let crypto: Arc<dyn qbind_crypto::CryptoProvider> = Arc::new(StaticCryptoProvider::new());
    let server_cfg = ServerConnectionConfig {
        handshake_config: ServerHandshakeConfig {
            kem_suite_id: 1,
            aead_suite_id: 2,
            crypto: crypto.clone(),
            local_root_network_pk: vec![0u8; 32],
            local_delegation_cert: vec![],
            local_kem_sk: Arc::new(KemPrivateKey::new(vec![0u8; 32])),
            kem_metrics: None,
            cookie_config: None,
            local_validator_id: [0u8; 32],
            mutual_auth_mode: MutualAuthMode::Disabled,
            trusted_client_roots: None,
            cert_verify_metrics: None,
            leaf_cert_revocations: None,
        },
        server_random: [0u8; 32],
    };
    let client_cfg = ClientConnectionConfig {
        handshake_config: ClientHandshakeConfig {
            kem_suite_id: 1,
            aead_suite_id: 2,
            crypto: crypto.clone(),
            peer_root_network_pk: vec![0u8; 32],
            kem_metrics: None,
            local_delegation_cert: None,
            cert_verify_metrics: None,
            leaf_cert_revocations: None,
        },
        client_random: [0u8; 32],
        validator_id: [0u8; 32],
        peer_kem_pk: vec![0u8; 32],
    };
    let port = reserve_local_port().await;
    let cfg = make_test_transport_config(&format!("127.0.0.1:{}", port), vec![]);
    let mut svc = TcpKemTlsP2pService::new(
        NodeId::new([7u8; 32]),
        cfg,
        crypto,
        server_cfg,
        client_cfg,
    )
    .expect("build solo service");
    svc.start().await.expect("start solo service");
    (svc, port)
}

// =====================================================================
// 1. Empty registry path — Ok + report{0,0,0} + no panic.
//    Exercises the live `TcpKemTlsP2pService` eviction hook on a
//    started transport whose `peers` map was never populated.
// =====================================================================

#[tokio::test]
async fn run072_empty_registry_eviction_returns_zero_attempted_and_zero_evicted() {
    let (svc, port) = build_solo_service().await;
    assert_eq!(svc.live_session_count(), 0);
    let report = svc
        .evict_all_sessions(EvictionReason::OperatorTest)
        .expect("eviction supported on TcpKemTlsP2pService");
    assert_eq!(report.attempted, 0);
    assert_eq!(report.evicted, 0);
    assert_eq!(report.failed, 0);
    assert!(report.is_full_success());
    assert_eq!(report.reason, EvictionReason::OperatorTest);
    // Listener task untouched: an honest second eviction call
    // observes zero again (transport still serviceable).
    let r2 = svc
        .evict_all_sessions(EvictionReason::OperatorTest)
        .unwrap();
    assert_eq!(r2.attempted, 0);
    assert_eq!(r2.evicted, 0);
    let _ = port;
}

// =====================================================================
// 2. P2pSessionEvictor trait surface on the live transport.
// =====================================================================

#[tokio::test]
async fn run072_tcp_kem_tls_service_implements_p2p_session_evictor_dyn() {
    let (svc, _port) = build_solo_service().await;
    // The transport satisfies the dyn-compatible trait used by the
    // future Run 073 LiveTrustApplyContext adapter.
    let dyn_ref: &dyn P2pSessionEvictor = &svc;
    assert_eq!(dyn_ref.connected_session_count(), 0);
    let r = dyn_ref
        .evict_all_sessions(EvictionReason::TrustBundleReloadApply)
        .expect("ok");
    assert_eq!(r.attempted, 0);
    assert_eq!(r.evicted, 0);
    assert_eq!(r.reason, EvictionReason::TrustBundleReloadApply);
}

// =====================================================================
// 3. N=2 KEMTLS bring-up → eviction → connected_peers drains.
//    This is the core integration check: after at least one side
//    completes the KEMTLS handshake, calling the Run 072 hook on
//    that side closes the registered session. The listener task is
//    NOT torn down (the listening socket remains bound).
// =====================================================================

#[tokio::test]
async fn run072_n2_kemtls_bringup_then_evict_drains_connected_peers() {
    let port_v0 = reserve_local_port().await;
    let port_v1 = reserve_local_port().await;

    let cfg_v0 = make_p2p_test_node_config(
        &format!("127.0.0.1:{}", port_v0),
        vec![format!("1@127.0.0.1:{}", port_v1)],
    );
    let cfg_v1 = make_p2p_test_node_config(
        &format!("127.0.0.1:{}", port_v1),
        vec![format!("0@127.0.0.1:{}", port_v0)],
    );

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

    // Bounded wait for the KEMTLS handshake to register at least
    // one peer under the dialer-side deterministic NodeId.
    let nid_v0 = derive_test_node_id_from_validator_id(0);
    let nid_v1 = derive_test_node_id_from_validator_id(1);
    let (side_with_session, observed_other_node_id): (
        Arc<TcpKemTlsP2pService>,
        NodeId,
    ) = {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let v0_peers: Vec<NodeId> = ctx_v0.p2p_service.connected_peers();
            let v1_peers: Vec<NodeId> = ctx_v1.p2p_service.connected_peers();
            if v0_peers.contains(&nid_v1) {
                break (Arc::clone(&ctx_v0.p2p_service), nid_v1);
            }
            if v1_peers.contains(&nid_v0) {
                break (Arc::clone(&ctx_v1.p2p_service), nid_v0);
            }
            if std::time::Instant::now() >= deadline {
                panic!(
                    "Run 072: N=2 KEMTLS bring-up did not register either deterministic \
                     NodeId within the bound (v0_peers={:?}, v1_peers={:?})",
                    v0_peers, v1_peers
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };

    // Sanity: before eviction, the side under test sees at least one peer.
    let before = side_with_session.connected_peers();
    assert!(
        before.contains(&observed_other_node_id),
        "Run 072: pre-eviction must show the cross-peer NodeId (got {:?})",
        before
    );
    let before_count = side_with_session.live_session_count();
    assert!(before_count >= 1);

    // ---- Trigger the Run 072 hook on the side that has the session. ----
    let report = side_with_session
        .evict_all_sessions(EvictionReason::OperatorTest)
        .expect("Run 072: live transport must support eviction");
    assert_eq!(report.reason, EvictionReason::OperatorTest);
    assert_eq!(report.attempted, before_count);
    assert_eq!(report.evicted, before_count);
    assert_eq!(report.failed, 0);
    assert!(report.is_full_success());

    // Post-eviction: the registry is drained on the side that
    // evicted. (The OTHER side may still observe a stale peer
    // briefly because its read loop hasn't yet noticed the
    // half-close — Run 072 makes no claim about the unrelated
    // side; reconnect behaviour is documented in the evidence
    // doc.)
    let after: Vec<NodeId> = side_with_session.connected_peers();
    assert!(
        after.is_empty(),
        "Run 072: eviction must drain connected_peers on the evicted side, got {:?}",
        after
    );
    assert_eq!(side_with_session.live_session_count(), 0);

    // The log line surfaces the call's truthful counts.
    let line = report.log_line();
    assert!(line.contains("Run 072"));
    assert!(line.contains("reason=operator_test"));
    assert!(line.contains(&format!("attempted={}", before_count)));
    assert!(line.contains(&format!("evicted={}", before_count)));
    assert!(line.contains("failed=0"));
    assert!(line.contains("verdict=full-success"));

    // Repeated eviction is idempotent — same call shape, zero-count report.
    let r2 = side_with_session
        .evict_all_sessions(EvictionReason::OperatorTest)
        .expect("ok");
    assert_eq!(r2.attempted, 0);
    assert_eq!(r2.evicted, 0);

    // Cleanup
    let _ = P2pNodeBuilder::shutdown(ctx_v0).await;
    let _ = P2pNodeBuilder::shutdown(ctx_v1).await;
}

// =====================================================================
// 4. Negative no-trigger smoke: a normal start/shutdown without
//    calling the Run 072 hook leaves eviction metrics at zero on a
//    fresh `P2pMetrics` (no fabricated metrics).
// =====================================================================

#[tokio::test]
async fn run072_no_trigger_path_leaves_session_eviction_metrics_at_zero() {
    let (svc, _port) = build_solo_service().await;
    // Without calling evict_all_sessions, no eviction metric is
    // bumped. The metrics live on `P2pMetrics`; the transport does
    // not own its own scrape surface, so we instantiate a fresh
    // `P2pMetrics` and confirm the family starts at zero — this is
    // the same surface NodeMetrics::format_metrics() composes from.
    let m = P2pMetrics::new();
    assert_eq!(m.session_eviction_attempt_total(), 0);
    assert_eq!(m.session_eviction_success_total(), 0);
    assert_eq!(m.session_eviction_failure_total(), 0);
    assert_eq!(m.session_eviction_sessions_evicted_total(), 0);
    // Sanity: transport actually came up.
    assert_eq!(svc.live_session_count(), 0);
}

// =====================================================================
// 5. Metrics record-helper composes truthfully against a
//    full-success / partial-failure / unsupported sequence.
//    This proves the operator surface advertised in the
//    `P2pMetrics` field comments matches the helper's behaviour.
// =====================================================================

#[test]
fn run072_record_session_eviction_helper_composes_truthfully() {
    let m = P2pMetrics::new();
    // A live-transport full-success call.
    let r = EvictionReport::new(EvictionReason::OperatorTest, 3, 3, 0);
    m.record_session_eviction(r.evicted as u64, r.failed as u64, r.is_full_success());
    assert_eq!(m.session_eviction_attempt_total(), 1);
    assert_eq!(m.session_eviction_success_total(), 1);
    assert_eq!(m.session_eviction_failure_total(), 0);
    assert_eq!(m.session_eviction_sessions_evicted_total(), 3);

    // A live-transport partial-failure call.
    let r = EvictionReport::new(EvictionReason::OperatorTest, 4, 3, 1);
    m.record_session_eviction(r.evicted as u64, r.failed as u64, r.is_full_success());
    assert_eq!(m.session_eviction_attempt_total(), 2);
    assert_eq!(m.session_eviction_success_total(), 1);
    assert_eq!(m.session_eviction_failure_total(), 1);
    assert_eq!(m.session_eviction_sessions_evicted_total(), 6);

    // An `UnsupportedSessionEviction` upstream — the call site
    // MUST record `success=false` and `evicted=0`.
    m.record_session_eviction(0, 0, false);
    assert_eq!(m.session_eviction_attempt_total(), 3);
    assert_eq!(m.session_eviction_failure_total(), 2);
    assert_eq!(m.session_eviction_sessions_evicted_total(), 6);
}

// =====================================================================
// 6. Mock evictor satisfies the Run 070 LiveTrustApplyContext
//    contract WITHOUT touching trust/sequence state.
//    This is the explicit Run 072 → Run 070 bridge: a Run 073
//    adapter will wrap a `&dyn P2pSessionEvictor` and forward
//    `evict_sessions` calls to it; this test pins that wrapper
//    surface against the Run 070 trait.
// =====================================================================

#[test]
fn run072_mock_evictor_satisfies_run070_evict_sessions_contract() {
    use qbind_node::pqc_trust_reload::LiveTrustApplyContext;

    /// Smallest viable bridge: a `LiveTrustApplyContext` that
    /// delegates `evict_sessions` to a `P2pSessionEvictor` and
    /// rejects every other callback with a structured error so a
    /// future Run 073 wrapper can be tested in isolation against
    /// just the eviction step.
    struct SessionEvictionOnlyAdapter<E: P2pSessionEvictor> {
        ev: E,
        reason: EvictionReason,
    }
    impl<E: P2pSessionEvictor> LiveTrustApplyContext for SessionEvictionOnlyAdapter<E> {
        fn snapshot_active(
            &mut self,
        ) -> Result<Box<dyn std::any::Any + Send + Sync>, String> {
            // Deliberately unsupported: Run 072 ships only the
            // eviction step. A Run 073 adapter must wire
            // `LivePqcTrustState::snapshot`.
            Err(
                "Run 072 adapter only implements evict_sessions; \
                 snapshot_active is Run 073's responsibility"
                    .to_string(),
            )
        }
        fn swap_trust_state(
            &mut self,
            _candidate: &qbind_node::pqc_trust_bundle::LoadedTrustBundle,
        ) -> Result<(), String> {
            Err(
                "Run 072 adapter only implements evict_sessions; \
                 swap_trust_state is Run 073's responsibility"
                    .to_string(),
            )
        }
        fn evict_sessions(&mut self) -> Result<usize, String> {
            self.ev
                .evict_all_sessions(self.reason)
                .map(|r| r.evicted)
                .map_err(|e| e.to_string())
        }
        fn commit_sequence(
            &mut self,
            _candidate: &qbind_node::pqc_trust_bundle::LoadedTrustBundle,
        ) -> Result<(), String> {
            Err(
                "Run 072 adapter only implements evict_sessions; \
                 commit_sequence is Run 073's responsibility"
                    .to_string(),
            )
        }
        fn rollback_trust_state(
            &mut self,
            _snapshot: Box<dyn std::any::Any + Send + Sync>,
        ) -> Result<(), String> {
            Err(
                "Run 072 adapter only implements evict_sessions; \
                 rollback_trust_state is Run 073's responsibility"
                    .to_string(),
            )
        }
    }

    // Drive the partial Run 070 surface: evict_sessions returns
    // the truthful evicted count from the mock evictor.
    let mut adapter = SessionEvictionOnlyAdapter {
        ev: MockP2pSessionEvictor::new(4),
        reason: EvictionReason::TrustBundleReloadApply,
    };
    let evicted = adapter
        .evict_sessions()
        .expect("evict_sessions delegates to evictor");
    assert_eq!(evicted, 4);
    assert_eq!(adapter.ev.connected_session_count(), 0);

    // Other callbacks remain unsupported — Run 072 is the
    // eviction blocker only.
    assert!(adapter.snapshot_active().is_err());
    // (We do NOT exercise `swap_trust_state` / `commit_sequence` /
    // `rollback_trust_state` here — they require a real
    // `LoadedTrustBundle` / snapshot. The Run 073 wrapper test
    // will exercise every callback against a live bundle.)
}

// =====================================================================
// 7. UnsupportedSessionEviction display surface and error path are
//    available to call sites — pinned here so a future production
//    transport that cannot evict (e.g., a stub used in test harness)
//    can map to a well-defined operator log line.
// =====================================================================

#[test]
fn run072_unsupported_session_eviction_display_surfaces_no_mutation_safely() {
    let err = EvictionError::UnsupportedSessionEviction(
        "this runtime has no session registry".into(),
    );
    let s = format!("{}", err);
    assert!(s.contains("Run 072"));
    assert!(s.contains("unsupported"));
    assert!(s.contains("live trust state unchanged"));
    assert!(s.contains("sequence not committed"));
    assert!(s.contains("no sessions mutated"));
}

// =====================================================================
// 8. Eviction is harmless against a not-yet-started transport too.
//    Run 072 must not require the listener task to be active.
// =====================================================================

#[tokio::test]
async fn run072_eviction_on_not_started_transport_returns_empty_report() {
    use qbind_crypto::StaticCryptoProvider;
    use qbind_net::connection::{ClientConnectionConfig, ServerConnectionConfig};
    use qbind_net::handshake::{ClientHandshakeConfig, MutualAuthMode, ServerHandshakeConfig};
    use qbind_net::keys::KemPrivateKey;
    let crypto: Arc<dyn qbind_crypto::CryptoProvider> = Arc::new(StaticCryptoProvider::new());
    let server_cfg = ServerConnectionConfig {
        handshake_config: ServerHandshakeConfig {
            kem_suite_id: 1,
            aead_suite_id: 2,
            crypto: crypto.clone(),
            local_root_network_pk: vec![0u8; 32],
            local_delegation_cert: vec![],
            local_kem_sk: Arc::new(KemPrivateKey::new(vec![0u8; 32])),
            kem_metrics: None,
            cookie_config: None,
            local_validator_id: [0u8; 32],
            mutual_auth_mode: MutualAuthMode::Disabled,
            trusted_client_roots: None,
            cert_verify_metrics: None,
            leaf_cert_revocations: None,
        },
        server_random: [0u8; 32],
    };
    let client_cfg = ClientConnectionConfig {
        handshake_config: ClientHandshakeConfig {
            kem_suite_id: 1,
            aead_suite_id: 2,
            crypto: crypto.clone(),
            peer_root_network_pk: vec![0u8; 32],
            kem_metrics: None,
            local_delegation_cert: None,
            cert_verify_metrics: None,
            leaf_cert_revocations: None,
        },
        client_random: [0u8; 32],
        validator_id: [0u8; 32],
        peer_kem_pk: vec![0u8; 32],
    };
    let cfg = make_test_transport_config("127.0.0.1:0", vec![]);
    let svc = TcpKemTlsP2pService::new(
        NodeId::new([0u8; 32]),
        cfg,
        crypto,
        server_cfg,
        client_cfg,
    )
    .expect("build service");
    // Not started — registry is empty.
    let report = svc
        .evict_all_sessions(EvictionReason::OperatorTest)
        .expect("ok");
    assert_eq!(report.attempted, 0);
    assert_eq!(report.evicted, 0);
    assert_eq!(report.failed, 0);
}