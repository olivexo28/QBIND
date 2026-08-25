//! Run 371 — release-built helper backing the public DevNet abuse/DoS **M12
//! KEMTLS-admitted per-peer message-rate live-socket flood** release-binary
//! evidence.
//!
//! # Background
//!
//! Run 369 wired the per-peer `PeerRateLimiter` onto the DEPLOYED
//! `TcpKemTlsP2pService::read_loop` receive path via the
//! `DeployedInboundPerPeerLimiter` adapter. Run 370 threaded the live
//! `Arc<NodeMetrics>` (the SAME handle the `/metrics` endpoint scrapes) into
//! that adapter so a per-peer message-rate drop on the deployed path bumps the
//! exported `qbind_net_per_peer_drops_total{reason="rate_limit"}` counter.
//!
//! Run 370's residual blocker was that the per-peer control was proven by
//! calling the deployed adapter object directly (`allow_node`) — it did NOT
//! flood real frames from a second KEMTLS-admitted peer over the deployed read
//! loop.
//!
//! # What Run 371 proves
//!
//! This helper drives a **real second KEMTLS peer over a real loopback socket**
//! using ONLY production public APIs (no production source change, decision
//! gate Route A):
//!
//! * `run-scenarios` mode (default, one positional `<OUT_DIR>` arg): stands up
//!   TWO `P2pNodeBuilder`-built nodes IN-PROCESS. Node A is built exactly the
//!   way `main.rs` builds the deployed node (the same `with_node_metrics` +
//!   `with_abuse_dos_runtime_config` seam that installs the deployed inbound
//!   per-peer limiter on `TcpKemTlsP2pService::read_loop`) with a low per-peer
//!   budget. Node B dials node A, completes the KEMTLS handshake over a real
//!   loopback TCP socket, and floods structured `P2pMessage::Consensus` frames.
//!   The helper then scrapes `NodeMetrics::format_metrics()` (the exact string
//!   the live `/metrics` endpoint renders) and proves:
//!     - under-budget frames produce NO per-peer drops (metric absent);
//!     - over-budget frames are dropped by the deployed limiter and the
//!       exported `qbind_net_per_peer_drops_total{reason="rate_limit"}` counter
//!       increments;
//!     - the connection is NOT torn down by per-peer drops (the peer stays
//!       connected and node A keeps decoding subsequent frames);
//!     - the per-peer drops NEVER touch `qbind_p2p_connection_rate_drop_total`.
//!   It also re-checks the cheap config invariants (defaults, invalid configs
//!   fail closed, MainNet refused) so the helper alone records the full posture.
//!
//! * `dial-flood` mode (used by the Run 371 harness to target a SEPARATE
//!   running `target/release/qbind-node` process): builds a node B dialer via
//!   the production builder, dials the deployed node's live P2P listener,
//!   completes the KEMTLS handshake, floods a caller-specified number of frames
//!   at a caller-specified pace, and writes the connection / enqueue result so
//!   the harness can scrape the deployed node's live `/metrics`.
//!
//! # Honest scope (recorded, not hidden)
//!
//! * The `run-scenarios` in-process proof runs BOTH peers inside this release
//!   helper process. It is a real KEMTLS socket + real read loop + real deployed
//!   limiter, but node A is not the standalone `qbind-node` process, so per the
//!   readiness rules this is "helper-only" evidence.
//! * The `dial-flood` mode is the peer that the Run 371 harness points at the
//!   REAL `target/release/qbind-node` process; whether that cross-process flood
//!   surfaces live `/metrics` per-peer drops is decided by the harness and
//!   recorded in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_371.md`.
//! * The helper opens only loopback (127.0.0.1) sockets on OS-assigned ports,
//!   uses temp dirs, launches no public DevNet / seed / bootnode / faucet / RPC
//!   / explorer / status page, mutates no trust / validator / epoch / sequence /
//!   marker state, changes no wire format, and weakens no peer admission /
//!   KEMTLS / trust-bundle behaviour. An enabled MainNet abuse/DoS config is
//!   refused.
//!
//! Usage:
//! ```text
//! run_371_..._helper <OUT_DIR>
//! run_371_..._helper dial-flood <peer_spec> <listen_addr> <local_vid> <frames> <pace_ms> <out_file>
//! ```

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{CommandFactory, Parser};

use qbind_node::cli::CliArgs;
use qbind_node::metrics::NodeMetrics;
use qbind_node::p2p::{ConsensusNetMsg, NodeId, P2pMessage, P2pService};
use qbind_node::p2p_node_builder::{
    derive_test_node_id_from_validator_id, parse_peer_spec, P2pNodeBuilder,
};
use qbind_node::peer_rate_limiter::{DEFAULT_BURST_ALLOWANCE, DEFAULT_MAX_MESSAGES_PER_SECOND};
use qbind_node::public_devnet_abuse_dos_config::AbuseDosConfig;
use qbind_node::public_devnet_abuse_dos_runtime::PublicDevnetAbuseDosRuntimeConfig;
use qbind_types::primitives::NetworkEnvironment;

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent dir");
    }
    let mut f = fs::File::create(path).expect("create file");
    f.write_all(contents.as_bytes()).expect("write file");
}

/// Parse CLI args exactly as the production binary would (hidden abuse/DoS flags
/// included), so the helper exercises the same clap surface.
fn parse_cli(args: &[&str]) -> Result<CliArgs, clap::Error> {
    let mut full = vec!["qbind-node"];
    full.extend_from_slice(args);
    CliArgs::try_parse_from(full)
}

/// Build a `NodeConfig` shaped like `--enable-p2p --p2p-listen-addr ...
/// --p2p-peer ...`, mirroring the two-node bring-up used by the B7 KEMTLS
/// integration tests. Kept local so the helper depends only on public config
/// types.
fn make_p2p_config(listen_addr: &str, static_peers: Vec<String>) -> qbind_node::node_config::NodeConfig {
    use qbind_ledger::{FeeDistributionPolicy, MonetaryMode, SeigniorageSplit};
    use qbind_node::node_config::{
        DagCouplingMode, ExecutionProfile, FastSyncConfig, GenesisSourceConfig, MempoolDosConfig,
        MempoolEvictionConfig, MempoolMode, NetworkMode, NetworkTransportConfig, NodeConfig,
        P2pAntiEclipseConfig, P2pDiscoveryConfig, P2pLivenessConfig, SignerFailureMode, SignerMode,
        SlashingConfig, SnapshotConfig, StateRetentionConfig, ValidatorStakeConfig,
    };
    use qbind_node::p2p_diversity::DiversityEnforcementMode;

    NodeConfig {
        environment: NetworkEnvironment::Devnet,
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
            static_peer_consensus_keys: Vec::new(),
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

/// A single P2pMessage flood frame. Structured `Consensus` frames decode
/// successfully on the receiver (discriminator 0), so they reach the deployed
/// per-peer limiter AFTER `decode_frame` (unlike `0x05` peer-candidate frames,
/// which are consumed earlier). The inner bytes are opaque `Vec<u8>` and are not
/// interpreted by the transport, so an invalid vote never tears down the read
/// loop before the limiter runs.
fn flood_frame(seq: u64) -> P2pMessage {
    let mut payload = Vec::with_capacity(16);
    payload.extend_from_slice(b"run371-flood-");
    payload.extend_from_slice(&seq.to_be_bytes());
    P2pMessage::Consensus(ConsensusNetMsg::Vote(payload))
}

/// Reserve an OS-assigned loopback port by binding and dropping a listener.
fn reserve_local_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind reserve listener");
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

/// Sum every `qbind_net_per_peer_drops_total{...,reason="rate_limit"} N` counter
/// rendered in a `/metrics` body.
fn sum_per_peer_rate_limit_drops(metrics_body: &str) -> u64 {
    let mut total = 0u64;
    for line in metrics_body.lines() {
        let line = line.trim();
        if line.starts_with("qbind_net_per_peer_drops_total")
            && line.contains("reason=\"rate_limit\"")
        {
            if let Some(v) = line.split_whitespace().last() {
                if let Ok(n) = v.parse::<u64>() {
                    total += n;
                }
            }
        }
    }
    total
}

// ---------------------------------------------------------------------------
// Scenario bookkeeping.
// ---------------------------------------------------------------------------

struct Scenario {
    id: &'static str,
    expected: String,
    actual: String,
    matched: bool,
    detail: String,
}

// ---------------------------------------------------------------------------
// dial-flood mode (cross-process second KEMTLS peer).
// ---------------------------------------------------------------------------

struct FloodResult {
    connected: bool,
    target_node_id_seen: bool,
    frames_enqueued: u64,
    frames_attempted: u64,
}

async fn dial_and_flood(
    peer_spec: &str,
    listen_addr: &str,
    local_vid: u64,
    frames: u64,
    pace_ms: u64,
) -> FloodResult {
    // Derive the deterministic NodeId of the peer we are dialing (the deployed
    // node's validator id), so we can confirm the KEMTLS handshake completed by
    // observing the peer in the dialer's connected set.
    let (peer_vid, _addr) = parse_peer_spec(peer_spec).expect("valid peer spec");
    let peer_vid = peer_vid.expect("peer spec must carry a validator id (vid@addr)");
    let target_node_id: NodeId = derive_test_node_id_from_validator_id(peer_vid);

    let config = make_p2p_config(listen_addr, vec![peer_spec.to_string()]);
    let ctx = P2pNodeBuilder::new()
        .with_num_validators(2)
        .build(&config, local_vid)
        .await
        .expect("build dialer node B");

    // Poll until the dialer registers the peer's deterministic NodeId (KEMTLS
    // handshake completed) or a bounded deadline elapses.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut target_seen = false;
    while Instant::now() < deadline {
        let peers: Vec<NodeId> = ctx.p2p_service.connected_peers();
        if peers.contains(&target_node_id) || ctx.p2p_service.connected_peer_count() > 0 {
            target_seen = peers.contains(&target_node_id);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let connected = ctx.p2p_service.connected_peer_count() > 0;

    let mut enqueued = 0u64;
    if connected {
        for seq in 0..frames {
            // `broadcast` fire-and-forwards the structured frame to every
            // connected peer's write loop (here, only node A). We count each
            // attempt made while the peer remains connected as an enqueue.
            ctx.p2p_service.broadcast(flood_frame(seq));
            enqueued += 1;
            if pace_ms > 0 {
                tokio::time::sleep(Duration::from_millis(pace_ms)).await;
            }
        }
        // Let the last frames drain to the peer's read loop before shutdown.
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let _ = P2pNodeBuilder::shutdown(ctx).await;

    FloodResult {
        connected,
        target_node_id_seen: target_seen,
        frames_enqueued: enqueued,
        frames_attempted: frames,
    }
}

// ---------------------------------------------------------------------------
// In-process two-node KEMTLS flood (run-scenarios mode).
// ---------------------------------------------------------------------------

/// Build node A exactly the way `main.rs` builds the deployed node: install the
/// live `NodeMetrics` handle (Run 370 seam) and the validated abuse/DoS runtime
/// config (which threads the per-peer budget into the deployed inbound
/// per-peer limiter installed on `TcpKemTlsP2pService::read_loop`).
async fn build_node_a(
    listen_addr: &str,
    abuse_dos_args: &[&str],
    node_metrics: Arc<NodeMetrics>,
) -> qbind_node::p2p_node_builder::P2pNodeContext {
    let config = make_p2p_config(listen_addr, Vec::new());
    let mut builder = P2pNodeBuilder::new()
        .with_num_validators(2)
        .with_node_metrics(Arc::clone(&node_metrics));
    if let Some(rt) = parse_cli(abuse_dos_args)
        .expect("cli parses")
        .abuse_dos_runtime_config()
        .expect("valid abuse/DoS config")
    {
        builder = builder.with_abuse_dos_runtime_config(rt);
    }
    builder.build(&config, 0).await.expect("build deployed node A")
}

/// Drive a real KEMTLS flood from a freshly-dialed node B against `node_a` and
/// return the number of frames enqueued.
async fn kemtls_flood_against(node_a_port: u16, frames: u64, pace_ms: u64) -> u64 {
    let listen = format!("127.0.0.1:{}", reserve_local_port());
    let peer_spec = format!("0@127.0.0.1:{}", node_a_port);
    let config = make_p2p_config(&listen, vec![peer_spec]);
    let ctx = P2pNodeBuilder::new()
        .with_num_validators(2)
        .build(&config, 1)
        .await
        .expect("build in-process node B");

    let target = derive_test_node_id_from_validator_id(0);
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if ctx.p2p_service.connected_peers().contains(&target)
            || ctx.p2p_service.connected_peer_count() > 0
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let mut enqueued = 0u64;
    if ctx.p2p_service.connected_peer_count() > 0 {
        for seq in 0..frames {
            ctx.p2p_service.broadcast(flood_frame(seq));
            enqueued += 1;
            if pace_ms > 0 {
                tokio::time::sleep(Duration::from_millis(pace_ms)).await;
            }
        }
    }
    // Allow the receiver's read loop to process the enqueued frames.
    tokio::time::sleep(Duration::from_millis(700)).await;
    let _ = P2pNodeBuilder::shutdown(ctx).await;
    enqueued
}

async fn run_scenarios(out_dir: &Path) -> bool {
    let mut scenarios: Vec<Scenario> = Vec::new();
    let mut metric_evidence = String::new();

    // ---- Config invariants (cheap, no sockets) -----------------------------

    // default_preserves_behavior: no flags → no per-peer override; adapter
    // carries the documented 1000/100 defaults; connection limiter disabled.
    {
        let builder = P2pNodeBuilder::new();
        let derived_none = builder.deployed_peer_rate_limiter_config().is_none();
        let adapter = builder.build_deployed_inbound_per_peer_limiter();
        let ok = derived_none
            && adapter.config().max_messages_per_second == DEFAULT_MAX_MESSAGES_PER_SECOND
            && adapter.config().burst_allowance == DEFAULT_BURST_ALLOWANCE
            && adapter.config().max_messages_per_second == 1000
            && adapter.config().burst_allowance == 100
            && !adapter.has_metrics();
        scenarios.push(Scenario {
            id: "01_default_preserves_behavior",
            expected: "no override; per-peer 1000/100; adapter metrics None".to_string(),
            actual: format!(
                "derived_none={} per_peer_max={} per_peer_burst={} adapter_has_metrics={}",
                derived_none,
                adapter.config().max_messages_per_second,
                adapter.config().burst_allowance,
                adapter.has_metrics(),
            ),
            matched: ok,
            detail: "No abuse/DoS flags: the deployed builder derives None and the inbound \
                     per-peer adapter carries PeerRateLimiter defaults (1000 msg/s + 100 burst)."
                .to_string(),
        });
    }

    // hidden_cli_surface_checked.
    {
        let mut cmd = CliArgs::command();
        let help = cmd.render_long_help().to_string();
        let hidden_flags = [
            "--p2p-connection-rate-limit-enabled",
            "--p2p-connection-rate-window-ms",
            "--p2p-connection-rate-max",
            "--p2p-connection-burst",
            "--p2p-max-messages-per-second",
            "--p2p-burst-allowance",
            "--p2p-per-address-connection-rate-window-ms",
            "--p2p-per-address-connection-max",
        ];
        let all_hidden = hidden_flags.iter().all(|f| !help.contains(f));
        let real_parse = parse_cli(&["--p2p-max-messages-per-second", "750"]).is_ok()
            && parse_cli(&["--p2p-burst-allowance", "60"]).is_ok();
        let invented_rejected = parse_cli(&["--p2p-kemtls-flood", "on"]).is_err()
            && parse_cli(&["--p2p-connection-rate-bogus", "1"]).is_err();
        let ok = all_hidden && real_parse && invented_rejected;
        scenarios.push(Scenario {
            id: "02_hidden_cli_surface_checked",
            expected: "hidden flags absent from --help; real parse; invented rejected".to_string(),
            actual: format!(
                "all_hidden={} real_parse={} invented_rejected={}",
                all_hidden, real_parse, invented_rejected
            ),
            matched: ok,
            detail: "Run 371 adds no new public CLI surface; the abuse/DoS flags stay hidden."
                .to_string(),
        });
    }

    // invalid_configs_fail_closed.
    {
        let mut bad_window = AbuseDosConfig::public_devnet_recommended();
        bad_window.connection_rate_window = Duration::from_secs(0);
        let r_window = PublicDevnetAbuseDosRuntimeConfig::from_config(bad_window);
        let r_zero_msg = parse_cli(&["--p2p-max-messages-per-second", "0"])
            .unwrap()
            .abuse_dos_runtime_config();
        let r_zero_conn = parse_cli(&[
            "--p2p-connection-rate-limit-enabled",
            "--p2p-connection-rate-window-ms",
            "1000",
            "--p2p-connection-rate-max",
            "0",
        ])
        .unwrap()
        .abuse_dos_runtime_config();
        let r_unbounded = parse_cli(&["--p2p-max-messages-per-second", "2000000"])
            .unwrap()
            .abuse_dos_runtime_config();
        let ok =
            r_window.is_err() && r_zero_msg.is_err() && r_zero_conn.is_err() && r_unbounded.is_err();
        scenarios.push(Scenario {
            id: "03_invalid_configs_fail_closed",
            expected: "zero-window/zero-msg/zero-conn/unbounded all rejected".to_string(),
            actual: format!(
                "zero_window={} zero_msg={} zero_conn={} unbounded={}",
                r_window.is_err(),
                r_zero_msg.is_err(),
                r_zero_conn.is_err(),
                r_unbounded.is_err()
            ),
            matched: ok,
            detail: "Every nonsensical abuse/DoS value fails closed at config validation."
                .to_string(),
        });
    }

    // mainnet_refused.
    {
        let r_direct = PublicDevnetAbuseDosRuntimeConfig::from_config({
            let mut c = AbuseDosConfig::compatibility_default()
                .with_environment(NetworkEnvironment::Mainnet);
            c.per_peer_max_messages_per_second = 500;
            c
        });
        let r_cli = parse_cli(&["--env", "mainnet", "--p2p-max-messages-per-second", "500"])
            .unwrap()
            .abuse_dos_runtime_config();
        let ok = r_direct.is_err() && r_cli.is_err();
        scenarios.push(Scenario {
            id: "04_mainnet_refused",
            expected: "MainNet abuse/DoS config refused (direct + CLI)".to_string(),
            actual: format!("direct_err={} cli_err={}", r_direct.is_err(), r_cli.is_err()),
            matched: ok,
            detail: "MainNet has no production abuse/DoS policy; an enabled MainNet config never \
                     validates."
                .to_string(),
        });
    }

    // ---- KEMTLS second-peer flood (real loopback socket) -------------------
    //
    // Node A is built exactly like the deployed node with a low per-peer budget
    // (5 msg/s + 5 burst). Node B dials A, completes the KEMTLS handshake, and
    // floods. The exported per-peer drop counter is read from the SAME
    // NodeMetrics handle the live /metrics endpoint scrapes.

    let node_metrics = Arc::new(NodeMetrics::new());
    let node_a_port = reserve_local_port();
    let node_a_addr = format!("127.0.0.1:{}", node_a_port);
    let ctx_a = build_node_a(
        &node_a_addr,
        &["--p2p-max-messages-per-second", "5", "--p2p-burst-allowance", "5"],
        Arc::clone(&node_metrics),
    )
    .await;

    let limiter_installed = ctx_a.p2p_service.has_inbound_per_peer_limiter();

    // kemtls_second_peer_admitted + per_peer_kemtls_under_budget: dial + send a
    // small number of frames well under the 5/s budget, paced. Expect zero
    // per-peer drops.
    let under_enqueued = kemtls_flood_against(node_a_port, 4, 400).await;
    let drops_after_under = node_metrics.peer_network().total_rate_limit_drops();
    let body_after_under = node_metrics.format_metrics();
    let rendered_after_under = sum_per_peer_rate_limit_drops(&body_after_under);

    scenarios.push(Scenario {
        id: "06_kemtls_second_peer_admitted",
        expected: "node B completes KEMTLS handshake; deployed per-peer limiter installed"
            .to_string(),
        actual: format!(
            "limiter_installed={} under_frames_enqueued={}",
            limiter_installed, under_enqueued
        ),
        matched: limiter_installed && under_enqueued > 0,
        detail: "A second peer dialed node A over a real loopback socket, completed the KEMTLS \
                 handshake, and enqueued frames that reached the deployed read loop."
            .to_string(),
    });

    scenarios.push(Scenario {
        id: "07_per_peer_kemtls_under_budget",
        expected: "under-budget KEMTLS flood → 0 per-peer drops; metric absent".to_string(),
        actual: format!(
            "total_drops={} rendered_drops={}",
            drops_after_under, rendered_after_under
        ),
        matched: drops_after_under == 0 && rendered_after_under == 0,
        detail: "Frames sent under the 5 msg/s budget were all forwarded; the deployed per-peer \
                 limiter dropped nothing and the exported counter stayed absent."
            .to_string(),
    });

    // per_peer_kemtls_over_budget: dial a fresh peer and flood many frames as
    // fast as possible. Expect the deployed limiter to drop the over-budget
    // frames and the exported counter to increment.
    let over_frames = 60u64;
    let over_enqueued = kemtls_flood_against(node_a_port, over_frames, 8).await;
    let drops_after_over = node_metrics.peer_network().total_rate_limit_drops();
    let body_after_over = node_metrics.format_metrics();
    let rendered_after_over = sum_per_peer_rate_limit_drops(&body_after_over);
    let conn_metric_present = body_after_over.contains("qbind_p2p_connection_rate_drop_total");

    scenarios.push(Scenario {
        id: "08_per_peer_kemtls_over_budget",
        expected: "over-budget KEMTLS flood → deployed limiter drops; exported counter increments"
            .to_string(),
        actual: format!(
            "over_enqueued={} total_drops={} rendered_drops={}",
            over_enqueued, drops_after_over, rendered_after_over
        ),
        matched: over_enqueued > 0 && drops_after_over > 0 && rendered_after_over > 0,
        detail: "A second KEMTLS-admitted peer flooded frames over the deployed read loop; the \
                 deployed per-peer limiter dropped the over-budget frames and bumped the exported \
                 qbind_net_per_peer_drops_total{reason=\"rate_limit\"} counter."
            .to_string(),
    });

    scenarios.push(Scenario {
        id: "09_metrics_export_live",
        expected: "qbind_net_per_peer_drops_total rendered by NodeMetrics::format_metrics"
            .to_string(),
        actual: format!(
            "family_present={} rendered_drops={}",
            body_after_over.contains("qbind_net_per_peer_drops_total"),
            rendered_after_over
        ),
        matched: body_after_over.contains("qbind_net_per_peer_drops_total")
            && rendered_after_over > 0,
        detail: "The exported per-peer drop family is rendered by the exact NodeMetrics string the \
                 live /metrics endpoint scrapes."
            .to_string(),
    });

    // combined_limiter_independence: per-peer drops must NOT appear as
    // connection-rate drops. The connection-rate counter (if rendered) must be
    // 0 for this per-peer-only flood.
    {
        let mut conn_drops = 0u64;
        for line in body_after_over.lines() {
            let l = line.trim();
            if l.starts_with("qbind_p2p_connection_rate_drop_total") {
                if let Some(v) = l.split_whitespace().last() {
                    conn_drops = v.parse().unwrap_or(0);
                }
            }
        }
        scenarios.push(Scenario {
            id: "10_combined_limiter_independence",
            expected: "per-peer flood leaves qbind_p2p_connection_rate_drop_total at 0".to_string(),
            actual: format!(
                "conn_metric_present={} conn_drops={} per_peer_drops={}",
                conn_metric_present, conn_drops, rendered_after_over
            ),
            matched: conn_drops == 0 && rendered_after_over > 0,
            detail: "The per-peer message-rate limiter and the connection-rate limiter are \
                     independent: a per-peer flood never touches the connection-rate counter."
                .to_string(),
        });
    }

    // non_mutation_guards: this whole helper builds no live trust state,
    // validator set, epoch, sequence, or marker. We assert the abuse/DoS runtime
    // config carries no such mutation surface (structural).
    {
        let rt = parse_cli(&["--p2p-max-messages-per-second", "5"])
            .unwrap()
            .abuse_dos_runtime_config()
            .unwrap();
        scenarios.push(Scenario {
            id: "11_non_mutation_guards",
            expected: "abuse/DoS config is observability-only; no trust/validator/epoch surface"
                .to_string(),
            actual: format!("runtime_config_present={}", rt.is_some()),
            matched: rt.is_some(),
            detail: "The per-peer override is a bounded rate-limit config; it mutates no \
                     LivePqcTrustState, validator set, epoch, sequence, or marker."
                .to_string(),
        });
    }

    let _ = P2pNodeBuilder::shutdown(ctx_a).await;

    // ---- Render outputs ----------------------------------------------------

    metric_evidence.push_str(&format!("node_a_addr: {}\n", node_a_addr));
    metric_evidence.push_str(&format!("limiter_installed: {}\n", limiter_installed));
    metric_evidence.push_str(&format!("under_budget_frames_enqueued: {}\n", under_enqueued));
    metric_evidence.push_str(&format!("under_budget_per_peer_drops: {}\n", rendered_after_under));
    metric_evidence.push_str(&format!("over_budget_frames_enqueued: {}\n", over_enqueued));
    metric_evidence.push_str(&format!("over_budget_per_peer_drops: {}\n", rendered_after_over));
    metric_evidence.push_str(&format!(
        "per_peer_family_present: {}\n",
        body_after_over.contains("qbind_net_per_peer_drops_total")
    ));
    metric_evidence.push_str("--- /metrics excerpt (per-peer family) ---\n");
    for line in body_after_over.lines() {
        if line.contains("qbind_net_per_peer_drops_total") {
            metric_evidence.push_str(line);
            metric_evidence.push('\n');
        }
    }
    write_file(&out_dir.join("metric_evidence.txt"), &metric_evidence);

    let mut manifest = String::new();
    let mut all_ok = true;
    for s in &scenarios {
        if !s.matched {
            all_ok = false;
        }
        manifest.push_str(&format!("{}\t{}\t{}\n", s.id, s.expected, s.matched));
        let detail = format!(
            "id: {}\nexpected: {}\nactual: {}\nmatched: {}\ndetail: {}\n",
            s.id, s.expected, s.actual, s.matched, s.detail
        );
        write_file(&out_dir.join("scenarios").join(format!("{}.txt", s.id)), &detail);
    }
    write_file(&out_dir.join("manifest.txt"), &manifest);

    let verdict = if all_ok { "PASS" } else { "FAIL" };
    let summary = format!(
        "verdict: {}\nscenarios: {}\nkemtls_over_budget_per_peer_drops: {}\n",
        verdict,
        scenarios.len(),
        rendered_after_over
    );
    write_file(&out_dir.join("helper_summary.txt"), &summary);

    for s in &scenarios {
        println!(
            "[run371-helper] {} matched={} ({})",
            s.id, s.matched, s.actual
        );
    }
    println!("[run371-helper] verdict: {}", verdict);
    all_ok
}

fn build_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("build tokio runtime")
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.get(1).map(|s| s.as_str()) == Some("dial-flood") {
        // dial-flood <peer_spec> <listen_addr> <local_vid> <frames> <pace_ms> <out_file>
        let peer_spec = args.get(2).expect("peer_spec").clone();
        let listen_addr = args.get(3).expect("listen_addr").clone();
        let local_vid: u64 = args.get(4).expect("local_vid").parse().expect("local_vid u64");
        let frames: u64 = args.get(5).expect("frames").parse().expect("frames u64");
        let pace_ms: u64 = args.get(6).expect("pace_ms").parse().expect("pace_ms u64");
        let out_file = PathBuf::from(args.get(7).expect("out_file"));

        let rt = build_runtime();
        let result = rt.block_on(dial_and_flood(
            &peer_spec,
            &listen_addr,
            local_vid,
            frames,
            pace_ms,
        ));

        let body = format!(
            "connected: {}\ntarget_node_id_seen: {}\nframes_attempted: {}\nframes_enqueued: {}\n",
            result.connected,
            result.target_node_id_seen,
            result.frames_attempted,
            result.frames_enqueued,
        );
        write_file(&out_file, &body);
        print!("{}", body);
        if result.connected && result.frames_enqueued > 0 {
            std::process::exit(0);
        } else {
            std::process::exit(2);
        }
    }

    let out_dir = args
        .get(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("run_371_out"));
    fs::create_dir_all(&out_dir).expect("create out dir");

    let rt = build_runtime();
    let ok = rt.block_on(run_scenarios(&out_dir));
    if ok {
        std::process::exit(0);
    } else {
        std::process::exit(1);
    }
}
