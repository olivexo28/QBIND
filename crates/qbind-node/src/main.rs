//! QBIND Node Binary Entry Point.
//!
//! Parses CLI arguments, validates configuration, spawns observability and
//! consensus components, and waits for shutdown.
//!
//! # Usage
//!
//! ```bash
//! # DevNet single-node smoke (LocalMesh, real consensus loop, metrics on)
//! QBIND_METRICS_HTTP_ADDR=127.0.0.1:9100 \
//! qbind-node --env devnet --validator-id 0
//!
//! # TestNet Alpha with P2P enabled
//! qbind-node \
//!   --env testnet \
//!   --execution-profile vm-v0 \
//!   --network-mode p2p \
//!   --enable-p2p \
//!   --p2p-listen-addr 0.0.0.0:19000 \
//!   --p2p-peer 127.0.0.1:19001 \
//!   --p2p-peer 127.0.0.1:19002 \
//!   --validator-id 0
//!
//! # MainNet v0 (requires all invariants satisfied)
//! qbind-node \
//!   --profile mainnet \
//!   --data-dir /data/qbind \
//!   --p2p-listen-addr 0.0.0.0:9000 \
//!   --p2p-peer mainnet-bootstrap-1.qbind.network:9000 \
//!   --validator-id 0
//! ```
//!
//! # DevNet v0 Freeze
//!
//! DevNet defaults remain `LocalMesh` + `enable_p2p = false` to preserve
//! the DevNet v0 freeze. P2P mode is opt-in for TestNet Alpha experimentation.
//!
//! # MainNet Safety Rails (T185)
//!
//! When `--profile mainnet` is specified, the node validates all MainNet
//! invariants before startup. If any invariant is violated (e.g., gas disabled,
//! P2P disabled, no data directory), the node refuses to start with a clear
//! error message.
//!
//! # Operability (B1, B2 — see
//! `docs/protocol/QBIND_REPO_CODE_DOC_ALIGNMENT_AUDIT.md` §9 and
//! `docs/whitepaper/contradiction.md` C4)
//!
//! - **B1 — real consensus loop**: After CLI/profile validation the binary
//!   spawns [`binary_consensus_loop::run_binary_consensus_loop`], which drives
//!   the existing `BasicHotStuffEngine`. Single-validator runs commit blocks
//!   honestly each tick; multi-validator runs propose when leader and
//!   advance views (full multi-node interconnect to `P2pConsensusNetwork`
//!   remains future work and is not silently faked here).
//! - **B2 — `/metrics` endpoint**: When `QBIND_METRICS_HTTP_ADDR` is set, the
//!   binary spawns the existing `metrics_http` server. When unset the server
//!   stays disabled (default-off) and startup logs say so.

use std::sync::Arc;

use tokio::sync::watch;

use qbind_node::binary_consensus_loop::{
    spawn_binary_consensus_loop, BinaryConsensusLoopConfig,
};
use qbind_node::cli::CliArgs;
use qbind_node::metrics::NodeMetrics;
use qbind_node::metrics_http::{
    spawn_metrics_http_server_with_crypto, CryptoMetricsRefs, MetricsHttpConfig,
};
use qbind_node::node_config::{ConfigProfile, NetworkMode};
use qbind_node::p2p_node_builder::P2pNodeBuilder;
use qbind_consensus::ids::ValidatorId;

/// Main entry point for qbind-node binary.
#[tokio::main]
async fn main() {
    // Parse CLI arguments
    let args = CliArgs::parse_args();

    // Build NodeConfig from CLI args
    let mut config = match args.to_node_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    // T185: Validate MainNet invariants if using MainNet profile
    if let Some(ref profile_str) = args.profile {
        if let Some(ConfigProfile::MainNet) =
            qbind_node::node_config::parse_config_profile(profile_str)
        {
            if let Err(e) = config.validate_mainnet_invariants() {
                eprintln!("[T185] ERROR: MainNet configuration validation failed!");
                eprintln!("[T185] {}", e);
                eprintln!("[T185] MainNet nodes must satisfy all invariants.");
                eprintln!(
                    "[T185] See docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md and \
                     docs/protocol/QBIND_PROTOCOL_REPORT.md for requirements."
                );
                std::process::exit(1);
            }
            eprintln!("[T185] MainNet invariants validated successfully.");
        }
    }

    // Validate P2P configuration (may modify config)
    let p2p_enabled = config.validate_p2p_config();

    // Log startup information
    let validator_id_str = args.validator_id_str();
    config.log_startup_info(Some(&validator_id_str));

    // ------------------------------------------------------------------
    // B2: Metrics HTTP endpoint (gated by QBIND_METRICS_HTTP_ADDR)
    //
    // `node_metrics` is shared with the metrics HTTP server *and* with the
    // binary-path consensus loop (DevNet Run 002 enabler): consensus-class
    // counters (ticks, proposals, commits, current view, view changes) are
    // updated from the loop directly so `/metrics` reflects live progress.
    // See `binary_consensus_loop::run_binary_consensus_loop`.
    // ------------------------------------------------------------------
    let node_metrics = Arc::new(NodeMetrics::new());
    let metrics_cfg = MetricsHttpConfig::from_env();
    if metrics_cfg.is_enabled() {
        eprintln!(
            "[metrics] Spawning metrics HTTP server on {} (set via QBIND_METRICS_HTTP_ADDR)",
            metrics_cfg.bind_addr
        );
    } else {
        eprintln!(
            "[metrics] Metrics HTTP server disabled (set QBIND_METRICS_HTTP_ADDR=host:port to enable)"
        );
    }
    let (metrics_shutdown_tx, metrics_shutdown_rx) = watch::channel(());
    let metrics_handle = spawn_metrics_http_server_with_crypto(
        node_metrics.clone(),
        metrics_cfg,
        CryptoMetricsRefs::new(),
        metrics_shutdown_rx,
    );

    // Branch based on network mode for transport / wiring.
    match config.network_mode {
        NetworkMode::LocalMesh => {
            run_local_mesh_node(&config, &args, Arc::clone(&node_metrics)).await;
        }
        NetworkMode::P2p => {
            if p2p_enabled {
                run_p2p_node(&config, &args, Arc::clone(&node_metrics)).await;
            } else {
                // P2P mode requested but not enabled by config.
                // Fail clearly rather than silently degrading: an operator
                // who asked for P2P should not be running on a LocalMesh
                // pretending to be P2P.
                eprintln!(
                    "[binary] ERROR: --network-mode p2p was requested but enable_p2p=false."
                );
                eprintln!(
                    "[binary] Pass --enable-p2p (or set network.enable_p2p=true) to actually \
                     start P2P, or use --network-mode local-mesh for single-host devnet."
                );
                std::process::exit(1);
            }
        }
    }

    // Tear down the metrics HTTP server on shutdown.
    eprintln!("[binary] Stopping metrics HTTP server...");
    drop(metrics_shutdown_tx);
    let _ = metrics_handle.await;
    eprintln!("[binary] Shutdown complete.");
}

/// Run a node in LocalMesh mode.
///
/// This spawns the binary consensus loop (`BasicHotStuffEngine` driven by
/// tokio interval). For a single-validator DevNet (the common bring-up
/// shape) the loop self-quorums and commits blocks each tick. For a
/// multi-validator LocalMesh the loop still proposes when leader; full
/// multi-node consensus interconnect over the in-process LocalMesh remains
/// covered by `NodeHotstuffHarness`-based integration tests.
async fn run_local_mesh_node(
    config: &qbind_node::node_config::NodeConfig,
    args: &CliArgs,
    node_metrics: Arc<NodeMetrics>,
) {
    eprintln!(
        "[binary] LocalMesh mode: starting consensus loop. environment={} profile={}",
        config.environment, config.execution_profile
    );

    // Default validator id 0 if unspecified (DevNet single-node smoke).
    let local_validator_id = ValidatorId::new(args.validator_id.unwrap_or(0));

    // Validator-set size: in LocalMesh we use the count of static peers + 1
    // (for the local node) when peers are configured, else 1 (single-node).
    let num_validators = (config.network.static_peers.len() as u64).saturating_add(1);

    let cfg = BinaryConsensusLoopConfig::new(local_validator_id, num_validators);
    eprintln!(
        "[binary] Consensus loop config: local_validator_id={:?} num_validators={}",
        local_validator_id, num_validators
    );
    if num_validators == 1 {
        eprintln!(
            "[binary] Single-validator LocalMesh: leader self-quorum will commit a block per tick."
        );
    } else {
        eprintln!(
            "[binary] Multi-validator LocalMesh ({} validators): the binary drives leader \
             proposal; multi-node message ingestion is not yet wired into the binary path \
             (covered by NodeHotstuffHarness integration tests).",
            num_validators
        );
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let (consensus_handle, _progress) = spawn_binary_consensus_loop(cfg, shutdown_rx, node_metrics);

    eprintln!("[binary] Consensus loop running. Press Ctrl+C to exit.");
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("[binary] Shutdown signal received, stopping consensus loop...");
    drop(shutdown_tx);
    let _ = consensus_handle.await;
    eprintln!("[binary] LocalMesh node stopped.");
}

/// Run a node in P2P mode.
///
/// Builds the P2P transport via `P2pNodeBuilder` *and* spawns the binary
/// consensus loop. The P2P transport and the consensus driver run side by
/// side; routing inbound P2P consensus messages back into the engine's
/// `on_proposal_event`/`on_vote_event` is part of the audit's outstanding
/// "wire P2P → consensus" work and is not silently claimed here.
async fn run_p2p_node(
    config: &qbind_node::node_config::NodeConfig,
    args: &CliArgs,
    node_metrics: Arc<NodeMetrics>,
) {
    eprintln!(
        "[binary] P2P mode: starting transport + consensus loop. environment={} profile={}",
        config.environment, config.execution_profile
    );

    let validator_id = args.validator_id.unwrap_or(0);
    let local_validator_id = ValidatorId::new(validator_id);

    // Build the P2P transport.
    let builder = P2pNodeBuilder::new();
    let node_context = match builder.build(config, validator_id).await {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("[binary] ERROR: Failed to build P2P node: {:?}", e);
            std::process::exit(1);
        }
    };

    eprintln!(
        "[binary] P2P transport up. Listen address: {}, static peers: {}",
        config.network.listen_addr.as_deref().unwrap_or("unknown"),
        config.network.static_peers.len()
    );

    // Validator-set size: peers + self.
    let num_validators = (config.network.static_peers.len() as u64).saturating_add(1);
    let consensus_cfg = BinaryConsensusLoopConfig::new(local_validator_id, num_validators);
    eprintln!(
        "[binary] Consensus loop config: local_validator_id={:?} num_validators={}",
        local_validator_id, num_validators
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let (consensus_handle, _progress) =
        spawn_binary_consensus_loop(consensus_cfg, shutdown_rx, node_metrics);

    eprintln!("[binary] P2P node started. Press Ctrl+C to exit.");
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("[binary] Shutdown signal received, stopping P2P node...");

    drop(shutdown_tx);
    let _ = consensus_handle.await;

    if let Err(e) = P2pNodeBuilder::shutdown(node_context).await {
        eprintln!("[binary] Error during P2P shutdown: {:?}", e);
    }
    eprintln!("[binary] P2P node shutdown complete.");
}