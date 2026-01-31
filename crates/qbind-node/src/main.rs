//! T175: QBIND Node Binary Entry Point
//!
//! This is the main entry point for the qbind-node binary.
//! It parses CLI arguments, builds the node configuration, and starts
//! the node in either LocalMesh or P2P mode.
//!
//! # Usage
//!
//! ```bash
//! # DevNet with default settings (LocalMesh, nonce-only)
//! qbind-node --env devnet
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
//! ```
//!
//! # DevNet v0 Freeze
//!
//! DevNet defaults remain `LocalMesh` + `enable_p2p = false` to preserve
//! the DevNet v0 freeze. P2P mode is opt-in for TestNet Alpha experimentation.

use qbind_node::cli::CliArgs;
use qbind_node::node_config::NetworkMode;
use qbind_node::p2p_node_builder::P2pNodeBuilder;

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

    // Validate P2P configuration (may modify config)
    let p2p_enabled = config.validate_p2p_config();

    // Log startup information
    let validator_id_str = args.validator_id_str();
    config.log_startup_info(Some(&validator_id_str));

    // Branch based on network mode
    match config.network_mode {
        NetworkMode::LocalMesh => {
            run_local_mesh_node(&config, &args).await;
        }
        NetworkMode::P2p => {
            if p2p_enabled {
                run_p2p_node(&config, &args).await;
            } else {
                // P2P mode requested but not enabled - fall back to LocalMesh stub
                eprintln!("[T175] P2P mode requested but not fully enabled. Running in LocalMesh mode.");
                run_local_mesh_node(&config, &args).await;
            }
        }
    }
}

/// Run the node in LocalMesh mode.
///
/// This is a stub for T175. Full LocalMesh node operation will be
/// implemented in future tasks. For now, this prints a message and
/// waits for shutdown signal.
async fn run_local_mesh_node(
    config: &qbind_node::node_config::NodeConfig,
    _args: &CliArgs,
) {
    println!(
        "[T175] LocalMesh mode: Node would start with environment={} profile={}",
        config.environment, config.execution_profile
    );
    println!("[T175] LocalMesh node startup is a stub in T175.");
    println!("[T175] Press Ctrl+C to exit.");

    // Wait for shutdown signal
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for ctrl-c");
    println!("[T175] Shutting down...");
}

/// Run the node in P2P mode.
///
/// This creates the P2P transport service, wires up the inbound demuxer,
/// and starts the consensus engine with P2P networking.
async fn run_p2p_node(
    config: &qbind_node::node_config::NodeConfig,
    args: &CliArgs,
) {
    println!(
        "[T175] P2P mode: Node starting with environment={} profile={}",
        config.environment, config.execution_profile
    );

    // Get validator ID (default to 0 if not specified)
    let validator_id = args.validator_id.unwrap_or(0);

    // Build the P2P node
    let builder = P2pNodeBuilder::new();
    
    let node_context = match builder.build(config, validator_id).await {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("[T175] Failed to build P2P node: {:?}", e);
            std::process::exit(1);
        }
    };

    println!("[T175] P2P node started successfully.");
    println!(
        "[T175] Listen address: {}",
        config.network.listen_addr.as_deref().unwrap_or("unknown")
    );
    println!("[T175] Static peers: {}", config.network.static_peers.len());
    println!("[T175] Press Ctrl+C to exit.");

    // Wait for shutdown signal
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for ctrl-c");

    println!("[T175] Shutting down P2P node...");
    
    // Shutdown the P2P node
    if let Err(e) = P2pNodeBuilder::shutdown(node_context).await {
        eprintln!("[T175] Error during shutdown: {:?}", e);
    }

    println!("[T175] P2P node shutdown complete.");
}
