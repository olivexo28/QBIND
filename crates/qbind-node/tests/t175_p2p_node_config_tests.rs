//! T175 P2P Node Config Tests
//!
//! This module tests the CLI/config parsing for P2P mode (T175):
//! - Network mode parsing (`--network-mode`)
//! - P2P configuration interaction matrix
//! - Address parsing for `--p2p-listen-addr` and `--p2p-peer`
//! - Startup info string includes P2P state

use qbind_node::node_config::{
    parse_network_mode, parse_socket_addr, ExecutionProfile, MempoolMode, NetworkMode, NetworkTransportConfig,
    NodeConfig, ParseAddrError, DEFAULT_NETWORK_MODE, DEFAULT_P2P_LISTEN_ADDR, VALID_NETWORK_MODES,
};
use qbind_types::NetworkEnvironment;

// ============================================================================
// Part 1: Network Mode Parsing Tests
// ============================================================================

#[test]
fn test_parse_network_mode_p2p() {
    assert_eq!(parse_network_mode("p2p"), NetworkMode::P2p);
    assert_eq!(parse_network_mode("P2P"), NetworkMode::P2p);
    assert_eq!(parse_network_mode("P2p"), NetworkMode::P2p);
}

#[test]
fn test_parse_network_mode_local_mesh() {
    assert_eq!(parse_network_mode("local-mesh"), NetworkMode::LocalMesh);
    assert_eq!(parse_network_mode("LOCAL-MESH"), NetworkMode::LocalMesh);
    assert_eq!(parse_network_mode("localmesh"), NetworkMode::LocalMesh);
    assert_eq!(parse_network_mode("mesh"), NetworkMode::LocalMesh);
}

#[test]
fn test_parse_network_mode_unknown_defaults_to_local_mesh() {
    // Unknown values should default to LocalMesh for safety
    assert_eq!(parse_network_mode("unknown"), NetworkMode::LocalMesh);
    assert_eq!(parse_network_mode("invalid"), NetworkMode::LocalMesh);
    assert_eq!(parse_network_mode(""), NetworkMode::LocalMesh);
}

#[test]
fn test_network_mode_display() {
    assert_eq!(format!("{}", NetworkMode::LocalMesh), "local-mesh");
    assert_eq!(format!("{}", NetworkMode::P2p), "p2p");
}

#[test]
fn test_network_mode_constants() {
    assert_eq!(DEFAULT_NETWORK_MODE, "local-mesh");
    assert_eq!(VALID_NETWORK_MODES, &["local-mesh", "p2p"]);
}

// ============================================================================
// Part 2: P2P Configuration Interaction Matrix Tests
// ============================================================================

/// LocalMesh + enable_p2p=false -> P2P disabled
#[test]
fn test_p2p_config_local_mesh_disabled() {
    let mut config = NodeConfig {
        environment: NetworkEnvironment::Testnet,
        execution_profile: ExecutionProfile::VmV0,
        data_dir: None,
        network: NetworkTransportConfig {
            enable_p2p: false,
            max_outbound: 16,
            max_inbound: 64,
            gossip_fanout: 6,
            listen_addr: None,
            advertised_addr: None,
            static_peers: vec![],
        },
        network_mode: NetworkMode::LocalMesh,
        gas_enabled: false,
        enable_fee_priority: false,
        mempool_mode: MempoolMode::Fifo,
        dag_availability_enabled: false,
    };

    let p2p_enabled = config.validate_p2p_config();
    assert!(
        !p2p_enabled,
        "LocalMesh + enable_p2p=false should disable P2P"
    );
    assert!(!config.is_p2p_mode());
}

/// P2p + enable_p2p=false -> warning, use LocalMesh
#[test]
fn test_p2p_config_p2p_mode_but_not_enabled() {
    let mut config = NodeConfig {
        environment: NetworkEnvironment::Testnet,
        execution_profile: ExecutionProfile::VmV0,
        data_dir: None,
        network: NetworkTransportConfig {
            enable_p2p: false, // Not enabled
            max_outbound: 16,
            max_inbound: 64,
            gossip_fanout: 6,
            listen_addr: Some("127.0.0.1:19000".to_string()),
            advertised_addr: None,
            static_peers: vec!["127.0.0.1:19001".to_string()],
        },
        network_mode: NetworkMode::P2p, // P2P mode requested
        gas_enabled: false,
        enable_fee_priority: false,
        mempool_mode: MempoolMode::Fifo,
        dag_availability_enabled: false,
    };

    let p2p_enabled = config.validate_p2p_config();
    assert!(!p2p_enabled, "P2p + enable_p2p=false should return false");
    assert!(!config.is_p2p_mode());
}

/// P2p + enable_p2p=true -> P2P enabled
#[test]
fn test_p2p_config_p2p_mode_enabled() {
    let mut config = NodeConfig {
        environment: NetworkEnvironment::Testnet,
        execution_profile: ExecutionProfile::VmV0,
        data_dir: None,
        network: NetworkTransportConfig {
            enable_p2p: true,
            max_outbound: 16,
            max_inbound: 64,
            gossip_fanout: 6,
            listen_addr: Some("0.0.0.0:19000".to_string()),
            advertised_addr: None,
            static_peers: vec!["127.0.0.1:19001".to_string()],
        },
        network_mode: NetworkMode::P2p,
        gas_enabled: false,
        enable_fee_priority: false,
        mempool_mode: MempoolMode::Fifo,
        dag_availability_enabled: false,
    };

    let p2p_enabled = config.validate_p2p_config();
    assert!(p2p_enabled, "P2p + enable_p2p=true should enable P2P");
    assert!(config.is_p2p_mode());
}

/// P2P enabled but no listen_addr -> should set default
#[test]
fn test_p2p_config_no_listen_addr_sets_default() {
    let mut config = NodeConfig {
        environment: NetworkEnvironment::Testnet,
        execution_profile: ExecutionProfile::VmV0,
        data_dir: None,
        network: NetworkTransportConfig {
            enable_p2p: true,
            max_outbound: 16,
            max_inbound: 64,
            gossip_fanout: 6,
            listen_addr: None, // No listen address
            advertised_addr: None,
            static_peers: vec![],
        },
        network_mode: NetworkMode::P2p,
        gas_enabled: false,
        enable_fee_priority: false,
        mempool_mode: MempoolMode::Fifo,
        dag_availability_enabled: false,
    };

    let p2p_enabled = config.validate_p2p_config();
    assert!(p2p_enabled);
    assert!(
        config.network.listen_addr.is_some(),
        "validate_p2p_config should set default listen_addr"
    );
    assert_eq!(
        config.network.listen_addr.as_deref(),
        Some("127.0.0.1:0"),
        "Default listen_addr should be 127.0.0.1:0"
    );
}

/// LocalMesh + enable_p2p=true -> warning, P2P disabled
#[test]
fn test_p2p_config_local_mesh_with_enable_p2p() {
    let mut config = NodeConfig {
        environment: NetworkEnvironment::Testnet,
        execution_profile: ExecutionProfile::VmV0,
        data_dir: None,
        network: NetworkTransportConfig {
            enable_p2p: true, // Enabled but...
            max_outbound: 16,
            max_inbound: 64,
            gossip_fanout: 6,
            listen_addr: Some("127.0.0.1:19000".to_string()),
            advertised_addr: None,
            static_peers: vec![],
        },
        network_mode: NetworkMode::LocalMesh, // LocalMesh mode
        gas_enabled: false,
        enable_fee_priority: false,
        mempool_mode: MempoolMode::Fifo,
        dag_availability_enabled: false,
    };

    let p2p_enabled = config.validate_p2p_config();
    assert!(
        !p2p_enabled,
        "LocalMesh mode should disable P2P even if enable_p2p=true"
    );
}

// ============================================================================
// Part 3: Address Parsing Tests
// ============================================================================

#[test]
fn test_parse_socket_addr_valid_ipv4() {
    let addr = parse_socket_addr("127.0.0.1:8080").unwrap();
    assert_eq!(addr.ip().to_string(), "127.0.0.1");
    assert_eq!(addr.port(), 8080);
}

#[test]
fn test_parse_socket_addr_valid_any() {
    let addr = parse_socket_addr("0.0.0.0:19000").unwrap();
    assert_eq!(addr.ip().to_string(), "0.0.0.0");
    assert_eq!(addr.port(), 19000);
}

#[test]
fn test_parse_socket_addr_valid_ipv6() {
    let addr = parse_socket_addr("[::1]:9000").unwrap();
    assert_eq!(addr.port(), 9000);
}

#[test]
fn test_parse_socket_addr_invalid_no_port() {
    let result = parse_socket_addr("127.0.0.1");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.invalid_value.contains("127.0.0.1"));
}

#[test]
fn test_parse_socket_addr_invalid_format() {
    let result = parse_socket_addr("invalid:addr:here");
    assert!(result.is_err());
}

#[test]
fn test_parse_socket_addr_invalid_empty() {
    let result = parse_socket_addr("");
    assert!(result.is_err());
}

#[test]
fn test_parse_addr_error_display() {
    let err = ParseAddrError {
        invalid_value: "bad:addr".to_string(),
        reason: "invalid format".to_string(),
    };
    let msg = format!("{}", err);
    assert!(msg.contains("bad:addr"));
    assert!(msg.contains("invalid format"));
}

#[test]
fn test_default_p2p_listen_addr() {
    assert_eq!(DEFAULT_P2P_LISTEN_ADDR, "127.0.0.1:0");
}

// ============================================================================
// Part 4: Startup Info String Tests
// ============================================================================

#[test]
fn test_startup_info_includes_network_mode() {
    let config = NodeConfig {
        environment: NetworkEnvironment::Testnet,
        execution_profile: ExecutionProfile::VmV0,
        data_dir: None,
        network: NetworkTransportConfig::default(),
        network_mode: NetworkMode::LocalMesh,
        gas_enabled: false,
        enable_fee_priority: false,
        mempool_mode: MempoolMode::Fifo,
        dag_availability_enabled: false,
    };

    let info = config.startup_info_string(Some("V0"));
    assert!(
        info.contains("network=local-mesh"),
        "Startup info should include network mode: {}",
        info
    );
}

#[test]
fn test_startup_info_p2p_disabled() {
    let config = NodeConfig {
        environment: NetworkEnvironment::Testnet,
        execution_profile: ExecutionProfile::VmV0,
        data_dir: None,
        network: NetworkTransportConfig::default(),
        network_mode: NetworkMode::LocalMesh,
        gas_enabled: false,
        enable_fee_priority: false,
        mempool_mode: MempoolMode::Fifo,
        dag_availability_enabled: false,
    };

    let info = config.startup_info_string(Some("V0"));
    assert!(
        info.contains("p2p=disabled"),
        "Startup info should show p2p=disabled: {}",
        info
    );
}

#[test]
fn test_startup_info_p2p_enabled() {
    let config = NodeConfig {
        environment: NetworkEnvironment::Testnet,
        execution_profile: ExecutionProfile::VmV0,
        data_dir: None,
        network: NetworkTransportConfig {
            enable_p2p: true,
            max_outbound: 16,
            max_inbound: 64,
            gossip_fanout: 6,
            listen_addr: Some("0.0.0.0:19000".to_string()),
            advertised_addr: None,
            static_peers: vec!["127.0.0.1:19001".to_string(), "127.0.0.1:19002".to_string()],
        },
        network_mode: NetworkMode::P2p,
        gas_enabled: false,
        enable_fee_priority: false,
        mempool_mode: MempoolMode::Fifo,
        dag_availability_enabled: false,
    };

    let info = config.startup_info_string(Some("V0"));
    assert!(
        info.contains("p2p=enabled"),
        "Startup info should show p2p=enabled: {}",
        info
    );
    assert!(
        info.contains("listen=0.0.0.0:19000"),
        "Startup info should show listen address: {}",
        info
    );
    assert!(
        info.contains("peers=2"),
        "Startup info should show peer count: {}",
        info
    );
}

#[test]
fn test_startup_info_includes_environment() {
    let config = NodeConfig::testnet_vm_v0();
    let info = config.startup_info_string(Some("V1"));

    assert!(info.contains("environment=TestNet"));
    assert!(info.contains("validator=V1"));
    assert!(info.contains("profile=vm-v0"));
}

// ============================================================================
// Part 5: NodeConfig Builder Tests
// ============================================================================

#[test]
fn test_node_config_with_network_mode() {
    let config = NodeConfig::testnet_vm_v0().with_network_mode(NetworkMode::P2p);
    assert_eq!(config.network_mode, NetworkMode::P2p);
}

#[test]
fn test_node_config_default_is_local_mesh() {
    let config = NodeConfig::default();
    assert_eq!(config.network_mode, NetworkMode::LocalMesh);
    assert!(!config.network.enable_p2p);
}

#[test]
fn test_node_config_testnet_default_is_local_mesh() {
    let config = NodeConfig::testnet_vm_v0();
    assert_eq!(config.network_mode, NetworkMode::LocalMesh);
}
