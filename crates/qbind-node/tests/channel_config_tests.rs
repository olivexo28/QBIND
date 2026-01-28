//! Integration tests for channel capacity configuration (T90.2).
//!
//! These tests verify:
//! - `ChannelCapacityConfig` construction and defaults
//! - Environment variable parsing with valid/invalid values
//! - Integration with `AsyncNodeRunner`, `AsyncConsensusNetAdapter`, `AsyncNetSender`
//! - Metrics output includes configured capacities
//!
//! # Note on Environment Variable Tests
//!
//! Tests that modify environment variables use a global mutex (`ENV_TEST_MUTEX`)
//! to prevent race conditions when tests run in parallel.

use std::sync::{Arc, Mutex};

use qbind_node::async_peer_manager::AsyncPeerManagerConfig;
use qbind_node::channel_config::ChannelCapacityConfig;
use qbind_node::consensus_net_worker::{AsyncConsensusNetAdapter, AsyncNetSender};
use qbind_node::metrics::NodeMetrics;

/// Global mutex to serialize tests that modify environment variables.
/// This prevents race conditions when tests run in parallel.
static ENV_TEST_MUTEX: Mutex<()> = Mutex::new(());

// ============================================================================
// Part A: ChannelCapacityConfig construction tests
// ============================================================================

#[test]
fn default_config_has_documented_values() {
    let config = ChannelCapacityConfig::default();

    // Verify documented default values
    assert_eq!(config.consensus_event_capacity, 1024);
    assert_eq!(config.outbound_command_capacity, 1024);
    assert_eq!(config.async_peer_inbound_capacity, 1024);
    assert_eq!(config.async_peer_outbound_capacity, 256);
}

#[test]
fn builder_methods_chain_correctly() {
    let config = ChannelCapacityConfig::new()
        .with_consensus_event_capacity(2048)
        .with_outbound_command_capacity(512)
        .with_async_peer_inbound_capacity(4096)
        .with_async_peer_outbound_capacity(128);

    assert_eq!(config.consensus_event_capacity, 2048);
    assert_eq!(config.outbound_command_capacity, 512);
    assert_eq!(config.async_peer_inbound_capacity, 4096);
    assert_eq!(config.async_peer_outbound_capacity, 128);
}

#[test]
fn config_is_clone_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ChannelCapacityConfig>();

    let config1 = ChannelCapacityConfig::default();
    let config2 = config1.clone();
    assert_eq!(config1, config2);
}

// ============================================================================
// Part B: Environment variable parsing tests
// ============================================================================

// These tests use ENV_TEST_MUTEX to prevent race conditions.

/// Helper to clear all channel config environment variables.
fn clear_channel_env_vars() {
    std::env::remove_var("QBIND_CONSENSUS_EVENT_CHANNEL_CAPACITY");
    std::env::remove_var("QBIND_OUTBOUND_COMMAND_CHANNEL_CAPACITY");
    std::env::remove_var("QBIND_ASYNC_PEER_INBOUND_CAPACITY");
    std::env::remove_var("QBIND_ASYNC_PEER_OUTBOUND_CAPACITY");
}

#[test]
fn from_env_uses_defaults_when_vars_unset() {
    let _guard = ENV_TEST_MUTEX.lock().unwrap();

    // Clear any existing vars
    clear_channel_env_vars();

    let config = ChannelCapacityConfig::from_env();

    // Should match defaults
    assert_eq!(config.consensus_event_capacity, 1024);
    assert_eq!(config.outbound_command_capacity, 1024);
    assert_eq!(config.async_peer_inbound_capacity, 1024);
    assert_eq!(config.async_peer_outbound_capacity, 256);
}

#[test]
fn from_env_parses_valid_values() {
    let _guard = ENV_TEST_MUTEX.lock().unwrap();

    // Clear any existing vars first to ensure clean state
    clear_channel_env_vars();

    // Set environment variables
    std::env::set_var("QBIND_CONSENSUS_EVENT_CHANNEL_CAPACITY", "2048");
    std::env::set_var("QBIND_OUTBOUND_COMMAND_CHANNEL_CAPACITY", "512");
    std::env::set_var("QBIND_ASYNC_PEER_INBOUND_CAPACITY", "4096");
    std::env::set_var("QBIND_ASYNC_PEER_OUTBOUND_CAPACITY", "128");

    let config = ChannelCapacityConfig::from_env();

    assert_eq!(config.consensus_event_capacity, 2048);
    assert_eq!(config.outbound_command_capacity, 512);
    assert_eq!(config.async_peer_inbound_capacity, 4096);
    assert_eq!(config.async_peer_outbound_capacity, 128);

    // Clean up
    clear_channel_env_vars();
}

#[test]
fn from_env_rejects_zero_value() {
    let _guard = ENV_TEST_MUTEX.lock().unwrap();

    // Clear first
    clear_channel_env_vars();

    // Set an invalid value
    std::env::set_var("QBIND_CONSENSUS_EVENT_CHANNEL_CAPACITY", "0");

    let config = ChannelCapacityConfig::from_env();

    // Should fall back to default
    assert_eq!(config.consensus_event_capacity, 1024);

    // Clean up
    clear_channel_env_vars();
}

#[test]
fn from_env_rejects_non_numeric_value() {
    let _guard = ENV_TEST_MUTEX.lock().unwrap();

    // Clear first
    clear_channel_env_vars();

    // Set an invalid value
    std::env::set_var("QBIND_CONSENSUS_EVENT_CHANNEL_CAPACITY", "not_a_number");

    let config = ChannelCapacityConfig::from_env();

    // Should fall back to default
    assert_eq!(config.consensus_event_capacity, 1024);

    // Clean up
    clear_channel_env_vars();
}

#[test]
fn from_env_partial_override() {
    let _guard = ENV_TEST_MUTEX.lock().unwrap();

    // Clear all environment variables first to ensure clean state
    clear_channel_env_vars();

    // Only override one value
    std::env::set_var("QBIND_CONSENSUS_EVENT_CHANNEL_CAPACITY", "2048");

    let config = ChannelCapacityConfig::from_env();

    // Only consensus_event should be overridden
    assert_eq!(config.consensus_event_capacity, 2048);
    assert_eq!(config.outbound_command_capacity, 1024); // default
    assert_eq!(config.async_peer_inbound_capacity, 1024); // default
    assert_eq!(config.async_peer_outbound_capacity, 256); // default

    // Clean up
    clear_channel_env_vars();
}

#[test]
fn has_env_overrides_detects_set_vars() {
    let _guard = ENV_TEST_MUTEX.lock().unwrap();

    // Clear all
    clear_channel_env_vars();

    assert!(!ChannelCapacityConfig::has_env_overrides());

    // Set one
    std::env::set_var("QBIND_CONSENSUS_EVENT_CHANNEL_CAPACITY", "2048");
    assert!(ChannelCapacityConfig::has_env_overrides());

    // Clean up
    clear_channel_env_vars();
}

// ============================================================================
// Part C: Integration with AsyncConsensusNetAdapter
// ============================================================================

#[test]
fn async_consensus_net_adapter_with_config() {
    let config = ChannelCapacityConfig::new().with_outbound_command_capacity(512);

    let (adapter, _inbound_tx, _outbound_rx) = AsyncConsensusNetAdapter::with_config(&config);

    // Verify adapter was created (we can't directly inspect channel capacity,
    // but we can verify construction succeeds)
    let debug_str = format!("{:?}", adapter);
    assert!(debug_str.contains("AsyncConsensusNetAdapter"));
}

// ============================================================================
// Part D: Integration with AsyncNetSender
// ============================================================================

#[test]
fn async_net_sender_with_channel_config() {
    let config = ChannelCapacityConfig::new().with_outbound_command_capacity(512);

    let (sender, _outbound_rx, _critical_rx) = AsyncNetSender::with_channel_config(&config);

    // Verify sender was created
    let debug_str = format!("{:?}", sender);
    assert!(debug_str.contains("AsyncNetSender"));
}

#[test]
fn async_net_sender_with_channel_config_and_metrics() {
    let config = ChannelCapacityConfig::new().with_outbound_command_capacity(512);
    let metrics = Arc::new(NodeMetrics::new());

    let (sender, _outbound_rx, _critical_rx) =
        AsyncNetSender::with_channel_config_and_metrics(&config, metrics);

    // Verify sender was created with metrics
    let debug_str = format!("{:?}", sender);
    assert!(debug_str.contains("AsyncNetSender"));
}

// ============================================================================
// Part E: Integration with AsyncPeerManagerConfig
// ============================================================================

#[test]
fn async_peer_manager_config_from_channel_config() {
    let channel_config = ChannelCapacityConfig::new()
        .with_async_peer_inbound_capacity(2048)
        .with_async_peer_outbound_capacity(512);

    let peer_config = AsyncPeerManagerConfig::from_channel_config(&channel_config);

    assert_eq!(peer_config.inbound_channel_capacity, 2048);
    assert_eq!(peer_config.outbound_channel_capacity, 512);
}

#[test]
fn async_peer_manager_config_builder_methods() {
    let config = AsyncPeerManagerConfig::new()
        .with_inbound_channel_capacity(4096)
        .with_outbound_channel_capacity(256)
        .with_listen_addr("0.0.0.0:8080".parse().unwrap());

    assert_eq!(config.inbound_channel_capacity, 4096);
    assert_eq!(config.outbound_channel_capacity, 256);
    assert_eq!(config.listen_addr.port(), 8080);
}

// ============================================================================
// Part F: Metrics output tests
// ============================================================================

#[test]
fn metrics_format_includes_channel_config() {
    let metrics = NodeMetrics::new();

    let config = ChannelCapacityConfig::new()
        .with_consensus_event_capacity(2048)
        .with_outbound_command_capacity(512);

    metrics.set_channel_config(config);

    let output = metrics.format_metrics();

    // Verify channel config section exists
    assert!(output.contains("# Channel capacity configuration"));
    assert!(output.contains("consensus_channel_config{kind=\"event\"} 2048"));
    assert!(output.contains("consensus_channel_config{kind=\"outbound_command\"} 512"));
}

#[test]
fn metrics_format_shows_defaults_when_config_not_set() {
    let metrics = NodeMetrics::new();

    let output = metrics.format_metrics();

    // Default values should be shown
    assert!(output.contains("consensus_channel_config{kind=\"event\"} 1024"));
    assert!(output.contains("consensus_channel_config{kind=\"outbound_command\"} 1024"));
    assert!(output.contains("consensus_channel_config{kind=\"async_peer_inbound\"} 1024"));
    assert!(output.contains("consensus_channel_config{kind=\"async_peer_outbound\"} 256"));
}

// ============================================================================
// Part G: Backward compatibility tests
// ============================================================================

#[test]
fn existing_constructors_still_work() {
    // AsyncConsensusNetAdapter::new() should still work
    let (adapter, _inbound_tx, _outbound_rx) = AsyncConsensusNetAdapter::new();
    let debug_str = format!("{:?}", adapter);
    assert!(debug_str.contains("AsyncConsensusNetAdapter"));

    // AsyncConsensusNetAdapter::with_capacity() should still work
    let (adapter2, _inbound_tx2, _outbound_rx2) = AsyncConsensusNetAdapter::with_capacity(512, 256);
    let debug_str2 = format!("{:?}", adapter2);
    assert!(debug_str2.contains("AsyncConsensusNetAdapter"));

    // AsyncNetSender::with_channel() should still work
    let (sender, _rx, _critical_rx) = AsyncNetSender::with_channel(512);
    let debug_str3 = format!("{:?}", sender);
    assert!(debug_str3.contains("AsyncNetSender"));
}
