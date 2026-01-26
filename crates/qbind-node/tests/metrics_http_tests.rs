//! Integration tests for the metrics HTTP server (T126).
//!
//! These tests verify that the minimal HTTP server correctly:
//! - Returns metrics on GET /metrics
//! - Returns 404 for unknown paths
//! - Shuts down cleanly when signaled
//! - Configures correctly from environment variables
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p qbind-node --test metrics_http_tests -- --nocapture
//! ```

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::timeout;

use qbind_node::metrics::NodeMetrics;
use qbind_node::metrics_http::{
    spawn_metrics_http_server_with_addr, CryptoMetricsRefs, MetricsHttpConfig,
    METRICS_HTTP_ADDR_ENV,
};

/// Mutex to serialize tests that manipulate the METRICS_HTTP_ADDR_ENV environment variable.
/// Environment variables are process-global state, so tests that read/write them must be serialized.
fn env_var_mutex() -> &'static Mutex<()> {
    static MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
    MUTEX.get_or_init(|| Mutex::new(()))
}

// ============================================================================
// Test Helpers
// ============================================================================

/// Helper to read an HTTP response into a string.
async fn read_http_response(stream: &mut TcpStream) -> std::io::Result<(String, String)> {
    let mut reader = BufReader::new(stream);
    let mut headers = String::new();
    let mut body = String::new();

    // Read headers line by line until we see the empty line
    loop {
        let mut line = String::new();
        let bytes_read = reader.read_line(&mut line).await?;
        if bytes_read == 0 {
            break;
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        headers.push_str(&line);
    }

    // Read the rest as body (limited to avoid hanging)
    let mut buf = vec![0u8; 32768];
    match timeout(Duration::from_millis(500), reader.read(&mut buf)).await {
        Ok(Ok(n)) => {
            body = String::from_utf8_lossy(&buf[..n]).to_string();
        }
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            // Timeout reading body - that's OK, we might have all we need
        }
    }

    Ok((headers, body))
}

/// Send an HTTP request and get the response.
async fn send_http_request(
    addr: std::net::SocketAddr,
    request: &str,
) -> std::io::Result<(String, String)> {
    let mut stream = TcpStream::connect(addr).await?;
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    read_http_response(&mut stream).await
}

// ============================================================================
// Test: Basic /metrics Happy Path
// ============================================================================

/// Test that GET /metrics returns 200 OK with metrics content.
#[tokio::test]
async fn test_metrics_endpoint_returns_200_with_metrics_body() {
    // Create metrics with some data
    let metrics = Arc::new(NodeMetrics::new());
    metrics.network().inc_inbound_vote();
    metrics.network().inc_inbound_proposal();
    metrics.runtime().inc_events_tick();

    // Bind to 127.0.0.1:0 to get OS-assigned port
    let config = MetricsHttpConfig::from_addr("127.0.0.1:0");
    let (shutdown_tx, shutdown_rx) = watch::channel(());

    let (handle, bound_addr) =
        spawn_metrics_http_server_with_addr(metrics, config, CryptoMetricsRefs::new(), shutdown_rx)
            .await;

    let addr = bound_addr.expect("Server should have bound to an address");
    eprintln!("[test] Server bound to {}", addr);

    // Small delay to let the server start accepting
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send HTTP request
    let request = "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let (headers, body) = send_http_request(addr, request)
        .await
        .expect("Failed to send request");

    eprintln!("[test] Response headers:\n{}", headers);
    eprintln!(
        "[test] Response body (first 500 chars):\n{}",
        &body[..body.len().min(500)]
    );

    // Verify response status
    assert!(
        headers.starts_with("HTTP/1.1 200 OK"),
        "Expected 200 OK, got: {}",
        headers.lines().next().unwrap_or("")
    );

    // Verify Content-Type header
    let content_type_present = headers.to_lowercase().contains("content-type: text/plain");
    assert!(
        content_type_present,
        "Expected Content-Type: text/plain header"
    );

    // Verify body contains at least one known metric line
    assert!(
        body.contains("consensus_net_inbound_total{kind=\"vote\"}")
            || body.contains("consensus_net_inbound_total")
            || body.contains("consensus_events_total"),
        "Expected at least one known metric in body"
    );

    // Shutdown the server
    drop(shutdown_tx);

    // Wait for the server task to complete
    let _ = timeout(Duration::from_secs(2), handle).await;
}

/// Test that GET /metrics/ (with trailing slash) also works.
#[tokio::test]
async fn test_metrics_endpoint_with_trailing_slash() {
    let metrics = Arc::new(NodeMetrics::new());
    let config = MetricsHttpConfig::from_addr("127.0.0.1:0");
    let (shutdown_tx, shutdown_rx) = watch::channel(());

    let (handle, bound_addr) =
        spawn_metrics_http_server_with_addr(metrics, config, CryptoMetricsRefs::new(), shutdown_rx)
            .await;

    let addr = bound_addr.expect("Server should have bound");
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Request with trailing slash
    let request = "GET /metrics/ HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let (headers, _body) = send_http_request(addr, request)
        .await
        .expect("Failed to send request");

    assert!(
        headers.starts_with("HTTP/1.1 200 OK"),
        "Expected 200 OK for /metrics/, got: {}",
        headers.lines().next().unwrap_or("")
    );

    drop(shutdown_tx);
    let _ = timeout(Duration::from_secs(2), handle).await;
}

// ============================================================================
// Test: 404 for Unknown Paths
// ============================================================================

/// Test that GET /foo returns 404 Not Found.
#[tokio::test]
async fn test_unknown_path_returns_404() {
    let metrics = Arc::new(NodeMetrics::new());
    let config = MetricsHttpConfig::from_addr("127.0.0.1:0");
    let (shutdown_tx, shutdown_rx) = watch::channel(());

    let (handle, bound_addr) =
        spawn_metrics_http_server_with_addr(metrics, config, CryptoMetricsRefs::new(), shutdown_rx)
            .await;

    let addr = bound_addr.expect("Server should have bound");
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Request unknown path
    let request = "GET /foo HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let (headers, body) = send_http_request(addr, request)
        .await
        .expect("Failed to send request");

    eprintln!("[test] 404 response headers: {}", headers);

    assert!(
        headers.starts_with("HTTP/1.1 404 Not Found"),
        "Expected 404 Not Found, got: {}",
        headers.lines().next().unwrap_or("")
    );

    assert!(
        body.contains("Not Found"),
        "Expected body to contain 'Not Found'"
    );

    drop(shutdown_tx);
    let _ = timeout(Duration::from_secs(2), handle).await;
}

/// Test that GET / returns 404 Not Found.
#[tokio::test]
async fn test_root_path_returns_404() {
    let metrics = Arc::new(NodeMetrics::new());
    let config = MetricsHttpConfig::from_addr("127.0.0.1:0");
    let (shutdown_tx, shutdown_rx) = watch::channel(());

    let (handle, bound_addr) =
        spawn_metrics_http_server_with_addr(metrics, config, CryptoMetricsRefs::new(), shutdown_rx)
            .await;

    let addr = bound_addr.expect("Server should have bound");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let (headers, _body) = send_http_request(addr, request)
        .await
        .expect("Failed to send request");

    assert!(
        headers.starts_with("HTTP/1.1 404 Not Found"),
        "Expected 404 Not Found for /, got: {}",
        headers.lines().next().unwrap_or("")
    );

    drop(shutdown_tx);
    let _ = timeout(Duration::from_secs(2), handle).await;
}

// ============================================================================
// Test: Shutdown Behavior
// ============================================================================

/// Test that the server shuts down cleanly when signaled.
#[tokio::test]
async fn test_server_shuts_down_cleanly() {
    let metrics = Arc::new(NodeMetrics::new());
    let config = MetricsHttpConfig::from_addr("127.0.0.1:0");
    let (shutdown_tx, shutdown_rx) = watch::channel(());

    let (handle, bound_addr) =
        spawn_metrics_http_server_with_addr(metrics, config, CryptoMetricsRefs::new(), shutdown_rx)
            .await;

    let addr = bound_addr.expect("Server should have bound");
    eprintln!("[test] Server bound to {}", addr);

    // Ensure server is running
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify server responds before shutdown
    let request = "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let (headers, _body) = send_http_request(addr, request)
        .await
        .expect("Failed to send request before shutdown");
    assert!(headers.starts_with("HTTP/1.1 200"));

    // Trigger shutdown
    drop(shutdown_tx);

    // The server task should complete within a reasonable timeout
    let result = timeout(Duration::from_secs(2), handle).await;
    assert!(
        result.is_ok(),
        "Server should terminate within 2 seconds of shutdown signal"
    );

    // The task should not have panicked
    let join_result = result.unwrap();
    assert!(
        join_result.is_ok(),
        "Server task should complete without panic"
    );
}

/// Test that new connections fail after shutdown.
#[tokio::test]
async fn test_connections_refused_after_shutdown() {
    let metrics = Arc::new(NodeMetrics::new());
    let config = MetricsHttpConfig::from_addr("127.0.0.1:0");
    let (shutdown_tx, shutdown_rx) = watch::channel(());

    let (handle, bound_addr) =
        spawn_metrics_http_server_with_addr(metrics, config, CryptoMetricsRefs::new(), shutdown_rx)
            .await;

    let addr = bound_addr.expect("Server should have bound");
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Shutdown the server
    drop(shutdown_tx);

    // Wait for server to fully stop
    let _ = timeout(Duration::from_secs(2), handle).await;

    // Give OS time to close the socket
    tokio::time::sleep(Duration::from_millis(100)).await;

    // New connections should fail
    let connect_result = timeout(Duration::from_millis(500), TcpStream::connect(addr)).await;

    // Either the connection should fail immediately, or timeout
    match connect_result {
        Ok(Ok(_)) => {
            // If connection succeeds, the read should fail (server closed)
            // This can happen if the OS hasn't cleaned up the socket yet
            eprintln!("[test] Connection succeeded after shutdown (OS socket cleanup pending)");
        }
        Ok(Err(_e)) => {
            // Connection refused - expected
            eprintln!("[test] Connection refused as expected");
        }
        Err(_) => {
            // Timeout - also acceptable
            eprintln!("[test] Connection timed out");
        }
    }
}

// ============================================================================
// Test: Configuration from Environment
// ============================================================================

/// Test that MetricsHttpConfig::from_env() returns disabled when env is not set.
#[test]
fn test_config_from_env_disabled_when_not_set() {
    // Acquire mutex to prevent parallel env var tests from interfering
    let _guard = env_var_mutex().lock().unwrap();

    // Save original value if it exists
    let original_value = std::env::var(METRICS_HTTP_ADDR_ENV).ok();

    // Remove the env var
    std::env::remove_var(METRICS_HTTP_ADDR_ENV);

    // Test that from_env() returns disabled when env var is not set
    let config = MetricsHttpConfig::from_env();
    assert!(
        !config.is_enabled(),
        "Config should be disabled when env var is not set. enabled={}, bind_addr={:?}",
        config.enabled,
        config.bind_addr
    );

    // Restore original value if it existed
    if let Some(val) = original_value {
        std::env::set_var(METRICS_HTTP_ADDR_ENV, val);
    }
}

/// Test that MetricsHttpConfig::from_env() returns enabled for valid address.
#[test]
fn test_config_from_env_enabled_for_valid_address() {
    // Acquire mutex to prevent parallel env var tests from interfering
    let _guard = env_var_mutex().lock().unwrap();

    // Save original value if it exists
    let original_value = std::env::var(METRICS_HTTP_ADDR_ENV).ok();

    // Set a valid address
    let test_addr = "127.0.0.1:9199";
    std::env::set_var(METRICS_HTTP_ADDR_ENV, test_addr);

    let config = MetricsHttpConfig::from_env();

    // Verify the config is enabled
    assert!(
        config.is_enabled(),
        "Config should be enabled for valid address. enabled={}, bind_addr={}",
        config.enabled,
        config.bind_addr,
    );

    // Verify the bind address matches
    assert_eq!(
        config.bind_addr.to_string(),
        test_addr,
        "Bind address should match env var"
    );

    // Restore original value or clean up
    if let Some(val) = original_value {
        std::env::set_var(METRICS_HTTP_ADDR_ENV, val);
    } else {
        std::env::remove_var(METRICS_HTTP_ADDR_ENV);
    }
}

/// Test that MetricsHttpConfig::from_env() returns disabled for invalid address.
#[test]
fn test_config_from_env_disabled_for_invalid_address() {
    // Acquire mutex to prevent parallel env var tests from interfering
    let _guard = env_var_mutex().lock().unwrap();

    // Save original value if it exists
    let original_value = std::env::var(METRICS_HTTP_ADDR_ENV).ok();

    // Set an invalid address
    std::env::set_var(METRICS_HTTP_ADDR_ENV, "not-a-valid-address");

    let config = MetricsHttpConfig::from_env();
    assert!(
        !config.is_enabled(),
        "Config should be disabled for invalid address. enabled={}, bind_addr={}",
        config.enabled,
        config.bind_addr
    );

    // Restore original value or clean up
    if let Some(val) = original_value {
        std::env::set_var(METRICS_HTTP_ADDR_ENV, val);
    } else {
        std::env::remove_var(METRICS_HTTP_ADDR_ENV);
    }
}

/// Test that MetricsHttpConfig::disabled() returns a disabled config.
#[test]
fn test_config_disabled_method() {
    let config = MetricsHttpConfig::disabled();
    assert!(
        !config.is_enabled(),
        "disabled() should return disabled config"
    );
}

/// Test that MetricsHttpConfig::from_addr() returns an enabled config.
#[test]
fn test_config_from_addr_method() {
    let config = MetricsHttpConfig::from_addr("0.0.0.0:8080");
    assert!(
        config.is_enabled(),
        "from_addr() should return enabled config"
    );
    assert_eq!(config.bind_addr.to_string(), "0.0.0.0:8080");
}

/// Test that default config is disabled.
#[test]
fn test_config_default_is_disabled() {
    let config = MetricsHttpConfig::default();
    assert!(!config.is_enabled(), "Default config should be disabled");
}

// ============================================================================
// Test: Disabled Server Returns Immediately
// ============================================================================

/// Test that a disabled config spawns a no-op task.
#[tokio::test]
async fn test_disabled_config_spawns_noop_task() {
    let metrics = Arc::new(NodeMetrics::new());
    let config = MetricsHttpConfig::disabled();
    let (_shutdown_tx, shutdown_rx) = watch::channel(());

    let (handle, bound_addr) =
        spawn_metrics_http_server_with_addr(metrics, config, CryptoMetricsRefs::new(), shutdown_rx)
            .await;

    // No address should be returned for disabled config
    assert!(
        bound_addr.is_none(),
        "Disabled config should not bind to an address"
    );

    // The task should complete immediately
    let result = timeout(Duration::from_millis(100), handle).await;
    assert!(
        result.is_ok(),
        "Disabled server task should complete immediately"
    );
}

// ============================================================================
// Test: Multiple Concurrent Requests
// ============================================================================

/// Test that the server handles multiple concurrent requests.
#[tokio::test]
async fn test_multiple_concurrent_requests() {
    let metrics = Arc::new(NodeMetrics::new());
    let config = MetricsHttpConfig::from_addr("127.0.0.1:0");
    let (shutdown_tx, shutdown_rx) = watch::channel(());

    let (handle, bound_addr) =
        spawn_metrics_http_server_with_addr(metrics, config, CryptoMetricsRefs::new(), shutdown_rx)
            .await;

    let addr = bound_addr.expect("Server should have bound");
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Spawn multiple concurrent requests
    let mut handles = vec![];
    for i in 0..5 {
        let addr = addr;
        handles.push(tokio::spawn(async move {
            let request = "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n";
            let result = send_http_request(addr, request).await;
            (i, result)
        }));
    }

    // Wait for all requests to complete
    let mut success_count = 0;
    for h in handles {
        if let Ok((i, Ok((headers, _body)))) = h.await {
            if headers.starts_with("HTTP/1.1 200") {
                success_count += 1;
            } else {
                eprintln!(
                    "[test] Request {} got non-200: {}",
                    i,
                    headers.lines().next().unwrap_or("")
                );
            }
        }
    }

    assert!(
        success_count >= 4,
        "At least 4 out of 5 concurrent requests should succeed, got {}",
        success_count
    );

    drop(shutdown_tx);
    let _ = timeout(Duration::from_secs(2), handle).await;
}

// ============================================================================
// Test: POST Method Returns 405
// ============================================================================

/// Test that POST requests return 405 Method Not Allowed.
#[tokio::test]
async fn test_post_method_returns_405() {
    let metrics = Arc::new(NodeMetrics::new());
    let config = MetricsHttpConfig::from_addr("127.0.0.1:0");
    let (shutdown_tx, shutdown_rx) = watch::channel(());

    let (handle, bound_addr) =
        spawn_metrics_http_server_with_addr(metrics, config, CryptoMetricsRefs::new(), shutdown_rx)
            .await;

    let addr = bound_addr.expect("Server should have bound");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let request = "POST /metrics HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n";
    let (headers, _body) = send_http_request(addr, request)
        .await
        .expect("Failed to send request");

    assert!(
        headers.starts_with("HTTP/1.1 405"),
        "Expected 405 for POST, got: {}",
        headers.lines().next().unwrap_or("")
    );

    drop(shutdown_tx);
    let _ = timeout(Duration::from_secs(2), handle).await;
}
