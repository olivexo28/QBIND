//! Binary-path operability tests for B1 + B2 + B4
//! (`docs/protocol/QBIND_REPO_CODE_DOC_ALIGNMENT_AUDIT.md` §9).
//!
//! These tests cover the three execution-unblock items:
//!
//! - **B1**: the consensus loop launched by `qbind-node` (single-validator
//!   smoke) actually proposes, self-quorums, advances views and commits.
//! - **B2**: the metrics HTTP endpoint is spawned with the same code path
//!   the binary uses (env-var gated) and serves `/metrics`.
//! - **B4**: no high-visibility code/test/comment still points at deleted
//!   legacy MainNet docs (`QBIND_MAINNET_V0_SPEC.md`,
//!   `QBIND_MAINNET_AUDIT_SKELETON.md`, `QBIND_MAINNET_RUNBOOK.md`).
//!
//! These tests intentionally do not spawn a child `qbind-node` process —
//! they exercise the same library entry points the binary calls
//! (`spawn_binary_consensus_loop`, `spawn_metrics_http_server_with_crypto`
//! gated by `MetricsHttpConfig::from_env`).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::timeout;

use qbind_consensus::ids::ValidatorId;
use qbind_node::binary_consensus_loop::{
    spawn_binary_consensus_loop, BinaryConsensusLoopConfig,
};
use qbind_node::metrics::NodeMetrics;
use qbind_node::metrics_http::{
    spawn_metrics_http_server_with_addr, CryptoMetricsRefs, MetricsHttpConfig,
};

// ============================================================================
// B1: consensus loop is real, not a stub
// ============================================================================

/// B1 smoke test: a single-validator binary consensus loop actually advances
/// past view 0 and emits at least one proposal within a short wall-clock
/// window. This test would FAIL if the binary path went back to being a
/// "build transport and idle" stub — the previous behavior captured by C4
/// in `docs/whitepaper/contradiction.md`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b1_binary_consensus_loop_actually_drives_consensus() {
    let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 1)
        .with_tick_interval(Duration::from_millis(5))
        .with_max_ticks(40);

    let (_shutdown_tx, shutdown_rx) = watch::channel(());
    let (handle, progress) = spawn_binary_consensus_loop(cfg, shutdown_rx);

    let final_progress = timeout(Duration::from_secs(5), handle)
        .await
        .expect("binary consensus loop did not finish within 5s")
        .expect("binary consensus loop task panicked");

    assert!(
        final_progress.proposals_emitted >= 1,
        "single-validator binary consensus loop must emit at least one \
         BroadcastProposal (audit B1: stub path emitted zero); got \
         proposals_emitted={}",
        final_progress.proposals_emitted
    );
    assert!(
        final_progress.current_view > 0,
        "single-validator binary consensus loop must advance past view 0; \
         got current_view={}",
        final_progress.current_view
    );
    // Sanity: the live progress snapshot exposed to the caller is also moving.
    let live = progress.lock().clone();
    assert_eq!(live.current_view, final_progress.current_view);
}

// ============================================================================
// B2: metrics endpoint can be spawned from the binary path
// ============================================================================

/// B2: when `MetricsHttpConfig::is_enabled()` (the same gate the binary
/// uses), `spawn_metrics_http_server_with_addr` actually binds and serves a
/// 200 OK response on `GET /metrics`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b2_metrics_http_server_serves_when_enabled() {
    let metrics = Arc::new(NodeMetrics::new());
    let cfg = MetricsHttpConfig::from_addr("127.0.0.1:0");
    assert!(cfg.is_enabled());

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let (handle, bound_addr) = spawn_metrics_http_server_with_addr(
        metrics,
        cfg,
        CryptoMetricsRefs::new(),
        shutdown_rx,
    )
    .await;

    let addr = bound_addr.expect("metrics server should bind when enabled");

    // Issue a GET /metrics request.
    let mut stream = TcpStream::connect(addr).await.expect("connect /metrics");
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");

    let mut buf = Vec::new();
    timeout(Duration::from_secs(3), stream.read_to_end(&mut buf))
        .await
        .expect("read /metrics response within 3s")
        .expect("read /metrics body");

    let resp = String::from_utf8_lossy(&buf);
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "expected HTTP 200 from /metrics, got: {}",
        resp.lines().next().unwrap_or("")
    );

    drop(shutdown_tx);
    let _ = timeout(Duration::from_secs(3), handle).await;
}

/// B2: when the metrics config is disabled (the `QBIND_METRICS_HTTP_ADDR`
/// env-var unset path), the server is NOT bound — the spawn returns a
/// no-op join handle and no listener address.
#[tokio::test]
async fn b2_metrics_http_server_disabled_by_default() {
    let metrics = Arc::new(NodeMetrics::new());
    let cfg = MetricsHttpConfig::disabled();
    assert!(!cfg.is_enabled());

    let (_shutdown_tx, shutdown_rx) = watch::channel(());
    let (_handle, bound_addr) = spawn_metrics_http_server_with_addr(
        metrics,
        cfg,
        CryptoMetricsRefs::new(),
        shutdown_rx,
    )
    .await;

    assert!(
        bound_addr.is_none(),
        "disabled metrics config must not bind a listener"
    );
}

// ============================================================================
// B4: no stale legacy doc anchors in code/tests/comments
// ============================================================================

const LEGACY_DOC_NAMES: &[&str] = &[
    "QBIND_MAINNET_V0_SPEC.md",
    "QBIND_MAINNET_AUDIT_SKELETON.md",
    "QBIND_MAINNET_RUNBOOK.md",
];

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is `crates/qbind-node`; repo root is two levels up.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("repo root resolves from CARGO_MANIFEST_DIR")
}

fn scan_dir_for_legacy_refs(dir: &Path, hits: &mut Vec<(PathBuf, usize, String)>) {
    if !dir.is_dir() {
        return;
    }
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            // Skip target/ and .git/ but scan everything else.
            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                if matches!(name, "target" | ".git" | "node_modules") {
                    continue;
                }
            }
            scan_dir_for_legacy_refs(&path, hits);
        } else {
            let ext_ok = path
                .extension()
                .and_then(|s| s.to_str())
                .map(|e| matches!(e, "rs" | "sh" | "toml"))
                .unwrap_or(false);
            if !ext_ok {
                continue;
            }
            // The B4 regression test itself must mention the legacy names
            // (it is the allow-list / scanner). Skip it.
            if path
                .file_name()
                .and_then(|s| s.to_str())
                .map(|n| n == "binary_path_b1_b2_b4_tests.rs")
                .unwrap_or(false)
            {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            for (i, line) in content.lines().enumerate() {
                for legacy in LEGACY_DOC_NAMES {
                    if !line.contains(legacy) {
                        continue;
                    }
                    // Allow lines that explicitly mark the reference as
                    // historical/retired context. Operators following such
                    // a line will not be misled into looking for a live
                    // doc — they will see "retired" / "legacy" / "B4" /
                    // "EXE-1" and look at the canonical replacement.
                    let lower = line.to_ascii_lowercase();
                    let is_historical = lower.contains("retired")
                        || lower.contains("legacy")
                        || lower.contains("deprecated")
                        || lower.contains("b4 in ")
                        || lower.contains("(b4 ")
                        || lower.contains("b4)")
                        || lower.contains("exe-1");
                    if is_historical {
                        continue;
                    }
                    hits.push((path.clone(), i + 1, line.to_string()));
                }
            }
        }
    }
}

/// B4: code, tests and shell scripts must not contain references to the
/// retired legacy MainNet docs (`QBIND_MAINNET_V0_SPEC.md`,
/// `QBIND_MAINNET_AUDIT_SKELETON.md`, `QBIND_MAINNET_RUNBOOK.md`). Each
/// offending hit must be retargeted to the current canonical docs (see B4
/// in `docs/protocol/QBIND_REPO_CODE_DOC_ALIGNMENT_AUDIT.md` §9).
///
/// Documentation files under `docs/` are intentionally excluded — those may
/// legitimately discuss the retirement of the legacy names.
#[test]
fn b4_no_stale_legacy_mainnet_doc_refs_in_code_or_tests() {
    let root = repo_root();
    let mut hits: Vec<(PathBuf, usize, String)> = Vec::new();

    // Scope: crates/ and scripts/. (docs/ retains commentary about retirement.)
    scan_dir_for_legacy_refs(&root.join("crates"), &mut hits);
    scan_dir_for_legacy_refs(&root.join("scripts"), &mut hits);

    if !hits.is_empty() {
        let mut report = String::from(
            "Found stale legacy doc references that B4 should have cleaned. \
             Retarget to docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md / \
             docs/ops/QBIND_MAINNET_CUTOVER_RUNBOOK.md / \
             docs/protocol/QBIND_PROTOCOL_REPORT.md as appropriate:\n",
        );
        for (path, line_no, line) in &hits {
            report.push_str(&format!(
                "  {}:{}: {}\n",
                path.strip_prefix(&root).unwrap_or(path).display(),
                line_no,
                line.trim()
            ));
        }
        panic!("{}", report);
    }
}