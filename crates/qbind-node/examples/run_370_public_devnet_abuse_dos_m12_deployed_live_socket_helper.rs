//! Run 370 — release-built helper backing the public DevNet abuse/DoS **M12
//! deployed live-socket** release-binary evidence.
//!
//! Run 369 wired the per-peer `PeerRateLimiter` onto the DEPLOYED
//! `TcpKemTlsP2pService::read_loop` receive path via the
//! `DeployedInboundPerPeerLimiter` adapter, but the deployed builder could only
//! install that adapter with `metrics = None` (it held a `P2pMetrics`, not the
//! `NodeMetrics` that owns `qbind_net_per_peer_drops_total`). So a per-peer
//! message-rate drop on the deployed path bumped the adapter's own bounded
//! counter but never the exported `/metrics` counter.
//!
//! Run 370 threads the optional live `NodeMetrics` handle through
//! `P2pNodeBuilder::with_node_metrics` into the deployed adapter (installed by
//! `start()` via the shared `build_deployed_inbound_per_peer_limiter()` seam,
//! wired in `main.rs` with the SAME `Arc<NodeMetrics>` the live `/metrics`
//! endpoint scrapes). This helper proves, in-process, on the real release
//! artifact:
//!
//! * the DEPLOYED builder seam (the exact object `start()` installs on the
//!   `TcpKemTls` read loop) now carries the live `NodeMetrics` handle;
//! * an over-budget frame on that deployed adapter increments BOTH the adapter's
//!   own per-peer drop counter AND the exported
//!   `qbind_net_per_peer_drops_total{reason="rate_limit"}` counter rendered by
//!   `NodeMetrics::format_metrics`;
//! * under-budget frames are forwarded with no drops and no exported movement;
//! * the connection-rate limiter decision (accept-loop parity with Run 367/368)
//!   admits under-budget and refuses over-budget, incrementing only
//!   `qbind_p2p_connection_rate_drop_total`;
//! * the two controls are independent (a connection refusal never touches the
//!   per-peer counter and vice-versa);
//! * defaults (connection limiter disabled; per-peer 1000 msg/s + 100 burst) are
//!   preserved with no flags;
//! * invalid / unbounded / inconsistent configs fail closed;
//! * an enabled MainNet abuse/DoS config is refused;
//! * the hidden/devnet-only abuse/DoS CLI surface stays hidden while the real
//!   hidden flags parse and invented flags are rejected by clap.
//!
//! **HONEST SCOPE (recorded, not hidden).** This helper drives the DEPLOYED
//! adapter object synchronously (`allow_node`) — it is the same adapter
//! `start()` installs on `TcpKemTlsP2pService::read_loop`, but the helper does
//! NOT complete a full KEMTLS mutual-auth handshake and flood real bytes over
//! that read loop. The connection-rate control IS driven over real loopback
//! sockets on the release binary by the Run 370 harness. The per-peer
//! message-rate control over a fully KEMTLS-admitted deployed socket flood
//! remains the residual blocker; therefore M12 stays **Yellow/Partial**
//! (strengthened: the exported per-peer drop metric is now wired end-to-end on
//! the deployed path). See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_370.md.
//!
//! Per the Run 370 scope this helper:
//!
//! * opens no sockets and no ports; it is a pure in-process runtime-symbol proof
//!   over the deployed builder seam;
//! * does NOT launch a public DevNet, seed / bootnode / faucet / RPC / explorer /
//!   status page;
//! * does NOT mutate any live trust state, validator set, epoch, sequence, or
//!   marker;
//! * does NOT enable MainNet (an enabled MainNet abuse/DoS config never
//!   validates and is refused here);
//! * does NOT weaken peer admission, KEMTLS, trust-bundle, or genesis-hash
//!   pinning, and does NOT change any P2P wire format;
//! * exists alongside (and does NOT replace) the Run 361/362/363/365/369
//!   source/test targets and the Run 362/364/366/367/368 release helpers.
//!
//! The helper writes the following files under `<OUT_DIR>/`:
//!
//! ```text
//! <OUT_DIR>/manifest.txt           # one line per scenario: <id>\t<expected>\t<match>
//! <OUT_DIR>/scenarios/<id>.txt     # per-scenario detail
//! <OUT_DIR>/metric_evidence.txt    # rendered metric families + counters
//! <OUT_DIR>/helper_summary.txt     # release-built helper verdict
//! ```
//!
//! The helper exits non-zero if any scenario does not match its expected
//! outcome, mirroring the existing release-built-helper pattern.
//!
//! Usage:
//! ```text
//! run_370_public_devnet_abuse_dos_m12_deployed_live_socket_helper <OUT_DIR>
//! ```

use std::env;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{CommandFactory, Parser};

use qbind_node::cli::CliArgs;
use qbind_node::deployed_inbound_per_peer_limiter::DeployedInboundPerPeerLimiter;
use qbind_node::metrics::{NodeMetrics, P2pMetrics};
use qbind_node::p2p::NodeId;
use qbind_node::p2p_node_builder::P2pNodeBuilder;
use qbind_node::peer_rate_limiter::{DEFAULT_BURST_ALLOWANCE, DEFAULT_MAX_MESSAGES_PER_SECOND};
use qbind_node::public_devnet_abuse_dos_config::{AbuseDosConfig, ConnectionDecision};
use qbind_node::public_devnet_abuse_dos_runtime::PublicDevnetAbuseDosRuntimeConfig;
use qbind_types::primitives::NetworkEnvironment;

/// RFC 5737 TEST-NET-1 documentation address; never a live endpoint.
fn addr(octet: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, octet)), port)
}

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

/// Build the deployed `P2pNodeBuilder` exactly the way `main.rs` does, and (Run
/// 370) install the live `NodeMetrics` handle via `with_node_metrics` — the
/// seam that reaches the deployed inbound limiter installed on the `TcpKemTls`
/// read loop.
fn deployed_builder(args: &[&str], node_metrics: Option<Arc<NodeMetrics>>) -> P2pNodeBuilder {
    let parsed = parse_cli(args).expect("cli parses");
    let mut builder = P2pNodeBuilder::new();
    if let Some(rt) = parsed
        .abuse_dos_runtime_config()
        .expect("valid abuse/DoS config")
    {
        builder = builder.with_abuse_dos_runtime_config(rt);
    }
    if let Some(m) = node_metrics {
        builder = builder.with_node_metrics(m);
    }
    builder
}

/// Construct the DEPLOYED inbound per-peer limiter adapter through the SAME
/// builder seam `start()` uses, so the tested object matches deployment.
fn deployed_adapter(
    args: &[&str],
    node_metrics: Option<Arc<NodeMetrics>>,
) -> DeployedInboundPerPeerLimiter {
    deployed_builder(args, node_metrics).build_deployed_inbound_per_peer_limiter()
}

fn node(seed: u64) -> NodeId {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_be_bytes());
    NodeId::new(bytes)
}

struct Scenario {
    id: &'static str,
    expected: String,
    actual: String,
    matched: bool,
    detail: String,
}

fn main() {
    let out_dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("run_370_out"));
    fs::create_dir_all(&out_dir).expect("create out dir");

    let mut scenarios: Vec<Scenario> = Vec::new();

    // Scenario 01: default_preserves_behavior — no abuse/DoS flags: the deployed
    // builder derives None; the deployed adapter carries per-peer defaults
    // (1000/100); with no NodeMetrics handle the adapter's shared metric is None
    // (Run 369 posture); connection limiter disabled.
    {
        let metrics = Arc::new(P2pMetrics::new());
        let runtime = PublicDevnetAbuseDosRuntimeConfig::disabled_default();
        let state = runtime
            .into_runtime_state(Some(Arc::clone(&metrics)))
            .unwrap();
        let now = Instant::now();
        let mut all_admitted = true;
        for i in 0..1000u16 {
            if !state.should_admit(addr(1, i), now) {
                all_admitted = false;
            }
        }
        let builder = deployed_builder(&[], None);
        let derived_none = builder.deployed_peer_rate_limiter_config().is_none();
        let adapter = builder.build_deployed_inbound_per_peer_limiter();
        let ok = all_admitted
            && !state.connection_limiter_enabled()
            && state.drop_count() == 0
            && metrics.connection_rate_drop_total() == 0
            && derived_none
            && !adapter.has_metrics()
            && adapter.config().max_messages_per_second == DEFAULT_MAX_MESSAGES_PER_SECOND
            && adapter.config().burst_allowance == DEFAULT_BURST_ALLOWANCE
            && adapter.config().max_messages_per_second == 1000
            && adapter.config().burst_allowance == 100;
        scenarios.push(Scenario {
            id: "01_default_preserves_behavior",
            expected: "deployed builder derives None; adapter metrics None; per-peer 1000/100; conn disabled; drop metric 0"
                .to_string(),
            actual: format!(
                "conn_enabled={} admitted_all={} conn_metric={} derived_none={} adapter_has_metrics={} per_peer_max={} per_peer_burst={}",
                state.connection_limiter_enabled(),
                all_admitted,
                metrics.connection_rate_drop_total(),
                derived_none,
                adapter.has_metrics(),
                adapter.config().max_messages_per_second,
                adapter.config().burst_allowance,
            ),
            matched: ok,
            detail: "No abuse/DoS flags: connection limiter stays disabled; the DEPLOYED \
                     P2pNodeBuilder derives None and installs the inbound adapter with \
                     PeerRateLimiter defaults (1000 msg/s + 100 burst) and metrics = None \
                     (Run 369 posture), preserved bit-for-bit."
                .to_string(),
        });
    }

    // Scenario 02: hidden_cli_surface_checked — hidden flags absent from --help;
    // real hidden flags parse; invented flags rejected by clap.
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
            && parse_cli(&["--p2p-burst-allowance", "60"]).is_ok()
            && parse_cli(&[
                "--p2p-connection-rate-limit-enabled",
                "--p2p-connection-rate-window-ms",
                "1000",
                "--p2p-connection-rate-max",
                "20",
            ])
            .is_ok();
        let invented_rejected = parse_cli(&["--p2p-node-metrics", "on"]).is_err()
            && parse_cli(&["--p2p-per-peer-metrics-enabled"]).is_err()
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
            detail: "The Run 362/363 abuse/DoS flags stay hidden/devnet-only; Run 370 adds no \
                     new public CLI surface (the NodeMetrics handle is a builder-internal Arc). \
                     Real hidden flags parse; invented flags are rejected by clap."
                .to_string(),
        });
    }

    // Scenario 03: invalid_configs_fail_closed — zero window / zero max /
    // zero conn-max / unbounded all rejected before any runtime state exists.
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
        let ok = r_window.is_err()
            && r_zero_msg.is_err()
            && r_zero_conn.is_err()
            && r_unbounded.is_err();
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
            detail: "Every nonsensical abuse/DoS value fails closed at config validation; no \
                     runtime state and no deployed adapter is ever built."
                .to_string(),
        });
    }

    // Scenario 04: mainnet_refused — an enabled MainNet abuse/DoS config is
    // refused, both directly and via the CLI.
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
                     validates and no runtime state or deployed adapter exists."
                .to_string(),
        });
    }

    // Scenario 05: connection_rate_live_socket_under_budget — the exact runtime
    // decision the live accept loop makes (the Run 370 harness re-runs this over
    // real loopback TCP on the release binary): N under-budget admitted, metric 0.
    {
        let metrics = Arc::new(P2pMetrics::new());
        let mut cfg = AbuseDosConfig::public_devnet_recommended();
        cfg.max_connections_per_window = 4;
        cfg.connection_burst_allowance = 0;
        cfg.per_address_rate_window = None;
        let state = PublicDevnetAbuseDosRuntimeConfig::from_config(cfg)
            .unwrap()
            .into_runtime_state(Some(Arc::clone(&metrics)))
            .unwrap();
        let now = Instant::now();
        let mut admitted = 0u64;
        for i in 0..4u16 {
            if state.should_admit(addr(1, i), now) {
                admitted += 1;
            }
        }
        let ok = admitted == 4 && metrics.connection_rate_drop_total() == 0 && state.drop_count() == 0;
        scenarios.push(Scenario {
            id: "05_connection_rate_live_socket_under_budget",
            expected: "4 under-budget connections admitted; conn drop metric 0".to_string(),
            actual: format!(
                "admitted={} conn_metric={} drop_count={}",
                admitted,
                metrics.connection_rate_drop_total(),
                state.drop_count()
            ),
            matched: ok,
            detail: "The connection-rate limiter admits under-budget inbound connections and \
                     leaves qbind_p2p_connection_rate_drop_total at 0; the Run 370 harness \
                     drives this over real loopback TCP on target/release/qbind-node."
                .to_string(),
        });
    }

    // Scenario 06: connection_rate_live_socket_over_budget — over-budget refused;
    // metric increments per refusal; no peer admitted on refusal.
    {
        let metrics = Arc::new(P2pMetrics::new());
        let mut cfg = AbuseDosConfig::public_devnet_recommended();
        cfg.max_connections_per_window = 4;
        cfg.connection_burst_allowance = 0;
        cfg.per_address_rate_window = None;
        let state = PublicDevnetAbuseDosRuntimeConfig::from_config(cfg)
            .unwrap()
            .into_runtime_state(Some(Arc::clone(&metrics)))
            .unwrap();
        let now = Instant::now();
        for i in 0..4u16 {
            let _ = state.should_admit(addr(1, i), now);
        }
        let metric_before = metrics.connection_rate_drop_total();
        let over1 = state.check_inbound(addr(1, 900), now);
        let over2 = state.check_inbound(addr(1, 901), now);
        let admitted_on_refusal = state.should_admit(addr(1, 902), now);
        let ok = metric_before == 0
            && over1 == ConnectionDecision::ConnectionRateLimited
            && over2 == ConnectionDecision::ConnectionRateLimited
            && !admitted_on_refusal
            && metrics.connection_rate_drop_total() == 3
            && state.drop_count() == 3;
        scenarios.push(Scenario {
            id: "06_connection_rate_live_socket_over_budget",
            expected: "over-budget ConnectionRateLimited; no admit on refusal; conn metric increments per refusal"
                .to_string(),
            actual: format!(
                "over1={:?} over2={:?} admitted_on_refusal={} metric_before={} metric_after={} drop_count={}",
                over1,
                over2,
                admitted_on_refusal,
                metric_before,
                metrics.connection_rate_drop_total(),
                state.drop_count()
            ),
            matched: ok,
            detail: "Over-budget inbound connections are refused (ConnectionRateLimited) with no \
                     peer admitted; qbind_p2p_connection_rate_drop_total increments by exactly \
                     the refusal count. The Run 370 harness proves this over real loopback TCP."
                .to_string(),
        });
    }

    // Scenario 07: per_peer_deployed_live_socket_under_budget — the DEPLOYED
    // adapter (built via the builder seam, WITH the live NodeMetrics handle)
    // forwards exactly-capacity frames: 0 drops, exported metric stays 0.
    {
        let metrics = Arc::new(NodeMetrics::new());
        let adapter = deployed_adapter(
            &["--p2p-max-messages-per-second", "5", "--p2p-burst-allowance", "0"],
            Some(Arc::clone(&metrics)),
        );
        let now = Instant::now();
        let n = node(7);
        let mut all_forwarded = true;
        for _ in 0..5 {
            if !adapter.allow_node(&n, now) {
                all_forwarded = false;
            }
        }
        let exported = metrics.peer_network().total_rate_limit_drops();
        let ok = adapter.has_metrics()
            && adapter.config().max_messages_per_second == 5
            && all_forwarded
            && adapter.drop_count() == 0
            && exported == 0;
        scenarios.push(Scenario {
            id: "07_per_peer_deployed_live_socket_under_budget",
            expected: "deployed adapter (bucket 5/0, NodeMetrics installed) forwards 5 frames; 0 drops; exported metric 0"
                .to_string(),
            actual: format!(
                "has_metrics={} bucket_max={} all_forwarded={} adapter_drops={} exported_drops={}",
                adapter.has_metrics(),
                adapter.config().max_messages_per_second,
                all_forwarded,
                adapter.drop_count(),
                exported
            ),
            matched: ok,
            detail: "The exact adapter object start() installs on TcpKemTlsP2pService::read_loop \
                     (built via build_deployed_inbound_per_peer_limiter with the live NodeMetrics \
                     handle) forwards under-budget frames and leaves \
                     qbind_net_per_peer_drops_total at 0."
                .to_string(),
        });
    }

    // Scenario 08: per_peer_deployed_live_socket_over_budget — the DEPLOYED
    // adapter drops over-budget frames; BOTH the adapter's own counter AND the
    // exported qbind_net_per_peer_drops_total{reason="rate_limit"} increment.
    {
        let metrics = Arc::new(NodeMetrics::new());
        let adapter = deployed_adapter(
            &["--p2p-max-messages-per-second", "5", "--p2p-burst-allowance", "0"],
            Some(Arc::clone(&metrics)),
        );
        let now = Instant::now();
        let n = node(9);
        let key = DeployedInboundPerPeerLimiter::bucket_key(&n);
        // Drain capacity, then flood 20 over-budget frames in the same instant.
        for _ in 0..5 {
            assert!(adapter.allow_node(&n, now));
        }
        let mut dropped = 0u64;
        for _ in 0..20 {
            if !adapter.allow_node(&n, now) {
                dropped += 1;
            }
        }
        let exported_total = metrics.peer_network().total_rate_limit_drops();
        let exported_peer = metrics
            .peer_network()
            .peer_rate_limit_drop_count(key)
            .unwrap_or(0);
        let rendered = metrics.format_metrics();
        let family_present = rendered.contains("qbind_net_per_peer_drops_total")
            && rendered.contains("reason=\"rate_limit\"");
        let ok = dropped == 20
            && adapter.drop_count() == 20
            && exported_total == 20
            && exported_peer == 20
            && family_present;
        scenarios.push(Scenario {
            id: "08_per_peer_deployed_live_socket_over_budget",
            expected: "deployed adapter drops 20 over-budget frames; adapter + exported per-peer counter both == 20; family rendered"
                .to_string(),
            actual: format!(
                "dropped={} adapter_drops={} exported_total={} exported_peer={} family_present={}",
                dropped,
                adapter.drop_count(),
                exported_total,
                exported_peer,
                family_present
            ),
            matched: ok,
            detail: "Over-budget frames on the DEPLOYED adapter are dropped before demuxer \
                     dispatch; Run 370's NodeMetrics threading makes the drop observable on the \
                     exported qbind_net_per_peer_drops_total{reason=\"rate_limit\"} counter served \
                     from NodeMetrics::format_metrics — the metric the live /metrics endpoint \
                     scrapes."
                .to_string(),
        });
    }

    // Scenario 09: combined_limiter_independence — a connection-rate refusal
    // increments only the connection metric; a per-peer message drop increments
    // only the per-peer counter. Counters are distinct objects.
    {
        let conn_metrics = Arc::new(P2pMetrics::new());
        let mut conn_cfg = AbuseDosConfig::public_devnet_recommended();
        conn_cfg.max_connections_per_window = 1;
        conn_cfg.connection_burst_allowance = 0;
        conn_cfg.per_address_rate_window = None;
        let state = PublicDevnetAbuseDosRuntimeConfig::from_config(conn_cfg)
            .unwrap()
            .into_runtime_state(Some(Arc::clone(&conn_metrics)))
            .unwrap();
        let now = Instant::now();
        let first_admitted = state.should_admit(addr(1, 1), now);
        let second_admitted = state.should_admit(addr(1, 2), now);
        let conn_after = conn_metrics.connection_rate_drop_total();

        // Independent per-peer drop on the deployed adapter.
        let peer_metrics = Arc::new(NodeMetrics::new());
        let adapter = deployed_adapter(
            &["--p2p-max-messages-per-second", "1", "--p2p-burst-allowance", "0"],
            Some(Arc::clone(&peer_metrics)),
        );
        let n = node(13);
        assert!(adapter.allow_node(&n, now));
        assert!(!adapter.allow_node(&n, now)); // per-peer drop
        let per_peer_drops = peer_metrics.peer_network().total_rate_limit_drops();
        let conn_final = conn_metrics.connection_rate_drop_total();

        let ok = first_admitted
            && !second_admitted
            && conn_after == 1
            && per_peer_drops == 1
            && conn_final == 1;
        scenarios.push(Scenario {
            id: "09_combined_limiter_independence",
            expected: "conn refusal increments only conn metric; per-peer drop increments only per-peer counter"
                .to_string(),
            actual: format!(
                "first_admitted={} second_admitted={} conn_metric={} per_peer_drops={}",
                first_admitted, second_admitted, conn_final, per_peer_drops
            ),
            matched: ok,
            detail: "The connection-rate limiter (accept path, P2pMetrics) and the deployed \
                     per-peer message-rate adapter (read_loop, NodeMetrics::peer_network) are \
                     independent objects; a connection refusal never touches the per-peer \
                     counter and vice-versa."
                .to_string(),
        });
    }

    // Scenario 10: metrics_export_live — the connection-rate family renders
    // exactly once with no endpoint labels; the per-peer rate-limit family renders
    // on the live NodeMetrics after a deployed-adapter over-budget drop.
    let conn_rendered = {
        let m = P2pMetrics::new();
        m.record_connection_rate_drop();
        m.format_metrics()
    };
    let conn_family_count = conn_rendered
        .matches("qbind_p2p_connection_rate_drop_total")
        .count();
    let conn_label_leak = conn_rendered.contains("qbind_p2p_connection_rate_drop_total{");
    let conn_line = conn_rendered
        .lines()
        .find(|l| l.starts_with("qbind_p2p_connection_rate_drop_total"))
        .unwrap_or("<absent>")
        .to_string();

    let per_peer_metrics = Arc::new(NodeMetrics::new());
    let per_peer_adapter = deployed_adapter(
        &["--p2p-max-messages-per-second", "1", "--p2p-burst-allowance", "0"],
        Some(Arc::clone(&per_peer_metrics)),
    );
    {
        let now = Instant::now();
        let n = node(21);
        assert!(per_peer_adapter.allow_node(&n, now));
        for _ in 0..5 {
            let _ = per_peer_adapter.allow_node(&n, now);
        }
    }
    let per_peer_drops = per_peer_metrics.peer_network().total_rate_limit_drops();
    let node_rendered = per_peer_metrics.format_metrics();
    let per_peer_family_present = node_rendered.contains("qbind_net_per_peer_drops_total")
        && node_rendered.contains("reason=\"rate_limit\"");
    let per_peer_line = node_rendered
        .lines()
        .find(|l| l.starts_with("qbind_net_per_peer_drops_total"))
        .unwrap_or("<absent>")
        .to_string();

    let metric_ok = conn_family_count == 1
        && !conn_label_leak
        && per_peer_drops >= 1
        && per_peer_family_present;
    {
        let ok = metric_ok;
        scenarios.push(Scenario {
            id: "10_metrics_export_live",
            expected: "conn family once (no endpoint labels); per-peer family present after deployed-adapter drop"
                .to_string(),
            actual: format!(
                "conn_family_count={} conn_label_leak={} per_peer_drops={} per_peer_family_present={}",
                conn_family_count, conn_label_leak, per_peer_drops, per_peer_family_present
            ),
            matched: ok,
            detail: "NodeMetrics::format_metrics (the live /metrics body) renders \
                     qbind_net_per_peer_drops_total{reason=\"rate_limit\"} after the deployed \
                     adapter drops an over-budget frame, and the connection-rate family renders \
                     exactly once with no endpoint labels."
                .to_string(),
        });
    }

    write_file(
        &out_dir.join("metric_evidence.txt"),
        &format!(
            "conn_metric_name: qbind_p2p_connection_rate_drop_total\n\
             conn_registered_once: {}\n\
             conn_endpoint_label_leak: {}\n\
             conn_rendered_line: {}\n\
             per_peer_metric_name: qbind_net_per_peer_drops_total\n\
             per_peer_family_present: {}\n\
             per_peer_rendered_line: {}\n\
             per_peer_drops_observed: {}\n",
            conn_family_count == 1,
            conn_label_leak,
            conn_line,
            per_peer_family_present,
            per_peer_line,
            per_peer_drops,
        ),
    );

    // Per-scenario files + manifest.
    let mut manifest = String::new();
    for s in &scenarios {
        write_file(
            &out_dir.join("scenarios").join(format!("{}.txt", s.id)),
            &format!(
                "id: {}\nexpected: {}\nactual: {}\nmatch: {}\nnote: {}\n",
                s.id, s.expected, s.actual, s.matched, s.detail
            ),
        );
        manifest.push_str(&format!("{}\t{}\t{}\n", s.id, s.expected, s.matched));
    }
    write_file(&out_dir.join("manifest.txt"), &manifest);

    let all_scenarios_ok = scenarios.iter().all(|s| s.matched);
    let all_ok = all_scenarios_ok && metric_ok;

    let summary = format!(
        "Run 370 — public DevNet abuse/DoS M12 deployed live-socket helper\n\
         scenarios_total: {}\n\
         scenarios_passed: {}\n\
         conn_metric_registered_once: {}\n\
         conn_metric_no_endpoint_label: {}\n\
         per_peer_drop_family_present: {}\n\
         per_peer_drops_observed: {}\n\
         verdict: {}\n\
         notes: Run 370 threads a live NodeMetrics handle through \
         P2pNodeBuilder::with_node_metrics into the DEPLOYED inbound per-peer adapter \
         (build_deployed_inbound_per_peer_limiter, the exact object start() installs on \
         TcpKemTlsP2pService::read_loop). An over-budget frame on that deployed adapter now \
         increments BOTH the adapter's own counter AND the exported \
         qbind_net_per_peer_drops_total{{reason=\"rate_limit\"}} counter served from \
         NodeMetrics::format_metrics; the connection-rate control (accept path) admits \
         under-budget and refuses over-budget on only qbind_p2p_connection_rate_drop_total; the \
         two are independent; defaults preserved; invalid/unbounded/MainNet fail closed; hidden \
         CLI surface preserved. HONEST SCOPE: this helper drives the deployed adapter \
         synchronously (no KEMTLS-admitted real-socket byte flood over read_loop); the \
         connection-rate control IS driven over real sockets on the release binary by the Run \
         370 harness. The KEMTLS-admitted deployed per-peer socket flood remains the residual \
         blocker, so M12 stays Yellow/Partial (strengthened). No socket opened; MainNet refused; \
         no trust/validator/epoch/sequence mutation; no wire-format change; no launch claim.\n",
        scenarios.len(),
        scenarios.iter().filter(|s| s.matched).count(),
        conn_family_count == 1,
        !conn_label_leak,
        per_peer_family_present,
        per_peer_drops,
        if all_ok { "PASS" } else { "FAIL" }
    );
    write_file(&out_dir.join("helper_summary.txt"), &summary);
    print!("{summary}");

    if !all_ok {
        eprintln!("[run_370_helper] FAIL: one or more scenarios did not match");
        std::process::exit(1);
    }
}
