//! Run 368 — release-built helper backing the public DevNet abuse/DoS **M12
//! admitted-peer message-rate live-socket** evidence attempt.
//!
//! Run 367 proved the *connection-rate* control live-socket on the real
//! `target/release/qbind-node` (over-budget inbound TCP connections refused,
//! `qbind_p2p_connection_rate_drop_total` increments) but left M12
//! Yellow/Partial because the *per-peer message-rate* control was only proven
//! through the DEPLOYED `P2pNodeBuilder` construction path (a synchronous
//! `PeerRateLimiter::allow()` call), never over an admitted peer's real socket
//! receive loop.
//!
//! Run 368 strengthens the per-peer evidence: this helper stands up a real
//! loopback TCP socket pair, registers one side as an **admitted peer** on a
//! live `AsyncPeerManagerImpl` (the component that owns the per-peer
//! `PeerRateLimiter`), and floods length-prefixed `NetMessage` frames from the
//! other side. It proves, over a real socket and through the actual async
//! `peer_reader_task` receive loop:
//!
//! * under-budget messages are accepted (no per-peer drop);
//! * over-budget messages are dropped by the live `PeerRateLimiter`;
//! * the live `NodeMetrics::peer_network().total_rate_limit_drops()` /
//!   `peer_rate_limit_drop_count(peer)` counter reflects the drops;
//! * the connection-rate metric (`P2pMetrics`) does NOT move for per-peer
//!   message drops (the two controls are independent);
//! * defaults (`1000` msg/s + `100` burst; connection limiter disabled) are
//!   preserved with no flags;
//! * invalid / unbounded / inconsistent configs fail closed;
//! * an enabled MainNet abuse/DoS config is refused;
//! * the hidden/devnet-only CLI surface stays hidden while the real hidden flags
//!   parse and invented flags are rejected by clap.
//!
//! **HONEST SCOPE (recorded, not hidden).** The admitted-peer receive loop
//! exercised here is `AsyncPeerManagerImpl::peer_reader_task`, which is the
//! component that *owns* the per-peer `PeerRateLimiter`. The DEPLOYED
//! `qbind-node` binary's live inbound path is `TcpKemTlsP2pService::subscribe()`
//! → `P2pInboundDemuxer` → handlers (see `p2p_node_builder.rs`), and that path
//! does **not** consult the `PeerRateLimiter`; `build_deployed_peer_manager()`
//! is construction-path-only and is never spawned by `main.rs`. Therefore this
//! helper proves per-peer message-rate enforcement over a real socket **at the
//! `AsyncPeerManagerImpl` layer only**, and the admission here is a plain-TCP
//! admitted peer, not a full KEMTLS mutual-auth handshake. Per the Run 368
//! decision gate (Route C), M12 stays **Yellow/Partial**: the remaining blocker
//! is wiring the `PeerRateLimiter` onto the deployed TcpKemTls receive path.
//!
//! Per `task/RUN_368_TASK.txt`, this helper is fixture-tooling and:
//!
//! * opens only bounded loopback (`127.0.0.1`) sockets it also closes; it does
//!   NOT launch a public DevNet, deploy a seed / bootnode / faucet / RPC /
//!   explorer / status page, or open a default-open public port;
//! * does NOT mutate any live trust state, validator set, epoch, or write any
//!   sequence / marker / trust-bundle file;
//! * does NOT enable MainNet (an enabled MainNet abuse/DoS config never
//!   validates and is refused here);
//! * does NOT weaken peer admission, KEMTLS, trust-bundle, or genesis-hash
//!   pinning, and does NOT change any P2P wire format;
//! * exists alongside (and does NOT replace) the Run 361/362/363/365 source/test
//!   targets and the Run 362/364/366/367 release helpers.
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
//! run_368_public_devnet_abuse_dos_per_peer_live_socket_helper <OUT_DIR>
//! ```

use std::env;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{CommandFactory, Parser};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use qbind_node::async_peer_manager::AsyncPeerManagerImpl;
use qbind_node::cli::CliArgs;
use qbind_node::metrics::{NodeMetrics, P2pMetrics};
use qbind_node::p2p_node_builder::P2pNodeBuilder;
use qbind_node::peer::PeerId;
use qbind_node::peer_rate_limiter::{
    PeerRateLimiter, DEFAULT_BURST_ALLOWANCE, DEFAULT_MAX_MESSAGES_PER_SECOND,
};
use qbind_node::public_devnet_abuse_dos_config::{AbuseDosConfig, ConnectionDecision};
use qbind_node::public_devnet_abuse_dos_runtime::PublicDevnetAbuseDosRuntimeConfig;
use qbind_types::primitives::NetworkEnvironment;
use qbind_wire::net::NetMessage;

fn addr(octet: u8, port: u16) -> SocketAddr {
    // RFC 5737 TEST-NET-1 documentation address; never a live endpoint.
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, octet)), port)
}

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent dir");
    }
    let mut f = fs::File::create(path).expect("create file");
    f.write_all(contents.as_bytes()).expect("write file");
}

/// Parse CLI args exactly as the production binary would (hidden/devnet-only
/// abuse/DoS flags included), so the helper exercises the same clap surface.
fn parse_cli(args: &[&str]) -> Result<CliArgs, clap::Error> {
    let mut full = vec!["qbind-node"];
    full.extend_from_slice(args);
    CliArgs::try_parse_from(full)
}

/// Build the deployed `P2pNodeBuilder` exactly the way `main.rs` does: parse the
/// CLI, and if the hidden abuse/DoS flags produced a validated runtime config,
/// install it via `with_abuse_dos_runtime_config`.
fn deployed_builder_from_cli(args: &[&str]) -> P2pNodeBuilder {
    let parsed = parse_cli(args).expect("cli parses");
    let mut builder = P2pNodeBuilder::new();
    if let Some(rt) = parsed
        .abuse_dos_runtime_config()
        .expect("valid abuse/DoS config")
    {
        builder = builder.with_abuse_dos_runtime_config(rt);
    }
    builder
}

/// Build the live `AsyncPeerManagerImpl` (with metrics) that owns the per-peer
/// `PeerRateLimiter`, threaded with the CLI-derived per-peer message-rate config
/// via the Run 365 deployed builder config.
fn peer_manager_with_metrics(args: &[&str], metrics: Arc<NodeMetrics>) -> Arc<AsyncPeerManagerImpl> {
    let cfg = deployed_builder_from_cli(args).deployed_async_peer_manager_config();
    Arc::new(AsyncPeerManagerImpl::with_metrics(cfg, metrics))
}

/// Frame a `NetMessage` the way `AsyncPeerManagerImpl::peer_reader_task` expects:
/// 4-byte big-endian length prefix followed by the encoded message body.
fn frame(msg: &NetMessage) -> Vec<u8> {
    let body = msg.encode_to_vec().expect("encode NetMessage");
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Create a connected pair of loopback TCP streams (client, server).
async fn connected_streams() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
    let local = listener.local_addr().expect("local addr");
    let (client_res, accept_res) = tokio::join!(TcpStream::connect(local), listener.accept());
    let client = client_res.expect("connect");
    let (server, _peer) = accept_res.expect("accept");
    (client, server)
}

/// Send `count` `Ping` frames over `client`, flushing after each so the admitted
/// peer's reader observes distinct messages.
async fn flood_pings(client: &mut TcpStream, count: u64) {
    for nonce in 0..count {
        let bytes = frame(&NetMessage::Ping(nonce));
        client.write_all(&bytes).await.expect("write ping frame");
    }
    client.flush().await.expect("flush");
}

struct Scenario {
    id: &'static str,
    expected: String,
    actual: String,
    matched: bool,
    detail: String,
}

/// Drive `count` framed pings into an admitted peer on `pm` and wait for the
/// reader loop to drain them, returning the observed per-peer rate-limit drop
/// count for the peer. `client`/`server` are a fresh connected pair; `server` is
/// registered as the admitted peer and `client` is the flooding sender.
async fn admitted_peer_flood(
    pm: &Arc<AsyncPeerManagerImpl>,
    metrics: &Arc<NodeMetrics>,
    peer: PeerId,
    count: u64,
) -> (usize, u64) {
    let (mut client, server) = connected_streams().await;
    pm.add_peer_with_stream(peer, server)
        .await
        .expect("register admitted peer");
    let peer_count = pm.peer_count().await;
    flood_pings(&mut client, count).await;

    // Wait for the reader loop to consume every framed message. The reader reads
    // each 4-byte length + body then applies the limiter, so once the counter
    // stabilises across two consecutive polls all messages have been processed.
    let mut last = metrics.peer_network().total_rate_limit_drops();
    let mut stable = 0u32;
    for _ in 0..200 {
        tokio::time::sleep(Duration::from_millis(25)).await;
        let now = metrics.peer_network().total_rate_limit_drops();
        if now == last {
            stable += 1;
            if stable >= 4 {
                break;
            }
        } else {
            stable = 0;
            last = now;
        }
    }
    // Close the sender so the peer reader task winds down cleanly.
    let _ = client.shutdown().await;
    let drops = metrics
        .peer_network()
        .peer_rate_limit_drop_count(peer)
        .unwrap_or(0);
    (peer_count, drops)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let out_dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("run_368_out"));
    fs::create_dir_all(&out_dir).expect("create out dir");

    let mut scenarios: Vec<Scenario> = Vec::new();

    // Scenario 01: default_preserves_behavior — no abuse/DoS flags: connection
    // limiter disabled, per-peer defaults 1000/100 (through the deployed builder
    // path), drop metric zero.
    {
        let metrics = Arc::new(P2pMetrics::new());
        let runtime = PublicDevnetAbuseDosRuntimeConfig::disabled_default();
        let per_peer_cfg = runtime.peer_rate_limiter_config();
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
        let builder = deployed_builder_from_cli(&[]);
        let derived_none = builder.deployed_peer_rate_limiter_config().is_none();
        let pm = builder.build_deployed_peer_manager();
        let pm_cfg = pm.peer_rate_limiter().config();
        let defaults = PeerRateLimiter::with_defaults();
        let ok = all_admitted
            && !state.connection_limiter_enabled()
            && state.drop_count() == 0
            && metrics.connection_rate_drop_total() == 0
            && per_peer_cfg.max_messages_per_second == DEFAULT_MAX_MESSAGES_PER_SECOND
            && per_peer_cfg.burst_allowance == DEFAULT_BURST_ALLOWANCE
            && derived_none
            && pm_cfg.max_messages_per_second == defaults.config().max_messages_per_second
            && pm_cfg.burst_allowance == defaults.config().burst_allowance
            && pm_cfg.max_messages_per_second == 1000
            && pm_cfg.burst_allowance == 100;
        scenarios.push(Scenario {
            id: "01_default_preserves_behavior",
            expected: "deployed builder derives None; conn limiter disabled; per-peer 1000/100; drop metric 0"
                .to_string(),
            actual: format!(
                "conn_enabled={} admitted_all={} drop_count={} metric={} per_peer_max={} per_peer_burst={} derived_none={} pm_max={} pm_burst={}",
                state.connection_limiter_enabled(),
                all_admitted,
                state.drop_count(),
                metrics.connection_rate_drop_total(),
                per_peer_cfg.max_messages_per_second,
                per_peer_cfg.burst_allowance,
                derived_none,
                pm_cfg.max_messages_per_second,
                pm_cfg.burst_allowance,
            ),
            matched: ok,
            detail: "No abuse/DoS flags: the connection limiter stays disabled and the \
                     DEPLOYED P2pNodeBuilder derives None and builds \
                     PeerRateLimiter::with_defaults() (1000 msg/s + 100 burst)."
                .to_string(),
        });
    }

    // Scenario 02: admitted_peer_live_socket_admission — a real loopback TCP peer
    // is registered on the live AsyncPeerManagerImpl (the component owning the
    // per-peer PeerRateLimiter). This is a plain-TCP admitted peer, NOT a full
    // KEMTLS mutual-auth handshake (recorded honestly; see helper header).
    {
        let metrics = Arc::new(NodeMetrics::new());
        let pm = peer_manager_with_metrics(
            &["--p2p-max-messages-per-second", "1000", "--p2p-burst-allowance", "100"],
            Arc::clone(&metrics),
        );
        let (mut client, server) = connected_streams().await;
        let peer = PeerId(42);
        let registered = pm.add_peer_with_stream(peer, server).await.is_ok();
        let peer_count = pm.peer_count().await;
        // A single in-budget ping to exercise the live receive path.
        flood_pings(&mut client, 1).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let drops = metrics
            .peer_network()
            .peer_rate_limit_drop_count(peer)
            .unwrap_or(0);
        let _ = client.shutdown().await;
        let ok = registered && peer_count == 1 && drops == 0;
        scenarios.push(Scenario {
            id: "02_admitted_peer_live_socket_admission",
            expected: "one admitted peer over a real loopback socket; in-budget ping accepted; 0 drops"
                .to_string(),
            actual: format!(
                "registered={} peer_count={} drops={}",
                registered, peer_count, drops
            ),
            matched: ok,
            detail: "A real loopback TCP peer is admitted on the live \
                     AsyncPeerManagerImpl receive loop (peer_reader_task). This is a \
                     plain-TCP admitted peer at the AsyncPeerManagerImpl layer, NOT a \
                     deployed KEMTLS mutual-auth handshake; the deployed binary's \
                     inbound path (TcpKemTls->demuxer) does not use this limiter."
                .to_string(),
        });
    }

    // Scenario 03: per_peer_message_rate_live_socket_under_budget — configure a
    // small per-peer bucket (5/0); send exactly capacity messages over a real
    // socket; prove 0 per-peer drops.
    {
        let metrics = Arc::new(NodeMetrics::new());
        let pm = peer_manager_with_metrics(
            &["--p2p-max-messages-per-second", "5", "--p2p-burst-allowance", "0"],
            Arc::clone(&metrics),
        );
        let cfg = pm.peer_rate_limiter().config();
        let peer = PeerId(7);
        let (_pc, drops) = admitted_peer_flood(&pm, &metrics, peer, 5).await;
        let ok = cfg.max_messages_per_second == 5 && cfg.burst_allowance == 0 && drops == 0;
        scenarios.push(Scenario {
            id: "03_per_peer_message_rate_live_socket_under_budget",
            expected: "bucket 5/0 installed; 5 framed messages over a real socket; 0 per-peer drops"
                .to_string(),
            actual: format!(
                "pm_max={} pm_burst={} sent=5 drops={}",
                cfg.max_messages_per_second, cfg.burst_allowance, drops
            ),
            matched: ok,
            detail: "Exactly capacity (5) framed NetMessages flow through the admitted \
                     peer's real-socket receive loop; the live PeerRateLimiter accepts \
                     all of them, so total_rate_limit_drops() stays 0."
                .to_string(),
        });
    }

    // Scenario 04: per_peer_message_rate_live_socket_over_budget — flood well
    // above the bucket over a real socket; prove over-budget messages are dropped
    // by the live PeerRateLimiter and the per-peer drop counter increments.
    {
        let metrics = Arc::new(NodeMetrics::new());
        let pm = peer_manager_with_metrics(
            &["--p2p-max-messages-per-second", "5", "--p2p-burst-allowance", "0"],
            Arc::clone(&metrics),
        );
        let peer = PeerId(9);
        let sent = 80u64;
        let (_pc, drops) = admitted_peer_flood(&pm, &metrics, peer, sent).await;
        let total = metrics.peer_network().total_rate_limit_drops();
        // Bucket capacity is 5 (max) + 0 (burst); refill is 5/s, so a fast flood
        // of 80 must drop well over half. Assert a conservative lower bound to
        // stay robust against scheduler timing while proving real drops occurred.
        let ok = drops >= 60 && drops <= sent && total >= drops;
        scenarios.push(Scenario {
            id: "04_per_peer_message_rate_live_socket_over_budget",
            expected: "flood of 80 over bucket 5/0 → per-peer drops >= 60 via live PeerRateLimiter"
                .to_string(),
            actual: format!("sent={} per_peer_drops={} total_rate_limit_drops={}", sent, drops, total),
            matched: ok,
            detail: "80 framed NetMessages flood the admitted peer's real-socket receive \
                     loop faster than the 5/s bucket refills; the live PeerRateLimiter \
                     drops the over-budget messages and \
                     NodeMetrics::peer_network().peer_rate_limit_drop_count(peer) / \
                     total_rate_limit_drops() reflect the drops."
                .to_string(),
        });
    }

    // Scenario 05: connection_rate_regression — the exact runtime decision the
    // live accept loop makes: N under-budget admitted, over-budget refused,
    // metric increments per refusal, no peer admitted on refusal (Run 367 parity).
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
        let metric_before = metrics.connection_rate_drop_total();
        let over = state.check_inbound(addr(1, 999), now);
        let admitted_on_refusal = state.should_admit(addr(1, 998), now);
        let ok = admitted == 4
            && metric_before == 0
            && over == ConnectionDecision::ConnectionRateLimited
            && !admitted_on_refusal
            && metrics.connection_rate_drop_total() == 2
            && state.drop_count() == 2;
        scenarios.push(Scenario {
            id: "05_connection_rate_regression",
            expected: "4 admitted; over-budget ConnectionRateLimited; no admit on refusal; metric per refusal"
                .to_string(),
            actual: format!(
                "admitted={} over={:?} admitted_on_refusal={} metric_before={} metric_after={} drop_count={}",
                admitted,
                over,
                admitted_on_refusal,
                metric_before,
                metrics.connection_rate_drop_total(),
                state.drop_count()
            ),
            matched: ok,
            detail: "The connection-rate limiter decision the live accept loop makes; \
                     the Run 368 harness re-runs this over real loopback TCP connections \
                     on the release binary as a regression of the Run 367 proof."
                .to_string(),
        });
    }

    // Scenario 06: combined_limiter_independence — a connection-rate refusal never
    // admits a peer and increments only the connection metric; a per-peer message
    // drop over a real socket increments only the per-peer counter. Counters are
    // distinct objects (P2pMetrics vs NodeMetrics::peer_network).
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
        let conn_after_first = conn_metrics.connection_rate_drop_total();
        let second_admitted = state.should_admit(addr(1, 2), now);
        let conn_after_second = conn_metrics.connection_rate_drop_total();

        // Independent per-peer drop over a real socket.
        let peer_metrics = Arc::new(NodeMetrics::new());
        let pm = peer_manager_with_metrics(
            &["--p2p-max-messages-per-second", "3", "--p2p-burst-allowance", "0"],
            Arc::clone(&peer_metrics),
        );
        let peer = PeerId(11);
        let (_pc, peer_drops) = admitted_peer_flood(&pm, &peer_metrics, peer, 60).await;
        let conn_final = conn_metrics.connection_rate_drop_total();

        let ok = first_admitted
            && conn_after_first == 0
            && !second_admitted
            && conn_after_second == 1
            && peer_drops >= 40
            && conn_final == 1;
        scenarios.push(Scenario {
            id: "06_combined_limiter_independence",
            expected: "conn refusal increments only conn metric; per-peer flood increments only per-peer counter"
                .to_string(),
            actual: format!(
                "first_admitted={} second_admitted={} conn_metric={} per_peer_drops={}",
                first_admitted, second_admitted, conn_final, peer_drops
            ),
            matched: ok,
            detail: "The connection-rate limiter (accept path, P2pMetrics) and the \
                     per-peer message-rate limiter (AsyncPeerManagerImpl receive loop, \
                     NodeMetrics::peer_network) are independent; a connection refusal \
                     never touches the per-peer counter and vice versa."
                .to_string(),
        });
    }

    // Scenario 07: invalid_configs_fail_closed — zero window / zero max /
    // unbounded / inconsistent per-address config are rejected before any runtime
    // state or peer manager exists.
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
        let r_inconsistent = parse_cli(&[
            "--p2p-connection-rate-limit-enabled",
            "--p2p-connection-rate-window-ms",
            "1000",
            "--p2p-connection-rate-max",
            "20",
            "--p2p-per-address-connection-rate-window-ms",
            "1000",
        ])
        .unwrap()
        .abuse_dos_runtime_config();
        let ok = r_window.is_err()
            && r_zero_msg.is_err()
            && r_zero_conn.is_err()
            && r_unbounded.is_err()
            && r_inconsistent.is_err();
        scenarios.push(Scenario {
            id: "07_invalid_configs_fail_closed",
            expected: "zero-window/zero-msg/zero-conn/unbounded/inconsistent all rejected"
                .to_string(),
            actual: format!(
                "zero_window={} zero_msg={} zero_conn={} unbounded={} inconsistent={}",
                r_window.is_err(),
                r_zero_msg.is_err(),
                r_zero_conn.is_err(),
                r_unbounded.is_err(),
                r_inconsistent.is_err()
            ),
            matched: ok,
            detail: "Every nonsensical abuse/DoS value fails closed at config validation; \
                     no runtime state and no peer manager is ever built."
                .to_string(),
        });
    }

    // Scenario 08: mainnet_refused — an enabled MainNet abuse/DoS config is
    // refused, both directly and via the CLI.
    {
        let direct = AbuseDosConfig::compatibility_default()
            .with_environment(NetworkEnvironment::Mainnet);
        let r_direct = PublicDevnetAbuseDosRuntimeConfig::from_config({
            let mut c = direct;
            c.per_peer_max_messages_per_second = 500;
            c
        });
        let r_cli = parse_cli(&["--env", "mainnet", "--p2p-max-messages-per-second", "500"])
            .unwrap()
            .abuse_dos_runtime_config();
        let ok = r_direct.is_err() && r_cli.is_err();
        scenarios.push(Scenario {
            id: "08_mainnet_refused",
            expected: "MainNet abuse/DoS config refused (direct + CLI)".to_string(),
            actual: format!("direct_err={} cli_err={}", r_direct.is_err(), r_cli.is_err()),
            matched: ok,
            detail: "MainNet has no production abuse/DoS policy; an enabled MainNet config \
                     never validates and no runtime state or peer manager exists."
                .to_string(),
        });
    }

    // Scenario 09: cli_surface_hidden_and_parse_checked — hidden flags absent from
    // --help; real hidden flags parse; invented flag rejected by clap.
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
        let invented_rejected = parse_cli(&["--p2p-max-messages", "500"]).is_err()
            && parse_cli(&["--p2p-message-burst", "60"]).is_err()
            && parse_cli(&["--p2p-connection-rate-bogus", "1"]).is_err();
        let ok = all_hidden && real_parse && invented_rejected;
        scenarios.push(Scenario {
            id: "09_cli_surface_hidden_and_parse_checked",
            expected: "hidden flags absent from --help; real parse; invented rejected"
                .to_string(),
            actual: format!(
                "all_hidden={} real_parse={} invented_rejected={}",
                all_hidden, real_parse, invented_rejected
            ),
            matched: ok,
            detail: "The Run 362/363 abuse/DoS flags are hidden/devnet-only (never in \
                     --help), the real hidden flags parse, and invented flags are \
                     rejected by clap."
                .to_string(),
        });
    }

    // Metric evidence: the connection-rate drop family renders exactly once
    // (no endpoint labels), and the per-peer rate-limit drop family renders on
    // the live NodeMetrics after a real-socket flood.
    let conn_metric_rendered = {
        let metrics = P2pMetrics::new();
        metrics.record_connection_rate_drop();
        metrics.format_metrics()
    };
    let conn_family_count = conn_metric_rendered
        .matches("qbind_p2p_connection_rate_drop_total")
        .count();
    let conn_label_leak = conn_metric_rendered.contains("qbind_p2p_connection_rate_drop_total{");
    let conn_metric_line = conn_metric_rendered
        .lines()
        .find(|l| l.starts_with("qbind_p2p_connection_rate_drop_total"))
        .unwrap_or("<absent>");

    // Prove the per-peer drop family renders on live NodeMetrics after a flood.
    let per_peer_metrics = Arc::new(NodeMetrics::new());
    let per_peer_pm = peer_manager_with_metrics(
        &["--p2p-max-messages-per-second", "5", "--p2p-burst-allowance", "0"],
        Arc::clone(&per_peer_metrics),
    );
    let (_pc, per_peer_metric_drops) =
        admitted_peer_flood(&per_peer_pm, &per_peer_metrics, PeerId(21), 80).await;
    let per_peer_rendered = per_peer_metrics.peer_network().format_metrics();
    let per_peer_family_present =
        per_peer_rendered.contains("qbind_net_per_peer_drops_total") &&
        per_peer_rendered.contains("reason=\"rate_limit\"");

    let metric_ok = conn_family_count == 1
        && !conn_label_leak
        && per_peer_metric_drops >= 1
        && per_peer_family_present;
    write_file(
        &out_dir.join("metric_evidence.txt"),
        &format!(
            "conn_metric_name: qbind_p2p_connection_rate_drop_total\n\
             conn_registered_once: {}\n\
             conn_endpoint_label_leak: {}\n\
             conn_rendered_line: {}\n\
             per_peer_metric_name: qbind_net_per_peer_drops_total\n\
             per_peer_family_present: {}\n\
             per_peer_drops_observed: {}\n",
            conn_family_count == 1,
            conn_label_leak,
            conn_metric_line,
            per_peer_family_present,
            per_peer_metric_drops,
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
        "Run 368 — public DevNet abuse/DoS M12 admitted-peer per-peer message-rate live-socket helper\n\
         scenarios_total: {}\n\
         scenarios_passed: {}\n\
         conn_metric_registered_once: {}\n\
         conn_metric_no_endpoint_label: {}\n\
         per_peer_drop_family_present: {}\n\
         per_peer_drops_observed: {}\n\
         verdict: {}\n\
         notes: real-loopback-socket admitted-peer per-peer message-rate proof through \
         AsyncPeerManagerImpl::peer_reader_task (owns the PeerRateLimiter): under-budget \
         accepted, over-budget dropped, live NodeMetrics per-peer drop counter increments; \
         connection-rate regression + independence + fail-closed + MainNet-refused + hidden \
         CLI surface preserved. HONEST SCOPE: this is the AsyncPeerManagerImpl layer with a \
         plain-TCP admitted peer; the DEPLOYED qbind-node inbound path (TcpKemTls->demuxer) \
         does NOT consult the PeerRateLimiter, so M12 stays Yellow/Partial (Route C). No \
         socket left open; MainNet refused; no trust/validator/epoch mutation; no launch claim.\n",
        scenarios.len(),
        scenarios.iter().filter(|s| s.matched).count(),
        conn_family_count == 1,
        !conn_label_leak,
        per_peer_family_present,
        per_peer_metric_drops,
        if all_ok { "PASS" } else { "FAIL" }
    );
    write_file(&out_dir.join("helper_summary.txt"), &summary);
    print!("{summary}");

    if !all_ok {
        eprintln!("[run_368_helper] FAIL: one or more scenarios did not match");
        std::process::exit(1);
    }
}
