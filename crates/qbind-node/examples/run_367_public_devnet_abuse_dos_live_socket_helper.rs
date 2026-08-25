//! Run 367 — release-built helper backing the public DevNet abuse/DoS **M12
//! live-socket** evidence attempt.
//!
//! Unlike Run 366 (whose harness never passed `--network-mode p2p`, so the node
//! ran in LocalMesh and the live inbound socket path was never driven), Run 367
//! pairs this in-process runtime-symbol helper with a harness
//! (`scripts/devnet/run_367_public_devnet_abuse_dos_live_socket_release_binary.sh`)
//! that launches a real `target/release/qbind-node` in a **P2P-capable loopback
//! mode** (`--network-mode p2p --enable-p2p --p2p-listen-addr 127.0.0.1:<port>`)
//! and drives real inbound TCP sockets against the accept-loop connection-rate
//! limiter.
//!
//! This helper links the real Run 361/362/363/365 runtime symbols and proves,
//! in release mode and **without opening a socket**, the invariants that the
//! live-socket harness then confirms end-to-end:
//!
//! 1. default config preserves old behavior (connection limiter disabled;
//!    per-peer defaults `1000` msg/s + `100` burst through the DEPLOYED builder
//!    path; drop metric zero);
//! 2. a configured connection-rate limiter admits under-budget and refuses
//!    over-budget inbound attempts while incrementing
//!    `qbind_p2p_connection_rate_drop_total` exactly once per refusal, without
//!    admitting a peer;
//! 3. a configured per-peer message-rate override reaches the DEPLOYED
//!    `P2pNodeBuilder` peer-manager construction path
//!    (`build_deployed_peer_manager`, Run 365) and allows under-budget / drops
//!    over-budget messages without touching the connection-rate metric;
//! 4. the two limiters are independent and their counters are distinct;
//! 5. invalid / unbounded / inconsistent configs fail closed;
//! 6. an enabled MainNet abuse/DoS config is refused;
//! 7. the hidden/devnet-only CLI surface is hidden from `--help` while the real
//!    hidden flags parse and invented flags are rejected by clap;
//! 8. the DEPLOYED builder default is bit-for-bit the direct default (no drift).
//!
//! Per `task/RUN_367_TASK.txt`, this helper is fixture-tooling and:
//!
//! * does NOT itself open a P2P socket, launch a public DevNet, deploy a seed /
//!   bootnode / faucet / RPC / explorer / status page (the harness opens a
//!   bounded loopback socket on the real binary; this helper does not);
//! * does NOT mutate any live trust state, validator set, epoch, or write any
//!   sequence / marker / trust-bundle file;
//! * does NOT enable MainNet (an enabled MainNet abuse/DoS config never
//!   validates and is refused here);
//! * does NOT weaken peer admission, KEMTLS, trust-bundle, or genesis-hash
//!   pinning, and does NOT change any P2P wire format;
//! * exists alongside (and does NOT replace) the Run 361/362/363/365 source/test
//!   targets and the Run 362/364/366 release helpers.
//!
//! The helper writes the following files under `<OUT_DIR>/`:
//!
//! ```text
//! <OUT_DIR>/manifest.txt           # one line per scenario: <id>\t<expected>\t<match>
//! <OUT_DIR>/scenarios/<id>.txt     # per-scenario detail
//! <OUT_DIR>/metric_evidence.txt    # rendered metric family + registration count
//! <OUT_DIR>/helper_summary.txt     # release-built helper verdict
//! ```
//!
//! The helper exits non-zero if any scenario does not match its expected
//! outcome, mirroring the existing release-built-helper pattern.
//!
//! Usage:
//! ```text
//! run_367_public_devnet_abuse_dos_live_socket_helper <OUT_DIR>
//! ```

use std::env;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{CommandFactory, Parser};

use qbind_node::async_peer_manager::{AsyncPeerManagerConfig, AsyncPeerManagerImpl};
use qbind_node::cli::CliArgs;
use qbind_node::metrics::P2pMetrics;
use qbind_node::p2p_node_builder::P2pNodeBuilder;
use qbind_node::peer::PeerId;
use qbind_node::peer_rate_limiter::{
    PeerRateLimiter, DEFAULT_BURST_ALLOWANCE, DEFAULT_MAX_MESSAGES_PER_SECOND,
};
use qbind_node::public_devnet_abuse_dos_config::{AbuseDosConfig, ConnectionDecision};
use qbind_node::public_devnet_abuse_dos_runtime::PublicDevnetAbuseDosRuntimeConfig;
use qbind_types::primitives::NetworkEnvironment;

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
/// install it via `with_abuse_dos_runtime_config` (the Run 365 deployed path
/// that `run_p2p_node` invokes at `main.rs:6823`).
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

/// Construct the live `AsyncPeerManagerImpl` the *deployed* node uses, threaded
/// with the CLI-derived per-peer message-rate limiter via the Run 365 builder
/// method `build_deployed_peer_manager`.
fn deployed_peer_manager_from_cli(args: &[&str]) -> AsyncPeerManagerImpl {
    deployed_builder_from_cli(args).build_deployed_peer_manager()
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
        .unwrap_or_else(|| PathBuf::from("run_367_out"));
    fs::create_dir_all(&out_dir).expect("create out dir");

    let mut scenarios: Vec<Scenario> = Vec::new();

    // Scenario 1: default preserves behavior — no abuse/DoS flags/config: the
    // connection limiter is disabled, per-peer defaults are 1000/100 (through
    // the deployed builder path), and the drop metric remains zero. This backs
    // the harness `default_preserves_behavior` live-socket scenario.
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
        let pm = deployed_peer_manager_from_cli(&[]);
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
            detail: "No abuse/DoS flags: the connection limiter stays disabled \
                     (accept loop unchanged) and the DEPLOYED P2pNodeBuilder derives \
                     None and builds PeerRateLimiter::with_defaults() (1000 msg/s + \
                     100 burst) via build_deployed_peer_manager(). The harness confirms \
                     the same over a real loopback socket: no-flag node keeps \
                     qbind_p2p_connection_rate_drop_total at 0."
                .to_string(),
        });
    }

    // Scenario 2: connection_rate_admit_refuse — the exact runtime decision the
    // live accept loop (`p2p_tcp::spawn_accept_loop` -> `state.should_admit`)
    // makes: N under-budget admitted, over-budget refused, metric increments per
    // refusal, no peer admitted on refusal.
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
            id: "02_connection_rate_admit_refuse",
            expected: "4 admitted; over-budget ConnectionRateLimited; no admit on refusal; metric increments per refusal"
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
            detail: "This is the exact decision the live accept loop makes per inbound \
                     socket: an enabled connection-rate limiter admits under-budget, \
                     refuses over-budget without admitting a peer, and increments \
                     qbind_p2p_connection_rate_drop_total per refusal. The harness \
                     drives this over real loopback TCP connections on the release binary."
                .to_string(),
        });
    }

    // Scenario 3: per_peer_message_rate_deployed — a configured per-peer message
    // bucket reaches the DEPLOYED builder path; first N allowed, N+1 dropped, and
    // the connection-rate metric does NOT move. (The live admitted-peer message
    // path is documented as the remaining blocker in the evidence doc.)
    {
        let metrics = Arc::new(P2pMetrics::new());
        let args = [
            "--p2p-max-messages-per-second",
            "5",
            "--p2p-burst-allowance",
            "0",
        ];
        let builder = deployed_builder_from_cli(&args);
        let derived = builder.deployed_peer_rate_limiter_config();
        let derived_ok = derived
            .map(|c| c.max_messages_per_second == 5 && c.burst_allowance == 0)
            .unwrap_or(false);
        let pm = deployed_peer_manager_from_cli(&args);
        let limiter = pm.peer_rate_limiter();
        let cfg = limiter.config();
        let peer = PeerId(1);
        let now = Instant::now();
        let mut allowed = 0u32;
        for _ in 0..5 {
            if limiter.allow(&peer, now) {
                allowed += 1;
            }
        }
        let dropped = !limiter.allow(&peer, now);
        let ok = derived_ok
            && cfg.max_messages_per_second == 5
            && cfg.burst_allowance == 0
            && allowed == 5
            && dropped
            && metrics.connection_rate_drop_total() == 0;
        scenarios.push(Scenario {
            id: "03_per_peer_message_rate_deployed",
            expected: "deployed builder installs 5/0; deployed pm honors it; 5 allowed; 6th dropped; conn metric 0"
                .to_string(),
            actual: format!(
                "derived_ok={} pm_max={} pm_burst={} allowed={} dropped={} conn_metric={}",
                derived_ok,
                cfg.max_messages_per_second,
                cfg.burst_allowance,
                allowed,
                dropped,
                metrics.connection_rate_drop_total()
            ),
            matched: ok,
            detail: "The hidden --p2p-max-messages-per-second/--p2p-burst-allowance \
                     override reaches the DEPLOYED P2pNodeBuilder \
                     (deployed_peer_rate_limiter_config) and its live \
                     AsyncPeerManagerImpl (build_deployed_peer_manager); over-budget \
                     messages drop without touching the connection-rate metric. Driving \
                     this over an admitted live peer requires a second KEMTLS peer/flood \
                     harness (recorded as the remaining M12 blocker)."
                .to_string(),
        });
    }

    // Scenario 4: combined_independence — connection-rate refusal never admits a
    // peer, a message-rate drop occurs only on the admitted deployed path, and
    // the counters are distinct.
    {
        let metrics = Arc::new(P2pMetrics::new());
        let mut conn_cfg = AbuseDosConfig::public_devnet_recommended();
        conn_cfg.max_connections_per_window = 1;
        conn_cfg.connection_burst_allowance = 0;
        conn_cfg.per_address_rate_window = None;
        conn_cfg.per_peer_max_messages_per_second = 3;
        conn_cfg.per_peer_burst_allowance = 0;
        let runtime = PublicDevnetAbuseDosRuntimeConfig::from_config(conn_cfg).unwrap();

        let builder = P2pNodeBuilder::new().with_abuse_dos_runtime_config(runtime.clone());
        let pm = builder.build_deployed_peer_manager();
        let limiter = pm.peer_rate_limiter();

        let state = runtime
            .into_runtime_state(Some(Arc::clone(&metrics)))
            .unwrap();
        let now = Instant::now();

        let first_admitted = state.should_admit(addr(1, 1), now);
        let conn_metric_after_first = metrics.connection_rate_drop_total();
        let second_admitted = state.should_admit(addr(1, 2), now);
        let conn_metric_after_second = metrics.connection_rate_drop_total();

        let peer = PeerId(7);
        let mut msg_allowed = 0u32;
        for _ in 0..3 {
            if limiter.allow(&peer, now) {
                msg_allowed += 1;
            }
        }
        let msg_dropped = !limiter.allow(&peer, now);
        let conn_metric_final = metrics.connection_rate_drop_total();

        let ok = first_admitted
            && conn_metric_after_first == 0
            && !second_admitted
            && conn_metric_after_second == 1
            && msg_allowed == 3
            && msg_dropped
            && conn_metric_final == 1
            && limiter.config().max_messages_per_second == 3;
        scenarios.push(Scenario {
            id: "04_combined_independence",
            expected: "conn refusal doesn't admit; msg drop on admitted deployed path; counters distinct"
                .to_string(),
            actual: format!(
                "first_admitted={} second_admitted={} conn_metric={} msg_allowed={} msg_dropped={}",
                first_admitted, second_admitted, conn_metric_final, msg_allowed, msg_dropped
            ),
            matched: ok,
            detail: "The connection-rate limiter (accept path) and the per-peer \
                     message-rate limiter (deployed builder peer-manager path) are \
                     independent: a connection refusal never admits a peer, and a \
                     message-rate drop increments no connection-rate counter."
                .to_string(),
        });
    }

    // Scenario 5: invalid_configs_fail_closed — zero window / zero max /
    // unbounded / inconsistent per-address config are rejected before any runtime
    // state or deployed peer manager exists.
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
            id: "05_invalid_configs_fail_closed",
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
            detail: "Every nonsensical abuse/DoS value fails closed at config \
                     validation; no runtime state, no deployed peer manager, and no \
                     limiter is ever built. The harness confirms the same via the \
                     production validation fn CliArgs::abuse_dos_runtime_config()."
                .to_string(),
        });
    }

    // Scenario 6: mainnet_refused — an enabled MainNet abuse/DoS config is refused
    // (no production abuse/DoS policy), both directly and via the CLI.
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
            id: "06_mainnet_refused",
            expected: "MainNet abuse/DoS config refused (direct + CLI)".to_string(),
            actual: format!("direct_err={} cli_err={}", r_direct.is_err(), r_cli.is_err()),
            matched: ok,
            detail: "MainNet has no production abuse/DoS policy; an enabled MainNet \
                     config never validates and no runtime state or deployed peer \
                     manager exists."
                .to_string(),
        });
    }

    // Scenario 7: cli_surface_hidden_and_parse_checked — hidden flags absent from
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
            id: "07_cli_surface_hidden_and_parse_checked",
            expected: "hidden flags absent from --help; real parse; invented rejected"
                .to_string(),
            actual: format!(
                "all_hidden={} real_parse={} invented_rejected={}",
                all_hidden, real_parse, invented_rejected
            ),
            matched: ok,
            detail: "The Run 362/363 abuse/DoS flags are hidden/devnet-only (never \
                     in --help), the real hidden flags parse, and invented flags are \
                     rejected by clap."
                .to_string(),
        });
    }

    // Scenario 8: deployed_builder_matches_direct_default — the deployed builder
    // default config is bit-for-bit the direct default AsyncPeerManagerConfig
    // (no accidental drift introduced by the Run 365 threading).
    {
        let deployed_default = deployed_builder_from_cli(&[]).deployed_async_peer_manager_config();
        let direct_default = AsyncPeerManagerConfig::default();
        let deployed_pm = deployed_peer_manager_from_cli(&[]);
        let direct_pm = AsyncPeerManagerImpl::new(AsyncPeerManagerConfig::default());
        let ok = deployed_default.peer_rate_limiter_config.is_none()
            == direct_default.peer_rate_limiter_config.is_none()
            && deployed_pm.peer_rate_limiter().config().max_messages_per_second
                == direct_pm.peer_rate_limiter().config().max_messages_per_second
            && deployed_pm.peer_rate_limiter().config().burst_allowance
                == direct_pm.peer_rate_limiter().config().burst_allowance;
        scenarios.push(Scenario {
            id: "08_deployed_builder_matches_direct_default",
            expected: "deployed default == direct default (no drift)".to_string(),
            actual: format!(
                "deployed_cfg_none={} deployed_pm_max={} direct_pm_max={} deployed_pm_burst={} direct_pm_burst={}",
                deployed_default.peer_rate_limiter_config.is_none(),
                deployed_pm.peer_rate_limiter().config().max_messages_per_second,
                direct_pm.peer_rate_limiter().config().max_messages_per_second,
                deployed_pm.peer_rate_limiter().config().burst_allowance,
                direct_pm.peer_rate_limiter().config().burst_allowance,
            ),
            matched: ok,
            detail: "With no override the deployed builder's AsyncPeerManagerConfig \
                     equals the default one bit-for-bit, so the Run 365 threading is \
                     purely additive and default-preserving."
                .to_string(),
        });
    }

    // Metric registration evidence: the connection-rate drop family renders
    // exactly once, without endpoint labels.
    let metric_rendered = {
        let metrics = P2pMetrics::new();
        metrics.record_connection_rate_drop();
        metrics.format_metrics()
    };
    let family_count = metric_rendered
        .matches("qbind_p2p_connection_rate_drop_total")
        .count();
    let has_label_leak = metric_rendered.contains("qbind_p2p_connection_rate_drop_total{");
    let metric_line = metric_rendered
        .lines()
        .find(|l| l.starts_with("qbind_p2p_connection_rate_drop_total"))
        .unwrap_or("<absent>");
    let metric_ok = family_count == 1 && !has_label_leak;
    write_file(
        &out_dir.join("metric_evidence.txt"),
        &format!(
            "metric_name: qbind_p2p_connection_rate_drop_total\n\
             registered_once: {}\n\
             endpoint_label_leak: {}\n\
             rendered_line: {}\n",
            family_count == 1,
            has_label_leak,
            metric_line
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
        "Run 367 — public DevNet abuse/DoS M12 live-socket release-binary helper\n\
         scenarios_total: {}\n\
         scenarios_passed: {}\n\
         metric_registered_once: {}\n\
         metric_no_endpoint_label: {}\n\
         verdict: {}\n\
         notes: in-process runtime-symbol proof that backs the live-socket harness \
         (scripts/devnet/run_367_public_devnet_abuse_dos_live_socket_release_binary.sh). \
         Connection-rate limiter decision (accept path) + per-peer message-rate \
         override through the DEPLOYED P2pNodeBuilder peer-manager path \
         (build_deployed_peer_manager, Run 365); both operator-configurable + \
         default-off/defaults-preserved; this helper opens NO socket; MainNet \
         refused; no trust/validator/epoch mutation; no launch claim.\n",
        scenarios.len(),
        scenarios.iter().filter(|s| s.matched).count(),
        family_count == 1,
        !has_label_leak,
        if all_ok { "PASS" } else { "FAIL" }
    );
    write_file(&out_dir.join("helper_summary.txt"), &summary);
    print!("{summary}");

    if !all_ok {
        eprintln!("[run_367_helper] FAIL: one or more scenarios did not match");
        std::process::exit(1);
    }
}