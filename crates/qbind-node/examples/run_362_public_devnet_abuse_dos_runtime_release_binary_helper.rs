//! Run 362 — release-built helper that exercises the runtime-owned public
//! DevNet abuse/DoS connection-rate limiter wiring **in release mode** through
//! the production library symbols
//! [`qbind_node::public_devnet_abuse_dos_runtime`],
//! [`qbind_node::public_devnet_abuse_dos_config`], and
//! [`qbind_node::metrics::P2pMetrics`].
//!
//! Per `task/RUN_362_TASK.txt`, Run 362 wires the Run 361 `AbuseDosConfig` /
//! `ConnectionRateLimiter` into the live `p2p_tcp` accept path behind a
//! runtime-owned, default-off handle. This helper is fixture-tooling and:
//!
//! * does NOT open a P2P socket, launch a public DevNet, deploy a seed /
//!   bootnode / faucet / RPC / explorer / status page;
//! * does NOT mutate any live trust state, validator set, epoch, or write any
//!   sequence / marker / trust-bundle file;
//! * does NOT enable MainNet (an enabled MainNet abuse/DoS config never
//!   validates and is refused here);
//! * does NOT weaken peer admission, KEMTLS, trust-bundle, or genesis-hash
//!   pinning;
//! * exists alongside (and does NOT replace) the Run 362 source/test target
//!   `crates/qbind-node/tests/run_362_public_devnet_abuse_dos_runtime_tests.rs`.
//!
//! It links the real Run 361/362 runtime symbols and proves, in release mode:
//! default config preserves old behavior; a configured DevNet limiter accepts
//! under-budget connection attempts and refuses over-budget attempts; the
//! `qbind_p2p_connection_rate_drop_total` metric increments on refusal and is
//! registered exactly once; invalid configs fail closed; MainNet is refused.
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
//! run_362_public_devnet_abuse_dos_runtime_release_binary_helper <OUT_DIR>
//! ```

use std::env;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use qbind_node::metrics::P2pMetrics;
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
        .unwrap_or_else(|| PathBuf::from("run_362_out"));
    fs::create_dir_all(&out_dir).expect("create out dir");

    let mut scenarios: Vec<Scenario> = Vec::new();

    // Scenario 1: default config preserves old behavior (limiter disabled).
    {
        let runtime = PublicDevnetAbuseDosRuntimeConfig::disabled_default();
        let state = runtime.into_runtime_state(None).unwrap();
        let now = Instant::now();
        let mut all_admitted = true;
        for i in 0..1000u16 {
            if !state.should_admit(addr(1, i), now) {
                all_admitted = false;
            }
        }
        let ok = all_admitted && !state.connection_limiter_enabled() && state.drop_count() == 0;
        scenarios.push(Scenario {
            id: "01_default_preserves_behavior",
            expected: "disabled limiter never refuses; drop_count=0".to_string(),
            actual: format!(
                "enabled={} admitted_all={} drop_count={}",
                state.connection_limiter_enabled(),
                all_admitted,
                state.drop_count()
            ),
            matched: ok,
            detail: "Default profile leaves the connection limiter disabled; \
                     the accept loop is unchanged."
                .to_string(),
        });
    }

    // Scenario 2: configured DevNet limiter accepts under-budget + refuses
    // over-budget attempts, and the metric increments on refusal.
    {
        let metrics = Arc::new(P2pMetrics::new());
        let state = PublicDevnetAbuseDosRuntimeConfig::from_config(
            AbuseDosConfig::public_devnet_recommended(),
        )
        .unwrap()
        .into_runtime_state(Some(Arc::clone(&metrics)))
        .unwrap();
        let now = Instant::now();
        // Capacity = 20 + 10 = 30 global tokens at t0.
        let mut admitted = 0u64;
        for i in 0..30u16 {
            if state.should_admit(addr(1, i), now) {
                admitted += 1;
            }
        }
        let over = state.check_inbound(addr(1, 999), now);
        let ok = admitted == 30
            && over == ConnectionDecision::ConnectionRateLimited
            && metrics.connection_rate_drop_total() == 1
            && state.drop_count() == 1;
        scenarios.push(Scenario {
            id: "02_enabled_allows_then_refuses",
            expected: "30 admitted; 31st ConnectionRateLimited; metric=1".to_string(),
            actual: format!(
                "admitted={} over={:?} metric={} drop_count={}",
                admitted,
                over,
                metrics.connection_rate_drop_total(),
                state.drop_count()
            ),
            matched: ok,
            detail: "Enabled DevNet-recommended profile bounds inbound \
                     connections and increments qbind_p2p_connection_rate_drop_total."
                .to_string(),
        });
    }

    // Scenario 3: invalid config fails closed (zero window on enabled limiter).
    {
        let mut bad = AbuseDosConfig::public_devnet_recommended();
        bad.connection_rate_window = Duration::from_secs(0);
        let result = PublicDevnetAbuseDosRuntimeConfig::from_config(bad);
        let ok = result.is_err();
        scenarios.push(Scenario {
            id: "03_invalid_config_fails_closed",
            expected: "zero-window enabled config rejected".to_string(),
            actual: format!("is_err={}", result.is_err()),
            matched: ok,
            detail: "A nonsensical connection-rate window is refused at config \
                     validation; no runtime state is built."
                .to_string(),
        });
    }

    // Scenario 4: MainNet is refused (no production abuse/DoS policy).
    {
        let mainnet = AbuseDosConfig::compatibility_default()
            .with_environment(NetworkEnvironment::Mainnet);
        let result = PublicDevnetAbuseDosRuntimeConfig::from_config(mainnet);
        let ok = result.is_err();
        scenarios.push(Scenario {
            id: "04_mainnet_refused",
            expected: "MainNet abuse/DoS config refused".to_string(),
            actual: format!("is_err={}", result.is_err()),
            matched: ok,
            detail: "MainNet has no production abuse/DoS policy; the config is \
                     refused before any runtime state exists."
                .to_string(),
        });
    }

    // Scenario 5: metric does not increment on an allowed connection.
    {
        let metrics = Arc::new(P2pMetrics::new());
        let state = PublicDevnetAbuseDosRuntimeConfig::from_config(
            AbuseDosConfig::public_devnet_recommended(),
        )
        .unwrap()
        .into_runtime_state(Some(Arc::clone(&metrics)))
        .unwrap();
        let now = Instant::now();
        let allowed = state.should_admit(addr(1, 1), now);
        let ok = allowed && metrics.connection_rate_drop_total() == 0;
        scenarios.push(Scenario {
            id: "05_metric_not_increment_on_allow",
            expected: "allowed connection leaves metric at 0".to_string(),
            actual: format!(
                "allowed={} metric={}",
                allowed,
                metrics.connection_rate_drop_total()
            ),
            matched: ok,
            detail: "The drop counter is bumped only on ConnectionRateLimited."
                .to_string(),
        });
    }

    // Metric registration evidence: the family renders exactly once, without
    // endpoint labels.
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
        "Run 362 — public DevNet abuse/DoS runtime release-binary helper\n\
         scenarios_total: {}\n\
         scenarios_passed: {}\n\
         metric_registered_once: {}\n\
         metric_no_endpoint_label: {}\n\
         verdict: {}\n\
         notes: connection-rate limiter runtime-wired + operator-configurable + \
         default-off; no P2P socket opened; no launch claim; MainNet refused; \
         no trust/validator/epoch mutation.\n",
        scenarios.len(),
        scenarios.iter().filter(|s| s.matched).count(),
        family_count == 1,
        !has_label_leak,
        if all_ok { "PASS" } else { "FAIL" }
    );
    write_file(&out_dir.join("helper_summary.txt"), &summary);
    print!("{summary}");

    if !all_ok {
        eprintln!("[run_362_helper] FAIL: one or more scenarios did not match");
        std::process::exit(1);
    }
}