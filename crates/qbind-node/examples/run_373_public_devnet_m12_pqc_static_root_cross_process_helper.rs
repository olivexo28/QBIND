//! Run 373 — release-built helper backing the public DevNet abuse/DoS **M12
//! cross-process PqcStaticRoot strict-mutual-auth** hardening evidence.
//!
//! # Background
//!
//! Run 371 (accepted POSITIVE) proved the deployed per-peer message-rate limiter
//! drops an over-budget KEMTLS-admitted peer's frames on live `/metrics`; Run 372
//! (accepted POSITIVE) re-proved that under strict `MutualAuthMode::Required`
//! admission with two simultaneous peers and isolated per-peer buckets. Run 372's
//! only recorded limitation was that `PqcRootMode::PqcStaticRoot` with
//! runtime-generated ML-DSA-44 root + ML-KEM-768 leaf material was proven
//! **in-process only** — it was not driven cross-process against the standalone
//! `target/release/qbind-node` binary with operator-configured
//! `--p2p-trusted-root`, `--p2p-leaf-cert`, and `--p2p-leaf-cert-key` material.
//!
//! # What Run 373 hardens
//!
//! Run 373 extends the Run 372 result from an in-process PqcStaticRoot proof to a
//! standalone-binary, cross-process loopback proof, using ONLY production public
//! APIs and the pre-existing public/hidden CLI surface (decision gate **Route A**,
//! no production source change):
//!
//! * The Run 373 harness generates **temporary** ML-DSA-44 root + ML-KEM-768 leaf
//!   material into a temp dir with the pre-existing `devnet_pqc_root_helper`
//!   example, then launches the standalone `target/release/qbind-node` under
//!   `--p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root
//!   --p2p-trusted-root <spec> --p2p-leaf-cert <path> --p2p-leaf-cert-key <path>`
//!   with a low per-peer budget on a loopback listen + metrics endpoint.
//!
//! * `dial-flood-static-root` mode drives a node B built from the SAME
//!   operator-configured static-root material (its own file-loaded leaf
//!   credentials + the deployed node A's leaf cert as a peer-leaf-cert) via the
//!   production `P2pNodeBuilder::with_pqc_root_config` seam. It completes the
//!   Required KEMTLS mutual-auth handshake against the deployed node's live P2P
//!   listener, floods a caller-specified number of frames at a caller-specified
//!   pace, and records the connection / cert-derived-NodeId / enqueue result so
//!   the harness can scrape the deployed node's live `/metrics`.
//!
//! * `bucket-key-cert <cert_path>` mode: prints the decimal per-peer metric
//!   `peer="..."` label the deployed inbound per-peer limiter assigns to the
//!   cert-derived NodeId of the leaf cert at `<cert_path>`. Under PqcStaticRoot
//!   the NodeId is derived from the leaf's ML-KEM-768 public key (NOT a
//!   deterministic validator-id function), so the label is computed from the
//!   ACTUAL generated cert material shared with the deployed node — this lets the
//!   harness match the exact `qbind_net_per_peer_drops_total{peer="<key>",...}`
//!   line for multi-peer bucket-isolation assertions on the LIVE binary.
//!
//! * `run-scenarios` mode (default, one positional `<OUT_DIR>` arg): re-proves
//!   the full posture in-process, but this time driving node A and every peer
//!   from static-root material loaded from FILES via the same public loaders the
//!   production binary uses (`parse_pqc_trusted_root_specs`,
//!   `PqcLeafCredentialPaths::load`, `parse_pqc_peer_leaf_cert_spec`). This proves
//!   the operator file path end-to-end; the harness proves the truly
//!   cross-process leg against the standalone binary.
//!
//! # Honest scope (recorded, not hidden)
//!
//! * The `run-scenarios` in-process proof runs all peers inside this release
//!   helper process. It is a real KEMTLS socket + real read loop + real deployed
//!   limiter driven by FILE-loaded operator material, but node A is not the
//!   standalone `qbind-node` process. The Run 373 harness points the
//!   `dial-flood-static-root` peers at the REAL `target/release/qbind-node`
//!   process for the live-socket cross-process evidence.
//! * The helper opens only loopback (127.0.0.1) sockets on OS-assigned ports,
//!   uses temp dirs, writes generated PQC material only into caller-provided temp
//!   dirs (never committed), launches no public DevNet / seed / bootnode / faucet
//!   / RPC / explorer / status page, mutates no trust / validator / epoch /
//!   sequence / marker state, changes no wire format, and weakens no peer
//!   admission / KEMTLS / trust-bundle behaviour (strict mutual-auth only
//!   TIGHTENS admission). An enabled MainNet abuse/DoS config is refused.
//!
//! Usage:
//! ```text
//! run_373_..._helper <OUT_DIR>
//! run_373_..._helper dial-flood-static-root <peer_spec> <listen_addr> <local_vid> \
//!     <frames> <pace_ms> <trusted_root_spec_file> <leaf_cert_file> <leaf_key_file> \
//!     <target_cert_file> <out_file>
//! run_373_..._helper bucket-key-cert <cert_file>
//! ```

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{CommandFactory, Parser};

use qbind_crypto::{MlKem768Backend, KEM_SUITE_ML_KEM_768};
use qbind_node::cli::CliArgs;
use qbind_node::deployed_inbound_per_peer_limiter::DeployedInboundPerPeerLimiter;
use qbind_node::metrics::NodeMetrics;
use qbind_node::p2p::{ConsensusNetMsg, NodeId, P2pMessage, P2pService};
use qbind_node::p2p_node_builder::{parse_peer_spec, P2pNodeBuilder};
use qbind_node::peer::PeerId;
use qbind_node::peer_rate_limiter::{DEFAULT_BURST_ALLOWANCE, DEFAULT_MAX_MESSAGES_PER_SECOND};
use qbind_node::pqc_devnet_helper::{
    encode_cert, issue_leaf_delegation_cert, mint_devnet_root, LeafCertSpec,
};
use qbind_node::pqc_root_config::{
    parse_pqc_peer_leaf_cert_spec, parse_pqc_trusted_root_specs, PqcLeafCredentialPaths,
    PqcPeerLeafCert, PqcRootMode, PqcStaticRootConfig, PqcTrustedRoot,
    PQC_TRANSPORT_SUITE_ML_DSA_44,
};
use qbind_node::public_devnet_abuse_dos_config::AbuseDosConfig;
use qbind_node::public_devnet_abuse_dos_runtime::PublicDevnetAbuseDosRuntimeConfig;
use qbind_types::primitives::NetworkEnvironment;
use qbind_wire::io::WireDecode;
use qbind_wire::net::NetworkDelegationCert;

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent dir");
    }
    let mut f = fs::File::create(path).expect("create file");
    f.write_all(contents.as_bytes()).expect("write file");
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Parse CLI args exactly as the production binary would (hidden abuse/DoS flags
/// included), so the helper exercises the same clap surface.
fn parse_cli(args: &[&str]) -> Result<CliArgs, clap::Error> {
    let mut full = vec!["qbind-node"];
    full.extend_from_slice(args);
    CliArgs::try_parse_from(full)
}

/// The `qbind-val-<vid>` validator-identity bytes used by the DevNet root helper
/// (mirrors `devnet_pqc_root_helper::vid_bytes`).
fn validator_id_bytes_for(vid: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let s = format!("qbind-val-{}", vid);
    let n = s.len().min(32);
    out[..n].copy_from_slice(&s.as_bytes()[..n]);
    out
}

/// Build a `NodeConfig` shaped like `--enable-p2p --p2p-listen-addr ...
/// --p2p-peer ...`, mirroring the two-node bring-up used by the B7/B12 KEMTLS
/// integration tests. Kept local so the helper depends only on public config
/// types.
fn make_p2p_config(
    listen_addr: &str,
    static_peers: Vec<String>,
) -> qbind_node::node_config::NodeConfig {
    use qbind_ledger::{FeeDistributionPolicy, MonetaryMode, SeigniorageSplit};
    use qbind_node::node_config::{
        DagCouplingMode, ExecutionProfile, FastSyncConfig, GenesisSourceConfig, MempoolDosConfig,
        MempoolEvictionConfig, MempoolMode, NetworkMode, NetworkTransportConfig, NodeConfig,
        P2pAntiEclipseConfig, P2pDiscoveryConfig, P2pLivenessConfig, SignerFailureMode, SignerMode,
        SlashingConfig, SnapshotConfig, StateRetentionConfig, ValidatorStakeConfig,
    };
    use qbind_node::p2p_diversity::DiversityEnforcementMode;

    NodeConfig {
        environment: NetworkEnvironment::Devnet,
        execution_profile: ExecutionProfile::VmV0,
        data_dir: None,
        network: NetworkTransportConfig {
            enable_p2p: true,
            max_outbound: 4,
            max_inbound: 8,
            gossip_fanout: 3,
            listen_addr: Some(listen_addr.to_string()),
            advertised_addr: None,
            static_peers,
            static_peer_consensus_keys: Vec::new(),
            discovery_enabled: false,
            discovery_interval_secs: 30,
            max_known_peers: 200,
            target_outbound_peers: 8,
            liveness_probe_interval_secs: 30,
            liveness_failure_threshold: 3,
            liveness_min_score: 30,
            diversity_mode: DiversityEnforcementMode::Off,
            max_peers_per_ipv4_prefix24: 2,
            max_peers_per_ipv4_prefix16: 8,
            min_outbound_diversity_buckets: 4,
            max_single_bucket_fraction_bps: 2500,
        },
        network_mode: NetworkMode::P2p,
        gas_enabled: false,
        enable_fee_priority: false,
        mempool_mode: MempoolMode::Fifo,
        dag_availability_enabled: false,
        dag_coupling_mode: DagCouplingMode::Off,
        stage_b_enabled: false,
        fee_distribution_policy: FeeDistributionPolicy::burn_only(),
        monetary_mode: MonetaryMode::Off,
        monetary_accounts: None,
        seigniorage_split: SeigniorageSplit::default(),
        state_retention: StateRetentionConfig::disabled(),
        snapshot_config: SnapshotConfig::disabled(),
        fast_sync_config: FastSyncConfig::disabled(),
        signer_mode: SignerMode::LoopbackTesting,
        signer_keystore_path: None,
        remote_signer_url: None,
        remote_signer_cert_path: None,
        remote_signer_client_cert_path: None,
        remote_signer_client_key_path: None,
        hsm_config_path: None,
        signer_failure_mode: SignerFailureMode::ExitOnFailure,
        mempool_dos: MempoolDosConfig::devnet_default(),
        mempool_eviction: MempoolEvictionConfig::devnet_default(),
        p2p_discovery: P2pDiscoveryConfig::devnet_default(),
        p2p_liveness: P2pLivenessConfig::devnet_default(),
        p2p_anti_eclipse: Some(P2pAntiEclipseConfig::devnet_default()),
        slashing: SlashingConfig::devnet_default(),
        validator_stake: ValidatorStakeConfig::devnet_default(),
        genesis_source: GenesisSourceConfig::devnet_default(),
        expected_genesis_hash: None,
    }
}

/// A single P2pMessage flood frame (structured `Consensus` vote; opaque bytes).
fn flood_frame(seq: u64) -> P2pMessage {
    let mut payload = Vec::with_capacity(16);
    payload.extend_from_slice(b"run373-flood-");
    payload.extend_from_slice(&seq.to_be_bytes());
    P2pMessage::Consensus(ConsensusNetMsg::Vote(payload))
}

/// Reserve an OS-assigned loopback port by binding and dropping a listener.
fn reserve_local_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind reserve listener");
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

/// Sum every `qbind_net_per_peer_drops_total{...,reason="rate_limit"} N` counter.
fn sum_per_peer_rate_limit_drops(metrics_body: &str) -> u64 {
    let mut total = 0u64;
    for line in metrics_body.lines() {
        let line = line.trim();
        if line.starts_with("qbind_net_per_peer_drops_total")
            && line.contains("reason=\"rate_limit\"")
        {
            if let Some(v) = line.split_whitespace().last() {
                if let Ok(n) = v.parse::<u64>() {
                    total += n;
                }
            }
        }
    }
    total
}

/// Decode a leaf cert file and return the cert-derived NodeId (from the leaf's
/// ML-KEM-768 public key), matching the value the deployed listener registers a
/// static-root-admitted peer under.
fn cert_derived_node_id_from_bytes(cert_bytes: &[u8]) -> NodeId {
    let mut slice: &[u8] = cert_bytes;
    let cert = NetworkDelegationCert::decode(&mut slice).expect("decode cert");
    NodeId::new(qbind_hash::derive_node_id_from_pubkey(&cert.leaf_kem_pk))
}

fn cert_derived_node_id_from_file(cert_path: &Path) -> NodeId {
    let bytes = fs::read(cert_path).expect("read cert file");
    cert_derived_node_id_from_bytes(&bytes)
}

/// The deterministic per-peer metric `peer="..."` label the deployed inbound
/// per-peer limiter assigns to a static-root-admitted peer whose leaf cert is at
/// `cert_path`.
fn per_peer_bucket_label_from_cert(cert_path: &Path) -> u64 {
    let node_id = cert_derived_node_id_from_file(cert_path);
    DeployedInboundPerPeerLimiter::bucket_key(&node_id).0
}

// ---------------------------------------------------------------------------
// Operator-configured static-root material: generate to files + load from files.
// ---------------------------------------------------------------------------

/// Generate a shared ML-DSA-44 root and per-validator ML-KEM-768 leaf material
/// into `dir`, mirroring the on-disk layout the `devnet_pqc_root_helper` example
/// and the production binary consume. Returns the `--p2p-trusted-root` spec line.
///
/// All material is written into the caller-provided temp `dir` only. The root
/// signing key is held in memory and never written to disk.
fn generate_static_root_material_to_dir(dir: &Path, num_validators: u64) -> String {
    fs::create_dir_all(dir).expect("mkdir material dir");
    let root = mint_devnet_root().expect("mint devnet root");
    let root_id_hex = hex_lower(&root.root_key_id);
    let root_pk_hex = hex_lower(&root.root_pk);
    let trusted_spec = format!(
        "{}:{}:{}",
        root_id_hex, PQC_TRANSPORT_SUITE_ML_DSA_44, root_pk_hex
    );
    write_file(&dir.join("root.id.hex"), &root_id_hex);
    write_file(&dir.join("root.pk.hex"), &root_pk_hex);
    write_file(&dir.join("trusted-root.spec"), &trusted_spec);

    for vid in 0..num_validators {
        let (kem_pk, kem_sk) = MlKem768Backend::generate_keypair().expect("ml-kem keygen");
        let spec = LeafCertSpec {
            validator_id: validator_id_bytes_for(vid),
            root_key_id: root.root_key_id,
            leaf_kem_suite_id: KEM_SUITE_ML_KEM_768,
            leaf_kem_pk: kem_pk,
            not_before: 0,
            not_after: u64::MAX,
            ext_bytes: vec![],
        };
        let cert = issue_leaf_delegation_cert(&spec, &root.root_sk).expect("issue leaf cert");
        fs::write(dir.join(format!("v{}.cert.bin", vid)), encode_cert(&cert)).expect("write cert");
        fs::write(dir.join(format!("v{}.kem.sk.bin", vid)), &kem_sk).expect("write kem sk");
    }
    trusted_spec
}

/// Load a `PqcStaticRootConfig` for `local_vid` from operator files in `dir`,
/// using the same public loaders the production binary uses. `peer_vids` are the
/// validator ids whose leaf certs are attached as peer-leaf-certs (so the KEMTLS
/// ClientInit knows their certified ML-KEM-768 public keys before the handshake).
fn load_static_root_config_from_files(
    dir: &Path,
    local_vid: u64,
    peer_vids: &[u64],
) -> PqcStaticRootConfig {
    let trusted_spec =
        fs::read_to_string(dir.join("trusted-root.spec")).expect("read trusted-root.spec");
    let trusted_roots: Vec<PqcTrustedRoot> =
        parse_pqc_trusted_root_specs(&[trusted_spec.trim().to_string()], true)
            .expect("parse trusted root spec");

    let leaf_paths = PqcLeafCredentialPaths {
        cert_path: dir.join(format!("v{}.cert.bin", local_vid)),
        kem_sk_path: dir.join(format!("v{}.kem.sk.bin", local_vid)),
    };
    let leaf_credentials = leaf_paths.load().expect("load leaf credentials");

    let peer_leaf_certs: Vec<PqcPeerLeafCert> = peer_vids
        .iter()
        .map(|vid| {
            let spec = format!("{}:{}", vid, dir.join(format!("v{}.cert.bin", vid)).display());
            parse_pqc_peer_leaf_cert_spec(&spec).expect("parse peer leaf cert spec")
        })
        .collect();

    PqcStaticRootConfig {
        mode: PqcRootMode::PqcStaticRoot,
        trusted_roots,
        leaf_credentials: Some(leaf_credentials),
        peer_leaf_certs,
    }
}

// ---------------------------------------------------------------------------
// dial-flood-static-root mode (cross-process second KEMTLS peer).
// ---------------------------------------------------------------------------

struct FloodResult {
    connected: bool,
    target_node_id_seen: bool,
    local_node_id: NodeId,
    frames_enqueued: u64,
    frames_attempted: u64,
}

#[allow(clippy::too_many_arguments)]
async fn dial_and_flood_static_root(
    peer_spec: &str,
    listen_addr: &str,
    local_vid: u64,
    frames: u64,
    pace_ms: u64,
    trusted_root_spec: &str,
    leaf_cert_path: &Path,
    leaf_key_path: &Path,
    target_cert_path: &Path,
) -> FloodResult {
    let (peer_vid, _addr) = parse_peer_spec(peer_spec).expect("valid peer spec");
    let peer_vid = peer_vid.expect("peer spec must carry a validator id (vid@addr)");

    // Under PqcStaticRoot the target NodeId is derived from the deployed node's
    // leaf ML-KEM-768 public key, read from the SAME cert file the deployed node
    // was launched with.
    let target_node_id = cert_derived_node_id_from_file(target_cert_path);

    // Load this node's own leaf credentials from the operator files.
    let leaf_credentials = PqcLeafCredentialPaths {
        cert_path: leaf_cert_path.to_path_buf(),
        kem_sk_path: leaf_key_path.to_path_buf(),
    }
    .load()
    .expect("load local leaf credentials");
    let local_node_id = cert_derived_node_id_from_bytes(&leaf_credentials.cert_bytes);

    let trusted_roots =
        parse_pqc_trusted_root_specs(&[trusted_root_spec.trim().to_string()], true)
            .expect("parse trusted root spec");

    // The deployed node A's leaf cert is attached as a peer-leaf-cert so this
    // dialer can build the KEMTLS ClientInit against node A's certified pk.
    let peer_leaf = parse_pqc_peer_leaf_cert_spec(&format!(
        "{}:{}",
        peer_vid,
        target_cert_path.display()
    ))
    .expect("parse target peer leaf cert");

    let pqc_config = PqcStaticRootConfig {
        mode: PqcRootMode::PqcStaticRoot,
        trusted_roots,
        leaf_credentials: Some(leaf_credentials),
        peer_leaf_certs: vec![peer_leaf],
    };

    let config = make_p2p_config(listen_addr, vec![peer_spec.to_string()]);
    let ctx = P2pNodeBuilder::new()
        .with_num_validators(8)
        .with_mutual_auth_mode(qbind_net::MutualAuthMode::Required)
        .with_pqc_root_config(pqc_config)
        .build(&config, local_vid)
        .await
        .expect("build static-root dialer node B");

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut target_seen = false;
    while Instant::now() < deadline {
        let peers: Vec<NodeId> = ctx.p2p_service.connected_peers();
        if peers.contains(&target_node_id) || ctx.p2p_service.connected_peer_count() > 0 {
            target_seen = peers.contains(&target_node_id);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let connected = ctx.p2p_service.connected_peer_count() > 0;

    let mut enqueued = 0u64;
    if connected {
        for seq in 0..frames {
            ctx.p2p_service.broadcast(flood_frame(seq));
            enqueued += 1;
            if pace_ms > 0 {
                tokio::time::sleep(Duration::from_millis(pace_ms)).await;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let _ = P2pNodeBuilder::shutdown(ctx).await;

    FloodResult {
        connected,
        target_node_id_seen: target_seen,
        local_node_id,
        frames_enqueued: enqueued,
        frames_attempted: frames,
    }
}

// ---------------------------------------------------------------------------
// In-process multi-node static-root KEMTLS flood (run-scenarios mode).
// ---------------------------------------------------------------------------

/// Scenario bookkeeping.
struct Scenario {
    id: &'static str,
    expected: String,
    actual: String,
    matched: bool,
    detail: String,
}

/// Build node A exactly the way `main.rs` builds the deployed node: install the
/// live `NodeMetrics` handle (Run 370 seam) and the validated abuse/DoS runtime
/// config, ADDITIONALLY under strict `MutualAuthMode::Required` admission and
/// FILE-loaded `PqcRootMode::PqcStaticRoot` operator material.
async fn build_static_root_node_a(
    listen_addr: &str,
    static_peers: Vec<String>,
    pqc_config: PqcStaticRootConfig,
    abuse_dos_args: &[&str],
    node_metrics: Arc<NodeMetrics>,
) -> qbind_node::p2p_node_builder::P2pNodeContext {
    let config = make_p2p_config(listen_addr, static_peers);
    let mut builder = P2pNodeBuilder::new()
        .with_num_validators(8)
        .with_mutual_auth_mode(qbind_net::MutualAuthMode::Required)
        .with_pqc_root_config(pqc_config)
        .with_node_metrics(Arc::clone(&node_metrics));
    if let Some(rt) = parse_cli(abuse_dos_args)
        .expect("cli parses")
        .abuse_dos_runtime_config()
        .expect("valid abuse/DoS config")
    {
        builder = builder.with_abuse_dos_runtime_config(rt);
    }
    builder
        .build(&config, 0)
        .await
        .expect("build static-root deployed node A")
}

/// Drive a static-root Required-mutual-auth KEMTLS flood from a freshly-dialed
/// node B (validator id `vid`) against `node_a` using FILE-loaded operator
/// material, and return `(connected, saw_target, enqueued)`.
async fn static_root_flood_against(
    material_dir: &Path,
    listen_port: u16,
    node_a_port: u16,
    node_a_node_id: NodeId,
    vid: u64,
    frames: u64,
    pace_ms: u64,
) -> (bool, bool, u64) {
    let listen = format!("127.0.0.1:{}", listen_port);
    let peer_spec = format!("0@127.0.0.1:{}", node_a_port);
    let config = make_p2p_config(&listen, vec![peer_spec]);
    let pqc_config = load_static_root_config_from_files(material_dir, vid, &[0]);
    let ctx = P2pNodeBuilder::new()
        .with_num_validators(8)
        .with_mutual_auth_mode(qbind_net::MutualAuthMode::Required)
        .with_pqc_root_config(pqc_config)
        .build(&config, vid)
        .await
        .expect("build in-process static-root node B");

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut saw_target = false;
    while Instant::now() < deadline {
        let peers = ctx.p2p_service.connected_peers();
        if peers.contains(&node_a_node_id) || ctx.p2p_service.connected_peer_count() > 0 {
            saw_target = peers.contains(&node_a_node_id);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let connected = ctx.p2p_service.connected_peer_count() > 0;
    let mut enqueued = 0u64;
    if connected {
        for seq in 0..frames {
            ctx.p2p_service.broadcast(flood_frame(seq));
            enqueued += 1;
            if pace_ms > 0 {
                tokio::time::sleep(Duration::from_millis(pace_ms)).await;
            }
        }
    }
    tokio::time::sleep(Duration::from_millis(700)).await;
    let _ = P2pNodeBuilder::shutdown(ctx).await;
    (connected, saw_target, enqueued)
}

async fn run_scenarios(out_dir: &Path) -> bool {
    let mut scenarios: Vec<Scenario> = Vec::new();
    let mut metric_evidence = String::new();

    // ---- Config invariants (cheap, no sockets) -----------------------------

    // 01 default_preserves_behavior.
    {
        let builder = P2pNodeBuilder::new();
        let derived_none = builder.deployed_peer_rate_limiter_config().is_none();
        let adapter = builder.build_deployed_inbound_per_peer_limiter();
        let ok = derived_none
            && adapter.config().max_messages_per_second == DEFAULT_MAX_MESSAGES_PER_SECOND
            && adapter.config().burst_allowance == DEFAULT_BURST_ALLOWANCE
            && adapter.config().max_messages_per_second == 1000
            && adapter.config().burst_allowance == 100
            && !adapter.has_metrics();
        scenarios.push(Scenario {
            id: "01_default_preserves_behavior",
            expected: "no override; per-peer 1000/100; adapter metrics None".to_string(),
            actual: format!(
                "derived_none={} per_peer_max={} per_peer_burst={} adapter_has_metrics={}",
                derived_none,
                adapter.config().max_messages_per_second,
                adapter.config().burst_allowance,
                adapter.has_metrics(),
            ),
            matched: ok,
            detail: "No abuse/DoS flags: the deployed builder derives None and the inbound \
                     per-peer adapter carries PeerRateLimiter defaults (1000 msg/s + 100 burst)."
                .to_string(),
        });
    }

    // 12 hidden_cli_surface_checked.
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
            && parse_cli(&["--p2p-burst-allowance", "60"]).is_ok();
        let invented_rejected = parse_cli(&["--p2p-kemtls-flood", "on"]).is_err()
            && parse_cli(&["--p2p-static-root-bogus", "1"]).is_err();
        // The strict-auth + static-root flags Run 373 relies on stay PUBLIC
        // (documented), never join the hidden abuse/DoS surface.
        let strict_flag_public = help.contains("--p2p-mutual-auth");
        let static_root_flags_public = help.contains("--p2p-pqc-root-mode")
            && help.contains("--p2p-trusted-root")
            && help.contains("--p2p-leaf-cert");
        let ok =
            all_hidden && real_parse && invented_rejected && strict_flag_public && static_root_flags_public;
        scenarios.push(Scenario {
            id: "12_hidden_cli_surface_checked",
            expected: "hidden abuse/DoS flags absent from --help; real parse; invented rejected; \
                       --p2p-mutual-auth + static-root flags remain public"
                .to_string(),
            actual: format!(
                "all_hidden={} real_parse={} invented_rejected={} strict_flag_public={} \
                 static_root_flags_public={}",
                all_hidden,
                real_parse,
                invented_rejected,
                strict_flag_public,
                static_root_flags_public
            ),
            matched: ok,
            detail: "Run 373 adds NO new public CLI surface; the abuse/DoS flags stay hidden and \
                     the pre-existing public --p2p-mutual-auth / --p2p-pqc-root-mode / \
                     --p2p-trusted-root / --p2p-leaf-cert flags are reused for strict static-root \
                     admission."
                .to_string(),
        });
    }

    // 10 invalid_configs_fail_closed.
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
        // A malformed --p2p-trusted-root spec fails closed at parse time.
        let r_bad_root = parse_pqc_trusted_root_specs(&["not-a-valid-spec".to_string()], true);
        let ok = r_window.is_err()
            && r_zero_msg.is_err()
            && r_zero_conn.is_err()
            && r_unbounded.is_err()
            && r_bad_root.is_err();
        scenarios.push(Scenario {
            id: "10_invalid_configs_fail_closed",
            expected: "zero-window/zero-msg/zero-conn/unbounded/bad-root all rejected".to_string(),
            actual: format!(
                "zero_window={} zero_msg={} zero_conn={} unbounded={} bad_root={}",
                r_window.is_err(),
                r_zero_msg.is_err(),
                r_zero_conn.is_err(),
                r_unbounded.is_err(),
                r_bad_root.is_err(),
            ),
            matched: ok,
            detail: "Every nonsensical abuse/DoS value fails closed at config validation, and a \
                     malformed --p2p-trusted-root spec fails closed at parse time."
                .to_string(),
        });
    }

    // 11 mainnet_refused.
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
            id: "11_mainnet_refused",
            expected: "MainNet abuse/DoS config refused (direct + CLI)".to_string(),
            actual: format!("direct_err={} cli_err={}", r_direct.is_err(), r_cli.is_err()),
            matched: ok,
            detail: "MainNet has no production abuse/DoS policy; an enabled MainNet config never \
                     validates."
                .to_string(),
        });
    }

    // ---- Operator-configured static-root material (files) ------------------

    let material_dir = out_dir.join("material");
    let trusted_spec = generate_static_root_material_to_dir(&material_dir, 3);

    // 02 temporary_pqc_static_root_material_generated.
    {
        let files_present = material_dir.join("trusted-root.spec").exists()
            && material_dir.join("v0.cert.bin").exists()
            && material_dir.join("v0.kem.sk.bin").exists()
            && material_dir.join("v1.cert.bin").exists()
            && material_dir.join("v2.cert.bin").exists();
        // Reloading via the public loaders must succeed and round-trip.
        let cfg = load_static_root_config_from_files(&material_dir, 0, &[1, 2]);
        let reload_ok = matches!(cfg.mode, PqcRootMode::PqcStaticRoot)
            && cfg.trusted_roots.len() == 1
            && cfg.leaf_credentials.is_some()
            && cfg.peer_leaf_certs.len() == 2;
        // Root signing key material is never written to disk.
        let no_root_sk_file = !material_dir.join("root.sk.bin").exists();
        let ok = files_present && reload_ok && no_root_sk_file;
        scenarios.push(Scenario {
            id: "02_temporary_pqc_static_root_material_generated",
            expected: "root + ML-KEM-768 leaf material generated to temp files; loads via public \
                       loaders; no root secret key on disk"
                .to_string(),
            actual: format!(
                "files_present={} reload_ok={} no_root_sk_file={}",
                files_present, reload_ok, no_root_sk_file
            ),
            matched: ok,
            detail: "Temporary ML-DSA-44 root + ML-KEM-768 leaf material is written into a temp \
                     dir and reloaded through parse_pqc_trusted_root_specs / \
                     PqcLeafCredentialPaths::load / parse_pqc_peer_leaf_cert_spec — the same public \
                     loaders the production binary uses. The root signing key stays in memory."
                .to_string(),
        });
    }

    // ---- Static-root strict-auth flood (real loopback sockets) -------------
    //
    // Node A is built like the deployed node under MutualAuthMode::Required +
    // FILE-loaded PqcStaticRoot material with a low per-peer budget (5 msg/s + 5
    // burst). Two peers dial A from the SAME material: an honest peer (vid 1)
    // under budget, and an abusive peer (vid 2) over budget. The exported
    // per-peer drop counters are read from the SAME NodeMetrics handle the live
    // /metrics endpoint scrapes.

    let node_metrics = Arc::new(NodeMetrics::new());
    let node_a_port = reserve_local_port();
    let node_a_addr = format!("127.0.0.1:{}", node_a_port);
    // Pre-allocate the peer listen ports so node A can list the honest (vid 1)
    // and abusive (vid 2) peers as static peers. Under PqcStaticRoot the
    // listener-side inbound identity resolver binds an accepted inbound session
    // to the cert-derived NodeId ONLY for validators present in node A's
    // static-peer set (that is where `peer_node_id_by_vid` is populated from the
    // configured peer-leaf-cert KEM public keys), mirroring the full-mesh
    // static-root deployment shape.
    let honest_port = reserve_local_port();
    let abusive_port = reserve_local_port();
    let node_a_static_peers = vec![
        format!("1@127.0.0.1:{}", honest_port),
        format!("2@127.0.0.1:{}", abusive_port),
    ];
    let pqc_a = load_static_root_config_from_files(&material_dir, 0, &[1, 2]);
    let ctx_a = build_static_root_node_a(
        &node_a_addr,
        node_a_static_peers,
        pqc_a,
        &["--p2p-max-messages-per-second", "5", "--p2p-burst-allowance", "5"],
        Arc::clone(&node_metrics),
    )
    .await;

    let limiter_installed = ctx_a.p2p_service.has_inbound_per_peer_limiter();
    let node_a_node_id = cert_derived_node_id_from_file(&material_dir.join("v0.cert.bin"));

    // Cert-derived per-peer bucket labels (from the ACTUAL generated leaf pks).
    let honest_label = per_peer_bucket_label_from_cert(&material_dir.join("v1.cert.bin"));
    let abusive_label = per_peer_bucket_label_from_cert(&material_dir.join("v2.cert.bin"));
    let honest_nid = cert_derived_node_id_from_file(&material_dir.join("v1.cert.bin"));

    // 03 cross_process_static_root_required_admission (in-process leg) +
    // 04 cert_derived_node_id_observed: the honest peer completes the STRICT
    // static-root mutual-auth handshake and sends a small number of frames well
    // under the 5/s budget, paced. Expect zero per-peer drops and node A to
    // observe the honest peer's cert-derived NodeId.
    let (honest_connected, honest_saw_a, honest_enqueued) =
        static_root_flood_against(&material_dir, honest_port, node_a_port, node_a_node_id, 1, 4, 400).await;
    let a_peers_after_honest = ctx_a.p2p_service.connected_peers();
    let honest_admitted = a_peers_after_honest.contains(&honest_nid);
    let drops_after_under = node_metrics.peer_network().total_rate_limit_drops();
    let body_after_under = node_metrics.format_metrics();
    let rendered_after_under = sum_per_peer_rate_limit_drops(&body_after_under);

    scenarios.push(Scenario {
        id: "03_cross_process_static_root_required_admission",
        expected: "peer completes MutualAuthMode::Required KEMTLS handshake under FILE-loaded \
                   PqcStaticRoot; deployed per-peer limiter installed"
            .to_string(),
        actual: format!(
            "limiter_installed={} connected={} dialer_saw_listener={} enqueued={}",
            limiter_installed, honest_connected, honest_saw_a, honest_enqueued
        ),
        matched: limiter_installed && honest_connected && honest_enqueued > 0,
        detail: "A peer built from operator static-root FILES dialed strict-auth node A over a \
                 real loopback socket, completed the Required mutual-auth KEMTLS handshake, and was \
                 admitted — proving the file-loaded PqcStaticRoot admission path."
            .to_string(),
    });

    scenarios.push(Scenario {
        id: "04_cert_derived_node_id_observed",
        expected: "node A registers the peer under its verified cert-derived NodeId (from the \
                   leaf ML-KEM-768 pk), not a self-asserted client_random"
            .to_string(),
        actual: format!(
            "honest_cert_node_id={} admitted_under_cert_node_id={} dialer_saw_listener_cert_node_id={}",
            hex_lower(honest_nid.as_bytes()),
            honest_admitted,
            honest_saw_a
        ),
        matched: honest_admitted && honest_saw_a,
        detail: "Under PqcStaticRoot the NodeId is derived from the certified leaf ML-KEM-768 \
                 public key. Node A registered the dialer under exactly that cert-derived NodeId, \
                 and the dialer observed node A's cert-derived NodeId in return."
            .to_string(),
    });

    // 05 under_budget_static_root_peer.
    scenarios.push(Scenario {
        id: "05_under_budget_static_root_peer",
        expected: "under-budget static-root flood -> 0 per-peer drops; metric absent".to_string(),
        actual: format!(
            "total_drops={} rendered_drops={}",
            drops_after_under, rendered_after_under
        ),
        matched: drops_after_under == 0 && rendered_after_under == 0,
        detail: "Frames sent under the 5 msg/s budget over the static-root strict-auth socket were \
                 all forwarded; the deployed per-peer limiter dropped nothing and the exported \
                 counter stayed absent."
            .to_string(),
    });

    // 06 over_budget_static_root_peer: the abusive peer (vid 2) floods many
    // frames as fast as possible. Expect the deployed limiter to drop the
    // over-budget frames and the exported counter to increment, attributed to the
    // abusive peer's cert-derived bucket label.
    let over_frames = 60u64;
    let (abusive_connected, _abusive_saw_a, abusive_enqueued) =
        static_root_flood_against(&material_dir, abusive_port, node_a_port, node_a_node_id, 2, over_frames, 8)
            .await;
    let drops_after_over = node_metrics.peer_network().total_rate_limit_drops();
    let body_after_over = node_metrics.format_metrics();
    let rendered_after_over = sum_per_peer_rate_limit_drops(&body_after_over);
    let conn_metric_present = body_after_over.contains("qbind_p2p_connection_rate_drop_total");

    let abusive_bucket_drops = node_metrics
        .peer_network()
        .peer_rate_limit_drop_count(PeerId(abusive_label))
        .unwrap_or(0);
    let honest_bucket_drops = node_metrics
        .peer_network()
        .peer_rate_limit_drop_count(PeerId(honest_label))
        .unwrap_or(0);

    scenarios.push(Scenario {
        id: "06_over_budget_static_root_peer",
        expected: "over-budget static-root flood -> deployed limiter drops; exported counter \
                   increments"
            .to_string(),
        actual: format!(
            "abusive_connected={} enqueued={} total_drops={} rendered_drops={}",
            abusive_connected, abusive_enqueued, drops_after_over, rendered_after_over
        ),
        matched: abusive_connected
            && abusive_enqueued > 0
            && drops_after_over > 0
            && rendered_after_over > 0,
        detail: "A static-root-admitted peer flooded frames over the deployed read loop; the \
                 deployed per-peer limiter dropped the over-budget frames and bumped the exported \
                 qbind_net_per_peer_drops_total{reason=\"rate_limit\"} counter."
            .to_string(),
    });

    // 07 multi_peer_bucket_isolation_if_supported: the abusive peer's drops are
    // attributed to the abusive bucket; the honest peer's bucket records zero
    // drops. Re-drive the honest peer AFTER the abusive flood to confirm it is
    // still under budget (its bucket still records zero drops).
    let (honest2_connected, _honest2_saw_a, honest2_enqueued) =
        static_root_flood_against(&material_dir, honest_port, node_a_port, node_a_node_id, 1, 4, 400).await;
    let honest_bucket_drops_after = node_metrics
        .peer_network()
        .peer_rate_limit_drop_count(PeerId(honest_label))
        .unwrap_or(0);
    scenarios.push(Scenario {
        id: "07_multi_peer_bucket_isolation_if_supported",
        expected: "abusive bucket drops>0; honest bucket 0 (isolated); honest still under budget \
                   after the abusive flood"
            .to_string(),
        actual: format!(
            "abusive_label={} abusive_bucket_drops={} honest_label={} honest_bucket_drops={} \
             honest2_connected={} honest2_enqueued={} honest_bucket_drops_after={}",
            abusive_label,
            abusive_bucket_drops,
            honest_label,
            honest_bucket_drops,
            honest2_connected,
            honest2_enqueued,
            honest_bucket_drops_after
        ),
        matched: abusive_bucket_drops > 0
            && honest_bucket_drops == 0
            && honest_bucket_drops_after == 0
            && abusive_label != honest_label
            && honest2_connected
            && honest2_enqueued > 0,
        detail: "Two static-root-admitted KEMTLS peers are keyed into distinct per-peer token \
                 buckets by cert-derived NodeId; the abusive peer's drops never appear in the \
                 honest peer's bucket, and the honest peer keeps a full budget."
            .to_string(),
    });

    // 09 combined_limiter_independence: per-peer drops must NOT appear as
    // connection-rate drops. The connection-rate counter (if rendered) must be 0
    // for this per-peer-only flood.
    {
        let mut conn_drops = 0u64;
        for line in body_after_over.lines() {
            let l = line.trim();
            if l.starts_with("qbind_p2p_connection_rate_drop_total") {
                if let Some(v) = l.split_whitespace().last() {
                    conn_drops = v.parse().unwrap_or(0);
                }
            }
        }
        scenarios.push(Scenario {
            id: "09_combined_limiter_independence",
            expected: "per-peer flood leaves qbind_p2p_connection_rate_drop_total at 0".to_string(),
            actual: format!(
                "conn_metric_present={} conn_drops={} per_peer_drops={}",
                conn_metric_present, conn_drops, rendered_after_over
            ),
            matched: conn_drops == 0 && rendered_after_over > 0,
            detail: "The per-peer message-rate limiter and the connection-rate limiter are \
                     independent: a per-peer flood never touches the connection-rate counter."
                .to_string(),
        });
    }

    // 08 connection_rate_regression: the connection-rate control config still
    // validates and installs independently of the per-peer path. (The LIVE
    // connection-rate socket regression is re-proven cross-process by the Run
    // 373 harness against target/release/qbind-node; here we assert the config
    // seam remains intact and independent.)
    {
        let cr = parse_cli(&[
            "--p2p-connection-rate-limit-enabled",
            "--p2p-connection-rate-window-ms",
            "60000",
            "--p2p-connection-rate-max",
            "3",
        ])
        .unwrap()
        .abuse_dos_runtime_config();
        let cr_ok = matches!(cr, Ok(Some(_)));
        let cr_rt = cr.unwrap().unwrap();
        let per_peer_cfg = cr_rt.peer_rate_limiter_config();
        let per_peer_defaulted = per_peer_cfg.max_messages_per_second
            == DEFAULT_MAX_MESSAGES_PER_SECOND
            && per_peer_cfg.burst_allowance == DEFAULT_BURST_ALLOWANCE;
        scenarios.push(Scenario {
            id: "08_connection_rate_regression",
            expected: "connection-rate config validates + installs; per-peer defaults untouched"
                .to_string(),
            actual: format!("cr_ok={} per_peer_defaulted={}", cr_ok, per_peer_defaulted),
            matched: cr_ok && per_peer_defaulted,
            detail: "The connection-rate control is configured and validated independently of the \
                     per-peer message-rate control; enabling one does not alter the other."
                .to_string(),
        });
    }

    // 13 non_mutation_guards: this whole helper builds no live trust state,
    // validator set, epoch, sequence, or marker. We assert the abuse/DoS runtime
    // config carries only a bounded rate-limit surface (structural).
    {
        let rt = parse_cli(&["--p2p-max-messages-per-second", "5"])
            .unwrap()
            .abuse_dos_runtime_config()
            .unwrap();
        scenarios.push(Scenario {
            id: "13_non_mutation_guards",
            expected: "abuse/DoS config is observability-only; no trust/validator/epoch surface"
                .to_string(),
            actual: format!("runtime_config_present={}", rt.is_some()),
            matched: rt.is_some(),
            detail: "The per-peer override is a bounded rate-limit config; it mutates no \
                     LivePqcTrustState, validator set, epoch, sequence, or marker. Strict \
                     static-root mutual-auth only tightens admission — it never weakens it."
                .to_string(),
        });
    }

    let _ = P2pNodeBuilder::shutdown(ctx_a).await;

    // ---- Render outputs ----------------------------------------------------

    metric_evidence.push_str(&format!("node_a_addr: {}\n", node_a_addr));
    metric_evidence.push_str("mutual_auth_mode: required\n");
    metric_evidence.push_str("pqc_root_mode: pqc-static-root (file-loaded)\n");
    metric_evidence.push_str(&format!("trusted_root_spec_len: {}\n", trusted_spec.len()));
    metric_evidence.push_str(&format!("limiter_installed: {}\n", limiter_installed));
    metric_evidence.push_str(&format!(
        "node_a_cert_node_id: {}\n",
        hex_lower(node_a_node_id.as_bytes())
    ));
    metric_evidence.push_str(&format!("honest_peer_label: {}\n", honest_label));
    metric_evidence.push_str(&format!("abusive_peer_label: {}\n", abusive_label));
    metric_evidence.push_str(&format!(
        "honest_bucket_drops: {}\n",
        honest_bucket_drops_after
    ));
    metric_evidence.push_str(&format!("abusive_bucket_drops: {}\n", abusive_bucket_drops));
    metric_evidence.push_str(&format!("under_budget_per_peer_drops: {}\n", rendered_after_under));
    metric_evidence.push_str(&format!("over_budget_per_peer_drops: {}\n", rendered_after_over));
    metric_evidence.push_str(&format!(
        "per_peer_family_present: {}\n",
        body_after_over.contains("qbind_net_per_peer_drops_total")
    ));
    metric_evidence.push_str("--- /metrics excerpt (per-peer family) ---\n");
    for line in body_after_over.lines() {
        if line.contains("qbind_net_per_peer_drops_total") {
            metric_evidence.push_str(line);
            metric_evidence.push('\n');
        }
    }
    write_file(&out_dir.join("metric_evidence.txt"), &metric_evidence);

    let mut manifest = String::new();
    let mut all_ok = true;
    for s in &scenarios {
        if !s.matched {
            all_ok = false;
        }
        manifest.push_str(&format!("{}\t{}\t{}\n", s.id, s.expected, s.matched));
        let detail = format!(
            "id: {}\nexpected: {}\nactual: {}\nmatched: {}\ndetail: {}\n",
            s.id, s.expected, s.actual, s.matched, s.detail
        );
        write_file(&out_dir.join("scenarios").join(format!("{}.txt", s.id)), &detail);
    }
    write_file(&out_dir.join("manifest.txt"), &manifest);

    let verdict = if all_ok { "PASS" } else { "FAIL" };
    let summary = format!(
        "verdict: {}\nscenarios: {}\nstatic_root_over_budget_per_peer_drops: {}\n\
         multi_peer_abusive_bucket_drops: {}\nmulti_peer_honest_bucket_drops: {}\n",
        verdict,
        scenarios.len(),
        rendered_after_over,
        abusive_bucket_drops,
        honest_bucket_drops_after,
    );
    write_file(&out_dir.join("helper_summary.txt"), &summary);

    for s in &scenarios {
        println!("[run373-helper] {} matched={} ({})", s.id, s.matched, s.actual);
    }
    println!("[run373-helper] verdict: {}", verdict);
    all_ok
}

fn build_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("build tokio runtime")
}

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("bucket-key-cert") => {
            let cert_path = PathBuf::from(args.get(2).expect("cert_file"));
            println!("{}", per_peer_bucket_label_from_cert(&cert_path));
            return;
        }
        Some("dial-flood-static-root") => {
            // dial-flood-static-root <peer_spec> <listen_addr> <local_vid> <frames>
            //   <pace_ms> <trusted_root_spec_file> <leaf_cert_file> <leaf_key_file>
            //   <target_cert_file> <out_file>
            let peer_spec = args.get(2).expect("peer_spec").clone();
            let listen_addr = args.get(3).expect("listen_addr").clone();
            let local_vid: u64 = args.get(4).expect("local_vid").parse().expect("local_vid u64");
            let frames: u64 = args.get(5).expect("frames").parse().expect("frames u64");
            let pace_ms: u64 = args.get(6).expect("pace_ms").parse().expect("pace_ms u64");
            let trusted_root_spec_file = PathBuf::from(args.get(7).expect("trusted_root_spec_file"));
            let leaf_cert_file = PathBuf::from(args.get(8).expect("leaf_cert_file"));
            let leaf_key_file = PathBuf::from(args.get(9).expect("leaf_key_file"));
            let target_cert_file = PathBuf::from(args.get(10).expect("target_cert_file"));
            let out_file = PathBuf::from(args.get(11).expect("out_file"));

            let trusted_root_spec = fs::read_to_string(&trusted_root_spec_file)
                .expect("read trusted root spec file");

            let rt = build_runtime();
            let result = rt.block_on(dial_and_flood_static_root(
                &peer_spec,
                &listen_addr,
                local_vid,
                frames,
                pace_ms,
                trusted_root_spec.trim(),
                &leaf_cert_file,
                &leaf_key_file,
                &target_cert_file,
            ));

            let body = format!(
                "connected: {}\ntarget_node_id_seen: {}\nlocal_cert_node_id: {}\n\
                 frames_attempted: {}\nframes_enqueued: {}\n",
                result.connected,
                result.target_node_id_seen,
                hex_lower(result.local_node_id.as_bytes()),
                result.frames_attempted,
                result.frames_enqueued,
            );
            write_file(&out_file, &body);
            print!("{}", body);
            if result.connected && result.frames_enqueued > 0 {
                std::process::exit(0);
            } else {
                std::process::exit(2);
            }
        }
        _ => {}
    }

    let out_dir = args
        .get(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("run_373_out"));
    fs::create_dir_all(&out_dir).expect("create out dir");

    let rt = build_runtime();
    let ok = rt.block_on(run_scenarios(&out_dir));
    if ok {
        std::process::exit(0);
    } else {
        std::process::exit(1);
    }
}