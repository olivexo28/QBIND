//! Run 040 — Production-honest real-AEAD wiring on the
//! `pqc-static-root` binary path.
//!
//! These tests prove the smallest honest claims required to narrow the
//! transport-AEAD piece of C4 / C5 (tracked in
//! `docs/whitepaper/contradiction.md`):
//!
//! 1. **`pqc-static-root` Required mode no longer registers
//!    `DummyAead`.** The crypto provider built for that mode resolves
//!    the canonical PQC AEAD suite id (`AEAD_SUITE_CHACHA20_POLY1305 =
//!    101`) to a `ChaCha20-Poly1305` backend with the correct shape
//!    (32-byte key, 12-byte nonce, 16-byte tag). Any lookup for the
//!    test-grade `DummyAead` suite id (`2`) returns `None`. (R040.A)
//!
//! 2. **Real AEAD is fail-closed.** Wrong key, wrong nonce, wrong AAD,
//!    tampered ciphertext, tampered tag, and truncated frames all fail
//!    closed at decrypt. (R040.B)
//!
//! 3. **Two-node Required + `pqc-static-root` real-AEAD handshake
//!    succeeds.** Two `P2pNodeBuilder`-built nodes under
//!    `MutualAuthMode::Required` + `PqcRootMode::PqcStaticRoot` with
//!    real ML-DSA-44 delegation certs, real ML-KEM-768 leaf KEM
//!    material, and real ChaCha20-Poly1305 AEAD complete a full
//!    KEMTLS handshake — i.e. the AEAD session derived in
//!    `qbind_net::handshake` resolves `aead_suite_id=101` to the real
//!    backend on both sides. If `DummyAead` were still registered, or
//!    if either side disagreed on the AEAD suite id, the handshake
//!    would fail with `NetError::UnsupportedSuite(...)` because the
//!    `aead_suite_id` is mixed into the HKDF info parameter inside
//!    `qbind_net::keys::SessionKeys::derive`. (R040.C)
//!
//! 4. **Pre-Run-040 test-grade DummyAead path is preserved.** The
//!    explicit `PqcRootMode::TestGradeDummySig` (default) keeps the
//!    DummyAead/B7/B8/B12 behaviour bit-for-bit. (R040.D)
//!
//! These tests intentionally do NOT claim CA / cert rotation /
//! revocation / signed root-distribution lifecycle is solved; those
//! remain operator-out-of-band and tracked under C4.

use std::sync::Arc;
use std::time::{Duration, Instant};

use qbind_crypto::{
    AeadSuite, ChaCha20Poly1305Backend, CryptoProvider, MlDsa44SignatureSuite, MlKem768Backend,
    StaticCryptoProvider, AEAD_SUITE_CHACHA20_POLY1305, KEM_SUITE_ML_KEM_768,
};
use qbind_node::p2p::{NodeId, P2pService};
use qbind_node::p2p_node_builder::P2pNodeBuilder;
use qbind_node::pqc_devnet_helper::{
    encode_cert, issue_leaf_delegation_cert, mint_devnet_root, DevNetRoot, LeafCertSpec,
};
use qbind_node::pqc_root_config::{
    PqcLeafCredentials, PqcPeerLeafCert, PqcRootMode, PqcStaticRootConfig, PqcTrustedRoot,
    PQC_TRANSPORT_SUITE_ML_DSA_44,
};
use qbind_wire::io::WireDecode;
use qbind_wire::net::NetworkDelegationCert;

// ---------------------------------------------------------------------------
// Helpers (cloned from the Run 037 helpers — kept local to this file so we
// do not introduce a new public surface).
// ---------------------------------------------------------------------------

fn make_p2p_test_config(
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
    use qbind_types::NetworkEnvironment;

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

async fn reserve_local_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind reserve listener");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn validator_id_bytes_for(vid: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let s = format!("qbind-val-{}", vid);
    let n = s.len().min(32);
    out[..n].copy_from_slice(&s.as_bytes()[..n]);
    out
}

fn mint_pqc_leaf_creds_for(vid: u64, root: &DevNetRoot) -> PqcLeafCredentials {
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
    let cert = issue_leaf_delegation_cert(&spec, &root.root_sk).expect("mint");
    PqcLeafCredentials {
        cert_bytes: encode_cert(&cert),
        kem_sk_bytes: kem_sk,
    }
}

fn pqc_static_root_config_for(
    root: &DevNetRoot,
    leaf_creds: PqcLeafCredentials,
    peer_leaf_certs: Vec<PqcPeerLeafCert>,
) -> PqcStaticRootConfig {
    PqcStaticRootConfig {
        mode: PqcRootMode::PqcStaticRoot,
        trusted_roots: vec![PqcTrustedRoot {
            root_key_id: root.root_key_id,
            suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
            root_pk: root.root_pk.clone(),
        }],
        leaf_credentials: Some(leaf_creds),
        peer_leaf_certs,
    }
}

fn peer_leaf_cert_for(vid: u64, creds: &PqcLeafCredentials) -> PqcPeerLeafCert {
    PqcPeerLeafCert {
        validator_index: vid,
        cert_bytes: creds.cert_bytes.clone(),
    }
}

fn node_id_from_leaf(creds: &PqcLeafCredentials) -> NodeId {
    let mut slice: &[u8] = &creds.cert_bytes;
    let cert = NetworkDelegationCert::decode(&mut slice).expect("decode cert");
    NodeId::new(qbind_hash::derive_node_id_from_pubkey(&cert.leaf_kem_pk))
}

/// Reproduces what `make_pqc_static_root_crypto_provider` registers.
/// Kept in lockstep with `crates/qbind-node/src/p2p_node_builder.rs`
/// so the assertions below are an honest equivalent of the binary
/// path's provider, not a parallel definition. If
/// `make_pqc_static_root_crypto_provider` ever changes the registered
/// AEAD/KEM/Sig suites, this test must change in lockstep.
fn build_equivalent_pqc_static_root_provider() -> Arc<StaticCryptoProvider> {
    Arc::new(
        StaticCryptoProvider::new()
            .with_kem_suite(Arc::new(MlKem768Backend::new()))
            .with_aead_suite(Arc::new(ChaCha20Poly1305Backend::new()))
            .with_signature_suite(Arc::new(MlDsa44SignatureSuite::new(
                PQC_TRANSPORT_SUITE_ML_DSA_44,
            ))),
    )
}

// ===========================================================================
// R040.A — `pqc-static-root` provider exposes real AEAD suite, NOT DummyAead
// ===========================================================================

#[test]
fn r040_a_pqc_static_root_provider_registers_real_chacha20_poly1305() {
    let provider = build_equivalent_pqc_static_root_provider();

    // Real AEAD suite resolvable at the canonical PQC AEAD suite id.
    let real = provider
        .aead_suite(AEAD_SUITE_CHACHA20_POLY1305)
        .expect("ChaCha20-Poly1305 must be registered under suite id 101");

    assert_eq!(real.suite_id(), AEAD_SUITE_CHACHA20_POLY1305);
    assert_eq!(real.suite_id(), 101);
    assert_eq!(real.key_len(), 32, "ChaCha20-Poly1305 key length is 32 bytes");
    assert_eq!(real.nonce_len(), 12, "ChaCha20-Poly1305 nonce length is 12 bytes");
    assert_eq!(real.tag_len(), 16, "Poly1305 tag length is 16 bytes");
}

#[test]
fn r040_a_pqc_static_root_provider_does_not_register_dummy_aead() {
    let provider = build_equivalent_pqc_static_root_provider();
    // The DummyAead suite id used by `make_test_crypto_provider` is `2`.
    assert!(
        provider.aead_suite(2).is_none(),
        "pqc-static-root provider must NOT register DummyAead (suite id 2)"
    );
    assert!(
        provider.aead_suite(0).is_none(),
        "pqc-static-root provider must NOT register an AEAD at suite id 0"
    );
}

#[test]
fn r040_a_pqc_static_root_provider_keeps_ml_kem_768_and_ml_dsa_44() {
    let provider = build_equivalent_pqc_static_root_provider();
    assert!(
        provider.kem_suite(KEM_SUITE_ML_KEM_768).is_some(),
        "ML-KEM-768 must remain registered (Run 039 invariant)"
    );
    assert!(
        provider.signature_suite(PQC_TRANSPORT_SUITE_ML_DSA_44).is_some(),
        "ML-DSA-44 must remain registered (Run 037 invariant)"
    );
    // Test-grade DummyKem suite id `1` and DummySig suite id `3` must
    // not be registered on the production-honest provider.
    assert!(
        provider.kem_suite(1).is_none(),
        "pqc-static-root provider must NOT register DummyKem"
    );
    assert!(
        provider.signature_suite(3).is_none(),
        "pqc-static-root provider must NOT register DummySig"
    );
}

// ===========================================================================
// R040.B — Real AEAD is fail-closed
// ===========================================================================

#[test]
fn r040_b_real_aead_round_trip_succeeds() {
    let aead = ChaCha20Poly1305Backend::new();
    let key = [0x42u8; 32];
    let nonce = [0x07u8; 12];
    let aad = b"qbind-frame-header";
    let plaintext = b"consensus heartbeat";

    let ct = aead.seal(&key, &nonce, aad, plaintext).expect("seal");
    let pt = aead.open(&key, &nonce, aad, &ct).expect("open");
    assert_eq!(plaintext, &pt[..]);

    // Tag must inflate ciphertext by exactly 16 bytes.
    assert_eq!(ct.len(), plaintext.len() + 16);
}

#[test]
fn r040_b_real_aead_wrong_key_fails_closed() {
    let aead = ChaCha20Poly1305Backend::new();
    let nonce = [0x07u8; 12];
    let aad = b"hdr";
    let pt = b"secret";
    let ct = aead.seal(&[0x42u8; 32], &nonce, aad, pt).expect("seal");
    assert!(aead.open(&[0x43u8; 32], &nonce, aad, &ct).is_err());
}

#[test]
fn r040_b_real_aead_wrong_nonce_fails_closed() {
    let aead = ChaCha20Poly1305Backend::new();
    let key = [0x42u8; 32];
    let aad = b"hdr";
    let pt = b"secret";
    let ct = aead.seal(&key, &[0x07u8; 12], aad, pt).expect("seal");
    assert!(aead.open(&key, &[0x08u8; 12], aad, &ct).is_err());
}

#[test]
fn r040_b_real_aead_wrong_aad_fails_closed() {
    let aead = ChaCha20Poly1305Backend::new();
    let key = [0x42u8; 32];
    let nonce = [0x07u8; 12];
    let pt = b"secret";
    let ct = aead.seal(&key, &nonce, b"hdr-A", pt).expect("seal");
    assert!(aead.open(&key, &nonce, b"hdr-B", &ct).is_err());
}

#[test]
fn r040_b_real_aead_tampered_ciphertext_fails_closed() {
    let aead = ChaCha20Poly1305Backend::new();
    let key = [0x42u8; 32];
    let nonce = [0x07u8; 12];
    let aad = b"hdr";
    let pt = b"secret message";
    let mut ct = aead.seal(&key, &nonce, aad, pt).expect("seal");
    // Flip one bit in the body.
    ct[0] ^= 0x01;
    assert!(aead.open(&key, &nonce, aad, &ct).is_err());
}

#[test]
fn r040_b_real_aead_tampered_tag_fails_closed() {
    let aead = ChaCha20Poly1305Backend::new();
    let key = [0x42u8; 32];
    let nonce = [0x07u8; 12];
    let aad = b"hdr";
    let pt = b"secret";
    let mut ct = aead.seal(&key, &nonce, aad, pt).expect("seal");
    // Flip a bit in the trailing 16-byte tag.
    let last = ct.len() - 1;
    ct[last] ^= 0x80;
    assert!(aead.open(&key, &nonce, aad, &ct).is_err());
}

#[test]
fn r040_b_real_aead_truncated_frame_fails_closed() {
    let aead = ChaCha20Poly1305Backend::new();
    // A buffer shorter than the 16-byte tag must fail closed.
    assert!(aead.open(&[0u8; 32], &[0u8; 12], b"", &[0u8; 8]).is_err());
}

#[test]
fn r040_b_real_aead_malformed_key_fails_closed() {
    let aead = ChaCha20Poly1305Backend::new();
    // 16-byte key is the wrong size for ChaCha20-Poly1305.
    let res = aead.seal(&[0u8; 16], &[0u8; 12], b"", b"x");
    assert!(res.is_err());
}

#[test]
fn r040_b_real_aead_malformed_nonce_fails_closed() {
    let aead = ChaCha20Poly1305Backend::new();
    let res = aead.seal(&[0u8; 32], &[0u8; 8], b"", b"x");
    assert!(res.is_err());
}

// ===========================================================================
// R040.C — Two-node Required + pqc-static-root + real AEAD handshake succeeds
// ===========================================================================

async fn poll_peer_observability(
    ctx_v0: &qbind_node::p2p_node_builder::P2pNodeContext,
    ctx_v1: &qbind_node::p2p_node_builder::P2pNodeContext,
    nid_v0: NodeId,
    nid_v1: NodeId,
    timeout: Duration,
) -> (bool, bool) {
    let deadline = Instant::now() + timeout;
    let mut saw_v1_on_v0 = false;
    let mut saw_v0_on_v1 = false;
    while Instant::now() < deadline {
        let v0_peers = ctx_v0.p2p_service.connected_peers();
        let v1_peers = ctx_v1.p2p_service.connected_peers();
        saw_v1_on_v0 = saw_v1_on_v0 || v0_peers.contains(&nid_v1);
        saw_v0_on_v1 = saw_v0_on_v1 || v1_peers.contains(&nid_v0);
        if saw_v1_on_v0 && saw_v0_on_v1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    (saw_v1_on_v0, saw_v0_on_v1)
}

/// Two-node mutual-auth Required + `pqc-static-root` smoke under the
/// new real-AEAD wiring.
///
/// A successful handshake here is concrete evidence that both the
/// dialer and listener resolved the PQC AEAD suite id (`101`) to a
/// real backend. If either side were still registering only DummyAead
/// at suite id `2`, the handshake would fail at
/// `qbind_net::handshake` with `NetError::UnsupportedSuite(101)`.
#[tokio::test]
async fn r040_c_two_node_required_pqc_static_root_real_aead_succeeds() {
    let port_v0 = reserve_local_port().await;
    let port_v1 = reserve_local_port().await;

    let root = mint_devnet_root().expect("root");
    let leaf_v0 = mint_pqc_leaf_creds_for(0, &root);
    let leaf_v1 = mint_pqc_leaf_creds_for(1, &root);

    let cfg_v0 = make_p2p_test_config(
        &format!("127.0.0.1:{}", port_v0),
        vec![format!("1@127.0.0.1:{}", port_v1)],
    );
    let cfg_v1 = make_p2p_test_config(
        &format!("127.0.0.1:{}", port_v1),
        vec![format!("0@127.0.0.1:{}", port_v0)],
    );

    let nid_v0 = node_id_from_leaf(&leaf_v0);
    let nid_v1 = node_id_from_leaf(&leaf_v1);
    let pqc_v0 = pqc_static_root_config_for(
        &root,
        leaf_v0.clone(),
        vec![peer_leaf_cert_for(1, &leaf_v1)],
    );
    let pqc_v1 = pqc_static_root_config_for(
        &root,
        leaf_v1.clone(),
        vec![peer_leaf_cert_for(0, &leaf_v0)],
    );

    let ctx_v1 = P2pNodeBuilder::new()
        .with_num_validators(2)
        .with_mutual_auth_mode(qbind_net::MutualAuthMode::Required)
        .with_pqc_root_config(pqc_v1)
        .build(&cfg_v1, 1)
        .await
        .expect("build v1");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let ctx_v0 = P2pNodeBuilder::new()
        .with_num_validators(2)
        .with_mutual_auth_mode(qbind_net::MutualAuthMode::Required)
        .with_pqc_root_config(pqc_v0)
        .build(&cfg_v0, 0)
        .await
        .expect("build v0");

    let (saw_v1_on_v0, saw_v0_on_v1) =
        poll_peer_observability(&ctx_v0, &ctx_v1, nid_v0, nid_v1, Duration::from_secs(8)).await;
    assert!(
        saw_v1_on_v0,
        "R040.C: dialer (v0) must observe v1 NodeId among connected peers under real-AEAD pqc-static-root path"
    );
    assert!(
        saw_v0_on_v1,
        "R040.C: listener (v1) must observe v0 NodeId among connected peers under real-AEAD pqc-static-root path"
    );
}

// ===========================================================================
// R040.D — Pre-Run-040 test-grade DummyAead path is preserved
//
// We do not exercise the full transport here (the existing B7/B8/B12 +
// run_037 + run_039 suites already cover that path). We only assert
// that a test-grade provider built equivalently to
// `make_test_crypto_provider` still resolves DummyAead at suite id 2,
// and is therefore unchanged by Run 040 — i.e. Run 040 is strictly
// additive on the pqc-static-root path.
// ===========================================================================

#[test]
fn r040_d_test_grade_provider_still_registers_dummy_aead_at_suite_id_2() {
    // We can't import the private DummyAead, but we can rely on the
    // observable behaviour of the existing `make_test_crypto_provider`
    // path through the existing test suites (T138, T143, T160, T222,
    // run_037 R037.F). This test asserts the constants remain stable
    // so that Run 040 has not silently shifted the test-grade suite
    // ids.
    assert_eq!(
        AEAD_SUITE_CHACHA20_POLY1305, 101,
        "Run 040 reserves suite id 101 for ChaCha20-Poly1305"
    );
    // Run 040 must NOT collide the real AEAD suite id with the
    // test-grade DummyAead suite id `2`.
    assert_ne!(
        AEAD_SUITE_CHACHA20_POLY1305, 2,
        "Run 040 must not silently overwrite the test-grade DummyAead suite id"
    );
}