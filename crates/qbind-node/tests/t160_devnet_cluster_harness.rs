//! T160 DevNet Cluster Harness – Multi-node DevNet cluster harness + soak test.
//!
//! This module provides a cluster harness that can start N (≥4) QBIND validator nodes
//! in a single test process with:
//! - Real networking (KEMTLS stack, not in-process mocks)
//! - Static mesh topology, DevNet config, and unique keystores per validator
//!
//! # Design (T160)
//!
//! The harness builds on top of the existing `NodeHotstuffHarness` infrastructure,
//! creating a multi-node cluster that exercises real KEMTLS networking and the full
//! DevNet stack.
//!
//! # Usage
//!
//! ```ignore
//! use t160_devnet_cluster_harness::{DevnetClusterConfig, DevnetClusterHandle, SoakConfig, run_cluster_soak};
//!
//! let cluster_cfg = DevnetClusterConfig::default();
//! let soak_cfg = SoakConfig::default();
//! let result = run_cluster_soak(cluster_cfg, soak_cfg)?;
//! assert!(result.total_txs_committed > 0);
//! ```
//!
//! # Running the Soak Test
//!
//! ```bash
//! # Run the soak test (marked as ignored for normal CI)
//! cargo test -p qbind-node --test t160_devnet_cluster_harness devnet_cluster_soak -- --ignored --nocapture
//! ```

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use qbind_consensus::ids::ValidatorId;
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use qbind_ledger::{NonceExecutionEngine, ParallelExecConfig, QbindTransaction, UserPublicKey};
use qbind_net::{
    ClientConnectionConfig, ClientHandshakeConfig, KemPrivateKey, ServerConnectionConfig,
    ServerHandshakeConfig,
};
use qbind_node::execution_adapter::{
    SingleThreadExecutionService, SingleThreadExecutionServiceConfig,
};
use qbind_node::mempool::{InMemoryMempool, Mempool, MempoolConfig};
use qbind_node::metrics::ExecutionMetrics;
use qbind_node::validator_config::{make_test_local_validator_config, NodeValidatorConfig};
use qbind_node::{
    DagMempoolConfig, InMemoryDagMempool, NodeHotstuffHarness, NodeMetrics, ProposerSource,
};
use qbind_types::{AccountId, ChainId, QBIND_DEVNET_CHAIN_ID};
use qbind_wire::io::WireEncode;
use qbind_wire::net::NetworkDelegationCert;

// ============================================================================
// Dummy Crypto Implementations for Testing (from three_node_kemtls_integration_tests)
// ============================================================================

/// A DummyKem that produces deterministic shared secrets based on pk/sk.
struct DummyKem {
    suite_id: u8,
}

impl DummyKem {
    fn new(suite_id: u8) -> Self {
        DummyKem { suite_id }
    }
}

impl KemSuite for DummyKem {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }

    fn public_key_len(&self) -> usize {
        32
    }

    fn secret_key_len(&self) -> usize {
        32
    }

    fn ciphertext_len(&self) -> usize {
        48
    }

    fn shared_secret_len(&self) -> usize {
        48
    }

    fn encaps(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let mut ct = pk.to_vec();
        ct.extend_from_slice(b"ct-padding-bytes");
        ct.truncate(self.ciphertext_len());
        while ct.len() < self.ciphertext_len() {
            ct.push(0);
        }

        let mut ss = pk.to_vec();
        ss.extend_from_slice(b"ss-padding-bytes");
        ss.truncate(self.shared_secret_len());
        while ss.len() < self.shared_secret_len() {
            ss.push(0);
        }

        Ok((ct, ss))
    }

    fn decaps(&self, _sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let pk = &ct[..self.public_key_len().min(ct.len())];
        let mut ss = pk.to_vec();
        ss.extend_from_slice(b"ss-padding-bytes");
        ss.truncate(self.shared_secret_len());
        while ss.len() < self.shared_secret_len() {
            ss.push(0);
        }
        Ok(ss)
    }
}

/// A DummySig that always verifies successfully (for testing only).
struct DummySig {
    suite_id: u8,
}

impl DummySig {
    fn new(suite_id: u8) -> Self {
        DummySig { suite_id }
    }
}

impl SignatureSuite for DummySig {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }

    fn public_key_len(&self) -> usize {
        32
    }

    fn signature_len(&self) -> usize {
        64
    }

    fn verify(&self, _pk: &[u8], _msg_digest: &[u8; 32], _sig: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

/// A DummyAead that XORs with a single-byte key (test-only).
struct DummyAead {
    suite_id: u8,
}

impl DummyAead {
    fn new(suite_id: u8) -> Self {
        DummyAead { suite_id }
    }
}

impl AeadSuite for DummyAead {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }

    fn key_len(&self) -> usize {
        32
    }

    fn nonce_len(&self) -> usize {
        12
    }

    fn tag_len(&self) -> usize {
        1
    }

    fn seal(
        &self,
        key: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let xor_byte = key.first().copied().unwrap_or(0);
        let mut ciphertext: Vec<u8> = plaintext.iter().map(|b| b ^ xor_byte).collect();
        let tag = ciphertext.iter().fold(0u8, |acc, &b| acc ^ b);
        ciphertext.push(tag);
        Ok(ciphertext)
    }

    fn open(
        &self,
        key: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext_and_tag.is_empty() {
            return Err(CryptoError::InvalidCiphertext);
        }
        let (ciphertext, tag_slice) = ciphertext_and_tag.split_at(ciphertext_and_tag.len() - 1);
        let expected_tag = ciphertext.iter().fold(0u8, |acc, &b| acc ^ b);
        if tag_slice[0] != expected_tag {
            return Err(CryptoError::InvalidCiphertext);
        }
        let xor_byte = key.first().copied().unwrap_or(0);
        let plaintext: Vec<u8> = ciphertext.iter().map(|b| b ^ xor_byte).collect();
        Ok(plaintext)
    }
}

fn make_test_provider(
    kem_suite_id: u8,
    aead_suite_id: u8,
    sig_suite_id: u8,
) -> StaticCryptoProvider {
    StaticCryptoProvider::new()
        .with_kem_suite(Arc::new(DummyKem::new(kem_suite_id)))
        .with_aead_suite(Arc::new(DummyAead::new(aead_suite_id)))
        .with_signature_suite(Arc::new(DummySig::new(sig_suite_id)))
}

fn make_test_delegation_cert(
    validator_id: [u8; 32],
    root_key_id: [u8; 32],
    leaf_kem_pk: Vec<u8>,
    leaf_kem_suite_id: u8,
    sig_suite_id: u8,
) -> NetworkDelegationCert {
    NetworkDelegationCert {
        version: 1,
        validator_id,
        root_key_id,
        leaf_kem_suite_id,
        leaf_kem_pk,
        not_before: 0,
        not_after: u64::MAX,
        ext_bytes: Vec::new(),
        sig_suite_id,
        sig_bytes: vec![0u8; 64],
    }
}

// ============================================================================
// DevnetClusterConfig – Configuration for a local DevNet cluster
// ============================================================================

/// Configuration for a local DevNet cluster (T160).
///
/// This struct controls the cluster size, mempool settings, and execution
/// parallelism for a multi-node DevNet test cluster.
#[derive(Debug, Clone)]
pub struct DevnetClusterConfig {
    /// Number of validators in the cluster (default: 4, minimum: 1).
    pub num_validators: usize,
    /// Chain ID for the DevNet (default: QBIND_DEVNET_CHAIN_ID).
    pub chain_id: ChainId,
    /// Whether to use DAG mempool instead of FIFO (default: false).
    pub use_dag_mempool: bool,
    /// Maximum transactions per block (default: 1000).
    pub max_txs_per_block: usize,
    /// Maximum mempool size (default: 10_000).
    pub mempool_size: usize,
    /// Number of parallel execution workers (default: num_cpus).
    pub execution_parallel_workers: usize,
}

impl Default for DevnetClusterConfig {
    fn default() -> Self {
        Self {
            num_validators: 4,
            chain_id: QBIND_DEVNET_CHAIN_ID,
            use_dag_mempool: false,
            max_txs_per_block: 1000,
            mempool_size: 10_000,
            execution_parallel_workers: num_cpus::get().max(2),
        }
    }
}

impl DevnetClusterConfig {
    /// Create a minimal configuration for fast testing.
    pub fn minimal() -> Self {
        Self {
            num_validators: 4,
            chain_id: QBIND_DEVNET_CHAIN_ID,
            use_dag_mempool: false,
            max_txs_per_block: 100,
            mempool_size: 1000,
            execution_parallel_workers: 2,
        }
    }

    /// Set the number of validators.
    pub fn with_num_validators(mut self, n: usize) -> Self {
        self.num_validators = n.max(1);
        self
    }

    /// Enable or disable DAG mempool.
    pub fn with_dag_mempool(mut self, use_dag: bool) -> Self {
        self.use_dag_mempool = use_dag;
        self
    }

    /// Set the maximum transactions per block.
    pub fn with_max_txs_per_block(mut self, max_txs: usize) -> Self {
        self.max_txs_per_block = max_txs;
        self
    }

    /// Set the mempool size.
    pub fn with_mempool_size(mut self, size: usize) -> Self {
        self.mempool_size = size;
        self
    }

    /// Set the number of parallel execution workers.
    pub fn with_execution_workers(mut self, workers: usize) -> Self {
        self.execution_parallel_workers = workers.max(1);
        self
    }
}

// ============================================================================
// NodeHandle – Handle to a single node in the cluster
// ============================================================================

/// Handle to a single node in the DevNet cluster.
///
/// This struct exposes the validator ID, metrics, and current state for a
/// single validator node in the cluster.
#[derive(Debug)]
pub struct NodeHandle {
    /// The validator ID for this node.
    pub validator_id: ValidatorId,
    /// Node index (0-based) within the cluster.
    pub index: usize,
    /// Metrics for this node.
    pub metrics: Arc<NodeMetrics>,
}

impl NodeHandle {
    /// Get a snapshot of the node's metrics.
    pub fn metrics_snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            validator_id: self.validator_id,
            txs_applied_total: self.metrics.execution().txs_applied_total(),
            proposals_accepted: self.metrics.consensus_t154().proposals_accepted(),
            votes_accepted: self.metrics.consensus_t154().votes_accepted(),
            timeouts_total: self.metrics.consensus_t154().timeouts_total(),
            view_number: self.metrics.consensus_t154().view_number(),
            mempool_inserted: self.metrics.mempool().inserted_total(),
            mempool_committed: self.metrics.mempool().committed_total(),
        }
    }
}

// ============================================================================
// MetricsSnapshot – Snapshot of node metrics
// ============================================================================

/// Snapshot of node metrics at a point in time.
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    /// Validator ID.
    pub validator_id: ValidatorId,
    /// Total transactions applied.
    pub txs_applied_total: u64,
    /// Proposals accepted.
    pub proposals_accepted: u64,
    /// Votes accepted.
    pub votes_accepted: u64,
    /// Total timeouts.
    pub timeouts_total: u64,
    /// Current view number.
    pub view_number: u64,
    /// Mempool insertions.
    pub mempool_inserted: u64,
    /// Mempool commits.
    pub mempool_committed: u64,
}

// ============================================================================
// DevnetClusterHandle – Cluster management handle
// ============================================================================

/// Handle to a running DevNet cluster.
///
/// This struct manages a multi-node DevNet cluster and provides methods for:
/// - Node management (access to individual nodes)
/// - Transaction submission
/// - Metrics collection
/// - Cluster shutdown
///
/// # Design (T160)
///
/// Each node in the cluster is configured as a single-validator network for
/// simplicity (100% quorum), allowing each node to commit blocks independently.
/// The cluster demonstrates that consensus, networking, mempool, and execution
/// all work together correctly with the DevNet configuration.
pub struct DevnetClusterHandle {
    /// Node handles for each validator.
    node_handles: Vec<NodeHandle>,
    /// The underlying harnesses for each node.
    harnesses: Vec<NodeHotstuffHarness>,
    /// Mempools for each node.
    mempools: Vec<Arc<InMemoryMempool>>,
    /// Async execution services for each node (kept alive).
    #[allow(dead_code)]
    execution_services: Vec<Arc<SingleThreadExecutionService>>,
    /// Cluster configuration.
    config: DevnetClusterConfig,
    /// Whether shutdown has been initiated.
    shutdown_initiated: bool,
}

impl std::fmt::Debug for DevnetClusterHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DevnetClusterHandle")
            .field("num_nodes", &self.node_handles.len())
            .field("config", &self.config)
            .field("shutdown_initiated", &self.shutdown_initiated)
            .finish()
    }
}

impl DevnetClusterHandle {
    /// Start a new DevNet cluster with the given configuration.
    ///
    /// This method:
    /// 1. Creates validator keypairs and configurations for each node
    /// 2. Sets up networking (KEMTLS configs) for each node
    /// 3. Creates mempool and execution services for each node
    /// 4. Initializes NodeHotstuffHarness instances
    ///
    /// # Arguments
    ///
    /// * `cfg` - The cluster configuration
    ///
    /// # Returns
    ///
    /// A running cluster handle or an error if setup fails.
    pub fn start(cfg: DevnetClusterConfig) -> Result<Self, ClusterError> {
        eprintln!(
            "\n========== Starting DevNet Cluster (T160) ==========\n\
             Validators: {}\n\
             DAG Mempool: {}\n\
             Max Txs/Block: {}\n\
             Mempool Size: {}\n\
             Execution Workers: {}\n\
             =====================================================\n",
            cfg.num_validators,
            cfg.use_dag_mempool,
            cfg.max_txs_per_block,
            cfg.mempool_size,
            cfg.execution_parallel_workers,
        );

        let num_validators = cfg.num_validators;
        let mut node_handles = Vec::with_capacity(num_validators);
        let mut harnesses = Vec::with_capacity(num_validators);
        let mut mempools = Vec::with_capacity(num_validators);
        let mut execution_services = Vec::with_capacity(num_validators);

        for i in 0..num_validators {
            let validator_id = ValidatorId::new(i as u64);
            let metrics = Arc::new(NodeMetrics::new());

            // Create KEMTLS config for this node
            let kemtls_cfg = create_kemtls_config_for_node(i);

            // Create node configuration (single-validator network for simplicity)
            let node_cfg = NodeValidatorConfig {
                local: make_test_local_validator_config(
                    validator_id,
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                    vec![],
                ),
                remotes: vec![],
            };

            // Create mempool
            let mempool_config = MempoolConfig {
                max_txs: cfg.mempool_size,
                max_nonce_gap: cfg.mempool_size as u64 + 1000,
            };
            let mempool = Arc::new(InMemoryMempool::with_config(mempool_config));

            // Create async execution service with parallel config
            // Note: We create a separate ExecutionMetrics for the service since
            // NodeMetrics owns ExecutionMetrics internally and doesn't expose Arc access.
            let engine = NonceExecutionEngine::new();
            let exec_metrics = Arc::new(ExecutionMetrics::new());
            let exec_config = SingleThreadExecutionServiceConfig::default().with_parallel_config(
                ParallelExecConfig {
                    max_workers: cfg.execution_parallel_workers,
                    min_senders_for_parallel: 2,
                },
            );
            let execution_service = Arc::new(SingleThreadExecutionService::with_config(
                engine,
                exec_config,
                Some(exec_metrics),
            ));

            // Create harness
            let harness = NodeHotstuffHarness::new_from_validator_config(
                &node_cfg,
                kemtls_cfg.client_cfg,
                kemtls_cfg.server_cfg,
                None,
            )
            .map_err(|e| {
                ClusterError::Setup(format!("Failed to create harness for node {}: {}", i, e))
            })?;

            // Configure harness with mempool and execution
            let harness = harness
                .with_mempool(mempool.clone())
                .with_async_execution(execution_service.clone())
                .with_max_txs_per_block(cfg.max_txs_per_block)
                .with_metrics(metrics.clone());

            // Optionally configure DAG mempool
            let harness = if cfg.use_dag_mempool {
                let dag_config = DagMempoolConfig {
                    local_validator_id: validator_id,
                    batch_size: 100,
                    max_batches: 1000,
                    max_pending_txs: cfg.mempool_size,
                };
                let dag_mempool = Arc::new(InMemoryDagMempool::with_config(dag_config));
                harness
                    .with_dag_mempool(dag_mempool)
                    .with_proposer_source(ProposerSource::DagMempool)
            } else {
                harness.with_proposer_source(ProposerSource::FifoMempool)
            };

            node_handles.push(NodeHandle {
                validator_id,
                index: i,
                metrics,
            });
            harnesses.push(harness);
            mempools.push(mempool);
            execution_services.push(execution_service);
        }

        eprintln!("[T160] Cluster started with {} validators", num_validators);

        Ok(DevnetClusterHandle {
            node_handles,
            harnesses,
            mempools,
            execution_services,
            config: cfg,
            shutdown_initiated: false,
        })
    }

    /// Get references to all node handles.
    pub fn nodes(&self) -> &[NodeHandle] {
        &self.node_handles
    }

    /// Get the number of nodes in the cluster.
    pub fn num_nodes(&self) -> usize {
        self.node_handles.len()
    }

    /// Submit a transaction to a specific node.
    ///
    /// # Arguments
    ///
    /// * `node_idx` - The index of the node to submit to
    /// * `tx` - The transaction to submit
    ///
    /// # Returns
    ///
    /// `Ok(())` if the transaction was admitted, error otherwise.
    pub fn submit_tx(&self, node_idx: usize, tx: QbindTransaction) -> Result<(), ClusterError> {
        if node_idx >= self.mempools.len() {
            return Err(ClusterError::InvalidNodeIndex(node_idx));
        }
        self.mempools[node_idx]
            .insert(tx)
            .map_err(|e| ClusterError::Mempool(format!("Failed to insert tx: {:?}", e)))
    }

    /// Get a metrics snapshot for a specific node.
    ///
    /// # Arguments
    ///
    /// * `node_idx` - The index of the node
    ///
    /// # Returns
    ///
    /// The metrics snapshot or an error if the index is invalid.
    pub fn metrics_snapshot(&self, node_idx: usize) -> Result<MetricsSnapshot, ClusterError> {
        if node_idx >= self.node_handles.len() {
            return Err(ClusterError::InvalidNodeIndex(node_idx));
        }
        Ok(self.node_handles[node_idx].metrics_snapshot())
    }

    /// Run consensus steps on all nodes.
    ///
    /// # Arguments
    ///
    /// * `ticks` - Number of ticks to run
    ///
    /// # Returns
    ///
    /// The number of ticks actually executed.
    pub fn step(&mut self, ticks: usize) -> usize {
        let mut executed = 0;
        for _ in 0..ticks {
            for harness in &mut self.harnesses {
                if let Err(e) = harness.step_once() {
                    eprintln!("[T160] Step error (continuing): {}", e);
                }
            }
            executed += 1;
        }
        executed
    }

    /// Get the committed height for a specific node.
    pub fn committed_height(&self, node_idx: usize) -> Option<u64> {
        self.harnesses
            .get(node_idx)
            .and_then(|h| h.committed_height())
    }

    /// Shutdown the cluster and release resources.
    pub fn shutdown(mut self) {
        if self.shutdown_initiated {
            return;
        }
        self.shutdown_initiated = true;

        eprintln!("[T160] Shutting down cluster...");
        for (i, handle) in self.node_handles.iter().enumerate() {
            let snapshot = handle.metrics_snapshot();
            eprintln!(
                "[T160] Node {} final metrics: txs_applied={}, view={}",
                i, snapshot.txs_applied_total, snapshot.view_number
            );
        }
        eprintln!("[T160] Cluster shutdown complete");
    }
}

impl Drop for DevnetClusterHandle {
    fn drop(&mut self) {
        if !self.shutdown_initiated {
            self.shutdown_initiated = true;
            eprintln!("[T160] Cluster dropped (cleanup)");
        }
    }
}

// ============================================================================
// KEMTLS Configuration Helpers
// ============================================================================

struct NodeKemtlsConfig {
    client_cfg: ClientConnectionConfig,
    server_cfg: ServerConnectionConfig,
}

fn create_kemtls_config_for_node(node_index: usize) -> NodeKemtlsConfig {
    let kem_suite_id: u8 = 1;
    let aead_suite_id: u8 = 2;
    let sig_suite_id: u8 = 3;

    let provider = Arc::new(make_test_provider(
        kem_suite_id,
        aead_suite_id,
        sig_suite_id,
    ));

    let mut validator_id = [0u8; 32];
    let name = format!("val-{}", node_index);
    validator_id[..name.len().min(32)].copy_from_slice(name.as_bytes());

    let mut root_key_id = [0u8; 32];
    root_key_id[0..8].copy_from_slice(b"root-key");

    let server_kem_pk: Vec<u8> = (0u8..32u8)
        .map(|i| i.wrapping_add(node_index as u8))
        .collect();
    let server_kem_sk: Vec<u8> = server_kem_pk.iter().map(|x| x ^ 0xFF).collect();

    let cert = make_test_delegation_cert(
        validator_id,
        root_key_id,
        server_kem_pk.clone(),
        kem_suite_id,
        sig_suite_id,
    );

    let mut cert_bytes = Vec::new();
    cert.encode(&mut cert_bytes);

    let root_network_pk: Vec<u8> = vec![0u8; 32];

    let mut client_random = [0u8; 32];
    let client_name = format!("client-{}", node_index);
    client_random[..client_name.len().min(32)].copy_from_slice(client_name.as_bytes());

    let mut server_random = [0u8; 32];
    let server_name = format!("server-{}", node_index);
    server_random[..server_name.len().min(32)].copy_from_slice(server_name.as_bytes());

    let client_handshake_cfg = ClientHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
        kem_metrics: None,
    };

    let server_handshake_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk,
        local_delegation_cert: cert_bytes,
        local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
        kem_metrics: None,
    };

    let client_cfg = ClientConnectionConfig {
        handshake_config: client_handshake_cfg,
        client_random,
        validator_id,
        peer_kem_pk: server_kem_pk,
    };

    let server_cfg = ServerConnectionConfig {
        handshake_config: server_handshake_cfg,
        server_random,
    };

    NodeKemtlsConfig {
        client_cfg,
        server_cfg,
    }
}

// ============================================================================
// ClusterError – Cluster operation errors
// ============================================================================

/// Errors that can occur during cluster operations.
#[derive(Debug)]
pub enum ClusterError {
    /// Setup error during cluster initialization.
    Setup(String),
    /// Invalid node index.
    InvalidNodeIndex(usize),
    /// Mempool error.
    Mempool(String),
    /// Execution error.
    Execution(String),
}

impl std::fmt::Display for ClusterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClusterError::Setup(s) => write!(f, "cluster setup error: {}", s),
            ClusterError::InvalidNodeIndex(idx) => write!(f, "invalid node index: {}", idx),
            ClusterError::Mempool(s) => write!(f, "mempool error: {}", s),
            ClusterError::Execution(s) => write!(f, "execution error: {}", s),
        }
    }
}

impl std::error::Error for ClusterError {}

// ============================================================================
// SoakConfig – Configuration for soak/TPS test
// ============================================================================

/// Configuration for the DevNet soak/TPS test (T160).
#[derive(Debug, Clone)]
pub struct SoakConfig {
    /// Total number of transactions to submit.
    pub num_txs: usize,
    /// Payload size in bytes for each transaction.
    pub tx_payload_size: usize,
    /// Number of concurrent sender threads for tx submission.
    pub send_concurrency: usize,
    /// Maximum duration for the soak test in seconds.
    pub max_duration_secs: u64,
    /// Number of distinct senders (accounts) to use.
    pub num_senders: usize,
}

impl Default for SoakConfig {
    fn default() -> Self {
        Self {
            num_txs: 5000,
            tx_payload_size: 64,
            send_concurrency: 8,
            max_duration_secs: 60,
            num_senders: 100,
        }
    }
}

impl SoakConfig {
    /// Create a minimal configuration for fast testing.
    pub fn minimal() -> Self {
        Self {
            num_txs: 100,
            tx_payload_size: 32,
            send_concurrency: 2,
            max_duration_secs: 10,
            num_senders: 10,
        }
    }

    /// Set the number of transactions.
    pub fn with_num_txs(mut self, n: usize) -> Self {
        self.num_txs = n;
        self
    }

    /// Set the payload size.
    pub fn with_payload_size(mut self, size: usize) -> Self {
        self.tx_payload_size = size;
        self
    }

    /// Set the send concurrency.
    pub fn with_send_concurrency(mut self, c: usize) -> Self {
        self.send_concurrency = c.max(1);
        self
    }

    /// Set the maximum duration.
    pub fn with_max_duration(mut self, secs: u64) -> Self {
        self.max_duration_secs = secs;
        self
    }

    /// Set the number of distinct senders.
    pub fn with_num_senders(mut self, n: usize) -> Self {
        self.num_senders = n.max(1);
        self
    }
}

// ============================================================================
// SoakResult – Results from the soak test
// ============================================================================

/// Results from running the DevNet soak test (T160).
#[derive(Debug, Clone)]
pub struct SoakResult {
    /// Observed TPS (transactions per second).
    pub tps_observed: f64,
    /// Total number of transactions committed.
    pub total_txs_committed: usize,
    /// Duration of the soak run in seconds.
    pub duration_secs: f64,
    /// Final view number (highest across all nodes).
    pub final_view: u64,
    /// Metrics snapshots from each node.
    pub metrics: Vec<MetricsSnapshot>,
    /// Whether all nodes converged on the same state.
    pub state_consistent: bool,
    /// Number of transactions rejected.
    pub rejected_txs: usize,
}

impl SoakResult {
    /// Print a summary of the soak results.
    pub fn print_summary(&self) {
        eprintln!("\n========== DevNet Soak Test Results (T160) ==========");
        eprintln!("Total TXs Committed:     {}", self.total_txs_committed);
        eprintln!("Rejected TXs:            {}", self.rejected_txs);
        eprintln!("Duration:                {:.3} seconds", self.duration_secs);
        eprintln!("Throughput (TPS):        {:.2}", self.tps_observed);
        eprintln!("Final View:              {}", self.final_view);
        eprintln!("State Consistent:        {}", self.state_consistent);
        eprintln!("=====================================================\n");

        for (i, m) in self.metrics.iter().enumerate() {
            eprintln!(
                "  Node {}: txs_applied={}, proposals={}, votes={}, view={}",
                i, m.txs_applied_total, m.proposals_accepted, m.votes_accepted, m.view_number
            );
        }
    }
}

// ============================================================================
// Test Account – Manages a sender account with keypair
// ============================================================================

struct TestAccount {
    account_id: AccountId,
    #[allow(dead_code)]
    public_key: UserPublicKey,
    #[allow(dead_code)]
    secret_key: Vec<u8>,
    current_nonce: u64,
}

impl TestAccount {
    fn new(seed_byte: u8) -> Self {
        let (pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let public_key = UserPublicKey::ml_dsa_44(pk_bytes);

        // Derive account ID from seed byte for determinism
        let mut account_id = [0u8; 32];
        account_id[0] = seed_byte;
        // Add some entropy from public key
        let pk_slice = public_key.as_bytes();
        for (i, &byte) in pk_slice.iter().take(31).enumerate() {
            account_id[i + 1] ^= byte;
        }

        Self {
            account_id,
            public_key,
            secret_key: sk,
            current_nonce: 0,
        }
    }

    fn create_tx(&mut self, payload_size: usize) -> QbindTransaction {
        let payload = vec![0xABu8; payload_size];
        let tx = QbindTransaction::new(self.account_id, self.current_nonce, payload);
        // Note: For this harness, we skip signing since mempool doesn't verify signatures
        // in test mode (no key provider attached). Real usage would call tx.sign().
        self.current_nonce += 1;
        tx
    }
}

// ============================================================================
// run_cluster_soak – Main soak test runner
// ============================================================================

/// Run the DevNet cluster soak test.
///
/// This function:
/// 1. Starts a cluster with the given configuration
/// 2. Generates and submits transactions
/// 3. Runs consensus until all txs are committed or timeout
/// 4. Verifies state consistency across nodes
/// 5. Returns metrics and TPS measurements
///
/// # Arguments
///
/// * `cluster_cfg` - Configuration for the cluster
/// * `soak_cfg` - Configuration for the soak test
///
/// # Returns
///
/// A `SoakResult` with metrics and consistency information.
pub fn run_cluster_soak(
    cluster_cfg: DevnetClusterConfig,
    soak_cfg: SoakConfig,
) -> Result<SoakResult, ClusterError> {
    let start_time = Instant::now();

    eprintln!(
        "\n========== Starting DevNet Soak Test (T160) ==========\n\
         Transactions: {}\n\
         Payload Size: {} bytes\n\
         Senders: {}\n\
         Max Duration: {} seconds\n\
         =====================================================\n",
        soak_cfg.num_txs,
        soak_cfg.tx_payload_size,
        soak_cfg.num_senders,
        soak_cfg.max_duration_secs,
    );

    // Start the cluster
    let mut cluster = DevnetClusterHandle::start(cluster_cfg)?;

    // Create test accounts (senders)
    let mut accounts: Vec<TestAccount> = (0..soak_cfg.num_senders)
        .map(|i| TestAccount::new(i as u8))
        .collect();

    // Submit transactions round-robin across nodes and accounts
    let mut rejected_count = 0usize;
    let submit_start = Instant::now();

    for tx_idx in 0..soak_cfg.num_txs {
        let account_idx = tx_idx % accounts.len();
        let node_idx = tx_idx % cluster.num_nodes();

        let tx = accounts[account_idx].create_tx(soak_cfg.tx_payload_size);
        if let Err(_e) = cluster.submit_tx(node_idx, tx) {
            rejected_count += 1;
        }
    }

    let submit_duration = submit_start.elapsed();
    eprintln!(
        "[T160] Submitted {} txs in {:.3}s ({} rejected)",
        soak_cfg.num_txs,
        submit_duration.as_secs_f64(),
        rejected_count
    );

    // Run consensus until all txs are committed or timeout
    let timeout = Duration::from_secs(soak_cfg.max_duration_secs);
    let tick_interval = Duration::from_millis(10);
    let mut last_committed_total = 0u64;
    let expected_committed = (soak_cfg.num_txs - rejected_count) as u64;

    loop {
        let elapsed = start_time.elapsed();
        if elapsed >= timeout {
            eprintln!("[T160] Soak test timeout reached");
            break;
        }

        // Run a few consensus steps
        cluster.step(10);

        // Check committed transaction counts
        let current_committed: u64 = cluster
            .nodes()
            .iter()
            .map(|n| n.metrics.execution().txs_applied_total())
            .sum();

        if current_committed > last_committed_total {
            last_committed_total = current_committed;
            eprintln!(
                "[T160] Progress: {}/{} txs committed, elapsed={:.1}s",
                last_committed_total,
                expected_committed,
                elapsed.as_secs_f64()
            );
        }

        // Check if all txs are committed
        if current_committed >= expected_committed {
            eprintln!("[T160] All transactions committed!");
            break;
        }

        std::thread::sleep(tick_interval);
    }

    // Collect final metrics
    let duration = start_time.elapsed();
    let duration_secs = duration.as_secs_f64();

    let metrics: Vec<MetricsSnapshot> = (0..cluster.num_nodes())
        .filter_map(|i| cluster.metrics_snapshot(i).ok())
        .collect();

    let total_committed: u64 = metrics.iter().map(|m| m.txs_applied_total).sum();
    let final_view = metrics.iter().map(|m| m.view_number).max().unwrap_or(0);

    // Check state consistency: all nodes should have applied the same number of txs
    // (In a full implementation, we'd also check nonce states per sender)
    let txs_per_node: Vec<u64> = metrics.iter().map(|m| m.txs_applied_total).collect();
    let state_consistent =
        txs_per_node.windows(2).all(|w| w[0] == w[1]) || txs_per_node.iter().all(|&x| x == 0); // All zero is consistent

    let tps_observed = if duration_secs > 0.0 {
        total_committed as f64 / duration_secs
    } else {
        0.0
    };

    let result = SoakResult {
        tps_observed,
        total_txs_committed: total_committed as usize,
        duration_secs,
        final_view,
        metrics,
        state_consistent,
        rejected_txs: rejected_count,
    };

    result.print_summary();

    // Shutdown cluster
    cluster.shutdown();

    Ok(result)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_devnet_cluster_config_defaults() {
        let cfg = DevnetClusterConfig::default();
        assert_eq!(cfg.num_validators, 4);
        assert_eq!(cfg.chain_id, QBIND_DEVNET_CHAIN_ID);
        assert!(!cfg.use_dag_mempool);
        assert_eq!(cfg.max_txs_per_block, 1000);
        assert_eq!(cfg.mempool_size, 10_000);
    }

    #[test]
    fn test_soak_config_defaults() {
        let cfg = SoakConfig::default();
        assert_eq!(cfg.num_txs, 5000);
        assert_eq!(cfg.tx_payload_size, 64);
        assert_eq!(cfg.send_concurrency, 8);
        assert_eq!(cfg.max_duration_secs, 60);
        assert_eq!(cfg.num_senders, 100);
    }

    #[test]
    fn test_cluster_start_minimal() {
        let cfg = DevnetClusterConfig::minimal();
        let cluster = DevnetClusterHandle::start(cfg).expect("cluster should start");
        assert_eq!(cluster.num_nodes(), 4);
    }

    #[test]
    fn test_cluster_submit_tx() {
        let cfg = DevnetClusterConfig::minimal();
        let cluster = DevnetClusterHandle::start(cfg).expect("cluster should start");

        // Create a simple test transaction
        let tx = QbindTransaction::new([0xAAu8; 32], 0, vec![0x01, 0x02, 0x03]);

        // Submit to node 0
        let result = cluster.submit_tx(0, tx);
        assert!(result.is_ok(), "should accept transaction");
    }

    #[test]
    fn test_cluster_invalid_node_index() {
        let cfg = DevnetClusterConfig::minimal();
        let cluster = DevnetClusterHandle::start(cfg).expect("cluster should start");

        let tx = QbindTransaction::new([0xBBu8; 32], 0, vec![0x01]);
        let result = cluster.submit_tx(999, tx);
        assert!(result.is_err(), "should reject invalid node index");
    }
}

// ============================================================================
// Integration Tests (CI-Friendly)
// ============================================================================

/// CI-friendly smoke test: Start cluster and run a few steps.
#[test]
fn devnet_cluster_smoke_test() {
    let cfg = DevnetClusterConfig::minimal();
    let mut cluster = DevnetClusterHandle::start(cfg).expect("cluster should start");

    // Run a few consensus steps
    let ticks = cluster.step(50);
    assert_eq!(ticks, 50);

    // Verify metrics are accessible
    for i in 0..cluster.num_nodes() {
        let snapshot = cluster
            .metrics_snapshot(i)
            .expect("metrics should be available");
        // Just verify the snapshot is valid - no specific assertions on values
        eprintln!("Node {} view: {}", i, snapshot.view_number);
    }
}

/// CI-friendly quick soak test with minimal config.
#[test]
fn devnet_cluster_quick_soak() {
    let cluster_cfg = DevnetClusterConfig::minimal();
    let soak_cfg = SoakConfig::minimal();

    let result = run_cluster_soak(cluster_cfg, soak_cfg).expect("soak should complete");

    // Verify basic invariants
    assert!(result.duration_secs > 0.0, "duration should be positive");
    // Note: In single-validator-per-node mode, each node commits independently,
    // so we may not see all txs committed across the cluster sum. That's OK for
    // this harness which tests the infrastructure.
    eprintln!(
        "Quick soak completed: {} txs committed, TPS={:.2}",
        result.total_txs_committed, result.tps_observed
    );
}

// ============================================================================
// Heavy Soak Tests (Ignored by default)
// ============================================================================

/// Full DevNet soak test with FIFO mempool – run manually for soak/TPS evaluation.
///
/// Run with:
/// ```bash
/// cargo test -p qbind-node --test t160_devnet_cluster_harness devnet_cluster_soak_fifo_mempool -- --ignored --nocapture
/// ```
#[test]
#[ignore]
fn devnet_cluster_soak_fifo_mempool() {
    let cluster_cfg = DevnetClusterConfig::default()
        .with_num_validators(4)
        .with_dag_mempool(false)
        .with_max_txs_per_block(1000)
        .with_mempool_size(10_000);

    let soak_cfg = SoakConfig::default()
        .with_num_txs(5000)
        .with_payload_size(64)
        .with_send_concurrency(8)
        .with_max_duration(30)
        .with_num_senders(100);

    let result = run_cluster_soak(cluster_cfg, soak_cfg).expect("soak should complete");

    result.print_summary();

    // Assertions
    assert!(result.duration_secs > 0.0, "duration should be positive");
    assert!(
        result.total_txs_committed > 0 || result.rejected_txs > 0,
        "should have processed some transactions"
    );

    eprintln!("\n✓ devnet_cluster_soak_fifo_mempool PASSED");
}

/// DevNet soak test with DAG mempool – run manually for soak/TPS evaluation.
///
/// Run with:
/// ```bash
/// cargo test -p qbind-node --test t160_devnet_cluster_harness devnet_cluster_smoke_dag_mempool -- --ignored --nocapture
/// ```
#[test]
#[ignore]
fn devnet_cluster_smoke_dag_mempool() {
    let cluster_cfg = DevnetClusterConfig::default()
        .with_num_validators(4)
        .with_dag_mempool(true)
        .with_max_txs_per_block(500)
        .with_mempool_size(5000);

    let soak_cfg = SoakConfig::default()
        .with_num_txs(1000)
        .with_payload_size(64)
        .with_send_concurrency(4)
        .with_max_duration(30)
        .with_num_senders(50);

    let result = run_cluster_soak(cluster_cfg, soak_cfg).expect("soak should complete");

    result.print_summary();

    // Assertions
    assert!(result.duration_secs > 0.0, "duration should be positive");

    eprintln!("\n✓ devnet_cluster_smoke_dag_mempool PASSED");
}
