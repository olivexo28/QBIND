//! T154 DevNet TPS Harness Integration Tests
//!
//! This module provides a TPS (transactions per second) benchmark harness for
//! QBIND DevNet. It measures throughput and latency of transaction processing
//! through the full execution pipeline.
//!
//! # Design
//!
//! The harness:
//! - Creates QbindTransactions with valid signatures and nonces
//! - Submits them through the mempool
//! - Measures throughput and latency
//! - Returns structured BenchResult
//!
//! # Running
//!
//! ```bash
//! # Run the TPS benchmark (marked as ignored for normal CI)
//! cargo test -p qbind-node --test t154_devnet_tps_harness -- --ignored --nocapture
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_ledger::{NonceExecutionEngine, QbindTransaction, UserPublicKey};
use qbind_node::execution_adapter::{ExecutionAdapter, InMemoryExecutionAdapter, QbindBlock};
use qbind_node::mempool::{InMemoryKeyProvider, InMemoryMempool, Mempool, MempoolConfig};
use qbind_node::NodeMetrics;
use qbind_types::AccountId;
use qbind_wire::consensus::{BlockHeader, BlockProposal};

// ============================================================================
// BenchResult - Benchmark results structure
// ============================================================================

/// Result of a DevNet TPS benchmark run.
#[derive(Debug, Clone)]
pub struct BenchResult {
    /// Total number of transactions submitted.
    pub total_txs: usize,
    /// Duration of the benchmark run in seconds.
    pub duration_secs: f64,
    /// Throughput: committed transactions per second.
    pub tps: f64,
    /// Average latency from submission to commit in milliseconds.
    pub avg_latency_ms: f64,
    /// 95th percentile latency in milliseconds (if available).
    pub p95_latency_ms: Option<f64>,
    /// Number of transactions successfully committed.
    pub committed_txs: usize,
    /// Number of transactions rejected.
    pub rejected_txs: usize,
}

impl BenchResult {
    /// Print a summary of the benchmark results.
    pub fn print_summary(&self) {
        eprintln!("\n========== DevNet TPS Benchmark Results (T154) ==========");
        eprintln!("Total transactions:      {}", self.total_txs);
        eprintln!("Committed transactions:  {}", self.committed_txs);
        eprintln!("Rejected transactions:   {}", self.rejected_txs);
        eprintln!("Duration:                {:.3} seconds", self.duration_secs);
        eprintln!("Throughput (TPS):        {:.2}", self.tps);
        eprintln!("Average latency:         {:.3} ms", self.avg_latency_ms);
        if let Some(p95) = self.p95_latency_ms {
            eprintln!("P95 latency:             {:.3} ms", p95);
        }
        eprintln!("=========================================================\n");
    }
}

// ============================================================================
// BenchConfig - Benchmark configuration
// ============================================================================

/// Configuration for DevNet TPS benchmark.
#[derive(Debug, Clone)]
pub struct BenchConfig {
    /// Number of validators in the DevNet (for info only in this single-node test).
    pub num_validators: usize,
    /// Total number of transactions to submit.
    pub num_txs: usize,
    /// Payload size in bytes for each transaction.
    pub tx_payload_size: usize,
    /// Maximum transactions per block.
    pub max_txs_per_block: usize,
    /// Maximum mempool size.
    pub mempool_size: usize,
    /// Whether to print verbose output.
    pub verbose: bool,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            num_validators: 4,
            num_txs: 1000,
            tx_payload_size: 128,
            max_txs_per_block: 1000,
            mempool_size: 10000,
            verbose: false,
        }
    }
}

impl BenchConfig {
    /// Create a minimal config for fast unit testing.
    pub fn minimal() -> Self {
        Self {
            num_validators: 4,
            num_txs: 100,
            tx_payload_size: 32,
            max_txs_per_block: 50,
            mempool_size: 1000,
            verbose: false,
        }
    }

    /// Create a canonical DevNet v0 benchmark scenario.
    pub fn canonical_devnet_v0() -> Self {
        Self {
            num_validators: 4,
            num_txs: 10000,
            tx_payload_size: 128,
            max_txs_per_block: 1000,
            mempool_size: 10000,
            verbose: true,
        }
    }
}

// ============================================================================
// Test Account - Manages a sender account with keypair
// ============================================================================

struct TestAccount {
    account_id: AccountId,
    public_key: UserPublicKey,
    secret_key: Vec<u8>,
    current_nonce: u64,
}

impl TestAccount {
    fn new() -> Self {
        let (pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let public_key = UserPublicKey::ml_dsa_44(pk_bytes);

        // Derive account ID from public key (using first 32 bytes)
        let mut account_id = [0u8; 32];
        let pk_slice = public_key.as_bytes();
        account_id.copy_from_slice(&pk_slice[..32.min(pk_slice.len())]);

        Self {
            account_id,
            public_key,
            secret_key: sk,
            current_nonce: 0,
        }
    }

    fn create_signed_tx(&mut self, payload_size: usize) -> QbindTransaction {
        let payload = vec![0xABu8; payload_size];
        let mut tx = QbindTransaction::new(self.account_id, self.current_nonce, payload);
        tx.sign(&self.secret_key).expect("signing should succeed");
        self.current_nonce += 1;
        tx
    }
}

// ============================================================================
// SimpleTpsBench - Simplified TPS benchmark
// ============================================================================

/// Run a simplified TPS benchmark that measures mempool + execution throughput.
///
/// This benchmark:
/// 1. Creates signed transactions
/// 2. Inserts them into the mempool
/// 3. Pulls block candidates
/// 4. Executes them via the ExecutionAdapter
/// 5. Measures total throughput and latency
pub fn run_simple_tps_bench(config: BenchConfig) -> BenchResult {
    let start_time = Instant::now();
    let metrics = Arc::new(NodeMetrics::new());

    if config.verbose {
        eprintln!(
            "[T154 TPS Bench] Starting with {} transactions",
            config.num_txs
        );
    }

    // Create test account
    let mut account = TestAccount::new();

    // Create key provider with the test account
    let mut key_provider = InMemoryKeyProvider::new();
    key_provider.register(account.account_id, account.public_key.clone());

    // Create mempool with signature verification
    let mempool_config = MempoolConfig {
        max_txs: config.mempool_size,
        max_nonce_gap: config.num_txs as u64 + 1000,
    };
    let mempool = InMemoryMempool::with_key_provider(mempool_config, Arc::new(key_provider));

    // Create execution adapter
    let engine = NonceExecutionEngine::new();
    let mut execution_adapter = InMemoryExecutionAdapter::new(engine);

    // Track per-tx latencies
    let mut latencies_ms: Vec<f64> = Vec::with_capacity(config.num_txs);
    let mut rejected_count = 0usize;
    let mut committed_count = 0usize;

    // Generate and submit transactions
    let submit_start = Instant::now();
    for i in 0..config.num_txs {
        let tx = account.create_signed_tx(config.tx_payload_size);
        let tx_submit_time = Instant::now();

        match mempool.insert(tx) {
            Ok(()) => {
                metrics.mempool().inc_inserted();
            }
            Err(e) => {
                if config.verbose && rejected_count < 5 {
                    eprintln!("[T154 TPS Bench] Transaction {} rejected: {:?}", i, e);
                }
                rejected_count += 1;
                continue;
            }
        }

        // For this simplified benchmark, record submission latency
        let latency = tx_submit_time.elapsed().as_secs_f64() * 1000.0;
        latencies_ms.push(latency);
    }
    metrics.mempool().set_size(mempool.size() as u64);

    if config.verbose {
        eprintln!(
            "[T154 TPS Bench] Submitted {} txs to mempool in {:.3}s",
            config.num_txs - rejected_count,
            submit_start.elapsed().as_secs_f64()
        );
    }

    // Process transactions in blocks
    let mut block_height = 1u64;
    while mempool.size() > 0 {
        let block_start = Instant::now();

        // Get block candidates
        let candidates = mempool.get_block_candidates(config.max_txs_per_block);
        if candidates.is_empty() {
            break;
        }

        // Create a QbindBlock
        let proposal = Arc::new(BlockProposal {
            header: BlockHeader {
                version: 1,
                chain_id: 1337,
                epoch: 0,
                height: block_height,
                round: 0,
                parent_block_id: [0u8; 32],
                payload_hash: [block_height as u8; 32],
                proposer_index: 0,
                suite_id: 0,
                tx_count: candidates.len() as u32,
                timestamp: 1704067200 + block_height,
                payload_kind: 0,
                next_epoch: 0,
            },
            qc: None,
            txs: Vec::new(),
            signature: Vec::new(),
        });

        let block = QbindBlock::new(proposal, candidates.clone());

        // Execute the block
        match execution_adapter.apply_block(&block) {
            Ok(()) => {
                committed_count += candidates.len();
                metrics.execution().add_txs_applied(candidates.len() as u64);
                metrics
                    .execution()
                    .record_block_apply(block_start.elapsed());

                // Remove committed txs from mempool
                mempool.remove_committed(&candidates);
                metrics.mempool().add_committed(candidates.len() as u64);
            }
            Err(e) => {
                if config.verbose {
                    eprintln!(
                        "[T154 TPS Bench] Block {} execution failed: {}",
                        block_height, e
                    );
                }
                // Remove the failing tx and continue
                if !candidates.is_empty() {
                    mempool.remove_committed(&candidates[..1]);
                }
            }
        }

        metrics.mempool().set_size(mempool.size() as u64);
        block_height += 1;
    }

    let duration = start_time.elapsed();
    let duration_secs = duration.as_secs_f64();

    // Calculate metrics
    let tps = if duration_secs > 0.0 {
        committed_count as f64 / duration_secs
    } else {
        0.0
    };

    let avg_latency_ms = if !latencies_ms.is_empty() {
        latencies_ms.iter().sum::<f64>() / latencies_ms.len() as f64
    } else {
        0.0
    };

    // Calculate p95 latency
    let p95_latency_ms = if latencies_ms.len() >= 20 {
        let mut sorted = latencies_ms.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p95_idx = (sorted.len() as f64 * 0.95) as usize;
        Some(sorted[p95_idx.min(sorted.len() - 1)])
    } else {
        None
    };

    let result = BenchResult {
        total_txs: config.num_txs,
        duration_secs,
        tps,
        avg_latency_ms,
        p95_latency_ms,
        committed_txs: committed_count,
        rejected_txs: rejected_count,
    };

    if config.verbose {
        result.print_summary();
        eprintln!("\n--- Metrics Snapshot ---");
        eprintln!("{}", metrics.format_metrics());
    }

    result
}

// ============================================================================
// Tests
// ============================================================================

#[test]
fn test_bench_config_defaults() {
    let config = BenchConfig::default();
    assert_eq!(config.num_validators, 4);
    assert_eq!(config.num_txs, 1000);
    assert_eq!(config.tx_payload_size, 128);
    assert_eq!(config.max_txs_per_block, 1000);
    assert_eq!(config.mempool_size, 10000);
}

#[test]
fn test_bench_config_canonical_devnet_v0() {
    let config = BenchConfig::canonical_devnet_v0();
    assert_eq!(config.num_validators, 4);
    assert_eq!(config.num_txs, 10000);
    assert_eq!(config.tx_payload_size, 128);
    assert_eq!(config.max_txs_per_block, 1000);
    assert_eq!(config.mempool_size, 10000);
}

#[test]
fn test_bench_result_structure() {
    let result = BenchResult {
        total_txs: 100,
        duration_secs: 1.0,
        tps: 100.0,
        avg_latency_ms: 5.0,
        p95_latency_ms: Some(10.0),
        committed_txs: 100,
        rejected_txs: 0,
    };

    assert_eq!(result.total_txs, 100);
    assert!(result.tps > 0.0);
    assert!(result.duration_secs > 0.0);
}

#[test]
fn test_simple_tps_bench_minimal() {
    // Run a minimal benchmark to verify the harness works
    let config = BenchConfig {
        num_validators: 4,
        num_txs: 10,
        tx_payload_size: 32,
        max_txs_per_block: 10,
        mempool_size: 100,
        verbose: false,
    };

    let result = run_simple_tps_bench(config);

    // Verify basic invariants
    assert!(result.tps > 0.0, "TPS should be positive");
    assert_eq!(
        result.committed_txs, 10,
        "All transactions should be committed"
    );
    assert_eq!(result.rejected_txs, 0, "No transactions should be rejected");
    assert!(result.duration_secs > 0.0, "Duration should be positive");
}

/// Full DevNet TPS benchmark - marked as ignored for normal CI runs.
///
/// Run with: cargo test -p qbind-node --test t154_devnet_tps_harness tps_benchmark_canonical -- --ignored --nocapture
#[test]
#[ignore]
fn tps_benchmark_canonical() {
    eprintln!("\n=== T154 DevNet TPS Benchmark (Canonical DevNet v0 Scenario) ===\n");

    let config = BenchConfig::canonical_devnet_v0();
    let result = run_simple_tps_bench(config);

    result.print_summary();

    // Verify the benchmark completed successfully
    assert!(result.tps > 0.0, "TPS should be positive");
    assert!(
        result.committed_txs > 0,
        "Some transactions should be committed"
    );
    assert!(result.duration_secs > 0.0, "Duration should be positive");

    // Print benchmark verification message
    eprintln!("✓ Benchmark completed successfully");
    eprintln!(
        "  - Processed {} transactions in {:.3}s",
        result.committed_txs, result.duration_secs
    );
    eprintln!("  - Achieved {:.2} TPS", result.tps);
}

// ============================================================================
// Metrics Smoke Tests (T154)
// ============================================================================

#[test]
fn test_t154_metrics_smoke() {
    // Create NodeMetrics and verify T154 metrics are accessible
    let metrics = NodeMetrics::new();

    // Consensus T154 metrics
    metrics.consensus_t154().inc_proposal_accepted();
    metrics.consensus_t154().inc_proposal_rejected();
    metrics.consensus_t154().inc_vote_accepted();
    metrics.consensus_t154().inc_vote_invalid();
    metrics.consensus_t154().inc_timeout();
    metrics.consensus_t154().set_view_number(42);

    assert_eq!(metrics.consensus_t154().proposals_accepted(), 1);
    assert_eq!(metrics.consensus_t154().proposals_rejected(), 1);
    assert_eq!(metrics.consensus_t154().votes_accepted(), 1);
    assert_eq!(metrics.consensus_t154().votes_invalid(), 1);
    assert_eq!(metrics.consensus_t154().timeouts_total(), 1);
    assert_eq!(metrics.consensus_t154().view_number(), 42);

    // Mempool metrics
    metrics.mempool().inc_inserted();
    metrics.mempool().inc_inserted();
    metrics.mempool().set_size(100);
    metrics
        .mempool()
        .inc_rejected(qbind_node::MempoolRejectReason::Full);
    metrics.mempool().add_committed(5);

    assert_eq!(metrics.mempool().inserted_total(), 2);
    assert_eq!(metrics.mempool().size(), 100);
    assert_eq!(
        metrics
            .mempool()
            .rejected_by_reason(qbind_node::MempoolRejectReason::Full),
        1
    );
    assert_eq!(metrics.mempool().committed_total(), 5);

    // Execution metrics
    metrics.execution().add_txs_applied(10);
    metrics
        .execution()
        .record_block_apply(Duration::from_millis(5));
    metrics
        .execution()
        .inc_error(qbind_node::ExecutionErrorReason::NonceMismatch);

    assert_eq!(metrics.execution().txs_applied_total(), 10);
    assert_eq!(metrics.execution().blocks_applied_total(), 1);
    assert_eq!(
        metrics
            .execution()
            .errors_by_reason(qbind_node::ExecutionErrorReason::NonceMismatch),
        1
    );

    // Signer/Keystore metrics
    metrics
        .signer_keystore()
        .inc_sign_request(qbind_node::SignRequestKind::Proposal);
    metrics
        .signer_keystore()
        .inc_sign_request(qbind_node::SignRequestKind::Vote);
    metrics
        .signer_keystore()
        .inc_sign_request(qbind_node::SignRequestKind::Timeout);
    metrics.signer_keystore().inc_sign_failure();
    metrics
        .signer_keystore()
        .inc_keystore_load_success(qbind_node::KeystoreBackendKind::EncryptedFsV1);
    metrics
        .signer_keystore()
        .inc_keystore_load_failure(qbind_node::KeystoreBackendKind::PlainFs);

    assert_eq!(metrics.signer_keystore().sign_requests_total(), 3);
    assert_eq!(metrics.signer_keystore().sign_failures_total(), 1);
    assert_eq!(
        metrics
            .signer_keystore()
            .keystore_load_success_by_backend(qbind_node::KeystoreBackendKind::EncryptedFsV1),
        1
    );

    // Verify format_metrics doesn't panic and includes T154 sections
    let output = metrics.format_metrics();
    assert!(output.contains("Consensus metrics (T154)"));
    assert!(output.contains("Mempool metrics (T154)"));
    assert!(output.contains("Execution metrics (T154)"));
    assert!(output.contains("Signer/Keystore metrics (T154)"));
    assert!(output.contains("qbind_consensus_proposals_total"));
    assert!(output.contains("qbind_mempool_txs_total"));
    assert!(output.contains("qbind_execution_txs_applied_total"));
    assert!(output.contains("qbind_signer_sign_requests_total"));
}

#[test]
fn test_metrics_http_endpoint_smoke() {
    // Verify the metrics HTTP module can be used with the new T154 metrics
    use qbind_node::MetricsHttpConfig;
    use std::sync::Arc;

    let metrics = Arc::new(NodeMetrics::new());

    // Update some T154 metrics
    metrics.consensus_t154().inc_proposal_accepted();
    metrics.mempool().set_size(50);
    metrics.execution().add_txs_applied(100);

    // Verify config creation
    let config = MetricsHttpConfig::disabled();
    assert!(!config.is_enabled());

    let config = MetricsHttpConfig::from_addr("127.0.0.1:0");
    assert!(config.is_enabled());

    // The metrics formatting should include T154 metrics
    let output = metrics.format_metrics();
    assert!(output.contains("qbind_consensus_proposals_total{result=\"accepted\"} 1"));
    assert!(output.contains("qbind_mempool_txs_total 50"));
    assert!(output.contains("qbind_execution_txs_applied_total 100"));
}
