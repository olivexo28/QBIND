//! Multi-threaded consensus signature verification pool (T147).
//!
//! This module provides `ConsensusVerifyPool`, a thread pool dedicated to
//! verifying consensus message signatures (proposals, votes, timeouts).
//!
//! # Design
//!
//! The pool uses bounded crossbeam channels for backpressure:
//! - Job channel: bounded queue for incoming verification jobs
//! - Result channel: bounded queue for verification results
//!
//! Worker threads:
//! - Receive jobs from the job channel
//! - Look up the validator's public key from the key provider
//! - Look up the signature backend from the registry
//! - Verify signatures using the raw preimage
//! - Send results to the result channel
//!
//! # Usage
//!
//! ```ignore
//! use qbind_node::verify_pool::{ConsensusVerifyPool, ConsensusVerifyPoolConfig};
//!
//! // Create pool with default config
//! let config = ConsensusVerifyPoolConfig::default();
//! let pool = ConsensusVerifyPool::new(config, key_provider, backend_registry);
//!
//! // Submit a job
//! pool.submit(job)?;
//!
//! // Poll for results (non-blocking)
//! while let Some(result) = pool.try_recv() {
//!     if result.ok {
//!         // Process verified message
//!     }
//! }
//! ```
//!
//! # Memory Safety
//!
//! The bounded channels prevent unbounded memory growth:
//! - When job queue is full, `submit()` returns `Err(SubmitError::QueueFull)`
//! - The caller can then drop messages or apply backpressure
//!
//! # Thread Safety
//!
//! The pool is designed for safe concurrent access:
//! - Job submission can happen from multiple threads
//! - Result polling can happen from any thread
//! - Worker threads are isolated and share no mutable state

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crossbeam_channel::{bounded, Receiver, Sender, TryRecvError, TrySendError};

use qbind_consensus::crypto_verifier::ConsensusSigBackendRegistry;
use qbind_consensus::key_registry::SuiteAwareValidatorKeyProvider;
use qbind_consensus::verify_job::{ConsensusMsgKind, ConsensusVerifyJob, ConsensusVerifyResult};
use qbind_crypto::ConsensusSigSuiteId;

/// Configuration for the consensus verification pool.
#[derive(Debug, Clone)]
pub struct ConsensusVerifyPoolConfig {
    /// Number of worker threads.
    /// Default: number of CPU cores.
    pub num_workers: usize,
    /// Maximum number of jobs in the queue.
    /// When full, new jobs are dropped.
    /// Default: 1024.
    pub job_queue_capacity: usize,
    /// Maximum number of results in the queue.
    /// Default: 1024.
    pub result_queue_capacity: usize,
}

impl Default for ConsensusVerifyPoolConfig {
    fn default() -> Self {
        ConsensusVerifyPoolConfig {
            num_workers: num_cpus::get().max(1),
            job_queue_capacity: 1024,
            result_queue_capacity: 1024,
        }
    }
}

impl ConsensusVerifyPoolConfig {
    /// Create a configuration with specific worker count.
    pub fn with_workers(mut self, num_workers: usize) -> Self {
        self.num_workers = num_workers.max(1);
        self
    }

    /// Create a configuration with specific queue capacities.
    pub fn with_queue_capacity(mut self, capacity: usize) -> Self {
        self.job_queue_capacity = capacity.max(1);
        self.result_queue_capacity = capacity.max(1);
        self
    }
}

/// Error type for job submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitError<BlockIdT: Eq> {
    /// The job queue is full; the job was not queued.
    QueueFull(ConsensusVerifyJob<BlockIdT>),
    /// The pool has been shut down.
    PoolShutdown,
}

impl<BlockIdT: Eq> std::fmt::Display for SubmitError<BlockIdT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubmitError::QueueFull(_) => write!(f, "verification job queue is full"),
            SubmitError::PoolShutdown => write!(f, "verification pool has shut down"),
        }
    }
}

impl<BlockIdT: std::fmt::Debug + Eq> std::error::Error for SubmitError<BlockIdT> {}

/// Metrics for the verification pool.
#[derive(Debug, Default)]
pub struct VerifyPoolMetrics {
    /// Total jobs submitted successfully.
    pub jobs_submitted: AtomicU64,
    /// Jobs dropped due to full queue.
    pub jobs_dropped: AtomicU64,
    /// Jobs completed with ok=true.
    pub jobs_ok: AtomicU64,
    /// Jobs completed with ok=false.
    pub jobs_failed: AtomicU64,
}

impl VerifyPoolMetrics {
    /// Create new metrics with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the total number of submitted jobs.
    pub fn submitted(&self) -> u64 {
        self.jobs_submitted.load(Ordering::Relaxed)
    }

    /// Get the number of dropped jobs.
    pub fn dropped(&self) -> u64 {
        self.jobs_dropped.load(Ordering::Relaxed)
    }

    /// Get the number of successful verifications.
    pub fn ok(&self) -> u64 {
        self.jobs_ok.load(Ordering::Relaxed)
    }

    /// Get the number of failed verifications.
    pub fn failed(&self) -> u64 {
        self.jobs_failed.load(Ordering::Relaxed)
    }

    fn inc_submitted(&self) {
        self.jobs_submitted.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_dropped(&self) {
        self.jobs_dropped.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_ok(&self) {
        self.jobs_ok.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_failed(&self) {
        self.jobs_failed.fetch_add(1, Ordering::Relaxed);
    }
}

/// A multi-threaded verification pool for consensus messages.
///
/// # Type Parameter
///
/// - `BlockIdT`: The block identifier type (typically `[u8; 32]`)
pub struct ConsensusVerifyPool<BlockIdT: Eq> {
    /// Sender for submitting jobs to workers.
    job_tx: Sender<ConsensusVerifyJob<BlockIdT>>,
    /// Receiver for verification results.
    result_rx: Receiver<ConsensusVerifyResult<BlockIdT>>,
    /// Worker thread handles.
    workers: Vec<JoinHandle<()>>,
    /// Pool metrics.
    metrics: Arc<VerifyPoolMetrics>,
}

impl<BlockIdT> ConsensusVerifyPool<BlockIdT>
where
    BlockIdT: Send + Clone + std::fmt::Debug + Eq + 'static,
{
    /// Create a new verification pool with the given configuration.
    ///
    /// # Arguments
    ///
    /// - `config`: Pool configuration (worker count, queue sizes)
    /// - `key_provider`: Provider for looking up validator public keys
    /// - `backend_registry`: Registry mapping suite IDs to verifier backends
    ///
    /// # Note
    ///
    /// Both the key provider and backend registry must be `Send + Sync + 'static`
    /// as they will be shared across worker threads.
    pub fn new<K, B>(
        config: ConsensusVerifyPoolConfig,
        key_provider: Arc<K>,
        backend_registry: Arc<B>,
    ) -> Self
    where
        K: SuiteAwareValidatorKeyProvider + Send + Sync + 'static,
        B: ConsensusSigBackendRegistry + Send + Sync + 'static,
    {
        let (job_tx, job_rx) = bounded::<ConsensusVerifyJob<BlockIdT>>(config.job_queue_capacity);
        let (result_tx, result_rx) =
            bounded::<ConsensusVerifyResult<BlockIdT>>(config.result_queue_capacity);

        let metrics = Arc::new(VerifyPoolMetrics::new());

        // Spawn worker threads
        let mut workers = Vec::with_capacity(config.num_workers);
        for worker_id in 0..config.num_workers {
            let job_rx = job_rx.clone();
            let result_tx = result_tx.clone();
            let key_provider = key_provider.clone();
            let backend_registry = backend_registry.clone();
            let metrics = metrics.clone();

            let handle = thread::Builder::new()
                .name(format!("verify-worker-{}", worker_id))
                .spawn(move || {
                    Self::worker_loop(
                        worker_id,
                        job_rx,
                        result_tx,
                        key_provider,
                        backend_registry,
                        metrics,
                    );
                })
                .expect("failed to spawn verification worker thread");

            workers.push(handle);
        }

        ConsensusVerifyPool {
            job_tx,
            result_rx,
            workers,
            metrics,
        }
    }

    /// Worker thread main loop.
    fn worker_loop<K, B>(
        worker_id: usize,
        job_rx: Receiver<ConsensusVerifyJob<BlockIdT>>,
        result_tx: Sender<ConsensusVerifyResult<BlockIdT>>,
        key_provider: Arc<K>,
        backend_registry: Arc<B>,
        metrics: Arc<VerifyPoolMetrics>,
    ) where
        K: SuiteAwareValidatorKeyProvider + Send + Sync + 'static,
        B: ConsensusSigBackendRegistry + Send + Sync + 'static,
    {
        #[cfg(debug_assertions)]
        eprintln!("[T147] Verify worker {} starting", worker_id);

        // Process jobs until channel is disconnected
        while let Ok(job) = job_rx.recv() {
            let result = Self::verify_job(&job, &*key_provider, &*backend_registry);

            // Update metrics
            if result.ok {
                metrics.inc_ok();
            } else {
                metrics.inc_failed();
            }

            #[cfg(debug_assertions)]
            eprintln!(
                "[T147] Worker {} verified {:?} job for validator {:?}: ok={}",
                worker_id, job.kind, job.validator_id, result.ok
            );

            // Send result (best effort - if result queue is full, we drop silently)
            // This prevents worker deadlock when result consumer is slow
            let _ = result_tx.try_send(result);
        }

        #[cfg(debug_assertions)]
        eprintln!("[T147] Verify worker {} exiting", worker_id);
    }

    /// Verify a single job using the key provider and backend registry.
    fn verify_job<K, B>(
        job: &ConsensusVerifyJob<BlockIdT>,
        key_provider: &K,
        backend_registry: &B,
    ) -> ConsensusVerifyResult<BlockIdT>
    where
        K: SuiteAwareValidatorKeyProvider,
        B: ConsensusSigBackendRegistry,
    {
        // Step 1: Look up the validator's public key and expected suite
        let (governance_suite, pk_bytes) = match key_provider.get_suite_and_key(job.validator_id) {
            Some(result) => result,
            None => {
                return ConsensusVerifyResult::failure(
                    job.clone(),
                    format!("missing key for validator {:?}", job.validator_id),
                );
            }
        };

        // Step 2: Verify suite ID matches governance expectation
        let wire_suite = ConsensusSigSuiteId::new(job.suite_id);
        if wire_suite != governance_suite {
            return ConsensusVerifyResult::failure(
                job.clone(),
                format!(
                    "suite mismatch: wire={}, governance={}",
                    wire_suite, governance_suite
                ),
            );
        }

        // Step 3: Get the verifier backend for this suite
        let backend = match backend_registry.get_backend(governance_suite) {
            Some(b) => b,
            None => {
                return ConsensusVerifyResult::failure(
                    job.clone(),
                    format!("unsupported suite: {}", governance_suite),
                );
            }
        };

        // Step 4: Verify the signature using the raw preimage
        // The backend's verify methods take the raw preimage directly.
        let verify_result = match job.kind {
            ConsensusMsgKind::Vote | ConsensusMsgKind::Timeout => backend.verify_vote(
                job.validator_id.as_u64(),
                &pk_bytes,
                &job.message_bytes,
                &job.signature,
            ),
            ConsensusMsgKind::Proposal => backend.verify_proposal(
                job.validator_id.as_u64(),
                &pk_bytes,
                &job.message_bytes,
                &job.signature,
            ),
        };

        match verify_result {
            Ok(()) => ConsensusVerifyResult::success(job.clone()),
            Err(e) => ConsensusVerifyResult::failure(job.clone(), format!("{}", e)),
        }
    }

    /// Submit a job for verification.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the job was queued successfully
    /// - `Err(SubmitError::QueueFull(job))` if the queue is full
    /// - `Err(SubmitError::PoolShutdown)` if the pool has been shut down
    pub fn submit(&self, job: ConsensusVerifyJob<BlockIdT>) -> Result<(), SubmitError<BlockIdT>> {
        match self.job_tx.try_send(job) {
            Ok(()) => {
                self.metrics.inc_submitted();
                Ok(())
            }
            Err(TrySendError::Full(job)) => {
                self.metrics.inc_dropped();
                Err(SubmitError::QueueFull(job))
            }
            Err(TrySendError::Disconnected(_)) => Err(SubmitError::PoolShutdown),
        }
    }

    /// Try to receive a verification result (non-blocking).
    ///
    /// # Returns
    ///
    /// - `Some(result)` if a result is available
    /// - `None` if no results are currently available
    pub fn try_recv(&self) -> Option<ConsensusVerifyResult<BlockIdT>> {
        match self.result_rx.try_recv() {
            Ok(result) => Some(result),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => None,
        }
    }

    /// Drain all available results (non-blocking).
    ///
    /// # Returns
    ///
    /// A vector of all currently available results.
    pub fn drain_results(&self) -> Vec<ConsensusVerifyResult<BlockIdT>> {
        let mut results = Vec::new();
        while let Some(result) = self.try_recv() {
            results.push(result);
        }
        results
    }

    /// Get the pool metrics.
    pub fn metrics(&self) -> &VerifyPoolMetrics {
        &self.metrics
    }

    /// Get the number of worker threads.
    pub fn num_workers(&self) -> usize {
        self.workers.len()
    }

    /// Check if any workers are still running.
    pub fn workers_alive(&self) -> usize {
        self.workers.iter().filter(|h| !h.is_finished()).count()
    }
}

impl<BlockIdT: Eq> Drop for ConsensusVerifyPool<BlockIdT> {
    fn drop(&mut self) {
        // Dropping job_tx will cause all workers to exit their loops
        // when the channel becomes disconnected.
        // We don't join workers here to avoid blocking during drop.
        #[cfg(debug_assertions)]
        eprintln!(
            "[T147] ConsensusVerifyPool dropping, {} workers will exit",
            self.workers.len()
        );
    }
}

// ============================================================================
// Test helpers
// ============================================================================

/// A mock key provider for testing that always returns a fixed key.
#[derive(Debug, Clone)]
pub struct MockKeyProvider {
    /// The suite ID to return for all validators.
    pub suite_id: ConsensusSigSuiteId,
    /// The public key bytes to return for all validators.
    pub pk_bytes: Vec<u8>,
}

impl MockKeyProvider {
    /// Create a new mock key provider.
    pub fn new(suite_id: u16, pk_bytes: Vec<u8>) -> Self {
        MockKeyProvider {
            suite_id: ConsensusSigSuiteId::new(suite_id),
            pk_bytes,
        }
    }
}

impl SuiteAwareValidatorKeyProvider for MockKeyProvider {
    fn get_suite_and_key(
        &self,
        _id: qbind_consensus::ids::ValidatorId,
    ) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        Some((self.suite_id, self.pk_bytes.clone()))
    }
}

/// A mock backend registry for testing that always verifies successfully.
#[derive(Debug, Clone)]
pub struct MockBackendRegistry {
    /// The suite ID this registry supports.
    pub suite_id: ConsensusSigSuiteId,
}

impl MockBackendRegistry {
    /// Create a new mock backend registry.
    pub fn new(suite_id: u16) -> Self {
        MockBackendRegistry {
            suite_id: ConsensusSigSuiteId::new(suite_id),
        }
    }
}

impl ConsensusSigBackendRegistry for MockBackendRegistry {
    fn get_backend(
        &self,
        suite: ConsensusSigSuiteId,
    ) -> Option<std::sync::Arc<dyn qbind_crypto::consensus_sig::ConsensusSigVerifier>> {
        if suite == self.suite_id {
            Some(std::sync::Arc::new(MockVerifier))
        } else {
            None
        }
    }
}

/// A mock verifier that always succeeds.
#[derive(Debug)]
struct MockVerifier;

impl qbind_crypto::consensus_sig::ConsensusSigVerifier for MockVerifier {
    fn verify_vote(
        &self,
        _validator_id: u64,
        _pk: &[u8],
        _preimage: &[u8],
        _signature: &[u8],
    ) -> Result<(), qbind_crypto::consensus_sig::ConsensusSigError> {
        Ok(())
    }

    fn verify_proposal(
        &self,
        _validator_id: u64,
        _pk: &[u8],
        _preimage: &[u8],
        _signature: &[u8],
    ) -> Result<(), qbind_crypto::consensus_sig::ConsensusSigError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_consensus::ids::ValidatorId;

    #[test]
    fn test_pool_config_default() {
        let config = ConsensusVerifyPoolConfig::default();
        assert!(config.num_workers >= 1);
        assert_eq!(config.job_queue_capacity, 1024);
        assert_eq!(config.result_queue_capacity, 1024);
    }

    #[test]
    fn test_pool_config_with_workers() {
        let config = ConsensusVerifyPoolConfig::default().with_workers(4);
        assert_eq!(config.num_workers, 4);
    }

    #[test]
    fn test_pool_config_with_queue_capacity() {
        let config = ConsensusVerifyPoolConfig::default().with_queue_capacity(100);
        assert_eq!(config.job_queue_capacity, 100);
        assert_eq!(config.result_queue_capacity, 100);
    }

    #[test]
    fn test_pool_creation() {
        let config = ConsensusVerifyPoolConfig::default().with_workers(2);
        let key_provider = Arc::new(MockKeyProvider::new(100, vec![1, 2, 3]));
        let backend_registry = Arc::new(MockBackendRegistry::new(100));
        let pool: ConsensusVerifyPool<[u8; 32]> =
            ConsensusVerifyPool::new(config, key_provider, backend_registry);

        assert_eq!(pool.num_workers(), 2);
        assert_eq!(pool.metrics().submitted(), 0);
        assert_eq!(pool.metrics().dropped(), 0);
    }

    #[test]
    fn test_pool_submit_and_receive() {
        let config = ConsensusVerifyPoolConfig::default()
            .with_workers(2)
            .with_queue_capacity(10);
        let key_provider = Arc::new(MockKeyProvider::new(100, vec![1, 2, 3]));
        let backend_registry = Arc::new(MockBackendRegistry::new(100));
        let pool: ConsensusVerifyPool<[u8; 32]> =
            ConsensusVerifyPool::new(config, key_provider, backend_registry);

        // Submit a job
        let job = ConsensusVerifyJob::new_vote(
            1,
            [1u8; 32],
            ValidatorId::new(1),
            100,
            vec![1, 2, 3],
            vec![4, 5, 6],
        );

        pool.submit(job).expect("should submit");
        assert_eq!(pool.metrics().submitted(), 1);

        // Wait for result
        std::thread::sleep(std::time::Duration::from_millis(50));

        let results = pool.drain_results();
        assert_eq!(results.len(), 1);
        assert!(results[0].ok); // MockVerifier always returns Ok
        assert_eq!(results[0].job.kind, ConsensusMsgKind::Vote);
    }

    #[test]
    fn test_pool_queue_full() {
        let config = ConsensusVerifyPoolConfig::default()
            .with_workers(1)
            .with_queue_capacity(1);
        let key_provider = Arc::new(MockKeyProvider::new(100, vec![1, 2, 3]));
        let backend_registry = Arc::new(MockBackendRegistry::new(100));
        let pool: ConsensusVerifyPool<[u8; 32]> =
            ConsensusVerifyPool::new(config, key_provider, backend_registry);

        // Submit first job (should succeed)
        let job1 =
            ConsensusVerifyJob::new_vote(1, [1u8; 32], ValidatorId::new(1), 100, vec![], vec![]);
        pool.submit(job1).expect("first job should submit");

        // Submit many more jobs to fill the queue
        // Some should fail with QueueFull
        let mut dropped = 0;
        for i in 0..100 {
            let job = ConsensusVerifyJob::new_vote(
                i,
                [i as u8; 32],
                ValidatorId::new(i),
                100,
                vec![],
                vec![],
            );
            if let Err(SubmitError::QueueFull(_)) = pool.submit(job) {
                dropped += 1;
            }
        }

        // With queue capacity of 1, most should be dropped
        assert!(
            dropped > 0,
            "some jobs should be dropped when queue is full"
        );
        assert!(pool.metrics().dropped() > 0);
    }

    #[test]
    fn test_pool_metrics() {
        let metrics = VerifyPoolMetrics::new();

        metrics.inc_submitted();
        metrics.inc_submitted();
        assert_eq!(metrics.submitted(), 2);

        metrics.inc_dropped();
        assert_eq!(metrics.dropped(), 1);

        metrics.inc_ok();
        metrics.inc_ok();
        metrics.inc_ok();
        assert_eq!(metrics.ok(), 3);

        metrics.inc_failed();
        assert_eq!(metrics.failed(), 1);
    }

    #[test]
    fn test_suite_mismatch_fails() {
        let config = ConsensusVerifyPoolConfig::default()
            .with_workers(1)
            .with_queue_capacity(10);
        // Key provider returns suite 100
        let key_provider = Arc::new(MockKeyProvider::new(100, vec![1, 2, 3]));
        // Backend registry also supports suite 100
        let backend_registry = Arc::new(MockBackendRegistry::new(100));
        let pool: ConsensusVerifyPool<[u8; 32]> =
            ConsensusVerifyPool::new(config, key_provider, backend_registry);

        // Submit a job with suite 200 (mismatch)
        let job = ConsensusVerifyJob::new_vote(
            1,
            [1u8; 32],
            ValidatorId::new(1),
            200, // Different from governance (100)
            vec![1, 2, 3],
            vec![4, 5, 6],
        );

        pool.submit(job).expect("should submit");

        // Wait for result
        std::thread::sleep(std::time::Duration::from_millis(50));

        let results = pool.drain_results();
        assert_eq!(results.len(), 1);
        assert!(!results[0].ok); // Should fail due to suite mismatch
        assert!(results[0]
            .error
            .as_ref()
            .unwrap()
            .contains("suite mismatch"));
    }
}
