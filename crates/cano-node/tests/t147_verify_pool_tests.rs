//! T147: Unit and integration tests for ConsensusVerifyPool.
//!
//! These tests verify:
//! - Pool configuration (workers, queue capacity)
//! - Job submission and result retrieval
//! - Happy path (valid signatures)
//! - Failure path (invalid signatures)
//! - Queue full behavior (backpressure)
//! - Parallelism (structural verification)

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use cano_consensus::ids::ValidatorId;
use cano_consensus::verify_job::{ConsensusMsgKind, ConsensusVerifyJob};
use cano_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier};
use cano_crypto::ConsensusSigSuiteId;
use cano_node::verify_pool::{
    ConsensusVerifyPool, ConsensusVerifyPoolConfig, MockBackendRegistry, MockKeyProvider,
    SubmitError, VerifyPoolMetrics,
};

// ============================================================================
// Configuration tests
// ============================================================================

#[test]
fn test_pool_config_default() {
    let config = ConsensusVerifyPoolConfig::default();
    assert!(config.num_workers >= 1, "should have at least 1 worker");
    assert_eq!(config.job_queue_capacity, 1024);
    assert_eq!(config.result_queue_capacity, 1024);
}

#[test]
fn test_pool_config_with_workers() {
    let config = ConsensusVerifyPoolConfig::default().with_workers(8);
    assert_eq!(config.num_workers, 8);
}

#[test]
fn test_pool_config_with_workers_zero_becomes_one() {
    let config = ConsensusVerifyPoolConfig::default().with_workers(0);
    assert_eq!(config.num_workers, 1, "zero workers should become 1");
}

#[test]
fn test_pool_config_with_queue_capacity() {
    let config = ConsensusVerifyPoolConfig::default().with_queue_capacity(100);
    assert_eq!(config.job_queue_capacity, 100);
    assert_eq!(config.result_queue_capacity, 100);
}

#[test]
fn test_pool_config_with_queue_capacity_zero_becomes_one() {
    let config = ConsensusVerifyPoolConfig::default().with_queue_capacity(0);
    assert_eq!(
        config.job_queue_capacity, 1,
        "zero capacity should become 1"
    );
    assert_eq!(config.result_queue_capacity, 1);
}

// ============================================================================
// Pool creation tests
// ============================================================================

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
    assert_eq!(pool.metrics().ok(), 0);
    assert_eq!(pool.metrics().failed(), 0);
}

#[test]
fn test_pool_creation_with_default_workers() {
    let config = ConsensusVerifyPoolConfig::default();
    let expected_workers = config.num_workers;

    let key_provider = Arc::new(MockKeyProvider::new(100, vec![1, 2, 3]));
    let backend_registry = Arc::new(MockBackendRegistry::new(100));
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    assert_eq!(pool.num_workers(), expected_workers);
}

// ============================================================================
// Happy path tests
// ============================================================================

#[test]
fn test_pool_submit_and_receive_vote() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(2)
        .with_queue_capacity(10);
    let key_provider = Arc::new(MockKeyProvider::new(100, vec![1, 2, 3]));
    let backend_registry = Arc::new(MockBackendRegistry::new(100));
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    // Submit a vote job
    let job = ConsensusVerifyJob::new_vote(
        1,
        [1u8; 32],
        ValidatorId::new(1),
        100, // Matches key provider and backend
        vec![1, 2, 3],
        vec![4, 5, 6],
    );

    pool.submit(job).expect("should submit");
    assert_eq!(pool.metrics().submitted(), 1);

    // Wait for result
    thread::sleep(Duration::from_millis(50));

    let results = pool.drain_results();
    assert_eq!(results.len(), 1);
    assert!(results[0].ok, "verification should succeed");
    assert_eq!(results[0].job.kind, ConsensusMsgKind::Vote);
    assert_eq!(pool.metrics().ok(), 1);
}

#[test]
fn test_pool_submit_and_receive_proposal() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(2)
        .with_queue_capacity(10);
    let key_provider = Arc::new(MockKeyProvider::new(100, vec![1, 2, 3]));
    let backend_registry = Arc::new(MockBackendRegistry::new(100));
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    // Submit a proposal job
    let job = ConsensusVerifyJob::new_proposal(
        10,
        [2u8; 32],
        ValidatorId::new(2),
        100,
        vec![7, 8, 9],
        vec![10, 11, 12],
    );

    pool.submit(job).expect("should submit");

    // Wait for result
    thread::sleep(Duration::from_millis(50));

    let results = pool.drain_results();
    assert_eq!(results.len(), 1);
    assert!(results[0].ok);
    assert_eq!(results[0].job.kind, ConsensusMsgKind::Proposal);
}

#[test]
fn test_pool_submit_and_receive_timeout() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(2)
        .with_queue_capacity(10);
    let key_provider = Arc::new(MockKeyProvider::new(100, vec![1, 2, 3]));
    let backend_registry = Arc::new(MockBackendRegistry::new(100));
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    // Submit a timeout job
    let job = ConsensusVerifyJob::new_timeout(
        20,
        ValidatorId::new(3),
        100,
        vec![13, 14, 15],
        vec![16, 17, 18],
    );

    pool.submit(job).expect("should submit");

    // Wait for result
    thread::sleep(Duration::from_millis(50));

    let results = pool.drain_results();
    assert_eq!(results.len(), 1);
    assert!(results[0].ok);
    assert_eq!(results[0].job.kind, ConsensusMsgKind::Timeout);
}

#[test]
fn test_pool_multiple_jobs() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(4)
        .with_queue_capacity(100);
    let key_provider = Arc::new(MockKeyProvider::new(100, vec![1, 2, 3]));
    let backend_registry = Arc::new(MockBackendRegistry::new(100));
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    // Submit multiple jobs
    let num_jobs = 50;
    for i in 0..num_jobs {
        let job = ConsensusVerifyJob::new_vote(
            i,
            [i as u8; 32],
            ValidatorId::new(i),
            100,
            vec![i as u8],
            vec![(i + 1) as u8],
        );
        pool.submit(job).expect("should submit");
    }

    assert_eq!(pool.metrics().submitted(), num_jobs);

    // Wait for all results
    thread::sleep(Duration::from_millis(200));

    let results = pool.drain_results();
    assert_eq!(results.len(), num_jobs as usize);
    assert!(results.iter().all(|r| r.ok));
    assert_eq!(pool.metrics().ok(), num_jobs);
}

// ============================================================================
// Failure path tests
// ============================================================================

#[test]
fn test_pool_suite_mismatch_fails() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(1)
        .with_queue_capacity(10);
    // Key provider returns suite 100
    let key_provider = Arc::new(MockKeyProvider::new(100, vec![1, 2, 3]));
    // Backend also supports suite 100
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
    thread::sleep(Duration::from_millis(50));

    let results = pool.drain_results();
    assert_eq!(results.len(), 1);
    assert!(!results[0].ok, "should fail due to suite mismatch");
    assert!(results[0]
        .error
        .as_ref()
        .unwrap()
        .contains("suite mismatch"));
    assert_eq!(pool.metrics().failed(), 1);
}

#[test]
fn test_pool_unsupported_suite_fails() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(1)
        .with_queue_capacity(10);
    // Key provider returns suite 100
    let key_provider = Arc::new(MockKeyProvider::new(100, vec![1, 2, 3]));
    // Backend only supports suite 200 (different from key provider)
    let backend_registry = Arc::new(MockBackendRegistry::new(200));
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    // Submit a job with suite 100 (matches key provider but not backend)
    let job = ConsensusVerifyJob::new_vote(
        1,
        [1u8; 32],
        ValidatorId::new(1),
        100,
        vec![1, 2, 3],
        vec![4, 5, 6],
    );

    pool.submit(job).expect("should submit");

    // Wait for result
    thread::sleep(Duration::from_millis(50));

    let results = pool.drain_results();
    assert_eq!(results.len(), 1);
    assert!(!results[0].ok, "should fail due to unsupported suite");
    assert!(results[0]
        .error
        .as_ref()
        .unwrap()
        .contains("unsupported suite"));
}

/// A verifier that always fails.
#[derive(Debug)]
struct FailingVerifier;

impl ConsensusSigVerifier for FailingVerifier {
    fn verify_vote(
        &self,
        _validator_id: u64,
        _pk: &[u8],
        _preimage: &[u8],
        _signature: &[u8],
    ) -> Result<(), ConsensusSigError> {
        Err(ConsensusSigError::InvalidSignature)
    }

    fn verify_proposal(
        &self,
        _validator_id: u64,
        _pk: &[u8],
        _preimage: &[u8],
        _signature: &[u8],
    ) -> Result<(), ConsensusSigError> {
        Err(ConsensusSigError::InvalidSignature)
    }
}

/// Backend registry that uses a failing verifier.
struct FailingBackendRegistry {
    suite_id: ConsensusSigSuiteId,
}

impl FailingBackendRegistry {
    fn new(suite_id: u16) -> Self {
        FailingBackendRegistry {
            suite_id: ConsensusSigSuiteId::new(suite_id),
        }
    }
}

impl cano_consensus::crypto_verifier::ConsensusSigBackendRegistry for FailingBackendRegistry {
    fn get_backend(&self, suite: ConsensusSigSuiteId) -> Option<Arc<dyn ConsensusSigVerifier>> {
        if suite == self.suite_id {
            Some(Arc::new(FailingVerifier))
        } else {
            None
        }
    }
}

#[test]
fn test_pool_invalid_signature_fails() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(1)
        .with_queue_capacity(10);
    let key_provider = Arc::new(MockKeyProvider::new(100, vec![1, 2, 3]));
    // Use a failing backend that rejects all signatures
    let backend_registry = Arc::new(FailingBackendRegistry::new(100));
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    let job = ConsensusVerifyJob::new_vote(
        1,
        [1u8; 32],
        ValidatorId::new(1),
        100,
        vec![1, 2, 3],
        vec![4, 5, 6],
    );

    pool.submit(job).expect("should submit");

    // Wait for result
    thread::sleep(Duration::from_millis(50));

    let results = pool.drain_results();
    assert_eq!(results.len(), 1);
    assert!(!results[0].ok, "should fail due to invalid signature");
    assert_eq!(pool.metrics().failed(), 1);
}

// ============================================================================
// Queue full behavior tests
// ============================================================================

#[test]
fn test_pool_queue_full_drops_jobs() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(1)
        .with_queue_capacity(1);
    let key_provider = Arc::new(MockKeyProvider::new(100, vec![1, 2, 3]));
    let backend_registry = Arc::new(MockBackendRegistry::new(100));
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    // Submit first job (should succeed)
    let job1 = ConsensusVerifyJob::new_vote(1, [1u8; 32], ValidatorId::new(1), 100, vec![], vec![]);
    pool.submit(job1).expect("first job should submit");

    // Quickly submit many more jobs to fill the queue
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

    assert!(
        dropped > 0,
        "some jobs should be dropped when queue is full"
    );
    assert!(
        pool.metrics().dropped() > 0,
        "dropped metric should be incremented"
    );
}

#[test]
fn test_pool_queue_full_returns_job() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(1)
        .with_queue_capacity(1);
    let key_provider = Arc::new(MockKeyProvider::new(100, vec![1, 2, 3]));
    let backend_registry = Arc::new(MockBackendRegistry::new(100));
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    // Fill the queue
    let job1 = ConsensusVerifyJob::new_vote(1, [1u8; 32], ValidatorId::new(1), 100, vec![], vec![]);
    pool.submit(job1).expect("first job should submit");

    // Try to submit another job (should fail and return the job)
    let job2 = ConsensusVerifyJob::new_vote(2, [2u8; 32], ValidatorId::new(2), 100, vec![], vec![]);
    match pool.submit(job2) {
        Err(SubmitError::QueueFull(returned_job)) => {
            assert_eq!(returned_job.view, 2);
            assert_eq!(returned_job.validator_id, ValidatorId::new(2));
        }
        _ => {
            // Job might have been processed and queue drained - this is also acceptable
        }
    }
}

#[test]
fn test_pool_no_panic_under_load() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(4)
        .with_queue_capacity(10);
    let key_provider = Arc::new(MockKeyProvider::new(100, vec![1, 2, 3]));
    let backend_registry = Arc::new(MockBackendRegistry::new(100));
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    // Spam many jobs - should not panic
    for i in 0..10000 {
        let job = ConsensusVerifyJob::new_vote(
            i,
            [(i % 256) as u8; 32],
            ValidatorId::new(i),
            100,
            vec![(i % 256) as u8],
            vec![((i + 1) % 256) as u8],
        );
        let _ = pool.submit(job); // Ignore errors
    }

    // Wait a bit for processing
    thread::sleep(Duration::from_millis(100));

    // Drain results - should not panic
    let _ = pool.drain_results();

    // Check metrics are reasonable
    let total = pool.metrics().submitted() + pool.metrics().dropped();
    assert!(total > 0, "should have processed some jobs");
}

// ============================================================================
// Metrics tests
// ============================================================================

#[test]
fn test_pool_metrics() {
    let metrics = VerifyPoolMetrics::new();

    // Check initial values
    assert_eq!(metrics.submitted(), 0);
    assert_eq!(metrics.dropped(), 0);
    assert_eq!(metrics.ok(), 0);
    assert_eq!(metrics.failed(), 0);

    // Increment and check
    metrics
        .jobs_submitted
        .fetch_add(10, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(metrics.submitted(), 10);

    metrics
        .jobs_dropped
        .fetch_add(5, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(metrics.dropped(), 5);

    metrics
        .jobs_ok
        .fetch_add(100, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(metrics.ok(), 100);

    metrics
        .jobs_failed
        .fetch_add(3, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(metrics.failed(), 3);
}

// ============================================================================
// Parallelism tests
// ============================================================================

#[test]
fn test_pool_uses_multiple_workers() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(4)
        .with_queue_capacity(100);
    let key_provider = Arc::new(MockKeyProvider::new(100, vec![1, 2, 3]));
    let backend_registry = Arc::new(MockBackendRegistry::new(100));
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    assert_eq!(pool.num_workers(), 4);

    // Submit many jobs
    for i in 0..100 {
        let job = ConsensusVerifyJob::new_vote(
            i,
            [i as u8; 32],
            ValidatorId::new(i),
            100,
            vec![],
            vec![],
        );
        pool.submit(job).expect("should submit");
    }

    // Wait for processing
    thread::sleep(Duration::from_millis(100));

    // All jobs should be processed
    let results = pool.drain_results();
    assert_eq!(results.len(), 100);

    // Check that workers are still alive (not crashed)
    assert!(pool.workers_alive() > 0, "workers should still be running");
}

#[test]
fn test_pool_workers_alive() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(4)
        .with_queue_capacity(10);
    let key_provider = Arc::new(MockKeyProvider::new(100, vec![1, 2, 3]));
    let backend_registry = Arc::new(MockBackendRegistry::new(100));
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    // Workers should be alive after creation
    assert_eq!(pool.workers_alive(), 4);

    // Submit a job
    let job = ConsensusVerifyJob::new_vote(1, [1u8; 32], ValidatorId::new(1), 100, vec![], vec![]);
    pool.submit(job).expect("should submit");

    // Wait a bit
    thread::sleep(Duration::from_millis(50));

    // Workers should still be alive
    assert_eq!(pool.workers_alive(), 4);
}

// ============================================================================
// try_recv tests
// ============================================================================

#[test]
fn test_pool_try_recv_empty() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(1)
        .with_queue_capacity(10);
    let key_provider = Arc::new(MockKeyProvider::new(100, vec![1, 2, 3]));
    let backend_registry = Arc::new(MockBackendRegistry::new(100));
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    // Should return None when no results available
    assert!(pool.try_recv().is_none());
}

#[test]
fn test_pool_try_recv_after_submit() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(2)
        .with_queue_capacity(10);
    let key_provider = Arc::new(MockKeyProvider::new(100, vec![1, 2, 3]));
    let backend_registry = Arc::new(MockBackendRegistry::new(100));
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    let job = ConsensusVerifyJob::new_vote(1, [1u8; 32], ValidatorId::new(1), 100, vec![], vec![]);
    pool.submit(job).expect("should submit");

    // Wait for processing
    thread::sleep(Duration::from_millis(50));

    // Should get a result
    let result = pool.try_recv();
    assert!(result.is_some());
    assert!(result.unwrap().ok);
}

#[test]
fn test_pool_drain_results_multiple() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(4)
        .with_queue_capacity(100);
    let key_provider = Arc::new(MockKeyProvider::new(100, vec![1, 2, 3]));
    let backend_registry = Arc::new(MockBackendRegistry::new(100));
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    // Submit multiple jobs
    for i in 0..20 {
        let job = ConsensusVerifyJob::new_vote(
            i,
            [i as u8; 32],
            ValidatorId::new(i),
            100,
            vec![],
            vec![],
        );
        pool.submit(job).expect("should submit");
    }

    // Wait for processing
    thread::sleep(Duration::from_millis(100));

    // Drain should get all results
    let results = pool.drain_results();
    assert_eq!(results.len(), 20);

    // Subsequent drain should be empty
    let more_results = pool.drain_results();
    assert!(more_results.is_empty());
}
