# QBIND DevNet v0 Architecture Spec

## Overview
This document describes the architecture of **QBIND DevNet v0**, the initial developer network for the QBIND protocol. DevNet v0 is designed as a minimal, functional baseline to validate core consensus, networking, and execution components before moving to a public TestNet.

**Scope**: DevNet v0 focuses on correctness, basic liveness, and component integration (HotStuff BFT + KEMTLS + Execution). It runs in a controlled environment with a static validator set.

## System Architecture (DevNet v0)

### 1. Validator Keys & Signing
*   **Keystore (T144/T153)**: Validators load keys from local disk using one of two backends:
    *   **PlainFs (T144)**: Plaintext JSON files (`.json`) containing secret key and suite ID (ML-DSA-44). **Recommended for testing/development only.**
    *   **EncryptedFsV1 (T153)**: Encrypted files (`.enc`) using ChaCha20-Poly1305 AEAD with PBKDF2-derived keys. **Recommended for DevNet and beyond.**
*   **Identity**: Nodes verify their identity at startup using `LocalValidatorIdentity`, ensuring the loaded key matches the configured validator ID. This self-check works identically for both keystore backends.
*   **Signer Abstraction**: The `ValidatorSigner` trait (T148) abstracts all consensus signing operations.
    *   **Current Implementation**: `LocalKeySigner` (in-memory signing).
    *   **Remote Signing**: Supported via `RemoteSignerClient` and `LoopbackSignerTransport` (T149) for testing remote signing flows without actual remote hardware.

#### DevNet Key Storage Policy v1 (T153)

For DevNet v0, the following key storage options are available:

| Backend | File Format | Encryption | DevNet Status | TestNet/MainNet |
| :--- | :--- | :--- | :--- | :--- |
| **PlainFs** | JSON (`.json`) | None (OS-level only) | Acceptable for local testing | **Not Acceptable** |
| **EncryptedFsV1** | JSON (`.enc`) | ChaCha20-Poly1305 + PBKDF2 | **Recommended** | Acceptable (with stronger passphrase mgmt) |
| **Remote Signer** | N/A | Handled externally | Available (loopback for testing) | **Required** (with HSM) |

**DevNet Recommendations:**
*   Use `EncryptedFsV1` for any non-ephemeral DevNet deployment.
*   Passphrase should be stored in a secure environment variable (e.g., `QBIND_VALIDATOR_KEY_PASSPHRASE`).
*   Encrypted files may be committed to version control (salt/nonce are public), but passphrases must never be committed.

**TestNet/MainNet Requirements (Future):**
*   Encrypted keystore with strong passphrase management (e.g., secrets manager, vault).
*   Remote signer with HSM support for production validator keys.
*   Threshold signatures for high-value validators.

### 2. Consensus Layer
*   **Protocol**: **HotStuff BFT** (3-chain commit rule).
*   **Engine**: `BasicHotStuffEngine` (T56+).
*   **View Synchronization**:
    *   **Pacemaker**: `BasicTickPacemaker` for proposal timing.
    *   **Timeout/View-Change**: `TimeoutPacemaker` (T146) handles liveness. Validators emit `TimeoutMsg` upon view timeout, forming a `TimeoutCertificate` (TC) to force a view change.
*   **Verification**: `ConsensusVerifyPool` (T147) offloads ML-DSA-44 signature verification to a thread pool to avoid blocking the main event loop.

### 3. Networking
*   **Transport**: **KEMTLS** (ML-KEM-768 + AEAD) for quantum-resistant validator-to-validator authenticated channels.
*   **Topology**: Full mesh (implied by `NetService` design).
*   **Discovery**: Static `PeerValidatorMap` provided at startup (no dynamic peer discovery yet).

### 4. Mempool & Proposer
*   **Mempool**: `InMemoryMempool` (T151).
    *   **Admission**: Verifies transaction signatures (ML-DSA-44) and checks capacity.
    *   **Ordering**: Strict FIFO based on insertion order.
    *   **Nonce Tracking**: Enforces per-sender nonce monotonicity and strictly limits "nonce gaps" to prevent spam/replay.
*   **Proposal Construction**: Leaders pull top candidates from the mempool up to `max_txs_per_block`.

### 5. Execution & State
*   **Transaction Format**: `QbindTransaction` (T150).
    *   Fields: `sender` (AccountId), `nonce` (u64), `payload` (bytes), `signature` (UserSignature).
    *   Verification: Domain-separated signing preimage (`QBIND:TX:v1`) + ML-DSA-44.
*   **Block Format**: `QbindBlock` wraps a consensus `BlockProposal` and contains decoded `QbindTransaction`s.
*   **Execution Engine**: `NonceExecutionEngine`.
    *   **State**: `InMemoryState` (Account -> Nonce mapping).
    *   **Semantics**: Only checks and increments nonces. Payloads are currently opaque/ignored (no VM yet).
*   **Async Execution Pipeline (T155)**: Block execution is now handled by an asynchronous worker thread.
    *   **`SingleThreadExecutionService`**: A dedicated worker thread that processes committed blocks in FIFO order.
    *   **Non-blocking Commit**: The consensus thread enqueues blocks via `submit_block()` instead of blocking on execution.
    *   **Bounded Queue**: Backpressure is applied via a bounded channel; `QueueFull` errors trigger fail-stop in DevNet.
    *   **Deterministic Order**: Blocks are executed in commit order across all validators.
    *   **Note**: Execution is still logically sequential (single worker thread). Parallel/DAG execution is a future enhancement.
*   **Commit Hook**: The harness uses `AsyncExecutionService` (T155) when configured, falling back to synchronous `ExecutionAdapter` (T150) for backward compatibility.

## DevNet-Specific Configuration

These are the default parameters for DevNet v0:

| Parameter | Value | Notes |
| :--- | :--- | :--- |
| **Validators** | 4-7 | Typical local cluster size (3f+1). |
| **Consensus Key** | ML-DSA-44 | Reference PQ signature scheme. |
| **Transport Key** | ML-KEM-768 | Reference PQ KEM. |
| **Block Time** | ~1s | Driven by pacemaker ticks. |
| **Max Txs/Block** | 1000 | Configurable in `NodeHotstuffHarness`. |
| **Mempool Size** | 10,000 | In-memory limit. |
| **State** | In-Memory | No disk persistence for execution state yet. |
| **Consensus Storage** | RocksDB (Optional) | Can persist blocks/QCs (T82), but disabled by default for ephemeral DevNets. |

## Security & Assumptions

*   **Closed Validator Set**: DevNet assumes a trusted, static set of validators.
*   **Partial Synchrony**: The protocol assumes partial synchrony for liveness (handled by TimeoutPacemaker).
*   **Safety**: Guaranteed by HotStuff 3-chain rule + ML-DSA-44 signatures.
*   **Hardware**: Intended for standard cloud VMs or local consumer hardware.

## Performance & Metrics (DevNet v0)

This section documents the observability infrastructure and performance measurement capabilities for DevNet v0 (T154).

### 1. Metrics Categories

The following metric families are exposed for observability:

#### Consensus Metrics
| Metric | Type | Description |
| :--- | :--- | :--- |
| `qbind_consensus_proposals_total{result}` | Counter | Proposals received (accepted/rejected) |
| `qbind_consensus_votes_total{result}` | Counter | Votes received (accepted/invalid) |
| `qbind_consensus_timeouts_total` | Counter | Timeout messages processed |
| `qbind_consensus_view_number` | Gauge | Current consensus view number |

#### Verification Pool Metrics (T147)
| Metric | Type | Description |
| :--- | :--- | :--- |
| `qbind_verify_jobs_submitted_total` | Counter | Jobs submitted to verification pool |
| `qbind_verify_jobs_dropped_total` | Counter | Jobs dropped due to queue overflow |
| `qbind_verify_jobs_ok_total` | Counter | Jobs verified successfully |
| `qbind_verify_jobs_failed_total` | Counter | Jobs that failed verification |

#### Mempool Metrics
| Metric | Type | Description |
| :--- | :--- | :--- |
| `qbind_mempool_txs_total` | Gauge | Current number of transactions in mempool |
| `qbind_mempool_inserted_total` | Counter | Transactions successfully inserted |
| `qbind_mempool_rejected_total{reason}` | Counter | Transactions rejected (full/invalid_signature/invalid_nonce/other) |
| `qbind_mempool_committed_total` | Counter | Transactions committed (removed from mempool) |

#### Execution Metrics
| Metric | Type | Description |
| :--- | :--- | :--- |
| `qbind_execution_txs_applied_total` | Counter | Transactions applied successfully |
| `qbind_execution_block_apply_seconds` | Histogram | Block application latency |
| `qbind_execution_errors_total{reason}` | Counter | Execution errors (nonce_mismatch/other) |
| `qbind_execution_queue_len` | Gauge | Current async execution queue length (T155) |
| `qbind_execution_queue_full_total` | Counter | Times submit_block failed due to full queue (T155) |
| `qbind_execution_worker_restarts_total` | Counter | Execution worker restarts (T155) |

#### Signer/Keystore Metrics
| Metric | Type | Description |
| :--- | :--- | :--- |
| `qbind_signer_sign_requests_total{kind}` | Counter | Signing requests (proposal/vote/timeout) |
| `qbind_signer_sign_failures_total` | Counter | Signing failures |
| `qbind_keystore_load_success_total{backend}` | Counter | Keystore loads (PlainFs/EncryptedFsV1) |
| `qbind_keystore_load_failure_total{backend}` | Counter | Keystore load failures |

**Security Note**: No secrets, key IDs, preimages, passphrases, or transaction contents are exposed in metrics. Only aggregate counts are tracked.

### 2. Metrics Export

Metrics are exposed via HTTP in Prometheus text format:

**Configuration**:
```bash
# Set environment variable to enable HTTP metrics endpoint
export QBIND_METRICS_HTTP_ADDR=127.0.0.1:9100
```

**Endpoints**:
*   `GET /metrics` - Returns all metrics in Prometheus text format

**Example**:
```bash
curl http://127.0.0.1:9100/metrics
```

### 3. DevNet TPS Harness

A performance benchmark harness is available for measuring DevNet throughput.

**Running the TPS Harness**:
```bash
# Run the canonical DevNet v0 benchmark scenario
cargo test -p qbind-node --test t154_devnet_tps_harness tps_benchmark_canonical -- --ignored --nocapture
```

**Canonical Benchmark Scenario (DevNet v0)**:

| Parameter | Value |
| :--- | :--- |
| Validators | 4 |
| Transactions | 10,000 |
| Payload Size | 128 bytes |
| Max Txs/Block | 1000 |
| Mempool Size | 10,000 |

**Benchmark Output**:
```
========== DevNet TPS Benchmark Results (T154) ==========
Total transactions:      10000
Committed transactions:  10000
Rejected transactions:   0
Duration:                X.XXX seconds
Throughput (TPS):        XXXX.XX
Avg mempool latency:     X.XXX ms
=========================================================
```

**Note**: Actual TPS figures depend on hardware. Operators should run the harness on their target hardware to obtain baseline measurements.

### 4. Performance Tracking

For tracking performance improvements over time:
*   Initial baseline established by T154
*   T155 introduced async execution pipeline (execution off consensus thread), a prerequisite for parallel execution
*   Future tasks may improve TPS via parallel execution (DAG mempool, multi-core execution)
*   See [DevNet Audit Log](./QBIND_DEVNET_AUDIT.md) for the current risk posture (R3, R6)

## Path to TestNet & MainNet

This section outlines how DevNet components evolve.

| Component | DevNet v0 | TestNet Goal | MainNet Goal |
| :--- | :--- | :--- | :--- |
| **Keys** | Local File / Loopback | HSM Basic Support | Full HSM / Threshold Sig |
| **Execution** | Nonce Only | Basic VM / Scripting | Full Smart Contract VM |
| **Mempool** | FIFO / In-Memory | Priority / QoS | DAG-based Mempool (Narwhal/Bullshark style) |
| **Storage** | Ephemeral / Basic RocksDB | Full State Persistence | Pruned/Archival Modes |
| **Networking** | Static Mesh | Dynamic P2P / Gossip | Public P2P + DDoS Protection |

### Future Work (Audit)
For tracking the evolution and readiness of these future networks, see:
*   [DevNet Audit Log](./QBIND_DEVNET_AUDIT.md)
*   [TestNet Audit Skeleton](../testnet/QBIND_TESTNET_AUDIT_SKELETON.md)
*   [MainNet Audit Skeleton](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md)