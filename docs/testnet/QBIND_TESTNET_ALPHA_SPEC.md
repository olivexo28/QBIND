# QBIND TestNet Alpha Specification

**Task**: T163 (Minimal VM v0), T164 (State Persistence)  
**Status**: Ready  
**Date**: 2026-01-28

---

## 1. Scope

TestNet Alpha is the first public test network for QBIND. It extends the DevNet v0 architecture with:

- **Network Environment**: `NetworkEnvironment::Testnet` (`QBIND_TESTNET_CHAIN_ID`)
- **Execution Profile**: `ExecutionProfile::VmV0` (sequential VM execution with account balances)
- **State Persistence**: RocksDB-backed persistent account state (T164)
- **Consensus**: Same as DevNet (HotStuff BFT, 3-chain commit rule)
- **Networking**: Same as DevNet (static KEMTLS mesh)
- **Mempool**: Same as DevNet (FIFO mempool, DAG v0 opt-in)

### What Changes from DevNet

| Component | DevNet v0 | TestNet Alpha |
| :--- | :--- | :--- |
| **Execution Profile** | `NonceOnly` | `VmV0` |
| **Account State** | Nonce only | Nonce + Balance |
| **Transaction Semantics** | Nonce validation only | Balance transfers |
| **Parallelism** | Stage A (sender-partitioned) | Sequential (for now) |
| **State Persistence** | In-memory only | RocksDB-backed disk persistence |

### What Remains the Same

- Consensus rules (HotStuff, timeouts, view-change)
- Cryptography (ML-DSA-44, ML-KEM-768, KEMTLS)
- Domain-separated signing preimages
- Static mesh networking
- Keystore and signer abstractions

---

## 2. VM v0 Semantics

### 2.1 Account State Model

Each account has:

```rust
pub struct AccountState {
    pub nonce: u64,    // Transaction replay protection
    pub balance: u128, // Account balance
}
```

- **Default**: Absent accounts have `nonce = 0`, `balance = 0`.
- **Persistence**: RocksDB-backed disk storage (T164). See §4.4 for details.

### 2.2 Transfer Transaction Format

VM v0 supports a single transaction type: **transfer**.

The transaction payload encodes:

```rust
pub struct TransferPayload {
    pub recipient: AccountId, // [u8; 32]
    pub amount: u128,         // big-endian
}
```

**Wire Format** (48 bytes):
```
Bytes 0..32:  recipient (AccountId)
Bytes 32..48: amount (u128, big-endian)
```

### 2.3 Transaction Execution Semantics

For each `QbindTransaction` in block order:

1. **Decode Payload**
   - Parse payload as `TransferPayload`.
   - If malformed → `MalformedPayload` error, no state change.

2. **Fetch Sender State**
   - Retrieve `AccountState` for `tx.sender`.
   - Default: `nonce = 0`, `balance = 0` if absent.

3. **Check Nonce**
   - Require `tx.nonce == sender_state.nonce`.
   - If mismatch → `NonceMismatch { expected, got }` error, no state change.

4. **Check Balance**
   - Require `sender_state.balance >= transfer.amount`.
   - If insufficient → `InsufficientBalance { balance, needed }` error, no state change.

5. **Apply State Transition** (if all checks pass)
   - `sender.balance -= amount`
   - `sender.nonce += 1`
   - `recipient.balance += amount` (create recipient if absent, `nonce = 0`)

### 2.4 Error Types

```rust
pub enum VmV0Error {
    NonceMismatch { expected: u64, got: u64 },
    InsufficientBalance { balance: u128, needed: u128 },
    MalformedPayload,
}
```

### 2.5 Determinism

- Transactions are executed **sequentially** in block order.
- All state transitions are deterministic.
- All validators executing the same block produce the same final state.

---

## 3. Execution Profile Abstraction

### 3.1 ExecutionProfile Enum

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ExecutionProfile {
    #[default]
    NonceOnly,  // DevNet default
    VmV0,       // TestNet Alpha
}
```

### 3.2 Profile Selection

| Environment | Recommended Profile | Behavior |
| :--- | :--- | :--- |
| DevNet | `NonceOnly` | Stage A parallel nonce execution |
| TestNet Alpha | `VmV0` | Sequential VM v0 execution |

### 3.3 CLI Arguments

```bash
# DevNet (implicit default)
qbind-node --env devnet

# TestNet Alpha with VM v0
qbind-node --env testnet --execution-profile vm-v0
```

---

## 4. Implementation Notes

### 4.1 SingleThreadExecutionService

The `SingleThreadExecutionService` selects behavior based on `ExecutionProfile`:

- **NonceOnly**: Uses `SenderPartitionedNonceExecutor` (Stage A parallelism).
- **VmV0**: Uses `VmV0ExecutionEngine` (sequential execution).

### 4.2 State Backends

VM v0 state can use either backend:

- `InMemoryAccountState`: In-memory only (for testing or when no `data_dir` is configured)
- `RocksDbAccountState`: Persistent disk storage (T164)

Production nodes should use persistent storage via the `CachedPersistentAccountState` wrapper, which provides:

- In-memory caching for fast reads during execution
- Write-through to RocksDB for durability
- Flush-at-block-boundary for crash safety

### 4.3 Parallelism

VM v0 execution is **sequential** for simplicity and safety.

Stage B parallelism (conflict-graph-based) is future work, requiring:
- Read/write set tracking per transaction
- Conflict detection and scheduling
- Deterministic parallel execution

### 4.4 State Persistence (T164)

TestNet Alpha uses RocksDB-backed persistent storage for VM v0 state.

#### Storage Layout

```
<data_dir>/
└── state_vm_v0/        # RocksDB database directory
    ├── 000001.sst     # SST files
    ├── CURRENT
    ├── MANIFEST-*
    └── ...
```

#### Key Format

Account states are stored with keys of the form:

```
"acct:" || account_id (32 bytes)
```

#### Value Format

Account states use a fixed 24-byte binary encoding:

```
nonce:   u64  (8 bytes, big-endian)
balance: u128 (16 bytes, big-endian)
```

#### Durability Guarantees

- State is flushed to disk after each committed block
- Node restart loads persisted state automatically
- All validators converge to the same state after replaying committed blocks

#### Configuration

```rust
// Configure persistent storage via NodeConfig
let config = NodeConfig::testnet_vm_v0()
    .with_data_dir("/data/qbind");

// The VM v0 state directory is: /data/qbind/state_vm_v0
let state_dir = config.vm_v0_state_dir();
```

#### Limitations

- No pruning or compaction yet (state grows monotonically)
- No snapshotting or checkpointing
- Single-node restart only; no cross-node state sync in this version

---

## 5. Testing

### 5.1 Unit Tests

Located in `qbind-ledger/tests/t163_vm_v0_tests.rs`:

- `test_happy_path_simple_transfer`
- `test_nonce_mismatch_rejected`
- `test_insufficient_balance_rejected`
- `test_recipient_creation`
- `test_malformed_payload_error`
- Additional tests for edge cases

### 5.2 Integration Tests

Located in `qbind-node/tests/t163_vm_v0_integration_tests.rs`:

- `test_service_vm_v0_profile`
- `test_service_vm_v0_multiple_blocks`
- `test_service_nonce_only_profile` (DevNet regression)

### 5.3 Persistence Tests (T164)

Located in `qbind-ledger/tests/t164_vm_persistence_tests.rs`:

- `basic_put_get_roundtrip`
- `default_state_for_missing_account`
- `persist_across_reopen`
- `account_state_serialization_roundtrip`
- `cached_state_basic`
- `cached_state_write_through`

Located in `qbind-node/tests/t164_vm_v0_persistence_integration_tests.rs`:

- `test_vm_v0_engine_with_persistent_state`
- `test_vm_v0_state_survives_restart`
- `test_vm_v0_execute_block_persistent`
- `test_vm_v0_multiple_blocks_persistent`

---

## 5.5 DAG Availability Tests (T165)

Located in `qbind-node/tests/t165_dag_availability_tests.rs`:

- `test_batch_ack_signing_preimage_starts_with_domain_tag`
- `test_batch_ack_cross_chain_preimages_differ`
- `test_acks_accumulate_to_quorum_form_cert`
- `test_duplicate_acks_ignored`
- `test_cross_chain_ack_preimage_rejection`
- `test_dag_mempool_metrics_ack_tracking`

Located in `qbind-node/tests/t165_dag_availability_integration_tests.rs`:

- `test_single_node_local_acks_cert`
- `test_multi_node_partial_ack_delivery`
- `test_dag_availability_config_integration`
- `test_t165_metrics_integration`

---

## 5.6 DAG Availability (T165)

TestNet Alpha introduces DAG availability certificates as an opt-in feature:

### Overview

When DAG mempool is enabled with availability certificates:

1. **Validators issue BatchAcks**: When a validator stores a batch (local or remote), it creates and broadcasts a `BatchAck` message signed with ML-DSA-44.

2. **Batches form certificates**: When a batch receives acknowledgments from ≥2f+1 validators, a `BatchCertificate` is formed, proving data availability.

3. **Certificates are data-plane artifacts**: In T165 v1, certificates do not change HotStuff consensus rules. They provide observability and prepare for future consensus integration.

### Configuration

```rust
// Enable DAG availability for TestNet Alpha
let dag_config = DagAvailabilityConfig::enabled();
let quorum_size = dag_config.compute_quorum_size(num_validators);
let mempool = InMemoryDagMempool::with_availability(config, quorum_size);
```

### Message Format

**BatchAck**:
```rust
pub struct BatchAck {
    pub batch_ref: BatchRef,      // (creator, batch_id)
    pub validator_id: ValidatorId,
    pub view_hint: u64,
    pub suite_id: u16,            // 100 for ML-DSA-44
    pub signature: Vec<u8>,
}
```

**Signing Preimage**:
```
QBIND:TST:BATCH_ACK:v1  (for TestNet Alpha)
<batch_ref.creator>     (8 bytes LE)
<batch_ref.batch_id>    (32 bytes)
<validator_id>          (8 bytes LE)
<view_hint>             (8 bytes LE)
```

### Metrics

| Metric | Description |
| :--- | :--- |
| `qbind_dag_batch_acks_total{result="accepted"}` | Accepted batch acks |
| `qbind_dag_batch_acks_total{result="rejected"}` | Rejected batch acks |
| `qbind_dag_batch_certs_total` | Certificates formed |
| `qbind_dag_batch_acks_invalid_total{reason}` | Invalid acks by reason |

### Limitations (v1)

- **No fetch-on-miss**: Acks for unknown batches are ignored (metrics tracked).
- **No signature aggregation**: Certificates store signer list, not aggregated signatures.
- **Data-plane only**: HotStuff consensus rules unchanged.

### Future Enhancements

TestNet Beta / MainNet may add:
- Batch fetch protocol for missing batches
- Consensus rule: require cert before commit
- PQ-safe aggregate signatures

| Work Item | Description | Target | Status |
| :--- | :--- | :--- | :--- |
| **State Persistence** | Disk-backed account state (RocksDB) | TestNet Alpha | ✅ Done (T164) |
| **DAG Availability Certs** | BatchAck + BatchCertificate v1 | TestNet Alpha | ✅ Done (T165) |
| **Cluster Harness** | Multi-node TestNet Alpha harness | TestNet Alpha | ✅ Done (T166) |
| **Gas & Fee Model Design** | Resource accounting and fee specification | TestNet Alpha | ✅ Done (T167 – Design) |
| **Stage B Parallelism** | Conflict-graph-based VM parallelism | TestNet Beta | Planned |
| **Gas Accounting** | Transaction fees and gas limits (implementation) | TestNet Beta | Planned |
| **Smart Contracts** | Full EVM or custom VM support | MainNet | Planned |

---

## 6. Cluster Harness & Soak Testing (T166)

TestNet Alpha includes a multi-node cluster harness for end-to-end verification of the full stack.

### Overview

The `t166_testnet_alpha_cluster_harness` test file provides:

- **TestnetAlphaClusterHandle**: A cluster management handle that:
  - Boots a 4-node (or N-node) TestNet Alpha cluster
  - Configures VM v0 execution with persistent RocksDB state
  - Optionally enables DAG mempool + DAG availability certificates
  - Provides transaction submission, state inspection, and metrics collection

- **TPS Measurement**: A helper function `run_testnet_alpha_tps_scenario()` that:
  - Pre-funds sender accounts
  - Submits transfers as fast as possible
  - Measures time to commit and computes TPS
  - Verifies final balance consistency

### Configuration

```rust
pub struct TestnetAlphaClusterConfig {
    pub num_validators: usize,          // Default: 4
    pub use_dag_mempool: bool,          // Default: false
    pub enable_dag_availability: bool,  // Default: false
    pub initial_balance: u128,          // Default: 10_000_000
    pub txs_per_sender: u64,            // Default: 10
    pub num_senders: usize,             // Default: 10
}
```

### Running the Tests

**CI-friendly smoke test (FIFO mempool + VM v0):**
```bash
cargo test -p qbind-node --test t166_testnet_alpha_cluster_harness \
  test_testnet_alpha_cluster_vm_v0_fifo_smoke
```

**VM v0 restart consistency test:**
```bash
cargo test -p qbind-node --test t166_testnet_alpha_cluster_harness \
  test_testnet_alpha_cluster_vm_v0_fifo_restart_consistency
```

**DAG availability smoke test (ignored by default):**
```bash
cargo test -p qbind-node --test t166_testnet_alpha_cluster_harness \
  test_testnet_alpha_cluster_dag_availability_smoke -- --ignored --nocapture
```

**TPS measurement scenario:**
```bash
cargo test -p qbind-node --test t166_testnet_alpha_cluster_harness \
  test_testnet_alpha_tps_scenario_minimal
```

### Tests Included

| Test | Description |
| :--- | :--- |
| `test_testnet_alpha_cluster_vm_v0_fifo_smoke` | Start cluster, run transfers, verify state consistency |
| `test_testnet_alpha_cluster_vm_v0_fifo_restart_consistency` | Verify state persists across restart |
| `test_testnet_alpha_cluster_dag_availability_smoke` | DAG + availability certs (ignored) |
| `test_testnet_alpha_cluster_dag_metrics_integration` | Verify DAG metrics (ignored) |
| `test_testnet_alpha_tps_scenario_minimal` | CI-friendly TPS measurement |
| `test_testnet_alpha_tps_scenario_heavy` | Heavy soak test (ignored) |

### Purpose

This harness is the **canonical entry point** to validate the full TestNet Alpha stack:

1. **VM v0 Execution**: Verifies that transfer transactions work correctly with account balances
2. **State Persistence**: Confirms RocksDB-backed state survives restarts
3. **DAG Availability**: Tests BatchAck/BatchCertificate formation in a multi-node setting
4. **TPS Measurement**: Provides baseline performance numbers for TestNet Alpha

---

## 7. Execution Economics & Gas (T167 – Design)

TestNet Alpha currently operates **without enforced gas or fee accounting**. All transfer transactions are processed without cost, and there is no resource metering.

### 7.1 Current State

| Aspect | TestNet Alpha Status |
| :--- | :--- |
| **Gas Metering** | Not enforced |
| **Transaction Fees** | None (all transfers are free) |
| **Block Gas Limit** | Not enforced |
| **Fee-Based Priority** | Not implemented (FIFO ordering) |

### 7.2 T167 Gas & Fee Model Design

Task T167 defines the gas and fee model for future implementation in TestNet Beta and MainNet:

- **Gas Cost Model**: Abstract gas units for measuring resource consumption (signature verification, state access, payload size).
- **VM v1 Transaction Format**: `TransferPayloadV1` with explicit `gas_limit` and `max_fee_per_gas` fields.
- **Per-Transaction and Per-Block Limits**: Gas limits to cap resource usage and prevent DoS.
- **Mempool Integration**: Admission policies based on gas validity and fee priority.
- **Fee Distribution**: Burn policy for TestNet, hybrid (burn + proposer reward) for MainNet.
- **DAG Integration**: Gas constraints enforced at block construction from DAG batches.

### 7.3 T168 Implementation Status

> **T168 adds config-gated gas enforcement for VM v0:**
>
> - When `ExecutionGasConfig.enabled = true`:
>   - Per-transaction gas limits are enforced (`GasLimitExceeded` error if exceeded)
>   - Per-block gas limit is enforced (`BLOCK_GAS_LIMIT_DEFAULT = 30,000,000`)
>   - Fees are computed as `gas_cost * max_fee_per_gas` and deducted from sender
>   - Fees are **burned** in TestNet (not credited to proposer)
>   - Mempool admission checks gas legality and balance sufficiency
>
> - When `ExecutionGasConfig.enabled = false` (default):
>   - Behavior is exactly as before T168 (no gas, no fees)
>   - This is the default for public TestNet Alpha
>
> **Transaction Payload Formats**:
> - `TransferPayload` (v0, 48 bytes): recipient + amount only; derives `gas_limit` = 50k, `max_fee_per_gas` = 0
> - `TransferPayloadV1` (v1, 72 bytes): recipient + amount + gas_limit + max_fee_per_gas
>
> **Configuration Example**:
> ```rust
> // Enable gas enforcement (for TestNet Beta / MainNet)
> let gas_config = ExecutionGasConfig::enabled();
> let engine = VmV0ExecutionEngine::with_gas_config(gas_config);
> 
> // Mempool with gas admission checks
> let mut mempool_config = MempoolConfig::default();
> mempool_config.gas_config = Some(ExecutionGasConfig::enabled());
> let mempool = InMemoryMempool::with_config(mempool_config);
> ```
>
> **Note**: Default public TestNet Alpha remains gas-disabled until TestNet Beta.

### 7.4 T169 Fee-aware Mempool Priority & Eviction

> **T169 adds optional fee-based priority and eviction to mempools:**
>
> - When `enable_fee_priority = true` (config-gated):
>   - FIFO mempool becomes a priority queue ordered by (`fee_per_gas`, `effective_fee`, `arrival_id`)
>   - When mempool is full, lowest-priority transactions are evicted to make room for higher-fee txs
>   - DAG mempool batch construction and frontier selection prioritize high-fee transactions
>   - Block proposals preferentially include transactions with higher fees
>
> - When `enable_fee_priority = false` (default):
>   - Existing FIFO (or DAG insertion-order) behavior is preserved
>
> **Configuration Coupling**:
> - Fee priority requires gas enforcement (`ExecutionGasConfig.enabled = true`)
> - If gas is disabled, `enable_fee_priority` is automatically forced to `false`
> - Default public TestNet Alpha remains FIFO-only; fee-priority is for TestNet Beta experimentation
>
> **Example**:
> ```rust
> // Enable fee-based priority (requires gas enabled)
> let mut mempool_config = MempoolConfig::default();
> mempool_config.gas_config = Some(ExecutionGasConfig::enabled());
> mempool_config.enable_fee_priority = true;
> let mempool = InMemoryMempool::with_config(mempool_config.enforce_constraints());
> ```
>
> **Metrics**:
> - `qbind_mempool_evicted_low_priority_total`: Count of evicted low-priority txs
> - `qbind_mempool_priority_enabled`: Gauge (0/1) indicating if priority is enabled
>
> **Note**: T169 implements the minimal fee market infrastructure; sophisticated MEV strategies are not in scope.

### 7.5 Migration Path

1. **TestNet Alpha**: No gas enforcement; `TransferPayload` (v0) format.
2. **TestNet Beta**: Gas enforcement enabled; both v0 and v1 payloads accepted with deprecation timeline.
3. **MainNet**: Full gas and fee enforcement; v1 format required.

**Reference**: [QBIND Gas and Fee Model Design](./QBIND_GAS_AND_FEES_DESIGN.md) for complete specification.

---

## 8. Networking / P2P (T170)

TestNet Alpha continues to use the **static KEMTLS mesh** networking model from DevNet v0.

### 8.1 Current State

| Aspect | TestNet Alpha Status |
| :--- | :--- |
| **Topology** | Static mesh (fully-connected validators) |
| **Transport** | KEMTLS (ML-KEM-768 + AEAD) |
| **Peer Discovery** | None (config-driven static peers) |
| **Gossip** | None (direct broadcast) |
| **Multi-Region** | Not supported |

### 8.2 P2P Design Reference

The comprehensive P2P networking design for QBIND is documented in:

- **[QBIND P2P Network Design](../network/QBIND_P2P_NETWORK_DESIGN.md)** (T170)

This document specifies:

- Node roles and identities (`NodeId`, key separation)
- Overlay topology evolution (DevNet → TestNet → MainNet)
- Protocol layering (transport, multiplexing, application frames)
- Threat model and mitigations (Sybil, eclipse, DoS)
- Phased rollout plan

### 8.3 Evolution Path

| Phase | P2P Capabilities |
| :--- | :--- |
| **TestNet Alpha** | Static mesh, config-driven peers, local harness |
| **TestNet Beta** | Basic peer discovery, gossip for DAG batches, multi-machine |
| **MainNet** | Full P2P with DoS protection, multi-region support |

**Note (T172)**: T172 introduces a minimal P2P transport v1 behind `enable_p2p` flag:
- PQC KEMTLS transport (`TcpKemTlsP2pService`)
- Static peer connections via `NetworkTransportConfig.static_peers`
- Basic P2pService interface (broadcast, send_to, subscribe)
- Simple framing (u8 discriminator + u32 length + payload)
- Metrics for connections, bytes, and message counts

TestNet Alpha remains default-off for P2P; `enable_p2p = false` is the default. P2P v1 is intended for experimental multi-process deployments and is not yet wired into production consensus/DAG paths.

---

## Appendix A: Related Documents

- [QBIND Gas and Fee Model Design](./QBIND_GAS_AND_FEES_DESIGN.md) — Gas and fee specification (T167)
- [QBIND DevNet v0 Freeze](../devnet/QBIND_DEVNET_V0_FREEZE.md) — DevNet v0 specification and freeze
- [QBIND Parallel Execution Design](../devnet/QBIND_PARALLEL_EXECUTION_DESIGN.md) — Stage A/B parallelism
- [QBIND Chain ID and Domains](../devnet/QBIND_CHAIN_ID_AND_DOMAINS.md) — Domain separation
- [QBIND P2P Network Design](../network/QBIND_P2P_NETWORK_DESIGN.md) — P2P networking architecture (T170)

---

*End of Document*