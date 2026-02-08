# QBIND Parallel Execution Design Specification

**Task**: T156  
**Status**: Design Document (DevNet-ready)  
**Author**: QBIND Engineering  
**Date**: 2026-01-27

---

## Table of Contents
1. [Objectives & Constraints](#1-objectives--constraints)
2. [Current Execution Model](#2-current-execution-model-t150--t155-recap)
3. [Parallelism Opportunities & Risk Analysis](#3-parallelism-opportunities--risk-analysis)
4. [Proposed Parallel Execution Model](#4-proposed-parallel-execution-model-stages)
5. [Interfaces & Changes Needed](#5-interfaces--changes-needed)

---

## 1. Objectives & Constraints

### 1.1 Objectives

The primary goals for introducing parallel execution in QBIND are:

| Objective | Description |
| :--- | :--- |
| **Multi-core Utilization** | Exploit modern multi-core hardware on validator nodes to increase transaction throughput beyond what a single-threaded execution model can achieve. |
| **Determinism** | Preserve strict determinism: all validators must arrive at the same state root regardless of scheduling order or hardware differences. |
| **Safety** | Maintain correctness guarantees—no execution reordering that could break nonce rules, causality, or future VM semantics. |
| **Extensibility** | Design the parallel execution model to support the current nonce-only engine while being extensible to a full VM with richer state access patterns. |

### 1.2 Constraints

The following constraints apply to any parallel execution design for QBIND:

| Constraint | Rationale |
| :--- | :--- |
| **No Classical Crypto** | All cryptographic assumptions remain post-quantum (PQ) only. Any new signing, hashing, or verification must use ML-DSA-44, ML-KEM-768, or QBIND-approved PQ primitives. |
| **Consensus Order is Fixed** | The total order of blocks is determined by HotStuff consensus. Parallelism is *within* a committed block or *across* independent blocks (pipelining), never reordering committed history. |
| **Adversarial Tolerance** | Execution must tolerate adversarial workloads—attackers can craft transactions to maximize conflicts, forcing serialization as a worst case. |
| **Backward Compatibility** | The new parallel engine must be able to fall back to sequential execution for debugging, compatibility testing, or edge cases. |
| **Metrics & Observability** | All parallelism must be observable via metrics (parallel factor, conflict rate, latency breakdown). |

---

## 2. Current Execution Model (T150 + T155 Recap)

This section summarizes the execution model as of T155, focusing on the implications for parallelism.

### 2.1 Transaction & Execution Engine

**QbindTransaction (T150)**:
- Fields: `sender` (AccountId), `nonce` (u64), `payload` (bytes), `signature` (UserSignature).
- Verification: Domain-separated signing preimage (`QBIND:TX:v1`) + ML-DSA-44.

**NonceExecutionEngine**:
- **State Model**: `InMemoryState` maintains a simple mapping `Account → Nonce`.
- **Execution Semantics**: For each transaction, the engine:
  1. Reads the sender's current nonce from state.
  2. Verifies `tx.nonce == current_nonce`.
  3. Increments the nonce: `state[sender] = current_nonce + 1`.
  4. Returns success/failure receipt.
- **Key Observation**: Each transaction touches *only* the `nonce::<sender>` key. There are no cross-account dependencies in the current model.

### 2.2 Async Execution Pipeline (T155)

**SingleThreadExecutionService**:
- A dedicated worker thread processes committed blocks in FIFO order.
- The consensus thread enqueues blocks via `submit_block()` without blocking.
- Blocks are executed in strict commit order (deterministic across validators).
- Within each block, transactions are executed **sequentially in list order**.

**Implications for Parallelism**:
- The execution worker is decoupled from consensus, removing the "R3" risk of blocking the consensus loop.
- However, execution is still **logically sequential**—no multi-core speedup is achieved within block execution.
- This provides a clean baseline: parallel execution can be introduced *inside* the worker thread's block processing loop.

### 2.3 Baseline Summary

| Aspect | Current State | Implication |
| :--- | :--- | :--- |
| **Threading** | Single worker thread | Easy to reason about; serialization point for parallelism. |
| **State Access** | Per-account nonce only | Transactions from different accounts are independent (commute). |
| **Determinism** | List-order execution | Any parallel scheme must preserve this semantic equivalence. |
| **Extensibility** | Nonce-only for now | Future VM will have richer state; design must anticipate conflicts. |

---

## 3. Parallelism Opportunities & Risk Analysis

### 3.1 Per-Account Independence (DevNet Nonce Engine)

**Key Insight**: In the current nonce-only model, transactions from different senders *commute*:
- Transaction A from sender `Alice` modifies `nonce::Alice`.
- Transaction B from sender `Bob` modifies `nonce::Bob`.
- The final state is the same regardless of which transaction executes first.

**Constraint**: Transactions from the *same* sender must preserve their relative order (nonce monotonicity):
- If `tx_1.nonce = 5` and `tx_2.nonce = 6` for sender `Alice`, then `tx_1` must execute before `tx_2`.

**Risk**: Low. This is the safest domain to introduce parallelism because:
- No shared state between senders.
- Per-sender ordering is easy to enforce by partitioning.

### 3.2 Future VM / Richer State

When QBIND introduces a full VM (e.g., EVM-style smart contracts), transactions may:
- Read/write shared storage keys.
- Call the same contract, creating conflicts.

**Approaches to handle conflicts**:

| Approach | Description | Trade-offs |
| :--- | :--- | :--- |
| **Static Conflict Analysis** | Pre-execute or statically analyze each tx to determine its read/write set. Schedule non-conflicting txs in parallel. | Requires access list or pre-execution; may be imprecise. |
| **Runtime Conflict Detection (STM)** | Use software transactional memory. Execute optimistically; detect conflicts and re-execute if necessary. | Higher complexity; potential rollback overhead. |
| **Explicit Access Lists** | Require transactions to declare keys they will touch. | Places burden on users/wallets; may limit expressiveness. |

**Risk**: Medium-High. Naive parallelism breaks determinism when transactions conflict.

### 3.3 Adversarial Workloads

An attacker can craft transactions to maximize conflicts:
- All transactions call the same contract.
- All transactions modify the same storage slot.

In the worst case, the system degrades to sequential execution—this is acceptable for safety, but TPS suffers.

**Mitigations**:
- Gas/fee mechanisms to discourage conflict-heavy workloads.
- Block builders may order transactions to minimize conflicts.
- DAG mempool can group transactions by access patterns (see `QBIND_DAG_MEMPOOL_DESIGN.md`).

### 3.4 Summary & Direction

| Parallelism Domain | Risk | Plan |
| :--- | :--- | :--- |
| **Per-account independence (nonce engine)** | Low | **Stage A**: Implement for DevNet/TestNet. |
| **Generalized VM parallelism** | Medium | **Stage B**: Implement for MainNet with conflict detection. |
| **Adversarial workloads** | Accepted | Degrade gracefully to sequential; incentivize good behavior via fees. |

**Conclusion**: Initial parallelism (Stage A) will target the current nonce-only engine. The design will be structured so that Stage B (full VM parallelism) can extend it without breaking backward compatibility.

---

## 4. Proposed Parallel Execution Model (Stages)

### 4.1 Stage A – Per-Block, Sender-Partitioned Parallel Execution (DevNet/TestNet)

**Target**: Current nonce-only execution engine.  
**Goal**: Multi-core speedup for blocks with transactions from many distinct senders.

#### 4.1.1 Algorithm Overview

For a committed block `B` containing `Vec<QbindTransaction>`:

1. **Partition by Sender**:
   - Group transactions by `tx.sender`.
   - Result: `HashMap<AccountId, Vec<QbindTransaction>>` where each `Vec` preserves original block order for that sender.

2. **Parallel Execution**:
   - Spawn one task per sender (or use a thread pool with work-stealing).
   - Each task processes its sender's transactions sequentially, maintaining a local nonce.
   - Tasks run concurrently; there is no cross-task communication during execution.

3. **Result Collection**:
   - Each task produces a `Vec<TxReceipt>` for its sender's transactions.
   - Collect all receipts.

4. **State Merge**:
   - Merge per-sender nonce updates into the global `InMemoryState`.
   - Since accounts are independent, merge order does not affect final state.

5. **Receipt Ordering**:
   - Re-order receipts to match the original transaction order in the block (for deterministic receipt root).

#### 4.1.2 Determinism Guarantee

**Theorem**: For the nonce-only engine, any schedule that:
- Preserves per-sender order, and
- Applies all transactions in the block

yields the same final state and the same set of receipts (though receipt computation order may vary).

**Proof Sketch**:
- Each sender's nonce is an independent counter.
- No transaction reads another sender's nonce.
- Therefore, interleaving transactions from different senders has no observable effect on final state.

The receipt list must be sorted to match block order for a deterministic `receipts_root`.

#### 4.1.3 Thread Pool Configuration

| Parameter | Recommended Value | Rationale |
| :--- | :--- | :--- |
| **Worker Threads** | `num_cpus::get()` or configurable | Match available cores. |
| **Queue Depth** | Bounded (e.g., 2× workers) | Prevent unbounded memory growth. |
| **Fallback** | Single-thread sequential | For debugging or low-tx blocks. |

#### 4.1.4 Example Execution Flow

```
Block B: [tx1(Alice), tx2(Bob), tx3(Alice), tx4(Charlie), tx5(Bob)]

Partition:
  Alice:   [tx1, tx3]
  Bob:     [tx2, tx5]
  Charlie: [tx4]

Parallel Execution:
  Worker 1: Alice   → tx1 ✓ → tx3 ✓
  Worker 2: Bob     → tx2 ✓ → tx5 ✓
  Worker 3: Charlie → tx4 ✓

Merge Nonces:
  state[Alice]   = initial + 2
  state[Bob]     = initial + 2
  state[Charlie] = initial + 1

Receipts (sorted by original order): [r1, r2, r3, r4, r5]
```

---

### 4.2 Stage B – Generalized Parallelism for Full VM (MainNet)

**Target**: Future EVM or custom VM with rich state access.  
**Goal**: Maximize parallelism while preserving determinism in the presence of conflicts.

#### 4.2.1 Read/Write Set Model

Each transaction's execution produces:
- **Read Set**: Keys read during execution.
- **Write Set**: Keys written during execution.

Two transactions conflict if:
- `tx_i.write_set ∩ tx_j.read_set ≠ ∅`, or
- `tx_i.write_set ∩ tx_j.write_set ≠ ∅`

#### 4.2.2 Scheduling Strategy

**Conflict Graph Construction**:
- Nodes: Transactions in the block.
- Edges: Directed edge `tx_i → tx_j` if `tx_i` appears before `tx_j` in block order and they conflict.

**Topological Layering**:
- Transactions with no incoming edges form the first layer (can execute in parallel).
- After layer completes, remove edges and compute next layer.
- Repeat until all transactions are executed.

**Fallback**: If all transactions conflict, the system degrades to sequential execution (layer size = 1).

#### 4.2.3 Implementation Approaches

| Approach | Description | Complexity |
| :--- | :--- | :--- |
| **Pre-execution Analysis** | Dry-run transactions to discover read/write sets, then schedule. | Two passes per block; may have false positives. |
| **Access Lists (EIP-2930 style)** | Transactions declare their access list upfront. | Simpler scheduling; requires wallet support. |
| **Speculative Execution (STM)** | Execute optimistically; detect conflicts via versioned state; re-execute on conflict. | Single pass but complex; rollback overhead. |

**Recommended**: Start with access-list-based scheduling for predictability, with optional speculative execution for contracts that don't declare lists.

#### 4.2.4 Determinism in Stage B

The conflict graph and layer assignment are deterministic given:
- The block's transaction list (fixed by consensus).
- The read/write sets (either declared or computed deterministically).

All validators compute the same layers and execute in the same logical order, producing identical state.

---

### 4.3 Stage C – Block-Level Pipelining (Extension)

**Concept**: Overlap execution of consecutive blocks.

**Scenario**:
- Block `N` is being executed.
- Block `N+1` is committed by consensus.
- Begin execution of `N+1` transactions that are provably independent of `N`'s pending writes.

**Requirements**:
- State must support concurrent reads across block boundaries.
- Dependency analysis between blocks (or conservative barrier).

**Risk**: High complexity. Recommended as a future optimization after Stage A and B are stable.

**DevNet/TestNet**: Not implemented; blocks execute fully before the next begins.  
**MainNet**: Evaluate based on observed bottlenecks.

---

### 4.4 Stage Summary

| Stage | Scope | Target Network | Complexity | Expected Speedup |
| :--- | :--- | :--- | :--- | :--- |
| **A** | Sender-partitioned parallel execution | DevNet / TestNet | Low | Linear in # distinct senders |
| **B** | Conflict-graph-based VM parallelism | MainNet | Medium-High | Workload-dependent |
| **C** | Block-level pipelining | MainNet (optional) | High | Marginal (hides latency) |

---

## 5. Interfaces & Changes Needed

This section specifies the interfaces and abstractions that must evolve to support parallel execution. No code is provided—this is a design-level specification for future implementation tasks.

### 5.1 Execution Engine Abstraction

**Current**: `ExecutionEngine` trait with `apply_transaction()`.

**Proposed New Abstraction**:

```
trait ParallelExecutionEngine {
    /// Execute a block with parallel scheduling.
    /// Returns receipts in block order.
    fn execute_block_parallel(
        &self,
        block: &QbindBlock,
        state: &mut dyn ExecutionState,
        config: ParallelExecConfig,
    ) -> Result<Vec<TxReceipt>, ExecutionError>;
}

struct ParallelExecConfig {
    /// Max worker threads (0 = auto-detect).
    max_workers: usize,
    /// Strategy for Stage B (when VM is available).
    conflict_strategy: ConflictStrategy,
    /// Enable metrics collection.
    collect_metrics: bool,
}

enum ConflictStrategy {
    /// Stage A: partition by sender only.
    SenderPartition,
    /// Stage B: build conflict graph from access lists.
    AccessListGraph,
    /// Stage B: speculative execution with STM.
    Speculative,
}
```

### 5.2 Execution Scheduler

A new component responsible for:
1. Partitioning transactions (Stage A) or building conflict graph (Stage B).
2. Dispatching work to a thread pool.
3. Collecting results and merging state.

```
trait ExecutionScheduler {
    /// Partition or analyze transactions for parallel execution.
    fn prepare(&self, txs: &[QbindTransaction]) -> ExecutionPlan;
    
    /// Execute the plan on the provided state.
    fn execute(&self, plan: ExecutionPlan, state: &mut dyn ExecutionState) -> Vec<TxReceipt>;
}

enum ExecutionPlan {
    /// Stage A: groups keyed by sender.
    SenderPartitioned(HashMap<AccountId, Vec<QbindTransaction>>),
    /// Stage B: layers of independent tx sets.
    ConflictLayers(Vec<Vec<QbindTransaction>>),
}
```

### 5.3 State Representation

**Current**: `InMemoryState` with `HashMap<AccountId, u64>`.

**Future Requirements**:

| Requirement | Rationale |
| :--- | :--- |
| **Concurrent Read Access** | Multiple workers may read state in parallel during Stage A/B. |
| **Sharded or Partitioned State** | For Stage A, per-sender state could be isolated to avoid locking. |
| **Versioned State (Stage B)** | For STM-style execution, state must support optimistic versioning and conflict detection. |
| **Snapshotting** | For speculative execution, ability to create cheap snapshots and rollback. |

**Proposed Interface Extension**:

```
trait ExecutionState: Send + Sync {
    /// Read a key (must be thread-safe for parallel reads).
    fn get(&self, key: &StateKey) -> Option<StateValue>;
    
    /// Write a key (may be batched for parallel merge).
    fn set(&mut self, key: StateKey, value: StateValue);
    
    /// Create a snapshot for speculative execution (Stage B).
    fn snapshot(&self) -> Box<dyn ExecutionState>;
    
    /// Merge updates from a parallel worker.
    fn merge(&mut self, updates: StateUpdates);
}
```

### 5.4 Integration with AsyncExecutionService

**Current**: `SingleThreadExecutionService` calls `engine.apply_transaction()` in a loop.

**Proposed Change**:

1. Replace the inner loop with a call to `ParallelExecutionEngine::execute_block_parallel()`.
2. The service remains single-threaded at the *block* level (one block at a time).
3. Parallelism occurs *within* `execute_block_parallel()`.

```
// Pseudocode for updated worker loop
loop {
    let block = queue.recv()?;
    let receipts = parallel_engine.execute_block_parallel(&block, &mut state, config)?;
    commit_receipts(receipts);
    notify_completion(block.height);
}
```

### 5.5 Metrics

**New Metrics for Parallel Execution**:

| Metric | Type | Description |
| :--- | :--- | :--- |
| `qbind_execution_parallel_workers_active` | Gauge | Number of worker threads currently executing. |
| `qbind_execution_parallel_factor` | Histogram | Avg parallelism factor per block (# concurrent tasks). |
| `qbind_execution_sender_partitions` | Histogram | # distinct senders per block (Stage A potential). |
| `qbind_execution_conflict_rate` | Histogram | % of tx pairs with conflicts (Stage B). |
| `qbind_execution_speculative_rollbacks` | Counter | Speculative executions that required rollback (Stage B STM). |
| `qbind_execution_block_parallel_seconds` | Histogram | Total block execution time (parallel). |
| `qbind_execution_block_sequential_seconds` | Histogram | Equivalent sequential time (for speedup calculation). |

### 5.6 Configuration & Feature Flags

**Proposed Configuration**:

```toml
[execution]
# Enable parallel execution (Stage A).
parallel_enabled = true

# Max worker threads (0 = auto-detect from CPU count).
parallel_workers = 0

# Conflict strategy for Stage B (future).
# Options: "sender_partition", "access_list", "speculative"
conflict_strategy = "sender_partition"

# Fall back to sequential if fewer than N distinct senders.
parallel_min_senders = 2
```

**Feature Flags** (compile-time):
- `parallel-execution`: Enable Stage A parallel execution.
- `parallel-execution-stm`: Enable Stage B speculative execution (future).

### 5.7 Testing Strategy

| Test Category | Description |
| :--- | :--- |
| **Determinism Tests** | Run same block through parallel and sequential engines; compare state roots. |
| **Stress Tests** | High-tx blocks with many senders; verify speedup. |
| **Adversarial Tests** | All txs from one sender; verify correct sequential fallback. |
| **Conflict Tests (Stage B)** | Txs with overlapping access lists; verify correct serialization. |
| **Metrics Tests** | Verify parallel factor and conflict rate metrics are recorded. |

---

## Appendix A: References

- [QBIND DevNet v0 Spec](./QBIND_DEVNET_V0_SPEC.md) — Current architecture baseline.
- [QBIND DevNet Audit Log](./QBIND_DEVNET_AUDIT.md) — Risk tracking (R3, R6).
- [QBIND DAG Mempool Design](./QBIND_DAG_MEMPOOL_DESIGN.md) — Companion design for DAG-based mempool.
- Narwhal & Tusk (Danezis et al.) — DAG-based mempool inspiration.
- Block-STM (Aptos) — Speculative parallel execution reference.

---

## Appendix B: Glossary

| Term | Definition |
| :--- | :--- |
| **Commute** | Two operations commute if their order does not affect the final state. |
| **Conflict Graph** | A graph where nodes are transactions and edges represent conflicts (shared state access). |
| **Read/Write Set** | The set of state keys read or written by a transaction. |
| **STM** | Software Transactional Memory—optimistic concurrency with conflict detection and rollback. |
| **Topological Layering** | Partitioning a DAG into layers where each layer contains nodes with no dependencies on other nodes in the same layer. |

---

## Appendix C: T171 Stage B Implementation Notes

**Task**: T171  
**Status**: Test-only skeleton (NOT wired into production)  
**Date**: 2026-01-30

### Overview

T171 provides the initial Stage B parallel execution skeleton with:

1. **New types** in `qbind-ledger/src/parallel_exec.rs`:
   - `TxIndex`: Transaction identifier within a block
   - `TxReadWriteSet`: Read/write set for conflict analysis
   - `ConflictGraph`: Dependency graph over transactions
   - `ParallelSchedule`: Deterministic schedule (levels) for parallel execution

2. **Core algorithms**:
   - `extract_read_write_set()`: Extract accounts touched by a VM v0 transfer
   - `build_conflict_graph()`: O(n²) conflict detection based on account overlap
   - `build_parallel_schedule()`: Topological layering for deterministic scheduling

3. **Test harness** (`#[cfg(test)]` only):
   - Parallel executor using Rayon for within-level parallelism
   - Comparison with sequential execution for correctness validation

### Critical Invariants

- **No randomness**: All conflict detection and scheduling are purely deterministic
- **Single-block scope**: Scheduler reasons within one block only
- **VM semantics preserved**: Stage B produces identical results to sequential execution

### What T171 Does NOT Do

- No changes to `SingleThreadExecutionService` behavior
- No CLI flags or node config changes
- No parallelism for DevNet `NonceOnly` profile (Stage A remains as-is)
- No speculative execution or rollback

### Future Work

Stage B wiring into the production pipeline will be addressed in future tasks (T172+)
after the conflict-graph core has been validated through testing and benchmarking.

---

## Appendix D: Implementation Status – Stage B Wiring (T186, T187)

**Tasks**: T186, T187  
**Status**: Production-ready, config-gated  
**Date**: 2026-02-02

### Overview

T186 and T187 complete the Stage B wiring into the VM v0 pipeline:

1. **T186: Initial Wiring**:
   - Added `stage_b_enabled` configuration option to `NodeConfig`
   - Added `StageBExecStats` and production `execute_block_stage_b()` API
   - Config defaults: DevNet/TestNet Alpha/Beta = `false`, MainNet = `true`
   - CLI flag: `--enable-stage-b` for runtime control

2. **T187: Production Activation**:
   - Wired `execute_block_stage_b()` into VM v0 worker loop in `execution_adapter.rs`
   - Added Stage B metrics: `stage_b_enabled`, `stage_b_blocks_total{mode}`, `stage_b_mismatch_total`, `stage_b_levels_histogram`, `stage_b_parallel_seconds`
   - Added cluster harness tests for Stage B verification
   - Verified determinism vs sequential execution

### Configuration

| Environment | `stage_b_enabled` Default | Notes |
| :--- | :--- | :--- |
| DevNet v0 | `false` | DevNet frozen at sequential |
| TestNet Alpha | `false` | Opt-in for testing |
| TestNet Beta | `false` | Opt-in for testing |
| MainNet v0 | `true` | Enabled by default, operators can disable |

### Metrics

| Metric | Type | Description |
| :--- | :--- | :--- |
| `qbind_execution_stage_b_enabled` | Gauge | 0 or 1 indicating Stage B status |
| `qbind_execution_stage_b_blocks_total{mode="parallel"}` | Counter | Blocks executed via Stage B |
| `qbind_execution_stage_b_blocks_total{mode="fallback"}` | Counter | Blocks that fell back to sequential |
| `qbind_execution_stage_b_mismatch_total` | Counter | Internal mismatches detected |
| `qbind_execution_stage_b_levels_histogram` | Histogram | Schedule levels per block |
| `qbind_execution_stage_b_parallel_seconds` | Histogram | Stage B execution time |

### Test Coverage

- `qbind-ledger`: 6 Stage B executor unit tests (from T186)
- `qbind-node`: Cluster harness tests:
  - `test_testnet_beta_stage_b_localmesh_smoke`: CI-friendly smoke test
  - `test_stage_b_pipeline_determinism_against_sequential`: Determinism verification
  - `test_testnet_beta_stage_b_p2p_smoke` (ignored): P2P mode smoke test

### Critical Invariants (Preserved)

- **Determinism**: Stage B produces identical state to sequential execution
- **No consensus changes**: Block ordering is still determined by HotStuff
- **No gas/fee changes**: Same gas accounting in both modes
- **Backward compatibility**: `stage_b_enabled = false` preserves exact pre-T186 behavior

---

## Appendix E: Stage B Soak & Determinism Harness (T223)

**Task**: T223  
**Status**: Design + Implementation + Soak Harness Ready  
**Date**: 2026-02-08

### Overview

T223 provides a comprehensive soak and determinism harness for Stage B parallel execution, proving correctness under long-run randomized workloads. This harness is the normative test artifact for MN-R7 (Stage B conflict-graph parallel execution risk).

### What T223 Does

1. **Long-Run Determinism Testing**:
   - Executes 100+ blocks with randomized transaction mixes
   - For each block: runs sequential execution AND Stage B parallel execution
   - Compares final state, receipts, and gas accounting
   - Any divergence surfaces as a hard test failure

2. **Randomized Workloads**:
   - Multiple senders (64+ by default)
   - Randomized transfer amounts and fee priorities
   - Exercises DAG mempool patterns and fee-priority ordering
   - Controllable random seed for reproducibility

3. **Metrics Verification**:
   - Confirms Stage B metrics show non-zero parallel blocks
   - Asserts `stage_b_mismatch_total == 0` after each run
   - Validates `stage_b_enabled == 1` gauge

### Test Harness

File: `crates/qbind-node/tests/t223_stage_b_soak_harness.rs`

Key tests:
- `test_stage_b_soak_determinism_over_100_blocks`: Main soak test (100 blocks, 64 senders)
- `test_stage_b_soak_short_sanity`: Fast smoke test (20 blocks)
- `test_stage_b_metrics_surface`: Metrics format verification
- `test_stage_b_soak_high_contention`: Sequential fallback verification
- `test_stage_b_soak_independent_txs`: Maximum parallelism verification
- `test_stage_b_soak_reproducibility`: Determinism with fixed seed

### Running the Harness

```bash
# Full soak test suite
cargo test -p qbind-node --test t223_stage_b_soak_harness -- --test-threads=1

# Quick sanity check only
cargo test -p qbind-node --test t223_stage_b_soak_harness test_stage_b_soak_short_sanity
```

### Invariants Checked

| Invariant | Description | Assertion |
| :--- | :--- | :--- |
| **State Equality** | Sequential and Stage B produce identical state | Per-block comparison |
| **Receipt Equality** | All tx results match (success, gas, fees) | Per-tx comparison |
| **No Mismatches** | `stage_b_mismatch_total == 0` | Post-run assertion |
| **Parallel Use** | Stage B parallel path exercised | `stage_b_blocks_parallel > 0` |

### Implementation Status Summary

Stage B parallel execution is now fully verified through multiple layers:

| Level | Task(s) | Coverage |
| :--- | :--- | :--- |
| **Unit tests** | T171 | Conflict graph, schedule construction |
| **Executor tests** | T186 | `execute_block_stage_b()` API correctness |
| **Pipeline wiring** | T187 | Production integration, basic determinism |
| **Hybrid fees** | T193 | Fee distribution with Stage B |
| **Soak harness** | **T223** | Long-run randomized determinism |

---

*End of Document*