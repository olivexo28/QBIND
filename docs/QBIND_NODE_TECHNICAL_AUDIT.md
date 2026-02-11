# QBIND-Node Technical Audit

**Version**: Code-Faithful Analysis (2026-02-11)  
**Status**: Whitepaper Accuracy Reference

This document provides a structured technical summary of qbind-node internals based on direct code inspection. All statements reflect the implemented codebase; no features have been invented or assumed beyond what exists in code.

---

## 1) Async Runtime Structure

### 1.1 Tokio Runtime Initialization

**Location**: `crates/qbind-node/src/main.rs:50-51`

```rust
#[tokio::main]
async fn main() {
```

The node uses `#[tokio::main]` macro for runtime initialization, which creates a multi-threaded runtime with default settings (CPU-bound worker threads).

### 1.2 Tasks Spawned

| Task | Location | Description |
|------|----------|-------------|
| P2P Demuxer Loop | `crates/qbind-node/src/p2p_node_builder.rs:463-466` | Routes inbound P2P messages to handlers (consensus, DAG, control) |
| Async Node Runner | `crates/qbind-node/src/async_runner.rs:547-549` | Event-driven consensus loop via `tokio::select!` |
| Metrics HTTP Server | `crates/qbind-node/src/metrics_http.rs:242-271` | HTTP server for Prometheus metrics (optional) |
| Async Execution Worker | `crates/qbind-node/src/execution_adapter.rs:650-681` | Block execution in separate thread (T155) |
| Secure Channel Workers | `crates/qbind-node/src/secure_channel.rs:375-467` | Read/write workers for KEMTLS channels |
| Verification Pool Workers | `crates/qbind-node/src/verify_pool.rs:270-298` | Parallel signature verification workers |

### 1.3 Service Communication Patterns

#### Channels (Primary Pattern)

**Location**: `crates/qbind-node/src/async_runner.rs:97-173`

```rust
pub const DEFAULT_EVENT_CHANNEL_CAPACITY: usize = 1024;
pub type ConsensusEventSender = mpsc::Sender<ConsensusEvent>;
pub type ConsensusEventReceiver = mpsc::Receiver<ConsensusEvent>;
```

- `tokio::sync::mpsc` channels for event-driven consensus
- `ConsensusEvent` enum: `Tick`, `IncomingMessage`, `Shutdown`
- Bounded channels (default 1024 capacity) provide backpressure

**Location**: `crates/qbind-node/src/p2p_node_builder.rs:441-442`

```rust
let (_inbound_tx, inbound_rx) = mpsc::channel::<P2pMessage>(256);
```

- P2P inbound messages routed via channels

**Location**: `crates/qbind-node/src/execution_adapter.rs:606-681`

- Block submission channel for async execution

#### Shared State with Locks

**Location**: `crates/qbind-node/src/mempool.rs:345-346`

```rust
struct InMemoryMempoolInner {
    txs: BTreeMap<TxPriorityScore, QbindTransaction>,
    by_sender: HashMap<AccountId, Vec<u64>>,
    // ...
}

pub struct InMemoryMempool {
    inner: Arc<RwLock<InMemoryMempoolInner>>,
    // ...
}
```

- `parking_lot::RwLock` for mempool access
- `Arc<RwLock<T>>` pattern for shared mutable state

**Location**: `crates/qbind-node/src/dag_mempool.rs`

- DAG mempool uses similar `Arc<RwLock<T>>` pattern

#### Atomics for Metrics

**Location**: `crates/qbind-node/src/metrics.rs:459-482`

```rust
pub disconnect_shutdown: AtomicU64,
```

- `std::sync::atomic::AtomicU64` for lock-free counter increments
- `Ordering::Relaxed` for most metrics (no strict ordering needed)

---

## 2) Mempool-Consensus Connection

### 2.1 Proposal Creation Trigger

**Location**: `crates/qbind-consensus/src/basic_hotstuff_engine.rs:883-890`

```rust
pub fn on_leader_step(&mut self) -> Vec<ConsensusEngineAction<ValidatorId>> {
    if !self.is_leader_for_current_view() {
        return Vec::new();
    }
    if self.proposed_in_view {
        return Vec::new();
    }
    // ... create proposal
}
```

**Trigger Chain**:
1. `AsyncNodeRunner::run_loop_internal()` calls `harness.on_tick()`
2. Timer tick fires at configured interval (default 100ms)
3. `NodeHotstuffHarness` processes tick event
4. Engine checks `is_leader_for_current_view()` (round-robin: `view % num_validators`)
5. If leader AND not already proposed, `on_leader_step()` generates proposal

**Leader Election** (`crates/qbind-consensus/src/basic_hotstuff_engine.rs:621`):
```rust
pub fn is_leader_for_current_view(&self) -> bool {
    self.leader_for_view(self.current_view) == self.local_id
}

fn leader_for_view(&self, view: u64) -> ValidatorId {
    let n = self.validators.len();
    let index = (view as usize) % n;
    self.validators[index]
}
```

### 2.2 Transaction Selection

**Location**: `crates/qbind-node/src/hotstuff_node_sim.rs:3200-3302`

```rust
fn apply_action(&mut self, mut action: ConsensusEngineAction<ValidatorId>) {
    if let ConsensusEngineAction::BroadcastProposal(ref mut proposal) = action {
        // Transaction selection based on proposer_source
        let (txs, certified_batch_refs) = match self.proposer_source {
            ProposerSource::FifoMempool => {
                (mempool.get_block_candidates(self.max_txs_per_block), None)
            }
            ProposerSource::DagMempool => {
                (dag_mempool.select_frontier_txs(self.max_txs_per_block), None)
            }
        };
        proposal.txs = /* serialize txs */;
    }
}
```

**Selection Strategies**:

| Source | Method | Ordering |
|--------|--------|----------|
| FIFO Mempool | `get_block_candidates(max_txs)` | Priority-ordered (T169: fee_per_gas → effective_fee → arrival_id) |
| DAG Mempool | `select_frontier_txs(max_txs)` | Certified frontier (T190 coupling) |

**FIFO Selection** (`crates/qbind-node/src/mempool.rs:510-519`):
```rust
fn get_block_candidates(&self, max_txs: usize) -> Vec<QbindTransaction> {
    let guard = self.inner.read();
    guard.txs.iter()
        .rev()  // BTreeMap ordered by TxPriorityScore, rev() gets highest first
        .take(max_txs)
        .map(|(_, tx)| tx.clone())
        .collect()
}
```

**DAG Selection** (`crates/qbind-node/src/dag_mempool.rs:2653-2680`):
- `select_frontier_txs()` returns transactions from certified batches
- `select_certified_frontier()` for DAG-coupled proposals (T190)

---

## 3) Persistence Ordering

### 3.1 Storage Backend

**Location**: `crates/qbind-node/src/storage.rs:1-44`

- **Engine**: RocksDB
- **Schema Version**: 1

### 3.2 Key Layout

| Key Pattern | Value |
|-------------|-------|
| `b:<block_id>` | Serialized `BlockProposal` |
| `q:<block_id>` | Serialized `QuorumCertificate` |
| `meta:last_committed` | Block ID bytes |
| `meta:current_epoch` | u64 (big-endian) |
| `meta:schema_version` | u32 (big-endian) |

### 3.3 Persistence Flow (Order Matters)

**Location**: `crates/qbind-node/src/hotstuff_node_sim.rs:2802-3024`

```rust
fn drain_and_persist_commits(&mut self) -> Result<(), NodeHotstuffHarnessError> {
    let new_commits = self.sim.drain_commits();
    
    // Step 1: Apply to in-memory commit index
    self.commit_index.apply_commits(new_commits.clone())?;
    
    // Step 2: Apply committed blocks (execution)
    for commit_info in &new_commits {
        // Decode and execute transactions
        // Remove from mempool
    }
    
    // Step 3: Persist to RocksDB (if storage attached)
    if let Some(storage) = &self.storage {
        for commit_info in &new_commits {
            // 3a: Persist block
            storage.put_block(&commit_info.block_id, &stored_block.proposal)?;
            
            // 3b: Persist QC if present
            if let Some(ref qc) = stored_block.proposal.qc {
                storage.put_qc(&commit_info.block_id, qc)?;
            }
            
            // 3c: Update last committed (CRITICAL for restart)
            storage.put_last_committed(&commit_info.block_id)?;
        }
    }
    
    // Step 4: Handle epoch transitions (T102.1)
    for commit_info in &new_commits {
        self.handle_potential_reconfig_commit(&commit_info.block_id)?;
    }
    Ok(())
}
```

### 3.4 Persistence Order Summary

1. **In-memory commit index update** - First (for fast queries)
2. **Transaction execution** - Second (applies state changes)
3. **Block persisted** - Third (`put_block`)
4. **QC persisted** - Fourth (`put_qc`)
5. **Last committed updated** - Fifth (critical for restart recovery)
6. **Epoch persisted** - On reconfig blocks only

### 3.5 Epoch Transition Atomicity (T112)

**Location**: `crates/qbind-node/src/hotstuff_node_sim.rs:3034-3049`

```
Atomic Epoch Transition ordering:
1. Validate epoch state
2. Persist new epoch to storage FIRST
3. Update in-memory engine state

Crash safety:
- Before step 2: Old epoch everywhere → consistent
- After step 2, before step 3: Storage has new, engine old → restart restores new
- After step 3: Both have new epoch → consistent
```

---

## 4) Error Boundaries

### 4.1 Error Type Hierarchy

**Location**: `crates/qbind-node/src/hotstuff_node_sim.rs:96-138`

```rust
pub enum NodeHotstuffHarnessError {
    Sim(NodeConsensusSimError),           // Consensus simulation errors
    NetService(NetServiceError),           // Network errors
    ConsensusNode(ConsensusNodeError),     // Node-level errors
    CommitIndex(CommitIndexError<[u8; 32]>), // Commit tracking errors
    BlockStore(BlockStoreError),           // Block storage errors
    Storage(StorageError),                 // RocksDB errors
    StartupValidation(StartupValidationError), // Startup checks
    Io(io::Error),                         // I/O errors
    Config(String),                        // Configuration errors
    MissingProposalForCommittedBlock,      // Data consistency error
    EpochTransition(EpochTransitionError), // Epoch handling
    RuntimeSuiteDowngrade { ... },         // Security violation
}
```

### 4.2 Fatal vs Recoverable Errors

#### Fatal Errors (Trigger Shutdown)

| Error | Location | Trigger |
|-------|----------|---------|
| MainNet invariant violation | `main.rs:70-76` | `std::process::exit(1)` |
| P2P node build failure | `main.rs:144-147` | `std::process::exit(1)` |
| Async execution queue full | `hotstuff_node_sim.rs:2920-2925` | `panic!()` |
| Storage corruption | `storage.rs:79-81` | `StorageError::Corruption` |
| Schema incompatibility | `storage.rs:64-74` | `StorageError::IncompatibleSchema` |
| RuntimeSuiteDowngrade | `hotstuff_node_sim.rs:126-138` | Security violation, blocks epoch transition |
| Signer failure (MainNet) | `node_config.rs:646` | `SignerFailureMode::ExitOnFailure` |

#### Recoverable Errors (Logged, Continue)

| Error | Location | Handling |
|-------|----------|----------|
| Execution adapter failure | `hotstuff_node_sim.rs:2940-2946` | Log warning, continue |
| Async exec shutting down | `hotstuff_node_sim.rs:2927-2933` | Log warning, continue |
| Invalid transaction encoding | `hotstuff_node_sim.rs:2826-2875` | Log warning, skip transaction |
| Network errors | Various | Log, retry or reconnect |
| Stale height/round | `hotstuff_state_engine.rs` | Reject message, continue |
| Double vote attempt | `hotstuff_state_engine.rs` | Reject, no penalty applied yet |

### 4.3 Shutdown Mechanisms

**Location**: `crates/qbind-node/src/async_runner.rs:665-677`

```rust
match maybe_event {
    Some(ConsensusEvent::Shutdown) => {
        metrics.runtime().inc_events_shutdown();
        eprintln!("[AsyncNodeRunner] Shutdown event received, exiting normally");
        return Ok(());
    }
    None => {
        // All senders dropped - graceful shutdown
        eprintln!("[AsyncNodeRunner] Event channel closed, exiting normally");
        return Ok(());
    }
}
```

**Shutdown Triggers**:
1. `ConsensusEvent::Shutdown` message
2. All channel senders dropped
3. `max_ticks` limit reached (testing)
4. Ctrl+C signal (`main.rs:119-122`)
5. Fatal errors (`std::process::exit(1)`)

**Location**: `crates/qbind-node/src/p2p_node_builder.rs:606-624`

```rust
pub async fn shutdown(context: P2pNodeContext) -> Result<(), P2pNodeError> {
    // Abort demuxer task
    context.demuxer_handle.abort();
    
    // Wait with timeout
    tokio::time::timeout(Duration::from_secs(5), context.demuxer_handle).await;
    
    // TcpKemTlsP2pService shutdown via internal channel on drop
}
```

### 4.4 Error Flow in Consensus Loop

**Location**: `crates/qbind-node/src/async_runner.rs:607-616`

```rust
// Errors from harness methods are treated as fatal
if let Err(err) = self.harness.on_tick() {
    eprintln!("[AsyncNodeRunner] on_tick error at tick {}: {}", tick_count, err);
    return Err(AsyncNodeError::Harness(err));
}
```

---

## Summary Table

| Component | Pattern | Key Files |
|-----------|---------|-----------|
| Runtime | `#[tokio::main]`, multi-threaded | `main.rs` |
| Consensus Events | `mpsc` channels, bounded | `async_runner.rs` |
| Mempool | `Arc<RwLock<T>>` | `mempool.rs`, `dag_mempool.rs` |
| Metrics | `AtomicU64` counters | `metrics.rs` |
| Proposal Trigger | Timer tick → leader check | `basic_hotstuff_engine.rs` |
| TX Selection | Priority ordering or DAG frontier | `mempool.rs:510` |
| Persistence | Execute → Block → QC → LastCommitted | `hotstuff_node_sim.rs:2987-3010` |
| Fatal Errors | `exit(1)` or `panic!()` | Multiple locations |
| Graceful Shutdown | Channel close or Shutdown event | `async_runner.rs:665-677` |

---

*This document was generated from direct code inspection of the QBIND repository at commit time. All file paths and line numbers reference the actual codebase.*
