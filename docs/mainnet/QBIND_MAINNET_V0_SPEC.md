# QBIND MainNet v0 Specification

**Task**: T184  
**Status**: Design Specification  
**Date**: 2026-02-02

---

## 1. Scope & Positioning

### 1.1 What "MainNet v0" Means

MainNet v0 is the **first production, economic-value-carrying network** for QBIND. It extends the TestNet Beta architecture with stronger requirements for security, reliability, and operational maturity.

- **Network Environment**: `NetworkEnvironment::Mainnet` (`QBIND_MAINNET_CHAIN_ID = 0x51424E444D41494E`)
- **Execution Profile**: `ExecutionProfile::VmV0` (transfer-only, sequential) with **Stage B parallelism available**
- **Configuration Profile**: MainNet-specific defaults with production-hardened settings

**Key Distinction**: MainNet v0 uses the same core protocol as TestNet Beta but with:
- **Economic value**: Real assets at stake, requiring stronger safety guarantees
- **Production-grade operations**: HSM support, monitoring, incident response
- **Audit requirements**: External security audit completed before launch
- **Governance constraints**: On-chain validator set with stake requirements

### 1.2 Relationship to TestNet Beta

MainNet v0 builds directly on TestNet Beta:

| Aspect | TestNet Beta | MainNet v0 |
| :--- | :--- | :--- |
| **Chain ID** | `QBIND_TESTNET_CHAIN_ID` | `QBIND_MAINNET_CHAIN_ID` |
| **Gas Enforcement** | Enabled (default) | **Required** (cannot be disabled) |
| **Fee Policy** | Burn-only | **Hybrid (burn + proposer reward)** |
| **Mempool** | DAG (default) | DAG (**only** for validators) |
| **P2P** | P2P (default) | P2P (**required**, no LocalMesh) |
| **State** | RocksDB (required) | RocksDB (**mandatory**, no in-memory) |
| **Keys** | EncryptedFs / loopback signer | **HSM-ready** (production signer required) |
| **Parallelism** | Sequential only | **Stage B available** (conflict-graph) |
| **Availability** | Certs v1 (data-plane) | **Consensus-coupled** certificates |
| **Discovery** | Static peers | **Dynamic discovery** + static fallback |
| **Audit** | Skeleton tracking | **Full external audit required** |

### 1.3 Phase Comparison Table

| Phase | Execution | Gas/Fees | Mempool | Networking | Persistence | Parallelism | Availability Certs |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **DevNet v0** | NonceOnly | None | FIFO | LocalMesh | In-memory | Stage A | None |
| **TestNet Alpha** | VmV0 | Design only | FIFO + DAG opt-in | LocalMesh + P2P opt-in | RocksDB | Sequential | v1 opt-in |
| **TestNet Beta** | VmV0 (gas-on) | Enforced (burn) | DAG default | P2P default | RocksDB | Sequential | v1 default |
| **MainNet v0** | VmV0 (gas-on) | Enforced (hybrid) | DAG only | P2P required | RocksDB mandatory | **Stage B available** | **Consensus-coupled** |

### 1.4 Intended Use Case

MainNet v0 is the **production network** for QBIND:

- Real economic value is transferred on-chain
- Validators stake real tokens and face slashing for misbehavior
- Users expect high availability and security
- All protocol changes require governance approval

### 1.5 Genesis State & Chain ID (T232)

MainNet v0 requires a **canonical genesis state** that establishes the initial network configuration:

| Field | Description | MainNet Requirement |
| :--- | :--- | :--- |
| **chain_id** | Network identifier | `qbind-mainnet-v0` |
| **genesis_time_unix_ms** | Canonical start time | Set at launch |
| **allocations** | Initial token distribution | Non-zero amounts, unique addresses |
| **validators** | Initial validator set | At least 1, with PQC keys |
| **council** | Governance council | threshold ≤ member count |
| **monetary** | Initial monetary parameters | Bootstrap phase defaults |

**MainNet Genesis Requirements**:
- **External genesis file required**: MainNet nodes MUST use `--genesis-path` CLI flag
- **Embedded genesis forbidden**: Unlike DevNet/TestNet, embedded genesis is not allowed
- **Hash verification**: Operators MUST verify genesis file hash before startup (see §1.6)
- **Canonical distribution**: All validators MUST use the identical genesis.json

**GenesisConfig Invariants** (enforced by `validate()`):
1. Non-empty chain_id
2. All allocation amounts > 0
3. No duplicate addresses in allocations
4. At least one validator with non-empty PQC key
5. Council threshold: 0 < threshold ≤ member count
6. Total supply > 0 (sum of allocations)

**CLI Usage**:
```bash
qbind-node --profile mainnet --genesis-path /etc/qbind/genesis.json --data-dir /data/qbind
```

See [QBIND_GENESIS_AND_LAUNCH_DESIGN.md](../consensus/QBIND_GENESIS_AND_LAUNCH_DESIGN.md) for the full genesis specification.

### 1.6 Genesis Hash Commitment & Verification (T233)

MainNet v0 enforces **genesis hash commitment** to prevent accidental or malicious startup with the wrong genesis file:

**Canonical Genesis Hash Definition**:
```
genesis_hash = SHA3-256(genesis_json_bytes)
```

Where `genesis_json_bytes` is the **exact** content of the genesis file as distributed, with:
- **No JSON normalization**
- **No whitespace stripping or key reordering**
- **Exact byte-for-byte hash**

**MainNet Requirements** (enforced by `validate_mainnet_invariants()`):
1. **`--expect-genesis-hash` is REQUIRED**: MainNet nodes MUST specify the expected genesis hash
2. **Hash verification at startup**: Node computes hash from loaded genesis file and compares to expected
3. **Fail-fast on mismatch**: If hashes don't match, node refuses to start

**CLI Flags**:

| Flag | Description | Required |
| :--- | :--- | :--- |
| `--print-genesis-hash` | Print SHA3-256 hash of genesis file and exit | No |
| `--expect-genesis-hash` | Expected hash to verify at startup | **Yes (MainNet)** |

**Operator Workflow**:

1. **Compute hash** of the official genesis file:
   ```bash
   qbind-node --print-genesis-hash --genesis-path /etc/qbind/genesis.json
   # Output: 0xabc123...def789
   ```

2. **Start node** with expected hash:
   ```bash
   qbind-node --profile mainnet \
     --genesis-path /etc/qbind/genesis.json \
     --expect-genesis-hash 0xabc123...def789 \
     --data-dir /data/qbind
   ```

3. **Cross-verify** with other validators to ensure all nodes use the same genesis

**Security Rationale**:
- Prevents fork due to different genesis files
- Detects distribution channel compromises
- Provides audit trail for genesis identity

See [QBIND_MAINNET_RUNBOOK.md](../ops/QBIND_MAINNET_RUNBOOK.md) §4.3 for operational procedures.

---

## 2. Execution & State

### 2.1 Execution Profile

MainNet v0 uses `ExecutionProfile::VmV0` with mandatory gas enforcement:

- **Transaction Type**: Transfer-only (recipient + amount + gas_limit + max_fee_per_gas)
- **Account State**: Nonce + Balance per account
- **Execution Order**: Deterministic (sequential or Stage B parallel)
- **Payload Format**: `TransferPayloadV1` (72 bytes) **required**; v0 format rejected

### 2.2 Stage B Parallel Execution

Stage B conflict-graph-based parallel execution is **available and enabled by default** for MainNet v0:

| Aspect | MainNet v0 Status | Notes |
| :--- | :--- | :--- |
| **Implementation** | ✅ Ready (T171, T186, T187) | Complete with metrics |
| **Production Wiring** | ✅ Complete (T187) | Wired into VM v0 pipeline |
| **Default Behavior** | `stage_b_enabled = true` | Operators can disable via CLI |
| **Determinism** | ✅ Verified | CI tests confirm identical results |
| **Soak Harness** | ✅ Ready (T223) | Long-run randomized determinism testing |
| **Metrics** | ✅ Available | `stage_b_enabled`, `stage_b_blocks_total`, etc. |

**Stage B Algorithm Summary** (from [QBIND_PARALLEL_EXECUTION_DESIGN.md](../devnet/QBIND_PARALLEL_EXECUTION_DESIGN.md)):

1. Extract read/write sets for each transaction
2. Build conflict graph based on account overlap
3. Generate parallel schedule (topological layering)
4. Execute layers in parallel with Rayon
5. Merge results deterministically

**Critical Invariant**: All validators MUST produce identical state regardless of parallel vs sequential execution. This is verified by:
- T187 CI tests (unit-level determinism)
- T193 hybrid fee distribution tests
- **T223 soak harness (100+ blocks, randomized workloads)**

**Disabling Stage B** (if needed):
```bash
qbind-node --profile mainnet --enable-stage-b false --data-dir /data/qbind
```

When Stage B is disabled, a soft warning is logged but the node continues with sequential execution.

### 2.3 State Persistence

RocksDB-backed persistent account state is **mandatory** for all MainNet v0 nodes:

| Requirement | MainNet v0 |
| :--- | :--- |
| **Persistent Storage** | Required (`data_dir` must be configured) |
| **In-Memory Mode** | **Not allowed** for validators |
| **Caching** | `CachedPersistentAccountState` (write-through) |
| **Crash Recovery** | WAL-based; state flushed at block boundaries |

### 2.4 State Growth Management

MainNet v0 introduces state growth management expectations:

| Feature | MainNet v0 Status | Notes |
| :--- | :--- | :--- |
| **State Pruning** | **Required** | Configurable retention period |
| **Archival Nodes** | Supported | Full history retention (no pruning) |
| **Snapshots** | **Required (T215)** | Periodic state snapshots for fast sync |
| **State Size Monitoring** | Required | Metrics + alerting |

**Node Types by Pruning Policy**:

| Node Type | Pruning | State Retention |
| :--- | :--- | :--- |
| **Validator Node** | Enabled | Recent N blocks (configurable) |
| **Full Node (Pruned)** | Enabled | Recent N blocks |
| **Archival Node** | Disabled | Full history |

### 2.5 State Snapshots (T215)

MainNet v0 requires periodic state snapshots for fast node synchronization and recovery:

| Parameter | MainNet v0 Default | Notes |
| :--- | :--- | :--- |
| `snapshot_config.enabled` | `true` | **Required** for MainNet |
| `snapshot_interval_blocks` | 50,000 | ~3.5 days at 5s blocks |
| `max_snapshots` | 5 | Keep last 5 snapshots |
| `snapshot_dir` | Must be configured | Operator-provided path |

**Snapshot Features**:

- **Deterministic snapshots**: Uses RocksDB checkpoint API for consistent point-in-time snapshots
- **Background creation**: Snapshots are created without blocking consensus
- **Metadata validation**: Each snapshot includes height, block hash, chain ID for validation
- **Fast sync restore**: Nodes can boot from local snapshots instead of replaying from genesis

**Snapshot Directory Layout**:

```text
snapshot_dir/
├── 50000/              # Snapshot at height 50,000
│   ├── meta.json       # Metadata (height, block_hash, chain_id, timestamp)
│   └── state/          # RocksDB checkpoint files
├── 100000/             # Snapshot at height 100,000
│   ├── meta.json
│   └── state/
└── ...
```

**CLI Flags**:

```bash
qbind-node --profile mainnet \
  --snapshot-dir /data/qbind/snapshots \
  --snapshot-interval 50000 \
  --max-snapshots 5
```

**Fast Sync from Snapshot** (optional):

```bash
qbind-node --profile mainnet \
  --fast-sync-snapshot-dir /data/qbind/snapshots/100000 \
  --data-dir /data/qbind
```

### 2.6 Performance & Benchmarking Evidence

MainNet v0 provides comprehensive performance testing and benchmarking evidence for PQC operations and throughput:

| Test Harness | Purpose | Status | Reference |
| :--- | :--- | :--- | :--- |
| **Stage B Soak (T223)** | Long-run determinism + correctness verification | ✅ Ready | `t223_stage_b_soak_harness.rs` |
| **E2E Perf Harness (T234)** | Realistic TPS/latency measurement with ML-DSA-44 | ✅ Ready | `t234_pqc_end_to_end_perf_tests.rs` |
| **PQC Cost Benchmarks (T198)** | Microbenchmarks for ML-DSA-44 signing/verification | ✅ Ready | See T198 task spec |

**T223 — Stage B Soak & Determinism Harness**:

- **Purpose**: Verify Stage B parallel execution produces identical results to sequential execution over long randomized workloads
- **Scope**: 100+ blocks with randomized transaction mixes, multiple senders, varying fee priorities
- **Assertions**:
  - Stage B state matches sequential state exactly (balances, nonces, receipts)
  - `stage_b_mismatch_total` metric remains at 0
  - Stage B metrics confirm parallel execution usage
- **Evidence**: Provides determinism guarantee for Stage B safety on MainNet

**T234 — E2E PQC Performance & TPS Harness**:

- **Purpose**: Measure effective TPS and end-to-end latency under realistic settings with real ML-DSA-44 signatures
- **Scope**: Small in-process cluster (3–4 validators), real PQC signing, controlled load generation
- **Measurements**:
  - Effective TPS (committed transactions per second)
  - End-to-end latency distribution (p50/p90/p99) from submission → commit
  - Stage B vs sequential performance comparison
  - Impact of DAG mempool, DoS limits, and eviction rate limiting
- **Profiles**:
  - **DevNet Profile**: 3 validators, Stage B off, moderate TPS (200–300)
  - **Beta Profile**: 4 validators, Stage B on, higher TPS (500+)
- **Evidence**: Demonstrates that PQC signature costs and Stage B overhead are acceptable for MainNet target throughput

**Running the Harness**:

```bash
# Run all T234 tests
cargo test -p qbind-node --test t234_pqc_end_to_end_perf_tests

# Run with nocapture for detailed output
cargo test -p qbind-node --test t234_pqc_end_to_end_perf_tests -- --nocapture
```

**Interpreting Results**:

- **Avg TPS**: Expected to be deployment-dependent (validator count, network latency, hardware specs)
- **Latency p99**: Should be sub-second for typical configurations
- **Stage B Impact**: Parallel execution should not significantly degrade TPS vs sequential
- **Reproducibility**: Same seed should produce identical submission/commit counts

**Performance Expectations**:

MainNet v0 does not specify a hard minimum TPS target but requires:
- All validators process blocks within reasonable time bounds (< 10s per block)
- Stage B parallelism provides measurable throughput benefit for high-conflict workloads
- PQC signature verification does not create bottlenecks for typical block sizes

**Note**: Specific TPS targets are deployment-dependent and will be established based on real-world MainNet validator hardware and geographic distribution. The T234 harness provides the testing framework for measuring performance characteristics in different configurations.

### 2.7 MainNet Launch Gates & Invariants (T237)

The following invariants are **enforced** by `validate_mainnet_invariants()` at startup. A MainNet node will **refuse to start** if any invariant is violated.

#### Core Execution Invariants

| Invariant | Requirement | Error on Violation |
| :--- | :--- | :--- |
| **Environment** | `NetworkEnvironment::Mainnet` | `WrongEnvironment` |
| **Gas Enforcement** | `gas_enabled = true` | `GasDisabled` |
| **Fee Priority** | `enable_fee_priority = true` | `FeePriorityDisabled` |
| **Mempool Mode** | `MempoolMode::Dag` | `WrongMempoolMode` |
| **DAG Availability** | `dag_availability_enabled = true` | `DagAvailabilityDisabled` |
| **Data Directory** | `data_dir` is set | `MissingDataDir` |

#### DAG & Consensus Invariants

| Invariant | Requirement | Error on Violation |
| :--- | :--- | :--- |
| **DAG Coupling** | `DagCouplingMode::Enforce` | `DagCouplingNotEnforced` |
| **Stage B** | Allowed but not required; warning if disabled | (warning only) |

#### P2P & Networking Invariants

| Invariant | Requirement | Error on Violation |
| :--- | :--- | :--- |
| **Network Mode** | `NetworkMode::P2p` | `WrongNetworkMode` |
| **P2P Transport** | `enable_p2p = true` | `P2pDisabled` |
| **Discovery** | `discovery_enabled = true` | `DiscoveryDisabled` |
| **Outbound Peers** | `target_outbound_peers >= 8` | `InsufficientTargetOutboundPeers` |
| **Diversity Mode** | `DiversityEnforcementMode::Enforce` | `DiversityNotEnforced` |
| **Anti-Eclipse** | Config present, `enforce = true`, min_outbound >= 4, min_asn >= 2 | `P2pAntiEclipseMisconfigured` |
| **Liveness** | `heartbeat_interval_secs > 0`, `max_heartbeat_failures > 0` | `P2pLivenessMisconfigured` |

#### Mempool Invariants

| Invariant | Requirement | Error on Violation |
| :--- | :--- | :--- |
| **DoS Limits** | All limits > 0, `max_pending_per_sender < 100,000` | `MempoolDosMisconfigured` |
| **Eviction Mode** | `EvictionRateMode::Enforce` | `MempoolEvictionMisconfigured` |

#### State & Snapshots Invariants

| Invariant | Requirement | Error on Violation |
| :--- | :--- | :--- |
| **State Retention** | Enabled (Height mode) | `StateRetentionDisabled` |
| **Retain Height** | `retain_height >= 10,000` | `StateRetentionInvalid` |
| **Snapshots** | `enabled = true` | `SnapshotsDisabled` |
| **Snapshot Interval** | `10,000 <= interval <= 500,000` | `SnapshotIntervalTooLow/TooHigh` |

#### Signer & Keys Invariants

| Invariant | Requirement | Error on Violation |
| :--- | :--- | :--- |
| **Signer Mode** | Not `LoopbackTesting` | `SignerModeLoopbackForbidden` |
| **Keystore Path** | Required for `EncryptedFsV1` | `SignerKeystorePathMissing` |
| **Remote Signer URL** | Required for `RemoteSigner` | `RemoteSignerUrlMissing` |
| **HSM Config** | Required for `HsmPkcs11` | `HsmConfigPathMissing` |
| **Failure Mode** | `SignerFailureMode::ExitOnFailure` | `SignerFailureModeInvalid` |

#### Slashing Invariants

| Invariant | Requirement | Error on Violation |
| :--- | :--- | :--- |
| **Slashing Mode** | Not `Off` (RecordOnly, EnforceCritical, or EnforceAll) | `SlashingMisconfigured` |

#### Monetary Invariants

| Invariant | Requirement | Error on Violation |
| :--- | :--- | :--- |
| **Monetary Mode** | Not `Off` (Shadow or Active) | `MonetaryModeOff` |
| **Fee Distribution** | `FeeDistributionPolicy::mainnet_default()` | `WrongFeeDistributionPolicy` |

#### Genesis Invariants

| Invariant | Requirement | Error on Violation |
| :--- | :--- | :--- |
| **Genesis Source** | External file required (`--genesis-path`) | `GenesisMisconfigured` |
| **Genesis Hash** | `--expect-genesis-hash` required | `ExpectedGenesisHashMissing` |

#### Test Harness

The canonical test harness for these invariants is:

```bash
# Run the T237 launch profile tests (mandatory pre-launch check)
cargo test -p qbind-node --test t237_mainnet_launch_profile_tests

# Run the T185 mainnet profile tests (original invariants)
cargo test -p qbind-node --test t185_mainnet_profile_tests
```

The `t237_mainnet_launch_profile_tests.rs` file contains:
- **Positive test**: `test_mainnet_preset_passes_launch_invariants` — verifies canonical preset passes
- **Negative tests**: One test per subsystem asserting correct `MainnetConfigError` on misconfiguration

See [QBIND_MAINNET_RUNBOOK.md §3](../ops/QBIND_MAINNET_RUNBOOK.md#3-configuration-profiles--invariants) for operational guidance.

---

## 3. Gas & Fees

### 3.1 Gas Enforcement

Gas enforcement is **mandatory** for MainNet v0:

| Parameter | MainNet v0 Default | Governance |
| :--- | :--- | :--- |
| `ExecutionGasConfig.enabled` | `true` (cannot be false) | Not adjustable |
| `BLOCK_GAS_LIMIT_DEFAULT` | 30,000,000 | Adjustable |
| `MINIMUM_GAS_LIMIT` | 21,000 | Not adjustable |
| `GAS_BASE_TX` | 21,000 | Governance-adjustable |
| `GAS_PER_ACCOUNT_READ` | 2,600 | Governance-adjustable |
| `GAS_PER_ACCOUNT_WRITE` | 5,000 | Governance-adjustable |

### 3.2 Fee Distribution Policy

MainNet v0 uses a **hybrid fee distribution** model:

| Component | Percentage | Recipient | Purpose |
| :--- | :--- | :--- | :--- |
| **Base Fee Burn** | 50% | Burned (destroyed) | Deflationary pressure |
| **Proposer Reward** | 50% | Block proposer | Incentive to include txs |

```rust
fn distribute_fee(actual_fee: u128, proposer: AccountId, state: &mut State) {
    let burn_amount = actual_fee / 2;
    let proposer_reward = actual_fee - burn_amount;
    
    // Burn 50%
    // (fee is simply removed from circulation)
    
    // Reward proposer 50%
    state.credit_balance(proposer, proposer_reward);
}
```

**Governance**: Fee distribution percentages are adjustable via on-chain governance.

### 3.3 Fee-Priority Mempool

Fee-priority ordering is **mandatory** for MainNet v0:

| Parameter | MainNet v0 Default |
| :--- | :--- |
| `enable_fee_priority` | `true` (cannot be false) |

**Priority Ordering**:

```
priority(tx) = (max_fee_per_gas, effective_fee, arrival_id)
```

### 3.4 Future Fee Market Upgrades

MainNet v0 uses a simple priority fee model. Future upgrades may include:

| Feature | Target Phase | Description |
| :--- | :--- | :--- |
| **EIP-1559-style base fee** | MainNet v1+ | Dynamic base fee based on block utilization |
| **Priority fee tipping** | MainNet v1+ | Explicit tip to proposer |
| **Fee oracle** | MainNet v1+ | On-chain fee estimation |

These upgrades are **out of scope** for MainNet v0.

### 3.5 Required Test Coverage

MainNet readiness requires the following gas/fee tests to pass:

| Test Category | Test Files | Requirement |
| :--- | :--- | :--- |
| **Gas property tests** | `t179_vm_v0_gas_proptests.rs` | **Mandatory CI** |
| **Fee conservation** | G2 property (balance + fees) | **Mandatory CI** |
| **Block gas limit** | G5 property | **Mandatory CI** |
| **Fee-market cluster tests** | `test_testnet_beta_fee_market_*` | **Mandatory CI** |
| **Eviction behavior** | `test_testnet_beta_fee_market_eviction` | **Mandatory CI** |

### 3.6 Monetary Policy

MainNet v0 operates under a formal monetary policy framework that integrates inflation, fee distribution, and validator rewards into a unified security budget model.

> **📋 Design Reference**: The complete monetary policy specification is provided in [QBIND_MONETARY_POLICY_DESIGN.md](../econ/QBIND_MONETARY_POLICY_DESIGN.md) (T194). This includes:
> - Three-phase model (Bootstrap / Transition / Mature) with time and economic readiness gates
> - PQC-adjusted inflation targets accounting for ML-DSA-44/ML-KEM-768 computational overhead
> - EMA-based fee smoothing to prevent inflation volatility
> - Seigniorage allocation (validators / treasury / insurance / community)
> - Integration with hybrid fee distribution (T193)
> - Parameter classification (hard-coded vs governance-tunable vs future/oracle-driven)
>
> **Implementation Status**:
> - T194: Design specification ✅ Complete
> - T195: Engine core (`compute_monetary_decision`) ✅ Complete
> - T196: Node-level telemetry (shadow mode) ✅ Complete — nodes compute and expose recommended inflation via metrics but do not yet enact it
> - T199: Epoch monetary state ✅ Complete — consensus-tracked per-epoch monetary state containing phase, fee coverage inputs, and chosen inflation rate
> - T200–T201: Seigniorage/issuance wiring ✅ Complete — validator reward distribution and application logic
> - T202: EMA-based fee smoothing ✅ **Ready** — per-epoch EMA with phase-dependent λ integrated into monetary pipeline
> - T203: Rate-of-change limiters ✅ **Ready** — consensus-side per-epoch Δ-limit on annual inflation, per phase, applied after floor/cap
> - T204: Phase transition logic ✅ **Ready** — consensus-enforced time and economic gates for automatic phase transitions

**MainNet v0 Monetary Phase State Machine** (T204):

MainNet v0 implements a consensus-tracked monetary phase state machine with the following properties:

- **Initial Phase**: Bootstrap at genesis
- **Time Gates** (using 10-minute epochs, ~52,560 epochs/year):
  - Bootstrap → Transition: epoch ≥ 157,680 (~3 years)
  - Transition → Mature: epoch ≥ 367,920 (~7 years)
- **Economic Gates**:
  - Bootstrap → Transition: fee_coverage ≥ 20%, stake_ratio ≥ 30%
  - Transition → Mature: fee_coverage ≥ 50%, stake_ratio ≥ 40%
- **Volatility Gate**: Instrumented; consensus enforcement deferred to T205
- **Monotonicity**: No backwards transitions; no phase skipping; Mature is terminal

**MainNet v0 Monetary Epoch State** (T199 + T202 + T203 + T204):

MainNet v0 nodes maintain a consensus-tracked per-epoch monetary state containing the current phase, EMA-smoothed fee inputs, and chosen inflation rate. The inflation rate is subject to per-epoch rate-of-change limits (T203) to ensure smooth transitions. Phase transitions are automatic when time and economic gates are satisfied (T204). Actual seigniorage application is controlled by `monetary_mode` and is initially deployed in Shadow mode.

| Aspect | MainNet v0 Behavior |
| :--- | :--- |
| **Epoch State** | `MonetaryEpochState` computed at each epoch boundary |
| **EMA Smoothing** | `ema_fees_per_epoch` with phase-dependent λ (T202) |
| **Rate-of-Change Limit** | `max_delta_r_inf_per_epoch_bps` per phase (T203) |
| **Phase Transitions** | Automatic via `compute_phase_transition()` (T204) |
| **Default Mode** | Shadow (metrics + state, no balance changes) |
| **Epoch Detection** | Height-based via `epoch_for_height(height, blocks_per_epoch)` |
| **Inflation Calc** | Deterministic via `compute_epoch_state()` calling T195 engine with Δ-limit |
| **Metrics** | Epoch-level gauges exposed via `/metrics` endpoint |

**Key MainNet v0 Monetary Parameters**:

| Parameter | MainNet v0 Value | Governance |
| :--- | :--- | :--- |
| **Initial Phase** | Bootstrap | Hard-coded |
| **R_target (Bootstrap)** | 7.5–9.0% annual (PQC-adjusted) | Tunable within bounds |
| **EMA λ (Bootstrap)** | 700 bps (7%) | Tunable [50, 1500] |
| **EMA λ (Transition)** | 300 bps (3%) | Tunable [20, 500] |
| **EMA λ (Mature)** | 150 bps (1.5%) | Tunable [10, 200] |
| **Max Δ r_inf (Bootstrap)** | 25 bps (0.25%) per epoch | Tunable within bounds |
| **Max Δ r_inf (Transition)** | 10 bps (0.10%) per epoch | Tunable within bounds |
| **Max Δ r_inf (Mature)** | 5 bps (0.05%) per epoch | Tunable within bounds |
| **Fee Burn Ratio** | 50% | Hard-coded (T193) |
| **Proposer Reward Ratio** | 50% | Hard-coded (T193) |
| **Validators Seigniorage Share** | 82% | Tunable [75%, 90%] |
| **Inflation Floor (Bootstrap)** | 0% | Hard-coded |

---

## 4. Mempool & DAG

### 4.1 DAG as Production Mode

For MainNet v0 validator nodes, DAG mempool is the **only** supported mode:

| Mode | MainNet v0 Validators | Other Uses |
| :--- | :--- | :--- |
| **DAG Mempool** | **Required** | Production |
| **FIFO Mempool** | **Not allowed** | Dev/harness only |

### 4.2 Availability Certificates

DAG availability certificates are **required** components for MainNet v0:

| Component | MainNet v0 Status | Description |
| :--- | :--- | :--- |
| **BatchAck** | Required | Validator acknowledgment of batch receipt |
| **BatchCertificate** | Required | 2f+1 acks proving data availability |
| **Fetch-on-miss** | Required (T182, T183) | Recovery protocol for missing batches |
| **Consensus coupling** | **Required** | Proposals must only commit certified batches |

### 4.3 Consensus Coupling to DAG

**MainNet v0 requirement**: HotStuff proposals MUST only commit batches that have valid availability certificates.

> **📋 Design Reference**: The complete DAG–HotStuff consensus coupling semantics are specified in [QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md](./QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md) (T188). This includes:
> - Full protocol flow (batch → cert → proposal → vote → commit)
> - Invariants (I1–I5) for MainNet v0 coupling
> - Block header structure with `batch_commitment`
> - Safety and liveness analysis
> - Phase-by-phase configuration (`dag_coupling_mode`)
>
> **Implementation Status**: Design complete (T188). Implementation pending in T189–T192.

| Rule | Description | Enforcement |
| :--- | :--- | :--- |
| **Certificate Required** | Batches without certificates cannot be proposed | Block validation |
| **Certificate Validity** | Certificates must have 2f+1 valid signatures | Block validation |
| **No Uncertified Batches** | Leader cannot include uncertified data | Block construction |

**Protocol Flow (MainNet)**:

```
1. Validator creates batch → broadcasts to all validators
2. Validators receive batch → issue BatchAck
3. Author collects 2f+1 acks → forms BatchCertificate
4. Only certified batches are eligible for consensus ordering
5. HotStuff leader proposes frontier of certified batches
6. Validators verify all proposed batches have valid certs
7. On 3-chain commit → execute transactions from certified batches
```

For detailed protocol steps, object definitions, and invariant specifications, see [QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md §3](./QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md#3-protocol-flow-with-coupling).

**Operator Monitoring (T192)**: MainNet v0 nodes expose metrics and logging for DAG-coupling invariant violations. Operators are expected to monitor:
- `qbind_dag_coupling_validation_total{result="..."}` - proposal validation outcomes
- `qbind_dag_coupling_block_check_total{result="..."}` - post-commit block checks
- `qbind_dag_coupling_block_mismatch_total` / `qbind_dag_coupling_block_missing_total` - violation counters

Any non-zero violation counters should be investigated. See [QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md §7.4](./QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md#74-t192-block-level-invariant-probes--safety-checks) for details.

#### T221 – DAG–Consensus Coupling Cluster Tests

**MainNet v0** has an automated cluster test harness (`crates/qbind-node/tests/t221_dag_coupling_cluster_tests.rs`) that validates DAG–HotStuff coupling under several scenarios:

1. **Warn mode cluster progress** — Validates that with DAG coupling in Warn mode, the cluster can process transactions and no `block_mismatch` violations occur.
2. **Enforce mode behavior** — Validates that Enforce mode correctly prevents blocks from committing without proper DAG certification.
3. **Off mode baseline** — Validates that Off mode allows normal operation without coupling enforcement.

The tests assert on the same metrics documented above (`qbind_dag_coupling_*`) to verify invariant compliance. This test harness is the normative test artifact for MN-R1 readiness regarding DAG–consensus coupling.

#### T222 – Consensus Chaos Harness

**MainNet v0** includes an adversarial chaos testing harness (`crates/qbind-node/tests/t222_consensus_chaos_harness.rs`) that validates consensus safety and liveness under fault injection:

1. **LeaderCrashAndRecover** — Periodically crashes the leader node, verifying view-changes occur and the cluster recovers without safety violations.
2. **RepeatedViewChangesUnderMessageLoss** — Drops a percentage of proposal/vote messages, triggering timeouts and view-changes while ensuring no double-commits or divergent chains.
3. **ShortPartitionThenHeal** — Temporarily partitions validators into two groups, verifying the majority side maintains quorum and no chain divergence occurs after healing.
4. **MixedFaultsBurst** — Combines message loss, leader crash, and partition for stress testing under multiple simultaneous faults.

**Safety Invariants Checked**:
- `has_commit_divergence == false` — No conflicting committed prefixes
- `block_mismatch_total == 0` — No DAG/Block data mismatches
- Heights converge after faults stop — Liveness recovery

This harness provides "chaos test coverage" for MN-R1 (Consensus Safety & Fork Risk) in the MainNet audit.

### 4.4 DoS Protections and Fee-Aware Eviction

MainNet v0 requires stronger DoS protections in the DAG mempool (T218):

| Protection | MainNet v0 Status | Config Field |
| :--- | :--- | :--- |
| **Fee-aware eviction** | Required (T169) | `enable_fee_priority=true` |
| **Per-sender tx limit** | Required (T218) | `max_pending_per_sender=1,000` |
| **Per-sender bytes limit** | Required (T218) | `max_pending_bytes_per_sender=8MiB` |
| **Batch tx limit** | Required (T218) | `max_txs_per_batch=4,000` |
| **Batch bytes limit** | Required (T218) | `max_batch_bytes=2MiB` |
| **Eviction rate limiting** | Required (T219) | `eviction_mode=enforce` |
| **Stake-weighted quotas** | MainNet v0.x (post-launch) | Not implemented |

**Implementation**: `MempoolDosConfig` struct in `qbind-node/src/node_config.rs`.

**Defaults by Environment**:

| Parameter | DevNet | TestNet Beta | MainNet v0 |
| :--- | :--- | :--- | :--- |
| `max_pending_per_sender` | 10,000 | 2,000 | 1,000 |
| `max_pending_bytes_per_sender` | 64 MiB | 16 MiB | 8 MiB |
| `max_txs_per_batch` | 10,000 | 5,000 | 4,000 |
| `max_batch_bytes` | 4 MiB | 2 MiB | 2 MiB |

**Metrics** (T218):
- `qbind_dag_sender_rate_limited_total`: Total txs rejected due to sender limits
- `qbind_dag_batch_size_limited_total`: Reserved for future batch truncation tracking

**Validation**: `validate_mainnet_invariants()` checks that all DoS config values are sensible for MainNet (all > 0, `max_pending_per_sender < 100,000`).

### 4.4.1 Eviction Rate Limiting (T219/T220)

MainNet v0 requires eviction rate limiting to prevent excessive mempool churn under adversarial conditions:

| Protection | MainNet v0 Status | Config Field |
| :--- | :--- | :--- |
| **Eviction mode** | Enforce (T219/T220) | `mempool_eviction.mode=enforce` |
| **Max evictions/interval** | Required (T219/T220) | `mempool_eviction.max_evictions_per_interval=1,000` |
| **Interval seconds** | Required (T219/T220) | `mempool_eviction.interval_secs=10` |

**Implementation**:
- Config: `MempoolEvictionConfig` struct in `qbind-node/src/node_config.rs` (T219)
- Enforcement: `InMemoryDagMempool::insert_local_txs()` in `qbind-node/src/dag_mempool.rs` (T220)

**Eviction Mode Behavior** (T220 enforcement):

| Mode | Behavior |
| :--- | :--- |
| **Off** | No rate limiting; metrics recorded only. Eviction proceeds as normal. |
| **Warn** | Log warnings when limit exceeded; still allow eviction. Increment `qbind_mempool_eviction_rate_limit_total{mode="warn"}`. |
| **Enforce** | When eviction limit is reached, block further evictions. Incoming transactions that would require eviction are rejected with `EvictionRateLimited` error. Increment `qbind_mempool_eviction_rate_limit_total{mode="enforce"}`. |

**Important**: In Enforce mode, when the eviction rate limit is reached:
- No additional evictions are performed
- New transactions requiring eviction are rejected (not the existing low-priority tx)
- The mempool degrades gracefully by rejecting further incoming txs instead of thrashing

**Defaults by Environment**:

| Parameter | DevNet | TestNet Alpha | TestNet Beta | MainNet v0 |
| :--- | :--- | :--- | :--- | :--- |
| `eviction_mode` | Off | Warn | Enforce | **Enforce** |
| `max_evictions_per_interval` | 10,000 | 5,000 | 2,000 | 1,000 |
| `interval_secs` | 10 | 10 | 10 | 10 |

**Metrics** (T219/T220):
- `qbind_mempool_eviction_mode`: Config gauge (0=off, 1=warn, 2=enforce)
- `qbind_mempool_max_evictions_per_interval`: Config gauge
- `qbind_mempool_eviction_interval_secs`: Config gauge
- `qbind_mempool_evictions_total{reason="capacity"}`: Evictions due to mempool full
- `qbind_mempool_evictions_total{reason="lifetime"}`: Evictions due to TTL
- `qbind_mempool_eviction_rate_limit_total{mode="warn"}`: Warn mode limit hits
- `qbind_mempool_eviction_rate_limit_total{mode="enforce"}`: Enforce mode rejections
- `qbind_mempool_evictions_window_reset_total`: Window reset count

**CLI Options** (T219):
- `--mempool-eviction-mode=off|warn|enforce`
- `--mempool-eviction-max-per-interval=<uint>`
- `--mempool-eviction-interval-secs=<uint>`

**Validation**: `validate_mainnet_invariants()` checks:
- `eviction_mode == Enforce`
- `max_evictions_per_interval > 0`
- `interval_secs >= 1`
- `max_evictions_per_interval < 1,000,000`

### 4.5 MainNet vs Beta: DAG Requirements

| Feature | TestNet Beta | MainNet v0 | MainNet v0.x |
| :--- | :--- | :--- | :--- |
| DAG mempool | Default | **Required** | Required |
| Availability certs | v1 (data-plane) | **Consensus-coupled** | Consensus-coupled |
| Fetch-on-miss | v0 (basic) | **Required** | Enhanced |
| Fee-aware eviction | Enabled | **Required** | Required |
| Per-sender quotas | Moderate (T218) | **Required** (T218) | Required |
| Stake-weighted quotas | Not implemented | Planned | **Required** |

---

## 5. Networking / P2P

### 5.1 P2P Transport v1 (KEMTLS-Based)

P2P transport is the **only** supported mode for MainNet v0 validators:

| Mode | MainNet v0 Validators | Notes |
| :--- | :--- | :--- |
| **P2P (KEMTLS)** | **Required** | Production mode |
| **LocalMesh** | **Not allowed** | Dev/harness only |

### 5.2 MainNet P2P Requirements

MainNet v0 has stronger P2P requirements compared to TestNet Beta:

| Requirement | TestNet Beta | MainNet v0 |
| :--- | :--- | :--- |
| **Transport** | P2P default | P2P **required** |
| **Discovery** | Static peers | **Dynamic discovery** + static fallback |
| **Peer diversity** | Guideline | **Enforced** (min 2 ASNs) |
| **Liveness scoring** | Not implemented | **Required** |
| **Anti-eclipse** | Basic | **Production-grade** |

### 5.3 Dynamic Peer Discovery

MainNet v0 requires dynamic peer discovery:

| Feature | MainNet v0 Status | Description |
| :--- | :--- | :--- |
| **Peer exchange protocol** | **Required** | Validators share known peers |
| **Static peer fallback** | Supported | Configured bootstrap nodes |
| **Discovery interval** | Configurable | Default: 30 seconds |
| **Max discovered peers** | Configurable | Default: 100 |

### 5.4 Anti-Eclipse Constraints

MainNet v0 enforces anti-eclipse measures:

| Constraint | MainNet v0 Requirement | Enforcement |
| :--- | :--- | :--- |
| **Minimum outbound connections** | 8 validators | Node startup check |
| **Peer diversity (ASN)** | ≥2 distinct ASNs | Soft requirement (logged warning) |
| **Peer diversity (region)** | ≥2 regions | Operator guideline |
| **Max connections per IP range** | 4 per /24 | Connection limit |
| **Random peer selection** | Required | Prevents deterministic isolation |

### 5.5 Liveness Scoring and Reconnection

MainNet v0 requires peer liveness scoring:

| Feature | MainNet v0 Status |
| :--- | :--- |
| **Heartbeat protocol** | Required (30s interval) |
| **Liveness scoring** | Required (track responsiveness) |
| **Automatic reconnection** | Required (exponential backoff) |
| **Peer eviction** | Required (low-score peers removed) |

### 5.6 Multi-Region Validation Testing (T238)

MainNet v0 validators are expected to operate across multiple geographic regions with varying network conditions. The T238 multi-region latency harness validates consensus safety and liveness under cross-region scenarios:

| Profile | Description | Key Metrics |
| :--- | :--- | :--- |
| **Uniform latency** | All regions have similar moderate latency (baseline) | Safety, convergence |
| **Asymmetric latency** | One region has significantly higher latency | Height divergence bounds |
| **High jitter** | Cross-region communication has high jitter variance | View-change frequency |
| **Lossy network** | Some region pairs experience packet loss | Safety under message loss |
| **Mixed adversarial** | Combination of latency, jitter, and loss | Full stress test |

**Test Harness**:
```bash
# Run all T238 multi-region tests
cargo test -p qbind-node --test t238_multi_region_latency_harness

# Run specific scenario
cargo test -p qbind-node --test t238_multi_region_latency_harness test_t238_uniform_latency_baseline
```

**Key Invariants Validated**:
- **Safety**: No block mismatches (`block_mismatch_total == 0`) under any scenario
- **Bounded divergence**: Height divergence across nodes stays within acceptable bounds
- **DAG coupling**: Consensus-DAG coupling invariants (I1–I5) maintained

See [QBIND_MAINNET_AUDIT_SKELETON.md §3.5](./QBIND_MAINNET_AUDIT_SKELETON.md#35-mn-r4-p2p--eclipse-resistance) for MN-R4 risk mitigation details.

### 5.7 P2P Implementation Status

From [QBIND_P2P_NETWORK_DESIGN.md](../network/QBIND_P2P_NETWORK_DESIGN.md):

| Component | TestNet Alpha | MainNet v0 Required |
| :--- | :--- | :--- |
| KEMTLS transport | ✅ T172 | Yes |
| Consensus/DAG over P2P | ✅ T173 | Yes |
| P2P receive path | ✅ T174 | Yes |
| Node P2P wiring | ✅ T175 | Yes |
| Peer health monitoring | ✅ T226 | **Yes** |
| Dynamic discovery | ✅ T205–T207 | **Yes** |
| Anti-eclipse measures | ✅ T231 | **Yes** |
| Liveness scoring | ✅ T226 | **Yes** |
| Multi-region testing | ✅ T238 | **Yes** |

---

## 6. Security & Risk Posture (MainNet View)

This section summarizes key security areas and the "risk budget" for MainNet v0. Detailed risk tracking lives in [QBIND_MAINNET_AUDIT_SKELETON.md](./QBIND_MAINNET_AUDIT_SKELETON.md).

### 6.1 Execution/VM Security

| Risk Area | MainNet v0 Mitigation |
| :--- | :--- |
| **Non-determinism** | Property tests (T177, T179); Stage B determinism proofs |
| **State corruption** | Safe integer arithmetic; fuzzing coverage |
| **Gas accounting bugs** | Gas property tests (G1-G5); fee conservation checks |
| **Parallelism bugs** | Stage B vs sequential comparison tests |

**Risk Budget**: VM execution is considered **low-to-medium risk** after T177/T179 property testing.

### 6.2 Gas/Fees and Fee Market Economics

| Risk Area | MainNet v0 Mitigation |
| :--- | :--- |
| **Fee market manipulation** | Simple priority model; EIP-1559 deferred |
| **Balance draining** | Property tests verify fee deduction correctness |
| **DoS via spam** | Gas enforcement + fee-priority eviction + per-sender quotas (T218) |
| **Economic attacks** | Burn + proposer hybrid prevents centralization |
| **Eviction churn** | Eviction rate limiting (T219/T220) |

**Risk Budget**: Fee market is **medium risk**; simple model reduces complexity but may be gameable.

**Adversarial Analysis (T236)**: The fee market has been stress-tested under adversarial conditions including single-sender spam, front-running patterns, and churn attacks. Key findings:
- Safety invariants (no balance underflow, no double-spend) verified across all scenarios
- Per-sender quotas (T218) prevent single-sender monopolization
- Eviction rate limiting (T219/T220) bounds mempool churn
- Honest senders maintain meaningful inclusion rates (>30%) even under aggressive attacks

See [QBIND_FEE_MARKET_ADVERSARIAL_ANALYSIS.md](../econ/QBIND_FEE_MARKET_ADVERSARIAL_ANALYSIS.md) for detailed analysis.

### 6.3 DAG Availability and Consensus Coupling

| Risk Area | MainNet v0 Mitigation |
| :--- | :--- |
| **Data availability holes** | Fetch-on-miss protocol (T182, T183) |
| **Consensus liveness** | Certificate-gated proposals |
| **Certificate forgery** | ML-DSA-44 signatures; 2f+1 quorum |
| **Batch equivocation** | Domain-separated signing preimages |

**Risk Budget**: DAG availability is **medium risk**; consensus coupling is new surface area.

### 6.4 P2P Topology and Anti-Eclipse

| Risk Area | MainNet v0 Mitigation |
| :--- | :--- |
| **Eclipse attacks** | Peer diversity requirements; random selection |
| **Sybil attacks** | Permissioned validator set (stake-weighted) |
| **DoS/bandwidth** | Rate limiting; bounded queues |
| **Network partitions** | Multi-region guidelines; reconnection policies |

**Risk Budget**: P2P topology is **medium-high risk**; validated via T238 multi-region harness.

**Multi-Region Testing (T238)**: The P2P and consensus layers have been stress-tested under simulated multi-region conditions including:
- Asymmetric latency (one slow region)
- High jitter environments
- Lossy network conditions (packet loss)
- Mixed adversarial scenarios

Key findings:
- Safety invariants (no block mismatches) maintained under all tested conditions
- Height convergence stays within acceptable bounds
- View-change recovery functions correctly under latency stress

See [t238_multi_region_latency_harness.rs](../../crates/qbind-node/tests/t238_multi_region_latency_harness.rs) for the normative test artifact.

### 6.5 Key Management and Remote Signer / HSM

| Risk Area | MainNet v0 Mitigation |
| :--- | :--- |
| **Key compromise** | HSM support required for validators |
| **Key separation** | Consensus keys separate from network keys |
| **Key rotation** | Rotation hooks implemented |
| **Remote signing** | Production signer required (no loopback) |

**Signer Mode Configuration (T210)**:

MainNet v0 enforces strict signer mode requirements:

| Signer Mode | Allowed on MainNet | Required Configuration |
| :--- | :--- | :--- |
| `loopback-testing` | ❌ **Forbidden** | - |
| `encrypted-fs` | ✅ Allowed | `--signer-keystore-path` |
| `remote-signer` | ✅ Allowed | `--remote-signer-url` |
| `hsm-pkcs11` | ✅ Recommended | `--hsm-config-path` |

- **LoopbackTesting** is explicitly forbidden on MainNet via `validate_mainnet_invariants()`
- **EncryptedFsV1** is acceptable with strong passphrase management
- **RemoteSigner** and **HsmPkcs11** are recommended for production validators
- **HsmPkcs11** is implemented (T211, PKCS#11 adapter) and production-ready for SoftHSM and vendor HSMs
- **RemoteSigner** is implemented (T212) with TcpKemTlsSignerTransport and qbind-remote-signer daemon

**Example MainNet HSM Configuration**:

```bash
# Start MainNet validator with HSM signer
qbind-node --signer-mode hsm-pkcs11 --hsm-config-path /etc/qbind/hsm.toml
```

**Example MainNet Remote Signer Configuration** (T212):

The recommended architecture for production validators uses a remote signer to isolate key material:

```bash
# On the signer host (runs the remote signer daemon with HSM backend)
export QBIND_HSM_PIN=<pin>
qbind-remote-signer --config /etc/qbind/remote_signer.toml

# On the consensus node (connects to the remote signer)
qbind-node --profile mainnet \
    --signer-mode remote-signer \
    --remote-signer-url kemtls://signer.internal:9443 \
    --data-dir /data/qbind
```

This topology separates consensus logic from key material:
- Consensus node: Runs HotStuff BFT, DAG mempool, P2P networking (no private keys)
- Remote signer: Holds key material, can use HSM backend, rate-limits requests

**Remote Signer Configuration** (`/etc/qbind/remote_signer.toml`):

```toml
listen_addr = "0.0.0.0:9443"
validator_id = 42
backend_mode = "hsm-pkcs11"  # or "encrypted-fs"
hsm_config_path = "/etc/qbind/hsm.toml"
rate_limit_rps = 100
```

**Risk Budget**: Key management is **high risk** area; HSM + remote signer recommended for MainNet.

#### 6.5.1 HSM / Remote Signer Availability and Failure Semantics (T214)

MainNet validators must treat signer/HSM availability as a **hard dependency**:

1. **Fail-Closed Behavior**: On signer failure (HSM error, remote signer unreachable), the node exits immediately rather than continuing without signing capability.

2. **Failure Mode Configuration**:
   - `SignerFailureMode::ExitOnFailure` – **Required for MainNet**
   - `SignerFailureMode::LogAndContinue` – Forbidden on MainNet (only for dev/test chaos testing)

3. **Expected Behavior on Signer Failure**:
   - Node logs error at `error!` level
   - Node increments failure metrics (`qbind_hsm_sign_error_total`, `qbind_remote_sign_failures_total`)
   - Node terminates process
   - External orchestration (systemd, k8s, etc.) may restart on same or replacement signer

4. **Health Signaling**:
   - `qbind_hsm_startup_ok` metric indicates startup health check result
   - `NodeMetrics::signer_health()` derives aggregate health (Healthy/Degraded/Failed)

5. **Redundancy Pattern**: Redundancy is achieved via external orchestration, not automatic in-node failover. See [QBIND_KEY_MANAGEMENT_DESIGN.md §3.7](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md#37-signer-failure-modes--redundancy-patterns-t214) for recommended patterns.

#### 6.5.2 Compromised Key Handling (T217)

MainNet validators must have documented procedures for responding to key compromise:

1. **Normative Design Guidance**: Compromise scenarios, blast radius, detection signals, and epoch-level rotation semantics are defined in [QBIND_KEY_MANAGEMENT_DESIGN.md §5.4](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md#54-compromised-key-handling-t217).

2. **Operational Playbooks**: Step-by-step incident procedures for suspected/confirmed compromise, HSM vs host compromise, P2P key compromise, and batch signing key compromise are documented in [QBIND_MAINNET_RUNBOOK.md §10.5](../ops/QBIND_MAINNET_RUNBOOK.md#105-compromised-key-incident-procedures-t217).

3. **Key Rotation Machinery**: All compromise response uses the T213 `KeyRotationEvent` and CLI helper (`qbind-key-rotation`) with appropriate `effective_epoch` and `grace_epochs` parameters for emergency vs planned rotations.

**MainNet Validator Requirements**:
- Operators must be familiar with compromise detection signals
- Emergency key rotation procedures must be tested during onboarding
- Incident response contacts must be established before MainNet participation

### 6.6 Risk Summary Table

| Area | Severity | MainNet v0 Status | Notes |
| :--- | :--- | :--- | :--- |
| Execution/VM | Medium | Partially Mitigated | Stage B needs validation |
| Gas/Fees | Medium | Partially Mitigated | Simple model; future EIP-1559 |
| DAG/Availability | Medium | Partially Mitigated | Consensus coupling new |
| P2P/Eclipse | Medium-High | Planned | Production validation needed |
| Key Management | High | Mitigated | HSM (T211) + Remote Signer (T212) + T214 fail-closed |
| Slashing/PQC Offenses | High | Design Ready (T227) | Design complete; implementation pending (T228+) |

**Risk Areas (T211 – HSM/PKCS#11, T212 – Remote Signer, T214 – Redundancy)**:

- HSM availability is a hard dependency (validator offline if HSM down)
- Startup invariants enforce presence of HSM/signer config
- Remote signer startup checks verify connectivity before consensus participation
- **T214**: Fail-closed behavior enforced (`SignerFailureMode::ExitOnFailure` required on MainNet)
- **T214**: Redundancy achieved via external orchestration, documented patterns available

---

### 6.7 PQC-Specific Slashing Rules (T227)

MainNet v0 defines a slashing model for PQC-specific consensus offenses. The full design is documented in [QBIND_SLASHING_AND_PQC_OFFENSES_DESIGN.md](../consensus/QBIND_SLASHING_AND_PQC_OFFENSES_DESIGN.md).

#### 6.7.1 Offense Classes Summary

| ID | Offense | Severity | Slash Range |
| :--- | :--- | :--- | :--- |
| **O1** | Classical Double-Signing | Critical | 5–10% |
| **O2** | Invalid Consensus Signature as Proposer | High | 5% |
| **O3a** | Single Lazy Vote | Medium | 0–0.5% |
| **O3b** | Repeated Lazy Votes | High | 1–3% |
| **O4** | Invalid DAG Certificate Propagation | High | 5–10% |
| **O5** | DAG/Consensus Coupling Violations | Medium-High | 1–5% |

#### 6.7.2 PQC Verification Incentives

ML-DSA-44 signature verification is ~5× more expensive than classical EdDSA. The slashing model ensures:

1. **Verification is economically dominant**: Expected slash cost exceeds CPU savings from skipping verification
2. **Lazy validators are detectable**: O3 offenses catch validators voting without verifying
3. **DAG integrity is protected**: O4/O5 offenses protect availability layer from invalid certificates

#### 6.7.3 Evidence Requirements

All slashing offenses require objective, on-chain-verifiable evidence:

- **O1/O2**: Conflicting signatures or invalid signature proof
- **O3**: Vote for invalid block + proof of block invalidity
- **O4**: Invalid DAG certificate with verification failure details
- **O5**: Block header with invalid batch_commitment + DAG state proof

#### 6.7.4 Implementation Status

| Component | Status | Task |
| :--- | :--- | :--- |
| Slashing design | ✅ Design Ready | T227 |
| Slashing infrastructure | ✅ Evidence Recording Only | T228 |
| Penalty engine | ✅ Implemented | T229 |
| Ledger backend | ✅ Implemented | T230 |

**MainNet v0 Launch**: The slashing pipeline is fully implemented:
- **T227**: Offense taxonomy (O1–O5) and slash ranges design
- **T228**: Evidence envelope and infrastructure (`NoopSlashingEngine`)
- **T229**: `PenaltySlashingEngine` with `SlashingBackend` trait and `SlashingMode` configuration
- **T230**: `SlashingLedger` trait and `LedgerSlashingBackend` for persistent stake/jail state

**Important**: MainNet defaults to `SlashingMode::RecordOnly` — evidence is recorded and metrics are emitted, but **no stake is burned and no validators are jailed**. Governance can later enable `SlashingMode::EnforceCritical` to apply O1/O2 penalties.

**T230 Scope**: The slashing ledger backend provides:
- `SlashingLedger` trait in `qbind-ledger` for validator stake/jail state management
- `InMemorySlashingLedger` for testing
- `LedgerSlashingBackend` implementing `SlashingBackend` using ledger storage
- `SlashingMetrics` for Prometheus monitoring (evidence counts, penalties, stake burned, jail events)
- Slashing records persisted for CLI/tooling inspection

**Slashing Mode Summary**:
| Mode | Evidence | Metrics | Slash Stake | Jail | Use Case |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `Off` | ❌ | ❌ | ❌ | ❌ | Dev tools only |
| `RecordOnly` | ✅ | ✅ | ❌ | ❌ | **MainNet default** |
| `EnforceCritical` | ✅ | ✅ | O1/O2 | O1/O2 | DevNet default, future MainNet |
| `EnforceAll` | ✅ | ✅ | O1–O5 | All | Reserved for future |

**Note**: Operators will see evidence warnings in logs and metrics. When governance enables `EnforceCritical`, O1 (double-sign) and O2 (invalid proposer sig) offenses will trigger stake slashing and jailing.

---

## 7. Operational Profiles & CLI Defaults

### 7.1 MainNet Profile

A canonical MainNet profile is available via the `--profile` CLI flag:

```bash
# Using the --profile flag (recommended)
qbind-node --profile mainnet --data-dir /data/qbind

# Or with the short flag
qbind-node -P mainnet -d /data/qbind
```

> **Implementation Status (T185)**: The MainNet profile is implemented in code via
> `ConfigProfile::MainNet` and `NodeConfig::mainnet_preset()`. The startup path
> validates all MainNet invariants via `validate_mainnet_invariants()` and refuses
> to start if any invariant is violated.

### 7.2 MainNet Configuration Parameters

| Parameter | CLI Flag | MainNet Default | Notes |
| :--- | :--- | :--- | :--- |
| **Profile** | `--profile` / `-P` | N/A | Use `mainnet` for canonical preset |
| Environment | `--env` | `mainnet` | **MainNet chain ID** |
| Execution Profile | `--execution-profile` | `vm-v0` | Same as Beta |
| Gas Enforcement | `--enable-gas` | `true` | **Cannot be disabled** |
| Fee Priority | `--enable-fee-priority` | `true` | **Cannot be disabled** |
| Mempool Mode | `--mempool-mode` | `dag` | **DAG only** for validators |
| DAG Availability | `--enable-dag-availability` | `true` | **Required** |
| Network Mode | `--network-mode` | `p2p` | **P2P only** for validators |
| P2P Transport | `--enable-p2p` | `true` | **Required** |
| Stage B Parallel | `--enable-stage-b` | `true` | **Enabled by default** |
| Discovery | `--enable-discovery` | `true` | **Required** |
| Data Directory | `--data-dir` / `-d` | Required | **Mandatory** |
| Signer Mode | `--signer-mode` | `encrypted-fs` | **No loopback** (T210) |
| Signer Keystore | `--signer-keystore-path` | Required for `encrypted-fs` | Path to keystore |
| Remote Signer URL | `--remote-signer-url` | Required for `remote-signer` | gRPC/Unix socket |
| HSM Config | `--hsm-config-path` | Required for `hsm-pkcs11` | PKCS#11 config |

### 7.3 NodeConfig Example (MainNet)

```rust
use qbind_node::{NodeConfig, ConfigProfile, MempoolMode, NetworkMode, SignerMode};

// Option 1: Use the canonical preset with EncryptedFs (recommended for most)
let config = NodeConfig::mainnet_preset()
    .with_data_dir("/data/qbind")
    .with_signer_keystore_path("/data/qbind/keystore");

// Option 2: Use HSM for maximum security (recommended for production validators)
let config = NodeConfig::mainnet_preset()
    .with_data_dir("/data/qbind")
    .with_signer_mode(SignerMode::HsmPkcs11)
    .with_hsm_config_path("/etc/qbind/hsm.toml");

// Option 3: Use remote signer for distributed signing infrastructure (T212)
let config = NodeConfig::mainnet_preset()
    .with_data_dir("/data/qbind")
    .with_signer_mode(SignerMode::RemoteSigner)
    .with_remote_signer_url("kemtls://signer.internal:9443");

// Verify MainNet defaults
assert!(config.gas_enabled);
assert!(config.enable_fee_priority);
assert_eq!(config.mempool_mode, MempoolMode::Dag);
assert_eq!(config.network_mode, NetworkMode::P2p);
assert!(config.dag_availability_enabled);
assert!(config.stage_b_enabled);
assert!(config.network.discovery_enabled);  // T205: Discovery required
assert_eq!(config.signer_mode, SignerMode::RemoteSigner);  // T210: Matches Option 3
```

### 7.4 Standard MainNet Validator Node

A "standard MainNet validator node" with encrypted keystore:

```bash
qbind-node \
  --profile mainnet \
  --data-dir /data/qbind \
  --signer-mode encrypted-fs \
  --signer-keystore-path /data/qbind/keystore \
  --validator-id 42 \
  --p2p-listen-addr 0.0.0.0:9000 \
  --p2p-advertised-addr validator42.qbind.network:9000 \
  --bootstrap-peers mainnet-bootstrap-1.qbind.network:9000,mainnet-bootstrap-2.qbind.network:9000
```

A "production MainNet validator node" with HSM (recommended):

```bash
qbind-node \
  --profile mainnet \
  --data-dir /data/qbind \
  --signer-mode hsm-pkcs11 \
  --hsm-config-path /etc/qbind/hsm.toml \
  --validator-id 42 \
  --p2p-listen-addr 0.0.0.0:9000 \
  --p2p-advertised-addr validator42.qbind.network:9000 \
  --bootstrap-peers mainnet-bootstrap-1.qbind.network:9000,mainnet-bootstrap-2.qbind.network:9000
```

---

## 8. Compatibility & Migration

### 8.1 TestNet Beta → MainNet v0 Roadmap

| Step | Description | Coordination Required |
| :--- | :--- | :--- |
| 1 | Complete all MainNet-blocking tasks | Engineering |
| 2 | External security audit | External auditor |
| 3 | Genesis block creation | Governance |
| 4 | Validator onboarding | Validators |
| 5 | MainNet launch | All parties |

### 8.2 Configuration Changes

| Configuration | TestNet Beta | MainNet v0 | Migration Impact |
| :--- | :--- | :--- | :--- |
| **Chain ID** | TestNet | **MainNet** | New genesis required |
| **Domain tags** | `QBIND:TST:*:v1` | `QBIND:MAIN:*:v1` | Signatures incompatible |
| **Fee policy** | Burn only | Hybrid | Protocol change |
| **Consensus coupling** | Data-plane certs | Consensus-coupled | Protocol change |
| **Payload format** | v0 + v1 | **v1 only** | Client migration |

### 8.3 Misconfiguration Handling

| Scenario | MainNet v0 Behavior |
| :--- | :--- |
| **Gas disabled** | Node refuses to start |
| **LocalMesh mode** | Node refuses to start (validator) |
| **In-memory state** | Node refuses to start (validator) |
| **v0 payload submitted** | Transaction rejected at mempool |
| **Uncertified batch proposed** | Block rejected by validators |
| **Wrong chain ID** | Signatures invalid; consensus failure |

---

## 9. Roadmap: Ready vs Pending

### 9.1 Required and Ready for MainNet v0

| Item | Status | Reference |
| :--- | :--- | :--- |
| VM v0 execution semantics | ✅ Ready | [QBIND_TESTNET_ALPHA_SPEC.md §2](../testnet/QBIND_TESTNET_ALPHA_SPEC.md) |
| RocksDB state persistence | ✅ Ready | [QBIND_TESTNET_ALPHA_SPEC.md §4.4](../testnet/QBIND_TESTNET_ALPHA_SPEC.md) |
| Gas enforcement | ✅ Ready | T168 |
| Fee-priority mempool | ✅ Ready | T169 |
| DAG mempool + availability certs v1 | ✅ Ready | T158, T165 |
| P2P transport v1 | ✅ Ready | T172, T173, T174, T175 |
| Property-based tests (T177) | ✅ Ready | T177 |
| Gas-aware property tests (T179) | ✅ Ready | T179 |
| Beta configuration profile | ✅ Ready | T180 |
| Fetch-on-miss v0 | ✅ Ready | T182, T183 |
| Stage B parallel skeleton | ✅ Ready | T171 |
| **MainNet configuration profile** | ✅ Ready | T185 |

### 9.2 Required but Pending (MainNet Blockers)

| Item | Status | Blocking Task |
| :--- | :--- | :--- |
| **Consensus coupling to DAG** | ⏳ Pending | Future task |
| **Dynamic peer discovery** | ⏳ Pending | Future task |
| **Peer liveness scoring** | ⏳ Pending | Future task |
| **Anti-eclipse enforcement** | ⏳ Pending | Future task |
| **State pruning** | ✅ Implemented | T208 |
| **State snapshots** | ✅ Implemented | T215 |
| **HSM production integration** | ⏳ Pending | Future task |
| **Hybrid fee distribution** | ✅ Implemented | T193 |
| **Stage B production wiring** | ⏳ Pending | Future task |
| **External security audit** | ⏳ Pending | External |

### 9.3 Out of Scope for MainNet v0

| Item | Target Phase | Notes |
| :--- | :--- | :--- |
| EIP-1559-style fee market | MainNet v1+ | Simple priority for v0 |
| Smart contracts | MainNet v1+ | Transfer-only in v0 |
| ZK L2 integration | MainNet v2+ | Future work |
| Light client support | MainNet v1+ | Full nodes only in v0 |
| Cross-shard transactions | MainNet v2+ | Single-shard in v0 |
| Validator slashing | MainNet v0.x | Post-launch enhancement |
| Stake-weighted DAG quotas | MainNet v0.x | Post-launch enhancement |

---

## 10. Operational Runbook & Observability

### 10.1 MainNet Operational Runbook

The canonical **MainNet v0 Operational Runbook** is available at:

- **[QBIND_MAINNET_RUNBOOK.md](../ops/QBIND_MAINNET_RUNBOOK.md)**

This runbook provides detailed guidance for:

- **Node roles and topology**: Validator, sentry, and RPC node configurations
- **Configuration profiles**: Required settings and invariants for MainNet
- **Bootstrapping**: Step-by-step procedure for new validator setup
- **Signer modes**: EncryptedFsV1, RemoteSigner, and HsmPkcs11 configuration
- **Snapshots and fast sync**: State snapshot management and fast sync procedures
- **Key rotation**: Procedures for rotating consensus, batch signing, and P2P keys
- **P2P operations**: Diversity enforcement, anti-eclipse, and liveness monitoring
- **Monetary telemetry**: Phase tracking, inflation rates, and fee coverage monitoring
- **Incident playbooks**: Handling compromised keys, signer failures, and state issues

### 10.2 Prometheus Alerting

Example Prometheus alert rules are provided at:

- **[prometheus/qbind_mainnet_alerts.example.yaml](../ops/prometheus/qbind_mainnet_alerts.example.yaml)**

Alert categories include:

| Category | Examples |
| :--- | :--- |
| **Consensus Health** | View lag, QC formation stalls |
| **P2P Health** | Outbound peer count, diversity violations |
| **Signer/HSM** | Error rates, startup failures |
| **State/Storage** | State size, snapshot failures |
| **Monetary** | Phase anomalies, fee coverage drops |

### 10.3 Grafana Dashboard

An importable Grafana dashboard is available at:

- **[grafana/qbind_mainnet_dashboard.example.json](../ops/grafana/qbind_mainnet_dashboard.example.json)**

Dashboard panels by domain:

1. **Consensus & DAG**: View progress, QC latency, DAG coupling validation
2. **P2P & Diversity**: Peer counts, diversity buckets, heartbeats
3. **State & Storage**: State size, pruning rate, snapshot status
4. **Monetary**: Phase, inflation rates, fee coverage
5. **Signer/HSM**: Health status, error rates, latency

---

## 11. Governance & Upgrades (T224, T225)

### 11.1 Governance Model Overview

MainNet v0 uses **off-chain governance** with a **Protocol Council** model:

| Aspect | MainNet v0 Approach |
| :--- | :--- |
| **Decision Making** | Off-chain deliberation via governance forum and async discussion |
| **Approval Mechanism** | M-of-N (5-of-7) PQC multi-signature by Protocol Council |
| **Enforcement** | Social consensus + operator compliance |
| **Audit Trail** | Signed Upgrade Envelopes published to governance repository |

**Key Principle**: No single individual or key can unilaterally change the protocol. All protocol upgrades require cryptographic approval from a supermajority of the Protocol Council.

For the complete governance design, threat model, and detailed procedures, see:
- **[QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md](../gov/QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md)**

### 11.2 Upgrade Classes

All upgrades are classified into three classes:

| Class | Description | Examples | Coordination |
| :--- | :--- | :--- | :--- |
| **Class A** | Non-consensus changes | CLI, docs, observability | None (maintainer approval) |
| **Class B** | Consensus-compatible | Performance, internal refactoring | Rolling (council envelope) |
| **Class C** | Hard-fork / protocol changes | Consensus rules, block format, monetary policy | Coordinated activation |

### 11.3 Upgrade Envelope

Each Council-approved upgrade is documented in a signed **Upgrade Envelope** containing:

- Protocol version (major.minor.patch)
- Binary hashes for all platforms (SHA3-256)
- Activation height (for Class C upgrades)
- Network environment (mainnet/testnet/devnet)
- Upgrade class (a_non_consensus, b_consensus_compatible, c_hard_fork)
- Council member signatures (ML-DSA-44)

**T225 Implementation**: The `qbind-gov` crate and `qbind-envelope` CLI tool provide:

```bash
# Inspect envelope contents
qbind-envelope inspect envelope.json

# Verify envelope signatures and binary hash
qbind-envelope verify \
  --envelope envelope.json \
  --council-keys council-pubkeys.json \
  --binary /usr/local/bin/qbind-node \
  --platform linux-x86_64
```

Operators MUST verify the Upgrade Envelope before deploying any upgrade:
1. Verify ≥M council signatures are valid (5-of-7 for normal, 4-of-7 for emergency)
2. Verify binary hash matches envelope
3. Verify activation parameters match expected values

### 11.4 Upgrade Process Summary

**Class C (Hard-Fork) Process**:

1. **Design**: RFC published and reviewed (2+ weeks)
2. **Implement**: Code merged, deployed to DevNet
3. **Test**: Chaos harness (T222) + Stage B soak (T223) on TestNet Beta
4. **Approve**: Council signs Upgrade Envelope (5-of-7)
5. **Deploy**: Operators upgrade before activation height
6. **Activate**: Protocol change active at specified height

**Emergency Patches**: Abbreviated process with 4-of-7 threshold for critical security fixes.

### 11.5 Operational References

For operator-facing procedures:
- **Upgrade Checklists**: [QBIND_MAINNET_RUNBOOK.md §11](../ops/QBIND_MAINNET_RUNBOOK.md#11-upgrade-procedures--governance-hooks-t224)
- **Emergency Downgrade**: See runbook emergency procedures

### 11.6 On-Chain Governance Roadmap

On-chain governance is explicitly **out of scope for v0**, but planned for future versions:

| Phase | Scope | Timeline |
| :--- | :--- | :--- |
| **v0** | Off-chain council + multi-sig | Current |
| **v0.x** | On-chain upgrade signaling | 6-12 months |
| **v1.0** | On-chain parameter governance | 12-18 months |
| **v1.x** | Full on-chain voting | 18-24 months |

The v0 off-chain model is designed to be compatible with future on-chain migration without breaking the mental model.

---

## 12. External Security Audit (T235)

### 12.1 Audit Requirement

Before MainNet v0 launch, the protocol **must undergo an external security audit** covering all critical subsystems:

| Area | Description |
| :--- | :--- |
| **Consensus & DAG** | HotStuff BFT, DAG availability certificates, consensus coupling |
| **Execution** | VM v0, Stage B parallel execution, state transitions |
| **PQC Cryptography** | ML-DSA-44 signatures, ML-KEM-768 key exchange, KEMTLS |
| **P2P Networking** | Transport, discovery, liveness, anti-eclipse protections |
| **Key Management** | HSM integration, remote signer, key rotation hooks |
| **Slashing** | PQC offense taxonomy, penalty engine, ledger backend |
| **Monetary Policy** | Phase transitions, EMA smoothing, seigniorage distribution |
| **Genesis & Governance** | Genesis validation, hash commitment, upgrade envelope |

### 12.2 RFP & Scope Document

The complete audit scope, vendor requirements, and expected deliverables are specified in:

- **[QBIND_EXTERNAL_SECURITY_AUDIT_RFP.md](../audit/QBIND_EXTERNAL_SECURITY_AUDIT_RFP.md)** (T235)

### 12.3 Launch Gate Requirements

MainNet v0 launch requires that:

1. **All Critical findings** from the external audit are remediated
2. **All High findings** are remediated OR explicitly accepted by governance with documented rationale
3. The **final audit report** is published (redacted if necessary for security)
4. Operators can verify the **audited commit hash** matches the binary they are running

### 12.4 Operator Verification

Before running a MainNet validator, operators MUST:

1. Verify the binary matches the audited commit (via hash or reproducible build)
2. Read the summarized audit findings and any governance-accepted residual risks
3. Only run builds at or after the "audited commit" unless explicitly instructed otherwise via governance

See [QBIND_MAINNET_RUNBOOK.md §4](../ops/QBIND_MAINNET_RUNBOOK.md#4-bootstrapping-a-fresh-mainnet-validator) for operational procedures.

---

## 13. Related Documents

| Document | Path | Description |
| :--- | :--- | :--- |
| **MainNet Runbook** | [QBIND_MAINNET_RUNBOOK.md](../ops/QBIND_MAINNET_RUNBOOK.md) | MainNet operational runbook (T216) |
| **MainNet Audit** | [QBIND_MAINNET_AUDIT_SKELETON.md](./QBIND_MAINNET_AUDIT_SKELETON.md) | MainNet risk and readiness tracking |
| **External Audit RFP** | [QBIND_EXTERNAL_SECURITY_AUDIT_RFP.md](../audit/QBIND_EXTERNAL_SECURITY_AUDIT_RFP.md) | External security audit scope and requirements (T235) |
| **Launch Gates Test Harness** | `crates/qbind-node/tests/t237_mainnet_launch_profile_tests.rs` | Launch gates & profile freeze tests (T237) |
| **Governance & Upgrades Design** | [QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md](../gov/QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md) | Governance and upgrade envelope design (T224, T225) |
| **DAG Consensus Coupling** | [QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md](./QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md) | DAG–HotStuff coupling design (T188) |
| **Monetary Policy Design** | [QBIND_MONETARY_POLICY_DESIGN.md](../econ/QBIND_MONETARY_POLICY_DESIGN.md) | Monetary policy and inflation design (T194) |
| TestNet Beta Spec | [QBIND_TESTNET_BETA_SPEC.md](../testnet/QBIND_TESTNET_BETA_SPEC.md) | TestNet Beta architecture |
| TestNet Beta Audit | [QBIND_TESTNET_BETA_AUDIT_SKELETON.md](../testnet/QBIND_TESTNET_BETA_AUDIT_SKELETON.md) | Beta risk tracker |
| TestNet Alpha Spec | [QBIND_TESTNET_ALPHA_SPEC.md](../testnet/QBIND_TESTNET_ALPHA_SPEC.md) | TestNet Alpha architecture |
| TestNet Alpha Audit | [QBIND_TESTNET_ALPHA_AUDIT.md](../testnet/QBIND_TESTNET_ALPHA_AUDIT.md) | Alpha risk and readiness |
| Gas and Fees Design | [QBIND_GAS_AND_FEES_DESIGN.md](../testnet/QBIND_GAS_AND_FEES_DESIGN.md) | Gas and fee specification |
| DAG Mempool Design | [QBIND_DAG_MEMPOOL_DESIGN.md](../devnet/QBIND_DAG_MEMPOOL_DESIGN.md) | DAG architecture |
| Parallel Execution Design | [QBIND_PARALLEL_EXECUTION_DESIGN.md](../devnet/QBIND_PARALLEL_EXECUTION_DESIGN.md) | Stage A/B parallelism |
| P2P Network Design | [QBIND_P2P_NETWORK_DESIGN.md](../network/QBIND_P2P_NETWORK_DESIGN.md) | P2P networking architecture |
| P2P TestNet Alpha Guide | [QBIND_P2P_TESTNET_ALPHA_GUIDE.md](../network/QBIND_P2P_TESTNET_ALPHA_GUIDE.md) | Multi-process runbook |
| DevNet v0 Freeze | [QBIND_DEVNET_V0_FREEZE.md](../devnet/QBIND_DEVNET_V0_FREEZE.md) | DevNet v0 baseline |
| Chain ID and Domains | [QBIND_CHAIN_ID_AND_DOMAINS.md](../devnet/QBIND_CHAIN_ID_AND_DOMAINS.md) | Domain separation |

---

*End of Document*