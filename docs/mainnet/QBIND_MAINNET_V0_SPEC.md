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
| **Metrics** | ✅ Available | `stage_b_enabled`, `stage_b_blocks_total`, etc. |

**Stage B Algorithm Summary** (from [QBIND_PARALLEL_EXECUTION_DESIGN.md](../devnet/QBIND_PARALLEL_EXECUTION_DESIGN.md)):

1. Extract read/write sets for each transaction
2. Build conflict graph based on account overlap
3. Generate parallel schedule (topological layering)
4. Execute layers in parallel with Rayon
5. Merge results deterministically

**Critical Invariant**: All validators MUST produce identical state regardless of parallel vs sequential execution. This is verified by T187 CI tests.

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

### 2.6 MainNet-Only Invariants

The following invariants are **enforced** for MainNet v0:

1. **No in-memory-only validator nodes**: All validators MUST use persistent storage
2. **No LocalMesh networking**: P2P transport is required
3. **No gas-disabled mode**: Gas enforcement cannot be turned off
4. **No v0 payloads**: Only `TransferPayloadV1` accepted
5. **No loopback signer**: Production signing required (HSM or EncryptedFs)
6. **Snapshots enabled**: Periodic snapshots must be enabled (T215)

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

### 4.4 DoS Protections and Fee-Aware Eviction

MainNet v0 requires stronger DoS protections in the DAG mempool:

| Protection | MainNet v0 Status |
| :--- | :--- |
| **Fee-aware eviction** | Required (T169) |
| **Rate limiting per sender** | Required |
| **Stake-weighted quotas** | MainNet v0.x (post-launch) |
| **Batch size limits** | Required |

### 4.5 MainNet vs Beta: DAG Requirements

| Feature | TestNet Beta | MainNet v0 | MainNet v0.x |
| :--- | :--- | :--- | :--- |
| DAG mempool | Default | **Required** | Required |
| Availability certs | v1 (data-plane) | **Consensus-coupled** | Consensus-coupled |
| Fetch-on-miss | v0 (basic) | **Required** | Enhanced |
| Fee-aware eviction | Enabled | **Required** | Required |
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

### 5.6 P2P Implementation Status

From [QBIND_P2P_NETWORK_DESIGN.md](../network/QBIND_P2P_NETWORK_DESIGN.md):

| Component | TestNet Alpha | MainNet v0 Required |
| :--- | :--- | :--- |
| KEMTLS transport | ✅ T172 | Yes |
| Consensus/DAG over P2P | ✅ T173 | Yes |
| P2P receive path | ✅ T174 | Yes |
| Node P2P wiring | ✅ T175 | Yes |
| Peer health monitoring | ⏳ Planned | **Yes** |
| Dynamic discovery | ⏳ Planned | **Yes** |
| Anti-eclipse measures | ⏳ Planned | **Yes** |
| Liveness scoring | ⏳ Planned | **Yes** |

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
| **DoS via spam** | Gas enforcement + fee-priority eviction |
| **Economic attacks** | Burn + proposer hybrid prevents centralization |

**Risk Budget**: Fee market is **medium risk**; simple model reduces complexity but may be gameable.

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

**Risk Budget**: P2P topology is **medium-high risk**; requires production validation.

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

### 6.6 Risk Summary Table

| Area | Severity | MainNet v0 Status | Notes |
| :--- | :--- | :--- | :--- |
| Execution/VM | Medium | Partially Mitigated | Stage B needs validation |
| Gas/Fees | Medium | Partially Mitigated | Simple model; future EIP-1559 |
| DAG/Availability | Medium | Partially Mitigated | Consensus coupling new |
| P2P/Eclipse | Medium-High | Planned | Production validation needed |
| Key Management | High | Mitigated | HSM (T211) + Remote Signer (T212) + T214 fail-closed |

**Risk Areas (T211 – HSM/PKCS#11, T212 – Remote Signer, T214 – Redundancy)**:

- HSM availability is a hard dependency (validator offline if HSM down)
- Startup invariants enforce presence of HSM/signer config
- Remote signer startup checks verify connectivity before consensus participation
- **T214**: Fail-closed behavior enforced (`SignerFailureMode::ExitOnFailure` required on MainNet)
- **T214**: Redundancy achieved via external orchestration, documented patterns available

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

## 10. Related Documents

| Document | Path | Description |
| :--- | :--- | :--- |
| **MainNet Audit** | [QBIND_MAINNET_AUDIT_SKELETON.md](./QBIND_MAINNET_AUDIT_SKELETON.md) | MainNet risk and readiness tracking |
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