# QBIND TestNet Beta v0 Specification

**Task**: T178  
**Status**: Design Specification  
**Date**: 2026-01-31

---

## 1. Scope & Positioning

### 1.1 What "TestNet Beta" Means

TestNet Beta is the second phase of the QBIND public test network, extending TestNet Alpha with:

- **Network Environment**: `NetworkEnvironment::Testnet` (`QBIND_TESTNET_CHAIN_ID`) — same as Alpha
- **Execution Profile**: `ExecutionProfile::VmV0` — same VM semantics as Alpha
- **Configuration Profile**: Beta-specific defaults that differ from Alpha

**Key Distinction**: TestNet Beta uses the same network environment and chain ID as TestNet Alpha, but with a different **default configuration profile** that enables features that were opt-in or disabled in Alpha.

### 1.2 Beta vs Alpha Configuration Defaults

| Configuration | TestNet Alpha Default | TestNet Beta Default |
| :--- | :--- | :--- |
| **Gas Enforcement** | Disabled (`enabled = false`) | Enabled (`enabled = true`) |
| **Fee Priority Mempool** | Disabled (`enable_fee_priority = false`) | Enabled (`enable_fee_priority = true`) |
| **Mempool Mode** | FIFO (default), DAG opt-in | DAG (default), FIFO fallback |
| **Network Mode** | LocalMesh (default), P2P opt-in | P2P (default), LocalMesh for dev/harness |
| **P2P Transport** | Disabled (`enable_p2p = false`) | Enabled (`enable_p2p = true`) |

### 1.3 Phase Comparison Table

| Phase | Execution Profile | Gas/Fees | Mempool | Networking |
| :--- | :--- | :--- | :--- | :--- |
| **DevNet v0** | NonceOnly | None | FIFO | LocalMesh |
| **TestNet Alpha** | VmV0 (no gas) | Design only | FIFO + DAG opt-in | LocalMesh default, P2P opt-in |
| **TestNet Beta** | VmV0 (gas on by default) | Enforced + fee priority | DAG as default | P2P as default |
| **MainNet** | VmV0+ (Stage B parallelism) | Full enforcement + governance | DAG + DoS protection | Full P2P + discovery |

### 1.4 Intended Use Case

TestNet Beta is the **gas-on, fee-market-on, DAG-default, P2P-preferred** test network:

- Validators and developers can test real gas accounting and fee behavior
- DAG mempool availability certificates operate in normal mode
- P2P networking is exercised in multi-machine/multi-region configurations
- Serves as the final validation environment before MainNet

> **For the risk-oriented view and readiness checklist of TestNet Beta, see [QBIND_TESTNET_BETA_AUDIT_SKELETON.md](./QBIND_TESTNET_BETA_AUDIT_SKELETON.md).**

---

## 2. Execution & State

### 2.1 Execution Profile

TestNet Beta uses the same `ExecutionProfile::VmV0` as TestNet Alpha:

- **Transaction Type**: Transfer-only (recipient + amount)
- **Account State**: Nonce + Balance per account
- **Execution Order**: Sequential within blocks (deterministic)

**Reference**: [QBIND_TESTNET_ALPHA_SPEC.md §2](./QBIND_TESTNET_ALPHA_SPEC.md) for full VM v0 semantics.

### 2.2 State Persistence

RocksDB-backed persistent account state is **required** for TestNet Beta nodes:

- All production Beta nodes must use persistent storage via `data_dir` configuration
- In-memory state is only acceptable for testing/development
- `CachedPersistentAccountState` provides write-through caching for durability

**Reference**: [QBIND_TESTNET_ALPHA_SPEC.md §4.4](./QBIND_TESTNET_ALPHA_SPEC.md) for persistence details.

### 2.3 Stage B Parallelism

Stage B conflict-graph-based parallel execution is **not a Beta requirement**:

- Beta continues with sequential execution (same as Alpha)
- Stage B parallelism is targeted for MainNet
- The Stage B skeleton exists (T171) but is not wired into production

**Reference**: [QBIND_PARALLEL_EXECUTION_DESIGN.md §4.2](../devnet/QBIND_PARALLEL_EXECUTION_DESIGN.md) for Stage B design.

---

## 3. Gas & Fees (Beta Defaults)

### 3.1 Gas Enforcement

TestNet Beta enables gas enforcement **by default**:

| Parameter | Beta Default | Notes |
| :--- | :--- | :--- |
| `ExecutionGasConfig.enabled` | `true` | Gas metering active |
| `BLOCK_GAS_LIMIT_DEFAULT` | 30,000,000 | Per-block gas ceiling |
| `MINIMUM_GAS_LIMIT` | 21,000 | Per-transaction minimum |

**Enforcement Rules**:

1. **Per-Transaction Gas Limit**: `gas(tx) <= tx.gas_limit` enforced at mempool admission and execution
2. **Per-Block Gas Limit**: `sum(gas) <= BLOCK_GAS_LIMIT` enforced at block construction and validation
3. **Balance Sufficiency**: `sender.balance >= amount + (gas_limit × max_fee_per_gas)` required

### 3.2 Fee Calculation

Fees are computed as:

```
max_fee = gas_limit × max_fee_per_gas
actual_fee = gas_used × effective_fee_per_gas
```

**Fee Policy for Beta**: All fees are **burned** (removed from circulation):

- Simplest implementation for testing
- No proposer rewards or treasury in Beta
- MainNet will introduce hybrid distribution (burn + proposer)

### 3.3 Fee-Priority Mempool

TestNet Beta enables fee-priority ordering **by default**:

| Parameter | Beta Default | Notes |
| :--- | :--- | :--- |
| `enable_fee_priority` | `true` | Priority ordering active |

**Priority Ordering**:

```
priority(tx) = (max_fee_per_gas, effective_fee, arrival_id)
```

- Higher `max_fee_per_gas` transactions are included first
- Ties broken by `effective_fee`, then `arrival_id`

**Eviction**: When mempool is full, lowest-priority transactions are evicted to make room for higher-fee transactions.

### 3.4 Payload Format Compatibility

TestNet Beta accepts **both** v0 and v1 payload formats:

| Format | Size | Beta Handling |
| :--- | :--- | :--- |
| **v0** (48 bytes) | recipient + amount | Accepted; assigned `gas_limit = 50,000`, `max_fee_per_gas = 0` |
| **v1** (72 bytes) | recipient + amount + gas_limit + max_fee_per_gas | Recommended; full gas/fee semantics |

**Deprecation Timeline**:

1. **Beta Launch**: Both v0 and v1 accepted
2. **Beta + 2 weeks**: Warning logged for v0 payloads
3. **Beta + 4 weeks**: v0 payloads rejected; v1 required
4. **MainNet**: v1 required from launch

**Reference**: [QBIND_GAS_AND_FEES_DESIGN.md](./QBIND_GAS_AND_FEES_DESIGN.md) for complete gas/fee specification.

---

## 4. Mempool & DAG

### 4.1 DAG as Default

TestNet Beta switches the default mempool from FIFO to DAG:

| Parameter | Alpha Default | Beta Default |
| :--- | :--- | :--- |
| Mempool Mode | FIFO | DAG |
| DAG Availability | Opt-in | Enabled |

**Rationale**: DAG mempool provides:

- Decoupled data availability from ordering
- Reduced leader bottleneck (all validators contribute batches)
- Improved throughput and fairness

FIFO mempool is retained as a **fallback/testing mode** only.

### 4.2 DAG Availability Certificates

BatchAck and BatchCertificate (T165 v1) are expected to operate in normal mode:

- Validators issue `BatchAck` messages for received batches
- Batches form `BatchCertificate` when ≥2f+1 acks accumulate
- Certificates prove data availability before consensus ordering

**Beta Goals**:

| Goal | Description | Status |
| :--- | :--- | :--- |
| Certs in normal operation | Batches should form certs during normal validator activity | Expected |
| Fetch-on-miss | Acks for unknown batches trigger batch fetch | Planned |
| Consensus coupling | Require certs before commit | Planned |

### 4.3 Fee-Priority DAG Integration

When fee-priority is enabled (Beta default), DAG batch construction and frontier selection respect gas/fee constraints:

1. **Batch Construction**: Batch creators preferentially include higher-fee transactions
2. **Frontier Selection**: Block construction from DAG frontier respects per-block gas limit
3. **Transaction Ordering**: Within blocks, transactions are ordered by fee priority

**Reference**: [QBIND_DAG_MEMPOOL_DESIGN.md §5.5](../devnet/QBIND_DAG_MEMPOOL_DESIGN.md) for gas model integration.

---

## 5. Networking / P2P

### 5.1 P2P as Default

TestNet Beta switches the default network mode from LocalMesh to P2P:

| Parameter | Alpha Default | Beta Default |
| :--- | :--- | :--- |
| `network_mode` | `LocalMesh` | `P2p` |
| `enable_p2p` | `false` | `true` |

**Rationale**: P2P transport enables:

- Multi-machine and multi-region deployments
- Real network conditions and latency
- Validation of P2P stack before MainNet

LocalMesh is retained for **dev/harness environments only**.

### 5.2 Static Peer Configuration

Beta continues to use **static peer configuration**:

- Peer addresses are configured via CLI flags or config files
- No dynamic discovery protocol in Beta
- Validators manually configure their peer lists

**Beta Expectations**:

| Aspect | Beta Status | MainNet Target |
| :--- | :--- | :--- |
| Static peers | Required | Acceptable as fallback |
| Dynamic discovery | Not implemented | Required |
| Peer liveness scoring | Not implemented | Required |

### 5.3 Resilience Requirements

TestNet Beta nodes should handle basic misconfigurations gracefully:

| Scenario | Expected Behavior |
| :--- | :--- |
| Peer unreachable | Retry with backoff; continue with remaining peers |
| Peer crash | Detect disconnect; attempt reconnection |
| Invalid peer address | Log error; skip peer |
| Partial mesh | Operate with ≥2f+1 connected validators |

### 5.4 Future P2P Enhancements

The following are **planned for Beta → MainNet**:

- **Dynamic Peer Discovery**: Basic peer exchange protocol
- **Peer Liveness Scoring**: Detect and remove unresponsive peers
- **Anti-Eclipse Measures**: Peer diversity requirements
- **Multi-Region Support**: Latency-aware peer selection

**Reference**: [QBIND_P2P_NETWORK_DESIGN.md](../network/QBIND_P2P_NETWORK_DESIGN.md) for full P2P architecture.

---

## 6. Security & Risk Posture (Beta View)

This section provides a Beta-specific view of key security areas. For the complete risk analysis, see [QBIND_TESTNET_BETA_AUDIT_SKELETON.md](./QBIND_TESTNET_BETA_AUDIT_SKELETON.md).

### 6.1 Execution / VM

| Aspect | Beta Status | Risk Level |
| :--- | :--- | :--- |
| VM v0 semantics | Same as Alpha | Low |
| Property-based tests (T177) | Active | Mitigated |
| Stage B parallelism | Off | N/A (not enabled) |
| Gas-on behavior | New for Beta | Medium (new surface) |

**Key Risk**: Gas-on execution introduces new failure modes (out-of-gas, fee deduction). Existing T177 property tests do not cover gas semantics.

### 6.2 Gas / Fees

| Aspect | Beta Status | Risk Level |
| :--- | :--- | :--- |
| Gas enforcement | Enabled by default | Medium |
| Fee market | Simple priority ordering | Medium |
| DoS resistance | Substantially improved | Improved vs Alpha |

**Key Risk**: Fee market is simple (no EIP-1559-style base fee); gaming and manipulation may be possible.

### 6.3 DAG Availability

| Aspect | Beta Status | Risk Level |
| :--- | :--- | :--- |
| BatchAck/BatchCert | Active by default | Medium |
| Consensus coupling | Partial (data-plane only) | Medium |
| Fetch-on-miss | Planned | Open |

**Key Risk**: Certificates are data-plane artifacts; consensus does not yet require them.

### 6.4 P2P Networking

| Aspect | Beta Status | Risk Level |
| :--- | :--- | :--- |
| P2P transport | Default for Beta | Medium |
| Static peers | Required | Medium (eclipse risk) |
| Dynamic discovery | Not implemented | Open |

**Key Risk**: Static peer configuration creates eclipse attack surface; mis-configured peers could isolate validators.

---

## 7. Operational Profiles & CLI Defaults

### 7.1 Beta Preset

A "standard TestNet Beta node" uses the following configuration:

```bash
qbind-node \
  --env testnet \
  --execution-profile vm-v0 \
  --enable-gas true \
  --mempool-fee-priority true \
  --network-mode p2p \
  --enable-p2p true \
  --dag-enabled true \
  --data-dir /data/qbind
```

### 7.2 Configuration Parameters

| Parameter | CLI Flag | Beta Default | Notes |
| :--- | :--- | :--- | :--- |
| Environment | `--env` | `testnet` | Same as Alpha |
| Execution Profile | `--execution-profile` | `vm-v0` | Same as Alpha |
| Gas Enforcement | `--enable-gas` | `true` | **New in Beta** |
| Fee Priority | `--mempool-fee-priority` | `true` | **New in Beta** |
| Network Mode | `--network-mode` | `p2p` | **Changed in Beta** |
| P2P Transport | `--enable-p2p` | `true` | **Changed in Beta** |
| DAG Mempool | `--dag-enabled` | `true` | **Changed in Beta** |
| Data Directory | `--data-dir` | Required | Persistent storage |

### 7.3 NodeConfig Example

```rust
// Beta-style NodeConfig
let config = NodeConfig::testnet_beta()
    .with_execution_profile(ExecutionProfile::VmV0)
    .with_gas_config(ExecutionGasConfig::enabled())
    .with_fee_priority(true)
    .with_network_mode(NetworkMode::P2p)
    .with_enable_p2p(true)
    .with_dag_enabled(true)
    .with_data_dir("/data/qbind");
```

**Note**: Actual CLI flags may be wired in later tasks. This section is declarative.

---

## 8. Compatibility & Migration

### 8.1 Alpha → Beta Upgrade Path

Clusters can be upgraded from Alpha-style to Beta-style configuration:

| Aspect | Migration Impact |
| :--- | :--- |
| **Gas/Fees** | Affects tx validity and ordering; block hashes remain deterministic given same config |
| **DAG vs FIFO** | Local mempool choice; consensus ordering unchanged (HotStuff-based) |
| **P2P vs LocalMesh** | Local transport choice; consensus rules unchanged |
| **State Persistence** | Required for Beta; Alpha data compatible |

### 8.2 Configuration Alignment

Beta nodes may interoperate with Alpha-style nodes **if configuration is aligned**:

| Mixed Scenario | Interoperability |
| :--- | :--- |
| Gas-on + Gas-off | ❌ Different validity rules |
| DAG + FIFO | ✅ Consensus ordering is HotStuff |
| P2P + LocalMesh | ⚠️ Requires network compatibility layer |

**Recommendation**: All "public TestNet nodes" should converge on Beta defaults to ensure consistent behavior.

### 8.3 Rolling Upgrade Procedure

1. **Phase 1**: Update node binaries to Beta-capable version
2. **Phase 2**: Enable gas enforcement on all nodes simultaneously
3. **Phase 3**: Enable fee-priority mempool
4. **Phase 4**: Switch mempool mode to DAG (if not already)
5. **Phase 5**: Switch network mode to P2P

**Note**: Gas/fee changes must be coordinated across all validators to avoid consensus divergence.

---

## 9. Roadmap: Ready vs Pending

### 9.1 Ready for Beta

| Item | Status | Reference |
| :--- | :--- | :--- |
| VM v0 execution semantics | ✅ Ready | [QBIND_TESTNET_ALPHA_SPEC.md §2](./QBIND_TESTNET_ALPHA_SPEC.md) |
| RocksDB state persistence | ✅ Ready | [QBIND_TESTNET_ALPHA_SPEC.md §4.4](./QBIND_TESTNET_ALPHA_SPEC.md) |
| Gas enforcement (config-gated) | ✅ Ready | T168 |
| Fee-priority mempool (config-gated) | ✅ Ready | T169 |
| DAG mempool + availability certs | ✅ Ready | T158, T165 |
| P2P transport v1 | ✅ Ready | T172, T173, T174, T175 |
| Property-based tests (T177) | ✅ Ready | T177 |

### 9.2 Pending for Beta

| Item | Status | Target Task |
| :--- | :--- | :--- |
| Gas-aware property tests | ⏳ Planned | T179+ |
| DAG fetch-on-miss protocol | ⏳ Planned | Future |
| DAG consensus coupling | ⏳ Planned | Future |
| Dynamic P2P discovery | ⏳ Planned | Future |
| Peer liveness scoring | ⏳ Planned | Future |
| State pruning | ⏳ Planned | Future |
| Multi-machine staging | ⏳ Planned | Future |

### 9.3 Out-of-Scope for Beta

| Item | Target Phase |
| :--- | :--- |
| Stage B parallel execution | MainNet |
| EIP-1559-style fee market | MainNet |
| HSM production mode | MainNet |
| Full security audit | MainNet |
| Smart contracts | MainNet |

---

## 10. Related Documents

| Document | Path | Description |
| :--- | :--- | :--- |
| TestNet Alpha Spec | [QBIND_TESTNET_ALPHA_SPEC.md](./QBIND_TESTNET_ALPHA_SPEC.md) | TestNet Alpha architecture |
| TestNet Alpha Audit | [QBIND_TESTNET_ALPHA_AUDIT.md](./QBIND_TESTNET_ALPHA_AUDIT.md) | Alpha risk and readiness |
| TestNet Beta Audit Skeleton | [QBIND_TESTNET_BETA_AUDIT_SKELETON.md](./QBIND_TESTNET_BETA_AUDIT_SKELETON.md) | Beta risk tracker |
| Gas and Fees Design | [QBIND_GAS_AND_FEES_DESIGN.md](./QBIND_GAS_AND_FEES_DESIGN.md) | Gas and fee specification |
| DAG Mempool Design | [QBIND_DAG_MEMPOOL_DESIGN.md](../devnet/QBIND_DAG_MEMPOOL_DESIGN.md) | DAG architecture |
| Parallel Execution Design | [QBIND_PARALLEL_EXECUTION_DESIGN.md](../devnet/QBIND_PARALLEL_EXECUTION_DESIGN.md) | Stage A/B parallelism |
| P2P Network Design | [QBIND_P2P_NETWORK_DESIGN.md](../network/QBIND_P2P_NETWORK_DESIGN.md) | P2P networking architecture |
| P2P TestNet Alpha Guide | [QBIND_P2P_TESTNET_ALPHA_GUIDE.md](../network/QBIND_P2P_TESTNET_ALPHA_GUIDE.md) | Multi-process runbook |
| DevNet v0 Freeze | [QBIND_DEVNET_V0_FREEZE.md](../devnet/QBIND_DEVNET_V0_FREEZE.md) | DevNet v0 baseline |
| VM v0 Property Tests | `qbind-ledger/tests/t177_vm_v0_proptests.rs` | T177 property tests |

---

*End of Document*