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

Stage B conflict-graph-based parallel execution is **available but disabled by default** for TestNet Beta:

- Beta defaults to sequential execution (same as Alpha)
- Stage B is available and testable via `--enable-stage-b` flag
- CI tests verify determinism vs sequential execution

**Configuration**:
```bash
# Enable Stage B for testing in Beta
qbind-node --profile testnet-beta --enable-stage-b true --data-dir /data/qbind
```

**Implementation Status (T186, T187)**:
- ✅ Stage B is wired into the VM v0 pipeline
- ✅ Determinism vs sequential verified via CI tests
- ✅ Metrics available: `stage_b_enabled`, `stage_b_blocks_total`, `stage_b_parallel_seconds`

**Reference**: [QBIND_PARALLEL_EXECUTION_DESIGN.md §4.2](../devnet/QBIND_PARALLEL_EXECUTION_DESIGN.md) for Stage B design and [Appendix D](../devnet/QBIND_PARALLEL_EXECUTION_DESIGN.md#appendix-d-implementation-status--stage-b-wiring-t186-t187) for implementation status.

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

### 3.5 Property-Based Test Coverage (T179)

Gas-enabled VM v0 execution has dedicated property-based test coverage validating:

- **Balance + Fee Conservation**: `sum(initial_balances) == sum(final_balances) + total_burned_fees`
- **Nonce Monotonicity with Gas**: Final nonce == initial nonce + count of successful txs
- **Failed Transaction Safety**: Failed transactions don't consume gas or modify state
- **Block Gas Limit Enforcement**: Total gas of included txs never exceeds configured limit

Test files:
- `qbind-ledger/tests/t179_vm_v0_gas_proptests.rs`: Ledger-level gas invariants (G1–G5)
- `qbind-node/tests/t179_gas_pipeline_proptests.rs`: Node-level pipeline tests (P1–P3)

### 3.6 Cluster-Level Fee-Market Tests (T181)

Cluster-level fee-market soak tests validate Beta profile behavior under realistic conditions:

- **Fee-Market Smoke Tests**: `test_testnet_beta_fee_market_localmesh_smoke` validates cluster operation with fee-priority enabled
- **Eviction Behavior**: `test_testnet_beta_fee_market_eviction` tests mempool behavior under constrained capacity
- **P2P Mode**: `test_testnet_beta_fee_market_p2p_smoke` (ignored) exercises fee-market with P2P transport

Test file: `qbind-node/tests/t166_testnet_alpha_cluster_harness.rs` (T181 section)

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

### 4.4 Cluster-Level DAG Tests (T181)

T181 provides cluster-level tests that exercise DAG mempool with Beta configuration:

- `test_testnet_beta_fee_market_localmesh_smoke`: DAG mempool with fee-priority enabled
- `test_testnet_beta_fee_market_eviction`: DAG mempool under constrained capacity

Test file: `qbind-node/tests/t166_testnet_alpha_cluster_harness.rs` (T181 section)

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
| Gas-enabled property tests (T179) | Active | Partially Mitigated |
| Stage B parallelism | Off | N/A (not enabled) |
| Gas-on behavior | New for Beta | Medium (new surface) |

**Key Risk**: Gas-on execution introduces new failure modes (out-of-gas, fee deduction). T179 gas-enabled property tests now cover balance + fee conservation, nonce monotonicity with gas, and block gas limit invariants.

### 6.2 Gas / Fees

| Aspect | Beta Status | Risk Level |
| :--- | :--- | :--- |
| Gas enforcement | Enabled by default | Medium |
| Fee market | Simple priority ordering | Medium |
| Fee accounting tests (T179) | Active | Partially Mitigated |
| DoS resistance | Substantially improved | Improved vs Alpha |

**Key Risk**: Fee market is simple (no EIP-1559-style base fee); gaming and manipulation may be possible. T179 property tests validate fee deduction correctness and balance conservation.

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

### 6.5 Key Management & Signers (T209)

TestNet Beta validators should follow improved key management practices in preparation for MainNet:

| Aspect | Beta Guidance | Risk Level |
| :--- | :--- | :--- |
| **Loopback signer** | ⚠️ Discouraged | Medium |
| **EncryptedFsV1** | ✅ Recommended | Low |
| **RemoteSigner** | ✅ Recommended | Low |
| **HsmPkcs11** | ✅ Available and strongly encouraged (T211) | Low |

**Beta Signer Recommendations**:

1. **Do NOT use loopback signers** for persistent Beta validators. While technically allowed, loopback signers expose key material in the same process as consensus and should only be used for development/testing.

2. **Use EncryptedFsV1 or RemoteSigner** for all Beta validators that will persist beyond testing. This practices production-grade key handling.

3. **HsmPkcs11 is available on Beta and strongly encouraged** for operators planning to run MainNet validators. Beta provides an opportunity to test HSM integration flows before MainNet. The PKCS#11 adapter (T211) supports SoftHSM for testing and hardware HSMs for production.

4. **Test key rotation procedures** during Beta. While not enforced, validators should practice the rotation workflow documented in the key management design.

> **📋 Design Reference**: For the complete key management architecture and MainNet requirements, see [QBIND_KEY_MANAGEMENT_DESIGN.md](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md) (T209).

**Example Beta Node with SoftHSM (non-production)**:

```bash
# Install SoftHSM2 (for testing only)
sudo apt-get install -y softhsm2

# Initialize a token
softhsm2-util --init-token --slot 0 \
    --label "qbind-validator" \
    --pin 1234 --so-pin 5678

# Create HSM config file
cat > /tmp/hsm-beta.toml <<EOF
library_path = "/usr/lib/softhsm/libsofthsm2.so"
token_label  = "qbind-validator"
key_label    = "qbind-consensus-42"
pin_env_var  = "QBIND_HSM_PIN"
EOF

# Set PIN and start the node
export QBIND_HSM_PIN=1234
qbind-node --signer-mode hsm-pkcs11 --hsm-config-path /tmp/hsm-beta.toml
```

> **⚠️ Note**: SoftHSM is suitable for testing only. For production MainNet validators, use a hardware HSM (AWS CloudHSM, Thales Luna, YubiHSM 2, etc.).

### 6.6 Remote Signer for Beta (T212)

Advanced Beta operators can experiment with `SignerMode::RemoteSigner` and the `qbind-remote-signer` daemon. This setup is recommended for operators planning to run MainNet validators, as it allows testing the production key isolation architecture.

**Remote Signer Setup for Beta**:

1. **Configure the remote signer daemon** (`/tmp/remote_signer.toml`):

```toml
listen_addr = "127.0.0.1:9443"
validator_id = 42
backend_mode = "encrypted-fs"
keystore_path = "/tmp/beta-keystore"
keystore_entry_id = "beta-validator-42"
rate_limit_rps = 100
passphrase_env_var = "QBIND_KEYSTORE_PASSPHRASE"
```

2. **Start the remote signer daemon**:

```bash
export QBIND_KEYSTORE_PASSPHRASE=<your-passphrase>
qbind-remote-signer --config /tmp/remote_signer.toml
```

3. **Start the Beta node with remote signer**:

```bash
qbind-node --profile testnet-beta \
    --signer-mode remote-signer \
    --remote-signer-url kemtls://127.0.0.1:9443 \
    --data-dir /data/qbind
```

> **Note**: For Beta testing, the remote signer and node can run on the same host. For MainNet, they should be on separate hosts for proper key isolation.

> **HSM Backend**: For production-grade testing, configure `backend_mode = "hsm-pkcs11"` in the remote signer to use a hardware HSM.

**Key Risk**: Beta validators using loopback signers may carry insecure habits to MainNet, where loopback is forbidden.

### 6.7 HSM Redundancy Experimentation (T214)

Beta operators are encouraged to experiment with HSM/remote signer redundancy following the MainNet runbook patterns:

| Pattern | Description | Beta Recommendation |
| :--- | :--- | :--- |
| **Active/Passive** | Two signer hosts, one active | ✅ Recommended for ops practice |
| **HSM Cluster** | Vendor-provided HA | ✅ Available if using cloud HSM |

**Chaos Testing with LogAndContinue**:

TestNet Beta may allow `SignerFailureMode::LogAndContinue` for chaos testing scenarios. This mode allows the node to continue running (and log errors) when the signer fails, which is useful for observing degraded behavior without immediate process termination.

```bash
# Chaos testing mode (TestNet Beta only, NOT for MainNet)
qbind-node --profile testnet-beta \
    --signer-failure-mode log-and-continue \
    --data-dir /data/qbind
```

**⚠️ WARNING**: `LogAndContinue` must **NOT** be used on MainNet. MainNet enforces `ExitOnFailure` via `validate_mainnet_invariants()` and will reject any configuration with `LogAndContinue`.

**Health Monitoring**:

Beta operators should monitor signer health metrics to practice MainNet operations:

- `qbind_hsm_startup_ok` – Startup health check (1=ok, 0=failed)
- `qbind_hsm_sign_error_total{kind}` – HSM errors by type
- `qbind_remote_sign_failures_total{reason}` – Remote signer failures

---

## 7. Operational Profiles & CLI Defaults

### 7.1 Beta Preset (T180)

As of T180, a canonical TestNet Beta preset is implemented. A "standard TestNet Beta node" can be started using the `--profile` CLI flag:

```bash
# Using the --profile flag (recommended)
qbind-node --profile testnet-beta --data-dir /data/qbind

# Or with the short flag
qbind-node -P testnet-beta -d /data/qbind
```

This is equivalent to manually specifying all Beta defaults:

```bash
qbind-node \
  --env testnet \
  --execution-profile vm-v0 \
  --enable-gas true \
  --enable-fee-priority true \
  --mempool-mode dag \
  --enable-dag-availability true \
  --network-mode p2p \
  --enable-p2p true \
  --data-dir /data/qbind
```

### 7.2 Configuration Parameters

| Parameter | CLI Flag | Beta Default | Notes |
| :--- | :--- | :--- | :--- |
| **Profile** | `--profile` / `-P` | N/A | Use `testnet-beta` for canonical preset |
| Environment | `--env` | `testnet` | Same as Alpha |
| Execution Profile | `--execution-profile` | `vm-v0` | Same as Alpha |
| Gas Enforcement | `--enable-gas` | `true` | **Enabled in Beta** |
| Fee Priority | `--enable-fee-priority` | `true` | **Enabled in Beta** |
| Mempool Mode | `--mempool-mode` | `dag` | **DAG default in Beta** |
| DAG Availability | `--enable-dag-availability` | `true` | **Enabled in Beta** |
| Network Mode | `--network-mode` | `p2p` | **P2P default in Beta** |
| P2P Transport | `--enable-p2p` | `true` | **Enabled in Beta** |
| Data Directory | `--data-dir` / `-d` | Required | Persistent storage |

### 7.3 NodeConfig Example (T180)

```rust
use qbind_node::{NodeConfig, ConfigProfile, MempoolMode, NetworkMode};

// Option 1: Use the canonical preset (recommended)
let config = NodeConfig::testnet_beta_preset()
    .with_data_dir("/data/qbind");

// Option 2: Use from_profile for CLI integration
let config = NodeConfig::from_profile(ConfigProfile::TestNetBeta)
    .with_data_dir("/data/qbind");

// Option 3: LocalMesh variant for CI/testing (no P2P multi-process)
let test_config = NodeConfig::testnet_beta_preset_localmesh()
    .with_data_dir("/tmp/qbind-test");

// Verify Beta defaults
assert!(config.gas_enabled);
assert!(config.enable_fee_priority);
assert_eq!(config.mempool_mode, MempoolMode::Dag);
assert_eq!(config.network_mode, NetworkMode::P2p);
assert!(config.dag_availability_enabled);
```

### 7.4 CLI Override Behavior

When using `--profile`, individual flags can still override specific settings:

```bash
# Beta profile but with gas disabled (for comparison testing)
qbind-node --profile testnet-beta --enable-gas false --data-dir /data/qbind

# Beta profile but with LocalMesh (for single-machine testing)
qbind-node --profile testnet-beta --network-mode local-mesh --data-dir /data/qbind
```

Override warnings are logged when a profile is modified by explicit flags.

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
| Gas-aware property tests (T179) | ✅ Ready | T179 |

### 9.2 Pending for Beta

| Item | Status | Target Task |
| :--- | :--- | :--- |
| DAG fetch-on-miss protocol | ✅ Implemented v0 | T182, T183 |
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

## 10. Path to MainNet

For the next phase of the network roadmap (MainNet v0), see [QBIND_MAINNET_V0_SPEC.md](../mainnet/QBIND_MAINNET_V0_SPEC.md).

MainNet v0 extends Beta with:

- **Hybrid fee distribution** — Burn + proposer reward (vs burn-only in Beta)
- **Formal monetary policy** — Three-phase inflation model with PQC cost adjustments and EMA-smoothed fee offsets; see [QBIND_MONETARY_POLICY_DESIGN.md](../econ/QBIND_MONETARY_POLICY_DESIGN.md) (T194)
- **Consensus-coupled DAG** — Proposals must only commit certified batches
- **Stage B parallelism** — Conflict-graph-based parallel execution available
- **Dynamic P2P discovery** — Validators can find new peers automatically
- **Anti-eclipse measures** — Peer diversity requirements enforced
- **HSM production mode** — Hardware security module support for validators
- **External security audit** — Required before MainNet launch

### 10.1 MainNet Configuration Profile (T185)

The **MainNet profile** (`--profile mainnet`) is the canonical entry point for MainNet v0 nodes
and is implemented via T185. It provides:

- `ConfigProfile::MainNet` enum variant and `NodeConfig::mainnet_preset()`
- `validate_mainnet_invariants()` safety rails that refuse to start misconfigured nodes
- Strict enforcement of: gas enabled, fee-priority enabled, DAG mempool, P2P required, data directory required

**Note**: DevNet and TestNet Alpha/Beta profiles remain unaffected. The MainNet profile is a
superset of Beta with additional mandatory constraints.

For MainNet risk tracking and readiness checklist, see [QBIND_MAINNET_AUDIT_SKELETON.md](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md).

### 10.2 MainNet Monetary Policy (T194)

The canonical specification for MainNet monetary behavior is [QBIND_MONETARY_POLICY_DESIGN.md](../econ/QBIND_MONETARY_POLICY_DESIGN.md). Key elements include:

- **Phase Model**: Bootstrap (0–3y) → Transition (3–7y) → Mature (7y+) with time and economic readiness gates
- **PQC-Adjusted Inflation**: Target rates account for ML-DSA-44/ML-KEM-768 computational overhead (~7.5–9% in Bootstrap)
- **Fee-Based Offset**: EMA-smoothed fee revenue reduces required inflation; capped by floor in Mature phase
- **Seigniorage Split**: Validators (82%), Treasury (12%), Insurance (4%), Community (2%)
- **Parameter Governance**: Hard-coded vs tunable parameters clearly defined; oracle hints reserved for Phase 2+

**Implementation Status**: Design complete (T194). Implementation pending in T195+ tasks.

---

## 11. Related Documents

| Document | Path | Description |
| :--- | :--- | :--- |
| **MainNet v0 Spec** | [QBIND_MAINNET_V0_SPEC.md](../mainnet/QBIND_MAINNET_V0_SPEC.md) | MainNet v0 architecture |
| **MainNet Audit** | [QBIND_MAINNET_AUDIT_SKELETON.md](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md) | MainNet risk tracker |
| **Monetary Policy Design** | [QBIND_MONETARY_POLICY_DESIGN.md](../econ/QBIND_MONETARY_POLICY_DESIGN.md) | Monetary policy and inflation design (T194) |
| **Key Management Design** | [QBIND_KEY_MANAGEMENT_DESIGN.md](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md) | Key management and signer architecture (T209) |
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