# QBIND MainNet v0 Operational Runbook

**Task**: T216  
**Status**: Ready  
**Date**: 2026-02-07

---

## Table of Contents

1. [Overview](#1-overview)
2. [Node Roles & Topology](#2-node-roles--topology)
3. [Configuration Profiles & Invariants](#3-configuration-profiles--invariants)
4. [Bootstrapping a Fresh MainNet Validator](#4-bootstrapping-a-fresh-mainnet-validator)
5. [Snapshots, Fast Sync, and State Retention](#5-snapshots-fast-sync-and-state-retention)
6. [Key Rotation & Compromise Handling](#6-key-rotation--compromise-handling)
7. [P2P, Diversity, and Anti-Eclipse Operations](#7-p2p-diversity-and-anti-eclipse-operations)
8. [Monetary Telemetry and Monetary Mode](#8-monetary-telemetry-and-monetary-mode)
9. [Alerting & Dashboard Reference](#9-alerting--dashboard-reference)
10. [Incident Playbooks](#10-incident-playbooks)
11. [Upgrade Procedures & Governance Hooks (T224)](#11-upgrade-procedures--governance-hooks-t224)
12. [Related Documents](#12-related-documents)

---

## 1. Overview

This runbook provides operational guidance for running QBIND MainNet v0 validator and infrastructure nodes. It is intended for SREs and operators with experience managing distributed systems and blockchain infrastructure.

### 1.1 Audience

- **Primary**: Site Reliability Engineers (SREs) operating MainNet validators
- **Secondary**: DevOps teams setting up monitoring and alerting
- **Secondary**: Security teams reviewing operational procedures

### 1.2 Prerequisites

Before using this runbook, ensure you have:

- Access to the QBIND binary (`qbind-node`) built with `--release`
- Familiarity with [QBIND_MAINNET_V0_SPEC.md](../mainnet/QBIND_MAINNET_V0_SPEC.md)
- Understanding of the [Key Management Design](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md)
- Prometheus + Grafana infrastructure for monitoring

### 1.3 Quick Reference

| Task | Section |
| :--- | :--- |
| Start a new MainNet validator | [§4 Bootstrapping](#4-bootstrapping-a-fresh-mainnet-validator) |
| Configure HSM/Remote Signer | [§4.2 Signer Configuration](#42-signer-configuration) |
| Restore from snapshot | [§5.3 Fast Sync](#53-fast-sync-procedure) |
| Rotate validator keys | [§6 Key Rotation](#6-key-rotation--compromise-handling) |
| Investigate P2P issues | [§7 P2P Operations](#7-p2p-diversity-and-anti-eclipse-operations) |
| Handle signer failure | [§10.2 Incident Playbooks](#102-remote-signer-unreachable) |

---

## 2. Node Roles & Topology

### 2.1 Node Types

QBIND MainNet supports three primary node roles:

| Role | Description | Consensus | P2P | State |
| :--- | :--- | :--- | :--- | :--- |
| **Validator** | Core consensus participant; signs proposals and votes | Active | Full mesh with validators | Pruned (default) |
| **Sentry** | P2P relay; shields validators from direct internet exposure | Passive | Public + validator mesh | Optional pruning |
| **RPC/Indexer** | Serves API requests; may maintain full state history | Passive | Public peers | Archival (optional) |

### 2.2 Recommended Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                         INTERNET                                │
└───────────────────────────────┬─────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
   ┌────▼────┐             ┌────▼────┐             ┌────▼────┐
   │ Sentry A │             │ Sentry B │             │ Sentry C │
   │ (Public) │             │ (Public) │             │ (Public) │
   └────┬────┘             └────┬────┘             └────┬────┘
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                │
                         (Private Network)
                                │
                         ┌──────▼──────┐
                         │  Validator  │
                         │   (Core)    │
                         └──────┬──────┘
                                │
                         ┌──────▼──────┐
                         │ Remote Signer│
                         │ (HSM/Signer) │
                         └─────────────┘
```

**Key Points**:
- Validators should NOT be directly exposed to the internet
- Sentry nodes handle public P2P connections
- Remote signer / HSM should be on a separate, hardened host

### 2.3 Hardware Requirements

#### Validator Node (Core)

| Resource | Minimum | Recommended |
| :--- | :--- | :--- |
| **CPU** | 8 cores (x86_64) | 16+ cores |
| **RAM** | 32 GB | 64 GB |
| **Disk** | 500 GB NVMe SSD | 1 TB NVMe SSD |
| **Network** | 1 Gbps | 10 Gbps |

**Notes**:
- ML-DSA-44 / ML-KEM-768 (PQC) operations are CPU-intensive
- Stage B parallel execution benefits from more cores
- NVMe required for RocksDB performance

#### Sentry Node

| Resource | Minimum | Recommended |
| :--- | :--- | :--- |
| **CPU** | 4 cores | 8 cores |
| **RAM** | 16 GB | 32 GB |
| **Disk** | 200 GB SSD | 500 GB NVMe SSD |
| **Network** | 1 Gbps | 10 Gbps |

#### RPC/Indexer Node

| Resource | Minimum (Pruned) | Recommended (Archival) |
| :--- | :--- | :--- |
| **CPU** | 8 cores | 16+ cores |
| **RAM** | 32 GB | 64 GB |
| **Disk** | 500 GB NVMe | 2+ TB NVMe |
| **Network** | 1 Gbps | 10 Gbps |

---

## 3. Configuration Profiles & Invariants

### 3.1 MainNet Configuration Profile

The canonical MainNet profile is invoked via CLI:

```bash
qbind-node --profile mainnet --data-dir /data/qbind
```

This is equivalent to:

```bash
qbind-node \
  --env mainnet \
  --execution-profile vm-v0 \
  --enable-gas true \
  --enable-fee-priority true \
  --mempool-mode dag \
  --enable-dag-availability true \
  --network-mode p2p \
  --enable-p2p true \
  --enable-stage-b true \
  --enable-discovery true \
  --data-dir /data/qbind
```

### 3.2 MainNet Invariants Checklist

The following invariants are **enforced** by `validate_mainnet_invariants()` at startup. The node will refuse to start if any invariant is violated.

| # | Invariant | Enforcement | Notes |
| :--- | :--- | :--- | :--- |
| 1 | `network_environment == Mainnet` | Error on mismatch | Chain ID validation |
| 2 | `gas_enabled == true` | Cannot disable gas | Economic security |
| 3 | `enable_fee_priority == true` | Cannot disable fees | Economic security |
| 4 | `mempool_mode == Dag` | DAG required | Availability guarantees |
| 5 | `dag_availability_enabled == true` | Certs required | Consensus coupling |
| 6 | `network_mode == P2p` | P2P required | No LocalMesh |
| 7 | `enable_discovery == true` | Discovery required | Eclipse resistance |
| 8 | `data_dir` configured | Must be set | Persistent storage |
| 9 | `signer_mode != LoopbackTesting` | Loopback forbidden | Key security |
| 10 | `signer_failure_mode == ExitOnFailure` | Fail-closed required | Security |
| 11 | `diversity_mode == Enforce` | Enforced | Anti-eclipse |
| 12 | `monetary_mode != Off` | Shadow or Active | Monetary tracking |
| 13 | `snapshot_config.enabled == true` | Snapshots required | Recovery |
| 14 | `snapshot_interval_blocks` in [10,000, 500,000] | Reasonable bounds | Ops flexibility |

### 3.3 Operator Checklist (Pre-Launch)

Before starting a MainNet validator, verify:

- [ ] **Signer mode** is `encrypted-fs`, `remote-signer`, or `hsm-pkcs11`
- [ ] **Signer failure mode** is `exit-on-failure`
- [ ] **Data directory** exists and has adequate disk space
- [ ] **Snapshot directory** is configured and has adequate space
- [ ] **P2P ports** are open and reachable (default: 9000)
- [ ] **Bootstrap peers** are configured
- [ ] **Diversity mode** is set to `enforce`
- [ ] **Monetary mode** is `shadow` (recommended for initial launch) or `active`

### 3.4 Pre-Release Testing

Before release, QA and operators should run the consensus chaos harness tests to validate fault tolerance:

```bash
# Run all chaos harness tests
cargo test -p qbind-node --test t222_consensus_chaos_harness -- --test-threads=1

# Run specific scenarios
cargo test -p qbind-node --test t222_consensus_chaos_harness test_t222_leader_crash_and_recover
cargo test -p qbind-node --test t222_consensus_chaos_harness test_t222_short_partition_then_heal
```

These tests validate that the consensus layer maintains safety (no commit divergence, no DAG/Block mismatches) under adversarial conditions including leader crashes, message loss, and network partitions. See `crates/qbind-node/tests/t222_consensus_chaos_harness.rs` for details.

### 3.5 CLI Reference

#### Starting a Standard MainNet Validator

```bash
qbind-node \
  --profile mainnet \
  --data-dir /data/qbind \
  --signer-mode encrypted-fs \
  --signer-keystore-path /data/qbind/keystore \
  --validator-id 42 \
  --p2p-listen-addr 0.0.0.0:9000 \
  --p2p-advertised-addr validator42.qbind.network:9000 \
  --bootstrap-peers mainnet-bootstrap-1.qbind.network:9000,mainnet-bootstrap-2.qbind.network:9000 \
  --snapshot-dir /data/qbind/snapshots
```

#### Starting with HSM (Production Recommended)

```bash
qbind-node \
  --profile mainnet \
  --data-dir /data/qbind \
  --signer-mode hsm-pkcs11 \
  --hsm-config-path /etc/qbind/hsm.toml \
  --validator-id 42 \
  --p2p-listen-addr 0.0.0.0:9000 \
  --bootstrap-peers mainnet-bootstrap-1.qbind.network:9000
```

#### Starting with Remote Signer

```bash
qbind-node \
  --profile mainnet \
  --data-dir /data/qbind \
  --signer-mode remote-signer \
  --remote-signer-url kemtls://signer.internal:9443 \
  --validator-id 42 \
  --p2p-listen-addr 0.0.0.0:9000
```

#### Overriding State Retention Settings

```bash
qbind-node \
  --profile mainnet \
  --data-dir /data/qbind \
  --state-retention-mode height \
  --state-retain-height 1000000 \
  --snapshot-dir /mnt/snapshots \
  --snapshot-interval 100000
```

### 3.5 Mempool Configuration (T218/T219/T220)

The DAG mempool includes several DoS protections and eviction rate limiting that can be tuned for operational needs.

#### Eviction Rate Limiting Options

| Parameter | CLI Flag | MainNet Default | Notes |
| :--- | :--- | :--- | :--- |
| **Eviction mode** | `--mempool-eviction-mode` | `enforce` | Required for MainNet |
| **Max per interval** | `--mempool-eviction-max-per-interval` | `1000` | Per 10-second window |
| **Interval seconds** | `--mempool-eviction-interval-secs` | `10` | Window length |

#### When to Adjust Eviction Settings

**Symptoms of too-strict settings**:
- Frequent `EvictionRateLimited` rejections in logs
- `qbind_mempool_eviction_rate_limit_total{mode="enforce"}` metric increasing rapidly
- High-priority transactions being rejected during network congestion

**Symptoms of too-loose settings**:
- Mempool churning excessively under load
- High rate of `qbind_mempool_evictions_total{reason="capacity"}` evictions
- Memory pressure on node due to rapid mempool turnover

#### Recommended Initial Values (MainNet v0)

```bash
# MainNet default - conservative, suitable for most validators
--mempool-eviction-mode=enforce \
--mempool-eviction-max-per-interval=1000 \
--mempool-eviction-interval-secs=10
```

#### Post-Launch Tuning

If observing high eviction rate limit hits:

1. **Monitor metrics**:
   ```bash
   curl http://localhost:9090/metrics | grep -E 'eviction_rate_limit|evictions_total'
   ```

2. **Consider increasing limit** (only after observing sustained issues):
   ```bash
   --mempool-eviction-max-per-interval=2000
   ```

3. **Alternative: Increase mempool capacity** (if disk/memory allows):
   ```bash
   --mempool-max-pending-txs=20000
   ```

> **⚠️ Warning**: Do not switch to `--mempool-eviction-mode=off` on MainNet. This is enforced by `validate_mainnet_invariants()` and will cause the node to fail startup.

---

## 4. Bootstrapping a Fresh MainNet Validator

### 4.1 Key Generation and Provisioning

#### Option A: EncryptedFsV1 Keystore (Single Host)

1. **Generate validator keys**:

```bash
qbind-keygen generate \
  --output /data/qbind/keystore \
  --validator-id 42 \
  --key-roles consensus,p2p-identity,batch-signing \
  --encrypt \
  --passphrase-env QBIND_KEYSTORE_PASSPHRASE
```

2. **Secure the passphrase**:
   - Store in a secrets manager (HashiCorp Vault, AWS Secrets Manager, etc.)
   - Never commit to version control
   - Set in environment at node startup

3. **Verify keystore**:

```bash
qbind-keygen verify \
  --keystore /data/qbind/keystore \
  --passphrase-env QBIND_KEYSTORE_PASSPHRASE
```

#### Option B: Remote Signer + HSM Architecture

1. **Provision HSM** (vendor-specific):
   - For AWS CloudHSM: Create cluster, initialize, generate ML-DSA-44 keypair
   - For YubiHSM 2: Initialize device, create authentication key, generate signing key
   - For SoftHSM (testing only): `softhsm2-util --init-token ...`

2. **Create HSM configuration** (`/etc/qbind/hsm.toml`):

```toml
# HSM PKCS#11 Configuration
library_path = "/usr/lib/pkcs11/libcloudhsm.so"  # Vendor-specific
token_label = "qbind-validator-42"
key_label = "qbind-consensus-42"
pin_env_var = "QBIND_HSM_PIN"
```

3. **Configure remote signer daemon** (`/etc/qbind/remote_signer.toml`):

```toml
listen_addr = "0.0.0.0:9443"
validator_id = 42
backend_mode = "hsm-pkcs11"
hsm_config_path = "/etc/qbind/hsm.toml"
rate_limit_rps = 100
```

4. **Start remote signer daemon**:

```bash
export QBIND_HSM_PIN=<pin>
qbind-remote-signer --config /etc/qbind/remote_signer.toml
```

5. **Verify signer reachability**:

```bash
# Check metrics endpoint
curl http://localhost:9443/metrics | grep qbind_hsm
```

### 4.2 Signer Configuration

#### HSM Configuration Options

| Field | Description | Required |
| :--- | :--- | :--- |
| `library_path` | Path to PKCS#11 library | Yes |
| `token_label` | HSM token/slot label | Yes |
| `key_label` | Key label within token | Yes |
| `pin_env_var` | Environment variable containing PIN | Yes |

#### Remote Signer Configuration Options

| Field | Description | Default |
| :--- | :--- | :--- |
| `listen_addr` | Address to listen on | `0.0.0.0:9443` |
| `validator_id` | Validator ID to sign for | Required |
| `backend_mode` | `encrypted-fs` or `hsm-pkcs11` | Required |
| `rate_limit_rps` | Max signing requests per second | 100 |

### 4.3 Joining the Network

#### Cold Start (Genesis Sync)

For new networks or when no snapshots are available:

```bash
qbind-node \
  --profile mainnet \
  --data-dir /data/qbind \
  --signer-mode encrypted-fs \
  --signer-keystore-path /data/qbind/keystore \
  --validator-id 42 \
  --bootstrap-peers mainnet-genesis.qbind.network:9000
```

**Expected behavior**:
- Node syncs blocks from genesis
- Initial sync may take hours/days depending on chain height
- Monitor `qbind_consensus_current_view` metric for progress

#### Fast Sync from Snapshot

If a recent snapshot is available (recommended for joining an existing network):

```bash
# 1. Download or copy snapshot to local storage
rsync -avz snapshot-server:/snapshots/mainnet/500000/ /data/qbind/snapshots/500000/

# 2. Validate snapshot
qbind-snapshot validate /data/qbind/snapshots/500000

# 3. Start node with fast-sync
qbind-node \
  --profile mainnet \
  --data-dir /data/qbind \
  --fast-sync-snapshot-dir /data/qbind/snapshots/500000 \
  --signer-mode encrypted-fs \
  --signer-keystore-path /data/qbind/keystore \
  --validator-id 42
```

### 4.4 Pre-Release Testing

Before MainNet launch or after significant upgrades, run the following test harnesses to verify node correctness:

#### Stage B Determinism Verification (T223)

The T223 soak harness validates Stage B parallel execution produces identical results to sequential execution over long-run randomized workloads:

```bash
# Run the Stage B soak harness (recommended before MainNet activation)
cargo test -p qbind-node --test t223_stage_b_soak_harness -- --test-threads=1

# Quick sanity check only
cargo test -p qbind-node --test t223_stage_b_soak_harness test_stage_b_soak_short_sanity
```

**Expected Output**:
- All tests should pass
- `mismatches: 0` — No divergence between sequential and parallel execution
- `stage_b_blocks_parallel > 0` — Stage B parallel path exercised

#### Consensus Chaos Testing (T222)

The T222 chaos harness validates consensus safety under adversarial conditions:

```bash
cargo test -p qbind-node --test t222_consensus_chaos_harness -- --test-threads=1
```

**Reference**: See [QBIND_MAINNET_AUDIT_SKELETON.md](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md) for the full MainNet readiness checklist.

### 4.5 Pre-Flight Verification

Before the node joins consensus, verify:

1. **Signer health** (check metrics):
   ```
   qbind_hsm_startup_ok == 1
   # OR
   qbind_remote_sign_failures_total == 0
   ```

2. **P2P connectivity** (check logs):
   ```
   [INFO] P2P: Connected to peer mainnet-bootstrap-1.qbind.network:9000
   [INFO] P2P: Outbound peers: 8
   ```

3. **State sync progress** (check metrics):
   ```
   qbind_consensus_current_view > 0
   qbind_consensus_view_lag < 10
   ```

---

## 5. Snapshots, Fast Sync, and State Retention

### 5.1 Snapshot Configuration

#### Default Settings (MainNet)

| Parameter | Value | Notes |
| :--- | :--- | :--- |
| `snapshot_config.enabled` | `true` | Required for MainNet |
| `snapshot_interval_blocks` | 50,000 | ~3.5 days at 5s blocks |
| `max_snapshots` | 5 | Disk space consideration |

#### CLI Configuration

```bash
qbind-node \
  --profile mainnet \
  --snapshot-dir /data/qbind/snapshots \
  --snapshot-interval 50000 \
  --max-snapshots 5
```

### 5.2 Snapshot Operations

#### When Snapshots are Created

Snapshots are created automatically when:
- `current_height % snapshot_interval_blocks == 0`
- Previous snapshot completed successfully
- Sufficient disk space available

#### Managing Disk Space

Monitor snapshot storage:
```bash
# Check snapshot directory size
du -sh /data/qbind/snapshots/*

# Example output:
# 45G    /data/qbind/snapshots/450000
# 46G    /data/qbind/snapshots/500000
# 47G    /data/qbind/snapshots/550000
```

Old snapshots are automatically pruned when `max_snapshots` is exceeded.

#### Validating Snapshots

```bash
qbind-snapshot validate /data/qbind/snapshots/500000

# Output:
# Snapshot height: 500000
# Chain ID: QBIND_MAINNET_CHAIN_ID
# Block hash: 0x1234...
# State root: 0xabcd...
# Validation: OK
```

### 5.3 Fast Sync Procedure

1. **Identify available snapshots**:
   ```bash
   ls -la /data/qbind/snapshots/
   # Or check snapshot provider
   curl https://snapshots.qbind.network/mainnet/latest.json
   ```

2. **Download snapshot** (if not local):
   ```bash
   wget https://snapshots.qbind.network/mainnet/500000.tar.gz
   tar -xzf 500000.tar.gz -C /data/qbind/snapshots/
   ```

3. **Validate snapshot**:
   ```bash
   qbind-snapshot validate /data/qbind/snapshots/500000
   ```

4. **Start with fast-sync**:
   ```bash
   qbind-node \
     --profile mainnet \
     --data-dir /data/qbind \
     --fast-sync-snapshot-dir /data/qbind/snapshots/500000
   ```

5. **Monitor catch-up progress**:
   ```
   qbind_consensus_current_view      # Current synced view
   qbind_consensus_highest_seen_view # Network tip
   qbind_consensus_view_lag          # Gap (should decrease)
   ```

### 5.4 State Pruning & Retention

#### Interaction Between Pruning and Snapshots

| Configuration | Behavior |
| :--- | :--- |
| Pruning enabled, snapshots enabled | State pruned below `retain_height`; snapshots capture full state at intervals |
| Pruning enabled, snapshots disabled | Historical state lost; **not recommended** for MainNet |
| Pruning disabled (archival) | Full history retained; snapshots optional |

#### Retention Guidelines

| Node Type | `retain_height` | `snapshot_interval` |
| :--- | :--- | :--- |
| Validator | 500,000 (~30 days) | 50,000 (~3.5 days) |
| Sentry | 100,000 (~7 days) | Optional |
| Archival | Disabled | 100,000 |

---

## 6. Key Rotation & Compromise Handling

### 6.1 Key Roles

| Role | Signed Operations | Rotation Impact |
| :--- | :--- | :--- |
| **Consensus** | Proposals, votes, timeouts | Network must accept new key |
| **BatchSigning** | DAG batches, availability acks | Local only during grace period |
| **P2pIdentity** | KEMTLS handshakes | Peer reconnections needed |

### 6.2 Key Rotation Procedure

#### Step 1: Generate New Key

```bash
qbind-keygen generate \
  --output /data/qbind/keystore/new \
  --validator-id 42 \
  --key-role consensus \
  --encrypt \
  --passphrase-env QBIND_KEYSTORE_PASSPHRASE
```

#### Step 2: Create Rotation Event

```bash
qbind-key-rotation init \
  --validator-id 42 \
  --key-role consensus \
  --old-key-path /data/qbind/keystore/current/consensus.pub \
  --new-key-path /data/qbind/keystore/new/consensus.pub \
  --grace-epochs 100 \
  --output rotation-event.json
```

**Example `rotation-event.json`**:
```json
{
  "validator_id": 42,
  "key_kind": "Consensus",
  "old_key": "base64-encoded-old-public-key",
  "new_key": "base64-encoded-new-public-key",
  "effective_epoch": 12345,
  "grace_epochs": 100
}
```

#### Step 3: Submit Rotation Event

Submit the rotation event via the validator registry:

```bash
qbind-validator-registry submit-rotation \
  --event rotation-event.json \
  --sign-with /data/qbind/keystore/current/consensus.key
```

#### Step 4: Monitor Grace Period

During the grace period (e.g., 100 epochs), **both keys are valid**:

```
qbind_consensus_key_rotation_pending{validator="42"} 1
qbind_consensus_key_rotation_grace_epochs_remaining{validator="42"} 95
```

**What to watch**:
- Signatures with both old and new keys should be accepted
- No consensus failures or vote rejections
- Logs show "Key rotation in progress" messages

#### Step 5: Finalize Rotation

After grace period ends:

1. **Verify new key is active**:
   ```
   qbind_consensus_key_rotation_pending{validator="42"} 0
   ```

2. **Update node to use new key exclusively**:
   ```bash
   mv /data/qbind/keystore/current /data/qbind/keystore/old
   mv /data/qbind/keystore/new /data/qbind/keystore/current
   # Restart node
   ```

3. **Securely destroy old key** (after confirming no issues):
   ```bash
   shred -u /data/qbind/keystore/old/consensus.key
   ```

### 6.3 HSM/Remote Signer Failure Modes

#### ExitOnFailure (MainNet Required)

When a signer error occurs with `signer_failure_mode = exit-on-failure`:

1. Node logs error at `error!` level
2. Increments `qbind_hsm_sign_error_total` or `qbind_remote_sign_failures_total`
3. Node terminates process (exit code 1)

**Operator response**:
- External orchestration (systemd, k8s) should restart the node
- If signer is permanently unavailable, failover to backup (see §10)

#### LogAndContinue (TestNet/DevNet Only)

**⚠️ FORBIDDEN on MainNet** – `validate_mainnet_invariants()` rejects this mode.

Use only for:
- Chaos testing on TestNet
- Debugging signer issues in non-production environments

### 6.4 Compromise Handling Incident Playbook

See [§10.5 Compromised Key Incident Procedures](#105-compromised-key-incident-procedures-t217) for comprehensive step-by-step playbooks covering:

- Suspected vs confirmed consensus key compromise
- HSM/remote signer compromise vs host compromise
- P2P identity key compromise and replacement
- Batch signing / DAG key compromise

For design rationale and epoch-level semantics, see [QBIND_KEY_MANAGEMENT_DESIGN.md §5.4](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md#54-compromised-key-handling-t217).

---

## 7. P2P, Diversity, and Anti-Eclipse Operations

### 7.1 P2P Configuration Overview

MainNet validators use dynamic peer discovery with anti-eclipse protections:

| Setting | MainNet Default | Notes |
| :--- | :--- | :--- |
| `discovery_enabled` | `true` | Required for MainNet |
| `diversity_mode` | `Enforce` | Required for MainNet |
| `max_peers_per_prefix24` | 2 | Per /24 subnet |
| `max_peers_per_prefix16` | 8 | Per /16 subnet |
| `outbound_peer_target` | 8 | Target outbound connections |

### 7.2 Diversity Buckets and Anti-Eclipse

Peer diversity is enforced to prevent eclipse attacks:

```
┌────────────────────────────────────────────────────────────────────┐
│ Peer Diversity Constraints                                         │
├────────────────────────────────────────────────────────────────────┤
│ /24 Subnet (e.g., 192.168.1.x):  Max 2 peers                       │
│ /16 Subnet (e.g., 192.168.x.x):  Max 8 peers                       │
│ IPv6 /48:                        Max 4 peers                       │
│ Max Single Bucket Fraction:      25% of total peers                │
└────────────────────────────────────────────────────────────────────┘
```

### 7.3 Key P2P Metrics

| Metric | Description | Alert Threshold |
| :--- | :--- | :--- |
| `qbind_p2p_outbound_peers` | Current outbound peer count | < 3 |
| `qbind_p2p_inbound_peers` | Current inbound peer count | — |
| `qbind_p2p_known_peers` | Total known peers | < 10 |
| `qbind_p2p_peer_rejected_diversity_total{reason="prefix24"}` | Rejected due to /24 limit | High rate |
| `qbind_p2p_peer_rejected_diversity_total{reason="prefix16"}` | Rejected due to /16 limit | High rate |
| `qbind_p2p_peer_evicted_total{reason="liveness"}` | Evicted for unresponsiveness | Sustained high rate |
| `qbind_p2p_heartbeat_failed_total` | Failed heartbeats | High rate |
| `qbind_p2p_diversity_distinct_buckets` | Number of distinct network buckets | < 4 |

### 7.4 Common P2P Issues and Remediation

#### Too Few Outbound Peers

**Symptoms**:
- `qbind_p2p_outbound_peers < 3`
- Logs show "Unable to connect to peer" errors

**Diagnosis**:
```bash
# Check peer list
curl http://localhost:9090/metrics | grep qbind_p2p_outbound_peers

# Check logs for connection errors
journalctl -u qbind-node | grep "P2P" | tail -50
```

**Remediation**:
1. Verify bootstrap peers are reachable
2. Check firewall rules (port 9000 TCP/UDP)
3. Add more bootstrap peers to config
4. Verify DNS resolution if using hostnames

#### Excess Diversity Rejections

**Symptoms**:
- High `qbind_p2p_peer_rejected_diversity_total` rate
- Logs show "Peer rejected: diversity constraint" messages

**Diagnosis**:
```bash
# Check diversity metrics
curl http://localhost:9090/metrics | grep qbind_p2p_diversity
```

**Remediation**:
1. This is expected behavior if peers are concentrated in few subnets
2. Ensure bootstrap list includes geographically diverse peers
3. Consider increasing diversity limits only if network is small

#### Multi-Region Deployment Issues

**Symptoms**:
- High latency between regions
- Increased `qbind_consensus_view_lag`

**Remediation**:
1. Deploy sentry nodes in each region
2. Configure sentries as preferred peers for validators
3. Monitor `qbind_consensus_qc_formation_latency_ms` for regional variations

---

## 8. Monetary Telemetry and Monetary Mode

### 8.1 Monetary Phases

QBIND uses a three-phase monetary model:

| Phase | Duration | Target r_inf | Characteristics |
| :--- | :--- | :--- | :--- |
| **Bootstrap** | 0–3 years | 7.5–9% | High inflation, PQC cost coverage |
| **Transition** | 3–7 years | 5–7.5% | Decreasing inflation as fees grow |
| **Mature** | 7+ years | 2–5% | Fee-dominant, minimal inflation |

### 8.2 Monetary Mode Configuration

| Mode | Behavior | MainNet Guidance |
| :--- | :--- | :--- |
| `Off` | No monetary calculations | **Forbidden on MainNet** |
| `Shadow` | Calculate but don't enact | Recommended for initial launch |
| `Active` | Full monetary policy enacted | Production mode |

**Setting monetary mode**:
```bash
qbind-node --profile mainnet --monetary-mode shadow
```

### 8.3 Key Monetary Metrics

| Metric | Description | Normal Range |
| :--- | :--- | :--- |
| `qbind_monetary_phase` | Current phase (0=Bootstrap, 1=Transition, 2=Mature) | 0–2 |
| `qbind_monetary_r_inf_annual_bps` | Current annual inflation rate (bps) | 500–900 (Bootstrap) |
| `qbind_monetary_r_target_annual_bps` | Target inflation rate (bps) | Phase-dependent |
| `qbind_monetary_fee_coverage_ratio_bps` | Fee coverage as fraction of target (bps) | Increases over time |
| `qbind_monetary_phase_recommendation` | Phase transition recommendation | 0=Stay, 1=Advance |
| `qbind_monetary_mode` | Active monetary mode | 1=Shadow, 2=Active |

### 8.4 Alerting Thresholds

| Condition | Severity | Action |
| :--- | :--- | :--- |
| `qbind_monetary_fee_coverage_ratio_bps` drops suddenly | Warning | Investigate fee revenue |
| `qbind_monetary_r_inf_annual_bps` changes > 50 bps in single epoch | Warning | Check rate limiter |
| `qbind_monetary_phase_recommendation == 1` for > 10 epochs | Info | Phase transition may be appropriate |

---

## 9. Alerting & Dashboard Reference

### 9.1 Prometheus Alerts

See [prometheus/qbind_mainnet_alerts.example.yaml](./prometheus/qbind_mainnet_alerts.example.yaml) for complete alert rules.

**Key alert categories**:
- **Consensus Health**: View lag, commit stalls
- **P2P Health**: Peer counts, diversity violations
- **Signer/HSM**: Error rates, health status
- **State/Storage**: State size, snapshot failures
- **Monetary**: Phase anomalies

### 9.2 Grafana Dashboard

See [grafana/qbind_mainnet_dashboard.example.json](./grafana/qbind_mainnet_dashboard.example.json) for importable dashboard.

**Dashboard panels by row**:
1. **Consensus & DAG**: View progress, QC formation, DAG coupling
2. **P2P & Diversity**: Peer counts, diversity metrics, heartbeats
3. **State & Storage**: State size, pruning, snapshots
4. **Monetary**: Phase, inflation, fee coverage
5. **Signer/HSM**: Health, error rates, latency

---

## 10. Incident Playbooks

### 10.1 Consensus Key Suspected Compromised

**Severity**: Critical

**Symptoms**:
- Unexpected signatures observed from validator
- Alerts from security monitoring
- External report of key compromise

**Immediate Actions**:

1. **Stop the compromised node immediately**:
   ```bash
   systemctl stop qbind-node
   ```

2. **Notify network operators** via established channels

3. **Initiate emergency key rotation** (if possible):
   ```bash
   qbind-key-rotation emergency \
     --validator-id 42 \
     --reason "suspected_compromise" \
     --effective-immediately
   ```

4. **Preserve evidence** (if forensics needed):
   ```bash
   tar -czf /tmp/qbind-forensics-$(date +%s).tar.gz \
     /var/log/qbind/ \
     /data/qbind/keystore/
   ```

5. **Provision new keys on fresh, verified host**

**Post-Incident**:
- Conduct root cause analysis
- Review access logs and security posture
- Update key management procedures if needed

### 10.2 Remote Signer Unreachable

**Severity**: High

**Symptoms**:
- `qbind_remote_sign_failures_total{reason="transport"}` increasing
- Node exits with "Remote signer unreachable" error
- Validator not participating in consensus

**Diagnosis**:

```bash
# Check signer process
systemctl status qbind-remote-signer

# Check network connectivity
telnet signer.internal 9443

# Check signer metrics
curl http://signer.internal:9443/metrics
```

**Remediation**:

1. **Restart remote signer** if process crashed:
   ```bash
   systemctl restart qbind-remote-signer
   ```

2. **Check network**:
   - Verify firewall rules
   - Check for network partition
   - Verify DNS resolution

3. **Failover to backup signer** (if configured):
   ```bash
   # Update config to point to backup
   sed -i 's/signer.internal/signer-backup.internal/' /etc/qbind/node.toml
   systemctl restart qbind-node
   ```

### 10.3 HSM Returns Persistent Errors

**Severity**: High

**Symptoms**:
- `qbind_hsm_sign_error_total{kind="runtime"}` increasing
- Node exits repeatedly with HSM errors
- HSM logs show errors

**Diagnosis**:

```bash
# Check HSM status (vendor-specific)
pkcs11-tool --module /usr/lib/pkcs11/libcloudhsm.so --list-slots

# Check HSM logs
tail -100 /var/log/hsm/cloudhsm.log
```

**Remediation**:

1. **Verify HSM connectivity and credentials**:
   ```bash
   # Test PKCS#11 operation
   pkcs11-tool --module /usr/lib/pkcs11/libcloudhsm.so \
     --login --pin $QBIND_HSM_PIN \
     --list-objects
   ```

2. **Check for HSM firmware issues** (vendor support)

3. **Failover to backup HSM** (if available):
   - For AWS CloudHSM: Traffic automatically routes to healthy HSM in cluster
   - For standalone HSM: Update config to point to backup

4. **Contact HSM vendor support** if issue persists

### 10.4 State Size Growing Unexpectedly

**Severity**: Medium

**Symptoms**:
- `qbind_state_size_bytes` increasing faster than expected
- Disk usage alerts
- Pruning not keeping pace

**Diagnosis**:

```bash
# Check state directory size
du -sh /data/qbind/state

# Check pruning metrics
curl http://localhost:9090/metrics | grep qbind_state_prune
```

**Remediation**:

1. **Verify pruning is enabled**:
   ```bash
   grep state_retention /etc/qbind/node.toml
   ```

2. **Manually trigger pruning** (if needed):
   ```bash
   qbind-admin prune-state --data-dir /data/qbind --retain-height 500000
   ```

3. **Increase disk space** if pruning is working but growth is legitimate

4. **Investigate unusual state growth** (e.g., spam attacks)

### 10.5 Compromised Key Incident Procedures (T217)

This section provides step-by-step playbooks for handling key compromise incidents. These procedures are **normative for MainNet validators**.

> **Related**: For design rationale and epoch-level semantics, see [QBIND_KEY_MANAGEMENT_DESIGN.md §5.4](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md#54-compromised-key-handling-t217).

#### 10.5.1 Suspected Consensus Key Compromise

**Severity**: Critical  
**When to Invoke**: Unusual signatures observed, security alert triggered, or insider threat suspected.

**Immediate Actions** (within 15 minutes):

1. **Stop the validator immediately**:
   ```bash
   systemctl stop qbind-node
   ```
   **Rationale**: Prevent further signing that could be used for equivocation.

2. **Verify the suspicion** — check for equivocation evidence:
   ```bash
   # Check if equivocation has been detected
   curl -s http://localhost:9090/metrics | grep qbind_consensus_equivocation
   
   # Review recent signatures in logs
   journalctl -u qbind-node --since "1 hour ago" | grep "signed\|signature"
   ```

3. **Assess current epoch**:
   ```bash
   curl -s http://localhost:9090/metrics | grep qbind_consensus_epoch
   ```

4. **Notify network operators** via established communication channels.

**Recovery Actions** (within 4 hours):

5. **Generate emergency replacement key** on fresh infrastructure:
   ```bash
   qbind-keygen generate \
     --output /data/qbind/keystore/emergency \
     --validator-id 42 \
     --key-role consensus \
     --encrypt \
     --passphrase-env QBIND_KEYSTORE_PASSPHRASE
   ```

6. **Create emergency rotation event**:
   ```bash
   qbind-key-rotation init \
     --validator-id 42 \
     --key-role consensus \
     --new-public-key-file /data/qbind/keystore/emergency/consensus.pub \
     --effective-epoch $(($(curl -s http://localhost:9090/metrics | grep qbind_consensus_epoch | awk '{print $2}') + 1)) \
     --grace-epochs 1 \
     --emergency \
     --output emergency-rotation.json
   ```

7. **Submit rotation event** via expedited governance process:
   ```bash
   qbind-validator-registry submit-rotation \
     --event emergency-rotation.json \
     --sign-with /data/qbind/keystore/emergency/consensus.key \
     --expedited
   ```

8. **Preserve evidence** for forensics:
   ```bash
   tar -czf /tmp/qbind-forensics-$(date +%s).tar.gz \
     /var/log/qbind/ \
     /data/qbind/keystore/ \
     /var/log/auth.log
   chmod 600 /tmp/qbind-forensics-*.tar.gz
   ```

**Post-Incident** (within 24 hours):
- Conduct root cause analysis
- File incident report with network governance
- Update key management procedures if needed

**Metrics to Monitor**:
- `qbind_signer_sign_failures_total` — should be 0 after restart
- `qbind_consensus_key_rotation_pending{validator="<id>"}` — should be 1 during grace period
- `qbind_consensus_equivocation_detected_total` — monitor for evidence

---

#### 10.5.2 Confirmed Consensus Key Compromise

**Severity**: Critical  
**When to Invoke**: Equivocation evidence on-chain, attacker activity confirmed.

**Immediate Actions** (within 5 minutes):

1. **Stop the validator immediately**:
   ```bash
   systemctl stop qbind-node
   # Kill any background processes
   pkill -9 -f qbind-node || true
   ```

2. **Isolate the compromised host** from the network:
   ```bash
   # Block outbound network (preserve forensics)
   iptables -A OUTPUT -j DROP
   ```

3. **Alert network operators** with equivocation evidence:
   ```bash
   # Broadcast emergency alert (implementation-specific)
   qbind-admin broadcast-alert \
     --severity critical \
     --message "Validator 42 consensus key confirmed compromised"
   ```

**Recovery Actions** (within 2 hours):

4. **Provision new infrastructure** (do NOT reuse compromised host)

5. **Generate new key on new infrastructure** (same as §10.5.1 step 5)

6. **Create emergency rotation with minimal grace period**:
   ```bash
   qbind-key-rotation init \
     --validator-id 42 \
     --key-role consensus \
     --new-public-key-file /data/qbind/keystore/new/consensus.pub \
     --effective-epoch $((current_epoch + 1)) \
     --grace-epochs 1 \
     --emergency \
     --reason "confirmed_compromise" \
     --output emergency-rotation.json
   ```

7. **Submit via emergency governance** (may require quorum vote)

**Slashing Preparation**:
- If equivocation occurred, prepare for potential slashing
- Document all evidence for dispute resolution
- Slashing amount depends on governance rules (out of scope for T217)

**Metrics to Monitor**:
- `qbind_consensus_equivocation_detected_total` — track all instances
- `qbind_validator_slashed_total` — monitor for slashing events

---

#### 10.5.3 HSM/Remote Signer Compromise vs Host Compromise

Different compromise scenarios require different response strategies:

**Scenario A: HSM Compromise (Host Secure)**

Indicators:
- HSM tamper detection triggered
- Vendor-reported vulnerability
- HSM firmware compromise suspected

Response:
1. **Stop validator** (HSM may still be accessible to attacker)
2. **Isolate HSM** from network if possible
3. **Do NOT attempt to use HSM** for emergency key generation
4. **Use backup HSM or EncryptedFsV1** for emergency key:
   ```bash
   # Generate on backup infrastructure
   qbind-keygen generate \
     --output /data/qbind/keystore/emergency \
     --validator-id 42 \
     --key-role consensus \
     --encrypt \
     --passphrase-env QBIND_KEYSTORE_PASSPHRASE
   ```
5. **Contact HSM vendor** for incident response
6. **Replace HSM hardware** before resuming production

**Scenario B: Host Compromise (HSM May Be Safe)**

Indicators:
- Root access detected on validator host
- Malware found
- Container escape detected

Response:
1. **Stop validator immediately** — host is untrusted
2. **Assume HSM is compromised** (conservative approach):
   - Attacker with host access may have extracted HSM PIN
   - Attacker may have sent signing requests via HSM API
3. **Treat as full key compromise** (follow §10.5.2)
4. **Provision entirely new infrastructure**:
   - New host
   - New HSM (or existing backup HSM if physically isolated)
   - New keys

**Decision Matrix**:

| Scenario | Assume Key Compromised? | Reuse HSM? | Reuse Host? |
| :--- | :--- | :--- | :--- |
| HSM compromise, host secure | Yes | ❌ No | Evaluate |
| Host compromise, HSM unknown | Yes | ❌ No (conservative) | ❌ No |
| Remote signer compromise | Yes | N/A | ❌ No |
| Network partition (not compromise) | No | ✅ Yes | ✅ Yes |

---

#### 10.5.4 P2P Identity Key Compromise and Replacement

**Severity**: High (but not critical — validator can continue consensus participation)  
**When to Invoke**: Suspected MITM, peer impersonation, or P2P key exposure.

**Assessment**:

P2P identity key compromise is **less severe** than consensus key compromise because:
- Cannot cause equivocation or slashing
- Cannot forge consensus votes
- Impact limited to network topology/peer trust

**Symptoms**:
- `qbind_p2p_handshake_failures_total` increasing unexpectedly
- Peers reporting conflicting validator identity claims
- Suspicious peer connections from unknown sources

**Response** (can be performed during normal operation):

1. **Continue consensus participation** — validator CAN keep signing
   ```bash
   # No need to stop the node
   ```

2. **Generate new P2P identity key**:
   ```bash
   qbind-keygen generate \
     --output /data/qbind/keystore/new-p2p \
     --validator-id 42 \
     --key-role p2p-identity \
     --encrypt \
     --passphrase-env QBIND_KEYSTORE_PASSPHRASE
   ```

3. **Create planned rotation event** (longer grace period):
   ```bash
   qbind-key-rotation init \
     --validator-id 42 \
     --key-role p2p-identity \
     --new-public-key-file /data/qbind/keystore/new-p2p/p2p_identity.pub \
     --effective-epoch $((current_epoch + 10)) \
     --grace-epochs 50 \
     --output p2p-rotation.json
   ```

4. **Submit rotation event** via normal governance:
   ```bash
   qbind-validator-registry submit-rotation \
     --event p2p-rotation.json \
     --sign-with /data/qbind/keystore/current/consensus.key
   ```

5. **Coordinate with peers** — notify other validators of upcoming P2P key change

6. **After grace period**, update node configuration:
   ```bash
   mv /data/qbind/keystore/current/p2p_identity.key \
      /data/qbind/keystore/old/p2p_identity.key.bak
   mv /data/qbind/keystore/new-p2p/p2p_identity.key \
      /data/qbind/keystore/current/p2p_identity.key
   systemctl restart qbind-node
   ```

**Metrics to Monitor**:
- `qbind_p2p_handshake_failures_total` — should decrease after rotation
- `qbind_p2p_connections_total` — verify peer connectivity restored
- `qbind_consensus_key_rotation_pending{validator="<id>",key_role="p2p-identity"}` — track rotation progress

---

#### 10.5.5 Batch Signing / DAG Key Compromise

**Severity**: Critical (same as consensus key)  
**When to Invoke**: Forged batches or availability certificates detected.

**Important**: In current implementation, batch signing key is the **same as consensus key**. Therefore:

1. **Treat as consensus key compromise** (follow §10.5.1 or §10.5.2)
2. **Stop signing immediately**
3. **Execute emergency key rotation**

**Symptoms Specific to Batch Signing Compromise**:
- `qbind_dag_batch_equivocation_detected` metric increasing
- Forged availability certificates in DAG
- Invalid batch signatures attributed to validator

**Additional DAG-Specific Actions**:

1. **Check DAG consistency**:
   ```bash
   curl -s http://localhost:9090/metrics | grep qbind_dag
   ```

2. **Verify batch signature status**:
   ```bash
   qbind-admin dag-status --validator-id 42
   ```

3. **Report forged certificates** to network operators for investigation

**Future Consideration**: If batch signing key becomes separate from consensus key, this playbook will be updated with independent rotation procedures.

**Metrics to Monitor**:
- `qbind_dag_batch_equivocation_detected` — should be 0
- `qbind_dag_certs_invalid_total` — track invalid certificate attempts
- `qbind_dag_batches_signed_total` — verify signing resumes after recovery

---

#### 10.5.6 Metrics Reference for Compromise Detection

The following metrics are useful for detecting and responding to key compromise:

| Metric | Description | Alert Threshold |
| :--- | :--- | :--- |
| `qbind_signer_sign_requests_total` | Total signing requests by type | Sudden spikes |
| `qbind_signer_sign_failures_total` | Total signing failures | Any increase |
| `qbind_consensus_equivocation_detected_total` | Equivocation events detected | > 0 |
| `qbind_consensus_key_rotation_pending` | Key rotation in progress | 1 during rotation |
| `qbind_consensus_key_rotation_grace_epochs_remaining` | Epochs until rotation completes | Decreasing |
| `qbind_p2p_handshake_failures_total` | P2P handshake failures | Sudden increase |
| `qbind_dag_batch_equivocation_detected` | DAG batch equivocation | > 0 |
| `qbind_hsm_sign_error_total` | HSM signing errors | Any increase |
| `qbind_remote_sign_failures_total` | Remote signer failures | Any increase |

**CLI Tools Reference**:

| Tool | Purpose | Example |
| :--- | :--- | :--- |
| `qbind-keygen generate` | Generate new keypair | See examples above |
| `qbind-key-rotation init` | Create rotation event | See examples above |
| `qbind-validator-registry submit-rotation` | Submit rotation to governance | See examples above |
| `qbind-admin dag-status` | Check DAG consistency | `qbind-admin dag-status --validator-id 42` |
| `qbind-admin broadcast-alert` | Emergency network alert | `qbind-admin broadcast-alert --severity critical` |

---

## 11. Upgrade Procedures & Governance Hooks (T224)

This section provides operator-facing procedures for applying protocol upgrades. For the full governance design and threat model, see [QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md](../gov/QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md).

### 11.1 Upgrade Classes Overview

| Class | Description | Coordination | Operator Action |
| :--- | :--- | :--- | :--- |
| **Class A** | Non-consensus (CLI, docs) | None | Upgrade at convenience |
| **Class B** | Consensus-compatible | Rolling | Upgrade within window |
| **Class C** | Hard-fork / protocol changes | Coordinated | Must upgrade before activation |

### 11.2 Pre-Upgrade Verification Checklist

Before applying any Council-approved upgrade:

- [ ] **Verify Upgrade Envelope exists** and is published in governance repository
- [ ] **Verify ≥5 council signatures** on the Upgrade Envelope are valid:
  ```bash
  qbind-envelope verify \
    --envelope /etc/qbind/upgrade-envelope-vX.Y.Z.json \
    --council-keys /etc/qbind/council-pubkeys.json
  ```
- [ ] **Verify binary hash** matches envelope `binary_hashes`:
  ```bash
  sha3-256 /path/to/new/qbind-node
  # Compare against envelope binary_hashes.linux-x86_64
  ```
- [ ] **Review changelog** and release notes for breaking changes
- [ ] **Review runbook updates** (if any) for new operational procedures
- [ ] **Backup current state** before upgrade:
  ```bash
  # Trigger snapshot
  qbind-admin snapshot create --output /data/qbind/pre-upgrade-snapshot
  ```
- [ ] **Run pre-release tests** on staging/test validator (non-MainNet):
  - [ ] Chaos harness passes (T222):
    ```bash
    cargo test -p qbind-node --test t222_consensus_chaos_harness -- --test-threads=1
    ```
  - [ ] Stage B soak passes (T223):
    ```bash
    cargo test -p qbind-node --test t223_stage_b_soak_harness -- --test-threads=1
    ```
- [ ] **Verify configuration** matches expected profile:
  ```bash
  qbind-node --profile mainnet --validate-only --data-dir /data/qbind
  ```
- [ ] **Verify activation height** (for Class C) matches envelope:
  ```bash
  cat /etc/qbind/upgrade-envelope-vX.Y.Z.json | jq '.activation'
  ```
- [ ] **Notify team** of planned upgrade window

### 11.3 Upgrade Execution (Class A/B)

For Class A (non-consensus) or Class B (consensus-compatible) upgrades:

```bash
# 1. Stop the node gracefully
systemctl stop qbind-node

# 2. Backup current binary
cp /usr/local/bin/qbind-node /usr/local/bin/qbind-node.backup

# 3. Install new binary
cp /path/to/new/qbind-node /usr/local/bin/qbind-node
chmod +x /usr/local/bin/qbind-node

# 4. Verify binary hash
sha3-256 /usr/local/bin/qbind-node

# 5. Start the node
systemctl start qbind-node

# 6. Monitor startup and consensus participation
journalctl -u qbind-node -f
curl -s http://localhost:9090/metrics | grep qbind_consensus_view
```

### 11.4 Upgrade Execution (Class C — Coordinated Activation)

For Class C (hard-fork) upgrades with activation height:

**Phase 1: Pre-Activation (upgrade binary, wait for activation)**

```bash
# 1. Verify activation height is in the future
curl -s http://localhost:9090/metrics | grep qbind_consensus_committed_height
# Current height should be significantly below activation height

# 2. Stop the node gracefully
systemctl stop qbind-node

# 3. Backup current binary
cp /usr/local/bin/qbind-node /usr/local/bin/qbind-node.backup

# 4. Install new binary
cp /path/to/new/qbind-node /usr/local/bin/qbind-node
chmod +x /usr/local/bin/qbind-node

# 5. Verify binary hash matches envelope
sha3-256 /usr/local/bin/qbind-node

# 6. Update configuration if required by upgrade
# (e.g., new flags or config file changes)

# 7. Start the node
systemctl start qbind-node

# 8. Verify node is running and participating
curl -s http://localhost:9090/metrics | grep qbind_consensus_view
```

**Phase 2: Activation Monitoring**

```bash
# Monitor height approaching activation
watch -n 10 'curl -s http://localhost:9090/metrics | grep qbind_consensus_committed_height'

# At activation height, verify:
# - No consensus forks
# - All validators on new version
# - New features active (if applicable)
```

### 11.5 Emergency Downgrade Procedure

**For Class A/B (consensus-compatible)**:

```bash
# 1. Stop node
systemctl stop qbind-node

# 2. Restore previous binary
mv /usr/local/bin/qbind-node.backup /usr/local/bin/qbind-node

# 3. Start node
systemctl start qbind-node

# 4. Monitor for normal operation
journalctl -u qbind-node -f
```

**For Class C (post-activation)**:

⚠️ **WARNING**: Do NOT unilaterally downgrade after a Class C activation. This will fork you off the network.

1. **Report issue** to engineering team and Protocol Council immediately
2. **Wait for coordinated response**:
   - Emergency hotfix (forward), OR
   - Coordinated rollback (requires new Upgrade Envelope from Council)
3. If Council approves rollback:
   - Download rollback binary
   - Verify rollback Upgrade Envelope
   - Apply rollback binary when instructed
   - Activate at specified rollback height

### 11.6 Upgrade Envelope Verification Commands (T225)

**Inspect envelope contents** (human-readable summary):
```bash
qbind-envelope inspect /etc/qbind/upgrade-envelope-vX.Y.Z.json
```

**Verify envelope signatures** (checks threshold is met):
```bash
qbind-envelope verify \
  --envelope /etc/qbind/upgrade-envelope-vX.Y.Z.json \
  --council-keys /etc/qbind/council-pubkeys.json
```

**Verify envelope signatures AND binary hash**:
```bash
qbind-envelope verify \
  --envelope /etc/qbind/upgrade-envelope-vX.Y.Z.json \
  --council-keys /etc/qbind/council-pubkeys.json \
  --binary /path/to/new/qbind-node \
  --platform linux-x86_64
```

**Exit Codes**:
- `0`: Verification passed (threshold met, all signatures valid, binary hash matches)
- `1`: Verification failed (threshold not met, invalid signatures, or binary hash mismatch)
- `2`: Invalid arguments or I/O error

**JSON Output** (for automation):
```bash
qbind-envelope verify \
  --envelope /etc/qbind/upgrade-envelope-vX.Y.Z.json \
  --council-keys /etc/qbind/council-pubkeys.json \
  --output json
```

**Compute envelope digest** (for manual verification):
```bash
qbind-envelope digest /etc/qbind/upgrade-envelope-vX.Y.Z.json
```

**Alternative: Manual verification with jq**:
```bash
# Verify envelope signature count
cat /etc/qbind/upgrade-envelope-vX.Y.Z.json | jq '.council_approvals | length'
# Should return >= 5

# Get binary hash from envelope
cat /etc/qbind/upgrade-envelope-vX.Y.Z.json | jq -r '.binary_hashes["linux-x86_64"]'
```

### 11.7 Post-Upgrade Monitoring

After any upgrade, monitor the following for at least 48 hours:

| Metric | Expected Behavior | Alert Threshold |
| :--- | :--- | :--- |
| `qbind_consensus_view` | Increasing | Stalled for > 1 minute |
| `qbind_consensus_qc_latency_ms` | Stable | > 2x baseline |
| `qbind_p2p_connections_total` | Stable | < 50% of pre-upgrade |
| `qbind_dag_batches_committed_total` | Increasing | Stalled |
| `qbind_signer_sign_failures_total` | Zero or stable | Any increase |

**Dashboard Reference**: See [Grafana Dashboard](./grafana/qbind_mainnet_dashboard.example.json) for pre-built panels.

### 11.8 Emergency Security Patch Process

For critical security vulnerabilities:

1. **Receive notification** via secure channel from Protocol Council
2. **Verify emergency envelope** has ≥4 council signatures (emergency threshold)
3. **Upgrade within 48 hours** (or as specified by Council)
4. **Skip some non-critical pre-release tests** (per Council guidance)
5. **Monitor closely** post-upgrade

**Note**: Emergency patches may use a lower council threshold (4-of-7 instead of 5-of-7).

### 11.9 Governance Links

| Resource | Description |
| :--- | :--- |
| **Governance Design** | [QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md](../gov/QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md) |
| **MainNet Spec §11** | [Governance & Upgrades](../mainnet/QBIND_MAINNET_V0_SPEC.md#11-governance--upgrades-t224) |
| **Audit Skeleton MN-R8** | [Governance & Upgrade Risk](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md#38-mn-r8-governance--upgrade-risk) |

---

## 12. Related Documents

| Document | Path | Description |
| :--- | :--- | :--- |
| **MainNet v0 Spec** | [QBIND_MAINNET_V0_SPEC.md](../mainnet/QBIND_MAINNET_V0_SPEC.md) | MainNet architecture |
| **MainNet Audit** | [QBIND_MAINNET_AUDIT_SKELETON.md](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md) | Risk tracking |
| **Governance & Upgrades Design** | [QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md](../gov/QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md) | Governance model (T224) |
| **Key Management Design** | [QBIND_KEY_MANAGEMENT_DESIGN.md](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md) | Key architecture (T209) |
| **Monetary Policy Design** | [QBIND_MONETARY_POLICY_DESIGN.md](../econ/QBIND_MONETARY_POLICY_DESIGN.md) | Monetary policy (T194) |
| **TestNet Beta Spec** | [QBIND_TESTNET_BETA_SPEC.md](../testnet/QBIND_TESTNET_BETA_SPEC.md) | TestNet Beta reference |
| **Prometheus Alerts** | [prometheus/qbind_mainnet_alerts.example.yaml](./prometheus/qbind_mainnet_alerts.example.yaml) | Alert rules |
| **Grafana Dashboard** | [grafana/qbind_mainnet_dashboard.example.json](./grafana/qbind_mainnet_dashboard.example.json) | Dashboard config |

---

*End of Document*