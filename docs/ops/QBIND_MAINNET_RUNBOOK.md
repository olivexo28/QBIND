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
11. [Related Documents](#11-related-documents)

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

### 3.4 CLI Reference

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

### 4.4 Pre-Flight Verification

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

See [§10.1 Consensus Key Suspected Compromised](#101-consensus-key-suspected-compromised).

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

---

## 11. Related Documents

| Document | Path | Description |
| :--- | :--- | :--- |
| **MainNet v0 Spec** | [QBIND_MAINNET_V0_SPEC.md](../mainnet/QBIND_MAINNET_V0_SPEC.md) | MainNet architecture |
| **MainNet Audit** | [QBIND_MAINNET_AUDIT_SKELETON.md](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md) | Risk tracking |
| **Key Management Design** | [QBIND_KEY_MANAGEMENT_DESIGN.md](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md) | Key architecture (T209) |
| **Monetary Policy Design** | [QBIND_MONETARY_POLICY_DESIGN.md](../econ/QBIND_MONETARY_POLICY_DESIGN.md) | Monetary policy (T194) |
| **TestNet Beta Spec** | [QBIND_TESTNET_BETA_SPEC.md](../testnet/QBIND_TESTNET_BETA_SPEC.md) | TestNet Beta reference |
| **Prometheus Alerts** | [prometheus/qbind_mainnet_alerts.example.yaml](./prometheus/qbind_mainnet_alerts.example.yaml) | Alert rules |
| **Grafana Dashboard** | [grafana/qbind_mainnet_dashboard.example.json](./grafana/qbind_mainnet_dashboard.example.json) | Dashboard config |

---

*End of Document*