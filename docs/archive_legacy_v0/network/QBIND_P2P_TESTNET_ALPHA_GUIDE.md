# QBIND P2P TestNet Alpha Guide

**Task**: T175  
**Status**: Implemented  
**Date**: 2026-01-31

---

## 1. Scope

This guide covers running a multi-process QBIND TestNet Alpha cluster over P2P transport.

### What This Guide Covers

- 4-validator TestNet Alpha cluster on a single machine (localhost)
- Static peer configuration (no discovery)
- Basic P2P transport with PQC KEMTLS encryption
- Transaction submission and verification

### What This Guide Does NOT Cover

- Dynamic peer discovery (planned for TestNet Beta)
- Multi-machine deployments (can be adapted from this guide)
- Production deployments (use MainNet configuration)
- DevNet v0 (remains frozen with LocalMesh mode)

---

## 2. Prerequisites

### 2.1 Build the Binary

```bash
# Clone and build the qbind-node binary
cd /path/to/qbind
cargo build --release -p qbind-node

# Verify the binary exists
ls -la target/release/qbind-node
```

### 2.2 Verify the Binary

```bash
# Check help output
./target/release/qbind-node --help
```

Expected output includes:
- `--env` option for environment selection
- `--network-mode` option for P2P mode
- `--enable-p2p` flag
- `--p2p-listen-addr` and `--p2p-peer` options

---

## 3. Topology

### 3.1 4-Validator Localhost Cluster

| Validator | Listen Address | Validator ID |
| :--- | :--- | :--- |
| Node 0 | 127.0.0.1:19000 | 0 |
| Node 1 | 127.0.0.1:19001 | 1 |
| Node 2 | 127.0.0.1:19002 | 2 |
| Node 3 | 127.0.0.1:19003 | 3 |

Each node connects to all other nodes as static peers.

### 3.2 Directory Structure

Each node uses its own data directory:

```
/tmp/qbind-node-0/
/tmp/qbind-node-1/
/tmp/qbind-node-2/
/tmp/qbind-node-3/
```

---

## 4. Running the Cluster

### 4.1 Terminal Setup

Open 4 terminal windows, one for each validator.

### 4.2 Node Commands

**Terminal 1 - Validator 0:**

```bash
./target/release/qbind-node \
  --env testnet \
  --execution-profile vm-v0 \
  --network-mode p2p \
  --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19000 \
  --p2p-advertised-addr 127.0.0.1:19000 \
  --p2p-peer 127.0.0.1:19001 \
  --p2p-peer 127.0.0.1:19002 \
  --p2p-peer 127.0.0.1:19003 \
  --validator-id 0 \
  --data-dir /tmp/qbind-node-0
```

**Terminal 2 - Validator 1:**

```bash
./target/release/qbind-node \
  --env testnet \
  --execution-profile vm-v0 \
  --network-mode p2p \
  --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19001 \
  --p2p-advertised-addr 127.0.0.1:19001 \
  --p2p-peer 127.0.0.1:19000 \
  --p2p-peer 127.0.0.1:19002 \
  --p2p-peer 127.0.0.1:19003 \
  --validator-id 1 \
  --data-dir /tmp/qbind-node-1
```

**Terminal 3 - Validator 2:**

```bash
./target/release/qbind-node \
  --env testnet \
  --execution-profile vm-v0 \
  --network-mode p2p \
  --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19002 \
  --p2p-advertised-addr 127.0.0.1:19002 \
  --p2p-peer 127.0.0.1:19000 \
  --p2p-peer 127.0.0.1:19001 \
  --p2p-peer 127.0.0.1:19003 \
  --validator-id 2 \
  --data-dir /tmp/qbind-node-2
```

**Terminal 4 - Validator 3:**

```bash
./target/release/qbind-node \
  --env testnet \
  --execution-profile vm-v0 \
  --network-mode p2p \
  --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19003 \
  --p2p-advertised-addr 127.0.0.1:19003 \
  --p2p-peer 127.0.0.1:19000 \
  --p2p-peer 127.0.0.1:19001 \
  --p2p-peer 127.0.0.1:19002 \
  --validator-id 3 \
  --data-dir /tmp/qbind-node-3
```

### 4.3 Expected Startup Output

Each node should print:

```
qbind-node[validator=V0]: starting in environment=TestNet chain_id=0x51424e4454535400 scope=TST profile=vm-v0 network=p2p p2p=enabled listen=127.0.0.1:19000 peers=3
[T175] P2P mode: Node starting with environment=TestNet profile=vm-v0
[P2P] Listening on 127.0.0.1:19000 (node_id=...)
[T175] P2P node started successfully.
```

---

## 5. Verifying the Cluster

### 5.1 Connection Health

Watch for connection messages:

```
[P2P] Accepted connection from 127.0.0.1:...
[P2P] Connected to peer 127.0.0.1:19001
```

Each node should establish 3 peer connections (one to each other node).

### 5.2 Metrics (Future)

When the metrics HTTP endpoint is enabled, check:

```bash
curl http://127.0.0.1:9090/metrics | grep p2p
```

Key metrics to watch:
- `qbind_p2p_connections_current`: Should be 3 per node
- `qbind_p2p_bytes_sent_total`: Should increase with activity
- `qbind_p2p_messages_sent_total`: Should increase with consensus

### 5.3 Log Messages

Healthy cluster shows:
- `[P2P] Accepted connection from ...` - Inbound connections
- `[P2P] Connected to peer ...` - Outbound connections established
- No error messages about connection failures

---

## 6. Transaction Submission (Future)

Transaction submission via RPC will be documented when the RPC layer is implemented.

For testing purposes, the harness tests in `t166_testnet_alpha_cluster_harness.rs` demonstrate transaction submission.

---

## 7. Shutting Down

Press `Ctrl+C` in each terminal to gracefully shut down the nodes.

Expected output:

```
[T175] Shutting down P2P node...
[T175] P2P node shutdown complete.
```

---

## 8. Troubleshooting

### 8.1 Port Already in Use

**Symptom:** `Address already in use` error on startup.

**Fix:** Either:
1. Kill the existing process using the port: `lsof -i :19000`
2. Use a different port for the node

### 8.2 Connection Refused

**Symptom:** `Connection refused` when dialing peers.

**Fix:** Ensure all peer nodes are running before starting new nodes. Start nodes in order (0, 1, 2, 3) with a small delay between each.

### 8.3 No Peer Connections

**Symptom:** Node starts but shows 0 connections.

**Fix:** Verify:
1. `--enable-p2p` flag is set
2. `--network-mode p2p` is set
3. `--p2p-peer` addresses are correct
4. Other nodes are actually running

### 8.4 Mismatched Advertised Address

**Symptom:** Connections fail or are one-way.

**Fix:** Ensure `--p2p-advertised-addr` matches the address other nodes use in their `--p2p-peer` list.

### 8.5 DevNet vs TestNet

**Symptom:** Warning about P2P in DevNet.

**Fix:** Use `--env testnet` for P2P experimentation. DevNet v0 is frozen with LocalMesh mode.

---

## 9. Configuration Reference

### 9.1 Required Flags for P2P Mode

| Flag | Required | Description |
| :--- | :--- | :--- |
| `--env` | Yes | Use `testnet` for P2P testing |
| `--network-mode` | Yes | Must be `p2p` |
| `--enable-p2p` | Yes | Must be present to enable P2P |
| `--p2p-listen-addr` | Yes | Local bind address |
| `--validator-id` | Yes | Validator index (0-3) |

### 9.2 Optional Flags

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--p2p-advertised-addr` | listen_addr | Public address for peers |
| `--p2p-max-outbound` | 16 | Max outbound connections |
| `--p2p-max-inbound` | 64 | Max inbound connections |
| `--p2p-gossip-fanout` | 6 | Gossip message fanout |
| `--data-dir` | None | Persistent state directory |

---

## 10. Related Documents

- [QBIND P2P Network Design](./QBIND_P2P_NETWORK_DESIGN.md) - Full P2P architecture
- [QBIND TestNet Alpha Spec](../testnet/QBIND_TESTNET_ALPHA_SPEC.md) - TestNet Alpha features
- [QBIND TestNet Alpha Audit](../testnet/QBIND_TESTNET_ALPHA_AUDIT.md) - P2P-related risks and roadmap (TA-R5)
- [QBIND DevNet v0 Freeze](../devnet/QBIND_DEVNET_V0_FREEZE.md) - DevNet freeze status

---

*End of Document*