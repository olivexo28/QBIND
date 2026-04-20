# QBIND DevNet Operational Guide

**Version**: 1.0  
**Date**: 2026-04-20  
**Status**: Canonical Internal Operational Document

---

## 1. Purpose and Scope

This document is the canonical internal operational guide for QBIND DevNet.

**DevNet is the controlled internal network** used for:

- **Integration testing**: Verifying that protocol components work together correctly
- **Operator practice**: Validating runbooks and operational procedures before public exposure
- **CI-like validation**: Continuous validation of protocol changes and configurations
- **Release readiness rehearsal**: Preparing for TestNet Alpha by exercising real operational workflows

**DevNet is NOT:**

- A stable public developer network
- A platform for external participants (without explicit approval)
- A network with uptime guarantees
- A basis for permanence claims

**DevNet may be reset at any time without advance notice.**

This guide provides the operational reference for bringing up, operating, and managing DevNet safely and consistently.

---

## 2. Relationship to the Release Track

DevNet is the **first stage** in the QBIND release track:

```
DevNet → TestNet Alpha → TestNet Beta → MainNet v0
```

**Release Track Reference:** `docs/release/QBIND_RELEASE_TRACK_SPEC.md`

### 2.1 DevNet's Role in the Release Sequence

DevNet exists to:

1. **Satisfy DevNet → TestNet Alpha exit criteria** before any public network is launched
2. **Validate operational procedures** that will be used in subsequent stages
3. **Demonstrate protocol stability** under controlled conditions
4. **Surface issues early** when the cost of discovery is lowest

### 2.2 What DevNet Should NOT Be Used For

- Making public permanence claims about state or data
- Onboarding external parties without explicit approval
- Testing production economics (economics are disabled or test-mode)
- Generating investor or presale messaging

### 2.3 Exit Criteria Alignment

DevNet operation should target the exit criteria defined in the release-track spec:

- Stable multi-node consensus (≥4 nodes, ≥72 hours continuous)
- Restart safety demonstrated
- Core observability operational
- Operator runbook validated
- No unresolved critical protocol issues
- Basic transactions functional
- Epoch transitions verified

---

## 3. DevNet Operational Model

DevNet operates under a **controlled, internal model** that differs from public networks.

### 3.1 Validator Set

- **Controlled validator set**: All validators are operated by the core team or explicitly approved collaborators
- **Known identities**: All validator operators are identified and accountable
- **Coordinated changes**: Validator additions or removals are coordinated through internal channels

### 3.2 Configuration Management

- **Centrally coordinated configuration**: Genesis, chain parameters, and environment settings are managed centrally
- **Version-controlled configs**: All configuration artifacts should be tracked in version control
- **Change documentation**: Configuration changes should be documented, even during rapid iteration

### 3.3 Release Messaging

- **Internal only**: DevNet activity should not be communicated externally without approval
- **No stability promises**: No claims about uptime, permanence, or reliability
- **Limited scope**: DevNet exists for the core team and approved technical collaborators

### 3.4 Change Velocity

- **Frequent changes are acceptable**: DevNet is designed for rapid iteration
- **Breaking changes permitted**: Protocol changes may be deployed without backward compatibility
- **Reset tolerance**: Full network resets are normal operations

---

## 4. Who DevNet Is For

DevNet is intended for the following participants:

### 4.1 Primary Participants

| Role | Purpose |
|------|---------|
| **Core protocol engineers** | Testing consensus, slashing, epoch transitions, and protocol correctness |
| **Node/runtime engineers** | Testing node bring-up, persistence, networking, and recovery |
| **Internal operators / SRE** | Practicing operational procedures, validating runbooks, testing monitoring |

### 4.2 Approved Participants

| Role | Conditions |
|------|------------|
| **Invited technical collaborators** | Only when explicitly approved by the core team |
| **Security researchers** | For specific testing engagements under NDA |

### 4.3 NOT Intended For

- External developers without explicit approval
- Community members or public participants
- Investors or non-technical stakeholders
- Anyone expecting production-grade stability

---

## 5. What DevNet Is and Is Not

### 5.1 DevNet IS

| Characteristic | Implication |
|----------------|-------------|
| **Internal** | Not visible or accessible to the public |
| **Resettable** | State may be discarded at any time |
| **Allowed to evolve quickly** | Breaking changes are acceptable |
| **Suitable for failure injection** | Deliberate fault testing is encouraged |
| **Suitable for restart testing** | Recovery workflows should be exercised |
| **Appropriate for observability validation** | Metrics and logging should be tested |

### 5.2 DevNet is NOT

| Characteristic | Implication |
|----------------|-------------|
| **A public permanence promise** | No data persistence guarantees |
| **An economically final environment** | No real economic value |
| **The basis for presale messaging** | No investor-facing claims |
| **A stable external onboarding target** | External parties should not depend on it |
| **A production security baseline** | Security posture may be relaxed for testing |

---

## 6. Recommended DevNet Capabilities

DevNet should demonstrate the following capabilities before progression to TestNet Alpha.

### 6.1 Consensus

| Capability | Requirement |
|------------|-------------|
| Multi-node consensus | Required (≥4 nodes) |
| View/round progression | Required |
| Commit progress | Required |
| Leader rotation | Required |

### 6.2 Persistence and Recovery

| Capability | Requirement |
|------------|-------------|
| Restart testing | Required (nodes must rejoin after restart) |
| Epoch transition across restarts | Required |
| Persistence mode | Should be tested with RocksDB; in-memory acceptable for rapid iteration |

### 6.3 Slashing

| Capability | Requirement |
|------------|-------------|
| Slashing mode | `RecordOnly` or `EnforceCritical` as a DevNet policy choice |
| Evidence ingestion | Should be functional |
| Penalty recording | Should be verified |

**Note:** The protocol implementation supports full O1–O5 enforcement. DevNet policy choices may be more permissive than later stages to facilitate rapid testing and iteration.

### 6.4 Economics

| Capability | Requirement |
|------------|-------------|
| Gas mode | May be disabled or configured for low-friction testing |
| Fee mode | May be disabled or free-tier |
| Stake requirements | May be relaxed for DevNet |

**Note:** DevNet is not for economics validation; economics are intentionally permissive.

### 6.5 Transactions

| Capability | Requirement |
|------------|-------------|
| Transaction submission | Required |
| Transaction execution | Required (nonce-only engine at minimum) |
| Transaction finality | Required |

### 6.6 Observability

| Capability | Requirement |
|------------|-------------|
| Metrics exposure | Required |
| Logging | Required |
| Basic health signals | Required |

### 6.7 DevNet Policy Flexibility

DevNet policy choices are allowed to be more permissive than later stages:

- Slashing may be `RecordOnly` to avoid accidental penalties during testing
- Gas may be disabled to reduce friction
- Minimum stake may be lowered or disabled
- Persistence may use in-memory mode for rapid iteration
- Network may reset without notice

---

## 7. Configuration Expectations

The following configuration aspects must be controlled and documented for DevNet operation.

### 7.1 Chain Identity

| Parameter | Description |
|-----------|-------------|
| Chain ID | Unique identifier for the DevNet instance |
| Network name | Human-readable name (e.g., `qbind-devnet-001`) |
| Genesis hash | Hash of the genesis configuration |

### 7.2 Environment Selection

| Parameter | Description |
|-----------|-------------|
| Environment type | `DevNet` (must be explicit) |
| Slashing mode | `RecordOnly`, `EnforceCritical`, or `EnforceAll` |
| Gas/fee mode | `Disabled`, `FreeTier`, or `Enabled` |

### 7.3 Validator Set Source

| Parameter | Description |
|-----------|-------------|
| Validator list source | Genesis file or configuration |
| Stake requirements | Minimum stake (may be relaxed) |
| Key material location | Path to validator keys |

### 7.4 Storage Mode

| Parameter | Description |
|-----------|-------------|
| Persistence backend | `InMemory` or `RocksDB` |
| Data directory | Path for persistent state |
| Checkpoint policy | Frequency of state checkpoints |

### 7.5 Networking Mode

| Parameter | Description |
|-----------|-------------|
| Network mode | `LocalMesh` or `P2P` |
| Peer discovery | Bootstrap nodes or static peer list |
| Port configuration | Consensus, RPC, metrics ports |

### 7.6 Slashing Mode

| Parameter | Description |
|-----------|-------------|
| Slashing mode | Policy choice for offense handling |
| Evidence retention | Configuration for evidence storage |

### 7.7 Logging and Metrics

| Parameter | Description |
|-----------|-------------|
| Log level | Verbosity setting |
| Metrics endpoint | Prometheus-compatible metrics port |
| Log output | File path or stdout |

### 7.8 Signing Mode

| Parameter | Description |
|-----------|-------------|
| Signer type | `EncryptedFs` (HSM not required on DevNet) |
| Key path | Location of signing keys |

---

## 8. Node Bring-Up Workflow

Follow this staged workflow when bringing up a DevNet node.

### 8.1 Pre-Flight Checklist

- [ ] Environment configuration selected and documented
- [ ] Genesis file or configuration available
- [ ] Validator identities and keys prepared
- [ ] Peer list or bootstrap nodes known
- [ ] Storage directory prepared
- [ ] Ports available and firewall rules configured

### 8.2 Configuration Preparation

1. **Select environment config**: Choose or create the DevNet configuration profile
2. **Prepare genesis/config**: Ensure genesis file is available and matches expected chain identity
3. **Verify chain parameters**: Confirm slashing mode, gas mode, and other environment settings

### 8.3 Key Material Verification

1. **Verify validator identities**: Confirm the validator public keys in genesis
2. **Verify signing keys**: Ensure signing key material is present and accessible
3. **Verify key format**: Confirm ML-DSA-44 key format compatibility

### 8.4 Node Startup

1. **Start storage subsystem**: Initialize or connect to the persistence backend
2. **Start node process**: Launch the node with the selected configuration
3. **Verify process health**: Confirm the process is running without immediate errors

### 8.5 Network Verification

1. **Verify peer connectivity**: Confirm connections to expected peers
2. **Verify peer count**: Ensure minimum peer count is met
3. **Verify handshake completion**: Confirm KEMTLS authentication succeeds

### 8.6 Consensus Verification

1. **Verify block production**: Observe blocks being proposed and committed
2. **Verify commit progress**: Confirm view/round advancement
3. **Verify finality**: Confirm transactions are reaching finality

### 8.7 Observability Verification

1. **Verify metrics exposure**: Confirm metrics endpoint is responsive
2. **Verify logging**: Confirm logs are being produced at expected verbosity
3. **Verify health endpoint**: Confirm health/readiness signals are functional

---

## 9. Validator Bring-Up Workflow

Validator nodes have additional requirements beyond basic nodes.

### 9.1 Pre-Validator Checklist

- [ ] Node bring-up workflow completed successfully
- [ ] Validator key material available and secured
- [ ] Validator identity registered in genesis or validator set
- [ ] Stake allocated (if stake requirements are enabled)

### 9.2 Key Material Handling

| Aspect | Requirement |
|--------|-------------|
| Key format | ML-DSA-44 signing keys |
| Key storage | `EncryptedFs` mode (HSM not required on DevNet) |
| Key backup | Recommended but not mandatory for DevNet |
| Key rotation | Not required for DevNet |

**Note:** HSM and remote signer are NOT required on DevNet. DevNet may use simpler key management to reduce operational friction.

### 9.3 Signer Mode Configuration

| Mode | When to Use |
|------|-------------|
| `EncryptedFs` | Default for DevNet; keys stored encrypted on local filesystem |
| `RemoteSigner` | Optional for DevNet; use when practicing for later stages |

### 9.4 Validator Registration Verification

1. **Verify validator in active set**: Confirm the validator appears in the epoch's active validator set
2. **Verify stake visibility**: If stake requirements are enabled, confirm stake is recognized
3. **Verify voting power**: Confirm the validator has expected voting power

### 9.5 Consensus Participation Verification

1. **Verify vote production**: Confirm the validator is producing votes
2. **Verify vote inclusion**: Confirm votes are being included in QCs
3. **Verify proposal participation**: If leader, confirm block proposals are accepted

### 9.6 Epoch Observation

1. **Verify epoch number**: Confirm the current epoch is as expected
2. **Verify epoch transitions**: Observe at least one epoch transition
3. **Verify validator set continuity**: Confirm the validator remains in the set across epochs (if expected)

---

## 10. Restart and Reset Policy

### 10.1 Restart Expectations

- **Restarts are expected**: DevNet should be used to practice node restarts
- **Restart safety must be validated**: Nodes should rejoin the network correctly after restart
- **Restart workflows should be documented**: Record the steps and any issues encountered

### 10.2 Restart Workflow

1. **Graceful shutdown**: Stop the node process cleanly when possible
2. **Verify state persistence**: Confirm state was written before shutdown
3. **Restart node**: Start the node with the same configuration
4. **Verify rejoin**: Confirm the node rejoins the network and resumes participation
5. **Verify state continuity**: Confirm state is consistent with pre-restart expectations

### 10.3 Reset Policy

| Aspect | Policy |
|--------|--------|
| Reset frequency | May occur at any time without advance notice |
| State discarding | All state may be discarded during reset |
| Genesis changes | Genesis may be updated during reset |
| Validator set changes | Validator set may change during reset |

### 10.4 Reset Documentation

Even though resets are permitted freely on DevNet, they should still be documented:

- **Reason for reset**: Why the reset was performed
- **Pre-reset state**: What state existed before reset (if relevant)
- **Post-reset configuration**: What changed after reset
- **Lessons learned**: Any insights from the pre-reset operation

### 10.5 Restart and Recovery Rehearsal

DevNet is the appropriate place to rehearse:

- Node crash recovery
- Network partition recovery
- State corruption handling
- Epoch boundary restart
- Rolling restart procedures

---

## 11. Observability and Monitoring Expectations

### 11.1 Required Observability

DevNet should expose the following at minimum:

| Signal | Requirement | Notes |
|--------|-------------|-------|
| Logs | Required | Structured logging preferred |
| Metrics | Required | Prometheus-compatible endpoint |
| Health signals | Required | Readiness/liveness endpoints |
| Commit progress | Required | Visible in metrics or logs |
| Peer/connectivity visibility | Required | Peer count and status |

### 11.2 Metrics Expectations

Key metrics to monitor:

| Metric Category | Examples |
|-----------------|----------|
| Consensus | Current view, committed height, vote count |
| Networking | Peer count, message rates, latency |
| Storage | Write latency, disk usage |
| System | CPU, memory, file descriptors |

### 11.3 Logging Expectations

| Aspect | Expectation |
|--------|-------------|
| Log level | `INFO` minimum; `DEBUG` for troubleshooting |
| Log format | Structured (JSON) preferred |
| Log retention | Local retention for debugging; aggregation optional |

### 11.4 Dashboards

- Dashboards are **recommended but not mandatory** for DevNet
- Simple Prometheus/Grafana setup is sufficient
- Focus on commit progress and peer connectivity

### 11.5 Alerting

- Alerting is **optional** for DevNet
- If used, focus on:
  - Consensus stall detection
  - Peer disconnection
  - Node crash detection

---

## 12. Incident / Failure Handling

### 12.1 General Approach

When issues occur on DevNet:

1. **Document**: Record what happened, when, and under what conditions
2. **Isolate**: Determine which component(s) are affected
3. **Reproduce**: Attempt to reproduce the issue in isolation
4. **Fix or reset**: Either fix the issue or reset if appropriate

### 12.2 Specific Scenarios

#### Node Crashes

| Step | Action |
|------|--------|
| 1 | Capture crash logs and any core dumps |
| 2 | Check for resource exhaustion (memory, disk, file descriptors) |
| 3 | Attempt restart with same configuration |
| 4 | If restart fails, check state corruption |
| 5 | Document and file issue if reproducible |

#### Consensus Stalls

| Step | Action |
|------|--------|
| 1 | Check if all validators are online and connected |
| 2 | Check view/round progression in logs |
| 3 | Check for leader availability |
| 4 | Check for timeout escalation in logs |
| 5 | Consider manual intervention or reset if unrecoverable |

#### Peer Connection Failures

| Step | Action |
|------|--------|
| 1 | Verify network connectivity (firewall, ports) |
| 2 | Verify peer addresses are correct |
| 3 | Check KEMTLS handshake logs |
| 4 | Verify key material is valid |
| 5 | Attempt reconnection or restart |

#### Epoch Transition Failures

| Step | Action |
|------|--------|
| 1 | Check epoch boundary logs for errors |
| 2 | Verify validator set configuration |
| 3 | Check for stake threshold issues |
| 4 | Check for storage write failures |
| 5 | Document and file issue; consider reset if blocking |

#### State Corruption Detected

| Step | Action |
|------|--------|
| 1 | Stop the affected node immediately |
| 2 | Preserve the corrupted state for analysis |
| 3 | Check storage integrity (checksums, consistency) |
| 4 | Do NOT restart on corrupted state |
| 5 | Reset the node with fresh state, or restore from backup if available |

### 12.3 Failure Normalization Warning

**Do not normalize silent failures.**

- All failures should be documented, even if expected during testing
- Repeated failures indicate issues that need investigation
- "It's just DevNet" is not an excuse for ignoring failures

---

## 13. Exit Criteria Toward TestNet Alpha

Before DevNet can be considered ready for transition to TestNet Alpha, the following criteria must be satisfied.

### 13.1 Exit Criteria Checklist

**Consensus Stability:**
- [ ] Multi-node consensus stable (≥4 nodes)
- [ ] ≥72 hours continuous stable operation demonstrated
- [ ] View/round progression consistent
- [ ] Commit progress advancing as expected

**Restart Safety:**
- [ ] Node restart successfully demonstrated
- [ ] State continuity verified across restarts
- [ ] Epoch transitions verified across restart cycles

**Basic Functionality:**
- [ ] Transaction submission functional
- [ ] Transaction execution functional (nonce-only at minimum)
- [ ] Transaction finality confirmed

**Observability:**
- [ ] Metrics collection operational
- [ ] Logging operational
- [ ] Health signals functional

**Operations:**
- [ ] Operator runbook draft validated through practice
- [ ] Known issues documented
- [ ] Validator onboarding instructions drafted

**Protocol Status:**
- [ ] No unresolved critical protocol issues
- [ ] All relevant M-series mitigations verified in DevNet environment

### 13.2 Exit Documentation

Before declaring DevNet exit criteria satisfied:

- [ ] Document the specific DevNet configuration that met criteria
- [ ] Document any workarounds or known limitations
- [ ] Document lessons learned during DevNet operation
- [ ] Update the known issues document

---

## 14. Non-Goals

The following are explicitly **NOT goals** of DevNet operation:

### 14.1 Economics

| Non-Goal | Rationale |
|----------|-----------|
| Finalized tokenomics | DevNet uses test tokens with no economic value |
| Inflation validation | Economics are disabled or test-mode |
| Fee market testing | Fees may be disabled or free-tier |

### 14.2 External Engagement

| Non-Goal | Rationale |
|----------|-----------|
| Presale | DevNet is not a basis for presale messaging |
| Exchange/investor signaling | No external communications about DevNet stability |
| Public stability guarantees | DevNet may reset at any time |
| External developer onboarding | DevNet is internal only |

### 14.3 Permanence

| Non-Goal | Rationale |
|----------|-----------|
| Long-term state permanence | State may be discarded at any time |
| Data migration guarantees | No promise to migrate state to later stages |
| Historical chain preservation | DevNet chains may be discarded entirely |

### 14.4 Production Security

| Non-Goal | Rationale |
|----------|-----------|
| Production-grade key management | HSM not required; simpler key handling acceptable |
| Full slashing enforcement | Slashing may be RecordOnly |
| Adversarial resistance | DevNet is controlled environment |

---

## 15. Operator Checklist

Use this checklist before declaring a DevNet instance healthy for continued internal testing.

### 15.1 Pre-Operation Checklist

- [ ] Environment configuration documented
- [ ] Genesis file validated
- [ ] Validator keys prepared and secured
- [ ] Peer list or bootstrap nodes configured
- [ ] Storage directory prepared
- [ ] Ports available and accessible

### 15.2 Post-Startup Checklist

- [ ] All expected validator nodes running
- [ ] All nodes connected to expected peers
- [ ] Consensus progressing (blocks being committed)
- [ ] Metrics endpoint responsive
- [ ] Logs being produced without errors
- [ ] Health endpoint returning healthy status

### 15.3 Operational Health Checklist

- [ ] Commit progress advancing (height increasing)
- [ ] View/round progression consistent
- [ ] No consensus stalls detected
- [ ] No unexpected node restarts
- [ ] Peer connections stable
- [ ] Storage not approaching capacity

### 15.4 Restart Validation Checklist

- [ ] At least one planned restart performed
- [ ] Node successfully rejoined after restart
- [ ] State continuity verified
- [ ] Epoch transition verified (if applicable)

### 15.5 Documentation Checklist

- [ ] Configuration documented
- [ ] Known issues documented
- [ ] Any incidents documented
- [ ] Lessons learned captured

---

## Appendix A: Document References

| Document | Location | Relationship |
|----------|----------|--------------|
| Release Track Spec | `docs/release/QBIND_RELEASE_TRACK_SPEC.md` | Defines DevNet scope and exit criteria |
| Whitepaper | `docs/whitepaper/QBIND_WHITEPAPER.md` | Authoritative protocol specification |
| Protocol Report | `docs/protocol/QBIND_PROTOCOL_REPORT.md` | Protocol gaps and implementation status |
| M-Series Coverage | `docs/protocol/QBIND_M_SERIES_COVERAGE.md` | Risk mitigation audit index |
| Contradiction Tracker | `docs/whitepaper/contradiction.md` | Implementation discrepancies |

---

## Appendix B: Revision History

| Date | Version | Change | Author |
|------|---------|--------|--------|
| 2026-04-20 | 1.0 | Initial DevNet operational guide | Operations |

---

*This document is the canonical internal reference for QBIND DevNet operation. All DevNet operational decisions should reference this guide.*