# QBIND Multi-Region Dress Rehearsal Guide

**Task**: T238.5  
**Status**: Ready (documentation only)  
**Date**: 2026-02-10

---

## 1. Objectives & Assumptions

### 1.1 Purpose

This document defines a **MainNet-grade, real-infrastructure "dress rehearsal"** procedure that:

- Bridges the gap between the synthetic multi-region harness (T238) and real cloud deployments
- Specifies how operators pick regions, measure RTT/jitter/loss, and map those to the existing `RegionNetworkProfile` presets
- Defines pass/fail criteria and metrics to inspect before:
  - **MainNet v0 launch**
  - **Any Class C (hard-fork) upgrade** per the governance docs

### 1.2 Gate Classification

This dress rehearsal is a **mandatory pre-launch and pre-upgrade gate**, not a one-off experiment:

| Gate Type | When Required |
| :--- | :--- |
| **MainNet v0 Launch** | Must pass before genesis block production |
| **Class C Upgrade (Hard Fork)** | Must pass on staging/Beta before upgrade envelope signature |
| **Post-Incident Recovery** | Recommended after major network events |

### 1.3 Assumptions

Before running the dress rehearsal, the following prerequisites **must** be met:

1. **T238 harness is green** — The synthetic multi-region latency harness (`t238_multi_region_latency_harness.rs`) passes all scenarios
2. **P2P & consensus invariants green** — T185/T237 single-region tests pass with MainNet profile
3. **Cloud access available** — Operators have access to at least **3 cloud regions across 2 continents**
4. **Monitoring infrastructure ready** — Prometheus + Grafana (or equivalent) for metrics collection
5. **Genesis configuration finalized** — Genesis file and expected hash committed

---

## 2. Region Selection & Network Targets

### 2.1 Region Selection Guidance

Select at least **three regions** with the following network characteristics (vendor-agnostic):

| Metric | Intra-Continent | Inter-Continent |
| :--- | :--- | :--- |
| **RTT (round-trip)** | 20–40 ms | 80–200 ms |
| **Jitter** | 5–15 ms | 10–30 ms |
| **Packet Loss** | < 0.5% | Up to 1–3% |

> **Note**: These ranges are illustrative. Actual values vary by provider, time of day, and network conditions. Measure your specific deployment.

### 2.2 Example Region Tuples

The following are **example** configurations using generic region names:

| Configuration | Region A | Region B | Region C | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Standard Tri-Region** | Western Europe | US East | APAC (Tokyo/Singapore) | Good geographic diversity |
| **US-Centric** | US East | US West | US Central | Low latency, limited inter-continent coverage |
| **Global Spread** | Europe (Frankfurt) | US East | Australia (Sydney) | Maximum RTT variance |

For each configuration, measure the actual RTT, jitter, and loss between your nodes using tools like `ping`, `mtr`, or cloud-native network diagnostics.

### 2.3 Mapping Real Measurements to T238 Profiles

After measuring your real infrastructure, map the observed network characteristics to the T238 profile presets:

| Observed Conditions | Maps To | T238 Preset | Key Characteristics |
| :--- | :--- | :--- | :--- |
| RTT spread narrow (< 50 ms variance), loss < 0.5% | **Uniform** | `MultiRegionClusterConfig::uniform_latency()` | All regions similar moderate latency (~80 ms), no loss |
| One region 2–3× slower RTT than others | **Asymmetric** | `MultiRegionClusterConfig::asymmetric_latency()` | One region at ~200 ms, others at ~30 ms |
| Jitter > 30 ms but RTT otherwise OK | **High-Jitter** | `MultiRegionClusterConfig::high_jitter()` | ~60 ms base latency, ~50 ms jitter |
| Loss 1–3% with moderate RTT | **Lossy** | `MultiRegionClusterConfig::lossy_network()` | ~80 ms latency, 5% simulated loss |
| Multiple conditions above at once | **Mixed** | `MultiRegionClusterConfig::mixed_adversarial()` | Combination of high latency, jitter, and loss |

### 2.4 Network Measurement Protocol

Before running tests, document your network measurements:

```bash
# Measure RTT between nodes (example)
for target in node-region-a node-region-b node-region-c; do
  echo "=== Measuring to $target ==="
  ping -c 100 $target | tail -1
  # Alternative: mtr --report --report-cycles 100 $target
done
```

Record results in a table:

| From | To | RTT (p50) | RTT (p99) | Jitter | Loss % |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Region A | Region B | ___ ms | ___ ms | ___ ms | ___% |
| Region A | Region C | ___ ms | ___ ms | ___ ms | ___% |
| Region B | Region C | ___ ms | ___ ms | ___ ms | ___% |

---

## 3. Cluster Topology & Config Baseline

### 3.1 Configuration Profile

The dress rehearsal **must** use the canonical MainNet profile with the following settings:

| Setting | Required Value | Reference |
| :--- | :--- | :--- |
| **P2P Discovery** | Enabled | T205–T207, T226 |
| **Anti-Eclipse Enforcement** | `enforce = true` | T206, T231 |
| **DAG Coupling Mode** | `Enforce` (strongly recommended) or `Warn` minimum | T221 |
| **Mempool DoS Protection** | Enabled (per-sender quotas, rate limiting) | T218, T219, T220 |
| **Monetary Mode** | `Shadow` (or current MainNet default) | T194 |
| **Slashing Mode** | `RecordOnly` (per T229/T230 MainNet defaults) | T229, T230 |
| **Genesis Source** | External (`--genesis-path`) | T232 |
| **Genesis Hash Verification** | Required (`--expect-genesis-hash`) | T233 |

### 3.2 Recommended Validator Layout

For a **7-validator** MainNet-grade deployment:

| Region | Validator Count | Notes |
| :--- | :--- | :--- |
| Region A | 3 | Primary region |
| Region B | 2 | Secondary region |
| Region C | 2 | Tertiary region |

**Critical constraints**:

- At least **two regions** must have **≥ 2 validators** to avoid single-point-of-failure for an entire region
- Total validators must satisfy BFT quorum: `n ≥ 3f + 1` (7 validators → tolerates 2 Byzantine faults)

### 3.3 Base Deployment Reference

For keys, snapshots, and base deployment procedures, refer to:

- [QBIND_MAINNET_RUNBOOK.md](./QBIND_MAINNET_RUNBOOK.md) — Operational runbook (T216)
- [QBIND_KEY_MANAGEMENT_DESIGN.md](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md) — Key management (T209)

---

## 4. Test Sequence (Real-Infra Dress Rehearsal)

Run the following tests **in order** on the live multi-region cluster. All tests must pass before proceeding.

### 4.1 Test Sequence Table

| # | Test | Command | Goal | Pass Criteria | Duration | Related |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | **Basic Health & Invariants** | `cargo test -p qbind-node --test t185_mainnet_profile_tests` | Ensure config invariants match MainNet expectations | All tests green | ~1 min | T185, T237 |
| 2 | **Consensus Chaos** | `cargo test -p qbind-node --test t222_consensus_chaos_harness -- --test-threads=1` | Verify consensus under leader crashes, message loss, partitions | No `commit_divergence`, no block mismatch, bounded view-change churn | ~5 min | T222 |
| 3 | **DAG–Consensus Coupling** | `cargo test -p qbind-node --test t221_dag_coupling_cluster_tests` | Verify DAG coupling invariants (I1–I5) | `block_mismatch_total == 0`, coupling violations = 0 in Enforce mode | ~3 min | T221 |
| 4 | **Stage B Soak** | `cargo test -p qbind-node --test t223_stage_b_soak_harness -- --test-threads=1` | Verify Stage B determinism over extended run | No state/receipt mismatches, clear parallel vs fallback counts | ~10 min | T223 |
| 5 | **PQC Performance** | `cargo test -p qbind-node --test t234_pqc_end_to_end_perf_tests -- --ignored --nocapture` | Verify PQC signing performance with real ML-DSA-44 | TPS and latency within documented factor of synthetic baseline | ~5 min | T234 |
| 6 | **Fee Adversarial** | `cargo test -p qbind-node --test t236_fee_market_adversarial_tests -- --test-threads=1` | Verify fee market resilience under adversarial conditions | No negative balances, no double-spend, honest inclusion > 30% | ~5 min | T236 |
| 7 | **Multi-Region Invariants** | `cargo test -p qbind-node --test t238_multi_region_latency_harness` | Verify consensus across simulated multi-region conditions | Safety = true, height divergence bounded, view changes reasonable | ~5 min | T238 |

### 4.2 Running Tests on Real Infrastructure

For real-infra validation (beyond the synthetic harness), collect the following from your live cluster:

```bash
# Check height divergence across nodes
curl -s http://node-a:9090/metrics | grep qbind_consensus_current_view
curl -s http://node-b:9090/metrics | grep qbind_consensus_current_view
curl -s http://node-c:9090/metrics | grep qbind_consensus_current_view

# Check for safety violations
curl -s http://node-a:9090/metrics | grep qbind_consensus_safety
curl -s http://node-a:9090/metrics | grep qbind_dag_coupling_block_mismatch

# Check P2P health
curl -s http://node-a:9090/metrics | grep qbind_p2p_outbound_peers
curl -s http://node-a:9090/metrics | grep qbind_anti_eclipse
```

### 4.3 Mapping Live Metrics to T238 Expectations

| Metric | T238 Synthetic Expectation | Real-Infra Acceptance |
| :--- | :--- | :--- |
| `max_height_divergence` | ≤ 5 (normal), ≤ 10 (stress) | Same bounds |
| `block_mismatch_total` | 0 | **Must be 0** |
| `safety_violated` | false | **Must be false** |
| `view_changes_total` | Profile-dependent | Should correlate with network quality |
| `p50/p90_latency_ms` | Profile-dependent | Should correlate with measured RTT |

---

## 5. Pass/Fail Criteria

### 5.1 Safety Invariants (Hard Gates)

The following are **non-negotiable** pass criteria. Any failure blocks MainNet launch:

| Invariant | Criterion | Action if Failed |
| :--- | :--- | :--- |
| **Commit Divergence** | `commit_divergence == false` | Debug consensus logic; do not launch |
| **Block Mismatch** | `block_mismatch_total == 0` | Debug DAG coupling; do not launch |
| **Double Spend** | `double_spend_detected == false` | Critical bug; halt all activity |
| **Negative Balances** | No account with `balance < 0` | Critical bug; halt all activity |

### 5.2 Height Divergence Bounds

| Profile Type | Max Height Divergence | Notes |
| :--- | :--- | :--- |
| **Normal** (uniform, asymmetric) | ≤ 5 blocks | Tighter bound for expected conditions |
| **Stress** (lossy, mixed) | ≤ 10 blocks | Looser bound under adverse conditions |
| **All profiles** | **Must converge** | Divergence must stabilize, not grow unbounded |

### 5.3 P2P Metrics

| Metric | Minimum | Notes |
| :--- | :--- | :--- |
| `qbind_p2p_outbound_peers` | ≥ 4 | Per MainNet min_outbound requirement |
| `qbind_anti_eclipse_asn_diversity` | ≥ 2 | Per T231 anti-eclipse constraints |
| `qbind_p2p_connected_peers` | ≥ `outbound_target` | Should maintain target peer count |

### 5.4 Performance Bounds

| Metric | Expectation | Notes |
| :--- | :--- | :--- |
| **Real-Infra TPS** | 0.5–2× of T234 synthetic baseline | Hardware and network dependent |
| **Real-Infra Latency** | 0.5–2× of T234 synthetic baseline | Accounts for real network RTT |
| **Commit Latency p99** | < 10 seconds | Under normal operation |

### 5.5 Failure Response

If any invariant fails:

1. **Stop** — Do not proceed with launch or upgrade
2. **Diagnose** — Review logs, metrics, and network measurements
3. **Adjust** — Consider:
   - Tuning anti-eclipse caps (`max_peers_per_ipv4_prefix`, `min_asn_diversity`)
   - Adjusting mempool limits (`per_sender_max_txs`, eviction rate limits)
   - Re-evaluating region selection (may need lower-latency regions)
4. **Re-run** — Execute the full dress rehearsal again after adjustments
5. **Document** — Record all findings for the audit trail

---

## 6. Governance & Upgrade Requirements

### 6.1 Integration with Governance (T224/T225)

For any **Class C upgrade (hard-fork)**, MainNet operators must:

1. **Build binaries** for the new version
2. **Repeat the multi-region dress rehearsal** on staging or Beta infrastructure
3. **All T238.5 checks must pass** before signing/accepting an upgrade envelope (T224/T225)

### 6.2 Upgrade Checklist

| Step | Requirement | Evidence Required |
| :--- | :--- | :--- |
| 1 | New binary built and tested | CI green, binary hash |
| 2 | T238.5 dress rehearsal complete | Metrics export, Grafana screenshots |
| 3 | Safety invariants verified | `commit_divergence == false`, `block_mismatch_total == 0` |
| 4 | Height divergence within bounds | Metrics showing convergence |
| 5 | P2P health maintained | `outbound_peers >= 4`, ASN diversity OK |
| 6 | Performance acceptable | TPS/latency within documented bounds |

### 6.3 Audit Evidence

Auditors should expect to see the following evidence for T238.5 compliance:

- Network measurement logs (RTT, jitter, loss tables)
- Prometheus metrics exports covering the test duration
- Grafana dashboard screenshots showing key invariants
- Test harness output logs (all tests green)
- Signed attestation from operators that all criteria passed

---

## 7. Quick Reference Checklist

Copy-paste this checklist for each dress rehearsal run:

```markdown
## T238.5 Multi-Region Dress Rehearsal Checklist

**Date**: _______________  
**Operator**: _______________  
**Regions**: _______________

### Prerequisites
- [ ] T238 synthetic harness green
- [ ] T185/T237 invariants green
- [ ] Network measurements documented
- [ ] Monitoring infrastructure ready

### Test Sequence
- [ ] T185: Basic health & invariants — PASS / FAIL
- [ ] T222: Consensus chaos — PASS / FAIL
- [ ] T221: DAG–Consensus coupling — PASS / FAIL
- [ ] T223: Stage B soak — PASS / FAIL
- [ ] T234: PQC performance — PASS / FAIL
- [ ] T236: Fee adversarial — PASS / FAIL
- [ ] T238: Multi-region invariants — PASS / FAIL

### Safety Invariants
- [ ] commit_divergence == false
- [ ] block_mismatch_total == 0
- [ ] No double-spend detected
- [ ] No negative balances

### Bounds Checks
- [ ] max_height_divergence ≤ 5 (normal) / ≤ 10 (stress)
- [ ] outbound_peers ≥ 4
- [ ] ASN diversity ≥ 2

### Performance
- [ ] TPS within 0.5–2× of T234 baseline
- [ ] Latency within 0.5–2× of T234 baseline

### Sign-Off
- [ ] All checks passed — Ready for MainNet / Upgrade

Signature: _______________
Date: _______________
```

---

## 8. Cross-References

### 8.1 Related Documents

| Document | Purpose |
| :--- | :--- |
| [QBIND_MAINNET_V0_SPEC.md](../mainnet/QBIND_MAINNET_V0_SPEC.md) | MainNet v0 specification (§5.6 for T238) |
| [QBIND_MAINNET_AUDIT_SKELETON.md](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md) | MainNet audit tracking (MN-R4) |
| [QBIND_MAINNET_RUNBOOK.md](./QBIND_MAINNET_RUNBOOK.md) | Operational runbook (T216) |
| [QBIND_PERF_AND_TPS_DESIGN.md](../devnet/QBIND_PERF_AND_TPS_DESIGN.md) | Performance testing design (T234) |
| [QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md](../gov/QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md) | Governance model (T224/T225) |

### 8.2 Related Test Harnesses

| Harness | File | Purpose |
| :--- | :--- | :--- |
| T185 | `t185_mainnet_profile_tests.rs` | MainNet config invariants |
| T221 | `t221_dag_coupling_cluster_tests.rs` | DAG–Consensus coupling |
| T222 | `t222_consensus_chaos_harness.rs` | Consensus chaos testing |
| T223 | `t223_stage_b_soak_harness.rs` | Stage B determinism soak |
| T234 | `t234_pqc_end_to_end_perf_tests.rs` | PQC E2E performance |
| T236 | `t236_fee_market_adversarial_tests.rs` | Fee market adversarial |
| T238 | `t238_multi_region_latency_harness.rs` | Multi-region latency simulation |

---

## Appendix A: T238 Profile Parameter Reference

Quick reference for T238 `RegionNetworkProfile` presets used in the synthetic harness:

| Profile | Base Latency (ms) | Jitter (ms) | Loss (basis points) |
| :--- | :--- | :--- | :--- |
| `same_region()` | 1 | 0 | 0 |
| `low_latency()` | 30 | 5 | 0 |
| `moderate_latency()` | 80 | 15 | 0 |
| `high_latency()` | 150 | 30 | 0 |
| `lossy()` | 80 | 20 | 500 (5%) |
| `high_jitter()` | 60 | 50 | 0 |

> **Note**: Loss is measured in **basis points** (bps), where 10,000 bps = 100%. For example, 500 bps = 5% packet loss.

These presets are defined in `t238_multi_region_latency_harness.rs` and provide the reference values for mapping real infrastructure measurements.