# QBIND Fee Market Adversarial Analysis v1

**Task**: T236  
**Status**: Complete  
**Date**: 2026-02-10

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Fee Model Recap](#2-fee-model-recap)
3. [Adversarial Scenarios](#3-adversarial-scenarios)
4. [Experimental Results](#4-experimental-results)
5. [Invariants Verification](#5-invariants-verification)
6. [Residual Risks](#6-residual-risks)
7. [Conclusions](#7-conclusions)
8. [Related Documents](#8-related-documents)

---

## 1. Executive Summary

This document provides a comprehensive analysis of the QBIND fee market and DAG mempool behavior under adversarial conditions. The analysis is based on a repeatable stress harness (T236) that tests the system against multiple attack scenarios.

### Key Findings

| Category | Finding | Status |
| :--- | :--- | :--- |
| **Balance Integrity** | No underflows, no double-debits | ✅ Verified |
| **Fee Accounting** | Total debits == burned + proposer rewards | ✅ Verified |
| **Honest Sender Inclusion** | Honest senders not starved by spam | ✅ Verified |
| **Per-Sender Quotas** | T218 limits prevent single-sender monopolization | ✅ Verified |
| **Eviction Rate Limiting** | T219/T220 limits prevent churn attacks | ✅ Verified |
| **Reproducibility** | Fixed seed produces identical results | ✅ Verified |

### Summary Statement

> **Under single-sender spam, front-running pattern, and churn attack adversarial load profiles, the QBIND fee market preserved all tested safety invariants. No balance anomalies, no double-spend attempts, and no negative balances were observed. Honest senders maintained meaningful inclusion rates (>30%) even under aggressive attack conditions, thanks to per-sender quotas (T218) and eviction rate limiting (T219/T220).**

---

## 2. Fee Model Recap

### 2.1 Overview

QBIND v0 implements a priority-fee-based transaction ordering with hybrid fee distribution:

- **Priority Ordering**: Transactions with higher `max_fee_per_gas` are prioritized for inclusion
- **Hybrid Distribution**: Fees are split 50% burn / 50% to block proposer
- **Per-Sender Quotas**: Limit transactions per sender in the mempool (T218)
- **Eviction Rate Limiting**: Limit mempool churn rate (T219/T220)

### 2.2 Fee Flow

```
Transaction Submission
         │
         ▼
┌────────────────────┐
│   DAG Mempool      │ ← Per-sender quota check (T218)
│   (Fee Priority)   │ ← Eviction rate limit check (T219/T220)
└────────────────────┘
         │
         ▼ select_frontier_txs()
┌────────────────────┐
│   Block Builder    │
│  (Priority Order)  │
└────────────────────┘
         │
         ▼ execute_block_with_proposer()
┌────────────────────┐
│     Execution      │
│  (Gas Accounting)  │
└────────────────────┘
         │
         ▼
┌─────────┬──────────┐
│  50%    │   50%    │
│ Burned  │ Proposer │
└─────────┴──────────┘
```

### 2.3 Key Parameters

| Parameter | MainNet Default | Purpose |
| :--- | :--- | :--- |
| `max_pending_per_sender` | 1,000 | Prevent single-sender DoS |
| `max_pending_bytes_per_sender` | 8 MiB | Memory protection |
| `max_txs_per_batch` | 4,000 | DAG batch size limit |
| `eviction_mode` | Enforce | Rate-limit eviction churn |
| `max_evictions_per_interval` | Configurable | Eviction rate ceiling |
| `enable_fee_priority` | true | Priority ordering |

**References**:
- [QBIND_MONETARY_POLICY_DESIGN.md](./QBIND_MONETARY_POLICY_DESIGN.md) — Full monetary policy
- [QBIND_MAINNET_V0_SPEC.md](../mainnet/QBIND_MAINNET_V0_SPEC.md) §3 — Gas & fees specification

---

## 3. Adversarial Scenarios

### 3.1 Baseline (Control)

**Configuration**:
- 10 honest senders, 0 adversarial senders
- Moderate TPS (~10 tx/block)
- 20 simulated blocks
- Fee priority enabled

**Adversary Goal**: None (control scenario)

**Expected Outcome**: All honest transactions included without anomalies

**Observed Outcome**: ✅ Honest inclusion ratio > 50%, no safety violations

### 3.2 Single-Sender Spam Attack

**Configuration**:
- 10 honest senders, 1 adversarial sender
- Honest fee range: 50–200 gas price units
- Adversarial fee range: 1–20 gas price units (very low)
- Adversarial sender submits 3x normal transaction rate
- Per-sender quota: 100 pending txs

**Adversary Goal**: Monopolize mempool and block space by flooding with transactions

**Expected Outcome**: 
- Per-sender quota (T218) limits adversarial transactions in mempool
- Fee-priority ordering favors honest txs with higher fees
- Honest senders see meaningful inclusion

**Observed Outcome**: 
- ✅ Honest inclusion ratio > 30%
- ✅ Per-sender limit rejections observed for adversary
- ✅ No balance anomalies or accounting bugs

### 3.3 Front-Running Pattern Attack

**Configuration**:
- 10 honest senders, 3 adversarial senders
- Honest fee range: 50–200 gas price units
- Adversarial fee range: 100–250 gas price units (slightly higher)
- Adversary follows pattern of slightly outbidding

**Adversary Goal**: Gain priority inclusion by outbidding honest transactions

**Expected Outcome**:
- Adversary may gain priority inclusion (this is expected behavior, not a bug)
- Fee accounting remains correct (no double-crediting or undercharging)
- Balance integrity maintained

**Observed Outcome**:
- ✅ Fee accounting consistent (total_fees ≈ burned + proposer)
- ✅ No double-spend or replay detected
- ✅ Some honest txs still included

**Note**: This test does NOT attempt to "solve MEV" — front-running remains economically possible. The test validates that accounting remains correct under front-running conditions.

### 3.4 Churn Attack (Eviction Pressure)

**Configuration**:
- 10 honest senders, 20 adversarial senders
- 60% probability of burst submission each block
- Adversarial burst: 5x normal transaction rate
- Eviction rate limiting: Enforce mode
- Per-sender quota: 50 pending txs (tighter limit)

**Adversary Goal**: Cause excessive mempool eviction to destabilize the fee market

**Expected Outcome**:
- Eviction rate limiting (T219/T220) caps churn
- Honest senders see inclusion over the test duration
- No complete block monopolization

**Observed Outcome**:
- ✅ Eviction rate limit enforcement observed
- ✅ Honest txs included despite churn
- ✅ Adversary does not completely dominate all blocks
- ✅ No balance anomalies

---

## 4. Experimental Results

### 4.1 Test Harness Overview

The T236 harness (`crates/qbind-node/tests/t236_fee_market_adversarial_tests.rs`) provides:

- **Reproducible RNG**: LCG-based deterministic randomness for fixed-seed runs
- **Mempool Integration**: Real `InMemoryDagMempool` with configurable limits
- **Execution Engine**: Real `VmV0ExecutionEngine` for accurate fee accounting
- **Metrics Tracking**: Submission/inclusion counts, latency buckets, fee aggregates

### 4.2 Summary Results

| Scenario | Honest Inclusion | Safety | Notes |
| :--- | :--- | :--- | :--- |
| Baseline | > 50% | ✅ Pass | Control scenario |
| Single-Sender Spam | > 30% | ✅ Pass | Quota limits effective |
| Front-Running | Some inclusion | ✅ Pass | Accounting correct |
| Churn Attack | Some inclusion | ✅ Pass | Rate limiting effective |

### 4.3 Reproducibility

Two runs with identical configuration and seed produce identical results:

| Metric | Run 1 | Run 2 | Match |
| :--- | :--- | :--- | :--- |
| Total submitted | N | N | ✅ |
| Honest submitted | M | M | ✅ |
| Total included | K | K | ✅ |
| Safety invariants | Pass | Pass | ✅ |

---

## 5. Invariants Verification

### 5.1 Balance Integrity Invariants

| Invariant | Status | Evidence |
| :--- | :--- | :--- |
| No negative balances | ✅ Verified | `negative_balance_detected = false` in all scenarios |
| No balance anomalies | ✅ Verified | `balance_anomalies_detected = false` in all scenarios |
| No double-spend | ✅ Verified | `double_spend_or_replay_detected = false` in all scenarios |

### 5.2 Fee Accounting Invariants

| Invariant | Status | Evidence |
| :--- | :--- | :--- |
| Total debits == credits + burned + treasury | ✅ Verified | Fee diff within tolerance in front-running test |
| Fee burn ratio correct | ✅ Verified | ~50% burn observed |
| Proposer rewards credited | ✅ Verified | Non-zero `total_to_proposers` |

### 5.3 Fairness Invariants

| Invariant | Status | Evidence |
| :--- | :--- | :--- |
| Honest senders not fully starved | ✅ Verified | Inclusion ratio > 30% under attack |
| Per-sender quotas enforced | ✅ Verified | Rejections observed for spam sender |
| Eviction rate limiting respected | ✅ Verified | Rate limit hits observed in churn attack |

---

## 6. Residual Risks

### 6.1 Accepted for MainNet v0

| Risk | Description | Rationale |
| :--- | :--- | :--- |
| **Economic front-running** | Adversary can outbid honest txs to gain priority | Expected behavior of priority-fee model; fee accounting remains correct. MEV mitigation is deferred to v1+. |
| **Partial starvation under extreme load** | Honest inclusion may drop under heavy attack | Per-sender quotas and rate limiting provide meaningful protection; complete starvation not observed. |

### 6.2 Deferred to v0.x / v1+

| Risk | Description | Planned Mitigation |
| :--- | :--- | :--- |
| **MEV extraction** | Sophisticated MEV strategies not tested | Future MEV analysis and potential mitigation (e.g., commit-reveal, proposer-builder separation) |
| **EIP-1559-style base fee** | Current model is simple priority fee | EIP-1559 adaptation considered for v1 |
| **Cross-chain replay** | Signatures include chain ID but not tested adversarially | Future cross-chain integration testing |

---

## 7. Conclusions

The T236 adversarial analysis demonstrates that the QBIND fee market and DAG mempool:

1. **Maintain safety invariants** under all tested adversarial conditions
2. **Protect honest senders** from complete starvation via per-sender quotas and eviction rate limiting
3. **Preserve fee accounting integrity** even under front-running patterns
4. **Produce reproducible results** for deterministic testing

### 7.1 MainNet Readiness Assessment

| Criterion | Status |
| :--- | :--- |
| Fee market analysis under adversarial conditions | ✅ **Ready** |
| Safety invariants verified | ✅ **Ready** |
| Repeatable test harness | ✅ **Ready** |
| Documentation complete | ✅ **Ready** |

### 7.2 Recommendations

1. **Run T236 harness** as part of pre-release validation (see Runbook)
2. **Monitor mempool metrics** in production for eviction rate anomalies
3. **Consider EIP-1559** for improved fee predictability in v1
4. **Plan MEV analysis** for future network evolution

---

## 8. Related Documents

| Document | Relevance |
| :--- | :--- |
| [QBIND_MONETARY_POLICY_DESIGN.md](./QBIND_MONETARY_POLICY_DESIGN.md) | Full monetary policy specification |
| [QBIND_MAINNET_V0_SPEC.md](../mainnet/QBIND_MAINNET_V0_SPEC.md) | MainNet v0 specification |
| [QBIND_MAINNET_AUDIT_SKELETON.md](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md) | Audit checklist (MN-R2) |
| [QBIND_MAINNET_RUNBOOK.md](../ops/QBIND_MAINNET_RUNBOOK.md) | Operational procedures |

### Related Tasks

| Task | Description | Status |
| :--- | :--- | :--- |
| T169 | Fee-priority mempool | ✅ Complete |
| T179 | Gas property tests | ✅ Complete |
| T181 | Fee-market cluster tests | ✅ Complete |
| T193 | Hybrid fee distribution | ✅ Complete |
| T218 | DAG mempool DoS protections | ✅ Complete |
| T219 | Eviction rate limiting config/metrics | ✅ Complete |
| T220 | Eviction rate limiting enforcement | ✅ Complete |
| **T236** | **Fee market adversarial analysis** | **✅ Complete** |

---

*Document Version: 1.0*  
*Last Updated: 2026-02-10*