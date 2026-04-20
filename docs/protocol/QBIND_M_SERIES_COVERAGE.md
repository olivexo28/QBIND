# QBIND M-Series Coverage Index & Audit Map

**Version**: 1.0  
**Date**: 2026-02-16  
**Status**: Pre-TestNet Documentation

This document provides a comprehensive audit-friendly index for the QBIND M-series mitigation track. It maps security risks and specification gaps to their corresponding mitigations, code implementations, and test suites.

---

## 1. Overview

### What is the M-Series?

The M-series (M0–M20) is QBIND's **risk-driven mitigation track**—a systematic effort to address protocol gaps, security risks, and specification deficiencies identified during internal audits. Each milestone targets one or more specific risks and delivers:

1. Code implementation (where applicable)
2. Test coverage demonstrating the mitigation
3. Specification updates in the whitepaper and/or protocol report
4. Documentation of design decisions and trade-offs

### Pre-TestNet Status

**All pre-testnet critical issues have been mitigated in code, tests, and specification.** The M-series has addressed:

- Slashing enforcement for all offense classes (O1–O5)
- Minimum stake requirements at registration and epoch boundary
- Timeout/view-change liveness under partition
- DoS cookie protection for connection establishment
- NodeId extraction from KEMTLS certificates
- Mutual authentication for inbound/outbound connections
- Remote signer security with KEMTLS mutual auth enforcement
- Governance-slashing parameter wiring
- Evidence ingestion hardening against abuse
- Atomic epoch transitions with crash recovery
- Gas accounting formalization
- Slashing state persistence and canonicalization

### Intentionally Open Items

**C3 (Reporter Rewards)** is intentionally left open as **future economics/tokenomics work**, not a protocol safety gap. Evidence reporting is hardened (M15) and abuse-resistant; monetary incentives will be designed separately when tokenomics are defined. See Section 4 for details.

---

## 2. Index by Risk/Spec Gap

This section maps each risk or specification gap to its mitigation status, implementation, and tests.

### 2.1 Slashing Enforcement

| Field | Value |
|-------|-------|
| **Gap ID** | Risk: No slashing enforcement |
| **Status** | ✅ Mitigated (M9, M11) |
| **Milestones** | M9 (O1/O2 penalties), M11 (O3–O5 penalties) |
| **Description** | All offense classes now have enforced economic penalties with deterministic signature verification. |

**Key Code Files:**
- `crates/qbind-consensus/src/slashing/mod.rs` — `AtomicSlashingBackend`, `PenaltySlashingEngine`, `apply_penalty_atomic()`
- `crates/qbind-node/src/ledger_slashing_backend.rs` — Production backend implementation
- `crates/qbind-types/src/state_validator.rs` — `ValidatorRecord` (canonical economic state)

**Key Test Files:**
- `crates/qbind-node/tests/m9_slashing_penalty_tests.rs` — O1/O2 atomic enforcement
- `crates/qbind-node/tests/m11_slashing_penalty_o3_o5_tests.rs` — O3–O5 enforcement (21 tests)

**Whitepaper Reference:** Section 12.2 (Byzantine Validator Behavior), Section 12.2.1 (Slashing Penalty Schedule)

---

### 2.2 Minimum Stake Requirement

| Field | Value |
|-------|-------|
| **Gap ID** | C2, Spec Gap 3.11: No minimum stake enforcement |
| **Status** | ✅ Mitigated (M2.1–M2.4) |
| **Milestones** | M2.1 (stake filter function), M2.2 (epoch state provider), M2.3 (node-level wiring), M2.4 (production constructors) |
| **Description** | `min_validator_stake` enforced at both registration and epoch boundary. Validators below threshold excluded from active set. |

**Key Code Files:**
- `crates/qbind-consensus/src/validator_set.rs` — `build_validator_set_with_stake_filter()`, `StakeFilteringEpochStateProvider`
- `crates/qbind-node/src/hotstuff_node_sim.rs` — `with_stake_filtering_epoch_state_provider()`, `enable_stake_filtering_for_environment()`, `new_with_stake_filtering()`
- `crates/qbind-system/src/validator_program.rs` — Registration-time enforcement

**Key Test Files:**
- `crates/qbind-consensus/tests/validator_set_tests.rs` — Core filtering logic
- `crates/qbind-consensus/tests/m2_2_stake_filter_epoch_transition_tests.rs` — Epoch integration (13 tests)
- `crates/qbind-node/tests/m2_3_stake_filtering_node_integration_tests.rs` — Node-level tests (8 tests)
- `crates/qbind-node/tests/m2_4_production_stake_filtering_tests.rs` — Production wiring

**Whitepaper Reference:** Section 18 (Validator Set Transition and Epoch Boundary Semantics)

---

### 2.3 MainNet Slashing Mode Enforcement

| Field | Value |
|-------|-------|
| **Gap ID** | Spec Gap 3.12: Slashing mode bypass |
| **Status** | ✅ Mitigated (M4) |
| **Milestones** | M4 |
| **Description** | MainNet rejects `Off` and `RecordOnly` slashing modes; must use `EnforceCritical` or `EnforceAll`. |

**Key Code Files:**
- `crates/qbind-node/src/node_config.rs` — `validate_for_mainnet()` in `SlashingConfig`

**Key Test Files:**
- `crates/qbind-node/tests/m4_slashing_mode_enforcement_tests.rs`
- `crates/qbind-node/tests/t237_mainnet_launch_profile_tests.rs`

**Whitepaper Reference:** Section 12.2 (Byzantine Validator Behavior)

---

### 2.4 Timeout/View-Change Liveness

| Field | Value |
|-------|-------|
| **Gap ID** | Spec Gap 2.4, Impl Gap 3.3: Liveness failure under partition |
| **Status** | ✅ Mitigated (M5) |
| **Milestones** | M5 |
| **Description** | Production-ready timeout and view-change mechanism with exponential backoff, TC formation, and locked-height safety. |

**Key Code Files:**
- `crates/qbind-consensus/src/basic_hotstuff_engine.rs` — `on_timeout_msg()`, `on_timeout_certificate()`, `try_advance_to_view()`
- `crates/qbind-consensus/src/pacemaker.rs` — `TimeoutPacemaker`, `TimeoutPacemakerConfig`
- `crates/qbind-consensus/src/timeout.rs` — `TimeoutAccumulator`, `TimeoutCertificate`

**Key Test Files:**
- `crates/qbind-consensus/tests/m5_timeout_view_change_tests.rs` — 28 tests covering leader crash recovery, partition simulation, safety preservation

**Whitepaper Reference:** Section 17 (View-Change and Liveness Model), Section 17.3.1 (Exponential Backoff Parameters)

---

### 2.5 DoS Cookie Protection

| Field | Value |
|-------|-------|
| **Gap ID** | Impl Gap 3.9: Connection exhaustion attacks |
| **Status** | ✅ Mitigated (M6) |
| **Milestones** | M6 |
| **Description** | 2-step handshake with stateless HMAC-SHA3-256 cookie; no KEM decapsulation until valid cookie received. |

**Key Code Files:**
- `crates/qbind-net/src/cookie.rs` — `CookieConfig`, HMAC-SHA3-256 validation
- `crates/qbind-net/src/handshake.rs` — `handle_client_init_with_cookie()`, `ServerHandshakeResponse`

**Key Test Files:**
- `crates/qbind-net/tests/m6_dos_cookie_protection_tests.rs` — 10 tests covering invalid/expired cookies, IP binding, backward compatibility

**Whitepaper Reference:** Section 5 (Networking Security Properties)

---

### 2.6 NodeId Extraction from KEMTLS

| Field | Value |
|-------|-------|
| **Gap ID** | Impl Gap 3.4: Peer identity not verified |
| **Status** | ✅ Mitigated (M7, M8) |
| **Milestones** | M7 (outbound NodeId derivation), M8 (mutual auth for inbound) |
| **Description** | NodeId derived from KEMTLS identity via domain-separated SHA3-256. Mutual authentication for both connection directions. |

**Key Code Files:**
- `crates/qbind-hash/src/net.rs` — `derive_node_id_from_pubkey()`, `derive_node_id_from_cert()`, `NODEID_DOMAIN_TAG`
- `crates/qbind-net/src/handshake.rs` — `verify_client_cert_if_required()`, `MutualAuthMode`
- `crates/qbind-node/src/p2p_tcp.rs` — Outbound/inbound NodeId derivation
- `crates/qbind-node/src/node_config.rs` — `MutualAuthConfig`

**Key Test Files:**
- `crates/qbind-node/tests/m7_nodeid_extraction_tests.rs` — 14 tests for deterministic derivation
- `crates/qbind-net/tests/m8_mutual_auth_tests.rs` — 9 tests for mutual auth
- `crates/qbind-node/tests/m8_mutual_auth_config_tests.rs` — 17 tests for config validation

**Whitepaper Reference:** Section 5 (Networking Security Properties)

---

### 2.7 Remote Signer Security

| Field | Value |
|-------|-------|
| **Gap ID** | Impl Gap 3.8: Remote signer channel security |
| **Status** | ✅ Mitigated (M10, M10.1) |
| **Milestones** | M10 (protocol foundation), M10.1 (policy enforcement) |
| **Description** | Remote signer with KEMTLS mutual auth; `LoopbackTesting` forbidden on TestNet/MainNet. |

**Key Code Files:**
- `crates/qbind-node/src/remote_signer.rs` — Protocol implementation, `REMOTE_SIGNER_DOMAIN_TAG`, replay protection
- `crates/qbind-node/src/node_config.rs` — `validate_signer_mode_for_mainnet()`, `validate_signer_mode_for_testnet()`
- `crates/qbind-node/src/metrics.rs` — `SignerIsolationMetrics`

**Key Test Files:**
- `crates/qbind-node/tests/m10_signer_isolation_tests.rs` — Signer isolation tests
- `crates/qbind-node/tests/m10_1_signer_policy_tests.rs` — 20 tests for policy enforcement

**Whitepaper Reference:** Section 9 (Cryptographic Architecture)

---

### 2.8 Validator Set Transition Formalism

| Field | Value |
|-------|-------|
| **Gap ID** | Spec Gap 2.2: Validator set changes not formally specified |
| **Status** | ✅ Mitigated (M12) |
| **Milestones** | M12 |
| **Description** | Formal specification for epoch-based validator transitions with eligibility predicates and persistence ordering. |

**Key Code Files:**
- `crates/qbind-consensus/src/validator_set.rs` — ValidatorSet construction algorithm
- `crates/qbind-types/src/state_validator.rs` — `ValidatorRecord`, eligibility predicates

**Key Test Files:**
- `crates/qbind-consensus/tests/validator_set_tests.rs`

**Whitepaper Reference:** Section 18 (Validator Set Transition and Epoch Boundary Semantics)

---

### 2.9 Canonical Economic State

| Field | Value |
|-------|-------|
| **Gap ID** | Item 10: Stake synchronization gap |
| **Status** | ✅ Mitigated (M13) |
| **Milestones** | M13 |
| **Description** | `ValidatorRecord.stake` and `ValidatorRecord.jailed_until_epoch` are canonical; `ValidatorSlashingState` is non-authoritative mirror. |

**Key Code Files:**
- `crates/qbind-types/src/state_validator.rs` — `ValidatorRecord` with `is_eligible_at_epoch()`
- `crates/qbind-ledger/src/slashing_ledger.rs` — M13 canonicalization documentation

**Key Test Files:**
- `crates/qbind-node/tests/m13_economic_state_unification_tests.rs` — 12 restart safety tests

**Whitepaper Reference:** Section 16.8 (Slashing State Persistence)

---

### 2.10 Governance Slashing Parameters

| Field | Value |
|-------|-------|
| **Gap ID** | Impl Gap 3.13, Item 9: Governance parameters not connected |
| **Status** | ✅ Mitigated (M14) |
| **Milestones** | M14 |
| **Description** | `SlashingPenaltySchedule` in `ParamRegistry` with epoch-boundary activation semantics. |

**Key Code Files:**
- `crates/qbind-types/src/state_governance.rs` — `SlashingPenaltySchedule` (O1–O5 params + activation_epoch)
- `crates/qbind-consensus/src/slashing/mod.rs` — `GovernanceSlashingSchedule`, `PenaltyEngineConfig::from_governance_schedule()`

**Key Test Files:**
- `crates/qbind-node/tests/m14_governance_slashing_params_tests.rs` — 15 tests (deterministic load, activation, fail-closed)

**Whitepaper Reference:** Section 12.2.2 (Governance and Activation Semantics)

---

### 2.11 Evidence Ingestion Hardening

| Field | Value |
|-------|-------|
| **Gap ID** | Impl Gap 3.14: Evidence abuse/DoS |
| **Status** | ✅ Mitigated (M15) |
| **Milestones** | M15 |
| **Description** | 8-step verification ordering with cheap checks first; per-block cap, size limits, age bounds, deduplication. |

**Key Code Files:**
- `crates/qbind-consensus/src/slashing/mod.rs` — `HardenedEvidenceIngestionEngine`, `EvidenceIngestionConfig`, `EvidenceRejectionReason`

**Key Test Files:**
- `crates/qbind-node/tests/m15_evidence_ingestion_hardening_tests.rs` — 25 tests (duplicate rejection, oversized, non-validator reporter, per-block cap, ordering)

**Whitepaper Reference:** Section 12.2.3 (Reporter Incentives - Future Work)

---

### 2.12 Epoch Transition Atomicity

| Field | Value |
|-------|-------|
| **Gap ID** | Spec Gap 2.6, Item 4: Epoch transition crash window |
| **Status** | ✅ Mitigated (M16) |
| **Milestones** | M16 |
| **Description** | Atomic RocksDB WriteBatch for all epoch-boundary writes; `EpochTransitionMarker` for crash detection. |

**Key Code Files:**
- `crates/qbind-node/src/storage.rs` — `EpochTransitionBatch`, `apply_epoch_transition_atomic()`, `EpochTransitionMarker`, `verify_epoch_consistency_on_startup()`

**Key Test Files:**
- `crates/qbind-node/tests/m16_epoch_transition_hardening_tests.rs` — 14 tests with failure injection

**Whitepaper Reference:** Section 18.4.3 (Persistence Ordering)

---

### 2.13 Slashing Economics Specification

| Field | Value |
|-------|-------|
| **Gap ID** | Spec Gap 2.5: Slashing penalty amounts not specified |
| **Status** | ✅ Mitigated (M17) |
| **Milestones** | M17 |
| **Description** | Formal penalty schedule table added to whitepaper with O1–O5 slash_bps, jail_epochs, evidence types, and verification rules. |

**Key Code Files:**
- (Documentation-only milestone)

**Key Test Files:**
- `crates/qbind-node/tests/m9_slashing_penalty_tests.rs`
- `crates/qbind-node/tests/m11_slashing_penalty_o3_o5_tests.rs`

**Whitepaper Reference:** Section 12.2.1 (Slashing Penalty Schedule)

---

### 2.14 Gas Accounting Formalization

| Field | Value |
|-------|-------|
| **Gap ID** | Spec Gap 2.3: Gas model lacks formal metering rules |
| **Status** | ✅ Mitigated (M18) |
| **Milestones** | M18 |
| **Description** | Formal gas transition function with determinism requirements and overflow protection via checked arithmetic. |

**Key Code Files:**
- `crates/qbind-ledger/src/execution.rs` — `execute_tx_with_gas_and_proposer()` with checked arithmetic
- `crates/qbind-runtime/src/gas_model.rs` — Gas cost calculation
- `crates/qbind-runtime/src/block_apply.rs` — Block-level gas accounting

**Key Test Files:**
- `crates/qbind-node/tests/m18_gas_accounting_tests.rs` — 19 tests

**Whitepaper Reference:** Section 19 (Gas Accounting and Deterministic Metering Model)

---

### 2.15 Slashing State Persistence Canonicalization

| Field | Value |
|-------|-------|
| **Gap ID** | Impl Gap 3.15, Item 1: Slashing state restart safety |
| **Status** | ✅ Mitigated (M1, M19) |
| **Milestones** | M1 (RocksDB persistence), M19 (canonicalization hardening) |
| **Description** | Persistent slashing ledger with atomic updates; fail-closed corruption detection; consensus-critical vs non-critical classification. |

**Key Code Files:**
- `crates/qbind-ledger/src/slashing_ledger.rs` — `RocksDbSlashingLedger`, `apply_slashing_update_atomic()`, `verify_slashing_consistency_on_startup()`

**Key Test Files:**
- `crates/qbind-node/tests/m19_slashing_persistence_canonicalization_tests.rs` — Restart safety, corruption detection
- `crates/qbind-ledger/tests/slashing_ledger_tests.rs` — Core ledger tests

**Whitepaper Reference:** Section 16.8 (Slashing State Persistence)

---

### 2.16 Documentation Hardening

| Field | Value |
|-------|-------|
| **Gap ID** | Items 2, 3, 5, 6, 7: Undocumented implementation details |
| **Status** | ✅ Mitigated (M20) |
| **Milestones** | M20 |
| **Description** | Whitepaper updates for vote history retention, CRC-32 checksums, key rotation semantics, mempool ordering, timeout backoff parameters, and reporter incentives (future work). |

**Key Code Files:**
- (Documentation-only milestone)

**Whitepaper Reference:** Section 8.4.1, 10.5.1, 9.8, 7.1.1, 17.3.1, 12.2.3

---

### 2.17 Non-ML-DSA-44 Suite Bypass

| Field | Value |
|-------|-------|
| **Gap ID** | Risk: Suite bypass for slashing verification |
| **Status** | ✅ Mitigated (M0) |
| **Milestones** | M0 |
| **Description** | Runtime invariant validation rejects validator sets containing non-ML-DSA-44 suites for TestNet/MainNet. |

**Key Code Files:**
- `crates/qbind-node/src/node_config.rs` — `validate_testnet_invariants()`, `validate_mainnet_validator_suites()`, `ML_DSA_44_SUITE_ID`

**Key Test Files:**
- `crates/qbind-node/src/node_config.rs` — Inline tests for suite validation

**Whitepaper Reference:** Section 18.4 (Fail-Closed Conditions)

---

## 3. Index by Milestone

This section provides a numerical index of all M-series milestones.

### M0: Non-ML-DSA-44 Suite Bypass Prevention

**What it implemented:** Runtime invariant validation that rejects validator sets containing non-ML-DSA-44 validators for TestNet and MainNet deployments.

**Risks addressed:** Suite bypass allowing validators to evade slashing signature verification.

**Key anchors:**
- Code: `crates/qbind-node/src/node_config.rs` (`validate_testnet_invariants()`, `validate_mainnet_validator_suites()`)
- Tests: Inline unit tests in `node_config.rs`

---

### M1: Slashing Ledger Persistence

**What it implemented:** Persistent RocksDB-backed slashing ledger with atomic updates via WriteBatch (M1.2) and failure injection testing (M1.3).

**Risks addressed:** Slashing state loss on restart; partial state corruption.

**Key anchors:**
- Code: `crates/qbind-ledger/src/slashing_ledger.rs` (`RocksDbSlashingLedger`, `apply_slashing_update_atomic()`)
- Tests: `crates/qbind-ledger/tests/slashing_ledger_tests.rs`, failure injection tests

---

### M2.1–M2.4: Minimum Stake Enforcement

**What it implemented:** Minimum stake filtering at epoch boundary via `StakeFilteringEpochStateProvider` and production-ready constructors for TestNet/MainNet.

**Risks addressed:** Validators with insufficient stake remaining in active set.

**Key anchors:**
- Code: `crates/qbind-consensus/src/validator_set.rs`, `crates/qbind-node/src/hotstuff_node_sim.rs`
- Tests: `m2_2_stake_filter_epoch_transition_tests.rs`, `m2_3_stake_filtering_node_integration_tests.rs`, `m2_4_production_stake_filtering_tests.rs`

---

### M4: MainNet Slashing Mode Enforcement

**What it implemented:** Configuration validation that rejects `Off` and `RecordOnly` slashing modes for MainNet.

**Risks addressed:** Operators disabling slashing penalties, removing economic deterrent.

**Key anchors:**
- Code: `crates/qbind-node/src/node_config.rs` (`validate_for_mainnet()`)
- Tests: `m4_slashing_mode_enforcement_tests.rs`

---

### M5: Timeout/View-Change Mechanism

**What it implemented:** Production-ready timeout detection via `TimeoutPacemaker`, timeout certificate formation via `TimeoutAccumulator`, and view advancement with locked-height safety.

**Risks addressed:** Liveness failure under network partition; consensus stall.

**Key anchors:**
- Code: `crates/qbind-consensus/src/basic_hotstuff_engine.rs`, `pacemaker.rs`, `timeout.rs`
- Tests: `m5_timeout_view_change_tests.rs` (28 tests)

---

### M6: DoS Cookie Protection

**What it implemented:** 2-step handshake with stateless HMAC-SHA3-256 cookie validation before KEM decapsulation.

**Risks addressed:** Connection exhaustion attacks.

**Key anchors:**
- Code: `crates/qbind-net/src/cookie.rs`, `crates/qbind-net/src/handshake.rs`
- Tests: `m6_dos_cookie_protection_tests.rs` (10 tests)

---

### M7: NodeId Extraction from KEMTLS

**What it implemented:** Domain-separated SHA3-256 derivation of NodeId from KEMTLS server KEM public key for outbound connections.

**Risks addressed:** Peer identity not cryptographically verified.

**Key anchors:**
- Code: `crates/qbind-hash/src/net.rs`, `crates/qbind-node/src/p2p_tcp.rs`
- Tests: `m7_nodeid_extraction_tests.rs` (14 tests)

---

### M8: Mutual KEMTLS Authentication

**What it implemented:** Client certificate exchange in ClientInit v2; server-side verification and NodeId derivation from client cert for inbound connections.

**Risks addressed:** Inbound connection identity spoofing.

**Key anchors:**
- Code: `crates/qbind-net/src/handshake.rs`, `crates/qbind-node/src/node_config.rs`
- Tests: `m8_mutual_auth_tests.rs` (9 tests), `m8_mutual_auth_config_tests.rs` (17 tests)

---

### M9: O1/O2 Slashing Enforcement

**What it implemented:** Atomic penalty application for O1 (Double Sign) and O2 (Invalid Block) offenses via `AtomicSlashingBackend`.

**Risks addressed:** No economic deterrent for critical Byzantine behavior.

**Key anchors:**
- Code: `crates/qbind-consensus/src/slashing/mod.rs`, `crates/qbind-node/src/ledger_slashing_backend.rs`
- Tests: `m9_slashing_penalty_tests.rs`

---

### M10: Remote Signer Protocol

**What it implemented:** Domain-separated remote signing protocol with replay protection (monotonic request_id), fail-closed behavior, and signer isolation metrics.

**Risks addressed:** Key exposure on validator host.

**Key anchors:**
- Code: `crates/qbind-node/src/remote_signer.rs`, `crates/qbind-node/src/metrics.rs`
- Tests: `m10_signer_isolation_tests.rs`

---

### M10.1: Signer Policy Enforcement

**What it implemented:** `LoopbackTesting` mode forbidden on TestNet/MainNet; KEMTLS mutual auth required for remote signer connections.

**Risks addressed:** Plaintext key usage in production environments.

**Key anchors:**
- Code: `crates/qbind-node/src/node_config.rs` (`validate_signer_mode_for_mainnet()`, `validate_signer_mode_for_testnet()`)
- Tests: `m10_1_signer_policy_tests.rs` (20 tests)

---

### M11: O3–O5 Slashing Enforcement

**What it implemented:** Penalty application for O3 (Invalid Vote), O4 (Censorship), O5 (Availability) offenses with deterministic verification.

**Risks addressed:** No deterrent for non-critical but harmful Byzantine behavior.

**Key anchors:**
- Code: `crates/qbind-consensus/src/slashing/mod.rs`
- Tests: `m11_slashing_penalty_o3_o5_tests.rs` (21 tests)

---

### M12: Validator Set Transition Specification

**What it implemented:** Formal specification in whitepaper for epoch-based validator transitions, eligibility predicates, and persistence ordering.

**Risks addressed:** Specification ambiguity for validator set changes.

**Key anchors:**
- Code: Specification-only (existing code mapped)
- Whitepaper: Section 18

---

### M13: Canonical Economic State

**What it implemented:** Unified canonical source for economic state in `ValidatorRecord`; documented `ValidatorSlashingState` as non-authoritative mirror.

**Risks addressed:** Economic state divergence between storage layers.

**Key anchors:**
- Code: `crates/qbind-types/src/state_validator.rs`, `crates/qbind-ledger/src/slashing_ledger.rs`
- Tests: `m13_economic_state_unification_tests.rs` (12 tests)

---

### M14: Governance Slashing Parameters

**What it implemented:** `SlashingPenaltySchedule` struct in `ParamRegistry` with O1–O5 parameters and epoch-boundary activation; deterministic config construction via `from_governance_schedule()`.

**Risks addressed:** Static penalty parameters requiring hard forks to change.

**Key anchors:**
- Code: `crates/qbind-types/src/state_governance.rs`, `crates/qbind-consensus/src/slashing/mod.rs`
- Tests: `m14_governance_slashing_params_tests.rs` (15 tests)

---

### M15: Evidence Ingestion Hardening

**What it implemented:** `HardenedEvidenceIngestionEngine` with 8-step verification ordering (cheap checks first), per-block cap, size limits, age bounds, and deduplication.

**Risks addressed:** Evidence submission abuse, DoS via oversized payloads, spam from non-validators.

**Key anchors:**
- Code: `crates/qbind-consensus/src/slashing/mod.rs`
- Tests: `m15_evidence_ingestion_hardening_tests.rs` (25 tests)

---

### M16: Epoch Transition Atomicity

**What it implemented:** Atomic epoch transition via `EpochTransitionBatch` and RocksDB WriteBatch; `EpochTransitionMarker` for crash detection; fail-closed startup verification.

**Risks addressed:** Epoch transition crash window leaving inconsistent state.

**Key anchors:**
- Code: `crates/qbind-node/src/storage.rs`
- Tests: `m16_epoch_transition_hardening_tests.rs` (14 tests with failure injection)

---

### M17: Slashing Economics Specification

**What it implemented:** Formal penalty schedule table in whitepaper Section 12.2.1 with O1–O5 offense types, evidence requirements, verification rules, slash percentages, and jail epochs.

**Risks addressed:** Specification gap for slashing economics.

**Key anchors:**
- Whitepaper: Section 12.2.1, 12.2.2

---

### M18: Gas Accounting Formalization

**What it implemented:** Formal gas transition function in whitepaper Section 19; code hardened with checked arithmetic (no saturating operations); `VmV0Error::ArithmeticOverflow` for overflow handling.

**Risks addressed:** Gas accounting specification gap; potential overflow in fee calculations.

**Key anchors:**
- Code: `crates/qbind-ledger/src/execution.rs`, `crates/qbind-runtime/src/gas_model.rs`
- Tests: `m18_gas_accounting_tests.rs` (19 tests)
- Whitepaper: Section 19

---

### M19: Slashing Persistence Canonicalization

**What it implemented:** `verify_slashing_consistency_on_startup()` for fail-closed corruption detection; explicit consensus-critical vs non-critical state classification; `SlashingStateCorrupt` error variant.

**Risks addressed:** Slashing state restart safety; eligibility divergence from corrupted state.

**Key anchors:**
- Code: `crates/qbind-ledger/src/slashing_ledger.rs`
- Tests: `m19_slashing_persistence_canonicalization_tests.rs`
- Whitepaper: Section 16.8

---

### M20: Documentation Hardening

**What it implemented:** Whitepaper updates for previously undocumented behaviors: vote history retention (8.4.1), CRC-32 checksums (10.5.1), key rotation semantics (9.8), mempool ordering (7.1.1), timeout backoff parameters (17.3.1), reporter incentives as future work (12.2.3).

**Risks addressed:** Specification gaps for implementation details.

**Key anchors:**
- Whitepaper: Sections 7.1.1, 8.4.1, 9.8, 10.5.1, 12.2.3, 17.3.1

---

## 4. Open Items / Non-Goals

This section lists items that are deliberately not addressed in the pre-testnet M-series.

### C3: Reporter Rewards (Future Work)

| Field | Value |
|-------|-------|
| **Status** | ⚠️ Open (Intentional) |
| **Description** | No economic incentive for evidence reporting. `reporter_reward_bps` parameter exists but is not wired to reward distribution. |
| **Rationale** | Reporter incentives are tokenomics design, not protocol safety. Whitepaper Section 12.2.3 explicitly documents this as future work. |
| **M15 Baseline** | Evidence ingestion is hardened and abuse-resistant even without rewards. Any future reward implementation must build on the M15 hardened pipeline. |
| **Not a Safety Gap** | Slashing works correctly (penalties applied); only the incentive to report is missing. Validators have intrinsic motivation to report Byzantine peers to maintain network health. |

**Reference:** `docs/whitepaper/contradiction.md` (C3), Whitepaper Section 12.2.3

---

### Remaining Future Work

The following items are documented as post-testnet work:

1. **Full Architectural Unification (M13 follow-up):** Single-write path for slashing penalties to both `ValidatorRecord` and `ValidatorSlashingState`.

2. **Validator vs Non-Validator Configuration (Impl Gap 3.5):** Stricter rules for non-validator nodes. Target: Pre-MainNet.

3. **Monetary State Error Handling (Impl Gap 3.6):** Stricter production error handling for monetary operations. Target: Pre-MainNet.

---

## 5. Pre-TestNet Security Posture

The QBIND protocol has undergone systematic risk mitigation through the M-series track. As of this writing:

**All pre-testnet critical issues have been addressed.** The following documents form the authoritative triad for auditors:

1. **This Document (`QBIND_M_SERIES_COVERAGE.md`):** Comprehensive index mapping risks to mitigations, code, and tests.

2. **Protocol Report (`QBIND_PROTOCOL_REPORT.md`):** Detailed tracking of specification gaps, implementation gaps, and security risk register with residual risk assessments.

3. **Whitepaper (`QBIND_WHITEPAPER.md`):** Formal protocol specification including consensus, cryptography, state transitions, validator economics, and gas accounting.

The **contradiction tracking document** (`contradiction.md`) maintains an up-to-date list of any discrepancies between specification and implementation.

**Security Risk Register Summary:**
- All risks in the Security Risk Register (Protocol Report Section 4) are marked **Mitigated** with residual risk **Low**.
- The only medium-risk open item (C3: Reporter Rewards) is explicitly classified as future economics work, not a protocol safety issue.

Auditors should cross-reference entries in this document with the Protocol Report and Whitepaper to verify mitigation claims. Each M-series milestone includes test files that can be executed via `cargo test` to demonstrate the mitigation in action.

---

*This document should be updated whenever new M-series milestones are added or existing mitigations are modified.*