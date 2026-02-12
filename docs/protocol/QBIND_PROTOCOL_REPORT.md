# QBIND Protocol Engineering Report

**Version**: 1.0  
**Date**: 2026-02-11  
**Status**: Active Tracking Document

This report tracks protocol gaps, security assumptions, incomplete components, and roadmap decisions for the QBIND protocol. It must be updated every time we modify the protocol or whitepaper.

---

# 1. Executive Protocol Status

## Current Whitepaper Version

- **Version**: Draft v3 (Full Technical Baseline)
- **Location**: `docs/whitepaper/QBIND_WHITEPAPER.md`
- **Status**: Technical Specification (No Tokenomics)

## Current Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| Core Types (`qbind-types`) | ✅ Implemented | AccountId, ValidatorState, SuiteRegistry, governance types |
| Wire Encoding (`qbind-wire`) | ✅ Implemented | Consensus messages, transactions, network handshake |
| Cryptography (`qbind-crypto`) | ✅ Implemented | ML-KEM-768, ML-DSA-44, ChaCha20-Poly1305, PBKDF2 |
| Hashing (`qbind-hash`) | ✅ Implemented | Domain-separated SHA3-256 |
| Serialization (`qbind-serde`) | ✅ Implemented | State serialization codec |
| Ledger (`qbind-ledger`) | ✅ Implemented | Account state, execution engine, gas accounting |
| System Programs (`qbind-system`) | ✅ Implemented | Keyset, Validator, Governance programs |
| Runtime (`qbind-runtime`) | ✅ Implemented | Transaction/block execution, EVM integration |
| Genesis (`qbind-genesis`) | ✅ Implemented | Suite registry, param registry, safety council |
| Consensus (`qbind-consensus`) | ⚠️ Partial | HotStuff BFT core implemented; timeouts/view-change TODO |
| Node (`qbind-node`) | ⚠️ Partial | P2P networking, mempool, storage; LocalMesh mode stubbed |
| Networking (`qbind-net`) | ⚠️ Partial | KEMTLS handshake implemented; DoS cookie not enforced |
| Remote Signer (`qbind-remote-signer`) | ⚠️ Partial | Basic structure; full KEMTLS server not fully wired |
| Governance (`qbind-gov`) | ✅ Implemented | Envelope parsing, multi-sig verification |

## Summary of Open Critical Issues

1. **Timeout/view-change mechanics not implemented** - Affects liveness under network partition
2. **Slashing penalties infrastructure present but not enforced** - No economic deterrent for misbehavior
3. **DoS cookie protection defined but not enforced** - Connection exhaustion vulnerability
4. **LocalMesh node operation is a stub** - Limited testing capability

---

# 2. Specification Gaps

This section lists items where the whitepaper lacks formal precision.

## 2.1 State Transition Function

| Field | Value |
|-------|-------|
| **Description** | The whitepaper describes transaction execution flow (Section 10.3) but lacks a formal state transition function δ(S, tx) → S' with explicit pre/post conditions |
| **Whitepaper Reference** | Section 10: Transaction and State Model |
| **Code Reference** | `qbind-ledger/src/`, `qbind-runtime/src/lib.rs` |
| **Status** | Mitigated (spec added) |
| **Risk Level** | Medium |
| **Justification** | All consensus safety, validator transitions, slashing, and upgrade semantics depend on a formally defined state transition function. |
| **Action Required** | Add formal δ(S, B) → S′ definition to whitepaper; include transaction validity, gas deduction, slashing application, epoch transitions, and persistence semantics. |
| **Required Milestone** | Pre-TestNet |
| **Note** | Formal δ(S, Input) → S′ definition added in Whitepaper Section 16. Implementation unchanged; future changes must preserve defined semantics. |

## 2.2 Validator Set Transition Formalism

| Field | Value |
|-------|-------|
| **Description** | Validator set changes (join/leave/rotation) are not formally specified in the whitepaper |
| **Whitepaper Reference** | Section 8: Consensus Protocol Specification (implicit reference only) |
| **Code Reference** | `qbind-types/src/` (ValidatorState), `qbind-consensus/src/` |
| **Risk Level** | High |
| **Action Required** | Add formal specification for epoch-based validator transitions; define entry/exit conditions |

## 2.3 Gas Accounting Formal Definition

| Field | Value |
|-------|-------|
| **Description** | Gas model is described at high level (Section 10.4) but lacks formal metering rules per operation type |
| **Whitepaper Reference** | Section 10.4: Gas Accounting |
| **Code Reference** | `qbind-ledger/src/`, `qbind-runtime/src/` |
| **Risk Level** | Medium |
| **Action Required** | Document gas cost table per instruction/operation; formalize fee calculation |

## 2.4 Timeout / View-Change Liveness Formalization

| Field | Value |
|-------|-------|
| **Description** | Whitepaper acknowledges timeout/view-change is partially implemented (Section 8.10) but lacks formal liveness proof under partial synchrony |
| **Whitepaper Reference** | Section 8.9: Liveness Assumptions, Section 8.10: Known Consensus Gaps |
| **Code Reference** | `qbind-consensus/src/driver.rs` (TODO at line 665) |
| **Risk Level** | High |
| **Action Required** | Implement timeout logic; formalize view-change protocol; provide liveness argument |

## 2.5 Slashing Economics Specification

| Field | Value |
|-------|-------|
| **Description** | Slashing infrastructure exists but penalty amounts, conditions, and economic impact are not specified |
| **Whitepaper Reference** | Section 8.10: Known Consensus Gaps, Section 12.2: Byzantine Validator Behavior |
| **Code Reference** | `qbind-consensus/src/slashing/mod.rs` |
| **Risk Level** | High |
| **Action Required** | Define slashing conditions (double-vote, equivocation); specify penalty amounts; document jail/unjail mechanics |

## 2.6 Epoch Transition Formalization

| Field | Value |
|-------|-------|
| **Description** | Epoch boundary semantics insufficiently formalized; activation rules need explicit state mutation description |
| **Whitepaper Reference** | Section 8, Section 11 |
| **Code Reference** | `qbind-consensus/`, `qbind-ledger/` |
| **Status** | Partially Mitigated |
| **Risk Level** | High |
| **Action Required** | Define epoch transition function and validator set update semantics |
| **Note** | Epoch transition formally defined in Whitepaper Section 16. Implementation hardening (crash-window elimination, persistence ordering guarantees) pending before TestNet. |

---

# 3. Implementation Gaps

This section lists items marked TODO or partially implemented in the codebase.

## 3.1 Consensus Driver Vote Processing

| Field | Value |
|-------|-------|
| **File Path** | `crates/qbind-consensus/src/driver.rs:619` |
| **Description** | Vote processing delegation to underlying engine not implemented |
| **Security Impact** | Consensus votes may not be properly accumulated |
| **Required Milestone** | Pre-TestNet |

## 3.2 Consensus Driver Proposal Processing

| Field | Value |
|-------|-------|
| **File Path** | `crates/qbind-consensus/src/driver.rs:649` |
| **Description** | Proposal processing delegation to underlying engine not implemented |
| **Security Impact** | Block proposals may not be properly validated |
| **Required Milestone** | Pre-TestNet |

## 3.3 Consensus Driver Timer-Based Logic

| Field | Value |
|-------|-------|
| **File Path** | `crates/qbind-consensus/src/driver.rs:665` |
| **Description** | Timer-based logic for view changes and timeouts not implemented |
| **Security Impact** | Liveness failure under network partition; consensus stall |
| **Required Milestone** | Pre-TestNet |

## 3.4 P2P NodeId Extraction from KEMTLS Cert

| Field | Value |
|-------|-------|
| **File Path** | `crates/qbind-node/src/p2p_tcp.rs:406,440` |
| **Description** | NodeId is set to zero instead of being extracted from KEMTLS certificate |
| **Security Impact** | Peer identity not cryptographically verified; potential impersonation |
| **Required Milestone** | Pre-TestNet |

## 3.5 Validator vs Non-Validator Stricter Rules

| Field | Value |
|-------|-------|
| **File Path** | `crates/qbind-node/src/node_config.rs:5128` |
| **Description** | No distinction between validator and non-validator node configuration |
| **Security Impact** | Non-validator nodes may have unnecessarily permissive settings |
| **Required Milestone** | Pre-MainNet |

## 3.6 Monetary State Error Handling

| Field | Value |
|-------|-------|
| **File Path** | `crates/qbind-ledger/src/monetary_state.rs:1367` |
| **Description** | Error handling marked for stricter production handling (T201) |
| **Security Impact** | Potential silent failures in monetary operations |
| **Required Milestone** | Pre-MainNet |

## 3.7 LocalMesh Node Operation

| Field | Value |
|-------|-------|
| **File Path** | `crates/qbind-node/src/main.rs:111-123` |
| **Description** | LocalMesh mode is stubbed (T175) |
| **Security Impact** | Limited testing capability for local multi-node setup |
| **Required Milestone** | Development tooling |

## 3.8 Remote Signer KEMTLS

| Field | Value |
|-------|-------|
| **File Path** | `crates/qbind-remote-signer/src/main.rs:587` |
| **Description** | Full KEMTLS server requires proper key configuration |
| **Security Impact** | Remote signer channel may not be fully secured |
| **Required Milestone** | Pre-MainNet |

## 3.9 DoS Cookie Enforcement

| Field | Value |
|-------|-------|
| **File Path** | `crates/qbind-net/src/handshake.rs` |
| **Description** | Cookie field exists in ClientInit but enforcement not implemented |
| **Security Impact** | Connection exhaustion attacks possible |
| **Required Milestone** | Pre-TestNet |

## 3.10 Slashing Penalty Application

| Field | Value |
|-------|-------|
| **File Path** | `crates/qbind-consensus/src/slashing/mod.rs` |
| **Description** | T228 implements infrastructure skeleton; actual stake burning/jailing deferred to T229+ |
| **Security Impact** | No economic deterrent for Byzantine behavior |
| **Required Milestone** | Pre-MainNet |

---

# 4. Security Risk Register

| Risk | Layer | Mitigation | Residual Risk | Priority |
|------|-------|------------|---------------|----------|
| Liveness failure under partition | Consensus | Implement timeout/view-change (TODO) | High until implemented | Critical |
| No slashing enforcement | Consensus | Complete T229+ implementation | High until enforced | Critical |
| Non-ML-DSA-44 suite bypass (M0) | Slashing | `validate_testnet_invariants()` / `validate_mainnet_validator_suites()` reject non-ML-DSA-44 validators | Low (mitigated for TestNet/MainNet) | Mitigated |
| Connection exhaustion (DoS) | Networking | Implement DoS cookie enforcement | Medium | High |
| Peer identity spoofing | Networking | Extract NodeId from KEMTLS cert | Medium | High |
| Key exposure on validator host | Crypto | Enable HSM/PKCS#11 integration | Medium (optional HSM) | High |
| Nonce overflow | Networking | Session termination at u64::MAX | Low (implemented) | Low |
| Double-vote attack | Consensus | Double-vote rejection implemented | Low (implemented) | Low |
| Suite downgrade | Crypto | Downgrade rejection implemented | Low (implemented) | Low |
| Storage corruption | Storage | Corruption detection implemented | Low (implemented) | Low |
| Replay attack (session) | Networking | Monotonic nonce implemented | Low (implemented) | Low |
| Replay attack (transaction) | Execution | Nonce-based protection implemented | Low (implemented) | Low |

---

# 5. Upgrade Discipline Log

This section tracks decisions about protocol upgrades and governance.

## Suite Versioning

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-02-11 | Initial suite: ML-DSA-44 (suite_id 100), ML-KEM-768 | NIST PQC standardization alignment |

## Governance Changes

| Date | Change | Impact |
|------|--------|--------|
| (None recorded) | | |

## Epoch Activation Rules

| Date | Rule | Description |
|------|------|-------------|
| 2026-02-11 | Suite transitions at epoch boundary only | Prevents mid-epoch cryptographic ambiguity |
| 2026-02-11 | Downgrade rejection as fatal | Prevents rollback attacks |

## Backward Compatibility

| Date | Decision | Scope |
|------|----------|-------|
| 2026-02-11 | Schema version check at startup | Prevents forward-incompatible DB opens |
| 2026-02-11 | State persistence compatibility required for suite upgrades | Maintains chain continuity |

---

# 6. Performance Constraints Log

This section tracks known performance bottlenecks.

## Crypto Verification

| Constraint | Current Status | Impact | Mitigation Path |
|------------|----------------|--------|-----------------|
| ML-DSA-44 signature verification cost | Single-threaded per signature | Limits throughput | Parallel verification worker pool implemented; batch verification pending (future crate support) |
| ML-KEM-768 encapsulation/decapsulation | Per-connection overhead | Handshake latency | Acceptable for current scale |

## RocksDB Write Amplification

| Constraint | Current Status | Impact | Mitigation Path |
|------------|----------------|--------|-----------------|
| State write amplification | Standard RocksDB config | Storage growth | Investigate compaction tuning; state pruning roadmap item |
| Epoch transition durability | Write-before-update pattern | Slight latency | Acceptable for atomicity guarantees |

## Network Latency

| Constraint | Current Status | Impact | Mitigation Path |
|------------|----------------|--------|-----------------|
| Quorum formation latency | Network-bound | Finality delay | Optimize message propagation; priority-based channels implemented |
| Proposal dissemination | Broadcast to all validators | Bandwidth | Acceptable for current validator set size |

## Execution Cost

| Constraint | Current Status | Impact | Mitigation Path |
|------------|----------------|--------|-----------------|
| EVM execution overhead | Revm integration | Variable per contract | Gas metering enforced |
| System program execution | Native execution | Minimal overhead | Acceptable |

---

# 7. Long-Term Architecture Direction

*This section is intentionally a placeholder. Primary architectural identity will be defined in future iterations.*

## Pending Decisions

- [ ] Primary identity: High-security chain vs. high-throughput chain
- [ ] Sharding/parallelization strategy
- [ ] Cross-chain interoperability approach
- [ ] Light client protocol design
- [ ] Formal verification scope

---

# Appendix: Update Rules

**This report MUST be updated when any of the following occur:**

1. A new whitepaper section is added
2. Consensus logic is changed
3. A cryptographic feature is added
4. A TODO is closed
5. Networking changes are made
6. A roadmap decision is finalized

**Update procedure:**

1. Identify affected section(s)
2. Update relevant entries
3. Add date stamp to changes
4. If contradictions with whitepaper are found, append to `docs/whitepaper/contradiction.md`
5. Commit with reference to change reason

---

*Document generated from code inspection of QBIND repository. Cross-referenced with `docs/whitepaper/QBIND_WHITEPAPER.md` and `ARCHITECTURE.md`. No features invented beyond what exists in code.*