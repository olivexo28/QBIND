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
| Consensus (`qbind-consensus`) | ✅ Implemented | HotStuff BFT core with timeout/view-change (M5) |
| Node (`qbind-node`) | ⚠️ Partial | P2P networking, mempool, storage; LocalMesh mode stubbed |
| Networking (`qbind-net`) | ✅ Implemented | KEMTLS handshake with DoS cookie protection (M6) |
| Remote Signer (`qbind-remote-signer`) | ✅ Implemented | M10.1: KEMTLS mutual auth enforced + signer policy enforcement for TestNet/MainNet |
| Governance (`qbind-gov`) | ✅ Implemented | Envelope parsing, multi-sig verification |

## Summary of Open Critical Issues

1. **Slashing penalties infrastructure present but not enforced** - No economic deterrent for misbehavior
2. **LocalMesh node operation is a stub** - Limited testing capability

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
| **Code Reference** | `qbind-consensus/src/basic_hotstuff_engine.rs`, `qbind-consensus/src/pacemaker.rs`, `qbind-consensus/src/timeout.rs` |
| **Status** | ✅ Mitigated (M5) |
| **Risk Level** | Low (mitigated) |
| **Action Required** | ~~Implement timeout logic; formalize view-change protocol; provide liveness argument~~ |
| **Note** | **M5**: Production-ready timeout and view-change mechanism implemented consistent with Section 17 of the QBIND whitepaper. Implementation includes: (1) `TimeoutPacemaker` with exponential backoff for timeout detection, (2) `TimeoutAccumulator` for collecting timeout messages and forming TimeoutCertificates (TC), (3) `BasicHotStuffEngine.on_timeout_msg()` and `on_timeout_certificate()` for TC processing, (4) View monotonicity enforcement via `try_advance_to_view()`, (5) Locked-height safety checks via `is_safe_to_vote_at_height()`, (6) Fail-closed behavior on inconsistent state. Comprehensive tests in `crates/qbind-consensus/tests/m5_timeout_view_change_tests.rs` (28 tests) covering: leader crash recovery, no-proposal timeout, proposal-without-QC timeout, safety preservation across view changes, determinism, partition simulation, double-vote protection, and locked-height safety. |

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
| **Status** | ✅ Mitigated (M5) |
| **Note** | Timeout/view-change mechanism implemented in `BasicHotStuffEngine`, `TimeoutPacemaker`, and `NodeHotstuffHarness`. The driver.rs TODO remains for generic interface but production code uses the engine-level implementation. See M5 tests in `crates/qbind-consensus/tests/m5_timeout_view_change_tests.rs`. |

## 3.4 P2P NodeId Extraction from KEMTLS Cert

| Field | Value |
|-------|-------|
| **File Path** | `crates/qbind-node/src/p2p_tcp.rs:406,440` |
| **Description** | NodeId is set to zero instead of being extracted from KEMTLS certificate |
| **Security Impact** | Peer identity not cryptographically verified; potential impersonation |
| **Required Milestone** | Pre-TestNet |
| **Status** | ✅ Fully Mitigated (M7 + M8) |
| **Note** | **M7**: NodeId derivation implemented using domain-separated SHA3-256. **Outbound connections** (client side): NodeId derived from peer server's KEM public key via `node_id = sha3_256("QBIND:nodeid:v1" || peer_kem_pk)`. This provides cryptographic binding between NodeId and KEMTLS identity. Tests in `crates/qbind-node/tests/m7_nodeid_extraction_tests.rs` (13 tests) verify: deterministic derivation, different certs/pubkeys produce different NodeIds, NodeId no longer defaults to zero, domain tag correctness. **M8**: Mutual KEMTLS authentication added for **inbound connections**. Protocol version 2 (0x02) introduces client certificate exchange in `ClientInit`. Server verifies client cert signature, derives `client_node_id = sha3_256("QBIND:nodeid:v1" || client_cert_bytes)`, and returns it in `HandshakeResult.client_node_id`. Implementation: `qbind-net/src/handshake.rs:779-857` (verify_client_cert_if_required, parse_and_verify_client_cert). Cookie validation (M6) occurs BEFORE client cert parsing to preserve DoS protection. Transcript hash includes both server and client identity. Environment gating: `MutualAuthMode::Required` mandatory for MainNet/TestNet (`qbind-node/src/node_config.rs`). Tests in `crates/qbind-net/tests/m8_mutual_auth_tests.rs` (9 tests) and `crates/qbind-node/tests/m8_mutual_auth_config_tests.rs` (17 tests). |

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
| **Status** | ✅ Implemented (M10.1) |
| **Note** | **M10.1**: Production-ready remote signer security with KEMTLS mutual auth enforcement. Building on M10's protocol foundation: (1) Signer policy enforcement: `LoopbackTesting` (plaintext keys) **FORBIDDEN** on TestNet/MainNet via `validate_signer_mode_for_{mainnet,testnet}()`, (2) KEMTLS mutual auth configuration: `remote_signer_cert_path`, `remote_signer_client_cert_path`, `remote_signer_client_key_path` fields in NodeConfig, (3) MainNet invariant validation requires all cert paths when `SignerMode::RemoteSigner` is selected, (4) Reuses M8 mutual auth patterns for KEMTLS transport (`MutualAuthMode::Required` for TestNet/MainNet). DevNet allows `LoopbackTesting` for development convenience. Implementation in `crates/qbind-node/src/node_config.rs`. Tests in `crates/qbind-node/tests/m10_1_signer_policy_tests.rs` (20 tests) covering: policy validation functions, LoopbackTesting rejection, cert path requirements, error message quality. |

## 3.9 DoS Cookie Enforcement

| Field | Value |
|-------|-------|
| **File Path** | `crates/qbind-net/src/handshake.rs`, `crates/qbind-net/src/cookie.rs` |
| **Description** | Cookie field exists in ClientInit but enforcement not implemented |
| **Security Impact** | Connection exhaustion attacks possible |
| **Required Milestone** | Pre-TestNet |
| **Status** | ✅ Fully Mitigated (M6) |
| **Note** | **M6**: DoS cookie protection implemented with 2-step handshake. `ServerHandshake.handle_client_init_with_cookie()` enforces: (1) ClientInit without valid cookie → returns `ServerCookie` challenge (no KEM decapsulation), (2) ClientInit with valid cookie → proceeds with KEMTLS accept. Cookie design: stateless HMAC-SHA3-256 MAC using domain tag "QBIND:cookie:v1", bound to client IP + ClientInit fields + timestamp bucket. Features: 30-second expiry buckets with clock skew tolerance, constant-size response, bounded length checks, fail-closed behavior. Implementation in `crates/qbind-net/src/cookie.rs` (CookieConfig) and `crates/qbind-net/src/handshake.rs` (ServerHandshakeResponse). Comprehensive tests in `crates/qbind-net/tests/m6_dos_cookie_protection_tests.rs` (10 tests) covering: no-cookie init, invalid cookie, valid cookie, expired cookie, random cookies never trigger decapsulation, IP binding, client_random binding, oversized cookie rejection, clock skew tolerance, and backward compatibility. |

## 3.10 Slashing Penalty Application

| Field | Value |
|-------|-------|
| **File Path** | `crates/qbind-consensus/src/slashing/mod.rs`, `crates/qbind-node/src/ledger_slashing_backend.rs` |
| **Description** | T228 implements infrastructure skeleton; T229+ adds penalty engine; M9 adds atomic O1/O2 enforcement |
| **Security Impact** | Economic deterrent now enforced for O1 (double-sign) and O2 (invalid proposer signature) |
| **Required Milestone** | Pre-MainNet |
| **Status** | ✅ Mitigated (M9: O1/O2 enforced) |
| **Note** | **M9**: O1/O2 economic penalties fully enforced with persistent atomic ledger integration. Implementation adds: (1) `AtomicSlashingBackend` trait for atomic penalty application, (2) `AtomicPenaltyRequest`/`AtomicPenaltyResult` types, (3) `apply_penalty_atomic()` commits stake reduction + jail + evidence marker + record in single RocksDB WriteBatch, (4) `build_validator_set_with_stake_and_jail_filter()` excludes jailed validators from active set at epoch boundary. Fail-closed behavior: if atomic commit fails, no partial state applied. Mode enforcement: `EnforceCritical` or `EnforceAll` required for penalty application; `RecordOnly` records evidence without penalties. O3–O5 penalties remain pending future implementation. Tests in `crates/qbind-node/tests/m9_slashing_penalty_tests.rs`. |

## 3.11 Minimum Stake Not Enforced at Epoch Boundary

| Field | Value |
|-------|-------|
| **Description** | ValidatorSet derivation does not exclude stake < min_validator_stake yet |
| **Security Impact** | Validators with insufficient stake may remain in the active set after epoch transition |
| **Required Milestone** | Pre-TestNet |
| **Status** | ✅ Fully Mitigated (M2.1 + M2.2 + M2.3 + M2.4) |
| **Note** | **M2.1**: `build_validator_set_with_stake_filter()` provides deterministic stake-based filtering for epoch boundary validator set derivation. **M2.2**: `StakeFilteringEpochStateProvider` wraps `EpochStateProvider` to integrate filtering into the canonical epoch transition path. **M2.3**: `with_stake_filtering_epoch_state_provider()` method in `NodeHotstuffHarness` wires stake filtering into the production epoch transition path. **M2.4**: `new_with_stake_filtering()` and `enable_stake_filtering_for_environment()` provide production-ready constructors for TestNet/MainNet. Validators with `stake < min_validator_stake` are excluded from the active set. Fail-closed behavior: if filtering excludes all validators, epoch transition fails with `StakeFilterEmptySetError`. Implementation in `crates/qbind-consensus/src/validator_set.rs` and `crates/qbind-node/src/hotstuff_node_sim.rs`. Tests in `crates/qbind-consensus/tests/validator_set_tests.rs`, `crates/qbind-consensus/tests/m2_2_stake_filter_epoch_transition_tests.rs`, `crates/qbind-node/tests/m2_3_stake_filtering_node_integration_tests.rs`, and `crates/qbind-node/tests/m2_4_production_stake_filtering_tests.rs`. |

## 3.12 MainNet Slashing Mode Enforcement (M4)

| Field | Value |
|-------|-------|
| **File Path** | `crates/qbind-node/src/node_config.rs` |
| **Description** | MainNet slashing mode enforcement to prevent running without penalties |
| **Security Impact** | Without enforcement, operators could disable penalties, removing economic deterrent for Byzantine behavior |
| **Required Milestone** | Pre-MainNet |
| **Status** | ✅ Fully Mitigated (M4) |
| **Note** | **M4**: `validate_for_mainnet()` in `SlashingConfig` now rejects `Off` and `RecordOnly` modes for MainNet. MainNet must use `EnforceCritical` or `EnforceAll`. TestNet prefers enforcement (default is `EnforceCritical`) but allows `RecordOnly` with a warning for testing. DevNet allows all modes for development flexibility. Implementation in `crates/qbind-node/src/node_config.rs`. Tests in `crates/qbind-node/tests/m4_slashing_mode_enforcement_tests.rs` and `crates/qbind-node/tests/t237_mainnet_launch_profile_tests.rs`. |

---

# 4. Security Risk Register

| Risk | Layer | Mitigation | Residual Risk | Priority |
|------|-------|------------|---------------|----------|
| Liveness failure under partition | Consensus | Timeout/view-change mechanism implemented (M5): `TimeoutPacemaker`, `TimeoutAccumulator`, `TimeoutCertificate`, fail-closed behavior | Low (mitigated M5) | Mitigated |
| No slashing enforcement | Consensus | M9: O1/O2 penalties enforced via `AtomicSlashingBackend.apply_penalty_atomic()`. Atomic ledger commit using RocksDB WriteBatch. Jail exclusion via `build_validator_set_with_stake_and_jail_filter()`. O3–O5 remain evidence-only (pending). | Low (O1/O2 enforced M9; O3–O5 pending) | Mitigated |
| Slashing mode bypass (M4) | Config | `validate_for_mainnet()` rejects `Off`/`RecordOnly` modes; MainNet requires `EnforceCritical` or `EnforceAll` | Low (mitigated M4) | Mitigated |
| No minimum stake requirement (M2) | Validator | `min_validator_stake` enforced at registration + epoch boundary via `StakeFilteringEpochStateProvider` + `build_validator_set_with_stake_filter()` + `with_stake_filtering_epoch_state_provider()` + `new_with_stake_filtering()`; fail-closed if all validators excluded | Low (fully mitigated M2.1+M2.2+M2.3+M2.4) | Mitigated |
| Non-ML-DSA-44 suite bypass (M0) | Slashing | `validate_testnet_invariants()` / `validate_mainnet_validator_suites()` reject non-ML-DSA-44 validators | Low (mitigated for TestNet/MainNet) | Mitigated |
| Slashing ledger partial state | Storage | Atomic WriteBatch in `apply_slashing_update_atomic()` + failure-injection test (M1.3) | Low (proven by test) | Mitigated |
| Connection exhaustion (DoS) | Networking | DoS cookie enforcement via `handle_client_init_with_cookie()`: 2-step handshake, stateless HMAC-SHA3-256 cookie, no KEM decaps until valid cookie (M6) | Low (mitigated M6) | Mitigated |
| Peer identity spoofing | Networking | NodeId extraction from KEMTLS via `derive_node_id_from_pubkey()` (M7) + mutual KEMTLS authentication (M8): outbound connections derive NodeId from server's KEM public key; inbound connections derive `client_node_id` from verified client certificate using `derive_node_id_from_cert()`. Cookie validation (M6) preserved before cert parsing. Environment gating: `MutualAuthMode::Required` for MainNet/TestNet. | Low (fully mitigated M7+M8) | Mitigated |
| Key exposure on validator host | Crypto | M10.1: Signer isolation via remote signer with domain separation (`QBIND:remote-signer:v1`), replay protection (monotonic `request_id`), fail-closed behavior, **KEMTLS mutual auth enforced for TestNet/MainNet**, `LoopbackTesting` (plaintext keys) **FORBIDDEN** on TestNet/MainNet. Optional HSM/PKCS#11 integration feature-gated. | Low (fully mitigated M10.1; policy enforcement + mutual auth) | Mitigated |
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