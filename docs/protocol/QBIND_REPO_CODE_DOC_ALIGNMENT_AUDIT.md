# QBIND Repo / Code ↔ Doc Alignment Audit

**Status:** Canonical
**Audience:** Internal — protocol engineering, ops, release management
**Purpose:** EXE-1. Code-grounded audit of the actual repository against the canonical doc stack. Identify confirmed alignments, partial alignments, gaps, and unresolved contradictions, and name the top execution blockers.

---

## 1. Purpose and Scope

This document is the EXE-1 deliverable defined by `docs/protocol/QBIND_DOCUMENTATION_CUTOFF_AND_EXECUTION_TRANSITION_AUDIT.md`. The docs-heavy phase is closed. Before continuing to EXE-2 (DevNet readiness against real repo state), QBIND must answer one question honestly:

> Where does the canonical doc stack actually agree with the repository today, and where does it not?

Scope is intentionally narrowed to execution-critical surfaces:

- **A.** Consensus and chain behavior (HotStuff, timeout/view-change, epoch transition, validator-set, slashing enforcement, restart/persistence/crash-safety).
- **B.** Networking and identity (KEMTLS, DoS cookie, mutual auth, NodeId derivation, peer identity, signer isolation).
- **C.** Ops-critical behavior (signal/metric emission where docs assume observability, backup/recovery surfaces, cutover/readiness assumptions).
- **D.** Economics-critical implementation (gas/fee plumbing, slashing economics enforcement, governance-wired economics state, unresolved numeric placeholders).
- **E.** Environment/config reality (DevNet/TestNet/MainNet distinctions actually present and enforceable in the repo).

Out of scope: cosmetic mismatches, exhaustive re-derivation of contradiction.md content already RESOLVED, broad theory exposition, new planning docs, marketing.

This is **not** a request to create a plan, a roadmap, or a new whitepaper. It is an audit. Where the doc stack is honest, this document records it. Where the doc stack overclaims or the code lags, this document records that too, with file/line evidence.

---

## 2. Canonical Sources Audited

The following docs (the canonical baseline reaffirmed by `docs/protocol/QBIND_DOCUMENTATION_CUTOFF_AND_EXECUTION_TRANSITION_AUDIT.md` §2) were treated as authoritative:

**Whitepaper / protocol foundation**
- `docs/whitepaper/QBIND_WHITEPAPER.md`
- `docs/whitepaper/contradiction.md`
- `docs/protocol/QBIND_PROTOCOL_REPORT.md`
- `docs/protocol/QBIND_M_SERIES_COVERAGE.md`

**Release track**
- `docs/release/QBIND_RELEASE_TRACK_SPEC.md`
- `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md`
- `docs/release/QBIND_MAINNET_AUTHORIZATION_MEMO_TEMPLATE.md`
- `docs/release/QBIND_MAINNET_READINESS_EVIDENCE_PACKET_TEMPLATE.md`

**DevNet / TestNet**
- `docs/devnet/QBIND_DEVNET_OPERATIONAL_GUIDE.md`
- `docs/testnet/QBIND_TESTNET_ALPHA_PLAN.md`
- `docs/testnet/QBIND_TESTNET_BETA_PLAN.md`
- `docs/testnet/QBIND_TESTNET_BETA_OPERATOR_CHECKLIST.md`
- `docs/testnet/QBIND_BETA_EVIDENCE_PACKET_TEMPLATE.md`

**Operations**
- `docs/ops/QBIND_INCIDENT_RESPONSE.md`
- `docs/ops/QBIND_MAINNET_CUTOVER_RUNBOOK.md`
- `docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md`
- `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md`
- `docs/ops/QBIND_OPERATOR_DRILL_CATALOG.md`

**Economics**
- `docs/economics/QBIND_ECONOMICS_DESIGN_DRAFT.md`
- `docs/economics/QBIND_TOKENOMICS_DECISION_FRAMEWORK.md`
- `docs/economics/QBIND_BETA_ECONOMICS_SCOPE.md`
- `docs/economics/QBIND_MAINNET_ECONOMICS_FINALIZATION.md`

**Index**
- `docs/README.md`

Audit anchors in code:

- `crates/qbind-consensus/` (HotStuff core, slashing engine, validator-set, pacemaker, key rotation, epoch transition).
- `crates/qbind-net/` (KEMTLS handshake, DoS cookie, mutual auth, framed I/O, KEM metrics).
- `crates/qbind-node/` (binary entry point, P2P node builder, metrics, storage, signer wiring, env-profile validation, harnesses, integration tests).
- `crates/qbind-ledger/` (account state, gas, monetary engine, slashing ledger, state snapshots).
- `crates/qbind-types/`, `crates/qbind-system/`, `crates/qbind-genesis/`, `crates/qbind-runtime/`, `crates/qbind-gov/`.
- `scripts/build-mainnet-release.sh`.

---

## 3. Audit Method

This is a **code-grounded** audit. The rules are:

1. **Existence of a doc is not implementation evidence.** A canonical doc that asserts behavior X is treated as a *claim*, not as proof. Confirmation requires an explicit code path, configuration knob, or test that exercises X.
2. **Existence of an integration test is treated as evidence at the level it exercises.** A `t1xx`/`mxx` test that drives the real path counts; a docstring that mentions a behavior does not.
3. **Tests-only support is recorded as partial.** When behavior is reachable via test harnesses (`NodeHotstuffHarness`, `LocalMesh`, fixed-cluster harnesses) but not from the production binary entry point, that is recorded as partial alignment, not full alignment.
4. **Stale references are recorded.** Code or test comments that point at deleted/legacy docs (per `docs/protocol/LEGACY_DOC_CLEANUP_MANIFEST.md`) are recorded as documentation gaps and do not invalidate the underlying code.
5. **Conservative classification.** Where a claim is partly implemented, this audit calls it partial; "close enough" is not a category.
6. **Contradiction recording is reserved.** `docs/whitepaper/contradiction.md` is updated only where a genuine code↔doc contradiction is unresolved and material; doc-wording drift alone is not promoted to a contradiction.

The audit was performed against the working tree at this commit, against the canonical doc baseline at §2.

---

## 4. Areas Confirmed Aligned

The following claim areas are genuinely supported by repo state.

### 4.1 HotStuff core, view-change, locking, equivocation

| Field | Value |
|-------|-------|
| Claim area | HotStuff 3-chain commit, locked-block safety, view-change/timeout pacemaker, equivocation detection |
| Canonical doc references | Whitepaper §8 (consensus), §17.3.1 (timeout backoff), Protocol Report §2.4, §3.3, §3.4 |
| Repo evidence | `crates/qbind-consensus/src/hotstuff_state_engine.rs`, `basic_hotstuff_engine.rs`, `pacemaker.rs`, `timeout.rs`, `qc.rs`; tests `hotstuff_locked_block_safety_tests.rs`, `hotstuff_qc_aggregation_tests.rs`, `hotstuff_state_locking_tests.rs`, `m5_timeout_view_change_tests.rs`, `hotstuff_equivocation_detection_tests.rs`, `t146_timeout_types_tests.rs` |
| Confidence | High |

### 4.2 Slashing enforcement for O1–O5 (M9/M11) and signed-evidence verification

| Field | Value |
|-------|-------|
| Claim area | All offense classes O1–O5 enforced under `EnforceCritical`/`EnforceAll`; ML-DSA-44 signature verification on evidence; deterministic, fail-closed handling |
| Canonical doc references | Whitepaper §12.2 + §12.2.3, contradiction.md C1, Protocol Report §3.10, §3.13 |
| Repo evidence | `crates/qbind-consensus/src/slashing/mod.rs`: `apply_penalty_if_needed` (lines ~2584–2660) enforces all five offense kinds; `verify_ml_dsa_44_signature` and per-offense verification paths; `PenaltyEngineConfig::from_governance_schedule` ties penalty engine to `ParamRegistry`. Tests `m11_slashing_penalty_o3_o5_tests.rs`, `m9_slashing_penalty_tests.rs`, `t229_slashing_penalty_engine_tests.rs`, `t230_slashing_ledger_backend_tests.rs`. |
| Confidence | High |

### 4.3 Persistent slashing ledger and restart safety (M1/M19)

| Field | Value |
|-------|-------|
| Claim area | Persistent, atomic slashing state with fail-closed corruption detection on startup |
| Canonical doc references | Whitepaper §16.8, contradiction.md Item 1, Protocol Report §3.15 |
| Repo evidence | `crates/qbind-ledger/src/slashing_ledger.rs` (`RocksDbSlashingLedger`, `apply_slashing_update_atomic`, `verify_slashing_consistency_on_startup`); tests `m19_slashing_persistence_canonicalization_tests.rs`, `t230_slashing_ledger_backend_tests.rs`. |
| Confidence | High |

### 4.4 Atomic epoch transition and validator-set transition (M12/M16)

| Field | Value |
|-------|-------|
| Claim area | Epoch boundary writes are atomic via RocksDB `WriteBatch`, with marker-based incomplete-transition detection on startup |
| Canonical doc references | Whitepaper §18 (Validator Set Transition), Protocol Report §2.6, contradiction.md Item 4 |
| Repo evidence | `crates/qbind-node/src/storage.rs` (epoch transition batch, marker), tests `m16_epoch_transition_hardening_tests.rs`, `t112_atomic_epoch_persistence_tests.rs`, `three_node_epoch_transition_tests.rs`, `three_node_staggered_epoch_transition_tests.rs`. |
| Confidence | High |

### 4.5 Minimum stake enforcement at epoch boundary (M2.1–M2.4)

| Field | Value |
|-------|-------|
| Claim area | `min_validator_stake` enforced at registration and at epoch boundary; fail-closed on empty filtered set |
| Canonical doc references | Whitepaper §8.1, §12.2, §18; contradiction.md C2; Protocol Report §3.11 |
| Repo evidence | `crates/qbind-system/src/validator_program.rs:130–132` (registration check), `crates/qbind-consensus/src/validator_set.rs:116–178` (`build_validator_set_with_stake_filter`), `crates/qbind-node/src/hotstuff_node_sim.rs:936–987` (`with_stake_filtering_epoch_state_provider`); tests `m2_2_stake_filter_epoch_transition_tests.rs`, `m2_3_stake_filtering_node_integration_tests.rs`, `m2_4_production_stake_filtering_tests.rs`. |
| Confidence | High |

### 4.6 KEMTLS handshake, DoS cookie (M6), NodeId derivation (M7), mutual auth (M8)

| Field | Value |
|-------|-------|
| Claim area | ML-KEM-768 KEMTLS with 2-step DoS cookie, peer identity bound to KEM public key, mutual KEMTLS authentication required for TestNet/MainNet |
| Canonical doc references | Whitepaper §9 (post-quantum networking), Protocol Report §3.4, §3.8, §3.9; contradiction.md (security risk register) |
| Repo evidence | `crates/qbind-net/src/handshake.rs`, `cookie.rs`, `kem_metrics.rs`; tests `m6_dos_cookie_protection_tests.rs`, `m7_nodeid_extraction_tests.rs`, `m8_mutual_auth_tests.rs`, `m8_mutual_auth_config_tests.rs`, `t135_ml_kem_768_kemtls_tests.rs`, `t139_real_pqc_kemtls_two_node_tests.rs`. |
| Confidence | High |

### 4.7 Signer isolation and remote signer (M10/M10.1)

| Field | Value |
|-------|-------|
| Claim area | Remote signer with KEMTLS mutual auth, replay protection, fail-closed; `LoopbackTesting` forbidden on TestNet/MainNet |
| Canonical doc references | Whitepaper §9.7, Protocol Report §3.8, contradiction.md security register |
| Repo evidence | `crates/qbind-node/src/remote_signer.rs`, `validator_signer.rs`, `node_config.rs::validate_signer_mode_for_mainnet` (~lines 620–650); tests `m10_signer_isolation_tests.rs`, `m10_1_signer_policy_tests.rs`, `t149_remote_signer_integration_tests.rs`, `t212_remote_signer_integration_tests.rs`. |
| Confidence | High |

### 4.8 MainNet config invariants (T185/T232/T237)

| Field | Value |
|-------|-------|
| Claim area | MainNet rejects insecure configurations (gas off, slashing off/RecordOnly, snapshots disabled, eviction off, anti-eclipse off, missing genesis path/expected hash, monetary mode off) |
| Canonical doc references | Release Track Spec, MainNet Readiness Checklist, MainNet Cutover Runbook |
| Repo evidence | `crates/qbind-node/src/node_config.rs::validate_mainnet_invariants` and `MainnetConfigError` variants; tests `t237_mainnet_launch_profile_tests.rs`, `t232_genesis_mainnet_profile_tests.rs`, `t185_mainnet_profile_tests.rs`. |
| Confidence | High |

### 4.9 Governance-wired slashing schedule (M14)

| Field | Value |
|-------|-------|
| Claim area | Slashing penalty schedule lives in `ParamRegistry`; engine config derived deterministically from governance state; epoch-boundary activation; TestNet/MainNet fail-closed if missing |
| Canonical doc references | Whitepaper §11, §12.2, contradiction.md Item 9, Protocol Report §3.13 |
| Repo evidence | `crates/qbind-types/src/state_governance.rs:44–117`; `crates/qbind-consensus/src/slashing/mod.rs` `from_governance_schedule`; `crates/qbind-genesis/src/lib.rs:24–53` writes a default schedule into genesis; tests `m14_governance_slashing_params_tests.rs`. |
| Confidence | High |

### 4.10 Hardened evidence ingestion (M15)

| Field | Value |
|-------|-------|
| Claim area | Cheap-checks-first evidence ingestion with deduplication, size bounds, per-block cap, age window, validator-reporter requirement |
| Canonical doc references | Protocol Report §3.14, contradiction.md C3 mitigation |
| Repo evidence | `crates/qbind-consensus/src/slashing/mod.rs` (`HardenedEvidenceIngestionEngine`, `EvidenceIngestionConfig`); tests `m15_evidence_ingestion_hardening_tests.rs`. |
| Confidence | High |

### 4.11 Storage corruption guardrails and CRC-32 framing

| Field | Value |
|-------|-------|
| Claim area | CRC-32 wraps for storage integrity (non-cryptographic), with fail-closed corruption handling at read time |
| Canonical doc references | Whitepaper §10.5.1, contradiction.md Item 3 |
| Repo evidence | `crates/qbind-node/src/storage.rs:256–336`; tests `storage_corruption_tests.rs`, `storage_corruption_guardrails_tests.rs`, `schema_versioning_tests.rs`. |
| Confidence | High |

### 4.12 Deterministic release build pipeline

| Field | Value |
|-------|-------|
| Claim area | Reproducible release binaries with SHA3-256 hashes and manifest fragment, suitable for the cutover runbook’s artifact-integrity expectations |
| Canonical doc references | MainNet Cutover Runbook, MainNet Readiness Checklist (binary identity / artifact integrity) |
| Repo evidence | `scripts/build-mainnet-release.sh` |
| Confidence | Medium-High (script exists; not yet exercised as a Beta-grade evidence artifact) |

---

## 5. Partial Alignments

The following are implemented to a degree, but the docs are stronger or broader than the current repo support, or only some paths are exercised.

### 5.1 `qbind-node` binary as an operable validator

| Field | Value |
|-------|-------|
| What docs claim | `docs/devnet/QBIND_DEVNET_OPERATIONAL_GUIDE.md` §8 (node bring-up workflow) presumes a runnable binary that starts a node, produces blocks, exposes metrics and health endpoints, advances views, and reaches finality. The TestNet Alpha and Beta plans inherit the same assumption. |
| What exists | The full consensus, networking, mempool, ledger, and execution stacks exist as crates and are exercised end-to-end via integration test harnesses (`NodeHotstuffHarness`, `t132`/`t138`/`t139`/`t154`/`t160`/`t166` cluster harnesses, `three_node_*` tests). The `P2pNodeBuilder` (`crates/qbind-node/src/p2p_node_builder.rs`) wires KEMTLS transport, demuxer, and the `P2pConsensusNetwork` adapter. MainNet config invariants are enforced at startup. |
| What is missing | The production binary entry point `crates/qbind-node/src/main.rs` is a startup stub. `run_local_mesh_node` only prints and waits for `Ctrl+C` (lines 111–124). `run_p2p_node` builds the P2P context but does **not** start a HotStuff/pacemaker driver, propose blocks, or commit them — there is no `consensus_engine`/`drive_consensus` invocation in `p2p_node_builder.rs`. End-to-end "runs as a validator from the binary" is therefore not yet a property of the repo; it is a property of the test harnesses. |
| Doc softening or code extension | **Code extension required.** Either (a) wire the existing harnessed consensus driver into `run_p2p_node`, or (b) DevNet/TestNet plans must explicitly say "operates via test harness" until then. The honest answer is (a). |

### 5.2 Metrics endpoint exposure at startup

| Field | Value |
|-------|-------|
| What docs claim | DevNet Operational Guide §7.7, §8.7 expect a metrics endpoint (Prometheus-compatible) to be reachable at node startup. Monitoring and Alerting Baseline §4 requires Class A/C/D/E/F signals to be observable. |
| What exists | `crates/qbind-node/src/metrics_http.rs` implements a Prometheus-format `/metrics` HTTP server (`spawn_metrics_http_server`, `format_metrics_output`) and `crates/qbind-node/src/metrics.rs` defines a comprehensive metric surface (consensus, network, snapshot, KEMTLS, evidence ingestion). The library re-exports the spawn helpers (`crates/qbind-node/src/lib.rs:349–351`). |
| What is missing | `spawn_metrics_http_server` is **not invoked** from `crates/qbind-node/src/main.rs` or `p2p_node_builder.rs`. Therefore the production binary does not expose `/metrics` even though all the plumbing is shipped. |
| Doc softening or code extension | **Code extension required.** Add a single spawn site in the binary path (gated on `QBIND_METRICS_HTTP_ADDR` already supported by `MetricsHttpConfig::from_env`). No doc change needed. |

### 5.3 Snapshot creation vs. snapshot-driven recovery

| Field | Value |
|-------|-------|
| What docs claim | `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md` C1–C5 require recoverability from validator state, ledger state, and snapshots. The Operator Drill Catalog and MainNet Readiness Checklist treat **restore proofs** as readiness evidence. |
| What exists | Snapshot **creation** is implemented (`crates/qbind-ledger/src/state_snapshot.rs` `StateSnapshotter`, RocksDB checkpoint layout `meta.json` + `state/`). EVM substate has an in-memory `restore` (`crates/qbind-runtime/src/evm_state.rs:168`). Snapshot metrics are emitted (`qbind_snapshot_*` in `metrics.rs`). |
| What is missing | There is **no boot-from-snapshot path** in `qbind-node`. `crates/qbind-node/src/main.rs`, `cli.rs`, `startup_validation.rs`, and `p2p_node_builder.rs` contain no `restore_from_snapshot`/`load_snapshot`/`apply_snapshot` invocation. A snapshot can be produced, but a node cannot be honestly demonstrated to recover from one end-to-end via the binary. |
| Doc softening or code extension | **Code extension required.** Either implement snapshot ingestion at startup, or scope DevNet/Beta evidence to "RocksDB checkpoint + manual restore" until then. The Backup/Recovery baseline expects the former. |

### 5.4 Per-environment genesis profiles

| Field | Value |
|-------|-------|
| What docs claim | DevNet/TestNet Alpha/TestNet Beta/MainNet are described as distinct environments with distinct economic and operational postures. |
| What exists | `crates/qbind-types/src/primitives.rs:84–135` defines `NetworkEnvironment` (Devnet/Testnet/Mainnet) and per-env `ChainId` constants and scope strings. `crates/qbind-node/src/node_config.rs` provides per-environment defaults for execution, signer mode, slashing, snapshots, retention, mempool, and validates MainNet invariants. T232 enforces "MainNet requires external genesis path." |
| What is missing | `crates/qbind-genesis/src/lib.rs` has a **single** genesis builder. `build_genesis_param_registry` writes the same constants regardless of environment (lines 38–53), and the comments explicitly call them "placeholder numbers, changeable via governance" (lines 33, 44). `LaunchChecklist` is initialized with all-false flags and zero hashes (lines 56–76). Per-environment genesis assets (e.g., distinct stake floors, allocation, reporter rewards) are not represented here. |
| Doc softening or code extension | **Either is acceptable.** Acceptable interpretation: genesis is intentionally minimal; per-environment parameterization happens via governance and external genesis files (consistent with T232's MainNet external-genesis requirement). Doc-side: the DevNet guide and Beta plan should make explicit that genesis is environment-agnostic at the code level and that per-env distinction is delivered via `NodeConfig` presets and external genesis files. |

### 5.5 Evidence templates vs. produced artifacts

| Field | Value |
|-------|-------|
| What docs claim | `docs/release/QBIND_MAINNET_READINESS_EVIDENCE_PACKET_TEMPLATE.md`, `docs/testnet/QBIND_BETA_EVIDENCE_PACKET_TEMPLATE.md`, `docs/release/QBIND_MAINNET_AUTHORIZATION_MEMO_TEMPLATE.md` enumerate evidence sections (drill records, restore proofs, monitoring evidence, postmortem records, version/integrity attestations, signed sign-offs). |
| What exists | Test harnesses produce structured assertions (`t154_devnet_tps_harness`, `t160_devnet_cluster_harness`, `t166_testnet_alpha_cluster_harness`, `t207_p2p_topology_harness`, `t222_consensus_chaos_harness`, `t223_stage_b_soak_harness`, `t238_multi_region_latency_harness`). Snapshot, slashing, and KEMTLS metrics exist in code. The release-build script produces hashes. |
| What is missing | None of these harnesses or scripts emit an artifact in the **shape required by the templates** (e.g., signed memo, packet section per template heading). An operator running today must produce evidence by transcribing test output, log captures, and monitoring screenshots into a template manually. |
| Doc softening or code extension | **Doc/process gap, not a code gap.** Templates are accurate; instances of the templates have not been produced. Either accept that templates remain blank until exercised in Beta (consistent with the cutoff audit's "execution evidence over docs" rule), or add a thin generator script. The honest reading: this is expected at this phase. |

### 5.6 Slashing-mode default documentation in code vs. enforcement

| Field | Value |
|-------|-------|
| What docs claim | Whitepaper §12.2 + contradiction.md C1: O1–O5 enforced under `EnforceCritical`/`EnforceAll`. Protocol Report §3.12: MainNet rejects `Off`/`RecordOnly`. |
| What exists | `crates/qbind-consensus/src/slashing/mod.rs` (apply_penalty_if_needed): `EnforceCritical` and `EnforceAll` both apply O1–O5 penalties (per M11). `validate_for_mainnet` rejects `Off`/`RecordOnly` (`m4_slashing_mode_enforcement_tests.rs`). |
| What is missing | The **doc comment** in `crates/qbind-node/src/node_config.rs:1935–1945` still describes `EnforceCritical` as "O1 (double-sign) and O2 (invalid proposer sig)" and `EnforceAll` as "Reserved for future use," and lists MainNet default as `RecordOnly`. The actual constructors at lines 2111–2160 produce `EnforceCritical` for Devnet/Alpha/Beta/MainNet. |
| Doc softening or code extension | **Documentation correction in code comments.** Code is correct; the doc-comment block is stale and contradicts both the code and the canonical contradiction.md C1 record. Should be reworded. (No canonical doc change required.) |

### 5.7 Stage B soak / chaos / multi-region claims

| Field | Value |
|-------|-------|
| What docs claim | `docs/testnet/QBIND_TESTNET_BETA_PLAN.md` and `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md` rely on Stage B soak, consensus chaos, and multi-region latency evidence. |
| What exists | Harnesses present: `t222_consensus_chaos_harness.rs`, `t223_stage_b_soak_harness.rs`, `t238_multi_region_latency_harness.rs`, `t234_pqc_end_to_end_perf_tests.rs`. |
| What is missing | These harnesses still reference the deleted `QBIND_MAINNET_AUDIT_SKELETON.md` document in their headers (see §6.4). The harnesses themselves are real; their doc anchors are not. Operationally these are still inner-loop tests rather than long-running cluster runs producing evidence packets. |
| Doc softening or code extension | **Doc/process gap.** Tests exist; readiness-grade execution against them is future work. |

---

## 6. Misalignments and Gaps

The following are outright misalignments between what canonical docs claim and what the repo currently supports.

### 6.1 Operable node binary missing the consensus driver

`docs/devnet/QBIND_DEVNET_OPERATIONAL_GUIDE.md` §8 reads as if running `qbind-node --env devnet` brings up a working validator. In fact `crates/qbind-node/src/main.rs::run_local_mesh_node` only prints `[T175] LocalMesh node startup is a stub in T175` and idles, and `run_p2p_node` builds the transport but never starts the HotStuff driver. **A node cannot be operated from the binary today.** Promoted to contradiction.md as a new entry (see §8). Recorded as the most material code gap in this audit.

### 6.2 `/metrics` endpoint not started by the binary

The Monitoring and Alerting Baseline lists Class A/C/D/E/F observability as the minimum baseline. The metrics implementation is comprehensive, but `spawn_metrics_http_server` has no caller in the binary. As a result, none of the documented signal classes are externally observable from a running `qbind-node` process. Promoted to contradiction.md.

### 6.3 Restore-from-snapshot path

The Backup and Recovery Baseline (§C5, §recoverability requirements) expects restore proofs as evidence. The repository can produce snapshots and emits `qbind_snapshot_*` metrics, but no code path imports or applies a snapshot at startup. There is no end-to-end "boot-from-snapshot" demonstrable from the binary. Promoted to contradiction.md.

### 6.4 Code/test references to deleted legacy docs

The legacy cleanup manifest (`docs/protocol/LEGACY_DOC_CLEANUP_MANIFEST.md`) marked for deletion: `mainnet/QBIND_MAINNET_V0_SPEC.md`, `mainnet/QBIND_MAINNET_AUDIT_SKELETON.md`, `ops/QBIND_MAINNET_RUNBOOK.md`. These docs do not exist in `docs/` today, but **are still referenced** by:

- `crates/qbind-node/src/main.rs:73` — `[T185] See QBIND_MAINNET_V0_SPEC.md`
- `crates/qbind-node/src/node_config.rs:3507`, `:4377` — references to `QBIND_MAINNET_V0_SPEC.md`
- `crates/qbind-node/tests/t185_mainnet_profile_tests.rs:28` — same
- `crates/qbind-node/tests/t237_mainnet_launch_profile_tests.rs:41–43` — references to `QBIND_MAINNET_V0_SPEC.md`, `QBIND_MAINNET_AUDIT_SKELETON.md`, `QBIND_MAINNET_RUNBOOK.md`
- `crates/qbind-node/tests/t222_consensus_chaos_harness.rs`, `t223_stage_b_soak_harness.rs`, `t234_pqc_end_to_end_perf_tests.rs`, `t236_fee_market_adversarial_tests.rs`, `t238_multi_region_latency_harness.rs` — references to `QBIND_MAINNET_AUDIT_SKELETON.md`
- `crates/qbind-ledger/src/monetary_state.rs:1112` — `QBIND_MAINNET_V0_SPEC §4.1`

These pointers now resolve to nothing. Doc-wording gap, not a code-correctness defect, but it actively misleads operators following the binary's own error messages and tests' contracts. Should be retargeted to the canonical baseline (`QBIND_MAINNET_READINESS_CHECKLIST.md` / `QBIND_MAINNET_CUTOVER_RUNBOOK.md` / `QBIND_PROTOCOL_REPORT.md`).

### 6.5 Stale `SlashingMode` enum docstring

`crates/qbind-node/src/node_config.rs:1933–1945` documents `EnforceCritical` as covering only O1/O2 and `EnforceAll` as "Reserved for future use," and lists MainNet default as `RecordOnly`. Since M9/M11/M14 the actual behavior is: `EnforceCritical` and `EnforceAll` both enforce O1–O5; MainNet default is `EnforceCritical`. This contradicts contradiction.md C1 (RESOLVED) and `apply_penalty_if_needed` itself. Doc-only fix (rewrite the comment). Not promoted to contradiction.md because the canonical docs are consistent — only the in-code comment is stale.

### 6.6 Genesis numerics labeled "placeholder"

`crates/qbind-genesis/src/lib.rs:32–53` self-describes its `slash_bps_prevote`, `slash_bps_precommit`, and `reporter_reward_bps` as "placeholder numbers, changeable via governance." The MainNet Economics Finalization document (§5.8, §5.9, §10) is explicit that several MainNet values are `REQUIRED FINAL VALUE`, including genesis supply and allocation percentages. There is no MainNet-finalization wiring in `qbind-genesis` for these values; MainNet genesis is intended to be supplied externally per T232. This is consistent with the doc; however, `min_validator_stake = 1_000_000` and the placeholder slash bps are baked into the embedded genesis builder and are silently inherited if external genesis is not used. Operators must understand that the embedded `build_genesis_param_registry` is **not** a MainNet-fit set of values. Doc-side: the DevNet guide and Beta economics scope already say Beta does not finalize. The gap is a wording-and-naming gap: the embedded constants should be marked `dev-only` more loudly, or the function renamed. No canonical doc change required.

### 6.7 RPC port mentioned in docs without an RPC server

`docs/devnet/QBIND_DEVNET_OPERATIONAL_GUIDE.md` §7.5 lists "Consensus, RPC, metrics ports." There is no JSON-RPC or RPC server implementation in `qbind-node`. `RPC` references in code (`remote_signer.rs`, `cli.rs`) refer to the remote-signer transport, not a public client RPC. Either the DevNet guide should remove the "RPC port" wording (recommended), or an RPC surface must be implemented (out of scope for DevNet readiness). Doc-side fix is the honest call.

### 6.8 Health/readiness endpoint mentioned in docs

DevNet Operational Guide §8.7 expects "health/readiness signals." There is no `/health` or `/ready` endpoint in `metrics_http.rs` (only `/metrics`). Either drop the wording, or extend `metrics_http.rs` with a no-op `/health` returning `200`. Marginal scope. Doc-side fix is acceptable for DevNet; readiness probes will eventually be required for MainNet operations and should land before MainNet readiness.

---

## 7. Code Gaps vs. Documentation Gaps

| ID | Item | Classification | Notes |
|---|---|---|---|
| 6.1 | Binary lacks consensus driver | **Code gap** | Material; blocks DevNet readiness. |
| 6.2 | Metrics HTTP not spawned by binary | **Code gap** | Trivial fix (one spawn site); blocks observability evidence. |
| 6.3 | No restore-from-snapshot path | **Code gap** | Required for Backup/Recovery readiness. |
| 6.4 | Code references deleted legacy docs | **Doc gap** | Update comments and test headers; no code-behavior change. |
| 6.5 | Stale `SlashingMode` enum docstring | **Doc gap** | In-code comment only. |
| 6.6 | "Placeholder" genesis numerics | **Doc/wording gap** | Embedded genesis is dev-only by design; clarify naming. |
| 6.7 | "RPC port" in DevNet guide | **Doc gap** | Drop wording or implement RPC (post-MainNet scope). |
| 6.8 | "Health/readiness" in DevNet guide | **Mixed** | Cheap code add (`/health` endpoint) is the cleaner fix. |
| 5.5 | Evidence templates vs. produced artifacts | **Process gap** | Templates are correct; they have not been instantiated yet. |
| 5.7 | Stage B / chaos / multi-region | **Process gap** | Harnesses exist; readiness-grade runs are future work. |

The big-three are all code gaps (6.1, 6.2, 6.3). Everything else is doc/process and can be fixed cheaply or absorbed by the cutoff audit's "execution evidence over docs" rule.

---

## 8. Contradictions Requiring Tracking

`docs/whitepaper/contradiction.md` is updated by this audit with **one new contradiction entry**, **C4: Production binary does not yet boot a fully operating node**, which subsumes §6.1, §6.2, and §6.3 (binary lacks consensus driver, metrics HTTP not spawned, no restore-from-snapshot path). These are recorded together because they are properties of the same artifact — `crates/qbind-node` as a runnable binary — and would naturally be resolved by the same execution work.

The pre-existing C3 (Reporter Rewards) remains OPEN, unchanged. No other prior contradictions are reopened by this audit.

This is the only contradiction added. The doc-only items in §6.4–6.8 and §5.6 are not promoted to `contradiction.md` — they are stale wording, not unresolved code↔doc contradictions in the canonical doc baseline.

---

## 9. Top Execution Blockers Exposed

The following blockers are concrete and arise directly from this audit. Order is priority.

### B1. `qbind-node` binary does not start a consensus loop

- **Why now:** DevNet, TestNet Alpha, TestNet Beta, and MainNet operational guides assume an operable validator binary. Today, only test harnesses operate the consensus stack end-to-end. EXE-2 (DevNet readiness against real repo state) cannot be honestly attempted without this.
- **Blocks:** DevNet readiness, TestNet Alpha, TestNet Beta, MainNet readiness.
- **Suggested next owner / action type:** Code. Wire the existing `BasicHotStuffEngine` / `NodeHotstuffHarness` driver into `run_p2p_node` (and a minimal LocalMesh path), gated by `--validator-id`. No new design needed.

### B2. `/metrics` endpoint not exposed at startup

- **Why now:** The Monitoring and Alerting Baseline and DevNet Operational Guide both presume metrics observability at startup. All metrics exist in code; only the spawn site is missing.
- **Blocks:** DevNet readiness evidence, Beta operations, MainNet observability assessment.
- **Suggested next owner / action type:** Code. Single spawn site in the binary path, gated on `QBIND_METRICS_HTTP_ADDR` (already supported by `MetricsHttpConfig::from_env`). Trivial.

### B3. No restore-from-snapshot path in the binary

- **Why now:** Backup and Recovery Baseline §C1–C5 and the Operator Drill Catalog require restore proofs. The repo can create snapshots; it cannot demonstrate restoring from one end-to-end.
- **Blocks:** Backup/recovery drill evidence; MainNet readiness §backup-and-recovery.
- **Suggested next owner / action type:** Code + ops. Implement startup ingestion of `meta.json` + RocksDB checkpoint and a CLI flag (`--restore-from-snapshot <path>`). A drill script can then produce the evidence the templates expect.

### B4. Stale references to deleted MainNet legacy docs in code/tests/error messages

- **Why now:** Operators following error messages like `[T185] See QBIND_MAINNET_V0_SPEC.md for requirements.` will land in nothing. Tests advertise non-existent doc anchors. This actively undermines operator trust.
- **Blocks:** Operator confidence; honest TestNet Beta operator-checklist execution.
- **Suggested next owner / action type:** Doc/code. Mechanical edit pass to retarget references to `QBIND_MAINNET_READINESS_CHECKLIST.md`, `QBIND_MAINNET_CUTOVER_RUNBOOK.md`, `QBIND_PROTOCOL_REPORT.md`. No behavior change.

### B5. MainNet economics numerics not yet fixed in canonical genesis

- **Why now:** `QBIND_MAINNET_ECONOMICS_FINALIZATION.md` §5.8/§5.9/§10 explicitly lists `REQUIRED FINAL VALUE` placeholders (genesis supply, allocation percentages). The repo's embedded genesis builder is dev-defaulted and labeled "placeholder." MainNet uses external genesis (T232), so this is not a code defect, but the values themselves remain a readiness blocker.
- **Blocks:** MainNet authorization (per the readiness checklist's economics gate). Does not block DevNet/Alpha/Beta.
- **Suggested next owner / action type:** Governance/economics. Land the `REQUIRED FINAL VALUE` numerics in the MainNet finalization doc and produce a corresponding external genesis fixture. No general code change required.

---

## 10. Final Assessment

The repository **partially matches** the canonical doc stack.

- The **protocol/consensus/networking/slashing/economics core** (Sections 4.1–4.11) is genuinely implemented and tested at the level the canonical docs claim. The Whitepaper, Protocol Report, and contradiction.md descriptions of safety-critical behavior are honest representations of what the crates do, supported by extensive `m*`/`t*` integration tests.
- The **binary-level operability** (Sections 5.1–5.3, 6.1–6.3) is materially behind the canonical operations and DevNet/TestNet documents. The validator stack works in tests; it does not yet run as a single command.
- The **doc-wording hygiene** around legacy MainNet references (Section 6.4) and a few in-code comments (Section 6.5) needs a mechanical cleanup pass.

**EXE-2 (DevNet readiness against real repo state) cannot start immediately.** It is gated on at minimum **B1** (binary runs consensus) and **B2** (metrics endpoint spawned). Without these two, DevNet "readiness" is performed against a stub binary rather than a running node, which the cutoff audit's R1 (required-doc rule) and the monitoring baseline's principle 5 (no anecdote-only signals) both forbid. **B3** (snapshot restore) is required before Backup/Recovery readiness can be claimed but does not block initial DevNet readiness.

**Highest-priority follow-up execution actions, in order:**

1. **B1** — Wire HotStuff driver into `qbind-node` binary (LocalMesh + P2P).
2. **B2** — Spawn `metrics_http` server from the binary (env-var gated).
3. **B3** — Implement `--restore-from-snapshot` startup path and a paired drill script.
4. **B4** — Mechanical reference cleanup in `qbind-node` and tests pointing at deleted legacy MainNet docs.
5. **B5** — Resolve the `REQUIRED FINAL VALUE` placeholders in `QBIND_MAINNET_ECONOMICS_FINALIZATION.md` and ship a MainNet external-genesis fixture (post-Beta).

Until B1–B3 land, the canonical claim "QBIND has a running node" is a claim about test harnesses, not about the binary. That distinction must be resolved before EXE-2 can be honestly closed.