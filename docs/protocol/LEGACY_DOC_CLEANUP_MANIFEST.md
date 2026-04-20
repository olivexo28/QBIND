# QBIND Legacy Documentation Cleanup Manifest

**Version**: 1.0  
**Date**: 2026-04-20  
**Status**: Consolidation Complete

---

## Executive Summary

| Category | Count |
|----------|-------|
| **Total files reviewed** | 50 |
| **Merged into synthesis** | 10 |
| **Superseded by canonical** | 21 |
| **Pure history** | 13 |
| **Duplicates** | 6 |

---

## Classification Key

- **A) KEEP_AS_CANONICAL_SOURCE_MATERIAL**: Contains useful material not already captured in current canonical docs
- **B) SUPERSEDED_BY_CANONICAL**: Same topic now covered better by current whitepaper/protocol report/M-series docs  
- **C) PURE_HISTORY**: Old drafts, snapshots, or context that should not stay in the live repo
- **D) DUPLICATE**: Redundant copy of another legacy file or canonical file

---

## Detailed File Audit

### Root Level Files (docs/archive_legacy_v0/)

| File | Classification | Reason | Action |
|------|---------------|--------|--------|
| `AUDIT_2026-01-26_QBIND_FULL_SYSTEM.md` | C) PURE_HISTORY | Historical audit snapshot; superseded by M-series docs and Protocol Report | delete_now |
| `QBIND_IGNORED_TESTS_AUDIT.md` | C) PURE_HISTORY | Temporary test tracking doc; no longer relevant | delete_now |
| `T150_EXECUTION_EVM_DESIGN.md` | B) SUPERSEDED_BY_CANONICAL | EVM design covered in whitepaper Section 10 and Protocol Report | delete_now |
| `T151_EXECUTION_BLOCK_APPLY.md` | B) SUPERSEDED_BY_CANONICAL | Block application covered in whitepaper Section 16 | delete_now |
| `T153_EVM_STATE_PERSISTENCE.md` | B) SUPERSEDED_BY_CANONICAL | State persistence covered in whitepaper Section 10.5 | delete_now |
| `T_AUDIT_360_FULL_SYSTEM.md` | C) PURE_HISTORY | Explicitly marked as superseded; historical context only | delete_now |
| `project_context_pqc.md` | A) KEEP_AS_CANONICAL_SOURCE_MATERIAL | Useful PQC background context; partially merged | merge_into_synthesis |

### ARCH/ Directory

| File | Classification | Reason | Action |
|------|---------------|--------|--------|
| `ARCH/QBIND_CODEBASE_ARCHITECTURE_OVERVIEW.md` | B) SUPERSEDED_BY_CANONICAL | Architecture now covered in whitepaper Sections 3-7 and Protocol Report | delete_now |
| `ARCH/QBIND_DIAGRAMS_DRAFT.md` | C) PURE_HISTORY | Draft diagrams; final diagrams in docs/whitepaper/diagrams/ | delete_now |

### audit/ Directory

| File | Classification | Reason | Action |
|------|---------------|--------|--------|
| `audit/QBIND_EXTERNAL_SECURITY_AUDIT_RFP.md` | C) PURE_HISTORY | RFP template; not part of protocol specification | delete_now |

### consensus/ Directory

| File | Classification | Reason | Action |
|------|---------------|--------|--------|
| `consensus/QBIND_GENESIS_AND_LAUNCH_DESIGN.md` | A) KEEP_AS_CANONICAL_SOURCE_MATERIAL | Genesis design details useful for synthesis | merge_into_synthesis |
| `consensus/QBIND_SLASHING_AND_PQC_OFFENSES_DESIGN.md` | B) SUPERSEDED_BY_CANONICAL | Slashing now fully covered in whitepaper Section 12 and M-series docs (M9, M11, M14, M17) | delete_now |

### devnet/ Directory

| File | Classification | Reason | Action |
|------|---------------|--------|--------|
| `devnet/QBIND_CHAIN_ID_AND_DOMAINS.md` | B) SUPERSEDED_BY_CANONICAL | Domain separation covered in whitepaper Section 5 | delete_now |
| `devnet/QBIND_DAG_MEMPOOL_DESIGN.md` | A) KEEP_AS_CANONICAL_SOURCE_MATERIAL | DAG mempool design has useful detail for future reference; merged | merge_into_synthesis |
| `devnet/QBIND_DEVNET_AUDIT.md` | C) PURE_HISTORY | DevNet-specific audit; superseded by TestNet/MainNet specs | delete_now |
| `devnet/QBIND_DEVNET_V0_FREEZE.md` | C) PURE_HISTORY | DevNet freeze capsule; historical milestone doc | delete_now |
| `devnet/QBIND_DEVNET_V0_SPEC.md` | B) SUPERSEDED_BY_CANONICAL | DevNet spec superseded by TestNet Alpha/Beta and MainNet specs | delete_now |
| `devnet/QBIND_PARALLEL_EXECUTION_DESIGN.md` | A) KEEP_AS_CANONICAL_SOURCE_MATERIAL | Parallel execution design (Stage A/B) useful for synthesis | merge_into_synthesis |
| `devnet/QBIND_PERF_AND_TPS_DESIGN.md` | B) SUPERSEDED_BY_CANONICAL | Performance covered in whitepaper Section 8 | delete_now |

### econ/ Directory

| File | Classification | Reason | Action |
|------|---------------|--------|--------|
| `econ/QBIND_FEE_MARKET_ADVERSARIAL_ANALYSIS.md` | A) KEEP_AS_CANONICAL_SOURCE_MATERIAL | Adversarial analysis valuable; fee market testing methodology | merge_into_synthesis |
| `econ/QBIND_MONETARY_POLICY_DESIGN.md` | A) KEEP_AS_CANONICAL_SOURCE_MATERIAL | Monetary policy foundation with PQC premium calculations | merge_into_synthesis |
| `econ/QBIND_TOKENOMICS_INPUT_SHEET.md` | B) SUPERSEDED_BY_CANONICAL | Tokenomics framework covered in whitepaper monetary policy section; content not used in synthesis | delete_now |
| `econ/T198_PQC_COST_BENCHMARKING.md` | A) KEEP_AS_CANONICAL_SOURCE_MATERIAL | PQC cost benchmarking methodology worth preserving | merge_into_synthesis |

### gov/ Directory

| File | Classification | Reason | Action |
|------|---------------|--------|--------|
| `gov/QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md` | A) KEEP_AS_CANONICAL_SOURCE_MATERIAL | Governance model design useful for synthesis | merge_into_synthesis |

### keys/ Directory

| File | Classification | Reason | Action |
|------|---------------|--------|--------|
| `keys/QBIND_KEY_MANAGEMENT_DESIGN.md` | B) SUPERSEDED_BY_CANONICAL | Key management covered in whitepaper Section 9 and M-series (M7, M8, M10) | delete_now |

### mainnet/ Directory

| File | Classification | Reason | Action |
|------|---------------|--------|--------|
| `mainnet/QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md` | A) KEEP_AS_CANONICAL_SOURCE_MATERIAL | DAG-consensus coupling details useful for synthesis | merge_into_synthesis |
| `mainnet/QBIND_MAINNET_AUDIT_SKELETON.md` | C) PURE_HISTORY | Audit skeleton template; not protocol content | delete_now |
| `mainnet/QBIND_MAINNET_V0_SPEC.md` | B) SUPERSEDED_BY_CANONICAL | MainNet spec now covered by canonical whitepaper and Protocol Report | delete_now |

### network/ Directory

| File | Classification | Reason | Action |
|------|---------------|--------|--------|
| `network/QBIND_P2P_NETWORK_DESIGN.md` | B) SUPERSEDED_BY_CANONICAL | P2P networking covered in whitepaper Section 4-5 and M-series (M6, M7, M8) | delete_now |
| `network/QBIND_P2P_TESTNET_ALPHA_GUIDE.md` | C) PURE_HISTORY | TestNet-specific guide; operational doc not protocol spec | delete_now |

### ops/ Directory

| File | Classification | Reason | Action |
|------|---------------|--------|--------|
| `ops/QBIND_MAINNET_RUNBOOK.md` | B) SUPERSEDED_BY_CANONICAL | Operational runbook; not protocol specification | delete_now |
| `ops/QBIND_MULTI_REGION_DRESS_REHEARSAL.md` | C) PURE_HISTORY | Dress rehearsal plan; operational planning doc | delete_now |
| `ops/grafana/qbind_mainnet_dashboard.example.json` | B) SUPERSEDED_BY_CANONICAL | Example config; not protocol specification | delete_now |
| `ops/prometheus/qbind_mainnet_alerts.example.yaml` | B) SUPERSEDED_BY_CANONICAL | Example config; not protocol specification | delete_now |

### release/ Directory

| File | Classification | Reason | Action |
|------|---------------|--------|--------|
| `release/QBIND_MAINNET_V0_RELEASE_MANIFEST.example.json` | C) PURE_HISTORY | Example release manifest; not protocol specification | delete_now |
| `release/QBIND_MAINNET_V0_RELEASE_MANIFEST.md` | C) PURE_HISTORY | Release manifest template; not protocol specification | delete_now |

### roadmap/ Directory

| File | Classification | Reason | Action |
|------|---------------|--------|--------|
| `roadmap/QBIND_FUTURE_TECH_RESEARCH.md` | A) KEEP_AS_CANONICAL_SOURCE_MATERIAL | Future tech research valuable for synthesis | merge_into_synthesis |

### testnet/ Directory

| File | Classification | Reason | Action |
|------|---------------|--------|--------|
| `testnet/QBIND_GAS_AND_FEES_DESIGN.md` | B) SUPERSEDED_BY_CANONICAL | Gas/fees covered in whitepaper Section 19 and Protocol Report | delete_now |
| `testnet/QBIND_TESTNET_ALPHA_AUDIT.md` | C) PURE_HISTORY | TestNet Alpha audit; historical milestone | delete_now |
| `testnet/QBIND_TESTNET_ALPHA_SPEC.md` | B) SUPERSEDED_BY_CANONICAL | TestNet Alpha spec superseded by MainNet whitepaper | delete_now |
| `testnet/QBIND_TESTNET_AUDIT_SKELETON.md` | D) DUPLICATE | Duplicate audit skeleton format | delete_now |
| `testnet/QBIND_TESTNET_BETA_AUDIT_SKELETON.md` | D) DUPLICATE | Duplicate audit skeleton format | delete_now |
| `testnet/QBIND_TESTNET_BETA_SPEC.md` | B) SUPERSEDED_BY_CANONICAL | TestNet Beta spec superseded by MainNet whitepaper | delete_now |

### whitepaper/ Directory

| File | Classification | Reason | Action |
|------|---------------|--------|--------|
| `whitepaper/QBIND_WHITEPAPER.md` | D) DUPLICATE | Older version of whitepaper; canonical is docs/whitepaper/QBIND_WHITEPAPER.md | delete_now |
| `whitepaper/QBIND_WHITEPAPER_DRAFT.tex` | D) DUPLICATE | LaTeX draft; redundant with markdown version | delete_now |
| `whitepaper/build_whitepaper.sh` | D) DUPLICATE | Build script for old whitepaper | delete_now |

### whitepaper_v2/ Directory

| File | Classification | Reason | Action |
|------|---------------|--------|--------|
| `whitepaper_v2/contradiction.md` | D) DUPLICATE | Duplicate of docs/whitepaper/contradiction.md with same content | delete_now |
| `whitepaper_v2/sections/01_executive_summary.tex` | B) SUPERSEDED_BY_CANONICAL | LaTeX section; canonical whitepaper is markdown | delete_now |
| `whitepaper_v2/sections/02_system_overview.tex` | B) SUPERSEDED_BY_CANONICAL | LaTeX section; canonical whitepaper is markdown | delete_now |
| `whitepaper_v2/sections/03_execution_and_state.tex` | B) SUPERSEDED_BY_CANONICAL | LaTeX section; canonical whitepaper is markdown | delete_now |

---

## Files Merged Into Synthesis

The following 10 files contributed useful material to `docs/protocol/QBIND_LEGACY_SYNTHESIS.md`:

1. `project_context_pqc.md` — PQC background context
2. `consensus/QBIND_GENESIS_AND_LAUNCH_DESIGN.md` — Genesis design patterns
3. `devnet/QBIND_DAG_MEMPOOL_DESIGN.md` — DAG mempool architecture
4. `devnet/QBIND_PARALLEL_EXECUTION_DESIGN.md` — Stage A/B parallel execution
5. `econ/QBIND_FEE_MARKET_ADVERSARIAL_ANALYSIS.md` — Fee market adversarial testing
6. `econ/QBIND_MONETARY_POLICY_DESIGN.md` — Security-budget-driven inflation
7. `econ/T198_PQC_COST_BENCHMARKING.md` — PQC cost benchmarking
8. `gov/QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md` — Governance model
9. `mainnet/QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md` — DAG-consensus coupling
10. `roadmap/QBIND_FUTURE_TECH_RESEARCH.md` — Future technology research

---

## Post-Cleanup State

**Cleanup Status: COMPLETE**

The deletions specified in this manifest have already been executed:

- **50 files** were deleted from `docs/archive_legacy_v0/`
- **0 files** remain in `docs/archive_legacy_v0/`
- The `docs/archive_legacy_v0/` directory has been removed
- Essential content preserved in `docs/protocol/QBIND_LEGACY_SYNTHESIS.md`

---

## Verification Checklist

Before executing deletions:

- [x] All canonical docs verified unchanged:
  - `docs/whitepaper/QBIND_WHITEPAPER.md`
  - `docs/protocol/QBIND_PROTOCOL_REPORT.md`
  - `docs/protocol/QBIND_M_SERIES_COVERAGE.md`
  - `docs/whitepaper/contradiction.md`
- [x] QBIND_LEGACY_SYNTHESIS.md created with distilled content
- [x] Source traceability maintained in synthesis doc
- [x] No contradictions introduced to canonical docs

---

## Execution Checklist

1. [x] **Verify synthesis committed** — `docs/protocol/QBIND_LEGACY_SYNTHESIS.md` exists and is committed
2. [x] **Delete files marked delete_now** — All 50 legacy files deleted
3. [x] **Verify remaining archive files** — `docs/archive_legacy_v0/` directory removed (0 remaining)
4. [x] **Update docs/README.md** — Updated to reference synthesis doc and note archive reduction

---

*Document prepared as part of legacy docs consolidation task.*  
*Last updated: 2026-04-20 (verification pass)*