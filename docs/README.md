# QBIND Documentation Index

This directory contains technical documentation for QBIND—a post-quantum-secure Layer-1 blockchain implemented in Rust.

QBIND is a pure PQC (Post-Quantum Cryptography) L1 chain covering:
- **Consensus**: HotStuff-style BFT consensus engine with timeout/view-change
- **Networking**: KEM-based secure networking with KEMTLS handshake
- **Economics**: Validator staking, slashing penalties, and monetary policy
- **Governance**: On-chain governance and upgrade mechanisms

---

## Canonical vs. Legacy Documentation

### Canonical Documentation (Current)

All documentation **outside** `archive_legacy_v0/` is considered canonical and authoritative. These documents reflect the current protocol design, implementation status, and engineering decisions.

### Legacy Archive (Historical Only)

The `archive_legacy_v0/` directory contains documentation imported from an older SSD repository. These documents are:
- **Non-authoritative**: May contain outdated or superseded information
- **Read-only**: Should not be edited or updated
- **Historical context**: Kept for reference and traceability only

> **Warning**: Do not rely on legacy archive documents for current protocol behavior. Always consult canonical documentation first.

---

## Documentation Index by Topic

### Protocol / Consensus

Core protocol specifications and consensus design:

- [QBIND Whitepaper](whitepaper/QBIND_WHITEPAPER.md) — Primary technical specification covering architecture, networking, consensus, state model, and roadmap
- [QBIND Protocol Report](protocol/QBIND_PROTOCOL_REPORT.md) — Protocol gaps, security assumptions, and implementation status tracking

### Networking / KEMTLS

Secure networking layer and handshake protocol:

- [QBIND Whitepaper §4–6](whitepaper/QBIND_WHITEPAPER.md) — Networking model, KEMTLS handshake, DoS protection (M6), NodeId extraction (M7), mutual authentication (M8)
- [QBIND Node Technical Audit](QBIND_NODE_TECHNICAL_AUDIT.md) — Async runtime structure, P2P demuxer, secure channel implementation

### Economics & Monetary Policy

Validator economics, staking, and fee markets:

- [Validator Economics Audit](protocol/QBIND_VALIDATOR_ECONOMICS_AUDIT.md) — Code-grounded audit of validator economics and slashing model
- [Economic Hardening Plan](protocol/ECONOMIC_HARDENING_PLAN.md) — Pre-TestNet engineering plan for economic security hardening
- [Validator Set Stake Filter Report](protocol/VALIDATOR_SET_STAKE_FILTER_INTEGRATION_REPORT.md) — Stake filtering integration for epoch transitions (M2.3, M2.4)

### Slashing / Governance

Slashing penalties, offense classes, and governance integration:

- [Slashing Invariants Audit](protocol/SLASHING_INVARIANTS_AUDIT.md) — Security invariants for O1–O5 penalty paths with code references
- [Validator Economics Audit §1](protocol/QBIND_VALIDATOR_ECONOMICS_AUDIT.md) — Offense classes (O1–O5), slashing modes, penalty enforcement

### DevNet / TestNet / MainNet Operations

Environment-specific configurations and operational guidance:

- [QBIND Whitepaper §3](whitepaper/QBIND_WHITEPAPER.md) — Network environments (DevNet, TestNet, MainNet) and their safety rails
- [Protocol Report §1](protocol/QBIND_PROTOCOL_REPORT.md) — Current implementation status and environment-specific requirements

### Audits & M-Series Coverage

Security audits and risk mitigation tracking:

- [M-Series Coverage Index](protocol/QBIND_M_SERIES_COVERAGE.md) — Comprehensive audit map for M0–M20 risk mitigations with code references and test suites
- [QBIND Node Technical Audit](QBIND_NODE_TECHNICAL_AUDIT.md) — Code-faithful analysis of qbind-node internals
- [State Audit](protocol/QBIND_STATE_AUDIT.md) — 360-degree audit of global protocol state components and mutation paths
- [Slashing Invariants Audit](protocol/SLASHING_INVARIANTS_AUDIT.md) — Verification of slashing security invariants

### Legacy Archive (Non-Authoritative)

Historical documentation from the older SSD repository. **These documents are not authoritative** and may contain outdated information.

- `archive_legacy_v0/whitepaper/` — Legacy whitepaper versions
- `archive_legacy_v0/consensus/` — Early consensus design documents
- `archive_legacy_v0/network/` — Original P2P network design
- `archive_legacy_v0/econ/` — Legacy tokenomics and fee market analysis
- `archive_legacy_v0/gov/` — Early governance design
- `archive_legacy_v0/devnet/`, `testnet/`, `mainnet/` — Legacy environment specs
- `archive_legacy_v0/audit/` — Historical audit documents
- `archive_legacy_v0/ops/` — Legacy operational runbooks
- `archive_legacy_v0/keys/` — Key management design (historical)
- `archive_legacy_v0/roadmap/` — Future tech research notes
- `archive_legacy_v0/ARCH/` — Architecture diagrams and overviews

---

## Rules for Future Documentation

### 1. Canonical Placement

New specifications, reports, and audits **MUST** be placed outside `archive_legacy_v0/`:
- Protocol specifications → `protocol/`
- Whitepaper updates → `whitepaper/`
- Audit documents → `protocol/` or root `docs/`

### 2. Legacy Archive Is Read-Only

Documents in `archive_legacy_v0/` are **frozen historical records**:
- Do not edit existing legacy documents
- Do not add new documents to the legacy archive
- Reference legacy docs only for historical context

### 3. Single Source of Truth

For each topic, maintain exactly **one canonical specification**:
- **Protocol design**: `whitepaper/QBIND_WHITEPAPER.md`
- **Implementation status**: `protocol/QBIND_PROTOCOL_REPORT.md`
- **M-series coverage**: `protocol/QBIND_M_SERIES_COVERAGE.md`

New documents should **reference** these canonical specs rather than duplicating content.

### 4. Cross-Referencing

When adding new documentation:
- Reference canonical documents by relative path
- Update this index (`docs/README.md`) to include the new document
- Link to specific sections where applicable (e.g., `whitepaper/QBIND_WHITEPAPER.md §10`)

### 5. Style Guidelines

- **Technical and neutral**: No marketing language
- **Structured**: Use headings, tables, and bullet lists
- **Code-grounded**: Reference file paths and line numbers where applicable
- **Standard Markdown**: Ensure compatibility with GitHub rendering

---

## Directory Structure

```
docs/
├── README.md                           # This index
├── QBIND_NODE_TECHNICAL_AUDIT.md       # Node technical audit
├── whitepaper/
│   ├── QBIND_WHITEPAPER.md             # Primary technical specification
│   ├── README.md                       # Whitepaper build instructions
│   └── diagrams/                       # Architecture diagrams
├── protocol/
│   ├── QBIND_PROTOCOL_REPORT.md        # Protocol status tracking
│   ├── QBIND_M_SERIES_COVERAGE.md      # M-series audit map
│   ├── QBIND_STATE_AUDIT.md            # State components audit
│   ├── QBIND_VALIDATOR_ECONOMICS_AUDIT.md
│   ├── SLASHING_INVARIANTS_AUDIT.md
│   ├── VALIDATOR_SET_STAKE_FILTER_INTEGRATION_REPORT.md
│   └── ECONOMIC_HARDENING_PLAN.md
└── archive_legacy_v0/                  # Legacy docs (non-authoritative)
    ├── whitepaper/
    ├── consensus/
    ├── network/
    ├── econ/
    ├── gov/
    ├── devnet/
    ├── testnet/
    ├── mainnet/
    ├── audit/
    ├── ops/
    ├── keys/
    ├── roadmap/
    └── ARCH/
```
