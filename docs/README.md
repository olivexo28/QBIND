# QBIND Documentation

This directory contains the canonical documentation for the QBIND post-quantum secure Layer-1 blockchain protocol.

---

## Documentation Structure

### Canonical Protocol Documentation

| Directory | Contents |
|-----------|----------|
| `whitepaper/` | **QBIND Whitepaper** — Full technical specification including consensus, networking, cryptography, execution, and state model |
| `protocol/` | **Protocol Engineering Documents** — M-series coverage index, protocol report, state audits, and technical implementation tracking |
| `diagrams/` | **Architecture Diagrams** — SVG diagrams for node architecture, consensus flow, crypto roles, etc. |

### Key Documents

**Whitepaper:**
- `whitepaper/QBIND_WHITEPAPER.md` — The authoritative technical specification for QBIND
- `whitepaper/contradiction.md` — Tracks contradictions between whitepaper and implementation

**Protocol Engineering:**
- `protocol/QBIND_PROTOCOL_REPORT.md` — Protocol gaps, security assumptions, and implementation status
- `protocol/QBIND_M_SERIES_COVERAGE.md` — Audit-friendly index of risk mitigations (M0–M20)
- `protocol/QBIND_LEGACY_SYNTHESIS.md` — Distilled carry-forward of useful legacy design material

---

## Legacy Documentation Status

The `archive_legacy_v0/` directory has been consolidated and reduced. Useful content from legacy planning documents has been distilled into:

**`docs/protocol/QBIND_LEGACY_SYNTHESIS.md`**

This synthesis document contains:
- Legacy monetary and fee-market background
- DevNet/TestNet/MainNet planning history  
- DAG mempool and parallel execution design origins
- Future technology research worth preserving
- Non-canonical future considerations

**The `archive_legacy_v0/` directory is no longer a parallel source of truth.** All authoritative protocol documentation is contained in `whitepaper/` and `protocol/`.

See `docs/protocol/LEGACY_DOC_CLEANUP_MANIFEST.md` for the full audit and consolidation record.

---

## Quick Reference

### Core Protocol Specs
- Consensus: HotStuff-style BFT with 3-chain commit rule
- Signatures: ML-DSA-44 (FIPS 204)
- Key Exchange: ML-KEM-768 (FIPS 203)
- Transport: KEMTLS with ChaCha20-Poly1305 AEAD
- State: Account-based model with RocksDB persistence

### Network Environments
- **DevNet**: Development and rapid iteration
- **TestNet**: Adversarial testing and performance validation
- **MainNet**: Production-grade operation with strict safety rails

---

*For implementation details, see the crate-level documentation in `crates/`.*