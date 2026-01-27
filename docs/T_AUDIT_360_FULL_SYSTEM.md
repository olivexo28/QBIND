> **SUPERSEDED**: This document has been superseded by `AUDIT_2026-01-26_QBIND_FULL_SYSTEM.md` for the current state of QBIND. This file is retained for historical reference only.

---

# T_AUDIT_360_FULL_SYSTEM (Historical)

**Date**: 2025-12-15 (approximate)  
**Scope**: T0–T142 (pre-timeout/view-change, pre-verification pool, pre-ValidatorSigner abstraction)  
**Status**: HISTORICAL - See AUDIT_2026-01-26_QBIND_FULL_SYSTEM.md for current audit

---

## Executive Summary (Historical)

This was the initial full-system audit covering the foundational work on QBIND (formerly "cano") through task T142. It documented:

- HotStuff BFT consensus core (3-phase commit, QC-based locking)
- ML-DSA-44 signatures for validator keys
- ML-KEM-768 for KEMTLS networking
- Basic keystore and key hygiene (zeroization, non-Clone)
- Initial test infrastructure

**Major gaps at T142**:
- No timeout/view-change protocol (liveness issues under leader failures)
- No multi-threaded verification (verification bottleneck)
- No ValidatorSigner abstraction (keys accessed directly)
- No identity self-check (operator error risk)

These gaps have been addressed in subsequent tasks:
- **T143**: Validator signing key integration
- **T144**: Keystore abstraction
- **T145**: Identity self-check
- **T146**: Timeout/view-change protocol
- **T147**: Multi-threaded verification pool
- **T148**: ValidatorSigner trait and LocalKeySigner

---

## System Model (T0–T142)

### Consensus
- **HotStuff 3-phase BFT**: Prepare → Pre-Commit → Commit
- **QCs**: Quorum certificates with 2f+1 threshold
- **Locked QC semantics**: Safety via voting rules
- **Gaps**: No timeout protocol, no view-change (liveness risk)

### Cryptography
- **ML-DSA-44** (FIPS 204): Validator signatures
- **ML-KEM-768** (FIPS 203): KEMTLS key exchange
- **ChaCha20-Poly1305**: Session encryption
- **Suite catalog**: ID 100 (ML-DSA-44) registered

### Networking
- **KEMTLS handshake**: ML-KEM-768 encapsulation
- **AEAD sessions**: ChaCha20-Poly1305
- **Gaps**: No DoS protection, no key rotation

### Key Management
- **Filesystem keystore**: JSON files with suite_id + private_key_hex
- **Key hygiene**: Zeroization on drop, no Clone, Debug redaction
- **Gaps**: No keystore abstraction, no identity self-check, no HSM support

### Verification
- **Sequential verification**: Single-threaded signature verification
- **Gaps**: Verification bottleneck (100 ms for 100 validators)

---

## Risk Register (T0–T142)

### Critical Risks (Historical)
1. **No timeout/view-change**: Leader failures cause consensus stall → **RESOLVED in T146**
2. **No multi-threaded verification**: Verification bottleneck → **RESOLVED in T147**
3. **No signer abstraction**: Direct key access, no HSM support → **RESOLVED in T148**
4. **No identity self-check**: Operator error (wrong key file) → **RESOLVED in T145**

### Persistent Risks
- No HSM/remote signer (T149 in progress)
- No key rotation protocol (roadmap T150+)
- No execution VM (roadmap T150+)
- No DAG mempool (roadmap T161+)

---

## Migration Notes

This document reflects the state of QBIND (formerly "cano") as of approximately T142 (December 2025). For the current state of the system, see:

**AUDIT_2026-01-26_QBIND_FULL_SYSTEM.md**

Key changes since T142:
- Timeout/view-change protocol (T146) for liveness
- Multi-threaded verification pool (T147) for throughput
- ValidatorSigner abstraction (T148) for HSM readiness
- Identity self-check (T145) for operational safety
- Keystore abstraction (T144) for key management

---

**Document Version**: 1.0 (Historical)  
**Archived**: 2026-01-26  
**Status**: Superseded
