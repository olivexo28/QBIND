# QBIND – Post-Quantum Context and Design Capsule

**Version**: 1.0  
**Last Updated**: 2026-01-26  
**Audience**: New contributors, security auditors, cryptography researchers

---

## Overview

QBIND is a **post-quantum Byzantine Fault Tolerant (BFT) Layer-1 blockchain** designed from inception with pure post-quantum cryptography. Unlike retrofit approaches that layer PQ algorithms onto classical chains, QBIND's entire stack—consensus, networking, key management—uses NIST-standardized post-quantum primitives with no classical fallback.

**Historical Note**: The project was formerly named "cano" and has been fully renamed to QBIND (all crate names, documentation, and internal references updated).

---

## Goals

### 1. Pure Post-Quantum Security (No Classical Fallback)

**Why it matters**:
- Shor's algorithm (1994) breaks RSA, ECDSA, DH in polynomial time on quantum computers
- NIST estimates large-scale quantum computers feasible by 2030–2040
- "Harvest now, decrypt later" attacks: adversaries store encrypted traffic today, decrypt with future quantum computers

**QBIND approach**:
- **ML-DSA-44** (FIPS 204) for all validator signatures (proposals, votes, timeouts)
- **ML-KEM-768** (FIPS 203) for KEMTLS networking (key exchange)
- **ChaCha20-Poly1305** for authenticated encryption (classical AEAD, but quantum-resistant)
- **No classical crypto** in the consensus/networking core; bridges to classical chains (if any) isolated at edge

### 2. High TPS / Low Latency Through HotStuff Core + Future DAG/L2

**Current performance**:
- **HotStuff 3-phase BFT**: Deterministic finality in ~500 ms (3 network round-trips)
- **Baseline TPS**: 500–2,000 TPS on modern hardware (8-core, NVMe SSD, 100 validators, 50 ms RTT)
- **Pipelined blocks**: Multiple proposals in flight for throughput

**Scaling path**:
- **DAG mempool** (roadmap T161+): Parallel transaction ordering → 10,000+ TPS
- **Multi-threaded verification** (T147): 4–8× throughput gain via parallel signature verification
- **ZK L2 rollups** (roadmap T181+): Off-chain execution → 100,000+ TPS with on-chain proof verification

### 3. Cryptographic Agility and Safe Upgrades via Suite Registry

**Challenge**: NIST PQC Round 4+ may introduce new algorithms; existing algorithms may be broken by cryptanalysis

**QBIND solution**:
- **Suite catalog** (`qbind-crypto/src/suite_catalog.rs`): Registry of supported suites (ML-DSA-44, ML-DSA-87, SPHINCS+)
- **Suite IDs**:
  - ID 100: ML-DSA-44 (production, NIST Level 1)
  - ID 101: ML-DSA-87 (reserved, NIST Level 3)
  - ID 102: SPHINCS+-SHAKE-128s (reserved, stateless hash-based)
- **Backend registry**: `ConsensusSigBackendRegistry` maps suite_id → verifier implementation
- **Governance-driven upgrades**: On-chain voting (planned) to activate new suites, deprecate old ones

**Constraints**:
- All suites must provide ≥128-bit classical security
- Suite metadata must specify key sizes, performance characteristics
- Consensus code must dispatch via suite_id, not hardcoded algorithms

### 4. Strong Key Management (Keystore, Signer Abstraction, Future HSM/Remote Signer)

**Keystore abstraction** (T144):
- `ValidatorKeystore` trait: Interface for loading signing keys
- `FsValidatorKeystore`: Filesystem implementation (JSON files with suite_id + private_key_hex)
- Custom parser (no external deps for security-sensitive code)

**Identity self-check** (T145):
- Startup validation: loaded signing key derives expected public key
- Aborts node launch on mismatch (prevents operator error)

**ValidatorSigner abstraction** (T148):
- Trait-based interface: `sign_proposal()`, `sign_vote()`, `sign_timeout()`
- Enables pluggable signers: local keys, remote signers, HSMs
- Thread-safe (`Send + Sync`)

**LocalKeySigner** (T148):
- Wraps `Arc<ValidatorSigningKey>` (no Clone, zeroization on drop)
- Debug redacts key material (`<redacted>`)
- Default signer for validators without HSM

**Future HSM/remote signer** (T149+):
- `RemoteKeySigner`: gRPC/Unix socket to external signer service
- HSM integration (YubiHSM, AWS CloudHSM, Azure Key Vault)
- Keys never leave HSM; signing requests proxied

---

## PQC Stack Overview

### Signatures: ML-DSA-44 (FIPS 204)

**Algorithm**: Module-Lattice Digital Signature Algorithm (Dilithium variant)  
**Security level**: NIST Level 1 (~128-bit classical security)  
**Suite ID**: 100 (`SUITE_PQ_RESERVED_1`)

**Key sizes**:
- Secret key: 2,560 bytes
- Public key: 1,312 bytes
- Signature: ~2,420 bytes (context-dependent, variable)

**Performance** (typical x86_64):
- KeyGen: ~0.1 ms
- Sign: ~0.2–0.5 ms
- Verify: ~0.5–1 ms

**Properties**:
- **EUF-CMA**: Existentially unforgeable under chosen-message attack (assuming hardness of Module-LWE and Module-SIS)
- **Constant-time**: Implementation in `fips204` crate (mitigates timing attacks)
- **Deterministic**: Same message + key → same signature (no nonce generation)

**Wrapper** (`qbind-crypto/src/ml_dsa44.rs`):
- `ValidatorSigningKey`: Wraps secret key with zeroization on drop
- No `Clone` trait (prevents duplication)
- `Debug` redacts secret material

**Domain separation**:
- `QBIND_PROPOSAL_V1`: Block proposals
- `QBIND_VOTE_V1`: Block votes
- `QBIND_TIMEOUT_V1`: Timeout messages

**Trade-offs**:
- **Large signatures**: 2,420 bytes vs 64 bytes (ECDSA) → 38× overhead
- **No aggregation**: ML-DSA lacks BLS-style aggregation → 242 KB QCs (100 validators)
- **High security margin**: NIST Level 1 provides ~128-bit security; Level 3 (ML-DSA-87) available if needed

### KEM: ML-KEM-768 (FIPS 203)

**Algorithm**: Module-Lattice Key Encapsulation Mechanism (Kyber variant)  
**Security level**: NIST Level 3 (~192-bit classical security)

**Key sizes**:
- Secret key: 2,400 bytes
- Public key: 1,184 bytes
- Ciphertext: 1,088 bytes
- Shared secret: 32 bytes

**Performance** (typical x86_64):
- KeyGen: ~0.05 ms
- Encapsulate: ~0.1 ms
- Decapsulate: ~0.15 ms

**Properties**:
- **IND-CCA2**: Indistinguishability under adaptive chosen-ciphertext attack (assuming hardness of Module-LWE)
- **Constant-time**: Implementation in `fips203` crate
- **No forward secrecy** (current): Static server KEM keys used for all handshakes; ephemeral keys planned (T149+)

**Usage**: KEMTLS handshake (`qbind-net/src/handshake.rs`)
1. Client → Server: ClientHello (client ephemeral KEM public key)
2. Server: Encapsulates → ciphertext, shared secret
3. Server → Client: ServerHello (ciphertext)
4. Client: Decapsulates → shared secret
5. Both: Derive AEAD keys via HKDF-SHA256(shared_secret || "QBIND_SESSION_V1")

**Trade-offs**:
- **Larger keys/ciphertexts**: 1,184-byte public keys vs 32-byte ECDH keys → higher handshake overhead
- **Higher security level**: NIST Level 3 (192-bit) vs Level 1 for signatures (conservative choice for networking)

### AEAD: ChaCha20-Poly1305

**Algorithm**: Stream cipher (ChaCha20) + MAC (Poly1305)  
**Security**: IND-CCA2 with nonce uniqueness

**Key sizes**:
- Key: 256 bits (32 bytes)
- Nonce: 96 bits (12 bytes)
- Tag: 128 bits (16 bytes)

**Performance**: ~1–2 GB/s throughput on modern CPUs (highly optimized implementations)

**Properties**:
- **Quantum-resistant**: ChaCha20-Poly1305 provides 256-bit key strength → ~128-bit post-quantum security (Grover's algorithm)
- **Nonce management**: Counter-based; each message increments counter (no nonce reuse)
- **Key derivation**: HKDF-SHA256 from ML-KEM shared secret

**Usage**: Encrypt consensus messages post-KEMTLS handshake (`qbind-net/src/session.rs`)

**Trade-offs**:
- **No forward secrecy** (current): Session keys derived from static server KEM key; rekeying protocol needed (T149+)
- **Nonce exhaustion**: 96-bit nonce → 2^96 messages per session; sessions assumed short-lived or rekeyed

### Suite Registry and Categories

**Catalog** (`qbind-crypto/src/suite_catalog.rs`):

| Suite ID | Algorithm | NIST Level | Status |
|----------|-----------|------------|--------|
| 100 | ML-DSA-44 | 1 (~128-bit) | Production |
| 101 | ML-DSA-87 | 3 (~192-bit) | Reserved |
| 102 | SPHINCS+-SHAKE-128s | 1 (~128-bit) | Reserved |

**Categories** (if present):
- **Cat-1**: ~128-bit classical security (AES-128 equivalent)
- **Cat-3**: ~192-bit classical security (AES-192 equivalent)
- **Cat-5**: ~256-bit classical security (AES-256 equivalent)

**Validation**:
- No duplicate suite IDs
- Security level ≥ 128 bits
- Metadata includes key sizes, performance estimates

**Backend registry**: `ConsensusSigBackendRegistry` maps suite_id → verifier (`qbind-consensus/src/crypto_verifier.rs`)

---

## Consensus and Networking Snapshot (post-T148)

### HotStuff-Style BFT Consensus

**Protocol**: 3-phase commit (Prepare → Pre-Commit → Commit)

**Phases**:
1. **Prepare**: Leader proposes block; replicas vote if block extends locked QC
2. **Pre-Commit**: Leader aggregates votes into QC; replicas lock on QC
3. **Commit**: Leader aggregates pre-commit votes; replicas commit block

**QCs (Quorum Certificates)**:
- Contains: block_id, view, list of signers (validator IDs)
- Quorum threshold: ≥2f+1 signatures (where n = 3f+1 validators)
- Validation: All signers are committee members, no duplicates, threshold met

**Locked QC semantics**:
- Replica locks on QC when pre-committing
- Cannot vote for conflicting blocks unless seeing higher QC
- Safety: Two conflicting blocks cannot both reach commit (quorum intersection)

**Commit rule**:
- Block committed if direct 2-chain of QCs exists (HotStuff 3-phase property)
- Finality: Irreversible once committed (no forks)

**Liveness** (under partial synchrony):
- If GST (Global Stabilization Time) eventually holds, timeout protocol ensures progress

### Timeout and View-Change Protocol (T146)

**Motivation**: Leader failures (crash, malicious, network partition) can stall consensus

**Timeout message** (`TimeoutMsg`):
- Validator broadcasts when local timeout expires (no block proposed/committed in view)
- Contains: view, validator_id, high_qc (highest QC seen), signature
- Signature domain: `QBIND_TIMEOUT_V1`

**Timeout certificate** (`TimeoutCertificate`):
- Aggregates ≥2f+1 timeout messages for same view
- Proves quorum agrees: no progress possible in this view
- Carries highest QC among timeout messages (safety invariant)

**View advance**:
- Validator increments view upon receiving valid TC
- New leader elected deterministically (round-robin or weighted)
- New leader's proposal must extend high_qc from TC (safety)

**Pacemaker** (`TimeoutPacemaker`):
- Tracks local time; emits timeout events after `base_timeout` × `multiplier^view_failures`
- Config: base_timeout (1 sec), multiplier (2.0×), max_timeout (30 sec)
- Exponential backoff prevents timeout thrashing under network congestion

**Safety invariant**: high_qc in TC ensures new leader cannot fork committed chain

**Liveness guarantee**: If GST holds, timeout succeeds → new leader elected → progress resumes (proven in HotStuff paper)

### ValidatorSigner Abstraction (T148)

**Trait** (`qbind-node/src/validator_signer.rs`):
```rust
pub trait ValidatorSigner: Send + Sync {
    fn sign_proposal(&self, block_id: &BlockId, view: u64) -> Result<Vec<u8>, SignerError>;
    fn sign_vote(&self, block_id: &BlockId, view: u64) -> Result<Vec<u8>, SignerError>;
    fn sign_timeout(&self, view: u64, high_qc: &QC) -> Result<Vec<u8>, SignerError>;
}
```

**Implementations**:
- **LocalKeySigner** (T148): Wraps `Arc<ValidatorSigningKey>` (in-process signing)
- **RemoteKeySigner** (T149+): gRPC/Unix socket to external signer service

**Benefits**:
- Consensus code agnostic to signer implementation (no hardcoded key access)
- Enables HSM integration without harness changes
- Testable with mock signers (no real keys needed)

**Constraints**:
- Thread-safe (`Send + Sync`): Usable from async consensus tasks
- All consensus signing must go through trait (no direct key access)

### KEMTLS-Style Networking

**Handshake** (`qbind-net/src/handshake.rs`):
1. Client → Server: ClientHello (client ephemeral KEM public key)
2. Server: Encapsulates client's KEM key → ciphertext, shared secret
3. Server → Client: ServerHello (ciphertext, server identity)
4. Client: Decapsulates → shared secret
5. Both: Derive session AEAD keys via HKDF-SHA256(shared_secret || "QBIND_SESSION_V1")

**Authentication**:
- Validators exchange public KEM keys in genesis config (trusted setup)
- Mutual authentication via validator signatures on handshake messages (future enhancement)

**Session encryption** (`qbind-net/src/session.rs`):
- ChaCha20-Poly1305 AEAD
- Counter-based nonces (no reuse)
- Key rotation not implemented yet (sessions assumed short-lived)

**No TLS**: Pure PQ stack; no dependency on classical PKI/certificates

---

## Key Management and Identity

### Keystore Model (T144)

**Abstraction**: `ValidatorKeystore` trait (`qbind-node/src/keystore.rs`)
- Interface: `load_signing_key(&self, validator_id: &ValidatorId) -> Result<ValidatorSigningKey, KeystoreError>`

**Filesystem implementation** (`FsValidatorKeystore`):
- Reads JSON files: `{"suite_id": 100, "private_key_hex": "..."}`
- Path convention: `${keystore_dir}/${validator_id}.json`
- Custom parser (no `serde` for security)
- Errors: `NotFound`, `Parse`, `InvalidKey`, `Io` (no key bytes logged)

**Key hygiene**:
- Secret keys zeroized on drop (`zeroize::Zeroize`)
- No `Clone` trait (prevents duplication)
- `Debug` redacts key material (`<redacted>`)

### Identity Self-Check (T145)

**Data structure**: `LocalValidatorIdentity` (`qbind-node/src/validator_config.rs`)
- Expected validator_id
- Expected public_key
- Expected suite_id

**Startup validation**:
1. Load signing key from keystore
2. Derive public key from signing key
3. Compare with expected public key from config
4. If mismatch → `IdentityMismatchError` (abort startup)

**Error types**:
- `PublicKeyMismatch`: Derived PK ≠ expected PK
- `SuiteIdMismatch`: Loaded suite ≠ expected suite
- `DerivationFailed`: Cannot derive PK from SK (corrupted key)

**Purpose**: Prevents operator error (loading wrong key file for validator)

### Expected Future: HSM / Remote Signer Boundary

**Remote signer** (T149+):
- `RemoteKeySigner`: Communicates with external signer service
- Transport: gRPC (mTLS) or Unix domain socket (filesystem ACLs)
- API: Same `ValidatorSigner` trait methods (`sign_proposal`, `sign_vote`, `sign_timeout`)
- HSM integration: Remote signer wraps HSM (YubiHSM, AWS CloudHSM, Azure Key Vault)

**Key rotation** (T150+):
- On-chain key registry: Validators publish public keys on-chain
- Rotation protocol: Sign new key with old key → governance approval → activate
- Grace period: Both old and new keys valid during transition

**On-chain key registry integration** (T171+):
- Smart contract stores validator public keys + suite IDs
- Consensus validates signatures against on-chain registry
- Governance-driven key updates (add, revoke, rotate)

---

## Performance Direction

### Multi-Threaded Verification (T147)

**Architecture**:
- **Job submission**: Consensus creates `ConsensusVerifyJob` (view, block_id, validator_id, message_bytes, signature)
- **Worker pool**: `ConsensusVerifyPool` spawns N threads (default: CPU cores)
- **Bounded queues**: Job queue (1024), result queue (1024)
- **Backpressure**: `SubmitError::QueueFull` if job queue full → caller slows down

**Performance impact**:
- **Baseline** (single-threaded): 100 votes × 1 ms/vote = 100 ms verification latency
- **Parallel** (8 cores): 100 votes ÷ 8 cores = 12.5 ms verification latency
- **Expected gain**: 4–8× throughput improvement on multi-core systems

**Metrics**:
- `jobs_submitted`: Total jobs submitted
- `jobs_verified_ok`: Successfully verified
- `jobs_failed`: Invalid signatures
- `jobs_dropped`: Queue full

### Planned DAG Mempool and ZK L2 for Scaling

**DAG mempool** (roadmap T161+):
- **Parallel transaction ordering**: Sharded by sender, conflict-free parallelization
- **Throughput**: 10,000+ TPS (limited by execution, not consensus)
- **Consensus impact**: HotStuff commits DAG vertices (posets of transactions), not linearized blocks

**ZK L2 rollups** (roadmap T181+):
- **Off-chain execution**: Sequencer processes transactions, generates proofs
- **On-chain verification**: QBIND validators verify ZK proofs (recursive SNARKs)
- **Throughput**: 100,000+ TPS off-chain, ~1,000 proofs/sec on-chain
- **Settlement**: State roots committed to QBIND; fraud proofs or validity proofs

**Scaling path**:
1. **Current** (T148): HotStuff baseline (~500–2,000 TPS)
2. **Near-term** (T161+): DAG mempool (~10,000 TPS)
3. **Mid-term** (T181+): ZK L2 (~100,000+ TPS)

---

## Design Principles

### 1. PQ-Only Core, Classical Crypto Only at Edges (Bridges)

**Core invariant**: All consensus, networking, and validator cryptography uses post-quantum primitives (ML-DSA, ML-KEM, ChaCha20-Poly1305).

**Classical crypto permitted only**:
- Bridge contracts (Ethereum interop via ECDSA/BLS signatures)
- User wallets (if user chooses classical keys for convenience, but not validators)
- Historical data (existing blockchain integrations)

**Enforcement**:
- Code review: All signing/verification in consensus/networking must use suite registry
- Suite catalog: Only PQ suites registered (IDs 100–102)
- Tests: No `secp256k1`, `ed25519`, or `rsa` imports in core crates

### 2. All Signing Goes Through ValidatorSigner

**Constraint**: Consensus code must not directly access `ValidatorSigningKey`.

**Benefits**:
- Enables HSM/remote signer without harness changes
- Testable with mock signers
- Prevents accidental key exposure (no direct key access in logs/metrics)

**Enforcement**:
- ValidatorSigner trait is the sole interface for signing proposals, votes, timeouts
- LocalKeySigner and RemoteKeySigner implement trait
- Code review: No direct `key.sign(...)` calls in consensus layer

### 3. All On-Disk Keys Go Through Keystore + Identity Checks

**Constraint**: No direct file reads of key material outside keystore implementations.

**Benefits**:
- Centralized key loading logic (easier to audit)
- Identity self-check prevents operator error
- Future: Keystore can integrate with secret management (Vault, KMS)

**Enforcement**:
- `ValidatorKeystore` trait is the sole interface for loading signing keys
- `FsValidatorKeystore` is the default implementation
- Startup: Identity self-check validates derived PK = expected PK

### 4. Cryptographic Parameters and Suites Must Be Upgradeable with Explicit Governance Rules

**Constraint**: Hardcoded algorithms are prohibited; all crypto dispatched via suite_id.

**Benefits**:
- Algorithm agility: Migrate from ML-DSA-44 → ML-DSA-87 → future NIST rounds
- Cryptanalysis response: Deprecate broken suites, activate replacements
- Future-proof: No consensus harness changes needed for new suites

**Governance** (future):
- On-chain voting: Propose new suite → validators vote → activate at block height H
- Phased rollout: Test on devnet → canary → mainnet
- Deprecation: Grace period (both old and new suites valid) → hard cutoff

**Enforcement**:
- Suite catalog validates all suites (no duplicate IDs, ≥128-bit security)
- Backend registry maps suite_id → verifier
- Consensus code dispatches via `CryptoConsensusVerifier::verify(suite_id, ...)`

---

## Summary

QBIND is a **pure post-quantum BFT blockchain** with:
- **ML-DSA-44** signatures (2,420-byte, ~0.5 ms verify)
- **ML-KEM-768** KEM (KEMTLS networking, no TLS)
- **HotStuff consensus** (3-phase, deterministic finality, timeout/view-change)
- **ValidatorSigner abstraction** (local keys, future HSM/remote signer)
- **Multi-threaded verification** (4–8× throughput gain)
- **Suite-based agility** (governance-driven algorithm upgrades)

**Current status** (T148):
- Consensus core production-ready (500–2,000 TPS baseline)
- Networking functional (KEMTLS handshake, AEAD sessions)
- Key management abstracted (keystore, identity self-check)
- Verification parallelized (T147)

**Roadmap**:
- **T149**: Remote/HSM signer
- **T150–T160**: EVM execution, mempool
- **T161–T180**: DAG mempool, on-chain key registry
- **T181+**: ZK L2, staking/slashing, bridges

QBIND is the **first pure PQ L1** designed for quantum-resistant DeFi, tokenization, and high-throughput applications.

---

**Document Version**: 1.0  
**Last Updated**: 2026-01-26  
**Status**: Canonical PQC context for QBIND (post-T148)