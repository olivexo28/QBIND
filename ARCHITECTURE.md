# QBIND Architectural Map

**Version**: Code-Faithful Analysis (2026-02-11)  
**Status**: Technical Whitepaper Reference

This document provides a complete, code-faithful architectural map of the QBIND repository. It describes only what exists in the code today; incomplete or stubbed components are explicitly marked.

---

## 1) Workspace Overview

### Repo Root Purpose

QBIND is a post-quantum blockchain protocol implementation in Rust, designed for high-security consensus and cryptographic agility. The codebase provides a modular, layered architecture spanning from low-level cryptographic primitives through consensus protocols to a complete node binary. The protocol uses post-quantum cryptographic algorithms (ML-KEM-768 for key encapsulation, ML-DSA-44 for signatures) and implements HotStuff-style BFT consensus with support for EVM-compatible smart contract execution.

### Workspace Members

| Crate | Responsibility |
|-------|---------------|
| `qbind-types` | Core on-chain state types, domain separation, and primitive type definitions (AccountId, ValidatorState, SuiteRegistry, governance types) |
| `qbind-wire` | Wire-format encoding/decoding for consensus messages, transactions, network handshake, and governance data |
| `qbind-hash` | Domain-separated SHA3-256 hashing for consensus votes, transactions, and network certificates |
| `qbind-crypto` | Cryptographic primitives: ML-KEM-768 (KEM), ML-DSA-44 (signatures), ChaCha20-Poly1305 (AEAD), PBKDF2 (KDF), signature suites catalog |
| `qbind-serde` | State serialization/deserialization codec for on-chain account data |
| `qbind-ledger` | Account state management, transaction execution engine, monetary policy, gas accounting, slashing ledger, state pruning/snapshots |
| `qbind-system` | Built-in system programs: Keyset, Validator, and Governance programs |
| `qbind-runtime` | Transaction/block execution layer with system programs and EVM (Revm) integration |
| `qbind-genesis` | Genesis state initialization (suite registry, param registry, safety council) |
| `qbind-consensus` | HotStuff-style BFT consensus verification, QC validation, vote accumulation, pacemaker, slashing infrastructure, key rotation |
| `qbind-node` | Node binary entrypoint, P2P networking, mempool, DAG mempool, storage, metrics, keystore, peer management |
| `qbind-net` | KEMTLS handshake engine, AEAD session management, post-handshake transport framing |
| `qbind-remote-signer` | Remote signing daemon for HSM/airgapped key management |
| `qbind-gov` | Governance envelope toolchain: upgrade envelope parsing, multi-sig verification, council keyset management |

---

## 2) Node Architecture (Code-Mapped)

### Binaries and Entrypoints

| Binary | Entrypoint | Description |
|--------|------------|-------------|
| `qbind-node` | `crates/qbind-node/src/main.rs` | Main validator node binary with P2P and LocalMesh modes |
| `qbind-remote-signer` | `crates/qbind-remote-signer/src/main.rs` | Remote signing daemon for consensus key isolation |
| `qbind-envelope` | `crates/qbind-gov/src/bin/` | CLI tool for upgrade envelope inspection and verification |

### Main Runtime Services

| Service | Module Path | Description |
|---------|-------------|-------------|
| CLI/Config | `qbind-node/src/cli.rs`, `node_config.rs` | Argument parsing, environment detection (DevNet/TestNet/MainNet), configuration profiles |
| P2P Networking | `qbind-node/src/p2p*.rs`, `async_peer_manager.rs` | TCP transport, KEMTLS secure channels, peer discovery/liveness |
| Consensus Engine | `qbind-consensus/src/basic_hotstuff_engine.rs`, `hotstuff_state_engine.rs` | HotStuff-style consensus with QC formation and 3-chain commit |
| Mempool | `qbind-node/src/mempool.rs`, `dag_mempool.rs` | FIFO and DAG-based transaction pools with signature verification |
| Storage | `qbind-node/src/storage.rs` | RocksDB-backed persistence for blocks, QCs, epochs |
| Execution | `qbind-runtime/src/lib.rs`, `revm_engine.rs` | System program execution and EVM transaction processing |
| Metrics/Observability | `qbind-node/src/metrics.rs`, `metrics_http.rs` | Atomic counter metrics with HTTP exposure |
| Keystore | `qbind-node/src/keystore.rs` | Local filesystem keystore with optional encryption |

### Dependency Graph (Text)

```
qbind-node
├── qbind-consensus -> qbind-wire -> qbind-types
│                   -> qbind-hash
│                   -> qbind-crypto -> qbind-types
├── qbind-runtime -> qbind-ledger -> qbind-types
│                 -> qbind-system -> qbind-ledger
│                 -> revm (optional, feature "evm")
├── qbind-net -> qbind-wire
│            -> qbind-crypto
│            -> qbind-hash
├── qbind-genesis -> qbind-ledger
│                 -> qbind-system
│                 -> qbind-types
└── rocksdb, tokio, crossbeam-channel
```

---

## 3) Networking Stack

### Handshake Design (KEMTLS-PDK)

**Implementation**: `crates/qbind-net/src/handshake.rs`

The networking layer implements a post-quantum KEMTLS-PDK (Pre-Distributed Key) handshake:

#### Message Types

| Message | Type ID | Direction | Purpose |
|---------|---------|-----------|---------|
| `ClientInit` | - | C → S | KEM ciphertext, client_random, validator_id, suite negotiation |
| `ServerCookie` | 0x02 | S → C | **Incomplete** - DoS protection cookie (stubbed) |
| `ServerAccept` | - | S → C | Server_random, delegation certificate, flags |

#### State Machine

1. **Client starts**: Generates ephemeral randomness, performs KEM encapsulation to server's public key
2. **Server receives ClientInit**: Validates suite compatibility, decapsulates KEM, derives session keys
3. **Session established**: Both parties derive symmetric keys via HKDF-SHA3

#### Transcript/Hash Binding

```
transcript_hash = SHA3-256("QBIND:KEMTLS" || client_random || server_random || kem_ct)
```

The transcript hash is fed into HKDF key derivation, binding the session keys to the handshake messages.

#### Delegation Certificate Verification

**Path**: `crates/qbind-net/src/handshake.rs::verify_delegation_cert()`

- NetworkDelegationCert is verified against a trusted root public key
- Uses `qbind_hash::net::network_delegation_cert_digest()` for the signed message
- Signature verified using the suite indicated by `cert.sig_suite_id`

### Key Schedule + AEAD Session Handling

**Implementation**: `crates/qbind-net/src/keys.rs`, `session.rs`

#### Key Derivation

```
PRK = HKDF-Extract(salt = "QBIND:KDF" || transcript_hash, ikm = shared_secret)
session_id = HKDF-Expand-Label(PRK, "QBIND:session-id", [kem_suite_id, aead_suite_id], 3)
k_c2s = HKDF-Expand-Label(PRK, "QBIND:k_c2s", info, key_len)
k_s2c = HKDF-Expand-Label(PRK, "QBIND:k_s2c", info, key_len)
```

#### Nonce Construction

**Path**: `crates/qbind-net/src/session.rs::make_nonce()`

```
nonce[12] = flag(1 byte) || session_id(3 bytes) || counter(8 bytes, big-endian)
```

- `flag = 0x01` for client-to-server direction
- `flag = 0x02` for server-to-client direction
- Counter starts at 0, increments monotonically per direction

#### Nonce Overflow Check

**Path**: `crates/qbind-net/src/session.rs::next_nonce()`

```rust
if counter == u64::MAX {
    return Err(NetError::NonceOverflow);
}
self.counter = self.counter.wrapping_add(1);
```

The session explicitly fails if the counter reaches `u64::MAX`, preventing nonce reuse.

### Post-Handshake Transport Framing

**Implementation**: `crates/qbind-net/src/transport.rs`, `framed_io.rs`

#### Frame Format

```
msg_type: u8 (0x01 = APP_MESSAGE)
len: u32 (big-endian, ciphertext length)
ciphertext: [u8; len] (AEAD encrypted payload)
```

#### AAD (Associated Authenticated Data)

```
APP_FRAME_AAD = b"QBIND:net:app-frame"
```

### Replay/Downgrade/Identity Binding Defenses

| Defense | Status | Location |
|---------|--------|----------|
| Nonce monotonicity | ✅ Implemented | `session.rs::next_nonce()` |
| Nonce overflow check | ✅ Implemented | Returns `NetError::NonceOverflow` at `u64::MAX` |
| Suite negotiation | ✅ Implemented | Client proposes, server rejects mismatches |
| Downgrade prevention | ⚠️ Partial | Single suite per connection; no fallback logic |
| Identity binding | ✅ Implemented | Delegation cert verified against root PK |
| Replay (session level) | ✅ Implemented | Unique session_id + monotonic counter |
| DoS cookie | ❌ Incomplete | `cookie` field exists but not enforced |

---

## 4) Cryptography & Key Management

### Key Types / Roles Present in Code

| Key Type | Algorithm | Size | Role | Module |
|----------|-----------|------|------|--------|
| Validator Signing Key | ML-DSA-44 | 2560 bytes (SK), 1312 bytes (PK), 2420 bytes (sig) | Consensus vote/proposal signing | `qbind-crypto/src/ml_dsa44.rs` |
| Network KEM Key | ML-KEM-768 | 2400 bytes (SK), 1184 bytes (PK), 1088 bytes (CT) | KEMTLS key encapsulation | `qbind-crypto/src/ml_kem768.rs` |
| AEAD Session Key | ChaCha20-Poly1305 | 32 bytes | Post-handshake encryption | `qbind-crypto/src/chacha20poly1305.rs` |
| Network Delegation Key | ML-DSA-44 | Same as validator | Signs NetworkDelegationCert | `qbind-net/src/handshake.rs` |
| Council Member Key | ML-DSA-44 | Same as validator | Governance envelope signing | `qbind-gov/src/verify.rs` |

### Keystore Format and Loading Rules

**Implementation**: `crates/qbind-node/src/keystore.rs`

#### Plaintext Format (DevNet/Testing)

```json
{
  "suite_id": 100,
  "private_key_hex": "<lowercase hex bytes>"
}
```

- File location: `{keystore_root}/{entry_id}.json`
- `suite_id` must be 100 (ML-DSA-44, SUITE_PQ_RESERVED_1)

#### Encrypted Format v1 (Production)

- File extension: `.enc`
- Encryption: ChaCha20-Poly1305 AEAD
- Key derivation: PBKDF2 with configurable iterations (default: 100,000)
- Passphrase source: Environment variable (e.g., `QBIND_KEYSTORE_PASSPHRASE`)

#### Loading Rules

1. KeystoreBackend enum selects `PlainFs` or `EncryptedFsV1`
2. `FsValidatorKeystore::load_signing_key()` reads and parses the file
3. Returns `ValidatorSigningKey` wrapped with `ZeroizeOnDrop`

### Signature Verification Flow and Metrics Hooks

**Path**: `qbind-consensus/src/crypto_verifier.rs`

#### Flow

1. `MultiSuiteCryptoVerifier::verify()` receives (validator_id, pk, preimage, signature)
2. Looks up appropriate `ConsensusSigVerifier` by suite_id from registry
3. Calls backend's `verify_vote()` or `verify_proposal()`
4. Records metrics via `ConsensusSigMetrics` (success/failure counts per suite)

#### Metrics (if present)

- `signature_verify_total{suite_id, result=ok|err}`
- `signature_verify_latency_seconds{suite_id}`

**Path**: `qbind-consensus/src/crypto_verifier.rs::ConsensusSigMetrics`

---

## 5) Consensus & Finality

### Consensus Algorithm Structure

**Implementation**: `crates/qbind-consensus/src/basic_hotstuff_engine.rs`, `hotstuff_state_engine.rs`

QBIND implements a **HotStuff-style 3-chain commit rule** with the following characteristics:

#### Core Components

| Component | Path | Description |
|-----------|------|-------------|
| `BasicHotStuffEngine` | `basic_hotstuff_engine.rs` | Concrete engine with static round-robin leader election |
| `HotStuffStateEngine` | `hotstuff_state_engine.rs` | QC formation, vote accumulation, commit tracking |
| `VoteAccumulator` | `vote_accumulator.rs` | Collects votes, forms QCs when threshold met |
| `TimeoutPacemaker` | `pacemaker.rs` | View advancement and timeout handling |

#### Leader Election

```rust
leader_index = view % num_validators
```

Static round-robin scheduling based on view number.

### Block Proposal / Vote / Commit Flow

#### Proposal Phase

1. Leader identified by `view % n`
2. Leader calls `create_proposal()` with justify QC from previous round
3. Proposal broadcast to all validators

#### Vote Phase

1. Validators receive proposal
2. `hotstuff_decide_and_maybe_record_vote()` checks:
   - Structural validity (`verify_block_proposal`)
   - HotStuff safety (`can_vote_hotstuff`)
   - Justify QC height >= locked height
3. If valid, validator signs and broadcasts vote

#### QC Formation

1. `VoteAccumulator::insert()` collects votes
2. When voting power >= `qc_threshold` (typically 2f+1), QC formed
3. QC contains bitmap + aggregated signatures

#### Commit Rule (3-chain)

```
B0 ← B1 ← B2 ← B3
      ↑    ↑    ↑
    lock  pre  commit
          commit
```

- **Lock**: When QC for B1 seen, lock on B0
- **Prepare**: When QC for B2 seen, B1 is prepare-committed
- **Commit**: When QC for B3 seen, B0 is fully committed

**Path**: `HotStuffStateEngine::process_qc()`, `update_lock_and_commit()`

### Safety Assumptions and Failure Modes

#### Safety Assumptions (from code/comments)

1. **Honest majority**: At least 2f+1 honest validators (f = floor((n-1)/3))
2. **No double-signing**: `can_vote_hotstuff()` prevents voting twice at same (height, round)
3. **Lock safety**: Votes only accepted if justify_qc_height >= locked_height
4. **Monotonic views**: Height and round must be monotonically increasing

#### Failure Modes Mentioned

| Failure | Handling | Path |
|---------|----------|------|
| Stale height | Rejected with `ConsensusStateError::StaleHeight` | `hotstuff_state_engine.rs` |
| Stale round | Rejected with `ConsensusStateError::StaleRound` | `hotstuff_state_engine.rs` |
| Double vote | Rejected with `ConsensusStateError::DoubleVote` | `hotstuff_state_engine.rs` |
| Round regression | Rejected with `ConsensusStateError::RoundRegression` | `hotstuff_state_engine.rs` |
| Wrong epoch | Rejected with `ConsensusVerifyError::WrongEpoch` | `lib.rs` (consensus) |
| Insufficient quorum | `InsufficientVotingPower` error | `verify_quorum_certificate()` |

#### What Is NOT Implemented

- **Timeouts with view-change mechanics**: Commented as TODO in `driver.rs`
- **Equivocation handling**: Slashing infrastructure exists but penalty application is deferred (T229+)
- **Dynamic leader rotation**: Only static round-robin

---

## 6) State, Execution, and Storage

### Transaction Format Modules

**Path**: `crates/qbind-wire/src/tx.rs`

#### Transaction Structure

```
msg_type:      u8  (0x10)
version:       u8
chain_id:      u32
payer:         AccountId (32 bytes)
nonce:         u64
fee_limit:     u64
account_count: u16
accounts:      [TxAccountMeta; account_count]
program_id:    ProgramId (32 bytes)
call_data_len: u32
call_data:     [u8; call_data_len]
auth_count:    u16
auths:         [TxAuth; auth_count]
```

#### TxAccountMeta

```
account_id:  AccountId (32 bytes)
flags:       u8 (bit0=is_signer, bit1=is_writable)
access_hint: u8 (bit0=may_read, bit1=may_write)
reserved0:   [u8; 2]
```

#### TxAuth

```
account_index: u16
suite_id:      u8
reserved:      u8
sig_len:       u16
sig_bytes:     [u8; sig_len]
```

### State Representation

**Path**: `crates/qbind-ledger/src/`

#### Account Model

```rust
pub struct AccountHeader {
    pub owner: ProgramId,       // 32 bytes - program that owns this account
    pub lamports: u64,          // balance (Solana-style naming convention)
    pub is_executable: bool,    // whether account contains executable program
    pub rent_epoch: u64,        // rent tracking
    pub reserved: [u8; 8],      // reserved for future use
}

pub struct Account {
    pub id: AccountId,          // 32 bytes
    pub header: AccountHeader,  // nested header struct
    pub data: Vec<u8>,          // arbitrary program-owned data
}
```

**Path**: `qbind-ledger/src/account.rs`

> Note: The `lamports` field name follows Solana's naming convention and represents the account balance in the smallest unit.

#### EVM State (Feature-Gated)

```rust
pub struct EvmAccountState {
    pub nonce: u64,
    pub balance: U256,
    pub code_hash: H256,
    pub code: Vec<u8>,
    pub storage: HashMap<U256, U256>,
}
```

**Path**: `qbind-runtime/src/evm_types.rs`

### Storage Engine and Persistence Boundaries

**Path**: `crates/qbind-node/src/storage.rs`

#### Storage Backend

- **Engine**: RocksDB
- **Schema Version**: 1 (stored at `meta:schema_version`)

#### Key Layout

| Key Pattern | Value |
|-------------|-------|
| `b:<block_id>` | Serialized `BlockProposal` |
| `q:<block_id>` | Serialized `QuorumCertificate` |
| `meta:last_committed` | Block ID bytes |
| `meta:current_epoch` | u64 (big-endian) |
| `meta:schema_version` | u32 (big-endian) |

#### Schema Compatibility

```rust
pub fn ensure_compatible_schema(storage: &impl ConsensusStorage) -> Result<(), StorageError>
```

- Missing or version ≤ current: accepted
- Version > current: `StorageError::IncompatibleSchema`

#### Data Integrity (T119)

- `StorageError::Corruption` variant for checksum mismatches
- Indicates bit-rot, disk corruption, or tampering

---

## 7) Observability & Ops

### Logging Strategy

- Uses `eprintln!` for startup/shutdown messages with task prefixes (e.g., `[T175]`, `[T185]`)
- No structured logging framework observed (plain stderr)
- Key material is NEVER logged (enforced by custom Debug impls with `<redacted>`)

### Metrics (Counters, Histograms)

**Path**: `crates/qbind-node/src/metrics.rs`

#### Metric Categories

| Category | Metrics | Type |
|----------|---------|------|
| Network | `inbound_{vote,proposal,other}_total`, `outbound_{vote_send_to,vote_broadcast,proposal_broadcast}_total` | AtomicU64 counters |
| Channel Health | `outbound_dropped_total`, `inbound_channel_closed_total`, `outbound_queue_depth` | AtomicU64 |
| Priority-Based (T90.3) | `outbound_*_{critical,normal,low}`, `outbound_dropped_{critical,normal,low}` | AtomicU64 |
| spawn_blocking | `critical_wait_under_1ms`, `critical_wait_1ms_to_10ms`, `critical_wait_10ms_to_100ms`, `critical_wait_over_100ms` | AtomicU64 histograms |
| Peer Metrics (T90.4) | Per-peer inbound/outbound/disconnect counters | HashMap with RwLock |
| Consensus Progress (T127) | QC formed, votes observed, view changes, leader changes | Via trait callbacks |
| KEM Operations | `encaps_count`, `decaps_count`, latency buckets | AtomicU64 |

#### HTTP Metrics Server (T126)

**Path**: `crates/qbind-node/src/metrics_http.rs`

```rust
pub async fn spawn_metrics_http_server(config: MetricsHttpConfig) -> Result<(), MetricsHttpError>
```

- Listens on configurable address (env: `METRICS_HTTP_ADDR_ENV`)
- Exposes Prometheus-style metrics

### Config System and Environment Separation

**Path**: `crates/qbind-node/src/node_config.rs`

#### Environments

| Environment | Chain ID | Purpose |
|-------------|----------|---------|
| DevNet | 1 | Local development and testing |
| TestNet | 2 | Public test network |
| MainNet | 0 | Production network |

```rust
pub fn parse_environment(s: &str) -> Option<NetworkEnvironment>
```

Valid values: `"devnet"`, `"testnet"`, `"mainnet"`

#### Configuration Profiles

| Profile | Description |
|---------|-------------|
| DevNet | LocalMesh, no gas enforcement, plain keystore |
| TestNet Alpha | P2P networking, gas enabled, encrypted keystore |
| TestNet Beta | Height-based pruning, stricter validation |
| MainNet | All safety rails enforced (T185) |

#### MainNet Safety Rails (T185)

**Path**: `qbind-node/src/node_config.rs::validate_mainnet_invariants()`

Required for MainNet profile:
- Gas enforcement enabled
- P2P networking enabled
- Data directory specified
- Encrypted keystore or HSM signer
- Genesis hash verified

---

## 8) Roadmap Extracted from Code

The following items are explicitly indicated by TODOs, feature flags, or stub modules:

### Feature Flags

| Flag | Path | Description |
|------|------|-------------|
| `async-peer-manager` | `qbind-node/Cargo.toml` | Enables fully async networking path (T90.1); when disabled, uses blocking + spawn_blocking |
| `hsm-pkcs11` | `qbind-node/Cargo.toml` | Enables HSM/PKCS#11 signer backend (T211) |
| `evm` | `qbind-runtime/Cargo.toml` | Enables Revm-based EVM execution (default: enabled) |

### Explicit TODOs

| Location | Description |
|----------|-------------|
| `qbind-ledger/src/monetary_state.rs:1367` | "TODO(T201): Add stricter error handling in production" |
| `qbind-consensus/src/driver.rs:619` | "TODO: Delegate to underlying engine for actual vote processing" |
| `qbind-consensus/src/driver.rs:649` | "TODO: Delegate to underlying engine for actual proposal processing" |
| `qbind-consensus/src/driver.rs:665` | "TODO: Add timer-based logic for view changes, timeouts" |
| `qbind-node/src/p2p_tcp.rs:406,440` | "TODO: Extract NodeId from KEMTLS cert" |
| `qbind-node/src/node_config.rs:5128` | "TODO(future): Add stricter rules for validators vs non-validators" |

### Incomplete/Stub Components

| Component | Path | Status |
|-----------|------|--------|
| DoS Cookie Protection | `qbind-net/src/handshake.rs` | Cookie field exists in `ClientInit`, but "no cookie for T25; DoS cookies can be added in later tasks" |
| Slashing Penalty Application | `qbind-consensus/src/slashing/mod.rs` | T228 implements infrastructure skeleton; actual stake burning/jailing deferred to T229+ |
| LocalMesh Node Operation | `qbind-node/src/main.rs:111-123` | LocalMesh mode is a stub: "LocalMesh node startup is a stub in T175" |
| Remote Signer KEMTLS | `qbind-remote-signer/src/main.rs:587` | "Full KEMTLS server requires proper key configuration" - handshake not fully wired |
| Timeouts/View-Change | `qbind-consensus/src/driver.rs` | BasicHotStuffEngine "does NOT implement: Timeouts or view-change mechanics" |
| Equivocation Handling | `qbind-consensus/src/basic_hotstuff_engine.rs` | Explicitly listed as NOT implemented |
| Batch Verification | `qbind-crypto/src/ml_dsa44.rs` | Future work: "Batch verification (when the underlying crate supports it)" |
| Epoch-Based Pruning | `qbind-node/src/node_config.rs` | `StateRetentionMode::Epochs` commented as "can be added in the future" |

---

## Security Summary

### Implemented Security Controls

| Control | Status | Location |
|---------|--------|----------|
| Post-quantum KEM (ML-KEM-768) | ✅ | `qbind-crypto/src/ml_kem768.rs` |
| Post-quantum signatures (ML-DSA-44) | ✅ | `qbind-crypto/src/ml_dsa44.rs` |
| Key zeroization (ZeroizeOnDrop) | ✅ | All key wrappers in `qbind-net/src/keys.rs`, `qbind-crypto/src/ml_dsa44.rs` |
| Nonce monotonicity | ✅ | `qbind-net/src/session.rs` |
| Nonce overflow detection | ✅ | Returns error at u64::MAX |
| AEAD with AAD | ✅ | Domain-separated AAD for app frames |
| Double-vote prevention | ✅ | HotStuffState tracks last_voted |
| Transcript binding | ✅ | Handshake transcript hashed into key derivation |
| Encrypted keystore | ✅ | PBKDF2 + ChaCha20-Poly1305 |
| Identity binding | ✅ | Delegation cert verification |
| Schema version check | ✅ | Prevents forward-incompatible DB opens |

### Security Gaps / Future Work

| Gap | Risk | Mitigation Path |
|-----|------|-----------------|
| No DoS cookie | Connection exhaustion | Implement ServerCookie flow |
| No timeout/view-change | Liveness under network partition | Complete T-series tasks |
| Slashing not enforced | No economic penalty for misbehavior | T229+ implementation |
| HSM optional | Key exposure on validator host | Enable `hsm-pkcs11` in production |

---

*This document was generated from direct code inspection of the QBIND repository. All statements reflect the implemented codebase; no features have been invented or assumed beyond what exists in code.*
