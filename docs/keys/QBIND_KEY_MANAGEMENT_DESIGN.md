# QBIND Key Management & Signer Architecture v1 Design

**Task**: T209  
**Status**: Design Specification  
**Date**: 2026-02-06

---

## Table of Contents

1. [Objectives & Threat Model](#1-objectives--threat-model)
2. [Key Roles & Scopes](#2-key-roles--scopes)
3. [Signer Modes & Backends](#3-signer-modes--backends)
4. [HSM & Remote Signer Architecture](#4-hsm--remote-signer-architecture)
5. [Key Rotation & Compromise Handling](#5-key-rotation--compromise-handling)
6. [Network Profiles & Requirements](#6-network-profiles--requirements)
7. [Implementation Roadmap (T210+)](#7-implementation-roadmap-t210)
8. [Related Documents](#8-related-documents)

---

## 1. Objectives & Threat Model

### 1.1 Goals

The QBIND key management and signer architecture is designed around the following objectives:

| Goal | Description |
| :--- | :--- |
| **Secure Validator Keys** | Protect consensus, network, and governance keys from exfiltration and misuse. |
| **PQC-Only Operation** | All signing operations use ML-DSA-44 (SUITE_PQ_RESERVED_1); no classical cryptography permitted. |
| **Clear Mode Separation** | Test/development signers (loopback) are explicitly forbidden on MainNet. |
| **HSM Readiness** | Production validators should use HSM-backed signing or hardened encrypted keystores. |
| **Operational Clarity** | Key rotation, backup, and recovery procedures are well-defined and auditable. |

### 1.2 Threat Model

The key management system must defend against the following threat categories:

#### 1.2.1 Key Exfiltration

| Threat | Description | Severity |
| :--- | :--- | :--- |
| **Disk-level exfiltration** | Attacker gains read access to unencrypted key files | Critical |
| **Memory extraction** | Key material leaked via memory dumps or side channels | High |
| **Backup compromise** | Encrypted backups decrypted due to weak passphrase | High |
| **Insider threat** | Operator with legitimate access exports keys | High |

**Mitigations**:
- EncryptedFsV1 keystore with PBKDF2-derived encryption key
- HSM for MainNet validators (private key never exported)
- Memory zeroization on key unload (future enhancement)

#### 1.2.2 Host Compromise

| Threat | Description | Severity |
| :--- | :--- | :--- |
| **Root access** | Attacker gains root on validator host | Critical |
| **Malware injection** | Signing requests intercepted or manipulated | Critical |
| **Container escape** | Isolation boundaries breached | High |

**Mitigations**:
- Remote signer architecture (key material on separate hardened host/HSM)
- KEMTLS channel between node and remote signer
- Host hardening guidelines for MainNet operators

#### 1.2.3 Misconfiguration

| Threat | Description | Severity |
| :--- | :--- | :--- |
| **Loopback signer on MainNet** | Test signer used in production exposes keys | Critical |
| **Weak passphrase** | EncryptedFsV1 keystore with guessable passphrase | High |
| **Missing file permissions** | Key files readable by non-validator processes | High |
| **Wrong network profile** | DevNet config accidentally used on MainNet | High |

**Mitigations**:
- `validate_mainnet_invariants()` rejects loopback signer mode
- Passphrase strength validation (future enhancement)
- File permission checks on keystore load
- Network profile validation at startup

#### 1.2.4 HSM Failures

| Threat | Description | Severity |
| :--- | :--- | :--- |
| **HSM hardware failure** | Signing operations fail; validator goes offline | High |
| **HSM misconfiguration** | Wrong key slot or PIN causes signing failures | High |
| **HSM vendor lock-in** | Migration to new HSM vendor is difficult | Medium |

**Mitigations**:
- HSM redundancy recommendations for MainNet operators
- Standardized PKCS#11 interface (vendor-agnostic)
- Key backup procedures via HSM escrow mechanisms

### 1.3 Security Principles

The following principles guide the key management architecture:

1. **Principle of Least Privilege**: Signing keys are accessible only to the signing component; the consensus engine never holds raw key material.

2. **Defense in Depth**: Multiple layers protect keys (encryption, isolation, HSM).

3. **Fail Secure**: If key access fails, the node stops rather than proceeding unsafely.

4. **Auditability**: All signing operations are loggable (without exposing key material).

5. **No Classical Crypto**: All cryptographic operations use PQC primitives (ML-DSA-44 for signatures, ML-KEM-768 for key exchange).

---

## 2. Key Roles & Scopes

### 2.1 Key Role Enumeration

QBIND validators manage multiple key roles, each with distinct purposes and security requirements:

| Key Role | Purpose | PQC Suite | HSM Requirement (MainNet) |
| :--- | :--- | :--- | :--- |
| **Consensus Key** | Sign proposals, votes, and timeout messages | ML-DSA-44 (suite_id=100) | **Strongly Recommended** |
| **P2P Identity Key** | KEMTLS handshake for P2P connections | ML-KEM-768 | Recommended |
| **Batch Signing Key** | Sign DAG batches and availability acks | ML-DSA-44 (suite_id=100) | Strongly Recommended |
| **Governance Key** (future) | Sign governance proposals and votes | ML-DSA-44 (suite_id=100) | Optional |
| **Operational Key** (future) | Node configuration and admin operations | ML-DSA-44 (suite_id=100) | Optional |

### 2.2 Consensus Key

The **consensus key** is the most critical key for validator operation. It signs:

- **Proposals**: Block proposals as HotStuff leader
- **Votes**: Votes on proposals from other validators
- **Timeouts**: Timeout messages for view changes

**Security Requirements**:
- Private key MUST NOT be stored in plaintext on MainNet
- HSM strongly recommended for MainNet validators
- EncryptedFsV1 acceptable with hardened host and strong passphrase
- Loopback signer FORBIDDEN on MainNet

**Key Derivation**:
- Generated via ML-DSA-44 key generation algorithm
- Suite ID: 100 (SUITE_PQ_RESERVED_1)
- Public key registered in genesis validator set

**Signing Context**:
```
Domain-separated preimages:
- Proposals: QBIND_PROPOSAL_V1 || chain_id || view || block_hash || ...
- Votes:     QBIND_VOTE_V1 || chain_id || view || block_hash || voter_id
- Timeouts:  QBIND_TIMEOUT_V1 || chain_id || view || high_qc_hash || voter_id
```

### 2.3 P2P Identity Key

The **P2P identity key** establishes secure channels between validators using KEMTLS:

- **Handshake**: ML-KEM-768 key encapsulation during KEMTLS
- **Authentication**: Validator identity proven via encapsulation to known public key

**Security Requirements**:
- Private key stored in keystore (EncryptedFsV1 or HSM)
- Compromise allows impersonation of validator P2P identity
- Rotation requires coordinated peer list updates

**Note**: P2P identity key is distinct from consensus key to allow independent rotation and compromise response.

### 2.4 Batch Signing Key

The **batch signing key** signs DAG mempool batches and availability acknowledgments:

- **Batches**: Validators sign batches they author
- **BatchAcks**: Validators sign acknowledgments of received batches

**Security Requirements**:
- Same security level as consensus key (signing critical consensus data)
- May share the same physical key as consensus key (implementation choice)
- HSM strongly recommended for MainNet

**Current Implementation**: The batch signing key is the same as the consensus key (single `ValidatorSigner` instance).

### 2.5 Future Key Roles

The following key roles are planned for future versions:

| Key Role | Purpose | Target Phase |
| :--- | :--- | :--- |
| **Governance Key** | Sign on-chain governance proposals and votes | MainNet v0.x |
| **Operational Key** | Sign node configuration changes and admin commands | MainNet v1+ |
| **Withdrawal Key** | Sign stake withdrawal requests (cold storage) | MainNet v1+ |

These keys may have different security requirements (e.g., withdrawal key should be air-gapped cold storage).

---

## 3. Signer Modes & Backends

### 3.1 Signer Mode Overview

QBIND supports multiple signer modes, each suitable for different deployment scenarios:

| Mode | Description | Key Location | Allowed Networks |
| :--- | :--- | :--- | :--- |
| **LoopbackTesting** | In-process test signer | In-memory | DevNet, TestNet Alpha |
| **EncryptedFsV1** | Encrypted keystore files | Local disk (encrypted) | DevNet, TestNet, MainNet |
| **RemoteSigner** | Separate signer process/service | Remote process/machine | TestNet Beta, MainNet |
| **HsmPkcs11** (future) | Hardware Security Module | HSM device | MainNet |

### 3.2 LoopbackTesting Mode

**Description**: The loopback signer (`LoopbackSignerTransport`) exercises the remote signer protocol shape while using `LocalKeySigner` for actual signing. The private key remains in the same process as the consensus harness.

**Use Cases**:
- Unit and integration tests
- Single-machine development
- DevNet cluster harness

**Key Location**: In-memory (loaded from keystore at startup)

**Security Level**: Low (key material in same process as consensus)

**Network Restrictions**:

| Network | Allowed | Rationale |
| :--- | :--- | :--- |
| DevNet | ✅ Yes | Testing network, no real value |
| TestNet Alpha | ✅ Yes | Early testing, opt-in |
| TestNet Beta | ⚠️ Discouraged | Beta validators should use EncryptedFsV1 |
| MainNet | ❌ **FORBIDDEN** | `validate_mainnet_invariants()` rejects |

**Implementation Reference**: `qbind-node/src/remote_signer.rs` → `LoopbackSignerTransport`

### 3.3 EncryptedFsV1 Mode

**Description**: The encrypted filesystem keystore (`EncryptedFsV1`) stores private keys encrypted with a passphrase-derived key using AEAD.

**Use Cases**:
- Production validators without HSM
- TestNet deployments
- Development with persistent keys

**Key Location**: Local disk at `{keystore_root}/{entry_id}.enc`

**Encryption Details**:
- KDF: PBKDF2 (iterations configurable, default: 600,000)
- Cipher: ChaCha20-Poly1305 AEAD
- Salt: Random per-key (stored in file)

**Security Level**: Medium-High (depends on passphrase strength and host hardening)

**Network Restrictions**:

| Network | Allowed | Rationale |
| :--- | :--- | :--- |
| DevNet | ✅ Yes | Convenient for persistent dev keys |
| TestNet Alpha | ✅ Yes | Acceptable for Alpha testing |
| TestNet Beta | ✅ Yes | Recommended for Beta validators |
| MainNet | ✅ Yes (with conditions) | Acceptable if host is hardened; HSM preferred |

**MainNet Conditions for EncryptedFsV1**:
1. Host must be hardened (minimal attack surface, firewalled)
2. Passphrase must be strong (>= 20 characters, high entropy)
3. Keystore file permissions must be restrictive (0600)
4. Regular security audits of host configuration

**Implementation Reference**: `qbind-node/src/keystore.rs` → `KeystoreBackend::EncryptedFsV1`

### 3.4 RemoteSigner Mode

**Description**: The remote signer mode separates the signing component from the consensus node. The node communicates with a separate signer process/service over a secure channel.

**Use Cases**:
- Air-gapped signing machines
- HSM-backed signer services
- Multi-tenant validator operations

**Key Location**: Remote process/machine (never on consensus node)

**Protocol**:
```
┌─────────────┐         KEMTLS          ┌──────────────┐
│  Consensus  │ ◄──────────────────────►│   Remote     │
│    Node     │   RemoteSignRequest     │   Signer     │
│             │   RemoteSignResponse    │   (+ HSM)    │
└─────────────┘                         └──────────────┘
```

**Security Level**: High (key material isolated from consensus node)

**Network Restrictions**:

| Network | Allowed | Rationale |
| :--- | :--- | :--- |
| DevNet | ⚠️ Overkill | Not needed for dev, but allowed |
| TestNet Alpha | ⚠️ Optional | Not needed for Alpha |
| TestNet Beta | ✅ Recommended | Good practice for Beta |
| MainNet | ✅ **Strongly Recommended** | Production-grade isolation |

**Operational Considerations**:
- Remote signer must be highly available (validator offline if signer unavailable)
- KEMTLS channel authenticated by validator's P2P identity key
- Signing latency added by network round-trip (typically <10ms local network)

**Implementation Reference**: `qbind-node/src/remote_signer.rs` → `RemoteSignerTransport` trait

### 3.5 HsmPkcs11 Mode (Implemented – T211)

**Description**: Hardware Security Module integration via the PKCS#11 standard interface. The private key is generated and stored inside the HSM; signing operations are performed by the HSM.

**Use Cases**:
- Enterprise-grade MainNet validators
- Regulatory compliance requirements
- Maximum key protection

**Key Location**: Inside HSM device (never exported)

**HSM Interface**:
```
┌─────────────┐      PKCS#11 API       ┌──────────────┐
│  QBIND      │ ◄─────────────────────►│     HSM      │
│  Node       │   C_Sign(key_handle,   │   Device     │
│             │         preimage)      │              │
└─────────────┘                        └──────────────┘
```

**Security Level**: Very High (key material never leaves HSM)

**Supported HSMs**:
- AWS CloudHSM
- Azure Dedicated HSM
- Thales Luna Network HSM
- Yubico YubiHSM 2
- Software HSM (SoftHSM) for testing

**Network Restrictions**:

| Network | Allowed | Rationale |
| :--- | :--- | :--- |
| DevNet | ⚠️ Overkill | Use SoftHSM for testing |
| TestNet Alpha | ⚠️ Optional | Not needed for Alpha |
| TestNet Beta | ✅ Encouraged | Good practice to test HSM flow |
| MainNet | ✅ **Strongly Recommended** | Highest security for production |

**Implementation Status**: Implemented in T211; production-ready for SoftHSM and vendor HSMs.

**Implementation Reference**: `qbind-node/src/hsm_pkcs11.rs` → `HsmPkcs11Signer`, feature flag `hsm-pkcs11`

**Example `hsm.toml` Configuration**:

```toml
# PKCS#11 HSM configuration for QBIND validator
library_path = "/usr/lib/softhsm/libsofthsm2.so"
token_label  = "qbind-validator"
key_label    = "qbind-consensus-42"
pin_env_var  = "QBIND_HSM_PIN"
# Optional: override the signing mechanism (default suitable for ML-DSA-44)
# mechanism = "vendor-ml-dsa-44"
```

**Example SoftHSM Environment Setup**:

```bash
# Install SoftHSM2
sudo apt-get install -y softhsm2

# Initialize a token
softhsm2-util --init-token --slot 0 \
    --label "qbind-validator" \
    --pin 1234 --so-pin 5678

# Set the PIN environment variable (never store PIN in config files)
export QBIND_HSM_PIN=1234

# Run the node with HSM signer
qbind-node --signer-mode hsm-pkcs11 --hsm-config-path /etc/qbind/hsm.toml
```

**Operational Caveats**:

- **Fail-closed on HSM failure**: If the HSM becomes unavailable, the node will NOT continue as a validator. Signing errors are fatal for consensus participation.
- **PIN management**: The HSM PIN is read from an environment variable at startup. Ensure the env var is set before starting the node. The PIN is never stored in config files or logs.
- **HSM health monitoring**: Monitor `qbind_hsm_sign_error_total` and `qbind_hsm_sign_last_latency_ms` metrics. Rising error counts or latency spikes indicate HSM issues.
- **Single point of failure**: HSM availability is a hard dependency. Plan for HSM redundancy at the infrastructure level (not handled by QBIND).

### 3.6 MainNet Signer Requirements

**MainNet v0 MUST forbid loopback/test signers and require either:**

1. **EncryptedFsV1** with hardened host configuration, OR
2. **RemoteSigner** with HSM backend (strongly recommended), OR
3. **HsmPkcs11** directly (when implemented)

The `validate_mainnet_invariants()` function enforces this:

```rust
// Pseudocode for signer mode validation (T210)
if config.environment == NetworkEnvironment::Mainnet {
    match config.signer_mode {
        SignerMode::LoopbackTesting => Err(MainnetConfigError::LoopbackSignerForbidden),
        SignerMode::EncryptedFsV1 => Ok(()),  // Acceptable with warnings
        SignerMode::RemoteSigner => Ok(()),   // Recommended
        SignerMode::HsmPkcs11 => Ok(()),      // Strongly recommended
    }
}
```

---

## 4. HSM & Remote Signer Architecture

### 4.1 Signer Abstraction Layer

The QBIND signing architecture uses a layered abstraction to support multiple backends:

```
┌─────────────────────────────────────────────────────────────┐
│                     Consensus Engine                        │
│  (HotStuff BFT, DAG Mempool, Block Construction)           │
└──────────────────────────┬──────────────────────────────────┘
                           │ ValidatorSigner trait
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    ValidatorSigner                          │
│  sign_proposal(preimage) -> Result<Vec<u8>, SignError>     │
│  sign_vote(preimage) -> Result<Vec<u8>, SignError>         │
│  sign_timeout(view, high_qc) -> Result<Vec<u8>, SignError> │
└──────────────────────────┬──────────────────────────────────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
           ▼               ▼               ▼
    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
    │ LocalKey    │ │ RemoteSigner│ │ (Future)    │
    │ Signer      │ │ Client      │ │ HSM Signer  │
    └─────────────┘ └──────┬──────┘ └─────────────┘
                           │
                           │ RemoteSignerTransport trait
                           ▼
           ┌───────────────┼───────────────┐
           │               │               │
           ▼               ▼               ▼
    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
    │ Loopback    │ │ TCP/KEMTLS  │ │ PKCS#11     │
    │ Transport   │ │ Transport   │ │ Transport   │
    │ (testing)   │ │             │ │ (future)    │
    └─────────────┘ └─────────────┘ └─────────────┘
```

### 4.2 ValidatorSigner Trait

The `ValidatorSigner` trait defines the interface for all signing operations:

```rust
/// Trait for validator signing operations (T148).
pub trait ValidatorSigner: Send + Sync {
    /// Get the validator ID.
    fn validator_id(&self) -> &ValidatorId;
    
    /// Get the signature suite ID (100 for ML-DSA-44).
    fn suite_id(&self) -> u16;
    
    /// Sign a block proposal.
    fn sign_proposal(&self, preimage: &[u8]) -> Result<Vec<u8>, SignError>;
    
    /// Sign a vote.
    fn sign_vote(&self, preimage: &[u8]) -> Result<Vec<u8>, SignError>;
    
    /// Sign a timeout message.
    fn sign_timeout(&self, view: u64, high_qc: Option<&QuorumCertificate<[u8; 32]>>) 
        -> Result<Vec<u8>, SignError>;
}
```

**Key Design Points**:
- Private key material is NEVER exposed through this interface
- All methods take preimages (not raw messages) to ensure domain separation
- Error handling is opaque (no information leakage about key material)

### 4.3 RemoteSignerTransport Trait

The `RemoteSignerTransport` trait abstracts the communication channel to a remote signer:

```rust
/// Transport abstraction for remote signing operations (T149).
pub trait RemoteSignerTransport: Send + Sync {
    /// Send a signing request and receive a response.
    fn send_sign_request(&self, request: RemoteSignRequest) 
        -> Result<RemoteSignResponse, RemoteSignError>;
}
```

**Implementations**:

| Transport | Description | Use Case |
| :--- | :--- | :--- |
| `LoopbackSignerTransport` | In-process, wraps `LocalKeySigner` | Testing |
| `TcpKemTlsSignerTransport` (future) | KEMTLS over TCP to remote signer | Production |
| `Pkcs11SignerTransport` (future) | Direct PKCS#11 calls to HSM | HSM integration |

### 4.4 Remote Signer Protocol

The remote signer protocol uses a simple request-response model:

**RemoteSignRequest**:
```rust
pub struct RemoteSignRequest {
    pub validator_id: ValidatorId,      // Which validator to sign as
    pub suite_id: u16,                   // Signature suite (100 = ML-DSA-44)
    pub kind: RemoteSignRequestKind,    // Proposal, Vote, or Timeout
    pub view: Option<u64>,              // View number (for timeout)
    pub preimage: Vec<u8>,              // Domain-separated signing preimage
}
```

**RemoteSignResponse**:
```rust
pub struct RemoteSignResponse {
    pub signature: Option<Vec<u8>>,     // Signature bytes (on success)
    pub error: Option<RemoteSignError>, // Error (on failure)
}
```

**Security Properties**:
- Private key material NEVER crosses the transport boundary
- Preimages include domain separators (replay protection)
- Request validation on signer side (validator_id, suite_id)

### 4.5 PKCS#11 HSM Integration (Future)

The PKCS#11 adapter (`HsmPkcs11Signer`) will provide integration with hardware security modules:

```
┌──────────────────────────────────────────────────────────────┐
│                     HsmPkcs11Signer                          │
├──────────────────────────────────────────────────────────────┤
│  - slot_id: u64         (PKCS#11 slot)                      │
│  - key_handle: CK_OBJECT_HANDLE  (private key handle)       │
│  - session: CK_SESSION_HANDLE    (logged-in session)        │
├──────────────────────────────────────────────────────────────┤
│  fn sign(&self, preimage: &[u8]) -> Vec<u8>                 │
│      1. C_SignInit(session, mechanism=ML-DSA-44, key_handle)│
│      2. C_Sign(session, preimage) -> signature              │
│      3. Return signature                                     │
└──────────────────────────────────────────────────────────────┘
```

**Logical Key IDs**:
- QBIND uses logical key IDs (e.g., `validator-42-consensus`) 
- Mapping to HSM key handles stored in HSM-specific config
- No private key material ever exported from HSM

**HSM Configuration Example**:
```toml
# /etc/qbind/hsm.toml
[hsm]
library = "/usr/lib/softhsm/libsofthsm2.so"  # PKCS#11 library path
slot_id = 0
pin = "env:HSM_PIN"  # PIN from environment variable

[keys.consensus]
label = "qbind-validator-42-consensus"
key_type = "ML-DSA-44"

[keys.p2p_identity]
label = "qbind-validator-42-p2p"
key_type = "ML-KEM-768"
```

### 4.6 Remote Signer Deployment Architecture

For MainNet, the recommended architecture separates the consensus node from the signer:

```
┌─────────────────────────────────────────────────────────────────┐
│                      Consensus Host                             │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  qbind-node                                                │ │
│  │  - HotStuff BFT consensus                                  │ │
│  │  - DAG mempool                                             │ │
│  │  - RemoteSignerClient (no key material)                    │ │
│  └───────────────────────────┬───────────────────────────────┘ │
│                              │ KEMTLS (localhost:9443)         │
└──────────────────────────────┼─────────────────────────────────┘
                               │
                               │ (or network to separate host)
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Signer Host / HSM                         │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  qbind-remote-signer                                       │ │
│  │  - Listens on localhost:9443 (or private network)          │ │
│  │  - PKCS#11 connection to HSM                               │ │
│  │  - Validates signing requests                              │ │
│  └───────────────────────────┬───────────────────────────────┘ │
│                              │ PKCS#11                          │
│  ┌───────────────────────────▼───────────────────────────────┐ │
│  │  HSM Device                                                │ │
│  │  - Private key stored inside                               │ │
│  │  - All signing performed in HSM                            │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

**Security Benefits**:
1. Consensus host compromise does not expose private key
2. HSM provides tamper-evident key storage
3. Signer can implement additional policies (rate limiting, view validation)

### 4.7 MainNet v0 Signer Expectations

| Signer Configuration | MainNet v0 Status | Notes |
| :--- | :--- | :--- |
| **HSM via RemoteSigner** | **Strongly Recommended** | Best security |
| **HSM via HsmPkcs11** | **Strongly Recommended** | Best security (when implemented) |
| **RemoteSigner (no HSM)** | Recommended | Good isolation |
| **EncryptedFsV1 (hardened host)** | Acceptable | Minimum for MainNet |
| **EncryptedFsV1 (unhardened host)** | **Not Recommended** | Security risk |
| **LoopbackTesting** | **FORBIDDEN** | `validate_mainnet_invariants()` rejects |

---

## 5. Key Rotation & Compromise Handling

### 5.1 Planned Rotation

Regular key rotation limits the exposure window if a key is compromised without detection.

#### 5.1.1 Rotation Schedule

| Key Role | Recommended Rotation Interval | Grace Period |
| :--- | :--- | :--- |
| Consensus Key | Annually or after security audit | 2 epochs |
| P2P Identity Key | Annually | 24 hours |
| Batch Signing Key | (Same as consensus key) | 2 epochs |
| Governance Key (future) | Per governance cycle | 1 epoch |

#### 5.1.2 Rotation Procedure (Normal)

1. **Generate New Key**: Create new keypair in HSM/keystore
2. **Register New Key**: Submit new public key to validator set via governance
3. **Grace Period Start**: Both old and new keys are valid for signing
4. **Transition**: Start signing with new key
5. **Grace Period End**: Old key deregistered; only new key valid
6. **Cleanup**: Securely destroy old key material (if exportable)

```
Timeline:
─────────────────────────────────────────────────────────────────►
│ Generate │ Register │  Grace Period  │ Old Key │
│ New Key  │ New Key  │ (both valid)   │ Invalid │
                      ├────────────────┤
                      Sign with new key
```

#### 5.1.3 Validator Set Update

Key rotation requires updating the validator set configuration:

```rust
// Pseudocode for validator set key update
ValidatorSetUpdate {
    validator_id: 42,
    action: UpdatePublicKey {
        key_role: KeyRole::Consensus,
        new_public_key: new_pk_bytes,
        effective_epoch: current_epoch + 2,  // Grace period
    },
}
```

### 5.2 Emergency Rotation (Compromise Response)

When key compromise is suspected or confirmed, emergency rotation is required.

#### 5.2.1 Compromise Indicators

- Unauthorized signatures detected on-chain
- Security breach on validator host
- HSM tamper detection triggered
- Insider threat identified

#### 5.2.2 Emergency Rotation Procedure

1. **Immediate**: Take validator offline (stop signing with compromised key)
2. **Generate**: Create emergency replacement key
3. **Report**: Submit compromise report to governance/ops team
4. **Request**: Emergency validator set update via governance
5. **Restore**: Resume operations with new key once approved

**Emergency Timeline** (target):
- Detection to offline: < 15 minutes
- New key generation: < 30 minutes
- Governance approval: < 2 hours (may require quorum)
- Back online: < 4 hours total

#### 5.2.3 Slashing Interaction

Compromised keys may be used maliciously (e.g., double-voting). The slashing protocol (future) will handle:

- **Equivocation Detection**: Conflicting signatures from same validator
- **Slashing Evidence**: Signed messages proving misbehavior
- **Penalty Application**: Stake reduction for equivocating validators

**Note**: Slashing specification is out of scope for T209. Key management design anticipates that malicious usage of a compromised key may result in slashing.

### 5.3 Backup and Recovery

#### 5.3.1 Backup Strategies by Signer Mode

| Signer Mode | Backup Strategy | Recovery Procedure |
| :--- | :--- | :--- |
| **EncryptedFsV1** | Encrypted backup of keystore files | Restore files, unlock with passphrase |
| **RemoteSigner** | Backup signer host configuration | Restore signer host, reconnect |
| **HsmPkcs11** | HSM-native backup (vendor-specific) | HSM restore procedure |

#### 5.3.2 EncryptedFsV1 Backup

```bash
# Backup (example)
tar -czf validator-42-keys-$(date +%Y%m%d).tar.gz \
    /data/qbind/keystore/*.enc

# Store backup securely (encrypted, offsite)
gpg --encrypt --recipient ops@qbind.network \
    validator-42-keys-*.tar.gz
```

**Recovery**:
1. Restore backup files to keystore directory
2. Start node with correct passphrase
3. Verify key material matches expected public key

#### 5.3.3 HSM Backup

HSM backup procedures are vendor-specific:

- **AWS CloudHSM**: AWS backup service
- **Thales Luna**: Remote Backup HSM or card-based backup
- **YubiHSM**: Wrap key export with backup key

**Critical**: HSM private key material should NEVER be exported in plaintext. All backup mechanisms must use HSM-native secure backup.

---

## 6. Network Profiles & Requirements

### 6.1 Requirements Matrix

The following matrix summarizes key management requirements across network phases:

| Requirement | DevNet | TestNet Alpha | TestNet Beta | MainNet |
| :--- | :---: | :---: | :---: | :---: |
| **LoopbackTesting allowed** | ✅ | ✅ | ⚠️ Discouraged | ❌ **Forbidden** |
| **EncryptedFsV1 allowed** | ✅ | ✅ | ✅ | ✅ (hardened) |
| **RemoteSigner allowed** | ✅ | ✅ | ✅ | ✅ |
| **HsmPkcs11 allowed** | ✅ | ✅ | ✅ | ✅ |
| **HSM required** | ❌ | ❌ | ❌ | ❌ (strongly rec.) |
| **Key rotation policy** | None | None | Recommended | **Required** |
| **Compromise procedures** | None | Informal | Documented | **Formal** |
| **Startup validation** | None | None | None | `validate_mainnet_invariants()` |

### 6.2 DevNet Profile

**Purpose**: Development and testing; no real value at stake.

**Signer Configuration**:
- Any signer mode allowed
- LoopbackTesting is typical for harness tests
- No key rotation required

**Sample Configuration**:
```bash
qbind-node --profile devnet-v0 \
    --signer-mode loopback \
    --keystore-path ./test-keys
```

### 6.3 TestNet Alpha Profile

**Purpose**: Early feature testing; opt-in participation.

**Signer Configuration**:
- Any signer mode allowed
- LoopbackTesting acceptable for testing
- EncryptedFsV1 recommended for persistent validators

**Sample Configuration**:
```bash
qbind-node --profile testnet-alpha \
    --signer-mode encrypted-fs \
    --keystore-path /data/qbind/keystore \
    --keystore-passphrase-file /etc/qbind/passphrase
```

### 6.4 TestNet Beta Profile

**Purpose**: Pre-production testing; validators should follow production practices.

**Signer Configuration**:
- LoopbackTesting discouraged (warning logged)
- EncryptedFsV1 or RemoteSigner recommended
- HSM encouraged for operators who will run MainNet validators

**Key Rotation**:
- Annual rotation recommended
- Rotation procedures should be tested

**Sample Configuration**:
```bash
qbind-node --profile testnet-beta \
    --signer-mode remote \
    --remote-signer-addr localhost:9443 \
    --data-dir /data/qbind
```

### 6.5 MainNet Profile

**Purpose**: Production network; real economic value at stake.

**Signer Configuration**:
- LoopbackTesting **FORBIDDEN** (node refuses to start)
- EncryptedFsV1 acceptable with hardened host
- RemoteSigner with HSM **strongly recommended**
- HsmPkcs11 **strongly recommended** (when available)

**Key Rotation**:
- Annual rotation **required**
- Emergency rotation procedures **required**
- Documented backup/recovery procedures **required**

**Startup Validation**:
`validate_mainnet_invariants()` checks:
1. Signer mode is not LoopbackTesting
2. If EncryptedFsV1, verify file permissions (future)
3. If RemoteSigner, verify connection to remote signer (future)

**Sample Configuration**:
```bash
qbind-node --profile mainnet \
    --signer-mode hsm \
    --hsm-config /etc/qbind/hsm.toml \
    --data-dir /data/qbind \
    --p2p-listen-addr 0.0.0.0:9000
```

### 6.6 Consistency with validate_mainnet_invariants()

The key management requirements are enforced (or will be enforced) by `validate_mainnet_invariants()`:

| Check | Current Status | T210 Target |
| :--- | :--- | :--- |
| Reject LoopbackTesting | Not yet | ✅ Implement |
| Warn on EncryptedFsV1 without hardening | Not yet | ⚠️ Implement warning |
| Verify remote signer reachable | Not yet | ✅ Implement |
| Verify HSM accessible | Not yet | ✅ Implement |

---

## 7. Implementation Roadmap (T210+)

### 7.1 T210 – Signer Stack Hardening v1

**Scope**: Explicit `SignerMode` configuration and startup invariant validation.

**Deliverables**:
- Add `SignerMode` enum to `NodeConfig`
- Implement `SignerMode` parsing in CLI
- Add signer mode validation to `validate_mainnet_invariants()`
- Log warnings for discouraged configurations
- Update documentation for signer mode configuration

**Non-Goals**:
- No changes to actual signing implementations
- No HSM integration
- No new remote signer transports

### 7.2 T211 – HSM/PKCS#11 Adapter v0 ✅ Completed

**Status**: Completed. Module: `qbind-node/src/hsm_pkcs11.rs`, feature flag: `hsm-pkcs11`.

**Scope**: Initial PKCS#11-based HSM integration.

**Deliverables**:
- ✅ Implemented `HsmPkcs11Signer` implementing `ValidatorSigner` trait
- ✅ Support key lookup by label via `HsmPkcs11Config`
- ✅ ML-DSA-44 signing via PKCS#11 (preimage-style, consistent with rest of stack)
- ✅ SoftHSM integration test (`t211_hsm_soft_tests.rs`, `#[ignore]` by default)
- ✅ Documented HSM configuration format (`HsmPkcs11Config` TOML)
- ✅ HSM metrics: `qbind_hsm_sign_success_total`, `qbind_hsm_sign_error_total`, `qbind_hsm_sign_last_latency_ms`
- ✅ Feature-gated behind `hsm-pkcs11` Cargo feature

**Non-Goals**:
- No key generation via PKCS#11 (manual setup assumed)
- No hot-plugging HSM support
- No HSM redundancy/failover

### 7.3 T212 – Remote Signer Protocol v0

**Scope**: Production-ready remote signer service and transport.

**Deliverables**:
- Implement `TcpKemTlsSignerTransport` for KEMTLS over TCP
- Implement `qbind-remote-signer` binary/service
- Define remote signer configuration format
- Implement request validation and rate limiting
- Test multi-process signer deployment

**Non-Goals**:
- No load balancing multiple signers
- No automatic failover
- No request queueing

### 7.4 T213 – Key Rotation Hooks v0

**Scope**: Primitives for key rotation without full governance integration.

**Deliverables**:
- Define `KeyRotationEvent` type for validator set updates
- Implement grace period handling for dual-key validity
- Add key rotation initiation CLI command
- Document rotation procedures
- Add rotation event logging/metrics

**Non-Goals**:
- No on-chain governance for key rotation (separate task)
- No automatic rotation scheduling
- No slashing integration

### 7.5 Future Tasks (T214+)

| Task | Scope | Target Phase |
| :--- | :--- | :--- |
| T214 | HSM redundancy and failover | MainNet v0.x |
| T215 | Governance-integrated key rotation | MainNet v0.x |
| T216 | Key rotation via on-chain transactions | MainNet v1+ |
| T217 | Withdrawal key cold storage integration | MainNet v1+ |
| T218 | Multi-signature validator keys | MainNet v2+ |

---

## 8. Related Documents

| Document | Path | Description |
| :--- | :--- | :--- |
| **MainNet v0 Spec** | [QBIND_MAINNET_V0_SPEC.md](../mainnet/QBIND_MAINNET_V0_SPEC.md) | MainNet v0 architecture |
| **MainNet Audit** | [QBIND_MAINNET_AUDIT_SKELETON.md](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md) | MainNet risk and readiness tracking |
| **TestNet Beta Spec** | [QBIND_TESTNET_BETA_SPEC.md](../testnet/QBIND_TESTNET_BETA_SPEC.md) | TestNet Beta architecture |
| **DAG Consensus Coupling** | [QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md](../mainnet/QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md) | DAG–HotStuff coupling design (T188) |
| **Monetary Policy Design** | [QBIND_MONETARY_POLICY_DESIGN.md](../econ/QBIND_MONETARY_POLICY_DESIGN.md) | Monetary policy specification (T194) |
| **P2P Network Design** | [QBIND_P2P_NETWORK_DESIGN.md](../network/QBIND_P2P_NETWORK_DESIGN.md) | P2P networking architecture |

### Implementation References

| Component | Path | Description |
| :--- | :--- | :--- |
| ValidatorSigner | `qbind-node/src/validator_signer.rs` | Signing trait and LocalKeySigner |
| RemoteSigner | `qbind-node/src/remote_signer.rs` | Remote signer protocol and transport |
| Keystore | `qbind-node/src/keystore.rs` | Encrypted keystore implementation |
| NodeConfig | `qbind-node/src/node_config.rs` | Node configuration and validation |

---

*End of Document*