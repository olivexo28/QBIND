# QBIND Genesis & Launch State Design

**Task**: T232  
**Status**: Implemented  
**Date**: 2026-02-09

---

## 1. Overview

This document specifies the genesis state configuration model for QBIND networks. The genesis state establishes the initial configuration of a network, including token allocations, validator set, governance council, and monetary policy parameters.

### 1.1 Design Goals

1. **Auditable**: Clear JSON schema with documented fields and constraints
2. **Replayable**: Deterministic genesis state from configuration file
3. **Validated**: Strong invariants checked at parse time
4. **Extensible**: Reserved fields for future enhancements
5. **Network-aware**: Different requirements for DevNet/TestNet vs MainNet

### 1.2 Related Documents

- [QBIND MainNet v0 Specification §1.5](../mainnet/QBIND_MAINNET_V0_SPEC.md#15-genesis-state--chain-id-t232)
- [QBIND MainNet Runbook §4.3](../ops/QBIND_MAINNET_RUNBOOK.md#43-genesis-configuration-t232)
- [QBIND TestNet Beta Specification §1.5](../testnet/QBIND_TESTNET_BETA_SPEC.md#15-genesis-configuration-t232)

---

## 2. Genesis Configuration Schema

### 2.1 Top-Level Structure

```rust
pub struct GenesisConfig {
    /// Chain identifier (e.g., "qbind-mainnet-v0")
    pub chain_id: String,
    
    /// Canonical genesis time (Unix milliseconds)
    pub genesis_time_unix_ms: u64,
    
    /// Initial token allocations
    pub allocations: Vec<GenesisAllocation>,
    
    /// Initial validator set
    pub validators: Vec<GenesisValidator>,
    
    /// Governance council configuration
    pub council: GenesisCouncilConfig,
    
    /// Initial monetary policy parameters
    pub monetary: GenesisMonetaryConfig,
    
    /// Reserved for future extensions
    pub extra: serde_json::Value,
}
```

### 2.2 GenesisAllocation

Defines initial token distribution:

```rust
pub struct GenesisAllocation {
    /// Account address (hex string)
    pub address: String,
    
    /// Token amount in base units
    pub amount: u128,
    
    /// Optional description (e.g., "Foundation reserve")
    pub memo: Option<String>,
    
    /// Optional lockup expiry (Unix milliseconds)
    pub lockup_until_unix_ms: Option<u64>,
}
```

### 2.3 GenesisValidator

Defines initial validator set:

```rust
pub struct GenesisValidator {
    /// Validator account address
    pub address: String,
    
    /// ML-DSA-44 public key (hex encoded)
    pub pqc_public_key: String,
    
    /// Initial stake amount
    pub stake: u128,
    
    /// Optional human-readable name
    pub name: Option<String>,
    
    /// Optional metadata (website, contact, etc.)
    pub metadata: Option<String>,
}
```

### 2.4 GenesisCouncilConfig

Defines governance council:

```rust
pub struct GenesisCouncilConfig {
    /// Council member addresses
    pub members: Vec<String>,
    
    /// Required signature threshold
    pub threshold: u32,
}
```

### 2.5 GenesisMonetaryConfig

Wraps `MonetaryEngineConfig` for initial monetary policy:

```rust
pub struct GenesisMonetaryConfig {
    /// PQC premiums (compute, bandwidth, storage)
    pub pqc_premium_compute: f64,
    pub pqc_premium_bandwidth: f64,
    pub pqc_premium_storage: f64,
    
    /// Bootstrap phase parameters
    pub bootstrap_r_target_annual: f64,
    pub bootstrap_inflation_floor_annual: f64,
    pub bootstrap_max_annual_inflation_cap: f64,
    // ... additional monetary parameters
}
```

---

## 3. Validation Rules

### 3.1 Core Invariants

The `GenesisConfig::validate()` method enforces these invariants:

| # | Invariant | Error Type |
| :--- | :--- | :--- |
| 1 | `chain_id` must be non-empty | `GenesisValidationError::EmptyChainId` |
| 2 | At least one allocation required | `GenesisValidationError::NoAllocations` |
| 3 | All allocation amounts must be > 0 | `GenesisValidationError::ZeroAllocationAmount` |
| 4 | No duplicate allocation addresses | `GenesisValidationError::DuplicateAllocationAddress` |
| 5 | At least one validator required | `GenesisValidationError::NoValidators` |
| 6 | Validator PQC keys must be non-empty | `GenesisValidationError::EmptyValidatorPqcKey` |
| 7 | No duplicate validator addresses | `GenesisValidationError::DuplicateValidatorAddress` |
| 8 | Council threshold must be > 0 | `GenesisValidationError::CouncilThresholdZero` |
| 9 | Council threshold ≤ member count | `GenesisValidationError::CouncilThresholdTooHigh` |
| 10 | No duplicate council members | `GenesisValidationError::DuplicateCouncilMember` |

### 3.2 Derived Properties

After validation, these properties are computed:

- `total_supply()`: Sum of all allocation amounts
- `total_stake()`: Sum of all validator stakes
- `validator_count()`: Number of initial validators
- `council_size()`: Number of council members

---

## 4. Genesis Source Configuration

### 4.1 GenesisSourceConfig

Node configuration includes genesis source settings:

```rust
pub struct GenesisSourceConfig {
    /// Whether to require external genesis file
    pub use_external: bool,
    
    /// Path to external genesis file (if use_external is true)
    pub genesis_path: Option<PathBuf>,
}
```

### 4.2 Network-Specific Defaults

| Network | `use_external` | `genesis_path` | Behavior |
| :--- | :--- | :--- | :--- |
| **DevNet** | `false` | `None` | Uses embedded test genesis |
| **TestNet Alpha** | `false` | Optional | Embedded default, external optional |
| **TestNet Beta** | `false` | Optional | Embedded default, external optional |
| **MainNet** | `true` | **Required** | External genesis file required |

### 4.3 MainNet Validation

MainNet nodes enforce strict genesis requirements:

```rust
impl GenesisSourceConfig {
    pub fn validate_for_mainnet(&self) -> Result<(), String> {
        if !self.use_external {
            return Err("MainNet requires external genesis file".to_string());
        }
        if self.genesis_path.is_none() {
            return Err("genesis_path must be set for MainNet".to_string());
        }
        Ok(())
    }
}
```

---

## 5. CLI Integration

### 5.1 CLI Flag

The `--genesis-path` flag specifies the path to an external genesis file:

```bash
qbind-node --profile mainnet --genesis-path /etc/qbind/genesis.json --data-dir /data/qbind
```

### 5.2 Profile Behavior

| Profile | `--genesis-path` | Effect |
| :--- | :--- | :--- |
| `devnet-v0` | Not provided | Uses embedded test genesis |
| `devnet-v0` | Provided | Uses external genesis |
| `testnet-alpha` | Not provided | Uses embedded test genesis |
| `testnet-alpha` | Provided | Uses external genesis |
| `testnet-beta` | Not provided | Uses embedded test genesis |
| `testnet-beta` | Provided | Uses external genesis |
| `mainnet` | **Required** | Uses external genesis (validation error if missing) |

---

## 6. JSON Schema

### 6.1 Example Genesis File

```json
{
  "chain_id": "qbind-mainnet-v0",
  "genesis_time_unix_ms": 1707472800000,
  "allocations": [
    {
      "address": "0x1234567890abcdef1234567890abcdef12345678",
      "amount": "1000000000000000000000000",
      "memo": "Foundation allocation"
    },
    {
      "address": "0xabcdef1234567890abcdef1234567890abcdef12",
      "amount": "500000000000000000000000",
      "lockup_until_unix_ms": 1739008800000
    }
  ],
  "validators": [
    {
      "address": "0xvalidator1...",
      "pqc_public_key": "0x...(ML-DSA-44 public key)...",
      "stake": "100000000000000000000000",
      "name": "Validator 1"
    }
  ],
  "council": {
    "members": [
      "0xcouncil1...",
      "0xcouncil2...",
      "0xcouncil3..."
    ],
    "threshold": 2
  },
  "monetary": {
    "pqc_premium_compute": 1.5,
    "pqc_premium_bandwidth": 1.3,
    "pqc_premium_storage": 1.2,
    "bootstrap_r_target_annual": 0.05,
    "bootstrap_inflation_floor_annual": 0.02,
    "bootstrap_max_annual_inflation_cap": 0.20
  },
  "extra": {}
}
```

---

## 7. Test Coverage

### 7.1 Unit Tests (qbind-ledger)

File: `crates/qbind-ledger/tests/t232_genesis_config_tests.rs`

| Test | Description |
| :--- | :--- |
| `test_genesis_valid_basic` | Basic valid config passes validation |
| `test_genesis_rejects_zero_allocation` | Zero amount allocation rejected |
| `test_genesis_rejects_duplicate_address` | Duplicate allocation addresses rejected |
| `test_genesis_rejects_invalid_council_threshold` | Invalid threshold rejected |
| `test_genesis_monetary_config_roundtrips` | Serialization roundtrip |
| `test_genesis_json_roundtrip` | JSON serialization roundtrip |
| + 10 additional validation tests | Edge cases and error conditions |

### 7.2 Integration Tests (qbind-node)

File: `crates/qbind-node/tests/t232_genesis_mainnet_profile_tests.rs`

| Test | Description |
| :--- | :--- |
| `test_mainnet_requires_genesis_path` | MainNet rejects missing genesis path |
| `test_mainnet_accepts_genesis_path` | MainNet accepts valid genesis path |
| `test_devnet_allows_embedded_genesis` | DevNet works with embedded genesis |
| `test_testnet_allows_embedded_genesis` | TestNet works with embedded genesis |
| `test_genesis_source_config_methods` | Factory methods work correctly |
| `test_profile_genesis_settings` | Profile presets have correct settings |
| `test_default_config_genesis` | Default config uses embedded genesis |

---

## 8. Security Considerations

### 8.1 Genesis File Integrity

- **Hash verification**: Operators should verify genesis file hash before startup
- **Canonical distribution**: All validators must use identical genesis.json
- **No secrets**: Genesis file must not contain private keys or sensitive data

### 8.2 Chain ID Uniqueness

- **Replay protection**: Unique chain_id prevents cross-network replay attacks
- **Signature domain separation**: Chain ID included in all signed messages

### 8.3 Council Threshold

- **Threshold validation**: Ensures threshold is feasible (≤ member count)
- **Non-zero requirement**: Prevents bypass of governance

---

## 9. Genesis Hash Commitment (T233)

**Status**: Implemented

Genesis hash commitment provides cryptographic verification that all nodes start from the same genesis state.

### 9.1 Canonical Hash Definition

The canonical genesis hash is:
```
genesis_hash = SHA3-256(genesis_json_bytes)
```

Where `genesis_json_bytes` is the **exact** content of the genesis file:
- **No JSON normalization**: Hash is sensitive to whitespace, key ordering
- **No preprocessing**: Exact byte-for-byte hash of the distributed file

### 9.2 ChainMeta Persistence

When applying genesis (height 0), the node:
1. Loads genesis file bytes
2. Computes `genesis_hash = SHA3-256(bytes)`
3. Parses genesis config to extract `chain_id`
4. Creates `ChainMeta { chain_id, genesis_hash }`
5. Persists `ChainMeta` as part of height 0 state

The `ChainMeta` struct:
```rust
pub struct ChainMeta {
    pub chain_id: String,
    pub genesis_hash: GenesisHash, // [u8; 32]
}
```

### 9.3 CLI Verification

Two CLI flags support genesis hash verification:

| Flag | Description |
| :--- | :--- |
| `--print-genesis-hash` | Print hash of genesis file and exit |
| `--expect-genesis-hash` | Verify hash matches at startup |

**Operator Workflow**:
```bash
# Step 1: Compute hash of genesis file
qbind-node --print-genesis-hash --genesis-path genesis.json
# Output: 0xabc123...def789

# Step 2: Start node with expected hash
qbind-node --profile mainnet \
  --genesis-path genesis.json \
  --expect-genesis-hash 0xabc123...def789
```

### 9.4 MainNet Invariant

MainNet validators **MUST** specify `--expect-genesis-hash`:
- `validate_mainnet_invariants()` returns `ExpectedGenesisHashMissing` if not set
- Node refuses to start without explicit hash commitment

### 9.5 Security Benefits

- **Fork prevention**: Ensures all validators start from identical genesis
- **Distribution integrity**: Detects tampered genesis files
- **Audit compliance**: Provides verifiable genesis identity

---

## 10. Future Work (T234+)

The following features are deferred to future tasks:

1. **Genesis Generator CLI**: Interactive tool to create genesis files
2. **Vesting Implementation**: Enforcement of `lockup_until_unix_ms` in execution
3. **Multi-sig Ceremony**: Distributed genesis creation with threshold signatures
4. **Faucet Integration**: Automated initial token distribution tooling

---

## 11. Implementation References

| Component | File |
| :--- | :--- |
| Genesis types | `crates/qbind-ledger/src/genesis.rs` |
| Genesis hash types (T233) | `crates/qbind-ledger/src/genesis.rs` |
| Genesis source config | `crates/qbind-node/src/node_config.rs` |
| CLI flags | `crates/qbind-node/src/cli.rs` |
| MainNet validation | `crates/qbind-node/src/node_config.rs` |
| T232 Ledger tests | `crates/qbind-ledger/tests/t232_genesis_config_tests.rs` |
| T232 Node tests | `crates/qbind-node/tests/t232_genesis_mainnet_profile_tests.rs` |
| T233 Hash tests | `crates/qbind-ledger/tests/t233_genesis_hash_tests.rs` |
| T233 CLI tests | `crates/qbind-node/tests/t233_genesis_cli_tests.rs` |