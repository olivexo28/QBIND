# QBIND Chain ID and Domain Separation Scheme (T159)

## Overview

This document describes the QBIND chain ID and domain-separation scheme for all signed objects. This scheme prevents cross-chain replay attacks between DevNet, TestNet, and MainNet by including the chain ID in all signing preimages.

## Chain ID Constants

QBIND defines three canonical chain IDs for its network environments:

| Environment | Chain ID (hex)         | Chain ID (decimal)       | Scope Tag |
| :---------- | :--------------------- | :----------------------- | :-------- |
| **DevNet**  | `0x51424E44_44455600`  | `5860389632063700480`    | `DEV`     |
| **TestNet** | `0x51424E44_54535400`  | `5860389632330203136`    | `TST`     |
| **MainNet** | `0x51424E44_4D41494E`  | `5860389632111296846`    | `MAIN`    |

### Chain ID Design

- **Non-trivial values**: Chain IDs are intentionally large to avoid accidental collisions with simple values like 1, 2, 3.
- **ASCII-like encoding**: Values encode parts of "QBND" plus environment abbreviation for easy identification in hex dumps.
- **Unique per environment**: Each environment has a distinct chain ID that is included in all signed data.

## Domain Separation Scheme

### Domain Tag Format

All domain tags follow the format:

```
QBIND:<SCOPE>:<KIND>:v1
```

Where:
- `SCOPE` is derived from the chain ID: "DEV", "TST", "MAIN", or "UNK" (unknown)
- `KIND` identifies the type of signed object
- `v1` is the version number

### Domain Kinds

| Kind       | Tag (DevNet)             | Description                    |
| :--------- | :----------------------- | :----------------------------- |
| `UserTx`   | `QBIND:DEV:TX:v1`        | User transaction signing       |
| `Batch`    | `QBIND:DEV:BATCH:v1`     | DAG mempool batch signing      |
| `Vote`     | `QBIND:DEV:VOTE:v1`      | Consensus vote signing         |
| `Proposal` | `QBIND:DEV:PROPOSAL:v1`  | Block proposal signing         |
| `Timeout`  | `QBIND:DEV:TIMEOUT:v1`   | Timeout message signing        |
| `NewView`  | `QBIND:DEV:NEWVIEW:v1`   | NewView/pacemaker signing      |

### Environment-Specific Tags

| Kind     | DevNet                  | TestNet                  | MainNet                   |
| :------- | :---------------------- | :----------------------- | :------------------------ |
| UserTx   | `QBIND:DEV:TX:v1`       | `QBIND:TST:TX:v1`        | `QBIND:MAIN:TX:v1`        |
| Batch    | `QBIND:DEV:BATCH:v1`    | `QBIND:TST:BATCH:v1`     | `QBIND:MAIN:BATCH:v1`     |
| Vote     | `QBIND:DEV:VOTE:v1`     | `QBIND:TST:VOTE:v1`      | `QBIND:MAIN:VOTE:v1`      |
| Proposal | `QBIND:DEV:PROPOSAL:v1` | `QBIND:TST:PROPOSAL:v1`  | `QBIND:MAIN:PROPOSAL:v1`  |
| Timeout  | `QBIND:DEV:TIMEOUT:v1`  | `QBIND:TST:TIMEOUT:v1`   | `QBIND:MAIN:TIMEOUT:v1`   |
| NewView  | `QBIND:DEV:NEWVIEW:v1`  | `QBIND:TST:NEWVIEW:v1`   | `QBIND:MAIN:NEWVIEW:v1`   |

## Security Rationale

### Cross-Chain Replay Prevention

Without chain-specific domain tags, a signed object (transaction, vote, batch, etc.) could potentially be replayed on a different network:

1. **Attack scenario**: Attacker obtains a valid signed transaction from DevNet
2. **Without T159**: Transaction could be replayed on TestNet or MainNet
3. **With T159**: Transaction signature is invalid on TestNet/MainNet because the domain tag differs

### Implementation

The domain prefix is prepended to all signing preimages:

```rust
pub fn domain_prefix(chain_id: ChainId, kind: DomainKind) -> Vec<u8> {
    let scope = match chain_id {
        QBIND_DEVNET_CHAIN_ID => "DEV",
        QBIND_TESTNET_CHAIN_ID => "TST",
        QBIND_MAINNET_CHAIN_ID => "MAIN",
        _ => "UNK",
    };
    let kind_str = match kind {
        DomainKind::UserTx => "TX",
        DomainKind::Batch => "BATCH",
        // ... etc
    };
    format!("QBIND:{}:{}:v1", scope, kind_str).into_bytes()
}
```

## Signed Objects

### User Transactions (QbindTransaction)

**Preimage Layout:**
```
QBIND:DEV:TX:v1  (15 bytes for DevNet)
sender           [u8; 32]
nonce            u64 LE
payload_len      u32 LE
payload          [u8; payload_len]
suite_id         u16 LE
```

### DAG Batches (QbindBatch)

**Preimage Layout:**
```
QBIND:DEV:BATCH:v1  (18 bytes for DevNet)
creator             u64 LE
view_hint           u64 LE
parents_root        [u8; 32] (SHA3-256 of parents encoding)
tx_root             [u8; 32] (SHA3-256 of txs encoding)
```

### Consensus Votes

**Preimage Layout:**
```
QBIND:DEV:VOTE:v1  (17 bytes for DevNet)
version            u8
chain_id           u32 LE
epoch              u64 LE
height             u64 LE
round              u64 LE
step               u8
block_id           [u8; 32]
validator_index    u16 LE
suite_id           u16 LE
```

### Block Proposals

**Preimage Layout:**
```
QBIND:DEV:PROPOSAL:v1  (21 bytes for DevNet)
version               u8
chain_id              u32 LE
epoch                 u64 LE
height                u64 LE
round                 u64 LE
parent_block_id       [u8; 32]
payload_hash          [u8; 32]
proposer_index        u16 LE
suite_id              u16 LE
tx_count              u32 LE
timestamp             u64 LE
payload_kind          u8
next_epoch            u64 LE
qc_len                u32 LE
qc_bytes              [u8; qc_len]
txs                   sequence of (u32 len, bytes[len])
```

### Timeout Messages

**Preimage Layout:**
```
QBIND:DEV:TIMEOUT:v1  (20 bytes for DevNet)
view                  u64 LE
high_qc_block_id      [u8; 32] (zeros if None)
high_qc_view          u64 LE (zeros if None)
validator_id          u64 LE
```

## Usage Guidelines

### For New Signed Objects

Any future signed object MUST use the `domain_prefix()` helper:

```rust
use qbind_types::domain::{domain_prefix, DomainKind};

fn signing_preimage(&self, chain_id: ChainId) -> Vec<u8> {
    let mut preimage = domain_prefix(chain_id, DomainKind::NewKind);
    // ... append object-specific fields ...
    preimage
}
```

### For Testing

- DevNet tests should use `QBIND_DEVNET_CHAIN_ID`
- Cross-chain tests should verify that different chain IDs produce different preimages
- Signature verification tests should confirm cross-chain signatures fail

### For Deployment

- Ensure the correct chain ID is configured at node startup
- Log the configured chain ID and environment at startup for visibility
- Never mix chain IDs between environments

## Upgrade Notes

### From Pre-T159 (Legacy Domain Tags)

Before T159, domain tags were not chain-aware:
- `QBIND:TX:v1` (legacy)
- `QBIND:VOTE:v1` (legacy)
- `QBIND:PROPOSAL:v1` (legacy)
- `QBIND:BATCH:v1` (legacy)
- `QBIND_TIMEOUT_V1` (legacy)

After T159, all tags include the chain scope:
- `QBIND:DEV:TX:v1` (new)
- `QBIND:DEV:VOTE:v1` (new)
- etc.

**Migration Impact**: This is a **consensus-breaking change** for signature verification. All nodes must upgrade together.

## References

- `qbind-types/src/domain.rs` - Domain separation implementation
- `qbind-types/src/primitives.rs` - ChainId type and constants
- `qbind-ledger/src/execution.rs` - QbindTransaction signing
- `qbind-wire/src/consensus.rs` - Vote and BlockProposal signing
- `qbind-consensus/src/timeout.rs` - TimeoutMsg signing
- `qbind-node/src/dag_mempool.rs` - QbindBatch signing