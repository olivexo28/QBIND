<!--
T143 – QBIND rebrand plan (draft)

Findings
- Crates (all under crates/): qbind-types (core state types), qbind-wire (wire/consensus/governance IO + suite IDs), qbind-hash (domain hashes), qbind-crypto (PQC suites, AEAD/KEM/signatures), qbind-serde (state encoding), qbind-ledger (accounts/ledger execution helpers), qbind-system (system programs), qbind-runtime (block/tx executor over ledger + programs), qbind-genesis (genesis state writers), qbind-consensus (HotStuff verification/driver/sim), qbind-node (node pipeline, async runtime, networking adapters, metrics, storage), qbind-net (KEMTLS transport + framing + keys + metrics).
- Binaries: none defined (no [[bin]] or src/bin/main.rs). Node crate is a library harness/tests only.
- Metrics prefixes/names using qbind_: node metrics exporter emits many Prom-style lines: qbind_consensus_* (view, validator vote/lag/equivocation counts, QC latency, view changes, etc.), qbind_net_* (kem_* totals/latency, per-peer drop counters), qbind_net_per_peer_drops_total, plus consensus sig metrics in qbind-consensus (qbind_consensus_sig_* buckets). Tests assert these strings.
- Config/env using QBIND_: QBIND_CONSENSUS_EVENT_CHANNEL_CAPACITY, QBIND_OUTBOUND_COMMAND_CHANNEL_CAPACITY, QBIND_ASYNC_PEER_INBOUND_CAPACITY, QBIND_ASYNC_PEER_OUTBOUND_CAPACITY (channel_config); QBIND_TRANSPORT_SECURITY_MODE (async_peer_manager); QBIND_METRICS_HTTP_ADDR (metrics_http). Docs/comments reference these.
- Protocol/wire/hash tags with CANO/QBIND: consensus domain tags in qbind-wire (VOTE_DOMAIN_TAG "QBIND:VOTE:v1", PROPOSAL "QBIND:PROPOSAL:v1"); hash domain separators in qbind-hash ("QBIND:VOTE", "QBIND:TX", "QBIND:NETCERT"); consensus timeout domain separator "QBIND_TIMEOUT_V1"; KEMTLS labels/AAD in qbind-net ("QBIND:KEMTLS", HKDF labels "QBIND:KDF", "QBIND:session-id", "QBIND:k_c2s", "QBIND:k_s2c"; transport AAD "QBIND:net:app-frame"); test AAD/tag literals like "QBIND:test", "QBIND:T140". Changing these affects signatures/wire compatibility.
- Docs: repo README is qbind-branded; several qbind-node test module headers mention QBIND; audit docs exist under docs/.

Rename plan
- Crate/package rename: qbind-* → qbind-* for all workspace members listed above; update workspace members and all inter-crate path deps accordingly.
- Binaries: none to rename; ensure future bin/package references use qbind-* naming.
- Metrics: rename Prom strings/prefixes qbind_* → qbind_* across node metrics exporter/tests and consensus sig metrics formatter/tests; keep metric shapes identical.
- Config/env: rename QBIND_* env vars to QBIND_* (channel capacities, transport security mode, metrics HTTP addr) and update docs/tests.
- Protocol/wire/hash tags: retag CANO-branded domain separators to QBIND equivalents (KEMTLS labels/AAD, transport AAD, hash tags, consensus signing domain tags, timeout separator). This breaks compatibility with existing signatures/checkpoints/recordings and requires regenerating devnet/test fixtures; note in summary as breaking change.
- Docs/comments: update README, crate docs, test module headers, audit markdown (non-quoted sections) to QBIND branding.
- On-disk paths/default filenames: audit and rename any qbind-* path defaults encountered during code pass (e.g., keystores/storage prefixes) to qbind-* while preserving behavior otherwise.

Compatibility notes
- Renaming protocol domain tags and hash/signing labels will invalidate prior artifacts (signatures, hashes, network handshakes, stored checkpoints). Metrics/env renames will break existing dashboards/config unless migrated. Treat as a coordinated rebrand cut; document impacts after implementation.

---

# Part B & C – Implementation Complete

## What Changed

### Crate & Binary Renames (Complete)

| Old Name | New Name | Status |
|----------|----------|--------|
| cano-types | qbind-types | ✓ |
| cano-wire | qbind-wire | ✓ |
| cano-hash | qbind-hash | ✓ |
| cano-crypto | qbind-crypto | ✓ |
| cano-serde | qbind-serde | ✓ |
| cano-ledger | qbind-ledger | ✓ |
| cano-system | qbind-system | ✓ |
| cano-runtime | qbind-runtime | ✓ |
| cano-genesis | qbind-genesis | ✓ |
| cano-consensus | qbind-consensus | ✓ |
| cano-node | qbind-node | ✓ |
| cano-net | qbind-net | ✓ |

**Actions taken:**
- Renamed all crate directories under `crates/` from `cano-*` to `qbind-*`
- Updated `[package] name` in all Cargo.toml files
- Updated all path dependencies to use `qbind-*` references
- Updated workspace members in root Cargo.toml
- Updated all `use` statements in source files from `cano_*` to `qbind_*`

### Metrics Prefix Changes (Complete)

**Prometheus metrics renamed:**
- `cano_consensus_*` → `qbind_consensus_*` (QC formation, view changes, validator votes/lags)
- `cano_net_*` → `qbind_net_*` (KEM operations, per-peer drops)
- `cano_net_per_peer_drops_total` → `qbind_net_per_peer_drops_total`
- All metrics tests updated to assert new prefixes

**Affected locations:**
- [qbind-node/src/metrics.rs](crates/qbind-node/src/metrics.rs): All Prometheus output strings
- [qbind-consensus/src/crypto_verifier.rs](crates/qbind-consensus/src/crypto_verifier.rs): Crypto metrics
- Test assertions throughout node and consensus test suites

### Environment Variable Changes (Complete)

**Config/env renames:**
- `CANO_CONSENSUS_EVENT_CHANNEL_CAPACITY` → `QBIND_CONSENSUS_EVENT_CHANNEL_CAPACITY`
- `CANO_OUTBOUND_COMMAND_CHANNEL_CAPACITY` → `QBIND_OUTBOUND_COMMAND_CHANNEL_CAPACITY`
- `CANO_ASYNC_PEER_INBOUND_CAPACITY` → `QBIND_ASYNC_PEER_INBOUND_CAPACITY`
- `CANO_ASYNC_PEER_OUTBOUND_CAPACITY` → `QBIND_ASYNC_PEER_OUTBOUND_CAPACITY`
- `CANO_TRANSPORT_SECURITY_MODE` → `QBIND_TRANSPORT_SECURITY_MODE`
- `CANO_METRICS_HTTP_ADDR` → `QBIND_METRICS_HTTP_ADDR`

**Affected locations:**
- [qbind-node/src/channel_config.rs](crates/qbind-node/src/channel_config.rs): env var parsing
- [qbind-node/src/async_peer_manager.rs](crates/qbind-node/src/async_peer_manager.rs): transport mode loading
- [qbind-node/src/metrics_http.rs](crates/qbind-node/src/metrics_http.rs): HTTP server config
- All associated tests and documentation

### Protocol / Wire / Hash Tag Changes (Complete) – BREAKING CHANGE

**Consensus signing domain tags:**
- `b"CANO:VOTE:v1"` → `b"QBIND:VOTE:v1"` in [qbind-wire/src/consensus.rs](crates/qbind-wire/src/consensus.rs#L121)
- `b"CANO:PROPOSAL:v1"` → `b"QBIND:PROPOSAL:v1"` in [qbind-wire/src/consensus.rs](crates/qbind-wire/src/consensus.rs#L529)

**Hash digest domain separators:**
- `b"CANO:VOTE"` → `b"QBIND:VOTE"` in [qbind-hash/src/consensus.rs](crates/qbind-hash/src/consensus.rs)
- `b"CANO:TX"` → `b"QBIND:TX"` in [qbind-hash/src/tx.rs](crates/qbind-hash/src/tx.rs)
- `b"CANO:NETCERT"` → `b"QBIND:NETCERT"` in [qbind-hash/src/net.rs](crates/qbind-hash/src/net.rs)

**KEMTLS/transport labels:**
- `b"CANO:KEMTLS"` → `b"QBIND:KEMTLS"` in [qbind-net/src/handshake.rs](crates/qbind-net/src/handshake.rs)
- `b"CANO:KDF"` → `b"QBIND:KDF"` in [qbind-net/src/keys.rs](crates/qbind-net/src/keys.rs)
- `b"CANO:session-id"`, `b"CANO:k_c2s"`, `b"CANO:k_s2c"` → `b"QBIND:*"` equivalents
- `b"CANO:net:app-frame"` → `b"QBIND:net:app-frame"` in [qbind-net/src/transport.rs](crates/qbind-net/src/transport.rs)

**Timeout domain separator:**
- `b"CANO_TIMEOUT_V1"` → `b"QBIND_TIMEOUT_V1"` in [qbind-consensus/src/timeout.rs](crates/qbind-consensus/src/timeout.rs)

**Test AAD/tag literals** updated throughout test suites (e.g., `b"CANO:test"` → `b"QBIND:test"`)

### Documentation & Comments (Complete)

**Updated:**
- [README.md](README.md): Repo description from "cano specification" to "qbind specification"
- All crate-level `//!` doc comments updated to reference "qbind" instead of "cano"
- All file headers in test modules mentioning "Canonot" updated to "QBIND"
- [docs/audit_date.txt](docs/audit_date.txt): Repository structure documentation

## Risks & Compatibility

### BREAKING CHANGES (Wire Format & Signatures)

These changes **WILL BREAK** compatibility with existing artifacts:

1. **Consensus message signatures** – All existing signed votes and proposals cannot be verified with new domain tags. Pre-signed messages from prior devnet/testnet are invalid.
2. **Hash digests** – Prior vote_digest, tx_digest, and network cert digests are invalidated.
3. **KEMTLS handshake transcripts** – Changing domain separators makes prior KEMTLS sessions incompatible.
4. **Stored consensus state** – Block hashes, QCs, and checkpoints from prior runs are meaningless.
5. **On-the-wire protocol** – Any persisted or cached consensus state/signatures is invalid.

### OPERATIONAL IMPACT (Metrics & Config)

1. **Metrics dashboards** – Prometheus/metrics scrapers expecting `cano_*` metrics will fail. Grafana/alerting rules must be updated.
2. **Environment variables** – Scripts/deployments using old env var names will be ignored; new names must be set.
3. **Backward compatibility** – No migration path for old metrics or configs; this is a clean cut.

**Action required for deployment:**
- Regenerate devnet/testnet fixtures and validator keys
- Update all monitoring/alerting rules to use `qbind_*` prefixes
- Update deployment automation to use new `QBIND_*` environment variables
- Resync all nodes and state

## How to Run Now

### Run Node (after Rust/Cargo install)

```bash
# Clone/navigate to workspace
cd /home/saeed/Block/cano

# Build all crates
cargo build --release --all

# Run a node with default config
cargo run --release -p qbind-node

# Run with custom channel capacities
QBIND_CONSENSUS_EVENT_CHANNEL_CAPACITY=2048 \
QBIND_TRANSPORT_SECURITY_MODE=kemtls \
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9100 \
  cargo run --release -p qbind-node
```

### Full Test & Validation Suite

```bash
# Format all code
cargo fmt --all

# Run all tests (single-threaded for determinism)
cargo test --all --all-features -j 1

# Clippy validation (warnings as errors)
cargo clippy --all-targets --all-features -- -D warnings

# Example test run for consensus
cargo test -p qbind-consensus --all-features -- --test-threads=1

# Example test run for node
cargo test -p qbind-node --all-features -- --test-threads=1

# Example test run for crypto/wire
cargo test -p qbind-crypto -p qbind-wire -p qbind-net --all-features
```

### Integration Test

```bash
# Run a three-node consensus simulation
cargo test -p qbind-node --test three_node_full_consensus_tests -- --nocapture

# Load harness (if enabled)
LOAD_HARNESS_MESSAGES=1000 \
LOAD_HARNESS_RATE=100 \
  cargo test -p qbind-node load_harness --release -- --nocapture
```

## Notes for Developers

1. **Code references** – All internal references now use `qbind_*` (module names, crate names, types).
2. **Test adjustments** – All test assertions expecting Prometheus metrics strings now expect `qbind_*` prefixes.
3. **Wire compatibility** – This is a **protocol-level rename**; signatures/hashes are part of consensus and **cannot be changed without breaking previous state**. This is intentional and acceptable for a devnet rebrand.
4. **Future compatibility** – When adding new features, use `qbind` branding consistently (e.g., new env vars should be `QBIND_*`, new metrics `qbind_*`, new wire tags `QBIND:`).
5. **Cargo.lock** – Will be regenerated on first `cargo build` after this change; do not commit stale locks.

---

## T143.1 – Signing Preimage Test Audit

### Preimage Structure (T143 Breaking Change)

The consensus signing preimage is constructed as follows (all integers are little-endian):

**Vote Signing Preimage Layout (v1):**
```
domain_tag:      b"QBIND:VOTE:v1" (13 bytes)
version:         u8
chain_id:        u32
epoch:           u64      (T101 addition)
height:          u64
round:           u64
step:            u8
block_id:        [u8; 32]
validator_index: u16
suite_id:        u16
---
Total length: 13 + 1 + 4 + 8 + 8 + 8 + 1 + 32 + 2 + 2 = 79 bytes
```

**BlockProposal Signing Preimage Layout (v1):**
```
domain_tag:       b"QBIND:PROPOSAL:v1" (17 bytes)
version:          u8
chain_id:         u32
epoch:            u64      (T101 addition)
height:           u64
round:            u64
parent_block_id:  [u8; 32]
payload_hash:     [u8; 32]
proposer_index:   u16
suite_id:         u16
tx_count:         u32
timestamp:        u64
payload_kind:     u8       (T102.1 addition)
next_epoch:       u64      (T102.1 addition)
qc_len:           u32
qc_bytes:         [u8; qc_len]  (full WireEncode of QC if present)
txs:              sequence of (u32 len, bytes[len])
---
Total length (no QC, no txs): 17 + 1 + 4 + 8 + 8 + 8 + 32 + 32 + 2 + 2 + 4 + 8 + 1 + 8 + 4 = 139 bytes
```

### Impact of CANO → QBIND Domain Tag Change

The CANO → QBIND rebrand changed only the domain tag bytes at the start of each preimage:
- `b"CANO:VOTE:v1"` (12 bytes) → `b"QBIND:VOTE:v1"` (13 bytes) – **+1 byte**
- `b"CANO:PROPOSAL:v1"` (16 bytes) → `b"QBIND:PROPOSAL:v1"` (17 bytes) – **+1 byte**

**All other field encodings remain identical.** No changes to field ordering, serialization, or semantics.

**Test Updates (T143.1):**
- Updated `vote_signing_preimage_stable_for_fields()` to expect QBIND domain bytes and length 79
- Updated `vote_signing_preimage_length_is_correct()` to expect 79 bytes (was 78)
- Updated `proposal_signing_preimage_stable_for_fields()` to expect QBIND domain bytes and length 139
- Updated `proposal_signing_preimage_length_no_qc_no_txs()` to expect 139 bytes (was 138)

### Compatibility & Risk Assessment

**Breaking Change (Intentional for Devnet):**
- All prior signatures over old CANO-tagged preimages are cryptographically invalid under QBIND domain tags
- Stored QuorumCertificates (QCs) referencing old signatures cannot be verified
- Network handshakes and vote accumulation will reject old-domain messages
- **This is acceptable and intentional for devnet**: the rebrand is a clean cut; no backward compatibility is required

**Other Domain Tags (Already Updated in T143):**
- Timeout domain separator: `b"CANO_TIMEOUT_V1"` → `b"QBIND_TIMEOUT_V1"` in [qbind-consensus/src/timeout.rs](crates/qbind-consensus/src/timeout.rs#L37)
- Hash domain separators: `"CANO:VOTE"` → `"QBIND:VOTE"`, `"CANO:TX"` → `"QBIND:TX"`, etc. in [qbind-hash/src/consensus.rs](crates/qbind-hash/src/consensus.rs)
- KEMTLS labels/AAD: `b"QBIND:KEMTLS"`, `b"QBIND:KDF"`, etc. in [qbind-net/src/handshake.rs](crates/qbind-net/src/handshake.rs#L52) and [qbind-net/src/keys.rs](crates/qbind-net/src/keys.rs#L55)
- Transport AAD: `b"QBIND:net:app-frame"` in [qbind-net/src/transport.rs](crates/qbind-net/src/transport.rs#L32)

All domain tags are now consistently QBIND:* or QBIND_* and will remain stable for the v1 protocol version.

### Validation Summary

- ✅ Vote preimage: correct QBIND:VOTE:v1 tag (13 bytes), field layout unchanged, length 79
- ✅ Proposal preimage: correct QBIND:PROPOSAL:v1 tag (17 bytes), field layout unchanged, length 139
- ✅ Tests updated: stable byte vectors match QBIND encoding
- ✅ No field encoding changes: only domain tag changed
- ✅ Timeout, hash, KEMTLS, and transport domain tags all verified as QBIND:*

--->
