# QBIND MainNet v0 Release Manifest (Example)

**Task**: T239  
**Status**: Design Specification  
**Date**: 2026-02-10

---

## 1. Overview

This document describes the **QBIND MainNet v0 Release Manifest** format and its companion example file. The release manifest is a JSON document that pins all critical artifacts for a reproducible, auditable MainNet release.

**Purpose**:
- Provide a single source of truth for release identity (commit, tag, hashes)
- Enable operators to verify their binaries match the official release
- Support supply-chain auditing and reproducibility requirements
- Document build configuration for deterministic compilation

**Scope**:
- Build scripts + manifest + simple verification commands + doc updates
- **Non-goal**: Full Sigstore / in-toto / SLSA (planned for v0.x+)

---

## 2. Manifest Schema

The release manifest (`QBIND_MAINNET_V0_RELEASE_MANIFEST.example.json`) contains the following top-level sections:

### 2.1 Chain Identity

```json
{
  "chain_id": "qbind-mainnet-v0",
  "protocol_version": "v0"
}
```

| Field | Description | Verification |
| :--- | :--- | :--- |
| `chain_id` | Network identifier | Must match `--expect-genesis-hash` chain |
| `protocol_version` | Protocol major version | Must match node binary protocol |

### 2.2 Git Provenance

```json
{
  "git": {
    "commit": "abcd1234deadbeef5678901234567890abcdef00",
    "tag": "v0.0.0-mainnet-rc1",
    "tree_state": "clean"
  }
}
```

| Field | Description | Verification |
| :--- | :--- | :--- |
| `commit` | Full 40-character Git commit SHA | `git rev-parse HEAD` |
| `tag` | Release tag name | `git describe --exact-match` |
| `tree_state` | Build tree state: `clean` or `dirty` | `git status --porcelain` |

### 2.3 Genesis State

```json
{
  "genesis": {
    "path_hint": "/etc/qbind/genesis.json",
    "sha3_256": "0x...",
    "chain_id": "qbind-mainnet-v0"
  }
}
```

| Field | Description | Verification |
| :--- | :--- | :--- |
| `path_hint` | Suggested filesystem path | Operator convention |
| `sha3_256` | SHA3-256 hash of genesis file | `qbind-node --print-genesis-hash` |
| `chain_id` | Chain ID embedded in genesis | Genesis file inspection |

**Cross-reference**: See [QBIND_MAINNET_V0_SPEC.md §1.6](../mainnet/QBIND_MAINNET_V0_SPEC.md) for genesis hash verification requirements.

### 2.4 Binaries

```json
{
  "binaries": [
    {
      "name": "qbind-node",
      "target": "x86_64-unknown-linux-gnu",
      "sha3_256": "0x..."
    }
  ]
}
```

| Field | Description | Verification |
| :--- | :--- | :--- |
| `name` | Binary name (e.g., `qbind-node`) | Matches release artifact name |
| `target` | Rust target triple | Build target platform |
| `sha3_256` | SHA3-256 hash of binary | `sha3sum <binary>` or build script output |

**Supported targets**:
- `x86_64-unknown-linux-gnu` — Linux x86_64 (Intel/AMD)
- `aarch64-unknown-linux-gnu` — Linux ARM64

**Binaries included**:
- `qbind-node` — Main validator/full node binary ([crates/qbind-node](../../crates/qbind-node))
- `qbind-envelope` — Upgrade envelope verification CLI ([crates/qbind-gov](../../crates/qbind-gov))
- `qbind-remote-signer` — Remote signing daemon ([crates/qbind-remote-signer](../../crates/qbind-remote-signer))

### 2.5 Container Images

```json
{
  "containers": [
    {
      "name": "ghcr.io/qbind/qbind-node",
      "tag": "v0.0.0-mainnet-rc1",
      "digest": "sha256:..."
    }
  ]
}
```

| Field | Description | Verification |
| :--- | :--- | :--- |
| `name` | Container image name (registry/repo) | Container registry URL |
| `tag` | Image tag | Matches release tag |
| `digest` | Content-addressable digest | `docker manifest inspect` |

### 2.6 Build Configuration

```json
{
  "build": {
    "rust_toolchain": "1.78.0",
    "cargo_profile": "release",
    "build_script": "scripts/build-mainnet-release.sh"
  }
}
```

| Field | Description | Verification |
| :--- | :--- | :--- |
| `rust_toolchain` | Rust compiler version | `rustc --version` |
| `cargo_profile` | Cargo build profile | Always `release` for production |
| `build_script` | Path to build script | Repository path |

### 2.7 SBOM (Software Bill of Materials)

```json
{
  "sbom": [
    {
      "artifact": "qbind-node-x86_64-unknown-linux-gnu",
      "format": "cyclonedx-json",
      "path_hint": "sbom/qbind-node-x86_64.json"
    }
  ]
}
```

| Field | Description | Notes |
| :--- | :--- | :--- |
| `artifact` | Associated binary artifact | Matches binary name + target |
| `format` | SBOM format | CycloneDX or SPDX |
| `path_hint` | Suggested path in release archive | Optional |

---

## 3. Operator Verification Workflow

### 3.1 Verify Binary Hashes

After downloading a release binary, operators should verify it against the manifest:

```bash
# Compute SHA3-256 hash of downloaded binary
sha3sum -a 256 /usr/local/bin/qbind-node

# Compare against manifest value
# Expected: 0x1111... (from manifest binaries[].sha3_256)
```

**Using qbind-envelope for verification**:

```bash
# Verify binary against upgrade envelope (if available)
qbind-envelope verify \
  --envelope /path/to/upgrade-envelope.json \
  --council-keys /path/to/council-pubkeys.json \
  --binary /usr/local/bin/qbind-node \
  --platform linux-x86_64
```

### 3.2 Verify Genesis Hash

```bash
# Print genesis hash for local file
qbind-node --print-genesis-hash --genesis-path /etc/qbind/genesis.json

# Start node with expected hash verification
qbind-node --profile mainnet \
  --genesis-path /etc/qbind/genesis.json \
  --expect-genesis-hash 0x... \
  --data-dir /data/qbind
```

**Cross-reference**: See [QBIND_MAINNET_V0_SPEC.md §1.6](../mainnet/QBIND_MAINNET_V0_SPEC.md) for the full genesis verification workflow.

### 3.3 Verify Git Commit

```bash
# Check out the release tag
git checkout v0.0.0-mainnet-rc1

# Verify commit hash matches manifest
git rev-parse HEAD
# Expected: abcd1234... (from manifest git.commit)

# Verify tree is clean
git status --porcelain
# Expected: (empty output)
```

### 3.4 Verify Container Image

```bash
# Pull by digest (immutable)
docker pull ghcr.io/qbind/qbind-node@sha256:...

# Verify digest matches
docker manifest inspect ghcr.io/qbind/qbind-node:v0.0.0-mainnet-rc1 \
  | jq '.config.digest'
```

---

## 4. Build Script

The release build script (`scripts/build-mainnet-release.sh`) produces deterministic binaries:

```bash
# Run the build script
./scripts/build-mainnet-release.sh

# Output: release/bin/<binary>-<target>
# Output: release/hashes.txt (SHA3-256 hashes)
```

**Build requirements**:
- Rust toolchain (version pinned in manifest)
- Cross-compilation toolchains for ARM64 (optional)
- `sha3sum` utility for hash computation

See [`scripts/build-mainnet-release.sh`](../../scripts/build-mainnet-release.sh) for full implementation.

---

## 5. Security Considerations

### 5.1 Supply Chain Risks Mitigated

| Risk | Mitigation |
| :--- | :--- |
| **Binary tampering** | SHA3-256 hashes in manifest |
| **Genesis substitution** | `--expect-genesis-hash` enforcement (T233) |
| **Version confusion** | Git commit + tag pinning |
| **Reproducibility** | Locked dependencies (`Cargo.lock`) |
| **Container tampering** | Digest-based pulls |

### 5.2 Future Enhancements (v0.x+)

- **Sigstore integration**: Keyless signing with transparency log
- **in-toto attestations**: Build provenance metadata
- **SLSA Level 3**: Hermetic builds with provenance

---

## 6. Related Documents

- [QBIND_MAINNET_V0_SPEC.md](../mainnet/QBIND_MAINNET_V0_SPEC.md) — MainNet specification
- [QBIND_MAINNET_RUNBOOK.md](../ops/QBIND_MAINNET_RUNBOOK.md) — Operational procedures
- [QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md](../gov/QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md) — Upgrade envelope format
- [QBIND_MAINNET_AUDIT_SKELETON.md](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md) — Audit tracking (MN-R10)
- [QBIND_EXTERNAL_SECURITY_AUDIT_RFP.md](../audit/QBIND_EXTERNAL_SECURITY_AUDIT_RFP.md) — External audit scope

---

## 7. Example Manifest

See [`QBIND_MAINNET_V0_RELEASE_MANIFEST.example.json`](./QBIND_MAINNET_V0_RELEASE_MANIFEST.example.json) for a complete example with placeholder values.

**Important**: The example manifest contains placeholder hashes (e.g., `0x1111...`). Production manifests will contain actual computed hashes from the release build process.