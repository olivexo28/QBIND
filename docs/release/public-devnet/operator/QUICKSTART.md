# QBIND Public DevNet — External Operator Quickstart (Run 358)

> **Safety label (applies to every file in this directory):**
> **experimental · resettable · no value · no MainNet readiness claim · no C4/C5 closure claim.**

This quickstart tells an external operator how to build QBIND and bring up a DevNet node **locally**
using only **pre-existing** `qbind-node` CLI flags, the Run 356 genesis package, and the Run 357
seed-list format. Run 358 adds **no** CLI flag and changes **no** default behaviour. All commands are
run from the repository root.

## 0. Public DevNet is NOT launch-ready yet

**Public DevNet is NOT launch-ready.** There are **no** externally reachable seeds
(must-have **M4** is Yellow and launch-blocking) and other must-haves (M6–M15) remain unresolved.
Release-binary reproducibility / BuildID (must-have **M3**) is **Green for same-host scope** after
Run 359 (see §3). This quickstart lets you build and run a node
**locally / in dry-run**; it does **not** let you join a live public network, because no live public
network exists yet. See `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` and §11 below.

## 1. Safety label

This DevNet is:

- **experimental** — subject to change without notice;
- **resettable** — the network and any local state may be wiped at any time;
- **no value** — all balances, stakes, and tokens are fixtures with **no** economic value;
- **no MainNet readiness claim** — nothing here implies MainNet readiness;
- **no C4/C5 closure claim** — this run does **not** close C4 or C5.

See `SAFETY.md` for the full disclaimer. Do **not** treat DevNet state as durable or valuable.

## 2. Prerequisites

- **Toolchain:** a working Rust toolchain with `cargo` (stable). The workspace uses Rust
  **edition 2021** (`Cargo.toml`, `crates/qbind-node/Cargo.toml`); no pinned `rust-toolchain` file is
  present, so a recent stable Rust is expected. Build with the standard `cargo` workflow below.
- **Source checkout:** a clone of this repository. All paths in this quickstart are relative to the
  repository root.
- **Python 3** (only for the JSON/seed-list verification steps and the SHA-256 cross-checks; already
  used by the Run 356 / Run 357 `VERIFY.md` docs).
- **No live seed expectation yet:** you do **not** need — and will not be given — any live seed or
  bootnode address. The published seed list is a **placeholder** (see §5).

## 3. Build the release binary

```bash
cargo build -p qbind-node --release
# binary: ./target/release/qbind-node
```

Confirm the binary runs and exposes its help (used by the checks in `VERIFY.md`):

```bash
./target/release/qbind-node --help
```

> To verify the release-binary SHA-256, inspect build inputs, or reproduce the build, see the Run 359
> release-binary provenance package: `docs/release/public-devnet/binary/` (`RELEASE_PROVENANCE.md`,
> `BUILDINFO.md`, `REPRODUCIBILITY.md`, `qbind-node.sha256`, `VERIFY.md`).

## 4. Verify the Run 356 genesis package

The canonical genesis package lives at `docs/release/public-devnet/genesis/`. Verify it before
running anything.

### 4.1 File SHA-256

The published canonical SHA-256 of `devnet-genesis.json` (Run 356) is:

```
d1db07febcf76267f9d3e277a0ff99d06bbe5dffd59d0607799521562ec5c86c
```

This digest is computed over the **LF-normalized** file bytes. Verify it in a line-ending-tolerant
way (recommended, works regardless of whether your checkout materialized the file with LF or CRLF):

```bash
python3 -c "import hashlib; b=open('docs/release/public-devnet/genesis/devnet-genesis.json','rb').read().replace(b'\r\n',b'\n'); print(hashlib.sha256(b).hexdigest())"
```

Expected: `d1db07febcf76267f9d3e277a0ff99d06bbe5dffd59d0607799521562ec5c86c`.

If your checkout materialized the file with LF line endings, the standard checksum file also
verifies directly:

```bash
cd docs/release/public-devnet/genesis && sha256sum -c devnet-genesis.sha256 ; cd - >/dev/null
```

Note: the **authoritative** integrity gate is the canonical genesis hash in §4.2
(`--print-genesis-hash`), which is computed over the *parsed* `GenesisConfig` and is therefore
independent of JSON whitespace and line endings. Use it as the primary check.

### 4.2 Canonical genesis hash with `--print-genesis-hash`

```bash
./target/release/qbind-node --env devnet \
  --genesis-path docs/release/public-devnet/genesis/devnet-genesis.json \
  --print-genesis-hash
```

Expected stdout (canonical Run 101 genesis hash):

```
0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f
```

### 4.3 Pin the canonical hash with `--expect-genesis-hash`

```bash
./target/release/qbind-node --env devnet \
  --genesis-path docs/release/public-devnet/genesis/devnet-genesis.json \
  --expect-genesis-hash 0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f
```

`--genesis-path`, `--print-genesis-hash`, and `--expect-genesis-hash` are **pre-existing** flags
(published in Run 356). On a hash mismatch or malformed genesis, the binary refuses to start with a
typed error before any network/consensus startup.

## 5. The Run 357 seed-list placeholder — do NOT dial it

The seed-list format and a **placeholder** artifact live at `docs/release/public-devnet/network/`:

- Format (JSON Schema draft-07): `devnet-seed-list.schema.json`
- Placeholder artifact: `devnet-seeds.placeholder.json`

The placeholder contains **no live seeds**. Its single entry uses `status: "placeholder"` with a
non-routable **RFC 5737 TEST-NET-1** host (`192.0.2.1`) and `null` `node_id` / `peer_id` /
`validator_address`. **It must not be dialed** — the host is a documentation address and is not
externally reachable.

**How a future live seed list will be used:** when a future run publishes a **live** seed list (real
externally reachable seeds + `last_reachability_evidence`), you will:

1. Fetch the seed list and confirm its `genesis_hash` / `genesis_file_sha256` match the genesis you
   verified in §4.
2. Select **only** entries with `status: "live"`.
3. Start `qbind-node` against those seeds using the pre-existing P2P flags in §8, pinning the
   genesis hash with `--expect-genesis-hash`.

## 6. Full-node local dry-run / local boot

Because there are no live seeds yet, bring up a node **locally** with P2P disabled (the DevNet
default). This exercises the real startup path with the verified genesis and a local data directory:

```bash
./target/release/qbind-node --env devnet \
  --genesis-path docs/release/public-devnet/genesis/devnet-genesis.json \
  --expect-genesis-hash 0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f \
  --data-dir ./devnet-data
```

All flags above are pre-existing. DevNet defaults to `--enable-p2p false` (LocalMesh), preserving the
DevNet v0 freeze; this is a **local** boot, not a public join. Stop the node with `Ctrl-C`.

## 7. Validator-node guidance

- **What is currently possible:** building the binary, verifying the genesis package, and running a
  node **locally** against the DevNet genesis with a local data directory (§6). Signer configuration
  surfaces exist as pre-existing flags — `--signer-mode`, `--signer-keystore-path`,
  `--remote-signer-url`, `--hsm-config-path` — and a `--validator-id` index selector. For consolidated
  key-management (signer modes, private-key `0600` permissions, backup/rotation posture) and PQC
  trust-bundle bootstrap / root/signing-key handling, see the Run 389 security package
  `docs/release/public-devnet/security/` (`KEY_MANAGEMENT.md`, `PQC_TRUST_BOOTSTRAP.md`,
  `PQC_ROOT_AND_SIGNING_KEYS.md`).
- **What remains fixture/internal:** the DevNet genesis validator set is a **fixture** (see the
  Run 356 genesis `README.md` §7). There is **no** externally documented, stable command that
  generates a fresh public validator identity for an external operator to register on a live public
  DevNet, because no live public DevNet exists. See `IDENTITY.md` for the exact gap.
- **What NOT to claim:** do **not** claim you are running a public validator, that your validator is
  part of a live validator set, or that DevNet validation carries any TestNet/MainNet meaning.

## 8. P2P joining guidance (future live seeds only)

Run 358 changes **no** P2P wire format, peer-admission logic, or default network behaviour, and adds
**no** flag. When a future live seed list exists, map its fields onto the **pre-existing** flags:

| Seed-list field | Pre-existing CLI flag |
|-----------------|-----------------------|
| `p2p_multiaddr` / `p2p_host:p2p_port` of a `status: "live"` entry | `--p2p-peer` (repeatable) |
| — (enable networking) | `--enable-p2p` (default `false`) |
| local listen address | `--p2p-listen-addr` |
| advertised address (NAT / LB) | `--p2p-advertised-addr` |
| `transport_security_mode` | `--p2p-mutual-auth` (`required`\|`optional`\|`disabled`) |
| `trust_bundle_required` | `--p2p-trust-bundle` (+ `--p2p-trust-bundle-signing-key`) |
| `expected_genesis_hash` | `--expect-genesis-hash` |

**Only** dial entries with `status: "live"`. **Do not** dial the placeholder entry — its host
(`192.0.2.1`) is a non-routable documentation address.

## 9. Data directory guidance

- **Recommended DevNet data-dir:** a dedicated, disposable local path such as `./devnet-data` passed
  via `--data-dir`. When omitted, the node uses in-memory state only.
- **Resettable / no-value warning:** DevNet state is **resettable** and carries **no value**. Do
  **not** expect balances or state to survive a reset.
- **Cleanup / reset:** stop the node, then remove the data directory to reset local state:

  ```bash
  rm -rf ./devnet-data
  ```

  This deletes only your **local** DevNet data directory; it affects no other network.

- **Reset policy + incident response:** the full DevNet **reset policy** (what a network reset means,
  triggers, notice policy, operator actions, and the reset evidence-record shape) and the
  public-DevNet **incident-response** process are published in `docs/release/public-devnet/ops/`
  (`RESET_POLICY.md`, `INCIDENT_RESPONSE.md`; M15/M16, Run 390).

### 9.1 Optional metrics / observability (M13/M14)

Metrics are **off by default**. To expose a Prometheus `/metrics` endpoint for a
local DevNet node, set `QBIND_METRICS_HTTP_ADDR` to a **loopback** address:

```bash
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9100 \
  qbind-node --network-mode p2p --enable-p2p \
             --p2p-listen-addr 127.0.0.1:0 --validator-id 0 --data-dir ./devnet-data
curl -s http://127.0.0.1:9100/metrics | head
```

- The endpoint has **no authentication and no TLS** — bind it to `127.0.0.1`
  only, never to a public interface, and never publish it on a status page.
- If a central Prometheus must scrape it, front it with a firewalled,
  authenticating reverse proxy.
- Full operator guidance — verified metric families, an example scrape config,
  alert rules with `page`/`ticket`/`observe` severities, and a response runbook —
  is in `docs/release/public-devnet/observability/` (M13/M14, Run 379).

## 10. Troubleshooting

- **Genesis hash mismatch:** `--expect-genesis-hash` failed. Re-verify §4.1/§4.2; ensure you passed
  the exact published hash and the unmodified `devnet-genesis.json`.
- **Invalid seed list:** validate the seed list against the schema (see `network/VERIFY.md`). A
  malformed list or a non-live entry carrying `last_reachability_evidence` is rejected by the schema.
- **P2P disabled by default:** DevNet defaults to `--enable-p2p false`. This is expected; a local
  dry-run does not require P2P.
- **No live seeds yet:** there is nothing to dial. The placeholder host (`192.0.2.1`) is not
  reachable by design. Wait for a future live seed list (M4 → Green).
- **MainNet / TestNet not affected:** every command here uses `--env devnet` only. Nothing in this
  quickstart touches TestNet or MainNet.

## 11. What remains before public DevNet launch

Public DevNet remains **NOT launch-ready**. Outstanding (non-exhaustive; see
`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`):

- **M3 — release-binary reproducibility / BuildID:** **Green (same-host scope, Run 359)**; see
  `docs/release/public-devnet/binary/` (`RELEASE_PROVENANCE.md`, `REPRODUCIBILITY.md`, `BUILDINFO.md`,
  `qbind-node.sha256`, `VERIFY.md`). Cross-host / SLSA / signed-release scope is **not** claimed.
- **M4 — live seed/bootnode list + external reachability evidence:** **Yellow / launch-blocking**
  (format + placeholder only).
- **M6 — operator identity generation:** **Yellow / Partial (first-class generation half Green-for-scope, Run 375)**. To
  generate the peer identity material used by the strict-auth flags above, use the first-class
  `qbind-node identity` command (Run 375):

  ```bash
  qbind-node identity generate devnet full-node "$OUT/node"
  qbind-node identity verify "$OUT/node/leaf.cert.bin"
  qbind-node identity register-check "$OUT/node/public-identity.json" \
      --seed-list docs/release/public-devnet/network/devnet-seeds.placeholder.json \
      --role full-node --cert "$OUT/node/leaf.cert.bin"
  ```

  See the identity package `docs/release/public-devnet/identity/`
  (`IDENTITY_GENERATION.md` / `IDENTITY_VERIFY.md`). The stable, documented,
  release-binary-evidenced generation + verification + **registration /
  admission-check** (Run 376, non-mutating) workflow now exists, but there is
  still **no live registration path** into a running public DevNet (M4-gated) —
  so M6 as a whole stays Yellow / Partial.
- Seed/bootnode reachability: **Run 377** adds a preflight live-seed candidate
  (`docs/release/public-devnet/network/devnet-seeds.live-candidate.json`),
  a reachability record, and a harness that release-proves the `register-check
  --status live --reachability-evidence` gate and a loopback listener dial — but
  **external reachability (from outside the operator host/NAT) is NOT proven**,
  so the candidate stays `status: planned` and **M4 stays Yellow**.
- External reachability, status page, and a seed-node runbook: still outstanding.
- **M13/M14 — telemetry + monitoring/alerting baseline: Green (Run 379)**: the
  operator observability package (`docs/release/public-devnet/observability/`)
  documents safe `/metrics` exposure, verified metric families, an example scrape
  config, alert rules, and a runbook. This does **not** make the DevNet
  launch-ready — M4 (external reachability) is still the blocker.
- Other must-haves (notably M4/M6, M15) remain unresolved (Yellow/Red).

Because at least one must-have is not Green, public DevNet is **not** launch-ready.