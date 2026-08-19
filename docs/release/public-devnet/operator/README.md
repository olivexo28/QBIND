# QBIND Public DevNet — External Operator Onboarding (Run 358)

> **Safety label (applies to every file in this directory):**
> **experimental · resettable · no value · no MainNet readiness claim · no C4/C5 closure claim.**
>
> This is a **DevNet-only**, **docs / artifact / verification-only** package. It deploys **no**
> seed node, bootnode, faucet, RPC gateway, explorer, or status page, and adds **no** CLI flag.
> Public DevNet is **NOT launch-ready** (see §6). Nothing here is a public DevNet launch claim, a
> public TestNet readiness claim, or a MainNet readiness claim.

This directory publishes the canonical **external public DevNet operator onboarding** material,
produced under Run 358. It tells a third-party operator how to build and (locally) bring up a QBIND
DevNet full node / validator node using the **existing** repository surfaces, the Run 356 genesis
package, and the Run 357 seed-list format — without inventing any new CLI flag, deploying any
infrastructure, or claiming the network is joinable yet.

## Package contents

| File | Purpose |
|------|---------|
| `README.md` | This document (index, scope, cross-links, launch-readiness statement). |
| `QUICKSTART.md` | Operator-facing bring-up quickstart (build, verify genesis, local boot, join guidance, troubleshooting). |
| `IDENTITY.md` | Identity guidance (node / peer / validator identities; what is safe to publish; existing CLI/config surfaces; honest gaps). |
| `SAFETY.md` | User-facing safety label / disclaimer publication. |
| `VERIFY.md` | Exact operator verification commands and expected outputs for this package. |

## Canonical location

This is the canonical location for external public DevNet operator onboarding material. It sits
alongside the Run 356 genesis package (`docs/release/public-devnet/genesis/`) and the Run 357
seed-list package (`docs/release/public-devnet/network/`) under the shared
`docs/release/public-devnet/` tree. No better pre-existing canonical location existed for a
published external-operator onboarding package, so the new `operator/` subdirectory was created.

## 1. Who this is for

External / third-party operators evaluating QBIND who want to understand how to run a DevNet
full node or validator node from a source checkout. It complements — and does not replace — the
internal `docs/devnet/QBIND_DEVNET_OPERATIONAL_GUIDE.md`.

## 2. What this package uses

- **Run 356 genesis package** — `docs/release/public-devnet/genesis/` (canonical
  `devnet-genesis.json`, its SHA-256, network parameters, and the canonical genesis hash
  `0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f`).
- **Run 357 seed-list format + placeholder** — `docs/release/public-devnet/network/`
  (`devnet-seed-list.schema.json`, `devnet-seeds.placeholder.json`).
- **Pre-existing `qbind-node` CLI surface** — `crates/qbind-node/src/cli.rs`. Run 358 adds **no**
  CLI flag and changes **no** default behaviour.

## 3. What this package does NOT do

- It does **not** launch a public DevNet, deploy seeds/bootnodes, or claim the network is joinable.
- It does **not** add, rename, or hide any CLI flag; every flag it references is pre-existing.
- It does **not** change P2P wire format, peer-admission logic, or default network behaviour.
- It does **not** introduce private keys, mnemonics, seed phrases, credentials, tokens, API keys,
  private infrastructure, real production hostnames, or unapproved live endpoints.
- It does **not** enable MainNet, claim TestNet readiness, close C4 or C5, or wire any
  authority-lifecycle boundary into runtime.

## 4. Reading order

1. `SAFETY.md` — understand the experimental / resettable / no-value posture first.
2. `QUICKSTART.md` — build, verify the genesis package, local dry-run, join guidance.
3. `IDENTITY.md` — node / peer / validator identity concepts and existing surfaces.
4. `VERIFY.md` — reproduce every documentation-safety and CLI-surface check.

## 5. Readiness track relationship

This package targets the public DevNet readiness must-haves **M5** (onboarding quickstart),
**M6** (validator identity guidance), **M17** (public how-to-run-a-node), and **M18** (user-facing
disclaimers), tracked in `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`. Run 358 does
**not** alter **M3** (reproducibility / BuildID — remains Red) or **M4** (seed/bootnodes — remains
Yellow and launch-blocking), because it adds no reproducibility/BuildID evidence and no live-seed
reachability evidence.

## 6. Why public DevNet is still NOT launch-ready

Publishing operator onboarding documentation does not make the network joinable. There are still
**no** externally reachable seeds (M4 remains Yellow / launch-blocking) and **no** documented
release-binary reproducibility / BuildID (M3 remains Red). Because at least one must-have is not
Green, public DevNet is **not** launch-ready. See
`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`.

## Provenance

Full provenance (git commit, branch, clean/dirty state, artifact paths + hashes, Run 356 genesis
hash + file SHA-256, Run 357 schema + placeholder hashes, commands, test results, security scan,
readiness deltas) is recorded in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_358.md`.
