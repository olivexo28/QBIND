# QBIND Public DevNet — Recovery Package Safety (Run 394)

> **Safety label:** experimental · resettable · no value · no uptime SLA · no guarantee of data
> permanence · no MainNet readiness claim · no TestNet readiness claim · no C4/C5 closure claim · NOT
> public-DevNet launch-ready.

This document states the DevNet-only safety posture for the Run 394 operator recovery package
(`docs/release/public-devnet/recovery/` — backup/restore, data retention, upgrade, rollback). It
restates what is safe to publish, what must **never** be published, and what this package does **not**
claim.

## 1. Safe to publish (public material)

- Publish-safe **provenance**: release-binary **SHA-256** / **BuildID** / **toolchain** and the pinned
  **genesis hash**.
- Public `node_id` / `peer_id` identifiers and published genesis hashes.
- **Summarized** metric counters (e.g. a drop-counter delta) and OK / status lines.
- The recovery **procedures** themselves (this package), which reference only pre-existing CLI flags.

## 2. Must NEVER be published or committed (sensitive material)

- Private keys, KEM secret keys, mnemonics, seed phrases, keystore contents / passwords, HSM secrets,
  credentials, API keys, or tokens.
- **Raw logs**, **raw metrics dumps**, or full `/metrics` scrapes.
- Node **data directories**, raw **snapshot** bodies, or their contents.
- Private / internal infrastructure hostnames, unapproved live endpoints, private endpoints, or
  **absolute build paths**.
- Branch dirty-state strings or any other environment-specific ephemeral state.

## 3. DevNet-only / no-value / resettable / no guarantees

- This package governs recovery operations on an **experimental, resettable, no-value** network.
- DevNet state may be wiped at any time (see `docs/release/public-devnet/ops/RESET_POLICY.md`); prior
  state has **no value** and **no persistence guarantee**.
- There is **no uptime SLA**, **no retention SLA**, and **no guarantee of data permanence**.
- Backup / restore is best-effort convenience; the DevNet-safe default for a corrupt or diverged node
  is **wipe-and-rejoin**, not restore.

## 4. Handling rules

- Keep backup/upgrade/rollback working material (raw logs, raw metrics, data dirs, snapshots)
  **outside any git tree**; only publish-safe values (§1) may be committed.
- Redact before any capture or sharing: remove secrets, private endpoints, private hostnames, and
  absolute build paths.
- Never hand-edit trust / authority / sequence / marker state to force a rollback; wipe-and-rejoin
  instead. The `--authority-state-reset` ceremony is **offline-only** and is not a rollback tool.

## 5. What this package does NOT claim

- It is **not** a public DevNet launch and deploys **no** live seed/bootnode/faucet/RPC/explorer/status
  page.
- It does **not** move **M4** to Green (no live reachability evidence) and does **not** move **M6** to
  fully Green (no live registration path). It does not move **S7**.
- It does **not** close **C4** or **C5**, create MainNet custody, or make any TestNet/MainNet readiness
  claim.
- It changes **no** P2P wire format, weakens **no** peer admission, enables **no** peer-driven apply,
  and mutates **no** trust / validator / epoch / sequence / marker / `LivePqcTrustState`. It adds
  **no** CLI flag; every flag referenced is pre-existing.
