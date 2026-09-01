# QBIND Public DevNet — Ops Package Safety (Run 390)

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim · NOT public-DevNet launch-ready.

This document states the DevNet-only safety posture for the Run 390 ops package
(`docs/release/public-devnet/ops/` — reset policy + incident response). It restates what is safe to
publish, what must **never** be published, and what this package does **not** claim.

## 1. Safe to publish (public material)

- Reset **evidence records** using the `RESET_POLICY.md` §7 shape: `reset_id`, `reason`,
  `utc_timestamp`, old/new genesis **hash**, operator action summary, safety statement, no-value
  reminder.
- Minimal **incident summaries** using `INCIDENT_RESPONSE.md` §7: class, severity, UTC window,
  operator impact, operator action required, resolution status.
- Public `node_id` / `peer_id` identifiers, published genesis hashes, release-artifact **SHA-256** /
  **BuildID** / manifest identifiers, and **summarized** metric counters (e.g. a drop-counter delta).

## 2. Must NEVER be published or committed (sensitive material)

- Private keys, KEM secret keys, mnemonics, seed phrases, keystore contents / passwords, HSM secrets,
  credentials, API keys, or tokens.
- **Raw logs**, **raw metrics dumps**, or full `/metrics` scrapes.
- Node **data directories** or their contents.
- Private / internal infrastructure hostnames, unapproved live endpoints, private endpoints, or
  absolute build paths.
- Branch dirty-state strings or any other environment-specific ephemeral state.

## 3. DevNet-only / no-value / resettable / no guarantees

- This package governs operations on an **experimental, resettable, no-value** network.
- DevNet state may be wiped at any time (see `RESET_POLICY.md`); prior state has **no value** and
  **no persistence guarantee**.
- There is **no uptime SLA** and **no value protection**.
- Resets and incident handling never touch, migrate into, or draw readiness conclusions for TestNet
  or MainNet.

## 4. Handling rules

- Keep incident/reset working notes (raw logs, raw metrics, configs) **outside any git tree**; only
  the publish-safe record shapes (§1) may be committed.
- Redact config before capture: remove secrets, private endpoints, private hostnames, and absolute
  build paths.
- The `--authority-state-reset` ceremony is **offline-only** and writes only a publish-safe audit
  record path you control; never commit its raw inputs (genesis/ratification material) or any
  generated marker/state.

## 5. What this package does NOT claim

- It is **not** a public DevNet launch and deploys **no** live seed/bootnode/faucet/RPC/explorer/status
  page.
- It does **not** move **M4** to Green (no live reachability evidence) and does **not** move **M6** to
  fully Green (no live registration path).
- It does **not** close **C4** or **C5**, create MainNet custody, or make any TestNet/MainNet readiness
  claim.
- It changes **no** P2P wire format, weakens **no** peer admission, enables **no** peer-driven apply,
  and mutates **no** trust/validator/epoch/sequence state. `--authority-state-reset` is a pre-existing
  offline ceremony, not a live governance / authority-lifecycle / C4-C5 closure surface.
