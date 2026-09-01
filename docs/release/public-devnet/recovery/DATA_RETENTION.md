# QBIND Public DevNet — Data-Retention Posture (S2) (Run 394)

> **Safety label:** experimental · resettable · no value · no guarantee of data permanence · no
> uptime SLA · no MainNet readiness claim · no TestNet readiness claim · no C4/C5 closure claim · NOT
> public-DevNet launch-ready.

This document is the **public-DevNet-scoped** operator data-retention posture (should-have **S2**). It
describes **only** pre-existing `qbind-node` surfaces and defers to the reset policy
`docs/release/public-devnet/ops/RESET_POLICY.md`. It adds **no** CLI flag and makes **no**
MainNet/TestNet readiness or C4/C5 closure claim.

## 1. DevNet data may be reset

- Public DevNet is **experimental** and **resettable**. DevNet state may be **wiped at any time** (see
  `docs/release/public-devnet/ops/RESET_POLICY.md`); prior state has **no value** and **no persistence
  guarantee**.
- A reset re-pins a new genesis; state from before a reset is not migrated and is not recoverable via
  restore across the reset boundary (see `BACKUP_RESTORE.md` §8).

## 2. Operator local retention is best-effort — no SLA

- Any data an operator keeps locally is **best-effort** convenience only. There is **no uptime SLA**,
  **no retention SLA**, and **no value protection**.
- Formal data-retention SLAs are explicitly **TestNet-deferred** (see readiness item T7); this
  document does **not** create one.

## 3. On-node state retention surfaces (pre-existing only)

State pruning / retention is controlled by pre-existing flags (see `crates/qbind-node/src/cli.rs`);
Run 394 invents nothing:

| Flag | Effect |
|------|--------|
| `--state-retention-mode` | Selects the state-retention posture. |
| `--state-retain-height` | State below `current_height - retain_height` may be pruned. |
| `--state-prune-interval` | Cadence at which pruning runs. |
| `--snapshot-max-snapshots` | Bounds how many numeric snapshot directories are retained under `--snapshot-dir`. |

These bound on-disk growth. They do **not** create any durability or availability guarantee.

## 4. Suggested local retention windows (best-effort)

These are **suggestions** for a DevNet operator, not requirements or SLAs:

| Artifact | Suggested local window | Notes |
|----------|------------------------|-------|
| Node data dir (`--data-dir`) | Until next reset or wipe-and-rejoin | Resettable; keep only current chain. |
| Snapshots (`--snapshot-dir`) | Last few via `--snapshot-max-snapshots` | Bound with a small `K`. |
| Publish-safe evidence (hashes, status lines) | Keep across resets if useful | Small, redacted, no secrets. |
| Raw logs / raw metrics dumps | Short-lived, operator-local | Redact before any sharing (§5); never commit. |

## 5. Redaction rules for logs / metrics / evidence

Before sharing or committing **anything** derived from a node:

- Remove private keys, KEM secret keys, mnemonics, keystore contents/passwords, credentials, tokens.
- Remove private/internal hostnames, unapproved live endpoints, and **absolute build paths**.
- Do **not** commit raw logs, raw `/metrics` scrapes, or node data-dir contents. Only **summarized**
  counters (e.g. a drop-counter delta) and publish-safe identifiers/hashes may be recorded.
- Keep raw working material **outside any git tree**.

This mirrors the redaction posture in `docs/release/public-devnet/ops/INCIDENT_RESPONSE.md` and
`docs/release/public-devnet/ops/SAFETY.md`.

## 6. Reset policy cross-link

Retention is bounded above by the reset policy: when DevNet is reset, retained pre-reset state stops
being relevant. Always read `docs/release/public-devnet/ops/RESET_POLICY.md` alongside this document.

## 7. Cross-links

- Backup / restore — `BACKUP_RESTORE.md`.
- Upgrade / rollback — `UPGRADE_PROCEDURE.md`, `ROLLBACK_PROCEDURE.md`.
- Reset policy — `docs/release/public-devnet/ops/RESET_POLICY.md`.
- Observability metrics — `docs/release/public-devnet/observability/METRICS.md`.
- Internal backup / recovery baseline — `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md`.

## 8. Non-claims

This posture does **not** move **M4** or **M6**, does **not** close **C4** or **C5**, and makes
**no** TestNet or MainNet readiness claim. It creates **no** uptime or retention SLA and **no**
guarantee of data permanence. Public DevNet remains **NOT launch-ready**.