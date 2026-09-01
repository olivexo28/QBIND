# QBIND Public DevNet — Operator Recovery Package (Run 394)

> **Safety label (applies to every file in this directory):**
> **experimental · resettable · no value · no uptime SLA · no guarantee of data permanence · no
> MainNet readiness claim · no TestNet readiness claim · no C4/C5 closure claim · NOT public-DevNet
> launch-ready.**
>
> This is a **DevNet-only**, **docs / verification-only** package. It deploys **no** seed node,
> bootnode, faucet, RPC gateway, explorer, or status page, and adds **no** CLI flag. Every command
> surface referenced here is a **pre-existing** `qbind-node` flag. Public DevNet is **NOT
> launch-ready** (see `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`). Nothing here is a
> public DevNet launch claim, a public TestNet readiness claim, or a MainNet readiness claim, and
> nothing here moves **M4** or **M6**. **C4 and C5 remain OPEN.**

This directory publishes the canonical **public DevNet operator recovery** material for the four
remaining should-have operator items that are recovery-owned:

- **S1 — snapshot / backup / restore baseline** (`BACKUP_RESTORE.md`): what a DevNet operator may back
  up, what must never be committed, safe stop-before-copy posture, the pre-existing snapshot / restore
  CLI surfaces, genesis-hash pinning after restore, build-provenance recording, expected failure
  handling, and when to wipe-and-rejoin instead of restoring.
- **S2 — DevNet data-retention posture** (`DATA_RETENTION.md`): DevNet data may be reset, operator
  local retention is best-effort with no SLA, suggested local retention windows, redaction rules for
  logs / metrics / evidence, and a cross-link to the reset policy.
- **S3 — binary upgrade / rolling restart procedure** (`UPGRADE_PROCEDURE.md`): verify the release
  artifact / manifest / provenance, stop the node, back up publish-safe metadata, replace the binary,
  restart with the same genesis pin, verify metrics / build info, and the rollback criteria.
- **S4 — rollback procedure** (`ROLLBACK_PROCEDURE.md`): roll back to the previous binary only under
  matching genesis / data assumptions, never roll back trust / authority state by hand, never edit
  sequence / marker files, wipe-and-rejoin rather than force an unsafe rollback, and incident-response
  escalation.

All four documents describe **only** the pre-existing `qbind-node` surfaces and existing ops runbooks.
Run 394 adds **no** production Rust source change and **no** invented CLI flag.

## Package contents

| File | Purpose |
|------|---------|
| `README.md` | This document (index, scope, cross-links, readiness statement). |
| `BACKUP_RESTORE.md` | **S1** — snapshot / backup / restore baseline for DevNet operators. |
| `DATA_RETENTION.md` | **S2** — DevNet data-retention posture (reset / no-SLA / no-value / redaction). |
| `UPGRADE_PROCEDURE.md` | **S3** — binary upgrade / rolling restart tied to release provenance verification. |
| `ROLLBACK_PROCEDURE.md` | **S4** — rollback procedure, fail-closed on unsafe state edits. |
| `SAFETY.md` | User-facing safety label / disclaimer publication for this package. |
| `VERIFY.md` | Exact copy-paste operator verification checks and expected outputs. |

## Pre-existing CLI surfaces referenced (no invented flag)

Every command surface used by this package already exists in `crates/qbind-node/src/cli.rs` and is
visible in `qbind-node --help`:

| Flag | Recovery use |
|------|--------------|
| `--data-dir` / `-d` | Locate the node data directory to stop-and-copy or restore into. |
| `--snapshot-dir` | Where in-process VM-v0 snapshots are written. |
| `--snapshot-interval-blocks` | Committed-height periodic snapshot trigger. |
| `--snapshot-max-snapshots` | Bounded retention of numeric snapshot directories. |
| `--restore-from-snapshot` | Restore-from-snapshot startup path (validates chain id + layout, fails loudly). |
| `--state-retention-mode` | State-retention posture selection. |
| `--state-retain-height` | Retention window (blocks) below head. |
| `--state-prune-interval` | Prune cadence. |
| `--genesis-path` | Genesis source used to (re)derive the pinned genesis hash. |
| `--print-genesis-hash` | Recompute the genesis hash for post-restore pinning. |
| `--expect-genesis-hash` | Fail-closed genesis-hash pin at startup. |

## Canonical location

This is the canonical location for public DevNet **operator recovery** material. It sits alongside the
operator onboarding package (`docs/release/public-devnet/operator/`), the ops package
(`docs/release/public-devnet/ops/`), the observability package
(`docs/release/public-devnet/observability/`), the security package
(`docs/release/public-devnet/security/`), and the network / seed package
(`docs/release/public-devnet/network/`) under the shared `docs/release/public-devnet/` tree.

## Reading order

1. `SAFETY.md` — understand the experimental / resettable / no-value / no-permanence posture first.
2. `BACKUP_RESTORE.md` — what may be backed up and how the pre-existing restore path works.
3. `DATA_RETENTION.md` — how long to keep DevNet data and what to redact.
4. `UPGRADE_PROCEDURE.md` — how to upgrade the binary against verified provenance.
5. `ROLLBACK_PROCEDURE.md` — how to fall back safely, and when to wipe-and-rejoin instead.
6. `VERIFY.md` — reproduce every CLI-surface and doc-structure check.

## Relationship to the existing internal recovery baseline

The canonical **internal** backup / recovery baseline remains
`docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md` (MainNet-readiness scoped: backup taxonomy,
integrity, restore validation, drill cadence). That document is **not** written for the public DevNet
audience. The recovery documents in this directory are the **public-DevNet-scoped** operator-facing
subset: they reference and defer to the internal baseline for backup principles, but scope backup
targets, restore commands, retention windows, upgrade, and rollback to what a third-party DevNet
operator needs on an experimental, resettable, no-value network.

## Cross-links

- Operator onboarding — `docs/release/public-devnet/operator/` (`README.md`, `QUICKSTART.md`,
  `IDENTITY.md`, `SAFETY.md`, `VERIFY.md`).
- Ops (reset policy + incident response) — `docs/release/public-devnet/ops/` (`RESET_POLICY.md`,
  `INCIDENT_RESPONSE.md`).
- Observability (metrics + alerting + runbook) — `docs/release/public-devnet/observability/`
  (`RUNBOOK.md`, `METRICS.md`).
- Network / seed-list posture — `docs/release/public-devnet/network/`.
- Genesis parameters / hash publication — `docs/release/public-devnet/genesis/`.
- Internal backup / recovery baseline — `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md`.
- PQC trust lifecycle runbook — `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`.
- C4/C5 closure criteria — `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`.

## Readiness track relationship

This package targets public DevNet should-have items **S1** (backup/restore), **S2** (data
retention), **S3** (upgrade), and **S4** (rollback), tracked in
`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`. Run 394 publishes and verifies this guidance
against the real CLI/help surfaces and existing ops runbooks (see `VERIFY.md` and
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_394.md`). It does **not** move **M4** (Yellow /
launch-blocking) or **M6** (Yellow / Partial), it does **not** move **S7**, and it does **not** close
**C4** or **C5** — both remain **OPEN**. Because at least one must-have (M4) is not Green, public
DevNet is NOT launch-ready.

## Provenance

Full provenance (git commit, artifact paths + hashes, release-binary SHA-256 / BuildID / toolchain,
CLI/help verification, recovery-package structure checks, non-claim grep, readiness deltas) is
recorded in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_394.md`.