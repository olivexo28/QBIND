# QBIND Public DevNet — Rollback Procedure (S4) (Run 394)

> **Safety label:** experimental · resettable · no value · no guarantee of data permanence · no
> uptime SLA · no MainNet readiness claim · no TestNet readiness claim · no C4/C5 closure claim · NOT
> public-DevNet launch-ready.

This document is the **public-DevNet-scoped** operator rollback procedure (should-have **S4**). It is
**fail-closed on unsafe state edits**: it describes **only** pre-existing `qbind-node` surfaces, adds
**no** CLI flag, and makes **no** MainNet/TestNet readiness or C4/C5 closure claim.

## 1. When to roll back

Roll back only when an upgrade (`UPGRADE_PROCEDURE.md` §8) has clearly regressed the node **and** the
previous binary is a verified, known-good artifact. On DevNet, if you are unsure, **wipe-and-rejoin**
instead (§5).

## 2. Roll back to the previous binary — only under matching assumptions

Roll back to the **previous verified binary** only when **all** of these hold:

- The previous binary's provenance (SHA-256 / BuildID / toolchain) was recorded before the upgrade
  (`UPGRADE_PROCEDURE.md` §4) and re-verifies now.
- The **genesis pin is unchanged**: restart with the same
  `--expect-genesis-hash 0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f`.
- The on-disk **data assumptions match**: the `--data-dir` state was written by a compatible binary,
  or you restore a pre-upgrade snapshot into a fresh `--data-dir`
  (`BACKUP_RESTORE.md` §5).

```bash
# Restart the previous verified binary against the same genesis pin:
qbind-node --env devnet \
  --data-dir <DATA_DIR> \
  --genesis-path <GENESIS> \
  --expect-genesis-hash 0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f
```

## 3. Never roll back trust / authority state by hand

- Do **not** hand-edit, downgrade, or "roll back" trust-bundle, validator-set, authority, or
  `LivePqcTrustState` state. There is no operator surface for this and none is invented here.
- Do **not** edit **sequence** or **marker** files. These are integrity-critical; editing them can
  silently corrupt the node.
- The only reset-related surface is the pre-existing, **hidden**, offline `--authority-state-reset`
  ceremony (Run 127), governed by `docs/release/public-devnet/ops/RESET_POLICY.md`. It is **not** a
  rollback tool and must not be used to "undo" an upgrade.

Any rollback that would require editing trust/authority/sequence/marker state is **out of scope** —
wipe-and-rejoin instead (§5).

## 4. If state compatibility is uncertain

If you cannot confirm that the previous binary can safely read the current `--data-dir` state:

- Do **not** force the rollback.
- Prefer **wipe-and-rejoin** (§5), or restore a pre-upgrade snapshot into a **fresh** `--data-dir`
  using `--restore-from-snapshot` (which fails closed on wrong chain id / wrong layout / already
  populated state — `BACKUP_RESTORE.md` §5, §8).

## 5. Wipe-and-rejoin (DevNet-safe default)

Because DevNet has **no value** and is **resettable**, wipe-and-rejoin is the preferred response to
any uncertain rollback:

1. Stop the node.
2. Remove the `--data-dir` contents.
3. Start fresh against the canonical genesis and current seed list
   (`docs/release/public-devnet/network/`), pinning
   `--expect-genesis-hash 0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f`.
4. Let the node re-sync.

See `BACKUP_RESTORE.md` §8 and `docs/release/public-devnet/ops/RESET_POLICY.md`.

## 6. Incident-response escalation

If a rollback is needed because of a suspected security issue (key compromise, trust-bundle anomaly,
consensus halt), follow `docs/release/public-devnet/ops/INCIDENT_RESPONSE.md`: classify severity,
capture publish-safe evidence (redacted), and escalate per the internal procedure
(`docs/ops/QBIND_INCIDENT_RESPONSE.md`). Never publish raw logs, secrets, or data-dir contents.

## 7. Cross-links

- Upgrade — `UPGRADE_PROCEDURE.md`.
- Backup / restore — `BACKUP_RESTORE.md`.
- Data retention — `DATA_RETENTION.md`.
- Reset policy / incident response — `docs/release/public-devnet/ops/RESET_POLICY.md`,
  `docs/release/public-devnet/ops/INCIDENT_RESPONSE.md`.
- PQC trust lifecycle runbook — `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`.

## 8. Non-claims

This procedure does **not** move **M4** or **M6**, does **not** close **C4** or **C5**, changes **no**
P2P wire format, weakens **no** peer admission, enables **no** peer-driven apply, and mutates **no**
trust / validator / epoch / sequence / marker / `LivePqcTrustState`. It makes **no** TestNet or
MainNet readiness claim and provides **no** uptime SLA. Public DevNet remains **NOT launch-ready**.