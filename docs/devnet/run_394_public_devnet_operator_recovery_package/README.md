# Run 394 evidence archive — public DevNet operator recovery package (S1–S4)

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_394_public_devnet_operator_recovery_package.sh` and contains only publish-safe
values: the release-binary SHA-256, BuildID, toolchain, and the OK / POSITIVE status lines. **No secret
key, private material, data dir, snapshot, raw log, or raw metrics dump is committed.**

Regenerate locally with:

```bash
bash scripts/devnet/run_394_public_devnet_operator_recovery_package.sh
```

**Decision gate = Route B** (docs + verification harness; no production Rust source change). The Run 394
recovery package (`docs/release/public-devnet/recovery/README.md`, `BACKUP_RESTORE.md`,
`DATA_RETENTION.md`, `UPGRADE_PROCEDURE.md`, `ROLLBACK_PROCEDURE.md`, `SAFETY.md`, `VERIFY.md`) documents
operator backup/restore, data-retention, upgrade, and rollback using **only** pre-existing `qbind-node`
CLI flags (`--data-dir`, `--snapshot-dir`, `--snapshot-interval-blocks`, `--snapshot-max-snapshots`,
`--restore-from-snapshot`, `--state-retention-mode`, `--state-retain-height`, `--state-prune-interval`,
`--genesis-path`, `--print-genesis-hash`, `--expect-genesis-hash`). Backup/restore is scoped as
best-effort DevNet convenience with **no guarantee of data permanence and no uptime SLA**; wipe-and-rejoin
is the DevNet-safe default. The harness verifies the docs against the **real** `qbind-node` CLI/help
surfaces. It starts no node, opens no externally reachable port, deploys no
seed/bootnode/faucet/RPC/explorer/status page, changes no wire format, weakens no peer admission, and
mutates no trust/validator/epoch/sequence/marker/LivePqcTrustState. No CLI flag is added.

**S1, S2, S3, S4** (should-haves) move **Yellow → Green** (documented + verified against real CLI
surfaces). **M4** stays Yellow/launch-blocking (no externally reachable seed / no independent off-host
vantage), **M6** stays Yellow/Partial (live registration is M4-gated), **S7** stays Yellow (live seed
operation is M4-gated), **M12/M13/M14/M15/M16** remain Green, public DevNet remains **NOT launch-ready**,
and **C4/C5 remain OPEN**. No M4 Green, no M6 Green, and no C4/C5 closure is claimed.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_394.md`.