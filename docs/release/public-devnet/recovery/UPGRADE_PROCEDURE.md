# QBIND Public DevNet — Binary Upgrade / Rolling Restart (S3) (Run 394)

> **Safety label:** experimental · resettable · no value · no guarantee of data permanence · no
> uptime SLA · no MainNet readiness claim · no TestNet readiness claim · no C4/C5 closure claim · NOT
> public-DevNet launch-ready.

This document is the **public-DevNet-scoped** operator binary-upgrade / rolling-restart procedure
(should-have **S3**). It describes **only** pre-existing `qbind-node` surfaces and ties the upgrade to
**release provenance verification**. It adds **no** CLI flag and makes **no** MainNet/TestNet
readiness or C4/C5 closure claim.

## 1. Scope

- Applies to upgrading a single DevNet `qbind-node` binary in place, then restarting against the
  **same** canonical genesis. On DevNet there is **no uptime SLA**; a brief downtime during restart is
  acceptable.
- This is **not** a coordinated network upgrade / hard-fork procedure and makes no such claim.

## 2. Step 1 — Verify the release artifact / manifest / provenance

Before replacing anything, verify the **new** binary against published provenance:

- Confirm the release-artifact **SHA-256** matches the published value.
- Confirm the **BuildID** (`file <binary>`) and **toolchain** (`rustc --version`) are as expected.
- Confirm the artifact appears in the release manifest
  (`RELEASE_ARTIFACT_MANIFEST.json`, produced by the Run 385 CI workflow
  `.github/workflows/public-devnet-release-artifact-manifest.yml`; the manifest is emitted as a CI
  artifact and is never committed).

Do **not** proceed if provenance does not verify.

## 3. Step 2 — Stop the node

Stop the running node cleanly (SIGTERM / your service manager stop) and confirm it has exited and is
no longer writing to `--data-dir` / `--snapshot-dir`. See `BACKUP_RESTORE.md` §3 (stop-before-copy).

## 4. Step 3 — Back up publish-safe metadata

With the node stopped, take a convenience backup (see `BACKUP_RESTORE.md`) and record publish-safe
provenance for the **outgoing** binary so a rollback target is known:

- Outgoing release-binary **SHA-256** / **BuildID** / **toolchain**.
- Pinned **genesis hash**.
- Optional data-dir / snapshot copy (best-effort only; DevNet is resettable).

## 5. Step 4 — Replace the binary

Replace the `qbind-node` binary with the verified new artifact. Keep the **previous** verified binary
available as the rollback target (see `ROLLBACK_PROCEDURE.md`).

## 6. Step 5 — Restart with the same genesis pin

Restart against the **same** canonical DevNet genesis, fail-closed on any mismatch:

```bash
qbind-node --env devnet \
  --data-dir <DATA_DIR> \
  --genesis-path <GENESIS> \
  --expect-genesis-hash 0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f
```

`--expect-genesis-hash` pins the canonical Run 101 DevNet genesis hash
(`docs/release/public-devnet/genesis/devnet-network-parameters.md`); a mismatch fails closed. Never
change the genesis pin as part of a routine binary upgrade.

## 7. Step 6 — Verify metrics / build info

Confirm the upgraded node reports the expected build and is healthy:

- Scrape `qbind_node_build_info{version,build_id,git_commit,env,chain_id}` and confirm `version` /
  `build_id` / `git_commit` match the new artifact and `env=devnet` / the expected `chain_id`.
- Confirm the node reaches peers and advances height (see
  `docs/release/public-devnet/observability/RUNBOOK.md` and `METRICS.md`).

Metrics are exposed only on the loopback address configured by `QBIND_METRICS_HTTP_ADDR`; Run 394 adds
no new metrics surface.

## 8. Rollback criteria

Roll back (see `ROLLBACK_PROCEDURE.md`) if, after the upgrade:

- the node fails to start or crashes repeatedly;
- `--expect-genesis-hash` fails (genesis mismatch);
- `qbind_node_build_info` does not reflect the intended build;
- the node cannot reach peers or does not advance height, and the cause is attributable to the new
  binary rather than the network.

If state compatibility with the previous binary is **uncertain**, prefer **wipe-and-rejoin**
(`BACKUP_RESTORE.md` §8) over a forced rollback.

## 9. Cross-links

- Rollback — `ROLLBACK_PROCEDURE.md`.
- Backup / restore — `BACKUP_RESTORE.md`.
- Data retention — `DATA_RETENTION.md`.
- Observability — `docs/release/public-devnet/observability/RUNBOOK.md`, `METRICS.md`.
- Reset policy / incident response — `docs/release/public-devnet/ops/RESET_POLICY.md`,
  `docs/release/public-devnet/ops/INCIDENT_RESPONSE.md`.
- Release artifact manifest workflow — `.github/workflows/public-devnet-release-artifact-manifest.yml`.

## 10. Non-claims

This procedure does **not** move **M4** or **M6**, does **not** close **C4** or **C5**, and makes
**no** TestNet or MainNet readiness claim. It provides **no** uptime SLA. Public DevNet remains **NOT
launch-ready**.
