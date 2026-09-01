# QBIND DevNet Evidence — Run 394

Public DevNet **operator recovery** evidence for the should-have items **S1** (snapshot / backup /
restore baseline), **S2** (data-retention posture), **S3** (binary upgrade / rolling restart), and
**S4** (rollback procedure). Run 394 publishes a consolidated, operator-facing recovery package under
`docs/release/public-devnet/recovery/` — `README.md`, `BACKUP_RESTORE.md`, `DATA_RETENTION.md`,
`UPGRADE_PROCEDURE.md`, `ROLLBACK_PROCEDURE.md`, `SAFETY.md`, `VERIFY.md` — and verifies it against the
**real** `qbind-node` CLI/help surfaces via the harness
`scripts/devnet/run_394_public_devnet_operator_recovery_package.sh` (`RESULT=POSITIVE`).

**Decision gate = Route B** (docs + a docs/verification harness; **no** production Rust source change,
**no** `build.rs` change, **no** new CLI flag). Every recovery command surface documented is a
pre-existing `qbind-node` flag; source inspection confirmed the snapshot/restore/retention/genesis
flags already exist, so the guidance is validated against the release binary without inventing
anything.

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA · no guarantee of data
permanence · NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no TestNet readiness ·
no MainNet readiness · **C4/C5 OPEN**. Run 394 starts no node, opens no externally reachable port,
deploys no seed/bootnode/faucet/RPC/explorer/status page, changes no P2P wire format, weakens no peer
admission, enables no peer-driven apply, and mutates no
trust/validator/epoch/sequence/marker/LivePqcTrustState.

## 1. Exact verdict

**PASS / public-DevNet operator recovery package POSITIVE.** The backup/restore baseline, data-retention
posture, upgrade procedure, and rollback procedure are published and verified against real CLI surfaces
with no overclaim. **S1, S2, S3, S4 move Yellow → Green** (should-haves; documented + verified).
**M4 stays Yellow/launch-blocking**, **M6 stays Yellow/Partial**, **S7 stays Yellow**,
**M12/M13/M14/M15/M16 remain Green**, public DevNet remains **NOT launch-ready**, and **C4/C5 remain
OPEN**.

## 2. Files changed

No production Rust source or `build.rs` change (docs + harness/archive only).

New:

- `docs/release/public-devnet/recovery/README.md`
- `docs/release/public-devnet/recovery/BACKUP_RESTORE.md`
- `docs/release/public-devnet/recovery/DATA_RETENTION.md`
- `docs/release/public-devnet/recovery/UPGRADE_PROCEDURE.md`
- `docs/release/public-devnet/recovery/ROLLBACK_PROCEDURE.md`
- `docs/release/public-devnet/recovery/SAFETY.md`
- `docs/release/public-devnet/recovery/VERIFY.md`
- `scripts/devnet/run_394_public_devnet_operator_recovery_package.sh`
- `docs/devnet/run_394_public_devnet_operator_recovery_package/README.md`
- `docs/devnet/run_394_public_devnet_operator_recovery_package/summary.txt`
- `docs/devnet/run_394_public_devnet_operator_recovery_package/.gitignore`
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_394.md` (this record)

Narrowly updated (cross-links + S1–S4 deltas only):

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` (Run 394 update note; S1–S4 checklist +
  status rows + gap-analysis rows + owner rows).

## 3. Decision gate route

**Route B.** Coverage existed but was incomplete: an internal backup baseline
(`docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md`) and real snapshot/restore/retention CLI flags
existed, but no public-DevNet-scoped operator recovery package tying them together. Run 394 adds narrow
public-DevNet docs + a docs/verification harness. It is **not** Route A (existing docs were not already
complete for the public audience) and **not** Route C (the behavior is documentable safely against
pre-existing, fail-closed surfaces without any source change or unproven production guarantee).

## 4. Recovery package contents

| File | Item | Purpose |
|------|------|---------|
| `README.md` | — | Index, scope, pre-existing CLI surface table, cross-links, readiness statement. |
| `BACKUP_RESTORE.md` | S1 | Backup targets, stop-before-copy, must-not-commit, snapshot/restore surfaces, genesis pinning, provenance, failure handling, wipe-and-rejoin. |
| `DATA_RETENTION.md` | S2 | Resettable/no-SLA/no-value posture, retention surfaces, best-effort windows, redaction, reset-policy link. |
| `UPGRADE_PROCEDURE.md` | S3 | Verify provenance → stop → back up metadata → replace binary → restart with same genesis pin → verify build info → rollback criteria. |
| `ROLLBACK_PROCEDURE.md` | S4 | Previous-binary rollback under matching assumptions, no hand-editing trust/authority/sequence/marker state, wipe-and-rejoin default, incident escalation. |
| `SAFETY.md` | — | Publish-safe vs never-publish material, no-guarantee posture, non-claims. |
| `VERIFY.md` | — | Copy-paste operator checks mirroring the harness. |

## 5. Backup/restore guidance (S1)

Covers what may be backed up (`--data-dir` state tree, `--snapshot-dir` numeric snapshots, genesis
source + published hash, publish-safe metadata); what must never be committed (keys, raw
logs/metrics, data dirs, absolute build paths); safe **stop-before-copy** posture; the pre-existing
snapshot creation flags (`--snapshot-dir`, `--snapshot-interval-blocks`, `--snapshot-max-snapshots`)
and the fail-closed `--restore-from-snapshot` startup path (validates chain id + layout, refuses
already-populated state); post-restore **genesis-hash pinning** to
`0x48b3a862…af18145f` via `--print-genesis-hash` / `--expect-genesis-hash`; build-provenance
recording; an expected-failure table; and **when to wipe-and-rejoin instead of restore** (the DevNet
default). Scoped explicitly as best-effort convenience with **no guarantee of data permanence**.

## 6. Data-retention guidance (S2)

Covers that DevNet data may be reset; operator local retention is best-effort with **no SLA and no
value**; on-node retention surfaces (`--state-retention-mode`, `--state-retain-height`,
`--state-prune-interval`, `--snapshot-max-snapshots`); suggested best-effort local retention windows;
redaction rules for logs/metrics/evidence; and a reset-policy cross-link. Formal retention SLAs are
noted as TestNet-deferred (T7) and explicitly not created here.

## 7. Upgrade procedure (S3)

Covers verifying the release artifact / manifest (Run 385 CI workflow) / provenance (SHA-256 /
BuildID / toolchain); stopping the node; backing up publish-safe metadata for the outgoing binary;
replacing the binary (keeping the previous verified binary as a rollback target); restarting with the
**same** `--expect-genesis-hash` pin; verifying `qbind_node_build_info` + peer/height health; and the
rollback criteria. Tied to release-provenance verification throughout.

## 8. Rollback procedure (S4)

Covers rolling back to the previous verified binary **only** under matching genesis + data
assumptions; **never** hand-editing trust/authority/sequence/marker/`LivePqcTrustState` state (no such
operator surface, none invented); wipe-and-rejoin when state compatibility is uncertain; and
incident-response escalation for security-driven rollbacks. Fail-closed on unsafe state edits.

## 9. CLI/help verification

`qbind-node --help` was captured from the release binary and all 11 documented recovery flags were
confirmed present: `--data-dir`, `--snapshot-dir`, `--snapshot-interval-blocks`,
`--snapshot-max-snapshots`, `--restore-from-snapshot`, `--state-retention-mode`,
`--state-retain-height`, `--state-prune-interval`, `--genesis-path`, `--print-genesis-hash`,
`--expect-genesis-hash`. The harness additionally asserts that **no** `--…` token referenced in the
recovery docs is outside the pre-existing allow-list (plus the generic `cargo`/`rustc` example flags
and the pre-existing hidden `--authority-state-reset`), so **no CLI flag is invented**.

## 10. Cross-link verification

Harness confirms the recovery docs cross-link: `docs/release/public-devnet/operator/`,
`docs/release/public-devnet/ops/RESET_POLICY.md`,
`docs/release/public-devnet/ops/INCIDENT_RESPONSE.md`,
`docs/release/public-devnet/observability/`, `docs/release/public-devnet/network/`,
`docs/release/public-devnet/genesis/`, `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md`, and
`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`.

## 11. Non-claim checks

Harness step 10 normalizes each doc (strips markdown emphasis, joins wrapped paragraph lines) and
greps for `launch-ready|M4 Green|M6 Green|C4 closed|C5 closed|TestNet ready|MainNet ready|uptime
SLA|data permanence`, excluding negated occurrences. Result: **no forbidden readiness/closure claim**.

## 12. Default compatibility

No defaults changed. No CLI flag added, no config default altered, no `build.rs`/workflow behavior
changed. All referenced flags retain their pre-existing semantics.

## 13. Runtime mutation check

None. Run 394 starts no node and opens no port; it mutates no
trust/validator/epoch/sequence/marker/`LivePqcTrustState`, changes no P2P wire format, weakens no peer
admission, and enables no peer-driven apply. `--authority-state-reset` is referenced only as a
pre-existing offline ceremony that must **not** be used as a rollback tool.

## 14. Readiness delta — S1

**Yellow → Green.** Backup/restore baseline published (`BACKUP_RESTORE.md`) and verified against the
real, fail-closed `--restore-from-snapshot` path plus snapshot creation/pinning flags. Scoped as
best-effort DevNet convenience with no data-permanence guarantee.

## 15. Readiness delta — S2

**Yellow → Green.** Data-retention posture published (`DATA_RETENTION.md`), explicit about
reset / no-SLA / no-value, with best-effort windows, redaction rules, and reset-policy cross-link.

## 16. Readiness delta — S3

**Yellow → Green.** Upgrade procedure published (`UPGRADE_PROCEDURE.md`), tied to release-artifact /
manifest / provenance verification and same-genesis-pin restart.

## 17. Readiness delta — S4

**Yellow → Green.** Rollback procedure published (`ROLLBACK_PROCEDURE.md`), fail-closed on unsafe
state edits, wipe-and-rejoin when compatibility is uncertain.

## 18. M4 status

**Yellow / launch-blocking.** Unchanged. No externally reachable seed and no independent off-host
vantage exist. Run 394 makes no M4 claim.

## 19. M6 status

**Yellow / Partial.** Unchanged. Live registration remains M4-gated. Run 394 makes no M6 claim.

## 20. S7 status

**Yellow.** Unchanged. Live seed operation remains M4-gated.

## 21. Public DevNet status

**NOT launch-ready.** At least one must-have (M4) is not Green.

## 22. Remaining DevNet blockers

- **M4** (externally reachable seed + independent off-host reachability evidence) — Yellow /
  launch-blocking.
- **M6** live validator registration — Yellow/Partial (M4-gated).
- **S7** live seed operation — Yellow (M4-gated).
- Should-haves **S5** (status page) and **S6** (shipped alert rules / scrape config) remain
  Red / not addressed here.

## 23. TestNet blockers

Untouched. Faucet, public RPC gateway, RPC rate limiting, explorer, validator-set rotation at scale,
formal retention SLAs, and multi-region/soak/chaos evidence remain TestNet-deferred (T1–T8).

## 24. MainNet blockers

Untouched. No MainNet custody, no MainNet readiness claim. C4/C5 remain OPEN.

## 25. C4/C5

**OPEN.** Unchanged. Run 394 makes no C4/C5 closure claim.

## 26. Tests run

- `bash scripts/devnet/run_394_public_devnet_operator_recovery_package.sh` → `RESULT=POSITIVE`
  (includes `cargo build -p qbind-node --release --locked --bin qbind-node`, which succeeded and was
  used for the `--help` provenance checks).
- `cargo test --lib`: **not run — no Rust source changed** (docs + shell harness only). Recorded
  honestly as no-Rust-delta.

## 27. Security scans

- Secret scan over changed files: no secrets. The package is docs + one shell harness; no keys, raw
  logs, raw metrics, data dirs, or absolute build paths are committed (harness step 11 confirms none
  under the recovery package; the evidence archive `.gitignore` excludes ephemeral artifacts).

## 28. CodeQL

**Trivial / not meaningful.** Docs + one shell verification harness only; no Rust or `build.rs`
change. No CodeQL-relevant code path was added or modified.

## 29. Provenance

- git commit: recorded at push time.
- release binary SHA-256: `465071abd1a4d4f02a8019b4de28d6649108cfd69323287200acc9f48d2c2861`
- BuildID: `33ba19951369a13b88fcc580049a8ecead960c09`
- toolchain: `rustc 1.98.0 (88d9e12ae 2026-08-18)` / `cargo 1.98.0 (797e8a9bc 2026-08-05)`
- canonical DevNet genesis hash referenced:
  `0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f`
- harness summary: `docs/devnet/run_394_public_devnet_operator_recovery_package/summary.txt`

## 30. Honest limitations

- Backup/restore is documented as **best-effort DevNet convenience**, not a durability or availability
  guarantee; the DevNet-safe default remains wipe-and-rejoin. S1 Green reflects an operator-usable
  documented baseline over pre-existing surfaces, not a production recovery SLA.
- The harness verifies **documentation structure + CLI-surface existence**; it does **not** execute a
  live snapshot/restore/upgrade/rollback cycle (no node is started). End-to-end restore behavior rests
  on the pre-existing `--restore-from-snapshot` implementation and its own tests, not on Run 394.
- S3/S4 provenance steps reference the Run 385 release-artifact manifest workflow, which emits the
  manifest as a CI artifact (never committed); operators must run that workflow to obtain the manifest.

## 31. Suggested Run 395

Address the two remaining Red should-haves with the same docs+harness discipline: **S6** — ship the
alert-rule definitions / scrape config alongside the observability baseline as a verified public
package (the example `prometheus-*.example.yml` already exist under
`docs/release/public-devnet/observability/`), and scope **S5** (status page / aggregate health view)
as an explicit DevNet decision (publish-safe design + non-claim, or record it as intentionally
deferred). Neither should touch M4/M6/C4/C5.