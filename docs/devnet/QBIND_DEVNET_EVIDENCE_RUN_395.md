# QBIND DevNet Evidence — Run 395

Public DevNet **status-page decision (S5)** and **S6 alert/scrape reconciliation** evidence. Run 395
resolves the two remaining observability-adjacent should-haves:

- **S6** — the readiness matrix previously kept "alert-rule definitions / scrape config shipped
  alongside the metrics baseline" as **Red / "None shipped"** even though **M14** already recorded
  the alert rules, scrape config, runbook, and machine-readable Prometheus examples as shipped and
  YAML-verified in Runs 379–381. Run 395 reconciles this genuine internal inconsistency by moving
  **S6 Red → Green** (Route A) citing the already-shipped observability files — **no** content
  duplicated.
- **S5** — no live status service is deployed (a live aggregate health view depends on M4, which is
  Yellow). Instead a **publish-safe static** status-page decision + future health-view
  schema/example package is published under `docs/release/public-devnet/status/`. **S5 moves Red →
  Yellow** (Route B); live status is deferred until M4.

Harness: `scripts/devnet/run_395_public_devnet_status_s6_reconciliation.sh` (`RESULT=POSITIVE`).

**Decision gate:** S6 = **Route A** (reconcile matrix against shipped package), S5 = **Route B**
(static decision + schema; live deployment deferred). **No** production Rust source change, **no**
`build.rs` change, **no** new CLI flag.

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA · NOT
public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no TestNet readiness · no MainNet
readiness · **C4/C5 OPEN**. Run 395 starts no node, opens no externally reachable port, deploys no
seed/bootnode/faucet/RPC/explorer/status service, changes no P2P wire format, weakens no peer
admission, enables no peer-driven apply, and mutates no
trust/validator/epoch/sequence/marker/`LivePqcTrustState`.

## 1. Exact verdict

**PASS / public-DevNet S5/S6 readiness reconciliation POSITIVE.** The S5 status-page decision +
future health-view schema/example land publish-safe and validated, and S6 is reconciled honestly
against the already-shipped Run 379–381 observability alert/scrape package. **S6 moves Red → Green;
S5 moves Red → Yellow.** **M4 stays Yellow/launch-blocking**, **M6 stays Yellow/Partial**, **S7
stays Yellow**, **M12/M13/M14/M15/M16 remain Green**, public DevNet remains **NOT launch-ready**, and
**C4/C5 remain OPEN**.

## 2. Files changed

No production Rust source or `build.rs` change (docs + schema + harness/archive only).

New:

- `docs/release/public-devnet/status/README.md`
- `docs/release/public-devnet/status/STATUS_PAGE_DECISION.md`
- `docs/release/public-devnet/status/STATUS_HEALTH_VIEW_SCHEMA.json`
- `docs/release/public-devnet/status/EXAMPLE_STATUS_HEALTH_VIEW.json`
- `docs/release/public-devnet/status/SAFETY.md`
- `docs/release/public-devnet/status/VERIFY.md`
- `scripts/devnet/run_395_public_devnet_status_s6_reconciliation.sh`
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_395.md` (this file)
- `docs/devnet/run_395_public_devnet_status_s6_reconciliation/{README.md,summary.txt,.gitignore}`

Updated:

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — Run 395 narrative note; S5/S6 checklist
  rows; S5/S6 summary-table rows; the "status page" gap-table row. **Only S5/S6 rows changed.**

## 3. Decision gate route

- **S6 = Route A** — S6 is already fully satisfied by the Run 379–381 observability package, so the
  matrix is reconciled (Red → Green) with citations to the existing shipped files and harness
  evidence. **No duplicate docs created** (no `SHIPPED_ALERT_SCRAPE_PACKAGE.md`).
- **S5 = Route B** — no live status service exists, so a static status-page decision document +
  future health-view schema/example/redaction rules are published; live deployment is deferred until
  M4. S5 moves Red → Yellow.

## 4. S6 investigation result

The observability package shipped in Runs 379–381 (M13/M14) already provides exactly what S6 asks
for — "alert-rule definitions / scrape config shipped alongside the metrics baseline":

- `docs/release/public-devnet/observability/ALERT_RULES.md` — 11 enabled rules with
  `page`/`ticket`/`observe` severities + a future/not-enabled group.
- `docs/release/public-devnet/observability/SCRAPE_CONFIG.md` — safe loopback scrape guidance.
- `docs/release/public-devnet/observability/RUNBOOK.md` — per-alert operator response.
- `docs/release/public-devnet/observability/prometheus-scrape.example.yml` — machine-readable scrape
  config (parses as YAML).
- `docs/release/public-devnet/observability/prometheus-alerts.example.yml` — machine-readable alert
  rules (parses as YAML).

The only defect was the **stale readiness-matrix S6 row** (Red / "None shipped"), which contradicted
the M14 Green row that cited these same files. This is a documentation inconsistency, not a missing
artifact. Route A is therefore correct.

## 5. S6 package / reconciliation

`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` is updated so that:

- The S6 checklist row moves `- [ ]` → `- [x]` (**Green, reconciled, Route A**) with full-path
  citations to the five shipped observability files and the Run 379/380/381 evidence.
- The S6 summary-table row moves `🔴 | None shipped` → `🟢` with the reconciliation note.
- A Run 395 narrative note documents the reconciliation.

No alert/scrape content is duplicated; the harness re-parses both shipped YAML files to confirm they
still validate.

## 6. S5 status-page decision

`docs/release/public-devnet/status/STATUS_PAGE_DECISION.md` records the decision to **defer a live
status page/aggregate health view until M4 (a live externally reachable network) exists**, because a
live view today would imply a reachable network that is not proven. In its place, Run 395 publishes a
static, clearly-labelled **decision + schema + example** so the shape is fixed and safe before any
live deployment. **S5 → Yellow** (not Green): no externally usable status page is deployed or
maintained. Route A (deploy live) and Route C (defer entirely, keep Red) are explicitly rejected in
the decision doc with reasoning.

## 7. Status / health-view package contents

`docs/release/public-devnet/status/`:

- `README.md` — index, scope, "what this is / is NOT", S6 relationship, cross-links.
- `STATUS_PAGE_DECISION.md` — the S5 decision + rejected routes + fields an eventual live view MUST
  carry.
- `STATUS_HEALTH_VIEW_SCHEMA.json` — draft-07 JSON Schema. Required fields: `genesis` (chain id +
  canonical genesis hash), `build` (version/git_commit/build_id/env), `seed_list` (status + counts;
  `live` requires M4), `readiness` (`public_devnet_launch_ready` fixed `false` + M4/M6 rollups),
  `metrics_endpoint` (`loopback-only`, no address), `alerts` (count-only summary referencing the
  shipped alert package), `notices` (redacted incident/reset summaries). Fixed safety envelope
  (`launch_ready`/`uptime_sla`/`testnet_ready`/`mainnet_ready`/`c4_closed`/`c5_closed` all const
  `false`, plus `example_data_only`). `additionalProperties:false` throughout; no uptime/SLA field
  exists; `notices[].reference` restricted to `docs/...`.
- `EXAMPLE_STATUS_HEALTH_VIEW.json` — illustrative instance; `data_source: static-example`,
  `example_data_only: true`. **Example data only.**
- `SAFETY.md` — mandatory labels, required fields, redaction rules (no private endpoints, raw logs,
  raw metrics dumps, secrets, data dirs, or absolute paths), non-claims.
- `VERIFY.md` — reproducible schema/example/YAML/non-claim checks.

## 8. Schema / example validation

`STATUS_HEALTH_VIEW_SCHEMA.json` passes `jsonschema.Draft7Validator.check_schema`; the example
validates against it. The harness additionally asserts the fixed safety-envelope consts, the absence
of any `uptime` field, and that the example is non-live (`static-example` /`example_data_only:true`/
`launch_ready:false`). `example_validates=OK`, `schema_safety_envelope=OK`.

## 9. Alert / scrape YAML verification

The Run 395 harness re-parses the shipped observability YAML with `yaml.safe_load`:
`prometheus-scrape.example.yml` and `prometheus-alerts.example.yml` both parse. `scrape_yaml=OK`,
`alerts_yaml=OK`.

## 10. Cross-link verification

The harness confirms the readiness-matrix S6 reconciliation references the shipped
`ALERT_RULES.md`, `SCRAPE_CONFIG.md`, `prometheus-scrape.example.yml`, and
`prometheus-alerts.example.yml` (`s6_references_shipped=OK`). The status package cross-links the
observability package, operator/ops/recovery docs, genesis verification, and the readiness matrix.

## 11. Non-claim checks

Normalized non-claim grep over the status docs passes (`non_claim_grep=OK`): no `launch-ready`,
`M4 Green`, `M6 Green`, `C4 closed`, `C5 closed`, `TestNet ready`, `MainNet ready`, or `uptime SLA`
claim. The schema structurally forbids uptime/SLA and hard-codes the non-claim envelope.

## 12. Default compatibility

No default changed. No CLI flag added or altered; metrics exposure stays env-only + loopback-only.
No config, wire format, or admission default touched.

## 13. Runtime mutation check

None. No node started, no port opened, no state written, no
trust/validator/epoch/sequence/marker/`LivePqcTrustState` mutated. Docs + schema + harness only.

## 14. Readiness delta S5

**S5 Red → Yellow.** Static status-page decision + future health-view schema/example published;
live status service explicitly deferred to M4. Not Green (nothing deployed/maintained).

## 15. Readiness delta S6

**S6 Red → Green (reconciled, Route A).** Alert-rule definitions + scrape config already shipped and
YAML-verified under M14 (Runs 379–381); matrix inconsistency resolved with citations; no content
duplicated.

## 16. M4 status

**Yellow / launch-blocking.** Unchanged.

## 17. M6 status

**Yellow / Partial.** Unchanged.

## 18. S7 status

**Yellow.** Unchanged.

## 19. Public DevNet status

**NOT launch-ready.** Unchanged.

## 20. Remaining DevNet blockers

M4 (external seed reachability) is the launch-blocking must-have; M6 (validator identity) remains
Partial. S5 is Yellow (live status deferred to M4); S7 is Yellow (live seed operation M4-gated).

## 21. TestNet blockers

Out of scope. TestNet remains untouched and not started (faucet/RPC/explorer are DevNet non-goals /
TestNet-deferred).

## 22. MainNet blockers

Out of scope. MainNet remains untouched; C4/C5 remain OPEN and are MainNet-gating.

## 23. C4/C5

**Both remain OPEN.** Nothing in this run closes, narrows, or claims progress on C4/C5.

## 24. Tests run

- `bash scripts/devnet/run_395_public_devnet_status_s6_reconciliation.sh` → `RESULT=POSITIVE`.
- JSON Schema validation (draft-07) of `STATUS_HEALTH_VIEW_SCHEMA.json` + example.
- YAML parse of `prometheus-scrape.example.yml` and `prometheus-alerts.example.yml`.
- Non-claim grep over status docs.
- No Rust changed → **no `cargo test`**; recorded honestly as no-Rust-delta.

## 25. Security scans

Secret scan over changed files: no secrets. The status package is docs + schema/example only; no
keys, logs, metrics dumps, data dirs, or absolute paths committed (`committed_private_material=NONE`).

## 26. CodeQL

**Not meaningful for this change** — docs, JSON schema/example, and a bash harness only; no Rust or
`build.rs` change. No CodeQL-analyzable production code was modified.

## 27. Provenance

- Harness: `scripts/devnet/run_395_public_devnet_status_s6_reconciliation.sh`.
- Summary: `docs/devnet/run_395_public_devnet_status_s6_reconciliation/summary.txt`
  (`RESULT=POSITIVE`).
- Underlying S6 evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_379.md`, `_380.md`, `_381.md`.

## 28. Honest limitations

- S5 is **Yellow, not Green**: this is a decision + schema, not a deployed status service. A live
  aggregate health view is not possible while M4 is Yellow.
- The example is illustrative static data; it reflects no live network.
- S6 reconciliation is a documentation correction; it ships no new alert/scrape content (by design).
- The `notices[].summary` free-text field is redaction-constrained by policy, not fully by schema;
  publishers remain responsible for redacting free text.

## 29. Suggested Run 396

Once M4 has a real externally reachable seed, wire a first **read-only** aggregate health-view
generator that emits an instance conforming to `STATUS_HEALTH_VIEW_SCHEMA.json` from real (not
example) data with `data_source: live-scrape`, keeping the loopback-only/no-secrets redaction rules,
and only then evaluate moving S5 Yellow → Green.