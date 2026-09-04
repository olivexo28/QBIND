# QBIND Public DevNet — Artifact Index (Run 403)

> **Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
> NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
> no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN** ·
> no C4/C5 closure claim.

This is the single **navigation index** for the QBIND public DevNet release
package. It exists so an external operator or reviewer can find **every** current
public DevNet artifact — its path, its purpose, the readiness item it covers, how
to verify it, its current status, and what it explicitly does **not** claim —
without reading the whole tree. It is **docs-only**: publishing it deploys
nothing, starts no node, opens no port, adds no CLI flag, changes no runtime
behavior, and moves **no** readiness item Green.

Companion documents:

- `docs/release/public-devnet/PACKAGE_INTEGRITY.md` — the package integrity
  manifest guide: verify the documented package files are present + unchanged
  (SHA-256 + byte size) **before** following the verification map.
- `docs/release/public-devnet/PACKAGE_INTEGRITY_FULL_TREE.md` — the full-tree
  integrity verifier guide: exhaustive, transiently-generated hashing of **every**
  publish-safe file in the package tree.
- `docs/release/public-devnet/PACKAGE_INTEGRITY_CI_ARTIFACTS.md` — the download-only
  CI artifacts guide (Run 406): the transient full-tree manifest + a publish-safe
  anchor-drift report, uploaded for inspection and never committed. Run 407 adds
  `PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json` (machine-readable JSON drift
  report schema) + `PACKAGE_INTEGRITY_CI_RETENTION.md` (CI artifact retention policy).
  Run 408 adds `PACKAGE_INTEGRITY_DRIFT_HISTORY.md` +
  `PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.schema.json` (a local, non-mutating comparator
  for two retained JSON drift reports; manual download; nothing committed).
- `docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md` — recommended read
  orders + the exact verification map + the launch stop rule.
- `docs/release/public-devnet/LAUNCH_GO_NO_GO.md` — the current launch decision
  gate (**NO-GO / NOT launch-ready**).
- `docs/release/public-devnet/BLOCKER_REGISTER.md` — the itemized blocker register
  (M4 / M6 / S5 / S7).
- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — the canonical
  readiness matrix (source of truth for item status).

Everything below reflects the recorded status **after Run 402**. This index adds
navigation and clarity only; it does not re-prove or change any item's status.

## How to read this index

Each artifact group lists:

- **Path** — where the artifacts live.
- **Purpose** — what the group is for.
- **Readiness item** — the matrix item(s) it covers.
- **Verify** — the verification command or document to use.
- **Status** — the current recorded status.
- **Non-claims** — what the group explicitly does **not** assert.

---

## 1. Genesis package

- **Path:** `docs/release/public-devnet/genesis/` — `README.md`, `VERIFY.md`,
  `devnet-genesis.json`, `devnet-genesis.sha256`, `devnet-network-parameters.md`.
- **Purpose:** the frozen public DevNet genesis + network parameters and their
  integrity hash.
- **Readiness item:** M1 / M19 / M20 (Green).
- **Verify:** `docs/release/public-devnet/genesis/VERIFY.md`; confirm
  `sha256sum devnet-genesis.json` matches `devnet-genesis.sha256`; pin the node
  with `--expect-genesis-hash`.
- **Status:** Green (DevNet scope).
- **Non-claims:** DevNet-only, resettable, no value; not a TestNet/MainNet genesis.

## 2. Binary provenance / reproducibility / manifest

- **Path:** `docs/release/public-devnet/binary/` — `README.md`, `BUILDINFO.md`,
  `RELEASE_PROVENANCE.md`, `REPRODUCIBILITY.md`, `VERIFY.md`, `qbind-node.sha256`,
  `RELEASE_ARTIFACT_MANIFEST.example.json`, `RELEASE_ARTIFACT_MANIFEST.schema.json`.
- **Purpose:** release-binary provenance, reproducible-build guidance, and the
  release artifact manifest schema/example.
- **Readiness item:** M2 / M3 (Green).
- **Verify:** `docs/release/public-devnet/binary/VERIFY.md`;
  `scripts/devnet/run_383_public_devnet_release_provenance_injected_repro.sh`,
  `scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh`,
  `scripts/devnet/run_385_public_devnet_ci_release_artifact_manifest.sh`.
- **Status:** Green (DevNet scope).
- **Non-claims:** no signed release attestation is asserted beyond the documented
  provenance/reproducibility scope; the manifest example is example data only.

## 3. Operator quickstart

- **Path:** `docs/release/public-devnet/operator/` — `README.md`, `QUICKSTART.md`,
  `IDENTITY.md`, `SAFETY.md`, `VERIFY.md`.
- **Purpose:** operator onboarding / quickstart / safety envelope.
- **Readiness item:** M5 / M17 / M18 (Green).
- **Verify:** `docs/release/public-devnet/operator/VERIFY.md`; follow `QUICKSTART.md`
  against a local DevNet node.
- **Status:** Green (DevNet scope).
- **Non-claims:** quickstart targets a local/experimental DevNet; it does not imply
  a live public network or an uptime SLA.

## 4. Identity

- **Path:** `docs/release/public-devnet/identity/` — `README.md`,
  `IDENTITY_GENERATION.md`, `IDENTITY_VERIFY.md`, `IDENTITY_CONTINUITY.md`,
  `ROTATION_REVOCATION_DEFERRAL.md`, `OPERATOR_IDENTITY_SCHEMA.json`,
  `EXAMPLE_PUBLIC_IDENTITY.json`, `SAFETY.md`, `VERIFY.md`.
- **Purpose:** operator identity generation, verification, continuity (durable
  reuse across restarts), and the rotation/revocation deferral statement.
- **Readiness item:** M6 (**Yellow / Partial**).
- **Verify:** `docs/release/public-devnet/identity/VERIFY.md`;
  `qbind-node identity generate|verify|print-public|seed-candidate|register-check`;
  `scripts/devnet/run_375_public_devnet_identity_cli.sh`,
  `scripts/devnet/run_376_public_devnet_identity_registration.sh`,
  `scripts/devnet/run_401_public_devnet_m6_identity_continuity.sh`.
- **Status:** **Yellow / Partial** — generation + verification + non-mutating
  `register-check` are Green-for-scope; the **live-registration** half is M4-gated
  and durable-**root** reuse / rotation / revocation is **C4/C5-deferred**.
- **Non-claims:** no production rotation/revocation is implemented; no live
  registration path exists; no C4/C5 closure.

## 5. P2P / peer admission

- **Path:** `docs/release/public-devnet/p2p/` — `P2P_PORT_POSTURE.md`,
  `PEER_ADMISSION_POLICY.md`, `ABUSE_DOS_POSTURE.md`, `VERIFY.md`.
- **Purpose:** P2P port posture, peer admission policy, and abuse/DoS posture.
- **Readiness item:** M10 / M11 / M12 (Green / Green-for-scope).
- **Verify:** `docs/release/public-devnet/p2p/VERIFY.md`;
  `scripts/devnet/run_367_public_devnet_abuse_dos_live_socket_release_binary.sh`,
  `scripts/devnet/run_368_public_devnet_abuse_dos_per_peer_live_socket_release_binary.sh`.
- **Status:** Green-for-scope (DevNet). No live public peer network is deployed.
- **Non-claims:** documents posture only; opens no port and weakens no admission.

## 6. Network / seed-list / M4 checklist

- **Path:** `docs/release/public-devnet/network/` — `README.md`,
  `M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md`, `SEED_NODE_OPERATIONS.md`,
  `SEED_REACHABILITY_EVIDENCE_TEMPLATE.md`, `VERIFY.md`,
  `devnet-seed-list.schema.json`, `devnet-seeds.placeholder.json`,
  `devnet-seeds.live-candidate.json`, `reachability/`.
- **Purpose:** the M4 Route-A deployment checklist, seed-node operations runbook,
  seed-list schema/placeholder, and the reachability evidence template.
- **Readiness item:** M4 (**Yellow / launch-blocking**), S7 (**Yellow**).
- **Verify:** `docs/release/public-devnet/network/VERIFY.md`;
  `scripts/devnet/run_392_public_devnet_seed_ops_route_a_checklist.sh`,
  `scripts/devnet/run_393_public_devnet_m4_real_external_seed_reachability.sh`.
- **Status:** **Yellow** — no real, externally reachable public DevNet seed with
  independent off-host reachability evidence exists; only a **placeholder** and a
  **live-candidate** seed-list are published (no `devnet-seeds.live.json`).
- **Non-claims:** no seed is live; no `devnet-seeds.live.json` exists; do **not**
  create one without real off-host M4 evidence.

## 7. Security / PQC trust bootstrap

- **Path:** `docs/release/public-devnet/security/` — `README.md`,
  `KEY_MANAGEMENT.md`, `PQC_TRUST_BOOTSTRAP.md`, `PQC_ROOT_AND_SIGNING_KEYS.md`,
  `SAFETY.md`, `VERIFY.md`.
- **Purpose:** operator key-management + PQC trust-bootstrap + root/signing-key
  guidance.
- **Readiness item:** M7 / M8 / M9 (Green).
- **Verify:** `docs/release/public-devnet/security/VERIFY.md`;
  `scripts/devnet/run_389_public_devnet_security_key_trust_bootstrap.sh`.
- **Status:** Green (DevNet scope).
- **Non-claims:** guidance only; applies no trust bundle and mutates no
  `LivePqcTrustState`; no key/secret is published.

## 8. Observability / alerting

- **Path:** `docs/release/public-devnet/observability/` — `README.md`,
  `METRICS.md`, `SCRAPE_CONFIG.md`, `ALERT_RULES.md`, `RUNBOOK.md`, `VERIFY.md`,
  `prometheus-scrape.example.yml`, `prometheus-alerts.example.yml`.
- **Purpose:** metrics catalogue, scrape config, alert rules, and runbook for
  loopback-exposed metrics.
- **Readiness item:** M13 / M14 (Green).
- **Verify:** `docs/release/public-devnet/observability/VERIFY.md`;
  `scripts/devnet/run_379_public_devnet_observability_baseline.sh`,
  `scripts/devnet/run_381_public_devnet_observability_gauges.sh`.
- **Status:** Green (DevNet scope). Metrics are loopback-only (no new CLI flag).
- **Non-claims:** examples are example config only; no metrics endpoint is exposed
  externally.

## 9. Ops / reset / incident response

- **Path:** `docs/release/public-devnet/ops/` — `README.md`, `RESET_POLICY.md`,
  `INCIDENT_RESPONSE.md`, `SAFETY.md`, `VERIFY.md`.
- **Purpose:** reset-policy + incident-response operator guidance.
- **Readiness item:** M15 / M16 (Green).
- **Verify:** `docs/release/public-devnet/ops/VERIFY.md`;
  `scripts/devnet/run_390_public_devnet_ops_reset_incident_response.sh`.
- **Status:** Green (DevNet scope).
- **Non-claims:** DevNet is explicitly resettable; guidance only, no live incident
  is implied.

## 10. Recovery / backup / upgrade / rollback

- **Path:** `docs/release/public-devnet/recovery/` — `README.md`,
  `BACKUP_RESTORE.md`, `UPGRADE_PROCEDURE.md`, `ROLLBACK_PROCEDURE.md`,
  `DATA_RETENTION.md`, `SAFETY.md`, `VERIFY.md`.
- **Purpose:** operator backup/restore, upgrade, rollback, and data-retention
  guidance.
- **Readiness item:** operator recovery package (Green-for-scope, Run 394).
- **Verify:** `docs/release/public-devnet/recovery/VERIFY.md`;
  `scripts/devnet/run_394_public_devnet_operator_recovery_package.sh`.
- **Status:** Green-for-scope (DevNet).
- **Non-claims:** procedures target a local/experimental DevNet; no live-network
  guarantee.

## 11. Status decision

- **Path:** `docs/release/public-devnet/status/` — `README.md`,
  `STATUS_PAGE_DECISION.md`, `STATUS_HEALTH_VIEW_SCHEMA.json`,
  `EXAMPLE_STATUS_HEALTH_VIEW.json`, `SAFETY.md`, `VERIFY.md`.
- **Purpose:** the publish-safe **static** status-page decision + frozen health-view
  schema/example.
- **Readiness item:** S5 (**Yellow**).
- **Verify:** `docs/release/public-devnet/status/VERIFY.md`; validate
  `EXAMPLE_STATUS_HEALTH_VIEW.json` against `STATUS_HEALTH_VIEW_SCHEMA.json`.
- **Status:** **Yellow** — a live status / aggregate health view is deferred until
  M4 / a live network. The example is marked `data_source: static-example`.
- **Non-claims:** no live status page is deployed; example data only.

## 12. Launch go / no-go

- **Path:** `docs/release/public-devnet/LAUNCH_GO_NO_GO.md`.
- **Purpose:** the single operator-facing launch **decision gate**.
- **Readiness item:** gates all must-haves (M1–M20).
- **Verify:** `scripts/devnet/run_402_public_devnet_launch_go_no_go_gate.sh`.
- **Status:** **NO-GO / NOT launch-ready** (current decision).
- **Non-claims:** no launch; GO only if every must-have is Green and launch is
  explicitly in scope.

## 13. Blocker register

- **Path:** `docs/release/public-devnet/BLOCKER_REGISTER.md`.
- **Purpose:** the itemized launch blocker register (owner / action /
  evidence-needed / status).
- **Readiness item:** M4 / M6 / S5 / S7 (all Yellow); C4 / C5 (OPEN).
- **Verify:** `scripts/devnet/run_402_public_devnet_launch_go_no_go_gate.sh`.
- **Status:** four launch blockers open; C4/C5 OPEN.
- **Non-claims:** no blocker is cleared by this index; no C4/C5 closure.

## 14. Package integrity manifest

- **Path:** `docs/release/public-devnet/PACKAGE_INTEGRITY.md`,
  `PACKAGE_INTEGRITY_MANIFEST.schema.json`,
  `PACKAGE_INTEGRITY_MANIFEST.example.json`,
  `PACKAGE_INTEGRITY_FULL_TREE.md`,
  `PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.schema.json`,
  `PACKAGE_INTEGRITY_CI_ARTIFACTS.md`,
  `PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json`,
  `PACKAGE_INTEGRITY_CI_RETENTION.md`,
  `PACKAGE_INTEGRITY_DRIFT_HISTORY.md`,
  `PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.schema.json`,
  `PACKAGE_INTEGRITY_STALE_PROSE_LINT.md`.
- **Purpose:** a machine-readable manifest (SHA-256 + byte size) so operators can
  confirm the documented public DevNet package files are present and unchanged
  **before** following `OPERATOR_VERIFICATION_MAP.md`. Two coverage levels: the
  Run 404 **anchor** manifest (one `VERIFY.md` per group + the top-level docs) and
  the Run 405 **full-tree** integrity verification, which hashes **every**
  publish-safe file under the package tree via a transiently-generated manifest
  (never committed). Run 406 additionally emits that transient manifest and a
  publish-safe **anchor-drift report** as **download-only CI artifacts** (never
  committed). Run 407 additionally emits a **machine-readable** JSON anchor-drift report
  (`ANCHOR_DRIFT_REPORT.json`, validated against
  `PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json`) and documents CI artifact
  retention (`PACKAGE_INTEGRITY_CI_RETENTION.md`; download-only, convenience/audit only).
  Run 408 additionally publishes a **local, non-mutating historical comparator**
  (`PACKAGE_INTEGRITY_DRIFT_HISTORY.md` + `PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.schema.json`)
  for two retained `ANCHOR_DRIFT_REPORT.json` reports (manual download; no auto-fetch; no
  token/secret; transient diff never committed).
  Run 410 additionally adds a **stale-prose lint** (`PACKAGE_INTEGRITY_STALE_PROSE_LINT.md`)
  that fails closed if the package-integrity docs/workflow drift on the current **four**
  download-only artifacts (`PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json`,
  `ANCHOR_DRIFT_REPORT.md`, `ANCHOR_DRIFT_REPORT.json`, `PACKAGE_INTEGRITY_CI_SUMMARY.txt`),
  the canonical Run 408 anchor-refresh statement, or any readiness/closure/launch/provenance/
  runtime overclaim.
  This is documentation-tree integrity, **not** binary provenance
  (see group 2 for the release-binary manifest).
- **Readiness item:** package integrity (docs-only; moves nothing).
- **Verify:** `docs/release/public-devnet/PACKAGE_INTEGRITY.md`;
  `scripts/devnet/run_404_public_devnet_package_integrity_manifest.sh`; validate
  `PACKAGE_INTEGRITY_MANIFEST.example.json` against its schema and re-hash each
  listed file. For exhaustive coverage,
  `docs/release/public-devnet/PACKAGE_INTEGRITY_FULL_TREE.md` +
  `scripts/devnet/run_405_public_devnet_full_tree_package_integrity.sh`. For the
  download-only CI artifacts + anchor-drift report,
  `docs/release/public-devnet/PACKAGE_INTEGRITY_CI_ARTIFACTS.md` +
  `scripts/devnet/run_406_public_devnet_full_tree_ci_artifact_anchor_drift.sh`. For the
  machine-readable JSON anchor-drift report + CI artifact retention policy,
  `docs/release/public-devnet/PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json` +
  `docs/release/public-devnet/PACKAGE_INTEGRITY_CI_RETENTION.md` +
  `scripts/devnet/run_407_public_devnet_anchor_drift_json_retention.sh`. For the local,
  non-mutating historical comparator over two retained JSON drift reports,
  `docs/release/public-devnet/PACKAGE_INTEGRITY_DRIFT_HISTORY.md` +
  `docs/release/public-devnet/PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.schema.json` +
  `scripts/devnet/run_408_public_devnet_retained_drift_history_comparator.sh`. For the
  cross-document stale-prose lint that keeps these guides and the CI workflow honest,
  `docs/release/public-devnet/PACKAGE_INTEGRITY_STALE_PROSE_LINT.md` +
  `scripts/devnet/run_410_public_devnet_package_integrity_stale_prose_lint.sh`. For the
  cross-**ledger** consistency lint that keeps the readiness matrix and the contradiction
  ledger in agreement on the Run 402–410 run narratives and the fixed posture,
  `docs/release/public-devnet/READINESS_CONTRADICTION_LEDGER_LINT.md` +
  `scripts/devnet/run_411_public_devnet_readiness_contradiction_ledger_lint.sh`. For the
  per-**milestone** status/blocker consistency lint that keeps the readiness matrix's §10
  current-status table in agreement with its §4/§5 checklists and the blocker register,
  `docs/release/public-devnet/READINESS_STATUS_BLOCKER_LINT.md` +
  `scripts/devnet/run_412_public_devnet_readiness_status_blocker_lint.sh`. For the
  **recommendation/gap-matrix** consistency lint that keeps the readiness matrix's §11 next-run
  recommendation table and §16 consolidated gap matrix in agreement with its §10 current-status
  table, `docs/release/public-devnet/READINESS_RECOMMENDATION_GAP_MATRIX_LINT.md` +
  `scripts/devnet/run_413_public_devnet_readiness_recommendation_gap_matrix_lint.sh`. For the
  **cross-section coverage** lint that keeps the readiness matrix's §11 next-run recommendation
  table and §16 consolidated gap matrix from silently dropping a milestone row that its §10
  current-status table still carries (coverage, not just status),
  `docs/release/public-devnet/READINESS_CROSS_SECTION_COVERAGE_LINT.md` +
  `scripts/devnet/run_414_public_devnet_readiness_cross_section_coverage_lint.sh`.
- **Status:** docs-only; **moves no readiness item** (M4/M6/S5/S7 stay Yellow;
  C4/C5 OPEN; public DevNet NOT launch-ready).
- **Non-claims:** not binary provenance; no signed release / SLSA claim; deploys
  nothing; mutates no runtime state; the full-tree manifest and the anchor-drift
  report are generated transiently and never committed.

---

## Package coverage summary

| Group | Path | Item | Status |
| ----- | ---- | ---- | ------ |
| Genesis | `genesis/` | M1/M19/M20 | Green |
| Binary provenance | `binary/` | M2/M3 | Green |
| Operator quickstart | `operator/` | M5/M17/M18 | Green |
| Identity | `identity/` | M6 | **Yellow / Partial** |
| P2P / admission | `p2p/` | M10/M11/M12 | Green-for-scope |
| Network / seed-list / M4 | `network/` | M4, S7 | **Yellow** |
| Security / PQC trust | `security/` | M7/M8/M9 | Green |
| Observability | `observability/` | M13/M14 | Green |
| Ops / reset / incident | `ops/` | M15/M16 | Green |
| Recovery | `recovery/` | recovery pkg | Green-for-scope |
| Status decision | `status/` | S5 | **Yellow** |
| Launch go/no-go | `LAUNCH_GO_NO_GO.md` | M1–M20 gate | **NO-GO** |
| Blocker register | `BLOCKER_REGISTER.md` | M4/M6/S5/S7; C4/C5 | Yellow; OPEN |
| Package integrity | `PACKAGE_INTEGRITY.md` | package integrity | docs-only (moves nothing) |

All present package paths are listed above. No public DevNet package path is
absent; if a package is later removed, mark it explicitly **absent** here rather
than silently dropping the row.

## C4 / C5 and the contradiction ledger

**C4 remains OPEN. C5 remains OPEN.** MainNet authority rotation/revocation remains
**Red**. This index closes, advances, or reinterprets nothing. See
`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` for the closure criteria and
`docs/whitepaper/contradiction.md` for the contradiction ledger.

## TestNet / MainNet non-claim

TestNet and MainNet remain **untouched**; readiness items N1–N7 remain **Red**.
**No TestNet readiness and no MainNet readiness is claimed** anywhere in this
index.