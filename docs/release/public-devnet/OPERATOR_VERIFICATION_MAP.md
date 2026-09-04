# QBIND Public DevNet — Operator Verification Map (Run 403)

> **Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
> NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
> no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN** ·
> no C4/C5 closure claim.

This is the operator/reviewer **verification map** for the QBIND public DevNet
release package. It gives a recommended **read order** for three audiences, an
**exact verification map** (what to run / read to verify each artifact), and a
clear **launch stop rule**. It is the companion to
`docs/release/public-devnet/ARTIFACT_INDEX.md` (the navigation index). It is
**docs-only**: it deploys nothing, starts no node, opens no port, adds no CLI
flag, changes no runtime behavior, and moves **no** readiness item Green.

Source of truth for item status is the canonical readiness matrix
`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`. The current launch
decision is **NO-GO / NOT launch-ready** (`LAUNCH_GO_NO_GO.md`).

## 1. Recommended read order — external operator

1. `docs/release/public-devnet/ARTIFACT_INDEX.md` — find every artifact.
2. `docs/release/public-devnet/PACKAGE_INTEGRITY.md` — **first** confirm the
   documented package files are present and unchanged (SHA-256 + byte size) via the
   package integrity check, before trusting the rest of the package. For exhaustive
   coverage, also run the **full-tree** integrity verifier
   (`docs/release/public-devnet/PACKAGE_INTEGRITY_FULL_TREE.md`), which hashes every
   publish-safe file in the tree, not just the anchor set.
3. `docs/release/public-devnet/operator/SAFETY.md` — understand the DevNet safety
   envelope (experimental, resettable, no value, no SLA).
4. `docs/release/public-devnet/operator/QUICKSTART.md` — bring up a local node.
5. `docs/release/public-devnet/genesis/VERIFY.md` — verify + pin genesis.
6. `docs/release/public-devnet/binary/VERIFY.md` — verify the release binary.
7. `docs/release/public-devnet/identity/IDENTITY_GENERATION.md` +
   `identity/IDENTITY_CONTINUITY.md` — generate a durable identity.
8. `docs/release/public-devnet/security/KEY_MANAGEMENT.md` +
   `security/PQC_TRUST_BOOTSTRAP.md` — key handling + trust bootstrap.
9. `docs/release/public-devnet/observability/RUNBOOK.md` — metrics + alerts.
10. `docs/release/public-devnet/ops/RESET_POLICY.md` +
    `recovery/BACKUP_RESTORE.md` — reset / backup / recovery.
11. `docs/release/public-devnet/LAUNCH_GO_NO_GO.md` — confirm the **NO-GO** posture
    before attempting anything network-facing.

## 2. Recommended read order — security reviewer

1. `docs/release/public-devnet/ARTIFACT_INDEX.md` — scope of artifacts.
2. `docs/release/public-devnet/security/PQC_ROOT_AND_SIGNING_KEYS.md` +
   `security/KEY_MANAGEMENT.md` — root/signing-key + key-management posture.
3. `docs/release/public-devnet/security/PQC_TRUST_BOOTSTRAP.md` — PQC trust
   bootstrap.
4. `docs/release/public-devnet/p2p/PEER_ADMISSION_POLICY.md` +
   `p2p/P2P_PORT_POSTURE.md` + `p2p/ABUSE_DOS_POSTURE.md` — admission + DoS posture.
5. `docs/release/public-devnet/identity/ROTATION_REVOCATION_DEFERRAL.md` — why
   production rotation/revocation is deferred (C4/C5).
6. `docs/release/public-devnet/binary/RELEASE_PROVENANCE.md` +
   `binary/REPRODUCIBILITY.md` — provenance + reproducibility.
7. `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — C4/C5 closure criteria (**OPEN**).
8. `docs/whitepaper/contradiction.md` — contradiction ledger.
9. `docs/release/public-devnet/BLOCKER_REGISTER.md` — open blockers.

## 3. Recommended read order — release manager

1. `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — the canonical matrix.
2. `docs/release/public-devnet/ARTIFACT_INDEX.md` — package coverage.
3. `docs/release/public-devnet/LAUNCH_GO_NO_GO.md` — the decision gate.
4. `docs/release/public-devnet/BLOCKER_REGISTER.md` — M4 / M6 / S5 / S7 blockers.
5. `docs/release/public-devnet/network/M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md` — the
   exact M4 Green prerequisites.
6. `docs/release/public-devnet/network/SEED_REACHABILITY_EVIDENCE_TEMPLATE.md` — the
   reachability evidence format M4 requires.
7. `docs/release/public-devnet/status/STATUS_PAGE_DECISION.md` — S5 deferral.
8. `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` +
   `docs/whitepaper/contradiction.md` — C4/C5 + contradiction ledger.

## 4. Exact verification map

| Verify | How | Reference | Item / status |
| ------ | --- | --------- | ------------- |
| **Package integrity check** | Validate `PACKAGE_INTEGRITY_MANIFEST.example.json` against its schema; re-hash every listed file and confirm each SHA-256 + byte size matches the on-disk tree. Do this **first**. | `PACKAGE_INTEGRITY.md`, `run_404…` | package integrity — docs-only (moves nothing) |
| **Full-tree integrity verification** | Run the full-tree verifier: it generates a transient manifest (outside the tree, never committed) covering **every** publish-safe file under `docs/release/public-devnet`, validates it against `PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.schema.json`, and confirms every file is present with matching SHA-256 + byte size. | `PACKAGE_INTEGRITY_FULL_TREE.md`, `run_405…` | full-tree integrity — docs-only (moves nothing) |
| **Full-tree CI artifacts + anchor drift** | Run the Run 406 wrapper (or download its CI artifacts): it reuses the full-tree verifier and emits, as **download-only** artifacts, the transient full-tree manifest, a publish-safe **anchor-drift report** (curated anchor set vs. full tree), and a CI summary — none committed. | `PACKAGE_INTEGRITY_CI_ARTIFACTS.md`, `run_406…` | full-tree CI artifacts — docs-only (moves nothing) |
| **Machine-readable drift + retention** | Run the Run 407 wrapper (or download its CI artifacts): it reuses the Run 406 wrapper and additionally emits a **machine-readable** `ANCHOR_DRIFT_REPORT.json` (validated against `PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json`, counts agree with the Markdown report); CI artifact retention is documented as download-only convenience/audit usability only — not provenance, not launch evidence. | `PACKAGE_INTEGRITY_CI_RETENTION.md`, `PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json`, `run_407…` | machine-readable drift + retention — docs-only (moves nothing) |
| **Retained drift history comparison** | Manually download two retained `ANCHOR_DRIFT_REPORT.json` artifacts and run the Run 408 comparator: it validates both against `PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json`, emits a transient `PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.json` (validated against `PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.schema.json`), reports added/removed full-tree-only drift, and **fails closed** on any new missing anchor or new undocumented mismatch — no auto-fetch, no token/secret, nothing committed. | `PACKAGE_INTEGRITY_DRIFT_HISTORY.md`, `PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.schema.json`, `run_408…` | retained drift history comparison — docs-only (moves nothing) |
| **Package-integrity stale-prose lint** | Run the Run 410 lint: it fails closed if the package-integrity docs and workflow drift on the current CI artifact set. The workflow uploads **exactly four** download-only artifacts — `PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json`, `ANCHOR_DRIFT_REPORT.md`, `ANCHOR_DRIFT_REPORT.json`, `PACKAGE_INTEGRITY_CI_SUMMARY.txt` — and the lint rejects stale "exactly three" wording, inconsistent artifact names, conflicting Run 408 anchor-refresh statements, non-existent/mismatched manifest anchors, and any readiness/closure/launch/provenance/runtime overclaim. | `PACKAGE_INTEGRITY_STALE_PROSE_LINT.md`, `run_410…` | stale-prose lint — docs-only (moves nothing) |
| **Readiness/contradiction ledger consistency lint** | Run the Run 411 lint: it fails closed if the readiness matrix (`QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`) and the contradiction ledger (`docs/whitepaper/contradiction.md`) disagree on the Run 402–410 run narratives, the fixed posture (M4/M6/S5/S7 Yellow; NO-GO; C4/C5 OPEN; N1–N7 Red; TestNet/MainNet untouched), or the standing non-claims — the cross-ledger companion to the Run 410 stale-prose lint. | `READINESS_CONTRADICTION_LEDGER_LINT.md`, `run_411…` | ledger consistency lint — docs-only (moves nothing) |
| **Readiness status/blocker consistency lint** | Run the Run 412 lint: it fails closed if the readiness matrix's §10 current-status table disagrees with its §4 must-have (M1–M20) or §5 should-have (S1–S7) checklists on any status, if M4/M6/S5/S7 are anything other than Yellow anywhere they appear, if the blocker register (`BLOCKER_REGISTER.md`) omits or resolves M4/M6/S5/S7, or if the launch gate (`LAUNCH_GO_NO_GO.md`) stops being NO-GO / listing M4+M6 as blockers / keeping S5+S7 M4-gated — the per-milestone companion to the Run 411 cross-ledger lint. | `READINESS_STATUS_BLOCKER_LINT.md`, `run_412…` | status/blocker consistency lint — docs-only (moves nothing) |
| **Readiness recommendation/gap-matrix consistency lint** | Run the Run 413 lint: it fails closed if the readiness matrix's §11 next-run recommendation table or §16 consolidated gap matrix disagrees with its §10 current-status table on any scoped M1–M20 / S1–S7 item, if §11/§16 marks M4 resolved/Green/non-blocking or M6 fully-Green, if the §16 seed/bootnodes row drops its Launch-blocker posture or the §16 validator-identity/status-page rows drop their M4-gated posture, if the §16 C4/C5 rows stop being 🔴/OPEN, or if §11/§16 claims launch-ready/GO, C4/C5 closure, TestNet/MainNet readiness, a deployment, or a runtime mutation — the recommendation/gap-matrix companion to the Run 412 status/blocker lint. | `READINESS_RECOMMENDATION_GAP_MATRIX_LINT.md`, `run_413…` | recommendation/gap-matrix consistency lint — docs-only (moves nothing) |
| **Genesis verification** | `sha256sum devnet-genesis.json` matches `devnet-genesis.sha256`; pin node with `--expect-genesis-hash`. | `genesis/VERIFY.md` | M1/M19/M20 — Green |
| **Binary provenance verification** | Verify `qbind-node.sha256`; follow provenance + reproducibility; validate the release artifact manifest against its schema. | `binary/VERIFY.md`, `run_383…`, `run_384…`, `run_385…` | M2/M3 — Green |
| **Identity verification** | `qbind-node identity verify` / `print-public` / non-mutating `register-check`; check continuity guidance. | `identity/IDENTITY_VERIFY.md`, `run_375…`, `run_376…`, `run_401…` | M6 — **Yellow / Partial** |
| **P2P posture verification** | Review port posture + admission policy + abuse/DoS posture; exercise the release-binary abuse/DoS harnesses. | `p2p/VERIFY.md`, `run_367…`, `run_368…` | M10/M11/M12 — Green-for-scope |
| **Observability verification** | Scrape loopback `/metrics`; validate scrape + alert examples; follow the runbook. | `observability/VERIFY.md`, `run_379…`, `run_381…` | M13/M14 — Green |
| **Recovery verification** | Follow backup/restore, upgrade, rollback, data-retention procedures on a local DevNet. | `recovery/VERIFY.md`, `run_394…` | recovery pkg — Green-for-scope |
| **Go/no-go verification** | Run the go/no-go gate harness; confirm decision is **NO-GO** and blockers are M4/M6/S5/S7. | `run_402_public_devnet_launch_go_no_go_gate.sh` | launch gate — **NO-GO** |

(Harness scripts live under `scripts/devnet/`; the `run_NNN…` shorthand above
refers to `scripts/devnet/run_NNN_*.sh`.)

## 5. Launch stop rule

Read and obey these stops before doing anything network-facing:

1. **Do not attempt launch while M4 / M6 are Yellow.** The launch decision is
   **NO-GO** (`LAUNCH_GO_NO_GO.md`). GO requires **every** must-have (M1–M20) Green
   **and** launch explicitly in scope. Neither holds today.
2. **Do not create `devnet-seeds.live.json` without real M4 evidence.** Only a
   `devnet-seeds.placeholder.json` and a `devnet-seeds.live-candidate.json` exist.
   A live seed-list requires a timestamped external TCP dial **and** external
   KEMTLS mutual-auth + PQC static-root handshake from a **genuinely independent
   off-host vantage** (not same-host / same-NAT / same-VPC / RFC 5737), matching
   the published `node_id`, per
   `network/SEED_REACHABILITY_EVIDENCE_TEMPLATE.md` and
   `network/M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md`.
3. **Do not claim TestNet / MainNet readiness.** N1–N7 remain **Red**; `identity
   generate` refuses `mainnet` / `testnet`. No TestNet/MainNet artifact is created
   or implied.
4. **Do not claim C4 / C5 closure.** **C4 remains OPEN. C5 remains OPEN.** Production
   key rotation/revocation is **deferred**, not delivered
   (`identity/ROTATION_REVOCATION_DEFERRAL.md`,
   `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`). See also
   `docs/whitepaper/contradiction.md`.

## 6. Cross-references

- `docs/release/public-devnet/ARTIFACT_INDEX.md` — artifact navigation index.
- `docs/release/public-devnet/PACKAGE_INTEGRITY.md` — package integrity manifest guide (run the package integrity check first).
- `docs/release/public-devnet/PACKAGE_INTEGRITY_FULL_TREE.md` — full-tree integrity verifier guide (exhaustive, transiently-generated coverage of every publish-safe file).
- `docs/release/public-devnet/PACKAGE_INTEGRITY_CI_ARTIFACTS.md` — download-only CI artifacts guide (Run 406): transient full-tree manifest + anchor-drift report, never committed.
- `docs/release/public-devnet/PACKAGE_INTEGRITY_CI_RETENTION.md` — CI artifact retention policy (Run 407): machine-readable JSON anchor-drift report + retention (download-only; convenience/audit only).
- `docs/release/public-devnet/PACKAGE_INTEGRITY_DRIFT_HISTORY.md` — retained anchor-drift history comparator guide (Run 408): compare two retained `ANCHOR_DRIFT_REPORT.json` reports locally (manual download; no auto-fetch; no token/secret; transient diff never committed).
- `docs/release/public-devnet/PACKAGE_INTEGRITY_STALE_PROSE_LINT.md` — package-integrity stale-prose lint guide (Run 410): fails closed if the docs/workflow drift on the current four download-only artifacts (`PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json`, `ANCHOR_DRIFT_REPORT.md`, `ANCHOR_DRIFT_REPORT.json`, `PACKAGE_INTEGRITY_CI_SUMMARY.txt`), the canonical Run 408 anchor-refresh statement, or any readiness/closure/launch/provenance/runtime overclaim.
- `docs/release/public-devnet/READINESS_CONTRADICTION_LEDGER_LINT.md` — readiness/contradiction ledger consistency lint guide (Run 411): fails closed if the readiness matrix and the contradiction ledger disagree on the Run 402–410 run narratives, the fixed posture (M4/M6/S5/S7 Yellow; NO-GO; C4/C5 OPEN; N1–N7 Red; TestNet/MainNet untouched), or the standing non-claims.
- `docs/release/public-devnet/READINESS_STATUS_BLOCKER_LINT.md` — readiness status/blocker consistency lint guide (Run 412): fails closed if the readiness matrix's §10 current-status table disagrees with its §4/§5 checklists on any M1–M20 / S1–S7 status, if M4/M6/S5/S7 are anything other than Yellow anywhere they appear, if the blocker register omits or resolves M4/M6/S5/S7, or if the launch gate stops being NO-GO / listing M4+M6 as blockers / keeping S5+S7 M4-gated.
- `docs/release/public-devnet/READINESS_RECOMMENDATION_GAP_MATRIX_LINT.md` — readiness recommendation/gap-matrix consistency lint guide (Run 413): fails closed if the readiness matrix's §11 next-run recommendation table or §16 consolidated gap matrix disagrees with its §10 current-status table on any scoped M1–M20 / S1–S7 item, if §11/§16 marks M4 resolved/Green/non-blocking or M6 fully-Green, if the §16 seed/bootnodes row drops its Launch-blocker posture or the §16 validator-identity/status-page rows drop their M4-gated posture, if the §16 C4/C5 rows stop being 🔴/OPEN, or if §11/§16 overclaims launch/C4-C5-closure/TestNet-MainNet-readiness/deployment/runtime mutation.
- `docs/release/public-devnet/LAUNCH_GO_NO_GO.md` — launch decision gate.
- `docs/release/public-devnet/BLOCKER_REGISTER.md` — blocker register.
- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — canonical readiness matrix.
- `docs/release/public-devnet/network/M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md` — M4 Green checklist.
- `docs/release/public-devnet/network/SEED_REACHABILITY_EVIDENCE_TEMPLATE.md` — reachability evidence format.
- `docs/release/public-devnet/identity/IDENTITY_CONTINUITY.md` — operator identity continuity (M6).
- `docs/release/public-devnet/identity/ROTATION_REVOCATION_DEFERRAL.md` — rotation/revocation deferral (M6).
- `docs/release/public-devnet/status/STATUS_PAGE_DECISION.md` — status-page decision (S5).
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — C4/C5 closure criteria.
- `docs/whitepaper/contradiction.md` — contradiction ledger.