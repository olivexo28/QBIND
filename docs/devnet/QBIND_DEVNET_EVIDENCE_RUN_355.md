# QBIND DevNet Evidence — Run 355

Public DevNet release-readiness audit / gap matrix. Kickoff of the public network release-readiness track.

Run 355 is **audit / docs / test-only**. It introduces public DevNet readiness as a tracked, evidence-grounded
classification. It does **not** launch a public DevNet, does **not** deploy seed nodes, a faucet, an explorer, or a
public RPC gateway, does **not** publish a public genesis package as ready, adds **no** public CLI flag, does **not**
enable MainNet, performs **no** runtime authority-lifecycle wiring, performs **no** validator-set mutation, and
performs **no** epoch transition. Full **C4 remains OPEN**, **C5 remains OPEN**, and MainNet authority
rotation/revocation remains **Red**. The Run 353/354 boundary remains **Green-for-scope only**.

## 1. Exact verdict

**PASS (public-DevNet-readiness-audit positive; audit/docs-only; public DevNet NOT launch-ready; Run 353/354
Green-for-scope only; MainNet authority rotation/revocation Red; Full C4 OPEN; C5 OPEN).**

Run 355 lands the public DevNet readiness criteria document, the gap matrix, the required classification, the narrow
protocol/ops/whitepaper doc updates, and this canonical evidence file. The audit is positive: the readiness track is
now tracked with an evidence-grounded matrix. The audit's honest result is that public DevNet is **not yet
launch-ready** — only the incident-response must-have is Green; all other must-haves are Yellow or Red (notably
**Red** for release reproducibility/BuildID and seed/bootnodes). No public DevNet, TestNet, or MainNet readiness is
claimed. C4 and C5 remain OPEN.

## 2. Files changed

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — new canonical public DevNet readiness criteria +
  gap matrix (launch definition, non-goals, safety label, must/should/TestNet-deferred/MainNet-deferred checklists,
  per-item evidence, owners, status, next-run recommendations, blocker summaries, C4/C5 non-closure statement,
  consolidated matrix).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_355.md` — this canonical evidence file.
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — narrow Run 355 note: public DevNet readiness introduced as a
  separate release-readiness track; C4/C5 remain OPEN; Run 353/354 remains Green-for-scope only.
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — narrow Run 355 note.
- `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md` — narrow Run 355 note.
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — narrow Run 355 note (DevNet trust-root bootstrap classified Yellow).
- `docs/whitepaper/contradiction.md` — Run 355 entry.

No production runtime source code was changed. No CLI flag was added. No boundary was wired into runtime.

## 3. Public DevNet readiness definition

An experimental, externally-reachable, resettable network with published genesis+hash+parameters, a
provenance-attested obtainable release binary, a published seed/bootnode list, an external operator quickstart,
published safety disclaimers (experimental / resettable / no value / no readiness claim), and appropriate
incident-response, monitoring, and abuse-handling posture. See
`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` §1.

## 4. Required classification result

All required classification areas are classified in the criteria document §10/§16:

- Green: incident response.
- Yellow (partial): genesis package, release binary provenance, seed onboarding docs, validator onboarding /
  identity / key-management guidance, trust-bundle bootstrap, PQC root/signing-key guidance, public P2P port
  posture, peer admission policy, abuse handling, telemetry/metrics, monitoring/alerting, reset policy, public
  documentation, user-facing disclaimers, network parameter publication, genesis hash publication, snapshot/backup,
  data retention, upgrade/rollback, DevNet authority lifecycle, governance proof status, validator-set rotation status.
- Red: release binary reproducibility/BuildID, seed nodes/bootnodes, status page, alert rules, seed-node runbook,
  runtime wiring for authority lifecycle, MainNet custody, MainNet authority rotation/revocation, C4, C5,
  SLSA-grade provenance, production economic finalization.
- N/A for DevNet (TestNet-deferred): faucet, RPC gateway, RPC rate limiting, explorer, data-retention SLAs,
  soak/chaos/multi-region.

## 5. Current public DevNet readiness status

**NOT launch-ready.** Among the 20 must-have items, only **M16 (incident response)** is Green. Two are Red
(**M3 reproducibility/BuildID**, **M4 seed/bootnodes**); the remainder are Yellow. Public DevNet is therefore not
marked ready.

## 6. Public DevNet blockers

Red: M3 (reproducibility/BuildID), M4 (seed/bootnodes). Yellow-must-reach-Green: M1, M2, M5, M6, M7, M8, M9, M10,
M11, M12, M13, M14, M15, M17, M18, M19, M20.

## 7. Public TestNet blockers

Faucet, public RPC gateway + rate limiting, explorer, governance-proof surface hardening at scale, live
validator-set rotation exercise, data-retention SLAs, soak/chaos/multi-region evidence, plus the TestNet Alpha/Beta
plan exit gates.

## 8. MainNet blockers

MainNet custody, MainNet authority rotation/revocation (**Red**), runtime wiring of the authority-lifecycle chain,
SLSA-grade signed provenance, **C4 closure**, **C5 closure**, production economic finalization, plus the full
MainNet readiness checklist gate.

## 9. C4/C5 status

Full **C4 remains OPEN**. **C5 remains OPEN**. MainNet authority rotation/revocation remains **Red**. The Run
353/354 boundary remains **Green-for-scope only** and is not reinterpreted. Public DevNet readiness is a **separate
release-readiness track**, not C4/C5 closure; C4/C5 closure is not a public DevNet precondition (it is MainNet-deferred).

## 10. Tests run

Run 355 is docs/audit-only and changes **no** source code (`crates/**` untouched). No code path changed, so the
node library behavior is unchanged from accepted Run 354. The repository-standard boundary test command was still
run in full to confirm the unchanged library builds and passes:

```
cargo test -p qbind-node --lib
```

Result: **`test result: ok. 1377 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out`** (finished in ~56s).
The run is unaffected by this run's diff, which touches only Markdown under `docs/`; the pass simply confirms no
regression was introduced.

## 11. Security scans

- **Secret scanning:** run over the changed files (the new readiness criteria doc, this evidence file, and the four
  narrow doc updates). No secrets: the diff is Markdown audit text with no keys, tokens, or credentials.
- **CodeQL:** not meaningful for the Run 355 diff. Run 355 changes only Markdown documentation and adds no source
  code, so CodeQL has no compiled code to analyze for this diff. **No CodeQL coverage is claimed** for Run 355. If
  CodeQL is invoked and skipped/timed-out/unavailable/database-too-large, that exact result is recorded and the diff
  is not called "clean" on that basis.

## 12. Provenance

- `git_commit:` `46acb4c14fde7846bfa197fffa8618d28bf95bfa`
- `git_branch:` `copilot/run-355-fix-bug-in-user-authentication`
- `git_status:` At the moment these Run 355 deliverables are authored the working tree is **dirty**, and the
  dirty/untracked entries are **exactly** the Run 355 deliverables listed in §2 (the new readiness criteria doc,
  this evidence file, and the four narrow doc updates + the whitepaper contradiction entry). After the Run 355
  commit lands these files, the tree is **clean** at that commit. There is no unexplained dirty state: every dirty
  path is an intended Run 355 deliverable.

## 13. Honest limitations

- This is an audit/docs-only run. It publishes no genesis, deploys no infrastructure, and enables nothing.
- Status values are grounded in the current repository state; several Yellow items depend on future publication runs
  and may be revised as evidence lands.
- No CodeQL coverage is claimed (docs-only diff).
- The Run 353/354 Green-for-scope boundary is not wired into runtime and is not reinterpreted; no prior
  Green-for-scope boundary is weakened.

## 14. Suggested Run 356 next step

Begin closing the highest-leverage Yellow must-haves with a single consolidated documentation/publication run:
publish the canonical DevNet **genesis package + network parameters + genesis hash** (M1/M19/M20) with a run that
records the artifact and its hash, moving those three items toward Green. Keep it audit/docs + genesis-artifact only;
do not deploy seeds, faucet, RPC, or explorer; keep C4/C5 OPEN and the Run 353/354 boundary Green-for-scope only.