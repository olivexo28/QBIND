# QBIND Public DevNet — Critical Path (Run 422 D7-D14)

> **Safety label:** DevNet · experimental · resettable · no value · NOT public-DevNet
> launch-ready · **RS1 OPEN / launch-blocking** · M4 Yellow / launch-blocking · M6 Yellow /
> Partial · S5 Yellow · S7 Yellow · **C4/C5 OPEN** · no TestNet readiness · no MainNet readiness.

This is a planning artifact only. It starts no node, opens no port, deploys nothing, changes no
runtime behaviour, and moves **no** readiness item Green. It synthesizes the governing documents
below into one public-DevNet launch critical path. It does not invent a completion percentage or a
launch date; genuinely unknown estimates are marked `UNKNOWN` with the condition that would
resolve them.

**Governing sources (read for this plan).**

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — canonical readiness matrix (M1–M20,
  S1–S7). Current canonical status: M1–M3, M5, M7–M20 **Green**; **M4 Yellow / launch-blocking**;
  **M6 Yellow / Partial**; S1–S4, S6 **Green**; **S5 Yellow**; **S7 Yellow**; C4/C5 **OPEN**.
- `docs/release/public-devnet/BLOCKER_REGISTER.md` and `.../LAUNCH_GO_NO_GO.md` — operator-facing
  blocker register and launch gate (current decision **NO-GO / NOT launch-ready**).
- `docs/protocol/QBIND_FOUNDATIONAL_RUNTIME_SECURITY_RECONCILIATION.md` and
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_417.md` — RS1 and its findings **F1–F8**.
- RS1 remediation evidence: Runs 418 (F6 code/test), 419 (F6 partial release-binary), 420 (F3/F4/F8
  code/test), 421 (F3/F4/F8 unavailable-authority release-binary), 422 + D4/D5/D6/D7 (genesis-bound
  authority **DISABLED**; domain-v2 signing; `DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`).
- `docs/devnet/QBIND_DEVNET_READINESS_AUDIT.md` — EXE-era binary-path readiness (restore, multi-node
  interconnect, observability, packaging).
- `docs/whitepaper/contradiction.md` — C4 (authority/trust-anchor) and C5 (governance/lifecycle).

**Launch rule (from `BLOCKER_REGISTER.md` / `LAUNCH_GO_NO_GO.md` §9).** Public DevNet **GO requires
both** (1) every required M1–M20 item Green **and** (2) RS1 closed with executable evidence that
the deployed consensus path is fail-closed, **and** that a public DevNet launch is explicitly in
scope. While any blocker is open — **including RS1, even if every M1–M20 item were Green** — the
decision is **NO-GO**.

---

## 1. Launch-blocker critical-path table

`Requirement | Governing source | Current evidence | Remaining work | Dependencies | Responsible role | Completion evidence | Estimated effort`

| Requirement | Governing source | Current evidence | Remaining work | Dependencies | Responsible role | Completion evidence | Estimated effort |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **RS1 — deployed consensus path fail-closed (F1–F8)** | `BLOCKER_REGISTER.md` RS1; `QBIND_FOUNDATIONAL_RUNTIME_SECURITY_RECONCILIATION.md`; Run 417 | OPEN / launch-blocking. F6 code/test (418) + partial release-binary (419); F3/F4/F8 code/test (420) + unavailable-authority release-binary (421); genesis-bound authority **DISABLED** (422, release binary refuses `--consensus-authority-from-genesis` exit 1); domain-v2 signing isolated (D6); authority-lifetime guard **PARTIAL**, `DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED` (D7) | Wire the verified signing/QC/timeout path into the **deployed** `binary_consensus_loop`; enable configured genesis authority; capture **configured-authority** release-binary adversarial evidence (unsigned / mismatched-identity / wrong-suite / forged-QC rejected with counters); resolve F1/F2 before transaction ingress; make F5/F7 (timeout/new-view + QC) verification mandatory on the deployed path | None internal (longest chain root). External: owner decision to enable activation | Protocol / consensus | Deployed-path (not harness) executable evidence per Run 417 reconciliation: rejections with counters for all RS1 vectors; `CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=CAPTURED` | **UNKNOWN (large).** 8 findings, production wiring, durable anti-rollback infra. Resolved by: a scoped per-finding remediation plan with release-binary evidence (next unit = Run 423 configured-authority evidence) |
| **M4 — durable published live seed** | `BLOCKER_REGISTER.md` M4; `network/M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md`; Run 416 | Yellow / launch-blocking. External reachability PROVEN once (Run 416, Route A) against a **temporary** seed with discarded PQC material; no durable published `devnet-seeds.live.json` | Deploy a durable seed on a routable public host (strict KEMTLS mutual-auth + PQC static-root, Run 356 genesis pinned); verify from a genuinely independent off-host vantage; promote to a schema-valid durable live seed-list entry with non-null `last_reachability_evidence` | External host provisioning; durable PQC seed identity (owner-provisioned) | Seed operator | Timestamped external TCP dial + external KEMTLS mutual-auth/static-root handshake from an independent off-host vantage matching the published `node_id`; durable `devnet-seeds.live.json` entry; live `register-check` fails closed without evidence | **UNKNOWN (ops-bounded).** Deployment is days once a host + durable identity are provisioned; resolved by an owner provisioning decision |
| **M6 — live operator identity continuity** | `BLOCKER_REGISTER.md` M6; `identity/IDENTITY_CONTINUITY.md`, `identity/ROTATION_REVOCATION_DEFERRAL.md` | Yellow / Partial. Generation + verification + non-mutating `register-check` Green-for-scope; live-registration half is **M4-gated**; durable-root rotation/revocation is **C4/C5-deferred** | After M4 Green, register a continuous operator identity into the live network; prove durable `node_id`/`peer_id` reuse across DevNet restarts. Do **not** attempt durable-root rotation/revocation until C4/C5 scoped | **M4 Green** (and C4/C5 for the rotation/revocation sub-item only) | Validator/seed operator (+ Protocol for C4/C5) | Operator identity admitted into the **live** seed list with persistent published identity across restarts | **UNKNOWN until M4.** Live-registration proof is hours-to-days once M4 is Green |
| **S5 — live status / health view** | `BLOCKER_REGISTER.md` S5; `status/STATUS_PAGE_DECISION.md` | Yellow. Publish-safe static decision + frozen schema published; no live status page (would misrepresent a non-operating network) | After M4 Green, deploy a live health view wired to the real network using the frozen schema | **M4 Green** | Ops / status | A live, externally usable status page reflecting a real durably operating network | **UNKNOWN until M4.** Small once M4 Green |
| **S7 — live seed operation** | `BLOCKER_REGISTER.md` S7; `network/SEED_NODE_OPERATIONS.md` | Yellow. Runbook + M4 Route-A checklist + evidence template published; operating a real live seed is M4-gated | Execute the published runbook against real external infrastructure as part of the M4 Route-A run | **M4 Green** (same off-host reachability evidence) | Seed operator | A real live seed operated + verified externally | **UNKNOWN until M4.** Co-executed with M4 |
| **Launch go/no-go flip** | `LAUNCH_GO_NO_GO.md` §9 | NO-GO / NOT launch-ready | Flip to GO only when every must-have M1–M20 is Green, RS1 is closed, and a public DevNet launch is explicitly in scope | RS1 closed **and** M4/M6 Green (S5/S7 as required) | Owner / release decision | Updated readiness matrix with all must-haves Green + RS1 closed + explicit launch-in-scope decision | Derived (follows the above) |

---

## 2. Completed isolated-component work (inputs, not launch gates)

These are complete at the component/code-test level and are **not** launch blockers by themselves;
they feed the RS1 / production-integration work above but do not move any readiness item Green on
their own:

- **Safety-record storage candidate — `D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED`,
  `D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET`** (accepted 23-row subset only; disabled-by-default;
  see `run_422_d7d14_fixed_candidate_assurance/independent_review/00_review_report.md`). Isolated
  storage logic only — no production wiring, stage-2 verification, anti-rollback, or activation.
- **Domain-v2 Proposal/Vote signing isolation** (Run 422 D6) — code/test-positive; wire bytes
  unchanged; **activation DISABLED**.
- **Dormant verified-QC / domain QC-verify modules** (D7-C3D `qc_verify_domain`, D7-C3E/F verified
  justification) — code/test only; **no non-test callers** on the deployed path.
- **Read-only genesis authority/network correspondence modules** (D7-C1/C2/C3A/C3B) — observation
  only; never become authorization.

These reduce the remaining RS1 work (the verification primitives largely exist) but still require
deployed-path wiring, configured-authority activation, and release-binary evidence to clear RS1.

## 3. Work required before a public DevNet (vs. later / MainNet-only)

**Required before public DevNet launch:** RS1 closure (F1–F8 fail-closed on the deployed path with
configured-authority release-binary evidence); M4 durable published live seed; M6 live operator
identity continuity (M4-gated); S5 live status view and S7 live seed operation (both M4-gated);
the explicit launch-in-scope owner decision.

**Explicitly NOT public-DevNet launch blockers (later / MainNet-only, do not assume they block):**

- **C4 / C5** (authority/trust-anchor and governance/lifecycle closure) are tracked **separately**
  and are **not** launch must-haves. They gate only the M6 *durable-root rotation/revocation*
  sub-item, which is deferred — not required — for launch.
- **Durable anti-rollback anchor** (`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`) and
  signing-state-continuity-across-restart are production-hardening obligations; they are not listed
  as public-DevNet must-haves (DevNet is resettable / no-value). They remain required for
  TestNet/MainNet and are recorded as open, not launch-gating for DevNet.
- **TestNet/MainNet readiness (N1–N7)** — Red and untouched; `identity generate` refuses
  `mainnet`/`testnet`. Not in scope for public DevNet.
- EXE-era binary-path items (restore-from-snapshot rehearsal, multi-node binary-path interconnect,
  `/health`, consensus counters from the binary loop) are **DevNet→TestNet exit criteria**, not
  Day-1 public-DevNet bring-up blockers (`QBIND_DEVNET_READINESS_AUDIT.md` §6/§8), except insofar as
  multi-node binary-path consensus is implied by RS1's deployed-path fail-closed evidence.

## 4. Dependency analysis

- **Next executable engineering task.** Capture **configured-authority release-binary evidence**
  for the genesis-activated consensus authority (the F3/F4/F8 configured path, i.e. the Run 423
  unit): enable activation on a release binary and run the adversarial vectors (unsigned /
  mismatched-identity / wrong-or-unknown-suite / forged-QC) proving fail-closed rejection with
  counters, moving `CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE` from `NOT-YET-CAPTURED` to
  `CAPTURED`. This is the smallest concrete step that advances RS1; the signing/QC primitives it
  exercises already exist (§2). **Responsible role:** Protocol / consensus. **Completion
  criterion:** release-binary (not harness) evidence per the Run 417 reconciliation showing all
  configured-authority adversarial vectors rejected with counters. *(This pass does not perform
  Run 423; it identifies it as the next task.)*
- **Longest dependency chain to launch:** RS1 closure (F1–F8, including configured-authority
  release-binary evidence and mandatory F5/F7 verification) → M4 durable live seed → M6 live
  identity registration → S5 live status + S7 live seed operation → owner launch-in-scope decision
  → go/no-go flip to GO. RS1 is the longest technical sub-chain.
- **Work that can proceed concurrently:** M4 seed provisioning/deployment (seed operator, external
  infra) can proceed in parallel with RS1 remediation (protocol/consensus); they share no code
  dependency. M6/S5/S7 cannot start until M4 is Green. C4/C5 scoping can proceed independently but
  is not on the launch critical path.
- **External provisioning / owner decisions needed:** (a) a routable public host + a durable
  PQC seed identity for M4 (owner/seed-operator provisioning); (b) an explicit owner decision to
  enable genesis-bound consensus-authority activation (currently DISABLED by design) so
  configured-authority evidence can be captured; (c) the explicit launch-in-scope decision required
  by the go/no-go rule.

## 5. Conditional effort estimate and assumptions

Total launch effort is **UNKNOWN** and is not reducible to a percentage or date from this inventory,
because RS1 spans eight findings with production wiring and durable anti-rollback infrastructure of
undetermined size. What is estimable, under stated assumptions:

- **Assumptions:** one protocol/consensus engineer able to modify production consensus code; one
  seed operator with access to external hosting and PQC key custody; the existing dormant
  signing/QC/verifier modules (§2) are reused rather than rebuilt; activation is enabled by owner
  decision; no new wire-format or trust-model redesign is required.
- **M4 + S7** (durable seed deploy + external verification): on the order of **days** once a host
  and durable identity are provisioned — bounded by provisioning, not code. Resolved by the owner
  provisioning decision.
- **M6 + S5** (live identity continuity + live status view): **hours-to-days each, after M4 Green.**
- **RS1**: **UNKNOWN / large.** The next unit (configured-authority release-binary evidence) is a
  bounded run; full F1–F8 closure (including F1/F2 transaction-authentication, F5/F7 mandatory
  verification, and durable anti-rollback) is not bounded by this inventory. **What would resolve
  the estimate:** a per-finding RS1 remediation plan (scope + evidence per F1–F8) with the deployed
  multi-node binary-path consensus harness defined.

No completion percentage or launch date is asserted. The only defensible near-term statement is the
ordering above and that **RS1 remaining OPEN forces NO-GO regardless of M1–M20 status.**