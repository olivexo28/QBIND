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
| **RS1 — deployed consensus path fail-closed (F1–F8)** | `BLOCKER_REGISTER.md` RS1; `QBIND_FOUNDATIONAL_RUNTIME_SECURITY_RECONCILIATION.md`; Run 417 | OPEN / launch-blocking. F6 code/test (418) + partial release-binary (419); F3/F4/F8 code/test (420) + unavailable-authority release-binary (421); genesis-bound authority **DISABLED** (422, release binary refuses `--consensus-authority-from-genesis` exit 1); domain-v2 signing isolated (D6); authority-lifetime guard **PARTIAL**, `DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED` (D7) | Wire the verified signing/QC/timeout path into the **deployed** `binary_consensus_loop`; enable configured genesis authority; capture **configured-authority** release-binary adversarial evidence (unsigned / mismatched-identity / wrong-suite / forged-QC rejected with counters); resolve F1/F2 before transaction ingress; make F5/F7 (timeout/new-view + QC) verification mandatory on the deployed path | None internal (longest chain root). External: owner decision to enable activation | Protocol / consensus | Deployed-path (not harness) executable evidence per Run 417 reconciliation: rejections with counters for all RS1 vectors; `CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=CAPTURED` | **UNKNOWN (large).** 8 findings, production wiring, durable anti-rollback infra. Resolved by: a scoped per-finding remediation plan with release-binary evidence. **The next engineering unit is NOT Run 423** (withdrawn as premature — §4.0); configured-authority release-binary evidence (item 8) is gated on items 1–7. The next bounded step is the local signing-journal crash-consistency task (§4.3); RS1 remediation and eligible-seed preparation proceed as **parallel workstreams** converging at launch |
| **M4 — durable published live seed** | `BLOCKER_REGISTER.md` M4; `network/M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md`; Run 416 | Yellow / launch-blocking. External reachability PROVEN once (Run 416, Route A) against a **temporary** seed with discarded PQC material; no durable published `devnet-seeds.live.json` | Deploy a durable seed on a routable public host (strict KEMTLS mutual-auth + PQC static-root, Run 356 genesis pinned); verify from a genuinely independent off-host vantage; promote to a schema-valid durable live seed-list entry with non-null `last_reachability_evidence` | External host provisioning; durable PQC seed identity (owner-provisioned) | Seed operator | Timestamped external TCP dial + external KEMTLS mutual-auth/static-root handshake from an independent off-host vantage matching the published `node_id`; durable `devnet-seeds.live.json` entry; live `register-check` fails closed without evidence | **UNKNOWN (ops-bounded).** Deployment is days once a host + durable identity are provisioned; resolved by an owner provisioning decision |
| **M6 — live operator identity continuity** | `BLOCKER_REGISTER.md` M6; `identity/IDENTITY_CONTINUITY.md`, `identity/ROTATION_REVOCATION_DEFERRAL.md` | Yellow / Partial. Generation + verification + non-mutating `register-check` Green-for-scope; live-registration half is **M4-gated**; durable-root rotation/revocation is **C4/C5-deferred** | After M4 Green, register a continuous operator identity into the live network; prove durable `node_id`/`peer_id` reuse across DevNet restarts. Do **not** attempt durable-root rotation/revocation until C4/C5 scoped | **M4 Green** (and C4/C5 for the rotation/revocation sub-item only) | Validator/seed operator (+ Protocol for C4/C5) | Operator identity admitted into the **live** seed list with persistent published identity across restarts | **UNKNOWN until M4.** Live-registration proof is hours-to-days once M4 is Green |
| **S5 — live status / health view** | `BLOCKER_REGISTER.md` S5; `status/STATUS_PAGE_DECISION.md` | Yellow. Publish-safe static decision + frozen schema published; no live status page (would misrepresent a non-operating network) | After M4 Green, deploy a live health view wired to the real network using the frozen schema | **M4 Green** | Ops / status | A live, externally usable status page reflecting a real durably operating network | **UNKNOWN until M4.** Small once M4 Green |
| **S7 — live seed operation** | `BLOCKER_REGISTER.md` S7; `network/SEED_NODE_OPERATIONS.md` | Yellow. Runbook + M4 Route-A checklist + evidence template published; operating a real live seed is M4-gated | Execute the published runbook against real external infrastructure as part of the M4 Route-A run | **M4 Green** (same off-host reachability evidence) | Seed operator | A real live seed operated + verified externally | **UNKNOWN until M4.** Co-executed with M4 |
| **Launch go/no-go flip** | `LAUNCH_GO_NO_GO.md` §9 | NO-GO / NOT launch-ready | Flip to GO only when every must-have M1–M20 is Green, RS1 is closed, and a public DevNet launch is explicitly in scope | RS1 closed **and** every must-have M1–M20 Green (incl. M4/M6). **S5/S7 are should-haves, not part of the required gate** (`QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`; `LAUNCH_GO_NO_GO.md` §9), absent an explicit governing decision to promote them | Owner / release decision | Updated readiness matrix with all must-haves Green + RS1 closed + explicit launch-in-scope decision | Derived (follows the above) |

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

**Required launch gate (must-haves only):** every must-have **M1–M20 Green**, **RS1 closed** with
deployed-path (not harness) evidence, and the **explicit launch-in-scope owner authorization**
(`LAUNCH_GO_NO_GO.md` §9; `QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`). Within the must-haves this
includes M4 (durable published live seed) and M6 (live operator identity continuity, M4-gated).

**RS1 remediation and eligible-seed preparation are parallel workstreams** that converge at the
launch gate: RS1 closure (deployed-path fail-closed F1–F8 with configured-authority release-binary
evidence) proceeds independently of M4 seed provisioning/host preparation, and preparatory work
(runbooks, checklists, host provisioning, identity generation) is distinct from **live publication
or public activation**, which happen only at/after the gate.

**Should-haves — NOT part of the required gate:** **S5** (live status/health view) and **S7** (live
seed operation) remain **should-haves**, M4-gated, converging at launch but **not** required for the
go/no-go flip unless an explicit governing decision promotes them
(`QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`). They are not imported into the required M1–M20 + RS1
gate here.

**Explicitly NOT public-DevNet launch blockers (later / MainNet-only, do not assume they block):**

- **C4 / C5** (authority/trust-anchor and governance/lifecycle closure) are tracked **separately**
  and are **not** launch must-haves; their complete MainNet closure is **not** imported into the
  DevNet gate. They gate only the M6 *durable-root rotation/revocation* sub-item, which is
  deferred — not required — for launch.
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

### 4.0 The next engineering task is NOT Run 423 (withdrawn as premature)

A previous revision of this document named **Run 423 configured-authority release-binary
evidence** as the next executable engineering task — "enable activation on a release binary and
run the adversarial vectors." **That recommendation is withdrawn.** It is premature and
misclassifies the dependency graph:

- **The `RUN_422_TASK.txt` successor condition is not met.** Run 423 may be recommended **only if
  activation is code/test-positive and reviewed**; "if activation remains partial, recommend the
  smallest missing implementation step first" (`task/RUN_422_TASK.txt` successor clause). Activation
  is **DISABLED**, not partial-but-present: the release binary refuses
  `--consensus-authority-from-genesis` with `FATAL … exit 1` **before** P2P and any consensus task,
  with no override, hidden flag, environment bypass, or unsigned fallback
  (`crates/qbind-node/src/main.rs:5405`). That refusal **remains intact** and is not changed here.
- **Configured-authority release-binary evidence requires a safely implemented and reviewed
  configured path first.** It is the **eighth** dependency of the lifecycle contract's activation
  checklist (`QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md` §3.3.1, item 8), not its
  entrypoint. Items 1 (activation authorization root), 6 (current-authority freshness), and the
  whole-copy-rollback half of 7 (signing-state recovery) are **unmet** and some are blocked by an
  **unresolved design decision** (§4.2 below). Evidence is **produced by** isolated validation of an
  implemented+reviewed configured path; it is **not obtained by treating the activation flag as an
  operator permission switch**. Flipping the flag before the configured path exists would be a
  circular prerequisite (activation used as its own precondition), a test bypass, or fixture
  authority escaping into production — all of which are prohibited (§3.3.1; §4.0/§7 of the lifecycle
  contract).
- **Isolated validation that *produces* evidence is distinct from authorization for public
  operation.** The accepted isolated storage subset (§2) and the dormant verifier/QC/correspondence
  modules are validation inputs; none of them authorizes activation or public DevNet operation.

### 4.1 Activation prerequisites (lifecycle contract §3.3.1, eight dependencies)

Source-grounded status of each §3.3.1 activation dependency. "Evidence" is existing, inspected
material; "missing work" is the precise unmet obligation; completion criteria are stated per item.
None of these is advanced, enabled, or activated by this document.

| # | Dependency (§3.3.1) | Current implementation | Existing evidence | Precise missing work | Depends on | Completion criterion |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | **Activation authorization root / evidence** (req. A) | Only `unavailable(...)` owner; release binary refuses the genesis flag (`main.rs:5405`, exit 1) | S16 refusal (Runs 420/421 fail-closed release-binary evidence); read-only genesis/authority correspondence D7-C1/C2/C3A/C3B | A trusted activation **mechanism** (operator policy / trust root / signed activation evidence bound to the exact authority) — not merely constructing an `Established` owner | A trust-root/governance decision (owner); distinct from identity validation, correspondence, and freshness | A reviewed authorization root exists and is exercised by the same validated constructor `main` would use; no test/fixture bypass |
| 2 | **Bootstrap / absent-QC policy** (§4.2) | `proposal.qc == None` is neither verified, counted, nor treated as bootstrap | Lifecycle §4.1 traced absent-QC path | A decided, source-backed bootstrap/absent-QC policy for the founding epoch | Item 1; QC/Timeout compatibility (item 5) | A written policy + fail-closed implementation; no implicit bootstrap from an empty QC |
| 3 | **Trusted production identity + runtime/wire correspondence** (S1, S11/S12) | Genesis pin validation + network/membership correspondence present; read-only modules exist | D7-C1/C2/C3A/C3B correspondence modules (non-authorizing); Run 356 genesis pin | Bind the validated identity to an authorized runtime authority (consumed by item 4), not just observed | Item 1 | Validated identity feeds the real authority constructor; correspondence remains non-authorizing until item 1 |
| 4 | **Authority / engine / verifier / signer wiring** (S2→`try_build_timeout_verification_context`; S13/S14/S15; S5/S6) | Dormant modules only; **no non-test callers** on the deployed path | `qc_verify_domain` (D7-C3D), verified-justification ingest (D7-C3E/F), domain-v2 signing isolation (D6) | Wire the coherent authority→engine→verifier→signer path into the deployed `binary_consensus_loop`, exercised in isolation | Items 1, 3, 5 | Isolated (non-production) validation drives the real wired path end-to-end; still gated by item 1 for production |
| 5 | **QC formation/propagation + Timeout/NewView compatibility** (S13/S14; Timeout bridge §6.1) | Present-QC verified via S13/S14; Timeout/NewView crypto verification is the unresolved F5 boundary | D6 domain-v2; D7-C3D/F; Run 417 F5/F7 findings | Make Timeout/NewView QC verification mandatory and compatible on the deployed path (F5/F7) | Item 4 | F5/F7 mandatory-verification evidence on the deployed path |
| 6 | **Current-authority freshness** (req. B, §5) | **Missing.** A persisted committed epoch (S9) is evidence, never freshness | D7-C1 `observe_consensus_storage` (read-only); epoch persistence | A durable, rollback-resistant proof — via an independent anchor (§5.2) — that the observed epoch is current **now** | **Unresolved anchor decision (§4.2)**; distinct from item 7 | A freshness proof bound to an out-of-rollback-domain anchor; no epoch-equality substitute |
| 7 | **Signing-state recovery + rollback safety** (req. C, §2.3.2/§5) | **Missing durable** last-voted-view / locked-QC / anti-rollback. Characterized read-only in D7-D2…D7-D14; continuity contract **DEFINED-NOT-IMPLEMENTED** | D7-D2 restart-drop characterization; continuity contract (durable-before-sign invariant, conflict rule, 5-state machine, 12-row recovery matrix); Run 291 backend (tests-only, no anti-rollback counter) | **Local crash-consistency half:** implement the durable per-position signing journal + recovery (design resolved — §4.3 selected task). **Whole-copy-rollback half + consensus-lock recovery (§5.3):** blocked by the §4.2 anchor decision | Item 6 anchor for the rollback half; Timeout/NewView (item 5) for lock recovery | Journal: local crash-consistency journal implemented + fail-closed recovery. Rollback half: deferred to the resolved anchor |
| 8 | **Configured-authority release-binary adversarial evidence** | `CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED` (S16) | Runs 419/421 unavailable-authority release-binary evidence (fail-closed) | Capture configured-authority adversarial vectors (unsigned / mismatched-identity / wrong-suite / forged-QC rejected with counters) on a release binary **after** items 1–7 | Items 1–7 (especially 1, 4, 5, 6) | Deployed-path (not harness) rejections with counters for all RS1 vectors; `=CAPTURED`. **This is Run 423 — not startable now** |

Authorization (1), freshness (6), **local crash recovery** (7, crash-consistency half), **whole-copy
rollback resistance** (7, rollback half), and **copied-key exclusivity** (continuity §5.2 row 13)
are kept distinct and are **not** interchangeable. No new anchor architecture is selected and no new
trust assumption is introduced here.

### 4.2 The one material design decision blocking the broader path (owner input required)

The single unresolved decision that blocks items 1 (current-ness), 6, the whole-copy-rollback half
of 7, and therefore item 8, is the **independent anti-rollback / freshness anchor selection**
(`QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md` §5.2/§5.3; signing-state continuity contract
§6). A whole-copy rollback is **locally indistinguishable** from a valid older state (continuity
§5.2 row 11), so no local record can establish latestness. The trade-off is between candidate
anchors — **protected local hardware** (monotonic counter / secure element: no external dependency,
but a new hardware trust assumption and provisioning burden) versus a **remote witness / attested
service** (no special hardware, but a liveness/availability dependency and a new remote trust
root). This decision is **out of scope for this pass** and must not be made by selecting a flag or a
fixture. Until it is resolved, requirements A-current-ness, B, and the rollback half of C remain
open regardless of other progress.

### 4.3 The ONE smallest non-activating engineering step whose design prerequisites ARE resolved

**Selected task:** Implement the **durable, single-writer, local signing journal** for per-position
Vote (then Proposal) anti-equivocation — the **local crash-consistency half of requirement C only**
(continuity contract §3.1/§3.2/§3.3/§3.4/§4.1/§4.3; §5.2 rows 1–9). This step's design is fully
resolved by the continuity contract; it introduces **no anchor and no new trust assumption** (it
relies only on the same local fsync/storage assumption as existing epoch persistence), it **does not
enable activation** (it is dormant in production exactly like the D7-C/D modules while `main.rs`
refuses the authority), and it produces evidence without authorizing public operation.

- **Exact code boundaries.** A new durable journal interface alongside `storage.rs`'s
  `ConsensusStorage` (which today has **no** `put_last_voted_view` / `put_locked_qc` / vote-record
  method, `storage.rs:142`), written **before** the signer is invoked on the production routes
  `guarded_sign_vote_for_broadcast` / `guarded_sign_proposal_for_broadcast`
  (`binary_consensus_loop.rs`). No change to `main.rs`, the activation refusal, the wire format, or
  the protocol contracts.
- **Required behavior.** Durable-before-sign ordering (continuity §4.1 step 4): persist a `RESERVED`
  record for the outbound position (view + canonical-decision binding digest) with an acknowledged
  sync **before** calling the signer; transition to `SIGNED` after the signer returns; on a
  same-epoch restart, reload the journal and apply the §3.2 conflict rule — permit an exact retry of
  a retained decision, **refuse** (fail-closed) any conflicting re-sign at a covered position, and
  treat an uncertain `RESERVED` as potentially-signed (continuity §5.2 rows 2/4).
- **Tests (`cfg(test)`, isolated; no production activation).** (a) durable-before-sign ordering: no
  `SIGNED` without a prior acknowledged `RESERVED`; (b) conflicting re-sign at the same position
  after restart is refused; (c) exact-retry resend permitted after association + authorization
  re-validation; (d) uncertain/torn `RESERVED` is treated as potentially-signed; (e) a missing /
  malformed / truncated journal fails closed (continuity §5.2 row 8).
- **Failure handling.** Every uncertain or unverifiable journal state is fail-closed (refuse to
  sign); no path infers "unused" from an empty or undecodable journal.
- **Stop conditions / explicit exclusions.** This task does **not** implement the §6 anti-rollback
  anchor (whole-copy-rollback resistance, §5.2 rows 10–11 — blocked by §4.2), consensus-lock
  recovery (§5.3, which also depends on item 5), copied-key exclusivity across hosts (§5.2 row 13),
  freshness (req. B), or activation (req. A). It must not relabel local crash-consistency as
  rollback resistance, and must not enable, bypass, or weaken the `main.rs` activation refusal.

*(This document selects and specifies the task; it does not implement it. No Rust/test/Cargo/config/
CI or contract change is made in this pass.)*

- **Longest dependency chain to launch:** RS1 closure (F1–F8, including configured-authority
  release-binary evidence and mandatory F5/F7 verification) → M4 durable live seed → M6 live
  identity registration → owner launch-in-scope decision → go/no-go flip to GO. RS1 is the longest
  technical sub-chain. **S5 live status + S7 live seed operation are should-haves** (M4-gated),
  converging at launch but not part of the required M1–M20 + RS1 gate.
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
- **RS1**: **UNKNOWN / large.** The next **non-activating** engineering unit is the local
  signing-journal crash-consistency task (§4.3), a bounded implementation whose design prerequisites
  are resolved. Configured-authority release-binary evidence (the former "Run 423") is **not** the
  next unit — it is item 8, gated on items 1–7 and on the §4.2 anchor decision. Full F1–F8 closure
  (including F1/F2 transaction-authentication, F5/F7 mandatory verification, and durable
  anti-rollback) is not bounded by this inventory. **What would resolve the estimate:** a per-finding
  RS1 remediation plan (scope + evidence per F1–F8) with the deployed multi-node binary-path
  consensus harness defined, and resolution of the §4.2 anti-rollback anchor decision.

No completion percentage or launch date is asserted. The only defensible near-term statement is the
ordering above and that **RS1 remaining OPEN forces NO-GO regardless of M1–M20 status.**