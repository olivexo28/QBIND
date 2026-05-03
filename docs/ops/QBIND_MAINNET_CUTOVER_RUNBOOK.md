# QBIND MainNet Cutover Runbook

**Version**: 1.0  
**Date**: 2026-05-03  
**Status**: Canonical Internal MainNet Cutover Runbook (Template / Procedure)  
**Audience**: Cutover commander, release operator, genesis verifier, node/operator coordinator, incident commander, on-call SRE, communications owner, evidence recorder, authorization contact, audit liaisons

---

## 1. Purpose and Scope

This document is the **canonical internal MainNet cutover runbook for QBIND**.

Its sole purpose is to define the **operational steps and controls used to execute MainNet cutover** during the launch window — and only that — **after** MainNet readiness has been assessed and MainNet launch has been **explicitly authorized** under their own canonical documents.

**What this document is:**
- The canonical internal runbook for executing MainNet cutover during the approved launch window
- A procedural artifact used by operators, coordinators, and the cutover commander to perform a controlled, auditable launch
- A structured source of cutover evidence (timestamps, artifact hashes, role assignments, verification results, holds/aborts)
- A clear separator between (a) readiness review, (b) economics finalization, (c) explicit MainNet authorization, and (d) cutover execution

**What this document is NOT:**
- It is **not** itself a MainNet authorization
- It is **not** a launch announcement
- It is **not** a public communications document or marketing copy
- It is **not** a presale, listing, or sale-related authorization
- It does **not** itself authorize MainNet launch
- It does **not** replace the MainNet readiness checklist
- It does **not** replace the MainNet economics finalization document
- It does **not** replace the MainNet authorization memo
- It does **not** replace the incident response procedure
- It does **not** override canonical protocol documents

**Canonical protocol behavior remains defined by:**
- `docs/whitepaper/QBIND_WHITEPAPER.md` — Authoritative technical specification
- `docs/protocol/QBIND_PROTOCOL_REPORT.md` — Protocol gaps and implementation status
- `docs/protocol/QBIND_M_SERIES_COVERAGE.md` — Risk mitigation audit index
- `docs/whitepaper/contradiction.md` — Contradiction tracker

**Release sequencing remains governed by:**
- `docs/release/QBIND_RELEASE_TRACK_SPEC.md`

**Readiness remains governed by:**
- `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md`

**Economics finalization remains governed by:**
- `docs/economics/QBIND_MAINNET_ECONOMICS_FINALIZATION.md`

**Authorization remains governed by:**
- `docs/release/QBIND_MAINNET_AUTHORIZATION_MEMO_TEMPLATE.md` (and any future filled, approved memo derived from it)

**Incident handling remains governed by:**
- `docs/ops/QBIND_INCIDENT_RESPONSE.md`

This runbook is a **subordinate instrument** to all of the above. If a conflict is discovered, the canonical documents above govern, and this runbook (and any cutover record derived from it) must be reconciled.

---

## 2. Relationship to Authorization and Readiness

This runbook is **strictly downstream** of the readiness checklist and the authorization memo. It is an **execution** instrument, not a **decision** instrument.

### 2.1 Strict ordering

The following order is mandatory and non-negotiable:

1. **Readiness review** — performed and recorded against `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md`. All gating items must be satisfied or explicitly waived under the documented governance path.
2. **Economics finalization** — completed and recorded in `docs/economics/QBIND_MAINNET_ECONOMICS_FINALIZATION.md` with **no remaining `REQUIRED FINAL VALUE` placeholders** in the fields that gate launch.
3. **Authorization memo** — a real authorization memo **derived from the canonical template** (`docs/release/QBIND_MAINNET_AUTHORIZATION_MEMO_TEMPLATE.md`), filled in, reviewed, and **explicitly approved** by the named authorizing parties.
4. **Cutover execution** — only then may this runbook be entered.

### 2.2 Hard rules

- This runbook **must not be used** until MainNet authorization is **explicit, written, dated, named, and on file**.
- A passed readiness checklist and a filled, approved authorization memo are **prerequisites**, not optional references.
- This runbook does **not** decide whether launch should happen. That decision lives in the authorization memo.
- This runbook does **not** revise readiness or economics. If new information would alter readiness or economics, cutover must **HOLD** and re-enter the upstream process.
- A cutover record produced from this runbook is **not** itself an authorization. It is an **execution record** that **references** the authorization on file.

This separation between authorization and execution is intentional and must be preserved at all times.

---

## 3. Cutover Principles

These principles govern all conduct during cutover. They are intentionally short and strong.

1. **Explicit authorization before action.** No cutover step is taken without a verified, on-file authorization memo and a named cutover commander.
2. **Freeze before cutover.** Code, configuration, genesis, validator set, asset naming, and communications must be frozen before launch-window execution begins.
3. **No improvisation during cutover.** If a step is not in this runbook, the authorization memo, or an explicit re-approval, it does not happen during the window.
4. **Evidence before assumption.** A step is complete only when its evidence has been recorded — not when someone believes it succeeded.
5. **One source of truth for commands and artifacts.** Build IDs, checksums, genesis hash, network identifiers, and validator roster have a single approved value each, pinned in the cutover inputs.
6. **Abort is acceptable; ambiguous launch is not.** Holding or aborting is always preferable to launching in an ambiguous, unverified, or partially-frozen state.
7. **Public communications are separated from ops execution.** Operators do not speak publicly; the communications owner follows the approved path only.
8. **Safety and reproducibility over speed.** Schedule slippage is acceptable. Unsafe, unrepeatable, or unauditable launch is not.

---

## 4. Preconditions Before Entering Cutover

Cutover **must not be entered** unless **every** item below is satisfied and recorded. This is a hard checklist. Casual entry is not permitted.

- [ ] **MainNet authorization memo approved.** A filled memo derived from the canonical template is on file, named, dated, signed/approved per the documented path, and references this exact cutover.
- [ ] **MainNet readiness checklist passed.** Every gating item in the readiness checklist is satisfied or explicitly waived under the documented governance path; the result is recorded.
- [ ] **MainNet economics finalization complete.** No remaining `REQUIRED FINAL VALUE` placeholders in any launch-gating field of the economics finalization document.
- [ ] **Final genesis artifacts produced and verified.** Genesis file, build artifacts, checksums, and signatures match the approved values and have been independently verified.
- [ ] **Final asset naming finalized.** Canonical asset naming (chain, native asset, denominations, tickers as applicable) is locked and consistent across artifacts; no testnet/devnet naming remains in any launch surface.
- [ ] **Incident response coverage active.** On-call rotation, incident commander, and escalation paths defined in `docs/ops/QBIND_INCIDENT_RESPONSE.md` are live for the entire window.
- [ ] **Launch-window staffing confirmed.** Each cutover role (Section 5) is assigned to a named, available person, with named backups.
- [ ] **No unresolved critical/high launch blockers.** No open critical/high finding from readiness, audit, or recent operations that would normally halt launch.
- [ ] **Cutover roles assigned.** Cutover commander, release operator, genesis verifier, node/operator coordinator, incident commander, communications owner, evidence recorder, and authorization contact are all named.
- [ ] **Cutover communications channels confirmed.** Internal cutover channel(s), incident channel(s), and approved external communications path(s) are stood up and verified.

If **any** item above is not satisfied, cutover **must not** start. The deficit is recorded, the upstream document(s) re-entered, and cutover re-attempted only after the deficit is closed.

---

## 5. Roles During Cutover

Roles are **operational**, not political. They define who does what during the launch window. Some roles may be held by the same person where defensible; the pairings used must be recorded.

| Role | Responsibility | Notes |
|------|----------------|-------|
| **Cutover Commander** | Owns the cutover end-to-end. Authorizes each step transition. Calls HOLD / ABORT. Speaks for cutover internally. | Single named person, with named backup. |
| **Release Operator** | Executes the build/release/deploy commands per the runbook. Reports outcome and evidence to the recorder. | Does not improvise. |
| **Genesis Verifier** | Independently verifies final binary, checksums, signatures, and genesis hash against approved values. | Must be independent of the release operator. |
| **Node / Operator Coordinator** | Coordinates coordinator-controlled nodes and validator-set operators during start-up. Confirms participation. | Owns the operator roster contact path. |
| **Incident Commander** | Owns incident response if invoked. May be the same person as the cutover commander only if pre-declared and recorded; otherwise separate. | Follows `docs/ops/QBIND_INCIDENT_RESPONSE.md`. |
| **Communications Owner** | Owns approved communications path. Sole party permitted to make external/public statements during the window. | Operates within approved language only. |
| **Evidence Recorder / Scribe** | Captures timestamps, artifact hashes, step status, verifications, holds/aborts, links to logs. Owns the cutover record. | Independent of the release operator. |
| **Authorization Contact** | The named person who can confirm, in real time, that authorization remains valid and unchanged. | Reachable for the full window. |

All role assignments and pairings are recorded in the cutover record before Section 7 begins.

---

## 6. Cutover Inputs and Required Artifacts

The following artifacts must exist, be **pinned** (immutable for the window), and be referenced from the cutover record. No artifact may be substituted, edited, or “patched” during the window.

| # | Artifact | Source / Location | Pinned Value Recorded |
|---|----------|-------------------|------------------------|
| 1 | Approved MainNet authorization memo | Filled instance of `docs/release/QBIND_MAINNET_AUTHORIZATION_MEMO_TEMPLATE.md` | Memo ID, version, date, approvers |
| 2 | Readiness checklist record | Completed `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md` outcome | Version, date, outcome, exceptions list |
| 3 | Economics finalization document | `docs/economics/QBIND_MAINNET_ECONOMICS_FINALIZATION.md` | Version, date, “no `REQUIRED FINAL VALUE` remaining” attestation |
| 4 | Final build ID(s) | Release tag / commit SHA / build pipeline ID | Tag / SHA / build ID |
| 5 | Final binary checksums and signatures | Release artifact registry | SHA-256 (and any additional) checksum + signature reference |
| 6 | Final genesis file and hash | Release artifact registry | Genesis file path + canonical hash |
| 7 | Final network identifiers | Genesis / chain configuration | Chain ID, network name, any sub-identifiers |
| 8 | Final validator set / operator roster | Coordinator records | Operator count, contact roster reference |
| 9 | Incident response procedure | `docs/ops/QBIND_INCIDENT_RESPONSE.md` | Version, date, on-call assignment |
| 10 | Rollback / abort notes (if applicable) | Cutover preparation notes | Reference to pre-agreed conditions |
| 11 | Cutover timeline / maintenance window record | Cutover preparation notes | Window start, expected duration, hard stop |
| 12 | Cutover roles assignment | This runbook, Section 5 | Names, backups, pairings |

If any pinned value cannot be produced or verified at start of window, cutover does not begin.

---

## 7. Pre-Cutover Freeze Checklist

Before launch-window execution (Section 9) begins, the following freezes must be in place. The cutover commander confirms each item with the named owner.

- [ ] **Code / build freeze.** No commits, merges, or rebuilds against the release branch / tag after the recorded freeze timestamp. Build ID is pinned.
- [ ] **Config / genesis freeze.** Genesis file, chain configuration, and network identifiers are immutable for the window. Hash is pinned.
- [ ] **Validator set freeze.** Validator set / operator roster is locked. No additions, removals, or key rotations during the window.
- [ ] **Asset naming freeze.** Canonical asset names, denominations, and tickers (as applicable) are locked across all artifacts and surfaces.
- [ ] **Communications freeze except approved channels.** Only the approved internal cutover channel(s), incident channel(s), and external communications path are in use. No ad-hoc public statements from operators.
- [ ] **No late parameter changes.** Economics, governance, or protocol parameters are not edited during the window.
- [ ] **No “just one more fix” items.** Any open issue not already approved into the release scope is deferred. The cutover commander explicitly rejects late-additions.
- [ ] **Re-approval path defined for any post-freeze change.** Any change after the freeze requires HOLD, return to the upstream process (readiness / economics / authorization as relevant), and an explicit, recorded re-approval before the freeze is re-established. There is no informal path.

The freeze status, with timestamps and confirming names, is recorded in the cutover record. If a freeze cannot be confirmed, cutover does not proceed.

---

## 8. Genesis and Artifact Verification Checklist

This section is procedural and must be performed by the **genesis verifier** independently of the release operator. The cutover commander observes and confirms.

- [ ] **Final binary matches approved build ID.** Build tag / commit SHA / build pipeline ID matches the value pinned in Section 6.
- [ ] **Checksums verified.** Computed checksums of final binary/artifacts match the pinned values exactly.
- [ ] **Signatures verified.** Release signatures verify against the approved signing identity / key. Verification command and output are recorded.
- [ ] **Genesis file matches approved hash.** Computed hash of the genesis file matches the pinned canonical hash exactly.
- [ ] **Chain / network identifiers match approved values.** Chain ID, network name, and any sub-identifiers in genesis and runtime configuration match the pinned values exactly.
- [ ] **Validator set matches approved roster.** Operator identities and keys present in genesis / initial set match the approved roster exactly.
- [ ] **No testnet / devnet identifiers remain.** No residual testnet / devnet chain IDs, names, endpoints, or naming artifacts are present in any launch-surface artifact.
- [ ] **No placeholder values remain in critical artifacts.** No `TBD`, `TODO`, `REQUIRED FINAL VALUE`, sample, or example values remain in genesis, configuration, or any launch-gating artifact.
- [ ] **Independent multi-reviewer verification.** At least two reviewers (typically genesis verifier + cutover commander, or genesis verifier + a second independent reviewer) independently re-run the checks above. Both record their results.

Each item above is logged with timestamp, reviewer name, command/tool used (where applicable), and the observed value compared to the pinned value. Any mismatch is an immediate **HOLD** condition (Section 11).

---

## 9. Launch-Window Execution Sequence

Steps are executed **strictly in order**. Each step has an owner, evidence to record, and a stop / hold condition. The cutover commander explicitly authorizes the transition from each step to the next; no step is skipped.

### Step 1 — Confirm authorization and freeze status
- **Owner:** Cutover commander, with authorization contact
- **Evidence:** Authorization memo reference confirmed valid and unchanged; freeze timestamps confirmed (Section 7)
- **Stop / hold if:** Authorization is unclear, withdrawn, or stale; any freeze is not in place

### Step 2 — Confirm staffing, communications, and on-call
- **Owner:** Cutover commander
- **Evidence:** All Section 5 roles present (or named backups present); cutover channel and incident channel verified live; on-call confirmed per `docs/ops/QBIND_INCIDENT_RESPONSE.md`
- **Stop / hold if:** Any required role is unfilled; incident response coverage is not live

### Step 3 — Re-verify final artifacts at window start
- **Owner:** Genesis verifier, with cutover commander observing
- **Evidence:** Section 8 checks re-run at window start; results recorded
- **Stop / hold if:** Any pinned value fails to verify; any placeholder or testnet/devnet identifier is detected

### Step 4 — Start coordinator-controlled nodes / services
- **Owner:** Release operator, supported by node/operator coordinator
- **Evidence:** Start commands, timestamps, and per-node status recorded
- **Stop / hold if:** Coordinator-controlled nodes do not start cleanly, or report configuration mismatch

### Step 5 — Confirm network formation
- **Owner:** Node/operator coordinator
- **Evidence:** Peer counts, peer identities, and network handshake status recorded
- **Stop / hold if:** Network does not form, or forms with unexpected identifiers / unexpected peers

### Step 6 — Confirm validator participation
- **Owner:** Node/operator coordinator
- **Evidence:** Participating validator set matches approved roster; signatures / proposals / votes (per protocol) observed and recorded
- **Stop / hold if:** Validator participation is below the agreed threshold, or includes unexpected identities

### Step 7 — Confirm chain progress
- **Owner:** Release operator, with genesis verifier reviewing
- **Evidence:** Initial blocks / commits / finality (per protocol semantics defined in the whitepaper and protocol report) observed advancing; heights and timestamps recorded
- **Stop / hold if:** Chain does not progress, stalls, or shows consensus anomalies

### Step 8 — Confirm public-facing infrastructure (if any)
- **Owner:** Release operator
- **Evidence:** Any approved public-facing endpoints / explorers / status surfaces operate as configured; asset naming and chain identifiers correct on every surface
- **Stop / hold if:** Any public surface displays incorrect chain identifiers, asset names, or testnet/devnet residue

### Step 9 — Declare cutover complete (internal only)
- **Owner:** Cutover commander
- **Evidence:** All prior steps recorded as complete with verification; internal completion declaration logged with timestamp and signoff
- **Stop / hold if:** Any prior step is not fully verified

**“Cutover complete” is an internal operational declaration only.** It is not a public announcement, not a marketing event, and not a sale-related signal. External communications follow Section 12 and the approved communications path only.

---

## 10. Immediate Post-Launch Verification

After the internal cutover-complete declaration, the cutover team performs a defined verification window before standing down. “Launched” means **verified**, not merely **started**.

- [ ] **Peers healthy.** Peer counts stable; no unexpected partitions; peer identities match approved roster.
- [ ] **Commits / finality progressing.** Block production / commits / finality (per protocol semantics) advance steadily for the verification window.
- [ ] **Validators participating.** Participation rates within expected bounds; no unexpected silent validators.
- [ ] **No immediate consensus anomalies.** No forks, equivocations, stalls, or unexpected reorgs observed.
- [ ] **Monitoring and alerting active.** Dashboards green; alerting paths verified live; incident response remains on standby per `docs/ops/QBIND_INCIDENT_RESPONSE.md`.
- [ ] **No asset naming confusion on exposed surfaces.** All operator and (if applicable) public-facing surfaces show approved asset and chain naming; no testnet/devnet residue.
- [ ] **No unexpected economics / parameter mismatch.** Runtime parameters match the economics finalization document and the approved memo.
- [ ] **No cutover step skipped without record.** Every step in Section 9 has recorded evidence and owner signoff.

The verification window length is set by the cutover commander before the window begins and recorded in the cutover record. Stand-down may not occur until verification is complete and recorded.

---

## 11. Abort / Hold / Rollback Guidance

This section is conservative and practical. **Ambiguous state is unacceptable.** When in doubt, HOLD.

### 11.1 HOLD — pause and reassess
Invoke a **HOLD** before proceeding when, for example:
- A pinned artifact value cannot be re-verified
- A role goes unfilled (no primary, no backup)
- A freeze is unclear or contested
- A late issue surfaces that may affect launch correctness
- Communications discipline is breached and cannot be immediately restored

A HOLD pauses Section 9 progression. The cutover commander records the reason, the deficit, and the resume condition. Resume is allowed only when the deficit is fully closed.

### 11.2 ABORT — stop and do not launch
Invoke an **ABORT** before launch when, for example:
- Authorization is withdrawn, expired, or cannot be confirmed
- Genesis hash, build ID, checksums, or signatures fail verification
- Validator set does not match the approved roster
- A critical / high issue is detected that the readiness checklist would have blocked on
- Any condition exists that would make the launch unauditable or unrepeatable

ABORT is the **safe** outcome whenever launch correctness cannot be assured. ABORT is recorded with reason, evidence, and the upstream document(s) to re-enter.

### 11.3 INCIDENT — invoke incident response
Invoke incident response per `docs/ops/QBIND_INCIDENT_RESPONSE.md` when:
- A consensus anomaly, network partition, or operator-impacting failure is observed during or after Step 4
- A security-relevant signal is detected at any time during the window
- Any condition matching the classification criteria of the incident response procedure occurs

Incident response and cutover are coordinated but distinct. The incident commander leads incident handling; the cutover commander decides whether cutover continues, holds, or aborts in light of the incident.

### 11.4 Rollback — when possible vs. not appropriate
- **Rollback is possible** when launch has not progressed past coordinator-controlled startup and no externally observable irreversible state has been produced. In that case, the cutover team stands down per ABORT, preserves all evidence, and re-enters readiness/authorization as needed.
- **Rollback is not appropriate** once externally observable, validator-signed state has been produced and propagated under the approved chain identifiers. From that point, recovery follows the incident response procedure, **not** an informal “undo” path.

### 11.5 Re-authorization / re-review
Late issues that materially change readiness, economics, or authorization scope **force return to the upstream document**:
- Readiness-impacting issues → re-enter `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md`
- Economics-impacting issues → re-enter `docs/economics/QBIND_MAINNET_ECONOMICS_FINALIZATION.md`
- Authorization-scope issues → re-enter the authorization memo process per `docs/release/QBIND_MAINNET_AUTHORIZATION_MEMO_TEMPLATE.md`

Cutover does not “patch around” these documents.

---

## 12. Communications Discipline During Cutover

Operations execution and public messaging are **separate tracks**. This separation is enforced for the full cutover window.

- **Internal status updates** follow a defined cadence (set by the cutover commander before the window begins) on the approved internal cutover channel. Status updates use neutral, factual language: step, owner, status, evidence reference.
- **External / public statements** may be made **only** by the named communications owner, **only** through the approved communications path, and **only** using approved language.
- **No speculative claims.** No statements about future performance, listings, prices, partnerships, or value.
- **No MainNet / presale / value claims** beyond the language explicitly approved in the authorization memo and any associated approved communications artifacts.
- **Operators do not make public statements.** Release operators, genesis verifier, node/operator coordinator, and other ops roles communicate only on internal channels.
- **If cutover is held or aborted**, communications follow the **approved** path only. There are no improvised public explanations. If no approved language exists for the situation, the default is silence on external channels until approved language is produced through the approved path.
- **Asset naming and identifiers** in any communication must match the frozen, approved values exactly.

This section is non-negotiable. Breach of communications discipline is itself a HOLD condition.

---

## 13. Evidence Capture and Recordkeeping

The evidence recorder owns the **cutover record**. The record must make later audit and review possible without reconstruction. At minimum, the following are captured:

- Timestamps for window start, each Section 9 step transition, each HOLD / ABORT, post-launch verification, and stand-down
- Role assignments and pairings, including any backup activations
- Pinned artifact references and observed hashes / IDs (Section 6)
- Freeze confirmations with owners and timestamps (Section 7)
- Genesis / artifact verification results, including reviewer names and tool / command output references (Section 8)
- Per-step status, evidence references, and signoffs (Section 9)
- Post-launch verification results with the verification window length and outcome (Section 10)
- HOLDs / ABORTs / incident invocations with reason, deficit, and resolution path (Section 11)
- Internal cutover-complete declaration timestamp and signoff (Section 9, Step 9)
- References to logs, metrics, dashboards, screenshots, recordings, or transcripts where useful
- Reference to the approved authorization memo and readiness/economics records the cutover relies on
- Any deviations from this runbook, with reason and approver

The cutover record is treated as a controlled artifact. It is not edited after the window closes; corrections are made by appended addendum, not in-place rewrite.

---

## 14. Post-Cutover Review Requirements

After the window closes — whether cutover succeeded, was held, or was aborted — the following are required.

- [ ] **Internal cutover report.** A written report summarizing the window: timeline, role assignments, step outcomes, deviations, holds/aborts, and the final state. The cutover record (Section 13) is the primary source.
- [ ] **Incident postmortem(s) if any incident was invoked.** Postmortems follow `docs/ops/QBIND_INCIDENT_RESPONSE.md` and are linked from the cutover report.
- [ ] **Evidence archived.** The cutover record and all referenced artifacts are archived in a durable internal location with a stable reference.
- [ ] **Readiness / authorization records linked.** The cutover report explicitly references the readiness checklist outcome, economics finalization version, and the authorization memo it executed under.
- [ ] **Deviations documented.** Any deviation from this runbook is documented with reason, approver, and remediation (typically a runbook update via the documented documentation path).
- [ ] **Follow-up actions assigned.** Any operational, documentation, or process follow-ups have a named owner and a target resolution path.

The post-cutover review is operational. It is not a public document and not a marketing artifact.

---

## 15. What This Runbook Does Not Do

To preserve the separation of concerns enforced across the canonical documentation baseline, this runbook explicitly does **not**:

- **Authorize launch.** Authorization lives in a filled, approved memo derived from `docs/release/QBIND_MAINNET_AUTHORIZATION_MEMO_TEMPLATE.md`.
- **Replace readiness review.** Readiness lives in `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md`.
- **Replace the authorization memo.** This runbook executes under an authorization memo; it does not constitute one.
- **Replace the incident response procedure.** Incident handling lives in `docs/ops/QBIND_INCIDENT_RESPONSE.md`. This runbook coordinates with it; it does not substitute for it.
- **Authorize a presale, listing, public sale, or any sale-related action.** No part of this runbook implies, enables, or constitutes such authorization.
- **Define marketing, public communications, or external messaging copy.** Approved external language is produced through the approved communications path, not here.
- **Override canonical protocol documents.** Protocol behavior remains defined by the whitepaper, protocol report, M-series coverage, and contradiction tracker.
- **Finalize economics, fees, supply, allocations, or pricing.** Economics finalization lives in `docs/economics/QBIND_MAINNET_ECONOMICS_FINALIZATION.md`.
- **Set or imply launch dates.** Any date that appears in a cutover record is observational (when something happened), not a forward-looking commitment.

If a reader is using this runbook to make any of the decisions above, they are using the wrong document.

---

## 16. Final Runbook Summary

This runbook is the canonical internal procedure for executing QBIND MainNet cutover **after** readiness and authorization are complete. It is conservative by design.

Key takeaways:

- **Strictly downstream of authorization.** Cutover begins only when readiness has passed, economics is finalized, and an explicit MainNet authorization memo is on file.
- **Freeze before action.** Code, configuration, genesis, validator set, asset naming, and communications are frozen before launch-window execution begins.
- **Procedural, not improvised.** Every step in the launch-window sequence has an owner, evidence requirements, and a stop / hold condition. Steps are not skipped.
- **Verified, not merely started.** “Launched” is declared only after the post-launch verification window confirms peer health, chain progress, validator participation, monitoring, and naming/parameter correctness.
- **HOLD and ABORT are first-class outcomes.** Ambiguous state is unacceptable. When launch correctness cannot be assured, the safe path is HOLD or ABORT, with re-entry to the upstream documents as required.
- **Communications discipline is enforced.** Operators do not speak publicly. The communications owner uses approved language only. Internal status and external messaging are separate tracks.
- **Evidence is the deliverable.** The cutover record makes later audit, postmortem, and review possible without reconstruction.
- **No authorization, no marketing, no sale claims.** This runbook is execution. It does not authorize launch, presale, listing, or any sale-related action, and it does not produce public communications.

If any aspect of this runbook conflicts with the whitepaper, protocol report, M-series coverage, contradiction tracker, release-track spec, readiness checklist, economics finalization, authorization memo template, or incident response procedure, **the canonical documents govern**, and this runbook must be reconciled.