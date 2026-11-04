# QBIND audit-remediation coordination plan

**Input: A49.1 / internal v1.138. Documentation only. No finding is fixed by
this plan. Implementation prerequisites NOT SATISFIED; activation DISABLED;
public DevNet NO-GO; RS1 OPEN / launch-blocking; C4/C5 OPEN.**

## 1. Authority, baseline and input identity

This is the maintained coordination inventory, not an amended auditor report,
a new whole-codebase audit, a technical-policy acceptance, or deployment
authorization. The [audit register](../../Audit/QBIND_SECURITY_FINDINGS_REGISTER.md)
remains byte-for-byte unchanged. Claude's dispositions below are attributed
to that input, not replaced by developer closure claims.

Release authority remains with the
[readiness criteria](../release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md),
[blocker register](../release/public-devnet/BLOCKER_REGISTER.md) and
[launch decision](../release/public-devnet/LAUNCH_GO_NO_GO.md).
All required M1-M20 must be Green, RS1 must be closed with deployed-path
executable evidence, and launch must be explicitly authorized. This plan
neither introduces substitute gates nor makes any existing gate Green.
RS1 is independent of the broader C4/C5 work; those separately tracked
requirements are not all automatically public-DevNet must-haves.

| Identity | Pinned value / observation |
|---|---|
| Repository; fetch and push | `https://github.com/olivexo28/QBIND`; both resolve to this repository |
| Coordination starting commit; advertised remote main | `c44370ee4b77eda8b4c9966632e3b8ce796ba203` |
| Coordination starting tree | `2d19a3ad9b5b2fde82ecd26be7b03cf5cd31d8cc` |
| Task branch | `copilot/audit-remediation-plan-v1138` |
| Checkout/instructions | Clean at entry, including untracked files; no applicable `AGENTS.md` in repository or ancestor instruction locations |
| Raw merge parent 1 | `b1b20ae4e48438ac7b0e66d6d951207ce3b2f272` |
| Raw merge parent 2 | `bbde041b362dc4332a2fb50af971eb39a48872be` |
| Available-object ancestry | Shallow checkout; both parent objects unavailable. Raw parentage does not prove traversable ancestry through either parent. Starting commit/tree are available; task commits descend directly from that available start |
| Audit source baseline, unchanged by delivery | `18d71a549d868ed33d352e9fc70a9d060f75e03b`, tree `5b6c543435ac017dd8372c93f48be397899db14a` |
| Audit baseline object availability | Not available locally; no ancestry/non-ancestry claim from absence |
| Committed input location | Starting commit, `Audit/QBIND_SECURITY_FINDINGS_REGISTER.md` |
| Input version; mode; Git blob | A49.1 / internal v1.138; `100644`; `cd81efdbaf2bfb45e00dc3c60db3ea4f523adfa0` |
| Raw committed identity | 5,509,470 bytes; SHA-256 `6e68d3d05964f9a6dc0384ffda2bb53d81d7da97ffb786ce84f4bd5a4360c0d9`; CRLF throughout, terminal CRLF |
| Normalized comparison identity | Replace CRLF with LF in memory: 5,480,145 bytes; SHA-256 `93caf37a8bb65ac3c8faf5fd692c08f6867473a435f32b2ca48011160581370f`; matches the supplied LF export identity |

Raw and normalized files are **not byte-identical**. The committed blob, not
working-tree text conversion, supplies the hashes. There are 29,325 logical
lines (29,325 CRLF sequences, no bare LF). Audit locators `A:Lx-Ly` below
refer to these lines in this exact blob; line numbers survive normalization.
The source baseline is the audit's stated baseline, not this delivery merge.

Protected blocker baseline: mode `100644`, blob
`e26d6b51fab8f56f80fc189313bedc0506568eef`, 16,476 bytes, SHA-256
`21b138edc218b462dc1b6b1a7e37eba969e9868bcd3ea5c59654d5163d3a284e`,
CRLF, **no terminal newline**. Its complete bytes must remain a prefix;
the append uses CRLF and preserves no-terminal-newline convention. The two
BR-04 documents and every other tracked file are protected unchanged.

## 2. Work sequence and task-entry rules

Before implementing **each selected remediation**, record an independent
pre-implementation verification. The reviewer must be independent of the
implementation author; record the actual reviewer/evidence and outcome, or
mark the reviewer **UNASSIGNED**. This is a bounded technical check, not an
invented protocol-owner approval or substitute for an existing authorization
gate. The review record covers both:

* **Finding:** latest audit disposition and supersession; exact current-source
  baseline; applicable requirement/invariant; source mechanism; reachability
  and prerequisites; bounded effect; remaining uncertainty.
* **Proposed correction:** intended behavior; permitted scope; compatibility
  and caller effects; relevant security dependencies; meaningful regression
  controls.

Record supporting source/evidence references and the review outcome. The
auditor's entry, its inclusion in this inventory, or the implementation
author's unsupported assertion is not independent confirmation. Use an
evidence-supported disposition such as **CONFIRMED TO [scope]**,
**UNRESOLVED**, **SUPERSEDED**, **ALREADY ADDRESSED**, or **NOT APPLICABLE**,
with rationale and boundaries; do not imply a reviewer approval not actually
given. Proceed only with a remediation confirmed to its stated scope and a
supported correction. An unresolved requirement that governs the proposed
change remains a dependency; it does not automatically block unrelated,
independently confirmed work. A deterministic source defect can be established
from source without live-network reproduction. If behavior must be observed,
a separately scoped and authorized isolated **pre-change** reproduction may
precede implementation; it is not automatic permission to probe a live
network.

1. Begin independently verified, confirmed-to-scope, fixable defects without
   waiting for all audit questions or every BR decision. Prioritize by
   security impact, actual reachability and dependencies, not audit pass
   number or raw item count. The manifest correction in section 8 was the
   initial bounded task and is now independently verified and published,
   **not** a claim that it was the highest-severity finding.
2. Triage other independently actionable defects in parallel where genuinely
   independent: for example proposal decoder reservation and evidence-harness
   verdict aggregation, after their separate pre-implementation checks. This
   plan does not itself authorize source changes. Do not duplicate RUN 422
   components.
3. Implement bootstrap authority, B/U, recovery and transition changes only
   after their **relevant** security requirements and entry decisions are
   settled. A missing policy is a design dependency, not permission to choose
   a convenient mechanism. An unrelated pending BR does not block a manifest
   truthfulness fix; its pre-implementation review still applies.
4. After any implementation, run the relevant focused regression controls and
   obtain independent code review. Keep both distinct from pre-implementation
   verification and from any optional pre-change behavioral reproduction.
   Produce required binary, process, crash, recovery and multi-node evidence
   under a **separately scoped and authorized test plan** with revision,
   configuration, threat model, expected outcomes, safe resources and cleanup
   pinned. Nothing here starts that evidence collection or authorizes full
   Run 384/385 execution.
5. Reconcile integration against concurrent main changes. Public activation
   remains subject to existing blockers, operational gates and explicit
   authorization. Planning accepts no unresolved technical policy.

Keep separate: **pre-implementation finding/correction verification;
optional pre-change behavioral reproduction; code completion; regression
validation; independent code review; binary/runtime validation; release
eligibility**. `PASSED` or `CLOSED` always names its boundary, producing
revision and evidence. Source evidence can confirm a deterministic mechanism
without runtime reproduction; source-complete never means defect-fixed,
regression-passed, runtime-passed or release-eligible. Unavailable authority
is containment, not configured positive readiness.

## 3. Reading rules, supersession and row metadata

The complete input includes prepended current-lineage amendments, preserved
masters and six embedded archives. Read explicit corrections before their
preserved targets; do not treat an embedded pass with the same A-number as
the current pass. Identify evidence by **baseline + internal version + pass
+ exact section**. Preserve historical reasons, not just the latest label.

| History / locator in pinned input | Effective interpretation for this plan |
|---|---|
| Historical ledger section 25.2, A:L19385-L19455; A22.1-C1, A:L9159-L9233 | Identity/definition inventory: 54 parents, not 54 defects. Earlier 37 -> 52 -> 53 -> 54 are bookkeeping splits. CONS-4a/4b replace parent CONS-4; STO-3 retains its CONS-4 snapshot-edge origin |
| A23.1, A:L8968-L8989, superseding A22.1 status-overreach | Ledger defines historical identities, not automatic current dispositions. A1-F1 is SOURCE-ADDRESSED, not a current context-absent bypass. Restore A7-F1's actual auth defect and alias QBIND-A1-F005 |
| A5/A5.1/A5.2/A5.3, A:L15337-L15880 | Successor/signed-view binding resolved; TC-setter gate scope only; withdraw hash-collision assumption and A5.2's missed registration-time cycle. A33-F1 conditional construction source-established; operator-crafted anchor required |
| A6/A6.1/A6.2/R1-R7, A:L14096-L15336 | Preserve configured transport/role gates, replay prerequisites, and handshake-only allocation reachability. Neither transport impersonation nor replay automatically forges inner consensus signatures |
| A8.1-A18.1, A:L10351-L14095 | Distinct transaction families; EVM authentication overclaim withdrawn; trust/root provenance, reload windows, admission, frame retry, cleanup, supervision, metric and keystore corrections retained; daemon accept loop is not its dead handler |
| A19.1/A20/A21/A22.1, A:L9128-L10350 | Authority RemoteSigner selector and KMS/HSM paths retain separate boundaries. Allocation A21-F1 is not a custody finding. A22's wildcard/renamed obligation index is superseded, not reused |
| A23-A26, A:L7959-L9127 | Run-188 composition source traced; A25-F1 minted separately from A23-F1; writer-location completed (encrypted provisioner external), journals present but production integration missing. No reopening of component internals excluded as STO-2b |
| A27.1/A28.1/A29.1/A30.1, A:L6547-L7738 | CONS-6 and CONS-7 source-complete to bounded scope; CONS-8 high-QC path source-complete, implementation/runtime residuals retained. Weighted library overflow distinct from selected binary. DEP-2b unreviewed, not proven inaccessible |
| A31-A34.1, A:L5713-L6546 | Commit and safe-voting sub-boundaries complete; CONS-9 overall partial. Parent/QC binding and proposal/justify ordering are unresolved invariant candidates, not dismissed as unnecessary or minted as proven defects |
| A35.1/A36.1/A37.1/A38.1, A:L4181-L5534 | Required-policy non-invocation remains unresolved contract/integration candidate. Invoked R1/R2 hooks enforce refusal, not advisory. Run-216/227 PASS aggregation is a distinct harness assurance defect |
| A39.1/A40/A41, A:L3509-L4180 | Wrapper randomness/error chain complete to scope; fallible dependency RNG traced, deployed backend conditional; private-key object ordinary Drop erases, repository intermediates not thereby protected |
| A42.1/A43.1/A44/A45.1, A:L2193-L3508 | Slice limit replaced by Infinite; explicit input precheck/availability remains. Requests != capacity != RSS; four-channel ingress accounting and logged terminal drops, not three channels/global heap guarantee |
| A46.1/A46.2/A47.1/A47.2/A47.3, A:L1018-L2192 | Epoch persistence/restart trace corrected; finite operator-local stored-value regression established, power-loss durability and harmful consequence unestablished. No applicable violated contract identified; broader STO-2a not complete |
| A48/A48.1/A48.2, A:L412-L1017 | Correct caller/invocation, CRLF prerequisites, skipped job versus required-check semantics, effect ordering and full-validation path; retain constant-clean candidate. Earlier broad safe-artifact and no-comparison conclusions are not closure |
| A49/A49.1, A:L1-L411 | Latest build-configuration correction layer governs; repository-source sub-boundary complete, tooling/build-environment/artifact residuals separate; runtime UNEXECUTED, C5 OPEN, A50 not authorized/scheduled |

**Shared metadata for every inventory row in sections 4-6 (part of each row,
not omitted fields):**

* **Audited applicability:** findings/dispositions attributed to the audit
  source baseline in section 1; older embedded evidence retains its own
  baseline, not silently promoted to that baseline or current main.
* **Current-code applicability:** **NOT YET CHECKED**, except the specifically
  bounded current script/schema/caller observations in section 8 and
  A21-F1 mechanism verification in section 12, QBIND-A1-F002 source/caller
  verification at the exact baseline in section 13 (correction contract
  AWAITING INDEPENDENT REVIEW), and document-cited existing verification
  in section 7. A reference to a RUN 422
  result is only evidence for its stated scope/revision, not blanket current
  applicability or a new source review. Before implementation, record the
  independent pre-implementation review and its bounded outcome under section
  2; historical status and this inventory alone are not confirmation.
* **Owner/assignee:** **UNASSIGNED** for remediation/evidence tasks. Existing
  gate roles are not new assignees; Olive's B/U accountability in section 7
  is preserved, not generalized.
* **Priority:** **ASSESSMENT PENDING** unless section 8 says FIRST BOUNDED
  CANDIDATE. Rationale: current reachability, relevant security requirements
  and dependency checks precede comparative ranking. No new severity assigned.
* **Coordination status:** **INVENTORIED / NOT STARTED**; audit-source
  completion, withdrawn or excluded scope remains as explicitly recorded.
  Implementation/review/evidence references are the locators and section-7
  producing references supplied here; new remediation commits: **NONE**.
* **Validation/closure:** establish applicability and verify the proposed
  correction independently before implementation; record references and
  outcome. Then use meaningful regression controls and independent code
  review. Behavioral pre-change reproduction, when necessary, and later
  runtime/external validation require separately scoped authorization. No row
  closes solely from this inventory.

Categories: **D** = defect (including an explicitly described assurance
defect, not a new severity); **DD** = design dependency; **MI** = missing
implementation; **ME** = missing runtime/external evidence (including
dependency material/analysis). Mixed rows explicitly separate these axes.
Gates: **R** = relevant RS1 boundary, without inventing a launch-blocker
decision for every finding; **O** = existing operational/readiness criteria
as applicable (M4/M6/S5/S7 remain as registered); **C** = broader C4/C5,
not imported wholesale into DevNet. **A** = artifact/evidence assurance;
no separate new release gate. Exact gate applicability remains assessment
pending where deployment/profile is unknown.

## 4. Canonical finding and alias inventory

All 29 canonical finding identities below are retained separately from the
rejected lead and imported hypotheses. The two QBIND aliases do not add
findings. "Current" inside an audit disposition means its audited baseline,
not this task's source verification.

| Finding / alias | Latest audit disposition and locator | Component; category; relevant gate | Dependencies and next concrete action | Required validation / closure evidence |
|---|---|---|---|---|
| A1-F1 | SOURCE-ADDRESSED; absent-context production rejection/caller inventory complete; A23.1 at A:L8969-L8972 corrects A22.1 | Timeout/NewView admission; ME; R-F5 | Preserve gate; obtain revision-bound actual-handler coverage, not another generic caller inventory | Absent/present context and genuine/invalid-signature controls; later configured binary evidence E01 |
| A1-F2 | SOURCE-FIX-IDENTIFIED; successor and signed-view cross-binding RESOLVED; A5 at A:L15783, A22.1-C2 | TC view arithmetic; ME; R-F5 | Preserve checked successor/evidence-view equality; scope pending boundary matrix | MAX/successor/mixed-view matrix, exact build/configuration and recovery evidence E02; no execution asserted |
| A1-F3 | SOURCE-GATED on TC-setter route only; A5/A5.1; A30.1 at A:L6675-L6683 | TC high-QC lock adoption; DD/MI/ME; R-F7 | Keep F7 refusal; supplier/authentication requirements before enabling; catch-up is A17-F1, not this route | High-QC endorsement and pre-effect confirmation on actual callers; E03; no all-lock closure |
| A2-F1 | OPEN STATIC; certificate presentation lacks client private-key possession; R1/A6 corrections, A:L14633-L14641 | KEMTLS client authentication; D; R-F6/O/C4 | Check configured Required/Optional reachability; define session-bound possession remedy without forging inner signatures | Public-cert-only versus key-holder, trust/map/revocation controls; E08 |
| A4-F1 | OPEN, mode-qualified occupancy/deadline gap; A12.1 at A:L12461 | Accept/handshake resources; D; O | Check occupancy/rate gates and actual blocking work; certificate gates decaps in Required/Optional-with-cert | Pending sockets/workers/queue occupancy; ensure timeout releases worker/socket, not just waiter; E10 |
| A4-F2 | OPEN integration/assurance gap, cookie pre-gate unwired; A12.1 at A:L12462 | Server cookie/client retry integration; MI; O | Set requirements for both endpoints and peer-IP/time propagation; cookie config alone insufficient | End-to-end challenge/retry and rejection before expensive work; E10 |
| A5-F1 | OPEN, connection-local mid-frame-timeout desync; A13.1 at A:L12227 | Secure-channel read framing; D; O | Check target platform read-timeout semantics; preserve partial progress or fail connection explicitly | Partial/idle/full-frame controls, exact consumption schedule, task/socket outcome; E11 |
| A6-F1 | OPEN displaced same-NodeId session retention; A13.1 at A:L12229; A45.1 preserves distinction | Registry/session ownership; D; O/C4 | Check replacement and registered/displaced cleanup; repeatable NodeId prerequisite | Idle/active reconnect, EOF/fatal-read, eviction and trust-reload completion; worker/socket reclamation E14 |
| A7-F1 = QBIND-A1-F005 | Auth completeness defect, LATENT callable-library/unwired binary; A23.1 at A:L8973-L8979 restores alias and actual defect | Native wire Transaction authentication; D/MI; R-F1/F2 before ingress | Use RUN 422 applicability reconciliation, not stale empty-auth claim; approve remaining auth/resource semantics before integration | Exact signer/identity/threshold/state/replay controls; real crypto; actual ingress before release claim; E15 |
| A8-F1 | Governance authority absent on audited library route, LATENT; A8.1 at A:L13832 | Native GovernanceProgram; D/MI; R before ingress/C5 | Preserve later unavailable-authority refusal scope; settle positive governance requirements, not repeat refusal implementation | No unauthorized mutation and approved positive authority on exact route; E16; not offline CLI finding |
| A10-F1 | OPEN local-secret hardening family; A17.1 and A41 at A:L3632-L3651 | Keystore/wrapper intermediates; D/ME; C5/O | Keep decoded dependency-object ordinary-Drop erasure result; assess repository buffers/KDF/provisioning separately | Disposable-key loader/KDF controls, secret-lifetime evidence, exact dependency/build; E18; no real-secret inspection |
| A11-F1 | OPEN replay/session freshness; R1/A6.2 at A:L14633-L14733 | KEMTLS key schedule/nonces; D/DD; O/C4 | Keep role/key/counter/replay prerequisites; settle session-freshness change; crypto backend scope separate | Synthetic captures; key/nonce equality and differing-plaintext conditions; receiving gates; E19; no observed forgery claimed |
| A11-F2 | OPEN, platform-conditional write-retry re-encryption/desync; A13.1 at A:L12228 | Secure-channel write worker; D; O | Check WouldBlock/partial-write mapping; preserve same ciphertext/progress or close explicitly | Retry/partial/full-write controls with real AEAD and relevant platform; E19; distinct from nonce reuse A11-F1 |
| A12-F1 | RETAINED conditional NoV2 apply-policy bypass, severity unresolved; A12.1 at A:L12463; A38.1 preserves | Trust-bundle drain/apply; D/DD; C4/O | Present out-of-band drain-file prerequisite; policy/permissions and hook contract must be settled | Correct composed invocation/apply gates; no assumption file write is less privilege than config edit |
| A15-F1 | OPEN supervision/observability gap; A14.1-D at A:L11708-L11728, A45.1 preserves | Consensus JoinHandle owners; D; O/R availability relevance | Check owner detection and process/task propagation; avoid rewriting component scope into protocol-safety claim | Task termination, owner detection, transport/metrics outcomes and cleanup E21; no automatic recovery claim |
| A17-F1 | OPEN logical-only catch-up endorsements; A5/A19.3/A19.4, A:L9260; downstream disagreement unestablished | RestoreCatchupResponse/QC reconstruction; D; R-F7 relevance | Check admitted validator/anchor/chain conditions and exact current consumer; do not conflate TC setter | Missing endorsement verification, suffix/commit controls and effects; later E20 multi-node evidence; no arbitrary-finality assertion |
| A19-F1 | OPEN parsed-but-ignored authority RemoteSigner selector; A19.1/A20, A:L9782-L10350 | Authority trust-bundle signing surfaces; D/MI; C5/O | Preserve seven-surface map; decide consume/remove selector under relevant contract, not duplicate validator signer | Selected-policy enforcement on each differing surface, clear refusal/operator documentation |
| A21-F1 = QBIND-A1-F001 | **OPEN; CONFIRMED TO THE STATED SOURCE MECHANISM**; R7.1 at A:L14115-L14128 and A44 qualifications retained; section 12 | Proposal decoder, after optional QC, before tx-body/sender checks; D; O/R availability relevance | Bounded allocation-free structural preflight **IMPLEMENTED — BOUNDED REVIEW PASSED**: independent source review and retained-evidence inspection at section 12's recorded revisions; no arbitrary resource caps or policy bypass | Author-executed focused E12 regressions recorded separately; bounded review does not close E12 or runtime/deployment evidence; E13 queue/aggregate-memory scope separate |
| A23-F1 | OPEN K!=T ratified-target/bundle-signer gap; A9.1 at A:L13517-L13518; A26 refinements retained | V2 trust ratification/install; D; C4/O | Ratification invocation/data-dir and independent genesis provenance prerequisites; retain DevNet no-data-dir no-op qualification | K/T, external genesis and gate/config controls; E23; not automatic runtime authorization escalation |
| A24-F1 | OPEN opt-in metrics HTTP resource limits/deadlines; A15 at A:L11446-L11489 | Metrics HTTP handlers; D; O | Check enabled/reachable endpoint and size/concurrency/deadline controls | Bounded request/header/stall/handler/shutdown evidence E24; default-disabled is reachability mitigation |
| A25-F1 | Source-established operator-assurance gap; severity uncertain, no distinct ratification authorization bypass; A25.2 at A:L8351-L8426 | Run-163 governance-proof fixture verifier; D/MI; C4/C5/O | Preserve upstream real ratification gate; decide real independent authority proof versus truthful unavailable control | Public-data issuer-pattern/threshold controls plus approved real proof; no bypass of upstream signature inferred |
| A28-F1 | OPEN cumulative limiter-key retention; A16 at A:L11280-L11305 | Per-peer/prefix and opt-in per-address bucket maps; D; O | Check both deployed/default and optional limiter ownership/pruning separately | Count retention after disconnect, insertion rate and memory/availability E25; separate from live-session occupancy |
| A31-F1 | OPEN stale outbound root; A10.1 at A:L13172 | Dial retry/handshake root snapshot; D/DD; C4/O | Correct two-root witness, pinned peer KEM private-key and reload-window prerequisites | Root-signature pass, handshake completion, registry insertion separately; E26; single-root witness withdrawn |
| A33-F1 | Conditional engine non-termination source-established; A5.3 at A:L15366; A22.1 restores current-baseline status | Block eviction ancestry walk; D; R/O availability relevance | Operator-crafted anchor and admitted catch-up construction; no hash-collision premise or anonymous attack claim | Exact registration-before-vote state/capacity, cycle termination and bounded impact E27; runtime UNEXECUTED |
| H04-F1 | Remote signer non-functional/unwired; A18/A18.1, A:L10351-L10740 | Validator daemon accept loop/node signer mode; MI; C5, not standalone DevNet blocker by audit | Use separate-signer feasibility/approved profile; do not transfer dead handler checks to live accept loop | Actual accept/handshake/handler and required/optional-mode evidence E17; no signing-oracle claim |
| QBIND-A1-F002 | **OPEN; IMPLEMENTED — VERIFICATION PENDING** at `149edffd8f7fd97c821d6df9a5a546eca4992b79`; supplied pre-implementation review and bounded execution record, section 13; A:L9280, A:L16254, A:L16363, A:L16506-L16513 | Offline qbind-gov approval counting; D; C5/O | Independent post-implementation code/evidence review pending; distinct from A8-F1, A23-F1 and bootstrap authority | Isolated baseline reproduction; 36 library + 4 CLI tests PASS, all 18 contract categories mapped in section 13 and retrievable F002 evidence; no new evidence ID |
| QBIND-A1-F003 | Durable timeout-signing design risk; exploitability unproven; A26 at A:L8099-L8230 | Timeout/NewView cross-restart history; DD/MI/ME; R-F5/C5 | Establish operation-specific journal and continuity requirements; RUN 422 Proposal/Vote result does not close it | Exact preimages/operations, durable history, restart/uncertainty/copies under approved scope; no slashable conflict asserted |
| QBIND-A1-F004 | Carried non-test insecure transport defaults; A:L9282, A:L16360-L16366 | Dummy providers/mutual-auth-disabled configuration axes; D/DD; O/C4/R | Check actual mode/primitive/map combination and operator-selected profile | Per-combination configured binary evidence, not source inclusion as deployed observation |
| QBIND-A1-F006 | Carried repository-documentation overstatement; not freshly revalidated by audit; A:L9283, A:L15919 | Repository claims versus OPEN posture; D; A/O/C | Name exact present-tense claim and current applicable evidence before correction | Source/evidence-linked claim review; report corrections alone do not close this repository finding |

### Rejected and imported identities retained

| Identity / locator | Disposition, reason and next action | Category / validation / gate |
|---|---|---|
| A2-F2; H01 / A2; A:L17685, A:L17781-L17796 | REJECTED-LEAD / resolved in validated production-input scope: absent/empty-root signature-skip excluded by builder/config length validation; custom resolver not compile-gated. Preserve; reopen only for relevant constructor/config change | ME (scope/evidence retention), not a new defect; regression if changed; O/C4 |
| H02 -> A7-F1; A:L17686 | Imported hypothesis resolved into canonical auth finding; not another task/count | D through A7-F1; E15; R-F1/F2 |
| H03 -> A8-F1; A:L17687 | Resolved into native governance finding, distinct from offline CLI | D through A8-F1; E16; C5/R before ingress |
| H04 -> H04-F1; A:L17688 | Resolved into missing remote-signer implementation, not oracle exposure | MI through H04-F1; E17; C5 |
| H05 -> A6-F1; A:L17689 | Resolved displaced ownership; temporary/unmapped NodeId occupancy dimension folded into A4-F1 | D through those two canonical rows; E10/E14; O |
| Intake NoopConsensusVerifier, suite-0 adapter and no-argument signing-preimage leads; A:L17776-L17778 | Reported production-reachability rejection, not independently re-audited; retain scoped reported status, not proof secure everywhere | ME; identify changed route before reopening; R |
| Intake "qc_verify_domain completely unwired"; A:L17779 | Narrowed to authority-gated wiring, not universal absence; selected refusal inspected by audit, full graph not claimed | MI/ME; supplier/route-specific evidence; R-F7 |

## 5. All 54 declared obligation identities

This is a definition-preserving coordination index, **not** an older index
relabeled "latest." `A22.1-C1` locates identity/property only; use section 3
corrections and each row's later references for disposition. Source-complete
labels remain bounded to their audited source sub-boundary. Historical ledger
statuses not supported by a current-lineage review remain provisional.

| Obligation | Property, latest audit disposition and locator | Category / component / gate | Dependencies and next concrete action | Required validation / closure evidence |
|---|---|---|---|---|
| OBL-CONS-1 | Timeout/TC admission; SOURCE-COMPLETE; A5 then A23.1 corrects current A1-F1 wording, A:L8969-L8972 | ME / binary timeout handlers / R-F5 | Preserve context/evidence gate; scope E01 behavior | Actual-handler absent-context and valid/invalid proof, no state effect before admission |
| OBL-CONS-2 | TC successor/signed-view binding SOURCE-COMPLETE / fix identified; A5, A:L15783 | ME / timeout verification / R-F5 | Do not redo resolved source review; execute pending boundary matrix later | Checked MAX/successor and mixed evidence; E02 |
| OBL-CONS-3 | Lock/vote/commit; SOURCE-COMPLETE **TC-setter route only**; A5/A5.1, A22.1-C2 | DD/MI/ME / engine locks / R-F7 | Separate catch-up on_qc and restart; preserve F7 supplier refusal | E03 downstream allowed-action and recovery evidence, not all-lock claim |
| OBL-CONS-4a | Catch-up downstream consumer inventory; source-complete bounded A19.3/current index A:L9174, A17-F1 retained | D/ME / catch-up dispatch/apply / R-F7 relevance | Check exact current effect boundary; separate error prefix/application/mode transition | E20 endorsement refusal and commit predicates |
| OBL-CONS-4b | Epoch header-cache association; bounded source-complete A19.4, A:L9175; older references baseline-qualified by A23.1 | ME / committed-block epoch consumer / R/C4 | Preserve identity split; applicability check before treating old trace as current | Exact header association and downstream epoch effects; E20 |
| OBL-CONS-5 | Verified-QC proposal path unwired; source-partial identity row, A33 chain advanced A:L6171-L6202 | MI/DD / authority-gated ingestion / R-F7 | Supplier and relevant invariant requirements before enablement | Verified evidence/wire/parent correspondence; A34.1 candidates remain |
| OBL-CONS-6 | two_thirds_vp callers/membership provenance; SOURCE-COMPLETE A27.1-C5, A:L7691-L7700 | ME / quorum arithmetic / R | Preserve caller inventory; weighted overflow residual separate | Corrected duplicate/weight/threshold assertions; no selected-binary overflow inferred |
| OBL-CONS-7 | Degenerate/sparse constructor admission SOURCE-COMPLETE bounded; A28.1, A29 carried corrections, A:L7350-L7358 | DD/ME / validator-set admission / R | Keep local_id >= 2^16 emission residual and actual signing gates distinct | Constructor/conversion guards; no automatic multi-node effect |
| OBL-CONS-8 | High-QC producer/aggregate/receiver source-complete A30.1, A:L6675-L6683 | MI/ME / Timeout/TC high-QC / R-F5/F7 | current_auth supplier missing; high-QC own endorsement must not be inferred from equality to evidence maximum | E03 configured propagation and Byzantine schedules under separate plan |
| OBL-CONS-9 | SOURCE-PARTIAL; A31/A32 predicates complete, A33 authentication advanced, A34.1 invariant questions open | DD/ME / HotStuff safety / R | Settle parent/QC and view-order requirements; do not invent full safety proof or new defect | Formal argument/counterexample plus scoped schedule evidence; A:L5851-L5861 |
| OBL-CONS-10 | Catch-up request/export/apply bounded source-complete; A22.1 identity A:L9181, historical ledger section 26.2M baseline-qualified | D/ME / restore protocol / R-F7 relevance | Check actual route and A17-F1 remediation boundary | E20 input provenance, effects and response controls |
| OBL-CONS-11a | Present Proposal/Vote handlers SOURCE-COMPLETE to latent implementation; A22.1 identity, A33 current-snapshot boundary | MI/ME / signed Proposal/Vote / R-F3/F4/F8 | Existing RUN 422 authority/journal contracts; production supplier absent | Configured binary positive/negative authentication, not unavailable-authority result |
| OBL-CONS-11b | EXCLUDED future enablement, not current-source task; A:L9183 | MI / future Proposal/Vote / R | Reassess only against approved concrete enablement change | New revision-bound admission/effect review before enablement |
| OBL-TRN-1a | Certificate acceptance without possession proof SOURCE-COMPLETE; A2-F1, A6/R1 qualifications | D / KEMTLS handshake / R-F6/O/C4 | Check current certificate/session-bound identity remedy | E08 certificate-only versus possession controls |
| OBL-TRN-1b | Dial/retry/reload lifecycle source-complete scoped A31/A10.1; A:L9185, A:L13172 | D/ME / dialer roots / C4/O | Preserve two-root/private-KEM/window conditions | E26 root check versus session versus insertion |
| OBL-TRN-2a | Session freshness/key-nonce reuse source-complete scoped; A11-F1 plus A6.2/R1 corrections | D/DD / KEMTLS schedule / O/C4 | Session-freshness policy and exact role/key prerequisites | E19 synthetic replay, not execution/forgery inferred |
| OBL-TRN-2b | Wired s2c emission/repeated-encryption conditions traced; R1 keeps receiving-session/counter questions open | D/DD/ME / s2c schedule / O/C4 | Check active receiver compatibility and current admission | E19 differing plaintext, key/counter alignment and acceptance separately |
| OBL-TRN-3 | Write retry/counter desync SOURCE-COMPLETE scoped; A13.1, A:L12228 | D / writer worker / O | Platform mapping and partial-write policy | E19 real-AEAD retry controls |
| OBL-AVL-1a | Accept occupancy/concurrency gap SOURCE-COMPLETE; A12.1 at A:L12461 | D / accept path / O | Distinguish rate limiter from occupancy and blocking-pool admission | E10 actual worker/socket release |
| OBL-AVL-1b | Bucket retention/cardinality SOURCE-COMPLETE scoped; A16/A28-F1 | D/ME / limiter maps / O | Per-address opt-in versus deployed message limiter | E25 key count, disconnect retention and measured growth |
| OBL-AVL-2 | Cookie source-proof not integrated SOURCE-COMPLETE assurance gap; A12.1 at A:L12462 | MI / handshake endpoints / O | Whole client/server retry integration requirements | E10 end-to-end pre-gate controls |
| OBL-AVL-3a | Mid-frame timeout framing desync SOURCE-COMPLETE; A13.1 at A:L12227 | D / frame reader / O | Exact target read behavior | E11 idle/partial-frame/fatal paths |
| OBL-AVL-3b | Downstream decrypt/desync traced scoped A29/A13.1; broader effects unproven | D/ME / decrypt/read loop / O | Preserve fatal-read versus reached-open counter distinction | E11/E19 connection-local impact, no blanket cross-node consequence |
| OBL-AVL-4a | Displaced session/eviction completeness SOURCE-COMPLETE; A13.1 at A:L12229 | D / session registry / O/C4 | Repeatable NodeId, detached ownership and cleanup | E14 registered/displaced idle/active comparison |
| OBL-AVL-4b | Eviction/reconnect full socket-release chain traced scoped; A13.1, A45.1 accounting preserves | D/ME / service shutdown / O | Abort request != blocking worker/socket completion | E14 completion and reload evidence |
| OBL-SUP-1a | Consensus-task owner/supervision SOURCE-COMPLETE bounded; A14.1/A15-F1 | D/ME / main task ownership / O/R relevance | Preserve actual owner/caller and no-inbound persistence corrections | E21 detection/recovery/process outcomes |
| OBL-SUP-1b | Outbound dial read-loop qualification source traced; A26 historical section 31 plus A13.1, A23.1 baseline rule | ME / dial/read ownership / O | Check precise route before applying older trace | E21 termination propagation and cleanup |
| OBL-PAR-1 | **OPEN**; inner parser/allocation source inventory complete to scope, A7.1/R7 then A42.1/A43.1; bounded A21-F1 correction **IMPLEMENTED — BOUNDED REVIEW PASSED** by independent source review and retained-evidence inspection (section 12); author-executed regressions recorded separately | D/ME / consensus/DAG codecs / O | Preserve hand-written versus serde distinction; no bincode limit-counter claim; select and independently verify the next bounded remediation from the remaining plan without authorizing implementation here | Caller-specific input caps, availability, nesting, reservation and E12/E13 residuals remain; no obligation closure |
| OBL-PAR-2 | Outbound-size boundaries source traced scoped A21/section 26.4b; A45.1 ingress does not close outbound | ME / frame/channel encoders / O | Check caller-specific outbound size and byte ownership | E13 item count != bytes; in-flight/copies included |
| OBL-DEP-1 | Retrievable pinned source, not availability-blocked (A23.1); bounded decoder review complete A43.1, broader residual open | ME / bincode/serde/std allocator / A/O | Do not re-queue completed schemas; pin remaining growth/aggregate question | Provenance, capacities versus requests, aggregate/runtime RSS E12 |
| OBL-DEP-2a | Repo-owned randomness/error chain complete sub-boundary A39.1; overall not declared complete A40 | ME / qbind-crypto integration / C5/O | Keep backend correctness/entropy and secret erasure separate | A40 platform/build inputs, A41 erasure scope; E06 |
| OBL-DEP-2b | UNREVIEWED, not proven BLOCKED (A27.1); A40 RNG/A41 key Drop narrow source results, not full backend audit | ME / crypto backend internals / C5 | Pin algorithm/constant-time question and available dependency source | R-DEP-2 analysis; runtime entropy remains separate |
| OBL-TX-1a | Auth completeness SOURCE-COMPLETE finding; A23.1 restores actual defect; opaque ingestion only reachability | D/MI / Transaction/BlockExecutor / R-F1/F2 | RUN 422 reconciliation before new work; keep three transaction types distinct | E15 auth positives/negatives and actual caller |
| OBL-TX-1b | SOURCE-PARTIAL downstream per-program authz/nonce/replay/payer; A8.1/A22.1 identity | DD/MI / ledger QbindTransaction callers / R before ingress | Name previously untraced caller/callback; approved native state/resource policy | Exact common-state, replay and program authority evidence E15 |
| OBL-GOV-1a | Governance auth absence SOURCE-COMPLETE finding, latent; A8.1 | D/MI / native governance / R before ingress/C5 | Preserve RUN 422 refusal, decide positive authority requirements | E16 source/library tests not production authorization |
| OBL-GOV-1b | SOURCE-PARTIAL downstream governance consumer variants; A8.1/A22.1 | DD/ME / SuiteRegistry/LaunchChecklist/raw loaders / C4/C5 | Name untraced variant, no generic rerun of completed execution inventory | Consumer-specific enforce/refuse effects E16 |
| OBL-GOV-2 | OPEN overall; A38.1 four composed surfaces traced, contract/integration gaps remain | DD/MI/ME / governance execution/apply/reload / C4/C5/O | A36.1 required-policy skips; live 0x05 threading/drain invocation missing | Invoked R1/R2 enforcing; skip-contract decision, then process/binary controls |
| OBL-SIGN-1a | Validator remote-signing wiring SOURCE-COMPLETE gap; A18/A18.1 | MI / daemon/node signer / C5 | Separate-signer feasibility and approved profile; no competing implementation | E17 actual daemon route/node mode, authenticated operation protocol |
| OBL-SIGN-1b | Broader lifecycle partial; Run-188 traced A23, journal present/unwired A26; provider/hardware/rotation unresolved | DD/MI/ME / custody/history / C5/profile prerequisites | Reuse D10/D14; C/L/X and relevant B/U decisions before integration | Actual process/device/rollback/exclusivity evidence, not fixture acceptance |
| OBL-KEY-1a | Loader/secret handling SOURCE-COMPLETE scoped A17.1; A41 narrows dependency erasure residual | D/ME / local keystore / C5/O | Do not repeat protected-object Drop review; assess unprotected intermediates | E18 disposable loader and runtime-lifetime evidence |
| OBL-KEY-1b | Writer-location SOURCE-COMPLETE A26, encrypted provisioning external; A:L8195-L8200 | MI/ME / encrypted provisioner / C5 | Obtain authenticated external writer/format provenance; plaintext DevNet example not production encrypted writer | Writer randomness/permissions/format and loader compatibility, separately scoped |
| OBL-GEN-1 | Genesis/bootstrap source-complete bounded A23-A23.3 historical trace, A22.1 identity; trust-binding finding remains | DD/MI/ME / genesis/ratification / R/C4 | Apply BR scoped decisions, operational label/pin still absent | Single validated genesis snapshot and independent expected identity; A23-F1/E23 |
| OBL-STO-1a | Startup restore trust source traced; A5.2/A5.3; local-crafted-anchor prerequisite retained | DD/ME / snapshot baseline / R/profile recovery | Approved authenticity/currentness/rollback requirements before recovery change | E22 anchor/state binding and local-write threat controls |
| OBL-STO-1b | Same-key restore/register acceptance source-complete scoped section 26.2L, baseline-qualified by A23.1 | DD/ME / restored block registration / R/profile recovery | Check exact candidate/anchor replacement and downstream condition | E22 same-key and ordinary distinct-ID cases separate |
| OBL-STO-2a | Broader storage/crash recovery OPEN; epoch write/read sub-boundary complete A46.1; regression A47.3 established conditional local trace | DD/ME / RocksDB epoch/restart / R/profile recovery | Resolve applicable contract/harmful consumer before declaring regression defect; other persisted objects not completed | API/atomic visibility vs clean reopen vs process crash vs power loss/rollback separate |
| OBL-STO-2b | EXCLUDED audit implementation thread: RUN 422 new journal/replay, A22.1/A26 preserve | MI/ME / D10/D14 / R/C5/profile | Continue existing thread and accepted subset, no competing journal | Producing-revision/component scope plus missing production/process correspondence |
| OBL-STO-3 | Snapshot output edge split from CONS-4, source-complete bounded section 26.3 / A22.1 identity | DD/ME / create_snapshot output / R/profile recovery | Preserve edge identity and input-to-durable-output trust question | E20/E22 snapshot anchor and epoch correspondence |
| OBL-OPS-1 | SOURCE-PARTIAL beyond completed metrics endpoint; A15/A24-F1 | D/ME / configuration/fail-open/observability / O | Name remaining default/fallback, check real operating profile | Config-specific refusal/visibility evidence; E24 metrics remains separate |
| OBL-REL-1a | Build/workflow source sub-boundaries complete A48.2/A49.1; constant-clean producer defect source-confirmed to its stated mechanism | D/ME / release manifest/workflows / A | **IMPLEMENTED / INDEPENDENTLY VERIFIED / PUBLISHED**; **PASSED/CLOSED** only for the bounded reporting correction and its isolated validation at the revisions recorded in section 8; earlier pending states narrowly superseded | E07 overall remains **OPEN**; build/artifact/deployment evidence and release eligibility remain unestablished |
| OBL-REL-1b | External CI/artifact/historical assurance remains evidence-blocked; A48.2/A49.1 | ME / artifacts/attestation / A | Obtain authorized exact run/artifact/environment evidence; source review cannot create it | Source-to-built-to-deployed correspondence; delegated attestation unexecuted |
| OBL-EXT-1 | 14-crate/repository interface inventory **NOT REVIEWED AT CURRENT AUDIT BASELINE**; identity A:L9221. Historical detailed definition/classification at A:L19453; A23.1 precedence A:L8982-L8989 means historical status is not current-source verification | ME / crate inventory; `ledger_bridge`, `timeout_verification_bridge`, `metrics_http`, and relevant EVM/execution interfaces (`QbindTx`, `VmV0ExecutionEngine`, `BlockExecutor`) / O and A only where existing gates apply; functional EVM/auth review remains OBL-TX-1a/1b | Treat A18.1's five-level presence/callability/production-wiring/ingress/not-found classification as historical, bounded evidence. Independently re-inventory current baseline within an explicit crate/filename/server-entrypoint search scope before relying on it; internal "bridge" files are wiring, not cross-chain bridges | Record code presence, callable library interface, production wiring, external ingress, and not-found-within-search-scope separately. Historical finding: EVM/execution code and callable interfaces present but no production wiring / no external ingress located; `metrics_http` is non-transaction `/metrics`, routed to OPS-1. Historical scoped searches found no wallet/JSON-RPC/cross-chain-bridge/contract-deploy ingress, not blanket absence. No current applicability claim until checked |
| OBL-LIVE-1 | BLOCKED on live-deployment evidence; latest owner clarification is stopped development machines | ME / deployment/launch profile / M4/M6/S5/S7/RS1 | No live probe or activation; approved profile/prerequisites first | Separately authorized external/multi-node evidence; E09, no non-use proof |
| OBL-PROV-1 | EXCLUDED separate candidate-provenance thread; E04/section 17 | ME / Run-422 candidate 56524ee provenance / A | Preserve prior provenance work; missing shallow objects not non-ancestry | Commit/tree/object availability, proven ancestry and scoped content correspondence separately |
| OBL-REPRO-1 | Runtime evidence, not a source-completion task; audit reproductions remain unexecuted as stated | ME / revision-bound reproductions / R/O/A as applicable | Before implementation, verify current source applicability and the proposed correction under section 2. Decide whether behavior needs pre-change observation; if so, require its own scoped authorization and isolated controls. Then plan post-change regression/runtime evidence separately; reuse prior results only within their producing scope | Source evidence may establish a deterministic defect without live reproduction. Where needed, record exact pre-change binary/config/counters/logs and controls; post-change regression, independent code review, later binary/runtime evidence and release eligibility remain distinct |

## 6. Evidence inventory and unnumbered residuals

E-identities are **evidence obligations, not 27 extra defects**. Definitions
come from A:L17691-L17721; later corrections in section 3 override stale
subclaims there. Each remains open to its stated extent, with section 7's
existing scoped results retained.

| Evidence ID | Latest scope / linked obligations | Category / component / gate | Dependency and next action; required closure evidence |
|---|---|---|---|
| E01 | A1-F1/F2/F3 actual-handler reproductions; CONS-1/2/3 | ME / timeout handlers / R | Source gates retained; revision-bound real-signature accept/refuse and no-effect controls |
| E02 | View limits/persistence/recovery; source successor fix identified | ME / pacemaker/TC / R | Current overflow fixes need applicable producing evidence, not obsolete unbound-view claim; target build/config and recovery matrix |
| E03 | TC lock downstream consumption/allowed actions; not global safety closure | DD/ME / lock/commit / R | Preserve TC gate; separate catch-up and Byzantine proof; configured post-implementation evidence |
| E04 | Excluded RUN 422 candidate provenance | ME / provenance / A | Prior thread, no inferred non-ancestry; commit/tree/content correspondence |
| E05 | Release-binary/isolated multi-node validation | ME / real binary / R/O | Relevant implementation tested and separately approved plan; actual process configuration/artifact identities |
| E06 | PQ trust/crypto coverage; A39.1-A41 source refinements | ME / crypto integration/backend / C5 | Pin remaining algorithm/platform/entropy scope; no wrapper review as backend correctness proof |
| E07 | **OPEN** overall: release/CI/build/historical assurance; A48.2/A49.1 four planes | D/ME / manifest/build environment / A | Section 8 bounded reporting correction independently verified and published; **PASSED/CLOSED** is limited to that correction and isolated validation, not effective-build/artifact evidence or provenance closure |
| E08 | A2-F1 possession reproduction | ME / transport / R-F6/O | Disposable isolated control set; public cert versus key-holder, actual session admission |
| E09 | Deployment and validator launch profile | ME / live operation / M4/M6/S5/S7/RS1 | Four stopped machines are not live evidence; approved deployment/test scope first |
| E10 | A4-F1 occupancy and A4-F2 cookie integration | ME / handshake resources / O | Occupancy/worker/socket release and complete cookie/client retry, not rate alone |
| E11 | A5-F1 frame-timeout platform behavior | ME / read framing / O | Exact partial-consumption schedule with idle/valid controls and connection outcome |
| E12 | **OPEN**; parser/dependency/aggregate memory; A21-F1 decoder evidence obligation retained | ME / codecs/allocator / O/A | A43.1 schema source work retained; bounded A21-F1 structural preflight **IMPLEMENTED — BOUNDED REVIEW PASSED** by independent source review and retained-evidence inspection (section 12); author-executed focused regressions separate; explicit cap != heap cap, request != capacity/RSS; broader dependency/aggregate residuals remain open |
| E13 | Queue/ownership/outbound byte budgets; separate queue/aggregate-memory scope, not the A21-F1 local correction | ME / channels/encoders / O | Four-channel A45.1 inventory, in-flight buffers/concurrency/outbound caller sizes and deployment-dependent effects retained; no global ceiling asserted or closed by section 12 |
| E14 | Displaced-session/eviction/reload completion | ME / session lifecycle / O/C4 | Registered/displaced, idle/active, EOF/fatal, task and blocking worker plus socket completion |
| E15 | Transaction families/auth/caller/state/nonce | DD/MI/ME / native/ledger/EVM / R before ingress | RUN 422 source/test slices retained; approved positive authority and actual deployed caller remain |
| E16 | Native governance/consumers | DD/MI/ME / governance programs / R/C5 | Refusal != usable governance; name remaining consumer and prove approved authorization |
| E17 | Remote signer actual daemon/node/policy | MI/ME / signer / C5 | No dead-handler credit; authenticated process operation and real node wiring under approved contract |
| E18 | Loader/provisioning/secret lifetimes | ME / keystore/wrappers / C5 | A26 writer-location/A41 ordinary-Drop findings retained; disposable inputs and runtime erasure limits |
| E19 | Session replay and distinct write-retry desync | DD/ME / KEMTLS/AEAD / O/C4 | Real primitive synthetic controls, role/key/counter alignment, conditional receiving acceptance |
| E20 | Catch-up/QC/signature-power downstream consequences | D/DD/MI/ME / consensus / R | Current snapshot supplier absent; A17-F1 endorsements distinct; configured applicability and end-to-end effect evidence |
| E21 | Task supervision/termination propagation | ME / node owners / O | Actual task/process/listener outcomes and shutdown evidence, not handle existence |
| E22 | Local snapshot authenticity/currentness/same-key consequences | DD/ME / restore / R/profile | Local-write threat and approved recovery requirements; exact snapshot-to-anchor/state/signing restrictions |
| E23 | A23-F1 K/T target-binding runtime confirmation | ME / trust activation / C4/O | Correct invoked-gate/data-dir/external-genesis prerequisites and independent key controls |
| E24 | Opt-in reachable metrics handler resource outcome | ME / HTTP metrics / O | Bounded size/concurrency/deadline/shutdown experiment; source gap != observed OOM |
| E25 | Bucket retention/count/rate/memory | ME / two limiter subcases / O | Workload-bound counts, post-disconnect retention and effect; no general availability outcome inferred |
| E26 | Outbound root revocation propagation | ME / dialer / C4/O | Two-root/private-key/window prerequisites; root check, handshake and registry observables separate |
| E27 | Conditional ancestry-walk runtime impact/prerequisites | ME / block eviction / R/O | A5.3 registration-time witness supersedes older constructions; local crafted anchor/admitted peer; no historical non-use inference |

| Exact section locator / residual | Latest disposition; category; gate | Dependency and next action | Required closure evidence |
|---|---|---|---|
| A13.5, A:L12367-L12397: Box::leak | Open unnumbered cumulative-retention question, not minted finding; ME; O | Preserve small box plus retained Arc count per processed handshake frame, including later-rejected attempts; not a provider clone or every TCP accept | Producing call/lifetime/accounting and actual retained impact if claimed |
| A22.1-C4, A:L9288-L9306: direct custody verifier / Run-188 | Inconsistent direct envelope can reach accepted-labelled enum, consequence unproven; no production consumer is not proof of no consequence. Run-188 source gap later advanced A23; DD/MI/ME; C5 | Preserve A23 composition, separate latent direct API from production integration | Actual caller/gate/consequence evidence, no reopened completed composition review |
| A27.1-C4/C5, A:L7661-L7719: weighted library 2*total | Bounded open arithmetic observation; no selected-binary reachability; DD/ME; R relevance pending | Check actual arbitrary-weight consumer and intended numeric contract | Boundary arithmetic plus reachable caller, not unit-weight engine overflow assertion |
| A34.1-C1/C2/C4, A:L5741-L5861 | Parent/QC binding and proposal/justify ordering remain protocol-invariant candidates, not proven defects; DD; R | Settle applicable engine-path invariant with proof/counterexample before implementation | Full conditional self-vote trace and invariant argument; production snapshot gate retained |
| A36.1-C1 + A38.1, A:L5032-L5077, A:L4397-L4426 | Required-policy non-invocation contract/integration candidate; DD/MI; C4/C5/O | Clarify skip/v1/no-data-dir/live-0x05/drain contract; no advisory-hook overclaim | Contract decision, exact surface-specific invocation/refusal and later binary evidence |
| A37.1-C2/C3 + A38 carry-forward, A:L4744-L4785, A:L4629-L4671 | Run-216/227 regression status not aggregated into PASS: evidence-harness assurance defect; D/ME; A | Bounded current harness check, then verdict/status fix; not node protocol defect or fabricated-run allegation | Failing regression flips verdict/status; exact harness/helper/evidence producing source, unavailable historical artifacts disclosed |
| R-DEP-1/R-DEP-2/R-RUNTIME-1, A39.1-A41 | RNG source chain resolved to scope; deployed backend/build and runtime entropy remain; algorithms/constant-time not performed; ME; C5 | Pin platform/features/cfgs and exact remaining backend question | Dependency provenance + build inputs; runtime entropy separate, no generic source rerun |
| R7.3/E12, A42.1-A45.1 | Schema/visitor/postdecode/four-channel route complete to scope; aggregate capacities/RSS/concurrency residuals; ME; O | Preserve corrected precheck/Infinite-limit and copy accounting; name unmeasured quantity | Revision-bound aggregate experiment under separate plan; no new forced defect |
| A47.3-C1-C3/disposition, A:L1039-L1151 | Local stored n>1 -> 1 regression trace established; violated contract/harm unestablished, no new finding; DD/ME; R/profile recovery | Resolve relevant storage/transition contract and consumer impact before a transition change | Correct restore chronology, cursor-vs-DB writer, atomic visibility != power-loss durability; multi-validator residual separate |
| A48.1-C2 / E07 / OBL-REL-1a, A:L650-L688 | Constant-clean producer evidence-assurance correction source-confirmed to the stated mechanism; D; A | **IMPLEMENTED / INDEPENDENTLY VERIFIED / PUBLISHED** in section 8; **PASSED/CLOSED** strictly for the bounded correction and isolated validation; historical pending states narrowly superseded | E07 overall remains **OPEN**; build provenance and other E07 evidence planes remain outstanding; no broader finding or release closure |
| A48.1-C6 + A48.2 + A49.1, A:L739-L768, A:L412-L593, A:L1-L202 | CRLF invocation, job/check/artifact ordering, external controls and delegated attestation retain qualifications; ME; A | No harness execution here; external run/environment evidence separately scoped | Actual reached stages, status/effects and source-to-artifact/deployment correspondence |

Retain negative sub-dispositions as well as open work: A17.1-C1-C5 and
A17.7 (A:L10741-L11118) do not support a format-label algorithm downgrade or
accepted arbitrary salt/nonce/iteration/ciphertext tampering; loader/KDF and
intermediate-secret observations are distinct. A16 (A:L11294-L11304) keeps the
capped metrics peer map separate from uncapped limiter buckets. A10.1 rejects
the original single-root revocation witness, not the corrected two-root
mechanism. A13.1 distinguishes no-progress timeouts (no lost framing) from
mid-frame timeouts. Neither a withdrawn witness nor an answered sub-question
withdraws its still-supported canonical finding.

## 7. RUN 422 continuity and existing evidence

Use the maintained [critical path](../devnet/QBIND_PUBLIC_DEVNET_CRITICAL_PATH.md),
[D7 evidence](../devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md) and
[bootstrap decisions](../devnet/QBIND_RUN_422_DEVNET_BOOTSTRAP_AUTHORITY_DECISION.md),
including their later corrections. Their existence is not a new execution
result. This task read those documentation surfaces, not a new consensus,
transport, native-auth or recovery source audit. The following are existing
applicable verification references **only to their named scopes**:

| Audit mapping | Existing producing evidence / effective scope | Continuation, not competing implementation |
|---|---|---|
| CONS-1/2/3/8; A1-F1/F2/F3; E01-E03/E20 | Critical-path sections 2-4 and D7 E7-E9 record mandatory timeout gates, retained-QC revalidation and exhaustion controls. F7 implementation `d17a4db2a24c682f988594e6c3347f24adeffcae`, reconciliation `efa76f08134792d754a0a25fae7898df6579592e`, as documented | Keep actual caller/configuration prerequisites and TC versus Proposal/QC routes. No configured release-binary or full recovery result inferred |
| SIGN-1b/STO-2b; E17/E20/E22 | D10 `D7D10_LOCAL_SIGNING_RESERVATION=CODE-AND-STORAGE-TEST-POSITIVE`; effective aggregate A-F acceptance in [continuity contract](../protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md), lines 1857-1991 | Local journal/reserve/uncertainty/exact-result acceptance only. No second authoritative node history. Proposal/Vote journal evidence **must not automatically close QBIND-A1-F003 timeout signing** |
| STO-1/2/3; CONS-3/8; E20/E22 | D14 `D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED`; `D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET`; accepted 23-row subset: candidate `aad0a4aaca8f66580d257c3468f1c27059145dbd`, reviewed evidence `ecf4cfdcc36e9438293173d89e44cd819d709ca5` | Later owner/publication/recovery models do not enlarge independently accepted subset or production integration; completed reviews not reopened |
| CONS-8/STO-2b; E03/E20 | Isolated TC/O4 finishing source `37709512d03c547d32d3494d4270bf04c2ad28d1`; explicit O5/exact-TC resumption `0553e374edf6a9221870b9c5e4f8a6689af3901f`; D7 lines 26464-26476 | Do not reimplement TC/O4. O5 resumption retained in-process evidence, not process-death reconstruction or production TC lifecycle closure |
| TX-1a/1b; A7-F1; E15 | D7 lines 26439-26461: threshold source `0a163bb733f7dd160a588b5aa11cd37ad13fd143`, tests `31af27f46aef427299fc83bffdfaaee7c0077753`; format source `da9bb1ffac15a5d2746014dcb89f8c1d36a5ea92`, corrected tests `15b53f496c8164d5bab4bff2713c44de5413e81b`; source blob `47b8309be4b42ab284b184f9ccf6ea12eecb1382` | Historical empty-auth acceptance is not current-source claim. Structural checks/individual first-key threshold != full aggregate weighted/key-identity/state/replay authority or standalone caller |
| TX/GOV-1; A8-F1; E15/E16 | Critical-path section 3: governance refusal `99023fcb30ec2c6c042dea0f0196b88c072049ac`, validator refusal `02198fac5ba638a1fbcbc2c5361fce7116a33e51`, keyset refusal `92ba29ee13b2470e4b21b681aefcd8cf1ecf3264`; later key-identity controls `52a9bcd1280c002755311c2a5d290b67691b11b1` focused 6/6 | Retain unavailable-authority refusals, not positive program authority; historical 990-selected package result belongs only to `1112d4b9f93a281085c10a0b4fd016f9194f0f0e`, not later corrected tests |
| GEN-1/GOV-2/SIGN-1b; CONS-5/11; E20 | Bootstrap decision document later BR-01, BR-02, BR-03 owner acceptances and BR-04 append/clarification | Technical dependencies below remain. No automatic implementation permission or reopened accepted review |

Effective owner decisions are narrowly scoped: **BR-01 ACCEPTED - DESIGN
ONLY**; **BR-02 ACCEPTED - IDENTIFIER ALLOCATION AND COMPATIBILITY CONTRACT
ONLY**, including exact layout; **BR-03 ACCEPTED - MAPPING POLICY ONLY**.
Overall BR-03 remains **OPEN / CLOSURE NOT ESTABLISHED**: exact operational
genesis label/canonical pin/configuration NOT SUPPLIED, independent
provisioning NOT DONE, production mapping NOT IMPLEMENTED, required
executed/release-binary correspondence evidence NOT PRODUCED.

**Olive (Project Lead / Lead Operator) remains accountable for both B and U.**
That shared accountability is not independent control or assignment of every
custody/readback/restore/enforcing role. Earlier unassigned B/U statements
are historical only for those accountable-person roles. **BR-04 technical
decision PENDING; operational B/U and overall closure NOT ESTABLISHED.**
No witness/counter/HSM/quorum service or failure-model exclusion is selected.
N=4, q=3 consensus parameters are not a B/U witness committee.

Effective deployment description: **four provisioned local development/test
machines, all stopped; no prior live multi-node Public DevNet consensus
operation reported**. This supersedes earlier "running validators" wording;
it is owner-reported, not independent machine evidence or an approved
founding configuration. The separately supplied node-A process observation
(2026-11-03T15:33:27.276224+00:00, visible processes named exactly qbind-node:
none observed) **proves no historical non-use** and covers neither all
machines nor names/containers/namespaces. It does not establish unused
keys/approvals/journals, absent signatures/reservations, B, or network-level U.
Reported local RocksDB/journal/0600 keystores do not prove enforced binary
wiring, separate signer, independent restore domains or safe recovery.

B authenticates present applicability, U unique authorized network
instantiation, C per-key authoritative history, L node lock/safety recovery,
X exclusive permitted key use. A valid approval supplies none of B/C/L/X/U.
Full-payload identity, custody, recovery, currentness, exclusivity,
operation/effect correspondence, uncertainty and production integration
remain separate requirements under the
[lifecycle contract](../protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md),
[recovery correspondence contract](../protocol/QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md)
and [bootstrap recovery trust model](../devnet/QBIND_RUN_422_BOOTSTRAP_CREDENTIAL_RECOVERY_TRUST_MODEL.md).
Backups/generation equality/empty local state do not establish freshness;
possibly signed Reserved state cannot be erased or re-signed by approval.
Retained result reuse requires its exact existing contract, not new permission.

Preserved: section 13.6 whole-lifecycle **INCOMPLETE**, durable anti-rollback
**NOT-ESTABLISHED**, candidate limits **UNAPPROVED**, whole native admission
and authority contracts **DRAFT / NOT APPROVED / NOT IMPLEMENTED**.
Implementation prerequisites **NOT SATISFIED**, implementation authorization
**PENDING**, founder-root/profile provisioning **NOT DONE**; activation
**DISABLED**, public DevNet **NO-GO**. BR-05-BR-11 and unresolved C/L/X
remain unchanged. RS1 and broader C4/C5 remain OPEN. M4 preparation may
continue alongside RS1 work; M6 live identity admission remains M4-gated;
M4 Yellow, M6 Yellow/Partial, S5/S7 and existing readiness distinctions
are not changed.

## 8. First bounded candidate task card: constant-clean producer

**Current bounded status (2026-11-03): IMPLEMENTED / INDEPENDENTLY VERIFIED /
PUBLISHED. PASSED/CLOSED — independent review of the bounded E07 correction.**
This disposition applies only to the correction and its isolated validation.
The completed independent review and separate publication record below
narrowly supersede the historical proposal and verification-pending states,
which remain as history. **E07 overall remains OPEN**; activation **DISABLED**
and public DevNet **NO-GO** remain unchanged.

### Review provenance recorded before implementation

Before implementation began on the required baseline commit
`6dd0bc9d4ad5426065460270bf30c2cda6b2ca37` (tree
`1796cf4eb505c15945f5c48821cc83329fcf5305`), the user conveyed that an
independent ChatGPT review of this finding and the section 8 correction
contract had completed with **PASSED / CLOSED** disposition for the bounded
reporting design, classification/error rules, observation timing, caller
compatibility, and future validation matrix. This records the provenance and
scope of that pre-implementation review only; it is not a review or acceptance
of code, which did not yet exist. GitHub Copilot is assigned the bounded
implementation in this task. No operational or protocol-authority role is
inferred from that assignment.

**Historical task-card status at contract-proposal time (retained; subsequent
review and implementation are recorded below): E07 / OBL-REL-1a / A48.1-C2.
FIRST BOUNDED CANDIDATE; not highest-severity ranking. Owner UNASSIGNED.
Finding status: SOURCE-CONFIRMED TO THE STATED MECHANISM. Correction contract:
PROPOSED / AWAITING INDEPENDENT REVIEW. Implementation: NOT STARTED.
Regression/runtime evidence: NOT EXECUTED.**

### Pinned evidence and scope of inspection

| Identity | Pinned value / observation |
|---|---|
| This task's implementation baseline | Commit `59d3021e050e289a05a2368040f7b68d52b2ce57`; tree `39ce4cd728393b7aa8ec0c8eb7e6de0c303ef032`; `origin/main` matched both at entry |
| Task branch / starting plan blob | `copilot/audit-e07-manifest-preimplementation-contract`; plan mode `100644`, blob `9477b9bc51b7b51ed03e92233453934f5d011b46` |
| Audited source baseline, kept distinct | A49.1 / internal v1.138 identifies commit `18d71a549d868ed33d352e9fc70a9d060f75e03b`, tree `5b6c543435ac017dd8372c93f48be397899db14a` (section 1); this is not this task's implementation baseline |
| Committed audit input at this task baseline | `Audit/QBIND_SECURITY_FINDINGS_REGISTER.md`, mode `100644`, blob `cd81efdbaf2bfb45e00dc3c60db3ea4f523adfa0`; A49.1 / v1.138, finding A48.1-C2 at A:L650-L688 |
| Run 384 producer | [Source](../../scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh), mode `100644`, blob `53be84e52f97288a2eba0fa53eee296c8d62a2a9`; lines 221-227 assign `clean` in both branches after worktree/index diff checks, including Git-error paths; line 261 emits the field |
| Manifest schema | [Schema](../release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.schema.json), mode `100644`, blob `54ae5827ce5bcd749bb674742128eb1b20afce8b`; `source_tree_state` is required, enum `clean`/`dirty`/`unknown`; description currently says "Source tree cleanliness at build time" |
| Run 385 wrapper | [Source](../../scripts/devnet/run_385_public_devnet_ci_release_artifact_manifest.sh), mode `100644`, blob `3c5a0f930195107b6d5a28c48ec7122140740a11`; lines 98-109 invoke Run 384 and require its positive summary; lines 134-178 stage and fully schema-validate the manifest; it does not recompute cleanliness |
| Producer workflow | [Workflow](../../.github/workflows/public-devnet-release-artifact-manifest.yml), mode `100644`, blob `b77bdc58e2d323d6cb784b8e056f1adc424dc337`; lines 72-74 invoke Run 385 |
| Additional workflow caller | `.github/workflows/public-devnet-release-signing-attestation.yml`, line 97 invokes Run 385 before attestation; it does not classify source state |

Repository-wide tracked-file searches at the pinned baseline used
`git grep -n` for `source_tree_state`, both harness names and the schema
filename. Direct value production is Run 384; Run 385 consumes the generated
manifest, schema-validates it, and stages it; both workflows above invoke Run
385. The schema defines the enum. The existing example at
`docs/release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.example.json:31`
contains `clean`. Maintained descriptions relevant to the field are in
`binary/README.md` §10a, `binary/BUILDINFO.md` under "Canonical release-artifact
manifest", and `binary/VERIFY.md` §6b-6c. The committed A48.1 audit register
and Run 384/385 historical evidence documents also describe the behavior; they
are evidence, not implementation consumers, and remain unchanged. No source,
schema, example, workflow or historical-evidence file is changed by this task.
Other tracked matches for the schema/harness names are documentation pointers
and evidence indexes (including `binary/REPRODUCIBILITY.md`,
`ARTIFACT_INDEX.md`, and the Run 384/385 evidence documents), not additional
classifiers. Run 387's schema-name reference concerns `signed_release` and
`slsa_grade`, not `source_tree_state`.

### Proposed correction contract for a subsequent task

**Classification boundary and producer integration.** Add
`scripts/devnet/lib/source_tree_state.sh` with the single shared boundary
`qbind_classify_source_tree_state`. Run 384 will source and call that boundary
once immediately before manifest serialization. Future tests will source and
exercise that exact function against disposable repositories; they must not
reimplement its logic. The function's stdout is exactly one validated enum
(`clean`, `dirty` or `unknown`); diagnostics go to stderr, never to the
published manifest. Unknown is a successful classification result. A failed
helper invocation, empty/extra/invalid output, or any result outside the
enum fails manifest generation; none may default to `clean`.

**Declared scope and exclusions.** Classify Git-observed tracked repository
paths, excluding `docs/**` only, using both HEAD-to-index and index-to-worktree
observations. Include staged and unstaged differences, tracked additions,
deletions, renames, supported mode/type changes, and tracked submodule state.
Do not silently exclude `Audit/`, workflows, scripts, lockfiles, or any other
tracked path. Untracked and ignored files, external build inputs, toolchains,
environment/configuration outside the repository and dependency/build
environment state are outside this tracked-only classification. Git-normalized
state is neither a raw-byte comparison nor a hermetic-build guarantee.

**Truth table and failures.** A completed no-difference observation is
`clean`; completed observations establishing any difference are `dirty`;
any required indeterminate/failed observation is `unknown`. Treat Git diff
exit 0 as no difference, 1 as difference, and other exits or invocation
failures as errors, not differences or success. Unknown takes precedence over
dirty if one required observation fails. Missing Git, an invalid repository,
an unavailable required revision, or a failed required observation can never
produce `clean`; emit a separate diagnostic explaining unknown. Invalid
classifier output or inability to invoke the helper is a manifest-generation
failure, not an `unknown` default.

**Observation time.** Retain one bounded observation immediately before
manifest serialization, after the existing build and scrape stages. This is
the state observed at that point, not state "at build time", not proof that
inputs remained unchanged throughout the build, and not source-to-binary
correspondence. Detectable instability during classification (for example
HEAD/index changes or repeated observations that disagree) must yield
`unknown`; bracket the diff pass with HEAD and index identity checks and repeat
the required observations, returning `unknown` if either pass or identity
differs. This is a bounded instability control, not an atomic-snapshot or
undetectable change-and-restore guarantee.

**Caller and schema compatibility.** Run 385 continues full schema validation
and records valid `dirty` and `unknown` values; when the value is `unknown`,
retain an explicit diagnostic in the ordinary run output, separate from the
manifest. Do not add a clean-only release gate or interpret schema-valid,
`RESULT=POSITIVE`, or artifact staging as clean source, provenance, or release
eligibility. Keep the enum and manifest structure unchanged. In the future
schema edit, replace the "at build time" description with wording that names
Git-observed tracked-path state at manifest-observation time and its
`docs/**` exclusion. Because this corrects description only and adds/retypes
no schema data, keep the schema's `$schema`, `$id`, `schema_version` value and
manifest schema version at `1.0.0`; no version bump is proposed. Preserve the
existing example's `clean` value and all historical values as historical
evidence; do not retroactively repair or re-label them.

**Unsupported or hiding conditions.** The classifier must neutralize or
explicitly reject diff settings that can suppress required observations
(including external diff/textconv and submodule-ignore behavior), and verify
mode reporting rather than trusting a configuration that suppresses mode
changes. Any relevant diff configuration it cannot neutralize yields
`unknown`. Detect `assume-unchanged` and `skip-worktree` index flags and
return `unknown`; sparse checkouts, unresolved index entries, or incomplete
index/revision access likewise yield `unknown` unless the implementation can
prove complete in-scope coverage. Force submodule dirt visibility where
supported; an uninitialized/unavailable submodule or any submodule state that
cannot be observed (including required nested tracked state) yields
`unknown`. Untracked/ignored files inside submodules remain excluded under
the declared tracked-only rule. Concurrent changes detected by stability
checks yield `unknown`; no claim is made for undetected transient mutations.
Tests must prove each supported mode or its explicit `unknown`/unsupported
outcome rather than assume Git configuration or filesystem behavior.

**Exact anticipated paths (not created by this task):**

* Implementation: `scripts/devnet/lib/source_tree_state.sh` (shared
  classifier); `scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh`
  (call and fail-closed output handling).
* Regression tests: `scripts/devnet/tests/test_source_tree_state.sh` (sources
  the production helper and builds disposable Git repositories/synthetic
  manifests).
* Direct documentation: `docs/release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.schema.json`
  (description only); `docs/release/public-devnet/binary/README.md`;
  `docs/release/public-devnet/binary/BUILDINFO.md`; and
  `docs/release/public-devnet/binary/VERIFY.md` (scope, timing, exclusions,
  diagnostic, and non-claims). Do not change the existing example.

### Historical pre-implementation validation matrix (FUTURE / NOT EXECUTED at proposal time)

All rows below preserve the original proposed regression cases; none had been
run when the contract was proposed. The successor record below reports their
bounded fixture execution. Use disposable
temporary Git repositories and synthetic manifests, never the real checkout.
First characterize the pinned baseline from its committed source: dirty
worktree/index observations and failed Git observations both select constant
`clean`; do not execute Run 384/385 to do so. Then invoke the actual shared
future classifier for the corrected outcomes.

| FUTURE case / control | Required result | Status |
|---|---|---|
| Clean repository; positive control with no in-scope changes | `clean` | FUTURE / NOT EXECUTED |
| Unstaged tracked edit; staged tracked edit; staged plus unstaged edit to the same/different paths; positive controls for each layer | `dirty` | FUTURE / NOT EXECUTED |
| Tracked addition, deletion and rename; positive controls | `dirty` | FUTURE / NOT EXECUTED |
| Supported executable-mode, symlink/type and other Git-representable mode/type changes; filesystem/config that cannot establish them | `dirty` when observed; otherwise explicit `unknown`/unsupported | FUTURE / NOT EXECUTED |
| `docs/**`-only tracked change; positive scope-exclusion control | `clean` | FUTURE / NOT EXECUTED |
| Untracked-only and ignored-only changes, including generated files; positive exclusion controls | `clean`, with the tracked-only limitation documented | FUTURE / NOT EXECUTED |
| Changes under `Audit/`, `.github/workflows/`, `scripts/`, and to `Cargo.lock`; positive inclusion controls | `dirty` for each | FUTURE / NOT EXECUTED |
| Tracked submodule gitlink change and initialized submodule tracked edit; submodule ignore settings; unavailable/uninitialized or incompletely observed (including nested) submodule | `dirty` when observed; otherwise `unknown` | FUTURE / NOT EXECUTED |
| Whitespace, leading-dash, newline, non-ASCII and other unusual tracked filenames | Correct `dirty`/`clean` result without path parsing loss | FUTURE / NOT EXECUTED |
| Diff-ignore/external-diff/textconv/submodule-ignore configuration; mode-detection configuration | Force correct observation or explicit `unknown`; never hidden `clean` | FUTURE / NOT EXECUTED |
| `assume-unchanged`, `skip-worktree`, sparse checkout, unresolved index state and missing required revision | `unknown` with separate diagnostic | FUTURE / NOT EXECUTED |
| Missing Git executable, invalid repository, diff exit/error, and other failed required observations | `unknown` with separate diagnostic | FUTURE / NOT EXECUTED |
| Mixed dirty observation plus an error; mutation detected between stability observations | `unknown` takes precedence; diagnostic remains separate | FUTURE / NOT EXECUTED |
| Helper nonzero exit, empty/invalid/multiple stdout values | Manifest generation fails; no manifest falsely reports `clean` | FUTURE / NOT EXECUTED |
| Every enum emitted by the classifier in a synthetic manifest; full schema validation; Run 385-compatible caller/staging behavior | All three enum values schema-accepted and recorded; unknown diagnostic is not in published manifest; no clean-only gate | FUTURE / NOT EXECUTED |
| Baseline positive/negative controls versus corrected classifier on the same fixtures | Pinned baseline remains constant-clean even for dirty/error fixtures; future classifier matches the truth table | FUTURE / NOT EXECUTED |
| Controlled post-build/pre-serialization fixture mutation and stable/unstable repeated observations | Value reflects observation-time state; detected instability is `unknown`; no build-time/continuous-snapshot claim | FUTURE / NOT EXECUTED |

No Run 384/385, Cargo, node, workflow, build, scanner, signing, deployment or
activation is part of this contract or its future fixture matrix.

### Historical pre-implementation review boundary

At contract-proposal time, this source finding was **confirmed to the stated
mechanism**, the correction contract was **proposed and awaiting independent
review**, and implementation/regression evidence had **NOT STARTED / NOT
EXECUTED**. This historical status is retained; the later pre-implementation
review provenance and successor implementation evidence follow. No additional
protocol-owner decision was required merely for this bounded reporting defect.

Eventual closure may cover only truthful Git-observed classification within
the declared scope and observation timing. It does not close E07 overall or
establish build provenance, historical-artifact correctness, runtime safety,
source-to-built or binary-to-deployed correspondence, or release eligibility.

### First implementation and focused evidence — historical, superseded in part (2026-11-03)

**Historical disposition as recorded at `0c23009037b75817d9ff3b97f4176ce348b2e100`:**
the first implementation and its fixture matrix were reported
**IMPLEMENTED / TESTED**. This report is retained as history, not current
verification. The review supplied through the present task identified an
fsmonitor false-clean and masked fixture cases; the corrected status and
revision-bound follow-up evidence are recorded below. No version of this
bounded work closes E07 overall or changes release/operational gates.

| Evidence identity | Exact value |
|---|---|
| Required baseline commit / tree | `6dd0bc9d4ad5426065460270bf30c2cda6b2ca37` / `1796cf4eb505c15945f5c48821cc83329fcf5305` |
| Remote `origin/main` | `6dd0bc9d4ad5426065460270bf30c2cda6b2ca37` at task entry and before evidence recording; its tree is the required baseline tree |
| Task branch | `copilot/audit-e07-manifest-source-tree-state-fix` |
| Unchanged audit input | `Audit/QBIND_SECURITY_FINDINGS_REGISTER.md`, mode `100644`, blob `cd81efdbaf2bfb45e00dc3c60db3ea4f523adfa0` |
| Implementation commit / tree | `501db84d9671c98d55e8370e0574a823daeec466` / `cb6ad721e1c0cb38baf108b2778fb3073225959c`; direct parent is the required baseline |
| Test-coverage follow-up commit / tree | `3fb3c400c0108cb30ee33a536a443ebe759e46de` / `7dd1841a33b6ec1415f8995f60272b912c72ba34`; adds the whitespace/tab filename case and is a direct child of the implementation commit |
| Final focused-validation revision | `3fb3c400c0108cb30ee33a536a443ebe759e46de`; the matrix below passed at this exact revision |
| Raw parentage and ancestry check | Raw parents: `501db84` → `6dd0bc9`; `3fb3c40` → `501db84`. `git merge-base --is-ancestor` succeeded for baseline→validation revision and implementation→validation revision. |

The independent pre-implementation review provenance and bounded scope are
recorded above, before the implementation. It was conveyed by the user as an
independent ChatGPT review **PASSED / CLOSED** for the design, classification
and error rules, timing, caller compatibility, and future validation matrix;
it was not a review of implementation code. GitHub Copilot performed only the
bounded implementation assigned here; no operational or protocol-authority
role is inferred.

The implementation observes staged and worktree tracked state, excludes only
root `docs/**`, disables relevant external-diff/textconv and mode-hiding
settings, treats assume-unchanged/skip-worktree/sparse/unresolved states
conservatively, and recursively checks initialized tracked submodules. It
neutralizes inherited Git repository/index/config environment overrides and
disables optional Git index writes. It brackets two observations with HEAD,
index-content/stat, and recursive submodule identity checks. `unknown` is a
valid successful result with stderr diagnostics; the producer's shared capture
boundary rejects failed helper invocations and any output other than exactly
one terminated enum line.

Limitations remain deliberate: untracked/ignored paths, external build inputs,
toolchains, and environment outside Git's tracked-path view are excluded;
Git-normalized tracked state is not a raw-byte or hermetic-build claim.
Repeated observations are not atomic and cannot detect a transient change
that is restored between checks. Unsupported or incomplete observations
produce `unknown`. No Run 384/385 harness, node, Cargo, workflow, scanner,
signing, deployment, or activation was run.

| Validation category (including subcases) | Expected | Observed |
|---|---|---|
| Pinned baseline slice: clean control; dirty fixture; failed Git/repository observation | Historical snippet selects `clean` for all three | `clean` / `clean` / `clean` |
| Clean control; unstaged, staged, mixed staged+unstaged same/different paths | `clean`; all change cases `dirty` | `clean`; each changed case `dirty` |
| Tracked addition, deletion, rename | `dirty` each | `dirty` each |
| Executable-mode `chmod` with default `core.filemode`; file-to-symlink type change | `dirty` each when supported | Both reported `dirty`; the former did not test `core.filemode=false` |
| Root `docs/**` staged and unstaged changes; nested-submodule docs change | Root docs `clean`; nested docs `dirty` | `clean` / `clean` / `dirty` |
| Root and submodule untracked/ignored-only controls | `clean` | `clean` |
| `Audit/`, `.github/workflows/`, `scripts/`, `Cargo.lock` changes | `dirty` each | `dirty` each |
| Initialized clean submodule; tracked edit; ignore settings; staged gitlink update; unavailable and nested-unavailable submodule; nested tracked edit | `clean`; observed changes `dirty`; incomplete/unavailable `unknown` | `clean`; `dirty` cases; `unknown` unavailable cases |
| Space, tab, leading dash, newline, and non-ASCII tracked filenames | No parsing loss; `dirty` | Each assertion reported `dirty`, but later cases retained earlier staged unusual paths and were not isolated |
| External diff, textconv, submodule-ignore, and `core.filemode=false` hiding settings | Force correct result or `unknown` | Mode and tracked change remained `dirty` |
| Assume-unchanged, skip-worktree, sparse checkout, unresolved index, unborn/missing HEAD | `unknown` | `unknown` each |
| Missing Git, invalid repository, and Git diff exit 2 | `unknown` with stderr diagnostic | `unknown` each; invalid-repository diagnostic verified on stderr |
| Dirty plus failed observation; disagreement between repeated observations; controlled worktree, root-index, and submodule-index instability | `unknown` takes precedence | `unknown` each |
| Helper nonzero, empty, unterminated, invalid, extra-line, blank-extra-line, or multiple-enum output | Reject manifest generation | Rejected each; only successful one-line enum accepted |
| `clean`, `dirty`, and `unknown` through actual producer capture boundary, full schema validation, and bounded staged-copy validation | All accepted; diagnostics absent from JSON | All accepted; diagnostics absent from JSON |
| Baseline versus corrected classifier on clean, dirty, and error fixtures | Baseline always `clean`; corrected truth table | Baseline `clean`; corrected `clean` / `dirty` / `unknown` |
| Stable pre-serialization state; controlled post-build/pre-serialization mutation; detected instability | Reflect observation time; instability `unknown` | `clean`, then `dirty`; instability `unknown` |

**Coverage qualification for this historical run:** the executable-mode
assertion performed `chmod` while `core.filemode` remained at its default, so
it did not establish mode detection when that config was false. A later fixture
set `core.filemode=false` but changed file contents, not mode. The purported
rename assertion followed a staged deletion in the same fixture, so the
deletion alone could satisfy its `dirty` expectation. The newline, leading-dash,
and whitespace filename assertions accumulated staged paths in one fixture;
earlier staged names could satisfy later assertions. The historical outputs
above remain accurate observations, but those specific assertions did not
isolate the behavior they were labeled to cover. The current isolated controls
are recorded below.

**Commands and tools:** focused matrix:
`PATH=/tmp/qbind-e07-validator-venv/bin:$PATH bash scripts/devnet/tests/test_source_tree_state.sh`
(PASS at `3fb3c400c0108cb30ee33a536a443ebe759e46de`). The test uses disposable
temporary Git repositories and a synthetic manifest, with Git `2.51.1`, GNU
Bash `5.2.21`, Python `3.12.3`, and `jsonschema 4.26.0` in a temporary venv;
Draft 7 schema checking plus full instance validation passed for each enum.
`bash -n scripts/devnet/lib/source_tree_state.sh
scripts/devnet/tests/test_source_tree_state.sh` passed. Producer syntax was
checked from a temporary LF-normalized copy created with
`sed 's/\r$//'`; this does **not** prove execution of the committed CRLF
harness, whose existing invocation limitation remains out of scope.
`python3 -m json.tool` parsed the schema; comparison against the baseline
confirmed the schema diff changes only the `source_tree_state` description.
CRLF-aware `git -c core.whitespace=cr-at-eol diff --check` passed, and the
checkout classifier returned `clean` at the validation revision.

Source identities at the first focused-validation revision (historical):

| Path | Mode | Blob |
|---|---:|---|
| `scripts/devnet/lib/source_tree_state.sh` | `100644` | `f17f698febfb17bf9d83981d463661608809ebf0` |
| `scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh` | `100644` | `3027ebee8d43b7a1565c666c4008758835ad5628` |
| `scripts/devnet/tests/test_source_tree_state.sh` | `100644` | `59dfd7d5d845a70809e9e73886721cc12a82947b` |
| `docs/release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.schema.json` | `100644` | `aef539a567c31a6c8bc9713598888fb7fe47d7f0` |

The first implementation retained the schema structure, enum, identifiers,
schema/manifest versions, and historical example. The producer and maintained
README/BUILDINFO/VERIFY files retain CRLF. **Correction to the earlier EOL
statement:** the schema baseline and reviewed final schema both contain
exactly 205 CRLF line endings and no bare LF; its bytes were preserved by the
current correction. The remediation plan and new shell files use LF. No
protected audit register, blocker register, Run 385, workflow, Rust,
dependency, lockfile, or historical evidence path changed. The evidence
record was committed after validation and did not contain its resulting
commit/blob identity.

### Corrective implementation and verification-pending review — historical (2026-11-03)

**Historical status: IMPLEMENTED — VERIFICATION PENDING.** Finding identifiers:
**E07 / OBL-REL-1a / A48.1-C2**. This bounded correction does not close the
finding or E07 overall and does not change release or operational gates.
Independent verification was pending at this record's producing revision;
the completed independent review below narrowly supersedes that pending state.

| Evidence identity | Exact value |
|---|---|
| Pre-change commit / tree | `0c23009037b75817d9ff3b97f4176ce348b2e100` / `d1642178a1dd24f444d3d2e81d8790b645553b63` |
| Expected remote `main` | `6dd0bc9d4ad5426065460270bf30c2cda6b2ca37` |
| Corrective implementation and fixture commit / tree | `f9acef1d7f57a5bb8cb7e242450584e67d277c29` / `9a534f74f99a184f2c9e559f8f0fffadd3dcd3be`; direct parent is pre-change commit `0c23009` |
| Validation revision | `f9acef1d7f57a5bb8cb7e242450584e67d277c29`; corrective fixture and syntax checks below were run after this commit |
| Unchanged audit input | `Audit/QBIND_SECURITY_FINDINGS_REGISTER.md`, mode `100644`, blob `cd81efdbaf2bfb45e00dc3c60db3ea4f523adfa0` |
| Task branch | `copilot/audit-e07-manifest-source-tree-state-fix` |

The pre-implementation design-review provenance remains the user-conveyed
independent ChatGPT review recorded at the start of section 8: **PASSED /
CLOSED** for the bounded design, classification/error rules, observation
timing, caller compatibility, and proposed validation matrix. It was not a
review of code that had not yet been written. The independent
post-implementation review evidence for this correction was supplied through
the current task. Its bounded reproduction used Git `2.51.1`, a disposable
repository-local protocol-v2 fsmonitor hook that returned a token followed by
NUL and no paths, and an explicitly persisted fsmonitor-valid index entry.
Before editing the helper, this agent reproduced the reported condition
against the exact pre-change helper blob
`f17f698febfb17bf9d83981d463661608809ebf0`: clean control classified `clean`;
after a tracked edit, `git ls-files -v` remained `H`, `git ls-files -f` showed
`h`, and the classifier still returned `clean`. The index checksum remained
`f69c3e739ad85095128fbc3d29943de6861ad229d044c8ffec34f69fd8eee27a` across
the calls. The same false-clean was reproduced with the exact pre-change
helper for an initialized submodule with the equivalent persisted flag; its
index checksum also remained unchanged. The review evidence supplied through
the task reports that a scratch candidate with command-scoped
`core.fsmonitor=false` returned `dirty`.

The fix adds `-c core.fsmonitor=false` to the shared, isolated Git invocation.
Recursive submodule inspection uses that same invocation boundary, so
fsmonitor cannot suppress tracked-path comparison in either the root or
initialized submodules. The classifier does not change repository-local
configuration or indexes. The fixture suite installs a protocol-v2 monitor,
verifies that it was invoked, explicitly sets and confirms `H` with
`ls-files -v` and persisted `h` with `ls-files -f`, checks a clean control,
then changes a tracked file and requires `dirty`; root and submodule index
checksums must remain unchanged across classifier calls. The environment
injects Git command-line configuration including fsmonitor=false, so the
fixture script explicitly sets `GIT_CONFIG_COUNT=0` to ensure its local
monitor setup is genuinely exercised.

Fixture coverage was repaired rather than relabeled: addition, deletion,
rename, mode-only, and type-only cases now use fresh repositories with clean
controls. The mode fixture explicitly verifies `core.filemode=false`, starts
with a non-executable tracked file, verifies `chmod +x` changed the actual
filesystem executable bit, then requires the production helper to return
`dirty`. Newline/non-ASCII, leading-dash/non-ASCII, and whitespace/tab filename
cases each use a fresh clean repository and require `dirty` only after adding
that path. The earlier staged deletion cannot satisfy the rename assertion,
nor can an earlier unusual filename satisfy a later one. Mixed-change,
failure-precedence, instability, malformed-output, schema, and synthetic
staging coverage remains.

| Corrected validation case | Expected | Observed |
|---|---|---|
| Configured root fsmonitor clean control; actual hook invocation and persisted `H`/`h` flags established | `clean` | `clean`; hook invocation recorded; flags verified |
| Tracked edit after persisted root fsmonitor-valid entry | `dirty`; no classifier index mutation | `dirty`; root index checksum unchanged |
| Configured initialized-submodule monitor clean control; actual hook and persisted flags established | `clean` | `clean`; hook invocation recorded; submodule flags verified |
| Tracked submodule edit after persisted fsmonitor-valid entry | `dirty`; no classifier index mutation | `dirty`; submodule index checksum unchanged |
| Isolated mode-only change, `core.filemode=false`, filesystem executable-bit capability | clean control then `dirty` | `clean`, then `dirty`; config false and executable-bit change both asserted |
| Isolated staged rename, with no pending deletion or other changes | clean control then `dirty` | `clean`, then `dirty` |
| Isolated newline/non-ASCII, leading-dash/non-ASCII, and space/tab names | Each clean control then `dirty` | Each `clean`, then `dirty` |
| Retained classification, recursive-submodule, hidden-config, error precedence, unstable-observation, output-rejection, full Draft 7 schema and bounded staging cases | Existing contract outcomes | All passed in the full isolated suite |

**Commands and evidence:** `PATH=/tmp/qbind-e07-review-venv/bin:$PATH bash
scripts/devnet/tests/test_source_tree_state.sh` passed at corrective commit
`f9acef1d7f57a5bb8cb7e242450584e67d277c29`, using disposable temporary Git
repositories and a synthetic manifest. The test log at that revision includes
pass results for root and submodule fsmonitor controls, mode-only, rename,
and isolated unusual-filename cases. The full Draft 7 schema and bounded
staged-copy checks accept `clean`, `dirty`, and `unknown`. Synthetic staged
copy validation is not execution of Run 385 and does not establish hosted CI
behavior. No Run 384/385, Cargo, nodes, workflows, scanners, signing,
deployment, or activation was run.

`bash -n scripts/devnet/lib/source_tree_state.sh
scripts/devnet/tests/test_source_tree_state.sh` passed.
`python3 -m json.tool
docs/release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.schema.json`
parsed the schema. `git -c core.whitespace=cr-at-eol diff --check` passed.
Run 384 syntax was checked from a temporary LF-normalized copy using
`sed 's/\r$//'`; this is not execution of the committed CRLF producer. The
schema bytes were not changed by this correction. The baseline and reviewed
final schema each contain exactly **205 CRLF line endings, zero bare LF, and
zero bare CR**; the schema's existing bytes and line-ending form are
preserved.

Corrective source identities at the validation revision:

| Path | Mode | Blob |
|---|---:|---|
| `scripts/devnet/lib/source_tree_state.sh` | `100644` | `ebdad4a2301467e90aea7d4ebe5b9ac804023980` |
| `scripts/devnet/tests/test_source_tree_state.sh` | `100644` | `67b1e7af03a61e8cc853120f1d0420dc5e5bd7d6` |
| `docs/release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.schema.json` (unchanged) | `100644` | `aef539a567c31a6c8bc9713598888fb7fe47d7f0` |

Remaining limitations are explicit: the classification is Git-normalized
tracked-path state with only root `docs/**` excluded; untracked/ignored files,
external build inputs, toolchains, and external environment remain outside
scope. It is not a raw-byte, build-time cleanliness, hermetic-build, or
source-to-binary claim. Stability checks are non-atomic and cannot detect a
transient change-and-restore between observations. External
build/artifact/runtime/deployment evidence remains unresolved. Historical status
remained **IMPLEMENTED — VERIFICATION PENDING** until the corrected
implementation and final fixture/documentation correction receive a separate
independent post-change review; E07 overall and all release/operational gates
remain unchanged. The completed review below supersedes only that bounded
verification-pending state.

### Final fixture reproducibility correction — historical review pending (2026-11-03)

**Historical status: IMPLEMENTED — VERIFICATION PENDING.** This final bounded
correction is for **E07 / OBL-REL-1a / A48.1-C2** and does not change the
successful disposition of the preceding fsmonitor and isolated-fixture
corrections. The completed independent review below narrowly supersedes this
pending state, not the remaining E07 obligations.

| Evidence identity | Exact value |
|---|---|
| Pre-change commit / tree | `462ab806ecb2c49c37a5fa49275864d236e53d8f` / `8014ae31856aee626144b233e2c861b634b0157a` |
| Corrective test commit / tree | `88ffed09929b250294b2ef3ddd2bc881c2aae545` / `9a6a799c1b995166896784292a80224c344bbd80`; direct parent is pre-change commit `462ab80` |
| Exact validation revision | `88ffed09929b250294b2ef3ddd2bc881c2aae545` |
| Unchanged production helper | `scripts/devnet/lib/source_tree_state.sh`, mode `100644`, blob `ebdad4a2301467e90aea7d4ebe5b9ac804023980` |
| Corrected fixture | `scripts/devnet/tests/test_source_tree_state.sh`, mode `100644`, blob `7ba0aa1a1195579b20d50d37005a6be0a38e0aab`; deepest-clone identity setup is in the nested-submodule fixture |

The pre-implementation design-review reference remains the independent
ChatGPT review conveyed before coding and recorded above: it passed the
bounded design, classification/error rules, observation timing, caller
compatibility, and proposed validation matrix. The independent review
supplied through this task reports that the previous fsmonitor, isolated
fixture, and documentation corrections passed review; the old helper fails
the fsmonitor regression as expected. It also found that the earlier full
fixture run stopped with exit 128 / “Author identity unknown” when Git author
and committer identities were not inherited: recursive submodule
initialization creates a new deepest repository, and local identity
configuration on its source and outer clone is not inherited by that clone.
This is a fixture-environment reproducibility issue, not a reported failure
of the prior runs, whose complete suite had passed with command-scoped
synthetic identities.

The fixture now configures `user.name`, `user.email`, `core.hooksPath=/dev/null`,
and `commit.gpgsign=false` directly in `"$nested_root/outer/nested"` after
recursive initialization and before its commit. It uses the existing
`QBIND fixture` / `fixture@example.invalid` convention. This ensures its
commits use disposable synthetic identity and no ordinary hooks or signing;
the purpose-installed fsmonitor fixture hook remains intact. No user/global
configuration is changed, and the production helper, producer, schema,
workflow, audit register, blocker/release documents, and operational logic
are unchanged by this correction.

**Validation performed on the exact corrective test commit**
`88ffed09929b250294b2ef3ddd2bc881c2aae545`:

| Command / check | Result |
|---|---|
| `env -u GIT_AUTHOR_NAME -u GIT_AUTHOR_EMAIL -u GIT_COMMITTER_NAME -u GIT_COMMITTER_EMAIL -u EMAIL PATH=/tmp/qbind-e07-review-venv/bin:$PATH bash scripts/devnet/tests/test_source_tree_state.sh` | PASS; entire isolated fixture matrix completed and printed `All focused source-tree-state fixture cases passed.` |
| `bash -n scripts/devnet/lib/source_tree_state.sh` | PASS |
| `bash -n scripts/devnet/tests/test_source_tree_state.sh` | PASS |
| `git diff --check HEAD^ HEAD` | PASS |

The full test command explicitly unset all five inherited identity variables;
the suite established its own synthetic identities. Its output, observed
during validation of that exact commit, includes the nested initialized
submodule tracked-edit, nested docs inclusion, unavailable nested submodule,
all other Git-state classifications, output rejection, full Draft 7 schema
validation for `clean`, `dirty`, and `unknown`, and bounded staging
compatibility. The durable test-case evidence is the committed fixture at
`scripts/devnet/tests/test_source_tree_state.sh` blob
`7ba0aa1a1195579b20d50d37005a6be0a38e0aab` (nested-clone setup at lines
291–320); no separate test-log artifact was created. These staging checks
are synthetic and are not execution of Run 385.

Remaining limitations are unchanged: classification is Git-normalized
tracked-path state with only root `docs/**` excluded; it does not establish
build-time cleanliness, source-to-binary correspondence, or a raw-byte or
hermetic-build guarantee. Its stability observations are non-atomic and
cannot detect a transient change-and-restore. External build, artifact,
runtime, deployment, and release evidence remains unresolved. Run 384/385,
Cargo, nodes, workflows, scanners, signing, deployment, and activation were
not run. E07 overall and release/operational gates remain unchanged.

### Completed independent review and separate publication record (2026-11-03)

**PASSED/CLOSED — independent review of the bounded E07 correction.**
The user conveyed a completed independent **ChatGPT** review, separate from
the **GitHub Copilot** implementation author. It covered the tracked-source-state
classifier, producer integration, filesystem-monitor correction, isolated
regression fixtures, and final nested-fixture identity correction. This is
post-implementation review, distinct from the pre-implementation design
review recorded above.

| Producing-revision distinction | Exact committed identity |
|---|---|
| Original implementation | `501db84d9671c98d55e8370e0574a823daeec466` |
| Fsmonitor and fixture corrections | `f9acef1d7f57a5bb8cb7e242450584e67d277c29` |
| Final fixture identity correction | `88ffed09929b250294b2ef3ddd2bc881c2aae545` |
| Final reviewed and published revision / tree | `93422c10b9b31215f9027aa1de880179749d21ef` / `f4c4cde7bbfe6b1e44b745ba367bf1ecde3370f9` |
| Exact committed fixture used by the final independent run | `scripts/devnet/tests/test_source_tree_state.sh`, mode `100644`, blob `7ba0aa1a1195579b20d50d37005a6be0a38e0aab` |
| Unchanged production helper | `scripts/devnet/lib/source_tree_state.sh`, mode `100644`, blob `ebdad4a2301467e90aea7d4ebe5b9ac804023980` |

**Review results conveyed through this documentation task:** the complete
isolated suite passed with `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`,
`GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL`, and `EMAIL` removed from the
inherited environment. Separate helper and test Bash syntax checks passed.
The prior independent review also established that the new fsmonitor
regression fails against the old helper with “expected dirty, observed clean.”
These are attributed review results, not tests rerun by this documentation
task. No execution-log artifact was supplied to or is claimed by this task.
The committed fixture identity is evidence of the exact reviewed test source,
not a substitute execution log.

**Publication, recorded separately from review:** the user supplied terminal
evidence of a **non-force fast-forward** publication from
`6dd0bc9d4ad5426065460270bf30c2cda6b2ca37` to the reviewed revision
`93422c10b9b31215f9027aa1de880179749d21ef`, followed by matching local/remote
main, the exact reviewed tree, and a clean checkout. This describes the
user-supplied terminal evidence; this task did **not** directly inspect the
user's local checkout. GitHub main was independently checked at that reviewed
revision. At entry to this documentation task, the task checkout's HEAD and
local main, advertised remote main, and GitHub default branch main matched
the required reviewed revision; HEAD's tree matched the exact reviewed tree
and the task checkout was clean, including untracked files.

| Documentation recording boundary | Verified entry identity / permitted scope |
|---|---|
| Repository fetch and push destinations | `https://github.com/olivexo28/QBIND`; GitHub repository `olivexo28/QBIND`, default branch `main` |
| Required starting commit / tree | `93422c10b9b31215f9027aa1de880179749d21ef` / `f4c4cde7bbfe6b1e44b745ba367bf1ecde3370f9` |
| Task branch | `copilot/audit-e07-bounded-verification-record`; documentation commit descends directly from the required starting commit |
| Sole permitted changed path / starting mode / blob | `docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md` / `100644` / `ee660906bdeb7f304879d4ddd4344a2ac9555cc6` |
| Applicable instructions / checkout | No applicable `AGENTS.md` in repository or ancestor locations and no repository instruction files found; clean checkout before branch creation and editing |
| Validation boundary | Documentation integrity only: status/scope consistency, revision references, links, unchanged inventory identities, sole-path scope, mode/EOL/EOF, and whitespace; final commit/tree, manifest and remote equality are reported after commit, not self-referenced here |

**Narrow supersession and remaining limits:** only the section 8 bounded
reporting correction and isolated validation move from pending to
**IMPLEMENTED / INDEPENDENTLY VERIFIED / PUBLISHED**, with the review
**PASSED/CLOSED**. The dated historical implementation and pending-review
records remain; no finding/obligation identity or unrelated disposition is
changed. **E07 overall remains OPEN.** Build-time cleanliness,
source-to-binary correspondence, historical artifacts, full Run 384/385
execution, runtime/deployment evidence, and release eligibility are **not
established**. Classification still excludes root `docs/**`, untracked and
ignored files, external build inputs, toolchains and external environment;
it is Git-normalized tracked-only observation, not a raw-byte or hermetic-build
guarantee. Non-atomic observations cannot establish continuous cleanliness or
detect every transient change-and-restore. Activation remains **DISABLED**,
public DevNet **NO-GO**, and all other release/operational gates unchanged.
This task runs no project tests or operational work.

**Next action:** independent pre-implementation verification of the next
selected candidate under section 2; section 12 now records A21-F1's confirmed
source mechanism and proposed contract awaiting independent contract review.
This documentation task does not authorize implementation.

### A49.1 non-regression rules for every provenance task

The workflow does **not** unconditionally select stable:
`rustup show active-toolchain || rustup toolchain install stable --profile minimal`
does not select a compiler if an active one exists. No explicit target/profile
override proves only command configuration, not the effective environment.
Empty qbind-node default features do not mean an empty dependency feature
graph. Build-script non-emission does not clear an inherited compiler variable;
`option_env!` may observe it. Sanitization is neither provenance authentication
nor universal absence of sensitive content/panics.

Run 384 **does** compare metric build ID and metric commit to captured and
canonical values, binary SHA and ELF ID to captures, and **metric build ID !=
ELF build ID**. These are internal consistency checks, conditional on reaching
them, not independent audited-source-to-deployed-binary correspondence.
Keep four planes: repository source (complete to A49.1 scope), documented
tooling semantics (local retrieval qualification retained), effective build
environment/execution, artifact/provenance residuals. Attestation is delegated
and UNEXECUTED in this audit. Preserve all unexecuted-evidence qualifications;
no new A50 is authorized here.

## 9. Coverage reconciliation and remaining gaps

Coverage is identity reconciliation, not remediation completeness. The entire
committed input is the search/parsing scope, including superseded and archived
layers, not just the A22.1 index. Exact locators allow tracing the controlling
amendment back to preserved text without rewriting it.

| Reconciliation | Result / limit |
|---|---|
| Declared obligation identities | Section 5 has exactly 54 unique rows: CONS 13, TRN 5, AVL 7, SUP 2, PAR 2, DEP 3, TX 2, GOV 3, SIGN 2, KEY 2, GEN 1, STO 5, remaining OPS/REL/EXT/LIVE/PROV/REPRO 7 |
| Canonical findings | Section 4 covers 29 canonical identities; A2-F2 separately retained as rejected lead; no severity/count forced from obligation rows |
| Exact aliases | QBIND-A1-F001 = A21-F1; QBIND-A1-F005 = A7-F1. A23.1 explicitly supersedes A22.1's false denial of F005; no unresolved alias among these. QBIND-A1-F002 is distinct from A8-F1; F003/F004/F006 remain independent |
| Imported hypotheses / rejected leads | H01-H05 and the section-11 intake leads retained with reasons; H04-F1 is canonical, H04 alone is its resolved hypothesis |
| Evidence identities | E01-E27 mapped in section 6; later source corrections override historical table residual wording; no evidence category converted into a defect |
| Non-identity tokens | OBL-CONS-4 is superseded parent of 4a/4b and snapshot STO-3; unsuffixed split families (CONS-11, TX-1, STO-2, DEP-2, REL-1), wildcard labels and OBL-AVL/PAR/KEY/SIGN/GOV/TRN/OPS/STO family shorthand are not extra declared obligations |
| Conflicting dispositions | A1-F1 bypass/current gate, F005 alias, A22 versus A23 precedence, conditional A33-F1 witness, DEP retrieval versus BLOCKED, later CONS-6/7/8/9, governance-hook and epoch-regression, A42-A49 corrections are explicitly reconciled in sections 3-6. Earlier wording is historical, not deleted or a second current disposition |
| Unmapped canonical IDs / declared obligations | None in the enumerated identity sets; verify against the exact blob again for each refresh |
| Remaining applicability and work-card gaps | Most current-code applicability NOT YET CHECKED; priorities/assignees pending. Named unnumbered residuals mapped in section 6 are not an assertion that every narrative sentence is a separate task or that the whole audit/program is complete |
| Remaining evidence / policy gaps | Missing runtime/external evidence, unreviewed backend/invariant questions, unapproved profile/resource/authority/recovery policies and production integration remain. No new acceptance, execution or closure results |

## 10. Mandatory maintenance with every fix and audit refresh

Each future remediation task must update **its row and relevant evidence
documentation in the same task**. Record finding/input version and exact
applicability baseline; what changed and why; exact implementation commit;
binary/schema/manifest/log or other relevant artifact identities; tests
performed and results; review evidence; remaining limitations/dependencies
and the next action. Before coding, also record the independent pre-
implementation finding/correction verification, its supporting evidence,
actual reviewer (or UNASSIGNED) and bounded outcome. Mark unresolved,
superseded, already-addressed and not-applicable cases with their evidence;
do not imply review, approval or confirmation that did not occur. Where
needed, record separately authorized pre-change behavioral reproduction
before the change. After coding, record regression validation and independent
code review separately; binary/runtime evidence and release eligibility
remain separate. Use actual producing commits, not a later summary's HEAD
label. A commit cannot contain its own final hash: record that hash in the
subsequent evidence/delivery record, not a fabricated self-reference. Do not
silently expand a local/component PASS into process/runtime closure.

For each new Claude audit uploaded under `Audit/`:

1. Pin repository delivery commit/blob, internal version, byte length and
   checksum from committed bytes; distinguish raw and normalized identities.
   Preserve the audited source baseline separately from the delivery revision.
2. Reconcile new, corrected, withdrawn and superseded findings, all aliases,
   obligation identities, unnumbered candidates and evidence residuals.
   Preserve remediation history and exact producing evidence; a newer index
   does not erase older accepted scope or retroactively authenticate binaries.
3. Reopen completed checks only for a relevant change or identified evidence
   gap. State why, which scope and revision, and what remains accepted.
   Never silently switch audit inputs during an active task.
4. Before integration, reconcile concurrent main changes, applicability,
   conflicts and links; re-pin any changed evidence, without assuming ancestry
   through missing objects. Commit/push the scoped task branch only under
   that task's authorization.

## 11. Historical coordination delivery checks and current next action

The delivery scope and check results in the following paragraphs belong to
the original coordination task, not this 2026-11-03 sole-path documentation
record. The E07 task boundary is recorded in section 8 above; the A21-F1
documentation-only contract task boundary is recorded in section 12 below.

This task permits only this new plan and an appended navigation/scope note in
the blocker register. Validate committed input identities/normalization,
54-row coverage and canonical/alias reconciliation, supersession precedence,
relative links/line locators, status consistency/unchanged gates, two-path
scope, blocker exact baseline-byte prefix, modes/EOL/EOF and whitespace.
Keep both BR-04 documents and the audit register byte-for-byte unchanged.

No source/configuration edits, project tests/builds/scanners, node execution,
full Run 384/385 harness, provisioning, key generation, signing or activation.
Final delivery records starting/final commit/tree, raw parentage separately
from available-object ancestry, complete changed-path/mode/blob manifest,
documentation check outcomes, remaining inventory gaps, clean worktree,
remote task-tip equality and unchanged remote main. No PR, merge, main push,
amend or force-push.

Pre-commit documentation checks: raw and LF-normalized input identities
matched section 1; full-input finding-token reconciliation found 32 distinct
tokens (29 canonical + two aliases + rejected A2-F2), all represented; 54/54
declared obligation rows and 27/27 evidence rows have no missing/duplicate
identities. The complete input contains 93 first-level headings and 276
`SUPERSEDED` occurrences; these are structural checks, not findings or an
audit-completion metric. Relative Markdown targets resolve; audit line
locators are within the pinned 29,325 lines, with controlling sections
semantically checked. Both BR-04 documents and audit bytes are unchanged;
blocker exact prefix/CRLF/no-final-newline and mode checks passed.
CRLF-aware whitespace checks passed. Only the two authorized paths are
staged for delivery; final commit/tree/remote checks are reported separately
after commit, without a self-referential hash in this document.

**Current next action (supersedes the prior generic candidate-selection
instruction):** obtain independent post-implementation review of the
QBIND-A1-F002 correction and evidence in section 13 under section 2;
implementation **IMPLEMENTED — VERIFICATION PENDING**, finding **OPEN**.
The supplied pre-implementation source/design review is not an independent
review of the implemented code or execution evidence. Section 12
records the completed bounded A21-F1 source review and retained-evidence
inspection; earlier pending instructions are historical for that scope only.
This record neither chooses unresolved policy nor authorizes implementation,
creates a finding, or closes an overall finding or evidence obligation. Section 8's
E07 / OBL-REL-1a / A48.1-C2
bounded correction is implemented, independently verified and published;
it is no longer the next implementation. Unrelated BR decisions remain
mandatory for their dependent authority/recovery/operational work; activation
remains DISABLED and public DevNet NO-GO.

## 12. A21-F1 candidate task card, pre-implementation contract and bounded implementation record

**Current status:** A21-F1 remains **OPEN, CONFIRMED TO THE STATED SOURCE
MECHANISM**. The bounded correction and focused test implementation are
**IMPLEMENTED — BOUNDED REVIEW PASSED**, meaning independent source review
and offline inspection of authoritative retained evidence. Author-executed
focused regression results remain separately attributed to their producing
revisions; the reviewer did not rerun them. Runtime, deployment and release
evidence are **NOT EXECUTED**. The subsequent review disposition below
supersedes review-pending statements only within this completed bounded
scope, not the overall finding, broader obligations or historical run results.

The original pre-implementation contract, review boundary and proposed
acceptance matrix below are retained as history. Their FUTURE / NOT EXECUTED
labels describe the proposal state, not the execution record appended below.

Candidate: **A21-F1 / QBIND-A1-F001**, related **OBL-PAR-1 / E12**.
The supplied independent **ChatGPT** review of starting commit
`c6f02fc73f2f2dee5eae34de08db7b8cd5d4eea7` found no blocking documentation
issue and accepted the proposed structural preflight and cursor-preservation
approach to its stated scope. It checked the finding's current-source
mechanism, decoder/caller references, compatibility boundaries, documentation
scope and retained inventories. It did **not** execute decoder tests, approve
an unseen implementation, establish a deployment target matrix, or approve
an allocation-observer implementation. The target/testing addendum below
was then **AWAITING INDEPENDENT REVIEW**, with reviewer UNASSIGNED (historical
proposal status, superseded only to the later recorded review scope). Finding
confirmation is not an executed exploit or implementation approval.
Implementation/evidence assignees and comparative priority remain UNASSIGNED /
ASSESSMENT PENDING. This is a bounded next candidate, not a new finding,
severity, closed obligation, policy acceptance or implementation authorization.
**E13's separate queue/aggregate-memory and deployment-effect scope remains
open**; the local decoder contract does not absorb or discharge it.

**Supplied independent pre-implementation review evidence (as conveyed in
this task):** the supplied ChatGPT review of `c6f02fc73f2f2dee5eae34de08db7b8cd5d4eea7`
accepted the current-source finding and the bounded structural-preflight /
cursor-preservation contract. The supplied review of the corrected addendum at
`73c2ad6e249ff77f6fd10761d1a2f90c34d9a903` found no remaining blocking
documentation issue; its three corrections address post-exec dump
suppression, distinguishable inclusive-boundary guard calibration, and
parent-validated proof of child execution/completion. These reviews did not
execute tests, approve an unseen implementation, or establish operational
readiness. This is the review evidence supplied by the task, not a signed
review, independently retrieved transcript, PR, URL or timestamp.

**Supplied independent-review correction (2026-11-03):** review of
`2ecb4515ddeb8d6023407b68cc96ea56f5152eef` identified three documentation gaps:
piped-core suppression, distinguishable guard calibration, and proof of actual
child dispatch/completion. These are test-contract gaps, not observed runtime
failures or implementation defects. This correction starts at that commit,
tree `c7f2eafeba56d33aaf4fcffb44ada54f4b893e46`, plan mode/blob
`100644` / `ad19af98a13fc7178858b7dcded4d942e77a7651`, on the existing task
branch; advertised task tip matched and the checkout was clean. Protected
main remains `c6f02fc73f2f2dee5eae34de08db7b8cd5d4eea7`. Only section 12 is
edited; the revised addendum remains **AWAITING INDEPENDENT REVIEW**.

### Original addendum entry identities and verification boundary (2026-11-03)

| Identity | Verified value / qualification |
|---|---|
| Fetch/push destination | `origin`, `https://github.com/olivexo28/QBIND`, same repository for both; no remote/configuration changes |
| Task starting commit; HEAD/local main/origin/main/advertised remote main | `c6f02fc73f2f2dee5eae34de08db7b8cd5d4eea7` |
| Task starting tree | `b895405af455d8c700f9b51c3020c68cedef5a94` |
| Task branch | `copilot/audit-a21-target-allocation-test-contract`; absent locally/remotely at entry, created from the exact starting commit |
| Sole permitted changed path; starting mode/blob | `docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md`; `100644` / `da689b53bf9d18a9beb44f29d839ebd43b23df90` |
| Checkout/instructions | Clean including untracked files; no applicable `AGENTS.md` in the repository or checked ancestor locations |
| Starting raw parent and ancestry | Raw parent `e9cf8e4c68a7432f36bf896955618a37461c77ba`; starting commit is shallow and its parent object is unavailable. The start equals local/remote main; no ancestry beyond that identity is claimed |
| Committed audit input | `Audit/QBIND_SECURITY_FINDINGS_REGISTER.md`, `100644` / `cd81efdbaf2bfb45e00dc3c60db3ea4f523adfa0`, A49.1 / internal v1.138; section 1 raw/normalized identities preserved |
| Historical audited source baseline reference (not this task's implementation baseline) | `18d71a549d868ed33d352e9fc70a9d060f75e03b`; unavailable locally as qualified in section 1 |
| Current decoder | `crates/qbind-wire/src/consensus.rs`, `100755` / `9233aaaa21196a3e6e9a3af8303e076671f73718` |
| Current primitive readers | `crates/qbind-wire/src/io.rs`, `100755` / `c5df712d3bbf42e7301d63f14d6b6710eef1a1dc` |
| Current wire NetMessage | `crates/qbind-wire/src/net.rs`, `100755` / `983a40757bfc612fc27d168014390c8be79e0187` |
| Current binary handler, separately inspected | `crates/qbind-node/src/binary_consensus_loop.rs`, `100644` / `7a60d01841263c1425434fc48045629e0a85ab14` |
| Historical A49.1 R7.6 handler blob reference (not re-compared here) | `c4925ddf0977dff528dbb1815f757d67ea31e7b8` |
| Rust and build configuration inspected | `qbind-wire` is edition 2021; no repository `rust-version`, `rust-toolchain*`, `.cargo` target/toolchain pin, or workflow toolchain/target pin was found. Two workflow steps are commented “pinned, stable” but run `rustup show active-toolchain || rustup toolchain install stable --profile minimal`; that floating stable fallback/comment is not an exact version pin. Workspace `[profile.test]`: `debug=0`, `strip="debuginfo"`, `incremental=false` |
| Read-only local toolchain metadata | `rustup` selects floating `stable-x86_64-unknown-linux-gnu`, resolving here to rustc `1.99.1 (58cf8f9c3 2026-10-13)` and Cargo `1.99.1`; this is not a repository pin or the future execution compiler |
| Existing allocator configuration | No allocator in `qbind-wire` manifests/configuration; a test-local `#[global_allocator]` exists in the separate `qbind-node` integration-test executable `run_422_d7d14_safety_record_store_tests.rs`, delegating to `System`. Cargo gives the focused `qbind-wire` integration test its own executable, so its one test-local allocator does not conflict; no dependency, manifest or production instrumentation change is anticipated |

All current source locators below refer to the task starting commit, not an
implementation revision. The supplied review is attributed only to the
current-source and documentation scope stated above. No historical equality
with an unavailable audited-source object is asserted. Final documentation
commit/tree, remote equality and clean-worktree checks are reported after
publication, not self-referentially embedded here.

**Audit reconciliation:** R7.1, A:L14115-L14128, retains OPEN STATIC and the
finite-u32, handshake-only, platform-dependent qualifications. A21.3,
A:L21163-L21169, distinguishes production wiring from observed deployment,
withdraws literal-unbounded and reservation-at-most-input language, and
separates source inventory completion from E12/E13 evidence. A44,
A:L2668-L2822, answers the successfully populated proposal's post-decode
ownership/refusal boundary, not the reservation defect. Its carry-forward
correction at A:L2446-L2458 places the metric before decode and preserves the
production binding gate. Later authority refusal contains downstream effects,
not earlier reservation. No older headline overrides these qualifications.

### Current mechanism, callers and prerequisites

`BlockProposal::decode`, consensus.rs:727-797, reads fixed fields including
`tx_count` at :747, obtains/decodes optional QC at :756-764, then calls
`Vec::with_capacity(tx_count as usize)` at :766 **before** reading transaction
lengths/bodies (:767-771) or signature framing/body (:774-776).
`get_u16`, `get_u32`, `get_bytes` (io.rs:39-55,72-79) reject unavailable bytes
with `UnexpectedEof`; a failed primitive does not consume its own input.
Earlier successful prefixes/fields remain consumed. Thus necessary body
validation occurs too late to prevent the identified transaction-list
reservation, and complete earlier transactions may already have been copied
before a later malformed field fails.

| Current route | Boundary and caller behavior |
|---|---|
| Direct `BlockProposal::decode(&mut slice)` | No input-size wrapper in this API. Binary handler :6191-6200 calls it directly; storage.rs:850-858,2049-2054 also decodes stored bytes directly and maps codec errors. Neither storage call checks remaining bytes. This does not equate stored-input and remote-input threat models. |
| `NetMessage::decode` | net.rs:584-610 reads an outer discriminator and directly invokes BlockProposal at :604; no size precheck. async_peer_manager.rs:2167-2177,2426-2436 calls this API, logs errors and discards that message's slice; the first route has its own 10 MiB frame-length check at :2129, not the NetMessage wrapper's cap. No universal cap is inferred for this API. |
| `NetMessage::decode_from_slice` | net.rs:634-644 checks `MAX_NET_MESSAGE_BYTES` (1 MiB, :11) before decoding a local slice; does not reject trailing bytes or expose its cursor. peer.rs:90-93 uses this wrapper after secure receive, mapping errors. Its cap is not inherited by the direct/binary routes. |
| P2P `ConsensusNetMsg::Proposal(Vec<u8>)` | Not wire `NetMessage`. secure_channel.rs:415-419,650-669 receives/decrypts transport frames; framed_io.rs:110-129 checks the 16 MiB ciphertext bound before its frame-buffer allocation. p2p_tcp.rs:177-201 validates its inner frame and bincode-decodes `P2pMessage`; :1489-1519 applies any installed per-peer rate limiter and forwards the origin-carrying envelope. p2p_inbound.rs:370-386,506-518 demuxes Consensus and queues an `InboundConsensusEnvelope`. main.rs:6317 installs that handler; binary_consensus_loop.rs:3128-3147 receives and invokes the binary handler. Outer buffers/decoding and queue admission precede inner BlockProposal decode. Ciphertext capacity is not all available inner-proposal bytes. |

P2P reach requires the selected P2P startup/configuration, completed KEMTLS
handshake, decryptable admitted frame, valid outer Consensus/Proposal encoding,
and passage through installed transport/rate/queue admission. Preserve R7.1's
mode prerequisites: Optional/Disabled may admit certificate-less sessions;
Required needs an accepted valid non-revoked certificate at handshake, not
consensus binding-map membership merely to reach this earlier allocation.
This is not transport impersonation or inner signature forgery evidence.
LocalMesh/no-P2P is distinct; `io=None` supplies no inbound receiver
(binary_consensus_loop.rs:2926-2933). No observed public deployment is asserted.

Production builder installs `Some(binding_gate)` even with an empty authority
map (p2p_node_builder.rs:1583-1590,1685); do not generalize the test-only no-gate
branch. Binary metrics run before decode (:6179-6187), decode precedes
`bind_sender` (:6191-6200), and binding refusal returns (:6201-6212).
Consensus signature/suite checks and current-authorization admission remain
later (:6214-6437), with embedded-QC/freshness/engine gates later still.
Production selects Required (main.rs:8665-8682), supplies no Proposal/Vote
authority there and no current-auth snapshot at the loop call (:3140-3141).
Absent effective authority rejects after decode (:6423-6435); a present
authority without current authorization also remains fail-closed under
Required. None of these guards prevents the earlier reservation.

The count is finite `u32` (at most 4,294,967,295), not literally unbounded.
An outer wire-length cap alone does not prove consistency of that internal
count. A reservation request is not allocator capacity, heap footprint or
RSS; no guaranteed OOM, process failure, consensus disruption or network-wide
impact follows from this source observation.

### Structural witness on paper only

Offsets are zero-based in the **inner BlockProposal**, little-endian for
integer fields, derived from consensus.rs:689-706,727-756:

| Field | Byte range |
|---|---|
| msg_type `0x03`; version; chain_id | 0; 1; 2-5 |
| epoch; height; round | 6-13; 14-21; 22-29 |
| parent_block_id; payload_hash | 30-61; 62-93 |
| proposer_index; suite_id; tx_count | 94-95; 96-97; 98-101 |
| timestamp; payload_kind; next_epoch | 102-109; 110; 111-118 |
| batch_commitment; qc_len | 119-150; 151-154 |

Set `qc_len=0`; no QC bytes follow, so post-QC input starts at offset 155.
Set `tx_count=2`, provide `tx_len=1` at 155-158 and stop: total input **159
bytes**, with no transaction body at 159 and no later signature. After fixed
fields/QC the current decoder requests the two-entry transaction-list
reservation, consumes the first length prefix, then returns `UnexpectedEof`
with the cursor at 159. A symbolic larger finite count has the same structural
failure; it is **not executed here**. No enormous count is passed to the old
allocation path. A zero-transaction/no-QC proposal needs the two-byte
signature length at 155-156; with empty signature its complete length is 157.
General structural length is `155 + Q + sum(4 + tx_len_i) + 2 + S`;
valid encodings can require more decoded storage than encoded bytes.

### One proposed correction and compatibility contract

After the existing optional-QC step and **before** transaction-list reservation
or transaction-payload copying, take a borrowed copy of the remaining slice
as a scan cursor. Perform one allocation-free structural preflight:

1. Iterate the declared `u32` transaction count without count-derived storage.
   Read each four-byte length, convert via checked `usize::try_from`, and
   bounds-check/advance over that borrowed body using primitive slice readers.
   Do not copy bodies, collect lengths, reserve a vector or invoke transaction
   decoders during this scan.
2. Read the required two-byte signature length and bounds-check/advance over
   its declared body, including length zero. Only this successful **complete
   structural sequence**, not merely available count prefixes or tx bodies,
   permits materialization.
3. On scan success keep the real input at its original post-QC position,
   checked-convert count for reservation, and run the existing materialization
   order to produce identical fields/owned values and consume exactly the
   same bytes. On scan failure assign the real input to the scan's remaining
   slice and return the same structural error, preserving legacy consumption
   through the last successful primitive without allocating tx storage.

Use existing `WireError::UnexpectedEof` for unavailable prefixes/bodies.
Checked conversion/arithmetic failure uses existing `WireError::LengthOverflow`
(error.rs:1-12), not truncating casts, wraparound, panic-based encoder helpers
or a new public error type. Availability comparison must precede slice
splitting; prefer advancing borrowed slices so no accumulated offset or
`count * bytes` calculation is needed. Any introduced offset/length arithmetic
must be checked. Use checked `usize::try_from` for transaction count, every
transaction length and signature length in both preflight and materialization;
the two passes must use identical conversions and map failure to
`LengthOverflow`. Do not alter the existing `qc_len` conversion as part of this
correction. On ordinary 32-bit and 64-bit `usize` targets all wire `u32`/`u16`
values fit `usize`, so these checks do not change structural acceptance or EOF
errors.

For post-QC slice length `L`, each completed tx scan consumes at least four
bytes even when its body is empty. At most `floor(L/4)` complete entries and
one failing entry can be visited, plus the signature reads; a huge declared
count with insufficient input stops at the first unavailable primitive.
Borrowed body skipping does not inspect/copy every byte. Extra work is a
second pass over the present length prefixes and constant-time slice bounds
checks, bounded by input length, with constant auxiliary storage; successful
materialization still performs its existing payload copies. This is not a
new total CPU, concurrency, heap or RSS budget.

**Guarantee:** necessary transaction-sequence **and signature** availability
is established before the identified transaction-count reservation or any
transaction-payload copying. Outer-message buffers and optional-QC decoding
may already allocate (QC's own bitmap/signature copies/reservation remain at
consensus.rs:351-358). Valid large proposals still materialize; allocator
failure/capacity behavior for them is not remedied or measured here. Introduce
no arbitrary transaction-count/byte cap or broader resource policy.

Keep these four conditions distinct: (1) converting a wire `u32`/`u16` to
`usize`; (2) whether the declared transaction/signature bytes are available;
(3) whether the transaction-vector allocation layout is representable; and
(4) whether the allocator actually succeeds. Ordinary 32-bit and 64-bit
targets represent every wire integer in `usize`, but that says nothing about
input availability, the layout for `count` elements of `Vec<u8>`, or allocator
success. Layout depends on the selected target's `size_of`/alignment and
rounding rules; keep it symbolic and do not assume a universal 24-byte `Vec`.
`Vec`/`Layout` representability limits and valid-input allocation failure stay
outside this correction's guarantee. No new recoverable allocation-failure
policy, production count cap, platform restriction, public error type, or
unrelated QC conversion change is authorized. Narrower or otherwise
unreviewed targets remain unestablished.

Preserve wire layout, encoders, canonical bodies/signing preimages and public
interfaces. Preserve structurally valid zero-transaction, empty-transaction,
empty-signature and mixed empty/non-empty sequences; cryptographic acceptance
is a later concern. Preserve `qc_len=0 => None`, existing present-QC decode
errors and outer consumption of the full QC slice, including existing behavior
when the nested QC leaves bytes within that slice. Do not require QC exhaustion,
reinterpret an empty/invalid QC as absent, or tighten unrelated QC semantics.
Success leaves the same remaining/trailing bytes; neither direct decode nor
NetMessage's wrapper gains an exhaustion requirement.

Header/QC failure and cursor behavior stays unchanged. For post-QC EOF,
earlier successful fields/prefixes are consumed, a failed prefix/body remains
unconsumed, and `UnexpectedEof` is unchanged. In particular a complete tx
length followed by unavailable payload consumes the length, not that payload;
signature failure after complete txs consumes those txs' bytes without copying
them. Do not add an early count-versus-minimum-length shortcut that changes
the error cursor. Current binary caller logs/counts decode failure and does
not reuse `slice` (:6687-6695); storage maps errors; async peer routes discard
the failed slice; wrapper hides it. Those observations do **not** erase the
public mutable-slice contract or justify changing direct callers' semantics.

No consensus check, sender binding, authority activation, transaction
execution or optional-QC policy changes.

### Proposed target, allocator observer and containment contract

The proposed **initial test profile** is Linux
`x86_64-unknown-linux-gnu`, the Cargo `test` profile from the existing workspace
configuration, and the exact `rustc -Vv`, `cargo -V`, target and relevant build
environment recorded when a future run is separately authorized. Use
`cargo test --locked --target x86_64-unknown-linux-gnu -p qbind-wire --test block_proposal_preflight_tests -- --test-threads=1`.
This is one proposed test profile, not a support decision for QBIND, a
deployment target matrix, or a claim about the four operator machines. The
currently observed floating `stable` toolchain is not a version pin. Record
the future run's exact compiler; do not silently substitute a different target
or profile.

Use one focused integration-test executable at
`crates/qbind-wire/tests/block_proposal_preflight_tests.rs`, with one
test-local `#[global_allocator]` wrapper delegating `alloc`, `alloc_zeroed`,
`realloc` and `dealloc` to `std::alloc::System`. The observation window records
`alloc`, `alloc_zeroed` and `realloc` operation, requested size, alignment and
monotonic event order in a fixed 256-entry event buffer. For `realloc`, record
the new requested size and the old layout alignment. Deallocation is forwarded
with the original pointer and layout; it does not erase cumulative
requested-byte accounting.

Use const-initialized thread-local `Cell` flags for the explicitly armed owner
thread and hook reentrancy, plus fixed static atomic counters/event slots and
a single active-window compare/exchange. Initialize and clear all state and
touch the TLS cells before arming. Only the owner thread is observed; other
threads forward directly to `System`. The focused decoder path must not spawn
work. Before each window, construct the bounded fixture and initialize/reset
the observer; arm immediately before calling the real
`qbind_wire::consensus::BlockProposal::decode`, and disarm immediately on its
return. Snapshot only after disarming and before any assertion, formatting or
reporting. An RAII guard disarms on ordinary unwinding and resets owner and
active-window state between cases. A second arm, malformed state, reentrant
hook, checked-counter overflow, next event beyond the full buffer, or
request-budget breach fails closed by aborting the dedicated child before
delegating the offending request. Hook code performs no formatting,
general-purpose logging, dynamic growth, locking or potentially allocating
synchronization and never panics or unwinds; only the bounded binary guard
record below is permitted. Outside the owner window, all operations pass
through unchanged.

Check each request **before** calling `System`: maximum single request 64 KiB,
maximum cumulative requested bytes 256 KiB, and at most 256 recorded events.
These maxima are inclusive: exactly 65,536 bytes, 262,144 cumulative requested
bytes, and 256 events are allowed; the next request/event exceeding a maximum
is rejected. Use checked additions; do not delegate on overflow or a ceiling
breach. The future candidate children also cover request budgets defensively,
but an abort is a failed decoder case, never evidence of a successful refusal.
A valid control must complete normally with the expected result.

Set `qc_len=0` for allocation attribution so optional-QC allocations are
excluded. Source review of reservation-before-copy order must agree with the
ordered observations; do not identify an allocation site from size alone.
Malformed cases must return the expected `WireError` and exact cursor with no
transaction-list reservation or transaction-payload-copy events. Valid
non-empty controls must show the observer can detect both ordinary list
materialization and a payload copy. If compiler optimization/elimination or
merging prevents the same target/profile from observing those modest expected
baseline allocations, classify allocation evidence **INCONCLUSIVE** and stop;
do not weaken the assertion or infer absence from a zero counter. Source review
and calibrated real-decoder observations are jointly required.

Use only small fixtures (for example `tx_count` 2 and 8) against the old
decoder, including one complete non-empty transaction before later truncation.
Run those pre-change controls only against the actual pinned baseline decoder
in an isolated temporary checkout. Never pass an enormous count to the
uncontrolled baseline. For candidate-only large-count cases, including
`u32::MAX`, encode tiny fixed inputs without allocating from the hostile count
and invoke each case in a dedicated child process.

The proposed test-only ceilings are: encoded fixture 4 KiB; individual
allocation request 64 KiB; cumulative requested bytes per observation 256 KiB;
256 events; child wall deadline 10 seconds; child CPU soft/hard limit 5
seconds; child address-space soft/hard limit 512 MiB (`536870912` bytes); core
limit 0. Verify the small controls fit these ceilings on the selected target
before accepting their evidence. Launch only the test child through
`prlimit --cpu=5:5 --as=536870912:536870912 --core=0:0 -- <current_exe> --exact isolated_child_entry --nocapture --test-threads=1`,
with one child-case name in `QBIND_A21_CHILD_CASE`. This installs limits
before the test executable starts; do not apply process limits to Cargo
compilation. The child must read and verify its effective CPU, address-space
and core soft/hard limits from `/proc/self/limits` before running a case.
`RLIMIT_CORE=0` alone does **not** disable Linux piped core handlers. In the
actual child, after exec and before arming or any abort calibration, call
`prctl(PR_SET_DUMPABLE, 0)` and require success, then require
`prctl(PR_GET_DUMPABLE)` to return exactly 0. Retain and verify both core
limits are 0 as an additional restriction. Proposed test-local mechanism:
Linux x86_64 GNU libc `extern "C"` variadic `prctl(c_int, ...) -> c_int`,
`PR_SET_DUMPABLE=4`, `PR_GET_DUMPABLE=3`, with four trailing `c_ulong` arguments
of zero for each call (including unused arguments). Check the ABI/constants
against target headers at instrumentation review; no new crate is needed.
Handle `-1` with captured errno outside the observation window; any failed
setup, nonzero GET result, unsupported FFI/platform, or mismatched limit stops
the case without arming or calibration, with a failing child result.
No subsequent exec, credential/capability transition, or dumpability change is
permitted during the protected phase. The suppression guarantee begins only
after successful child setup; earlier executable startup is not covered.
Do not change host `core_pattern`, systemd settings or machine configuration.

The parent enforces a monotonic 10-second deadline from spawn by polling
`Child::try_wait`; on expiry it rechecks status, kills a still-running child,
then always calls `wait` to reap it. A child starts no grandchildren. Record
the actual exit code/signal, elapsed time, parent timeout/kill actions and reap
outcome separately from inferred cause. An unexplained SIGKILL or SIGABRT is
not proof of a CPU-limit or allocator-guard event. Only the matching result
protocol below plus normal successful exit can pass a decoder case.

**Per-invocation result protocol.** Before launch, the parent obtains a fresh
128-bit invocation ID from `/dev/urandom`, assigns a known numeric case ID,
and creates an empty regular evidence file with `create_new`, mode `0600`,
in a private run directory. Pass the invocation ID, exact case selector and
evidence path to the child; no destination reuse/truncation is allowed. The
child opens and verifies that fresh destination before arming, retains its
descriptor until teardown, requires initial length zero, rejects missing/unknown
selectors, and dispatches exactly one case from a closed match. The sole
`isolated_child_entry` writes:

1. `ENTRY`, only once, identifying the invocation and selected case.
2. `SETUP`, only after CPU/address-space/core soft/hard limits and dumpability
   are verified, recording their values.
3. Exactly one terminal `COMPLETE` after the intended decoder/control
   assertions succeed and the observer is disarmed, or `GUARD` from the actual
   rejecting branch before abort and before delegation to `System`.

Use three sequential fixed 128-byte binary records (384 bytes maximum), with
explicit byte encoding, magic/version, record kind/sequence, invocation ID,
case ID, and fixed numeric fields/zero padding. `COMPLETE` identifies the
assertion set and observed request/event totals. Ordinary serialization and
all assertions occur outside the armed window. Enforce a single monotonic
record-state transition; a duplicate/out-of-order write is an error, never an
overwrite. After disarming, normal cases also persist the fixed event snapshot
to a separately fresh/prepared regular file: a 32-byte invocation/case/count
header and at most 256 fixed 32-byte operation/size/alignment/order entries
(8,224 bytes maximum). Write and validate that bounded snapshot before
`COMPLETE`; no growing storage or reporting is introduced into hooks.
Guard records include the operation, requested size/alignment, one-based
offending event, prior and prospective event/byte counters, and distinct reason codes for single-request,
cumulative-byte, event-capacity, reentrancy, malformed-state, counter-overflow
and other guard failures. Counter-overflow uses an explicit invalid-prospective
flag, not fabricated counter values.

The hook writes a stack `[u8; 128]` with test-local GNU libc
`extern "C" pwrite(c_int, *const c_void, usize, i64) -> isize` at terminal
offset 256, using the preopened regular-file descriptor (no `O_APPEND`).
Use fixed byte-copy/encoding operations only: no formatting, allocation or
allocating synchronization. Handle positive partial writes by advancing the
buffer/offset; retry `EINTR` using test-local
`extern "C" __errno_location() -> *mut c_int`. This assumes GNU x86_64
`off_t=i64`, `ssize_t=isize`, and `EINTR=4`; verify these FFI assumptions
against the execution target's headers before authorization.
Bound the entire record write to eight calls. Zero progress, other errors,
or incomplete output after that bound cause non-unwinding abort without
delegating; no fallback logging. Never panic/unwind in this writer or a hook.
Such failures cannot produce accepted guard evidence. Normal records use the
same bounded writer outside the window. Any write failure fails the case.

The parent redirects stdout/stderr to the null device, not undrained pipes;
the bounded evidence file is read (at most 385 bytes to detect excess) only
after termination/reap; likewise read at most 8,225 bytes from a normal-case
event file and validate its identity/count/length. Thus output backpressure
cannot block deadline polling.
Require exactly `ENTRY, SETUP, COMPLETE` and exit 0 for normal cases, or
`ENTRY, SETUP, GUARD` and SIGABRT for the specific abort calibration. Validate
record length, magic/version, sequence, invocation/case identity, setup values,
expected assertion set or guard reason and exact counters; reject extra,
duplicate, stale, incomplete or mismatched records. A successful status,
generic “test result: ok”, typoed filter or zero executed child entries is
never sufficient. Missing setup/completion or a reason other than the expected
ceiling fails the overall run, even with SIGABRT.

Provide separately labelled guard-calibration child controls, not decoder
regressions. Invoke the allocator wrapper directly with bounded `alloc`
requests and alignment 1 for deterministic guard coverage; free each permitted
request correctly without resetting cumulative accounting. All fixture and
control bookkeeping is fixed/prepared outside the window, with no hidden
observed allocations. Pair each abort case with a normal-completion control:

| Calibration pair | Allowed control (`COMPLETE`, exit 0) | Next rejected request (`GUARD`, SIGABRT) |
|---|---|---|
| Single-request | One 65,536-byte request | One 65,537-byte request: event 1, prior bytes/events 0, prospective bytes 65,537/events 1, reason single-request |
| Cumulative bytes | 64 requests of 4 KiB, exactly 262,144 bytes | Request 65 of 4 KiB: prior bytes 262,144/events 64, prospective bytes 266,240/events 65, reason cumulative-byte |
| Event capacity | 256 one-byte requests, exactly filling the buffer | One-byte request 257: prior bytes/events 256, prospective bytes/events 257, reason event-capacity |

For allowed controls assert exact counters and no guard record. For rejected
requests require the matching reason/counters **and** SIGABRT; the rejecting
branch writes its complete `GUARD` record before abort and before `System`.
If the forbidden call returns, fail normally rather than synthesizing an abort.
Missing/partial/mismatched reason records, unintended guards, panic exits,
timeouts and resource failures all fail calibration. Direct wrapper calibration
does not replace allocation observations of the real `BlockProposal` decoder
and never counts as a decoder regression pass.

Linux references consulted on 2026-11-03:
[core(5)](https://man7.org/linux/man-pages/man5/core.5.html) documents the
piped-handler exception to `RLIMIT_CORE`;
[PR_SET_DUMPABLE](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html)
documents nondumpable value 0 and credential/exec-related resets; and
[PR_GET_DUMPABLE](https://man7.org/linux/man-pages/man2/PR_GET_DUMPABLE.2const.html)
documents reading the attribute and error handling. Direct fetches failed DNS;
man7 search-result excerpts were consulted, not a local execution or complete
page retrieval. These are documentation references, not verified future
kernel/libc behavior; target-header/FFI correspondence remains a future review
requirement.

Official Rust references consulted on 2026-11-03:
[GlobalAlloc](https://doc.rust-lang.org/std/alloc/trait.GlobalAlloc.html),
[Vec](https://doc.rust-lang.org/std/vec/struct.Vec.html), and
[Layout](https://doc.rust-lang.org/std/alloc/struct.Layout.html). The retrieved
current documentation says allocator hooks must not unwind and allocation
calls can be optimized away; `Vec` capacity is not an exact allocator request
and vectors do not allocate more than `isize::MAX` bytes; `Layout` constrains
rounded size to `isize::MAX`. Retrieval was through official-doc search
results (pages reported updated 2026-10-13; crawled 2026-10-30 to 2026-11-02);
direct page fetch was unavailable and the local rustdoc component was not
installed. This is current documentation, not the future execution toolchain.

### Pre-implementation execution sequence and acceptance matrix (historical)

The sequence and FUTURE / NOT EXECUTED labels in this matrix record the
proposal state before the implementation below. The appended execution record
supersedes only the cases it explicitly names; no unrun or broader assurance
is implied.

Keep review and evidence phases distinct:

1. Obtain independent review of this target/testing addendum.
2. Implement and validate the focused test instrumentation in the named new
   integration-test file only.
3. In an isolated temporary checkout, run modest pre-change controls against
   the actual pinned baseline decoder.
4. Implement only the independently reviewed decoder correction.
5. Run candidate regressions and guarded boundary cases.
6. Obtain independent implementation review.

The supplied review above is pre-implementation finding/contract input, not
approval of this target/testing addendum. The future remediation record must
name A21-F1 / QBIND-A1-F001, pre-change and implementation SHAs, what changed
and why, pre-implementation review reference, exact tests/results and retained
evidence/log locations, and limitations. After implementation, status remains
**IMPLEMENTED — VERIFICATION PENDING** until the independent implementation
review is recorded. Do not combine pre-change, instrumentation calibration,
candidate regression or review results into one pass.

| Case (every row FUTURE / NOT EXECUTED) | Expected result | Required evidence |
|---|---|---|
| Zero tx; empty tx; empty and non-empty signatures; mixed empty/non-empty txs | Valid decode preserves all values and wire behavior | Exact target/profile; decoded values; encoder bytes; event order for non-empty controls |
| QC absent/present, including nested-QC leftover behavior | Preserve `None`/present-QC errors and current outer consumption of the full QC slice; do not require nested exhaustion | Exact error/value and cursor; `qc_len=0` observer controls separated from QC cases |
| Missing/1-3-byte tx-length prefix; truncated tx body; tx-count/body mismatch | Existing `UnexpectedEof`; failed primitive remains unconsumed; complete prefix/length consumption preserved | Error variant and exact remaining-slice bytes; no tx-list or payload-copy events |
| Missing/one-byte signature prefix; truncated signature body, after zero or earlier complete txs | Existing `UnexpectedEof` and exact cursor; no tx materialization before full signature availability | Error variant, cursor and ordered events with `qc_len=0` |
| Truncation after earlier complete transactions | Earlier bytes stay consumed as before; no transaction list/payload is materialized | Separate later-prefix, body and signature failures; exact cursor and no tx allocation events |
| Successful decode with sentinel trailing bytes | Direct decoder preserves trailing bytes; no new exhaustion check | Decoded value and exact trailing slice |
| Direct decoder, `NetMessage::decode`, `decode_from_slice` size wrapper | Same delegation, cursor/error behavior and existing wrapper size check; wrapper still accepts trailing bytes | Exact APIs, inputs/results, cursor where exposed; no broadened cap |
| Encoder, decode/encode round trips and signing preimages | Byte-for-byte existing output and preimages | Existing focused consensus/epoch/payload/NetMessage/signing-preimage tests and exact output comparisons |
| Old decoder controls, `tx_count` 2 and 8, including earlier non-empty copy | Safely observe baseline list reservation and copy before later truncation | Isolated checkout at pinned pre-change SHA; ordered operation/size/alignment log; no large count |
| Malformed candidate observer cases; valid non-empty controls | Refusal has expected error/cursor and zero tx-list/payload events; valid controls reveal intended materialization | Real `BlockProposal::decode`, `qc_len=0`, source-order cross-check, fixed-buffer dump; zero expected baseline allocations means INCONCLUSIVE/STOP |
| Conversion/layout boundary on selected 32/64-bit target | Checked conversions agree in preflight/materialization; wire integers fit `usize`, while availability/layout/allocation remain separate | Compiler/target; conversion/error source review; symbolic target layout (no assumed Vec size); no claim for unreviewed targets |
| Exact-boundary wrapper calibration: 65,536 bytes; 64 x 4 KiB; 256 x 1 byte | Normal completion at the inclusive single-request, cumulative-byte and event maxima; next request/event is rejected | Matching `ENTRY, SETUP, COMPLETE`, exact event/byte totals and snapshot, exit 0; bookkeeping adds no observed allocations; no decoder-pass credit |
| Above-boundary wrapper calibration: 65,537 bytes; 65 x 4 KiB; 257 x 1 byte | Actual pre-delegation branch records the expected ceiling and offending request, then aborts | Matching `ENTRY, SETUP, GUARD`, operation/alignment and exact prior/prospective counters plus SIGABRT; incomplete/missing/unexpected reasons fail; no decoder-pass credit |
| Child setup and dump suppression; failed/unsupported setup controls | After exec, SET succeeds, GET returns 0, CPU/address-space/core soft/hard limits match; any failure stops before the case | Matching verified `SETUP`, including dumpability 0/core 0:0; no subsequent exec/credential transition; earlier startup explicitly outside guarantee |
| Child dispatch negative controls: absent/unknown selector, misspelled filter, zero child entries | Overall run fails even if process exits 0 or prints “test result: ok” | Separate future case IDs and parent rejection of missing/wrong `ENTRY, SETUP, COMPLETE`; no decoder evidence |
| Evidence negative controls: absent/duplicate completion, stale ID, mismatched case, incomplete/extra records or unexpected guard reason (including reentrancy/state/overflow) | Parent rejects every malformed sequence/outcome; SIGABRT alone cannot pass | Bounded synthetic protocol-negative fixtures and independently labelled outcomes, not decoder regressions |
| Candidate large counts, including `u32::MAX`, and child containment | Tiny-input candidate returns intended `UnexpectedEof` and exact cursor/assertions with matching completion and exit 0; any abort/timeout/resource failure is failure | Verified limits/dumpability, invocation/case sequence, command, actual exit code/signal, elapsed time, cursor/result, parent kill/reap and logs; unexplained signals do not establish cause |
| Small-control fit and unsupported-limit handling | Small controls fit all ceilings; unavailable/mismatched controls stop the run, with no silent fallback | Actual request/event maxima; verified setup records and `/proc/self/limits`; `prlimit` identity; explicit stop reason if unsupported |

Future evidence must identify source and implementation revisions, focused
test-file blob, exact compiler and Cargo versions, target/profile and relevant
environment, exact commands, installed/verified limits, per-child and overall
exit outcomes, verified dumpability, invocation/case identities and bounded
records, case results, parent timeout/kill/reap actions, and retained
log/evidence locations. Keep actual process observations distinct from inferred
causes. Do not fabricate measurements or evidence files.

### Original bounded implementation and verification record (historical run)

The results below remain results of the original producing revision. The
earlier supplied source review did not rerun these tests or inspect the original
raw artifact; the later offline inspection is recorded separately below.
The earlier review's four test/evidence findings and the corrective run are
recorded separately below; passing the original suite did not establish the
missing coverage or external artifact delivery.

| Item | Recorded value |
|---|---|
| Finding and related identities | **A21-F1 / QBIND-A1-F001**; **OBL-PAR-1 / E12**; E13 remains a separate queue/ownership/outbound-byte obligation |
| Starting commit/tree and advertised main | `73c2ad6e249ff77f6fd10761d1a2f90c34d9a903` / `cee733f72d38de1f67fa6965b61cd10cb0744ce6`; fetch/push `origin` both resolved to `https://github.com/olivexo28/QBIND`; local and advertised `main` matched the required commit at entry |
| Task branch and entry state | `copilot/audit-a21-proposal-decoder-preflight-fix`; branch absent locally/remotely before use; checkout clean including untracked files; no applicable `AGENTS.md` found |
| Raw parentage and available ancestry | The starting commit object has raw `parent 2ecb4515ddeb8d6023407b68cc96ea56f5152eef`; `.git/shallow` marks the starting commit and that parent object is unavailable. `git rev-list --parents -n 1` lists only the starting commit, so no ancestry through that shallow boundary is claimed. Implementation commit `9bc10bb0313505697ce7a4e46e4612edec7e9814` has raw parent `73c2ad6e249ff77f6fd10761d1a2f90c34d9a903`. |
| Protected input identities | Remediation plan `100644` / `dd5e16a1e8206b7ba187524644cc3d4c315fae76`; decoder `100755` / `9233aaaa21196a3e6e9a3af8303e076671f73718`; primitive readers `100755` / `c5df712d3bbf42e7301d63f14d6b6710eef1a1dc`; audit register `100644` / `cd81efdbaf2bfb45e00dc3c60db3ea4f523adfa0` |
| Supplied pre-implementation review | The task-supplied ChatGPT review of `c6f02fc73f2f2dee5eae34de08db7b8cd5d4eea7` accepted the current-source finding and bounded structural-preflight/cursor-preservation contract. The task-supplied review of the corrected addendum at `73c2ad6e249ff77f6fd10761d1a2f90c34d9a903` found no remaining blocking documentation issue; its three corrections concern post-exec dump suppression, distinguishable inclusive-boundary calibration, and parent-validated proof of child execution/completion. Neither review ran tests, approved an unseen implementation, or established operational readiness. No signed review, retrieved transcript, URL, PR or review timestamp is asserted. |
| Instrumentation identity / author | GitHub Copilot authored the test instrumentation and implementation. There was no separate instrumentation-only commit: the final test file was overlaid in the isolated baseline checkout with mode `100644`, blob `0474b043a8f623935669f98eb8d7b32f1830bfae`, then committed with the decoder in implementation/test commit `9bc10bb0313505697ce7a4e46e4612edec7e9814` (tree `ae81a2432e5112af782484eb809308a67dea994a`). |
| Baseline controls | In an isolated checkout at exact source commit `73c2ad6e249ff77f6fd10761d1a2f90c34d9a903`, overlaid only with that focused test file, `baseline_small_controls` passed for `tx_count=2` and `8`. Both returned `UnexpectedEof` with the expected cursor after one complete non-empty transaction and a missing next prefix. Ordered events were allocation requests `(alloc, 48, align 8)` then `(alloc, 3, align 1)` for count 2, and `(alloc, 192, align 8)` then `(alloc, 3, align 1)` for count 8. This matches the old decoder's list reservation followed by payload copy; no large count was run on the baseline. |
| Header/toolchain prerequisites | Linux `x86_64-unknown-linux-gnu`; `rustc 1.99.1 (58cf8f9c3 2026-10-13)`, Cargo `1.99.1 (5f94df478 2026-08-27)`; this floating stable compiler is recorded, not treated as a repository pin. Workspace test profile: `debug=0`, `strip="debuginfo"`, `incremental=false`; relevant environment included `CARGO_HOME=/usr/local/cargo`, with no target override or Rust flags set. `/usr/bin/prlimit`, util-linux `2.39.3`, SHA-256 `17064f67e650d6152a6902b013aab496b54c87587c8eea6f5023aafee6154069`. |
| FFI assumptions checked before controls | Target headers confirmed `PR_SET_DUMPABLE=4`, `PR_GET_DUMPABLE=3`, `EINTR=4`; GNU declarations for variadic `prctl`, `pwrite(int,const void *,size_t,off_t)` and `__errno_location`; target widths `off_t=8`, `ssize_t=8`, `size_t=8`, `c_ulong=8`. The retained `ffi-abi-check.c` passed `cc -std=c11 -Wall -Wextra -Werror -fsyntax-only`; compiler was Ubuntu GCC `13.3.0`, libc was glibc `2.39`. No fallback was used. |
| Instrumentation calibration and containment | Dedicated children verified `/proc/self/limits` as CPU `5:5`, address-space `536870912:536870912`, core `0:0`, then verified `PR_SET_DUMPABLE=0` and `PR_GET_DUMPABLE=0` before arming or calibration. All three inclusive controls completed normally: one 65,536-byte request; 64 requests × 4 KiB; 256 one-byte requests. Each paired next request/event wrote the corresponding pre-delegation `GUARD` record with exact counters and exited by `SIGABRT`. Parent validation checked record identity, case, exact event sequence, setup, terminal kind, counters and actual outcome. All child records were reaped; no wall timeout or parent kill occurred. Deliberately failed/unsupported setup and unavailable/mismatched-limit controls were **NOT EXECUTED** because the target prerequisites and requested limits were available; no fallback was used. This is instrumentation calibration, not decoder regression evidence. |
| Candidate decoder matrix | Required command `cargo test --locked --target x86_64-unknown-linux-gnu -p qbind-wire --test block_proposal_preflight_tests -- --test-threads=1` passed after commit `9bc10bb0313505697ce7a4e46e4612edec7e9814`: 3 passed, 0 failed, 2 intentionally ignored (the separately selected baseline parent and child entry). All 22 candidate child cases completed with `ENTRY, SETUP, COMPLETE`, exit code 0, and exact case/cursor assertions: `large_count`, `zero`, `empty_tx`, `nonempty_tx`, `mixed_tx`, `prefix_0`–`prefix_3`, `body_truncated`, `count_mismatch`, `signature_prefix_0`, `signature_prefix_1`, `signature_body`, `signature_after_tx`, `trailing`, `present_qc`, `bad_qc`, `bad_header`, `wrapped_net`, `large_tx_len`, and `max_signature_len`. These cover zero/empty/mixed/nonempty materialization; tx-prefix/body/signature truncation and count mismatch; `u32::MAX` count with a tiny fixture; maximum transaction and signature lengths with truncated bodies; successful trailing bytes; QC errors and nested-QC leftover; direct and wrapped `NetMessage` decode plus `decode_from_slice`. Malformed post-QC allocation-attribution cases use `qc_len=0` and observed no allocation events; valid controls observed reservation and payload/signature copies. Abort, timeout, signal-only or resource failure is not counted as success. |
| Conversion/layout boundary | On the selected 64-bit target, all `u32`/`u16` wire values tested fit `usize`; `u32::MAX` conversion succeeded. Observed `size_of::<Vec<u8>>()=24`, alignment 8, and `Layout::array::<Vec<u8>>(u32::MAX)` was representable at 103,079,215,080 bytes. No such vector was allocated. **32-bit execution and its conversion/layout behavior were NOT EXECUTED.** This reports one target only and does not conflate integer conversion, byte availability, layout representability or allocator success. |
| Protocol-negative results | Missing and unknown child selectors failed with exit 101 and no records. Two misspelled exact filters exited 0 with no child entries or evidence and were explicitly rejected as zero-match outcomes. Synthetic incomplete, extra, duplicate/out-of-order, stale-ID, wrong-case and wrong-guard-reason records were rejected. These are separately labelled protocol/dispatch controls, not decoder regressions. |
| Existing qbind-wire integration targets | Command `cargo test --locked --target x86_64-unknown-linux-gnu -p qbind-wire --test consensus_roundtrip_tests --test consensus_signing_preimage_tests --test epoch_roundtrip_tests --test payload_type_roundtrip_tests --test net_roundtrip_tests --test net_message_limits_tests -- --test-threads=1` passed at the same locked target/profile: `consensus_roundtrip_tests` 10; `consensus_signing_preimage_tests` 13; `epoch_roundtrip_tests` 7; `payload_type_roundtrip_tests` 6; `net_roundtrip_tests` 10; `net_message_limits_tests` 12 (58 passed total, 0 failed). |
| Formatting and scope | `rustfmt --edition 2021 --check` passed for the test file and for the decoder source with only a temporary final newline added for the formatter; the decoder's original no-final-newline convention is preserved in the committed file. `git diff --check` passed. The baseline and current canonical-finding, obligation, and evidence identity tables are unchanged (29 findings, 54 obligations, E01–E27). No dependencies, manifests, readers, encoders, node files, audit register, RUN 422 material or other paths changed. |
| Retained evidence | Raw Cargo logs, all 22 candidate child records and event snapshots, 6 calibration child records/snapshots, 2 baseline child records/snapshots, protocol-negative outcomes, baseline overlay identity, FFI check, and toolchain/profile capture are retained under `/root/.copilot/session-state/68e4e5078c814cc7ba7fec6c8c02e063/files/a21-f1-evidence/`. `AUTHORITATIVE-MANIFEST.txt` enumerates 102 retained files with sizes and SHA-256 values (14,480 bytes; SHA-256 `942f0041fd609d044b66db0be7581e4f096517b70abed2aa3069e00997658e3a`). The temporary baseline checkout is excluded and is not an evidence location. |
| Historical review and residual disposition | Independent post-implementation review was **PENDING** at this original run; superseded only for the subsequent bounded review scope below. A21-F1 remains **OPEN**; OBL-PAR-1, E12 and E13 remain open. Optional-QC allocations, valid-input allocation/layout failures, aggregate-memory and queue/outbound ownership, unreviewed targets, node/runtime/deployment and release evidence remain separate. No live exploit, node execution, deployment, activation or release validation was run. Activation remains **DISABLED**; public DevNet remains **NO-GO**. |

### Supplied review and corrective test/evidence record

**Historical supplied independent ChatGPT source review:** “At revision
8497c7b52bbb483675ebd9be480b694f40d160bd, source review found the three
requested code/test corrections resolved: shared real-validator negatives,
missing matrix cases, and bounded child cleanup. The production decoder was
unchanged. The reviewer did not rerun Rust tests or inspect the undelivered
raw archives. Independent raw-evidence verification remains pending.”
This is the supplied review statement, not a signed review, timestamp or
transcript URL. At that stage it did not claim archive inspection; the
subsequent inspection and disposition are recorded separately below.

GitHub Copilot authored the corrective tests and evidence. Entry checks
confirmed clean tracked/untracked state on the existing task branch
`copilot/audit-a21-proposal-decoder-preflight-fix`, commit
`b1feaf7bde9083eccaef10b6333c4bfe864c7cf0`, tree
`7f3f40a71512e53be6d570902eb074cd364fc9c2`. Both origin destinations identify
`https://github.com/olivexo28/QBIND`; the advertised task tip matched entry
HEAD and advertised main was
`73c2ad6e249ff77f6fd10761d1a2f90c34d9a903`. No applicable `AGENTS.md` was
found. Only the focused test and this plan change. The production implementation
remains `9bc10bb0313505697ce7a4e46e4612edec7e9814`; the decoder's mode
`100755` and blob `5a60b7a1aed1bfb93a78817224e11f89276e5868` are unchanged.

| Correction | Change, producing revision and actual result |
|---|---|
| Real acceptance logic | Removed the redundant parser. Both synthetic COMPLETE/GUARD positives and all synthetic negatives call `validate_child_evidence`, also used for actual children. `protocol_negative_controls` passed: two positive fixtures accepted, 89 explicitly labelled synthetic invalid outcomes rejected, and four actual dispatch-negative executions rejected by that same validator. Mutations cover absent/partial/extra/duplicate/out-of-order records, identities, setup and reserved fields, assertions, exit/signal/timeout/reap/status, guard operation/reason/prior/prospective counters, and missing/malformed/inconsistent event snapshots. Unexpected reentrancy/state/overflow/other reasons are **synthetic evidence controls**, not observed allocator failures. Missing/unknown selectors actually exited 101; two misspelled exact filters exited 0 with empty evidence, which the validator rejected. A negative-control pass is never a child/decoder pass. |
| Missing decoder/wrapper matrix | `candidate_acceptance_matrix` passed with 26 dedicated children, all matching COMPLETE and exit 0. Added `later_body` (complete non-empty tx then truncated later body), `later_signature_0` and `later_signature_1` (two complete non-empty txs then absent/one-byte signature prefix): `qc_len=0`, exact `UnexpectedEof`, exact remaining slices and zero observed allocations. Added `wrapped_trailing`: independently specified header/tx/signature values through both `NetMessage::decode` and `decode_from_slice`, exposed remaining slice `[0xFE, 0xED]`, equality of decoded results and preserved wrapper acceptance of trailing bytes. |
| Setup refusal | `setup_refusal_controls` passed for decoder and calibration selectors. A clearly labelled **test-only injected setup-boundary failure**, after real resource-limit/dumpability verification but before SETUP, observer arming or case dispatch, produced exactly ENTRY, no snapshot and exit 42. Exit 42 occurs only after assertions that the observer has never armed and case dispatch has never occurred; the normal validator rejects these incomplete outcomes. This was not a kernel failure and did not alter host settings or weaken normal limits. Actual unavailable-prerequisite/kernel-failure and mismatched-limit executions remain **NOT EXECUTED**; the deliberately failed setup alternative was executed. |
| Bounded cleanup | Ownership transfers to the real `wait_bounded` immediately after successful spawn. It uses nonblocking status/reap polling, records original and cleanup errors distinctly, makes at most two termination attempts, and allows at most 500 ms of bounded cleanup after timeout/management failure; no blocking `wait` or unbounded retry is used. Status/reaped are established only by an actual successful `try_wait` result. Exhausted cleanup honestly reports unestablished termination/reaping. Evidence-read/log errors retain the process outcome. `child_cleanup_controls` passed: normal completion; real 100-ms deadline/SIGKILL/reap; injected initial-poll, first-termination and cleanup-reap-poll errors followed by real cleanup. Final observed cleanup elapsed times were 107, 5, 112 and 107 ms; all four terminated children were actually reaped, and all were rejected as decoder evidence. Persistent OS failure/cleanup exhaustion was **NOT EXECUTED**; synthetic unreaped/missing-status outcomes were rejected. Injected errors are not claimed as real OS failures. |
| Evidence transfer | Earlier session-only delivery was blocked (historical status recorded below). This task authorizes and delivers both exact verified archives in `docs/security/evidence/a21-f1/`; their bytes and embedded manifests were rechecked after copying. Repository delivery makes the bytes retrievable but is not independent raw-evidence review. |

**Producing test revisions:** the substantial correction is commit
`9091d35b80ac30116b142adf4f8966450debba6e` (tree
`7b61ab780631c42621b2fc8a81f3d72628247b99`, test blob
`61193c46e738c5feef0cbbf0535f7a15f4025a53`). A subsequent conservative
deadline correction, commit
`2007126aec85dcd4b470e18d08bbed01ff67a942` (tree
`8cea98ad08ccfb739ecc3879f147e4ce9fd7a728`, final test mode `100644`, blob
`b064d22dd678593e4f7d3133d9c3679de51e5a80`), classifies a status first
observed at/after the parent deadline as timed out. Both states were committed
before their runs; both focused and modest baseline runs passed at each state.
The **authoritative corrective results** are the repeated runs using the
final `2007126...` test bytes. Earlier corrective/development runs remain
separately labelled and do not replace the original historical results.

At `2007126...`, the exact authoritative command was:

```text
cargo test --locked --target x86_64-unknown-linux-gnu -p qbind-wire --test block_proposal_preflight_tests -- --test-threads=1
```

Result: **5 passed, 0 failed, 2 intentionally ignored** (the separately
selected baseline parent and context-requiring child entry). The five executed
tests were `candidate_acceptance_matrix`, `child_cleanup_controls`,
`instrumentation_calibration`, `protocol_negative_controls` and
`setup_refusal_controls`. Normal decoder/calibration children retained CPU
5:5 s, address space 536,870,912:536,870,912 bytes, core 0:0, verified
post-exec dumpability 0, private fresh invocation/case files and the original
65,536-byte/request, 262,144-byte/cumulative, 256-event inclusive ceilings.
The normal wall limit remains 10 seconds, with a separate bounded 500-ms
cleanup allowance; only the benign cleanup controls use a shorter 100-ms
supervision deadline. Guard calibration observed the expected SIGABRT with
exact GUARD counters; decoder cases had no unexpected timeout, termination
or process-management error.

**Revised baseline controls:** a detached isolated worktree at exact
`73c2ad6e249ff77f6fd10761d1a2f90c34d9a903` / tree
`cee733f72d38de1f67fa6965b61cd10cb0744ce6`, decoder blob
`9233aaaa21196a3e6e9a3af8303e076671f73718`, was overlaid only with final test
blob `b064d22dd678593e4f7d3133d9c3679de51e5a80`. This augmented worktree was
not called pristine. The same Cargo target/profile ran only:

```text
cargo test --locked --target x86_64-unknown-linux-gnu -p qbind-wire --test block_proposal_preflight_tests -- --ignored --exact baseline_small_controls --test-threads=1
```

Result: **1 passed, 0 failed, 6 filtered out**. Counts 2 and 8 each completed
with expected EOF/cursor assertions and observed ordered allocations:
48 bytes/alignment 8 then 3 bytes/alignment 1, and 192 bytes/alignment 8 then
3 bytes/alignment 1, respectively. Their source-order correspondence remains
the baseline list reservation followed by the earlier complete transaction's
payload copy, not allocation-size-only attribution. No huge baseline count
or full candidate suite was run there. The isolated worktree/build output is
temporary, not a retained evidence location.

**Compiler/profile/FFI:** observed `rustc -Vv` was
`rustc 1.99.1 (58cf8f9c3 2026-10-13)`, commit
`58cf8f9c35b355199727627d07ae34a4e2846d67`, host
`x86_64-unknown-linux-gnu`, LLVM 23.1.1; Cargo
`1.99.1 (5f94df478 2026-08-27)`. This is an observed floating compiler, not a
pin. The unchanged unoptimized test profile has `debug=0`,
`strip="debuginfo"`, `incremental=false`; `CARGO_HOME=/usr/local/cargo`,
no Rust flags/target-dir override for the authoritative suite, and a separate
temporary target directory for baseline compilation. `/usr/bin/prlimit`
is util-linux 2.39.3, SHA-256
`17064f67e650d6152a6902b013aab496b54c87587c8eea6f5023aafee6154069`.
Before executing controls, the retained C prerequisite check was executed
anew with GCC 13.3.0/glibc 2.39: `prctl`, `pwrite`, errno declarations,
integer widths, `PR_SET_DUMPABLE=4`, `PR_GET_DUMPABLE=3`, `EINTR=4`
matched actual target headers. No compatibility fallback was used.

### Historical matrix reconciliation at the corrective producing revision

All rows below refer to the final `2007126...` focused run unless expressly
marked historical or not executed. This table supersedes only execution and
coverage dispositions, not the reviewed correction contract.

| Historical acceptance row | Concrete tests/cases and disposition |
|---|---|
| Zero tx, empty tx/signature, mixed/non-empty values | `candidate_acceptance_matrix`: `zero`, `empty_tx`, `nonempty_tx`, `mixed_tx`; passed |
| QC absent/present/errors/nested leftover | `present_qc`, `bad_qc`, qc-absent fixtures; passed; existing nested leftover acceptance preserved |
| Tx prefix/body/count mismatch | `prefix_0`–`prefix_3`, `body_truncated`, `count_mismatch`; passed, exact error/cursor and zero allocation |
| Missing/one-byte signature prefix/body after zero/earlier txs | `signature_prefix_0`, `signature_prefix_1`, `signature_body`, `signature_after_tx`, `later_signature_0`, `later_signature_1`; passed |
| Truncation after earlier complete tx | `count_mismatch`, `later_body`, `later_signature_0`, `later_signature_1`, `signature_after_tx`; passed |
| Successful sentinel trailing bytes | `trailing` direct, `wrapped_trailing` through both wrapper entrypoints; passed |
| Direct/NetMessage/slice wrapper delegation and size boundary | Direct cases, `wrapped_net`, `wrapped_trailing`; passed. Existing size-cap results remain historical at `9bc10bb...`; unchanged targets were not rerun |
| Encoder/roundtrips/signing preimages | Original six integration targets: 58 passed at `9bc10bb...`; source and these targets unchanged, **NOT RERUN** in corrective task |
| Actual old decoder counts 2/8, earlier copy | Separate ignored `baseline_small_controls` on exact baseline plus revised overlay; passed |
| Malformed zero-allocation vs observable valid materialization | Malformed qc-absent candidate cases, `empty_tx`, `nonempty_tx`, `mixed_tx`, `wrapped_trailing`; passed |
| Selected-target conversion/layout | `target_layout_boundaries` within candidate test; passed, no enormous allocation; 32-bit/other-target execution **NOT EXECUTED** |
| Inclusive calibration boundaries | `instrumentation_calibration`: `single_allowed`, `bytes_allowed`, `events_allowed`; passed with exact snapshots and exit 0 |
| Above-boundary calibration | `single_rejected`, `bytes_rejected`, `events_rejected`; expected GUARD plus SIGABRT validated; control passed, not decoder credit |
| Verified setup/dump suppression and failed setup | Normal dedicated children plus `setup_refusal_controls`; passed. Failure injection is synthetic; actual unavailable/kernel-failure/mismatched-limit cases **NOT EXECUTED** |
| Missing/unknown selector and zero-match dispatch | Four actual executions in `protocol_negative_controls`; shared validator rejected all, including two successful zero-match processes |
| Malformed evidence and unexpected guard reasons | Same real validator tested by two synthetic positives and 89 invalid synthetic mutations; all expected decisions obtained; not observed allocator failures |
| Candidate large count/tiny fixture containment | `large_count`, `large_tx_len`, `max_signature_len`; passed normally with exact EOF/cursor, verified setup and COMPLETE |
| Small-control fit and unsupported-limit handling | Normal small controls fit all ceilings; injected setup refusal tested. Real unsupported/mismatched prerequisites **NOT EXECUTED**; no fallback or broader platform claim |

**Corrective evidence location:** retained in the session under
`/root/.copilot/session-state/68e4e5078c814cc7ba7fec6c8c02e063/files/a21-f1-correction-evidence/`.
Final runs are `authoritative/` and `baseline/`; `authoritative-9091d35/`
and `baseline-9091d35/` retain the preceding committed run.
`development/` is explicitly non-authoritative (including an initial
compile-time correction, not a decoder regression). The directory also
retains Cargo logs, exact baseline overlay identities, toolchain/profile/FFI
records, decoded raw-record summaries and validation checks. Locally prepared
original/corrective archives and manifests are identified in the delivery
report; no external artifact reference had yet been established and a private
session path did not satisfy evidence delivery at that time.

**Historical transfer preparation (prior to this task):** the local directory was
`/root/.copilot/session-state/68e4e5078c814cc7ba7fec6c8c02e063/files/a21-f1-review-artifacts/`.
Both archives were reopened and every member compared byte-for-byte with
its selected retained source file. They were then **local-only**, not attached
or repository-delivered.

| Prepared file | Bytes | SHA-256 |
|---|---|---|
| `a21-f1-original-evidence.tar.gz` (102 original files plus unchanged original manifest) | 17,251 | `5b1356c1d731caf1cbe3d2a05faa23c433de275591f770d6e736098b1293fa76` |
| `a21-f1-corrective-evidence.tar.gz` (299 corrective/provenance/development files plus corrective manifest) | 73,138 | `437d11defd1a8017f9b04f2da58b62e3f1d5b563fbc37f4dd52282384153d1cd` |
| Corrective `MANIFEST.txt` (relative paths, sizes, SHA-256) | 42,422 | `42d05cf978609726db91485e8df8787769e118a454fc72263e166d9503f102b3` |

Focused formatting, relative-documentation-link, whitespace, two-path scope,
identity-table/alias reconciliation and mode/LF/EOF checks passed. The entire
accepted E07 section is byte-for-byte unchanged. No additional integration
targets were necessary: the decoder and the six previously tested targets
are unchanged. Final commit/tree, task-tip equality and remote-main checks
are reported after the subsequent evidence commit; no self-referential hash
is invented here.

**Historical repository evidence delivery:** the exact verified original and
corrective archives, both mode `100644`, and their guide are now available in
[`docs/security/evidence/a21-f1/README.md`](evidence/a21-f1/README.md).
The README records archive sizes/hashes, embedded manifest names/hashes,
producing revisions and review limits. Its supplied-review quotation says
independent raw-evidence verification remains pending; repository delivery
does not imply the reviewer inspected these archives. The prior
session-only transfer block above is retained strictly as historical status.

**Historical delivery-time status (superseded only for the bounded review
below):** independent **post-correction review remained PENDING**. A21-F1 remains
**OPEN**; implementation **IMPLEMENTED — VERIFICATION PENDING**;
OBL-PAR-1/E12/E13 remain open; activation **DISABLED**; public DevNet
**NO-GO**. Production optional-QC/outer allocations, valid-input
allocation/layout failures, aggregate/queue/outbound ownership, unreviewed
targets and runtime/release evidence remain separate residuals. E07's
accepted bounded result and unrelated inventories/gates are unchanged. No
node execution, deployment, activation or integration approval is implied.

### Subsequent independent bounded review disposition

**Attribution and method:** independent ChatGPT review supplied through this
documentation task. The bounded production preflight received source review.
Subsequent source review at
`8497c7b52bbb483675ebd9be480b694f40d160bd` found the three requested
code/test corrections resolved: negative controls exercise the actual
child-result validator; missing later-body/signature-prefix, wrapped
trailing-byte and setup-refusal cases are covered; process-management errors
enter bounded cleanup with explicit outcomes.

Independent offline inspection at delivery revision
`2e93ba7c202898f275703c94df8ed9677aa111e6` then retrieved both committed
archives and verified exact archive sizes, SHA-256 hashes and Git blob
identities, safe regular-file membership and complete embedded-manifest
coverage. All 102 original and 299 corrective manifest-listed files were
checked (401 entries total), plus the two manifest identities. Archive and
manifest sizes/hashes recorded above and in the committed
[evidence README](evidence/a21-f1/README.md) are retained unchanged.

| Committed evidence | Git blob identity |
|---|---|
| [Original archive](evidence/a21-f1/a21-f1-original-evidence.tar.gz) | `4ebfdb694599e32bd0e027e86ec3f11f1f083ad1` |
| [Corrective archive](evidence/a21-f1/a21-f1-corrective-evidence.tar.gz) | `3489829f4734e57fe4d01f0ede73ce78520a543a` |

The archived final test source matches Git blob
`b064d22dd678593e4f7d3133d9c3679de51e5a80`. Authoritative binary records,
event snapshots and parent logs agree on invocation/case identities, record
sequences, setup limits/dumpability, assertion sets, request counters and
process outcomes. The final corrective evidence supports 26 candidate
children, six calibration children, two setup refusals, five cleanup controls
and revised modest baseline controls. Retained logs report two shared-validator
positive fixtures, 89 synthetic rejections, four actual dispatch-negative
outcomes, and the focused suite result of five passed/two intentionally
ignored. Original retained integration logs report 58 passes across the six
unchanged targets. These are inspection conclusions about retained
author-executed results, not new executions.

**Historical evidence qualification:** the original archive's
`original/instrumentation-final/instrumentation/*/records.bin` contains three
GUARD records whose bytes 88–95 are zero rather than the offending-event
values required by the final format: 1, 65 and 257. Those earlier records were
excluded from acceptance under the final format. The original
`postcommit/instrumentation/` and corrective `authoritative/instrumentation/`
records contain the required values and passed independent inspection.
This historical record-format discrepancy is distinct from the accepted
later evidence. The historical archive is not altered, removed or regenerated,
and its previously reported test pass is not recast as a newly executed failure.
Earlier development evidence was not substituted for the authoritative run.

| Revision role | Producing / inspected revision |
|---|---|
| Original implementation/test revision | `9bc10bb0313505697ce7a4e46e4612edec7e9814` |
| Authoritative corrective test revision | `2007126aec85dcd4b470e18d08bbed01ff67a942` |
| Corrective source-review revision | `8497c7b52bbb483675ebd9be480b694f40d160bd` |
| Evidence delivery, independently inspected revision and published implementation tip | `2e93ba7c202898f275703c94df8ed9677aa111e6` |

The production decoder remains blob
`5a60b7a1aed1bfb93a78817224e11f89276e5868`; the focused test remains blob
`b064d22dd678593e4f7d3133d9c3679de51e5a80`.

**Conclusion:** “PASSED/CLOSED — bounded A21-F1 structural-preflight
implementation review and inspection of its authoritative retained evidence.
No remaining blocking issue was found within that scope.”

The reviewer performed source review and offline inspection of retained
evidence, did not rerun Rust tests, independently reproduce execution,
authenticate a release binary or establish deployment readiness. No signature,
transcript URL, precise review timestamp or additional approval is asserted.
The unchanged archive/README review-pending statements describe delivery-time
status; this plan record is the subsequent bounded review disposition.
**IMPLEMENTED — BOUNDED REVIEW PASSED** closes only that review scope, not
A21-F1 / QBIND-A1-F001 overall or broader evidence obligations.

### Separate publication evidence

Supplied user-terminal evidence reports a non-force publication from
`73c2ad6e249ff77f6fd10761d1a2f90c34d9a903` to
`2e93ba7c202898f275703c94df8ed9677aa111e6`, tree
`7263b229ed2aa8e283860337c5a1a77bdd77492b`. That terminal output reports
matching local/remote main and a clean user checkout. The user's local-checkout
observation is attributed solely to the supplied output; this task did not
inspect the user's machine. A subsequent GitHub read confirmed remote main at
that commit, also matching this documentation task's entry observation.
Publication is separate from source review, test execution and evidence
inspection. This report does not prove ancestry across an unavailable shallow
boundary: this task's starting commit has raw parent
`8497c7b52bbb483675ebd9be480b694f40d160bd`, but that parent object is
unavailable in this shallow checkout. No ancestry from the publication's
reported starting revision is inferred from that raw parent field.

### Scope and evidence status

Delivered bounded source scope: decoder in
`crates/qbind-wire/src/consensus.rs` and the single focused test file
`crates/qbind-wire/tests/block_proposal_preflight_tests.rs`. Any need to change
a manifest, dependency, workflow, production allocator instrumentation,
shared reader, or other path requires a precise scope proposal and fresh
authorization; none is silently approved here.

The official references' important caveats are applied jointly with actual
decoder source review and calibrated observations. Requests are not Vec
capacity or RSS. The test ceilings are containment limits only, not protocol
limits or measured production budgets. Existing valid-input layout/allocation
failures, broader E12 dependency/aggregate-memory questions and all E13
queue/ownership/outbound-byte questions remain open.

**Status remains:** A21-F1 **OPEN, CONFIRMED TO THE STATED SOURCE MECHANISM**;
implementation **IMPLEMENTED — BOUNDED REVIEW PASSED** for independent source
review and authoritative retained-evidence inspection only; author-executed
focused decoder regressions passed on their recorded producing revisions;
runtime/deployment/release evidence
**NOT EXECUTED**; activation **DISABLED**; public DevNet **NO-GO**. This bounded
task does not close OBL-PAR-1, E12 or E13 and does not change unrelated BR
decisions or operational gates. Optional-QC/outer allocations, valid-input
allocation/layout failures, aggregate-memory/queue ownership, unreviewed
targets and runtime/release evidence remain unresolved to their existing scopes.
This documentation-only task runs no builds, project tests, scanners, nodes,
provisioning, signing, deployment or activation and changes no evidence files.
## 13. QBIND-A1-F002 contract and bounded implementation: offline duplicate approvals

**Finding: OPEN. Implementation: IMPLEMENTED — VERIFICATION PENDING.
Implementation/test commit: `149edffd8f7fd97c821d6df9a5a546eca4992b79`.
Independent post-implementation review: PENDING.** The original proposal
and its historical documentation-only evidence remain below; the separately
authorized implementation and execution record follows at the end of this
section. The supplied pre-implementation review is recorded with its limits,
not as signed approval or post-implementation verification. Comparative
priority: **ASSESSMENT PENDING**. All BR decisions and release/operational gates remain
unchanged; activation **DISABLED**; public DevNet **NO-GO**; RS1 and C4/C5
remain OPEN. Sections 8 and 12, including accepted E07/A21 bounded reviews,
historical GUARD qualification, evidence identities and publication records,
are preserved byte-for-byte.

### Entry identities and historical/current-source separation

| Identity | Verified documentation-task entry |
|---|---|
| Repository; fetch/push destination | `olivexo28/QBIND`; `origin`, `https://github.com/olivexo28/QBIND` for both; no destination changes |
| Starting commit; local main; fetched/advertised remote main | `427c72a6bd2712b58c2777df2b26145463ef1257` |
| Starting tree | `a5c056a4c01bbfec7623158d60c7a9c409fd5ec8` |
| Task branch | `copilot/audit-f002-distinct-approval-preimplementation-contract`; absent locally/remotely at entry, created from the exact start |
| Sole permitted changed path; starting mode/blob | `docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md`; `100644` / `0543c589212cd2597e9fe720a8c4d4942e71ab63` |
| Checkout/instructions | Clean including untracked files before editing; no applicable repository/ancestor `AGENTS.md` or repository instruction files found |
| Raw starting parent; available-object ancestry | Raw header names `2e93ba7c202898f275703c94df8ed9677aa111e6`; that object is unavailable at the shallow boundary. No ancestry through it is inferred. Only the available start and subsequent task descent can be proven |
| Pinned audit input, unchanged | `Audit/QBIND_SECURITY_FINDINGS_REGISTER.md`; `100644` / `cd81efdbaf2bfb45e00dc3c60db3ea4f523adfa0`; A49.1 / internal v1.138 |
| Historical audited source, not this task's source baseline | `18d71a549d868ed33d352e9fc70a9d060f75e03b`, tree `5b6c543435ac017dd8372c93f48be397899db14a`; section 1's unavailable-object qualification remains |

Audit locators retain section 1's exact input identity and line convention.
A:L9280 carries F002 as an offline STATIC counting finding. A:L16254
(preserved status snapshot) and A:L16363 (earlier current-baseline index)
record confirmation at their audit baseline, no runtime evidence and offline
CLI reachability; their word "current" is not this task's current-source
verification. A:L16506-L16513 keeps F002 distinct from native **A8-F1**.
A:L13684 also distinguishes **A23-F1** trust-bundle ratification. The
historical optional approval-set digest change at A:L29118-L29119 is superseded
by A:L28554-L28559's correction: preserve incremental signing and correct
counting, not the digest. Its additional public-key-distinctness suggestion
is not silently included in this member-ID proposal; key aliasing remains
separate below. A49.1 does not close F002. RUN 422 bootstrap-authority
decisions and native governance containment are not this finding.

**Supplied independent source review (ChatGPT, as supplied in this task):**

> At commit 427c72a6bd2712b58c2777df2b26145463ef1257, verify_envelope increments valid_count for every cryptographically valid approval without deduplicating member_id. With a structurally valid envelope and a validated 2-of-3 keyset, two copies of one genuine approval can therefore satisfy the current threshold. Council approvals are excluded from the signed digest; copying an approval does not change that digest. The CLI validates the keyset and envelope, then uses this verifier's result for its success verdict and exit status. This confirms the stated offline counting mechanism from source. No reproduction, deployed exploitation, signature forgery or native-consensus bypass was demonstrated.

This is attributed supplied source review, not an independently retrieved
transcript, signature, URL, precise review timestamp or approval of this
completed contract. The author rechecked the following baseline sources.
Source correspondence is not executed reproduction or independent contract
acceptance.

### Current source anchors and bounded caller/consumer inventory

All source paths/line numbers in this section refer to the exact starting
commit above. Each linked file is unchanged by this task.

| Current source (mode `100644`) | Pinned blob | Rechecked mechanism / locator |
|---|---|---|
| [verify.rs](../../crates/qbind-gov/src/verify.rs) | `98c114623dcc09a1a2d505bf352e1705d4ba57de` | `VerificationResult` fields/helpers :43-78; `verify_envelope` :95-124; single-signature checks :127-189; threshold wrapper :194-208; existing real-crypto/helper tests :317-512 |
| [council.rs](../../crates/qbind-gov/src/council.rs) | `45e87a93f97a4e75ccc1b220ead93daaac62e2cf` | Key validation :61-77; construction/parsing :108-133; thresholds/lookup/map :141-163; keyset validation :166-205; tests :208-316 |
| [envelope.rs](../../crates/qbind-gov/src/envelope.rs) | `707483ff9213fb74e4113b09973d47482adf7fcf` | Approval fields/hex decoding :116-144; JSON parsing :200-211; structural validation :224-256; raw count helpers :263-271; errors :274-306; existing tests :308-434 |
| [hash.rs](../../crates/qbind-gov/src/hash.rs) | `a68780a1353ce16275f5c7c470185ea3361adf7b` | Domain/digest :34-63; canonical fields exclude approvals :82-147; approval-exclusion test :219-238 |
| [CLI](../../crates/qbind-gov/src/bin/qbind_envelope.rs) | `df952c77d6cd003794ea0b07378a6d8780502437` | Exit constants :42-46; inspect :122-182; verify/validators/error path :185-257; binary check :260-283; text :286-353; JSON :356-393 |
| [lib.rs](../../crates/qbind-gov/src/lib.rs) | `f4e68132c05a68d77f5f24fbb91482193583b7aa` | Public modules/re-exports :63-77, including both verification entry points; ignored example :21-38 does not call structural validators |
| [qbind-gov manifest](../../crates/qbind-gov/Cargo.toml) | `3514efce58d5bd0cfb8111ad491e9cf0a21b2d10` | Package/binary :1-9; real crypto, hex/JSON dependencies and existing `tempfile` dev-dependency :11-23 |

**Search performed, bounded to tracked text at this baseline:** `git grep`
over `crates/`, `scripts/`, `.github/`, root `Cargo.toml` and `Cargo.lock`
for `qbind[-_]gov`, `qbind[-_]envelope`, `verify_envelope(_threshold)?`,
`VerificationResult`, `approval_count`, `has_threshold`; supplementary
`CouncilKeySet`, `CouncilSignature`, `UpgradeEnvelope`, `valid_members(`
and `invalid_signatures(` searches in crates/scripts/workflows. Documentation
search covered `docs/` (including `docs/devnet/`), root `README.md`, and tracked
`examples/`, `tests/`, `tools/` and manifests where present. A further
crate/verifier-name file-list-result search of tracked text outside `Audit/`,
`docs/` and `crates/qbind-gov/` found only root manifest/lockfile and the
release-build script. Unrelated consensus `VerificationResult` and rejected
signature counters are different types, not envelope consumers.

The shared verifier and threshold wrapper are **public library APIs**, not
CLI-private functions. The CLI :224 is the located non-test executable caller;
the wrapper delegates to the shared verifier at verify.rs:198. Unit tests call
the library; docstrings in verify.rs/lib.rs show library examples (ignored,
not executed).
The workspace includes qbind-gov at Cargo.toml:17; the package manifest
declares the standalone binary. [build-mainnet-release.sh](../../scripts/build-mainnet-release.sh):54-60,254-279
maps `qbind-envelope` to qbind-gov and builds/packages it separately from
qbind-node. Packaging does not demonstrate node invocation or deployment.
[qbind-node/Cargo.toml](../../crates/qbind-node/Cargo.toml):28-64 has no
qbind-gov dependency; inspection of the Cargo.lock workspace dependency
closure rooted at qbind-node also found none. No node-side envelope API call
was located in this bounded source search. This supports the stated offline
boundary, not a universal proof that no external consumer exists.

Protocol-report/alignment references and
[native-governance contract](../devnet/QBIND_RUN_422_NATIVE_GOVERNANCE_AUTHORITY_CONTRACT.md):55-57,184-186,
[RUN 422 evidence](../devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md):24329-24333
and [contradiction notes](../whitepaper/contradiction.md):4265-4268
are documentation, not executable integrations. Searches do not cover
untracked/ignored/generated files, archive contents, external repositories,
downstream API aliases or deployed binaries/configurations. No such absence
is evidence of harmlessness or of no possible external library consumer.

### Proposed shared-boundary refusal and compatibility contract

For a **validated keyset** and structurally valid envelope, an authorization
threshold must not be satisfied by repeatedly presenting one member's
genuine approval. At this boundary the bounded identity is the configured
**member ID**, not a claim about independent public keys or operators.

1. At entry to `verify_envelope`, before `envelope_digest`, key-map building
   or any cryptographic verification, scan the **entire**
   `council_approvals` list for repeated `member_id` values. Use existing exact
   Rust string equality, as in council.rs:152,160,191: no trimming, case
   folding or new identity normalization. Include nonadjacent repetitions.
2. Record the ID whose **second occurrence has the lowest input index**;
   finish the list scan, then return
   `EnvelopeError::VerificationFailed(format!("duplicate approval member_id: {}", member_id))`
   for that ID if any duplicate exists. The stable payload is
   `duplicate approval member_id: <exact ID>`; enum Display prepends
   `verification failed: `. Selection must not depend on set iteration or
   lexical sorting. For `[b,a,a,b]`, report `a`; reordering can change which
   ID is first repeated, but not refusal. All repeated IDs are refused, not
   merely the first adjacent pair.
3. Do not count only the first occurrence, discard redundant entries,
   short-circuit upon reaching threshold, or return any successful
   `VerificationResult` for a duplicate-bearing input. The refusal applies
   to identical or different signature/key/timestamp bytes; valid, invalid
   and unknown-member duplicates; and inputs with an otherwise sufficient
   distinct valid quorum. It takes precedence over digest/key-map/crypto
   errors inside this function, not over earlier CLI parsing/validation.
4. `verify_envelope_threshold` must propagate the identical refusal via its
   existing `?`, not convert it to `ThresholdNotMet`. With no duplicate IDs,
   retain the existing full verification path, ordered per-signature results
   and helper semantics: unknown/mismatched/malformed/invalid extras are
   marked invalid, and do **not** prevent success when enough other distinct
   valid approvals meet threshold. Below threshold the main API still
   returns a result with `is_valid()==false`; the wrapper returns
   `ThresholdNotMet`.
5. Preserve public signatures, result fields, serialized envelope/keyset/
   output formats, canonical signed digest and `QBIND-ENVELOPE-v1:` domain
   tag, ML-DSA-44 backend, configured thresholds and unrelated validation.
   Do not add blanket structural-validation calls, public-key deduplication
   or new policy checks as part of this bounded change.
6. Preserve the existing CLI error path :224-230: duplicate refusal prints
   `Error during verification: verification failed: duplicate approval member_id: <ID>`
   plus newline to **stderr**, returns **exit 1**, and reaches neither binary
   checking nor result rendering. For both default text and `--output json`,
   **stdout is empty** on this early error: no success verdict, no JSON
   result object, and no new JSON error schema. Earlier invalid keyset errors
   remain exit 2; invalid envelope structure remains exit 1. Nonduplicate
   result rendering and exit calculation :237-255 remain unchanged.

**Compatibility trade-off:** duplicate-bearing envelopes previously accepted
will be refused, including those with an otherwise sufficient distinct
quorum. Removing redundant approval entries leaves the current signed digest
unchanged because approvals are excluded; it does not supply missing distinct
authority. This task repairs no artifact and performs no signing. External
consumers expecting `Ok` on duplicate inputs must handle the existing error
variant. `inspect` remains descriptive and can report duplicate entries;
`approval_count` and `has_threshold` remain raw length helpers, **not**
cryptographic authorization substitutes.

### Adjacent gaps, dependencies and exclusions

| Boundary / current source | Disposition for this proposal |
|---|---|
| CLI vs direct public calls: CLI :213-221; verify.rs:95-124,194-208; parsing in envelope.rs:200-211 and council.rs:119-128 | CLI explicitly validates keyset then envelope. Library parsing and both verification APIs do not automatically invoke all structural validators. Tests establishing the confirmed quorum case must validate inputs first. Do not imply this proposal closes all direct-library admission gaps |
| Duplicate keyset IDs: council.rs:166-205 vs key_map :156-163 and find_key :151-153 | Keyset validation already rejects duplicate IDs and zero/excess thresholds; direct unvalidated calls can overwrite map entries (last entry), whereas find_key returns the first. Separate residual, not the attacker-supplied approval duplication. Preserve existing CLI rejection; do not broaden this change into keyset validation |
| Threshold zero / emergency: council.rs:108-116,141-148,174-186; verify.rs:56-58,120-121 | Zero can pass `is_valid` on an unvalidated keyset; normal validation forbids it. The verifier uses normal threshold, not emergency threshold. No new zero/emergency/class policy selected; no claim that all library callers are safe |
| Distinct IDs vs distinct keys/operators: council.rs:61-77,188-202; verify.rs:133-157 | Validation dedups IDs, not public keys or operators. Two configured IDs can alias a key; exact-ID rejection does not establish independent signers. Keyset authenticity, key uniqueness and operator independence remain separate unresolved authority requirements, not prerequisites to proving this limited member-ID invariant |
| Algorithm policy: council.rs:69-75; verify.rs:171-188 | Key validation conditions length on the algorithm label; verifier always invokes ML-DSA-44. Algorithm admission/allowlisting is separate, not fixed or selected here |
| Network/root provenance and replay/currentness: hash.rs:120-123,144; verify.rs:95-124; envelope.rs:116-144,224-256 | Envelope network is signed, but not compared with keyset/expected network; approvals/timestamps are excluded and timestamps not freshness-validated. Verifier takes supplied keyset, not an authenticated current root. No provenance, replay, currentness or one-use guarantee follows |
| Binary-hash policy: CLI :233-255,260-283; envelope.rs:249-254 | Signature threshold is separate from checking a local binary. Missing optional check or missing platform can produce `None`, treated as true by `unwrap_or(true)`; this policy is unchanged, not endorsed or repaired |
| Upgrade execution, native governance, trust ratification and founder-authorized bootstrap | No upgrade executor is called by CLI :185-257. A8-F1, A23-F1 and section 7's RUN 422 authority decisions remain separate; this proposal selects no operational council members, threshold, authority allocation or bootstrap policy |

This is a bounded actionable authorization-counting candidate because a
specific shared public boundary, a deterministic source mechanism and an
offline verdict consumer are identified, with genuine-crypto positive and
negative controls available. It is not asserted to be globally highest
priority, a forgery, a deployed exploit or a native-consensus bypass; other
defects are not declared harmless. No adjacent gap above is necessary to the
exact-ID duplicate-refusal invariant. If independent review requires a
broader identity or admission invariant, record that dependency and leave
the contract **UNRESOLVED**, rather than claiming this proposal covers it.

### Historical pre-implementation acceptance matrix

At the contract revision, all cases below were **FUTURE / NOT EXECUTED**;
the implementation record below maps all 18 rows to actual execution.
Unless a row
explicitly isolates direct-library residuals, use a structurally validated
envelope and validated keyset. Use **disposable test credentials** and real
ML-DSA-44 signing/verification, following verify.rs:324-460; never an
always-success verifier, operational keys or operational signatures.
Retain assertions and actual outcomes for both APIs and relevant CLI cases.
Here, "duplicate refusal" means the exact variant/payload and no result
specified above; "below threshold" distinguishes `Ok`/false from wrapper error.
Row labels are local descriptions, **not new finding or evidence IDs**.

| FUTURE case (all NOT EXECUTED) | Expected result and required evidence |
|---|---|
| Single genuine approval, threshold 1 | Main API and wrapper succeed; count 1, threshold 1, is_valid true; real-verification fixture and assertions |
| Single genuine approval, validated 2-of-3 | Main API count 1 / false; wrapper `ThresholdNotMet { required: 2, actual: 1 }`; CLI text/JSON false and exit 1 |
| Two distinct genuine approvals, validated 2-of-3 | Both APIs succeed with count 2; CLI text success / JSON valid true / exit 0 without binary check; controls use distinct disposable keypairs |
| One genuine approval repeated, fewer than two distinct IDs | Duplicate refusal, not count 2 or ThresholdNotMet; separately retained baseline reproduction, if authorized, must not be mislabeled post-change regression |
| Same ID, different key/signature bytes or timestamps | Duplicate refusal for each variation, including byte-identical copies; digest comparison remains equal when only approvals change |
| Adjacent/nonadjacent duplicates; order variations; multiple repeated IDs | Refuse `[a,a,b]`, `[a,b,a]`, their permutations; assert first-second-occurrence rule on `[b,a,a,b]` and reordered inputs, not hash-set order |
| Enough other distinct genuine approvals plus duplicate | Refuse even if distinct valid quorum is already met before the duplicate or would be met later; no early success |
| Invalid-then-valid / valid-then-invalid, same ID | Same duplicate refusal in both orders, not first-wins/last-wins counting; include malformed encoding on the invalid occurrence |
| Repeated unknown member ID | Same duplicate refusal even though neither signature could authorize; include repeated unknowns alongside a sufficient distinct quorum |
| Distinct-ID unknown member / wrong approval public key / malformed key hex / malformed signature hex / cryptographically invalid signature | Each individually marked invalid with existing diagnostics; below-threshold result/wrapper error as appropriate. Repeat with enough other valid distinct IDs: success with invalid extras retained, not a new all-signatures-valid requirement |
| Exact identity comparison | IDs differing only in case or whitespace are not duplicates; test membership against exact configured IDs and retain unknown-member results where absent; no new normalization |
| Empty approvals; validated threshold boundaries | Main API count 0 / false and wrapper threshold error for valid positive thresholds. Exercise threshold 1, 2-of-3, and N-of-N with N-1/N distinct valid approvals; no zero-validations bypass in quorum fixtures |
| Both entry points / nonduplicate helpers | Same duplicate variant/payload on both APIs. For nonduplicates assert threshold, ordered signatures, digest_hex, valid_count, is_valid, invalid_count, valid_members and invalid_signatures consistency, including mixed valid/invalid extras |
| CLI early error, default text and `--output json` | Capture stdout/stderr/status: exact duplicate diagnostic, empty stdout, exit 1, no success or JSON object. Include optional binary path to show early return precedes binary I/O; preserve nonduplicate JSON schema and normal result/exit controls |
| Canonical digest / existing distinct-member fixtures | Assert unchanged domain/canonical bytes and digest for unchanged payload with approvals added, removed, duplicated or reordered; existing real distinct-member success fixtures still accepted; digest test alone is not authorization |
| Existing keyset rejection / CLI validation order | Zero threshold, threshold greater than key count, duplicate keyset IDs, invalid key material and unsupported version still fail keyset validation; CLI exit 2 before verifier, including duplicate approvals. Invalid envelope structure still exit 1 before verifier |
| Clearly isolated direct-library residuals / precedence | Show parsing alone does not validate. Characterize unchanged zero/excess-threshold, duplicate-keyset and malformed-structure handling without presenting it as valid quorum evidence. Duplicate approvals still refuse at API entry, including when a malformed key-map hex would otherwise error; source review verifies guard precedes digest/crypto |
| Raw helpers / inspect | Raw counts still include entries and inspect is not crypto authorization; their apparent threshold/structure output is never substituted for either verifier API |

### Proposed future paths, focused commands and evidence handoff

Only proposed future implementation path:
`crates/qbind-gov/src/verify.rs` (shared preflight and its directly related
API documentation; retain existing public types/signatures).
Extend its existing `#[cfg(test)] mod tests` for both entry points and
helper/real-signature controls. Extend existing
`crates/qbind-gov/src/hash.rs` tests only for digest-invariance controls.
Add `crates/qbind-gov/tests/envelope_cli_tests.rs` for CLI behavior, using
`env!("CARGO_BIN_EXE_qbind-envelope")`, `std::process::Command` and existing
`tempfile`; the repository precedent is
`crates/qbind-node/tests/run_375_public_devnet_identity_cli_tests.rs:21-66,310`.
This is a proposed new test target, not a file created now. Existing
`council.rs` validation tests are preservation controls. No manifest,
dependency, signing-format, CLI production, node or workflow change is
anticipated; any necessary expansion needs a revised reviewed scope.

**Proposed future commands, NOT RUN here** (from repository root, after
independent contract review and separately authorized implementation):

```sh
cargo test --locked -p qbind-gov --lib --test envelope_cli_tests
rustfmt --check --edition 2021 crates/qbind-gov/src/verify.rs crates/qbind-gov/src/hash.rs crates/qbind-gov/tests/envelope_cli_tests.rs
```

Keep independent contract review separate from any separately authorized
**pre-change reproduction**, implementation, **post-change regressions**,
independent code/evidence review, and later release/runtime evidence.
Future batches must record exact producing SHAs, source/test blobs, actual
commands/toolchain/configuration, exit statuses and pass/fail/ignored counts,
plus retrievable logs/fixture identities and checksums without secret key
material. Do not relabel a baseline outcome as a fixed result or use a
later summary's HEAD as the producer. Implementation must remain
**IMPLEMENTED — VERIFICATION PENDING** until independently reviewed; neither
source completion nor passing tests alone closes this finding or operational
gates. No new evidence ID is allocated; E01-E27 mappings and all 29 canonical
finding identities, aliases and 54 obligation identities remain unchanged.

The original contract task performed only documentation/source correspondence, pinned
identity/locator/link, scope/status/inventory, protected-section byte,
mode/LF/terminal-newline and whitespace checks. Every other tracked file,
including the audit register and evidence archives, is unchanged. No Cargo,
key generation, signing, CLI execution, node or harness is run. Final
documentation commit/tree, changed-path mode/blob manifest, raw parentage
versus available-object ancestry, remote task-tip equality, unchanged remote
main and clean worktree are reported after commit/push, without embedding a
self-referential final hash.

### Authorized bounded implementation and supplied pre-implementation review (2026-11-04)

**Status: IMPLEMENTED — VERIFICATION PENDING; overall finding OPEN.**
This conversation separately authorized the bounded fix, isolated baseline
reproduction, disposable-credential tests, evidence/documentation and a push
only to `copilot/audit-f002-distinct-approval-fix`. No PR, merge, main push,
force-push, deployment or activation is authorized or performed.

The following review was supplied through this task in this conversation,
attributed to ChatGPT, not independently retrieved or signed:

> ChatGPT reviewed section 13 at commit 305640e0dffa16872692906af052dbf15937b192 and the relevant verifier, threshold-wrapper, keyset-validation, canonical-digest and CLI paths. The existing verifier counts every valid approval without deduplicating member IDs. The specified shared-entry duplicate refusal addresses that mechanism while preserving the signed digest and nonduplicate verification behavior. No blocking issue was identified within this bounded contract. This was source/design review; no reproduction or tests were executed by that reviewer.

No human reviewer, external review URL, signed approval or execution evidence
is inferred from that statement. Independent post-implementation code and
evidence review remains **PENDING**.

| Implementation entry identity | Actual observation |
|---|---|
| Repository; fetch/push | `olivexo28/QBIND`; `origin`, `https://github.com/olivexo28/QBIND` both directions, unchanged |
| Required pre-change commit/tree | `305640e0dffa16872692906af052dbf15937b192` / `6529ebb5d0cefeacdc3c047d85134fe755d011da` |
| Authoritative plan blob | `eb4787ce154564f17364a5442331b8299eeff4c6`, verified before editing |
| Main at entry | Advertised `427c72a6bd2712b58c2777df2b26145463ef1257`; contract fetched from its existing branch, not required on main |
| Implementation branch | `copilot/audit-f002-distinct-approval-fix`, absent locally/remotely at entry, freshly created at required commit |
| Checkout/instructions | Initial checkout clean including untracked files; no applicable `AGENTS.md` or repository instruction files found; unrelated files preserved |
| Producing implementation/test commit/tree | `149edffd8f7fd97c821d6df9a5a546eca4992b79` / `d3872f17f033b32c5cfb451bc60d96979b0aec37` |
| Raw parentage versus proven ancestry | Required commit raw parent is `427c72a6bd2712b58c2777df2b26145463ef1257`; producing commit raw parent is the required commit. Available objects prove that descent. Main's raw parent `2e93ba7c202898f275703c94df8ed9677aa111e6` remains unavailable at the shallow boundary; no deeper ancestry claimed |

The only production modification is the entry guard and directly related
function documentation in `crates/qbind-gov/src/verify.rs`. A borrowed-ID
HashSet scans every approval using exact Rust string equality, retaining the
first failed insertion in input order without iterating the set. It completes
the loop before returning the existing `VerificationFailed` payload.
Digest computation, key-map construction and ML-DSA-44 verification occur
only afterward. The threshold wrapper's existing `?` propagates refusal.
Nonduplicate result fields/helpers, thresholds, canonical bytes, domain,
crypto and CLI rendering/exit behavior remain unchanged. `hash.rs` changes
are test-only; the new CLI target uses the existing dependencies.

### Isolated pre-change reproduction, not post-change regression

Before any production edit, a detached checkout of the exact required commit
was created and instrumented only with
`crates/qbind-gov/tests/f002_baseline_probe.rs`, delivered as
[baseline_probe.rs](evidence/f002/baseline_probe.rs). It is **not** described
as an unchanged baseline working tree: tracked production bytes were
unchanged, with one untracked test probe. Exact source blobs and the probe
SHA-256 are retained in [baseline.log](evidence/f002/baseline.log) and
[toolchain-and-format.log](evidence/f002/toolchain-and-format.log).

The probe validates a 2-of-3 keyset, checks all three disposable public keys
are distinct, structurally validates each envelope and uses genuine
ML-DSA-44 signatures. One approval gives count 1 / false and wrapper
`ThresholdNotMet`; two distinct approvals give count 2 / true; copying the
first genuine approval twice also gives count 2 / true in both APIs,
reproducing the defect. **1 passed, 0 failed/ignored; exit 0.**
An earlier probe used the wrong JSON class label `C` and failed parsing
before reproduction: **0 passed, 1 failed, exit 101**. Its log is retained
separately as [baseline-initial-failed.log](evidence/f002/baseline-initial-failed.log);
the corrected delivered probe uses `c_hard_fork`. No baseline result is
assigned to the later implementation revision.

### Actual acceptance mapping at the producing implementation/test revision

All rows below **PASS** in [focused-tests.log](evidence/f002/focused-tests.log),
produced by `149edffd8f7fd97c821d6df9a5a546eca4992b79`, not by a later
documentation-only HEAD. `verify::tests::` prefixes the library verifier
test names below; `hash::tests::` prefixes the digest test; `f002_cli_*`
names are in the `envelope_cli_tests` integration target.

| Contract category (original row order) | Actual tests / result |
|---|---|
| 1. Single genuine approval, threshold 1 | `f002_validated_thresholds_and_empty_approvals` — both APIs, count/threshold/helpers PASS |
| 2. Single approval, validated 2-of-3 | `f002_validated_thresholds_and_empty_approvals`; `f002_cli_nonduplicate_controls_schema_and_invalid_extra` — library false/wrapper exact threshold error, text/JSON exit 1 PASS |
| 3. Two distinct approvals, validated 2-of-3 | Same tests; existing `test_threshold_verification` — both APIs and CLI text/JSON success without binary check PASS |
| 4. One genuine approval repeated | `f002_duplicate_order_and_sufficient_quorum`; separate pre-change probe above — both APIs refuse after correction PASS |
| 5. Same ID, different bytes/timestamps | `f002_duplicate_bytes_timestamps_and_invalid_orders`; `hash::tests::f002_canonical_domain_and_approval_invariance` — exact refusal, digest invariance PASS |
| 6. Adjacency/permutations/multiple repeats | `f002_duplicate_order_and_sufficient_quorum` — `[b,a,a,b]` reports `a`, reordered `[a,b,b,a]` reports `b` PASS |
| 7. Otherwise sufficient distinct quorum | `f002_duplicate_order_and_sufficient_quorum`; `f002_unknown_duplicates_with_and_without_quorum` — repeats before/after quorum refuse PASS |
| 8. Invalid/valid same-ID ordering | `f002_duplicate_bytes_timestamps_and_invalid_orders` — both orders including malformed hex PASS |
| 9. Repeated unknown ID | `f002_unknown_duplicates_with_and_without_quorum`; `f002_cli_duplicate_text_json_and_binary_early_return` — with/without quorum refuse PASS |
| 10. Five distinct-ID invalid-extra classes | `f002_nonduplicate_invalid_extras_and_helpers` — each unknown/mismatch/bad-key-hex/bad-signature-hex/crypto-invalid extra, 0/1/2 genuine controls, existing diagnostics retained PASS |
| 11. Exact identity | `f002_exact_identity_and_membership` — case/leading/trailing whitespace distinct, configured membership/unknown diagnostics, exact refusal payload PASS |
| 12. Empty/validated threshold boundaries | `f002_validated_thresholds_and_empty_approvals` — 0 through 3 approvals at thresholds 1/2/3, including N-1/N PASS |
| 13. Both APIs/result helpers | All library `f002_*` tests via `f002_refuses`/`f002_counts`; existing `test_verification_result_helpers` — ordered results/count/digest/members/invalids PASS |
| 14. CLI text/JSON early error/binary | `f002_cli_duplicate_text_json_and_binary_early_return`; `f002_cli_nonduplicate_controls_schema_and_invalid_extra` — exact stderr newline/empty stdout/exit 1, missing binary not reached on duplicate, normal schema/result controls PASS |
| 15. Canonical/domain/digest | `hash::tests::f002_canonical_domain_and_approval_invariance`; existing digest/signature fixtures — exact canonical JSON/domain, approval add/remove/copy/reorder invariance PASS |
| 16. Keyset rejection/CLI precedence | `f002_cli_keyset_and_envelope_validation_precedence`; existing council validation tests — zero/excess threshold, duplicate IDs, malformed/wrong-size key, version reject exit 2 before invalid envelope/duplicates; valid-keyset invalid envelope exit 1 PASS |
| 17. Direct-library residuals/entry precedence | `f002_direct_library_residuals_and_entry_precedence` — deliberately unvalidated zero/excess/duplicate-keyset/malformed-envelope cases, parsing not validation, malformed key-map duplicate refusal PASS; source inspection confirms full scan before digest/map/crypto |
| 18. Raw helpers/inspect | `f002_raw_helpers_do_not_authorize`; `f002_cli_inspect_is_descriptive_not_authorization` — raw count/inspect descriptive success unchanged, verifier refusal PASS |

Required focused command:
`cargo test --locked -p qbind-gov --lib --test envelope_cli_tests`:
**36 library + 4 CLI passed; 0 failed, 0 ignored, exit 0.**
Required `rustfmt --check --edition 2021` command over the three Rust
paths: **exit 0**. Toolchain/host/configuration, commands and exact producing
blobs are in the retrievable logs. No code/tests changed after that run.
Scope/mode/LF/whitespace, protected sections 8/12, hash production bytes and
local documentation links are checked by the delivered evidence checker.
See [evidence README](evidence/f002/README.md) and
[SHA-256 manifest](evidence/f002/SHA256SUMS) for commands, identities,
limitations and delivered-byte checksums. Documentation/evidence commits
are separate; final revision/tree, delivery, main observation and complete
changed-path manifest are reported after commit without a self-referential
hash claim in this document.

### Retained limits and operational gates

Member-ID uniqueness establishes neither distinct keys nor independent
operators. Keyset provenance, direct-library structural admission, algorithm
policy, network binding, freshness/replay, binary-check policy and operational
authority remain separate unresolved boundaries. These direct-library tests
are characterizations, not validated quorum evidence or endorsements.
No operational key/signature is used or delivered; test secret keys exist
only in process memory. No node execution, Run 384/385, workspace-wide suite,
scanner, live exploit, upgrade execution or release run was performed.
Passing bounded tests is not independent review, deployed exploitation
evidence or closure. All BR decisions, evidence qualifications and release
gates remain unchanged. Activation remains **DISABLED**; public DevNet remains
**NO-GO**; independent post-implementation review is **PENDING**, finding **OPEN**.
