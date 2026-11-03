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
   number or raw item count. The manifest candidate in section 8 is an initial
   bounded task, **not** a claim that it is the highest-severity finding.
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
  document-cited existing verification in section 7. A reference to a RUN 422
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
| A21-F1 = QBIND-A1-F001 | OPEN STATIC hand-written count-driven reservation; R7.1 at A:L14115 and A44 | Proposal decoder, before body/sender checks; D; O/R availability relevance | Bounded current check, then checked count/body/resource limits; no policy bypass | Temporary hostile/truncated counts plus valid controls; reservation != RSS != guaranteed crash; E12/E13 |
| A23-F1 | OPEN K!=T ratified-target/bundle-signer gap; A9.1 at A:L13517-L13518; A26 refinements retained | V2 trust ratification/install; D; C4/O | Ratification invocation/data-dir and independent genesis provenance prerequisites; retain DevNet no-data-dir no-op qualification | K/T, external genesis and gate/config controls; E23; not automatic runtime authorization escalation |
| A24-F1 | OPEN opt-in metrics HTTP resource limits/deadlines; A15 at A:L11446-L11489 | Metrics HTTP handlers; D; O | Check enabled/reachable endpoint and size/concurrency/deadline controls | Bounded request/header/stall/handler/shutdown evidence E24; default-disabled is reachability mitigation |
| A25-F1 | Source-established operator-assurance gap; severity uncertain, no distinct ratification authorization bypass; A25.2 at A:L8351-L8426 | Run-163 governance-proof fixture verifier; D/MI; C4/C5/O | Preserve upstream real ratification gate; decide real independent authority proof versus truthful unavailable control | Public-data issuer-pattern/threshold controls plus approved real proof; no bypass of upstream signature inferred |
| A28-F1 | OPEN cumulative limiter-key retention; A16 at A:L11280-L11305 | Per-peer/prefix and opt-in per-address bucket maps; D; O | Check both deployed/default and optional limiter ownership/pruning separately | Count retention after disconnect, insertion rate and memory/availability E25; separate from live-session occupancy |
| A31-F1 | OPEN stale outbound root; A10.1 at A:L13172 | Dial retry/handshake root snapshot; D/DD; C4/O | Correct two-root witness, pinned peer KEM private-key and reload-window prerequisites | Root-signature pass, handshake completion, registry insertion separately; E26; single-root witness withdrawn |
| A33-F1 | Conditional engine non-termination source-established; A5.3 at A:L15366; A22.1 restores current-baseline status | Block eviction ancestry walk; D; R/O availability relevance | Operator-crafted anchor and admitted catch-up construction; no hash-collision premise or anonymous attack claim | Exact registration-before-vote state/capacity, cycle termination and bounded impact E27; runtime UNEXECUTED |
| H04-F1 | Remote signer non-functional/unwired; A18/A18.1, A:L10351-L10740 | Validator daemon accept loop/node signer mode; MI; C5, not standalone DevNet blocker by audit | Use separate-signer feasibility/approved profile; do not transfer dead handler checks to live accept loop | Actual accept/handshake/handler and required/optional-mode evidence E17; no signing-oracle claim |
| QBIND-A1-F002 | OPEN carried offline duplicate-approval quorum bypass; A:L9280, A:L16506-L16510 | Offline qbind-gov approval counting; D; C5/O | Check distinct-signer counting in current CLI before bounded fix; not native A8-F1 | Duplicate/distinct valid approvals, threshold boundaries and offline output controls |
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
| OBL-PAR-1 | Inner parser/allocation source inventory complete to scope, A7.1/R7 then A42.1/A43.1; A21-F1 distinct | D/ME / consensus/DAG codecs / O | Preserve hand-written versus serde distinction; no bincode limit-counter claim | Explicit input cap, availability, nesting, reservation and E12 |
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
| OBL-REL-1a | Build/workflow source sub-boundaries complete A48.2/A49.1, constant-clean candidate retained | D/ME / release manifest/workflows / A | FIRST BOUNDED CANDIDATE section 8; only three current files inspected | Temporary Git-fixture regressions; four evidence planes remain separate |
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
| E07 | Release/CI/build/historical assurance; A48.2/A49.1 four planes | D/ME / manifest/build environment / A | Section 8 candidate plus distinct effective-build/artifact evidence; no provenance closure from consistency |
| E08 | A2-F1 possession reproduction | ME / transport / R-F6/O | Disposable isolated control set; public cert versus key-holder, actual session admission |
| E09 | Deployment and validator launch profile | ME / live operation / M4/M6/S5/S7/RS1 | Four stopped machines are not live evidence; approved deployment/test scope first |
| E10 | A4-F1 occupancy and A4-F2 cookie integration | ME / handshake resources / O | Occupancy/worker/socket release and complete cookie/client retry, not rate alone |
| E11 | A5-F1 frame-timeout platform behavior | ME / read framing / O | Exact partial-consumption schedule with idle/valid controls and connection outcome |
| E12 | Parser/dependency/aggregate memory | ME / codecs/allocator / O/A | A43.1 schema source work retained; explicit cap != heap cap, reservation != capacity/RSS; measure remaining aggregate scope |
| E13 | Queue/ownership/outbound byte budgets | ME / channels/encoders / O | Four-channel A45.1 inventory, in-flight buffers/concurrency/outbound caller sizes; no global ceiling asserted |
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
| A48.1-C2 / E07 / OBL-REL-1a, A:L650-L688 | Constant-clean producer evidence-assurance candidate retained; D; A | Section 8, FIRST BOUNDED CANDIDATE; no highest-severity claim | Truthful classification and temporary Git-fixture before/after evidence |
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

**E07 / OBL-REL-1a / A48.1-C2. FIRST BOUNDED CANDIDATE; not highest-severity
ranking. Owner UNASSIGNED. Status PREPARED / NOT IMPLEMENTED / NOT TESTED.**

Current-code applicability is **CONFIRMED ONLY for the inspected producer
mechanism, schema contract and caller below**, at coordination starting commit
`c44370ee4b77eda8b4c9966632e3b8ce796ba203`. No whole build/workflow or
deployed-binary applicability claim follows.

| Current file / mode / blob | Bounded observation |
|---|---|
| [Run 384 producer](../../scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh), `100644`, `53be84e52f97288a2eba0fa53eee296c8d62a2a9` | Lines 221-227: both branches assign `TREE_STATE="clean"` after worktree/index `git diff --quiet` with `:(exclude)docs/**`; Git errors also fall into constant clean. Line 261 emits the value. Does not inspect untracked files |
| [Manifest schema](../release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.schema.json), `100644`, `54ae5827ce5bcd749bb674742128eb1b20afce8b` | `source_tree_state` is required; enum `clean`, `dirty`, `unknown`; description says "Source tree cleanliness at build time." Enum acceptance cannot establish truthfulness |
| [Run 385 caller](../../scripts/devnet/run_385_public_devnet_ci_release_artifact_manifest.sh), `100644`, `3c5a0f930195107b6d5a28c48ec7122140740a11` | Lines 98-109 invoke Run 384 via bash and require its positive summary; 134-177 stage/revalidate manifest. Does not recompute or correct tree state; full schema validation accepts all three enum values |

**Scope and prerequisites for the future implementation task:**

* Before implementation, an independent reviewer other than the
  implementation author must record the finding and correction check required
  in section 2. Pin the then-current commit/tree, A49.1 input identity and
  three file blobs; record the scoped source mechanism, applicable
  truthfulness requirement, reachability, effect/uncertainty, intended
  behavior, checked-file/timing scope, caller/schema compatibility,
  dependencies and fixture controls. Outcome must be supported and
  **CONFIRMED TO [scope]** before this correction proceeds. Reviewer identity
  and outcome are not supplied by this plan; do not treat this card or its
  initial source observation as independent confirmation. Use the existing
  task authorization and assignment process; no additional protocol-owner
  decision is a prerequisite for this routine, bounded defect. No bootstrap
  B/U decision, live deployment or full harness execution is prerequisite.
* Define the checked-file scope explicitly in code/docs and tests. A bounded
  compatibility target is the existing **tracked repository paths excluding
  `docs/**` only**, compared HEAD -> index and index -> worktree; include
  staged/unstaged changes, additions, deletions, renames, mode changes and
  dirty tracked submodules regardless of user diff-ignore configuration.
  Do not silently add an `Audit/**`, workflow, lockfile or script exclusion.
  Untracked files (including untracked build outputs) are **not checked** by
  this bounded tracked-only policy and must be disclosed; ignored files,
  external configuration and dependency/build environments are not proven
  clean. If "clean" must instead mean all build-affecting inputs, settle and
  test the expanded scope before claiming it; do not conceal this mismatch.
* Classify clean only when **every required observation succeeds with no
  differences**, dirty on an observed difference, unknown on an indeterminate
  observation. Git diff status 0, 1 and errors (>1/failed invocation) are
  distinct. Preserve stderr/explicit diagnostic for errors; never silently
  turn an error into clean. Define precedence for mixed dirty/error
  observations; conservative candidate: **unknown if any required check
  fails**, dirty only after all checks succeed. Either emit explicit unknown
  with diagnostic or fail manifest generation according to a documented
  caller contract; this choice must be fixed in the task before coding.
* Resolve **timing versus wording**. Current observation is after build and
  node/metrics runs (build lines 158-161; node launch 178 and 207; observation
  221-227), not evidence of state "at build time." Capture at an explicitly
  named pre-build boundary and recheck after building, or truthfully narrow
  the schema/documentation claim to the observation instant. Pre/post equality
  alone does not exclude transient edits during the build; do not claim a
  continuous immutable snapshot without providing one. No node is needed to
  validate this classification slice.
* Preserve schema/caller compatibility: enum already permits dirty/unknown;
  determine whether downstream policy merely records them or explicitly
  refuses. No schema-value expansion is needed for classification alone.
  Read Run 385 and all relevant selected callers at task entry; retain
  existing manifest format/non-claim fields and full validation. Do not
  alter independent metric/ELF comparisons, workflow checks or node behavior.
  Respect committed EOL/invocation prerequisites; do not fix CRLF execution
  or attestation in this task by incidental rewrite.

**Focused regression evidence, future task only:** use disposable temporary
Git fixtures outside the real checkout. Exercise the actual extracted/reused
classification logic, not a separately reimplemented proxy. Capture before
and after for clean, tracked unstaged, staged, staged+unstaged, added/deleted/
renamed/mode-changed, docs-only changes, untracked-only, ignored-only,
included Audit/script/workflow/lockfile changes, tracked submodule changes,
and explicit Git failure/not-a-repository. Include whitespace/unusual path
names and Git ignore/diff configuration that could hide differences. Baseline
must show constant clean for dirty and failing observations; after must
match the declared truth table. Test error diagnostics, chosen mixed-result
precedence, schema acceptance of each emitted value and caller behavior with
a synthetic manifest without executing Run 384/385. Prove observation timing
with controlled fixture mutations. Preserve commands/results and remove only
known temporary fixtures.

**Closure boundary:** implementation commit + review + focused regression
evidence may close **only the constant-clean classification defect to the
declared scope/timing**. It does not establish source-to-built or
binary-to-deployed correspondence, effective compiler/target/profile/features,
cache behavior, inherited environment, reproducibility, attestation authenticity,
CRLF invocation success, historical uploaded-artifact contents, runtime safety,
E07 overall closure or release eligibility.

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

## 11. Documentation-only delivery checks

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

**Next bounded implementation:** section 8's E07 / OBL-REL-1a / A48.1-C2
constant-clean producer. Actual prerequisites are a pinned current input/
source baseline, bounded implementation authorization and assignee, explicit
checked-path/untracked/error/timing contract, caller/schema compatibility
review and a no-node temporary-Git-fixture regression plan. Unrelated BR
decisions and public activation are not prerequisites for that bounded fix;
they remain mandatory for their dependent authority/recovery/operational work.
