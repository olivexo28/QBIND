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
| OBL-REL-1a | Build/workflow source sub-boundaries complete A48.2/A49.1; constant-clean producer defect source-confirmed to its stated mechanism | D/ME / release manifest/workflows / A | **IMPLEMENTED — VERIFICATION PENDING**; fsmonitor false-clean corrected and fixture gaps repaired at the revisions recorded in section 8; independent review pending; not closed | Isolated Git fixtures cover the bounded reporting contract; build/artifact/deployment evidence remains separate |
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
| E07 | Release/CI/build/historical assurance; A48.2/A49.1 four planes | D/ME / manifest/build environment / A | Section 8 bounded reporting correction contract plus distinct effective-build/artifact evidence; no provenance closure from consistency |
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
| A48.1-C2 / E07 / OBL-REL-1a, A:L650-L688 | Constant-clean producer evidence-assurance candidate source-confirmed to the stated mechanism; D; A | **IMPLEMENTED — VERIFICATION PENDING** in section 8; independent review supplied through the task identified fsmonitor suppression and test-coverage gaps, now corrected; no closure change | Corrected isolated fixtures pass; build provenance and other E07 evidence planes remain outstanding |
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

### Corrective implementation and verification-pending review (2026-11-03)

**Current status: IMPLEMENTED — VERIFICATION PENDING.** Finding identifiers:
**E07 / OBL-REL-1a / A48.1-C2**. This bounded correction does not close the
finding or E07 overall and does not change release or operational gates.
Independent verification of the corrected implementation remains pending.

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
build/artifact/runtime/deployment evidence remains unresolved. Current status
remains **IMPLEMENTED — VERIFICATION PENDING** until the corrected
implementation and final fixture/documentation correction receive a separate
independent post-change review; E07 overall and all release/operational gates
remain unchanged.

### Final fixture reproducibility correction — review pending (2026-11-03)

**Status remains IMPLEMENTED — VERIFICATION PENDING.** This final bounded
correction is for **E07 / OBL-REL-1a / A48.1-C2** and does not change the
successful disposition of the preceding fsmonitor and isolated-fixture
corrections.

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
constant-clean producer. The proposed path, source baseline, scope, timing,
error/caller/schema treatment and future Git-fixture matrix are recorded;
independent review and the subsequent task's bounded implementation
authorization remain outstanding. Unrelated BR decisions and public
activation are not prerequisites for that bounded fix; they remain mandatory
for their dependent authority/recovery/operational work.
