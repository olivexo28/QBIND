# Empty RestoreCatchupResponse containment contract (candidate)

**EMPTY-RESPONSE CONTAINMENT CONTRACT — INDEPENDENT REVIEW PENDING.**
A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain **OPEN**.
Activation remains **DISABLED**; public DevNet remains **NO-GO**.

This is a documentation-only candidate boundary for independent review. It
does not implement or accept containment, alter A17-F1, authorize recovery,
or assert runtime/deployed behavior. The investigation's user-supplied
**PASS WITH LIMITATIONS** and the source analysis and publication/integrity
checks accepted within its scope are carried forward. No reviewer identity
or unavailable raw review artifact is asserted. The previously proposed
investigation acceptance tests remain **FUTURE / NOT EXECUTED**. The future
cases below are proposed contract controls, not tests run in this task.

## Pinned source and accepted evidence

The frozen base is commit
`541d9a6c9a43fe10410260d9c2494a5fc4416c7a`, tree
`0b0e597a29dc8f2d95d93f9bd04364cc140a9db1`. It is the accepted merge
of the prior containment history; its parent is
`2d3b2f7a4c4055882525e3af1814d57e87c01c76`, and its second parent is
`9ef29e2432b9b84fca63e59440d64d085631e9a3`. The former and frozen commits
have identical trees. Source references below are pinned to frozen commit
541d9a6. No source or test code is changed here.

* Actual ingress, counters and the existing unconditional non-empty guard:
  [binary_consensus_loop.rs:6150-6190](https://github.com/olivexo28/QBIND/blob/541d9a6c9a43fe10410260d9c2494a5fc4416c7a/crates/qbind-node/src/binary_consensus_loop.rs#L6150-L6190)
  and
  [7390-7425](https://github.com/olivexo28/QBIND/blob/541d9a6c9a43fe10410260d9c2494a5fc4416c7a/crates/qbind-node/src/binary_consensus_loop.rs#L7390-L7425).
* Authenticated-origin/claimed-responder one-to-one comparison:
  [peer_consensus_binding.rs:388-447](https://github.com/olivexo28/QBIND/blob/541d9a6c9a43fe10410260d9c2494a5fc4416c7a/crates/qbind-node/src/peer_consensus_binding.rs#L388-L447)
  and
  [binary_consensus_loop.rs:7393-7424](https://github.com/olivexo28/QBIND/blob/541d9a6c9a43fe10410260d9c2494a5fc4416c7a/crates/qbind-node/src/binary_consensus_loop.rs#L7393-L7424).
* Empty helper behavior, self early-return, and empty-path anchor bypass:
  [binary_consensus_loop.rs:8450-8505](https://github.com/olivexo28/QBIND/blob/541d9a6c9a43fe10410260d9c2494a5fc4416c7a/crates/qbind-node/src/binary_consensus_loop.rs#L8450-L8505)
  and
  [8555-8590](https://github.com/olivexo28/QBIND/blob/541d9a6c9a43fe10410260d9c2494a5fc4416c7a/crates/qbind-node/src/binary_consensus_loop.rs#L8555-L8590).
* Request cadence, proposal deferral and view-timeout active gate:
  [binary_consensus_loop.rs:8350-8405](https://github.com/olivexo28/QBIND/blob/541d9a6c9a43fe10410260d9c2494a5fc4416c7a/crates/qbind-node/src/binary_consensus_loop.rs#L8350-L8405),
  [3270-3315](https://github.com/olivexo28/QBIND/blob/541d9a6c9a43fe10410260d9c2494a5fc4416c7a/crates/qbind-node/src/binary_consensus_loop.rs#L3270-L3315),
  [7550-7610](https://github.com/olivexo28/QBIND/blob/541d9a6c9a43fe10410260d9c2494a5fc4416c7a/crates/qbind-node/src/binary_consensus_loop.rs#L7550-L7610).
* Existing A17 inactive, non-self empty, direct-import progressed fixture and
  pure state tests:
  [binary_consensus_loop.rs:10400-10440](https://github.com/olivexo28/QBIND/blob/541d9a6c9a43fe10410260d9c2494a5fc4416c7a/crates/qbind-node/src/binary_consensus_loop.rs#L10400-L10440),
  [10835-10935](https://github.com/olivexo28/QBIND/blob/541d9a6c9a43fe10410260d9c2494a5fc4416c7a/crates/qbind-node/src/binary_consensus_loop.rs#L10835-L10935),
  [10935-11020](https://github.com/olivexo28/QBIND/blob/541d9a6c9a43fe10410260d9c2494a5fc4416c7a/crates/qbind-node/src/binary_consensus_loop.rs#L10935-L11020).
  They are accepted prior tests/source evidence, not executions for this
  contract.
* Production P2P Required policy/no current Proposal-Vote authorization,
  inbound authority refusal, and mode-independent leader tick:
  [main.rs:8680-8710](https://github.com/olivexo28/QBIND/blob/541d9a6c9a43fe10410260d9c2494a5fc4416c7a/crates/qbind-node/src/main.rs#L8680-L8710),
  [binary_consensus_loop.rs:3220-3260](https://github.com/olivexo28/QBIND/blob/541d9a6c9a43fe10410260d9c2494a5fc4416c7a/crates/qbind-node/src/binary_consensus_loop.rs#L3220-L3260),
  [6240-6330](https://github.com/olivexo28/QBIND/blob/541d9a6c9a43fe10410260d9c2494a5fc4416c7a/crates/qbind-node/src/binary_consensus_loop.rs#L6240-L6330).
* Honest empty-export behavior:
  [binary_consensus_loop.rs:8405-8455](https://github.com/olivexo28/QBIND/blob/541d9a6c9a43fe10410260d9c2494a5fc4416c7a/crates/qbind-node/src/binary_consensus_loop.rs#L8405-L8455).
* Existing accepted investigation and its integrity record remain
  [unchanged](../README.md); the prior package manifest is not rewritten.
  The new append-only plan entry links this candidate, and this subdirectory
  has its own paths list, checks log and checksum manifest.

## Recommendation and boundary

**Recommend for independent review:** after successful sender binding,
successful-response accounting, and the preserved non-empty refusal, refuse
an empty response as an input to peer-height tracking and restore-mode
transition. Count it once as a bound empty response deliberately ignored,
emit no per-frame log, do not call the existing response helper, and leave
the peer maximum and mode untouched.

This is the narrowest proposed containment of the empty-response scalar
effect. It prevents this handler from using a peer's bare optional height to
clear restore mode. It is not a recovery path, not an operator resume/clear
capability, and not an engine or signer quarantine. Do not add a fallback
that permits empty-response mode exit for a trusted peer, matched request,
configuration, self identity, inactivity, or timer.

### Exact handler point

At the actual `RestoreCatchupResponse` arm:

1. Keep generic inbound message count and inbound `other` metric where they
   are now, before binding. Those count received/attempted handler input and
   are not successful-response admission.
2. Keep authenticated-origin/claimed-responder binding before response
   receipt accounting. Missing, unknown, ambiguous, or mismatched origins
   return through the existing binding-reject path.
3. Keep `restore_catchup_responses_received` after successful binding.
4. Keep the existing `!blocks.is_empty()` refusal exactly as is: increment
   `restore_catchup_responses_rejected` once, diagnose missing verifiable QC
   endorsements, return. Do not route non-empty responses to the new empty
   counter or helper.
5. Immediately after that guard, identify the now-empty bound response,
   increment the proposed `restore_catchup_empty_responses_ignored_total`
   once, then return. Do not invoke
   `handle_restore_catchup_response` or
   `evaluate_restore_mode_transition`.

The counter is proposed and does not exist in current production source.
It must be wired consistently to the loop stats/metrics surface if this
candidate is implemented. It counts only empty responses that reached this
point after successful binding, including bound self-labelled and initially
inactive responses. Existing `restore_catchup_responses_received` still
counts them too; that is intentional stage accounting, not double-counting
the new counter. Do not increment `restore_catchup_responses_rejected` for
an intentionally ignored empty. A binding failure increments only generic
inbound observation and existing binding rejection accounting—not received,
empty-ignored, or non-empty rejection.

Prefer the single bounded counter as the diagnostic. Do not emit a
peer-controlled per-message log or high-cardinality peer/height labels. A
static startup/configuration note may explain the behavior, but it does not
replace event accounting. If implementation later requires logging, rate
limit it and do not duplicate response-rejection metrics.

## Observable outcomes and mode invariants

| Input that reaches the response arm | Existing observation | Proposed empty policy: counter/diagnostic | Peer maximum, helper, mode, handler-originated outbound |
|---|---|---|---|
| Successfully bound, non-self, empty | Generic inbound + `other`; binding accepted; response received | `empty_responses_ignored_total += 1`; no per-frame log | No maximum update; helper not called; no clear/rearm; no handler-originated action |
| Successfully bound and self-labelled empty (origin is the local mapped identity) | Same successful-binding and receipt accounting; current helper returns before peer tracking | Same one ignored increment | No maximum update; no helper; mode unchanged |
| Claimed self while origin is an authenticated non-self peer | Generic inbound + `other`; binding reject only | No empty ignored/received/rejected response increment; existing binding diagnostic/counter only | No helper/tracking/mode change/action |
| Missing or otherwise unbound origin, unknown/ambiguous peer, or claimed-responder mismatch | Generic inbound + `other`; existing binding rejection only | No empty ignored/received/non-empty rejection increment; no additional empty log | No helper/tracking/mode change/action |
| Successfully bound non-empty (self or non-self) | Generic inbound + `other`; binding accepted; response received; existing non-empty rejected once | Existing endorsement diagnostic and rejection counter unchanged; new empty counter stays 0 | Existing immediate return preserved; no helper/tracking/mode change/action |

This rule is state-independent: while active, already inactive, or after any
number of repeated responses, a bound empty does not update or lower/raise
the prior peer maximum, clear mode, or rearm mode. Repeats each increment
the existing receipt count and proposed empty-ignored count once. Self and
binding failures retain the distinctions above. The new response counter
is observability only; it is not clearance or resume authority.

No response-helper call means no scalar peer-height evaluation. It does not
mean no generic ingress observation, no existing binding metrics, or no
other event in the receive loop. Do not describe the proposed behavior as
"zero engine effects" for the whole loop.

## Liveness, compatibility and comparison

Retaining existing behavior preserves compatibility with any peer that
sends empty responses and preserves the current scalar exit path. But a
bound peer can report `None`, a lower/equal value that helps meet the
stored maximum, or an inflated `Some(H)` that raises the monotone target.
Identity binding establishes which configured identity sent the frame; it
does not establish the accuracy of H, chain agreement, response freshness,
quorum endorsement, or recovery authority.

The pinned honest request handler returns without sending a response when
export is empty. Therefore its current empty-export path does not generate
an empty response. Behavior of external/older implementations, alternate
senders, or manually generated frames is **unverified**. Do not claim that
the pinned honest path proves empty frames impossible.

Under the candidate refusal, a restored node may remain in restore mode
indefinitely. It keeps attempting eligible `RestoreCatchupRequest`
broadcasts (tick cadence, local anchor and facade still gate emission),
continues deferring qualifying far-future/wrong-parent proposals, and
continues suppressing the local view-timeout emission path. Honest recovery
availability through empty responses is lost. No timeout or height-based
fallback clears mode. The proposed change therefore trades current
untrusted scalar-exit behavior for potentially indefinite restore-mode
availability loss; it requires explicit independent review and compatibility
assessment before implementation.

An outstanding-request or request-anchor check is a possible distinct
future admission condition, not a sufficient replacement for this
containment. Empty responses currently bypass both anchor fields and there is
no outstanding-request ledger at this path. Matching a request could prove
correlation to a local request, but the responder still chooses the reported
height. Transport binding proves the sender identity under configured
transport/mapping checks, not that sender's claimed height is truthful.
Neither mechanism gives QC endorsement, positive recovery, or clear/resume
authority. If considered later, specify its wire semantics and lifecycle
separately; do not weaken the proposed no-scalar-clear rule by treating a
match as proof.

### Not a complete engine/signer quarantine

Restore mode is only a gate for request emission, selected proposal
deferrals and local timeout eligibility. Leader ticks still run in either
mode. Engine proposal registration and a local logical self-vote happen
before outbound Proposal/Vote admission; current production Required policy
and absent coherent PV authorization suppress publication, but do not roll
back those local engine mutations. Bound inbound Timeout/NewView handling
is also a separate mode-independent route, with its own binding,
verification, quorum, retained-high-QC and publication checks. An empty
response rejection does not stop these routes.

Therefore neither active mode nor ignoring empty responses establishes
complete engine isolation, signer fencing, global signer exclusivity,
durable quarantine, authenticated recovery, or safe consensus
participation. Positive recovery/currentness, signer exclusivity, durable
quarantine ownership/lifecycle, and separately authorized clear/resume
remain independent obligations. No allow, clear, resume, or trust decision
is introduced by this candidate contract.

## Future acceptance matrix — NOT EXECUTED

All rows below are future test requirements; there is no code/test change
or execution in this documentation task. The actual handler and the same
non-vacuous protected-state/outbound assertions should be used wherever
applicable. Any test-only omitted-guard invocation must be clearly isolated
from production reachability.

| ID | Actual-handler inputs / state | Required assertion if candidate is implemented | Sensitivity / evidence status |
|---|---|---|---|
| H1: bound non-self empty | Valid non-self origin/claimed binding, active baseline, recording facade | Generic inbound/other, binding accepted, received +1, proposed ignored +1; rejected unchanged; peer maximum, exit height, engine protected state and facade unchanged; helper not called | Actual-handler, **FUTURE / NOT EXECUTED** |
| H2: bound self empty | Authenticated local mapped origin and matching self label fixture; document production reachability limits | Receipt and ignored +1; no peer maximum or mode change, no engine/facade effect | Actual-handler fixture; do not claim remote peer can validly impersonate local mapping |
| H3: binding failures | Missing/unknown/ambiguous origin; authenticated non-self with self/mismatched/unknown claim | Generic observation + binding rejection only; received, ignored and non-empty rejected counters unchanged; no helper, mode, engine or facade effects | Include production-equivalent gate; test-only `binding_gate=None` is not production evidence |
| H4: reported height matrix | Bound non-self empty with `H=None`, below, equal, above local, and `u64::MAX`; stored maximum absent/lower/higher | For each, proposed ignored increments exactly once; prior maximum exactly preserved; no target poisoning or reduction; mode/engine/facade unchanged | Include H None with existing maximum, and repeated identical/lower/higher responses |
| H5: local/baseline matrix | Local height `None`, exactly baseline, below if constructible, and above baseline; active/inactive | No empty input clears or rearms mode, regardless of scalar exit predicate; local `None` covered as helper/state boundary where not constructible from production restore initialization | Distinguish active fresh-engine baseline from fixture-injected states |
| H6: repeats | Repeated bound empties before and after prior mode exit; self and non-self separately | Existing receipt and proposed ignored counts track each admitted frame; binding rejects do not accrue either; peer/max/mode/exit record remain byte-for-byte unchanged | No per-peer metric labels or unbounded logs |
| H7: irrelevant request fields | Empty response with mismatched height/ID and no outstanding request | Same ignored behavior; explicitly assert there is no anchor/request correlation dependency in the proposed refusal | These facts are not a bypass |
| H8: old-behavior positive control | Isolated test-only omitted-guard control drives existing helper with active non-self empty and a state meeting strict-progress/stored-maximum predicates | Same protected-state/facade oracle must detect old peer tracking/mode-only exit; this is sensitivity evidence, never accepted behavior | Must not mutate production or turn fixture into production reachability |
| H9: guard omission/misplacement | Test-only build/dispatch control omits or places proposed empty guard after helper/evaluation | Same assertions fail specifically on changed max/mode; nonempty existing guard remains separately checked | Non-vacuous detection for omission and after-effect placement |
| H10: A17 non-empty preservation | Bound non-empty with self/non-self, matching/stale/mismatched request anchors, authority/config combinations | Existing A17 rejection remains after receipt and before helper; rejected increments once; engine/mode/peer/outbound state unchanged | Preserve exact accepted non-empty guard; honest non-empty liveness impact remains |
| D1: requests | Active/inactive ticks around cadence, committed anchor absent/present, facade absent/failing/successful | Active and anchor/facade/cadence controls request emission; ignored empty does not change mode or bypass gates; inactive stops fresh requests | No claim requests imply recovery |
| D2: proposals | Active/inactive, near/far height and parent, with/without current PV admission | Mode affects only existing deferral; authorization/domain/epoch/signer/journal/freshness checks remain distinct; leader-generated local engine effects are recorded before outbound refusal | Current production Required/no-current-PV refuses ordinary inbound PV before engine; test authorities must be explicit |
| D3: timeout | Active/inactive; configured/disabled threshold; facade; elapsed/no-progress boundary; signer/context/F7 prerequisites | Active suppression persists after ignored empty; inactive only removes that gate; all timing, timeout signer, identity/suite/backend, F7 and publication checks stay independently asserted | No timeout signing or participation claim from mode change |
| D4: independent progress and responder | Local leader progression isolated in a single-validator fixture; bound non-self empty input isolated in a validator set with admissible non-self origin | Demonstrate local leader state can progress independently and separately show bound responder handler behavior; do not combine one-validator local identity 0 with a purported bound nonself peer, impossible under its configured membership map | Characterization only; no live/network experiment |

For every future row, record exact source revision, command, full output,
exit status, changed paths and hashes; separate existing accepted test
evidence, author reports, newly executed cases and still-unexecuted rows.
Do not rerun unrelated accepted suites.

## Contract assumptions and unresolved questions

* The candidate applies only to actual successfully bound empty response
  dispatch. If binding is absent/fails, existing fail-closed binding logic
  remains authoritative; this contract adds no fallback.
* The existing non-empty guard is preserved byte-for-byte by this
  documentation-only task. Candidate implementation must not move,
  weaken, bypass, or double-count it.
* `restore_catchup_empty_responses_ignored_total` is a proposed name and
  semantics, not an existing metric or promised API. Independent review may
  select another bounded counter name, but must preserve stage separation
  and single increment semantics.
* External empty-response generation, actual deployment settings, a
  progressed multi-validator production history, availability change,
  signer exclusivity and durable quarantine remain unresolved here.
  Evidence requires separately pinned implementation/configuration and
  independent actual-handler/downstream controls; this task performs no
  node/network experiment.
* The previously accepted local/progress fixtures are fixture states, not
  a proof that a bound non-self empty responder can coexist with a
  progressed instance under current binary production wiring.

## Integrity and scope

This is a new addendum rather than an edit to the accepted investigation
README, prior path list, prior checksum manifest, prior diagnostics, A17
evidence, or audit register. The append-only plan receives a separate
section. `CHANGED_PATHS.txt` lists only this contract delivery.
`SHA256SUMS` pins those paths and records the unchanged accepted artifacts'
historical hashes against their producing commit; it excludes itself.
`documentation-checks.log` records exact commands/results and
historical-byte verification. No Rust tests, build, production code,
configuration, keys, node, network experiment, activation, merge or PR is
part of this task.
