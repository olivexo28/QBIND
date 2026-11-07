# Quorum-to-content binding options and first test slice

**BINDING OPTIONS AND TEST SLICE — INDEPENDENT REVIEW PENDING.**

```text
SOURCE_MAIN=9bf0eb43e4e3c601d02d3886d220b0abeb3a103e
PRIOR_ANALYSIS=6ba38e9fa66f216e45906b3eb0575d67aa0cd071
DECISION=OPTIONS B AND C UNSELECTED
IMPLEMENTATION=NONE
PRODUCTION_CALLER=NONE
DATA_APPLICATION_OR_RESUME_AUTHORITY=NONE
A17-F1 / RS1-F7=OPEN
RS1=OPEN
A33-F1 / E27=OPEN
ACTIVATION=DISABLED
PUBLIC_DEVNET=NO-GO
```

The user supplied **PASS WITH LIMITATIONS** for the quorum-to-content
analysis at `6ba38e9f`. That disposition is carried forward for its documented
scope only; it does not select B or C, approve a cryptographic construction,
or grant authority. AP1 and its document-source navigation follow-up remain
**PASSED / CLOSED** within their documented scope. Earlier bounded
acceptances and inventory corrections are preserved. No reviewer identity
or unavailable raw review artifact is asserted.

This comparison is an append-only design record based on source pinned to
protected main `9bf0eb43e4e3c601d02d3886d220b0abeb3a103e`. It proposes no
wire encoding, digest algorithm, activation or operational procedure. The
source-backed signed-field inventory and prior G/P/B analysis remain in the
[quorum-to-content analysis](QUORUM_CONTENT_BINDING_ANALYSIS.md).

## 1. Decision summary

| Route | What it could establish | Safety and availability | Decision state |
|---|---|---|---|
| **A. Continue fail-closed refusal** | Nothing new: current recovery dispatch does not admit a non-empty catch-up response; an authenticated empty response is ignored before peer-height/mode effects ([current dispatch](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L7398-L7440)). | Preserves refusal when evidence cannot establish the required binding. Availability cost is indefinite restore/refusal and possible inability to catch up. Restore mode is not a complete engine, worker or signer fence; do not describe A as a complete containment mechanism. Low new protocol/storage complexity; no claim that currentness or recovery is established. | Existing fail-closed direction; preserve it unless a separately reviewed path is approved. |
| **B. Future consensus version, quorum votes bind content** | A QC under the new reviewed version could authenticate validators' agreement to a particular complete content-and-parent statement, subject to the statement semantics, authority and protocol fault assumptions below. It would be a consensus attestation, not just a proposer statement. | Best direct alignment between vote quorum, block content and the consensus decision, but requires coordinated protocol, signer, evidence-retention and compatibility changes. Historical votes do not contain the new statement. Unknown implementation, bandwidth, storage, verification and rollout costs. | **Unselected.** Requires consensus and signer owners plus independent protocol/security review. |
| **C. Separately purposed quorum recovery attestations** | A separate quorum might attest to a specifically defined recovery claim about an archived prefix. It would prove only the recovery-purpose statement under its independently authorized rule; it is not an original consensus vote or automatically proof of original consensus finality. | Can avoid changing consensus vote meaning, but adds a second signing purpose, authority, conflict/anti-equivocation state, evidence association and operational workflow. More complex authorization and stale-state risks; unknown resource and coordination costs. Existing old votes alone are not sufficient input. | **Unselected.** Requires an explicit recovery-attestation authority and review that its claim is adequate for the intended recovery scope. |

No route grants durable application, global currentness, rollback
resistance, ownership, signing-history continuity, exclusive signer
fencing, quarantine clearance or participation/resume authority. Those remain
separate decisions after evidence verification.

## 2. Attested statement and signer obligations

The following is a field inventory for independent review, not a byte layout
or construction. A future signed statement for either B or C must identify,
unambiguously:

* **Network and authority:** full runtime chain identity, expected wire
  chain identity and genesis identity; epoch; the exact authorized validator
  set/key/weight commitment and the independently trusted source/version of
  that authority.
* **Object and position:** consensus height, view/round and step as
  applicable; complete parent identity (not a truncated prefix); block or
  prefix association; content-commitment value plus explicit commitment
  algorithm/format identifier; and the full application-relevant content
  whose commitment is being asserted.
* **Purpose and versions:** non-confusable message purpose (consensus vote
  for B versus recovery attestation for C), signing-domain version,
  statement/schema version, protocol version and commitment version. No
  fallback across unsupported versions or purposes.
* **Recovery-specific scope for C:** exact trusted anchor identity, start and
  claimed committed endpoint, the evidence/coverage rule being attested,
  and the distinction between committed blocks and supporting descendants.
  The statement cannot use an endpoint label to silently promote P/B into
  committed state.

Before signing, validators would need a reviewed rule to resolve the
independently trusted chain, epoch and authority; validate the full parent and
the application-relevant content against the commitment; check position,
epoch transitions and the applicable G/P/B relationship and per-block
coverage; and reject ambiguous or incomplete evidence. For C they must also
know exactly whether they are attesting to (i) correspondence of archived
bytes to a newly validated commitment, (ii) an independently authorized
recovery checkpoint, or (iii) a proposed substitute for missing historical
finality evidence. These claims are not interchangeable. C cannot silently
assert (iii) merely because the same validators can sign a message today.

Each route needs a purpose- and authority-aware anti-equivocation rule. For
B, a validator must refuse conflicting content/parent commitments at the
same protocol signing position under the new protocol rules, with a durable,
exclusive signing reservation that survives restart and cannot be bypassed
through another signer path. For C, a separately scoped signing journal must
refuse conflicting recovery statements for the same defined anchor/range/
authority and specify how overlapping ranges, revised evidence and new
authority epochs are handled. It must not reuse or weaken the consensus lock
semantics. The exact keys, conflict scope, durable reservation protocol and
recovery after uncertain writes require review; this document does not claim
that a current signer enforces either proposed rule.

Quorum verification must authenticate each distinct signer under the
independently supplied authority, count only authorized weight once with
checked arithmetic, and apply a reviewed threshold. The existing wire-QC
verifier checks a `ceil(2W/3)` threshold and verifies each declared signature,
but that implementation fact alone does not establish a fault theorem for
either new purpose. Review must define the maximum Byzantine voting weight,
quorum intersection (including equality/rounding behavior), honest signer
locking and availability assumptions, key/backend validity, and how authority
changes preserve those assumptions. Transport identity, a bitmap, or a list
of validator indices is not independent endorsement proof.

### Source precision: Proposal, outbound helper and inbound verifier

`BlockProposal::canonical_body()` excludes the Proposal's **own** signature.
It serializes the embedded QC as bytes, including that QC's constituent
signature bytes, and then includes the other canonical proposal fields and
transactions ([body assembly](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/consensus.rs#L915-L954);
[QC encoder](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/consensus.rs#L300-L332)).
This says what the proposer body encodes; it does not mean the QC's signers
signed the proposal body or its content.

Also distinguish two v2 operations:

1. The outbound `ProposalVoteAuthority::{proposal_preimage,vote_preimage}`
   helpers build a preimage from the trusted signing domain and message body
   ([helpers](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L1113-L1120);
   outbound proposal and vote use in guarded signing
   [proposal](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L4718-L4742),
   [vote](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L5145-L5170)).
2. Inbound Proposal/Vote paths call the domain-verifier entrypoints, which
   recompute the preimage from the received message and selected trusted
   domain rather than accepting an outbound helper's supplied preimage
   ([inbound Proposal](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L6352-L6370),
   [inbound Vote](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L6824-L6840)).

These are related uses of the same versioned domain, not the same call or
proof that future signer-side validation will enforce a new content-binding
rule. The previous analysis details Vote fields, domain assumptions and QC
verification. No changed rule is present in this documentation task.

## 3. Option-by-option design comparison

| Consideration | A. Continued refusal | B. Consensus-version content-bound quorum | C. Separate recovery-purpose quorum |
|---|---|---|---|
| **G/P/B and committed coverage** | No recovered prefix is accepted. | Each QC must bind the full statement/content for its exact block. Apply the reviewed three-chain rule: G is committed when required own-QCs, parent links, increasing views and monotonicity hold; P and B are supporting descendants. To claim a multi-block prefix, provide per-block evidence or a separately reviewed coverage proof; do not equate newest QC with finalized tip. | Attestation must name the exact committed endpoint and supporting roles, and bind to the consensus evidence used for every claimed committed block. A new recovery-purpose quorum is not by itself a consensus G/P/B proof. It can substitute for unavailable historical evidence only if a separately authorized and reviewed recovery policy explicitly says so and accepts its trust model. |
| **Historical blocks** | No historical catch-up through the refused path. | Not retroactive: old Vote signatures did not attest a newly introduced full-parent/content commitment. Historical use needs actual independently authenticated historical evidence that already binds the exact content, or a separately authorized historical attestation/checkpoint; do not infer it from stored bytes, logical signer IDs or current B signatures. | Can speak about historical bytes only if current/authorized attesters actually inspect and sign the precise historical claim. That creates a new recovery-purpose statement, not an old consensus vote. If it is to stand in for missing finality evidence, authority must explicitly authorize that scope and rationale. |
| **Consensus and signer changes** | None for this route; maintain refusal. Keep its known containment limits visible. | New versioned vote statement/domain, compatible vote/QC verification, proposal/block identity and content association, validator pre-sign validation, conflict/anti-equivocation semantics, and reviewed behavior across every signing route. Ensure protocol logic cannot form a QC over a different or incomplete statement. | New purpose-specific statement/domain and verifier, distinct validator authorization, signer admission and conflict journal, governance/operational authorization, and a reviewed link to historical consensus evidence. It must not be a backdoor around consensus locks or current signing guards. |
| **Wire, storage, upgrade and compatibility** | No new evidence format; existing non-empty recovery response remains refused. | Versioned wire and canonical representation; retained/retrievable signatures and content commitments for each relevant block; migration/activation boundary, mixed-version and downgrade behavior, storage schema, crash/restart behavior, archival and release compatibility. Old nodes must not silently interpret new vote semantics as old. | Versioned recovery message and archival evidence store; explicit signer-purpose policy and durable log; old/new verifier, archival and revocation behavior; clear separation of attestation validity from consensus-vote compatibility. Existing QCs remain separately checked evidence. |
| **Safety, availability and operations** | Strongest refusal posture but potentially indefinite unavailability; restore mode alone is not a complete fence. | Directest match of quorum vote with block content if all signers enforce the reviewed rule. Requires validator upgrades and quorum availability under the new version; mixed versions may halt or refuse. Operational rollout, evidence retention and monitoring costs are unknown. | May allow an independently authorized recovery attestation while keeping consensus signatures unchanged, but introduces a second authority and signing workflow, additional coordination and risk of stale or mis-scoped attestation. Availability depends on recovery quorum and evidence access; costs are unknown. |
| **Failure handling** | Missing, non-empty unverified, unsupported or malformed evidence remains refused; no automatic resume. | Missing content, unsupported version/domain, wrong chain/epoch/authority, conflicting vote, unauthorized/duplicate signer, insufficient quorum, invalid G/P/B or excessive input refuses before application. Conflicting signer outcome or uncertain journal state remains closed and requires reconciliation, not assumed rollback. | Missing historical signatures/content, ambiguous scope, expired or stale authority, conflicting attestation, wrong purpose, failed quorum or excessive input refuses. An uncertain attestation write is not treated as absent or safely retryable without journal reconciliation. No approval or signature alone clears quarantine. |

All implementation, performance, memory, bandwidth, durable-storage,
coordination and upgrade costs for B and C are **unknown**. Do not convert the
earlier unvalidated witness ceilings/deadline into runtime guarantees.
Resource admission would need hard limits before frame allocation and before
nested decode, content materialization, signature copies and crypto work.
Counts, cumulative bytes, decoded capacity, concurrent work and arithmetic
overflow need independent, enforceable bounds; the existing outbound setting
or a fixed latch is not an inbound or complete-evidence bound.

### Historical recovery authority is not implicit

An alternate historical route is reviewable only if it names: (1) the
independent trust authority and how that authority is itself authenticated;
(2) the chain, epoch(s), anchor, exact content and committed endpoint in
scope; (3) whether it asserts historical consensus finality or only an
authority-approved recovery checkpoint; (4) how currentness and rollback are
handled, including any external freshness/monotonicity assumption; and (5)
what happens on absent, conflicting, stale, revoked, unavailable or oversized
evidence. A signed checkpoint proves only its signed statement, not that no
newer authorized state exists. Founder/bootstrap approval, if any were ever
separately specified, cannot silently become consensus finality, signer
override, currentness proof, quarantine-clear authority or resume decision.
No such external authority or currentness mechanism is asserted to exist.

## 4. Recommended first test-only investigation

**Recommendation:** first perform a test-only signed-artifact sensitivity
investigation of the existing v2 Proposal and QC paths, before prototyping B
or C. Its purpose is to make the exact gap and the distinct historical
limitations measurable without choosing a new statement format or proving a
new recovery mechanism.

Bound the future test fixture to one trusted anchor, one epoch and authority,
three G/P/B roles, four equal-weight synthetic validators, and at most
16 KiB total fixture input. Three of the four fixture validators is the
existing `ceil(2W/3)` arithmetic for that artificial fixture only; it is not
a production fault-model recommendation or safety proof. Use test-only keys
and in-memory data. Do not use network, production signer keys, a production
caller, recovery stores or application APIs.

**Measurable acceptance cases — FUTURE / NOT EXECUTED:**

1. A valid original Proposal verifies with its own signature excluded from
   its body, while its embedded QC signature bytes are present in the
   canonical body; changing the Proposal's parent, content or embedded QC
   invalidates that Proposal signature.
2. A valid existing QC verifies each included Vote and its exact signed Vote
   fields. Changing a signed field such as the vote block ID/domain/epoch
   fails verification; changing only externally associated proposal content
   does not add a content check to that QC verifier.
3. Keep the existing derived block ID and QC fixed while supplying
   substituted full parent/content. The fixture demonstrates that the QC
   result alone cannot authenticate that association, without asserting a
   collision or exploit. The Proposal signature check remains an independent
   check, not a quorum-content proof.
4. An inbound verifier case recomputes from the received message and trusted
   domain; an outbound preimage-helper case is separately observed. Tests
   must not treat one path as proof that the other path or future signer
   admission enforces new rules.
5. Three-block cases distinguish committed G from supporting P/B and reject
   missing QC, wrong parent/view, unsupported epoch transition, duplicate or
   unauthorized signer and insufficient weight. No result may authorize
   application, clear or resume.
6. Bounded malformed/oversized fixtures refuse at documented pre-allocation
   or pre-crypto limits. A side-effect oracle confirms this investigation has
   no production caller, data writes, network effects, signer authority or
   quarantine/resume path.

The investigation succeeds only if a reviewer can reproduce each expected
result with the pinned existing verifier semantics, identify any mismatch
between the source-backed claim and test behavior, and observe zero protected
effects. Failure or ambiguity keeps A in force and blocks a B/C prototype.
These cases are proposed, not run; this task runs no Rust tests or builds.

## 5. Decisions required before implementation or activation

Before any B/C production implementation, the responsible owners must decide
the statement semantics and protocol boundary; content/parent and execution
validation rules; exact G/P/B-to-prefix coverage; historical evidence or
checkpoint authority; chain/epoch transition policy; signer anti-equivocation,
durability and exclusive ownership/fencing; evidence retention and bounded
parsing; wire compatibility, upgrade and downgrade handling; failure/
uncertain-outcome reconciliation; and the separate currentness and resume
authorities. Independent reviewers must assess the consensus fault model,
quorum intersection, cryptographic/domain separation, historical claim,
resource bounds, actual caller and release/multi-node evidence. Owner roles
and reviewer identities have not been supplied here.

Successful verification, a current marker or a mode change cannot itself
establish global currentness, rollback resistance, durable ownership,
signing-history continuity, exclusive signer control, application success,
quarantine clearance or permission to resume. Preserve present containment;
any later application attempt must retain known effects and Unknown outcomes
and remain closed until separately reconciled and authorized.
