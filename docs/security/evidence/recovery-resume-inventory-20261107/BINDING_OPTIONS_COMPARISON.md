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

<a id="test-plan-correction"></a>

## 6. Superseding test-plan correction

**TEST-PLAN CORRECTION — INDEPENDENT REVIEW PENDING.**

The user supplied **PASS WITH LIMITATIONS** for the options comparison and
**CHANGES REQUIRED** for its proposed test plan. This section supersedes
section 4's 16 KiB fixture cap and incomplete attribution of acceptance
checks, not the accepted options analysis. AP1, I1, W1/W2 and all earlier
bounded acceptances are preserved within their prior documented scopes.
No reviewer identity or unavailable raw artifact is asserted. B and C remain
unselected; current refusal remains in force. Every case below is
**FUTURE / NOT EXECUTED**. No scaffolding described here has been implemented.

### 6.1. Split fixture profiles and byte accounting

**R: real-signature, positive/small-mutation profile.** Proposed backend:
`qbind_crypto::ml_dsa44::MlDsa44Backend` registered under suite 100, using
four synthetic equal-weight validators, one trusted epoch/domain/anchor,
three own-QCs associated with G/P/B, three distinct signatures per QC, and
one separately signed Proposal for the proposer-body tests. Existing
test-only key and QC construction provides prior art, not execution evidence
for this plan ([real fixture construction](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L1160-L1275)).
A counting test adapter must **delegate** signature verification to the real
backend, not return fake success. Test signatures and keys are not
operational signing or a prototype B/C attestation.

The source constants are 2,420 bytes per ML-DSA-44 signature, 1,312 per public
key, and 2,560 per serialized secret key
([sizes](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-crypto/src/ml_dsa44.rs#L36-L43)).
Thus **3 QCs x 3 signatures x 2,420 = 21,780 signature bytes before other
data**. The old 16 KiB cap cannot hold even those signatures.

For this particular artificial R fixture, the proposed **encoded fixture
segment budget is 65,536 bytes (64 KiB)**. This is not a selected network
format: it accounts for existing encoded QCs, one canonical Proposal body,
its own detached signature and at most 512 bytes of test-only segment
framing/graph metadata. With validator indices 0..3, a one-byte bitmap and
exactly three signatures:

| Encoded segment | Accounted bytes | Scope |
|---|---:|---|
| Three QCs | 3 x 7,336 = 22,008 | Each: 65 fixed bytes, 2-byte bitmap length + 1 bitmap byte, 2-byte signature count, and 3 x (2-byte length + 2,420 signature). Includes all nine signatures and QC framing. |
| One Proposal canonical body | 7,750 | 150 header bytes + 4-byte embedded-QC length + one 7,336-byte QC + one 4-byte transaction length + at most 256 transaction bytes. The QC is a **duplicate** of one separately supplied QC; its signatures count again. |
| Proposal's own detached signature | 2,420 | Excluded from canonical body, included in the fixture input budget. |
| Test-only segment framing / graph metadata | At most 512 | Includes segment lengths and G/P/B association metadata; any excess rejects this profile, rather than silently being outside the budget. |
| **Total fixture segments** | **At most 32,690** | Below 65,536; spare bytes are not permission to add unbounded content, certificates or validators. |

QC field arithmetic follows the
[encoder](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/consensus.rs#L304-L327);
Proposal arithmetic follows the
[canonical body](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/consensus.rs#L915-L954).
The future harness must assert actual segment lengths and total, not simply
assume this arithmetic matches its generated fixture.

**Decoded, retained and working-memory accounting is separate.** The
64 KiB figure covers encoded segments only, not the following:

* Input `Vec` lengths/capacities and their container/object metadata; decoded
  QCs (outer `Vec<Vec<u8>>` and each signature/bitmap capacity), Proposal
  transaction/signature capacities, and graph/scaffolding structures. Record
  these at actual entrypoints; do not equate `len()` with allocated capacity.
* Four trusted public keys contain 5,248 serialized bytes; four setup secret
  keys contain 10,240 serialized bytes. These are trusted fixture setup, not
  encoded peer input. Count provider storage, provider-returned key clones,
  allocator slack, key objects and setup/keygen working memory separately.
  Do not treat serialized key sizes as backend object/stack sizes.
* If encoded input, decoded evidence and verified output coexist, count each
  simultaneously. The owning QC verifier clones the certificate on success
  ([owning result](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L877-L912)).
  Retaining all three results duplicates another 21,780 signature bytes plus
  bitmap/container/domain/signer metadata. Drop each result before the next
  case unless explicitly measuring that duplicate-retention scenario.
* Measure peak simultaneously live vector **capacities**, outer vector
  storage, inline structures, provider clones, temporary embedded-QC
  encoding, canonical/preimage buffers, reconstructed Vote signature clones
  and backend working memory. Setup and execution peaks are separate.
  Backend heap/stack and allocator overhead need independent instrumentation.

A total decoded/retained/process-memory cap remains **UNSELECTED / NOT
JUSTIFIED** until that inventory is measured for the target build and
allocator. The proposed encoded cap is feasible for the enumerated byte
segments, not proof that the entire process fits within it. No runtime,
deadline, cancellation or network-admission guarantee follows.

**D: split decoded negative profile.** This intentionally bypasses
R's admitted encoded shape to test the existing verifier *after fixture
allocation*. It has one QC and at most four signatures, subject to the
byte-vector-length cap below. One QC with a 65,536-byte signature, two 2,420-byte signatures
and a one-byte bitmap has 70,377 decoded byte-vector payload bytes. A
proposed 131,072-byte (128 KiB) **sum-of-byte-vector-lengths** fixture cap is
feasible for that single case; it excludes keys, capacities, outer/inline
objects and working memory, which remain separately measured/unselected.
Do not call this a valid encoded QC: that signature cannot fit a u16 wire
length. Do not canonical-encode it through panic-prone length helpers.
It exercises decoded preflight, not pre-input-allocation enforcement.
Duplicate entries and invalid extra fourth signatures also use D, not the
three-signature R admission shape; distinguish preflight refusal from
crypto-loop failure when extra signatures are structurally well formed.

**S: proposed test-only pre-materialization / streaming-source profile.**
An unimplemented `test_admit_fixture_segments` helper would first receive a
fixed-size announced-length descriptor and a test source whose payload
materialization callback has not been invoked. It would reject length
greater than 65,536 or checked-sum overflow before that callback. A separate
borrowed-segment scanner would inspect complete bounded segment headers and
nested counts/lengths before calling any decode/materialization callback.
For that scanner the borrowed input already exists; zero decoder allocations
does **not** mean zero prior input allocations. Scanner bounds, truncation
and exact-byte consumption must be specified and tested before using it.
For R admission its proposed finite shape is at most six segments (three
QCs, one Proposal body, one detached signature and metadata), three signatures
per QC, one bitmap byte, 2,420 bytes per signature, one embedded QC and one
transaction of at most 256 bytes. Checked sums must cover duplicate embedded
material and segment framing. D is a separate intentionally allocated
preflight case, not an exception that S silently admits.
Neither helper is an existing production ingress or a claim that a streaming
QC verifier exists. Production pre-network/input-allocation admission is
**unresolved** and outside this slice.

**M: structural mock profile.** Proposed `test_check_gpb_associations`
scaffolding may use tiny labeled graph objects and a set of certificate IDs
already verified by R. It does no signature verification and cannot create
`VerifiedQuorumCertificate` values or recovery authority. It records only
graph/coverage predicate outcomes. A fake signature backend is not used for
cryptographic positive cases; structural M results cannot be reported as
real-signature, existing-engine or production-verifier enforcement.
M is limited to three fixed-field role records, one baseline/anchor and
three certificate summaries in one epoch, with zero crypto calls and no
multi-block prefix coverage. No variable-size content is copied into the
graph model; it borrows R's bounded fixture content and explicit test oracle.
Its objects/capacities still belong in the separate decoded/retained-memory
inventory; no total-memory cap is asserted for M.

### 6.2. Entrypoints, already-allocated state and exact observables

The actual existing QC entrypoint is
`qbind_consensus::verify_quorum_certificate_with_domain`. It receives
`&WireQuorumCertificate` with **already allocated** bitmap/signature vectors.
Its preflight checks structure and size before the cryptographic loop and
signature cloning; it then verifies constituent Votes, uniqueness through
bitmap association, membership and weighted quorum. It does **not** receive
the G/P/B graph, full parent/content, or raw input before allocation
([contract](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L849-L877),
[preflight](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L995-L1057),
[crypto and quorum](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L1059-L1120)).
No production rejection counter is required to observe this function:
assert its typed return and a proposed test adapter's backend-call count.

The following rows replace section 4's six grouped acceptance cases. Every
row is **FUTURE / NOT EXECUTED**; `test_*` names below are **proposed
test-only scaffolding**, not current source functions.

| Case / profile | Entrypoint and input state | Checker and observable | Sensitivity control |
|---|---|---|---|
| Proposal body/signature / R | Existing `BlockProposal::canonical_body` and `verify_proposal_msg_with_domain`; fully decoded Proposal, embedded QC and transactions already allocated; signature generated over original v2 preimage. | Canonical body includes embedded QC signatures but excludes its own signature. Existing Proposal verifier returns `Ok(())` for original, signature failure for changed parent, transaction or embedded-QC signature with original own signature. It verifies proposer authentication, not quorum-content agreement. | Change own signature only: body unchanged, verification fails. Change embedded-QC signature: body changes, old proposer signature fails; restore original for passing control. |
| Valid QCs and insufficient weight / R | Existing `verify_quorum_certificate_with_domain` on each allocated G/P/B QC; trusted domain, epoch, set, provider and real registry. | `Ok(VerifiedQuorumCertificate)` for three distinct equal-weight signers; `verified_voting_power()==3`, `threshold()==3`, `signers().len()==3`; three backend invocations per QC. Consistent two-signer QC yields `InsufficientVotingPower { have: 2, need: 3 }` after two verifies. | Restore third authorized valid signature and bit: pass; in separate D add an invalid extra fourth signature: fail even though three good signatures already reach quorum. |
| Signed Vote fields / R | Existing QC verifier, allocated QC, signature list retained from original; mutate block ID or height/round/step, not signatures. | QC reconstruction plus real signature check returns `InvalidSignature` for first affected authorized signer. Standalone `verify_vote_msg_with_domain` similarly recomputes from allocated Vote. | Restore original signed fields: pass; alteration must not be tested against an old caller-supplied preimage. |
| Chain/epoch/domain / R | Existing QC verifier on allocated QC. Mismatch wire chain or supplied authorized epoch; separately change trusted genesis/authority/runtime domain while keeping wire chain/epoch matching. | Chain mismatch gives `WireChainMismatch`, epoch mismatch `EpochMismatch`, with zero backend calls. Changed signing domain gives signature failure after invocation. These outcomes are not graph or currentness checks. | Restore expected chain/epoch/domain for positive control. Test purpose/version sensitivity separately on existing domain-built preimages; future B/C purpose parsing remains unresolved, not credited to current QC parser. |
| Signer structure / R + D | Existing QC verifier; allocated bitmap/signatures. In D duplicate a signature entry without a corresponding distinct bit; for the unauthorized R case use a separate four-member sparse set {0,1,3,4}, a one-byte bitmap with unauthorized bit 2 within its span, matching signature count and controlled provider. | Duplicate entry gives `SignatureCountMismatch` before backend calls. Unknown membership is rejected through existing membership verification; assert `UnknownSigner` using controlled provider/configuration, not transport identity. | Restore valid bit/count/membership; swapping a second signer's signature while keeping bit count constant must yield signature failure, not a second weight credit. |
| QC versus full-parent/content association / R + M | Existing QC verifier gets original allocated QC only; proposed `test_check_gpb_associations` gets separate allocated full-parent/content objects, role positions, verified certificate summaries and explicit trusted expected associations. | Existing QC still verifies if only external parent/content changes. Proposed scaffold must return `ParentAssociationMismatch` or `ContentAssociationMismatch` against the explicit **test oracle**. The oracle is not authenticated historical binding and is not a recovery proof. | Change parent suffix / transaction while retaining derived ID and QC: QC remains valid, oracle rejects. Restore matching oracle data: scaffold passes. No collision/exploit assertion. |
| G/P/B and committed endpoint / M | Proposed `test_check_gpb_associations` receives allocated labeled graph, expected own-QC identities and trusted baseline; no engine application API is called. | Proposed `MissingOwnQc`, `ParentLinkMismatch`, `ViewsNotIncreasing`, `NonMonotonicEndpoint` or `UnprovenEndpoint`. Predicate is modeled on pinned `try_commit_with_qc`; current private mutating engine function is **not** executed or credited as proof. Only G is marked supported, not P/B; multi-block coverage is unresolved outside one G slice. | Remove each own-QC, swap parent, equalize adjacent views, claim B as committed, or lower baseline endpoint. Restore exact G/P/B for passing structural control. Any defect-disabled variant is test-only and must be caught by the assertions. |
| Unsupported epoch transition / M | Proposed scaffold gets allocated roles plus one independently trusted epoch; no transition authority is supplied. | Proposed `UnsupportedTransition`; existing QC verifier separately checks each QC's supplied authorized epoch but cannot validate a transition or inherit an old set. | Change P/B to another epoch: scaffold refuses; restore all roles to trusted epoch. Supplying arbitrary alternate epoch to existing QC verifier must not bypass scaffold policy. |
| Decoded pre-crypto size / D | Existing QC verifier after all D vectors have been deliberately allocated; one late signature length 65,536, bitmap/count otherwise coherent. | `MalformedSignature(offending_signer)` with zero counting-adapter backend calls. This is a pre-crypto/post-input-allocation result. | Move oversized signature to last signer: still zero calls. Restore 2,420-byte real signatures: invokes backend and passes. Length below structural max with invalid crypto is a distinct signature failure, not a preflight-size claim. |
| Before payload materialization / S | Proposed `test_admit_fixture_segments` gets only announced lengths and uninvoked payload callback. Separate proposed scanner gets already-existing borrowed encoded segments but no decoded vectors. | Proposed `EncodedBudgetExceeded`, `LengthOverflow`, `TruncatedSegment` or `NestedLengthExceeded`; assert zero payload callback calls for announced oversize/overflow and zero decoder/materializer calls for nested invalidity. Neither is current QC enforcement. | Announce 65,537 bytes or checked-add overflow: reject; 65,536 passes only the length gate, not structure verification or unsupported padding. Enumerated valid R segments are admitted through both gates. Disable the helper in a test-only mutant and verify materialization counter becomes nonzero / negative test fails. Scanner case truncates nested lengths while total frame stays within cap. |
| Outbound/inbound distinction / R | Existing `ProposalVoteSigningDomainV2::{proposal_preimage,vote_preimage}` helpers, allocated messages; separate `verify_proposal_msg_with_domain` / `verify_vote_msg_with_domain` calls recompute from actual received message and trusted domain. | Compare captured helper bytes; assert real inbound verifier accepts originals and refuses post-signature mutation. No `ProposalVoteAuthority` production signer caller is wired, and helper byte construction is not signer admission. | Hold captured preimage fixed while mutating received message: inbound must fail. Passing a stale preimage to the public inbound API is not an available interface. |
| Isolation / all | Proposed test runner references only the stated existing pure verification/encoding APIs and test-only scaffolds; no node dispatch, persistent stores, network, production signer or resume APIs. | Source/compile reachability check and proposed effect-oracle counters for application/write/network/signing-authority/clear/resume remain zero. Synthetic fixture signature generation is explicitly separated setup, not participation. | A test-only sentinel attempted-effect adapter increments an oracle and must fail isolation assertion; do not connect a real protected API to create that control. |

Return labels for scaffolding are proposed assertion names, not repository
error variants. Existing typed labels must be confirmed against the pinned
error enum when future tests are authored. Proposed backend-call counters
must be observed directly; they are not production telemetry.
The existing
[QC error enum](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L206-L328),
[Proposal verifier](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/proposal_vote_verify.rs#L405-L433)
and [Vote verifier](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/proposal_vote_verify.rs#L511-L540)
support the stated separation of decoded message verification from graph
and pre-materialization scaffolding.
Graph model predicates are based on the
[current private three-chain function](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/hotstuff_state_engine.rs#L1819-L1938);
their model acceptance does not demonstrate the production caller, quorum
content correspondence or full prefix verification. Current wire decoding
already materializes signature vectors
([decoder](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/consensus.rs#L330-L358)).

This correction makes the investigation boundaries reviewable; it does not
complete them or approve implementation. Verification remains separate from
durable application, currentness, ownership, signing-history continuity,
signer exclusivity, quarantine clearance and resume. Unknown or missing
evidence retains refusal. No source/tests, checker, format or authority have
been added; activation remains DISABLED and public DevNet remains NO-GO.
