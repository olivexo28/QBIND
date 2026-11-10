# Engine-produced finalized-input handoff: specification and feasibility

## Status, scope, and provenance

**DOCUMENTATION ONLY — INDEPENDENT REVIEW REQUIRED.** This is a candidate
specification and feasibility assessment. It authorizes no implementation,
experiment, migration, startup, integration, signing, recovery, activation, or
DevNet action. Every proposed control and validation is **FUTURE / NOT
AUTHORIZED / NOT EXECUTED**. The implementation-grade cursor use-proof remains
**OPEN / BLOCKED**.

**OWNER DECISION (specification / feasibility only):** investigate an
engine-produced finalized-input record as the PRIMARY candidate for execution
handoff. A separately authenticated external finality artifact remains an
explicit **UNSELECTED** alternative. This does not select a key, trust root,
cryptographic construction, storage format, lag policy, or recovery authority.
The owner decision does not establish an available production consensus
signing authority or authorize bypassing its separate approval.

**Pinned source:** `main` at
`aa382fa28b2d3e97e6203d47fa8231b5f2269741`; reviewed handoff-audit branch
`docs/cursor-nonentanglement-handoff-audit` at
`cdbe8b0fbe0b558e8040f1c07999880cfeb3741c`, tree
`3389f7840a68f8a533d31e090fb65f6b90d20418`, parent
`b559658a0042d4b495ad8c22fb50f08ef9dd7223`.

**Reviewed audit:** `docs/security/evidence/cursor-nonentanglement-source-use-path-audit-20261110.md`
at the pinned audit commit. It establishes the prior source inventory and
specific snapshot-to-consensus-baseline and snapshot-to-activation-height
channels. This document supplements, rather than replaces, that audit.

Use these labels precisely: **SOURCE FACT** is behavior observed at the pinned
source endpoint; **OWNER DECISION** is the scoped direction above; **CANDIDATE
REQUIREMENT** is a future proof obligation; **OPEN / BLOCKED** means the
necessary authority, implementation, policy, or evidence is not established.

## 1. Pinned source and authority map

| Source / route | Established behavior | Handoff limitation |
|---|---|---|
| `crates/qbind-wire/src/consensus.rs:890-958` | Proposal signing preimage binds the canonical header, `tx_count`, embedded QC bytes, and ordered length-prefixed transaction bytes. | This authenticates what a proposal signer signed if its signature is verified. It does not make the proposal finalized. Embedded QC bytes are not external finality evidence. |
| `crates/qbind-consensus/src/proposal_vote_verify.rs:405-540`; `crates/qbind-consensus/src/qc_verify_domain.rs:1-36,506-555,878-910` | Proposal/vote and QC verifier code exists. QC verification checks signatures/quorum relative to caller-supplied domain, epoch, validator set, keys, and backend. `VerifiedQuorumCertificate` is explicitly non-authorizing and establishes no persistent freshness. | An available verifier is not proof that trusted inputs are official/current or that a production verification authority is active. |
| `crates/qbind-node/src/main.rs:6162-6172,8678-8705`; `crates/qbind-node/src/binary_consensus_loop.rs:736-786,3140-3180` | In the inspected Required production configuration, `proposal_vote_authority` is `None`; missing authority fails closed for inbound Proposal/Vote and suppresses outbound Proposal/Vote. | This is a route/configuration-specific observation, not a claim about every build or configuration. There is no adequate production handoff authority established here. |
| `crates/qbind-consensus/src/hotstuff_state_engine.rs:1780-1805,1819-1938` | The in-memory engine updates a lock on QC and commits the grandparent when three linked blocks have QCs and strictly increasing views. | The logical commit decision is not itself a durable, independently authenticated execution handoff record. Commit tip/log are in memory. |
| `crates/qbind-node/src/hotstuff_node_sim.rs:3030-3115,3205-3219`; `crates/qbind-node/src/storage.rs:815-840,874-898,929-959` | Simulator decodes proposal transactions in order but logs and skips malformed entries. It stores block, optional QC, and last-committed through separate calls. CRC is corruption detection, not authentication. | No exact-count reconciliation after skips is established. Separate calls do not establish atomicity across stores or with account state. |
| `crates/qbind-node/src/hotstuff_node_sim.rs:2080-2147` | Simulator restart reconstructs a logical lock from stored QC/embedded QC, treating the record as previously validated and omitting signer history. | This is not independent re-verification, currentness, rollback protection, or an execution-prefix proof. |
| `crates/qbind-node/src/execution_adapter.rs:165-207,445-475`; `crates/qbind-node/src/evm_commit.rs:323-365` | `QbindBlock` maps proposal `payload_hash` to its block ID and header height to view; `submit_block` is queue admission. The EVM bridge accepts `evm_txs` separately from the consensus block. | Neither height nor payload hash alone binds exact executed inputs. Queue admission is not execution completion. The separate EVM vector is not verified against the proposal in the inspected function. |
| `crates/qbind-consensus/src/basic_hotstuff_engine.rs:3875-3889` | The inspected `derive_block_id_from_header` uses proposer, view, and only the first 16 bytes of parent ID. | This is not interchangeable with `QbindBlock.block_id = payload_hash`; neither value by itself is a stable operation identity for the required unit. |
| `crates/qbind-node/src/main.rs:2888-2900,3012-3038`; reviewed audit §1 and §2 | Snapshot metadata height becomes `RestoreBaseline`; selected startup/CLI paths derive `ActivationContext.current_height` from that baseline. | These are actual indirect channels. Do not place the execution cursor in snapshot height, baseline height, or activation context. A cursor must not seed consensus restart, lock/view/finality, recovery, or activation. |

The inspected QC evidence and commit tip are in memory. In the inspected
Required configuration, Proposal/Vote authority is disabled as above. Do not
generalize either fact to every configuration or imply this document has
established another adequate production authority.

## 2. Candidate record and semantic subject

The candidate is an immutable **engine-produced finalized-input record** for
one engine decision. “Engine-produced” identifies its proposed producer, not
its trust: the execution side must treat the record and its origin as untrusted
until independent verification succeeds.

The represented decision must be the authoritative finalized subject under a
future reviewed finality rule—not merely a proposal, a QC, or the last observed
height. A QC authenticates a quorum statement relative to its trust inputs; the
engine's inspected 3-chain rule identifies when its in-memory state commits a
grandparent. A handoff must prove both the authenticated consensus evidence and
that the subject satisfies the applicable finalized-decision rule. A proposal
signature, QC-shaped object, in-process callback, matching digest, or engine
claim alone is insufficient.

The record is expected to carry or unambiguously reference:

- deployment/genesis, chain, state/backend namespace, and the authorized
  validator/ruleset context applicable to the decision;
- finalized subject, authoritative consensus position, and predecessor;
- exact authenticated canonical input bytes, ordered decoded transactions,
  declared count, and exact count/order actually passed to execution;
- a stable operation/commit identity derived from the semantic subject;
- proof material sufficient for execution-side independent authentication,
  finality verification, and applicable-context/currentness checks;
- the predecessor execution position and resulting execution position;
- the state and membership generation and the entitled completion fields.

The six identity-binding obligations remain **OPEN**:

1. **Finality:** proof the subject is finalized under the applicable rule.
2. **Exact executed inputs:** prove authenticated ordered bytes/count equal the
   exact sequence execution consumed.
3. **Position continuity:** prove predecessor and next positions are
   authoritative, current, and contiguous under the chosen policy.
4. **Deployment/backend association:** bind the decision and applied state to
   the intended deployment, genesis, and execution backend/state namespace.
5. **Authorized ruleset:** bind execution to the ruleset/schema authorized for
   that decision.
6. **Commit identity:** bind one stable operation identity to the decision,
   state/membership, exact inputs, acknowledgement, and every entitled outcome.

No height, payload hash, local worker counter, `last_committed`, snapshot
directory, matching balances, or queue response supplies these bindings.
Proposal block IDs and execution wrapper IDs also differ in the inspected
source; the reviewed semantic-subject mapping is **OPEN**.

## 3. Field, producer, verifier, and trust-source matrix

| Binding / field | Future producer | Independent execution-side check | Trust source / status |
|---|---|---|---|
| Deployment, genesis, chain, backend namespace | Consensus context plus execution backend association | Compare record to independently configured and authenticated deployment/backend identity; refuse mismatch or unavailable context. | Owner-selected trust root and demonstrated backend association are **OPEN**. |
| Authorized validator set, epoch, signing domain, ruleset | Consensus decision context | Reverify evidence using an immutable/current authorized context; prove the ruleset was applicable at the decision and at the required currentness boundary. | The existing verifier accepts caller-supplied inputs but does not establish their official origin/currentness. Production authority remains separately **OPEN / disabled** in the inspected Required route. |
| Finalized subject and position | Engine's finalized-decision path | Independently validate authenticated proposal/vote/QC evidence and the finality rule, including the subject and required links/predecessor. Do not accept origin or matching digest as proof. | Current QC verifier returns non-authorizing evidence; engine commit tip is in memory. Adequate production finality proof is **OPEN**. |
| Exact bytes, ordered transactions, and count | Authenticated proposal/input path | Recompute/validate canonical input commitment under the authorized rules; decode all entries strictly; compare declared count, decoded count, and exact executed vector/order/bytes. Reject malformed, skipped, trailing, missing, duplicated, reordered, or substituted inputs. | Proposal canonical body includes ordered bytes and `tx_count`, but the simulator skips malformed entries and EVM receives a separate vector. Equality with actual execution is **OPEN**. |
| Predecessor and position continuity | Engine history plus separately maintained execution position | Independently verify expected predecessor, currentness/freshness, and continuity; restart inspection must re-establish latest applicable history, not merely validity of a historical proof. | Existing `last_committed`, worker height, snapshots, or absent markers are not independent currentness/anti-rollback authority. **OPEN**. |
| Stable operation/commit identity | Candidate semantic-subject function, not evidence-byte hash alone | Recompute from the reviewed semantic subject and all six bindings; ensure proof representation does not alter identity when an approved equivalence policy says evidence is equivalent. | Mapping and policy are **OPEN**; no production identity is selected here. |
| Resulting account state and membership | Execution transaction over the chosen consistency unit | Verify the transaction's committed generation corresponds to the verified operation and exact input sequence; readback alone cannot manufacture success after uncertain commit. | Account values/membership, cursor, acknowledgements/outcomes span the actual separate stores today. Joint atomicity is not established. |
| Acknowledgement and entitled outcomes | Completion publisher inside the same reviewed commit unit | Retrieve only by stable operation identity after commit/currentness checks; distinguish committed block execution from per-transaction success. Unresolved fields stay unavailable or pending owner decision. | `submit_block` is queue admission only. EVM receipts/other transaction-outcome entitlements remain open. |

The record should include enough proof to independently verify the decision.
If that requires a new signature over the record, a new signing operation,
message domain, authority, provisioning route, or signer position, each is a
separate design and approval question. No such operation or authority is
selected or assumed here.

## 4. Candidate execution-side verification and commit sequence

1. **Receive, do not trust by origin.** Treat the record, its transport, and
   any engine-local provenance as untrusted. Missing record or proof means no
   cursor advance and no durable acknowledgement.
2. **Establish trusted expected context.** Obtain deployment/genesis, chain,
   authorized validator set/epoch/domain, ruleset and backend association from
   independently approved current sources. Their authority, lifecycle,
   first-use enrollment, mutation protection, and currentness are all
   **OPEN**. If unavailable, stale, conflicting, or inconsistent, refuse.
3. **Authenticate and establish finality.** Independently verify signatures
   and quorum against that expected context, then verify the applicable
   finalized-decision rule and links/predecessor. Proposal authentication,
   a valid QC alone, or in-memory engine acceptance is not finality. If a
   future record signature is needed, do not bypass its separate approval.
4. **Verify semantic subject and continuity.** Check deployment/backend,
   authorized ruleset, finalized position, predecessor and execution
   predecessor. Require evidence that this is the currently applicable
   history after restart. A valid historical proof without currentness is
   insufficient.
5. **Verify exact inputs before execution.** Strictly decode every authenticated
   input; reject malformed/trailing data, skipped items, count mismatch,
   omission, duplication, reordering, or substitution. Ensure the exact vector
   passed to execution equals the authenticated ordered vector. Any failure
   refuses before cursor advancement and durable state-dependent completion.
6. **Execute under future-reviewed fencing.** Execute exactly that vector in
   order under applicable rules against coherent account values and
   membership. Whether transaction-level failures can coexist with block
   commit and which outcomes are entitled remain policy matters; do not
   translate them into blanket transaction success.
7. **Commit one consistency unit.** The standing unit includes account values
   and membership; authenticated execution position; stable operation/commit
   identity; exact executed transaction order and count; acknowledgement; and
   every entitled outcome. The current separate account and consensus/position
   stores do not establish joint atomic commit. One-domain redesign or a
   justified cross-store protocol, fencing, durability, and crash recovery
   remain **OPEN / BLOCKED**. A batch or clean reopen is not proof.
8. **Acknowledge / retry.** Return an acknowledgement only when the complete
   unit and its currentness can be established. It means committed execution
   under applicable rules, not that every transaction succeeded. Retry looks
   up the same operation identity and returns the same committed result only
   after verification; unknown commit status is unavailable, never inferred
   from balances, later flush, queue admission, or blind re-execution.
9. **Restart inspection.** Preserve ordinary-access gates. Independently
   reverify the record/proof, expected context, currentness, continuity,
   fencing/ownership and consistency-unit association. A local persisted
   record or historical proof alone is not freshness, anti-rollback, recovery
   authority, or permission to resume service.

No candidate sequence above establishes an atomic primitive.

## 5. Proof representation and external alternative

### Proposal-embedded QC versus finality evidence

The proposal's canonical signed body includes its embedded QC bytes. This
proves only that the proposer signature covers those bytes, assuming the
proposal signature is verified under trusted inputs. QC verification then
checks the QC's constituent votes and quorum relative to separately supplied
trusted inputs. Neither fact alone proves that this is the applicable
finalized decision or current history.

The engine's in-memory 3-chain commit decision is a distinct step. No inspected
source establishes a durable, independently authenticated finalized-input
record consumable by execution. No external finality artifact route is
established either.

Under a future approved equivalence/reverification policy, alternative
policy-authorized proof representations for the same semantic decision must
not create conflicting operation identities solely because their bytes differ.
That requires exact semantic-subject mapping, complete re-verification,
equivalence rules, and currentness checks. Do not assume proof uniqueness,
equivalence, or a QBIND route accepting alternate proofs; all remain **OPEN**.

### Separately authenticated external artifact — UNSELECTED

An external artifact would need an independently approved issuing authority
and trust root, authentication/integrity construction, deployment/genesis and
backend association, authorized-ruleset binding, finalized subject and
predecessor continuity, exact input bytes/order/count, stable commit identity,
and currentness/revocation/rollback evidence. It must not override consensus
safety rules or claim finality from a QC-shaped payload alone. Its authority,
applicability, relationship to engine commit decisions, and full bindings are
**OPEN**. It remains unselected, not presumed safer, unnecessary, or available.

## 6. Native post-quantum requirement

Native post-quantum trust is a **FIXED** project requirement for the handoff's
authentication and integrity path. The future construction and complete trust
path must provide authenticated origin and message/context binding, integrity
of the semantic subject and all required fields, domain separation, and
verifiable key/authority lifecycle and currentness. It must remain valid under
the project's post-quantum threat model; no algorithm, key, suite, trust root,
provisioning scheme, or construction is selected here.

Identify every classical dependency in the full path—including any digest,
transport, trust bootstrap, metadata authentication, storage integrity,
provisioning, or fallback—as a separate isolation and owner-review item.
A post-quantum signature alone does not establish finality, authorized context,
exact execution, position continuity, backend association, atomic durability,
anti-rollback, or recovery. Actual construction, trust roots, and demonstrated
security remain **OPEN**.

## 7. Failures, restart, and unknown outcomes

| Condition | Required candidate result |
|---|---|
| Missing authority, trust context, proof, predecessor, or required field | Refuse before advancement; no durable acknowledgement. Field remains unavailable. |
| Invalid signature/quorum, wrong deployment/backend/ruleset, invalid finality, stale or conflicting history | Refuse; do not substitute a proposal signature, local origin, matching digest, height, or QC alone. |
| Malformed, skipped, trailing, reordered, duplicated, omitted, count-mismatched, or substituted input | Refuse execution publication; no cursor advance or state-dependent completion. |
| Equivalent representation is claimed but policy/currentness cannot be independently established | Treat as unverified/conflicting; no new identity, cursor advance, or acknowledgement. Reverify under an approved policy or remain unavailable. |
| Execution fails or individual transaction result is unresolved | Report only defined outcomes. Never claim every transaction succeeded; retain unresolved fields or mark unavailable pending owner decision. |
| Commit fails or response is lost after a possible commit | Commit status unknown until the whole operation is independently established. Do not fabricate acknowledgement, infer from balances/flush, or blindly re-execute. Retry only by stable operation identity under reviewed fencing. |
| Process restart with apparently valid historical record | Reverify authentication, current context, predecessor continuity, exact operation/unit association, and currentness. Without trusted continuity/recovery evidence, ordinary dependent access remains gated and status unavailable. |
| OS crash, power loss, stale process/handle, competing writer, rollback, or storage corruption | No durability claim until backend, filesystem, hardware, ordering, flush, fencing, and anti-rollback properties are demonstrated. Unknown status remains unavailable. |

Process-crash behavior is not equivalent to operating-system crash or power
loss. No inspected evidence establishes the backend/filesystem/hardware ordering
and durability needed for the proposed unit, or protection against stale
owners, other processes, rollback, or interrupted migration/cutover. Atomicity
across today's actual stores, fencing, migration/cutover, recovery/currentness,
first-use enrollment, and lag policy remain **OPEN / BLOCKED**.

## 8. Authority separation and non-entanglement

The execution-applied cursor is distinct from consensus committed tip/lock,
vote/finality state, signing-reservation journal position, recovery authority,
and activation height. It is not finality proof, anti-rollback protection,
signing/participation authorization, or recovery authorization.

The reviewed audit identifies two concrete indirect channels which must remain
separate:

- consensus `SnapshotAnchor` → snapshot metadata height → `RestoreBaseline` →
  `initialize_from_snapshot_baseline` seeds consensus committed height/view;
- `RestoreBaseline.snapshot_height` → `ActivationContext.current_height` on
  selected startup/CLI trust-bundle routes.

The cursor must never populate or be transformed into either channel, nor into
consensus locks/votes/finality, signing-journal position, snapshot/restore
authority, recovery decisions, or activation context. Preventing direct reads
is insufficient: future source/use-path, type/provenance, build/feature,
callback/cache/API, restart, migration, and runtime evidence must exclude
indirect flows. An in-process mutex or advisory lock alone cannot establish
fencing against other processes, stale handles, or backend-level writers.
Current implementation-grade non-entanglement proof is **OPEN / BLOCKED**.

## 9. Decision and evidence matrix

| Category | Finding |
|---|---|
| Source-established | Proposal signature preimage includes embedded QC bytes and ordered transaction bytes/count; QC verifier is conditional on supplied trust inputs and returns non-authorizing evidence; inspected 3-chain commit is in-memory; Required production route sets Proposal/Vote authority to `None`; simulator skips malformed transaction encodings; block/QC/last-committed are separate writes; queue submission is admission only; snapshot height has the reviewed consensus-baseline and activation channels. |
| Owner-approved | Specify/assess engine-produced finalized-input record as primary candidate; keep external authenticated artifact unselected; no implementation, experiment, integration, activation, or DevNet is authorized. |
| Candidate requirement | Execution independently authenticates authority and finality, checks context/currentness and exact inputs, derives stable semantic identity, and commits the complete required consistency unit before acknowledging. Fail closed and preserve unknown/unavailable outcomes. |
| Unselected alternatives | External finality artifact; possible new signed handoff record; single-domain or cross-store atomic design; cryptographic construction; storage/backend format; lag policy; recovery authority. None is selected or evidenced. |
| Feasibility blockers | No adequate production canonical Proposal/Vote authority in the inspected Required route; no durable independently authenticated finality record; in-memory QC/tip; exact execution vector equality not established; actual stores are separate; six bindings, post-quantum construction/trust, currentness, fencing, migration, recovery and non-entanglement proof open. |
| Evidence required before implementation entry | Approved authority and semantic-subject policy; independent verifier/currentness and post-restart continuity design; exact authenticated-input-to-executed-vector proof; explicit six-binding closure; fixed native-PQ construction and classical-dependency review; atomicity/durability/fencing/recovery proof for the actual stores; migration and initial enrollment authority; full direct/indirect non-entanglement source/build/runtime use-proof; separately reviewed failure, retry, entitlement and lag policy. Any future tests/build/runtime validation requires separate authorization. |

### Future validation status

All proposed source, type/data-flow, build/feature, test, crash, storage,
concurrency, restart, migration, cryptographic, runtime, and DevNet validation
is **FUTURE / NOT AUTHORIZED / NOT EXECUTED**. This task does not authorize an
experiment or implementation entry.

## 10. Scope and preserved dispositions

This specification adds no claim that an engine-produced record, production
authority, durable cursor, joint commit, alternate-proof route, or
implementation-grade non-entanglement proof currently exists. The reviewed
audit's bounded search and unverified downstream/build/runtime scope remain.
No requested pinned source object was unavailable during this assessment; any
claim beyond the inspected source paths and configurations remains unverified.

Required-persistence remains **NOT ACCEPTED / NOT INTEGRATION-READY**.
Recipient overflow, A23-F1, and A33-F1 / E27 remain **OPEN**. All six identity
bindings, native-PQ construction, cursor non-entanglement,
recovery/currentness, and lag policy remain **OPEN / BLOCKED**. Activation
remains **DISABLED**; public DevNet remains **NO-GO**.
