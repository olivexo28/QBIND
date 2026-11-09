# Future submitter acknowledgement and atomic-commit design candidate

## 1. Status, provenance and authority

**DOCUMENTATION ONLY / CANDIDATE FOR INDEPENDENT REVIEW.** No acknowledgement
mechanism, storage mechanism or implementation entry is approved. This task
authorizes no implementation, experiment, production wiring, startup,
integration, signing, recovery, deployment or activation. All proposed
validation below is **FUTURE / NOT EXECUTED** and requires separate approval;
this document does not authorize another experiment.

Remote refs were checked before authoring:

| Ref | Required and observed commit | Reviewed tree |
|---|---|---|
| `main` | `aa382fa28b2d3e97e6203d47fa8231b5f2269741` | Main is the comparison baseline, not the design parent. |
| `docs/owner-working-caller-classification` | `9b3cec9a850c53afababe17b2adc949631af48af` | `44b658a9e059c96bb4046c03cbfb1138d41138dd` |

This document is added on a separate branch directly from the reviewed
classification endpoint. Existing local work and historical evidence are
preserved. The independent reviewer maintains the carry-forward record;
this document does not replace that record.

Labels used throughout:

- **SOURCE FACT:** observed in the pinned source below; not a new guarantee.
- **OWNER DECISION:** the narrow requirement supplied for this task.
- **CANDIDATE:** an unimplemented assumption or proposed obligation.
- **OPEN:** unresolved feasibility, policy, evidence or future owner decision.

### Pinned citations

All paths and line ranges in this document refer to commit
`9b3cec9a850c53afababe17b2adc949631af48af`, not a moving branch. Source
links use that immutable pin. The specification/evidence blob identities are:

| Citation | Pinned artifact and location | Blob |
|---|---|---|
| R1 | [Reviewed caller contract](https://github.com/olivexo28/QBIND/blob/9b3cec9a850c53afababe17b2adc949631af48af/docs/security/evidence/caller-completion-actual-store-failure-contract-20261109.md), section 1, especially the five-row working classification; sections 2-6 | `5644b132d591b5402ce21b7b75a27f68c911b599` |
| R2 | [Candidate recovery protocol](https://github.com/olivexo28/QBIND/blob/9b3cec9a850c53afababe17b2adc949631af48af/docs/security/evidence/candidate-durable-execution-recovery-protocol-20261109.md), sections 3.1-3.3, 4 and 5 | `e48d199a8544faa353036e0127cc7e874339689d` |
| R3 | [Prior bounded capability evidence](https://github.com/olivexo28/QBIND/blob/9b3cec9a850c53afababe17b2adc949631af48af/docs/security/evidence/atomic-block-retained-completion-capability-experiment-20261109.md), status, existing behavior, failure model and implementation-entry decision | `1b4d45b1543f38963c109803bd1eeed148a2b5f2` |
| S1 | [execution_adapter.rs](https://github.com/olivexo28/QBIND/blob/9b3cec9a850c53afababe17b2adc949631af48af/crates/qbind-node/src/execution_adapter.rs#L460-L505), 460-505, 577-680, 1300-1382 and 1492-1525 | Queue admission, shared handle/worker claim, per-account operations, execution/flush/local height |
| S2 | [execution.rs](https://github.com/olivexo28/QBIND/blob/9b3cec9a850c53afababe17b2adc949631af48af/crates/qbind-ledger/src/execution.rs#L1130-L1141), 1130-1141, 1258-1285 and 1380-1483 | Account view/updater, persistent interface, RocksDB implementation |
| S3 | [node_config.rs](https://github.com/olivexo28/QBIND/blob/9b3cec9a850c53afababe17b2adc949631af48af/crates/qbind-node/src/node_config.rs#L5271-L5291), 5271-5291; [vm_v0_runtime.rs](https://github.com/olivexo28/QBIND/blob/9b3cec9a850c53afababe17b2adc949631af48af/crates/qbind-node/src/vm_v0_runtime.rs#L58-L90), 58-90; [production_consensus_storage.rs](https://github.com/olivexo28/QBIND/blob/9b3cec9a850c53afababe17b2adc949631af48af/crates/qbind-node/src/production_consensus_storage.rs#L353-L375), 353-375 | Separate account and consensus paths/openers |
| S4 | [storage.rs](https://github.com/olivexo28/QBIND/blob/9b3cec9a850c53afababe17b2adc949631af48af/crates/qbind-node/src/storage.rs#L929-L1025), 929-1025 and `apply_epoch_transition_atomic` beginning at 1110 | Separate committed-ID/epoch methods and consensus-local batch |
| S5 | [consensus.rs](https://github.com/olivexo28/QBIND/blob/9b3cec9a850c53afababe17b2adc949631af48af/crates/qbind-wire/src/consensus.rs#L915-L950), 915-950 | Canonical signed body includes header, embedded QC bytes and ordered length-prefixed transactions |

**SOURCE FACT (S1-S4):** the inspected account and consensus/position paths
use separate stores. Account persistence exposes per-account put and flush,
not the required joint block commit. The account read implementation collapses
absence, decode failure and read error to default; its updater returns no
storage error. The worker's setter can fail without propagating that failure
through this updater, logs flush failure and advances local height. Neither
local height nor these APIs establish durable block completion. A consensus
epoch batch or durability barrier in that database does not span account state.

**HISTORICAL EVIDENCE (R3):** the prior 5/5 capability run is author-run
evidence only for its narrow synthetic characterization. Its single-database
batch/clean-reopen control did not establish the actual separate-store joint
durable commit, process-crash recovery or power-loss safety. Its injected
separate-store partial-state control is not a proof that all cross-store
protocols are impossible. No experiment is repeated or expanded here.

## 2. Owner decision and caller boundary

**OWNER DECISION:** for a future persistent execution service, its block
submitter is designated as entitled to request an authenticated,
operation/position-bound durable block acknowledgement. This is a target
entitlement, not an existing caller, capability or approved mechanism.
The acknowledgement must not mean that every transaction succeeded.

**SOURCE FACT (S1):** today's `submit_block(QbindBlock)` response remains
**QUEUE ADMISSION ONLY**: enqueue success, queue-full or shutdown. No durable
acknowledgement or submitter completion-retrieval mechanism is established.
The proposed request/retrieval separation below does not change this API.

**OWNER DECISION:** the new narrow future entitlement is additive to, not a
rewrite of, R1's approved five-row working specification baseline:

| Working row retained from R1 | Effect of this owner decision |
|---|---|
| Synchronous execution adapter | Preserve immediate success/first-error semantics; no new durable entitlement. |
| Asynchronous service submitter | Preserve current admission semantics. Designate only the future persistent service's block submitter for the specified durable acknowledgement, contingent on the unresolved prerequisites. |
| `Node::apply_block` | Preserve immediate ordered results; durable-outcome entitlement remains OPEN. |
| `LedgerApply` / `NodeLedgerHarness` | Preserve inspected in-memory/harness semantics; no invented durable acknowledgement. |
| EVM bridge consumer | Preserve immediate results and reviewed in-memory retrieval limitations; durable receipts/outcome entitlement remains OPEN. |

No entitlement is inferred for another caller, including a transaction
originator, RPC/P2P consumer, metrics consumer or harness. Transaction-outcome
entitlements, including EVM receipts, remain **OPEN**. Unknown or unresolved
fields must be explicitly unavailable or retained pending the owner's
decision, never silently omitted. The narrow acknowledgement decision does
not decide that acknowledgement-only is sufficient for all callers.

The entitlement remains contingent on durable atomic commit, all six identity
bindings, a native post-quantum authentication construction, fencing and
recovery. All remain **OPEN** and require independent review.

## 3. Required unit and candidate record

**OWNER REQUIREMENT:** one reviewed atomic consistency unit must include:

1. Account values and exact membership, distinguishing absent, present-default,
   created and deleted accounts.
2. Authenticated prior/new execution positions and stable operation identity.
3. The acknowledgement and every entitled outcome.
4. The exact executed transaction order and count.

All four are jointly visible and durable, or ordinary access must remain
closed until the protocol establishes a coherent unit. A protocol may block
availability; it must not expose mixed units. References to required outcomes
are acceptable only if both references and target bytes are in the same unit
(R1). Independently committing a required result is not this candidate.

**CANDIDATE logical record, not a selected encoding:** deployment/backend
association, schema and authorized ruleset/version; stable decision subject
and operation ID; prior/new position and full predecessor relation; verified
finality/equivalence-policy context; exact canonical executed inputs and
count; state values/membership or their complete transactional representation;
commit identity; retained acknowledgement assertion; and ordered entitled
outcomes with explicit unresolved-field availability. Any integrity
commitment must cover the entire relation, not just balances. Its algorithm,
canonical encoding, bounds and authenticated availability remain OPEN.

The acknowledgement asserts only that execution of this operation was
durably committed under the authorized rules, including whatever transaction
failures those rules permit. A VM rejection is not a storage failure; a
committed block may contain failed transactions. Whether particular failures
abort a block, and their exact retained encoding/fields, remain owner/ruleset
decisions. Do not mask arithmetic failures as generic success.

**CANDIDATE authentication boundary:** the retained assertion and a retrieval
response must authenticate operation, position, exact inputs/count, commit
identity and state relation, with entitled outcomes covered by the same unit.
Authentication cannot merely attest queue admission or authenticate a server
connection. Whether retrieval carries a precommitted authenticated object or
an authenticated proof of the committed record is OPEN; no new signing step,
key or primitive is selected. Freshness/currentness must prevent replay of a
superseded backend or policy context while allowing identified historical
retrieval under an approved policy.

Native post-quantum trust is fixed. Construction, parameters, roots, key
authority, authentication/integrity composition and demonstrated end-to-end
security remain OPEN. A hash, named signature suite or classical dependency
alone is not proof of that property. Classical or unqualified dependencies
in finality, association, commit and recovery must be identified, not counted
as satisfying the native requirement.

## 4. Identity and proof obligations

**OPEN, required before effects (R2 sections 3.1-3.3):**

| Binding | Required verification, not just a stored field |
|---|---|
| 1. Finality | Authenticate finality for the exact stable decision subject under authorized consensus history and policy. A proposal signature or QC-shaped object is not automatically finality. |
| 2. Exact executed inputs | Verify canonical authenticated inputs, every relevant commitment, actual decoded/executed bytes, order and count; reject substitutions and inconsistent counts. |
| 3. Position continuity | Authenticate prior/new position, full predecessor and applicable chain/epoch/height/round continuity. Same-position semantic conflicts must refuse. |
| 4. Deployment/backend association | Independently authenticate history, deployment and state-instance association, including replacements; directory names/local configuration are insufficient. |
| 5. Ruleset | Verify authorized execution/schema versions and transition history at this position, not merely a local flag. |
| 6. Commit identity | Bind the stable operation, state/membership, position, exact inputs and required completion within the reviewed durable unit; retrieval must establish that binding. |

Height plus payload hash is insufficient. Neither current block IDs nor
locally matching state proves these bindings (R2 section 3.1). Required identity
components include deployment/state instance, chain/epoch/position, full
parent and predecessor, stable decision subject, exact ordered inputs/count,
and authorized ruleset/schema/transition interpretation. Encoding these
components does not verify them.

**CANDIDATE equivalence rule:** a valid, policy-authorized equivalent finality
representation of the same decision must not manufacture a conflicting
operation ID. Unexamined proof bytes cannot define semantic identity.
Unselected approaches are an authorized unique-proof/equivalence-selection
rule or a stable authenticated decision subject with separately verified,
bound evidence (R2). Canonical encoding alone does not choose uniquely among
different sufficient proofs.

Each alternate representation must be independently reverified, or reuse
must rely on a durable authenticated verification record binding the stable
subject, exact representation/approved equivalence class, verifier/policy
version, deployment and context. Required currentness, revocation and
transition checks must be re-established; reuse cannot bypass them. Invalid,
unauthorized, wrong-subject, non-equivalent, stale, conflicting or unavailable
evidence refuses execution/retrieval success. Uncertain equivalence yields
unknown/unavailable, not a fabricated conflict or fresh execution.

**SOURCE FACT (S5):** proposal-embedded QC bytes are part of the signed
canonical body, alongside ordered transactions. External finality evidence
is not authenticated by that signature merely because it accompanies the
proposal. Different embedded QCs change the signed body; equivalence of
external proofs does not establish equivalence of those proposal subjects.
Mapping proposal, embedded QC and external finality evidence to one decision
requires explicit verification. No applicable QBIND route, implemented
equivalence policy or currentness mechanism is established here.

## 5. Concrete conditional sequence

Every step below is **CANDIDATE / UNIMPLEMENTED**. The steps describe proof
obligations, not an actual atomic primitive. They apply to either unselected
storage candidate in section 6.

| Step | Checks and writes | Permitted visibility | Unproven dependency / failure disposition |
|---|---|---|---|
| 0. Enroll and fence | Independently verify backend association, currentness, existing committed unit and authority; acquire an enforceable owner generation/fence. First use needs authenticated enrollment, not an empty directory inference. | No ordinary access until enrollment and inspection succeed. | Authority, currentness and enforceable fence are OPEN. Uncertainty keeps service unavailable. |
| 1. Authenticate request | Verify request authority, all applicable identity bindings, finality/equivalence, exact bytes/count, ruleset and predecessor. Bind request correlation to stable operation identity; do not trust a caller-chosen ID alone. No account effects. | Admission may be reported separately; never durable completion. | Authenticated input source and schema are OPEN. Invalid evidence refuses; unavailable evidence remains unavailable. |
| 2. Resolve retry before work | Under the same fence/snapshot, look up operation and position. Verify any prior commit, acknowledgement and required outcomes. Conflicting subject or predecessor refuses. Prepared/uncertain history enters restricted inspection. | Return only an authenticated, established retained completion for the same operation. | Absence/pruning is not proof of nonexecution. Retention and historical currentness policy are OPEN. |
| 3. Prepare | Durably record operation-specific intent, exact input reference/bytes and count, prior position, policy/schema and fence generation. Establish preparation durability before execution effects. This is not a commit record. | No staged effects or acknowledgement. Ordinary mutation/new worker work is closed. | Prepare barrier, error resolution and evidence retention are OPEN. Ambiguous preparation means unknown and no execution. |
| 4. Execute in isolation | Read a coherent committed snapshot, preserving membership and read errors; compute changes and ordered results off to the side. Propagate storage errors distinctly from VM outcomes. No live per-key publication. | Old committed unit only through explicitly permitted coherent reads, or all ordinary reads refused. | Current infallible updater/defaulting read boundary needs redesign (S2); isolation and correct execution, including overflow behavior, are unproven. |
| 5. Validate complete candidate | Check all bindings against preparation, prior position and fence; validate membership, order/count and results; construct acknowledgement content and retain every entitled field. Mark unresolved fields unavailable or preserve them. Enforce approved bounds without truncation. | No new values, local height or durable-success metrics exposed. | Schema, limits, entitlement details and native authentication construction are OPEN. Incomplete candidate cannot commit as complete. |
| 6. Commit/publish | Within the chosen reviewed protocol, jointly commit values/membership, authenticated position, operation/commit identity, exact executed order/count, acknowledgement and entitled outcomes; resolve preparation consistently. Recheck fence/predecessor at the authoritative decision point. | One complete old or new unit, never independently published position/result. | Atomic visibility, durability, decision point and unknown-outcome inspection must be proved for the actual domain. Errors/timeouts default to unknown unless no effects are proved. |
| 7. Establish and retrieve | Establish durable commit of the entire unit, authenticate retained record and retrieval authority/currentness; validate every required completion's availability. Invalidate/update caches before opening access or exposing success. | Durable acknowledgement only after the whole contract is established; transaction failures remain represented under the rules. | A successful write return, later flush or matching balances is insufficient without the selected durability contract. Missing required completion means unknown/unavailable, even if some commit evidence exists. |
| 8. Retry/lost response | Reauthenticate the same semantic operation, including alternate authorized equivalent evidence under section 4. Retrieve the original retained assertion and entitled outcomes; do not execute again. | Same operation/position/inputs/count and original completion, not a newly invented success. | No retained or establishable result means unavailable; pruning must not reopen execution. |
| 9. Restart inspection | Start gated; independently verify recovery authority/evidence, fence out stale owners, inspect preparation/decision/participants and committed unit. Establish currentness and cache consistency before any authorized service return. | Restricted inspection only until resolution. No automatic normal startup or participation. | Recovery, enrollment, signing-history continuity and return-to-service authority remain OPEN. No resolution means quarantine/unavailability. |

The preparation record can be separately durable only as intent, without
exposing partial required-unit contents as committed. Its reconciliation
with the final unit must be proved. Prepared state cannot be cleared merely
because a timer expired or an owner disappeared.

## 6. Actual store boundary: two unselected candidates

### A. One appropriately reviewed transaction domain

**CANDIDATE:** relocate or redesign authoritative account values/membership,
execution position, operation/commit identity, exact input order/count and
retained completion into one domain with a supported atomic primitive.
This is not a selection of RocksDB, another database, a batch or a transaction
API. It is not evidence that today's two databases share a transaction.

Required changes include a joint fallible prepare/commit/lookup interface;
membership-aware, error-preserving reads; isolated execution; and routing all
position/result readers and writers to that authority. Existing consensus
metadata must not remain a competing authoritative execution-position copy.
If consensus data stays separate, its relationship to the new authoritative
execution position must be reviewed: either it is a nonauthoritative,
rebuildable projection with no independent success semantics, or any required
authoritative dependency joins the unit. This distinction cannot be assumed.
Migration, enrollment, projections, backups and restoration must not expose
mixed generations or accidentally admit an old backend.

It must prove snapshot isolation/conflict handling, old-or-new visibility,
membership correctness, exact unit coverage, durable ordering of preparation
and commit, ambiguous-result resolution, authentication, fencing and restart
behavior under a specified failure model. A batch that is atomic only inside
one database is useful only after actual unit placement and all access routes
are proved. Neither S4's consensus batch nor R3's synthetic batch proves it.

### B. Separately justified cross-store publication protocol

**CANDIDATE, conditional feasibility only:** retain separate stores but add
durable versioned staging, participant prepare records, an authenticated
coordinator decision and universally enforced publication gates. This is a
conceptual blocking coordinator protocol, not an assertion that current
QBIND/RocksDB interfaces support distributed prepare or commit.

1. Under a current enforceable fence, record the operation intent and prior
   unit. Participants stage immutable, operation-bound versions: accounts
   and membership; position/identity; input manifest; acknowledgement and
   entitled outcomes. Nothing is visible as the new unit.
2. Each participant durably prepares its exact version and records a
   binding to the common operation, predecessor, unit manifest and fence.
   The coordinator must establish every required prepare before deciding.
   No independent participant is permitted to expose or discard prepared data.
3. Record one authenticated durable commit decision referencing all prepared
   versions. The decision must be irrevocable and unique for that predecessor.
   Participants then durably install/reconcile that decision idempotently.
   Abort is permitted only with proof that no commit decision can exist under
   the approved protocol; timeout or a missing coordinator is not that proof.
4. Publish one coherent generation only after all required data and completion
   are durable and resolvable. Every read/retrieval must validate the generation
   and decision across its required participants, or refuse while gated.
   Position or account stores becoming locally readable first is not permission
   to expose them. A publication marker alone is not an atomicity proof.
5. After interruption, authenticated fenced inspection resolves the durable
   decision and each participant without re-execution. A known commit decision
   with unavailable/incomplete participant data still yields unavailable
   completion and closed ordinary access; it does not permit an acknowledgement.

This needs new transactional/versioning and decision-resolution APIs in every
participant, durable coordinator storage with its own failure model, global
generation-aware read/write gates, anti-stale-owner enforcement, safe retention
and an authenticated recovery protocol. If ordinary clients can bypass the
gate or overwrite prepared versions, this candidate fails.

It must prove a single decision point, no split decisions, no mixed external
visibility, safe partial-prepare/partial-install handling, durable retained
data, termination limits and safe blocking on coordinator/participant loss.
Coordinator replacement/failover cannot use an unauthenticated local decision.
The physical writes can be sequential only if the reviewed protocol proves
logical atomicity and durability across the complete unit for every admitted
observer. No such proof, primitive or bypass-free access boundary is currently
established. Choosing to block forever may preserve safety, not availability.

**Neither A nor B is selected or demonstrated.** Deterministic reconstruction
of completion remains an unselected inherited alternative requiring a new
justification/decision; it must not replace the required retained-unit contract
or authorize blind re-execution here.

## 7. Failure, retry and durability contract

All outcomes below are **CANDIDATE requirements**, not tested behavior.
Unknown commit and unavailable required data must be explicit, not encoded as
a committed acknowledgement. Internal evidence may establish a commit decision
without establishing caller-required completion; report that distinction.

| Failure/crash window | Required outcome and next permitted action |
|---|---|
| Before preparation | No execution effects. Definite rejection only when its no-effects scope is established. Missing association/history is unavailable, not first-use authorization. |
| Preparing, including lost prepare return | Unknown preparation; close access and inspect. Do not execute until durable intent and prior position are established. |
| During isolated execution | Do not publish partial state. Preserve typed execution/storage failures. Only prove definite noncommit from the reviewed primitive and complete evidence; otherwise unknown. A VM failure is not automatically a block-level failure. |
| During publication, including any store/coordinator error | Unknown unless the selected contract and authenticated inspection resolve the entire unit. Partial states remain gated; never independently acknowledge position or state. |
| After commit but before cache/response, or response lost | Caller has unknown result until authenticated lookup establishes the same durable unit and required completion. Retrieve original result, never re-execute to reconstruct success. |
| Retried same operation | Verify identity/equivalence/currentness and retrieve retained completion. Prepared, missing, expired, corrupt, conflicting or unresolvable evidence refuses success. No record is not proof of no earlier commit. |
| Restart, coordinator replacement or stale owner reappearance | Closed ordinary gates; independent recovery authority/evidence and new enforceable ownership must resolve status. Do not infer completion from balances, height, a later flush or clean database opening. |
| Required outcome/acknowledgement missing despite state/position evidence | Explicit unknown/unavailable for the required completion; do not fabricate it or silently omit fields. Keep unresolved state gated as required by the approved contract. |

**OPEN failure model:** process death with a surviving OS/page cache is distinct
from an OS crash and from power loss. A clean reopen is narrower still.
Before any durable claim, evidence must identify the exact backend/native
build, APIs and options, WAL policy, write/flush/sync semantics, metadata and
directory ordering, filesystem/mount behavior, kernel guarantees, storage
controller/device caches, barriers and power-loss protection. Cross-device
ordering, torn writes, corruption detection and behavior on lost/lying flush
acknowledgements require explicit supported assumptions. State the bounds of
the model; do not promise recovery from arbitrary hardware failure.

Errors after a durability call can be ambiguous. A later successful flush does
not retrospectively prove that the correct complete unit committed. Missing,
malformed, conflicting or stale evidence remains unknown/unavailable. No
balance comparison, later height or successful unrelated write resolves it.

## 8. Gates, ownership and recovery dependencies

| Access path | Required future fence/refusal boundary |
|---|---|
| Shared-state reads and cached reads | Check enrollment, current generation, coherent unit and gate on every route; do not return default values for unavailable/corrupt state. During ambiguity refuse ordinary reads, including through clones. |
| Writes, setters and flushes | Require current enforced ownership and operation scope; refuse unrelated mutation/flush during prepare, quarantine or inspection. A flush can change persistence and is not harmless read-only maintenance. |
| Worker claims, queues and shutdown | Claim must be bound to backend instance and fenced owner generation, with predecessor checks before effects. Drain/shutdown/worker death must not release authority while work or handles can still act. Queue admission is not execution permission. |
| Retained handles, aliases and stale owners | Revalidate generation at access and authoritative commit; revoke or fence obsolete handles at the storage/publication boundary. Renamed paths, old snapshots or clones cannot retain mutation authority. |
| Other processes and tools | Cover all database openers, runtime paths, maintenance, snapshot/backup/restore and direct-store clients. Enforce ownership at a boundary they cannot bypass, or explicitly refuse the unsupported deployment. |
| Restart and recovery inspection | Start closed. A restricted authenticated read-only inspection capability may examine evidence, but must not be a raw-handle escape from ordinary gates or create a missing database. It cannot execute, flush, sign or participate. |

**SOURCE FACT (S1):** shared mutexes and worker claims serialize documented
in-process routes. They do not prove cross-process exclusion, currentness,
authenticated ownership or durable atomicity. An advisory lock alone cannot
fence noncooperating writers, retained handles or a stale owner after takeover.
The selected backend/OS/deployment mechanism must prove enforcement; none is
selected here.

**OPEN recovery authority and evidence:** independently authenticate the
deployment/backend instance, finalized history, six bindings, preparation and
commit records, participant status, state/membership, required completion,
ruleset transitions, currentness and revocation. Independently authorize
inspection, abort/roll-forward, backend replacement and return to service.
Define first-use enrollment and how absence is distinguished from erased or
replaced history. No validator key, bundle-signing authority, local file or
configuration flag self-authorizes these actions. Loss of authority/evidence
leaves the backend quarantined/unavailable.

Signing-history continuity and recovery authority remain OPEN. VM-state
recovery does not authorize signing, proposal/vote participation, startup or
activation. No recovery action is authorized by this document.

## 9. Decision and evidence matrix

Every proposed validation/evidence requirement in this section is
**FUTURE / NOT EXECUTED / NOT AUTHORIZED BY THIS TASK**.

| Classification | Decision/evidence now | Evidence required before any implementation entry |
|---|---|---|
| SOURCE-ESTABLISHED | S1 admission-only API and local serialization; S2 per-key account API and error/membership limitations; S3-S4 separate stores; S5 signed embedded QC/input bytes | Reviewed actual-path inventory of all authority, store and access boundaries; no assumption that a new API alone supplies guarantees |
| OWNER-APPROVED REQUIREMENT | Narrow future persistent-service submitter acknowledgement entitlement; not universal transaction success; preserve five-row baseline; joint unit, explicit unknown/unavailable and native post-quantum trust | Independently reviewed contract/schema covering correlation, retrieval, order/count, failure semantics and field availability |
| CANDIDATE ASSUMPTION | Durable preparation, isolated fallible execution, one commit decision, coherent publication and authenticated original-result retrieval | A complete design and safety argument showing each step's supported primitive, error semantics and identity checks, including negative/bypass cases; not just sequence diagrams |
| UNSELECTED ALTERNATIVES | Single transaction domain A; cross-store protocol B; inherited reconstruction alternative | Separate owner selection and independent feasibility review of the real boundary, changes, migration and limitations; no automatic experiment authorization |
| FEASIBILITY BLOCKER: ATOMICITY | No established joint durable commit; R3 is narrow author-run 5/5 evidence only | Primitive/backend provenance and contract; proof of all unit contents and references; visibility/ordering/unknown-resolution argument for every failure window and participant |
| FEASIBILITY BLOCKER: IDENTITY/TRUST | All six bindings, authorized proof equivalence/currentness and native authentication construction OPEN | Authenticated route/subject mapping and transition policy, re-verification/reuse rules, security review of post-quantum end-to-end construction and independent roots |
| FEASIBILITY BLOCKER: ACCESS/RECOVERY | Fencing, independently authorized recovery and first enrollment OPEN | Complete path coverage and non-bypass argument for handles, flushes, workers, processes, stale owners, inspection and restart; separate signing-history continuity obligations |
| FUTURE OWNER DECISIONS | Outcome entitlements including EVM receipts; retention/retry windows, size bounds, canonical errors/encoding, historical retrieval currentness, enrollment/return authority and supported failure model OPEN | Explicit per-caller/field decision: retain pending decision or report unavailable; no silent omission/pruning; capacity exhaustion must not truncate required completion |
| FUTURE VALIDATION | No validation of candidate behavior was performed here | Only after separate authorization: exact-unit/order/count positive and negative checks; wrong/missing-field and same-checker bypass controls; equivalent-proof retry; lost response and unknown commit; actual-store/coordinator failure and restart controls; stale-handle/multiprocess controls |
| FUTURE DURABILITY EVIDENCE | Process-crash, OS-crash and power-loss properties not established | Separately scoped evidence for each claimed failure class on the selected backend/filesystem/hardware and configuration, without generalizing clean reopen or process death to power loss |

**Implementation entry remains BLOCKED.** The listed evidence and independent
review are prerequisites, not authorization to gather it now or a substitute
for a later explicit implementation decision.

## 10. Preserved status and exact inherited scope

The five-row caller classification remains an approved working specification
baseline. CCI-1 and CCI-2 remain CLOSED in their inventory scopes; CCC-1 and
CCC-2 remain CLOSED in their documentation scopes. No scoped closure is expanded
into production acceptance. The arithmetic baseline remains red; recipient
overflow remains OPEN. Native post-quantum trust remains fixed, while its
constructions and demonstrated security remain OPEN. Historical evidence,
including the narrow prior 5/5 author run, is unchanged.

Required-persistence and the inherited branch remain **NOT ACCEPTED /
NOT INTEGRATION-READY**. Recipient overflow, A23-F1 and A33-F1 / E27 remain
**OPEN**; activation remains **DISABLED**; public DevNet remains **NO-GO**.

### Scope report

The sole new path versus `9b3cec9a850c53afababe17b2adc949631af48af` is:

```text
A docs/security/evidence/future-submitter-acknowledgement-atomic-commit-design-20261109.md
```

The full inherited change scope from pinned main
`aa382fa28b2d3e97e6203d47fa8231b5f2269741` to the reviewed parent is the
following 48 paths (A = added, M = modified). These inherited code/tests/logs
are not changes authorized or made by this documentation task. The delivered
branch's full scope versus main is these 48 paths plus the single new document
above, totaling 49 paths. This reports ancestry, not integration readiness.

```text
A crates/qbind-ledger/src/checked_arithmetic_oracle_tests.rs
M crates/qbind-ledger/src/parallel_exec.rs
A crates/qbind-ledger/tests/atomic_block_retained_completion_capability.rs
A crates/qbind-ledger/tests/gas_disabled_recipient_overflow_characterization.rs
A crates/qbind-ledger/tests/sequential_direct_stage_b_overflow_characterization.rs
M crates/qbind-node/src/execution_adapter.rs
M crates/qbind-node/src/lib.rs
M crates/qbind-node/tests/t155_async_execution_integration_tests.rs
M crates/qbind-node/tests/t157_parallel_execution_integration_tests.rs
M crates/qbind-node/tests/t160_devnet_cluster_harness.rs
M crates/qbind-node/tests/t163_vm_v0_integration_tests.rs
M crates/qbind-node/tests/t166_testnet_alpha_cluster_harness.rs
M crates/qbind-node/tests/t177_vm_v0_pipeline_proptests.rs
M crates/qbind-node/tests/t179_gas_pipeline_proptests.rs
M crates/qbind-node/tests/t221_dag_coupling_cluster_tests.rs
M crates/qbind-node/tests/t222_consensus_chaos_harness.rs
M crates/qbind-node/tests/t238_multi_region_latency_harness.rs
A docs/security/evidence/atomic-block-retained-completion-capability-experiment-20261109.md
A docs/security/evidence/caller-completion-actual-store-failure-contract-20261109.md
A docs/security/evidence/candidate-durable-execution-recovery-protocol-20261109.md
A docs/security/evidence/checked-arithmetic-oracle-baseline-20261109.md
A docs/security/evidence/checked-arithmetic-oracle-debug-20261109.txt
A docs/security/evidence/checked-arithmetic-oracle-nontest-build-20261109.txt
A docs/security/evidence/checked-arithmetic-oracle-release-20261109.txt
A docs/security/evidence/checked-arithmetic-owner-followup-debug-20261109.txt
A docs/security/evidence/checked-arithmetic-owner-followup-release-20261109.txt
A docs/security/evidence/checked-arithmetic-owner-test-contract-20261109.md
A docs/security/evidence/checked-arithmetic-owner-test-contract-followup-20261109.md
A docs/security/evidence/gas-disabled-arithmetic-compatibility-transition-assessment-20261109.md
A docs/security/evidence/gas-disabled-arithmetic-refusal-contract-proposal-20261109.md
A docs/security/evidence/gas-disabled-recipient-overflow-characterization-20261109.md
A docs/security/evidence/gas-disabled-recipient-overflow-debug-20261109.txt
A docs/security/evidence/gas-disabled-recipient-overflow-release-20261109.txt
A docs/security/evidence/required-persistence-adapter-unit-output-20261109.txt
A docs/security/evidence/required-persistence-refusal-candidate-20261109.md
A docs/security/evidence/required-persistence-shared-state-check-output-20261109.txt
A docs/security/evidence/required-persistence-shared-state-correction-20261109.md
A docs/security/evidence/required-persistence-shared-state-t166-output-20261109.txt
A docs/security/evidence/required-persistence-shared-state-unit-output-20261109.txt
A docs/security/evidence/required-persistence-t166-initial-duplicate-open-output-20261109.txt
A docs/security/evidence/required-persistence-t166-smoke-output-20261109.txt
A docs/security/evidence/required-persistence-test-check-output-20261109.txt
A docs/security/evidence/sequential-direct-stage-b-overflow-characterization-20261109.md
A docs/security/evidence/sequential-direct-stage-b-overflow-debug-20261109.txt
A docs/security/evidence/sequential-direct-stage-b-overflow-release-20261109.txt
A docs/security/evidence/shared-state-blocker-controls-20261109.md
A docs/security/evidence/shared-state-blocker-controls-output-20261109.txt
A docs/security/evidence/worker-write-failure-backend-reuse-decision-brief-20261109.md
```
