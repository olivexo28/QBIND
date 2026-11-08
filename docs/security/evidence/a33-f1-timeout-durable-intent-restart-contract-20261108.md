# Timeout durable intent and restart contract

**TIMEOUT DURABLE INTENT AND RESTART CONTRACT — INDEPENDENT REVIEW
PENDING.** This is a focused design record, not production behavior,
backend selection, permission to resume, or approval to participate.
TSL-1/2/3/4 remain **PASSED/CLOSED WITH LIMITATIONS** only within their
accepted test-only scenarios. Transport, A17-F1 / RS1-F7, RS1 and A33-F1 /
E27 remain **OPEN**. Activation **DISABLED**; public DevNet **NO-GO**.

## Provenance and preserved decisions

Repository `olivexo28/QBIND`. The dedicated documentation branch starts at
accepted Timeout-boundary commit
`a1ed2b89e3f9eeceff2ca26d58edcc254b558dd4`, tree
`2747efe0224679267a7dc5c8ab9ece8f843facaa`. Required current main is
`0d1b56515c52abe2862064027d1a9f103fef5a0c`, tree
`b3e8914e6ff234afd80fd29b58470c43f2b08009`.

The general durable-intent candidate
`ebd65c6e0afa0ed3c2ceb2aaf1e302803bfa2e88` and accepted local
fencing/permit clarification `405297a0e791d1f9db9898323495902e26e46d82`
remain prior evidence. The general candidate's record format, one-shot
policy and storage/publication bounds are **not selected** here. This record
applies the accepted refusal-only and permit/revocation direction to the
Timeout path; it does not recreate or supersede the general analysis.

Source line anchors below refer to main at the exact commit above. The
accepted TSL evidence endpoint is
`9f75e6db91a449918399d100db258d8c5f79ac17`. Its test-only owner does not
establish production wiring, persistent intent, external signer
termination, cross-process exclusivity, or restart authority. No tests were
rerun for this design-only continuation.

## Timeout operation identity and source-specific F7 boundary

The candidate durable operation identity must bind the run/destination and
the exact local signer domain and operation, without claiming that the
Timeout signature covers fields it does not cover:

| Identity component | Source-grounded requirement |
|---|---|
| Run and owner | Destination identity under held local ownership, run/attempt identity, and an operation identity unique within that run. Their generation, persistence and trust semantics remain undecided. |
| Signing domain | Configured `ChainId` and the corresponding Timeout domain tag (`DomainKind::Timeout`, chain-aware `QBIND:<scope>:TIMEOUT:v1`), plus the message-format/domain version. The chain ID is explicitly supplied to `sign_timeout_with_chain_id` (`binary_consensus_loop.rs:7740-7744`; `qbind-consensus/src/timeout.rs:157-187`). |
| Signer identity | `validator_id`, configured signature `suite_id`, and stable identity of the corresponding public key/key version. These are separate from the signature preimage; key fingerprint format and binding authority are unresolved. Do not persist secret key material. Existing identity checks compare signer, context and engine (`binary_consensus_loop.rs:7645-7686`). |
| Timeout operation | Timed-out `view`, and whether a high-QC is present. If present, retain its block ID and view as the signed projection. `TimeoutMsg` also carries the full logical QC and suite (`qbind-consensus/src/timeout.rs:72-85`); the canonical Timeout preimage commits to domain, view, QC block ID/view (or zeros), and validator ID (`:157-187`). QC signer list is not part of that signature preimage, though QC presence/full contents remain relevant message/F7 context. |
| Durable result facts | Whether intent was acknowledged; invocation may have occurred; signer returned `Ok` or `Err`; signature verification/encoding; final F7 confirmation; local Timeout ingestion; Timeout publication; local TC application; and NewView publication. Preserve stage outcomes independently. A returned-signature fact is not erased by any later failure. |

Do not use a digest alone as proof of signer identity, freshness or
authority. If a candidate encoding stores a preimage hash rather than all
bounded structured inputs, its collision, parser and audit limitations need
separate review; no encoding is selected here.

Both tick callers at `binary_consensus_loop.rs:3288-3298` and `:3436-3446`
pass `None` for the Proposal/Vote authorization snapshot. For the local
Timeout F7 gate, `admit_f7_retained_high_qc_with_budget` returns `NoQc` when
`high_qc` is absent, but refuses a present QC without a snapshot as
`AuthorityUnavailable` (`:1546-1558`); final confirmation preserves that
distinction (`:1490-1503`). Therefore a present high-QC is refused at this
particular pre-sign gate under these callers, while an absent one passes this
particular gate. Neither result proves the other eligibility checks pass or
that a live node signs.

## Candidate ordering and durable state invariant

The future lifecycle/destination owner must hold the required local
ownership before classification or intent publication. The binary loop
remains the serial engine owner; its helper is
`maybe_emit_view_timeout_with_auth` (`binary_consensus_loop.rs:7563`).
Candidate ordering, subject to the unresolved coordinator/storage decisions:

1. **Classify before protected startup effects.** While holding the
   destination ownership, strictly classify the Timeout/run state before
   opening relevant consensus storage, materializing restore, performing
   reset, loading/using a signer for protected participation, starting
   listeners or admitting workers. An absent, corrupt, foreign, unsupported,
   unreadable, ambiguous or unresolved state is not clean. Refuse with a
   nonzero diagnostic outcome; do not create a clean state on fallback.
2. **Preserve current pre-effect guards.** In the live loop, perform existing
   timeout eligibility, restore/outbound/signer/context/key/suite checks and
   F7 admission plus confirmation before any possible signer effect
   (`binary_consensus_loop.rs:7563-7730`). Existing guards remain
   authoritative and are not bypassed by the durable owner.
3. **Acknowledge intent before a permit.** Bind the exact operation identity
   above and durably acknowledge an intent whose conservative meaning is
   “this operation may be invoked.” Only after positive acknowledgement may
   the operation request the final-effect permit. If publication fails or
   its result is uncertain, do not call the signer; retain artifacts and
   refuse. A prior unresolved record is never replaced with clean state.
4. **Serialize permit against revocation.** Acquire the per-operation permit
   atomically with admission state under a shared coordinator. If revocation
   wins first, refuse before signer invocation; the already acknowledged
   intent remains unresolved (no cleanup based on presumed no effect). If
   the permit wins first, that operation remains owned and may finish after
   admission closes; no later operation may obtain a permit.
5. **Account for invocation and return.** Durably record
   `may_have_been_invoked` before entering `sign_timeout_with_chain_id`, then
   separately observe actual function entry in the live owner. Any `Err`
   after entry is `UnknownAfterInvocation` unless a separately reviewed
   signer contract establishes no effect. Any `Ok(signature)` is a
   returned-signature fact. Persist that fact before later stages; if its
   durable update fails, retain the earlier acknowledged “may have been
   invoked” intent, do not proceed to later effects, and leave restart
   unresolved. A crash between signer effect and result acknowledgement is
   likewise unresolved, not “no signature.”
6. **Write-ahead account for local and external effects.** Keep independent
   stage facts for signature verification, encoding and final F7. Before
   `mark_timeout_emitted` and local `engine.on_timeout_msg`, and before each
   Timeout publication, TC application and NewView publication, durably mark
   that effect as possibly next; afterward record its observed result. If
   recording is unavailable or ambiguous, do not claim rollback: preserve
   the previous possibly-effected stage and classify unresolved. Current
   source marks the per-view timeout before local ingestion, still broadcasts
   if ingestion rejects, and may apply a formed TC before NewView publication
   (`binary_consensus_loop.rs:7819-7879, 7914-8018`). Stage accounting must
   represent those partial outcomes separately.
7. **Never infer restart permission from local completion.** Any unresolved,
   absent or ambiguous record refuses startup before relevant effects. A
   signer error, no local engine mutation, failed publication API, clean
   process exit, successful loop join, or local quiescence does not clear
   durable intent. Even a fully observed local Timeout path does not itself
   establish restart-safe anti-equivocation history or authorize resumption.

Intent acknowledgement means only that the selected publication protocol
reported its required durable boundary under an owner-approved storage
profile. The backend, atomic-write/update semantics, filesystem/barrier
assumptions, record schema, bounds, and treatment of post-rename or sync
uncertainty are unselected. The earlier general candidate's `CATCHUP_...`
record and byte bounds do not automatically apply to Timeout.

## Independent revocation while the signer call is synchronous

The current signer call is synchronous in the loop task. It cannot process
its own select-based shutdown branch until the helper returns. The P2P main
task currently receives Ctrl-C outside that loop, drops the shutdown sender,
and awaits the loop handle (`main.rs:8724-8729`); it discards the join
result. The loop is spawned with a Tokio `JoinHandle`
(`binary_consensus_loop.rs:9432-9478`). This does not currently serialize
admission with shutdown or prove signer-descendant termination.

**Concrete candidate, not wired:** a lifecycle supervisor outside the loop
owns a shared `TimeoutAdmissionCoordinator`. All graceful shutdown/fatal
stop paths must call its `revoke_and_close` operation before signaling or
awaiting the loop. The loop obtains a permit from the same coordinator only
after durable intent acknowledgement. A short critical section atomically
checks open admission and registers the permit; revocation atomically closes
admission so no later permit can be acquired. Do not hold the coordinator
mutex over filesystem I/O, signing, or publication. If revocation occurs
during durable intent publication, the subsequent permit fails and intent
remains sticky. If permit acquisition linearizes first, the in-progress
signer/helper retains its permit and may finish its owned stages.

On shutdown, the supervisor closes admission, signals the loop, and awaits
the loop task without dropping or cancelling the in-progress synchronous
call. A positive local completion requires observing the helper return and
permit retirement, then the loop `JoinHandle` returning `Ok(progress)`;
`JoinError`/panic/abort or a missing completion observation leaves closure
unproven. Classify and retain the returned progress/error rather than
discarding it. Because the loop is blocked in the signer, it cannot process
shutdown until that call returns. No cancellation or dropped waiter is
evidence of signer termination.

This local ordering does not control an HSM/remote signer that can continue
after its method returns or errors, a competing process that does not honor
the same lock/coordinator, another key user, a copied data directory, another
host, or storage rollback. Such an outcome remains Unknown and restart
refuses absent a separately approved authority. SIGKILL, process crash and
power loss cannot rely on graceful revocation; the pre-effect durable intent
must carry the refusal across those cases under a proven storage model.
Who can revoke on every termination path and how hard termination is
classified are implementation blockers.

## Decision table: boundaries and options still unresolved

| Decision | Source/prior record establishes | Still requires an owner/reviewer decision |
|---|---|---|
| Stay-closed policy | Unresolved work stays closed across restart; no automatic clear/resume. Local permit-before-revoke may finish while owned. | The general one-shot marker is an unapproved candidate, not selected. Choose whether first Timeout intent blocks every restart or define a separately reviewed durable history/closure authority. The former can permanently stop restart; the latter needs stronger evidence and is not authorized here. |
| Intent granularity | Timeout signature domain and fields are source-grounded above; existing helper is serial. | A per-process/run marker is smaller but does not preserve per-operation signature history. A per-operation journal can retain exact outcomes but needs bounded retention/exhaustion policy and safe history semantics. Do not pick a policy/backend by assumption. |
| Signer/error semantics | `ValidatorSigner` is synchronous and may have future HSM/remote implementations (`validator_signer.rs:125-200`); remote and PKCS#11 implementations exist (`remote_signer.rs:394-430`, `hsm_pkcs11.rs:552-582`). | Define when return/error proves effect and executor completion. Without an explicit no-effect guarantee, error/cancellation is Unknown. |
| Startup coverage | Normal data-dir path takes a local destination lock at `main.rs:2503-2550`; restore can open storage at `:2619-2632`; reset takes a separate lock at `:2222-2247`. | Classifier placement and complete coverage of reset, restore, early CLI/identity exits (identity dispatch precedes normal lock at `main.rs:2010-2025`), no-data-dir/stateless starts, alternate binaries and direct library callers. No local lock protects copied state or other hosts. |
| Publication/currentness | Existing RTR provides local publication precedent, not a Timeout history contract. | Select storage and durable acknowledgement semantics; bind destination, chain/genesis, validator and key version; decide provisioning/absence policy and currentness/rollback assumptions. No external authority/service or anti-rollback mechanism is selected. |
| Liveness and continuation | Sticky refusal is consistent with stay-closed. | A run-wide one-shot marker can make restart unavailable; blocking on first uncertain Timeout can halt local view changes/quorum. No automatic resume or cleanup is accepted. Decide whether operation history can be safely continued in-process and what happens on exhaustion. |
| Bounded accounting | The helper is serial, but current stats are aggregate and not per-operation durable ownership. | Set hard bounds for records, stage transitions, IDs and retained outcome facts; all overflow, full storage, missing association or ambiguous handoff must refuse before new signer effects and keep startup unresolved. |

An absent file is `UnprovisionedOrUnknown`, not clean. A valid unresolved
record remains unresolved even if a later observer believes the signer had
no effect. The classification of any provisioned-clean or completed record
must wait for approved provisioning and restart/anti-equivocation decisions.
No storage backend, provisioning procedure, global signer authority,
automatic recovery, currentness service or clear procedure is selected.

## Future controls — NOT EXECUTED

All controls below require eventual production wiring; test-only TSL evidence
is not a substitute. Process-kill evidence is distinct from power-loss
durability. Local quiescence is distinct from external signer completion.

| Control | Required observation and failure behavior |
|---|---|
| Intent publication failure | Inject failure before acknowledged publication and ambiguous publication result. Actual signer invocation count/effect remains absent; no permit or later effect; next start refuses absent/ambiguous state rather than treating it clean. |
| Crash windows | Kill after intent acknowledgement but before permit, after permit before call, during call, after signer return before result acknowledgement, after returned-signature acknowledgement, and around each local engine/publication stage. Fresh startup refuses every unresolved/ambiguous state before relevant effects. Process termination does not establish power-loss behavior. |
| Signer error / late result | Actual signer invocation followed by error remains Unknown. Pause a signer across revocation; record late `Ok` as signature-returned if observed, but do not claim an external descendant has terminated without positive evidence. |
| Post-sign stage failures | Inject verifier failure, encoding failure, final F7 refusal, local engine rejection, Timeout broadcast error, TC verification/application failure, and NewView publication error. Preserve signature-returned and each prior engine/publication stage; never claim rollback. |
| Revocation ordering | Barrier before permit: revocation wins, no call. Barrier after permit: close admission while signer is paused, allow owned operation to finish, deny new permit, and await helper plus task completion. Demonstrate loop cannot service its own shutdown select while blocked. |
| Startup classification | Test valid unresolved, absent, malformed/corrupt, foreign domain/key, unreadable, ambiguous staging, and lock contention. Every unclassifiable state refuses before storage/restore/reset/signer/participation; no automatic clean-state creation. Cover reset and CLI/early exit paths separately. |
| Sensitivity | Remove the durable-intent barrier and prove an actual signer effect can precede intent; lose the invocation/result association or retire a live permit early and show the same closure classifier refuses. Include non-vacuous invocation, not counters alone. |
| Bounded accounting | Exhaust every selected fixed bound and inject incomplete/ambiguous stage publication. Refuse before a new invocation where possible; preserve unresolved classification and never treat dropped outcome state as closure. |
| Storage durability | Separately test selected filesystem/database barriers and crash recovery. Process-kill tests alone do not prove power-loss, copied-state, cross-host exclusivity or rollback resistance. |

## Next slice and remaining status

There is **no production implementation slice ready to wire** until owners
choose intent granularity and startup policy, durable publication and
provisioning/currentness assumptions, complete startup coverage, and the
independent revocation/coordinator contract. The smallest subsequent
candidate, after those decisions, is a refusal-only Timeout owner that
publishes bounded durable intent before a per-operation permit, retains
stage facts through the helper, closes admission from the independent
lifecycle supervisor, and classifies unresolved state before startup
effects. It must not add a signer recovery path, clear record, importer,
restart permission, or broader consensus authority. If a one-shot policy is
selected, its permanent restart/liveness cost must be explicitly accepted;
if durable history is selected, its authority and anti-equivocation evidence
must be separately specified first.

Source review and prior documentation are the only checks performed here.
No production behavior, tests, power-loss, HSM, cross-host, global signer
exclusivity, or live-node behavior was exercised. This record does not close
Transport, A17-F1 / RS1-F7, RS1 or A33-F1 / E27. Activation remains
**DISABLED**; public DevNet remains **NO-GO**.
