# Timeout signing: first production enforcement boundary

**TIMEOUT PRODUCTION ENFORCEMENT BOUNDARY — INDEPENDENT REVIEW PENDING.**

## Provenance and disposition

Repository: `olivexo28/QBIND`. This documentation branch starts at the
accepted test-seam evidence endpoint
`9f75e6db91a449918399d100db258d8c5f79ac17`, tree
`e5f32e91e63cdb9d19cdd2d2bf3851c5fc097b00`. Accepted source producer:
`c3a1366e8b9d7ed4298474c576fbdc157ceefef3`. Main remains
`0d1b56515c52abe2862064027d1a9f103fef5a0c`, tree
`b3e8914e6ff234afd80fd29b58470c43f2b08009`.

TSL-1/2/3/4 are accepted **PASSED/CLOSED WITH LIMITATIONS** for their
specified test scenarios. The retained author evidence reports seven
focused test bodies, three local-Timeout regressions and a library check at
the source producer above; it is retained test evidence, not an independent
reviewer Rust rerun. The seam is test-only and does not establish a
production owner, durable history, external signer outcome, or production
fence. The previously accepted stay-closed direction remains unchanged:
unresolved work stays closed, including across restart; there is no
automatic clear or recovery authority.

This is a source/design proposal only. No production source, tests, manifests,
lockfile, audit register or prior evidence are changed by this task.

## Current production Timeout path

In the P2P path, `main.rs` loads a local signer and requires a
`TimeoutVerificationContext`; a valid peer key provider and suite/backend
are required to build the context (`main.rs:5718-5723, 6010-6127`).
When active, the context is threaded into the binary loop
(`main.rs:6138-6163, 8687-8708`). It is a Timeout/NewView verification and
signing capability, **not** an operation permit or signing-history owner.
The single-validator/LocalMesh entry can have no context and then the
helper refuses before signing. Production Proposal/Vote authority is
separate and remains `None` (`main.rs:6162-6170, 8687-8705`).

Both tick branches call the same
`maybe_emit_view_timeout_with_auth` helper (`binary_consensus_loop.rs:3288,
3436`). Before its signer call at `:7740`, it requires progress to be
stationary, the timeout primitive enabled, restore mode inactive, an
outbound facade, no timeout already emitted in the view, elapsed timeout
window, valid successor view, a present context and signer, matching local
validator/key suite/backend, encodable wire suite, matching engine identity,
and successful F7 retained-high-QC admission plus re-confirmation
(`:7563-7730`). F7 protects the current high-QC authorization on this path;
it is not a signer permit, invocation journal, or lifecycle owner.

The call to `sign_timeout_with_chain_id` is synchronous
(`binary_consensus_loop.rs:7740-7754`). An `Err` increments the signing
failure counter and returns before local timeout ingestion, broadcast, or
per-view emission marking. Source does not distinguish an error known to
have had no signing effect from an error after an external signer acted.
The `ValidatorSigner` trait is synchronous and documents possible future
HSM/remote implementations, but does not define whether return/error means
all backend descendants are terminated (`validator_signer.rs:125-182`).
Thus an error is not proof of no effect or executor quiescence.

On `Ok(signature)`, the function puts the bytes in the message, verifies it,
serializes it and performs another F7 confirmation before marking the view
timeout and calling `engine.on_timeout_msg` (`binary_consensus_loop.rs:7740-
7818`). Verification, serialization, or final F7 refusal returns after a
signature has already been produced; no lifecycle record retains that fact.
After final confirmation, `mark_timeout_emitted` precedes local engine
ingestion (`:7821-7850`). Even if local ingestion rejects, the function still
attempts Timeout broadcast. A broadcast error is logged, but does not undo
the local latch or any engine mutation (`:7852-7869`). If local ingestion
formed a TC, TC verification/F7 checks, engine application and NewView
publication follow in `apply_local_tc_and_broadcast_new_view_with_auth`
(`:7871-7879, 7914-8005`). The TC apply mutates engine state before its
NewView broadcast; publication errors are logged without rollback.

The Timeout attempt itself is not a spawned worker: the helper runs
synchronously inside the consensus Tokio task. The loop is spawned and
returns a `JoinHandle`; node shutdown signals the loop and awaits that handle
(`binary_consensus_loop.rs:9432-9478; main.rs:8724-8729`). This establishes
neither an operation-level registry nor termination of a hypothetical
external signer child. The current stats expose aggregate signing,
verification and publication counters, not a joined per-attempt outcome or
invocation/Unknown accounting (`binary_consensus_loop.rs:1831-1932,
9308-9362; metrics.rs:2055-2108, 2327-2336`).

## Proposed first refusal boundary

**Candidate only; not approved or implemented.** The narrowest useful
production boundary is the actual local Timeout attempt in
`maybe_emit_view_timeout_with_auth`, owned by the binary consensus loop
task. One loop-owned, bounded `TimeoutAttemptOwner` would be created in
`run_binary_consensus_loop_with_io` and supplied to both existing tick
callers. It would govern only this local Timeout emission path; it would
not claim to fence Proposal/Vote, inbound Timeout/NewView, other signer
instances, remote/copied keys, or the whole process.

1. Keep all existing progress, restore, identity, suite, verifier and F7
   guards. A missing owner, closed admission, invalid accounting, or full
   one-operation slot refuses before signer invocation. Such refusal must
   not call the signer, locally ingest the Timeout, broadcast it, or apply a
   resulting TC. Report a typed, bounded refusal reason and increment an
   explicit low-cardinality outcome counter; do not silently map it to
   success.
2. Admit one operation and acquire its effect permit atomically with
   admission revocation, immediately before the existing synchronous signer
   call. The permit is per operation, not a sticky historical Boolean.
   Keep the operation lease and bounded record alive through signature
   verification, encoding, final F7 confirmation, local engine ingestion,
   Timeout publication and any TC/NewView processing in this helper.
3. If revocation precedes permit acquisition, refuse this new signing effect.
   If permit acquisition precedes revocation, allow that already-permitted
   operation to finish its owned path; do not cancel it or discard its
   result merely because admission closed. No later operation may acquire a
   permit after closure.
4. Record signer invocation before calling the signer. Conservatively
   classify a signer error as `Unknown` unless a separately reviewed signer
   contract proves no effect. Retain `Unknown` as a sticky bounded
   process-local refusal state; later successful work must not erase it.
   Record a returned-signature fact before verification. A later verifier,
   encoding, final-F7, engine, or publication failure must not erase that
   fact or be recast as “not invoked.” Distinguish local engine ingestion
   from publication API result; a broadcast error is not proof that no peer
   observed the message.
5. Release the local operation obligation only after the synchronous helper
   returns through all work it owns. The loop continues to own the task
   afterward; loop-task `JoinHandle` completion is separately observed on
   shutdown. If an implementation can leave signer work in a thread,
   remote service, queue or callback after returning, local helper return is
   not sufficient evidence for that work. Missing handoff, capacity
   exhaustion, lost outcome association or uncertain completion refuses
   closure and prevents any new Timeout signing through this owner.

The record can be bounded to one in-flight operation, a fixed-size outcome
state, sticky uncertainty bits and checked fixed-width counters; it need not
retain a history vector or signature bytes. Exact error taxonomy and counter
names remain implementation-review decisions. Do not select a digest,
storage backend or cryptographic proof as a substitute for outcome or
authority.

This proposal accounts for a single loop's Timeout path only. It does not
roll back engine mutation or retract a broadcast. A completed local
publication API `Ok` is only that API result, not proof of remote delivery.
If an unexpected later stage fails, preserve the observed stages and refuse
subsequent Timeout signing while the attempt remains uncertain; do not
automatically clear it. Existing behavior that broadcasts after a local
`on_timeout_msg` rejection must be explicitly reviewed before changing:
the first slice may retain it but must record the local-ingest rejection and
the separate publication outcome.

## Wiring decision and unresolved prerequisites

**This is not safe to wire as the production-default stay-closed boundary
yet.** On an ordinary successful operation the proposal could preserve
existing ordering and signed bytes, but a sticky refusal after an Unknown or
partial attempt intentionally suppresses later local Timeout emissions and
can stall view-change liveness or quorum. More importantly, this in-memory
owner disappears on process restart; reopening it would permit effects
after an unresolved prior run, contrary to the accepted across-restart
stay-closed direction. Persisting and classifying intent requires the
separate durable-state/startup contract and decisions; this proposal does
not choose its format, backend, provisioning, currentness or clearing
authority. Wiring a volatile latch while claiming the accepted boundary
would be misleading.

Before any runtime wiring, reviewers/owners must resolve:

- The exact owner and revocation event, synchronization primitive and lock
  ordering. Current shutdown is observed by the loop select; there is no
  production Timeout admission-revocation coordinator.
- The signer contract for success, error, cancellation, descendant work and
  external outcomes. Current trait bounds do not establish that a returned
  `Err` means no signature was produced or that all external work ended.
- Which post-sign outcomes count as known completion versus unresolved,
  including engine rejection followed by broadcast, ambiguous publication
  errors, and a formed-TC/NewView partial path.
- The no-automatic-clear consequence and acceptable liveness/quorum loss
  when an Unknown blocks future Timeout signing.
- The durable unresolved-intent and startup-classification policy required
  to preserve the refusal across restart, plus exact destination/key/network
  binding and provisioning history. No backend or authority is selected.
- Whether another local Timeout signer path exists in each supported
  executable/test mode and how any such path is accounted for. This proposal
  is not a global signer fence or an audit of every signer family.

Until these dependencies are decided, the boundary can be exercised only
with test-only injection or left unwired. No operator switch or new trust
source is proposed to bypass the missing contract.

## Acceptance evidence

All controls below are **FUTURE / NOT EXECUTED** against production entry
points. The accepted TSL tests support deterministic observation of the
actual helper and disposable local signer under the test model, including
Unknown, returned signature, later failure, revocation ordering, worker
barrier, sequential sticky state and sensitivity mutants. They do not
establish that a production owner is wired, that a production shutdown
revokes admission atomically, or that external signer work terminates.

| Future control | Required result |
|---|---|
| Existing-guard and missing-owner refusal | Exercise both production tick callers through the real loop/helper. F7 and owner refusal occur before signer invocation; no local Timeout ingest, broadcast or TC apply follows owner refusal; bounded refusal reason is observable. |
| Post-invocation error | A recording actual-path signer is invoked and returns an injected error after invocation. The owner records Unknown, holds ownership until the local helper returns, and refuses the next signing attempt. No test may infer no effect from `Err`. |
| Returned signature, later refusal/failure | Return a real disposable-key signature, then inject each reachable verification/serialization/F7/engine/publication failure. Preserve the signature fact and stage observations; distinguish engine mutation, publication attempt and publication API result. |
| Revocation ordering | Barrier before permit: revocation wins, no signer call. Barrier after permit: close admission, allow this owned operation to finish through the specified path, and deny a subsequent permit. |
| Executor completion | Pause the synchronous signer/helper and verify operation ownership remains until helper return; separately request loop shutdown and observe the loop `JoinHandle`. A signer child/external operation requires its own observed completion or remains Unknown. |
| Lost Unknown / missing barrier sensitivity | Deliberately clear sticky Unknown or release ownership before the synchronous path returns; the same production-owner closure checker must expose false acceptance. Exercise a non-vacuous actual signing invocation. |
| Capacity/accounting failure | Exhaust the bounded slot or invalidate operation/outcome association; refuse before a new signer call and refuse closure, with explicit observable status. |
| Restart/durability boundary | Separate future work: process restart after Unknown must refuse before participation under an approved durable intent/classifier. No process-kill test alone establishes power-loss durability or anti-rollback. |

No TSL tests were rerun for this design-only record. Source review confirms
the production Timeout path, test-only limitation, and task shutdown flow
described above; no runtime behavior or participation authority is claimed.

**Remaining OPEN:** Transport, A17-F1 / RS1-F7, RS1 and A33-F1 / E27.
Activation **DISABLED**; public DevNet **NO-GO**.
