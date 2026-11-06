# A33-F1 / E27 test-only owner/lease lifecycle model

**TEST-ONLY OWNER/LEASE MODEL — INDEPENDENT REVIEW PENDING.**

This isolated model and its shared trace checker exercise a candidate
cancellation-safe ownership lifecycle. It is not connected to the node,
consensus engine, quarantine marker, storage backend, startup, CLI, signer,
or network. Publication visibility/acknowledgment, cancellation, supervisor
acceptance, late completion, and restart are deterministic model events, not
actual Tokio scheduling or filesystem operations.

The source-backed snapshot contract and its append-only user-supplied review
corrections are in the
[owner-held snapshot contract](quarantine-owner-held-snapshot-contract.md).
The prior user-supplied **PASS WITH LIMITATIONS** filesystem-prototype review
remains recorded in the
[capacity inventory](capacity-inventory.md); reviewer identity and raw
artifact were not supplied, and this work did not rerun that prototype.

## Refusal-state owner and lease lifecycle

The model starts closed. “Closed” is monotonic: there is no event that
clears the latch or enables participation. The coordinator is responsible
before acquisition; an accepted initiator owns the engine lease and the
operation's refusal state; only an explicit supervisor acceptance transfers
that responsibility and lease. `Lost` means no active lifecycle owner can
continue, not that cleanup or handoff succeeded. In `Lost`, the refusal
state remains closed, pending outcomes remain unresolved, and mutation is
forbidden.

| Transition | Refusal-state owner and model result |
|---|---|
| Before engine admission | Coordinator owns the closed refusal state. Cancellation before acquisition leaves it closed; acquisition after cancellation is rejected. |
| Exclusive engine admission acquired | Initiator owns the lease. A coherent tuple snapshot can be recorded only under this lease. |
| Intent/evidence publication | Initiator retains the lease while visibility and acknowledgment are modeled. Visible-but-unacknowledged, error, and uncertain outcomes stay closed; no protected mutation is admitted without acknowledgment. |
| Acknowledged intent | Initiator still owns the lease. A matching tuple revalidation detects a changed tuple only; it is not the intervening-mutation fence. |
| Initiator cancellation or lease drop | Without accepted transfer, owner becomes `Lost`; outstanding work remains unresolved. Dropping the lease does not count as cleanup, completion, or handoff. |
| Handoff offered | Initiator remains owner. The offer alone changes no responsibility and cannot authorize supervisor mutation. |
| Supervisor accepts | Responsibility and the engine lease transfer to Supervisor. Initiator cancellation thereafter does not revoke the accepted supervisor's ownership. |
| Supervisor loss | Owner becomes `Lost`. No continuation or mutation is admitted; late work can add evidence but cannot resolve Unknown. |
| Completion after cancellation/loss | The model records the observed effect (including `Unknown`) and preserves unresolved/conflict state. It cannot grant participation. |
| Application/task completion/ordinary cleanup | Existing known effects remain; task completion and cleanup do not clear refusal or authorize another operation. |
| Modeled restart | Owner returns to the startup coordinator role with no live engine lease. The prior acknowledgment is not reused as a live permit; pending work remains unresolved and no new operation can begin in this model. |

Other effect domains (signer, storage, snapshot, callback, outbound) begin
with independent ownership `Unknown`. The engine lease changes none of them.
For protected engine mutation, this model requires a separate owner to accept
each domain and report its admissions fenced with no pending, unresolved, or
conflicting work. This is a conservative test-model condition, not a selected
production barrier policy or proof of a real fence. Unowned admission fails;
loss with pending work preserves the obligation as unresolved. No
generation-counter alternative is modeled or selected.

### Candidate API shape — not implemented

The test model's explicit events correspond to this conceptual result
contract; this sketch is not a Rust production API:

```text
acquire_exclusive_engine_lease() -> Lease
snapshot_under_lease(&Lease) -> StartingAnchor
publish_applying_and_ack(&Lease, operation, response, bindings, snapshot)
    -> Acknowledged | Failed(visibility: NotVisible | Visible | Unknown)
transfer_to_supervisor(&Lease, supervisor)
    -> AcceptedLease | StillInitiatorOwned
apply_only_with(&AcknowledgedIntent, &Lease)
record_monotonic_outcome(owner, domain, operation_id, outcome)
```

Invariants exercised by the model:

* Refusal remains closed before/after acquisition, during publication, after
  acknowledgment, on error/uncertainty, on cancellation/drop, after transfer,
  after completion/cleanup, and after modeled restart.
* Protected engine mutation requires a live initiator/supervisor lease and a
  certain acknowledged intent. Failed, visible-unacknowledged, or uncertain
  publication cannot authorize mutation.
* Handoff is effective only after the receiver accepts. Initiator cancellation
  after acceptance leaves the supervisor responsible; supervisor loss leaves
  no active owner and remains refused.
* Tuple change is rejected. An intervening mutation invalidates the lease;
  equality after an ABA-like change does not restore ownership or authorize
  mutation. This assumes a real lease excludes every relevant engine mutation;
  the model does not prove that assumption.
* Late outcomes preserve known effect facts and Unknown. Duplicate and
  out-of-order completions create/retain conflict or unresolved state and
  cannot clear it.
* Separate external-domain owners default to Unknown and are never inferred
  from engine ownership; protected mutation is rejected until each modeled
  domain is independently accepted and fenced with no unresolved work.

## Supplied review corrections and source distinctions

The review corrections are attributed to the user-supplied report; no
reviewer identity or raw report artifact is claimed.

1. Tuple equality detects only tuple differences between the two reads. It
   does not detect every intervening mutation, including ABA or mutations
   outside the tuple. Loss or uncertainty of the required lease itself
   refuses, even if a later tuple compares equal. A generation mechanism is
   a separately reviewable alternative requiring atomic admission/revocation,
   complete mutation coverage, and overflow refusal; it is not selected or
   modeled as a production fence.
2. The response handler invokes sender binding at
   `crates/qbind-node/src/binary_consensus_loop.rs:7393-7410`. The binding
   closure at `:6097-6160` uses the installed gate's `authorize(origin,
   claimed)` path; when the gate is `None`, the explicit fallback returns
   `Ok(claimed)` and source comments identify it as test-only
   (`:6061-6090`). Tests also directly call the response handler
   (`:10078-10091,10175-10188`), bypassing that closure. These are distinct
   installed-gate, no-gate test, and direct-handler modes. They do not prove
   an unauthenticated production route or the configuration of a built
   deployment.

The prior source review remains: in the live loop, the engine is a local
mutable value dispatched synchronously by the loop task; this serializes only
that loop. The actual empty-response path can update restore-mode transition
state from peer-reported height before any anchor comparison, while
nonempty responses compare the local request anchor before applying blocks.
Those source facts do not imply that an engine lease fences signer, storage,
snapshot, callback, or outbound work.

## Executed model tests

Exact focused commands:

```sh
rustfmt --edition 2021 crates/qbind-node/tests/a33_f1_quarantine_owner_lease_model_tests.rs
rustfmt --edition 2021 --check crates/qbind-node/tests/a33_f1_quarantine_owner_lease_model_tests.rs
cargo test -p qbind-node --test a33_f1_quarantine_owner_lease_model_tests -- --nocapture --test-threads=1
```

Observed result: **11 passed, 0 failed, 5 ignored**. The five ignored tests
are intentionally defective child fixtures; they are not passing security
tests. The parent test launched all five; each exited with status 101 and the
expected checker diagnostic:

| Deliberate negative control | Expected checker rejection |
|---|---|
| Dropped lease reopens participation | Reopen transition is forbidden |
| Handoff treated as complete before receiver acceptance | Transfer without offered-and-accepted ownership is rejected |
| ABA-equivalent tuple accepted after intervening mutation | Tuple equality cannot restore invalidated/lost lease |
| Late completion clears unresolved obligation | Cancellation/loss keeps the obligation unresolved |
| Duplicate completion clears conflict | Duplicate/out-of-order completion cannot clear conflict/Unknown |

Negative controls are sensitivity checks, not passing lifecycle outcomes.
The passing positive controls cover cancellation before lease and before
visibility, visible-but-unacknowledged and acknowledged cancellation, failed
publication visibility states, accepted supervisor handoff and subsequent
initiator cancellation, lease drops before/after acknowledgment, supervisor
loss, late completion after owner loss, external-domain Unknown, duplicate
and out-of-order completion, ordinary cleanup, task completion, and modeled
restart. No separate child command was run; expected child failures were
verified by the parent launcher in the focused command above.

The initial focused compile failed because `Effect` lacked `Ord` for the
model's `BTreeSet`; the derive was corrected and the final focused command
passed. This test-build iteration is recorded, not silently omitted.

The first expanded run also exposed a misplaced nested test and showed that
the supervisor-publication positive trace had not explicitly fenced each
independent effect domain. The test was moved to module scope and the model
was tightened so protected mutation requires each separate domain owner to
accept and fence with no unresolved work. A rerun then passed 11 tests with
the five expected ignored children. These are resolved model/test iteration
failures; the retained focused log contains the final successful
command/output and all five expected child failures.

## Assurance limits and remaining blockers

This is a deterministic state/trace model. Mocked publication does not prove
visible bytes, synchronization, crash/power-loss durability, or failure-after-
publication behavior of a filesystem. Recorded cancellation events do not
exercise actual task drop, abort, unwinding, runtime scheduling, or process
termination. Modeled supervision does not prove a supervisor can survive or
accept handoff. Modeled restart does not reconstruct a process or gate startup.
No engine, marker, startup, CLI, signer, filesystem, network, or node path was
invoked. No signer exclusivity, external-domain fencing, currentness,
anti-rollback, storage durability, automatic clear, resume, or allow authority
is established.

Implementation remains blocked on a production owner/admission API that
cannot lose its refusal responsibility on task cancellation; an acknowledged
Applying publisher with explicit uncertain-visibility semantics; verified
receiver-acceptance transfer and restart handling; and independent ownership,
drain/fence, and outcome reporting for every external effect domain. The
engine lease must not be presented as a process-wide or deployment-wide
fence. A33-F1 / E27 and remaining obligations remain **OPEN**; activation
**DISABLED**; public DevNet **NO-GO**.
