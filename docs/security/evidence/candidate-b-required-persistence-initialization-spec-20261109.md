# QBIND — Required-persistence initialization specification and future test plan

**DOCUMENTATION-ONLY SPECIFICATION — OWNER-APPROVED DIRECTION, NOT AN
APPROVED API OR IMPLEMENTATION.** When persistent storage is requested,
initialization must establish a successful open before making an
executable service available. If that open fails, initialization must
return an identifiable refusal and must not publish a service that can
silently execute in memory. A timeout, worker panic, missing response, or
other infrastructure failure is not an affirmative refusal. Explicitly
selected in-memory operation is separate.

This direction selects no exact API, error type, test seam, production
implementation, or operational procedure. The existing path-encoding
baseline remains not integration-ready; its four contract failures and
historical author-run evidence are retained. The corrected consensus
result-category oracle is CLOSED within its test scope. Same-captured-path
identity, pre-wrapper refusal, complete backend effects, and startup
ordering remain open. The no-replacement-database finding, CB-1, and
CB-FIXTURE-1 retain their accepted scopes. A23-F1 and A33-F1 / E27 remain
OPEN; activation remains DISABLED; public DevNet remains NO-GO.

## Pinned basis and scope

| Reference | Revision |
|---|---|
| Main source baseline | `aa382fa28b2d3e97e6203d47fa8231b5f2269741`, tree `f1a7d40993bfefbe18635bd637a100ad5527d875` |
| Reviewed observability assessment | `b2b5378a705e7cbdd8e087f636107029785b0f48`, tree `103eba0e3bb4f359c3adaffece6d8db82d542be1` |
| Reviewed test and oracle-correction evidence | `2c387809e9a58d80ff9e9a92d7e14708f824f6aa`, tree `134d2f5d3070d31aa40e2df49ce3acbed7c4c3ed` |
| Earlier baseline and retained raw logs | `e5820cec9b942002c95dc14eeb22a1302f3e9a63`, tree `ef1adec8184a3b14e4d5f4e13aec498b956608a9` |

Source line references below are pinned to main. Test and evidence
references are pinned to their reviewed endpoints. The cited raw test logs
are historical artifacts; this document does not modify or reproduce
them.

## 1. Proposed observable boundary

The proposed boundary is the point at which a caller is given a usable
service capability that can accept executable work. Before that point, the
requested backend must be known to have initialized successfully. A
returned handle, a spawned thread, or a successful enqueue is not by
itself proof of that condition.

For **requested persistent storage**, a conforming initialization outcome
must establish both:

1. The specific configured persistent backend open completed successfully
   for that initialization attempt, with its result associated with the
   service instance being published.
2. Only after that success, the caller can obtain the executable service
   capability. If open fails, the caller instead receives an identifiable
   refusal and no executable service is published.

The test needs evidence of the ordering, not just endpoint states. For
success, it must observe a successful persistent-open result and service
availability for the same initialization instance, with availability
strictly after open success. For refusal, it must observe the
contract-defined open-failure refusal and establish that no executable
service capability was returned or made reachable. Lack of a handle or
response is not enough: it can result from a panic, stalled thread,
lost notification, or unrelated initialization failure.

An API might expose this boundary through a synchronous fallible
initializer or a readiness-gated asynchronous initializer. These are
alternatives only; no mechanism or signature is chosen here. If a
readiness handshake is used, “not ready,” “ready,” and “refused” need
observable, distinct states. A waiter timing out while state remains
pending must remain inconclusive, and dropping the waiter must not turn a
pending initialization into a successful refusal.

### Outcomes that must remain distinct

| State | Required interpretation |
|---|---|
| Persistent open succeeds and service is made available afterward | Successful requested-persistence initialization. The evidence must correlate open success and the published service instance. |
| Persistent open fails and an identifiable refusal is returned before service availability | Affirmative persistent-open refusal. No executable service may be published. |
| In-memory mode is explicitly selected without requesting a persistent path | Separate supported positive case. Its explicit configuration or initialization outcome must establish that persistence was not requested. |
| Initialization has not completed by a deadline | Pending / timed out / inconclusive. A timeout is not refusal, success, or proof of termination. |
| Worker panics, initialization response is absent, or the worker becomes otherwise unobservable | Infrastructure failure or unknown state. It is not a successful refusal; worker termination may itself remain unresolved. |
| Generic argument, thread-spawn, or unrelated setup failure | Distinct initialization failure. It must not be reported as a persistent-open refusal unless the contract explicitly identifies the cause. |

## 2. Worker ownership if started before refusal

The simplest ownership property to review would be that no executable
worker is published before persistent storage is ready. This does not
require selecting whether the backend opens synchronously or in an
initialization worker; it specifies the externally observable boundary.

If an implementation starts a worker before it can return a persistent
open refusal, the initialization owner must retain responsibility for
that worker. The refusal outcome must account for whether a worker was
started, request or perform cleanup as specified, and report either:

- observed worker termination, with a join/termination result associated
  with that worker; or
- an explicitly unresolved termination state, which must not be
  represented as a fully cleaned-up successful refusal.

Requesting cancellation, setting a shutdown flag, dropping a waiter, or
dropping a service-like wrapper does not prove that the worker observed
the request or terminated. The owner and test need a way to track the
worker identity/lifetime, await or observe termination, and distinguish
termination from a still-pending or panicked worker. If the worker remains
unresolved, that state must be reported, not silently folded into
refusal.

### Ordering and ownership alternatives

- **Synchronous initialization:** the initializer opens storage before
  returning an executable service. The test observes the returned
  success/refusal and establishes that no worker capable of processing
  work can run before open success. Decisions remain about where the
  worker is spawned, what happens if worker creation fails after open, and
  how opened storage is released on that failure.
- **Readiness handshake:** a non-executable initialization object may
  start work before readiness, but must withhold the executable service
  capability until an explicit ready result follows successful open.
  Initialization ownership must remain responsible for a worker on
  refusal, panic, timeout, or cancellation. The handshake needs distinct
  ready/refused/pending/infrastructure outcomes and a termination
  observation if a worker was started.

Neither alternative is selected. Their key invariant is that no caller
can execute work against a service whose requested persistent backend
has not been established.

## 3. Pinned current behavior, compatibility, and limits

### Construction and current fallback

At pinned main, `SingleThreadExecutionServiceConfig::vm_v0_persistent`
selects VM-v0 with `Some(state_dir)`, while `vm_v0()` selects VM-v0 with
`None` (`crates/qbind-node/src/execution_adapter.rs:449-596`). The
`with_config` constructor returns `Self`, spawns a worker, discards its
`JoinHandle`, and does not expose a readiness result
(`execution_adapter.rs:639-692`). The worker is independently scheduled;
there is no handshake establishing whether the persistent open occurs
before or after the constructor returns (`execution_adapter.rs:856-880`).

Today, if `Some(path)` open fails, the VM-v0 worker logs the failure and
continues with `InMemoryAccountState`; `None` also uses memory, with a
different log indicating that memory was selected without persistence
(`execution_adapter.rs:876-928`). The public `AsyncExecutionService`
returns `Ok(())` for successful queue admission or generic `QueueFull` /
`ShuttingDown` submission errors; it has no initialization or
per-submission completion/refusal result (`execution_adapter.rs:380-437,
1150-1185`). `txs_applied_total` is aggregate transaction metrics, not a
correlated service readiness or refusal outcome
(`crates/qbind-node/src/metrics.rs:4414-4422`).

The owner-approved direction changes the current behavior when persistence
is requested: fallback to in-memory after open failure must no longer
produce an executable service. This does not alter explicitly selected
in-memory mode. The reviewed test records both the current fallback and
the separate explicit-memory positive control; its new refusal assertion
also observes current fallback and fails (`crates/qbind-node/tests/candidate_b_storage_path_encoding_baseline_tests.rs:377-453`
at the reviewed test endpoint). The raw logs and author-run attribution
remain at that endpoint and are preserved.

No pinned source independently establishes that ordinary P2P startup
reaches this adapter. This proposed boundary does not claim normal-node
reachability or current enforcement.

### Compatibility and owner decisions

Implementation entry requires review of:

- Whether existing infallible constructors can change to return a
  fallible initialization result, or must be replaced/wrapped while
  preserving source and binary compatibility for callers.
- Which callers currently create this service and how they must handle an
  identifiable persistent-open refusal rather than receiving a service.
- The error/result representation distinguishing persistent-open refusal
  from thread-spawn failure, invalid configuration, panic, timeout,
  queue-full, shutdown, execution error, and flush error. No public error
  type, variant, or exact diagnostic is selected.
- Whether a readiness object or initializer can safely own and release
  a successfully opened backend if subsequent worker startup fails.
- What happens to work not yet admitted when initialization refuses, and
  whether current callers can continue safely without a service.
- How explicitly selected in-memory operation remains distinct from
  fallback after a requested persistent open.
- Whether and how test-only observation can exercise the real production
  worker path without creating an alternate behavior path.

The separate approved path-encoding test-contract direction continues to
apply to non-representable storage paths. This document selects no
migration, renaming, adoption, or recovery procedure for existing data.

### Separate contracts not settled here

A successful open proves only that the open attempt succeeded according
to the storage API. It does not establish destination authority, filesystem
object identity/binding, namespace or symlink race resistance, ownership,
fencing, or durability of later writes.

This initialization direction does not settle later backend failure after
service availability; transaction admission and correlated execution
outcomes; successful completion semantics; flush errors; shutdown and
pending-work handling; worker panic recovery; restart or recovery; or
startup-route ordering. Those require separate contracts and evidence.

## 4. FUTURE TEST PLAN — NOT EXECUTED

Every control below is **FUTURE / NOT EXECUTED**. No tests were run for
this specification. A synthetic model may validate an oracle's outcome
classification but is not evidence that the actual adapter enforces the
boundary.

### Fixtures and observations

Use temporary test-owned paths only. A test-only controlled persistent
open result may be needed to deterministically exercise open success,
open failure, and a stalled open. Any seam must be separately reviewed
for whether the real adapter worker consumes it; a standalone mock/model
must be labeled synthetic. Record, for each initialization instance:
requested mode, open-start/open-terminal result, service-availability
event, returned refusal or infrastructure outcome, worker identity and
termination state if started, and any submitted-work identifier/outcome.
Do not use operational keys, start a node, or infer behavior from metrics
or filesystem listings alone.

| Scenario | Expected future result | Required observations and sensitivity |
|---|---|---|
| **Successful requested-persistence initialization — FUTURE / NOT EXECUTED** | Positive initialization control. | Open a valid test-owned persistent database; establish the actual open succeeded and the same service became available only afterward. Submit identified work only after availability and use the separately defined completion contract. This is actual adapter evidence only if the real initializer/worker is exercised. |
| **Forced persistent-open failure — FUTURE / NOT EXECUTED** | Identifiable refusal; no executable service available. | Force the real open to fail through a reviewed seam or fixture; assert the contract-defined refusal category and requested-persistence context. Assert no usable service capability was published. Do not require `submit_block` to succeed; if no service is returned, that is the expected early-refusal shape. |
| **Refusal sensitivity against current fallback — FUTURE / NOT EXECUTED** | Current fallback must fail the future refusal oracle. | Exercise actual current adapter behavior, if a separately authorized characterization target remains available, and correlate the admitted test work with an execution result/effect. The refusal oracle must reject observed execution. Preserve the existing historical fallback logs; do not make fallback a passing conformance expectation. |
| **Explicitly selected in-memory mode — FUTURE / NOT EXECUTED** | Positive control, distinct from refusal and fallback. | Select `vm_v0()` / no persistent path explicitly; establish that configuration and initialization outcome; submit identified work after availability and observe its defined completion. This must not reuse a persistent-failure configuration. |
| **Stalled open / initialization — FUTURE / NOT EXECUTED** | Pending or timed out; inconclusive. | Hold the open operation or readiness outcome pending. A deadline must not yield success or refusal. Observe whether a worker exists and whether it is still pending; a missing terminal event stays unknown. |
| **Timeout and missing response — FUTURE / NOT EXECUTED** | Inconclusive / infrastructure observation. | Verify that timeout, channel closure, lost notification, or absent response is not accepted as refusal. Preserve the request and worker state; do not equate dropping the observer with cancellation or termination. |
| **Worker panic — FUTURE / NOT EXECUTED** | Infrastructure failure; not refusal. | Induce panic only in a controlled test fixture. Observe panic/join outcome if the chosen mechanism exposes it. If the worker's termination cannot be established, report unresolved termination rather than completed cleanup. |
| **Worker started before refusal — FUTURE / NOT EXECUTED** | Refusal plus observed termination, or refusal with explicit unresolved worker state. | Track worker ownership and identity. Demonstrate actual join/termination for a claimed clean refusal. Merely requesting cancellation, setting a flag, dropping a waiter, or seeing no applied transaction is insufficient. |
| **Valid early refusal — FUTURE / NOT EXECUTED** | Test passes without successful enqueue when refusal is explicit and no service capability is published. | Assert the identifiable persistent-open refusal before attempting submission. Separately ensure the test can distinguish constructor/setup error, panic, timeout, and missing response. |
| **Unrelated initialization failure — FUTURE / NOT EXECUTED** | Distinct infrastructure/initialization failure, not persistent-open refusal. | Force a non-storage failure (for example worker creation or invalid setup where controllable) and ensure the oracle does not misclassify it as the approved open-failure refusal. |

### What current APIs can and cannot exercise

The current public APIs can:

- select persistent (`vm_v0_persistent`) versus explicitly selected
  in-memory (`vm_v0`) configuration;
- attempt actual construction, submit work, observe generic enqueue
  outcomes and coarse metrics; and
- characterize the current persistent-open fallback, as the retained
  author-run test already did.

They cannot affirmatively report persistent initialization success or
failure before service availability, expose a readiness state, correlate
completion/refusal to a submitted item, observe worker panic or join
termination, or establish that a zero metric means refusal. Therefore the
current public API cannot by itself pass a positive early-refusal test or
establish that a timeout/missing response is terminal. A test that only
checks `with_config` returned, `submit_block` succeeded, `txs_applied_total`
stayed zero, or shutdown was requested cannot establish the owner-approved
boundary.

A future real-adapter test likely needs a separately approved narrow
initialization/open observation and lifecycle outcome seam, or a reviewed
production interface that returns readiness/refusal and worker lifetime
state. The seam must expose the actual adapter's decisions, not replace
them with a model. A synthetic classifier test can verify that the oracle
labels success, explicit refusal, pending, timeout, panic, missing response,
and unresolved termination distinctly; it cannot establish production
enforcement.

## 5. Open owner decisions

- What observable operation establishes “service available,” and what
  capability must remain withheld until persistent open success?
- Should initialization be synchronous or use a readiness handshake?
  Which owner tracks any worker created before readiness?
- How is an open failure distinguished from unrelated startup failures
  without choosing a misleading generic error?
- What owns a successfully opened database if later service/worker startup
  fails?
- How are timeout, panic, missing response, cancellation, and unresolved
  worker termination reported and cleaned up?
- Which existing constructors and callers must change, and what
  compatibility/deprecation path is acceptable?
- What terminal states are promised for work after service availability,
  including flush failure and shutdown? These are intentionally separate
  from this initialization contract.
- Which minimal test seam or public interface can observe the real path
  without implying that a synthetic model proves enforcement?
- What evidence, if any, would establish that a normal P2P startup route
  reaches this adapter? This specification makes no such claim.

Until these questions are separately reviewed, no exact API or operating
procedure is selected. This document does not authorize implementation,
test changes, migration, provisioning, node operation, PR, merge, or
deployment.
