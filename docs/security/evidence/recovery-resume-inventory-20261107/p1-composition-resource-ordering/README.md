# P1 composition resource-ordering control

**P1 COMPOSITION RESOURCE-ORDERING CONTROL — INDEPENDENT REVIEW PENDING.**
The five composition controls accepted at
[`58ea48c1bb1d20526143cf2737767c912fd0f365`](https://github.com/olivexo28/QBIND/tree/58ea48c1bb1d20526143cf2737767c912fd0f365)
remain accepted within their test-only scope. The previously disclosed
signature-copy/frame-before-provider ordering was a test-harness limitation,
not an established production vulnerability.

## Starting order and corrected call

At the starting revision,
`support/p1_content_composition.rs::compose` first cloned every signature into
owned `Vec<u8>` values and called `encode_evidence`, then called
`ProviderSlot::verify_use`. That use path performs provider/liveness,
fixture, lease and currentness checks. The new private defective-ordering
control reproduces that sequence using a destroyed provider and the original
valid three-signature evidence: it observes 7,260 signature-copy bytes and
one frame construction, then `ProviderDestroyed`; callback and backend counts
remain zero. This demonstrates the model's pre-existing ordering and is not
a production-network allocation observation.

The corrected `compose` builds only a test-owned vector of borrowed signature
slice references before calling `verify_use_with_borrowed_entries`. The
pointer-reference vector is metadata allocation; it copies no signature
bytes. Inside the provider use boundary, while a single-threaded immutable
`RefCell` borrow keeps the live instance and lease relationship in scope, the
method checks provider liveness and instance, bound fixture, lease, and
independently simulated currentness. It then checks actual borrowed slice
count, each actual length, checked aggregate frame arithmetic, and evidence
and combined caps. Only after these succeed does the callback compare witness
context, clone signature bytes for the verifier, build a frame from those
same copied signatures, scan the actual frame, and compare scanned entries
byte-for-byte with the copied entries before invoking the existing
content-binding verifier with those copied signatures. The callback and
verification complete before the provider borrow ends; replacement cannot
interleave in this single-thread test model. This is not thread-safe ownership
or production fencing.

## Limits and stage evidence

The provider's accepted evidence limits are 1–8 entries, each 1–2,420 bytes,
and checked encoded frame length `13 + Σ(2 + entry_len)` no greater than
19,389 bytes. Eight 2,420-byte entries exactly equal 19,389 bytes; given the
per-count and per-entry maxima, a valid bounded set cannot exceed that
aggregate cap. The separate combined ceiling is checked with candidate length
zero because this test composition has no encoded candidate argument in the
evidence frame. Arithmetic overflow is tested directly on synthetic length
metadata `usize::MAX`; no such byte slice is allocated or claimed.

`composition_preflight_limits_before_signature_copy_and_frame` has three
useful controls:

* Three actual, valid 2,420-byte signatures pass all provider preflight
  stages, are copied (7,260 bytes), framed, scanned and reach the real
  verifier (three calls, success).
* Eight caller-allocated 2,420-byte entries pass the exact frame cap, are
  copied (19,360 signature bytes) and framed to 19,389 bytes. The existing
  content experiment then independently refuses `TooManyEndorsements` at its
  four-member committee bound, before encoding/backend. This is a valid
  resource-bounded frame, not a valid verifier quorum.
* Nine one-byte entries refuse `EvidenceEntryCountExceeded`; one 2,421-byte
  entry refuses `EvidenceEntryTooLarge`. Provider identity/fixture/lease and
  Available-currentness checks and count check pass; length check runs only
  for the one-entry case. Both negatives have zero callback, signature-copy,
  frame and backend counts. The caller has already allocated these test
  inputs; the controls are not pre-ingress or pre-allocation guarantees.

`composition_provider_and_currentness_refuse_before_evidence_copy_or_frame`
demonstrates replacement-invalidated and destroyed leases, and Stale and
Unknown currentness. Each reaches its specific provider/currentness refusal
before signature copying, frame construction, callback or backend. New
admission after explicit B replacement passes the same real verifier.
`defective_order_copies_and_frames_before_provider_refusal_is_detected`
uses the same copy/frame/provider observations to show the old order fails
the `refusal_precedes_materialization` oracle.

Counters report operation counts and byte lengths at explicit test sites.
They do not measure Vec capacities, allocator internals, total memory, runtime,
cancellation or external ingress allocations. Test fixture setup and caller
inputs are already allocated before composition. The 8-entry limit case
cannot be a valid verifier input because the existing hypothetical verifier
uses four committee slots.

The focused target ran 37 cases: 19 provider-model tests, 3 accepted
provider-to-verifier tests, 7 accepted content-binding tests, 5 accepted
composition tests, and **3 distinct new ordering controls**. It passed 37/37,
with 0 failed/ignored/filtered. Directly affected provider and handoff target
executions each also passed 37/37; standalone content target passed 7/7.
Those are repeated test bodies, not additional distinct tests. Intermediate
compile and assertion failures are retained and described in `COMMANDS.txt`.

The model remains test-only: no production provenance/currentness, finality,
durable application, signer fencing or resume authority is established.
The statement and 3-of-4 threshold remain hypothetical fixtures. B/C and
production P1/P2 remain unselected; catch-up containment is unchanged.

A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain OPEN.
Activation DISABLED; public DevNet NO-GO.
