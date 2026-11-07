# P1 test-only provider model — implementation and evidence

**P1 TEST-ONLY PROVIDER MODEL — INDEPENDENT REVIEW PENDING.**

Implemented only as an isolated Rust integration-test target:
[`p1_provider_model_tests.rs`](../../../../../crates/qbind-consensus/tests/p1_provider_model_tests.rs).
This target has no production caller, and the change adds no production
module, application/store-writer/signer capability, quarantine-clear path,
participation route, or resume authority. The model uses opaque deterministic
bytes and a sentinel callback; it performs no cryptographic verification or
protocol activity.

The implementation follows the original test-only specification and its
superseding corrections, all present unchanged at the task base
`1d0b66739633b1232187b0cdc04849900f6f411e`:

* [Original P1 provider specification](../p1-provider-model-specification/README.md)
* [P1-SPEC-1/2/3 correction](../p1-provider-model-specification-correction/README.md)
* [Nested evidence scanner-control correction](../p1-nested-evidence-controls/README.md)

The user-supplied **PASS WITH LIMITATIONS** at `1d0b6673` is carried forward.
P1-SPEC-1/2/3 remain PASSED/CLOSED at specification level; the current
implementation has not received independent review. No reviewer identity or
raw review artifact is asserted. Earlier bounded acceptances, the audit
register, and all prior documentation/evidence bytes are preserved.

## 1. Implemented test-only boundary

`ExpectedCatalogFixture` is independently constructed and immutable during
each operation. The candidate supplies claims only; it cannot provide or
replace the expected catalog, provenance-source identity, policy, threshold,
or currentness input. Fixture identity is checked separately from exact
structural comparison. The `Currentness` simulation implements
`Available`, `Unavailable`, `Stale`, `Conflict`, and `Unknown`; only Available
continues. It is not evidence of production freshness, non-rollback, durable
ownership, signer exclusivity, or external authority.

The single-threaded `ProviderSlot` holds one live provider and at most one
lease. Provider and lease identifiers use checked, non-reused increments;
exhaustion refuses without replacing the prior provider or invalidating its
live lease. The provider owns the admitted immutable snapshot and logical
byte charge. A returned non-`Clone` token holds only a `Weak` slot reference
and identity values, not the snapshot. Replacement/destruction invalidate
prior tokens; dropping an old token cannot release a newer lease. A held lease
refuses a second admission before descriptor materialization or decoding.
Dropping the matching token releases the one logical charge. Caller-owned
inputs, allocator capacity, transient allocations, and total memory are not
accounted.

Use rechecks live provider, lease, fixture identity, and independently
simulated currentness before invoking a test sentinel. Replacement, provider
destruction, fixture mismatch, invalidated lease, and every non-Available
currentness status refuse before the sentinel. This is an in-process,
single-threaded test model, not a production ownership fence or signer
exclusivity mechanism.

## 2. Framing and exact boundaries

The test target implements the specified fixture-only `QBP1TEST` candidate
and `QBE1TEST` evidence frames. Candidate fields are ordered, exact-consumed
TLVs. The scanner checks actual segment lengths, checked offsets, field
shapes, member count/key lengths, duplicate identities/keys, and evidence
framing/count/entry lengths before the test decoder. Descriptor entrypoints
gate claimed sizes before the callback, then compare callback-returned byte
lengths to descriptors and recheck actual limits. A descriptor is not treated
as proof that returned bytes match.

Evidence remains a separate segment. The valid maximum candidate is
11,339 bytes, the evidence cap is 19,389 bytes, and the combined descriptor
ceiling is 35,773 bytes. A 16,384-byte candidate descriptor is a size-gate
control, not a valid maximum-schema envelope; the valid maximum-schema bytes
are separately scanned and decoded. A callback returning exactly 16,384
candidate bytes can pass size and descriptor correspondence, but the
non-schema filler is refused by framing before candidate decoding/admission.
Exact 37/40-byte count frames and
2,435/2,436-byte entry-length frames exercise nested evidence predicates.
Nested negatives prove outer-size and framing prerequisites passed and
assert the intended typed refusal with the evidence decoder and crypto
counter still zero. Scanner fixtures are not signature-verification
evidence.

Checked additions protect combined sizes, field offsets, and logical snapshot
accounting. Enforced bounds are limited to already-allocated descriptors,
borrowed slices, and decoded test inputs at their named entrypoints. The
descriptor callback itself may allocate before the returned lengths can be
checked. No socket/framework allocation, allocator capacity, total memory,
runtime, cancellation, concurrent access, persistent storage, or OS/hardware
rollback behavior is measured.

## 3. Executed tests and interpretation

The focused target ran 17 tests: all passed, none ignored or filtered. Their
names and exact outputs are recorded in `COMMANDS.txt` and the captured
`03-focused-provider.log.gz`. The cases cover independently supplied positive
and restored-positive context, complete context mismatches, uniqueness and
trust-selection/omitted-field/currentness sensitivity, the four refusing
currentness states, copied old data with Unknown/Stale simulations, use-time
currentness changes, fixture/provider/lease identity, replacement,
destruction, held-lease blocking, release and re-admission, checked identity
exhaustion, descriptor preflight/returned-length mismatch, size limits,
maximum valid framing, malformed/duplicate candidates, and nested evidence
controls, including use-time evidence refusal before the sentinel.

Related accepted regression targets were run without modifying them:
`authority_context_experiment_tests` passed 9/9 and
`content_binding_experiment_tests` passed 7/7. Full compressed output is
`04-related-regressions.log.gz`. This reruns those tests; it
does not replace or expand the user-supplied earlier review dispositions.

The test-only outcomes establish only that these synthetic model controls
behave as asserted on this toolchain/platform. They do **not** establish
authenticated provenance/currentness, validator endorsements, finality,
recovery-prefix correctness, durable application, crash consistency,
signing-history continuity, fencing, production allocation bounds,
production enforcement, or a separately authorized resume decision.
Conditional P2 authority records and real provisioning/currentness remain
unexecuted. P1/P2 production selection and protocol options B/C remain
unselected. Founder-bootstrap scope remains one exact initial DevNet
configuration; no completed credential ceremony, later-transition
authority, finality, signer override, history reset, recovery-clear, or resume
authority is implied.

Current catch-up containment is unchanged: non-empty catch-up responses
refuse, admitted empty responses are ignored before peer-height/mode effects,
restore mode may remain active indefinitely, and active restore mode is not
a complete engine/worker/signer fence.

**A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain OPEN.
Activation DISABLED; public DevNet NO-GO.**
