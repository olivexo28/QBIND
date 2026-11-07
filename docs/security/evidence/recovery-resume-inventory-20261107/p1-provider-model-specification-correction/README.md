# P1 provider specification correction

**P1 SPECIFICATION CORRECTION — INDEPENDENT REVIEW PENDING.**

Documentation-only correction to the P1 provider model specification at
commit `6914c6257f11b55fddb0f24de42a1a0ed316ca7f` (tree
`3a9aeab263f14f74a3b98e92e5a98c81ba280ac1`). It records the user-supplied
**CHANGES REQUIRED** disposition. These are specification findings, not
demonstrated production vulnerabilities or executed model failures. No
reviewer identity or raw review artifact is asserted.

The original specification at
[`../p1-provider-model-specification/README.md`](../p1-provider-model-specification/README.md)
and its raw outputs remain byte-for-byte historical evidence. This correction
is authoritative where it conflicts with it, specifically:

| Finding | Earlier text superseded |
|---|---|
| P1-SPEC-1 | Section 3 `Matching independent context` decoder counter; section 3 `Duplicate/ambiguous identities/keys` whole-path sensitivity assertion. |
| P1-SPEC-2 | Sections 1.1-1.2 ownership, provider-lifetime, result-snapshot and use-after-replacement/destruction descriptions; section 2 retained-copy claims; section 3 related use/lifetime cases. |
| P1-SPEC-3 | Section 2 generic 4,096-byte field bound, evidence/envelope relationship, encoded-segment accounting and entrypoint materialization descriptions; section 3 size/count boundary descriptions. |

All other accepted boundaries remain: expected catalog, attribution and
simulated currentness are independently supplied; candidate claims are
untrusted; `Unavailable`, `Stale`, `Conflict` and `Unknown` refuse; no
application/signing/clear/resume capability is granted. The accepted
provenance contract, earlier bounded acceptances and their evidence are
preserved and not rerun.

## 1. P1-SPEC-1 — Stage-specific oracles

Every proposed test below is **FUTURE / NOT EXECUTED**. The counters name
distinct events; do not infer one from another:

* `structural_checks`: decoded field-shape and required-field checks entered.
* `uniqueness_checks`: strict duplicate identity/key predicate entered.
* `context_comparisons`: full candidate-to-independent-catalog comparison
  entered.
* `admissions`: provider admission completed.
* `borrowed_scans`: already-allocated envelope scanner entered.
* `decoders`: envelope decoder invoked after the borrowed scan accepts.
* `materializers`: descriptor-controlled callback invoked.
* `crypto_calls` and sentinel-effect callbacks are separate downstream
  observations; provider-context cases do not infer them from admission.

### Decoded positive and envelope-decoder attribution

`test_admit_decoded_candidate(expected_fixture, candidate_by_value,
Available)` receives an already allocated, typed candidate. The strict
positive oracle requires `structural_checks > 0`, `uniqueness_checks > 0`,
`context_comparisons > 0`, and `admissions == 1`, with no refusal/effect.
`decoders == 0` is expected for this entrypoint: decoding occurred before it
was called and is outside its observation boundary. A restored-positive
control reuses the original valid decoded value after a negative test and
requires the same stage counters/outcome.

Only `test_scan_borrowed_envelope_then_decode` may receive decoder credit.
It is supplied an already allocated borrowed envelope slice and separately
bounded evidence slice. A structurally valid candidate must show
`borrowed_scans == 1`, `decoders == 1`, then the expected strict stage
counters and result. The scanner does not account for the allocation that
created either borrowed slice.

### Duplicate identity/key controls

Keep the independently supplied expected catalog valid and unchanged. Start
from a structurally well-formed candidate with valid lengths, required fields,
supported version, independently supplied `Available` currentness, and all
non-uniqueness structure checks passing. Mutate only the candidate to repeat
one member identity or one public key. Use separate tests for each mutation.

For each mutation, call
`test_strict_uniqueness_stage(candidate)` at its own test-only stage boundary.
Its oracle is `uniqueness_checks == 1` and typed `Ambiguous`. A private
`test_omitted_uniqueness_mutant(candidate)` runs against the same candidate
and must fail that stage oracle (it reports no `Ambiguous`; the mutant's
result demonstrates that the strict uniqueness assertion detects the
omission). No mutant is a production path or a full-pipeline admission
oracle.

Then report the complete strict pipeline independently: it stops at
`Ambiguous`, before full-context comparison. In a separate diagnostic run,
the private mutant may proceed to exact comparison; because the malformed
candidate no longer equals the unchanged valid expected catalog, that
comparison must independently return `ContextMismatch`. Report this as a
second defense, not as a reason to require whole-pipeline admission or to
weaken exact comparison. Neither strict nor mutant full-pipeline acceptance
is expected. Restore the original candidate and require the decoded and
borrowed-envelope positive controls above to pass again.

For every negative, assert the required preconditions and stage counter before
crediting the intended refusal. An earlier shape, size, context, currentness,
or parser refusal does not establish duplicate-check sensitivity. No
signature, application, or real provider effect is implied.

## 2. P1-SPEC-2 — One owner, one lease, no copied result snapshot

The proposed model is a deterministic, single-threaded test model with an
independently constructed immutable `ExpectedCatalogFixture`, a stable
`ProviderSlot` owner, and at most one live provider instance in that slot.
The fixture and the `Available` currentness observation remain independent
inputs. This is an ownership simulation only; it is not thread-safe provider
fencing, durable ownership, external currentness, or signer exclusivity.

### Identity and lease state

Each provider instance receives a slot-local, monotonically increasing
`ProviderInstanceId`; each successful admission receives a monotonically
increasing `LeaseId`. IDs are created by checked increment before publishing
the instance/lease. They never wrap or get reused. Exhaustion returns typed
`IdentityExhausted`/`LeaseExhausted` without admitting, replacing or
revalidating under a recycled identity. A failed replacement leaves the old
instance unchanged. No generation token is needed.

`ProviderSlot` owns the current instance state and the sole optional
`LeaseRecord { instance_id, lease_id, fixture_id, immutable_snapshot,
logical_charge }`. A returned `AdmittedTestContext` is a non-`Clone` token
containing only those identities and a weak reference to the slot. It carries
no snapshot bytes and cannot keep the provider alive. The slot, not the
caller-held token, owns the single immutable admitted snapshot. Use requires
the same live slot instance, matching IDs, matching independently supplied
fixture identity, and independently supplied `Available` currentness. The
use callback receives only a temporary immutable borrow; no snapshot is
returned or cloned.

`replace_current` first allocates a fresh instance ID, then atomically removes
the old lease/snapshot and installs a new instance. A still-held old token
fails use as `ProviderReplaced`, even when the fixture is unchanged and
currentness remains `Available`. `destroy_current` removes the active instance
and lease; a still-held token fails `ProviderDestroyed` under the same
fixture/Available conditions. Destroying the slot itself drops its owned
snapshot; a weak token cannot preserve it. These typed failures are caused by
owner identity/liveness checks, not stale-currentness checks.

Dropping the non-cloneable token releases the active lease only if its
instance and lease IDs still match the slot; it then drops the snapshot and
releases the logical charge. If the lease has already been cleared by
replacement/destruction, dropping the old token is a no-op. A second
admission while a first token/lease is held returns `LeaseHeld` before
materialization/decoding and does not overwrite the first snapshot. After
the token is dropped and its matching charge released, admission may proceed.
There is no API to clone a token or snapshot. Caller-side copies made before
calling the model are outside its enforceable accounting and must be
identified as such.

### Ownership and copy ledger

* Already-decoded admission takes the bounded typed candidate by value and
  moves its owned fields into the one `LeaseRecord`; it does not clone them.
  The caller cannot retain that moved value. Inputs allocated before the call
  are still already-allocated test inputs.
* Borrowed-envelope admission scans the caller-owned bytes and, only after
  scan success, decodes once into one owned snapshot. It retains that decoded
  snapshot, not an envelope copy; caller-owned borrowed bytes remain outside
  the model's ownership.
* Descriptor admission invokes a callback only after claimed lengths pass
  checked limits. Returned owned segment buffers exist at callback return;
  the scanner borrows them, then one decoded snapshot is created. Segment
  buffers are dropped after decoding; the moved decoded snapshot alone is
  retained. Callback allocation and allocator capacity are not hidden by this
  logical copy model.
* Evidence is separately borrowed by `verify_use`; it is not retained in the
  provider lease. The use operation holds at most one bounded temporary
  decoded view and drops it before return. It does not duplicate the stored
  snapshot.
* The active lease's logical charge is the sum of normalized field byte
  lengths: fixed identity/context/policy/threshold fields, content bytes, and
  each member identity, key and weight. Checked arithmetic computes it before
  publishing the lease. It is an accounting value, not allocator capacity,
  object size, RSS or a total-memory bound.
* At most one snapshot charge may be live per slot. The charge is released
  exactly when the matching lease is dropped, replaced, destroyed, or the
  slot is dropped. A mismatched/old token cannot release a newer lease's
  charge because IDs must match.

Proposed test controls, all keeping the same independently supplied fixture
and `Available` currentness:

| Control | Required setup/oracle |
|---|---|
| Live-provider use | Admit once; use through the same live instance; require identity/lease/currentness checks and callback success. |
| Provider replacement | Hold token, replace instance successfully, then use old token; require `ProviderReplaced`, identity-check counter, and zero use callback. |
| Provider destruction | Hold token, call `destroy_current`, then attempt use through the still-existing slot; require `ProviderDestroyed`, liveness-check counter, and zero callback. |
| Second admission while retained | Hold first token; second admission returns `LeaseHeld` with materializer/decoder/admission counters unchanged; first token still works. |
| Admission after release | Drop first token; assert charge is zero; a new admission succeeds and can be used. |
| Identity exhaustion | Set only the private test counter to its maximum; replacement/admission refuses without wrapping/reuse and without invalidating the old live state. |

All cases are FUTURE / NOT EXECUTED. A sentinel callback proves only this
model's call ordering. The model establishes no cross-process property,
non-rollback, concurrent ownership, external authority, signing exclusivity
or real currentness.

## 3. P1-SPEC-3 — Exact test-only framing and separate budgets

This is a proposed test fixture encoding solely to make scanner and boundary
oracles reviewable. It is not a production wire format, canonical consensus
encoding, cryptographic commitment, or production resource policy.

### Candidate envelope bytes

The candidate envelope is one byte slice. It contains authority/context
claims and the bounded content claim, but no evidence signatures:

```text
header:
  magic       8 bytes, exactly ASCII "QBP1TEST"
  total_len   u32 little-endian, total envelope length including this header
fields:
  repeated records, in strictly increasing tag order:
    tag       u16 little-endian
    value_len u32 little-endian
    value     exactly value_len bytes
```

Exactly the following 12 tags are required, once each, in order; no unknown
or duplicate tags, alternate ordering, padding, or trailing bytes are
accepted. Header length must equal the actual slice length. All additions,
multiplications, conversions and end offsets use checked arithmetic before
slice access, allocation, or decoder callback.

| Tag | Exact value |
|---:|---|
| 1 | Network identity: 32 bytes |
| 2 | Genesis identity: 32 bytes |
| 3 | Purpose: u16 LE |
| 4 | Test schema version: u16 LE |
| 5 | Epoch: u64 LE |
| 6 | Applicability start and end: two u64 LE values |
| 7 | Authority identifier: 32 bytes |
| 8 | Provenance-source identifier: 1-32 bytes |
| 9 | Test policy version: u16 LE |
| 10 | Members: count u8 (1-8), then for each member identity 32 bytes, public-key length u16 LE, exactly 1,312 public-key bytes, and weight u64 LE |
| 11 | Threshold: u64 LE |
| 12 | Content claim: 0-256 raw bytes; the TLV value length is its length |

Member tag 10 is at most `1 + 8 * (32 + 2 + 1,312 + 8) = 10,833`
value bytes. Other tag values have the fixed sizes above, except source ID
and content claim. The largest structurally valid envelope is therefore:

```text
12-byte header + 12 * 6-byte TLV headers
+ 32 + 32 + 2 + 2 + 8 + 16 + 32 + 32 + 2 + 10,833 + 8 + 256
= 11,339 bytes.
```

This is a feasible valid at-limit fixture for 8 members, 1,312-byte keys,
32-byte source ID and 256-byte content. It is below the separate
16,384-byte envelope ceiling. The 16,384-byte ceiling test is deliberately
**size-gate-only**: a 16,384-byte descriptor passes the descriptor-size
predicate without inspecting or materializing bytes. If its callback later
returns exactly 16,384 bytes, the actual-length gate also passes, but strict
framing cannot accept that buffer as a valid envelope under this exact
schema; it must not be reported as a successful decode or admission. A
16,385-byte claimed or actual envelope refuses at its corresponding size
gate before the next stage.
Separate valid 11,339-byte max-schema fixture proves scanner/decoder progress.

The reproducible max-schema fixture values are: network `[0x10; 32]`,
genesis `[0x20; 32]`, purpose `1`, schema version `1`, epoch `7`,
applicability `[0, 10]`, authority `[0x30; 32]`, source ID `[0x40; 32]`,
policy version `1`, eight members with IDs `[i; 32]` for `i = 1..=8`,
keys `[0x50 + i; 1,312]`, weight `1` each, threshold `5`, and content
`[0x60; 256]`. This byte pattern specifies lengths and deterministic values;
the key-shaped byte arrays are opaque test data, not generated/validated
production keys or cryptographic evidence. Encoding the 12 required tags in
order gives exactly 11,339 bytes by the formula above. The restored-positive
control reuses the same encoded bytes and unchanged independent fixture after
the negative case; it does not regenerate or reinterpret them.

### Evidence bytes and total checked input

Evidence is a second, separately framed byte slice. It is never counted as
part of the candidate envelope:

```text
header:
  magic       8 bytes, exactly ASCII "QBE1TEST"
  total_len   u32 little-endian, total evidence length including header
  count       u8, 1-8
entries:
  entry_len   u16 little-endian
  entry       exactly entry_len bytes, 1-2,420
```

No trailing bytes are allowed; total length equals actual slice length.
Maximum evidence frame is
`12 + 1 + 8 * (2 + 2,420) = 19,389` bytes. Eight 2,420-byte entries thus
consume 19,360 payload bytes and **do not** overflow the 16,384-byte
candidate-envelope ceiling because evidence is a separate segment. Evidence
has its own 19,389-byte frame cap. The separately checked combined encoded
input maximum is `16,384 + 19,389 = 35,773` bytes; check each segment and
checked-add the total before materialization. A ninth entry, entry length
2,421, evidence frame 19,390, envelope 16,385, or combined sum overflow
must produce the corresponding typed refusal before decoding/effect.

There is no extra statement/content segment in this proposed P1 envelope:
the content claim is tag 12. If a later verifier introduces a distinct
statement segment, it needs a separate reviewed length/copy budget and
entrypoint; it is not implicitly covered by either frame.

### Entry-point allocation and descriptor correspondence

| Entry point | Inputs and boundary |
|---|---|
| `test_descriptor_gate_only` | Receives already allocated descriptors (claimed envelope and evidence lengths); checked arithmetic tests only the size predicate and does not call materializer, scanner or decoder. The 16,384-byte descriptor is a size-gate pass only. |
| `test_admit_descriptor_then_materialize` | Receives descriptors plus callback. Check each segment and checked combined length first. Only then call once for owned envelope/evidence `Vec`s. Compare returned actual lengths exactly to descriptors, then independently recheck actual per-segment limits, combined sum, framing and exact consumption before decoding. Any mismatch is `DescriptorMismatch` or the more specific actual-length refusal; decoder count stays zero. A descriptor never proves returned bytes match. |
| `test_scan_borrowed_envelope_then_decode` | Receives already allocated borrowed envelope and evidence slices. Checks actual lengths, framing, tag order, all nested lengths/counts, exact consumption and duplicates before one decoder call. It does not protect the earlier slice allocation. |
| `test_admit_decoded_candidate` | Receives already allocated decoded candidate and separately bounded borrowed evidence, with the candidate moved by value. No envelope bytes, scanner or decoder are involved. It checks decoded structure/unique members/exact expected context before admission. It is not a preallocation gate. |
| `test_verify_use` | Receives a lease token and already allocated borrowed evidence bytes. Checks provider/lease/fixture identity and independent currentness before a borrowed verification callback. Neither bytes nor decoded evidence are retained in the provider slot. |

The descriptor fixture uses exact declared byte counts, then callback variants
returning the exact size, one byte fewer and one byte more. Exact match reaches
the actual scanner; either mismatch refuses before scanner/decoder. A
descriptor within bounds whose materialized bytes exceed a segment cap is
refused by the actual-length check. This demonstrates descriptor/actual
comparison, not control of allocations performed by the callback or transport.

### Feasible boundary fixtures and what is measured

* **Envelope size:** a `16,384`-byte descriptor passes
  `test_descriptor_gate_only`; `16,385` refuses. This is explicitly not a
  structurally valid envelope. A valid maximum-schema envelope is exactly
  `11,339` bytes by the formula above, uses eight members and reaches the
  decoder; restore its original bytes after negative controls for the
  positive/restored-positive oracle.
* **Members/keys/source/content:** the valid maximum-schema envelope gives
  eight members and 1,312-byte keys with exact 32-byte IDs/source and 256-byte
  content. Separate one-field mutations append a ninth member, set one key
  length to 1,313, source length to 33, or content length to 257; all other
  fields remain the deterministic positive values. These are not combined
  with the 16,384-byte size-gate fixture.
* **Evidence:** a separate valid 19,389-byte evidence frame has eight
  2,420-byte entries whose payloads are `[i; 2,420]` for `i = 1..=8`.
  Separate cases append a ninth `[0x09; 2,420]` entry, set one entry to
  2,421 bytes, or append one byte to make 19,390 bytes. These are
  size/scanner fixtures only unless a test explicitly exercises
  cryptographic verification.
* Encoded lengths and the checked logical snapshot charge are counted.
  `Vec::capacity`, allocator/object/map overhead, transient decoder
  allocations, caller-owned input buffers, callback allocation, stack/heap,
  RSS, concurrent requests, runtime and cancellation remain unmeasured.
  Passing a size gate is not proof of valid structure, and a count/field
  maximum alone does not assert every independent maximum is jointly
  feasible under the aggregate cap.

The actual boundary tests and restored-positive controls remain FUTURE /
NOT EXECUTED. No production wire format, production memory/runtime limit,
cryptographic commitment or resource guarantee is selected.

## 4. Preserved boundaries and status

The independent expected catalog, provenance attribution and simulated
currentness remain separate from candidate claims. `Unavailable`, `Stale`,
`Conflict` and `Unknown` continue to refuse; a local ID, marker, generation,
or matching copy does not prove no newer authority exists. Founder approval
remains limited to the exact initial DevNet configuration in its accepted
decision; it does not imply completed credential ceremony, later-transition
authority, finality, signer override, history reset, recovery clear, or
resume permission.

Provider/context verification remains separate from consensus finality,
authenticated historical binding, durable application, crash recovery,
signing-history continuity, fencing, signer exclusivity, quarantine clear and
an independently authorized resume decision. Current catch-up containment
and restore-mode liveness limits are unchanged.

All proposed model cases, including the corrected stage, provider-lifetime
and byte-boundary cases above, remain **FUTURE / NOT EXECUTED**. No Rust tests
or builds were rerun. P1/P2 production approaches and B/C remain unselected.

**A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain OPEN.
Activation DISABLED; public DevNet NO-GO.**
