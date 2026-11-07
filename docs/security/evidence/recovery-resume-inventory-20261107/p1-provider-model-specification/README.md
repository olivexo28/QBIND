# P1 provider-envelope and attribution model specification

**P1 PROVIDER MODEL SPECIFICATION — INDEPENDENT REVIEW PENDING.**

Documentation-only decision specification. This does **not** implement P1,
select P1/P2 for production, select B/C, or authorize a wire format,
commitment, quorum/fault policy, operational authorizer or freshness mechanism.

```text
TASK_BASE=5d328c9ad5c15177960b5b5da50f8b181169b723
TASK_BASE_TREE=8f095c72c77599d0ffd62451bef373c71ae68168
PROTECTED_MAIN=9bf0eb43e4e3c601d02d3886d220b0abeb3a103e
PROTECTED_MAIN_TREE=56509b20084ee1cbe2c42fda9d73d87e4c82c33f
P1_PRODUCTION=UNSELECTED
P2_PRODUCTION=UNSELECTED
B/C=UNSELECTED
A17-F1 / RS1-F7=OPEN
RS1=OPEN
A33-F1 / E27=OPEN
ACTIVATION=DISABLED
PUBLIC_DEVNET=NO-GO
```

The user supplied **PASS WITH LIMITATIONS** for the authority-provenance
contract at the base. Its 13 cases remain **FUTURE / NOT EXECUTED**.
The nine authority-context controls remain PASSED/CLOSED within test-only
scope, as do the seven content-binding controls, R/D/S/M and earlier bounded
acceptances. No reviewer identity, raw artifact or rerun is asserted.
This task reruns no Rust tests/builds.

Read first and preserve as governing scope:
[accepted authority-provenance contract at the task base](../authority-provenance-contract/README.md).
The following is a proposed P1 **test-only model specification**, not the
unexecuted cases in that accepted contract being represented as done.

The relevant pinned production distinctions are directly inspectable:
[genesis validator schema and canonical hash](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-ledger/src/genesis.rs#L129-L150),
[boot genesis policy](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-ledger/src/genesis.rs#L1797-L1848),
[genesis-derived set weights and keys](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/genesis_consensus_authority.rs#L334-L440),
[transport bundle signature verification](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/pqc_trust_bundle.rs#L1480-L1556),
[genesis-authority startup refusal](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/main.rs#L5420-L5441),
[production Proposal/Vote authority remains absent](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/main.rs#L6162-L6173),
and [founder-bootstrap decision at the accepted contract revision](https://github.com/olivexo28/QBIND/blob/1d5d12e85f7ad939b731e56bf929d20403d00d11/docs/devnet/QBIND_RUN_422_DEVNET_BOOTSTRAP_AUTHORITY_DECISION.md#L1-L60).
These links are source evidence, not mechanisms selected or activated here.

## 1. Boundary and logical API

### 1.1 Separate fixture, candidate, provider and caller

Proposed test-only components, with no production names/types implied:

| Component | Origin/ownership | Authority allowed |
|---|---|---|
| `ExpectedCatalogFixture` | Constructed by test setup before the candidate; immutable shared borrow (`&`) held by the model for its lifetime | Supplies expected network/genesis/scope, catalog, provenance-source identity and fixed test policy. Its origin is an explicit test assumption, not authenticated production configuration. |
| `CandidateEnvelope` | Bounded candidate bytes or an already-decoded candidate passed separately; may contain claims and attribution text | Untrusted claims only. Cannot choose/replace trusted source, roots, catalog, keys, weights, quorum/threshold, policy, or currentness. |
| `SimulatedCurrentnessInput` | Separate test-controlled input, never a candidate field | Drives only the model's Available/Unavailable/Stale/Conflict/Unknown result. It is not a service, clock, signed witness or real freshness evidence. |
| `P1TestProviderModel` | Test-only value borrowing the fixture and owning at most one bounded candidate snapshot plus one admitted immutable context | Compares exact identity correspondence, classifies simulated currentness and admits a read-only context; no external I/O or durable state. |
| `AdmittedTestContext` | Immutable owned snapshot returned only on scoped admission; bound to fixture identity and a model-local use token | Supplies data to subsequent test-only evidence verification. It has no application, store writer, signer, quarantine-clear, participation or resume capability. |

Expected catalog and attribution come from a separately constructed fixture,
not the recovery witness, responder, candidate envelope, or an identifier
copied out of that envelope. The fixture explicitly states its assumed
provenance source (for example test constant `fixture-source-A`) and source
policy/version. Candidate attribution is a claim to compare, not a way to
choose that fixture. Candidate-supplied committee/threshold/policy/currentness
claims never set the expectation. If claims are present, compare the complete
claims; missing claim fields are not filled from a witness-selected default.
If claims are absent where correspondence is required, refuse as incomplete.

The fixture must be immutable during admission and use. Proposed identity
correspondence is structural equality of the complete normalized-in-test
catalog plus a fixture-instance identity that is not serialized by the
candidate. A local generation/equality token can detect replacement within
this in-process model only; it is **not proof that no newer authority exists**,
not durable ownership, anti-rollback or a cross-process fence.

### 1.2 Inputs, outputs and refusal classifications

Logical operations to review before any test implementation:

```text
admit(
  expected: &ExpectedCatalogFixture,       // independent immutable fixture
  candidate: CandidateEnvelope,            // untrusted, bounded
  currentness: &SimulatedCurrentnessInput  // independent simulation only
) -> Result<AdmittedTestContext, AdmissionRefusal>

verify_use(
  expected: &ExpectedCatalogFixture,
  admitted: &AdmittedTestContext,
  currentness_now: &SimulatedCurrentnessInput,
  evidence: &BoundedEvidence
) -> Result<TestOnlyVerificationResult, UseRefusal>
```

These are specification pseudotypes only. Neither exists in QBIND. Admission
checks descriptor bounds before any candidate materialization when using the
descriptor entrypoint; then parses/copies at most one candidate; validates
exact fields/duplicates; compares attribution and claims to expected; and
classifies currentness independently. A passing result owns the candidate
snapshot and exact admitted-context copy; both retain their fixture identity.
No effects occur on either success or refusal.

| Classification | Meaning in this simulation | Required result |
|---|---|---|
| `Available` | Separate simulated source says the fixture applies at the queried scope/time | Continue only after complete expected/candidate correspondence; never infer from candidate |
| `Unavailable` | Simulated source cannot be read or supplies no observation | `CurrentnessUnavailable`; refuse admission/use |
| `Stale` | Independent simulated observation says candidate applicability is superseded or outside its allowed interval | `StaleContext`; refuse |
| `Conflict` | Independent simulation has two incompatible applicable records or an unresolved successor | `ConflictingContext`; refuse both, never arrival-order select |
| `Unknown` | Simulation cannot distinguish current from stale (including unavailable rollback signal) | `CurrentnessUnknown`; refuse current-use admission/use; do not convert to Available |

Other logical refusals: `EncodedLimitExceeded`, `LengthOverflow`,
`FieldLimitExceeded`, `MemberLimitExceeded`, `Malformed`, `Ambiguous`,
`Unsupported`, `AttributionMismatch`, `ContextMismatch`,
`ApplicabilityMismatch`, `SnapshotIdentityMismatch`,
`InvalidatedBeforeUse`, `EvidenceRefused`. They remain distinguishable for
test oracles. No panic, default acceptance, weak-version fallback, or
success-shaped empty context is permitted. On missing/ambiguous evidence,
retain refusal/Unknown.

At use, recompare the admitted snapshot identity to the separately supplied
fixture and re-query the *independent simulated currentness input*. If
applicability changed after admission, the admitted object is not used:
return `InvalidatedBeforeUse` (or the specific `StaleContext`,
`ConflictingContext`, `CurrentnessUnavailable` or `CurrentnessUnknown`
cause). A counter or callback may prove the modeled effect did not run; it
does not prove a real store/signing API was fenced. No admitted context
survives provider destruction/replacement as authority; it is just test data.

`Available` authenticity/applicability in this fixture is stipulated by test
setup, not cryptographically authenticated. The model tests separation of
inputs and refusal behavior; it cannot establish external provisioning,
non-rollback, durable ownership or signer exclusivity. A generation token,
label match, revision, checksum or equality check alone never proves no
newer authority exists.

## 2. Concrete test fixture bounds and accounting

These are **chosen for a bounded test fixture**, not production policy,
wire format, network admission, total memory, deadline or cancellation limits.
The chosen maxima exercise both exact-boundary acceptance and one-beyond
refusal; they require independent review before implementation.

| Counted object/field | Chosen fixture limit | Boundary behavior |
|---|---:|---|
| Encoded candidate envelope | 16,384 bytes inclusive | 16,384 can proceed to scanner; 16,385 refuses before materialization callback |
| Any encoded field / text claim | 4,096 bytes inclusive | Checked before copy; 4,097 refuses |
| Members | 8 inclusive | Ninth member refuses before member/key decode/copy |
| Member identity | 32 bytes exact | Other length refuses |
| Member public key | 1,312 bytes exact, at most 8 keys | Wrong length refuses; duplicates detected by full decoded bytes |
| Content claim | 256 bytes inclusive | 257 refuses before statement encoding |
| Authority/provenance identifiers | 32 bytes exact each | Missing/extra/unsupported length refuses |
| Signature/evidence entry | 2,420 bytes exact; at most 8 entries | Wrong length or ninth entry refuses |
| Decoded candidate | One context, one evidence vector, no recursion; at most 8 members/8 entries | A second candidate is not queued/retained; refuse or process only after prior object release |
| Simultaneously retained context copies | At most 3 logical contexts: immutable expected fixture, owned candidate snapshot, admitted immutable snapshot | No unbounded clones; a fourth context-shaped copy refuses in the model |
| Simultaneously retained encoded segments | Candidate envelope and one statement/content segment, each charged at full capacity | Charge both; no assume-shared buffer |

Use checked addition/multiplication and fallible reservation in a future
test-only implementation. Reject arithmetic overflow before reservation,
decode or callback. Exact cap may pass the relevant gate only; malformed
content can still fail later shape checks. One beyond must return a typed
limit refusal and show zero relevant materialization/crypto/effect calls.
Every nested length and count is independently checked before slicing/copying.
Exact consumption is required; trailing/duplicate fields refuse. No lengths
are narrowed with unchecked casts.

### Allocation boundaries and what is counted

1. `test_admit_descriptor_then_materialize`: receives six/n descriptors and
   a sentinel callback before candidate bytes are materialized. It may show
   checked aggregate arithmetic and zero callback invocations on 16,385 or
   overflow. It does **not** prove the caller did not allocate the descriptors,
   nor model a socket/framework allocation.
2. `test_scan_borrowed_envelope_then_decode`: receives an already allocated
   borrowed `&[u8]`; scans lengths/counts/duplicates/whole consumption before
   invoking its test decoder. It can count decoder calls, but not the earlier
   allocation that produced the slice.
3. `test_admit_decoded_candidate`: receives already allocated structs/Vecs;
   checks decoded object/member/copy limits before deeper clone/crypto/effects.
   It cannot be credited with pre-input-allocation rejection.
4. `test_verify_use`: receives an already admitted immutable context and
   bounded synthetic evidence; rechecks identity/currentness before a
   sentinel-only effect callback. It is not a production caller.

Report encoded lengths, separate component vector lengths/capacities if
measured, decoded member/key/signature counts and simultaneous logical-copy
inventory. Do not equate lengths with allocator capacity/RSS. Do not add a
calculated bundle size to the encoded cap unless it is actually encoded at
that boundary. **Unmeasured unless separately instrumented:** allocator and
map overhead; parsed string/object overhead; temporaries and clones; keygen/
signature verification stack/heap; peak process memory; test runtime under
adversarial scheduling; cancellation responsiveness; filesystem/network
buffers; concurrent requests. Limits above do not bound those resources or
production operation.

## 3. Test-only entrypoints and oracles

All rows below are proposed **FUTURE / NOT EXECUTED**. Entry names are
specification names, not existing functions. A future slice should keep the
strict implementation as the same path for positive and negative inputs.
Counters/oracles must identify the intended check; unrelated earlier refusal
does not count as sensitivity. For each negative, assert the stated
preconditions passed and a typed result/counter identifies the intended
predicate.

| Case | Proposed entrypoint and input boundary | Preconditions / intended output | Sensitivity and limitation |
|---|---|---|---|
| Matching independent context | `test_admit_decoded_candidate(expected_fixture, matching_candidate, Available)` after independently created fixture | All structural/context/provenance correspondence checks true; `AdmittedTestContext`; comparison/decoder counters positive; no effect capability returned | Same admitted snapshot verifies again with unchanged Available state; positive restoration control |
| Witness-selected catalog or attribution | Same `test_admit_decoded_candidate`; candidate sets root/source/catalog/threshold/policy/currentness to its own values while independent fixture stays fixed | Candidate structurally valid and internally consistent so refusal reaches `AttributionMismatch`/`ContextMismatch`; currentness comes separately | Defective `trust_candidate` branch accepts; assert strict oracle rejects. No actual root/authorship proof in P1 |
| Wrong network/genesis/purpose/version/applicability/epoch | Same decoded entrypoint, mutate one field at a time; all other fields and fixture source valid | Specific `ContextMismatch`, `Unsupported`, or `ApplicabilityMismatch`; restore one original field/record to positive | Assert prior validation stages passed and comparison-stage counter reached; do not credit signature/shape failure |
| Duplicate/ambiguous identities/keys | Same decoded entrypoint with only ID/key duplicated; fixture remains valid | `Ambiguous` before evidence crypto; same label/full other context; decoder/crypto zero | Dedup bypass accepts or inflates count; same structural oracle must detect expected refusal |
| Altered members, key, weight, threshold | Same candidate comparison; mutate one claim while all types/counts valid | Exact field comparison to independent catalog yields `ContextMismatch`; no crypto | `label_only`/omitted-field control accepts substituted set/threshold; strict same-field oracle refuses |
| Unavailable | `test_admit_decoded_candidate` with valid candidate and separately supplied `Unavailable` | All context comparisons pass; `CurrentnessUnavailable`, effect callback0 | Defective missing→Available branch would invoke callback; counter only models sentinel |
| Stale | Same entrypoint with independent `Stale` observation | Candidate/context otherwise valid; `StaleContext`; callback0 | Omitted currentness check accepts; strict currentness predicate reached |
| Conflict | Same entrypoint with two valid but incompatible simulated applicable records | Both candidates individually structurally valid; `ConflictingContext`, neither selected | Defective first-arrival selection demonstrates unsafe acceptance; no real adjudication |
| Unknown | Same entrypoint with observation unable to distinguish stale/current | Context/source otherwise valid; `CurrentnessUnknown`; no callback/effect | Defective Unknown→Available conversion detected by same refusal oracle |
| Joint rollback/copy with independent newer observation | `test_admit_decoded_candidate` receives copied old candidate/local marker and separate simulated source still says newer | Local values match old copy but independent observation yields `Stale`/`Conflict`; refuse | A synthetic sentinel can show the independent observation was consulted. This does not demonstrate OS/hardware nonrollback |
| Joint rollback/copy without independent observation | Same old copied inputs but currentness is `Unknown`/`Unavailable` | Must return Unknown/Unavailable, not assert rollback detected or accept old currentness | Sensitivity ensures no code silently labels copied local equality Available; local generation/checksum not oracle |
| Applicability changes between admission/use | `test_verify_use(expected, admitted, Available_then_Stale_or_Conflict)`; admission positive first | Admission counter confirms success; mutate only separate simulated currentness at use; `InvalidatedBeforeUse`/specific currentness result before sentinel callback | Strict use-time recheck counter reached; bypass produces sentinel effect, not proof about actual effects |
| At-limit / over-limit encoded input | `test_admit_descriptor_then_materialize`; descriptors before payload | All non-size descriptors valid; 16,384 allowed past size gate; 16,385/overflow typed refusal with materialization callback0 | Gate bypass calls sentinel callback; not proof of socket/pre-handler allocation bound |
| At-limit / over-limit borrowed nested fields | `test_scan_borrowed_envelope_then_decode`; already allocated bytes | Same candidate grammar valid at exact field/member limit; one-beyond rejects before decoder; restored valid bytes decode | Scanner bypass invokes decoder on malformed input; only test decoder calls observed |
| Decoded-copy/member bound | `test_admit_decoded_candidate`; vectors already allocated | Limit checks precede any additional clone/crypto; exact count passes; one beyond refuses | Clearly label already allocated object; never call this preallocation protection |
| Omitted provenance/context field | Same strict comparison oracle versus private defective projection dropping one field (e.g. source identity, genesis, policy version, weight rule) | Control fixture holds other requirements true; strict `ContextMismatch`; defective path admits altered candidate | Restore field/signatures/context and require positive; no production bypass |
| Omitted currentness | Same strict `test_admit`/`test_verify_use` with Stale/Unknown and a sentinel callback | Currentness state is independently valid as a test input, context comparisons pass | Defective branch invokes callback; strict oracle remains refusal. Sentinel is not application/signing authority |

P2 cryptographic authority-record signatures are conditional on a separate
owner/review decision and are **not executed or accepted** by this P1 model.
Real provisioning/root ceremony, trust-source operator attribution and
currentness/rollback evidence are operational matters, not synthetic tests.
The model must not smuggle a root signature into P1 and then describe the
result as independently authenticated authority.

## 4. Decisions, exclusions and continuation

Before implementing even this isolated P1 test-only model, require independent
review and owner agreement on: fixture provenance-source identity semantics;
candidate fields that are required versus claim-only; normalized structural
comparison and ambiguous-field rejection; relationship among genesis, full
runtime chain/wire aliases and epoch applicability; currentness state machine
and revalidation timing; exact test limits/copy inventory; callback/effect
oracle and bypass controls; refusal taxonomy; and proof that test support
cannot be reached by production targets. This request selects none of these
for production and builds/runs no tests.

The founder-bootstrap decision remains only the role decision for one exact
initial DevNet configuration and founding set. It supplies no completed
credential ceremony, external root, currentness, later-transition authority,
signer override, history reset, consensus finality, recovery-clear authority
or separate resume permission. Any later transition needs separately approved
scope and currentness; no fixed membership implies later epoch use.

Context/provenance checking remains separate from:

* authenticating a recovery prefix, QC/TC finality, per-block committed
  coverage or historical content binding;
* currentness/non-rollback proof, durable application or crash-safe ownership;
* signing-history continuity, uncertain outcome handling or exclusive signer
  fencing;
* quarantine clearance, a mode flip, catch-up completion or the separate
  independently authorized resume/participation decision.

Current catch-up containment is unchanged: non-empty responses refuse;
admitted empty responses are ignored before peer-height/mode effects. Restore
mode may persist indefinitely and is not a complete engine/worker/signer
fence. The liveness cost remains explicit; missing evidence stays refusal,
not no-effect or auto-resume.

## 5. Status

This specification contains **no executed cases**. Every row in section 3 is
FUTURE / NOT EXECUTED; the 13 accepted provenance-contract cases retain their
status and the nine authority-context test results are carried forward only
as user-supplied PASS WITH LIMITATIONS within scope. The next step is
independent review of this proposed API, limits and oracle plan, not
implementation or protocol activation.

**A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain OPEN.
Activation DISABLED; public DevNet NO-GO.**
