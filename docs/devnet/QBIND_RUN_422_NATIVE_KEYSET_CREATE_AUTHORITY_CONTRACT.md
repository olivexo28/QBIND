# RUN 422 - Native keyset-create authority characterization and draft contract

**DRAFT / NOT APPROVED / NOT IMPLEMENTED**

This is test-and-contract work, not creation-policy approval or enforcement.
Production Rust, existing tests, governance/validator refusals and contracts,
isolated helpers/models, manifests, dependencies, wire formats and signing
preimages are unchanged. The one safeguard proposed below is not implemented.

## 1. Baseline, scope and evidence attribution

Required starting commit: `62217a3792932db6948e602c39facade0190a180`.
Required root tree: `380813f63c73df6aa0eebfb86493a68595047663`.
The initial checkout was clean; both objects were readable with the expected
types, and the commit's tree header and `HEAD^{tree}` matched that tree.
Origin fetch/push URL was `https://github.com/olivexo28/QBIND`.
The task branch was created directly from that commit:
`copilot/run-422-native-keyset-create-authority-contract`.
No applicable `AGENTS.md` or repository Copilot instruction file was found.

Tree correspondence is independent of ancestry. The repository reported
shallow history. The raw starting commit header contains parent
`a7d7c1dc31094b59e13f758791f1d77c49055b62`, but that object was unavailable
locally (`git cat-file -t` failed). This is not an absent parent header or
evidence that the starting commit is parentless. No reason for shallow history
is inferred; ancestry before the required baseline is not established here.
New task commits descend from the baseline; final delivery checks that relation
separately from source/tree correspondence.

Scope is the library route `qbind_wire::tx::Transaction` ->
`qbind_runtime::TxExecutor::execute_transaction` -> `KeysetProgram`.
Do not import properties from ledger `QbindTransaction`, its nonce/VM execution
or adapters, or runtime `QbindTx`/EVM execution. Source registration of the native
program does not establish selected-binary or deployed reachability. Observed
library acceptance is not labelled a deployed exploit or a demonstrated
consensus failure.

Sections 2-3 are source-derived findings at the pinned baseline. Section 4 maps
executable assertions; actual command exits/counts and tested revision are
recorded separately in the appended
`QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` evidence, not inferred from source review.
Historical claims in existing documents retain their original attribution.

## 2. Source-derived authentication and creation boundary

| Source | Finding |
|---|---|
| `crates/qbind-runtime/src/lib.rs:124-159`, `TxExecutor::{new,execute_transaction}` | Registers native programs, builds `ExecutionContext`, authenticates, then resolves/dispatches the program. Unknown program dispatch follows authentication. |
| `crates/qbind-ledger/src/context.rs:10-52` | Context contains a mutable store borrow, provider `Arc` and validator minimum. It conveys no authenticated creator/namespace capability, policy profile, nonce reservation or transactional commit protocol. |
| `crates/qbind-ledger/src/auth.rs:29-83` | Empty auth refuses first. Account/auth count checks and exact bit-0 signer-index coverage precede digest, account reads and crypto. Transaction-supplied declarations identify which keysets to check, not independent creator rights. |
| `crates/qbind-ledger/src/auth.rs:86-145` | Each auth loads its resolved keyset via legacy `get`, decodes owned state, rejects trailing state bytes, selects the first entry matching suite ID, gets the suite and verifies the signature. It does not evaluate weights/thresholds, canonical duplicate identities, keyset owner/executability or a chain-selected suite policy. |
| `crates/qbind-hash/src/tx.rs:11-56` | Legacy `tx_digest` hashes `QBIND:TX` plus allocated signing body: version, chain ID, payer, nonce, fee limit, all account metadata, program ID and complete call data. Message type and auth vector are excluded. Binding bytes is not independent authorization of the claims in those bytes. |
| `crates/qbind-system/src/keyset_program.rs:55-96` | Program ID, empty-call/opcode, create decoding, trailing bytes and target existence are checked in that order. The target is taken from call data, not resolved from writable/signer metadata. |
| `crates/qbind-system/src/keyset_program.rs:98-128` | Copies entries into `KeysetAccount`, encodes, constructs `Account`, then calls `put`: the first store mutation. No creator/namespace rule, target-key possession, suite/canonical-key admission, duplicate-weight or threshold-reachability check is invoked. |
| `crates/qbind-wire/src/keyset.rs:9-104` | Legacy create decoder reads opcode/version/target/threshold/count/reserved bytes and allocates entries/key vectors. It is structural decoding, not semantic admission. |
| `crates/qbind-serde/src/keyset.rs:5-79`; `crates/qbind-types/src/state_keyset.rs:5-21` | Stored codecs preserve threshold, count, entry order/weights/suite/key bytes. Decoder allocates owned entries/keys; no weighted authentication policy is applied by decoding. |
| `crates/qbind-ledger/src/account.rs:5-42`; `store.rs:19-41` | Complete account has ID, owner, lamports, executable flag, rent epoch, reserved header and data. `put` is insert-or-replace; generic store API has no atomic absent-target insertion primitive. |
| `crates/qbind-system/tests/keyset_program_tests.rs:36-133` | Existing direct-program create/existence controls bypass executor authentication. They are preserved, not reattributed as genuine-auth execution evidence. |

Authenticated principals in these tests are pre-state keysets resolved from
signer-marked account indices, with a successful genuine ML-DSA-44 check.
Ordinary fixtures use correctly owned, non-executable, single-key, weight-1,
threshold-1 keysets. Their good metadata is fixture discipline, not evidence
that legacy auth enforces it. The payer, target ID, account flags/access hints,
threshold, candidate suites, weights and keys are transaction-supplied claims.
An authenticated signer can bind such claims without proving a right to
allocate the target, authority over the payer, or possession of candidate keys.

Admission uses signer declarations/auth resolution and stored first matching
suite/key for authentication, program ID/opcode for dispatch, and decoded
target for existence. Payer, nonce, fee limit, chain ID and versions are signed
but receive no independent fee/replay/context policy validation on this route.
Target metadata need not match the call target for the observed creation.
Candidate entries are copied, not used to verify a creation proof.

Successful creation establishes that authentication, dispatch, structural call
decoding and the target lookup passed, and the store accepted the supplied
account write. The constructed account has the call target ID,
`KEYSET_PROGRAM_ID` owner, zero lamports, non-executable status, zero rent epoch
and zero reserved header. Stored version/threshold/order/weights/keys follow
the call, while stored reserved fields are zero and counts/lengths are derived.
Success establishes neither creator entitlement nor target possession, usable
candidate keys, weighted policy enforcement, payer consent/payment, durable
replay protection, persistent atomicity or deployment readiness.

## 3. Isolated mechanisms are not active authority

`keyset_create.rs::prepare_keyset_account_bounded` performs isolated bounded
parsing, sizing, semantic analysis and owned output preparation. It neither
authorizes a creator nor checks target absence or accesses a store.
`keyset_validation.rs::{prepare_entries,summarize_workspace}` checks canonical
identity/duplicate consistency and mathematical reachability, not signatures
or permission. Caller capacities and all candidate limits remain `UNAPPROVED`.

`keyset_proof.rs::evaluate_stored_keyset_proofs` can verify all matching entries
and count distinct verified weight;
`native_tx_proof.rs::evaluate_native_transaction_proofs` composes bounded reads
and these checks.
They are diagnostic-only, separately supplied provider/limit evaluations, not
the active first-suite-entry verifier. In particular, their weighted refusal
does not describe what `TxExecutor` currently does.

`native_admission_context.rs` pins concrete in-memory reads using trusted fixture
binding/profile labels; generic per-account coherence is not a common pre-state.
`native_staged_effects.rs` models exclusive in-memory staging/publication and
normal-error atomicity, not persistent transactions or crash recovery.
`native_keyset_create_model.rs::NativeKeysetCreateModel` composes fresh proof
evaluation, preparation and single-create staging against the same borrowed
transaction/store for trusted fixtures. It explicitly establishes no creator,
payer, nonce, fee, replay or bootstrap policy. Neither labels nor proof
summaries are authenticated execution capabilities. These APIs are not called
by the reviewed executor/context/auth/KeysetProgram route and are not activated
by this task.

## 4. Source/test assertion mapping

Target:
`crates/qbind-runtime/tests/run_422_native_keyset_create_authority_contract_tests.rs`.
Every case runs the actual `TxExecutor`. `CountedSuite` records key/digest/proof
bytes and delegates to real `MlDsa44SignatureSuite::verify`; canonical descriptor
calls are separately counted. No always-accepting provider is used.
`Key::genuine` independently signs/verifies fixture keys outside measured work.
This is fixture usability only, not a production possession rule.

`Fixture::invoke` resets store/crypto traces per invocation, snapshots raw map
state without `get`, round-trips complete transaction wire bytes, and compares
complete transaction values/bytes afterward. Refusals require exact error
variants/payloads, complete pre/post equality, and no puts/deletes. Successes
compare the entire map with exactly one new account, including an independently
assembled byte/header oracle and decoded-state equality. Signer, payer, sentinel
and all previous creations must be preserved. Counts below are per invocation;
the aggregate test/command results belong to the separate execution evidence.

Here S is the authenticated pre-state signer; T/F are distinct absent targets.

| Test | Baseline assertion and observed-work expectation | Source boundary |
|---|---|---|
| `authenticated_creation_control` | S creates T with independently generated key; T is not a declared signer, supplies no creation signature. Reads `[S,T]`, 1 genuine outer verification, 1 put. | Auth first; no target-possession rule. |
| `payer_is_signed_data_not_independent_authority_or_fee_payment` | Absent payer and separately seeded sentinel-state payer both permit creation; payer differs from S and is not declared. Same reads/verification/put; no payer read or change. | Signed payer claim is not consent or fee payment. |
| `signed_target_binding_and_resigned_fresh_state` | Change only call target without re-signing: `CryptoError("signature verification failed")`, `[S]`, 1 attempted real verification, no target access. Re-sign same changed body on unchanged state: creation at F, `[S,F]`, 1 verification/put. Metadata still names T. | Digest binds call target; handler uses call target, not metadata as allocation authority. |
| `authentication_refusals_then_valid_retry` | Empty auth: `InvalidCallData("transaction requires at least one authentication entry")`, no reads/verification. Truncated and bit-tampered genuine signatures: exact crypto error above, `[S]`, 1 attempt each. Original valid retry freshly authenticates and creates T. | Refusal precedes program effects; no cached authentication. |
| `existing_targets_exact_replay_and_same_nonce_fresh_target` | First create succeeds; exact replay authenticates again then `ProgramError("keyset account already exists")`, `[S,T]`, 1 verification, no put. Separately seeded unrelated-owner/executable target is wholly preserved with same error/work. Separately signed F with same nonce succeeds. | Existence protection, not nonce consumption or durable replay protection. |
| `structurally_decodable_semantic_gaps_store_exact_candidate_claims` | Eight small calls: empty entries; unreachable threshold; zero weight; zero threshold; both zero; identical key with inconsistent weights; unsupported suite; malformed ML-DSA key. All expect exact claim storage, `[S,target]`, 1 outer verification/put each, 0 descriptors. | Candidate entries are not cryptographically/semantically admitted. |
| `actual_subsequent_use_ignores_threshold_two_with_threshold_one_control` | Actually create two distinct genuine keys, weights 1+1/threshold 2, then use only first key in later executor authentication to create F. Both steps succeed with 1 verification/put each; later reads `[T,F]`. Separate actual single-key threshold-1 creation/use control also succeeds. | Successful real signature verification does not enforce stored threshold. No isolated evaluator substitutes for execution. |
| `absent_signer_keyset_cannot_bootstrap_its_own_creation` | Signature mathematically verifies outside execution, but its signer keyset/target is absent: exact `AccountNotFound`, `[T]`, 0 verifier calls/puts/deletes. | Pre-state lookup precedes crypto and creation; no missing-account bootstrap. |
| `authenticated_framing_controls_refuse_before_target_access` | Empty data: `InvalidCallData("empty call_data")`; opcode FF: `ProgramError("unsupported keyset opcode")`; opcode-only and truncated key data: `InvalidCallData("invalid CreateKeysetCall")`; trailing byte: `InvalidCallData("extra bytes after CreateKeysetCall")`. Each reads `[S]`, verifies once, never puts/deletes. | Authentication precedes framing; framing precedes target lookup. |

These are bounded local characterizations, not wire-maximum workloads, policy
limits, fee receipts, persistent-store experiments or a deployed exploit claim.

## 5. Draft enforcement obligations, independently unresolved

**DRAFT / NOT APPROVED / NOT IMPLEMENTED.** The following are review obligations,
not policy decisions made by these tests:

1. **Transaction authentication / weighted signer policy.** Specify the
   relationship among signer indices, account identities, allowed suites,
   canonical duplicate identities and independently satisfied stored thresholds.
   Exact signed-index coverage and a successful first-key signature are not
   weighted authorization. Bind any future decision to the exact transaction,
   coherent pre-state and authenticated provider/policy interpretation; a
   diagnostic helper result must not become an execution capability.
2. **Creator rights / target and namespace allocation.** Decide whether creation
   is permissionless or requires independently authorized allocation. Neither is
   selected here. Define how an authenticated principal may allocate a particular
   absent ID and how conflicts are resolved. Signed target metadata, chosen IDs,
   candidate keys and their possession cannot silently answer that question.
3. **Candidate semantics / admission / possession.** Review supported suites,
   canonical key validity, thresholds, zero weights, reachability, duplicate
   identity/weight consistency, aliases, versions and reserved bytes. Decide any
   required target-key possession or consent independently of outer auth, with
   explicit scope/binding if approved. Key generation in tests supplies none of
   that production policy. Do not silently grandfather malformed candidates or
   assume the isolated semantics are already approved protocol.
4. **Payer / funding / fees / nonce / replay / failure.** Define payer
   authorization and funding, whether/when fees and allocations are charged,
   nonce domains and durable replay rules, and the disposition of each failure.
   Preserve distinctions between deterministic invalidity and local inability.
   Zero-lamport account creation and a signed payer/fee/nonce do not implement
   these obligations; no effects in this fixture do not imply general rollback.
5. **Coherent pre-state / atomic insertion.** Authentication, candidate/allocation
   decisions and absent-target insertion must use one justified conflict domain
   if a future contract requires that guarantee. A mutable generic store borrow
   does not establish backend snapshot isolation. Review atomic absent-target
   insertion, concurrent writers, write failure, receipts and effect visibility;
   separate `get` and insert-or-replace `put` are not such a primitive.
6. **Compatibility.** Inventory existing native callers and stored keysets
   (including historically accepted empty, unreachable, duplicate, malformed and
   multi-key states). Weighted checks may reject existing signatures previously
   accepted; stricter creation can reject previously successful callers. Review
   migration/versioning and error precedence separately. No retroactive repair,
   grandfathering, bootstrap exception or activation is authorized here.
7. **Persistent store / crash / restart / deployment.** Obtain backend-specific
   coherent-read and atomic-publication evidence, interruption/restart/replay
   tests, recovery/anti-rollback evidence and selected-binary reachability before
   making corresponding guarantees. In-memory snapshots and passing library
   tests establish none of these. Public deployment remains out of scope.

## 6. Inherited resources, not new ceilings

The active legacy auth still allocates a signing-preimage `Vec`; materializes
owned signer account data through `get`; decodes an owned entry vector and
public-key vectors per auth; then performs backend verification work. Its
coverage bitmap is not a whole-path memory bound. Creation decoding allocates
an entry vector from the wire count and copies each key into a vector before
the target check. After absence, handler construction copies entries/keys into
stored-state representation and output encoding allocates/grows another `Vec`
before the final `put`. Store/backend and fixture observation/snapshot copies
are separate. The isolated bounded helpers do not change this legacy work.

This task adds no resource ceiling, candidate policy limit, physical-memory,
Vec-capacity, allocator, stack-frame, RSS or latency bound. No wire-maximum
workload is allocated. Earlier resource assessments retain their own source,
profile and command attribution.

## 7. Exactly one proposed bounded follow-up safeguard

For separate review only: add an unconditional unavailable-authority refusal
after existing create-call decoding, trailing-byte rejection and target-existence
validation, but before account construction, state serialization or `put`.
A proposed exact result is
`ExecutionError::ProgramError("native keyset creation authority unavailable")`.
This is a proposal, not the current error or an implemented rule.

Acceptance impact: every previously successful, authenticated, structurally
valid absent-target creation would refuse, including the ordinary control and
semantic-gap examples. Auth, program-ID/empty/opcode errors, malformed/trailing
call errors and existing-target errors would retain precedence. The legacy
signing-preimage, signer reads/decoding/crypto, create decoder allocations and
target-existence read would still occur. This is not zero-work rejection.
There would be no account construction/serialization/write after that point.
It would not implement positive creator/namespace policy, weighted auth,
candidate admission, payer/funding, replay or persistent atomicity. No policy
flag, alternate permissive route or missing-account bootstrap exception is
proposed or introduced. Production behavior is frozen in this task.

## 8. Preserved posture and cross-references

See `QBIND_RUN_422_NATIVE_ADMISSION_STATE_CONTRACT.md`,
`QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` and `../whitepaper/contradiction.md` for
append-only cross-references and independently attributed historical evidence.
Whole native-admission, governance and validator contracts remain
**DRAFT / NOT APPROVED / NOT IMPLEMENTED**; completed governance/validator
refusals and their contracts are unchanged.

Preserve `D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED`,
`D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET`, section 13.6 whole-lifecycle
`INCOMPLETE`, activation `DISABLED`, public DevNet `NO-GO`, durable anti-rollback
`NOT-ESTABLISHED`, C4/C5 `OPEN`, RS1 `OPEN`; all candidate limits `UNAPPROVED`.
No F1/F2 closure, production-consistency guarantee, release approval,
activation or deployment follows from this characterization.

## 9. Implemented bounded unavailable-authority refusal

**Bounded safeguard: IMPLEMENTED. Whole contract: DRAFT / NOT APPROVED / NOT IMPLEMENTED.** The source/test revision is `92ba29ee13b2470e4b21b681aefcd8cf1ecf3264`, root tree `8657372596b2d5dbeaed5954028cb6aa14642a1d`, directly descended from required starting commit `90b01cb95487e7c49f5dad39294fa3c7c4810255` / tree `3a643f824d8624cbcba43ae40076b5a6ffb2f009`.

`KeysetProgram::execute` still checks program ID first, then empty call and opcode. `handle_create` still decodes `CreateKeysetCall`, rejects trailing bytes, and reads the target. An existing target still returns exactly `ProgramError("keyset account already exists")`. Only after an absent-target lookup, the single private zero-argument `unavailable_authority()` helper returns exactly `ExecutionError::ProgramError("native keyset creation authority unavailable")`. It has no authority input, switch, feature, environment override, permissive default or bootstrap exception.

The creation handler no longer copies entries, constructs `KeysetAccount`/`KeysetEntry` state, serializes state, constructs an `Account`, calls `put`, or retains an unreachable success path. The new refusal adds no allocation or external work. It does not remove existing legacy authentication preimage allocation, signer reads/owned decode/signature verification, create-call decode/entry allocations, or the target lookup.

### Assertion mapping and controls

* `keyset_program_tests.rs` has three direct-Program tests: a valid absent target reaches the exact new error after one target read with no mutation; a fixture-seeded complete existing account preserves the exact old error and full account; wrong ID, empty/unsupported calls, malformed/truncated and trailing framing (including invalid framing against an already seeded target) retain their exact prior errors without target reads. These direct tests do not establish executor authentication.
* `run_422_native_keyset_create_authority_contract_tests.rs` retains nine genuine `TxExecutor` scenarios and genuine ML-DSA-44 verification. They cover authenticated refusal and `[signer,target]` reads; absent/seeded payer non-use; target tampering before target access and freshly re-signed refusal; empty/malformed/tampered authentication and genuine retry; repeated same-request absent-target refusal, same-nonce fresh-target refusal and a separately seeded existing-target error; eight structurally decodable candidate variants reaching the same refusal (not semantic admission); an attempted threshold-2 creation leaving the target absent followed by a separately fixture-seeded genuine 1+1/threshold-2 keyset whose first key authenticates a later request to the refusal; threshold-1 fixture control; absent signer `AccountNotFound`; and authenticated framing errors.
* The runtime fixture snapshots the complete map without traced reads, observes read/put/delete activity, and compares complete transaction values and encoded bytes. Refusal assertions require exact error variants/payloads, unchanged map, and zero puts/deletes. Fixture seeding of pre-existing signer/threshold controls is not production creation.
* `tx_executor_tests.rs` distinguishes missing signer coverage from fully signed authentication reaching the new error. `block_executor_tests.rs` retains ordered multiple-request processing, exact malformed-validator failure, the missing-coverage / fully signed create / would-be-signer `AccountNotFound` sequence, and an explicitly empty-block `all_succeeded()` control. No would-be account is seeded between transactions.
* `block_apply_tests.rs` retains successful outer block processing with failed transaction results, consensus outcome, complete proposal preservation (including encoded payload bytes), count and malformed/trailing transaction-blob controls. The accepting consensus suite remains structural harness-only; transaction authentication uses real ML-DSA-44. No real consensus-signature or deployed-node evidence is claimed.

Compatibility impact is intentional: every formerly successful, authenticated, structurally valid absent-target native keyset creation now refuses. Program-ID, empty/opcode, decode, trailing-byte and existing-target precedence is preserved. Weighted authentication, positive creator/namespace authority, candidate-semantic admission, payer/funding/fee/nonce/replay policy and persistent atomic publication remain absent and unresolved. No memory ceiling, bounded backend behavior, zero-read/zero-allocation claim, or activation follows. Preserve `D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED`, `D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET`, §13.6 whole-lifecycle `INCOMPLETE`, activation `DISABLED`, public DevNet `NO-GO`, durable anti-rollback `NOT-ESTABLISHED`, C4/C5 `OPEN`, RS1 `OPEN`, and all candidate limits `UNAPPROVED`.

The earlier successful characterization remains historical at its recorded source commit `ce25c42e3a389608832294c29bf5d2cdc7a59a6d` / tree `6e776019580b4a0139425b65b125353cd89b01b3`. That commit/tree object is unavailable in this shallow checkout, so no ancestry or local byte-correspondence claim is made and the closed historical characterization was not rerun. The earlier baseline's raw parent header is recorded separately from its unavailable parent object in the final evidence appendix.
