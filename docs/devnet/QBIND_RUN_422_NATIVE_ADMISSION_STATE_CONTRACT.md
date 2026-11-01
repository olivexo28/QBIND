# RUN 422 - Native admission policy and state-consistency contract

**DRAFT / NOT APPROVED / NOT IMPLEMENTED.** This is a concrete proposal for review,
not a protocol rule, activation instruction, production guarantee, or release
approval. All numerical candidate limits remain **UNAPPROVED**. The new
integration target characterizes the existing isolated diagnostic API; it does
not fix or activate it. No production authorization or creation changes.

## 1. Baseline, scope and authority of this evidence

Required clean starting HEAD: `bb2ce6ad0fa5362abe5f5b523d5cbfc8b98cfbd8`;
root tree: `1d41962bcca0867408d53bac8909182ce548bafd`. Both objects and exact
content correspondence were verified independently of ancestry. Origin is
`https://github.com/olivexo28/QBIND`. Raw commit header names parent
`8ae9ceafb2fd4fd9e491d33c44415f99c0de8a5f`. Initially shallow at the starting
commit, that parent object was unavailable, not absent. After
`git fetch --no-tags --deepen=1 origin main`, the parent was a readable commit
and `git merge-base --is-ancestor <parent> HEAD` exited 0. The repository remains
shallow at that parent; more remote ancestry is not established. No applicable
`AGENTS.md` or tracked instruction file was found.

Task branch: `copilot/run-422-native-admission-state-contract`. Only this new
document, `crates/qbind-ledger/tests/run_422_native_admission_state_contract_tests.rs`,
and append-only updates to `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` and
`docs/whitepaper/contradiction.md` are authorized. Starting historical blobs are
respectively `f68c30602ade715dff705c687d9465d69e075f27` and
`29fb5150763f9c0912690283e46e1756e93af3dd`, mode `100644`.

Scope is exclusively native `qbind_wire::tx::Transaction`. Do not import nonce,
gas, rollback, or authorization properties from `qbind_ledger::QbindTransaction`
and its VM/nonce engines (`crates/qbind-ledger/src/execution.rs`), or from
`qbind_runtime::QbindTx` and EVM execution. Consensus authority, safety-record
ownership and signing-recovery mechanisms are separate domains.

The completed
`docs/devnet/QBIND_RUN_422_NATIVE_ADMISSION_RESOURCE_ASSESSMENT.md` is reused,
including its closed corrections and original source/profile attributions.
Its benchmarks, full suites and node checks are not rerun or reattributed here.

## 2. Current source versus proposed guarantees

Source statements below refer to the pinned baseline and unchanged prerequisite
source, not to an imagined production integration.

| Surface and exact source symbols | Current behavior | Proposed guarantee (not implemented) |
|---|---|---|
| `crates/qbind-ledger/src/native_tx_proof.rs::{evaluate_native_transaction_proofs, preflight, NativeTransactionProofLimits}` | Caller supplies provider and limits; `<G,P,E>` are implementation capacities. Preflight checks complete structure; groups are visited in first signer-index occurrence order. | One chain-selected profile and one transaction-scoped execution context, selected before external evaluation. |
| Same file, `NativeTransactionProofSummary` and module contract | Diagnostic counts only; every supplied proof is checked against its separately read keyset. No snapshot, policy or execution authority. | Summary remains diagnostic-only and is discarded as authority; subsequent execution uses the same admitted transaction and context. |
| `crates/qbind-ledger/src/store.rs::{AccountStore::get_bounded, InMemoryAccountStore::get_bounded, materialize_account}` | Default `Unsupported`, no legacy fallback. In-memory length check and materialization use one borrowed map result; `try_reserve_exact` failure maps to `Backend`. No multi-read version/commit API. | Common logical pre-state, bounded reads and transaction atomic validation/commit, with local failures kept out of deterministic receipts. |
| `crates/qbind-ledger/src/keyset_account.rs::read_keyset_owned_account_bounded` | Checks requested ID, keyset owner, non-executable metadata and data ceiling. | Same checks against the selected pre-state, not independent moving reads. |
| `crates/qbind-ledger/src/keyset_proof.rs::evaluate_stored_keyset_proofs`; `keyset_validation.rs::{prepare_entries, summarize_workspace}` | Canonicalizes all entries, checks reachability using actual group proof count, verifies all matching candidates, counts distinct identity weight, refuses late invalid proofs. Provider references alone do not establish stable semantics. | Profile pins allowed suites, descriptors/aliases and verification interpretation for the context lifetime. |
| `crates/qbind-ledger/src/context.rs::{ExecutionContext, verify_tx_auth}`; `crates/qbind-runtime/src/lib.rs::TxExecutor::execute_transaction` | Context holds `&mut S` and provider `Arc`; calls legacy auth then dispatches program. Does not call isolated evaluator or select native policy/version/snapshot. | All independent authority reads and effects share admitted context; neither Rust borrow nor `Arc` is evidence of backend serialization. |
| `crates/qbind-ledger/src/auth.rs::{verify_transaction_auth, verify_single_auth}` | Exact signer-index coverage, owned `get`/decode per auth, first matching suite entry, no weighted thresholds. Declarations come from transaction. No payer-specific authorization or nonce reservation here. | Explicit program/payer/nonce/fee/creation rules, independently approved; no inference from signer declarations or proof success. |
| `crates/qbind-system/src/keyset_program.rs::KeysetProgram::handle_create` | Decodes call, separately checks target with `get`, builds/encodes account and `put`s it. No independent creator-authority or threshold admission in this handler; no atomic absence/insert primitive. | Authorized preparation and absent-target predicate in same atomic conflict domain as insertion. No bootstrap exception inferred. |
| `crates/qbind-runtime/src/lib.rs::BlockExecutor::execute_block` | Runs sequentially, records `Success`/`Failed(ExecutionError)` and continues. No rollback; no transaction staging API. | Earlier successes preserved; current transaction effects invisible until atomic commit. Local inability stops execution rather than becoming a validator-dependent committed failure. |
| `crates/qbind-hash/src/tx.rs::{try_tx_digest_streaming, tx_digest, tx_sign_body_preimage}` | Both digest signing body, excluding auths; legacy materializes preimage. | Exact admitted transaction including proof vector retained/borrowed in context; signing-body digest alone is not proof identity. No new cryptographic construction. |

## 3. Executable characterization and requirement mapping

Harness uses four distinct genuine ML-DSA-44 keypairs: A0, B0, A1, B1.
S0 stores A0 and B0; S1 stores A1 and B1. Both are complete, immutable
`InMemoryAccountStore` generations with legitimate requested IDs,
`KEYSET_PROGRAM_ID` ownership, non-executable accounts and one weight-1 key at
threshold 1. The only published states are S0 and S1, never A0+B1.
Key generation/signing are genuine; determinism concerns the read boundary,
not reproducible random key bytes.

`ReadBoundaryStore::get_bounded` delegates length checking and materialization
to the selected immutable in-memory store and compares the complete returned
account with its generation oracle. After returning the complete first read
internally, it explicitly selects S1 for subsequent reads. No threads, sleeps,
torn bytes, account-content mutation, fake verification or scheduling race.
Every evaluated transaction is compared both structurally and by complete
`WireEncode` bytes, including authentication proofs. Both stored generations
are compared completely afterward. Fixture setup and preservation-oracle reads
are outside the evaluator's counted store surface.

| Test / control | Current result asserted; exact counted work | Proposed requirement illuminated |
|---|---|---|
| `mixed_proofs_refuse_fixed_generations_but_pass_coherent_switching_reads`, A | Unchanged A0+B1 transaction on S0: `KeysetProof(InvalidProof)`; reads `(A,S0),(B,S0)`; 2 provider lookups, 2 descriptors, 2 real verification attempts. | Validity must be evaluated against one selected pre-state. |
| Same test, B | Same transaction on S1: `KeysetProof(InvalidProof)`; only `(A,S1)` read; 1 lookup/descriptor/verification. | Early refusal is expected; no fabricated second read. |
| Same test and unchanged transaction, C | A0+B1 through switch: success summary exactly `(required_signer_index_count=2, distinct_keyset_account_count=2, evaluated_authentication_proof_count=2)`; reads `(A,S0),(B,S1)`; one transition; 2 lookups/descriptors/verifications. | Per-account coherence is insufficient to establish common state. This asserts current behavior, not a future rejection. |
| `matched_genuine_proofs_pass_separate_fixed_generation_controls`, D | Separate fixed wrappers: A0+B0 on S0 and A1+B1 on S1 each return the same exact success summary, ordered A then B, and 2 lookups/descriptors/verifications. No transitions. | Provider/fixtures are valid; positive controls do not publish a mixed generation or pollute switching history. |
| All controls | Requested budget 65,536 per read; zero evaluator legacy reads/fallback, writes and deletes; complete unchanged transaction bytes and both generation contents. | Isolated checking has no effects; state-selection, freshness and commit remain future obligations. |

The literal focused run below confirmed all these assertions, including C.
Successful C is allowed by the diagnostic
helper's documented contract, not a violation of a guarantee it never provided.
It does not establish a production exploit, deployed exposure, consensus
failure or demonstrated safety violation. Tests do not implement the proposed
context, commit, payer or replay requirements.

## 4. Proposed authoritative native policy selection

**Recommendation:** chain execution selects a versioned immutable profile from
its authenticated execution context. Selection is a deterministic function of
chain identity, the canonical predecessor/block execution position and the
protocol's eventually approved activation/version rules. All validators must
derive the same version and complete parameter/provider interpretation.
The transaction's chain ID must match that context; a transaction or backend
cannot choose a weaker policy. A local CLI, environment variable, Boolean or
test constant is not policy authority.

The authoritative mapping, governance root, upgrade authorization, profile
encoding/commitment and activation schedule are pending approval. No activation
height or approved numeric profile is selected here. Once selected, the profile
and provider interpretation are pinned until release, including if chain
configuration is concurrently refreshed locally.

| Policy selection condition | Proposed fail-closed disposition |
|---|---|
| Missing selection in execution context | Refuse to start native execution; no implicit legacy/default profile. Context/configuration inability, not an invented transaction receipt. |
| Unknown version in chain context | Stop execution/synchronization at the unsupported rule boundary; require software/configuration support, no guessed fallback. |
| Inactive version requested by transaction/caller | Caller has no selection authority. If an approved transaction policy-version field is later introduced, mismatch is deterministic refusal under that rule; none is added here. Otherwise use only chain selection. |
| Known active version unsupported by local capacities/backend/provider | Local inability; no effects/committed transaction disposition. Upgrade/support the selected profile and acquire a fresh context before retry. |
| Active fully supported version | Bind exact profile to context before proof work; no mid-transaction version change. |

### Candidate limits and enforcement (all UNAPPROVED)

| Assessment value | Existing isolated enforcement point | Approval still needed |
|---|---|---|
| 8 required signer indices; 8 distinct keyset IDs; 8 total proofs | `native_tx_proof.rs::preflight` | Numerical profile, chain authority and acceptance consequences. |
| 8,192 bytes/signature; 65,536 aggregate signature bytes | `preflight`, checked addition; `keyset_proof.rs::checked_aggregate_signature_bytes` | Allowed suites' encodings and aggregate budget. |
| 65,536 stored keyset bytes; 16 encoded entries; 4,096 bytes/key; 65,536 aggregate key bytes | `read_keyset_owned_account_bounded`; `qbind_serde::keyset::parse_stored_keyset` with `StoredKeysetLimits` | Existing-state compatibility, malformed-state disposition and backend guarantees. |
| 128 combined algorithm/parameter identifier bytes | `keyset_validation.rs::prepare_entries` | Canonical identities, aliases, provider/suite allowlist and lifecycle. |
| Separate create fixture: 65,536 call bytes, 16 entries, same key/identifier limits; 65,536 stored output; 8 distinct-proof reachability budget | `qbind_wire::keyset::parse_create_keyset`; `keyset_create.rs::prepare_keyset_account_bounded` | Independent input/output caps, creator rights and actual multi-group feasibility. No create activation here. |

`<8,8,16>` arrays are local workspace capacities, not protocol limits. A selected
profile exceeding supported capacities must refuse locally before execution;
do not truncate keys/proofs or reduce protocol limits to fit an implementation.
Current helper workspace errors are not yet an approved consensus mapping.
Wire-representability checks are separate from operational resource approval.

## 5. Proposed state/provider context and primary backend contract

**Primary proposal: immutable read version plus atomic validation/commit.**
The chain executor, not an untrusted caller, acquires a backend-owned context
for the exact logical pre-state of the next native transaction: canonical
predecessor plus earlier successful transactions in the chosen block order.
The backend proves/binds that provenance through its trusted execution API;
an arbitrary externally supplied generation number is insufficient.

All keyset and program authorization reads in the context see that same
immutable logical pre-state. All reads, including absence predicates, are
recorded in its conflict domain. Provider/suite implementations and canonical
descriptor/alias interpretation must be immutable and match the chain-selected
profile. Pinning an `Arc` alone cannot exclude interior mutation, HSM/provider
changes or inconsistent validator installations.

The context borrows or owns one unchanged admitted transaction (full body,
metadata, auth indices, suite IDs, reserved fields and proof bytes). Execution
cannot substitute another transaction with the same signing digest, append or
remove auths, or re-use counts for a different call. No transferable
authorization token is proposed. Proof success is valid only inside this
context, for these bytes and selected state/policy/provider, up to commit.

Program reads observe the pre-state plus the current transaction's private
staged overlay for ordinary data effects, with explicit provenance. Independent
authorization and proof checks must use the common pre-state, not a newly
staged keyset that would bootstrap its own rights. Any intended intra-transaction
authority change would need a separate approved rule; none is inferred here.

At commit the backend atomically validates the execution-position/predecessor
binding, policy selection, read/write dependencies (including absence), and
publishes all staged effects or none. It must prevent write-skew and changes
to any authorization/nonce/fee dependency between proof checking and commit;
validating only write targets is insufficient. A conservative backend may
require the exact expected global version/execution cursor to remain unchanged,
trading parallelism for simpler correctness. Reordering/conflicting execution
must discard the attempt and reacquire the correct fresh pre-state, never
carry forward cached proof success.

This can be implemented by an MVCC/transactional persistent backend with pinned
read versions, serializable dependency validation and atomic write batches,
or a bounded in-memory overlay with a trusted version/commit arbiter. Those
are possible implementations, not capabilities established for a repository
persistent native `AccountStore`. Snapshot retention, read-set, staged-effect
and context-lifetime budgets must be explicit and supported; do not clone the
unbounded whole store to obtain a "bounded" snapshot.

**Alternative: backend-enforced serialization.** An exclusive backend
execution lease acquired at the correct chain position can exclude *all*
relevant writers and policy/provider changes through commit, with bounded
staging and atomic publication. It fits a single-writer in-memory backend or
persistent backend with a real transaction/lock manager. A process-local mutex
is insufficient if other processes or storage clients bypass it. Holding the
lease across crypto limits concurrency and can extend stalls. It still needs
rollback/staging, explicit cancellation and uncertain-commit handling.
The primary versioned proposal separates immutable reads from crypto duration
and permits validated concurrency, while requiring stronger commit evidence.

Snapshot consistency is not freshness: S0 can be internally consistent yet
wrong for a transaction that must execute after S1. The chain-selected cursor
must identify the correct pre-state, and commit validation must preserve that
binding. `&mut S`, an `Arc`, coherent `get_bounded`, cloned `Account`, or
untrusted version ID establishes neither property.

### Event order and release

1. Resolve authoritative chain position and active native policy; check local
   capacities/provider/backend support before any state effects.
2. Acquire and pin the correct pre-state/context with bounded lifetime/resources;
   bind the complete immutable transaction and provider interpretation.
3. Run structural preflight and bounded proof evaluation through that context;
   if a transitional legacy check is selected, run it on the same context too.
4. Perform independent program, payer, nonce/replay, fee and creation-authority
   checks against the pre-state; stage permitted effects privately.
5. Atomically validate all dependencies, absence predicates and chain cursor,
   then publish all effects and known outcome together, or publish none.
6. Release snapshot/lease, read set, staged buffers and provider/context ownership
   on success, deterministic refusal, known local failure or cancellation.

Cancellation before commit discards staged changes and releases context.
Cancellation racing with commit requires an authoritative commit outcome:
do not report refusal or retry until publication is known. Uncertain commit
retains a bounded recovery reference rather than reusing admission context;
halt advancement and reconcile durable outcome before any replay. No normal
execution capability survives release. Deadline/retention/diagnostic budgets
and recovery identifiers are prerequisites for a real backend design, not new
signing-recovery mechanisms approved by this document.

## 6. Independent authority, staging and creation

Native proof success does not authorize the selected program, authenticate the
payer independently, reserve a nonce, validate replay policy, charge fees or
permit creation. Current native auth checks transaction-supplied signer flags;
`TxExecutor::execute_transaction` dispatches after that check. Neither that
boundary nor `KeysetProgram::handle_create` supplies a general payer/nonce/fee
policy. Native transaction fields alone do not enforce those rules.
Other system programs can impose program-specific conditions; they must be
inventoried and made context-consistent before integration, not replaced by
a generic weighted-proof summary.

Pending independent decisions: which identities may invoke each program/op;
whether/how payer must appear in required signer metadata and satisfy its own
keyset; nonce namespace, expected value, replay and advancement rules; fee
calculation/limit/charging rights and failure treatment; target-ID namespace,
creator authority, initialization funding and keyset lifecycle. No unsigned,
self-signed or newly created-keyset bootstrap exception is proposed.

Proposed per-transaction staging preserves earlier successful transactions in
the block as the current pre-state. Current writes/deletes are private until
commit. Deterministic refusal discards that transaction's staged effects;
local execution inability stops at that position rather than continuing with
a committed failure result. Known commit failure publishes nothing and stops;
uncertain outcome stops/reconciles before advancing. The choice to include a
deterministic failure receipt, continue the block, consume nonce or charge fees
on refusal is pending; no new fee-on-failure/replay policy is silently adopted.
If such effects are approved, they must be an explicit atomic disposition,
not leaked partial program effects.

Creation requires independent creator authority and admitted preparation,
then an absent-target read predicate plus insertion validated atomically with
all other effects. A concurrent insertion invalidates the attempt, even if
the initial absence read was correct. `prepare_keyset_account_bounded` only
returns a prepared `Account`; it neither inserts nor authorizes it.
Existing `get`-then-`put` creation and `BlockExecutor` supply no transaction
rollback or atomic-creation guarantee.

## 7. Proposed deterministic failure classification

This table is a proposed disposition contract, not new Rust error variants or
changes to existing mappings. Evidence/state classification uses the same
selected pre-state and profile on every validator. Unsupported local machinery
must never silently become a committed invalid-transaction outcome.

| Condition / existing category example | Proposed class and response | Retry context |
|---|---|---|
| Invalid signature, missing suite entry in a fully supported allowed profile, ambiguous proof, insufficient verified weight | Deterministic transaction-evidence refusal; discard stage. | Same immutable context may diagnose; any later execution attempt reacquires correct fresh context. |
| Malformed stored framing/descriptors, conflicting weights, wrong owner/executable metadata in the authenticated pre-state | Deterministic state/evidence refusal under selected rules; no writes. Whether malformed canonical state invalidates the block rather than the transaction receipt remains approval-required. | No local repair/default; fresh context only after authoritative state/rule resolution. |
| Missing required keyset account in selected pre-state | Deterministic refusal, not bootstrap permission. | Fresh context on any reordered attempt. |
| Selected protocol signature/proof/keyset limits exceeded | Deterministic policy refusal after approval of those limits. | Retrying unchanged input in same position cannot help. |
| Unsupported suite forbidden by policy versus allowed suite unavailable locally | Forbidden evidence is deterministic refusal; missing local allowed implementation is local inability. `SuiteNotFound` alone cannot establish which. | Local support fixed; fresh context. |
| Returned ID/span inconsistent with requested state/backend contract | Local backend integrity inability unless independently proven malformed canonical state; stop, explicit diagnostic. | Investigate backend; fresh context, no committed guess. |
| Snapshot unavailable/expired, wrong chain-position provenance, unsupported bounded reads | Local inability; fail closed, no fallback or receipt, stop execution. | Acquire correct fresh context after support/recovery. |
| Workspace capacity below selected profile, allocation/reservation failure | Local inability; no input truncation, partial stage or deterministic receipt. `BoundedReadError::Backend` includes allocation failure today. | Restore capacity/resources and acquire fresh context. |
| Backend I/O failure or non-invalid-signature crypto backend error (`VerificationFailure`) | Local inability; stop without committing a transaction classification. | Recover backend/provider; fresh context and recheck all evidence. |
| State/dependency/target-absence conflict at validation | Attempt invalidated, not invalid transaction evidence; discard stage and cached proof results. | Reacquire chain-correct pre-state and rerun all checks; never retry just the write. |
| Known atomic commit rejection/failure | No publication; stop advancement, explicit local error. | Fresh context after fault resolution. |
| Uncertain commit, including cancellation during publication | No success/failure receipt inferred; halt, reconcile authoritative outcome before retry or advancement. | Never blind replay; fresh context only after outcome known. |

The trusted backend must distinguish authenticated missing/malformed evidence
from inability to read it. Current error enums and legacy `ExecutionError`
collapse some distinctions; this task leaves those mappings unchanged.
No validator-dependent allocation/I/O failure may be encoded as a committed
transaction failure merely because current `BlockExecutor` records errors.

## 8. Resource and compatibility consequences

Carry forward the assessment's work bounds: at most 8 bounded keyset reads,
16 entries each, and at most `sum_k(p_k*e_k) <= 128` signature attempts for
8 proofs, plus per-entry descriptors and worst-case `O(E^2)` exact canonical
deduplication/reachability work. Exact-index coverage and independently
reachable thresholds imply `sum(max(m_k,r_k)) <= sum(p_k) <= 8`, necessary but
not sufficient. Preparation's eight-proof reachability budget is not an
actual multi-group transaction feasibility result.

Signing body length is `91 + 36*A + C` (plus 8-byte hash domain tag).
Streaming digest work is `O(A+C)`; grouping/preflight and proof gathering
cost `O(A*G + U*G)`. The 8,192-byte coverage bitmap ends at preflight return;
the group/proof arrays span evaluation, while one owned bounded account and
its borrowed parser/proof workspace are live per group. The assessment's
compiler-specific object inventories remain historical observations, not
physical stack/allocator/RSS guarantees. Caller-owned transaction/store,
provider/ML-DSA workspace and backend allocations remain outside helper bounds.
Context snapshots, dependencies and staged writes are additional owners needing
independent budgets; the proposed context is not proven bounded by helper arrays.

Stored framing is `12+6*n+sum(key_bytes)`; create input is
`42+5*n+sum(key_bytes)`. At 16 entries/65,536 encoded bytes the aggregate
key payload can reach only 65,428 stored or 65,414 create bytes, respectively.
Sixteen 4,096-byte keys do not fit after framing. Eight 8,192-byte signatures
consume the whole aggregate budget but do not cap transaction metadata/body.
Genuine ML-DSA-44 public keys/signatures here are 1,312/2,420 bytes, not padded
synthetic maxima.

**Transitional intersection proposal only:** requiring both isolated and legacy
verifiers would avoid widening acceptance relative to legacy, but still reject
legacy-accepted unreachable thresholds, conflicting duplicates, unsupported
unused entries, invalid metadata and over-budget proofs/accounts. Legacy's
first same-suite entry refusal still rejects isolated-accepted later-key proofs;
aliases/canonical identity semantics do not become fully integrated weighted
authorization. Empty/exact-index coverage remains required by both.
This is not behavior-neutral and does not close F1/F2.

That route repeats reads and crypto: isolated up to 8 bounded reads and 128
attempts/descriptors as above, plus legacy one owned `get`/decode per auth and
up to 8 selected-key signature checks/provider lookups. It also repeats hashing
and retains legacy `tx_digest`'s `O(body length)` signing-preimage allocation
and copying plus owned keyset decoding, not just bounded borrowed parsing.
Full simultaneously-live ownership and backend snapshot retention must be
assessed for the actual combined call order; isolated-helper memory accounting
cannot be applied to the combined route. Both checks would need the same pinned
state/provider; merely calling both on a moving store solves nothing.

No approved body cap, deployed corpus, persistent native backend guarantee,
target-hardware performance acceptance or production state consistency follows.
No benchmark rerun or reopening of completed assessment corrections.

## 9. Trust assumptions, review decisions and failure boundaries

Trust the chain executor to select canonical execution order/pre-state and the
approved profile; the backend to bind provenance, immutable reads and atomic
serializable commit (including all writers and absence); provider implementations
to obey selected immutable canonical/verification semantics; programs to use
only the context for authorization/effects; and validators to implement the same
approved rules. Transaction-supplied metadata, version hints, keyset bytes and
proofs are untrusted inputs. Crash durability/uncertain publication and provider
inability are local failure boundaries, not transaction authenticity evidence.
This proposal does not add durable anti-rollback or signing continuity.

| Unresolved choice | Recommendation | Alternative | Compatibility impact | Required evidence | Approval |
|---|---|---|---|---|---|
| Policy authority/version mapping | Chain-derived immutable profile at execution position | Authenticated explicit block policy reference with equivalent deterministic mapping | Rule/version mismatches may stop old validators | Governance/encoding/upgrade design and cross-validator vectors | NOT APPROVED |
| Numeric candidate/profile capacity | Review existing candidate separately; reject locally unsupported implementation | Different justified approved ceilings | Rejection of previously accepted inputs/state | Corpus, bounded backend and target-hardware assessment | UNAPPROVED |
| Context/commit mechanism | Pinned immutable pre-state plus atomic serializable validation/commit | Exclusive backend lease through staged atomic commit | Conflicts become retries, resource/concurrency costs | Backend provenance, all-writer coverage, write-skew/absence/crash tests | DRAFT |
| Provider suites/aliases/lifecycle | Policy-pinned complete interpretation | Versioned allowlist with explicit migration | Unsupported/unused entries and rotation behavior change | Canonical vectors, provider failures and upgrade compatibility | NOT APPROVED |
| First verifier integration | Additional required intersection, same context, summary discarded | Direct weighted-verifier replacement after compatibility review | Intersection narrows legacy; replacement may widen later-key acceptance | Every assessment compatibility witness plus combined-route budget | NOT APPROVED |
| Program/payer authority | Explicit independent pre-state rules per operation and payer | Reviewed program-specific payer delegation | May reject previously accepted signer declarations | Authority inventory, unauthorized payer/op controls | OPEN |
| Nonce/replay and fee/failure effects | Explicit atomic rules; no implicit consumption/charge | Reviewed fee-on-failure/nonce-consumption disposition | Receipt/replay/balance changes | Sequential repeated-tx and refusal/commit vectors | OPEN |
| Creation rights/absence | Independent creator right, atomic absence+insert | Namespace-specific approved creator rules | Existing creation may narrow; no bootstrap default | Present/absent conflict, authorization, all-or-none tests | OPEN |
| Failure receipts/state malformation | Separate local inability from deterministic evidence; stage discard | Block invalidation for malformed canonical state | Changes continuation/receipt semantics | Cross-validator mappings, backend faults/uncertainty | NOT APPROVED |
| Context budgets/cancellation | Bounded retention/dependencies/stage with outcome-aware release | Serialization with bounded lease duration | Resource inability halts rather than commits failure | Expiry, cancellation-before/during-commit, retention exhaustion | OPEN |
| Activation/public rollout | Keep disabled until all independent gates accepted | No rollout | No current caller behavior change | Corpus/backend/hardware, program/replay/effects and lifecycle review | DISABLED / NO-GO |

## 10. One narrowly scoped next implementation proposal

**Propose only an opt-in isolated ledger context prototype for immutable
pre-state reads, not runtime integration or production commit.** Allowlist:
one new `crates/qbind-ledger/src/native_admission_context.rs`,
module export in `crates/qbind-ledger/src/lib.rs`,
one new `crates/qbind-ledger/tests/run_422_native_admission_context_tests.rs`,
and this contract's status/evidence updates. Do not edit helpers, defaults,
runtime, programs, manifests, wire or node paths. Reviewer must separately
authorize this allowlist; it is not the current task's allowlist.

Prototype receives a trusted test execution-position/profile binding and a
borrowed immutable backend view, binds the full transaction and fixed provider,
exposes diagnostic proof checking only, and cannot commit or export authority.
No whole-store clone or production activation. Preconditions for this slice:
approve the *prototype's* immutable-view/provenance and release API, explicit
test-only profile fixtures (numbers still unapproved), provider immutability
assumption and local-inability classification. Protocol governance root,
numerical approval and persistent atomic commit are later gates, not secretly
implemented as test constants.

Required tests: mixed-proof transaction refuses on each context-pinned S0/S1
while today's switching characterization still passes unchanged; genuine
matched controls; wrong chain-position/profile rejection; missing/unknown/local
unsupported context refusal with no fallback/effects; complete transaction/proof
identity binding including same-signing-body different auths; unchanged backend,
bounded-read failures and cancellation/release. This slice proves only pinned
read lifetime behavior under its trusted prototype assumptions. Later production
gates require chain-selected freshness, serializable atomic commit/staging,
creation conflict tests, program/payer/replay/fee rules, complete error mappings,
backend crash evidence and combined-route compatibility/resources. Public DevNet
requires independent acceptance beyond that slice.

## 11. Validation and delivery

Tested source HEAD: `f06bb7ad4bd9a9fdf694e07d696eaf8d5f205fb9`;
tree: `8f61c60c6fbba789d1387953ab31c9d9bce99486`;
new test blob: `858baf09554b20988b8d1acc826d614c60a70f91`.
Source and the initial draft were committed before the focused validation.
Subsequent updates are evidence/documentation only; final Rust must equal that
tested blob exactly. Compiler: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`,
LLVM 23.1.1, target `x86_64-unknown-linux-gnu`; ordinary workspace test profile,
no overrides beyond the literal `LIBCLANG_PATH`.

| Literal command | Result at tested source |
|---|---|
| `LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-ledger --test run_422_native_admission_state_contract_tests -- --nocapture --test-threads=1` | Exit 0; 2 selected, 2 passed, 0 failed, 0 ignored, 0 measured, 0 filtered. A/B/C share one unchanged transaction in one test; D is separate. |
| `rustfmt --check --edition 2021 crates/qbind-ledger/tests/run_422_native_admission_state_contract_tests.rs` | Exit 0; no mutation. |

The first exact target invocation at the same source exited 101 before selecting
tests: bindgen could not find libclang under `/usr/lib/llvm-18/lib`.
`apt-get update -qq` / `apt-get install -y -qq libclang-18-dev` restored this
environment prerequisite (installation exit 0; update warned of an unrelated
Chrome repository DNS failure). The unchanged-source exact retry above passed.
Cargo downloaded/built locked dependencies; no manifests or lockfile changed.
No benchmark, full ledger/system suite, node build/check or Miri run here.
Earlier assessment results retain their original source/profile attribution.

Historical prefix inventory: D7 starting length 2,596,194 bytes, 23,538 CRLF,
zero bare LF, no terminal newline; contradiction 2,652,524 bytes, 4,021 LF,
zero CRLF, no terminal newline. Both retain mode `100644`. Appends use the
respective EOL convention and retain no terminal newline; complete starting
bytes must remain exact prefixes, including the old EOF bytes. New files use LF.

Delivery checks cover CRLF-aware working-tree whitespace and complete
baseline-to-final whitespace, exact four-path scope/modes, prefix/EOL/EOF
preservation, unchanged production/prerequisite Rust and exact tested-test
correspondence. Final self-referential HEAD/tree identities, complete four-path
mode/blob manifest, clean worktree and non-force remote-tip equality are
reported after the documentation-only commit and task-branch push, not embedded
in their own hashed content.

Preserved posture: `D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED`;
`D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET`; §13.6 whole-lifecycle
INCOMPLETE; activation DISABLED; public DevNet NO-GO; durable anti-rollback
NOT-ESTABLISHED; C4/C5 OPEN; RS1 OPEN. All candidate limits UNAPPROVED.
No F1/F2 closure, production state-consistency guarantee or release approval.
Push only the named task branch; no PR, merge, main push, force-push, activation
or deployment.
