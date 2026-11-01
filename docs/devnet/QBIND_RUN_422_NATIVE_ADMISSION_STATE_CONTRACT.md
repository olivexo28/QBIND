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

## 12. Isolated native admission context slice (RUN 422)

**Whole contract: DRAFT / NOT APPROVED / NOT IMPLEMENTED.** Only the unused
concrete in-memory diagnostic read-context slice is implemented. All numerical
candidate limits remain **UNAPPROVED**. This is not production state-consistency
enforcement, F1/F2 closure, release readiness or chain-policy approval.

### Source, selection and trust boundary

`crates/qbind-ledger/src/native_admission_context.rs` adds `PrototypePolicy`,
`FixtureBinding`, `FixtureProfileStatus`, `PrototypeFixture::new_for_fixture`,
`NativeAdmissionContext::new_for_fixture`, `evaluate` and consuming `cancel`.
`crates/qbind-ledger/src/lib.rs` changes only by exporting the module.
No existing evaluator, AccountStore, provider, runtime/program/node caller,
manifest, dependency, feature, wire format, signing preimage or default changes.
The resource assessment and existing state-contract characterization are unchanged.

The private fixture source contains one concrete `&InMemoryAccountStore`, one
`&dyn CryptoProvider`, one copied complete binding and an explicit selection
status. A separately presented `Option<FixtureBinding>` is compared with that
source, not with itself. Labels cover u32 chain identity, a 32-byte combined
execution-position/pre-state identity, a 32-byte profile identity plus version
and every selected limit, and a 32-byte fixture provider identity. The transaction
chain ID is independently compared with the fixture chain. These labels do not
authenticate the fixture's state, policy or provider; there is no governance
root, activation height, production registry or new wire policy field.

Missing request, unavailable fixture/selection, chain or pre-state mismatch,
unknown profile identity, inactive profile, mismatched version/limits and
provider identity, and insufficient G/P/E return fixed-size
`NativeAdmissionContextError` categories before evaluator entry, account reads
or provider work. Unknown identity and mismatched version are distinct cases.
Selected max_keyset_account_count <= G, max_authentication_proof_count <= P,
and stored_keyset.max_entries <= E are required even when the actual transaction
would fit smaller arrays. No selected limits are lowered and no legacy/default
fallback exists. These are trusted fixture-contract checks, not provenance
verification or policy approval.

The supported store has a private ordinary HashMap and mutation requires a safe
mutable borrow. Its immutable borrow enforces stable in-memory account contents
for this context's usable lifetime. Borrowing arbitrary `&dyn AccountStore`
would not: that trait promises only per-account coherence and admits the
baseline switching store. The constructor accepts only the concrete store;
no extensible snapshot trait is introduced. Do not generalize this argument to
persistent stores, interior-mutable implementations or other processes.
Execution-position and policy provenance are trusted fixture inputs only.
Provider semantic stability and conformance are separately trusted assumptions,
not proved by a trait-object borrow or Arc. No production chain authority,
freshness or commit guarantee is established.

### Complete transaction, delegation, errors and release

The context immutably borrows the complete native Transaction, including all
auth vectors, and retains the selected provider reference and binding. Its
argument-free `evaluate()` delegates to
`evaluate_native_transaction_proofs::<G,P,E>` with those original inputs.
There is no replacement transaction/store/provider/limits parameter, public
field mutation, rebinding, Clone/Copy, serialization, execution, insertion,
commit, nonce reservation or transferable authorization method. A signing-body
digest excludes auths; digest equality is not used to accept proof substitution.

The private read-only adapter delegates each genuine bounded read to the same
borrowed concrete store. Unbounded get explicitly panics if wrongly reached;
put/delete return explicit read-only ProgramError and are inaccessible to public
callers. Evaluation uses get_bounded only, with no unbounded fallback.
Delegation preserves exact-index coverage, first-occurrence AccountId grouping,
one bounded owned account per group, borrowed parsing and complete semantic
admission, independent thresholds, all supplied proof verification and checked
streaming digest semantics. No evaluator implementation is copied.

Construction is fixed-size and performs no crypto, transaction/proof cloning
or snapshot allocation. Context errors describe prototype availability or
configuration only. `evaluate()` preserves `NativeTransactionProofError`
detail separately; backend/crypto inability is not universally classified as
an invalid transaction and no consensus receipt mapping is invented.
`NativeTransactionProofSummary` is uncached diagnostic counts, not an execution
token. Each evaluation, including repeated evaluation, does fresh helper work.

Drop or consuming cancel ends only this context's borrows and copied binding.
It performs no reads/evaluation, writes, deletes or commit, leaves no reusable
context, and does not destroy the caller-owned transaction, provider or store.
There are no staged effects, locks, MVCC owners or recovery references to release.
Unwinding is tested through the existing provider interface, without adding a
callback API. Injection controls are private cfg(test) or clearly identified
test providers, not production bypasses or genuine backend/crypto faults.

### Acceptance source/test mapping

`crates/qbind-ledger/tests/run_422_native_admission_context_tests.rs`:

| Test | Evidence asserted |
|---|---|
| pinned_generations_refuse_mixed_genuine_proofs_and_accept_matched_controls | Four distinct genuine ML-DSA-44 keys; S0=A0+B0 and S1=A1+B1. Unchanged A0+B1 refuses as KeysetProof(InvalidProof) on S0 at B (two lookup/descriptor/verification calls), and on S1 at A (one each). Matched controls succeed with exact summary (2,2,2), two calls each. Complete transactions/wire bytes and both account generations remain unchanged. |
| fixture_selection_refusals_and_small_transaction_workspace_controls | Separate trusted/requested fixture bindings; all selection refusals, transaction chain mismatch and G/P/E incompatibility; zero observed provider work before refusal. The unchanged small transaction succeeds through the old evaluator with arrays (2,2,1), yet the selected (8,8,16) profile refuses those local capacities. Fresh valid context succeeds with fresh provider work. |
| complete_transaction_binding_does_not_use_signing_digest_as_proof_identity | Equal signing-body digests with altered auth vectors, bit-flipped genuine proof and late invalid extra proof. Changing the caller's copied request cannot change context policy. Separate contexts freshly refuse; original context continues to evaluate its original complete transaction successfully. Late threshold attainment does not skip supplied proofs. |
| concrete_bounded_read_and_existing_evidence_refusals_preserve_state | Missing B, 65,537-byte B, malformed B, wrong-owner B and executable B after genuine A work; exact helper errors, preserved complete supplied state/transactions, and fresh valid retries. |
| injected_provider_failure_and_unwind_release_only_context_borrows | Explicit synthetic InternalError and panic controls use genuine input material and real descriptor delegation. VerificationFailure/panic does not succeed or mutate state; caller owners survive and a fresh genuine provider/context succeeds. No claim that injection proves genuine provider reliability. |
| cancellation_and_drop_do_not_evaluate_or_destroy_caller_owners | Unused contexts cancel/drop with zero provider work and no state effects; caller-owned store/proofs can then be mutated, restored and freshly evaluated. |
| report_fixed_context_and_configuration_sizes | Compiler-derived type sizes; context storage is independent of G/P/E; not physical memory/stack/RSS accounting. |

Private inline tests in the new module have the
`run422_native_admission_context` prefix. They observe evaluator/bounded-read
entry counts (zero on early refusal, nonzero valid entry), private adapter
write/get refusal, and an explicitly injected helper-level Backend error while
retaining the concrete pinned store, followed by fresh genuine success.
Those entry counters are cfg(test) only; test-local thread storage does not
create threads. Integration provider lookup/descriptor/verification counts
are observed separately. First-occurrence ordering and absence of extra reads,
writes or fallback are also source-derived from unchanged delegation and the
private adapter, not falsely claimed as an integration store-call observer.

Five compile-fail module doctests and a valid construction/release counterpart
cover store mutation, transaction/proof mutation, required store-owner lifetime,
unsupported generic backend type, and reuse after consuming cancellation.
They use actual APIs/imports and fail for borrow/type/move reasons, not missing
APIs. No generic backend is added just to elicit Unsupported. Genuine account
materialization allocation failure is not manufactured; the private Backend
injection is helper-level propagation evidence only.

The unchanged `run_422_native_admission_state_contract_tests` target still
allows A/S0 followed by B/S1 through its switching store. Its success remains
valid under the old diagnostic contract; it is not exposed through the new
restricted construction surface.

### Inherited and excluded resources; measured sizes

At tested source `34ee33fd5c96c6d78d9979293411823fa622a170` / root tree
`ee92c7c5a9c4bbba1ea4d0c6abb012b812b2d431`, ordinary x86_64 workspace profile,
the integration size_of observations are: context 224 bytes (unchanged for
G/P/E=0/0/0, 8/8/16 and 32/32/32), fixture 224, binding 192, policy 120,
context error 1, evaluator error 24, limits 80, summary 24, Transaction 160,
Account 120, provider reference 16, store reference 8. The production-layout
context stores transaction reference (8), adapter/store reference (8), provider
reference (16) and copied binding (192). Binding includes three 32-byte labels,
chain ID, policy/version and limits, plus compiler alignment padding.
Private cfg(test) observations are context 248 and adapter 24: additional
evaluator/read counters and injected-backend Boolean plus compiler padding.
Test entry instrumentation is excluded from the production-layout observation.
These are type-size observations, not physical-memory/stack/RSS guarantees.

The context adds only borrowed store/transaction/provider references and a
fixed-size copied fixture binding. The fixture owns no snapshot. The immutable
inputs span the usable context lifetime; the copied binding is discarded on
release. G/P/E helper arrays are created afresh inside each evaluation, not
retained in the context. The inherited 8,192-byte coverage bitmap ends with
preflight; group/proof arrays span evaluation and one newly owned bounded
Account plus borrowed parser/semantic/proof workspace is live per group.
The completed assessment's ownership/work qualifications remain unchanged.

Caller-owned transaction/proof capacities, the entire store and its allocations,
backend materialization, provider/ML-DSA internals, allocator behavior, compiler
stack layout and physical memory remain outside component accounting. No whole
store clone, account snapshot, body clone, physical-memory guarantee, allocator
hook, unsafe code, threads, sleeps, benchmark suite or production resource
ceiling is introduced.

Remaining requirements include chain authority/correct execution position and
freshness; authenticated approved profile provenance and numeric approval;
provider conformance/immutable suite interpretation; persistent backend/all-writer
guarantees; staging, serializable atomic commit, cancellation during publication
and recovery; independent creation/absence, program/payer authority, replay,
nonce/fee and compatibility/corpus/hardware rules. This read-only slice
implements or approves none of those whole-contract obligations.

### Final-source validation and delivery attribution

The exact final-source literal commands, counts (overlapping, not additive),
initial environment failure and zero-selection correction, baseline/object
facts, prefix/mode/EOL/EOF inventory and delivery checks are appended under
`RUN 422 - isolated native admission context validation` in
`QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`. The producing source commit/tree are
`34ee33fd5c96c6d78d9979293411823fa622a170` /
`ee92c7c5a9c4bbba1ea4d0c6abb012b812b2d431`. All six new module doctests
executed in the full ledger run; direct rustc metadata checks separately
confirmed E0502/E0502/E0597/E0308/E0382 and a valid counterpart with exit 0.
Evidence-only final commits do not change tested Rust.

Preserved: D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED;
D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET; §13.6 whole-lifecycle INCOMPLETE;
activation DISABLED; public DevNet NO-GO; durable anti-rollback NOT-ESTABLISHED;
C4/C5 OPEN; RS1 OPEN. All candidate limits UNAPPROVED. No production integration,
atomic commit, activation, deployment, PR, merge, main push, force-push, F1/F2
closure or release approval.

## 13. Bounded native staged-effects fixture slice (RUN 422)

**Whole contract: DRAFT / NOT APPROVED / NOT IMPLEMENTED.** This slice is
implemented only as an unused trusted fixture model. All limits remain
**UNAPPROVED**. The primary persistent immutable-version plus serializable
validation/commit recommendation in section 5 is unchanged, not implemented
or replaced by this concrete in-memory serialization alternative.

### Binding and exclusive access

`native_staged_effects.rs::NativeStagedEffects::begin_for_fixture` receives
one concrete `&mut InMemoryAccountStore` before any proof work. Within that
outer borrow it constructs the existing `PrototypeFixture` from an immutable
reborrow, then the existing `NativeAdmissionContext`, evaluates afresh and
cancels the temporary diagnostic context. The outer exclusive borrow is
retained in private session fields until consuming publication, cancellation,
drop or unwind. There is no success-token handoff or reacquisition gap and no
self-referential session. Existing context selection/capacity checks and proof
evaluation are delegated, not copied. A failed begin produces no session.

The session borrows the complete immutable transaction including proof bytes,
retains the selected provider reference, and copies the complete selected
binding/status. Trusted `FixtureSelection` inputs are separate from requested
`Option<FixtureBinding>`. Stage configuration is checked before context/proof
work. Missing, unavailable, mismatched and unsupported context refusals retain
their existing categories; proof errors retain their typed detail separately.
No replacement transaction, provider, policy or store arguments/setters exist.
Changing a caller's copied binding cannot change the retained selection.

Safe external store access is excluded while the session remains usable:
the concrete private HashMap has no interior mutation surface. This is compiler
enforced serialization, NOT implemented optimistic conflict detection or a
generic/persistent/all-process backend contract. Holding exclusivity through
crypto serializes this model and limits concurrency; no throughput measurement
or claim is made. Provider semantic stability and label/policy/execution-position
provenance remain trusted fixture assumptions, not current-authority capabilities.

### Trusted plans, ownership and refusal

Only explicit create, replace and delete fixture effects are supported.
They are trusted effect plans, not native program execution. Proof success
does not establish program/payer authority, nonce/replay policy, fees, creation
rights or a bootstrap exception. There is no dispatch or read-your-writes API.
No production caller may use this model.

The private `[Option<FixtureEffect>; W]` stores complete moved Accounts.
Independent caller-supplied limits bound operation count, each logical data
length, each actual Vec capacity and checked aggregate retained Vec capacity.
W is an implementation array capacity, not an approved profile. Small test
effect limits (W=3, at most 3 operations, 8 logical/retained bytes per offered
account and 16 aggregate bytes) are UNAPPROVED and distinct from the existing
UNAPPROVED native proof candidate (8/8/16 workspace/selection).

Targets must be unique across all operation variants. No coalescing or implicit
overwrite is allowed. Admission checks the offered Account ID, resource limits
and uniqueness before changing any existing stage slot. Rejected create/replace
returns `FixtureAccountRefusal` containing the actual offered Account, including
its original data pointer/length/capacity. This owner can exceed the stage bound:
it is caller-offered, never admitted, and remains caller-owned after refusal.
Every staging refusal poisons the attempt, including a late invalid submission.
Ignoring an error cannot publish a previously accepted subset. Existing accepted
stage owners remain intact until cancel/drop or consuming publication refusal;
a retry requires a fresh begin and fresh proof evaluation.

Cancel/drop and prepublication unwind discard only session-owned effects and
release borrows. Caller store/transaction/provider owners survive. Publication
consumes on both outcomes; a publication refusal may drop all stage-owned
Accounts but leaves the complete original store unchanged. There is no cached
proof result and no reusable successful/cancelled session. Earlier successful
in-memory batches remain present after later refusal/cancellation, and a fresh
attempt observes that modified pre-state.

### Complete preflight and narrow publication argument

The crate-private model-scoped
`store.rs::InMemoryAccountStore::publish_native_fixture_batch` itself checks
eligibility/configuration, operation/resource counts, unique targets, matching
Account IDs, create-absent and replace/delete-present predicates, checked result
arithmetic and existing map capacity before taking ANY effect or changing ANY
map entry. It does not loop over fallible trait `put` calls. The existing trait,
public store methods and their behavior are unchanged; no map access or
general-purpose public batch mutation API is exposed.

The standard-library `HashMap::capacity` contract is the number of elements the
map can hold without reallocating:
`https://doc.rust-lang.org/std/collections/struct.HashMap.html#method.capacity`.
Admission requires checked `len + all_creates <= existing_capacity`, without
credit for any deletion. Creates execute first, while count increases only
within that admitted peak. Unique replacements target existing entries and
cannot increase count; deletions follow and reduce it. Unique targets make this
order irrelevant to the final logical contents. No growth factor, accidental
fixture spare capacity, reserve/try_reserve/shrink or rebuilding is relied on.
Insufficient capacity is `MapCapacity`, a LOCAL model inability, never
deterministic invalid-transaction evidence or a consensus failure receipt.
Fixture provisioning is outside the attempt and publication.

The fixed diagnostic summary is fully computed before first mutation.
The publication loops then only move admitted Accounts, replace and remove
entries. There is no fallible allocation, data cloning, external callback,
crypto/provider work, program execution, remaining fallible input validation,
unwrap/indexing or fault hook after mutation starts. Test-only thread-local
entry/mutation counters are internal observation, not user callbacks or failure
injection; production contains none of that instrumentation.

Concrete keys are byte arrays with standard Hash/Eq, the private map uses
standard RandomState, and Account contains scalar/byte-array headers and
Vec<u8>. No user-defined key/hasher/destructor code is invoked. Replaced/deleted
old Accounts are dropped, including deallocation of their original data Vec;
these existing-store owners are not copied into a rollback journal. Incoming
stage data and old store data coexist before displacement, and earlier newly
inserted data coexists with old entries until those later operations run.
HashMap hashing/probing is not constant worst-case lookup work. The argument
bounds stage ownership, not allocator metadata, total store/process memory,
physical stack/RSS or deallocation implementation internals.

Guarantee: no state changes on defined refusals; no externally observable
partial batch through supported safe access; no remaining fallible work of the
specified kinds after first publication mutation. This is normal-error
atomicity for concrete in-memory serialization ONLY. It is NOT persistent
atomic commit, crash durability, restart safety, rollback after arbitrary
midpublication panic, process-abort recovery or all-writer persistent isolation.
No midpublication panic injection/rollback claim is made.

### Evidence and remaining prerequisites

Integration target `run_422_native_staged_effects_tests.rs` covers genuine
ML-DSA-44 admission, invalid/mixed proofs, separate selection refusals, complete
transaction bytes, fresh provider counts, multi-effect headers/data, duplicate
and mismatched IDs, late resource/predicate refusal, intact returned candidates,
poisoning, drop/cancel, caller/provider prepublication unwind and sequential
success/refusal/cancellation. Injection controls are explicitly separate from
genuine cryptographic outcomes.

Private tests prefixed `run422_native_staged_effects` directly observe private
stage/base-state preservation, moved pointers/capacities and copied selection;
real map len/capacity exact and insufficient boundaries plus fresh provisioned
retry; helper rejection before consuming any input; zero mutation counters on
refusal; complete mixed operation results; scalar arithmetic overflow without
large allocations/fabricated Vec values; and compiler layout inventories.
Compile-fail doctests exclude conflicting external writers, transaction/proof
mutation, provider-owner destruction, private store/selection replacement and
reuse after consuming publication/cancel. A valid release counterpart and
genuine integration publication use actual imports/APIs.

Retained session storage is fixed fields plus W option-operation slots plus
admitted Account Vec capacities (aggregate bounded). Summary/errors/limits and
selection have fixed layouts; the refused-candidate error additionally owns the
offered Account's unadmitted allocation. G/P/E proof workspace is inherited and
temporary during begin: coverage preflight ends before group evaluation, and
one owned bounded read plus borrowed parsing/proof workspace is live per group.
No stage is retained during that proof evaluation. Existing store accounts and
caller transaction/provider are outside the NEW stage bound, not hidden new
owners. The stage then coexists with all existing store data through preflight.
Exact tested layouts and command/source attribution are in the D7 validation
appendix. No heap-backed operation index, whole-store/transaction clone,
rollback journal, unsafe code, allocator hook or new dependency is introduced.

Remaining production prerequisites include independently approved authority,
execution-position freshness/provenance, immutable governed provider policy,
numeric profiles, persistent/all-writer backend semantics, program/payer/
nonce/replay/fee/creation rules, full error/receipt mappings, corpus/resource
compatibility, cancellation/uncertain-outcome and durable recovery evidence.
Existing evaluators, assessment/characterization/context evidence, runtime/
program callers, wire/signing formats, manifests and production defaults remain
unchanged.

Preserved: D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED;
D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET; §13.6 whole-lifecycle INCOMPLETE;
activation DISABLED; public DevNet NO-GO; durable anti-rollback NOT-ESTABLISHED;
C4/C5 OPEN; RS1 OPEN. No F1/F2 closure, activation, deployment, PR, merge,
main/force push or release approval.

## RUN 422: isolated transaction-bound keyset-create composition (2026-11-01)

Whole native admission contract: **DRAFT / NOT APPROVED / NOT IMPLEMENTED**.
The new `native_keyset_create_model` module is IMPLEMENTED-ISOLATED, unused
trusted fixture composition, not production KeysetProgram execution. All limits
and execution-position/provider/profile labels remain UNAPPROVED trusted
configuration. No default, approved numeric profile, governance commitment,
activation mechanism or authenticated policy selection is supplied.

`NativeKeysetCreateModel<'a,G,P,E>` privately owns exactly one
`NativeStagedEffects<'a,G,P,E,1>`. Its constructor receives one complete
immutable Transaction, one concrete mutable InMemoryAccountStore, optional
selected provider/binding/status, separate requested native binding, and explicit
create-preparation/staging limits. There is no second provider, alternate call,
target ID, prepared Account or replacement transaction input after admission.
The wrapper has only consuming publication/cancellation after construction:
no arbitrary staging, inner-session extraction, rebinding, Clone/Copy,
serialization, read-your-writes or program dispatch.

Source argument (`crates/qbind-ledger/src/native_keyset_create_model.rs`):
lines 89-108 define private selected provider/binding/status; 111-124 define
explicit limits and fixed errors; 127-179 compose the private one-slot session.
Lines 140-153 check shared KEYSET_PROGRAM_ID and local compatibility before
external work: selected create max_entries <= E, staging max_operations == 1,
create logical output <= staging logical length <= individual actual-capacity
limit <= aggregate capacity. No selected limit is silently reduced.
Lines 154-164 delegate native selection/proofs to the unchanged constructor,
preserving its Context versus Proof error distinctions. Lines 166-178 enter
preparation only after successful fresh proof evaluation, pass the original
transaction.call_data and SAME selected provider to the unchanged bounded
preparer, and move the returned Account with its own returned ID directly into
create staging. A staging refusal's internally prepared Account is dropped
before its fixed-size reason is returned. Preparation/staging errors discard
the private session; no publishable partial result escapes.

One continuous exclusive borrow spans proof evaluation, preparation, staging
and publication/cancellation/drop. No store release/reacquisition occurs within
an attempt. Publication (lines 184-185) accepts no new inputs and delegates to
the unchanged complete batch helper in store.rs: all target predicates,
operation/ID/length/actual-capacity/aggregate checks and len + ALL creates
capacity calculation precede mutation, with no deletion credit. The absent
target predicate preserves any existing complete Account, including metadata.
Admitted map capacity supports subsequent moves without reservation or other
fallible publication work. Map provisioning occurs only outside an attempt,
including after a consuming MapCapacity refusal. Fresh retry reacquires the
session and repeats genuine proof evaluation and preparation.

Proof success does NOT confer creator, payer, program, nonce, fee, replay or
bootstrap authority. A proposed missing keyset cannot authorize its own create
from future state: existing bounded pre-state proof reads refuse MissingAccount
before preparation. A later separately admitted transaction may use a previously
stored keyset with genuine proofs, but execution-position labels remain fixture
inputs, not evidence of production freshness. Earlier successful publication
survives later existing-target refusal, map-capacity refusal and cancellation.

Resource overlap is phase-specific, not an end-to-end physical-memory bound:
inherited proof workspace and owned bounded account reads end before create
preparation; the empty one-slot session is live during preparation; the unchanged
create semantic workspace ends before destination reservation. One prepared
Account allocation moves into the stage and then map, while existing store
allocations and caller-owned complete transaction/provider remain live. The
preparer checks logical stored length and requests try_reserve_exact(length);
it does NOT guarantee an actual Vec-capacity ceiling before allocation. The
stage checks actual capacity only AFTER the transient prepared owner exists.
An over-capacity owner is disposed of on staging refusal, not published or
returned as a reusable capability. No stage budget is promoted to a
preallocation, allocator-overhead, physical-stack, RSS or provider-internal bound.

Compiler-measured x86_64 sizes for the tested G=2/P=4/E=4 fixture: wrapper
448 B, configuration 88 B, selected fixture 216 B, error 32 B, summary 48 B.
Observed prepared logical length 1330 B, requested reservation 1330 B and actual
Vec capacity 1330 B are distinct facts; equality in this run is not a guarantee.
The private map test measures capacity 3, succeeds at len+1=3 without capacity
change, refuses the next create at len=3, then provisions capacity 7 after
release and succeeds on a fresh attempt. Preparation-boundary pointer/length/
capacity equal those of the actual private map owner, not a get() clone.

Tests in `tests/run_422_native_keyset_create_model_tests.rs` cover genuine
complete-account publication and preservation (298-337), zero-work local/native
selection refusals (340-475), equal body digests with altered auth vectors,
missing required coverage, late invalid extra proof and no bootstrap (478-533),
genuinely re-signed altered-body preparation refusals (536-590), lifecycle/fresh
retry (593-627), explicitly synthetic semantic provider error/unwind after
genuine proof (630-658), later genuine use and preserved earlier creation
(661-692), and measured layouts (696 onward). The private cfg(test) store module
executes these same composition fixtures plus actual preparation-entry and
measured capacity/allocation controls. The new module's fixed-size cfg(test)
observer is not a production interface or allocator hook. Five compile-fail
doctests plus one valid counterpart all execute; direct rustc checks confirm
E0499, E0502, E0616, E0382 and E0382, with no unrelated failure cause.

Guarantee retained: normal-error atomicity for concrete in-memory fixture
publication ONLY. Construction failure, cancellation, drop, caller unwind and
injected provider failure/unwind before publication preserve the complete store
and release borrows. This is not arbitrary-panic rollback during mutation, crash
durability, restart safety, persistent isolation or production transaction
receipts. MapCapacity and destination-allocation/backend inability are local
inability, not consensus invalid-transaction receipts. No experimentally
reproduced allocator failure or production exploit is claimed.

Final Rust/test source commit `beec901e974715932f0d3faf6470189d0c562fec`,
tree `c5afb9d96a5bbbec43b5ae11b96bc9e6f581a466`: all seven required
validation commands exit 0. Focused new integration 10 passed; private selector
12 passed (10 shared composition fixtures plus 2 private controls); unchanged
staged/context/contract 9/7/2 passed; full ledger 787 passed, 0 failed,
16 pre-existing ignored; unchanged system keyset tests 2 passed. All six new
doctests passed, none ignored. Node check is compilation only; counts overlap.
Literal commands, per-target counts, initial missing-libclang restoration,
identity and prefix evidence are recorded in the D7 appendix.

Remaining authority/production prerequisites are unchanged: approved authority
and policy/provider provenance, numeric limits and resource compatibility,
creator/payer/program/nonce/fee/replay/bootstrap rules, production execution
integration, persistent all-writer isolation and commit semantics, receipt/error
classification, cancellation/uncertain outcome and durable recovery evidence.
No frozen prerequisite, production caller, parser/crypto adapter, account/wire
representation, signing preimage, manifest, dependency or feature is changed.

Preserved exactly: D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED;
D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET; §13.6 whole-lifecycle INCOMPLETE;
activation DISABLED; public DevNet NO-GO; durable anti-rollback NOT-ESTABLISHED;
C4/C5 OPEN; RS1 OPEN. All limits UNAPPROVED. No F1/F2 closure, deployed-path
readiness, PR, merge, main/force push, activation, deployment or release approval.

## RUN 422 — Native governance authority characterization

**DRAFT / NOT APPROVED / NOT IMPLEMENTED.** The new source/test characterization
is limited to `qbind_wire::tx::Transaction` through the real
`TxExecutor::execute_transaction` and registered `GovernanceProgram`. Genuine
ML-DSA-44 controls show that transaction-declared signer-keyset authentication
passes independently of the privileged governance authority question. Each of
the four existing native operations succeeded with an ordinary signer distinct
from the seeded 5-of-7 council identifiers and no supplied approval capability.
The witness recorded reads only of the signer keyset and fixed operation target,
then one target write; council keyset/member and payer accounts were not read.
Complete non-target state, account headers, transaction values and wire bytes
were preserved.

`proposal_id` and `eta_height` are encoded into signed `call_data`: changing
either without re-signing failed genuine authentication. Re-signed variants
(including proposal ID `u64::MAX` and ETA 0) succeeded with unchanged target
outcomes. The native context has no trusted execution height, and handlers do
not consult proposal approval, council membership, timelock or replay state.
The exact signed parameter-setter transaction was accepted twice with fresh
verification and one write each; its second write produced no further logical
state change. This is executor/handler source-test evidence, not approved
governance, deployed exposure, exploit, or consensus safety violation.

New test: `crates/qbind-runtime/tests/run_422_native_governance_authority_contract_tests.rs`.
New draft contract and bounded next fail-closed-boundary proposal:
`docs/devnet/QBIND_RUN_422_NATIVE_GOVERNANCE_AUTHORITY_CONTRACT.md`. The tests
exercise the actual `TxExecutor`, not only direct `Program::execute`; existing
system governance handler tests remain separate. The inspected node
`Node::apply_block`/`BlockExecutor` path is not a demonstrated executable or
network call site; EVM block execution, upgrade envelopes, trust-bundle
governance and consensus Proposal/Vote authority remain separate mechanisms.
The existing historical evidence is neither reclassified nor rerun.

Proposed future requirements include independently admitted authority, exact
network/position and operation/target/parameter/proposal binding, current
membership and provider interpretation, owner-approved threshold/identity
semantics, trusted height/timelock, one-use replay consumption, common-state
evaluation and atomic publication, fail-closed local inability and explicit
uncertain-outcome/restart/rollback limits. Payer, nonce/fee, keyset-creation
and validator-registration rights remain separate unresolved obligations.
The sole next proposal is a production unavailable/refusal gate immediately
before the four governance dispatch handlers, with positive authority execution
deferred to a later approved phase. Nothing in that proposal is implemented.

Producing test source revision:
`c279c7be1cc415032975f162109e5e2c3f9c6ed0`,
tree `3a08eca808d2e84c80d5b9f969289f0c21f8c0de`. Required focused runtime test:
exit 0, selected/passed 5/5, failed/ignored 0. Required combined runtime/system
suite: exit 0, selected 123, passed 122, failed 0, ignored 1 (one pre-existing
ignored runtime gas-model doctest). Counts overlap. Rustfmt and both
CRLF-aware whitespace checks exit 0. The first focused compile attempt in this
iteration failed before test selection with E0369 because `ExecutionError` does
not implement `PartialEq`; the test was corrected to assert exact error variant
and message. Its required-command rerun passed; no production or existing test
was changed. Full commands, counts and source attribution are appended in D7.

Preserved: D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED;
D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET; §13.6 whole-lifecycle INCOMPLETE;
activation DISABLED; public DevNet NO-GO; durable anti-rollback NOT-ESTABLISHED;
C4/C5 OPEN; RS1 OPEN. Whole native admission contract remains **DRAFT / NOT
APPROVED / NOT IMPLEMENTED**. All limits remain UNAPPROVED. No F1/F2 or C4/C5
closure, production authorization, deployed-path readiness, or release approval.


## RUN 422 bounded refusal implementation update

The bounded native refusal is now implemented in `GovernanceProgram` and tested using the two existing test targets; the earlier proposal for three new enforcement files/targets is superseded, and the old successful-write assertions were migrated rather than ignored or bypassed. All four recognized operations parse their existing call-only format, retain decode/trailing-data errors and then reach one private unconditional boundary. SuiteStatus's existing scalar validation runs before that boundary and before target access; the existing MainnetStatus decoder still rejects invalid enum encodings.

The exact result for a valid call is `ProgramError("native governance authority unavailable")`. This boundary executes before target lookup or state decoding, so absent/malformed target and missing suite-entry errors are intentionally no longer reached. Invalid SuiteStatus remains the call-only error even when the target is absent. No positive authorization is inferred from transaction authentication, council IDs/accounts, signed proposal or ETA fields, or requested mainnet status. TxExecutor's existing authentication-before-dispatch order is unchanged; authentication still incurs its legacy work and is not claimed to be allocation-free or newly bounded.

At source/test commit `99023fcb30ec2c6c042dea0f0196b88c072049ac`, real ML-DSA-44 executor tests verify fresh signature checks, signer-only account reads, zero governed reads/writes/deletes, and unchanged full account and transaction oracles. Direct Program tests are distinct and prove no handler bypass. Malformed-call, authentication retry, proposal/ETA, council-ID identity-claim, Ready/Activated, identical signed replay, absent-target, and malformed-target cases are mapped in the governance authority contract and D7 evidence appended with this update. Repeated refusal is not durable replay protection or decision consumption.

No positive authority provenance/currentness, timelock, one-use consumption, atomic publication, or recovery is implemented. Historical successful-write findings remain attributable only to `c279c7be1cc415032975f162109e5e2c3f9c6ed0`; new refusal behavior is attributable to the tested source above. No selected binary, running-node, network, or deployed-path evidence is established.

Preserved posture: D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED; D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET; §13.6 whole-lifecycle INCOMPLETE; activation DISABLED; public DevNet NO-GO; durable anti-rollback NOT-ESTABLISHED; C4/C5 OPEN; RS1 OPEN. The whole contract remains **DRAFT / NOT APPROVED / NOT IMPLEMENTED**. All candidate limits remain UNAPPROVED. No F1/F2 closure, C4/C5 closure, or release approval.
