# Atomic block with retained completion: bounded capability experiment

## Status and decision boundary

The owner selected **atomic block publication with retained completion** as
the primary candidate. Deterministic reconstruction remains an unselected
alternative. This note records a bounded, test-only capability experiment; it
does not authorize production wiring, recovery, signing, startup, deployment,
activation, or an integration decision.

The experiment uses synthetic keys and values. It does not execute a QBIND
block, invoke the node, use operational keys, simulate a power failure, test
real finality, or establish production identity, authorization, durability,
cross-process fencing, or recovery. It does not modify production source,
tests outside the isolated fixture, manifests, or lockfiles.

**Result:** the existing QBIND public interfaces inspected do not expose one
operation spanning VM account values/membership, authoritative position,
operation identity, and completion. The one-database `WriteBatch` control
passed, but it does not satisfy the actual two-database QBIND boundary. The
separate-database injected-boundary control produced partial state. Atomic
publication across the actual QBIND stores is therefore **BLOCKED / UNPROVEN**
for this candidate. This is not a claim that no backend or separately
justified redesign could provide the guarantee.

## Pinned scope and source provenance

- Reviewed source endpoint: commit
  `3803e00c985a1813d70553eef5e1c1b77884b5dc`, tree
  `e301d1f4917f98fc6746ce975e42d41c01d689e1`.
- Dependency resolution: `Cargo.lock` at that endpoint, blob
  `8f19cdd29d9923e04d600669fea26acd93b6d73c`; workspace package manifest
  `crates/qbind-ledger/Cargo.toml` pins the direct `rocksdb = "0.22"` range.
- Candidate protocol: `docs/security/evidence/candidate-durable-execution-recovery-protocol-20261109.md`
  at that commit, blob `e48d199a8544faa353036e0127cc7e874339689d`. Its
  sections 3.1–3.2 define the still-open stable identity and proof policy;
  sections 4.2–4.4 address retained completion, publication, and failures;
  sections 5 and 10 preserve the open recovery and authority decisions.
- Relevant pinned QBIND sources:
  - `crates/qbind-ledger/src/execution.rs`, blob
    `fe78bed4bddc5f00aa0ea2c8a464050106d84093`: `PersistentAccountState`
    (lines 1250–1285), `RocksDbAccountState` (1380–1483),
    `AccountStateUpdater` (1137–1141), `VmV0TxResult` (1913 onward),
    and ordered block results from `execute_block` (2508–2522).
  - `crates/qbind-node/src/execution_adapter.rs`, blob
    `13adcb22f3317485c47ed019daf019599193e721`: `AsyncExecutionService`
    queue-admission contract (460–475), process-local worker claim (495–505),
    and result/flush/height handling (1315–1382).
  - `crates/qbind-node/src/node_config.rs`, blob
    `f95376764ce5cc6d8ccd42567d134e3aa8dac207`: VM-v0 location
    `<data_dir>/state_vm_v0` (5271–5277) and consensus location
    `<data_dir>/consensus` (5279 onward).
  - `crates/qbind-node/src/production_consensus_storage.rs`, blob
    `636ef998eb51354f6794de0620b2e2149b6c0739`: production consensus
    storage open at the canonical consensus path (353–375).
  - `crates/qbind-node/src/storage.rs`, blob
    `9a78a55ce75b2e9e5a7107eb478d1da2ebc215f0`: separate consensus
    position interfaces including `put_last_committed`,
    `put_current_epoch`, and `apply_epoch_transition_atomic`
    (168–224, 293–315, 929–1110).
  - `crates/qbind-node/src/vm_v0_runtime.rs`, blob
    `0762478b16847ffaee3b06536cd5d5f23e0aca14`: VM-v0 account database
    opener (58–90).
  - `crates/qbind-wire/src/consensus.rs`: proposal canonical body and
    embedded QC/ordered transaction encoding, lines 915–950 at the pinned
    endpoint, blob `5a60b7a1aed1bfb93a78817224e11f89276e5868`. The signed body
    covers embedded QC bytes and transactions; it does not authenticate
    arbitrary external evidence.

The exact resolved Cargo packages are `rocksdb 0.22.0` and
`librocksdb-sys 0.16.0+8.10.0`, from `Cargo.lock`. The local registry
archives matched the lockfile checksums:

| Package | Cargo.lock SHA-256 | Local archive SHA-256 |
|---|---|---|
| `rocksdb 0.22.0` | `6bd13e55d6d7b8cd0ea569161127567cd587676c99f4472f779a0279aa60a7a7` | same |
| `librocksdb-sys 0.16.0+8.10.0` | `ce3d60bc059831dc1c83903fb45c103f75db65c5a7bf22272764d9cc683e348c` | same |

The matching unpacked `rocksdb-0.22.0` source was available at
`/usr/local/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rocksdb-0.22.0`;
the dependency file for the existing compiled `rocksdb` artifact names that
source path. Package metadata identifies the rust-rocksdb repository. The
lock-matched source archives establish integrity-matched package provenance
for these crate versions; no upstream git commit or source-tree identity was
independently pinned. They do not prove a specific deployed/native library
build, filesystem, or hardware durability profile. No native dependency was
rebuilt for this fixture.

Environment: Ubuntu 24.04.3 LTS; Linux
`6.12.8+ #1 SMP Thu Jul 30 23:01:31 UTC 2026`, `x86_64-unknown-linux-gnu`;
`rustc 1.99.1 (58cf8f9c3 2026-10-13)`, LLVM 23.1.1; Cargo
`1.99.1 (5f94df478 2026-08-27)`. The repository tree was on a filesystem
with 79–102 MiB available during the run; no unrelated files or build
artifacts were removed. The C/C++ compiler invocation for the pre-existing
native RocksDB artifact was not independently recorded.

## Existing behavior, possible backend capability, and gaps

| Area | EXISTING QBIND behavior at the pinned endpoint | Potential backend capability | UNPROVEN / required redesign |
|---|---|---|---|
| Account state | VM-v0 `RocksDbAccountState` opens its own RocksDB at `state_vm_v0`; the persistent interface exposes per-account get/put/flush. Missing or failed account reads return a default state. There is no block-level publication method in this interface. | A single database may group multiple keys in a RocksDB `WriteBatch`; the synthetic one-DB control exercised the crate API. | Actual account membership semantics and all changed values must be part of a defined atomic unit. A batch in one DB does not span the consensus DB. |
| Position | `RocksDbConsensusStorage` opens a separate RocksDB at `<data_dir>/consensus`; `ConsensusStorage` stores committed block ID and epoch separately from account state. Its epoch transition batch is a consensus-DB facility. | A redesigned store might place all commit data in one supported transactional boundary, or use another reviewed protocol/backend. | No inspected QBIND API atomically binds account values/membership to position, identity, and result. The consensus batch and sync writes do not establish this joint guarantee. |
| Completion | Direct ledger block execution returns ordered `Vec<VmV0TxResult>` including success/error, gas and fee fields. `AsyncExecutionService::submit_block` returns queue admission, not execution completion. The worker consumes results for counters/metrics; no caller entitlement to a durable acknowledgment instead of receipts is established. | Retaining a minimal success/identity acknowledgment may be cheaper than retaining every receipt if that is what the caller is entitled to receive. | Exact completion schema and caller entitlement remain **OPEN**. Do not discard receipts, gas, fee, or other result fields until owners establish they are not required. A synthetic acknowledgment proves only its fixture policy. |
| Atomic visibility | The account implementation uses individual DB operations; flush follows them. The consensus interface is separate. | A selected backend may offer transaction, batch, or coordinator mechanisms with specified scope. | No cross-database atomic visibility or resolution contract is established. A batch, subsequent flush, or matching balances is not proof. |
| Durability | Account state code calls RocksDB `put` and `flush`; consensus has explicit synced paths for selected metadata. Those paths are not a joint account-plus-position operation. | RocksDB options can configure write behavior; specific native behavior depends on selected API/configuration and environment. | This experiment used default write options, did not request sync, and did not test power loss. Flush semantics, WAL configuration, filesystem guarantees and error/unknown-commit resolution remain unproven for the candidate. |
| Access/fencing | `PersistentVmV0State` uses process-local synchronization and an atomic worker-claim flag for its documented in-process routes. | A separately selected OS/backend lock or fencing token may protect an agreed scope. | These do not fence other processes, retained handles, aliases, uncooperative writers, maintenance tools, or stale owners. All public reads/writes/flushes, worker claims, restart and other writers must be gated and fenced by a separately specified mechanism. |

The source also keeps distinct: Stage B account materialization and export,
transaction setter calls, adapter publication, and durable backend effects.
This fixture does not test those routes or establish membership correctness.

## Contract and identity boundary

The candidate commit unit is still required to bind all of the following:

1. Finalized account values **and membership**.
2. Authenticated authoritative execution position and predecessor.
3. Stable operation identity.
4. The minimum caller-required completion data.

The semantic identity must bind deployment and backend/state association,
chain/epoch/height/round, full parent and prior position, the stable decision
subject, the exact ordered transaction bytes actually executed, ruleset and
transition/schema interpretation, and durable completion. Height plus payload
hash or the current truncated block-ID derivation is insufficient. All six
operation-identity bindings and proof-equivalence/currentness policy remain
OPEN as recorded in the protocol.

The canonical signed proposal body contains the embedded QC bytes and ordered
transactions. An external proof is not thereby authenticated by that
signature. The identity must not change solely because a policy-authorized
equivalent proof uses different non-canonical bytes. The equivalence,
re-verification and currentness policy is unselected; no production route is
claimed to accept alternative finality proofs. The fixture models two
different synthetic proof representations as equivalent for one synthetic
subject and refuses invalid, unauthorized, wrong-subject, non-equivalent,
stale, or unavailable cases. This does not establish a real proof policy.

Native post-quantum protection of identity and commit records is a fixed
project requirement. Actual constructions, parameters, roots and demonstrated
end-to-end properties remain OPEN. No classical mechanism, hash, database
feature, or synthetic test in this experiment is counted as satisfying that
requirement.

## Failure model and observed fixture results

The fixture intentionally uses only these cases:

| Case | Required handling / fixture observation | Limit |
|---|---|---|
| Before preparation | Do not execute. If authoritative context, identity, fencing, or the pre-effect marker cannot be authenticated and durably established, refuse and remain gated. | Preparation is not implemented or tested here. |
| Pre-effect marker window | Effects must not begin until the prepared marker is confirmed under the approved contract. A crash after an effect but before a confirmed marker is unresolved; quarantine and refuse ordinary access. | No real effects or marker were exercised. |
| Calculation or injected pre-publication failure | The one-DB fixture withholds the batch before `DB::write`; reopen finds none of its keys. Production must preserve the error and prove no publication escaped before classifying a definite failure. | Injection is in the test wrapper, not a RocksDB write failure. |
| Normal success | A single `WriteBatch` stores synthetic account value, membership, position, operation ID and completion; closing/reopening the DB finds all keys. | Normal process close/reopen only. Default write options; no power-loss/durability claim. |
| Separate-store boundary | One synthetic DB write succeeds; an injected failure before the second DB write leaves first-store state without second-store metadata. | A control showing sequential calls can be partial; not a claim that every possible coordinator is impossible. |
| During commit or commit error | Treat as unknown unless the selected primitive and authenticated recovery inspection establish the exact outcome. Do not retry execution or report success from a later flush/balance match. | No backend commit error, mid-commit fault or crash was injected. |
| Lost response | The fixture writes the batch, suppresses the modeled caller response, and classifies caller outcome as unknown; reopen finds the completion. | This is an in-process model, not an actual dropped response or commit-error injection. Reopen data does not resolve what a real caller could safely conclude without the approved contract. |
| Durable commit before cache update/response | Keep caller outcome unknown until the same operation's durable identity and required retained completion are authenticated and retrieved. Do not publish a cache/height/ack as proof of commit. | The fixture does not test cache, worker, caller or durability behavior. |
| Restart inspection | Missing, malformed, conflicting, stale, unauthenticated or unavailable position/history/currentness evidence must refuse ordinary access and keep the result unavailable. No missing record may imply an empty valid history. | No restart or recovery inspection route was tested. |
| Controlled process crash/reopen | **Not run.** | The isolated harness did not include a controlled crash/recovery supervisor. A killed process would not simulate power loss. |
| Power loss / arbitrary filesystem failure | **Not run.** | Requires separate backend-, filesystem-, and hardware-specific evidence. |

### Acknowledgment retention versus reconstruction

**A — atomically retain completion (primary candidate).** Retain the smallest
caller-required result with the state, membership, position and identity.
If the owner confirms the caller needs only a durable success/identity
acknowledgment, a compact value could suffice; if callers are entitled to
ordered transaction receipts, gas/fee fields, or other data, those must also
be retained. A lost commit response remains unknown until an authenticated
lookup resolves the same operation and retrieves its original completion.
The owner has not established which response contract applies.

**B — reconstruct completion (unselected).** Requires authenticated and
sufficiently complete durable inputs/history, the applicable versioned
ruleset, adequate prior state, and evidence that deterministic reconstruction
returns exactly the caller-required result. Availability of persistent block
storage does not establish complete authenticated replay history for this
route. Snapshots do not independently establish currentness, authority or
safe recovery. If any input or result cannot be established, outcome remains
unknown/unavailable; do not blindly re-execute.

## Candidate sequencing and implementation-entry decision

1. **Owner contract decisions first:** define caller-required completion;
   authoritative finality/history and six identity bindings; equivalence and
   currentness policy; exact membership semantics; transaction/failure
   outcome; and unknown-commit handling. Preserve native post-quantum trust as
   fixed. Keep association-verification authority separate from validator
   signing and bundle-signing authority.
2. **Resolve a supported consistency boundary:** identify the actual selected
   backend primitive or a reviewed redesign that atomically binds all four
   required data classes and resolves unknown outcomes. A same-database
   control is not enough while account and position remain in separate
   databases. Existing consensus epoch batches and sync signing-record
   batches are not evidence of this cross-store guarantee.
3. **Only after separate approval, build an isolated storage contract:** typed
   prepare/commit/unknown results and read-only recovery inspection over
   versioned identity, state, membership and retained completion. Keep all
   ordinary access gated on incomplete/conflicting/unavailable evidence.
4. **Then integrate execution and response:** propagate worker write/flush
   errors to a work-correlated result, retain caller-required completion, and
   publish cache/height/ack only after contractually established commit.
   `submit_block` currently reports enqueue only; changing that API alone
   would not create atomicity.
5. **Finally establish fencing, crash recovery and authority:** gate every
   shared-state path and stale owner; define authenticated pre-effect
   preparation and restricted inspection; identify who can authorize
   enrollment, quarantine, replacement, abort/roll-forward and return to
   service. The authority and evidence remain OPEN; no recovery procedure is
   selected here.

**Implementation entry: BLOCKED.** The experiment supports only the
single-database capability control and synthetic policies. The real QBIND
account and position stores are separate and have no inspected joint API.
Caller-required completion, operation identity, proof policy, fencing,
currentness, independent authority and recovery remain unresolved. Do not
wire this candidate or describe it as safe based on five passing tests.

**Recommendation:** retain the owner-selected atomic-with-retained-completion
direction as the primary candidate, but first decide whether the caller needs
only a durable operation acknowledgment or the ordered execution results,
including receipts/gas/fees. Retaining full results increases atomic storage
and write cost but avoids depending on complete replay history; a minimal
ack is smaller but cannot satisfy an unverified richer caller contract.
Deterministic reconstruction remains unselected and has a higher dependence
on complete authenticated history and versioned deterministic execution.
After a separate backend/consistency approval, the smallest viable
implementation slice is an isolated commit API and recovery lookup that
atomically stores account values/membership, authoritative position,
operation identity and the owner-approved completion, and reports
committed/refused/unknown without integrating workers or startup. It is
blocked until the chosen primitive supports the real QBIND consistency
boundary.

## Future verification plan — FUTURE / NOT EXECUTED

These are not results of this experiment:

- Positive and negative tests of every state, membership, position,
  identity, completion and versioned schema element in the **selected**
  atomic primitive, with same-checker bypass sensitivity.
- Backend-native failure injection at preparation, during publication,
  after durable commit but before response, and on restart inspection;
  verify every ambiguous outcome stays unknown/unavailable and prevents
  re-execution and ordinary access.
- A controlled process-crash/reopen test if supported; separately test
  power-loss assumptions with evidence appropriate to the selected backend,
  filesystem and hardware. Do not generalize process death to power loss.
- Cross-store atomicity/partial-state controls for the actual QBIND
  boundaries, or demonstrate that a separately approved redesign removes
  those boundaries.
- Fault tests for lost responses and retrieval of the same retained
  completion; exact caller-entitlement assertions for success, execution
  refusal, definite storage failure, unknown commit and unavailable history.
- Adversarial proof tests for invalid, malformed, unauthorized, wrong
  subject, non-equivalent, stale, conflicting and unavailable evidence;
  valid authorized equivalence controls; and same-checker bypass controls for
  identity binding, proof policy and required currentness.
- Deployment/backend substitution, cross-deployment replay, stale/replayed
  transition, partial replacement, unavailable provenance and
  self-authorization refusal controls.
- Access/fencing tests for public reads, writes, flushes, workers, restart,
  multiple processes, retained handles, stale owners, aliases and
  maintenance/recovery routes.
- Independently authenticated provisioning, storage, runtime and operational
  evidence for selected roots, currentness, history, authority and recovery.
  Synthetic tests cannot establish any of these.

A23-F1 and A33-F1 / E27 remain OPEN; activation remains DISABLED; public
DevNet remains NO-GO. Required-persistence remains NOT ACCEPTED /
NOT INTEGRATION-READY. DER-1-TM-2 remains closed in its documentation scope;
DER-2 and DER-3 remain passed in their documentation scopes. The arithmetic
baseline remains red. No earlier scoped finding is broadened or replaced.

## Executed command and complete output

Command:

```text
CARGO_INCREMENTAL=0 cargo test -p qbind-ledger --test atomic_block_retained_completion_capability --locked --offline -- --nocapture
```

Exit code: `0`.

```text
Compiling qbind-ledger v0.1.0 (/workspaces/QBIND/olivexo28/QBIND/crates/qbind-ledger)
    Finished `test` profile [unoptimized] target(s) in 0.47s
     Running tests/atomic_block_retained_completion_capability.rs (target/debug/deps/atomic_block_retained_completion_capability-1ae137c09b342d53)

running 5 tests
test injected_failure_before_one_database_batch_publication_leaves_no_candidate_keys ... ok
test a_lost_response_after_write_is_unknown_even_when_reopen_finds_commit ... ok
test one_database_batch_retains_candidate_and_minimal_completion_after_reopen ... ok
test synthetic_equivalent_evidence_retrieves_same_completion_and_other_cases_refuse ... ok
test separate_database_calls_can_leave_partial_state_at_injected_boundary ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s
```

The five tests are limited to this fixture. They do not close any candidate
blocker or establish implementation readiness.
