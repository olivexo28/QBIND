# Gas-disabled arithmetic: compatibility and transition assessment

**Documentation-only assessment; no transition or production policy approved.**
Recipient overflow remains OPEN. The required-persistence candidate remains
NOT ACCEPTED / NOT INTEGRATION-READY.

## Verified basis and evidence limits

Before work, remote `docs/gas-disabled-arithmetic-refusal-contract` matched
`b6fcee7c0a7e1701a57136a130688c17d64990a5`, tree
`e2b4f4c649b62160a084a739c92cc12effbc0521`; remote main matched
`aa382fa28b2d3e97e6203d47fa8231b5f2269741`. Local HEAD/tree matched the
reviewed endpoint and the worktree was clean.

**All file/line citations below are pinned to b6fcee7c0a7e1701a57136a130688c17d64990a5.**
Reviewed documents are
`docs/security/evidence/gas-disabled-arithmetic-refusal-contract-proposal-20261109.md`
and `docs/security/evidence/gas-disabled-recipient-overflow-characterization-20261109.md`.
Their proposals and retained author-run limitations are preserved. No new
tests, deployment observations, or history validation were performed.

## 1. Why this is a semantic change

The default engine disables gas (`crates/qbind-ledger/src/execution.rs:2103-2109`).
After malformed-payload, nonce and insufficient-balance checks, the disabled
path increments sender nonce, subtracts sender balance, writes sender, then
reads and adds to recipient balance and writes recipient (`:2147-2198`).
The nonce increment and recipient addition are ordinary arithmetic, not
explicit checked refusals.

The recorded fixture starts sender `(nonce=4,balance=100)`, recipient
`(9,u128::MAX)`, and transfers 1 with matching nonce. The recorded debug build
panics after sender becomes `(5,99)` and leaves recipient unchanged. The
recorded release build returns success with sender `(5,99)` and recipient
`(9,0)`. These are measured results for two builds, not a universal mapping
from profile name to behavior.

The proposed refusal instead returns transaction failure and leaves both
accounts at their input values, with zero updater calls. Thus, for the same
input, it changes termination/result, sender state, and in the wrapping case
recipient state. Later nonce checks, balances and transaction results may
therefore also differ. This is not merely replacing an exception message:
replicas or replay tools using different semantics can diverge.

Source proves the arithmetic and adapter calls; tests prove only synthetic
in-memory outcomes in those builds. Neither establishes that the offending
input was historically committed, reached an ordinary P2P node, or affected
an operating network. These possibilities require separate evidence.

## 2. Bounded caller and selection inventory

| Inspected surface | Pinned evidence and relevance | Limit |
|---|---|---|
| Public ledger engine | `execution.rs:2098-2198` exposes `new`, `with_gas_config`, and `execute_tx`; `:2508-2522` executes sequential blocks. `crates/qbind-ledger/src/lib.rs:52` re-exports the engine. | Public downstream callers are not inventoried. A source change affects direct default-engine users without a separate selector. |
| Adapter VM-v0 worker | `crates/qbind-node/src/execution_adapter.rs:1213` creates the default engine; `:1320-1360` chooses Stage B when enabled and transaction count exceeds one, otherwise calls the sequential engine. | This establishes a library worker route, not ordinary P2P startup wiring. |
| Separate Stage B arithmetic | `crates/qbind-ledger/src/parallel_exec.rs:475-523` manually implements transfer validation, sender update and recipient addition; `:567` exposes `execute_block_stage_b`. Adapter copies its snapshot results back through updater calls (`execution_adapter.rs:149-157,1320-1360`). | It is not a call to `VmV0ExecutionEngine::execute_tx`. Updating only that engine does not establish a consistent ruleset across scheduling modes/block sizes. No Stage B overflow test was run here. |
| Test-only parallel baseline | `parallel_exec.rs:651-663,885-895` places a sequential default-engine baseline in `#[cfg(test)] test_executor`; later unit tests compare Stage B and sequential execution (`:1409-1432`). | Test baseline coverage is not production route coverage or proof that boundary cases agree. |
| Execution profile selection | `crates/qbind-node/src/node_config.rs:3295-3317` distinguishes `NonceOnly` and `VmV0`; adapter config exposes `execution_profile` and `stage_b_enabled` (`execution_adapter.rs:716-740,803-830`). | Profile/scheduler switches are not legacy-versus-corrected arithmetic versions. |
| Direct integration tests | Located default-engine calls include ledger `tests/t163_vm_v0_tests.rs:143`, `t177_vm_v0_proptests.rs:103`, `t171_parallel_executor_integration_tests.rs:45`, node `tests/t163_vm_v0_integration_tests.rs:289`, `t164_vm_v0_persistence_integration_tests.rs:104`, `t177_vm_v0_pipeline_proptests.rs:131`, and the retained overflow characterization. | Locations identify callers, not a claim that all their assertions or feature combinations were audited. No tests were rerun. |
| Gas-selected test callers | Examples include ledger `tests/t168_vm_gas_tests.rs:123,266`, `t193_hybrid_fee_distribution_tests.rs:63,512`, node `tests/m18_gas_accounting_tests.rs:84,677` and `t179_gas_pipeline_proptests.rs:174`. | Gas-enabled callers are a different route; some files also instantiate the disabled default. |

Within the inspected engine, Stage B, gas configuration, adapter and
`node_config.rs`, no execution ruleset/version or arithmetic activation-height
selector was found. The engine selects gas behavior through `gas_config.enabled`
(`execution.rs:2153-2154`); this is not authenticated historical arithmetic
versioning. Unrelated protocol-version or trust activation fields elsewhere
must not be treated as such a mechanism without a traced binding to execution.

This is a bounded checkout inventory, not proof of absence across the entire
repository or downstream code. It does not enumerate every wrapper, example,
generated caller or feature combination. The ledger manifest's `test-helpers`
feature exposes bundle-signing test helpers (`crates/qbind-ledger/Cargo.toml:6-11`),
not a gas-disabled arithmetic ruleset. No feature matrix or dependency graph
was compiled here. Public trait/result consumers and all claimed execution
routes need a fresh implementation-entry inventory.

## 3. Transition scenarios: alternatives, not selected policy

| Scenario | Evidence required before applicability or safety can be claimed | Compatibility consequence |
|---|---|---|
| Pre-activation transition | Independently establish deployment inventory, no relevant active replicated history or obligations, authoritative initial state/history policy, and agreement on the intended engine/settings for every participant. The continuing NO-GO status alone does not prove these facts. | A coordinated initial ruleset may avoid an old-history boundary only if those conditions are actually established. Previously executed fixtures, snapshots or private deployments cannot silently be treated as disposable. |
| Versioned activation on an existing replicated network | Owner-approved rule identity and boundary; authenticated canonical history/position; deterministic selection at and around the boundary for all execution routes; participant compatibility and unsupported-version behavior; snapshot/restart binding and validated upgrade procedure. | Old and corrected semantics can disagree for identical inputs. A rolling upgrade is unsafe by assumption unless both implementations select identical historical rules and enforce the approved boundary. Neither a local flag nor a database migration establishes replicated agreement. |
| Historical replay | Authoritative transactions, order, initial state and snapshots; original rule identity, build artifact/settings or a proven equivalent semantics; expected state/results and evidence of any interrupted execution. | Replaying old blocks with corrected semantics may produce a different state. Rebuilding from genesis is not automatically safe: genesis authority, complete history and correct historical semantics are prerequisites, not consequences of replay. |

If original overflow behavior or authoritative inputs are unavailable, record
the replay result as unresolved, not canonical. A debug panic does not itself
define a committed post-panic state; a release wrap observed in a fixture does
not prove historical release settings. Guessing from a profile label, selecting
the new rules retroactively, accepting an arbitrary snapshot or replaying only
the available suffix cannot repair missing authority/history. Whether any
reconstruction, migration or history reset is allowed requires separate owner
approval and evidence; none is chosen here.

## 4. Owner decisions before implementation

**Error and precedence.** The existing
`VmV0Error::ArithmeticOverflow { operation: &'static str }`
(`execution.rs:1866-1876`) is a reuse candidate, not an approved exact public
representation or message. Owners must decide classification and consumers'
compatibility, including arithmetic-error precedence when nonce and recipient
both overflow. Preserve malformed payload, then nonce mismatch, then
insufficient balance before arithmetic refusal as proposed, or explicitly
approve a deviation. Moving a check can change the returned error for inputs
with multiple defects. Result counters and receipt consumers must not silently
treat a newly classified failure as the old success.

**Self-transfer publication.** Existing aliasing reads the same account after
the debit, so final success is `(n+1,B)` when `B >= amount` and the nonce can
increment. Checking `original B + amount` would falsely refuse
`B=u128::MAX, amount=1`; correct precomputation must model debit then restoration
or an equivalent representable final state. One final write changes the
existing two-call sequence, observable intermediate state and failure points.
Two precomputed writes preserve that shape but retain partial-write windows.
The owner must approve write shape; no choice is made here.

**Zero amounts and absent recipients.** Today zero amount still increments the
sender nonce and calls both updates. `InMemoryAccountState` inserts an entry
even for a default account (`execution.rs:1194-1197`); an absent recipient can
be materialized at zero. Omitting that write can change observable account
membership, backend I/O or test instrumentation even when balances compare
equal. Approve preserving or changing those semantics explicitly.

**Coherent reads and side effects.** Prevalidation captures account values
earlier than today's post-sender recipient read. It requires a coherent view
and alias handling, not unrelated reads assumed to be a snapshot. The public
`AccountStateView`/`AccountStateUpdater` interfaces (`execution.rs:1130-1140`)
do not themselves guarantee isolation, pure reads, infallible persistence or
absence of write side effects. Decide permitted updater/read observations,
including account materialization, notifications and cache effects. A zero-call
arithmetic-refusal guarantee must test attempted writes, not just final values.

**Scope and activation.** Approve which routes comprise the ruleset, including
the distinct Stage B implementation and its sequential comparisons. Approve
transition applicability, historical selection and unsupported-version behavior
before choosing implementation scope. No production ruleset, activation height,
deployment policy or recovery authority is selected by this assessment.

The zero-updater-call proposal is transaction-local at the engine interface.
Stage B snapshots touched accounts and publishes final snapshot entries through
`apply_state_changes`, even when a transaction result is a refusal. Extending
the same call-count guarantee to the service boundary therefore requires an
explicit scope and publication decision; unchanged final values alone do not
prove that stronger guarantee.

## 5. Future verification once a transition is approved

**Every row is FUTURE / NOT EXECUTED.** Exact identities and boundaries below
must come from the approved transition, not this document.

| FUTURE / NOT EXECUTED control | Inputs and proposed oracle |
|---|---|
| Build independence | Run debug/release and explicit overflow-checks on/off; record actual engine/test compiler flags, panic strategy and runtime arithmetic probe. Corrected rules must return the same approved refusal/state under each setting; use isolated processes for abort builds. |
| Boundary arithmetic | Matching sender nonce `u64::MAX`, or distinct recipient balance `u128::MAX` with positive amount: approved arithmetic refusal, unchanged accounts, zero updater calls. Verify representable `MAX-1 + 1`, maximal funded transfer, zero amount and ordinary valid transfers. |
| Precedence | Malformed payload plus other faults; nonce mismatch plus insufficient balance/recipient overflow; insufficient balance plus nonce overflow; both arithmetic overflows. Assert the approved exact error classification/order and zero mutations. |
| Self-transfer | Ordinary, zero, insufficient funding, nonce maximum and maximum-balance self-transfers; verify debit/restoration semantics, one nonce increment, and approved one/two-call publication shape. |
| Materialization and reads | Start recipient absent versus explicitly present at zero. Record reads, update count/order, account membership and values; check approved zero-amount behavior and coherent captured state under controlled interference. |
| Same-oracle mutation sensitivity | Against the unchanged conformance oracle, test-only write-before-refusal and write-then-restore mutants must fail zero-call assertions; unchecked arithmetic mutants must fail on panic/wrap; original-balance self-credit mutant must fail valid maximum self-transfer. |
| Route consistency | Compare direct engine, sequential service, Stage B and its public boundary with one- and multi-transaction blocks under the approved ruleset; detect scheduler/block-size-dependent outcomes. |
| Mixed versions / boundary | Execute authoritative fixtures immediately before, at and after the approved boundary using each supported version. Assert identical selected historical rules/results, explicit unsupported-version handling and no accidental early/late activation. Include a deliberately wrong boundary/version mapping that the same oracle rejects. |
| Replay and snapshots | Replay authoritative complete history with pinned original and corrected rule identities/settings. Verify approved state/results, snapshot rule binding and restart boundary selection; missing build/settings/history or conflicting snapshots must remain unresolved/refused per approved policy. |
| Evidence separation | Retain injected/synthetic controls separately from isolated process-crash experiments and real deployment/history evidence. Neither local replay nor unit success proves network-wide upgrade safety. |

The prior characterization's passing panic/wrap assertions document the old
recorded builds. Future refusal conformance must not reuse those adaptive
expectations to declare a wrapped success acceptable, or silently edit the
historical logs. A failed assertion, panic, abort, timeout, missing output,
compile error and infrastructure failure are distinct outcomes.

## 6. Separate unresolved mechanisms and delivery scope

Arithmetic prevalidation can avoid updater calls for arithmetic refusal; it
cannot turn the void updater into fallible storage, roll back later failures,
make account or block publication durably atomic, quarantine an uncertain
backend across restart, establish snapshot/history authority or authorize
recovery. Join completion alone does not establish safe state reuse.
The reviewed worker decision brief
`docs/security/evidence/worker-write-failure-backend-reuse-decision-brief-20261109.md`
retains those separate decisions. Gas-aware M18 checks
(`execution.rs:2260-2477`) and ATOM-1 requirements
(`docs/whitepaper/QBIND_WHITEPAPER.md:2052-2061`) retain their accepted scopes;
none automatically covers gas-disabled arithmetic or durable storage.

Only this assessment is added relative to the reviewed endpoint:
`docs/security/evidence/gas-disabled-arithmetic-compatibility-transition-assessment-20261109.md`.
The full branch relative to main is the inherited 29-path package (the 28-path
inventory in the retained characterization plus the arithmetic contract
proposal), plus this document: **30 paths**, including inherited unaccepted
production work. The new slice must not be presented as a clean production
candidate based directly on main.

No code, tests, manifests, lockfiles or historical evidence changed. No tests,
node, operational keys, PR, merge or deployment were run. Recipient overflow
remains OPEN; candidate remains NOT ACCEPTED / NOT INTEGRATION-READY. A23-F1
and A33-F1 / E27 remain OPEN; activation remains DISABLED; public DevNet remains
NO-GO.
