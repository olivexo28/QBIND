# RUN 422 — Native governance authority characterization and draft contract

**DRAFT / NOT APPROVED / NOT IMPLEMENTED**

This is source-backed test-and-contract evidence for the
`qbind_wire::tx::Transaction` native system-program route only. It does not
implement or enable governance, approve policy, integrate the isolated native
admission/staging models, or establish production authorization.

The whole native admission contract remains **DRAFT / NOT APPROVED / NOT
IMPLEMENTED**. All limits remain **UNAPPROVED**. D7D14 storage remains
`IMPLEMENTED-ISOLATED` / `PASS-ACCEPTED-SUBSET`; §13.6 whole-lifecycle remains
**INCOMPLETE**; activation **DISABLED**; public DevNet **NO-GO**; durable
anti-rollback **NOT-ESTABLISHED**; C4/C5 and RS1 **OPEN**. No F1/F2 closure,
C4/C5 closure, production authorization, deployed-path readiness, or release
approval is established.

## Evidence boundary and levels

The required clean start was commit
`af5f739076263ce9b46406650d019a91243de851`, tree
`a0e0023779ebd325768233e6fb1365dd7fa16739`. Both objects were available after
fetching the advertised `origin/main`; exact `HEAD^{tree}` correspondence was
checked separately. Raw starting commit header names parent
`2903b50f8aaeb857349da76d1e968d0bc5585435`, whose object was available. The
repository is shallow at `2903b50f8aaeb857349da76d1e968d0bc5585435`; that is
the recorded shallow boundary, not a claim about older history. The start is
an ancestor of this test source commit. The task branch is
`copilot/run-422-native-governance-authority-contract`.

Evidence labels used here:

| Level | Evidence | What it establishes |
|---|---|---|
| Source inspection | Runtime, ledger, system handlers, wire codecs, state types, node call sites and adjacent mechanisms cited below | The implemented control/data flow and explicit absence of calls/inputs in inspected code; not deployed reachability. |
| Newly executed source/test characterization | New `qbind-runtime` integration target invokes real `TxExecutor::execute_transaction`, genuine ML-DSA-44 signing/verification, existing `GovernanceProgram` handlers and an instrumented test-local `AccountStore` | These exact in-process executor results, read/write boundaries, errors, state changes and replay behavior. |
| Historical evidence | Existing Run 422 native admission contract, D7 evidence, contradiction record and protocol governance audits | Prior independently scoped evidence and preserved posture only; it is not rerun or reattributed to this task. |
| Not established | No release-binary harness, selected production executable invocation, network test, or public-network interaction was performed | No deployed exposure, deployment state, exploit, consensus safety violation or production readiness. |

`TxExecutor` is a public library type registered with `GovernanceProgram`.
`qbind-node::Node::apply_block` also contains a source path through wire
`Transaction` decoding and `BlockExecutor`; its current in-repository callers
are block-apply tests, not the node executable. The inspected `main.rs` and
network simulation paths do not call this legacy `TxExecutor` route.
`hotstuff_node_sim`'s execution-adapter path uses the separate EVM
`QbindBlock`/`ExecutionEngine` route, not `qbind_wire::tx::Transaction`.
Thus this run proves the actual executor/handler library route, not selection
by a deployed executable or network ingress. Existing direct
`GovernanceProgram::execute` system tests are handler-only and do not establish
executor authentication; the new tests are distinct and exercise the real
`TxExecutor`.

This evidence does not import behavior from ledger `QbindTransaction`/VM,
runtime `QbindTx`/EVM, consensus Proposal/Vote authority, upgrade envelopes, or
node trust-bundle governance. `qbind-runtime` does not depend on `qbind-gov`.
`qbind-gov::verify_envelope` verifies a separate signed protocol-upgrade
envelope; no native executor/handler call consumes its outcome. Node
`GovernanceProofPolicy`/`OnChainGovernanceProofPolicy` and associated proof
types govern separate trust-bundle lifecycle surfaces; their default-disabled
or fixture-only outcomes are not passed to `GovernanceProgram`. The existing
`QBinding Governance Execution Runtime Surface Audit` likewise records a
separate trust-bundle governance lifecycle and says no real governance
execution engine is implemented. No adjacent mechanism is assumed to authorize
the native calls characterized here.

## Current source behavior

The native route is:

```text
TxExecutor::execute_transaction
  -> ExecutionContext::verify_tx_auth
  -> verify_transaction_auth / verify_single_auth
  -> registered GovernanceProgram::execute
  -> opcode-selected handler
  -> AccountStore::put(target)
```

Source anchors:

| Source | Relevant behavior |
|---|---|
| `crates/qbind-runtime/src/lib.rs:120-160` | `TxExecutor::new` registers `GOVERNANCE_PROGRAM_ID`; `execute_transaction` constructs `ExecutionContext`, verifies auth, resolves program ID, then calls `Program::execute`. |
| `crates/qbind-ledger/src/context.rs:7-51` | Context contains mutable store, crypto provider and validator-minimum-stake field; auth delegates to `verify_transaction_auth`. It has no trusted block height, proposal decision, governance authority, or replay consumer input. |
| `crates/qbind-ledger/src/auth.rs:29-83,86-144` | Empty auth refuses before digest/store/provider work. Otherwise auth indices must point at account metas with signer bit 0 set, and every signer-marked index must be covered. Each auth resolves that declared meta's account ID, reads/decodes a `KeysetAccount`, selects the first entry matching suite ID, and verifies the transaction signing-body digest. This authenticates transaction-declared signer keysets; it does not bind a signer to a council or operation, enforce keyset ownership/threshold weights, or establish program authority. |
| `crates/qbind-system/src/governance_program.rs:20-34,59-88` | Fixed program/target/council IDs; program checks program ID and nonempty call data, then dispatches one of four opcodes. Council constants are declared but not consulted by this dispatcher. |
| `crates/qbind-wire/src/gov.rs:9-286` | Every native call encodes and decodes `proposal_id` and `eta_height`. |
| `crates/qbind-system/src/governance_program.rs:92-290` | The four selected handlers parse their own call, read their fixed target, validate target state framing, update state and call `put`; none reads council/proposal/replay state or obtains trusted execution height. |
| `crates/qbind-hash/src/tx.rs:13-54` | The transaction digest covers the complete canonical signing body including `call_data`; authentication entries are excluded. Changing proposal/ETA call bytes therefore invalidates an old signature, even though handlers do not enforce those fields. |

Operation inventory:

| Operation / selected handler | Authenticated signer and target | Reads, checks and first mutation | `proposal_id` / `eta_height`; authority and replay consulted |
|---|---|---|---|
| `OP_GOV_UPDATE_SUITE_STATUS` (`0x20`), `handle_update_suite_status` | Auth verifier reads the signer keyset resolved from each `TxAuth.account_index` and caller-supplied signer meta. Handler target is fixed `SUITE_REGISTRY_ACCOUNT_ID`; it need not select a council signer. | Decode complete `GovUpdateSuiteStatusCall`; reject trailing call bytes; `get` SuiteRegistry; decode state and reject trailing state bytes; map status 0/1/2 or refuse `InvalidCallData("invalid SuiteStatus")`; find suite or refuse `"suite_id not found in SuiteRegistry"`; first mutation is `put` of account with only encoded registry data changed. | Decoded into a local call but not used to admit or mutate. No proposal approval, council membership, trusted height, timelock or consumed-decision state read. |
| `OP_GOV_UPDATE_PARAM_REGISTRY` (`0x21`), `handle_update_param_registry` | Same declared signer verification; fixed target `PARAM_REGISTRY_ACCOUNT_ID`. | Decode; reject trailing call bytes; get/decode ParamRegistry and reject trailing state; overwrite `slash_bps_prevote`, `slash_bps_precommit`, `reporter_reward_bps`; first mutation is `put`. No range/authority check is added by this handler. | Decoded but not used. No proposal, council, height, timelock or replay read. |
| `OP_GOV_UPDATE_LAUNCH_CHECKLIST` (`0x22`), `handle_update_launch_checklist` | Same declared signer verification; fixed target `LAUNCH_CHECKLIST_ACCOUNT_ID`. | Decode; reject trailing call bytes; get/decode LaunchChecklist and reject trailing state; overwrite seven booleans and seven report hashes; first mutation is `put`. | Decoded but not used. No proposal, council, height, timelock or replay read. |
| `OP_GOV_SET_MAINNET_STATUS` (`0x23`), `handle_set_mainnet_status` | Same declared signer verification; fixed target `PARAM_REGISTRY_ACCOUNT_ID`. | Decode status as PreGenesis/Ready/Activated (invalid status maps to `InvalidCallData("invalid GovSetMainnetStatusCall")`); reject trailing call bytes; get/decode ParamRegistry and reject trailing state; overwrite `mainnet_status`; first mutation is `put`. | Decoded but not used. No proposal, council, height, timelock or replay read. A local field change is not launch approval or node/network activation. |

All handlers preserve account headers by mutating the local account's `data`
then storing it, but no common atomic decision-consumption/mutation boundary
exists. `AccountStore::put` is the first external mutation for each handler;
prior parse, target-read and target-state errors occur before that `put`.
Executor authentication reads declared signer keysets before program dispatch.
The verifier's required signer flags are caller-declared and do not themselves
authorize governance operations. `tx.payer` and `tx.nonce` are signed fields,
not checked or consumed by this route.

The fixed `SAFETY_COUNCIL_KEYSET_ACCOUNT_ID` is only an identifier. A constant
does not authenticate its keyset, establish an independently admitted source,
or make the native program consult it.

## Newly executed characterization

`crates/qbind-runtime/tests/run_422_native_governance_authority_contract_tests.rs`
uses the real `TxExecutor<WitnessStore>` and real registered `GovernanceProgram`.
Its authorizing account is an existing, correctly encoded one-entry,
threshold-one keyset with `KEYSET_PROGRAM_ID` owner and ordinary non-council ID.
Genuine generated ML-DSA-44 keys/signatures are verified by
`MlDsa44SignatureSuite`; a thin counter delegates to that suite and does not
fabricate success. The test-local witness records each `get`, `put`, and
`delete`; observations are reset after fixture seeding. Complete map comparison
uses the witness map directly, excluding preservation-oracle reads. The
transaction includes the ordinary signer, target, unrelated sentinel, and
well-formed council keyset/member accounts; no governance decision or approval
capability is supplied.

The test demonstrates for each of the four operations:

* One genuine transaction signature over its actual complete signing body
  passes. The exact target account changes as described above; every other
  account and the target's ID/header metadata remain equal to the full expected
  map. The complete transaction, including auth bytes, is unchanged.
* The executor's observed reads are exactly `[ordinary signer keyset, fixed
  operation target]`; one target `put`, no deletes. The seeded council keyset
  and seven member IDs are not read. No payer account is read.
* Removing auth returns exactly
  `InvalidCallData("transaction requires at least one authentication entry")`,
  performs no store read/write/delete and no signature verification. Restoring
  the genuine input succeeds. Tampering one signature byte returns exactly
  `CryptoError("signature verification failed")` after one real verification,
  with only the signer keyset read and no write/delete; restoring the genuine
  transaction succeeds.
* A genuinely re-signed truncated call reaches the selected handler and returns
  that handler's exact `InvalidCallData("invalid <call type>")`; it reads only
  the signer keyset and performs no mutation. A genuinely re-signed unknown
  opcode returns exactly `ProgramError("unsupported governance opcode")`.
  A genuinely signed invalid suite status reaches the suite handler, reads the
  signer and suite registry, returns exactly
  `InvalidCallData("invalid SuiteStatus")`, and performs no mutation.
* Altering either proposal-ID or ETA bytes without re-signing changes
  `tx_digest` and fails the genuine signature check before target access.
  Separately re-signed proposal-ID=`u64::MAX` and ETA=`0` variants of each
  operation are accepted and result in the same governed account state. The
  call has no trusted execution height input; ETA zero is reported as an
  accepted encoded value, not “premature at height H.” The handlers do not
  consult an approved proposal state.

For `OP_GOV_UPDATE_PARAM_REGISTRY`, the exact same complete signed transaction
is submitted twice through the executor. Both attempts return success, each
performs a fresh real signature verification, reads the same signer and target,
and issues one `put` with no delete. The complete state after the second write
equals the state after the first; this is a second accepted idempotent setter
write, not a second logical state transition, double spend, or value loss. No
nonce/proposal-consumption state is consulted or written by this route.

These are source/test results, not approved governance, a demonstrated deployed
exploit, or a consensus safety violation. No production code, existing test,
manifest, dependency, feature, wire/signing format, resource assessment,
critical-path plan, governance audit, executable, or network state was changed.

## Historical evidence and reusable mechanisms

The existing `docs/devnet/QBIND_RUN_422_NATIVE_ADMISSION_STATE_CONTRACT.md`
already states that `TxExecutor`'s legacy auth is separate from program,
payer, nonce, fee, replay and creation authority, and that native models remain
isolated. Its D7 evidence maps the native executor path and explicitly excludes
release/deployed-path claims. This run supplements that historical evidence
with actual native governance handler execution; its historical tests are not
reclassified as tests of this new target.

The source contains separate governance-adjacent mechanisms:

* `qbind-gov` verifies an off-chain protocol-upgrade envelope against its own
  council keyset and CLI inputs. It is not a native system program and its
  verification result has no caller edge into `TxExecutor` or
  `GovernanceProgram`.
* Node trust-bundle governance proof/evaluator/policy types concern validator
  trust/lifecycle changes. `OnChainGovernanceProofPolicy::Disabled` is its
  default, and source/test fixture acceptance is separate from native
  `GovernanceProgram` dispatch. No such decision or replay set is passed to the
  native handler.
* Consensus Proposal/Vote proof and signing-state contracts concern consensus
  authorization, not authorization of these native governance transactions.

These mechanisms may inform a later design only after their provenance,
scope and failure semantics are independently admitted. An upgrade envelope,
historical verification result, fixture Boolean or generic “authorized” token
must not silently become native governance permission.

## Recommended future requirements and unresolved decisions

Before the first governed mutation, a future approved boundary must bind and
atomically enforce all of the following. These are requirements for review, not
implemented behavior or selected cryptographic construction:

1. **Independent authority provenance:** authenticated authority state/evidence
   admitted independently of the caller-declared signer bit and auth keyset.
   The fixed Safety Council account ID alone is insufficient.
2. **Network and execution position:** exact network/chain plus authenticated
   execution position and common pre-state; transaction labels alone are not a
   trusted clock or freshness proof.
3. **Exact decision correspondence:** operation, target account, complete
   parameters, proposal ID, approved decision/outcome and decision digest bind
   to this exact execution request.
4. **Current authority interpretation:** current membership, allowed signature
   suites/provider semantics, key identity/alias rules and approved threshold;
   duplicate identities and threshold semantics require explicit owner
   decisions.
5. **Timelock:** trusted height source and any approved delay; do not infer a
   delay from the signed `eta_height` input itself.
6. **Replay/one-use:** decision-consumption key, ordering, idempotency and
   one-use rules are explicitly approved and enforced.
7. **Common-state atomicity:** evaluate authority, proposal, target and replay
   dependencies against one state version, then atomically publish decision
   consumption and governed effects together or publish neither.
8. **Fail closed:** missing, stale, unsupported or unavailable authority,
   membership, provider/backend, state version or required decision refuses
   before mutation; no fallback to caller-declared signer authorization.
9. **Disposition separation:** local capability/backend/resource inability
   remains distinct from deterministic transaction disposition. Do not invent
   receipt mappings for this contract.
10. **Lifecycle limits:** specify cancellation, publication uncertainty,
    restart, rollback, persistence and recovery semantics; a known return value
    or in-process replay set alone does not establish durable one-use behavior.

Still separate and unresolved are payer authorization; nonce namespace,
validation and consumption; fee calculation/charging and failure behavior;
keyset creation/creator rights; and validator-registration authority/stake
policy. This work resolves none by analogy.

## One bounded next enforcement proposal — production unavailable boundary

**Proposal only; unapproved and unimplemented.** The next bounded phase should
add a production **unavailable/refusal boundary**, not a positive authority
implementation or fixture bypass. The real gate is the common native
`GovernanceProgram::execute` dispatch immediately before the four handler
branches and therefore before every handler's first `AccountStore::put`.
Until independently admitted authority with exact network, execution-position,
operation, target, parameter, proposal/decision and current-membership/provider
binding is available, all four privileged operation branches must fail closed
before target mutation. Do not accept a generic Boolean/token, transaction
signer declaration, hard-coded council ID or trust-bundle/upgrade verification
result as that authority.

Compatibility consequence: native transactions that currently execute these
four setters would return an explicit unavailable/refusal error and leave all
state unchanged until a separately reviewed positive authority phase exists.
No new policy value, threshold, council size, delay, activation height, root,
wire field or cryptographic construction is selected here. The unavailable
boundary does not itself solve authority provenance or approve positive
execution.

Proposed future file allowlist for that bounded boundary:

* `crates/qbind-system/src/governance_program.rs`
* `crates/qbind-system/tests/native_governance_unavailable_tests.rs`
* `crates/qbind-runtime/tests/native_governance_unavailable_executor_tests.rs`

Acceptance tests should send each of the four operations through real
`TxExecutor` with genuine signer authentication and prove exact unavailable
refusal, zero writes/deletes, complete state and transaction preservation, and
no council/proposal claim. They should also prove malformed/unsupported calls
retain documented error ordering without a mutation. Positive authenticated
governance execution, decision consumption, and persistent atomicity must be a
later separately approved design and implementation; they are outside this
single unavailable-boundary proposal.

## Source-identification correction

I withdraw the earlier identification above of `hotstuff_node_sim`'s
`execution_adapter` route as EVM. Source shows it is a separate ledger route:
`crates/qbind-node/src/execution_adapter.rs:71-76` imports
`qbind_ledger::{ExecutionEngine, QbindTransaction, VmV0ExecutionEngine}`;
`:166-175` defines `QbindBlock.txs` as `Vec<QbindTransaction>`, and
`:341-350` executes each transaction through the ledger `ExecutionEngine`.
The async worker constructs `VmV0ExecutionEngine` at
`crates/qbind-node/src/execution_adapter.rs:865-866`. The simulator creates
this `QbindBlock` and submits it to the async service or synchronous adapter
at `crates/qbind-node/src/hotstuff_node_sim.rs:3118-3127,3153-3156`.

These are three distinct paths: (1) native
`qbind_wire::tx::Transaction` → `TxExecutor` → `GovernanceProgram`, which this
characterization tests; (2) ledger `QbindTransaction` through the node
execution-adapter with nonce-or-VM execution; and (3) runtime `QbindTx` with
the EVM `RevmExecutionEngine` (`crates/qbind-runtime/src/qbind_tx.rs:43-52`;
`crates/qbind-runtime/src/revm_engine.rs:100-103`). This source-identification
correction changes no governance result, adds no executed evidence, and does
not establish deployed reachability. Historical validation remains attributed
to `c279c7be1cc415032975f162109e5e2c3f9c6ed0`.
