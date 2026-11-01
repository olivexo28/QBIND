# RUN 422 Native Validator-Registration Authority Contract

**Status: DRAFT / NOT APPROVED / NOT IMPLEMENTED**

This document records a source-based characterization of native validator
registration and the proposed authority boundary that remains unresolved. It
does not change registration behavior, choose a registration authority, approve
a stake amount, or establish that a node or network reaches this route.

## Route and claims

The route characterized here is the `qbind_wire::tx::Transaction` passed to
`qbind_runtime::TxExecutor::execute_transaction`. That executor constructs
`qbind_ledger::ExecutionContext::new`, verifies the transaction's declared
`TxAuth` entries against signer keyset accounts, selects a registered `Program`
by `program_id`, and dispatches to `ValidatorProgram`.

The signature digest covers the transaction sign-body fields: version,
chain ID, payer, nonce, fee limit, account metadata, program ID, and all call
data. The `auths` vector is not in the signed preimage. For registration, the
call data carries the requested validator ID, declared owner keyset ID,
consensus suite/key, network suite/key, and stake. A valid signature therefore
authenticates the signer keyset's signed transaction claims; it does not by
itself make the signer the declared owner or grant that signer the independent
authority to register the owner, validator, keys, or declared stake.

The authentication principal is the keyset at the transaction account index
referenced by `TxAuth`. `verify_transaction_auth` checks required-signer
coverage and verifies each signature, but does not bind that authenticated
keyset ID to `RegisterValidatorCall.owner_keyset_id`. The handler does not
look up or authorize the named owner. A missing owner keyset and a valid but
different owner keyset therefore do not establish or prevent owner
authorization in this route.

## First mutation and what success means

`ValidatorProgram::execute` rejects a wrong program ID and empty call data,
then dispatches only `OP_REGISTER_VALIDATOR`; other validator opcodes are not
implemented as registration, update, or key-rotation authority routes.
`handle_register` decodes `RegisterValidatorCall`, rejects trailing data,
checks whether the target account already exists, then compares the declared
stake with `ctx.min_validator_stake`. It constructs a version-1
`ValidatorRecord` with `status = Active`, copies the declared owner ID, suite
IDs, public-key bytes, and stake, and initializes slash/jail/extension fields.
It then encodes the record and calls `AccountStore::put` with a target account
owned by `VALIDATOR_PROGRAM_ID`, zero lamports, and default account-header
fields. That `put` is the route's first mutation.

The default `TxExecutor` route uses `ExecutionContext::new`, whose minimum
stake is zero. It does not configure a production policy minimum. Direct
callers can use `ExecutionContext::new_with_min_stake`; the existing handler
comparison rejects `stake < minimum` and accepts equality. The direct-context
test threshold is only a fixture value, not approved policy and not a
configuration received by `TxExecutor`.

The handler does not independently establish the named owner's authorization,
debit or escrow stake, validate possession of either validator key, or perform
a key-admission check. A successful write records the call's declared stake;
it is not token minting, evidence of funded stake, owner consent, network
admission, or evidence that the validator entered a live consensus set.

`ValidatorRecord::is_eligible_at_epoch` separately checks `Active`, not jailed,
and nonzero stake. The consensus stake-filter builder accepts
`ValidatorCandidate` values and filters candidate stake against a supplied
threshold. Its epoch-state wrapper currently documents/usefully exposes that
the current `EpochState` has no explicit stake and uses voting power as a
proxy. This characterization neither feeds the created account into those
consumers nor proves the complete account-to-epoch-set wiring in any deployed
configuration. The local `Active` value must not be interpreted as activation;
nor does this test establish that downstream consumers ignore, harmlessly
filter, or can never observe such a record.

## Source findings and executed assertions

The source observations in this table are not test results. Test assertions
exercise the in-memory `TxExecutor` route and direct `ValidatorProgram`
control; they do not prove node deployment reachability.

| Finding | Source basis | Characterization assertions |
|---|---|---|
| Executor auth precedes program dispatch and uses a zero-minimum `ExecutionContext::new`. | `crates/qbind-runtime/src/lib.rs`: `TxExecutor::execute_transaction`; `crates/qbind-ledger/src/context.rs`: `ExecutionContext::new` and `new_with_min_stake`. | `unrelated_authenticated_signer_can_name_an_existing_different_owner`, `missing_declared_owner_does_not_block_authenticated_record_creation`, `default_tx_executor_context_records_zero_stake`, and the refusal/retry cases use the actual executor. |
| The sign body commits to call data and transaction metadata, not `auths`; it does not create independent operation authority. | `crates/qbind-hash/src/tx.rs`: `tx_sign_body_preimage` and `tx_digest`; `crates/qbind-ledger/src/auth.rs`: `verify_transaction_auth` and `verify_single_auth`. | `signed_stake_change_is_rejected_until_the_changed_body_is_resigned` demonstrates failed authentication before program access and successful registration after re-signing. |
| Registration decodes before target/minimum checks, rejects trailing data, checks target uniqueness, then minimum, and writes an Active record copying call values. | `crates/qbind-system/src/validator_program.rs`: `execute` and `handle_register`; `crates/qbind-wire/src/validator.rs`: `RegisterValidatorCall::decode`. | Positive registration, owner identity, stake/default assertions, direct minimum control, exact replay, pre-existing target, and authenticated framing controls in the new integration target. |
| The wire decoder materializes consensus/network key vectors before target/minimum checks. | `crates/qbind-wire/src/validator.rs`: `get_bytes(...).to_vec()` for both keys; handler checks occur after `decode`. | Framing cases assert current decoder/program errors and nonmutation; they do not assert allocation bounds. |
| The handler has no owner-keyset lookup, stake debit/escrow, or key-possession check. | `crates/qbind-system/src/validator_program.rs`: full `handle_register` sequence; `crates/qbind-ledger/src/auth.rs`: auth lookup is only for the transaction signer. | Existing-owner and absent-owner cases, positive stake/no-debit state comparison, and independent genuine consensus-signature/network-KEM setup controls. Fixture key usability is not a production admission check. |
| Other validator opcodes are not implemented by this program's dispatch. | `crates/qbind-system/src/validator_program.rs`: opcode match; `crates/qbind-wire/src/validator.rs`: opcode constants and separate call codecs. | The authenticated unsupported-opcode case requires `ProgramError("unsupported validator opcode")` with no target access or mutation. |
| A local record is not by itself a live set result. | `crates/qbind-types/src/state_validator.rs`: `ValidatorRecord::is_eligible_at_epoch`; `crates/qbind-consensus/src/validator_set.rs`: candidate filtering and `StakeFilteringEpochStateProvider`. | These downstream routines are not invoked by this target. No consensus-set, networking, or activation result is asserted. |

The test fixtures use structurally valid, correctly owned, non-executable,
single-key threshold-1 signer keysets. The counting signature wrapper delegates
to the genuine ML-DSA-44 verifier. Fixture setup separately verifies a
signature under the generated consensus key and completes an ML-KEM-768
encapsulation/decapsulation round trip for the generated network key. Those
setup checks establish fixture-key usability only; the transaction verifier's
measured count is separate.

The instrumented store records every `get`, `put`, and `delete`; full-state
snapshots read its internal map directly and do not contaminate the activity
trace. Assertions compare complete account state, decoded record fields,
transaction values, and wire bytes across success/refusal paths. Positive
declared stake remains in the record while payer, owner, and sentinel accounts
remain byte-for-byte unchanged. Empty-auth and invalid-signature refusals are
followed by authentic retries. Exact replay performs fresh authentication but
is refused by the existing target-exists check; this is not durable one-use
authorization or replay consumption.

## Authority dimensions and remaining requirements

These are separate questions and none is resolved merely by a signed call or
an Active record:

1. **Transaction authentication:** establish who signed the transaction
   digest, using current signer keyset policy and a fresh verification.
2. **Owner authorization:** independently admit the principal allowed to
   register for the named owner, including currentness, revocation, scope, and
   the required relationship between owner and caller. No source or policy is
   selected here.
3. **Backed stake:** establish a funded source and an atomic debit/escrow or
   other approved conservation transition. A caller-supplied integer is not
   backing.
4. **Key roles and admission:** govern consensus/network key roles, supported
   suite policy, key validation, and any authorized proof or process required
   for key possession. The fixture round trips do not supply a production
   proof-of-possession format.
5. **Current policy and minimum:** define the independently governed,
   effective registration policy and minimum stake. No council rule, threshold,
   bootstrap exception, or production authority source is invented here.
6. **Freshness and replay disposition:** define whether registration intent is
   one-use, how it is bound to the exact target and body, and how duplicate,
   stale, revoked, or conflicting intent is handled. The existing target
   uniqueness check is not durable authorization consumption.
7. **Coherent state and atomic effects:** define a consistent policy/owner/
   balance/target view and atomic publication of authorization consumption,
   funding changes, and validator-record creation, including failure behavior.
8. **Membership handoff:** define how an admitted record is validated, selected,
   and handed to the live validator set and network admission path. A successful
   local account write supplies no such handoff evidence.

## Resource, execution, and deployment limits

This route is not allocation-free. The registration decoder copies the
consensus and network key vectors before handler target and minimum checks.
The transaction digest path constructs its sign-body preimage. Authentication
also materializes signer state through the existing `AccountStore::get` path.
These observations neither approve limits nor establish bounded physical
memory, allocator behavior, account-store coherence, or a worst-case execution
budget. The framing tests establish only the current returned errors and
nonmutation for their bounded inputs.

The `qbind_wire::tx::Transaction` / `TxExecutor` route is distinct from
`qbind_ledger::execution::QbindTransaction` and its signature/VM execution
adapter, and from `qbind_runtime::QbindTx` / EVM execution. Those types and
paths are not substituted for the native transaction tested here.

This source/integration-test evidence does not establish whether deployed
configuration invokes this executor, durable or persistent account storage,
crash/restart behavior, atomicity across external effects, replay state after
restart, or anti-rollback protection. It does not establish selected-binary,
running-node, network, validator-set, or deployment behavior.

Preserved posture: `D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED`;
`D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET`; §13.6 whole-lifecycle
`INCOMPLETE`; activation `DISABLED`; public DevNet `NO-GO`; durable anti-rollback
`NOT-ESTABLISHED`; C4/C5 `OPEN`; RS1 `OPEN`. Candidate limits remain
`UNAPPROVED`. Whole native admission and governance contracts remain
`DRAFT / NOT APPROVED / NOT IMPLEMENTED`. No F1/F2 closure or deployed-path
readiness is established.

## One proposed bounded enforcement slice

**Proposal only; unapproved and unimplemented:** refuse native validator
registration while the required independent registration authority is
unavailable. The likely source scope is the registration branch in
`ValidatorProgram::handle_register`, with focused direct-program and
`TxExecutor` tests in
`crates/qbind-runtime/tests/run_422_native_validator_authority_contract_tests.rs`.
Keep executor authentication before dispatch, preserve wrong-program,
empty/unsupported opcode, decode/trailing-data, target-exists, and existing
explicit-minimum error ordering, and make the unavailable-authority refusal
occur before the first account mutation. Existing registrations would become
refusals when no independent authority is available; this is an intentional
compatibility break for successful writes, not a positive authorization
implementation. No source change, policy choice, or enforcement is made in
this task.
