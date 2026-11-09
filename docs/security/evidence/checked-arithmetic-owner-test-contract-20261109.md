# Gas-disabled arithmetic test-contract decision of record

**Owner-supplied decision in this session; test scope only.** No message ID,
URL, earlier approval or timestamp is asserted. This record describes the
owner's explicit test expectations, not authorization for a production change.

The owner approved these conformance-test expectations:

1. Preserve malformed-payload, then nonce-mismatch, then insufficient-balance
   refusal precedence.
2. Refuse nonce increment overflow as
   `VmV0Error::ArithmeticOverflow { operation: "nonce increment" }` before
   any transaction-level update.
3. Refuse distinct-recipient balance overflow as
   `VmV0Error::ArithmeticOverflow { operation: "recipient balance increment" }`
   before any transaction-level update.
4. If both arithmetic operations overflow, report nonce overflow first, after
   earlier validation checks.
5. For successful self-transfer, preserve the observed final balance and two
   updater calls in this test contract. The call count characterizes current
   behavior only; it is not a production guarantee requiring two calls.
6. Preserve existing successful zero-amount writes and absent-recipient
   materialization behavior.
7. Extend the result oracle with gas/fee assertions and add a synthetic
   false-overflow self-transfer regression control.

The oracle expects gas-disabled result fields `gas_used`, `fee_paid`,
`fee_burned` and `fee_to_proposer` to be zero for both success and failure.
These are test assumptions explicitly approved for this scope; they do not
establish a public production contract beyond it.

## Follow-up implementation and boundaries

`crates/qbind-ledger/src/checked_arithmetic_oracle_tests.rs` compares all four
gas/fee fields as well as result/error. Its same-oracle synthetic sensitivity
control alters each field independently and asserts rejection.

For maximum-balance self-transfer, the synthetic control evaluates the tempting
but incorrect precheck `original_balance.checked_add(amount)`: it is
unrepresentable for `u128::MAX + 1`, which would falsely refuse a valid
debit-then-credit self-transfer. A compliant synthetic observation follows the
existing post-debit restoration: debit first to `MAX-1`, then credit 1 back to
`MAX`; expected result is success with the two calls required by this test
contract. The control confirms the same oracle accepts that observation and
rejects a synthetic arithmetic-refusal observation. It is not a real-engine
mutation or a claim that the current engine already implements checked
gas-disabled arithmetic.

The historical baseline output was produced by source commit
`08f72bff797d6a8692967e921a5c7b9d8e6c8679`, before this follow-up and before
the owner's current-session decision was recorded in this note. Its 38-pass /
9-fail counts and raw logs remain historical; they are not results of the
follow-up. The follow-up's source identity, actual results and full raw logs
are recorded separately in
`checked-arithmetic-owner-test-contract-followup-20261109.md`.

The decision does not authorize production behavior, mutation promotion,
ruleset transition, replay/upgrade policy, network activation or deployment.
It does not establish service/storage updater-call counts, storage validity,
durability, successful adapter publication, atomicity or recovery. The direct
Stage B API's returned result/state is not a zero-setter-call observation.
Neither it nor engine-level transaction instrumentation observes adapter
snapshot publication. The updater is void-returning and the read interface is
infallible; neither proves persistence success.

Recipient overflow remains OPEN. The candidate remains NOT ACCEPTED /
NOT INTEGRATION-READY. Prior ATOM-1/M18, CB-1, CB-FIXTURE-1,
no-replacement-database, consensus-oracle and RPC dispositions remain within
their reviewed scopes. A23-F1 and A33-F1 / E27 remain OPEN; activation remains
DISABLED; public DevNet remains NO-GO.
