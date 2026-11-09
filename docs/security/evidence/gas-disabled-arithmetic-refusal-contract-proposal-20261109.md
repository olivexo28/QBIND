# Gas-disabled VM-v0 arithmetic refusal: contract proposal and future controls

**PROPOSAL ONLY / NOT APPROVED.** No fix, public error representation, or
overflow policy is selected by this document. The recipient-overflow concern
remains OPEN.

## Verified and pinned basis

Before creating this documentation branch, remote
`test/gas-disabled-recipient-overflow` was verified at
`07412d568e50638aef979028145fbb6b7186e782`, tree
`df877994a9ddc27a75d0c09b3d7ae32df3c573aa`; remote main was
`aa382fa28b2d3e97e6203d47fa8231b5f2269741`. Local HEAD/tree matched the
reviewed endpoint and the worktree was clean.

All source and document locations below are pinned to **07412d568e50638aef979028145fbb6b7186e782**,
not moving branch tips. `crates/qbind-ledger/src/execution.rs` has blob
`fe78bed4bddc5f00aa0ea2c8a464050106d84093`.
The retained evidence is
`docs/security/evidence/gas-disabled-recipient-overflow-characterization-20261109.md`,
with its raw debug/release outputs, commands, flags, hashes, and limitations.
Those are prior author runs, not new runs for this proposal.

The recorded debug build caught recipient-addition overflow after the sender
update; the recorded release build wrapped the recipient balance and returned
success. Both used synthetic in-memory state. These two observations neither
establish every build's behavior nor approve panic/wrapping, durable corruption,
rollback, node reachability, or exploitability.

## 1. Existing arithmetic and ordering

`VmV0ExecutionEngine::new()` disables gas
(`crates/qbind-ledger/src/execution.rs:2103-2109`).
`execute_tx` dispatches gas-enabled work elsewhere; the gas-disabled route is
at `:2147-2198`:

| Order | Existing decision or operation | Bounds and effects |
|---|---|---|
| 1 | Decode transfer payload | Malformed payload returns `MalformedPayload` before account mutation. |
| 2 | Read sender; compare transaction nonce | A mismatch returns `NonceMismatch`. Equality is validation, not protection against increment overflow. |
| 3 | Compare sender balance with amount | `balance < amount` returns `InsufficientBalance`; it establishes that subsequent subtraction cannot underflow for this captured sender value. |
| 4 | Construct sender update | `u64` nonce `+ 1` is ordinary addition; `u128` balance `- amount` is ordinary subtraction following the balance guard. A nonce increment beyond `u64::MAX` is not explicitly refused. |
| 5 | Write sender | Calls void-returning `set_account_state` before fetching recipient or checking recipient addition. |
| 6 | Read recipient; construct update | Recipient nonce is preserved; `u128` balance `+ amount` is ordinary addition, not a checked refusal. For self-transfer this read sees the sender's just-written value in the in-memory fixture. |
| 7 | Write recipient; return success | No subsequent arithmetic validation or rollback exists in this path. |

The proposed checked operations are nonce increment, sender debit, and
recipient credit (or self-transfer restoration). A sender-debit underflow
cannot occur after the existing balance guard on the same captured value;
using checked subtraction would be defense in depth, not a reason to replace
the existing insufficient-balance error or change its precedence.

Arithmetic validation and backend writes are different failure classes.
`AccountStateUpdater::set_account_state` returns `()`
(`execution.rs:1138-1140`). `PersistentAccountState::put_account_state` returns a
storage result (`:1258-1279`), but `CachedPersistentAccountState` caches first
and ignores the put result (`:1806-1813`). The adapter's private persistent
worker updates cache only on successful put and otherwise discards the error
(`crates/qbind-node/src/execution_adapter.rs:621-675`). None of these limitations
is fixed by an arithmetic precheck.

## 2. Proposed refusal contract and precedence

Subject to owner approval, propose that an unrepresentable gas-disabled
transaction arithmetic result returns an identifiable transaction failure,
with **no call to the updater for either account**, no panic, and no wrapped
value, independently of compiler overflow-check settings. Both account values
must remain exactly unchanged. Checking final values alone is weaker than
proving no update was attempted.

Proposed decision order:

1. Retain malformed-payload refusal first.
2. Retain sender nonce mismatch next.
3. Retain insufficient sender balance next, even for self-transfer.
4. Compute and validate all required arithmetic, including nonce increment,
   using captured values, before the first updater call.
5. Only after successful prevalidation, publish the previously computed values.

This preserves existing *returned validation-refusal* precedence. It
intentionally replaces the existing profile-dependent arithmetic outcome;
in particular, recipient overflow would no longer occur after sender mutation.
Within arithmetic failures, checking nonce increment before recipient credit
is the proposed ordering (matching the current calculation order), but
precedence when both overflow must be explicitly approved and tested.
Do not let earlier recipient reads or arithmetic checks mask malformed
payload, nonce mismatch, or insufficient balance. Read count/order may change
for successful validation; compatibility with nontrivial backends must be
reviewed rather than assumed.

`VmV0Error::ArithmeticOverflow { operation: &'static str }` already exists
(`execution.rs:1830-1876`), with formatting at `:1902-1904`, and
`VmV0TxResult` is the current return vehicle. Reuse is a candidate, not an
approved exact variant, operation label, string, or public message contract.
Owner review must decide whether its present semantics cover nonce overflow
and how callers classify it. A storage error must not be relabeled as this
arithmetic refusal. Gas-disabled outcomes should retain their zero gas/fee
accounting unless an explicit separate policy is approved.

## 3. Distinct accounts, self-transfer, and boundaries

Let captured sender state be `(n, B)`, captured distinct recipient state
`(r, R)`, and transfer amount `a`, with matching nonce and `B >= a`.

**Distinct accounts:** propose precomputing `(n + 1, B - a)` and
`(r, R + a)` with representability checks before either write. Refuse when
`n = u64::MAX` or `R + a > u128::MAX`. Otherwise preserve both account
results and recipient nonce. An absent recipient retains current default
account semantics; the correction should not add an account-existence policy.

**Self-transfer:** the existing sequence debits to `(n + 1, B - a)`,
then reads that same account and restores `a`, leaving `(n + 1, B)`.
Checking `B + a` against the original account is incorrect: for example
`B = u128::MAX, a = 1` is a representable self-transfer when `n < u64::MAX`.
Propose deriving the aliased final result from the post-debit value:
`(B - a) + a = B`, with one nonce increment and the existing sufficient-balance
requirement. This restoration cannot overflow under that guard.
Skipping the amount-coverage check because the net debit is zero would change
current validation behavior and is not proposed.

Whether successful self-transfer publishes one final write or preserves two
updater calls is an unresolved compatibility decision. One write avoids an
intermediate debit but changes observable call count and failure points; two
precomputed writes preserve that shape but retain an intermediate state and
storage-failure window. Neither choice is approved here. The proposed
zero-write guarantee applies to arithmetic refusal under either choice.

**Zero amount:** distinct accounts preserve both balances, increment sender
nonce, preserve recipient nonce, and currently still invoke account updates.
Do not silently remove recipient materialization/write behavior for an absent
account. `R = MAX, a = 0` is representable; it must not be rejected as recipient
overflow. Self-transfer zero likewise preserves balance and increments nonce.
Both require refusal if the sender nonce is already `u64::MAX`, under the
proposed nonce policy.

**Maximum and normal values:** `n = u64::MAX - 1` can advance to `MAX`;
the next matching-nonce transaction needs explicit arithmetic refusal.
`R = MAX - 1, a = 1` reaches `MAX` without overflow.
`B = MAX, R = 0, a = MAX` yields balances `0, MAX`.
`B = 0, a = 1` remains insufficient balance, not an arithmetic failure.
Normal transfers preserve current success results, balances, nonces and
zero gas/fee values. No saturation, wrap, panic, automatic nonce reset, or
special maximum-balance policy is proposed as an alternative success.

## 4. Atomicity boundary and gas-aware scope

Prevalidation would establish absence of updater calls only on arithmetic
refusal. It would not establish atomic publication of multiple successful
writes, block atomicity, rollback after a backend error, safety under panic or
crash, durability, snapshot authority, external-effect atomicity, or exclusive
signer control. State views also do not expose read errors
(`execution.rs:1130-1140`); the arithmetic proposal assumes coherent captured
values under the applicable execution ownership contract, not authenticated
or current storage merely because the values were read.

Gas-aware M18 code checks arithmetic and handles aliasing before its mutations
(`execution.rs:2260-2477`); it is useful prior art, not a drop-in policy for
gas-disabled validation precedence or fees. Its source comment invoking
ATOM-1 does not itself prove durable transactionality.
`docs/whitepaper/QBIND_WHITEPAPER.md:2052-2061` states gas/state atomicity
requirements. Existing accepted ATOM-1/M18 findings remain within their
reviewed scopes; this proposal neither reruns them nor transfers their
guarantees to the gas-disabled route.

## 5. Future conformance matrix

**Every row and sensitivity control is FUTURE / NOT EXECUTED.** Inputs below
use the actual gas-disabled engine, synthetic in-memory state and distinct
accounts unless labeled self-transfer. `(n, B)` and `(r, R)` denote initial
states; use `r = 9` where not otherwise specified. All expected arithmetic
refusals are proposals pending approval, not current observed conformance.

| FUTURE / NOT EXECUTED control | Inputs | Proposed expected outcome |
|---|---|---|
| Recipient overflow | `(4,100)`, `R=MAX`, matching nonce, `a=1` | Identifiable arithmetic failure; both original states unchanged; zero updater calls. |
| Sender nonce overflow | `(u64::MAX,100)`, `R=0`, matching nonce, `a=1` | Arithmetic failure before any updater call; unchanged accounts. |
| Both arithmetic overflows | Sender nonce `MAX`, balance 100; recipient balance `MAX`; `a=1` | Refuse without mutation; exact arithmetic precedence requires owner approval (proposed nonce-first). |
| Normal distinct transfer | `(4,100)`, `(9,20)`, `a=7` | Success: sender `(5,93)`, recipient `(9,27)`; zero gas/fees. |
| Normal self-transfer | One account `(4,100)`, `a=7` | Success: same account `(5,100)`; approved write count separately asserted. |
| Maximum self-transfer | One account `(4,MAX)`, `a=1` and `a=MAX` | Success `(5,MAX)`, not false overflow from `MAX+a`. |
| Self-transfer insufficiency | One account `(4,0)`, `a=1` | Existing insufficient-balance refusal; no updates despite net-zero transfer. |
| Self-transfer nonce overflow | One account `(u64::MAX,100)`, `a=1` and `a=0` | Arithmetic refusal, unchanged account, no writes. |
| Zero amount | Distinct `(4,100)`, `(9,MAX)`, `a=0`; repeat self and absent-recipient fixtures | Success with sender nonce 5 and unchanged balances; preserve approved recipient write/materialization semantics. |
| Boundary nonce | `(u64::MAX-1,100)`, `R=0`, `a=1`; next transaction with matching `MAX` nonce | First succeeds with nonce `MAX`; next refuses before mutation. |
| Boundary balances | `(4,1)`, `R=MAX-1`, `a=1`; `(4,MAX)`, `R=0`, `a=MAX`; `(4,0)`, `R=MAX`, `a=0` | All succeed with representable exact values; no spurious overflow rejection. |
| Malformed precedence | Malformed payload with sender nonce `MAX` and mismatched transaction nonce | `MalformedPayload`; accounts unchanged; zero writes. |
| Nonce precedence | Valid payload, mismatched nonce; insufficient sender balance and overflowing recipient balance | `NonceMismatch`; no arithmetic refusal and no mutations. |
| Balance precedence | Matching sender nonce `MAX`, balance 0, `a=1`, recipient `MAX` | `InsufficientBalance` before nonce/recipient arithmetic failure; zero writes. |
| Publication-order sensitivity | Observing updater records every attempted mutation for recipient and nonce overflow fixtures | Require no calls, not just equal final values; a deliberately reordered test-only path that writes sender first must be rejected by that oracle even if values are restored later. |
| Checked-arithmetic sensitivity | Test-only bypass of checked recipient addition or nonce increment | The same conformance oracle must reject panic or wrapped success, rather than adapt its expected result to a wrapping build. |
| Alias sensitivity | Test-only computation from original self-recipient balance `B+a` | Maximum self-transfer positive case must reject this erroneous false refusal. |
| Build independence | Run all cases in debug and release; record actual compiler flags, panic strategy and independent runtime overflow probe | Identical proposed transaction outcomes/account values regardless of arithmetic probe result. A caught panic is a conformance failure, not arithmetic refusal; isolate abort configurations in child processes. |

Unexpected panic, fixture error, absent output, process abort, timeout,
compilation failure and infrastructure failure must be reported separately,
not counted as valid arithmetic refusal. Future test-only mutants must remain
separate from production code and demonstrate rejection by the same oracle.

The retained characterization intentionally accepts its exact measured
panic/wrap outcomes, with strict fixture/state checks. It is not the future
conformance oracle above and must not be silently relabeled or rewritten to
claim the proposed contract already passes.

## 6. Implementation-entry decisions, delivery scope, and status

Owner approval is needed for the pre-mutation refusal contract, arithmetic
failure ordering, exact public error classification/message compatibility,
self-transfer write shape, and zero-amount/absent-recipient write semantics.
Any deliberate change to the existing malformed/nonce/balance precedence
requires separate explicit approval. Implementers would need to review
`execution.rs` and public result consumers plus focused tests; storage-error
propagation, transactional publication, recovery and caller readiness are
separate work, not implied implementation scope.

This branch adds only
`docs/security/evidence/gas-disabled-arithmetic-refusal-contract-proposal-20261109.md`
relative to `07412d568e50638aef979028145fbb6b7186e782`. Relative to main it
inherits the 28-path package inventoried in the pinned characterization report
and adds this document: **29 paths total**, including inherited unaccepted
production work. This is not a one-document branch based directly on main.
Production code, tests, manifests, lockfiles and historical evidence are
unchanged. No tests were rerun, and no node, operational keys, PR, merge or
deployment were used.

Recipient overflow remains OPEN. The required-persistence candidate remains
NOT ACCEPTED / NOT INTEGRATION-READY. Recovery identity, authoritative history,
snapshot authority and storage failure handling remain OPEN. Previously
accepted findings are preserved within their scopes. A23-F1 and A33-F1 / E27
remain OPEN; activation remains DISABLED; public DevNet remains NO-GO.
