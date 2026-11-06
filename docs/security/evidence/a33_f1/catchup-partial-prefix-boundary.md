# Real-engine valid-prefix-then-error boundary

**TEST-ONLY REAL-ENGINE CATCH-UP BOUNDARY — INDEPENDENT REVIEW PENDING.**

## Producer and retained review

Source and historical-evidence producer:
`c56138c0139c4df5d12ae9b0aaf3222de3ce3968`.
Entry verification found repository `olivexo28/QBIND`, branch
`copilot/a33-f1-bounded-eviction`, clean worktree/staging, matching
local/direct-remote task tip, and local/direct-remote protected main
`c9aaef40b045e896ddfa8b01bad230f6b680715e`.
The new test/evidence producer is the delivery commit containing this record;
its exact commit, tree and parent are reported separately after committing,
not embedded in checksummed content.

The user-supplied review closes E1's documentation-reporting correction.
Producing revisions of the two intermediate integrity-log states remain
unestablished. W1/W2, P1/P2, capacity controls and earlier accepted controls
remain closed within their specified scopes. No reviewer identity or
reviewer-run Rust tests are asserted.

## Existing coverage and source anchors

At the pinned source:

- `crates/qbind-consensus/src/basic_hotstuff_engine.rs:11072-11137`
  provides the synthetic catch-up fixture, valid-suffix test and malformed-
  parent first-item refusal test. Neither covers a later error after a
  valid prefix.
- `crates/qbind-consensus/tests/a33_f1_eviction_ancestry_tests.rs:160-219`
  exercises successful crafted catch-up registration, not a later invalid
  item. The quarantine model tests are not direct real-engine evidence.
- Searching `apply_restore_catchup_blocks` across `crates/**/*.rs` found
  the engine, those tests, the node caller, and the node's one-block
  restore-mode fixture; no retained real-engine prefix-then-error test
  was found. Existing accepted test bodies are unchanged.
- Engine `basic_hotstuff_engine.rs:3954-4053` validates each item's height,
  parent, view, proposer, derived id and logical QC, then registers it and
  replays signers through the real state's `on_vote`. Its final view update
  is after the complete loop, not on an error return.
- `hotstuff_state_engine.rs:1694-1775,1784-1941` covers vote replay,
  logical QC application, lock/own-QC mutation and three-chain commit.
- Node `binary_consensus_loop.rs:8506-8544` calls this API and still has the
  erroneous no-mutation comment on its error arm. This investigation does
  not exercise or change the node caller, counters or restore mode.
- Remediation-plan section 25 already describes partial-prefix source
  semantics and unresolved policy. This test supplies direct engine
  evidence; it does not select or implement that policy.

## Test inputs and observations

New test:
`crates/qbind-consensus/tests/a33_f1_catchup_partial_prefix_tests.rs`.
It uses existing public engine/state accessors, without production
instrumentation. Its fixture follows the retained synthetic fixture:
four unit-power validators (0 through 3), three logical QC signers (0, 1,
2), snapshot anchor `[0x44; 32]` at height 10, and linked items 11 through
15. Id construction follows the existing integration-test byte layout
because the production helper is private. All existing structural and
logical-QC checks remain enabled.

The same observer records all retained nodes (id, parent, view, height,
justifying/own QCs, verified-evidence presence and charge), vote counts for
all five input targets, lock, committed id/height/log, current view, block
count, evictions and retained-evidence bytes. Only QC signer ordering and
map iteration ordering are normalized; no effects are removed.

| Observable | Before call | Four valid items, then invalid QC | Five valid items |
|---|---|---|---|
| Return | not called | `Err(InvalidQc(NonMemberSigner(ValidatorId(99))))` | `Ok(5)` |
| Retained block count | 1 | 5 | 6 |
| Input vote counts (11 through 15) | `[0,0,0,0,0]` | `[3,3,3,3,0]` | `[3,3,3,3,3]` |
| Prefix own QCs | absent | present for 11 through 14 | present for 11 through 15 |
| Lock view | none | 14 | 15 |
| Committed height | 10 | 12 | 13 |
| New commit-log heights | empty | `[11,12]` | `[11,12,13]` |
| Current view | 11 | 11 | 16 |
| Evictions / retained-evidence bytes | 0 / 0 | 0 / 0 | 0 / 0 |

The invalid case appends nonmember signer 99 to item 15's otherwise-valid
signer list. Real QC validation rejects it before that item's registration
or vote replay. After the call, its node is absent and its vote count is
zero. The complete observation equals that of a separate successful
four-item prefix control **except** current view: successful prefix-only
application advances to 15; the error path remains at 11. The comparison
explicitly checks this difference before comparing the other observations.
This demonstrates retained prefix effects and no batch rollback in these
observations; it does not assert universal atomicity or an approved retry
contract.

A separate invalid-first-item control adds the same nonmember to item 11:
the exact same error is returned and the complete observer snapshot is
unchanged. The all-valid control records all five items and advances view
to 16. Prefix and valid controls inspect actual own QCs and actual commit
entries, not inferred commit effects.

Private bookkeeping not exposed by this observer, transient allocations,
external publication and durability are not measured. The current-item
boundary above is specific to pre-registration logical-QC rejection; it
does not characterize a hypothetical error after current-item mutation.
There is no capacity pressure, cycle or retained cryptographic evidence in
this fixture; zero byte charges do not prove general accounting safety.

These are synthetic logical signers/QCs and direct in-process engine
calls, not authenticated network inputs or cryptographic signatures.
No verification checks are disabled, but this API performs logical QC
validation, not signature authentication. No node/network, startup,
signing, durable quarantine, marker, gate, recovery/clear authority or
production catch-up changes are exercised or installed.

## Executed commands and raw results

All commands ran in the repository root; raw captures retain stdout and
stderr without normalization. Existing compiler warnings are retained.

1. `cargo test -p qbind-consensus --test a33_f1_catchup_partial_prefix_tests -- --nocapture`
   first exited **101**: E0624, attempted use of private id-derivation
   helper. No tests ran. Raw: `catchup-partial-prefix-compile-attempt.log`.
2. The same command after adopting the existing fixture's byte layout
   exited **101**: E0283, validator collection type inference. No tests
   ran. Raw: `catchup-partial-prefix-inference-attempt.log`. An explicit
   `Vec` collection fixed the test fixture without production changes.
3. The same command finally exited **0**: **3 passed, 0 failed, 0 ignored**.
   Raw: `catchup-partial-prefix-focused.log`.
4. `cargo test -p qbind-consensus --lib restore_catchup -- --nocapture`
   exited **0**: **2 passed, 0 failed, 310 filtered out**.
   Raw: `catchup-partial-prefix-existing-catchup.log`.
5. `cargo test -p qbind-consensus --test a33_f1_eviction_ancestry_tests --test hotstuff_locked_block_safety_tests --test run_422_safety_decision_gate_tests --test run_422_safety_decision_observer_spike_tests -- --nocapture`
   exited **0**, respectively **10, 9, 9, 12 passed** (40 total), no failed
   or ignored tests. Raw: `catchup-partial-prefix-regressions.log`.

Thus 3 new tests and 42 existing regressions passed. The two compile
failures are unsuccessful attempts, not expected detector failures or
passing security tests. `rustfmt --edition 2021 --check
crates/qbind-consensus/tests/a33_f1_catchup_partial_prefix_tests.rs`
exited 0 after formatting.

## Delivery checks and historical separation

Plan and checksum-manifest additions are append-only. Every pre-existing
evidence file other than the manifest, all accepted test bodies, source
and audit-register bytes remain unchanged relative to the pinned producer.
The existing integrity log is not edited.

The inherited manifest has 211 entries. The E1 record reports its ordinary
check as exit 1, 161 OK / 50 FAILED; this is pinned historical reporting,
not a pass of a later manifest. This delivery appends eight entries: new
test, updated plan, this record and five raw logs, for **219 entries**.
The full current ordinary `sha256sum --check SHA256SUMS` exits **1**:
**168 OK / 51 FAILED**. One additional mismatch is the superseded plan
entry. All eight appended hashes match current files. No producing-revision
reverification of all historical mismatches is claimed. In particular,
the two disclosed intermediate integrity-log prefixes do not become
current-file checksum passes or proven producing revisions.

Ordinary complete staged `git diff --cached --check` exits **2** for
terminal blank lines in the unedited raw captures:
`catchup-partial-prefix-existing-catchup.log:130`,
`catchup-partial-prefix-focused.log:340`, and
`catchup-partial-prefix-regressions.log:403`.
`git -c core.whitespace=cr-at-eol,-blank-at-eof diff --cached --check`
exits **0**. Source/prose-only whitespace checking exits **0** separately;
historical raw logs are preserved, not repaired.

No checksum of the manifest or this record's own checksum text is embedded
here. The delivery commit/tree/parent and direct remote verification are
reported separately, avoiding a checksum cycle.

A33-F1 / E27 and remaining unresolved obligations remain **OPEN**;
activation **DISABLED**; public DevNet **NO-GO**. No anonymous remote
reachability, production failure, partial-prefix policy, all-or-nothing
recovery, operational signing or activation assurance is established.
