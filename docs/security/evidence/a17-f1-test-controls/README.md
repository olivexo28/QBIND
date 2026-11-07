# A17-F1 / RS1-F7 acceptance-control correction

**TEST CONTROLS CORRECTED — INDEPENDENT REVIEW PENDING.**
A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain **OPEN**. Activation remains
**DISABLED**; public DevNet remains **NO-GO**.

## Provenance and identity

The user supplied an independent **CHANGES REQUIRED** acceptance-control review
and reported that it found no production guard bypass. No reviewer identity or
raw review artifact was supplied; neither is invented here. This correction
does not independently reproduce that review or promote the earlier candidate's
author-reported summaries into independently verified execution evidence.
Missing raw outputs for the earlier candidate are not reconstructed.

Initial verification used the actual repository origin
`https://github.com/olivexo28/QBIND`, local branch
`copilot/a17-f1-catchup-containment`, clean worktree and empty staging area.
Local HEAD and direct remote task tip both matched
`7d52477ce0eecff9f3fc80692eccbdee771cc81a`, tree
`057430ef7167a5d08ddb8807b36f86fe25540e66`, parent
`e584738c81814e70cbd58f80c921bea93983758c`.
Direct remote main matched the reviewed
`619a75fa8355692823802754f605e6c02bb57537`; fetching that ref confirmed tree
`a7d18a4bb4d40037e49042cb30c69a56e85ecd75`. The initial local object lookup
for that main commit failed because it was not present locally; fetching the
direct ref resolved it. This was not a test failure or a worktree change.
Cached tracking refs were not used to establish current remote identity.

The candidate and reviewed main have diverged. This task neither integrates
them nor authorizes integration. Any later integration candidate requires
separate preparation and review against then-current main.

## Correction and protected observations

Only the A17 test block in
`crates/qbind-node/src/binary_consensus_loop.rs` changes. No production
inspection API is added. The production `RestoreCatchupResponse` refusal,
sender binding, counters, placement and helper behavior are unchanged.
All non-empty network suffixes, including honest ones, remain refused.
This liveness impact remains explicit; empty responses are characterization,
not approval of recovery or participation.

`a17_admitted_snapshot` uses the existing
`GenesisConsensusAuthority::for_verification_snapshot_fixture`,
`CurrentAuthorizationOwner::establish_for_fixture`,
`AuthorizedProposalVoteSnapshot::try_bind`, `owner.admit()` and
`owner.confirm()` path. Coherence checks are the real existing checks, not a
replacement test-only bypass. The test asserts shared Timeout/snapshot
membership, key-provider and backend instances, matching chain ID and epoch.
It supplies both matching Timeout/PV contexts and `Some(snapshot)` under
`Required`, separately from the otherwise identical `Some(PV), None(snapshot)`
control. A present PV context is **not** a present admitted snapshot. Existing
missing-authority cases remain. The fixture is synthetic/local and signerless;
it establishes no independently provisioned production authority, currentness,
activation, signer exclusivity, rollback or recovery policy. Admission and
confirmation are fixture preconditions; catch-up dispatch does not itself
admit the snapshot or authenticate the suffix.

The shared checker compares the same engine before and after dispatch through
its existing `Debug` representation. It does not compare independently seeded
HashMaps or parse debug text. The representation is an exact diagnostic
snapshot for this pinned revision, not a canonical wire format. Source:
`BasicHotStuffEngine::fmt` at
`crates/qbind-consensus/src/basic_hotstuff_engine.rs:1970-2009`,
derived `HotStuffStateEngine::Debug` at
`crates/qbind-consensus/src/hotstuff_state_engine.rs:278-359`,
derived `VoteAccumulator::Debug` at
`crates/qbind-consensus/src/vote_accumulator.rs:201-214`, and derived
`BlockNode::Debug` at `crates/qbind-consensus/src/block_state.rs:30-85`.

| Category | Actual observation |
|---|---|
| Votes/history/accumulator | Per-view voting/proposal latches, accumulator entries with voter sets and tracked views, vote-history map and tracked-view set, equivocation state and eviction/drop counters |
| QCs and lock | Full retained block justify/own QC fields, locked QC, commit ID/height and commit log |
| Retained contents/order/accounting | All BlockNode fields, same-map diagnostic iteration order, actual pending eviction queue order, per-block evidence charge, aggregate retained evidence bytes/ceiling/refusals, block/vote/log eviction counts |
| Restore/peer progress | All four RestoreCatchupModeState fields, including active/baseline/peer maximum/exit height |
| Outbound | Supplied recording facade captures calls and arguments to proposal broadcast, vote broadcast, directed vote, directed timeout and generic consensus broadcast |

The admitted-snapshot test seeds three real logical votes, their history and a
formed QC/lock. They must remain unchanged by dispatch. Separate controls
demonstrate that the checker detects each incremental vote and the QC/lock
formation; another actual facade call demonstrates detection of an outbound
effect. The valid-suffix sensitivity path deliberately invokes the existing
downstream helper directly in test code. That helper has no outbound parameter
or emission path. The **same checker** returns
`Err(["engine", "restore_mode"])` after its non-vacuous suffix import; this is
an expected sensitivity detection, not a passing production-security result.
No production switch, fallback or bypass is introduced.

The shared before/after checker runs on all A17 real-dispatch calls: successful
bindings, existing authority/compatibility combinations, the newly admitted
snapshot, response shapes, and sender-binding failures. Engine and outbound
effects are always refused by the oracle. Only active, non-self empty controls
allow the existing restore-mode-only effect, then assert the exact progress,
exit or no-exit observations. The added initially inactive empty control
requires no engine/mode/peer/outbound effect. Existing active/exit,
active/no-exit and self-response controls remain.

Ingress/binding/receipt/rejection statistics and the inbound `kind="other"`
metric are explicitly outside the no-effect oracle and asserted separately.
Binding failures still count only binding rejection, not endorsement rejection.
This synchronous handler fixture executes no unrelated tick, receive-loop,
signing, networking or deployment event.

**Unavailable/unexercised:** allocation capacities and transient allocations,
opaque recorder internals, or the internals of an installed isolated
received-Vote context are not fully observed. Recorders and isolated contexts
are absent in these fixtures; verified evidence slots are empty, while their
accounting fields are observed. There is no claim of populated verified-QC
resource coverage, deserialization bounds, durable quarantine, whole-node
memory limits, heap identity, concurrent effects, release/runtime assurance or
authenticated recovery. HashMap diagnostic order is not protocol ordering;
only the pending queue supplies the actual eviction ordering observation.

## Executed validation and raw outputs

All `.log` files retain complete combined stdout/stderr, the exact command and
exit code. Parallel test output interleaving is retained, not rewritten.

| Command | Raw output | Result |
|---|---|---|
| `LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-node --lib a17_ -- --nocapture` | `focused-attempt-1.log` | Exit 0; 9 passed, 0 failed, 0 ignored, 0 measured, 2,227 filtered |
| Same command after A17-only formatting | `focused-final.log` | Exit 0; 9 passed, 0 failed, 0 ignored, 0 measured, 2,227 filtered |
| `LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-node --lib restore_mode_ -- --nocapture` | `restore-regressions.log` | Exit 0; 9 passed, 0 failed, 0 ignored, 0 measured, 2,227 filtered |
| `rustfmt --check --edition 2021 crates/qbind-node/src/binary_consensus_loop.rs` | `rustfmt-module.log` | Exit 1; existing formatting differences outside the A17 block; no A17 formatting diff |
| `git diff --check` | `whitespace-default.log` | Exit 2; CRLF additions reported as trailing whitespace under default settings |
| `git -c core.whitespace=cr-at-eol diff --check` before evidence staging | `whitespace-crlf.log` | Exit 0 for the tracked source change at that checkpoint |
| `git -c core.whitespace=cr-at-eol diff --cached --check` | `whitespace-staged.log` | Exit 2; literal whitespace-only context lines in the complete raw rustfmt output |
| `git -c core.whitespace=cr-at-eol diff --cached --check -- "*.rs" "*.md" "docs/security/evidence/a17-f1-test-controls/SHA256SUMS"` | `whitespace-source-docs.log` | Exit 0 for source/documentation/manifest, explicitly excluding raw logs |

There were no failed Cargo attempts for this correction. All three formatting/
whitespace non-passes are retained, not relabeled passes. The staged check
prevented the first chained commit attempt from reaching `git commit`; no
commit was created by that attempt. Raw formatting output is deliberately not
trimmed or rewritten to manufacture a whitespace pass. Only the A17 block was formatted
with rustfmt; CRLF source bytes were preserved. No unchanged workspace suite,
historical accepted suite, release build or production compilation was repeated.
The changed `cfg(test)` code was compiled by the focused library test commands.
The candidate's earlier production check and earlier full-workspace claims
remain their original author/user-reported evidence, not new execution here.

## Source identity and changed-path inventory

Corrected source Git blob: `8aa890c63412c7048ea6bb5a790ebcb9831c2013`.
Source SHA-256:
`9b03a9fb9c2f0d7f5883bfe41f035886b276e58f0b56b65b5cefb5a70eaeb2b3`.
The final commit/tree/parent and direct remote tip are reported after commit
and push; this file deliberately does not assert a self-referential hash.

Changed paths:

```text
crates/qbind-node/src/binary_consensus_loop.rs
docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md
docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md
docs/security/evidence/a17-f1-test-controls/README.md
docs/security/evidence/a17-f1-test-controls/focused-attempt-1.log
docs/security/evidence/a17-f1-test-controls/focused-final.log
docs/security/evidence/a17-f1-test-controls/restore-regressions.log
docs/security/evidence/a17-f1-test-controls/rustfmt-module.log
docs/security/evidence/a17-f1-test-controls/whitespace-default.log
docs/security/evidence/a17-f1-test-controls/whitespace-crlf.log
docs/security/evidence/a17-f1-test-controls/whitespace-staged.log
docs/security/evidence/a17-f1-test-controls/whitespace-source-docs.log
docs/security/evidence/a17-f1-test-controls/SHA256SUMS
```

The source path supplies only test controls; the plan and Run 422 paths are
append-only coordination records; this package supplies correction-specific
provenance, limitations and raw outputs. No other source or dependency path is
needed. Audit-register bytes and accepted production/consensus/reset/fixture
integrations remain unchanged.
`SHA256SUMS` pins all other changed files, including documentation and raw
outputs; it deliberately excludes itself.

Raw-output SHA-256 identities:

```text
5a76d11b99cf7228a029bda24c7c8a7f6f919789841d733fdd6d14bc0717b875  focused-attempt-1.log
bba78f719d69170f38b90c9cfe1cb826de2699d6916ee10082a1ac348b019f24  focused-final.log
fe92c93f8d687acabd16bce75a003d835bd373c5b0ff0c7e38fce07fcd0c5798  restore-regressions.log
1cee09c5d2e626495d46379ae85ae2454edbcdc98c52ab76ca96112d1deda978  rustfmt-module.log
15feb0e46be3553691046e728644d04aefe5f26d65463a757023a06cc465cfc8  whitespace-default.log
7c204dcbf59ce50658c0cd9695e217f30ebb4552e4950971500d9b1ce234a9d3  whitespace-crlf.log
3cc036399287fadd070e7139e4bad31e283da78eb919f594cc407a5665fa7808  whitespace-staged.log
b5a055054bbe4df0604da9b2aedf30e63c7fc11403fb731b8d686458effb326e  whitespace-source-docs.log
```
