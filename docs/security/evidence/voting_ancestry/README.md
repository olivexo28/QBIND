# Voting-ancestry correction: A33-F1 / E27 residual

**VOTING-ANCESTRY CORRECTION — INDEPENDENT REVIEW PENDING.**

A33-F1 / E27 and all other unresolved obligations remain **OPEN**.
Activation **DISABLED**; public DevNet **NO-GO**. This narrow correction does
not expand earlier bounded acceptances or reopen the completed consensus/reset
integration. Historical evidence and the remediation plan's entire base prefix
are preserved; section 25 is an append, not a replacement of section 24.

## Entry and immutable producers

Before branching or editing, `git remote -v`, `git status --porcelain=v1`,
`git rev-parse HEAD HEAD^{tree}`, and
`git ls-remote origin refs/heads/main` observed the requested repository,
both origin URLs `https://github.com/olivexo28/QBIND`, no tracked/untracked
changes, HEAD and direct remote main
`644a3c69dce095458c6e9e2208c200b29fc9fe0f`, tree
`c708a1dfb7362b8dcc8165970b7519b0a9194146`. Local main and origin/main
were also verified at that commit. These initial observations are from the
session tool output, not misrepresented as a retained pre-branch command log.
No `AGENTS.md` was found. Task branch:
`copilot/a33-f1-e27-voting-ancestry`, created directly at that base.

| Identity | Commit | Tree |
|---|---|---|
| Unchanged production plus pinned witnesses | `e4876fc2bef1217035d484568cd791fca1f88d69` | `0a1df93882027fe5a3dfc1dd3532725b91ed1614` |
| Corrected production / identical witnesses | `e57a337fd5afc5f1bd2f49ea43a50c0a866c86aa` | `09a196c6b85a396c4d8d6b762ed0cbb5a38dad89` |

The first is a direct child of the required base; the second is its direct
child. Final evidence publication is not relabeled as the executable producer.
The corrected source is mode `100755`, blob
`d3578a5c3ab25dcc9c16a9c8411bea9ee224cc7c`, SHA-256
`947592ce168ed4e1f74ab729d5ebd6af832ca09bd8f6e49a5111e08839895765`.
The focused test is mode `100644`, blob
`739254bfa30354ec64d0b83ad1a7835daa83509b`, SHA-256
`9761a9d01cbbdb8d7d4d9396457489c0e6d6e61958dbf1637cc0dbdab0fb375c`.
`check_scope.py` checks the unchanged baseline production, identical tests
between producers, current source/test equality to the corrected producer,
exact modes, old tracked bytes and permitted path scope. Its retained output
records source/test Git blobs and SHA-256 values. Toolchain: Linux x86_64,
`rustc 1.99.1 (58cf8f9c3 2026-10-13)`,
`cargo 1.99.1 (5f94df478 2026-08-27)`, default features, existing profiles,
`--locked`; no dependency manifest or cryptographic-policy changes.

## Exact-base source trace and decision contract

All line references here are at **the required base**, unless labeled otherwise.

The authoritative walk is
`crates/qbind-consensus/src/hotstuff_state_engine.rs:2130-2179`,
`HotStuffStateEngine::safety_decision(&block_id) -> SafetyDecision`.
The public boolean wrapper at :2113-2115 maps **only** `Safe(_)` to true.
The production decision caller is
`basic_hotstuff_engine.rs:4714` in private `ingest_proposal`.
All eight public legacy/verified, ordinary/observed/gated/gated-owning proposal
entrypoints at :4227-4507 funnel into that body (verified routes first use
`ingest_verified_proposal`, :4547-4614). Unsafe returns `None` before hooks,
`state.on_vote`, `voted_in_view = true`, or `BroadcastVote` (:4715-4720,
:4807-4848). Verified Unsafe is **`Ok(None)`**, not a typed preflight error.
Gated Unsafe is ordinary refusal, not `GateRejected`.

Node callers are `binary_consensus_loop.rs:6615-6646` (verified present-QC
handoff; otherwise legacy), and `hotstuff_node_sim.rs:2814,2982` (legacy).
The binary loop counts delivery and observes reconfiguration metadata before
calling the engine (:6582-6597); it counts engine acceptance and forwards an
outbound action only when an action exists (:6648 onward). Owner entrypoints
in `safety_record_store/owner.rs:2632,2778` use gated-owning ingestion, but
this trace does not establish their production reachability. Consensus driver
comments are not another actual voting-walk call.

`bounded_safety_decision` (:2200-2249) is a separate explicit-hop query,
used by node safety-record owner code (:2096); observer view queries are
also separately bounded. `is_safe_to_vote_at_height` (:5074) is a different
view-only predicate, not a caller of this walk. Received `on_vote` and
catch-up replay do not use this local proposal-voting decision. Neither does
this correction impose a new safety check on leader self-voting. No unrelated
rule or authority surface is changed.

The existing ordered contract is:

1. **No logical locked QC:** `Safe(NoLock)` even if the candidate/parent is
   absent or cyclic. This is an existing boundary, not newly inferred proof.
2. **Lock present, candidate absent:** `Unsafe`, before reading justification.
3. **Registered candidate, justification view >= lock view:**
   `Safe(ViewSufficiency)`, without walking ancestry. Equality suffices.
   Even absent retained lock data or cyclic parents does not revoke this
   independent pre-existing OR branch.
4. Otherwise walk the **candidate toward its parents**, testing each retained
   node's ID against the logical lock's block ID. Reaching the lock is
   `Safe(Ancestry)`; reaching a parentless root or absent parent is `Unsafe`.
   A parent link equal to an absent lock ID is not proof: lookup must succeed.

Consequently missing ancestry by itself already terminates/refuses. A cycle
can prevent termination only when the lock exists, the candidate is registered,
its justification is absent/older, and its path enters a fully retained cycle
that does not contain the lock. Self-cycle and multi-node cycle are possible;
an outside candidate feeding either cycle suffices. A cycle containing the
lock instead reaches it and returns Safe under the existing rule; unchanged.

Public `register_block` (:1457-1495) accepts arbitrary parent references,
including missing/forward/self links, and replaces an existing ID; insertion
does not enforce decreasing views or acyclicity. `state_mut` (:2413),
`set_locked_qc`, and verified registration also permit these **engine-level**
fixtures. Header-derived IDs (:3875-3889) concatenate proposer/view and the
first 16 parent bytes, so this is not a cryptographic hash-collision assertion.
A5.3's crafted-anchor catch-up construction is historically preserved, but
its eviction witness is **not automatically a voting witness**: a candidate
whose path reaches the lock, or whose QC satisfies the view branch, need not
hang here. We have not constructed a bootable restore plus admitted/authenticated
delivery satisfying all voting-hang conditions. No authenticated-network
reachability, live exploit, unsafe production vote or operational key use
is established by these engine fixtures.

## Minimal correction and effects

The sole production behavioral edit replaces the ancestry `loop` by
`for _ in 0..self.blocks.len()` at the authoritative decision. It borrows an
immutable map and inspects at most **N retained nodes**, with at most N parent
lookups (including the final unsuccessful/exhausting transition), O(1)
additional space and no visited collection, certificate clone or state mutation.
Every complete acyclic retained chain contains at most N distinct nodes; a
lock at the Nth node is checked before exhaustion. Thus valid acyclic decisions
are preserved. Exhaustion reaches existing `SafetyDecision::Unsafe`, never
vote authorization. Missing links and roots retain their refusal behavior;
no-lock and sufficient-view branches retain their exact prior results.

The decision itself takes `&self` and has no effects. **Proposal ingestion is
not transactional:** epoch/view/leader/duplicate-vote checks precede registration;
a future proposal may advance `current_view` and reset proposed/voted flags
before later checks. Registration occurs before safety evaluation and may
insert or replace a node, change height/queue, evict other nodes, reclaim old
evidence, or retain new evidence. Verified correspondence/byte/slot preflight
precedes engine effects; successful verified registration retains the admitted
QC even if voting then refuses. Refusal does not roll back these allowed effects
or recover evidence already replaced/evicted by registration. The tests check
retained original node/evidence identity and exact extra candidate charge where
no replacement/eviction is needed, not an unconditional preservation guarantee.

Unsafe emits no observation/gate consultation, self-vote, vote action, latch
consumption or vote-derived QC/lock/commit transition. The existing API reports
it as `None`/`Ok(None)`; no new error taxonomy or notification contract is added.
No capacity, catch-up, quarantine, recovery, cycle-admission, cryptographic or
activation policy is introduced. Legacy over-capacity insertion remains
unchanged, and the bound uses actual map size, not configured capacity.

## Commands, observations and controls

Every retained `NAME.json` records exact argv, HEAD/tree, dirty status, UTC
times and exit; `NAME.log` retains raw stdout/stderr without normalization.
Rebuild the pinned producer to obtain Cargo's emitted executable path rather
than relying on its build-specific filename. `run_cases.py` runs each exact
libtest case in a separate owned child, with `communicate(timeout=3)`, explicit
`kill()` on timeout, then bounded `communicate(timeout=3)` to reap it.

| Record | Exit / actual outcome |
|---|---|
| `baseline-build-attempt-1` | 101; initial uncommitted test overlay failed compilation, no tests ran |
| `baseline-build` | 0; pinned test-only baseline `cargo test --locked -p qbind-consensus --test a33_f1_voting_ancestry_tests --no-run` |
| `baseline-cycles` | 1; wrong executable filename, no child launched |
| `baseline-cycles-attempt-2` | Driver exit 0; **five TIMEOUT observations**, each child -9, reaped; **zero passing tests** |
| `baseline-acyclic`, `baseline-missing`, `baseline-missing-proposal` | 0 each; three distinct terminating baseline controls passed |
| `focused-tests` | 0; `cargo test --locked -p qbind-consensus --test a33_f1_voting_ancestry_tests -- --nocapture`; **9 passed, 0 failed/ignored** |
| `fixed-cycles` | 0; same five children returned exit 0 within outer deadline and were reaped |
| `consensus-regressions` | 0; **485 passed, 0 failed/ignored**, library plus 12 selected integration targets |
| `production-compile-attempt-1` | 101; missing libclang in bindgen/zstd build, not a production-code failure or test pass |
| `dependency-install` | 0; `apt-get update -qq && apt-get install -y -qq libclang-dev`, only after missing-dependency failure |
| `production-compile-attempt-2` | 0; `cargo check --locked -p qbind-node --lib --bin qbind-node`; non-test library and production binary check completed; existing warnings retained |
| `scope-format-whitespace-attempt-1` | 0; all 4,284 other baseline paths unchanged, exact old plan prefix preserved, whole new test and complete changed production method rustfmt pass, targeted non-raw-log whitespace pass |
| `preserved-a33-manifest` | 0; unchanged section-24 evidence manifest, 19/19 checksums passed |

The preserved plan prefix is exactly **361,456 bytes**, SHA-256
`56de034bf757af3bf4778df17cbc116e0e3b946adb40db98fbf8d7ff2f7bb3f8`.
This includes the completed consensus/reset integration's historical plan;
all its prior evidence and source paths are among the unchanged baseline paths.
`rustfmt --edition 2021 --check` checks the whole new integration file and an
extracted complete `safety_decision` method, not inherited whole-source
formatting. `git -c core.whitespace=cr-at-eol diff --check BASE --` checks
the source, test, plan and new package with `:(exclude)*.log`; raw Cargo/libtest
outputs retain EOF blank lines and dependency-install output retains terminal
control bytes, so no all-artifact whitespace pass is claimed.

Baseline cycle times were 3.002-3.006 seconds before kill; corrected observations
were 0.002 seconds for the four logical children and 0.073 seconds for the
verified child. These are particular process observations, not latency bounds.
The baseline driver exiting zero records successful **observation collection**,
not a passed timeout test. Baseline and fixed results/logs are separately retained
with different binary SHA-256 identities.

The initial uncommitted test overlay incorrectly used a nonexistent
`BlockNode.votes` field, omitted required `Debug` for the test key provider,
and used the borrowed verified accessor where an Arc was required. Those
test mistakes were fixed using the real `state.vote_count` and node Arc; no
production behavior was changed in that attempt. The exact full failed overlay
was not pinned; its original log and dirty revision context are retained, not
invented as immutable source/test evidence. The baseline cycle launch also
initially guessed the wrong executable suffix; the retained failed attempt is
not an executed baseline observation. The corrected invocation uses the path
actually emitted by Cargo. No failed output was overwritten.

The nine new registered tests include direct typed/boolean read-only snapshots;
self/two-node cycles with candidate outside and lock disjoint; complete
acyclic positive/negative chains; **exact N-node boundary at N=1,2,16** with
N-1/N-2 explicit-query controls and actual map deliberately over configured
capacity; candidate/missing-parent/absent-lock lookup cases; equal/higher/older
QC-view controls, no-lock and reachable-lock-in-cycle compatibility; actual
ordinary/observed/gated proposal refusal, no hook calls, unchanged prior nodes,
zero votes, unchanged lock/commit/evictions, permitted future-view/candidate
effects, repeated refusal and successful same-view acyclic retry followed by
duplicate-vote rejection; and genuine verified-QC refusal retaining exact Arc
identity and accounted candidate evidence. The verified fixture generates
disposable ML-DSA-44 keys in memory and calls the actual domain-aware verifier;
it does not use operational signing keys or a test-authored voting predicate.

Regression command (complete argv is also in its JSON):

```sh
cargo test --locked -p qbind-consensus --lib \
  --test a33_f1_eviction_ancestry_tests \
  --test hotstuff_locked_block_safety_tests \
  --test hotstuff_state_locking_tests \
  --test m5_timeout_view_change_tests \
  --test consensus_state_memory_limits_tests \
  --test consensus_memory_limits_tests \
  --test run_422_decision_view_queries_tests \
  --test run_422_safety_decision_gate_tests \
  --test run_422_safety_decision_observer_spike_tests \
  --test run_422_owning_decision_vote_handoff_tests \
  --test run_422_leader_owning_handoff_tests \
  --test run_422_d7c3d_qc_domain_verification_tests
```

Per-target passes in Cargo execution order: library 312; eviction 10; memory
limits 19/7; locked-block 9; state-locking 15; timeout/view-change 28; QC domain
46; decision queries 5; leader owning 7; owning vote 6; gate 9; observer 12.
The new focused nine are additional, not included in the 485 regressions.
Five fixed isolated executions duplicate selected focused cases, not five new
independent scenarios.

## Limits and publication

Termination follows from the immutable finite graph and the retained-count
budget, not a new whole-node cap. Legacy retained-map growth, repeated work,
hash-map lookup cost, pre-checks/registration, other traversals, catch-up,
network/admission, scheduling, recovery, durability and signing remain outside
this single-walk bound. No whole-node resource or latency claim is made.
No live node, network, deployment or activation was run.

Independent review of code/evidence and E27's remaining production prerequisites
and runtime impact remain **OPEN**. Only the task branch is pushed; no PR,
merge, main push, force-push, deployment or activation. Final publication
commit/tree/parent, direct remote task tip/main and clean-worktree status are
reported after publication, avoiding a self-referential commit claim.
