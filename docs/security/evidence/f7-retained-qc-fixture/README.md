# F7 retained-QC formed-TC fixture correction

**REPRODUCED. CORRECTION — INDEPENDENT REVIEW PENDING.**

This is a synthetic library-test fixture correction, not a consensus-policy
change or an independent acceptance review. Reviewer: **UNASSIGNED**.
A33-F1 / E27 and other unresolved obligations remain **OPEN**.
Activation remains **DISABLED**; public DevNet remains **NO-GO**.

## Revision and report boundaries

The entry checkout was clean (including untracked files). Fetch and push origin
both identified `https://github.com/olivexo28/QBIND`. Direct
`git ls-remote origin refs/heads/main`, local HEAD and expected main agreed:
`01e5731617a1ca2a9894bad4e7c5d54466587c39`, tree
`63d25cc32d01d37f382fa101d2ecce7c78cf5cca`, parent
`e57a337fd5afc5f1bd2f49ea43a50c0a866c86aa`.
Only then was `copilot/investigate-retained-qc-tc-eviction` created from that
base. The initially shallow checkout was unshallowed for the bounded revision
comparison. No earlier commit or accepted evidence was edited.

The original reported run's **command, revision, features and environment remain
unknown**. This investigation independently reproduces the same assertion on
verified current main; it does not establish the original run's provenance.
The reported 2,279 passed / one failed / six ignored is not our suite result.
Our isolated base run selected one test and filtered out 2,225.
The separately reported "controlled observer caller unwind" was reported **ok**;
it is not the failed test and was not investigated as one.

The unmodified earlier revision
`60c03f9fc3f9860a14a971c0923363d7257059ac` has tree
`4ae34b986f1d79ab69468912e5f197eeb6b29587`, parent
`c9aaef40b045e896ddfa8b01bad230f6b680715e`.
Its immediate conservative-eviction successor
`38a0180c3905d02ff252f4b98915265271c730b4` has tree
`42eac8a1f92859e02d801478c60cbc4ea051ac5e`, parent equal to that earlier
revision. The node fixture file is unchanged across these revisions and
current main: SHA-256
`87a6dc3870308838c58cb1ecfe8ca3f527b941517dcf3735cdf596c2005d06f7`.
Detached comparison worktrees were used, with the same toolchain and a shared
`CARGO_TARGET_DIR=/workspaces/QBIND/olivexo28/QBIND/target`. Cargo rebuilt the
changed workspace crates for each revision.

Delivery identities are supplied by the branch commits: the correction commit
contains the tested source, this package and the plan append; the final
documentation-only seal records its exact commit/tree/parent and publication
checks. Neither commit can embed its own final hash without circularity.

## Demonstrated cause

Baseline locators in `crates/qbind-node/src/binary_consensus_loop.rs`:
fixture construction at 24021-24068, `retain_lower_qc` at 24070-24094, and the
failed assertion at 25189. The fixture has two retained proof carriers:

| Carrier | Verified justification projection | Parent | Own QC |
|---|---|---|---|
| `[0xCC; 32]`, inserted first | Selected higher QC: block `[9; 32]`, view 1 | None | None |
| `[0xDD; 32]`, inserted second | Trigger/lower QC: block `[8; 32]`, view 0 | None | None |

Both QCs have genuine synthetic ML-DSA-44 constituent signatures, verified
under the fixture's proposal/vote domain. A proof carrier is not the block
certified by its justification. The fixture sets the engine lock to the lower
QC, but **never registers its certified block `[8; 32]`**.
Two genuine timeouts from validators 1 and 2 already carry the higher QC;
they are admitted before pressure and remain in the timeout accumulator.

With `max_pending_blocks=2`, legacy insertion of `[0xEE; 32]` creates pressure.
The queue is `[CC, DD, EE]`. The test expects the oldest unrelated carrier CC
to be evicted, losing the selected higher proof but preserving the lower
trigger proof. Before the conservative correction, an absent locked block
ended the ancestry walk without protection; CC was evicted.

Current `hotstuff_state_engine.rs:1102-1189` instead requires a complete,
acyclic protected ancestry ending at a parentless retained node.
`ancestry_excludes_block` starts at absent `[8; 32]` and returns false for
**every** queued candidate. `is_block_safe_to_evict` therefore refuses all
three. Legacy insertion remains insert-then-evict: the queue is exhausted,
the tree has three blocks, no proof was removed, and the eviction counter
stays zero. A subsequent bounded QC lookup would refuse this over-limit
tree, not report a missing selected proof. The failed assertion occurs before
that lookup or the intended formed-TC handler refusal.

This is a **fixture precondition/expectation mismatch**, not evidence of a
production defect in conservative eviction. One exact isolated run passes
before the correction and fails immediately after it; verified main also
fails in isolation. These observations and the source predicate establish
the revision relationship without ordering/concurrency speculation. No
flakiness claim, stress loop, full-suite provenance claim or policy change
is made.

## Smallest supported correction and control

Only the `#[cfg(test)]` library-test region of `binary_consensus_loop.rs`
changes. The affected fixture now has **three slots** and registers the lower
QC's certified block as a synthetic parentless lock root, separately from
both genuine proof carriers. This does not supply or substitute QC evidence.
Pressure still occurs on the fourth insertion. The test asserts full
capacity, complete lock ancestry and safe admission before insertion, then
exactly one eviction, CC absent, the lock root retained, and only the selected
proof missing. It does not merely raise the limit to avoid eviction.

Both inbound and local trigger paths retain their original assertions:
the lower trigger is reverified, the TC selects the higher absent proof and
is refused before view/lock/accumulator-application or NewView publication;
permitted local signing/timeout consumption and pacing remain checked.
Restoring the **same genuinely verified** higher proof permits revalidation,
view advancement, higher lock installation and NewView publication.

The new `run422_f7_retained_qc_missing_locked_block_prevents_eviction`
control preserves the original two-slot/missing-lock state. It requires:
no safe slot admission; typed verified-registration refusal with exact
capacity values and no observed state/accounting mutation; legacy insertion
may exceed capacity but evicts nothing; both original logical justifications
and verified proofs remain retained. Together the two tests distinguish
missing protected ancestry from a complete disjoint lock root.

No production code, safety predicate, ancestry protection, retained-QC
requirement, signature/evidence validation or operational setting changed.
A production compile check was not required because the source delta is
entirely test-only. Existing accepted checks remain closed; no broad audit
or full workspace suite was reopened.

## Exact execution evidence

All Cargo runs use `--locked`, default features (`qbind-node` default is `[]`),
no `--features` or `--all-features`, the workspace test profile (unoptimized,
debug=0, stripped debuginfo, incremental=false), and
`stable-x86_64-unknown-linux-gnu`: rustc 1.99.1
`58cf8f9c35b355199727627d07ae34a4e2846d67`, LLVM 23.1.1; cargo 1.99.1
`5f94df478` (2026-08-27). Host: Ubuntu 24.04.3, x86_64 Linux 6.12.8+,
two available CPUs. Relevant environment is recorded in `inventory.log` and
each control log. RUSTFLAGS, RUST_BACKTRACE, RUST_TEST_THREADS, feature
overrides, LIBCLANG_PATH and ROCKSDB_LIB_DIR were unset. Native comparison
and corrected builds used GCC/G++ 13.3.0 and libclang 18.1.3. Cargo built
bundled RocksDB 8.10.0, not the installed system RocksDB 8.9.1.

The exact isolated Cargo command (all three unmodified revisions and the
corrected fixture):

```sh
cargo test --locked -p qbind-node --lib binary_consensus_loop::tests::run420::run422_d7a::run422_d7c3e::c3f::run422_f7_retained_qc::run422_f7_retained_qc_formed_tc_handlers_refuse_evicted_selected_proof_then_recover -- --exact --nocapture --test-threads=1
```

| Log | Result / exit | Diagnostic purpose |
|---|---|---|
| `base-isolated.log` | Build failure, 101; no test executed | First attempt: missing libclang during zstd-sys bindgen |
| `dependencies.log` | 0; apt emitted an unrelated Chrome index DNS warning | Exact restoration: `sudo -n apt-get update -qq && sudo -n apt-get install -y -qq libclang-dev librocksdb-dev` |
| `base-isolated-restored.log` | One selected, failed 0 vs 1 at 25189; 101 | Exact verified-main reproduction |
| `pre-eviction-isolated.log` | One selected, passed; 0 | Unchanged fixture before conservative correction |
| `post-eviction-isolated.log` | One selected, same assertion failure; 101 | Immediate successor attribution, excluding later voting-ancestry changes |
| `corrected-focused.log` | Build failure E0533, 101; no test executed | New control initially matched a struct variant as a unit variant; corrected to explicit capacity fields |
| `corrected-focused-restored.log` | One selected, passed; 0 | Exact corrected refusal/recovery test, both trigger branches |
| `corrected-c3f.log` | 30 passed; 0 | All C3F retained-QC/ingestion/eviction controls, including new missing-lock control, two threads |
| `corrected-timeout-handlers.log` | 30 passed; 0 | Authenticated Timeout/TC handler regressions, two threads |
| `consensus-regressions.log` | 10 + 7 + 9 + 15 + 28 = 69 passed; 0 | Protected ancestry, memory pressure, locking and TC regressions |
| `consensus-ancestry-unit-controls.log` | Five passed; 0 | Private cardinality, atomic refusal and verified-evidence reclamation controls |
| `default-whitespace-check.log` | 2 | Default Git check treats preserved CRLF as trailing whitespace |
| `crlf-whitespace-check.log` | 0 | `git -c core.whitespace=cr-at-eol diff --check`; no newline conversion or global Git configuration change |
| `staged-raw-whitespace-check.log` | 2 | Staging brought verbatim logs into scope: native/tool output and argv printing contain trailing spaces; commit/push chain stopped before commit |
| `scope-check-staged.log` | 0 | Source/documentation check excludes only verbatim `*.log` artifacts rather than rewriting their bytes |

The directly relevant regression commands:

```sh
cargo test --locked -p qbind-node --lib binary_consensus_loop::tests::run420::run422_d7a::run422_d7c3e::c3f:: -- --nocapture --test-threads=2
cargo test --locked -p qbind-node --lib binary_consensus_loop::tests::run030:: -- --nocapture --test-threads=2
cargo test --locked -p qbind-consensus --test a33_f1_eviction_ancestry_tests --test consensus_state_memory_limits_tests --test hotstuff_state_locking_tests --test hotstuff_locked_block_safety_tests --test m5_timeout_view_change_tests -- --nocapture --test-threads=2
cargo test --locked -p qbind-consensus --lib a33_f1_ -- --nocapture --test-threads=2
```

The corrected focused result is 1/1; regression commands total 134/134,
with the focused case also included in C3F (not 135 unique tests).
Every executed Cargo test command selected at least one test; compile failures
are expressly not passes. Complete combined stdout/stderr, exit codes and
warnings are retained. `run-control.sh` records exact argv, cwd, revision/tree/
parent, dirty status, source-diff hash, toolchain and relevant environment for
the controlled runs. The two initial logs and dependency log precede that
runner; their commands and pinned base are specified above, not inferred from
their bare outputs. Generated logs were copied without editing.

The first commit attempt executed `git add` and then
`git -c core.whitespace=cr-at-eol diff --cached --check`. The latter returned
2 on raw log whitespace, so the chained commit and push did not execute.
The failure was retained by a second explicit staged check. Subsequent
whitespace checks use `-- . ':(exclude)docs/security/evidence/f7-retained-qc-fixture/*.log'`
to exempt only verbatim output, not source, documentation or scripts.

`scope-check.log` and `publication.log` provide byte-preservation and delivery
checks. Historical plan bytes remain a prefix; accepted audit/evidence bytes
and every other previously tracked path are unchanged. Full main has not been
tested or declared green. Only the new task branch is committed/pushed:
no PR, merge, main push, force-push, operational keys, live node/network,
deployment, signing activation or operational activation.

## Publication seal (append-only)

Correction commit: `076df9e90563a6a817e13464bd3abab1347d9c13`.
Correction tree: `3c00b7882180294cf012ae8fbb466349246c403e`.
Correction parent: `01e5731617a1ca2a9894bad4e7c5d54466587c39`.
The correction was committed on the task branch and published with
`git push -u origin copilot/investigate-retained-qc-tc-eviction` (exit 0).
`publication.log` independently confirms the direct remote task tip equals
that commit, direct main remains the expected base, the worktree is clean,
the comparison worktree has been removed, and the accepted-byte/scope checks
pass. It lists every changed path at that correction revision.

This trailing seal and `publication.log` are the only additions after that
tested correction commit. The seal commit is documentation/output-only,
parented directly by the correction commit; the final response and delivery
tool output report its resulting hash/tree and direct remote tip. Publication
uses a normal `git push origin copilot/investigate-retained-qc-tc-eviction`,
not a force-push. Source SHA-256 remains
`c14ec2ee813ea4e318659206f96f647199f1794f394cfda1bd42d0db819aa83d`;
no further test repetition or broader suite is needed for this seal.

**CORRECTION — INDEPENDENT REVIEW PENDING.** Original-run provenance remains
unknown. A33-F1 / E27 and other unresolved obligations remain **OPEN**;
activation **DISABLED**, public DevNet **NO-GO**.
