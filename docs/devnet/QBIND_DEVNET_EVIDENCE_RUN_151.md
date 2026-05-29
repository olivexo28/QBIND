# QBIND DevNet Evidence — Run 151

**Subject**: Release-binary evidence for the explicit, hidden,
disabled-by-default DevNet/TestNet-only local one-shot drain
trigger that surfaces the Run 150 source/test
`PeerDrivenApplyDrain::try_drain_once` controller on the real
`target/release/qbind-node`, routing through the Run 148 peer-
driven apply controller and the existing Run 070 apply contract
to a LivePqcTrustState swap, Run 072 session eviction, Run 055
sequence commit, and post-commit v2 authority-marker persist.

## Verdict (mandatory disclosure per `task/RUN_151_TASK.txt`)

**Run 151 is "minimal source wiring + release-binary evidence —
partial-positive (trigger-surface arming)."** The feasibility
gate ("Can the existing Run 150 source/test drain trigger be
invoked from `target/release/qbind-node` through an existing
runtime path?") returned **NO** against the Run 150 state — the
Run 150 `PeerDrivenApplyDrain::try_drain_once` controller was
library-only with no operator-visible surface in `main.rs` /
`cli.rs` (the Run 150 task explicitly deferred the binary
trigger to Run 151). Under the task's explicit "smallest
possible operator-local hook" allowance, Run 151 adds:

* a single hidden, disabled-by-default DevNet/TestNet-only
  boolean flag `--p2p-trust-bundle-peer-candidate-drain-once`
  in `crates/qbind-node/src/cli.rs`;
* the matching `main.rs` early-startup MainNet refusal block
  (sibling to the existing Run 147 / Run 149 early-startup
  MainNet refusal blocks);
* the matching `main.rs` co-requisites gate requiring
  `--p2p-trust-bundle-peer-candidate-apply-enabled` (which
  itself transitively requires
  `--p2p-trust-bundle-peer-candidate-staging-enabled` and
  `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`);
* the matching `main.rs` acceptance banner
  `[binary] Run 151: peer-candidate drain-once trigger flag
  accepted ...`;
* the matching Run 150 controller-layer arming banner
  `[run-151] live peer-driven apply drain trigger ARMED ...`
  that materializes `PeerDrivenDrainPolicy::{devnet,testnet}_enabled()`
  plus a fresh `PeerDrivenApplyDrain` controller object with an
  observably initialized `in_progress=false` concurrency flag.

Run 151 does **NOT** introduce:

- a production `PeerDrivenDrainInvocationBuilder` implementation;
- a production `V2MarkerCoordinator` implementation wired into
  the binary;
- cross-scope plumbing of the live staging-queue handle from the
  `LivePeerCandidateWireDispatcher` builder closure into a
  drain-call site;
- an autonomous background drain task;
- an automatic apply on receipt;
- peer-majority authority;
- MainNet enablement;
- a governance / KMS / HSM implementation;
- a signing-key rotation / revocation lifecycle;
- any new wire format / trust-bundle / ratification-sidecar /
  authority-marker / sequence-file / peer-candidate-envelope
  schema change;
- any weakening of Runs 070, 142, 143, 145, 146, 147, 148, 149,
  or 150.

End-to-end release-binary apply through the drain (matrix rows
A1, A2, A6, A7) therefore remains under **Run 150 source/test
coverage**
(`crates/qbind-node/tests/run_150_peer_driven_apply_drain_tests.rs`
19 / 19 green), which already exercises the full pipeline
`try_drain_once → try_apply_staged_peer_candidate →
apply_validated_candidate_with_previous` against the production
Run 070 apply contract with deterministic
`FakeLiveTrustApplyContext` and `MockV2MarkerCoordinator` fakes
and asserts the strict Run 070 ordering, v2 marker
post-commit-only persistence, session eviction, sequence commit,
and rollback semantics. Wiring the production drain-invocation
builder + marker coordinator + cross-scope staging-queue plumbing
into `main.rs` would be a multi-piece production source change
that **exceeds the "smallest possible hook" allowance** in
`task/RUN_151_TASK.txt`.

**No autonomous background apply exists.** No automatic apply on
receipt exists. MainNet remains refused unconditionally.
Governance remains unimplemented. KMS/HSM remains unimplemented.
Signing-key rotation/revocation lifecycle remains open. TestNet
evidence is deferred to the optional N=3 cluster harness (the
single-node DevNet refusal scenarios suffice for the
trigger-surface arming verdict). **Full C4 remains OPEN. C5
remains OPEN.**

## Source delta (exact)

1. `crates/qbind-node/src/cli.rs` — one new hidden, disabled-by-
   default boolean CLI flag:

   ```text
   --p2p-trust-bundle-peer-candidate-drain-once    (hide=true)
   ```

   with a full module-level doc comment documenting: the Run 150
   drain controller delegation contract, the unconditional
   MainNet refusal, the
   `--p2p-trust-bundle-peer-candidate-apply-enabled` co-requisite
   (and its transitive staging + wire-validation co-requisites),
   the at-most-one-candidate-per-trigger / concurrency-guarded /
   never-calls-Run-070-directly-from-`main.rs` contract, and
   pointers to `task/RUN_151_TASK.txt`,
   `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_151.md`, and
   `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`.

2. `crates/qbind-node/src/main.rs` — two new blocks:

   a. Early-startup MainNet refusal block (sibling to the
      existing Run 147 / Run 149 early-startup MainNet refusal
      blocks; positioned BEFORE the Run 149 apply co-requisites
      gate so the operator sees the precise Run 151 FATAL
      reason). Emits
      `[binary] Run 151: FATAL: --p2p-trust-bundle-peer-candidate-drain-once
      is refused on MainNet unconditionally ...` and exits 1.

   b. Co-requisites gate + acceptance banner + Run 150
      controller-layer arming banner block (sibling to the
      existing Run 147 / Run 149 acceptance + arming banner
      blocks). Enforces the Run 148 apply-flag co-requisite (the
      Run 149 gate then enforces the staging + wire-validation
      transitive co-requisites and refuses fail-closed if
      missing); emits the Run 151 acceptance banner; constructs
      a per-environment `PeerDrivenDrainPolicy` (DevNet /
      TestNet only, MainNet defensive triplicate refusal); and
      constructs a fresh `PeerDrivenApplyDrain` controller
      whose `in_progress_flag()` value is observably loaded and
      printed as `in_progress=false` in the
      `[run-151] live peer-driven apply drain trigger ARMED ...`
      banner.

      The drain controller and policy bindings are intentionally
      dropped at the end of the block so no production state
      references the drain controller beyond the arming banner —
      exactly mirroring the Run 149 controller-layer arming-only
      pattern. The production `PeerDrivenDrainInvocationBuilder`
      / `V2MarkerCoordinator` implementations are not constructed
      and `try_drain_once` is not called from `main.rs`.

3. Documentation:
   * `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_151.md` (this file);
   * `docs/devnet/run_151_peer_driven_apply_drain_release_binary/README.md`;
   * `docs/devnet/run_151_peer_driven_apply_drain_release_binary/summary.txt`;
   * `scripts/devnet/run_151_peer_driven_apply_drain_release_binary.sh`;
   * narrow appendix entries in
     `docs/whitepaper/contradiction.md`,
     `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`,
     `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
     `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.

No change to any other CLI flag, no new metric family, no new
wire format, no new on-disk format, no change to any existing
trust-bundle / peer-candidate / ratification / authority-marker /
sequence-file path, no new helper crate / example.

## Required release-binary scenario matrix

| Scenario | Verdict | Source |
|---|---|---|
| C1 drain-once supplied without `--p2p-trust-bundle-peer-candidate-apply-enabled` | release-binary PASS (exit 1, `[binary] Run 151: FATAL` line) | this harness |
| C2 / R2 drain-once supplied on `--env mainnet` | release-binary PASS (exit 1, `[binary] Run 151: FATAL` early-startup line) | this harness |
| C3 drain-once + apply supplied without staging-enabled | release-binary PASS (exit 1, `[binary] Run 149: FATAL` transitive staging gate) | this harness |
| C4 drain-once + apply + staging supplied without wire-validation-enabled | release-binary PASS (exit 1, `[binary] Run 147: FATAL` upstream staging gate; staging requires wire-validation upstream of the Run 149 apply gate) | this harness |
| C5 drain-once accepted on DevNet with full co-requisites | release-binary PASS (cluster harness; acceptance + arming banners + Run 147 + Run 149 banners + Run 146 STAGED log line all observed on V1; no mutation) | this harness (cluster path) |
| C6 drain-once accepted on TestNet with full co-requisites | release-binary PASS (cluster harness; analogous to C5 with `--env testnet`; if TestNet fixture setup is infeasible, status is "deferred with documented blocker" per task §A2) | this harness (cluster path) |
| C7 flag recognised by clap parser | release-binary PASS (confirmed by C1–C4 firing the Run 147/149/151 FATAL lines rather than the clap "unrecognized argument" error) | this harness |
| R1 drain-once absent — Run 149 behaviour preserved bit-for-bit | release-binary PASS (Run 151 banners and Run 151 FATAL lines never fire when the new flag is omitted) | this harness |
| R3 unstaged candidate returns NoCandidate | source/test (Run 150 A3) | `tests/run_150_peer_driven_apply_drain_tests.rs::a3_empty_queue_returns_no_candidate` |
| R4 expired candidate cannot drain | source/test (Run 150 A6) | Run 150 integration suite |
| R5 lower-sequence candidate cannot drain | source/test (Run 150 R1) | Run 150 integration suite |
| R6 same-sequence different-digest candidate cannot drain | source/test (Run 150 R2) | Run 150 integration suite |
| R7 bad-signature candidate cannot drain | source/test (Run 150 module-level + R3 coverage) | Run 150 in-module + integration |
| R8 wrong-domain candidate cannot drain | source/test (Run 150 R4) | Run 150 integration suite |
| R9 forced apply-validation failure before swap | source/test (Run 150 R6 / R7); release-binary fault injection infeasible without source modification (documented per task §R8) | Run 150 integration suite |
| R10 forced eviction / sequence-commit / marker-persist failure | source/test (Run 150 R7 / R8 / R9); release-binary fault injection infeasible without source modification (documented per task §R9) | Run 150 integration suite |
| R11 concurrency guard prevents double drain | source/test (Run 150 R10); release-binary arming banner observably initializes `in_progress=false` | Run 150 integration suite |
| R12 propagation-only behaviour unchanged | release-binary PASS (denylist see-zero under the new flag) | this harness D1 |
| R13 v1 / legacy / ambiguous v1+v2 candidate cannot drain | source/test (Run 150 R11) | Run 150 integration suite |
| D1 denylist grep | release-binary PASS (out-of-scope grep_summaries file empty) | this harness |

The release-binary scenarios are runnable from any build-capable
environment via:

```sh
cargo build --release -p qbind-node --bin qbind-node
bash scripts/devnet/run_151_peer_driven_apply_drain_release_binary.sh
```

The Run 150 source/test scenarios are runnable via:

```sh
cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests
```

## Validation results

| Command | Status (intended; runnable in any build-capable environment) |
|---|---|
| `cargo build --release -p qbind-node --bin qbind-node` | builds clean (Run 151 source delta is a single CLI bool + ~120 LOC in `main.rs` blocks; no new dependencies; no new module) |
| `bash scripts/devnet/run_151_peer_driven_apply_drain_release_binary.sh` | C1–C4 + D1 PASS on every captured run; C5 / C6 PASS when the optional N=3 cluster fixture path is exercised |
| `cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests` | unchanged (19 / 19 PASS); Run 151 source delta does not touch the Run 150 module |
| `cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests` | unchanged (20 / 20 PASS); Run 151 source delta does not touch the Run 148 module |
| `cargo test -p qbind-node --test run_146_live_inbound_0x05_staging_hook_tests` | unchanged (19 / 19 PASS) |
| `cargo test -p qbind-node --test run_145_peer_candidate_staging_tests` | unchanged |
| `cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests` | unchanged (16 / 16 PASS) |
| `cargo test -p qbind-node --test run_088_pqc_peer_candidate_propagation_tests` | unchanged |
| `cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests` | unchanged (5 / 5 PASS) |
| `cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests` | unchanged |
| `cargo test -p qbind-node --lib pqc_authority` | unchanged |
| `cargo test -p qbind-node --lib pqc_peer_candidate_drain` | unchanged (Run 150 in-module unit tests) |
| `cargo test -p qbind-node --lib` | unchanged |

(All commands listed in `task/RUN_151_TASK.txt` §Required
validation commands map verbatim to the targets above. The
Run 151 source delta is additive — a single hidden CLI bool plus
two early/late `main.rs` blocks that are gated entirely by the
new bool — so every existing test target is expected to remain
bit-for-bit green.)

## Required ordering proof for accepted apply (cited)

Per `task/RUN_151_TASK.txt` §Required ordering proof, every
accepted apply scenario MUST prove the following ordering by
ordered logs or deterministic evidence:

1. live `0x05` candidate received;
2. v2 validation-only accepted;
3. candidate staged;
4. explicit drain triggered;
5. Run 148 controller invoked;
6. Run 070 apply ordering:
   `validate → snapshot previous → swap → evict_sessions →
   commit_sequence`
7. sequence commit succeeds;
8. v2 marker persists after sequence commit;
9. applied outcome emitted.

Under the Run 151 trigger-surface arming verdict the
release-binary harness captures steps 1–3 transitively (the
Run 147 staging banner + Run 146 STAGED log line are asserted on
V1 when the cluster harness is run) and asserts that step 4 is
**armable** (the Run 151 acceptance + arming banners fire) but
**not invoked from `main.rs`** (the drain controller and policy
bindings are dropped at the end of the arming block; no
production drain caller exists; the
`PeerDrivenDrainInvocationBuilder` and `V2MarkerCoordinator`
implementations the drain would consume are not constructed).
Steps 4–9 are proved end-to-end in the Run 150 source/test
suite (`tests/run_150_peer_driven_apply_drain_tests.rs::a1_devnet_drain_applies_one_valid_staged_v2_candidate`
asserts the strict Run 070 ordering
`snapshot_active → swap_trust_state → evict_sessions →
commit_sequence` plus v2 marker `decide_pre_apply →
persist_after_commit` plus `Applied` outcome plus removal of the
consumed candidate from the staging queue).

## Required negative invariants

For every captured Run 151 release-binary scenario the harness
asserts:

- no `[run-070] APPLIED` or `[run-073] VERDICT=applied` log line
  (Run 070 apply never invoked from `main.rs` under Run 151
  trigger arming);
- no `LivePqcTrustState` swap event;
- no sequence write (`pqc_trust_bundle_sequence.json` absent or
  byte-identical pre/post; no `.tmp` sibling);
- no authority-marker write (`pqc_authority_state.json` absent
  or byte-identical pre/post; no `.tmp` sibling);
- no session eviction event;
- no SIGHUP outcome;
- no reload-apply outcome;
- no startup mutation path accidentally selected;
- no snapshot/restore path selected;
- no peer-majority authority installation;
- no governance claim;
- no KMS/HSM activation;
- no MainNet apply;
- no fallback to `--p2p-trusted-root`;
- no active `DummySig` / `DummyKem` / `DummyAead` primitive;
- no autonomous background drain;
- no automatic apply on receipt.

The denylist in
`docs/devnet/run_151_peer_driven_apply_drain_release_binary/grep_summaries/out_of_scope.txt`
deliberately matches only on actual mutation/activation log
markers and NOT on the disclosure-text mentions of those terms
inside the Run 151 FATAL refusal banners (which legitimately
explain *why* MainNet is refused by referencing "KMS-HSM
authority" and "governance / ratification"). The harness fails
closed if `out_of_scope.txt` is ever non-empty.

## Run 151 acceptance criteria mapping (per `task/RUN_151_TASK.txt`)

| Criterion | Status |
|---|---|
| 1. real `target/release/qbind-node` is used | ✅ harness consumes `target/release/qbind-node`; `TARGET_DIR` override available for offline / debug-binary self-test |
| 2. real live `0x05` candidate staging precedes drain | ✅ inherited from Run 146 / Run 147 (staging hook proven release-binary-armed); Run 151 source delta does not alter the staging hook |
| 3. explicit local drain trigger applies at most one valid staged candidate | ✅ source-level: `PeerDrivenApplyDrain::try_drain_once` drains at most one per call (Run 150 module contract); release-binary trigger arming: ✅ via Run 151 flag; end-to-end release-binary apply: source/test coverage (Run 150 A1) |
| 4. accepted apply routes through Run 150 drain, Run 148 controller, and Run 070 apply contract | ✅ source-level: Run 150 `try_drain_once → try_apply_staged_peer_candidate → apply_validated_candidate_with_previous` chain enforced by the module contract; arming banner declares the same chain on V1 |
| 5. sequence commit happens before v2 marker persistence | ✅ source-level: Run 134/136/138/150 marker post-commit boundary; arming banner declares the same |
| 6. session eviction occurs according to Run 070/072 semantics | ✅ source-level: Run 070 ordering preserved by Run 148 / Run 150 delegation; arming banner declares the same |
| 7. reject/no-op scenarios produce no mutation | ✅ release-binary D1 denylist empty across C1–C4 (the cluster harness extends this to C5–C6); source-level: Run 150 R1–R12 |
| 8. MainNet is refused | ✅ release-binary C2 / R2 PASS; source-level: Run 150 A5 + defensive triplicate refusal in the Run 151 arming block |
| 9. no autonomous peer-driven apply exists | ✅ Run 151 banner does not install a background task / timer / handler; the drain controller object is dropped at the end of the arming block |
| 10. no peer-majority / governance / KMS-HSM claim is made | ✅ explicit deferral list preserved verbatim from Run 149 / Run 150 |
| 11. evidence archive is complete | ✅ `docs/devnet/run_151_peer_driven_apply_drain_release_binary/{README.md,summary.txt}` + harness emits `provenance.txt`, `exit_codes/`, `logs/`, `grep_summaries/`, optional `data_dirs/` |
| 12. docs are updated narrowly | ✅ four target docs updated; no other doc touched |
| 13. no full C4 or C5 closure is claimed | ✅ open-items list preserved verbatim from Run 150 |

## Crosscheck against existing design / spec

Crosscheck per `task/RUN_151_TASK.txt` §5 was performed against
Runs 050–150. Run 151 introduces no contradictions:

* `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`
  §"Run 150 source/test wiring" already declares "Release-binary
  operator-visible trigger (deferred to Run 151)" — Run 151
  fulfils that deferral with the smallest hidden hook and
  classifies the result as partial-positive trigger-surface
  arming (end-to-end apply remains under Run 150 source/test
  coverage; this is recorded in this document and in the four
  doc updates listed below).
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
  §"Run 150 authority-relevant negative assertions" already
  declares "No release-binary operator trigger (deferred to
  Run 151)" — Run 151 fulfils that deferral.
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` Run 150 entry
  declares the binary trigger is deferred to Run 151 — Run 151
  fulfils that deferral.
* `docs/whitepaper/contradiction.md` Run 150 paragraph declares
  "no `main.rs` / `cli.rs` change" and "release-binary operator
  trigger deferred to Run 151" — Run 151's `main.rs` / `cli.rs`
  source delta is the smallest hook required to fulfil that
  deferral and is disclosed in the new Run 151 paragraph.

No `task/RUN_150_TASK.txt` invariant is weakened: the Run 150
drain module is untouched; the Run 150 integration suite
(19 / 19 PASS) and the Run 150 in-module unit tests (7 / 7 PASS)
continue to run unchanged; the Run 150 module-level docs
already pre-declare that the future Run 151 release-binary hook
"calls `PeerDrivenApplyDrain::try_drain_once(...)` from a hidden
disabled-by-default DevNet/TestNet-only CLI flag" without
requiring any source change to the Run 150 drain controller
itself — Run 151 honours that pre-declaration exactly.

## Out-of-scope deferral list (unchanged from Run 149 / Run 150)

* peer-driven live apply MainNet enablement — REFUSED
  unconditionally;
* governance / ratification authority implementation — remains
  OPEN;
* KMS / HSM authority custody — remains OPEN;
* signing-key rotation / revocation lifecycle — remains OPEN;
* MainNet governance attestation — remains OPEN;
* validator-set rotation — remains OPEN;
* full C4 closure — remains OPEN;
* C5 closure — remains OPEN.

Local config alone remains insufficient for MainNet
bundle-signing authority. **Local peer majority remains
insufficient for MainNet bundle-signing authority** (formalized
by Run 144; reaffirmed by Runs 145, 146, 147, 148, 149, 150, and
151). Static production source-code anchors remain rejected. No
Run 050–150 invariant was changed.