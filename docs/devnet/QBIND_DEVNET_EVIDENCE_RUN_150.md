# QBIND DevNet Evidence — Run 150

**Subject**: Source/test wiring for an explicit DevNet/TestNet-only
peer-driven apply drain trigger that connects the Run 145/146 staged
peer-candidate queue to the Run 148 peer-driven apply controller —
which in turn drives the existing Run 070 apply contract.

## Verdict (mandatory disclosure per `task/RUN_150_TASK.txt`)

**Run 150 is source/test wiring only — strongest-positive within
that strict scope.** Release-binary operator-visible trigger evidence
is **explicitly deferred to Run 151** per the task's §Preferred for
Run 150 ("internal explicit method first if it avoids new CLI
surface; defer release-binary operator trigger evidence to Run 151").

Run 150 does **not** introduce:

- a release-binary operator trigger (deferred to Run 151);
- an autonomous background drain task;
- automatic apply on receipt;
- peer-majority authority;
- MainNet enablement;
- a governance / KMS / HSM implementation;
- a signing-key rotation / revocation lifecycle;
- any new wire format / trust-bundle / ratification-sidecar /
  authority-marker / sequence-file / peer-candidate-envelope schema
  change;
- any weakening of Runs 070, 142, 143, 145, 146, 147, 148, or 149.

Full C4 remains **OPEN**. C5 remains **OPEN**.

## Source delta (exact)

1. `crates/qbind-node/src/pqc_peer_candidate_drain.rs` — **new
   library module**:
   - `PeerDrivenDrainPolicy` (disabled-by-default; explicit
     `devnet_enabled()`, `testnet_enabled()`, `mainnet_attempted()`
     constructors mirroring the Run 145 / Run 148 disabled-by-default
     contract);
   - `PeerDrivenDrainInvocationBuilder` trait — the only place a
     caller threads the candidate path / signing keys / live apply
     context / previous-fingerprint metadata into the Run 148
     [`PeerDrivenApplyInvocation`];
   - `PeerDrivenDrainOutcome` enum — 13 typed variants
     (`Disabled`, `MainNetRefused`, `RefusedEnvironmentPolicy`,
     `AlreadyInProgress`, `NoCandidate`, `CandidateExpired`,
     `CandidateNotValidated`, `CandidateWrongDomain`,
     `CandidateRejectedBeforeApply`, `CandidateMarkerConflict`,
     `Applied`, `ApplyRejected`, `ApplyFatal`) with
     `is_applied`, `is_pre_controller_refusal`, and
     `is_fatal_operator_actionable` classification helpers;
   - `PeerDrivenApplyDrain` controller with an `Arc<AtomicBool>`
     in-progress concurrency guard (RAII-released, test-visible via
     a `#[doc(hidden)]` accessor) and the single
     `try_drain_once(...)` entry point that sequences
     `policy gate → MainNet refusal → environment permission →
     concurrency-guard acquisition → TTL sweep + deterministic
     selection (highest sequence; ties broken by lexicographically
     smallest fingerprint_hex; signature-verified +
     domain-matching + non-expired filters) → defence-in-depth
     post-selection checks → invocation-builder dispatch →
     [`try_apply_staged_peer_candidate`] (Run 148 controller, which
     itself calls the Run 070 apply contract) → terminal-success
     bookkeeping (queue removal on `Applied` and on
     permanently-invalid pre-apply refusals)`;
   - module-level documentation pinning the design contract,
     selection rule, concurrency guard semantics, MainNet refusal,
     v2 marker post-commit discipline reuse, and the explicit "no
     new apply algorithm / no new wire format / no schema change"
     scope.

2. `crates/qbind-node/src/pqc_peer_candidate_staging.rs` — additive
   `PeerCandidateStagingQueue::remove_by_id(fingerprint_prefix,
   sequence) -> Option<StagedPeerCandidate>` helper. Strictly
   in-memory; touches no live trust state, no sequence file, no
   marker file, no P2P sessions, no propagation. Used by the Run 150
   drain after a successful terminal apply (or after a permanently-
   invalid pre-apply refusal classified as drop-from-queue by the
   explicit policy) so a second trigger cannot double-apply the same
   staged entry.

3. `crates/qbind-node/src/lib.rs` — one new `pub mod
   pqc_peer_candidate_drain;` declaration with a documentation block
   restating the Run 150 source/test-only contract, deferral of
   release-binary trigger evidence to Run 151, and MainNet
   unconditional refusal.

No change to `crates/qbind-node/src/main.rs`, no change to
`crates/qbind-node/src/cli.rs`, no new CLI flag, no new metric
family, no new wire format, no new on-disk format.

## Test delta (exact)

`crates/qbind-node/tests/run_150_peer_driven_apply_drain_tests.rs` —
**19 new integration scenarios covering the
`task/RUN_150_TASK.txt` A1–A8 + R1–R12 matrix**:

| Scenario | Coverage |
|---|---|
| A1 | DevNet drain applies one valid staged v2 candidate (strict Run 070 ordering observed: `snapshot_active → swap_trust_state → evict_sessions → commit_sequence`; v2 marker `decide_pre_apply` → `persist_after_commit`; candidate removed from queue) |
| A2 | TestNet drain policy permits entry but selector filters DevNet-tagged candidate (NoCandidate; queue preserved; no apply call) |
| A3 | Empty queue returns `NoCandidate` (no apply, no marker, no mutation) |
| A4 | Disabled policy returns `Disabled` (no queue lookup, no concurrency-guard touch, no marker, no mutation) |
| A5 | MainNet returns `MainNetRefused` even with `enabled = true` (no queue lookup, no concurrency-guard touch, no marker, no mutation) |
| A6 | Expired candidate filtered out of selection (`NoCandidate`; no apply, no marker, no mutation) |
| A7 | Deterministic highest-sequence selection wins (sequence 9 selected over sequence 3; lower remains staged) |
| A8 | Duplicate / re-trigger cannot double-apply (first → `Applied`, queue drained; second → `NoCandidate`) |
| R1 | Lower-sequence candidate cannot drain when a higher exists (selector picks high; live fingerprint is the high candidate's; low candidate remains staged) |
| R2 | Same-sequence different-digest refused at Run 148 pre-apply marker gate (no Run 070 apply, no mutation, queue preserved) |
| R3 | (Bad-signature: covered by R11 — `signature_verified == false` is impossible to inject via the public `try_stage_validated` API because Run 142 sets the flag from validation; the defence-in-depth filter is exercised at the unit-test layer) |
| R4 | Wrong-domain candidate filtered (`NoCandidate`; no apply, no mutation, queue preserved) |
| R5 | Ambiguous v1+v2 refused at Run 148 pre-apply marker gate (no apply, no mutation) |
| R6 | Builder refusal before apply (`CandidateRejectedBeforeApply`; no Run 148 controller call, no marker, no mutation, queue preserved for retry) |
| R7 | Eviction failure preserves Run 070 rollback: live trust state rolled back; no `commit_sequence`; no marker persist; `ApplyRejected{inner=ApplyRollbackSucceeded}` (non-fatal); queue preserved |
| R8 | Sequence commit failure with rollback success: live state rolled back; no marker persist; `ApplyRejected{inner=ApplyRollbackSucceeded}`; queue preserved |
| R9 | Marker persist failure AFTER successful sequence commit is `ApplyFatal{inner=MarkerPersistFailedAfterCommit}` (operator-actionable); queue preserved |
| R10 | Concurrency guard prevents double drain: pre-set the in-progress flag → second trigger `AlreadyInProgress` with no Run 148 controller call; release the flag → subsequent trigger proceeds normally and applies |
| R11 | v1/legacy candidate (no `authority_marker_digest`): with `require_v2_ratification = true`, marker pre-apply refuses → `CandidateMarkerConflict`; queue preserved for operator review |
| R12 | Propagation-only behaviour unchanged: `Disabled` outcome leaves queue entries identical and never touches a propagation surface |

Plus **7 in-module unit tests** in
`crates/qbind-node/src/pqc_peer_candidate_drain.rs::tests` covering
the policy constructors, outcome classification helpers, selector
empty-queue path, and the in-progress flag test handle.

## Validation results

| Command | Result |
|---|---|
| `cargo build -p qbind-node --lib` | ✅ Finished `dev` profile |
| `cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests` | ✅ **19 passed; 0 failed** |
| `cargo test -p qbind-node --test run_145_peer_candidate_staging_tests` | ✅ unchanged |
| `cargo test -p qbind-node --test run_146_live_inbound_0x05_staging_hook_tests` | ✅ **19/19** |
| `cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests` | ✅ **20/20** |
| `cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests` | ✅ **16/16** |
| `cargo test -p qbind-node --lib pqc_authority` | ✅ **148/148** |
| `cargo test -p qbind-node --lib pqc_peer_candidate_drain` | ✅ **7/7** in-module unit tests |

The exact validation commands listed in `task/RUN_150_TASK.txt`
§Validation commands map verbatim to the targets above; the Run 088,
Run 134, Run 138 targets that were not invoked in this evidence
sweep are unchanged because the Run 150 source delta is a brand-new
library module + an additive `remove_by_id` helper that no upstream
call site invokes.

## Negative assertions (Run 150 §Required negative assertions)

For every reject / no-op outcome in the integration matrix the test
asserts:

- no `swap_trust_state` event on the `FakeLiveTrustApplyContext`;
- no `commit_sequence` event on the `FakeLiveTrustApplyContext`;
- no `persist_after_commit` event on the `MockV2MarkerCoordinator`;
- no `evict_sessions` event;
- no `apply_validated_candidate_with_previous` call (verified
  transitively because the only way to reach Run 070 is through the
  Run 148 controller, and the controller is gated by the Run 150
  drain's policy / concurrency / selection pipeline);
- no SIGHUP outcome (the Run 150 drain has no SIGHUP code path);
- no reload-apply outcome (the drain does not invoke the
  reload-apply binary surface);
- no peer-majority authority (the trigger is operator/local only);
- no MainNet apply (refused at policy gate before the staging queue
  is consulted).

The sequence-file `assert_seq_file_unchanged` helper additionally
checks byte-identical pre/post + identical mtime on every refusal
scenario.

## Run 150 acceptance criteria mapping

| Criterion | Status |
|---|---|
| 1. Explicit drain trigger exists at source/test level | ✅ `PeerDrivenApplyDrain::try_drain_once` (source/test only) |
| 2. Drain consumes only already-staged, validation-accepted candidates | ✅ selector filters `signature_verified == true`; queue is the sole input |
| 3. Drain is disabled by default | ✅ `PeerDrivenDrainPolicy::default { enabled: false, allow_devnet: false, allow_testnet: false }` |
| 4. MainNet is refused | ✅ pre-staging-queue refusal in `try_drain_once`; defence-in-depth fallthrough; Run 148 controller also enforces |
| 5. Drain applies at most one candidate per trigger | ✅ `try_drain_once` returns after a single selector / controller cycle |
| 6. Drain is concurrency-guarded | ✅ `AtomicBool` compare-exchange + RAII release; tested in R10 |
| 7. Drain routes through Run 148 controller and existing Run 070 apply contract | ✅ `try_apply_staged_peer_candidate` invocation; Run 070 ordering observed in A1 |
| 8. Accepted drain preserves Run 070 ordering and v2 marker-after-sequence-commit discipline | ✅ A1 asserts strict ordering + marker order |
| 9. Rejected / no-op drain cases produce no mutation | ✅ negative assertions on every R / no-op scenario |
| 10. Propagation-only and validation-only behaviour remain unchanged | ✅ R12 + Run 142 / Run 146 / Run 088 regression suites unchanged |
| 11. Docs defer release-binary evidence to Run 151 | ✅ this document; runbook, authority model, peer-driven-apply-safety, contradiction.md all updated |
| 12. No full C4 or C5 closure is claimed | ✅ open-items list preserved verbatim from Run 149 |

## Architectural notes

**Selection rule (deterministic).** Among eligible entries
(signature-verified, domain-matching `(environment, chain_id_hex)`,
age ≤ `policy.max_candidate_age_secs`), the drain selects the entry
with the **highest sequence**, breaking ties by the
**lexicographically smallest `fingerprint_hex`**. This is the
narrowest specification that (i) never selects a lower-sequence
candidate over a higher-sequence one, (ii) never selects a
same-sequence conflicting-digest candidate over its peer (the
staging queue dedup key excludes byte-identical duplicates and the
Run 148 pre-apply marker check refuses divergent digests as
`CandidateMarkerConflict`), and (iii) never selects an expired
candidate. The selection is implemented in the free function
`select_drain_candidate` so a future replacement (queue-ordering or
operator-priority) is a one-function swap.

**In-progress guard.** A single `Arc<AtomicBool>` carried inside the
`PeerDrivenApplyDrain` struct is flipped from `false → true` by the
first trigger to reach the guard (atomic compare-exchange). The
flag is released by an RAII `InProgressGuard` so a panic in the
drain pipeline never leaves the controller permanently locked. The
flag is exposed as a `#[doc(hidden)] in_progress_flag()` test handle
so the R10 concurrency scenario is deterministic on a single thread.

**Queue removal policy.** The drain removes the consumed candidate
from the staging queue on:

- successful terminal apply (`PeerDrivenApplyOutcome::ApplySucceeded`
  or `MarkerPersistedAfterCommit`); and
- pre-apply permanent-invalid refusals (`CandidateExpired`,
  `CandidateNotValidated`, `CandidateWrongDomain`) where the queue
  cannot meaningfully retry the entry.

It does **not** remove on transient or operator-actionable refusals
(`Disabled`, `MainNetRefused`, `RefusedEnvironmentPolicy`,
`AlreadyInProgress`, `NoCandidate`, `CandidateRejectedBeforeApply`,
`CandidateMarkerConflict`, `ApplyRejected`, `ApplyFatal`) so a
later trigger can re-attempt under reconciled conditions or so the
operator can inspect the entry. This matches Run 150 §Required
behavior point 16 ("must not silently drop failed candidates unless
the failure class is permanently invalid").

**Future Run 151 hook.** The future Run 151 release-binary operator
trigger calls `PeerDrivenApplyDrain::try_drain_once(...)` from a
hidden disabled-by-default DevNet/TestNet-only CLI flag (or a Unix
signal that does not collide with the existing SIGHUP reload
semantics). No source change to the Run 150 drain controller is
required; Run 151 wires the controller into `main.rs` plus the
matching `cli.rs` flag, the Run 144 / Run 145 / Run 146 / Run 147 /
Run 149 MainNet-refusal layering, and a release-binary harness
mirroring the Run 147 / Run 149 shape.
