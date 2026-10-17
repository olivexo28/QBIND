# RUN 422 — Safety-Decision Observer Spike — Revision 1 (Published Evidence)

This directory publishes the **corrected** experimental evidence for the Run 422
§13.6 safety-decision observer spike. It **corrects the experimental observer
published at commit `881bbb9d…`** (the original package in the parent directory,
"revision 0"), whose patch targets the same baseline
`0de4df69cf55a05e88baff50733ffa578cdf171e`.

It remains an **isolated feasibility experiment**: the observer implementation is
**not** landed, **not** wired into accepted source, and **not** applied to this
branch. Only this evidence directory is published. **The original package in the
parent directory is preserved unchanged.**

**§13.6 engine-decision binding remains INCOMPLETE.** The spike *observes* the
real safety decision; it does not *bind* a decision to a durable generation, does
not associate the decision with the outbound action, and establishes no
D10/signing prerequisite. Accepted storage stays **CLOSED**. Activation remains
**DISABLED**; public DevNet remains **NO-GO**.

## Why a revision

Review of the published observer found two public-API gaps and three evidence
weaknesses. This revision closes them:

### 1. Ancestry access was too wide

`SafetyDecisionView::for_each_ancestor` previously handed the callback a
`&BlockNode`. `BlockNode` has public `justify_qc`/`own_qc`
(`QuorumCertificate`) fields and a `verified_justification: Option<Arc<…>>`, so a
caller could clone a certificate `Arc` — or the whole node — out of the callback.
Ancestry inspection now yields an **opaque `SafetyAncestorView`** exposing only
identifiers, the parent relationship, and `Copy` scalar fields. There is no
accessor that returns an owned `QuorumCertificate`, an evidence `Arc`, or the raw
`BlockNode`. Bounded traversal and the voting rule are unchanged.

Two doctests on `SafetyDecisionObserver` make the boundary executable: a
`compile_fail` **external-API** example (`CertThief`) proving a certificate cannot
be cloned out of an ancestor, plus a **valid-use control** that reads only the
opaque scalar identifiers. A runtime test
(`opaque_ancestor_view_exposes_only_scalars_and_identifiers`) exercises every
scalar accessor.

### 2. A silent observation omission

With `max_pending_blocks == 0`, `register_block` evicts the candidate it just
registered; the `NoLock` safety predicate then succeeds **without reading the
block**, so the observation input (the candidate) is absent at the observation
point. The earlier revision silently skipped observation and **self-voted
anyway**. On the opt-in **observed** route this is now **explicit**: when the
observation input is missing the engine refuses to self-vote and returns no
action — *before* the self-vote or `BroadcastVote`. The route therefore never
casts a vote that was not observed ("observe and vote, or do neither").

The **unobserved legacy route is unchanged** — it still votes in exactly this
scenario — and the safety predicate is untouched. No bootstrap authorization
policy is introduced. The paired tests
(`observed_route_makes_missing_observation_input_explicit`,
`unobserved_legacy_route_still_votes_when_candidate_evicted`) assert the callback
count, the absence of dependent voting (no `BroadcastVote`; the single-validator
self-vote would otherwise have formed a QC and set the lock), and precisely which
earlier mutations remain (the candidate was registered then evicted — block tree
empty, eviction counter advanced by exactly one; no vote-derived state).

### 3. Tightened evidence

- The observed-vs-legacy test now compares the **complete outgoing `Vote`** (every
  field), not merely the action variant.
- The callback-panic test now requires the **expected observer panic payload** and
  rejects unrelated panics (e.g. an engine assertion that would also unwind).
- The post-operation `Arc::strong_count` assertion is documented as an **endpoint
  (before/after) retention check**: it does **not** detect temporary clones during
  the call and does **not** measure heap allocation.

## Contents

- `patch/run_422_safety_decision_observer_spike.patch` — the complete, applyable
  corrected patch against baseline `0de4df69…`, including the new test file. No
  abbreviated hunks or omitted bodies. LF line endings.
- `logs/` — raw execution logs (see "Reproduced vs. inherited" below).
- `MANIFEST.txt` — baseline, changed experimental paths, execution dates, hashes.
- `SHA256SUMS.txt` — checksums for every file in this directory (except itself).
- `BASELINE.txt` — the baseline commit hash.

## Applying the patch (for reviewers)

    git worktree add --detach /tmp/obs 0de4df69cf55a05e88baff50733ffa578cdf171e
    cd /tmp/obs
    git apply docs/.../revision_1/patch/run_422_safety_decision_observer_spike.patch
    cargo test -p qbind-consensus --test run_422_safety_decision_observer_spike_tests
    cargo test -p qbind-consensus --doc        # includes the compile_fail escape controls

The patch reproduces the four changed files byte-for-byte on the clean baseline;
their post-edit content hashes are recorded in `MANIFEST.txt` and were re-derived
in `logs/05_patch_apply_verify.log`.

## Reproduced results vs. inherited

This distinction is deliberate and must not be blurred:

- **Newly executed 2026-10-17 (this revision):** every log under `logs/`
  (`01_build.log`, `02_observer_tests.log`, `03_doctests.log`,
  `04_consensus_lib_regression.log`, `05_patch_apply_verify.log`) is the output of
  a **fresh execution for this revision**, each labelled `## NEWLY EXECUTED` in its
  header. They cover: the `qbind-consensus` compile, the 12 focused observer tests,
  the 7 doctests (including the 2 `compile_fail` escape controls and 2 valid-use
  controls), the 183-test `qbind-consensus` library regression, and clean patch
  application + source-hash reproduction on a pristine baseline.
- **Inherited / NOT re-run here:** the original revision-0 package's logs
  (`../logs/`) are its own earlier runs and are not reproduced here. The full
  `qbind-node` build and broader cross-crate consensus regressions were **not**
  re-executed for this revision (they are unaffected: the spike is isolated and
  not wired into accepted source). Request a fresh run explicitly if those are
  needed. No file in this directory is presented as a revision-0 log.

## Two report clarifications (carried from the original delivery, still accurate)

1. **Post-panic mutations.** On a callback panic, the actual `ingest_proposal`
   route permits, before the observation point: (a) candidate block registration
   (and, on the verified path, retention of the verified-justification `Arc`), and
   (b) — only for a *future-view* proposal — advancing `current_view` and resetting
   `proposed_in_view`/`voted_in_view`. The executed test
   (`callback_panic_prevents_self_vote_and_action`) submits a proposal whose height
   equals the current view, so it exercises only the block-registration mutation
   and asserts `block_count + 1` and lock-still-L0; it does **not** exercise the
   future-view advancement, which the route nonetheless permits in general.
2. **"Zero additional heap allocations" attribution.** `size_of` establishes the
   48-byte **layout** only (unchanged by this revision), not allocation behavior.
   The no-additional-heap / no-`Arc`-clone property rests on **source inspection**
   (all fields are borrows or `Copy` scalars) plus the **endpoint retention check**
   described in §3 — it is **not** backed by a heap-allocation profiler and does
   **not** claim to catch transient clones.
