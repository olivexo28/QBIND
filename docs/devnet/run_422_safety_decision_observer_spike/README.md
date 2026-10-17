# RUN 422 — Safety-Decision Observer Spike (Published Evidence)

This directory publishes the **experimental evidence** for the Run 422 §13.6
safety-decision observer spike. It is an **isolated feasibility experiment**: the
observer implementation is **not** landed, **not** wired into accepted source, and
**not** applied to this branch. Only this evidence directory is published.

**§13.6 engine-decision binding remains INCOMPLETE.** The spike *observes* the real
safety decision; it does not *bind* a decision to a durable generation, does not
associate the decision with the outbound action, and establishes no D10/signing
prerequisite. Activation remains **DISABLED**; public DevNet remains **NO-GO**.

## Contents

- `patch/run_422_safety_decision_observer_spike.patch` — the complete, applyable
  patch against baseline `0de4df69…`, including the new test file. No abbreviated
  hunks or omitted bodies.
- `logs/` — raw execution logs (see "Reproduced vs. unavailable" below).
- `MANIFEST.txt` — baseline, changed experimental paths, execution dates, and hashes.
- `SHA256SUMS.txt` — checksums for every file in this directory (except itself).
- `BASELINE.txt` — the baseline commit hash.

## What the spike is

Between the real safety predicate and the self-vote in
`BasicHotStuffEngine::ingest_proposal`, an optional borrowed
`&mut dyn SafetyDecisionObserver<[u8;32]>` is handed a stack-only
`SafetyDecisionView`. The predicate is refactored into one typed evaluation
`HotStuffStateEngine::safety_decision -> SafetyDecision::{Safe(SafetyBranch), Unsafe}`
(`SafetyBranch::{NoLock, ViewSufficiency, Ancestry}`); `is_safe_to_vote_on_block`
becomes a thin `matches!(…, Safe(_))` wrapper, so the boolean outcome, OR-structure,
and the view-sufficiency short-circuit are unchanged. The observer therefore sees the
**L0** lock in effect **before** the self-vote can form a QC and raise it to **L1**.
The view is read-only: it holds no owned data, clones no certificate `Arc`, takes no
token, and returns `()`.

## Applying the patch (for reviewers)

    git worktree add --detach /tmp/obs 0de4df69cf55a05e88baff50733ffa578cdf171e
    cd /tmp/obs
    git apply docs/.../patch/run_422_safety_decision_observer_spike.patch
    # optional: cargo test -p qbind-consensus --test run_422_safety_decision_observer_spike_tests

The patch reproduces the four changed files byte-for-byte on the clean baseline;
their post-edit content hashes are recorded in `MANIFEST.txt` and `SHA256SUMS.txt`.

## Reproduced results vs. unavailable original evidence

This distinction is deliberate and must not be blurred:

- **Reproduced / verified (durable, deterministic):** the **patch** is a deterministic
  source artifact. It was regenerated on a clean baseline worktree and its SHA-256
  matches the value recorded earlier (`210e39e9…`), as do the four post-edit file
  hashes. Reviewers can re-derive it exactly.
- **Re-executed 2026-10-17 (genuine, but not the original run):** the logs under
  `logs/` (`01_build.log`, `02_spike_tests.log`, `03_doctests.log`,
  `04_patch_apply_verify.log`) are the outputs of a **fresh re-execution on
  2026-10-17**. They are labeled as such in each file's header. They are NOT the
  original run's logs.
- **UNAVAILABLE — original 2026-10-13 evidence:** the original experiment's checkout
  and its original build/test logs were in ephemeral storage that has since been
  cleared. They are **gone and are not reconstructed here**. No file in this directory
  is an original 2026-10-13 log; nothing here is presented as a recovered original.

### Not re-run for this publication

Per the delivery constraint (do not re-run broad validation merely to package
evidence), the following were **not** re-executed and are cited from the prior
session as prior/not-re-verified-now: the `qbind-node` build (prior: ~4m48s) and the
full `qbind-consensus` library suite and broader consensus regressions. Request a
fresh run explicitly if those are needed.

## Two report clarifications (carried from the delivery)

1. **Post-panic mutations.** On a callback panic, the actual `ingest_proposal` route
   permits, before the observation point: (a) candidate block registration (and, on
   the verified path, retention of the verified-justification `Arc`), and (b) — only
   for a *future-view* proposal — advancing `current_view` and resetting
   `proposed_in_view`/`voted_in_view`. The executed test
   (`callback_panic_prevents_self_vote_and_action`) submits a proposal whose height
   equals the current view, so it exercises only the block-registration mutation and
   asserts `block_count + 1` and lock-still-L0; it does **not** exercise the
   future-view advancement, which the route nonetheless permits in general.
2. **"Zero additional heap allocations" attribution.** `size_of` establishes the
   48-byte **layout** only, not allocation behavior. The no-additional-heap / no-Arc-
   clone property rests on **source inspection** (all fields are borrows or `Copy`
   scalars) plus an executed `Arc::strong_count` assertion in the verified test — it
   is **not** backed by a heap-allocation profiler.
