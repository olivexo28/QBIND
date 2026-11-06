# A33-F1 / E27 isolated model correction

**TEST-ONLY MODEL CORRECTION — INDEPENDENT REVIEW PENDING.**

The user supplied the independent review verdict **CHANGES REQUIRED** and
four findings. No reviewer identity or independently accessible raw review
artifact was supplied; this record attributes the report to the user and
does not invent either. I1, W1/W2 and earlier bounded acceptances remain
closed within their scopes. A33-F1 / E27 and other remaining obligations
remain **OPEN**; activation **DISABLED**; public DevNet **NO-GO**.

## Entry and scope

Repository `olivexo28/QBIND`, branch `copilot/a33-f1-bounded-eviction`;
starting commit `74206e34a6af557f8e710e7e402b907b36faa1a8`, tree
`42f1a6aaa6fe4dfc6cc88ff0e7ac1d4c80c248db`. Local HEAD and direct remote
task ref matched. Local/direct remote main matched
`c9aaef40b045e896ddfa8b01bad230f6b680715e`. Worktree/staging were clean.
These observations used `git remote get-url origin`, `git branch
--show-current`, `git status --porcelain`, `git rev-parse HEAD
refs/heads/main` and `git ls-remote origin
refs/heads/copilot/a33-f1-bounded-eviction refs/heads/main`.

Only `crates/qbind-consensus/tests/support/a33_f1_ordered_planner.rs`,
its dedicated integration tests, and append-only plan/evidence are changed.
The support module is a synthetic model explicitly imported by a separate
Cargo test crate, not the real engine. Production consensus, catch-up,
node/caller, startup, signer, storage and network behavior remain unchanged.
The v3 design direction and later stay-closed contract still govern the
proposal; no automatic conflict resolution, quarantine clearing or resumption
is introduced. No recovery authority or production policy is selected.

## Corrections and distinguishing controls

| Supplied finding | Correction in support model | Regression |
|---|---|---|
| 1: conflict lost on refusal | `refuse_current` ORs into the existing unresolved latch rather than assigning it. `NoEffectRefusal` is documented as the current-item/empty-prefix label only; operation evidence and unresolved status must also be inspected. | `conflict_and_refusal_commute_without_clearing_unresolved_evidence` retains the exact conflict before/after refusal in both orders, with an empty prefix and participation refused. The former assignment fails the conflict-first case. |
| 2: candidate queue insertion unreported | `publish` sets queue observation to `Observed` and advances registration phase immediately after pushing the candidate, before generation or injected failure can return. | `candidate_queue_insertion_is_observed_without_queued_victims` compares actual empty-before/one-entry-after queues under injected post-registration failure, both with zero victims and a fallback victim absent from the queue. Former code reports `ConfirmedNoEffect`. |
| 3: zero-deficit mismatch | `plan` validates all pre-existing accounting before issuing a plan. `publish` rechecks candidate lineage only when D=0, using all protected paths only for D>0; actual ancestry/accounting refusals are not mislabeled stale. | `zero_deficit_checks_accounting_and_publishes_unchanged_malformed_protected_state` requires pure refusal for inconsistent accounting, then successful planning AND publication with unchanged unrelated own-QC/lock/committed malformed components (self-cycle or missing parent). Former planning accepts bad accounting; former publication rejects valid free-slot plans as stale. Existing missing/cyclic candidate-lineage controls remain. |
| 4: count-only current signers | `record_current_signers` binds completed dispositions to supplied input IDs/order by index and zip; an interrupted signer is separately bound to the next input identity. Vote-history observation, optional accumulator disposition and QC observation are separate. Existing count-only API explicitly marks replay details unavailable. | `current_signers_bind_order_dispositions_interruption_and_capacity` distinguishes two one-completed-signer histories (Added versus Duplicate, different history/QC knowledge), identifies interrupted signer 7 separately from completed signer 42, preserves all four identities at the fixture boundary, and refuses five inputs or excessive known-effect observations conservatively. |

`SignerDisposition.accumulator = None` means unavailable/unknown, not no
effect. Neither an absent QC result nor an `Ok(None)`-like return proves
history or accumulator dispositions. `KnownDetailsUnavailable` retains
knowledge of an effect without payload details; `NotObserved` asserts no
observation, not no effect. On oversized input or observation exhaustion,
the report retains unresolved ownership and `EvidenceLimitExhausted` but
does not store/reconstruct discarded signer detail. Its known-observation
counter counts categories actually supplied (potentially overlapping
summary/per-signer observations), not distinct physical mutations. A
Duplicate accumulator disposition is not counted as an added-vote effect.

`Complete` describes only modeled response completion. External effects are
separately `NotObserved` by default, and completion keeps `unresolved` true
when they are unobserved or known with unavailable details. This is missing
external assurance, not proof an external effect occurred. Participation
always remains refused. No complete/no-effect result can clear quarantine.

Additional controls:

* `same_generation_substitution_refuses_and_last_shared_owner_releases_charge`
  changes public block contents on a clone without changing generation;
  snapshot equality rejects it without mutation. A valid separate publication
  then removes the sole shared-evidence owner and checks charge/map removal.
  This is logical accounting release, not proof of physical memory reclamation.
* `ordered_victims_preserve_frozen_protected_roots_and_parent_links` checks each
  ordered removal against frozen roots/links and the complete protected set.
  Under that conditional model assumption, distinct victims outside the set
  preserve all protected nodes and their parent paths throughout the sequence.
  It is not production equivalence, a claim about changing roots, or an
  ownership barrier.
* The existing direct-parent-only R -> A -> P -> C negative control still
  returns false from the invariant checker; a lineage-preserving plan returns
  true. Post-queue/removal/registration faults remain explicitly injected
  controls, not demonstrated production failures. No deliberately defective
  implementation was executed in this task; no expected failure is counted
  as a security pass.

Fixture bounds remain 4 items, 4 signers/item, 4 victims, 32 lineage visits,
8 known effect observations and 2 late/conflicting records. They constrain
these synthetic operations only: they do not establish bounded inbound
deserialization, whole-model allocation/work, total evidence retention,
production 64-KiB sufficiency, durability or ownership barriers. Cloned
snapshots, queue scans and accounting inventories are not covered by a
whole-model resource proof. Production wiring still requires separately
reviewed exclusive ownership/admission-revocation, cancellation-safe
observation, durable intent/startup containment and previously admitted
non-engine work handling.

## Fresh executions and raw bytes

Commands (default features; no feature flags):

```text
rustfmt --edition 2021 crates/qbind-consensus/tests/support/a33_f1_ordered_planner.rs crates/qbind-consensus/tests/a33_f1_ordered_planner_model_tests.rs
rustfmt --edition 2021 --check crates/qbind-consensus/tests/support/a33_f1_ordered_planner.rs crates/qbind-consensus/tests/a33_f1_ordered_planner_model_tests.rs
CARGO_TERM_COLOR=never cargo test -p qbind-consensus --test a33_f1_ordered_planner_model_tests -- --nocapture --test-threads=1
```

All four formatted test iterations exited 0, each with **17 passed, 0 failed,
0 ignored, 0 measured, 0 filtered out**. Formatting/check exited 0. First
execution preceded an additional effect-limit assertion and correction to
count Added rather than every available accumulator disposition as a known
vote effect. The second execution preceded retaining the bounded complete
input signer list in the current-item record. Final execution covers the
delivered Rust source, including preservation of known signer observations
when the input-item limit is exhausted after a completed prefix. The third
execution preceded that additional exhaustion control. There were
no unsuccessful test/format attempts in this correction task. The 37
library warnings remain visible in all four complete logs; none is a test failure.
No unchanged historical integrations were rerun or requested.

| Retained file (in this evidence directory) | SHA-256 |
|---|---|
| `ordered-model-correction-tests-attempt-1.log` | `8f876dcd0b75dc184d9c57e4baf112a63eecb5b27f5252c893f615db1ca12b7b` |
| `ordered-model-correction-tests-attempt-2.log` | `dd3c4dd08e00e1f7478a622ab0a4c21f3ad3d4a92f330e81857e357020131809` |
| `ordered-model-correction-tests-attempt-3.log` | `a98044e8dd408f34de4964e7b03cff961b54c4fc5bbd9d906cbd08adae02cf9a` |
| `ordered-model-correction-tests-final.log` | `f96ef587bf6c8a816a26940e9429c9ef64581c4c4f76a4ee1f757202c143e1d5` |
| `ordered-model-correction-format.log` (empty success output) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `ordered-model-correction-format-final.log` (empty success output) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `ordered-model-correction-platform.txt` | `8395d7c775818f556db70eb4d865e07d3290d86799809b7d23f04cba59cd639b` |

Toolchain: rustc 1.99.1 / cargo 1.99.1, rustfmt 1.10.0-stable, Linux
x86_64 kernel 6.12.8+. Exact version/build strings are in the platform file.
Original new logs, command/exit sidecars and integrity diagnostics are also
retained outside checkout under `/tmp/a33-model-correction-74206e3/`.
No historical log is overwritten, reconstructed or normalized. Older
overwritten logs remain unavailable as previously reported.

## Append-only historical reporting correction

The reviewed `74206e3` appended **10 checksum entries, not nine**. Its
`ordered-planner-outcome-candidate.md` still contains the earlier nine-entry
wording; that document and previous manifest bytes are preserved. This is
the new correcting entry, not a silent historical edit.

Only current-artifact entries are suitable for an ordinary current-file
verification; superseded hashes remain historical and require producing-
revision bytes. Recoverable integrity-log prefixes alone do not establish
their producing revisions: the two previously reported intermediate prefix
identities remain unestablished. This correction does not reopen E1 or
claim fresh historical revision-matched verification. Ordinary full-manifest
and full whitespace non-passes must not be relabeled targeted passes.
Final scoped diagnostics are reported with the delivery and retained outside
checkout; this document/plan do not hash their own checksum manifest.

## Current integrity and whitespace disposition

The pre-final ordinary `sha256sum -c SHA256SUMS` execution at this working
state exited **1**: 237 entries, 181 OK and 56 FAILED comparisons, without
missing files. The earlier pre-append execution (before extending the plan)
also exited 1, with 55 mismatches. These are ordinary non-passes, not
historical integrity failures automatically resolved by this correction.
Superseded hashes of now-modified source/plan account for additional
current-file mismatches. No fresh producing-revision historical verification
or prefix-producer proof is asserted.

`git diff --cached --check` for this task exited **2** with three final blank
lines in newly preserved raw test logs. `git diff --cached
c9aaef40b045e896ddfa8b01bad230f6b680715e --check` for the complete branch
also exited **2**. The source/new-document/plan restriction exited **0**;
these scoped passes do not override either complete non-pass. Raw bytes
are intentionally not normalized.

Diagnostics are outside checkout in `/tmp/a33-model-correction-74206e3/`:
`scoped-whitespace.log` SHA-256
`eb7051b8157b02ec47572f65f84e5cdaa683bfd2f30d1914c5a1c60dba44166e`;
`complete-branch-whitespace.log` SHA-256
`a842cd59003f84dfb8dede068aa7f9bdda5345db9ffa488812aa4a0381b9d90c`.
The full-manifest logs and each exit sidecar are retained there as well.
The final appended current-artifact checksum slice is checked separately
at delivery; no manifest self-hash or self-referential checksum cycle is used.

Delivery checks recorded 11 new current-artifact entries, all OK (exit 0).
The ordinary full manifest remains a **non-pass**, exit 1, with 248 entries:
192 OK and 56 FAILED comparisons. Scoped-with-logs and complete-branch
whitespace both remain **non-passes**, exit 2; non-log source/document/
manifest whitespace exits 0. The additional fourth raw test log has the
same preserved final blank-line limitation.

The final diagnostics are retained as `current-checksums-final.log`,
`full-manifest-delivery.log`, `scoped-whitespace-delivery.log` and
`complete-branch-whitespace-delivery.log` with exit sidecars under the same
external directory. Existing plan and manifest bytes were checked as exact
prefixes of their current files. Only the two support/test sources and the
appended plan/manifest modify existing files; earlier evidence documents,
raw logs, the audit register and production paths are unchanged.
