# A33-F1 / E27 bounded early-refusal evidence accounting

**TEST-ONLY EVIDENCE-ACCOUNTING CORRECTION — INDEPENDENT REVIEW PENDING.**

The user supplied an independent review accepting the previous four
corrections with limitations, and identified the remaining source-derived
early length/shape refusal gap. No reviewer identity, raw review artifact,
independent execution or review of this new correction is asserted.
Accepted conflict, queue, zero-deficit, current-signer, final-shared-owner,
same-generation substitution and conditional frozen-lineage controls are
preserved. I1, W1/W2 and earlier bounded acceptances are not reopened.
A33-F1 / E27 and remaining obligations stay **OPEN**; activation **DISABLED**;
public DevNet **NO-GO**.

## Entry and permitted scope

Direct remote task and main were verified before editing, together with
repository URL, current branch, clean worktree/staging and local revisions:

```text
git remote get-url origin
git branch --show-current
git status --porcelain
git rev-parse HEAD refs/heads/main
git ls-remote origin refs/heads/copilot/a33-f1-bounded-eviction refs/heads/main
```

Repository `olivexo28/QBIND`; branch `copilot/a33-f1-bounded-eviction`;
HEAD/direct remote task `8bc374d7554db821cebd4d06412a30fe4c0a535d`,
tree `f3ab86c3fc334b91b89d0b9e41f499e0bf7859dd`. Local/direct remote
main `c9aaef40b045e896ddfa8b01bad230f6b680715e`; worktree/staging clean.
No local tracking-ref assumption substitutes for the direct remote result.

Changes are confined to the separate synthetic integration-test support
module and focused tests, plus appended plan, manifest and new evidence.
No production code, Cargo configuration, actual catch-up caller, startup,
storage, network, signer or quarantine wiring changes. The synthetic model
never grants participation, resolves conflict or clears quarantine.

## Reporting invariant and bounded implementation

Before either early oversized/shape refusal or later outcome/effect-budget
refusal, `record_current_signers` now calls `summarize_signers`. This inspects
at most the first **four completed observations** and the **one optional
interrupted observation**, independent of rejected slice length and even
when a caller supplies larger custom limits. It does not scan signer input
identities or the discarded completed suffix and allocates nothing in the
refusal summary. Successful detail retention remains confined by the
fixture limits; an incomplete summary cannot authorize detail publication.

Each inspected supplied `Observed`/`KnownDetailsUnavailable` vote-history or
QC category and an accumulator `Added` disposition contributes a known
observation. Unknown history/QC and unavailable accumulator details do not
invent effects. Interrupted observations contribute independently even if
shape prevents binding them to a valid input identity; this preserves their
reported fact, not proof that a real engine execution occurred.

The cumulative `known_unrecorded_effects` counts supplied known observation
categories, not distinct physical mutations (aggregate and signer categories
can overlap). Its semantics are:

* When `unrecorded_accounting_incomplete` and
  `unrecorded_accounting_saturated` are both false, it is exact for supplied
  known categories inspected by these counting APIs, not an assertion that
  all real effects are known.
* `unrecorded_accounting_incomplete` is sticky when a supplied completed
  observation suffix was not inspected. The count is then a lower bound;
  zero cannot establish that no known facts were supplied in that suffix.
* Addition overflow saturates at `usize::MAX` and sets sticky
  `unrecorded_accounting_saturated`. Exact arithmetic magnitude is no longer
  asserted; this flag does not erase the incomplete flag or prior facts.
* `last_signer_observations_inspected` reports this helper's actual bounded
  inspection count (0 through 5); it is diagnostic, not recovery authority.

Detail payloads past the inspection cap are not stored or recoverable.
The early length/shape and later terminal/item/effect-budget refusals use
the same summary, preserve cumulative facts and sticky unresolved state,
and return `EvidenceLimitExhausted` without participant permission. A zero
with complete inspection of wholly unknown observations means only that no
known category was supplied in the inspected observations; unknown is not
`ConfirmedNoEffect`.

Inspection of other exhaustion paths found the same omission in
`record_completed`: rejected supplied Added dispositions and `Some(true)`
QC facts were ignored when aggregate effects were unobserved. Its refusal
now inspects at most four dispositions, counts those Added categories plus
the scalar known QC and aggregate categories, and marks an uninspected suffix
incomplete. Existing current-failure scalar/effect-array refusals inspect
fixed-size input; count-only replay information stays explicitly unavailable.
Late/conflict refusal has no supplied signer-effect payload to count and
does not infer effects from missing evidence.

The previously accepted 17 control scenarios remain; two assertions in
the existing exhaustion test are corrected only for these newly retained
supplied facts: rejected Added contributes one, and rejected Added + known
QC + two aggregate categories contributes four. Other accepted semantics
are unchanged. Fixture values are not a production resource policy.

## Focused controls and exact execution record

Three new registered tests use the same known/unknown counting invariant:

* `early_signer_refusal_preserves_known_facts_without_inventing_unknown_effects`:
  five IDs against limit four, one completed Observed-history/Added signer,
  aggregate NotObserved, refuses with count two. The equivalent unknown
  observation refuses with count zero and complete inspection, remaining
  unknown rather than no-effect. Malformed empty-input shape includes both
  completed and interrupted known observations (count four); a later
  exhaustion adds two without clearing prior facts.
* `rejected_signer_inspection_is_bounded_and_incomplete_counts_are_lower_bounds`:
  the driver creates 10,000 observations with a known observation only at
  index 9,999. The model inspects four, records zero with incomplete=true,
  stores no current/prefix/late payload; adding a separately supplied known
  interrupted observation inspects five total and retains three known
  categories. A synthetic near-maximum counter tests saturation while
  preserving incomplete/unresolved status.
* `completed_item_refusal_also_accounts_bounded_supplied_vote_and_qc_facts`:
  a 10,000-Added slice plus known QC, aggregate NotObserved, refuses with
  four inspected Added facts + one QC, incomplete=true and no retained item.

The large driver vector is test setup, not an allocation performed by the
refusal model. Source `.min(4)`/prefix iteration plus the diagnostic assertion
establish this bounded summary path, not a whole-model allocation/work proof.
Input decoding, inbound transport, total retained evidence, cloned snapshots,
production 64-KiB sufficiency, durability and ownership barriers remain
unestablished. Logical final-owner charge release is not physical reclamation.
Conditional frozen-root lineage evidence is not production equivalence.

Exact commands, default Cargo features (no feature flags):

```text
rustfmt --edition 2021 crates/qbind-consensus/tests/support/a33_f1_ordered_planner.rs crates/qbind-consensus/tests/a33_f1_ordered_planner_model_tests.rs
rustfmt --edition 2021 --check crates/qbind-consensus/tests/support/a33_f1_ordered_planner.rs crates/qbind-consensus/tests/a33_f1_ordered_planner_model_tests.rs
CARGO_TERM_COLOR=never cargo test -p qbind-consensus --test a33_f1_ordered_planner_model_tests -- --nocapture --test-threads=1
```

First test command exited 0 but ran only **17** tests: accidental nested
placement left the three new controls unregistered, producing six test-crate
warnings. This was an **unsuccessful coverage attempt**, not passing evidence
for the new regressions. Its full raw log is preserved. Moving these tests
to top level and formatting again resulted in the final command exiting 0:
**20 passed, 0 failed, 0 ignored, 0 measured, 0 filtered out**.
Final formatting/check exited 0; no compilation/test assertion failures
occurred. Final output includes 37 existing library warnings and no new
test-crate warnings. No expected test failure is counted as a security pass.
The earlier direct-parent-only negative invariant control remains a rejection,
not a defective production execution.

| New retained file in this directory | SHA-256 |
|---|---|
| `early-accounting-tests-unregistered-attempt.log` | `6130e94a5c974eaf2d56f90b05635fee087c46bbe712e2c87028633be9a8eea1` |
| `early-accounting-tests-final.log` | `55bd0799b344afefb4b444a3b6c970d8affb83d93b3b2cdbf92b2164bd02c6f7` |
| `early-accounting-format.log` (empty success output) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `early-accounting-platform.txt` | `8395d7c775818f556db70eb4d865e07d3290d86799809b7d23f04cba59cd639b` |

Toolchain: rustc/cargo 1.99.1, rustfmt 1.10.0-stable, Linux x86_64
kernel 6.12.8+; complete build/version strings are in the platform file.
Raw output, exact commands and exit sidecars also remain outside checkout
at `/tmp/a33-early-accounting-8bc374d/`. None of the historical outputs is
overwritten, normalized or reconstructed. Older unavailable logs remain
unavailable; no unchanged historical results are independently reviewed or
rerun by assertion.

## Integrity interpretation

The plan and checksum manifest are extended only by new suffixes; previous
bytes, audit register and evidence documents/logs are preserved. Current
new-artifact checksums are checked separately from ordinary full-manifest
verification. Historical superseded entries require their producing-
revision bytes rather than current files; no fresh revision-matched
historical verification is claimed here. Recoverable integrity-log prefixes
still do not establish the two previously unestablished producing revisions.
Full-manifest and complete-whitespace non-passes are not scoped passes, and
E1 is not reopened. Delivery checks and diagnostic exits are reported
separately, with raw output retained outside checkout. The manifest does not
hash itself; no self-referential checksum cycle is introduced.

Current checks before appending new checksum entries: ordinary manifest
verification exited **1**, 248 comparisons: **189 OK, 59 FAILED**, no missing
files. The added mismatches include superseded support/test/plan identities;
no historical entry is erased or relabeled. Scoped-with-raw-logs and
complete-branch whitespace both exited **2**. This scope reports final blank
lines in the two new raw logs; non-log source/plan/document whitespace exited
**0**. Raw output remains byte-preserved.

Diagnostics under `/tmp/a33-early-accounting-8bc374d/` include
`full-manifest-before-append.log`, `scoped-whitespace.log` (SHA-256
`2e034cecab4c75d4fe51b5484963a58b62513c1a70e9d55be086bca43859d514`),
`complete-whitespace.log` (SHA-256
`ed1710917f3b291d253643752817f81329edd7d8344412fc419fd95aa1131b08`)
and matching exit sidecars. Eight new current-artifact entries are checked
separately at delivery; the expected ordinary full-manifest non-pass then
has 256 comparisons, 197 OK and the same 59 superseded/mismatched entries.
Delivery confirms actual results rather than assuming those totals.

Delivery verification confirmed **8/8** new entries OK (exit 0); ordinary
full manifest exited **1**, with **256 entries, 197 OK, 59 FAILED**.
`new-checksums.log` and `full-manifest-final.log` with matching exit
sidecars are retained in the external directory. Exact prior plan/manifest
prefixes were verified, and staged modified-existing-path checks confirm
only the two Rust test files and appended plan/manifest changed.
