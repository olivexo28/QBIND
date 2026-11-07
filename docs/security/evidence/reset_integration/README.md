# Authority-reset integration candidate

**RESET INTEGRATION CANDIDATE — INDEPENDENT REVIEW PENDING.**

A33-F1 / E27 and all other unresolved obligations remain **OPEN**.
Activation remains **DISABLED** and public DevNet **NO-GO**. The existing
full task branch is **not approved for integration**. This package neither
changes the independent reviewer's carry-forward list nor expands any
accepted I1, E1, W1/W2 or other review beyond its recorded scope.

## Entry and source identity

Repository: `olivexo28/QBIND`, origin
`https://github.com/olivexo28/QBIND`.
Before any changes, the original worktree was clean on main.
Direct `git ls-remote origin` (not a tracking-ref assumption) returned:

| Ref | Commit |
|---|---|
| Protected main / candidate base | `3926fd4d9e7c1ec68c4b22610e154f9e90460f1c` |
| Existing source-branch tip | `f5ccefecec4d47b5fd529513e9eae8ac4b46fef7` |
| Reviewed reset source | `748ee3ab2a4c88ffa0bfe8152eebd1c695f49c95` |

Main's tree is exactly `1a846b01962f7ea016ec971f8a11b71ce91a30c9`.
The existing branch is `copilot/a33-f1-bounded-eviction`.
The isolated candidate branch is `copilot/authority-reset-integration-candidate`;
its worktree is `/workspaces/QBIND/olivexo28/QBIND-reset-integration`.
The original worktree and existing long-running branch are not modified.
[Entry recheck](entry-recheck.log) retains direct refs, original-worktree
status and tool/platform versions; its exact command and exit are in
[entry-recheck.json](entry-recheck.json).

The eight selected source/test blobs were staged before documentation or
log files. That tested source-only tree is
`38d547f401e91a1c0753c002df7e01fcd3e0a997`: expected main plus precisely
those eight paths. It is a Git tree, **not a historical producing commit**.
The final delivery commit identifies the published candidate; all eight
blobs must equal this tested tree and the reviewed source byte-for-byte.
Final commit/tree/parent and push verification are reported after commit,
not embedded in self-referential evidence.

## Selected production and dependencies

| Production path | Candidate and reviewed Git blob | SHA-256 |
|---|---|---|
| `crates/qbind-node/src/main.rs` | `9e3652f03b18bdb0baf899d64bc735b7c459c798` | `e234fcfb2d54628dec76c51162ed7b45a7baab7d960d6585e40c274eb555aca3` |
| `crates/qbind-node/src/pqc_authority_state_reset.rs` | `210a071f8b1d2c4f6393f60115e109c428a55ef9` | `11efa2d36617a0fb740a29a386e7e1eabfd8b25d31ecb90a32146fac3cd553c2` |

There are **no byte or production-behavior differences** from the reviewed
reset implementation in these two files. Existing CRLF reset-source bytes,
the I1 `(2, 3)` marker/own-temporary identity comparison, private sequencing
seams, and the non-operative future-quarantine comment are retained exactly.
The eight complete blob comparisons and SHA-256 values are independently
checked by [check_candidate.py](check_candidate.py).

Compared with main, the selected behavior is:

- Inspect audit final/temp, marker final/appended `.tmp`, and `restore.lock`
  before verification and each audit publication. Refuse canonical-path,
  parent-identity/name, or existing inode aliases, including marker/own-temp
  identity, without unsafe publication.
- Preserve typed primary operation and secondary audit failures separately,
  including `NotAttempted`, `AttemptedUncertain`, and `Acknowledged`
  persistence outcomes. An error is not a rollback or unchanged-marker claim.
- Require explicit destination ownership in the Linux reset CLI before
  reset writes, including verification-refusal audits, and retain the
  existing lock descriptor through reset reporting and process exit.

The additional six selected paths are dependencies, not optional coverage:

- `crates/qbind-node/src/pqc_authority_state_reset_error_tests.rs` is loaded
  by the selected source's private Linux test module and exercises its actual
  shared sequencing and independent error contexts.
- `crates/qbind-node/tests/a33_f1_authority_reset_audit_collision_tests.rs`
  uses the changed exported audit-writer signature and path guards.
- `crates/qbind-node/tests/a33_f1_authority_reset_destination_lock_tests.rs`
  runs the actual offline reset CLI and cooperating advisory-lock holder.
- `crates/qbind-node/tests/a33_f1_authority_reset_verified_success_tests.rs`
  verifies signed synthetic genesis/trust/ratification inputs through the
  public verifier/reset, including fresh/repeated success, real CLI success
  under ownership, equal-path refusal and signature tampering.
- `crates/qbind-node/tests/a33_f1_reset_marker_temp_identity_tests.rs`
  holds destination ownership and exercises the fully verified I1 shared-inode
  refusal and distinct-stale-temp successful control.
- `crates/qbind-node/tests/support/authority_reset_cli.rs` is the shared
  owned-child, bounded-wait CLI helper required by destination-lock and
  verified-success tests. No dependency manifest changes are needed.

All six are byte-identical to their reviewed blobs, not copied from the later
task-tip tests. The existing genesis loader, marker derivation/persistence,
trust-bundle signing/verification, ML-DSA backend, ratification enforcement
and its synthetic `test_helpers::build_signed_ratification`, devnet-root
helper, `restore_completion` lock implementation, and Cargo manifests are
unchanged between main and reviewed source. They are already on main.
All other maintained production paths stay at main. In particular,
`src/lib.rs` does **not** receive the reviewed branch's unrelated
`pub mod pqc_reset_quarantine` addition, and `pqc_reset_quarantine.rs`,
quarantine interfaces/models, owner/lease prototypes and planner work are
excluded. No selected import or call depends on them.

Thus the only differences from the reviewed branch's surrounding package
are the deliberate exclusion of unrelated files/registration, preservation
of main's historical documents, and this new integration evidence. None
changes the selected reset behavior. No quarantine gate, participation,
clear, recovery or signing authority is introduced.

The supported profile remains case-sensitive Linux with stable,
operator-owned directories and no hostile namespace/hard-link/mount races.
Advisory ownership coordinates cooperating destination users, not arbitrary
writers to an external audit path. The public library reset still requires
its caller to retain ownership; it does not acquire a lock itself. Some
accepted direct-API fixtures use exclusively owned synthetic temporary
directories without testing that caller precondition; the CLI and I1
controls actually acquire the lock. The shared public marker writer remains
outside this reset guard's protection. Neither persistence acknowledgment
nor these tests establishes power-loss durability, recovery or activation.

## Historical evidence: reuse, not new execution

[historical-index.tsv](historical-index.tsv) contains 53 selected historical
artifacts: immutable **publishing revision**, repository path, complete-file
SHA-256 and immutable URL. Each digest was newly checked against that
publishing revision's recorded manifest entry. The index includes raw
unsuccessful and incomplete attempts rather than omitting them. It does not
copy the cumulative historical manifest or imply those artifacts describe
the candidate's files.

| Historical final result | Production source revision | Publishing revision / final logs |
|---|---|---|
| Original equal-path defect and distinct-path control; 2 baseline assertions, not a security pass | `6597596abe69f739ec5d3130cdb20413f0cf0c36` (production unchanged in publisher) | `e8f58a5c391f282c1996f4306c02743ace056fa5`: `authority-reset-collision-focused-tests.log` |
| Corrected path separation; 6 path tests, 18 existing regressions | `6506faf18485769a2c852b7609149f908b807848` | Same revision: `authority-reset-correction-focused-tests.log`, `authority-reset-correction-regressions.log` |
| Compound errors; 22 module tests, 6 path tests | `11bb930e005abd082a1dbb296f0b8fe90dcf4fc0` | Same revision: `authority-reset-errors-unit.log`, `authority-reset-errors-paths.log` |
| Public fully verified synthetic success and path controls; 1 success test + 6 path tests, 22 module tests | `11bb930e005abd082a1dbb296f0b8fe90dcf4fc0` (production unchanged in publisher) | `f30cae3f502020101edf5e447bdf26aea9c9f0e1`: `authority-reset-verified-focused.log`, `authority-reset-verified-regressions.log` |
| CLI destination ownership; final 5 ownership tests + existing lock regression, 22 reset module tests | `bc33bca493c154dac47c797c518b77290da61566` | Same revision: `authority-reset-ownership-final-controls.log`, `authority-reset-ownership-reset-regressions.log` |
| I1 corrected marker/temp identity; 13 integration tests and 22 reset module tests | `748ee3ab2a4c88ffa0bfe8152eebd1c695f49c95` | Same revision: `i1-marker-temp-focused.log`, `i1-marker-temp-errors.log` |

The I1 and ownership **baseline** production was respectively
`c33132812646794de3640301e291313c6e182e04` and
`f30cae3f502020101edf5e447bdf26aea9c9f0e1`; baseline harnesses were overlaid
and observed defective behavior. Their logs are not corrected acceptance.
Intermediate/incomplete runs and failed build/assertion/format/scope
attempts remain attributed exactly as described by their immutable evidence
records. Where an intermediate uncommitted harness has no immutable complete
source revision, none is invented here; such output is retained context,
not a validation result claimed for a pinned complete source or candidate.
Earlier success-path-untested statements are historical limits, not rewritten.

The historical I1 record reports an ordinary cumulative 227-entry checksum
**non-pass**, exit 1, **175 OK / 52 FAILED**, with two prefix-only entries
having unestablished producing revisions. Its full profile-aware whitespace
check also failed on a preserved failed-attempt trailing space. These are
historical reported checks, **not newly rerun full-branch checks**, and are
not converted to passes by the 53 selected complete-file checks.

## New candidate execution and preservation

New commands run only against the assembled eight-blobs source tree above,
on Linux x86_64 with Rust/Cargo 1.99.1. Every command has a corresponding
raw `.log` and `.json` with argv, UTC times and exit code; raw stdout/stderr
is captured without whitespace normalization by
[run_validation.py](run_validation.py). All unsuccessful attempts remain.
Synthetic credentials stay in memory; serialized fixture files contain
only synthetic public material/signatures in temporary directories.
Only the early-exit offline reset CLI is invoked, never node/network startup.

The original **19** A33-F1 manifest entries and all **20** existing evidence
files (including that manifest) are byte-identical to main. The entire
existing remediation plan, **361,456 bytes**, is also byte-identical, not
merely an append-only prefix. Every other baseline tracked path is unchanged.
The independent reviewer carry-forward list and historical review bytes
are therefore untouched. The original manifest newly passes 19/19
([preserved-main-checksums.log](preserved-main-checksums.log)).

Whole-production-file rustfmt checking exits **1** for inherited formatting
differences, preserved in [production-format-whole-files.log](production-format-whole-files.log).
This is not a whole-file formatting pass. Complete selected test/helper
formatting and all changed production-line formatting pass separately;
legacy differences are explicitly excluded without rewriting source bytes.

## New command outcomes

| Command record | Exit | Observed result |
|---|---|---|
| `focused-attempt-1.json` / `.log` | 101 | Build stopped before tests: bindgen could not find libclang. Not a test result |
| `dependency-install.json` / `.log` | 0 | `apt-get update -qq && apt-get install -y -qq libclang-dev`; installed only after the missing-dependency failure |
| `focused-attempt-2.json` / `.log` | 0 | 6 path tests, 5 ownership tests, 1 fully verified success test, 1 I1 identity test; 13 passed, none failed/ignored |
| `reset-unit.json` / `.log` | 0 | 22 reset module tests, including the four shared error-sequencing tests; none failed/ignored; 2,204 filtered |
| `existing-lock-regression.json` / `.log` | 0 | 1 existing destination-lock contention test passed; 2,225 filtered |
| `production-compile.json` / `.log` | 0 | Non-test library and `qbind-node` binary compile check completed; warnings retained |
| `identity-scope-format-attempt-1.json` / `.log` | 0 | Initial 53 historical digests, eight exact blobs, historical preservation and bounded formatting checks passed |
| `production-format-whole-files.json` / `.log` | 1 | Whole-file inherited formatting differences; not a whole-source formatting pass |
| `preserved-main-checksums.json` / `.log` | 0 | Original main manifest: 19 OK, no failures |
| `whitespace-ordinary.json` / `.log` | 2 | Ordinary staged whitespace non-pass: retained source CRLF, install progress CRLF, raw formatter context spaces and Cargo EOF blanks |
| `whitespace-profile.json` / `.log` | 2 | CRLF/EOF-aware full staged non-pass: raw formatter context spaces remain |
| `whitespace-source-prose.json` / `.log` | 0 | CRLF-aware code/prose check, explicitly excluding new raw `.log` files |
| `seal-check.json` / `.log` | 0 | Final source identity, reconstructed tested tree, registered test totals, bounded scope/formatting, immutable index and new current-file checksum/inventory checks |

The focused ownership suite's `cooperating_lock_holder` entry is a no-op in
the parent suite. Its actual lock-holder body runs in the contention
test's owned subprocess. Thus **36 registered test passes** are not claimed
as 36 independent substantive scenarios. The error seams use deterministic
injected return values around real writers, not OS fault/power-loss
reproductions or fully verified post-rename failure ceremonies.
The I1 test ran corrected mode (`QBIND_I1_BASELINE` explicitly removed),
not the historical defective-behavior observation mode.

Exact underlying test/compile commands:

```sh
env -u QBIND_I1_BASELINE -u QBIND_A33_LOCK_HOLDER cargo test --locked -p qbind-node --test a33_f1_reset_marker_temp_identity_tests --test a33_f1_authority_reset_audit_collision_tests --test a33_f1_authority_reset_verified_success_tests --test a33_f1_authority_reset_destination_lock_tests -- --nocapture --test-threads=1
cargo test --locked -p qbind-node --lib pqc_authority_state_reset:: -- --nocapture --test-threads=1
cargo test --locked -p qbind-node --lib restore_completion::tests::second_lock_acquisition_is_contended -- --exact --nocapture
cargo check --locked -p qbind-node --lib --bin qbind-node
```

The first and second focused attempts used the same command and unchanged
source. The successful unit command briefly waited on Cargo's build lock;
that wait is retained, not a failed execution. No source/test changes were
made to obtain test passes. No historical author test command was rerun
against its old producer by this integration task.

[changed-paths.txt](changed-paths.txt) is the **full changed-path list**
against the expected base. Outside the eight selected Rust files, every
path is newly added under `docs/security/evidence/reset_integration/`.
[SHA256SUMS](SHA256SUMS) is a new candidate-specific manifest, not a copied
historical cumulative manifest. Run from repository root:

```sh
sha256sum --check docs/security/evidence/reset_integration/SHA256SUMS
python3 docs/security/evidence/reset_integration/check_candidate.py --verify-seal
```

It covers all changed source, tests, notes, index, inventory, scripts and
pre-seal raw logs/command records. Only the manifest itself and the final
`seal-check.log`/`.json` checksum receipt are excluded to avoid circular
self-hashes; these remain covered by the published Git tree. The check
script reconstructs the source-only tree using a temporary index, so it
does not require an unreachable pre-evidence tree object in a fresh clone.
Full ordinary and profile-aware whitespace checks remain non-passes;
raw formatter/install/test/whitespace outputs are not normalized or
deleted to obtain an apparent pass. Final post-commit checks and direct
remote/worktree status are reported on delivery.

No main update, PR, merge, force-push, release, deployment, live node/network,
operational key use, signing-service activation or quarantine wiring is
part of this candidate.
