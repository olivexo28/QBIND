# A33-F1 startup-route model review package

**NARROW SYNTHETIC TEST PACKAGE — INDEPENDENT REVIEW PENDING.** This package
is not an integration proposal or production-startup implementation.
SRM-1/2/3, TDI-1 and TSL-1/2/3/4 retain their prior PASSED/CLOSED WITH
LIMITATIONS only in their reviewed scopes. Transport, A17-F1 / RS1-F7, RS1
and A33-F1 / E27 remain OPEN. Activation remains DISABLED; public DevNet
remains NO-GO.

## Source revisions and identity

| Purpose | Commit | Tree |
|---|---|---|
| Current main and source used for route anchors | `0d1b56515c52abe2862064027d1a9f103fef5a0c` | `b3e8914e6ff234afd80fd29b58470c43f2b08009` |
| Reviewed model endpoint | `f851d94fc1c9683b2886f828acc23292478a7cf9` | `8ff770ff5f643f49305288787af6c445503f10ab` |
| Reviewed final model source producer | `22d5cb21f9b804bf6f4109842ea9c0f89b836a9b` | `f11c8edc7d55c1d11178f76b536b5904f130811b` |

The required model test file is mode `100644`, blob
`99753735d8e0f3a514e870ccf4b4fc7187947216` at both the endpoint and source
producer. The package preserves that file's bytes. Its source contains only
synthetic test-model code; it does not call production startup.

## Complete package paths and purpose

Every listed path is mode `100644`. The route and review evidence below was
selected from the reviewed endpoint; retained raw logs are copied unchanged.

| Path | Purpose |
|---|---|
| `crates/qbind-node/tests/a33_f1_startup_route_classification_model.rs` | Standalone synthetic route/checker tests; source-producer bytes. |
| `docs/security/evidence/a33-f1-startup-route-classification-model-20261108.md` | Route/source inventory and SRM-1/2 model history. |
| `docs/security/evidence/a33-f1-startup-route-classification-model-srm-focused-test-output.txt` | Historical SRM-1/2 focused test output, including its exact recorded command output and 11/11 result. |
| `docs/security/evidence/a33-f1-startup-route-classification-model-srm-compile-output.txt` | Historical SRM-1/2 compile-only output. |
| `docs/security/evidence/a33-f1-startup-route-classification-model-srm-order-enforcement-failed-output.txt` | Preserved failed intermediate SRM-1/2 run; not a current failure. |
| `docs/security/evidence/a33-f1-startup-route-classification-model-srm3-20261108.md` | SRM-3 restore-refusal correction, source anchors, provenance and limitations. |
| `docs/security/evidence/a33-f1-startup-route-classification-model-srm3-focused-output.txt` | Historical SRM-3 focused run and full recorded output. |
| `docs/security/evidence/a33-f1-startup-route-classification-model-srm3-compile-output.txt` | Historical SRM-3 compile-only output. |
| `docs/security/evidence/a33-f1-startup-route-model-package-focused-output.txt` | Focused test output from the first extracted-package commit, including command, environment, test count, exit code and source commit/tree. |
| `docs/security/evidence/a33-f1-startup-route-model-package-compile-output.txt` | Compile-only output from the first extracted-package commit, including command, environment, exit code and source commit/tree. |
| `docs/security/evidence/a33-f1-startup-route-model-package-20261108.md` | This package manifest and provenance assessment. |

All retained source/evidence blobs, including the original raw logs, have
their exact Git identities available in the package commit tree. The original
route evidence and SRM-1/2 outputs are included here, rather than being
available only on the originating branch. The SRM-3 evidence and outputs are
also included. No raw historical log was edited or regenerated.

The committed author outputs at
`677284995048d9ec1a6c7ea098f0b934f745d371`, tree
`f794e424945d4e22b4156d4c83f37593c2d1d27a`, report 13/13 focused tests and
a successful compile-only check. Those complete committed outputs, including
their commands, environment and exit codes, are retained in the two package
validation output files above. Test and build inputs were unchanged through
the final package endpoint `77b842857fc914474f3d4b1fefa4fddfaa0610cd`.

A separately reported run against that final endpoint, and the exact bytes
attributed to that run, remain **AUTHOR-REPORTED AND UNVERIFIED**. Earlier
pasted output text and later-supplied output files had discrepancies; these
remain evidence limitations and do not supersede the committed author
outputs above. The output-transfer investigation is CLOSED. This record
does not request or reconstruct the earlier ZIP, and this correction does
not rerun those earlier final-tree checks.

## PR #11 follow-up controls

The PR #11 model corrections were tested from source commit
`d22e308793c4d301cebbb621c6a11fa36ac8e444`, tree
`3d7653eb6add23d3cc052e9912d7fb8d1e307c10`. The retained focused output
`a33-f1-startup-route-model-package-pr11-focused-output.txt` records
`cargo test -p qbind-node --test a33_f1_startup_route_classification_model
-- --nocapture`, 16 passed, 0 failed, exit code 0. The retained compile
output `a33-f1-startup-route-model-package-pr11-compile-output.txt` records
`cargo test -p qbind-node --test a33_f1_startup_route_classification_model
--no-run`, successful executable generation, exit code 0. Both records
include the Rust/Cargo versions and target. These output files and this
paragraph are evidence-only additions after the tested source commit; the
test file, manifests, lockfile and build configuration are unchanged.

The added same-checker controls reject nonterminal and duplicate Exit,
require a metrics-task event before consensus storage only for the modeled
ordinary normal route, and verify admission refusals for each nontrusted
identity field/value using the synthetic positive record fixture. A
test-only guard bypass makes the assertion for
`IdentityCannotSupportAdmission` fail. Restore ordering remains separately
modeled. No production path, identity authority, startup permission or
restart policy is established. Earlier SRM/TDI/TSL raw logs remain
byte-for-byte unchanged.

## Historical attribution and TDI-1 boundary

The earlier SRM-1/2 report records a final 11/11 focused run and an
intermediate 9/11 failure as historical author-reported evidence. It
describes the run as performed in a worktree based on `23ecb164…`; that
commit alone does not identify the producing test-source tree, because the
model test file was added later. This package does not claim that the earlier
run has an independently established producing tree or was independently
rerun. Its historical command outputs are retained verbatim. The separately
documented SRM-3 13/13 and compile-only executions were attributed to the
committed source producer and tree above; they are historical validations,
not runs of this extracted package.

The reviewed TDI-1 clarification was supplied as design context but is not
present in the original branch's Timeout durable-intent contract file. That
pre-clarification contract is not included in this package. This record does
not claim independent verification of a local-only clarification commit or
its tree.

## Scope, dependencies, and exclusions

The model depends on the existing `qbind-node` integration-test target and
workspace dependency graph to compile. It models normal startup, requested
restore, reset, no-data-directory and pre-participation early-exit traces with
synthetic events. Its positive identity/record fixtures are only checker
controls. It does not execute actual CLI routes, acquire a real destination
lock, establish production startup enforcement, identity/currentness
authority, durable storage, signer exclusivity, fencing, or restart safety.
The synthetic admission fixture grants no real startup, recovery or restart
authority.

The package intentionally excludes the separate
`a33_timeout_lifecycle` test module in
`crates/qbind-node/src/binary_consensus_loop.rs`, all Timeout lifecycle test
logs, the broader stay-closed/restart policy contracts, and the original
Timeout durable-intent contract. These are not dependencies of the synthetic
route checker. No production source, manifest or lockfile is included.

## Pinned source references

The model's source-order claims are against main commit
`0d1b56515c52abe2862064027d1a9f103fef5a0c`:

- Normal startup directory creation and destination ownership:
  [`main.rs:2515-2550`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2515-L2550).
- Normal metrics-task spawn and ordinary consensus-storage open:
  [`main.rs:5025-5031`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L5025-L5031),
  [`main.rs:5180-5197`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L5180-L5197).
- Requested restore storage open, restore-record/intent order, epoch
  persistence and completion:
  [`main.rs:2619-2649`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2619-L2649),
  [`main.rs:2776-2857`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2776-L2857),
  [`main.rs:5227-5257`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L5227-L5257),
  [`main.rs:5260-5358`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L5260-L5358).
- Separate reset ownership/effects:
  [`main.rs:2222-2281`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2222-L2281).
- Early identity dispatch and pre-lock utility exits:
  [`main.rs:2010-2025`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2010-L2025),
  [`main.rs:2305-2352`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2305-L2352),
  [`main.rs:2404-2449`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2404-L2449).

These are source-order anchors only. The proposed classifier is not wired,
and the model does not prove that the real routes obey its synthetic rules.
