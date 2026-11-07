# A17-F1 / RS1-F7 integration preparation

**INTEGRATION CANDIDATE PREPARED — INDEPENDENT REVIEW PENDING.**
A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain **OPEN**; activation
**DISABLED**; public DevNet **NO-GO**.

## Review provenance and preparation

The reviewer disposition **PASS WITH LIMITATIONS** is user-supplied.
No reviewer identity or unavailable raw review artifact is asserted.
The accepted scope covers admitted-snapshot, protected-state/outbound,
sensitivity and inactive-empty-response controls. It does not establish
allocation behavior, opaque optional internals, populated verified-evidence
resources or runtime assurance. No broader acceptance or hosted CI pass is
claimed.

Repository origin was verified as `https://github.com/olivexo28/QBIND`.
Before any change, direct remote main matched
`619a75fa8355692823802754f605e6c02bb57537`, tree
`a7d18a4bb4d40037e49042cb30c69a56e85ecd75`; local HEAD and direct remote
`copilot/a17-f1-catchup-containment` matched the reviewed endpoint
`9ef29e2432b9b84fca63e59440d64d085631e9a3`, tree
`f2521f571c2f5c6e64c0f4bdd9d88bdc18871233`. Worktree and staging were clean.
The endpoint's parent is implementation
`7d52477ce0eecff9f3fc80692eccbdee771cc81a`, tree
`057430ef7167a5d08ddb8807b36f86fe25540e66`; its parent and the verified
main/task common ancestor are `e584738c81814e70cbd58f80c921bea93983758c`.
Cached refs were not substituted for direct remote observations.

Executed preparation commands:

```text
git switch -c copilot/a17-f1-catchup-integration 619a75fa8355692823802754f605e6c02bb57537
git cherry-pick 7d52477ce0eecff9f3fc80692eccbdee771cc81a 9ef29e2432b9b84fca63e59440d64d085631e9a3
```

Both commits applied in order, exit 0, without conflicts or resolution edits:

| Carried change | New commit | Tree | Parent |
|---|---|---|---|
| Implementation | `6b80a7992c7a7f34706d8ec8c2be83fda526f171` | `edf0ca67088c6f70aff1a05e4bce4734f2f245be` | `619a75fa8355692823802754f605e6c02bb57537` |
| Accepted test endpoint | `fb27c7e7d864bbea8b91fb6c109872ca15aa6d77` | `29c5667a037c0e282cd0192074a390e46e5ac98b` | `6b80a7992c7a7f34706d8ec8c2be83fda526f171` |

The original task branch was not changed, rebased or rewritten. The final
documentation commit adds only this integration package atop the tested
revision; its exact commit/tree/parent and direct branch tip are reported after
publication. No main integration/merge or PR is performed by this task.

## Exact correspondence and comparison

`correspondence.log` records byte comparisons at the tested integration
revision. All 13 reviewed changed files are identical to the accepted endpoint.
The source prefix before `a17_node_id` is identical to the accepted
implementation, covering the actual production guard and corrected helper
comment. The A17 controls and all remaining source bytes match the endpoint.
Both existing documentation files still begin with their common-ancestor
historical bytes and match the endpoint completely. Every retained reviewed
evidence file, including raw logs and `SHA256SUMS`, is unchanged.

Both main additions remain byte-for-byte identical to protected main:
`docs/security/QBIND_DEEP_AUDIT_PLAYBOOK.md` and
`docs/security/QBIND_DEEP_AUDIT_TRACKER.md`. The audit findings register is
unchanged, as follows from the exact endpoint/main comparison. No production
behavior changed during integration preparation.

`reviewed-inventory.log` contains the complete main-to-carried-endpoint raw Git
comparison: old/new modes, old/new full blob IDs, status and path for all 13
reviewed paths. All existing files keep mode `100644`; every added file is
`100644`. No deletion, rename, executable or symlink change occurs.
Relevant endpoint blobs are preserved:

```text
8aa890c63412c7048ea6bb5a790ebcb9831c2013  crates/qbind-node/src/binary_consensus_loop.rs
f992242470abf2032092e974ae7949b95640c755  docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md
015634933ecba8de5923d68af2afc48304bd9d5d  docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md
fc0921fde6925ae6234b1c8b7b47e07587d18eed  docs/security/evidence/a17-f1-test-controls/SHA256SUMS
```

The sole additional directory is this evidence package. It is needed to
attribute the user-supplied review, pin the new integration execution, retain
complete new outputs, and describe comparison/limits without modifying prior
evidence bytes or invalidating the reviewed checksum manifest. No existing
plan or evidence document is appended again.

Complete final main-to-candidate path inventory (25 paths; all `100644`):

```text
M crates/qbind-node/src/binary_consensus_loop.rs
M docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md
M docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md
A docs/security/evidence/a17-f1-test-controls/README.md
A docs/security/evidence/a17-f1-test-controls/SHA256SUMS
A docs/security/evidence/a17-f1-test-controls/focused-attempt-1.log
A docs/security/evidence/a17-f1-test-controls/focused-final.log
A docs/security/evidence/a17-f1-test-controls/restore-regressions.log
A docs/security/evidence/a17-f1-test-controls/rustfmt-module.log
A docs/security/evidence/a17-f1-test-controls/whitespace-crlf.log
A docs/security/evidence/a17-f1-test-controls/whitespace-default.log
A docs/security/evidence/a17-f1-test-controls/whitespace-source-docs.log
A docs/security/evidence/a17-f1-test-controls/whitespace-staged.log
A docs/security/evidence/a17-f1-integration/README.md
A docs/security/evidence/a17-f1-integration/SHA256SUMS
A docs/security/evidence/a17-f1-integration/correspondence.log
A docs/security/evidence/a17-f1-integration/focused.log
A docs/security/evidence/a17-f1-integration/production-check.log
A docs/security/evidence/a17-f1-integration/restore-regressions.log
A docs/security/evidence/a17-f1-integration/reviewed-checksums.log
A docs/security/evidence/a17-f1-integration/reviewed-inventory.log
A docs/security/evidence/a17-f1-integration/rustfmt-module.log
A docs/security/evidence/a17-f1-integration/whitespace-default.log
A docs/security/evidence/a17-f1-integration/whitespace-full-crlf.log
A docs/security/evidence/a17-f1-integration/whitespace-source-docs.log
```

The new `SHA256SUMS` pins the entire package except itself. Final Git inventory
is independently obtainable with
`git diff --raw --no-abbrev 619a75fa8355692823802754f605e6c02bb57537 <final-commit>`.
Final blob IDs and the package manifest hash are reported after commit. The
manifest does not assert a self-referential checksum.

## New integration execution

All new tests and compilation ran at **`fb27c7e7d864bbea8b91fb6c109872ca15aa6d77`**,
tree **`29c5667a037c0e282cd0192074a390e46e5ac98b`**. These are fresh
integration-revision runs, not the earlier reviewed author runs. Each log
retains the exact command, complete combined stdout/stderr and exit status;
interleaving and diagnostics are not reconstructed or edited.

| Exact command | Output | Result |
|---|---|---|
| `env LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-node --lib a17_ -- --nocapture` | `focused.log` | Exit 0; 9 passed, 0 failed, 0 ignored, 0 measured, 2,227 filtered |
| `env LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-node --lib restore_mode_ -- --nocapture` | `restore-regressions.log` | Exit 0; 9 passed, 0 failed, 0 ignored, 0 measured, 2,227 filtered |
| `env LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo check --locked -p qbind-node --bin qbind-node` | `production-check.log` | Exit 0; dev-profile production target checked; existing dead-code warnings retained |
| `rustfmt --check --edition 2021 crates/qbind-node/src/binary_consensus_loop.rs` | `rustfmt-module.log` | Exit 1; existing formatting differences outside A17 |
| `git diff --check 619a75fa8355692823802754f605e6c02bb57537 HEAD` | `whitespace-default.log` | Exit 2; CRLF source/evidence additions and literal raw-log whitespace |
| `git -c core.whitespace=cr-at-eol diff --check 619a75fa8355692823802754f605e6c02bb57537 HEAD` | `whitespace-full-crlf.log` | Exit 2; retained raw-output whitespace |
| `git -c core.whitespace=cr-at-eol diff --check 619a75fa8355692823802754f605e6c02bb57537 HEAD -- "*.rs" "*.md" "*SHA256SUMS"` | `whitespace-source-docs.log` | Exit 0; scoped source/docs/manifests only, raw logs explicitly excluded |
| `sha256sum -c docs/security/evidence/a17-f1-test-controls/SHA256SUMS` | `reviewed-checksums.log` | Exit 0; all 12 reviewed manifest entries match |
| `git diff --raw --no-abbrev 619a75fa8355692823802754f605e6c02bb57537 HEAD` | `reviewed-inventory.log` | Exit 0; exact carried comparison |

No test, checksum or build attempt failed. The formatting and whitespace
non-passes remain non-passes, not success-shaped claims. Neither old nor new
raw logs are trimmed to manufacture a pass. No unrelated historical test
suite or workspace suite was repeated. No dependencies or source were changed
to make these checks pass. The final additional commit is evidence-only, so
the tested code revision remains exact.

## Security and runtime limits

The guard still rejects every non-empty successfully bound response after
receipt accounting and before helper application. Configured authority,
snapshot, mode, anchor, self-label or compatibility settings do not bypass it.
All non-empty network suffix imports, including honest suffixes, remain
refused: the catch-up liveness impact is intentional and unchanged.
Empty-response peer progress/mode effects remain characterized behavior,
not authenticated recovery or participation approval.

The admitted snapshot is synthetic, fixture-established and signerless.
Protected observations remain pinned diagnostic snapshots for the same
engine, not a canonical format or a complete heap inspection. Allocation
behavior, opaque optional internals, populated verified-evidence resources
and whole-node/concurrent effects remain outside accepted scope. The dev
compilation check is not a release artifact; no release binary or running
node was produced or inspected, no runtime revision was captured, and no
hosted CI result is claimed. No operational keys, signing, activation,
live network, PR, main push, force-push or original-task rewrite occurred.
