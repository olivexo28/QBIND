# A33-F1 startup route model — SRM-3 correction

**TEST-ONLY SYNTHETIC MODEL — INDEPENDENT REVIEW PENDING.** This correction
addresses restore-route refusal classification only. It does not execute
production startup or establish production fencing, durability, identity
authority, or safe restart. SRM-1 and SRM-2 remain PASSED/CLOSED WITH
LIMITATIONS only in their specified normal-route scenarios. TDI-1 and
TSL-1/2/3/4 retain prior scoped closures. Transport, A17-F1 / RS1-F7, RS1 and
A33-F1 / E27 remain OPEN; activation remains DISABLED; public DevNet remains
NO-GO.

## Provenance and changed paths

Repository: `olivexo28/QBIND`.

| Item | Revision |
|---|---|
| Required starting commit | `13683dd7eea674c6d6340bfad18922495ebd4ff6` |
| Required starting tree | `5dd00e7712a07776ebf42fd4957b8d9bd2e65e28` |
| Test-code commit used for executions | `22d5cb21f9b804bf6f4109842ea9c0f89b836a9b` |
| Test-code tree used for executions | `f11c8edc7d55c1d11178f76b536b5904f130811b` |
| Test-code commit parent | `13683dd7eea674c6d6340bfad18922495ebd4ff6` |
| Pinned startup-source baseline | `0d1b56515c52abe2862064027d1a9f103fef5a0c` |
| Pinned startup-source tree | `b3e8914e6ff234afd80fd29b58470c43f2b08009` |
| Task branch | `test/a33-f1-startup-route-classification-model` |

Preflight confirmed the expected branch, commit and tree, a clean worktree, and
the remote branch at the expected starting commit. The test-only source was
then committed before running the checks, so both successful command outputs
are bound to `22d5cb21…` / `f11c8edc…`, not to an uncommitted working tree.

Changed paths for the correction and evidence:

- `crates/qbind-node/tests/a33_f1_startup_route_classification_model.rs`
- `docs/security/evidence/a33-f1-startup-route-classification-model-srm3-20261108.md`
- `docs/security/evidence/a33-f1-startup-route-classification-model-srm3-focused-output.txt`
- `docs/security/evidence/a33-f1-startup-route-classification-model-srm3-compile-output.txt`

The prior SRM-1/SRM-2 evidence and logs were not modified.

## SRM-3 behavior and controls

For `Route::RequestedRestore`, the shared `check_trace` checker now requires
the full restore event sequence only when the classification decision is
`AdmitSyntheticTrace`. A refusal can therefore follow modeled directory
creation and normal destination ownership, record the refusal observation,
and exit without fabricating later restore effects.

The new refusal test uses the same checker for each of the five existing
refusal observations: `Absent`, `CorruptOrInvalid`, `Unreadable`,
`ForeignOrAmbiguous`, and `Unresolved`. Each refusal trace uses a separately
modeled `IdentityClaims::synthetic_trusted()` fixture; those claims do not
override the record observation or grant real authority. The controls verify:

- a refusal followed by exit and no protected effects is accepted;
- a protected restore effect after refusal produces
  `ProtectedEffectAfterRefusal`; and
- storage before the refusal classification produces
  `ProtectedEffectBeforeClassification`.

For a continuing synthetic restore, the same checker still requires the
complete ordered sequence: consensus-storage open, restore-record check,
restore `INTENT`, account-state materialization, snapshot epoch persistence,
and restore `COMPLETE`. New controls show that omission of `COMPLETE` and
reordering restore `INTENT` before the restore-record check produce
`RestoreEffectsOutOfOrder`. The existing positive continuing restore remains
the positive control.

The restore source sequence is pinned to
[`main.rs:2619-2649`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2619-L2649)
(requested restore opens consensus storage),
[`main.rs:2776-2857`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2776-L2857)
(restore-record precondition and `INTENT` before guarded restore),
[`main.rs:5227-5257`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L5227-L5257)
(snapshot epoch persistence), and
[`main.rs:5260-5358`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L5260-L5358)
(restore `COMPLETE`). These are source-order references, not evidence that
the proposed Timeout classifier exists or is enforced. Restore ordering
remains separate from ordinary startup's metrics-task/storage ordering
([`main.rs:5025-5031`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L5025-L5031),
[`main.rs:5180-5197`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L5180-L5197)).

## Checks and retained outputs

Focused command:

```text
cargo test -p qbind-node --test a33_f1_startup_route_classification_model -- --nocapture
```

Exit code **0**, **13 passed, 0 failed**. The full output, warnings included,
and command exit code are retained in
[`a33-f1-startup-route-classification-model-srm3-focused-output.txt`](a33-f1-startup-route-classification-model-srm3-focused-output.txt).

Compile-only command:

```text
cargo test -p qbind-node --test a33_f1_startup_route_classification_model --no-run
```

Exit code **0**. The full output, warnings included, and command exit code
are retained in
[`a33-f1-startup-route-classification-model-srm3-compile-output.txt`](a33-f1-startup-route-classification-model-srm3-compile-output.txt).
Both outputs were generated from source commit
`22d5cb21f9b804bf6f4109842ea9c0f89b836a9b`, tree
`f11c8edc7d55c1d11178f76b536b5904f130811b`. The builds reported existing
dead-code warnings in `qbind-consensus` and `qbind-node`.

`rustfmt --check --edition 2021
crates/qbind-node/tests/a33_f1_startup_route_classification_model.rs` and
`git diff --check HEAD^ HEAD` also succeeded. The prior 11/11 author-reported run and intermediate 9/11 failure are
historical evidence from the SRM-1/SRM-2 correction. They were not
independently rerun here, and their logs were not rewritten.

## Limitations

The model uses synthetic arrays, a synthetic positive record fixture and
synthetic identity claims. It does not execute the actual CLI or restore
route, open production storage, acquire a real destination lock, validate
identity authority, establish durability or fencing, or prove restart safety.
Acceptance of the synthetic continuation is not approval to start or resume a
real node.
