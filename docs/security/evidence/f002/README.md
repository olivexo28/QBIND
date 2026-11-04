# QBIND-A1-F002 bounded correction evidence

Status: **IMPLEMENTED — VERIFICATION PENDING**. Overall finding **OPEN**;
independent post-implementation review pending. Activation **DISABLED**;
public DevNet **NO-GO**. Section 13 of the
[remediation plan](../../QBIND_AUDIT_REMEDIATION_PLAN.md) contains the supplied
pre-implementation review verbatim, all 18 acceptance-category mappings,
actual results and retained residuals. That supplied review is source/design
review conveyed through the task conversation, not signed approval, an
external review URL, a human review or execution evidence.

## Revisions and production identities

Required baseline commit: `305640e0dffa16872692906af052dbf15937b192`;
tree: `6529ebb5d0cefeacdc3c047d85134fe755d011da`;
authoritative plan blob: `eb4787ce154564f17364a5442331b8299eeff4c6`.

Producing implementation/test revision:
`149edffd8f7fd97c821d6df9a5a546eca4992b79`;
tree: `d3872f17f033b32c5cfb451bc60d96979b0aec37`.
Its raw parent is the required baseline. Raw baseline parent is
`427c72a6bd2712b58c2777df2b26145463ef1257`, also actual advertised main at
entry and during evidence preparation. Available objects prove that ancestry;
main's raw parent `2e93ba7c202898f275703c94df8ed9677aa111e6` is unavailable
at the shallow boundary, so no ancestry beyond main is inferred.

`origin` fetch/push is `https://github.com/olivexo28/QBIND`, unchanged.
Fresh branch: `copilot/audit-f002-distinct-approval-fix`, created at the exact
baseline after verifying it was unoccupied and the entry checkout clean.
The contract was fetched from its existing branch, not assumed on main.
No applicable repository/ancestor AGENTS.md or other repository instruction
files were found. No unrelated work was modified.

Baseline and producing source blobs/modes are in
[toolchain-and-format.log](toolchain-and-format.log). Subsequent
documentation/evidence commits are not test-producing revisions. Their
actual final commit/tree, raw parentage, full baseline-to-final manifest,
main-at-completion and advertised pushed-tip equality are reported in the
delivery handoff, avoiding self-referential commit hashes in committed files.

## Baseline reproduction: separate isolated instrumentation

Before any production edit, a detached worktree at the required baseline was
created under the session files directory. Its tracked production was
unchanged; its tree was **instrumented**, not an unchanged baseline working
tree, by copying the delivered [baseline_probe.rs](baseline_probe.rs) to
`crates/qbind-gov/tests/f002_baseline_probe.rs`. No manifests changed.
The probe generates three pairwise-distinct disposable ML-DSA-44 keypairs
in memory, validates the 2-of-3 keyset and each envelope, and exercises both
public verification APIs.

Command, from the isolated checkout:

```sh
cargo test --locked -p qbind-gov --test f002_baseline_probe -- --nocapture
```

[baseline.log](baseline.log): exit **0**, **1 passed**, 0 failed/ignored.
Single approval: count 1 / false, wrapper rejects. Two distinct approvals:
count 2 / true, wrapper accepts. One genuine approval copied twice: count
2 / true, wrapper accepts, reproducing the pre-change mechanism.
The baseline source subtree is `b05691d0996fde3d7b5352301530605862a3562c`;
verifier blob `98c114623dcc09a1a2d505bf352e1705d4ba57de`;
digest blob `a68780a1353ce16275f5c7c470185ea3361adf7b`.
The delivered probe SHA-256 is
`44d04ac1cdbfdbc9395b42a5d61fe3a979728444b575bd0e837e782a3ac069be`.

An initial attempt used JSON class `C` instead of `c_hard_fork` and failed
parsing before signing/reproduction: exit **101**, 0 passed / **1 failed**.
[baseline-initial-failed.log](baseline-initial-failed.log) retains that
failure. The initial probe SHA-256 was
`a6b33dcec9677721d37129c734817f8d8eddb948a121a924d65e6100da94e42b`;
its only difference from the delivered corrected probe is that class literal.
This failed attempt is not evidence that the baseline defect was absent.

## Post-change authoritative focused checks

Executed after committing implementation/tests, against exactly the producing
revision above, from repository root:

```sh
cargo test --locked -p qbind-gov --lib --test envelope_cli_tests
rustfmt --check --edition 2021 crates/qbind-gov/src/verify.rs crates/qbind-gov/src/hash.rs crates/qbind-gov/tests/envelope_cli_tests.rs
```

[focused-tests.log](focused-tests.log): exit **0**, **36 library + 4 CLI
passed**, 0 failed/ignored/filtered. Thirteen new named tests cover the
18 matrix categories; test loops exercise additional cases. Existing tests
are retained. No code/tests changed after this authoritative run.
[toolchain-and-format.log](toolchain-and-format.log): rustfmt exit **0**,
exact source identities and configuration.

Toolchain: rustc 1.99.1 (`58cf8f9c3`), cargo 1.99.1, rustfmt 1.10.0-stable;
host/target `x86_64-unknown-linux-gnu`, LLVM 23.1.1. No cross target specified,
features/defaults unchanged, `--locked`; dev/test profiles use debug=0,
strip=debuginfo, incremental=false. No tracked Cargo config/toolchain file or
relevant target/profile/Rust flag environment override was present. No
dependency installation/restoration, manifest or lockfile change was needed.

Additional bounded checks, from repository root:

```sh
python docs/security/evidence/f002/check_scope.py
git -c core.whitespace=blank-at-eol,blank-at-eof,space-before-tab,cr-at-eol diff --check 305640e0dffa16872692906af052dbf15937b192
sha256sum -c docs/security/evidence/f002/SHA256SUMS
```

[check_scope.py](check_scope.py) checks protected sections 8/12 and all other
unmodified sections, finding rows other than F002, the audit register,
hash.rs production bytes, exact tested code bytes, permitted scope, existing
modes, LF/final-newline conventions, relative documentation links, whitespace
and available-object ancestry. Its actual output is
[scope-and-docs.log](scope-and-docs.log); it is a documentation/scope check,
not independent implementation review. The log checks the pre-evidence-commit
working bytes; it does not claim tests were rerun at a later summary HEAD.
Initial scope-check attempts caught the checker's own unflushed output and
verbatim CRLF configuration lines in the toolchain log. The checker now
flushes before inspecting files and permits intact CRLF records in logs
only; source/document LF rules remain strict. A checksum attempt before the
manifest refresh consequently reported stale README/checker hashes; the
delivered manifest is regenerated after the corrected successful scope run.
SHA manifest verification is performed after generating the manifest and
again at final delivery; its result is reported in the handoff.

## Delivered bytes, confidentiality and limits

[SHA256SUMS](SHA256SUMS) hashes the three producing Rust paths, updated plan,
this README, probe, checker and logs, using repository-root paths. It excludes
itself to avoid an impossible self-hash; its own SHA-256 is given in the final
handoff. No log redactions were necessary. Logs contain commands/results and
build paths only, no private keys, credentials, tokens or operational
signatures. Disposable test secret keys remain solely in process memory;
CLI temporary JSON contains only public keys/test signatures and is removed
by tempfile. No key material or generated fixtures are delivered.

Library residual tests are explicitly unvalidated characterizations, not
validated quorum fixtures. Exact member-ID uniqueness does not establish
distinct keys or independent operators. Keyset provenance, structural
admission by direct callers, algorithm policy, network binding,
freshness/replay, binary-check policy and operational authority remain
separate. No node, Run 384/385 harness, workspace-wide tests, scanner, live
exploit, upgrade execution or release run was executed. No PR, merge, main
push, force-push, deployment or activation was performed. No audit-register,
dependency, workflow or other production path changed. No deletions/renames
are intended; final scope is verified in the delivery handoff.

Only the implementation branch is to be pushed. Manual application should
review the identified files individually; a future local commit is not
claimed to share this task's SHA.
