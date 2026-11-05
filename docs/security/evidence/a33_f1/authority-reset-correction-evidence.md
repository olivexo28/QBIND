# Bounded authority-reset audit/marker separation correction

**IMPLEMENTED — INDEPENDENT REVIEW PENDING.**
A33-F1 / E27 and all other unresolved obligations **OPEN**.
Activation **DISABLED**; public DevNet **NO-GO**.

## Entry, producer and historical distinction

Repository `olivexo28/QBIND`, existing branch
`copilot/a33-f1-bounded-eviction`. Starting/producer-parent commit
`e8f58a5c391f282c1996f4306c02743ace056fa5`, tree
`79d70e25bbdfeae5e3168d5f7c7ddb7887c20fb4`, parent
`6597596abe69f739ec5d3130cdb20413f0cf0c36`.
Repository URL, branch, exact local/remote task tip, protected local/remote
main and clean worktree/staging all matched before editing. Protected main
remains `c9aaef40b045e896ddfa8b01bad230f6b680715e`.
No reset, overwrite, discard or force update was performed.

The [historical baseline](authority-reset-collision-evidence.md) and its raw
bytes are unchanged. Its two tests passed assertions of existing behavior:
equal-path refusal replaced the marker, distinct-path refusal preserved it.
That baseline pass was **not a security pass**. The current test assertions
instead require unchanged, loadable marker bytes in every tested case.

## Enforcement and filesystem profile

The correction is in
`crates/qbind-node/src/pqc_authority_state_reset.rs`.
`execute_authority_state_reset` checks separation before input verification.
Every `write_authority_reset_audit` call also checks, before serialization,
directory creation, temporary-file write or rename. This covers pending,
verification-refusal, persistence-refusal and final-success audit calls.
The low-level exported writer now requires `data_dir` explicitly; all
repository callers are updated. The verifier itself retains its existing
input semantics and does not publish audits.

The four inspected paths are audit final, audit
`with_extension("json.tmp")`, marker
`<data_dir>/pqc_authority_state.json`, and marker temporary
`<data_dir>/pqc_authority_state.json.tmp` (the marker writer appends `.tmp`,
not `with_extension`). Each parent must exist, canonicalize and be a
directory. A leaf must be absent or a regular file; symlinks, directories
and other non-regular leaves refuse. Missing leaf is distinguishable from
an unavailable parent. Other metadata errors refuse.

Compare canonical-parent-plus-leaf paths, parent-directory
`(device, inode)` plus leaf names (also when leaves are absent), and
existing regular-file `(device, inode)` identities. Compare both audit paths against both
marker paths and against each other. This catches dot/parent spellings,
parent-directory symlinks and existing hard-link aliases, including an
audit temporary file that would otherwise truncate the marker. It uses
four fixed inspections and five pair comparisons, not an ancestry walk or
an unbounded directory scan. The tests' snapshot scans are fixture-only.

**Supported assumptions:** Linux, case-sensitive filesystem with ordinary
path/rename and reliable device/inode metadata semantics; stable,
operator-controlled directories; no concurrent namespace, mount, file or
hard-link modifications during the operation. Parent-directory symlinks
are allowed only under these same stability/ownership assumptions. Relative
paths additionally require a stable process working directory. Successful
checks do not establish those operational assumptions.

Other target operating systems explicitly return `UnsafeAuditPath`.
Case-insensitive/casefolded or unusual virtual/network filesystem
semantics, hostile local filesystem mutation, permission revocation,
concurrent resets, mount replacement and adversarial namespace races are
**unsupported**. Tests do not establish this profile on every Linux mount.
Canonicalization and inode inspection are time-of-check observations, not
held-descriptor fencing or protection against replacement between check and
write. Rechecking before publication catches supported changes *between*
calls; it does not eliminate intra-call TOCTOU races. No complete alias
coverage or hostile-filesystem guarantee is claimed.

## Observable changes and effect boundary

Unsafe or indeterminate separation returns typed `UnsafeAuditPath` and
attempts **no audit publication at that check**. It takes precedence over
malformed genesis hash and other later verification errors. Missing
`data_dir`/audit option returns its corresponding presence error before
verification; no unsafe fallback audit is attempted. Both directory parents
must already exist, including fresh data or audit directories; missing
parents now fail closed instead of being created by the audit writer.
This intentionally narrows reset admissibility without selecting an
initialization/migration procedure or changing marker persistence order.

For safe distinct destinations, normal malformed-hash refusal still
returns `MalformedExpectedGenesisHash` and publishes a separate refusal
audit. Refusal-audit write errors are now surfaced instead of ignored:
an `AuditWriteFailed`/`UnsafeAuditPath` can supersede the original
verification or marker-persistence refusal. No misleading success is
returned. Existing audit framing and pending → marker → success ordering
are unchanged. The marker-persist diagnostic no longer promises unchanged
bytes: failure after rename/directory sync can leave new marker bytes.
An error from the overall operation is **not** a general no-effects
guarantee, especially after marker persistence or prior audit publication.
No new durability claim is made for either writer.

## Actual corrected tests and limits

All tests use actual QBIND code, isolated `tempfile` directories, synthetic
loader-accepted marker JSON, and deliberately malformed expected hash.
No key generation, signing, operational data, live node or peer network.
Unsafe cases compare the entire owned fixture namespace before/after
(without following symlinks), in addition to exact marker/temp bytes.
They call the guarded writer with pending/refused/success audit-record
labels and require refusal with no publication for all three labels.
Those are writer controls, **not successful reset fixtures**.

Final focused suite: **6 passed; 0 failed; 0 ignored; 0 measured;
0 filtered out**, 48.45 seconds; **18 isolated scenarios**:

| Test/control | Actual result and marker/audit observations |
|---|---|
| Equal marker/audit path | `UnsafeAuditPath`; marker identical and loadable; no audit replaces it |
| Safe distinct path | `MalformedExpectedGenesisHash`; marker identical/loadable, separate refusal audit |
| Dot and child/parent spellings | `UnsafeAuditPath`; entire fixture unchanged |
| Audit final = existing marker temp | `UnsafeAuditPath`; marker and existing temp unchanged |
| Derived audit temp = marker temp, initially absent | `UnsafeAuditPath`; no file created |
| Hard-link audit final or audit temp to marker; audit temp to marker temp | `UnsafeAuditPath`; no truncation, rename or other fixture change |
| Parent symlink to marker directory | Collision refuses; symlink to a safely distinct audit name preserves normal refusal-audit behavior |
| Leaf symlink to marker | `UnsafeAuditPath`; symlink and marker unchanged |
| Missing/dangling/looping parent, non-directory parent, directory leaf | `UnsafeAuditPath`; no audit publication, repair or parent creation |
| Parent alias retargeted after a safe refusal audit | Earlier marker remains intact; pending/refused/success writer calls recheck and refuse, retaining earlier audit and namespace |

Existing authority-reset module regressions: **18 passed; 0 failed;
0 ignored; 0 measured; 2,204 filtered out**, 22.09 seconds.
No Linux cases were skipped. Non-Linux focused alias cases were not run
(the test file is Linux-only); the production branch on those targets is
explicit refusal, not claimed cross-platform test assurance.
Static bind-mount alias behavior was not runtime-tested; parent-identity
comparison avoids assuming canonical strings alone identify a directory.

**Full successful reset: UNTESTED.** The baseline investigation found no
reusable successful reset fixture; this task did not assemble matching
genesis, signed trust bundle and Strict-enforced ratification or weaken
validation. Enforcement occurs before verification and is repeated in the
shared writer used by final-success audit publication. Writer-label
controls verify that labels cannot bypass separation, not successful
ceremony execution. No startup, process-kill, power loss, race exploitation
or operational ceremony was run.

## Exact validation commands and retained attempts

Commands ran from `/workspaces/QBIND/olivexo28/QBIND`.
`rustc --version`, `cargo --version`, `uname -srmo` are retained in
[platform output](authority-reset-correction-platform.log).

```text
rustfmt --edition 2021 crates/qbind-node/src/pqc_authority_state_reset.rs crates/qbind-node/tests/a33_f1_authority_reset_audit_collision_tests.rs
cargo test -p qbind-node --test a33_f1_authority_reset_audit_collision_tests -- --nocapture --test-threads=1
cargo test -p qbind-node --lib pqc_authority_state_reset::tests -- --test-threads=1
rustfmt --check --edition 2021 crates/qbind-node/tests/a33_f1_authority_reset_audit_collision_tests.rs
python docs/security/evidence/a33_f1/authority-reset-correction-checks.py
git -c core.whitespace=cr-at-eol diff --check
git -c core.whitespace=cr-at-eol,-blank-at-eof diff --cached --check
(cd docs/security/evidence/a33_f1 && sha256sum -c SHA256SUMS)
```

Final commands exit **0**. Test merged stdout/stderr was redirected first
to session files and copied byte-for-byte to evidence:
[focused output](authority-reset-correction-focused-tests.log),
[regressions](authority-reset-correction-regressions.log).
[Formatting check](authority-reset-correction-format.log) is empty.
The source retains existing CRLF; unrelated rustfmt-only hunks and legacy
module-test formatting were restored. The check script compares the
new separation helper against `rustfmt --emit stdout --edition 2021`
and checks the complete integration test; it does not claim the legacy
whole source file is rustfmt-clean. Whitespace checking permits source
CRLF and Cargo's raw final blank line; raw evidence is not rewritten.
No dependency/lockfile change or new installation was needed for this task.

An [initial corrected suite](authority-reset-correction-intermediate-5-tests.log)
exited **0**, 5 tests/16 scenarios passed in 120.41 seconds. This was an
intermediate, not final coverage claim. The
[next attempt](authority-reset-correction-incomplete-registration.log)
exited **0**, but ran only **5 tests/17 scenarios**, 46.12 seconds:
the new recheck test was accidentally nested, with a compiler warning
that inner items cannot be tested. That attempt **did not execute the
recheck control** and is not counted as complete validation. Moving the
test to module scope and rerunning produced the final six-test result.
The [first six-test run](authority-reset-correction-intermediate-6-tests.log)
passed in 48.67 seconds; the
[first 18-regression run](authority-reset-correction-intermediate-regressions.log)
passed in 22.47 seconds. Both were retained before a further source check
added parent-directory identity comparison for absent leaves. The focused
and regression suites were rerun against that final guard, producing the
48.45/22.09-second results above. This is not a new hostile-mount guarantee.
All outputs/warnings remain separately retained. There were no failed
test assertions in these runs; exit success alone did not establish
expected test registration. Full earlier A33/model/filesystem suites were
not rerun without relevance to this correction.

The initial preservation-check attempt exited **1**, detecting that the
new §38 had been inserted before older sections rather than appended.
Its [failed output](authority-reset-correction-checks-attempt-1.log) is
retained, not a passing check. Moving only the new section to EOF restored
the exact historical plan prefix. The corrected check script includes
that newly retained attempt log in its whitelist.

[Reproducible scope/check script](authority-reset-correction-checks.py) and
[raw checks output](authority-reset-correction-checks.log) verify local
links, expected executed counts, prefix preservation, legacy tests and
changed-path whitelist. Its pre-manifest-update hash listing is an
observation of that stage, not the final checksum manifest. It deliberately
does not hash its own output while being written. Final evidence hashes
are in `SHA256SUMS`; final commit/tree/parent and remote equality are
reported on delivery, avoiding self-referential commit claims.

Source SHA-256:

```text
f2ea732d5f6b8cb9627664fee315f08a027870446dfba127746ecdf28a04470a  crates/qbind-node/src/pqc_authority_state_reset.rs
305a16ec7ad177180c9a7964a99630df28a6d538cd2f3fe7df3b5654ad2f2fc0  crates/qbind-node/tests/a33_f1_authority_reset_audit_collision_tests.rs
```

Changed paths are the source and integration test above, append-only
`docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md` §38 and
`docs/security/evidence/a33_f1/SHA256SUMS`, and the twelve new
`authority-reset-correction-*` evidence/check files enumerated by the
script/output. Historical evidence, audit register, previous plan bytes,
authentication/signing/crypto/operational gates remain unchanged.
No quarantine store, startup gate, codec, recovery, clear/resume,
currentness or signer-fencing mechanism is introduced.
