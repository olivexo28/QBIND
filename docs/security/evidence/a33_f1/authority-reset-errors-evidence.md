# Authority-reset stage-aware compound errors

**IMPLEMENTED — INDEPENDENT REVIEW PENDING.**
A33-F1 / E27 and all other unresolved obligations **OPEN**.
Activation **DISABLED**; public DevNet **NO-GO**.

## Entry and scope

Repository `olivexo28/QBIND`, existing branch
`copilot/a33-f1-bounded-eviction`. Starting/producer-parent commit
`6506faf18485769a2c852b7609149f908b807848`, tree
`335acda5ba0d43dec5e30c9d34c5754649209f5e`, parent
`e8f58a5c391f282c1996f4306c02743ace056fa5`. Before editing, repository
URL, branch, exact local/remote task tip, protected local/remote main and
clean worktree/staging all matched. Main remains
`c9aaef40b045e896ddfa8b01bad230f6b680715e`.
No reset, discard, overwrite or force update.

The [historical correction](authority-reset-correction-evidence.md) and
[baseline investigation](authority-reset-collision-evidence.md) are
preserved verbatim. This task corrects the former's error-precedence
behavior, not its path guard. Previous claims/results remain historical;
the original baseline pass reproduced a defect, not security assurance.

## Typed API and observable behavior

The existing `Result<AuthorityResetSuccess, AuthorityResetRefusal>` signature
is unchanged. `AuthorityResetRefusal` gains an inspectable
`AttemptFailed { stage, marker, operation_failure, audit_failure }` variant.
Both failure fields are independent `Option<Box<AuthorityResetRefusal>>`;
underlying typed primary and secondary errors remain available through
pattern matching. `stable_id()` returns `AttemptFailed`; `detail()` and
the existing `Display` expose stage, marker outcome and both errors.
Downstream exhaustive matches must handle the new enum variant.
CLI error exit remains 1 through its existing generic error arm, but its
diagnostic now retains both failure contexts instead of only the audit error.
No new persistent record format or audit JSON fields are introduced.

| Branch | Returned error context |
|---|---|
| Early presence/path guard refusal | Existing direct typed error; persistence not reached; no unsafe audit attempt |
| Verification refusal, audit succeeds | Existing original verification error |
| Verification refusal, refusal audit fails | `VerificationRefusalAudit`, `NotAttempted`, original operation error AND audit error |
| Pending audit fails | `PendingAudit`, `NotAttempted`, no operation failure, audit error |
| Marker persistence returns error | `MarkerPersistence`, `AttemptedUncertain`, primary `MarkerPersistFailed`, plus refusal-audit error if any |
| Persistence returns success, final success audit fails | `SuccessAudit`, `Acknowledged`, no operation failure, separate audit error |
| Both persistence and final audit return success | Existing `AuthorityResetSuccess` |

`AttemptedUncertain` is mandatory for any persistence error: no claim of
unchanged bytes, rollback or lack of effects is made even when an error
could have happened before rename. `Acknowledged` means only that the
existing persistence function returned `Ok`; it does not acknowledge the
final audit, power-loss durability or the complete reset ceremony.
Audit errors themselves can follow visible bytes. `audit_failure=None`
in the persistence-error context means the attempted refusal audit
returned success; the primary failure/uncertain marker still remains.

Production sequencing is shared via private functions. The public entry
calls the private entry with the real guarded audit writer. Real input
verification still gates the verified sequencing function; the production
persist closure calls the unchanged real marker writer. There is no
runtime flag, public bypass, injected success verifier or relaxed crypto.
The verified sequencing function also checks path separation on entry.
The exact path guard/audit writer/verification bodies and legacy module
tests are checked unchanged by the scope script.

The existing stable Linux, case-sensitive, operator-controlled filesystem
assumptions remain in force, with no concurrent namespace/mount/hard-link
changes. Other targets refuse. Missing parents and non-regular leaves
refuse; parent symlinks are resolved under those stability assumptions.
No hostile-filesystem, complete-alias or intra-call race protection is
claimed. No persistence order, codec, initialization, quarantine store,
startup gate, clear/resume, currentness or fencing redesign is introduced.

## Deterministic evidence and precise test layer

New private module tests live in
`crates/qbind-node/src/pqc_authority_state_reset_error_tests.rs`.
They use isolated `tempfile` directories, synthetic record fields, actual
QBIND audit/marker writers and deterministic closure-returned failures.
These injected errors are harness observations, **not OS-reported faults**.
No keys are generated, no signing occurs, and no operational data/node/
peer network is used.

| Control | What actually ran and was asserted |
|---|---|
| Verification + audit error | Actual entry/guard/verifier with malformed expected hash; test audit closure calls the real guarded writer, then returns an injected error **after visible audit bytes**. Both errors retained with `NotAttempted`; prior marker bytes remain unchanged |
| Persistence + audit error | Private shared verified sequencing receives a hand-constructed synthetic plan. Pending audit uses real writer. Persist closure calls real marker persistence successfully, then returns injected `MarkerPersistFailed`; refusal-audit closure returns a separate injected error. Result retains both errors, `AttemptedUncertain`; loader confirms marker bytes exist despite the error |
| Persistence error, successful refusal audit | Same sequence with real refusal-audit write; primary remains `MarkerPersistFailed`, marker remains `AttemptedUncertain`, secondary error absent |
| Acknowledged persist + failed success audit | Private shared sequencing calls real marker writer returning `Ok`; injected final-audit failure leaves prior pending audit. Result retains `Acknowledged` independently of audit failure, with no primary persistence failure |
| Pending audit failure | Private shared sequencing returns injected audit error; persist closure panics if invoked. It is not invoked; result says `PendingAudit`/`NotAttempted`; marker absent |

These are shared **production-sequencing seam tests**, not a separate
duplicate sequencing model. The first uses real verification but an
injected audit outcome. Persistence-stage cases **do not** pass real
genesis/trust-bundle/Strict-ratification verification: their synthetic plan
is constructed only inside the private test module. They are **not
end-to-end verified successful reset tests**. A complete valid success
fixture remains unavailable/UNTESTED as previously documented; no new
signing fixture was assembled or verification weakened. Actual rename,
fsync-error injection, device power loss, binary/CLI execution and full
startup are not tested by these controls.

Results:

* **22 module tests passed**, 0 failed/ignored/measured, 2,204 filtered:
  four new error tests (five scenarios) plus 18 existing reset regressions,
  111.13 seconds. Raw output exposes typed compound failures.
* **6 existing path tests / 18 scenarios passed**, 0 failed/ignored/
  measured/filtered, 47.42 seconds. Equal-path audit still refuses
  without marker change, and safely distinct audit remains available.
* No Linux controls skipped; non-Linux tests not executed. No unsuccessful
  test/build/check attempts occurred in this task. Previous tasks' failed
  attempts remain unchanged rather than being relabeled.

## Exact commands, artifacts and source pins

Commands from `/workspaces/QBIND/olivexo28/QBIND`:

```text
rustfmt --edition 2021 crates/qbind-node/src/pqc_authority_state_reset_error_tests.rs
rustfmt --emit stdout --edition 2021 crates/qbind-node/src/pqc_authority_state_reset.rs
cargo test -p qbind-node --lib pqc_authority_state_reset:: -- --nocapture --test-threads=1
cargo test -p qbind-node --test a33_f1_authority_reset_audit_collision_tests -- --nocapture --test-threads=1
rustfmt --check --edition 2021 crates/qbind-node/src/pqc_authority_state_reset_error_tests.rs
python docs/security/evidence/a33_f1/authority-reset-errors-checks.py
git -c core.whitespace=cr-at-eol diff --check
git -c core.whitespace=cr-at-eol,-blank-at-eof diff --cached --check
(cd docs/security/evidence/a33_f1 && sha256sum -c SHA256SUMS)
```

Commands exit **0**. Test stdout/stderr were redirected to session files
`authority-reset-errors-unit.log` and `authority-reset-errors-paths.log`,
then copied byte-for-byte to this evidence directory. Outputs:
[module tests](authority-reset-errors-unit.log),
[path tests](authority-reset-errors-paths.log),
[formatting](authority-reset-errors-format.log),
[platform](authority-reset-errors-platform.log),
[check script](authority-reset-errors-checks.py),
[check output](authority-reset-errors-checks.log).
New production error/sequencing sections are formatted against emitted
rustfmt output, while unrelated legacy formatting and CRLF remain intact;
the complete old source is not claimed rustfmt-clean. Whitespace checks
permit source CRLF and raw Cargo EOF blank lines without altering evidence.
No dependency/lockfile change, install or unrelated suite rerun.

```text
31858871b21358d1f8135bfc40fae347dbfbfafb685f4af3414ddcab9cf150e7  crates/qbind-node/src/pqc_authority_state_reset.rs
265f87fa5f4dcef855f65ea4554860805c298870c16c007ee9aed9a46556b216  crates/qbind-node/src/pqc_authority_state_reset_error_tests.rs
```

Full changed-path whitelist is emitted by the check script: production
reset source, new private test source, appended plan §39/manifest, and
seven new `authority-reset-errors-*` check/evidence artifacts. Every other
tracked byte, including audit register, old evidence and plan prefix,
is preserved. Manifest checksums cover new evidence; exact final commit,
tree, parent and remote verification are reported after commit rather
than embedded self-referentially. Only the existing task branch is pushed.
