# Authority-reset audit/marker path collision: isolated baseline

**TEST-ONLY INVESTIGATION — INDEPENDENT REVIEW PENDING.**
A33-F1 / E27 and other unresolved obligations **OPEN**.
Activation **DISABLED**; public DevNet **NO-GO**.

## Revision and scope

Repository: `olivexo28/QBIND`.
Existing branch: `copilot/a33-f1-bounded-eviction`.
Starting/producer-parent commit: `6597596abe69f739ec5d3130cdb20413f0cf0c36`.
Starting tree: `3a3155972f013298ee3735d30371ccef735fa52d`.
Starting parent: `bf2e2020e981697e1fb44cf65fe44b6b57303767`.
Protected local/remote main: `c9aaef40b045e896ddfa8b01bad230f6b680715e`.
Repository URL, branch, exact local/remote task tip, protected main and clean
worktree/staging were checked before changes; all matched. No reset,
overwrite, discard or fast-forward was performed.

New test source:
`crates/qbind-node/tests/a33_f1_authority_reset_audit_collision_tests.rs`.
It calls the exported QBIND verifier and reset orchestrator without mocks,
patching validation, invoking the CLI or introducing a production helper.
Each case creates a new `tempfile::tempdir`, writes synthetic marker JSON
and first confirms that QBIND's marker loader accepts it. The fingerprints
are repeated synthetic hex, not keys or attestations. No key generation,
signing, live node, peer network or operational data is involved.
Successful tests explicitly close/remove only their own temporary directory.

## Source prediction, separate from runtime evidence

Anchors at the starting revision:

* `crates/qbind-node/src/pqc_authority_state.rs:188-198` names/resolves
  `<data_dir>/pqc_authority_state.json`.
* `crates/qbind-node/src/pqc_authority_state_reset.rs:554-603` checks input
  presence, MainNet policy and expected-hash syntax before genesis loading
  and before any marker derivation/persistence. The tests use Devnet with
  every required option present and `not-a-genesis-hash`; no input file
  load or successful trust/ratification verification is needed.
* `pqc_authority_state_reset.rs:925-956` writes audit bytes to
  `audit_path.with_extension("json.tmp")`, then renames to the supplied
  audit path. It does not compare the audit destination with the marker.
* `pqc_authority_state_reset.rs:980-993` catches verification refusal,
  builds a refusal audit with no verified plan, attempts the audit write
  (ignoring its result), then returns the original refusal.
* `pqc_authority_state_reset.rs:851-920` fills old-marker metadata as
  false/null when there is no verified plan. Such audit fields do not
  establish that a pre-existing marker was absent.
* `pqc_authority_state_reset.rs:1004-1022` orders the success branch as
  pending audit, marker persistence, final success audit. Equal audit and
  marker destinations therefore predict another replacement; this is
  **source-only**, not a runtime success result.
* `crates/qbind-node/src/main.rs:2221-2257` passes operator-supplied paths
  to the function. No CLI process/startup execution is tested here.

The comments promising marker non-mutation on any refusal are not enforced
for an equal supplied audit destination. No production comment or behavior
is changed by this task.

Pinned source SHA-256:

```text
68441f60fb88ea1b6d826831977a1ff720e1124a8abd01b0b8d2ec20ab3a4aa2  crates/qbind-node/src/pqc_authority_state_reset.rs
75ce5a368fc76ce6867ba112deb89afafd1c7b1840e3974154f48dc307938d12  crates/qbind-node/src/pqc_authority_state.rs
8e222c1e30a6a18f4089fc2e90fe49fb270ac02dd6a52b790f4175e6f88a8442  crates/qbind-node/tests/a33_f1_authority_reset_audit_collision_tests.rs
```

The reset and state source blobs are respectively
`3e1d6108643fbe2d27aad1d202c0979402676186` and
`ddee78fc25bc698452b2acf6287187c744670fca` at the producer revision.
The new test's hash identifies the test producer independently of a
self-referential final commit. Final commit/tree/parent are reported on
delivery after commit; the only production dependency is unchanged source.

## Commands and unsuccessful attempts

Commands ran from `/workspaces/QBIND/olivexo28/QBIND`.
Platform/toolchain details are in
[platform output](authority-reset-collision-platform.log).

1. `rustfmt --check --edition 2021 crates/qbind-node/tests/a33_f1_authority_reset_audit_collision_tests.rs`
   exited **1** (one formatting difference). The chained Cargo command
   did not run. [Output](authority-reset-collision-format-attempt-1.log)
   transcribes the tool-returned formatting diff (blank context line
   whitespace normalized); this is not a test result.
2. `rustfmt --edition 2021 crates/qbind-node/tests/a33_f1_authority_reset_audit_collision_tests.rs`
   exited **0** and applied formatting to this new test only.
3. With Bash `set -o pipefail`:
   `cargo test -p qbind-node --test a33_f1_authority_reset_audit_collision_tests -- --nocapture --test-threads=1 2>&1 | tee /root/.copilot/session-state/91b3e4989c9b42ca94b79c6910b46e5d/files/authority-reset-collision-focused-tests.log`
   exited **101** during native build, before any tests. Cargo retried
   dependency-download HTTP 500s and progressed, but `zstd-sys`/bindgen
   reported missing `libclang`. Raw merged output is retained as
   [failed build](authority-reset-collision-build-attempt-1.log).
   This is an unsuccessful build attempt, not a baseline reproduction
   or passing/failed test assertion.
4. After the missing-dependency failure:
   `apt-get update -qq && apt-get install -y -qq libclang-dev > /root/.copilot/session-state/91b3e4989c9b42ca94b79c6910b46e5d/files/authority-reset-collision-dependency-install.log 2>&1`
   exited **0**. Install output is retained
   [here](authority-reset-collision-dependency-install.log). The update
   printed a warning that `dl.google.com` could not resolve and old index
   files were used; this warning was returned by the tool, outside that
   redirected install log. No dependency manifest or lockfile changed.
   Dependency retrieval is not a QBIND peer/live-node experiment.
5. With Bash `set -o pipefail`:
   `cargo test -p qbind-node --test a33_f1_authority_reset_audit_collision_tests -- --nocapture --test-threads=1 2>&1 | tee /root/.copilot/session-state/91b3e4989c9b42ca94b79c6910b46e5d/files/authority-reset-collision-focused-tests-retry.log`
   exited **0**. Complete merged stdout/stderr is retained as
   [focused tests](authority-reset-collision-focused-tests.log), including
   existing compiler warnings, result, marker-before/after and audit bytes.
6. Final `rustfmt --check --edition 2021 crates/qbind-node/tests/a33_f1_authority_reset_audit_collision_tests.rs`
   exited **0**, [empty output](authority-reset-collision-format.log).

## Runtime results

**2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out.** Assertions
passed in 5.44 seconds after a native build of 5 minutes 49 seconds.
No tests were skipped. These are baseline reproduction/control passes,
not security passes. The earlier failed build ran no tests.

| Case | Actual function return | Marker observation | Audit observation |
|---|---|---|---|
| `refusal_audit_at_marker_path_replaces_synthetic_marker_baseline` | `Err(MalformedExpectedGenesisHash("not-a-genesis-hash"))` | **Changed** from loader-accepted synthetic marker to the exact refusal-audit bytes; marker loader then errors | Same file parses as `AuthorityResetAuditRecord`, `result="refused"`, matching refusal ID, no new-marker record/hash |
| `refusal_audit_at_distinct_path_preserves_synthetic_marker_control` | Same typed error | **Unchanged**, exact byte equality and still loader-accepted | Distinct file contains parseable refusal audit with matching refusal ID, no new-marker record/hash |

Each test separately invokes the actual verifier first, establishes that
verification refuses without changing marker bytes, then invokes the reset
orchestrator. Thus the write is reproduced in refusal audit handling,
not attributed to successful marker persistence. Exact bytes before/after
and audit JSON are retained in the raw test log. Both audit temporary paths
were absent after return, and temporary-directory cleanup succeeded.

Both audits report `old_marker_present=false` and old-marker fields null
because no verified plan existed. This source-described null-fill is not
evidence that the synthetic marker was absent: the tests loaded it before
the call. In the collision case the overwritten marker is not archived in
that refusal audit. No preservation/durability claim is made for it.

## Untested cases and limits

**Full successful reset: UNTESTED.** Source search for
`execute_authority_state_reset(` and `verify_authority_reset_inputs(`
across `crates/**/*.rs` found the orchestrator, CLI call and module tests
for presence/refusal/audit formatting, but no reusable successful
end-to-end reset fixture. Adjacent authority tests have signing helpers,
not a ready successful reset input bundle. A valid success would require
matching genesis/hash, signed trust bundle and Strict-enforced ratification
before marker derivation (`pqc_authority_state_reset.rs:642-746`).
No new signing fixture, operational key, bypass or relaxed validation
was created. The source-predicted final-success-audit collision is not
claimed reproduced by these refusal tests.

No path-alias matrix (symlinks, hard links, relative spelling, directory
replacement or concurrent filesystem actors), injected OS-write failures,
process-kill, power loss, durability, rollback, binary/CLI, startup,
production reset ceremony or later node participation was tested.
Audit timestamp and executable metadata are implementation-generated;
the tests compare exact before/after bytes from each invocation rather
than imposing deterministic values for that incidental audit metadata.
Test pass means the expected baseline/control assertions held, **not**
a fix, security pass or A33-F1 / E27 resolution.

Only the new test, new task evidence, append-only plan and checksum entries
are changed. Audit register, existing evidence, prior plan bytes and all
production source are preserved. No path rejection, quarantine backend,
startup gate, codec, recovery, fencing or clear mechanism is implemented.

## Documentation and preservation checks

The following exact Python body was run from repository root with stdout/
stderr redirected to `authority-reset-collision-scope-checks.log` in this
evidence directory. Exit **0**; this is a scope/documentation check, not an
additional Rust test. The changed-path whitelist also serves as the full
delivery path inventory (the test path plus evidence-directory entries,
plan and manifest).

```python
import pathlib, re, subprocess

base = '6597596abe69f739ec5d3130cdb20413f0cf0c36'
root = pathlib.Path('docs/security/evidence/a33_f1')
plan = pathlib.Path('docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md')
manifest = root / 'SHA256SUMS'
test = 'crates/qbind-node/tests/a33_f1_authority_reset_audit_collision_tests.rs'
names = [
    'authority-reset-collision-evidence.md',
    'authority-reset-collision-build-attempt-1.log',
    'authority-reset-collision-dependency-install.log',
    'authority-reset-collision-focused-tests.log',
    'authority-reset-collision-format-attempt-1.log',
    'authority-reset-collision-format.log',
    'authority-reset-collision-platform.log',
    'authority-reset-collision-scope-checks.log',
    'authority-reset-collision-scope-attempt-1.log',
    'authority-reset-collision-whitespace-attempts.log',
]
for path in (plan, manifest):
    old = subprocess.check_output(['git', 'show', f'{base}:{path}'])
    assert path.read_bytes().startswith(old), path
allowed = {str(plan), str(manifest), test} | {str(root / n) for n in names}
tracked = subprocess.check_output([
    'git', 'diff', '--name-only', base
]).decode().splitlines()
untracked = subprocess.check_output([
    'git', 'ls-files', '--others', '--exclude-standard'
]).decode().splitlines()
assert set(tracked + untracked) <= allowed, tracked + untracked
assert set(tracked) <= allowed
subprocess.run([
    'git', 'diff', '--exit-code', base, '--', '.',
    *[f':(exclude){path}' for path in sorted(allowed)]
], check=True)
links = 0
evidence = root / 'authority-reset-collision-evidence.md'
for path, text in (
    (evidence, evidence.read_text()),
    (plan, plan.read_text().split('## 37.', 1)[1]),
):
    text = re.sub(r'```.*?```', '', text, flags=re.S)
    for link in re.findall(r'\[[^\]]+\]\(([^)]+)\)', text):
        assert (path.parent / link).is_file(), link
        links += 1
assert len(re.findall(r'^```', evidence.read_text(), re.M)) % 2 == 0
log = (root / 'authority-reset-collision-focused-tests.log').read_text()
assert '2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out' in log
assert 'marker_bytes_changed=true' in log
assert 'marker_bytes_changed=false' in log
print(f'PASS: {links} local documentation links; balanced fences.')
print('PASS: historical plan/manifest prefixes preserved.')
print('PASS: tracked production/source/audit/evidence bytes unchanged.')
print('PASS: only whitelisted test/new evidence/append-only paths changed.')
print('PASS: retained focused output has 2 baseline/control passes and both marker outcomes.')
for path in sorted(allowed):
    print(path)
```

Additional exact commands, each exit **0**:

```text
git diff --check
git diff --cached --check -- . ':(exclude)docs/security/evidence/a33_f1/authority-reset-collision-dependency-install.log' ':(exclude)docs/security/evidence/a33_f1/authority-reset-collision-focused-tests.log' ':(exclude)docs/security/evidence/a33_f1/authority-reset-collision-format-attempt-1.log' ':(exclude)docs/security/evidence/a33_f1/authority-reset-collision-whitespace-attempts.log'
git -c core.whitespace=cr-at-eol,-blank-at-eol,-blank-at-eof diff --cached --check
(cd docs/security/evidence/a33_f1 && sha256sum -c SHA256SUMS)
```

The complete manifest includes these new evidence artifacts and their
SHA-256 hashes. Checksums of historical artifacts were reverified without
rerunning their earlier suites. No dependency manifest or lockfile,
production source, audit-register or old evidence bytes changed.

An earlier scope-check attempt exited **1** because its fence checker
counted the literal fence token inside its own embedded Python source.
It used the same body above without the scope-attempt log entry and with
`assert evidence.read_text().count('```') % 2 == 0` instead of the
line-anchored fence check. The failed output is retained as
`authority-reset-collision-scope-attempt-1.log`; it is not counted as a
passing check. Only the documentation validator was corrected.
The final scope check additionally whitelists the subsequently retained
whitespace-attempt log and excludes the explicitly whitelisted new files
from the tracked historical-byte comparison, so it also works after staging.

Default staged whitespace validation exited **2** on captured output:
CRLF/progress lines in the install log, the transcribed format diff's blank
context line, and Cargo's final blank line. A CR-aware retry also exited
**2**, on the latter two cases. Both outputs/statuses are retained in
`authority-reset-collision-whitespace-attempts.log`. These unsuccessful
checks are not relabeled passes. Raw log bytes are deliberately preserved;
standard staged checking of all other paths and full CR/blank-output-aware
checking pass with the exact commands above. No repository whitespace
configuration is changed.
