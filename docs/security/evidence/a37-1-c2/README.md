# A37.1-C2 / A38-iv: bounded Run 216/227 verdict correction

**IMPLEMENTED — VERIFICATION PENDING.** Independent post-implementation
review is **PENDING**. E07 / OBL-GOV-2 remain **OPEN**; activation is
**DISABLED**, public DevNet **NO-GO**. This is isolated fixture evidence,
not successful QBIND Rust regression tests, a release-harness run, runtime
evidence, historical provenance, or independent acceptance.

## Producing identity and review boundary

The clean entry baseline was `f36e59a5e2cebab6fdfd0365920ca3e1a09444ac`,
tree `64011836fc74638590a8fda334f338c286156877`, raw sole parent
`0a35ef1fff2b7cdc15acddd9de8d5a01995418c7`. Origin fetch/push and
`gh repo view` identified `olivexo28/QBIND`; remote main matched the
baseline. The task branch did not already exist. Available history was
fetched: the raw parent is available and proven ancestral to the baseline.

The user supplied ChatGPT's completed bounded independent source/contract
review of `c176056a22a965b5d0411495a55a0517453fa907`, after corrections
to interruption guarantees and OUTDIR ownership assumptions. Its reported
tree equals the published baseline tree. That reviewed object is not in the
available fetched objects. Tree equality is not commit identity or ancestry;
manual publication has different parentage. No locally retrieved review
artifact, ancestry to that reviewed object, or post-implementation review
is claimed.

The controlling entry plan was blob
`d44b11fe875343cae49d2823c4f02d3733283f0a`, SHA-256
`87d6c75594571925eeac8867f7ce14f2bb0807efd47b6c70cfff0648a468315a`.
Its section 14 historical NOT EXECUTED statements describe preparation,
not these later executions.

**Implementation/test producing commit:**
`9b3458b7674140569b550fb7f6034fe0eb9a83f3`, tree
`55177a97b3cd0ad521cfe5d5400961652e6624d3`, sole parent the entry baseline.
The authoritative suite ran after that commit, with exact matching committed
script blobs and fixture bytes. The following evidence/documentation commit
changes no script or fixture. Its own identity and final remote equality
are reported in the delivery handoff, avoiding self-referential hashes.

## Executed commands and results

From the repository root, against that producing commit:

```bash
bash scripts/devnet/tests/run_216_227_regression_verdict_fixture.sh docs/security/evidence/a37-1-c2
```

The command was captured with `tee` under `pipefail`; suite exit **0**.
There were **94 actual harness invocations**: **4 baseline** (two controls
and two controlled defect reproductions) and **90 candidate** (45 per
harness). The harnesses attempted **1,694 guarded stub regression commands**
in total (94 baseline and 1,600 candidate). These are not Rust tests.
There were also **7 guard-calibration probes**; these are not additional
harness invocations. All 24 contract categories below are covered, with
overlapping categories referring to the same executions rather than
inflating counts.

Both positive controls reached regression and accounted for every required
command: Run 216, 35 integration plus two library commands; Run 227, eight
plus two. The pinned baseline copies, unmodified except temporary LF
normalization, returned overall PASS/exit zero even with injected first
regression status 17, after the earlier gates succeeded. This is a
**controlled fixture reproduction**, not evidence of historical failures.

The candidate continues safely capturable commands after ordinary failures,
retains exact numeric statuses, validates its literal invocation-bound
inventory, and refuses malformed/incomplete evidence. Baseline/candidate
raw and normalized identities are in [environment.json](environment.json).
Only LF-normalized temporary copies executed. LF syntax checks do not prove
execution of the committed CRLF bytes; raw CRLF `bash -n` diagnostics are
separately retained in [validation.json](validation.json).

| Contract category | Executed mode(s), both harnesses unless noted |
|---|---|
| All required commands succeed | `success`, `reuse_success`; exact 37 / 10 records |
| First integration failure | `first`, status 17 |
| Middle integration failure | `middle`, status 23, exact contract middle targets |
| Last integration failure | `last`, status 29 |
| First library failure | `lib_first`, status 31; second library still runs |
| Second library failure | `lib_last`, status 37 |
| Multiple failures then successes | `multiple`; first integration 17 and first library 31 |
| Missing required target | `missing`; explicit missing row, remaining commands run |
| Incomplete capture | `log_error`; log path is a directory, command not launched |
| Malformed stored result | `malformed_state`, `malformed_rc` (256), `manifest_header`, `unterminated`, `manifest_nul` |
| Duplicated stored result | `duplicate` |
| Stale stored result | `stale`, previous invocation ID |
| Missing/unincorporated result | `missing_row`, `unknown`; real validator refuses; successful cases check every summary row |
| Status/manifest I/O failure | `rc_io`, `manifest_io`; also `status_mismatch`, `status_missing`, `status_extra`, `status_nul` |
| Summary initialization I/O failure | `startup_write`, `startup_rename`, old PASS retained but explicitly untrusted; no work |
| Summary publication I/O failure | `final_write`, `final_rename`, current INCOMPLETE retained/repaired |
| Pre-existing PASS summary | All cases seeded; `seeded_pass_build_failure` explicitly stops before regression |
| Catchable interruption before publication | `before_INT`, `before_TERM`, `before_HUP`; observed 130 / 143 / 129 |
| Uncatchable termination before publication | `before_KILL`; observed signal termination -9; supervisor cleanup |
| Termination after PASS, before completion | `after_INT`, `after_TERM`, `after_HUP`, `after_KILL`; live harness synchronized after replacement |
| Command-substitution propagation | Actual direct parent-shell call sites checked; nonzero cases preserve statuses |
| Run 227 expected S6 rejection | Run 227 successful/complete cases retain scenario rc 2 and expected diagnostics, outside regression inventory |
| Successful-output compatibility | Successful/complete cases retain sections, paths, logs, numeric statuses; add ID, records and aggregate |
| Fixture isolation/guards and sequential reuse | Calibration plus every invocation; `reuse_success` then `reuse_failure`, after verified child cleanup |

Additional subcases are `failure_and_capture` (INCOMPLETE precedence over
an ordinary failure), `launch_failure` (controlled launcher-style status
127, not a claim that a real Cargo executable was missing), `early_build`,
`helper_fail`, `help_fail`, and `denylist`. Negative-case assertions check
the intended fault/gate, actual command sequence, process outcome and
summary, not merely any nonzero exit.

## Isolation, fault and signal evidence

The driver uses one temporary fake repository, copies scripts at their
expected paths, and changes only CRLF to LF in those copies. Fake textual
reachability files permit the existing grep gates; no Rust source is
compiled and these are not source-wiring proofs. Git, Cargo, rustc,
build-ID, node and helper invocations inside the harness are guarded stubs.
Only explicitly enumerated local utilities are executable through its PATH.
Network-capable commands are rejection stubs. `env`/`xargs` executable
selection and cleanup/rename paths are guarded. Calibration proves expected
rejections without invoking networking or out-of-root removal.

Each active OUTDIR is exclusive. No production bypass or script-body rewrite
injects faults: controlled stubs create directory/file conflicts, corrupt
stored records before validation, or deny a rename with a recorded nonzero
status. Actual redirection failures and explicit fault events are retained;
chmod alone was not used (the environment UID was 0).

Each harness is in its own process group. Normal completion is bounded at
30 seconds; signal completion has a four-second grace, then up to three
seconds for containment wait, with a three-second child-reaping bound.
The Linux subreaper supervisor verifies no group members remain before
OUTDIR reuse. All 94 cleanup checks passed. The 16 signal executions include
all three catchable signals and SIGKILL before and after publication.
Catchable cases observed exact exits 130/143/129, INCOMPLETE repair and no
supervisor timeout containment. SIGKILL cases observed -9; the harness
cannot run cleanup. After-PASS tests block the rename stub **after actual
replacement**, prove the harness is still alive, then signal its group.
After SIGKILL the matching-ID PASS remains, but parent-observed -9 explicitly
precludes successful completion. This is not a signal sent to an exited
process.

The production contract remains single-writer, with foreground Bash trap
deferral, best-effort repair, unavailable-storage/host-failure/SIGKILL limits,
and atomic visibility rather than crash durability. No locking, concurrency
support, cryptographic provenance, test-count certification or release claim
was added. No real Cargo, node/helper binary, build, Rust test, live network,
scanner, deployment, signing or activation ran.

## Retained files and reading

- [cases.json](cases.json): compact per-case outcomes, actual counts, faults
  and verified cleanup.
- [raw/run-216.jsonl](raw/run-216.jsonl) and
  [raw/run-227.jsonl](raw/run-227.jsonl): one exact case record per line,
  including invocation command/environment, stdout, stderr, guard events,
  summary, relative-path log/status/manifest contents and supervision/reaping.
  Logs are JSON strings, not reconstructed PASS assertions. Fixture paths
  are temporary paths already cleaned, not required live evidence locations.
- [suite.log](suite.log): authoritative supervisor transcript.
- [calibration.json](calibration.json): actual guard probes and rejection log.
- [environment.json](environment.json): actual producing revisions, script
  byte identities, fixture hash, commands, timestamps, tool versions and exit.
- [preliminary.log](preliminary.log) and [preliminary.json](preliminary.json):
  separate pre-commit calibration/reproduction/debugging, including failed
  preliminary attempts; not authoritative producing-revision results.
- [validation.json](validation.json): entry identities, protected-section and
  audit checks, syntax results, scope/modes/EOL/EOF, source inventory/scenario
  compatibility, local links, and changed-file identities.
- [SHA256SUMS](SHA256SUMS): final repository-relative changed-file checksums,
  excluding only itself. Run `sha256sum -c docs/security/evidence/a37-1-c2/SHA256SUMS`
  from the repository root. The checksum manifest's own identity is in the
  delivery handoff; there is no circular/self-referential hashing.

Raw evidence is bounded to this focused suite (under 12 MiB total).
For example, with Python's standard library:

```bash
python3 - <<'PY'
import json
from pathlib import Path
for line in Path("docs/security/evidence/a37-1-c2/raw/run-216.jsonl").read_text().splitlines():
    case = json.loads(line)
    if case["mode"] == "after_KILL":
        print(case["case"], case["parent_observed_returncode"], case["summary"])
PY
```

The [remediation plan](../../QBIND_AUDIT_REMEDIATION_PLAN.md#14-a371-c2--a38-iv-pre-implementation-contract-run-216227-regression-verdict)
records narrow supersession of preparation status and the unchanged open
historical/runtime/release obligations.
