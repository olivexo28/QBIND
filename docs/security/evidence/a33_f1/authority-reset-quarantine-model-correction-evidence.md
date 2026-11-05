# Corrected reset quarantine decision model

**CORRECTED TEST MODEL — INDEPENDENT REVIEW PENDING.**

## Entry and correction scope

Before editing, repository `olivexo28/QBIND`, branch
`copilot/a33-f1-bounded-eviction`, local/remote task tip
`ce2fa5f2c6239df60497ecb811fc5e38bc5f9f5a`, tree
`9aaf0eed7e0cb1abd20268d07f61d00fb269208f`, parent
`42b4c49e46c75f9ec8ffa758b4821bc3123aded5`, clean worktree/staging and
protected local/remote main `c9aaef40b045e896ddfa8b01bad230f6b680715e`
matched.

The correction is limited to the self-contained model
`crates/qbind-node/tests/a33_f1_authority_reset_quarantine_model_tests.rs`
and this append-only evidence/plan/checksum update. The previous evidence,
including `authority-reset-quarantine-model-tests.log` and the earlier
`authority-reset-quarantine-negative-control.log`, is preserved byte for
byte. No production code, existing tests, audit register, reset/CLI path,
quarantine implementation or authority was changed.

## Why the prior results were insufficient

At the previous producer, `classify(LocalCleanLooking, hypothetical authority)`
could overwrite `Decision::Refuse` with authorization despite an already
latched quarantine; `admit_write` did not consult `quarantine_latched`.
Consequently, a refusal followed by reclassification could allow reset
writes. The old `restart()` set the latch but left ownership, classification
and authorization fields intact; because write admission ignored the latch,
those process-local permissions could survive restart. The previous
negative control tested only a write before classification and did not share
one trace checker across writes before ownership, before classification and
after refusal. Thus the earlier passing test count did not validate the
requested latch, restart invalidation or full checker sensitivity claims.

The corrected model makes the latch dominant: later classification returns
Refuse when latched, write admission checks the latch, and `reset_result`
has no clear transition. Restart resets ownership/classification/decision
while preserving the latch. This is still only an abstract fixture; the
model's restart method does not prove process or storage persistence.

## Controls mapped to the correction

| Requirement | Corrected control | Observed outcome |
|---|---|---|
| Latched quarantine refuses every write after attempted reclassification | `reset_success_audit_marker_replacement_and_restart_never_clear_latched_quarantine` first classifies Applying/None to produce refusal/latch, calls reset result, attempts Clean-looking plus hypothetical authority, then all six reset-write stages. | PASS: later decision Refuse; every write admission false. |
| No reset success/refusal/audit/marker replacement/restart clears latch | Same test models both reset results, refusal/pending/final audit publication, marker replacement/acknowledgment, restart, reacquisition and another classification/write attempt. | PASS: latch persists; reclassification remains Refuse; all six writes remain refused. |
| Restart invalidates process-local authorization | `restart_invalidates_process_local_authorization_until_reacquired_and_reclassified` creates an unlatched hypothetical positive control, restarts, then tries each write before reacquisition/reclassification. | PASS: ownership/classified/decision reset; all writes refused until acquisition and classification repeat. |
| Reacquisition and classification may authorize only the explicitly hypothetical, unlatched model case | Same restart test, after a fresh modeled acquisition and reclassification. | PASS as a test-only sequencing control; not production authority. |
| Reacquisition/reclassification cannot clear a latched refusal | Latched test restarts, reacquires, reclassifies Clean-looking with hypothetical authority and attempts all six writes. | PASS: Refuse and no write admissions. |
| Shared checker accepts valid and rejects the three requested trace defects | `trace_is_valid` is used in the valid sequence test, in the three ignored failing sensitivity children, and the parent launcher confirms the same children fail. | PASS: accepts ownership → authorized classification → write; rejects write before ownership, before classification, and after refusal. |
| Negative-control output retained separately | Three direct ignored-child invocations are retained in `authority-reset-quarantine-model-correction-negative-controls.log`. | Each expected child failure exits 101 with its shared-checker diagnostic; not counted as a passing security outcome. |

The positive trace explicitly starts unlatched and uses
`HypotheticalApprovedCurrentAndReconciled` only as a hypothetical future
input. This does not claim that production authority exists, was selected,
or can be inferred from local Clean-looking bytes. There is still no clear
transition.

## Exact focused commands and results

```sh
rustfmt --edition 2021 crates/qbind-node/tests/a33_f1_authority_reset_quarantine_model_tests.rs
rustfmt --edition 2021 --check crates/qbind-node/tests/a33_f1_authority_reset_quarantine_model_tests.rs
cargo test -p qbind-node --test a33_f1_authority_reset_quarantine_model_tests -- --nocapture --test-threads=1
```

Exit 0: **9 passed, 0 failed, 3 ignored**. The three ignored tests are
deliberate failing child fixtures and are not counted as passes; the parent
sensitivity test launches each. Raw output:
`authority-reset-quarantine-model-correction-focused.log`.

The three sensitivity commands were each executed separately:

```sh
cargo test -p qbind-node --test a33_f1_authority_reset_quarantine_model_tests -- --ignored --exact negative_control_before_ownership_must_fail --nocapture --test-threads=1
cargo test -p qbind-node --test a33_f1_authority_reset_quarantine_model_tests -- --ignored --exact negative_control_before_classification_must_fail --nocapture --test-threads=1
cargo test -p qbind-node --test a33_f1_authority_reset_quarantine_model_tests -- --ignored --exact negative_control_after_refusal_must_fail --nocapture --test-threads=1
```

Each child exited **101 as expected** and failed with respectively:
`shared ordering checker rejected write before ownership`,
`shared ordering checker rejected write before classification`, and
`shared ordering checker rejected write after quarantine refusal`.
The wrapper returned success only after all three expected exits were
observed. Raw output with each exact command and exit status:
`authority-reset-quarantine-model-correction-negative-controls.log`.
The retained terminal captures have only trailing whitespace and extra
blank lines at EOF normalized; commands, diagnostics and exit outcomes are
unchanged.
The intentionally defective traces are sensitivity evidence only, not a
passing security result. Corrected shared-checker acceptance is reported
separately by the focused passing suite.

No unsuccessful test attempt occurred in this correction. No unrelated tests or
previously passing suites were rerun.

## Evidence boundary and untested behavior

All changed executable behavior is a self-contained model; no actual QBIND
reset orchestrator, destination lock, CLI, startup, filesystem, quarantine
store, storage, signer or transport path is called. The prior actual reset
and CLI tests are earlier evidence, not this correction's tests.

Modeled restart clears only process-local fields in one in-memory struct
while the fixture latch remains; it does not simulate process reconstruction,
filesystem persistence, crash, power loss or a real startup gate. Path
identity remains synthetic/lexical. No real filesystem alias, symlink,
namespace race or durability behavior is exercised. No real quarantine
record exists or is selected. Signer fencing, cancellation completion,
outbound delivery, network behavior and production currentness remain
unproved. No production marker, backend, gate, clear/resume, recovery,
network behavior, operational signing, deployment or activation was added.

Final documentation checks run after appending the record: targeted
`rustfmt --check`; an exact prior plan/manifest byte-prefix assertion;
`git -c core.whitespace=cr-at-eol,-blank-at-eof diff --check`; a manifest
integrity check described below; and an exact changed-path whitelist.

`cargo fmt --all -- --check` was also attempted and failed on existing
formatting differences in unrelated workspace files, beginning with
`crates/qbind-consensus/src/basic_hotstuff_engine.rs`; it did not modify any
files. The changed test itself passes the targeted rustfmt check. An initial
append-only check caught that this correction section had been inserted
between older plan sections; it was moved to the plan's end, after which the
exact starting-tip byte-prefix assertion passed. No source or evidence from
the preceding plan sections was rewritten.

The prior append-only manifest includes the hash of the model source at its
previous revision
(`772cc9df58bdeb052c56be30540c4db333e0ba1dc63f9bb0110e2501b7b60423`).
That historical line is deliberately preserved. The correction appends a
second hash for the current source
(`f13f88f6162695acf3c3aba1a98897d26c67b600e9ecedd50e28bd4507bf831b`)
rather than rewriting the original entry. Consequently
plain `sha256sum --check SHA256SUMS` now exits 1 on the historical source
hash (the newly appended current-source hash and all other entries pass).
Exact output is retained as
`authority-reset-quarantine-correction-manifest-check.log`; this expected
stale historical line is not silently described as a full standard-manifest
pass.

Final integrity commands:

```sh
python3 - <<'PY'
import hashlib, pathlib, subprocess
manifest = pathlib.Path("docs/security/evidence/a33_f1/SHA256SUMS")
base = pathlib.Path("docs/security/evidence/a33_f1")
source = "crates/qbind-node/tests/a33_f1_authority_reset_quarantine_model_tests.rs"
source_entries = 0
for line in manifest.read_text().splitlines():
    digest, name = line.split(maxsplit=1)
    if name == "../../../../" + source:
        source_entries += 1
        if source_entries == 1:
            data = subprocess.check_output(["git", "show",
                "ce2fa5f2c6239df60497ecb811fc5e38bc5f9f5a:" + source])
        else:
            data = pathlib.Path(source).read_bytes()
    else:
        data = (base / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest, name
assert source_entries == 2
print("manifest integrity with historical source hash anchored to entry-tip bytes: PASS")
PY
python3 - <<'PY'
import pathlib, subprocess
base = "ce2fa5f2c6239df60497ecb811fc5e38bc5f9f5a"
for path in ("docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md",
             "docs/security/evidence/a33_f1/SHA256SUMS"):
    assert pathlib.Path(path).read_bytes().startswith(
        subprocess.check_output(["git", "show", f"{base}:{path}"]))
print("append-only plan/manifest prefixes: PASS")
PY
git -c core.whitespace=cr-at-eol,-blank-at-eof diff --check
```

The custom manifest check treats the first source entry as historical and
verifies it against the prior source bytes at entry tip; the appended duplicate
source entry is verified against the corrected current source. All other
entries are checked against their files. The plan and manifest are checked
to retain the exact prior-tip bytes as prefixes. This preserves historical
evidence and provides a verifiable current-source digest without rewriting
history. Plain `sha256sum --check SHA256SUMS` is expected to exit 1 solely
because the preserved historical source hash targets the prior model; its
new current hash and all other manifest entries pass.
Final outcomes and final commit/tree/parent identities are recorded below
after commit. A33-F1 / E27 and all other unresolved obligations remain
**OPEN**. Activation **DISABLED**; public DevNet **NO-GO**.
