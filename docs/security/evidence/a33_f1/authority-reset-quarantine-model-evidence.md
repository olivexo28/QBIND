# Reset-specific quarantine decision model

**TEST-ONLY RESET CONTROLS — INDEPENDENT REVIEW PENDING.**

## Entry and source mapping

Before editing, repository `olivexo28/QBIND`, branch
`copilot/a33-f1-bounded-eviction`, local/remote task tip
`42b4c49e46c75f9ec8ffa758b4821bc3123aded5`, tree
`ab72e6bb0d33f59a61dc967500f2268296a0dcad`, parent
`bc33bca493c154dac47c797c518b77290da61566`, clean worktree/staging and
protected local/remote main `c9aaef40b045e896ddfa8b01bad230f6b680715e`
matched.

The controlling boundary is
`authority-reset-quarantine-boundary.md`. Existing mechanisms were mapped
before adding tests:

| Existing source/model | Existing coverage | Missing reset-specific control now added |
|---|---|---|
| `crates/qbind-consensus/tests/a33_f1_stay_closed_quarantine_model_tests.rs` | Isolated catch-up lifecycle/effect model; generic latched state, restart and unknown worker outcomes. No reset writes, reset destination paths, CLI lock ordering or quarantine path preservation. | `a33_f1_authority_reset_quarantine_model_tests.rs`: reset write stages, lock-before-classification-before-write ordering, reset-specific latch non-clear, and synthetic destination-preservation matrix. |
| `crates/qbind-node/tests/a33_f1_authority_reset_destination_lock_tests.rs` | Real reset CLI and real advisory lock controls for contention, normal verification outcome, missing/unavailable destination and lock aliases. No quarantine classifier or marker. | No CLI test was changed or rerun. The new model explicitly states it does not call these actual paths. |
| `crates/qbind-node/tests/a33_f1_authority_reset_audit_collision_tests.rs` and `a33_f1_authority_reset_verified_success_tests.rs` | Actual reset audit/authority-marker collision guard, verified public reset and CLI success controls. No quarantine record or decision. | The model instruments refusal/pending/final audit, audit temp, authority marker and marker temp as distinct synthetic stages. |
| `main.rs:2222-2267` | Actual reset CLI: explicit data-dir, directory creation, destination lock, then reset invocation. No quarantine read/classification. | Model asserts the required abstract order and separately logs possible data-directory/lock-file creation. This is not a production ordering assertion. |
| `pqc_authority_state_reset.rs:1130-1248`, `976-1114`; `pqc_authority_state.rs:1308-1395` | Actual reset orchestrator can write refusal audit; successful path pending audit, marker/temp, final audit; refusal after persistence failure can write audit. | Model has six distinct write labels/targets: refusal-audit final, pending-audit final, final-audit final, audit temp, authority marker, marker temp. No production writer is called. |

The decision-boundary document and prior tests are unchanged by this task.
The new test is a separate `qbind-node` integration-test target, but it is a
self-contained abstract model. Cargo compiles the crate/test harness; test
logic does **not** call the reset orchestrator, destination lock, filesystem
writer, startup, signer, storage, network or real CLI. The earlier real CLI
tests remain prior-revision evidence and were not repeated here.

## Requirement-to-test mapping and observed results

| Requirement | Model control | Result |
|---|---|---|
| Ownership before classification and authorizing decision before every write | `ownership_then_classification_then_authorization_precedes_every_reset_write` | PASS. Events order ownership, classification/explicit hypothetical authority, then all six reset-write destinations. |
| Ownership failure prevents classification/reset writes; setup effects remain separate | `ownership_failure_skips_classification_and_reset_writes_but_records_setup_effects` | PASS. Models directory and lock-file creation before failed ownership; no classification or reset writer invocation. These setup artifacts are not quarantine observations. |
| Applying, recorded outcome, absent-only, malformed, unsupported, foreign, mismatched, unavailable, uncertain and local-Clean-looking without separate authority refuse | `every_local_observation_refuses_without_invoking_any_reset_write` | PASS for all 10 observations. No modeled reset writer invocation at any of the six stages. |
| Each reset stage instrumented | Ordering test and all-local-observation test | PASS for refusal/pending/final audit destinations, derived audit temp, authority-marker persistence and derived marker temp. |
| Reset cannot clear catch-up quarantine | `reset_success_audit_marker_replacement_and_restart_never_clear_latched_quarantine`; refusal test; cancellation test | PASS. Existing latch remains set after reset success/refusal, all audit stages, marker replacement/acknowledgment, restart, cancellation request, timeout and enqueue/unknown statuses. |
| Quarantine record/publication path preservation | `reset_write_destinations_cannot_alias_synthetic_quarantine_record_or_publish_paths` | PASS for equal path, lexical-equivalent `..` spelling, explicitly modeled parent-symlink alias, audit-temp collision, marker-final collision, marker-temp collision and indeterminate separation. Every modeled write stage is also checked against synthetic quarantine record, `.tmp`, and `.publish` paths. |
| Ordering control sensitivity | `negative_control_misplaced_write_before_classification_must_fail` (ignored in normal suite; invoked by parent) | EXPECTED FAILURE, exit 101: deliberately appended refusal-audit invocation before classification trips the ordering assertion. This defective outcome is not counted as a passing security result. |
| Corrected control after sensitivity check | `ownership_then_classification_then_authorization_precedes_every_reset_write` | PASS in normal suite; no production switch or weakened assertion. |

The local-Clean-looking positive authorization uses only the explicitly
named `HypotheticalApprovedCurrentAndReconciled` input to test ordering and
path guards. It is an abstract future authority input, not a claim that such
an authority exists, has been selected, or can be derived from a local
record. Without it, local-Clean-looking refuses like every other local
observation.

## Exact commands and retained output

Corrected focused controls:

```sh
rustfmt --edition 2021 crates/qbind-node/tests/a33_f1_authority_reset_quarantine_model_tests.rs
rustfmt --edition 2021 --check crates/qbind-node/tests/a33_f1_authority_reset_quarantine_model_tests.rs
cargo test -p qbind-node --test a33_f1_authority_reset_quarantine_model_tests -- --nocapture --test-threads=1
```

Exit 0. **7 passed, 0 failed, 1 ignored** (the deliberately defective
negative test is explicitly ignored in ordinary suite invocation and is
launched separately). Raw exact output:
`authority-reset-quarantine-model-tests.log`. The ignored test was not
counted as a pass. Existing compiler warnings are retained in that output.

Expected-negative control, separately:

```sh
cargo test -p qbind-node --test a33_f1_authority_reset_quarantine_model_tests -- --ignored --exact negative_control_misplaced_write_before_classification_must_fail --nocapture --test-threads=1
```

Expected exit **101**, one deliberately defective test failed with
`reset ordering control detected write before classification`. The wrapper
confirmed nonzero as expected. Raw output:
`authority-reset-quarantine-negative-control.log`. This is a sensitivity
demonstration, not a security pass. The standard focused suite separately
passes the corrected control and has no production switch.

Only test code, appended plan/evidence and checksum entries are in scope.
No prior test suites, builds beyond the focused Cargo target, production CLI,
filesystem alias tests, or model suites were repeated. No code change was
made after the focused tests; documentation/evidence changes were checked
for whitespace, scope and manifest integrity. Their exact commands and
results appear in the appended plan section.

Final documentation/scope checks:

```sh
rustfmt --edition 2021 --check crates/qbind-node/tests/a33_f1_authority_reset_quarantine_model_tests.rs
python3 - <<'PY'
import pathlib, subprocess
base = "42b4c49e46c75f9ec8ffa758b4821bc3123aded5"
for path in ("docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md",
             "docs/security/evidence/a33_f1/SHA256SUMS"):
    old = subprocess.check_output(["git", "show", f"{base}:{path}"])
    assert pathlib.Path(path).read_bytes().startswith(old), path
print("append-only prefixes: PASS")
PY
git -c core.whitespace=cr-at-eol,-blank-at-eof diff --check
(cd docs/security/evidence/a33_f1 && sha256sum --check SHA256SUMS)
python3 - <<'PY'
import subprocess
expected = {
 "crates/qbind-node/tests/a33_f1_authority_reset_quarantine_model_tests.rs",
 "docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md",
 "docs/security/evidence/a33_f1/SHA256SUMS",
 "docs/security/evidence/a33_f1/authority-reset-quarantine-model-tests.log",
 "docs/security/evidence/a33_f1/authority-reset-quarantine-negative-control.log",
 "docs/security/evidence/a33_f1/authority-reset-quarantine-model-evidence.md",
}
changed = set(subprocess.check_output(["git", "diff", "--name-only"]).decode().splitlines())
changed |= set(subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard"]).decode().splitlines())
assert changed == expected, (changed, expected)
print("scope: PASS", len(changed), "paths")
PY
```

Observed outcomes: rustfmt **PASS**; prior plan and manifest byte-prefix
check **PASS**; whitespace **PASS**; SHA-256 manifest **PASS, 103 entries**;
exact allowed-scope assertion **PASS, 6 paths**. No failed test/check
attempts occurred in this task.

## Model assumptions and evidence limits

All destination paths are fixed synthetic `PathBuf` labels under
`/synthetic-reset-model`. The model performs lexical `.`/`..` normalization
only. “Parent-symlink alias” and “indeterminate” are explicit supplied
separation outcomes, not symlinks, metadata checks, mount operations,
concurrent replacements or actual path resolution. The synthetic protected
publication set is `quarantine.record`, `quarantine.record.tmp`, and
`quarantine.record.publish`; production format/path is unselected.

This model does not establish actual alias coverage, race resistance,
filesystem durability, production reset ordering, startup coverage,
quarantine enforcement, signer fencing, process-crash safety, power-loss
behavior, storage completion or network delivery. A passing model cannot
prove that CLI or direct library calls consult quarantine. The public reset
function remains separate and does not acquire ownership/classify. Existing
direct calls and actual CLI behaviors are source/prior-test evidence only.

No quarantine marker, backend, production gate, clear/resume, recovery,
signer fence, network behavior, audit-register edit, operational key,
live node/network, deployment or activation was introduced. A33-F1 / E27
and all other unresolved obligations remain **OPEN**. Activation
**DISABLED**; public DevNet **NO-GO**.
