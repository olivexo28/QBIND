# I1 authority-reset marker / own-temporary-path separation

**I1 RESET PATH-SEPARATION CORRECTION — INDEPENDENT REVIEW PENDING.**

## Entry, review and correction

Repository `olivexo28/QBIND`, branch `copilot/a33-f1-bounded-eviction`,
local/direct-remote task tip
`c33132812646794de3640301e291313c6e182e04`, clean worktree/staging and
local/direct-remote protected main
`c9aaef40b045e896ddfa8b01bad230f6b680715e` were verified before changes.
The delivery commit/tree/parent are reported separately after committing,
avoiding self-referential evidence hashes.

The user-supplied review source-supports I1; the reviewer did not execute
a QBIND reproduction. The shared writer and its truncating temporary-file
behavior predate this branch and are unchanged from protected main.
Earlier audit-to-marker separation, reset error reporting, destination
ownership, E1, W1/W2 and catch-up controls remain accepted within their
recorded scopes. Full-branch integration approval remains withheld pending
I1 correction/review and integration-evidence disposition.

The sole production change is adding `(2, 3)` to the comparison pairs in
`crates/qbind-node/src/pqc_authority_state_reset.rs:1054-1064`:
`paths[2]` is the marker; `paths[3]` is its appended `.tmp` sibling.
The existing canonical-parent/name and device/inode checks now refuse
their identity collision as `UnsafeAuditPath`.

Enforcement remains in `check_authority_reset_audit_path`: the public
reset orchestrator calls it before input verification and any refusal,
pending or final audit/marker publication; the audit writer also calls
it before serialization/I/O, and the private verified sequencing seam
rechecks it. This adds no new verification bypass, writer or lock policy.
The existing Linux, case-sensitive, stable operator-controlled filesystem
profile and exclusions for hostile namespace/hard-link/mount races remain.

`pqc_authority_state::persist_authority_state_atomic` is unchanged. Direct
callers of that shared public marker writer are **outside this reset
guard's protection**. The public reset API still requires its caller to
hold destination ownership; the new test actually acquires `restore.lock`.
This is not a general hard-link/race fix, crash-durability guarantee,
quarantine/currentness authority or signer-exclusivity mechanism.

## Verified public-API fixture

The new separate test
`crates/qbind-node/tests/a33_f1_reset_marker_temp_identity_tests.rs`
follows the existing verified-success ceremony's fixture construction:
synthetic ML-DSA-44 keys, matching genesis authority and canonical genesis
hash, signed trust bundle and signed ratification, and real public input
verification. Existing accepted test bodies are unchanged; their
monolithic fixture was not refactored to expose new helpers.
Private keys remain in memory and are not serialized or logged.

The test holds a real destination lock, verifies inputs and calls the public
reset API once to establish a valid existing marker. It removes the initial
success audit, hard-links the marker's own `.tmp` name to the marker and
increments the informational marker timestamp so baseline byte changes are
distinguishable. Real verification still accepts these otherwise-valid
inputs. Audit final/temp and the destination lock remain distinct.

Before calling reset, it snapshots every directory entry's name, device,
inode, link count and bytes, and verifies marker/temp share identity and
bytes with link count two; both audit paths are absent.
On the corrected path the public API returns `UnsafeAuditPath`, the complete
snapshot is equal, the original marker is loadable/unchanged and no audit
paths appear. Source ordering locates that refusal before all reset writes;
the snapshot checks do not claim independent instrumentation of transient
I/O. The test then replaces only the temp hard link with a distinct stale
regular file, proves different inode identity, re-verifies inputs and
executes reset successfully. The expected new marker and final success
audit load, with no temp siblings remaining.

## Isolated executed baseline (not reviewer evidence)

The baseline source was exported with `git archive` at exact starting tip
`c33132812646794de3640301e291313c6e182e04` into a fresh Python
`TemporaryDirectory` outside the repository. Only the new test file was
overlaid. `CARGO_TARGET_DIR` reused the repository's build cache; all fixture
data remained in independently created temporary directories. The command:

```text
QBIND_I1_BASELINE=1 cargo test -p qbind-node --test a33_f1_reset_marker_temp_identity_tests -- --nocapture --test-threads=1
```

was run via `subprocess.run(..., timeout=300)` with stdout/stderr captured.
No timeout occurred; command completion was observed and both temporary
checkouts were removed on scope exit. Baseline mode has different, labelled
assertions and is not the corrected acceptance mode.

First attempt: exit **101**, **0 passed / 1 failed**. The public reset
returned success and changed bytes on the original inode, but the test
incorrectly expected a link count of one after rename. Actual count was
two. Raw `i1-marker-temp-baseline-attempt-1.log` is preserved. Linux rename
of these two names for the same inode does not remove either name. The
test's baseline expectation was corrected to check both remaining names,
shared identity, count two and identical changed bytes.

Final baseline: exit **0**, **1 passed / 0 failed** in the explicitly
defective-behavior observation mode. It confirms the starting public reset
accepted the valid hard-link fixture, changed marker/temp bytes on the
original shared inode, retained both names and published a success audit.
Raw `i1-marker-temp-baseline.log` is not counted as a corrected security
pass or production incident. No corruption window, crash or power-loss
outcome was exercised.

## Corrected commands and results

Linux x86_64, kernel `6.12.8+`; `rustc 1.99.1 (58cf8f9c3 2026-10-13)`;
`cargo 1.99.1 (5f94df478 2026-08-27)`. Compiler warnings remain in raw output.

```text
cargo test -p qbind-node --test a33_f1_reset_marker_temp_identity_tests --test a33_f1_authority_reset_audit_collision_tests --test a33_f1_authority_reset_verified_success_tests --test a33_f1_authority_reset_destination_lock_tests -- --nocapture --test-threads=1
```

Exit **0**: collision **6**, destination lock **5**, verified success **1**
and new marker/temp identity **1** passed; **13 total**, none failed or
ignored. Raw: `i1-marker-temp-focused.log`. Actual offline reset CLI child
controls are covered by the retained regression harness, not live nodes.

```text
cargo test -p qbind-node --lib pqc_authority_state_reset:: -- --nocapture --test-threads=1
```

Exit **0**: **22 passed**, none failed or ignored, **2205 filtered out**.
Raw: `i1-marker-temp-errors.log`. These include the independent
operation/audit error and persistence-stage controls.

```text
rustfmt --edition 2021 --check crates/qbind-node/tests/a33_f1_reset_marker_temp_identity_tests.rs
```

Exit **0**. Existing production source CRLF bytes are preserved; the source
diff is exactly one inserted comparison-pair line. No unsuccessful
corrected-path test attempts occurred. The unsuccessful baseline assertion
is explicitly retained above rather than omitted or counted as a pass.

## Scope, preservation and checksum interpretation

The plan and `SHA256SUMS` receive appended bytes only; all pre-existing raw
evidence, the existing integrity log, audit register and accepted tests are
preserved. The shared marker writer, CLI and all consensus paths are
unchanged. No full-branch integration approval is inferred.

The inherited manifest contains **219 entries**. This delivery adds eight
rows (production source, new test, updated plan, this record and four raw
logs), for **227 entries**. The ordinary full
`sha256sum --check SHA256SUMS` remains a **non-pass**; its actual exit/counts
and complete-scope whitespace results are reported with the delivery.
All eight appended current-file entries are checked separately.
Historical complete-file digests are verified against reachable producing
Git revisions separately, not treated as current-file matches.

The two disclosed intermediate integrity-log digests remain distinct:
`a00af7bbec3fde32bf29311565fa11ec363cfb66f1db1c294b6bc483ac680cb6`
matches the first 46,704 bytes and
`e1d10145b2f99b8c7ce0bb2f96215b577bbfeb90cfaf186df572d9e1849d4e3f`
matches the first 48,188 bytes. Prefix recoverability is not a current-file
pass or proof of a producing revision; those revisions remain unestablished.
The earlier 207/209/211-entry reports are pinned historical results, not
relabelled as full checks of this delivery.

No manifest self-hash or this record's own digest is embedded here. Raw
Cargo terminal blank lines and historical log whitespace remain unedited;
ordinary and profile-aware whitespace outcomes are distinguished.

Final delivery checks: ordinary full 227-entry checksum verification exited
**1**, with **175 OK / 52 FAILED**. Independent complete-file history
classification found **175 current**, **50 matching reachable producing
revisions**, **2 prefix-only entries with unestablished producing
revisions**, and **0 other unverified entries**. This does not convert the
ordinary non-pass to a pass. All eight appended hashes match current files.
Preservation checks confirmed the original **464,165 plan bytes** and
**24,967 manifest bytes** are exact prefixes, and all **158** pre-existing
non-manifest evidence files are byte-identical.

Ordinary staged `git diff --cached --check` exited **2**: the inserted CRLF
source line is diagnosed as trailing whitespace, the failed baseline raw
log has a trailing space on line 424, and the errors/focused raw logs have
terminal blank lines at 413/1081. The profile-aware
`git -c core.whitespace=cr-at-eol,-blank-at-eof diff --cached --check`
also exited **2**, solely for that preserved failed-attempt trailing space.
The source/prose-only CRLF-aware staged check exited **0**. No raw log was
edited to obtain a pass.

A33-F1 / E27 and all remaining obligations remain **OPEN**;
activation **DISABLED**; public DevNet **NO-GO**. No live node/network,
operational signing, deployment or activation was performed.
