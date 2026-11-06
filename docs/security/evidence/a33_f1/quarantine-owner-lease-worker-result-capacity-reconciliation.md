# E1 worker-result capacity evidence reconciliation

**E1 EVIDENCE RECONCILIATION — INDEPENDENT REVIEW PENDING.**

This documentation-only reconciliation is pinned to task commit
`e950c437acba6012614f1e369f1a0d68bd588229`, not to a later manifest.
Entry verification found the expected repository and task branch, clean
worktree/staging, matching local/direct-remote task tip, and local/direct-
remote protected main `c9aaef40b045e896ddfa8b01bad230f6b680715e`.

The user-supplied PASS WITH LIMITATIONS review closes the full/available-
capacity controls and bounded interpretation of `Recorded` within their
test-only scopes. W1/W2, P1/P2, substituted-snapshot, retirement and earlier
accepted controls remain closed within their reviewed scopes. The reviewer
did not rerun Rust tests or complete historical checksum verification.
No new production capacity or recovery assurance follows.

## Pinned bytes and independently verified results

Paths below are relative to `docs/security/evidence/a33_f1/`.
The pinned `SHA256SUMS` contains **209 entries**, including repeated paths;
these are manifest rows, not 209 unique files. Its SHA-256 is
`11625f202c0b31f5ab94e6b7d76b91b77a4132b723b51f3413eda5eda55b53d6`.
The pinned `quarantine-owner-lease-model-integrity.log` is **48,651 bytes**,
with full-file SHA-256
`9f682356169de4326dfb4f2ca400dfa375e2bebaf22c577b2dde5e4a0bd1fe2d`.

Both intermediate integrity-log entries were independently checked against
bytes read directly with `git show` from the pinned commit:

| Manifest row | Prefix length (bytes) | SHA-256 of exact prefix |
|---|---:|---|
| 207 | 46,704 | `a00af7bbec3fde32bf29311565fa11ec363cfb66f1db1c294b6bc483ac680cb6` |
| 208 | 48,188 | `e1d10145b2f99b8c7ce0bb2f96215b577bbfeb90cfaf186df572d9e1849d4e3f` |

Each prefix is shorter than the committed full log. These bytes are
recoverable from the committed log without depending on an unreachable
blob. A matching prefix or standalone blob does **not** establish a
producing Git revision and is **not** a current-file checksum pass.
The 11 reachable path-history revisions returned by
`git log --all --format=%H -- <integrity-log-path>` were inspected with
`git show`: neither intermediate digest matched a complete log in those
revisions. Their producing revisions remain unestablished; no retrospective
provenance is asserted, and unreachable history was not re-audited here.

Reproduction of the prefix checks:

```python
import hashlib
import subprocess

revision = "e950c437acba6012614f1e369f1a0d68bd588229"
path = "docs/security/evidence/a33_f1/quarantine-owner-lease-model-integrity.log"
data = subprocess.check_output(["git", "show", revision + ":" + path])
for length in (46704, 48188):
    print(length, hashlib.sha256(data[:length]).hexdigest())
```

Before any edits, all working files matched the pinned revision.
Running `sha256sum --check SHA256SUMS` in the evidence directory exited
**1**, with **160 OK and 49 FAILED** across the final **209 entries**.
Both prefix entries failed against the full log; row 209, the full-log
digest, passed. This independently reproduces the final ordinary checksum
**non-pass**, not a blanket integrity pass.

## Intermediate versus final reporting

The preserved integrity log reports an earlier **207-entry** intermediate
check as ordinary exit 1, 160 OK / 47 FAILED, and revision-aware totals of
160 current / 47 producing-revision matches / 0 unverified. Those statements
describe that earlier check, not the final committed 209-row manifest.

The author's final delivery reported **209 entries**, ordinary exit 1,
160 OK / 49 FAILED, and revision-aware totals of **160 current / 47
producing-revision matches / 2 unverified**. This follow-up independently
verified the final row count, ordinary exit/counts, complete-log hash and
both prefixes. It did **not** rerun the complete historical verification of
the reported 47 producing-revision matches. Those full historical totals
remain attributed to the author; prefix verification does not promote the
two intermediate entries into that category.

## Documentation delivery and preservation

The plan and manifest receive only appended bytes. The existing integrity
log, source, tests, audit register and every pre-existing raw-evidence file
remain unchanged. This record is separate from the preserved integrity log.
No Rust tests or builds are required or run for this follow-up.

The later delivery manifest appends exactly two rows: the updated plan and
this reconciliation. Its **211 entries** are distinct from the pinned
209-entry totals. No checksum of the manifest itself or of this record's
own checksum text is embedded here, avoiding a self-referential cycle.
Complete-delivery verification results are reported with the delivery;
the historical non-pass is not relabelled as a pass.

The later 211-entry manifest was actually checked with
`sha256sum --check SHA256SUMS`: **exit 1, 161 OK, 50 FAILED**.
The additional historical mismatch is the superseded plan digest, not a
change to the preserved integrity log. Both appended current-file entries
match. This is a full ordinary-check non-pass, not full historical
producing-revision verification. No historical mismatch is waived.

Preservation verification against the pinned commit found all **151**
pre-existing non-manifest evidence files byte-identical. The original
**460,414 plan bytes** and **23,806 manifest bytes** are exact prefixes of
the updated files. Only this record, the plan append and manifest append
are delivered. Changed-document trailing-space/tab scans and ordinary
staged `git diff --cached --check` exited **0**; preserved historical raw
logs were not rewritten or included as changed lines in that check.

A33-F1 / E27 and remaining unresolved obligations remain **OPEN**;
activation **DISABLED**; public DevNet **NO-GO**. No production capacity,
recovery, durability, worker reclamation, startup enforcement, signer
fencing or network-delivery assurance is established.
