# Run 408 evidence archive — public DevNet retained anchor-drift history comparator

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_408_public_devnet_retained_drift_history_comparator.sh` and contains
only publish-safe values: the drift-history guide SHA-256, the diff schema SHA-256, and
the OK / POSITIVE status lines. **No secret key, private material, generated identity,
data dir, raw log, raw metrics dump, private endpoint, or absolute path is committed.**
The transient Run 407-style input fixtures, the reused Run 407 artifacts, and the emitted
`PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.json` are written to staging directories **outside**
the package tree (runner temp) and are **never** committed.

Regenerate locally with:

```bash
bash scripts/devnet/run_408_public_devnet_retained_drift_history_comparator.sh
```

**Decision gate = Route B** (docs + schema + shell only; no production Rust source
change). Run 408 publishes and verifies a **local, non-mutating historical comparator**
for retained Run 407-style `ANCHOR_DRIFT_REPORT.json` artifacts. It lets an
operator/reviewer compare **two** downloaded JSON drift reports (a base and a candidate)
and produce a publish-safe **transient** diff summary, **without** fetching CI artifacts
automatically, **without** any token or secret, **without** committing generated output,
and **without** changing any readiness status.

It adds:

- `docs/release/public-devnet/PACKAGE_INTEGRITY_DRIFT_HISTORY.md` — the comparator guide
  (how to download two retained reports manually; how to run the comparator; how to
  interpret added/removed full-tree-only paths; why full-tree-only drift can be expected;
  why missing anchors / undocumented mismatches remain failures; why the comparator is not
  binary provenance or launch evidence; why M4/M6/S5/S7 and C4/C5 are unchanged; and that
  retained artifacts are provider-dependent and may expire).
- `docs/release/public-devnet/PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.schema.json` — the
  draft-07 diff schema (`diff_version`; `scope: public-devnet-docs-anchor-drift-history-diff`;
  `base_report`/`candidate_report`; `package_root: docs/release/public-devnet`; a
  `count_delta` object; `path_delta` arrays of safe relative paths only; the four `verdict`
  enum values; the eight safety labels; eleven `non_claims` all `false`;
  `additionalProperties: false` throughout).
- the harness `scripts/devnet/run_408_public_devnet_retained_drift_history_comparator.sh`
  (`RESULT=POSITIVE`; 25 checks).

The comparator validates both inputs against
`PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json`, compares their counts and path
arrays, emits a transient `PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.json` **outside** the tree,
validates it against `PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.schema.json`, and classifies:
unchanged counts; added/removed full-tree-only paths; new/cleared missing anchors;
new/cleared undocumented mismatches; and changed documented refreshes. It **fails closed**
if either input has `non_claims` not all `false`, claims launch/readiness/deployment/runtime
mutation/TestNet-MainNet readiness/C4-C5 closure, or contains an unsafe/absolute/private
path — and if the candidate introduces a **new** missing anchor
(`negative-new-missing-anchor`) or a **new** undocumented mismatch
(`negative-new-undocumented-mismatch`); an unreadable/invalid input yields
`negative-invalid-input`. Added/removed **full-tree-only** paths are reported as expected
curated-anchor drift and are **not** a failure by themselves.

The harness verifies (25 checks): the guide exists + is safety-labelled; the diff schema
exists + is valid JSON; the Run 407 wrapper still passes; two Run 407-style reports
validate against the Run 407 schema; the comparator emits the diff **outside** the tree;
the diff validates against the Run 408 schema; safe relative-path rules hold for all diff
arrays; the positive no-new-failures case passes; the new missing-anchor and new
undocumented-mismatch fixtures fail closed; full-tree-only added/removed drift is reported
(not a failure); generated artifacts are not committed; the working tree stays clean; there
is no automatic CI/API fetch and no token/secret requirement; the readiness matrix still
shows **M4 🟡; M6 🟡; S5 🟡; S7 🟡**; the guide states public DevNet **NOT launch-ready**
and **C4/C5 OPEN**; no TestNet/MainNet readiness or deployment or runtime-mutation claim
appears; the non-claim grep passes; and the secret / private-material scan is clean.

This run adds audit/reviewer usability **only**. It starts no node, opens no externally
reachable port, deploys no seed/bootnode/faucet/RPC/explorer/status service, changes no
wire format, weakens no peer admission, enables no peer-driven apply, adds no CLI flag, and
mutates no trust/validator/epoch/sequence/marker/`LivePqcTrustState` state. **No** readiness
item moves Green. **M4** stays Yellow/launch-blocking, **M6** stays Yellow/Partial, **S5**
and **S7** stay Yellow, public DevNet remains **NOT launch-ready**, and **C4/C5 remain
OPEN**. TestNet/MainNet untouched.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_408.md`.
