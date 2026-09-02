# Run 407 evidence archive — public DevNet machine-readable anchor-drift artifact + CI retention policy

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_407_public_devnet_anchor_drift_json_retention.sh` and contains only
publish-safe values: the JSON drift schema SHA-256, the CI retention guide SHA-256, and
the OK / POSITIVE status lines. **No secret key, private material, generated identity,
data dir, raw log, raw metrics dump, private endpoint, or absolute path is committed.**
The generated full-tree manifest, the Markdown and JSON anchor-drift reports, and the CI
summary are written to staging directories **outside** the package tree (runner temp) and
are **never** committed — they are download-only CI artifacts.

Regenerate locally with:

```bash
bash scripts/devnet/run_407_public_devnet_anchor_drift_json_retention.sh
```

**Decision gate = Route B** (docs + schema + shell + YAML only; no production Rust source
change). Run 407 extends the Run 406 CI artifact wrapper (which reuses the Run 405
full-tree package integrity verifier) so CI can emit, as an additional **download-only**
artifact:

- `ANCHOR_DRIFT_REPORT.json` — a machine-readable JSON counterpart of the existing
  Markdown `ANCHOR_DRIFT_REPORT.md`, validated against
  `docs/release/public-devnet/PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json`.

It adds that JSON schema, `docs/release/public-devnet/PACKAGE_INTEGRITY_CI_RETENTION.md`
(the CI artifact retention guide), the harness, and updates the least-privilege
`.github/workflows/public-devnet-package-integrity.yml` to run the Run 407 wrapper and
upload the **four** publish-safe artifacts
(`PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json`, `ANCHOR_DRIFT_REPORT.md`,
`ANCHOR_DRIFT_REPORT.json`, `PACKAGE_INTEGRITY_CI_SUMMARY.txt`) with an explicit
`retention-days` value (`permissions: contents: read`; no secrets; no
deploy/release/tag/commit/push).

The harness verifies (29 checks): the JSON anchor-drift schema exists; the CI retention
guide exists + is safety-labelled; the Run 406 wrapper still passes; the full-tree
manifest, Markdown drift report, and JSON drift report are all generated **outside** the
tree; the JSON report validates against the schema; the JSON counts equal the Markdown
summary counts; every anchor entry exists in the full-tree set; there is no undocumented
mismatch; full-tree-only files are reported as **expected curated-anchor drift**; the CI
workflow uses `permissions: contents: read`, references no secrets, has no
deploy/release/tag/commit/push step, uploads only the four publish-safe artifact names,
and sets/documents `retention-days`; generated artifacts stay outside the tree and are
never committed; the working tree stays clean; the readiness matrix still shows **M4 🟡;
M6 🟡; S5 🟡; S7 🟡**; the retention guide states public DevNet **NOT launch-ready** and
**C4/C5 OPEN**; the non-claim grep passes; and no secret / private material / absolute
path / private endpoint is committed.

Retention is **convenience/audit usability only**: it keeps the download-only artifacts
downloadable for a bounded, provider-dependent window. It is **not** a signed attestation,
**not** binary provenance, and **not** launch evidence.

This run adds audit/reviewer usability **only**. It starts no node, opens no externally
reachable port, deploys no seed/bootnode/faucet/RPC/explorer/status service, changes no
wire format, weakens no peer admission, enables no peer-driven apply, adds no CLI flag,
and mutates no trust/validator/epoch/sequence/marker/`LivePqcTrustState` state. **No**
readiness item moves Green. **M4** stays Yellow/launch-blocking, **M6** stays
Yellow/Partial, **S5** and **S7** stay Yellow, public DevNet remains **NOT launch-ready**,
and **C4/C5 remain OPEN**. TestNet/MainNet untouched.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_407.md`.
