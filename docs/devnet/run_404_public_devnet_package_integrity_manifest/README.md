# Run 404 evidence archive — public DevNet package integrity manifest

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_404_public_devnet_package_integrity_manifest.sh` and contains
only publish-safe values: the schema / example-manifest / guide SHA-256 hashes and
the OK / POSITIVE status lines. **No secret key, private material, generated
identity, data dir, raw log, raw metrics dump, private endpoint, or absolute path
is committed.**

Regenerate locally with:

```bash
bash scripts/devnet/run_404_public_devnet_package_integrity_manifest.sh
```

**Decision gate = Route B** (docs + schema + verification harness; no production
Rust source change). Run 404 publishes the public DevNet **package integrity
manifest** — `docs/release/public-devnet/PACKAGE_INTEGRITY_MANIFEST.schema.json`
(draft-07 schema), `PACKAGE_INTEGRITY_MANIFEST.example.json` (a schema-valid example
whose per-file SHA-256 + byte size match the current on-disk tree), and
`PACKAGE_INTEGRITY.md` (the operator guide: how to regenerate the manifest, how to
verify file hashes, how it differs from binary provenance, why it is not a launch
artifact, why it moves no readiness item, why C4/C5 remain OPEN, and how to use it
before `OPERATOR_VERIFICATION_MAP.md`).

The manifest records `manifest_version`, `generated_for_run: 404`,
`scope: public-devnet-docs-release-package`, the eight safety labels
(`devnet`/`experimental`/`resettable`/`no_value`/`no_uptime_sla`/`not_launch_ready`/`c4_open`/`c5_open`),
`package_root: docs/release/public-devnet`, per-file entries
(`relative_path`/`sha256`/`byte_size`/`artifact_group`/`readiness_item`/`status`/`verification_reference`),
and the eleven explicit non-claim booleans (all `false`).

The harness verifies (21 checks): schema + example + guide exist and the guide is
safety-labelled; the manifest validates against the schema; every listed file path
exists, its SHA-256 + byte size match the on-disk file, and its `relative_path` is a
safe relative path resolving under `docs/release/public-devnet`; no absolute path,
private endpoint, or private/raw material (keys/certs/KEM/signing/API/logs/metrics/
data dirs/private identity) is embedded or committed; `ARTIFACT_INDEX.md` references
`PACKAGE_INTEGRITY.md`; `OPERATOR_VERIFICATION_MAP.md` references the package
integrity check; the readiness matrix still shows **M4 🟡; M6 🟡; S5 🟡; S7 🟡**;
the guide states public DevNet **NOT launch-ready** and **C4/C5 OPEN**; and the
non-claim grep passes.

This run adds integrity coverage **only**. It starts no node, opens no externally
reachable port, deploys no seed/bootnode/faucet/RPC/explorer/status service, changes
no wire format, weakens no peer admission, enables no peer-driven apply, adds no CLI
flag, and mutates no
trust/validator/epoch/sequence/marker/`LivePqcTrustState` state. **No** readiness
item moves Green. **M4** stays Yellow/launch-blocking, **M6** stays Yellow/Partial,
**S5** and **S7** stay Yellow, public DevNet remains **NOT launch-ready**, and
**C4/C5 remain OPEN**. TestNet/MainNet untouched.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_404.md`.