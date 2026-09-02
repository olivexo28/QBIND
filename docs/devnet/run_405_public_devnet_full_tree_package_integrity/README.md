# Run 405 evidence archive — public DevNet full-tree package integrity verifier

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_405_public_devnet_full_tree_package_integrity.sh` and contains
only publish-safe values: the guide / schema SHA-256 hashes, the file-count, and the
OK / POSITIVE status lines. **No secret key, private material, generated identity,
data dir, raw log, raw metrics dump, private endpoint, or absolute path is
committed.** The generated full-tree manifest is written to a temporary directory
**outside** the package tree and is **never** committed.

Regenerate locally with:

```bash
bash scripts/devnet/run_405_public_devnet_full_tree_package_integrity.sh
```

**Decision gate = Route B** (docs + schema + shell + optional CI; no production Rust
source change). Run 405 adds the public DevNet **full-tree package integrity
verifier** — `docs/release/public-devnet/PACKAGE_INTEGRITY_FULL_TREE.md` (the guide),
`docs/release/public-devnet/PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.schema.json`
(draft-07 schema for the transiently-generated manifest), and the harness. It
addresses the honest Run 404 limitation that the committed anchor manifest lists only
one `VERIFY.md` per group plus the top-level docs, not every file: the verifier
generates a full-tree manifest covering **every** publish-safe file under
`docs/release/public-devnet`, validates it against the schema, and confirms coverage
and hashes — without committing the generated manifest.

The transient manifest records `manifest_version`, `generated_for_run: 405`,
`scope: public-devnet-docs-release-package-full-tree`, `coverage: full-tree`, the
eight safety labels
(`devnet`/`experimental`/`resettable`/`no_value`/`no_uptime_sla`/`not_launch_ready`/`c4_open`/`c5_open`),
`package_root: docs/release/public-devnet`, `file_count`, per-file entries
(`relative_path`/`sha256`/`byte_size`), and the eleven explicit non-claim booleans
(all `false`).

The harness verifies (21 checks): the full-tree guide + schema exist and the guide
is safety-labelled; the generated manifest validates against the schema; every
regular publish-safe file under the tree is included (and no extra path); every
`relative_path` is safe + root-confined; every SHA-256 + byte size matches on-disk;
the Run 404 anchor manifest still validates; `ARTIFACT_INDEX.md` and
`OPERATOR_VERIFICATION_MAP.md` reference full-tree integrity verification; the
external-operator read-order numbering is consecutive; the readiness matrix still
shows **M4 🟡; M6 🟡; S5 🟡; S7 🟡**; the guide states public DevNet **NOT
launch-ready** and **C4/C5 OPEN**; the non-claim grep passes; and no secret /
private material / absolute path / private endpoint is committed.

This run adds integrity coverage **only**. It starts no node, opens no externally
reachable port, deploys no seed/bootnode/faucet/RPC/explorer/status service, changes
no wire format, weakens no peer admission, enables no peer-driven apply, adds no CLI
flag, and mutates no
trust/validator/epoch/sequence/marker/`LivePqcTrustState` state. **No** readiness
item moves Green. **M4** stays Yellow/launch-blocking, **M6** stays Yellow/Partial,
**S5** and **S7** stay Yellow, public DevNet remains **NOT launch-ready**, and
**C4/C5 remain OPEN**. TestNet/MainNet untouched.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_405.md`.