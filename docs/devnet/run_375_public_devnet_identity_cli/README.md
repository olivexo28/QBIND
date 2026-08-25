# Run 375 evidence archive — first-class `qbind-node identity` command

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_375_public_devnet_identity_cli.sh` and contains only
publish-safe values: the release-binary SHA-256, BuildID, toolchain, short
(8-byte) node ids, and PASS/OK status lines. **No secret key, root signing key,
KEM secret key, full private material, data dir, or log is committed.**

Regenerate locally with:

```bash
bash scripts/devnet/run_375_public_devnet_identity_cli.sh
```

All per-run artifacts (generated roots, certs, KEM secret keys, node data dirs,
logs, metrics dumps) are written under a temporary `material/` directory that is
removed on exit and is gitignored here as a backstop.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_375.md`.