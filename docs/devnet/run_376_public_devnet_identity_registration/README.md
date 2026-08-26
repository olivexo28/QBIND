# Run 376 evidence archive — public DevNet identity registration / admission-check

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_376_public_devnet_identity_registration.sh` and contains only
publish-safe values: the release-binary SHA-256, BuildID, toolchain, and
PASS/OK/REFUSED status lines. **No secret key, root signing key, KEM secret key,
full private material, data dir, or log is committed.**

Regenerate locally with:

```bash
bash scripts/devnet/run_376_public_devnet_identity_registration.sh
```

All per-run artifacts (generated roots, certs, KEM secret keys, tampered test
fixtures) are written under a temporary `material/` directory that is removed on
exit and is gitignored here as a backstop.

`register-check` is a NON-MUTATING admission verifier: it reads public material
only, opens no socket, mutates no runtime state, and makes no live / reachability
/ M4 / C4 / C5 claim.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_376.md`.