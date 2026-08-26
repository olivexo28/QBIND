# Run 377 evidence archive — public DevNet M4 live seed reachability (preflight)

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_377_public_devnet_live_seed_reachability.sh` and contains
only publish-safe values: the release-binary SHA-256, BuildID, toolchain, the
generated public `node_id`, and PARTIAL-POSITIVE / OK / REFUSED / NOT_PROVEN
status lines. **No secret key, root signing key, KEM secret key, private
material, data dir, or log is committed.**

Regenerate locally with:

```bash
bash scripts/devnet/run_377_public_devnet_live_seed_reachability.sh
```

All per-run artifacts (generated roots, certs, KEM secret keys, node data dirs,
logs) are written under a temporary `material/` + `node-data/` directory that is
removed on exit and is gitignored here as a backstop.

**Decision gate = Route B (Partial-positive).** Run 377 proves the `register-check
--status live --reachability-evidence <ref>` **admission gate** (accepts a live
candidate with an evidence reference; fails closed without it; fails closed on
`planned`+reachability) and a **loopback / same-host** reachability preflight of
the deployed `qbind-node` P2P listener. It does **NOT** prove external
reachability from outside the seed operator's own host/NAT, so **M4 stays
Yellow** and no committed seed entry is marked `status: live`.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_377.md`.