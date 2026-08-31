# Run 388 evidence archive — public DevNet M4 EXTERNAL seed reachability execution

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_388_public_devnet_m4_external_seed_reachability.sh` and
contains only publish-safe values: the release-binary SHA-256, BuildID,
toolchain, the generated public `node_id`, and the NEGATIVE-FOR-EXTERNAL / OK /
REFUSED / NOT_PROVEN status lines. **No secret key, root signing key, KEM secret
key, private material, data dir, or log is committed.**

Regenerate locally with:

```bash
bash scripts/devnet/run_388_public_devnet_m4_external_seed_reachability.sh
```

All per-run artifacts (generated roots, certs, KEM secret keys, node data dirs,
logs) are written under a temporary `material/` + `node-data/` directory that is
removed on exit and is gitignored here as a backstop.

**Decision gate = Route C (no safe external seed infrastructure available).**
Run 388 executes the **Route A** objective (real external reachability from an
independent off-host vantage point) but the sandboxed CI environment has **no
external ingress and no independent off-host vantage point**, so a real endpoint
cannot be exposed and external reachability cannot be proven. Run 388 still proves
the `register-check --status live --reachability-evidence <ref>` **admission gate**
(accepts a live candidate with an evidence reference; fails closed without it;
fails closed on `planned`+reachability) and a **loopback / same-host**
reachability preflight of the deployed `qbind-node` P2P listener (continuity with
Run 377/378). It does **NOT** prove external reachability from outside the seed
operator's own host/NAT, so **M4 stays Yellow** and no committed seed entry is
marked `status: live`. The Route A infrastructure prerequisites are documented in
`docs/release/public-devnet/network/reachability/RUN_388_qbind-devnet-seed-1.md`.
This finding is unchanged from Run 378; Run 386/387 preflight posture
(`signed_release=false`, `slsa_grade=false`) is likewise unchanged.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_388.md`.
