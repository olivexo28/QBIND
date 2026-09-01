# Run 389 evidence archive — public DevNet security key-management + PQC trust-bundle bootstrap

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_389_public_devnet_security_key_trust_bootstrap.sh` and contains only
publish-safe values: the release-binary SHA-256, BuildID, toolchain, a generated **public**
`node_id`, and the OK / REFUSED / POSITIVE status lines. **No secret key, root signing key,
trust-bundle signing secret, KEM secret key, private material, data dir, or log is committed.**

Regenerate locally with:

```bash
bash scripts/devnet/run_389_public_devnet_security_key_trust_bootstrap.sh
```

All per-run artifacts (generated identities, roots, leaf certs, KEM secret keys, signed trust
bundles) are written under a temporary `material/` directory that is removed on exit and is
gitignored here as a backstop.

**Decision gate = Route B** (docs + verification harness; no production Rust source change). The Run
389 security package (`docs/release/public-devnet/security/`) publishes the operator-facing
key-management (**M7**), PQC trust-bundle bootstrap (**M8**), and PQC root/signing-key (**M9**)
guidance and verifies it against the **real** `qbind-node` CLI/help surfaces and the existing DevNet
`devnet_pqc_trust_bundle_helper` example. It opens no externally reachable port, deploys no
seed/bootnode/faucet/RPC/explorer/status page, changes no wire format, weakens no peer admission
(the `identity` command and `--p2p-trust-bundle-reload-check` are read-only / validation-only), and
mutates no trust/validator/epoch/sequence/marker/LivePqcTrustState.

**M4** stays Yellow/launch-blocking (no external seed reachability), **M6** stays Yellow/Partial (no
live registration path), **M12/M13/M14** remain Green, public DevNet remains **NOT launch-ready**,
and **C4/C5 remain OPEN**. No M4 Green, no M6 fully-Green, and no C4/C5 closure is claimed.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_389.md`.