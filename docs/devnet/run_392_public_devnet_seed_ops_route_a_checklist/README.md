# Run 392 evidence archive — public DevNet seed-node operations runbook (S7) + M4 Route-A deployment checklist

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_392_public_devnet_seed_ops_route_a_checklist.sh` and contains only publish-safe
values: the release-binary SHA-256, BuildID, toolchain, and the OK / POSITIVE status lines. **No secret
key, private material, data dir, raw log, or raw metrics dump is committed.**

Regenerate locally with:

```bash
bash scripts/devnet/run_392_public_devnet_seed_ops_route_a_checklist.sh
```

**Decision gate = Route B** (docs + verification harness; no production Rust source change). The Run 392
seed-node operations package (`docs/release/public-devnet/network/SEED_NODE_OPERATIONS.md`,
`M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md`, `SEED_REACHABILITY_EVIDENCE_TEMPLATE.md`) makes it unambiguous what
a **real** seed operator must do before **M4** can move Green — durable seed identity custody, strict
KEMTLS mutual-auth + PQC static-root startup, genesis pinning, independent off-host external TCP + KEMTLS
verification, seed-list promotion to `status: live`, `register-check --status live` admission, and
retirement — **without faking any external endpoint or reachability**. The harness verifies the docs
against the **real** `qbind-node` CLI/help + seed-list schema surfaces. It starts no node, opens no
externally reachable port, deploys no seed/bootnode/faucet/RPC/explorer/status page, changes no wire
format, weakens no peer admission, and mutates no trust/validator/epoch/sequence/marker/LivePqcTrustState.
No CLI flag is added.

**S7** (seed-node operational runbook, a should-have) moves **Red → Yellow**. **M4** stays
Yellow/launch-blocking (no externally reachable seed / no independent off-host vantage), **M6** stays
Yellow/Partial (live registration is M4-gated), **M12/M13/M14/M15/M16** remain Green, public DevNet remains
**NOT launch-ready**, and **C4/C5 remain OPEN**. No M4 Green, no M6 Green, and no C4/C5 closure is claimed.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_392.md`.