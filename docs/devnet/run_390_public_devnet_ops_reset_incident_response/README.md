# Run 390 evidence archive — public DevNet ops reset policy (M15) + incident response (M16)

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_390_public_devnet_ops_reset_incident_response.sh` and contains only
publish-safe values: the release-binary SHA-256, BuildID, toolchain, and the OK / POSITIVE status
lines. **No secret key, private material, data dir, raw log, or raw metrics dump is committed.**

Regenerate locally with:

```bash
bash scripts/devnet/run_390_public_devnet_ops_reset_incident_response.sh
```

**Decision gate = Route B** (docs + verification harness; no production Rust source change). The Run
390 ops package (`docs/release/public-devnet/ops/`) publishes the operator-facing DevNet **reset
policy** (**M15**) and **public-DevNet-scoped incident-response** process (**M16**) and verifies them
against the **real** `qbind-node` CLI/help + source surfaces and existing ops runbooks. It starts no
node, opens no externally reachable port, deploys no seed/bootnode/faucet/RPC/explorer/status page,
changes no wire format, weakens no peer admission, and mutates no
trust/validator/epoch/sequence/marker/LivePqcTrustState. The only reset-related CLI surface referenced
is the pre-existing, **hidden**, offline `--authority-state-reset` ceremony (Run 127); no CLI flag is
added.

**M15** moves **Yellow → Green** (DevNet reset policy published + verified). **M16** is **reconciled
to Green** with a real public-DevNet-scoped incident-response artifact (the prior Green rested only on
the internal Beta-scoped `docs/ops/QBIND_INCIDENT_RESPONSE.md`). **M4** stays Yellow/launch-blocking,
**M6** stays Yellow/Partial, **M12/M13/M14** remain Green, public DevNet remains **NOT launch-ready**,
and **C4/C5 remain OPEN**. No M4 Green, no M6 fully-Green, and no C4/C5 closure is claimed.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_390.md`.