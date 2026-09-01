# Run 396 evidence archive — public DevNet readiness matrix canonicalization / stale-row cleanup

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_396_public_devnet_readiness_matrix_canonicalization.sh` and contains only
publish-safe `[PASS]` / `RESULT=POSITIVE` status lines. **No secret key, private material, data dir,
snapshot, raw log, or raw metrics dump is committed.**

Regenerate locally with:

```bash
bash scripts/devnet/run_396_public_devnet_readiness_matrix_canonicalization.sh
```

**Decision gate: Route A** — the source of truth (§10 current-status table + §4/§5 checklists in
`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`) is clear, so Run 396 updates only the stale
§16 gap-matrix rows / §12 / §17 summaries and next-run recommendations to agree with it, and adds
this verification harness. No section required a generated consistency summary (Route B) and no
status was unreconcilable from committed evidence (Route C).

This is a **docs + verification harness** run: no production Rust source change, no `build.rs`
change, no new CLI flag, no runtime behavior change, no node started, no port opened, no
seed/bootnode/faucet/RPC/explorer/status service deployed, and no
trust/validator/epoch/sequence/marker mutation. No readiness semantics are changed and no
functionality is added. Public DevNet remains **NOT launch-ready**; M4 stays Yellow/launch-blocking;
M6/S5/S7 stay Yellow; C4/C5 remain OPEN; TestNet/MainNet untouched.

Canonical record: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_396.md`.