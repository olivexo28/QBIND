# Run 395 evidence archive — public DevNet status-page decision (S5) + S6 reconciliation

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_395_public_devnet_status_s6_reconciliation.sh` and contains only publish-safe
`OK` / `RESULT=POSITIVE` status lines. **No secret key, private material, data dir, snapshot, raw
log, or raw metrics dump is committed.**

Regenerate locally with:

```bash
bash scripts/devnet/run_395_public_devnet_status_s6_reconciliation.sh
```

**Decision gate:**

- **S6 = Route A** — reconcile the readiness matrix (Red → Green) against the **already shipped**
  observability alert/scrape package (Runs 379–381). No alert/scrape content is duplicated.
- **S5 = Route B** — publish a publish-safe **static** status-page decision + future
  aggregate-health-view schema/example (`docs/release/public-devnet/status/`). A live status
  service is **deferred until M4** (Yellow). **S5 moves Red → Yellow, not Green.**

This is a **docs + schema + verification** run: no production Rust source change, no `build.rs`
change, no new CLI flag, no node started, no port opened, no seed/status service deployed, and no
trust/validator/epoch/sequence/marker/`LivePqcTrustState` mutation. Public DevNet remains **NOT
launch-ready**; M4/M6/S7 remain Yellow; C4/C5 remain OPEN.

Canonical record: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_395.md`.