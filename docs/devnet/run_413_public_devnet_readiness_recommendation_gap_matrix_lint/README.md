# Run 413 evidence archive — public DevNet readiness recommendation/gap-matrix consistency lint

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_413_public_devnet_readiness_recommendation_gap_matrix_lint.sh` and contains
only publish-safe values: OK / POSITIVE / NONE status lines for each lint check. **No secret key,
private material, generated identity, data dir, raw log, raw metrics dump, private endpoint, or
absolute path is committed.**

The Run 413 harness is a **read-only**, fail-closed **recommendation/gap-matrix** consistency lint
over the public DevNet readiness matrix's §11 next-run recommendation table and §16 consolidated
gap matrix, checked against its §10 current-status table (the source of truth). It extends the
Run 412 per-milestone status/blocker lint (§10 table vs §4/§5 checklists + blocker register +
launch gate) to the two remaining status-bearing views of the readiness matrix. It generates
nothing under the repository tree; any transient output (the summary and extracted section blocks)
is written to a staging directory **outside** the package tree (runner temp) and is **never**
committed.

Regenerate locally with:

```bash
bash scripts/devnet/run_413_public_devnet_readiness_recommendation_gap_matrix_lint.sh
```

**Decision gate = Route B** (docs + shell only; no production Rust source change, no `build.rs`
change, no `Cargo.toml` change, no CLI flag, no runtime change).

## What the lint checks

- The recommendation/gap-matrix-lint guide (`READINESS_RECOMMENDATION_GAP_MATRIX_LINT.md`) exists
  and is safety-labelled.
- The readiness matrix and its §10 current-status table, §11 next-run recommendation table, and
  §16 consolidated gap matrix all exist.
- The §11 recommendation table agrees with the §10 table for every M1–M20, and both match the
  frozen status truth.
- The §16 consolidated gap matrix agrees with the §10 table for every scoped M/S item (mapped by
  descriptive label), and both match the frozen status truth.
- M4 stays Yellow / launch-blocking in §11 (no Green move) and §16 (Launch blocker); M6 stays
  Yellow / Partial / M4-gated; S5 stays Yellow / M4-gated in §16.
- The §16 C4/C5 rows stay 🔴 / OPEN; public DevNet stays NO-GO; TestNet/MainNet stay untouched;
  N1–N7 stay Red.
- No live seed/bootnode/faucet/RPC/explorer/status-service deployment, `devnet-seeds.live.json`,
  C4/C5 closure, TestNet/MainNet readiness, or runtime mutation is claimed in §11/§16.
- Nothing generated is committed; the working tree stays clean; the secret/private-material scan
  is clean.

## Readiness

**No item moves Green.** M4 stays Yellow/launch-blocking, M6 stays Yellow/Partial, S5/S7 stay
Yellow, M1–M3/M5/M7–M20 remain Green (M12 Green-for-scope, Run 371), public DevNet remains NOT
launch-ready. C4/C5 remain OPEN; MainNet authority rotation/revocation remains Red;
TestNet/MainNet untouched.