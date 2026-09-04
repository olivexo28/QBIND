# Run 414 evidence archive — public DevNet readiness cross-section coverage lint

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_414_public_devnet_readiness_cross_section_coverage_lint.sh` and contains only
publish-safe values: OK / POSITIVE / NONE status lines for each lint check. **No secret key, private
material, generated identity, data dir, raw log, raw metrics dump, private endpoint, or absolute
path is committed.**

The Run 414 harness is a **read-only**, fail-closed **cross-section coverage** lint over the public
DevNet readiness matrix's §11 next-run recommendation table and §16 consolidated gap matrix,
checked for **coverage** against its §10 current-status table (the source of truth). It extends the
Run 412 per-milestone status/blocker lint and the Run 413 recommendation/gap-matrix **status** lint
(which compare the *values* of rows that exist) to the **coverage** dimension — the *set* of rows
that must exist — so a status-bearing row cannot be silently **removed** (rather than mutated)
without detection. It generates nothing under the repository tree; any transient output (the
summary, extracted section blocks, and self-test scratch copies) is written to a staging directory
**outside** the package tree (runner temp) and is **never** committed.

Regenerate locally with:

```bash
bash scripts/devnet/run_414_public_devnet_readiness_cross_section_coverage_lint.sh
```

**Decision gate = Route B** (docs + shell only; no production Rust source change, no `build.rs`
change, no `Cargo.toml` change, no CLI flag, no runtime change).

## What the lint checks

- The cross-section coverage lint guide (`READINESS_CROSS_SECTION_COVERAGE_LINT.md`) exists and is
  safety-labelled.
- The readiness matrix and its §10 current-status table, §11 next-run recommendation table, and §16
  consolidated gap matrix all exist.
- §10 covers every M1–M20 and S1–S7 item exactly once (source-of-truth coverage).
- §11 covers every must-have M1–M20 item exactly once and stays must-have-only (no S row without a
  documented scope change).
- §16 covers all 25 required mapped labels exactly once, every status-bearing §16 row maps to a
  known M/S/N/C/T item via the explicit label-to-item map, and the S6/S7 coverage exceptions are
  explicit with a reason + §10 protection source (S7 kept Yellow / M4-gated).
- No existing Run 413 scoped §16 mapped row was silently removed.
- §10/§11/§16 status values still agree for every represented item (the Run 413 protection is
  preserved).
- M4 stays Yellow / launch-blocking, M6 stays Yellow / Partial / M4-gated, S5/S7 stay Yellow /
  M4-gated; the §16 C4/C5 rows stay 🔴 / OPEN; public DevNet stays NO-GO; TestNet/MainNet stay
  untouched; N1–N7 stay Red.
- No live seed/bootnode/faucet/RPC/explorer/status-service deployment, `devnet-seeds.live.json`,
  C4/C5 closure, TestNet/MainNet readiness, or runtime mutation is claimed in §11/§16.
- Three built-in fail-closed self-tests (deleted §11 M row, deleted §16 mapped row, §16 unmapped
  label) abort as intended, on temporary copies outside the tree.
- Nothing generated is committed; the working tree stays clean; the secret/private-material scan is
  clean.

## Readiness

**No item moves Green.** M4 stays Yellow/launch-blocking, M6 stays Yellow/Partial, S5/S7 stay
Yellow, M1–M3/M5/M7–M20 remain Green (M12 Green-for-scope, Run 371), public DevNet remains NOT
launch-ready. C4/C5 remain OPEN; MainNet authority rotation/revocation remains Red; TestNet/MainNet
untouched.
