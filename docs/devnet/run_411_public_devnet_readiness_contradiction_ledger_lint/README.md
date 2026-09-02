# Run 411 evidence archive — public DevNet readiness/contradiction ledger consistency lint

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_411_public_devnet_readiness_contradiction_ledger_lint.sh` and contains
only publish-safe values: OK / POSITIVE / NONE status lines for each lint check. **No
secret key, private material, generated identity, data dir, raw log, raw metrics dump,
private endpoint, or absolute path is committed.**

The Run 411 harness is a **read-only**, fail-closed **cross-ledger** lint over QBIND's two
canonical public DevNet ledgers — the readiness matrix
(`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`) and the contradiction ledger
(`docs/whitepaper/contradiction.md`). It extends consistency protection beyond the Run 410
package-integrity stale-prose lint: it verifies that both ledgers agree on the Run 402–410
run narratives, the fixed readiness posture, and the standing non-claims. It generates
nothing under the repository tree; any transient output is written to a staging directory
**outside** the package tree (runner temp) and is **never** committed.

Regenerate locally with:

```bash
bash scripts/devnet/run_411_public_devnet_readiness_contradiction_ledger_lint.sh
```

**Decision gate = Route B** (docs + shell only; no production Rust source change, no
`build.rs` change, no `Cargo.toml` change, no CLI flag, no runtime change).

## What the lint checks

- The ledger-lint guide (`READINESS_CONTRADICTION_LEDGER_LINT.md`) exists and is
  safety-labelled.
- Both ledgers exist and carry the fixed NO-GO / C4-C5-OPEN posture.
- Runs **402–410** are present in **both** ledgers: an `Updated Run N` narrative in the
  readiness matrix and a `Run N` no-contradiction entry in the contradiction ledger.
- For every scoped run, both ledgers agree: no readiness item moved Green, M4/M6/S5/S7 stay
  Yellow, public DevNet stays NOT launch-ready, C4/C5 stay OPEN, TestNet/MainNet remain
  untouched, and the docs/shell-only run is recorded as Route B (not launch/runtime
  evidence).
- The fixed status table holds M4/M6/S5/S7 🟡, NO-GO, C4/C5 OPEN, and N1–N7 Red.
- No deployment / runtime-mutation / TestNet-MainNet-readiness / C4-C5-closure claim appears
  in the Run 411 docs.
- Nothing generated is committed; the working tree stays clean; the secret/private-material
  scan is clean.

## Readiness

**No item moves Green.** M4 stays Yellow/launch-blocking, M6 stays Yellow/Partial, S5/S7
stay Yellow, M1–M3/M5/M7–M20 remain Green, public DevNet remains NOT launch-ready. C4/C5
remain OPEN; MainNet authority rotation/revocation remains Red; TestNet/MainNet untouched.