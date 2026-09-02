# Run 412 evidence archive — public DevNet readiness table/checklist/blocker consistency lint

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_412_public_devnet_readiness_status_blocker_lint.sh` and contains only
publish-safe values: OK / POSITIVE / NONE status lines for each lint check. **No secret key,
private material, generated identity, data dir, raw log, raw metrics dump, private endpoint,
or absolute path is committed.**

The Run 412 harness is a **read-only**, fail-closed **per-milestone** consistency lint over
the public DevNet readiness matrix's §10 current-status table, its §4 must-have checklist
(M1–M20), its §5 should-have checklist (S1–S7), the blocker register
(`docs/release/public-devnet/BLOCKER_REGISTER.md`), and the launch go/no-go gate
(`docs/release/public-devnet/LAUNCH_GO_NO_GO.md`). It extends consistency protection beyond
the Run 411 cross-ledger run-narrative lint: it verifies that the status table agrees with the
must-have/should-have checklists on every item, that M4/M6/S5/S7 stay Yellow across the
matrix / blocker register / launch gate, and that the launch decision stays NO-GO with C4/C5
OPEN. It generates nothing under the repository tree; any transient output (the summary and
extracted section blocks) is written to a staging directory **outside** the package tree
(runner temp) and is **never** committed.

Regenerate locally with:

```bash
bash scripts/devnet/run_412_public_devnet_readiness_status_blocker_lint.sh
```

**Decision gate = Route B** (docs + shell only; no production Rust source change, no
`build.rs` change, no `Cargo.toml` change, no CLI flag, no runtime change).

## What the lint checks

- The status/blocker-lint guide (`READINESS_STATUS_BLOCKER_LINT.md`) exists and is
  safety-labelled.
- The readiness matrix, blocker register, and launch gate all exist.
- The §10 current-status table covers M1–M20 and S1–S7; the §4 checklist covers M1–M20; the
  §5 checklist covers S1–S7.
- The §10 table agrees with the §4 must-have checklist for every M1–M20, and with the §5
  should-have checklist for every S1–S7, and both match the frozen status truth.
- M4 is Yellow / launch-blocking, M6 is Yellow / Partial, and S5/S7 are Yellow consistently.
- The blocker register carries M4/M6/S5/S7 as Yellow / open and keeps the launch rule.
- The launch gate remains NO-GO / NOT launch-ready, lists M4 and M6 as must-have blockers,
  and keeps S5/S7 M4-gated / Yellow.
- C4/C5 remain OPEN; N1–N7 stay Red; TestNet/MainNet remain untouched.
- No live seed/bootnode/faucet/RPC/explorer/status-service deployment, `devnet-seeds.live.json`,
  C4/C5 closure, TestNet/MainNet readiness, or runtime mutation is claimed.
- Nothing generated is committed; the working tree stays clean; the secret/private-material
  scan is clean.

## Readiness

**No item moves Green.** M4 stays Yellow/launch-blocking, M6 stays Yellow/Partial, S5/S7 stay
Yellow, M1–M3/M5/M7–M20 remain Green (M12 Green-for-scope, Run 371), public DevNet remains NOT
launch-ready. C4/C5 remain OPEN; MainNet authority rotation/revocation remains Red;
TestNet/MainNet untouched.