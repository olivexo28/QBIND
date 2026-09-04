# Run 415 evidence archive — public DevNet readiness artifact path/reference lint

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_415_public_devnet_readiness_artifact_path_reference_lint.sh` and contains only
publish-safe values: OK / POSITIVE / NONE status lines for each lint check. **No secret key, private
material, generated identity, data dir, raw log, raw metrics dump, private endpoint, or absolute
path is committed.**

The Run 415 harness is a **read-only**, fail-closed **artifact path/reference** consistency lint
over the public DevNet readiness documents. It extends the Run 412/413/414 status/coverage
consistency lints (which protect the readiness *rows*) to the **path/reference** layer beneath them:
it verifies that the `docs/release/…` evidence paths named in the readiness matrix §9/§10/§11/§16,
the `docs/release/public-devnet/…` package paths named in the artifact index and operator
verification map (that are not marked generated/transient), the `scripts/devnet/run_*.sh`
verification commands those documents name, and the `docs/devnet/…` committed-evidence `.md` paths
named in the matrix / contradiction ledger all resolve on disk; that every package directory under
`docs/release/public-devnet` is represented in the artifact index; and that every tracked
publish-safe file is discoverable through the index / operator map / an indexed package
README/VERIFY / a documented exception. It generates nothing under the repository tree; any
transient output (the summary, extracted path lists, and self-test scratch copies) is written to a
staging directory **outside** the package tree (runner temp) and is **never** committed.

Regenerate locally with:

```bash
bash scripts/devnet/run_415_public_devnet_readiness_artifact_path_reference_lint.sh
```

**Decision gate = Route B** (docs + shell only; no production Rust source change, no `build.rs`
change, no `Cargo.toml` change, no CLI flag, no runtime change).

## What the lint checks

- The path/reference lint guide (`READINESS_ARTIFACT_PATH_REFERENCE_LINT.md`) exists and is
  safety-labelled.
- The readiness matrix, artifact index, operator verification map, blocker register, and launch
  gate all exist; the launch gate remains NO-GO / NOT launch-ready.
- Every readiness-matrix §9/§10/§11/§16 `docs/release/…` evidence path resolves on disk.
- Every artifact-index / operator-map `docs/release/public-devnet/…` package path resolves on disk
  or is explicitly marked generated / download-only / transient / not committed.
- Every `scripts/devnet/run_*.sh` command named in the index / operator map resolves on disk.
- Every `docs/devnet/…` committed-evidence `.md` path named in the matrix / ledger resolves on disk.
- Every package directory under `docs/release/public-devnet` is represented in the artifact index.
- Every tracked publish-safe file is discoverable through the index / operator map / an indexed
  package README/VERIFY / a documented exception, and the set of non-discoverable files equals
  exactly the documented exception set (the six seed-reachability evidence templates).
- Each exception is well-formed (relative path + reason + protecting indexed parent) and does not
  hide an M4/M6/S5/S7 path without Yellow / launch-blocking or a C4/C5 path without OPEN.
- No checked document claims launch-ready / GO, a C4/C5 closure, TestNet/MainNet readiness, a live
  seed/bootnode/faucet/RPC/explorer/status-service deployment, a `devnet-seeds.live.json`, or a
  runtime mutation.
- Three built-in fail-closed self-tests (a moved readiness-matrix evidence path, a package
  directory absent from the index, an undiscoverable public-DevNet file) abort as intended, on
  temporary copies outside the tree.
- Nothing generated is committed; the working tree stays clean; the secret/private-material scan is
  clean.

## Readiness

**No item moves Green.** M4 stays Yellow/launch-blocking, M6 stays Yellow/Partial, S5/S7 stay
Yellow, M1–M3/M5/M7–M20 remain Green (M12 Green-for-scope, Run 371), public DevNet remains NOT
launch-ready. C4/C5 remain OPEN; MainNet authority rotation/revocation remains Red; TestNet/MainNet
untouched.
