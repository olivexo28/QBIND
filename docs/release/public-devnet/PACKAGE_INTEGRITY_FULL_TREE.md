# QBIND Public DevNet — Full-Tree Package Integrity Verifier (Run 405)

> **Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
> NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
> no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN** ·
> no C4/C5 closure claim.

This document explains the **full-tree package integrity verifier** for the QBIND
public DevNet release package. The verifier hashes **every** regular publish-safe
file under `docs/release/public-devnet` at verification time and confirms each file
is **present and unchanged** (SHA-256 + byte size).

It is **docs + schema + shell (+ optional CI) only**: running it deploys nothing,
starts no node, opens no port, adds no CLI flag, changes no runtime behavior, and
moves **no** readiness item Green.

Companion files:

- `docs/release/public-devnet/PACKAGE_INTEGRITY.md` — the Run 404 **anchor** manifest
  guide (one `VERIFY.md` per group + the top-level docs).
- `docs/release/public-devnet/PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.schema.json` — the
  full-tree manifest JSON Schema (draft-07).
- `scripts/devnet/run_405_public_devnet_full_tree_package_integrity.sh` — the local
  verifier / harness.
- `docs/release/public-devnet/ARTIFACT_INDEX.md` — the navigation index.
- `docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md` — the verification map.

## 1. How full-tree verification differs from the Run 404 anchor manifest

The Run 404 **anchor** manifest
(`PACKAGE_INTEGRITY_MANIFEST.example.json`) is a **committed, curated** list: one
stable `VERIFY.md` anchor per artifact group plus the five top-level package
documents (16 files). It carries per-file `artifact_group` / `readiness_item` /
`status` / `verification_reference` labelling and is the human-readable integrity
anchor an operator reads first.

The Run 405 **full-tree** manifest is **mechanically generated** and lists **every**
regular publish-safe file under `docs/release/public-devnet` (currently every tracked
file in the tree), each with only `relative_path`, `sha256`, and `byte_size`. It
answers the honest Run 404 limitation — *"a tampered file that is not one of the 16
anchors would not be caught"* — by hashing the **whole** tree. The two are
complementary: the anchor manifest gives labelled, committed anchors; the full-tree
manifest gives exhaustive, transient coverage.

## 2. Why the full-tree manifest is generated transiently, not committed

The package tree changes every time a document is added, edited, or removed. A
committed full-tree manifest would drift out of date on the very next docs change and
would have to be regenerated and re-committed in lockstep — creating a
constantly-churning generated artifact and a self-reference problem (the committed
manifest would have to hash itself). Instead, the verifier **generates the full-tree
manifest into a temporary directory outside `docs/release/public-devnet`** at
verification time, validates it, checks it against the on-disk tree, and discards it.
Only the **schema**, this **guide**, and the **harness** are committed. There is no
committed full-tree manifest to drift.

## 3. How to run the local verifier

```bash
cd <repo-root>
bash scripts/devnet/run_405_public_devnet_full_tree_package_integrity.sh
```

The harness:

1. generates the full-tree manifest into a temp dir **outside** the package tree;
2. validates it against
   `PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.schema.json`;
3. enumerates every regular publish-safe file under `docs/release/public-devnet` and
   fails if the manifest **omits** any of them (or lists an extra path);
4. re-hashes every listed file and verifies its SHA-256 + byte size;
5. fails if any `relative_path` escapes the package root or is unsafe;
6. re-validates the existing Run 404 anchor manifest;
7. runs the private-material / secret / non-claim scans.

It writes only publish-safe values (relative paths, hashes, byte sizes, OK/POSITIVE
lines) to its summary; the generated manifest itself stays in the temp dir and is
never committed.

## 4. How CI uses the verifier without committing generated output

The optional workflow `.github/workflows/public-devnet-package-integrity.yml` runs
**the same harness** on `workflow_dispatch` and on pull requests that touch the
package tree, schema, guide, or harness. It runs with least-privilege
`permissions: contents: read`, references no secrets, deploys nothing, publishes no
release or tag, and **does not commit or push** anything. The generated full-tree
manifest is produced under the runner temp directory and is **not** uploaded as a
committed file and **not** written back to the repository — CI only asserts that the
tree still hashes cleanly.

## 5. Why this is not binary provenance

This verifier covers the **documentation package tree** under
`docs/release/public-devnet`. It answers *"are the documented package files present
and unchanged?"*. It is **not** binary provenance. The release **binary** is covered
separately by
`docs/release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.schema.json` /
`RELEASE_ARTIFACT_MANIFEST.example.json` (Run 383/384), which records the
release-binary SHA-256, ELF BuildID, injected build id / git commit, toolchain,
lockfile, and reproducibility scope. This full-tree manifest embeds no binary and
asserts no signed release or SLSA provenance.

## 6. Why this is not launch evidence

Hashing the whole documentation tree proves only that the files match a snapshot
computed at verification time. It does **not** deploy a seed, bootnode, faucet, RPC,
explorer, or status service; it opens no port, starts no node, applies no trust
bundle, and mutates no validator/epoch/sequence/marker/`LivePqcTrustState` state.
Running or wiring this verifier is **not** a launch and does not make the public
DevNet launch-ready. The launch decision remains **NO-GO / NOT launch-ready**
(`LAUNCH_GO_NO_GO.md`).

## 7. Why M4 / M6 / S5 / S7 remain unchanged

- **M4 (seed/bootnodes)** stays **Yellow / launch-blocking**: no real, externally
  reachable public DevNet seed with independent off-host reachability evidence
  exists. Full-tree hashing proves nothing about external reachability.
- **M6 (validator identity)** stays **Yellow / Partial**: identity generation +
  verification + non-mutating `register-check` are Green-for-scope; the
  live-registration half is M4-gated and durable-root reuse/rotation/revocation is
  C4/C5-deferred. Full-tree hashing changes none of that.
- **S5 (status page)** stays **Yellow**: a live status / aggregate health view is
  deferred until M4 / a live network.
- **S7 (seed-node runbook)** stays **Yellow**: operating a live seed remains
  M4-gated.

## 8. Why C4 / C5 remain OPEN

**C4 remains OPEN. C5 remains OPEN.** MainNet authority rotation/revocation remains
**Red**. Confirming full documentation-tree integrity closes, advances, or
reinterprets nothing about the contradiction ledger. See
`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` for the closure criteria and
`docs/whitepaper/contradiction.md` for the ledger.

## 9. TestNet / MainNet non-claim

TestNet and MainNet remain **untouched**; readiness items N1–N7 remain **Red**.
**No TestNet readiness and no MainNet readiness is claimed** anywhere in this guide,
the schema, or the generated manifest.
