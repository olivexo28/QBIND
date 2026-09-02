# QBIND Public DevNet — Package Integrity Manifest Guide (Run 404)

> **Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
> NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
> no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN** ·
> no C4/C5 closure claim.

This document explains the **package integrity manifest** for the QBIND public
DevNet release package. The manifest is a machine-readable list of documented
public DevNet package files with their **SHA-256** and **byte size**, so an
operator or reviewer can confirm the files they hold are **present and unchanged**
before following `docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md`.

It is **docs + schema only**: publishing it deploys nothing, starts no node, opens
no port, adds no CLI flag, changes no runtime behavior, and moves **no** readiness
item Green.

Companion files:

- `docs/release/public-devnet/PACKAGE_INTEGRITY_MANIFEST.schema.json` — the manifest
  JSON Schema (draft-07).
- `docs/release/public-devnet/PACKAGE_INTEGRITY_MANIFEST.example.json` — a
  schema-valid example manifest whose hashes match the current on-disk tree.
- `docs/release/public-devnet/ARTIFACT_INDEX.md` — the navigation index.
- `docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md` — the verification map
  (run the integrity check **first**, then follow this map).

## 1. What the manifest contains

Each manifest is a single JSON object with:

- `manifest_version` — semver of the manifest contract.
- `generated_for_run: 404`.
- `scope: public-devnet-docs-release-package`.
- `safety_labels` — the eight standing labels: `devnet`, `experimental`,
  `resettable`, `no_value`, `no_uptime_sla`, `not_launch_ready`, `c4_open`,
  `c5_open`.
- `package_root: docs/release/public-devnet`.
- `files[]` — one entry per covered file, each with `relative_path` (relative to
  `package_root`), `sha256`, `byte_size`, `artifact_group`, `readiness_item`,
  `status`, and `verification_reference`.
- `non_claims` — the eleven explicit non-claim booleans, all fixed
  (`launches_public_devnet: false`, `moves_m4_green: false`, `moves_m6_green: false`,
  `moves_s5_green: false`, `moves_s7_green: false`, `closes_c4: false`,
  `closes_c5: false`, `claims_testnet_ready: false`, `claims_mainnet_ready: false`,
  `deploys_seed_or_service: false`, `mutates_runtime_state: false`).
- `artifact_safety_label` — the standing human-readable label.
- `generated_at_utc` — **optional**; see the reproducibility note below.

## 2. How to regenerate the manifest

The manifest is a plain hash listing; regenerate it deterministically from the
on-disk tree. For each covered file under `docs/release/public-devnet`:

```bash
cd <repo-root>
# hash and size of a covered file (relative to the package root):
sha256sum   docs/release/public-devnet/genesis/VERIFY.md   # -> sha256
wc -c       docs/release/public-devnet/genesis/VERIFY.md   # -> byte_size
```

Populate each `files[]` entry's `relative_path` **relative to
`docs/release/public-devnet`** (for example `genesis/VERIFY.md`, not an absolute
path and not a repo-root path), with the matching `sha256` and `byte_size`. Keep
`artifact_group` / `readiness_item` / `status` / `verification_reference` in sync
with `ARTIFACT_INDEX.md`; **never** upgrade a Yellow item's `status`.

The example manifest lists one stable anchor file per artifact group (each group's
`VERIFY.md`) plus the top-level package documents. It intentionally does **not**
list the schema or the example manifest itself (a manifest cannot self-hash), and
it lists only publish-safe documentation — never keys, certs, logs, metrics, data
dirs, or generated private identity files.

### Reproducibility of `generated_at_utc`

`generated_at_utc` is **optional** and is **not** part of the integrity signal —
the `sha256` + `byte_size` fields are. Regenerating the manifest at a different
time changes only this timestamp, not any hash. Include it only as informational
provenance; omit it if you need a byte-for-byte reproducible manifest. The
verification harness never depends on it.

## 3. How to verify file hashes

Given a manifest, verify every entry against the current on-disk tree:

```bash
cd <repo-root>
python3 - <<'PY'
import hashlib, json, os, sys
root = "docs/release/public-devnet"
m = json.load(open(os.path.join(root, "PACKAGE_INTEGRITY_MANIFEST.example.json")))
bad = 0
for f in m["files"]:
    p = os.path.join(root, f["relative_path"])
    if not os.path.isfile(p):
        print("MISSING", f["relative_path"]); bad += 1; continue
    data = open(p, "rb").read()
    got = hashlib.sha256(data).hexdigest()
    if got != f["sha256"] or len(data) != f["byte_size"]:
        print("MISMATCH", f["relative_path"]); bad += 1
print("OK" if bad == 0 else f"{bad} problem(s)")
sys.exit(1 if bad else 0)
PY
```

Or use the bundled harness, which additionally validates the manifest against the
schema and runs the safety/non-claim checks:

```bash
bash scripts/devnet/run_404_public_devnet_package_integrity_manifest.sh
```

## 4. How this differs from binary provenance

This manifest covers the **documentation package tree** under
`docs/release/public-devnet`. It answers *"are the documented package files present
and unchanged?"*.

It is **not** binary provenance. The release **binary** is covered separately by
`docs/release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.schema.json` /
`RELEASE_ARTIFACT_MANIFEST.example.json` (Run 383/384), which records the
release-binary SHA-256, ELF BuildID, injected build id / git commit, toolchain,
lockfile, and reproducibility scope. This package integrity manifest neither
duplicates nor supersedes that; it embeds no binary and asserts no signed release
or SLSA provenance.

## 5. Why this is not a launch artifact

Verifying document hashes proves only that files match a recorded snapshot. It does
**not** deploy a seed, bootnode, faucet, RPC, explorer, or status service; it opens
no port, starts no node, applies no trust bundle, and mutates no
validator/epoch/sequence/marker/`LivePqcTrustState` state. Publishing or verifying
this manifest is **not** a launch and does not make the public DevNet
launch-ready.

## 6. Why it does not move M4 / M6 / S5 / S7

- **M4 (seed/bootnodes)** stays **Yellow / launch-blocking**: no real, externally
  reachable public DevNet seed with independent off-host reachability evidence
  exists. Hashing docs proves nothing about external reachability.
- **M6 (validator identity)** stays **Yellow / Partial**: identity generation +
  verification + non-mutating `register-check` are Green-for-scope, but the
  live-registration half is M4-gated and durable-root reuse/rotation/revocation is
  C4/C5-deferred. A file-hash manifest changes none of that.
- **S5 (status page)** stays **Yellow**: a live status / aggregate health view is
  deferred until M4 / a live network.
- **S7 (seed-node runbook)** stays **Yellow**: operating a live seed remains
  M4-gated.

## 7. Why C4 / C5 remain OPEN

**C4 remains OPEN. C5 remains OPEN.** MainNet authority rotation/revocation remains
**Red**. Confirming documentation-file integrity closes, advances, or reinterprets
nothing about the contradiction ledger. See
`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` for the closure criteria and
`docs/whitepaper/contradiction.md` for the ledger.

## 8. How operators should use this

1. **First**, verify package integrity (Section 3) — confirm the documented files
   you hold match the recorded hashes and sizes.
2. **Then** follow `docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md` to
   verify each artifact group and confirm the launch decision is **NO-GO /
   NOT launch-ready** (`LAUNCH_GO_NO_GO.md`).

The integrity check is a **precondition** for trusting the rest of the package, not
a substitute for the per-artifact verification or the launch stop rule.

## 9. TestNet / MainNet non-claim

TestNet and MainNet remain **untouched**; readiness items N1–N7 remain **Red**.
**No TestNet readiness and no MainNet readiness is claimed** anywhere in this guide
or the manifest.
