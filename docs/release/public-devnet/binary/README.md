# QBIND Public DevNet — Release-Binary Provenance Package (Run 359)

> **Safety label (applies to every file in this directory):**
> **experimental · resettable · no value · no MainNet readiness claim · no C4/C5 closure claim.**

This directory publishes the canonical public DevNet **release-binary provenance + reproducibility /
BuildID record** for `qbind-node`, produced under Run 359. It is **docs / artifact / verification
only**: it copies **no** binary blob into the repository, deploys **no** seed node, bootnode, faucet,
RPC gateway, explorer, or status page, and adds **no** new CLI flag.

## 1. What this package is

A published, operator-verifiable record of **how the `qbind-node` release binary is built and what it
hashes to** on the reference build host. It records the source commit, toolchain versions, exact build
command, cargo profile, target triple, binary size, binary SHA-256, ELF BuildID/debug-id, and a
same-host two-build reproducibility result, so an operator can rebuild `qbind-node` and confirm they
are running the artifact this repository describes.

| File | Purpose |
|------|---------|
| `README.md` | This document (scope, safety labels, verification pointers). |
| `RELEASE_PROVENANCE.md` | Canonical provenance record (commit, toolchain, build command, SHA-256, BuildID). |
| `REPRODUCIBILITY.md` | Same-host two-build reproducibility experiment + BuildID result. Includes the Run 383 same-input reproducibility result for the canonical injected-provenance release build. |
| `BUILDINFO.md` | Full build-input record for audit/reproduction. Includes the Run 382 ELF-BuildID-vs-metric-`build_id`-label distinction and the Run 383 canonical injected release-provenance build command. |
| `qbind-node.sha256` | SHA-256 of the locally built `target/release/qbind-node`, standard checksum format. |
| `RELEASE_ARTIFACT_MANIFEST.schema.json` | JSON Schema (draft-07) contract for the canonical CI/release-artifact manifest (Run 384). |
| `RELEASE_ARTIFACT_MANIFEST.example.json` | Publish-safe example manifest generated from the real canonical injected build (Run 384); validates against the schema. |
| `VERIFY.md` | Exact operator verification commands and expected outputs. |

## 2. What this package is NOT

- It is **not** a committed binary: `qbind-node.sha256` is the checksum of the **locally built**
  release artifact (`target/release/qbind-node`), **not** a binary blob stored in git.
- It is **not** a signed-release attestation. **No** release-signing claim is made — no signing
  material or signature-verification evidence exists for this run.
- It is **not** a SLSA-grade provenance attestation. **No** SLSA-grade claim is made.
- It is **not** a cross-host reproducibility claim. Only **same-host** reproducibility was tested (see
  `REPRODUCIBILITY.md`).
- It is **not** a public DevNet launch, a TestNet readiness claim, or a MainNet readiness claim.

## 3. Public DevNet is NOT launch-ready

Public DevNet remains **NOT launch-ready**. This package narrows the release-provenance track only
(readiness must-haves **M2** and **M3**); it does not deploy live infrastructure. See §11 and
`../../QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`.

## 4. DevNet-only / experimental / resettable / no value

Everything described here pertains to a **DevNet-only, experimental, resettable, no-value** binary.
DevNet state carries no value and may be reset at any time. TestNet and MainNet are separate future
stages and are unaffected by this package.

## 5. No MainNet readiness claim

This package makes **no** MainNet readiness claim. MainNet authority rotation/revocation remains
**Red**.

## 6. No C4/C5 closure claim

This package makes **no** C4 or C5 closure claim. Full **C4 remains OPEN**; **C5 remains OPEN**.

## 7. Which binary is covered

The covered artifact is the release build of the workspace binary crate `qbind-node`:

```
target/release/qbind-node
```

built from workspace member `crates/qbind-node` (binary name `qbind-node`, `src/main.rs`).

## 8. How to verify the binary SHA-256

Build the release binary with the documented command, then verify the checksum:

```
cargo build -p qbind-node --release --locked
( cd target/release && sha256sum -c "$OLDPWD/docs/release/public-devnet/binary/qbind-node.sha256" )
```

Expected: `qbind-node: OK`. The recorded SHA-256 is
`f916af6db4cd1d8575b02f750ad4759c3470c2a2027d532cde50ca06e5b22990`. Full commands are in `VERIFY.md`.

## 9. How to inspect the build inputs

See `BUILDINFO.md` for the complete build-input record (commit, branch, clean/dirty state, build
command, target triple, `rustc`/`cargo` verbose versions, profile, size, SHA-256, BuildID). Inspect
the live binary's metadata with:

```
file target/release/qbind-node
readelf -n target/release/qbind-node
objdump -f target/release/qbind-node
target/release/qbind-node --version
```

## 10. How to read the reproducibility result

See `REPRODUCIBILITY.md`. On the reference host, two clean `--locked` release builds in separate
target directories produced a **byte-identical** `qbind-node` (same SHA-256, same ELF BuildID). This
is a **same-host, clean-tree** reproducibility result for scope only. Cross-host reproducibility and
SLSA-grade provenance are **not** claimed. Run 383 extends this to the **canonical injected-provenance**
release build: injecting the canonical `QBIND_GIT_COMMIT` / `QBIND_BUILD_ID` (so the published artifact
ships populated `qbind_node_build_info` provenance) is **same-input reproducible** (byte-identical
across two clean builds), and changing the injected `build_id` changes the hash as expected — a
**per-input**, same-host result only (see `REPRODUCIBILITY.md` §10 and
`../../../devnet/QBIND_DEVNET_EVIDENCE_RUN_383.md`).

## 10a. Canonical release-artifact manifest (Run 384)

Run 384 adds a canonical, publish-safe **release-artifact manifest** for the Run 383
canonical injected build. `RELEASE_ARTIFACT_MANIFEST.schema.json` is the JSON-Schema
(draft-07) contract and `RELEASE_ARTIFACT_MANIFEST.example.json` is an example
generated from the **real** artifact and a **live loopback** `qbind_node_build_info`
scrape. The manifest records the injected build inputs, the release-binary SHA-256,
the ELF BuildID, the metric `build_id` / `git_commit` (kept a **separate field** from
and distinct from the ELF BuildID), the toolchain, the target triple, the
`Cargo.lock` hash, the exact build command, the **same-host / per-input**
reproducibility scope (referencing Run 383, **not** overclaimed as cross-host or
SLSA), the source-tree state, explicit non-claim fields, verification commands, and
the artifact safety label. It embeds **no** binary blob, absolute path, private
hostname, external endpoint, secret, or raw `/metrics` dump. Regenerate + validate
with `scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh` (see
`VERIFY.md` §6b and `../../../devnet/QBIND_DEVNET_EVIDENCE_RUN_384.md`).

## 10b. CI generation of the release-artifact manifest (Run 385)

Run 385 wires the Run 384 manifest generation into CI. The workflow
`.github/workflows/public-devnet-release-artifact-manifest.yml` (manual /
release-track scoped, least-privilege `permissions: contents: read`, no secrets)
builds the canonical injected artifact, generates the manifest from the actual binary
+ a live loopback `qbind_node_build_info` scrape, validates it against the committed
schema, and uploads a publish-safe bundle (`RELEASE_ARTIFACT_MANIFEST.json`,
`qbind-node.sha256`, `MANIFEST_VALIDATION_SUMMARY.txt`, `BUILDID.txt`) as a **CI
artifact** — the generated manifest is **never** committed. The local dry-run wrapper
`scripts/devnet/run_385_public_devnet_ci_release_artifact_manifest.sh` runs the same
commands (see `VERIFY.md` §6c and
`../../../devnet/QBIND_DEVNET_EVIDENCE_RUN_385.md`).

## 11. What remains before public DevNet launch

Publishing this provenance record does **not** make the network joinable. Remaining public DevNet
blockers include, at minimum:

- **M4** — real live seed/bootnode deployment + external reachability evidence (still launch-blocking).
- **M6** — a stable operator-facing identity-**generation** command/procedure.
- **M7–M15** — the remaining Yellow readiness must-haves.

Public DevNet stays **NOT launch-ready** until all must-haves are Green. See
`../../QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`.

## Related packages

- Genesis package: `../genesis/` (Run 356).
- Seed-list format package: `../network/` (Run 357).
- Operator onboarding package: `../operator/` (Run 358).
- Run 359 evidence: `../../../devnet/QBIND_DEVNET_EVIDENCE_RUN_359.md`.
- Run 382 build-info provenance evidence: `../../../devnet/QBIND_DEVNET_EVIDENCE_RUN_382.md`.
- Run 383 canonical injected release-provenance + reproducibility evidence:
  `../../../devnet/QBIND_DEVNET_EVIDENCE_RUN_383.md`.
- Run 384 CI/release-artifact manifest package (`RELEASE_ARTIFACT_MANIFEST.schema.json` +
  `RELEASE_ARTIFACT_MANIFEST.example.json`), evidence:
  `../../../devnet/QBIND_DEVNET_EVIDENCE_RUN_384.md`.
- Run 385 CI wiring of the release-artifact manifest
  (`.github/workflows/public-devnet-release-artifact-manifest.yml` +
  `scripts/devnet/run_385_public_devnet_ci_release_artifact_manifest.sh`), evidence:
  `../../../devnet/QBIND_DEVNET_EVIDENCE_RUN_385.md`.