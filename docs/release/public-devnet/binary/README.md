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
| `REPRODUCIBILITY.md` | Same-host two-build reproducibility experiment + BuildID result. |
| `BUILDINFO.md` | Full build-input record for audit/reproduction. |
| `qbind-node.sha256` | SHA-256 of the locally built `target/release/qbind-node`, standard checksum format. |
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
SLSA-grade provenance are **not** claimed.

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
