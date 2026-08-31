# QBIND `qbind-node` — Reproducibility & BuildID Record (Run 359)

> **Safety label:** **experimental · resettable · no value · no MainNet readiness claim ·
> no C4/C5 closure claim.** DevNet-only. Public DevNet is **NOT launch-ready**.

## 1. Experiment description

Goal: determine whether the `qbind-node` release binary is **deterministic on the same host** — i.e.
whether two independent clean release builds from the same commit and the same build command produce a
byte-identical artifact. To avoid contamination from incremental compilation artifacts, each build
used a **separate `CARGO_TARGET_DIR`**. A third build in the repository's default `target/` directory
was also produced and compared, giving three independent builds of the same commit.

- **Commit:** `420bb571281fc243fb0581150b0f628f6ee8d284`
- **Build command (each build):** `cargo build -p qbind-node --release --locked`
- **Toolchain:** `rustc`/`cargo` 1.97.1, target `x86_64-unknown-linux-gnu` (see `BUILDINFO.md`).

`--locked` was **supported** and succeeded for every build; no substitution was needed.

## 2. The builds

```
CARGO_TARGET_DIR=/tmp/qbind-run359-a cargo build -p qbind-node --release --locked
CARGO_TARGET_DIR=/tmp/qbind-run359-b cargo build -p qbind-node --release --locked
cargo build -p qbind-node --release --locked      # default target/ (third, cross-check)
```

## 3. SHA-256 of each produced `qbind-node`

```
f916af6db4cd1d8575b02f750ad4759c3470c2a2027d532cde50ca06e5b22990  /tmp/qbind-run359-a/release/qbind-node
f916af6db4cd1d8575b02f750ad4759c3470c2a2027d532cde50ca06e5b22990  /tmp/qbind-run359-b/release/qbind-node
f916af6db4cd1d8575b02f750ad4759c3470c2a2027d532cde50ca06e5b22990  target/release/qbind-node
```

Sizes were identical (`16557072` bytes each).

## 4. Do the hashes match?

**Yes — all three are byte-identical.** `cmp -s` confirmed equality:

```
cmp -s /tmp/qbind-run359-a/release/qbind-node /tmp/qbind-run359-b/release/qbind-node   # exit 0 (identical)
cmp -s /tmp/qbind-run359-a/release/qbind-node target/release/qbind-node                # exit 0 (identical)
```

## 5. Result (hashes match)

- The **local same-host reproducibility experiment** is marked **Green for scope**: on this host,
  with this commit, toolchain, lockfile, and build command, `qbind-node` builds deterministically to a
  single SHA-256 across separate target directories and the default target.
- **Cross-host reproducibility is NOT claimed** — it was not tested. A different host, toolchain
  version, target triple, or filesystem layout may change the SHA-256 and/or the ELF BuildID.

## 6. Result (hashes do not match)

Not applicable — the hashes matched. (Had they differed, this record would compare the available
metadata, document the bounded non-determinism honestly, and keep **M3** at Yellow/Partial rather than
Green.)

## 7. BuildID / debug-id result

- **Status:** **present.**
- **Exact command:**

  ```
  readelf -n target/release/qbind-node
  file target/release/qbind-node
  ```

- **Exact output (`readelf -n`, `.note.gnu.build-id`):**

  ```
  Displaying notes found in: .note.gnu.build-id
    Owner                Data size 	Description
    GNU                  0x00000014	NT_GNU_BUILD_ID (unique build ID bitstring)
      Build ID: 274fdaf3ded72362e87e11ccffce6912bde5208b
  ```

- The BuildID was **identical** across all three builds
  (`274fdaf3ded72362e87e11ccffce6912bde5208b`), consistent with the byte-identical binaries. The GNU
  BuildID is by default a hash over the linked output, so a stable BuildID corroborates the stable
  SHA-256.

## 8. Reproducibility taxonomy — what IS and IS NOT claimed

| Level | Claimed? | Basis |
|-------|----------|-------|
| **Same-host reproducibility** (same machine, same toolchain, repeated builds) | ✅ **Yes (Green for scope)** | Three builds → one SHA-256 + one BuildID. |
| **Clean-tree reproducibility** (separate fresh `CARGO_TARGET_DIR`, no incremental reuse) | ✅ **Yes (Green for scope)** | Builds A and B used isolated target dirs and still matched. |
| **Cross-host reproducibility** (different machines / toolchains) | ❌ **No** | Not tested; different host/toolchain may differ. |
| **SLSA-grade provenance** (hardened, attested, signed build pipeline) | ❌ **No** | No signing material, no attestation pipeline. |

## 9. No SLSA / signed-release claim

No **SLSA-grade** provenance and no **signed-release** claim is made. No signing material or
signature-verification evidence exists for this run. This record is a same-host, clean-tree
reproducibility + BuildID observation only.

## 10. Run 383 — same-input reproducibility of the injected-provenance build

Run 359 (above) proved same-host reproducibility of the **default** (no-injection) build. Run 383
extends that to the **canonical injected-provenance** release build wired in Run 382/383, so the
published artifact ships populated `qbind_node_build_info` provenance **and** is reproducible.

- **Canonical injected provenance:** `QBIND_GIT_COMMIT="$(git rev-parse --short=12 HEAD)"` and
  `QBIND_BUILD_ID="qbind-devnet-<pkg-version>-<short-commit>"` (see `BUILDINFO.md`).
- **Build command (each build):**
  `QBIND_GIT_COMMIT=<commit> QBIND_BUILD_ID=<canonical-id> cargo build -p qbind-node --release --locked --bin qbind-node`.
- **Experiment:** two clean builds in separate `CARGO_TARGET_DIR`s with the **same** source,
  lockfile, toolchain, and injected provenance, plus a third build in the default `target/`.

Result on the reference host:

- **Same-input reproducible = YES (Green for scope).** Both isolated builds and the default-target
  build produced a **byte-identical** `qbind-node` (`cmp -s` exit 0; identical SHA-256 and identical
  ELF BuildID across all three).
- **Changed-input sensitivity = YES.** Rebuilding with a **different** injected `build_id`
  (`…-alt`) changed the binary SHA-256, as expected — the injected provenance is compiled into the
  binary.
- **Missing-injection fallback intact.** A build with no `QBIND_BUILD_ID` does not embed the
  canonical id; the metric renders `build_id="unknown"` (Run 382 regression preserved).

The exact captured SHA-256, ELF BuildID, toolchain, git commit, canonical injected `build_id`, and
build command line for the reference run are recorded in
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_383.md` and the archived
`docs/devnet/run_383_public_devnet_release_provenance_injected_repro/summary.txt`.

**Scope unchanged.** This is a **same-host, clean-tree, per-input** reproducibility result. Because
the injected `git_commit` / `build_id` are compiled in, reproducibility is **per input**: the same
source + lockfile + toolchain + injected provenance ⇒ the same binary; a different injected value ⇒ a
different binary. Cross-host reproducibility, SLSA-grade provenance, and signed-release attestation
are still **not** claimed.

**Run 384 manifest.** Run 384 records this canonical injected build (its SHA-256, ELF BuildID, live
metric `build_id` / `git_commit`, toolchain, target, and `Cargo.lock` hash) in a schema-validated
release-artifact manifest (`RELEASE_ARTIFACT_MANIFEST.schema.json` /
`RELEASE_ARTIFACT_MANIFEST.example.json`). The manifest's `reproducibility_scope` is **same-host /
per-input** only and **references** this Run 383 result without overclaiming cross-host or SLSA-grade
provenance. See `BUILDINFO.md` and `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_384.md`.

**Run 385 CI generation.** Run 385 generates this same manifest in CI as a publish-safe **CI artifact**
(never committed) via `.github/workflows/public-devnet-release-artifact-manifest.yml` and the local
dry-run wrapper `scripts/devnet/run_385_public_devnet_ci_release_artifact_manifest.sh`. The
reproducibility scope is unchanged (**same-host / per-input** only; cross-host and SLSA-grade are not
claimed). See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_385.md`.