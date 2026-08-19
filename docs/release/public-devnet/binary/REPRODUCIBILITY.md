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
