# QBIND `qbind-node` — Build Inputs / BUILDINFO (Run 359)

> **Safety label:** **experimental · resettable · no value · no MainNet readiness claim ·
> no C4/C5 closure claim.** DevNet-only. Public DevNet is **NOT launch-ready**.

Complete build-input record for an operator to reproduce or audit the `qbind-node` release build.

## Build inputs

| Input | Value |
|-------|-------|
| Git commit | `420bb571281fc243fb0581150b0f628f6ee8d284` |
| Git branch | `copilot/run-359-update-user-documentation` |
| Clean / dirty state | **Clean** (no tracked-source modifications at build time; the Run 359 change is docs/artifact-only and does not touch any build input) |
| Build command | `cargo build -p qbind-node --release --locked` |
| Target triple | `x86_64-unknown-linux-gnu` (default host target; no `--target` override) |
| rustc (verbose) | `rustc 1.97.1 (8bab26f4f 2026-07-14)` — see full block below |
| cargo (verbose) | `cargo 1.97.1 (c980f4866 2026-06-30)` — see full block below |
| Active cargo config | **None.** No `.cargo/config*` exists in the repository |
| Profile | `release` (workspace defaults; no `[profile.release]` override) |
| Env vars set for reproducibility | **None required.** For the two-build experiment only `CARGO_TARGET_DIR` was varied to isolate incremental artifacts; no `SOURCE_DATE_EPOCH`, `RUSTFLAGS`, or remapping env was set |
| Debug symbols / stripping | `debug = false`, `strip = false` (default) — ELF retains its symbol table (`not stripped`) |
| LTO | `false` (default) |
| codegen-units | `16` (default for the release profile) |
| panic strategy | `unwind` (default; not overridden) |
| Binary size | `16557072` bytes |
| Binary SHA-256 | `f916af6db4cd1d8575b02f750ad4759c3470c2a2027d532cde50ca06e5b22990` |
| ELF BuildID (sha1) | `274fdaf3ded72362e87e11ccffce6912bde5208b` |
| `--version` | `qbind-node 0.1.0` |

## `rustc --version --verbose`

```
rustc 1.97.1 (8bab26f4f 2026-07-14)
binary: rustc
commit-hash: 8bab26f4f68e0e26f0bb7960be334d5b520ea452
commit-date: 2026-07-14
host: x86_64-unknown-linux-gnu
release: 1.97.1
LLVM version: 22.1.6
```

## `cargo --version --verbose`

```
cargo 1.97.1 (c980f4866 2026-06-30)
release: 1.97.1
commit-hash: c980f4866141969fab6254a680546a277789d6f0
commit-date: 2026-06-30
host: x86_64-unknown-linux-gnu
libgit2: 1.9.2 (sys:0.20.4 vendored)
libcurl: 8.20.0-DEV (sys:0.4.88+curl-8.20.0 vendored ssl:OpenSSL/3.6.2)
ssl: OpenSSL 3.6.2 7 Apr 2026
os: Ubuntu 24.4.0 (noble) [64-bit]
```

## Toolchain pinning

There is **no** `rust-toolchain` / `rust-toolchain.toml` file in the repository, so the build uses the
host's active toolchain. The exact toolchain used for the reference build is recorded above. An
operator on a different toolchain may produce a different BuildID/SHA-256; see `REPRODUCIBILITY.md` for
the same-host vs cross-host distinction.

## Lockfile

`Cargo.lock` is committed at the repository root (89,859 bytes) and was consumed with `--locked`, so
the dependency graph is pinned to the committed lockfile.

## BuildID / metadata extraction commands

```
file target/release/qbind-node
readelf -n target/release/qbind-node
objdump -f target/release/qbind-node
target/release/qbind-node --version
```

`objdump -f` (reference host):

```
target/release/qbind-node:     file format elf64-x86-64
architecture: i386:x86-64, flags 0x00000150:
HAS_SYMS, DYNAMIC, D_PAGED
start address 0x0000000000291340
```

## ELF BuildID vs the `qbind_node_build_info` metric `build_id` label (Run 382)

Two different "build id" values exist and must **not** be conflated:

- **ELF BuildID** — the `.note.gnu.build-id` recorded above (`readelf -n`). It is a
  linker-computed identity of the compiled binary and is captured in this
  provenance record.
- **`qbind_node_build_info` `build_id` label** — an operator-facing release
  identity exposed on the `/metrics` scrape. Run 382 populates it **only** from a
  build-time-injected `QBIND_BUILD_ID` env var (harness / CI); it is never derived
  from git or from the ELF BuildID, and renders `unknown` when not injected. The
  companion `git_commit` label is auto-derived to a short git commit hash (or an
  explicit `QBIND_GIT_COMMIT`).

To ship populated metric provenance, inject both at build time (this changes the
compiled label strings and therefore the SHA-256 / ELF BuildID, so record the
injected values alongside the binary hash):

```
QBIND_GIT_COMMIT="$(git rev-parse --short=12 HEAD)" \
QBIND_BUILD_ID="<release-id>" \
  cargo build -p qbind-node --release --locked --bin qbind-node
```

See `../observability/METRICS.md` and `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_382.md`.

## Canonical injected release provenance (Run 383)

Run 383 wires the Run 382 bridge to **canonical injected provenance** so a published
release artifact ships populated `qbind_node_build_info` provenance by default, and
proves the injected build is **same-input reproducible**. The canonical values the
release harness injects are:

- `QBIND_GIT_COMMIT` = the expected short commit, `git rev-parse --short=12 HEAD`.
- `QBIND_BUILD_ID` = a canonical, low-cardinality, non-secret release id derived
  deterministically from the package version + short commit,
  `qbind-devnet-<pkg-version>-<short-commit>`. It is **injected** (never derived
  inside `build.rs` from git or the ELF) and is intentionally **not** the ELF
  BuildID.

Canonical release build command:

```
QBIND_GIT_COMMIT="$(git rev-parse --short=12 HEAD)" \
QBIND_BUILD_ID="qbind-devnet-0.1.0-$(git rev-parse --short=12 HEAD)" \
  cargo build -p qbind-node --release --locked --bin qbind-node
```

Injecting `QBIND_GIT_COMMIT` / `QBIND_BUILD_ID` changes the compiled label strings
and therefore the SHA-256 / ELF BuildID relative to a no-injection build, so the
injected artifact's binary hash, ELF BuildID, and the canonical injected values are
recorded together (see `REPRODUCIBILITY.md` §Run 383 and
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_383.md`). Two clean builds with the same
source, lockfile, toolchain, and injected provenance produce a **byte-identical**
binary on the reference host; changing the injected `build_id` changes the hash (as
expected). Regenerate the full evidence with
`scripts/devnet/run_383_public_devnet_release_provenance_injected_repro.sh`.

## Canonical release-artifact manifest (Run 384)

Run 384 records the canonical injected build above as a machine-readable,
publish-safe **release-artifact manifest**. The contract is
`RELEASE_ARTIFACT_MANIFEST.schema.json`; a real generated example is
`RELEASE_ARTIFACT_MANIFEST.example.json`. The manifest binds together, for one
published artifact, the fields recorded in this document plus the live metric
labels:

- `injected_QBIND_GIT_COMMIT` / `injected_QBIND_BUILD_ID` — the canonical injected
  provenance.
- `binary_sha256` / `elf_build_id` — the release binary's SHA-256 and ELF
  `.note.gnu.build-id`.
- `metric_build_id` / `metric_git_commit` — the labels from a live loopback
  `qbind_node_build_info` scrape. `metric_build_id` is a **separate field** from and
  is asserted **distinct** from `elf_build_id` (operator-facing release id vs
  linker-computed binary identity).
- `toolchain` / `target_triple` / `cargo_lock_sha256` — the recorded `rustc`/`cargo`
  versions, the host target triple, and the SHA-256 of the committed root
  `Cargo.lock` consumed with `--locked`.
- `reproducibility_scope` — **same-host / per-input** only, referencing the Run 383
  same-input reproducibility evidence and explicitly **not** claiming cross-host or
  SLSA-grade provenance.

The manifest embeds no absolute path, private hostname, external endpoint, secret,
or raw `/metrics` dump. Generate + schema-validate it against the actual build with
`scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh` (evidence
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_384.md`).

## Limitations

- **Toolchain-sensitive.** The SHA-256 and BuildID above are specific to the recorded
  `rustc`/`cargo` 1.97.1 toolchain, target triple, and dependency lockfile. A different toolchain,
  target, or lockfile can change both.
- **No profile hardening applied.** The release profile is unmodified defaults; no reproducibility
  hardening (`SOURCE_DATE_EPOCH`, `--remap-path-prefix`, deterministic `RUSTFLAGS`) was applied or is
  required for the same-host result.
- **Same-host scope only.** These inputs support the same-host, clean-tree reproducibility result in
  `REPRODUCIBILITY.md`. Cross-host reproducibility and SLSA-grade provenance are **not** claimed.
- **No signing.** No signing material exists; no signed-release claim is made.