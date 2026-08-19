# QBIND `qbind-node` — Release Provenance Record (Run 359)

> **Safety label:** **experimental · resettable · no value · no MainNet readiness claim ·
> no C4/C5 closure claim.** DevNet-only. Public DevNet is **NOT launch-ready**.

Canonical provenance record for the public DevNet `qbind-node` release binary. All values below were
observed on the reference build host during Run 359.

## 1. Repository

- **Repository (from checkout):** `olivexo28/QBIND` (GitHub).
- **Workspace member built:** `crates/qbind-node` (binary crate `qbind-node`, `src/main.rs`).

## 2. Git commit

```
420bb571281fc243fb0581150b0f628f6ee8d284
```

## 3. Git branch

```
copilot/run-359-update-user-documentation
```

## 4. Clean / dirty state

**Clean** at build time — `git status --porcelain` produced no output for tracked source before the
release builds. The Run 359 change is docs/artifact-only and does not touch any input to the binary
build (no source, `Cargo.toml`, or `Cargo.lock` change).

## 5. Build host OS / architecture

- **OS:** Ubuntu 24.04.4 LTS (Linux, x86-64).
- **Kernel:** `6.17.0-1022-azure` (`uname -m` = `x86_64`).
- **Host triple (rustc):** `x86_64-unknown-linux-gnu`.

> The build host is an ephemeral CI-class sandbox. It is recorded for provenance only and is **not**
> claimed to be a canonical, reproducible reference environment for cross-host builds.

## 6. `rustc --version --verbose`

```
rustc 1.97.1 (8bab26f4f 2026-07-14)
binary: rustc
commit-hash: 8bab26f4f68e0e26f0bb7960be334d5b520ea452
commit-date: 2026-07-14
host: x86_64-unknown-linux-gnu
release: 1.97.1
LLVM version: 22.1.6
```

## 7. `cargo --version --verbose`

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

## 8. Cargo profile

**`release`**, using workspace defaults. There is **no** `[profile.release]` override in the root
`Cargo.toml` or any member `Cargo.toml`, and there is **no** `.cargo/config*` in the repository. The
effective settings are therefore Cargo's release defaults: `opt-level = 3`, `debug = false`,
`strip = false` (symbol table retained — the ELF is reported `not stripped`), `lto = false`,
`codegen-units = 16`, `panic = "unwind"`, `incremental = false`.

## 9. Exact build command

```
cargo build -p qbind-node --release --locked
```

For the reproducibility experiment, the same command was run with `CARGO_TARGET_DIR` pointing at two
separate directories (see `REPRODUCIBILITY.md`).

## 10. `Cargo.lock` present and used

**Yes.** `Cargo.lock` is committed at the repository root (89,859 bytes) and was used for the build.

## 11. Dependency resolution frozen / locked / offline

Built with **`--locked`**, which fails if `Cargo.lock` is out of date, so dependency resolution was
pinned to the committed lockfile. The build was **not** run `--offline` and did **not** set
`--frozen`; `--locked` succeeded without modifying `Cargo.lock`.

## 12. SHA-256 of `target/release/qbind-node`

```
f916af6db4cd1d8575b02f750ad4759c3470c2a2027d532cde50ca06e5b22990
```

Recorded in `qbind-node.sha256` in standard checksum format (`<sha256>  qbind-node`). This is the
checksum of the **locally built** artifact; **no** binary blob is committed to the repository.

## 13. Binary size

```
16557072 bytes
```

## 14. Build timestamp

**Intentionally excluded from the provenance identity.** A wall-clock build timestamp is deliberately
**not** used as an identity input, because embedding build time would defeat reproducibility. The
reference builds completed on 2026-08-19 (UTC) on the sandbox host; this is recorded for context only
and is **not** part of the artifact identity. The produced binary is byte-identical across repeated
same-host builds regardless of build time (see `REPRODUCIBILITY.md`).

## 15. BuildID / debug-id / version metadata present

**Yes.** The ELF carries a GNU BuildID (sha1) and the binary exposes a `--version` string:

- **ELF BuildID (sha1):** `274fdaf3ded72362e87e11ccffce6912bde5208b`
- **`qbind-node --version`:** `qbind-node 0.1.0` (from `#[command(version = "0.1.0")]` in
  `crates/qbind-node/src/cli.rs`).

## 16. Exact command used to extract BuildID / debug-id / version metadata

```
file target/release/qbind-node
readelf -n target/release/qbind-node
objdump -f target/release/qbind-node
target/release/qbind-node --version
```

`file` output (BuildID inline):

```
target/release/qbind-node: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0,
BuildID[sha1]=274fdaf3ded72362e87e11ccffce6912bde5208b, not stripped
```

`readelf -n` (`.note.gnu.build-id`):

```
    Build ID: 274fdaf3ded72362e87e11ccffce6912bde5208b
```

## 17. Safety label and non-launch statement

**experimental · resettable · no value · no MainNet readiness claim · no C4/C5 closure claim.**

Public DevNet is **NOT launch-ready**. This record makes **no** public DevNet launch claim, **no**
public TestNet readiness claim, **no** MainNet readiness claim, **no** SLSA-grade provenance claim, and
**no** signed-release claim. Full **C4 remains OPEN**; **C5 remains OPEN**; MainNet authority
rotation/revocation remains **Red**.
