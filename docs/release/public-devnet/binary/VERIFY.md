# QBIND `qbind-node` — Provenance Package Verification (Run 359)

> **Safety label:** **experimental · resettable · no value · no MainNet readiness claim ·
> no C4/C5 closure claim.** DevNet-only. Public DevNet is **NOT launch-ready**.

Run every command from the repository root. These reproduce the checks behind this provenance package.
Expected reference values are for `rustc`/`cargo` 1.97.1 on `x86_64-unknown-linux-gnu`; a different
toolchain/host may legitimately produce different SHA-256 / BuildID values (see `REPRODUCIBILITY.md`).

## 1. Build `qbind-node` release with the documented command

```
cargo build -p qbind-node --release --locked
```

Expected: build succeeds and `target/release/qbind-node` exists.

```
ls -l target/release/qbind-node
```

## 2. Verify `qbind-node.sha256`

```
( cd target/release && sha256sum -c "$OLDPWD/docs/release/public-devnet/binary/qbind-node.sha256" )
```

Expected:

```
qbind-node: OK
```

Reference SHA-256: `f916af6db4cd1d8575b02f750ad4759c3470c2a2027d532cde50ca06e5b22990`.

## 3. Print `rustc --version --verbose`

```
rustc --version --verbose
```

Expected (reference host): `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `host: x86_64-unknown-linux-gnu`.

## 4. Print `cargo --version --verbose`

```
cargo --version --verbose
```

Expected (reference host): `cargo 1.97.1 (c980f4866 2026-06-30)`.

## 5. Extract / attempt BuildID / debug-id / version metadata

```
file target/release/qbind-node
readelf -n target/release/qbind-node
objdump -f target/release/qbind-node
target/release/qbind-node --version
```

Expected (reference host): ELF BuildID `274fdaf3ded72362e87e11ccffce6912bde5208b`;
`--version` prints `qbind-node 0.1.0`. If `readelf`/`objdump`/`file` is unavailable on your platform,
record that it is unavailable — do not invent BuildID output.

## 6. Re-run the two-build reproducibility experiment

```
CARGO_TARGET_DIR=/tmp/qbind-run359-a cargo build -p qbind-node --release --locked
CARGO_TARGET_DIR=/tmp/qbind-run359-b cargo build -p qbind-node --release --locked
sha256sum /tmp/qbind-run359-a/release/qbind-node /tmp/qbind-run359-b/release/qbind-node
cmp -s /tmp/qbind-run359-a/release/qbind-node /tmp/qbind-run359-b/release/qbind-node && echo IDENTICAL || echo DIFFER
```

Expected (reference host): both SHA-256 equal `f916af6d…b22990`; `cmp` prints `IDENTICAL`. If they
differ on your host, that is bounded cross-host/toolchain non-determinism — record it; the published
result is a **same-host** claim only.

## 7. Confirm public DevNet is not claimed launch-ready

```
grep -RiL "NOT launch-ready" docs/release/public-devnet/binary/README.md
grep -Rin "launch-ready" docs/release/public-devnet/binary/*.md
```

Expected: the first command prints nothing (every check confirms the README asserts NOT launch-ready);
the surrounding text always negates any "launch-ready" mention.

## 8. Confirm C4/C5 are not claimed closed

```
grep -Rin "C4 remains OPEN\|C5 remains OPEN\|no C4/C5 closure" docs/release/public-devnet/binary/
```

Expected: matches present; no doc claims C4 or C5 closed.

## 9. Confirm MainNet / TestNet readiness is not claimed

```
grep -Rin "no MainNet readiness claim\|no .*TestNet readiness claim\|MainNet readiness" docs/release/public-devnet/binary/
```

Expected: only negative statements ("no MainNet readiness claim", "no ... TestNet readiness claim");
no positive readiness claim.

## 10. Confirm no binary blob is committed

```
git ls-files docs/release/public-devnet/binary/
file docs/release/public-devnet/binary/qbind-node.sha256
```

Expected: only text files are tracked (`README.md`, `RELEASE_PROVENANCE.md`, `REPRODUCIBILITY.md`,
`BUILDINFO.md`, `qbind-node.sha256`, `VERIFY.md`); no `qbind-node` ELF blob is tracked. The
`.sha256` file is an ASCII checksum, not a binary.
