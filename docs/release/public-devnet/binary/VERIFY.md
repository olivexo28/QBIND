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

## 6a. Re-run the Run 383 canonical injected-provenance reproducibility experiment

Prove the **injected** release build (canonical `QBIND_GIT_COMMIT` / `QBIND_BUILD_ID`) is same-input
reproducible and that a changed injected `build_id` changes the hash:

```
GC="$(git rev-parse --short=12 HEAD)"; BID="qbind-devnet-0.1.0-${GC}"
CARGO_TARGET_DIR=/tmp/qbind-run383-a QBIND_GIT_COMMIT="$GC" QBIND_BUILD_ID="$BID" \
  cargo build -p qbind-node --release --locked --bin qbind-node
CARGO_TARGET_DIR=/tmp/qbind-run383-b QBIND_GIT_COMMIT="$GC" QBIND_BUILD_ID="$BID" \
  cargo build -p qbind-node --release --locked --bin qbind-node
cmp -s /tmp/qbind-run383-a/release/qbind-node /tmp/qbind-run383-b/release/qbind-node && echo IDENTICAL || echo DIFFER
CARGO_TARGET_DIR=/tmp/qbind-run383-a QBIND_GIT_COMMIT="$GC" QBIND_BUILD_ID="${BID}-alt" \
  cargo build -p qbind-node --release --locked --bin qbind-node
sha256sum /tmp/qbind-run383-a/release/qbind-node   # expect a DIFFERENT hash than the identical pair
```

Expected (reference host): the two same-input builds print `IDENTICAL`; the changed `build_id` build
hashes differently. The full harness
(`scripts/devnet/run_383_public_devnet_release_provenance_injected_repro.sh`) automates this and also
scrapes `qbind_node_build_info` to confirm the injected `git_commit` / `build_id` labels. This is a
**same-host, per-input** result only — see `REPRODUCIBILITY.md` §10.

## 6b. Generate and validate the Run 384 release-artifact manifest

Produce a canonical, publish-safe manifest from the **actual** canonical injected build and a live
loopback `qbind_node_build_info` scrape, and validate it against the committed schema:

```
bash scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh
```

Expected: `RESULT=POSITIVE`. The harness builds the canonical injected artifact, generates the
manifest, validates the generated manifest **and** the committed
`RELEASE_ARTIFACT_MANIFEST.example.json` against `RELEASE_ARTIFACT_MANIFEST.schema.json`, and asserts
the manifest's `binary_sha256`, `elf_build_id`, `metric_build_id`, and `metric_git_commit` match the
real build / live scrape (metric `build_id` kept a **separate field** from and distinct from the ELF
BuildID), that the `Cargo.lock` hash and toolchain are recorded, that no absolute path / hostname /
endpoint / secret / raw `/metrics` dump is embedded, that the non-claim fields are all true, and that
the reproducibility scope is same-host / per-input only (referencing Run 383, not cross-host / SLSA).
To validate an existing manifest standalone:

```
python3 -c "import json,jsonschema,sys; \
 s=json.load(open('docs/release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.schema.json')); \
 i=json.load(open('docs/release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.example.json')); \
 jsonschema.validate(i,s); print('manifest OK')"
```

Expected: `manifest OK`.

## 6c. Generate the manifest as a CI artifact (Run 385)

Run 385 wires the Run 384 manifest generation into CI as a **CI artifact** (never a
committed file). Run the same commands the workflow runs — this is the local dry-run:

```
bash scripts/devnet/run_385_public_devnet_ci_release_artifact_manifest.sh
```

Expected: `RESULT=POSITIVE`. The wrapper lints
`.github/workflows/public-devnet-release-artifact-manifest.yml` (valid YAML,
manual/release-track trigger, least-privilege `permissions: contents: read`, no
secrets, no release/commit/push), reuses the Run 384 harness to build + generate +
schema-validate + live-cross-check, and stages only publish-safe CI artifacts
(`RELEASE_ARTIFACT_MANIFEST.json`, `qbind-node.sha256`,
`MANIFEST_VALIDATION_SUMMARY.txt`, `BUILDID.txt`) with raw logs / metrics / data dirs
excluded. The generated `RELEASE_ARTIFACT_MANIFEST.json` is uploaded as a CI artifact
and is **not** committed. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_385.md`.

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
`BUILDINFO.md`, `qbind-node.sha256`, `VERIFY.md`, `RELEASE_ARTIFACT_MANIFEST.schema.json`,
`RELEASE_ARTIFACT_MANIFEST.example.json`); no `qbind-node` ELF blob is tracked. The
`.sha256` file is an ASCII checksum, not a binary.
## 11. Confirm the signing/attestation preflight keeps signed_release/slsa_grade false (Run 386)

```
grep -n '"signed_release"\|"slsa_grade"' RELEASE_ARTIFACT_MANIFEST.example.json
grep -Rin "signed_release=false\|slsa_grade=false" docs/devnet/run_386_public_devnet_release_signing_attestation_preflight/summary.txt
git ls-files ':(glob)**/*.sig' ':(glob)**/*.sigstore*' ':(glob)**/*.intoto.jsonl' ':(glob)**/ATTESTATION_IDENTITY.txt'
```

Expected: the manifest example keeps `signed_release`/`slsa_grade` **false**; the Run 386 summary
records `signed_release=false` / `slsa_grade=false`; and the last command prints nothing (no
signature/attestation/private-key artifact is committed). The optional signing workflow
`.github/workflows/public-devnet-release-signing-attestation.yml` is disabled by default (manual-only,
`confirm` defaults to `no`, protected `release-signing` environment) and mints a keyless GitHub
attestation only when explicitly enabled; verify it then with
`gh attestation verify target/release/qbind-node --repo <owner>/<repo>`.

## 12. Verify a real hosted-CI attestation against the binary SHA-256 (Run 387)

Inside GitHub-hosted CI, after the Run 386 workflow mints a real keyless build-provenance
attestation, run the Run 387 verify harness to bind the attestation to the built binary's
SHA-256 and emit a publish-safe attestation identity:

```
bash scripts/devnet/run_387_public_devnet_hosted_ci_attestation_verify.sh
```

Expected in hosted CI (Route A): the harness runs
`gh attestation verify target/release/qbind-node --repo <owner>/<repo> --predicate-type
https://slsa.dev/provenance/v1`, records `RESULT=POSITIVE` **only** on a genuine PASS, and
writes a publish-safe `ATTESTATION_IDENTITY.txt` (workflow, repo, predicate type, binary
SHA-256, verifier command, verification result, issuer/OIDC identity, and the unchanged
`signed_release=false` / `slsa_grade=false`). Offline (Route C) it honestly records the
missing prerequisite and never fakes a PASS; `signed_release`/`slsa_grade` stay **false**
and the schema still pins both `const:false`. See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_387.md`.