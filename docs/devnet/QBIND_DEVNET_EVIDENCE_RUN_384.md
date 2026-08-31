# QBIND DevNet Evidence - Run 384

Canonical CI/release-artifact **manifest** for the Run 383 canonical injected DevNet
build. Run 383 (accepted PASS) wired the Run 382 `crates/qbind-node/build.rs`
provenance bridge to **canonical injected** values (`QBIND_GIT_COMMIT` /
`QBIND_BUILD_ID`) for a published release artifact so `qbind_node_build_info` ships
populated `git_commit` / `build_id`, and proved the injected build is **same-input
reproducible**. Run 384 records a canonical, publish-safe **release-artifact
manifest** that captures — for the real canonical injected build — the exact
injected inputs, the release-binary SHA-256, the ELF BuildID, the metric `build_id`
/ `git_commit`, the toolchain, the target triple, the `Cargo.lock` hash, the exact
build command, the bounded reproducibility scope, the source-tree state, explicit
non-claims, verification commands, and the artifact safety label. It is a
**docs/harness/schema-only** run (decision gate Route A): **no** production Rust
source change, **no** `build.rs` change, **no** runtime behaviour change, and **no**
new CLI flag.

Safety label: DevNet, experimental, no value, resettable, metrics loopback-only by
default, NOT public-DevNet launch-ready, no M4 Green, no M6 Green, no TestNet
readiness, no MainNet readiness, C4/C5 OPEN. This manifest/provenance evidence does
not imply launch, TestNet, MainNet, C4, or C5 readiness. There is no source or
`build.rs` change; the run builds the canonical injected artifact, scrapes the
resulting metric on loopback, generates a manifest from the actual artifact, and
validates it against the committed schema. No new public endpoint, no CLI flag, no
P2P wire-format change, no peer-admission weakening, and no
trust/validator/epoch/sequence/marker/LivePqcTrustState mutation.

## 1. Exact verdict

PASS / public-DevNet release-artifact manifest POSITIVE. The harness builds the
canonical injected release binary
(`QBIND_GIT_COMMIT=262e2df5c333`,
`QBIND_BUILD_ID=qbind-devnet-0.1.0-262e2df5c333`), generates the manifest from the
**real** artifact and a **live loopback** `qbind_node_build_info` scrape, and the
manifest **validates against the committed schema**. All cross-checks pass: the
manifest `binary_sha256`
(`bf0fadd4dff37aa426e5dfc87fda04123395eff04675f43c65ba1c3cf6d0e673`), `elf_build_id`
(`4bb114ba7cf7fd89795da80c2ad7c2bdee9e45b2`), `metric_build_id`
(`qbind-devnet-0.1.0-262e2df5c333`), and `metric_git_commit` (`262e2df5c333`) equal
the real build / live scrape; the metric `build_id` is kept a separate field from
and distinct from the ELF BuildID; the `Cargo.lock` hash
(`70aec07f6e1eb8ea3e98634acefdd92bf9f9ea03929d2821e3cc04c75bb1baaf`) and the
toolchain are recorded; the manifest carries no absolute path / hostname / endpoint
/ secret / raw `/metrics` dump; the non-claim fields are all present and true; the
reproducibility scope is same-host / per-input only and references Run 383 without
overclaim; metrics stay disabled-by-default and loopback-only; no new CLI flag.
M12, M13, M14 remain Green; M4 remains Yellow; M6 remains Yellow/Partial; the public
DevNet remains NOT launch-ready; C4/C5 remain OPEN; TestNet/MainNet untouched.

## 2. Files changed

No production source or `build.rs` change (docs/harness/schema only).

New (manifest package + harness + archive + evidence):

- docs/release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.schema.json (new schema).
- docs/release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.example.json (new publish-safe example, generated from the real build).
- scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh (new harness).
- docs/devnet/run_384_public_devnet_release_artifact_manifest/ (README.md, summary.txt, .gitignore) (new archive).
- docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_384.md (this evidence record).

Updated (binary package docs — manifest pointers only):

- docs/release/public-devnet/binary/README.md
- docs/release/public-devnet/binary/BUILDINFO.md
- docs/release/public-devnet/binary/REPRODUCIBILITY.md
- docs/release/public-devnet/binary/VERIFY.md

Updated (observability package — manifest pointer only; no metric/alert change):

- docs/release/public-devnet/observability/VERIFY.md

Updated (narrow run-log append):

- docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md
- docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md
- docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md
- docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md
- docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md
- docs/whitepaper/contradiction.md

## 3. Decision gate route

Route A (docs/harness/schema only). Run 382 added the `build.rs` provenance bridge;
Run 383 wired it to canonical injected values and proved same-input
reproducibility. Run 384 needs no further source change: it builds the existing
canonical injected artifact, reads its SHA-256 / ELF BuildID / live metric labels,
records the `Cargo.lock` hash and toolchain, and emits a schema-validated manifest
plus a shell harness and documentation. No new dependency, CLI flag, endpoint, or
runtime code path is added. A tiny release-script helper (the manifest generator) is
included in the harness; no separate production helper was required.

## 4. Manifest package contents

- `RELEASE_ARTIFACT_MANIFEST.schema.json` — JSON Schema (draft-07) contract with
  `additionalProperties:false`, `required` for every mandated field, and
  `const`/`enum` guards on the fixed and non-claim fields.
- `RELEASE_ARTIFACT_MANIFEST.example.json` — a publish-safe example generated from
  the real canonical injected build; validates against the schema.
- `scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh` — the harness
  that builds the artifact, scrapes the live metric, generates the manifest, and
  runs every verification check.

## 5. Canonical injected build inputs

- `QBIND_GIT_COMMIT=262e2df5c333` — the expected short commit,
  `git rev-parse --short=12 HEAD` at build time.
- `QBIND_BUILD_ID=qbind-devnet-0.1.0-262e2df5c333` — a canonical, low-cardinality,
  non-secret release id derived deterministically from the package version
  (`0.1.0`) + short commit. It is **injected** (never derived inside `build.rs` from
  git or the ELF) and is intentionally **not** the ELF BuildID.

Build command:

    QBIND_GIT_COMMIT=262e2df5c333 \
    QBIND_BUILD_ID=qbind-devnet-0.1.0-262e2df5c333 \
      cargo build -p qbind-node --release --locked --bin qbind-node

## 6. Release artifact identity

- `binary_path` = `target/release/qbind-node` (repository-relative; no absolute path).
- `binary_sha256` = `bf0fadd4dff37aa426e5dfc87fda04123395eff04675f43c65ba1c3cf6d0e673`.
- `elf_build_id` = `4bb114ba7cf7fd89795da80c2ad7c2bdee9e45b2` (ELF `.note.gnu.build-id`).
- `metric_build_id` = `qbind-devnet-0.1.0-262e2df5c333`.
- `metric_git_commit` = `262e2df5c333`.

## 7. Manifest schema evidence

`manifest_schema_valid=OK` — the generated manifest validates against
`RELEASE_ARTIFACT_MANIFEST.schema.json` via `jsonschema` (dependency-free structural
fallback available). `example_schema_valid=OK` — the committed
`RELEASE_ARTIFACT_MANIFEST.example.json` validates too. The schema pins
`additionalProperties:false`, requires all mandated fields, and constrains the fixed
fields (`package_name`, `environment`, `binary_path`, `artifact_safety_label`) and
every non-claim / reproducibility-scope boolean with `const`.

## 8. Live metric cross-check

`live_metric_crosscheck=OK`. The live loopback scrape (HTTP 200, `127.0.0.1`) shows:

    qbind_node_build_info{version="0.1.0",build_id="qbind-devnet-0.1.0-262e2df5c333",git_commit="262e2df5c333",env="devnet",chain_id="51424e4444455600"} 1

The manifest `metric_build_id` and `metric_git_commit` equal both the live scrape
labels and the canonical injected values.

## 9. SHA / ELF BuildID cross-check

`binary_sha256_crosscheck=OK` and `elf_build_id_crosscheck=OK`: the manifest
`binary_sha256` equals the real built binary's SHA-256
(`bf0fadd4…`) and the manifest `elf_build_id` equals `readelf -n`'s
`.note.gnu.build-id` (`4bb114ba…`). `elf_vs_metric_separate=OK`: the manifest keeps
`metric_build_id` and `elf_build_id` as **separate fields** and asserts they differ
(distinct provenance planes — a harness-injected operator-facing release id vs a
linker-computed binary identity).

## 10. Cargo.lock / toolchain evidence

`cargo_lock_recorded=OK cargo_lock_sha256=70aec07f6e1eb8ea3e98634acefdd92bf9f9ea03929d2821e3cc04c75bb1baaf`
— the committed root `Cargo.lock` consumed with `--locked`.
`toolchain_recorded=OK rustc=rustc 1.98.0 (88d9e12ae 2026-08-18) cargo=cargo 1.98.0 (797e8a9bc 2026-08-05)`;
`target_triple=x86_64-unknown-linux-gnu`.

## 11. Default compatibility

`metrics_disabled_by_default=OK`: a node started without `QBIND_METRICS_HTTP_ADDR`
logs no `/metrics` bind. The metrics transport (`metrics_http.rs`) is unchanged and
binds loopback (`127.0.0.1`) with HTTP 200 only when env-gated. No runtime behaviour
changed.

## 12. CLI surface

`no_new_cli_flag=OK`: `qbind-node --help` exposes no
metrics/observability/build-info/provenance/manifest/artifact flag. The manifest is
generated by the external harness from the built artifact + live scrape; provenance
remains build-time only and exposure remains `QBIND_METRICS_HTTP_ADDR` env only.

## 13. Reproducibility scope

The manifest `reproducibility_scope` is `same_host:true, per_input:true,
cross_host:false, slsa_grade:false, signed_release:false` and its `reference` points
to `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_383.md`. `reproducibility_scope=OK`: the
harness asserts the scope is same-host / per-input only and **references** Run 383
without overclaiming cross-host or SLSA-grade provenance.

## 14. Non-claim checks

`non_claims_true=OK`: the manifest `non_claims` object has all of
`no_public_devnet_launch`, `no_M4_green`, `no_M6_green`, `no_testnet_ready`,
`no_mainnet_ready`, `no_C4_closure`, `no_C5_closure`, `no_signed_release`, and
`no_slsa_provenance` present and `true`. `non_claim_check=OK`: the release-binary +
observability docs contain no forbidden launch-ready / M4-Green / TestNet / MainNet
/ C4-C5-closure claim. `no_private_material=OK`: the manifest embeds no absolute
path, private hostname, external endpoint, secret, or raw `/metrics` dump;
`schema_example_publish_safe=OK` for the schema and example.

## 15. Readiness M13

M13 remains Green. Operator telemetry is unchanged in shape; Run 384 adds a
canonical, schema-validated release-artifact manifest that records the exact
provenance of the published canonical injected artifact, widening CI/operator
auditability while preserving every Run 379/380/381/382/383 required family and the
loopback-only, disabled-by-default exposure.

## 16. Readiness M14

M14 remains Green. No alert/scrape change was required; the Run 381 disk gauge /
`QbindNodeDiskSpaceLow` alert and the enabled/future split are unchanged. The
observability example YAML still parses.

## 17. Public DevNet status

NOT launch-ready. A release-artifact manifest is an operator/CI auditability
improvement on a valueless, resettable DevNet; it does not launch a network.

## 18. Remaining DevNet blockers

M4 (external seed reachability) remains Yellow / launch-blocking; M6 remains
Yellow/Partial (M4-gated). No live seed/bootnode, faucet, RPC gateway, explorer, or
status page. All out of scope for Run 384.

## 19. TestNet blockers

All public DevNet blockers above, plus TestNet-grade validator set / economics /
upgrade governance and sustained multi-operator soak — untouched by Run 384.

## 20. MainNet blockers

MainNet custody and MainNet authority rotation/revocation remain Red; C4/C5 must
close first. Untouched by Run 384.

## 21. C4/C5

C4 OPEN. C5 OPEN. Run 384 makes no closure claim and touches no
authority-lifecycle / validator-set / epoch / sequence / marker / LivePqcTrustState
surface.

## 22. Tests run

- Canonical injected release build:
  `QBIND_GIT_COMMIT=262e2df5c333 QBIND_BUILD_ID=qbind-devnet-0.1.0-262e2df5c333 cargo build -p qbind-node --release --locked --bin qbind-node`:
  OK (sha256 `bf0fadd4dff37aa426e5dfc87fda04123395eff04675f43c65ba1c3cf6d0e673`,
  ELF BuildID `4bb114ba7cf7fd89795da80c2ad7c2bdee9e45b2`).
- scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh:
  RESULT=POSITIVE (all checks OK; see summary.txt).
- Manifest schema validation: `jsonschema_ok` for the generated manifest and the
  committed example.
- cargo test -p qbind-node --test run_382_public_devnet_build_info_provenance_tests:
  6 passed, 0 failed.
- cargo test -p qbind-node --lib: baseline (no code changed this run; docs/harness/
  schema only). Run 383 recorded 1394 passed, 0 failed on the same source; Run 384
  adds no Rust delta.
- YAML parse (observability scrape + alerts examples): pyyaml_ok for both.
- non-claim grep over the release-binary + observability packages: OK.

## 23. Security scans

secret_scanning over all changed files: no secrets. The canonical injected
provenance tokens (`262e2df5c333`, `qbind-devnet-0.1.0-262e2df5c333`) and the
recorded hashes are non-secret, low-cardinality identifiers. The harness commits no
private key, credential, private hostname, raw log, data dir, git branch,
dirty-state string, absolute build path, or raw `/metrics` dump; node data dirs,
scrape dumps, and the generated `manifest.json` are removed on exit; only
publish-safe hashes and status lines appear in the tracked summary. The committed
example manifest is repository-relative and publish-safe. Only loopback
(`127.0.0.1`) is used.

## 24. CodeQL

No production Rust / `build.rs` change in this run (docs + JSON schema + shell
harness only), so CodeQL is **trivial / not meaningful** for Run 384: there is no
compiled-code delta to analyze. The only source change that introduced the
provenance bridge (`build.rs`) was already analyzed/reviewed under Run 382 and is
unchanged here.

## 25. Provenance

Canonical release binary sha256
`bf0fadd4dff37aa426e5dfc87fda04123395eff04675f43c65ba1c3cf6d0e673`, ELF BuildID
`4bb114ba7cf7fd89795da80c2ad7c2bdee9e45b2`; `Cargo.lock` sha256
`70aec07f6e1eb8ea3e98634acefdd92bf9f9ea03929d2821e3cc04c75bb1baaf`; toolchain
`rustc 1.98.0 (88d9e12ae 2026-08-18)` / `cargo 1.98.0 (797e8a9bc 2026-08-05)`;
target `x86_64-unknown-linux-gnu`; git commit `262e2df5c333`; canonical injected
metric `build_id=qbind-devnet-0.1.0-262e2df5c333`, `git_commit=262e2df5c333`
(both distinct from the ELF BuildID). Metric labels observed by a live loopback
scrape of the canonical binary; the manifest is generated from these exact values.

## 26. Honest limitations

- **Documentation/manifest of a single reference build.** The manifest records one
  canonical injected build on this host/toolchain. A different host/toolchain/target
  or a different injected `git_commit` / `build_id` legitimately changes the SHA-256
  / ELF BuildID (the injected values are compiled in). Cross-host reproducibility,
  SLSA-grade provenance, and signed-release attestation are **not** claimed; the
  manifest's `reproducibility_scope` says so explicitly.
- **References, does not re-prove, Run 383.** The same-input reproducibility result
  is Run 383's; Run 384 references it and does not re-run the two-build experiment.
- **git-dependent commit.** The canonical `QBIND_GIT_COMMIT` is derived from
  `git rev-parse` at build time; a source-tarball / git-less build must inject it
  explicitly or `git_commit` renders `unknown`.
- **No launch impact.** This is auditability evidence only; M4/M6 remain the launch
  blockers and are untouched. The metrics endpoint remains loopback-only with no
  auth/TLS and must stay loopback.

## 27. Suggested Run 385

Wire the Run 384 manifest generation into CI so every published DevNet artifact
emits a schema-validated `RELEASE_ARTIFACT_MANIFEST.json` alongside the binary
(archived as a CI job artifact, not committed), and/or begin M4 external seed
reachability work (out of scope here), which remains the top launch blocker.
