# QBIND DevNet Evidence - Run 385

Wires the Run 384 canonical injected release-artifact **manifest** generation into
**CI** so every published DevNet release build can produce a schema-validated
`RELEASE_ARTIFACT_MANIFEST.json` as a **CI artifact** — never a committed, changing
file. Run 384 (accepted PASS) added the manifest package
(`RELEASE_ARTIFACT_MANIFEST.schema.json` + `.example.json` + the harness) and proved
the manifest is generated from the real canonical injected build and a live loopback
`qbind_node_build_info` scrape, schema-valid, and cross-checked. Run 385 adds a CI
workflow and a local dry-run wrapper that reuse that harness, without any production
Rust source change, `build.rs` change, runtime behaviour change, or new CLI flag,
and without committing any generated CI output. Decision gate **Route A**
(CI/workflow + harness/docs only).

Safety label: DevNet, experimental, no value, resettable, metrics loopback-only by
default, NOT public-DevNet launch-ready, no M4 Green, no M6 Green, no TestNet
readiness, no MainNet readiness, C4/C5 OPEN. This CI/manifest evidence does not imply
launch, TestNet, MainNet, C4, or C5 readiness. There is no source or `build.rs`
change; the workflow and wrapper build the canonical injected artifact, scrape the
resulting metric on loopback, generate a manifest from the actual artifact, validate
it against the committed schema, and archive it as a CI artifact only. No new public
endpoint, no CLI flag, no P2P wire-format change, no peer-admission weakening, and no
trust/validator/epoch/sequence/marker/LivePqcTrustState mutation.

## 1. Exact verdict

PASS / public-DevNet CI release-manifest artifact generation POSITIVE. The new CI
workflow `.github/workflows/public-devnet-release-artifact-manifest.yml` and the
local dry-run wrapper
`scripts/devnet/run_385_public_devnet_ci_release_artifact_manifest.sh` run the same
commands: they build the canonical injected release binary
(`QBIND_GIT_COMMIT=3113c2116154`,
`QBIND_BUILD_ID=qbind-devnet-0.1.0-3113c2116154`) via the reused Run 384 harness,
generate the manifest from the **real** artifact and a **live loopback**
`qbind_node_build_info` scrape, validate it against the committed schema
(`RESULT=POSITIVE`), and stage only publish-safe CI artifacts
(`RELEASE_ARTIFACT_MANIFEST.json`, `qbind-node.sha256`,
`MANIFEST_VALIDATION_SUMMARY.txt`, `BUILDID.txt`). All cross-checks pass: manifest
`binary_sha256`
(`f949b16623bc42bb91a42bac4b5cdf6017ca5cc087976e41ef2e9bfeb2352240`), `elf_build_id`
(`29284c66c8ec3b7a09b838bd921c724e631940eb`), `metric_build_id`
(`qbind-devnet-0.1.0-3113c2116154`), and `metric_git_commit` (`3113c2116154`) equal
the real build / live scrape; the `Cargo.lock` hash
(`70aec07f6e1eb8ea3e98634acefdd92bf9f9ea03929d2821e3cc04c75bb1baaf`) and the
toolchain are recorded; the workflow uses least-privilege `permissions: contents:
read`, references no secrets, creates no release/tag/deployment, and commits/pushes
nothing; the generated manifest is a CI artifact only and is not tracked in git;
`signed_release=false` and `slsa_grade=false` are recorded; the staged directory
excludes raw logs / metrics / data dirs; no new CLI flag; metrics stay
disabled-by-default and loopback-only. M12, M13, M14 remain Green; M4 remains Yellow;
M6 remains Yellow/Partial; the public DevNet remains NOT launch-ready; C4/C5 remain
OPEN; TestNet/MainNet untouched.

## 2. Files changed

No production source or `build.rs` change (CI/workflow + harness/docs only).

New:

- .github/workflows/public-devnet-release-artifact-manifest.yml (new CI workflow).
- scripts/devnet/run_385_public_devnet_ci_release_artifact_manifest.sh (new local dry-run wrapper reusing the Run 384 harness).
- docs/devnet/run_385_public_devnet_ci_release_artifact_manifest/ (README.md, summary.txt, .gitignore) (new archive).
- docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_385.md (this evidence record).

Changed (necessary coupled fix, content-preserving):

- scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh — line endings normalized CRLF → LF only (no logic/content change). The committed Run 384 harness carried CRLF terminators, which abort with `set: pipefail: invalid option name` on a fresh Linux/CI checkout; LF is required for the CI workflow to reuse it. All Run 384 schema and publish-safety checks are preserved byte-for-byte apart from the stripped `\r`.

Updated (binary package docs — CI-manifest pointer only):

- docs/release/public-devnet/binary/README.md
- docs/release/public-devnet/binary/BUILDINFO.md
- docs/release/public-devnet/binary/REPRODUCIBILITY.md
- docs/release/public-devnet/binary/VERIFY.md

Updated (observability package — CI-manifest pointer only; no metric/alert change):

- docs/release/public-devnet/observability/VERIFY.md

Updated (narrow run-log append):

- docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md
- docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md
- docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md
- docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md
- docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md
- docs/whitepaper/contradiction.md

## 3. Decision gate route

Route A (CI/workflow + harness/docs only). Run 384 already generates the manifest
from the real artifact + live scrape and validates it. Run 385 needs no further
source change: it adds a GitHub Actions workflow and a thin wrapper that reuse the
Run 384 harness, then stage the result as a CI artifact. No production Rust,
`build.rs`, dependency, CLI flag, endpoint, or runtime code path is added. The only
non-doc change to an existing file is a content-preserving CRLF→LF normalization of
the Run 384 harness so CI can execute it.

## 4. CI workflow/package contents

`.github/workflows/public-devnet-release-artifact-manifest.yml`:

- Triggers: `workflow_dispatch` (manual) and `push` on version tags (`v*`) —
  release-track scoped only; no branch-push trigger, so a normal merge never runs it.
- `permissions: contents: read` (least privilege; no write scope).
- Steps: checkout (full history for the short commit, `persist-credentials: false`),
  install pinned stable Rust, install `jsonschema`, run the Run 385 wrapper, then
  `actions/upload-artifact` of the staged `ci-artifacts/` bundle only.
- No secrets referenced; no signing; no release/tag/deployment creation; no commit
  or push.

`scripts/devnet/run_385_public_devnet_ci_release_artifact_manifest.sh` (the exact
commands CI runs; running it locally is the dry-run):

- Lints the workflow YAML (valid YAML, manual/release trigger, `permissions ==
  {contents: read}`, no secrets, no release/commit/push).
- Reuses `scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh`
  (`RESULT=POSITIVE`) to build the canonical injected artifact, generate the
  manifest, validate it, and cross-check the live metric.
- Stages publish-safe CI artifacts and re-validates the staged manifest.
- Asserts artifact upload safety, no new CLI flag, `signed_release=false` /
  `slsa_grade=false`, generated manifest not tracked in git, non-claim grep, and
  observability YAML parse.

## 5. Canonical injected build inputs

- `QBIND_GIT_COMMIT=3113c2116154` — `git rev-parse --short=12 HEAD` at build time.
- `QBIND_BUILD_ID=qbind-devnet-0.1.0-3113c2116154` — canonical, low-cardinality,
  non-secret release id (package version `0.1.0` + short commit); injected, not the
  ELF BuildID.

Build command (identical in CI and the wrapper):

    QBIND_GIT_COMMIT=3113c2116154 \
    QBIND_BUILD_ID=qbind-devnet-0.1.0-3113c2116154 \
      cargo build -p qbind-node --release --locked --bin qbind-node

## 6. CI artifact outputs

Uploaded from the staged `ci-artifacts/` directory only:

- `RELEASE_ARTIFACT_MANIFEST.json` — the generated, schema-valid manifest.
- `qbind-node.sha256` — `f949b16623bc42bb91a42bac4b5cdf6017ca5cc087976e41ef2e9bfeb2352240  qbind-node`.
- `MANIFEST_VALIDATION_SUMMARY.txt` — `manifest_schema_valid=OK`, `validator=jsonschema`, plus the publish-safe identity fields and `signed_release=False` / `slsa_grade=False`.
- `BUILDID.txt` — `ELF .note.gnu.build-id: 29284c66c8ec3b7a09b838bd921c724e631940eb`.

Not uploaded: raw node logs, raw `/metrics` dumps, temp data dirs, the working tree,
secrets, or any private material.

## 7. Manifest generation evidence

`run384_reuse=OK (RESULT=POSITIVE)`. The manifest is generated from the actual
CI-built binary (SHA-256, ELF BuildID), a live loopback `qbind_node_build_info`
scrape (metric `build_id` / `git_commit`), the `Cargo.lock` hash, and the recorded
toolchain / target triple — not from any pre-committed value. `ci_artifacts_staged=OK`
and `generated_manifest_not_committed=OK`.

## 8. Manifest schema evidence

`staged_manifest_schema_valid=OK` — the staged `RELEASE_ARTIFACT_MANIFEST.json`
validates against the committed `RELEASE_ARTIFACT_MANIFEST.schema.json` via
`jsonschema` (independent re-validation on top of the Run 384 in-harness validation
of the generated manifest and the committed example).

## 9. Live metric cross-check

Live loopback scrape (HTTP 200, `127.0.0.1`) observed by the reused harness:

    qbind_node_build_info{version="0.1.0",build_id="qbind-devnet-0.1.0-3113c2116154",git_commit="3113c2116154",env="devnet",chain_id="51424e4444455600"} 1

The manifest `metric_build_id` and `metric_git_commit` equal the live scrape labels
and the canonical injected values.

## 10. SHA / ELF BuildID cross-check

`binary_sha256_crosscheck=OK`
(`f949b16623bc42bb91a42bac4b5cdf6017ca5cc087976e41ef2e9bfeb2352240`) and
`elf_build_id_crosscheck=OK` (`29284c66c8ec3b7a09b838bd921c724e631940eb`); the metric
`build_id` is kept a separate field from and asserted distinct from the ELF BuildID.
Both hashes are re-emitted into the staged `qbind-node.sha256` and `BUILDID.txt`.

## 11. Cargo.lock / toolchain evidence

`cargo_lock_recorded=OK cargo_lock_sha256=70aec07f6e1eb8ea3e98634acefdd92bf9f9ea03929d2821e3cc04c75bb1baaf`;
`toolchain_recorded=OK rustc=rustc 1.98.0 (88d9e12ae 2026-08-18) cargo=cargo 1.98.0 (797e8a9bc 2026-08-05)`;
`target_triple=x86_64-unknown-linux-gnu`. Consumed with `--locked`.

## 12. Artifact upload safety

`artifact_upload_safety=OK`: the staged directory contains no `*.log` / `*.metrics*`
/ `*.err` file and no `nodes` / `data` / `logs` directory, and each staged file
carries no absolute private path, no non-loopback endpoint, no secret, and no raw
`/metrics` dump. The workflow uploads only `ci-artifacts/`.

## 13. Workflow permissions/secrets posture

`workflow_least_privilege=OK` (`permissions: contents: read` only; no write scope),
`workflow_no_secrets=OK` (no `secrets.*` reference; no signing this run),
`workflow_no_release=OK` (no release/tag/deployment/seed/endpoint creation; no
commit/push of artifacts). `signed_release=false slsa_grade=false` recorded in the
manifest.

## 14. Default compatibility

`metrics_disabled_by_default=OK` (from the reused harness): a node started without
`QBIND_METRICS_HTTP_ADDR` logs no `/metrics` bind. The metrics transport
(`metrics_http.rs`) is unchanged and binds loopback (`127.0.0.1`) with HTTP 200 only
when env-gated. No runtime behaviour changed.

## 15. CLI surface

`no_new_cli_flag=OK`: `qbind-node --help` exposes no
metrics/observability/build-info/provenance/manifest/artifact/CI flag. The manifest
is generated by the external harness/CI from the built artifact + live scrape;
provenance remains build-time only and exposure remains `QBIND_METRICS_HTTP_ADDR` env
only.

## 16. Reproducibility scope

The manifest `reproducibility_scope` is `same_host:true, per_input:true,
cross_host:false, slsa_grade:false, signed_release:false` and its `reference` points
to `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_383.md`. Same-host / per-input only; Run
385 does not claim cross-host or SLSA-grade reproducibility. A different
host/toolchain/target or a different injected `git_commit` / `build_id` legitimately
changes the SHA-256 / ELF BuildID.

## 17. Non-claim checks

`non_claim_check=OK`: the release-binary + observability docs contain no forbidden
launch-ready / M4-Green / TestNet / MainNet / C4-C5-closure claim. The manifest
`non_claims` object has all of `no_public_devnet_launch`, `no_M4_green`,
`no_M6_green`, `no_testnet_ready`, `no_mainnet_ready`, `no_C4_closure`,
`no_C5_closure`, `no_signed_release`, and `no_slsa_provenance` present and `true`.

## 18. Readiness M13

M13 remains Green. Operator telemetry is unchanged in shape; Run 385 adds CI
generation of the canonical, schema-validated release-artifact manifest, widening
CI/operator auditability while preserving every Run 379/380/381/382/383/384 required
family and the loopback-only, disabled-by-default exposure.

## 19. Readiness M14

M14 remains Green. No alert/scrape change was required; the Run 381 disk gauge /
`QbindNodeDiskSpaceLow` alert and the enabled/future split are unchanged. The
observability example YAML still parses (`observability_yaml_parse=OK`).

## 20. Public DevNet status

NOT launch-ready. CI generation of a release-artifact manifest is an operator/CI
auditability improvement on a valueless, resettable DevNet; it does not launch a
network.

## 21. Remaining DevNet blockers

M4 (external seed reachability) remains Yellow / launch-blocking; M6 remains
Yellow/Partial (M4-gated). No live seed/bootnode, faucet, RPC gateway, explorer, or
status page. All out of scope for Run 385.

## 22. TestNet blockers

All public DevNet blockers above, plus TestNet-grade validator set / economics /
upgrade governance and sustained multi-operator soak — untouched by Run 385.

## 23. MainNet blockers

MainNet custody and MainNet authority rotation/revocation remain Red; C4/C5 must
close first. Untouched by Run 385.

## 24. C4/C5

C4 OPEN. C5 OPEN. Run 385 makes no closure claim and touches no
authority-lifecycle / validator-set / epoch / sequence / marker / LivePqcTrustState
surface.

## 25. Tests run

- Canonical injected release build (via the reused Run 384 harness):
  `QBIND_GIT_COMMIT=3113c2116154 QBIND_BUILD_ID=qbind-devnet-0.1.0-3113c2116154 cargo build -p qbind-node --release --locked --bin qbind-node`:
  OK (sha256 `f949b16623bc42bb91a42bac4b5cdf6017ca5cc087976e41ef2e9bfeb2352240`,
  ELF BuildID `29284c66c8ec3b7a09b838bd921c724e631940eb`).
- scripts/devnet/run_385_public_devnet_ci_release_artifact_manifest.sh:
  RESULT=POSITIVE (all checks OK; see summary.txt).
- scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh (reused):
  RESULT=POSITIVE.
- Manifest schema validation: `jsonschema` OK for the generated manifest, the staged
  manifest, and the committed example.
- Workflow YAML parse/lint: PyYAML parse OK; least-privilege / no-secrets / no-release
  static assertions OK (`actionlint` not installed in this environment — recorded as
  SKIP, not claimed clean).
- Observability example YAML parse (scrape + alerts): OK.
- cargo test -p qbind-node --test run_382_public_devnet_build_info_provenance_tests:
  6 passed, 0 failed.
- cargo test -p qbind-node --lib: not run — no Rust source changed this run
  (CI/workflow + harness/docs only; the only non-doc edit is a CRLF→LF normalization
  of a shell harness). Run 383 recorded 1394 passed, 0 failed on the same Rust
  source; Run 385 adds no Rust delta.
- non-claim grep over the release-binary + observability packages: OK.

## 26. Security scans

secret_scanning over all changed files: no secrets. The canonical injected
provenance tokens (`3113c2116154`, `qbind-devnet-0.1.0-3113c2116154`) and the
recorded hashes are non-secret, low-cardinality identifiers. The workflow references
no secrets and requests only `contents: read`. The wrapper commits no private key,
credential, private hostname, raw log, data dir, git branch, dirty-state string,
absolute build path, or raw `/metrics` dump; node data dirs, scrape dumps, the staged
`ci-artifacts/`, and the generated `RELEASE_ARTIFACT_MANIFEST.json` are CI-artifact /
temporary only and gitignored; only publish-safe hashes and status lines appear in
the tracked summary. Only loopback (`127.0.0.1`) is used.

## 27. CodeQL

No production Rust / `build.rs` change in this run (CI YAML + shell + docs only; the
one non-doc edit is a content-preserving CRLF→LF normalization of a shell harness),
so CodeQL is **trivial / not meaningful** for Run 385: there is no compiled-code
delta to analyze. CodeQL was invoked with a trivial declaration and its result
recorded honestly; no skipped analysis is claimed clean.

## 28. Provenance

Canonical release binary sha256
`f949b16623bc42bb91a42bac4b5cdf6017ca5cc087976e41ef2e9bfeb2352240`, ELF BuildID
`29284c66c8ec3b7a09b838bd921c724e631940eb`; `Cargo.lock` sha256
`70aec07f6e1eb8ea3e98634acefdd92bf9f9ea03929d2821e3cc04c75bb1baaf`; toolchain
`rustc 1.98.0 (88d9e12ae 2026-08-18)` / `cargo 1.98.0 (797e8a9bc 2026-08-05)`;
target `x86_64-unknown-linux-gnu`; git commit `3113c2116154`; canonical injected
metric `build_id=qbind-devnet-0.1.0-3113c2116154`, `git_commit=3113c2116154` (both
distinct from the ELF BuildID). Metric labels observed by a live loopback scrape of
the canonical binary; the manifest is generated from these exact values and archived
as a CI artifact.

## 29. Honest limitations

- **CI wiring of a single reference build.** The workflow records one canonical
  injected build per run on the CI host/toolchain. A different host/toolchain/target
  or a different injected `git_commit` / `build_id` legitimately changes the SHA-256 /
  ELF BuildID. Cross-host reproducibility, SLSA-grade provenance, and signed-release
  attestation are **not** claimed; the manifest says so explicitly.
- **`actionlint` unavailable here.** The workflow was validated with a PyYAML parse
  plus explicit least-privilege / no-secrets / no-release static checks; `actionlint`
  is not installed in this environment and is recorded as SKIP rather than claimed
  clean. A hosted runner with `actionlint` should re-lint.
- **CRLF→LF normalization of the Run 384 harness.** This content-preserving edit was
  required because the committed harness could not execute on Linux; it changes no
  logic and preserves all Run 384 checks.
- **No launch impact.** This is CI/auditability evidence only; M4/M6 remain the
  launch blockers and are untouched. The metrics endpoint remains loopback-only with
  no auth/TLS and must stay loopback.

## 30. Suggested Run 386

Add optional, opt-in release **signing / SLSA provenance** (`signed_release` /
`slsa_grade`) to the CI workflow behind a protected environment and flip the
corresponding manifest fields only when real attestation is produced; and/or begin M4
external seed reachability work (out of scope here), which remains the top launch
blocker.