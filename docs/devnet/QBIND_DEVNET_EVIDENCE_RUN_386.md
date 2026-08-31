# QBIND DevNet Evidence - Run 386

Adds an **optional, disabled-by-default, protected** CI **signing / attestation
preflight** for public DevNet release artifacts, while keeping `signed_release=false`
and `slsa_grade=false` honest. A real, **secret-free** signing/attestation path exists
— GitHub artifact attestation via `actions/attest-build-provenance` (keyless Sigstore
over GitHub OIDC, **no repository secrets**) — but it requires the elevated
`id-token: write` + `attestations: write` permissions and can only mint/verify a
genuine attestation inside GitHub-hosted CI. It cannot run in this offline sandbox, so
Run 386 ships the workflow **disabled by default** with the exact operator/CI
prerequisites and produces **no** signature/attestation in this run. Decision gate
**Route B**.

Safety label: DevNet, experimental, no value, resettable, metrics loopback-only by
default, NOT public-DevNet launch-ready, no M4 Green, no M6 Green, no TestNet
readiness, no MainNet readiness, C4/C5 OPEN. This signing-preflight evidence does not
imply launch, TestNet, MainNet, C4, or C5 readiness. There is no production Rust or
`build.rs` change; no new public endpoint, no CLI flag, no P2P wire-format change, no
peer-admission weakening, and no trust/validator/epoch/sequence/marker/LivePqcTrustState
mutation. No signature, attestation, private key, OIDC token, or raw attestation
material is committed.

## 1. Exact verdict

PASS / public-DevNet release signing-attestation preflight POSITIVE. Run 386 adds the
disabled-by-default protected workflow
`.github/workflows/public-devnet-release-signing-attestation.yml` (manual-only;
`confirm` input defaults to `no`; single job gated on `confirm == 'yes'`; protected
`release-signing` environment; top-level `permissions: contents: read`; job elevates
**only** `id-token: write` + `attestations: write`; no `secrets.*`; uses
`actions/attest-build-provenance` + `gh attestation verify`) and the preflight harness
`scripts/devnet/run_386_public_devnet_release_signing_attestation_preflight.sh`
(`RESULT=POSITIVE`). The harness reuses the Run 385 wrapper (`RESULT=POSITIVE`) to
build the canonical injected release binary
(`QBIND_GIT_COMMIT=cc0ca25e3c04`, `QBIND_BUILD_ID=qbind-devnet-0.1.0-cc0ca25e3c04`),
generate a schema-valid manifest from the **real** artifact
(`binary_sha256=3932279e6f1eea3799562a69d959b1b6286a06a012aca5f96360f4b9948324cd`,
`elf_build_id=636475b1fc3f038a992f6a16947c3f9a722e7da4`) plus a **live loopback**
`qbind_node_build_info` scrape, confirms `signed_release=false` / `slsa_grade=false`
(and that the committed schema still pins both to `const:false`), asserts **no**
signature/attestation/private-key artifact is tracked in git, and preserves the CI
artifact-upload safety, no-new-CLI-flag, and non-claim checks. M12, M13, M14 remain
Green; M4 remains Yellow; M6 remains Yellow/Partial; the public DevNet remains NOT
launch-ready; C4/C5 remain OPEN; TestNet/MainNet untouched.

> The `git_commit` / `build_id` / SHA-256 / ELF BuildID above are a **build-time
> snapshot** at the HEAD when the harness ran; they legitimately change on every commit
> (per-input provenance). The archived
> `docs/devnet/run_386_public_devnet_release_signing_attestation_preflight/summary.txt`
> records the exact values from that run.

## 2. Files changed

No production source or `build.rs` change (CI/workflow + harness/docs only).

New:

- .github/workflows/public-devnet-release-signing-attestation.yml (new disabled-by-default protected signing/attestation workflow).
- scripts/devnet/run_386_public_devnet_release_signing_attestation_preflight.sh (new preflight harness; reuses the Run 385 wrapper).
- docs/devnet/run_386_public_devnet_release_signing_attestation_preflight/ (README.md, summary.txt, .gitignore) (new archive).
- docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_386.md (this evidence record).

Changed (necessary coupled fix, content-preserving):

- scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh — line endings normalized CRLF → LF only (no logic/content change).
- scripts/devnet/run_385_public_devnet_ci_release_artifact_manifest.sh — line endings normalized CRLF → LF only (no logic/content change). Both committed harnesses carried CRLF terminators, which abort with `set: pipefail: invalid option name` on a fresh Linux/CI checkout; LF is required for the CI workflow and this preflight to reuse them. All Run 384/385 checks are preserved byte-for-byte apart from the stripped `\r`.

Updated (binary package docs — signing-preflight pointer only):

- docs/release/public-devnet/binary/README.md
- docs/release/public-devnet/binary/BUILDINFO.md
- docs/release/public-devnet/binary/REPRODUCIBILITY.md
- docs/release/public-devnet/binary/VERIFY.md

Updated (narrow run-log append):

- docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md
- docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md
- docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md
- docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md
- docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md
- docs/whitepaper/contradiction.md

## 3. Decision gate route

**Route B.** A real signing/attestation path exists and needs **no repository
secret** — GitHub artifact attestation (`actions/attest-build-provenance`, keyless
Sigstore over GitHub OIDC). It nonetheless requires a protected CI environment and the
elevated `id-token: write` + `attestations: write` permissions, and it can only mint /
verify a genuine attestation inside GitHub-hosted CI. This offline sandbox has no OIDC
issuer, no `cosign`, and `gh attestation verify` needs a real CI-minted attestation, so
a real attestation cannot be produced or verified here. Per Route B, Run 386 adds a
disabled-by-default workflow stub plus the exact operator/CI prerequisites and keeps
`signed_release=false` / `slsa_grade=false`. No fake/local throwaway signing key is
created; neither field is flipped.

## 4. Signing / attestation design

- **Mechanism.** GitHub build-provenance attestation (`actions/attest-build-provenance@v2`)
  over `target/release/qbind-node`, producing a keyless Sigstore signature bound to the
  workflow's GitHub OIDC identity (SLSA provenance predicate). **No repository secret**
  and **no long-lived private key** are used.
- **Trust root / issuer / identity.** Sigstore public-good Fulcio/Rekor; the signing
  identity is the GitHub Actions OIDC token for
  `repo:<owner>/<repo>:...` on the `release-signing` environment. Verification is
  `gh attestation verify target/release/qbind-node --repo <owner>/<repo>`, which checks
  the attestation covers the exact binary SHA-256.
- **Manifest posture.** The committed `RELEASE_ARTIFACT_MANIFEST.schema.json` pins
  `signed_release` and `slsa_grade` to `const:false`. A real attestation is therefore
  recorded in a **separate** publish-safe artifact file (`ATTESTATION_IDENTITY.txt`:
  binary SHA-256 + verifier command + repo/issuer identity + `verification=PASS`),
  **not** by flipping those fields or committing the attestation blob. ELF BuildID and
  metric `build_id` remain separate planes.

## 5. CI workflow changes

New workflow `.github/workflows/public-devnet-release-signing-attestation.yml`:

- Trigger: `workflow_dispatch` only (no push/tag/schedule) with a `confirm` choice
  input defaulting to `no`.
- `permissions: contents: read` at top level. The single `attest` job is guarded by
  `if: ${{ github.event.inputs.confirm == 'yes' }}`, targets the protected
  `release-signing` environment, and elevates only `id-token: write` +
  `attestations: write`.
- Steps: checkout (`persist-credentials: false`), install pinned stable Rust, build the
  canonical injected artifact + manifest via the Run 385 wrapper,
  `actions/attest-build-provenance` over the binary, `gh attestation verify` against the
  binary, then `actions/upload-artifact` of only the publish-safe checksum +
  `ATTESTATION_IDENTITY.txt`.

The existing manifest workflow
`.github/workflows/public-devnet-release-artifact-manifest.yml` is **unchanged**
(`permissions: contents: read`; no secrets; Run 385 posture preserved).

## 6. Canonical build / manifest regression

`run385_regression=OK (RESULT=POSITIVE)`. The reused Run 385 wrapper (which reuses the
Run 384 harness) built the canonical injected artifact and generated a schema-valid
manifest from the real binary + a live loopback `qbind_node_build_info` scrape:

    QBIND_GIT_COMMIT=cc0ca25e3c04 \
    QBIND_BUILD_ID=qbind-devnet-0.1.0-cc0ca25e3c04 \
      cargo build -p qbind-node --release --locked --bin qbind-node

`binary_sha256=3932279e6f1eea3799562a69d959b1b6286a06a012aca5f96360f4b9948324cd`;
`elf_build_id=636475b1fc3f038a992f6a16947c3f9a722e7da4`;
`cargo_lock_sha256=70aec07f6e1eb8ea3e98634acefdd92bf9f9ea03929d2821e3cc04c75bb1baaf`;
`target=x86_64-unknown-linux-gnu`;
toolchain `rustc 1.98.0 (88d9e12ae 2026-08-18)` / `cargo 1.98.0 (797e8a9bc 2026-08-05)`.
`staged_manifest_schema_valid=OK` (independent re-validation against the committed
schema).

## 7. Signature / attestation artifact outputs

None in this run. No signature, attestation, DSSE bundle, Sigstore/Rekor entry, or
private key was produced or committed (`no_signature_committed=OK`). When the protected
workflow is enabled in CI, its only signing-related artifact is the publish-safe
`ATTESTATION_IDENTITY.txt` (binary SHA-256 + verifier command + repo identity +
`verification=PASS`); the attestation itself lives in GitHub's attestation store, not
in the repository. The preflight stages `RELEASE_ARTIFACT_MANIFEST.json`,
`qbind-node.sha256`, `BUILDID.txt`, and `SIGNING_PREFLIGHT.txt` (Route-B posture) only.

## 8. Verification evidence

No real attestation was produced here, so no `gh attestation verify` PASS is claimed
for this run. The **enabled** path's verification is
`gh attestation verify target/release/qbind-node --repo <owner>/<repo>`
(`--predicate-type https://slsa.dev/provenance/v1`), which the workflow runs and which
must PASS against the built binary's SHA-256 before anything is treated as signed. The
preflight instead verifies the honest posture: `signed_release=false` / `slsa_grade=false`
present and true, schema still pins both `const:false`, and no attestation committed.

## 9. Manifest signed_release / slsa_grade fields

`reproducibility_scope.signed_release=false` and `reproducibility_scope.slsa_grade=false`
(present and true), `non_claims.no_signed_release=true` and
`non_claims.no_slsa_provenance=true`. `schema_pins_false=OK`: the committed schema keeps
`signed_release`/`slsa_grade` `const:false`, so no honest flip is possible without a
real, verified attestation recorded via separate fields/artifacts.

## 10. Workflow permissions / secrets posture

`signing_workflow_least_privilege=OK` (top-level `contents: read`; job elevates only
`id-token: write` + `attestations: write`; no `contents`/`packages`/`deployments`
write), `signing_workflow_no_secrets=OK` (no `secrets.*`; keyless Sigstore over GitHub
OIDC), `signing_workflow_no_release=OK` (no release/tag/deployment; no commit/push).
`manifest_workflow_unchanged=OK`. The `release-signing` environment is referenced by
**name** only (not a secret) and Route B documents that a real attestation is
unavailable locally.

## 11. Artifact upload safety

`artifact_upload_safety=OK`: the staged directory contains no `*.log` / `*.metrics*` /
`*.err` file and no `nodes`/`data`/`logs` directory, and each staged file carries no
absolute private path, no non-loopback endpoint, no secret, no signing key, and no raw
`/metrics` dump. Both workflows upload only their staged `ci-artifacts/` bundle.

## 12. Default compatibility

`metrics_disabled_by_default=OK` (from the reused harness): a node started without
`QBIND_METRICS_HTTP_ADDR` logs no `/metrics` bind. The metrics transport is unchanged
and binds loopback (`127.0.0.1`) with HTTP 200 only when env-gated. No runtime behaviour
changed.

## 13. CLI surface

`no_new_cli_flag=OK`: `qbind-node --help` exposes no
metrics/observability/build-info/provenance/manifest/release-signing/attestation flag.
The pre-existing consensus block-signer flags (`--signer-mode`,
`--signer-keystore-path`) are unrelated and unchanged. Release provenance/signing
remains a CI/build-time concern; node exposure remains `QBIND_METRICS_HTTP_ADDR` env
only.

## 14. Non-claim checks

`non_claim_check=OK`: the release-binary + observability docs contain no forbidden
launch-ready / M4-Green / TestNet / MainNet / C4-C5-closure claim. The manifest
`non_claims` object has all nine fields present and `true` (including
`no_signed_release` and `no_slsa_provenance`).

## 15. Readiness M13

M13 remains Green. Operator/CI telemetry and manifest generation are unchanged in
shape; Run 386 adds an optional, disabled-by-default signing/attestation preflight that
strengthens supply-chain auditability **when explicitly enabled** while preserving every
Run 379/380/381/382/383/384/385 guarantee and the loopback-only, disabled-by-default
exposure.

## 16. Readiness M14

M14 remains Green. No alert/scrape change was required; the Run 381 disk gauge /
`QbindNodeDiskSpaceLow` alert and the enabled/future split are unchanged. The
observability example YAML still parses (`observability_yaml_parse=OK`).

## 17. Public DevNet status

NOT launch-ready. An optional, disabled-by-default CI signing/attestation preflight is a
supply-chain auditability improvement on a valueless, resettable DevNet; it does not
launch a network.

## 18. Remaining DevNet blockers

M4 (external seed reachability) remains Yellow / launch-blocking; M6 remains
Yellow/Partial (M4-gated). No live seed/bootnode, faucet, RPC gateway, explorer, or
status page. All out of scope for Run 386.

## 19. TestNet blockers

All public DevNet blockers above, plus TestNet-grade validator set / economics /
upgrade governance and sustained multi-operator soak — untouched by Run 386.

## 20. MainNet blockers

MainNet custody and MainNet authority rotation/revocation remain Red; C4/C5 must close
first. Untouched by Run 386.

## 21. C4/C5

C4 OPEN. C5 OPEN. Run 386 makes no closure claim and touches no
authority-lifecycle / validator-set / epoch / sequence / marker / LivePqcTrustState
surface.

## 22. Tests run

- scripts/devnet/run_386_public_devnet_release_signing_attestation_preflight.sh:
  RESULT=POSITIVE (all checks OK; see archived summary.txt).
- scripts/devnet/run_385_public_devnet_ci_release_artifact_manifest.sh (reused
  regression): RESULT=POSITIVE.
- scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh (reused):
  RESULT=POSITIVE.
- Manifest schema validation (`jsonschema`): OK for the generated and staged manifests
  and the committed example.
- Signing workflow YAML parse + static safety lint (manual-only; `confirm` default
  `no`; job `if` == `'yes'`; protected environment; top-level `contents: read`; only
  `id-token`+`attestations` write; no secrets; no release/commit): OK. Manifest
  workflow re-lint (`permissions: contents: read`; no secrets): OK. `actionlint` not
  installed here — recorded as SKIP, not claimed clean.
- Observability example YAML parse (scrape + alerts): OK.
- cargo test -p qbind-node --test run_382_public_devnet_build_info_provenance_tests:
  6 passed, 0 failed.
- cargo test -p qbind-node --lib: not run — no Rust source changed this run
  (CI/workflow + harness/docs only; the only non-doc edits are content-preserving
  CRLF→LF normalizations of two shell harnesses). Run 383 recorded 1394 passed, 0
  failed on the same Rust source; Run 386 adds no Rust delta.
- non-claim grep over the release-binary + observability packages: OK.

## 23. Security scans

secret_scanning over all changed files: no secrets. The signing workflow references
**no** `secrets.*`, uses keyless GitHub OIDC (no long-lived key), and requests only the
minimal `id-token`+`attestations` writes. No private key, signing token, credential,
raw attestation secret, raw log, raw `/metrics` dump, data dir, private endpoint,
hostname, git branch, dirty-state string, or absolute build path is committed; node data
dirs, scrape dumps, the staged `ci-artifacts/`, the generated
`RELEASE_ARTIFACT_MANIFEST.json`, and any future attestation bundle are CI-artifact /
temporary only and gitignored. Only loopback (`127.0.0.1`) is used. The protected
`release-signing` environment is referenced by name only.

## 24. CodeQL

No production Rust / `build.rs` change in this run (CI YAML + shell + docs only; the two
non-doc edits are content-preserving CRLF→LF normalizations of shell harnesses), so
CodeQL is **trivial / not meaningful** for Run 386: there is no compiled-code delta to
analyze. CodeQL was invoked with a trivial declaration and its result recorded honestly;
no skipped analysis is claimed clean.

## 25. Provenance

Canonical release binary sha256
`3932279e6f1eea3799562a69d959b1b6286a06a012aca5f96360f4b9948324cd`, ELF BuildID
`636475b1fc3f038a992f6a16947c3f9a722e7da4`; `Cargo.lock` sha256
`70aec07f6e1eb8ea3e98634acefdd92bf9f9ea03929d2821e3cc04c75bb1baaf`; toolchain
`rustc 1.98.0 (88d9e12ae 2026-08-18)` / `cargo 1.98.0 (797e8a9bc 2026-08-05)`; target
`x86_64-unknown-linux-gnu`; git commit `cc0ca25e3c04`; canonical injected metric
`build_id=qbind-devnet-0.1.0-cc0ca25e3c04`, `git_commit=cc0ca25e3c04` (both distinct
from the ELF BuildID). Values are a build-time snapshot; the archived summary.txt is the
authoritative record for that run. No signature/attestation was minted here; the enabled
CI path would additionally bind a keyless build-provenance attestation to this binary's
SHA-256.

## 26. Honest limitations

- **No real attestation in this run.** Route B: the keyless GitHub attestation path
  needs GitHub-hosted CI + `id-token`/`attestations` writes + a protected environment
  and cannot be minted/verified offline. `signed_release`/`slsa_grade` therefore stay
  `false`; a real attestation must be produced by the enabled workflow and verified
  against the binary SHA-256 before any posture change.
- **Disabled by default.** The signing workflow only runs on a manual dispatch with
  `confirm = yes` in the protected `release-signing` environment; an operator must first
  create that environment with required reviewers.
- **`actionlint` unavailable here.** Both workflows were validated with a PyYAML parse
  plus explicit least-privilege / no-secrets / no-release static checks; a hosted runner
  with `actionlint` should re-lint.
- **CRLF→LF normalization of two shell harnesses.** Content-preserving edits required
  because the committed run_384/run_385 harnesses carried CRLF and could not execute on
  Linux/CI; they change no logic and preserve all Run 384/385 checks.
- **Snapshot provenance.** The recorded SHA-256 / ELF BuildID / git_commit are per-input
  and per-HEAD; they change on later commits. Cross-host reproducibility and SLSA-grade
  provenance are not claimed.
- **No launch impact.** M4/M6 remain the launch blockers and are untouched; the metrics
  endpoint remains loopback-only with no auth/TLS and must stay loopback.

## 27. Suggested Run 387

Once a protected `release-signing` environment exists on a hosted runner, dispatch the
Run 386 workflow with `confirm = yes` to mint a **real** keyless build-provenance
attestation, verify it with `gh attestation verify` against the binary SHA-256, and
record the attestation identity in a separate publish-safe artifact (still without
flipping the schema-pinned fields unless/until a signed-release contract is designed);
and/or begin M4 external seed reachability work, which remains the top launch blocker.