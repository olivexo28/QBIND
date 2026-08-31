# Run 386 evidence archive — public DevNet release signing/attestation preflight (M13/M14)

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_386_public_devnet_release_signing_attestation_preflight.sh` and
contains only publish-safe values: the decision gate, the disabled-by-default signing
workflow path, the reused manifest workflow / Run 385 wrapper paths, the workflow
safety-lint results, the canonical injected provenance tokens (`QBIND_GIT_COMMIT`
short commit + the canonical `QBIND_BUILD_ID`), the release-binary SHA-256, the ELF
`.note.gnu.build-id`, and the OK / POSITIVE status lines. **No secret, private key,
OIDC token, raw attestation material, data dir, raw log, private hostname, git branch,
dirty-state string, absolute build path, or raw `/metrics` dump is committed.**

Regenerate locally (this is the dry-run/preflight that proves the exact safety checks
before the protected CI signing path is ever enabled):

```bash
bash scripts/devnet/run_386_public_devnet_release_signing_attestation_preflight.sh
```

## Decision gate = Route B

A real, **secret-free** signing/attestation path exists — GitHub artifact attestation
via [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance)
(keyless Sigstore over GitHub OIDC, **no repository secrets**) — **but** it requires
the elevated `id-token: write` + `attestations: write` permissions and can only mint /
verify a genuine attestation inside GitHub-hosted CI. It **cannot** run in this offline
sandbox (no OIDC issuer, no `cosign`; `gh attestation verify` needs a real CI-minted
attestation). So Run 386 ships a **disabled-by-default, protected** signing workflow
plus the exact operator/CI prerequisites and keeps the release-artifact manifest
honest: **`signed_release=false`** and **`slsa_grade=false`** remain present and true.
No signature or attestation is produced or committed in this run.

## What Run 386 adds

- **Disabled-by-default protected workflow**
  `.github/workflows/public-devnet-release-signing-attestation.yml`:
  - Manual-only (`workflow_dispatch`); a required `confirm` input **defaults to `no`**
    and the single job is guarded by `if: inputs.confirm == 'yes'`, so an accidental
    dispatch is a no-op.
  - Targets a protected GitHub Environment (`release-signing`) an operator must create
    with required reviewers. The environment **name** is not a secret and **no**
    `secrets.*` value is referenced.
  - Top-level `permissions: contents: read`; the job narrowly elevates **only**
    `id-token: write` (keyless OIDC) and `attestations: write` (write the provenance
    attestation) — no `contents`/`packages`/`deployments` write, no repository secret.
  - Builds the canonical injected artifact via the reused Run 385 wrapper, runs
    `actions/attest-build-provenance` over `target/release/qbind-node`, then
    `gh attestation verify` against the binary, and uploads only a publish-safe
    checksum + attestation-**identity** summary (never a private key, OIDC token, raw
    attestation secret, raw log, `/metrics` dump, data dir, or the ELF blob).
- **Preflight harness**
  `scripts/devnet/run_386_public_devnet_release_signing_attestation_preflight.sh`:
  lints both workflows (the new signing workflow's disabled-by-default / least-privilege
  / no-secrets posture, and the unchanged manifest workflow), reuses the Run 385 wrapper
  (`RESULT=POSITIVE`) to build + generate + schema-validate + live-cross-check, confirms
  `signed_release=false` / `slsa_grade=false` (and that the committed schema still pins
  both to `const:false`), asserts **no** signature/attestation/private-key artifact is
  tracked in git, and preserves the CI artifact-upload safety, no-new-CLI-flag, and
  non-claim checks.

## Manifest fields (honest, unchanged)

Because no real attestation is minted/verified here, the manifest keeps
`reproducibility_scope.signed_release=false` and `reproducibility_scope.slsa_grade=false`
and `non_claims.no_signed_release=true` / `non_claims.no_slsa_provenance=true`. The
committed `RELEASE_ARTIFACT_MANIFEST.schema.json` pins both fields to `const:false`; a
real attestation is recorded in a **separate** publish-safe artifact file by the CI job,
**never** by flipping those fields or committing the attestation blob.

## Operator/CI prerequisites to enable real signing (Route B → real attestation)

1. Create a protected GitHub Environment named `release-signing` with required
   reviewers (Settings → Environments).
2. Dispatch `public-devnet-release-signing-attestation` manually with `confirm = yes`.
3. The job mints a keyless build-provenance attestation (GitHub OIDC; no secrets) and
   verifies it against the binary's SHA-256 with `gh attestation verify`.
4. Only after a real attestation is minted **and** verified should any `signed_release`
   / `slsa_grade` posture change be considered — via separate manifest fields/artifacts,
   not by weakening the pinned schema.

## Readiness

**M12, M13, M14 remain Green.** M4 stays **Yellow / launch-blocking**; M6 remains
**Yellow/Partial**; the public DevNet remains **NOT launch-ready**; **C4/C5 remain
OPEN**; TestNet/MainNet untouched. This preflight adds no launch, no seed/bootnode, no
faucet/RPC/explorer/status page, no CLI flag, no P2P wire/admission/trust change, and
mutates no validator set / epoch / sequence / marker / `LivePqcTrustState`.

Canonical evidence record: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_386.md`.