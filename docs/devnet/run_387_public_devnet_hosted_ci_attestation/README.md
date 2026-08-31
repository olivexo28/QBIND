# Run 387 evidence archive — public DevNet HOSTED-CI keyless attestation execution (M13/M14)

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd, publish-safe output of
`scripts/devnet/run_387_public_devnet_hosted_ci_attestation_verify.sh`. It records only
the decision gate, the resolved `<owner>/<repo>` (public), the release binary basename
and — when available — its SHA-256, whether `gh` is present/authenticated, the exact
`gh attestation verify` command, the verification result, and the honest posture. **No
secret, private key, OIDC token, raw attestation blob, data dir, raw log, private
hostname, git branch, dirty-state string, absolute build path, or raw `/metrics` dump is
committed.** No release/tag/deployment/seed/endpoint is created and no `qbind-node` CLI
flag is added.

Regenerate locally / in hosted CI:

```bash
bash scripts/devnet/run_387_public_devnet_hosted_ci_attestation_verify.sh
```

## Decision gate = Route C (this run)

The objective was to execute the protected Run 386 signing path **for real**: dispatch
`.github/workflows/public-devnet-release-signing-attestation.yml` with `confirm=yes` in a
protected `release-signing` environment, mint a real keyless build-provenance
attestation for `target/release/qbind-node`, and verify it against the binary SHA-256.

From this offline agent sandbox that path **cannot be driven**:

- `gh` is installed but **not authenticated** (`gh auth status` → not logged in), and
  `api.github.com` is **blocked by the environment's DNS proxy**, so the GitHub
  attestation store is unreachable.
- There is **no OIDC issuer** in the sandbox, so `actions/attest-build-provenance`
  cannot mint a keyless attestation here.
- The agent **cannot create/configure the protected `release-signing` GitHub
  Environment** (required reviewers) nor perform a `workflow_dispatch` with
  `confirm=yes`; it cannot push to or administer the repository.
- No release binary is built in this environment, so there is no subject to bind.

Per the task decision gate this is **Route C**: hosted CI cannot be used from this
environment/account. The Run 386 preflight posture is **preserved unchanged** and the
exact blocker is documented. Verdict: **Negative-for-attestation**.

> Route A vs Route C is decided at run time by the harness itself, honestly. When run
> inside GitHub-hosted CI **after** the Run 386 workflow mints an attestation (built
> binary present, `gh` authenticated, attestation store reachable), the harness runs the
> real `gh attestation verify … --predicate-type https://slsa.dev/provenance/v1`, and
> **only if it PASSES** records `RESULT=POSITIVE` and writes a publish-safe
> `ATTESTATION_IDENTITY.txt`. A missing prerequisite or a failed verify keeps it on
> Route C — it never fakes a PASS.

## What Run 387 adds

- **Verify harness** `scripts/devnet/run_387_public_devnet_hosted_ci_attestation_verify.sh`:
  encapsulates the single publish-safe verification contract for the Run 386 workflow —
  `gh attestation verify <binary> --repo <owner>/<repo> --predicate-type
  https://slsa.dev/provenance/v1` bound to the built binary's SHA-256 — and emits only a
  publish-safe attestation **identity** summary (`ATTESTATION_IDENTITY.txt`: workflow,
  repo, predicate type, binary SHA-256, verifier command, verification result, issuer/
  OIDC identity as reported by GitHub, and `signed_release=false` / `slsa_grade=false`).
  It builds nothing, adds no CLI flag, creates no release/endpoint, and never flips the
  schema-pinned manifest fields.
- **This archive** (`README.md`, `summary.txt`, `.gitignore`) and the canonical evidence
  record `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_387.md`.

## Manifest fields (honest, unchanged)

Because no real attestation was minted/verified in this run, the manifest keeps
`reproducibility_scope.signed_release=false`, `reproducibility_scope.slsa_grade=false`,
`non_claims.no_signed_release=true`, and `non_claims.no_slsa_provenance=true`. The
committed `RELEASE_ARTIFACT_MANIFEST.schema.json` still pins both fields to
`const:false`; a real attestation is recorded in a **separate** publish-safe artifact
(`ATTESTATION_IDENTITY.txt`), **never** by flipping those fields or committing the blob.

## Operator/CI prerequisites to complete Route A (real attestation)

1. Create a protected GitHub Environment named `release-signing` with required
   reviewers (Settings → Environments).
2. Dispatch `public-devnet-release-signing-attestation` manually with `confirm = yes`.
3. The job builds the canonical injected artifact (Run 385 wrapper), runs
   `actions/attest-build-provenance` over `target/release/qbind-node`, then
   `gh attestation verify` against the binary SHA-256; this Run 387 harness wraps that
   verify + identity-emit step.
4. Only after a real attestation is minted **and** verified should any `signed_release`
   / `slsa_grade` posture change be considered — via separate manifest fields/artifacts,
   not by weakening the pinned schema.

## Readiness

**M12, M13, M14 remain Green.** M4 stays **Yellow / launch-blocking**; M6 remains
**Yellow/Partial**; the public DevNet remains **NOT launch-ready**; **C4/C5 remain
OPEN**; TestNet/MainNet untouched. This run adds no launch, no seed/bootnode, no
faucet/RPC/explorer/status page, no CLI flag, no P2P wire/admission/trust change, and
mutates no validator set / epoch / sequence / marker / `LivePqcTrustState`.

Canonical evidence record: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_387.md`.