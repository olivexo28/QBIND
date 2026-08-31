# QBIND DevNet Evidence - Run 387

Attempts to **execute the protected hosted-CI signing/attestation path for real** —
dispatch the Run 386 workflow with `confirm=yes` in a protected `release-signing`
environment, mint a real keyless build-provenance attestation for
`target/release/qbind-node`, and verify it against the binary SHA-256. From this offline
agent sandbox that path **cannot be driven** (`gh` unauthenticated, `api.github.com`
DNS-blocked, no OIDC issuer, no ability to create the protected environment or dispatch
`confirm=yes`, repository not administrable). Decision gate **Route C**: hosted CI cannot
be used from this environment/account. The Run 386 preflight posture is **preserved
unchanged** — `signed_release=false` and `slsa_grade=false` stay present and true, the
committed schema still pins both to `const:false`, and no attestation/signature/private
key is produced or committed. Run 387 adds a publish-safe **verify harness** that runs
the real `gh attestation verify` binding when executed inside hosted CI, plus this
evidence and a publish-safe archive.

Safety label: DevNet, experimental, no value, resettable, metrics loopback-only by
default, NOT public-DevNet launch-ready, no M4 Green, no M6 Green, no TestNet readiness,
no MainNet readiness, C4/C5 OPEN. This attestation-execution evidence does not imply
launch, TestNet, MainNet, C4, or C5 readiness. There is no production Rust or `build.rs`
change; no new public endpoint, no CLI flag, no P2P wire-format change, no peer-admission
weakening, and no trust/validator/epoch/sequence/marker/LivePqcTrustState mutation. No
signature, attestation, private key, OIDC token, or raw attestation material is committed.

## 1. Exact verdict

**Negative-for-attestation.** Decision gate **Route C**: the protected hosted-CI keyless
attestation path could not be executed from this environment/account, so no real
attestation was minted or verified in this run. Per the task's expected verdicts, when
protected CI prerequisites are absent the run is Negative-for-attestation and **preserves
the Run 386 preflight posture**. Run 387 adds the publish-safe verify harness
`scripts/devnet/run_387_public_devnet_hosted_ci_attestation_verify.sh`
(`RESULT=NEGATIVE-FOR-ATTESTATION` here; `RESULT=POSITIVE` only when a real hosted-CI
attestation verifies against the binary SHA-256), the archive
`docs/devnet/run_387_public_devnet_hosted_ci_attestation/`, and this record. M12, M13,
M14 remain Green; M4 remains Yellow / launch-blocking; M6 remains Yellow/Partial; the
public DevNet remains NOT launch-ready; C4/C5 remain OPEN; TestNet/MainNet untouched.
`signed_release=false` / `slsa_grade=false` are unchanged and the schema still pins both
`const:false`.

## 2. Files changed

No production source or `build.rs` change (harness/docs only).

New:

- scripts/devnet/run_387_public_devnet_hosted_ci_attestation_verify.sh (new publish-safe verify harness; run-time Route A/Route C gating; never fakes a PASS).
- docs/devnet/run_387_public_devnet_hosted_ci_attestation/ (README.md, summary.txt, .gitignore) (new archive).
- docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_387.md (this evidence record).

Updated (binary package docs — hosted-CI attestation pointer only):

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

No existing workflow, schema, manifest example, Rust source, or `build.rs` was changed.
`.github/workflows/public-devnet-release-signing-attestation.yml` (Run 386) and
`.github/workflows/public-devnet-release-artifact-manifest.yml` (Run 385) are unchanged.

## 3. Decision gate route

**Route C.** Hosted GitHub CI cannot be used from this offline agent sandbox/account:

- `gh` is installed (v2.98.0) but **not authenticated** (`gh auth status` → not logged
  into any host), and `api.github.com` is **blocked by the environment's DNS proxy**, so
  the GitHub attestation store is unreachable for `gh attestation verify`.
- There is **no OIDC issuer** in the sandbox, so `actions/attest-build-provenance` cannot
  mint a keyless Sigstore attestation here.
- The agent **cannot create/configure the protected `release-signing` GitHub Environment**
  (required reviewers) and **cannot perform a `workflow_dispatch` with `confirm=yes`**; it
  has no repository-admin capability and cannot push directly.
- No release binary is built in this environment, so there is no subject to bind.

Route B (hosted CI reachable but protected environment/permissions incomplete) is **not**
applicable, because hosted CI is not reachable from here at all. Route A is not applicable
for the same reason. Per Route C the Run 386 preflight is left unchanged and the exact
blocker is recorded; neither `signed_release` nor `slsa_grade` is flipped.

## 4. Hosted CI execution

Not performed from this environment (Route C). The two existing runs of
`public-devnet-release-signing-attestation.yml` observed via the GitHub Actions API are
`event=push` **startup failures** (the workflow has no `push` trigger), **not** the
`workflow_dispatch` + `confirm=yes` protected path, and mint no attestation. No
confirm-gated protected dispatch has succeeded. When an operator runs the protected path
on GitHub-hosted CI, the Run 387 harness performs the real verify + identity emit step.

## 5. Protected environment evidence

Not established from this environment. The protected `release-signing` GitHub Environment
(required reviewers) must be created by a repository administrator; the agent cannot
create it and cannot reach the environments API (DNS-blocked). The workflow references the
environment by **name** only (not a secret). No protected-environment execution occurred
in this run, so no environment-scoped attestation identity exists yet.

## 6. Canonical build / manifest evidence

No canonical build was run in this environment for Run 387 (the harness builds nothing;
the canonical injected build remains the Run 385 wrapper's job, executed inside the Run
386 workflow). The last recorded canonical injected build (Run 386 archive) was
`QBIND_GIT_COMMIT=cc0ca25e3c04`,
`QBIND_BUILD_ID=qbind-devnet-0.1.0-cc0ca25e3c04`,
`binary_sha256=3932279e6f1eea3799562a69d959b1b6286a06a012aca5f96360f4b9948324cd`,
`elf_build_id=636475b1fc3f038a992f6a16947c3f9a722e7da4`. These are a build-time snapshot
and legitimately change per input/HEAD; the authoritative record for a given attestation
is the `ATTESTATION_IDENTITY.txt` emitted alongside that run's binary.

## 7. Attestation mint evidence

None in this run. No keyless build-provenance attestation was minted; no OIDC issuer,
`cosign`, or Sigstore/Rekor entry is available in the sandbox. `actions/attest-build-
provenance` runs only inside GitHub-hosted CI. No attestation blob, DSSE bundle, or
signature was produced or committed (`no_attestation_committed=OK`).

## 8. Attestation verification evidence

`verification=NOT-RUN` in this environment (Route C). The harness resolved the verifier
command `gh attestation verify qbind-node --repo olivexo28/QBIND --predicate-type
https://slsa.dev/provenance/v1` but did not execute it against a real attestation because
`gh` is unauthenticated, the attestation store is unreachable, and no binary/attestation
exists here. No `gh attestation verify` PASS is claimed. When run in hosted CI after the
Run 386 workflow mints an attestation, the harness runs this exact command and records
`RESULT=POSITIVE` **only** on a genuine PASS.

## 9. Subject SHA binding

No subject binding in this run: `binary_sha256=UNAVAILABLE (binary not built in this
environment)`. The verification contract binds the attestation to the **built binary's**
SHA-256 (`gh attestation verify target/release/qbind-node`), and the harness records that
SHA-256 into `ATTESTATION_IDENTITY.txt` only on a real PASS. No binding is asserted
without a verified attestation.

## 10. Attestation identity artifact

No `ATTESTATION_IDENTITY.txt` is committed this run (none minted). The harness's designed
publish-safe identity artifact records: workflow name
(`public-devnet-release-signing-attestation`), repository identity (`<owner>/<repo>`),
predicate type (`https://slsa.dev/provenance/v1`), subject binary basename and SHA-256,
verifier command, verification result, issuer / OIDC identity as reported by GitHub, and
the `signed_release=false` / `slsa_grade=false` posture. Run id / run URL are recorded
only if publish-safe. The raw attestation blob is **never** written; it lives in GitHub's
attestation store.

## 11. Manifest signed_release / slsa_grade posture

Unchanged and honest: `reproducibility_scope.signed_release=false`,
`reproducibility_scope.slsa_grade=false`, `non_claims.no_signed_release=true`,
`non_claims.no_slsa_provenance=true`. The committed
`RELEASE_ARTIFACT_MANIFEST.schema.json` still pins both fields to `const:false`. Per the
task hard rule, no schema-pinned field is flipped because no real attestation was minted
and verified; a real attestation identity is recorded in the separate publish-safe
artifact only.

## 12. Workflow permissions / secrets posture

Unchanged from Run 386 (no workflow edited). The signing/attestation workflow keeps
top-level `permissions: contents: read`; the single gated `attest` job elevates **only**
`id-token: write` + `attestations: write` (no contents/packages/deployments/pull-requests
write) and references **no** `secrets.*` (keyless Sigstore over GitHub OIDC). The Run 385
manifest workflow keeps `permissions: contents: read`, no secrets. The Run 387 harness
references no secret and requires none.

## 13. Artifact upload safety

`artifact_upload_safety=OK`. The harness emits only publish-safe lines (owner/repo, binary
basename, SHA-256 when available, `gh` presence/auth booleans, the verifier command, and
status lines). It writes no raw log, `/metrics` dump, data dir, absolute path, private
hostname, token, key, or raw attestation blob. The archive tracks only
`README.md`/`summary.txt`/`.gitignore`; the `.gitignore` excludes any built binary,
manifest, attestation-identity file, signature, key, OIDC/JWT material, log, or metrics
dump.

## 14. Default compatibility

`metrics_disabled_by_default=OK` (posture preserved via the reused Run 385/386 path). A
node started without `QBIND_METRICS_HTTP_ADDR` binds no `/metrics`; the metrics transport
is unchanged and binds loopback (`127.0.0.1`) only when env-gated. Run 387 changes no
runtime behaviour.

## 15. CLI surface

`no_new_cli_flag=OK`. Run 387 adds no `qbind-node` CLI flag; release provenance/signing/
attestation remains a CI/build-time concern. The pre-existing consensus block-signer
flags (`--signer-mode`, `--signer-keystore-path`) are unrelated and unchanged; node
exposure remains `QBIND_METRICS_HTTP_ADDR` env only.

## 16. Non-claim checks

`non_claim_check=OK`. The release-binary + observability docs and the new Run 387 evidence
contain no forbidden launch-ready / M4-Green / TestNet / MainNet / C4-C5-closure claim.
No `signed_release`/`slsa_grade` flip is claimed. The verdict is explicitly
Negative-for-attestation.

## 17. Readiness M13

M13 remains Green. Operator/CI telemetry and manifest generation are unchanged in shape;
Run 387 adds only an optional publish-safe verify harness + docs and preserves every Run
379–386 guarantee and the loopback-only, disabled-by-default exposure.

## 18. Readiness M14

M14 remains Green. No alert/scrape change was required; the Run 381 disk gauge /
`QbindNodeDiskSpaceLow` alert and the enabled/future split are unchanged.

## 19. Public DevNet status

NOT launch-ready. Attempting (and honestly failing to reach) the hosted-CI attestation
path from an offline sandbox does not launch a network. M4/M6 remain the launch blockers.

## 20. Remaining DevNet blockers

M4 (external seed reachability) remains Yellow / launch-blocking; M6 remains
Yellow/Partial (M4-gated). No live seed/bootnode, faucet, RPC gateway, explorer, or status
page. Also outstanding for signed release: a protected `release-signing` environment on a
hosted runner and a completed confirm-gated dispatch (Route A). All out of scope for the
strict Run 387 scope beyond documenting the blocker.

## 21. TestNet blockers

All public DevNet blockers above, plus TestNet-grade validator set / economics / upgrade
governance and sustained multi-operator soak — untouched by Run 387.

## 22. MainNet blockers

MainNet custody and MainNet authority rotation/revocation remain Red; C4/C5 must close
first. Untouched by Run 387.

## 23. C4/C5

C4 OPEN. C5 OPEN. Run 387 makes no closure claim and touches no
authority-lifecycle / validator-set / epoch / sequence / marker / LivePqcTrustState
surface.

## 24. Tests run

- scripts/devnet/run_387_public_devnet_hosted_ci_attestation_verify.sh:
  RESULT=NEGATIVE-FOR-ATTESTATION (Route C; honest blocker recorded; see archived
  summary.txt). Also exercised writing to the archive path — same Route C result.
- GitHub Actions API inspection of `public-devnet-release-signing-attestation.yml` runs:
  both existing runs are `event=push` startup failures, not confirm-gated dispatches;
  no attestation minted.
- No Rust build/test run this run (harness/docs only; no Rust or `build.rs` delta). The
  reused Run 385/386 canonical build path is unchanged; Run 383 recorded 1394 passed, 0
  failed on the same Rust source and Run 387 adds no Rust delta.
- non-claim grep over the release-binary + observability packages: OK.

## 25. Security scans

secret_scanning over all changed files: no secrets. The Run 387 harness references **no**
`secrets.*` and requires none; it emits only owner/repo (public), binary basename,
SHA-256 (when built), `gh` presence/auth booleans, and status lines. No private key,
signing token, credential, raw attestation blob, OIDC/JWT material, raw log, raw
`/metrics` dump, data dir, private endpoint, hostname, git branch, dirty-state string, or
absolute build path is committed. The archive `.gitignore` excludes all such artifacts.
Only loopback (`127.0.0.1`) semantics are referenced. The protected `release-signing`
environment is referenced by name only.

## 26. CodeQL

No production Rust / `build.rs` change in this run (a new shell harness + docs/evidence
only). Per the task, docs/harness/workflow-only changes make CodeQL **trivial / not
meaningful** for Run 387: there is no compiled-code delta to analyze. CodeQL was invoked
with a trivial declaration and its result recorded honestly; no skipped analysis is
claimed clean.

## 27. Provenance

No new canonical binary was built for Run 387. The last recorded canonical release binary
(Run 386 archive) is sha256
`3932279e6f1eea3799562a69d959b1b6286a06a012aca5f96360f4b9948324cd`, ELF BuildID
`636475b1fc3f038a992f6a16947c3f9a722e7da4`, `Cargo.lock` sha256
`70aec07f6e1eb8ea3e98634acefdd92bf9f9ea03929d2821e3cc04c75bb1baaf`, toolchain
`rustc 1.98.0` / `cargo 1.98.0`, target `x86_64-unknown-linux-gnu`, git commit
`cc0ca25e3c04`, canonical injected metric `build_id=qbind-devnet-0.1.0-cc0ca25e3c04` /
`git_commit=cc0ca25e3c04` (both distinct from the ELF BuildID). Values are a build-time
snapshot; the per-run `ATTESTATION_IDENTITY.txt` is the authoritative record once a real
attestation is minted. No attestation was minted or verified in this run.

## 28. Honest limitations

- **No real attestation in this run.** Route C: the keyless GitHub attestation path needs
  GitHub-hosted CI + `id-token`/`attestations` writes + a protected environment and an
  OIDC issuer, none of which are available in this offline sandbox (also `gh`
  unauthenticated and `api.github.com` DNS-blocked). `signed_release`/`slsa_grade`
  therefore stay `false`; a real attestation must be produced by the enabled workflow and
  verified against the binary SHA-256 before any posture change.
- **Cannot create the protected environment or dispatch from here.** A repository
  administrator must create the `release-signing` environment (required reviewers) and
  dispatch the Run 386 workflow with `confirm=yes` on GitHub-hosted CI.
- **Existing workflow runs are startup failures.** The two observed
  `public-devnet-release-signing-attestation.yml` runs are `event=push` (no push trigger)
  startup failures, not confirm-gated protected dispatches; they mint no attestation.
- **Harness runs the real verify only in CI.** Offline it honestly records the missing
  prerequisite; it never fakes a PASS. Cross-host reproducibility and SLSA-grade
  provenance are not claimed.
- **No launch impact.** M4/M6 remain the launch blockers and are untouched; the metrics
  endpoint remains loopback-only with no auth/TLS and must stay loopback.

## 29. Suggested Run 388

On GitHub-hosted CI, a repository administrator creates the protected `release-signing`
environment (required reviewers) and dispatches
`public-devnet-release-signing-attestation` with `confirm=yes` to mint a **real** keyless
build-provenance attestation; Run 388 then runs
`scripts/devnet/run_387_public_devnet_hosted_ci_attestation_verify.sh` in that job to
verify against the binary SHA-256 and archive the publish-safe `ATTESTATION_IDENTITY.txt`
(still without flipping the schema-pinned fields unless/until a signed-release contract is
designed). Alternatively, begin M4 external seed reachability work, which remains the top
launch blocker.