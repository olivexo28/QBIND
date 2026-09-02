# QBIND DevNet Evidence — Run 407

Public DevNet **machine-readable anchor-drift artifact + CI retention policy** — extends
the Run 406 CI artifact wrapper so CI can emit a machine-readable JSON anchor-drift
report (`ANCHOR_DRIFT_REPORT.json`) alongside the existing Markdown report, and documents
CI artifact retention expectations — without committing any generated output and without
changing any readiness status.

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN**.
Run 407 adds **no** production Rust source change, **no** `build.rs` change,
**no** `Cargo.toml` change, **no** new CLI flag; it starts no externally reachable
listener, opens no externally reachable port, deploys no
seed/bootnode/faucet/RPC/explorer/status service, changes no P2P wire format,
weakens no peer admission, enables no peer-driven apply, and mutates no
trust/validator/epoch/sequence/marker/`LivePqcTrustState` state.

## 1. Exact verdict

**PASS / public-DevNet machine-readable anchor-drift artifact + CI retention policy
POSITIVE.** The harness reuses the Run 406 wrapper (which reuses the Run 405 full-tree
verifier), generates the machine-readable `ANCHOR_DRIFT_REPORT.json` into a **staging
directory outside** `docs/release/public-devnet`, validates it against
`PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json`, confirms the JSON counts equal the
Markdown `ANCHOR_DRIFT_REPORT.md` summary counts, and confirms every anchor entry is
present with no undocumented mismatch and full-tree-only files reported as expected
curated-anchor drift; the CI workflow is least-privilege, uploads only the four
publish-safe artifact names, and sets an explicit `retention-days` documented as
convenience/audit usability only; nothing generated is committed; and no readiness
overclaim is introduced. No readiness item moves Green.

## 2. Files changed

New:
- `docs/release/public-devnet/PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json`
- `docs/release/public-devnet/PACKAGE_INTEGRITY_CI_RETENTION.md`
- `scripts/devnet/run_407_public_devnet_anchor_drift_json_retention.sh`
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_407.md` (this file)
- `docs/devnet/run_407_public_devnet_anchor_drift_json_retention/{README.md,summary.txt,.gitignore}`

Narrowly updated (docs + YAML only):
- `.github/workflows/public-devnet-package-integrity.yml` (runs the Run 407 wrapper and
  uploads the four download-only artifacts including `ANCHOR_DRIFT_REPORT.json`, with an
  explicit `retention-days`; still `contents: read`, no secrets, no deploy/commit/push)
- `docs/release/public-devnet/PACKAGE_INTEGRITY_CI_ARTIFACTS.md` (JSON drift report +
  retention companion pointer)
- `docs/release/public-devnet/PACKAGE_INTEGRITY_FULL_TREE.md` (JSON drift + retention note)
- `docs/release/public-devnet/PACKAGE_INTEGRITY.md` (JSON drift + retention companion pointer)
- `docs/release/public-devnet/ARTIFACT_INDEX.md` (group 14 + companion list now reference
  the JSON drift report + retention guide)
- `docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md` (verification-map row +
  cross-reference for the JSON drift report + retention)
- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` (Run 407 narrative; item
  statuses unchanged — M4 🟡, M6 🟡, S5 🟡, S7 🟡, C4/C5 OPEN)
- `docs/whitepaper/contradiction.md` (Run 407 — No contradiction found)

No production source, `build.rs`, `Cargo.toml`, or CLI file is changed. The Run 404
anchor manifest was **not** edited this run (no anchor doc was narrowly edited).

## 3. Decision gate route

**Route B.** Adding a machine-readable JSON drift artifact + a retention policy doc over
the already-recorded Run 406 wrapper is purely operator/reviewer-facing tooling — **docs +
schema + shell + YAML only**, no new CLI surface and no source change. Route A (deploy
anything to change status) was not taken; Route C (defer) was not taken because the JSON
artifact can be emitted and validated honestly and transiently without overclaiming.

## 4. JSON anchor-drift schema contents

`PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json` (draft-07) fixes `report_version`,
`generated_for_run: 407`, `scope: public-devnet-docs-anchor-drift`,
`package_root: docs/release/public-devnet`,
`anchor_manifest_path: PACKAGE_INTEGRITY_MANIFEST.example.json`,
`full_tree_manifest_artifact_name: PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json`,
the eight safety labels
(`devnet`/`experimental`/`resettable`/`no_value`/`no_uptime_sla`/`not_launch_ready`/`c4_open`/`c5_open`),
a `counts` object (`anchor_total`, `anchors_present_matching`, `anchors_missing`,
`undocumented_mismatches`, `documented_refreshes`, `full_tree_only`), the five matching
string arrays of safe relative paths, the eleven `non_claims` booleans (all `false`), and
`artifact_safety_label`. `additionalProperties` is `false` throughout.

## 5. CI retention guide contents

`PACKAGE_INTEGRITY_CI_RETENTION.md` (safety-labelled) explains: which four CI artifacts
are retained; that retention is download-only and provider-dependent; how the JSON and
Markdown drift reports differ; how to compare reports across runs manually (download +
diff, focusing on `counts` and the `undocumented_mismatches`/`anchors_missing`/`full_tree_only`
arrays); why retained artifacts are not committed source artifacts; why retention is not
binary provenance; why retention is not launch evidence; why M4/M6/S5/S7 remain unchanged;
and why C4/C5 remain OPEN.

## 6. Generated JSON drift artifact behavior

`ANCHOR_DRIFT_REPORT.json` is generated by the Run 407 harness into a **staging directory
outside** `docs/release/public-devnet` (in CI, under `${runner.temp}`), validated against
`PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json` (via `jsonschema`, structural fallback
if unavailable), and checked so its `counts` equal the array lengths and all eleven
`non_claims` are `false`. It is uploaded as a download-only CI artifact and is **never**
committed — the harness asserts the artifact path is outside the repo tree, none of the
four artifact names is git-tracked, and the working tree is clean after the run.

## 7. Markdown/JSON drift consistency

The JSON report is produced from the **same** classification as the Markdown report, so
their counts always agree. This run: `anchor_total=16`, `anchors_present_matching=16`,
`documented_refreshes=0`, `undocumented_mismatches=0`, `anchors_missing=0`,
`full_tree_only=73`. The harness parses the Markdown summary lines and fails if any count
disagrees with the JSON `counts` object.

```
json_md_counts_match anchor_total=16 anchors_present_matching=16 documented_refreshes=0 undocumented_mismatches=0 anchors_missing=0 full_tree_only=73
```

## 8. Anchor drift classification

- **anchor files unchanged** — anchor `sha256` + `byte_size` equal the full-tree entry (16
  this run) → `anchors_present_matching`;
- **documented refresh** — acceptable only when the anchor doc was narrowly edited **and**
  its anchor entry was refreshed + documented in the same run (0 this run, since no anchor
  doc was edited) → `documented_refreshes`;
- **full-tree-only files** — expected because the anchor manifest is curated (73 this run,
  including the newly added JSON schema + retention guide) → `full_tree_only`;
- **missing anchor file** — a failure (none this run) → `anchors_missing`;
- **hash mismatch without documented refresh** — a failure (none this run) →
  `undocumented_mismatches`.

## 9. Full-tree coverage verification

The reused Run 406 wrapper (via the Run 405 verifier) generates a full-tree manifest whose
file set **equals** the on-disk publish-safe set under `docs/release/public-devnet` and
re-hashes every file. This run's package tree grew by two committed files (the new JSON
schema + retention guide), both reported as full-tree-only drift; coverage stays exact.

## 10. Hash verification

The reused Run 405/406 path re-hashes every listed file with SHA-256 and checks its byte
size; every entry matched. The JSON drift report itself carries no hashes — it references
paths only — and its safe-relative-path arrays are schema-validated.

## 11. Run 406 compatibility

```
run406_compat=OK (Run 406 wrapper RESULT=POSITIVE; reused via LF-normalized transient copy)
```

The Run 407 harness **reuses** the committed Run 406 wrapper. Because the Run 406 harness
is stored with CRLF line endings, the wrapper normalizes a transient LF copy and runs it
**in place** (so its `BASH_SOURCE`-derived `REPO_ROOT` stays correct), asserts
`RESULT=POSITIVE`, and consumes its generated full-tree manifest + Markdown drift report.
The transient copy is deleted after the run; the committed Run 406 harness is unchanged.

## 12. CI workflow safety

`.github/workflows/public-devnet-package-integrity.yml` runs the Run 407 wrapper on
`workflow_dispatch` and on pull requests touching the package tree / harnesses / workflow.
It is least-privilege (`permissions: contents: read`), references no secrets, deploys
nothing, publishes no release/tag, opens no endpoint, starts no node, and **does not commit
or push**. A final step fails if the working tree is dirty. The harness checks these
properties over a comment-stripped, CRLF-normalized view of the workflow.

## 13. Artifact upload and retention safety

```
ci_upload_names=OK (workflow uploads only the four publish-safe artifact names: PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json ANCHOR_DRIFT_REPORT.md ANCHOR_DRIFT_REPORT.json PACKAGE_INTEGRITY_CI_SUMMARY.txt)
ci_retention_days=OK (workflow sets retention-days: 14)
ci_retention_semantics=OK (retention guide states convenience/audit usability only; not signed attestation/provenance; not launch evidence)
generated_artifacts_transient=OK (full-tree manifest + Markdown + JSON drift reports + CI summary staged outside the tree; none committed)
```

The workflow uploads exactly the four publish-safe artifacts from `${runner.temp}/…`; the
harness asserts those four names are referenced, that no other generated artifact is
uploaded, and that none of the four names is git-tracked anywhere. The explicit
`retention-days: 14` is documented as convenience/audit usability only.

## 14. Non-claim checks

```
non_claim_grep=OK (no launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment claim in CI retention guide)
non_claims_all_false=OK
```

The normalized non-claim grep over the CI retention guide finds no forbidden
readiness/closure/launch/deployment claim, and the generated JSON drift report's eleven
`non_claims` booleans are all `false`.

## 15. Security scans

- **Secret / private-material scan:** the retention guide, the JSON schema, the generated
  JSON drift report, and the package tree were scanned; **no** secret / API key / token /
  credential / key / cert / KEM / signing secret / raw log / raw metrics / data dir /
  private identity is present or listed. `committed_private_material=NONE`.
- The harness also verifies the guide + schema + generated JSON contain **no** absolute
  filesystem path and the JSON report's path arrays list **no** forbidden private/raw
  artifact and **no** absolute path.
- The evidence archive `.gitignore` excludes keys, certs, logs, metrics, data dirs, the
  `run406/` + `artifact-staging/` directories, and the transient `*.generated.json`,
  `ANCHOR_DRIFT_REPORT.md`, `ANCHOR_DRIFT_REPORT.json`, and `PACKAGE_INTEGRITY_CI_SUMMARY.txt`.

## 16. Runtime mutation check

None. Run 407 applies **no** trust bundle, performs **no** live/peer-driven apply, and
mutates **no** validator set / `LivePqcTrustState` / epoch / sequence / marker. It opens no
externally reachable port and starts no node listener. The JSON report's
`mutates_runtime_state` non-claim is `false`.

## 17. Readiness delta

**None.** No readiness item moves Green. M4 🟡, M6 🟡, S5 🟡, S7 🟡, and the Green items
are unchanged. C4/C5 remain OPEN. Public DevNet remains **NOT launch-ready**. This run adds
audit/reviewer usability only.

## 18. M4 status

**Yellow / launch-blocking (unchanged).** No real, externally reachable public DevNet seed
with independent off-host reachability evidence exists. Emitting a JSON drift artifact
proves nothing about external reachability.

## 19. M6 status

**Yellow / Partial (unchanged).** Generation + verification + non-mutating `register-check`
are Green-for-scope; the live-registration half is M4-gated and durable-root
reuse/rotation/revocation is C4/C5-deferred.

## 20. S5/S7 status

**Both Yellow (unchanged).** S5's live status view and S7's live seed operation are
deferred until M4 / a live network.

## 21. Public DevNet status

**NOT launch-ready (unchanged).** The launch decision remains **NO-GO**.

## 22. C4/C5

**C4 OPEN; C5 OPEN (unchanged).** MainNet authority rotation/revocation remains **Red**.
Emitting download-only integrity artifacts closes, advances, or reinterprets nothing about
C4 or C5.

## 23. TestNet/MainNet non-claims

TestNet and MainNet remain **untouched**; N1–N7 remain **Red**. `identity generate` refuses
`mainnet`/`testnet`. **No TestNet readiness and no MainNet readiness is claimed.** The JSON
report's `claims_testnet_ready` and `claims_mainnet_ready` non-claims are both `false`.

## 24. Tests run

- `bash scripts/devnet/run_407_public_devnet_anchor_drift_json_retention.sh` →
  `RESULT=POSITIVE` (all 29 checks OK; see
  `run_407_public_devnet_anchor_drift_json_retention/summary.txt`).
- Run 406 wrapper compatibility (reused) → `RESULT=POSITIVE`.
- Full-tree schema validation + coverage + SHA-256/byte-size verification (reused Run
  405/406) → OK.
- Markdown anchor-drift report verification (reused Run 406) → OK.
- JSON anchor-drift schema validation → OK (`jsonschema`).
- Markdown/JSON count consistency → OK (16/16/0/0/0/73).
- CI workflow safety checks (permissions / secrets / deploy / four upload names /
  retention-days) → OK.
- Non-claim grep → OK. Secret / absolute-path / private-material scan → clean.
- **No Rust source changed → no `cargo test` / `cargo build` is required or run**
  (recorded honestly; this is a docs + schema + shell + YAML run).

## 25. CodeQL

**Docs + schema + shell + YAML only; no production Rust/`build.rs`/`Cargo.toml`/source
change** → trivial / not meaningful for CodeQL. No skipped/timed-out/DB-too-large analysis
is presented as clean.

## 26. Honest limitations

- The JSON anchor-drift report is a **point-in-time** diff generated transiently; it is not
  a signed/timestamped attestation and not binary provenance.
- Retention (`retention-days`) is convenience/audit usability only; the actual retained
  window is provider-dependent and may be further restricted by CI settings.
- The JSON report references paths only and does not itself re-hash files; the per-file
  SHA-256 + byte-size integrity signal comes from the reused Run 405/406 full-tree path.
- Full-tree coverage is computed from the **git-tracked plus not-ignored** file set at run
  time; a path deliberately added to `.gitignore` is excluded from "publish-safe" coverage
  by design.
- Correctness of each group's readiness `status` still rests on the prior runs' recorded
  status, not a fresh re-proof of each item.

## 27. Suggested Run 408

Pursue the real launch blocker: **M4** — deploy or validate a genuinely externally
reachable public DevNet seed/bootnode under strict KEMTLS static-root, capture independent
off-host reachability evidence, publish a schema-valid `devnet-seeds.live.json`, and only
then flip M4 Green and revisit the go/no-go gate. Optionally: have the CI wrapper retain
download-only artifacts across runs to support historical drift diffing, or add a small
JSON-schema-validated index that links each run's `ANCHOR_DRIFT_REPORT.json` — still
without committing generated output. Do not attempt operator-root reuse/rotation/revocation
until C4/C5 work is scoped, to avoid overclaiming closure.