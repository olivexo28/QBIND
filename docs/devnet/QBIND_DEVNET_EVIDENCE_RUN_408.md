# QBIND DevNet Evidence — Run 408

Public DevNet **retained anchor-drift artifact historical comparator** — publishes and
verifies a **local, non-mutating** comparator that lets an operator/reviewer compare two
downloaded Run 407-style `ANCHOR_DRIFT_REPORT.json` reports and produce a publish-safe
**transient** diff summary — without fetching CI artifacts automatically, without any
token or secret, without committing generated output, and without changing any readiness
status.

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN**.
Run 408 adds **no** production Rust source change, **no** `build.rs` change,
**no** `Cargo.toml` change, **no** new CLI flag; it starts no externally reachable
listener, opens no externally reachable port, deploys no
seed/bootnode/faucet/RPC/explorer/status service, changes no P2P wire format,
weakens no peer admission, enables no peer-driven apply, and mutates no
trust/validator/epoch/sequence/marker/`LivePqcTrustState` state.

## 1. Exact verdict

**PASS / public-DevNet retained drift artifact historical comparator POSITIVE.** The
comparator validates two Run 407-style reports against
`PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json`, emits a schema-valid **transient**
`PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.json` **outside** the package tree, fails closed on
new anchor failures, treats full-tree-only drift honestly, commits no generated output,
and introduces no readiness overclaim. The harness reports `RESULT=POSITIVE` (25 checks).
No readiness item moves Green.

## 2. Files changed

New:
- `docs/release/public-devnet/PACKAGE_INTEGRITY_DRIFT_HISTORY.md`
- `docs/release/public-devnet/PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.schema.json`
- `scripts/devnet/run_408_public_devnet_retained_drift_history_comparator.sh`
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_408.md` (this file)
- `docs/devnet/run_408_public_devnet_retained_drift_history_comparator/{README.md,summary.txt,.gitignore}`

Narrowly updated (docs only):
- `docs/release/public-devnet/PACKAGE_INTEGRITY_CI_RETENTION.md` (drift-history companion pointer)
- `docs/release/public-devnet/PACKAGE_INTEGRITY_CI_ARTIFACTS.md` (drift-history companion pointer)
- `docs/release/public-devnet/ARTIFACT_INDEX.md` (group 14 + companion list reference the comparator)
- `docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md` (verification-map row + cross-reference)
- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` (Run 408 narrative; statuses unchanged)
- `docs/whitepaper/contradiction.md` (Run 408 — No contradiction found)

No production source, `build.rs`, `Cargo.toml`, or CLI file is changed. Because this run
narrowly edits two curated anchor docs (`ARTIFACT_INDEX.md`, `OPERATOR_VERIFICATION_MAP.md`)
to reference the comparator, the Run 404 anchor manifest
(`PACKAGE_INTEGRITY_MANIFEST.example.json`) had its SHA-256/byte size
**refreshed for exactly those two anchor docs** as a documented deliberate refresh — no
manifest entry was added or removed, and no `status` changed.

## 3. Decision gate route

**Route B.** Adding a local, non-mutating historical comparator + a diff schema + a guide
over the already-recorded Run 407 machine-readable drift artifact is purely
operator/reviewer-facing tooling — **docs + schema + shell only**, no new CLI surface and
no source change. Route A (deploy anything to change status) was not taken; Route C (defer)
was not taken because the comparator can be published and validated honestly and
transiently without overclaiming.

## 4. Drift history guide contents

`PACKAGE_INTEGRITY_DRIFT_HISTORY.md` (safety-labelled) explains: how to download two
retained `ANCHOR_DRIFT_REPORT.json` artifacts **manually** from the CI web UI; how to run
the local comparator; how to interpret added/removed full-tree-only paths; why
full-tree-only drift can be expected (the anchor manifest is curated on purpose); why
missing anchors or undocumented mismatches remain failures (and make the diff fail closed);
why the comparator is not binary provenance; why it is not launch evidence; why
M4/M6/S5/S7 remain unchanged; why C4/C5 remain OPEN; and that retained artifacts are
provider-dependent and may expire.

## 5. Diff schema contents

`PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.schema.json` (draft-07) fixes `diff_version`,
`generated_for_run: 408`, `scope: public-devnet-docs-anchor-drift-history-diff`,
`package_root: docs/release/public-devnet`, `base_report` + `candidate_report` (each a
`reportRef` fixing `scope: public-devnet-docs-anchor-drift`, `generated_for_run: 407`, and
a `counts` object), the eight safety labels, a `count_delta` object (six integer deltas,
which may be negative), a `path_delta` object of **safe-relative-path** arrays
(`added_full_tree_only`, `removed_full_tree_only`, `new_missing_anchors`,
`cleared_missing_anchors`, `new_undocumented_mismatches`,
`cleared_undocumented_mismatches`, `changed_documented_refreshes`), the `verdict` enum
(`positive-no-new-failures`, `negative-new-missing-anchor`,
`negative-new-undocumented-mismatch`, `negative-invalid-input`), the eleven `non_claims`
booleans (all `false`), and `artifact_safety_label`. `additionalProperties` is `false`
throughout, and the `relativePath` pattern rejects absolute paths, `..`, and drive-letter
prefixes.

## 6. Comparator behavior

The comparator reads **two local files** (a base and a candidate Run 407-style report). It:
validates both against the Run 407 schema; **fails** if either has `non_claims` not all
`false`, or claims launch/readiness movement/deployment/runtime mutation/TestNet-MainNet
readiness/C4-C5 closure (all captured by the eleven non-claims), or contains an
unsafe/absolute/private path; compares counts and path arrays; emits
`PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.json` outside the repo tree; validates that diff
against the Run 408 schema; and classifies unchanged counts, added/removed full-tree-only
paths, new/cleared missing anchors, new/cleared undocumented mismatches, and changed
documented refreshes. It **never** fetches CI artifacts automatically, **never** requires a
GitHub token or secret (it makes no network call — no `gh`/`curl`/`wget`/`urllib`/socket
use), and **never** commits generated output. Exit code is `0` for
`positive-no-new-failures` and non-zero (`3`) for every negative verdict.

## 7. Positive comparison case

`base.json` vs `candidate_positive.json` → `verdict=positive-no-new-failures` (exit 0). The
candidate added two full-tree-only paths (`PACKAGE_INTEGRITY_DRIFT_HISTORY.md`,
`PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.schema.json`) and removed one
(`network/M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md`); the diff reports
`added_full_tree_only=2`, `removed_full_tree_only=1`, and **no** new missing anchor and
**no** new undocumented mismatch. The emitted diff validates against the Run 408 schema.

```
positive_case=OK (base vs candidate_positive -> verdict=positive-no-new-failures)
full_tree_only_reported added=2 removed=1
```

## 8. Fail-closed missing-anchor case

`base.json` vs `candidate_missing.json` → `verdict=negative-new-missing-anchor`, comparator
**exit 3**. The candidate moved `genesis/VERIFY.md` from present-matching into
`anchors_missing`; the diff's `path_delta.new_missing_anchors` is non-empty and the
comparator fails closed.

```
missing_anchor_fail_closed=OK (new missing anchor -> verdict=negative-new-missing-anchor; comparator exit=3)
```

## 9. Fail-closed undocumented-mismatch case

`base.json` vs `candidate_mismatch.json` → `verdict=negative-new-undocumented-mismatch`,
comparator **exit 3**. The candidate moved `OPERATOR_VERIFICATION_MAP.md` into
`undocumented_mismatches`; the diff's `path_delta.new_undocumented_mismatches` is non-empty
and the comparator fails closed.

```
undocumented_mismatch_fail_closed=OK (new undocumented mismatch -> verdict=negative-new-undocumented-mismatch; comparator exit=3)
```

## 10. Full-tree-only drift classification

Added/removed **full-tree-only** paths are reported in `path_delta.added_full_tree_only`
and `path_delta.removed_full_tree_only` and are treated as **expected curated-anchor
drift, not a failure by itself** — the positive case has full-tree-only add/remove yet
still verdicts `positive-no-new-failures`. Only a **new** missing anchor or a **new**
undocumented mismatch flips the verdict negative.

## 11. Run 407 compatibility

```
run407_compat=OK (Run 407 wrapper RESULT=POSITIVE; reused via LF-normalized transient copy)
```

The Run 408 harness **reuses** the committed Run 407 wrapper (which itself reuses Run
406/405). Because the Run 407 harness is stored with CRLF line endings, the wrapper
normalizes a transient LF copy and runs it **in place** (so its `BASH_SOURCE`-derived
`REPO_ROOT` stays correct) and asserts `RESULT=POSITIVE`. The transient copy is deleted
after the run; the committed Run 407 harness is unchanged.

## 12. Generated artifact behavior

The two input fixtures, the reused Run 407 artifacts, the comparator source, and the
emitted `PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.json` are all written to staging directories
**outside** `docs/release/public-devnet` (in CI, under `${runner.temp}`) and are **never**
committed — the harness asserts the diff path is outside the repo tree, none of the
transient leaf names (`PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.json`,
`ANCHOR_DRIFT_REPORT.json`, `PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json`) is
git-tracked, and the working tree is clean after the run.

```
diff_outside_tree=OK (PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.json generated into staging, outside the tree; not committed)
generated_artifacts_transient=OK (diff JSON + fixtures + reused Run 407 artifacts staged outside the tree; none committed)
working_tree_clean=OK (harness generated nothing under the repo tree; git status unchanged by this run)
```

## 13. Non-claim checks

```
non_claim_grep=OK (no launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment claim in drift history guide)
non_claims_all_false=OK
```

The normalized non-claim grep over the drift-history guide finds no forbidden
readiness/closure/launch/deployment claim, and the generated diff's eleven `non_claims`
booleans are all `false`.

## 14. Security scans

- **Secret / private-material scan:** the guide, the diff schema, the generated diff, and
  the package tree were scanned; **no** secret / API key / token / credential / key / cert
  / KEM / signing secret / raw log / raw metrics / data dir / private identity is present
  or listed. `committed_private_material=NONE`.
- The harness verifies the guide + schema + generated diff contain **no** absolute
  filesystem path and the diff's `path_delta` arrays list **no** forbidden private/raw
  artifact and **no** absolute path.
- The comparator itself contains no artifact-fetch command and no token/secret/network use
  (`no_auto_fetch=OK`).
- The evidence archive `.gitignore` excludes keys, certs, logs, metrics, data dirs, the
  `run407/`, `artifact-staging/`, and `fixtures/` directories, the comparator source, and
  the transient `*.generated.json`, `ANCHOR_DRIFT_REPORT.json`, and
  `PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.json`.

## 15. Runtime mutation check

None. Run 408 applies **no** trust bundle, performs **no** live/peer-driven apply, and
mutates **no** validator set / `LivePqcTrustState` / epoch / sequence / marker. It opens no
externally reachable port and starts no node listener. The diff's `mutates_runtime_state`
non-claim is `false`.

## 16. Readiness delta

**None.** No readiness item moves Green. M4 🟡, M6 🟡, S5 🟡, S7 🟡, and the Green items
are unchanged. C4/C5 remain OPEN. Public DevNet remains **NOT launch-ready**. This run adds
audit/reviewer usability only.

## 17. M4 status

**Yellow / launch-blocking (unchanged).** No real, externally reachable public DevNet seed
with independent off-host reachability evidence exists. Comparing retained drift reports
proves nothing about external reachability.

## 18. M6 status

**Yellow / Partial (unchanged).** Generation + verification + non-mutating `register-check`
are Green-for-scope; the live-registration half is M4-gated and durable-root
reuse/rotation/revocation is C4/C5-deferred.

## 19. S5/S7 status

**Both Yellow (unchanged).** S5's live status view and S7's live seed operation are
deferred until M4 / a live network.

## 20. Public DevNet status

**NOT launch-ready (unchanged).** The launch decision remains **NO-GO**.

## 21. C4/C5

**C4 OPEN; C5 OPEN (unchanged).** MainNet authority rotation/revocation remains **Red**.
Comparing download-only integrity reports closes, advances, or reinterprets nothing about
C4 or C5.

## 22. TestNet/MainNet non-claims

TestNet and MainNet remain **untouched**; N1–N7 remain **Red**. `identity generate` refuses
`mainnet`/`testnet`. **No TestNet readiness and no MainNet readiness is claimed.** The
diff's `claims_testnet_ready` and `claims_mainnet_ready` non-claims are both `false`.

## 23. Tests run

- `bash scripts/devnet/run_408_public_devnet_retained_drift_history_comparator.sh` →
  `RESULT=POSITIVE` (all 25 checks OK; see
  `run_408_public_devnet_retained_drift_history_comparator/summary.txt`).
- Run 407 wrapper compatibility (reused) → `RESULT=POSITIVE`.
- Run 407 input-schema validation for the two generated reports → OK.
- Run 408 diff-schema validation for the emitted diff → OK.
- Positive no-new-failures fixture → verdict `positive-no-new-failures` (exit 0).
- Fail-closed missing-anchor fixture → verdict `negative-new-missing-anchor` (exit 3).
- Fail-closed undocumented-mismatch fixture → verdict `negative-new-undocumented-mismatch`
  (exit 3).
- Safe-path checks over all diff arrays → OK.
- No-committed-generated-output check + clean-working-tree check → OK.
- Non-claim grep → OK. Secret / absolute-path / private-material scan → clean.
- **No Rust source changed → no `cargo test` / `cargo build` is required or run**
  (recorded honestly; this is a docs + schema + shell run).

## 24. CodeQL

**Docs + schema + shell only; no production Rust/`build.rs`/`Cargo.toml`/source change** →
trivial / not meaningful for CodeQL. No skipped/timed-out/DB-too-large analysis is
presented as clean.

## 25. Honest limitations

- The historical diff is a **point-in-time** comparison of two reports generated
  transiently; it is not a signed/timestamped attestation and not binary provenance.
- Cross-run comparison is only possible while **both** retained `ANCHOR_DRIFT_REPORT.json`
  artifacts are still downloadable; retention is provider-dependent and may expire, in
  which case that comparison can no longer be performed.
- The comparator reasons over the **paths and counts** the two reports declare; it does not
  itself re-hash files. The per-file SHA-256 + byte-size integrity signal comes from the
  reused Run 405/406/407 full-tree path that produced each report.
- The verified example uses two **generated** Run 407-style fixtures (plus the reused Run
  407 wrapper for schema compatibility); comparing two genuinely downloaded artifacts is
  the operator's manual step, documented in the guide.
- Correctness of each readiness item's `status` still rests on the prior runs' recorded
  status, not a fresh re-proof of each item.

## 26. Suggested Run 409

Pursue the real launch blocker: **M4** — deploy or validate a genuinely externally
reachable public DevNet seed/bootnode under strict KEMTLS static-root, capture independent
off-host reachability evidence, publish a schema-valid `devnet-seeds.live.json`, and only
then flip M4 Green and revisit the go/no-go gate. Optionally: add a small schema-validated
**index** that links a sequence of retained `ANCHOR_DRIFT_REPORT.json` artifacts across
runs (still download-only, still never committing generated output) so the Run 408
comparator can be chained over more than two reports. Do not attempt operator-root
reuse/rotation/revocation until C4/C5 work is scoped, to avoid overclaiming closure.