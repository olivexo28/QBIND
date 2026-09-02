# QBIND DevNet Evidence — Run 405

Public DevNet **full-tree package integrity verifier** — a verifier + JSON schema +
operator guide (+ optional CI check) that hashes **every** publish-safe file in the
public DevNet package tree at verification time.

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN**.
Run 405 adds **no** production Rust source change, **no** `build.rs` change,
**no** `Cargo.toml` change, **no** new CLI flag; it starts no externally reachable
listener, opens no externally reachable port, deploys no
seed/bootnode/faucet/RPC/explorer/status service, changes no P2P wire format,
weakens no peer admission, enables no peer-driven apply, and mutates no
trust/validator/epoch/sequence/marker/`LivePqcTrustState` state.

## 1. Exact verdict

**PASS / public-DevNet full-tree package integrity verifier POSITIVE.** The verifier
generates a transient, schema-valid full-tree manifest covering **every** publish-safe
file under `docs/release/public-devnet` (86 files), every hash + byte size matches the
on-disk tree, the generated manifest is never committed, the Run 404 anchor manifest
still validates, CI/local checks are non-mutating, and no readiness overclaim is
introduced. No readiness item moves Green.

## 2. Files changed

New:
- `docs/release/public-devnet/PACKAGE_INTEGRITY_FULL_TREE.md`
- `docs/release/public-devnet/PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.schema.json`
- `scripts/devnet/run_405_public_devnet_full_tree_package_integrity.sh`
- `.github/workflows/public-devnet-package-integrity.yml`
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_405.md` (this file)
- `docs/devnet/run_405_public_devnet_full_tree_package_integrity/{README.md,summary.txt,.gitignore}`

Narrowly updated (docs only):
- `docs/release/public-devnet/PACKAGE_INTEGRITY.md` (full-tree companion pointer)
- `docs/release/public-devnet/ARTIFACT_INDEX.md` (group 14 + companion pointer now
  reference full-tree verification)
- `docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md` (full-tree verification
  in the read order + verification map + cross-references; the external-operator
  read-order numbering was **fixed** — the earlier duplicate `3.` is now 1..11
  consecutive)
- `docs/release/public-devnet/PACKAGE_INTEGRITY_MANIFEST.example.json` (Run 404 anchor
  manifest: SHA-256 + byte size refreshed for the three narrowly-edited files so the
  anchor manifest stays valid — no new entries, no status change)
- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` (Run 405 narrative; item
  statuses unchanged — M4 🟡, M6 🟡, S5 🟡, S7 🟡, C4/C5 OPEN)
- `docs/whitepaper/contradiction.md` (Run 405 — No contradiction found)

No production source, `build.rs`, `Cargo.toml`, or CLI file is changed.

## 3. Decision gate route

**Route B.** Adding a full-tree integrity verifier + schema + guide + harness (+ an
optional least-privilege CI check) over the already-recorded package tree is purely
operator-facing tooling — **docs + schema + shell + YAML only**, no new CLI surface
and no source change. Route A (deploy anything to change status) was not taken; Route C
(defer) was not taken because the tree can be hashed exhaustively and honestly without
overclaiming.

## 4. Full-tree guide contents

`PACKAGE_INTEGRITY_FULL_TREE.md` (safety-labelled) explains: how full-tree
verification differs from the Run 404 anchor manifest (mechanical, exhaustive vs.
curated, labelled anchors); why the full-tree manifest is generated **transiently**
rather than committed (the tree changes; a committed full-tree manifest would drift
and would have to self-hash); how to run the local verifier; how CI uses the verifier
without committing generated output; why this is **not** binary provenance; why this
is **not** launch evidence; why M4/M6/S5/S7 remain unchanged; and why C4/C5 remain
OPEN.

## 5. Full-tree schema contents

`PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.schema.json` (draft-07) fixes `manifest_version`
(semver), `generated_for_run` (`const 405`), `scope`
(`const public-devnet-docs-release-package-full-tree`), `coverage`
(`const full-tree`), `safety_labels` (the eight-member enum array),
`package_root` (`const docs/release/public-devnet`), `file_count` (int ≥ 1), an
optional `generated_at_utc`, a `files[]` array of **minimal** objects
(`relative_path` — a safe relative path with no leading `/`, no `..`, no drive
letter; `sha256` — 64-hex; `byte_size` — int ≥ 0), a `non_claims` object whose eleven
booleans are each `const false`, and a fixed `artifact_safety_label`.
`additionalProperties: false` throughout.

## 6. Generated manifest behavior

The full-tree manifest is **generated at verification time into a temporary directory
outside `docs/release/public-devnet`** (default
`/tmp/qbind-run405-…/PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json`; in CI, under
`${runner.temp}`). It is validated, checked against the on-disk tree, and left in the
temp dir. It is **never** committed — the harness asserts the generated path is outside
the package tree, and the CI job additionally fails if the working tree is dirty after
the run. Only the schema, guide, and harness are committed.

## 7. Full-tree coverage verification

The harness enumerates every regular publish-safe file under
`docs/release/public-devnet` (git-tracked plus new-but-not-ignored, so a file added in
the same change is covered before commit) and asserts the generated manifest's file
set **equals** the on-disk set — failing on any **omitted** or **extra** path. This
run covers **86** files.

```
full_tree_coverage=OK (manifest file set == on-disk publish-safe file set under docs/release/public-devnet; 86 files)
```

## 8. Hash verification

```
full_tree_schema_validation=OK (generated manifest validates; generated_for_run=405; scope=full-tree; safety labels + non_claims fixed)
full_tree_hash_verification=OK (every listed file exists; sha256 + byte_size match on-disk; relative paths safe + root-confined)
file_count=86  files_verified=86
```

Every listed file was re-hashed with SHA-256 and its byte size checked; every entry
matched. The manifest validated against the schema via `jsonschema` (structural
fallback if unavailable).

## 9. Existing Run 404 anchor-manifest compatibility

```
anchor_manifest_compat=OK (Run 404 PACKAGE_INTEGRITY_MANIFEST.example.json still validates; hashes/sizes match)
```

The Run 404 anchor manifest still validates against its schema and its listed hashes
match. Because Run 405 narrowly edited three files the anchor manifest lists
(`ARTIFACT_INDEX.md`, `OPERATOR_VERIFICATION_MAP.md`, `PACKAGE_INTEGRITY.md`), the
anchor manifest's SHA-256 + byte size for exactly those three entries were refreshed;
no entry was added or removed and no `status` changed.

## 10. Artifact index update

`ARTIFACT_INDEX.md` group 14 and the top companion-document list now reference the
full-tree verifier (`PACKAGE_INTEGRITY_FULL_TREE.md` +
`PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.schema.json` + `run_405…`), noting the two
coverage levels (anchor + full-tree) and that the full-tree manifest is generated
transiently and never committed. No status changes.

## 11. Operator verification map update

`OPERATOR_VERIFICATION_MAP.md` references the full-tree verifier in the
external-operator read order (step 2), adds a dedicated **Full-tree integrity
verification** row to the exact verification map, and adds a cross-reference. The
external-operator read order numbering was also **cleaned** (the prior duplicate `3.`
is now a consecutive `1..11`).

## 12. CI workflow

`.github/workflows/public-devnet-package-integrity.yml` runs the Run 405 verifier on
`workflow_dispatch` and on pull requests touching the package tree / schema / guide /
harness. It is least-privilege (`permissions: contents: read`), references no secrets,
deploys nothing, publishes no release/tag, opens no endpoint, starts no node, and
**does not commit or push**. The generated manifest stays under `${runner.temp}`; a
final step fails if the working tree is dirty, guaranteeing nothing generated is
committed.

## 13. Non-claim checks

```
non_claim_grep=OK (no launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment claim in full-tree guide)
non_claims_all_false=OK
```

The normalized non-claim grep over the guide finds no forbidden
readiness/closure/launch/deployment claim, and the generated manifest's eleven
`non_claims` booleans are all `false`.

## 14. Security scans

- **Secret / private-material scan:** the changed files and the package tree were
  scanned; **no** secret / API key / token / credential / key / cert / KEM / signing
  secret / raw log / raw metrics / data dir / private identity is present or listed.
  `committed_private_material=NONE`.
- The harness also verifies the guide/schema contain **no** absolute filesystem path
  and the generated manifest lists **no** forbidden private/raw artifact and **no**
  absolute path.
- The evidence archive `.gitignore` excludes keys, certs, logs, metrics, data dirs,
  and the transient `*.generated.json` manifest.

## 15. Runtime mutation check

None. Run 405 applies **no** trust bundle, performs **no** live/peer-driven apply, and
mutates **no** validator set / `LivePqcTrustState` / epoch / sequence / marker. It
opens no externally reachable port and starts no node listener. The manifest's
`mutates_runtime_state` non-claim is `false`.

## 16. Readiness delta

**None.** No readiness item moves Green. M4 🟡, M6 🟡, S5 🟡, S7 🟡, and the Green
items are unchanged. C4/C5 remain OPEN. Public DevNet remains **NOT launch-ready**.
This run adds full-tree integrity coverage only.

## 17. M4 status

**Yellow / launch-blocking (unchanged).** No real, externally reachable public DevNet
seed with independent off-host reachability evidence exists. Full-tree hashing proves
nothing about external reachability.

## 18. M6 status

**Yellow / Partial (unchanged).** Generation + verification + non-mutating
`register-check` are Green-for-scope; the live-registration half is M4-gated and
durable-root reuse/rotation/revocation is C4/C5-deferred.

## 19. S5/S7 status

**Both Yellow (unchanged).** S5's live status view and S7's live seed operation are
deferred until M4 / a live network.

## 20. Public DevNet status

**NOT launch-ready (unchanged).** The launch decision remains **NO-GO**.

## 21. C4/C5

**C4 OPEN; C5 OPEN (unchanged).** MainNet authority rotation/revocation remains
**Red**. Confirming full documentation-tree integrity closes, advances, or
reinterprets nothing about C4 or C5.

## 22. TestNet/MainNet non-claims

TestNet and MainNet remain **untouched**; N1–N7 remain **Red**. `identity generate`
refuses `mainnet`/`testnet`. **No TestNet readiness and no MainNet readiness is
claimed.** The manifest's `claims_testnet_ready` and `claims_mainnet_ready` non-claims
are both `false`.

## 23. Tests run

- `bash scripts/devnet/run_405_public_devnet_full_tree_package_integrity.sh` →
  `RESULT=POSITIVE` (all 21 checks OK; see
  `run_405_public_devnet_full_tree_package_integrity/summary.txt`).
- Generated full-tree manifest schema validation → OK (`jsonschema`).
- Full-tree file-coverage check (manifest set == on-disk set) → OK (86 files).
- SHA-256 + byte-size verification over all 86 entries → OK.
- Run 404 anchor manifest re-validation → OK.
- Non-claim grep → OK. Secret / absolute-path / private-material scan → clean.
- **No Rust source changed → no `cargo test` / `cargo build` is required or run**
  (recorded honestly; this is a docs + schema + shell + YAML run).

## 24. CodeQL

**Docs + schema + shell + YAML only; no production Rust/`build.rs`/source change** →
trivial / not meaningful for CodeQL. No skipped/timed-out/DB-too-large analysis is
presented as clean.

## 25. Honest limitations

- Full-tree coverage is computed from the **git-tracked plus not-ignored** file set at
  run time; a path deliberately added to `.gitignore` would be excluded from
  "publish-safe" coverage by design. The verifier proves the enumerated set is
  complete and unchanged **at verification time**; it is not a signed/timestamped
  attestation and not binary provenance.
- The generated manifest is transient by design, so there is no committed full-tree
  hash to diff against historically; the Run 404 anchor manifest remains the committed,
  labelled anchor.
- Correctness of each group's readiness `status` still rests on the prior runs'
  recorded status, not a fresh re-proof of each item.

## 26. Suggested Run 406

Pursue the real launch blocker: **M4** — deploy or validate a genuinely externally
reachable public DevNet seed/bootnode under strict KEMTLS static-root, capture
independent off-host reachability evidence, publish a schema-valid
`devnet-seeds.live.json`, and only then flip M4 Green and revisit the go/no-go gate.
Optionally: emit the transient full-tree manifest as a **non-committed CI artifact**
for download-only inspection, or extend the full-tree verifier to diff against the
Run 404 anchor set and flag anchor drift. Do not attempt operator-root
reuse/rotation/revocation until C4/C5 work is scoped, to avoid overclaiming closure.