# QBIND DevNet Evidence — Run 404

Public DevNet **release package integrity manifest** — machine-readable manifest +
JSON schema + operator guide + verification harness.

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN**.
Run 404 adds **no** production Rust source change, **no** `build.rs` change,
**no** `Cargo.toml` change, **no** new CLI flag; it starts no externally reachable
listener, opens no externally reachable port, deploys no
seed/bootnode/faucet/RPC/explorer/status service, changes no P2P wire format,
weakens no peer admission, enables no peer-driven apply, and mutates no
trust/validator/epoch/sequence/marker/`LivePqcTrustState` state.

## 1. Exact verdict

**PASS / public-DevNet package integrity manifest POSITIVE.** The schema, example
manifest, operator guide, and verification harness land cleanly and are verified
against the **on-disk package tree** and the **canonical** readiness matrix. Every
listed file exists and its SHA-256 + byte size match the on-disk file. No readiness
overclaim is introduced; no readiness item moves Green.

## 2. Files changed

New:
- `docs/release/public-devnet/PACKAGE_INTEGRITY_MANIFEST.schema.json`
- `docs/release/public-devnet/PACKAGE_INTEGRITY_MANIFEST.example.json`
- `docs/release/public-devnet/PACKAGE_INTEGRITY.md`
- `scripts/devnet/run_404_public_devnet_package_integrity_manifest.sh`
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_404.md` (this file)
- `docs/devnet/run_404_public_devnet_package_integrity_manifest/{README.md,summary.txt,.gitignore}`

Narrowly updated (docs only):
- `docs/release/public-devnet/ARTIFACT_INDEX.md` (new group 14 + companion pointer +
  coverage row; no status change)
- `docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md` (package integrity check
  added to the external-operator read order, the verification map, and the
  cross-references; no status change)
- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` (Run 404 narrative; item
  statuses unchanged — M4 🟡, M6 🟡, S5 🟡, S7 🟡, C4/C5 OPEN)
- `docs/whitepaper/contradiction.md` (Run 404 — No contradiction found)

No production source, `build.rs`, `Cargo.toml`, or CLI file is changed.

## 3. Decision gate route

**Route B (expected).** Publishing a machine-readable integrity manifest + schema +
guide + harness over the already-recorded package tree is purely operator-facing
documentation — **docs + schema + verification harness only**, no new CLI surface
and no source change. Route A (deploy anything to change status) was not taken
because the run moves no item Green; Route C (defer / publish nothing) was not taken
because the current package tree **can** be hashed and manifested honestly without
overclaiming, which is precisely the integrity assurance this run adds.

## 4. Manifest schema contents

`PACKAGE_INTEGRITY_MANIFEST.schema.json` (draft-07) fixes `manifest_version`
(semver), `generated_for_run` (`const 404`), `scope`
(`const public-devnet-docs-release-package`), `safety_labels` (an eight-member enum
array that must contain `devnet`/`experimental`/`resettable`/`no_value`/
`no_uptime_sla`/`not_launch_ready`/`c4_open`/`c5_open`), `package_root`
(`const docs/release/public-devnet`), an optional `generated_at_utc` (ISO-8601 Zulu),
a `files[]` array of objects with `relative_path` (a safe relative path — no leading
`/`, no `..`, no drive letter), `sha256` (64-hex), `byte_size` (int ≥ 0),
`artifact_group` (enum), `readiness_item`, `status` (enum:
green/green-for-scope/yellow/yellow-partial/no-go), `verification_reference`, a
`non_claims` object whose eleven booleans are each `const false`, and a fixed
`artifact_safety_label`. `additionalProperties: false` throughout.

## 5. Manifest example contents

`PACKAGE_INTEGRITY_MANIFEST.example.json` is schema-valid and lists **16** covered
files: one stable `VERIFY.md` anchor per artifact group (genesis, binary, operator,
identity, p2p, network, security, observability, ops, recovery, status) plus the
five top-level package documents (`ARTIFACT_INDEX.md`,
`OPERATOR_VERIFICATION_MAP.md`, `LAUNCH_GO_NO_GO.md`, `BLOCKER_REGISTER.md`,
`PACKAGE_INTEGRITY.md`). Each entry carries the file's real SHA-256 and byte size and
the group's `readiness_item`/`status`/`verification_reference`. All eleven
`non_claims` are `false`. It intentionally does **not** list the schema or the
example manifest itself (a manifest cannot self-hash) and lists only publish-safe
documentation.

## 6. Integrity guide contents

`PACKAGE_INTEGRITY.md` (safety-labelled) explains: what the manifest contains; how
to regenerate it (`sha256sum` + `wc -c` per file, relative to the package root, with
an honest `generated_at_utc` reproducibility note — hashes/sizes are the integrity
signal, the timestamp is not); how to verify file hashes (an inline `python3`
re-hash loop and the bundled harness); how it differs from **binary provenance**
(the release binary is covered separately by
`binary/RELEASE_ARTIFACT_MANIFEST.schema.json`); why it is **not** a launch artifact;
why it does **not** move M4/M6/S5/S7; why **C4/C5 remain OPEN**; and how operators
should run the integrity check **before** following `OPERATOR_VERIFICATION_MAP.md`.

## 7. Hash verification

```
schema_validation=OK (PACKAGE_INTEGRITY_MANIFEST.example.json validates; generated_for_run=404; scope + safety labels + non_claims fixed)
hash_verification=OK (every listed file exists; sha256 + byte_size match on-disk; relative paths resolve under docs/release/public-devnet)
```

All 16 listed files were re-hashed with SHA-256 and their byte sizes checked against
the on-disk tree; every entry matched. The manifest validated against the schema via
`jsonschema` (with a structural fallback if `jsonschema` is unavailable).

## 8. Package path coverage

Every artifact group present under `docs/release/public-devnet/` is represented by
its `VERIFY.md` anchor, and all five top-level package documents are listed. Each
`relative_path` is a safe relative path that resolves under
`docs/release/public-devnet` (no absolute path, no `..`, no path escaping the
package root).

## 9. Artifact index update

`ARTIFACT_INDEX.md` gains a companion-document pointer to `PACKAGE_INTEGRITY.md`, a
new **group 14 — Package integrity manifest** (path / purpose / readiness item /
verify / status / non-claims), and a package-coverage table row. It explicitly notes
this is documentation-tree integrity, **not** binary provenance, and that it moves no
readiness item.

## 10. Operator verification map update

`OPERATOR_VERIFICATION_MAP.md` adds the **package integrity check** as the first step
of the external-operator read order (run it before trusting the rest of the package),
a dedicated **Package integrity check** row in the exact verification map, and a
cross-reference to `PACKAGE_INTEGRITY.md`.

## 11. Non-claim checks

```
non_claim_grep=OK (no launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment claim; manifest non_claims all false)
```

The normalized non-claim grep over the guide finds no forbidden
readiness/closure/launch/deployment claim, and the manifest's eleven `non_claims`
booleans are all `false`.

## 12. Security scans

- **Secret scan:** the changed files were scanned; **no** secret / API key / token
  / credential is present. The package is docs + schema + shell only; the harness
  `.gitignore` excludes keys, certs, logs, metrics, and data dirs.
  `committed_private_material=NONE`.
- The harness additionally verifies the manifest/schema/guide contain **no** absolute
  filesystem path, the manifest embeds **no** IP:port / host:port private endpoint,
  and the manifest lists **no** key/cert/KEM/signing/API/raw-log/raw-metrics/
  data-dir/private-identity artifact.

## 13. Runtime mutation check

None. Run 404 applies **no** trust bundle, performs **no** live/peer-driven apply,
and mutates **no** validator set / `LivePqcTrustState` / epoch / sequence / marker.
It opens no externally reachable port and starts no node listener. The manifest's
`mutates_runtime_state` non-claim is `false`.

## 14. Readiness delta

**None.** No readiness item moves Green. M4 🟡, M6 🟡, S5 🟡, S7 🟡, and the Green
items are unchanged. C4/C5 remain OPEN. Public DevNet remains **NOT launch-ready**.
This run adds integrity coverage only.

## 15. M4 status

**Yellow / launch-blocking (unchanged).** No real, externally reachable public DevNet
seed with independent off-host reachability evidence exists. Hashing docs proves
nothing about external reachability.

## 16. M6 status

**Yellow / Partial (unchanged).** Generation + verification + non-mutating
`register-check` are Green-for-scope; the live-registration half is M4-gated and
durable-root reuse/rotation/revocation is C4/C5-deferred.

## 17. S5/S7 status

**Both Yellow (unchanged).** S5's live status view and S7's live seed operation are
deferred until M4 / a live network.

## 18. Public DevNet status

**NOT launch-ready (unchanged).** The launch decision remains **NO-GO**.

## 19. C4/C5

**C4 OPEN; C5 OPEN (unchanged).** MainNet authority rotation/revocation remains
**Red**. Confirming documentation-file integrity closes, advances, or reinterprets
nothing about C4 or C5.

## 20. TestNet/MainNet non-claims

TestNet and MainNet remain **untouched**; N1–N7 remain **Red**. `identity generate`
refuses `mainnet`/`testnet`. **No TestNet readiness and no MainNet readiness is
claimed.** The manifest's `claims_testnet_ready` and `claims_mainnet_ready`
non-claims are both `false`.

## 21. Tests run

- `bash scripts/devnet/run_404_public_devnet_package_integrity_manifest.sh` →
  `RESULT=POSITIVE` (all OK lines; see
  `run_404_public_devnet_package_integrity_manifest/summary.txt`).
- JSON schema validation for `PACKAGE_INTEGRITY_MANIFEST.example.json` → OK
  (`jsonschema`).
- SHA-256 + byte-size verification over all 16 manifest entries → OK.
- Non-claim grep → OK. Secret / absolute-path / private-endpoint scan → clean.
- **No Rust source changed → no `cargo test` / `cargo build` is required or run**
  (recorded honestly; this is a docs + schema + shell run).

## 22. CodeQL

**Docs + schema + shell only; no production Rust/`build.rs`/source change** →
trivial / not meaningful for CodeQL. No skipped/timed-out/DB-too-large analysis is
presented as clean.

## 23. Honest limitations

- The manifest proves only that the **listed** documentation files match a recorded
  snapshot; it is not exhaustive (it lists one anchor per group plus the top-level
  docs, not every file in the tree) and it does not — and cannot — list itself or the
  schema. A tampered file that is not listed would not be caught by the hash loop;
  operators who need full coverage can extend `files[]` per Section 2 of the guide.
- This is **documentation-tree** integrity, not binary provenance and not a signed
  release / SLSA attestation.
- The `generated_at_utc` timestamp is informational only; the integrity signal is the
  per-file SHA-256 + byte size.
- Correctness of each group's `status` rests on the prior runs' recorded status, not
  a fresh re-proof of each readiness item.

## 24. Suggested Run 405

Pursue the real launch blocker: **M4** — deploy or validate a genuinely externally
reachable public DevNet seed/bootnode under strict KEMTLS static-root, capture
independent off-host reachability evidence, publish a schema-valid
`devnet-seeds.live.json`, and only then flip M4 Green and revisit the go/no-go gate,
the artifact index, and this integrity manifest. Optionally extend the integrity
manifest to cover the full package tree (every file, not just anchors) and wire it
into CI as a non-committing check. Do not attempt operator-root reuse/rotation/
revocation until C4/C5 work is scoped, to avoid overclaiming closure.
