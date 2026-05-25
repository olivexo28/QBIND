# QBIND DevNet Evidence — Run 135

**Subject:** Release-binary evidence for v2 (ratification-v2) **process-start
reload-apply** mutating-surface wiring (Run 134).
**Verdict:** **strongest-positive**
**Date:** 2026-05-25
**Task:** `task/RUN_135_TASK.txt`
**Type:** Evidence-only release-binary harness (no production runtime code
changes).

---

## 1. Scope summary

Run 135 captures release-binary evidence for the Run 134 wiring of v2
bundle-signing-key ratification into the **process-start reload-apply**
mutating surface
(`--p2p-trust-bundle-reload-apply-path` + `--p2p-trust-bundle-reload-apply-enabled`).

The harness mirrors Run 133's evidence shape (release-binary, ephemeral
DevNet fixtures, exit-code + log assertions, non-mutation invariants),
but exercises the **mutating** surface that Run 133 explicitly excluded
(Run 133 evidence was confined to validation-only `reload-check` and
local `peer-candidate-check`).

Run 135 is **evidence-only**. It does **not** change production runtime
code, does **not** wire v2 into any new surface, does **not** implement
signing-key rotation or revocation, does **not** wire SIGHUP / startup
`--p2p-trust-bundle` / snapshot-restore / live `0x05` for v2, does
**not** introduce KMS/HSM, does **not** verify MainNet governance
artifacts, and does **not** change any wire format.

---

## 2. Harness layout

- Script: `scripts/devnet/run_135_v2_reload_apply_release_binary.sh`
- Fixture helper: `crates/qbind-node/examples/run_133_v2_validation_only_fixture_helper.rs`
  (reused as-is — no new helper, no new example crate). The Run 133
  helper already mints every fixture Run 135 needs: per-environment
  `genesis.json` + `expected-genesis-hash.txt` + ratified
  `signing-key.ratified.spec`, signed baseline + candidate trust
  bundles, the full v2 ratification matrix
  (`ratification.v2.ratify.seq{1,2}.json`,
  `ratification.v2.same.seq1.json`,
  `ratification.v2.equivocation.seq1.json`,
  `ratification.v2.lower.seq1.json`,
  `ratification.v2.bad-signature.json`,
  `ratification.v2.wrong-environment.json`,
  `ratification.v2.wrong-chain.json`,
  `ratification.v2.wrong-genesis.json`,
  `ratification.v2.sequence-zero.json`,
  `ratification.v2.rotate.seq2.json`,
  `ratification.v2.revoke.seq2.json`,
  `ratification.v1.valid.json` for the v1 regression),
  and seeded marker files
  (`seed-marker.v1.json`, `seed-marker.v2.seq1.json`,
  `seed-marker.v2.seq2.json`).
- Archive: `docs/devnet/run_135_v2_reload_apply_release_binary/`
  - `summary.txt` — release-binary SHA-256 + Build ID, fixture-helper
    SHA-256 + Build ID, git commit, per-scenario exit codes,
    non-mutation summary lines.
  - `logs/scenario_*.stderr.log` + `logs/scenario_*.stdout.log` —
    per-scenario release-binary output.
  - `exit_codes/scenario_*.exit_code` — per-scenario exit code.
  - `marker_hashes/scenario_*.marker_{pre,post}.sha256` — SHA-256 of
    the on-disk `pqc_authority_state.json` before and after the run
    (empty when no marker existed at that point).
  - `marker_hashes/marker_hashes.csv` — collapsed CSV with one row per
    scenario: `(scenario, pre_sha256, post_sha256)`.

Every scenario runs with its own `--data-dir` so the per-scenario marker
state is isolated.

---

## 3. Scenario matrix and verdict per scenario

All scenarios run against DevNet with the flag block

```
--env devnet
--genesis-path <DEV>/genesis.json
--expect-genesis-hash <hash>
--p2p-trust-bundle <DEV>/baseline-bundle.json
--p2p-trust-bundle-signing-key <ratified-spec>
--p2p-trust-bundle-reload-apply-enabled
--p2p-trust-bundle-reload-apply-path <DEV>/candidate-bundle.json
--p2p-trust-bundle-ratification-enforcement-enabled
--data-dir <OUT>/data/scenario_*
```

with `--p2p-trust-bundle-ratification` pointed at the per-scenario
sidecar. The apply path dispatches to v2 via
`ctx_data.ratification_v2.is_some()` (Run 134 §2.3) directly — no v1
enforcer runs ahead of it on the apply branch — so the
`--p2p-trust-bundle-allow-unratified-testnet-devnet` v1-bypass escape
used by the Run 133 validation-only path is **not** needed here.

### A. Acceptance scenarios

| ID | Scenario | Pre marker | Sidecar | Expected v2 outcome | Observed `[run-134]` line | rc |
|----|----------|------------|---------|---------------------|---------------------------|----|
| A1 | first v2 write | none | `ratify.seq1` | `FirstV2Write` | `v2 authority-marker persisted ... (v2-first-write; candidate latest_authority_domain_sequence=1)` | 0 |
| A2 | v2-after-v1 migration | `seed-marker.v1.json` | `ratify.seq2` | `V2AfterV1Migration` | `v2 authority-marker persisted ... candidate latest_authority_domain_sequence=2` | 0 |
| A3 | idempotent v2 same-digest | `seed-marker.v2.seq1.json` | `same.seq1` | `Idempotent` | `v2 authority-marker unchanged ... (idempotent; no rewrite)` | 0 |
| A4 | higher-sequence upgrade | `seed-marker.v2.seq1.json` | `ratify.seq2` | `UpgradeV2{previous_sequence=1,new_sequence=2}` | `v2 authority-marker persisted ... candidate latest_authority_domain_sequence=2` | 0 |

Apply-ordering invariant on every accepted scenario (asserted via the
harness `assert_apply_ordering` helper):

1. `[binary] Run 070: trust-bundle candidate APPLIED live ... sequence_commit=ok`
2. `[binary] Run 073: VERDICT=applied ... sequence committed`
3. `[run-134] v2 authority-marker persisted ...` **or**
   `[run-134] v2 authority-marker unchanged ...`

In that order. The Run 134 line never precedes `sequence_commit=ok`.

Post-commit invariants on accept (asserted via
`assert_v2_marker_after_commit`):

- `pqc_authority_state.json` exists.
- `"record_version": 2` and `"authority_schema_version": 2`.
- `"latest_authority_domain_sequence": <expected>`.
- `"latest_lifecycle_action": "ratify"` (lower-case; serde
  rename_all = snake_case).
- `"last_update_source": "reload-apply"`.
- `pqc_trust_bundle_sequence.json` exists (`commit_sequence` ran).
- No `pqc_authority_state.json.tmp` sibling left behind.

A2 additionally asserts `cmp -s seed-marker.v1.json
post-marker` is **false** (the v1 record was migrated, not preserved).
A3 additionally asserts `cmp -s seed-marker.v2.seq1.json post-marker`
is **true** (idempotent — byte-for-byte unchanged). A4 additionally
asserts `cmp -s seed-marker.v2.seq1.json post-marker` is **false**
(the marker advanced from seq=1 to seq=2).

### B. Rejection scenarios — refused BEFORE any mutation

| ID  | Scenario | Pre marker | Sidecar | Refusal source | Observed `[run-134]` line | rc |
|-----|----------|------------|---------|----------------|---------------------------|----|
| R1  | lower-sequence | `seed-marker.v2.seq2.json` | `lower.seq1` | `LowerV2SequenceRefused` | `FATAL: reload-apply refused by v2 authority-marker preflight: ... v2 authority-marker rollback rejected: attempted authority_domain_sequence=1 is lower than persisted authority_domain_sequence=2 (fail closed)` | 1 |
| R2  | equivocation (same-seq / different-digest) | `seed-marker.v2.seq1.json` | `equivocation.seq1` | `SameSequenceConflictingKeyOrAction` / `SameSequenceConflictingDigest` | `FATAL: reload-apply refused by v2 authority-marker preflight: ... same-sequence ...` | 1 |
| R3a | bad signature | none | `bad-signature` | `DerivationFailed` (Run 130 verifier — `signature failed ML-DSA-44 PQC verification`) | `FATAL: reload-apply refused by v2 authority-marker preflight: ... signature failed ML-DSA-44 PQC verification` | 1 |
| R3b | wrong environment | none | `wrong-environment` | `DerivationFailed` (Run 130 verifier — `environment mismatch`) | `FATAL: reload-apply refused by v2 authority-marker preflight: ... environment mismatch` | 1 |

Non-mutation invariant on every rejection (asserted via the harness
`assert_no_mutation` helper):

- No `pqc_trust_bundle_sequence.json` file under the scenario data dir.
- No `pqc_authority_state.json.tmp` sibling under the scenario data dir.
- If a marker was pre-seeded: post-run marker bytes are
  byte-identical to the pre-seeded bytes (`cmp -s` succeeds; SHA-256
  pre = SHA-256 post in `marker_hashes/marker_hashes.csv`).
- If no marker was pre-seeded: no marker file is created.
- stderr contains none of: `trust-bundle candidate APPLIED live`,
  `VERDICT=applied`, `session_evictions=[1-9]`, `SIGHUP`, `KMS|HSM`,
  `live inbound 0x05`, `peer-driven live apply`.

### C. v1 regression

| ID | Scenario | Pre marker | Sidecar | Expected | Observed | rc |
|----|----------|------------|---------|----------|----------|----|
| V1 | v1 valid ratification | none | `ratification.v1.valid.json` | Run 119 v1 path runs unchanged; v1 marker persisted | `[run-112] reload-apply ratification gate INVOKED (...env=Devnet)` → Run 070 APPLIED + Run 073 VERDICT=applied → `[run-119] authority-marker persisted` | 0 |

V1 additionally asserts:

- Post-commit marker has `"record_version": 1` (v1, not v2 — proves the
  v1 path was taken even though enforcement was enabled).
- No `[run-134] reload-apply v2 ratification path SELECTED` line in
  stderr.
- No `[run-134] v2 authority-marker persisted` line in stderr.

### D. Scenario R4 — apply failure after preflight

A release binary cannot deterministically inject an apply-pipeline
failure between the Run 134 v2 preflight and `commit_sequence` using
operator-supplied flag inputs alone. The behavior — "swap-stage
failure does not persist marker" — is therefore covered by Run 134
§C.3 test-only evidence in
`crates/qbind-node/tests/run_134_reload_apply_v2_authority_marker_tests.rs::run134_apply_failure_after_v2_accept_does_not_persist_marker`,
which uses the deterministic `FakeLiveTrustApplyContext` from Run
070 / Run 119 to force a swap-stage error.

The Run 134 evidence doc §C.3 explicitly accepts this surface
boundary (release-binary cannot deterministically trigger a swap-stage
fault). Run 135 inherits that boundary verbatim, and the
strongest-positive matrix accommodates it the same way Run 133 (also
strongest-positive) accommodated source-only fixtures for unreachable
wire-format corner cases.

---

## 4. Cross-scenario observability assertions

The harness asserts, across **every** scenario stderr log:

- No `SIGHUP-driven live trust-bundle reload-apply trigger is ACTIVE`
  (SIGHUP v2 wiring is deferred; the binary subcommand path Run 135
  exercises never installs the SIGHUP handler).
- No `KMS|HSM` (KMS/HSM custody is deferred).
- No `live inbound 0x05` (live `0x05` v2 wiring is deferred).
- No `peer-driven live apply` (peer-driven live apply is deferred).
- No `signing-key (rotation|revocation) lifecycle` (rotation /
  revocation lifecycle is deferred).
- No `[run-132] reload-check v2 authority-marker check` (Run 132
  validation-only surface is not on this subcommand path).
- No `[run-132] peer-candidate-check v2 authority-marker check`
  (Run 132 peer-candidate-check is not on this subcommand path).

These cross-scenario assertions are what makes Run 135's strongest-
positive verdict honest about the scope it does **not** cover.

---

## 5. Source diff

Run 135 changes are confined to:

- `scripts/devnet/run_135_v2_reload_apply_release_binary.sh` —
  evidence harness (new).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_135.md` — this doc (new).
- `docs/devnet/run_135_v2_reload_apply_release_binary/` — archived
  release-binary evidence (new).
- `docs/whitepaper/contradiction.md` C4 — Run 135 update paragraph
  appended after the Run 134 paragraph.
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — Run 135
  update appended.
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 135 operator
  note appended.

**No production runtime code path was changed** — neither
`crates/qbind-node/src/main.rs`, nor
`crates/qbind-node/src/pqc_authority_marker_acceptance.rs`, nor
`crates/qbind-node/src/pqc_authority_state.rs`, nor
`crates/qbind-ledger/src/bundle_signing_ratification.rs` was edited.

---

## 6. Test results

Run on the same checkout that produced the release-binary evidence:

| Test set | Result |
|----------|--------|
| `cargo test -p qbind-ledger --lib` | 260 passed / 0 failed |
| `cargo test -p qbind-node --test run_112_reload_apply_ratification_tests` | 10 passed / 0 failed |
| `cargo test -p qbind-node --test run_119_authority_marker_acceptance_tests` | 4 passed / 0 failed |
| `cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests` | 5 passed / 0 failed |
| `cargo test -p qbind-node --lib` | 1246 passed / 0 failed |
| `bash scripts/devnet/run_135_v2_reload_apply_release_binary.sh /tmp/qbind-run135` | PASS (9/9 scenarios) |

The release-binary itself was built via
`cargo build --release -p qbind-node --bin qbind-node` and
`cargo build --release -p qbind-node --example run_133_v2_validation_only_fixture_helper`;
both build IDs and SHA-256 hashes are recorded in
`docs/devnet/run_135_v2_reload_apply_release_binary/summary.txt`.

---

## 7. C4 / scope state after Run 135

C4 status after Run 135: **OPEN but further narrowed for the process-
start reload-apply mutating surface, now release-binary-evidenced.**

Closed (cumulative, v2 ratification + marker):

- Run 130 — v2 schema + verifier (types/primitive).
- Run 131 — v2 authority marker primitives + monotonic comparison.
- Run 132 — v2 validation-only surface wiring
  (`reload-check`, `peer-candidate-check`).
- Run 133 — release-binary evidence for v2 validation-only.
- Run 134 — v2 mutating-surface wiring (process-start reload-apply).
- **Run 135 — release-binary evidence for v2 process-start reload-apply.**

Still open (cumulative):

- v2 wiring for the other mutating surfaces (startup
  `--p2p-trust-bundle`, SIGHUP live reload, snapshot/restore).
- Live inbound `0x05` v2 wiring.
- Signing-key rotation / revocation lifecycle.
- Peer-driven live apply.
- KMS/HSM custody.
- MainNet governance artifact verification.
- Validator-set rotation.
- Full C4 closure.
- C5 closure.

Static production source-code anchors remain rejected. Local config
alone remains insufficient for MainNet bundle-signing authority. No
Run 050–134 invariant was changed.

---

## 8. Cross-references

- Run 130 — v2 bundle-signing-key ratification verifier
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_130.md`).
- Run 131 — v2 authority marker primitives + monotonic comparison
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_131.md`).
- Run 132 — v2 validation-only surface wiring
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_132.md`).
- Run 133 — release-binary evidence for v2 validation-only
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_133.md`).
- Run 134 — v2 mutating-surface wiring (process-start reload-apply)
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_134.md`).
- Run 118 §D — stale-by-one crash-window rule that Run 134 / Run 135
  inherit verbatim for v2.
- Run 119 — v1 mutating-surface accept-and-persist release-binary
  evidence, whose harness shape Run 135 mirrors.
- `docs/whitepaper/contradiction.md` C4 — bundle-signing-key
  ratification status tracker.
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — protocol
  description of v2 ratification and authority markers.
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — operator runbook
  for v1/v2 reload-apply and authority marker semantics.
