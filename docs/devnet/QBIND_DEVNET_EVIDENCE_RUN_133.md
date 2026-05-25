# QBIND DevNet Evidence — Run 133

**Subject:** Release-binary evidence matrix for the v2 (ratification-v2) validation-only authority-marker check on the reload-check and peer-candidate-check binary surfaces (Run 132 wiring).  
**Verdict:** **strongest-positive**  
**Date:** 2026-05-25  
**Task:** `task/RUN_133_TASK.txt`  
**Type:** Evidence-only (no production runtime code change; no wire-format change).

---

## 1. Scope

Run 132 wired the Run 130 v2 ratification verifier and the Run 131 v2 authority-marker validator into the two binary validation-only surfaces:

* `--p2p-trust-bundle-reload-check <CANDIDATE>` (Run 069 / Run 105 / Run 123 path), and
* `--p2p-trust-bundle-peer-candidate-check <ENVELOPE>` (Run 077 / Run 107 / Run 123 path).

Run 133 captures the **release-binary** evidence matrix that proves Run 132's per-policy verdict is honored end-to-end by `target/release/qbind-node`, that no validation-only path persists a marker, advances a sequence file, applies a candidate, evicts a session, or otherwise mutates trust state, and that the v1 fall-through path remains unchanged.

This run is evidence-only. No production runtime code is changed. The fixtures are minted by an ephemeral helper binary under `crates/qbind-node/examples/`. No wire format (trust-bundle, peer-candidate envelope, ratification) is changed by this run.

---

## 2. Doc-sync first checkpoint (pre-Run-133)

Per `task/RUN_133_TASK.txt`, the doc-sync checkpoint for Run 131 / Run 132 was applied **before** any harness work began:

* `docs/whitepaper/contradiction.md` — appended a paragraph identifying the v2 ratification-validator/marker primitives (Run 131) and the validation-only wire-up (Run 132).
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — appended two update sections: Run 131 (additive v2 marker structures, no on-disk format change) and Run 132 (validation-only surfaces dispatch by sidecar version).
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — appended Run 131 / Run 132 sections with the per-policy verdict table and the operator-facing CLI fact (sidecar-version is detected from the on-disk file; same `--p2p-trust-bundle-ratification` flag).

No mutating-surface wiring is implied or claimed in those sections.

---

## 3. Build warnings

`cargo build --release -p qbind-node --bin qbind-node` produced **zero warnings** after this run. Three pre-existing warnings were fixed:

| File | Warning | Fix |
|---|---|---|
| `crates/qbind-node/src/binary_consensus_loop.rs` (two sites) | `use of deprecated function bincode::config: please use bincode::options() instead` | Replaced `bincode::config()` with `bincode::options()`; the existing `.with_*` chain was wire-compatible with the new builder, and the 63 `binary_consensus_loop` unit tests still pass. |
| `crates/qbind-node/src/verify_pool.rs::worker_loop` | `unused variable: worker_id` (only used under `cfg(debug_assertions)`) | Added `#[cfg_attr(not(debug_assertions), allow(unused_variables))]` on the parameter; the debug-build self-check still runs verbatim. |

---

## 4. Artifacts

* **Fixture helper:** `crates/qbind-node/examples/run_133_v2_validation_only_fixture_helper.rs` (ephemeral, mints ML-DSA-44 authority + bundle-signing keys, writes per-environment genesis / signed bundles / v1 + v2 ratification sidecars / seeded v1 and v2 markers).
* **Harness:** `scripts/devnet/run_133_v2_validation_only_release_binary.sh`.
* **Archived evidence:** `docs/devnet/run_133_v2_validation_only_release_binary/` (`summary.txt` + per-scenario stderr logs and exit codes).

Reproduce locally:

```bash
bash scripts/devnet/run_133_v2_validation_only_release_binary.sh /tmp/qbind-run133-evidence
```

The harness:

1. builds the release binary and the example helper,
2. mints ephemeral DevNet + MainNet fixtures (DevNet is exercised; MainNet fixtures are produced for future expansion),
3. runs the 16-scenario matrix below,
4. asserts the expected exit code, expected stderr verdict line, expected typed accept/refusal reason, and the four-part non-mutation invariant for every scenario.

---

## 5. Scenario matrix

All scenarios run on DevNet against `target/release/qbind-node`. Each scenario provides a fresh `--data-dir`, optionally pre-seeded with a marker file. The harness asserts the exit code matches **and** asserts non-mutation: no `pqc_authority_state.json` is created or rewritten under a no-seed scenario, no seeded marker is rewritten under a seeded scenario, no `pqc_authority_state.json.tmp` is left behind, no `pqc_trust_bundle_sequence.json` is written, and no apply / propagate / session-eviction / SIGHUP / KMS marker is logged.

The DevNet reload-check flag block is:

```
--env devnet
--genesis-path <FIXTURE>/genesis.json
--expect-genesis-hash <hash>
--p2p-trust-bundle <FIXTURE>/baseline-bundle.json
--p2p-trust-bundle-signing-key <SPEC>
--p2p-trust-bundle-reload-check <FIXTURE>/candidate-bundle.json
--p2p-trust-bundle-ratification-enforcement-enabled
--p2p-trust-bundle-allow-unratified-testnet-devnet
--p2p-trust-bundle-ratification <SIDECAR>
--data-dir <PER-SCENARIO>
```

The `--p2p-trust-bundle-allow-unratified-testnet-devnet` flag is required on DevNet for pure-v2 sidecars: the Run 105 v1 enforcer is reached first by `validate_candidate_bundle_with_ratification`, and a v2-only sidecar carries `ratification = None` in the Run 132 versioned loader; allow-unratified lets the v1 enforcer pass-through, after which the Run 132 v2 dispatch fires. This is documented operator behavior (Run 105 escape hatch is DevNet/TestNet-only; MainNet refuses pre-Run-105 unratified semantics regardless).

### v1 regression (Run 123 path unchanged)

| # | Scenario | Seed marker | Sidecar | Expected exit | Expected log |
|---|---|---|---|---|---|
| 1 | v1 valid, no marker | none | `ratification.v1.valid.json` | `0` | `[run-123] reload-check authority-marker check passed`, `VERDICT=valid` |

### v2 acceptance

| # | Scenario | Seed marker | Sidecar | Expected exit | Expected log (`[run-132] reload-check v2 authority-marker check passed:` …) |
|---|---|---|---|---|---|
| 2 | v2 first-seen | none | `ratification.v2.ratify.seq1.json` | `0` | `no-persisted-marker-yet (v2 first-seen pass; …)` |
| 3 | v2 idempotent (same seq, same digest) | `seed-marker.v2.seq1.json` | `ratification.v2.same.seq1.json` | `0` | `v2 idempotent (same marker; …)` |
| 4 | v2 ratify upgrade (1 → 2) | `seed-marker.v2.seq1.json` | `ratification.v2.ratify.seq2.json` | `0` | `v2 upgrade-compatible 1 -> 2 (…)` |
| 5 | v2 rotate upgrade (1 → 2) | `seed-marker.v2.seq1.json` | `ratification.v2.rotate.seq2.json` | `0` | `v2 upgrade-compatible 1 -> 2 (…)` |
| 6 | v2 revoke upgrade (1 → 2) | `seed-marker.v2.seq1.json` | `ratification.v2.revoke.seq2.json` | `0` | `v2 upgrade-compatible 1 -> 2 (…)` |
| 7 | v2 after v1 (migration candidate) | `seed-marker.v1.json` | `ratification.v2.ratify.seq2.json` | `0` | `v2-after-v1 migration candidate (validation-only; …)` |

### v2 rejection

| # | Scenario | Seed marker | Sidecar | Expected exit | Expected log |
|---|---|---|---|---|---|
| 8  | same-sequence different-digest (equivocation) | `seed-marker.v2.seq1.json` | `ratification.v2.equivocation.seq1.json` | `1` | `Run 132: v2 same-sequence different-digest refused: seq=1 …`, `Run 132: VERDICT=invalid` |
| 9  | lower sequence (1 vs marker 2) | `seed-marker.v2.seq2.json` | `ratification.v2.lower.seq1.json` | `1` | `Run 132: v2 lower sequence refused: persisted=2 candidate=1; …`, `Run 132: VERDICT=invalid` |
| 10 | seq=0 (malformed) | none | `ratification.v2.sequence-zero.json` | `1` | `authority_domain_sequence=0 is invalid …`, `Run 132: VERDICT=invalid` |
| 11 | tampered signature | none | `ratification.v2.bad-signature.json` | `1` | `signature failed ML-DSA-44 PQC verification`, `Run 132: VERDICT=invalid` |
| 12 | wrong chain | none | `ratification.v2.wrong-chain.json` | `1` | `chain_id mismatch`, `Run 132: VERDICT=invalid` |
| 13 | wrong environment | none | `ratification.v2.wrong-environment.json` | `1` | `environment mismatch`, `Run 132: VERDICT=invalid` |
| 14 | wrong genesis | none | `ratification.v2.wrong-genesis.json` | `1` | `genesis_hash does not match runtime canonical genesis hash`, `Run 132: VERDICT=invalid` |

### Peer-candidate-check spot-check (Run 077 / Run 107 / Run 132 path)

| # | Scenario | Seed marker | Sidecar | Expected exit | Expected log |
|---|---|---|---|---|---|
| 15 | peer-candidate-check v2 first-seen | none | `ratification.v2.ratify.seq1.json` | `0` | `[run-132] peer-candidate-check v2 authority-marker check passed: no-persisted-marker-yet …`, `VERDICT=validated` |
| 16 | peer-candidate-check v2 bad-signature | none | `ratification.v2.bad-signature.json` | `1` | `signature failed ML-DSA-44 PQC verification`, `Run 132: VERDICT=invalid` |

All 16 scenarios pass. The recorded `summary.txt` and per-scenario `*.stderr.log` / `*.exit_code` files in `docs/devnet/run_133_v2_validation_only_release_binary/` are the auditable artifacts.

---

## 6. What this evidence proves

1. **Release binary honors Run 132 verdicts.** Every typed accept reason (`NoPersistedMarkerYet`, `Idempotent`, `UpgradeCompatible{previous,new}`, `V2AfterV1MigrationCandidate`) surfaces verbatim on stderr from a release-mode binary, and every typed refusal (`V2VerifierFailure`, `V2LowerSequenceRefused`, `V2SameSequenceDifferentDigestRefused`, marker-corruption / wrong-domain refusals) drives a non-zero exit with the `Run 132: VERDICT=invalid` line.
2. **Validation-only surfaces never mutate.** The harness's `assert_no_mutation` check (sequence-file absence, marker-bytes equality vs the pre-seeded marker, `.tmp` sibling absence, no `applied` / `evictions` / `SIGHUP` / `KMS` / `HSM` markers in stderr) holds across all 16 scenarios, including the seven acceptance scenarios that exercise non-trivial accept reasons.
3. **v1 fall-through path is preserved.** Scenario 1 demonstrates a v1 sidecar continues to land in the Run 123 verifier and emits the unchanged `[run-123] reload-check authority-marker check passed` line — Run 132 only adds a side branch when `ratification_v2.is_some()`.
4. **v1-only marker + v2-only sidecar is a migration candidate, not an error.** Scenario 7 returns the `V2AfterV1MigrationCandidate` accept reason, validating Run 131's explicit fail-open-for-migration semantics on the validation-only surface (no marker is written; a future Run is required to wire the explicit migration on the mutating surface, which is intentionally out of scope for Run 132 / Run 133).
5. **Build warnings are gone.** `cargo build --release -p qbind-node --bin qbind-node` is warning-free after this run.

---

## 7. What this evidence does NOT prove (intentionally out of scope)

* **No live-apply / SIGHUP / peer-driven-apply mutation evidence.** Run 132 / Run 133 do not wire the v2 path into any mutating surface; the production reload-apply path (Run 070 / Run 119) is v1-only, and Run 133 does not extend it.
* **No v2 marker persistence by the release binary.** No scenario writes a `pqc_authority_state.json` v2 record; the only on-disk v2 markers in the matrix are the pre-seeded fixtures, which exist solely so the validator can compare against persisted state.
* **No MainNet evidence under enforcement.** MainNet fixtures are produced by the helper for future expansion, but the harness does not exercise them under enforcement — pure-v2 sidecars on MainNet currently require both the Run 132 v2 dispatch and the Run 105 v1 enforcer to be reconciled; that reconciliation is a future Run.
* **No KMS / HSM, no peer-gossip, no governance, no policy upgrade.** Same as Run 132.

---

## 8. Code-side test parity

The targeted Run 132 / Run 131 / Run 130 / Run 123 / Run 107 / Run 103 / Run 104 test surfaces and the full `qbind-node --lib` and `qbind-ledger --lib` suites pass in release mode:

```
cargo test --release -p qbind-node --lib pqc_authority_marker_acceptance
  test result: ok. 43 passed; 0 failed; 0 ignored
cargo test --release -p qbind-node --lib
  test result: ok. 1246 passed; 0 failed; 0 ignored
cargo test --release -p qbind-ledger --lib
  test result: ok. 260 passed; 0 failed; 0 ignored
```

---

## 9. Files produced / changed by Run 133

* `crates/qbind-node/examples/run_133_v2_validation_only_fixture_helper.rs` — **new** (ephemeral fixture helper).
* `scripts/devnet/run_133_v2_validation_only_release_binary.sh` — **new** (harness).
* `docs/devnet/run_133_v2_validation_only_release_binary/{summary.txt,logs/*}` — **new** (archived evidence).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_133.md` — **new** (this file).
* `docs/whitepaper/contradiction.md` — **+Run 131/132 doc-sync paragraph and +Run 133 release-binary verdict paragraph** (additive only).
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — **+Run 131/132 update sections and +Run 133 update section** (additive only).
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — **+Run 131/132 runbook sections and +Run 133 operator runbook update** (additive only).
* `crates/qbind-node/src/binary_consensus_loop.rs` — bincode deprecated-config warning fix (two sites, wire-compatible).
* `crates/qbind-node/src/verify_pool.rs` — release-build unused-variable warning fix on `worker_loop::worker_id`.

No production runtime mutating surface is touched. No wire format struct is touched.
