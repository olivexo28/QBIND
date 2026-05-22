# QBIND DevNet Evidence — Run 111

**Task:** `task/RUN_111_TASK.txt` — execute and archive the Run 110 N=3 release-binary live peer-candidate ratification evidence.

**Verdict:** **strongest-positive**. The Run 110 release-binary N=3 DevNet harness (`scripts/devnet/run_110_live_peer_candidate_ratification_n3.sh`) was executed end-to-end on real `target/release/qbind-node` processes (plus the four release helper binaries) against the canonical genesis-authority + ratification fixture overlay produced by `run_110_live_ratification_fixture_helper`. All six scenarios passed on the first attempt with zero retries and zero changes to production runtime code. The fresh release-binary capture is archived under `docs/devnet/run_110_live_peer_candidate_ratification_n3/`. The Run 110 evidence gap ("harness landed, full capture deferred") is therefore closed by Run 111.

Run 111 is evidence-only. No production runtime code under `crates/**/src/**` changed. No harness or helper changes were needed: the Run 110 deliverable ran first-shot on the build it was designed against.

---

## Scope

Run 111 executes Run 110. It does not extend the harness, does not add scenarios, does not change wire formats, does not change verifier semantics, and does not change enforcement policy. It produces:

1. a release-binary `target/release/qbind-node` plus the four supporting helpers (sha256 + ELF BuildID recorded);
2. fresh DevNet trust material (signed bundle, transport root + leaf certs, consensus signer keystores) minted by the Run 089-style helpers;
3. fresh Run 110 ratification fixtures (Run 101 `GenesisConfig` with `genesis_authority`, Run 102 expected genesis hash, Run 103 signed ratification sidecar for the R1 baseline signing key, a tampered copy of that sidecar with signature byte 0 flipped, a freshly-minted U1 unratified ML-DSA-44 signing key, a U1-signed alternate trust bundle, and matching `PeerCandidateEnvelope` JSON files);
4. six executed scenarios on real release `qbind-node` processes wired exactly per Run 110's design (V0 sender / V1 ratification hub + Run 088 relay / V2 terminal observer; ML-KEM-768 + ChaCha20-Poly1305 + ML-DSA-44 mutual auth; signed DevNet trust bundle; Run 109 `--p2p-trust-bundle-ratification*` flags on V1 and V2 in the enforced-policy scenarios);
5. per-scenario `/metrics` snapshots from every node, full stderr/stdout logs, `pqc_trust_bundle_sequence.json` sha256 hashes before/after every scenario, a `summary.txt` manifest, and grep-extracted ratification gate / Run 033 / Run 040 marker lines;
6. the canonical archive at `docs/devnet/run_110_live_peer_candidate_ratification_n3/`.

Run 111 does **not**:

- change the `0x05` peer-candidate wire format;
- change the trust-bundle wire format;
- introduce a new metric family;
- introduce a peer-supplied ratification object;
- introduce static production source-code anchors or fallback authorities;
- introduce peer-driven live apply, reload-apply ratification, SIGHUP ratification, signing-key rotation/revocation, authority anti-rollback persistence, KMS/HSM custody, fast-sync ratification parity, governance, or validator-set rotation;
- claim full C4 closure or C5 closure.

---

## Release-binary artifacts under test

Recorded under `docs/devnet/run_110_live_peer_candidate_ratification_n3/artifact_sha256.txt` and `artifact_build_id.txt`:

| Binary                                                                         | sha256                                                             |
|--------------------------------------------------------------------------------|--------------------------------------------------------------------|
| `target/release/qbind-node`                                                    | `96a783bb89cee49f1fd90a514839e5f5a60d4d7a69ca833abc539408bc16dba5` |
| `target/release/examples/devnet_pqc_trust_bundle_helper`                       | `8535f5d2f79ea63d5a157944355caadd67437e7952e574c315bbad05b78b32ca` |
| `target/release/examples/devnet_pqc_root_helper`                               | `e33c883304e032699b41c2d02818c545dd38822235fa68a3fc939b733e5211bf` |
| `target/release/examples/devnet_consensus_signer_keystore_helper`              | `5cab05cfed77110d4fbe2a0d77c79e25b184dd5cad74616dcc1a94a6d92b365b` |
| `target/release/examples/run_110_live_ratification_fixture_helper`             | `ff5aab8ea01a35bcdb756b54a0c608fcf51f0ca252bf8f4c30ad6d0c5adb69f5` |

ELF BuildIDs are recorded alongside in `artifact_build_id.txt`.

---

## Replay command

```bash
scripts/devnet/run_110_live_peer_candidate_ratification_n3.sh
```

The harness self-archives into `docs/devnet/run_110_live_peer_candidate_ratification_n3/` on success. Default tunables (`QBIND_RUN110_NODE_TIMEOUT=60s`, `QBIND_RUN110_P2P_BASE=19000`, `QBIND_RUN110_METRICS_BASE=9500`) were used unchanged.

---

## Scenario results (release-binary, N=3, live wire)

All six scenarios PASSED. The per-scenario metric / log assertions reproduced in `summary.txt` and the archived `metrics/*.metrics` and `logs/*.stderr.log` files are summarised below.

### Scenario A — `baseline_ratification`

Cluster bootstrap with Run 109 gate INVOKED on V1 + V2 (V0 has no live ratification dispatcher installed because V0 is the sender in this evidence set).

- All three nodes reached `P2P transport up`.
- `qbind_p2p_pqc_cert_verify_accepted_total >= 1` on every node; `qbind_p2p_pqc_cert_verify_rejected_total == 0` everywhere (mutual ML-KEM/ML-DSA auth real, no `DummySig` / `DummyKem` / `DummyAead`).
- V1 and V2 logged the Run 109 gate marker:
  `[run-109] live peer-candidate wire ratification gate INVOKED (policy=devnet-operator-opt-in, env=Devnet)`.
- `qbind_p2p_pqc_trust_bundle_peer_candidate_received_total = 0`,
  `qbind_p2p_pqc_trust_bundle_peer_candidate_sent_total = 0` on every node (no peer-candidate traffic yet — pure boot proof).
- All non-mutation invariants held (see "Cross-cutting non-mutation invariants" below).

### Scenario 1 — `valid_ratified`

V0 publishes the R1-ratified envelope exactly once. V1 ratifies → validates → propagates under Run 088 rules. V2 receives and validates. V0 source exclusion holds.

V1 metrics (from `metrics/valid_ratified_v1.metrics`):

| metric                                                                          | value |
|---------------------------------------------------------------------------------|-------|
| `qbind_p2p_pqc_trust_bundle_peer_candidate_received_total`                      | 1     |
| `qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total`                     | 1     |
| `qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total`                      | 0     |
| `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_attempt_total`           | 1     |
| `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total`              | 1     |
| `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_suppressed_invalid_total`| 0     |

V2: `received_total >= 1`, `validated_total = 1`, `rejected_total = 0`, `propagation_sent_total = 0` (V2 is terminal observer). V0: `received_total = 0` (Run 088 source-peer exclusion held — V0 never received an echo of its own candidate).

`pqc_trust_bundle_sequence.json` sha256 byte-identical on every node before/after the scenario.

### Scenario 2 — `missing_ratification`

V0 publishes the U1-signed alternate bundle envelope. V1 accepts U1 via `--p2p-trust-bundle-signing-key` so the inner Run 050 / 076 signature check passes and the candidate reaches the Run 109 gate. The Run 109 gate then rejects with `Missing` (U1 is not covered by the ratification sidecar). Propagation is suppressed. V2 does not receive via V1 propagation.

V1 metrics (from `metrics/missing_ratification_v1.metrics`):

| metric                                                                          | value |
|---------------------------------------------------------------------------------|-------|
| `qbind_p2p_pqc_trust_bundle_peer_candidate_received_total`                      | 1     |
| `qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total`                     | 0     |
| `qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total`                      | 1     |
| `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_attempt_total`           | 0     |
| `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total`              | 0     |
| `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_suppressed_invalid_total`| 1     |

V1 stderr contains a typed `RatificationRefused` / `Missing` marker (assertion passed). V2: `validated_total = 0`, `propagation_sent_total = 0`, `received_total <= 1` (direct broadcast from V0 may hit V2; V2 rejects identically and does not propagate). V0: `received_total = 0`. Sequence files unchanged on every node.

### Scenario 3 — `bad_ratification_startup_refuse`

V1 is started with the tampered `ratification.bad-signature.json` sidecar. The Run 105 startup preflight refuses to install the live dispatcher and the binary exits non-zero. `P2P transport up` is never reached. No `pqc_trust_bundle_sequence.json` is created under V1's data dir.

V1 stderr (from `logs/bad_ratification_startup_refuse_v1.stderr.log`):

```
[run-105] FATAL: bundle-signing-key ratification refused at startup; sequence record NOT written, bundle roots NOT merged into the live PQC trust set, no live trust mutation occurred. Reason: bundle-signing ratification signature failed PQC verification
[run-105] qbind-node refuses to start. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_105.md, docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md §"Run 105 ratification enforcement".
```

This is the truthful Run 109 / Run 105 layering: Run 109 reuses the Run 105 sidecar model and the `0x05` wire has no peer-supplied ratification field, so a tampered ratification can only enter the system through the operator's local file, and the Run 105 startup preflight intercepts it before the live dispatcher is installed. Defense-in-depth proof that bad-signature ratification cannot reach the live wire path.

### Scenario 4 — `duplicate_unratified_no_promotion`

V0 publishes the unratified envelope. The first V0 process is then stopped and a second V0 process is started on a different port slot to republish. V1 ratification-rejects the first arrival. The seen-cache does NOT convert the prior rejection into acceptance on the second arrival.

V1 metrics (from `metrics/duplicate_unratified_no_promotion_v1.metrics`):

| metric                                                                          | value |
|---------------------------------------------------------------------------------|-------|
| `qbind_p2p_pqc_trust_bundle_peer_candidate_received_total`                      | 2     |
| `qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total`                     | 0     |
| `qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total`                      | 1     |
| `qbind_p2p_pqc_trust_bundle_peer_candidate_duplicate_total`                     | 1     |
| `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_attempt_total`           | 0     |
| `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total`              | 0     |
| `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_suppressed_invalid_total`| 1     |

`rejected_total + duplicate_total = 2 = received_total`. The second arrival was duplicate-suppressed (covers the second envelope); the first was rejection-suppressed. Either way V1 never validated, never propagated, never converted a rejection into an acceptance. V2: `validated_total = 0`, `propagation_sent_total = 0`. Sequence files unchanged on every node.

### Scenario 5 — `devnet_no_opt_in_legacy`

V1 and V2 are started **without** `--p2p-trust-bundle-ratification-enforcement-enabled` and **without** `--p2p-trust-bundle-ratification`. The Run 106 DevNet skip branch fires and the live dispatcher runs the pre-Run-109 unguarded path; V0 publishes the ratified envelope and V1 / V2 validate exactly as in Run 089.

V1 stderr contains the SKIPPED marker:

```
[run-109] live peer-candidate wire ratification gate SKIPPED (policy=devnet-no-operator-opt-in, env=Devnet). This preserves pre-Run-109 DevNet legacy behaviour only; MainNet/TestNet always invoke the gate by default and never reach this branch.
```

V1: `validated_total = 1`, `propagation_sent_total = 1`. V2: `validated_total = 1`. Sequence files unchanged on every node. The harness comment is correct: this is **explicitly non-production** DevNet developer ergonomics; the same node configuration on MainNet or TestNet would never reach this branch because Run 106 default-strict policy fires there.

---

## Cross-cutting non-mutation invariants

Asserted by the harness on every node in every applicable scenario (verified by reviewing the archived metrics files and stderr logs):

- `pqc_trust_bundle_sequence.json` sha256 **byte-identical before and after each scenario** on every node (see `sequence/*.before.sha256` and `sequence/*.after.sha256`). No sequence write occurred.
- `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total` **absent** from every `/metrics` response (Run 088 metric-family contract). No apply occurred.
- `qbind_p2p_trust_bundle_live_reload_*` and `qbind_p2p_session_eviction_*` counters all **= 0** on every node in every scenario. No live trust mutation, no root merge, no session eviction, no reload-apply.
- No `--p2p-trusted-root` fallback log line fired anywhere. No fallback authority was activated.
- No `DummySig` / `DummyKem` / `DummyAead` / `dummy_*_registered=true` line fired anywhere. The Run 033 / Run 040 SuiteAware key provider was built honestly; PQC mutual auth was real (`qbind_p2p_pqc_cert_verify_accepted_total >= 1` and `qbind_p2p_pqc_cert_verify_rejected_total == 0` on every node).
- No consensus ratification occurred (the harness exercises only the live trust-bundle ratification path; no consensus epoch changed during any scenario).

These invariants pin objectives 8–13 from the task spec on real release binaries.

---

## Source-level and test evidence

Targeted test suites run on `target/release/...` after the harness; all green:

| Target                                                                  | Result               |
|-------------------------------------------------------------------------|----------------------|
| `qbind-ledger --lib`                                                    | 222 passed, 0 failed |
| `qbind-crypto --lib`                                                    | 68 passed, 0 failed  |
| `qbind-node tests/run_076_pqc_peer_candidate_validation_tests`          | 16 passed, 0 failed  |
| `qbind-node tests/run_078_pqc_peer_candidate_wire_tests`                | 19 passed, 0 failed  |
| `qbind-node tests/run_079_pqc_peer_candidate_wire_live_dispatch_tests`  | 11 passed, 0 failed  |
| `qbind-node tests/run_088_pqc_peer_candidate_propagation_tests`         | 5 passed, 0 failed   |
| `qbind-node tests/run_105_ratification_enforcement_tests`               | 6 passed, 0 failed   |
| `qbind-node tests/run_106_ratification_policy_tests`                    | 7 passed, 0 failed   |
| `qbind-node tests/run_107_peer_candidate_ratification_tests`            | 6 passed, 0 failed   |
| `qbind-node tests/run_109_pqc_peer_candidate_wire_live_ratification_tests` | 23 passed, 0 failed |

Pre-existing compile error noted (predates Run 111, unrelated to the ratification path): `crates/qbind-node/tests/m16_epoch_transition_hardening_tests.rs` references `clear_epoch_transition_marker` / similar methods that do not exist on `RocksDbConsensusStorage`. This is a pre-existing failure in `cargo test --release -p qbind-node --tests --no-run` (the trait method was renamed elsewhere) and has nothing to do with Run 109 / 110 / 111. It is not fixed under Run 111 (out of scope; touching that file is not in the Run 111 allowed-change list and would not affect the live ratification evidence). Test compile and run for every Run 076 / 078 / 079 / 088 / 105 / 106 / 107 / 109 target succeeded on its own as a single-test compilation when invoked individually with `--test <name>`.

The Run 103 verifier and Run 104 key-material rules are exercised inside `qbind-ledger --lib` (222 passed) and inside the Run 105 / 106 / 107 / 109 test suites listed above. The Run 110 helper (`run_110_live_ratification_fixture_helper`) compiled cleanly as part of the release build and executed successfully during fixture mint (see `docs/devnet/run_110_live_peer_candidate_ratification_n3/fixtures/`).

---

## What changed in the repository under Run 111

- **No production runtime code changed.** No file under `crates/**/src/**` was modified.
- **No harness or helper code changed.** `scripts/devnet/run_110_live_peer_candidate_ratification_n3.sh` and `crates/qbind-node/examples/run_110_live_ratification_fixture_helper.rs` ran first-shot.
- **New evidence document:** `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_111.md` (this file).
- **New archived release-binary capture** under `docs/devnet/run_110_live_peer_candidate_ratification_n3/` (the canonical Run 110 archive directory referenced by `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_110.md`'s "Replay procedure" section). Contents:
  - `summary.txt`
  - `artifact_sha256.txt`, `artifact_build_id.txt`
  - `ratification_lines.txt`, `run033_run040_lines.txt`
  - `logs/` (per-node stdout/stderr for every scenario)
  - `metrics/` (per-node `/metrics` snapshot for every scenario)
  - `sequence/` (per-node sha256 of `pqc_trust_bundle_sequence.json` before/after every applicable scenario)
  - `fixtures/` (the genesis-authority + ratification fixtures, including the R1 and U1 signing-key specs, valid and tampered sidecars, and ratified / unratified envelope JSONs)
- **Doc cross-reference updates:** `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_110.md` (Run 111 closes-the-gap note), `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` (Run 111 evidence-closure paragraph), `docs/whitepaper/contradiction.md` (Run 111 C4 paragraph), `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` (Run 111 operator note).

---

## Security boundaries (unchanged)

Run 111 preserves every Run 100 → Run 110 security boundary:

- **Local config alone is still not enough for MainNet bundle-signing authority.** The ratification verifier remains rooted in the genesis authority block via the canonical genesis hash. The Run 111 harness mints a fresh DevNet authority per run; no production identity is reused.
- **Static production source-code anchors remain rejected.** Run 111 introduces no new static anchors, no fallback authorities, and no static signing keys.
- **Transport roots cannot ratify bundle-signing keys.** `--p2p-trust-bundle-signing-key` accepts only ML-DSA-44 bundle-signing keys (R1 and U1 in the harness), never the transport ML-KEM-768 root.
- **Rejection remains validation-only and non-mutating.** No sequence file is written, no root merge occurs, no live trust state is mutated, no sessions are evicted, no `_applied_total` metric family is introduced, no `0x05` rebroadcast happens on rejection, and no node reload-applies on rejection. Verified by sequence sha256 invariance and the live-reload / session-eviction counters all being 0.
- **No wire-format changes.** `0x05` peer-candidate envelopes and the trust-bundle on-disk format are bit-for-bit unchanged.

---

## Future work (still open, explicitly not closed by Run 111)

Run 111 does **not** close any of the following:

- peer-driven live apply;
- reload-apply ratification (Run 070 path);
- SIGHUP ratification;
- signing-key rotation lifecycle;
- signing-key revocation lifecycle;
- authority anti-rollback persistence;
- persistent ratified-authority state;
- peer-distributed ratification objects on the `0x05` wire (would require a wire-format change and is the only path that could expand "bad-signature" rejection from the startup boundary to a per-frame V1 runtime rejection);
- KMS/HSM custody;
- production fast-sync / broader consensus-storage restore ratification parity;
- governance;
- validator-set rotation.

C4 remains OPEN for the items above. C5 remains OPEN / unchanged. Run 111 is release-binary evidence for live inbound validation only.

---

## Evidence references

- Evidence document: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_111.md` (this file).
- Release-binary archive directory: `docs/devnet/run_110_live_peer_candidate_ratification_n3/`.
- Summary manifest: `docs/devnet/run_110_live_peer_candidate_ratification_n3/summary.txt`.
- Per-scenario stderr logs: `docs/devnet/run_110_live_peer_candidate_ratification_n3/logs/<scenario>_v{0,1,2}.stderr.log`.
- Per-scenario metrics snapshots: `docs/devnet/run_110_live_peer_candidate_ratification_n3/metrics/<scenario>_v{0,1,2}.metrics`.
- Per-scenario sequence sha256s: `docs/devnet/run_110_live_peer_candidate_ratification_n3/sequence/<scenario>.v{0,1,2}.{before,after}.sha256`.
- Fixtures: `docs/devnet/run_110_live_peer_candidate_ratification_n3/fixtures/`.
- Targeted tests: see "Source-level and test evidence" table above.
- Run 110 design / replay procedure: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_110.md`.
- Run 109 source-level pin: `crates/qbind-node/tests/run_109_pqc_peer_candidate_wire_live_ratification_tests.rs`.

Exact command summaries:

```bash
# Build release artifacts (or reuse if prebuilt)
cargo build --release -p qbind-node \
    --bin qbind-node \
    --example devnet_pqc_trust_bundle_helper \
    --example devnet_pqc_root_helper \
    --example devnet_consensus_signer_keystore_helper \
    --example run_110_live_ratification_fixture_helper

# Execute the harness end-to-end and archive evidence
scripts/devnet/run_110_live_peer_candidate_ratification_n3.sh

# Targeted tests
cargo test --release -p qbind-node \
    --test run_076_pqc_peer_candidate_validation_tests \
    --test run_078_pqc_peer_candidate_wire_tests \
    --test run_079_pqc_peer_candidate_wire_live_dispatch_tests \
    --test run_088_pqc_peer_candidate_propagation_tests \
    --test run_105_ratification_enforcement_tests \
    --test run_106_ratification_policy_tests \
    --test run_107_peer_candidate_ratification_tests \
    --test run_109_pqc_peer_candidate_wire_live_ratification_tests
cargo test --release -p qbind-ledger --lib
cargo test --release -p qbind-crypto --lib
```

---

## Residual risks and next recommended run

Risks honestly remaining after Run 111:

- The bad-signature evidence still lives at the startup boundary (Run 105 preflight) because Run 109 has no peer-supplied ratification on the `0x05` wire. A future peer-distributed-ratification design would re-open a runtime-V1 bad-signature evidence path; until then the truthful boundary for bad-signature rejection is startup-refuse.
- Reload-apply ratification (Run 070 path) and SIGHUP ratification remain unevidenced and unenforced — see Run 105 / Run 107 / Run 109 notes.
- Authority anti-rollback persistence is not yet implemented; an operator that downgrades the ratification sidecar to an older valid one is not detected today.
- Signing-key rotation / revocation lifecycle is not yet implemented; the Run 110 / Run 111 harness exercises only the static R1-ratified / U1-unratified split.
- KMS/HSM custody for the bundle-signing key is out of scope; the Run 110 / Run 111 harness uses in-memory ML-DSA-44 keys.
- Production fast-sync / broader consensus-storage restore ratification parity is unevidenced.
- C5 is unchanged.

Recommended next run: a Run 112 that wires reload-apply ratification (Run 070 path) under the same Run 106 default-strict policy with its own source-level test coverage AND a release-binary harness — the next-narrowest unresolved C4 sub-piece beyond Runs 100–111. (Do not bundle rotation/revocation lifecycle with reload-apply; keep each lifecycle in its own dedicated run to preserve evidence discipline.)
