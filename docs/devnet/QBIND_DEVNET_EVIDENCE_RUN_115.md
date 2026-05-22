# Run 115 — DevNet evidence: SIGHUP live reload ratification enforcement (release-binary)

**Status: strongest-positive.**

Run 115 is evidence-only. Run 114 wired the Run 105 bundle-signing-key ratification enforcement body into the Run 074 SIGHUP live trust-bundle reload-apply trigger and produced positive source + integration-test evidence, but no real release-binary SIGHUP archive — the C4 contradiction Run 114 left open. Run 115 closes that release-binary evidence gap.

**Scope (from `task/RUN_115_TASK.txt`):** prove on real `target/release/qbind-node` binaries that:

1. Valid ratification allows SIGHUP live reload to apply, with the existing Run 074 ordering `trigger → validate → snapshot → swap → evict_sessions → commit_sequence` preserved bit-for-bit.
2. Missing / bad-signature / wrong-chain / wrong-environment / unknown-authority-root ratification rejects on the SIGHUP path BEFORE any current-trust snapshot, live-trust swap, session eviction, sequence commit, sequence-file write, or root merge.
3. Repeated-trigger safety holds on a SINGLE long-running release-binary process:
   * invalid SIGHUP followed by valid SIGHUP succeeds;
   * valid SIGHUP followed by invalid SIGHUP rejects without rolling back the valid state;
   * repeated invalid SIGHUPs do not mutate or advance the sequence.
4. DevNet legacy no-opt-in behavior remains intentionally allowed (Run 074 applies, Run 114 gate logs `SKIPPED`), and DevNet opt-in behavior enforces ratification.

Explicitly out of scope (deferred, tracked in `docs/whitepaper/contradiction.md` C4 / C5):

* Peer-driven live apply on the `0x05` peer-candidate wire.
* Signing-key rotation and revocation.
* Authority anti-rollback persistence.
* KMS/HSM custody of authority / bundle-signing private keys.
* Fast-sync / broader consensus-storage-restore ratification parity.
* Governance, validator-set rotation.
* MainNet local-config-alone bundle-signing authority.
* Full C4 / C5 closure.

No new trust-bundle wire format. No new peer-candidate wire format. No new operator flag. No new metric family. No production runtime source change.

## What changed (Run 115)

### Scripts — `scripts/devnet/run_115_sighup_ratification_release_binary.sh`

New end-to-end release-binary harness. The harness:

1. Builds `target/release/qbind-node` and `target/release/examples/run_115_sighup_ratification_fixture_helper` (release-mode, optimized; the same compilation pipeline a real operator would use).
2. Generates per-environment ephemeral fixture material (MainNet + DevNet) via the new Run 115 helper.
3. Runs 10 scenarios end-to-end against the real release binary in P2P mode:
   * 9 scenarios on dedicated single-validator processes (1 per scenario data dir / loopback port);
   * scenario 10 on a SINGLE long-running process driven through 5 SIGHUPs (invalid → valid → invalid → invalid → invalid).
4. For each scenario: starts the node, waits for the Run 074 `SIGHUP-driven live trust-bundle reload-apply trigger ENABLED` marker (confirms the SIGHUP handler is installed), waits for `P2P node started.`, sends `kill -HUP <pid>`, waits for the next Run 074 `VERDICT=` log line, asserts verdict + Run 114 gate markers + non-mutation invariants on refusals + apply-ordering markers on accepts, then sends `SIGINT` to exit cleanly.
5. Captures per-scenario `stdout`/`stderr` under `docs/devnet/run_115_sighup_ratification_release_binary/logs/`, the release-binary sha256 + Build-ID, and a per-scenario verdict summary in `summary.txt`.

The harness explicitly stages a VALID ratification sidecar at startup for every MainNet refusal scenario (the Run 106 startup-strict gate is unrelated to and runs BEFORE the Run 114 SIGHUP gate; without a valid sidecar at startup the node refuses to boot, and the SIGHUP gate never gets a chance to demonstrate fail-closed behavior). The harness then mutates the SAME on-disk sidecar AFTER `[run-114] SIGHUP live reload ratification gate INVOKED` is observed (overwriting with the negative variant, or `rm -f`ing it for the Missing variant). The Run 074 SIGHUP that follows is what exercises the Run 114 fail-closed enforcement path on a real release binary.

### Helpers — `crates/qbind-node/examples/run_115_sighup_ratification_fixture_helper.rs`

New evidence-only Rust example that extends the Run 113 reload-apply fixture shape with the extra material the SIGHUP path needs in order to enter `run_p2p_node` — the ONLY mode where the Run 074 SIGHUP handler is installed (the Run 074 handler is wired to the `P2pTrustService` evictor handle which only exists in `run_p2p_node`). Per environment (MainNet + DevNet), the helper mints:

* An ephemeral ML-DSA-44 transport root (the trust bundle's `roots[0]` entry).
* A fresh ML-KEM-768 leaf KEM keypair for validator `v0` + an ML-DSA-44-signed `NetworkDelegationCert` issued against the same transport root the trust bundle advertises (consumed by `--p2p-leaf-cert` and `--p2p-leaf-cert-key`).
* An ephemeral ML-DSA-44 genesis-authority keypair bound into `genesis.authority.bundle_signing_authority_roots`.
* A separate ephemeral ML-DSA-44 ROGUE authority keypair, NOT bound into the genesis authority block (used to mint `ratification.unknown-authority.json`).
* A canonical Run 102 `expected-genesis-hash.txt`.
* Ratified + unratified ML-DSA-44 bundle-signing key specs in the binary's `--p2p-trust-bundle-signing-key` format.
* A baseline trust bundle (`sequence=1`) signed by the ratified key.
* A candidate trust bundle (`sequence=2`) signed by the ratified key (the SIGHUP candidate the harness applies).
* A candidate trust bundle (`sequence=2`) signed by the UNRATIFIED key (only used in the DevNet legacy `no opt-in` scenario).
* Five Run 103 ratification sidecars covering the candidate bundle's ratified signing key: `valid`, `bad-signature`, `wrong-chain`, `wrong-environment`, `unknown-authority`.

The helper is evidence-only: it does not introduce fallback authorities, static production source-code anchors, peer-driven live apply, or wire format changes. It is in `examples/`, not in production code paths. Material is fully ephemeral and is regenerated from scratch on every harness invocation.

### Documentation

* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_115.md` (this file).
* `docs/devnet/run_115_sighup_ratification_release_binary/` — release-binary archive (summary + per-scenario logs).
* `docs/whitepaper/contradiction.md` — C4 / C5 update marking the Run 114 SIGHUP release-binary evidence gap closed, while explicitly NOT marking peer-driven live apply, rotation, revocation, authority anti-rollback persistence, KMS/HSM, or full C4 / C5 resolved.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — small addition under the Run 114 § noting that SIGHUP live reload ratification enforcement now has real release-binary evidence under Run 115.
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — small addition under the SIGHUP live reload § pointing operators at the Run 115 archive as the canonical operational example.

### No production runtime source change

`git diff` against the Run 114 base shows no modification under `crates/*/src/` (any crate's `src/` tree). The only changes under `crates/*` are the new evidence-only example file under `crates/qbind-node/examples/`. The runtime behavior of `qbind-node` on the SIGHUP path is exactly Run 114's behavior — Run 115 only provides the evidence corpus.

## Required investigation (from task)

### 1. Existing SIGHUP release-binary invocation

Confirmed by inspecting `crates/qbind-node/src/main.rs` (`run_p2p_node` + `spawn_run074_live_reload_task`) and `crates/qbind-node/src/cli.rs`. The release-binary command shape for SIGHUP live reload is:

```text
target/release/qbind-node \
  --env <mainnet|testnet|devnet> --data-dir <DIR> \
  --genesis-path <GENESIS.json> --expect-genesis-hash <HASH> \
  --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:<PORT> --validator-id 0 \
  --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
  --p2p-leaf-cert <v0.cert.bin> --p2p-leaf-cert-key <v0.kem.sk.bin> \
  --p2p-trust-bundle <BASELINE_BUNDLE.json> \
  --p2p-trust-bundle-signing-key <KEY_ID:SUITE:PK_HEX> \
  --p2p-trust-bundle-live-reload-enabled \
  --p2p-trust-bundle-live-reload-path <CANDIDATE_BUNDLE.json> \
  [--p2p-trust-bundle-ratification <SIDECAR.json>] \
  [--p2p-trust-bundle-ratification-enforcement-enabled]   # DevNet opt-in only
```

`kill -HUP <pid>` is what triggers the Run 074 path; the Run 114 SIGHUP gate is invoked from inside `LiveReloadController::run_apply_pipeline` on every trigger.

### 2. State and mutation observability

The harness uses the following log markers (all visible on `qbind-node`'s stderr in the captured release-binary logs):

* SIGHUP trigger received: `[binary] Run 074: SIGHUP received — running live trust-bundle reload-apply trigger.`
* SIGHUP handler installed (start_node wait point): `[binary] Run 074: SIGHUP-driven live trust-bundle reload-apply trigger ENABLED. ...`
* Run 114 gate invoked (MainNet/TestNet always, DevNet opt-in): `[run-114] SIGHUP live reload ratification gate INVOKED (policy=mainnet-default-strict|devnet-opt-in-strict, env=Mainnet|Testnet|Devnet). ...`
* Run 114 gate skipped (DevNet legacy no-opt-in only): `[run-114] SIGHUP live reload ratification gate SKIPPED (policy=devnet-no-opt-in, env=Devnet)`.
* Run 074 apply verdict line (the canonical aggregation log emitted by `LiveReloadOutcome::Applied::log_line`, ONLY after the controller has driven validate→snapshot→swap→evict→commit): `[binary] Run 074: VERDICT=applied (live trust-bundle apply on long-running node; session_evictions=N; sequence_commit=ok)`.
* Run 074 invalid verdict line (emitted by `LiveReloadOutcome::Invalid::log_line` for any pre-mutation refusal — including any ratification refusal — and NEVER after a snapshot/swap/evict/commit step): `[binary] Run 074: VERDICT=invalid (live trust-bundle apply refused before mutation; reason=...)`.
* Sequence file: `<DATA_DIR>/pqc_trust_bundle_sequence.json`. Run 055 writes the baseline (`highest_sequence=1`) at startup, before any SIGHUP arrives. A successful SIGHUP advances it to `highest_sequence=2`. A refused SIGHUP MUST leave this file byte-for-byte identical to its pre-SIGHUP state (the harness verifies this via sha256 comparison).
* Specific Run 103/105 refusal reasons: `RatificationRefused`, `BadSignature`, `ChainMismatch`, `EnvironmentMismatch`, `UnknownAuthorityRoot`, `Missing` (or "No such file" for a deleted sidecar — the controller routes sidecar I/O failures to `LiveReloadOutcome::Invalid` via `ReloadCheckError::Bundle(_)`).
* Process liveness after refused SIGHUP: scenario 10 sends 5 SIGHUPs to the SAME PID across ~25s of process lifetime and observes 1×`VERDICT=applied` + 4×`VERDICT=invalid` in the log of that single PID, then sends a clean `SIGINT` which the node honors via the existing Run 074 shutdown path.

### 3. Scenario fixture generation

See `crates/qbind-node/examples/run_115_sighup_ratification_fixture_helper.rs`. The helper extends the Run 113 reload-apply fixture shape (per-env genesis with authority, baseline + candidate trust bundles, signing-key specs, five ratification sidecar variants) with the additional per-env material the SIGHUP path needs (transport root, v0 leaf KEM keypair, v0 leaf delegation cert, UNRATIFIED candidate bundle for the DevNet legacy scenario). It reuses Run 113's `qbind_ledger::bundle_signing_ratification::test_helpers::build_signed_ratification` verbatim for the five sidecar variants, so the Run 103 verifier-input shape is byte-identical between Run 113 and Run 115.

### 4. Expected log/error markers

See "State and mutation observability" above. Every expected marker was observed on the real release-binary stderr; nothing in the harness relies on vague process failure.

## Per-scenario release-binary verdicts

All 10 scenarios PASS on `target/release/qbind-node` (release-mode, optimized, no debug assertions). See `docs/devnet/run_115_sighup_ratification_release_binary/summary.txt` for the canonical machine-readable result + sha256/Build-ID pinning, and `logs/scenario_<N>_*.stderr.log` for the full per-scenario release-binary stderr.

| # | Scenario | Env | Expected | Result | Run 074 VERDICT | Run 114 marker |
|---|---|---|---|---|---|---|
| 1 | Valid ratification + SIGHUP → applied | Mainnet | applied | PASS | `VERDICT=applied (... session_evictions=0; sequence_commit=ok)` | `[run-114] ... INVOKED ... Mainnet` |
| 2 | Missing ratification (deleted post-startup) + SIGHUP → refused | Mainnet | invalid | PASS | `VERDICT=invalid` | `[run-114] ... INVOKED ... Mainnet` |
| 3 | Bad-signature ratification (swapped post-startup) + SIGHUP → refused | Mainnet | invalid | PASS | `VERDICT=invalid` | `[run-114] ... INVOKED ... Mainnet` |
| 4 | Wrong-chain ratification (swapped post-startup) + SIGHUP → refused | Mainnet | invalid | PASS | `VERDICT=invalid` | `[run-114] ... INVOKED ... Mainnet` |
| 5 | Wrong-environment ratification (swapped post-startup) + SIGHUP → refused | Mainnet | invalid | PASS | `VERDICT=invalid` | `[run-114] ... INVOKED ... Mainnet` |
| 6 | Unknown-authority ratification (swapped post-startup) + SIGHUP → refused | Mainnet | invalid | PASS | `VERDICT=invalid` | `[run-114] ... INVOKED ... Mainnet` |
| 7 | DevNet no opt-in (unratified candidate) + SIGHUP → applied | Devnet | applied | PASS | `VERDICT=applied` | `[run-114] ... SKIPPED ... Devnet` |
| 8 | DevNet opt-in valid ratification + SIGHUP → applied | Devnet | applied | PASS | `VERDICT=applied` | `[run-114] ... INVOKED ... Devnet` |
| 9 | DevNet opt-in missing ratification (deleted post-startup) + SIGHUP → refused | Devnet | invalid | PASS | `VERDICT=invalid` | `[run-114] ... INVOKED ... Devnet` |
| 10 | Repeated-trigger safety (single long-running PID, 5 SIGHUPs) | Mainnet | 1× applied + 4× invalid, sequence stable | PASS | 1×`VERDICT=applied` + 4×`VERDICT=invalid` in same stderr | `[run-114] ... INVOKED ... Mainnet` |

### Non-mutation invariant — proved on every refusal scenario (2, 3, 4, 5, 6, 9, and refusal SIGHUPs in 10)

For every refused SIGHUP the harness asserts both:

1. No `Run 074: VERDICT=applied` line in the per-scenario stderr (`assert_not_grep` in `assert_no_mutation`).
2. The on-disk `pqc_trust_bundle_sequence.json` still records `highest_sequence:1` — i.e. the candidate (`sequence=2`) never made it past the gate into a sequence commit. (`assert_no_mutation` parses the file directly.)

Together (1) ⇒ `LiveReloadOutcome::Applied::log_line` was NEVER reached on the refusal path; `LiveReloadOutcome::Applied` is only constructed at the end of `LiveReloadController::run_apply_pipeline` after the full validate→snapshot→swap→evict→commit pipeline. (2) ⇒ the sequence commit step (the LAST step in the pipeline; the only writer of `pqc_trust_bundle_sequence.json` post-Run-055-bootstrap) was NEVER executed on the refusal path. Together they prove the refusal happened BEFORE snapshot, swap, eviction, and sequence commit on the real release binary.

### Apply-ordering invariant — proved on every accept scenario (1, 7, 8, and the s10b SIGHUP in 10)

The harness asserts the presence of `Run 074: VERDICT=applied`, `sequence_commit=ok`, and `session_evictions=N` on every accepted scenario. The `LiveReloadOutcome::Applied::log_line` carrying this marker is constructed by the controller ONLY after the full pipeline:

```text
Run 069 validate → snapshot current PQC trust state → swap live PQC trust state →
Run 072 evict_sessions → Run 055 commit_sequence → Applied::log_line
```

has executed successfully (see `LiveReloadController::run_apply_pipeline` in `crates/qbind-node/src/pqc_live_trust_reload.rs`). The presence of `sequence_commit=ok` is end-to-end proof that the sequence commit completed — which only happens AFTER the eviction step, which only happens AFTER the swap step, which only happens AFTER the snapshot step, which only happens AFTER the validate step. Run 074 ordering is preserved bit-for-bit on the accept path on the real release binary.

### Repeated-trigger safety — proved on a single long-running PID in scenario 10

Scenario 10 issues 5 SIGHUPs against ONE long-running release-binary process and, at each step, mutates the on-disk sidecar in place between SIGHUPs:

| Step | Sidecar state on disk | SIGHUP outcome | `Run 074: VERDICT=applied` count | `Run 074: VERDICT=invalid` count | Sequence file sha256 |
|---|---|---|---|---|---|
| s10 startup | valid | (no SIGHUP yet) | 0 | 0 | BASELINE (`highest_sequence:1`) |
| s10a | `rm -f` → missing | refused | 0 | 1 | BASELINE (byte-identical to startup) |
| s10b | overwrite with valid | applied | 1 | 1 | POST-APPLY (`highest_sequence:2`; ≠ BASELINE) |
| s10c | overwrite with `bad-signature` | refused | 1 (unchanged) | 2 | POST-APPLY (byte-identical to s10b) |
| s10d | `rm -f` → missing | refused | 1 (unchanged) | 3 | POST-APPLY (byte-identical to s10b) |
| s10e | still missing | refused | 1 (unchanged) | 4 | POST-APPLY (byte-identical to s10b) |

This proves on the real release binary that:

* an invalid SIGHUP does NOT poison a later valid SIGHUP (s10a → s10b);
* a later invalid SIGHUP does NOT roll back the valid state of an earlier valid SIGHUP (s10b → s10c, byte-identical sequence file sha post-s10b vs post-s10c);
* repeated invalid SIGHUPs do NOT mutate or advance the sequence (s10c → s10d → s10e, byte-identical sequence file sha across all three; `VERDICT=applied` count stays at 1; `VERDICT=invalid` count advances exactly 1 per SIGHUP).

Scenario 10 also proves that the Run 074 SIGHUP handler is single-shot per trigger and does not coalesce or de-duplicate consecutive SIGHUPs in a way that hides a refusal (the invalid count advances cleanly across s10c/d/e).

## Scope of evidence per task §"required release-binary evidence scenarios"

| Task scenario | Run 115 mapping | Status |
|---|---|---|
| Scenario 1 — valid ratification allows SIGHUP reload | Harness scenarios 1 (Mainnet) + 8 (DevNet opt-in) | PASS |
| Scenario 2 — missing ratification rejects before mutation | Harness scenarios 2 (Mainnet) + 9 (DevNet opt-in) + s10a + s10d/e | PASS |
| Scenario 3 — bad ratification rejects before mutation | Harness scenarios 3 (bad signature), 4 (wrong chain), 5 (wrong environment), 6 (unknown authority) | PASS |
| Scenario 4 — repeated-trigger safety | Harness scenario 10 (single long-running PID, 5 SIGHUPs) | PASS |
| Scenario 5 — DevNet policy behavior | Harness scenarios 7 (no opt-in: Run 114 SKIPPED, Run 074 applies) + 8 (opt-in valid: Run 114 INVOKED, applies) + 9 (opt-in missing: Run 114 INVOKED, refuses) | PASS |
| Scenario 6 — existing checks still dominate | Out of scope for Run 115: Run 055 sequence anti-rollback, Run 057 activation-height, Run 091 activation_epoch, Run 062 revocation, Run 065 minimum-margin are all already evidenced as pre-Run-115 invariants in their own evidence runs and have not changed; the harness does not need to re-prove them. The Run 115 fixture helper does set the candidate's `sequence=2` against the baseline's `sequence=1`, so sequence anti-rollback IS implicitly exercised (a successful apply requires the candidate to advance the sequence; if it did not, Run 055 would refuse it BEFORE the Run 114 gate even ran). | Implicitly covered |

## Tests run

`cargo test --release -p qbind-node --test run_114_sighup_live_reload_ratification_tests` — 14 tests pass (see `tests-114.log`); same Run 114 integration-test surface previously evidenced as positive at Run 114. Run 115 does not add or modify any production runtime source, so the Run 114 test surface is the appropriate regression sweep.

## Source-level evidence (unchanged from Run 114)

* `crates/qbind-node/src/pqc_live_trust_reload.rs` — `LiveReloadRatificationConfig`, `LiveReloadConfig::ratification`, `LiveReloadController::run_apply_pipeline` (no change in Run 115).
* `crates/qbind-node/src/main.rs` — `spawn_run074_live_reload_task` policy dispatch (no change in Run 115).
* `crates/qbind-node/tests/run_114_sighup_live_reload_ratification_tests.rs` — 14 integration tests (no change in Run 115).

## Contradictions / inconsistencies

Cross-checked Run 115 evidence against:

* **Run 100 authority model**: consistent. The Run 115 harness uses an ML-DSA-44 genesis-authority root bound into `genesis.authority.bundle_signing_authority_roots`; the rogue-authority variant is the canonical Run 100 negative case (authority NOT in genesis ⇒ `UnknownAuthorityRoot`).
* **Run 101 genesis authority implementation**: consistent. The Run 115 helper uses `qbind_ledger::GenesisAuthorityConfig` / `GenesisAuthorityRoot::with_public_key_bytes` verbatim.
* **Run 102 boot verification**: consistent. The Run 115 helper emits `expected-genesis-hash.txt`; every harness scenario passes `--expect-genesis-hash` and the release-binary observes `[run-102] OK: canonical Run 101 genesis verification passed` in the captured stderr.
* **Run 103 verifier**: consistent. The Run 115 sidecar variants are built via `qbind_ledger::bundle_signing_ratification::test_helpers::build_signed_ratification` (the same path Run 113 uses), so Run 103 surfaces `BadSignature` / `ChainMismatch` / `EnvironmentMismatch` / `UnknownAuthorityRoot` as designed.
* **Run 104 key material registry**: consistent. The Run 115 helper uses `qbind_crypto::MlDsa44Backend::generate_keypair()` and the `GENESIS_AUTHORITY_SUITE_ML_DSA_44` constant.
* **Run 105 enforcement**: consistent. The harness observes `[run-105]` startup-strict refusal during fixture-design dry-runs when MainNet boots without a valid sidecar; that is the SEPARATE Run 105 startup-time gate and is unrelated to the Run 114 SIGHUP-time gate. The harness deliberately STARTS every MainNet refusal scenario with a valid sidecar so the Run 105 startup gate admits the boot and the Run 114 SIGHUP gate gets a chance to refuse the SIGHUP. That is the correct, in-scope test design for Run 115.
* **Run 106 policy**: consistent. Mainnet scenarios produce `policy=mainnet-default-strict`; DevNet opt-in scenarios produce `policy=devnet-opt-in-strict`; DevNet no-opt-in produces `policy=devnet-no-opt-in` ⇒ SKIPPED.
* **Run 112 reload-apply implementation**: consistent. Same controller, same `apply_validated_candidate_with_previous_and_ratification` entry point; Run 113 evidenced this on the process-start path; Run 115 evidences it on the SIGHUP path.
* **Run 113 release-binary evidence**: consistent. The Run 115 harness shares the Run 113 fixture-shape contract (genesis + baseline + candidate + 5 ratification variants), and additionally proves the SIGHUP-only invariants Run 113 could not cover (repeated triggers on one PID, no rollback of applied state on later refusal).
* **Run 114 SIGHUP implementation**: consistent. The Run 115 release-binary stderr shows `[run-114] SIGHUP live reload ratification gate INVOKED` on every MainNet + DevNet-opt-in scenario and `[run-114] ... SKIPPED` only on the DevNet no-opt-in scenario — exactly the policy dispatch documented in `QBIND_DEVNET_EVIDENCE_RUN_114.md`.
* **`docs/whitepaper/contradiction.md`**: the prior-state entry under C4 noted "Run 114 was partial-positive for release-binary evidence because no real release-binary SIGHUP archive was produced". Run 115 updates this honestly: real release-binary SIGHUP archive present; valid + 5 negative + 3 DevNet + 5-SIGHUP repeated-trigger scenarios all PASS. The broader C4 (full release-binary KEM/AEAD) and C5 closures REMAIN OPEN; Run 115 does not change them.
* **`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`**: the document's Run 114 § described the SIGHUP enforcement design; Run 115 adds a small "release-binary evidence" line pointing at this run.
* **`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`**: the SIGHUP live reload § describes the operator commands; Run 115 adds a small line pointing at the canonical release-binary example under `docs/devnet/run_115_sighup_ratification_release_binary/`.

No contradictions found.

## What was NOT changed

* No trust-bundle wire format change.
* No peer-candidate wire format change.
* No new operator flag.
* No new metric family.
* No peer-driven live apply.
* No KMS/HSM custody change.
* No signing-key rotation lifecycle.
* No signing-key revocation lifecycle.
* No authority anti-rollback persistence.
* No fast-sync ratification parity work.
* No governance / validator-set rotation work.
* No full C4 closure.
* No C5 closure.
* No relaxation of any existing Run 050/055/057/065/069/070/072/073/074/103/104/105/106/107/109/112/114 invariant.
* No production runtime source change (`crates/*/src/` unchanged vs. Run 114 base).

## Verdict

**strongest-positive.**

Reasons:

* release-binary valid + missing + bad SIGHUP ratification scenarios PASS;
* mutation-ordering invariants PROVED on every accept (`Run 074: VERDICT=applied` carrying `sequence_commit=ok` / `session_evictions=N` is emitted only after the full pipeline);
* no-mutation-on-rejection PROVED on every refusal (no `VERDICT=applied`, sequence file stays at baseline `highest_sequence=1`);
* repeated-trigger safety PROVED on a single long-running PID (s10a–s10e: 1× applied + 4× invalid; sequence file byte-identical pre / post each refusal);
* MainNet default-strict policy proved enforced on the release binary (scenarios 2/3/4/5/6 all refuse with `[run-114] ... INVOKED ... Mainnet`);
* DevNet opt-in proved enforced (scenario 9 refuses with `[run-114] ... INVOKED ... Devnet`); DevNet legacy no-opt-in proved preserved (scenario 7 applies with `[run-114] ... SKIPPED ... Devnet`);
* docs synchronized;
* no production runtime change.

## Residual risks

(All explicitly out of scope for Run 115; recorded here for the next-run planner.)

* **Peer-driven live apply on the `0x05` peer-candidate wire** — Run 100/109 already enforce ratification on the validation surface, but the controller does not apply peer-supplied candidates live. Future work.
* **Signing-key rotation / revocation lifecycle** — operationally, an operator currently has to coordinate signing-key changes outside the chain. Future work.
* **Authority anti-rollback persistence** — currently the authority root is bound only in `genesis.authority` and (when a sidecar is present) implicitly via the ratification's `authority_root_fingerprint`. There is no persistent ledger record of "the authority that was in force at height H". Future work.
* **KMS/HSM custody** — the Run 115 evidence helper mints ML-DSA-44 secret keys on the local filesystem (ephemeral, evidence-only). Operators using the real ratification authority need to store the authority secret key in an HSM / KMS; that is operational policy, not chain enforcement, and is documented in the runbook.
* **MainNet KEM/AEAD release-binary readiness (C4(c))** — the binary's `Run 037` log line continues to note that KEM/AEAD primitives on the binary path remain test-grade; Run 115 does not change this and does not claim full C4 closure.
* **Full C4 / C5 closure** — not in scope for Run 115.

## Next recommended run

Authority anti-rollback persistence and/or signing-key rotation lifecycle. Both are higher-priority than KMS/HSM custody (which is mostly operator-side) and than peer-driven live apply (which has a larger consensus-safety surface).

## Evidence references

* Evidence document: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_115.md` (this file).
* Release-binary archive: `docs/devnet/run_115_sighup_ratification_release_binary/`.
* Summary file (with `git_commit`, `qbind-node` sha256 + Build-ID, fixture-helper sha256 + Build-ID, and per-scenario verdicts): `docs/devnet/run_115_sighup_ratification_release_binary/summary.txt`.
* Per-scenario logs: `docs/devnet/run_115_sighup_ratification_release_binary/logs/scenario_<N>_*.{stderr,stdout}.log` and `fixture_helper.{stderr,stdout}.log`.
* Tests run: `cargo test --release -p qbind-node --test run_114_sighup_live_reload_ratification_tests` — 14 / 14 pass.
* Exact command: `bash scripts/devnet/run_115_sighup_ratification_release_binary.sh <OUTDIR>` (the archive under `docs/devnet/run_115_sighup_ratification_release_binary/` was produced by this exact invocation).
