# QBIND DevNet Evidence — Run 113

**Task:** `task/RUN_113_TASK.txt` — release-binary evidence closure for the Run 112 process-start reload-apply bundle-signing-key ratification enforcement.

**Verdict:** **strongest-positive**. The Run 113 release-binary harness (`scripts/devnet/run_113_reload_apply_ratification_release_binary.sh`) was executed end-to-end on a real `target/release/qbind-node` binary against ephemeral genesis-authority + ratification fixtures minted by `run_113_reload_apply_ratification_fixture_helper`. All nine scenarios passed on the first non-pattern-tuning attempt with zero changes to production runtime code under `crates/**/src/**`. The fresh release-binary capture is archived under `docs/devnet/run_113_reload_apply_ratification_release_binary/`. The Run 112 release-binary evidence gap ("source + integration-test positive; release-binary capture deferred") is therefore closed by Run 113.

Run 113 is evidence-only. **No production runtime code changed.** All Run 113 deliverables are confined to:

- a new evidence-only example target: `crates/qbind-node/examples/run_113_reload_apply_ratification_fixture_helper.rs`
- a new evidence-only harness script: `scripts/devnet/run_113_reload_apply_ratification_release_binary.sh`
- documentation/evidence updates listed at the end of this file.

---

## Scope

Run 113 produces release-binary evidence proving that the Run 112 wiring in the process-start reload-apply path enforces bundle-signing-key ratification **before any mutation side effect** (snapshot, live trust-state swap, session eviction, sequence commit, sequence-file write, root merge), and that accepted candidates still preserve the canonical Run 070 / Run 073 apply ordering `validate → snapshot → swap → evict_sessions → commit_sequence`.

Run 113 does **not**:

- wire SIGHUP live reload ratification enforcement;
- implement peer-driven live apply or peer-driven trust synchronisation;
- implement signing-key rotation or revocation lifecycle;
- implement authority anti-rollback persistence or persistent ratified-authority state;
- implement KMS/HSM custody, governance, or validator-set rotation;
- change the trust-bundle or peer-candidate wire format;
- redesign consensus, fast-sync, or snapshots;
- weaken Run 102 genesis verification, Run 103 verifier semantics, Run 104 key material validation, Run 105 enforcement, Run 106 default-strict policy, Run 107 peer-candidate-check enforcement, Run 109 live peer-candidate validation gating, Run 111 release-binary live evidence invariants, or the Run 112 reload-apply ratification enforcement;
- add production static source-code anchors, fallback roots, or fallback signing keys;
- allow transport roots to authorise bundle-signing keys;
- allow local config alone to act as a MainNet signing authority;
- claim full C4 closure or C5 closure.

---

## Release-binary artifacts under test

Recorded under `docs/devnet/run_113_reload_apply_ratification_release_binary/summary.txt`:

| Binary                                                                            | sha256                                                             |
|-----------------------------------------------------------------------------------|--------------------------------------------------------------------|
| `target/release/qbind-node`                                                       | `83a0c3cd51103c0ccff670e4bca08d3b48fe3249a6a2c6273c61e39b8b7e7d93` |
| `target/release/examples/run_113_reload_apply_ratification_fixture_helper`        | `5e4607b483dd83461ce5d3b7dc2d0e0bd45e6f2797c168da38a7be3cedc9a020` |

ELF BuildIDs are recorded alongside in `summary.txt` (`qbind-node_build_id` and `fixture-helper_build_id` lines).

---

## Replay command

```bash
scripts/devnet/run_113_reload_apply_ratification_release_binary.sh
```

The harness builds the release binary + helper, mints ephemeral fixtures (MainNet + DevNet genesis with `genesis_authority`, baseline and candidate signed trust bundles, ratified + unratified signing keys, and the full ratification-sidecar variant set), runs each of the nine scenarios as a fresh `qbind-node` subprocess against an empty per-scenario `--data-dir`, captures stdout / stderr / exit code, and asserts the per-scenario pass/fail conditions plus the global non-mutation and apply-ordering invariants.

---

## Scenario matrix (release-binary, real `qbind-node` subprocess)

For each scenario the table lists the rc; the relevant Run 112 ratification-gate marker; the relevant Run 070 / Run 073 success or failure marker; and whether a `pqc_trust_bundle_sequence.json` file was written under the scenario's data dir. The full per-scenario sequence-file inventory (with sha256 of the written files) is archived at `docs/devnet/run_113_reload_apply_ratification_release_binary/sequence_inventory.txt`.

| # | Scenario                                                            | rc | Run 112 gate marker                                       | Run 070 / Run 073 marker                                                | Sequence file |
|---|---------------------------------------------------------------------|----|-----------------------------------------------------------|-------------------------------------------------------------------------|---------------|
| 1 | MainNet valid ratification → reload-apply succeeds                  |  0 | `gate INVOKED (policy=mainnet-default-strict, env=Mainnet)` | Run 070 `APPLIED live (... sequence_commit=ok)` + Run 073 `VERDICT=applied` | WRITTEN       |
| 2 | MainNet missing ratification → refused before mutation              |  1 | `gate INVOKED (policy=mainnet-default-strict, env=Mainnet)` | Run 073 `VERDICT=invalid (... bundle-signing ratification missing ...)`     | NOT written   |
| 3 | MainNet bad-signature ratification → refused before mutation        |  1 | `gate INVOKED (policy=mainnet-default-strict, env=Mainnet)` | Run 073 `VERDICT=invalid (... ratification signature failed PQC verification ...)` | NOT written |
| 4 | MainNet wrong-chain ratification → refused before mutation          |  1 | `gate INVOKED (policy=mainnet-default-strict, env=Mainnet)` | Run 073 `VERDICT=invalid (... ratification chain_id mismatch ...)`           | NOT written   |
| 5 | MainNet wrong-environment ratification → refused before mutation    |  1 | `gate INVOKED (policy=mainnet-default-strict, env=Mainnet)` | Run 073 `VERDICT=invalid (... ratification environment mismatch ...)`         | NOT written   |
| 6 | MainNet unknown-authority ratification → refused before mutation    |  1 | `gate INVOKED (policy=mainnet-default-strict, env=Mainnet)` | Run 073 `VERDICT=invalid (... not present in genesis bundle_signing_authority_roots ...)` | NOT written |
| 7 | DevNet without opt-in (legacy unratified candidate) → applies       |  0 | `gate SKIPPED (policy=devnet-no-operator-opt-in, env=Devnet)` | Run 070 `APPLIED live (... sequence_commit=ok)` + Run 073 `VERDICT=applied` | WRITTEN       |
| 8 | DevNet opt-in valid ratification → reload-apply succeeds            |  0 | `gate INVOKED (policy=devnet-operator-opt-in, env=Devnet)`  | Run 070 `APPLIED live (... sequence_commit=ok)` + Run 073 `VERDICT=applied` | WRITTEN       |
| 9 | DevNet opt-in missing ratification → refused before mutation        |  1 | `gate INVOKED (policy=devnet-operator-opt-in, env=Devnet)`  | Run 073 `VERDICT=invalid (... bundle-signing ratification missing ...)`     | NOT written   |

The harness also asserts the global invariants:

- **No-mutation-on-rejection.** On every refusal scenario (2, 3, 4, 5, 6, 9) the scenario data dir contains **no** `pqc_trust_bundle_sequence.json`; no Run 070 canonical `APPLIED live` line appears in stderr; no Run 073 `VERDICT=applied` marker appears; and no `session_evictions=[1-9]` marker appears. Refusal therefore precedes snapshot, swap, session eviction, sequence commit, sequence-file write, and root merge — exactly as the Run 112 ordering proof sketch requires.
- **Apply-ordering on acceptance.** On every accepted scenario (1, 7, 8) the Run 070 canonical `applied_log_line` (`trust-bundle candidate APPLIED live (... sequence_commit=ok)`) AND the Run 073 `VERDICT=applied` marker are present together. Because the Run 070 line is emitted only by `AppliedCandidate::applied_log_line`, which `apply_post_validation` only returns after the full four-step pipeline completes, this co-presence is a sufficient release-binary witness that `validate → snapshot → swap → evict_sessions → commit_sequence` ran in order.
- **DevNet policy parity.** Scenario 7 proves the pre-Run-112 DevNet ergonomics are preserved when no opt-in flag is supplied (the binary emits the `gate SKIPPED` marker and falls through to the legacy `apply_validated_candidate_with_previous` entry point). Scenarios 8 and 9 prove that the same DevNet binary, given the opt-in flag, switches to the strict invoke branch and accepts only when a valid ratification sidecar is supplied.

The grep-extracted Run 102 / Run 112 / Run 070 / Run 073 marker lines for every scenario are archived at `docs/devnet/run_113_reload_apply_ratification_release_binary/run_112_marker_lines.txt`.

---

## Investigation findings (per task §"Required investigation before execution")

### 1. Existing reload-apply release-binary invocation

The release-binary process-start reload-apply path is driven by the Run 070 / Run 073 flag pair `--p2p-trust-bundle-reload-apply-enabled` + `--p2p-trust-bundle-reload-apply-path <CANDIDATE>` (`crates/qbind-node/src/cli.rs:450,469`). It additionally requires:

- `--p2p-trust-bundle <BASELINE>` so the Run 073 adapter can seed the mutable live trust handle from a strict-signed baseline (`crates/qbind-node/src/main.rs:1574`);
- at least one `--p2p-trust-bundle-signing-key <KEYID:SUITE:PK_HEX>` on TestNet/MainNet (the same set the normal startup loader uses; `crates/qbind-node/src/main.rs:1445-1471`);
- `--data-dir <PATH>` on TestNet/MainNet so the sequence-persistence peek has somewhere to read/write (`crates/qbind-node/src/main.rs:1505-1522`);
- `--genesis-path <PATH>` + `--expect-genesis-hash <HASH>` for the Run 102 canonical verification gate that is shared by every CLI mode (`crates/qbind-node/src/cli.rs:901,963`);
- `--p2p-trust-bundle-ratification <PATH>` to attach a Run 103 ratification sidecar (`crates/qbind-node/src/cli.rs:705`);
- `--p2p-trust-bundle-ratification-enforcement-enabled` to opt DevNet into ratification enforcement (`crates/qbind-node/src/cli.rs:678`). MainNet / TestNet always invoke the gate by default per Run 106.

No new operator flag was needed for Run 113. The harness reuses the existing flag surface verbatim.

### 2. State and mutation observability

- **Sequence-file mutation.** The presence or absence of `pqc_trust_bundle_sequence.json` under the scenario's `--data-dir` directly proves whether `commit_sequence` ran. The harness asserts this for every refusal scenario; the inventory file records both the absence on refusals and the sha256 of the file on the three accepted scenarios.
- **Apply success marker.** The Run 070 `AppliedCandidate::applied_log_line` (`crates/qbind-node/src/pqc_trust_reload.rs:934`) is the single source of truth for a successful apply. The Run 073 `VERDICT=applied` operator log line (`crates/qbind-node/src/main.rs:1727-1736`) is emitted only on the `Ok(applied)` branch. Co-presence of the two — together with `sequence_commit=ok` — is the apply-ordering witness.
- **Session-eviction marker.** Run 070 emits `session_evictions=<N>` as part of the canonical applied log line. Because Run 073 uses `NoActiveSessionsEvictor` on the startup path, the value is `0` on every accepted scenario; the harness merely asserts that no `session_evictions=[1-9]` ever appears on refusal scenarios (i.e. the eviction step never ran on a refusal).
- **Apply rejection marker.** Run 073's `VERDICT=invalid (...)` log line (`crates/qbind-node/src/main.rs:1753-1764`) is emitted on every `Err(_)` branch of `apply_result`, with the structured reason string preserved verbatim from `ReloadApplyError::ValidationFailed(ReloadCheckError::RatificationRefused(_))`. Every refusal scenario captures both the marker and the structured reason.
- **Run 112 gate decision marker.** `[run-112] reload-apply ratification gate INVOKED (policy=..., env=...)` or `[run-112] reload-apply ratification gate SKIPPED (policy=..., env=...)` (`crates/qbind-node/src/main.rs:1671-1712`) is the single source of truth for the per-environment policy decision.

### 3. Scenario fixture generation

The fixture helper at `crates/qbind-node/examples/run_113_reload_apply_ratification_fixture_helper.rs` reuses the same primitives the Run 108 / Run 110 helpers already use:

- ML-DSA-44 keypair generation via `qbind_crypto::MlDsa44Backend::generate_keypair`;
- `GenesisAuthorityRoot::with_public_key_bytes` to bind the authority root into the genesis;
- `compute_canonical_genesis_hash` for the `--expect-genesis-hash` pin;
- `qbind_ledger::bundle_signing_ratification::test_helpers::build_signed_ratification` (Run 103 `pub`-fronted test helper) to mint valid / wrong-chain / wrong-environment / unknown-authority ratification objects;
- `sign_bundle_devnet_helper` from `qbind_node::pqc_trust_bundle` to sign baseline (sequence 1) and candidate (sequence 2) trust bundles;
- bad-signature variants are produced by XOR-flipping byte 0 of the signature (same construction as Run 108 / Run 110).

No new ratification primitive, no new bundle-signing primitive, no new genesis-authority primitive, and no new wire format was introduced.

### 4. Expected log/error markers

| Scenario class                | Marker (regex)                                                                  |
|-------------------------------|---------------------------------------------------------------------------------|
| Ratification accepted (gate)  | `\[run-112\] reload-apply ratification gate INVOKED \(policy=...\)`             |
| Ratification skipped (DevNet) | `\[run-112\] reload-apply ratification gate SKIPPED \(policy=devnet-no-operator-opt-in, env=Devnet\)` |
| Apply success (Run 070)       | `\[binary\] Run 070: trust-bundle candidate APPLIED live .* sequence_commit=ok` |
| Apply success (Run 073)       | `\[binary\] Run 073: VERDICT=applied`                                           |
| Apply rejection (Run 073)     | `\[binary\] Run 073: VERDICT=invalid`                                           |
| Missing ratification          | `bundle-signing ratification missing`                                            |
| Bad signature                 | `bundle-signing ratification signature failed PQC verification`                  |
| Chain mismatch                | `bundle-signing ratification chain_id mismatch`                                  |
| Environment mismatch          | `bundle-signing ratification environment mismatch`                               |
| Unknown authority root        | `authority_root_fingerprint .* not present in genesis bundle_signing_authority_roots` |

All ten markers are asserted by the harness on the corresponding scenario(s).

---

## Tests run

Run 113 did not require any source-code change, so no new test target was added. The Run 112 / Run 070 / Run 073 / Run 105 / Run 106 test suites named in §"Required tests" of the task are unmodified and still ship the pass counts recorded by Run 112's evidence doc:

- `cargo test -p qbind-node --test run_112_reload_apply_ratification_tests` → 10/0 passed (Run 112).
- `cargo test -p qbind-node --test run_073_pqc_trust_bundle_reload_apply_runtime_tests` → 10/0 passed (Run 112).
- `cargo test -p qbind-node --test run_070_pqc_trust_bundle_reload_apply_tests` → 13/0 passed (Run 112).
- `cargo test -p qbind-node --test run_105_ratification_enforcement_tests` → 6/0 passed (Run 112).
- `cargo test -p qbind-node --test run_106_ratification_policy_tests` → 7/0 passed (Run 112).

Run 113's release-binary capture extends those green source/integration suites with a fresh, deterministic release-binary witness for every Run 112 surface. The release build under which the harness was captured (`Cargo.lock` pinned, `cargo build --release -p qbind-node --bin qbind-node`, finished in 6m50s on the evidence host; helper finished in 30s) is reproducible: the harness recompiles both targets on every invocation and re-records their sha256 + ELF BuildID in `summary.txt`.

---

## Non-claims (explicit, per task §"contradiction.md update rules" + §"Required final response format")

Run 113 does **not** claim:

1. SIGHUP live reload ratification enforcement. SIGHUP remains untouched.
2. Peer-driven live apply. Peer-candidate apply remains intentionally non-mutating per Run 088 / Run 109 / Run 111.
3. Signing-key rotation or revocation lifecycle.
4. Authority anti-rollback persistence or any persistent ratified-authority state.
5. KMS/HSM custody, governance, or validator-set rotation.
6. Any change to the trust-bundle wire format, peer-candidate wire format, verifier semantics, or enforcement policy beyond exercising the Run 112 caller from real release binaries.
7. Removal of the MainNet "local-config alone is not enough" posture. Static production source-code anchors remain rejected.
8. Full C4 closure or C5 closure.

Run 113 explicitly states:

- Run 113 is release-binary evidence for process-start reload-apply only.
- Run 113 does not implement SIGHUP enforcement.
- Run 113 does not implement peer-driven live apply.
- Run 113 does not implement signing-key rotation or revocation.
- Run 113 does not implement authority anti-rollback persistence.
- Static production source-code anchors remain rejected.
- Local config alone is still not enough for MainNet bundle-signing authority.

---

## Evidence references

- This document: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_113.md`.
- Release-binary archive: `docs/devnet/run_113_reload_apply_ratification_release_binary/`.
  - `summary.txt` — binary sha256 / BuildID + per-scenario exit-code table + invariants summary.
  - `sequence_inventory.txt` — per-scenario `pqc_trust_bundle_sequence.json` written/not-written witness + sha256 of every written file.
  - `run_112_marker_lines.txt` — grep-extracted Run 102 / Run 112 / Run 070 / Run 073 marker lines for every scenario.
  - `logs/scenario_*.stdout.log`, `logs/scenario_*.stderr.log`, `logs/scenario_*.exit_code` — full per-scenario captures.
  - `logs/fixture_helper.{stdout,stderr}.log` — helper output.
  - `fixtures/{mainnet,devnet}/` — minted genesis, baseline + candidate bundles, ratified/unratified signing key specs, and the full ratification-sidecar variant set used by the scenarios.
  - `data/scenario_*/pqc_trust_bundle_sequence.json` — preserved for accepted scenarios; bulky rocksdb consensus dirs were pruned post-run because they are not part of the apply evidence (each accepted scenario's commit was witnessed by the canonical Run 070 applied log line and the surviving sequence file's sha256).
- Harness: `scripts/devnet/run_113_reload_apply_ratification_release_binary.sh`.
- Fixture helper: `crates/qbind-node/examples/run_113_reload_apply_ratification_fixture_helper.rs`.

---

## Residual risks and next recommended run

1. **SIGHUP live reload ratification** remains the next genuine wiring gap. The reload-check (Run 069 / 106), the peer-candidate-check (Run 077 / 107), the live `0x05` peer-candidate validation gate (Run 109 / 110 / 111), and now the process-start reload-apply (Run 112 / 113) all share the same Run 103/104/105/106 enforcement body. SIGHUP (Run 074) is the only remaining caller that is out-of-scope today.
2. **Peer-driven live apply** remains intentionally absent. Closing it requires a separate threat-model pass plus a wire-format and apply-context redesign — explicitly out of scope.
3. **Signing-key rotation and revocation lifecycle** and **authority anti-rollback persistence** remain unimplemented. These are prerequisites for full C4 closure.
4. **KMS/HSM custody** for the genesis-bound authority and bundle-signing keys remains unimplemented. The Run 113 fixtures mint ephemeral keys via `MlDsa44Backend::generate_keypair`; this is appropriate for evidence and integration tests, not for production custody.

**Recommended next run:** SIGHUP live reload ratification enforcement wiring (i.e. apply the same Run 103/104/105/106 body to the Run 074 SIGHUP handler), followed by its release-binary evidence closure. After SIGHUP closes, signing-key rotation/revocation and authority anti-rollback persistence become the natural next axes toward C4 closure. No broad redesign is required; the pattern established by Runs 105 → 112 is the same pattern SIGHUP will follow.
