# QBIND DevNet Evidence — Run 102

**Task:** `task/RUN_102_TASK.txt` — Release-binary genesis verification wiring + canonical `--print-genesis-hash`.

**Verdict:** PARTIAL-POSITIVE (Priority 1 + Priority 2 complete; Priority 3 deferred to Run 103 per task's allowed-scope rules).

**Anchor:**
- Implementation: `crates/qbind-node/src/pqc_boot_genesis.rs` (new), `crates/qbind-node/src/main.rs` (Run 102 hooks), `crates/qbind-node/src/cli.rs` (help text).
- Tests: `crates/qbind-node/src/pqc_boot_genesis.rs::tests` (8 in-module unit tests), `crates/qbind-node/tests/run_102_boot_genesis_wiring_tests.rs` (14 integration tests).
- Release-binary smoke logs: this directory, `run_102_genesis_verification_evidence/`.

---

## 1. Investigation

The Run 101 evidence note `docs/devnet/run_101_genesis_authority_evidence/scenario_5_print_genesis_hash.stderr.log` flagged two operator-facing gaps that Run 102 must close:

1. **The release binary's `--print-genesis-hash` flag was not wired to exit after printing.** Existing T233 `CliArgs::print_genesis_hash` field (`crates/qbind-node/src/cli.rs:851`) was parsed but never consumed in `main.rs`; the binary fell through to the regular consensus loop. The pre-Run-101 documentation also described this flag as hashing the *raw file bytes* of the genesis file, which contradicts Run 101's canonical-parsed semantics.
2. **`qbind_ledger::verify_boot_time_genesis` was not invoked by the release binary at all.** The Run 101 unit + integration tests covered the helper exhaustively, but the production `qbind-node` `main` made no call to it. The existing T233 `MainnetConfigError::ExpectedGenesisHashMissing` shield only checked that the CLI flag was non-empty — it did not load the genesis file, compute the canonical hash, or compare it.

Both gaps were within MainNet's release-binary security boundary. Run 102 closes them.

---

## 2. What was implemented

| Component                                                                       | File                                                                                | Behaviour                                                                                                                                                                                                          |
|---------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `pqc_boot_genesis::map_environment`                                             | `crates/qbind-node/src/pqc_boot_genesis.rs`                                         | 1-to-1 map `qbind_types::NetworkEnvironment` → `qbind_ledger::NetworkEnvironmentPolicy`; scope strings asserted equal byte-for-byte.                                                                               |
| `pqc_boot_genesis::load_external_genesis`                                       | `crates/qbind-node/src/pqc_boot_genesis.rs`                                         | Reads the genesis file as bytes and `serde_json::from_slice`s into a strict `GenesisConfig`. No defaults are filled; no embedded fallback is consulted.                                                            |
| `pqc_boot_genesis::run_boot_time_genesis_verification`                          | `crates/qbind-node/src/pqc_boot_genesis.rs`                                         | Run 102 entry point. Loads + parses external genesis (or returns `SkippedNoExternalGenesis` on DevNet/TestNet embedded-genesis path) and delegates to `qbind_ledger::verify_boot_time_genesis`. Fails closed.      |
| `pqc_boot_genesis::compute_print_genesis_hash` + `format_for_operator`          | `crates/qbind-node/src/pqc_boot_genesis.rs`                                         | Canonical `--print-genesis-hash` backend. Calls Run 101's `compute_canonical_genesis_hash` over the parsed `GenesisConfig`. Result is the same `0x`-prefixed 64-char hex pasteable into `--expect-genesis-hash`. |
| `--print-genesis-hash` wiring                                                   | `crates/qbind-node/src/main.rs` (new block after `to_node_config`)                  | Loads `--genesis-path`, computes canonical hash for the resolved env, prints to stdout, exits `0`. Refuses with non-zero exit on missing path / malformed JSON / I/O failure.                                      |
| Boot-time genesis verification wiring                                           | `crates/qbind-node/src/main.rs` (new block after T185 MainNet invariants, before B3 restore, Run 069 reload-check, P2P startup, consensus loop) | Calls `run_boot_time_genesis_verification` and exits `1` on any failure. On MainNet refusal happens *before* trust-bundle / P2P / consensus startup.                                                                |
| `--print-genesis-hash` and `--expect-genesis-hash` help text                    | `crates/qbind-node/src/cli.rs`                                                      | Updated: now explicitly describes canonical Run 101 parsed-genesis semantics; explicitly states no raw-file-byte fallback; references Run 102 evidence.                                                            |

No new CLI flags. No new dependencies. No new Prometheus metric. No `Dummy*` re-enablement. No fallback authority. No fallback expected hash. No source-code production trust anchor. No new admin API / network listener / peer-driven apply.

---

## 3. What was proven

### 3.1 Unit tests (in-module — `crates/qbind-node/src/pqc_boot_genesis.rs::tests`)

```
$ cargo test -p qbind-node --lib pqc_boot_genesis
running 8 tests
test pqc_boot_genesis::tests::map_environment_is_1to1 ... ok
test pqc_boot_genesis::tests::print_hash_differs_for_chain_id_change ... ok
test pqc_boot_genesis::tests::print_hash_differs_for_authority_field_change ... ok
test pqc_boot_genesis::tests::print_hash_differs_across_environments ... ok
test pqc_boot_genesis::tests::print_hash_rejects_malformed_json ... ok
test pqc_boot_genesis::tests::print_hash_rejects_missing_file ... ok
test pqc_boot_genesis::tests::print_hash_is_canonical_not_raw_file_bytes ... ok
test pqc_boot_genesis::tests::print_hash_loads_and_canonicalizes_mainnet_genesis ... ok
test result: ok. 8 passed; 0 failed
```

### 3.2 Integration tests (`crates/qbind-node/tests/run_102_boot_genesis_wiring_tests.rs`)

```
$ cargo test -p qbind-node --test run_102_boot_genesis_wiring_tests
running 14 tests
test run_102_devnet_embedded_genesis_is_preserved ... ok
test run_102_mainnet_empty_authority_roots_rejects ... ok
test run_102_devnet_flag_does_not_bypass_mainnet_strictness ... ok
test run_102_devnet_with_external_genesis_verifies ... ok
test run_102_mainnet_chain_environment_mismatch_rejects ... ok
test run_102_mainnet_malformed_genesis_file_rejects ... ok
test run_102_mainnet_malformed_authority_root_rejects ... ok
test run_102_mainnet_hash_mismatch_rejects ... ok
test run_102_mainnet_missing_genesis_file_rejects ... ok
test run_102_mainnet_no_genesis_path_rejects ... ok
test run_102_mainnet_missing_authority_rejects ... ok
test run_102_mainnet_missing_expected_hash_rejects ... ok
test run_102_mainnet_valid_genesis_passes ... ok
test run_102_print_then_expect_workflow_roundtrip ... ok
test result: ok. 14 passed; 0 failed
```

### 3.3 Regression — Run 101 / T232 / T233 / T237 are bit-for-bit preserved

```
$ cargo test -p qbind-node --test run_101_genesis_authority_tests \
                          --test t232_genesis_mainnet_profile_tests \
                          --test t233_genesis_cli_tests \
                          --test t237_mainnet_launch_profile_tests
test result: ok. 11 passed   (run_101_genesis_authority_tests)
test result: ok.  7 passed   (t232_genesis_mainnet_profile_tests)
test result: ok. 16 passed   (t233_genesis_cli_tests)
test result: ok. 24 passed   (t237_mainnet_launch_profile_tests)
```

### 3.4 Release-binary smoke scenarios

All commands are run against `./target/release/qbind-node` built with `cargo build -p qbind-node --bin qbind-node --release`. Stdout / stderr captures are in this directory.

| # | Scenario                                                                                  | Files                                                                                                  | Exit | Outcome                                                                                                                                                                                                              |
|---|-------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0 | CLI help text snapshot for `--genesis-path`, `--print-genesis-hash`, `--expect-genesis-hash`.| `scenario_0_help_genesis_path.txt`, `scenario_0_help_print_genesis_hash.txt`, `scenario_0_help_expect_genesis_hash.txt` | 0    | `--print-genesis-hash` help explicitly describes canonical Run 101 parsed semantics and the absence of any raw-file-byte fallback. Run 102 update visible to operators.                                              |
| 1 | `--print-genesis-hash --genesis-path genesis_a.json --env mainnet`.                       | `scenario_1_print_hash_genesis_a.{stdout,stderr}.log`                                                  | 0    | stdout: `0xc0bf6b82180bac5e2aa6acb51217fc63ba457862558776ab6a338f80fbc89872`. stderr provenance line confirms canonical Run 101 hash over parsed genesis, env=Mainnet.                                                |
| 2 | Same as #1 but on `genesis_b_authority_only_diff.json` (differs only in `authority.bundle_signing_authority_roots[0].key_fingerprint`). | `scenario_2_print_hash_genesis_b.{stdout,stderr}.log`                                                  | 0    | stdout: `0x623a3c497658446056fa14330d85f08c42a8a34294020a4065acb58a17c6d43c`. **Proves canonical hash is authority-sensitive** — Priority 2 §1 acceptance criterion: "release binary on two genesis files that differ only in authority fields prints two different canonical hashes." |
| 3 | `--print-genesis-hash` on a malformed JSON file.                                          | `scenario_3_print_hash_malformed.{stdout,stderr}.log`                                                  | 1    | stderr: `[run-102] FATAL: --print-genesis-hash failed: [run-102] failed to parse genesis file …: key must be a string at line 1 column 2. Release binary refuses to start. No fallback to defaults.`                  |
| 4 | `--print-genesis-hash --env mainnet` without `--genesis-path`.                            | `scenario_4_print_hash_no_path.{stdout,stderr}.log`                                                    | 1    | stderr: `[run-102] FATAL: --print-genesis-hash requires --genesis-path to be set …`                                                                                                                                  |
| 5 | `--env mainnet --genesis-path genesis_a.json --expect-genesis-hash 0x000…0` (mismatch).   | `scenario_5_mainnet_hash_mismatch.{stdout,stderr}.log`                                                 | 1    | stderr: `[run-102] FATAL: [run-102] canonical genesis hash mismatch on environment Mainnet: expected 0x000…0 actual 0xc0bf6b82…9872`. **Fails before any network/consensus startup.**                                  |
| 6 | `--env mainnet --genesis-path genesis_no_authority.json --expect-genesis-hash <matching canonical hash of the no-authority config>`. | `scenario_6_mainnet_missing_authority.{stdout,stderr}.log`                                             | 1    | stderr: `[run-102] FATAL: [run-102] genesis authority validation failed: genesis authority block is required for environment Mainnet but is missing`. **Even with a matching hash, MainNet refuses on missing authority.** |
| 7 | `--env mainnet --genesis-path genesis_a.json` (missing `--expect-genesis-hash`).          | `scenario_7_mainnet_missing_expected_hash.{stdout,stderr}.log`                                         | 1    | stderr: `[run-102] FATAL: [run-102] expected canonical genesis hash is required for environment Mainnet but was not provided`.                                                                                       |
| 8 | `--env mainnet --genesis-path genesis_a.json --expect-genesis-hash 0xc0bf6b82…9872` (matching). | `scenario_8_mainnet_happy_path.{stdout,stderr}.log`                                                    | 124  | First stderr line is the Run 102 OK log; the *next* lines are `[restore] no --restore-from-snapshot requested; normal startup.`, `[metrics] …`, `[binary] …`. **Proves Run 102 fires before any trust-bundle / network / consensus startup.** Process killed by `timeout 10`. |
| 9 | `--env devnet` (no `--genesis-path`).                                                     | `scenario_9_devnet_embedded.{stdout,stderr}.log`                                                       | 124  | First stderr line: `[run-102] no external --genesis-path configured; canonical boot verification skipped (env=Devnet, embedded-genesis path). MainNet always requires --genesis-path so this branch is unreachable on MainNet.` **DevNet embedded-genesis path is preserved.** |

#### 3.4.1 Ordering proof (Scenario 8 stderr head)

```
[run-102] OK: canonical Run 101 genesis verification passed (env=Mainnet, genesis=…/genesis_a.json, canonical_hash=0xc0bf6b82…9872).
[restore] no --restore-from-snapshot requested; normal startup.
[metrics] Metrics HTTP server disabled (set QBIND_METRICS_HTTP_ADDR=host:port to enable)
[binary] Run 093 consensus storage: state=no-consensus-storage path=<none>
[binary] LocalMesh mode: starting consensus loop. environment=MainNet profile=nonce-only
…
```

`[run-102] OK` precedes every `[restore]`, `[metrics]`, `[binary]`, `[binary-consensus]`, `[snapshot]` line. The Run 102 verifier therefore satisfies the task's required ordering:

```
load genesis → canonicalize/hash → verify expected hash → validate authority
            → only then continue to trust-bundle processing / networking / consensus startup
```

#### 3.4.2 Authority-only diff is reflected in canonical hash (scenarios 1 + 2)

| File                                       | Differs from `genesis_a.json` only in… | Canonical hash (env=Mainnet)                                            |
|--------------------------------------------|----------------------------------------|--------------------------------------------------------------------------|
| `genesis_a.json`                           | (reference)                            | `0xc0bf6b82180bac5e2aa6acb51217fc63ba457862558776ab6a338f80fbc89872`     |
| `genesis_b_authority_only_diff.json`       | `authority.bundle_signing_authority_roots[0].key_fingerprint` (one byte) | `0x623a3c497658446056fa14330d85f08c42a8a34294020a4065acb58a17c6d43c`     |

The two hashes differ in every byte; the canonical hash is authority-sensitive even when no other field changes.

---

## 4. Key security decisions

1. **No fallback.** When `--print-genesis-hash` cannot parse the genesis file, the binary exits non-zero with a typed error. There is no raw-file-byte fallback (which would silently disagree with `verify_boot_time_genesis`).
2. **No source-code production root anchor.** The authority block is read only from the operator-supplied genesis file. No `pqc_transport_root` or `bundle_signing_authority_root` is hard-coded into the release-binary source tree.
3. **Composition with T233, not replacement.** The existing `MainnetConfigError::ExpectedGenesisHashMissing` shield in `validate_mainnet_invariants` still fires when `--profile mainnet` is used and `--expect-genesis-hash` is absent. Run 102 adds the actual canonical hash comparison (which the T233 shield never performed) and adds an additional belt-and-braces fail-closed path for callers that bypass the profile (Scenario 7 — `--env mainnet` without the profile).
4. **Belt-and-braces MainNet `genesis_path` shield.** Even though `GenesisSourceConfig::mainnet_default()` + T185 already refuse MainNet without `--genesis-path`, `run_boot_time_genesis_verification` independently returns `GenesisPathMissing { env: Mainnet }` (covered by `run_102_mainnet_no_genesis_path_rejects`). MainNet cannot reach the `SkippedNoExternalGenesis` branch.
5. **DevNet/TestNet preserved.** When `genesis_source.use_external == false`, the verifier returns `SkippedNoExternalGenesis` with a clear log line. No DevNet or TestNet workflow is broken. Scenario 9 shows the DevNet path still starts.
6. **Map function is byte-equivalent.** `NetworkEnvironment::scope()` and `NetworkEnvironmentPolicy::scope()` must return the same `"DEV"` / `"TST"` / `"MAIN"` strings so the canonical hash domain-separation is identical across the crate boundary. Asserted in `map_environment_is_1to1`.

---

## 5. Evidence references

| What                                                                  | Where                                                                                                                       |
|-----------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| Run 102 module                                                        | `crates/qbind-node/src/pqc_boot_genesis.rs`                                                                                 |
| Run 102 main wiring (print + verify)                                  | `crates/qbind-node/src/main.rs` (block titled "Run 102 — `--print-genesis-hash` operator tooling" and the verifier block) |
| Run 102 help-text update                                              | `crates/qbind-node/src/cli.rs` (`print_genesis_hash` / `expect_genesis_hash` doc comments)                                  |
| Run 102 in-module unit tests (8)                                      | `crates/qbind-node/src/pqc_boot_genesis.rs::tests`                                                                          |
| Run 102 integration tests (14)                                        | `crates/qbind-node/tests/run_102_boot_genesis_wiring_tests.rs`                                                              |
| Release-binary smoke logs (this evidence)                             | `docs/devnet/run_102_genesis_verification_evidence/` (this directory)                                                       |
| Run 101 anchor (canonical hash + verifier helpers)                    | `crates/qbind-ledger/src/genesis.rs` (`compute_canonical_genesis_hash`, `verify_boot_time_genesis`, …)                      |
| Run 101 evidence note that flagged this work                          | `docs/devnet/run_101_genesis_authority_evidence/scenario_5_print_genesis_hash.stderr.log`                                   |
| Spec                                                                  | `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` §17 (Run 101) + Run 102 addendum                                       |
| Runbook                                                               | `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` (Run 102 row + prose note)                                                  |

---

## 6. Contradictions found

None. All Run 101 tests, T232 tests, T233 tests, T237 tests, and `--p2p-trust-bundle-reload-check` integration paths remain green and their behaviour is unchanged. The Run 102 verifier is purely additive on the DevNet/TestNet embedded-genesis path (returns `SkippedNoExternalGenesis` with a log line) and strictly tighter on MainNet (where the T185/T232/T233 shields previously could be bypassed by callers that did not use `--profile mainnet`).

---

## 7. Explicit non-claims

Run 102 does **NOT**:

* implement bundle-signing-key ratification / signature verification (deferred — see §9 below);
* implement signing-key rotation, revocation, or custody;
* implement anti-rollback persistence of the genesis hash beyond the boot-time binding;
* implement governance for the authority block;
* introduce production-binary source-code root anchors;
* introduce a new `/metrics` family;
* introduce a new CLI flag (operator surface = T232/T233 unchanged: `--genesis-path`, `--print-genesis-hash`, `--expect-genesis-hash`);
* introduce a new dependency;
* introduce any peer/network listener, gossip subscription/publisher, admin-API endpoint, filesystem watcher, KMS/HSM custody binding, or `activation_epoch` runtime sourcing;
* introduce or strengthen any `Dummy*` (DummySig / DummyKem / DummyAead) path;
* introduce any classical signatures (the Run 101 authority constants `GENESIS_AUTHORITY_SUITE_ML_DSA_44 == 100` are unchanged);
* reuse a transport root as a bundle-signing authority root (the Run 050 trust-separation invariant is preserved bit-for-bit);
* introduce a `--p2p-trusted-root` fallback when `--p2p-trust-bundle` is absent;
* reference any private-key material on any code path or in this evidence record.

---

## 8. Residual risks

1. **The matched-but-not-ratified property.** Run 102 binds the genesis hash and validates the *schema* of the authority block. It does NOT verify that the authority roots have actually signed anything (no ratification verifier yet). Run 103 must add the bundle-signing-key ratification verifier skeleton (the task's Priority 3, deferred per §9 below).
2. **TestNet remains permissive on expected hash.** `verify_boot_time_genesis` allows `expected_canonical_genesis_hash = None` on TestNet (Run 101 partial-positive policy). This is unchanged in Run 102; tightening it is a separate decision that requires a TestNet operator-impact assessment.
3. **No anti-rollback persistence for the genesis hash itself.** A misconfigured operator could re-launch with a different genesis file across restarts. This is the same residual risk as Run 101 §8.

---

## 9. Run 103 candidate work

The task allows Priority 3 ("smallest minimal bundle-signing-key ratification verifier skeleton") **only after** Priority 1 and Priority 2 are complete and only if it can be added without broad redesign. Priority 1 and Priority 2 are complete (this run). Adding even a skeleton verifier in this run would require:

* a new operator-supplied input (a ratification certificate or signed bootstrap payload),
* a new public canonical preimage for the ratified blob,
* a new typed error variant in `qbind-ledger` for "ratification missing on MainNet",
* a new acceptance/refusal call site in `qbind-node` startup before the trust-bundle path.

Per the task's explicit rule — *"If the skeleton cannot be added cleanly without broad redesign, do not implement it in Run 102. Document it as Run 103 instead."* — Run 102 stops here and Run 103 will introduce the ratification verifier skeleton in a focused follow-up, in the same shape used for Run 101's authority types.

---

## 10. Verdict

**PARTIAL-POSITIVE.** Run 102 closes the two operator-facing release-binary gaps recorded in the Run 101 evidence note: (1) the canonical genesis hash is now actually verified at startup against `--expect-genesis-hash` (no longer just a CLI-presence shield), and (2) `--print-genesis-hash` now prints the canonical Run 101 parsed-genesis hash (no longer raw-file-byte semantics, no longer a no-op that falls through to the consensus loop). MainNet refusal happens before any trust-bundle / network / consensus startup. DevNet/TestNet behavior is preserved. The bundle-signing-key ratification verifier skeleton (Priority 3) is deferred to Run 103 per the task's explicit scope rule.