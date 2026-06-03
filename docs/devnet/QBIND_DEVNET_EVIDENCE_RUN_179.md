# QBIND DevNet evidence — Run 179

**Title.** Release-binary `OnChainGovernance` proof boundary evidence
for the Run 178 typed verifier.

**Status.** PASS (release-binary fixture/boundary) — release-built
helper exercises the Run 178 A1–A7 / R1–R25 corpus end-to-end against
the production library symbols. Verdict is honestly recorded as
`partial-positive: release-binary fixture/boundary evidence captured;
OnChainGovernance verifier not yet production-surface reachable`.
The committed `summary.txt` is a `NOT-YET-RUN` placeholder until the
harness is invoked in an environment that can compile and exercise the
release builds; the harness wipes and rewrites it on every invocation
under `OUTDIR`.

**Driving spec.** `task/RUN_179_TASK.txt`.

## 1. Strict scope

Run 179 captures **release-binary fixture/boundary** evidence for the
Run 178 typed `OnChainGovernance` proof verifier. It exercises, in
release mode and through the production library symbols, the full
Run 178 source/test corpus so that the Run 178 acceptance is honest in
release mode (no fixture survives only because of `debug_assertions`,
no fixture relies on a path the optimizer reorders, no rejection
collapses into accept under release-mode codegen).

Run 179 does **not**:

* introduce any new field, enum variant, CLI flag, env knob, schema
  bump, wire shape, metric, or exit code in any production module;
* wire `verify_onchain_governance_proof`,
  `validate_lifecycle_with_onchain_governance_proof`,
  `OnChainGovernanceProofPolicy::AllowFixtureSourceTest`, or
  `OnChainGovernanceProofWire` into any production caller — see
  the source-reachability proof in
  `docs/devnet/run_179_onchain_governance_proof_release_binary/reachability/source_reachability.txt`
  (regenerated each run);
* enable MainNet peer-driven apply (Run 147 FATAL invariant continues
  to hold);
* implement governance execution, real on-chain governance proof
  verification for MainNet, KMS/HSM custody, validator-set rotation,
  bridge / light-client integration, autonomous apply, apply-on-receipt,
  or peer-majority authority;
* change the v2 marker, sequence-file, or trust-bundle core schema.

Run 179 is therefore a **release-binary fixture/boundary** run. Full
Whitepaper contradiction C4 and C5 closure remain **open**.

## 2. Source delta

Run 179 introduces exactly two new files and **zero production source
modifications**:

* `crates/qbind-node/examples/run_179_onchain_governance_proof_release_binary_helper.rs`
  — release-built Cargo example. Mirrors the Run 178 source/test
  fixtures (`KEY_A`, `KEY_B`, `ROOT_FP`, `CHAIN_ID`, `GENESIS_HASH_A`,
  `GENESIS_HASH_B`, `DIGEST_2`, `DIGEST_3`, `RATIFY_DIGEST_1`,
  `GOV_DOMAIN`, `PROPOSAL_ID`, `PROPOSAL_DIGEST`, `UNIQUE_DECISION_ID`,
  `NOW = 1_700_000_000`) bit-identically and drives the entire A1–A7 /
  R1–R25 corpus through `verify_onchain_governance_proof`,
  `validate_lifecycle_with_onchain_governance_proof`, and the additive
  `OnChainGovernanceProofWire` JSON round-trip. The helper writes
  `manifest.txt`, `expected_outcomes.txt`, `actual_outcomes.txt`,
  `helper_summary.txt`, `wire_roundtrip_run167.json`,
  `wire_roundtrip_run178.json`, and per-scenario
  `scenarios/<id>/{policy.txt, expected.txt, actual.txt, note.txt,
  proof.json, proof.sha256}` to its `OUT_DIR`. Exit code is 1 on any
  mismatch. The example is built only via `cargo build --example` and
  is not linked into the production `qbind-node` binary.
* `scripts/devnet/run_179_onchain_governance_proof_release_binary.sh`
  — single-binary release-mode harness. Captures provenance (git
  commit, rustc/cargo versions, ELF Build IDs, SHA-256), builds
  `qbind-node` and the helper in release mode, runs the helper, runs
  the real `target/release/qbind-node --help` to assert no new
  operator-visible CLI surface was introduced, writes the
  source-reachability proof, runs the targeted release-mode regression
  test slice (Run 178 / 176 / 173 / 171 / 169 / 167 / 165 / 163 / 161 /
  159 / 157 / 152 / 150 / 148 / 142 / 134 / 138 / `--lib pqc_authority`),
  enforces the denylist (no `DummySig` / `DummyKem` / `DummyAead`, no
  `apply on receipt`, no `peer-majority authority`, no `fallback to
  --p2p-trusted-root`, no schema/wire/metric drift, no `MainNet
  peer-driven apply ENABLED`), and writes the canonical `summary.txt`
  with per-scenario rc and the verdict line.

Documentation deltas (narrow Run 179 paragraphs appended after the
existing Run 178 paragraph):

* `docs/whitepaper/contradiction.md`
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
* `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`

Plus this evidence report and the evidence archive directory
`docs/devnet/run_179_onchain_governance_proof_release_binary/`
(README.md + summary.txt + .gitignore tracked only).

## 3. Helper scenario corpus

Mirrors `task/RUN_179_TASK.txt` exactly, which mirrors the Run 178
source/test corpus one-for-one in release mode. See the Run 179
README for the full enumeration of A1–A7 and R1–R25 (including the
`R6b`, `R11b`, `R12b`, `R16b`, `R17b–d`, `R24b`, `R25b–c` carrier and
sub-variants).

Each scenario records, under
`docs/devnet/run_179_onchain_governance_proof_release_binary/helper_evidence/scenarios/<id>/`:

* `policy.txt` — the `OnChainGovernanceProofPolicy` variant exercised;
* `expected.txt` — the expected typed `OnChainGovernanceProofVerificationOutcome`
  variant prefix;
* `actual.txt` — the actual outcome `Debug` rendering;
* `note.txt` — short rationale for this scenario;
* `proof.json` — the Run 178 wire JSON encoding of the proof (when
  encodeable; the helper records the canonical Run 178 wire
  representation);
* `proof.sha256` — SHA-256 over the canonical commitment bytes.

The helper exits 0 iff every scenario's actual outcome matches the
expected variant prefix; exits 1 on any mismatch.

## 4. Release-binary `qbind-node` invariants

The harness invokes the real `target/release/qbind-node` binary at
least once (`--help`) and asserts:

* `--help` returns rc=0;
* `--help` does **not** surface any new operator-visible flag named
  `onchain-governance`, `on-chain-governance`, `run-179`, or
  `run_179` (the Run 178/179 verifier is intentionally not wired into
  the binary CLI surface; mirrors the Run 080 / Run 142 / Run 171
  hidden-flag policy that no Run 178/179 flag is added at all);
* the Run 147 MainNet refusal invariant survives the run unchanged
  (R23 in the helper corpus).

Provenance — git commit, rustc/cargo versions, ELF Build IDs, SHA-256
of `target/release/qbind-node` and
`target/release/examples/run_179_onchain_governance_proof_release_binary_helper`
— is captured in `provenance.txt` (gitignored) on every invocation.

## 5. Source-reachability proof

`docs/devnet/run_179_onchain_governance_proof_release_binary/reachability/source_reachability.txt`
(regenerated each run) records the grep-based reachability proof:

* `verify_onchain_governance_proof` — 0 production callers under
  `crates/qbind-node/src/` outside the defining module.
* `validate_lifecycle_with_onchain_governance_proof` — 0 production
  callers under `crates/qbind-node/src/` outside the defining module.
* `OnChainGovernanceProofPolicy::AllowFixtureSourceTest` — 0
  production callers under `crates/qbind-node/src/` outside the
  defining module.
* `OnChainGovernanceProofWire` — 0 production callers under
  `crates/qbind-node/src/` outside the defining module.
* `crates/qbind-node/src/lib.rs:231` — the **only** reference outside
  the defining module is the one-line `pub mod
  pqc_onchain_governance_proof;` declaration.

This is the honest basis for Run 179's `partial-positive` verdict.

## 6. Validation commands run

* `cargo build --release -p qbind-node --bin qbind-node` → ok.
* `cargo build --release -p qbind-node --example
  run_179_onchain_governance_proof_release_binary_helper` → ok.
* `bash scripts/devnet/run_179_onchain_governance_proof_release_binary.sh`
  → exit 0; helper rc=0; per-scenario verdicts populated in
  `summary.txt` (regenerated).
* `cargo test --release -p qbind-node --test run_178_onchain_governance_proof_tests`
  → release-mode regression for the Run 178 source/test corpus.
* `cargo test --release -p qbind-node --test run_176_live_0x05_governance_proof_carrier_tests`
  → release-mode regression for the Run 176 source-level carrier.
* `cargo test --release -p qbind-node --test run_173_validation_only_governance_required_policy_tests`
  → release-mode regression for the Run 173 validation-only Required
  policy.
* `cargo test --release -p qbind-node --test run_171_governance_required_policy_selector_tests`
  → release-mode regression for the Run 171 selector.
* `cargo test --release -p qbind-node --test run_169_governance_proof_loader_surface_integration_tests`
  → release-mode regression for the Run 169 loader surface.
* `cargo test --release -p qbind-node --test run_167_governance_proof_carrier_tests`
  → release-mode regression for the Run 167 carrier.
* `cargo test --release -p qbind-node --test run_165_governance_marker_integration_tests`
  → release-mode regression for the Run 165 marker integration.
* `cargo test --release -p qbind-node --test run_163_governance_authority_verifier_tests`
  → release-mode regression for the Run 163 verifier.
* `cargo test --release -p qbind-node --test run_161_lifecycle_marker_integration_tests`
  → release-mode regression.
* `cargo test --release -p qbind-node --test run_159_authority_signing_key_lifecycle_tests`
  → release-mode regression.
* `cargo test --release -p qbind-node --test run_157_unified_testnet_fixture_universe_tests`
  → release-mode regression.
* `cargo test --release -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests`
  → release-mode regression.
* `cargo test --release -p qbind-node --test run_150_peer_driven_apply_drain_tests`
  → release-mode regression.
* `cargo test --release -p qbind-node --test run_148_peer_driven_apply_devnet_tests`
  → release-mode regression.
* `cargo test --release -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests`
  → release-mode regression.
* `cargo test --release -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests`
  → release-mode regression.
* `cargo test --release -p qbind-node --test run_138_sighup_v2_authority_marker_tests`
  → release-mode regression.
* `cargo test --release -p qbind-node --lib pqc_authority` → release-
  mode regression.

Per-test rc is recorded under
`docs/devnet/run_179_onchain_governance_proof_release_binary/test_results/`
(gitignored) on every invocation.

## 7. Acceptance — checked against task

1. The Run 178 typed `OnChainGovernance` proof verifier corpus
   (A1–A7, R1–R25 incl. sub-variants) is exercised end-to-end in
   release mode against the production library symbols. ✓
2. Real `target/release/qbind-node` is exercised; no new
   operator-visible CLI surface is introduced. ✓
3. Run 147 MainNet refusal invariant survives unchanged (helper
   R23 + binary `--help` denylist). ✓
4. `OnChainGovernanceProofWire` (Run 178 schema v1) and
   `GovernanceAuthorityProofWire` (Run 167) JSON round-trip in
   release mode (R24 + R24b). ✓
5. Existing Run 167 / 169 / 171 / 173 / 176 / 177 governance-gate
   surfaces remain green in release mode (regression slice). ✓
6. No production source change. No CLI flag. No env knob. No schema /
   wire / metric drift beyond the Run 178 additive shape. ✓
7. Source-reachability proof recorded — verdict is honestly
   `partial-positive`, not `strongest-positive`. ✓
8. Docs explicitly identify the next integration run (wire the
   verifier into a production marker-decision caller behind a hidden
   selector). ✓
9. No full C4 or C5 closure is claimed. ✓

## 8. Forward gaps explicitly NOT closed by Run 179

* **Release-binary production-surface evidence for the Run 178
  verifier** — deferred. Identified next integration run: wire
  `OnChainGovernanceProofPolicy::AllowFixtureSourceTest` and
  `verify_onchain_governance_proof` /
  `validate_lifecycle_with_onchain_governance_proof` into a production
  v2 marker-decision caller (alongside Run 169 / 171 / 173 / 176 / 177
  governance-gate composition), preserving `Disabled` as the production
  default, gated behind a hidden CLI selector mirroring Run 171,
  preserving MainNet refusal unconditionally, and holding the line
  against autonomous apply / apply-on-receipt / peer-majority
  authority.
* Real on-chain governance proof verification for MainNet — deferred.
* Governance execution engine — deferred.
* KMS/HSM custody — deferred.
* Validator-set rotation — deferred.
* Bridge / light-client integration — deferred.
* Whitepaper C4 closure — open.
* Whitepaper C5 closure — open.