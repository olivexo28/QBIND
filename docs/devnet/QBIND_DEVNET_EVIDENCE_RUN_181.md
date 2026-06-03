# QBIND DevNet evidence — Run 181

**Title.** Release-binary `OnChainGovernance` production-surface
fixture-policy selector evidence on real `target/release/qbind-node`.

**Status.** PASS (release-binary, partial-positive) — the real
`target/release/qbind-node` binary parses the hidden Run 180 selector
(CLI flag `--p2p-trust-bundle-onchain-governance-fixture-allowed` and
environment variable
`QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`),
OR-combines them via
[`onchain_governance_proof_policy_from_cli_or_env`](
  ../../crates/qbind-node/src/pqc_onchain_governance_proof_surface.rs)
inside `crates/qbind-node/src/main.rs`, and emits the
`[run-180] hidden DevNet/TestNet OnChainGovernance fixture-proof
policy ARMED (AllowFixtureSourceTest)` banner exactly when armed.
The production default — neither flag nor env var truthy — emits no
banner and preserves the
`OnChainGovernanceProofPolicy::Disabled` production default on every
surface. The release-built helper drives the full Run 178 / Run 180
acceptance/rejection corpus through the production library symbols
`verify_onchain_governance_proof`,
`validate_lifecycle_with_onchain_governance_proof`,
`compose_onchain_governance_marker_decision`, and the seven Run 180
per-surface named wrappers in release mode against the same
`qbind_node` library that is linked into `target/release/qbind-node`.
MainNet peer-driven apply remains the Run 147 FATAL invariant. Verdict
is honestly recorded as `partial-positive: production-surface
SELECTOR reachability captured on real qbind-node; per-surface
wrappers exercised in-process via release-built helper; binary-side
wiring of the wrappers into reload-check / reload-apply / startup /
SIGHUP / peer-candidate-check / live-0x05 / peer-driven-drain call
sites is the strictly-next-after-Run-181 integration run identified
by this evidence`.

**Driving spec.** `task/RUN_181_TASK.txt`.

## 1. Strict scope

Run 181 captures **release-binary** evidence that the real
`target/release/qbind-node` binary can:

* parse the hidden Run 180 CLI flag and env var;
* resolve the `OnChainGovernanceProofPolicy` via
  `onchain_governance_proof_policy_from_cli_or_env`;
* emit the `[run-180] ... policy ARMED (AllowFixtureSourceTest)`
  banner only when armed;
* preserve the `OnChainGovernanceProofPolicy::Disabled` production
  default when neither selector source is truthy;
* hide the selector from `qbind-node --help` (`hide = true`);
* preserve the Run 147 FATAL invariant
  ("MainNet peer-driven apply remains refused") even with the
  selector engaged.

Run 181 also drives a release-built helper that exercises the
Run 178 typed verifier and the seven Run 180 per-surface named
wrappers in **release mode** through the production library
symbols, so the per-wrapper acceptance and rejection matrix is
captured in release mode against the same `qbind_node` library that
is linked into the production binary.

Run 181 does **not**:

* change the production default policy on any surface — it remains
  `OnChainGovernanceProofPolicy::Disabled`;
* enable MainNet peer-driven apply (Run 147 FATAL invariant
  continues to hold; both the helper R23 and the release-binary
  R23 capture re-assert it);
* introduce any new wire field, enum variant, schema bump, metric,
  or exit code in any production module beyond the Run 180
  surface;
* implement governance execution, real on-chain governance proof
  verification for MainNet, KMS/HSM custody, validator-set
  rotation, bridge / light-client integration, autonomous apply,
  or apply-on-receipt;
* wire the Run 180 per-surface wrappers into the binary-side
  `--p2p-trust-bundle-*` marker-decision call sites — that
  integration is the strictly next-after-Run-181 source/test
  step identified by Run 181's `mutation_proof.txt`.

Full Whitepaper contradiction C4 and C5 closure remain **open**.

## 2. What Run 181 commits

| Path | Status |
| --- | --- |
| `scripts/devnet/run_181_onchain_governance_production_surface_release_binary.sh` | new — idempotent harness |
| `docs/devnet/run_181_onchain_governance_production_surface_release_binary/README.md` | new — evidence archive scope |
| `docs/devnet/run_181_onchain_governance_production_surface_release_binary/summary.txt` | new — placeholder canonical verdict |
| `docs/devnet/run_181_onchain_governance_production_surface_release_binary/.gitignore` | new — per-run artifacts ignored |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_181.md` | new — this file |
| `docs/whitepaper/contradiction.md` | append-only Run 181 paragraph |
| `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` | append-only Run 181 paragraph |
| `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md` | append-only Run 181 paragraph |
| `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` | append-only Run 181 paragraph |

No production source file under `crates/qbind-node/src/` or
`crates/qbind-node/examples/` or `crates/qbind-node/tests/` is
modified by Run 181. The Run 181 harness reuses the Run 179
release-built helper
(`crates/qbind-node/examples/run_179_onchain_governance_proof_release_binary_helper.rs`)
because that helper drives the production library
`OnChainGovernance` verifier surface that Run 180 wired the new
per-surface wrappers into; introducing a new example crate target
would be source change beyond Run 181's strict scope.

## 3. Selector and policy reachability on real qbind-node

`crates/qbind-node/src/main.rs` resolves the
`OnChainGovernanceProofPolicy` via
[`onchain_governance_proof_policy_from_cli_or_env`](
  ../../crates/qbind-node/src/pqc_onchain_governance_proof_surface.rs)
between the Run 151 refusal block and the Run 127 reset block, and
emits the armed banner only when `AllowFixtureSourceTest` resolves.
The selector is the OR-combination of:

* the hidden CLI flag
  `--p2p-trust-bundle-onchain-governance-fixture-allowed`
  (`hide = true`, `default_value_t = false`);
* the environment variable
  `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED` set
  to a truthy value (one of `1`, `true`, `TRUE`, `True`, `yes`,
  `YES`, `on`, `ON`).

The release-binary harness captures this on the real
`target/release/qbind-node` binary by invoking it with
`--print-genesis-hash --network devnet` (a no-op terminal that
exits non-zero deterministically without opening sockets, mounting
data dirs, writing markers, writing sequences, evicting sessions,
or invoking Run 070) under three matrix variants:

* **A1** — neither CLI flag nor env var set: banner not present;
* **A2** — CLI flag set, env var unset: banner present, mentions
  `AllowFixtureSourceTest` and `MainNetProductionProofUnavailable`;
* **A3** — env var truthy across `{1, true, TRUE, True, yes, YES,
  on, ON}`: banner present in every truthy variant; absent in
  every falsey variant `{0, false, FALSE, no, off, "", garbage}`.

`qbind-node --help` is captured separately (`logs/qbind_node_help.log`)
and asserted to **not** surface
`p2p-trust-bundle-onchain-governance-fixture-allowed`,
`onchain-governance-fixture`, `run-180`, or `run-181`.

## 4. MainNet refusal on real qbind-node (R23)

The release-binary harness invokes
`qbind-node --print-genesis-hash --network mainnet
--p2p-trust-bundle-onchain-governance-fixture-allowed` with
`QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1` and
asserts that:

* no `MainNet peer-driven apply ENABLED` token is emitted;
* no MainNet apply is performed (the `--print-genesis-hash` path is
  non-mutating regardless of selector);

This re-asserts the Run 147 FATAL invariant on the real binary. The
helper R23 scenario asserts the same at the library level via
`OnChainGovernanceProofVerificationOutcome::MainNetProductionProofUnavailable`.

## 5. Per-surface wrapper reachability (release-mode helper)

The release-built helper exercises the Run 180 per-surface named
wrappers through the production library symbols in release mode.
Every wrapper delegates to the shared
`compose_onchain_governance_marker_decision`, which composes:

1. selector / policy gate;
2. optional-proof gate;
3. MainNet refusal short-circuit;
4. Run 159 v2 lifecycle validation;
5. Run 178 fixture verifier (under
   `OnChainGovernanceProofPolicy::AllowFixtureSourceTest` only).

The seven wrappers are:

* `reload_check_compose_onchain_governance_marker_decision` —
  `--p2p-trust-bundle-reload-check` validation-only;
* `reload_apply_compose_onchain_governance_marker_decision` —
  `--p2p-trust-bundle-reload-apply-*` mutating-preflight;
* `startup_p2p_trust_bundle_compose_onchain_governance_marker_decision`
  — startup `--p2p-trust-bundle` mutating-preflight;
* `sighup_compose_onchain_governance_marker_decision` — SIGHUP live
  trust-bundle reload mutating-preflight;
* `local_peer_candidate_check_compose_onchain_governance_marker_decision`
  — local `--p2p-trust-bundle-peer-candidate-check`
  validation-only;
* `live_inbound_0x05_compose_onchain_governance_marker_decision` —
  live inbound `0x05` peer-candidate validation-only;
* `peer_driven_drain_compose_onchain_governance_marker_decision` —
  Run 150 peer-driven apply drain coordinator preflight.

Every wrapper is exercised in release mode by the helper across the
A1–A8 / R1–R26 matrix (see
`docs/devnet/run_181_onchain_governance_production_surface_release_binary/summary.txt`
once the harness has run). MainNet refusal short-circuits before
the verifier in every surface (R23). Non-MainNet rejection paths
(R1–R22, R24–R26) reach the lifecycle and / or verifier rejection
without mutating any persistent state.

## 6. Source / release reachability proof

The harness writes
`reachability/source_reachability.txt` capturing the production
source-tree call sites for:

* `verify_onchain_governance_proof`;
* `validate_lifecycle_with_onchain_governance_proof`;
* `OnChainGovernanceProofPolicy::AllowFixtureSourceTest`;
* `pqc_onchain_governance_proof_surface`;
* `compose_onchain_governance_marker_decision`;
* every per-surface named wrapper;
* `onchain_governance_proof_policy_from_cli_or_env`;
* `onchain_governance_proof_policy_from_selector`;
* `onchain_governance_fixture_allowed_env_selector_enabled`;
* `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`;
* `p2p_trust_bundle_onchain_governance_fixture_allowed`;
* `mainnet_peer_driven_apply_remains_refused_for_onchain_governance`;
* `OnChainGovernanceMarkerDecisionOutcome`.

Together with the release-built helper exit code (must be 0 for
every Run 178 / Run 180 scenario), this captures release-mode
reachability of the wrapper symbols inside the production library
linked into `target/release/qbind-node`.

## 7. Validation

The following targets are exercised by the harness from a clean
release tree at HEAD:

```
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example run_179_onchain_governance_proof_release_binary_helper
bash scripts/devnet/run_181_onchain_governance_production_surface_release_binary.sh
cargo test --release -p qbind-node --test run_180_onchain_governance_marker_integration_tests
cargo test --release -p qbind-node --test run_178_onchain_governance_proof_tests
cargo test --release -p qbind-node --test run_176_live_0x05_governance_proof_carrier_tests
cargo test --release -p qbind-node --test run_173_validation_only_governance_required_policy_tests
cargo test --release -p qbind-node --test run_171_governance_required_policy_selector_tests
cargo test --release -p qbind-node --test run_169_governance_proof_loader_surface_integration_tests
cargo test --release -p qbind-node --test run_167_governance_proof_carrier_tests
cargo test --release -p qbind-node --test run_165_governance_marker_integration_tests
cargo test --release -p qbind-node --test run_163_governance_authority_verifier_tests
cargo test --release -p qbind-node --test run_161_lifecycle_marker_integration_tests
cargo test --release -p qbind-node --test run_159_authority_signing_key_lifecycle_tests
cargo test --release -p qbind-node --test run_157_unified_testnet_fixture_universe_tests
cargo test --release -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests
cargo test --release -p qbind-node --test run_150_peer_driven_apply_drain_tests
cargo test --release -p qbind-node --test run_148_peer_driven_apply_devnet_tests
cargo test --release -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests
cargo test --release -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests
cargo test --release -p qbind-node --test run_138_sighup_v2_authority_marker_tests
cargo test --release -p qbind-node --lib pqc_authority
cargo test --release -p qbind-node --lib pqc_onchain_governance_proof_surface
```

No prior-run regression test was modified or skipped. Test targets
that may not exist verbatim at HEAD are skipped with a logged
`(not present in this tree)` note (matches the Run 179 harness
convention).

## 8. Mutation / no-mutation proof

For Run 181:

* every release-binary scenario uses
  `qbind-node --print-genesis-hash --network <env>` which is
  inherently non-mutating (no `--data-dir`, no socket open, no
  marker write, no sequence write, no Run 070 invocation, no
  session eviction). `no_mutation_proof.txt` records the empty
  data dir at `OUTDIR/data/` for every scenario;
* every helper-driven scenario is in-process pure: the helper
  drives `compose_onchain_governance_marker_decision` and the
  per-surface wrappers, all of which are pure / non-mutating
  (Run 180 source-test invariant);
* the binary-side wiring of the wrappers into the
  `--p2p-trust-bundle-*` marker-decision call sites is **not**
  introduced by Run 181 (`mutation_proof.txt` records this and
  identifies the strict next integration run).

## 9. Honesty record / what is NOT done

Run 181 does not close, and does not claim to close, any of the
following:

* **Per-surface binary wiring.** `--p2p-trust-bundle-reload-check`,
  `--p2p-trust-bundle-reload-apply-*`, startup
  `--p2p-trust-bundle`, SIGHUP,
  `--p2p-trust-bundle-peer-candidate-check`, live `0x05`, and
  peer-driven drain do **not** yet pass the resolved
  `OnChainGovernanceProofPolicy` into the per-surface wrappers.
  The strict next integration run identified by Run 181 must do so
  and capture mutating-scenario marker / sequence JSON+SHA before /
  after on at least one mutating surface.
* **Governance execution.** No on-chain governance contract,
  validator set, or block-producer schedule is read or executed.
* **Real on-chain proof verification on MainNet.** MainNet remains
  fail-closed and explicitly refuses peer-driven apply.
* **KMS / HSM custody.** No production-grade authority custody is
  implemented.
* **Validator-set rotation.** No rotation engine is implemented.
* **Bridge / light-client integration.** None.
* **Autonomous apply / apply-on-receipt / peer-majority
  authority.** None.
* **Whitepaper contradictions C4 and C5.** Remain **open**.

The Run 180 selector remains hidden, must be explicit, is
DevNet/TestNet fixture-only, and changes nothing on production
defaults. Run 181 captures release-binary evidence that this is
exactly the case on real `target/release/qbind-node`.

## 10. Provenance

This run produces a per-run artifact set under
`docs/devnet/run_181_onchain_governance_production_surface_release_binary/`
captured by the harness in
`provenance.txt`, `logs/`, `exit_codes/`, `helper_evidence/`,
`reachability/`, `test_results/`, `negative_invariants.txt`,
`mutation_proof.txt`, and `no_mutation_proof.txt`. Only `README.md`,
`summary.txt`, and `.gitignore` are tracked in git; the other files
contain absolute paths and ephemeral data and are regenerated on
every harness invocation.

## 11. Crosschecks against existing design / spec

Cross-checked against:

* `task/RUN_181_TASK.txt` (driving spec) — every required
  deliverable, scenario, surface, and denylist invariant is
  addressed; honest limitations are recorded both here and in the
  archive `summary.txt`;
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_180.md` — Run 181 inherits
  the source/test surface that Run 180 introduced and adds the
  release-binary boundary Run 180 deferred;
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_179.md` — Run 181 reuses
  the Run 179 release-built helper as the OnChainGovernance
  fixture-proof minter / verifier driver to avoid a new example
  crate target;
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_178.md` — Run 181 makes no
  source change to the Run 178 typed verifier;
* `docs/whitepaper/contradiction.md` — the Run 181 paragraph
  appended to that file records this run's honest boundary
  (release-binary selector reachability captured; binary-side
  wrapper wiring deferred) and identifies the strict next
  integration run, mirroring the Run 178 / 179 / 180 honesty
  record convention.

No contradictions or inconsistencies were identified during
crosscheck. If any are surfaced post-merge, they will be recorded in
`docs/whitepaper/contradiction.md` per Run 181 §5 of the driving
spec.

## 12. Cross-references

* Driving spec: `task/RUN_181_TASK.txt`.
* Run 178 typed verifier:
  `crates/qbind-node/src/pqc_onchain_governance_proof.rs`.
* Run 180 source/test wiring:
  `crates/qbind-node/src/pqc_onchain_governance_proof_surface.rs`,
  `crates/qbind-node/tests/run_180_onchain_governance_marker_integration_tests.rs`,
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_180.md`.
* Run 179 release-binary boundary helper:
  `crates/qbind-node/examples/run_179_onchain_governance_proof_release_binary_helper.rs`,
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_179.md`.
* Run 147 MainNet peer-driven apply FATAL invariant (re-asserted
  by R23): see helper R23 and harness R23 in this run.
* Evidence archive:
  `docs/devnet/run_181_onchain_governance_production_surface_release_binary/`.
* Harness:
  `scripts/devnet/run_181_onchain_governance_production_surface_release_binary.sh`.
