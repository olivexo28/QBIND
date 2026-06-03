# QBIND DevNet evidence — Run 180

**Title.** Source-level wiring of the Run 178 typed `OnChainGovernance`
proof verifier into production marker-decision composition behind a
hidden DevNet/TestNet-only `AllowFixtureSourceTest` selector.

**Status.** PASS (source/test only) — the Run 178 typed verifier is
now reachable at the production marker-decision composition layer
through a single shared composed helper and seven named per-surface
wrappers. The `AllowFixtureSourceTest` policy is selectable only via
a hidden CLI flag (`--p2p-trust-bundle-onchain-governance-fixture-allowed`)
or an explicit environment variable
(`QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`). The
production default remains `OnChainGovernanceProofPolicy::Disabled`
on every surface; MainNet peer-driven apply remains the Run 147 FATAL
invariant. Verdict is honestly recorded as `partial-positive:
source/test reachability captured; OnChainGovernance verifier not yet
exercised through the release binary harness — deferred to Run 181`.

**Driving spec.** `task/RUN_180_TASK.txt`.

## 1. Strict scope

Run 180 wires the Run 178 typed `OnChainGovernance` proof verifier
into the production marker-decision composition path, in source and
test only, so that the seven runtime surfaces that compose marker
decisions (reload-check, reload-apply, startup `--p2p-trust-bundle`,
SIGHUP, peer-candidate-check, live `0x05`, peer-driven drain) call
the typed verifier through one shared composed helper plus per-surface
named wrappers.

Run 180 does **not**:

* change the production default policy on any surface — it remains
  `OnChainGovernanceProofPolicy::Disabled`;
* enable MainNet peer-driven apply (Run 147 FATAL invariant continues
  to hold; Run 180 wires an explicit `MainNetRefused` short-circuit
  before any verifier work and re-asserts it via test);
* introduce any new wire field, enum variant, schema bump, metric, or
  exit code in any production module beyond a single hidden CLI flag
  and a single typed marker-decision outcome enum;
* implement governance execution, real on-chain governance proof
  verification for MainNet, KMS/HSM custody, validator-set rotation,
  bridge / light-client integration, autonomous apply, or
  apply-on-receipt;
* exercise the wiring through the release binary harness — that is
  Run 181's scope.

Run 180 is therefore a **source/test wiring** run. Full Whitepaper
contradiction C4 and C5 closure remain **open**.

## 2. Source delta

The source delta consists of one new library module, three small
edits to existing files, and one new integration test file:

* `crates/qbind-node/src/pqc_onchain_governance_proof_surface.rs`
  (new) — selector helpers, the typed
  `OnChainGovernanceMarkerDecisionOutcome` enum
  (`Accepted` / `PolicyDisabled` / `NoOnChainGovernanceProofSupplied` /
  `MainNetRefused` / `Rejected`), the shared composed helper
  `compose_onchain_governance_marker_decision`, the seven per-surface
  named wrappers
  (`reload_check_compose_onchain_governance_marker_decision`,
  `reload_apply_compose_onchain_governance_marker_decision`,
  `startup_p2p_trust_bundle_compose_onchain_governance_marker_decision`,
  `sighup_compose_onchain_governance_marker_decision`,
  `local_peer_candidate_check_compose_onchain_governance_marker_decision`,
  `live_inbound_0x05_compose_onchain_governance_marker_decision`,
  `peer_driven_drain_compose_onchain_governance_marker_decision`), and
  the MainNet-refusal helper
  `mainnet_peer_driven_apply_remains_refused_for_onchain_governance`.
* `crates/qbind-node/src/lib.rs` — registers
  `pub mod pqc_onchain_governance_proof_surface;` with a Run 180
  doc-comment.
* `crates/qbind-node/src/cli.rs` — adds the hidden boolean CLI flag
  `--p2p-trust-bundle-onchain-governance-fixture-allowed`
  (`hide = true`, `default_value_t = false`).
* `crates/qbind-node/src/main.rs` — captures the policy via
  `onchain_governance_proof_policy_from_cli_or_env(..)` once during
  startup (between the Run 151 refusal block and the Run 127 reset
  block) and emits a banner only when armed; the production default
  remains `Disabled`.
* `crates/qbind-node/tests/run_180_onchain_governance_marker_integration_tests.rs`
  (new) — A1–A9 + R1–R27 acceptance/rejection matrix.

## 3. Selector and policy capture

The selector is a single boolean. It is enabled when **either**:

* the hidden CLI flag
  `--p2p-trust-bundle-onchain-governance-fixture-allowed` is supplied,
  **or**
* the environment variable
  `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED` is set
  to a truthy value (one of `1`, `true`, `TRUE`, `True`, `yes`, `YES`,
  `on`, `ON`).

When neither is supplied, the policy resolves to
`OnChainGovernanceProofPolicy::Disabled` and every per-surface wrapper
short-circuits with `OnChainGovernanceMarkerDecisionOutcome::PolicyDisabled`
before any verifier work runs. This is the production default and is
asserted by tests R1, R2, and A1.

## 4. MainNet refusal

The composed helper short-circuits with
`OnChainGovernanceMarkerDecisionOutcome::MainNetRefused` whenever any
of the proof, the trust-bundle environment domain, or the candidate
v2 record advertises `TrustBundleEnvironment::Mainnet`, regardless of
whether `AllowFixtureSourceTest` is armed. The Run 147 FATAL invariant
("MainNet peer-driven apply is unsupported and fail-closed") therefore
continues to hold even with the selector engaged. This is asserted by
test R3.

## 5. Composition order

`compose_onchain_governance_marker_decision` short-circuits in the
following order:

1. `policy == Disabled` → `PolicyDisabled`;
2. `proof.is_none()` → `NoOnChainGovernanceProofSupplied`;
3. any of (proof / trust_domain / candidate) advertises Mainnet →
   `MainNetRefused`;
4. delegate to
   `validate_lifecycle_with_onchain_governance_proof(..)` and map
   `Accept` → `Accepted`, `Reject(..)` → `Rejected(..)`.

This order is asserted by tests A9 (no-proof short-circuits),
R3 (MainNet short-circuits even with proof), and the ordering
covered transitively across R1–R27.

## 6. Tests

Run 180 ships two test surfaces:

* **In-module unit tests** (`#[cfg(test)] mod tests` inside
  `pqc_onchain_governance_proof_surface.rs`) — 4 tests covering the
  selector helpers and the policy-from-cli-or-env resolver in isolation.
* **Integration tests**
  (`tests/run_180_onchain_governance_marker_integration_tests.rs`) —
  40 tests covering A1–A9 acceptance, A2 selector parsing, A3–A8c
  per-surface acceptance under `AllowFixtureSourceTest` + DevNet/TestNet
  + a fixture proof, and R1–R27 rejection (default policy disabled,
  selector unset, MainNet refusal, environment / chain / genesis /
  authority root / governance domain / proposal id / proposal digest /
  candidate digest / lifecycle action / freshness / quorum / threshold /
  invalid proof bytes / unsupported proof suite / malformed proof
  rejection paths, plus the local-operator-config-alone /
  peer-majority-alone / proof-valid-but-lifecycle-invalid /
  lifecycle-valid-but-proof-invalid / non-mutating determinism /
  pure preflight / live-0x05 short-circuit cases).

Test environment serialization. Tests that touch
`QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED` use the
Run 171 `EnvGuard` + `OnceLock<Mutex<()>>` pattern to serialize
process-wide environment access against the cargo parallel test
runner.

## 7. Validation

The following targets were run from a clean tree at HEAD and all
passed:

```
cargo build -p qbind-node --lib
cargo build -p qbind-node --bin qbind-node
cargo test  -p qbind-node --test run_180_onchain_governance_marker_integration_tests
cargo test  -p qbind-node --test run_178_onchain_governance_proof_tests
cargo test  -p qbind-node --test run_176_live_0x05_governance_proof_carrier_tests
cargo test  -p qbind-node --test run_173_validation_only_governance_required_policy_tests
cargo test  -p qbind-node --test run_171_governance_required_policy_selector_tests
cargo test  -p qbind-node --test run_169_governance_proof_loader_surface_integration_tests
cargo test  -p qbind-node --test run_167_governance_proof_carrier_tests
cargo test  -p qbind-node --test run_165_governance_marker_integration_tests
cargo test  -p qbind-node --test run_163_governance_authority_verifier_tests
cargo test  -p qbind-node --test run_161_lifecycle_marker_integration_tests
cargo test  -p qbind-node --test run_159_authority_signing_key_lifecycle_tests
cargo test  -p qbind-node --lib pqc_authority
```

No prior-run regression test was modified or skipped.

## 8. Honesty record / what is NOT done

Run 180 does not close, and does not claim to close, any of the
following:

* **Release binary harness.** No release-binary harness exercises the
  Run 180 wiring. That is Run 181's scope. Until Run 181 lands, the
  source-reachability claim is honest at the source/test layer only.
* **Governance execution.** No on-chain governance contract,
  validator set, or block-producer schedule is read or executed.
* **Real on-chain proof verification on MainNet.** MainNet remains
  fail-closed and explicitly refuses peer-driven apply.
* **KMS / HSM custody.** No production-grade authority custody is
  implemented.
* **Validator-set rotation.** No rotation engine is implemented.
* **Bridge / light client integration.** None.
* **Autonomous apply / apply-on-receipt / peer-majority authority.**
  None.
* **Whitepaper contradictions C4 and C5.** Remain **open**.

The Run 180 selector is hidden, must be explicit, is DevNet/TestNet
fixture-only, and changes nothing on production defaults. It is a
gated wiring step, not a feature flip.

## 9. Provenance

This run produces no `docs/devnet/run_180_*/` evidence directory
because there is no release-binary harness and therefore no per-run
generated artifact set to capture. All Run 180 evidence is contained
in this Markdown document and the source/test files listed in §2.

## 10. Cross-references

* Driving spec: `task/RUN_180_TASK.txt`.
* Run 178 typed verifier:
  `crates/qbind-node/src/pqc_onchain_governance_proof.rs`.
* Run 179 release-binary boundary evidence (verifier-only, pre-wiring):
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_179.md`.
* Run 171 selector pattern (reference):
  `crates/qbind-node/src/pqc_governance_proof_surface.rs`.
* Run 147 MainNet peer-driven apply FATAL invariant (re-asserted):
  see test R3 in
  `tests/run_180_onchain_governance_marker_integration_tests.rs`.
