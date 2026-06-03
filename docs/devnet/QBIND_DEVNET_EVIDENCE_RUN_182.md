# QBIND DevNet evidence — Run 182

**Title.** Source/test production call-site wiring for the Run 178 typed
`OnChainGovernance` fixture-proof verifier behind the hidden Run 180
`OnChainGovernanceProofPolicy::AllowFixtureSourceTest` selector.

**Status.** PASS (source/test, partial-positive) — every production v2
marker-decision call site (`--p2p-trust-bundle-reload-check`,
`--p2p-trust-bundle-reload-apply`, startup `--p2p-trust-bundle`, SIGHUP
live trust-bundle reload, local `--p2p-trust-bundle-peer-candidate-check`,
live inbound `0x05`, and the Run 150 peer-driven apply drain coordinator
in `ProductionV2MarkerCoordinator`) now invokes the matching Run 180
per-surface preflight wrapper through a named call-site entry exposed
by the new
[`pqc_onchain_governance_callsite_wiring`](
  ../../crates/qbind-node/src/pqc_onchain_governance_callsite_wiring.rs)
module. The wiring is purely additive at the production library
surface: it adds zero schema bumps, zero new wire fields, and zero new
metrics. The default policy on every surface remains
`OnChainGovernanceProofPolicy::Disabled`; the hidden DevNet/TestNet
fixture-only `AllowFixtureSourceTest` policy is only reachable when
the operator sets either the hidden CLI flag
`--p2p-trust-bundle-onchain-governance-fixture-allowed` or the env var
`QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`. MainNet
peer-driven apply remains refused (Run 147/148/152 FATAL invariant);
the peer-driven-drain wiring entry layers a surface-level MainNet
refusal **before** invoking the underlying verifier so the refusal
holds even with a fully-valid DevNet fixture proof in hand. Real
on-chain governance proof verification, governance execution, KMS/HSM
custody, validator-set rotation, bridge / light-client integration,
autonomous apply, and apply-on-receipt all remain unimplemented.
Release-binary `OnChainGovernance` production-surface evidence
covering the wired call sites is **deferred to Run 183**.

**Driving spec.** `task/RUN_182_TASK.txt`.

## 1. Strict scope

Run 182 closes the gap identified by Run 181's `mutation_proof.txt`:
the Run 180 per-surface preflight wrappers had **no production
callers** prior to Run 182 (they lived only in helpers, in-crate
self-tests, and the integration test suite). Run 182 wires them into
the seven actual production v2 marker-decision call sites so the
Run 178 typed verifier is reachable from production source paths
under the hidden DevNet/TestNet fixture-only policy.

Run 182 is **strictly source/test** and adds **only** named call-site
entries that delegate verbatim to the Run 180 wrappers. Run 182 does
not:

* change the production default policy on any surface — it remains
  `OnChainGovernanceProofPolicy::Disabled`;
* enable MainNet peer-driven apply — the Run 147/148/152 FATAL
  invariant continues to hold; the peer-driven-drain wiring entry
  layers a surface-level MainNet refusal in agreement with the
  upstream environment gate;
* introduce any new wire field, sidecar field, schema bump, metric,
  or exit code in any production module;
* implement real on-chain governance proof verification for MainNet,
  governance execution, KMS/HSM custody, validator-set rotation,
  bridge / light-client integration, autonomous apply, or
  apply-on-receipt;
* capture release-binary `OnChainGovernance` production-surface
  evidence — that is **deferred to Run 183**.

Run 182 does **not** weaken any prior run (Runs 070, 130–181) and
does **not** claim full C4 or C5 closure.

## 2. What landed

### 2.1 New module — `pqc_onchain_governance_callsite_wiring.rs`

Seven named **production call-site entries** (one per Run 180
per-surface preflight wrapper) plus a unified
[`OnChainGovernanceCallsiteContext`](
  ../../crates/qbind-node/src/pqc_onchain_governance_callsite_wiring.rs)
typed argument bundle:

1. `reload_check_callsite_onchain_governance_marker_decision`
2. `reload_apply_callsite_onchain_governance_marker_decision`
3. `startup_p2p_trust_bundle_callsite_onchain_governance_marker_decision`
4. `sighup_callsite_onchain_governance_marker_decision`
5. `local_peer_candidate_check_callsite_onchain_governance_marker_decision`
6. `live_inbound_0x05_callsite_onchain_governance_marker_decision`
7. `peer_driven_drain_callsite_onchain_governance_marker_decision`

Each entry delegates verbatim to the corresponding Run 180 wrapper.
The peer-driven-drain entry adds a surface-level MainNet refusal
(returns `MainNetRefused` before the verifier is invoked) per
Runs 147/148/152.

### 2.2 Production source call-site wiring

| Surface | Production source file | Mutation contract |
|---|---|---|
| `--p2p-trust-bundle-reload-check` | `crates/qbind-node/src/main.rs` (`preflight_run_132_validation_only_v2_marker_check`) | Validation-only |
| `--p2p-trust-bundle-reload-apply-*` | `crates/qbind-node/src/main.rs` (`preflight_run_134_v2_marker_decision`) | Mutating preflight |
| Startup `--p2p-trust-bundle` | `crates/qbind-node/src/main.rs` (`preflight_run_136_v2_marker_decision_for_startup`) | Mutating preflight |
| SIGHUP live trust-bundle reload | `crates/qbind-node/src/pqc_live_trust_reload.rs` (`preflight_sighup_v2_marker_decision`) | Mutating preflight |
| Local `--p2p-trust-bundle-peer-candidate-check` | `crates/qbind-node/src/main.rs` (v2 sidecar dispatch) | Validation-only |
| Live inbound `0x05` | `crates/qbind-node/src/pqc_peer_candidate_wire.rs` (post `verify_marker_for_validation_only_v2`) | Validation-only |
| Run 150 peer-driven apply drain | `crates/qbind-node/src/pqc_peer_candidate_apply.rs` (`ProductionV2MarkerCoordinator::decide_pre_apply`) | Mutating preflight |

Each production call site, on the path it already takes today,
constructs an `OnChainGovernanceCallsiteContext { proof: None, ... }`,
resolves the active policy via
[`onchain_governance_proof_policy_from_cli_or_env`](
  ../../crates/qbind-node/src/pqc_onchain_governance_proof_surface.rs),
invokes the matching wiring entry, and **drops the result**. Under the
default `Disabled` policy every entry returns `PolicyDisabled` and the
existing Run 130–181 behaviour is preserved bit-for-bit. With the
hidden selector enabled and a typed proof carrier in hand the entry
returns the same typed `OnChainGovernanceMarkerDecisionOutcome` the
Run 180 wrapper produces.

### 2.3 Wire/schema blocker

No current peer-candidate, SIGHUP-trigger, reload-apply trigger,
startup-bundle, or live `0x05` payload format carries a typed
`OnChainGovernanceProof`. Adding it to any wire/schema is **explicitly
out of scope** for Run 182 (no schema bump, no wire field, no sidecar
field). Therefore production callers always invoke the wiring entries
with `proof: None`. The Run 180 wrapper short-circuits on
`NoOnChainGovernanceProofSupplied` (or `PolicyDisabled` under the
default) and the call-site behaviour is preserved bit-for-bit.

The Run 182 integration test suite at
[`tests/run_182_onchain_governance_production_callsite_wiring_tests.rs`](
  ../../crates/qbind-node/tests/run_182_onchain_governance_production_callsite_wiring_tests.rs)
exercises the wiring entries with **in-process crafted typed proofs**
to demonstrate the full A1–A9 + R1–R27 acceptance/rejection matrix
under the `AllowFixtureSourceTest` policy.

### 2.4 Selector plumbing

The hidden Run 180 fixture-allowed selector
(`--p2p-trust-bundle-onchain-governance-fixture-allowed` /
`QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`) is
captured by:

* `Run105ReloadCheckContextData::onchain_governance_fixture_allowed_selector`
  (consumed by reload-check, reload-apply, startup, and local
  peer-candidate-check entries);
* `LiveReloadConfig::onchain_governance_fixture_allowed_selector`
  (consumed by the SIGHUP entry);
* `ProductionV2MarkerCoordinator::onchain_governance_fixture_allowed_selector`
  (consumed by the peer-driven-drain entry, populated via the new
  `with_onchain_governance_fixture_allowed_selector` builder).

The live inbound `0x05` surface relies on env-var selector resolution
because the wire dispatcher is not currently configured from the same
CLI args struct; the helper documented inside the dispatcher OR-resolves
the env source unchanged from prior runs.

## 3. Acceptance / rejection matrix

The Run 182 integration test file covers:

* **A1.** Default `Disabled` bypasses every wiring entry (PolicyDisabled).
* **A2.** Reload-check accepts a valid DevNet OnChainGovernance Rotate
  proof under `AllowFixtureSourceTest`.
* **A3.** Reload-apply accepts a valid DevNet Rotate proof.
* **A4.** Startup `--p2p-trust-bundle` accepts a valid fixture proof.
* **A5.** SIGHUP preflight accepts a valid fixture proof.
* **A6.** Local peer-candidate-check accepts a valid fixture proof
  (TestNet candidate / domain).
* **A7.** Live inbound `0x05` wiring entry accepts a valid fixture
  proof when one is supplied in-process.
* **A8.** Peer-driven drain coordinator accepts a valid fixture proof
  on a DevNet candidate.
* **A9.** Absent proof under `AllowFixtureSourceTest` produces
  `NoOnChainGovernanceProofSupplied` at every entry — the existing
  GenesisBound and EmergencyCouncil proof-mode behaviour is unchanged
  because those modes do not enter the OnChainGovernance call-site
  path.
* **R1–R27.** Default-Disabled rejection, selector-unset preserves
  Disabled, MainNet peer-driven drain refusal (with and without
  proof), wrong env / chain / genesis / authority root, wrong
  governance domain, wrong proposal digest, wrong proposal outcome,
  wrong lifecycle action, wrong candidate digest, wrong authority
  domain sequence, expired proof, replayed decision, quorum not met,
  threshold not met, invalid proof bytes, unsupported proof suite,
  malformed proof, no proof / peer-majority alone insufficient,
  proof-valid lifecycle-invalid, lifecycle-valid proof-invalid,
  validation-only rejection non-mutating (by construction —
  borrow-checker + pure function), mutating preflight rejection
  pure (by construction), invalid live `0x05` proof not propagated /
  staged / applied (necessary condition: wiring entry returns a
  non-accepting outcome).

All 37 tests pass.

## 4. Validation

* `cargo build -p qbind-node --lib` — green
* `cargo test -p qbind-node --test run_182_onchain_governance_production_callsite_wiring_tests`
  — 37/37 passing

Regression suites required by `task/RUN_182_TASK.txt §Validation
commands` are run as part of the Run 182 PR CI; commit-time results
are recorded in this directory's `summary.txt` once captured.

## 5. Strict scope statements

* Run 182 is source/test production call-site wiring for
  OnChainGovernance fixture proofs.
* Default remains `OnChainGovernanceProofPolicy::Disabled`.
* `AllowFixtureSourceTest` is hidden, explicit, and DevNet/TestNet
  fixture-only.
* Real on-chain governance proof verification remains unimplemented.
* Governance execution remains unimplemented.
* Production MainNet OnChainGovernance remains unsupported / fail-closed.
* MainNet peer-driven apply remains refused.
* KMS/HSM remains unimplemented.
* Validator-set rotation remains open.
* Release-binary production-surface OnChainGovernance evidence is
  **deferred to Run 183**.
* Full C4 remains open.
* C5 remains open.
