# QBIND DevNet Evidence — Run 165

## Subject

Run 165: **wire the Run 163 governance authority verifier into the v2
lifecycle / marker-decision path** so governance authority checks become
**production-source reachable** before lifecycle-sensitive marker
decisions are accepted.

New/changed source surfaces:

* `crates/qbind-node/src/pqc_governance_authority.rs`
  * `GovernanceProofPolicy` (`NotRequired`,
    `RequiredForLifecycleSensitive`);
  * `GovernanceProofContext` (`Unavailable`, `Supplied { proof,
    verifier }`);
  * `GovernanceMarkerGate` (`NotRequiredNoProof`, `Accepted`,
    `RequiredButMissing`, `Rejected`);
  * `evaluate_governance_marker_gate(...)` — pure, non-mutating gate;
  * `classify_candidate_lifecycle_action(...)` made `pub`;
  * `verify_governance_authority_proof` generic bound relaxed to
    `+ ?Sized` so a `&dyn GovernanceIssuerSignatureVerifier` trait
    object can be threaded through the non-generic marker layer.
* `crates/qbind-node/src/pqc_authority_marker_acceptance.rs`
  * `decide_v2_marker_acceptance_with_lifecycle_and_governance(...)` —
    shared governance-aware marker decision helper;
  * `MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(...)` and
    `::GovernanceAuthorityRequiredButMissing { action }`;
  * `decide_marker_acceptance_v2` internals refactored into a shared
    `decide_marker_acceptance_v2_inner` that additionally returns the
    persisted v2 `authority_domain_sequence` (no behaviour change to the
    public `decide_marker_acceptance_v2`).
* Production surfaces routed through the governance-aware helper:
  * `pqc_live_trust_reload.rs` (SIGHUP marker preflight);
  * `pqc_peer_candidate_apply.rs` (peer-driven drain
    `ProductionV2MarkerCoordinator`);
  * `main.rs` (process-start reload-apply preflight and
    `--p2p-trust-bundle` startup preflight).

Tests: `crates/qbind-node/tests/run_165_governance_marker_integration_tests.rs`.

Run 165 builds on Run 159 (pure v2 lifecycle validator), Run 161
(lifecycle wired into the shared marker-decision helper), Run 162
(release-binary lifecycle enforcement evidence), Run 163 (governance
authority verifier), and Run 164 (partial-positive release-binary
governance boundary).

## Strict scope

Run 165 is **source/test integration only**. It does **not**:

* enable MainNet peer-driven apply (MainNet apply remains refused even
  with a valid governance proof — the refusal lives in the surface
  environment gate, unchanged by Run 165);
* implement a governance execution engine;
* implement on-chain governance integration (`OnChainGovernance` remains
  fail-closed / `UnsupportedOnChainGovernance`);
* implement KMS/HSM custody;
* implement validator-set rotation;
* implement autonomous / on-receipt / peer-majority apply;
* change the wire format, marker schema, sequence-file schema, or
  trust-bundle schema;
* weaken any Run 070 / Run 130–164 acceptance or rejection behaviour.

**Release-binary governance enforcement evidence is deferred to Run 166.**

## Composition

The governance-aware shared marker decision composes, in order:

1. existing v2 marker anti-rollback comparison
   (`compare_authority_marker_v2`);
2. Run 159 lifecycle transition validation
   (`validate_v2_lifecycle_transition`);
3. Run 163 governance authority verification
   (`verify_governance_authority_proof`), gated by
   `GovernanceProofPolicy` / `GovernanceProofContext`.

The final decision accepts only if every required layer accepts: domain
binding, v2 anti-rollback, lifecycle transition validity, and — where the
policy requires it — governance authority proof validity. The decision
remains pure/preflight; marker persistence still occurs only at the
existing post-Run-055-commit boundary
(`persist_accepted_v2_marker_after_commit_boundary`).

## Chosen governance-proof policy (A5)

| Lifecycle action  | Governance proof requirement |
| ----------------- | ---------------------------- |
| `ActivateInitial` | **optional** (genesis-bound first activation), under both policies |
| `Rotate`          | **required** under `RequiredForLifecycleSensitive` |
| `Retire`          | **required** under `RequiredForLifecycleSensitive` |
| `Revoke`          | **required** under `RequiredForLifecycleSensitive` |
| `EmergencyRevoke` | **required**; `EmergencyCouncil` class authorizes it (genesis-bound also authorizes it in the source/test model) |
| `OnChainGovernance` | **unsupported / fail-closed** (no proof format exists) |

Under `RequiredForLifecycleSensitive`, a lifecycle-sensitive action with
**no** proof rejects with a clear typed
`GovernanceAuthorityRequiredButMissing { action }` — never silent
acceptance.

## Documented wire schema-carrying gap

The current v2 ratification / authority-marker wire material does **not**
carry governance authority proof fields. Run 165 deliberately does **not**
invent a schema to smuggle proof bytes through the existing wire format
(no hard blocker was found that would require a schema change). Instead:

* a surface that cannot obtain a proof supplies
  `GovernanceProofContext::Unavailable`;
* under a policy that requires a proof for the candidate's lifecycle
  action, the gate fails closed with
  `GovernanceMarkerGate::RequiredButMissing` →
  `MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing`;
* a future run that defines an actual proof-carrying schema (or supplies
  a proof out-of-band) passes `GovernanceProofContext::Supplied`.

Because of this gap, the Run 165 production surfaces are wired with the
**`NotRequired`** policy and an **`Unavailable`** context, which is
behaviour-preserving: governance verification is composed into the
decision path and is exercised whenever a proof is supplied, but a
missing proof does not by itself refuse a transition. This keeps the
existing DevNet/TestNet peer-driven apply evidence
(Runs 148/150/152/153/158) valid with no governance-proof fixture
changes. Release-binary governance **enforcement** (a non-`NotRequired`
policy on a release surface, with proof fixtures) is deferred to Run 166.

## Production-source reachability (acceptance criterion 1)

`verify_governance_authority_proof` now has production `src` call sites
outside `pqc_governance_authority.rs`:

* `pqc_authority_marker_acceptance::decide_v2_marker_acceptance_with_lifecycle_and_governance`
  invokes `evaluate_governance_marker_gate`, which calls
  `verify_governance_authority_proof`;
* every mutating v2 marker surface (startup, reload-apply, SIGHUP,
  peer-driven drain) routes through that helper.

## Test matrix

`run_165_governance_marker_integration_tests` — **31 tests, all passing**.

Section 1 — pure gate (`evaluate_governance_marker_gate`, the exact
composition the marker helper invokes), over in-memory v2 records:

* A1 Rotate accepted (GenesisBound); A2 Revoke accepted; A3
  EmergencyRevoke accepted (EmergencyCouncil); A4 idempotent
  same-record accepted; A5 chosen policy (required-for-lifecycle-
  sensitive; `ActivateInitial` optional).
* R1 Rotate w/o proof; R2 Revoke w/o proof; R3 EmergencyRevoke w/o
  proof; R4 wrong env; R5 wrong chain; R6 wrong genesis; R7 wrong
  authority root; R8 wrong lifecycle action; R9 wrong candidate digest;
  R10 wrong sequence; R11 invalid signature; R12 unsupported suite; R13
  non-PQC suite; R14 threshold not met; R15 malformed; R16
  stale/replayed; R17 on-chain unsupported; R18 local-operator-config
  alone; R19 peer-majority not authority.

Section 2 — end-to-end shared marker helper with real ML-DSA-44
authority root + signed v2 ratifications:

* E1 ActivateInitial accepted with proof, **no marker write** before the
  post-commit boundary;
* E2 (R20/R23) lifecycle-valid but governance-invalid → typed
  `GovernanceAuthorityRejected`, **no marker write**;
* E3 (R1/R23) Rotate required-but-missing → typed
  `GovernanceAuthorityRequiredButMissing`, persisted seed marker
  **byte-for-byte untouched**;
* E4 (A1) Rotate accepted with proof (`UpgradeV2 1 -> 2`);
* E5 (R21) governance-valid but lifecycle-invalid → `LifecycleRejected`
  (lifecycle layer refuses before governance), seed marker untouched;
* R26/R27 gate is deterministic / side-effect free, and acceptance is a
  typed decision only — it carries no MainNet-apply capability.

## Validation commands and results

* `cargo build -p qbind-node --lib` — OK.
* `cargo build -p qbind-node` — OK.
* `cargo test -p qbind-node --test run_165_governance_marker_integration_tests` — 31 passed.
* `cargo test -p qbind-node --test run_163_governance_authority_verifier_tests` — 32 passed.
* `cargo test -p qbind-node --test run_161_lifecycle_marker_integration_tests` — 29 passed.
* `cargo test -p qbind-node --test run_159_authority_signing_key_lifecycle_tests` — 29 passed.
* `cargo test -p qbind-node --test run_157_unified_testnet_fixture_universe_tests` — 16 passed.
* `cargo test -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests` — 23 passed.
* `cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests` — 19 passed.
* `cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests` — 20 passed.
* `cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests` — 16 passed.
* `cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests` — 5 passed.
* `cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests` — 11 passed.
* `cargo test -p qbind-node --lib pqc_authority` — 148 passed.
* `cargo test -p qbind-node --lib` — 1277 passed.

## Standing limitations (unchanged)

* MainNet peer-driven apply remains **refused** even with a valid
  governance proof.
* Governance execution / on-chain proof remains **unimplemented**;
  `OnChainGovernance` is fail-closed.
* KMS/HSM remains **unimplemented**.
* validator-set rotation remains **open**.
* full C4 remains **open**; C5 remains **open** — Run 165 claims neither.
* Release-binary governance **enforcement** evidence is deferred to
  **Run 166**.