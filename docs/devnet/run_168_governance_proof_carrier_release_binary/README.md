# Run 168 — Release-Binary Governance-Proof Carrier Enforcement Evidence

## Scope

Run 168 produces release-binary evidence that the **Run 167 governance-
proof carrier** (`pqc_governance_proof_wire`,
`GovernanceAuthorityProofWire`,
`GovernanceProofLoadStatus::{Absent, Available, Malformed}`,
`pqc_ratification_input::load_v2_ratification_sidecar_with_governance_proof_from_path`)
composed with the **Run 165 governance gate**
(`pqc_authority_marker_acceptance::decide_v2_marker_acceptance_with_lifecycle_and_governance`,
`pqc_governance_authority::evaluate_governance_marker_gate`) is reachable
and enforced from real release-built binaries linking the same
production marker-decision symbols `target/release/qbind-node` links.

Per `task/RUN_168_TASK.txt`, Run 168 honestly proves:

1. old no-proof v2 sidecars remain compatible under
   `GovernanceProofPolicy::NotRequired` on real
   `target/release/qbind-node` `--p2p-trust-bundle-reload-check`
   (validation-only) and `--p2p-trust-bundle-reload-apply-path`
   (mutating);
2. proof-required policy fails closed when the proof is absent
   (`GovernanceAuthorityRequiredButMissing`) on a release-built helper
   linking the same production loader and gate symbols;
3. a valid proof-carrying GenesisBound `Rotate` v2 sidecar is parsed by
   the Run 167 production sidecar loader, reaches the Run 165 gate, and
   is accepted where lifecycle / anti-rollback also pass; idempotent
   re-presentation produces a structurally-equivalent decision;
4. malformed (`schema_version=99`), wrong-binding (`WrongAuthorityRoot`,
   `WrongLifecycleAction`, `WrongCandidateDigest`,
   `WrongAuthoritySequence`), invalid-signature
   (`InvalidIssuerSignature`), and explicitly-unsupported
   (`OnChainGovernance`, empty issuer signature) proof carriers all
   fail closed and produce no marker / sequence / live-trust mutation;
5. MainNet peer-driven apply remains refused regardless of any
   governance-proof carrier — the surface refusal is owned by the
   Run 130 environment policy and unchanged by Run 165 / Run 167.

Run 168 does **not**:

* enable MainNet peer-driven apply on any surface;
* introduce a governance execution engine, on-chain governance
  integration, KMS/HSM custody, or validator-set rotation;
* introduce any wire / marker / sequence / trust-bundle schema change
  beyond the additive Run 167 optional sibling field already landed;
* change the four production marker-decision call sites
  (`crates/qbind-node/src/main.rs` reload-apply preflight,
  `crates/qbind-node/src/main.rs` startup `--p2p-trust-bundle`
  preflight, `crates/qbind-node/src/pqc_live_trust_reload.rs` SIGHUP
  preflight, `crates/qbind-node/src/pqc_peer_candidate_apply.rs`
  peer-driven drain) — those still supply
  `policy=NotRequired, context=Unavailable` on their direct call sites,
  and the Run 168 evidence covers the parse-and-enforce composition via
  a release-built helper that links the same production helper symbols
  (the established Run 166 precedent for honest release-binary
  evidence);
* weaken Runs 070, 130–167.

Run 168 does **not** close C4 or C5.

## Verdict

**`positive (release-binary boundary): the Run 167 sidecar loader
parses real on-disk proof-carrying v2 ratification sidecars; the Run 165
governance gate accepts valid proofs and fail-closes on absent /
malformed / invalid / wrong-binding / unsupported proofs; the helper
linking the same production loader + gate symbols
target/release/qbind-node links exercises the proof-carrier composition
on the release-built artifact; old no-proof sidecars remain compatible
under NotRequired on real qbind-node; MainNet peer-driven apply remains
refused.`**

This supersedes Run 166's *"the wire schema cannot carry a proof"*
boundary by demonstrating that the additive Run 167 sibling field
(`governance_authority_proof`) is parsed and enforced end-to-end on the
release-built artifacts, with no wire schema change beyond what Run 167
already landed.

## Reachability — Run 166 boundary superseded

Run 166's `reachability/src_grep.txt` and Run 167's source-test matrix
proved that the governance gate is reachable from production surfaces
but that the existing v2 wire material could not carry a real
governance proof. Run 167 added the additive sibling field and the
typed loader. After Run 167, `reachability/src_grep.txt` returns hits
in:

* `crates/qbind-node/src/pqc_governance_proof_wire.rs` —
  `GovernanceAuthorityProofWire`,
  `GovernanceProofLoadStatus::{Absent, Available, Malformed}`,
  `GovernanceProofLoadStatus::governance_proof_context(verifier)`.
* `crates/qbind-node/src/pqc_ratification_input.rs` —
  `load_v2_ratification_sidecar_with_governance_proof_from_path`,
  `LoadedV2RatificationSidecar`.
* `crates/qbind-node/src/pqc_authority_marker_acceptance.rs` —
  `decide_v2_marker_acceptance_with_lifecycle_and_governance` (the
  shared marker-decision helper used by every mutating v2 surface).
* `crates/qbind-node/src/pqc_governance_authority.rs` —
  `evaluate_governance_marker_gate`,
  `GovernanceAuthorityVerificationOutcome` (typed reject variants).
* `crates/qbind-node/src/main.rs`,
  `crates/qbind-node/src/pqc_live_trust_reload.rs`, and
  `crates/qbind-node/src/pqc_peer_candidate_apply.rs` — the four
  production marker-decision callers that link the same
  `decide_v2_marker_acceptance_with_lifecycle_and_governance` symbol
  the Run 168 release-built helper links.

The Run 168 harness records this grep in
`reachability/src_grep.txt` and `reachability/reachability.txt` and
asserts the production callers via `assert_grep`.

## Surfaces investigated

| # | surface                                            | reachable? | proof-carrier wiring used                         | expected behaviour                                                                                          |
|---|----------------------------------------------------|-----------|---------------------------------------------------|-------------------------------------------------------------------------------------------------------------|
| 1 | real `qbind-node` `--p2p-trust-bundle-reload-check`| yes       | no proof; loader returns `Absent`; policy=NotRequired | accept; no sequence write; no marker write (validation-only)                                            |
| 2 | real `qbind-node` `--p2p-trust-bundle-reload-apply-path` | yes | no proof; loader returns `Absent`; policy=NotRequired | accept; sequence-before-marker preserved (Run 070 / Run 055)                                       |
| 3 | helper, proof-carrying GenesisBound Rotate         | yes       | proof present; loader returns `Available`; policy=Required | gate accept (`UpgradeV2 1->2`); seed marker bytes unchanged before post-commit boundary           |
| 4 | helper, idempotent re-presentation                 | yes       | same loader + gate composition twice              | deterministic identical accept; no marker mutation                                                          |
| 5 | helper, no-proof Rotate under Required             | yes       | loader returns `Absent`; policy=Required          | `GovernanceAuthorityRequiredButMissing(Rotate)`; seed marker bytes unchanged                                |
| 6 | helper, malformed sibling under Required           | yes       | loader returns `Malformed(UnknownSchemaVersion)`; mapped to `Unavailable` | `GovernanceAuthorityRequiredButMissing(Rotate)`; seed marker bytes unchanged                  |
| 7 | helper, wrong authority root                       | yes       | loader returns `Available`; gate verifier rejects | `GovernanceAuthorityRejected(WrongAuthorityRoot)`; no marker write                                          |
| 8 | helper, wrong lifecycle action                     | yes       | loader returns `Available`; gate verifier rejects | `GovernanceAuthorityRejected(WrongLifecycleAction)`; no marker write                                        |
| 9 | helper, wrong candidate digest                     | yes       | loader returns `Available`; gate verifier rejects | `GovernanceAuthorityRejected(WrongCandidateDigest)`; no marker write                                        |
|10 | helper, wrong authority sequence                   | yes       | loader returns `Available`; gate verifier rejects | `GovernanceAuthorityRejected(WrongAuthoritySequence)`; no marker write                                      |
|11 | helper, invalid issuer signature                   | yes       | loader returns `Available`; gate verifier rejects | `GovernanceAuthorityRejected(InvalidIssuerSignature)`; no marker write                                      |
|12 | helper, `OnChainGovernance` class                  | yes       | wire round-trip OK; gate verifier rejects         | `GovernanceAuthorityRejected(UnsupportedOnChainGovernance)`; no marker write                                |
|13 | helper, empty issuer signature                     | yes       | wire boundary rejects → `Malformed(EmptyIssuerSignature)` → `Unavailable` | `GovernanceAuthorityRequiredButMissing(Rotate)`; seed marker bytes unchanged           |
|14 | real `qbind-node` MainNet candidate                | yes       | environment-policy refusal owns the boundary      | refused regardless of any governance-proof carrier                                                          |

The four production marker-decision call sites
(`pqc_live_trust_reload.rs`, `pqc_peer_candidate_apply.rs`,
`main.rs` reload-apply preflight, `main.rs` startup preflight) continue
to supply `GovernanceProofPolicy::NotRequired` and
`GovernanceProofContext::Unavailable` on their direct call sites — the
release-built helper exercises the proof-carrier composition through
the same production loader + gate symbols those callers link, so a
passing helper scenario is honest release-binary evidence per the
Run 166 precedent.

## Release-binary scenario matrix

### A1 — old no-proof sidecar under NotRequired remains accepted on reload-check (real `target/release/qbind-node`)

* Inputs: Run 133 corpus (no-proof v2 sidecar, baseline + candidate
  trust bundles).
* Surface: `--p2p-trust-bundle-reload-check`.
* Expected: exit=0; loader status `Absent`; gate accepts under
  `NotRequired`; no sequence write; no marker write.

### A2 — old no-proof sidecar under NotRequired remains accepted on reload-apply (real `target/release/qbind-node`)

* Inputs: Run 133 corpus.
* Surface: `--p2p-trust-bundle-reload-apply-path`.
* Expected: exit=0; sequence persisted; marker persisted strictly after
  sequence (Run 055 / Run 070 ordering).

### A3 — valid proof-carrying GenesisBound Rotate sidecar accepted under Required (release-built helper)

* Inputs: minted on disk by the helper. Sidecar carries an additive
  `governance_authority_proof` sibling with a structurally-valid
  GenesisBound Rotate proof bound to the candidate digest, sequence,
  authority root, and DevNet trust domain.
* Loader: `Available(GovernanceAuthorityProof)`.
* Gate: `decide_v2_marker_acceptance_with_lifecycle_and_governance`
  with `policy=RequiredForLifecycleSensitive` and
  `context=Supplied{ proof, verifier }`.
* Expected: `Ok(MarkerAcceptKindV2::UpgradeV2 { previous_sequence: 1,
  new_sequence: 2 })`. Helper does not persist past the seed marker;
  seed marker bytes byte-for-byte unchanged.

### A4 — valid proof-carrying GenesisBound Rotate sidecar accepted on a mutating-equivalent path

Covered by A3 (the helper exercises the same
`decide_v2_marker_acceptance_with_lifecycle_and_governance` symbol the
mutating reload-apply preflight links). The sequence-before-marker
ordering invariant is captured separately on the real release binary
under A2 and is unchanged by Run 167 / Run 168.

### A5 — valid proof-carrying GenesisBound Revoke sidecar accepted

The Run 168 release-built helper is scoped to GenesisBound Rotate /
ActivateInitial fixtures because those are the policy-sensitive actions
that exercise both the policy switch and the verifier accept paths.
Source/test coverage for Revoke is provided by the Run 167 matrix in
`crates/qbind-node/tests/run_167_governance_proof_carrier_tests.rs`
(GenesisBound Rotate, Revoke, EmergencyRevoke). The Run 168 evidence
report cites that test file.

### A6 — valid proof-carrying EmergencyCouncil EmergencyRevoke sidecar accepted

Same boundary as A5. Source/test coverage for the EmergencyCouncil
class is provided by the Run 167 matrix and the Run 163 verifier tests
in `crates/qbind-node/tests/run_163_governance_authority_verifier_tests.rs`.

### A7 — idempotent proof-carrying sidecar accepted

* Inputs: helper re-presents the same proof-carrying sidecar twice
  through the same loader + gate composition.
* Expected: deterministically-equal `Ok(...)` decisions; no marker
  mutation in either evaluation; the gate is pure.

### R1 — proof required but sidecar has no proof (release-built helper)

* Loader: `Absent`.
* Policy: `RequiredForLifecycleSensitive`.
* Action: Rotate (lifecycle-sensitive).
* Expected: `Err(GovernanceAuthorityRequiredButMissing { action: Rotate })`.
* Seed marker bytes unchanged.

### R2 — malformed governance proof sibling rejected (release-built helper)

* Loader: `Malformed(UnknownSchemaVersion { got: 99, expected: 1 })`.
* `governance_proof_context(verifier)` maps `Malformed` to `Unavailable`.
* Policy: `RequiredForLifecycleSensitive`.
* Expected: `Err(GovernanceAuthorityRequiredButMissing { action: Rotate })`.
* Seed marker bytes unchanged.

### R3, R4, R6 — wrong environment / wrong chain / wrong genesis

Source-test coverage by Run 167
(`crates/qbind-node/tests/run_167_governance_proof_carrier_tests.rs`)
and the Run 163 verifier tests
(`crates/qbind-node/tests/run_163_governance_authority_verifier_tests.rs`).
Each maps to a distinct typed reject:
`GovernanceAuthorityRejected(WrongEnvironment{..})`,
`GovernanceAuthorityRejected(WrongChain{..})`,
`GovernanceAuthorityRejected(WrongGenesis{..})`. The Run 168
release-built helper covers the structurally-equivalent
`WrongAuthorityRoot`, `WrongLifecycleAction`, `WrongCandidateDigest`,
and `WrongAuthoritySequence` rejects directly to evidence the
parse-from-disk → gate composition.

### R5 — wrong authority root proof rejected (release-built helper)

* Loader: `Available`.
* Gate verifier: `GovernanceAuthorityRejected(WrongAuthorityRoot{..})`.
* No marker write.

### R7 — wrong lifecycle action proof rejected (release-built helper)

* Loader: `Available`.
* Gate verifier: `GovernanceAuthorityRejected(WrongLifecycleAction{..})`.
* No marker write.

### R8 — wrong candidate digest proof rejected (release-built helper)

* Loader: `Available`.
* Gate verifier: `GovernanceAuthorityRejected(WrongCandidateDigest{..})`.
* No marker write.

### R9 — wrong authority-domain sequence proof rejected (release-built helper)

* Loader: `Available`.
* Gate verifier: `GovernanceAuthorityRejected(WrongAuthoritySequence{..})`.
* No marker write.

### R10 — invalid issuer signature rejected (release-built helper)

* Loader: `Available`.
* Gate verifier: `GovernanceAuthorityRejected(InvalidIssuerSignature{..})`.
* No marker write.

### R11, R12 — unsupported issuer suite / non-PQC suite

Source-test coverage by Run 167 and Run 163. Typed rejects:
`GovernanceAuthorityRejected(UnsupportedIssuerSuite{ suite_id })` and
`GovernanceAuthorityRejected(NonPqcSuiteRejected{ suite_id })` (and
`NonPqcAuthorityRootSuiteRejected` for the authority-root suite).

### R13 — threshold-not-met rejected if representable

Source-test coverage by Run 167 (the wire carries an optional
`GovernanceThresholdWire`) and Run 163.
`GovernanceAuthorityRejected(ThresholdNotMet{ approvals, required })`.

### R14 — stale/replayed lower-sequence proof rejected

Source-test coverage by Run 167 and Run 163.
`GovernanceAuthorityRejected(ReplayRejected{ persisted_sequence,
proof_sequence })` is distinct from the idempotent re-acceptance path
(`AcceptedIdempotent`).

### R15 — `OnChainGovernance` proof rejected as unsupported / fail-closed (release-built helper)

* Loader: `Available` (round-trips through the wire).
* Gate verifier: `GovernanceAuthorityRejected(UnsupportedOnChainGovernance)`.
* No marker write.
* The wire format intentionally permits round-tripping the
  `on-chain-governance` class so a future on-chain proof format can
  bind without a new wire-version bump; today the verifier fail-closes.

### R16 — local operator config alone cannot satisfy proof-required policy (release-built helper)

* Loader: `Malformed(EmptyIssuerSignature)` (the wire boundary rejects
  empty issuer signatures, so an "operator-config-only" non-authority
  proof cannot encode in-band).
* `governance_proof_context(verifier)` maps `Malformed` to `Unavailable`.
* Gate: `Err(GovernanceAuthorityRequiredButMissing { action: Rotate })`.
* Seed marker bytes unchanged.

### R17 — peer majority / gossip count cannot satisfy proof-required policy

The wire schema has no peer-majority / gossip-count class. There is no
in-band path to inject such a "proof". Source-test coverage by Run 167
(no peer-majority class is wire-representable).

### R18 — proof valid but lifecycle invalid rejected

Source-test coverage by Run 167 (the gate composed with the lifecycle
layer rejects on the broken-lifecycle side; the gate alone surfaces the
persisted-sequence replay path).

### R19 — lifecycle valid but proof invalid rejected

Covered structurally by R5 / R7 / R8 / R9 / R10 above (the lifecycle
layer accepts each candidate; the governance-proof layer rejects on
the precise typed binding mismatch).

### R20 — proof valid but MainNet peer-driven apply remains refused (real `target/release/qbind-node`)

The MainNet peer-driven apply refusal is owned by the Run 130
environment policy on every mutating v2 surface and is unchanged by
Run 165 / Run 167. The surface refusal fires before any governance gate
evaluation or any sequence/marker write, so a valid governance proof on
a MainNet candidate cannot enable apply. Inherited evidence: Run 070 /
Run 142 / Run 148 / Run 150 / Run 152 / Run 166. Run 168's harness
re-asserts MainNet refusal regression with the current release binary.

## Mutation proof for accepted mutating scenarios

For A2 (real `target/release/qbind-node` reload-apply on a no-proof
sidecar under `NotRequired`):

* proof parse occurs before marker decision (loader returns `Absent`
  before the gate is consulted);
* governance verification occurs before apply/mutation
  (`evaluate_governance_marker_gate` returns
  `GovernanceMarkerGate::NotRequiredNoProof` before any persist);
* lifecycle validation occurs before apply/mutation (Run 161);
* Run 070 reload-apply ordering preserved;
* Run 055 sequence commit succeeds before v2 marker persist;
* marker JSON SHA captured before/after under
  `marker_hashes/A2.post.sha256`;
* sequence JSON SHA captured before/after under
  `sequence_hashes/A2.post.sha256`.

## No-mutation proof for rejected scenarios

For every rejected scenario:

* binary or helper exits non-zero or returns the precise typed error;
* no Run 070 apply call;
* no live trust swap;
* no session eviction;
* no sequence write;
* no marker write (marker bytes byte-for-byte unchanged on seeded
  scenarios; absent on un-seeded ones);
* no `.tmp` residue;
* no fallback to `--p2p-trusted-root`;
* no active `DummySig` / `DummyKem` / `DummyAead`.

The harness asserts these invariants per scenario via
`assert_no_mutation_validation` (validation-only paths) and
`assert_no_mutation_rejected_mutating` (mutating paths), and the
release-built helper asserts pre/post marker SHA equality on every
seeded scenario before recording the scenario as `expect_no_mutation`.

## Denylist

Across the run:

* no MainNet apply;
* no autonomous apply;
* no apply on receipt;
* no peer-majority authority;
* no governance execution claim;
* no on-chain governance claim;
* no KMS/HSM claim;
* no validator-set rotation claim;
* no fallback to `--p2p-trusted-root`;
* no active `DummySig` / `DummyKem` / `DummyAead` in production source;
* no schema/wire/metric drift beyond Run 167's optional sibling field;
* no marker write before sequence commit;
* no sequence write on validation-only surfaces;
* no marker write on validation-only surfaces.

The harness records denylist results under
`grep_summaries/denylist.txt` and asserts the absence of the listed
strings in every captured stdout/stderr.

## Captured metadata

`provenance.txt`:

* `qbind-node` SHA-256 + ELF Build ID;
* `run_133_v2_validation_only_fixture_helper` SHA-256 + ELF Build ID;
* `run_164_governance_authority_fixture_helper` SHA-256 + ELF Build ID;
* `run_166_governance_gate_release_binary_helper` SHA-256 + ELF Build ID;
* `run_168_governance_proof_carrier_release_binary_helper` SHA-256 +
  ELF Build ID;
* git commit hash;
* rustc / cargo versions;
* host uname.

`logs/`, `exit_codes/`, `marker_hashes/`, `sequence_hashes/`,
`data_inventories/`, `grep_summaries/`, `reachability/`,
`test_results/`, `helper_evidence/`, `fixtures/`, plus the
`fixture_manifest.txt`, `scenario_assertions.txt`, and
`negative_invariants.txt` rollups carry the per-scenario evidence.
Per Run 153 / Run 155 / Run 156 / Run 158 / Run 160 / Run 162 / Run 164 /
Run 166 precedent, those subtrees are reproduced by re-running the
harness and are not committed.

## Validation commands

```text
cargo build --release -p qbind-node \
  --bin qbind-node \
  --example run_133_v2_validation_only_fixture_helper \
  --example run_164_governance_authority_fixture_helper \
  --example run_166_governance_gate_release_binary_helper \
  --example run_168_governance_proof_carrier_release_binary_helper

bash scripts/devnet/run_168_governance_proof_carrier_release_binary.sh

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
cargo test --release -p qbind-node --test run_138_sighup_v2_authority_marker_tests
cargo test --release -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests
cargo test --release -p qbind-node --lib pqc_authority
cargo test --release -p qbind-node --lib
```

All listed targets pass; the new release-built helper records 13
proof-carrier scenarios under `helper_evidence/run_168/scenarios/`, and
real `target/release/qbind-node` records 2 NotRequired-compatibility
scenarios (A1 / A2) plus the MainNet refusal regression (R20).

## Out of scope (deferred)

* MainNet peer-driven apply enablement — remains refused;
* governance execution engine — remains unimplemented;
* on-chain governance integration — `OnChainGovernance` remains
  fail-closed at the verifier;
* KMS/HSM custody — remains unimplemented;
* validator-set rotation — remains open;
* autonomous / on-receipt / peer-majority apply — remains refused;
* full C4 closure — remains open;
* C5 closure — remains open;
* wiring the four production marker-decision callers
  (`main.rs` reload-apply / startup,
  `pqc_live_trust_reload.rs` SIGHUP,
  `pqc_peer_candidate_apply.rs` peer-driven drain) to consume
  `load_v2_ratification_sidecar_with_governance_proof_from_path` and
  expose a configurable governance-proof policy on the CLI — this is
  operator-control plumbing and is intentionally not in Run 168 scope
  (no schema/wire change; documented as a follow-up wiring run).