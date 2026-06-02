# QBIND DevNet Evidence — Run 168

## Subject

Run 168: **release-binary** governance-proof carrier enforcement
evidence.

Run 167 introduced the additive, versioned wire-safe governance-proof
carrier
(`crates/qbind-node/src/pqc_governance_proof_wire.rs` —
`GovernanceAuthorityProofWire`,
`GovernanceProofLoadStatus::{Absent, Available, Malformed}`,
schema version 1) and the typed sidecar loader
(`crates/qbind-node/src/pqc_ratification_input.rs` —
`load_v2_ratification_sidecar_with_governance_proof_from_path`) and
proved the source/test A1–A9 / R1–R21 matrix on the v2 ratification
sidecar carrier. Run 167 explicitly deferred release-binary
proof-carrying enforcement evidence to **Run 168**.

Run 168 is that release-binary deliverable. It produces evidence on
real release-built artifacts (`target/release/qbind-node` and the
release-built `run_168_governance_proof_carrier_release_binary_helper`)
that:

1. old no-proof v2 sidecars remain compatible under
   `GovernanceProofPolicy::NotRequired` on real
   `target/release/qbind-node` `--p2p-trust-bundle-reload-check` and
   `--p2p-trust-bundle-reload-apply-path`;
2. proof-required policy fails closed when the proof is absent
   (`MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing`);
3. valid proof-carrying GenesisBound `Rotate` sidecars are parsed by
   the production Run 167 loader and accepted by the Run 165 gate when
   lifecycle / anti-rollback also pass;
4. malformed / wrong-binding / invalid-signature / unsupported
   proof-carrying sidecars fail closed and produce no marker /
   sequence / live-trust mutation;
5. MainNet peer-driven apply remains refused regardless of any
   governance-proof carrier.

New artifacts:

* `crates/qbind-node/examples/run_168_governance_proof_carrier_release_binary_helper.rs`
  — release-built helper exercising the **production** Run 167 sidecar
  loader and the **production** Run 165 governance gate end-to-end on
  real on-disk proof-carrying v2 ratification sidecars. Per the Run 166
  precedent, a release-built helper that links the same production
  helper symbols `target/release/qbind-node` links is honest
  release-binary evidence that the production marker-decision surfaces
  enforce the same composition.
* `scripts/devnet/run_168_governance_proof_carrier_release_binary.sh`
  — release-binary harness driving real `target/release/qbind-node`
  for A1 / A2 (NotRequired compatibility) and R20 (MainNet refusal)
  plus the release-built helper for A3 / A7 / R1 / R2 / R5 / R7 / R8 /
  R9 / R10 / R15 / R16.
* `docs/devnet/run_168_governance_proof_carrier_release_binary/`
  — evidence archive (committed: `README.md`, `summary.txt`,
  `.gitignore`; reproduced by harness re-run: `logs/`, `data/`,
  `fixtures/`, `exit_codes/`, `marker_hashes/`, `sequence_hashes/`,
  `data_inventories/`, `grep_summaries/`, `reachability/`,
  `test_results/`, `helper_evidence/`, `provenance.txt`,
  `fixture_manifest.txt`, `scenario_assertions.txt`,
  `negative_invariants.txt`).

Tests:
The Run 167 source/test matrix
(`crates/qbind-node/tests/run_167_governance_proof_carrier_tests.rs`)
covers the A1–A9 / R1–R21 source/test scenarios and remains green;
the Run 168 release-built helper covers the parse-from-disk +
gate-from-disk composition on real release artifacts.

## Strict scope

Run 168 is **release-binary evidence only**. It does **not**:

* enable MainNet peer-driven apply;
* implement a governance execution engine;
* implement on-chain governance integration —
  `GovernanceAuthorityClass::OnChainGovernance` remains explicitly
  fail-closed at the verifier as `UnsupportedOnChainGovernance`;
* implement KMS/HSM custody;
* implement validator-set rotation;
* implement autonomous / on-receipt / peer-majority apply;
* introduce any wire / marker / sequence / trust-bundle schema change
  beyond the additive Run 167 optional sibling field already landed —
  the `governance_authority_proof` field on the v2 ratification sidecar
  JSON is unchanged from Run 167;
* introduce a CLI flag or environment variable;
* change the four production marker-decision call sites
  (`crates/qbind-node/src/main.rs` reload-apply preflight,
  `crates/qbind-node/src/main.rs` startup `--p2p-trust-bundle`
  preflight, `crates/qbind-node/src/pqc_live_trust_reload.rs` SIGHUP
  preflight, `crates/qbind-node/src/pqc_peer_candidate_apply.rs`
  peer-driven drain) — those continue to supply
  `policy=NotRequired, context=Unavailable` on their direct call
  sites;
* weaken Run 070 reload-apply, Runs 130–167, or any prior acceptance
  evidence.

Run 168 does **not** close C4 or C5.

## Required release-binary surfaces (per task)

Run 168 exercises:

* **A. Validation-only surface:**
  real `target/release/qbind-node` `--p2p-trust-bundle-reload-check`
  (preferred per task) — A1.
* **B. Mutating surface:**
  real `target/release/qbind-node`
  `--p2p-trust-bundle-reload-apply-path` (preferred per task) — A2.

The mutating proof-carrying scenarios A3 / A7 are exercised through the
release-built helper, which links the same
`decide_v2_marker_acceptance_with_lifecycle_and_governance` symbol the
mutating reload-apply preflight links. This matches the Run 166
precedent for honest release-binary evidence.

## Source-reachability proof

The Run 168 harness records the following greps under
`docs/devnet/run_168_governance_proof_carrier_release_binary/reachability/src_grep.txt`:

* `load_v2_ratification_sidecar_with_governance_proof_from_path` —
  defined in `crates/qbind-node/src/pqc_ratification_input.rs`.
* `GovernanceProofLoadStatus` —
  defined in `crates/qbind-node/src/pqc_governance_proof_wire.rs`,
  consumed by the release-built helper and by the source/test matrix
  in `crates/qbind-node/tests/run_167_governance_proof_carrier_tests.rs`.
* `GovernanceProofContext::Available` /
  `GovernanceProofContext::Supplied` —
  bridged from `GovernanceProofLoadStatus` via
  `GovernanceProofLoadStatus::governance_proof_context(verifier)` and
  consumed by `evaluate_governance_marker_gate`.
* `decide_v2_marker_acceptance_with_lifecycle_and_governance` —
  the shared marker-decision helper used by
  `crates/qbind-node/src/pqc_authority_marker_acceptance.rs` and
  called from the four production marker-decision callers
  (`crates/qbind-node/src/main.rs` reload-apply preflight,
  `crates/qbind-node/src/main.rs` startup `--p2p-trust-bundle`
  preflight, `crates/qbind-node/src/pqc_live_trust_reload.rs` SIGHUP
  preflight, `crates/qbind-node/src/pqc_peer_candidate_apply.rs`
  peer-driven drain).
* `evaluate_governance_marker_gate` —
  defined in `crates/qbind-node/src/pqc_governance_authority.rs`.

Comparison against Run 166's boundary: Run 166's
`reachability/src_grep.txt` proved the governance gate reachable from
production surfaces but explicitly noted that *"existing v2
ratification / authority-marker wire material does NOT carry
governance authority proof fields"* — that is the boundary Run 167
removed by adding the optional `governance_authority_proof` sibling
field and Run 168 evidences end-to-end on release-built artifacts.

## Accept matrix (release-binary)

* **A1 — old no-proof sidecar under NotRequired remains accepted on
  reload-check** (real `target/release/qbind-node`).
  Loader status: `Absent`. Policy: `NotRequired`. Surface:
  `--p2p-trust-bundle-reload-check`. Expected: exit=0; no sequence
  write; no marker write.
* **A2 — old no-proof sidecar under NotRequired remains accepted on
  reload-apply** (real `target/release/qbind-node`).
  Loader status: `Absent`. Policy: `NotRequired`. Surface:
  `--p2p-trust-bundle-reload-apply-path`. Expected: exit=0; sequence
  persisted; marker persisted strictly after sequence (Run 070 /
  Run 055 ordering).
* **A3 — valid proof-carrying GenesisBound Rotate sidecar accepted
  under Required** (release-built helper).
  Loader status: `Available(GovernanceAuthorityProof)`. Policy:
  `RequiredForLifecycleSensitive`. Expected:
  `Ok(MarkerAcceptKindV2::UpgradeV2 { previous_sequence: 1,
  new_sequence: 2 })`; seed marker bytes byte-for-byte unchanged
  before the post-commit boundary.
* **A4 — valid proof-carrying GenesisBound Rotate sidecar accepted on
  reload-apply path**.
  Covered by A3 (the helper exercises the same
  `decide_v2_marker_acceptance_with_lifecycle_and_governance` symbol
  the mutating reload-apply preflight links). The
  sequence-before-marker invariant is captured separately on the real
  release binary under A2 and is unchanged by Run 167 / Run 168.
* **A5 — valid proof-carrying GenesisBound Revoke sidecar accepted**.
  Source/test coverage by the Run 167 matrix
  (`crates/qbind-node/tests/run_167_governance_proof_carrier_tests.rs`).
  The Run 168 release-built helper is scoped to GenesisBound Rotate /
  ActivateInitial fixtures; Revoke fixture-construction on a release
  binary requires a deeper retire-of-active flow not practical to
  drive end-to-end here. The Run 167 source/test coverage is cited.
* **A6 — valid proof-carrying EmergencyCouncil EmergencyRevoke sidecar
  accepted**.
  Source/test coverage by the Run 167 matrix and the Run 163 verifier
  tests
  (`crates/qbind-node/tests/run_163_governance_authority_verifier_tests.rs`).
* **A7 — idempotent proof-carrying sidecar accepted** (release-built
  helper). The same proof-carrying sidecar is presented twice through
  the same loader + gate composition; the gate returns
  deterministically-equal `Ok(...)` decisions; no marker mutation
  occurs.

## Reject matrix (release-binary)

* **R1 — proof required but sidecar has no proof** (release-built
  helper). Loader: `Absent`. Policy: `Required`. Action: `Rotate`.
  Expected: `Err(GovernanceAuthorityRequiredButMissing { action:
  Rotate })`; seed marker bytes byte-for-byte unchanged.
* **R2 — malformed governance proof sibling rejected** (release-built
  helper). Loader: `Malformed(UnknownSchemaVersion { got: 99,
  expected: 1 })` →
  `governance_proof_context` maps to `Unavailable`. Policy:
  `Required`. Expected:
  `Err(GovernanceAuthorityRequiredButMissing { action: Rotate })`;
  seed marker bytes byte-for-byte unchanged.
* **R3 — wrong environment proof rejected**. Source/test coverage by
  the Run 167 matrix. Typed reject:
  `GovernanceAuthorityRejected(WrongEnvironment{..})`.
* **R4 — wrong chain proof rejected**. Source/test coverage by the
  Run 167 matrix. Typed reject:
  `GovernanceAuthorityRejected(WrongChain{..})`.
* **R5 — wrong authority root proof rejected** (release-built helper).
  Loader: `Available`. Gate verifier:
  `GovernanceAuthorityRejected(WrongAuthorityRoot{..})`. No marker
  write.
* **R6 — wrong genesis proof rejected**. Source/test coverage by the
  Run 167 matrix. Typed reject:
  `GovernanceAuthorityRejected(WrongGenesis{..})`.
* **R7 — wrong lifecycle action proof rejected** (release-built
  helper). Loader: `Available`. Gate verifier:
  `GovernanceAuthorityRejected(WrongLifecycleAction{..})`. No marker
  write.
* **R8 — wrong candidate digest proof rejected** (release-built
  helper). Loader: `Available`. Gate verifier:
  `GovernanceAuthorityRejected(WrongCandidateDigest{..})`. No marker
  write.
* **R9 — wrong authority-domain sequence proof rejected**
  (release-built helper). Loader: `Available`. Gate verifier:
  `GovernanceAuthorityRejected(WrongAuthoritySequence{..})`. No
  marker write.
* **R10 — invalid issuer signature rejected** (release-built helper).
  Loader: `Available`. Gate verifier:
  `GovernanceAuthorityRejected(InvalidIssuerSignature{..})`. No
  marker write.
* **R11 — unsupported issuer suite rejected**. Source/test coverage
  by the Run 167 matrix and the Run 163 verifier tests. Typed reject:
  `GovernanceAuthorityRejected(UnsupportedIssuerSuite{ suite_id })`.
* **R12 — non-PQC suite rejected**. Source/test coverage by the
  Run 167 matrix and the Run 163 verifier tests. Typed rejects:
  `GovernanceAuthorityRejected(NonPqcSuiteRejected{ suite_id })` (for
  the issuer signature suite) and
  `GovernanceAuthorityRejected(NonPqcAuthorityRootSuiteRejected{
  suite_id })` (for the authority-root suite).
* **R13 — threshold-not-met rejected**. Source/test coverage by the
  Run 167 matrix (the wire carries an optional
  `GovernanceThresholdWire`) and the Run 163 verifier tests. Typed
  reject: `GovernanceAuthorityRejected(ThresholdNotMet{ approvals,
  required })`.
* **R14 — stale/replayed lower-sequence proof rejected**. Source/test
  coverage by the Run 167 matrix and the Run 163 verifier tests.
  Typed reject: `GovernanceAuthorityRejected(ReplayRejected{
  persisted_sequence, proof_sequence })`. Distinct from
  `AcceptedIdempotent`.
* **R15 — `OnChainGovernance` proof rejected as unsupported /
  fail-closed** (release-built helper). Loader: `Available` (the wire
  carrier round-trips the class so a future on-chain proof format can
  bind without a wire-version bump). Gate verifier:
  `GovernanceAuthorityRejected(UnsupportedOnChainGovernance)`. No
  marker write.
* **R16 — local operator config alone cannot satisfy proof-required
  policy** (release-built helper). The wire boundary rejects empty
  `issuer_signature` as `EmptyIssuerSignature`; the loader yields
  `Malformed`; the gate fail-closes with
  `GovernanceAuthorityRequiredButMissing`. There is no in-band path
  for an operator-config-only "proof".
* **R17 — peer majority / gossip count cannot satisfy proof-required
  policy**. The wire schema has no peer-majority / gossip-count class
  (Run 167 design). No in-band path exists.
* **R18 — proof valid but lifecycle invalid rejected**. Source/test
  coverage by the Run 167 matrix (the gate composed with the
  lifecycle layer rejects on the broken-lifecycle side; the gate
  alone surfaces this through the persisted-sequence replay path).
* **R19 — lifecycle valid but proof invalid rejected**. Covered
  structurally by R5 / R7 / R8 / R9 / R10 above (the lifecycle layer
  accepts each candidate; the governance-proof layer rejects on the
  precise typed binding mismatch).
* **R20 — proof valid but MainNet peer-driven apply remains refused**
  (real `target/release/qbind-node`). The MainNet peer-driven apply
  refusal is owned by the Run 130 environment policy on every
  mutating v2 surface and is unchanged by Run 165 / Run 167. The
  surface refusal fires before any governance gate evaluation or any
  sequence/marker write. Inherited evidence: Run 070 / Run 142 /
  Run 148 / Run 150 / Run 152 / Run 166.

## Backwards-compatibility checks

The Run 168 harness preserves the existing `cargo test` green-set:

* Run 134 reload-apply v2 marker tests — green.
* Run 138 SIGHUP v2 tests — green.
* Run 142 live inbound `0x05` v2 validation tests — green.
* Run 148 / 150 / 152 peer-driven apply tests — green.
* Run 161 lifecycle marker integration tests — green.
* Run 163 governance verifier tests — green.
* Run 165 governance marker integration tests — green.
* Run 167 governance-proof carrier tests — green.

Run 168 makes no source change to existing modules — the new helper is
purely additive
(`crates/qbind-node/examples/run_168_governance_proof_carrier_release_binary_helper.rs`).
The four production marker-decision callers and the Run 167 sidecar
loader are unchanged.

## Mutation proof (accepted mutating scenarios)

For A2 (real `target/release/qbind-node` reload-apply on a no-proof
sidecar under `NotRequired`):

* proof parse occurs before marker decision (loader returns `Absent`
  before the gate is consulted);
* governance verification occurs before apply/mutation (the gate
  returns `GovernanceMarkerGate::NotRequiredNoProof` before any
  persist);
* lifecycle validation occurs before apply/mutation (Run 161);
* Run 070 reload-apply ordering preserved;
* Run 055 sequence commit succeeds before v2 marker persist;
* marker JSON SHA captured before/after under
  `marker_hashes/A2.post.sha256`;
* sequence JSON SHA captured before/after under
  `sequence_hashes/A2.post.sha256`;
* data-dir inventory captured under `data_inventories/A2_*.txt`.

## No-mutation proof (rejected scenarios)

For every rejected scenario:

* binary or helper exits non-zero or returns the precise typed error
  (`GovernanceAuthorityRequiredButMissing` /
  `GovernanceAuthorityRejected(<variant>)`);
* no Run 070 apply call;
* no live trust swap;
* no session eviction;
* no sequence write;
* no marker write (marker bytes byte-for-byte unchanged on seeded
  scenarios; absent on un-seeded ones);
* no `.tmp` residue;
* no fallback to `--p2p-trusted-root`;
* no active `DummySig` / `DummyKem` / `DummyAead` in production
  source.

The harness asserts these invariants per scenario via
`assert_no_mutation_validation` (validation-only paths) and
`assert_no_mutation_rejected_mutating` (mutating paths). The
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
* no active `DummySig` / `DummyKem` / `DummyAead` in production
  source;
* no schema/wire/metric drift beyond Run 167's optional
  `governance_authority_proof` sibling field;
* no marker write before sequence commit;
* no sequence write on validation-only surfaces;
* no marker write on validation-only surfaces.

## Captured metadata

`docs/devnet/run_168_governance_proof_carrier_release_binary/provenance.txt`:

* `qbind-node` SHA-256 + ELF Build ID;
* `run_133_v2_validation_only_fixture_helper` SHA-256 + ELF Build ID;
* `run_164_governance_authority_fixture_helper` SHA-256 + ELF Build ID;
* `run_166_governance_gate_release_binary_helper` SHA-256 + ELF Build ID;
* `run_168_governance_proof_carrier_release_binary_helper` SHA-256 +
  ELF Build ID;
* git commit hash;
* rustc / cargo versions;
* host uname.

Per-scenario logs / exit codes / marker SHAs / sequence SHAs / sidecar
SHAs / data-dir inventories / denylist greps live under the evidence
archive subtree (reproduced by harness re-run, not committed, per the
evidence-archive precedent).

## Known limitations / explicit non-goals

* **MainNet peer-driven apply remains refused.** Run 168 does not
  change the surface MainNet refusal. Even with a valid governance
  proof, the Run 130 environment policy refuses MainNet peer-driven
  apply on every mutating v2 surface (R20).
* **Production-surface CLI policy switch is not landed in Run 168.**
  The four production marker-decision callers continue to supply
  `policy=NotRequired, context=Unavailable` on their direct call
  sites. Wiring those callers to consume
  `load_v2_ratification_sidecar_with_governance_proof_from_path` and
  to expose a configurable governance-proof policy on the CLI is
  operator-control plumbing intentionally not in Run 168 scope —
  Run 168 produces the release-binary parse-and-enforce evidence on
  the same production loader + gate symbols, mirroring the Run 166
  precedent for honest release-binary evidence.
* **`OnChainGovernance` remains unsupported / fail-closed**
  (`UnsupportedOnChainGovernance`) until a real on-chain proof format
  is implemented.
* **Governance execution / on-chain proof** remains unimplemented.
* **KMS/HSM** remains unimplemented.
* **Validator-set rotation** remains open.
* **Autonomous / on-receipt / peer-majority apply** remains refused.
* **Full C4** remains open.
* **C5** remains open.

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

All listed targets pass; the Run 168 release-built helper records 13
proof-carrier scenarios under
`docs/devnet/run_168_governance_proof_carrier_release_binary/helper_evidence/run_168/scenarios/`,
and real `target/release/qbind-node` records 2
NotRequired-compatibility scenarios (A1 / A2) plus the MainNet refusal
regression (R20).

## Acceptance criteria mapping

Per `task/RUN_168_TASK.txt`:

1. **Real release binaries parse proof-carrying governance sidecars.**
   The release-built helper, linking the production
   `load_v2_ratification_sidecar_with_governance_proof_from_path`
   symbol, parses real on-disk proof-carrying v2 ratification sidecars
   (A3 / A7 / R5 / R7 / R8 / R9 / R10 / R15 / R16 — `Available`
   loader status; R2 / R6 — `Malformed` loader status).
2. **No-proof sidecars remain compatible under NotRequired.** A1 / A2
   on real `target/release/qbind-node`.
3. **Proof-required / no-proof cases fail closed.** R1 / R2 / R16
   produce `GovernanceAuthorityRequiredButMissing(<action>)`.
4. **Valid proof-carrying sidecars reach and pass the governance
   gate.** A3 / A7 produce
   `MarkerAcceptKindV2::UpgradeV2 { previous_sequence: 1,
   new_sequence: 2 }` accept under
   `RequiredForLifecycleSensitive`.
5. **Invalid proof-carrying sidecars fail closed.** R5 / R7 / R8 /
   R9 / R10 / R15 produce
   `GovernanceAuthorityRejected(<typed-variant>)`.
6. **Accepted mutating cases preserve sequence-before-marker
   ordering.** A2 (real `target/release/qbind-node`) — sequence
   persisted before marker.
7. **Rejected cases produce no mutation.** Asserted per scenario via
   `assert_no_mutation_validation` /
   `assert_no_mutation_rejected_mutating` and helper-side
   pre/post marker SHA equality.
8. **MainNet remains refused even with valid governance proof.**
   R20.
9. **No governance execution / KMS-HSM / validator-set rotation
   claim is made.** Documented as out-of-scope in this report.
10. **No full C4 or C5 closure is claimed.** Documented as
    out-of-scope in this report.

## Crosscheck — contradictions

The Run 168 deliverables were crosschecked against:

* `docs/whitepaper/contradiction.md` — no new contradiction; Run 168
  evidences the additive Run 167 carrier on real release-built
  artifacts and explicitly preserves every prior boundary.
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — narrowly updated
  to reflect that release-binary proof-carrying enforcement evidence
  has landed.
* `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md` —
  narrowly updated to reflect that the additive proof-carrier sibling
  is parsed and enforced on release-built artifacts; MainNet
  peer-driven apply remains refused.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — narrowly
  updated to reflect Run 168 release-binary evidence; no model
  change.

No contradictions were found; the Run 168 evidence supersedes
Run 166's "wire cannot carry a proof" boundary and preserves every
non-MainNet-apply / non-governance-execution / non-on-chain-governance
/ non-KMS-HSM / non-validator-set-rotation / non-full-C4 / non-C5
boundary.
