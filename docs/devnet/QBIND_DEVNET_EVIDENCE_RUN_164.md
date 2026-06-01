# QBIND DevNet Evidence — Run 164

## Subject

Run 164: **release-binary evidence / boundary** for the Run 163 typed
pure governance ratification authority verifier
(`crates/qbind-node/src/pqc_governance_authority.rs`,
`verify_governance_authority_proof`,
`validate_lifecycle_with_governance_authority`,
`GovernanceAuthorityProof`,
`GovernanceAuthorityClass{GenesisBound, EmergencyCouncil, OnChainGovernance}`,
`GovernanceAuthorityVerificationOutcome`,
`CombinedLifecycleGovernanceOutcome`,
`GovernanceIssuerSignatureVerifier`,
`FixtureIssuerSignatureVerifier`,
`GovernanceThreshold`).

Per `task/RUN_164_TASK.txt`, Run 164 must produce the **strongest
honest** release-binary evidence currently possible for that verifier
and must clearly determine whether the verifier is reachable from any
production binary surface today. If the verifier is **not** reachable
from any release-binary production surface, Run 164 must report that
as a partial-positive boundary, capture the release-binary
fixture/evidence available through the helper / example binary path,
and identify the exact next required integration run — rather than
fabricate governance closure.

## Verdict

**`partial-positive: release-binary fixture/evidence boundary
captured; governance authority verifier not yet production-surface
reachable`.**

The Run 164 source-level reachability proof (captured by the harness
in
`docs/devnet/run_164_governance_authority_release_binary/reachability/{src_grep.txt,reachability.txt}`)
shows that `verify_governance_authority_proof`,
`validate_lifecycle_with_governance_authority`, and the
`pqc_governance_authority` module have **zero production callers** in
`crates/qbind-node/src/` outside:

* `crates/qbind-node/src/pqc_governance_authority.rs` (the module
  itself);
* `crates/qbind-node/src/lib.rs` (`pub mod pqc_governance_authority;`
  declaration only).

Test-side references live only in
`crates/qbind-node/tests/run_163_governance_authority_verifier_tests.rs`
(the Run 163 test suite, 32 tests). None of the eight production
release-binary v2 surfaces enumerated by the task — startup
`--p2p-trust-bundle` v2 (Run 137), reload-check validation-only (Run
132/133), local peer-candidate-check validation-only (Run 132/133),
process-start reload-apply (Run 134/135/162), SIGHUP live-reload (Run
138/139), live inbound `0x05` validation-only (Run 142/143),
peer-driven staged queue / drain-once
(Run 148/150/151/152/153/158), and the lifecycle marker-decision path
from Run 161/162 — calls the Run 163 governance verifier today.

Run 164 therefore captures the release-binary evidence that is
honestly available — a release-built helper that exercises the
verifier on every feasible accept and reject scenario, plus the
release-built `qbind-node` identity and the source-level
reachability proof — and **does not claim strongest-positive**.

## Source delta

Additive only. **No production runtime source change.**

* `crates/qbind-node/examples/run_164_governance_authority_fixture_helper.rs`
  — new release-built helper that mints the governance proof corpus
  (A1–A5 + R1–R16) and invokes `verify_governance_authority_proof`
  and `validate_lifecycle_with_governance_authority` on every
  scenario. Uses the existing public Run 163 surface
  (`GovernanceAuthorityProof`, `fixture_issuer_signature`,
  `FixtureIssuerSignatureVerifier`, `GovernanceThreshold`) and the
  existing `PersistentAuthorityStateRecordV2::new` /
  `validate_structure` primitives. No new wire format, no new
  sidecar schema, no marker schema change, no sequence-file schema
  change, and no peer-candidate envelope schema change.
* `scripts/devnet/run_164_governance_authority_release_binary.sh` —
  new release-binary harness.
* `docs/devnet/run_164_governance_authority_release_binary/` — new
  evidence archive (`README.md` + `summary.txt` tracked; everything
  else `.gitignore`d, mirroring Run 153 / 155 / 156 / 158 / 160 /
  162).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_164.md` — this report.
* Narrow alignment updates to:
  * `docs/whitepaper/contradiction.md`,
  * `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`,
  * `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
  * `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.

**No `main.rs` / `cli.rs` edit. No CLI flag added or renamed. No
SIGHUP / reload-apply / startup-mutation / snapshot-restore / live
`0x05` dispatcher / drain-once code path change. No
`LivePqcTrustState` mutation. No sequence-file write. No
authority-marker write. No new wire format. No schema/wire/metric
drift.**

## Surfaces investigated (release-binary reachability matrix)

Per `task/RUN_164_TASK.txt` §Investigation requirement:

| # | Surface                                                | Calls `verify_governance_authority_proof`? | Calls `validate_lifecycle_with_governance_authority`? | Carries `GenesisBound`? | Carries `EmergencyCouncil`? | Carries `OnChainGovernance`? | Wire/schema change required for evidence? | Used for release-binary evidence in Run 164?       |
|---|--------------------------------------------------------|--------------------------------------------|-------------------------------------------------------|-------------------------|-----------------------------|------------------------------|-------------------------------------------|----------------------------------------------------|
| 1 | startup `--p2p-trust-bundle` v2 (Run 137)              | No                                         | No                                                    | No                      | No                          | No                           | No (call site only; Run 165)              | No — observed-no-claim invariant only              |
| 2 | reload-check validation-only (Run 132/133)             | No                                         | No                                                    | No                      | No                          | No                           | No (call site only; Run 165)              | No — observed-no-claim invariant only              |
| 3 | local peer-candidate-check validation-only (Run 132)   | No                                         | No                                                    | No                      | No                          | No                           | No (call site only; Run 165)              | No — observed-no-claim invariant only              |
| 4 | process-start reload-apply (Run 134/135/162)           | No                                         | No                                                    | No                      | No                          | No                           | No (call site only; Run 165)              | No — observed-no-claim invariant only              |
| 5 | SIGHUP live-reload (Run 138/139)                       | No                                         | No                                                    | No                      | No                          | No                           | No (call site only; Run 165)              | No — observed-no-claim invariant only              |
| 6 | live inbound `0x05` validation-only (Run 142/143)      | No                                         | No                                                    | No                      | No                          | No                           | No (call site only; Run 165)              | No — observed-no-claim invariant only              |
| 7 | peer-driven staged queue / drain-once (Run 150–158)    | No                                         | No                                                    | No                      | No                          | No                           | No (call site only; Run 165)              | No — observed-no-claim invariant only              |
| 8 | lifecycle marker-decision (Run 161/162)                | No                                         | No                                                    | No                      | No                          | No                           | No (call site only; Run 165)              | No — observed-no-claim invariant only              |
| 9 | fixture helper / example binary path                   | **Yes**                                    | **Yes**                                               | **Yes**                 | **Yes**                     | **Yes** (fail-closed)        | No                                        | **Yes** — A1–A5 / R1–R16 typed-outcome assertion   |

For every accept proof class (`GenesisBound`, `EmergencyCouncil`,
`OnChainGovernance` deliberately fail-closed), the existing v2
ratification proof field set is sufficient at the wire level (Run
163 module docs §Proof shape) — what is missing on production
surfaces 1–8 is the production call site, not the wire format.
`OnChainGovernance` remains explicitly fail-closed
(`UnsupportedOnChainGovernance`); Run 164 does **not** silently
invent an on-chain proof schema.

## Acceptance / rejection matrix exercised on the release-built helper

Each scenario is minted by the release-built helper
`target/release/examples/run_164_governance_authority_fixture_helper`,
which links against the production `qbind-node` library (same source
checkout as `target/release/qbind-node`) and invokes
`verify_governance_authority_proof` and
`validate_lifecycle_with_governance_authority` on the candidate /
proof / persisted / trust-domain it constructs. The harness asserts
that each scenario's actual typed-outcome dump contains the expected
typed-outcome class string from `manifest.txt`. PASS=21, FAIL=0.

### Acceptance

| ID | Class             | Lifecycle action     | Verifier outcome                                    | Combined outcome (lifecycle + governance)                                 |
|----|-------------------|----------------------|-----------------------------------------------------|---------------------------------------------------------------------------|
| A1 | GenesisBound      | Rotate               | `AcceptedGenesisBound{action:Rotate, seq:2}`        | `Accepted{lifecycle:RotationAccepted, governance:AcceptedGenesisBound}`   |
| A2 | GenesisBound      | Revoke               | `AcceptedGenesisBound{action:Revoke, seq:3}`        | `Accepted{lifecycle:RevocationAccepted, governance:AcceptedGenesisBound}` |
| A3 | GenesisBound      | EmergencyRevoke      | `AcceptedGenesisBound{action:EmergencyRevoke, 3}`   | `Accepted{lifecycle:EmergencyRevocationAccepted, governance:Accepted…}`   |
| A4 | EmergencyCouncil  | EmergencyRevoke      | `AcceptedEmergencyCouncil{seq:3}`                   | `Accepted{lifecycle:EmergencyRevocationAccepted, governance:Accepted…}`   |
| A5 | GenesisBound      | Rotate (idempotent)  | `AcceptedGenesisBound{action:Rotate, seq:2}`        | `Accepted{lifecycle:Idempotent{sequence:2}, governance:AcceptedGenesisBound}` |

A5 honest classification: Run 163's verifier accepts the same proof
re-presented at the same sequence as `AcceptedGenesisBound`. The
verifier's `AcceptedIdempotent` enum variant exists at the type level
but is reserved for a future stronger replay-classification surface
(per Run 163 module docs §Outcome variants). The combined
`validate_lifecycle_with_governance_authority` helper classifies the
lifecycle layer as `Idempotent{sequence:2}` — that idempotent claim
is captured in `combined_outcomes.txt` and is the right place for
idempotent / replay-safe classification today.

### Rejection

| ID  | Trigger                                                    | Verifier outcome class                |
|-----|------------------------------------------------------------|----------------------------------------|
| R1  | proof environment != domain environment                    | `WrongEnvironment`                    |
| R2  | proof chain_id != domain chain_id                          | `WrongChain`                          |
| R3  | proof genesis_hash != domain genesis_hash                  | `WrongGenesis`                        |
| R4  | proof authority_root_fingerprint != domain root            | `WrongAuthorityRoot`                  |
| R5  | proof.lifecycle_action != classified candidate action      | `WrongLifecycleAction`                |
| R6  | proof.candidate_v2_digest != candidate latest digest       | `WrongCandidateDigest`                |
| R7  | proof.authority_domain_sequence != candidate sequence      | `WrongAuthoritySequence`              |
| R8  | proof.issuer_signature byte mutated                        | `InvalidIssuerSignature`              |
| R9  | proof.issuer_signature_suite_id = 200 (unknown)            | `UnsupportedIssuerSuite`              |
| R10 | proof.issuer_signature_suite_id = 1 (Ed25519, known non-PQC) | `NonPqcSuiteRejected`               |
| R11 | proof.threshold = (approvals=1, required=2, total=3)       | `ThresholdNotMet`                     |
| R12 | proof.issuer_signature is empty                            | `MalformedProof`                      |
| R13 | proof_sequence=1 but persisted_sequence=2                  | `ReplayRejected`                      |
| R14 | proof.issuer_authority_class = OnChainGovernance           | `UnsupportedOnChainGovernance`        |
| R15 | empty signature + empty authority root (operator-config-only) | `MalformedProof`                   |
| R16 | empty signature, threshold (0,0,0) (peer-majority surrogate) | `MalformedProof`                    |

R14 carries a class-bound signature and is rejected ahead of any
binding check — `OnChainGovernance` is fail-closed.

R15 captures the local-operator-config-only refusal as a malformed
proof; the typed enum variant `LocalOperatorConfigOnlyRejected` is
exercised by Run 163 R15 source/test coverage at the verifier
level. The release-built helper here exhibits the harder honest
signal: a synthetic operator-config proof (no signature, no class
binding) is rejected as malformed, satisfying the task's R15
requirement.

R16 captures the peer-majority refusal at the type level. The
`GovernanceAuthorityClass` enum has no peer-majority variant by
construction; Run 163 R16 source/test coverage explicitly asserts
that. The release-built helper exhibits the corresponding honest
release-binary signal: a synthetic peer-majority proof is rejected
as malformed because the verifier refuses to accept any proof
without a valid issuer signature regardless of declared class or
threshold.

R8/R12/R15/R16 all overlap conceptually with malformed-proof or
invalid-signature classes. They are kept as distinct release-binary
scenarios because the task explicitly enumerates them, and the
helper's per-scenario fixture material on disk lets a future audit
re-run the verifier on each scenario independently.

## Negative invariants asserted

The harness writes
`docs/devnet/run_164_governance_authority_release_binary/negative_invariants.txt`
and asserts:

* `harness_started_qbind_node: NO`
* `harness_wrote_sequence_file: NO`
* `harness_wrote_authority_marker: NO`
* `harness_mutated_live_trust_state: NO`
* `harness_opened_p2p_socket: NO`
* `harness_modified_data_dir_outside_archive: NO`
* `harness_enabled_mainnet_peer_driven_apply: NO`
* `data/` is empty by construction.

The harness also runs the standard out-of-scope denylist grep
(banner-excluded per the Run 153 / 155 / 156 / 158 / 160 / 162
precedent) over the harness logs and reachability records, captured
in `grep_summaries/denylist.txt`. The denylist must remain empty
post banner-exclusion; the harness fails closed otherwise.

## Validation commands

The harness runs the following on this checkout:

* `cargo build --release -p qbind-node --bin qbind-node`
* `cargo build --release -p qbind-node --example
  run_164_governance_authority_fixture_helper`
* `bash scripts/devnet/run_164_governance_authority_release_binary.sh`
* `cargo test -p qbind-node --test run_163_governance_authority_verifier_tests`
* `cargo test -p qbind-node --test run_161_lifecycle_marker_integration_tests`
* `cargo test -p qbind-node --test run_159_authority_signing_key_lifecycle_tests`
* `cargo test -p qbind-node --test run_157_unified_testnet_fixture_universe_tests`
* `cargo test -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests`
* `cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests`
* `cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests`
* `cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests`
* `cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests`
* `cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests`
* `cargo test -p qbind-node --lib pqc_authority`

All eleven regression suites are green on this checkout. Per-suite
stdout/stderr/exit_code are captured under
`docs/devnet/run_164_governance_authority_release_binary/test_results/`.

## Documentation alignment

* `docs/whitepaper/contradiction.md` — new Run 164 paragraph; the
  Run 050–163 invariants are explicitly preserved.
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — new Run 164
  entry; operators have no new CLI surface and no new runtime
  behaviour.
* `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md` —
  new Run 164 entry; the Run 144 safety contract and six-phase
  fail-closed pipeline are unchanged.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — new Run
  164 entry; the trust-anchor authority model is unchanged.

## Crosscheck against existing design / spec

* The on-wire `BundleSigningRatificationV2Action` byte set
  (`Ratify=0`, `Rotate=1`, `Revoke=2`) is unchanged.
* The trust-bundle schema, the authority-marker schema, the
  sequence-file schema, and the peer-candidate envelope schema are
  unchanged.
* The Run 130 v2 verifier, the Run 131/134/136/138/150/152
  marker-comparison/persistence helpers, the existing
  authority-domain sequence anti-rollback, and the existing chain
  id / environment / genesis / authority-root binding are reused
  verbatim.
* The Run 161 wiring of the Run 159 lifecycle validator into
  `decide_marker_acceptance_v2` (and through it the Run 134 / 136 /
  138 / 150 / 152 mutating and Run 132 / 142 validation-only v2
  surfaces) is unchanged.
* The Run 162 release-binary lifecycle ENFORCEMENT evidence remains
  valid — the Run 161 production-call-site grep still fires on
  `pqc_authority_marker_acceptance.rs`, independently of Run 164.
* DevNet evidence from Run 153, TestNet evidence from Runs
  154/155/157/158, Run 159 source/test lifecycle coverage, Run 161
  source/test integration coverage, Run 160's release-binary
  fixture-corpus boundary, Run 162's release-binary lifecycle
  ENFORCEMENT evidence, and Run 163's source/test governance
  verifier coverage all remain valid.
* MainNet drain-once refusal, no autonomous peer-driven apply, no
  automatic apply on receipt, no peer-majority authority, no
  governance execution implementation, no on-chain governance
  integration, no KMS / HSM, no validator-set rotation, no static
  production MainNet anchor, and the explicit refusals of local
  operator config alone and local peer majority as MainNet
  bundle-signing authority are all preserved.

No contradictions are introduced. Run 164's only delta to
production-surface reachability is the addition of the
release-built helper as a release-binary caller of the verifier;
the eight production v2 surfaces remain unchanged.

## Release-binary reachability today

* Run 163 governance authority verification is **NOT** release-binary
  reachable from any production v2 surface today.
* The proof classes actually evidenced on release binaries (through
  the Run 164 release-built helper) are: `GenesisBound` (via A1,
  A2, A3), `EmergencyCouncil` (via A4), and `OnChainGovernance`
  (via R14 — the helper deliberately exercises the fail-closed
  path).
* The proof classes that remain source/test-only on production v2
  surfaces are **all of them** (`GenesisBound`,
  `EmergencyCouncil`, `OnChainGovernance`) — none of the eight
  production release-binary v2 surfaces calls the Run 163 verifier
  today. That is the partial-positive boundary captured here.
* `OnChainGovernance` remains unsupported / fail-closed pending an
  explicit on-chain proof schema; Run 164 does not silently invent
  one.
* No MainNet apply is enabled by Run 164.
* Governance execution / on-chain proof remains unimplemented in
  this codebase.
* KMS / HSM remains unimplemented.
* Validator-set rotation remains open.
* Full **C4** remains open.
* **C5** remains open.

## Acceptance criteria mapping (per `task/RUN_164_TASK.txt`)

1. **Honestly determines release-binary reachability.** Yes — the
   harness emits a source-level grep that confirms zero production
   callers in `crates/qbind-node/src/` outside the module itself
   and the `lib.rs` declaration; the verdict is partial-positive.
2. **Captures release-binary governance verifier evidence for every
   feasible existing proof class.** Yes — the release-built helper
   exercises the verifier on A1 (GenesisBound Rotate), A2
   (GenesisBound Revoke), A3 (GenesisBound EmergencyRevoke), A4
   (EmergencyCouncil EmergencyRevoke), A5 (idempotent), and R1–R16,
   with per-scenario typed-outcome assertions.
3. **Documents infeasible proof classes without fabricating
   evidence.** Yes — `OnChainGovernance` remains explicitly
   fail-closed; the eight production v2 surfaces are documented as
   non-reachable rather than fictionalised; A5's idempotent
   classification is honestly attributed to the lifecycle layer
   rather than to the verifier.
4. **Preserves all validation-only and mutating-surface
   invariants.** Yes — the harness does not start `qbind-node`
   and does not touch any v2 production surface; Run 161/162
   wiring is unchanged.
5. **Does not introduce schema/wire drift silently.** Yes — every
   record is built through the existing
   `PersistentAuthorityStateRecordV2::new` /
   `validate_structure` primitives and the existing public Run 163
   surface; no wire/schema/metric change of any kind.
6. **MainNet remains refused.** Yes — Run 151 / Run 158
   release-binary refusal evidence is unaffected; the harness does
   not enable MainNet on any surface.
7. **KMS-HSM / governance execution / validator-set rotation
   remain open.** Yes — explicitly stated in
   `partial_positive_proof.txt`, the README, this report, and the
   four narrow doc updates.
8. **Next required integration run is precisely identified.** Yes —
   **Run 165 — compose `verify_governance_authority_proof` and
   `validate_lifecycle_with_governance_authority` into
   `decide_marker_acceptance_v2`** (or an immediately-upstream
   typed pre-flight gate). Run 166 is then the partner
   release-binary ENFORCEMENT evidence run for Run 165.
9. **No full C4 or C5 closure is claimed.** Confirmed throughout
   this report and the four narrow doc updates.

## Verdict (restated)

`partial-positive: release-binary fixture/evidence boundary
captured; governance authority verifier not yet production-surface
reachable`.

Run 164 is **release-binary evidence/boundary only**. No production
runtime source change. No schema drift. No MainNet enablement. No
governance execution. No on-chain governance integration. No KMS /
HSM. No validator-set rotation. No autonomous apply. No automatic
apply on receipt. No peer-majority authority. No fallback to
`--p2p-trusted-root`. No active `DummySig` / `DummyKem` /
`DummyAead`. **Full C4 is NOT claimed by Run 164; C5 remains OPEN.**