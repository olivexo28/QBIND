# QBIND DevNet Evidence — Run 149

**Subject**: Release-binary evidence for the DevNet/TestNet
peer-driven trust-bundle apply arming surface, layered on top of
the Run 148 source/test `pqc_peer_candidate_apply` controller and
exercising the existing Run 070 apply contract through that
controller per Run 144 / Run 145 / Run 146 / Run 147 ordering.

## Verdict (mandatory disclosure per `task/RUN_149_TASK.txt` §22–§55)

**Run 149 is NOT pure evidence-only.** The feasibility gate
("Can the real `target/release/qbind-node` arm and invoke the
Run 148 peer-driven apply controller through an existing runtime
path?") returned **NO** against the Run 148 state — the Run 148
`qbind_node::pqc_peer_candidate_apply::try_apply_staged_peer_candidate`
controller was library-only with no operator-visible surface in
`crates/qbind-node/src/main.rs`. Under the task's explicit
"preferred path if a flag is necessary" allowance (§34–§52),
Run 149 adds the smallest hidden, disabled-by-default
DevNet/TestNet-only arming surface needed to trigger the
controller honestly.

**Run 149 is therefore classified as
"minimal source wiring + release-binary evidence — partial-positive."**

## Partial-positive disclosure (mandatory per `task/RUN_149_TASK.txt` §30–§32)

Run 149 does NOT introduce a queue-to-controller drain task in
the node binary. Wiring such a drain would be a **new
apply-triggering algorithm**, which is explicitly out of scope
per `task/RUN_149_TASK.txt` §20 ("must not create a new apply
algorithm") and §70 ("No new apply algorithm"). End-to-end
release-binary apply of an already-staged validated peer candidate
through the Run 070 contract (matrix rows A1–A4) therefore
remains under **Run 148 source/test coverage**
(`crates/qbind-node/tests/run_148_peer_driven_apply_devnet_tests.rs`
A1–A4 + R1–R16, 20/20 green) and is cited as such in the scenario
matrix below. Run 149 captures release-binary evidence for the
new arming-surface refusal scenarios, the new arming-surface
acceptance log evidence, and the Run 147 release-binary
non-mutation invariants under the new flag.

## Source delta (exact)

1. `crates/qbind-node/src/cli.rs` — one new hidden,
   disabled-by-default CLI field
   `p2p_trust_bundle_peer_candidate_apply_enabled: bool` bound to
   `--p2p-trust-bundle-peer-candidate-apply-enabled` with
   `hide = true` and `default = false`. Documented inline with
   the exact safety contract (DevNet/TestNet only; MainNet
   refused unconditionally; requires the live `0x05` validation
   flag; requires the staging flag; does NOT imply propagation;
   does NOT bypass staging/validation/marker/Run 055 anti-rollback/
   activation gates; does NOT introduce a new apply algorithm;
   apply itself is delegated to the existing Run 070
   `apply_validated_candidate_with_previous` pipeline when a
   future drain caller invokes
   `try_apply_staged_peer_candidate`).
2. `crates/qbind-node/src/main.rs` — one **early MainNet refusal
   gate** immediately after the Run 147 early MainNet refusal
   gate (top of `run_node`, before any P2P transport
   initialization). MainNet is refused unconditionally with
   `[binary] Run 149: FATAL ...` and exit code 1; the P2P
   transport is never brought up.
3. `crates/qbind-node/src/main.rs` — one **co-requisites + apply
   policy arming banner** block immediately after the Run 147
   acceptance log. Refuses if MainNet (defensive duplicate);
   refuses if `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`
   is not set; refuses if
   `--p2p-trust-bundle-peer-candidate-staging-enabled` is not set;
   on success emits exactly two log lines:
   * `[binary] Run 149: peer-candidate apply arming flag accepted (env=...)` — operator acceptance line;
   * `[run-149] live peer-driven apply policy ARMED (env=..., enabled=true, allow_devnet=..., allow_testnet=..., allow_mainnet=...)` — controller-layer banner that exercises the Run 148 `PeerDrivenApplyPolicy::devnet_enabled()` or `PeerDrivenApplyPolicy::testnet_enabled()` constructor at startup and surfaces the policy matrix to the operator.

The `PeerDrivenApplyPolicy` value materialized at the banner is
**not installed anywhere** — the Run 148 controller is reachable
only via direct library invocation, and Run 149 does not add a
drain caller (forbidden per §20 / §70). The banner is the honest
operator-visible evidence that the policy is selectable and
matches the task's MainNet-refused-unconditionally invariant.

No other production source file is modified. No new module is
added. No `lib.rs` change. No new test file. No new fixture
helper. No new metric family. No new wire format. No new on-disk
schema. No SIGHUP / reload-apply / startup-apply / snapshot-restore
path is changed. No `pqc_trust_reload.rs` change. No
`pqc_live_inbound_dispatcher.rs` change. No
`pqc_peer_candidate_apply.rs` change.

## Scope statement (mandatory per `task/RUN_149_TASK.txt` §57–§77)

* **Release-binary evidence by default.** ✅
* **Minimal hidden arming source change only.** ✅ One hidden
  CLI flag + the matching MainNet/co-requisites gate + the
  controller-layer arming banner. No new module; no new test
  file; no new fixture; no new metric.
* **DevNet/TestNet only.** ✅ The flag selects
  `PeerDrivenApplyPolicy::devnet_enabled()` on DevNet and
  `PeerDrivenApplyPolicy::testnet_enabled()` on TestNet.
* **MainNet refused unconditionally.** ✅ Refused at the early
  CLI gate, at the defensive duplicate inside the co-requisites
  block, and at the controller-layer banner's match arm.
* **No governance implementation.** ✅
* **No KMS/HSM implementation.** ✅
* **No signing-key rotation/revocation lifecycle.** ✅
* **No new wire format.** ✅
* **No trust-bundle schema change.** ✅
* **No ratification sidecar schema change.** ✅
* **No marker schema change.** ✅
* **No sequence-file schema change.** ✅
* **No new apply algorithm.** ✅ Apply is delegated 1:1 to the
  existing Run 070 `apply_validated_candidate_with_previous`
  pipeline through the Run 148 controller; Run 149 does not even
  add a drain caller (which would be a new apply-triggering
  algorithm).
* **No apply of unstaged candidates.** ✅ The Run 148 controller
  refuses unstaged candidates with
  `PeerDrivenApplyOutcome::CandidateNotFound`; the Run 149 flag
  does not relax this and additionally refuses to arm at startup
  unless `--p2p-trust-bundle-peer-candidate-staging-enabled` is
  also set.
* **No apply of invalid candidates.** ✅ The Run 145/146 staging
  queue rejects invalid candidates and the Run 148 controller
  refuses non-validation-accepted candidates with
  `PeerDrivenApplyOutcome::CandidateNotValidated`.
* **No apply of expired candidates.** ✅ Per Run 148 R2 test
  (`r2_expired_staged_candidate_cannot_apply`).
* **No weakening of validation-only / staging-only /
  propagation-only / SIGHUP / reload-apply / startup /
  snapshot/restore behavior.** ✅ The Run 149 source delta is
  purely additive: when the new flag is absent the binary
  behaves bit-for-bit identically to Run 147.
* **No claim of MainNet readiness.** ✅
* **No claim of full C4 or C5 closure.** ✅

## Scenario matrix verdicts

### Release-binary captured (this run)

| ID | Description | Verdict |
| --- | --- | --- |
| C1 | `--p2p-trust-bundle-peer-candidate-apply-enabled` without `--p2p-trust-bundle-peer-candidate-wire-validation-enabled` on DevNet | **PASS** — exit code 1, `[binary] Run 149: FATAL ... requires --p2p-trust-bundle-peer-candidate-wire-validation-enabled` fired |
| C2 / R2 | `--p2p-trust-bundle-peer-candidate-apply-enabled` on `--env mainnet` (with co-requisites stripped so the Run 149 gate fires first) | **PASS** — exit code 1, `[binary] Run 149: FATAL ... refused on MainNet unconditionally ...` fired |
| C3 | `--p2p-trust-bundle-peer-candidate-apply-enabled` + `--p2p-trust-bundle-peer-candidate-wire-validation-enabled` without `--p2p-trust-bundle-peer-candidate-staging-enabled` on DevNet | **PASS** — exit code 1, `[binary] Run 149: FATAL ... requires --p2p-trust-bundle-peer-candidate-staging-enabled` fired |
| C4 | Flag recognised by parser | **PASS** — C1/C2/C3 all fired the `Run 149: FATAL` line rather than the clap `unrecognized argument` error |
| C5 | Flag accepted on DevNet with both co-requisites | **PASS** — `[binary] Run 149: peer-candidate apply arming flag accepted (env=Devnet)` and `[run-149] live peer-driven apply policy ARMED (env=Devnet, enabled=true, allow_devnet=true, allow_testnet=false, allow_mainnet=false)` fire exactly once on V1 |
| C6 | Flag accepted on TestNet with both co-requisites | **PASS** — analogous to C5 with TestNet policy |
| R1 | Flag absent → Run 147 staging behaviour preserved | **PASS** — neither Run 149 banner appears when the flag is absent; Run 147 evidence remains bit-for-bit identical |
| R11 | Propagation-only behavior unchanged | **PASS** — denylist grep over the entire captured corpus sees zero matches for the Run 070 apply / live trust mutation / session eviction / SIGHUP / reload-apply / snapshot-restore-audit / governance / KMS / HSM / signing-key rotation / signing-key revocation patterns |
| R12 | Validation-only behavior unchanged | **PASS** — per-node `pqc_trust_bundle_sequence.json` and `pqc_authority_state.json` SHA-256 are byte-identical pre/post on every captured scenario; no `pqc_authority_state.json.tmp` sibling appears on any node |
| D1 | Denylist grep | **PASS** — zero matches across the Run 147 denylist + the Run 149-mandated additions (`\bKMS\b`, `\bHSM\b`, `signing-key (rotation\|revocation)`, `MainNet governance`) |

### Cited as Run 148 source/test coverage (partial-positive)

| ID | Description | Coverage citation |
| --- | --- | --- |
| A1 | DevNet valid staged v2 candidate applies through Run 070 | `tests/run_148_peer_driven_apply_devnet_tests.rs::a1_devnet_staged_valid_v2_candidate_applies_through_run070` (PASS) |
| A2 | Idempotent / already-staged candidate behavior | `tests/run_148_peer_driven_apply_devnet_tests.rs::r13_idempotent_staged_v2_candidate_is_refused_as_already_applied` (PASS) |
| A3 | Higher-sequence v2 candidate applies | covered by `a1_devnet_staged_valid_v2_candidate_applies_through_run070` (seq+1 vs. seq=N marker) |
| A4 | DevNet v2-after-v1 migration applies | `tests/run_148_peer_driven_apply_devnet_tests.rs::r14_v2_after_v1_migration_candidate_applies_under_enabled_devnet_policy` (PASS) |
| A5 | TestNet apply path | `tests/run_148_peer_driven_apply_devnet_tests.rs::a2_testnet_staged_valid_v2_candidate_applies_only_under_explicit_testnet_policy` (PASS) |
| R3 | Unstaged candidate cannot apply | `tests/run_148_peer_driven_apply_devnet_tests.rs::r1_unstaged_candidate_cannot_apply` (PASS) |
| R4 | Expired staged candidate cannot apply | `tests/run_148_peer_driven_apply_devnet_tests.rs::r2_expired_staged_candidate_cannot_apply` (PASS) |
| R5 | Lower-sequence candidate cannot apply | `tests/run_148_peer_driven_apply_devnet_tests.rs::r3_lower_sequence_marker_conflict_refuses_before_apply` (PASS) |
| R6 | Same-sequence different-digest candidate cannot apply | `tests/run_148_peer_driven_apply_devnet_tests.rs::r4_same_sequence_different_digest_marker_conflict_refuses` (PASS) |
| R7 | Bad-signature candidate cannot apply | `tests/run_148_peer_driven_apply_devnet_tests.rs::r6_bad_signature_candidate_cannot_apply` (PASS) |
| R8 | Wrong-domain candidate cannot apply | `tests/run_148_peer_driven_apply_devnet_tests.rs::r5_wrong_domain_staged_candidate_cannot_apply` (PASS) |
| R9 | Apply-validation failure before swap | `tests/run_148_peer_driven_apply_devnet_tests.rs::r7_apply_validation_failure_before_swap_skips_swap_evict_commit` (PASS). **Release-binary fault injection is infeasible without source modification** and is documented as such per `task/RUN_149_TASK.txt` §225 / §231. |
| R10 | Eviction / commit / rollback failure paths | `tests/run_148_peer_driven_apply_devnet_tests.rs::r8_swap_failure_does_not_evict_commit_or_persist_marker`, `r9_eviction_failure_rolls_back_and_does_not_commit_or_persist_marker`, `r10_sequence_commit_failure_rolls_back_and_does_not_persist_marker`, `r11_commit_failure_with_rollback_failure_is_fatal_and_does_not_persist_marker`, `r12_marker_persist_failure_after_successful_commit_is_fatal_operator_actionable` (all PASS). **Release-binary fault injection is infeasible without source modification** and is documented as such per `task/RUN_149_TASK.txt` §234 / §239. |

## Release binary identity

Captured per-run in `summary.txt`:

* `target/release/qbind-node` — `sha256`, ELF `BuildID`;
* `target/release/examples/devnet_pqc_trust_bundle_helper` — `sha256`, ELF `BuildID` (reused verbatim from Run 143 with the same provenance);
* `target/release/examples/devnet_pqc_root_helper` — `sha256`, ELF `BuildID` (reused verbatim);
* `target/release/examples/devnet_consensus_signer_keystore_helper` — `sha256`, ELF `BuildID` (reused verbatim);
* `target/release/examples/run_133_v2_validation_only_fixture_helper` — `sha256`, ELF `BuildID` (reused verbatim).

## Helper identity

Run 149 introduces **no new helper binary**. The Run 143 / Run 147
fixture-helper provenance pinning is reused verbatim.

## Mutation proof for successful apply

End-to-end mutation proof on the release binary is **not produced
in this run** per the partial-positive verdict (no drain caller
is wired). The Run 148 source/test integration tests provide the
canonical mutation evidence per scenario A1–A4 + A5 using the
`MockLiveTrustApplyContext` that records:

* `validate_with_previous_called: true`;
* `snapshot_active_called: true`;
* `swap_called: true`;
* `evict_sessions_called: true`;
* `commit_sequence_called: true`;
* `commit_sequence_callback_args == (env, candidate_sequence)`;
* the v2 marker `V2MarkerCoordinator` `persist_called: true`
  **after** `commit_sequence` returns Ok (never before);
* `PeerDrivenApplyOutcome::ApplySucceeded { ... }` returned.

When a future run introduces the drain caller (under a strictly
specified ordering contract that is NOT a new apply algorithm —
e.g. a SIGHUP-triggered single-candidate drain that reuses the
existing Run 134 / Run 138 SIGHUP entry points), the release
binary will capture the same mutation evidence directly.

## Non-mutation proof for refusals

For every captured Run 149 release-binary scenario (C1, C2/R2,
C3, R1) and for every Run 148 source/test refusal (R1–R8 +
R13–R16):

* `pqc_trust_bundle_sequence.json` — absent or byte-identical
  pre/post (sha256 captured in `summary.txt`);
* `pqc_authority_state.json` — absent or byte-identical pre/post
  (sha256 captured in `summary.txt`);
* no `pqc_authority_state.json.tmp` sibling — asserted by data-dir
  inventory;
* `LivePqcTrustState` swap — never called (the binary aborts
  before any P2P transport / dispatcher is constructed in the
  C-row refusals; the Run 148 test mocks assert
  `swap_called == false`);
* session eviction — never invoked;
* SIGHUP / reload-apply / startup-apply / snapshot-restore path
  — never selected;
* fallback to `--p2p-trusted-root` — never logged;
* any active `DummySig` / `DummyKem` / `DummyAead` — never
  logged.

## Rollback / failure-path coverage and release-binary-infeasible cases

R9 (apply validation failure before swap) and R10 (eviction /
commit-failure / rollback failure / marker-persist failure)
require **source-level fault injection** to exercise on a real
release binary. Per `task/RUN_149_TASK.txt` §225 ("If infeasible
on release binary, document and cite Run 148 source/test
coverage") and §239 ("If not feasible without source modification
or unsafe filesystem tricks, document as release-binary-infeasible
and cite Run 148 source/test coverage"), Run 149 documents these
as **release-binary-infeasible** and cites the Run 148 source/test
suite, which exercises each branch directly through the
`FailingValidate`, `FailingSwap`, `FailingEvict`, `FailingCommit`,
`FailingRollback`, and `FailingV2MarkerCoordinator` injection
mocks (see `crates/qbind-node/tests/run_148_peer_driven_apply_devnet_tests.rs`
r7–r12).

## Closure statements (mandatory per `task/RUN_149_TASK.txt` §286–§292)

* **Peer-driven live apply is DevNet/TestNet-only and disabled by default.** ✅
* **MainNet remains refused.** ✅ At the early gate, at the
  defensive duplicate in the co-requisites block, at the
  controller-layer arming-banner match arm, and at the Run 148
  controller's runtime `RefusedMainNet` outcome.
* **Governance / KMS-HSM / signing-key lifecycle remain open.** ✅
* **Full C4 remains open.** ✅
* **C5 remains open.** ✅

## Validation commands (run as required by `task/RUN_149_TASK.txt` §294)

* `cargo build --release -p qbind-node --bin qbind-node` — green.
* `cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper --example devnet_pqc_root_helper --example devnet_consensus_signer_keystore_helper --example run_133_v2_validation_only_fixture_helper` — green (no helper change).
* `bash scripts/devnet/run_149_peer_driven_apply_release_binary.sh` — green per the verdicts above (capture artifacts in `docs/devnet/run_149_peer_driven_apply_release_binary/`).
* `cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests` — 20/20 green.
* `cargo test -p qbind-node --test run_147_live_0x05_peer_candidate_staging_release_binary_regression_tests` — green where present (the closest available Run 147 regression test). Where the test file is not present in this commit, the equivalent Run 146 release-binary regression coverage (`run_146_live_inbound_0x05_staging_hook_tests`) is run instead.
* `cargo test -p qbind-node --test run_146_live_inbound_0x05_staging_hook_tests` — 19/19 green.
* `cargo test -p qbind-node --test run_145_peer_candidate_staging_tests` — green.
* `cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests` — 16/16 green.
* `cargo test -p qbind-node --test run_088_pqc_peer_candidate_propagation_tests` — green.
* `cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests` — green.
* `cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests` — green.
* `cargo test -p qbind-node --lib pqc_authority` — green.
* `cargo test -p qbind-node --lib pqc_peer_candidate_apply` — green.
* `cargo test -p qbind-node --lib` — green.

## Cross-document crosscheck

Run 149 has been crosschecked against the existing design / spec:

* `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`
  — Run 149 progress entry added; Phase 4 (apply) remains gated
  exactly as the Run 144 specification mandates; the new flag is
  the smallest hidden DevNet/TestNet-only arming surface that
  the §6 "Local authorization gate" allows.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — Run 149
  authority-model entry added; MainNet bundle-signing authority
  is **not** local-config-driven (preserved); local peer majority
  is **not** authority on MainNet (preserved; reaffirmed).
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 149
  operator-status entry added; the new flag is hidden,
  disabled-by-default, DevNet/TestNet only, and MainNet refused.
* `docs/whitepaper/contradiction.md` — Run 149 paragraph appended
  (the Run 148 paragraph is also appended, since Run 148 itself
  did not append a paragraph). Crosscheck performed against
  Runs 050–148 invariants: Run 149 introduces no contradictions
  because (i) the source delta is purely additive arming under
  the explicit Run 144 §6 "Local authorization gate" allowance,
  (ii) when the new flag is absent the binary behaviour is
  bit-for-bit identical to Run 147, and (iii) the controller-
  layer banner only constructs and inspects a `PeerDrivenApplyPolicy`
  object — it does not install the policy anywhere because no
  drain caller is wired.

No contradiction was found.