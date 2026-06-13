# QBIND DevNet evidence — Run 237

**Title.** Release-binary governance evaluator replay consume runtime
integration evidence.

**Status.** PASS (release-binary). Run 237 is the release-binary evidence run
for the Run 236 source/test governance evaluator **replay consume runtime
integration**. It proves, in release mode, that the integration runs the real
Run 232 replay/freshness runtime integration **before** consume and only reaches
the real Run 234 post-mutation consume boundary on a `ProceedFresh`, and that
the consume step that records a governance decision as consumed runs **only
after a successful mutation** — it is after-success-only. Run 230 proved a typed
replay/freshness state boundary, Run 231 closed its release-binary evidence,
Run 232 composed that boundary into the Run 224 evaluator-runtime integration
path as a mandatory pre-mutation gate, Run 233 closed that composition's
release-binary evidence, Run 234 added the strict after-success-only consume
boundary at the source/test level, Run 235 closed that boundary's release-binary
evidence, and Run 236 composed the consume boundary onto the replay/freshness
runtime integration at the source/test level. Run 237 proves on real
`target/release/qbind-node` plus a release-built helper that the release-built
code exposes and exercises the integration: replay/freshness runs before
consume; fresh is required before mutation authorization; consume is
after-success-only; legacy-bypass, deferred (fresh-but-not-yet-effective),
validation-only, before-apply, failed-apply, rolled-back, unsupported-surface,
and MainNet-refused outcomes never consume; the DevNet/TestNet fixture writer
records consumed only on the explicit after-success path (with a prior
observation), and a re-validation then classifies the decision already-consumed
through the Run 230 state; the production / MainNet consume writers remain
callable but always fail closed unavailable; MainNet peer-driven apply remains
refused and never consumes even when the replay state would otherwise be fresh;
and the consume authorization is overridden with the exact Run 232 freshness
result.

Run 237 is **release-binary evidence only**. It implements **no** real
governance execution engine, **no** real mutation engine, **no** real on-chain
governance proof verifier, **no** real KMS/HSM backend, **no** real RemoteSigner
backend, **no** MainNet governance enablement, **no** MainNet peer-driven apply
enablement, and **no** validator-set rotation. It changes **no** wire, schema,
marker, sequence, or trust-bundle format and introduces **no** RocksDB schema,
file format, or database migration.

## Strict scope

* Release-binary evidence only.
* Uses a release-built helper and the real `target/release/qbind-node` where
  applicable.
* No production source behavior change.
* No real governance execution engine; no real mutation engine; no real
  on-chain governance proof verifier.
* No MainNet governance enablement; no MainNet peer-driven apply enablement.
* No validator-set rotation.
* No KMS/HSM backend; no RemoteSigner backend.
* No RocksDB schema change; no file format change; no database migration; no
  network wire schema change; no trust-bundle / authority-marker / sequence
  schema change.
* No autonomous apply; no automatic apply on receipt; no peer-majority
  authority.
* Does not weaken Runs 070, 130–236, and does not claim full C4 or C5 closure.

## Release helper

`crates/qbind-node/examples/run_237_governance_evaluator_replay_consume_runtime_integration_release_binary_helper.rs`

The release-built helper exercises the Run 236 replay-consume-runtime-integration
symbols through production library code and emits a tabular PASS/FAIL corpus
(`accepted` / `rejection` / `reachability`) plus a fixture dump (outcome tags,
before/after fixture replay-store snapshots, and a symbol inventory). The entry
point is `integrate_replay_consume_runtime`, which runs the real Run 232
replay/freshness runtime integration first and only reaches the real Run 234
post-mutation consume boundary (calling the Run 230
`GovernanceEvaluatorReplayStateWriter` mark-consumed path) on the after-success
consume path.

### Accepted / compatible cases (A1–A23)

* **A1** — legacy bypass does not consume (`ProceedLegacyBypassNoConsume`).
* **A2** — deferred replay/freshness does not consume and authorizes no mutation
  (`ProceedDeferredNoConsume`).
* **A3** — validation-only fresh decision does not consume
  (`ProceedValidationOnlyNoConsume`).
* **A4** — fresh decision authorizes mutation but does not consume before apply
  (`ProceedFreshMutationAuthorized`).
* **A5** — fresh decision plus `AppliedSuccessfully` consumes in DevNet fixture
  only (`ConsumeFixtureAfterMutationSuccess`).
* **A6** — fresh decision plus `AppliedSuccessfully` consumes in TestNet fixture
  only (`ConsumeFixtureAfterMutationSuccess`).
* **A7** — after fixture consume, the same decision re-validates as
  already-consumed / fail-closed through the Run 230 state.
* **A8** — read-only validation path never consumes.
* **A9** — failed apply never consumes (`DoNotConsumeApplyFailed`).
* **A10** — rollback never consumes (`DoNotConsumeRolledBack`).
* **A11** — unsupported surface never consumes
  (`DoNotConsumeUnsupportedSurface`).
* **A12** — MainNet refused never consumes
  (`MainNetPeerDrivenApplyRefused`).
* **A13** — production consume is callable and fails closed unavailable
  (`ProductionConsumeUnavailable`).
* **A14** — MainNet consume is callable and fails closed unavailable
  (`MainNetConsumeUnavailable`).
* **A15** — MainNet peer-driven apply refused even when fresh
  (`is_mainnet_peer_driven_apply_refused`).
* **A16** — a Run 232 `ProceedFresh` projects into an authorized-fresh consume
  reach.
* **A17** — the consume boundary is reached after-success-only.
* **A18** — the integration transcript is stable in release mode and bound to
  the outcome.
* **A19** — the Run 230 replay state key matches across the integration.
* **A20** — Run 230 replay/freshness standalone release behavior remains
  compatible.
* **A21** — replay/freshness runs before consume; the writer is untouched and
  fresh is required on the non-consume path.
* **A22** — a failed apply leaves the writer uncalled and the store length
  unchanged.
* **A23** — the consume authorization is overridden with the exact Run 232
  freshness result (a deferred consume input still consumes when the Run 232
  result is fresh).

### Rejection cases (R1–R35)

R1 expired, R2 stale, R3 replayed, R4 already-consumed, R5 superseded, R6 wrong
environment, R7 wrong chain, R8 wrong genesis, R9 wrong validation surface, R10
wrong mutation surface, R11 wrong source identity, R12 wrong request, R13 wrong
response, R14 wrong transcript, R15 wrong proposal, R16 wrong decision id, R17
wrong lifecycle action, R18 wrong candidate, R19 wrong authority-domain
sequence, R20 wrong replay nonce, R21 malformed replay state, R22 malformed
consume state, R23 consume before apply, R24 consume after failed apply, R25
consume after rollback, R26 consume on a validation-only surface, R27 consume on
an unsupported surface, R28 production consume unavailable, R29 MainNet consume
unavailable / refused, R30 local operator cannot satisfy the consume policy, R31
peer majority cannot satisfy the consume policy, R32 validator-set rotation
unsupported, R33 policy-change action unsupported, R34 a failed apply leaves the
store empty / fail-closed and is never consumed, R35 MainNet peer-driven apply
remains refused and does not consume even when the replay state is fresh. Every
rejection surfaces as a typed `ReplayConsumeRuntimeOutcome` non-consume /
fail-closed variant returned from a pure composition; the writer is never called
on a non-consume path.

## Release harness

`scripts/devnet/run_237_governance_evaluator_replay_consume_runtime_integration_release_binary.sh`

The harness:

* builds `target/release/qbind-node` and the release helper;
* captures the helper binary SHA-256 + ELF Build ID and the `qbind-node`
  release binary SHA-256 + ELF Build ID;
* runs the helper A1–A23 / R1–R35 corpus and asserts `verdict: PASS`;
* runs real-binary surface scenarios (`--help`, default DevNet/TestNet/MainNet,
  hidden governance-execution selector parse + invalid-selector fail-closed)
  and asserts the binary never claims an active consume-runtime-integration /
  governance surface;
* writes source-reachability grep proof for the Run 236 symbols
  (`pqc_governance_evaluator_replay_consume_runtime_integration`,
  `ReplayConsumeRuntimeIntegrationInput`, `ReplayConsumeRuntimeOutcome`,
  `integrate_replay_consume_runtime`, `wire_replay_consume_runtime_callsite`,
  `ConsumeFixtureAfterMutationSuccess`, the replay-before-consume ordering, the
  production / MainNet consume unavailable path, and the MainNet peer-driven
  refusal guard);
* proves an empty denylist across captured logs (no MainNet apply, no
  autonomous apply, no apply-on-receipt, no peer-majority authority, no real
  governance engine / mutation engine / on-chain verifier / KMS / HSM /
  RemoteSigner / custody active claim, no validator-set rotation, no
  RocksDB/file/schema/migration/wire/marker/sequence drift);
* records the no-mutation / mutation proofs;
* runs the regression test targets below.

## Validation commands

* `cargo build --release -p qbind-node --bin qbind-node`
* `cargo build --release -p qbind-node --example run_237_governance_evaluator_replay_consume_runtime_integration_release_binary_helper`
* `bash scripts/devnet/run_237_governance_evaluator_replay_consume_runtime_integration_release_binary.sh`
* `cargo test -p qbind-node --test run_236_governance_evaluator_replay_consume_runtime_integration_tests`
* `cargo test -p qbind-node --test run_234_governance_evaluator_replay_consume_boundary_tests`
* `cargo test -p qbind-node --test run_232_governance_evaluator_replay_runtime_integration_tests`
* `cargo test -p qbind-node --test run_230_governance_evaluator_replay_state_tests`
* `cargo test -p qbind-node --test run_228_peer_evaluator_context_representation_tests`
* `cargo test -p qbind-node --test run_226_governance_evaluator_runtime_callsite_wiring_tests`
* `cargo test -p qbind-node --test run_224_governance_evaluator_runtime_integration_tests`
* `cargo test -p qbind-node --lib pqc_authority`
* `cargo test -p qbind-node --lib`

(Plus the Run 222 / 220 / 217 / 215 / 213 / 211 / 157 / 152 / 150 / 148 / 142
regression targets exercised by the harness.) The exact captured commands,
stdout/stderr logs, per-scenario exit codes, outcome tags, and before/after
fixture-store snapshots are recorded under
`docs/devnet/run_237_governance_evaluator_replay_consume_runtime_integration_release_binary/`
(generated artifacts are `.gitignore`d; `summary.txt` is tracked).

## Acceptance mapping

1. The release-built helper exercises the Run 236 consume runtime integration
   through release library symbols.
2. Replay/freshness runtime integration is release-evidenced as running before
   consume (A16 / A21).
3. Fresh is required before mutation authorization (A4 / A21).
4. Consume is allowed only after successful mutation completion — only
   `ConsumeFixtureAfterMutationSuccess` (after `AppliedSuccessfully`) consumes
   (A5 / A6 / A17).
5. Deferred is not consumed (`ProceedDeferredNoConsume`, A2).
6. Validation-only is not consumed (`ProceedValidationOnlyNoConsume`, A3 / R26).
7. Failed/rolled-back mutation is not consumed (`DoNotConsumeApplyFailed` /
   `DoNotConsumeRolledBack`, A9 / A10 / R24 / R25 / R34).
8. Fixture consume remains DevNet/TestNet evidence-only (A5 / A6).
9. Production / MainNet consume remains unavailable / fail-closed (A13 / A14 /
   R28 / R29).
10. Rejections are non-mutating (the composition is pure; the writer is never
    called on a non-consume path, A22).
11. MainNet peer-driven apply remains refused and does not consume even when the
    state is fresh (A12 / A15 / R35).
12. No storage / schema / migration / RocksDB / file-format change is claimed.
13. Existing Run 235, Run 233, Run 231, Run 229, and Run 227 release behavior
    remains compatible.
14. No full C4 or C5 closure is claimed.

## Limitations / honest gaps

* Run 237 is release-binary evidence for a pure, local/source-test-only replay
  consume runtime integration; the integration performs no I/O and authorizes no
  mutation directly.
* The integration runs the real Run 232 replay/freshness runtime integration
  first and the real Run 234 post-mutation consume boundary only on a
  `ProceedFresh`, over the Run 230 reader/writer traits.
* Fresh is required before mutation authorization; consume is after-success-only
  — only `ConsumeFixtureAfterMutationSuccess` (after `AppliedSuccessfully`)
  authorizes a fixture consume; deferred, validation-only, before-apply,
  failed-apply, rolled-back, unsupported-surface, and MainNet-refused outcomes
  never consume.
* Fixture consume remains DevNet/TestNet evidence-only (the
  `FixtureReplayStateStore` is an in-process map; it reads as `Unavailable` for
  a MainNet environment and introduces no storage format).
* Production / MainNet consume remains unavailable / fail-closed; no real
  governance engine, mutation engine, or on-chain proof verifier is
  implemented.
* No RocksDB / file / schema / migration / storage format change is
  implemented.
* MainNet peer-driven apply remains refused.
* Validator-set rotation remains unsupported.
* Full C4 remains OPEN.
* C5 remains OPEN.