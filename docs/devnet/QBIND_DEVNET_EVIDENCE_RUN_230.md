# QBIND DevNet evidence — Run 230

**Title.** Source/test governance evaluator replay and freshness state
boundary.

**Status.** PASS (source/test only). Run 230 adds a typed, pure, fail-closed
**replay and freshness state boundary** for governance evaluator decisions.
Evaluator requests and responses already bind a replay nonce, a freshness
window (`effective_epoch` / `expiry_epoch`), and an expiry; what was still
missing was a typed state boundary that decides — *before* any lifecycle
mutation can happen — whether a given evaluator decision is fresh, not yet
effective, expired, stale, a replay, already consumed, superseded, or bound to
the wrong domain. Run 230 adds exactly that boundary as a pure module composing
the Run 222 evaluator request/response/identity digests and the Run 211
lifecycle action / candidate / sequence binding.

Run 230 is **source/test only**. It implements **no** real governance
execution engine, **no** real on-chain governance proof verifier, **no** real
KMS/HSM backend, **no** real RemoteSigner backend, **no** MainNet governance
enablement, and **no** validator-set rotation. It changes **no** wire, schema,
marker, sequence, or trust-bundle format and introduces **no** RocksDB schema,
file format, or database migration. Release-binary replay/freshness evidence is
deferred to **Run 231**.

## Strict scope

* Source/test evidence only. No release-binary harness (deferred to Run 231).
* Typed pure replay/freshness state boundary only; fail-closed by default.
* No real governance execution engine.
* No real on-chain governance proof verifier.
* No MainNet governance enablement.
* No MainNet peer-driven apply enablement.
* No validator-set rotation.
* No KMS/HSM backend implementation; no RemoteSigner backend implementation.
* No schema/wire/marker/sequence/trust-bundle change.
* No broad storage redesign; no RocksDB/file/schema/migration change.
* No autonomous apply; no automatic apply on receipt; no peer-majority
  authority.
* Run 230 does not weaken any prior run (Runs 070, 130–229) and does not claim
  full C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_evaluator_replay_state.rs`

Run 230 adds a new source module (registered in `lib.rs`) that defines the
typed pure replay/freshness state boundary:

* `ReplayStatePolicy` — `Disabled` (boundary not wired; prior layers
  unchanged), `FixtureDevNet`, `FixtureTestNet`, `Production`, `MainNet`.
* `EvaluatorReplayFreshnessInput` — the typed replay/freshness inputs:
  evaluator source identity digest, evaluator request digest, evaluator
  response digest, evaluator transcript digest, governance execution decision
  digest, proposal id, decision id, lifecycle action, candidate digest,
  authority-domain sequence, effective epoch, expiry epoch, replay nonce,
  environment, chain id, genesis hash, validation surface, current canonical
  epoch, and the optional previously-seen decision state.
* `EvaluatorReplayFreshnessExpectations` — the canonical binding the input is
  checked against (a mismatch is a typed fail-closed, never an approval).
* `PreviouslySeenState` — `FirstSeen`, `Seen(SeenDecisionRecord)`,
  `Unavailable`, `ProductionUnavailable`, `MainNetUnavailable`.
* `ReplayFreshnessState` — the typed state classification: `Fresh`,
  `FreshButNotYetEffective`, `Expired`, `Stale`, `ReplayDetected`,
  `AlreadyConsumed`, `Superseded`, `WrongEpoch`, `WrongEnvironment`,
  `WrongChain`, `WrongGenesis`, `WrongSurface`, `MalformedState`,
  `StateUnavailable`, `ProductionStateUnavailable`, `MainNetStateUnavailable`.
* `EvaluatorReplayFreshnessOutcome` — the typed outcome: `ProceedFresh`,
  `ProceedDeferred`, `FailClosedExpired`, `FailClosedReplay`,
  `FailClosedAlreadyConsumed`, `FailClosedSuperseded`, `FailClosedWrongBinding`,
  `FailClosedStateUnavailable`, `FailClosedProductionUnavailable`,
  `FailClosedMainNetUnavailable`. Only `ProceedFresh` authorizes a mutation;
  `ProceedDeferred` is explicitly **not** an approval for mutation.
* Deterministic digest helpers: `replay_state_key_digest` (binds the
  run-scope A10 set — environment, chain id, genesis hash, source identity
  digest, request digest, response digest, proposal id, decision id, lifecycle
  action, candidate digest, authority-domain sequence, replay nonce),
  `replay_observation_digest`, `consumed_decision_digest`, and
  `freshness_transcript_digest`.
* `GovernanceEvaluatorReplayStateReader` / `GovernanceEvaluatorReplayStateWriter`
  — the pure boundary traits. Reading is non-mutating; only an explicit
  `mark_consumed` records a consumed decision.
* `FixtureReplayStateStore` — an in-memory DevNet/TestNet **source-test only**
  reader/writer. It is the only store that records anything, reads as
  `Unavailable` for a MainNet environment, and introduces no RocksDB/file/schema
  change.
* `ProductionReplayStateReader` / `MainnetReplayStateReader` — callable but
  always unavailable / fail-closed.
* `classify_evaluator_replay_freshness` / `evaluate_evaluator_replay_freshness`
  / `gate_evaluator_replay_freshness` — the pure classification, outcome, and
  policy-gated entry points.

The classification order is deterministic: a MainNet peer-driven drain surface
is refused first; then binding checks (so a wrong-domain decision is rejected
before any freshness or replay reasoning); then reader availability; then
previously-seen replay/consumed/superseded reasoning; then the first-seen
freshness window. Every entry point is pure — it performs no I/O, writes no
marker, writes no sequence, swaps no live trust, evicts no sessions, and never
invokes Run 070 — so replay/freshness rejection necessarily happens before any
mutation.

## Tests

`crates/qbind-node/tests/run_230_governance_evaluator_replay_state_tests.rs`
(52 tests, PASS).

* **A1–A2** — DevNet/TestNet fixture replay state accepts a first-seen fresh
  decision.
* **A3** — fresh-but-not-yet-effective returns `ProceedDeferred` (not an
  approval for mutation).
* **A4–A5** — decision at the effective epoch / before expiry returns
  `ProceedFresh`.
* **A6–A9** — deterministic replay state key / observation / consumed-decision
  / freshness-transcript digests.
* **A10** — the replay state key binds all twelve required fields.
* **A11–A12** — the fixture writer records consumed only after an explicit
  consume call; read-only validation never marks consumed.
* **A13–A14** — production / MainNet readers are callable and return
  unavailable / fail-closed.
* **A15–A16** — Run 224 integration and Run 228 peer context remain compatible
  when the replay state policy is Disabled / not wired.
* **R1–R32** — expired, stale, replay, already-consumed, superseded, wrong
  effective/expiry epoch, wrong environment/chain/genesis/surface, wrong
  source-identity/request/response/transcript digests, wrong proposal/decision
  id, wrong lifecycle action, wrong candidate digest, wrong authority-domain
  sequence, wrong replay nonce, malformed state, state/production/MainNet
  unavailable, local-operator/peer-majority cannot satisfy, validator-set
  rotation unsupported, policy-change action unsupported, validation-only
  rejection writes no marker/sequence, mutating rejection produces no mutation,
  and MainNet peer-driven apply refused even when state is fresh.
* Plus a full first-seen → observe → replay → consume lifecycle test, a
  fixture-store-rejects-MainNet test, and a production/MainNet-writers-never-
  record test.

## Acceptance mapping

* A typed replay/freshness state boundary exists — `ReplayFreshnessState` /
  `EvaluatorReplayFreshnessOutcome`.
* Fresh / expired / stale / replay / consumed / superseded outcomes are
  distinguished.
* Production / MainNet state remains unavailable / fail-closed.
* Read-only validation does not mark consumed; explicit consume marks consumed
  only in the fixture source tests.
* Rejections are non-mutating (the boundary is pure).
* MainNet peer-driven apply remains refused even when state is fresh.
* Validator-set rotation and policy-change actions remain unsupported.
* No storage / schema / migration change is introduced.
* Release-binary evidence is deferred to Run 231.
* No full C4 or C5 closure is claimed.

## Limitations / honest gaps

* Run 230 is source/test only — there is **no** release-binary replay/freshness
  evidence in this run; it is deferred to **Run 231**.
* The `FixtureReplayStateStore` is a DevNet/TestNet in-process map only; it is
  not a persistent store and introduces no storage format.
* Production / MainNet replay state remains unavailable / fail-closed; no real
  governance engine or on-chain proof verifier is implemented.
* MainNet peer-driven apply remains refused.
* Validator-set rotation remains unsupported.
* Full C4 remains OPEN.
* C5 remains OPEN.

## Validation commands

* `cargo build -p qbind-node --lib`
* `cargo test -p qbind-node --test run_230_governance_evaluator_replay_state_tests`
* `cargo test -p qbind-node --test run_228_peer_evaluator_context_representation_tests`
* `cargo test -p qbind-node --test run_226_governance_evaluator_runtime_callsite_wiring_tests`
* `cargo test -p qbind-node --test run_224_governance_evaluator_runtime_integration_tests`
* `cargo test -p qbind-node --test run_222_governance_execution_evaluator_tests`
* `cargo test -p qbind-node --test run_220_governance_execution_runtime_consumption_tests`
* `cargo test -p qbind-node --lib pqc_authority`
* `cargo test -p qbind-node --lib`