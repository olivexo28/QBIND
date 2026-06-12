# QBIND DevNet evidence — Run 233

**Title.** Release-binary governance evaluator replay/freshness runtime
integration evidence.

**Status.** PASS (release-binary). Run 233 is the release-binary evidence run
for the Run 232 source/test governance evaluator **replay/freshness runtime
integration**. It proves, in release mode, that the Run 230 replay/freshness
state boundary is composed into the Run 224 / Run 226 evaluator runtime
integration path as a mandatory pre-mutation gate; that fresh is required
before mutation authorization; that deferred (fresh-but-not-yet-effective) is
not a mutation approval; that expired, stale, replayed, already-consumed, and
superseded decisions fail closed before mutation; that wrong-binding,
malformed, unavailable, production-unavailable, and MainNet-unavailable states
fail closed; that read-only validation does not mark consumed; that explicit
fixture consume marks consumed only in fixture evidence; that production/MainNet
replay state remains unavailable/fail-closed; that no mutation can occur from a
replay/freshness rejection; and that MainNet peer-driven apply remains refused
even when the replay/freshness state is fresh.

Run 233 is **release-binary evidence only**. It implements **no** real
governance execution engine, **no** real on-chain governance proof verifier,
**no** real KMS/HSM backend, **no** real RemoteSigner backend, **no** MainNet
governance enablement, **no** MainNet peer-driven apply enablement, and **no**
validator-set rotation. It changes **no** wire, schema, marker, sequence, or
trust-bundle format and introduces **no** RocksDB schema, file format, or
database migration.

## Strict scope

* Release-binary evidence only.
* Uses a release-built helper and the real `target/release/qbind-node` where
  applicable.
* No production source behavior change.
* No real governance execution engine; no real on-chain governance proof
  verifier.
* No MainNet governance enablement; no MainNet peer-driven apply enablement.
* No validator-set rotation.
* No KMS/HSM backend; no RemoteSigner backend.
* No RocksDB schema change; no file format change; no database migration; no
  network wire schema change; no trust-bundle / authority-marker / sequence
  schema change.
* No autonomous apply; no automatic apply on receipt; no peer-majority
  authority.
* Does not weaken Runs 070, 130–232, and does not claim full C4 or C5 closure.

## Release helper

`crates/qbind-node/examples/run_233_governance_evaluator_replay_runtime_integration_release_binary_helper.rs`

The release-built helper exercises the Run 232 replay/freshness runtime
integration symbols through production library code and emits a tabular
PASS/FAIL corpus (`accepted` / `rejection` / `reachability`) plus a fixture
dump (composed outcome tags, before/after fixture replay-store snapshots, and a
symbol inventory). The composed entry point is
`integrate_governance_evaluator_replay_runtime`; the call-site / peer-context
wiring entry points are
`wire_governance_evaluator_replay_runtime_callsite` and
`wire_governance_evaluator_replay_runtime_peer_context`.

### Accepted / compatible cases (A1–A17)

* **A1** — `Disabled` policy + absent carrier preserves `ProceedLegacyBypass`;
  the replay/freshness boundary is never reached.
* **A2** — DevNet fixture evaluator decision with fresh replay state reaches
  `ProceedFresh` (mutation authorized; runtime consumption accepted, evaluator
  authorized, lifecycle / candidate / sequence bound).
* **A3** — TestNet fixture evaluator decision with fresh replay state reaches
  `ProceedFresh`.
* **A4** — not-yet-effective decision reaches `ProceedDeferred` (the Run 224
  layer still authorizes a mutate on its own, but the composed outcome is a
  deferral and **not** a mutation authorization).
* **A5** — fresh decision at the effective epoch reaches `ProceedFresh` only
  after the evaluator and the replay state both agree.
* **A6** — explicit fixture consume marks consumed only after a successful
  fixture authorization (caller-side, fixture-only).
* **A7** — read-only validation does not mark consumed.
* **A8** — the production replay reader is reached and fails closed unavailable.
* **A9** — the MainNet replay reader is reached and fails closed
  unavailable/refused.
* **A10** — MainNet peer-driven apply remains refused even when the replay
  state is fresh.
* **A11** — `ProceedFresh` is the only replay/freshness outcome that authorizes
  a mutation.
* **A12** — `ProceedDeferred` is release-evidenced as not an approval.
* **A13** — the Run 230 replay/freshness boundary release behavior remains
  compatible.
* **A14** — the Run 231 replay/freshness standalone release behavior remains
  compatible.
* **A15** — the Run 228 peer evaluator context behavior remains compatible.
* **A16** — the Run 226 call-site integration behavior remains compatible.
* **A17** — the Run 224 evaluator runtime integration behavior remains
  compatible.

### Rejection cases (R1–R27)

R1 expired, R2 stale (degenerate window), R3 replayed, R4 already-consumed, R5
superseded, R6 wrong environment, R7 wrong chain, R8 wrong genesis, R9 wrong
validation surface, R10 wrong source identity, R11 wrong request digest, R12
wrong response digest, R13 wrong transcript digest, R14 wrong proposal id, R15
wrong decision id, R16 wrong lifecycle action, R17 wrong candidate digest, R18
wrong authority-domain sequence, R19 wrong replay nonce, R20 malformed replay
state, R21 replay state unavailable, R22 production replay state unavailable,
R23 MainNet replay state unavailable/refused, R24 validator-set rotation
unsupported, R25 policy-change action unsupported, R26 validation-only rejection
writes no marker and no sequence, R27 mutating rejection produces no Run 070
call, no live trust swap, and no mutation. Every rejection surfaces as a typed
`GovernanceEvaluatorReplayRuntimeOutcome` fail-closed variant
(`ReplayFreshnessFailClosed`, `RuntimeIntegrationFailClosed`, or
`MainNetPeerDrivenApplyRefused`) returned from a pure function.

## Release harness

`scripts/devnet/run_233_governance_evaluator_replay_runtime_integration_release_binary.sh`

The harness:

* builds `target/release/qbind-node` and the release helper;
* captures the helper binary SHA-256 + ELF Build ID and the `qbind-node`
  release binary SHA-256 + ELF Build ID;
* runs the helper A1–A17 / R1–R27 corpus and asserts `verdict: PASS`;
* runs real-binary surface scenarios (`--help`, default DevNet/TestNet/MainNet,
  hidden governance-execution selector parse + invalid-selector fail-closed)
  and asserts the binary never claims an active replay-runtime / governance
  surface;
* writes source-reachability grep proof for the Run 232 symbols, the composed
  outcome taxonomy, the entry point and the wiring entry points, the
  fresh-before-mutation gate, the deferred-is-not-approval guard, the
  production/MainNet unavailable path, the MainNet peer-driven refusal guard,
  and the rotation/policy-change unsupported guards;
* proves an empty denylist across captured logs (no MainNet apply, no
  autonomous apply, no apply-on-receipt, no peer-majority authority, no real
  governance engine / on-chain verifier / KMS / HSM / RemoteSigner / custody
  active claim, no validator-set rotation, no `--p2p-trusted-root` fallback, no
  active DummySig/DummyKem/DummyAead, no RocksDB/file/schema/migration/wire/
  marker/sequence drift, no marker write before sequence commit, no
  marker/sequence write on validation-only surfaces);
* records the no-mutation / mutation proofs;
* runs the regression test targets below.

## Validation commands

* `cargo build --release -p qbind-node --bin qbind-node`
* `cargo build --release -p qbind-node --example run_233_governance_evaluator_replay_runtime_integration_release_binary_helper`
* `bash scripts/devnet/run_233_governance_evaluator_replay_runtime_integration_release_binary.sh`
* `cargo test -p qbind-node --test run_232_governance_evaluator_replay_runtime_integration_tests`
* `cargo test -p qbind-node --test run_230_governance_evaluator_replay_state_tests`
* `cargo test -p qbind-node --test run_228_peer_evaluator_context_representation_tests`
* `cargo test -p qbind-node --test run_226_governance_evaluator_runtime_callsite_wiring_tests`
* `cargo test -p qbind-node --test run_224_governance_evaluator_runtime_integration_tests`
* `cargo test -p qbind-node --test run_222_governance_execution_evaluator_tests`
* `cargo test -p qbind-node --test run_220_governance_execution_runtime_consumption_tests`
* `cargo test -p qbind-node --lib pqc_authority`
* `cargo test -p qbind-node --lib`

(Plus the Run 217 / 215 / 213 / 211 / 157 / 152 / 150 / 148 / 142 regression
targets exercised by the harness.) The exact captured commands, stdout/stderr
logs, per-scenario exit codes, digests, and before/after fixture-store
snapshots are recorded under
`docs/devnet/run_233_governance_evaluator_replay_runtime_integration_release_binary/`
(generated artifacts are `.gitignore`d; `summary.txt` is tracked).

## Acceptance mapping

1. The release-built helper exercises the Run 232 replay/freshness runtime
   integration through release library symbols.
2. Fresh is required before mutation authorization in release evidence (only
   `ProceedFresh` authorizes a mutation, and only after the replay/freshness
   validation returns fresh).
3. Deferred is not approval in release evidence (`ProceedDeferred`).
4. Expired / stale / replayed / consumed / superseded decisions fail closed
   before mutation.
5. Read-only validation does not consume.
6. Explicit consume remains fixture-only.
7. Production / MainNet replay state remains unavailable / fail-closed.
8. Rejections are non-mutating (the composition is pure).
9. MainNet peer-driven apply remains refused even when the state is fresh.
10. No storage / schema / migration / RocksDB / file-format change is claimed.
11. Existing Run 231, Run 229, Run 227, Run 225, and Run 223 release behavior
    remains compatible.
12. No full C4 or C5 closure is claimed.

## Limitations / honest gaps

* Run 233 is release-binary evidence for a pure, local/source-test-only
  replay/freshness runtime integration; the composition performs no I/O and
  authorizes no mutation directly.
* The composition layers the Run 224 evaluator runtime integration, the Run 226
  call-site wiring, the Run 228 peer evaluator context, and the Run 230
  replay/freshness state boundary as a mandatory pre-mutation gate.
* Fixture replay state remains DevNet/TestNet evidence-only (the
  `FixtureReplayStateStore` is an in-process map; it reads as `Unavailable` for
  a MainNet environment and introduces no storage format).
* Production / MainNet replay state remains unavailable / fail-closed; no real
  governance engine or on-chain proof verifier is implemented.
* Read-only validation does not mark consumed; explicit consume marks consumed
  only in fixture evidence.
* No RocksDB / file / schema / migration / storage format change is
  implemented.
* MainNet peer-driven apply remains refused.
* Validator-set rotation remains unsupported.
* Full C4 remains OPEN.
* C5 remains OPEN.