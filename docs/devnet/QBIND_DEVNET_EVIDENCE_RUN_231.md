# QBIND DevNet evidence — Run 231

**Title.** Release-binary governance evaluator replay and freshness state
evidence.

**Status.** PASS (release-binary). Run 231 is the release-binary evidence run
for the Run 230 source/test governance evaluator **replay and freshness state
boundary**. It proves, in release mode, that the replay/freshness boundary
distinguishes fresh, deferred (not-yet-effective), expired, stale, replayed,
already-consumed, superseded, wrong-binding, unavailable, production-unavailable,
and MainNet-unavailable outcomes; that the deterministic digests are stable;
that read-only validation does not consume; that explicit fixture consume marks
consumed only in fixture evidence; that production/MainNet state remains
unavailable/fail-closed; that no mutation can occur from replay/freshness
rejection; and that MainNet peer-driven apply remains refused even when the
state is fresh.

Run 231 is **release-binary evidence only**. It implements **no** real
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
* Does not weaken Runs 070, 130–230, and does not claim full C4 or C5 closure.

## Release helper

`crates/qbind-node/examples/run_231_governance_evaluator_replay_state_release_binary_helper.rs`

The release-built helper exercises the Run 230 replay/freshness symbols through
production library code and emits a tabular PASS/FAIL corpus
(`accepted` / `rejection` / `reachability`) plus a fixture dump (deterministic
digests, before/after fixture replay-store snapshots, and a symbol inventory).

### Accepted / compatible cases (A1–A19)

* **A1–A2** — DevNet / TestNet fixture replay state accepts a first-seen fresh
  evaluator decision (`ProceedFresh`).
* **A3** — fresh but not-yet-effective decision returns `ProceedDeferred`
  (not a mutation approval).
* **A4** — decision at the effective epoch returns `ProceedFresh`.
* **A5** — decision before expiry returns `ProceedFresh`.
* **A6–A9** — replay state key / observation / consumed-decision /
  freshness-transcript digests are deterministic (and field-sensitive) in
  release mode.
* **A10** — the replay state key binds environment, chain id, genesis hash,
  source identity digest, request digest, response digest, proposal id,
  decision id, lifecycle action, candidate digest, sequence, and replay nonce.
* **A11** — the fixture writer records a consumed decision only after an
  explicit consume call.
* **A12** — read-only validation does not mark consumed.
* **A13** — the production replay state reader is callable and returns
  unavailable / fail-closed.
* **A14** — the MainNet replay state reader is callable and returns
  unavailable / fail-closed.
* **A15** — Run 224 integration remains compatible when the replay-state
  policy is `Disabled` / not wired.
* **A16** — Run 228 peer evaluator context remains compatible when the
  replay-state policy is `Disabled` / not wired.
* **A17** — first-seen → observe → replay → consume lifecycle behaves
  deterministically.
* **A18** — explicit consume converts a future same-decision validation to
  already-consumed / fail-closed.
* **A19** — MainNet peer-driven apply remains refused even when the replay
  state is fresh.

### Rejection cases (R1–R32)

R1 expired, R2 stale, R3 replayed, R4 already-consumed, R5 superseded
(explicit + higher recorded sequence), R6 wrong effective epoch, R7 wrong
expiry epoch, R8 wrong environment, R9 wrong chain, R10 wrong genesis, R11
wrong validation surface, R12 wrong source identity digest, R13 wrong request
digest, R14 wrong response digest, R15 wrong transcript digest, R16 wrong
proposal id, R17 wrong decision id, R18 wrong lifecycle action, R19 wrong
candidate digest, R20 wrong authority-domain sequence, R21 wrong replay nonce,
R22 malformed state, R23 state unavailable, R24 production state unavailable,
R25 MainNet state unavailable, R26 local operator cannot satisfy replay-state
policy, R27 peer majority cannot satisfy replay-state policy, R28 validator-set
rotation unsupported, R29 policy-change action unsupported, R30 validation-only
rejection writes no marker and no sequence, R31 mutating rejection produces no
mutation, R32 MainNet peer-driven apply remains refused even when fresh. Every
rejection surfaces as a typed `EvaluatorReplayFreshnessOutcome` fail-closed
variant returned from a pure function.

## Release harness

`scripts/devnet/run_231_governance_evaluator_replay_state_release_binary.sh`

The harness:

* builds `target/release/qbind-node` and the release helper;
* captures the helper binary SHA-256 + ELF Build ID and the `qbind-node`
  release binary SHA-256 + ELF Build ID;
* runs the helper A1–A19 / R1–R32 corpus and asserts `verdict: PASS`;
* runs real-binary surface scenarios (`--help`, default DevNet/TestNet/MainNet,
  hidden governance-execution selector parse + invalid-selector fail-closed)
  and asserts the binary never claims an active replay-state / governance
  surface;
* writes source-reachability grep proof for the Run 230 symbols, the state /
  outcome taxonomies, the digest helpers, the state-key bindings, the
  reader/writer boundary, the read-only path, the explicit consume path, the
  production/MainNet unavailable path, the MainNet peer-driven refusal guard,
  and the apply-authorization guard;
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
* `cargo build --release -p qbind-node --example run_231_governance_evaluator_replay_state_release_binary_helper`
* `bash scripts/devnet/run_231_governance_evaluator_replay_state_release_binary.sh`
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
`docs/devnet/run_231_governance_evaluator_replay_state_release_binary/`
(generated artifacts are `.gitignore`d; `summary.txt` is tracked).

## Acceptance mapping

* Release-built helper exercises the Run 230 replay/freshness state boundary.
* Fresh / expired / stale / replay / consumed / superseded outcomes are
  release-evidenced.
* Production / MainNet state remains unavailable / fail-closed.
* Read-only validation does not mark consumed.
* Explicit consume marks consumed only in fixture evidence.
* Rejections are non-mutating (the boundary is pure).
* MainNet peer-driven apply remains refused.
* Validator-set rotation remains unsupported.
* No storage / schema / migration / RocksDB / file-format change is claimed.
* Existing Run 229, Run 227, Run 225, and Run 223 release behavior remains
  compatible.
* No full C4 or C5 closure is claimed.

## Limitations / honest gaps

* Run 231 is release-binary evidence for a pure, local/source-test-only
  replay/freshness classification layer; the boundary performs no I/O and
  authorizes no mutation directly.
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