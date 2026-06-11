# QBIND DevNet evidence — Run 229

**Title.** Release-binary peer evaluator-context representation evidence.

**Status.** PASS (release-binary). Run 229 is the release-binary evidence run
for the Run 228 governance evaluator **peer evaluator-context representation**
boundary in `crates/qbind-node/src/pqc_governance_evaluator_peer_context.rs`.
Where Run 228 proved at the source/test level that a representable local
`Present` evaluator-context routes through the Run 226 call-site wiring into
the Run 224 governance evaluator runtime integration layer, Run 229 proves on
real `target/release/qbind-node` plus a release-built helper that the
release-built code exposes and exercises the representation boundary entry
points (`evaluate_peer_evaluator_context` and
`evaluate_peer_evaluator_context_wire_only`), the representation type
`GovernanceEvaluatorPeerContext`, the full carrier taxonomy
(`Absent` / `Present` / `Malformed` / `UnsupportedSurface` /
`WireSchemaUnavailable` / `PeerMajorityUnsupported` / `MainNetRefused`), and
the `PeerEvaluatorContextOutcome` taxonomy. Only a routed
`RoutedProceedMutate` authorizes apply; every other outcome is typed
fail-closed.

Run 229 is **release-binary evidence only**. It implements **no** real
governance execution engine, **no** real on-chain governance proof verifier,
**no** real KMS/HSM backend, **no** real RemoteSigner backend, **no** MainNet
governance enablement, and **no** validator-set rotation. It introduces no
production source behavior change.

## Strict scope

* Release-binary evidence only; real `target/release/qbind-node`.
* Release-built helper mints fixture/evaluator/payload material where needed.
* No production source behavior change.
* No real governance execution engine.
* No real on-chain governance proof verifier.
* No MainNet governance enablement.
* No MainNet peer-driven apply enablement.
* No validator-set rotation.
* No KMS/HSM backend implementation; no RemoteSigner backend
  implementation.
* No network wire / trust-bundle / authority-marker / sequence schema change.
* Run 229 does not weaken any prior run (Runs 070, 130–228) and does not
  claim full C4 or C5 closure.

## Deliverables

* Release helper:
  `crates/qbind-node/examples/run_229_peer_evaluator_context_representation_release_binary_helper.rs`
* Release harness:
  `scripts/devnet/run_229_peer_evaluator_context_representation_release_binary.sh`
* Evidence archive:
  `docs/devnet/run_229_peer_evaluator_context_representation_release_binary/`
  (tracks `README.md`, `summary.txt`, `.gitignore`; all other artifacts are
  regenerated and ignored).
* This canonical report.

## Release evidence

The release-built helper exercises the Run 228 peer evaluator-context
representation symbols through production library code over an A1–A18
accepted/compatible corpus and an R1–R27 rejection corpus, plus a reachability
corpus, all in release mode (total 170 checks, 0 failures):

* the default Disabled-policy + absent-carrier path preserves **legacy
  validation behavior** (`LegacyValidationPreserved`) for both live inbound
  `0x05` and peer-driven drain;
* a `Present` DevNet/TestNet fixture context binds selected policy, candidate
  digest, evaluator request/response digests, lifecycle action, sequence,
  environment, chain id, and genesis hash, and routes through the Run 226
  wiring into the Run 224 integration, reaching `RoutedProceedMutate` where
  representable, or a typed `UnsupportedSurface` / `WireSchemaUnavailable`
  fail-closed where not representable — never a silent approval;
* a missing/unsupported/malformed carrier under an explicit evaluator policy
  is typed fail-closed (`MissingContextRejected` / `UnsupportedSurface` /
  `MalformedRejected`);
* the live wire inability to carry an evaluator binding is represented as the
  typed `WireSchemaUnavailable` status, which is fail-closed and **never an
  approval**;
* the production / on-chain / MainNet evaluator boundaries are reachable and
  return the typed unavailable / fail-closed (`RoutedFailClosed`) outcome;
* invalid live inbound `0x05` context is **not propagated, not staged, not
  applied**; invalid peer-driven drain context produces **no apply**;
* **MainNet peer-driven apply remains refused** (`MainNetRefused`) even with a
  fixture evaluator approval;
* every rejection is pure and non-mutating, and the only apply-authorizing
  outcome is the terminal `RoutedProceedMutate`
  (`is_apply_authorized()` true);
* the carrier taxonomy (`Absent` / `Present` / `Malformed` /
  `UnsupportedSurface` / `WireSchemaUnavailable` / `PeerMajorityUnsupported` /
  `MainNetRefused`) is fully release-evidenced.

The real `target/release/qbind-node` scenarios confirm the help output and
the default DevNet/TestNet/MainNet surfaces make no peer evaluator-context
claims, that a hidden governance-execution policy selector still parses, and
that an invalid governance-execution policy selector **fails closed before
mutation** (`no marker write; no sequence write; no live trust swap; no
session eviction; no Run 070 call`). Source and module reachability greps
confirm the Run 228 representation symbols, the carrier taxonomy, the selected
policy / load-status / payload-digest / evaluator source/request/response
digest / candidate trust-bundle digest / candidate v2 marker digest /
authority-domain sequence / lifecycle-action / environment-chain-genesis
bindings, the live inbound `0x05` and peer-driven drain validation-surface
bindings, the Run 226 integration routing, and the MainNet peer-driven refusal
guard. A 26-pattern denylist is proven empty across the captured logs.

Captured metadata includes the helper and `qbind-node` SHA-256 + ELF Build
IDs, the git commit, rustc/cargo versions, exact commands, stdout/stderr
logs, per-scenario exit codes, evaluator-context digests, evaluator
source/request/response digests, governance-execution payload digests, peer
candidate/trust-bundle digests, integration outcome values, carrier taxonomy
outcome values, and the denylist grep results. See
`docs/devnet/run_229_peer_evaluator_context_representation_release_binary/summary.txt`.

## Representability limitation (documented honestly)

The Run 228 peer evaluator-context boundary is a local/source-test-only
representation layer. The binary marker/candidate metadata cannot yet carry a
governance proposal/decision evaluator binding, so the **live inbound `0x05`**
and **peer-driven drain** surfaces are represented but their full positive
evaluator binding is not yet wire-representable from the binary: the live wire
carrier inability is the typed `WireSchemaUnavailable` status, never an
approval. Full positive `RoutedProceedMutate` authorization with a fixture
proposal binding is exercised through the release-built helper, which uses the
same library symbols a future production call site would.

## Invariants restated

* Run 229 is release-binary peer evaluator-context representation evidence.
* The peer evaluator-context boundary is local/source-test and does not change
  wire/schema/marker/sequence/trust-bundle formats.
* Missing/unsupported carrier status is typed and fail-closed under an
  explicit evaluator policy.
* `WireSchemaUnavailable` is not approval.
* Invalid live inbound `0x05` candidates are not propagated, staged, or
  applied.
* Invalid peer-driven drain candidates are not applied.
* MainNet peer-driven apply remains refused.
* Production/on-chain/MainNet evaluators remain unavailable/fail-closed.
* Fixture/emergency fixture evaluators remain non-production.
* Validator-set rotation remains unsupported.
* No real governance engine or on-chain proof verifier is implemented.
* Existing Run 227 call-site wiring, Run 225 integration-layer, and Run 223
  evaluator-interface release behaviour remains compatible.
* Full C4 remains OPEN.
* C5 remains OPEN.

## Validation commands

* `cargo build --release -p qbind-node --bin qbind-node`
* `cargo build --release -p qbind-node --example run_229_peer_evaluator_context_representation_release_binary_helper`
* `bash scripts/devnet/run_229_peer_evaluator_context_representation_release_binary.sh`
* `cargo test -p qbind-node --test run_228_peer_evaluator_context_representation_tests`
* `cargo test -p qbind-node --test run_226_governance_evaluator_runtime_callsite_wiring_tests`
* `cargo test -p qbind-node --test run_224_governance_evaluator_runtime_integration_tests`
* `cargo test -p qbind-node --test run_222_governance_execution_evaluator_tests`
* `cargo test -p qbind-node --test run_220_governance_execution_runtime_consumption_tests`
* `cargo test -p qbind-node --test run_217_governance_execution_runtime_arming_tests`
* `cargo test -p qbind-node --test run_215_governance_execution_policy_selector_tests`
* `cargo test -p qbind-node --test run_213_governance_execution_payload_callsite_tests`
* `cargo test -p qbind-node --test run_211_governance_execution_policy_tests`
* `cargo test -p qbind-node --test run_157_unified_testnet_fixture_universe_tests`
* `cargo test -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests`
* `cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests`
* `cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests`
* `cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests`
* `cargo test -p qbind-node --lib pqc_authority`
* `cargo test -p qbind-node --lib`
