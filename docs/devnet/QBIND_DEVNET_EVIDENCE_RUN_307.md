# QBIND DevNet Evidence — Run 307

Source/test live validator-set application / epoch-transition **authorization**
boundary implementation.

Run 307 is **source/test only**. It is **not** release-binary evidence.
Release-binary evidence is deferred to Run 308.

---

## 1. Exact verdict

**PASS — Run 307 source/test live validator-set application / epoch-transition
authorization boundary implemented.**

A new narrow source/test boundary consumes a verified Run 305/306 non-mutating
validator-set rotation *application decision* (the accepted
`ProductionValidatorSetRotationApplicationDecision` output that `is_accept()`
and carries `Some(application_intent)`) and produces a typed, deterministic,
policy-gated, **non-mutating** live-application authorization intent for a
future mutating epoch-transition executor (Run 308+). Default posture is
`Disabled` / fail-closed. MainNet stays refused, no live validator set,
consensus state, epoch counter, or trust state is mutated,
`BasicHotStuffEngine::transition_to_epoch` is never called, `meta:current_epoch`
is never written, no `PAYLOAD_KIND_RECONFIG` block is injected, and Full C4 / C5
remain OPEN. The new live validator-set application authorization matrix row
moves Red → Yellow (source/test implementation landed, release-binary evidence
pending Run 308). The pre-existing Run 305/306 validator-set rotation
application row stays Green-for-scope.

---

## 2. Files changed

New:

* `crates/qbind-node/src/pqc_production_live_validator_set_application_authorization.rs` — boundary module.
* `crates/qbind-node/tests/run_307_production_live_validator_set_application_authorization_tests.rs` — 135 source/test cases.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_307.md` — this evidence report.

Modified:

* `crates/qbind-node/src/lib.rs` — registered `pub mod pqc_production_live_validator_set_application_authorization;`.
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — added a new live validator-set application authorization row Red → Yellow; refreshed status line; added Run 307 changelog entry.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`, `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`, `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`, `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`, `docs/whitepaper/contradiction.md` — narrow Run 307 changelog entries.

---

## 3. Boundary design summary

`ProductionLiveValidatorSetApplicationAuthorizationExecutor` takes:

* a `ProductionLiveValidatorSetApplicationAuthorizationRequest` (a
  `LiveValidatorSetApplicationAuthorizationAuthoritySource` plus optional
  custody / attestation / durable-replay bindings, an epoch-transition target,
  and a live-application nonce),
* `ProductionLiveValidatorSetApplicationAuthorizationInputs` (operator-trusted
  expected values, trust domain, evidence requirements, replay/freshness
  anchors), and
* a `LiveValidatorSetApplicationAuthorizationReplaySet`.

`evaluate_live_validator_set_application_authorization` returns a
`ProductionLiveValidatorSetApplicationAuthorizationDecision` carrying a typed
`ProductionLiveValidatorSetApplicationAuthorizationOutcome`, an
`authorization_id`, a `request_id`, an optional
`ProductionLiveValidatorSetApplicationAuthorizationIntent`, an intent digest,
and a transcript digest.

---

## 4. Authority source

The only accepted authority source is
`VerifiedApplicationDecision { decision }` where the Run 305/306
`ProductionValidatorSetRotationApplicationDecision` `is_accept()` **and** carries
`Some(application_intent)`. Every other source
(`MissingApplicationDecision`, `UnverifiedApplicationDecision`,
`AcceptedDecisionWithoutApplicationIntent`,
`RotationPlanWithoutApplicationDecision`,
`GovernanceExecutionIntentWithoutApplicationDecision`,
`GovernanceProofWithoutApplicationDecision`, `LocalOperatorAssertion`,
`PeerMajorityAssertion`, `CustodyOnlyEvidence`, `RemoteSignerOnlyEvidence`,
`CustodyAttestationOnlyEvidence`, `FixtureOnlyApplicationDecision`,
`ArbitraryValidatorSetBytes`) is rejected with a precise fail-closed outcome.

---

## 5. Fail-closed default

The default `ProductionLiveValidatorSetApplicationAuthorizationPolicy` is
`Disabled` and the default config kind is `Disabled`; the boundary returns
`Disabled` before any application binding or authorization construction.

---

## 6. Policy / kind gating

`Disabled` fails first. MainNet trust domain or MainNet binding environment is
refused (`MainNetRefused`, or `MainNet…Unavailable` under the MainNet policy).
The production and MainNet policies fail closed as unavailable (no production
authority wired). The reserved production kind fails closed as unavailable.
Config/inputs well-formedness is required.

---

## 7. Application-decision binding

The bound `application_decision_id`, `application_request_id`,
`application_intent_digest`, and `application_transcript_digest` must equal the
operator-trusted expected values, and the carried application intent must
reproduce its digest (`intent.intent_digest() == decision.intent_digest`) or the
boundary returns `ApplicationDecisionIntegrityMismatch`.

---

## 8. Governance / rotation / validator-set binding

The full re-exposed tuple (environment, chain, genesis, authority root,
governance domain/epoch/proposal, governance execution ids/digests, rotation
ids/digests, lifecycle/rotation actions, authority sequence, quorum, threshold,
current/proposed/delta digests, validator-set epoch/version, proposed validator
count, rotation nonce) is bound to expected inputs, each with a precise
`Wrong…` outcome.

---

## 9. Epoch-transition + nonce binding

The request's `proposed_epoch_transition_target` must equal both
`expected_epoch_transition_target` and the application intent's
`epoch_transition_target`; the application intent's `application_nonce` must
equal `expected_application_nonce`.

---

## 10. Evidence composition

Represented custody / attestation / durable-replay bindings must match both the
operator-trusted expected bindings and the application intent's carried bindings
(where present), else a precise `…Mismatch` / `…Required` outcome.

---

## 11. Replay / freshness

A caller-owned `LiveValidatorSetApplicationAuthorizationReplaySet` (read-only)
rejects a replayed `authorization_id`. Stale governance epoch, authority
sequence, validator-set epoch, and validator-set version are rejected. All
digests are deterministic, domain-separated SHA3-256; never wall-clock, never
`Debug`-formatted.

---

## 12. Recovery / idempotency

`recover_live_validator_set_application_authorization_window` is non-mutating:
`NoPriorAuthorizationWindow`, `IdempotentReplayObserved`, and `RecoveryDisabled`
write no durable state.

---

## 13. Output authorization intent

`ProductionLiveValidatorSetApplicationAuthorizationIntent` re-exposes the full
application tuple plus the bound application-decision authority tuple, the
epoch-transition target, and the live-application nonce. It is
`is_non_mutating()` and only authorizes a *future* mutation run.

---

## 14. Tests

`crates/qbind-node/tests/run_307_production_live_validator_set_application_authorization_tests.rs`
carries 135 source/test cases (Groups A–F): accepted authorizations,
authority-source + wrong-field rejections, MainNet/authority policy refusal,
replay/recovery/idempotency, non-mutation invariants, and C4/C5 taxonomy.
Each accepted case composes the real Run 303 rotation boundary → real Run 305
application executor → Run 307 authorization executor. `135 passed; 0 failed`.

---

## 15. Non-mutation / non-wiring guarantees

* No default runtime wiring and no CLI flag were added; the boundary is inert
  unless explicitly constructed and invoked in source/test.
* MainNet remains refused.
* The boundary produces authorization intents only; it never applies a live
  validator-set change, never transitions a consensus epoch, never calls
  `BasicHotStuffEngine::transition_to_epoch`, never writes `meta:current_epoch`,
  never injects a `PAYLOAD_KIND_RECONFIG` block, never calls Run 070, and never
  mutates `LivePqcTrustState`.

---

## 16. C4/C5 status

Full C4 remains **OPEN**. C5 remains **OPEN**. Run 307 does not close either and
does not weaken any prior Green-for-scope status.

---

## 17. Suggested Run 308 next step

Build a real `target/release/qbind-node` plus a release-built helper, exercise
the Run 307 live validator-set application authorization boundary in release
mode, prove verified source/test DevNet/TestNet application decisions produce
only typed non-mutating authorization intents, prove
missing/unverified/rotation-plan-alone/governance-proof-alone/
governance-execution-intent-alone/fixture/local-operator/peer-majority/
custody-only/remote-signer-only/custody-attestation-only/arbitrary-bytes
rejection, prove wrong-field / epoch-transition / nonce / replay / freshness /
evidence fail-closed behavior, prove production binary surfaces remain
Disabled/silent with no CLI flag, preserve prior Green-for-scope rows, keep
MainNet authority rotation/revocation Red, and preserve Full C4 OPEN / C5 OPEN.