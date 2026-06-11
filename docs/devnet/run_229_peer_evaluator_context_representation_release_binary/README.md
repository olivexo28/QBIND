# Run 229 — Release-binary peer evaluator-context representation evidence

## Scope

Run 229 is the release-binary evidence run for the Run 228 source/test
governance evaluator **peer evaluator-context representation** boundary in
`crates/qbind-node/src/pqc_governance_evaluator_peer_context.rs`:

* the representation type `GovernanceEvaluatorPeerContext`
  (`.surface`, `.carrier_status`, `.selected_policy`, `.evaluator_policy`,
  `.load_status`, `.governance_execution_payload_digest`,
  `.evaluator_source_identity_digest`, `.evaluator_request_digest`,
  `.evaluator_response_digest`, `.candidate_trust_bundle_digest`,
  `.candidate_v2_marker_digest`, `.authority_domain_sequence`,
  `.lifecycle_action`, `.environment`, `.chain_id`, `.genesis_hash`,
  `.context_digest()`, `.present_bindings_complete()`,
  `.binds_consistently_with()`);
* the carrier taxonomy `PeerEvaluatorCarrierStatus`
  (`Absent`, `Present`, `Malformed`, `UnsupportedSurface`,
  `WireSchemaUnavailable`, `PeerMajorityUnsupported`, `MainNetRefused`);
* the boundary entry points `evaluate_peer_evaluator_context` and
  `evaluate_peer_evaluator_context_wire_only`;
* the `PeerEvaluatorContextOutcome` taxonomy
  (`LegacyValidationPreserved`, `RoutedProceedMutate`, `RoutedFailClosed`,
  `UnsupportedSurface`, `WireSchemaUnavailable`, `MalformedRejected`,
  `MissingContextRejected`, `PeerMajorityUnsupported`, `MainNetRefused`) and
  its predicates (`is_apply_authorized`, `is_legacy_validation_preserved`,
  `is_fail_closed`, `is_mainnet_refused`,
  `no_propagation_no_staging_no_apply`).

A representable `Present` context routes through the Run 226 call-site wiring
(`wire_governance_evaluator_runtime_callsite`) into the Run 224 integration
layer (composing Run 220 runtime consumption + Run 222 evaluator interface +
Run 211 decision validation + Run 213 payload material). Only a routed
`RoutedProceedMutate` authorizes apply; every other outcome is typed
fail-closed.

Where Run 228 proved the boundary at the source/test level, Run 229 proves on
real `target/release/qbind-node` plus a release-built helper
(`crates/qbind-node/examples/run_229_peer_evaluator_context_representation_release_binary_helper.rs`,
driven by
`scripts/devnet/run_229_peer_evaluator_context_representation_release_binary.sh`)
that the release-built code exposes and exercises the representation boundary:

* the default Disabled-policy + absent-carrier path preserves **legacy
  validation behavior** (`LegacyValidationPreserved`) for both live inbound
  `0x05` and peer-driven drain;
* a `Present` DevNet/TestNet fixture context routes through the Run 226
  wiring into the Run 224 integration and reaches `RoutedProceedMutate` where
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
* every rejection is pure and non-mutating (the boundary is a pure function),
  and the only apply-authorizing outcome is the terminal
  `RoutedProceedMutate`;
* the carrier taxonomy (`Absent` / `Present` / `Malformed` /
  `UnsupportedSurface` / `WireSchemaUnavailable` / `PeerMajorityUnsupported` /
  `MainNetRefused`) is fully release-evidenced.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`.
Everything else is regenerated and ignored:

```text
provenance.txt
logs/
data/
exit_codes/
helper_evidence/run_229/
reachability/
grep_summaries/
test_results/
negative_invariants.txt
mutation_proof.txt / no_mutation_proof.txt
```

## Reproduce

```bash
bash scripts/devnet/run_229_peer_evaluator_context_representation_release_binary.sh
```

The harness is idempotent: it wipes and regenerates generated artifacts while
preserving the three tracked files.

## Honest limitations

* The Run 228 peer evaluator-context boundary is a local/source-test-only
  representation layer. The binary marker / candidate metadata cannot yet
  carry a governance proposal/decision evaluator binding, so the **live
  inbound `0x05`** and **peer-driven drain** surfaces are represented but
  their full positive evaluator binding is not yet wire-representable from the
  binary: the live wire carrier inability is the typed `WireSchemaUnavailable`
  status, never an approval. Full positive `RoutedProceedMutate` authorization
  with a fixture proposal binding is exercised through the release-built
  helper, which uses the same library symbols a future production call site
  would.
* The default Disabled legacy bypass is preserved bit-for-bit, so the Run 227
  call-site wiring, Run 225 integration-layer, and Run 223 evaluator-interface
  behaviour are unchanged.
* The boundary changes **no** network wire schema, trust-bundle schema,
  authority-marker schema, or sequence schema.
* No real governance execution engine is implemented. Production / on-chain /
  MainNet evaluators are reachable but always return the typed unavailable /
  fail-closed outcome, regardless of the resolved policy.
* No real on-chain governance proof verifier is implemented.
* The fixture evaluator remains DevNet/TestNet evidence-only and is refused
  on a MainNet trust domain.
* The emergency-council fixture evaluator is explicit and non-production.
* The boundary is pure: it performs no network or file I/O, writes no marker,
  writes no sequence, mutates no live trust, evicts no sessions, and never
  invokes Run 070 apply. Validation-only and mutating-surface rejection paths
  therefore perform no mutation, and the only apply-authorizing outcome is the
  terminal `RoutedProceedMutate`.
* No real KMS / HSM backend, no real RemoteSigner backend, and no production
  signing-key custody; KMS/HSM/RemoteSigner/custody-attestation remain
  boundary-only and unchanged.
* Validator-set rotation remains unsupported.
* MainNet peer-driven apply remains refused (Run 147 FATAL invariant) even
  with a fixture evaluator approval.
* Full C4 remains open. C5 remains open.