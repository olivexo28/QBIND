# P1 provider-to-verifier test-only handoff

**P1 PROVIDER-TO-VERIFIER TEST — INDEPENDENT REVIEW PENDING.** User-supplied
PASS WITH LIMITATIONS at
[`25a03a1e82aca9643ea86f8368a3c6cedfe2826f`](https://github.com/olivexo28/QBIND/tree/25a03a1e82aca9643ea86f8368a3c6cedfe2826f)
places P1-IMPL-1 PASSED/CLOSED within the test-only model. P1-SPEC-1/2/3 and
earlier bounded acceptances remain unchanged. No reviewer identity or raw
review artifact is invented.

## Actual boundary

The [accepted provider](https://github.com/olivexo28/QBIND/blob/25a03a1e82aca9643ea86f8368a3c6cedfe2826f/crates/qbind-consensus/tests/p1_provider_model_tests.rs)
owns a fixture snapshot, admits only matching context, and invokes a sentinel
only after provider, lease, fixture, simulated currentness and evidence-frame
checks. Its callback receives the admitted `Candidate`, not an authority
capability. The new nested test module accesses this *same* private model
without changing its behavior or making its types public. A new standalone
test target includes the existing target as a module, so its 19 pre-existing
tests run alongside three new tests. The original target also includes these
three because of the one added test-module declaration.

The [authority-context experiment](https://github.com/olivexo28/QBIND/blob/25a03a1e82aca9643ea86f8368a3c6cedfe2826f/crates/qbind-consensus/tests/authority_context_experiment_tests.rs)
performs test-only context validation, comparison, statement encoding and
weighted checks before invoking the backend; the [content-binding experiment](https://github.com/olivexo28/QBIND/blob/25a03a1e82aca9643ea86f8368a3c6cedfe2826f/crates/qbind-consensus/tests/content_binding_experiment_tests.rs)
uses its own hypothetical complete-statement encoding and count checks.
These helpers are private to separate integration-test crates; neither is
silently copied or made production API. Both call the public
[`MlDsa44Backend.verify_vote`](https://github.com/olivexo28/QBIND/blob/25a03a1e82aca9643ea86f8368a3c6cedfe2826f/crates/qbind-crypto/src/ml_dsa44.rs#L576-L585),
whose [trait](https://github.com/olivexo28/QBIND/blob/25a03a1e82aca9643ea86f8368a3c6cedfe2826f/crates/qbind-crypto/src/consensus_sig.rs#L100-L113)
receives validator ID, public key, preimage bytes and signature. This backend
implementation ignores the ID and verifies the key/message/signature; it
does not validate authority, membership, threshold or a consensus QC.

The new test uses one synthetic member, threshold one, a newly generated
test-only keypair, and exactly the constant bytes
`QBIND-TEST-P1-HANDOFF-v1:synthetic-statement` as the signed message. Secret
bytes are not logged and are zeroed after fixture signing. The provider scans
the same bounded one-entry evidence frame from which the handoff extracts
the signature, then the callback compares the witness candidate to the
provider-admitted snapshot and selects that snapshot's key. Only then is the
real backend called. This is not the previous hypothetical statement encoding
or a consensus vote preimage, and the constant message does **not** encode
or cryptographically bind the candidate, chain, epoch, contents or parent.
The fixture equality check is test-only context selection, not signed context
authentication. A separate success sentinel records only a successful test
verification; neither sentinel grants any application or participation power.

## Controls and retained observations

See `focused.log.gz` for named tests and printed summaries, and the
`crates/qbind-consensus/tests/support/p1_provider_verifier_handoff.rs` source for
the exact stage assertions. All evidence is synthetic; the counters are test
instrumentation and not production telemetry.

| Test | Observation |
|---|---|
| `matching_corrupted_and_restored_signature_reach_real_backend` | Live bound fixture/lease and Available advance fixture, lease, currentness, evidence-scanner and callback counters. Original, one-byte-corrupted signature and restored original invoke the real backend once each: success, `InvalidSignature`, success; success sentinel 1/0/1. |
| `same_label_witness_replacement_strict_and_defective_selection_oracle` | Same numeric label, distinct valid generated keys: strict context check refuses B before backend; the private witness-selection mutant invokes the real backend on B's valid signature and succeeds but fails the *same* selected-context oracle; strict A is restored and passes. |
| `currentness_and_provider_lifetime_refuse_before_backend_then_replacement_succeeds` | Same-ID B as the fixture argument refuses at the provider fixture check. Stale, Unknown and Unavailable each reach the simulated currentness predicate but not callback/backend. Replacing A with B rejects A's old lease at provider identity; new B rejects A witness and verifies B. Destroyed B refuses before backend. Available A and B positives are asserted. |

Focused target: 22 passed, 0 failed, 0 ignored, 0 filtered (19 included
provider tests plus 3 handoff tests); the directly affected original provider
target also passed 22/22. `discovery.log.gz`, `provider-regression.log.gz`,
`COMMANDS.txt` and `SHA256SUMS` retain commands, names, raw outputs and hashes.

The independent fixture and currentness are simulations, not authenticated
production provenance or a rollback-resistant external authority. One real
signature on a constant test message is not quorum agreement on full content,
historical finality, or per-block committed-prefix coverage. Nothing establishes
durable application, signing-history continuity, signer exclusivity, fencing,
or a separately authorized resume. P1/P2 production approaches and B/C remain
unselected; the narrow founder scope and catch-up containment are unchanged.
There is no production source change, operational signing or live activity.

A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain OPEN.
Activation DISABLED; public DevNet NO-GO.
