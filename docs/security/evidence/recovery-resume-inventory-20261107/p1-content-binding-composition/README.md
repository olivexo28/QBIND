# P1 provider and content-binding composition

**P1 CONTENT-BINDING COMPOSITION — INDEPENDENT REVIEW PENDING.** The
user-supplied PASS WITH LIMITATIONS at
[`af3110da83a5555da5307b981e276f1cff9d058b`](https://github.com/olivexo28/QBIND/tree/af3110da83a5555da5307b981e276f1cff9d058b)
accepts the three handoff controls within their test-only scope. P1-IMPL-1,
P1-SPEC-1/2/3, the content experiment and all earlier bounded acceptances
remain in their previous scopes. No reviewer identity or raw review artifact
is asserted.

## Reuse and explicit mapping

The [accepted provider](https://github.com/olivexo28/QBIND/blob/af3110da83a5555da5307b981e276f1cff9d058b/crates/qbind-consensus/tests/p1_provider_model_tests.rs)
checks bound fixture, live instance/lease, independently simulated currentness,
and bounded evidence framing before the callback. Its unchanged snapshot
selects the verifier context; a separate witness candidate is compared
field-for-field to that snapshot. The
[previous handoff](https://github.com/olivexo28/QBIND/blob/af3110da83a5555da5307b981e276f1cff9d058b/crates/qbind-consensus/tests/support/p1_provider_verifier_handoff.rs)
remains byte-identical.

The existing [content experiment](https://github.com/olivexo28/QBIND/blob/af3110da83a5555da5307b981e276f1cff9d058b/crates/qbind-consensus/tests/content_binding_experiment_tests.rs)
is included as a nested test module. Its existing `Fixture::new`,
`test_verify`, and `test_encode` are used directly; no verifier is copied.
Only the necessary test-crate-local visibility is widened, without changing
test bodies, encoder, verifier, fixed threshold or production APIs. Its
verifier checks duplicate/unauthorized IDs and signature sizes before
encoding, calls the real
[`MlDsa44Backend.verify_vote`](https://github.com/olivexo28/QBIND/blob/af3110da83a5555da5307b981e276f1cff9d058b/crates/qbind-crypto/src/ml_dsa44.rs#L576-L585)
once per entry, and requires three verified entries from four keys. The backend
itself ignores the validator ID and verifies supplied key, bytes and
signature. These are test assumptions, not an approved quorum policy.

Fixture setup calls the existing experiment's synthetic key generator and
signer once, constructs the independent provider fixture from the generated
public-key catalog, and separately supplies its witness claims and
endorsements. Secret keys stay in the fixture generator and are zeroed as in
the existing test. No expected fixture is selected from witness claims at
use. All four members have weight one and the provider threshold is three.
The adapter refuses any other threshold, member count or weight; only after
that equality does the experiment's fixed 3-of-4 verifier apply. For member
index `i` in `0..4`, provider identity is `u16(i)` little-endian in the first
two bytes followed by 30 zero bytes; the verifier signer ID is that same `i`.
The adapter checks all 32 bytes and ordering before extracting fixture-owned
keys; it does not equate arbitrary provider IDs with integers.

The test mapping requires provider `network` to equal the statement's chain
`u64` in little-endian followed by 24 zeros; `schema_version`, `purpose`,
`epoch`, and `authority` equal the corresponding statement fields. This is
an explicit test-only convention, not a production chain-ID encoding.
The experiment signs its 16-byte `QBIND-TEST-CBND1` tag, version and purpose
u16 LE, chain and epoch u64 LE, 32-byte authority, 32-byte parent, u16 LE
content length, and content bytes. Parent and statement content are supplied
to the experiment and are not compared to the provider candidate's `content`.
The witness candidate is independently compared in full to the snapshot;
provider genesis, applicability, provenance source, policy, member identities,
keys, weights, threshold and candidate content are **not in the signed
statement bytes**. Test-only comparison does not make them signed or
authenticated. Signer IDs are checked by the experiment separately and are
not part of those signed statement bytes.

The composition generates the bounded scanner frame from the same
endorsement signature byte vectors passed to the existing verifier; signer
IDs are separate inputs to the test verifier. The provider callback counter
is separate from successful verification: duplicate/unauthorized cases
enter the callback but do not reach the backend.

## Executed controls

| Test | Result and boundary |
|---|---|
| `composition_parent_content_mutations_and_restored_positive` | Matching endorsements pass with three backend calls. Independently altered parent and content reach encoding and the first real signature predicate, each returning `InvalidSignature(0)`; restored original passes. Callback counts are separate from verification-success counts. |
| `composition_duplicate_unauthorized_and_insufficient_stage_controls` | Duplicate signer 0 and unauthorized signer 4 refuse in the existing verifier before encoding/backend. Two valid distinct endorsements invoke the backend twice and then refuse `Insufficient { have: 2, need: 3 }`; a full matching positive is restored after each negative. |
| `composition_same_label_selection_mutant_preserves_real_verification` | Same-label, independently generated B keys/signatures: strict context comparison refuses before backend. The private witness-selection mutant verifies all three B signatures yet fails the same bound-context selection oracle; A restores and passes. |
| `composition_currentness_replacement_and_destroyed_lease_precede_verification` | Stale and Unknown reach the simulated currentness predicate; replacement and destruction refuse at provider identity/liveness. None enters the callback or real backend. Available A passes; explicit replacement invalidates A's lease, and new admission of B verifies B. |
| `composition_requires_exact_fixture_threshold_weights_and_identity_mapping` | Valid fixture variants with threshold two, weight two, noncanonical identity or noncanonical network refuse at mapping before verifier. The original fixture restores and passes. |

Focused target: 34 passed, 0 failed/ignored/filtered: 19 original provider,
3 prior handoff, 7 existing content, and **5 distinct new composition tests**.
Directly affected provider and handoff targets also each run the same 34
bodies; standalone content target runs its same 7. These repeated executions
are regressions, not additional distinct tests. See `COMMANDS.txt`, compressed
raw logs, `check_artifacts.py`, and `SHA256SUMS`; one intermediate standalone
regression compile failed and is retained, then corrected and rerun.

The fixture is not authenticated production provenance; simulated
currentness is neither freshness nor rollback resistance. Hypothetical
content endorsements are not existing Vote/QC semantics, historical
finality or per-block recovery evidence. Verification is not durable
application, signing-history continuity, signer fencing, or an independently
authorized resume. B/C and production P1/P2 remain unselected; no protocol,
wire format, signing rule, production source, operational key or live
activity is authorized. Narrow founder scope and catch-up containment remain.

A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain OPEN.
Activation DISABLED; public DevNet NO-GO.
