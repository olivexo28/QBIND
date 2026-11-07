# Executed test-only binding sensitivity slice

**TEST-ONLY BINDING SENSITIVITY — INDEPENDENT REVIEW PENDING.**

```text
SOURCE_MAIN=9bf0eb43e4e3c601d02d3886d220b0abeb3a103e
TASK_BASE=4ab46f22a66afdfae2363da7da3e493f56155451
TASK_BASE_TREE=1adbf89d1e6221b0b89c8d5866f9e0ef656a741c
BINDING_OPTIONS_B_C=UNSELECTED
PRODUCTION_RECOVERY_OR_CONTENT_BINDING=NOT ESTABLISHED
A17-F1 / RS1-F7=OPEN
RS1=OPEN
A33-F1 / E27=OPEN
ACTIVATION=DISABLED
PUBLIC_DEVNET=NO-GO
```

The user supplied **PASS WITH LIMITATIONS** for the reviewed test-only slice.
The prior budget, entrypoint/oracle and structural-document findings remain
**PASSED / CLOSED** within their documented scopes. AP1, I1, W1/W2 and earlier
bounded acceptances are preserved. No reviewer identity or unavailable raw
review report is asserted. This record attributes actual author executions,
not independent acceptance, release-binary evidence or deployment.

## Scope and execution results

New code is only
`crates/qbind-consensus/tests/binding_sensitivity_slice_tests.rs` and its
integration-test-only module
`crates/qbind-consensus/tests/binding_sensitivity_support/mod.rs`.
The latter is included only by that integration test's `mod` declaration.
Production source, configuration, dependencies, wire formats, safety policy
and existing tests are unchanged. The test target cannot grant signing,
recovery application, quarantine clearance or resume authority. It imports
no node, store, delivery or engine application API.

| Final execution target | Distinct discovered/executed | Passed | Failed | Ignored | Filtered |
|---|---:|---:|---:|---:|---:|
| New `binding_sensitivity_slice_tests` | 21 / 21 | 21 | 0 | 0 | 0 |
| Existing `run_422_d7c3d_qc_domain_verification_tests` | 46 / 46 | 46 | 0 | 0 | 0 |
| Existing `proposal_vote_verify::tests` unit subset | 20 / 20 | 20 | 0 | 0 | 292 |

**87 distinct tests passed in the final executions.** The earlier 20-case
development run is retained but is not added to this distinct count.
Discovery output is preserved separately from execution output; discovery
does not count as a pass. The whole-predicate/gate/scanner bypasses are
deliberately defective **test-only sensitivity controls**. Their acceptance
of a forbidden candidate or invocation of a callback/decoder is evidence
that the assertions detect that defect, not a production-security pass.

Complete cargo commands, stdout, stderr and exits (including the initial
compile failure) are in [COMMANDS.txt](COMMANDS.txt) and `01` through `07`
files. Existing library warnings were retained rather than fixed by changing
production source. The final source and logs are covered by `SHA256SUMS`;
the manifest's own final hash is reported separately.

## R: real synthetic ML-DSA-44 evidence

`Fixture::new` creates four synthetic keypairs with
`qbind_crypto::ml_dsa44::MlDsa44Backend`, suite 100, equal weight, epoch 0,
and a fixed test v2 domain. All signatures are generated during isolated
fixture setup. Secret vectors are overwritten and dropped after setup;
this is not a claim about compiler/backend secret-memory erasure.
No production signer object, credentials or authority are involved.

`CountingRealBackend` implements `ConsensusSigVerifier` and delegates to
the existing real backend; it never fabricates signature success. It counts
actual vote/proposal backend calls. `Keys` counts provider-returned public
key clones. R uses existing `verify_proposal_msg_with_domain`,
`verify_vote_msg_with_domain` and `verify_quorum_certificate_with_domain`.
Those APIs receive already allocated decoded objects.
The pinned
[QC verifier boundary](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L849-L912)
and [crypto loop](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L1059-L1120)
explain signature cloning, owning output duplication and the lack of graph
inputs; [wire decoding](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/consensus.rs#L330-L358)
has already allocated signature vectors.

The exact generated segments are three encoded QCs (7,336 bytes each), one
Proposal canonical body (7,750), one detached Proposal signature (2,420),
and 448 bytes of test-only fixed metadata. Metadata contains four fixed
record tuples, a coherent baseline and genesis identity. Six u64 segment
length descriptors account for another 48 bytes:

```text
nine QC signatures                = 3 * 3 * 2420 = 21780
three QCs incl. field framing      = 3 * 7336     = 22008
Proposal canonical body           =                 7750
detached Proposal own signature   =                 2420
metadata + segment length framing = 448 + 48     =    496
actual enumerated encoded total   =                32674
reviewed upper example            =                32690
encoded fixture cap               =                65536
```

The Proposal body excludes its own signature but includes the embedded QC
and its signature bytes. That duplicate QC is counted again, not silently
shared. R's detached own signature is counted as input. A separately retained
fourth synthetic signature for D controls is **outside R's encoded input**
and separately identified in the retained inventory (2,420 bytes).

The accounting test retains encoded segments, decoded input and three owning
verified QC results simultaneously. The successful results duplicate another
21,780 signature bytes. It prints actual vector capacity/storage observations,
not only lengths: in the final execution the encoded segment capacities sum
to 47,816; three input QCs' byte/outer-vector storage is 22,071; embedded-QC
storage is 7,333; own signature 2,420; transaction outer storage 24 and bytes
256; public keys 5,248; D extra signature 2,420; inline Fixture size 1,272.
These disjoint component observations are **not a full process peak** or a
single enforced memory ceiling. The three returned certificate signatures,
their containers, allocator/map overhead, temporary embedded-QC/canonical/
preimage buffers, reconstructed Vote signature copies, backend stack/heap,
key objects and keygen work remain separate. Backend/allocator/stack working
memory and a total retained/decoded/process-memory cap are **UNMEASURED /
UNSELECTED**. No runtime, cancellation or network-admission guarantee follows.

Serialized setup public keys total 5,248 bytes and secret keys total 10,240,
both reported separately from input. Provider-returned key-clone count is
observed, not treated as retained process memory. Fixture source documents
the test arithmetic reproducing the private block-ID derivation; it does
not invoke or replace that private engine function.

## D/S/M attribution

**D** deliberately creates vectors *before* calling the existing QC verifier.
An oversized signature of 65,536 bytes plus two 2,420-byte signatures and a
one-byte bitmap totals 70,377 byte-vector lengths, below the reviewed
131,072 byte-length-only cap. In the final run, signature vector capacities
total 70,376 and outer-vector storage 72 bytes. Both first and last oversized
positions return `MalformedSignature` with zero backend calls, then restored
valid input invokes three real verifies. This is decoded **pre-crypto**, not
pre-input-allocation refusal; the oversized object is not canonical-encoded.
Duplicate/fourth-signature D cases separately test `SignatureCountMismatch`
and invalid-extra-signature refusal after reaching quorum.

**S** is new test-only scaffolding. `test_admit_fixture_segments` receives
six announced lengths and an uninvoked sentinel materialization callback;
it uses checked total arithmetic including 48 framing bytes and the 65,536
cap. No payload is materialized by the negative descriptor cases. Exact cap
passes only the length gate, not full shape. `test_scan_then_decode` receives
already existing borrowed segments. It scans the bounded R QC bitmap/count/
signature lengths, embedded QC, tx count/length, fixed detached signature,
metadata and exact consumption **before** invoking the existing `WireQc`
decoder. Negative scanner cases have zero decoder calls; valid cases have
three. The intentionally bypassed scanner reaches the decoder once and
preserves its precise `WireError::UnexpectedEof` inside `DecoderFailure`.
No streaming cryptographic QC verifier or production ingress was introduced.

**M** is `test_check_gpb_associations`, a small, test-only association/graph
model. R real verification produces certificate summaries during setup,
then counters reset. M receives already allocated fixed records, summaries,
borrowed content and an independently supplied **test oracle**, plus a
coherent baseline tuple. It never constructs reusable authorization or calls
the private mutating engine method. Changes to the oracle in graph-only
negative cases are explicit: they isolate link/view/epoch predicates and do
not assert authenticated correspondence.

For the monotonic case, A/G/P/B stay at heights/views 9/9, 10/10, 11/11, 12/12.
Only the baseline changes: A passes, G and P return `NonMonotonicEndpoint`,
and restoring A passes. Every case records `earlier_passed=true` and
`monotonic_reached=1`. The same checker with the **whole** monotonic predicate
bypassed accepts both negatives; the expected refusal assertion would fail.
All other prerequisites remain valid. P as independently supplied retained
baseline does not mean this witness newly finalizes P. Historical finality,
currentness and full-prefix coverage are not established.

## Entry-point to executed-case mapping

Names below are the actual integration tests; loop subcases are not counted
as separate tests. `QC` abbreviates the existing owning domain-QC verifier,
`Proposal` / `Vote` the existing message-bound domain entrypoints.

| Test | Boundary / exact checker | Observed outcome and sensitivity |
|---|---|---|
| `r_encoded_accounting_and_retained_duplicates_are_separate` | Allocated fixture + existing encoders/canonical body + QC | Exact segment lengths/total; 9 real backend calls; duplicated result signature lengths 21,780; lengths/capacities separated. |
| `r_proposal_own_signature_excluded_embedded_signatures_included` | Allocated Proposal / canonical body and Proposal | Original/restored `Ok`; own-signature bit flip leaves body unchanged but fails; embedded signature changes body and fails. Four Proposal backend calls. |
| `r_proposal_parent_and_content_mutations_use_same_checker` | Allocated Proposal / Proposal | Parent suffix and tx mutation each `InvalidSignature(0)`; originals pass through same checker. Four calls. |
| `r_each_qc_verifies_three_distinct_real_signatures` | Allocated G/P/B QCs / QC | Each weight 3, threshold 3, signers [0,1,2]; 9 real vote calls. |
| `r_insufficient_weight_restored_third_signer` | Allocated QC / QC | Two real calls then `InsufficientVotingPower {2,3}`; restoring third signer passes (5 cumulative calls). |
| `r_signed_vote_fields_fail_and_restore` | Allocated QC / QC reconstruction + Vote | Block ID, height, round, step mutation yields `InvalidSignature(0)`; restore each yields `Ok` (16 calls). |
| `r_wire_chain_and_authorized_epoch_fail_before_crypto` | Allocated QC / QC preflight | `WireChainMismatch` and `EpochMismatch` with zero calls; original passes (3 calls). |
| `r_genesis_authority_runtime_domains_fail_signature_verification` | Allocated QC, supplied trusted domain / QC | Three wrong domains each `InvalidSignature(0)`; originals restore (12 calls). No currentness claim. |
| `r_outbound_helpers_and_inbound_message_recomputation_are_distinct` | Allocated Vote / v2 helper vs Vote | Captured preimage stays old; inbound recomputation refuses height/version mutation, original passes. Three calls; no caller-supplied inbound preimage API. |
| `r_message_purpose_and_signing_format_bytes_are_authenticated` | Allocated v2 preimage / direct counting real backend | Purpose/format byte mutation `ConsensusSigError::InvalidSignature`; original passes each (4 calls). This is not a future B/C parser or signer check. |
| `r_unauthorized_sparse_member_and_swapped_signature_refuse` | Allocated QC / QC under sparse authority | Unknown index 2 within bitmap span gives `UnknownSigner(2)` after two earlier verifies; swapped signature fails; ordinary authority restores (6 calls). |
| `d_duplicate_entry_and_invalid_extra_signature_are_not_quorum_passes` | Deliberately allocated D / QC | Duplicate entry `SignatureCountMismatch` with zero calls; fourth invalid signature `InvalidSignature(3)` after 4 calls; real fourth signature restores weight 4 (8 total). |
| `d_allocated_late_oversize_signature_refuses_before_any_backend_call` | Deliberately allocated D / QC preflight | First/last oversized signature `MalformedSignature(offender)`, zero calls; original restored invokes three. No pre-allocation attribution. |
| `s_announced_oversize_overflow_and_whole_gate_bypass_sensitivity` | Length descriptors only / test-only admission | `EncodedBudgetExceeded` or `LengthOverflow`, callback 0; bypass callback 1; exact-cap length control callback 1. |
| `s_borrowed_valid_segments_scan_before_real_qc_decoding` | Already allocated borrowed bytes / S then existing decoder | Admission callback 1, decoders 3, crypto 0. |
| `s_borrowed_nested_malformed_truncated_and_padding_prevent_decoding` | Borrowed malformed bytes / S | Nested length, truncation and trailing-byte errors; decoders 0; restored fixture decoders 3. |
| `s_whole_scanner_bypass_is_detected_not_production_security_evidence` | Borrowed malformed count / S | Scanner `ShapeMismatch`, decoder 0; bypass decoder 1 then exact decoder EOF error. Deliberate defect is detected. |
| `m_fixed_g_coherent_baselines_reach_same_monotonic_predicate` | Fixed allocated/borrowed M / model | A `Ok`, G/P `NonMonotonicEndpoint`, restored A `Ok`; earlier predicates passed and monotonic reached once each; bypass accepts negatives; crypto 0 after R setup. |
| `m_missing_qcs_parent_views_endpoint_and_epoch_controls` | M plus explicit graph/oracle mutations / model | Each missing summary, wrong link, equal view, unsupported epoch and B endpoint fail typed model predicates before monotonic (trace 0); restore G passes (trace 1). Crypto 0 after setup. |
| `r_m_qc_does_not_authenticate_external_parent_or_content_oracle` | Unchanged QC vs separate M parent/content | QC remains valid (6 calls), model oracle refuses parent/content substitution; restored model passes. No authenticated binding claim. |
| `isolation_sentinel_oracles_and_test_only_support_have_no_protected_caller` | Sentinel-only `EffectOracle` | Six effect categories start/end at 0; each sentinel attempt fails isolation predicate. No real protected API is connected. Source-scope checks, not a disconnected oracle alone, support caller absence. |

## Limits of the executed evidence

There is no node caller, release binary, multi-node exercise, persistent write,
network delivery, signer ownership/fencing, history-continuity reconstruction,
currentness service, recovery application, quarantine clear or resume.
Decoded-vector QC verification is not a full-parent graph or content-binding
checker. M's oracle is not an authenticated historical binding. S's callback
and borrowed scanner observations are not production network-admission
guarantees. Synthetic cryptographic acceptance does not establish quorum
endorsement of complete content or finality of a recovered prefix. B/C remain
unselected, current refusal stays in force and all previously unexecuted
production/recovery acceptance stages remain FUTURE / NOT EXECUTED.
