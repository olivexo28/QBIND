# RUN 422 — Native authentication key identity and admission contract

**DRAFT / NOT APPROVED / NOT IMPLEMENTED**

This document records current behavior and proposes a future admission contract. It does not change production code, verifier behavior, authorization, resource limits, or deployment posture. All test fixture capacities and budget values below are **UNAPPROVED**.

## Scope and evidence

This is test-and-contract work. `crates/qbind-ledger/src/auth.rs` and all existing production callers remain unchanged. The new characterization suite uses genuine generated ML-DSA-44 keys and signatures, the existing production verifier, the real `TxExecutor`, the existing `analyze_stored_keyset_semantics` and `evaluate_stored_keyset_proofs` APIs, and registered suite adapters for aliases 100 and 101. Fixture alias registration is provider configuration, not governance approval. The exact test-to-control mapping and measured observations are appended to `QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`.

The existing Run 422 resource-harness tests and isolated-helper tests already cover parser/account resource controls, bounded-read evidence, and broader helper workloads; this contract references those results instead of repeating their tests. A direct helper call begins from a test-extracted account byte snapshot and is not evidence that the helper performed a bounded account read.

## Current production behavior

`verify_transaction_auth` rejects empty auth, invalid transaction/auth counts, malformed signer coverage, unsupported transaction version, and nonzero transaction reservations before digest, store, or provider work. It then processes every `TxAuth` sequentially. For each proof, `verify_single_auth` reads its indexed account once, checks returned ID, keyset owner, and non-executable metadata, completely parses the stored framing, checks version and reserved bytes, and rejects a zero threshold. It then selects only the first entry matching that proof's numeric suite ID, requires that entry's individual weight to meet the threshold, looks up the requested suite, confirms the suite-reported ID, and verifies the signature.

The production verifier does **not** request canonical descriptors, compare canonical identities, inspect every entry semantically, aggregate weights across identities, or search later same-suite keys after the first match. An unused entry with an unavailable suite or malformed key encoding is ignored if the first selected entry verifies. Same-suite duplicate weights have a first-entry effect; aliases select by the auth's numeric suite ID. Repeating proofs does not increase weight because every proof independently requires its selected entry's weight to meet the threshold. Production verification remains per proof, including repeated proofs.

The `KeysetProgram` boundary is separate from authentication: a valid native keyset-create call with an absent target reaches `ProgramError("native keyset creation authority unavailable")`. This is an explicit refusal, not successful execution, creation, or positive authority. Authentication failure occurs before dispatch and target access.

## Isolated canonical semantics

`CanonicalKeyDescriptor` identity is the exact tuple:

1. algorithm identifier bytes;
2. parameter identifier bytes; and
3. canonical public-key encoding bytes.

Equality compares all three fields by content. It does not use a numeric suite ID, pointer identity, signature result, key authorization, or backend identity. `MlDsa44SignatureSuite` describes its FIPS 204 ML-DSA-44 encoding under either alias with the same algorithm/parameter identifiers and a borrow of the supplied encoding. A generated distinct key has a distinct descriptor.

`analyze_stored_keyset_semantics` and `evaluate_stored_keyset_proofs` prepare every encoded entry before proof verification. Each entry must resolve to a provider suite whose reported ID equals the requested ID, and its descriptor must be supported, well-formed, canonical, within the identifier-byte budget, and borrow exactly the original key span (same length and pointer). An unavailable suite, suite-ID mismatch, unsupported descriptor, malformed descriptor, noncanonical descriptor, identifier overflow/limit, or descriptor-span mismatch refuses the entire keyset, including an otherwise unused entry. These descriptor failures are distinct from malformed stored-keyset framing: framing is the responsibility of `parse_stored_keyset`, before the isolated APIs receive a view.

Entries with the same descriptor and same weight are one identity. Their weight contributes once to the isolated distinct-key summary even across aliases. Equal identities with different weights are refused as `ConflictingDuplicateWeights`. The isolated proof evaluator repeats semantic preparation and reachability checks before any signature operation, then scans every candidate with a matching suite ID for each supplied proof. It counts verified identity weight once, regardless of repeated proofs. This is diagnostic evidence for one borrowed keyset and digest, not production authentication, common-state admission, or authority.

The provider-reported descriptor is a trust assumption. The API can verify that the returned descriptor obeys its borrowing shape and compare its reported contents; it cannot prove that the provider is authentic, that the implementation is the intended cryptographic backend, or that a suite alias is authorized by registry governance. A real signature operation still uses the provider-selected suite.

## Cross-route characterization and differences

The new source covers:

| Control | Production route | Isolated route | Contract result |
|---|---|---|---|
| Equal bytes in separate buffers under registered aliases 100/101 | Genuine proofs verify independently | One canonical identity and one weight | Suite IDs and addresses are not identity |
| Equal-weight distinct generated key | Production remains suite/first-entry based | Descriptor is distinct | Identity is established using the descriptor API |
| Same-suite and alias conflicts, both encoded orders | Threshold 1 can authenticate; at threshold 2 same-suite order and alias selection determine the production result | At thresholds 1 and 2, both semantic analysis and proof preparation refuse `ConflictingDuplicateWeights` before verification | Refusal is independent of encoded order and selected alias |
| Repeated proofs over one weight-1 identity, threshold 2 | Refuses `selected key weight below keyset threshold` before suite lookup | Refuses `ThresholdUnreachable` before signature verification | This is a reachability refusal, not an invalid-signature result |
| Two distinct same-suite keys with one fixed genuine proof and only key order changed | First wrong key fails; first correct key verifies | Complete scan attempts both candidates and finds the matching key | Production proof selection is intentionally not replaced by this evidence |
| Unused unavailable-suite entry | Selected valid key still authenticates | Refuses `SuiteNotFound` before verification | Complete semantic admission changes acceptance/error ordering |
| Unused malformed key under registered alias, valid framing | Selected valid key still authenticates | Refuses `DescriptorMalformed` before verification | Key encoding fault is not framing failure |
| Valid create, conflicting alias, unused invalid entry | Executor behavior follows production auth; valid auth reaches unavailable-authority refusal and reads absent target | Isolated refusal is diagnostic only | No fixture demonstrates positive authority or successful execution |
| Corrected retry | Not an authorization-policy change | Fresh evaluation of a snapshot with only the conflicting weight corrected succeeds and counts one identity/weight | Transaction and genuine proof remain unchanged |

Full observations, exact attempted signature counts, account-read traces, provider/descriptor work, snapshots, and the per-control fixture-to-result mappings are in the D7 evidence appendix. Existing resource-harness and isolated-helper evidence remains referenced rather than replayed.

## Proposed admission ordering and compatibility

A future semantic-admission integration would parse the complete stored framing and validate metadata, then semantically admit **every** keyset entry, and only then execute the existing production proof-selection rule. The isolated evaluator is not a drop-in replacement for production verification: directly substituting it would additionally change first-match selection into complete candidate search, change proof ambiguity behavior, and use distinct-key weighted aggregation/reachability instead of the current individual-entry threshold rule. Those are independent policy changes and must not be hidden inside “canonical identity admission.”

Whole-keyset admission intentionally changes compatibility. Previously accepted state may newly fail due to unavailable suites, unsupported/malformed/noncanonical descriptors, span mismatch, conflicting alias/same-suite weights, or isolated reachability policy if that policy is also adopted. The exact refusal variant and order relative to threshold checks, provider lookup, signature verification, and target access must be specified. This proposal recommends that complete semantic admission be a pre-proof gate, while leaving current proof selection and individual-weight rule unchanged in the first integration slice. The chosen policy must decide whether semantic and signature errors are distinguishable externally and how existing stored accounts are migrated or grandfathered.

No positive native keyset creation authority, signer governance, payer/fee semantics, transaction replay protection, durable anti-rollback, persistence, or deployed reachability is established here.

## Resource assessment and unresolved policy

The isolated implementation has compile-time workspace capacity `N`. Its semantic record workspace is O(N); proof evaluation additionally holds O(N) candidate references and verified flags. Caller-chosen signature-proof and identifier-byte limits are scalar inputs and do not size the workspace. The implementation returns `EntryCountExceedsWorkspace` when an input exceeds `N`; this task does not approve any protocol or operational capacity.

Admission provider work is one suite lookup and one `suite_id()` observation plus one descriptor call for each encoded entry before signature checks. Duplicate identity detection linearly scans prior distinct descriptors for each entry, giving worst-case O(N²) descriptor comparisons; each equality may compare up to the encoded key span and identifier bytes. This must not be integrated as an unbounded production quadratic scan. Proof work is bounded by the supplied proof count and matching candidates, with up to O(P×N) real verification calls when all entries share the proof suite. Provider, decoder, key-decoding, and cryptographic backend latency/resource use are not bounded by the helper's workspace.

This test fixture uses explicit values only to keep the scenarios small: `N=8`, parser encoded/aggregate-key budget 8192 bytes, maximum entries 8, per-key limit 1312 bytes, identifier budget 32 bytes, maximum proof count 4, per-signature limit 4096 bytes, and aggregate signature limit 8192 bytes. The tested cases use at most two entries and two proofs; the genuine ML-DSA-44 public key is 1312 bytes and signature is below the test limits. None of these test values is a production cap, operational measurement, accepted resource profile, or approved limit.

Before integration, owners must choose and justify: maximum admitted account/keyset bytes; maximum entry count and per-key/aggregate key bytes; a bounded identity-comparison work strategy (or an explicit small cap for N²); supported algorithms/parameter identifiers and maximum identifier bytes; maximum proof count and distinct proof count; per-proof and aggregate signature bytes; provider lookup/descriptor and signature-verification work budgets; deadline/resource failure handling; and whether provider registration/alias identity is trusted or must be bound to an independently governed registry. These are concrete resource-policy and trust decisions, not values inferable from protocol integer widths. All candidate limits remain **UNAPPROVED**.

## Recommended bounded follow-on slice — not implemented

1. Approve an explicit stored-keyset input profile, entry/key/identifier ceilings, and a worst-case descriptor-comparison budget; demonstrate each cap does not pre-empt valid compatibility fixtures.
2. Establish the trust boundary for provider identity, backend implementation, and suite alias registration; specify canonical descriptor error mapping and external error-order compatibility.
3. Add a bounded semantic-preflight gate to the production auth path, using borrowed parsed entries and a bounded identity strategy, before existing proof verification. Preserve first-matching-key selection, individual-weight threshold, transaction semantics, account reads, and program authority in this slice.
4. Add differential tests for the accepted/rejected stored-state corpus and measured worst-case work; separately propose any later proof-selection, weighted aggregation, migration, or authorization change.

This follow-on must not directly substitute `evaluate_stored_keyset_proofs` for production verification, silently choose caps, or enable authority. It requires review and approval before any production change.

## Preserved posture

`D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED`; `D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET`; §13.6 whole-lifecycle **INCOMPLETE**; activation **DISABLED**; public DevNet **NO-GO**; durable anti-rollback **NOT-ESTABLISHED**; C4/C5 **OPEN**; RS1 **OPEN**; all candidate limits **UNAPPROVED**. Whole native-admission and authority contracts remain **DRAFT / NOT APPROVED / NOT IMPLEMENTED**. No full authorization, deployed reachability, operational resource bounds, persistence, replay protection, F1/F2 closure, or release approval is claimed.
