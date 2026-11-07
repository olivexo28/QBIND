# Independently supplied test authority context

**TEST-ONLY AUTHORITY CONTEXT — INDEPENDENT REVIEW PENDING.**

Task base `e531a7c5a96b978cd1b82b006396c08b24e0933e`, tree
`b0af01d91cee4ba1f5e24b8e375dd99a1eb41597`; source main
`9bf0eb43e4e3c601d02d3886d220b0abeb3a103e`, tree
`56509b20084ee1cbe2c42fda9d73d87e4c82c33f`.

The user supplied **PASS WITH LIMITATIONS** for the seven content-binding
controls at the task base. Those remain **PASSED / CLOSED within test-only
scope**, unchanged and not rerun. Accepted R/D/S/M controls and all earlier
bounded evidence are preserved. No reviewer identity, raw report or reviewer
rerun is asserted.

## Separately supplied immutable expectation

Only `crates/qbind-consensus/tests/authority_context_experiment_tests.rs`
is new test code. Each test calls `independently_supplied_fixture()` to create
an expected `Context` **before** cloning witness claims. The caller owns the
expected value and explicitly passes `&Context` to private `test_verify`;
the verifier cannot mutate or replace it. Negative expected-context cases
use distinct local clones rather than mutating a live expected value.
The positive case compares the expected value before/after repeated checks.
No interior mutability, cache, store or production context provider exists.

The fixture supplies chain5, epoch9, label `[a5;32]`, ordered identities
0/1/2/3, four fresh synthetic ML-DSA-44 public keys, weights 2/1/1/1 and
**fixed threshold4** (total weight5). Original endorsements from 0/1/2
give weight4; 0/1 give weight3 and refuse. This is a fixture rule, not a
reviewed quorum/fault assumption. Label-to-context association and the
caller's expected value are **test trust assumptions**, not authenticated
production configuration, a committed validator-set digest, external anchor,
currentness evidence or authority-discovery mechanism.

The witness carries an allocated clone of the full context as explicit
untrusted claims. Strict `test_verify` validates both context shapes, then
compares chain, epoch, label, threshold and every ordered member tuple
(identity, full public bytes, weight). Member reordering also refuses:
the fixture requires exact order, without a normalization protocol.
Witness keys/weights/threshold never replace the expected value in strict
mode. Its statement chain/epoch/label must separately equal expectation.
Neither strict equality nor the label alone authenticates the expectation's
origin or proves that this is the current set.

All member IDs and public-key assignments must be unique, keys exactly1312
bytes, exactly four members, positive weights, checked u64 total, and
threshold in 1..=total. At most four endorsements are allowed; identities
must be unique/authorized and signatures exactly2420 bytes. The verifier
uses the expected member's key/weight, verifies every declared signature
and accumulates checked weight. No early quorum success. Unknown backend
errors panic explicitly; expected invalid signatures have a typed refusal.
Output `Result<u64, Refusal>` reports fixture verified weight only, never
application, signing, durable ownership or resume authority.

## Statement, signatures and allocations

This new target independently implements the same **test-only** complete
statement encoding as the accepted content experiment; it does not import
or modify that target. Exact bytes: ASCII `QBIND-TEST-CBND1` at0..16,
u16 LE version1 at16..18, u16 LE purpose7 at18..20, u64 LE chain at20..28,
u64 LE epoch at28..36, authority32 bytes at36..68, full parent32 bytes
at68..100, u16 LE content length at100..102, then exactly that many content
bytes (0..256). Positive parent is `[3c;32]` and content `[7e;256]`:
102 fixed+256=358 bytes. No new wire decoder/format or commitment choice.
Keys/weights/threshold claims are **not newly signed fields**; they are
checked against separately supplied expected data. The signed authority
label is not a digest of them.

Synthetic setup uses the unchanged
[keygen/sign backend](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-crypto/src/ml_dsa44.rs#L386-L439);
verification uses the unchanged
[raw real wrapper](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-crypto/src/ml_dsa44.rs#L576-L597)
with [serialized sizes](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-crypto/src/ml_dsa44.rs#L36-L43).
`verify_vote` here merely accepts raw statement bytes; the method name is
not consensus Vote authorization. Fixture key lookup associates identity
with the key (the backend ignores its numeric ID argument).
Secret vectors are overwritten/dropped sequentially, not a guarantee about
backend/compiler/allocator erasure. All keys/signatures are synthetic.

At entry, member/key/content/signature vectors and negative clones have
already been allocated. Limits precede statement encoding and crypto,
**not input allocations**. Exactly four member and at most four endorsement
checks bound iteration; duplicate assignments are compared directly.
Trace records successful full context comparisons, encoding invocations,
backend calls and valid accumulated weight.

Separate length accounting (not capacities or total memory):

```text
actually encoded positive statement             358
expected public key lengths                 4*1312 = 5248
separate witness-claimed public key lengths  4*1312 = 5248
three original signature lengths            3*2420 = 7260
sequential serialized setup secret               2560/key
```

Context/bundle accounting is **conceptual**, not an implemented serializer:
context chain8+epoch8+label32+threshold8+u16 count2=58;
each member u16 ID2+weight8+u16 key length2+key1312=1324;
full claimed context=58+4*1324=5354.
Statement+claimed context+u16 endorsement count+
three (u16 ID+u16 signature length+signature)=358+5354+2+3*2424=12986.
Four-entry maximum=15410. The independent expected keys are not folded
into that input bundle; they remain separately retained.

Actual decoded structures, witness/negative clones, expected-context
snapshots, encoded vectors, key objects, secret/signature copies, temporary
buffers and real backend keygen/sign/verify memory/work coexist or occur
separately. Peak/capacity/process/stack/backend memory, execution deadlines,
cancellation and network admission are **UNMEASURED / UNSELECTED**.
Length arithmetic is not a production memory bound or pre-allocation fence.

## Nine executed controls

All cases use the same private `test_verify` and restoration helper. Counts
below are per assertion/subcase, not additional distinct tests.

| Actual test name | Typed result/counter and sensitivity |
|---|---|
| `immutable_expected_context_positive_and_separate_accounting` | Repeated `Ok(4)`, context/encoding/backend/weight 1/1/3/4; expected unchanged; exact length arithmetic. |
| `same_label_substituted_member_or_public_key_refuses_before_crypto` | Member ID7 or fresh key at member2, same label: `ContextMismatch("members/keys/weights/order")`, 0 encoding/crypto; originals restore. |
| `lowered_threshold_and_altered_weight_claims_do_not_override_expected` | Threshold2 or changed weight: explicit context mismatch, crypto0; originals restore. |
| `duplicate_identity_and_key_assignments_refuse_in_expected_and_claims` | Malformed expected and malformed claimed contexts separately: `DuplicateIdentity(0)` / `DuplicateKey`, encoding/crypto0; valid context restores. |
| `duplicate_unauthorized_insufficient_and_corrupt_signatures_refuse` | `DuplicateSigner(0)`, `Unauthorized(7)` before crypto; two signatures valid weight3 give `Insufficient {3,4}` (2 calls); corrupt last gives `InvalidSignature(2)` (3 calls/weight3); original restores. |
| `wrong_chain_epoch_authority_statement_and_other_set_context_refuse` | Claimed chain/epoch/label mismatch; statement chain/epoch `StatementMismatch` before encoding; same-label independent fresh-key expected set mismatches members; original restores each. |
| `trusting_witness_threshold_and_weights_is_detected_by_strict_controls` | Two endorsements insufficient under expected context; strict altered threshold/weight mismatch before crypto. Private `TrustWitness` instead returns `Ok(3)` or `Ok(4)` after2 calls/context matches0; `assert_ne!` detects intended defective behavior; originals restore. |
| `label_only_or_witness_committee_trust_accepts_other_keys_and_is_detected` | Fresh synthetic committee signs the same label/statement; strict mismatch/crypto0. Private label-only and witness-trust both return `Ok(4)`, context matches0/3 calls; strict refusal expectation would fail. Original expected committee restores. |
| `allocated_fixture_bounds_and_invalid_contexts_refuse_without_crypto` | Wrong count/key length/zero threshold/weight overflow/257-byte content/5 endorsements/short signature give specific refusal, encoding/crypto0; restored cases pass. |

Defects are private enum branches in this integration target only. They
illustrate forbidden reliance on witness data, **not security approvals**
or production bypasses. Both retain basic shape and signature checks so the
successful defect is attributable to trust selection, not fake crypto.
**9 discovered / 9 executed / 9 passed / 0 failed / 0 ignored /
0 measured / 0 filtered**; complete outputs/exits and existing37 library
warnings are retained. No accepted or unrelated suite was rerun.

## Limits and integrity

The experiment answers the narrow question: a test-only verifier can compare
witness claims with an independently supplied immutable expected fixture and
use that fixture's keys/weights/threshold. It cannot establish external
authority, quorum/fault assumptions, currentness, finality, historical binding,
durable application, signer authorization/exclusivity/history or resume.
Old signatures cannot be reinterpreted as new context attestations.
No committed set digest, authenticated production trust anchor, protocol
selection, production caller, operational signing or network exists here.

Four existing delivery/index/plan files receive append-only records. All
earlier tests, evidence and audit bytes are preserved. Historical manifests
are checked at their producing revisions, independently of this directory's
current `SHA256SUMS`. Its own hash and commit/tree/parent/direct refs are
reported separately to avoid circular publication identifiers.

Artifact checks passed: four exact historical prefixes,75 byte-identical
prior evidence/Audit files, eleven producing-revision manifests/166 entries,
accepted-test/production/config scope, exact discovery/execution counts,
arithmetic and pinned links. Format check passed. Complete logs and exits
are retained; no unsuccessful execution occurred in this experiment.
Original cargo stdout EOF blank line is preserved as an explicit scoped
whitespace exception, not trimmed.

**B/C remain unselected. A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain OPEN.
Activation remains DISABLED; public DevNet remains NO-GO.**
