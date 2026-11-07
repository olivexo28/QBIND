# Isolated hypothetical complete-statement experiment

**TEST-ONLY CONTENT BINDING — INDEPENDENT REVIEW PENDING.**

Base: `4162a9c20b2686f6a4d662e7e487eb536073e37a`, tree
`27068454296bc4bf4980e79b79b50d41d2406431`. Protected source main:
`9bf0eb43e4e3c601d02d3886d220b0abeb3a103e`, tree
`56509b20084ee1cbe2c42fda9d73d87e4c82c33f`.

The user supplied **PASS WITH LIMITATIONS** for the R/D/S/M slice. Its
specified controls and 87 distinct author-reported passing tests are
**PASSED / CLOSED within their reviewed scope**. They were neither changed
nor rerun here. No reviewer identity, raw report or reviewer rerun is asserted.
Earlier bounded acceptances remain preserved.

## Exact hypothetical statement

Only `crates/qbind-consensus/tests/content_binding_experiment_tests.rs`
implements this experiment. Its private `test_encode` concatenates these
bytes, without padding, hashing, implicit fields or host-endian encoding:

| Byte range (half-open) | Representation | Positive fixture |
|---|---|---|
| 0..16 | ASCII tag, 16 bytes | `QBIND-TEST-CBND1` |
| 16..18 | version u16 little-endian | 1 (`01 00`) |
| 18..20 | purpose u16 little-endian | 7 (`07 00`) |
| 20..28 | chain u64 little-endian | 5 |
| 28..36 | epoch u64 little-endian | 9 |
| 36..68 | test authority/set label, 32 bytes | `a5` repeated 32 times |
| 68..100 | complete parent identity, 32 bytes | `3c` repeated 32 times |
| 100..102 | content length u16 little-endian | 256 (`00 01`) |
| 102..102+length | content, length 0..256 inclusive | `7e` repeated 256 times |

Thus fixed overhead=102 bytes; maximum/positive statement=358 bytes.
The accounting test compares the **entire encoded vector** with an
independently assembled explicit byte sequence. All content bytes and its
length are signed; the tag makes this test statement distinct from a Vote,
Proposal or proposed recovery protocol. There is no decoder or new wire type.
Limits are checked on already allocated structured inputs before producing
the encoding, not before their input allocations.

The independently supplied **fixed test committee** is an array of four
fresh synthetic public keys mapped to IDs 0,1,2,3, each fixture weight one.
Three unique valid signatures suffice; at most four endorsements are admitted.
The `a5` label has only this fixture's declared association to that array:
it is not a derived set commitment, trust-discovery service or authoritative
mapping. Caller-supplied public keys and statement meanings are test
assumptions. The checker authenticates bytes rather than selecting supported
real-world chain/epoch/purpose/version values. No approved fault/quorum
model, signer rule, threshold derivation, equivocation rule or consensus
finality is inferred from the fixture rule.

Existing backend sources are pinned:
[synthetic keygen and raw signing](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-crypto/src/ml_dsa44.rs#L386-L439),
[real verification wrapper](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-crypto/src/ml_dsa44.rs#L576-L605)
and [serialized sizes](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-crypto/src/ml_dsa44.rs#L36-L43).
Fixture setup uses `generate_keypair` and `sign`; `test_verify` delegates
raw bytes to `MlDsa44Backend.verify_vote`. The method name does **not** turn
the arbitrary preimage into a consensus Vote. No existing Proposal/Vote/QC
domain verifier or production signer is changed or given new meaning.
Serialized setup secrets are overwritten then dropped sequentially; this
does not claim backend/compiler/allocator erasure.

## Verification boundary and seven executed cases

Private `test_verify` first checks endorsement count<=4, authorized index,
uniqueness and exact signature length=2420 for every entry. It then invokes
bounded `test_encode`, verifies every signature (no early quorum success),
and requires three verified entries. Results are `Result<usize, Refusal>`,
not reusable authority or evidence for application. Any unknown backend
failure panics the test explicitly instead of returning success or silently
converting it into an expected signature refusal.

`Trace` exposes encoding calls, real-backend calls and successfully verified
entries. All inputs, keys and endorsement vectors already exist at entry.

| Actual test function | Same checker / observable outcome and restoration |
|---|---|
| `exact_complete_encoding_and_separate_fixture_accounting` | `test_encode`: full vector equality, lengths and separate bundle/key arithmetic. |
| `sufficient_unique_synthetic_signatures_pass_and_restore` | `test_verify`: two original runs `Ok(3)`, encoding/backend/verified counters 1/3/3 each. |
| `every_complete_field_mutation_refuses_original_signatures_and_restores` | Seven field mutations, including parent byte31/content byte255: each `InvalidSignature(0)`, counters 1/1/0; original restoration `Ok(3)` with three backend calls each. |
| `duplicate_unauthorized_and_insufficient_entries_never_add_weight` | Repeated ID0 `Duplicate(0)` and ID4 `Unauthorized(4)` before encoding/crypto; two unique entries verify twice but return `Insufficient {2,3}`; originals restore `Ok(3)`. |
| `omitted_field_defects_accept_substitutions_and_are_detected` | Same encode/verify path with only a private test defect: seven independently generated defective-signature fixtures accept the corresponding substitution, three calls. Complete encoding refuses these defective signatures; fresh complete fixtures reject mutations and restore originals. |
| `omitted_uniqueness_defect_counts_one_signer_three_times_and_is_detected` | Same checker: strict duplicate refusal, private bypass incorrectly returns `Ok(3)` after three checks of one signature; one entry is insufficient; three distinct originals restore. |
| `allocated_oversized_or_malformed_inputs_refuse_before_encoding_and_crypto` | Allocated 257-byte content `ContentTooLarge` and late 2419-byte signature `SignatureLength(2)` with zero encoding/backend calls; five entries `TooManyEndorsements`; corrupt last signature refuses after 3 calls/2 verified; originals restore. |

Omission defects replace the chosen field's bytes with zero before signing
**and** verification; for content they retain the length but omit every
content byte. This models loss of value binding without a second parser.
Signatures are freshly produced over these defective bytes, never
reinterpreted complete-statement or historical signatures. `assert_ne!`
controls demonstrate that the intended strict-refusal assertion would fail.
Uniqueness bypass likewise exposes forbidden successful weight, not a
production-security pass. All defect switches are private in this one
integration target; no production bypass exists.

Author execution: **7 discovered / 7 executed / 7 passed / 0 failed /
0 ignored / 0 measured / 0 filtered**. Loop subcases are not extra tests.
Discovery is not execution. First compilation failed because the initial tag
literal was 17 rather than 16 bytes; only the new test literal/expected bytes
were corrected. Complete commands, stdout/stderr/exits are in
[COMMANDS.txt](COMMANDS.txt) and `01`..`03` files; existing 37 library warnings
are preserved. No unrelated accepted suite was rerun.

## Separate byte and resource accounting

The statement encoding is actually materialized. The following bundle is
**an accounting convention only**, not a new serializer/parser or wire format:
statement bytes, u16 endorsement count, and for each entry u16 ID + u16
signature length + signature. Its boundaries are unambiguous by the content
length, count and entry lengths, but no bundle decoder is introduced.

```text
positive statement                     102 + 256 = 358
three signature lengths                3 * 2420 = 7260
count + three entry framing             2 + 3*4 = 14
positive conceptual encoded bundle      358+7260+14 = 7632
maximum four-entry bundle               358+2+4*(4+2420) = 10056
separately retained public key lengths  4 * 1312 = 5248
sequential serialized setup secret      2560 bytes/key
```

This is not total retained memory. Decoded fixture inputs, encoded vectors,
expected-byte vectors, clones/mutations, key objects, keygen/sign/verify work,
allocator capacities/overhead, temporary signature/key copies and backend
heap/stack coexist or occur separately. Peak memory/capacities/work/runtime,
cancellation and network admission are **UNMEASURED / UNSELECTED**.
The seven-case omitted-field loop creates its own fresh keys, not a single
production bounded key pool. Input caps do not bound all negative-test
allocations or prior materialization. No production resource guarantee follows.

## Non-results and publication

This shows synthetic real signatures authenticate the exact hypothetical
bytes and that explicit fixture uniqueness is necessary for fixture weight.
It does not establish validator pre-sign checks, conflict prevention,
quorum finality, G/P/B or historical attestations, full-prefix finality,
currentness, safe/durable application, ownership, signer history/exclusivity,
clearance or permission to resume. Old signatures cannot be reinterpreted as
signing these new bytes. B/C remain unselected. No selected commitment,
consensus/recovery wire format, protocol activation or migration is implied.

All historical documents/logs/tests and audit-register bytes are preserved.
Only the new test target, this new evidence directory and four append-only
plan/index/delivery files change. Producing-revision manifests are verified
separately from this directory's current `SHA256SUMS`; its own hash and
publication commit/tree/parent/direct refs are reported outside the commit
to avoid circularity. No production caller, store mutation, network delivery,
operational signing, activation, PR, merge or main push.

Final artifact checks passed: four preserved byte prefixes, 53 byte-identical
historical evidence/Audit files and ten producer manifests/129 entries.
The first integrity-script attempt failed on a git path separator ambiguity;
its full error/output/exit are retained as `05-integrity.*`, followed by the
successful `06-final-integrity.*`. Format check passed. Original cargo stdout
EOF blank line is preserved, explicitly excepted from scoped whitespace.

**B/C remain unselected. A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain OPEN.
Activation remains DISABLED; public DevNet remains NO-GO.**
