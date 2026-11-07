# P1 nested evidence scanner-control correction

**P1 NESTED EVIDENCE CONTROL CORRECTION — INDEPENDENT REVIEW PENDING.**

Documentation-only addendum for the evidence scanner fixtures in the P1
provider-model correction. User-supplied review carries P1-SPEC-1 and
P1-SPEC-2 as PASSED/CLOSED at specification level. P1-SPEC-3 framing,
segmentation, descriptor correspondence and arithmetic are accepted; only
isolation of nested evidence-limit controls remains open. This addendum
addresses only that remaining scope. It does not reopen or repeat accepted
work, implement the model, or modify production/test code.

The original specification and previous correction, their evidence and the
audit register remain unchanged. All cases below are **FUTURE / NOT
EXECUTED** and are scanner/framing fixtures only, not cryptographic
signature-verification evidence.

## 1. Retained outer-size controls (not nested controls)

Retain the existing outer-size controls:

* 16,384-byte candidate-envelope descriptor: descriptor-size predicate
  passes only; 16,385 refuses at the envelope outer-size predicate.
* 19,389-byte evidence frame: evidence outer-size boundary accepted;
  19,390 refuses at the evidence outer-size predicate.
* 35,773-byte combined candidate-plus-evidence input: combined arithmetic
  boundary accepted when component lengths and checked sum agree. A claimed
  segment above its own cap is rejected at that component's outer-size gate;
  it is not credited to the combined or nested predicate.
* Checked-add overflow, if exercised directly at the descriptor arithmetic
  helper, is an outer arithmetic refusal and is not credited to a nested
  evidence predicate.

The 19,390 and combined-overflow cases refuse at the outer-size stage. They
must **not** be reported as reaching the nested entry-count or entry-length
predicate. Conversely, all nested controls below have a valid frame whose
actual length equals its declared total and whose evidence length is well
below 19,389 bytes. Use the already specified valid 11,339-byte maximum
candidate envelope as the separate candidate segment. Thus even the largest
nested negative (2,436 evidence bytes) has combined length
`11,339 + 2,436 = 13,775`, below the 35,773-byte combined ceiling.

## 2. Exact evidence frame and stage observations

Use the existing test-only evidence framing:

```text
8 bytes   ASCII magic "QBE1TEST"
4 bytes   u32 little-endian declared total length, including header
1 byte    u8 declared entry count
repeated declared-count times:
  2 bytes u16 little-endian entry length
  N bytes payload, exactly N bytes
```

The minimum header is 13 bytes. No padding or trailing data is allowed.
For every fixture, the header total equals the actual byte-slice length,
count equals the number of encoded entries, each entry length equals its
payload bytes, checked offsets consume the slice exactly, and the separate
candidate/evidence length and combined-length gates pass before nested
checks.

Record these distinct scanner observations:

* `evidence_outer_size_checks == 1`: evidence and combined byte caps passed.
* `evidence_frame_checks == 1`: magic, declared total versus actual length,
  exact frame consumption, entry boundaries, and framing consistency passed.
* `evidence_count_checks == 1`: the nested count predicate was reached.
* `evidence_entry_length_checks == 1`: the nested per-entry length predicate
  was reached.
* `evidence_decoder_calls`: count of the test-only evidence decoder calls.
  A valid scanner fixture may invoke it once after all scanner predicates
  pass; any count/length refusal must leave it zero.
* `crypto_calls == 0` for all cases in this addendum.

These are proposed counter names for future test assertions, not existing
symbols. The count and length controls use separate calls/fixtures. For a
count-negative, require outer-size and frame counters to pass, then count
counter one and typed `EvidenceEntryCountExceeded`; entry-length counter
remains zero and decoder remains zero. For an entry-length-negative, require
outer-size, frame and count counters to pass, then entry-length counter one
and typed `EvidenceEntryTooLarge`; decoder remains zero. A failure at an
earlier stage does not count as sensitivity for the intended nested limit.

## 3. Isolated nested count controls

All payloads below are actual bytes, not just declared lengths. `u32le(n)`
and `u16le(n)` denote the exact fixed-width little-endian encoding of integer
`n`. Each frame starts with the eight literal ASCII bytes `QBE1TEST`,
followed by `u32le(total)`, then one count byte.

| Case | Exact fields and payloads | Exact total |
|---|---|---:|
| Positive count control | `u32le(37)`, count `0x08`, then eight repetitions of `u16le(1)` and one-byte payloads `[0x01]`, `[0x02]`, …, `[0x08]` | `13 + 8 * (2 + 1) = 37` |
| Negative count control | `u32le(40)`, count `0x09`, then nine repetitions of `u16le(1)` and one-byte payloads `[0x01]`, `[0x02]`, …, `[0x09]` | `13 + 9 * (2 + 1) = 40` |

For both frames, verify `actual_len == declared_total`, exact count/entry
encoding, no trailing bytes, evidence outer-size pass and combined size pass
with the separate 11,339-byte candidate. The positive requires frame and
count checks each once, all eight entry lengths within bounds, one decoder
call after scanning, and zero crypto calls.

The negative must prove the same outer-size and framing prerequisites passed,
then `evidence_count_checks == 1` yields
`EvidenceEntryCountExceeded` for count nine. It must not be attributed to an
outer 19,389-byte refusal, malformed magic/total, truncation, or trailing
bytes. Since the count limit rejects after syntactic frame validation but
before evidence decoding/materialization, the separate per-entry policy
predicate is not credited; `evidence_entry_length_checks == 0`,
`evidence_decoder_calls == 0`, and `crypto_calls == 0`.

After the negative, restore the exact 37-byte positive frame and unchanged
independent catalog/currentness inputs. Require the same positive scanner
result and counters again (restored-positive control).

## 4. Isolated nested entry-length controls

Each frame has one entry and a count within bounds. The single entry length
is encoded in u16 little-endian and is followed by exactly that many
deterministic payload bytes.

| Case | Exact fields and payload | Exact total |
|---|---|---:|
| Positive entry-length control | `u32le(2435)`, count `0x01`, `u16le(2420)`, payload `[0xA5; 2420]` | `13 + 2 + 2,420 = 2,435` |
| Negative entry-length control | `u32le(2436)`, count `0x01`, `u16le(2421)`, payload `[0xA5; 2421]` | `13 + 2 + 2,421 = 2,436` |

For both frames, verify magic, declared and actual total, count one, exact
entry boundary, no trailing bytes, evidence outer-size pass and combined
size pass with the separate 11,339-byte candidate. The positive requires
outer-size, frame, count and entry-length counters each once, one decoder
call after scan acceptance, and zero crypto calls.

The negative must prove outer-size, frame and count prerequisites passed;
then `evidence_entry_length_checks == 1` yields `EvidenceEntryTooLarge`
because 2,421 exceeds the accepted 2,420-byte entry limit. This must not be
credited to an outer-cap, malformed frame, count, truncation or trailing-byte
refusal. It must leave `evidence_decoder_calls == 0` and `crypto_calls == 0`.

Restore the exact 2,435-byte positive frame after the negative and require the
same positive scanner result/counters (restored-positive control).

## 5. Scope and preserved bounds

The evidence outer cap remains 19,389 bytes and the combined checked cap
remains 35,773 bytes. The maximum valid candidate envelope remains 11,339
bytes. These independently accepted bounds do not change. The 37-, 40-,
2,435-, and 2,436-byte controls are all nested scanner fixtures far below the
outer caps. They demonstrate only framing and nested predicate ordering with
test counters; they do not prove signature validity, production ingress
allocation bounds, total memory, runtime, cancellation, authority,
currentness, finality, application, signing, fencing or resume.

All proposed model cases remain **FUTURE / NOT EXECUTED**. P1/P2 production
approaches and B/C remain unselected. The founder decision remains scoped to
one exact initial DevNet configuration; no completed credential ceremony,
later-transition authority, finality, signer override, recovery-clear or
resume authority is implied.

**A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain OPEN.
Activation DISABLED; public DevNet NO-GO.**
