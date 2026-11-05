# A33-F1 / E27 quarantine backend contract review correction

**BACKEND CONTRACT CORRECTED — INDEPENDENT REVIEW PENDING.**

This append-only correction records the user-supplied independent review
report. No reviewer identity or raw review artifact was supplied, so none is
asserted. It applies narrowly to
[the backend contract proposal](quarantine-backend-contract-proposal.md).
The original proposal and prior evidence bytes remain historical and
unchanged; where this record conflicts with it, this correction supersedes
the identified wording. No implementation or authority is approved.

Entry verification: repository `olivexo28/QBIND`, branch
`copilot/a33-f1-bounded-eviction`, clean worktree/index, task tip and remote
task tip `45eb183ee85348bba2efa0bf759a3255720d8c01`, and protected local/
remote main `c9aaef40b045e896ddfa8b01bad230f6b680715e`.

## 1. Store identity bytes and comparison

The candidate layout stores **digests**, not the generated store ID or
incarnation bytes themselves, in offsets `64..96` and `96..128`. The earlier
proposal's sentence saying the exact generated values are persisted in both
RocksDB metadata and the latch is corrected as follows:

* Separately authorized provisioning would generate two independent,
  exactly 32-byte values: `store_id_raw[32]` and
  `incarnation_raw[32]`. A dedicated RocksDB metadata record would store
  those exact 32 raw bytes in distinct fields, with a metadata format
  version. The metadata key, schema, value-generation source, uniqueness
  scope, provisioning authority and copy/restore lifecycle are unresolved.
  No such metadata or provisioning code currently exists.
* The latch would store only the full 32-byte digests:
  `SHA-256("QBIND-A33-F1-STORE\0" || canonical(raw_store_id))` and
  `SHA-256("QBIND-A33-F1-INCARNATION\0" ||
  canonical(raw_incarnation))`. For this candidate, `canonical(raw32)` is
  `u16be(1) || u32be(32) || raw32`: canonical-value encoding version 1,
  32-bit big-endian byte length 32, then all 32 bytes. No prefix, truncation,
  caller-provided string or platform-native encoding is permitted.
* After destination ownership, a future backend would read and validate the
  exact metadata fields from the same held RocksDB handle used for guarded
  effects, require each raw field to be exactly 32 bytes, recompute both
  domain-separated digests using that canonical encoding, and compare the
  full 32 bytes against latch offsets `64..96` and `96..128`. Missing,
  malformed, unsupported or mismatched metadata/latch values refuse; an
  indeterminate handle or comparison is uncertain and refuses. A backend
  would need a future refusal representation for these typed causes, or map
  them to the existing generic mismatch/uncertainty refusals while retaining
  precise diagnostics. This comparison does not prove that the held RocksDB
  object is the intended pathname object.

The chain/genesis digest remains separately domain-separated by
`QBIND-A33-F1-CHAIN\0`; its authoritative source bytes and canonical
encoding are unresolved. Operation and writer-session IDs remain full
32-byte latch fields, not truncated values; their allocation, non-reuse and
binding rules remain unresolved. Matching local IDs/digests establish
neither currentness, anti-rollback nor exclusive signer ownership. A copied
database copies its metadata values and is not thereby detected as stale.

## 2. Current versus proposed refusal mapping

Current source behavior is narrower than the proposal's earlier mismatch
table suggested. `classify_for_reset` directly compares the decoded
`StoreIdentity.store_id` and `.chain_id` `String` fields to the expected
`String` fields. It has no typed incarnation ID or operation ID and performs
no separate comparison for either. All its outcomes are `ResetRefusal`
values; no result can authorize reset.

| Check or observation | Current interface | Future backend/interface work |
|---|---|---|
| Store and chain identity strings | Direct exact `String` equality; either mismatch returns `ForeignOrMismatchedIdentity` | Canonical source derivation and full-width digest comparison remain unselected |
| Store incarnation | No field or separate check | Read raw 32-byte RocksDB metadata, recompute/compare digest; malformed or mismatch needs a new typed refusal or generic mismatch plus diagnostic |
| Operation and writer-session binding | Not compared as typed expected identities | Validate against active owner/record; mismatch needs a new typed refusal or generic mismatch plus diagnostic |
| Missing, malformed, unsupported or unreadable record | Existing `Absent`, `MalformedOrCorrupt`, `UnsupportedVersion`, `Unavailable`, `ReadFailure`, or `Uncertain` values as applicable | Backend must accurately distinguish failure stage; never repair or reinterpret as clean |
| Clean-looking observation | `CleanLookingRequiresSeparateAuthority` | No authority is selected; remains refusal |

Consequently, the original table's “Chain/store/incarnation/operation
mismatch” row is superseded: only the current store/chain string comparison
is implemented in this component. Incarnation and operation/session checks
are proposals requiring a future backend and possibly interface extension.
They must not be reported as existing behavior.

## 3. Publication failure after rename

The prior wording that an acknowledged `Applying` latch “remains” after
every failed update is withdrawn as a statement about bytes on disk. A
temporary-file rename may already make new bytes visible before a subsequent
directory-sync or acknowledgment failure; the new bytes may be valid, stale,
malformed, incomplete or unreadable. This proposal establishes no actual
durability guarantee.

Replacement rule for every update failure or lost/uncertain acknowledgment:
the owner refuses further protected effects and records publication state as
uncertain when possible. A later observation may find the prior latch, the
new visible latch, malformed bytes, no readable latch, or no determinate
answer. All cases remain closed:

* a readable old or new supported latch is not permission to continue;
* malformed/partial bytes map to `MalformedOrCorrupt` or `ReadFailure`;
* unavailable or unreadable storage maps to `Unavailable` or `ReadFailure`;
* uncertain visibility, revision disagreement, replacement or inconclusive
  acknowledgment maps to `Uncertain`;
* absence maps to `Absent`, never to initialization or clean state.

Do not assert that the prior bytes remain unchanged after an I/O error, that
the new bytes are durable because rename returned, or that a failed update
restored the earlier state. The earlier `Applying` record is a desired
restart anchor only if that record is actually observed and validated; if
not, uncertainty still refuses. No reset, audit, marker replacement or
restart clears quarantine.

## 4. Committed anchor semantics

The original layout label at `224..232`, “Starting committed view/height,”
is superseded by **“committed-anchor scalar (meaning undecided)”**. The
proposal has not selected whether the gate needs committed view, committed
height, both, or another documented engine-specific representation. The
32-byte committed block ID remains at `192..224`; the following scalar's
meaning, derivation and relationship to that ID require consensus-owner
review. The existing lock-view field is separate and does not resolve the
committed-anchor choice.

If the selected contract requires both view and height as distinct `u64`
values, the current 416-byte candidate is insufficient. A conditional
two-scalar alternative inserts committed-height at `232..240`, shifts all
later fields by 8 bytes, moves the integrity field from `384..416` to
`392..424`, and yields a checked total of **424 bytes** (`416 + 8`). For
that conditional alternative, lock block is `240..272`, lock view
`272..280`, response digest `280..312`, bitmaps `312..336`, prefix/current
indices `336..352`, evidence digest `352..384`, evidence revision
`384..392`, and integrity digest `392..424`. This is a layout arithmetic
alternative only, not a selection or production limit. If another
representation is selected, recalculate and verify all offsets and the
whole total.

Any anchor fact required for safety but retained only in evidence is usable
only after that exact evidence object is read, validated and bound to the
latch revision. Missing, stale, malformed, unreadable or mismatched evidence
means the anchor cannot be established and therefore refuses/uncertain; it
must not be treated as zero, inferred from a similar field, or silently
discarded. Evidence capacity and the necessary anchor contract remain
unresolved.

## Checks and boundaries

These are documentation corrections only. The original proposal's accepted
stay-closed direction is preserved. No production code, backend, codec,
gate, test, initialization, migration, signing, node/network operation or
activation was added or run. Evidence bounds, identity authority and
canonical chain source, initialization/migration, RocksDB object continuity,
filesystem/durability profile, currentness, anti-rollback, signer
exclusivity, and clear/resume authority remain unresolved. A33-F1 / E27 and
all other unresolved obligations remain **OPEN**; activation **DISABLED**;
public DevNet **NO-GO**.
