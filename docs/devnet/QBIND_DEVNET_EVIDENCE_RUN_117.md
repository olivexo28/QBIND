# QBIND DevNet Evidence — Run 117

**Run:** 117
**Title:** Persistent Authority Anti-Rollback Marker — Storage / Snapshot Primitive
**Date:** 2026-05-22
**Verdict:** positive (storage primitive only; no surface wiring)
**Scope:** Implement the Run 116 anti-rollback model at the storage and
snapshot-metadata level only. Run 117 lands the record type, canonical
digest, typed comparison semantics, atomic persistence helpers, and
the additive snapshot-metadata extension. **No production validation
or apply surface is changed.** Surface wiring is staged for Run 118.

This document is the canonical Run 117 deliverable. It records exactly
what code Run 117 lands, exactly which invariants it preserves, and
exactly which surfaces remain unwired (deferred to Run 118+).

---

## 1. What Run 117 changed

### 1.1 Code changed

- **New module:** `crates/qbind-node/src/pqc_authority_state.rs`
  (1 file, ~1000 LOC including extensive module-level documentation
  and 38 unit tests). Declares the `pub mod pqc_authority_state` line
  in `crates/qbind-node/src/lib.rs`.
- **Extended:** `crates/qbind-ledger/src/state_snapshot.rs`
  - Added `AuthorityStateSnapshotMeta` struct.
  - Added `StateSnapshotMeta::authority_state: Option<AuthorityStateSnapshotMeta>`
    field (additive, defaults to `None`, omitted entirely from JSON
    when `None`).
  - Added builder method `StateSnapshotMeta::with_authority_state(...)`.
  - Extended `to_json` / `from_json` to additively serialise / parse
    the new block, with fail-closed handling of malformed authority
    blocks.
  - Added 10 new Run 117 unit tests; all 8 existing Run 097 unit
    tests preserved verbatim.
  - Added `pub use state_snapshot::AuthorityStateSnapshotMeta` to
    `crates/qbind-ledger/src/lib.rs`.
- **Updated callers:** `crates/qbind-node/src/vm_v0_runtime.rs` and
  `crates/qbind-ledger/tests/t215_state_snapshot_tests.rs` — added
  `authority_state: None` to the existing `StateSnapshotMeta { .. }`
  struct literals so they still compile. Behaviour is unchanged.

No other `.rs` file under `crates/` is modified.

### 1.2 Docs changed

- **New:** `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_117.md` (this document).
- **Updated:** `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` —
  appended a Run 117 update section recording the landed primitive and
  the staged-still-pending surface wiring.
- **Updated:** `docs/whitepaper/contradiction.md` — appended a Run 117
  C4 update narrowing the "authority anti-rollback persistence"
  sub-item from "design landed, implementation staged to Run 117" to
  "storage primitive + snapshot extension landed in Run 117;
  surface wiring staged to Run 118".
- **Updated:** `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` —
  appended a Run 117 operator section. **No operator action is
  required.** The marker file `<data_dir>/pqc_authority_state.json` is
  defined by Run 117 but not yet written by any production surface.

### 1.3 Tests added

- **38 unit tests** in `crates/qbind-node/src/pqc_authority_state.rs`
  (full list in §6.2).
- **10 unit tests** in `crates/qbind-ledger/src/state_snapshot.rs`
  (full list in §6.3) — all prefixed `run117_`.

### 1.4 Storage / wire format changed

- **No wire format is changed.** Run 117 does not touch any peer
  message, transport handshake, signed-bundle format, ratification
  object, or consensus payload.
- **One new on-disk schema is defined**:
  `<data_dir>/pqc_authority_state.json` (see §3). The schema is
  defined but Run 117 does **not** wire any production surface to
  write it — see §5 for the explicit non-wiring statement.
- The `StateSnapshotMeta` JSON additively grows an optional
  `"authority_state"` block. Snapshots created by pre-Run-117
  binaries parse cleanly under the Run 117 parser (`authority_state`
  → `None`), and snapshots created by Run-117+ binaries with
  `authority_state: None` are byte-identical to pre-Run-117 output
  for all common fields.

### 1.5 Explicit non-regression statement

Run 117 explicitly does NOT change:

- Run 050–055 signed-bundle verification (parse, ML-DSA-44 signature,
  environment, chain_id, anti-rollback sequence).
- Run 057 activation epoch / height gating.
- Run 061 / 063 local self-checks.
- Run 065 minimum-activation-margin policy.
- Run 069 / 071 / 072 / 073 trust-reload pipeline.
- Run 097 snapshot epoch parity (all 8 unit tests and all 7
  integration tests still pass).
- Run 100–106 ratification authorisation layer.
- Run 107 / 109 / 112 / 114 surface wiring.

The strongest possible non-regression guarantee is that **no
existing production surface calls any function in the new
`pqc_authority_state` module**. The module exists and is unit-tested,
but it is not yet wired anywhere.

---

## 2. Core security problem (recap)

Run 116 framed the open monotonicity gap: a node must persist the
highest **ratified bundle-signing authority state** it has ever
accepted, so an attacker or operator-mistake cannot silently roll
back to an older ratification on a future startup, reload, or restore.

Run 117 implements the **storage primitive** that makes that anchor
durable, plus the **snapshot metadata carrier** so that a future
fast-sync restore can detect a conflict between a snapshot's
authority state and the local node's persisted state.

Run 117 does **not** itself prevent any rollback in production today:
no production validation / apply surface yet calls into
`pqc_authority_state`. That wiring lands in Run 118. The Run 117
primitive is staged precisely so that Run 118 is a narrow, surgical
"call the right function in the right place" change rather than a
combined design + wiring change.

---

## 3. On-disk authority-state record

### 3.1 File path

`<data_dir>/pqc_authority_state.json`, where `<data_dir>` is the
operator-supplied data directory (the same `--data-dir` already
consumed by `qbind-node`). The path is resolved by
`pqc_authority_state::authority_state_file_path(data_dir)`.

### 3.2 JSON schema (Run 117 = `record_version: 1`)

```json
{
  "record_version": 1,
  "chain_id": "<16 lowercase hex chars>",
  "environment": "devnet" | "testnet" | "mainnet",
  "genesis_hash": "<64 lowercase hex chars>",
  "authority_policy_version": <u32>,
  "authority_sequence": <u64>,
  "authority_epoch": <u64 | null>,
  "authority_root_fingerprint": "<lowercase hex>",
  "ratified_bundle_signing_key_fingerprint": "<lowercase hex>",
  "ratification_object_hash": "<64 lowercase hex chars>",
  "last_update_source":
      "startup-load" | "reload-apply" | "sighup-reload"
    | "operator-reset" | "test-or-fixture",
  "updated_at_unix_secs": <u64>
}
```

**No private key material is persisted.** The ratified bundle-signing
key is referenced only by its lowercase-hex SHA3-256 fingerprint, and
the ratification object itself is captured only as its 32-byte
SHA3-256 `canonical_ratification_digest` rendered as 64 lowercase hex
chars in `ratification_object_hash`.

### 3.3 Canonical preimage and digest

The `canonical_authority_state_preimage` of a record is a
length-prefixed, big-endian byte buffer with the layout documented
in the module source:

```
AUTHORITY_STATE_DOMAIN_V1                                    (= b"QBIND:AUTHORITY-STATE:v1")
u32  record_version
u32 len(chain_id)                                | chain_id bytes (ascii)
u32 len(environment_tag)                         | environment_tag bytes (ascii)
u32 len(genesis_hash)                            | genesis_hash bytes (ascii)
u32  authority_policy_version
u64  authority_sequence
u8   authority_epoch_present (0 or 1)
u64  authority_epoch  (present iff prev byte == 1; else absent)
u32 len(authority_root_fingerprint)              | authority_root_fingerprint bytes
u32 len(ratified_bundle_signing_key_fingerprint) | ratified_bundle_signing_key_fingerprint bytes
u32 len(ratification_object_hash)                | ratification_object_hash bytes
```

`canonical_authority_state_digest(...)` is the SHA3-256 over this
preimage. Domain separation follows the existing project convention
(`QBIND:GENESIS:v1`, `QBIND:BUNDLE-SIGNING-RATIFICATION:v1`).

**`last_update_source` and `updated_at_unix_secs` are intentionally
excluded** from the canonical preimage. They are informational-only
audit fields and must not contribute to the security digest;
otherwise a benign restart would change the digest without changing
the security-relevant state. The unit test
`digest_excludes_informational_fields` enforces this invariant.

### 3.4 Atomic write discipline

Persistence uses `pqc_authority_state::persist_authority_state_atomic`
which performs:

1. Structural pre-write validation (refuses to persist a malformed
   record).
2. Serialise to JSON bytes.
3. `create_dir_all` on the parent if missing.
4. Write the bytes to `<path>.tmp`.
5. `sync_all()` on the tmp file.
6. `rename(<path>.tmp, <path>)`.
7. On Unix only: `sync_all()` on the parent directory so the rename
   is durable in the directory entry, not just in the inode.

This mirrors the Run 055 `pqc_trust_sequence::atomic_write_record`
pattern and adds the parent-dir fsync that the Run 116 spec called
out. On Windows the parent-dir fsync step is skipped (best-effort)
because opening a directory for read is unsupported there; the rename
+ tmp-file fsync combination remains the durability anchor.

---

## 4. Comparison semantics

`pqc_authority_state::compare_authority_state(persisted, candidate)`
is a pure, side-effect-free function that returns a typed
`AuthorityStateComparison` outcome. Run 117 lands the **eleven**
variants enumerated by the Run 116 spec; the comparator never
returns a boolean. Reject variants carry the data needed to emit a
precise operator log line without re-inspecting the records.

| Variant | Class | Meaning |
| --- | --- | --- |
| `FirstLoad` | accept-advance | No prior marker. |
| `EqualIdempotent` | accept-no-rewrite | Persisted record bit-for-bit identical to candidate (ignoring informational fields). |
| `Upgrade { previous_sequence, new_sequence }` | accept-advance | Candidate's `authority_sequence` is strictly higher. |
| `RollbackRefused { ... }` | reject | Candidate's `authority_sequence` is strictly lower. |
| `SameSequenceConflictingHash { ... }` | reject | Equal `authority_sequence`, different `ratification_object_hash`. |
| `SameSequenceConflictingKey { ... }` | reject | Equal `authority_sequence`, same authority_root, different ratified-key fingerprint. |
| `ChainMismatch { ... }` | reject | `chain_id` disagrees. |
| `EnvironmentMismatch { ... }` | reject | `environment` disagrees. |
| `GenesisHashMismatch { ... }` | reject | `genesis_hash` disagrees. |
| `PolicyVersionRegression { ... }` | reject | Candidate's `authority_policy_version` strictly lower than persisted. |
| `Corrupt { reason }` | reject | Both records structurally valid but disagree in a way no other variant captures. |

`AuthorityStateComparison::is_accept()` returns true iff the outcome
permits accepting the candidate. `accept_advance()` returns true iff
the persisted record must be rewritten (`FirstLoad` or `Upgrade`);
`EqualIdempotent` is an accept but does **not** require a rewrite,
matching the Run 055 same-fingerprint precedent.

**Honest limitation.** Without a per-key monotonic field in the
Run 103 `BundleSigningRatification` schema (deferred to Run 120),
the marker cannot detect a key-level downgrade if a new ratification
keeps the same `authority_sequence`. The
`SameSequenceConflictingHash` / `SameSequenceConflictingKey`
variants make this bounded protection explicit: at equal
`authority_sequence` a different ratification content / key is
treated as a **conflict to reject**, not as a silent upgrade. The
canonical path forward is the Run 120 ratification-schema bump.

---

## 5. Explicit non-wiring statement

Run 117 deliberately does **not** wire the new module into any
production surface. The following list is the complete set of
surfaces that are **NOT** changed by Run 117:

- Startup-load path (`crates/qbind-node/src/main.rs`).
- Process-start reload-apply path (Run 112).
- SIGHUP live-reload path (Run 114).
- Reload-check / validation-only path (Run 069 / 109).
- Local peer-candidate check.
- Live inbound `0x05` peer-candidate validation.
- Fast-sync restore (Run 118 enforcement scope).

No `qbind_node::pqc_authority_state::*` call appears anywhere outside
the new module's `#[cfg(test)]` block. Run 117 therefore cannot
change runtime behaviour on any of the listed surfaces; the marker
file `<data_dir>/pqc_authority_state.json` will not be created by a
running production binary until Run 118 lands. This non-wiring is
verifiable by `grep -rn pqc_authority_state crates/ | grep -v "pqc_authority_state\(\.rs\|\:\)"`.

Run 118 is scoped to add precisely those call sites, with no further
schema or semantic changes to the marker.

---

## 6. Tests

### 6.1 Build matrix

- `cargo build -p qbind-ledger` — OK.
- `cargo build -p qbind-node` — OK.
- `cargo build -p qbind-node --lib` — OK.

### 6.2 Authority-state primitive tests

`cargo test -p qbind-node --lib pqc_authority_state::` — **38 passed**.

```
chain_id_hex_format
compare_chain_mismatch
compare_corrupt_equal_seq_equal_hash_drift_epoch
compare_environment_mismatch
compare_equal_idempotent
compare_equal_idempotent_ignores_informational_fields
compare_first_load
compare_genesis_hash_mismatch
compare_policy_version_regression
compare_rollback_refused
compare_same_sequence_conflicting_hash
compare_same_sequence_conflicting_key
compare_upgrade
comparison_accept_classification
digest_excludes_informational_fields
digest_flips_on_each_security_relevant_field
digest_is_deterministic
digest_preimage_starts_with_domain_tag
genesis_hash_hex_format
load_fails_closed_on_corrupt_json
load_fails_closed_on_truncated_record
load_fails_closed_on_unsupported_version
load_returns_none_when_file_absent
no_tmp_file_leftover_on_successful_write
persist_creates_missing_parent_dir
persist_overwrites_idempotently
persist_rejects_structurally_invalid_record
persist_then_load_round_trips
validate_record_for_domain_accepts_matching_runtime
validate_record_for_domain_rejects_wrong_chain
validate_record_for_domain_rejects_wrong_env
validate_record_for_domain_rejects_wrong_genesis
validate_structure_accepts_sample
validate_structure_rejects_bad_chain_id
validate_structure_rejects_bad_genesis_hash
validate_structure_rejects_uppercase_hex
validate_structure_rejects_wrong_version
validate_structure_rejects_zero_policy_version
```

### 6.3 Snapshot-meta Run 117 tests

`cargo test -p qbind-ledger --lib state_snapshot::` — **27 passed**
(8 Run 097 + 10 Run 117 + 9 prior T215). All ten new Run 117 tests:

```
run117_authority_state_some_serializes_and_round_trips
run117_authority_state_none_omits_field_for_backward_compatibility
run117_old_snapshot_without_authority_state_parses_as_none
run117_run097_snapshot_with_epoch_only_parses_with_authority_none
run117_authority_state_explicit_null_is_treated_as_absent
run117_malformed_authority_state_fails_closed
run117_authority_state_with_no_authority_epoch_parses_as_none
run117_authority_state_serialization_is_deterministic
run117_epoch_and_authority_state_are_independent
```

### 6.4 Run 097 backward-compatibility tests preserved

`cargo test -p qbind-node --test run_097_snapshot_epoch_parity_tests`
— **7 passed**, identical to the pre-Run-117 baseline:

```
run097_snapshot_metadata_carries_canonical_committed_epoch_when_present
run097_snapshot_metadata_omits_epoch_when_no_canonical_source_available
run097_restore_persists_snapshot_epoch_into_canonical_consensus_storage
run097_restore_inconsistent_snapshot_epoch_fails_closed
run097_restore_with_pre_run097_snapshot_leaves_storage_at_no_committed_epoch
run097_idempotent_restore_when_snapshot_epoch_matches_existing
run097_does_not_touch_activation_context_current_epoch_surface
```

### 6.5 Full `qbind-ledger` lib test suite

`cargo test -p qbind-ledger --lib` — **222 passed, 0 failed**.

---

## 7. Strict non-goals (still open after Run 117)

Run 117 explicitly does **NOT** address any of the following:

- **Signing-key rotation lifecycle.** The Run 103 ratification
  schema lacks a per-key monotonic field; rotation safety requires
  the Run 120 schema bump and is out of scope here.
- **Signing-key revocation lifecycle.** Not modelled by Run 116;
  staged for a later run.
- **Peer-driven live apply.** Run 109 explicitly forbids mutation
  on the live `0x05` path; Run 117 preserves that contract by not
  wiring any mutating call into the validation-only surface.
- **KMS / HSM custody.** Outside the scope of the on-disk marker.
- **Governance / quorum / voting.** Outside the scope of the
  marker.
- **Validator-set rotation.** Outside the scope of the marker.
- **Full C4 / C5 closure.** Run 117 narrows the C4
  authority-anti-rollback sub-item to "storage primitive landed",
  not "closed". Full closure requires Run 118 surface wiring,
  Run 119 release-binary evidence, and Run 120 ratification-schema
  bump.

These non-goals are repeated in the `docs/whitepaper/contradiction.md`
Run 117 update and the
`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` Run 117 update
so an external reader sees the bounded scope from any starting
document.

---

## 8. Staged plan after Run 117

| Run | Scope |
| --- | --- |
| **117 (this run)** | Storage primitive + snapshot metadata extension. **No surface wiring.** |
| 118 | Wire the marker into startup-load / reload-apply / SIGHUP / reload-check / local peer-candidate / live `0x05` validation paths. Add the `--allow-authority-state-reset` operator-recovery flag. Add restore-side conflict detection that consumes the snapshot's `authority_state` block. |
| 119 | Release-binary evidence demonstrating the wired behaviour end-to-end on DevNet. |
| 120 | Bump `BundleSigningRatification` schema to carry a per-key monotonic field so the marker can detect key-level downgrade at equal `authority_sequence` (today's `SameSequenceConflictingHash` / `SameSequenceConflictingKey` conflicts upgrade to a clean ordering). |

---

## 9. Honest verdict

Run 117 delivers exactly what its scope demands: a narrow,
well-tested storage and snapshot-metadata primitive that Run 118
can wire without further design work. No production surface is
changed; no wire format is changed; every prior invariant is
preserved (Run 050–115 plus Run 097). The marker file does not
yet exist on any running node because Run 117 deliberately does
not write it from any production path — the Run 116 spec explicitly
staged the wiring to Run 118.

The honest scope of the protection this primitive will provide
once wired in Run 118 is bounded by the Run 103 ratification
schema: until Run 120 adds a per-key monotonic field, the marker
can detect authority-sequence rollback and equal-sequence content
conflicts, but cannot detect a same-sequence key-level downgrade.
That limitation is recorded in three places — the module docs, this
evidence document, and the Run 117 sections of the protocol and
contradiction documents — so no future run can claim a stronger
guarantee than this primitive actually offers.

Verdict: **positive (storage primitive only; no surface wiring;
all prior invariants preserved)**.