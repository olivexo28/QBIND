# QBIND DevNet Evidence — Run 118

**Subject:** Wire Authority Anti-Rollback Marker into Ratification-Enforced Surfaces — first wiring step (helper layer)
**Verdict:** **partial-positive**
**Date:** 2026-05-22
**Task:** `task/RUN_118_TASK.txt`

---

## 1. Exact verdict

**partial-positive.**

Run 118 lands the Run 117 → live-surface bridge **as pure helpers with full
test coverage**, plus the doc-sync verification the task's first checkpoint
required, plus honest documentation of which surfaces have NOT yet been
wired. No production validation/apply call site in
`crates/qbind-node/src/main.rs`, in the startup `--p2p-trust-bundle` path,
in the Run 112 process-start reload-apply path, in the Run 114 SIGHUP
live-reload path, or in the three Run 105/106/107/109 validation-only
surfaces yet calls into the new helpers — that final call-site wiring is
deferred to a follow-up run so it can be reviewed and release-binary-
evidenced against a stable, test-covered helper layer rather than landing
six surface changes plus the helpers in one risky merge.

Per `task/RUN_118_TASK.txt` §"Expected verdicts", partial-positive is the
honest fit when "marker derivation/checking lands on only some surfaces;
persistence is not wired; release evidence is incomplete;
restore/snapshot conflict handling remains deferred." All four of those
sub-conditions apply here and are documented below.

---

## 2. What was implemented

### 2.1 Run 117 doc-sync verification (first checkpoint)

The task's first checkpoint required that three documents explicitly state
the eight Run 117 / Run 118 / Run 120 facts before any code lands. All
three were inspected against the current `main` of this branch:

| Doc | Run 117 paragraph present | All eight required statements? |
|-----|---------------------------|--------------------------------|
| `docs/whitepaper/contradiction.md` | Yes (lines 1542–1544) | Yes — `pqc_authority_state.rs` landed, `PersistentAuthorityStateRecord` landed, atomic persist helpers landed, `AuthorityStateSnapshotMeta` landed, surfaces NOT wired in Run 117, Run 118 is the wiring run, Run 120 needed for per-key monotonic schema bump, full C4 / C5 remain OPEN. |
| `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` | Yes (§ "Run 117 update — Storage primitive and snapshot metadata extension landed", line 1551+) | Yes — same eight statements present and binding. |
| `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` | Yes (8× "Run 117" hits) | Yes — operator-facing description of the marker file path, fail-closed behaviour, and Run 118 deferral. |

**Result of the first checkpoint: no doc-sync edit is required**, because
the docs uploaded in the Run 117 deliverable already reflect Run 117's
landed-code reality (the review concern about "pre-Run-117 planning text"
does not apply to the doc state checked in this branch). The Run 118
update sections appended below now extend each of the three docs with the
Run 118 helper-layer status.

### 2.2 Files changed

- `crates/qbind-node/src/pqc_authority_state.rs`
  - New imports of `BundleSigningRatification`, `RatifiedBundleSigningKey`,
    and `canonical_ratification_digest` from `qbind_ledger`.
  - New Run 118 helper section:
    - `AuthorityStateDerivationInputs<'a>` — typed input bundle (10 fields)
      derived strictly from already-verified Run 102/104 boot context and
      Run 103/105 verifier output.
    - `AuthorityStateDerivationError` — five typed fail-closed precondition
      variants (`MalformedRuntimeGenesisHash`, `EnvironmentMismatch`,
      `ChainIdMismatch`, `RatificationVerifierInconsistent`,
      `InvalidDerivedRecord`) so a binary surface can emit a precise
      operator-log line.
    - `derive_authority_state_from_ratification(...)` — deterministic
      derivation. Cross-checks
      `ratification.environment ↔ runtime_env`,
      `ratification.chain_id ↔ canonical 16-char hex of runtime ChainId`,
      and `ratification.authority_root_fingerprint ↔
      RatifiedBundleSigningKey.authority_root_fingerprint`. Computes
      `ratification_object_hash` directly from
      `canonical_ratification_digest(&ratification)` so the marker can
      never disagree with the verifier on which ratification object it
      records. Finally calls
      `PersistentAuthorityStateRecord::validate_structure()` so a
      structurally invalid record is fail-closed *before* the marker
      leaves the helper.
  - New Run 118 compare-before-accept section:
    - `AuthorityStatePrepareOutcome` — six-variant typed surface
      (`FirstWrite`, `AlreadyPersistedIdempotent`, `Upgrade { .. }`,
      `ConflictReject(AuthorityStateComparison)`,
      `LoadFailedFailClosed(AuthorityStateError)`,
      `PersistedDomainMismatch(AuthorityStateComparison)`) with
      `is_accept` / `is_reject` / `should_persist` helpers.
    - `prepare_marker_for_acceptance(...)` — pure wrapper around the
      Run 117 `load_authority_state` + `validate_record_for_domain` +
      `compare_authority_state` pipeline. Never writes. The
      `(env, chain_id, genesis_hash)` of the **persisted** record is
      validated against the runtime *before* the rollback / equivocation
      comparison, so the wrong-data-dir / wrong-snapshot-copy case
      surfaces as `PersistedDomainMismatch(...)` and not as a generic
      chain mismatch reported against the candidate.
- `crates/qbind-node/src/pqc_authority_state.rs` test module:
  21 new Run 118 unit tests under `pqc_authority_state::tests::run118::*`.
- `docs/whitepaper/contradiction.md` — Run 118 update paragraph appended.
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — Run 118 update
  section appended.
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 118 operator
  section appended.

### 2.3 Surfaces wired in this run

**None of the six runtime surfaces.** The helpers are deliberately
landed without call-site wiring so that the call-site changes (six
distinct surfaces, each with its own existing 700–1300-line file and its
own mutation ordering contract from Runs 070 / 105 / 106 / 107 / 109 /
112 / 113 / 114 / 115) can land separately against a stable, already-
tested helper layer.

### 2.4 Surfaces deferred (follow-up run)

| Class | Surface | Existing module | Deferred Run 118 work |
|------:|---------|------------------|------------------------|
| Mutating (P1) | Startup `--p2p-trust-bundle` accept path | `crates/qbind-node/src/startup_validation.rs` + `pqc_trust_bundle.rs` | Call `prepare_marker_for_acceptance` after Run 103/105 verifier success, persist via `persist_authority_state_atomic` immediately after the Run 070 `commit_sequence` step. |
| Mutating (P1) | Process-start reload-apply (Run 112) | `crates/qbind-node/src/pqc_live_trust_apply.rs` | Same compare + persist; preserve the four-step validate→snapshot→swap→evict→commit ordering. |
| Mutating (P1) | SIGHUP live reload (Run 114) | `crates/qbind-node/src/pqc_live_trust_reload.rs` | Same compare + persist; preserve the SIGHUP ordering. |
| Validation-only (P2) | `--p2p-trust-bundle-reload-check` | `crates/qbind-node/src/pqc_trust_reload.rs` | Compare only; never persist. |
| Validation-only (P2) | `--p2p-trust-bundle-peer-candidate-check` | `crates/qbind-node/src/pqc_trust_peer_candidate.rs` | Compare only; never persist. |
| Validation-only (P2) | Live inbound `0x05` validation | `crates/qbind-node/src/pqc_peer_candidate_binary.rs` | Compare only; preserve the Run 109 non-mutation contract bit-for-bit. |

The follow-up run will additionally produce the release-binary scenarios
(first-write accepted; equal idempotent; lower-sequence rejected; same-
sequence-different-hash rejected; wrong-chain/env/genesis rejected;
corrupt rejected) and the `--allow-authority-state-reset` operator-
recovery flag.

### 2.5 Persistence behaviour

`prepare_marker_for_acceptance` **never writes** the marker file — that
is the explicit contract documented on the function and exercised by the
`prepare_does_not_persist` test. The pure wrapper exists so validation-
only surfaces can call it safely. Mutating surfaces are expected to call
`persist_authority_state_atomic` separately at the safest commit
boundary relative to the existing trust mutation.

### 2.6 Ordering / crash-consistency decision (binding for follow-up run)

For each mutating surface the binding ordering will be:

```
verify ratification (Run 103/105)             (existing)
   ↓
derive_authority_state_from_ratification(...) (new, pure)
   ↓
prepare_marker_for_acceptance(...)            (new, pure, no I/O write)
   ↓ if accept (FirstWrite or Upgrade)
existing validate → snapshot → swap → evict_sessions → commit_sequence
   ↓
persist_authority_state_atomic(...)           (new, atomic, fail-closed)
```

The marker is persisted **after** the existing Run 070 `commit_sequence`
step. Rationale: `commit_sequence` is itself an atomic tmp+rename+fsync
on a separate file, so the only two possible boot-time states are
(a) commit_sequence advanced + marker advanced (happy), or
(b) commit_sequence advanced + marker stale-by-one (a benign crash window
where the next boot replays the comparison with the just-advanced
sequence and re-derives + re-persists the marker, hitting `Upgrade`
again). Reversing the order — marker first, then commit_sequence —
would produce the *worse* failure mode where a crash leaves a marker
ahead of the sequence, blocking future legitimate bumps. This is the
ordering Run 116 specified and Run 118 preserves it.

### 2.7 Tests added

21 new unit tests in `crates/qbind-node/src/pqc_authority_state.rs`
under module `tests::run118`:

**Marker derivation (12 tests; covers Run 118 task §A):**
- `derive_same_ratification_same_marker`
- `derive_chain_change_changes_marker`
- `derive_environment_change_changes_marker`
- `derive_genesis_hash_change_changes_marker`
- `derive_authority_root_change_changes_marker`
- `derive_ratified_key_change_changes_marker` (same authority root, two
  different bundle-signing keypairs — must flip the digest *and* the
  `ratified_bundle_signing_key_fingerprint` field)
- `derive_ratification_digest_change_changes_marker`
- `derive_digest_excludes_audit_fields` (audit-only fields `update_source`
  and `updated_at_unix_secs` must NOT influence the digest, mirroring the
  Run 117 invariant)
- `derive_rejects_malformed_genesis_hash`
- `derive_rejects_runtime_env_disagreement`
- `derive_rejects_runtime_chain_disagreement`
- `derive_rejects_verifier_inconsistency` (fabricates an inconsistent
  `(ratification, ratified)` pair the production verifier could never
  emit and confirms the helper fails closed instead of silently picking
  one side)

**Compare-before-accept (9 tests; covers Run 118 task §B / §C / §D):**
- `prepare_first_write_when_no_persisted_marker`
- `prepare_idempotent_after_first_persist` (different audit fields on
  the candidate must still produce `AlreadyPersistedIdempotent`)
- `prepare_upgrade_at_higher_sequence`
- `prepare_rejects_rollback`
- `prepare_rejects_same_sequence_conflicting_hash` (two independent
  fixtures share runtime context but differ on `authority_root` and
  `ratification_object_hash`; the typed reject reason is preserved)
- `prepare_rejects_persisted_domain_mismatch` (seeds an on-disk record
  for the *mainnet, chain=2* trust domain and confirms the wrapper
  rejects with `PersistedDomainMismatch` when the runtime is
  *devnet, chain=1* — the wrong-data-dir / wrong-snapshot-copy case)
- `prepare_fails_closed_on_corrupt_persisted_marker` (and asserts the
  wrapper does NOT silently delete or rewrite the corrupt file)
- `prepare_does_not_persist` (the wrapper must never write the file
  itself — validation-only surfaces depend on this)
- `outcome_classification_helpers` (`is_accept` / `is_reject` /
  `should_persist` semantics)

---

## 3. What was proven

### 3.1 Source-level proof

- The Run 118 helpers compile in `crates/qbind-node` with no new warnings.
- The derived `PersistentAuthorityStateRecord` is structurally validated
  before it leaves the helper, so a `derive_*` success guarantees a
  candidate that can be persisted, compared, or domain-validated by every
  Run 117 primitive without a second structural check.
- The compare-before-accept wrapper is pure (never writes) by
  construction: a single `prepare_does_not_persist` test asserts the
  marker file does not exist after a `FirstWrite` outcome.

### 3.2 Test proof

| Suite | Tests | Status |
|---|---|---|
| `pqc_authority_state` (Run 117 + Run 118) | 59 | passed |
| `qbind-node --lib` (full) | 1158 | passed |
| `qbind-ledger --lib` (full) | 231 | passed |

Pre-existing `bincode::config` deprecation warnings (2 emitted from
`qbind-node` lib build) are untouched by Run 118.

Per task §"Required tests / E. Regression tests": no Run 055 / Run 097 /
Run 103 / Run 104 / Run 105–115 test target reports a regression.

### 3.3 Release-binary evidence

**Deferred.** No mutating surface is wired in Run 118, so no release
binary writes the marker file. Release-binary evidence is staged to the
follow-up run that wires the three mutating surfaces.

---

## 4. Key security decisions

- **Marker derived only from verified ratification.** The helper takes a
  `&BundleSigningRatification` *and* its matching `&RatifiedBundleSigningKey`,
  and cross-checks the two for fingerprint agreement before producing a
  marker. The helper is the only Run 118 path that can produce a marker;
  there is no constructor that accepts an unverified ratification.
- **Marker distinct from Run 055 trust-bundle sequence.** The derived
  record's `authority_sequence` field is sourced from the runtime's
  Run 101 genesis-bound `GenesisAuthorityConfig::authority_sequence`,
  never from any `TrustBundleSequence` value, `activation_height`, or
  `activation_epoch`. The Run 055 anti-rollback layer continues to
  guard the bundle sequence on its own file (`pqc_trust_sequence.json`).
- **No fake monotonic authority sequence.** Run 118 invents no field.
  The bounded protection limit — that two distinct ratifications at
  the same `authority_sequence` cannot be ordered without a per-key
  monotonic field — is preserved as the Run 117
  `SameSequenceConflictingHash` / `SameSequenceConflictingKey` reject
  variants and surfaces unchanged through the new
  `AuthorityStatePrepareOutcome::ConflictReject(...)` wrapper.
- **Corruption / conflict fail closed.** A `LoadFailedFailClosed`
  outcome from `prepare_marker_for_acceptance` preserves the on-disk
  bytes verbatim — the wrapper does not delete, truncate, or repair a
  corrupted marker. Operator intervention (the `--allow-authority-state-
  reset` flag staged to the follow-up run) is the only recovery path.
- **No validation-only persistence.** The compare-before-accept wrapper
  is purely a load + validate + compare; it has no `persist_*` call site.
  Validation-only surfaces (reload-check, local peer-candidate check,
  live `0x05` validation) will be able to call it directly without any
  risk of accidental marker mutation.
- **No peer-driven apply.** No code path in Run 118 accepts a marker
  produced from a peer-supplied ratification on the wire. The Run 109
  `0x05` non-mutation contract is preserved bit-for-bit; the marker
  primitive is not even invoked from any peer-driven path.
- **No rotation / revocation lifecycle.** Run 118 adds no rotation
  state machine, no per-key sequence, and no revocation flag. The
  Run 120 per-key monotonic schema bump remains a prerequisite for
  any rotation guarantee.

---

## 5. Contradictions or inconsistencies

Cross-checked the Run 118 implementation against:

- **Run 100 authority model** — Run 118 records the *outcome* of operator-
  supplied genesis + sidecar validation, never a standalone authority
  anchor; "local-config alone is not enough on MainNet" remains true
  because the helper requires a verified `(BundleSigningRatification,
  RatifiedBundleSigningKey)` pair, which the production verifier only
  emits for ratifications signed by a genesis-bound root.
- **Run 101 genesis authority implementation** — the helper consumes
  `authority_policy_version`, `authority_sequence`, and `authority_epoch`
  directly from the caller (i.e. from the boot-time
  `GenesisAuthorityConfig`); no recomputation is performed inside the
  helper, so there is no risk of the helper computing a value different
  from what Run 101 hash-bound.
- **Run 102 boot verification** — Run 118 expects callers to have run
  `validate_canonical_genesis_at_startup` before invoking the helper;
  the genesis hash hex passed in is exactly the hash Run 102 produced.
- **Run 103 verifier** — Run 118 consumes a `RatifiedBundleSigningKey`
  produced by `verify_bundle_signing_key_ratification` and never re-
  derives the signature or the authority-root membership.
- **Run 104 key material registry** — the bundle-signing PK fingerprint
  the helper records is the SHA3-256 of the full PK bytes, identical to
  what Run 104 / `pqc_public_key_fingerprint` produces.
- **Run 105–115 ratification enforcement / evidence** — every existing
  surface still emits the same FATAL log lines, the same
  `VERDICT=applied`, the same `sequence_commit=ok`, and the same `0x05`
  peer-candidate non-mutation contract because Run 118 does not modify
  any of those surfaces. The Run 105 enforcement layer's `Outcome`
  variants are not changed.
- **Run 116 model** — the helper's `(chain_id, environment,
  genesis_hash, authority_policy_version, authority_sequence,
  authority_epoch, authority_root_fingerprint,
  ratified_bundle_signing_key_fingerprint, ratification_object_hash)`
  binding matches the Run 116 schema bit-for-bit.
- **Run 117 primitive** — the helper reuses
  `PersistentAuthorityStateRecord`, `compare_authority_state`,
  `load_authority_state`, `validate_record_for_domain`, and
  `persist_authority_state_atomic` without modification. No existing
  Run 117 test, error type, or comparison variant was changed.

**No contradictions found.** No silent regressions.

---

## 6. Explicit non-claims

Run 118 does **not** implement any of:

- signing-key rotation (requires Run 120 per-key monotonic field on
  `BundleSigningRatification`);
- signing-key revocation lifecycle;
- peer-driven live apply (Run 109 `0x05` non-mutation contract
  preserved bit-for-bit);
- KMS/HSM custody;
- governance;
- validator-set rotation;
- production startup / reload-apply / SIGHUP marker compare-and-persist
  wiring (deferred — helpers are landed; call sites are not);
- production reload-check / local peer-candidate check / live `0x05`
  validation marker conflict-check wiring (deferred);
- snapshot/restore conflict enforcement (the Run 117
  `AuthorityStateSnapshotMeta` carrier exists but no restore-side
  conflict check is wired in Run 118);
- full C4 closure;
- C5 closure.

Run 118 makes no MainNet readiness claim beyond what Run 117 already
made: the marker primitive plus its derivation/compare helpers exist
and are tested. No release binary writes the marker file in Run 118.

---

## 7. Evidence references

**Evidence document.** This file: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_118.md`.

**Tests added (21 new in `crates/qbind-node/src/pqc_authority_state.rs`,
module `tests::run118`):**
- Derivation: `derive_same_ratification_same_marker`,
  `derive_chain_change_changes_marker`,
  `derive_environment_change_changes_marker`,
  `derive_genesis_hash_change_changes_marker`,
  `derive_authority_root_change_changes_marker`,
  `derive_ratified_key_change_changes_marker`,
  `derive_ratification_digest_change_changes_marker`,
  `derive_digest_excludes_audit_fields`,
  `derive_rejects_malformed_genesis_hash`,
  `derive_rejects_runtime_env_disagreement`,
  `derive_rejects_runtime_chain_disagreement`,
  `derive_rejects_verifier_inconsistency`.
- Compare-before-accept: `prepare_first_write_when_no_persisted_marker`,
  `prepare_idempotent_after_first_persist`,
  `prepare_upgrade_at_higher_sequence`,
  `prepare_rejects_rollback`,
  `prepare_rejects_same_sequence_conflicting_hash`,
  `prepare_rejects_persisted_domain_mismatch`,
  `prepare_fails_closed_on_corrupt_persisted_marker`,
  `prepare_does_not_persist`,
  `outcome_classification_helpers`.

**Tests run (regression):**
- `cargo test -p qbind-node --lib` → 1158 passed / 0 failed.
- `cargo test -p qbind-ledger --lib` → 231 passed / 0 failed.
- `cargo test -p qbind-node --lib pqc_authority_state` → 59 passed
  (38 Run 117 + 21 Run 118) / 0 failed.

**Release-binary logs.** None — release-binary evidence is deferred to
the follow-up run that wires the mutating surfaces.

---

## 8. Residual risks and next recommended run

### Residual risks

1. **No release-binary evidence yet.** The helpers compile, are
   structurally consistent with the Run 117 primitive, and have unit
   coverage of every documented accept/reject path; but no DevNet binary
   has written the marker file end-to-end. A subtle integration mismatch
   between the helper's expected `(env, chain_id, genesis_hash)` inputs
   and what the boot path actually computes would only surface at
   call-site wiring time.
2. **Same-sequence key-level downgrade still undetectable.** Run 118
   does not solve the bounded protection limit that Run 117 documented:
   at equal `authority_sequence`, the marker can only catch a
   *content* conflict (`SameSequenceConflictingHash` /
   `SameSequenceConflictingKey`), not a key-level downgrade signed by
   the same authority root in two different but equivalent
   ratifications. Run 120's per-key monotonic field is still the
   prerequisite for closing this.
3. **Snapshot/restore enforcement still open.** The Run 117
   `AuthorityStateSnapshotMeta` carrier is present in
   `StateSnapshotMeta`, but no restore-side conflict check consumes it
   yet. A fast-sync / snapshot-restore that ships an older
   `AuthorityStateSnapshotMeta` than the local persisted marker would
   currently restore without conflict detection. Closing this is
   independent of the live-trust surface wiring and could be done in
   parallel.
4. **No operator-recovery flag yet.** The
   `--allow-authority-state-reset` + `--authority-state-reset-reason`
   pair that Run 116 specified is not yet wired into the CLI. Operators
   recovering from a corrupted marker would today need to delete the
   file manually, which is an out-of-binary action.

### Next recommended run

A **Run 119** that wires the three Priority-1 mutating surfaces
(`startup_validation.rs`, `pqc_live_trust_apply.rs`,
`pqc_live_trust_reload.rs`) to call `derive_authority_state_from_
ratification` + `prepare_marker_for_acceptance` + (on accept)
`persist_authority_state_atomic`, preserving the four-step
validate→snapshot→swap→evict→commit ordering bit-for-bit and persisting
the marker immediately after `commit_sequence`. Run 119 should also
produce the release-binary evidence the task's Scenario 1–4 calls for
(first-write accepted, equal-marker idempotent, conflicting marker
rejected, corrupt marker fail-closed). The validation-only surface
wiring and the `--allow-authority-state-reset` flag can land in a
companion run or fold into Run 119 if it stays narrow.

Run 118 does **not** claim full C4 closure and does **not** claim C5
closure. Static production source-code anchors remain rejected. Local
config alone remains insufficient for MainNet bundle-signing authority.