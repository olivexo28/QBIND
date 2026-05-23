# QBIND DevNet Evidence — Run 125

**Subject:** Release-binary evidence for the snapshot/restore authority
anti-rollback marker conflict enforcement landed in Run 124.
**Verdict:** **strongest-positive**
**Date:** 2026-05-23
**Task:** `task/RUN_125_TASK.txt`

---

## 1. Exact verdict

**strongest-positive.**

Run 125 is **evidence-only** — no production runtime code was changed.
The harness, an `examples/` fixture helper, and the docs are the only
additions. All 7 scenarios passed on the captured release binary.
Conflict-rejection, no-mutation-on-rejection, marker-integrity,
corrupt-marker-fail-closed, wrong-domain-fail-closed, and
no-context-fail-closed invariants are all proven on a real
`target/release/qbind-node` binary across the snapshot/restore
surface (Run 124 wiring).

**Surfaces covered:**

| Surface | Scenarios | Verdict |
|---------|-----------|---------|
| `--restore-from-snapshot` with Run 124 authority context (Run 102 `Verified` branch) | 1–6 | All pass |
| `--restore-from-snapshot` with legacy no-context path (Run 102 `SkippedNoExternalGenesis` branch) | 7 | Pass |

**Explicitly deferred, honestly (matching Run 124 strict non-goals):**

* `--allow-authority-state-reset` operator-recovery flag — future run.
* Per-key monotonic authority-sequence schema bump — future run
  (Run 126+, mirroring the staging language in the Run 123 / Run 124
  "Run X+ update" footers in `docs/whitepaper/contradiction.md` and
  `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`).
* Signing-key rotation / revocation lifecycle — future run.
* Peer-driven live apply — still intentionally non-mutating.
* KMS/HSM custody, governance, validator-set rotation — future.
* Wire format changes — none. Snapshot meta layout is the Run 117
  additive `authority_state` block; Run 125 does not change it.

---

## 2. Scenario matrix

All 7 scenarios run against the same `target/release/qbind-node`
build, with ephemeral DevNet fixtures minted by the fixture helper
(`run_125_snapshot_restore_authority_marker_fixture_helper`).

| # | Scenario | Local marker on disk | Snapshot `authority_state` | Expected outcome | Actual | Evidence file |
|---|----------|----------------------|---------------------------|------------------|--------|---------------|
| 1 | Legacy snapshot into fresh data dir | absent | absent | Accept (`NoMarkerEitherSide`); B3 audit marker written; no local marker invented | **PASS** | `logs/scenario_1_legacy_snapshot_no_local_marker.stderr.log` |
| 2 | Legacy snapshot would silently shadow local marker | matching | absent | Reject (`RejectMissingSnapshotMarker`); rc=1; no audit marker; local bytes preserved | **PASS** | `logs/scenario_2_legacy_snapshot_local_marker_present.stderr.log` |
| 3 | Matching snapshot + matching local marker | matching | matching | Accept (`AcceptMatchingMarker`); local marker bytes byte-identical post-run; B3 audit marker written | **PASS** | `logs/scenario_3_matching_snapshot_and_local_marker.stderr.log` |
| 4 | Same-sequence different ratification (equivocation) | matching | same `authority_sequence`, different `ratification_object_hash` | Reject (`RejectConflict(SameSequenceConflictingHash)`); rc=1; no audit marker; local bytes preserved | **PASS** | `logs/scenario_4_conflicting_snapshot.stderr.log` |
| 5 | Corrupt local marker (non-JSON 16 bytes) | corrupt | matching | Reject (`RejectLocalMarkerCorrupt`); rc=1; no audit marker; corrupt bytes preserved verbatim | **PASS** | `logs/scenario_5_corrupt_local_marker.stderr.log` |
| 6 | Wrong-domain snapshot (different `genesis_hash`) | absent | wrong `genesis_hash_hex` | Reject (`RejectSnapshotMarkerWrongDomain`); rc=1; no audit marker | **PASS** | `logs/scenario_6_wrong_domain_snapshot_no_local.stderr.log` |
| 7 | Legacy no-context entry point + local marker | matching | matching (irrelevant; path doesn't compare) | Reject (`AuthorityContextMissing`); rc=1; no silent shadowing through the no-context path | **PASS** | `logs/scenario_7_no_genesis_context.stderr.log` |

---

## 3. Key evidence lines

### 3.1 Scenario 1 — legacy snapshot accepted into fresh data dir

```
[restore] requested: snapshot_dir=.../snap-legacy data_dir=.../scenario_1_legacy_snapshot_no_local_marker expected_chain_id=0x51424e4444455600
[restore] Run 124 authority-marker check: no local authority marker and no snapshot authority metadata (legacy snapshot, fresh data dir; restore may proceed without authority enforcement on the restore surface) (proceeding with materialization)
[restore] complete: height=100 chain_id=0x51424e4444455600 bytes_copied=8572 target=.../state_vm_v0
[restore] audit marker written to .../RESTORED_FROM_SNAPSHOT.json
[restore] OK: restored from snapshot height=100 chain_id=0x51424e4444455600
```

Post-run on-disk shape under the per-scenario data dir:

```
data/scenario_1_legacy_snapshot_no_local_marker/
├── RESTORED_FROM_SNAPSHOT.json          # B3 audit marker
├── state_vm_v0/                         # materialized RocksDB checkpoint
└── (no pqc_authority_state.json — restore surface never invented one)
```

### 3.2 Scenario 2 — legacy snapshot rejected when local marker exists

```
[restore] FATAL: refused by Run 124 authority-marker check: snapshot restore rejected: local authority marker exists but snapshot carries no authority metadata (fail closed; accepting would silently erase or roll back the local persisted authority state)
[restore] ERROR: restore-from-snapshot refused by authority-marker check: ... (no state mutation, no audit-marker write; local pqc_authority_state.json bytes preserved verbatim)
[restore] qbind-node refuses to start because the requested snapshot restore could not be honestly applied.
```

Local marker sha256 before run: `a3008fd4c8a1c86a9d3a4ca33b753f943c90f19201477d3c415b65e5457535ff`.
Local marker sha256 after run:  `a3008fd4c8a1c86a9d3a4ca33b753f943c90f19201477d3c415b65e5457535ff` — byte-identical.

No `RESTORED_FROM_SNAPSHOT.json` and no `state_vm_v0/` under the data
dir — refused before mutation.

### 3.3 Scenario 3 — matching snapshot accepted; local marker NOT rewritten

```
[restore] Run 124 authority-marker check: local authority marker matches snapshot authority metadata bit-for-bit (restore may proceed; local marker NOT rewritten) (proceeding with materialization)
[restore] complete: height=101 chain_id=0x51424e4444455600 bytes_copied=8572 target=.../state_vm_v0
[restore] audit marker written to .../RESTORED_FROM_SNAPSHOT.json
[restore] OK: restored from snapshot height=101 chain_id=0x51424e4444455600
```

Local marker sha256 before: `a3008fd4c8a1c86a9d3a4ca33b753f943c90f19201477d3c415b65e5457535ff`.
Local marker sha256 after:  `a3008fd4c8a1c86a9d3a4ca33b753f943c90f19201477d3c415b65e5457535ff` — byte-identical.

This is the "no synthesis from snapshot bytes" invariant on the
accept path. The restore surface never writes, rewrites, or deletes
`<data_dir>/pqc_authority_state.json`; only B3's
`RESTORED_FROM_SNAPSHOT.json` and `state_vm_v0/` checkpoint are
written.

### 3.4 Scenario 4 — same-sequence equivocation rejected

```
[restore] FATAL: refused by Run 124 authority-marker check: snapshot restore rejected: snapshot authority metadata conflicts with local marker: authority-state same-sequence equivocation rejected: authority_sequence=7 persisted_ratification_hash=ddd... attempted_ratification_hash=eee... (fail closed; two distinct ratifications cannot share the same authority_sequence) (fail closed)
```

No audit marker, no state materialization, local marker bytes
preserved verbatim.

### 3.5 Scenario 5 — corrupt local marker fails closed; bytes preserved

```
[restore] FATAL: refused by Run 124 authority-marker check: snapshot restore rejected: local authority marker is corrupt or unsupported: pqc authority-state malformed: expected value at line 1 column 1 (fail closed) (fail closed; bytes preserved verbatim)
```

Corrupt marker sha256 before: `b3ef3c781f73c95e46e1d73cd209f235b58b7942d49110a3991295dccaeb4be5`.
Corrupt marker sha256 after:  `b3ef3c781f73c95e46e1d73cd209f235b58b7942d49110a3991295dccaeb4be5` — byte-identical.

The restore surface does NOT auto-repair, NOT delete, NOT overwrite
the corrupt bytes.

### 3.6 Scenario 6 — wrong-domain snapshot rejected even without local marker

```
[restore] FATAL: refused by Run 124 authority-marker check: snapshot restore rejected: snapshot authority metadata has wrong trust domain: snapshot.genesis_hash_hex=fff... runtime.genesis_hash_hex=70c64204... (fail closed)
```

A snapshot whose `authority_state.genesis_hash_hex` does not match
the canonical Run 101 hash of the runtime genesis is refused before
materialization — Run 124's wrong-domain branch is fully wired on
the release binary.

### 3.7 Scenario 7 — legacy no-context path itself fails closed on pre-existing marker

```
[run-102] no external --genesis-path configured; canonical boot verification skipped (env=Devnet, embedded-genesis path). MainNet always requires --genesis-path so this branch is unreachable on MainNet.
[restore] requested: snapshot_dir=.../snap-matching data_dir=.../scenario_7_no_genesis_context expected_chain_id=0x51424e4444455600
[restore] ERROR: restore-from-snapshot refused: a local pqc_authority_state.json marker exists but no runtime authority context (env, chain_id, genesis_hash) was supplied to the restore surface (fail closed). Use restore_from_snapshot_with_authority_marker_check from a binary surface that has loaded the canonical genesis.
[restore] qbind-node refuses to start because the requested snapshot restore could not be honestly applied.
```

This proves Run 124's "no silent shadowing through the no-context
path either" invariant on the release binary: even on DevNet without
`--genesis-path`, a pre-existing local marker causes
`AuthorityContextMissing`. Local marker bytes preserved verbatim.

---

## 4. Artifacts

| File | Description |
|------|-------------|
| `scripts/devnet/run_125_snapshot_restore_authority_marker_release_binary.sh` | Release-binary evidence harness |
| `crates/qbind-node/examples/run_125_snapshot_restore_authority_marker_fixture_helper.rs` | Ephemeral fixture helper (DevNet genesis + 4 snapshots + 2 local markers + manifest) |
| `docs/devnet/run_125_snapshot_restore_authority_marker/` | Evidence archive directory |
| `docs/devnet/run_125_snapshot_restore_authority_marker/summary.txt` | sha256s, build IDs, scenario rc/before/after sha256s |
| `docs/devnet/run_125_snapshot_restore_authority_marker/logs/` | Per-scenario stderr + exit codes (7 scenarios × 2 files each) |
| `docs/devnet/run_125_snapshot_restore_authority_marker/local-marker-matching.json` | The canonical `PersistentAuthorityStateRecord` fixture that was seeded into the per-scenario data dirs |
| `docs/devnet/run_125_snapshot_restore_authority_marker/snap-matching.meta.json` | Snapshot meta with matching `authority_state` block |
| `docs/devnet/run_125_snapshot_restore_authority_marker/snap-conflicting.meta.json` | Snapshot meta with the same `authority_sequence` but a different `ratification_object_hash` |

---

## 5. Test results

All existing unit and integration tests pass byte-identically on the
same build used for this evidence:

| Test suite | Count | Result |
|-----------|-------|--------|
| `run_124_snapshot_restore_authority_marker_tests` | 7 | all pass |
| `b3_snapshot_restore_tests` | 10 | all pass |
| `run_119_authority_marker_acceptance_tests` | 4 | all pass |
| `run_121_sighup_authority_marker_tests` | 7 | all pass |
| `qbind-node --lib pqc_authority_state` | (full module) | all pass |

No existing test was modified. No production runtime code was
changed. The new fixture helper lives in `examples/` and is built
only when explicitly requested (`cargo build --example
run_125_snapshot_restore_authority_marker_fixture_helper`).

---

## 6. Non-goals confirmed

* No validation-only marker writes.
* No fake authority sequence injection (Scenario 4 uses the same
  `authority_sequence` deliberately, so the binary's existing
  same-sequence-equivocation rule does the work — no synthetic
  bump).
* No peer-driven live apply.
* No signing-key rotation or revocation lifecycle.
* No KMS/HSM custody, governance, or validator-set rotation.
* No trust-bundle wire format or peer-candidate wire format change.
* No new CLI flag, metric family, or dependency.
* No production `crates/**/src/**` change — evidence-only. The only
  new code under `crates/` is `crates/qbind-node/examples/run_125_*.rs`,
  which is not compiled into `qbind-node` and is not invoked by any
  production binary path.

---

## 7. Relationship to prior runs

* Run 117 added the additive `AuthorityStateSnapshotMeta` snapshot
  carrier (no behaviour change).
* Run 118 wired the typed `compare_authority_state` primitive that
  Run 124 composes with.
* Run 119/120/121 wired the three mutating surfaces.
* Run 122 was the release-binary evidence-only sub-run for the
  three mutating surfaces.
* Run 123 wired the three validation-only surfaces.
* Run 124 wired the snapshot/restore surface, deferring release-binary
  evidence "to an optional future sub-run, matching the Run 119 → Run
  122 pattern" (see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_124.md`
  §Forward staging).

Run 125 is that sub-run. It presents release-binary evidence for the
snapshot/restore authority anti-rollback marker conflict enforcement
on the same build as the rest of the Run 124 source/unit/integration
test evidence, closing the release-binary evidence gap identified in
Run 124.

---

## 8. Statement Run 125 makes true on the release binary

> On a release-built `target/release/qbind-node` binary, snapshot
> restore cannot silently downgrade, conflict with, erase, rewrite,
> or repair the locally persisted ratified bundle-signing authority
> marker; conflicting snapshot authority metadata fails closed
> before restore acceptance, the B3 `RESTORED_FROM_SNAPSHOT.json`
> audit marker is never written on a refusal path, no `state_vm_v0/`
> bytes are materialized on a refusal path, and the local
> `pqc_authority_state.json` bytes are byte-identical post-refusal.
> Matching authority metadata is accepted and the local marker
> bytes are still byte-identical post-acceptance (the restore
> surface never writes the local marker file, even when the
> snapshot block matches it).

Proven by Scenarios 1–7 (§2, §3) running against
`target/release/qbind-node` (sha256 + build-id recorded in
`docs/devnet/run_125_snapshot_restore_authority_marker/summary.txt`).