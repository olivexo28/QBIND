# RUN 422 — Reproducible generation-only prepared-decision L0 ownership spike

**Status:** bounded executable experiment, complete. **IMPLEMENTED-ISOLATED /
PASS-ACCEPTED-SUBSET** for the accepted storage component is preserved.
Activation remains **DISABLED**; public DevNet remains **NO-GO**. No engine
wiring, signing enablement, stage-2 verification, anti-rollback architecture,
startup changes, deployment, or Run 423 is performed.

This directory is a *read/reproduce* evidence package. The experimental source
changes live in an isolated checkout and are reproduced here as a complete
applicable patch plus the two new-file sources, actual command logs, baseline
identity, and checksums. The accepted storage code, contracts, assurance
artifacts, and verdicts on the supplied branch are **not** modified by this
package — `prepared.rs` and the spike test are delivered as an evidence patch,
not wired into the accepted component.

## 1. Baseline and experimental identity

See [`BASELINE.txt`](BASELINE.txt).

- Supplied branch (unrenamed): `copilot/complete-engineering-brief`
- Baseline HEAD (experiment parent): `8aa44e520cf6e15568231bc4da122da804f5b4fb`
- Asserted correspondence target: `cfb88a3ff5c3a8e1c47fa2740450c10e7ba2a76d`
  (absent from this shallow single-branch clone; correspondence is asserted per
  the brief, not re-verified by diff here).
- Isolated experimental checkout: `cp -a` of the baseline, same branch name.
- Complete applicable patch:
  [`patch/run_422_spike_prepared_generation.patch`](patch/run_422_spike_prepared_generation.patch)
  (9 files, +1711/-5; two new files included).

## 2. Design: generation-only prepared retention

The previous full-proof approach re-charged the ~811-byte encoded record buffer
against budget that `profile.rs::max_aggregate_retained_bytes` never reserved for
prepared holders. The holder term there budgets prepared entries as
**generation-only**: per outstanding entry `identity (40) + arc_handle (8) = 48`
bytes, with **no** encoded-buffer term, plus a pinned superseded generation under
the existing generation multiplicity. Generation-only retention therefore fits
**without raising** `GEN_STRUCT_MAX`, `CAPNORM_SLACK`, any multiplicity, or the
aggregate ceilings.

On a successful capture the experiment retains the **decoded evidence generation
and required provenance only**; the original encoded record is dropped. On
refusal the original proof — original bytes and O5 reservation — is returned
intact and keeps its existing O3/O5 behavior.

### Ownership / conversion / release sequence (capture)

`SafetyRecordOwner::capture_prepared_decision(proof: ValidatedRecord,
expected_authoritative_revision: u64) -> Result<PreparedPin, (ValidatedRecord,
CaptureRefusal)>` (owner.rs:1224).

Gate order — all borrow the proof (no consumption) until the commit step:

1. `recovery_required()` → `RecoveryRequired`.
2. backend incarnation: `proof.recovery_backend_incarnation() != Some(inc)` →
   `ForeignOrUncharged` (catches both a foreign incarnation and a standalone
   `None`/uncharged proof).
3. pinned-context digest mismatch → `ForeignContext`.
4. `BootstrapNoLock` record → `BootstrapUnresolved` (Locked-only; bootstrap left
   explicitly unresolved).
5. **serialization domain lock** (the existing accountant/domain lock is the
   linearization point; registry mutex is the leaf — capture takes
   domain → registry, release/Drop takes registry only; no cycle).
6. authoritative-revision read under the domain (the metadata-read scratch
   allocation is charged via `authoritative_revision_locked` *before* the read);
   mismatch → `StaleRevision`.
7. registry lock → first free slot, else `RegistryFull` (**no eviction**).
8. `next_serial_checked()` → `CounterExhausted` **before** any mutation
   (fail-closed; never wraps or reuses an identity).
9. reserve the per-entry charge (48) on the shared accountant.
10. share-or-reserve the generation: if an existing entry already pins an equal
    `RetainedRecord` (non-cloning `PartialEq`), clone its `Arc` backing and drop
    the incoming generation; otherwise reserve a fresh generation charge.
11. **commit**: consume the proof (`ValidatedRecord::into_prepared_parts`),
    destructure, drop `encoded`, release the prior full-proof holder
    (`release_now`), insert the entry, return a `PreparedPin`.

There is **no interval in which a live object is uncharged**: the new
generation + per-entry reservations are taken *while the proof's full holder is
still live and charged* (accepted "conversion overlap"); only after both the new
reservations hold and the entry is inserted is the old holder released. Evidence
`Vec`s are never cloned to simplify ownership.

### Release / abandonment

- `SafetyRecordOwner::release_prepared(pin)` (owner.rs:1358): normal completion.
- `PreparedPin` is a **non-`Copy` owning guard**; its `Drop` releases the entry
  automatically (abandonment cleanup) while the backend is alive. Explicit
  release and automatic `Drop` share one inner release path.
- `PreparedHandle` is `Copy` and owns nothing: it can neither keep an entry
  alive nor release it twice. Lookup and release both check the backend
  incarnation stamped on the handle → `ForeignIncarnation`; a stale serial →
  `NotFound`.
- Release on rejection: every refusal path returns the proof and takes no
  registry slot; the per-entry reservation taken at step 9 is released if a
  later step (generation admission) fails. `D10` obligations are untouched.

## 3. Object-to-reservation table

Per prepared entry (application-owned, charged against the existing holder /
generation terms of the aggregate ceiling):

| Object | Charged reservation | Notes |
|---|---|---|
| Entry identity (lock_block_id 32 + lock_view 8) | 40 | existing holder `identity` term |
| `Arc` handle to shared generation backing | 8 | existing holder `arc_handle` term |
| **Per-entry subtotal** | **48** | `prepared_entry_charge_bytes()` |
| Shared generation backing (`Arc<GenerationBacking>`, decoded evidence + provenance) | `prepared_generation_charge` | one charge **shared** across entries pinning an equal `RetainedRecord`; released on the **last** entry drop |

Infrastructure objects **not** charged against the aggregate (backend
infrastructure, on par with the serialization-domain / accountant mutexes):
`PreparedRegistry` container (fixed `[Option; 2]` slots, `next_serial`,
`incarnation`), its `Arc<Mutex<…>>`. Inline `size_of` is reported for audit only
(registry 240, entry 112, backing 464, handle 24 bytes) and each allocation is
counted once — the registry inline size already includes its embedded slots.

Initialization and refusal paths: at construction the registry holds 0 entries
and 0 generation charges. On any refusal, 0 slots and 0 generation charges are
added; a per-entry reservation taken before a later-step refusal is released
back to the pre-capture baseline (verified).

## 4. N=1 / N=4 coexistence measurements (measured, not hardcoded)

Aggregate ceiling: **3956** (N=1) / **7772** (N=4), unchanged.

| Quantity | N=1 | N=4 |
|---|---|---|
| QC generation charge | 417 | 481 |
| TC generation charge | 536 | 888 |
| Generation sub-ceiling | 552 | 1104 |
| Full-proof holder (pre-conversion) | 1097 | 2051 |
| Per-entry charge | 48 | 48 |
| **Shared** generation, two entries (current) | 513 | 577 |
| **Distinct** generations, two entries coexisting (current) | 930 | 1058 |

**Coexistence result:** two **distinct** prepared generations plus their
per-entry reservations coexist successfully at both N=1 (930 ≤ 3956) and N=4
(1058 ≤ 7772), with ample room remaining for a contemporaneous O4 publication
reservation. No shortfall; no ceiling increase required.

## 5. Executed test results

All commands run in the isolated checkout after the experimental changes. Raw
logs under [`logs/`](logs). Literal outcomes:

- Focused spike tests
  ([`logs/01_spike_tests.log`](logs/01_spike_tests.log)):
  **23 passed; 0 failed; 0 ignored.**
  Covers: fixture dimensions/charges (N=1,4); shared generation (two entries,
  one generation charge, first drop retains, last drop releases); distinct
  generations + registry-full third-entry refusal without eviction; normal
  release and automatic abandonment (Drop) while the backend is alive;
  Bootstrap/stale-revision/foreign-incarnation/standalone-None/foreign-context/
  recovery-required refusals with the proof returned intact; counter exhaustion
  fail-closed before mutation via a bounded test seam; stale/foreign handle
  refusal; capture/publication interleaving under the serialization boundary;
  admission refusal before new allocation + cleanup-to-baseline + readmission;
  TC-generation capture; evidence/context binding.
- Default library build
  ([`logs/02_default_lib_build.log`](logs/02_default_lib_build.log)):
  **Finished** (the spike test and inspection seams are `test-utils`-gated and
  absent from a default build).
- Existing D7–D14 regression target
  ([`logs/03_d7d14_regression.log`](logs/03_d7d14_regression.log)):
  **157 passed; 0 failed; 1 ignored** (inherited, re-executed, **not** relabeled
  as newly authored).

## 6. Remaining concrete blocker / untested guarantees

No design blocker: ownership and admission resolve within the unchanged limits.

Deliberately **untested until actual engine integration** (capture is
non-authorizing and does not establish these): engine decision timing,
stage-2 certificate verification against independently supplied trusted context,
current-authority freshness and anchor selection, durability acknowledgement,
verified-evidence status, and `BootstrapNoLock` resolution (left explicitly
unresolved for this Locked-only experiment).

## 7. Durable artifacts and checksums

See [`SHA256SUMS.txt`](SHA256SUMS.txt) for sha256 of every file in this package
(patch, new-file sources, logs, baseline).