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

This revision completes the prepared-generation registry's **allocation
lifetime**: the registry is now **lazily allocated** — it does not exist at
backend open or ordinary attachment, is created only on the first prepared
capture after its storage charge is admitted, and is then **retained with its
reservation for the whole allocation lifetime** (including zero-entry periods),
released only when the allocation is destroyed. It preserves the corrected
prepared-generation **object accounting** and shared-conversion **lifetime** of
the previous package.

This revision additionally **removes the uncharged eager initialization
allocation** the previous package had introduced: the backend no longer allocates
a separate `Arc<Mutex<Option<Arc<Mutex<PreparedRegistry>>>>>` lazy-init wrapper at
open. The one-word lazy slot now lives **inside the already-existing
serialization domain** (reached through the pre-existing `domain` mutex), so no
new per-open heap allocation is created and the corrected inner lifecycle
(admission-before-allocation, one shared registry, standing reservation while
empty, ownership extending through an outliving pin) is unchanged. It also adds
two **discriminating** sensitivity experiments — a duplicate-release invariant and
a coordinated concurrent-serialization overlap — each exercised against an actual
**source mutation** with raw failure/restoration logs. The headings below keep
four kinds of evidence distinct:
*source-derived arithmetic* (struct layout and charge formulas), *executed
object observations* (measured live allocations), *reservation observations*
(live aggregate charges), and *inherited evidence* (the baseline identity and
the re-executed D7–D14 target).

## 1. Baseline and experimental identity

See [`BASELINE.txt`](BASELINE.txt).

- Supplied branch (unrenamed): `copilot/run-422-finish-lazy-registry-allocation`
- Baseline HEAD (experiment parent): `8aa44e520cf6e15568231bc4da122da804f5b4fb`
- Asserted correspondence target: `cfb88a3ff5c3a8e1c47fa2740450c10e7ba2a76d`
  (absent from this shallow single-branch clone; correspondence is asserted per
  the brief, not re-verified by diff here).
- Isolated experimental checkout: `cp -a` of the baseline, same branch name.
- Complete applicable patch:
  [`patch/run_422_spike_prepared_generation.patch`](patch/run_422_spike_prepared_generation.patch)
  (9 files, +3668/-10; two new files included).

## 2. The corrected defect (inherited observation)

The previous package charged `prepared_generation_charge` as the **synthetic
`RetainedGeneration` inline size**, while `insert_fresh` actually allocates an
`Arc<GenerationBacking>`. A captured prepared generation therefore lived as an
object strictly larger than its reservation.

*Inherited reported figure (baseline representation):* for the N=1 TC case the
live allocation was `GenerationBacking` inline `464` + owned evidence backings
`152` + `Arc` overhead `16` = **632 bytes**, versus a generation reservation of
only **536** — a silent undercharge of 96 bytes. In addition the registry cell
and the owning pins were exempted as "backend infrastructure", and evidence
capacity was read through a silent `evidence_backing_capacity(...).unwrap_or(0)`
that masked measurement failure.

## 3. §1 — Corrected actual-object accounting

The correction charges the **actual** `Arc<GenerationBacking>` allocation and all
previously-exempt owning objects, with no silent measurement substitution:

- `RetainedRecord::evidence_backing_capacity` / `retained_evidence_capacity` now
  return `Result<usize, SafetyStoreError>`; the `.unwrap_or(0)` is removed, so a
  measurement failure is **explicit**, never a silent zero.
- `prepared_generation_charge` (**generation-core**) is the size of the embedded
  `RetainedRecord` + the owned evidence backing capacities + the `Arc` control
  overhead (`ARC_CTRL = 16`). It stays within the unchanged generation
  sub-ceiling (`GEN_STRUCT_MAX`, `CAPNORM_SLACK`, multiplicities untouched).
- `prepared_holder_control_charge` (**holder/control**) =
  `size_of::<GenerationBacking>() − size_of::<RetainedRecord>()`: the remainder
  of the heap wrapper beyond the embedded record, including the embedded control
  `Reservation`, provenance pin, and padding.
- The registry cell (`Arc<Mutex<PreparedRegistry>>` + its reservation) is charged
  **once**, **lazily**: no registry exists before the first prepared capture; on
  first capture the registry-storage charge is admitted **before** the allocation
  is created, and the installed registry then **owns that reservation for its
  entire allocation lifetime — including while it holds zero entries** — releasing
  it only when the allocation is destroyed (its last owner, the backend slot plus
  any outstanding pin, drops). Deallocation-whenever-empty is **not** performed.
  Each owning `PreparedPin` is charged per live pin. Neither is exempt.

Every embedded entry is counted **once** within its containing allocation: the
`RetainedRecord` is counted inside `GenerationBacking` (never separately), and
the registry's fixed `[Option; 2]` slots are counted inside the registry cell.

### Source-derived arithmetic (measured `size_of`, audit only)

| Symbol | bytes |
|---|---|
| `size_of::<GenerationBacking>()` | 512 |
| `size_of_retained_record()` | 368 |
| holder/control = 512 − 368 | **144** |
| `size_of::<PreparedRegistry>()` | 176 |
| registry-cell charge (`Arc<Mutex<…>>` + reservation) | **208** |
| `size_of::<PreparedPin>()` / pin charge | **96** |
| `size_of::<PreparedEntry>()` | 56 |
| `size_of::<PreparedHandle>()` | 24 |

The registry-storage charge was **re-measured** after the lifetime change (the
registry's reservation field is now an owned `Reservation`, held for the whole
allocation lifetime, rather than an `Option<Reservation>` cleared when empty):
`size_of::<PreparedRegistry>()` is **176** and the registry-cell charge
(`Mutex<PreparedRegistry>` cell + `Arc` control overhead) is **208** —
measured, not assumed.

### Executed object observation vs covering reservation

`actual Arc<GenerationBacking> = size_of::<GenerationBacking>() + owned backings
+ ARC_CTRL`, covered exactly by `generation-core + holder/control`:

| N / class | inline | owned backings | Arc | **actual** | core | control | core+control |
|---|---|---|---|---|---|---|---|
| N=1 TC | 512 | 152 | 16 | **680** | 536 | 144 | **680** |
| N=4 TC | 512 | 704 | 16 | **1232** | 1088 | 144 | **1232** |

The discriminating assertion (`spike_actual_object_accounting_n{1,4}`) shows
core-only **under-covers** the actual allocation by **exactly** the holder/control
charge, and core+control covers every live byte exactly. (Embedding the control
reservation grows the wrapper from the baseline 464 to 512; the undercharge the
baseline reported as 96 is now the fully-accounted 144, and it is charged, not
exempted.)

## 4. §2 — Corrected shared-conversion lifetime

On a shared capture the incoming duplicate proof owns its **own** evidence
backings; only the canonical generation's `Arc` backing is retained. The previous
code released the duplicate's covering reservation (`prior_holder`) **before**
dropping the duplicate's `retained` evidence, leaving those bytes live-but-
uncharged for an interval. The correction destroys `parts.retained` **before**
releasing `parts.prior_holder`, and preserves the canonical generation's
independent reservation.

A discriminating regression (`spike_sharing_lifetime_regression_n{1,4}`) drives a
bounded, one-shot test seam that records the duplicate bytes **live at the moment
its reservation is released**:

| ordering | live-at-release (N=1 / N=4) |
|---|---|
| premature (`HolderBeforeRetained`) | 33 / 129 — **non-zero: the defect** |
| corrected (`RetainedBeforeHolder`, default) | 0 / 0 — **passes** |

The test fails under the premature ordering and passes after correction, then
**restores** the sensitivity mutation (`set_shared_release_order(RetainedBefore
Holder)`). It covers fresh conversion, shared conversion, refusal (no conversion,
empty registry), explicit release, and automatic `Drop`.

### Discriminating invariant + source-mutation evidence

The runtime seam above proves the branch *selection* is observable, but it is a
**branch-assigned** observer: the capture path *sets* the reported value from the
chosen `SharedReleaseOrder` branch, so it reports which branch ran rather than
independently measuring backing liveness. It is retained as historical evidence
for the branch-selection experiment (`spike_sharing_lifetime_regression`).

The **invariant** test, `spike_duplicate_release_invariant_n{1,4}`, instead reads
an **independent owned-object destruction probe** (`dup_backing_live_at_release()`):
each duplicate evidence backing is registered live with its measured backing byte
size and a `Drop` probe is bundled onto the retained object, so the live byte total
decrements exactly when that owned object is actually destroyed. The probe measures
owned-object destruction by byte size — it does **not** trace allocation addresses
or object identities. It is sampled at the covering-reservation **release
boundary**. The sampled value is therefore derived from real owned-object
destruction — **not** from the selected release-order flag and **not** from a
hard-coded expected value. The single unchanged invariant it asserts is
**`Some(0)`: zero duplicate backing bytes remain live when their covering
reservation is released** — it never expects the defect value.

To show this invariant is *sensitive to the production teardown order*, the normal
(corrected) shared branch was mutated **in source** by moving the covering
reservation's release (`prior_holder.release_now()`) **before** the duplicate
backing's destruction (`drop(retained)`), leaving the observer and the test
assertion byte-for-byte unchanged:

| Source state | `spike_duplicate_release_invariant` | Log |
|---|---|---|
| mutated (release before backing destruction) | **FAILS** — `Some(33)` / `Some(129)` | [`logs/04_dup_release_mutation_fail.log`](logs/04_dup_release_mutation_fail.log) |
| restored (destroy backing before release) | **PASSES** — `Some(0)` / `Some(0)` | [`logs/05_dup_release_restored_pass.log`](logs/05_dup_release_restored_pass.log) |

The failing `Some(33)` / `Some(129)` counts are read from the independent probe,
not assigned by the selected branch. The source was restored **byte-identically**
(sha256 `d7dcea17…` verified before and after) after the experiment; the
production path drops the probe under `#[cfg(not(test))]` (no runtime cost).

## 5. §3 — Bounded coexistence evidence (measured, not hardcoded)

Aggregate ceiling: **3956** (N=1) / **7772** (N=4), unchanged. Maximum complete QC
and TC fixtures at N=1 and N=4 (N signer/timeout entries, maximum signature
lengths, all nested signer backings, required anchor/predecessor history);
explicit dimension and capacity assertions precede every measurement.

### Reservation observations — two **distinct** pinned generations, through O4

Measured through capture and through an O4 publication while two distinct
prepared generations remain pinned (context ownership + conversion overlap
included):

| Quantity | N=1 | N=4 |
|---|---|---|
| context-ownership standing partition | 192 | 240 |
| generation-core, each (QC) | 417 | 513 |
| two distinct generations, operational (2·core + 2·control + registry-cell + 2·pin) | 1522 | 1714 |
| aggregate with two pinned (context + operational) | **1714** | **1954** |
| aggregate ceiling | 3956 | 7772 |

**Two distinct prepared generations coexist while pinned at both N** (1714 ≤ 3956;
1954 ≤ 7772). That aggregate-with-two figure is the **pre-operation** reservation,
sampled *before* any O4 is attempted — its slack from the ceiling is the
**pre-operation headroom** (2242 at N=1, 5818 at N=4). The honest distinction is
the *contemporaneous O4 through both*, observed at a real O4 phase while both
generations stay pinned:

- **N=4 — COEXIST_THROUGH_O4:** a further authoritative publication (a third
  maximum anchored lock) while both generations stay pinned **succeeds**. The run
  now samples the executing backend **during** the O4 — at the publish
  pre-effective phase, after admission and before release, while both prepared
  generations remain pinned and the O4 reservation is live. The contemporaneous
  reservation sample is **operational 6413, aggregate 6653** (= context-ownership
  240 + operational 6413), giving an **in-operation O4 reservation of 4699** and an
  **in-operation headroom of 1119**; the unchanged aggregate ceiling **holds at
  that phase** (6653 ≤ 7772). This is distinct from, and much tighter than, the
  5818 pre-operation headroom.

  At that **same** pre-effective phase the run also derives an **independent
  live-object measurement** — an actual per-object charge, not a reservation
  counter — for every contract-charged object live there: the two pinned prepared
  generations (each measured as its retained-record size + evidence backing
  **capacities** + `Arc` control + control charge), the prepared **registry cell**
  once, and one **pin** per occupied slot (**1714** pinned-object bytes), plus the
  **O4-owned objects** of the in-flight publication. Those O4-owned objects are the
  **actual live objects the publish path still holds at that phase**, measured **in
  place** — not a post-operation reconstruction and not derived from a reservation
  counter. At the pre-effective phase `owner.rs` holds a **`ValidatedRecord`** (the
  retained validated proof — **not** a transient `DecodedRecord`), and its
  metadata-encoding temporary remains live through the publish match arm. The
  measured O4-owned bytes are therefore the **complete `ValidatedRecord` inline
  size** counted once (**496**), its **owned evidence-backing capacities** (**129**),
  its **retained encoded publication buffer** capacity (**310**), and the **live
  metadata payload** capacity (**42**) = **977**. The measured live-object total is
  **2691** (pinned 1714 + O4-owned 977). The precise phase is identified by its
  genuine two-pin occupancy (`occupied == 2`); objects already destroyed there (the
  CRC staging envelopes inside `publish_atomic`, which has returned by this phase)
  are **not** counted. Object measurements, reservation observations, and
  source-derived bounds are kept **separate**, and a missing backing capacity
  **fails explicitly** (the publish-path measurement surfaces its `Err`; the sampler
  rejects a missing slot). An independent **source-derived cross-check** (audit
  only, not the asserted observation and not substituted for the measured values),
  using the reported layouts and a 310-byte encoded capacity, is
  `1714 + 496 + 129 + 310 + 42 = 2691`. The asserted bounds are **measured
  live-object charge 2691 ≤ contemporaneous covering operational reservation 6413**
  and **context 240 + operational 6413 = aggregate 6653 ≤ unchanged ceiling 7772**;
  the 4699 in-operation O4 reservation is retained only as a source-derived bound
  and is **not** substituted for the object measurement.

  The in-operation observation is taken through a **non-cyclic** mechanism: the
  pre-effective hook captures a shared `accounting_handle_for_test()` accountant
  (plus leaf registry/pin handles) instead of a **cloned `SafetyBackend`**, so the
  backend's shared hook slot no longer retains a backend clone (the previous
  backend→hook→callback→backend retention cycle is removed). After the pins,
  temporary proofs, owner/backend handles, and sampler ownership are released, an
  **independent accountant** observes **0** remaining registry or generation
  reservation (teardown verified). A third capture is then refused `RegistryFull`
  without eviction; both pins release to baseline.
- **N=1 — COEXIST_REFUSE_O4 (genuine two-pin publication refusal):** the same O4
  through both pinned generations would reach **4103 > 3956**, an exact
  **147-byte shortfall** (measured against the unchanged fixtures, not forced to a
  prior figure). Because the operation is **refused**, there is **no admitted
  in-operation O4 phase** to sample — the in-operation observation is honestly
  `NONE(refused)` and no admitted O4 is fabricated. Across the refusal the run
  compares **actual state**: it captures, *before* the refused publication (and
  outside the measured allocation interval), the **complete stored record bytes**,
  the **complete stored metadata bytes**, the **publication revision** (separately),
  **`owner.recovery_required()`** (not merely the backend incarnation), both
  retained **pin identities/provenance**, and the **operational and aggregate**
  reservations; then confirms *after* the refusal that **every one** of these is
  unchanged — complete record bytes equal, complete metadata bytes equal, revision
  equal, `recovery_required()` equal, both pins still resolve to their original
  retained generation identities/provenance (occupancy alone is insufficient), and
  both the operational and aggregate reservations returned to the pre-operation
  baseline (the refusal mutated nothing). It then (c) **explicitly abandons** the
  necessary pin (`release_prepared(pin1)`), freeing one registry slot while the
  retained registry keeps its standing reservation; (d) **retries the SAME refused
  publication** (the byte-identical cloned lock C at the same expected revision),
  which is now **readmitted** to revision 3; (e) captures into the freed slot and
  releases both, returning the aggregate to context-ownership + the standing
  registry charge — **without** raising any limit or redefining any exclusion.

### Other §3 evidence

- `spike_capture_publication_boundary`: a deterministic capture/publication
  boundary test (replacing the prior sequential "concurrency" claim) that
  distinguishes correct serialization from its removal.
- `spike_capture_publication_serialization_overlap`: a **coordinated concurrent**
  test (replacing the earlier "deterministic — no threads" substitution) in which
  a publisher thread and a capturing thread genuinely contend for the
  serialization-domain guard. A bounded, one-shot capture-interval hook on the
  capturing thread releases the publisher and then samples, after a bounded delay,
  whether the publisher completed **while the capture still held the domain
  guard**. Correct serialization keeps the publisher blocked (observed = false).
  Dropping the guard across the interval **in source** makes the publisher's write
  overlap the capture interval and the test fails; the source was restored
  byte-identically (sha256 verified) and the test passes again:

  | Source state | `spike_capture_publication_serialization_overlap` | Log |
  |---|---|---|
  | mutated (guard dropped across interval) | **FAILS** — overlap observed | [`logs/06_serialization_mutation_fail.log`](logs/06_serialization_mutation_fail.log) |
  | restored (guard held across interval) | **PASSES** — no overlap | [`logs/07_serialization_restored_pass.log`](logs/07_serialization_restored_pass.log) |
- `spike_admission_refusal_and_readmission`: O5 exercised with an **actual
  returned refused proof** after releasing artificial pressure — exact original
  bytes compared, recovery outcome verified, cleanup/readmission preserved.
- Retained refusals/isolation: foreign-context, standalone/uncharged `None`,
  recovery-required, counter-exhaustion (fail-closed before mutation),
  automatic-abandonment (`Drop`), stale/foreign handle isolation. Under lazy
  allocation the counter-exhaustion and foreign-incarnation refusals now run
  **after** a first capture has installed the registry (there is no registry to
  exhaust or to present a foreign handle to before the first capture).

## 5b. §LT — Lazy registry allocation lifetime (allocation + reservation)

The registry is **not** allocated at backend open or ordinary attachment. The one
shared registry is created lazily on the first prepared capture, serialized across
all handles sharing the backend by the existing serialization-domain guard, with
its storage charge **admitted before** the allocation. It is then retained with a
standing reservation for the whole allocation lifetime and released only when the
allocation is destroyed.

**Control-storage inventory.** The lazy slot now lives **inside the pre-existing
`SerializationDomain`** (itself reached through the already-existing
`domain: Arc<Mutex<SerializationDomain>>`), as a single
`Option<Arc<Mutex<PreparedRegistry>>>` field. The earlier revision had instead
introduced a **separate** `Arc<Mutex<Option<Arc<Mutex<PreparedRegistry>>>>>`
field that was heap-allocated at **every** backend open — an uncharged eager
allocation that this revision **removes**. Embedding the slot in the domain adds
**no new per-open heap allocation**: the only added control storage is one
`Option` discriminant word plus one pointer word living inside the domain value
that is already allocated for serialization. That storage sits on the **same
accepted accounting boundary as the serialization domain** (the backend's own
infrastructure, outside the prepared-generation aggregate), and it holds the one
shared registry rather than a second eagerly-allocated registry. The capture path
reads and installs the registry **through the serialization-domain guard it
already holds** (the accessors take `&`/`&mut` to that guard), so no second lock
is taken and lock ordering is unchanged. The owning pin holds a clone of the
shared registry `Arc`, so the registry (and its reservation) follow **actual
shared ownership**: a pin may outlive its owner handle and keeps the allocation
alive until it drops.

**Chosen behavior on a post-initialization refusal.** When a later capture step
(pin / generation / control admission, `RegistryFull`, or `CounterExhausted`)
refuses **after** the registry was initialized, the chosen behavior is to
**RETAIN** the installed registry with its standing reservation (an empty charged
registry, which the brief permits), never a rollback or stale-handle revival.
When the registry-storage admission **itself** is refused on the first capture, no
registry is created and the proof is returned intact.

Focused allocation-lifetime evidence (`spike_lt_*`), using allocation presence
(`prepared_registry_for_test()`) alongside reservation observations:

| Scenario | Allocation | Reservation |
|---|---|---|
| open/attach + ordinary O4, no capture | `None` | no prepared/registry charge |
| first-capture admission refusal (one byte short of the cell) | `None` | nothing leaked; proof intact |
| successful first capture | installed | charge admitted **before** install |
| last entry released, backend alive | **retained** | standing reservation **retained** |
| subsequent capture | same `Arc` reused | **no** duplicate registry charge |
| pin outlives its owner (owner dropped, pin live) | retained via pin | reservation held until the pin drops |
| final destruction (last owner drops) | freed | reservation **released** |

The subsequent-capture reuse is verified by `Arc::ptr_eq` (the **same** shared
registry, not a re-created one) with a fresh serial (no stale-handle revival), and
the pin-outlives-owner case observes the shared operational ledger through an
independent accountant handle after the owner/backend have been dropped.

## 6. §4 — Executed test results

Commands run in the isolated checkout after the corrections. Raw logs under
[`logs/`](logs).

| # | Command | Exit | Result | Log |
|---|---|---|---|---|
| 1 | `cargo test -p qbind-node --features test-utils --test run_422_spike_prepared_generation_tests -- --nocapture` | 0 | **34 passed; 0 failed; 0 ignored** | [`logs/01_spike_tests.log`](logs/01_spike_tests.log) |
| 2 | `cargo build -p qbind-node` | 0 | **Finished** (spike + seams are `test-utils`-gated, absent from a default build) | [`logs/02_default_lib_build.log`](logs/02_default_lib_build.log) |
| 3 | `cargo test -p qbind-node --features test-utils --test run_422_d7d14_safety_record_store_tests` | 0 | **157 passed; 0 failed; 1 ignored** (inherited, re-executed, **not** relabeled as newly authored) | [`logs/03_d7d14_regression.log`](logs/03_d7d14_regression.log) |

The spike count is **34** (the previous 31 plus the duplicate-release invariant
`spike_duplicate_release_invariant_n{1,4}` and the concurrent-serialization
overlap `spike_capture_publication_serialization_overlap`); the brief does not
require it to remain exactly 31/33.

### Source-mutation sensitivity experiments (raw failure/restoration logs)

Each discriminating test was exercised against an actual **source** mutation and a
**byte-identical** restoration (sha256 verified before/after), establishing that
the test fails on the defect and passes on the correction:

| # | Experiment | Mutated → Restored | Logs |
|---|---|---|---|
| 4/5 | duplicate-release invariant | normal shared branch: covering-reservation release moved **before** backing destruction → restored to **destroy backing before release** | [`04`](logs/04_dup_release_mutation_fail.log) / [`05`](logs/05_dup_release_restored_pass.log) |
| 6/7 | concurrent-serialization overlap | domain guard dropped across capture interval → held across interval | [`06`](logs/06_serialization_mutation_fail.log) / [`07`](logs/07_serialization_restored_pass.log) |

## 7. What the corrected execution establishes

- Every live byte of a captured prepared generation — the actual
  `Arc<GenerationBacking>` allocation, its owned evidence backings, the `Arc`
  overhead, the registry cell, and each owning pin — has a **justified covering
  reservation**; no component object is exempted and no counter or synthetic
  wrapper is substituted for an actual measurement. Measurement failure is
  explicit.
- The prepared registry is **lazily allocated**: absent before the first capture,
  created only after its storage charge is admitted, installed once under the
  shared serialization boundary, retained with its reservation for the whole
  allocation lifetime (including empty periods), and released only when the
  allocation is destroyed — with a pin able to outlive its owner handle. For a
  backend that never captures, there is no registry and no standing reservation,
  preserving the accepted operational baseline; the accepted D7–D14 assertions are
  unchanged.
- The shared-conversion path keeps a duplicate proof's reservation active until
  its separately-owned evidence backings are destroyed, while preserving the
  canonical generation's independent reservation. An **independent owned-object
  destruction probe** with measured backing bytes (not allocation-address/identity
  tracing, not the release-order flag, not a hard-coded value) measures zero
  duplicate backing bytes live at the covering-reservation release boundary; a
  release-before-destruction source mutation makes that invariant fail with the
  actual still-live byte count.
- Under **complete** maximum-fixture accounting, two distinct prepared generations
  coexist while pinned at both N. At N=4 a contemporaneous O4 through both
  **succeeds** and is sampled **in operation** (after admission, before release,
  both generations pinned, O4 reservation live): operational 6413 / aggregate 6653
  (in-operation O4 reservation 4699, in-operation headroom 1119), with the
  **unchanged** ceiling holding at that phase (6653 ≤ 7772) — distinct from the
  5818 pre-operation headroom. At that same phase an **independent live-object
  measurement** charges every object actually live there — the two pinned
  generations, the registry cell, each pin (1714), plus the **O4-owned live
  objects** the publish path still holds (the complete `ValidatedRecord` inline 496
  + owned evidence backing 129 + retained encoded buffer 310 + live metadata
  payload 42 = 977), measured **in place** at the pre-effective phase — for a
  **measured live-object total of 2691**,
  reported alongside the reservation total and asserted **≤ the contemporaneous
  operational reservation (2691 ≤ 6413)** without substituting the 4699 reservation
  for the object measurement; already-destroyed staging envelopes are excluded and
  a missing backing capacity fails explicitly. The in-operation sample is taken
  through a **non-cyclic** accountant handle (no retained backend clone), and after
  all pins, proofs, owner/backend handles, and sampler ownership release, an
  independent accountant observes **0** remaining registry/generation reservation.
  At N=1 the same O4 through both exceeds the
  **unchanged** ceiling by an honest **147-byte** shortfall and is **refused** (no
  admitted in-operation O4 phase is fabricated, the in-operation observation stays
  honestly `NONE(refused)`); across the refusal the run
  captures and compares **complete record bytes**, **complete metadata bytes**, the
  **publication revision** (separately), **`owner.recovery_required()`**, both **pin
  identities/provenance**, and the **operational and aggregate** reservations —
  every property unchanged — then abandons the necessary pin and **retries the SAME
  refused publication** to readmission (revision 3), rather than raising any limit.

These are bounded experimental observations only. Deliberately **untested until
actual engine integration** (capture is non-authorizing): engine decision timing,
stage-2 certificate verification against independently supplied trusted context,
current-authority freshness and anchor selection, durability acknowledgement,
verified-evidence status, and `BootstrapNoLock` resolution (left explicitly
unresolved for this Locked-only experiment). **IMPLEMENTED-ISOLATED /
PASS-ACCEPTED-SUBSET** for accepted D14 storage is retained; activation remains
**DISABLED**; public DevNet remains **NO-GO**.

## 8. Durable artifacts and checksums

See [`SHA256SUMS.txt`](SHA256SUMS.txt) for sha256 of every file in this package
(patch, new-file sources, logs, baseline).