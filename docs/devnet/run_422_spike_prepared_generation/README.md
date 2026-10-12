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
the previous package. The headings below keep four kinds of evidence distinct:
*source-derived arithmetic* (struct layout and charge formulas), *executed
object observations* (measured live allocations), *reservation observations*
(live aggregate charges), and *inherited evidence* (the baseline identity and
the re-executed D7–D14 target).

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
  (9 files, +2736/-6; two new files included).

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
| N=4 TC | 512 | 504 | 16 | **1032** | 888 | 144 | **1032** |

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
| premature (`HolderBeforeRetained`) | 33 / 97 — **non-zero: the defect** |
| corrected (`RetainedBeforeHolder`, default) | 0 / 0 — **passes** |

The test fails under the premature ordering and passes after correction, then
**restores** the sensitivity mutation (`set_shared_release_order(RetainedBefore
Holder)`). It covers fresh conversion, shared conversion, refusal (no conversion,
empty registry), explicit release, and automatic `Drop`.

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
| generation-core, each (QC) | 417 | 481 |
| two distinct generations, operational (2·core + 2·control + registry-cell + 2·pin) | 1522 | 1650 |
| aggregate with two pinned (context + operational) | **1714** | **1890** |
| aggregate ceiling | 3956 | 7772 |

**Two distinct prepared generations coexist while pinned at both N** (1714 ≤ 3956;
1890 ≤ 7772). The honest distinction is the *contemporaneous O4 through both*:

- **N=4 — COEXIST_THROUGH_O4:** a further authoritative publication while both
  generations stay pinned **succeeds** (headroom 5882). A third capture is then
  refused `RegistryFull` without eviction; both pins release to baseline.
- **N=1 — COEXIST_REFUSE_O4 (conservative refusal):** the same O4 through both
  pinned generations would reach **4103 > 3956**, an exact **147-byte shortfall**.
  The run reports the shortfall honestly, confirms the refusal mutated nothing
  (both pins intact, no leaked charge), and then **demonstrates cleanup +
  readmission** (release, re-publish, re-capture) — **without** raising any limit
  or redefining any exclusion.

### Other §3 evidence

- `spike_capture_publication_boundary`: a deterministic capture/publication
  boundary test (replacing the prior sequential "concurrency" claim) that
  distinguishes correct serialization from its removal.
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

**Control-storage inventory.** The lazy lifecycle adds exactly one piece of
control storage: the backend's registry slot, now
`Mutex<Option<Arc<Mutex<PreparedRegistry>>>>` (previously a non-optional
`Arc<Mutex<PreparedRegistry>>`). The added `Option` is a one-word discriminant
living inside the already-charged backend container; it is **uncharged control
storage on the same accepted accounting boundary as the serialization domain**
(the backend's own infrastructure, outside the prepared-generation aggregate),
and it holds the one shared registry rather than a second eagerly-allocated
registry. The owning pin now also holds a clone of the shared registry `Arc`, so
the registry (and its reservation) follow **actual shared ownership**: a pin may
outlive its owner handle and keeps the allocation alive until it drops.

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
| 1 | `cargo test -p qbind-node --features test-utils --test run_422_spike_prepared_generation_tests -- --nocapture` | 0 | **31 passed; 0 failed; 0 ignored** | [`logs/01_spike_tests.log`](logs/01_spike_tests.log) |
| 2 | `cargo build -p qbind-node` | 0 | **Finished** (spike + seams are `test-utils`-gated, absent from a default build) | [`logs/02_default_lib_build.log`](logs/02_default_lib_build.log) |
| 3 | `cargo test -p qbind-node --features test-utils --test run_422_d7d14_safety_record_store_tests` | 0 | **157 passed; 0 failed; 1 ignored** (inherited, re-executed, **not** relabeled as newly authored) | [`logs/03_d7d14_regression.log`](logs/03_d7d14_regression.log) |

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
  canonical generation's independent reservation.
- Under **complete** accounting, two distinct prepared generations coexist while
  pinned at both N, but at N=1 a contemporaneous O4 through both exceeds the
  **unchanged** ceiling by exactly 147 bytes; the run reports that shortfall and
  demonstrates cleanup/readmission rather than raising any limit. At N=4 the O4
  succeeds.

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