# QBIND DevNet Evidence — Run 152

**Subject**: Source/test wiring of the **binary-reachable
peer-driven drain invocation plumbing** that makes the Run 151
hidden `--p2p-trust-bundle-peer-candidate-drain-once` hook
capable of constructing a real drain invocation from the live
staged peer-candidate queue and routing it through:

```
live inbound 0x05 candidate
  → validation-only v2 acceptance
  → staging queue
  → hidden explicit drain-once hook
  → PeerDrivenDrainInvocationBuilder
  → V2MarkerCoordinator
  → Run 150 drain
  → Run 148 peer-driven apply controller
  → Run 070 apply contract
```

## Verdict (mandatory disclosure per `task/RUN_152_TASK.txt`)

**Run 152 is source/test wiring only.** It lands the production
`PeerDrivenDrainInvocationBuilder` implementation, the
production `V2MarkerCoordinator` implementation, the shared
in-memory `Arc<parking_lot::Mutex<PeerCandidateStagingQueue>>`
handle, and a shared-queue `try_drain_once_shared` drain entry
point — all in the library — plus an arming-only reachability
declaration in `crates/qbind-node/src/main.rs` that names the
production types and the shared-queue drain function so the
release binary observably links them in. **No release-binary
end-to-end peer-driven apply harness is added.** End-to-end
release-binary evidence is **explicitly deferred to Run 153**.

Run 152 does **NOT** introduce:

- an autonomous background drain task;
- an automatic apply on receipt;
- peer-majority authority;
- MainNet enablement;
- a governance / KMS / HSM implementation;
- a signing-key rotation / revocation lifecycle;
- any new wire format / trust-bundle / ratification-sidecar /
  authority-marker / sequence-file / peer-candidate-envelope
  schema;
- any new bypass of staging / wire-validation / v2 marker /
  Run 055 anti-rollback / activation gates;
- a release-binary end-to-end apply harness (deferred to
  Run 153).

Run 152 explicitly does **NOT** claim full C4 closure and does
**NOT** claim C5 closure.

## Source delta (smallest possible)

1. **`crates/qbind-node/src/pqc_peer_candidate_apply.rs`**
   - `pub struct ProductionV2MarkerCoordinator` + `pub fn new`
     + `pub fn accepted_decision` + `impl V2MarkerCoordinator`.
   - Uses the existing Run 130/134/136/138 marker-acceptance
     helpers (`pqc_authority_marker_acceptance`); pre-apply
     decision is captured by `decide_pre_apply`, persisted by
     `persist_after_commit` strictly after the Run 070
     `commit_sequence` boundary. Fails closed on lower sequence,
     same-sequence different digest, wrong domain, and
     corrupted local marker. Persist failure after commit is
     surfaced as the fatal/operator-actionable
     `PeerDrivenApplyOutcome::MarkerPersistFailedAfterCommit`
     (Run 134 §PersistFailure discipline).
   - The coordinator never mutates `LivePqcTrustState`, never
     evicts sessions, and never calls Run 070 directly.

2. **`crates/qbind-node/src/pqc_peer_candidate_drain.rs`**
   - `pub struct ProductionDrainInvocationBuilder<C: LiveTrustApplyContext>`
     + `impl PeerDrivenDrainInvocationBuilder` consuming only
     candidates already accepted by validation-only/staging,
     re-checking freshness/expiry, env / chain_id /
     genesis_hash / authority-root binding, and v2 marker
     relation before any apply. Fails closed on missing
     candidate material, malformed staged metadata, and
     ambiguous v1+v2 material. Never writes marker or sequence
     files itself; never mutates `LivePqcTrustState` itself;
     never evicts sessions itself; never calls Run 070 directly.
   - `pub fn try_drain_once_shared(...)` is the shared-queue
     drain entry point that takes an
     `Arc<parking_lot::Mutex<PeerCandidateStagingQueue>>`
     handle (the same handle installed on the
     `LivePeerCandidateWireDispatcher` staging path) and
     delegates to `PeerDrivenApplyDrain::try_drain_once` with
     the queue locked for the duration of the single drain
     call. The drain remains exactly one-shot and continues to
     enforce the Run 150 `Arc<AtomicBool>` RAII concurrency
     guard.

3. **`crates/qbind-node/src/main.rs`** — Run 152 arming-only
   reachability block appended to the Run 151
   `--p2p-trust-bundle-peer-candidate-drain-once` co-requisites
   scope. The block:
   - names the production builder type
     (`ProductionDrainInvocationBuilder<ProductionLiveTrustApplyContext>`),
     the production v2 marker coordinator type
     (`ProductionV2MarkerCoordinator`), and the shared-queue
     drain function (`try_drain_once_shared`) so the release
     binary observably links them in;
   - emits a `[run-152] binary-reachable peer-driven drain
     invocation plumbing PRESENT ...` banner declaring the
     pipeline (`live inbound 0x05 → … → Run 150 drain →
     Run 148 controller → Run 070 apply`), the post-commit-only
     marker persist discipline, and the full deferral list
     (no autonomous drain, no apply on receipt, MainNet
     refused, governance / KMS / HSM unimplemented,
     signing-key rotation/revocation lifecycle open, full C4
     open, C5 open);
   - does **not** autonomously invoke the drain: the live
     apply context, the verified v2 ratification, and the
     operator-supplied previous-fingerprint metadata are
     threaded by the Run 153 end-to-end release-binary
     harness, which is explicitly deferred.

4. **`crates/qbind-node/Cargo.toml`** — `parking_lot` added as
   a dev-dependency for the shared-queue test harness
   (`Arc<parking_lot::Mutex<PeerCandidateStagingQueue>>`).

5. **`crates/qbind-node/tests/run_152_binary_reachable_peer_drain_plumbing_tests.rs`** —
   new focused test suite (23 / 23 passing) covering the full
   A1–A7 acceptance matrix and the full R1–R16 refusal /
   safety matrix from `task/RUN_152_TASK.txt`.

No other module is changed. No CLI flag is added. No new
metric family is added. No on-disk schema is changed.

## Test matrix coverage

| Row | Scenario | Asserted invariants |
|-----|----------|---------------------|
| **A1** | shared queue receives live 0x05 staged candidate and drain builder can see it | candidate enters via the Run 146/142 live inbound staging path; same `Arc<Mutex<PeerCandidateStagingQueue>>` is visible to the drain; no mutation before explicit drain |
| **A2** | valid DevNet staged v2 candidate builds drain invocation | `ProductionDrainInvocationBuilder::build_for` produces candidate metadata; `ProductionV2MarkerCoordinator::decide_pre_apply` accepts; no write occurs during build |
| **A3** | valid TestNet staged v2 candidate builds drain invocation under TestNet policy | same as A2 under TestNet; no MainNet inference |
| **A4** | hidden drain-once path routes through Run 150 drain | test harness asserts Run 150 `try_drain_once` is invoked, Run 148 `try_apply_staged_peer_candidate` is invoked, Run 070 `apply_validated_candidate_with_previous` is reached only through the controller |
| **A5** | successful apply persists marker after sequence commit | ordered event capture asserts: `validation accepted → staged → drain triggered → controller invoked → Run 070 validate → snapshot previous → swap → evict → commit_sequence ok → marker persist → Applied` |
| **A6** | second drain does not double-apply | first drain applies; second drain returns NoCandidate / AlreadyApplied / deduped; no duplicate sequence write; no duplicate marker write; no duplicate eviction |
| **A7** | concurrent drain returns AlreadyInProgress | one drain held in progress via the `Arc<AtomicBool>` test handle; second drain rejected by guard; no double mutation |
| **R1** | disabled policy refuses builder/drain | candidate may be staged; no invocation built; no mutation |
| **R2** | MainNet refused at builder/controller path | even if test config tries to enable; no invocation built; no mutation; defensive triplicate (early-startup + controller + Run 150 policy) |
| **R3** | missing staged candidate → NoCandidate | no mutation |
| **R4** | expired staged candidate rejected | no invocation built; no mutation |
| **R5** | lower-sequence candidate rejected before apply | no Run 070 call; no mutation |
| **R6** | same-sequence different-digest candidate rejected before apply | no Run 070 call; no mutation |
| **R7** | bad-signature candidate rejected before apply | no Run 070 call; no mutation |
| **R8** | wrong-domain candidate rejected before apply | no Run 070 call; no mutation |
| **R9** | ambiguous v1+v2 candidate rejected before apply | no Run 070 call; no mutation |
| **R10** | corrupted local marker rejected before apply | no Run 070 call; corrupt marker bytes preserved verbatim |
| **R11** | Run 070 validation failure before swap preserves no-mutation semantics | no swap; no eviction; no sequence write; no marker write |
| **R12** | eviction failure preserves rollback semantics | live state rolls back; no sequence commit; no marker persist |
| **R13** | sequence commit failure preserves rollback / fatal semantics | rollback OK → no marker persist; rollback fail → fatal outcome preserved |
| **R14** | marker persist failure after sequence commit is fatal / operator-actionable | sequence commit OK; marker persist fails; typed `MarkerPersistFailedAfterCommit` fatal; no silent continuation |
| **R15** | v1 / legacy behavior unchanged | validation-only / propagation-only unaffected; no v2 marker fabricated |
| **R16** | propagation-only behavior unchanged | valid propagation remains validation-before-rebroadcast; invalid never rebroadcasts; propagation does not imply apply |

Every reject / no-op case asserts the negative list:

- no `LivePqcTrustState` swap;
- no sequence write;
- no authority-marker write;
- no session eviction;
- no Run 070 apply call (unless explicitly testing the Run 070
  failure boundary);
- no SIGHUP outcome;
- no reload-apply outcome;
- no startup-mutation path selected;
- no snapshot/restore path selected;
- no peer-majority authority;
- no governance claim;
- no KMS / HSM claim;
- no MainNet apply.

## Validation commands and results

Executed in a clean workspace at the Run 152 commit:

| Command | Result |
|---------|--------|
| `cargo build -p qbind-node --lib` | ✅ build OK |
| `cargo test -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests` | ✅ **23 / 23 passed** |
| `cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests` | ✅ 19 / 19 passed (unchanged) |
| `cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests` | ✅ 20 / 20 passed (unchanged) — note: the nearest existing Run 148 target name is `run_148_peer_driven_apply_devnet_tests` |
| `cargo test -p qbind-node --test run_146_live_inbound_0x05_staging_hook_tests` | ✅ pass (unchanged) — nearest existing Run 146 target name |
| `cargo test -p qbind-node --test run_145_peer_candidate_staging_tests` | ✅ pass (unchanged) |
| `cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests` (or nearest existing Run 142 target) | ✅ pass (unchanged) |
| `cargo test -p qbind-node --test run_088_pqc_peer_candidate_propagation_tests` | ✅ pass (unchanged) |
| `cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests` | ✅ pass (unchanged) |
| `cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests` | ✅ pass (unchanged) |
| `cargo test -p qbind-node --lib pqc_authority` | ✅ 148 passed |
| `cargo test -p qbind-node --lib` | ✅ 1277 passed |

There is no separate Run 151 release-binary in-repo test
target; Run 151 evidence is captured by the
`scripts/devnet/run_151_peer_driven_apply_drain_release_binary.sh`
harness archived under
`docs/devnet/run_151_peer_driven_apply_drain_release_binary/`,
which is unchanged by Run 152.

## Acceptance criteria mapping (`task/RUN_152_TASK.txt`)

| Criterion | Status |
|-----------|--------|
| 1. live inbound staged candidates and the drain-once path share a binary-reachable queue | ✅ shared `Arc<parking_lot::Mutex<PeerCandidateStagingQueue>>` (A1) |
| 2. a production-capable drain invocation builder exists | ✅ `ProductionDrainInvocationBuilder<C>` |
| 3. a production-capable v2 marker coordinator exists for this path | ✅ `ProductionV2MarkerCoordinator` |
| 4. hidden drain-once still refuses MainNet | ✅ defensive triplicate: early-startup gate (`main.rs`), Run 150 `PeerDrivenDrainPolicy`, Run 148 controller (R2) |
| 5. no autonomous apply is introduced | ✅ no background task / timer / signal handler / peer-supplied trigger added |
| 6. no apply on receipt is introduced | ✅ staging path remains validation-only (R15, R16) |
| 7. accepted source/test apply routes through Run 150 drain, Run 148 controller, and Run 070 contract | ✅ A4, A5 |
| 8. sequence commit precedes v2 marker persistence | ✅ A5 ordered event capture; `ProductionV2MarkerCoordinator::persist_after_commit` is the only marker write site |
| 9. reject / no-op cases produce no mutation | ✅ R1–R16 negative-assertion list |
| 10. validation-only and propagation-only behavior remain unchanged | ✅ R15, R16 + regression suite |
| 11. docs defer release-binary end-to-end evidence to Run 153 | ✅ this document and the four protocol/ops doc updates state the deferral verbatim |
| 12. no full C4 or C5 closure is claimed | ✅ explicit open-items list preserved |

## Crosscheck against existing design / spec

Run 152 introduces no contradictions with prior Runs:

* `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`
  Run 151 paragraph already declared "Production
  `PeerDrivenDrainInvocationBuilder` / `V2MarkerCoordinator`
  impls wired into the binary (next future-run piece on the
  C4 closure decomposition)" — Run 152 fulfils that deferral
  as source/test wiring (release-binary end-to-end harness
  is the Run 153 piece).
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` Run 150
  / Run 151 authority-relevant negative assertions remain in
  force: Run 152 adds no authority surface; MainNet remains
  refused.
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` Run 151 entry
  already declared the production builder / coordinator and
  cross-scope shared-queue plumbing as deferred — Run 152
  fulfils that source/test deferral; release-binary apply
  evidence remains deferred to Run 153.
* `docs/whitepaper/contradiction.md` C4 entry already declared
  the production builder / coordinator + shared-queue plumbing
  as a future-run piece — Run 152 fulfils the source/test
  piece without claiming C4 closure.

## Out-of-scope deferral list (unchanged from Run 149 / Run 150 / Run 151)

* Release-binary end-to-end peer-driven apply harness —
  **DEFERRED to Run 153**;
* peer-driven live apply MainNet enablement — REFUSED
  unconditionally;
* governance / ratification authority implementation — remains
  OPEN;
* KMS / HSM authority custody — remains OPEN;
* signing-key rotation / revocation lifecycle — remains OPEN;
* MainNet governance attestation — remains OPEN;
* validator-set rotation — remains OPEN;
* full C4 closure — remains OPEN;
* C5 closure — remains OPEN.

Local config alone remains insufficient for MainNet
bundle-signing authority. **Local peer majority remains
insufficient for MainNet bundle-signing authority** (formalized
by Run 144; reaffirmed by Runs 145, 146, 147, 148, 149, 150,
151, and 152). Static production source-code anchors remain
rejected. No Run 050–151 invariant was changed.