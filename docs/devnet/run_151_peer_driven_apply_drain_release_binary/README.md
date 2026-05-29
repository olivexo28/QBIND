# Run 151 — release-binary evidence archive

This directory is the persistent archive for the **DevNet/TestNet
peer-driven trust-bundle apply drain trigger** release-binary
evidence produced by:

```
scripts/devnet/run_151_peer_driven_apply_drain_release_binary.sh
```

## Verdict scope (mandatory disclosure per `task/RUN_151_TASK.txt`)

Run 151 is **NOT pure evidence-only.** The feasibility gate
("Can the existing Run 150 source/test drain trigger be invoked
from `target/release/qbind-node` through an existing runtime
path?") returned **NO** against the Run 150 state — the Run 150
`qbind_node::pqc_peer_candidate_drain::PeerDrivenApplyDrain`
controller was library-only with **no operator-visible surface in
`main.rs` / `cli.rs`** (the Run 150 task explicitly deferred
binary surface to Run 151). Under the task's explicit "smallest
possible operator-local hook" allowance, Run 151 added:

* a single hidden, disabled-by-default DevNet/TestNet-only
  boolean flag `--p2p-trust-bundle-peer-candidate-drain-once`
  (`crates/qbind-node/src/cli.rs`);
* the matching `main.rs` early-startup MainNet refusal block;
* the matching `main.rs` co-requisites gate (requires
  `--p2p-trust-bundle-peer-candidate-apply-enabled`, which
  itself transitively requires
  `--p2p-trust-bundle-peer-candidate-staging-enabled` and
  `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`);
* the matching `main.rs` acceptance banner
  (`[binary] Run 151: peer-candidate drain-once trigger flag
  accepted ...`);
* the matching Run 150 controller-layer arming banner
  (`[run-151] live peer-driven apply drain trigger ARMED ...`)
  that materializes
  `PeerDrivenDrainPolicy::{devnet,testnet}_enabled()` plus a
  fresh `PeerDrivenApplyDrain` controller object with an
  observably initialized `in_progress=false` concurrency flag.

Run 151 is therefore classified as **"minimal source wiring +
release-binary evidence — partial-positive (trigger-surface
arming)."** The exact source delta and rationale are recorded in
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_151.md`.

## Partial-positive disclosure (mandatory)

Run 151 does **NOT** wire a production
`PeerDrivenDrainInvocationBuilder` implementation or a production
`V2MarkerCoordinator` implementation into `main.rs`, and does
**NOT** plumb the live staging-queue handle (constructed inside
the `LivePeerCandidateWireDispatcher` builder closure in
`main.rs`) across into an explicit drain caller. Wiring those
three pieces together so the binary can actually fire
`try_drain_once` on a real staged candidate and run it through
Run 070 → `commit_sequence` → v2 marker persistence would be a
multi-piece production source change that **exceeds the
"smallest possible hook" allowance** in `task/RUN_151_TASK.txt`.
End-to-end release-binary apply through the drain (matrix rows
A1, A2, A6, A7) therefore remains under **Run 150 source/test
coverage**
(`crates/qbind-node/tests/run_150_peer_driven_apply_drain_tests.rs`
19 / 19 green) which already exercises the full pipeline against
the production `try_apply_staged_peer_candidate` + production
`apply_validated_candidate_with_previous` with deterministic
`FakeLiveTrustApplyContext` and `MockV2MarkerCoordinator` fakes.

Run 151 captures release-binary evidence for:

* the new trigger-surface **refusal scenarios** (C1 missing
  `--p2p-trust-bundle-peer-candidate-apply-enabled`; C2 / R2
  MainNet refused unconditionally; C3 missing
  `--p2p-trust-bundle-peer-candidate-staging-enabled` transitive
  co-requisite via Run 149 gate; C4 missing
  `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`
  transitive co-requisite via the upstream Run 147 staging
  gate);
* the new trigger-surface **acceptance log evidence** (C5
  DevNet with full co-requisites; C6 TestNet with full
  co-requisites) via the optional N=3 cluster harness;
* the **Run 147 / Run 149 release-binary non-mutation
  invariants** under the new flag (denylist grep + pre/post
  sequence/marker SHAs remain identical, asserting that the
  Run 151 source delta introduces no mutation surface and no
  apply call site beyond the arming banner).

## Archive layout

When the harness runs on a build-capable environment it emits
the following layout under this directory:

* `summary.txt` — top-level provenance and per-scenario verdict.
* `provenance.txt` — git commit, rustc / cargo versions, release
  `qbind-node` SHA-256 + ELF Build ID, helper binaries' SHA-256
  + ELF Build IDs.
* `logs/<SCENARIO>/v{0,1,2}.{stdout,stderr}` — per-scenario,
  per-node `stdout` and `stderr` from every release `qbind-node`
  process started by the harness. The Run 151 positive log
  markers asserted by the harness are:
  * `[binary] Run 151: FATAL ...` — emitted on the single-node
    refusal scenarios when the gate fires fail-closed;
  * `[binary] Run 151: peer-candidate drain-once trigger flag
    accepted ...` — emitted exactly once on V1 when the flag is
    supplied with valid co-requisites on DevNet/TestNet;
  * `[run-151] live peer-driven apply drain trigger ARMED ...` —
    emitted exactly once on V1 by the controller-layer arming
    banner with `in_progress=false`;
  * `[binary] Run 149: peer-candidate apply arming flag accepted`
    + `[run-149] live peer-driven apply policy ARMED` — Run 149
    banners continue to fire on V1 under the Run 151 flag;
  * `[binary] Run 147: peer-candidate staging hook arming flag
    accepted` + `[run-147] live peer-candidate staging hook
    ARMED` — Run 147 banners continue to fire on V1.
* `exit_codes/<SCENARIO>.exit_code` — per-scenario exit code:
  * `C1_drain_once_without_apply_enabled` (exit 1, Run 151
    FATAL co-requisites gate);
  * `C2_R2_drain_once_mainnet_refused` (exit 1, Run 151 early
    MainNet refusal);
  * `C3_drain_once_without_staging_enabled` (exit 1, Run 149
    transitive staging co-requisite gate);
  * `C4_drain_once_without_wire_validation_enabled` (exit 1,
    upstream Run 147 staging gate — staging requires
    wire-validation upstream of Run 149).
* `grep_summaries/in_scope.txt` — collected
  `Run 147 / 149 / 151: FATAL` lines + Run 151 acceptance /
  arming banner lines from every captured stderr.
* `grep_summaries/out_of_scope.txt` — explicit empty file (the
  harness fails closed if it is ever non-empty). Asserts the
  **denylist** of actual mutation outcomes:
  `[run-070] APPLIED`, `[run-073] VERDICT=applied`, live trust
  apply event, sequence write event, marker write event,
  session eviction event, KMS / HSM activation, signing-key
  rotation/revocation event, `--p2p-trusted-root` fallback
  activation, any active `DummySig` / `DummyKem` / `DummyAead`
  primitive, peer-majority authority installation, autonomous
  background / on-receipt apply activation. The denylist
  deliberately matches only on actual mutation/activation log
  markers and not on the disclosure-text mentions of those
  terms inside the Run 151 FATAL refusal banners.
* `data_dirs/<SCENARIO>/v{0,1,2}/` — pre/post `find . -type f |
  sort` inventories and SHA-256 sums for
  `pqc_trust_bundle_sequence.json` and
  `pqc_authority_state.json` on every node (when the optional
  cluster harness is run with persistent `--data-dir`s).

## N=3 DevNet cluster topology (optional path)

When run with the optional cluster fixtures the harness mirrors
the Run 143 / Run 147 / Run 149 N=3 DevNet topology bit-for-bit:

* **V0** — publisher (real release `qbind-node`).
* **V1** — receiver / would-be drain node (real release
  `qbind-node`, the Run 147 staging hook armed PLUS the Run 149
  apply arming flag armed PLUS the Run 151 drain-once trigger
  armed). The controller-layer
  `[run-151] live peer-driven apply drain trigger ARMED` banner
  with `in_progress=false` is asserted on V1.
* **V2** — observer (real release `qbind-node`).

The cluster-level delta vs. Run 149 is limited to V1's
extra-args list (V1 receives
`--p2p-trust-bundle-peer-candidate-drain-once` in addition to
the Run 149 extra args). The Run 143 / Run 147 / Run 149 fixture
helpers are reused verbatim with the same `sha256` / `BuildID`
provenance — Run 151 introduces **no new fixture helper, no new
metric family, no new wire-format change, no schema change, no
propagation-protocol change**.

See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_151.md` for the
canonical verdict, the full scenario matrix, the source delta,
and the explicit deferral list (governance / KMS / HSM /
signing-key rotation / revocation lifecycle / validator-set
rotation / full C4 closure / C5 closure — all OPEN).
